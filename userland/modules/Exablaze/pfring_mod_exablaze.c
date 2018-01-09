/*
 *
 * (C) 2016 - ntop.org
 *
 * Module for supporting Exablaze NICs
 *
 * Use it as exanic:xxxx. Example pfsend -i exanic:enp6s0
 *
 */

#include "pfring_mod_exablaze.h"
#include "pfring_mod.h" /* to print stats under /proc */
#include "../nbpf/nbpf.h"

#include <net/if.h>
#include <sys/ioctl.h>

// #define DEBUG 1

/* **************************************************** */

static void __pfring_exablaze_set_promiscuous_mode(exanic_t *exanic, int port_number, int enable) {
  struct ifreq ifr;
  int fd;

  memset(&ifr, 0, sizeof(ifr));
  if(exanic_get_interface_name(exanic, port_number, ifr.ifr_name,
				sizeof(ifr.ifr_name)) == -1)
    return;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(ioctl(fd, SIOCGIFFLAGS, &ifr) != -1) {
    if (enable)
      ifr.ifr_flags |= IFF_PROMISC;
    else
      ifr.ifr_flags &= ~IFF_PROMISC;

    ioctl(fd, SIOCSIFFLAGS, &ifr);
  }

  close(fd);
}

/* **************************************************** */

static void __pfring_exablaze_read_mac_address(pfring_exablaze *ex, char *device_name) {
  int _sock, res;
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(struct ifreq));

  /* Dummy socket, just to make ioctls with */
  _sock = socket(PF_INET, SOCK_DGRAM, 0);
  strncpy(ifr.ifr_name, device_name, IFNAMSIZ-1);
  res = ioctl(_sock, SIOCGIFHWADDR, &ifr);

  if(res < 0) {
#ifdef DEBUG
    fprintf(stderr, "[EXABLAZE] Cannot get hw addr for %s\n", device_name);
#endif
  } else
    memcpy(ex->mac_address, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

  close(_sock);
}

/* **************************************************** */

static void __pfring_exablaze_release_resources(pfring *ring) {
  pfring_exablaze *ex = (pfring_exablaze *)ring->priv_data;

  if(ex) {
    if(ex->exanic)
      __pfring_exablaze_set_promiscuous_mode(ex->exanic, ex->port_number, 0 /* disable */);

    if(ex->rx) exanic_release_rx_buffer(ex->rx);
    if(ex->tx) exanic_release_tx_buffer(ex->tx);
    if(ex->exanic) exanic_release_handle(ex->exanic);

    free(ring->priv_data);
    ring->priv_data = NULL;
  }
}

/* **************************************************** */

static int __pfring_exablaze_check_ip_rules(pfring_exablaze *exablaze,
					    nbpf_rule_list_item_t *pun) {
  u_int num_filters = 0;

  /* Scan the list and set the single rule */
  while(pun != NULL) {
    nbpf_rule_core_fields_t *c = &pun->fields;

    if(c->ip_version == 6) return(-1); /* Hardware IPv6 filters are not supported */
    if(c->vlan_id != 0) return(-2);
    if(c->sport_low != c->sport_high) return(-3); /* Ranges are not supported */
    if(c->dport_low != c->dport_high) return(-3); /* Ranges are not supported */

    if(++num_filters >= 128) return(-4); /* Too many filters */

    pun = pun->next;
  }

  return(0);
}

/* *********************************************************** */

#ifdef DEBUG
static void exablaze_dump_rule(u_int id, nbpf_rule_core_fields_t *c) {
  printf("[%u] ", id);

  if(c->ip_version) printf("[IPv%d] ", c->ip_version);

  if(c->vlan) {
    if(c->vlan_id) printf("[VLAN: %u] ", c->vlan_id);
    else            printf("[VLAN] ");
  }
  if(c->mpls) {
    if(c->mpls_label) printf("[MPLS: %u] ", c->mpls_label);
    else               printf("[MPLS] ");
  }
  if(c->proto)      printf("[L4 Proto: %u] ", c->proto);

  if(!c->ip_version || c->ip_version == 4) {
    char a[32];

    printf("[");

    if(c->shost.v4) printf("%s", bpf_intoaV4(ntohl(c->shost.v4), a, sizeof(a)));
    else printf("*");
    printf(":");
    if(c->sport_low) {
      printf("%u", ntohs(c->sport_low));
      if(c->sport_high && c->sport_high != c->sport_low) printf("-%u", ntohs(c->sport_high));
    } else printf("*");

    printf(" -> ");

    if(c->dhost.v4) printf("%s", bpf_intoaV4(ntohl(c->dhost.v4), a, sizeof(a)));
    else printf("*");
    printf(":");
    if(c->dport_low) {
      printf("%u", ntohs(c->dport_low));
      if(c->dport_high && c->dport_high != c->dport_low) printf("-%u", ntohs(c->dport_high));
    } else printf("*");

    printf("]");
  } else if(c->ip_version == 6) {
    char a[64];

    printf("[");

    if(c->shost.v4) printf("[%s]", bpf_intoaV6(&c->shost.v6, a, sizeof(a)));
    else printf("*");
    printf(":");
    if(c->sport_low) {
      printf("%u", ntohs(c->sport_low));
      if(c->sport_high && c->sport_high != c->sport_low) printf("-%u", ntohs(c->sport_high));
    } else printf("*");

    printf(" -> ");

    if(c->dhost.v4) printf("[%s]", bpf_intoaV6(&c->dhost.v6, a, sizeof(a)));
    else printf("*");
    printf(":");
    if(c->dport_low) {
      printf("%u", ntohs(c->dport_low));
      if(c->dport_high && c->dport_high != c->dport_low) printf("-%u", ntohs(c->dport_high));
    } else printf("*");

    printf("] ");
  }

  if(c->gtp) printf("[GTP] ");

  printf("\n");
}
#endif

/* **************************************************** */

static int __pfring_exablaze_set_ip_rules(pfring_exablaze *exablaze,
					  nbpf_rule_list_item_t *pun) {
  if(exablaze->rx == NULL) {
    if((exablaze->rx = exanic_acquire_unused_filter_buffer(exablaze->exanic,
							   exablaze->port_number)) == NULL)
    return(-1);
  }

  /* Scan the list and set the single rule */
  while(pun != NULL) {
    exanic_ip_filter_t f;

#ifdef DEBUG
    exablaze_dump_rule(i++, &pun->fields);
#endif
    
    memset(&f, 0, sizeof(f));
    f.protocol = pun->fields.proto,
      f.src_addr = pun->fields.shost.v4, f.src_port = pun->fields.sport_low,
      f.dst_addr = pun->fields.dhost.v4, f.dst_port = pun->fields.dport_low;

    if(exanic_filter_add_ip(exablaze->exanic, exablaze->rx, &f) == -1) {
      fprintf(stderr, "[EXABLAZE] exanic_filter_add_ip() error: %s\n", exanic_get_last_error());
      return(-1);
    }

    pun = pun->next;
  }

  return(0);
}

/* **************************************************** */

int pfring_exablaze_set_bpf_filter(pfring *ring, char *bpf) {
  pfring_exablaze *exablaze = (pfring_exablaze *)ring->priv_data;
  nbpf_tree_t *tree;
  nbpf_rule_list_item_t *pun;
  int rc = 0;

  /* Parses the bpf filters and builds the rules tree */
  if((tree = nbpf_parse(bpf, NULL)) == NULL) {
#ifdef DEBUG
    printf("Error on parsing the bpf filter.");
#endif
    return -1; /* not supported, falling back to standard bpf */
  }

  /* check the general rules of the nbpf */
  if(!nbpf_check_rules_constraints(tree, 0)) {
    nbpf_free(tree);
    return -1; /* not supported, falling back to standard bpf */
  }

  /* Generates rules list */
  if((pun = nbpf_generate_rules(tree)) == NULL) {
#ifdef DEBUG
    printf("Error generating rules.");
#endif
    nbpf_free(tree);
    return -3; /* error generating rules */
  }

  /* Check if the BPF can be supported by the NIC */
  if(__pfring_exablaze_check_ip_rules(exablaze, pun)
     /* Create and set the rules on the nic */
     || __pfring_exablaze_set_ip_rules(exablaze, pun)) {
#ifdef DEBUG
    printf("Error on creating and setting the rules list on the NIC card: using software BPF");
#endif

    rc = -4; /* error setting rules */
  }

  nbpf_rule_list_free(pun);
  nbpf_free(tree);

  return rc;
}



/* **************************************************** */

int pfring_exablaze_open(pfring *ring) {
  pfring_exablaze *exablaze;
  char device_name[32];
  char *at = strchr(ring->device_name, '@');

  ring->close              = pfring_exablaze_close;
  ring->stats              = pfring_exablaze_stats;
  ring->recv               = pfring_exablaze_recv;
  ring->poll               = pfring_exablaze_poll;
  ring->set_direction      = pfring_exablaze_set_direction;
  ring->enable_ring        = pfring_exablaze_enable_ring;
  ring->get_bound_device_ifindex = pfring_exablaze_get_bound_device_ifindex;
  ring->get_bound_device_address = pfring_exablaze_get_bound_device_address;
  ring->send               = pfring_exablaze_send;
  ring->set_bpf_filter     = pfring_exablaze_set_bpf_filter;

  /* inherited from pfring_mod.c */
  ring->set_socket_mode          = pfring_mod_set_socket_mode;
  ring->set_bound_dev_name       = pfring_mod_set_bound_dev_name;
  ring->set_application_name     = pfring_mod_set_application_name;
  ring->set_application_stats    = pfring_mod_set_application_stats;
  ring->get_appl_stats_file_name = pfring_mod_get_appl_stats_file_name;

  ring->poll_duration = DEFAULT_POLL_DURATION;
  ring->priv_data = NULL;

  ring->fd = socket(PF_RING, SOCK_RAW, htons(ETH_P_ALL)); /* opening PF_RING socket to write stats under /proc */
  if(ring->fd < 0) return -1;

  ring->priv_data = calloc(1, sizeof(pfring_exablaze));

  if(ring->priv_data == NULL)
    goto free_private;

  exablaze = (pfring_exablaze *)ring->priv_data;

  if(at)
    at[0] = '\0', exablaze->channel_id = atoi(&at[1]);

  snprintf(device_name, sizeof(device_name), "%s", ring->device_name);
  if(strncmp(device_name, "exanic", 6) == 0)
    exablaze->exanic = exanic_acquire_handle(device_name), exablaze->port_number = 0;
  else {
    char device[32];
    int rc = exanic_find_port_by_interface_name(device_name,
						device, sizeof(device),
						&exablaze->port_number);

    exablaze->exanic = (rc == 0) ? exanic_acquire_handle(device) : NULL;

    if(exablaze->exanic != NULL) {
      exablaze->if_index = if_nametoindex(device);
      __pfring_exablaze_read_mac_address(exablaze, device_name);
#ifdef DEBUG
      if(rc == 0)
	fprintf(stderr, "[EXABLAZE] Succesfully open device %s / port %d\n",
		device, exablaze->port_number);
#endif
    }
  }

  if(exablaze->exanic == NULL) {
#ifdef DEBUG
    fprintf(stderr, "[EXABLAZE] Unable to open device %s", ring->device_name);
#endif
    goto free_private;
  }

  return 0;

 free_private:
  __pfring_exablaze_release_resources(ring);

  return -1;
}

/* **************************************************** */

void pfring_exablaze_close(pfring *ring) {
  __pfring_exablaze_release_resources(ring);
  close(ring->fd);
}

/* **************************************************** */

int pfring_exablaze_stats(pfring *ring, pfring_stat *stats) {
  pfring_exablaze *exablaze = (pfring_exablaze *)ring->priv_data;

  stats->recv = exablaze->recv, stats->drop = 0;
  return 0;
}

/* **************************************************** */

int pfring_exablaze_set_direction(pfring *ring, packet_direction direction) {
  if(direction == rx_only_direction || direction == rx_and_tx_direction)
    return setsockopt(ring->fd, 0, SO_SET_PACKET_DIRECTION, &direction, sizeof(direction));

  return -1;
}

/* **************************************************** */

int pfring_exablaze_get_bound_device_ifindex(pfring *ring, int *if_index) {
  pfring_exablaze *exablaze = (pfring_exablaze *)ring->priv_data;

  *if_index = exablaze->if_index;
  return 0;
}

/* **************************************************** */

int pfring_exablaze_enable_ring(pfring *ring) {
  pfring_exablaze *exablaze = (pfring_exablaze *)ring->priv_data;

  if((ring->mode == recv_only_mode) || (ring->mode == send_and_recv_mode)) {
    if(exablaze->rx == NULL) {
      if((exablaze->rx = exanic_acquire_rx_buffer(exablaze->exanic,
						  exablaze->port_number, exablaze->channel_id)) == NULL) {
	fprintf(stderr, "[EXABLAZE] Unable to acquire RX buffer %d\n", exablaze->channel_id);
	return -1;
      }
    }

#ifdef DEBUG
    fprintf(stderr, "[EXABLAZE] RX open [port=%u][channel=%u]\n", exablaze->port_number, exablaze->channel_id);
#endif
    __pfring_exablaze_set_promiscuous_mode(exablaze->exanic, exablaze->port_number, 1);
  }

  if((ring->mode == send_only_mode) || (ring->mode == send_and_recv_mode)) {
    if((exablaze->tx = exanic_acquire_tx_buffer(exablaze->exanic, exablaze->port_number, 0 /* requested_size */)) == NULL) {
      fprintf(stderr, "[EXABLAZE] Unable to acquire TX buffer\n");
      return -1;
    }
  }

  return 0;
}

/* **************************************************** */

int pfring_exablaze_recv(pfring *ring, u_char **buffer,
			 u_int buffer_len,
			 struct pfring_pkthdr *hdr,
			 u_int8_t wait_for_incoming_packet) {
  pfring_exablaze *exablaze = (pfring_exablaze *)ring->priv_data;
  ssize_t len;
  uint32_t timestamp;

  if(unlikely(exablaze->rx == NULL)) return(-1);

 exablaze_rx_read:
  if(likely(buffer_len == 0))
    len = exanic_receive_frame(exablaze->rx, (char*)exablaze->pkt, sizeof(exablaze->pkt), &timestamp);
  else
    len = exanic_receive_frame(exablaze->rx, (char*)*buffer, buffer_len, &timestamp);

  if(len > 0) {
    uint64_t ns;

    hdr->len = hdr->caplen = len, hdr->caplen = min_val(hdr->caplen, ring->caplen);
    hdr->extended_hdr.pkt_hash = 0, hdr->extended_hdr.if_index = exablaze->if_index, hdr->extended_hdr.rx_direction = 1;
    ns = exanic_timestamp_to_counter(exablaze->exanic, timestamp);
    hdr->ts.tv_sec  = ns / 1000000000, hdr->ts.tv_usec = ns / 1000, hdr->extended_hdr.timestamp_ns = ns;

    if(likely(buffer_len == 0)) {
      *buffer = exablaze->pkt;
    } else {
      memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(hdr->extended_hdr.parsed_pkt));
      pfring_parse_pkt(*buffer, hdr, 4, 0 /* ts */, 1 /* hash */);
    }

    exablaze->recv++;
    return 1;
  } else {
    if(wait_for_incoming_packet) {
      if(unlikely(ring->break_recv_loop)) {
	ring->break_recv_loop = 0;
	return -1;
      }

      usleep(1);
      goto exablaze_rx_read;
    }
  }

  return 0;
}

/* **************************************************** */

int pfring_exablaze_poll(pfring *ring, u_int wait_duration) {
  return(0); /* TODO */
}

/* **************************************************** */

int  pfring_exablaze_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet) {
  pfring_exablaze *exablaze = (pfring_exablaze *)ring->priv_data;
  int rc = exanic_transmit_frame(exablaze->tx, (const char *)pkt, pkt_len);

  return(rc == 0 ? pkt_len : -1);
}

/* **************************************************** */

int pfring_exablaze_get_bound_device_address(pfring *ring, u_char mac_address[6]) {
  pfring_exablaze *exablaze = (pfring_exablaze *)ring->priv_data;

  memcpy(mac_address, exablaze->mac_address, 6);
  return(0);
}

/* **************************************************** */
