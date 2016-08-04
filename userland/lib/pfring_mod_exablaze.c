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
    __pfring_exablaze_set_promiscuous_mode(ex->exanic, ex->port_number, 0 /* disable */);

    if(ex->rx) exanic_release_rx_buffer(ex->rx);
    if(ex->tx) exanic_release_tx_buffer(ex->tx);
    if(ex->exanic) exanic_release_handle(ex->exanic);

    free(ring->priv_data);
    ring->priv_data = NULL;
  }
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
    exablaze->if_index = if_nametoindex(device);
    __pfring_exablaze_read_mac_address(exablaze, device_name);
#ifdef DEBUG
    if(rc == 0)
      fprintf(stderr, "[EXABLAZE] Succesfully open device %s / port %d\n",
	      device, exablaze->port_number);
#endif
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
    if((exablaze->rx = exanic_acquire_rx_buffer(exablaze->exanic, exablaze->port_number, exablaze->channel_id)) == NULL)
      {
      fprintf(stderr, "[EXABLAZE] Unable to acquire RX buffer %d\n", exablaze->channel_id);
      return -1;
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

  return (rc == 0 ? pkt_len : -1);
}

/* **************************************************** */

int pfring_exablaze_get_bound_device_address(pfring *ring, u_char mac_address[6]) {
  pfring_exablaze *exablaze = (pfring_exablaze *)ring->priv_data;

  memcpy(mac_address, exablaze->mac_address, 6);
  return(0);
}

/* **************************************************** */
