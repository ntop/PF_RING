/*
 *
 * (C) 2018 - ntop.org
 *
 * Module for supporting Netcope NICs
 *
 */

#include "pfring_mod_netcope.h"
#include "pfring_mod_netcope_priv.h"
#include "pfring_mod.h" /* to print stats under /proc */

//#define DEBUG

/* **************************************************** */

static struct thirdparty_func pfring_nsf_function_ptr[] = {
  /* libnsf.h */
  { "nsf_init", NULL },
  { "nsf_error_string", NULL },
  { "nsf_action", NULL },
  { "nsf_create_context", NULL },
  { "nsf_open", NULL },
  { "nsf_rx_stream_open", NULL },
  { "nsf_get_rx_queues_count", NULL },
  { "nsf_core_receive_queue_min", NULL },
  { "nsf_core_receive_queue_max", NULL },
  { "nsf_rx_stream_read_next", NULL },
  { "nsf_parse_frame", NULL },
  { "nsf_send_command", NULL },
  { "nsf_close", NULL },
  { "nsf_rx_stream_close", NULL },
  { "nsf_remove_context", NULL },
  { "nsf_exit", NULL },
  { "nsf_rx_get_link_speed_interface", NULL },
  { "nsf_flow_id", NULL },
  { "nsf_rx_read_frame_counters_basic_interface", NULL },
  /* end */
  { NULL, NULL }
};

/* pfring_nsf_api.h */
#define	nsf_init_card		(* (nsf_error_t (*)(nsf_t **nsf, int card_id)) pfring_nsf_function_ptr[0].ptr)
#define	nsf_error_string	(* (const char * (*)(nsf_error_t error)) pfring_nsf_function_ptr[1].ptr)
#define	nsf_action		(* (nsf_error_t (*)(nsf_t *nsf, nsf_action_t *action, nsf_action_receive_t receive, unsigned frame_trim_length, nsf_action_distribute_t distribute, unsigned core_queue_min, unsigned core_queue_max, bool send, unsigned core_interface)) pfring_nsf_function_ptr[2].ptr)
#define	nsf_create_context	(* (nsf_error_t (*)(nsf_t *nsf, nsf_context_id_t *context_id, const nsf_action_t *default_action)) pfring_nsf_function_ptr[3].ptr)
#define	nsf_open		(* (nsf_error_t (*)(nsf_t *nsf, nsf_access_t **access)) pfring_nsf_function_ptr[4].ptr)
#define	nsf_rx_stream_open	(* (nsf_error_t (*)(nsf_t *nsf, uint64_t queue_mask, nsf_rx_stream_t **rx_stream)) pfring_nsf_function_ptr[5].ptr)
#define	nsf_get_rx_queues_count	(* (unsigned (*)(nsf_t *nsf)) pfring_nsf_function_ptr[6].ptr)
#define	nsf_core_receive_queue_min (* (unsigned (*)(nsf_t *nsf)) pfring_nsf_function_ptr[7].ptr)
#define	nsf_core_receive_queue_max (* (unsigned (*)(nsf_t *nsf)) pfring_nsf_function_ptr[8].ptr)
#define	nsf_rx_stream_read_next	(* (unsigned char * (*)(nsf_rx_stream_t *nsf_rx, unsigned *length)) pfring_nsf_function_ptr[9].ptr)
#define	nsf_parse_frame		(* (nsf_error_t (*)(unsigned char *data, nsf_header_t *header, unsigned char **payload, unsigned *payload_length)) pfring_nsf_function_ptr[10].ptr)
#define	nsf_send_command	(* (nsf_error_t (*)(nsf_access_t *access, const nsf_context_id_t *context_id, const nsf_flow_id_t *flow_id, const nsf_action_t *action, nsf_command_t command)) pfring_nsf_function_ptr[11].ptr)
#define	nsf_close		(* (nsf_error_t (*)(nsf_access_t **access)) pfring_nsf_function_ptr[12].ptr)
#define	nsf_rx_stream_close	(* (nsf_error_t (*)(nsf_t *nsf, nsf_rx_stream_t **rx_stream)) pfring_nsf_function_ptr[13].ptr)
#define	nsf_remove_context	(* (nsf_error_t (*)(nsf_t *nsf, const nsf_context_id_t context_id)) pfring_nsf_function_ptr[14].ptr)
#define	nsf_exit		(* (nsf_error_t (*)(nsf_t **nsf)) pfring_nsf_function_ptr[15].ptr)
#define nsf_rx_get_link_speed_interface (* (nsf_error_t (*)(nsf_t *nsf, unsigned interface, nsf_speed_t * speed)) pfring_nsf_function_ptr[16].ptr)
#define nsf_flow_id		(* (nsf_error_t (*)(nsf_t *nsf, nsf_flow_id_t *flow_id, uint8_t interface, uint8_t ip_version, nsf_ip_t *src_ip, nsf_ip_t *dst_ip, uint8_t protocol, uint16_t src_port, uint16_t dst_port, uint8_t icmp_type, uint8_t icmp_code)) pfring_nsf_function_ptr[17].ptr)
#define nsf_rx_read_frame_counters_basic_interface (* (nsf_error_t (*)(nsf_t *nsf, unsigned interface, uint64_t *total, uint64_t *received, uint64_t *dropped, uint64_t *bufoverflow, uint64_t *error)) pfring_nsf_function_ptr[18].ptr)

static int __pfring_nsf_init() {
  static u_int8_t pfring_nsf_initialized_ok = 0;
  int i, all_right = 1;

  if (pfring_nsf_initialized_ok != 0)
    return pfring_nsf_initialized_ok;

  pfring_thirdparty_lib_init("/usr/lib64/libnsf.so", pfring_nsf_function_ptr);

  for (i = 0; pfring_nsf_function_ptr[i].name != NULL; i++) {
    if (pfring_nsf_function_ptr[i].ptr == NULL) {
#ifdef DEBUG
      printf("[NETCOPE] Unable to locate function %s\n", pfring_nsf_function_ptr[i].name);
#endif
      all_right = -2;
      break;
    }
  }

  pfring_nsf_initialized_ok = all_right;
  return all_right;
}

/* **************************************************** */

static void __pfring_netcope_release_resources(pfring *ring) {
  pfring_netcope *netcope = (pfring_netcope *) ring->priv_data;

  if (netcope) {

    if (netcope->acc)
      nsf_close(&netcope->acc);

    if (netcope->rx_stream)
      nsf_rx_stream_close(netcope->nsf, &netcope->rx_stream);

    if (netcope->context_id >= 0)
      nsf_remove_context(netcope->nsf, netcope->context_id);

    if (netcope->nsf)
      nsf_exit(&netcope->nsf);

    free(ring->priv_data);
    ring->priv_data = NULL;
  }
}

/* **************************************************** */

int pfring_netcope_open(pfring *ring) {
  pfring_netcope *netcope;
  nsf_error_t err;

  if (__pfring_nsf_init() < 0)
    return -99;

  ring->close              = pfring_netcope_close;
  ring->stats              = pfring_netcope_stats;
  ring->recv               = pfring_netcope_recv;
  ring->poll               = pfring_netcope_poll;
  ring->set_direction      = pfring_netcope_set_direction;
  ring->enable_ring        = pfring_netcope_enable_ring;
  ring->get_bound_device_ifindex = pfring_netcope_get_bound_device_ifindex;
  ring->send               = pfring_netcope_send;
  ring->flush_tx_packets   = pfring_netcope_flush_tx_packets;
  ring->get_interface_speed = pfring_netcope_get_interface_speed;
  ring->add_hw_rule        = pfring_netcope_add_hw_rule;

  /* inherited from pfring_mod.c */
  ring->set_socket_mode          = pfring_mod_set_socket_mode;
  ring->set_bound_dev_name       = pfring_mod_set_bound_dev_name;
  ring->set_application_name     = pfring_mod_set_application_name;
  ring->set_application_stats    = pfring_mod_set_application_stats;
  ring->get_appl_stats_file_name = pfring_mod_get_appl_stats_file_name;

  ring->poll_duration = DEFAULT_POLL_DURATION;

  ring->priv_data = NULL;

  ring->fd = socket(PF_RING, SOCK_RAW, htons(ETH_P_ALL)); /* opening PF_RING socket to write stats under /proc */
  if (ring->fd < 0) return -1;

  ring->priv_data = calloc(1, sizeof(pfring_netcope));

  if (ring->priv_data == NULL)
    goto error;

  netcope = (pfring_netcope *) ring->priv_data;

  /*
   * Device name [X:]Y[@Z] where
   * X Card ID
   * Y Port ID
   * Z Queue ID
   */

  if (sscanf(ring->device_name, "%u:%u@%u", &netcope->card_id, &netcope->port_id, &netcope->queue_id) == 3) {
    // all set
  } else if (sscanf(ring->device_name, "%u@%u", &netcope->port_id, &netcope->queue_id) == 2) {
    netcope->card_id = 0;
  } else if (sscanf(ring->device_name, "%u:%u", &netcope->card_id, &netcope->port_id) == 2) {
    netcope->queue_id = -1;
  } else {
    sscanf(ring->device_name, "%u", &netcope->port_id);
    netcope->card_id = 0;
    netcope->queue_id = -1;
  }

  err = nsf_init_card(&netcope->nsf, netcope->card_id);

  if (err) {
    fprintf(stderr, "nsf_init failed: %s\n", nsf_error_string(err));
    free(ring->priv_data);
    goto error;
  }

  return 0;

 //release:
 // __pfring_netcope_release_resources(ring);

 error:
  return -1;
}

/* **************************************************** */

void pfring_netcope_close(pfring *ring) {
  __pfring_netcope_release_resources(ring);
  close(ring->fd);
}

/* **************************************************** */

int pfring_netcope_stats(pfring *ring, pfring_stat *stats) {
  pfring_netcope *netcope = (pfring_netcope *) ring->priv_data;
  u_int64_t total, received, dropped = 0, bufoverflow, error;

  nsf_rx_read_frame_counters_basic_interface(netcope->nsf,
    netcope->port_id, &total, &received, &dropped, &bufoverflow, &error);

  stats->recv = netcope->recv;
  stats->drop = dropped; /* dropped = bufoverflow + error */

  return 0;
}

/* **************************************************** */

int pfring_netcope_set_direction(pfring *ring, packet_direction direction) {
  if (direction == rx_only_direction || direction == rx_and_tx_direction) {
    return setsockopt(ring->fd, 0, SO_SET_PACKET_DIRECTION, &direction, sizeof(direction));
  }

  return -1;
}

/* **************************************************** */

int pfring_netcope_get_bound_device_ifindex(pfring *ring, int *if_index) {
  pfring_netcope *netcope = (pfring_netcope *) ring->priv_data;
  *if_index = netcope->port_id;
  return 0;
}

/* **************************************************** */

u_int32_t pfring_netcope_get_interface_speed(pfring *ring) {
  pfring_netcope *netcope = (pfring_netcope *) ring->priv_data;
  nsf_speed_t speed;
  nsf_error_t err;

  err = nsf_rx_get_link_speed_interface(netcope->nsf, netcope->port_id, &speed);

  if (err) {
    fprintf(stderr, "nsf_rx_get_link_speed_interface failed: %s\n", nsf_error_string(err));
    return 0;
  }

  switch (speed) {
    case NSF_SPEED_10Mb:  return     10;
    case NSF_SPEED_100Mb: return    100;
    case NSF_SPEED_1Gb:   return   1000;
    case NSF_SPEED_10Gb:  return  10000;
    case NSF_SPEED_40Gb:  return  40000;
    case NSF_SPEED_100Gb: return 100000;
    default: break;
  }

  return 0;
}

/* **************************************************** */

int pfring_netcope_enable_ring(pfring *ring) {
  pfring_netcope *netcope = (pfring_netcope *) ring->priv_data;
  nsf_error_t err;
  uint64_t queue_rxmask;

  //TODO select the port_id (it will be possible with nsf 2.x)

  err = nsf_action(netcope->nsf, &netcope->action, NSF_RECEIVE_FULL, 0xFFFF, NSF_DISTRIBUTE_HASH /* NSF_DISTRIBUTE_ROUND_ROBIN */, 
    nsf_core_receive_queue_min(netcope->nsf),
    (netcope->queue_id == -1) ? nsf_core_receive_queue_min(netcope->nsf) : nsf_core_receive_queue_max(netcope->nsf),
    false /* send */, 0);

  if (err) {
    fprintf(stderr, "nsf_action failed: %s\n", nsf_error_string(err));
    goto error;
  }

  err = nsf_create_context(netcope->nsf, &netcope->context_id, &netcope->action);

  if (err) {
    fprintf(stderr, "nsf_create_context failed: %s\n", nsf_error_string(err));
    goto error;
  }

  err = nsf_open(netcope->nsf, &netcope->acc);

  if (err) {
    fprintf(stderr, "nsf_create_context failed: %s\n", nsf_error_string(err));
    goto error;
  }

#ifdef DEBUG
  printf("[NETCOPE] %u queues detected\n", nsf_get_rx_queues_count(netcope->nsf));
#endif

  if (netcope->queue_id == -1)
    queue_rxmask = (1 << nsf_get_rx_queues_count(netcope->nsf)) - 1;
  else
    queue_rxmask = (1 << netcope->queue_id);
  err = nsf_rx_stream_open(netcope->nsf, queue_rxmask, &netcope->rx_stream);

  if (err) {
    fprintf(stderr, "nsf_create_context failed: %s\n", nsf_error_string(err));
    goto error;
  }

  return 0;

error:
  return -1;
}

/* **************************************************** */

static int __pfring_netcope_ready(pfring *ring, int timeout_ms) {
  pfring_netcope *netcope = (pfring_netcope *) ring->priv_data;
  netcope->packet = nsf_rx_stream_read_next(netcope->rx_stream, &netcope->packet_len);
  return netcope->packet != NULL;
}

/* **************************************************** */

int pfring_netcope_recv(pfring *ring, u_char **buffer,
			u_int buffer_len,
			struct pfring_pkthdr *hdr,
			u_int8_t wait_for_incoming_packet) {
  pfring_netcope *netcope = (pfring_netcope *) ring->priv_data;
  unsigned char *payload;
  unsigned payload_len;
  nsf_header_t nsfhdr = { 0 };
  nsf_error_t err;
#if 0
  unsigned frame_len;
  unsigned char *frame;
#endif

check_next:

  if (netcope->packet != NULL || __pfring_netcope_ready(ring, wait_for_incoming_packet ? ring->poll_duration : 0) > 0) {

    err = nsf_parse_frame(netcope->packet, &nsfhdr, &payload, &payload_len);
    if (err) {
#ifdef DEBUG
      fprintf(stderr, "nsf_parse_frame failed: %s\n", nsf_error_string(err));
#endif
      goto check_next;
    }

    if (nsfhdr.type != NSF_INPUT_FRAME) {
#ifdef DEBUG
      fprintf(stderr, "Unsupported frame type: %u\n", nsfhdr.type);
#endif
      goto check_next;
    }

#ifdef DEBUG
    err = nsf_decode_frame(&nsfhdr, payload, payload_len, &frame, &frame_len);
    if (err) 
      fprintf(stderr, "nsf_decode_frame failed: %s\n", nsf_error_string(err));
#endif

#ifdef DEBUG
    printf("[NETCOPE] payload_len = %u frame_len = %u ts = %u.%u ts = %ju\n", 
      payload_len, nsfhdr.frame_size,
      le32toh(nsfhdr.timestamp_s), le32toh(nsfhdr.timestamp_ns),
      nsfhdr.timestamp);
#endif

    hdr->len = hdr->caplen = payload_len;
    hdr->caplen = min_val(hdr->caplen, ring->caplen);

    hdr->extended_hdr.pkt_hash = nsfhdr.hash;
    hdr->extended_hdr.if_index = nsfhdr.iface;
    hdr->extended_hdr.rx_direction = 1;

    hdr->ts.tv_sec = le32toh(nsfhdr.timestamp_s); // prepare PCAP packet header
    hdr->ts.tv_usec = le32toh(nsfhdr.timestamp_ns) / 1000; // don't forget to apply ns to us conversion
    hdr->extended_hdr.timestamp_ns = ((u_int64_t) le32toh(nsfhdr.timestamp_s) * 1000000000) + le32toh(nsfhdr.timestamp_ns);

    if (likely(buffer_len == 0)) {
      *buffer = payload;
    } else {
      if (buffer_len < hdr->caplen)
        hdr->caplen = buffer_len;
      memcpy(*buffer, payload, hdr->caplen);
      memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(hdr->extended_hdr.parsed_pkt));
      pfring_parse_pkt(*buffer, hdr, 4, 0 /* ts */, 1 /* hash */);
    }

    netcope->recv++;
    netcope->packet = NULL;
    return 1;
  }

  if (wait_for_incoming_packet) {
    if (unlikely(ring->break_recv_loop)) {
      ring->break_recv_loop = 0;
      return -1;
    }

    goto check_next;
  }

  return 0;
}

/* **************************************************** */

int pfring_netcope_poll(pfring *ring, u_int wait_duration) {
  pfring_netcope *netcope = (pfring_netcope *) ring->priv_data;
  return (netcope->packet != NULL || __pfring_netcope_ready(ring, wait_duration));
}

/* **************************************************** */

int  pfring_netcope_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet) {

  //TODO

  return -1;
}

/* **************************************************** */

void pfring_netcope_flush_tx_packets(pfring *ring) {

  //TODO

}

/* **************************************************** */

int pfring_netcope_add_hw_rule(pfring *ring, hw_filtering_rule *rule) {
  pfring_netcope *netcope = (pfring_netcope *) ring->priv_data;
  nsf_action_t action;                
  nsf_flow_id_t flow_id;
  union nsf_ip sip;
  union nsf_ip dip;                   
  nsf_error_t err;

  if (rule->rule_family_type != generic_flow_tuple_rule) return -1;
  if (rule->rule_family.flow_tuple_rule.action != flow_drop_rule) return -1;

  err = nsf_action(netcope->nsf, &action, NSF_RECEIVE_DROP, 0xFFFF, 
    NSF_DISTRIBUTE_ROUND_ROBIN /* ignored here */,
    nsf_core_receive_queue_min(netcope->nsf),
    (netcope->queue_id == -1) ? nsf_core_receive_queue_min(netcope->nsf) : nsf_core_receive_queue_max(netcope->nsf),
    false, 0);

  if (err) return -1;

  if (rule->rule_family.flow_tuple_rule.ip_version == 4) {
    sip.v4.s_addr = rule->rule_family.flow_tuple_rule.src_ip.v4;
    dip.v4.s_addr = rule->rule_family.flow_tuple_rule.dst_ip.v4;
  } else {
    memcpy(sip.v6.s6_addr, rule->rule_family.flow_tuple_rule.src_ip.v6.s6_addr, sizeof(struct in6_addr));
    memcpy(dip.v6.s6_addr, rule->rule_family.flow_tuple_rule.dst_ip.v6.s6_addr, sizeof(struct in6_addr));
  }

  err = nsf_flow_id(netcope->nsf, &flow_id, 
    rule->rule_family.flow_tuple_rule.interface,
    rule->rule_family.flow_tuple_rule.ip_version,    
    &sip, &dip,
    rule->rule_family.flow_tuple_rule.protocol,
    rule->rule_family.flow_tuple_rule.src_port, 
    rule->rule_family.flow_tuple_rule.dst_port, 
    0, 0);

  if (err) return -1;

  nsf_send_command(netcope->acc, &netcope->context_id, &flow_id, 
    &action, NSF_COMMAND_ADD_MARK_HEAVY);

  return -1;
}

/* **************************************************** */

