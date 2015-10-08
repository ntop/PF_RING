/*
 *
 * (C) 2015 - ntop.org
 *
 * Module for supporting Myricom NICs (APIv4)
 *
 */

#include "pfring_mod_myricom.h"
#include "pfring_mod.h" /* to print stats under /proc */

//#define DEBUG

/* **************************************************** */

static void __pfring_myri_release_resources(pfring *ring) {
  pfring_myri *myricom = (pfring_myri *) ring->priv_data;

  if (myricom) {
    if (ring->mode != send_only_mode) {
      snf_ring_close(myricom->hring);
      snf_close(myricom->hsnf);
    }

    if (ring->mode != recv_only_mode) {
      snf_inject_close(myricom->hinj);
    }

    free(ring->priv_data);
    ring->priv_data = NULL;
  }
}

/* **************************************************** */

int pfring_myri_open(pfring *ring) {
  pfring_myri *myricom;

  ring->close              = pfring_myri_close;
  ring->stats              = pfring_myri_stats;
  ring->recv               = pfring_myri_recv;
  ring->poll               = pfring_myri_poll;
  ring->set_direction      = pfring_myri_set_direction;
  ring->enable_ring        = pfring_myri_enable_ring;
  ring->get_bound_device_ifindex = pfring_myri_get_bound_device_ifindex;
  ring->send             = pfring_myri_send;

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

  ring->priv_data = calloc(1, sizeof(pfring_myri));

  if (ring->priv_data == NULL)
    goto free_private;

  myricom = (pfring_myri *) ring->priv_data;

  /*
   * Device name X where
   * X device ID
   */

  sscanf(ring->device_name, "%u", &myricom->device_id);

  snf_init(SNF_VERSION_API);

  return 0;

 free_private:
  __pfring_myri_release_resources(ring);

  return -1;
}

/* **************************************************** */

void pfring_myri_close(pfring *ring) {
  __pfring_myri_release_resources(ring);
  close(ring->fd);
}

/* **************************************************** */

int pfring_myri_stats(pfring *ring, pfring_stat *stats) {
  pfring_myri *myricom = (pfring_myri *) ring->priv_data;
  struct snf_ring_stats myri_stats;
  int rc;

  rc = snf_ring_getstats(myricom->hring, &myri_stats);

  if (rc)
    return -1;

  stats->recv = myri_stats.ring_pkt_recv;

  stats->drop =
    myri_stats.nic_pkt_overflow +
    myri_stats.ring_pkt_overflow +
    myri_stats.nic_pkt_bad;

  //myri_stats.nic_bytes_recv

  return 0;
}

/* **************************************************** */

int pfring_myri_set_direction(pfring *ring, packet_direction direction) {
  if (direction == rx_only_direction || direction == rx_and_tx_direction) {
    return setsockopt(ring->fd, 0, SO_SET_PACKET_DIRECTION, &direction, sizeof(direction));
  }

  return -1;
}

/* **************************************************** */

int pfring_myri_get_bound_device_ifindex(pfring *ring, int *if_index) {
  //pfring_myri *myricom = (pfring_myri *) ring->priv_data;

  *if_index = 0; /* TODO */
  return 0;
}

/* **************************************************** */

int pfring_myri_enable_ring(pfring *ring) {
  pfring_myri *myricom = (pfring_myri *) ring->priv_data;
  int rc;
  //struct snf_rss_params rssp;
  //rssp.mode = SNF_RSS_FLAGS;
  //rssp.params.rss_flags = SNF_RSS_IP | SNF_RSS_SRC_PORT | SNF_RSS_DST_PORT;

#ifdef DEBUG
  printf("[MYRICOM] Opening myri device=%u\n", myricom->device_id);
#endif

  if (ring->mode != send_only_mode) {
    rc = snf_open(
		  myricom->device_id,
		  0 /* num rings (0: read from env var) */,
		  NULL /* &rssp (NULL: default RSS settings or from env var) */,
		  0 /* ring size */,
		  -1, /* flags */
		  &myricom->hsnf
		  );

    if (rc) {
      errno = rc;
      perror("Can't open snf for sniffing");
      return -1;
    }

    rc = snf_ring_open(myricom->hsnf, &myricom->hring);

    if (rc) {
      errno = rc;
      perror("Can't open a receive ring for sniffing");
      return -1;
    }

    rc = snf_start(myricom->hsnf);

    if (rc) {
      errno = rc;
      perror("Can't start packet capture for sniffing");
      return -1;
    }
  }

  if (ring->mode != recv_only_mode) {
    //rc = snf_netdev_reflect_enable(myricom->hsnf, &myricom->hnetdev);
    rc = snf_inject_open(myricom->device_id, 0, &myricom->hinj);

    if (rc) {
      errno = rc;
      perror("Can't open port for injecting packets");
      return -1;
    }
  }

  return 0;
}

/* **************************************************** */

static int __pfring_myri_ready(pfring *ring, int timeout_ms) {
  pfring_myri *myricom = (pfring_myri *) ring->priv_data;
  int rc;

  //check_again:
  rc = snf_ring_recv(myricom->hring, timeout_ms, &myricom->recv_req);

  //if (rc == EAGAIN || rc == EINTR)
  //  goto check_again;

  return !rc;
}

/* **************************************************** */

int pfring_myri_recv(pfring *ring, u_char **buffer,
		     u_int buffer_len,
		     struct pfring_pkthdr *hdr,
		     u_int8_t wait_for_incoming_packet) {
  pfring_myri *myricom = (pfring_myri *) ring->priv_data;

 check_pfring_myri_ready:
  if (myricom->packet_ready ||
      __pfring_myri_ready(ring, wait_for_incoming_packet ? ring->poll_duration : 0) > 0) {
    myricom->packet_ready = 0;

    hdr->len = hdr->caplen = myricom->recv_req.length;
    hdr->caplen = min_val(hdr->caplen, ring->caplen);

    if (likely(buffer_len == 0)) {
      *buffer = (uint8_t *) myricom->recv_req.pkt_addr;
    } else {
      if (buffer_len < hdr->caplen)
        hdr->caplen = buffer_len;
      memcpy(*buffer, (uint8_t *) myricom->recv_req.pkt_addr, hdr->caplen);
      memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(hdr->extended_hdr.parsed_pkt));
      pfring_parse_pkt(*buffer, hdr, 4, 0 /* ts */, 1 /* hash */);
    }

    hdr->extended_hdr.pkt_hash = 0; //TODO available?
    hdr->extended_hdr.rx_direction = 1;
    hdr->extended_hdr.timestamp_ns = myricom->recv_req.timestamp;

    return 1;
  }

  if (wait_for_incoming_packet) {
    if (unlikely(ring->break_recv_loop)) {
      ring->break_recv_loop = 0;
      return -1;
    }

    goto check_pfring_myri_ready;
  }

  return 0;
}

/* **************************************************** */

int pfring_myri_poll(pfring *ring, u_int wait_duration) {
  pfring_myri *myricom = (pfring_myri *) ring->priv_data;
  if (myricom->packet_ready) return 1;
  myricom->packet_ready = __pfring_myri_ready(ring, wait_duration);
  return myricom->packet_ready;
}

/* **************************************************** */

int  pfring_myri_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet) {
  pfring_myri *myricom = (pfring_myri *) ring->priv_data;
  int rc;

  //rc = snf_netdev_reflect(myricom->hnetdev, pkt, pkt_len);
  rc = snf_inject_send(myricom->hinj, 0 /* -1 to wait instead of active poll */, 0, pkt, pkt_len);

  return (rc == 0 ? pkt_len : -1);
}

/* **************************************************** */

