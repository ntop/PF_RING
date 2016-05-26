/*
 *
 * (C) 2015 - ntop.org
 *
 * Module for supporting InveaTech NICs
 *
 */

#include "pfring_mod_invea.h"
#include "pfring_mod.h" /* to print stats under /proc */

//#define DEBUG

/* **************************************************** */

static void __pfring_invea_release_resources(pfring *ring) {
  pfring_invea *invea = (pfring_invea *) ring->priv_data;

  if (invea) {
#ifdef INVEA_DROP_STATS 
    cs_space_unmap(invea->dev, &invea->ibuf_space);
    cs_detach(&invea->dev);
#endif

    szedata_close(invea->sze);

    free(ring->priv_data);
    ring->priv_data = NULL;
  }
}

/* **************************************************** */

int pfring_invea_open(pfring *ring) {
  pfring_invea *invea;
  char *sze_dev = "/dev/szedataII0";

  ring->close              = pfring_invea_close;
  ring->stats              = pfring_invea_stats;
  ring->recv               = pfring_invea_recv;
  ring->poll               = pfring_invea_poll;
  ring->set_direction      = pfring_invea_set_direction;
  ring->enable_ring        = pfring_invea_enable_ring;
  ring->get_bound_device_ifindex = pfring_invea_get_bound_device_ifindex;
  ring->send               = pfring_invea_send;
  ring->flush_tx_packets   = pfring_invea_flush_tx_packets;
  ring->get_interface_speed = pfring_invea_get_interface_speed;

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

  ring->priv_data = calloc(1, sizeof(pfring_invea));

  if (ring->priv_data == NULL)
    goto free_private;

  invea = (pfring_invea *) ring->priv_data;

  /*
   * Device name X where
   * X device ID
   */

  sscanf(ring->device_name, "%u", &invea->device_id);

  invea->sze = szedata_open(sze_dev);

  if (invea->sze == NULL) {
    fprintf(stderr, "szedata_open failed");
    goto free_private;
  }

  SZE2_RX_POLL_TIMEOUT = 5000; /* set 5s timeout for szedata_read_next */

  return 0;

 free_private:
  __pfring_invea_release_resources(ring);

  return -1;
}

/* **************************************************** */

void pfring_invea_close(pfring *ring) {
  __pfring_invea_release_resources(ring);
  close(ring->fd);
}

/* **************************************************** */

int pfring_invea_stats(pfring *ring, pfring_stat *stats) {
  pfring_invea *invea = (pfring_invea *) ring->priv_data;

  stats->recv = invea->recv;
  stats->drop = 0;
#ifdef INVEA_DROP_STATS
  //cs_space_write_4(dev, ibuf_space, MY_IBUF_EN, 1);
  stats->drop += cs_space_read_4(invea->dev, ibuf_space, MY_IBUF_CNT_RECVERR);
  stats->drop += cs_space_read_4(invea->dev, ibuf_space, MY_IBUF_CNT_OVERFLOW);
#endif

  return 0;
}

/* **************************************************** */

int pfring_invea_set_direction(pfring *ring, packet_direction direction) {
  if (direction == rx_only_direction || direction == rx_and_tx_direction) {
    return setsockopt(ring->fd, 0, SO_SET_PACKET_DIRECTION, &direction, sizeof(direction));
  }

  return -1;
}

/* **************************************************** */

int pfring_invea_get_bound_device_ifindex(pfring *ring, int *if_index) {
  pfring_invea *invea = (pfring_invea *) ring->priv_data;

  *if_index = invea->device_id;
  return 0;
}

/* **************************************************** */

u_int32_t pfring_invea_get_interface_speed(pfring *ring) {
  //pfring_invea *invea = (pfring_invea *) ring->priv_data;

  /* TODO */

  return 0;
}

/* **************************************************** */

int pfring_invea_enable_ring(pfring *ring) {
  pfring_invea *invea = (pfring_invea *) ring->priv_data;
  unsigned int rx = (ring->mode != send_only_mode) ? (1 << invea->device_id) : 0;
  unsigned int tx = (ring->mode != recv_only_mode) ? (1 << invea->device_id) : 0;
  int rc;

#ifdef DEBUG
  printf("subscribing: RX interface mask-0x%02hx; TX interface mask-0x%02hx\n", rx, tx);
  printf("poll timeouts: RX %ums; TX %ums\n", SZE2_RX_POLL_TIMEOUT, SZE2_TX_POLL_TIMEOUT);
#endif

  rc = szedata_subscribe3(invea->sze, &rx, &tx);

  if (rc) {
    fprintf(stderr, "szedata_subscribe3 failure\n");
    return -1;
  }

#ifdef DEBUG 
  printf("subscribed: RX 0x%02hx; TX 0x%02hx\n\n", rx, tx);
#endif

  rc = szedata_start(invea->sze);

  if (rc) {
    fprintf(stderr, "szedata_start failure\n");
    return -1;
  }

#ifdef DEBUG
  printf("[INVEATECH] Opening invea device=%u\n", invea->device_id);
#endif

#ifdef INVEA_DROP_STATS 
  if ((rc = cs_attach_noex(&invea->dev, CS_PATH_DEV(0))) != 0) {
    fprintf(stderr, "%s: cs_attach_noex failed (%s).", strerror(rc));
    return -1;
  }

  if (cs_identify(invea->dev, &invea->board, NULL, NULL) != 0) {
    fprintf(stderr, "%s: cs_identify failed (%s).", strerror(rc));
    return -1;
  }

  if (!strncmp(invea->board, COMBO_80G, sizeof(COMBO_80G)-1)) {
    invea->ibuf_base_addr = MY_IBUF_80G_100G_BASE_ADDR;
    invea->ibuf_size = MY_IBUF_80G_100G_SIZE;
  } else if (!strncmp(invea->board, COMBO_100G, sizeof(COMBO_100G)-1)) {
    invea->ibuf_base_addr = MY_IBUF_80G_100G_BASE_ADDR;
    invea->ibuf_size = MY_IBUF_80G_100G_SIZE;
  } else {
    fprintf(stderr, "%s: Unknown card (%s).", strerror(rc));
    return -1;
  }

  if ((rc = cs_space_map(invea->dev, &invea->ibuf_space, CS_SPACE_FPGA, invea->ibuf_size, invea->ibuf_base_addr, 0)) != 0) {
    fprintf(stderr, "%s: cs_space_map failed to map component (%s).", strerror(rc));
    return -1;
  }
#endif

  return 0;
}

/* **************************************************** */

static int __pfring_invea_ready(pfring *ring, int timeout_ms) {
  pfring_invea *invea = (pfring_invea *) ring->priv_data;
  //TODO timeout_ms
  invea->packet = szedata_read_next(invea->sze, &invea->packet_len);
  return (invea->packet != NULL);
}

/* **************************************************** */

int pfring_invea_recv(pfring *ring, u_char **buffer,
		     u_int buffer_len,
		     struct pfring_pkthdr *hdr,
		     u_int8_t wait_for_incoming_packet) {
  pfring_invea *invea = (pfring_invea *) ring->priv_data;
  unsigned char *data, *hw_data;
  unsigned int data_len, hw_data_len;
  unsigned int segsize;
  uint32_t ts_s, ts_ns;
#ifdef DEBUG
  unsigned int iface, dma, flags, label;
#endif

 check_pfring_invea_ready:

  if (invea->packet != NULL || 
      __pfring_invea_ready(ring, wait_for_incoming_packet ? ring->poll_duration : 0) > 0) {

    segsize = szedata_decode_packet(invea->packet, &data, &hw_data, &data_len, &hw_data_len);

#ifdef DEBUG
    printf("Hw data = %04u ", hw_data_len);
    for (i = 0; i < hw_data_len; i++)
      printf("0x%02x ", *(hw_data + i));
    printf("\nData = %04u ", data_len);
    for (i = 0; i < data_len; i++)
      printf("0x%02x ", *(data + i));
    printf("\n");

    iface = (*(hw_data + IFACE_OFFSET)) & 0x0f;
    dma   = (((*(hw_data + DMA_OFFSET)) >> 4) & 0x0f);
    flags = (*(hw_data + FLAGS_OFFSET));
    label = le16toh(*(hw_data + LABEL_OFFSET));

    printf("SZE header\n");
    printf("\tSegment size   = %u\n", segsize);
    printf("\tHardware size  = %u\n", hw_data_len);
    printf("\tEth. interface = %u\n", iface);
    printf("\tDMA queue      = %u\n", dma);
    printf("\tFlags          = %u\n", flags);
    printf("\tLabel          = %u\n", label);
#endif

    ts_ns =  *((uint32_t*) (hw_data + (uint32_t) TIMESTAMP_NS_OFFSET));
    ts_s  =  *((uint32_t*) (hw_data + (uint32_t) TIMESTAMP_S_OFFSET));

    hdr->len = hdr->caplen = data_len;
    hdr->caplen = min_val(hdr->caplen, ring->caplen);

    hdr->extended_hdr.pkt_hash = 0; //TODO available?
    hdr->extended_hdr.if_index = invea->device_id;
    hdr->extended_hdr.rx_direction = 1;

    hdr->ts.tv_sec  = ts_s;
    hdr->ts.tv_usec = ts_ns / 1000;
    hdr->extended_hdr.timestamp_ns = ((u_int64_t) ts_s * 1000000000) + ts_ns;

    if (likely(buffer_len == 0)) {
      *buffer = data;
    } else {
      if (buffer_len < hdr->caplen)
        hdr->caplen = buffer_len;
      memcpy(*buffer, data, hdr->caplen);
      memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(hdr->extended_hdr.parsed_pkt));
      pfring_parse_pkt(*buffer, hdr, 4, 0 /* ts */, 1 /* hash */);
    }

    invea->recv++;

    invea->packet = NULL;

    return 1;
  }

  if (wait_for_incoming_packet) {
    if (unlikely(ring->break_recv_loop)) {
      ring->break_recv_loop = 0;
      return -1;
    }

    goto check_pfring_invea_ready;
  }

  return 0;
}

/* **************************************************** */

int pfring_invea_poll(pfring *ring, u_int wait_duration) {
  pfring_invea *invea = (pfring_invea *) ring->priv_data;
  return (invea->packet != NULL || __pfring_invea_ready(ring, wait_duration));
}

/* **************************************************** */

int  pfring_invea_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet) {
  pfring_invea *invea = (pfring_invea *) ring->priv_data;
  int rc;

  if (flush_packet)
    rc = szedata_prepare_and_try_write_next(invea->sze, NULL, 0, (u_char *) pkt, pkt_len, invea->device_id);
  else
    rc = szedata_burst_write_next(invea->sze, NULL, 0, (u_char *) pkt, pkt_len, invea->device_id);

  return (rc == 0 ? pkt_len : -1);
}

/* **************************************************** */

void pfring_invea_flush_tx_packets(pfring *ring) {
  //pfring_invea *invea = (pfring_invea *) ring->priv_data;  
  //FIXX szedata_burst_write_flush(invea->sze, invea->device_id);
}

/* **************************************************** */

