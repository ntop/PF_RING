/*
 *
 * (C) 2014-2020 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 *
 */

/* ********************************* */

#include "pfring.h"
#include "pfring_hw_timestamp.h"

#include <linux/ip.h>

static int32_t thiszone = 0;

/* ********************************* */

int pfring_read_ixia_hw_timestamp(u_char *buffer, 
				  u_int32_t buffer_len, struct timespec *ts) {
  struct ixia_hw_ts* ixia;
  u_char *signature;

  ixia = (struct ixia_hw_ts *) &buffer[buffer_len - IXIA_TS_LEN];
  signature = (u_char *) &ixia->signature;

  if((signature[0] == 0xAF) && (signature[1] == 0x12)) {
    if(unlikely(thiszone == 0)) thiszone = gmt_to_local(0);    
    ts->tv_sec = ntohl(ixia->sec) - thiszone;
    ts->tv_nsec = ntohl(ixia->nsec);
    return IXIA_TS_LEN;
  }

  ts->tv_sec = ts->tv_nsec = 0;
  return 0;
}

/* ********************************* */

void pfring_handle_ixia_hw_timestamp(u_char* buffer, struct pfring_pkthdr *hdr) {
  struct timespec ts;
  int ts_size;

  if(unlikely(hdr->caplen != hdr->len)) 
    return; /* full packet only */

  ts_size = pfring_read_ixia_hw_timestamp(buffer, hdr->len, &ts);

  if(likely(ts_size > 0)) {
    hdr->caplen = hdr->len = hdr->len - ts_size;
    hdr->ts.tv_sec = ts.tv_sec, hdr->ts.tv_usec = ts.tv_nsec/1000;
    hdr->extended_hdr.timestamp_ns = (((u_int64_t) ts.tv_sec) * 1000000000) + ts.tv_nsec;
  }
}

/* ********************************* */

int pfring_read_arista_keyframe(u_char *buffer, u_int32_t buffer_len,
                                struct timespec *ts, u_int32_t *ticks) {
  struct arista_7150_keyframe_hw_ts *kf;
  u_char bcmac[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  struct ethhdr *eh = (struct ethhdr*) buffer;
  struct iphdr *ip;
  u_int32_t offset = sizeof(struct ethhdr);
  u_int16_t eth_type = ntohs(eh->h_proto);
  u_int64_t ns;

  if (memcmp(eh->h_dest, bcmac, sizeof(bcmac)) != 0)
    return -1;

  eth_type = ntohs(eh->h_proto);

  while (eth_type == ETH_P_8021Q /* 802.1q (VLAN) */ && offset+sizeof(struct eth_vlan_hdr) <= buffer_len) { /* More QinQ */
    struct eth_vlan_hdr *vh;
    vh = (struct eth_vlan_hdr *) &buffer[offset];
    offset += sizeof(struct eth_vlan_hdr);
    eth_type = ntohs(vh->h_proto);
  }

  if (eth_type != 0x0800 /* IPv4 */ ||
      buffer_len < offset+sizeof(struct iphdr))
    return -1;

  ip = (struct iphdr *)(&buffer[offset]);

  if (ip->protocol != 253)
    return -1;

  offset += ip->ihl*4;

  if (buffer_len < offset + sizeof(struct arista_7150_keyframe_hw_ts))
    return -1;

  kf = (struct arista_7150_keyframe_hw_ts *) &buffer[offset];

  ns = be64toh(kf->utc_nsec);
  ts->tv_sec = ns/1000000000;
  ts->tv_nsec = ns%1000000000;

  *ticks = ntohl(kf->asic_time.ticks);

#if 1
  printf("[ARISTA][Key-Frame] Ticks: %u UTC: %ju.%ju\n", *ticks, ts->tv_sec, ts->tv_nsec);
#endif

  return 0;
}

/* ********************************* */

int pfring_read_arista_hw_timestamp(u_char *buffer, 
				    u_int32_t buffer_len, struct timespec *ts) {
  struct arista_7150_pkt_hw_ts *fcsts;
  u_int32_t ticks;

  fcsts = (struct arista_7150_pkt_hw_ts *) &buffer[buffer_len - sizeof(struct arista_7150_pkt_hw_ts)];

  ticks = ntohl(fcsts->asic.ticks);

#if 1
  printf("[ARISTA][Packet] Ticks: %u\n", ticks);
#endif

  return 0;
}

/* ********************************* */

void pfring_handle_arista_hw_timestamp(u_char* buffer, struct pfring_pkthdr *hdr) {
  struct timespec ts = { 0 };
  u_int32_t ticks;

  if(unlikely(hdr->caplen != hdr->len))
    return; /* full packet only */

  if (pfring_read_arista_keyframe(buffer, hdr->len, &ts, &ticks) == 0) {
    /* Thi was a keyframe: TODO update the time and skip the packet */
  } else {
    /* This is a packet, reading the timestamp */
    pfring_read_arista_hw_timestamp(buffer, hdr->len, &ts);
  }
}

/* ********************************* */

int pfring_read_vss_apcon_hw_timestamp(u_char *buffer, u_int32_t buffer_len, struct timespec *ts) {
  struct vss_apcon_hw_ts* vss_apcon = (struct vss_apcon_hw_ts *)&buffer[buffer_len - VSS_APCON_TS_LEN];

  if(unlikely(thiszone == 0)) thiszone = gmt_to_local(0);    
  ts->tv_sec = ntohl(vss_apcon->sec) - thiszone;
  ts->tv_nsec = ntohl(vss_apcon->nsec);
  return VSS_APCON_TS_LEN;
}

/* ********************************* */

void pfring_handle_vss_apcon_hw_timestamp(u_char* buffer, struct pfring_pkthdr *hdr) {
  struct timespec ts;
  int ts_size;

  if(unlikely(hdr->caplen != hdr->len)) 
    return; /* full packet only */

  ts_size = pfring_read_vss_apcon_hw_timestamp(buffer, hdr->len, &ts);

  if(likely(ts_size > 0)) {
    hdr->caplen = hdr->len = hdr->len - ts_size;
    hdr->ts.tv_sec = ts.tv_sec, hdr->ts.tv_usec = ts.tv_nsec/1000;
    hdr->extended_hdr.timestamp_ns = (((u_int64_t) ts.tv_sec) * 1000000000) + ts.tv_nsec;
  }
}

/* ********************************* */

