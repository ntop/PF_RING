/*
 *
 * (C) 2014 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 */

/* ********************************* */

#include "pfring.h"
#include "pfring_hw_timestamp.h"

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

