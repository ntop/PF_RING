/*
 *
 * (C) 2014-22 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 *
 */

#ifndef _PFRING_MOD_PCAP_H_
#define _PFRING_MOD_PCAP_H_


typedef struct {
  pcap_t  *pd;
  u_int8_t is_pcap_file;
  int fd;
} pfring_pcap;

int  pfring_mod_pcap_open(pfring *ring);
void pfring_mod_pcap_close(pfring *ring);
int  pfring_mod_pcap_stats(pfring *ring, pfring_stat *stats);
int  pfring_mod_pcap_recv(pfring *ring, u_char** buffer, u_int buffer_len,
			  struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_mod_pcap_poll(pfring *ring, u_int wait_duration);
int  pfring_mod_pcap_enable_ring(pfring *ring);
int  pfring_mod_pcap_stats(pfring *ring, pfring_stat *stats);
int  pfring_mod_pcap_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_mod_pcap_set_poll_watermark(pfring *ring, u_int16_t watermark);
int  pfring_mod_pcap_set_bpf_filter(pfring *ring, char *filter_buffer);

#endif /* _PFRING_MOD_PCAP_H_ */
