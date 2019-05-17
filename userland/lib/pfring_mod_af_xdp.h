/*
 *
 * (C) 2019 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 *
 */

#ifndef _PFRING_MOD_AF_XDP_H_
#define _PFRING_MOD_AF_XDP_H_

int pfring_mod_af_xdp_open(pfring *ring);
void pfring_mod_af_xdp_close(pfring *ring);
int pfring_mod_af_xdp_stats(pfring *ring, pfring_stat *stats);
int pfring_mod_af_xdp_is_pkt_available(pfring *ring);
int pfring_mod_af_xdp_recv(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int pfring_mod_af_xdp_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
int pfring_mod_af_xdp_get_selectable_fd(pfring *ring);
int pfring_mod_af_xdp_set_direction(pfring *ring, packet_direction direction);
int pfring_mod_af_xdp_poll(pfring *ring, u_int wait_duration);
int pfring_mod_af_xdp_enable_ring(pfring *ring);

int pfring_mod_af_xdp_get_bound_device_address(pfring *ring, u_char mac_address[6]);
int pfring_mod_af_xdp_get_bound_device_ifindex(pfring *ring, int *if_index);
u_int8_t pfring_mod_af_xdp_get_num_rx_channels(pfring *ring);

#endif /* _PFRING_MOD_AF_XDP_H_ */
