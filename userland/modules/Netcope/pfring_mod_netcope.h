/*
 *
 * (C) 2018 - ntop.org
 *
 * Module for supporting Netcope NICs
 *
 */

#ifndef _PFRING_MOD_NETCOPE_H_
#define _PFRING_MOD_NETCOPE_H_

#include "pfring.h"

int  pfring_netcope_open(pfring *ring);
void pfring_netcope_close(pfring *ring);
int  pfring_netcope_stats(pfring *ring, pfring_stat *stats);
int  pfring_netcope_recv(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_netcope_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
void pfring_netcope_flush_tx_packets(pfring *ring);
int  pfring_netcope_set_poll_watermark(pfring *ring, u_int16_t watermark);
int  pfring_netcope_set_poll_duration(pfring *ring, u_int duration);
int  pfring_netcope_poll(pfring *ring, u_int wait_duration);
int  pfring_netcope_set_direction(pfring *ring, packet_direction direction);
int  pfring_netcope_enable_ring(pfring *ring);
int  pfring_netcope_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_netcope_get_bound_device_ifindex(pfring *ring, int *if_index);
u_int32_t pfring_netcope_get_interface_speed(pfring *ring);
int pfring_netcope_add_hw_rule(pfring *ring, hw_filtering_rule *rule);

#endif /* _PFRING_MOD_NETCOPE_H_ */
