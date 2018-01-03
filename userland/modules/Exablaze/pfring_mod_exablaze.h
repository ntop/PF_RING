/*
 *
 * (C) 2016 - ntop.org
 *
 */

#ifndef _PFRING_MOD_EXABLAZE_H_
#define _PFRING_MOD_EXABLAZE_H_

#include "pfring.h"

#include <exanic/config.h>
#include <exanic/fifo_rx.h>
#include <exanic/fifo_tx.h>
#include <exanic/filter.h>
#include <exanic/exanic.h>
#include <exanic/time.h>

typedef struct {
  exanic_t *exanic;
  u_char pkt[1514], mac_address[6];
  int device_id, port_number, channel_id, if_index;
  exanic_rx_t *rx;
  exanic_tx_t *tx;
  u_int64_t recv;
} pfring_exablaze;

int  pfring_exablaze_open(pfring *ring);
void pfring_exablaze_close(pfring *ring);
int  pfring_exablaze_stats(pfring *ring, pfring_stat *stats);
int  pfring_exablaze_recv(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_exablaze_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
int  pfring_exablaze_poll(pfring *ring, u_int wait_duration);
int  pfring_exablaze_set_direction(pfring *ring, packet_direction direction);
int  pfring_exablaze_enable_ring(pfring *ring);
int  pfring_exablaze_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_exablaze_get_bound_device_ifindex(pfring *ring, int *if_index);
u_int32_t pfring_exablaze_get_interface_speed(pfring *ring);
int pfring_exablaze_get_bound_device_address(pfring *ring, u_char mac_address[6]);

#endif /* _PFRING_MOD_EXABLAZE_H_ */
