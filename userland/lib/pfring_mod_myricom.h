/*
 *
 * (C) 2015    - ntop.org
 *
 */

#ifndef _PFRING_MOD_MYRICOM_H_
#define _PFRING_MOD_MYRICOM_H_

#include "pfring.h"

#include "snf.h"

typedef struct {
  int device_id;

  /* RX */
  snf_handle_t hsnf;
  snf_ring_t hring;
  struct snf_recv_req recv_req;
  int packet_ready;

  /* TX */
  //snf_netdev_reflect_t hnetdev;
  snf_inject_t hinj;
} pfring_myri;


int  pfring_myri_open(pfring *ring);
void pfring_myri_close(pfring *ring);
int  pfring_myri_stats(pfring *ring, pfring_stat *stats);
int  pfring_myri_recv(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_myri_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
int  pfring_myri_set_poll_watermark(pfring *ring, u_int16_t watermark);
int  pfring_myri_set_poll_duration(pfring *ring, u_int duration);
int  pfring_myri_poll(pfring *ring, u_int wait_duration);
int  pfring_myri_set_direction(pfring *ring, packet_direction direction);
int  pfring_myri_enable_ring(pfring *ring);
int  pfring_myri_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_myri_get_bound_device_ifindex(pfring *ring, int *if_index);

#endif /* _PFRING_MOD_MYRICOM_H_ */
