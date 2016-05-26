/*
 *
 * (C) 2015 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 *
 */

#ifndef _PFRING_MOD_MLX_H_
#define _PFRING_MOD_MLX_H_

#include "pfring.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <malloc.h>

#include <infiniband/verbs.h>

#define MTU 		1536
#define WC_POLL_FETCH 	16
#define MAX_SGE		1
#define MAX_INLINE	64
#define HW_CRC_ADDITION	4
#define POST_LIST_SIZE	64

struct mlx_stats {
  u_int64_t total_bytes, total_packets;
};

struct mlx_ring {
  void *buf;
  struct ibv_qp *qp;
  struct ibv_cq *cq;
  struct ibv_mr *mr;
  struct ibv_pd *pd;
  struct ibv_wc *wc;
  struct ibv_sge *sg;
  struct mlx_stats stats;
  struct ibv_context *context;
};

typedef struct {
  struct mlx_ring ring;
  u_int num_entries, port_num;
  u_int16_t rx_watermark, num_rx_queued_packets, last_processed_queued_packet;
  struct ibv_recv_wr *wr;
  struct ibv_exp_flow *flow;
  struct ibv_exp_flow *uc_flow;

#ifdef LICENSE_CHECK
  u_int32_t demo_check_counter;
#endif
} pfring_mlx;


int  pfring_mlx_open(pfring *ring);
void pfring_mlx_close(pfring *ring);
int  pfring_mlx_stats(pfring *ring, pfring_stat *stats);
int  pfring_mlx_recv(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_mlx_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
int  pfring_mlx_set_poll_watermark(pfring *ring, u_int16_t watermark);
int  pfring_mlx_set_poll_duration(pfring *ring, u_int duration);
int  pfring_mlx_poll(pfring *ring, u_int wait_duration);
int  pfring_mlx_set_direction(pfring *ring, packet_direction direction);
int  pfring_mlx_enable_ring(pfring *ring);
int  pfring_mlx_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_mlx_get_bound_device_ifindex(pfring *ring, int *if_index);
u_int32_t pfring_mlx_get_interface_speed(pfring *ring);

#endif /* _PFRING_MOD_MLX_H_ */
