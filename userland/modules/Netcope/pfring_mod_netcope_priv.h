/*
 *
 * (C) 2018 - ntop.org
 *
 * Module for supporting Netcope NICs
 *
 */

#ifndef _PFRING_MOD_NETCOPE_PRIV_H_
#define _PFRING_MOD_NETCOPE_PRIV_H_

#include <libnsf.h>

typedef struct {
  int card_id;
  int port_id;
  int queue_id;

  nsf_t *nsf;
  nsf_action_t action;
  nsf_context_id_t context_id;
  nsf_access_t *acc;
  nsf_rx_stream_t *rx_stream;

  unsigned char *packet;
  unsigned packet_len;

  u_int64_t recv;
} pfring_netcope;

#endif /* _PFRING_MOD_NETCOPE_PRIV_H_ */
