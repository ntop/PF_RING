/*
 *
 * (C) 2005-2018 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 *
 */

#ifndef _PFRING_MOD_DAG_H_
#define _PFRING_MOD_DAG_H_

#include "pfring.h"

int  pfring_dag_open (pfring *ring);
void pfring_dag_close(pfring *ring);
int  pfring_dag_stats(pfring *ring, pfring_stat *stats);
int  pfring_dag_recv (pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_dag_set_poll_watermark(pfring *ring, u_int16_t watermark);
int  pfring_dag_set_poll_duration(pfring *ring, u_int duration);
int  pfring_dag_poll(pfring *ring, u_int wait_duration);
int  pfring_dag_set_direction(pfring *ring, packet_direction direction);
int  pfring_dag_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_dag_set_application_name(pfring *ring, char *name);
int  pfring_dag_enable_ring(pfring *ring);
u_int32_t pfring_dag_get_interface_speed(pfring *ring);
pfring_if_t *pfring_dag_findalldevs(void);

#endif /* _PFRING_MOD_DAG_H_ */
