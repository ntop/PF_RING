/*
 *
 * (C) 2015 - ntop.org
 *
 */

#ifndef _PFRING_MOD_INVEATECH_H_
#define _PFRING_MOD_INVEATECH_H_

#include "pfring.h"

#include <libsze2.h>

//#define INVEA_DROP_STATS
#ifdef INVEA_DROP_STATS
#include <combosix.h>
#define MY_IBUF_80G_100G_BASE_ADDR 0x8000
#define MY_IBUF_80G_100G_SIZE 0x0200
//#define MY_IBUF_EN			0x0020
#define MY_IBUF_CNT_RECVERR		0x0008 /*! Discarded Frames Counter (DFC) */
#define MY_IBUF_CNT_OVERFLOW		0x000C /*! Counter of frames discarded due to buffer overflow */
#define COMBO_80G   "COMBO-80G"
#define COMBO_100G  "COMBO-100G"
#endif

#define IFACE_OFFSET            0
#define DMA_OFFSET              0 
#define FLAGS_OFFSET            1
#define LABEL_OFFSET            2

#define TIMESTAMP_NS_OFFSET     4
#define TIMESTAMP_S_OFFSET      8

typedef struct {
  int device_id;
  struct szedata *sze;
  unsigned char *packet;
  unsigned int packet_len;
  u_int64_t recv;
#ifdef INVEA_DROP_STATS 
  cs_device_t *dev;
  cs_space_t *ibuf_space;
  char *board;
  uint32_t ibuf_base_addr;
  uint32_t ibuf_size;
#endif
} pfring_invea;

int  pfring_invea_open(pfring *ring);
void pfring_invea_close(pfring *ring);
int  pfring_invea_stats(pfring *ring, pfring_stat *stats);
int  pfring_invea_recv(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_invea_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
void pfring_invea_flush_tx_packets(pfring *ring);
int  pfring_invea_set_poll_watermark(pfring *ring, u_int16_t watermark);
int  pfring_invea_set_poll_duration(pfring *ring, u_int duration);
int  pfring_invea_poll(pfring *ring, u_int wait_duration);
int  pfring_invea_set_direction(pfring *ring, packet_direction direction);
int  pfring_invea_enable_ring(pfring *ring);
int  pfring_invea_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_invea_get_bound_device_ifindex(pfring *ring, int *if_index);
u_int32_t pfring_invea_get_interface_speed(pfring *ring);

#endif /* _PFRING_MOD_INVEATECH_H_ */
