/*
 *
 * (C) 2015    - ntop.org
 * (C) 2014-15 - Accolade Technology Inc. 
 *
 */

#ifndef _PFRING_MOD_ACCOLADE_H_
#define _PFRING_MOD_ACCOLADE_H_

#include "pfring.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <anic_api.h>
#include <anic_api_private.h>
#include <anic_api_block.h>

#include <limits.h>
#include <sys/shm.h>
#include <signal.h>
#include <setjmp.h>

#define MFL_SUPPORT

#define ACCOLADE_HUGEPAGE_SIZE   (2*1024*1024)
#define ACCOLADE_RING_SIZE       (RING_HUGEPAGE_COUNT * HUGEPAGE_SIZE)
#define ACCOLADE_BUFFER_COUNT    (256)
#define ACCOLADE_MAX_RINGS       (64)
#define ACCOLADE_MAX_BLKS        (2048)
#define ACCOLADE_MAX_PACKET_SIZE (16*1024)
#define ACCOLADE_BLOCKS_PER_RING (64)

struct block_ref {
  u_int8_t *buf_p;
  u_int64_t dma_address;
};

#ifdef MFL_SUPPORT
struct block_header_s /* bufheader_s */ {
  u_int32_t block_size;
  u_int32_t packet_count;
  u_int32_t byte_count;
  u_int32_t reserved;;
  u_int64_t first_timestamp;
  u_int64_t last_timestamp;
  u_int32_t first_offset;
  u_int32_t last_offset;
};
#else
struct block_header_s {
  u_int32_t block_size;
  u_int32_t packet_count;
  u_int32_t byte_count;
  u_int32_t reserved;
  u_int64_t first_timestamp;
  u_int64_t last_timestamp;
};
#endif

struct block_status {
  struct anic_blkstatus_s blkStatus;
  int refcount;
};

struct ring_stats {
  u_int64_t packets;
  u_int64_t bytes;
  u_int64_t packet_errors;
  u_int64_t timestamp_errors;
#ifdef MFL_SUPPORT
  u_int64_t last_drops_counter;
  u_int64_t cumulative_drops;
#endif
};

struct workqueue {
  int head;
  int tail;
  int entryA[ACCOLADE_BUFFER_COUNT+1];  // bounded queue (can never have more entries than there are blks)
};

struct block_processing {
  int processing;
  u_int8_t *buf_p;
  struct anic_blkstatus_s *blkstatus_p;
  int blk;
#ifdef MFL_SUPPORT
  u_int8_t *last_buf_p;
#endif
};

typedef struct {
  anic_handle_t anic_handle;

  u_int32_t device_id, ring_id;

  u_int32_t blocksize, pages, pageblocks, portCount;

  struct block_ref l_blkA[ACCOLADE_MAX_BLKS /* ACCOLADE_BUFFER_COUNT */];
  struct block_status l_blkStatusA[ACCOLADE_MAX_BLKS /* ACCOLADE_BUFFER_COUNT */];
  struct ring_stats rstats;
  
  anic_blocksize_e blocksize_e;
  struct workqueue wq;
  u_int64_t lastTs; 

  struct block_processing currentblock;

  struct anic_dma_info dmaInfo;

#ifdef MFL_SUPPORT
  int mfl_mode;
#endif
} pfring_anic;


int  pfring_anic_open(pfring *ring);
void pfring_anic_close(pfring *ring);
int  pfring_anic_stats(pfring *ring, pfring_stat *stats);
int  pfring_anic_recv(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_anic_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
int  pfring_anic_set_poll_watermark(pfring *ring, u_int16_t watermark);
int  pfring_anic_set_poll_duration(pfring *ring, u_int duration);
int  pfring_anic_poll(pfring *ring, u_int wait_duration);
int  pfring_anic_set_direction(pfring *ring, packet_direction direction);
int  pfring_anic_enable_ring(pfring *ring);
int  pfring_anic_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_anic_get_bound_device_ifindex(pfring *ring, int *if_index);
u_int32_t pfring_anic_get_interface_speed(pfring *ring);

#endif /* _PFRING_MOD_ACCOLADE_H_ */
