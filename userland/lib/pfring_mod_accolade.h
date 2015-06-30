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

#define ACCOLADE_HUGEPAGE_SIZE (2*1024*1024)
#define ACCOLADE_RING_SIZE     (RING_HUGEPAGE_COUNT * HUGEPAGE_SIZE)
#define ACCOLADE_BUFFER_COUNT  (256)
#define ACCOLADE_MAX_RINGS     (64)

struct block_ref {
  u_int8_t *buf_p;
  u_int64_t dma_address;
};

struct blkheader_s {
  u_int32_t block_size;
  u_int32_t packet_count;
  u_int32_t byte_count;
  u_int32_t reserved;
  u_int64_t first_timestamp;
  u_int64_t last_timestamp;
};

struct blkstatus {
  struct anic_blkstatus_s blkStatus;
  int refcount;
};

struct ring_stats {
  struct {
    uint64_t packets;
    uint64_t bytes;
    uint64_t packet_errors;
    uint64_t timestamp_errors;
    uint64_t validation_errors;
    uint64_t pad[3];  // use full cache lines
  } ring[ACCOLADE_MAX_RINGS];
};

struct workqueue {
  int head;
  int tail;
  int entryA[ACCOLADE_BUFFER_COUNT+1];  // bounded queue (can never have more entries than there are blks)
};

typedef struct {
  anic_handle_t anic_handle;

  /* ***************************** */

  struct block_ref l_blkA[ACCOLADE_BUFFER_COUNT];
  u_int8_t *l_patternBuffer;
  struct blkstatus l_blkStatusA[ACCOLADE_BUFFER_COUNT];
  struct ring_stats l_rstats;
  u_int32_t device_id, ring_id, blocksize, pages, pageblocks;
  anic_blocksize_e blocksize_e;

  struct workqueue wq;
  u_int64_t lastTs[64]; 

  /* ***************************** */

  struct anic_dma_info dmaInfo;
} pfring_accolade;


int  pfring_accolade_open(pfring *ring);
void pfring_accolade_close(pfring *ring);
int  pfring_accolade_stats(pfring *ring, pfring_stat *stats);
int  pfring_accolade_recv(pfring *ring, u_char** buffer, u_int buffer_len, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int  pfring_accolade_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
int  pfring_accolade_set_poll_watermark(pfring *ring, u_int16_t watermark);
int  pfring_accolade_set_poll_duration(pfring *ring, u_int duration);
int  pfring_accolade_poll(pfring *ring, u_int wait_duration);
int  pfring_accolade_set_direction(pfring *ring, packet_direction direction);
int  pfring_accolade_enable_ring(pfring *ring);
int  pfring_accolade_set_socket_mode(pfring *ring, socket_mode mode);
int  pfring_accolade_get_bound_device_ifindex(pfring *ring, int *if_index);

#endif /* _PFRING_MOD_ACCOLADE_H_ */
