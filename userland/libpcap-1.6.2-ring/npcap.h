/*
 *
 *  Copyright (C) 2012-14 - ntop.org
 *
 */

#ifndef _NPCAP_H_
#define _NPCAP_H_

#include <sys/types.h>

#include "pcap.h"

#define PCAP_MAGIC      0xa1b2c3d4
#define PCAP_NSEC_MAGIC 0xa1b23c4d

struct compact_timeval {
  u_int32_t tv_sec;
  u_int32_t tv_usec;
};

struct compact_pcap_pkthdr {
  struct compact_timeval ts; /* time stamp */
  u_int32_t caplen;          /* length of portion present */
  u_int32_t len;             /* length this packet (off wire) */
};

struct pcap_disk_timeval {
  u_int32_t tv_sec;  /* seconds */
  u_int32_t tv_usec; /* microseconds */
#define tv_nsec32 tv_usec
#define tv_subsec tv_usec
};

struct pcap_disk_pkthdr {
  struct pcap_disk_timeval ts; /* time stamp                    */
  u_int32_t caplen;            /* length of portion present     */
  u_int32_t len;               /* length this packet (off wire) */
};

#if 0 //#ifndef PF_RING_PCAP
/* Nanosecond accuracy */
struct ns_pcaphdr {
  struct pcap_disk_timeval ts;
  u_int32_t caplen;
  u_int32_t len;
  u_int64_t ns;
};
#endif

struct pcap_disk_pkthdr_nsec {
  struct pcap_disk_pkthdr pkthdr;
  u_int64_t ns;
};

/* ************************************************************ */

typedef enum {
  packet_mode = 0,
  chunk_mode
} decompression_mode;

typedef struct npcap_fd npcap_fd_t;

/* ************************************************************ */

int     is_plain_pcap(char *file_path);
int64_t pcap_file_size(char *file_path);
int     npcap_decompress(char *in_file_path, char *out_file_path, u_int64_t* decompressed_len);

npcap_fd_t *npcap_open(const char *in_file_path, decompression_mode mode);
void    npcap_close(npcap_fd_t *cfd);
int     npcap_read_header(npcap_fd_t *cfd, struct pcap_file_header *pcap_file_hdr);
int64_t npcap_read_next_chunk(npcap_fd_t *cfd, u_char *out_chunk, u_int64_t out_chunk_len);
int     npcap_read_at(npcap_fd_t *cfd, u_int64_t pkt_offset, struct pcap_disk_pkthdr **extracted_hdr, u_char **extracted_pkt);
int     npcap_read_next(npcap_fd_t *cfd, struct pcap_disk_pkthdr **extracted_hdr, u_char **extracted_pkt);

#endif /* _NPCAP_H_ */

