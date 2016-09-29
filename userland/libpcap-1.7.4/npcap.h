/*
 *
 *  Copyright (C) 2012-16 - ntop.org
 *
 */

#ifndef _NPCAP_H_
#define _NPCAP_H_

#include <sys/types.h>

#include "pcap.h"

struct pcap_disk_timeval {
  u_int32_t tv_sec;
  u_int32_t tv_usec;
#define tv_nsec32 tv_usec
#define tv_subsec tv_usec
};

struct pcap_disk_pkthdr {
  struct pcap_disk_timeval ts; /* time stamp                    */
  u_int32_t caplen;            /* length of portion present     */
  u_int32_t len;               /* length this packet (off wire) */
};

struct pcap_disk_pkthdr_nsec {
  struct pcap_disk_pkthdr pkthdr;
  u_int64_t ns;
};

/* ************************************************************ */

typedef struct npcap_fd npcap_fd_t;

/* ************************************************************ */

int     is_plain_pcap(char *file_path);
int64_t pcap_file_size(char *file_path);
int     npcap_decompress(char *in_file_path, char *out_file_path, u_int64_t* decompressed_len);

npcap_fd_t *npcap_open(const char *in_file_path, int chunk_mode /* 0 - packet mode, 1 - chunk mode */);
void    npcap_close(npcap_fd_t *cfd);
int     npcap_read_header(npcap_fd_t *cfd, struct pcap_file_header *pcap_file_hdr);
int64_t npcap_read_next_chunk(npcap_fd_t *cfd, u_char *out_chunk, u_int64_t out_chunk_len);
int     npcap_read_at(npcap_fd_t *cfd, u_int64_t pkt_offset, struct pcap_disk_pkthdr **extracted_hdr, u_char **extracted_pkt);
int     npcap_read_next(npcap_fd_t *cfd, struct pcap_disk_pkthdr **extracted_hdr, u_char **extracted_pkt);

/* ************************************************************ */

#include "pfring.h"
#include "nbpf.h"

typedef struct npcap_extract_handle npcap_extract_handle_t;
typedef struct timeline_extract_handle timeline_extract_handle_t;

/* single npcap extraction */
npcap_extract_handle_t * npcap_extract_open(char *pcap_path, char *index_path, nbpf_tree_t *nbpf_filter, struct bpf_program *pcap_filter);
struct pcap_file_header *npcap_extract_header(npcap_extract_handle_t *handle);
int                      npcap_extract_next(npcap_extract_handle_t *handle, struct pcap_disk_pkthdr **extracted_hdr, u_char **extracted_pkt);
void                     npcap_extract_close(npcap_extract_handle_t *handle);

/* timeline extraction */
timeline_extract_handle_t *timeline_extract_open(char *timeline_path, time_t begin_epoch, time_t end_epoch, nbpf_tree_t *nbpf_filter, struct bpf_program *pcap_filter);
struct pcap_file_header *  timeline_extract_header(timeline_extract_handle_t *handle);
int                        timeline_extract_next(timeline_extract_handle_t *handle, struct pcap_disk_pkthdr **extracted_hdr, u_char **extracted_pkt, u_int64_t *match_epoch_nsec);
void                       timeline_extract_close(timeline_extract_handle_t *handle);

/* extra extraction functions */
void extract_set_debug_level(u_int8_t level);
void extract_toggle_index_scan_only(u_int8_t enable);
void extract_toggle_files_list_only(u_int8_t enable);

#endif /* _NPCAP_H_ */

