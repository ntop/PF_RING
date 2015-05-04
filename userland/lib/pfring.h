/*
 *
 * (C) 2005-14 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef _PFRING_H_
#define _PFRING_H_

/**
 * @mainpage  Main Page
 *
 *            PF_RING API documentation.
 */

/**
 * @file pfring.h
 *
 * @brief      PF_RING library header file.
 * @details    This header file must be included in any PF_RING-based applications.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>

#ifndef HAVE_PCAP
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#endif

#ifdef ENABLE_BPF
#include <pcap/pcap.h>
#include <pcap/bpf.h>
#endif

#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include <poll.h>
#include <string.h>
#include <pthread.h>
#include <linux/pf_ring.h>
#include <linux/if_ether.h>

#ifdef HAVE_REDIRECTOR
#include <librdi.h>
#endif

#define MAX_CAPLEN             65535
#define PAGE_SIZE               4096

#define DEFAULT_POLL_DURATION   500

#define POLL_SLEEP_STEP           10 /* ns = 0.1 ms */
#define POLL_SLEEP_MIN          POLL_SLEEP_STEP
#define POLL_SLEEP_MAX          1000 /* ns */
#define POLL_QUEUE_MIN_LEN       500 /* # packets */

#ifndef HAVE_RW_LOCK
#define pthread_rwlock_t       pthread_mutex_t
#define pthread_rwlock_init    pthread_mutex_init
#define pthread_rwlock_rdlock  pthread_mutex_lock
#define pthread_rwlock_wrlock  pthread_mutex_lock
#define pthread_rwlock_unlock  pthread_mutex_unlock
#define pthread_rwlock_destroy pthread_mutex_destroy
#endif

#define timespec_is_before(a, b) \
  ((((a)->tv_sec<(b)->tv_sec)||(((a)->tv_sec==(b)->tv_sec)&&((a)->tv_nsec<(b)->tv_nsec)))?1:0)

/* ********************************* */

#ifndef likely
#define likely(x)       __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect((x),0)
#endif

/* ********************************* */

/*
  See also __builtin_prefetch
  http://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
*/
#define prefetch(x) __asm volatile("prefetcht0 %0" :: "m" (*(const unsigned long *)x));

/* ********************************* */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SAFE_RING_MODE
static char staticBucket[2048];
#endif

typedef void (*pfringProcesssPacket)(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes);

/* ********************************* */

typedef struct __pfring pfring; /* Forward declaration */

/* ********************************* */

#define MAX_NUM_BUNDLE_ELEMENTS 32

typedef enum {
  pick_round_robin = 0,
  pick_fifo
} bundle_read_policy;

typedef struct {
  bundle_read_policy policy;
  u_int16_t num_sockets, last_read_socket;
  pfring *sockets[MAX_NUM_BUNDLE_ELEMENTS];
  struct pollfd pfd[MAX_NUM_BUNDLE_ELEMENTS];
} pfring_bundle;

/* ********************************* */

typedef struct {
  u_int32_t max_packet_size;
  u_int32_t rx_ring_slots;
  u_int32_t tx_ring_slots;
} pfring_card_settings;

/* ********************************* */

typedef struct {
  u_int64_t recv, drop;
} pfring_stat;

/* ********************************* */

typedef enum {
  hardware_and_software = 0,
  hardware_only,
  software_only
} filtering_mode;

/* ********************************* */

typedef void pfring_pkt_buff;

/* ********************************* */

#ifndef BPF_RELEASE
struct pfring_bpf_program {
  u_int bf_len; 
  void *bf_insns; 
};
#endif

/* ********************************* */

struct __pfring {
  u_int8_t initialized, enabled, long_header, rss_mode;
  u_int8_t force_timestamp, strip_hw_timestamp, disable_parsing,
    disable_timestamp, ixia_timestamp_enabled,
    vss_apcon_timestamp_enabled,
    chunk_mode_enabled, userspace_bpf, force_userspace_bpf;
  packet_direction direction; /* Specify the capture direction for packets */
  socket_mode mode;

#ifdef BPF_RELEASE
  struct bpf_program
#else
  struct pfring_bpf_program
#endif
    userspace_bpf_filter;

  /* Hardware Timestamp */
  struct {
    u_int8_t force_timestamp, is_silicom_hw_timestamp_card, enable_hw_timestamp;
    struct timespec last_hw_timestamp;
  } hw_ts;

  struct {
    u_int8_t enabled_rx_packet_send;
    struct pfring_pkthdr *last_received_hdr; /*
						 Header of the past packet
						 that has been received on this socket
					       */
  } tx;

  u_int8_t zc_device;

  /* FIXX these fields should be moved in ->priv_data */
  /* DNA (Direct NIC Access) only */ 
  struct {
    u_int16_t num_rx_pkts_before_dna_sync, num_tx_pkts_before_dna_sync; 
    u_int16_t dna_rx_sync_watermark, dna_tx_sync_watermark;
    u_int64_t tot_dna_read_pkts, tot_dna_lost_pkts;
    u_int32_t rx_reg, tx_reg, last_rx_slot_read;
    u_int32_t num_rx_slots_per_chunk, num_tx_slots_per_chunk;
    
    zc_dev_info dna_dev;
    volatile u_int32_t *rx_reg_ptr, *tx_reg_ptr,
      *mpc_reg_ptr, *qprdc_reg_ptr, *rnbc_reg_ptr, *rqdpc_reg_ptr, *gorc_reg_ptr;
    zc_dev_operation last_dna_operation;
  } dna;

  void   *priv_data; /* module private data */

  void      (*close)                        (pfring *);
  int       (*stats)                        (pfring *, pfring_stat *);
  int       (*recv)                         (pfring *, u_char**, u_int, struct pfring_pkthdr *, u_int8_t);
  int       (*set_poll_watermark)           (pfring *, u_int16_t);
  int       (*set_poll_duration)            (pfring *, u_int);
  int       (*set_tx_watermark)             (pfring *, u_int16_t);
  int       (*set_channel_id)               (pfring *, u_int32_t);
  int       (*set_channel_mask)             (pfring *, u_int64_t);
  int       (*set_application_name)         (pfring *, char *);
  int       (*set_application_stats)        (pfring *, char *);
  char*     (*get_appl_stats_file_name)     (pfring *ring, char *path, u_int path_len);
  int       (*bind)                         (pfring *, char *);
  int       (*send)                         (pfring *, char *, u_int, u_int8_t);
  int       (*send_ifindex)                 (pfring *, char *, u_int, u_int8_t, int);
  int       (*send_get_time)                (pfring *, char *, u_int, struct timespec *);
  u_int8_t  (*get_num_rx_channels)          (pfring *);
  int       (*get_card_settings)            (pfring *, pfring_card_settings *);
  int       (*set_sampling_rate)            (pfring *, u_int32_t);
  int       (*get_selectable_fd)            (pfring *);
  int       (*set_direction)                (pfring *, packet_direction);
  int       (*set_socket_mode)              (pfring *, socket_mode);
  int       (*set_cluster)                  (pfring *, u_int, cluster_type);
  int       (*remove_from_cluster)          (pfring *);
  int       (*set_master_id)                (pfring *, u_int32_t);
  int       (*set_master)                   (pfring *, pfring *);
  u_int16_t (*get_ring_id)                  (pfring *);
  u_int32_t (*get_num_queued_pkts)          (pfring *);
  u_int8_t  (*get_packet_consumer_mode)     (pfring *);
  int       (*set_packet_consumer_mode)     (pfring *, u_int8_t, char *, u_int);
  int       (*get_hash_filtering_rule_stats)(pfring *, hash_filtering_rule *, char *, u_int *);
  int       (*handle_hash_filtering_rule)   (pfring *, hash_filtering_rule *, u_char);
  int       (*purge_idle_hash_rules)        (pfring *, u_int16_t);
  int       (*add_filtering_rule)           (pfring *, filtering_rule *);
  int       (*remove_filtering_rule)        (pfring *, u_int16_t);
  int       (*purge_idle_rules)             (pfring *, u_int16_t);
  int       (*get_filtering_rule_stats)     (pfring *, u_int16_t, char *, u_int *);
  int       (*toggle_filtering_policy)      (pfring *, u_int8_t);
  int       (*enable_rss_rehash)            (pfring *);
  int       (*poll)                         (pfring *, u_int);
  int       (*is_pkt_available)             (pfring *);
  int       (*next_pkt_time)                (pfring *, struct timespec *);
  int       (*next_pkt_raw_timestamp)       (pfring *, u_int64_t *ts);
  int       (*version)                      (pfring *, u_int32_t *);
  int       (*get_bound_device_address)     (pfring *, u_char [6]);
  int       (*get_bound_device_ifindex)     (pfring *, int *);
  int       (*get_device_ifindex)           (pfring *, char *, int *);
  u_int16_t (*get_slot_header_len)          (pfring *);
  int       (*set_virtual_device)           (pfring *, virtual_filtering_device_info *);
  int       (*add_hw_rule)                  (pfring *, hw_filtering_rule *);
  int       (*remove_hw_rule)               (pfring *, u_int16_t);
  int       (*loopback_test)                (pfring *, char *, u_int, u_int);
  int       (*enable_ring)                  (pfring *);
  int       (*disable_ring)                 (pfring *);
  void      (*shutdown)                     (pfring *);
  int       (*set_bpf_filter)               (pfring *, char *);
  int       (*remove_bpf_filter)            (pfring *);
  int       (*get_device_clock)             (pfring *, struct timespec *);
  int       (*set_device_clock)             (pfring *, struct timespec *);
  int       (*adjust_device_clock)          (pfring *, struct timespec *, int8_t);
  void      (*sync_indexes_with_kernel)     (pfring *);
  int       (*send_last_rx_packet)          (pfring *, int);
  u_char*   (*get_pkt_buff_data)            (pfring *, pfring_pkt_buff *);
  int       (*set_pkt_buff_len)             (pfring *, pfring_pkt_buff *, u_int32_t);
  int       (*set_pkt_buff_ifindex)         (pfring *, pfring_pkt_buff *, int);
  int       (*add_pkt_buff_ifindex)         (pfring *, pfring_pkt_buff *, int);
  pfring_pkt_buff* (*alloc_pkt_buff)        (pfring *);
  void      (*release_pkt_buff)             (pfring *, pfring_pkt_buff *);
  int       (*recv_pkt_buff)                (pfring *, pfring_pkt_buff *, struct pfring_pkthdr *, u_int8_t);
  int       (*send_pkt_buff)                (pfring *, pfring_pkt_buff *, u_int8_t);
  void      (*flush_tx_packets)             (pfring *);
  int       (*register_zerocopy_tx_ring)    (pfring *, pfring *);
  int       (*recv_chunk)                   (pfring *, void **chunk, u_int32_t *chunk_len, u_int8_t wait_for_incoming_chunk); 
  int       (*set_bound_dev_name)           (pfring *, char*);

  /* DNA only */
  int      (*dna_init)             (pfring *);
  void     (*dna_term)             (pfring *);   
  int      (*dna_enable)           (pfring *);
  u_int8_t (*dna_check_packet_to_read) (pfring *, u_int8_t);
  u_char*  (*dna_next_packet)      (pfring *, u_char **, u_int, struct pfring_pkthdr *);
  u_int    (*dna_get_num_tx_slots)(pfring *ring);
  u_int    (*dna_get_num_rx_slots)(pfring *ring);
  u_int    (*dna_get_next_free_tx_slot)(pfring *ring);
  u_char*  (*dna_copy_tx_packet_into_slot)(pfring *ring, u_int32_t tx_slot_id, char *buffer, u_int len);
  u_int8_t (*dna_tx_ready)(pfring *);

  /* Silicom Redirector Only */
  struct {
    int8_t device_id, port_id;
  } rdi;

  filtering_mode ft_mode;
  pfring_device_type ft_device_type;  

  /* All devices */
  char *buffer, *slots, *device_name;
  u_int32_t caplen;
  u_int16_t slot_header_len, mtu_len /* 0 = unknown */;
  u_int32_t sampling_rate, sampling_counter;
  u_int8_t kernel_packet_consumer, is_shutting_down, socket_default_accept_policy;
  int fd, device_id;
  FlowSlotInfo *slots_info;
  u_int poll_sleep;
  u_int16_t poll_duration;
  u_int8_t promisc, clear_promisc, reentrant, break_recv_loop;
  u_long num_poll_calls;
  pthread_rwlock_t rx_lock, tx_lock;

  struct sockaddr_ll sock_tx;

  /* Reflector socket (copy RX packets onto it) */
  pfring *reflector_socket;

  /* Semi-ZC/DNA devices (1-copy) */
  pfring *one_copy_rx_pfring;
};

/* ********************************* */

#define PF_RING_ZC_SYMMETRIC_RSS     1 << 0  /**< pfring_open() flag: Set the hw RSS function to symmetric mode (both directions of the same flow go to the same hw queue). Supported by ZC/DNA drivers only. This option is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_DNA_RSS environment variable. */
#define PF_RING_REENTRANT            1 << 1  /**< pfring_open() flag: The device is open in reentrant mode. This is implemented by means of semaphores and it results is slightly worse performance. Use reentrant mode only for multithreaded applications. */
#define PF_RING_LONG_HEADER          1 << 2  /**< pfring_open() flag: If uset, PF_RING does not fill the field extended_hdr of struct pfring_pkthdr. If set, the extended_hdr field is also properly filled. In case you do not need extended information, set this value to 0 in order to speedup the operation. */
#define PF_RING_PROMISC              1 << 3  /**< pfring_open() flag: The device is open in promiscuous mode. */
#define PF_RING_TIMESTAMP            1 << 4  /**< pfring_open() flag: Force PF_RING to set the timestamp on received packets (usually it is not set when using zero-copy, for optimizing performance). */
#define PF_RING_HW_TIMESTAMP         1 << 5  /**< pfring_open() flag: Enable hw timestamping, when available. */
#define PF_RING_RX_PACKET_BOUNCE     1 << 6  /**< pfring_open() flag: Enable fast forwarding support (see pfring_send_last_rx_packet()). */
#define PF_RING_ZC_FIXED_RSS_Q_0     1 << 7  /**< pfring_open() flag: Set hw RSS to send all traffic to queue 0. Other queues can be selected using hw filters (ZC/DNA cards with hw filtering only). */
#define PF_RING_STRIP_HW_TIMESTAMP   1 << 8  /**< pfring_open() flag: Strip hw timestamp from the packet. */
#define PF_RING_DO_NOT_PARSE         1 << 9  /**< pfring_open() flag: Disable packet parsing also when 1-copy is used. (parsing already disabled in zero-copy) */
#define PF_RING_DO_NOT_TIMESTAMP     1 << 10 /**< pfring_open() flag: Disable packet timestamping also when 1-copy is used. (sw timestamp already disabled in zero-copy) */
#define PF_RING_CHUNK_MODE           1 << 11 /**< pfring_open() flag: Enable chunk mode operations. This mode is supported only by specific adapters and it's not for general purpose. */
#define PF_RING_IXIA_TIMESTAMP	     1 << 12 /**< pfring_open() flag: Enable ixiacom.com hardware timestamp support+stripping. */
#define PF_RING_USERSPACE_BPF	     1 << 13 /**< pfring_open() flag: Force userspace bpf even with standard drivers (not only with ZC/DNA). */
#define PF_RING_ZC_NOT_REPROGRAM_RSS 1 << 14 /**< pfring_open() flag: Do not touch/reprogram hw RSS */ 
#define PF_RING_VSS_APCON_TIMESTAMP  1 << 14 /**< pfring_open() flag: Enable apcon.com/vssmonitoring.com hardware timestamp support+stripping. */

/* ********************************* */

/* backward compatibility */
#define PF_RING_DNA_SYMMETRIC_RSS PF_RING_ZC_SYMMETRIC_RSS
#define PF_RING_DNA_FIXED_RSS_Q_0 PF_RING_ZC_FIXED_RSS_Q_0

/* ********************************* */

/**
 * This call is used to initialize a PF_RING socket hence obtain a handle of type struct pfring 
 * that can be used in subsequent calls. Note that: 
 * 1. you can use physical (e.g. ethX) and virtual (e.g. tapX) devices, RX-queues (e.g. ethX@Y), 
 *    and additional modules (e.g. dna:dnaX@Y, dag:dagX:Y, "multi:ethA@X;ethB@Y;ethC@Z", "dnacluster:A@X", "stack:dnaX").
 * 2. you need super-user capabilities in order to open a device.
 * @param device_name Symbolic name of the PF_RING-aware device we’re attempting to open (e.g. eth0).
 * @param caplen      Maximum packet capture len (also known as snaplen).
 * @param flags       It allows several options to be specified on a compact format using bitmaps (see PF_RING_* macros).
 * @return On success a handle is returned, NULL otherwise.
 */
pfring *pfring_open(const char *device_name, u_int32_t caplen, u_int32_t flags);

/**
 * Same as pfring_open(), but initializes a kernel plugin for packet processing.
 * @param device_name
 * @param caplen
 * @param flags
 * @param consumer_plugin_id The plugin id.
 * @param consumer_data      The plugin data.
 * @param consumer_data_len  The size of the plugin data.
 * @return On success a handle is returned, NULL otherwise. 
 */
pfring *pfring_open_consumer(const char *device_name, u_int32_t caplen, u_int32_t flags,
			     u_int8_t consumer_plugin_id,
			     char* consumer_data, u_int consumer_data_len);

/**
 * This call is similar to pfring_open() with the exception that in case of a multi RX-queue NIC, 
 * instead of opening a single ring for the whole device, several individual rings are open (one per RX-queue).
 * @param device_name Symbolic name of the PF_RING-aware device we’re attempting to open (e.g. eth0). 
 *                    No queue name hash to be specified, but just the main device name.
 * @param caplen      Maximum packet capture len (also known as snaplen).
 * @param flags       See pfring_open() for details.
 * @param ring        A pointer to an array of rings that will contain the opened ring pointers.
 * @return The last index of the ring array that contain a valid ring pointer.
 */
u_int8_t pfring_open_multichannel(const char *device_name, u_int32_t caplen, 
				  u_int32_t flags, pfring *ring[MAX_NUM_RX_CHANNELS]);

/**
 * Shutdown a socket.
 * @param ring The PF_RING handle. 
 */
void pfring_shutdown(pfring *ring);

/**
 * Set the scheduler priority for the current thread.
 * @param cpu_percentage The priority. 
 */
void pfring_config(u_short cpu_percentage);

/**
 * Process ingress packets until pfring_breakloop() is called, or an error occurs.
 * @param ring            The PF_RING handle.
 * @param looper          The user callback for packet processing. 
 * @param user_bytes      The user ptr passed to the callback.
 * @param wait_for_packet If 0 active wait is used to check the packet availability.
 * @return 0 on success (pfring_breakloop()), a negative value otherwise.
 */
int pfring_loop(pfring *ring, pfringProcesssPacket looper, 
		 const u_char *user_bytes, u_int8_t wait_for_packet);

/**
 * Break a receive loop (pfring_loop() or blocking pfring_recv()).
 * @param ring The PF_RING handle.
 */
void pfring_breakloop(pfring *);

/**
 * This call is used to terminate an PF_RING device previously open. 
 * Note that you must always close a device before leaving an application. If unsure, you can close a device from a signal handler. 
 * @param ring The PF_RING handle that we are attempting to close.
 */
void pfring_close(pfring *ring);

/**
 * Read ring statistics (packets received and dropped). 
 * @param ring  The PF_RING handle.
 * @param stats A user-allocated buffer on which stats (number of received and dropped packets) will be stored.
 * @return 0 on uccess, a negative value otherwise.
 */
int pfring_stats(pfring *ring, pfring_stat *stats);

/**
 * This call returns an incoming packet when available. 
 * @param ring       The PF_RING handle where we perform the check.
 * @param buffer     A memory area allocated by the caller where the incoming packet will be stored. 
 *                   Note that this parameter is a pointer to a pointer, in order to enable zero-copy implementations (buffer_len must be set to 0).
 * @param buffer_len The length of the memory area above. 
 *                   Note that the incoming packet is cut if it is too long for the allocated area. 
 *                   A length of 0 indicates to use the zero-copy optimization, when available.
 * @param hdr        A memory area where the packet header will be copied.
 * @param wait_for_incoming_packet If 0 we simply check the packet availability, otherwise the call is blocked until a packet is available. 
 *                   This option is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_ACTIVE_POLL environment variable.
 * @return 0 in case of no packet being received (non-blocking), 1 in case of success, -1 in case of error.
 */
int pfring_recv(pfring *ring, u_char** buffer, u_int buffer_len,
		struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);

/**
 * Same of pfring_recv(), with additional parameters to force packet parsing.
 * @param ring
 * @param buffer
 * @param buffer_len
 * @param hdr
 * @param wait_for_incoming_packet
 * @param level         The header level where to stop parsing.
 * @param add_timestamp Add the timestamp.
 * @param add_hash      Compute an IP-based bidirectional hash. 
 * @return 0 in case of no packet being received (non-blocking), 1 in case of success, -1 in case of error.
 */
int pfring_recv_parsed(pfring *ring, u_char** buffer, u_int buffer_len,
		       struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet,
		       u_int8_t level /* 1..4 */, u_int8_t add_timestamp, u_int8_t add_hash);

/**
 * Whenever a user-space application has to wait until incoming packets arrive, it can instruct PF_RING not to return from poll() call 
 * unless at least “watermark” packets have been returned. A low watermark value such as 1, reduces the latency of poll() but likely 
 * increases the number of poll() calls. A high watermark (it cannot exceed 50% of the ring size, otherwise the PF_RING kernel module 
 * will top its value) instead reduces the number of poll() calls but slightly increases the packet latency. 
 * The default value for the watermark (i.e. if user-space applications do not manipulate is value via this call) is 128.
 * @param ring      The PF_RING handle to enable.
 * @param watermark The packet poll watermark.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_poll_watermark(pfring *ring, u_int16_t watermark);

/**
 * Set the poll timeout when passive wait is used. 
 * @param ring     The PF_RING handle to enable.
 * @param duration The poll timeout in msec.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_poll_duration(pfring *ring, u_int duration);

/**
 * Set the number of packets that have to be enqueued in the egress queue before being sent on the wire. 
 * @param ring      The PF_RING handle to enable.
 * @param watermark The tx watermark.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_tx_watermark(pfring *ring, u_int16_t watermark);

/**
 * Set a specified filtering rule into the NIC. Note that no PF_RING filter is added, but only a NIC filter.
 *
 * Some multi-queue modern network adapters feature "packet steering" capabilities. Using them it is possible to 
 * instruct the hardware NIC to assign selected packets to a specific RX queue. If the specified queue has an Id 
 * that exceeds the maximum queueId, such packet is discarded thus acting as a hardware firewall filter.
 * Note: kernel packet filtering is not supported by ZC/DNA.
 * @param ring The PF_RING handle on which the rule will be added. 
 * @param rule The filtering rule to be set in the NIC as defined in the last chapter of this document. 
 *             All rule parameters should be defined, and if set to zero they do not participate to filtering.
 * @return 0 on success, a negative value otherwise (e.g. the rule to be added has wrong format or if the NIC to 
 *         which this ring is bound does not support hardware filters).
 */
int pfring_add_hw_rule(pfring *ring, hw_filtering_rule *rule);

/**
 * Remove the specified filtering rule from the NIC. 
 * @param ring The PF_RING handle on which the rule will be removed. 
 * @param rule The filtering rule to be removed from the NIC.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_remove_hw_rule(pfring *ring, u_int16_t rule_id);

/**
 * Set the device channel id to be used.
 * @param ring       The PF_RING handle.
 * @param channel_id The channel id. 
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_channel_id(pfring *ring, u_int32_t channel_id);

/**
 * Set the channel mask to be used for packet capture.
 * @param ring         The PF_RING handle.
 * @param channel_mask The channel mask.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_channel_mask(pfring *ring, u_int64_t channel_mask);

/**
 * Tell PF_RING the name of the application (usually argv[0]) that uses this ring. This information is used to identify the application 
 * when accessing the files present in the PF_RING /proc filesystem. 
 * This is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_APPNAME environment variable.
 * Example:
 * $ cat /proc/net/pf_ring/16614-eth0.0 | grep Name
 * Appl. Name     : pfcount
 * @param ring The PF_RING handle to enable. 
 * @param name The name of the application using this ring.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_application_name(pfring *ring, char *name);

/**
 * Set custom application statistics. 
 * @param ring The PF_RING handle.
 * @param stats The application stats.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_application_stats(pfring *ring, char *stats);

/**
 * Return the filename where the application statistics can be read. 
 * @param ring     The PF_RING handle.
 * @param path     A user-allocated buffer on which the stats filename will be stored.
 * @param path_len The path len.
 * @return The path if success, NULL otherwise.
 */
char* pfring_get_appl_stats_file_name(pfring *ring, char *path, u_int path_len);

/**
 * Bind a socket to a device.
 * @param ring        The PF_RING handle.
 * @param device_name The device name.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_bind(pfring *ring, char *device_name);

/**
 * Send a raw packet (i.e. it is sent on wire as specified). This packet must be fully specified (the MAC address up) 
 * and it will be transmitted as-is without any further manipulation.
 * 
 * Depending on the driver being used, packet transmission happens differently:
 * - Vanilla and PF_RING aware drivers: PF_RING does not accelerate the TX so the standard Linux transmission facilities are used. 
 *   Do not expect speed advantage when using PF_RING in this mode.
 * - ZC/DNA: line rate transmission is supported.
 * @param ring         The PF_RING handle on which the packet has to be sent.
 * @param pkt          The buffer containing the packet to send.
 * @param pkt_len      The length of the pkt buffer.
 * @param flush_packet 1 = Flush possible transmission queues. If set to 0, you will decrease your CPU usage but at the cost of 
 *                     sending packets in trains and thus at larger latency.
 * @return The number of bytes sent if success, a negative value otherwise.
 */
int pfring_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);

/**
 * Same as pfring_send(), with the possibility to specify the outgoing interface index. 
 * @param ring
 * @param pkt
 * @param pkt_len
 * @param flush_packet
 * @param if_index     The interface index assigned to the outgoing device. 
 * @return The number of bytes sent if success, a negative value otherwise.
 */
int pfring_send_ifindex(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet, int if_index);

/**
 * Same as pfring_send(), but this function allows to send a raw packet returning the exact time (ns) it has been sent on the wire. 
 * Note that this is available when the adapter supports tx hardware timestamping only and might affect performance.
 * @param ring
 * @param pkt
 * @param pkt_len
 * @param ts      The struct where the tx timestamp will be stored.
 * @return The number of bytes sent if success, a negative value otherwise. 
 */
int pfring_send_get_time(pfring *ring, char *pkt, u_int pkt_len, struct timespec *ts);

/**
 * Returns the number of RX channels (also known as RX queues) of the ethernet interface to which this ring is bound. 
 * @param ring The PF_RING handle to query.
 * @return The number of RX channels, or 1 (default) in case this in information is unknown.
 */
u_int8_t pfring_get_num_rx_channels(pfring *ring);

/**
 * Implement packet sampling directly into the kernel. Note that this solution is much more efficient than implementing it in user-space. 
 * Sampled packets are only those that pass all filters (if any).
 * @param ring The PF_RING handle on which sampling is applied. 
 * @param rate The sampling rate. Rate of X means that 1 packet out of X is forwarded. This means that a sampling rate of 1 disables sampling.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_sampling_rate(pfring *ring, u_int32_t rate /* 1 = no sampling */);

/**
 * Returns the file descriptor associated to the specified ring. 
 * This number can be used in function calls such as poll() and select() for passively waiting for incoming packets. 
 * @param ring The PF_RING handle to query. 
 * @return A number that can be used as reference to this ring, in function calls that require a selectable file descriptor.
 */
int pfring_get_selectable_fd(pfring *ring);

/**
 * Tell PF_RING to consider only those packets matching the specified direction. If the application does not call this function, 
 * all the packets (regardless of the direction, either RX or TX) are returned. 
 * @param ring      The PF_RING handle to enable.
 * @param direction The packet direction (RX, TX or both RX and TX).
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_direction(pfring *ring, packet_direction direction);

/**
 * Tell PF_RING if the application needs to send and/or receive packets to/from the socket. 
 * @param ring The PF_RING handle to enable. 
 * @param mode The socket mode (send, receive or both send and receive).
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_socket_mode(pfring *ring, socket_mode mode);

/**
 * This call allows a ring to be added to a cluster that can spawn across address spaces. 
 * On a nuthsell when two or more sockets are clustered they share incoming packets that are balanced on a per-flow manner. 
 * This technique is useful for exploiting multicore systems of for sharing packets in the same address space across multiple threads.
 * Clustering is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_CLUSTER_ID environment variable (Round-Robin by default, 
 * per-flow via the PCAP_PF_RING_USE_CLUSTER_PER_FLOW environment variable). 
 * @param ring The  PF_RING handle to be cluster. 
 * @param clusterId A numeric identifier of the cluster to which the ring will be bound.
 * @param the_type  The cluster type (2-tuple, 4-tuple, 5-tuple, tcp only 5-tuple, 6-tuple flow or Round-Robin).
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_cluster(pfring *ring, u_int clusterId, cluster_type the_type);

/**
 * This call allows a ring to be removed from a previous joined cluster. 
 * @param ring      The PF_RING handle to be cluster.
 * @param clusterId A numeric identifier of the cluster to which the ring will be bound.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_remove_from_cluster(pfring *ring);

/**
 * Set the master ring using the id (vanilla PF_RING only)
 * @param ring   The PF_RING handle.
 * @param master The master socket id.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_master_id(pfring *ring, u_int32_t master_id);

/**
 * Set the master ring using the PF_RING handle (vanilla PF_RING only).
 * @param ring   The PF_RING handle.
 * @param master The master PF_RING handle.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_master(pfring *ring, pfring *master);

/**
 * Return the ring id.
 * @param ring The PF_RING handle.
 * @return The ring id.
 */
u_int16_t pfring_get_ring_id(pfring *ring);

/**
 * Return an estimation of the enqueued packets.
 * @param ring The PF_RING handle.
 * @param  
 * @return 0 on success, a negative value otherwise.
 */
u_int32_t pfring_get_num_queued_pkts(pfring *ring);

/**
 * Return the identifier of the kernel plugin responsible for consuming packets.
 * @param ring The PF_RING handle.
 * @return The kernel plugin identifier.
 */
u_int8_t pfring_get_packet_consumer_mode(pfring *ring);

/**
 * Initialize the kernel plugin for packet processing.
 * @param ring The PF_RING handle.
 * @param plugin_id       The plugin id.
 * @param plugin_data     The plugin data.
 * @param plugin_data_len The size of the plugin data.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_packet_consumer_mode(pfring *ring, u_int8_t plugin_id,
				    char *plugin_data, u_int plugin_data_len);

/**
 * Add or remove a hash filtering rule. 
 * All rule parameters should be defined in the filtering rule (no wildcards).
 * @param ring        The PF_RING handle from which stats will be read.
 * @param rule_to_add The rule that will be added/removed as defined in the last chapter of this document. 
 *                    All rule parameters should be defined in the filtering rule (no wildcards).
 * @param add_rule    If set to a positive value the rule is added, if zero the rule is removed.
 * @return 0 on success, a negative value otherwise (e.g. the rule to be removed does not exist).
 */
int pfring_handle_hash_filtering_rule(pfring *ring,
				      hash_filtering_rule* rule_to_add,
				      u_char add_rule);

/**
 * Add a wildcard filtering rule to an existing ring. Each rule will have a unique rule Id across the ring (i.e. two rings can have rules with the same id).
 * 
 * PF_RING allows filtering packets in two ways: precise (a.k.a. hash filtering) or wildcard filtering. 
 * Precise filtering is used when it is necessary to track a precise 6-tuple connection <vlan Id, protocol, source IP, source port, destination IP, destination port>. 
 * Wildcard filtering is used instead whenever a filter can have wildcards on some of its fields (e.g. match all UDP packets regardless of their destination). 
 * If some field is set to zero it will not participate in filter calculation.
 *
 * Note about packet reflection: packet reflection is the ability to bridge packets in kernel without sending them to userspace and back. 
 * You can specify packet reflection inside the filtering rules.
 * 
 * typedef struct {
 *  ...
 * char reflector_device_name[REFLECTOR_NAME_LEN];
 * ...
 * } filtering_rule;
 * 
 * In the reflector_device_name you need to specify a device name (e.g. eth0) on which packets matching the filter will be reflected. 
 * Make sure NOT to specify as reflection device the same device name on which you capture packets, as otherwise you will create a packet loop.
 *
 * @param ring        The PF_RING handle on which the rule will be added.
 * @param rule_to_add The rule to add as defined in the last chapter of this document.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add);

/**
 * Remove a previously added filtering rule. 
 * @param ring    The PF_RING handle on which the rule will be removed.
 * @param rule_id The id of a previously added rule that will be removed.
 * @return 0 on success, a negative value otherwise (e.g. the rule does not exist).
 */
int pfring_remove_filtering_rule(pfring *ring, u_int16_t rule_id);

/**
 * Remove hash filtering rules inactive for the specified number of seconds.
 * @param ring           The PF_RING handle on which the rules will be removed.
 * @param inactivity_sec The inactivity threshold.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_purge_idle_hash_rules(pfring *ring, u_int16_t inactivity_sec);

/**
 * Remove filtering rules inactive for the specified number of seconds. 
 * @param ring           The PF_RING handle on which the rules will be removed.
 * @param inactivity_sec The inactivity threshold.
 * @return 0 on success, a negative value otherwise
 */
int pfring_purge_idle_rules(pfring *ring, u_int16_t inactivity_sec);

/**
 * Read statistics of a hash filtering rule. 
 * @param ring      The PF_RING handle on which the rule will be added/removed.
 * @param rule      The rule for which stats are read. This needs to be the same rule that has been previously added.
 * @param stats     A buffer allocated by the user that will contain the rule statistics. 
 *                  Please make sure that the buffer is large enough to contain the statistics. 
 *                  Such buffer will contain number of received and dropped packets.
 * @param stats_len The size (in bytes) of the stats buffer.
 * @return 0 on success, a negative value otherwise (e.g. the rule to be removed does not exist). 
 */
int pfring_get_hash_filtering_rule_stats(pfring *ring,
					 hash_filtering_rule* rule,
					 char* stats, u_int *stats_len);

/**
 * Read statistics of a hash filtering rule. 
 * @param ring      The PF_RING handle from which stats will be read.
 * @param rule_id   The rule id that identifies the rule for which stats are read.
 * @param stats     A buffer allocated by the user that will contain the rule statistics. 
 *                  Please make sure that the buffer is large enough to contain the statistics. 
 *                  Such buffer will contain number of received and dropped packets.
 * @param stats_len The size (in bytes) of the stats buffer.
 * @return 0 on success, a negative value otherwise (e.g. the rule does not exist).
 */
int pfring_get_filtering_rule_stats(pfring *ring, u_int16_t rule_id,
				    char* stats, u_int *stats_len);

/**
 * Set the default filtering policy. This means that if no rule is matching the incoming packet the default policy will decide 
 * if the packet is forwarded to user space or dropped. Note that filtering rules are limited to a ring, so each ring can have 
 * a different set of rules and default policy. 
 * @param ring The PF_RING handle on which the rule will be added/removed. 
 * @param rules_default_accept_policy If set to a positive value the default policy is accept (i.e. forward packets to user space), drop otherwise.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_toggle_filtering_policy(pfring *ring, u_int8_t rules_default_accept_policy);

/**
 * Tells PF_RING to rehash incoming packets using a bi-directional hash function.
 * This is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_RSS_REHASH environment variable. 
 * @param ring The PF_RING handle to query.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_enable_rss_rehash(pfring *ring);

/**
 * Performs passive wait on a PF_RING socket, similar to the standard poll(), taking care of data structures synchronization. 
 * @param ring          The PF_RING socket to poll. 
 * @param wait_duration The poll timeout in msec.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_poll(pfring *ring, u_int wait_duration);

/**
 * Check if a packet is available.
 * @param ring The PF_RING handle.
 * @return 1 if a packet is available, 0 otherwise.
 */
int pfring_is_pkt_available(pfring *ring);

/**
 * This call returns the arrival time of the next incoming packet, when available. 
 * @param ring The PF_RING handle where we perform the check.
 * @param ts   The struct where the time will be stored.
 * @return 0 in case of success, a negative number in case of error.
 */
int pfring_next_pkt_time(pfring *ring, struct timespec *ts);

/**
 * This call returns the raw timestamp of the next incoming packet, when available. This is available with adapters supporting rx hardware timestamping only. 
 * @param ring         The PF_RING handle where we perform the check. 
 * @param timestamp_ns Where the timestamp will be stored.
 * @return 0 in case of success, a negative number in case of error.
 */
int pfring_next_pkt_raw_timestamp(pfring *ring, u_int64_t *timestamp_ns);

/**
 * Read the ring version. Note that if the ring version is 5.6 the retuned ring version is 0x050600. 
 * @param ring    The PF_RING handle to enable.
 * @param version A user-allocated buffer on which ring version will be copied.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_version(pfring *ring, u_int32_t *version);

/**
 * Set a reflector device to send all incoming packets. This open a new socket and packets are automatically sent using pfring_send().
 * @param ring        The PF_RING handle.
 * @param device_name The device name. 
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_reflector_device(pfring *ring, char *device_name);

/**
 * Returns the MAC address of the device bound to the socket. 
 * @param ring        The PF_RING handle to query.
 * @param mac_address The memory area where the MAC address will be copied.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_get_bound_device_address(pfring *ring, u_char mac_address[6]);

/**
 * Return the size of the PF_RING packet header (vanilla PF_RING only).
 * @param ring The PF_RING handle.
 * @return The size of the packet header.
 */
u_int16_t pfring_get_slot_header_len(pfring *ring);

/**
 * Returns the interface index of the device bound to the socket. 
 * @param ring     The PF_RING handle to query. 
 * @param if_index The memory area where the interface index will be copied
 * @return 0 on success, a negative value otherwise.
 */
int pfring_get_bound_device_ifindex(pfring *ring, int *if_index);

/**
 * Return the interface index of the provided device.
 * @param ring        The PF_RING handle.
 * @param device_name The device name.
 * @param if_index    The memory area for storing the interface index.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_get_device_ifindex(pfring *ring, char *device_name, int *if_index);

/**
 * Set a filtering device.
 * @param ring The PF_RING handle.
 * @param info The filtering device info.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_virtual_device(pfring *ring, virtual_filtering_device_info *info);

/**
 * This call processes packets until pfring_breakloop() is called or an error occurs. 
 * @param ring            The PF_RING handle.
 * @param looper          A callback to be called for each received packet. The parameters passed to this routine are: 
 *                        a pointer to a struct pfring_pkthdr, a pointer to the packet memory, and a pointer to user_bytes.
 * @param user_bytes      A pointer to user’s data which is passed to the callback.
 * @param wait_for_packet If 0 active wait is used to check the packet availability.
 * @return A non-negative number if pfring_breakloop() is called. A negative number in case of error.
 */
int pfring_loopback_test(pfring *ring, char *buffer, u_int buffer_len, u_int test_len);

/**
 * When a ring is created, it is not enabled (i.e. incoming packets are dropped) until the above function is called. 
 * @param ring The PF_RING handle to enable.
 * @return 0 on success, a negative value otherwise (e.g. the ring cannot be enabled).
 */
int pfring_enable_ring(pfring *ring);

/**
 * Disable a ring. 
 * @param ring The PF_RING handle to disable.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_disable_ring(pfring *ring);

/**
 * In order to set BPF filters through the PF_RING API it’s necessary to enable (this is the default) BPF support 
 * at compile time and link PF_RING-enabled applications against the -lpcap library (it is possible to disable the 
 * BPF support with "cd userland/lib/; ./configure --disable-bpf; make" to avoid linking libpcap). 
 * @param ring          The PF_RING handle on which the filter will be set.
 * @param filter_buffer The filter to set.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_bpf_filter(pfring *ring, char *filter_buffer);

/**
 * Remove the BPF filter. 
 * @param ring The PF_RING handle.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_remove_bpf_filter(pfring *ring);

/**
 * Sets the filtering mode (software only, hardware only, both software and hardware) in order to implicitly 
 * add/remove hardware rules by means of the same API functionality used for software (wildcard and hash) rules. 
 * @param ring The PF_RING handle on which the rule will be removed. 
 * @param mode The filtering mode.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_filtering_mode(pfring *ring, filtering_mode mode);

/**
 * Reads the time from the device hardware clock, when the adapter supports hardware timestamping. 
 * @param ring The PF_RING handle. 
 * @param ts   The struct where time will be stored.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_get_device_clock(pfring *ring, struct timespec *ts);

/**
 * Sets the time in the device hardware clock, when the adapter supports hardware timestamping. 
 * @param ring The PF_RING handle.
 * @param ts   The time to be set.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_device_clock(pfring *ring, struct timespec *ts);

/**
 * Adjust the time in the device hardware clock with an offset, when the adapter supports hardware timestamping. 
 * @param ring   The PF_RING handle.
 * @param offset The time offset.
 * @param sign   The offset sign.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_adjust_device_clock(pfring *ring, struct timespec *offset, int8_t sign);

/**
 * Synchronizes the ingress ring indexes/registers with the kernel.
 * @param ring The PF_RING handle.
 */
void pfring_sync_indexes_with_kernel(pfring *ring);

/**
 * Send the last received packet to the specified device. This is an optimization working with standard PF_RING only. 
 * @param ring            The PF_RING handle on which the packet has been received. 
 * @param tx_interface_id The egress interface index.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_send_last_rx_packet(pfring *ring, int tx_interface_id);

/**
 * Return the link status.
 * @param ring The PF_RING handle.
 * @return 1 if link is up, 0 otherwise.
 */
int pfring_get_link_status(pfring *ring);

/**
 * Return the number of slots in the egress ring.
 * @param ring The PF_RING handle.
 * @return The number of slots. 
 */

u_int pfring_get_num_tx_slots(pfring *ring);

/**
 * Return the number of slots in the ingress ring.
 * @param ring The PF_RING handle.
 * @return The number of slots.
 */
u_int pfring_get_num_rx_slots(pfring *ring);

/**
 * Copies a packet into the specified slot of the egress ring.
 * @param ring       The PF_RING handle.
 * @param tx_slot_id The slot index. 
 * @param buffer     The packet to copy. 
 * @param len        The packet length.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_copy_tx_packet_into_slot(pfring *ring, u_int16_t tx_slot_id, char* buffer, u_int len);

/**
 * Return the pointer to the buffer pointed by the packet buffer handle.
 * @param ring       The PF_RING handle.
 * @param pkt_handle The packet handle.
 * @return The pointer to the packet buffer. 
 */
u_char* pfring_get_pkt_buff_data(pfring *ring, pfring_pkt_buff *pkt_handle);

/**
 * Set the length of the packet. This function call is not necessary unless you want to custom set the packet length, instead of using the size from the received packet.
 * @param ring       The PF_RING handle.
 * @param pkt_handle The packet handle.
 * @param len        The packet length.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_pkt_buff_len(pfring *ring, pfring_pkt_buff *pkt_handle, u_int32_t len);

/**
 * Bind the buffer handle (handling a packet) to an interface id. This function call is useful to specify the egress interface index.
 * @param ring       The PF_RING handle.
 * @param pkt_handle The packet handle.
 * @param if_index   The interface index.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_pkt_buff_ifindex(pfring *ring, pfring_pkt_buff *pkt_handle, int if_index);

/**
 * Add an interface index to the interface indexes bound to the buffer handle. This is used to specify the egress interfaces (fan-out) of a packet buffer.
 * @param ring The PF_RING handle.
 * @param pkt_handle The packet handle. 
 * @param if_index   The interface index.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_add_pkt_buff_ifindex(pfring *ring, pfring_pkt_buff *pkt_handle, int if_index);

/**
 * Allocate a packet buffer handle. 
 * The memory is allocated by PF_RING into the kernel and it is managed by PF_RING (i.e. no free() on this memory) using the pfring_XXX_XXX calls.
 * @param ring The PF_RING handle.
 * @return The buffer handle. 
 */
pfring_pkt_buff* pfring_alloc_pkt_buff(pfring *ring);

/**
 * Release a packet buffer handle previously allocated by pfring_alloc_pkt_buff.
 * @param ring       The PF_RING handle.
 * @param pkt_handle The packet buffer handle.
 */
void pfring_release_pkt_buff(pfring *ring, pfring_pkt_buff *pkt_handle);

/**
 * Same as pfring_recv(), this function receive a packet filling the buffer pointed by the provided packet handle instead of returning a new buffer. 
 * In a nutshell, the returned packet is put on the passed function argument.
 * @param ring       The PF_RING handle.
 * @param pkt_handle The packet buffer handle.
 * @param hdr        The PF_RING header.
 * @param wait_for_incoming_packet If 0 we simply check the packet availability, otherwise the call is blocked until a packet is available. 
 * @return 0 in case of no packet being received (non-blocking), 1 in case of success, -1 in case of error.
 */
int pfring_recv_pkt_buff(pfring *ring, pfring_pkt_buff *pkt_handle, struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);

/**
 * Same as pfring_send(), this function send the packet pointed by the provided packet buffer handle. 
 * Note: this function resets the content of the buffer handle so if you need to keep its content, make sure you copy the data before you call it.
 * @param ring         The PF_RING handle.
 * @param pkt_handle   The packet buffer handle.
 * @param flush_packet Flush all packets in the transmission queues, if any.
 * @return The number of bytes sent if success, a negative value otherwise.
 */
int pfring_send_pkt_buff(pfring *ring, pfring_pkt_buff *pkt_handle, u_int8_t flush_packet);

/**
 * Synchronizes the egress ring indexes/registers flushing enqueued packets.
 * @param ring The PF_RING handle.
 * @param  
 * @return 0 on success, a negative value otherwise.
 */
int pfring_flush_tx_packets(pfring *ring);

/**
 * Add a string to search in the packet payload (used for filtering).
 * @param ring             The PF_RING handle.
 * @param string_to_search The string to search.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_search_payload(pfring *ring, char *string_to_search);

/**
 * Attach a DNA socket to a DNA Cluster slave socket, allowing an application receiving packets from a cluster to send them in zero-copy to a DNA interface/queue.
 * @param ring The PF_RING DNA Cluster slave handle.
 * @param ring The PF_RING DNA tx socket that have to be attached to the cluster.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_register_zerocopy_tx_ring(pfring *ring, pfring *tx_ring);

/* PF_RING Socket bundle */

/**
 * Initialize a bundle socket.
 * @param bundle             The PF_RING bundle handle.
 * @param bundle_read_policy The policy for reading ingress packets.
 */
void pfring_bundle_init(pfring_bundle *bundle, bundle_read_policy p);

/**
 * Add a ring to a bundle socket.
 * @param bundle The PF_RING bundle handle.
 * @param ring   The PF_RING handle to add.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_bundle_add(pfring_bundle *bundle, pfring *ring);

/**
 * Poll on a bundle socket.
 * @param bundle        The PF_RING bundle handle.
 * @param wait_duration The poll duration.
 * @return The poll return value.
 */
int pfring_bundle_poll(pfring_bundle *bundle, u_int wait_duration);

/**
 * Same as pfring_recv() on a bundle socket.
 * @param bundle     The PF_RING bundle handle.
 * @param buffer
 * @param buffer_len
 * @param hdr
 * @param wait_for_incoming_packet
 * @return 0 in case of no packet being received (non-blocking), 1 in case of success, -1 in case of error.
 */
int pfring_bundle_read(pfring_bundle *bundle, 
		       u_char** buffer, u_int buffer_len,
		       struct pfring_pkthdr *hdr,
		       u_int8_t wait_for_incoming_packet);

/**
 * Destroy a bundle socket.
 * @param bundle The PF_RING bundle handle.
 */
void pfring_bundle_destroy(pfring_bundle *bundle);

/**
 * Close a bundle socket.
 * @param bundle The PF_RING bundle handle.
 */
void pfring_bundle_close(pfring_bundle *bundle);

/* Utils (defined in pfring_utils.c) */

/**
 * Parse a packet. 
 * It expects that the hdr memory is either zeroed or contains valid values for the current packet, in order to avoid  parsing twice the same packet headers. 
 * This is implemented by controlling the l3_offset and l4_offset fields, indicating that respectively the L2 and L3 layers have been parsed when other than zero.
 * @param pkt           The packet buffer.
 * @param hdr           The header to be filled.
 * @param level         The header level where to stop parsing.
 * @param add_timestamp Add the timestamp.
 * @param add_hash      Compute an IP-based bidirectional hash.
 * @return A non-negative number indicating the topmost header level on success,  a negative value otherwise.
 */
int pfring_parse_pkt(u_char *pkt, struct pfring_pkthdr *hdr, u_int8_t level /* 2..4 */, 
		     u_int8_t add_timestamp /* 0,1 */, u_int8_t add_hash /* 0,1 */);
/**
 * Set the promiscuous mode flag to a device.
 * @param device      The device name.
 * @param set_promisc The promisc flag. 
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_if_promisc(const char *device, int set_promisc);

/**
 * Format a number.
 * @param val          The value.
 * @param buf          The destination buffer.
 * @param buf_len      The destination buffer length.
 * @param add_decimals A flag indicating whether to add decimals.
 * @return The produced string.
 */
char* pfring_format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals);

/**
 * Enables rx and tx hardware timestamping, when the adapter supports it. 
 * @param ring        The PF_RING handle.
 * @param device_name The name of the device where timestamping will be enabled.
 * @param enable_rx   Flag to enable rx timestamping.
 * @param enable_tx   Flag to enable tx timestamping.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_enable_hw_timestamp(pfring *ring, char *device_name, u_int8_t enable_rx, u_int8_t enable_tx);

/**
 * Return the size of the MTU.
 * @param ring The PF_RING handle.
 * @return The MTU size on success, a negative value otherwise.
 */
int pfring_get_mtu_size(pfring *ring);

/**
 * Return NIC settings: max packet length, num rx/tx slots (DNA/ZC only).
 * @param ring     The PF_RING handle.
 * @param settings The card settings (output).
 * @return 0 on success, a negative value otherwise.
 */
int pfring_get_card_settings(pfring *ring, pfring_card_settings *settings);

/**
 * Print a packet (the header with parsing info must be provided). 
 * @param buff     The destination buffer.
 * @param buff_len The destination buffer length.
 * @param p        The packet.
 * @param h        The header.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_print_parsed_pkt(char *buff, u_int buff_len, const u_char *p, const struct pfring_pkthdr *h);

/**
 * Print a packet.
 * @param buff     The destination buffer.
 * @param buff_len The destination buffer length.
 * @param p        The packet.
 * @param caplen   The packet length.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_print_pkt(char *buff, u_int buff_len, const u_char *p, u_int len, u_int caplen);

 /**
 * Receive a packet chunk, if enabled via pfring_open() flag.
 * @param ring                      The PF_RING handle.
 * @param chunk                     A buffer that will point to the received chunk. Note that the chunk format is adapter specific.
 * @param chunk_len                 Length of the received data chunk.
 * @param wait_for_incoming_chunk   If 0 active wait is used to check the packet availability.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_recv_chunk(pfring *ring, void **chunk, u_int32_t *chunk_len, u_int8_t wait_for_incoming_chunk);

 /**
 * Set a custom device name to which the socket is bound. This function should be called for devices that are not visible via ifconfig
 * @param ring            The PF_RING handle.
 * @param custom_dev_name The custom device name to be used for this socket.
 * @return 0 on success, a negative value otherwise.
 */
int pfring_set_bound_dev_name(pfring *ring, char *custom_dev_name);

 /**
 * Reads a IXIA-formatted timestamp from an incoming packet and puts it into the timestamp variable.
 * @param buffer            Incoming packet buffer.
 * @param buffer_len        Incoming packet buffer length.
 * @param ts                If found the hardware timestamp will be placed here
 * @return The length of the IXIA timestamp (hence 0 means that the timestamp has not been found).
 */
int pfring_read_ixia_hw_timestamp(u_char *buffer, u_int32_t buffer_len, struct timespec *ts);

 /**
 * Strip a IXIA-formatted timestamp from an incoming packet. If the timestamp is found, the
 * hdr parameter (caplen and len fields) are decreased by the size of the timestamp.
 * @param buffer            Incoming packet buffer.
 * @param hdr               This is an in/out parameter: it is used to read the original packet len, and it is updated (size decreased) if the hw timestamp is found
 * @return 0 on success, a negative value otherwise.
 */
void pfring_handle_ixia_hw_timestamp(u_char* buffer, struct pfring_pkthdr *hdr);

 /**
 * Reads a VSS/APCON-formatted timestamp from an incoming packet and puts it into the timestamp variable.
 * @param buffer            Incoming packet buffer.
 * @param buffer_len        Incoming packet buffer length.
 * @param ts                If found the hardware timestamp will be placed here
 * @return The length of the VSS/APCON timestamp
 */
int pfring_read_vss_apcon_hw_timestamp(u_char *buffer, u_int32_t buffer_len, struct timespec *ts);

 /**
 * Strip an VSS/APCON-formatted timestamp from an incoming packet. If the timestamp is found, the
 * hdr parameter (caplen and len fields) are decreased by the size of the timestamp.
 * @param buffer            Incoming packet buffer.
 * @param hdr               This is an in/out parameter: it is used to read the original packet len, and it is updated (size decreased) if the hw timestamp is found
 * @return 0 on success, a negative value otherwise.
 */
void pfring_handle_vss_apcon_hw_timestamp(u_char* buffer, struct pfring_pkthdr *hdr);

/* ********************************* */

int pfring_parse_bpf_filter(char *filter_buffer, u_int caplen,
 #ifdef BPF_RELEASE
                            struct bpf_program
#else
                            struct pfring_bpf_program
#endif
                            *filter);

void pfring_free_bpf_filter(
#ifdef BPF_RELEASE
                            struct bpf_program
#else
                            struct pfring_bpf_program
#endif
                            *filter);

/* ********************************* */

/* pfring_utils.h */
int32_t gmt_to_local(time_t t);

/* ********************************* */

typedef struct {
  char   *name;
  int   (*open)  (pfring *);
} pfring_module_info;

#ifdef HAVE_ZERO
#include "pfring_zero.h"
#endif

#ifdef __cplusplus
}
#endif

#endif /* _PFRING_H_ */

