/*
 * PF_RING ZC API
 *
 * (C) 2013-22 - ntop.org
 *
 */

#ifndef _PF_RING_ZC_H_
#define _PF_RING_ZC_H_

/**
 * @file pfring_zc.h
 *
 * @brief      PF_RING ZC library header file.
 * @details    This header file is automatically included in any PF_RING-based applications (when the HAVE_PF_RING_ZC macro is defined).
 */

#include <sys/types.h>
#include <linux/pf_ring.h> /* needed for hw_filtering_rule */

/* pfring_zc_create_cluster flags */
#define PF_RING_ZC_ENABLE_VM_SUPPORT          (1 << 0) /**< pfring_zc_create_cluster() flag: enable KVM support (memory is rounded up to power of 2 thus it allocates more memory!) */

/* pfring_zc_open_device flags */
#define PF_RING_ZC_DEVICE_ASYMMETRIC_RSS      (1 <<  0) /**< pfring_zc_open_device() flag: use asymmetric hw RSS for multiqueue devices. */
#define PF_RING_ZC_DEVICE_FIXED_RSS_Q_0       (1 <<  1) /**< pfring_zc_open_device() flag: redirect all traffic to the first hw queue. */
#define PF_RING_ZC_DEVICE_SW_TIMESTAMP        (1 <<  2) /**< pfring_zc_open_device() flag: compute sw timestamp (please note: this adds per-packet overhead). */
#define PF_RING_ZC_DEVICE_HW_TIMESTAMP        (1 <<  3) /**< pfring_zc_open_device() flag: enable hw timestamp, when available */
#define PF_RING_ZC_DEVICE_STRIP_HW_TIMESTAMP  (1 <<  4) /**< pfring_zc_open_device() flag: strip hw timestamp from packet, when available */
#define PF_RING_ZC_DEVICE_IXIA_TIMESTAMP      (1 <<  5) /**< pfring_zc_open_device() flag: extract IXIA timestamp from packet */
#define PF_RING_ZC_DEVICE_NOT_REPROGRAM_RSS   (1 <<  6) /**< pfring_zc_open_device() flag: do not reprogram RSS redirection table */
#define PF_RING_ZC_DEVICE_CAPTURE_TX          (1 <<  7) /**< pfring_zc_open_device() flag: capture RX+TX traffic (ignored in kernel-bypass mode) */
#define PF_RING_ZC_DEVICE_IPONLY_RSS          (1 <<  8) /**< pfring_zc_open_device() flag: compute RSS hash on IP only (not 4-tuple) */
#define PF_RING_ZC_DEVICE_NOT_PROMISC         (1 <<  9) /**< pfring_zc_open_device() flag: do NOT set the device in promiscuos mode */
#define PF_RING_ZC_DO_NOT_STRIP_FCS           (1 << 10) /**< pfring_zc_open_device() flag: do NOT strip the FCS (CRC), when not stripped out by the adapter */
#define PF_RING_ZC_DEVICE_ARISTA_TIMESTAMP    (1 << 11) /**< pfring_zc_open_device() flag: extract Arista 7150 series timestamp from packet */
#define PF_RING_ZC_DEVICE_METAWATCH_TIMESTAMP (1 << 11) /**< pfring_zc_open_device() flag: extract Arista Metawatch timestamp from packet */

#define UNDEFINED_QUEUEID 0xFFFFFFFF    /**< pfring_zc_get_queue_id() return val: queue id is not valid */
#define QUEUE_IS_DEVICE(i) (i > 0xFFFF) /**< pfring_zc_get_queue_id() return val: queue id is an encoded device index */
#define QUEUEID_TO_IFINDEX(i) (i >> 16) /**< pfring_zc_get_queue_id() return val: convert queue id to device index, if QUEUE_IS_DEVICE(id) */
#define IFINDEX_TO_QUEUEID(i) (i << 16) /**< pfring_zc_get_queue_id() return val: convert back device index to queue id, if QUEUE_IS_DEVICE(id) */

#define PF_RING_ZC_PKT_FLAGS_GOOD_IP_CS   (1 << 0) /**< pfring_zc_pkt_buff.flags: valid IP checksum detected */
#define PF_RING_ZC_PKT_FLAGS_BAD_IP_CS    (1 << 1) /**< pfring_zc_pkt_buff.flags: bad IP checksum detected */
#define PF_RING_ZC_PKT_FLAGS_GOOD_L4_CS   (1 << 2) /**< pfring_zc_pkt_buff.flags: valid TCP/UDP checksum detected */
#define PF_RING_ZC_PKT_FLAGS_BAD_L4_CS    (1 << 3) /**< pfring_zc_pkt_buff.flags: bad TCP/UDP checksum detected (note: UDP checksum 0 is detected as bad on some cards!) */
//#define PF_RING_ZC_PKT_FLAGS_TX_IP_CS   (1 << 4) /**< pfring_zc_pkt_buff.flags: compute IP checksum on transmission (when supported) */ 
//#define PF_RING_ZC_PKT_FLAGS_TX_L4_CS   (1 << 5) /**< pfring_zc_pkt_buff.flags: compute TCP checksum on transmission (when supported) */ 
#define PF_RING_ZC_PKT_FLAGS_FLOW_OFFLOAD_UPDATE (1 << 6) /**< pfring_zc_pkt_buff.flags: buffer contains flow metadata */ 
#define PF_RING_ZC_PKT_FLAGS_FLOW_OFFLOAD_PACKET (1 << 7) /**< pfring_zc_pkt_buff.flags: buffer contains a raw packet */ 
#define PF_RING_ZC_PKT_FLAGS_FLOW_OFFLOAD_MARKER (1 << 8) /**< pfring_zc_pkt_buff.flags: buffer belongs to a flow that has been marked */ 
#define PF_RING_ZC_PKT_FLAGS_FLOW_OFFLOAD_1ST    (1 << 9) /**< pfring_zc_pkt_buff.flags: buffer belongs to a flow and it's the first one (start of flow) */ 

#define PF_RING_ZC_BUILTIN_GTP_HASH_FLAGS_V1   (1 << 0) /**< pfring_zc_builtin_gtp_hash flags: GTP v1 */ 
#define PF_RING_ZC_BUILTIN_GTP_HASH_FLAGS_V2   (1 << 1) /**< pfring_zc_builtin_gtp_hash flags: GTP v2 */
#define PF_RING_ZC_BUILTIN_GTP_HASH_FLAGS_GTPC (1 << 2) /**< pfring_zc_builtin_gtp_hash flags: GTP-C */
#define PF_RING_ZC_BUILTIN_GTP_HASH_FLAGS_GTPU (1 << 3) /**< pfring_zc_builtin_gtp_hash flags: GTP-U */

/* New API features defines */
#define PF_RING_ZC_API_CLUSTER_INFO

/* Misc defines */
#define PF_RING_ZC_SEND_PKT_MULTI_MAX_QUEUES 64 /**< pfring_zc_send_pkt_multi: max number of queues in queues_mask */
#define PF_RING_ZC_BUFFER_HEAD_ROOM          64

#ifdef __cplusplus
extern "C" {
#endif

typedef void pfring_zc_cluster;
typedef void pfring_zc_queue;
typedef void pfring_zc_buffer_pool;
typedef void pfring_zc_worker;
typedef void pfring_zc_multi_queue;

/**
 * List of possible queue modes. 
 */
typedef enum {
  rx_only,        /**< RX only mode. */
  tx_only         /**< TX only mode. */
} pfring_zc_queue_mode;

/**
 * Queue stats structure. 
 */
typedef struct {
  u_int64_t recv;
  u_int64_t sent;
  u_int64_t drop;
} pfring_zc_stat;

/**
 * Struct for nsec time (similar to struct timespec).
 */
typedef struct {
  u_int32_t tv_sec;
  u_int32_t tv_nsec;
} pfring_zc_timespec;

/**
 * Buffer handle. 
 */
typedef struct {
  u_int16_t len;         /**< Packet length. */
  u_int16_t flags;       /**< Packet flags (see PF_RING_ZC_PKT_FLAGS_*). */
  u_int32_t hash;        /**< Packet hash. */
  pfring_zc_timespec ts; /**< Packet timestamp (nsec) */
  u_char user[];         /**< Start of user metadata, if any. */
} pfring_zc_pkt_buff;

/**
 * Queue info.
 */
typedef struct {
  u_int32_t buffer_len;   /**< Max packet length. */
  u_int32_t metadata_len; /**< User metadata length. */
} pfring_zc_queue_info;

/**
 * Cluster required resources info.
 */
typedef struct {
  u_int64_t total_memory;    /**< Total amount of allocated memory. */
  u_int32_t buffer_len;      /**< Max packet length. */
  u_int32_t real_buffer_len; /**< Real size of allocated buffers (including head room and padding). */
} pfring_zc_cluster_info;

/**
 * Cluster memory info.
 */
typedef struct {
  void *base_addr;   /**< Allocated memory base address. */
  u_int64_t size;    /**< Total amount of allocated memory. */
} pfring_zc_cluster_mem_info;

/**
 * Return the pointer to the actual packet data (same as pfring_zc_pkt_buff_data_from_cluster).
 * @param pkt_handle The buffer handle.
 * @param queue      Any queue from the cluster (e.g. the queue from which the packet is arrived or destined).
 * @return           The pointer on success, NULL otherwise.
 */
u_char *
pfring_zc_pkt_buff_data(
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_queue *queue
);

/**
 * Return the pointer to the actual packet data (same as pfring_zc_pkt_buff_data).
 * @param pkt_handle The buffer handle.
 * @param cluster    The cluster handle.
 * @return           The pointer on success, NULL otherwise.
 */
u_char *
pfring_zc_pkt_buff_data_from_cluster(
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_cluster *cluster
);

/**
 * Return the buffer handle given a pointer to a actual packet data.
 * This is the reverse of pfring_zc_pkt_buff_data.
 * @param data    The packet data pointer.
 * @param cluster The cluster handle.
 * @return        The buffer handle on success, NULL otherwise.
 */
pfring_zc_pkt_buff *
pfring_zc_pkt_data_buff(
	u_char *data,
	pfring_zc_cluster *cluster
);

/**
 * Remove data from the start of a buffer.
 * @param pkt_handle The buffer handle.
 * @param queue Any queue from the cluster.
 * @param len The number of bytes to remove.
 * @return The pointer to the start of the buffer on success, NULL otherwise. 
 */
u_char *
pfring_zc_pkt_buff_pull(
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_queue *queue,
  u_int16_t len
);

/**
 * Add data to the start of a buffer.
 * @param pkt_handle The buffer handle.
 * @param queue Any queue from the cluster.
 * @param len The number of bytes to add.
 * @return The pointer to the start of the buffer on success, NULL otherwise. 
 */
u_char *
pfring_zc_pkt_buff_push(
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_queue *queue,
  u_int16_t len
);

/**
 * Remove data from the start of a buffer.
 * @param pkt_handle The buffer handle.
 * @param len The number of bytes to remove.
 */
void
pfring_zc_pkt_buff_pull_only(
  pfring_zc_pkt_buff *pkt_handle,
  u_int16_t len
);

/* **************************************************************************************** */

/**
 * Create a new cluster. 
 * @param cluster_id           The unique cluster identifier.
 * @param buffer_len           The size of each buffer: it must be at least as large as the MTU + L2 header (it will be rounded up to cache line) and not bigger than the page size.
 * @param metadata_len         The size of each buffer metadata.
 * @param tot_num_buffers      The total number of buffers to reserve for queues/devices/extra allocations.
 * @param numa_node_id         The NUMA node id for cpu/memory binding.
 * @param hugepages_mountpoint The HugeTLB mountpoint (NULL for auto-detection) for memory allocation.
 * @param flags                Optional flags:
 *                             @code
 *                             PF_RING_ZC_ENABLE_VM_SUPPORT enable KVM support (memory is rounded up to power of 2 thus it allocates more memory!)
 *                             @endcode
 * @return                     The cluster handle on success, NULL otherwise (errno is set appropriately).
 */
pfring_zc_cluster * 
pfring_zc_create_cluster(
  u_int32_t cluster_id,
  u_int32_t buffer_len,
  u_int32_t metadata_len,
  u_int32_t tot_num_buffers,
  int32_t numa_node_id,
  const char *hugepages_mountpoint,
  u_int32_t flags
);

/**
 * Return information about the resources that will be allocated the cluster 
 * including the max amount of memory.
 * @param info                 A struct that is filled with the cluster information.
 * @param buffer_len           The size of each buffer: it must be at least as large as the MTU + L2 header (it will be rounded up to cache line) and not bigger than the page size.
 * @param metadata_len         The size of each buffer metadata.
 * @param tot_num_buffers      The total number of buffers to reserve for queues/devices/extra allocations.
 * @param flags                Optional flags:
 *                             @code
 *                             PF_RING_ZC_ENABLE_VM_SUPPORT enable KVM support (memory is rounded up to power of 2 thus it allocates more memory!)
 *                             @endcode
 * @return                     0 on success, a negative value otherwise (errno is also set appropriately)
 */
int
pfring_zc_precompute_cluster_settings(
  pfring_zc_cluster_info *info, /**< Out */ 
  u_int32_t buffer_len,
  u_int32_t metadata_len,
  u_int32_t tot_num_buffers,
  u_int32_t flags
);

/**
 * Return information about allocated resources.
 * @param cluster The cluster handle.
 * @param mem_info The returned information.
 */
int
pfring_zc_get_memory_info(
  pfring_zc_cluster *cluster,
  pfring_zc_cluster_mem_info *mem_info
);

/**
 * Get the cluster id. 
 * @param cluster The cluster handle.
 * @return        The cluster id.
 */
u_int32_t
pfring_zc_get_cluster_id(
  pfring_zc_cluster *cluster
);

/**
 * Destroy a cluster.
 * @param cluster The cluster handle.
 */
void 
pfring_zc_destroy_cluster(
  pfring_zc_cluster *cluster
);

/* **************************************************************************************** */

/**
 * Open a network device.
 * @param cluster     The cluster handle.
 * @param device_name The device name.
 * @param queue_mode  The direction, RX or TX.
 * @param flags       Optional flags:
 *                    @code
 *                    PF_RING_ZC_DEVICE_ASYMMETRIC_RSS use asymmetric hw RSS for multiqueue devices
 *                    PF_RING_ZC_DEVICE_FIXED_RSS_Q_0 redirect all traffic to the first hw queue
 *                    PF_RING_ZC_DEVICE_SW_TIMESTAMP compute sw timestamp (please note: this adds per-packet overhead).
 *                    PF_RING_ZC_DEVICE_HW_TIMESTAMP enable hw timestamp, when available 
 *                    PF_RING_ZC_DEVICE_STRIP_HW_TIMESTAMP strip hw timestamp from packet, when available
 *                    PF_RING_ZC_DEVICE_IXIA_TIMESTAMP extract IXIA timestamp from packet
 *                    PF_RING_ZC_DEVICE_NOT_REPROGRAM_RSS do not reprogram RSS redirection table
 *                    PF_RING_ZC_DEVICE_CAPTURE_TX capture RX+TX traffic (ignored in kernel-bypass mode)
 *                    PF_RING_ZC_DEVICE_IPONLY_RSS compute RSS hash on IP only (not 4-tuple)
 *                    PF_RING_ZC_DEVICE_NOT_PROMISC  do NOT set the device in promiscuos mode
 *                    PF_RING_ZC_DO_NOT_STRIP_FCS do NOT strip the FCS (CRC), when not stripped out by the adapter
 *                    PF_RING_ZC_DEVICE_ARISTA_TIMESTAMP extract Arista 7150s timestamp from packet
 *                    PF_RING_ZC_DEVICE_METAWATCH_TIMESTAMP extract Arista Metawatch timestamp from packet
 *                    @endcode
 * @return            The queue handle on success, NULL otherwise (errno is set appropriately). 
 */
pfring_zc_queue * 
pfring_zc_open_device(
  pfring_zc_cluster *cluster,
  const char *device_name,
  pfring_zc_queue_mode queue_mode,
  u_int32_t flags
);

/**
 * Create a SPSC queue.
 * Please note that in order to create queues to be used by external
 * processes, pfring_zc_create_queue_pool_pair is recommended.
 * @param cluster   The cluster handle.
 * @param queue_len The queue length.
 * @return          The queue handle on success, NULL otherwise (errno is set appropriately). 
 */
pfring_zc_queue * 
pfring_zc_create_queue(
  pfring_zc_cluster *cluster,
  u_int32_t queue_len
);

/**
 * Create a pair of SPSC queue and Pool with the same ID. This can be
 * used to create queues to be used by external processes.
 * @param cluster   The cluster handle.
 * @param queue_len The queue length.
 * @param pool_len  The number of buffers to reserve for the pool.
 * @param queue     The queue handle on success, NULL otherwise (out)
 * @param pool      The pool handle on success, NULL otherwise (out)
 * @return          0 on success, a negative value otherwise (errno is also set appropriately)
 */
int
pfring_zc_create_queue_pool_pair(
  pfring_zc_cluster *cluster,
  u_int32_t queue_len,
  u_int32_t pool_len,
  pfring_zc_queue **queue,
  pfring_zc_buffer_pool **pool
);

/**
 * Close a queue tied to a network device. Please note that by using this API 
 * to release a SPSC hugepages, memory is not actually released for a few 
 * reasons (e.g. memory becomes fragmented, and there could be consumer
 * processes still mapping this memory).
 * Please note that both devices and SPSC queues are automatically released
 * calling pfring_zc_destroy_cluster.
 * @param queue       The queue handle.
 */
void
pfring_zc_close_device(
  pfring_zc_queue *queue
);

/* **************************************************************************************** */

/**
 * Read the next packet from the queue.
 * @param queue                    The queue handle.
 * @param pkt_handle               The pointer to the buffer handle for the received buffer. The buffer handle must have been allocated earlier with get_packet_handle()/get_packet_handle_from_pool().
 * @param wait_for_incoming_packet The flag indicating whether this call is blocking or not.
 * @return                         1 on success, 0 on empty queue (non-blocking only), a negative value otherwise.
 */
int 
pfring_zc_recv_pkt(
  pfring_zc_queue *queue, 
  pfring_zc_pkt_buff **pkt_handle, 
  u_int8_t wait_for_incoming_packet
);

/**
 * Read a burst of packets from the queue.
 * @param queue                    The queue handle.
 * @param pkt_handles              The array with the buffer handles for the received buffers. The buffer handles must have been allocated earlier with get_packet_handle()/get_packet_handle_from_pool().
 * @param max_num_packets          The maximum number of packets to read from the queue.
 * @param wait_for_incoming_packet The flag indicating whether this call is blocking or not.
 * @return                         The number of received packets on success, 0 on empty queue (non-blocking only), a negative value otherwise.
 */
int 
pfring_zc_recv_pkt_burst(
  pfring_zc_queue *queue, 
  pfring_zc_pkt_buff **pkt_handles,
  u_int32_t max_num_packets,
  u_int8_t wait_for_incoming_packet
); 

/**
 * Check if the queue is empty (rx only for devices). 
 * @param queue The queue handle.
 * @return      1 on empty queue, 0 otherwise. 
 */
int 
pfring_zc_queue_is_empty(
  pfring_zc_queue *queue 
); 

/**
 * Break the receive loop in case of blocking pfring_zc_recv_pkt()/pfring_zc_recv_pkt_burst().
 * @param queue The queue handle.
 */
void
pfring_zc_queue_breakloop(
  pfring_zc_queue *queue 
);

/* **************************************************************************************** */

/**
 * Insert a packet into the queue.
 * @param queue        The queue handle.
 * @param pkt_handle   The pointer to the buffer handle to send. Once a packet has been sent, the buffer handle can be reused or if not longer necessary it must be freed by calling pfring_zc_release_packet_handle().
 * @param flush_packet The flag indicating whether this call should flush the enqueued packet, and older packets if any.
 * @return             The packet length on success, 0 if filtered out (bpf), a negative value otherwise. 
 */
int 
pfring_zc_send_pkt(
  pfring_zc_queue *queue, 
  pfring_zc_pkt_buff **pkt_handle,
  u_int8_t flush_packet
);

/**
 * Send a burst of packets to the queue.
 * @param queue         The queue handle.
 * @param pkt_handles   The array with the buffer handles for the buffers to send.
 * @param num_packets   The number of packets to send to the queue.
 * @param flush_packets The flag indicating whether this call should flush the enqueued packets, and older packets if any.
 * @return              The number of packets successfully sent, a negative value in case of error. Note: packets sent can be less than num_packets in case there is not enough room in the TX queue or in case of BPF filters.
 */
int 
pfring_zc_send_pkt_burst(
  pfring_zc_queue *queue, 
  pfring_zc_pkt_buff **pkt_handles,
  u_int32_t num_packets,
  u_int8_t flush_packets 
); 

/**
 * Check if the queue is full (tx only for devices). 
 * @param queue The queue handle.
 * @return      1 on full queue, 0 otherwise. 
 */
int 
pfring_zc_queue_is_full(
  pfring_zc_queue *queue 
); 

/* **************************************************************************************** */

/**
 * Sync/flush a queue. 
 * @param queue     The queue handle.
 * @param direction The direction to sync/flush, RX or TX.
 */
void
pfring_zc_sync_queue(
  pfring_zc_queue *queue,
  pfring_zc_queue_mode direction 
);

/* **************************************************************************************** */

/**
 * Set a BPF filter.
 * @param queue  The queue handle.
 * @param filter The BPF filter.
 * @return       0 on success, a negative value otherwise.
 */
int
pfring_zc_set_bpf_filter(
  pfring_zc_queue *queue,
  char *filter
);

/**
 * Remove the BPF filter.
 * @param queue  The queue handle.
 * @return       0 on success, a negative value otherwise.
 */
int
pfring_zc_remove_bpf_filter(
  pfring_zc_queue *queue
);

/* **************************************************************************************** */

/**
 * Add an hw filtering rule to the network device, when the queue is bound to a supported card.
 * @param queue The queue handle.
 * @param rule  The filtering rule.
 * @return      0 on success, a negative value otherwise.
 */
int
pfring_zc_add_hw_rule(
  pfring_zc_queue *queue,
  hw_filtering_rule *rule
);

/**
 * Remove an hw filtering rule from the network device.
 * @param queue    The queue handle.
 * @param rule_id  The filtering rule identifier.
 * @return         0 on success, a negative value otherwise.
 */
int
pfring_zc_remove_hw_rule(
  pfring_zc_queue *queue,
  u_int16_t rule_id
);

/* **************************************************************************************** */

/**
 * Change the hw RSS indirection table (RETA) for Intel igb/ixgbe-based cards.
 * @param queue       The queue handle.
 * @param indir_table The indirection table (128 cells), with the destination queue for each hash value input.
 */
void 
pfring_zc_set_rxfh_indir(
  pfring_zc_queue *queue,
  u_int8_t *indir_table
);

/* **************************************************************************************** */

/**
 * Read the queue id. If the actual queue is a device, it is possible to convert the ID to the device index using QUEUEID_TO_IFINDEX(id)
 * @param queue The queue handle.
 * @return      The queue id. A few macros are available to check the queue id:
 *              @code
 *              UNDEFINED_QUEUEID queue id is not valid
 *              QUEUE_IS_DEVICE(i) queue id is an encoded device index
 *              QUEUEID_TO_IFINDEX(i) convert queue id to device index, if QUEUE_IS_DEVICE(id)
 *              IFINDEX_TO_QUEUEID(i) convert back device index to queue id, if QUEUE_IS_DEVICE(id)
 *              @endcode
 */
u_int32_t
pfring_zc_get_queue_id(
  pfring_zc_queue *queue
);

/**
 * Read queue settings, including queue len, buffers len, metadata len.
 * @param queue The queue handle.
 * @param info  The queue settings (out).
 */
void
pfring_zc_get_queue_settings(
  pfring_zc_queue *queue,
  pfring_zc_queue_info *info
);

/**
 * Read queue speed.
 * @param queue The queue handle.
 * @return      The queue speed in Mbit/s, 0 if unknown.
 */
u_int32_t
pfring_zc_get_queue_speed(
  pfring_zc_queue *queue
);

/**
 * Read the queue stats.
 * @param queue The queue handle.
 * @param stats The stats structure.
 * @return      0 on success, a negative value otherwise.
 */
int
pfring_zc_stats(
  pfring_zc_queue *queue,
  pfring_zc_stat *stats
);

/* **************************************************************************************** */

/**
 * Allocate a buffer from global resources. 
 * @param cluster The cluster handle.
 * @return        The buffer handle on success, NULL otherwise.
 */
pfring_zc_pkt_buff * 
pfring_zc_get_packet_handle(
  pfring_zc_cluster *cluster
);

/**
 * Release a buffer to global resources. 
 * @param cluster    The cluster handle.
 * @param pkt_handle The buffer handle.
 */
void
pfring_zc_release_packet_handle(
  pfring_zc_cluster *cluster,
  pfring_zc_pkt_buff *pkt_handle
);

/* **************************************************************************************** */

/**
 * Create a multi-queue object to send the same packet to multiple queues. 
 * Constraints: when using fan-out with multiqueue (i.e. calling pfring_zc_send_pkt_multi() with multiple bits set in queues_mask)
 * it is not possible to have multiple multiqueue sharing the same consumers (expect metadata corruptions in this case).
 * Note: this call will disable standard send on the queues (only pfring_zc_send_pkt_multi() is allowed).
 * @param queues     The array with the queues to bind to the multi-queue object. 
 * @param num_queues The number of egress queues.
 * @return           The multi-queue handle on success, NULL otherwise (errno is set appropriately). 
 */
pfring_zc_multi_queue *
pfring_zc_create_multi_queue(
  pfring_zc_queue *queues[],
  u_int32_t num_queues
);

/**
 * Send a packet to multiple queues bound to a multi-queue object.
 * @param multi_queue  The multi-queue handle.
 * @param pkt_handle   The pointer to the buffer handle to send. Once a packet has been sent, the buffer handle can be reused or if not longer necessary it must be freed by calling pfring_zc_release_packet_handle().
 * @param queues_mask  The mask with the egress queues where the buffer should be inserted. The LSB indicates the first queue in the multi-queue array. The max number of queues is defined in PF_RING_ZC_SEND_PKT_MULTI_MAX_QUEUES.
 * @param flush_packet The flag indicating whether this call should flush the enqueued packet, and older packets if any.
 * @return             The number of packet copies enqueued. 
 */
int 
pfring_zc_send_pkt_multi(
  pfring_zc_multi_queue *multi_queue, 
  pfring_zc_pkt_buff **pkt_handle, 
  u_int64_t queues_mask,
  u_int8_t flush_packet
);

/* **************************************************************************************** */

/**
 * List of possible policies when receiving packets from multiple queues. 
 */
typedef enum {
  round_robin_policy = 0,   /**< Round-Robin policy. */
  round_robin_bursts_policy /**< Round-Robin policy using bursts. */
} pfring_zc_recv_policy;

/**
 * The filtering function prototype.
 * @param pkt_handle The received buffer handle.
 * @param in_queue   The ingress queues handle from which the packet arrived.
 * @param user       The pointer to the user data.
 * @return           0 to drop the packet, 1 to pass the packet.
 */
typedef int64_t
(*pfring_zc_filtering_func) (
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_queue *in_queue,
  void *user
);

/**
 * The distribution function prototype.
 * @param pkt_handle The received buffer handle.
 * @param in_queue   The ingress queues handle from which the packet arrived.
 * @param user       The pointer to the user data.
 * @return           The egress queue index (or a negative value to drop the packet) in case of balancing, the egress queues bit-mask in case of fan-out.
 */
typedef int64_t
(*pfring_zc_distribution_func) (
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_queue *in_queue,
  void *user
);

/**
 * The idle callback prototype.
 */
typedef void
(*pfring_zc_idle_callback) (
);


/**
 * Run a balancer worker.
 * @param in_queues        The ingress queues handles array. 
 * @param out_queues       The egress queues handles array.
 * @param num_in_queues    The number of ingress queues.
 * @param num_out_queues   The number of egress queues.
 * @param working_set_pool The pool handle for working set buffers allocation. The worker uses 8 buffers in burst mode, 1 otherwise.
 * @param recv_policy      The receive policy.
 * @param idle_func        The function called when there is no incoming packet.
 * @param filter_func      The filtering function, or NULL for no filtering.
 * @param filter_user_data The user data passed to the filtering function.
 * @param distr_func       The distribution function, or NULL for the defualt IP-based distribution function.
 * @param distr_user_data  The user data passed to distribution function.
 * @param active_wait      The flag indicating whether the worker should use active or passive wait for incoming packets.
 * @param core_id_affinity The core affinity for the worker thread.
 * @return                 The worker handle on success, NULL otherwise (errno is set appropriately). 
 */
pfring_zc_worker * 
pfring_zc_run_balancer_v2(
  pfring_zc_queue *in_queues[],
  pfring_zc_queue *out_queues[], 
  u_int32_t num_in_queues,
  u_int32_t num_out_queues,
  pfring_zc_buffer_pool *working_set_pool,
  pfring_zc_recv_policy recv_policy,
  pfring_zc_idle_callback idle_func,
  pfring_zc_filtering_func filter_func,
  void *filter_user_data,
  pfring_zc_distribution_func distr_func,
  void *distr_user_data,
  u_int32_t active_wait,
  int32_t core_id_affinity
);

/**
 * Same as pfring_zc_run_balancer_v2 but without a filtering function. (deprecated)
 */
pfring_zc_worker * 
pfring_zc_run_balancer(
  pfring_zc_queue *in_queues[],
  pfring_zc_queue *out_queues[], 
  u_int32_t num_in_queues,
  u_int32_t num_out_queues,
  pfring_zc_buffer_pool *working_set_pool,
  pfring_zc_recv_policy recv_policy,
  pfring_zc_idle_callback idle_func,
  pfring_zc_distribution_func distr_func,
  void *distr_user_data,
  u_int32_t active_wait,
  int32_t core_id_affinity
);

/**
 * Run a fan-out worker. 
 * @param in_queues        The ingress queues handles array. 
 * @param out_multi_queue  The egress multi-queue handle.
 * @param num_in_queues    The number of ingress queues.
 * @param working_set_pool The pool handle for working set buffers allocation. The worker uses 8 buffers in burst mode, 1 otherwise.
 * @param recv_policy      The receive policy.
 * @param idle_func        The function called when there is no incoming packet.
 * @param filter_func      The filtering function, or NULL for no filtering.
 * @param filter_user_data The user data passed to the filtering function.
 * @param distr_func       The distribution function, or NULL to send all the packets to all the egress queues.
 * @param distr_user_data  The user data passed to distribution function.
 * @param active_wait      The flag indicating whether the worker should use active or passive wait for incoming packets.
 * @param core_id_affinity The core affinity for the worker thread.
 * @return                 The worker handle on success, NULL otherwise (errno is set appropriately). 
 */
pfring_zc_worker * 
pfring_zc_run_fanout_v2(
  pfring_zc_queue *in_queues[],
  pfring_zc_multi_queue *out_multi_queue, 
  u_int32_t num_in_queues,
  pfring_zc_buffer_pool *working_set_pool,
  pfring_zc_recv_policy recv_policy,
  pfring_zc_idle_callback idle_func,
  pfring_zc_filtering_func filter_func,
  void *filter_user_data,
  pfring_zc_distribution_func distr_func,
  void *distr_user_data,
  u_int32_t active_wait,
  int32_t core_id_affinity
);

/**
 * Same as pfring_zc_run_fanout_v2 but without a filtering function. (deprecated)
 */
pfring_zc_worker * 
pfring_zc_run_fanout(
  pfring_zc_queue *in_queues[],
  pfring_zc_multi_queue *out_multi_queue, 
  u_int32_t num_in_queues,
  pfring_zc_buffer_pool *working_set_pool,
  pfring_zc_recv_policy recv_policy,
  pfring_zc_idle_callback idle_func,
  pfring_zc_distribution_func distr_func,
  void *distr_user_data,
  u_int32_t active_wait,
  int32_t core_id_affinity
);

/**
 * Run a fifo worker. (experimental) 
 * @param in_queues        The ingress queues handles array. 
 * @param out_queue        The egress queue handle, or NULL for processing packets directly using the provided func.
 * @param num_in_queues    The number of ingress queues.
 * @param working_set_pool The pool handle for working set buffers allocation. The worker uses num_in_queues * 32 buffers.
 * @param callback         The function called when there is no incoming packet.
 * @param func             The packet processing function.
 * @param user_data        The user data passed to func.
 * @param active_wait      The flag indicating whether the worker should use active or passive wait for incoming packets.
 * @param core_id_affinity_sorter The core affinity for the sorter thread.
 * @param core_id_affinity_timer  The core affinity for the timer thread.
 * @return                 The worker handle on success, NULL otherwise (errno is set appropriately). 
 */
pfring_zc_worker * 
pfring_zc_run_fifo(
  pfring_zc_queue *in_queues[],
  pfring_zc_queue *out_queue,
  u_int32_t num_in_queues,
  pfring_zc_buffer_pool *working_set_pool,
  pfring_zc_idle_callback callback,
  pfring_zc_distribution_func func,
  void *user_data,
  u_int32_t active_wait,
  int32_t core_id_affinity_sorter,
  int32_t core_id_affinity_timer
);

/**
 * Kill the worker. 
 * @param worker The worker handle.
 */
void 
pfring_zc_kill_worker(
  pfring_zc_worker *worker
);

/* **************************************************************************************** */

/**
 * Create a buffer pool to reserve a subset of the global resources.
 * @param cluster  The cluster handle.
 * @param pool_len The number of buffers to reserve for the pool.
 * @return         The pool handle on success, NULL otherwise (errno is set appropriately). 
 */
pfring_zc_buffer_pool *
pfring_zc_create_buffer_pool(
  pfring_zc_cluster *cluster, 
  u_int32_t pool_len
);

/**
 * Read pool id.
 * @param pool The pool handle.
 */
u_int32_t
pfring_zc_get_pool_id(
  pfring_zc_buffer_pool *pool
);

/**
 * Allocate a buffer from a pool resource. 
 * @param pool The pool handle.
 * @return     The buffer handle on success, NULL otherwise.
 */
pfring_zc_pkt_buff * 
pfring_zc_get_packet_handle_from_pool(
  pfring_zc_buffer_pool *pool
);

/**
 * Release a buffer to a pool. 
 * @param pool       The pool handle.
 * @param pkt_handle The buffer handle.
 */
void
pfring_zc_release_packet_handle_to_pool(
  pfring_zc_buffer_pool *pool,
  pfring_zc_pkt_buff *pkt_handle
);

/* **************************************************************************************** */

/**
 * Initialise the inter-process support on a slave.
 * @param hugepages_mountpoint The HugeTLB mountpoint (NULL for auto-detection) for the shared memory.
 */
void
pfring_zc_ipc_init(
  const char *hugepages_mountpoint
);

/**
 * Attach to a pool created by a cluster in another process.
 * @param cluster_id The cluster identifier.
 * @param pool_id    The pool identifier.
 * @return           The pool handle on success, NULL otherwise (errno is set appropriately).
 */
pfring_zc_buffer_pool *
pfring_zc_ipc_attach_buffer_pool(
  u_int32_t cluster_id,
  u_int32_t pool_id
);

/**
 * Detach a pool.  
 * @param pool The pool handle.
 */
void
pfring_zc_ipc_detach_buffer_pool(
  pfring_zc_buffer_pool *pool
);

/**
 * Attach to a queue created by a cluster on another process.
 * @param cluster_id The cluster identifier.
 * @param queue_id   The queue identifier.
 * @param queue_mode The direction to open, RX or TX.
 * @return           The queue handle on success, NULL otherwise (errno is set appropriately).
 */
pfring_zc_queue *
pfring_zc_ipc_attach_queue(
  u_int32_t cluster_id,
  u_int32_t queue_id,
  pfring_zc_queue_mode queue_mode
);

/**
 * Detach a queue.  
 * @param queue The queue handle.
 */
void
pfring_zc_ipc_detach_queue(
  pfring_zc_queue *queue
);

/* **************************************************************************************** */

/**
 * (Host) Initialise the KVM support for a VM.
 * @param cluster                The cluster handle.
 * @param vm_monitor_socket_path The monitor socket of the VM to initialise.
 * @return                       0 on success, a negative value otherwise. 
 */
int
pfring_zc_vm_register(
  pfring_zc_cluster *cluster,
  const char *vm_monitor_socket_path
);

/**
 * (Host) Enable the KVM support for all the VMs registered with pfring_zc_vm_register().
 * @param cluster The cluster handle.
 * @return        0 on success, a negative value otherwise. 
 */
int
pfring_zc_vm_backend_enable(
  pfring_zc_cluster *cluster
);

/* **************************************************************************************** */

/**
 * (Guest) Initialise the inter-VM support on a slave.
 * @param uio_device The UIO device path for the shared memory.
 */
void
pfring_zc_vm_guest_init(
  const char *uio_device
);

/* **************************************************************************************** */

/**
 * Computes an IP-based packet hash.
 * Hash input: <src ip, dst ip>
 * @param pkt_handle The pointer to the buffer handle.
 * @param queue      The queue from which the packet is arrived or destined.
 * @return           The packet hash.
 */
u_int32_t
pfring_zc_builtin_ip_hash(
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_queue *queue
);

/**
 * Computes a 5-tuple packet hash.
 * Hash input: <src ip, dst ip, src port, dst port, protocol>
 * @param pkt_handle The pointer to the buffer handle.
 * @param queue      The queue from which the packet is arrived or destined.
 * @return           The packet hash.
 */
u_int32_t
pfring_zc_builtin_5tuple_hash(
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_queue *queue
);

/**
 * Computes a GTP-C Seq-based packet hash and a GTP-U Inner-IP/Port-based packet hash, Outer-IP/Port-based packet hash otherwise.
 * Hash input: 
 * - <GTP-C Seq> for GTP-C packets
 * - <inner src ip, inner dst ip, inner src port, inner dst port> for GTP-U packets
 * - <src ip, dst ip, src port, dst port> for non GTP packets
 * @param pkt_handle The pointer to the buffer handle.
 * @param queue      The queue from which the packet is arrived or destined.
 * @param flags      Flags with info about the GTP content (version, GTP-c/GTP-u, etc)
 * @return           The packet hash.
 */
u_int32_t
pfring_zc_builtin_gtp_hash(
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_queue *queue,
  u_int32_t *flags /* out */
);

/**
 * Computes a Inner-IP-based packet hash on GRE packets, Outer-IP/Port-based packet hash otherwise.
 * Hash input:
 * - <inner src ip, inner dst ip> for GRE packets
 * - <src ip, dst ip, src port, dst port> for non GRE packets
 * @param pkt_handle The pointer to the buffer handle.
 * @param queue      The queue from which the packet is arrived or destined.
 * @return           The packet hash.
 */
u_int32_t
pfring_zc_builtin_gre_hash(
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_queue *queue
);

/* **************************************************************************************** */

/**
 * Write custom stats under /proc/net/pf_ring/stats/CLUSTER-FILE
 * @param cluster The cluster handle.
 * @param stats   The stats string to write.
 * @return        0 on success, a negative value otherwise.
 */
int
pfring_zc_set_proc_stats(
  pfring_zc_cluster *cluster,
  char *stats
);

/**
 * Write application name under /proc/net/pf_ring/SOCKET
 * @param cluster The cluster handle.
 * @param name    The application name.
 * @return      0 on success, a negative value otherwise.
 */
int
pfring_zc_set_app_name(
  pfring_zc_cluster *cluster,
  const char *name
);

/* **************************************************************************************** */

/**
 * Write custom device stats under /proc/net/pf_ring/stats/DEVICE-FILE
 * @param queue The queue handle for the device.
 * @param stats The stats string to write.
 * @return      0 on success, a negative value otherwise.
 */
int
pfring_zc_set_device_proc_stats(
  pfring_zc_queue *queue,
  const char *stats
);

/**
 * Write application name under /proc/net/pf_ring/SOCKET
 * @param queue The queue handle for the device.
 * @param name  The application name.
 * @return      0 on success, a negative value otherwise.
 */
int
pfring_zc_set_device_app_name(
  pfring_zc_queue *queue,
  const char *name
);

/* **************************************************************************************** */

/**
 * Return the ZC version
 * @return The PF_RING ZC version.
 */
char *
pfring_zc_version();

/* **************************************************************************************** */

/**
 * Check if ZC is running in demo mode (using adapters in zero-copy mode without a valid license)
 * @return 1 if ZC is running with no demo limit, 0 otherwise.
 */
int
pfring_zc_check_license();

/* **************************************************************************************** */

/**
 * Check if the license for a ZC device is valid and returns the license expiration epoch.
 * @param queue            The queue handle for the device.
 * @param expiration_epoch The variable (ptr) that will contain the expiration epoch as return value.
 * @return 1 if the license is valid, and set the expiration epoch accordingly, 0 otherwise.
 */
int
pfring_zc_check_device_license(
  pfring_zc_queue *queue,
  u_int32_t *expiration_epoch
);

/**
 * Check if the license for a ZC device is valid and returns the license expiration epoch.
 * @param device_name      The interface name.
 * @param expiration_epoch The variable (ptr) that will contain the expiration epoch as return value.
 * @return 1 if the license is valid, and set the expiration epoch accordingly, 0 otherwise.
 */
int
pfring_zc_check_device_license_by_name(
  char *device_name,
  u_int32_t *expiration_epoch
);

/* **************************************************************************************** */

/**
 * Return the NUMA node bound to the selected core
 * @param core_id The core id
 * @return        node id on success, -1 otherwise.
 */
int
pfring_zc_numa_get_cpu_node(int core_id);

/* **************************************************************************************** */

/**
 * Set the NUMA affinity to the selected NUMA node (for memory allocation)
 * @param node_id The NUMA node id
 * @return        0 on success, -1 otherwise.
 */
int
pfring_zc_numa_set_numa_affinity(int node_id);

/* **************************************************************************************** */

/**
 * Enable debug mode
 */
void
pfring_zc_debug();

/* **************************************************************************************** */

#ifdef __cplusplus
}
#endif

#endif /* _PF_RING_ZC_H_ */

