---
title: "PF_RING ZC API"
description: "PF_RING ZC library header file."
outline: [2, 3]
---
# PF_RING ZC API


PF_RING ZC library header file.

This header file is automatically included in any PF_RING-based applications (when the HAVE_PF_RING_ZC macro is defined).

## pfring_zc_queue_mode

```c
typedef enum {
  rx_only,        /**< RX only mode. */
  tx_only,        /**< TX only mode. */
  management_only /**< No capture/transmission. */
} pfring_zc_queue_mode;
```

List of possible queue modes.

## pfring_zc_stat

```c
typedef struct {
  u_int64_t recv;
  u_int64_t sent;
  u_int64_t drop;
} pfring_zc_stat;
```

Queue stats structure.

## pfring_zc_timespec

```c
typedef struct {
  u_int32_t tv_sec;
  u_int32_t tv_nsec;
} pfring_zc_timespec;
```

Struct for nsec time (similar to struct timespec).

## pfring_zc_pkt_buff

```c
typedef struct {
  u_int16_t len;         /**< Packet length. */
  u_int16_t flags;       /**< Packet flags (see PF_RING_ZC_PKT_FLAGS_*). */
  u_int32_t hash;        /**< Packet hash. */
  pfring_zc_timespec ts; /**< Packet timestamp (nsec) */
  u_char user[];         /**< Start of user metadata, if any. */
} pfring_zc_pkt_buff;
```

Buffer handle.

## pfring_zc_queue_info

```c
typedef struct {
  u_int32_t buffer_len;   /**< Max packet length. */
  u_int32_t metadata_len; /**< User metadata length. */
} pfring_zc_queue_info;
```

Queue info.

## pfring_zc_cluster_info

```c
typedef struct {
  u_int64_t total_memory;    /**< Total amount of allocated memory. */
  u_int32_t buffer_len;      /**< Max packet length. */
  u_int32_t real_buffer_len; /**< Real size of allocated buffers (including head room and padding). */
} pfring_zc_cluster_info;
```

Cluster required resources info.

## pfring_zc_cluster_mem_info

```c
typedef struct {
  void *base_addr;   /**< Allocated memory base address. */
  u_int64_t size;    /**< Total amount of allocated memory. */
} pfring_zc_cluster_mem_info;
```

Cluster memory info.

## u_char *

```c
u_char *
pfring_zc_pkt_buff_data(
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_queue *queue
);
```

Return the pointer to the actual packet data (same as pfring_zc_pkt_buff_data_from_cluster).

| Parameter | Description |
|---|---|
| `pkt_handle` | The buffer handle. |
| `queue` | Any queue from the cluster (e.g. the queue from which the packet is arrived or destined). |

**Returns:** The pointer on success, NULL otherwise.

## pfring_zc_pkt_buff *

```c
pfring_zc_pkt_buff *
pfring_zc_pkt_data_buff(
	u_char *data,
	pfring_zc_cluster *cluster
);
```

Return the buffer handle given a pointer to a actual packet data.
This is the reverse of pfring_zc_pkt_buff_data.

| Parameter | Description |
|---|---|
| `data` | The packet data pointer. |
| `cluster` | The cluster handle. |

**Returns:** The buffer handle on success, NULL otherwise.

## void

```c
void
pfring_zc_pkt_buff_pull_only(
  pfring_zc_pkt_buff *pkt_handle,
  u_int16_t len
);
```

Remove data from the start of a buffer.

| Parameter | Description |
|---|---|
| `pkt_handle` | The buffer handle. |
| `len` | The number of bytes to remove. |

## pfring_zc_cluster *

```c
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
```

Create a new cluster.

| Parameter | Description |
|---|---|
| `cluster_id` | The unique cluster identifier. |
| `buffer_len` | The size of each buffer: it must be at least as large as the MTU + L2 header (it will be rounded up to cache line) and not bigger than the page size. |
| `metadata_len` | The size of each buffer metadata. |
| `tot_num_buffers` | The total number of buffers to reserve for queues/devices/extra allocations. |
| `numa_node_id` | The NUMA node id for cpu/memory binding. |
| `hugepages_mountpoint` | The HugeTLB mountpoint (NULL for auto-detection) for memory allocation. |
| `flags` | Optional flags: @code PF_RING_ZC_ENABLE_VM_SUPPORT enable KVM support (memory is rounded up to power of 2 thus it allocates more memory!) @endcode |

**Returns:** The cluster handle on success, NULL otherwise (errno is set appropriately).

## int

```c
int
pfring_zc_precompute_cluster_settings(
  pfring_zc_cluster_info *info, /**< Out */ 
  u_int32_t buffer_len,
  u_int32_t metadata_len,
  u_int32_t tot_num_buffers,
  u_int32_t flags
);
```

Return information about the resources that will be allocated the cluster 
including the max amount of memory.

| Parameter | Description |
|---|---|
| `info` | A struct that is filled with the cluster information. |
| `buffer_len` | The size of each buffer: it must be at least as large as the MTU + L2 header (it will be rounded up to cache line) and not bigger than the page size. |
| `metadata_len` | The size of each buffer metadata. |
| `tot_num_buffers` | The total number of buffers to reserve for queues/devices/extra allocations. |
| `flags` | Optional flags: @code PF_RING_ZC_ENABLE_VM_SUPPORT enable KVM support (memory is rounded up to power of 2 thus it allocates more memory!) @endcode |

**Returns:** 0 on success, a negative value otherwise (errno is also set appropriately)

## u_int32_t

```c
u_int32_t
pfring_zc_get_cluster_id(
  pfring_zc_cluster *cluster
);
```

Get the cluster id.

| Parameter | Description |
|---|---|
| `cluster` | The cluster handle. |

**Returns:** The cluster id.

## pfring_zc_queue *

```c
pfring_zc_queue * 
pfring_zc_open_device(
  pfring_zc_cluster *cluster,
  const char *device_name,
  pfring_zc_queue_mode queue_mode,
  u_int32_t flags
);
```

Open a network device.

| Parameter | Description |
|---|---|
| `cluster` | The cluster handle. |
| `device_name` | The device name. |
| `queue_mode` | The direction, RX or TX. |
| `flags` | Optional flags: @code PF_RING_ZC_DEVICE_ASYMMETRIC_RSS use asymmetric hw RSS for multiqueue devices PF_RING_ZC_DEVICE_FIXED_RSS_Q_0 redirect all traffic to the first hw queue PF_RING_ZC_DEVICE_SW_TIMESTAMP compute sw timestamp (please note: this adds per-packet overhead). PF_RING_ZC_DEVICE_HW_TIMESTAMP enable hw timestamp, when available PF_RING_ZC_DEVICE_STRIP_HW_TIMESTAMP strip hw timestamp from packet, when available PF_RING_ZC_DEVICE_IXIA_TIMESTAMP extract IXIA timestamp from packet PF_RING_ZC_DEVICE_NOT_REPROGRAM_RSS do not reprogram RSS redirection table PF_RING_ZC_DEVICE_CAPTURE_TX capture RX+TX traffic (ignored in kernel-bypass mode) PF_RING_ZC_DEVICE_IPONLY_RSS compute RSS hash on IP only (not 4-tuple) PF_RING_ZC_DEVICE_NOT_PROMISC  do NOT set the device in promiscuos mode PF_RING_ZC_DO_NOT_STRIP_FCS do NOT strip the FCS (CRC), when not stripped out by the adapter PF_RING_ZC_DEVICE_ARISTA_TIMESTAMP extract Arista 7150s timestamp from packet PF_RING_ZC_DEVICE_METAWATCH_TIMESTAMP extract Arista Metawatch timestamp from packet @endcode |

**Returns:** The queue handle on success, NULL otherwise (errno is set appropriately).

## pfring_zc_multi_queue *

```c
pfring_zc_multi_queue *
pfring_zc_create_multi_queue(
  pfring_zc_queue *queues[],
  u_int32_t num_queues
);
```

Create a multi-queue object to send the same packet to multiple queues. 
Constraints: when using fan-out with multiqueue (i.e. calling pfring_zc_send_pkt_multi() with multiple bits set in queues_mask)
it is not possible to have multiple multiqueue sharing the same consumers (expect metadata corruptions in this case).
Note: this call will disable standard send on the queues (only pfring_zc_send_pkt_multi() is allowed).

| Parameter | Description |
|---|---|
| `queues` | The array with the queues to bind to the multi-queue object.  |
| `num_queues` | The number of egress queues. |

**Returns:** The multi-queue handle on success, NULL otherwise (errno is set appropriately).

## pfring_zc_recv_policy

```c
typedef enum {
  round_robin_policy = 0,   /**< Round-Robin policy. */
  round_robin_bursts_policy /**< Round-Robin policy using bursts. */
} pfring_zc_recv_policy;
```

List of possible policies when receiving packets from multiple queues.

## typedef int64_t

```c
typedef int64_t
(*pfring_zc_filtering_func) (
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_queue *in_queue,
  void *user
);
```

The filtering function prototype.

| Parameter | Description |
|---|---|
| `pkt_handle` | The received buffer handle. |
| `in_queue` | The ingress queues handle from which the packet arrived. |
| `user` | The pointer to the user data. |

**Returns:** 0 to drop the packet, 1 to pass the packet.

## typedef __int128_t

```c
typedef __int128_t
(*pfring_zc_distribution_func_v3) (
  pfring_zc_pkt_buff *pkt_handle,
  pfring_zc_queue *in_queue,
  void *user
);
```

The distribution function prototype (v3 - up to 128 queues with pfring_zc_run_fanout_v3).

| Parameter | Description |
|---|---|
| `pkt_handle` | The received buffer handle. |
| `in_queue` | The ingress queues handle from which the packet arrived. |
| `user` | The pointer to the user data. |

**Returns:** The egress queue index (or a negative value to drop the packet) in case of balancing, the egress queues bit-mask in case of fan-out.

## typedef void

```c
typedef void
(*pfring_zc_idle_callback) (
);
```

The idle callback prototype.

## pfring_zc_worker *

```c
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
```

Run a balancer worker (v2).

| Parameter | Description |
|---|---|
| `in_queues` | The ingress queues handles array.  |
| `out_queues` | The egress queues handles array. |
| `num_in_queues` | The number of ingress queues. |
| `num_out_queues` | The number of egress queues. |
| `working_set_pool` | The pool handle for working set buffers allocation. The worker uses 8 buffers in burst mode, 1 otherwise. |
| `recv_policy` | The receive policy. |
| `idle_func` | The function called when there is no incoming packet. |
| `filter_func` | The filtering function, or NULL for no filtering. |
| `filter_user_data` | The user data passed to the filtering function. |
| `distr_func` | The distribution function, or NULL for the defualt IP-based distribution function. |
| `distr_user_data` | The user data passed to distribution function. |
| `active_wait` | The flag indicating whether the worker should use active or passive wait for incoming packets. |
| `core_id_affinity` | The core affinity for the worker thread. |

**Returns:** The worker handle on success, NULL otherwise (errno is set appropriately).

## pfring_zc_buffer_pool *

```c
pfring_zc_buffer_pool *
pfring_zc_create_buffer_pool(
  pfring_zc_cluster *cluster, 
  u_int32_t pool_len
);
```

Create a buffer pool to reserve a subset of the global resources.

| Parameter | Description |
|---|---|
| `cluster` | The cluster handle. |
| `pool_len` | The number of buffers to reserve for the pool. |

**Returns:** The pool handle on success, NULL otherwise (errno is set appropriately).

## char *

```c
char *
pfring_zc_version();
```

Return the ZC version

**Returns:** The PF_RING ZC version.
