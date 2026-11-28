---
title: "PF_RING API"
description: "PF_RING library header file."
outline: [2, 3]
---
# PF_RING API


PF_RING library header file.

This header file must be included in any PF_RING-based applications.

## pfring_open

```c
pfring *pfring_open(const char *device_name, u_int32_t caplen, u_int32_t flags);
```

This call is used to initialize a PF_RING socket hence obtain a handle of type struct pfring 
that can be used in subsequent calls. Note that: 
1. you can use physical (e.g. ethX) and virtual (e.g. tapX) devices, RX-queues (e.g. ethX@Y), 
   and additional modules (e.g. zc:ethX@Y, dag:dagX:Y, "multi:ethA@X;ethB@Y;ethC@Z", "stack:ethX").
2. you need super-user capabilities in order to open a device.
 - eth0            interface eth0, all channels
 - eth0@1         interface eth0, channel 1
 - eth0,eth1       interface eth0 and eth1, all channels
 - eth0,eth1@1    interface eth0 and eth1, channel 1
 - eth0@1,5       interface eth0, channel 1 and 5
 - eth0@1-5       interface eth0, channel 1,2...5
 - eth0@1-3,5-7   interface eth0, channel 1,2,3,5,6,7
 - ',' and '-' are supported with standard kernel capture / drivers only
 - in case of multiple interfaces, the channels are same for all interfaces

| Parameter | Description |
|---|---|
| `device_name` | Symbolic name of the PF_RING-aware device we are attempting to open. Syntax: Note: |
| `caplen` | Maximum packet capture len (also known as snaplen). |
| `flags` | It allows several options to be specified on a compact format using bitmaps (see PF_RING_* macros). |

**Returns:** On success a handle is returned, NULL otherwise.

## pfring_open_multichannel

```c
u_int8_t pfring_open_multichannel(const char *device_name, u_int32_t caplen, 
				  u_int32_t flags, pfring *ring[MAX_NUM_RX_CHANNELS]);
```

This call is similar to pfring_open() with the exception that in case of a multi RX-queue NIC, 
instead of opening a single ring for the whole device, several individual rings are open (one per RX-queue).

| Parameter | Description |
|---|---|
| `device_name` | Symbolic name of the PF_RING-aware device we are attempting to open (e.g. eth0).  No queue name hash to be specified, but just the main device name. |
| `caplen` | Maximum packet capture len (also known as snaplen). |
| `flags` | See pfring_open() for details. |
| `ring` | A pointer to an array of rings that will contain the opened ring pointers. |

**Returns:** The last index of the ring array that contain a valid ring pointer.

## pfring_shutdown

```c
void pfring_shutdown(pfring *ring);
```

Shutdown a socket.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

## pfring_config

```c
void pfring_config(u_short cpu_percentage);
```

Set the scheduler priority for the current thread.

| Parameter | Description |
|---|---|
| `cpu_percentage` | The priority. |

## pfring_loop

```c
int pfring_loop(pfring *ring, pfringProcesssPacket looper, 
		 const u_char *user_bytes, u_int8_t wait_for_packet);
```

Process ingress packets until pfring_breakloop() is called, or an error occurs.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `looper` | The user callback for packet processing.  |
| `user_bytes` | The user ptr passed to the callback. |
| `wait_for_packet` | If 0 active wait is used to check the packet availability. |

**Returns:** 0 on success (pfring_breakloop()), a negative value otherwise.

## pfring_breakloop

```c
void pfring_breakloop(pfring *ring);
```

Break a receive loop (pfring_loop() or blocking pfring_recv()).

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

## pfring_close

```c
void pfring_close(pfring *ring);
```

This call is used to terminate an PF_RING device previously open. 
Note that you must always close a device before leaving an application. If unsure, you can close a device from a signal handler.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle that we are attempting to close. |

## pfring_stats

```c
int pfring_stats(pfring *ring, pfring_stat *stats);
```

Read ring statistics (packets received and dropped).

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `stats` | A user-allocated buffer on which stats (number of received and dropped packets) will be stored. |

**Returns:** 0 on uccess, a negative value otherwise.

## pfring_recv

```c
int pfring_recv(pfring *ring, u_char** buffer, u_int buffer_len,
		struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
```

This call returns an incoming packet when available.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle where we perform the check. |
| `buffer` | A memory area allocated by the caller where the incoming packet will be stored.  Note that this parameter is a pointer to a pointer, in order to enable zero-copy implementations (buffer_len must be set to 0). |
| `buffer_len` | The length of the memory area above.  Note that the incoming packet is cut if it is too long for the allocated area. A length of 0 indicates to use the zero-copy optimization, when available. |
| `hdr` | A memory area where the packet header will be copied. |
| `wait_for_incoming_packet` | If 0 we simply check the packet availability, otherwise the call is blocked until a packet is available.  This option is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_ACTIVE_POLL environment variable. |

**Returns:** 0 in case of no packet being received (non-blocking), 1 in case of success, -1 in case of error.

## pfring_recv_burst

```c
int pfring_recv_burst(pfring *ring, pfring_packet_info *packets, u_int8_t num_packets, u_int8_t wait_for_packets);
```

Similart to pfring_recv, this call returns a set of incoming packets, when available, 
up to the specified number. (experimental - not supported by all modules)

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle where we perform the check. |
| `packets` | An array of packet descriptors that will be filled up received packets. A length of 0 indicates to use the zero-copy optimization, when available. |
| `num_packets` | The number of packet descriptors. |
| `wait_for_packets` | If 0 we simply check the packet availability, otherwise the call  is blocked until at lease one packet is available. packets in case of success, -1 in case of error. |

**Returns:** 0 in case of no packet being received (non-blocking), the number of

## pfring_recv_parsed

```c
int pfring_recv_parsed(pfring *ring, u_char** buffer, u_int buffer_len,
		       struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet,
		       u_int8_t level /* 1..4 */, u_int8_t add_timestamp, u_int8_t add_hash);
```

Same of pfring_recv(), with additional parameters to force packet parsing.

| Parameter | Description |
|---|---|
| `ring` |  |
| `buffer` |  |
| `buffer_len` |  |
| `hdr` |  |
| `wait_for_incoming_packet` |  |
| `level` | The header level where to stop parsing. |
| `add_timestamp` | Add the timestamp. |
| `add_hash` | Compute an IP-based bidirectional hash.  |

**Returns:** 0 in case of no packet being received (non-blocking), 1 in case of success, -1 in case of error.

## pfring_recv_flow

```c
int pfring_recv_flow(pfring *ring, pfring_flow_update *flow, u_int8_t wait_for_flows);
```

This call returns an flow when PF_RING_FLOW_OFFLOAD is enabled (supported adapters only).

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle where we perform the check. |
| `flowr` | A struct to be filled with flow metadata. |
| `hdr` | A memory area where the packet header will be copied. |
| `wait_for_flows` | If 0 we simply check the flow availability, otherwise the call is blocked until a packet is available.  |

**Returns:** 0 in case of no flow being received (non-blocking), 1 in case of success, -1 in case of error.

## pfring_get_metadata

```c
int pfring_get_metadata(pfring *ring, u_char **metadata, u_int32_t *metadata_len);
```

Get metadata for the last captured packet, if any. This is usually used with ZC SPSC queues for reading packet metadata.

| Parameter | Description |
|---|---|
| `ring` |  |
| `metadata` | Ptr to a variable that will contain the packet metadata (out). |
| `metadata_len` | Length of returned metadata (out). |

**Returns:** 0 if this is supported by the actual module and metadata is found, a negative error value otherwise.

## pfring_set_poll_watermark

```c
int pfring_set_poll_watermark(pfring *ring, u_int16_t watermark);
```

Whenever a user-space application has to wait until incoming packets arrive, it can instruct PF_RING not to return from poll() call 
unless at least “watermark” packets have been returned. A low watermark value such as 1, reduces the latency of poll() but likely 
increases the number of poll() calls. A high watermark (it cannot exceed 50% of the ring size, otherwise the PF_RING kernel module 
will top its value) instead reduces the number of poll() calls but slightly increases the packet latency. 
The default value for the watermark (i.e. if user-space applications do not manipulate this value via this call) is 128.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to enable. |
| `watermark` | The packet poll watermark. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_poll_watermark_timeout

```c
int pfring_set_poll_watermark_timeout(pfring *ring, u_int16_t poll_watermark_timeout);
```

Flush ring's queue if timeout passed.
This helps to avoid situation where packets are waiting in the rings's queue too long (e.g. low-traffic network).
The default value for the timeout is 0, which disables the flushing.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `poll_watermark_timeout` | Milliseconds to flush ring's queue even if watermark packets hasn't reached yet. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_poll_duration

```c
int pfring_set_poll_duration(pfring *ring, u_int duration);
```

Set the poll timeout when passive wait is used. Default timeout is 500 msec.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to enable. |
| `duration` | The poll timeout in msec. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_tx_watermark

```c
int pfring_set_tx_watermark(pfring *ring, u_int16_t watermark);
```

Set the number of packets that have to be enqueued in the egress queue before being sent on the wire.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to enable. |
| `watermark` | The tx watermark. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_default_hw_action

```c
int pfring_set_default_hw_action(pfring *ring, generic_default_action_type action);
```

Set a default action for filtering into the NIC.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the default rule will be set.  |
| `action.` | The action (default_pass or default_drop). |

**Returns:** 0 on success, a negative value otherwise.

## pfring_add_hw_rule

```c
int pfring_add_hw_rule(pfring *ring, hw_filtering_rule *rule);
```

Set a specified filtering rule into the NIC. Note that no PF_RING filter is added, but only a NIC filter.

Some multi-queue modern network adapters feature "packet steering" capabilities. Using them it is possible to 
instruct the hardware NIC to assign selected packets to a specific RX queue. If the specified queue has an Id 
that exceeds the maximum queueId, such packet is discarded thus acting as a hardware firewall filter.
Note: kernel packet filtering is not supported by ZC.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the rule will be added.  |
| `rule` | The filtering rule to be set in the NIC as defined in the last chapter of this document.  All rule parameters should be defined, and if set to zero they do not participate to filtering. which this ring is bound does not support hardware filters). |

**Returns:** 0 on success, a negative value otherwise (e.g. the rule to be added has wrong format or if the NIC to

## pfring_remove_hw_rule

```c
int pfring_remove_hw_rule(pfring *ring, u_int16_t rule_id);
```

Remove the specified filtering rule from the NIC.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the rule will be removed.  |
| `rule_id` | The filtering rule id to be removed from the NIC. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_channel_id

```c
int pfring_set_channel_id(pfring *ring, u_int32_t channel_id);
```

Set the device channel id to be used.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `channel_id` | The channel id.  |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_channel_mask

```c
int pfring_set_channel_mask(pfring *ring, u_int64_t channel_mask);
```

Set the channel mask to be used for packet capture.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `channel_mask` | The channel mask. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_application_name

```c
int pfring_set_application_name(pfring *ring, char *name);
```

Tell PF_RING the name of the application (usually argv[0]) that uses this ring. This information is used to identify the application 
when accessing the files present in the PF_RING /proc filesystem. 
This is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_APPNAME environment variable.
Example:
$ cat /proc/net/pf_ring/16614-eth0.0 | grep Name
Appl. Name     : pfcount

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to enable.  |
| `name` | The name of the application using this ring. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_application_stats

```c
int pfring_set_application_stats(pfring *ring, char *stats);
```

Set custom application statistics.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `stats` | The application stats. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_get_appl_stats_file_name

```c
char* pfring_get_appl_stats_file_name(pfring *ring, char *path, u_int path_len);
```

Return the filename where the application statistics can be read.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `path` | A user-allocated buffer on which the stats filename will be stored. |
| `path_len` | The path len. |

**Returns:** The path if success, NULL otherwise.

## pfring_set_vlan_id

```c
int pfring_set_vlan_id(pfring *ring, u_int16_t vlan_id);
```

Set the VLAN Id of the packets that will be copied to this ring (RX only)

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `vlan_id` | The vlan id to filter or 0 to accept only untagged VLAN packets |

**Returns:** 0 on success, a negative value otherwise.

## pfring_bind

```c
int pfring_bind(pfring *ring, char *device_name);
```

Bind a socket to a device.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `device_name` | The device name. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_send

```c
int pfring_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
```

Send a raw packet (i.e. it is sent on wire as specified). This packet must be fully specified (the MAC address up) 
and it will be transmitted as-is without any further manipulation.

Depending on the driver being used, packet transmission happens differently:
- Vanilla and PF_RING aware drivers: PF_RING does not accelerate the TX so the standard Linux transmission facilities are used. 
  Do not expect speed advantage when using PF_RING in this mode.
- ZC: line rate transmission is supported.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the packet has to be sent. |
| `pkt` | The buffer containing the packet to send. |
| `pkt_len` | The length of the pkt buffer. |
| `flush_packet` | 1 = Flush possible transmission queues. If set to 0, you will decrease your CPU usage but at the cost of  sending packets in trains and thus at larger latency. |

**Returns:** The number of bytes sent if success, a negative value otherwise.

## pfring_send_get_time

```c
int pfring_send_get_time(pfring *ring, char *pkt, u_int pkt_len, struct timespec *ts);
```

Same as pfring_send(), but this function allows to send a raw packet returning the exact time (ns) it has been sent on the wire. 
Note that this is available when the adapter supports tx hardware timestamping only and might affect performance.

| Parameter | Description |
|---|---|
| `ring` |  |
| `pkt` |  |
| `pkt_len` |  |
| `ts` | The struct where the tx timestamp will be stored. |

**Returns:** The number of bytes sent if success, a negative value otherwise.

## pfring_get_num_rx_channels

```c
u_int8_t pfring_get_num_rx_channels(pfring *ring);
```

Returns the number of RX channels (also known as RX queues) of the ethernet interface to which this ring is bound.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to query. |

**Returns:** The number of RX channels, or 1 (default) in case this in information is unknown.

## pfring_set_sampling_rate

```c
int pfring_set_sampling_rate(pfring *ring, u_int32_t rate /* 1 = no sampling */);
```

Implement packet sampling directly into the kernel. Note that this solution is much more efficient than implementing it in user-space. 
Sampled packets are only those that pass all filters (if any).

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which sampling is applied.  |
| `rate` | The sampling rate. Rate of X means that 1 packet out of X is forwarded. This means that a sampling rate of 1 disables sampling. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_filtering_sampling_rate

```c
int pfring_set_filtering_sampling_rate(pfring *ring, u_int32_t rate /* 0 = no sampling */);
```

Implement packet sampling during filtering directly into the kernel. Note that this solution is much more efficient than implementing it in user-space. 
Sampled packets during filtering are only those that already have been filtered out (if any).

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which filtering sampling is applied.  |
| `rate` | The filtering sampling rate. Rate of X means 1 packet every X packets is forwarded. Rate of 0 disables sampling. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_packet_slicing

```c
int pfring_set_packet_slicing(pfring *ring, packet_slicing_level level, u_int32_t additional_bytes);
```

Set packet slicing level.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which slicing is applied, when supported.  |
| `level` | The slicing level (disabled, L2, L3, L4, ..) |
| `additional_bytes` | Bytes to capture in addition to the selected layer. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_get_selectable_fd

```c
int pfring_get_selectable_fd(pfring *ring);
```

Returns the file descriptor associated to the specified ring. 
This number can be used in function calls such as poll() and select() for passively waiting for incoming packets.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to query.  |

**Returns:** A number that can be used as reference to this ring, in function calls that require a selectable file descriptor.

## pfring_set_direction

```c
int pfring_set_direction(pfring *ring, packet_direction direction);
```

Tell PF_RING to consider only those packets matching the specified direction. If the application does not call this function, 
all the packets (regardless of the direction, either RX or TX) are returned.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to enable. |
| `direction` | The packet direction (RX, TX or both RX and TX). |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_socket_mode

```c
int pfring_set_socket_mode(pfring *ring, socket_mode mode);
```

Tell PF_RING if the application needs to send and/or receive packets to/from the socket.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to enable.  |
| `mode` | The socket mode (send, receive or both send and receive). |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_cluster_consumer

```c
int pfring_set_cluster_consumer(pfring *ring, u_int16_t cluster_id, u_int16_t queue_id, cluster_type the_type, u_int32_t options);
```

This call allows a ring to be added to a cluster that can spawn across address spaces. 
On a nuthsell when two or more sockets are clustered they share incoming packets that are balanced on a per-flow manner. 
This technique is useful for exploiting multicore systems of for sharing packets in the same address space across multiple threads.
Clustering is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_CLUSTER_ID environment variable (Round-Robin by default, 
per-flow via the PCAP_PF_RING_USE_CLUSTER_PER_FLOW environment variable).

| Parameter | Description |
|---|---|
| `ring` | The  PF_RING handle to be cluster.  |
| `cluster_id` | A numeric identifier of the cluster to which the ring will be bound. |
| `queue_id` | Index of the consumer queue (0 .. MAX_CLUSTER_QUEUES-1). Use MAX_CLUSTER_QUEUES or bigger to get the first available queue. |
| `the_type` | The cluster type (2-tuple, 4-tuple, 5-tuple, tcp only 5-tuple, 6-tuple flow or Round-Robin). |
| `options` | Cluster options (flags). CLUSTER_OPTION_RELAXED_DISTRIBUTION to deliver packet to the first available queue if a consumer is down. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_cluster

```c
int pfring_set_cluster(pfring *ring, u_int clusterId, cluster_type the_type);
```

Deprecated: use pfring_set_cluster_consumer.

## pfring_remove_from_cluster

```c
int pfring_remove_from_cluster(pfring *ring);
```

This call allows a ring to be removed from a previous joined cluster.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to be cluster. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_master_id

```c
int pfring_set_master_id(pfring *ring, u_int32_t master_id);
```

Set the master ring using the id (vanilla PF_RING only)

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `master_id` | The master socket id. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_master

```c
int pfring_set_master(pfring *ring, pfring *master);
```

Set the master ring using the PF_RING handle (vanilla PF_RING only).

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `master` | The master PF_RING handle. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_get_ring_id

```c
u_int32_t pfring_get_ring_id(pfring *ring);
```

Return the ring id.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

**Returns:** The ring id.

## pfring_get_num_queued_pkts

```c
u_int32_t pfring_get_num_queued_pkts(pfring *ring);
```

Return an estimation of the enqueued packets.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_handle_hash_filtering_rule

```c
int pfring_handle_hash_filtering_rule(pfring *ring,
				      hash_filtering_rule* rule_to_add,
				      u_char add_rule);
```

Add or remove a hash filtering rule. 
All rule parameters should be defined in the filtering rule (no wildcards).

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle from which stats will be read. |
| `rule_to_add` | The rule that will be added/removed as defined in the last chapter of this document.  All rule parameters should be defined in the filtering rule (no wildcards). |
| `add_rule` | If set to a positive value the rule is added, if zero the rule is removed. |

**Returns:** 0 on success, a negative value otherwise (e.g. the rule to be removed does not exist).

## pfring_add_filtering_rule

```c
int pfring_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add);
```

Add a wildcard filtering rule to an existing ring. Each rule will have a unique rule Id across the ring (i.e. two rings can have rules with the same id).

PF_RING allows filtering packets in two ways: precise (a.k.a. hash filtering) or wildcard filtering. 
Precise filtering is used when it is necessary to track a precise 6-tuple connection <vlan Id, protocol, source IP, source port, destination IP, destination port>. 
Wildcard filtering is used instead whenever a filter can have wildcards on some of its fields (e.g. match all UDP packets regardless of their destination). 
If some field is set to zero it will not participate in filter calculation.

Note about packet reflection: packet reflection is the ability to bridge packets in kernel without sending them to userspace and back. 
You can specify packet reflection inside the filtering rules.

typedef struct {
 ...
char reflector_device_name[REFLECTOR_NAME_LEN];
...
} filtering_rule;

In the reflector_device_name you need to specify a device name (e.g. eth0) on which packets matching the filter will be reflected. 
Make sure NOT to specify as reflection device the same device name on which you capture packets, as otherwise you will create a packet loop.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the rule will be added. |
| `rule_to_add` | The rule to add as defined in the last chapter of this document. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_remove_filtering_rule

```c
int pfring_remove_filtering_rule(pfring *ring, u_int16_t rule_id);
```

Remove a previously added filtering rule.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the rule will be removed. |
| `rule_id` | The id of a previously added rule that will be removed. |

**Returns:** 0 on success, a negative value otherwise (e.g. the rule does not exist).

## pfring_purge_idle_hash_rules

```c
int pfring_purge_idle_hash_rules(pfring *ring, u_int16_t inactivity_sec);
```

Remove hash filtering rules inactive for the specified number of seconds.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the rules will be removed. |
| `inactivity_sec` | The inactivity threshold. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_purge_idle_rules

```c
int pfring_purge_idle_rules(pfring *ring, u_int16_t inactivity_sec);
```

Remove filtering rules inactive for the specified number of seconds.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the rules will be removed. |
| `inactivity_sec` | The inactivity threshold. |

**Returns:** 0 on success, a negative value otherwise

## pfring_get_hash_filtering_rule_stats

```c
int pfring_get_hash_filtering_rule_stats(pfring *ring,
					 hash_filtering_rule* rule,
					 char *stats, u_int *stats_len);
```

Read statistics of a hash filtering rule.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the rule will be added/removed. |
| `rule` | The rule for which stats are read. This needs to be the same rule that has been previously added. |
| `stats` | A buffer allocated by the user that will contain the rule statistics.  Please make sure that the buffer is large enough to contain the statistics (hash_filtering_rule_stats struct). |
| `stats_len` | The size (in bytes) of the stats buffer. |

**Returns:** 0 on success, a negative value otherwise (e.g. the rule to be removed does not exist).

## pfring_get_filtering_rule_stats

```c
int pfring_get_filtering_rule_stats(pfring *ring, u_int16_t rule_id,
				    char* stats, u_int *stats_len);
```

Read statistics of a hash filtering rule.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle from which stats will be read. |
| `rule_id` | The rule id that identifies the rule for which stats are read. |
| `stats` | A buffer allocated by the user that will contain the rule statistics.  Please make sure that the buffer is large enough to contain the statistics. Such buffer will contain number of received and dropped packets. |
| `stats_len` | The size (in bytes) of the stats buffer. |

**Returns:** 0 on success, a negative value otherwise (e.g. the rule does not exist).

## pfring_toggle_filtering_policy

```c
int pfring_toggle_filtering_policy(pfring *ring, u_int8_t rules_default_accept_policy);
```

Set the default filtering policy. This means that if no rule is matching the incoming packet the default policy will decide 
if the packet is forwarded to user space or dropped. Note that filtering rules are limited to a ring, so each ring can have 
a different set of rules and default policy.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the rule will be added/removed.  |
| `rules_default_accept_policy` | If set to a positive value the default policy is accept (i.e. forward packets to user space), drop otherwise. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_enable_rss_rehash

```c
int pfring_enable_rss_rehash(pfring *ring);
```

Tells PF_RING to rehash incoming packets using a bi-directional hash function.
This is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_RSS_REHASH environment variable.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to query. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_poll

```c
int pfring_poll(pfring *ring, u_int wait_duration);
```

Performs passive wait on a PF_RING socket, similar to the standard poll(), taking care of data structures synchronization.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING socket to poll.  |
| `wait_duration` | The poll timeout in msec. |

**Returns:** 0 (no packet) or 1 (packet available) on success, a negative value otherwise.

## pfring_is_pkt_available

```c
int pfring_is_pkt_available(pfring *ring);
```

Check if a packet is available.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

**Returns:** 1 if a packet is available, 0 if there is no packet available, a negative number in case of error.

## pfring_next_pkt_time

```c
int pfring_next_pkt_time(pfring *ring, struct timespec *ts);
```

This call returns the arrival time of the next incoming packet, when available.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle where we perform the check. |
| `ts` | The struct where the time will be stored. |

**Returns:** 0 in case of success, a negative number in case of error.

## pfring_next_pkt_raw_timestamp

```c
int pfring_next_pkt_raw_timestamp(pfring *ring, u_int64_t *timestamp_ns);
```

This call returns the raw timestamp of the next incoming packet, when available. This is available with adapters supporting rx hardware timestamping only.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle where we perform the check.  |
| `timestamp_ns` | Where the timestamp will be stored. |

**Returns:** 0 in case of success, a negative number in case of error.

## pfring_version_noring

```c
void pfring_version_noring(u_int32_t *version);
```

Read the ring version. Note that if the ring version is 5.6 the retuned ring version is 0x050600.

| Parameter | Description |
|---|---|
| `version` | A user-allocated buffer on which ring version will be copied. |

## pfring_version

```c
int pfring_version(pfring *ring, u_int32_t *version);
```

Read the ring version. Note that if the ring version is 5.6 the retuned ring version is 0x050600.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle, in case the module supports versioning. |
| `version` | A user-allocated buffer on which ring version will be copied. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_reflector_device

```c
int pfring_set_reflector_device(pfring *ring, char *device_name);
```

Set a reflector device to send all incoming packets. This open a new socket and packets are automatically sent using pfring_send().

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `device_name` | The device name.  |

**Returns:** 0 on success, a negative value otherwise.

## pfring_get_bound_device_address

```c
int pfring_get_bound_device_address(pfring *ring, u_char mac_address[6]);
```

Returns the MAC address of the device bound to the socket.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to query. |
| `mac_address` | The memory area where the MAC address will be copied. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_get_slot_header_len

```c
u_int16_t pfring_get_slot_header_len(pfring *ring);
```

Return the size of the PF_RING packet header (vanilla PF_RING only).

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

**Returns:** The size of the packet header.

## pfring_get_bound_device_ifindex

```c
int pfring_get_bound_device_ifindex(pfring *ring, int *if_index);
```

Returns the interface index of the device bound to the socket.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to query.  |
| `if_index` | The memory area where the interface index will be copied |

**Returns:** 0 on success, a negative value otherwise.

## pfring_get_device_ifindex

```c
int pfring_get_device_ifindex(pfring *ring, char *device_name, int *if_index);
```

Return the interface index of the provided device.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `device_name` | The device name. |
| `if_index` | The memory area for storing the interface index. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_virtual_device

```c
int pfring_set_virtual_device(pfring *ring, virtual_filtering_device_info *info);
```

Set a filtering device.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `info` | The filtering device info. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_loopback_test

```c
int pfring_loopback_test(pfring *ring, char *buffer, u_int buffer_len, u_int test_len);
```

This call processes packets until pfring_breakloop() is called or an error occurs.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `buffer` |  |
| `buffer_len` |  |
| `test_len` |  |

**Returns:** A non-negative number on success. A negative number in case of error.

## pfring_enable_ring

```c
int pfring_enable_ring(pfring *ring);
```

When a ring is created, it is not enabled (i.e. incoming packets are dropped) until the above function is called.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to enable. |

**Returns:** 0 on success, a negative value otherwise (e.g. the ring cannot be enabled).

## pfring_disable_ring

```c
int pfring_disable_ring(pfring *ring);
```

Disable a ring.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle to disable. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_bpf_filter

```c
int pfring_set_bpf_filter(pfring *ring, const char *filter_buffer);
```

In order to set BPF filters through the PF_RING API it’s necessary to enable (this is the default) BPF support 
at compile time and link PF_RING-enabled applications against the -lpcap library (it is possible to disable the 
BPF support with "cd userland/lib/; ./configure --disable-bpf; make" to avoid linking libpcap).

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the filter will be set. |
| `filter_buffer` | The filter to set. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_remove_bpf_filter

```c
int pfring_remove_bpf_filter(pfring *ring);
```

Remove the BPF filter.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_filtering_mode

```c
int pfring_set_filtering_mode(pfring *ring, filtering_mode mode);
```

Sets the filtering mode (software only, hardware only, both software and hardware) in order to implicitly 
add/remove hardware rules by means of the same API functionality used for software (wildcard and hash) rules.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the rule will be removed.  |
| `mode` | The filtering mode. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_get_device_clock

```c
int pfring_get_device_clock(pfring *ring, struct timespec *ts);
```

Reads the time from the device hardware clock, when the adapter supports hardware timestamping.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle.  |
| `ts` | The struct where time will be stored. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_device_clock

```c
int pfring_set_device_clock(pfring *ring, struct timespec *ts);
```

Sets the time in the device hardware clock, when the adapter supports hardware timestamping.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `ts` | The time to be set. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_adjust_device_clock

```c
int pfring_adjust_device_clock(pfring *ring, struct timespec *offset, int8_t sign);
```

Adjust the time in the device hardware clock with an offset, when the adapter supports hardware timestamping.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `offset` | The time offset. |
| `sign` | The offset sign. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_sync_indexes_with_kernel

```c
void pfring_sync_indexes_with_kernel(pfring *ring);
```

Synchronizes the ingress ring indexes/registers with the kernel.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

## pfring_send_last_rx_packet

```c
int pfring_send_last_rx_packet(pfring *ring, int tx_interface_id);
```

Send the last received packet to the specified device. This is an optimization working with standard PF_RING only.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle on which the packet has been received.  |
| `tx_interface_id` | The egress interface index. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_get_link_status

```c
int pfring_get_link_status(pfring *ring);
```

Return the link status.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

**Returns:** 1 if link is up, 0 otherwise.

## pfring_get_link_type

```c
int pfring_get_link_type(pfring *ring);
```

Return the Network link type.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

**Returns:** The link type (e.g. DLT_EN10MB)

## pfring_get_caplen

```c
int pfring_get_caplen(pfring *ring);
```

Return the max capture length.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

**Returns:** The capture length.

## pfring_flush_tx_packets

```c
int pfring_flush_tx_packets(pfring *ring);
```

Synchronizes the egress ring indexes/registers flushing enqueued packets.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_search_payload

```c
int pfring_search_payload(pfring *ring, char *string_to_search);
```

Add a string to search in the packet payload (used for filtering).

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `string_to_search` | The string to search. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_parse_pkt

```c
int pfring_parse_pkt(u_char *pkt, struct pfring_pkthdr *hdr, u_int8_t level /* 2..4 */, 
		     u_int8_t add_timestamp /* 0,1 */, u_int8_t add_hash /* 0,1 */);
```

Parse a packet. 
It expects that the hdr memory is either zeroed or contains valid values for the current packet, in order to avoid  parsing twice the same packet headers. 
This is implemented by controlling the l3_offset and l4_offset fields, indicating that respectively the L2 and L3 layers have been parsed when other than zero.

| Parameter | Description |
|---|---|
| `pkt` | The packet buffer. |
| `hdr` | The header to be filled. |
| `level` | The header level where to stop parsing. |
| `add_timestamp` | Add the timestamp. |
| `add_hash` | Compute an IP-based bidirectional hash. |

**Returns:** A non-negative number indicating the topmost header level on success,  a negative value otherwise.

## pfring_set_if_promisc

```c
int pfring_set_if_promisc(const char *device, int set_promisc);
```

Set the promiscuous mode flag to a device.

| Parameter | Description |
|---|---|
| `device` | The device name. |
| `set_promisc` | The promisc flag.  |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_promisc

```c
int pfring_set_promisc(pfring *ring, int set_promisc);
```

Set the promiscuous mode to bound device.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `set_promisc` | The promisc flag.  |

**Returns:** 0 on success, a negative value otherwise.

## pfring_format_numbers

```c
char* pfring_format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals);
```

Format a number.

| Parameter | Description |
|---|---|
| `val` | The value. |
| `buf` | The destination buffer. |
| `buf_len` | The destination buffer length. |
| `add_decimals` | A flag indicating whether to add decimals. |

**Returns:** The produced string.

## pfring_enable_hw_timestamp

```c
int pfring_enable_hw_timestamp(pfring *ring, char *device_name, u_int8_t enable_rx, u_int8_t enable_tx);
```

Enables rx and tx hardware timestamping, when the adapter supports it.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `device_name` | The name of the device where timestamping will be enabled. |
| `enable_rx` | Flag to enable rx timestamping. |
| `enable_tx` | Flag to enable tx timestamping. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_get_mtu_size

```c
int pfring_get_mtu_size(pfring *ring);
```

Return the size of the MTU.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |

**Returns:** The MTU size on success, a negative value otherwise.

## pfring_get_card_settings

```c
int pfring_get_card_settings(pfring *ring, pfring_card_settings *settings);
```

Return NIC settings: max packet length, num rx/tx slots (ZC only).

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `settings` | The card settings (output). |

**Returns:** 0 on success, a negative value otherwise.

## pfring_print_parsed_pkt

```c
int pfring_print_parsed_pkt(char *buff, u_int buff_len, const u_char *p, const struct pfring_pkthdr *h);
```

Print a packet (the header with parsing info must be provided).

| Parameter | Description |
|---|---|
| `buff` | The destination buffer. |
| `buff_len` | The destination buffer length. |
| `p` | The packet. |
| `h` | The header. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_print_pkt

```c
int pfring_print_pkt(char *buff, u_int buff_len, const u_char *p, u_int len, u_int caplen);
```

Print a packet.

| Parameter | Description |
|---|---|
| `buff` | The destination buffer. |
| `buff_len` | The destination buffer length. |
| `p` | The packet. |
| `len` | The packet length. |
| `caplen` | The captured packet length. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_recv_chunk

```c
int pfring_recv_chunk(pfring *ring, void **chunk, pfring_chunk_info *chunk_info, u_int8_t wait_for_incoming_chunk);
```

Receive a packet chunk, if enabled via pfring_open() flag.

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `chunk` | A buffer that will point to the received chunk. Note that the chunk format is adapter specific. |
| `chunk_info` | Informations about the chunk content and length. |
| `wait_for_incoming_chunk` | If 0 active wait is used to check the packet availability. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_set_bound_dev_name

```c
int pfring_set_bound_dev_name(pfring *ring, char *custom_dev_name);
```

Set a custom device name to which the socket is bound. This function should be called for devices that are not visible via ifconfig

| Parameter | Description |
|---|---|
| `ring` | The PF_RING handle. |
| `custom_dev_name` | The custom device name to be used for this socket. |

**Returns:** 0 on success, a negative value otherwise.

## pfring_enable_hw_timestamp_debug

```c
void pfring_enable_hw_timestamp_debug();
```

Enable debug mode for hw timestamps.

## pfring_read_ixia_hw_timestamp

```c
int pfring_read_ixia_hw_timestamp(u_char *buffer, u_int32_t buffer_len, struct timespec *ts);
```

Reads a IXIA-formatted timestamp from an incoming packet and puts it into the timestamp variable.

| Parameter | Description |
|---|---|
| `buffer` | Incoming packet buffer. |
| `buffer_len` | Incoming packet buffer length. |
| `ts` | If found the hardware timestamp will be placed here |

**Returns:** The length of the IXIA timestamp (hence 0 means that the timestamp has not been found).

## pfring_handle_ixia_hw_timestamp

```c
int pfring_handle_ixia_hw_timestamp(u_char* buffer, struct pfring_pkthdr *hdr);
```

Strip a IXIA-formatted timestamp from an incoming packet. If the timestamp is found, the
hdr parameter (caplen and len fields) are decreased by the size of the timestamp.

| Parameter | Description |
|---|---|
| `buffer` | Incoming packet buffer. |
| `hdr` | This is an in/out parameter: it is used to read the original packet len, and it is updated (size decreased) if the hw timestamp is found |

**Returns:** 0 on success, a negative value otherwise.

## pfring_read_metawatch_hw_timestamp

```c
int pfring_read_metawatch_hw_timestamp(u_char *buffer, u_int32_t buffer_len, struct timespec *ts);
```

Read a MetaWatch trailer extracting the timestamp (ns and sub_ns)

| Parameter | Description |
|---|---|
| `buffer` | Incoming packet buffer. |
| `buffer_len` | Incoming packet buffer length. |
| `ts` | If found the hardware timestamp will be placed here |

**Returns:** The length of the Metwatch trailer

## pfring_read_metawatch_device_info

```c
int pfring_read_metawatch_device_info(u_char *buffer, u_int32_t buffer_len, u_int16_t *device_id, u_int8_t *port_id);
```

Read a MetaWatch trailer extracting device_id and port_id

| Parameter | Description |
|---|---|
| `buffer` | Incoming packet buffer. |
| `buffer_len` | Incoming packet buffer length. |
| `device_id` | The device ID will be placed here |
| `port_id` | The port ID will be placed here |

**Returns:** The length of the Metwatch trailer

## pfring_handle_metawatch_hw_timestamp

```c
int pfring_handle_metawatch_hw_timestamp(u_char* buffer, struct pfring_pkthdr *hdr);
```

MetaWatch trailer containing, timestamp (ns), device_id, port_id, sub_ns, flags

| Parameter | Description |
|---|---|
| `buffer` | Incoming packet buffer. |
| `hdr` | This is an in/out parameter: it is used to read the original packet len, and it is updated (size decreased) if the hw timestamp is found |

**Returns:** 0 on success, a negative value otherwise.

## pfring_read_arista_7150_keyframe

```c
int pfring_read_arista_7150_keyframe(u_char *buffer, u_int32_t buffer_len, u_int64_t *ns_ts, u_int32_t *ticks_ts);
```

Reads the UTC time and ticks from a ARISTA key frame.

| Parameter | Description |
|---|---|
| `buffer` | Incoming packet buffer. |
| `buffer_len` | Incoming packet buffer length. |
| `ns_ts` | The nsec UTC time will be placed here. |
| `ticks_ts` | The ticks will be placed here. |

**Returns:** 0 on success, a negative number otherwise.

## pfring_read_arista_7150_hw_timestamp

```c
int pfring_read_arista_7150_hw_timestamp(u_char *buffer, u_int32_t buffer_len, u_int64_t *ns_ts);
```

Reads a ARISTA-formatted timestamp from an incoming packet and puts it into the timestamp variable.

| Parameter | Description |
|---|---|
| `buffer` | Incoming packet buffer. |
| `buffer_len` | Incoming packet buffer length. |
| `ns_ts` | If found the hardware timestamp will be placed here |

**Returns:** The length of the ARISTA timestamp.

## pfring_handle_arista_hw_timestamp

```c
int pfring_handle_arista_hw_timestamp(u_char* buffer, struct pfring_pkthdr *hdr);
```

Strip a ARISTA-formatted timestamp from an incoming packet. If the timestamp is found, the
hdr parameter (caplen and len fields) are decreased by the size of the timestamp.

| Parameter | Description |
|---|---|
| `buffer` | Incoming packet buffer. |
| `hdr` | This is an in/out parameter: it is used to read the original packet len, and it is updated (size decreased) if the hw timestamp is found |

**Returns:** 0 on success, a negative value otherwise.

## pfring_get_interface_speed

```c
u_int32_t pfring_get_interface_speed(pfring *ring);
```

Get interface speed.

| Parameter | Description |
|---|---|
| `ring` |  |

**Returns:** 0 if interface speed is unknown, the interface speed (Mbit/s) otherwise.

## pfring_get_ethtool_link_speed

```c
u_int32_t pfring_get_ethtool_link_speed(const char *ifname);
```

Get interface speed by linux interface name.

| Parameter | Description |
|---|---|
| `ifname` | The interface name. |

**Returns:** 0 if interface speed is unknown, the interface speed (Mbit/s) otherwise.

## pfring_findalldevs

```c
pfring_if_t *pfring_findalldevs(void);
```

List all interfaces.

**Returns:** The interface list.

## pfring_freealldevs

```c
void pfring_freealldevs(pfring_if_t *list);
```

Free an interface list returned by pfring_findalldevs().

| Parameter | Description |
|---|---|
| `list` | The interface list. |

## pfring_is_module_prefix

```c
int pfring_is_module_prefix(const char *prefix);
```

Check if the prefix is a valid pf_ring module prefix
