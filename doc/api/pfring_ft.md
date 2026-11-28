---
title: "PF_RING FT API"
description: "PF_RING FT library header file."
outline: [2, 3]
---
# PF_RING FT API


PF_RING FT library header file.

## PFRING_FT_ACTION_DEFAULT

```c
#define PFRING_FT_ACTION_DEFAULT 0
```

enums

## pfring_ft_in4_addr

```c
typedef u_int32_t pfring_ft_in4_addr;
```

packet header structs

## pfring_ft_pcap_pkthdr

```c
typedef struct {     /* pfring_pkthdr / pcap_pkthdr common struct */
  struct timeval ts; /**< time stamp */
  u_int32_t caplen;  /**< length of captured portion */
  u_int32_t len;     /**< length original packet (off wire) */
} pfring_ft_pcap_pkthdr;
```

packet metadata structs

## pfring_ft_ip_address

```c
typedef union {
  pfring_ft_in4_addr v4;
  pfring_ft_in6_addr v6;
} pfring_ft_ip_address;
```

flow metadata structs

## pfring_ft_stats

```c
typedef struct {
  u_int64_t active_flows;     /**< Number of currently active flows */
  u_int64_t flows;            /**< Number of total flows */
  u_int64_t err_no_room;      /**< Flow creation errors due to no room left in the flow table */
  u_int64_t err_no_mem;       /**< Flow creation errors due to memory allocation failures */
  u_int64_t disc_no_ip;       /**< Number of packets not processed because L3 header was missing */
  u_int64_t max_lookup_depth; /**< Maximum collition list depth during flow lookup */
  u_int64_t packets;          /**< Number of processed packets */
  u_int64_t bytes;            /**< Total number of packet bytes */
} pfring_ft_stats;
```

stats struct

## typedef void

```c
typedef void
(*pfring_ft_export_list_func) (
  pfring_ft_list *flows_list,
  void *user
);
```

Callbacks prototypes

## pfring_ft_table *

```c
pfring_ft_table *
pfring_ft_create_table(
  u_int32_t flags,
  u_int32_t max_flows,
  u_int32_t flow_idle_timeout,
  u_int32_t flow_lifetime_timeout,
  u_int32_t user_metadata_size
);
```

Create a new flow table.

| Parameter | Description |
|---|---|
| `flags` | Flags to enable selected flow table features. |
| `max_flows` | Maximum number of concurrent flows the table should be able to handle (use 0 if not sure to use default settings). |
| `flow_idle_timeout` | Maximum flow idle time (seconds) before expiration (use 0 if not sure to use default: 30s). |
| `flow_lifetime_timeout` | Maximum flow duration (seconds) before expiration (use 0 if not sure to use default: 2m). |
| `user_metadata_size` | Size of the user metadata in pfring_ft_flow_value->user |

**Returns:** The flow table on success, NULL on failure.

## void

```c
void
pfring_ft_destroy_table(
  pfring_ft_table *table
);
```

Destroy a flow table.

| Parameter | Description |
|---|---|
| `table` | The flow table handle. |

## pfring_ft_action

```c
pfring_ft_action
pfring_ft_process(
  pfring_ft_table *table,
  const u_char *packet,
  const pfring_ft_pcap_pkthdr *header,
  const pfring_ft_ext_pkthdr *ext_header
);
```

Provide a raw packet to the flow table for processing. Usually the main
capture loop provides all the packets to the hash table calling this function.

| Parameter | Description |
|---|---|
| `table` | The flow table handle.  |
| `packet` | The raw packet. |
| `header` | The packet metadata (including length and timestamp). |
| `ext_header` | Additional packet metadata not available in the pcap header (including hash). |

**Returns:** The action for the packet, in case filtering rules have been specified.

## int

```c
int
pfring_ft_housekeeping(
  pfring_ft_table *table,
  u_int32_t epoch
);
```

This should be called when there is no packet to be processed and the
main loop is idle, for running housekeeping activities in the flow table.

| Parameter | Description |
|---|---|
| `table` | The flow table handle.  |
| `epoch` | The current epoch (sec).  |

**Returns:** 1 if there is more work to do, 0 if the caller can sleep a bit.

## pfring_ft_flow *

```c
pfring_ft_flow *
pfring_ft_list_get_next(
  pfring_ft_list *list
);
```

Pop the next from a flow list.

| Parameter | Description |
|---|---|
| `list` | The flow list. |

**Returns:** The flow if the list is not empty, NULL otherwise.

## u_int64_t

```c
u_int64_t
pfring_ft_flow_get_id(
  pfring_ft_flow *flow
);
```

Get the flow ID.

| Parameter | Description |
|---|---|
| `flow` | The flow handle. |

**Returns:** The flow ID.

## pfring_ft_flow_key *

```c
pfring_ft_flow_key *
pfring_ft_flow_get_key(
  pfring_ft_flow *flow
);
```

Get the flow key.

| Parameter | Description |
|---|---|
| `flow` | The flow handle. |

**Returns:** The flow key.

## pfring_ft_flow_value *

```c
pfring_ft_flow_value *
pfring_ft_flow_get_value(
  pfring_ft_flow *flow
);
```

Get the flow value.

| Parameter | Description |
|---|---|
| `flow` | The flow handle. |

**Returns:** The flow value.

## ndpi_flow_struct

```c
struct ndpi_flow_struct *
pfring_ft_flow_get_ndpi_handle(
  pfring_ft_flow *flow
);
```

Get the nDPI flow handle.

| Parameter | Description |
|---|---|
| `flow` | The flow handle. |

**Returns:** The flow value.

## char *

```c
char *
pfring_ft_category_name(
  pfring_ft_table *table,
  int category,
  char *buffer,
  int buffer_len
);
```

Return the nDPI category name providing the nDPI category ID.

| Parameter | Description |
|---|---|
| `table` | The flow table handle. |
| `category` | The nDPI category ID. |
| `buffer` | The output buffer. |
| `buffer_len` | The output buffer length. |

**Returns:** The buffer.

## u_int16_t

```c
u_int16_t
pfring_ft_l7_protocol_id(
  pfring_ft_table *table,
  const char *name
);
```

Return the nDPI L7 protocol ID providing the L7 protocol name.

| Parameter | Description |
|---|---|
| `table` | The flow table handle.  |
| `name` | The L7 protocol name. |

**Returns:** The nDPI protocol ID.

## ndpi_detection_module_struct

```c
struct ndpi_detection_module_struct *
pfring_ft_get_ndpi_handle(
  pfring_ft_table *table
);
```

Return the nDPI handle.

| Parameter | Description |
|---|---|
| `table` | The flow table handle.  |

**Returns:** The nDPI handle, NULL if there is no handle.

## pfring_ft_stats *

```c
pfring_ft_stats *
pfring_ft_get_stats(
  pfring_ft_table *table
);
```

Get flow processing statistics.

| Parameter | Description |
|---|---|
| `table` | The flow table handle.  |

**Returns:** The stats struct.

## u_int32_t

```c
u_int32_t
pfring_ft_api_version(
);
```

Get the PF_RING FT API version.

**Returns:** The version number as unsigne inte.
