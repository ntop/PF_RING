/*
 *
 * (C) 2018 - ntop.org
 *
 *  http://www.ntop.org/
 *
 * This code is proprietary code subject to the terms and conditions
 * defined in LICENSE file which is part of this source code package.
 *
 */

#ifndef _PFRING_FT_H_
#define _PFRING_FT_H_

/**
 * @file pfring_ft.h
 *
 * @brief      PF_RING FT library header file.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void pfring_ft_table;
typedef void pfring_ft_list;
typedef void pfring_ft_flow;

struct ndpi_detection_module_struct;

/*** enums ***/

typedef enum {
  PFRING_FT_ACTION_DEFAULT = 0,
  PFRING_FT_ACTION_FORWARD,
  PFRING_FT_ACTION_DISCARD
} pfring_ft_action;

typedef enum { 
  s2d_direction = 0, /**< Source to destination */
  d2s_direction,     /**< Destination to source */
  NUM_DIRECTIONS
} pfring_ft_direction;

/*** packet header structs ***/

typedef u_int32_t pfring_ft_in4_addr;

typedef struct {
  union {
    u_int8_t   u6_addr8[16];
    u_int16_t  u6_addr16[8];
    u_int32_t  u6_addr32[4];
  } u6_addr;
} __attribute__((packed))
pfring_ft_in6_addr;

typedef struct {
  u_int8_t ihl:4, version:4;
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
} __attribute__((packed))
pfring_ft_iphdr;

typedef struct {
  u_int32_t ip6_un1_flow;
  u_int16_t ip6_un1_plen;
  u_int8_t ip6_un1_nxt;
  u_int8_t ip6_un1_hlim;
  pfring_ft_in6_addr ip6_src;
  pfring_ft_in6_addr ip6_dst;
} __attribute__((packed))
pfring_ft_ipv6hdr;

typedef struct {
  u_int16_t source;
  u_int16_t dest;
  u_int32_t seq;
  u_int32_t ack_seq;
  u_int16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
  u_int16_t window;
  u_int16_t check;
  u_int16_t urg_ptr;
} __attribute__((packed))
pfring_ft_tcphdr;

typedef struct {
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
} __attribute__((packed))
pfring_ft_udphdr;

/*** packet metadata structs ***/

typedef struct { /* pfring_pkthdr / pcap_pkthdr common struct */
  struct timeval ts; /**< time stamp */
  u_int32_t caplen;  /**< length of captured portion */
  u_int32_t len;     /**< length original packet (off wire) */
} pfring_ft_pcap_pkthdr;

typedef struct { /* additional packet metadata not available in pcap_pkthdr */
  u_int32_t hash;  /**< packet hash */
} pfring_ft_ext_pkthdr;

typedef struct {
  pfring_ft_pcap_pkthdr *hdr;
  pfring_ft_ext_pkthdr *ext_hdr;
  pfring_ft_direction direction;
  u_int16_t vlan_id;
  u_int8_t ip_version;
  u_int8_t l4_proto;
  u_int16_t payload_len;
  u_int16_t reserved; /* padding */
  union {
    pfring_ft_iphdr   *ip4;
    pfring_ft_ipv6hdr *ip6;
  } l3;
  union {
    pfring_ft_tcphdr *tcp;
    pfring_ft_udphdr *udp;
  } l4;
  const u_char *payload;
} pfring_ft_packet_metadata;

/*** flow metadata structs ***/

typedef union {
  pfring_ft_in4_addr v4;
  pfring_ft_in6_addr v6;
} pfring_ft_ip_address;

typedef struct {
  u_int16_t master_protocol;  /**< e.g. HTTP */
  u_int16_t app_protocol;     /**< e.g. FaceBook */
  int category;
} pfring_ft_ndpi_protocol;

typedef struct {
  pfring_ft_ip_address saddr; /**< Source IP address */
  pfring_ft_ip_address daddr; /**< Destination IP address */
  u_int8_t ip_version;        /**< IP version */
  u_int8_t protocol;          /**< L4 protocol */
  u_int16_t sport;            /**< Source port */
  u_int16_t dport;            /**< Destination port */
  u_int16_t vlan_id;          /**< VLAN ID */
} pfring_ft_flow_key;

typedef struct {
  struct {
    u_int64_t pkts;                    /**< Number of packets per direction */
    u_int64_t bytes;                   /**< Number of bytes per direction */
    struct timeval first;              /**< Time of first packet seen per direction */
    struct timeval last;               /**< Time of last packet seen per direction */
    u_int8_t tcp_flags;                /**< TCP flags per direction */
  } direction[NUM_DIRECTIONS];         /**< Metadata per flow direction */
  pfring_ft_ndpi_protocol l7_protocol; /**< nDPI protocol */
  void *user;                          /**< User metadata */
} pfring_ft_flow_value;

/*** stats struct ***/

typedef struct {
  u_int64_t flows;            /**< Number of flows */
  u_int64_t err_no_room;      /**< Flow creation errors due to no room left in the flow table */
  u_int64_t err_no_mem;       /**< Flow creation errors due to memory allocation failures */
  u_int64_t disc_no_ip;       /**< Number of packets not processed because L3 header was missing */
  u_int64_t max_lookup_depth; /**< Maximum collition list depth during flow lookup */
} pfring_ft_stats;

/*** Callbacks prototypes ***/

typedef void
(*pfring_ft_export_list_func) (
  pfring_ft_list *flows_list,
  void *user
);

typedef void
(*pfring_ft_export_flow_func) (
  pfring_ft_flow *flow,
  void *user
);

typedef void
(*pfring_ft_flow_packet_func) (
  const u_char *data,
  pfring_ft_packet_metadata *metadata,
  pfring_ft_flow *flow,
  void *user
);

#define PFRING_FT_TABLE_FLAGS_DPI (1 << 0) /**< pfring_ft_create_table() flag: enable nDPI support for L7 protocol detection */

/**
 * Create a new flow table.
 * @param flags Flags to enable selected flow table features.
 * @param max_flows Maximum number of concurrent flows the table should be able to handle (use 0 if not sure to use default settings).
 * @param flow_idle_timeout Maximum flow idle time (seconds) before expiration (use 0 if not sure to use default: 30s).
 * @param flow_lifetime_timeout Maximum flow duration (seconds) before expiration (use 0 if not sure to use default: 2m).
 * @return The flow table on success, NULL on failure.
 */
pfring_ft_table *
pfring_ft_create_table(
  u_int32_t flags,
  u_int32_t max_flows,
  u_int32_t flow_idle_timeout,
  u_int32_t flow_lifetime_timeout
);

/**
 * Destroy a flow table.
 * @param table The flow table handle.
 */
void
pfring_ft_destroy_table(
  pfring_ft_table *table
);

/**
 * Set the function to be called when a new flow has been created.
 * @param table The flow table handle.
 * @param callback The callback.
 * @param user The user data provided to the callback.
 */
void
pfring_ft_set_new_flow_callback(
  pfring_ft_table *table,
  pfring_ft_export_flow_func callback,
  void *user
);

/**
 * Set the function to be called when a packet and its flow have been processed, for each packet.
 * @param table The flow table handle.
 * @param callback The callback.
 * @param user The user data provided to the callback.
 */
void
pfring_ft_set_flow_packet_callback(
  pfring_ft_table *table,
  pfring_ft_flow_packet_func callback, 
  void *user
);

/**
 * Set the function to be called when a flow expires and needs to be exported.
 * The callback should release the flow calling pfring_ft_flow_free(flow).
 * @param table The flow table handle. 
 * @param callback The callback.
 * @param user The user data provided to the callback.
 */
void
pfring_ft_set_flow_export_callback(
  pfring_ft_table *table,
  pfring_ft_export_flow_func callback,
  void *user
);

/**
 * Set the function to be called when a some flow expires and need to be exported.
 * This can be used as an optimised alternative to pfring_ft_set_flow_export_callback().
 * The callback should release all flows in the list calling pfring_ft_flow_free(flow) for each flow.
 * It is possible to iterate all the flows in the list using pfring_ft_list_get_next().
 * @param table The flow table handle. 
 * @param callback The callback.
 * @param user The user data provided to the callback. 
 */
void
pfring_ft_set_flow_list_export_callback(
  pfring_ft_table *table,
  pfring_ft_export_list_func callback, 
  void *user
);

/**
 * Provide a raw packet to the flow table for processing. Usually the main
 * capture loop provides all the packets to the hash table calling this function.
 * @param table The flow table handle. 
 * @param packet The raw packet.
 * @param header The packet metadata (including length and timestamp).
 * @param ext_header Additional packet metadata not available in the pcap header (including hash).
 * @return The action for the packet, in case filtering rules have been specified.
 */
pfring_ft_action
pfring_ft_process(
  pfring_ft_table *table,
  const u_char *packet,
  const pfring_ft_pcap_pkthdr *header,
  const pfring_ft_ext_pkthdr *ext_header
);

/**
 * This should be called when there is no packet to be processed and the
 * main loop is idle, for running housekeeping activities in the flow table.
 * @param table The flow table handle. 
 * @param epoch The current epoch (sec). 
 * @return 1 if there is more work to do, 0 if the caller can sleep a bit.
 */
int
pfring_ft_housekeeping(
  pfring_ft_table *table,
  u_int32_t epoch
);

/**
 * Flush all flows (usually called on program termination, before destroying the flow table).
 * @param table The flow table handle. 
 */
void
pfring_ft_flush(
  pfring_ft_table *table
);

/**
 * Pop the next from a flow list.
 * @param list The flow list.
 * @return The flow if the list is not empty, NULL otherwise.
 */
pfring_ft_flow *
pfring_ft_list_get_next(
  pfring_ft_list *list
);

/**
 * Get the flow key.
 * @param flow The flow handle.
 * @return The flow key.
 */
pfring_ft_flow_key *
pfring_ft_flow_get_key(
  pfring_ft_flow *flow
);

/**
 * Get the flow value.
 * @param flow The flow handle.
 * @return The flow value.
 */
pfring_ft_flow_value *
pfring_ft_flow_get_value(
  pfring_ft_flow *flow
);

/**
 * Set the flow action, to be returned by pfring_ft_process() for all packets for this flow.
 * @param flow The flow handle.
 * @param action The action.
 */
void
pfring_ft_flow_set_action(
  pfring_ft_flow *flow,
  pfring_ft_action action
);

/**
 * Get the computed/actual flow action, the same returned by pfring_ft_process() for this flow.
 * @param flow The flow handle.
 * @return The action.
 */
pfring_ft_action
pfring_ft_flow_get_action(
  pfring_ft_flow *flow
);

/**
 * Release a flow.
 * @param flow The flow handle.
 */
void
pfring_ft_flow_free(
  pfring_ft_flow *flow
);

/**
 * Load filtering/shunting rules from a configuration file.
 * Please refer to the documentation for the file format.
 * @param table The flow table handle. 
 * @param path The configuration file path.
 * @return 0 on success, a negative number on failures.
 */
int
pfring_ft_load_configuration(
  pfring_ft_table *table, 
  const char *path
);

/**
 * Set a shunt rule for a L7 protocol.
 * @param table The flow table handle. 
 * @param protocol_name The nDPI protocol name.
 * @param packets The number of packets before shunting the flow returning a discard action from pfring_ft_process().
 */
void 
pfring_ft_set_shunt_protocol_by_name(
  pfring_ft_table *table,
  const char *protocol_name,
  u_int8_t packets
);

/**
 * Set a filtering rule for a L7 protocol.
 * @param table The flow table handle. 
 * @param protocol_name The nDPI protocol name.
 * @param action The action returned by pfring_ft_process() for all packets matching the protocol.
 */
void 
pfring_ft_set_filter_protocol_by_name(
  pfring_ft_table *table,
  const char *protocol_name,
  pfring_ft_action action
);

/**
 * Return the L7 protocol name providing the nDPI protocol ID.
 * @param table The flow table handle. 
 * @param protocol The nDPI protocol ID.
 * @param buffer The output buffer.
 * @param buffer_len The output buffer length.
 * @return The buffer.
 */
char *
pfring_ft_l7_protocol_name(
  pfring_ft_table *table,
  pfring_ft_ndpi_protocol *protocol,
  char *buffer, 
  int buffer_len
);

/**
 * Set the nDPI handle. This is meant to be used for custom nDPI settings only,
 * as FT already creates a nDPI instance internally when using PFRING_FT_TABLE_FLAGS_DPI.
 * FT takes care of releasing the nDPI instance on pfring_ft_destroy_table.
 * @param table The flow table handle. 
 * @return 0 on success, a negative number on failures.
 */
int
pfring_ft_set_ndpi_handle(
  pfring_ft_table *table,
  struct ndpi_detection_module_struct *ndpi
);

/**
 * Load nDPI categories (defined by hostname) from a configuration file.
 * Please refer to the nDPI documentation for the file format.
 * Example: https://github.com/ntop/nDPI/blob/dev/example/mining_hosts.txt
 * @param table The flow table handle. 
 * @param path The configuration file path.
 * @return 0 on success, a negative number on failures.
 */
int
pfring_ft_load_ndpi_categories(
  pfring_ft_table *table,
  const char *path
);

/**
 * Get flow processing statistics.
 * @param table The flow table handle. 
 * @return The stats struct.
 */
pfring_ft_stats *
pfring_ft_get_stats(
  pfring_ft_table *table
);

/**
 * Get the PF_RING FT version.
 * @param version A buffer (32 bytes long) where version is returned. (out)
 */
void
pfring_ft_version(
  char *version
);

/**
 * Get license info.
 * @param system_id A buffer (32 bytes long) where system id  is returned. (out)
 * @param license_expiration A pointer to a time_t where license expiration is returned. (out)
 * @param maintenance_expiration A pointer to a time_t where maintenance expiration is returned. (out)
 * @return 1 if a valid license is installed, 0 otherwise.
 */
int
pfring_ft_license(
  char *system_id, 
  time_t *license_expiration, 
  time_t *maintenance_expiration
);

/**
 * Enable debug mode
 */
void
pfring_ft_debug(
  void
);

#ifdef __cplusplus
}
#endif

#endif /* _PFRING_FT_H_ */

