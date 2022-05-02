/*
 *
 * (C) 2018-2021 - ntop.org
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

#define FT_API_VERSION 47

typedef void pfring_ft_table;
typedef void pfring_ft_list;
typedef void pfring_ft_flow;

struct ndpi_detection_module_struct;
struct ndpi_flow_struct;

/*** enums ***/

#define PFRING_FT_ACTION_DEFAULT 0
#define PFRING_FT_ACTION_FORWARD 1
#define PFRING_FT_ACTION_DISCARD 2
#define PFRING_FT_ACTION_USER_1  3
#define PFRING_FT_ACTION_USER_2  4

typedef u_int8_t pfring_ft_action;

typedef enum { 
  s2d_direction = 0, /**< Source to destination */
  d2s_direction,     /**< Destination to source */
  PF_RING_FT_FLOW_NUM_DIRECTIONS
} pfring_ft_direction;

typedef enum {
  PFRING_FT_FLOW_STATUS_ACTIVE = 0,     /**< Active flow */
  PFRING_FT_FLOW_STATUS_IDLE_TIMEOUT,   /**< Idle timeout */
  PFRING_FT_FLOW_STATUS_ACTIVE_TIMEOUT, /**< Terminated after the maximum lifetime */
  PFRING_FT_FLOW_STATUS_END_DETECTED,   /**< Terminated for end of flow (e.g. FIN) */
  PFRING_FT_FLOW_STATUS_FORCED_END,     /**< Terminated for external event (shutdown) */
  PFRING_FT_FLOW_STATUS_SLICE_TIMEOUT,  /**< Flow slice timeout */
  PFRING_FT_FLOW_STATUS_OVERFLOW        /**< Exported from those with higher inactivity to make room */
} pfring_ft_flow_status;

#define PF_RING_FT_FLOW_FLAGS_L7_GUESS (1 <<  0) /**< pfring_ft_flow_value.flags: detected L7 protocol is a guess. */

typedef struct {
  u_int32_t num_protocols; /**< Number of supported L7 protocols */

  /* Filtering */
  struct {
    pfring_ft_action *protocol_to_action; /**< Action per L7 protocol */
  } match;

  /* Shunting */
  struct {
    u_int8_t default_npkts;      /**< Default number of packets to forward */
    u_int8_t tcp_npkts;          /**< Number of packets to forward in case of TCP */
    u_int8_t udp_npkts;          /**< Number of packets to forward in case of UDP */
    u_int8_t *protocol_to_npkts; /**< Number of packets to forward per L7 protocol */
  } shunt;
} pfring_ft_flow_filter;

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

typedef struct {     /* pfring_pkthdr / pcap_pkthdr common struct */
  struct timeval ts; /**< time stamp */
  u_int32_t caplen;  /**< length of captured portion */
  u_int32_t len;     /**< length original packet (off wire) */
} pfring_ft_pcap_pkthdr;

typedef struct {       /* additional packet metadata not available in pcap_pkthdr */
  u_int32_t hash;      /**< packet hash */
  u_int16_t device_id; /**< Source device ID */
  u_int8_t  port_id;   /**< Source device port ID */
  u_int8_t  reserved;  /**< Padding */
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
  u_int8_t smac[6];           /**< Source MAC */
  u_int8_t dmac[6];           /**< Destination MAC */
  pfring_ft_ip_address saddr; /**< Source IP address (HBO) */
  pfring_ft_ip_address daddr; /**< Destination IP address (HBO) */
  u_int8_t ip_version;        /**< IP version */
  u_int8_t protocol;          /**< L4 protocol */
  u_int16_t sport;            /**< Source port (HBO) */
  u_int16_t dport;            /**< Destination port (HBO) */
  u_int16_t vlan_id;          /**< VLAN ID (HBO) */
} pfring_ft_flow_key;

typedef struct {
  u_int64_t pkts;           /**< Number of packets per direction */
  u_int64_t bytes;          /**< Number of bytes per direction */
  struct timeval first;     /**< Time of first packet seen per direction */
  struct timeval last;      /**< Time of last packet seen per direction */
  u_int8_t tcp_flags;       /**< TCP flags per direction */
  u_int8_t port_id;         /**< Port ID (when provided e.g. MetaWatch) */
  u_int16_t device_id;      /**< Device ID (when provided e.g. MetaWatch) */
} pfring_ft_flow_dir_value;

typedef struct {
  pfring_ft_flow_dir_value direction[PF_RING_FT_FLOW_NUM_DIRECTIONS]; /**< Metadata per flow direction */

  pfring_ft_ndpi_protocol l7_protocol; /**< nDPI protocol */
  u_int32_t tunnel_type; /**< nDPI tunnel type (ndpi_packet_tunnel) */
  u_int32_t tunnel_id;   /**< Tunnel ID (if any) */

  union {
    struct {
      char *query;            /**< DNS query */
      u_int16_t queryType;    /**< DNS query type */
      u_int16_t replyCode;    /**< DNS reply code */
    } dns;

    struct {
      char *serverName;       /**< TLS Server Name */
      u_int8_t *sha1_certificate_fingerprint; /**< SHA-1 Certificate Fingerprint (20-bytes) */
    } tls;

    struct {
      char *serverName;       /**< HTTP Server Name */
      char *url;              /**< HTTP URL */
      u_int16_t responseCode; /**< HTTP response code */
    } http;

    struct {
      u_int8_t type;          /**< ICMP Type */
      u_int8_t code;          /**< ICMP Code */
    } icmp;
  } l7_metadata;

  pfring_ft_flow_status status;
  u_int32_t flags;            /**< See PFRING_FT_FLOW_STATUS_* */

  u_char *user;               /**< User metadata: this points to the end of
                               * the same struct usually. In case of flow
                               * slice this points to the original flow's
                               * user data. */
} pfring_ft_flow_value;

/*** stats struct ***/

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

#define PFRING_FT_TABLE_FLAGS_DPI       (1 << 0) /**< pfring_ft_create_table() flag: enable nDPI support for L7 protocol detection */
#define PFRING_FT_TABLE_FLAGS_DPI_EXTRA (1 << 1) /**< pfring_ft_create_table() flag: enable nDPI extra dissection (more flow metadata) */
#define PFRING_FT_DECODE_TUNNELS        (1 << 2) /**< pfring_ft_create_table() flag: decode tunnels (GTP, L2TP, CAPWAP) */
#define PFRING_FT_IGNORE_HW_HASH        (1 << 3) /**< pfring_ft_create_table() flag: ignore hw packet hash (e.g. when it's asymmetric leading to one flow per direction) */

/**
 * Create a new flow table.
 * @param flags Flags to enable selected flow table features.
 * @param max_flows Maximum number of concurrent flows the table should be able to handle (use 0 if not sure to use default settings).
 * @param flow_idle_timeout Maximum flow idle time (seconds) before expiration (use 0 if not sure to use default: 30s).
 * @param flow_lifetime_timeout Maximum flow duration (seconds) before expiration (use 0 if not sure to use default: 2m).
 * @param user_metadata_size Size of the user metadata in pfring_ft_flow_value->user
 * @return The flow table on success, NULL on failure.
 */
pfring_ft_table *
pfring_ft_create_table(
  u_int32_t flags,
  u_int32_t max_flows,
  u_int32_t flow_idle_timeout,
  u_int32_t flow_lifetime_timeout,
  u_int32_t user_metadata_size
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
 * Enable flow slicing to peridiocally export flow updates, even when the 
 * configured flow_lifetime_timeout is not reached.
 * @param table The flow table handle.
 * @param flow_slice_timeout Maximum flow slice duration (seconds). This should be lower then flow_lifetime_timeout
 */
void
pfring_ft_flow_set_flow_slicing(
  pfring_ft_table *table,
  u_int32_t flow_slice_timeout
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
 * Set the function to be called when a packet and its flow have been processed and the l7 protocol has been just detected.
 * @param table The flow table handle.
 * @param callback The callback (Note: packet/metadata may be NULL).
 * @param user The user data provided to the callback.
 */
void
pfring_ft_set_l7_detected_callback(
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
 * Get the flow ID.
 * @param flow The flow handle.
 * @return The flow ID.
 */
u_int64_t
pfring_ft_flow_get_id(
  pfring_ft_flow *flow
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
 * Get the nDPI flow handle.
 * @param flow The flow handle.
 * @return The flow value.
 */
struct ndpi_flow_struct *
pfring_ft_flow_get_ndpi_handle(
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
 * Return the number of users for the flow (value of the reference counter).
 * This is usually 1, unless slicing is enabled (+1 for each slice not yet released).
 * Calling this on the slice, returns the reference counter of the master flow.
 * @param flow The flow handle.
 */
int
pfring_ft_flow_get_users(
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
 * Configure ZMQ flow export (see pfring_ft_zmq_export_flow)
 * @param table The flow table handle.
 * @param endpoint The ZMQ endpoint.
 * @param server_public_key The ZMQ Public encryption key (NULL for clear).
 * @param probe_mode Probe mode (connect to the ZMQ collector).
 * @param disable_compression Disable message compression.
 * @param use_json Use JSON format (Default: TLV).
 */
void
pfring_ft_zmq_export_configure(
  pfring_ft_table *table,
  const char *endpoint,
  const char *server_public_key,
  u_int8_t probe_mode,
  u_int8_t disable_compression,
  u_int8_t use_json
);

/**
 * Built-in callback to be provided to pfring_ft_set_flow_export_callback for
 * exporting flows in JSON or TLV format to ZMQ. This implements pfring_ft_export_flow_func.
 * The ZMQ endpoint should be configure with pfring_ft_zmq_export_configure().
 * The callback also releases the flow calling pfring_ft_flow_free(flow).
 * Usage: pfring_ft_set_flow_export_callback(table, pfring_ft_zmq_export_flow, table);
 * @param flow The flow to be exported.
 * @param user The flow table handle.
 */
void
pfring_ft_zmq_export_flow(
  pfring_ft_flow *flow,
  void *user
);

/**
 * Export stats via ZMQ
 * @param table The flow table handle.
 * @param if_name Interface name.
 * @param if_speed Interface speed (Mbps).
 * @param if_ip Interface IP.
 * @param management_ip Management Interface IP.
 */
void
pfring_ft_zmq_export_stats(
  pfring_ft_table *table,
  const char *if_name,
  u_int16_t if_speed,
  const char *if_ip,
  const char *management_ip
);

/**
 * Set the default action for detected L7 protocols with no filtering rule.
 * This can be used to 'drop all' traffic, exception made for specific protocols
 * setting the default to PFRING_FT_ACTION_DISCARD and filter actions to PFRING_FT_ACTION_FORWARD
 * Default: PFRING_FT_ACTION_DEFAULT
 * @param table The flow table handle. 
 * @param action The action returned by pfring_ft_process() by default.
 */
void 
pfring_ft_set_default_action(
  pfring_ft_table *table,
  pfring_ft_action action
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
 * Load filtering/shunting rules from a configuration file
 * to an external pfring_ft_flow_filter handle.
 * Please refer to the documentation for the file format.
 * @param table The flow table handle. 
 * @param path The configuration file path.
 * @param filter The destination pfring_ft_flow_filter handle.
 * @return 0 on success, a negative number on failures.
 */
int
pfring_ft_load_configuration_ext(
  pfring_ft_table *table, 
  const char *path,
  pfring_ft_flow_filter *filter
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
 * Set a default action for all L7 protocols. This is usually used to reset all filtering rules
 * by passing PFRING_FT_ACTION_DEFAULT as action.
 * @param table The flow table handle. 
 * @param action The action to set for all protocols.
 */
void 
pfring_ft_set_filter_all_protocols(
  pfring_ft_table *table,
  pfring_ft_action action
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
 * Return the nDPI L7 protocol ID providing the L7 protocol name.
 * @param table The flow table handle. 
 * @param name The L7 protocol name.
 * @return The nDPI protocol ID.
 */
u_int16_t
pfring_ft_l7_protocol_id(
  pfring_ft_table *table,
  const char *name
);

/**
 * Set the nDPI handle. This is meant to be used for custom nDPI settings only,
 * as FT already creates a nDPI instance internally when using PFRING_FT_TABLE_FLAGS_DPI.
 * FT takes care of releasing the nDPI instance on pfring_ft_destroy_table.
 * @param table The flow table handle. 
 * @param ndpi  The nDPI handle.
 * @return 0 on success, a negative number on failures.
 */
int
pfring_ft_set_ndpi_handle(
  pfring_ft_table *table,
  struct ndpi_detection_module_struct *ndpi
);

/**
 * Return the nDPI handle.
 * @param table The flow table handle. 
 * @return The nDPI handle, NULL if there is no handle.
 */
struct ndpi_detection_module_struct *
pfring_ft_get_ndpi_handle(
  pfring_ft_table *table
);

/**
 * Load custom nDPI protocols from a configuration file.
 * Please refer to the nDPI documentation for the file format.
 * Example: https://github.com/ntop/nDPI/blob/dev/example/protos.txt
 * @param table The flow table handle. 
 * @param path The configuration file path.
 * @return 0 on success, a negative number on failures.
 */
int
pfring_ft_load_ndpi_protocols(
  pfring_ft_table *table,
  const char *path
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
 * Check if nDPI is available.
 * @return 1 if nDPI is available, 0 otherwise.
 */
int
pfring_ft_is_ndpi_available();

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
 * Get the PF_RING FT API version.
 * @return The version number as unsigne inte.
 */
u_int32_t
pfring_ft_api_version(
);

/**
 * Get license info.
 * @param system_id A buffer (48 bytes long) where system id is returned. (out)
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
 * Install a PF_RING FT license key.
 * @param license_key The license key.
 * @return 1 if the license has been successfully installed, 0 otherwise (e.g. no permissions).
 */
int
pfring_ft_set_license(
  const char *license_key
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

