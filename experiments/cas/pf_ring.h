/*
 *
 * Definitions for packet ring
 *
 * 2004-11 Luca Deri <deri@ntop.org>
 *
 */

#ifndef __RING_H
#define __RING_H

#ifdef __KERNEL__
#include <linux/in6.h>
#else
#include <netinet/in.h>
#endif /* __KERNEL__ */

#define INCLUDE_MAC_INFO

#ifdef INCLUDE_MAC_INFO
#define SKB_DISPLACEMENT    14 /* Include MAC address information */
#else
#define SKB_DISPLACEMENT    0  /* Do NOT include MAC address information */
#endif

#define RING_MAGIC
#define RING_MAGIC_VALUE             0x88
#define RING_FLOWSLOT_VERSION          14

#define DEFAULT_BUCKET_LEN            128
#define MAX_NUM_DEVICES               256

/* Watermark */
#define DEFAULT_MIN_PKT_QUEUED        128

/* Dirty hack I know, but what else shall I do man? */
#define pfring_ptr ec_ptr

/* Versioning */
#define RING_VERSION                "5.3.0"
#define RING_VERSION_NUM           0x050300

/* Set */
#define SO_ADD_TO_CLUSTER                 99
#define SO_REMOVE_FROM_CLUSTER           100
#define SO_SET_STRING                    101
#define SO_ADD_FILTERING_RULE            102
#define SO_REMOVE_FILTERING_RULE         103
#define SO_TOGGLE_FILTER_POLICY          104
#define SO_SET_SAMPLING_RATE             105
#define SO_ACTIVATE_RING                 106
#define SO_RING_BUCKET_LEN               107
#define SO_SET_CHANNEL_ID                108
#define SO_PURGE_IDLE_HASH_RULES         109 /* inactivity (sec) */
#define SO_SET_APPL_NAME                 110
#define SO_SET_PACKET_DIRECTION          111
#define SO_SET_MASTER_RING               112
#define SO_ADD_HW_FILTERING_RULE         113
#define SO_DEL_HW_FILTERING_RULE         114
#define SO_SET_PACKET_CONSUMER_MODE      115
#define SO_DEACTIVATE_RING               116
#define SO_SET_POLL_WATERMARK            117
#define SO_SET_VIRTUAL_FILTERING_DEVICE  118
#define SO_REHASH_RSS_PACKET             119
#define SO_SET_VPFRING_HOST_EVENTFD      120 /* host  to guest */
#define SO_SET_VPFRING_GUEST_EVENTFD     121 /* guest to host (unused) */
#define SO_SET_VPFRING_CLEAN_EVENTFDS    122
#define SO_ATTACH_USERSPACE_RING         123
#define SO_SHUTDOWN_RING                 124
#define SO_PURGE_IDLE_RULES              125 /* inactivity (sec) */

/* Get */
#define SO_GET_RING_VERSION              170
#define SO_GET_FILTERING_RULE_STATS      171
#define SO_GET_HASH_FILTERING_RULE_STATS 172
#define SO_GET_MAPPED_DNA_DEVICE         173
#define SO_GET_NUM_RX_CHANNELS           174
#define SO_GET_RING_ID                   175
#define SO_GET_PACKET_CONSUMER_MODE      176
#define SO_GET_BOUND_DEVICE_ADDRESS      177
#define SO_GET_NUM_QUEUED_PKTS           178
#define SO_GET_PKT_HEADER_LEN            179
#define SO_GET_LOOPBACK_TEST             180
#define SO_GET_BUCKET_LEN                181
#define SO_GET_DEVICE_TYPE               182
#define SO_GET_EXTRA_DMA_MEMORY          183

/* Map */
#define SO_MAP_DNA_DEVICE                190

/* Error codes */
#define PF_RING_ERROR_GENERIC              -1
#define PF_RING_ERROR_INVALID_ARGUMENT     -2
#define PF_RING_ERROR_NO_PKT_AVAILABLE	   -3
#define PF_RING_ERROR_NO_TX_SLOT_AVAILABLE -4
#define PF_RING_ERROR_WRONG_CONFIGURATION  -5
#define PF_RING_ERROR_END_OF_DEMO_MODE     -6
#define PF_RING_ERROR_NOT_SUPPORTED        -7
#define PF_RING_ERROR_INVALID_LIB_VERSION  -8
#define PF_RING_ERROR_UNKNOWN_ADAPTER      -9

#define REFLECTOR_NAME_LEN                 8

#ifndef IN6ADDR_ANY_INIT
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#endif

#ifndef NETDEV_PRE_UP
#define NETDEV_PRE_UP  0x000D
#endif

/* *********************************** */

struct pkt_aggregation_info {
  u_int32_t num_pkts, num_bytes;
  struct timeval first_seen, last_seen;
};

/*
  Note that as offsets *can* be negative,
  please do not change them to unsigned
*/
struct pkt_offset {
  int16_t eth_offset; /* This offset *must* be added to all offsets below */
  int16_t vlan_offset;
  int16_t l3_offset;
  int16_t l4_offset;
  int16_t payload_offset;
};


struct pkt_flow_info {
  u_int32_t in_iface, out_iface, samplingPopulation, flow_sequence;
};

#ifndef ETH_ALEN
#define ETH_ALEN  6
#endif

#define REFLECT_PACKET_DEVICE_NONE     0

typedef union {
  struct in6_addr v6;  /* IPv6 src/dst IP addresses (Network byte order) */
  u_int32_t v4;        /* IPv4 src/dst IP addresses */
} ip_addr;

#define ipv4_tos     ip_tos
#define ipv6_tos     ip_tos
#define ipv4_src     ip_src.v4
#define ipv4_dst     ip_dst.v4
#define ipv6_src     ip_src.v6
#define ipv6_dst     ip_dst.v6
#define host4_low    host_low.v4
#define host4_high   host_high.v4
#define host6_low    host_low.v6
#define host6_high   host_high.v6
#define host4_peer_a host_peer_a.v4
#define host4_peer_b host_peer_b.v4
#define host6_peer_a host_peer_a.v6
#define host6_peer_b host_peer_b.v6

typedef union {
  struct pkt_flow_info flow; /* Flow Information */
  struct pkt_aggregation_info aggregation; /* Future or plugin use */
} packet_user_detail;

struct pkt_parsing_info {
  /* Core fields (also used by NetFlow) */
  u_int8_t dmac[ETH_ALEN], smac[ETH_ALEN];  /* MAC src/dst addresses */
  u_int16_t eth_type;   /* Ethernet type */
  u_int16_t vlan_id;    /* VLAN Id or NO_VLAN */
  u_int8_t  ip_version;
  u_int8_t  l3_proto, ip_tos; /* Layer 3 protocol/TOS */
  ip_addr   ip_src, ip_dst;   /* IPv4 src/dst IP addresses */
  u_int16_t l4_src_port, l4_dst_port; /* Layer 4 src/dst ports */
  struct {
    u_int8_t flags;   /* TCP flags (0 if not available) */
    u_int32_t seq_num, ack_num; /* TCP sequence number */
  } tcp;
  u_int16_t last_matched_plugin_id; /* If > 0 identifies a plugin to that matched the packet */
  u_int16_t last_matched_rule_id; /* If > 0 identifies a rule that matched the packet */
  struct pkt_offset offset; /* Offsets of L3/L4/payload elements */

  /* Leave it at the end of the structure */
  packet_user_detail pkt_detail;
};

#define UNKNOWN_INTERFACE          -1
#define FAKE_PACKET                -2 /* It indicates that the returned packet
					 is faked, and that the info is basically
					 a message from PF_RING
				      */
struct pfring_extended_pkthdr {
  u_int64_t timestamp_ns; /* Packet timestamp at ns precision. Note that if your NIC supports
			     hardware timestamp, this is the place to read timestamp from */
  u_int8_t rx_direction;  /* 1=RX: packet received by the NIC, 0=TX: packet transmitted by the NIC */
  int if_index;           /* index of the interface on which the packet has been received.
                             It can be also used to report other information */
  u_int32_t pkt_hash;     /* Hash based on the packet header */
  u_int16_t parsed_header_len; /* Extra parsing data before packet */

  /* NOTE: leave it as last field of the memset on parse_pkt() will fail */
  struct pkt_parsing_info parsed_pkt; /* packet parsing info */
};

/* NOTE

   Keep 'struct pfring_pkthdr' in sync with 'struct pcap_pkthdr'
*/

struct pfring_pkthdr {
  /* pcap header */
  struct timeval ts;    /* time stamp */
  u_int32_t caplen;     /* length of portion present */
  u_int32_t len;        /* length this packet (off wire) */
  struct pfring_extended_pkthdr extended_hdr; /* PF_RING extended header */
};

/* *********************************** */

#define NO_PLUGIN_ID        0
#define MAX_PLUGIN_ID      72
#define MAX_PLUGIN_FIELDS  32

/* ************************************************* */

typedef struct {
  u_int8_t smac[ETH_ALEN], dmac[ETH_ALEN]; /* Use '0' (zero-ed MAC address) for any MAC address.
					      This is applied to both source and destination. */
  u_int16_t vlan_id;                 /* Use '0' for any vlan */
  u_int8_t  proto;                   /* Use 0 for 'any' protocol */
  ip_addr   shost, dhost;            /* User '0' for any host. This is applied to both source and destination. */
  ip_addr   shost_mask, dhost_mask;  /* IPv4/6 network mask */
  u_int16_t sport_low, sport_high;     /* All ports between port_low...port_high means 'any' port */
  u_int16_t dport_low, dport_high;     /* All ports between port_low...port_high means 'any' port */
} filtering_rule_core_fields;

/* ************************************************* */

#define FILTER_PLUGIN_DATA_LEN   256

typedef struct {
  char payload_pattern[32];         /* If strlen(payload_pattern) > 0, the packet payload
				       must match the specified pattern */
  u_int16_t filter_plugin_id;       /* If > 0 identifies a plugin to which the datastructure
				       below will be passed for matching */
  char      filter_plugin_data[FILTER_PLUGIN_DATA_LEN];
  /* Opaque datastructure that is interpreted by the
     specified plugin and that specifies a filtering
     criteria to be checked for match. Usually this data
     is re-casted to a more meaningful datastructure
  */
} filtering_rule_extended_fields;

/* ************************************************* */

typedef struct {
  /* Plugin Action */
  u_int16_t plugin_id; /* ('0'=no plugin) id of the plugin associated with this rule */
} filtering_rule_plugin_action;

typedef enum {
  forward_packet_and_stop_rule_evaluation = 0,
  dont_forward_packet_and_stop_rule_evaluation,
  execute_action_and_continue_rule_evaluation,
  execute_action_and_stop_rule_evaluation,
  forward_packet_add_rule_and_stop_rule_evaluation, /* auto-filled hash rule or via plugin_add_rule() */
  forward_packet_del_rule_and_stop_rule_evaluation, /* via plugin_del_rule() only */
  reflect_packet_and_stop_rule_evaluation,
  reflect_packet_and_continue_rule_evaluation,
  bounce_packet_and_stop_rule_evaluation,
  bounce_packet_and_continue_rule_evaluation
} rule_action_behaviour;

typedef enum {
  pkt_detail_flow,
  pkt_detail_aggregation
} pkt_detail_mode;

typedef enum {
  rx_and_tx_direction = 0,
  rx_only_direction,
  tx_only_direction
} packet_direction;

typedef enum {
  standard_linux_path = 0,           /* Business as usual */
  driver2pf_ring_transparent = 1,    /* Packets are still delivered to the kernel */
  driver2pf_ring_non_transparent = 2 /* Packets not delivered to the kernel */
} direct2pf_ring;


typedef struct {
  unsigned long jiffies_last_match;  /* Jiffies of the last rule match (updated by pf_ring) */
  struct net_device *reflector_dev;  /* Reflector device */
} filtering_internals;

typedef struct {
  u_int16_t rule_id;                 /* Rules are processed in order from lowest to higest id */
  rule_action_behaviour rule_action; /* What to do in case of match */
  u_int8_t balance_id, balance_pool; /* If balance_pool > 0, then pass the packet above only if the
					(hash(proto, sip, sport, dip, dport) % balance_pool) = balance_id */
  u_int8_t locked;		     /* Do not purge with pfring_purge_idle_rules() */
  u_int8_t bidirectional;	     /* Swap peers when checking if they match the rule. Default: monodir */
  filtering_rule_core_fields     core_fields;
  filtering_rule_extended_fields extended_fields;
  filtering_rule_plugin_action   plugin_action;
  char reflector_device_name[REFLECTOR_NAME_LEN];

  filtering_internals internals;   /* PF_RING internal fields */
} filtering_rule;

/* *********************************** */

/* 82599 packet steering filters */

typedef struct {
  u_int8_t  proto;
  u_int32_t s_addr, d_addr;
  u_int16_t s_port, d_port;
  u_int16_t queue_id;
} intel_82599_five_tuple_filter_hw_rule;

typedef struct {
  u_int16_t vlan_id;
  u_int8_t  proto;
  u_int32_t s_addr, d_addr;
  u_int16_t s_port, d_port;
  u_int16_t queue_id;
} intel_82599_perfect_filter_hw_rule;

/*
  Rules are defined per port. Each redirector device
  has 4 ports (numbeder 0..3):

         0   +--------------+   2   +--------------+
  LAN  <===> |              | <===> |   1/10G      |
             |  Redirector  |       |   Ethernet   |
  LAN  <===> |    Switch    | <===> |   Adapter    |
         1   +--------------+   3   +--------------+

  Drop Rule
  Discard incoming packets matching the filter
  on 'rule_port'

  Redirect Rule
  Divert incoming packets matching the filter
  on 'rule_port' to 'rule_target_port'.

  Mirror Rule
  Copy incoming packets matching the filter
  on 'rule_port' to 'rule_target_port'. The original
  packet will continue its journey (i.e. packet are
  actually duplicated)
*/

typedef enum {
  drop_rule,
  redirect_rule,
  mirror_rule
} silicom_redirector_rule_type;

typedef struct {
  silicom_redirector_rule_type rule_type;
  u_int8_t rule_port; /* Port on which the rule is defined */
  u_int8_t rule_target_port; /* Target port (ignored for drop rules) */
  u_int16_t vlan_id_low, vlan_id_high;
  u_int8_t l3_proto;
  ip_addr src_addr, dst_addr;
  u_int32_t src_mask, dst_mask;
  u_int16_t src_port_low, src_port_high;
  u_int16_t dst_port_low, dst_port_high;
} silicom_redirector_hw_rule;

typedef enum {
  intel_82599_five_tuple_rule,
  intel_82599_perfect_filter_rule,
  silicom_redirector_rule
} hw_filtering_rule_type;

typedef struct {
  hw_filtering_rule_type rule_family_type;
  u_int16_t rule_id;

  union {
    intel_82599_five_tuple_filter_hw_rule five_tuple_rule;
    intel_82599_perfect_filter_hw_rule perfect_rule;
    silicom_redirector_hw_rule redirector_rule;
  } rule_family;
} hw_filtering_rule;

#define MAGIC_HW_FILTERING_RULE_REQUEST  0x29010020 /* deprecated? */

#ifdef __KERNEL__

#define ETHTOOL_PFRING_SRXFTCHECK 0x10000000
#define ETHTOOL_PFRING_SRXFTRLDEL 0x10000031
#define ETHTOOL_PFRING_SRXFTRLINS 0x10000032

#if defined(I82599_HW_FILTERING_SUPPORT) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,40))
#define	FLOW_EXT 0x80000000
union _kcompat_ethtool_flow_union {
	struct ethtool_tcpip4_spec		tcp_ip4_spec;
	struct ethtool_usrip4_spec		usr_ip4_spec;
	__u8					hdata[60];
};
struct _kcompat_ethtool_flow_ext {
	__be16	vlan_etype;
	__be16	vlan_tci;
	__be32	data[2];
};
struct _kcompat_ethtool_rx_flow_spec {
	__u32		flow_type;
	union _kcompat_ethtool_flow_union h_u;
	struct _kcompat_ethtool_flow_ext h_ext;
	union _kcompat_ethtool_flow_union m_u;
	struct _kcompat_ethtool_flow_ext m_ext;
	__u64		ring_cookie;
	__u32		location;
};
#define ethtool_rx_flow_spec _kcompat_ethtool_rx_flow_spec
#endif /* defined(I82599_HW_FILTERING_SUPPORT) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,40)) */

#endif /* __KERNEL__ */

typedef enum {
  add_hw_rule,
  remove_hw_rule
} hw_filtering_rule_command;

/* *********************************** */

extern struct pf_ring_socket *pfr; /* Forward */

/* *********************************** */

typedef int (*five_tuple_rule_handler)(struct pf_ring_socket *pfr,
				       hw_filtering_rule *rule,
				       hw_filtering_rule_command request);
typedef int (*perfect_filter_hw_rule_handler)(struct pf_ring_socket *pfr,
					      hw_filtering_rule *rule,
					      hw_filtering_rule_command request);

typedef struct {
  five_tuple_rule_handler five_tuple_handler;
  perfect_filter_hw_rule_handler perfect_filter_handler;
} hw_filtering_device_handler;

/* *********************************** */

/* Hash size used for precise packet matching */
#define DEFAULT_RING_HASH_SIZE     4096

/*
 * The hashtable contains only perfect matches: no
 * wildacards or so are accepted. (bidirectional)
 */
typedef struct {
  u_int16_t rule_id; /* Future use */
  u_int16_t vlan_id;
  u_int8_t  proto;
  ip_addr host_peer_a, host_peer_b;
  u_int16_t port_peer_a, port_peer_b;

  rule_action_behaviour rule_action; /* What to do in case of match */
  filtering_rule_plugin_action plugin_action;
  char reflector_device_name[REFLECTOR_NAME_LEN];

  filtering_internals internals;   /* PF_RING internal fields */
} hash_filtering_rule;

/* ************************************************* */

typedef struct _sw_filtering_hash_bucket {
  hash_filtering_rule           rule;
  void                          *plugin_data_ptr; /* ptr to a *continuous* memory area
						     allocated by the plugin */
  u_int16_t                     plugin_data_ptr_len;
  struct _sw_filtering_hash_bucket *next;
} sw_filtering_hash_bucket;

/* *********************************** */

#define RING_MIN_SLOT_SIZE    (60+sizeof(struct pfring_pkthdr))
#define RING_MAX_SLOT_SIZE    (1514+sizeof(struct pfring_pkthdr))

#if !defined(__cplusplus)

#define min_val(a,b) ((a < b) ? a : b)
#define max_val(a,b) ((a > b) ? a : b)

#endif

/* *********************************** */

#ifndef __KERNEL__
/* Missing type in userland */
typedef struct {
  int counter;
} atomic_t;
#endif

/* False sharing reference: http://en.wikipedia.org/wiki/False_sharing */

typedef struct flowSlotInfo {
  /* first page, managed by kernel */
  u_int16_t version, sample_rate;
  u_int32_t min_num_slots, slot_len, data_len, tot_mem;
  atomic_t shadow_insert_off /* managed by kernel (necessary for atomic ring insert) */;
  atomic_t insert_off /* managed by kernel */;
  atomic_t tot_pkts, tot_lost, tot_insert;
  u_int64_t tot_fwd_ok, tot_fwd_notok;
  /* <-- 64 bytes here, should be enough to avoid some L1 VIVT coherence issues (32 ~ 64bytes lines) */
  char padding[128];
  /* <-- 128 bytes here, should be enough to avoid false sharing in most L2 (64 ~ 128bytes lines) */
  char k_padding[3904];
  /* <-- 4096 bytes here, to get a page aligned block writable by kernel side only */

  /* second page, managed by userland */
  u_int64_t tot_read;
  u_int32_t remove_off /* managed by userland */;
  u_int32_t vpfring_guest_flags; /* used by vPFRing */
  u_int32_t userspace_ring_flags;
  char u_padding[4076];
  /* <-- 8192 bytes here, to get a page aligned block writable by userland only */
} FlowSlotInfo;

/* **************************************** */

#define DNA_MAX_CHUNK_ORDER		5
#define DNA_MAX_NUM_CHUNKS		4096
#define MAX_EXTRA_DMA_SLOTS		524288

/* *********************************** */

#ifdef __KERNEL__

FlowSlotInfo *getRingPtr(void);
int allocateRing(char *deviceName, u_int numSlots,
		 u_int bucketLen, u_int sampleRate);
unsigned int pollRing(struct file *fp, struct poll_table_struct * wait);
void deallocateRing(void);

/* ************************* */

#endif /* __KERNEL__ */

/* *********************************** */

#define PF_RING          27      /* Packet Ring */
#define SOCK_RING        PF_RING

/* ioctl() */
#define SIORINGPOLL      0x8888

/* ************************************************* */

#ifdef __KERNEL__
struct ring_sock {
  struct sock           sk; /* It MUST be the first element */
  struct packet_type    prot_hook;
  spinlock_t		bind_lock;
};
#endif

/* *********************************** */

typedef int (*dna_wait_packet)(void *adapter, int mode);
typedef void (*dna_device_notify)(void *adapter, u_int8_t device_in_use);

typedef enum {
  add_device_mapping = 0, remove_device_mapping
} dna_device_operation;

typedef enum {
  intel_e1000e = 0,
  intel_igb,
  intel_igb_82580,
  intel_ixgbe,
  intel_ixgbe_82598,
  intel_ixgbe_82599
} dna_device_model;

typedef struct {
  u_int32_t packet_memory_num_chunks;
  u_int32_t packet_memory_chunk_len;
  u_int32_t packet_memory_num_slots;
  u_int32_t packet_memory_slot_len;
  u_int32_t descr_packet_memory_tot_len;
} mem_ring_info;

typedef enum {
  dna_v1 = 0,
  dna_v2
} dna_version;

typedef struct {
  dna_version version;
  mem_ring_info rx;
  mem_ring_info tx;
  u_int32_t phys_card_memory_len;
  dna_device_model device_model;
} dna_memory_slots;

typedef struct {
  u_int16_t rx_descr_head, rx_descr_tail, rx_descr_next;
} dna_indexes;

typedef struct {
  u_int16_t rx_descr_head, rx_descr_tail;
} tnapi_indexes;

typedef struct {
  u_int16_t pkt_len;  /* 0 = no packet received */
  u_int32_t pkt_hash; /* RSS */
  /* TODO We need to add the timestamp at some point */
} dna_descriptor;

typedef struct {
  dna_memory_slots mem_info;
  u_int16_t channel_id;
  unsigned long rx_packet_memory[DNA_MAX_NUM_CHUNKS];  /* Invalid in userland */
  unsigned long tx_packet_memory[DNA_MAX_NUM_CHUNKS];  /* Invalid in userland */
  void *rx_descr_packet_memory; /* Invalid in userland */
  void *tx_descr_packet_memory; /* Invalid in userland */
  char *phys_card_memory;       /* Invalid in userland */
  struct net_device *netdev;    /* Invalid in userland */
  struct device *hwdev;         /* Invalid in userland */
  u_char device_address[6];
#ifdef __KERNEL__
  wait_queue_head_t *packet_waitqueue;
#else
  void *packet_waitqueue;
#endif
  u_int8_t *interrupt_received, in_use;
  void *adapter_ptr;
  dna_wait_packet wait_packet_function_ptr;
  dna_device_notify usage_notification;
} dna_device;

typedef struct {
  dna_device_operation operation;
  char device_name[8];
  int32_t channel_id;
} dna_device_mapping;

/* ************************************************* */

#define RING_ANY_CHANNEL          ((u_int32_t)-1)
#define UNKNOWN_RX_CHANNEL        RING_ANY_CHANNEL
#define MAX_NUM_RX_CHANNELS       32 /* channel_id is a 32 bit value */
#define UNKNOWN_NUM_RX_CHANNELS   1

/* ************************************************* */

typedef enum {
  cluster_per_flow = 0,     /* 6-tuple: <src ip, src port, dst ip, dst port, proto, vlan>  */
  cluster_round_robin,
  cluster_per_flow_2_tuple, /* 2-tuple: <src ip,           dst ip                       >  */
  cluster_per_flow_4_tuple, /* 4-tuple: <src ip, src port, dst ip, dst port             >  */
  cluster_per_flow_5_tuple, /* 5-tuple: <src ip, src port, dst ip, dst port, proto      >  */
} cluster_type;

struct add_to_cluster {
  u_int clusterId;
  cluster_type the_type;
};

typedef enum {
  standard_nic_family = 0, /* No Hw Filtering */
  intel_82599_family,
} pfring_device_type;

typedef struct {
  char device_name[16];
  pfring_device_type device_type;

  /* Entry in the /proc filesystem */
  struct proc_dir_entry *proc_entry;
} virtual_filtering_device_info;

#ifdef __KERNEL__

#define CLUSTER_LEN       32

/*
 * A ring cluster is used group together rings used by various applications
 * so that they look, from the PF_RING point of view, as a single ring.
 * This means that developers can use clusters for sharing packets across
 * applications using various policies as specified in the hashing_mode
 * parameter.
 */
struct ring_cluster {
  u_short        cluster_id; /* 0 = no cluster */
  u_short        num_cluster_elements;
  cluster_type   hashing_mode;
  u_short        hashing_id;
  struct sock    *sk[CLUSTER_LEN];
};

/*
 * Linked-list of ring clusters
 */
typedef struct {
  struct ring_cluster cluster;
  struct list_head list;
} ring_cluster_element;

#define MAX_NUM_DNA_BOUND_SOCKETS  8

typedef struct {
  u8 num_bound_sockets;
  dna_device dev;
  struct list_head list;
  /*
    In the DNA world only one application can open the device@channel
    per direction. The two variables below are used to keep
    pointers to the max two sockets (one for RX and one for TX) that can open
    the DNA socket
  */
  struct pf_ring_socket *bound_sockets[MAX_NUM_DNA_BOUND_SOCKETS];
} dna_device_list;

#define MAX_NUM_IFIDX                       1024

/*
 * Linked-list of virtual filtering devices
 */
typedef struct {
  virtual_filtering_device_info info;
  struct list_head list;
} virtual_filtering_device_element;


typedef struct {
  /* DNA */
  u_int num_dna_rx_queues; /* 0 for non DNA devices */
  u_int8_t is_dna_device;
  dna_device_model dna_device_model;

  pfring_device_type device_type; /* Device Type */

  /*
    NOTE

    Some device types (e.g. redirector) might NOT
    have a net_device handler but a dummy pointer
  */
  struct net_device *dev;

  /* Entry in the /proc filesystem */
  struct proc_dir_entry *proc_entry;

  /* Hardware Filters */
  struct {
    u_int16_t num_filters;
    hw_filtering_device_handler filter_handlers;
  } hw_filters;

  struct list_head device_list;
} ring_device_element;

/* ************************************************* */

/*
 * Linked-list of ring sockets.
 */
struct ring_element {
  struct list_head  list;
  struct sock      *sk;
};

/* ************************************************* */

typedef enum {
  userspace_ring_consumer = 0,
  userspace_ring_producer
} userspace_ring_client_type;

struct pf_userspace_ring {
  u_int16_t  id;

  u_int16_t  slot_header_len;
  u_int32_t  bucket_len;

  u_int32_t  tot_mem;
  char      *ring_memory;

  atomic_t   users[2]; /* producers/consumers */

  wait_queue_head_t *consumer_ring_slots_waitqueue;

  struct list_head list;
};

/* ************************************************* */

typedef int (*do_handle_sw_filtering_hash_bucket)(struct pf_ring_socket *pfr,
					       sw_filtering_hash_bucket* rule,
					       u_char add_rule);

typedef int (*do_add_packet_to_ring)(struct pf_ring_socket *pfr,
				     u_int8_t real_skb,
				     struct pfring_pkthdr *hdr, struct sk_buff *skb,
				     int displ, u_int8_t parse_pkt_first);

typedef int (*do_add_raw_packet_to_ring)(struct pf_ring_socket *pfr,
					 struct pfring_pkthdr *hdr,
					 char *data, u_int data_len,
					 u_int8_t parse_pkt_first);

/* ************************************************* */

#define MAX_NUM_DEVICES_ID    MAX_NUM_IFIDX
/*
 * Ring options
 */
struct pf_ring_socket {
  u_int8_t ring_active, ring_shutdown, num_rx_channels, rehash_rss, num_bound_devices;
  ring_device_element *ring_netdev;

  DECLARE_BITMAP(netdev_mask, MAX_NUM_DEVICES_ID /* bits */);
  u_short ring_pid;
  u_int32_t ring_id;
  char *appl_name; /* String that identifies the application bound to the socket */
  packet_direction direction; /* Specify the capture direction for packets */

  /* /proc */
  char sock_proc_name[64];

  /* Poll Watermark */
  u_int32_t num_poll_calls;
  u_int16_t poll_num_pkts_watermark;

  /* Master Ring */
  struct pf_ring_socket *master_ring;

  /* Direct NIC Access */
  dna_device *dna_device;
  dna_device_list *dna_device_entry;

  /* Extra DMA memory */
  u_int32_t extra_dma_memory_num_chunks, extra_dma_memory_chunk_len;
  u_int32_t extra_dma_memory_num_slots,  extra_dma_memory_slot_len;
  unsigned long *extra_dma_memory;  /* chunks pointers */
  u_int64_t *extra_dma_memory_addr; /* per-slot DMA adresses */
  struct device *extra_dma_memory_hwdev; /* dev for DMA mapping */

  /* Cluster */
  u_short cluster_id; /* 0 = no cluster */

  /* Channel */
  int32_t channel_id;  /* -1 = any channel */
  u_int16_t num_channels_per_ring;

  /* Ring Slots */
  char *ring_memory;
  u_int16_t slot_header_len;
  u_int32_t bucket_len;
  FlowSlotInfo *slots_info; /* Points to ring_memory */
  char *ring_slots;         /* Points to ring_memory+sizeof(FlowSlotInfo) */

  /* Packet Sampling */
  u_int32_t pktToSample, sample_rate;

  /* Virtual Filtering Device */
  virtual_filtering_device_element *v_filtering_dev;

  /* BPF Filter */
  struct sk_filter *bpfFilter;

  /* Sw Filtering Rules */
  sw_filtering_hash_bucket **sw_filtering_hash;
  u_int16_t num_sw_filtering_rules;
  u_int8_t sw_filtering_rules_default_accept_policy; /* 1=default policy is accept, drop otherwise */
  struct list_head sw_filtering_rules;

  /* Hw Filtering Rules */
  u_int16_t num_hw_filtering_rules;
  struct list_head hw_filtering_rules;

  /* Locks */
  atomic_t num_ring_users;
  wait_queue_head_t ring_slots_waitqueue;
  rwlock_t ring_index_lock, ring_rules_lock;

  /* Indexes (Internal) */
  u_int insert_page_id, insert_slot_id;

  /* Function pointer */
  do_add_packet_to_ring add_packet_to_ring;
  do_add_raw_packet_to_ring add_raw_packet_to_ring;

  /* Kernel consumer */
  u_int8_t kernel_consumer_plugin_id; /* If != 0 it identifies a plugin responsible for consuming packets */
  char *kernel_consumer_options, *kernel_consumer_private;

#ifdef VPFRING_SUPPORT
  struct eventfd_ctx *vpfring_host_eventfd_ctx;   /* host  -> guest */
#endif /* VPFRING_SUPPORT */

  /* UserSpace RING */
  userspace_ring_client_type  userspace_ring_type;
  struct pf_userspace_ring   *userspace_ring;
};

/* **************************************** */

/*
 * Linked-list of device rings
 */
typedef struct {
  struct pf_ring_socket *the_ring;
  struct list_head list;
} device_ring_list_element;

/* **************************************** */

#define MAX_NUM_PATTERN   32

typedef struct {
  filtering_rule rule;

#ifdef CONFIG_TEXTSEARCH
  struct ts_config *pattern[MAX_NUM_PATTERN];
#endif
  struct list_head list;

  /* Plugin action */
  void *plugin_data_ptr; /* ptr to a *continuous* memory area allocated by the plugin */
} sw_filtering_rule_element;

typedef struct {
  hw_filtering_rule rule;
  struct list_head list;
} hw_filtering_rule_element;

struct parse_buffer {
  void      *mem;
  u_int16_t  mem_len;
};

/* **************************************** */

/* Plugins */
/* Execute an action (e.g. update rule stats) */
typedef int (*plugin_handle_skb)(struct pf_ring_socket *pfr,
				 sw_filtering_rule_element *rule,       /* In case the match is on the list */
				 sw_filtering_hash_bucket *hash_bucket, /* In case the match is on the hash */
				 struct pfring_pkthdr *hdr,
				 struct sk_buff *skb, int displ,
				 u_int16_t filter_plugin_id,
				 struct parse_buffer **filter_rule_memory_storage,
				 rule_action_behaviour *behaviour);
/* Return 1/0 in case of match/no match for the given skb */
typedef int (*plugin_filter_skb)(struct pf_ring_socket *pfr,
				 sw_filtering_rule_element *rule,
				 struct pfring_pkthdr *hdr,
				 struct sk_buff *skb, int displ,
				 struct parse_buffer **filter_rule_memory_storage);
/* Get stats about the rule */
typedef int (*plugin_get_stats)(struct pf_ring_socket *pfr,
				sw_filtering_rule_element *rule,
				sw_filtering_hash_bucket  *hash_bucket,
				u_char* stats_buffer, u_int stats_buffer_len);

/* Check the expiration status. Return 1 if the rule must be removed, 0 otherwise. */
typedef int (*plugin_purge_idle)(struct pf_ring_socket *pfr,
				 sw_filtering_rule_element *rule,
				 sw_filtering_hash_bucket  *hash_bucket,
				 u_int16_t rule_inactivity);

/* Build a new rule when forward_packet_add_rule_and_stop_rule_evaluation is specified
   return 0 in case of success, an error code (< 0) otherwise.
   Rule memory (sw_filtering_rule_element or sw_filtering_hash_bucket) must be allocated 
   by the plugin, the non-NULL rule will be added. */
typedef int (*plugin_add_rule)(sw_filtering_rule_element *rule,
			       struct pfring_pkthdr *hdr,
			       u_int16_t new_rule_element_id, /* next free rule id */
			       sw_filtering_rule_element **new_rule_element,
			       sw_filtering_hash_bucket **new_hash_bucket,
			       u_int16_t filter_plugin_id,
			       struct parse_buffer **filter_rule_memory_storage);
/* Build an hash rule or return the wildcard rule id when forward_packet_del_rule_and_stop_rule_evaluation 
   is specified. Return values: 0 - no action, 1 - remove hash rule, 2 - remove wildcard rule, 3 - remove both,
   an error code (< 0) otherwise. */
typedef int (*plugin_del_rule)(sw_filtering_rule_element *rule,
			       struct pfring_pkthdr *hdr,
			       u_int16_t *zombie_rule_element_id,
			       sw_filtering_hash_bucket *zombie_hash_bucket,
			       u_int16_t filter_plugin_id,
			       struct parse_buffer **filter_rule_memory_storage);

typedef void (*plugin_register)(u_int8_t register_plugin);

/* Called when a rule is removed */
typedef void (*plugin_free_rule_mem)(sw_filtering_rule_element *rule);

/* Called when a ring is disposed */
typedef void (*plugin_free_ring_mem)(sw_filtering_rule_element *rule);

typedef int (*copy_raw_data_2ring)(struct pf_ring_socket *pfr,
				   struct pfring_pkthdr *dummy_hdr,
				   void *raw_data, uint raw_data_len);

/* Kernel packet poller */
typedef int (*kernel_packet_start)(struct pf_ring_socket *pfr, copy_raw_data_2ring raw_copier);
typedef void (*kernel_packet_term)(struct pf_ring_socket *pfr);
typedef void (*kernel_packet_reader)(struct pf_ring_socket *pfr, struct sk_buff *skb,
				     u_int8_t channel_id, struct pfring_pkthdr *hdr, int displ);

struct pfring_plugin_registration {
  u_int16_t plugin_id;
  char name[16];          /* Unique plugin name (e.g. sip, udp) */
  char description[64];   /* Short plugin description */

  plugin_filter_skb    pfring_plugin_filter_skb; /* Filter skb: 1=match, 0=no match */
  plugin_handle_skb    pfring_plugin_handle_skb;
  plugin_get_stats     pfring_plugin_get_stats;
  plugin_purge_idle    pfring_plugin_purge_idle;
  plugin_free_rule_mem pfring_plugin_free_rule_mem;
  plugin_free_ring_mem pfring_plugin_free_ring_mem;
  plugin_add_rule      pfring_plugin_add_rule;
  plugin_del_rule      pfring_plugin_del_rule;
  plugin_register      pfring_plugin_register;

  /* ************** */

  kernel_packet_start  pfring_packet_start;
  kernel_packet_reader pfring_packet_reader;
  kernel_packet_term   pfring_packet_term;
};

typedef int   (*register_pfring_plugin)(struct pfring_plugin_registration *reg);
typedef int   (*unregister_pfring_plugin)(u_int16_t pfring_plugin_id);
typedef u_int (*read_device_pfring_free_slots)(int ifindex);
typedef void  (*handle_ring_dna_device)(dna_device_operation operation,
					dna_version version,
					mem_ring_info *rx_info,
					mem_ring_info *tx_info,
					unsigned long *rx_packet_memory,
					void          *rx_descr_packet_memory,
					unsigned long *tx_packet_memory,
					void          *tx_descr_packet_memory,
					void          *phys_card_memory,
					u_int          phys_card_memory_len,
					u_int channel_id,
					struct net_device *netdev,
					struct device *hwdev,
					dna_device_model device_model,
					u_char *device_address,
					wait_queue_head_t *packet_waitqueue,
					u_int8_t *interrupt_received,
					void *adapter_ptr,
					dna_wait_packet wait_packet_function_ptr,
					dna_device_notify dev_notify_function_ptr);
typedef u_int8_t (*pfring_tx_pkt)(void* private_data, char *pkt, u_int pkt_len);

extern register_pfring_plugin get_register_pfring_plugin(void);
extern unregister_pfring_plugin get_unregister_pfring_plugin(void);
extern read_device_pfring_free_slots get_read_device_pfring_free_slots(void);

extern void set_register_pfring_plugin(register_pfring_plugin the_handler);
extern void set_unregister_pfring_plugin(unregister_pfring_plugin the_handler);
extern void set_read_device_pfring_free_slots(read_device_pfring_free_slots the_handler);

extern int do_register_pfring_plugin(struct pfring_plugin_registration *reg);
extern int do_unregister_pfring_plugin(u_int16_t pfring_plugin_id);
extern int do_read_device_pfring_free_slots(int deviceidx);

extern handle_ring_dna_device get_ring_dna_device_handler(void);
extern void set_ring_dna_device_handler(handle_ring_dna_device
					the_dna_device_handler);
extern void do_ring_dna_device_handler(dna_device_operation operation,
				       mem_ring_info *rx_info,
				       mem_ring_info *tx_info,
			 	       unsigned long *rx_packet_memory,
				       void          *rx_descr_packet_memory,
				       unsigned long *tx_packet_memory,
				       void          *tx_descr_packet_memory,
				       void          *phys_card_memory,
				       u_int          phys_card_memory_len,
				       u_int channel_id,
				       struct net_device *netdev,
				       struct device *hwdev,
				       dna_device_model device_model,
				       u_char *device_address,
				       wait_queue_head_t * packet_waitqueue,
				       u_int8_t * interrupt_received,
				       void *adapter_ptr,
				       dna_wait_packet wait_packet_function_ptr,
				       dna_device_notify dev_notify_function_ptr);

typedef int (*handle_ring_skb)(struct sk_buff *skb, u_char recv_packet,
			       u_char real_skb, u_int32_t channel_id,
			       u_int32_t num_rx_channels);
typedef int (*handle_ring_buffer)(struct net_device *dev,
				  char *data, int len);
typedef int (*handle_add_hdr_to_ring)(struct pf_ring_socket *pfr,
				      u_int8_t real_skb,
				      struct pfring_pkthdr *hdr);

/* Hack to jump from a device directly to PF_RING */
struct pfring_hooks {
  u_int32_t magic; /*
		     It should be set to PF_RING
		     and is MUST be the first one on this struct
		   */
  unsigned int *transparent_mode;
  void *rx_private_data, *tx_private_data;
  handle_ring_skb ring_handler;
  handle_ring_buffer buffer_ring_handler;
  handle_add_hdr_to_ring buffer_add_hdr_to_ring;
  register_pfring_plugin pfring_registration;
  unregister_pfring_plugin pfring_unregistration;
  handle_ring_dna_device ring_dna_device_handler;
  read_device_pfring_free_slots pfring_free_device_slots;
  pfring_tx_pkt pfring_send_packet;
};

/* *************************************************************** */

extern void pf_ring_add_module_dependency(void);

#ifdef PF_RING_PLUGIN
static struct pfring_plugin_registration plugin_reg;
static struct list_head plugin_registered_devices_list;
static u_int16_t pfring_plugin_id = 0;

int add_plugin_to_device_list(struct net_device *dev) {
  ring_device_element *dev_ptr;

  if ((dev_ptr = kmalloc(sizeof(ring_device_element),
			 GFP_KERNEL)) == NULL)
    return (-ENOMEM);

  INIT_LIST_HEAD(&dev_ptr->device_list);
  dev_ptr->dev = dev;

  list_add(&dev_ptr->device_list, &plugin_registered_devices_list);

  return(0);
}

void remove_plugin_from_device_list(struct net_device *dev) {
  struct list_head *ptr, *tmp_ptr;
  struct pfring_hooks* hook = (struct pfring_hooks*)dev->pfring_ptr;

  if(hook && (hook->magic == PF_RING)) {
    hook->pfring_unregistration(pfring_plugin_id);
  }

  list_for_each_safe(ptr, tmp_ptr, &plugin_registered_devices_list) {
    ring_device_element *dev_ptr;

    dev_ptr = list_entry(ptr, ring_device_element, device_list);
    if(dev_ptr->dev == dev) {
      list_del(ptr);
      kfree(dev_ptr);
      break;
    }
  }
}

static int ring_plugin_notifier(struct notifier_block *this, unsigned long msg, void *data)
{
  struct net_device *dev = data;
  struct pfring_hooks *hook;

  switch(msg) {
  case NETDEV_REGISTER:
    hook = (struct pfring_hooks*)dev->pfring_ptr;
    if(hook && (hook->magic == PF_RING)) {
      hook->pfring_registration(&plugin_reg);
      add_plugin_to_device_list(dev);
    }
    break;

  case NETDEV_UNREGISTER:
    hook = (struct pfring_hooks*)dev->pfring_ptr;
    if(hook && (hook->magic == PF_RING)) {
      hook->pfring_unregistration(pfring_plugin_id);
    }
    break;
  }

  return NOTIFY_DONE;
}

static struct notifier_block ring_netdev_notifier = {
  .notifier_call = ring_plugin_notifier,
};

static void register_plugin(struct pfring_plugin_registration *reg_info) {
  INIT_LIST_HEAD(&plugin_registered_devices_list);
  memcpy(&plugin_reg, reg_info, sizeof(struct pfring_plugin_registration));
  pfring_plugin_id = reg_info->plugin_id;

  /*
    Trick to push the kernel to call the above ring_plugin_notifier()
    and this to register the plugin in PF_RING
  */
  register_netdevice_notifier(&ring_netdev_notifier);
}

static void unregister_plugin(int pfring_plugin_id) {
  struct list_head *ptr, *tmp_ptr;

  /*
    Trick to push the kernel to call the above ring_plugin_notifier()
    and this to register the plugin in PF_RING
  */
  unregister_netdevice_notifier(&ring_netdev_notifier);

  list_for_each_safe(ptr, tmp_ptr, &plugin_registered_devices_list) {
    ring_device_element *dev_ptr;
    struct pfring_hooks *hook;

    dev_ptr = list_entry(ptr, ring_device_element, device_list);
    hook = (struct pfring_hooks*)dev_ptr->dev->pfring_ptr;
    if(hook && (hook->magic == PF_RING)) {
      printk("[PF_RING] Unregister plugin_id %d for %s\n",
	     pfring_plugin_id, dev_ptr->dev->name);
      hook->pfring_unregistration(pfring_plugin_id);
      list_del(ptr);
      kfree(dev_ptr);
    }
  }
}

#endif /* PF_RING_PLUGIN */

/* *********************************** */

/* pcap header */
struct pcaplike_file_header {
  int32_t magic;
  u_int16_t version_major, version_minor;
  int32_t thiszone;     /* gmt to local correction */
  u_int32_t sigfigs;    /* accuracy of timestamps */
  u_int32_t snaplen;    /* max length saved portion of each pkt */
  u_int32_t linktype;   /* data link type (LINKTYPE_*) */
};

struct pcaplike_timeval {
  u_int32_t tv_sec, tv_usec;
};

struct pcaplike_pkthdr {
  struct pcaplike_timeval ts;  /* time stamp */
  u_int32_t caplen;            /* length of portion present */
  u_int32_t len;               /* length this packet (off wire) */
};

#endif /* __KERNEL__  */

/* *********************************** */

struct vpfring_eventfd_info {
  u_int32_t id; /* an id (unused now, but maybe useful in future) */
  int32_t fd;
};

/* Values for the FlowSlotInfo.vpfring_guest_flags bitmap */
#define VPFRING_GUEST_NO_INTERRUPT 1

/* Host event IDs */
#define VPFRING_HOST_EVENT_RX_INT 0

/* *********************************** */

/* bit masks for the FlowSlotInfo.userspace_ring_flags bitmap */
#define USERSPACE_RING_NO_INTERRUPT 1

#endif /* __RING_H */
