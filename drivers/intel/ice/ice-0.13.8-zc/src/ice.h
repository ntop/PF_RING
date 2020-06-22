/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _ICE_H_
#define _ICE_H_

#include "kcompat.h"
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/netdevice.h>
#include <linux/compiler.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/cpumask.h>
#include <linux/rtnetlink.h>
#include <linux/if_vlan.h>
#ifdef HAVE_NETDEV_SB_DEV
#include <linux/if_macvlan.h>
#endif /* HAVE_NETDEV_SB_DEV */
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/aer.h>
#include <linux/interrupt.h>
#include <linux/ethtool.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/bitmap.h>
#include <linux/log2.h>
#include <linux/ip.h>
#include <linux/sctp.h>
#include <linux/ipv6.h>
#include <linux/pkt_sched.h>
#include <linux/if_bridge.h>
#include <linux/string.h>
#include <linux/ctype.h>
#ifdef HAVE_XDP_SUPPORT
#include <linux/bpf.h>
#include <linux/filter.h>
#endif /* HAVE_XDP_SUPPORT */
#ifdef HAVE_AF_XDP_ZC_SUPPORT
#include <net/xdp_sock.h>
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
#include <net/ipv6.h>
#include "ice_devids.h"
#include "ice_type.h"
#include "ice_txrx.h"
#include "ice_dcb.h"
#include "ice_switch.h"
#include "ice_common.h"
#include "ice_flow.h"
#include "ice_sched.h"
#include <linux/mfd/core.h>
#include <linux/idr.h>
#include "ice_idc_int.h"
#include "virtchnl.h"
#include "ice_virtchnl_pf.h"
#include "ice_sriov.h"
#include "ice_fdir.h"
#ifdef HAVE_AF_XDP_ZC_SUPPORT
#include "ice_xsk.h"
#endif /* HAVE_AF_XDP_ZC_SUPPORT */

#if defined(HAVE_VXLAN_RX_OFFLOAD) || defined(HAVE_VXLAN_TYPE)
#if IS_ENABLED(CONFIG_VXLAN)
#include <net/vxlan.h>
#endif
#endif /* HAVE_VXLAN_RX_OFFLOAD || HAVE_VXLAN_TYPE */
#ifdef HAVE_GRE_ENCAP_OFFLOAD
#include <net/gre.h>
#endif /* HAVE_GRE_ENCAP_OFFLOAD */
#if defined(HAVE_GENEVE_RX_OFFLOAD) || defined(HAVE_GENEVE_TYPE)
#if IS_ENABLED(CONFIG_GENEVE)
#include <net/geneve.h>
#endif
#endif /* HAVE_GENEVE_RX_OFFLOAD || HAVE_GENEVE_TYPE */
#ifdef HAVE_UDP_ENC_RX_OFFLOAD
#include <net/udp_tunnel.h>
#endif
#ifdef NETIF_F_HW_TC
#include <net/pkt_cls.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_gact.h>
#endif /* NETIF_F_HW_TC */
#include <net/ip.h>
#include <linux/cpu_rmap.h>
#include <linux/atomic.h>
#include <linux/jiffies.h>
#include "ice_arfs.h"

extern const char ice_drv_ver[];
#define ICE_BAR0		0
#define ICE_BAR3		3
#ifdef CONFIG_DEBUG_FS
#define ICE_MAX_CSR_SPACE	(8 * 1024 * 1024 - 64 * 1024)
#endif /* CONFIG_DEBUG_FS */
#define ICE_REQ_DESC_MULTIPLE	32
#define ICE_MIN_NUM_DESC	64
#define ICE_MAX_NUM_DESC	8160
#define ICE_DFLT_MIN_RX_DESC	512
#define ICE_DFLT_NUM_TX_DESC	256
#define ICE_DFLT_NUM_RX_DESC	2048

#define ICE_DFLT_TXQ_VMDQ_VSI	1
#define ICE_DFLT_RXQ_VMDQ_VSI	1
#define ICE_DFLT_VEC_VMDQ_VSI	1
#define ICE_MAX_NUM_VMDQ_VSI	16
#define ICE_MAX_TXQ_VMDQ_VSI	4
#define ICE_MAX_RXQ_VMDQ_VSI	4
#ifdef HAVE_NETDEV_SB_DEV
#define ICE_MAX_MACVLANS	64
#endif
#define ICE_DFLT_TRAFFIC_CLASS	BIT(0)
#define ICE_INT_NAME_STR_LEN	(IFNAMSIZ + 16)
#define ICE_AQ_LEN		64
#define ICE_MBXSQ_LEN		64
#define ICE_MBXRQ_LEN		1024
#define ICE_MIN_MSIX		2
#define ICE_FDIR_MSIX		1
#define ICE_NO_VSI		0xffff
#define ICE_VSI_MAP_CONTIG	0
#define ICE_VSI_MAP_SCATTER	1
#define ICE_MAX_SCATTER_TXQS	16
#define ICE_MAX_SCATTER_RXQS	16
#define ICE_Q_WAIT_RETRY_LIMIT	10
#define ICE_Q_WAIT_MAX_RETRY	(5 * ICE_Q_WAIT_RETRY_LIMIT)
#define ICE_MAX_LG_RSS_QS	256
#define ICE_MAX_MEDIUM_RSS_QS	64
#define ICE_MAX_SMALL_RSS_QS	16
#define ICE_RES_VALID_BIT	0x8000
#define ICE_RES_MISC_VEC_ID	(ICE_RES_VALID_BIT - 1)
#define ICE_RDMA_NUM_VECS	4
#define ICE_RES_RDMA_VEC_ID	(ICE_RES_MISC_VEC_ID - 1)
#define ICE_INVAL_Q_INDEX	0xffff
#define ICE_INVAL_VFID		256

#define ICE_MAX_TXQS_PER_TC		8
#define ICE_MAX_RDMA_QSET_PER_TC	1

#define ICE_CHNL_START_TC		1
#define ICE_CHNL_MAX_TC			16

#define ICE_MAX_RESET_WAIT		20

#define ICE_VSIQF_HKEY_ARRAY_SIZE	((VSIQF_HKEY_MAX_INDEX + 1) *	4)

#define ICE_DFLT_NETIF_M (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)

#define ICE_MAX_MTU	(ICE_AQ_SET_MAC_FRAME_SIZE_MAX - ICE_ETH_PKT_HDR_PAD)

#define ICE_UP_TABLE_TRANSLATE(val, i) \
		(((val) << ICE_AQ_VSI_UP_TABLE_UP##i##_S) & \
		  ICE_AQ_VSI_UP_TABLE_UP##i##_M)

#define ICE_TX_DESC(R, i) (&(((struct ice_tx_desc *)((R)->desc))[i]))
#define ICE_RX_DESC(R, i) (&(((union ice_32b_rx_flex_desc *)((R)->desc))[i]))
#define ICE_TX_CTX_DESC(R, i) (&(((struct ice_tx_ctx_desc *)((R)->desc))[i]))
#define ICE_TX_FDIRDESC(R, i) (&(((struct ice_fltr_desc *)((R)->desc))[i]))
/* Default ports for tunnels when operating in Basic mode */
#define ICE_DFLT_PORT_VXLAN		4789
#define ICE_DFLT_PORT_GENEVE		6081

/* Minimum BW limit is 500 Kbps for any scheduler node */
#define ICE_MIN_BW_LIMIT		500
/* User can specify BW in either Kbit/Mbit/Gbit and OS converts it in bytes.
 * use it to convert user specified BW limit into Kbps
 */
#define ICE_BW_KBPS_DIVISOR		125

/* Macro for each VSI in a PF */
#define ice_for_each_vsi(pf, i) \
	for ((i) = 0; (i) < (pf)->num_alloc_vsi; (i)++)

/* Macros for each Tx/Rx ring in a VSI */
#define ice_for_each_txq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_txq; (i)++)

#define ice_for_each_rxq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_rxq; (i)++)

/* Macros for each allocated Tx/Rx ring whether used or not in a VSI */
#define ice_for_each_alloc_txq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->alloc_txq; (i)++)

#define ice_for_each_alloc_rxq(vsi, i) \
	for ((i) = 0; (i) < (vsi)->alloc_rxq; (i)++)

#define ice_for_each_q_vector(vsi, i) \
	for ((i) = 0; (i) < (vsi)->num_q_vectors; (i)++)

#define ice_for_each_chnl_tc(i)	\
	for ((i) = ICE_CHNL_START_TC; (i) < ICE_CHNL_MAX_TC; (i)++)

#define ICE_UCAST_PROMISC_BITS (ICE_PROMISC_UCAST_TX | ICE_PROMISC_MCAST_TX | \
				ICE_PROMISC_UCAST_RX | ICE_PROMISC_MCAST_RX)

#define ICE_UCAST_VLAN_PROMISC_BITS (ICE_PROMISC_UCAST_TX | \
				     ICE_PROMISC_MCAST_TX | \
				     ICE_PROMISC_UCAST_RX | \
				     ICE_PROMISC_MCAST_RX | \
				     ICE_PROMISC_VLAN_TX  | \
				     ICE_PROMISC_VLAN_RX)

#define ICE_MCAST_PROMISC_BITS (ICE_PROMISC_MCAST_TX | ICE_PROMISC_MCAST_RX)

#define ICE_MCAST_VLAN_PROMISC_BITS (ICE_PROMISC_MCAST_TX | \
				     ICE_PROMISC_MCAST_RX | \
				     ICE_PROMISC_VLAN_TX  | \
				     ICE_PROMISC_VLAN_RX)

#define ice_pf_to_dev(pf) (&((pf)->pdev->dev))


enum ice_channel_fltr_type {
	ICE_CHNL_FLTR_TYPE_INVALID,
	ICE_CHNL_FLTR_TYPE_SRC_PORT,
	ICE_CHNL_FLTR_TYPE_DEST_PORT,
	ICE_CHNL_FLTR_TYPE_SRC_DEST_PORT, /* for future use cases */
	ICE_CHNL_FLTR_TYPE_TENANT_ID,
	ICE_CHNL_FLTR_TYPE_LAST /* must be last */
};

struct ice_channel {
	struct list_head list;
	u8 type;
	u8 ch_type; /* NVMe over TCP, AF_XDP, UDP based, etc.. */
	u16 sw_id;
	u16 base_q;
	u16 num_rxq;
	u16 num_txq;
	u16 vsi_num;
	u8 ena_tc;
	struct ice_aqc_vsi_props info;
	u64 max_tx_rate;
	u64 min_tx_rate;
	atomic_t num_sb_fltr;
#ifdef ADQ_PERF
	/* counter index when side-band FD is used */
	u32 fd_cnt_index;
	/* queue used to setup inline-FD */
	atomic_t fd_queue;
	/* packets services thru' inline-FD filter */
	u64 fd_pkt_cnt;
#endif /* ADQ_PERF */
	enum ice_channel_fltr_type fltr_type;
	struct ice_vsi *ch_vsi;
};

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
/* To convert BPS BW parameter into Mbps*/
#define ICE_BW_MBIT_PS_DIVISOR	125000 /* rate / (1000000 / 8) Mbps */
#define ICE_MAX_MQPRIO_TCF		8 /*Max number of Traffic Classifiers*/

struct ice_qreg_info {
	u16 qoffset;
	u16 qcount;
	u8 netdev_tc;	/* Netdev TC index if netdev associated */
};

struct ice_tcf_qreg_cfg {
	u8 num_qreg; /* number of Traffic classifier*/
	u8 ena_tcf; /* Rx map */
	struct ice_qreg_info qreg_info[ICE_MAX_MQPRIO_TCF];
};
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

struct ice_txq_meta {
	u32 q_teid;	/* Tx-scheduler element identifier */
	u16 q_id;	/* Entry in VSI's txq_map bitmap */
	u16 q_handle;	/* Relative index of Tx queue within TC */
	u16 vsi_idx;	/* VSI index that Tx queue belongs to */
	u8 tc;		/* TC number that Tx queue belongs to */
};

struct ice_tc_info {
	u16 qoffset;
	u16 qcount_tx;
	u16 qcount_rx;
	u8 netdev_tc;
};

struct ice_tc_cfg {
	u8 numtc; /* Total number of enabled TCs */
	u16 ena_tc; /* Tx map */
	struct ice_tc_info tc_info[ICE_MAX_TRAFFIC_CLASS];
};

struct ice_res_tracker {
	u16 num_entries;
	u16 end;
	u16 list[1];
};

struct ice_qs_cfg {
	struct mutex *qs_mutex;  /* will be assigned to &pf->avail_q_mutex */
	unsigned long *pf_map;
	unsigned long pf_map_size;
	unsigned int q_count;
	unsigned int scatter_count;
	u16 *vsi_map;
	u16 vsi_map_offset;
	u8 mapping_mode;
};

struct ice_sw {
	struct ice_pf *pf;
	u16 sw_id;		/* switch ID for this switch */
	u16 bridge_mode;	/* VEB/VEPA/Port Virtualizer */
	struct ice_vsi *dflt_vsi;	/* default VSI for this switch */
	u8 dflt_vsi_ena:1;	/* true if above dflt_vsi is enabled */
	u16 stats_id;			/* stats counter for this switch */
	u16 flags;
	struct ice_eth_stats stats;
	struct ice_eth_stats stats_prev;
	struct ice_veb_up_stats veb_stats;
	struct ice_veb_up_stats veb_stats_prev;
	u8 stat_offsets_loaded:1;
};

enum ice_state {
	__ICE_TESTING,
	__ICE_DOWN,
	__ICE_NEEDS_RESTART,
	__ICE_PREPARED_FOR_RESET,	/* set by driver when prepared */
	__ICE_RESET_OICR_RECV,		/* set by driver after rcv reset OICR */
	__ICE_DCBNL_DEVRESET,		/* set by dcbnl devreset */
	__ICE_PFR_REQ,			/* set by driver and peers */
	__ICE_CORER_REQ,		/* set by driver and peers */
	__ICE_GLOBR_REQ,		/* set by driver and peers */
	__ICE_CORER_RECV,		/* set by OICR handler */
	__ICE_GLOBR_RECV,		/* set by OICR handler */
	__ICE_EMPR_RECV,		/* set by OICR handler */
	__ICE_SUSPENDED,		/* set on module remove path */
	__ICE_RESET_FAILED,		/* set by reset/rebuild */
	__ICE_RECOVERY_MODE,		/* set when recovery mode is detected */
	__ICE_PREPPED_RECOVERY_MODE,	/* set on recovery mode transition */
	/* When checking for the PF to be in a nominal operating state, the
	 * bits that are grouped at the beginning of the list need to be
	 * checked. Bits occurring before __ICE_STATE_NOMINAL_CHECK_BITS will
	 * be checked. If you need to add a bit into consideration for nominal
	 * operating state, it must be added before
	 * __ICE_STATE_NOMINAL_CHECK_BITS. Do not move this entry's position
	 * without appropriate consideration.
	 */
	__ICE_STATE_NOMINAL_CHECK_BITS,
	__ICE_ADMINQ_EVENT_PENDING,
	__ICE_MAILBOXQ_EVENT_PENDING,
	__ICE_MDD_EVENT_PENDING,
	__ICE_VFLR_EVENT_PENDING,
	__ICE_FLTR_OVERFLOW_PROMISC,
	__ICE_VF_DIS,
	__ICE_CFG_BUSY,
	__ICE_SERVICE_SCHED,
	__ICE_SERVICE_DIS,
	__ICE_FD_FLUSH_REQ,
	__ICE_OICR_INTR_DIS,		/* Global OICR interrupt disabled */
	__ICE_BAD_EEPROM,
	__ICE_MDD_VF_PRINT_PENDING,	/* set when MDD event handle */
	__ICE_STATE_NBITS		/* must be last */
};

enum ice_vsi_flags {
	ICE_VSI_FLAG_UMAC_FLTR_CHANGED,
	ICE_VSI_FLAG_MMAC_FLTR_CHANGED,
	ICE_VSI_FLAG_VLAN_FLTR_CHANGED,
	ICE_VSI_FLAG_PROMISC_CHANGED,
	ICE_VSI_FLAG_NBITS		/* must be last */
};

enum ice_chnl_feature {
#ifdef ADQ_PERF
	ICE_CHNL_FEATURE_FD_ENA, /* for side-band flow-director */
	ICE_CHNL_FEATURE_INLINE_FD_ENA, /* for inline flow-director */
#endif /* ADQ_PERF */
	/* for pkt based inspection optimization - related to SW triggered
	 * interrupt from napi_poll for channel enabled vector
	 */
	ICE_CHNL_FEATURE_PKT_INSPECT_OPT_ENA,
	ICE_CHNL_FEATURE_NBITS		/* must be last */
};

#ifdef HAVE_TC_SETUP_CLSFLOWER
#define ICE_TC_FLWR_FIELD_DST_MAC		0x01
#define ICE_TC_FLWR_FIELD_SRC_MAC		0x02
#define ICE_TC_FLWR_FIELD_VLAN			0x04
#define ICE_TC_FLWR_FIELD_DEST_IPV4		0x08
#define ICE_TC_FLWR_FIELD_SRC_IPV4		0x10
#define ICE_TC_FLWR_FIELD_DEST_IPV6		0x20
#define ICE_TC_FLWR_FIELD_SRC_IPV6		0x40
#define ICE_TC_FLWR_FIELD_DEST_L4_PORT		0x80
#define ICE_TC_FLWR_FIELD_SRC_L4_PORT		0x100
#define ICE_TC_FLWR_FIELD_TENANT_ID		0x200
#define ICE_TC_FLWR_FIELD_ENC_DEST_IPV4		0x400
#define ICE_TC_FLWR_FIELD_ENC_SRC_IPV4		0x800
#define ICE_TC_FLWR_FIELD_ENC_DEST_IPV6		0x1000
#define ICE_TC_FLWR_FIELD_ENC_SRC_IPV6		0x2000
#define ICE_TC_FLWR_FIELD_ENC_DEST_L4_PORT	0x4000
#define ICE_TC_FLWR_FIELD_ENC_SRC_L4_PORT	0x8000
#define ICE_TC_FLWR_FIELD_ENC_DST_MAC		0x10000

/* TC flower supported filter match */
#define ICE_TC_FLWR_FLTR_FLAGS_DST_MAC		ICE_TC_FLWR_FIELD_DST_MAC
#define ICE_TC_FLWR_FLTR_FLAGS_VLAN		ICE_TC_FLWR_FIELD_VLAN
#define ICE_TC_FLWR_FLTR_FLAGS_DST_MAC_VLAN	(ICE_TC_FLWR_FIELD_DST_MAC | \
						 ICE_TC_FLWR_FIELD_VLAN)
#define ICE_TC_FLWR_FLTR_FLAGS_IPV4_DST_PORT	(ICE_TC_FLWR_FIELD_DEST_IPV4 | \
						 ICE_TC_FLWR_FIELD_DEST_L4_PORT)
#define ICE_TC_FLWR_FLTR_FLAGS_IPV4_SRC_PORT	(ICE_TC_FLWR_FIELD_DEST_IPV4 | \
						 ICE_TC_FLWR_FIELD_SRC_L4_PORT)
#define ICE_TC_FLWR_FLTR_FLAGS_IPV6_DST_PORT	(ICE_TC_FLWR_FIELD_DEST_IPV6 | \
						 ICE_TC_FLWR_FIELD_DEST_L4_PORT)
#define ICE_TC_FLWR_FLTR_FLAGS_IPV6_SRC_PORT	(ICE_TC_FLWR_FIELD_DEST_IPV6 | \
						 ICE_TC_FLWR_FIELD_SRC_L4_PORT)

#define ICE_TC_FLOWER_MASK_32	0xFFFFFFFF
#define ICE_TC_FLOWER_MASK_16	0xFFFF
#define ICE_TC_FLOWER_VNI_MAX	0xFFFFFFU

#ifdef HAVE_TC_INDIR_BLOCK
struct ice_indr_block_priv {
	struct net_device *netdev;
	struct ice_netdev_priv *np;
	struct list_head list;
};
#endif /* HAVE_TC_INDIR_BLOCK */

struct ice_tc_flower_action {
	u32 tc_class;
	enum ice_sw_fwd_act_type fltr_act;
};

struct ice_tc_flower_vlan_hdrs {
	__be16 vlan_id; /* Only last 12 bits valid */
#ifdef HAVE_FLOW_DISSECTOR_VLAN_PRIO
	u16 vlan_prio; /* Only last 3 bits valid (valid values: 0..7) */
#endif
};

struct ice_tc_flower_lyr_2_4_hdrs {
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	struct ice_tc_flower_vlan_hdrs vlan_hdr;
	__be16 dst_port;
	__be16 src_port;
	union {
		struct {
			struct in_addr dst_ip;
			struct in_addr src_ip;
		} v4;
		struct {
			struct in6_addr dst_ip6;
			struct in6_addr src_ip6;
		} v6;
	} ip;
#define dst_ipv6	ip.v6.dst_ip6.s6_addr32
#define dst_ipv6_addr	ip.v6.dst_ip6.s6_addr
#define src_ipv6	ip.v6.src_ip6.s6_addr32
#define src_ipv6_addr	ip.v6.src_ip6.s6_addr
#define dst_ipv4	ip.v4.dst_ip.s_addr
#define src_ipv4	ip.v4.src_ip.s_addr
	u16 n_proto;    /* Ethernet Protocol */
	u8 ip_proto;    /* IPPROTO value */
	u8 tos;
	u8 ttl;

};

struct ice_tc_flower_fltr {
	struct hlist_node tc_flower_node;

	/* cookie becomes filter_rule_id if rule is added successfully */
	unsigned long cookie;

	/* add_adv_rule returns information like recipe ID, rule_id. Store
	 * those values since they are needed to remove advanced rule
	 */
	u16 rid;
	u16 rule_id;
	/* this could be queue/vsi_idx (sw handle)/queue_group, depending upon
	 * destination type
	 */
	u16 dest_id;
	/* if dest_id is vsi_idx, then need to store destination VSI ptr */
	struct ice_vsi *dest_vsi;

	/* Parsed TC flower configuration params */
	struct ice_tc_flower_lyr_2_4_hdrs outer_headers;
	struct ice_tc_flower_lyr_2_4_hdrs inner_headers;
	u16 vsi_num;
	__be32 tenant_id;
	u32 flags;
#define ICE_TC_FLWR_TNL_TYPE_NONE        0xff
	u8 tunnel_type;
	struct ice_tc_flower_action	action;
};
#endif /* HAVE_TC_SETUP_CLSFLOWER */

#ifdef ADQ_PERF
/* This is to be used only when channels are configured, to track state
 * at PF level, whether it should use RSS or inline flow-director and this
 * state gets set/reset appropriately as the HW flow-director table becomes
 * full/not-full
 */
enum ice_advanced_state_t {
	ICE_SWITCH_TO_RSS,
	ICE_ADVANCED_STATE_LAST, /* this must be last */
};
#endif /* ADQ_PERF */

/* struct that defines a VSI, associated with a dev */
struct ice_vsi {
	struct net_device *netdev;
	struct ice_sw *vsw;		 /* switch this VSI is on */
	struct ice_pf *back;		 /* back pointer to PF */
	struct ice_port_info *port_info; /* back pointer to port_info */
	struct ice_ring **rx_rings;	 /* Rx ring array */
	struct ice_ring **tx_rings;	 /* Tx ring array */
#ifdef HAVE_NETDEV_SB_DEV
	/* Initial VSI tx_rings array when L2 offload is off */
	struct ice_ring **base_tx_rings;
#endif /* HAVE_NETDEV_SB_DEV */
	struct ice_q_vector **q_vectors; /* q_vector array */

	irqreturn_t (*irq_handler)(int irq, void *data);

	u64 tx_linearize;
	DECLARE_BITMAP(state, __ICE_STATE_NBITS);
	DECLARE_BITMAP(flags, ICE_VSI_FLAG_NBITS);
	unsigned int current_netdev_flags;
	u32 tx_restart;
	u32 tx_busy;
	u32 rx_buf_failed;
	u32 rx_page_failed;
	int num_q_vectors;
	int base_vector;		/* IRQ base for OS reserved vectors */
	enum ice_vsi_type type;
	u16 vsi_num;			/* HW (absolute) index of this VSI */
	u16 idx;			/* software index in pf->vsi[] */

	s16 vf_id;			/* VF ID for SR-IOV VSIs */

	u16 ethtype;			/* Ethernet protocol for pause frame */
	u16 num_gfltr;
	u16 num_bfltr;
	u16 cntr_gfltr;
	u16 cntr_bfltr;

	/* RSS config */
	u16 rss_table_size;	/* HW RSS table size */
	u16 rss_size;		/* Allocated RSS queues */
	u8 *rss_hkey_user;	/* User configured hash keys */
	u8 *rss_lut_user;	/* User configured lookup table entries */
	u8 rss_lut_type;	/* used to configure Get/Set RSS LUT AQ call */

#ifdef CONFIG_RFS_ACCEL
	/* aRFS members only allocated for the PF VSI */
#define ICE_MAX_RFS_FILTERS	0xFFFF
#define ICE_MAX_ARFS_LIST	BIT(10) /* 1024 entries */
#define ICE_ARFS_LST_MASK	(ICE_MAX_ARFS_LIST - 1)
	struct hlist_head *arfs_fltr_list;
	struct ice_arfs_active_fltr_cntrs *arfs_fltr_cntrs;
	spinlock_t arfs_lock;	/* protects aRFS hash table and filter state */
	atomic_t *arfs_last_fltr_id;
#endif /* CONFIG_RFS_ACCEL */

	u16 max_frame;
	u16 rx_buf_len;

	struct ice_aqc_vsi_props info;	 /* VSI properties */

	/* VSI stats */
	struct rtnl_link_stats64 net_stats;
	struct ice_eth_stats eth_stats;
	struct ice_eth_stats eth_stats_prev;

	struct list_head tmp_sync_list;		/* MAC filters to be synced */
	struct list_head tmp_unsync_list;	/* MAC filters to be unsynced */

	u8 irqs_ready:1;
	u8 current_isup:1;		 /* Sync 'link up' logging */
	u8 stat_offsets_loaded:1;
	u8 vlan_ena:1;
	u16 num_vlan;


	/* queue information */
	u8 tx_mapping_mode;		 /* ICE_MAP_MODE_[CONTIG|SCATTER] */
	u8 rx_mapping_mode;		 /* ICE_MAP_MODE_[CONTIG|SCATTER] */
	u16 *txq_map;			 /* index in pf->avail_txqs */
	u16 *rxq_map;			 /* index in pf->avail_rxqs */
	u16 alloc_txq;			 /* Allocated Tx queues */
	u16 num_txq;			 /* Used Tx queues */
	u16 alloc_rxq;			 /* Allocated Rx queues */
	u16 num_rxq;			 /* Used Rx queues */
	u16 req_txq;			 /* User requested Tx queues */
	u16 req_rxq;			 /* User requested Rx queues */
	u16 num_rx_desc;
	u16 num_tx_desc;
	u16 qset_handle[ICE_MAX_TRAFFIC_CLASS];
	struct ice_tc_cfg tc_cfg;
#ifdef HAVE_XDP_SUPPORT
	struct bpf_prog *xdp_prog;
	struct ice_ring **xdp_rings;	 /* XDP ring array */
	u16 num_xdp_txq;		 /* Used XDP queues */
	u8 xdp_mapping_mode;		 /* ICE_MAP_MODE_[CONTIG|SCATTER] */
#endif /* HAVE_XDP_SUPPORT */
#ifdef HAVE_AF_XDP_ZC_SUPPORT
	struct xdp_umem **xsk_umems;
	u16 num_xsk_umems_used;
	u16 num_xsk_umems;
#endif /* HAVE_AF_XDP_ZC_SUPPORT */

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	struct tc_mqprio_qopt_offload mqprio_qopt;/* queue parameters */
	struct ice_tcf_qreg_cfg tcf_qreg_cfg;
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

	/* Channel Specific Fields */
	struct ice_vsi *tc_map_vsi[ICE_CHNL_MAX_TC];
	u16 cnt_q_avail;
	u16 next_base_q;    /* next queue to be used for channel setup */
	struct list_head ch_list;
	u16 num_chnl_rxq;
	u16 num_chnl_txq;
	u16 ch_rss_size;
	u16 num_chnl_fltr;
	/* store away rss size info before configuring ADQ channels so that,
	 * it can be used after tc-qdisc delete, to get back RSS setting as
	 * they were before
	 */
	u16 orig_rss_size;
	u8 vf_adq_tc;	/* traffic class number for VF ADQ VSI */
	/* track various feature bits for channel VSI */
	DECLARE_BITMAP(features, ICE_CHNL_FEATURE_NBITS);
#ifdef ADQ_PERF
#define ICE_TBL_FULL_TIMES             5
	/* how many times transitioned into inline flow-director from RSS */
	u64 cnt_inline_fd_transition;
	/* how many times HW table is flushed */
	u64 cnt_table_flushed;
	/* keeps track, how many times SW detected that HW table remain full
	 * once SW state is SWITCHED_TO_RSS
	 */
	int cnt_tbl_full;

	/* inline_fd_active_cnt is SW based counter which keeps track of active
	 * inline-FD filter entries in table
	 */
	atomic_t inline_fd_active_cnt;
	DECLARE_BITMAP(adv_state, ICE_ADVANCED_STATE_LAST);
#endif /* ADQ_PERF */

	/* this keeps tracks of all enabled TC with and without DCB
	 * and inclusive of ADQ, vsi->mqprio_opt keeps track of queue
	 * information
	 */
	u8 all_numtc;
	u16 all_enatc;

	/* store away TC info, to be used for rebuild logic */
	u8 old_numtc;
	u16 old_ena_tc;

	struct ice_channel *ch;
} ____cacheline_internodealigned_in_smp;

#ifdef ADQ_PERF
enum ice_chnl_vector_state {
	ICE_CHNL_VECTOR_IN_BP,
	ICE_CHNL_VECTOR_PREV_IN_BP,
	ICE_CHNL_VECTOR_ONCE_IN_BP,
	ICE_CHNL_VECTOR_PREV_DATA_PKT_RECV,
	ICE_CHNL_VECTOR_NBITS, /* This must be last */
};

#ifdef ADQ_PERF_COUNTERS
struct ice_q_vector_ch_stats {
	/* following are used as part of managing driver internal
	 * state machine. Only to be used for perf debugging and
	 * it is controlled by module_param : debug_mask
	 */
	u64 in_bp;
	u64 in_int;
	u64 real_int_to_bp;
	u64 real_bp_to_int;
	u64 real_int_to_int;
	u64 real_bp_to_bp;

	/* These counter is used to track real transition of vector from
	 * BUSY_POLL to INTERRUPT based on enhanced logic (using state
	 * machine and control packets).
	 */
	u64 unlikely_cb_to_bp;
	/* This is used to keep track of enabling interrupt from napi_poll
	 * when state machine condition indicated once_in_bp is false
	 */
	u64 once_bp_false;
	u64 num_need_resched_bp_stop;
	u64 num_timeout_bp_stop;
	u64 num_l_c_data_pkt;
	u64 num_l_c_data_pkt1;
	u64 num_sw_intr_timeout; /* track SW INTR from napi_poll */
	u64 num_sw_intr_serv_task; /* track SW INTR from service_task */
	u64 cleaned_any_data_pkt;
	/* Tracking "unlikely_cb_bp and once_in_bp is true" */
	u64 ucb_o_bp;
	/* This keeps track of how many times, bailout when once_in_bp is set,
	 * unlikely_cb_to_bp is set, but pkt based interrupt optimization
	 * is OFF
	 */
	u64 num_no_sw_intr_opt_off;
	/* tracking, how many times WB_ON_ITR is set */
	u64 num_wb_on_itr_set;
};
#endif /* ADQ_PERF_COUNTERS */
#endif /* ADQ_PERF */

/* struct that defines an interrupt vector */
struct ice_q_vector {
	struct ice_vsi *vsi;

	u16 v_idx;			/* index in the vsi->q_vector array. */
	u16 reg_idx;
	u8 num_ring_rx;			/* total number of Rx rings in vector */
	u8 num_ring_tx;			/* total number of Tx rings in vector */
	u8 itr_countdown;		/* when 0 should adjust adaptive ITR */
	/* in usecs, need to use ice_intrl_to_usecs_reg() before writing this
	 * value to the device
	 */
	u8 intrl;

	struct napi_struct napi;

	struct ice_ring_container rx;
	struct ice_ring_container tx;

	cpumask_t affinity_mask;
	struct irq_affinity_notify affinity_notify;

	struct ice_channel *ch;

	char name[ICE_INT_NAME_STR_LEN];
#ifdef ADQ_PERF
	/* This tracks current state of vector, BUSY_POLL or INTR */
#define ICE_CHNL_IN_BP			BIT(ICE_CHNL_VECTOR_IN_BP)
	/* This tracks prev state of vector, BUSY_POLL or INTR */
#define ICE_CHNL_PREV_IN_BP		BIT(ICE_CHNL_VECTOR_PREV_IN_BP)
	/* This tracks state of vector, was the ever in BUSY_POLL. This
	 * state goes to INTT if interrupt are enabled or SW interrupts
	 * are triggered from either service_task or napi_poll
	 */
#define ICE_CHNL_ONCE_IN_BP		BIT(ICE_CHNL_VECTOR_ONCE_IN_BP)
	/* Tracks if previously - were there any data packets received
	 * on per channel enabled vector or not
	 */
#define ICE_CHNL_PREV_DATA_PKT_RECV	BIT(ICE_CHNL_VECTOR_PREV_DATA_PKT_RECV)
	/* it is used to keep track of various states as defined earlier
	 * and those states are used during ADQ performance optimization
	 */
	u8 state_flags;
	/* Used in logic to determine if SW inter is needed or not.
	 * This is used only for channel enabled vector
	 */
	u64 jiffies;
	/* Primarily used in decision making w.r.t using inline flow-director */
	atomic_t inline_fd_cnt;

#ifdef ADQ_PERF_COUNTERS
	struct ice_q_vector_ch_stats ch_stats;
#endif /* ADQ_PERF_COUNTERS */
#endif /* ADQ_PERF */
} ____cacheline_internodealigned_in_smp;

enum ice_pf_flags {
	ICE_FLAG_FLTR_SYNC,
	ICE_FLAG_VMDQ_ENA,
#ifdef HAVE_NETDEV_SB_DEV
	ICE_FLAG_MACVLAN_ENA,
#endif /* HAVE_NETDEV_SB_DEV */
	ICE_FLAG_IWARP_ENA,
	ICE_FLAG_RSS_ENA,
	ICE_FLAG_SRIOV_ENA,
	ICE_FLAG_SRIOV_CAPABLE,
	ICE_FLAG_SRIOV_CHNL_FLTR_AS_UDP,
	ICE_FLAG_DCB_CAPABLE,
	ICE_FLAG_DCB_ENA,
	ICE_FLAG_FD_ENA,
	ICE_FLAG_PEER_ENA,
	ICE_FLAG_ADV_FEATURES,
#ifdef NETIF_F_HW_TC
	ICE_FLAG_TC_MQPRIO,		/* support for Multi queue TC */
	ICE_FLAG_CLS_FLOWER,		/* support cls flower filters */
#endif /* NETIF_F_HW_TC */
	ICE_FLAG_LINK_DOWN_ON_CLOSE_ENA,
	ICE_FLAG_NO_MEDIA,
#ifndef ETHTOOL_GFECPARAM
	ICE_FLAG_RS_FEC,
	ICE_FLAG_BASE_R_FEC,
#endif /* !ETHTOOL_GFECPARAM */
	ICE_FLAG_FW_LLDP_AGENT,
	ICE_FLAG_EXTERNAL_PHY,
#ifdef ADQ_PERF
	ICE_FLAG_CHNL_INLINE_FD_ENA,
#endif /* ADQ_PERF */
#ifdef ADQ_PERF
	ICE_FLAG_CHNL_PKT_INSPECT_OPT_ENA,
#endif /* ADQ_PERF */
	ICE_FLAG_ETHTOOL_CTXT,		/* set when ethtool holds RTNL lock */
	ICE_FLAG_LEGACY_RX,
	ICE_FLAG_VF_TRUE_PROMISC_ENA,
	ICE_FLAG_MDD_AUTO_RESET_VF,
	ICE_PF_FLAGS_NBITS		/* must be last */
};

#ifdef HAVE_NETDEV_SB_DEV
struct ice_macvlan {
	struct list_head list;
	int id;
	struct net_device *vdev;
	struct ice_vsi *parent_vsi;
	struct ice_vsi *vsi;
	u8 mac[ETH_ALEN];
};
#endif /* HAVE_NETDEV_SB_DEV */


struct ice_pf {
	struct pci_dev *pdev;

	/* OS reserved IRQ details */
	struct msix_entry *msix_entries;
	struct ice_res_tracker *irq_tracker;
	/* First MSIX vector used by SR-IOV VFs. Calculated by subtracting the
	 * number of MSIX vectors needed for all SR-IOV VFs from the number of
	 * MSIX vectors allowed on this PF.
	 */
	u16 sriov_base_vector;

	u16 ctrl_vsi_idx;		/* control VSI index in pf->vsi array */

	struct ice_vsi **vsi;		/* VSIs created by the driver */
	struct ice_sw *first_sw;	/* first switch created by firmware */
#ifdef CONFIG_DEBUG_FS
	struct dentry *ice_debugfs_pf;
#endif /* CONFIG_DEBUG_FS */
	/* Virtchnl/SR-IOV config info */
	struct ice_vf *vf;
	int num_alloc_vfs;		/* actual number of VFs allocated */
	u16 num_vfs_supported;		/* num VFs supported for this PF */
	u16 num_vf_qps;			/* num queue pairs per VF */
	u16 num_vf_msix;		/* num vectors per VF */
	/* used to ratelimit the MDD event logging */
	unsigned long last_printed_mdd_jiffies;
	DECLARE_BITMAP(state, __ICE_STATE_NBITS);
	DECLARE_BITMAP(flags, ICE_PF_FLAGS_NBITS);
	unsigned long *avail_txqs;	/* bitmap to track PF Tx queue usage */
	unsigned long *avail_rxqs;	/* bitmap to track PF Rx queue usage */
	unsigned long serv_tmr_period;
	unsigned long serv_tmr_prev;
	struct timer_list serv_tmr;
	struct work_struct serv_task;
	struct mutex avail_q_mutex;	/* protects access to avail_[rx|tx]qs */
	struct mutex sw_mutex;		/* lock for protecting VSI alloc flow */
	struct mutex tc_mutex;		/* lock to protect TC changes */
	u32 msg_enable;
	/* Total number of MSIX vectors reserved for base driver */
	u32 num_rdma_msix;
	u32 rdma_base_vector;
	struct ice_peer_dev *rdma_peer;
#ifdef HAVE_NETDEV_SB_DEV
	/* MACVLAN specific variables */
	DECLARE_BITMAP(avail_macvlan, ICE_MAX_MACVLANS);
	struct list_head macvlan_list;
	u16 num_macvlan;
	u16 max_num_macvlan;
#endif /* HAVE_NETDEV_SB_DEV */
	u32 hw_csum_rx_error;
	u32 oicr_idx;		/* Other interrupt cause MSIX vector index */
	u32 num_avail_sw_msix;	/* remaining MSIX SW vectors left unclaimed */
	u16 max_pf_txqs;	/* Total Tx queues PF wide */
	u16 max_pf_rxqs;	/* Total Rx queues PF wide */
	u32 num_lan_msix;	/* Total MSIX vectors for base driver */
	u16 num_lan_tx;		/* num LAN Tx queues setup */
	u16 num_lan_rx;		/* num LAN Rx queues setup */
	u16 next_vsi;		/* Next free slot in pf->vsi[] - 0-based! */
	u16 num_alloc_vsi;
	u16 corer_count;	/* Core reset count */
	u16 globr_count;	/* Global reset count */
	u16 empr_count;		/* EMP reset count */
	u16 pfr_count;		/* PF reset count */

	struct ice_hw_port_stats stats;
	struct ice_hw_port_stats stats_prev;
	struct ice_hw hw;
	u8 stat_prev_loaded:1; /* has previous stats been loaded */
	u8 wol_ena:1;
#ifdef ICE_ADD_PROBES
	u64 tcp_segs;
	u64 udp_segs;
	u64 tx_tcp_cso;
	u64 tx_udp_cso;
	u64 tx_sctp_cso;
	u64 tx_ip4_cso;
	u64 tx_l3_cso_err;
	u64 tx_l4_cso_err;
	u64 rx_tcp_cso;
	u64 rx_udp_cso;
	u64 rx_sctp_cso;
	u64 rx_ip4_cso;
	u64 rx_ip4_cso_err;
	u64 rx_tcp_cso_err;
	u64 rx_udp_cso_err;
	u64 rx_sctp_cso_err;
	u64 tx_vlano;
	u64 rx_vlano;
#endif
	u16 dcbx_cap;
	u32 tx_timeout_count;
	unsigned long tx_timeout_last_recovery;
	u32 tx_timeout_recovery_level;
	char int_name[ICE_INT_NAME_STR_LEN];
	struct ice_peer_dev_int **peers;
	int peer_idx;
	u32 sw_int_count;
#ifdef HAVE_TC_SETUP_CLSFLOWER
	struct hlist_head tc_flower_fltr_list;
	u16 num_tc_flower_fltrs;
#endif /* HAVE_TC_SETUP_CLSFLOWER */

#ifdef HAVE_PF_RING
	u16 instance; /* A unique number per ice_pf instance in the system */
	struct {
		atomic_t usage_counter;
		u8 interrupts_required;
		bool zombie; /* interface brought down while running */
	} pfring_zc;
#endif
};

struct ice_netdev_priv {
	struct ice_vsi *vsi;
#ifdef HAVE_TC_INDIR_BLOCK
	/* indirect block callbacks on registered higher level devices
	 * (e.g. tunnel devices)
	 *
	 * tc_indr_block_cb_priv_list is used to lookup indirect callback
	 * private data
	 *
	 * netdevice_nb is the netdev events notifier - used to register
	 * tunnel devices for block events
	 *
	 */
	struct list_head tc_indr_block_priv_list;
	struct notifier_block netdevice_nb;
#endif /* HAVE_TC_INDIR_BLOCK */
};

extern struct ida ice_peer_index_ida;


#ifdef ADQ_PERF
/**
 * ice_vector_ch_enabled
 * @qv: pointer to q_vector, can be NULL
 *
 * This function returns true if vector is channel enabled otherwise false
 */
static inline bool ice_vector_ch_enabled(struct ice_q_vector *qv)
{
	return !!qv->ch; /* Enable it to run with TC */
}

/**
 * ice_vector_busypoll_intr
 * @qv: pointer to q_vector
 *
 * This function returns true if vector is transitioning from BUSY_POLL
 * to INTERRUPT based on current and previous state of vector
 */
static inline bool ice_vector_busypoll_intr(struct ice_q_vector *qv)
{
	return (qv->state_flags & ICE_CHNL_PREV_IN_BP) &&
	      !(qv->state_flags & ICE_CHNL_IN_BP);
}

/**
 * ice_vector_ever_in_busypoll
 * @qv: pointer to q_vector
 *
 * This function returns true if vectors current OR previous state
 * is BUSY_POLL
 */
static inline bool ice_vector_ever_in_busypoll(struct ice_q_vector *qv)
{
	return (qv->state_flags & ICE_CHNL_PREV_IN_BP) ||
	       (qv->state_flags & ICE_CHNL_IN_BP);
}

/**
 * ice_vector_state_curr_prev_intr
 * @qv: pointer to q_vector
 *
 * This function returns true if vectors current AND previous state
 * is INTERRUPT
 */
static inline bool ice_vector_state_curr_prev_intr(struct ice_q_vector *qv)
{
	return !(qv->state_flags & ICE_CHNL_PREV_IN_BP) &&
	       !(qv->state_flags & ICE_CHNL_IN_BP);
}

/**
 * ice_vector_intr_busypoll
 * @qv: pointer to q_vector
 *
 * This function returns true if vector is transitioning from INTERRUPT
 * to BUSY_POLL based on current and previous state of vector
 */
static inline bool ice_vector_intr_busypoll(struct ice_q_vector *qv)
{
	return !(qv->state_flags & ICE_CHNL_PREV_IN_BP) &&
		(qv->state_flags & ICE_CHNL_IN_BP);
}

/**
 * ice_adq_trigger_sw_intr
 * @hw: ptr to HW
 * @q_vector: pointer to q_vector
 *
 * This function triggers SW interrupt on specified vector and re-enables
 * interrupt. This is for use with ADQ.
 */
static inline void
ice_adq_trigger_sw_intr(struct ice_hw *hw, struct ice_q_vector *q_vector)
{
	q_vector->state_flags &= ~ICE_CHNL_ONCE_IN_BP;

	wr32(hw,
	     GLINT_DYN_CTL(q_vector->reg_idx),
	     (ICE_ITR_NONE << GLINT_DYN_CTL_ITR_INDX_S) |
	     GLINT_DYN_CTL_SWINT_TRIG_M |
	     GLINT_DYN_CTL_CLEARPBA_M |
	     GLINT_DYN_CTL_INTENA_M);
}

#ifdef ADQ_PERF_COUNTERS
/**
 * ice_sw_intr_cntr
 * @q_vector: pointer to q_vector
 * @napi_codepath: codepath separator for stats purpose
 *
 * This function counts the trigger code path for sw_intr. Caller of this
 * expected to call ice_adq_trigger_sw_intr or ice_trigger_sw_intr function to
 * actually trigger SW intr.
 */
static inline void
ice_sw_intr_cntr(struct ice_q_vector *q_vector, bool napi_codepath)
{
	if (napi_codepath) /* napi - detected timeout */
		q_vector->ch_stats.num_sw_intr_timeout++;
	else
		q_vector->ch_stats.num_sw_intr_serv_task++;
}
#endif /* ADQ_PERF_COUNTERS */

/**
 * ice_force_wb - trigger force write-back by setting WB_ON_ITR bit
 * @hw: ptr to HW
 * @qv: pointer to q_vector
 *
 * This function is used to force write-backs by setting WB_ON_ITR bit
 * in DYN_CTLN register. WB_ON_ITR and INTENA are mutually exclusive bits.
 * Setting WB_ON_ITR bits means Tx and Rx descriptors are written back based
 * on ITR expiration irrespective of INTENA setting
 */
static inline void
ice_force_wb(struct ice_hw *hw, struct ice_q_vector *q_vector)
{
#ifdef ADQ_PERF_COUNTERS
	q_vector->ch_stats.num_wb_on_itr_set++;

#endif /* ADQ_PERF_COUNTERS */
	wr32(hw,
	     GLINT_DYN_CTL(q_vector->reg_idx),
	     (ICE_ITR_NONE << GLINT_DYN_CTL_ITR_INDX_S) |
	     GLINT_DYN_CTL_WB_ON_ITR_M);

	/* needed to avoid triggering WB_ON_ITR again which typically
	 * happens from ice_set_wb_on_itr function
	 */
	q_vector->itr_countdown = ICE_IN_WB_ON_ITR_MODE;
}
#endif /* ADQ_PERF */

/**
 * ice_irq_dynamic_ena - Enable default interrupt generation settings
 * @hw: pointer to HW struct
 * @vsi: pointer to VSI struct, can be NULL
 * @q_vector: pointer to q_vector, can be NULL
 */
static inline void
ice_irq_dynamic_ena(struct ice_hw *hw, struct ice_vsi *vsi,
		    struct ice_q_vector *q_vector)
{
	u32 vector = (vsi && q_vector) ? q_vector->reg_idx :
				((struct ice_pf *)hw->back)->oicr_idx;
	int itr = ICE_ITR_NONE;
	u32 val;

	/* clear the PBA here, as this function is meant to clean out all
	 * previous interrupts and enable the interrupt
	 */
	val = GLINT_DYN_CTL_INTENA_M | GLINT_DYN_CTL_CLEARPBA_M |
	      (itr << GLINT_DYN_CTL_ITR_INDX_S);
	if (vsi)
		if (test_bit(__ICE_DOWN, vsi->state))
			return;
	wr32(hw, GLINT_DYN_CTL(vector), val);
}

/**
 * ice_netdev_to_pf - Retrieve the PF struct associated with a netdev
 * @netdev: pointer to the netdev struct
 */
static inline struct ice_pf *ice_netdev_to_pf(struct net_device *netdev)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);

	return np->vsi->back;
}

#ifdef HAVE_XDP_SUPPORT
static inline bool ice_is_xdp_ena_vsi(struct ice_vsi *vsi)
{
	return !!vsi->xdp_prog;
}

static inline void ice_set_ring_xdp(struct ice_ring *ring)
{
	ring->flags |= ICE_TX_FLAGS_RING_XDP;
}

#endif /* HAVE_XDP_SUPPORT */
#ifdef HAVE_AF_XDP_ZC_SUPPORT
/**
 * ice_xsk_umem - get XDP UMEM bound to a ring
 * @ring - ring to use
 *
 * Returns a pointer to xdp_umem structure if there is an UMEM present,
 * NULL otherwise.
 */
static inline struct xdp_umem *ice_xsk_umem(struct ice_ring *ring)
{
	struct xdp_umem **umems = ring->vsi->xsk_umems;
	u16 qid = ring->q_index;

	if (ice_ring_is_xdp(ring))
		qid -= ring->vsi->num_xdp_txq;

	if (qid >= ring->vsi->num_xsk_umems || !umems || !umems[qid] ||
	    !ice_is_xdp_ena_vsi(ring->vsi))
		return NULL;

	return umems[qid];
}
#endif /* HAVE_AF_XDP_ZC_SUPPORT */

/**
 * ice_get_main_vsi - Get the PF VSI
 * @pf: PF instance
 *
 * returns pf->vsi[0], which by definition is the PF VSI
 */
static inline struct ice_vsi *ice_get_main_vsi(struct ice_pf *pf)
{
	if (pf->vsi)
		return pf->vsi[0];

	return NULL;
}

/**
 * ice_get_ctrl_vsi - Get the control VSI
 * @pf: PF instance
 */
static inline struct ice_vsi *ice_get_ctrl_vsi(struct ice_pf *pf)
{
	/* if pf->ctrl_vsi_idx is ICE_NO_VSI, control VSI was not set up */
	if (!pf->vsi || pf->ctrl_vsi_idx == ICE_NO_VSI)
		return NULL;

	return pf->vsi[pf->ctrl_vsi_idx];
}

/**
 * ice_find_first_vsi_by_type - Find and return first VSI of a given type
 * @pf: PF to search for VSI
 * @type: VSI type we are looking for
 */
static inline struct ice_vsi *
ice_find_first_vsi_by_type(struct ice_pf *pf, enum ice_vsi_type type)
{
	int i;

	ice_for_each_vsi(pf, i) {
		struct ice_vsi *vsi = pf->vsi[i];

		if (vsi && vsi->type == type)
			return vsi;
	}

	return NULL;
}

enum ice_fd_stat_idx {
	ICE_FD_STAT_SB,
#ifdef ADQ_PERF
	ICE_FD_STAT_CH,
#endif /* ADQ_PERF */
#ifdef ICE_ADD_PROBES
	ICE_ARFS_STAT_TCPV4,
	ICE_ARFS_STAT_TCPV6,
	ICE_ARFS_STAT_UDPV4,
	ICE_ARFS_STAT_UDPV6
#endif /* ICE_ADD_PROBES */
};

#define ICE_FD_STAT_CTR_BLOCK_COUNT	256
#define ICE_FD_STAT_PF_IDX(base_idx) \
			((base_idx) * ICE_FD_STAT_CTR_BLOCK_COUNT)
#define ICE_FD_SB_STAT_IDX(base_idx) \
			(ICE_FD_STAT_PF_IDX(base_idx) + ICE_FD_STAT_SB)
#ifdef ICE_ADD_PROBES
#define ICE_ARFS_STAT_TCPV4_IDX(base_idx) \
			(ICE_FD_STAT_PF_IDX(base_idx) + ICE_ARFS_STAT_TCPV4)
#define ICE_ARFS_STAT_TCPV6_IDX(base_idx) \
			(ICE_FD_STAT_PF_IDX(base_idx) + ICE_ARFS_STAT_TCPV6)
#define ICE_ARFS_STAT_UDPV4_IDX(base_idx) \
			(ICE_FD_STAT_PF_IDX(base_idx) + ICE_ARFS_STAT_UDPV4)
#define ICE_ARFS_STAT_UDPV6_IDX(base_idx) \
			(ICE_FD_STAT_PF_IDX(base_idx) + ICE_ARFS_STAT_UDPV6)
#endif /* ICE_ADD_PROBES */

#ifdef ADQ_PERF
#define ICE_FD_CH_STAT_IDX(base_idx) \
			(ICE_FD_STAT_PF_IDX(base_idx) + ICE_FD_STAT_CH)

/**
 * ice_vsi_fd_ena
 * @vsi: pointer to VSI
 *
 * This function returns true if VSI is capable for usage of flow-director
 * otherwise returns false
 */
static inline bool ice_vsi_fd_ena(struct ice_vsi *vsi)
{
	return !!test_bit(ICE_CHNL_FEATURE_FD_ENA, vsi->features);
}

/**
 * ice_vsi_inline_fd_ena
 * @vsi: pointer to VSI
 *
 * This function returns true if VSI is enabled for usage of flow-director
 * otherwise returns false. This is controlled thru' ethtool priv-flag
 * 'channel-inline-flow-director'
 */
static inline bool ice_vsi_inline_fd_ena(struct ice_vsi *vsi)
{
	return !!test_bit(ICE_CHNL_FEATURE_INLINE_FD_ENA, vsi->features);
}

/**
 * ice_get_current_fd_cnt - Get total FD filters programmed for this VSI
 * @vsi: ptr to VSI
 */
static inline u32 ice_get_current_fd_cnt(struct ice_vsi *vsi)
{
	u32 val;

	val = rd32(&vsi->back->hw, VSIQF_FD_CNT(vsi->vsi_num));

	return (val & VSIQF_FD_CNT_FD_GCNT_M) +
		((val & VSIQF_FD_CNT_FD_BCNT_M) >>
		VSIQF_FD_CNT_FD_BCNT_S);
}

/**
 * ice_read_cntr - read counter value using counter_index
 * @pf: ptr to PF
 * @counter_index: index of counter to be read
 */
static inline u64 ice_read_cntr(struct ice_pf *pf, u32 counter_index)
{
	/* Read the HW counter based on counter_index */
	return ((u64)rd32(&pf->hw, GLSTAT_FD_CNT0H(counter_index)) << 32) |
		rd32(&pf->hw, GLSTAT_FD_CNT0L(counter_index));
}

/**
 * ice_clear_cntr - initialize counter to zero
 * @pf: ptr to PF
 * @counter_index: index of counter to be initialized
 */
static inline void ice_clear_cntr(struct ice_pf *pf, u32 counter_index)
{
	/* Read the HW counter based on counter_index */
	wr32(&pf->hw, GLSTAT_FD_CNT0H(counter_index), 0);
	wr32(&pf->hw, GLSTAT_FD_CNT0L(counter_index), 0);
}

/**
 * ice_is_vsi_fd_table_full - VSI specific FD table is full or not
 * @vsi: ptr to VSI
 * @cnt: fd count, specific to VSI
 *
 * Retutn true if HW FD table specific to VSI is full, otherwise false
 */
static inline bool ice_is_vsi_fd_table_full(struct ice_vsi *vsi, u32 cnt)
{
	if (!cnt)
		return false;

	/* determine if 'cnt' reached max_allowed for specified VSI,
	 * if so, return HW table full for that specific VSI
	 */
	return (cnt >= (vsi->num_gfltr + vsi->num_bfltr - 1)) ? true : false;
}
#endif /* ADQ_PERF */

#ifdef NETIF_F_HW_TC
/**
 * ice_is_adq_active - any active ADQs
 * @pf: pointer to PF
 *
 * This function returns true if there are any ADQs configured (which is
 * determined by looking at VSI type (which should be VSI_PF), numtc, and
 * TC_MQPRIO flag) otherwise return false
 */
static inline bool ice_is_adq_active(struct ice_pf *pf)
{
	struct ice_vsi *vsi;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return false;

	/* is ADQ configured */
	if (vsi->tc_cfg.numtc > ICE_CHNL_START_TC &&
	    test_bit(ICE_FLAG_TC_MQPRIO, pf->flags))
		return true;

	return false;
}
#endif /* NETIF_F_HW_TC */
#ifdef ADQ_PERF
/**
 * ice_vsi_pkt_inspect_opt_ena - packet inspection based optimization is ON/OFF
 * @vsi: pointer to VSI
 *
 * This function returns true if VSI is enabled for optimization based on
 * control/data packet. By default, respective PF priv flags is ON (which user
 * can change using ethtool if needed), hence by default VSI level feature
 * flags is also ON. If user changes PF level priv flag after creating channel
 * VSIs (aka ADQ VSI), those changes are not reflected in VSI level feature
 * flag by design.
 */
static inline bool ice_vsi_pkt_inspect_opt_ena(struct ice_vsi *vsi)
{
	return !!test_bit(ICE_CHNL_FEATURE_PKT_INSPECT_OPT_ENA, vsi->features);
}
#endif /* ADQ_PERF */

static inline bool ice_active_vmdqs(struct ice_pf *pf)
{
	return !!ice_find_first_vsi_by_type(pf, ICE_VSI_VMDQ2);
}

#ifdef CONFIG_DEBUG_FS
void ice_debugfs_pf_init(struct ice_pf *pf);
void ice_debugfs_pf_exit(struct ice_pf *pf);
void ice_debugfs_init(void);
void ice_debugfs_exit(void);
#else
static inline void ice_debugfs_pf_init(struct ice_pf *pf) {}
static inline void ice_debugfs_pf_exit(struct ice_pf *pf) {}
static inline void ice_debugfs_init(void) {}
static inline void ice_debugfs_exit(void) {}
#endif /* CONFIG_DEBUG_FS */

#ifdef HAVE_NETDEV_SB_DEV
bool netif_is_ice(struct net_device *dev);
static inline bool ice_is_offloaded_macvlan_ena(struct ice_pf *pf)
{
	return test_bit(ICE_FLAG_MACVLAN_ENA, pf->flags);
}
#endif /* HAVE_NETDEV_SB_DEV */

int ice_vsi_setup_tx_rings(struct ice_vsi *vsi);
int ice_vsi_setup_rx_rings(struct ice_vsi *vsi);
int ice_vsi_open_ctrl(struct ice_vsi *vsi);
int ice_vsi_open(struct ice_vsi *vsi);
void ice_set_ethtool_ops(struct net_device *netdev);
void ice_set_ethtool_recovery_ops(struct net_device *netdev);
void ice_set_ethtool_safe_mode_ops(struct net_device *netdev);
u16 ice_get_avail_txq_count(struct ice_pf *pf);
u16 ice_get_avail_rxq_count(struct ice_pf *pf);
int ice_vsi_recfg_qs(struct ice_vsi *vsi, int new_rx, int new_tx);
void ice_update_pf_stats(struct ice_pf *pf);
void ice_update_vsi_stats(struct ice_vsi *vsi);
int ice_up(struct ice_vsi *vsi);
int ice_down(struct ice_vsi *vsi);
int ice_vsi_cfg(struct ice_vsi *vsi);
struct ice_vsi *ice_lb_vsi_setup(struct ice_pf *pf, struct ice_port_info *pi);
#ifdef HAVE_NETDEV_SB_DEV
int ice_vsi_cfg_netdev_tc0(struct ice_vsi *vsi);
#endif /* HAVE_NETDEV_SB_DEV */
#ifdef HAVE_XDP_SUPPORT
int ice_prepare_xdp_rings(struct ice_vsi *vsi, struct bpf_prog *prog);
int ice_destroy_xdp_rings(struct ice_vsi *vsi);
#ifndef NO_NDO_XDP_FLUSH
void ice_xdp_flush(struct net_device *dev);
#endif /* NO_NDO_XDP_FLUSH */
#ifdef HAVE_XDP_FRAME_STRUCT
int
ice_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames,
	     u32 flags);
#else
int ice_xdp_xmit(struct net_device *dev, struct xdp_buff *xdp);
#endif /* HAVE_XDP_FRAME_STRUCT */
#endif /* HAVE_XDP_SUPPORT */
int ice_set_rss(struct ice_vsi *vsi, u8 *seed, u8 *lut, u16 lut_size);
int ice_get_rss(struct ice_vsi *vsi, u8 *seed, u8 *lut, u16 lut_size);
void ice_fill_rss_lut(u8 *lut, u16 rss_table_size, u16 rss_size);
int ice_schedule_reset(struct ice_pf *pf, enum ice_reset_req reset);
void ice_print_link_msg(struct ice_vsi *vsi, bool isup);
#if IS_ENABLED(CONFIG_MFD_CORE)
int ice_init_peer_devices(struct ice_pf *pf);
int
ice_for_each_peer(struct ice_pf *pf, void *data,
		  int (*fn)(struct ice_peer_dev_int *, void *));
#ifdef CONFIG_PM
void ice_peer_refresh_msix(struct ice_pf *pf);
#endif /* CONFIG_PM */
#else /* !CONFIG_MFD_CORE */
static inline int ice_init_peer_devices(struct ice_pf *pf) { return 0; }

static inline int
ice_for_each_peer(struct ice_pf *pf, void *data,
		  int (*fn)(struct ice_peer_dev_int *, void *))
{
	return 0;
}

#ifdef CONFIG_PM
#define ice_peer_refresh_msix(pf) do { } while (0)
#endif /* CONFIG_PM */
#endif /* !CONFIG_MFD_CORE */

const char *ice_stat_str(enum ice_status stat_err);
const char *ice_aq_str(enum ice_aq_err aq_err);
bool ice_is_wol_ena(struct ice_pf *pf);
int
ice_prgm_fdir_fltr(struct ice_vsi *vsi, struct ice_fltr_desc *fdir_desc,
		   u8 *raw_packet);
int
ice_fdir_write_fltr(struct ice_pf *pf, struct ice_fdir_fltr *input, bool add,
		    bool is_tun);
void ice_vsi_drain_rxq(struct ice_vsi *vsi, int idx);
void ice_vsi_manage_fdir(struct ice_vsi *vsi, bool ena);
int ice_add_fdir_ethtool(struct ice_vsi *vsi, struct ethtool_rxnfc *cmd);
int ice_del_fdir_ethtool(struct ice_vsi *vsi, struct ethtool_rxnfc *cmd);
int ice_get_ethtool_fdir_entry(struct ice_hw *hw, struct ethtool_rxnfc *cmd);
int
ice_get_fdir_fltr_ids(struct ice_hw *hw, struct ethtool_rxnfc *cmd,
		      u32 *rule_locs);
void ice_fdir_rem_adq_chnl(struct ice_hw *hw, u16 vsi_idx);
void ice_fdir_release_flows(struct ice_hw *hw);
void ice_fdir_replay_flows(struct ice_hw *hw);
void ice_fdir_replay_fltrs(struct ice_pf *pf);
int ice_create_fdir_rule(struct ice_pf *pf, enum ice_fltr_ptype flow);
int ice_open(struct net_device *netdev);
int ice_stop(struct net_device *netdev);
void ice_service_task_schedule(struct ice_pf *pf);

#ifdef HAVE_TC_SETUP_CLSFLOWER
int
ice_add_tc_flower_adv_fltr(struct ice_vsi *vsi,
			   struct ice_tc_flower_fltr *tc_fltr);
#endif /* HAVE_TC_SETUP_CLSFLOWER */
#endif /* _ICE_H_ */
