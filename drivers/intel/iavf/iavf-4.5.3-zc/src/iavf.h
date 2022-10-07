/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2013, Intel Corporation. */

#ifndef _IAVF_H_
#define _IAVF_H_

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/socket.h>
#include <linux/jiffies.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/udp.h>
#ifdef HAVE_SCTP
#include <linux/sctp.h>
#endif
#ifdef __TC_MQPRIO_MODE_MAX
#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_mirred.h>
#endif /* __TC_MQPRIO_MODE_MAX */

#include "kcompat.h"

#include "iavf_type.h"
#include "virtchnl.h"
#include "iavf_txrx.h"
#include "iavf_ptp.h"
#include <linux/bitmap.h>
#include "siov_regs.h"

#define DEFAULT_DEBUG_LEVEL_SHIFT 3
#define PFX "iavf: "

int iavf_status_to_errno(enum iavf_status status);
int virtchnl_status_to_errno(enum virtchnl_status_code v_status);

/* VSI state flags shared with common code */
enum iavf_vsi_state_t {
	__IAVF_VSI_DOWN,
	/* This must be last as it determines the size of the BITMAP */
	__IAVF_VSI_STATE_SIZE__,
};

/* dummy struct to make common code less painful */
struct iavf_vsi {
	struct iavf_adapter *back;
	struct net_device *netdev;
#ifdef HAVE_VLAN_RX_REGISTER
	struct vlan_group *vlgrp;
#endif
	unsigned long active_cvlans[BITS_TO_LONGS(VLAN_N_VID)];
	unsigned long active_svlans[BITS_TO_LONGS(VLAN_N_VID)];

	/* dummy pointer - VF plans to add this functionality in the future */
	struct iavf_ring **xdp_rings;
	u16 seid;
	u16 id;
	DECLARE_BITMAP(state, __IAVF_VSI_STATE_SIZE__);
	int base_vector;
	u16 qs_handle;
};

/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define IAVF_RX_BUFFER_WRITE	16	/* Must be power of 2 */
#define IAVF_DEFAULT_TXD	512
#define IAVF_DEFAULT_RXD	512
#define IAVF_MAX_TXD		4096
#define IAVF_MIN_TXD		64
#define IAVF_MAX_RXD		4096
#define IAVF_MIN_RXD		64
#define IAVF_REQ_DESCRIPTOR_MULTIPLE	32
#define IAVF_MAX_AQ_BUF_SIZE	4096
#define IAVF_AQ_LEN		32
#define IAVF_AQ_MAX_ERR	20 /* times to try before resetting AQ */

#define MAXIMUM_ETHERNET_VLAN_SIZE (VLAN_ETH_FRAME_LEN + ETH_FCS_LEN)

#define IAVF_RX_DESC(R, i) (&(((union iavf_32byte_rx_desc *)((R)->desc))[i]))
#define IAVF_TX_DESC(R, i) (&(((struct iavf_tx_desc *)((R)->desc))[i]))
#define IAVF_TX_CTXTDESC(R, i) \
	(&(((struct iavf_tx_context_desc *)((R)->desc))[i]))
#define IAVF_MAX_REQ_QUEUES 16

#define IAVF_START_CHNL_TC	1

#define IAVF_HKEY_ARRAY_SIZE ((IAVF_VFQF_HKEY_MAX_INDEX + 1) * 4)
#define IAVF_HLUT_ARRAY_SIZE ((IAVF_VFQF_HLUT_MAX_INDEX + 1) * 4)
#define IAVF_MBPS_DIVISOR	125000 /* divisor to convert to Mbps */
#define IAVF_MBPS_QUANTA	50

#define IAVF_VIRTCHNL_VF_RESOURCE_SIZE	(sizeof(struct virtchnl_vf_resource) + \
					 (IAVF_MAX_VF_VSI *		       \
					 sizeof(struct virtchnl_vsi_resource)))

#define IAVF_NETIF_F_HW_VLAN_BITS
#ifdef NETIF_F_HW_VLAN_CTAG_RX
#define IAVF_NETIF_F_HW_VLAN_CTAG_RX	NETIF_F_HW_VLAN_CTAG_RX
#else
#define IAVF_NETIF_F_HW_VLAN_CTAG_RX	NETIF_F_HW_VLAN_RX
#endif

#ifdef NETIF_F_HW_VLAN_CTAG_TX
#define IAVF_NETIF_F_HW_VLAN_CTAG_TX	NETIF_F_HW_VLAN_CTAG_TX
#else
#define IAVF_NETIF_F_HW_VLAN_CTAG_TX	NETIF_F_HW_VLAN_TX
#endif

#ifdef NETIF_F_HW_VLAN_CTAG_FILTER
#define IAVF_NETIF_F_HW_VLAN_CTAG_FILTER	NETIF_F_HW_VLAN_CTAG_FILTER
#else
#define IAVF_NETIF_F_HW_VLAN_CTAG_FILTER	NETIF_F_HW_VLAN_FILTER
#endif

enum iavf_chnl_vector_state {
	IAVF_VEC_IN_BP,
	IAVF_VEC_PREV_IN_BP,
	IAVF_VEC_ONCE_IN_BP,
	IAVF_VEC_PREV_DATA_PKT_RECV,
	IAVF_VEC_NBITS, /* This must be last */
};

struct iavf_channel_ex {
	atomic_t fd_queue;
	u32 fd_cnt_idx;
	u16 num_rxq;
	u16 base_q;
	/* number of filter specific to this channel (aka ADQ TC) */
	u32 num_fltr;
};

struct iavf_q_vector_ch_stats {
	/* following are used as part of managing driver internal
	 * state machine. Only to be used for perf debugging.
	 */
	u64 in_bp;
	u64 in_intr;
	u64 intr_to_bp;
	u64 bp_to_intr;
	u64 intr_to_intr;
	u64 bp_to_bp;

	/* This counter is used to track real transition of vector from
	 * BUSY_POLL to INTERRUPT based on enhanced logic (using state
	 * machine and control packets).
	 */
	u64 unlikely_cb_to_bp;
	/* Tracking "unlikely_cb_bp and once_in_bp is true" */
	u64 ucb_once_in_bp_true;
	/* This is used to keep track of enabling interrupt from napi_poll
	 * when state machine condition indicated once_in_bp is false
	 */
	u64 intr_once_bp_false;
	u64 bp_stop_need_resched;
	u64 bp_stop_timeout;

	u64 cleaned_any_data_pkt;
	/* busy_poll stop, need_resched is set and did not clean
	 * any data packet during this previous invocation of napi_poll
	 */
	u64 need_resched_no_data_pkt;
	/* busy_poll stop, need_resched is not set: hence it is inferred as
	 * possible timeout and did not clean any data packet during this
	 * previous invocation of napi_poll
	 */
	u64 timeout_no_data_pkt;
	u64 sw_intr_timeout; /* track SW INTR from napi_poll */
	u64 sw_intr_serv_task; /* track SW INTR from service_task */
	/* This keeps track of how many times, bailout when once_in_bp is set,
	 * unlikely_cb_to_bp is set, but pkt based interrupt optimization
	 * is OFF
	 */
	u64 no_sw_intr_opt_off;
	/* tracking, how many times WB_ON_ITR is set */
	u64 wb_on_itr_set;
	/* keeps track of SW triggered interrupt due to not clean_complete */
	u64 intr_en_not_clean_complete;
};

/* MAX_MSIX_Q_VECTORS of these are allocated,
 * but we only use one per queue-specific vector.
 */
struct iavf_q_vector {
	struct iavf_adapter *adapter;
	struct iavf_vsi *vsi;
	struct napi_struct napi;
	struct iavf_ring_container rx;
	struct iavf_ring_container tx;
	u32 ring_mask;
	u8 itr_countdown;	/* when 0 should adjust adaptive ITR */
	u8 num_ringpairs;	/* total number of ring pairs in vector */
	u16 v_idx;		/* index in the vsi->q_vector array. */
	u16 reg_idx;		/* register index of the interrupt */
	char name[IFNAMSIZ + 15];
	bool arm_wb_state;
#ifdef HAVE_IRQ_AFFINITY_NOTIFY
	cpumask_t affinity_mask;
	struct irq_affinity_notify affinity_notify;
#endif
	/* This tracks current state of vector, BUSY_POLL or INTR */
#define IAVF_VECTOR_STATE_IN_BP                 BIT(IAVF_VEC_IN_BP)
	/* This tracks prev state of vector, BUSY_POLL or INTR */
#define IAVF_VECTOR_STATE_PREV_IN_BP            BIT(IAVF_VEC_PREV_IN_BP)
	/* This tracks state of vector, was the ever in BUSY_POLL. This
	 * state goes to INTT if interrupt are enabled or SW interrupts
	 * are triggered from either service_task or napi_poll
	 */
#define IAVF_VECTOR_STATE_ONCE_IN_BP            BIT(IAVF_VEC_ONCE_IN_BP)

	/* Tracks if previously - were there any data packets received
	 * on per channel enabled vector or not
	 */
#define IAVF_VECTOR_STATE_PREV_DATA_PKT_RECV    BIT(IAVF_VEC_PREV_DATA_PKT_RECV)
	/* it is used to keep track of various states as defined earlier
	 * and those states are used during ADQ performance optimization
	 */
	u8 state_flags;

#define IAVF_VECTOR_CHNL_PERF_ENA	BIT(0)
	/* controls packet inspection based optimization is OFF/ON */
#define IAVF_VECTOR_CHNL_PKT_OPT_ENA	BIT(1)
	u16 chnl_flags;

	/* Used in logic to determine if SW inter is needed or not.
	 * This is used only for channel enabled vector
	 */
	u64 jiffies;

	struct iavf_channel_ex *ch;
	struct iavf_q_vector_ch_stats ch_stats;
};

static inline bool vector_pkt_inspect_opt_ena(struct iavf_q_vector *q_vector)
{
	return q_vector->chnl_flags & IAVF_VECTOR_CHNL_PKT_OPT_ENA;
}

static inline bool vector_ch_ena(struct iavf_q_vector *qv)
{
	return !!qv->ch;
}

static inline bool vector_ch_perf_ena(struct iavf_q_vector *qv)
{
	return qv->chnl_flags & IAVF_VECTOR_CHNL_PERF_ENA;
}

/**
 * vector_busypoll_intr
 * @qv: pointer to q_vector
 *
 * This function returns true if vector is transitioning from BUSY_POLL
 * to INTERRUPT based on current and previous state of vector
 */
static inline bool vector_busypoll_intr(struct iavf_q_vector *qv)
{
	return (qv->state_flags & IAVF_VECTOR_STATE_PREV_IN_BP) &&
		!(qv->state_flags & IAVF_VECTOR_STATE_IN_BP);
}

/**
 * vector_ever_in_busypoll
 * @qv: pointer to q_vector
 *
 * This function returns true if vectors current OR previous state
 * is BUSY_POLL
 */
static inline bool vector_ever_in_busypoll(struct iavf_q_vector *qv)
{
	return (qv->state_flags & IAVF_VECTOR_STATE_PREV_IN_BP) ||
	       (qv->state_flags & IAVF_VECTOR_STATE_IN_BP);
}

/**
 * vector_state_curr_prev_intr
 * @qv: pointer to q_vector
 *
 * This function returns true if vectors current AND previous state
 * is INTERRUPT
 */
static inline bool vector_state_curr_prev_intr(struct iavf_q_vector *qv)
{
	return !(qv->state_flags & IAVF_VECTOR_STATE_PREV_IN_BP) &&
	       !(qv->state_flags & IAVF_VECTOR_STATE_IN_BP);
}

/**
 * vector_intr_busypoll
 * @qv: pointer to q_vector
 *
 * This function returns true if vector is transitioning from INTERRUPT
 * to BUSY_POLL based on current and previous state of vector
 */
static inline bool vector_intr_busypoll(struct iavf_q_vector *qv)
{
	return !(qv->state_flags & IAVF_VECTOR_STATE_PREV_IN_BP) &&
		(qv->state_flags & IAVF_VECTOR_STATE_IN_BP);
}

/**
 * iavf_inc_napi_sw_intr_counter
 * @q_vector: pointer to q_vector
 *
 * Track software interrupt from napi_poll codeflow.  Caller of this
 * expected to call iavf_force_wb to actually trigger SW intr.
 */
static inline void
iavf_inc_napi_sw_intr_counter(struct iavf_q_vector *q_vector)
{
	q_vector->ch_stats.sw_intr_timeout++;
}

/**
 * iavf_inc_serv_task_sw_intr_counter
 * @q_vector: pointer to q_vector
 *
 * Track software interrupt from service_task codeflow.  Caller of this
 * expected to call iavf_force_wb to actually trigger SW intr.
 */
static inline void
iavf_inc_serv_task_sw_intr_counter(struct iavf_q_vector *q_vector)
{
	q_vector->ch_stats.sw_intr_serv_task++;
}

/**
 * iavf_set_wb_on_itr - trigger force write-back by setting WB_ON_ITR bit
 * @hw: ptr to HW
 * @qv: pointer to vector
 *
 * This function is used to force write-backs by setting WB_ON_ITR bit
 * in DYN_CTLN register. WB_ON_ITR and INTENA are mutually exclusive bits.
 * Seting WB_ON_ITR bits means TX and RX descriptors are written back based
 * on ITR expiration irrespective of INTENA setting
 */
static inline void
iavf_set_wb_on_itr(struct iavf_hw *hw, struct iavf_q_vector *qv)
{
	qv->ch_stats.wb_on_itr_set++;
	wr32(hw, INT_DYN_CTL(hw, qv->reg_idx),
	     IAVF_VFINT_DYN_CTLN1_ITR_INDX_MASK |
	     IAVF_VFINT_DYN_CTLN1_WB_ON_ITR_MASK);
}

/* Helper macros to switch between ints/sec and what the register uses.
 * And yes, it's the same math going both ways.  The lowest value
 * supported by all of the iavf hardware is 8.
 */
#define EITR_INTS_PER_SEC_TO_REG(_eitr) \
	((_eitr) ? (1000000000 / ((_eitr) * 256)) : 8)
#define EITR_REG_TO_INTS_PER_SEC EITR_INTS_PER_SEC_TO_REG

#define IAVF_DESC_UNUSED(R) \
	((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	(R)->next_to_clean - (R)->next_to_use - 1)

#define OTHER_VECTOR 1
#define NONQ_VECS (OTHER_VECTOR)

#define MIN_MSIX_Q_VECTORS 1
#define MIN_MSIX_COUNT (MIN_MSIX_Q_VECTORS + NONQ_VECS)

#define IAVF_QUEUE_END_OF_LIST 0x7FF
#define IAVF_FREE_VECTOR 0x7FFF
struct iavf_mac_filter {
	struct list_head list;
	u8 macaddr[ETH_ALEN];
	struct {
		u8 is_new_mac:1;    /* filter is new, wait for PF decision */
		u8 remove:1;	    /* filter needs to be removed */
		u8 add:1;	    /* filter needs to be added */
		u8 is_primary:1;    /* filter is a default VF MAC */
		u8 add_handled:1;   /* received response from PF for filter add */
		u8 padding:3;
	};
};

#define IAVF_VLAN(vid, tpid) ((struct iavf_vlan){ vid, tpid })
struct iavf_vlan {
	u16 vid;
	u16 tpid;
};

struct iavf_vlan_filter {
	struct list_head list;
	struct iavf_vlan vlan;
	struct {
		u8 is_new_vlan:1;	/* filter is new, wait for PF answer */
		u8 remove:1;		/* filter needs to be removed */
		u8 add:1;		/* filter needs to be added */
		u8 padding:5;
	};
};

/* State of traffic class creation */
enum iavf_tc_state_t {
	__IAVF_TC_INVALID, /* no traffic class, default state */
	__IAVF_TC_RUNNING, /* traffic classes have been created */
};

/* channel info */
struct iavf_channel_config {
	struct virtchnl_channel_info ch_info[VIRTCHNL_MAX_ADQ_V2_CHANNELS];
	enum iavf_tc_state_t state;
	u8 total_qps;
	struct iavf_channel_ex ch_ex_info[VIRTCHNL_MAX_ADQ_V2_CHANNELS];
};

/* State of cloud filter */
enum iavf_cloud_filter_state_t {
	__IAVF_CF_INVALID,	 /* cloud filter not added */
	__IAVF_CF_ADD_PENDING, /* cloud filter pending add by the PF */
	__IAVF_CF_DEL_PENDING, /* cloud filter pending del by the PF */
	__IAVF_CF_ACTIVE,	 /* cloud filter is active */
};

/* Driver state. The order of these is important! */
enum iavf_state_t {
	__IAVF_STARTUP,		/* driver loaded, probe complete */
	__IAVF_REMOVE,		/* driver is being unloaded */
	__IAVF_INIT_VERSION_CHECK,	/* aq msg sent, awaiting reply */
	__IAVF_INIT_GET_RESOURCES,	/* aq msg sent, awaiting reply */
	__IAVF_INIT_EXTENDED_CAPS,	/* process extended caps which require aq msg exchange */
	__IAVF_INIT_CONFIG_ADAPTER,
	__IAVF_INIT_SW,		/* got resources, setting up structs */
	__IAVF_INIT_FAILED,		/* init failed, restarting procedure */
	__IAVF_RESETTING,		/* in reset */
	__IAVF_COMM_FAILED,		/* communication with PF failed */
	/* Below here, watchdog is running */
	__IAVF_DOWN,			/* ready, can be opened */
	__IAVF_DOWN_PENDING,		/* descending, waiting for watchdog */
	__IAVF_TESTING,		/* in ethtool self-test */
	__IAVF_RUNNING		/* opened, working */
};

enum iavf_critical_section_t {
	__IAVF_IN_CRITICAL_TASK,	/* cannot be interrupted */
	__IAVF_IN_REMOVE_TASK,	/* device being removed */
	__IAVF_TX_TSTAMP_IN_PROGRESS,	/* PTP Tx timestamp request in progress */
};

#define IAVF_CLOUD_FIELD_OMAC		0x01
#define IAVF_CLOUD_FIELD_IMAC		0x02
#define IAVF_CLOUD_FIELD_IVLAN	0x04
#define IAVF_CLOUD_FIELD_TEN_ID	0x08
#define IAVF_CLOUD_FIELD_IIP		0x10

#define IAVF_CF_FLAGS_OMAC	IAVF_CLOUD_FIELD_OMAC
#define IAVF_CF_FLAGS_IMAC	IAVF_CLOUD_FIELD_IMAC
#define IAVF_CF_FLAGS_IMAC_IVLAN	(IAVF_CLOUD_FIELD_IMAC |\
					 IAVF_CLOUD_FIELD_IVLAN)
#define IAVF_CF_FLAGS_IMAC_TEN_ID	(IAVF_CLOUD_FIELD_IMAC |\
					 IAVF_CLOUD_FIELD_TEN_ID)
#define IAVF_CF_FLAGS_OMAC_TEN_ID_IMAC	(IAVF_CLOUD_FIELD_OMAC |\
						 IAVF_CLOUD_FIELD_IMAC |\
						 IAVF_CLOUD_FIELD_TEN_ID)
#define IAVF_CF_FLAGS_IMAC_IVLAN_TEN_ID	(IAVF_CLOUD_FIELD_IMAC |\
						 IAVF_CLOUD_FIELD_IVLAN |\
						 IAVF_CLOUD_FIELD_TEN_ID)
#define IAVF_CF_FLAGS_IIP	IAVF_CLOUD_FIELD_IIP

/* bookkeeping of cloud filters */
struct iavf_cloud_filter {
	enum iavf_cloud_filter_state_t state;
	struct list_head list;
	struct virtchnl_filter f;
	unsigned long cookie;
	bool del;		/* filter needs to be deleted */
	bool add;		/* filter needs to be added */
	struct iavf_channel_ex *ch;
};

#define IAVF_RESET_WAIT_MS 10
#define IAVF_RESET_WAIT_DETECTED_COUNT	500
#define IAVF_RESET_WAIT_COMPLETE_COUNT	2000

/* structure used for the virtchnl message queue */
struct iavf_vc_msg {
	struct list_head list;
	enum virtchnl_ops v_opcode;
	u16 msglen;
	u8 msg[];
};

struct iavf_vc_msg_queue {
	struct list_head msgs;
	/* Lock protecting access to the virtchnl message queue */
	spinlock_t lock;
};

enum iavf_rdma_vc_op_state {
	IAVF_RDMA_VC_OP_NO_WORK = 0,
	IAVF_RDMA_VC_OP_PENDING,
	IAVF_RDMA_VC_OP_COMPLETE,
	IAVF_RDMA_VC_OP_FAILED,
};

struct iavf_rdma {
	struct iidc_core_dev_info *cdev_info;
	int aux_idx;
	u16 num_msix;
	u16 recv_sync_msg_size;
	u8 recv_sync_msg[IAVF_MAX_AQ_BUF_SIZE];
	wait_queue_head_t vc_op_waitqueue;
	enum iavf_rdma_vc_op_state vc_op_state;
	struct iavf_adapter *back;
	struct delayed_work init_task;
};

/* board specific private data structure */
struct iavf_adapter {
	struct work_struct adminq_task;
	struct delayed_work watchdog_task;
	wait_queue_head_t down_waitqueue;
	wait_queue_head_t vc_waitqueue;
	struct iavf_q_vector *q_vectors;
	struct list_head vlan_filter_list;
	struct list_head mac_filter_list;
	/* Lock to protect accesses to MAC and VLAN lists */
	spinlock_t mac_vlan_list_lock;
	char misc_vector_name[IFNAMSIZ + 9];
	u8 rxdid;
	int num_active_queues;
	int num_req_queues;

	/* TX */
	struct iavf_ring *tx_rings;
	u32 tx_timeout_count;
	u32 tx_desc_count;

	/* RX */
	struct iavf_ring *rx_rings;
	u64 hw_csum_rx_error;
	u32 rx_desc_count;
	int num_msix_vectors;
	struct msix_entry *msix_entries;

	u32 flags;
#define IAVF_FLAG_RX_CSUM_ENABLED		BIT(0)
#define IAVF_FLAG_PF_COMMS_FAILED		BIT(3)
#define IAVF_FLAG_RESET_PENDING			BIT(4)
#define IAVF_FLAG_RESET_NEEDED			BIT(5)
#define IAVF_FLAG_WB_ON_ITR_CAPABLE		BIT(6)
#define IAVF_FLAG_LEGACY_RX			BIT(15)
#define IAVF_FLAG_REINIT_ITR_NEEDED		BIT(16)
#define IAVF_FLAG_QUEUES_ENABLED		BIT(17)
#define IAVF_FLAG_QUEUES_DISABLED		BIT(18)
#define IAVF_FLAG_REINIT_MSIX_NEEDED		BIT(20)
#define IAVF_FLAG_REINIT_CHNL_NEEDED		BIT(21)
#define IAVF_FLAG_RESET_DETECTED		BIT(22)
#define IAVF_FLAG_INITIAL_MAC_SET		BIT(23)


	u32 chnl_perf_flags;
#define IAVF_FLAG_CHNL_PKT_OPT_ENA		BIT(0)

/* duplicates for common code */
#define IAVF_FLAG_DCB_ENABLED			0
	/* flags for admin queue service task */
	u64 aq_required;
#define IAVF_FLAG_AQ_ENABLE_QUEUES			BIT(0)
#define IAVF_FLAG_AQ_DISABLE_QUEUES			BIT(1)
#define IAVF_FLAG_AQ_ADD_MAC_FILTER			BIT(2)
#define IAVF_FLAG_AQ_ADD_VLAN_FILTER			BIT(3)
#define IAVF_FLAG_AQ_DEL_MAC_FILTER			BIT(4)
#define IAVF_FLAG_AQ_DEL_VLAN_FILTER			BIT(5)
#define IAVF_FLAG_AQ_CONFIGURE_QUEUES			BIT(6)
#define IAVF_FLAG_AQ_MAP_VECTORS			BIT(7)
#define IAVF_FLAG_AQ_HANDLE_RESET			BIT(8)
#define IAVF_FLAG_AQ_CONFIGURE_RSS			BIT(9) /* direct AQ config */
#define IAVF_FLAG_AQ_GET_CONFIG				BIT(10)
/* Newer style, RSS done by the PF so we can ignore hardware vagaries. */
#define IAVF_FLAG_AQ_GET_HENA				BIT(11)
#define IAVF_FLAG_AQ_SET_HENA				BIT(12)
#define IAVF_FLAG_AQ_SET_RSS_KEY			BIT(13)
#define IAVF_FLAG_AQ_SET_RSS_LUT			BIT(14)
#define IAVF_FLAG_AQ_CONFIGURE_PROMISC_MODE		BIT(15)
#define IAVF_FLAG_AQ_ENABLE_VLAN_STRIPPING		BIT(19)
#define IAVF_FLAG_AQ_DISABLE_VLAN_STRIPPING		BIT(20)
#define IAVF_FLAG_AQ_ENABLE_CHANNELS			BIT(21)
#define IAVF_FLAG_AQ_DISABLE_CHANNELS			BIT(22)
#define IAVF_FLAG_AQ_ADD_CLOUD_FILTER			BIT(23)
#define IAVF_FLAG_AQ_DEL_CLOUD_FILTER			BIT(24)
#define IAVF_FLAG_AQ_REQUEST_STATS			BIT(25)
#define IAVF_FLAG_AQ_GET_OFFLOAD_VLAN_V2_CAPS		BIT(26)
#define IAVF_FLAG_AQ_ENABLE_CTAG_VLAN_STRIPPING		BIT(27)
#define IAVF_FLAG_AQ_DISABLE_CTAG_VLAN_STRIPPING	BIT(28)
#define IAVF_FLAG_AQ_ENABLE_STAG_VLAN_STRIPPING		BIT(29)
#define IAVF_FLAG_AQ_DISABLE_STAG_VLAN_STRIPPING	BIT(30)
#define IAVF_FLAG_AQ_ENABLE_CTAG_VLAN_INSERTION		BIT(31)
#define IAVF_FLAG_AQ_DISABLE_CTAG_VLAN_INSERTION	BIT(32)
#define IAVF_FLAG_AQ_ENABLE_STAG_VLAN_INSERTION		BIT(33)
#define IAVF_FLAG_AQ_DISABLE_STAG_VLAN_INSERTION	BIT(34)
#define IAVF_FLAG_AQ_GET_SUPPORTED_RXDIDS		BIT(35)
#define IAVF_FLAG_AQ_GET_PTP_CAPS			BIT(36)
#define IAVF_FLAG_AQ_MSG_QUEUE_PENDING			BIT(37)

	/* AQ messages that must be sent after IAVF_FLAG_AQ_GET_CONFIG, in
	 * order to negotiated extended capabilities.
	 */
#define IAVF_FLAG_AQ_EXTENDED_CAPS			\
	(IAVF_FLAG_AQ_GET_OFFLOAD_VLAN_V2_CAPS |	\
	 IAVF_FLAG_AQ_GET_SUPPORTED_RXDIDS |		\
	 IAVF_FLAG_AQ_GET_PTP_CAPS)

	/* flags for processing extended capability messages during
	 * __IAVF_INIT_EXTENDED_CAPS. Each capability exchange requires
	 * both a SEND and a RECV step, which must be processed in sequence.
	 *
	 * During the __IAVF_INIT_EXTENDED_CAPS state, the driver will
	 * process one flag at a time during each state loop.
	 */
	u64 extended_caps;
#define IAVF_EXTENDED_CAP_SEND_VLAN_V2			BIT(0)
#define IAVF_EXTENDED_CAP_RECV_VLAN_V2			BIT(1)
#define IAVF_EXTENDED_CAP_SEND_RXDID			BIT(2)
#define IAVF_EXTENDED_CAP_RECV_RXDID			BIT(3)
#define IAVF_EXTENDED_CAP_SEND_PTP			BIT(4)
#define IAVF_EXTENDED_CAP_RECV_PTP			BIT(5)

#define IAVF_EXTENDED_CAPS				\
	(IAVF_EXTENDED_CAP_SEND_VLAN_V2 |		\
	 IAVF_EXTENDED_CAP_RECV_VLAN_V2	|		\
	 IAVF_EXTENDED_CAP_SEND_RXDID |			\
	 IAVF_EXTENDED_CAP_RECV_RXDID |			\
	 IAVF_EXTENDED_CAP_SEND_PTP |			\
	 IAVF_EXTENDED_CAP_RECV_PTP)

	/* Lock to prevent possible clobbering of
	 * current_netdev_promisc_flags
	 */
	spinlock_t current_netdev_promisc_flags_lock;
#ifdef HAVE_RHEL6_NET_DEVICE_OPS_EXT
	u32 current_netdev_promisc_flags;
#else
	netdev_features_t current_netdev_promisc_flags;
#endif /* HAVE_RHEL6_NET_DEVICE_OPS_EXT */

	/* OS defined structs */
	struct net_device *netdev;
	struct pci_dev *pdev;
	struct net_device_stats net_stats;

	struct iavf_hw hw; /* defined in iavf_type.h */

	enum iavf_state_t state;
	enum iavf_state_t last_state;
	unsigned long crit_section;

	bool netdev_registered;
	bool link_up;
	enum virtchnl_link_speed link_speed;
#ifdef VIRTCHNL_VF_CAP_ADV_LINK_SPEED
	/* This is only populated if the VIRTCHNL_VF_CAP_ADV_LINK_SPEED is set
	 * in vf_res->vf_cap_flags. Use ADV_LINK_SUPPORT macro to determine if
	 * this field is valid. This field should be used going forward and the
	 * enum virtchnl_link_speed above should be considered the legacy way of
	 * storing/communicating link speeds.
	 */
	u32 link_speed_mbps;
#endif /* VIRTCHNL_VF_CAP_ADV_LINK_SPEED */

	enum virtchnl_ops current_op;
	struct iavf_vc_msg_queue vc_msg_queue;

#define RDMA_ALLOWED(_a) ((_a)->vf_res->vf_cap_flags & \
			  VIRTCHNL_VF_CAP_RDMA)
/* RSS by the PF should be preferred over RSS via other methods. */
#define RSS_PF(_a) ((_a)->vf_res->vf_cap_flags & \
		    VIRTCHNL_VF_OFFLOAD_RSS_PF)
#define RSS_AQ(_a) ((_a)->vf_res->vf_cap_flags & \
		    VIRTCHNL_VF_OFFLOAD_RSS_AQ)
#define RSS_REG(_a) (!((_a)->vf_res->vf_cap_flags & \
		       (VIRTCHNL_VF_OFFLOAD_RSS_AQ | \
			VIRTCHNL_VF_OFFLOAD_RSS_PF)))
#define VLAN_ALLOWED(_a) ((_a)->vf_res->vf_cap_flags & \
			  VIRTCHNL_VF_OFFLOAD_VLAN)
#define VLAN_V2_ALLOWED(_a) ((_a)->vf_res->vf_cap_flags & \
			     VIRTCHNL_VF_OFFLOAD_VLAN_V2)
#define VLAN_V2_FILTERING_ALLOWED(_a) \
	(VLAN_V2_ALLOWED((_a)) && \
	 ((_a)->vlan_v2_caps.filtering.filtering_support.outer || \
	  (_a)->vlan_v2_caps.filtering.filtering_support.inner))
#define VLAN_FILTERING_ALLOWED(_a) \
	(VLAN_ALLOWED((_a)) || VLAN_V2_FILTERING_ALLOWED((_a)))
#ifdef VIRTCHNL_VF_CAP_ADV_LINK_SPEED
#define ADV_LINK_SUPPORT(_a) ((_a)->vf_res->vf_cap_flags & \
			      VIRTCHNL_VF_CAP_ADV_LINK_SPEED)
#endif /* VIRTCHNL_VF_CAP_ADV_LINK_SPEED */
#define ADQ_ALLOWED(_a) ((_a)->vf_res->vf_cap_flags & \
			  VIRTCHNL_VF_OFFLOAD_ADQ)
#define ADQ_V2_ALLOWED(_a) ((_a)->vf_res->vf_cap_flags & \
			  VIRTCHNL_VF_OFFLOAD_ADQ_V2)
#define RXDID_ALLOWED(_a) ((_a)->vf_res->vf_cap_flags & \
			   VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC)
#define PTP_ALLOWED(_a) ((_a)->vf_res->vf_cap_flags & \
			 VIRTCHNL_VF_CAP_PTP)
	struct virtchnl_vf_resource *vf_res; /* incl. all VSIs */
	struct virtchnl_vsi_resource *vsi_res; /* our LAN VSI */
	struct virtchnl_version_info pf_version;
#define PF_IS_V11(_a) (((_a)->pf_version.major == 1) && \
		       ((_a)->pf_version.minor == 1))
	struct virtchnl_vlan_caps vlan_v2_caps;
	struct virtchnl_supported_rxdids supported_rxdids;
	struct iavf_ptp ptp;
	u16 msg_enable;
	struct iavf_eth_stats current_stats;
	struct iavf_vsi vsi;
	u32 aq_wait_count;
	/* RSS stuff */
	u64 hena;
	u16 rss_key_size;
	u16 rss_lut_size;
	u8 *rss_key;
	u8 *rss_lut;
	/* ADQ related members */
	struct iavf_channel_config ch_config;
	u8 num_tc;
	struct list_head cloud_filter_list;
	/* lock to protect access to the cloud filter list */
	spinlock_t cloud_filter_list_lock;

	/* max allowed ADQ filters */
#define IAVF_MAX_CLOUD_ADQ_FILTERS 128
	u16 num_cloud_filters;
	/* snapshot of "num_active_queues" before setup_tc for qdisc add
	 * is invoked. This information is useful during qdisc del flow,
	 * to restore correct number of queues
	 */
	int orig_num_active_queues;

#ifdef IAVF_ADD_PROBES
	u64 tcp_segs;
	u64 udp_segs;
	u64 tx_tcp_cso;
	u64 tx_udp_cso;
	u64 tx_sctp_cso;
	u64 tx_ip4_cso;
	u64 tx_vlano;
	u64 tx_ad_vlano;
	u64 rx_tcp_cso;
	u64 rx_udp_cso;
	u64 rx_sctp_cso;
	u64 rx_ip4_cso;
	u64 rx_vlano;
	u64 rx_ad_vlano;
	u64 rx_tcp_cso_err;
	u64 hw_csum_rx_vxlan;
	u64 hw_csum_rx_geneve;
	u64 hw_csum_rx_outer;
	u64 rx_udp_cso_err;
	u64 rx_sctp_cso_err;
	u64 rx_ip4_cso_err;
#endif
	struct iavf_rdma rdma;
#ifdef HAVE_PF_RING
	struct {
		atomic_t usage_counter;
		u8 interrupts_required;
		bool zombie; /* interface brought down while running */
	} pfring_zc;
#endif
};

/* Ethtool Private Flags */

/* needed by iavf_ethtool.c */
extern char iavf_driver_name[];
extern const char iavf_driver_version[];
extern struct workqueue_struct *iavf_wq;
static inline const char *iavf_state_str(enum iavf_state_t state)
{
	switch (state) {
	case __IAVF_STARTUP:
		return "__IAVF_STARTUP";
	case __IAVF_REMOVE:
		return "__IAVF_REMOVE";
	case __IAVF_INIT_VERSION_CHECK:
		return "__IAVF_INIT_VERSION_CHECK";
	case __IAVF_INIT_GET_RESOURCES:
		return "__IAVF_INIT_GET_RESOURCES";
	case __IAVF_INIT_EXTENDED_CAPS:
		return "__IAVF_INIT_EXTENDED_CAPS";
	case __IAVF_INIT_CONFIG_ADAPTER:
		return "__IAVF_INIT_CONFIG_ADAPTER";
	case __IAVF_INIT_SW:
		return "__IAVF_INIT_SW";
	case __IAVF_INIT_FAILED:
		return "__IAVF_INIT_FAILED";
	case __IAVF_RESETTING:
		return "__IAVF_RESETTING";
	case __IAVF_COMM_FAILED:
		return "__IAVF_COMM_FAILED";
	case __IAVF_DOWN:
		return "__IAVF_DOWN";
	case __IAVF_DOWN_PENDING:
		return "__IAVF_DOWN_PENDING";
	case __IAVF_TESTING:
		return "__IAVF_TESTING";
	case __IAVF_RUNNING:
		return "__IAVF_RUNNING";
	default:
		return "__IAVF_UNKNOWN_STATE";
	}
}

/**
 * iavf_is_adq_enabled - adq enabled or not
 * @adapter: pointer to adapter
 *
 * This function returns true based on negotiated capability of ADQ,
 * num_tc and channel config state and channel config state is _RUNNING and ADQ
 * has been successfully configured
 **/
static inline bool iavf_is_adq_enabled(struct iavf_adapter *adapter)
{
	return (ADQ_ALLOWED(adapter) &&
		(adapter->num_tc >= IAVF_START_CHNL_TC) &&
		(adapter->ch_config.state == __IAVF_TC_RUNNING));
}

/**
 * iavf_is_adq_v2_enabled - adq v2 enabled or not
 * @adapter: pointer to adapter
 *
 * This function returns true based on negotiated capability ADQ_V2
 * if set and basic ADQ enabled
 **/
static inline bool iavf_is_adq_v2_enabled(struct iavf_adapter *adapter)
{
	return (iavf_is_adq_enabled(adapter) && ADQ_V2_ALLOWED(adapter));
}

/**
 * iavf_chnl_filters_exist - channel filters exists
 * @adapter: pointer to adapter
 *
 * This function returns true if adq_v2_enabled is true and if there
 * are active filters otherwise false
 **/
static inline bool iavf_chnl_filters_exist(struct iavf_adapter *adapter)
{
	return (iavf_is_adq_v2_enabled(adapter) &&
		adapter->num_cloud_filters) ? true : false;
}

static inline void iavf_change_state(struct iavf_adapter *adapter,
				       enum iavf_state_t state)
{
	if (adapter->state != state) {
		adapter->last_state = adapter->state;
		adapter->state = state;
	}

	dev_dbg(&adapter->pdev->dev,
		"state transition from:%s to:%s\n",
		iavf_state_str(adapter->last_state),
		iavf_state_str(adapter->state));
}

/**
 * iavf_is_reset - Check if reset has been triggered
 * @hw: pointer to iavf_hw
 *
 * Return true if reset has been already triggered, false otherwise
 *
 **/
static inline bool iavf_is_reset(struct iavf_hw *hw)
{
	return !(rd32(hw, IAVF_VF_ARQLEN1) & IAVF_VF_ARQLEN1_ARQENABLE_MASK);
}

/**
 * iavf_force_wb - Issue SW Interrupt so HW does a wb
 * @vsi: the VSI we care about
 * @q_vector: the vector  on which to force writeback
 *
 **/
static inline void iavf_force_wb(struct iavf_vsi *vsi,
				 struct iavf_q_vector *q_vector)
{
	u32 val = IAVF_VFINT_DYN_CTLN1_INTENA_MASK |
		  IAVF_VFINT_DYN_CTLN1_ITR_INDX_MASK | /* set noitr */
		  IAVF_VFINT_DYN_CTLN1_SWINT_TRIG_MASK |
		  IAVF_VFINT_DYN_CTLN1_SW_ITR_INDX_ENA_MASK
		  /* allow 00 to be written to the index */;

	if (vector_ch_ena(q_vector))
		q_vector->state_flags &= ~IAVF_VECTOR_STATE_ONCE_IN_BP;

	wr32(&vsi->back->hw,
	     INT_DYN_CTL(&vsi->back->hw, q_vector->reg_idx), val);
}

struct iavf_adapter *iavf_pdev_to_adapter(struct pci_dev *pdev);
int iavf_up(struct iavf_adapter *adapter);
void iavf_down(struct iavf_adapter *adapter);
int iavf_process_config(struct iavf_adapter *adapter);
int iavf_parse_vf_resource_msg(struct iavf_adapter *adapter);
void iavf_schedule_reset(struct iavf_adapter *adapter);
void iavf_schedule_request_stats(struct iavf_adapter *adapter);
void iavf_reset(struct iavf_adapter *adapter);
bool iavf_is_reset_in_progress(struct iavf_adapter *adapter);
bool iavf_is_remove_in_progress(struct iavf_adapter *adapter);
void iavf_set_ethtool_ops(struct net_device *netdev);
void iavf_update_stats(struct iavf_adapter *adapter);
void iavf_reset_interrupt_capability(struct iavf_adapter *adapter);
int iavf_init_interrupt_scheme(struct iavf_adapter *adapter);
void iavf_irq_enable_queues(struct iavf_adapter *adapter, u32 mask);
void iavf_free_all_tx_resources(struct iavf_adapter *adapter);
void iavf_free_all_rx_resources(struct iavf_adapter *adapter);

void iavf_napi_add_all(struct iavf_adapter *adapter);
void iavf_napi_del_all(struct iavf_adapter *adapter);

int iavf_send_api_ver(struct iavf_adapter *adapter);
int iavf_verify_api_ver(struct iavf_adapter *adapter);
int iavf_send_vf_config_msg(struct iavf_adapter *adapter);
int iavf_get_vf_config(struct iavf_adapter *adapter);
int iavf_get_vf_vlan_v2_caps(struct iavf_adapter *adapter);
int iavf_send_vf_offload_vlan_v2_msg(struct iavf_adapter *adapter);
int iavf_send_vf_supported_rxdids_msg(struct iavf_adapter *adapter);
int iavf_get_vf_supported_rxdids(struct iavf_adapter *adapter);
int iavf_send_vf_ptp_caps_msg(struct iavf_adapter *adapter);
int iavf_get_vf_ptp_caps(struct iavf_adapter *adapter);
int iavf_send_vf_ptp_pin_cfgs_msg(struct iavf_adapter *adapter);
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
int iavf_get_vf_ptp_pin_cfgs(struct iavf_adapter *adapter);
#endif /* IS_ENABLED(CONFIG_PTP_1588_CLOCK) */
void iavf_set_queue_vlan_tag_loc(struct iavf_adapter *adapter);
u16 iavf_get_num_vlans_added(struct iavf_adapter *adapter);
void iavf_irq_enable(struct iavf_adapter *adapter, bool flush);
void iavf_configure_queues(struct iavf_adapter *adapter);
void iavf_deconfigure_queues(struct iavf_adapter *adapter);
void iavf_enable_queues(struct iavf_adapter *adapter);
void iavf_disable_queues(struct iavf_adapter *adapter);
void iavf_map_queues(struct iavf_adapter *adapter);
int iavf_request_queues(struct iavf_adapter *adapter, int num);
void iavf_add_ether_addrs(struct iavf_adapter *adapter);
void iavf_del_ether_addrs(struct iavf_adapter *adapter);
void iavf_add_vlans(struct iavf_adapter *adapter);
void iavf_del_vlans(struct iavf_adapter *adapter);
void iavf_set_promiscuous(struct iavf_adapter *adapter);
bool iavf_promiscuous_mode_changed(struct iavf_adapter *adapter);
void iavf_request_stats(struct iavf_adapter *adapter);
int iavf_request_reset(struct iavf_adapter *adapter);
void iavf_get_hena(struct iavf_adapter *adapter);
void iavf_set_hena(struct iavf_adapter *adapter);
void iavf_set_rss_key(struct iavf_adapter *adapter);
void iavf_set_rss_lut(struct iavf_adapter *adapter);
void iavf_enable_vlan_stripping(struct iavf_adapter *adapter);
void iavf_disable_vlan_stripping(struct iavf_adapter *adapter);
void iavf_virtchnl_completion(struct iavf_adapter *adapter,
			      enum virtchnl_ops v_opcode,
			      enum virtchnl_status_code v_retval,
			      u8 *msg, u16 msglen);
int iavf_config_rss(struct iavf_adapter *adapter);
void iavf_enable_channels(struct iavf_adapter *adapter);
void iavf_disable_channels(struct iavf_adapter *adapter);
void iavf_add_cloud_filter(struct iavf_adapter *adapter);
void iavf_del_cloud_filter(struct iavf_adapter *adapter);
void iavf_enable_vlan_stripping_v2(struct iavf_adapter *adapter, u16 tpid);
void iavf_disable_vlan_stripping_v2(struct iavf_adapter *adapter, u16 tpid);
void iavf_enable_vlan_insertion_v2(struct iavf_adapter *adapter, u16 tpid);
void iavf_disable_vlan_insertion_v2(struct iavf_adapter *adapter, u16 tpid);
int iavf_replace_primary_mac(struct iavf_adapter *adapter,
			     const u8 *new_mac);
void iavf_send_vc_msg(struct iavf_adapter *adapter);
struct iavf_vc_msg *iavf_alloc_vc_msg(enum virtchnl_ops v_opcode, u16 msglen);
void
iavf_queue_vc_msg(struct iavf_adapter *adapter, struct iavf_vc_msg *msg);
void
iavf_flush_vc_msg_queue(struct iavf_adapter *adapter,
			bool (*op_match)(enum virtchnl_ops pending_op));
void iavf_setup_ch_info(struct iavf_adapter *adapter, u32 flags);
#ifdef HAVE_RHEL6_NET_DEVICE_OPS_EXT
void iavf_set_vlan_offload_features(struct iavf_adapter *adapter,
				    u32 prev_features,
				    u32 features);
#else
void iavf_set_vlan_offload_features(struct iavf_adapter *adapter,
				    netdev_features_t prev_features,
				    netdev_features_t features);
#endif /* HAVE_RHEL6_NET_DEVICE_OPS_EXT */
#ifdef CONFIG_DEBUG_FS
void iavf_dbg_vf_init(struct iavf_adapter *adapter);
void iavf_dbg_vf_exit(struct iavf_adapter *adapter);
void iavf_dbg_init(void);
void iavf_dbg_exit(void);
#endif /* CONFIG_DEBUG_FS*/
#endif /* _IAVF_H_ */
