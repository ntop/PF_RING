/*******************************************************************************

  Intel 10 Gigabit PCI Express Linux driver
  Copyright (c) 1999 - 2014 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#ifndef _IXGBE_H_
#define _IXGBE_H_

#ifndef IXGBE_NO_LRO
#include <net/tcp.h>
#else
#include <net/ip.h>
#endif

#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>

#ifdef SIOCETHTOOL
#include <linux/ethtool.h>
#endif
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
#include <linux/if_vlan.h>
#endif
#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
#define IXGBE_DCA
#include <linux/dca.h>
#endif
#include "ixgbe_dcb.h"

#include "kcompat.h"

#ifdef CONFIG_NET_RX_BUSY_POLL
#include <net/busy_poll.h>
#define BP_EXTENDED_STATS
#endif

#ifdef HAVE_SCTP
#include <linux/sctp.h>
#endif

#ifdef HAVE_INCLUDE_LINUX_MDIO_H
#include <linux/mdio.h>
#endif

#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
#define IXGBE_FCOE
#include "ixgbe_fcoe.h"
#endif /* CONFIG_FCOE or CONFIG_FCOE_MODULE */

#include "ixgbe_api.h"

#ifdef ENABLE_DNA
#include "../../../../kernel/linux/pf_ring.h"
#endif

#include "ixgbe_common.h"

#define PFX "ixgbe: "
#define DPRINTK(nlevel, klevel, fmt, args...) \
	((void)((NETIF_MSG_##nlevel & adapter->msg_enable) && \
	printk(KERN_##klevel PFX "%s: %s: " fmt, adapter->netdev->name, \
		__func__ , ## args)))

#ifdef HAVE_PTP_1588_CLOCK
#include <linux/clocksource.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#endif

/* TX/RX descriptor defines */
#define IXGBE_DEFAULT_TXD		512
#define IXGBE_DEFAULT_TX_WORK		256
#define IXGBE_MAX_TXD			4096
#define IXGBE_MIN_TXD			64

#define IXGBE_DEFAULT_RXD		512
#define IXGBE_DEFAULT_RX_WORK		256
#define IXGBE_MAX_RXD			4096
#define IXGBE_MIN_RXD			64

#ifdef ENABLE_DNA
#undef IXGBE_MAX_RXD
#undef IXGBE_MAX_TXD
#define IXGBE_MAX_RXD                     32768
#define IXGBE_MAX_TXD                     32768
#define DNA_IXGBE_DEFAULT_RXD              8192
#define DNA_IXGBE_DEFAULT_TXD              8192
#endif

/* flow control */
#define IXGBE_MIN_FCRTL			0x40
#define IXGBE_MAX_FCRTL			0x7FF80
#define IXGBE_MIN_FCRTH			0x600
#define IXGBE_MAX_FCRTH			0x7FFF0
#define IXGBE_DEFAULT_FCPAUSE		0xFFFF
#define IXGBE_MIN_FCPAUSE		0
#define IXGBE_MAX_FCPAUSE		0xFFFF

/* Supported Rx Buffer Sizes */
#define IXGBE_RXBUFFER_256       256  /* Used for skb receive header */
#define IXGBE_RXBUFFER_2K	2048
#define IXGBE_RXBUFFER_3K	3072
#define IXGBE_RXBUFFER_4K	4096
#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
#define IXGBE_RXBUFFER_1536	1536
#define IXGBE_RXBUFFER_7K	7168
#define IXGBE_RXBUFFER_8K	8192
#define IXGBE_RXBUFFER_15K	15360
#endif /* CONFIG_IXGBE_DISABLE_PACKET_SPLIT */
#define IXGBE_MAX_RXBUFFER	16384  /* largest size for single descriptor */

/*
 * NOTE: netdev_alloc_skb reserves up to 64 bytes, NET_IP_ALIGN means we
 * reserve 64 more, and skb_shared_info adds an additional 320 bytes more,
 * this adds up to 448 bytes of extra data.
 *
 * Since netdev_alloc_skb now allocates a page fragment we can use a value
 * of 256 and the resultant skb will have a truesize of 960 or less.
 */
#define IXGBE_RX_HDR_SIZE	IXGBE_RXBUFFER_256

#define MAXIMUM_ETHERNET_VLAN_SIZE	(VLAN_ETH_FRAME_LEN + ETH_FCS_LEN)

/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define IXGBE_RX_BUFFER_WRITE	16	/* Must be power of 2 */

enum ixgbe_tx_flags {
	/* cmd_type flags */
	IXGBE_TX_FLAGS_HW_VLAN	= 0x01,
	IXGBE_TX_FLAGS_TSO	= 0x02,
	IXGBE_TX_FLAGS_TSTAMP	= 0x04,

	/* olinfo flags */
	IXGBE_TX_FLAGS_CC	= 0x08,
	IXGBE_TX_FLAGS_IPV4	= 0x10,
	IXGBE_TX_FLAGS_CSUM	= 0x20,

	/* software defined flags */
	IXGBE_TX_FLAGS_SW_VLAN	= 0x40,
	IXGBE_TX_FLAGS_FCOE	= 0x80,
};

/* VLAN info */
#define IXGBE_TX_FLAGS_VLAN_MASK	0xffff0000
#define IXGBE_TX_FLAGS_VLAN_PRIO_MASK	0xe0000000
#define IXGBE_TX_FLAGS_VLAN_PRIO_SHIFT	29
#define IXGBE_TX_FLAGS_VLAN_SHIFT	16

#define IXGBE_MAX_RX_DESC_POLL		10

#define IXGBE_MAX_VF_MC_ENTRIES		30
#define IXGBE_MAX_VF_FUNCTIONS		64
#define IXGBE_MAX_VFTA_ENTRIES		128
#define MAX_EMULATION_MAC_ADDRS		16
#define IXGBE_MAX_PF_MACVLANS		15
#define IXGBE_82599_VF_DEVICE_ID	0x10ED
#define IXGBE_X540_VF_DEVICE_ID		0x1515

#ifdef CONFIG_PCI_IOV
#define VMDQ_P(p)	((p) + adapter->ring_feature[RING_F_VMDQ].offset)
#else
#define VMDQ_P(p)	(p)
#endif

#define UPDATE_VF_COUNTER_32bit(reg, last_counter, counter)	\
	{							\
		u32 current_counter = IXGBE_READ_REG(hw, reg);	\
		if (current_counter < last_counter)		\
			counter += 0x100000000LL;		\
		last_counter = current_counter;			\
		counter &= 0xFFFFFFFF00000000LL;		\
		counter |= current_counter;			\
	}

#define UPDATE_VF_COUNTER_36bit(reg_lsb, reg_msb, last_counter, counter) \
	{								 \
		u64 current_counter_lsb = IXGBE_READ_REG(hw, reg_lsb);	 \
		u64 current_counter_msb = IXGBE_READ_REG(hw, reg_msb);	 \
		u64 current_counter = (current_counter_msb << 32) |	 \
			current_counter_lsb;				 \
		if (current_counter < last_counter)			 \
			counter += 0x1000000000LL;			 \
		last_counter = current_counter;				 \
		counter &= 0xFFFFFFF000000000LL;			 \
		counter |= current_counter;				 \
	}

struct vf_stats {
	u64 gprc;
	u64 gorc;
	u64 gptc;
	u64 gotc;
	u64 mprc;
};
struct vf_data_storage {
	unsigned char vf_mac_addresses[ETH_ALEN];
	u16 vf_mc_hashes[IXGBE_MAX_VF_MC_ENTRIES];
	u16 num_vf_mc_hashes;
	u16 default_vf_vlan_id;
	u16 vlans_enabled;
	bool clear_to_send;
	struct vf_stats vfstats;
	struct vf_stats last_vfstats;
	struct vf_stats saved_rst_vfstats;
	bool pf_set_mac;
	u16 pf_vlan; /* When set, guest VLAN config not allowed. */
	u16 pf_qos;
	u16 tx_rate;
	u16 vlan_count;
	u8 spoofchk_enabled;
	unsigned int vf_api;
};

struct vf_macvlans {
	struct list_head l;
	int vf;
	bool free;
	bool is_macvlan;
	u8 vf_macvlan[ETH_ALEN];
};

#ifndef IXGBE_NO_LRO
#define IXGBE_LRO_MAX		32	/*Maximum number of LRO descriptors*/
#define IXGBE_LRO_GLOBAL	10

struct ixgbe_lro_stats {
	u32 flushed;
	u32 coal;
};

/*
 * ixgbe_lro_header - header format to be aggregated by LRO
 * @iph: IP header without options
 * @tcp: TCP header
 * @ts:  Optional TCP timestamp data in TCP options
 *
 * This structure relies on the check above that verifies that the header
 * is IPv4 and does not contain any options.
 */
struct ixgbe_lrohdr {
	struct iphdr iph;
	struct tcphdr th;
	__be32 ts[0];
};

struct ixgbe_lro_list {
	struct sk_buff_head active;
	struct ixgbe_lro_stats stats;
};

#endif /* IXGBE_NO_LRO */
#define IXGBE_MAX_TXD_PWR	14
#define IXGBE_MAX_DATA_PER_TXD	(1 << IXGBE_MAX_TXD_PWR)

/* Tx Descriptors needed, worst case */
#define TXD_USE_COUNT(S)	DIV_ROUND_UP((S), IXGBE_MAX_DATA_PER_TXD)
#ifndef MAX_SKB_FRAGS
#define DESC_NEEDED	4
#elif (MAX_SKB_FRAGS < 16)
#define DESC_NEEDED	((MAX_SKB_FRAGS * TXD_USE_COUNT(PAGE_SIZE)) + 4)
#else
#define DESC_NEEDED	(MAX_SKB_FRAGS + 4)
#endif

/* wrapper around a pointer to a socket buffer,
 * so a DMA handle can be stored along with the buffer */
struct ixgbe_tx_buffer {
	union ixgbe_adv_tx_desc *next_to_watch;
	unsigned long time_stamp;
	struct sk_buff *skb;
	unsigned int bytecount;
	unsigned short gso_segs;
	__be16 protocol;
#ifdef ENABLE_DNA
	dma_addr_t dma;
#else
	DEFINE_DMA_UNMAP_ADDR(dma);
#endif
	DEFINE_DMA_UNMAP_LEN(len);
	u32 tx_flags;
};

struct ixgbe_rx_buffer {
	struct sk_buff *skb;
	dma_addr_t dma;
#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
	struct page *page;
	unsigned int page_offset;
#endif
};

struct ixgbe_queue_stats {
	u64 packets;
	u64 bytes;
#ifdef BP_EXTENDED_STATS
	u64 yields;
	u64 misses;
	u64 cleaned;
#endif  /* BP_EXTENDED_STATS */
};

struct ixgbe_tx_queue_stats {
	u64 restart_queue;
	u64 tx_busy;
	u64 tx_done_old;
};

struct ixgbe_rx_queue_stats {
	u64 rsc_count;
	u64 rsc_flush;
	u64 non_eop_descs;
	u64 alloc_rx_page_failed;
	u64 alloc_rx_buff_failed;
	u64 csum_err;
};

enum ixgbe_ring_state_t {
	__IXGBE_TX_FDIR_INIT_DONE,
	__IXGBE_TX_XPS_INIT_DONE,
	__IXGBE_TX_DETECT_HANG,
	__IXGBE_HANG_CHECK_ARMED,
	__IXGBE_RX_RSC_ENABLED,
	__IXGBE_RX_CSUM_UDP_ZERO_ERR,
#ifdef IXGBE_FCOE
	__IXGBE_RX_FCOE,
#endif
};

#define check_for_tx_hang(ring) \
	test_bit(__IXGBE_TX_DETECT_HANG, &(ring)->state)
#define set_check_for_tx_hang(ring) \
	set_bit(__IXGBE_TX_DETECT_HANG, &(ring)->state)
#define clear_check_for_tx_hang(ring) \
	clear_bit(__IXGBE_TX_DETECT_HANG, &(ring)->state)
#ifndef IXGBE_NO_HW_RSC
#define ring_is_rsc_enabled(ring) \
	test_bit(__IXGBE_RX_RSC_ENABLED, &(ring)->state)
#else
#define ring_is_rsc_enabled(ring)	false
#endif
#define set_ring_rsc_enabled(ring) \
	set_bit(__IXGBE_RX_RSC_ENABLED, &(ring)->state)
#define clear_ring_rsc_enabled(ring) \
	clear_bit(__IXGBE_RX_RSC_ENABLED, &(ring)->state)
#define netdev_ring(ring) (ring->netdev)
#define ring_queue_index(ring) (ring->queue_index)


struct ixgbe_ring {
	struct ixgbe_ring *next;	/* pointer to next ring in q_vector */
	struct ixgbe_q_vector *q_vector; /* backpointer to host q_vector */
	struct net_device *netdev;	/* netdev ring belongs to */
	struct device *dev;		/* device for DMA mapping */
	void *desc;			/* descriptor ring memory */
	union {
		struct ixgbe_tx_buffer *tx_buffer_info;
		struct ixgbe_rx_buffer *rx_buffer_info;
	};
	unsigned long state;
#ifndef NO_LER_WRITE_CHECKS
	u8 __iomem **adapter_present;	/* Points to field in ixgbe_hw */
#endif /* NO_LER_WRITE_CHECKS */
	u8 __iomem *tail;
	dma_addr_t dma;			/* phys. address of descriptor ring */
	unsigned int size;		/* length in bytes */

	u16 count;			/* amount of descriptors */

	u8 queue_index; /* needed for multiqueue queue management */
	u8 reg_idx;			/* holds the special value that gets
					 * the hardware register offset
					 * associated with this ring, which is
					 * different for DCB and RSS modes
					 */
	u16 next_to_use;
	u16 next_to_clean;

#ifdef HAVE_PTP_1588_CLOCK
	unsigned long last_rx_timestamp;

#endif
	union {
#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
		u16 rx_buf_len;
#else
		u16 next_to_alloc;
#endif
		struct {
			u8 atr_sample_rate;
			u8 atr_count;
		};
	};

	u8 dcb_tc;
	struct ixgbe_queue_stats stats;
#ifdef HAVE_NDO_GET_STATS64
	struct u64_stats_sync syncp;
#endif
	union {
		struct ixgbe_tx_queue_stats tx_stats;
		struct ixgbe_rx_queue_stats rx_stats;
	};

#ifdef ENABLE_DNA
	struct {
		u8 queue_in_use, memory_allocated;
		u32 tot_packet_memory, num_memory_pages, packet_slot_len, packet_num_slots, mem_order;

		union {
			struct {
				wait_queue_head_t packet_waitqueue;
				u8                interrupt_received;
				u8                interrupt_enabled;
	
				/* Pointer to the slots where packets will be hosted */
				unsigned long     packet_memory[DNA_MAX_NUM_CHUNKS];
			} rx;
      
			struct {
				/* Pointer to the slots where packets will be hosted */
				unsigned long     packet_memory[DNA_MAX_NUM_CHUNKS];
			} tx;
		} rx_tx;
	} dna;
#endif

} ____cacheline_internodealigned_in_smp;

static inline void ixgbe_write_tail(struct ixgbe_ring *ring, u32 value)
{
#ifndef NO_LER_WRITE_CHECKS
	if (unlikely(!*ring->adapter_present))
		return;
#endif /* NO_LER_WRITE_CHECKS */
	writel(value, ring->tail);
}

enum ixgbe_ring_f_enum {
	RING_F_NONE = 0,
	RING_F_VMDQ,  /* SR-IOV uses the same ring feature */
	RING_F_RSS,
	RING_F_FDIR,
#ifdef IXGBE_FCOE
	RING_F_FCOE,
#endif /* IXGBE_FCOE */
	RING_F_ARRAY_SIZE  /* must be last in enum set */
};

#define IXGBE_MAX_DCB_INDICES		8
#define IXGBE_MAX_RSS_INDICES		16
#define IXGBE_MAX_VMDQ_INDICES		64
#define IXGBE_MAX_FDIR_INDICES		63
#ifdef IXGBE_FCOE
#define IXGBE_MAX_FCOE_INDICES	8
#define MAX_RX_QUEUES	(IXGBE_MAX_FDIR_INDICES + IXGBE_MAX_FCOE_INDICES)
#define MAX_TX_QUEUES	(IXGBE_MAX_FDIR_INDICES + IXGBE_MAX_FCOE_INDICES)
#else
#define MAX_RX_QUEUES	(IXGBE_MAX_FDIR_INDICES + 1)
#define MAX_TX_QUEUES	(IXGBE_MAX_FDIR_INDICES + 1)
#endif /* IXGBE_FCOE */
#if 0 //#ifdef ENABLE_DNA
#undef IXGBE_MAX_RSS_INDICES
#define IXGBE_MAX_RSS_INDICES MAX_RX_QUEUES
#endif
struct ixgbe_ring_feature {
	u16 limit;	/* upper limit on feature indices */
	u16 indices;	/* current value of indices */
	u16 mask;	/* Mask used for feature to ring mapping */
	u16 offset;	/* offset to start of feature */
};

#define IXGBE_82599_VMDQ_8Q_MASK 0x78
#define IXGBE_82599_VMDQ_4Q_MASK 0x7C
#define IXGBE_82599_VMDQ_2Q_MASK 0x7E

#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
/*
 * FCoE requires that all Rx buffers be over 2200 bytes in length.  Since
 * this is twice the size of a half page we need to double the page order
 * for FCoE enabled Rx queues.
 */
static inline unsigned int ixgbe_rx_bufsz(struct ixgbe_ring *ring)
{
#if MAX_SKB_FRAGS < 8
	return ALIGN(IXGBE_MAX_RXBUFFER / MAX_SKB_FRAGS, 1024);
#else
#ifdef IXGBE_FCOE
	if (test_bit(__IXGBE_RX_FCOE, &ring->state))
		return (PAGE_SIZE < 8192) ? IXGBE_RXBUFFER_4K :
					    IXGBE_RXBUFFER_3K;
#endif
	return IXGBE_RXBUFFER_2K;
#endif
}

static inline unsigned int ixgbe_rx_pg_order(struct ixgbe_ring *ring)
{
#ifdef IXGBE_FCOE
	if (test_bit(__IXGBE_RX_FCOE, &ring->state))
		return (PAGE_SIZE < 8192) ? 1 : 0;
#endif
	return 0;
}
#define ixgbe_rx_pg_size(_ring) (PAGE_SIZE << ixgbe_rx_pg_order(_ring))

#endif
struct ixgbe_ring_container {
	struct ixgbe_ring *ring;	/* pointer to linked list of rings */
	unsigned int total_bytes;	/* total bytes processed this int */
	unsigned int total_packets;	/* total packets processed this int */
	u16 work_limit;			/* total work allowed per interrupt */
	u8 count;			/* total number of rings in vector */
	u8 itr;				/* current ITR setting for ring */
};

/* iterator for handling rings in ring container */
#define ixgbe_for_each_ring(pos, head) \
	for (pos = (head).ring; pos != NULL; pos = pos->next)

#define MAX_RX_PACKET_BUFFERS	((adapter->flags & IXGBE_FLAG_DCB_ENABLED) \
				 ? 8 : 1)
#define MAX_TX_PACKET_BUFFERS	MAX_RX_PACKET_BUFFERS

/* MAX_MSIX_Q_VECTORS of these are allocated,
 * but we only use one per queue-specific vector.
 */
struct ixgbe_q_vector {
	struct ixgbe_adapter *adapter;
	int cpu;	/* CPU for DCA */
	u16 v_idx;	/* index of q_vector within array, also used for
			 * finding the bit in EICR and friends that
			 * represents the vector for this ring */
	u16 itr;	/* Interrupt throttle rate written to EITR */
	struct ixgbe_ring_container rx, tx;

	struct napi_struct napi;
#ifndef HAVE_NETDEV_NAPI_LIST
	struct net_device poll_dev;
#endif
#ifdef HAVE_IRQ_AFFINITY_HINT
	cpumask_t affinity_mask;
#endif
#ifndef IXGBE_NO_LRO
	struct ixgbe_lro_list lrolist;   /* LRO list for queue vector*/
#endif
	int numa_node;
	struct rcu_head rcu;	/* to avoid race with update stats on free */
	char name[IFNAMSIZ + 9];
	bool netpoll_rx;

#ifdef CONFIG_NET_RX_BUSY_POLL
	unsigned int state;
#define IXGBE_QV_STATE_IDLE        0
#define IXGBE_QV_STATE_NAPI	   1    /* NAPI owns this QV */
#define IXGBE_QV_STATE_POLL	   2    /* poll owns this QV */
#define IXGBE_QV_STATE_DISABLED	   4    /* QV is disabled */
#define IXGBE_QV_OWNED (IXGBE_QV_STATE_NAPI | IXGBE_QV_STATE_POLL)
#define IXGBE_QV_LOCKED (IXGBE_QV_OWNED | IXGBE_QV_STATE_DISABLED)
#define IXGBE_QV_STATE_NAPI_YIELD  8    /* NAPI yielded this QV */
#define IXGBE_QV_STATE_POLL_YIELD  16   /* poll yielded this QV */
#define IXGBE_QV_YIELD (IXGBE_QV_STATE_NAPI_YIELD | IXGBE_QV_STATE_POLL_YIELD)
#define IXGBE_QV_USER_PEND (IXGBE_QV_STATE_POLL | IXGBE_QV_STATE_POLL_YIELD)
	spinlock_t lock;
#endif  /* CONFIG_NET_RX_BUSY_POLL */

	/* for dynamic allocation of rings associated with this q_vector */
	struct ixgbe_ring ring[0] ____cacheline_internodealigned_in_smp;
};
#ifdef CONFIG_NET_RX_BUSY_POLL
static inline void ixgbe_qv_init_lock(struct ixgbe_q_vector *q_vector)
{

	spin_lock_init(&q_vector->lock);
	q_vector->state = IXGBE_QV_STATE_IDLE;
}

/* called from the device poll routine to get ownership of a q_vector */
static inline bool ixgbe_qv_lock_napi(struct ixgbe_q_vector *q_vector)
{
	int rc = true;
	spin_lock_bh(&q_vector->lock);
	if (q_vector->state & IXGBE_QV_LOCKED) {
		WARN_ON(q_vector->state & IXGBE_QV_STATE_NAPI);
		q_vector->state |= IXGBE_QV_STATE_NAPI_YIELD;
		rc = false;
#ifdef BP_EXTENDED_STATS
		q_vector->tx.ring->stats.yields++;
#endif
	} else {
		/* we don't care if someone yielded */
		q_vector->state = IXGBE_QV_STATE_NAPI;
	}
	spin_unlock_bh(&q_vector->lock);
	return rc;
}

/* returns true is someone tried to get the qv while napi had it */
static inline bool ixgbe_qv_unlock_napi(struct ixgbe_q_vector *q_vector)
{
	int rc = false;
	spin_lock_bh(&q_vector->lock);
	WARN_ON(q_vector->state & (IXGBE_QV_STATE_POLL |
			       IXGBE_QV_STATE_NAPI_YIELD));

	if (q_vector->state & IXGBE_QV_STATE_POLL_YIELD)
		rc = true;
	/* reset state to idle, unless QV is disabled */
	q_vector->state &= IXGBE_QV_STATE_DISABLED;
	spin_unlock_bh(&q_vector->lock);
	return rc;
}

/* called from ixgbe_low_latency_poll() */
static inline bool ixgbe_qv_lock_poll(struct ixgbe_q_vector *q_vector)
{
	int rc = true;
	spin_lock_bh(&q_vector->lock);
	if ((q_vector->state & IXGBE_QV_LOCKED)) {
		q_vector->state |= IXGBE_QV_STATE_POLL_YIELD;
		rc = false;
#ifdef BP_EXTENDED_STATS
		q_vector->rx.ring->stats.yields++;
#endif
	} else {
		/* preserve yield marks */
		q_vector->state |= IXGBE_QV_STATE_POLL;
	}
	spin_unlock_bh(&q_vector->lock);
	return rc;
}

/* returns true if someone tried to get the qv while it was locked */
static inline bool ixgbe_qv_unlock_poll(struct ixgbe_q_vector *q_vector)
{
	int rc = false;
	spin_lock_bh(&q_vector->lock);
	WARN_ON(q_vector->state & (IXGBE_QV_STATE_NAPI));

	if (q_vector->state & IXGBE_QV_STATE_POLL_YIELD)
		rc = true;
	/* reset state to idle, unless QV is disabled */
	q_vector->state &= IXGBE_QV_STATE_DISABLED;
	spin_unlock_bh(&q_vector->lock);
	return rc;
}

/* true if a socket is polling, even if it did not get the lock */
static inline bool ixgbe_qv_busy_polling(struct ixgbe_q_vector *q_vector)
{
	WARN_ON(!(q_vector->state & IXGBE_QV_LOCKED));
	return q_vector->state & IXGBE_QV_USER_PEND;
}

/* false if QV is currently owned */
static inline bool ixgbe_qv_disable(struct ixgbe_q_vector *q_vector)
{
	int rc = true;
	spin_lock_bh(&q_vector->lock);
	if (q_vector->state & IXGBE_QV_OWNED)
		rc = false;
	q_vector->state |= IXGBE_QV_STATE_DISABLED;
	spin_unlock_bh(&q_vector->lock);
	return rc;
}
#endif /* CONFIG_NET_RX_BUSY_POLL */
#ifdef IXGBE_HWMON

#define IXGBE_HWMON_TYPE_LOC		0
#define IXGBE_HWMON_TYPE_TEMP		1
#define IXGBE_HWMON_TYPE_CAUTION	2
#define IXGBE_HWMON_TYPE_MAX		3

struct hwmon_attr {
	struct device_attribute dev_attr;
	struct ixgbe_hw *hw;
	struct ixgbe_thermal_diode_data *sensor;
	char name[12];
};

struct hwmon_buff {
	struct device *device;
	struct hwmon_attr *hwmon_list;
	unsigned int n_hwmon;
};
#endif /* IXGBE_HWMON */

/*
 * microsecond values for various ITR rates shifted by 2 to fit itr register
 * with the first 3 bits reserved 0
 */
#define IXGBE_MIN_RSC_ITR	24
#define IXGBE_100K_ITR		40
#define IXGBE_20K_ITR		200
#define IXGBE_16K_ITR		248
#define IXGBE_10K_ITR		400
#define IXGBE_8K_ITR		500

/* ixgbe_test_staterr - tests bits in Rx descriptor status and error fields */
static inline __le32 ixgbe_test_staterr(union ixgbe_adv_rx_desc *rx_desc,
					const u32 stat_err_bits)
{
	return rx_desc->wb.upper.status_error & cpu_to_le32(stat_err_bits);
}

/* ixgbe_desc_unused - calculate if we have unused descriptors */
static inline u16 ixgbe_desc_unused(struct ixgbe_ring *ring)
{
	u16 ntc = ring->next_to_clean;
	u16 ntu = ring->next_to_use;

	return ((ntc > ntu) ? 0 : ring->count) + ntc - ntu - 1;
}

#define IXGBE_RX_DESC(R, i)	\
	(&(((union ixgbe_adv_rx_desc *)((R)->desc))[i]))
#define IXGBE_TX_DESC(R, i)	\
	(&(((union ixgbe_adv_tx_desc *)((R)->desc))[i]))
#define IXGBE_TX_CTXTDESC(R, i)	\
	(&(((struct ixgbe_adv_tx_context_desc *)((R)->desc))[i]))

#define IXGBE_MAX_JUMBO_FRAME_SIZE	9728
#ifdef IXGBE_FCOE
/* use 3K as the baby jumbo frame size for FCoE */
#define IXGBE_FCOE_JUMBO_FRAME_SIZE	3072
#endif /* IXGBE_FCOE */

#define TCP_TIMER_VECTOR	0
#define OTHER_VECTOR	1
#define NON_Q_VECTORS	(OTHER_VECTOR + TCP_TIMER_VECTOR)

#define IXGBE_MAX_MSIX_Q_VECTORS_82599	64
#define IXGBE_MAX_MSIX_Q_VECTORS_82598	16

struct ixgbe_mac_addr {
	u8 addr[ETH_ALEN];
	u16 queue;
	u16 state; /* bitmask */
};


#define IXGBE_MAC_STATE_DEFAULT		0x1
#define IXGBE_MAC_STATE_MODIFIED	0x2
#define IXGBE_MAC_STATE_IN_USE		0x4

#ifdef IXGBE_PROCFS
struct ixgbe_therm_proc_data {
	struct ixgbe_hw *hw;
	struct ixgbe_thermal_diode_data *sensor_data;
};

#endif /* IXGBE_PROCFS */
/*
 * Only for array allocations in our adapter struct.  On 82598, there will be
 * unused entries in the array, but that's not a big deal.  Also, in 82599,
 * we can actually assign 64 queue vectors based on our extended-extended
 * interrupt registers.  This is different than 82598, which is limited to 16.
 */
#define MAX_MSIX_Q_VECTORS	IXGBE_MAX_MSIX_Q_VECTORS_82599
#define MAX_MSIX_COUNT		IXGBE_MAX_MSIX_VECTORS_82599

#define MIN_MSIX_Q_VECTORS	1
#define MIN_MSIX_COUNT		(MIN_MSIX_Q_VECTORS + NON_Q_VECTORS)

/* default to trying for four seconds */
#define IXGBE_TRY_LINK_TIMEOUT	(4 * HZ)

/* board specific private data structure */
struct ixgbe_adapter {
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
#ifdef HAVE_VLAN_RX_REGISTER
	struct vlan_group *vlgrp; /* must be first, see ixgbe_receive_skb */
#else
	unsigned long active_vlans[BITS_TO_LONGS(VLAN_N_VID)];
#endif
#endif /* NETIF_F_HW_VLAN_TX || NETIF_F_HW_VLAN_CTAG_TX */
	/* OS defined structs */
	struct net_device *netdev;
	struct pci_dev *pdev;

	unsigned long state;

	/* Some features need tri-state capability,
	 * thus the additional *_CAPABLE flags.
	 */
	u32 flags;
#define IXGBE_FLAG_MSI_CAPABLE			(u32)(1 << 0)
#define IXGBE_FLAG_MSI_ENABLED			(u32)(1 << 1)
#define IXGBE_FLAG_MSIX_CAPABLE			(u32)(1 << 2)
#define IXGBE_FLAG_MSIX_ENABLED			(u32)(1 << 3)
#ifndef IXGBE_NO_LLI
#define IXGBE_FLAG_LLI_PUSH			(u32)(1 << 4)
#endif

#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
#define IXGBE_FLAG_DCA_ENABLED			(u32)(1 << 6)
#define IXGBE_FLAG_DCA_CAPABLE			(u32)(1 << 7)
#define IXGBE_FLAG_DCA_ENABLED_DATA		(u32)(1 << 8)
#else
#define IXGBE_FLAG_DCA_ENABLED			(u32)0
#define IXGBE_FLAG_DCA_CAPABLE			(u32)0
#define IXGBE_FLAG_DCA_ENABLED_DATA             (u32)0
#endif
#define IXGBE_FLAG_MQ_CAPABLE			(u32)(1 << 9)
#define IXGBE_FLAG_DCB_ENABLED			(u32)(1 << 10)
#define IXGBE_FLAG_VMDQ_ENABLED			(u32)(1 << 11)
#define IXGBE_FLAG_FAN_FAIL_CAPABLE		(u32)(1 << 12)
#define IXGBE_FLAG_NEED_LINK_UPDATE		(u32)(1 << 13)
#define IXGBE_FLAG_NEED_LINK_CONFIG		(u32)(1 << 14)
#define IXGBE_FLAG_FDIR_HASH_CAPABLE		(u32)(1 << 15)
#define IXGBE_FLAG_FDIR_PERFECT_CAPABLE		(u32)(1 << 16)
#ifdef IXGBE_FCOE
#define IXGBE_FLAG_FCOE_CAPABLE			(u32)(1 << 17)
#define IXGBE_FLAG_FCOE_ENABLED			(u32)(1 << 18)
#endif /* IXGBE_FCOE */
#define IXGBE_FLAG_SRIOV_CAPABLE		(u32)(1 << 19)
#define IXGBE_FLAG_SRIOV_ENABLED		(u32)(1 << 20)
#define IXGBE_FLAG_SRIOV_REPLICATION_ENABLE	(u32)(1 << 21)
#define IXGBE_FLAG_SRIOV_L2SWITCH_ENABLE	(u32)(1 << 22)
#define IXGBE_FLAG_SRIOV_L2LOOPBACK_ENABLE	(u32)(1 << 23)
#define IXGBE_FLAG_RX_HWTSTAMP_ENABLED          (u32)(1 << 24)

/* preset defaults */
#define IXGBE_FLAGS_82598_INIT		(IXGBE_FLAG_MSI_CAPABLE |	\
					 IXGBE_FLAG_MSIX_CAPABLE |	\
					 IXGBE_FLAG_MQ_CAPABLE)

#define IXGBE_FLAGS_82599_INIT		(IXGBE_FLAGS_82598_INIT |	\
					 IXGBE_FLAG_SRIOV_CAPABLE)

#define IXGBE_FLAGS_X540_INIT		IXGBE_FLAGS_82599_INIT


	u32 flags2;
#ifndef IXGBE_NO_HW_RSC
#define IXGBE_FLAG2_RSC_CAPABLE			(u32)(1 << 0)
#define IXGBE_FLAG2_RSC_ENABLED			(u32)(1 << 1)
#else
#define IXGBE_FLAG2_RSC_CAPABLE			0
#define IXGBE_FLAG2_RSC_ENABLED			0
#endif
#define IXGBE_FLAG2_TEMP_SENSOR_CAPABLE		(u32)(1 << 3)
#define IXGBE_FLAG2_TEMP_SENSOR_EVENT		(u32)(1 << 4)
#define IXGBE_FLAG2_SEARCH_FOR_SFP		(u32)(1 << 5)
#define IXGBE_FLAG2_SFP_NEEDS_RESET		(u32)(1 << 6)
#define IXGBE_FLAG2_RESET_REQUESTED		(u32)(1 << 7)
#define IXGBE_FLAG2_FDIR_REQUIRES_REINIT	(u32)(1 << 8)
#define IXGBE_FLAG2_RSS_FIELD_IPV4_UDP		(u32)(1 << 9)
#define IXGBE_FLAG2_RSS_FIELD_IPV6_UDP		(u32)(1 << 10)
#define IXGBE_FLAG2_PTP_PPS_ENABLED		(u32)(1 << 11)
	bool cloud_mode;

	/* Tx fast path data */
	int num_tx_queues;
	u16 tx_itr_setting;
	u16 tx_work_limit;

	/* Rx fast path data */
	int num_rx_queues;
	u16 rx_itr_setting;
	u16 rx_work_limit;

	/* TX */
	struct ixgbe_ring *tx_ring[MAX_TX_QUEUES] ____cacheline_aligned_in_smp;

	u64 restart_queue;
	u64 lsc_int;
	u32 tx_timeout_count;

	/* RX */
	struct ixgbe_ring *rx_ring[MAX_RX_QUEUES];
	int num_rx_pools;		/* == num_rx_queues in 82598 */
	int num_rx_queues_per_pool;	/* 1 if 82598, can be many if 82599 */
	u64 hw_csum_rx_error;
	u64 hw_rx_no_dma_resources;
	u64 rsc_total_count;
	u64 rsc_total_flush;
	u64 non_eop_descs;
	u32 alloc_rx_page_failed;
	u32 alloc_rx_buff_failed;

	struct ixgbe_q_vector *q_vector[MAX_MSIX_Q_VECTORS];

#ifdef HAVE_DCBNL_IEEE
	struct ieee_pfc *ixgbe_ieee_pfc;
	struct ieee_ets *ixgbe_ieee_ets;
#endif
	struct ixgbe_dcb_config dcb_cfg;
	struct ixgbe_dcb_config temp_dcb_cfg;
	u8 dcb_set_bitmap;
	u8 dcbx_cap;
#ifndef HAVE_MQPRIO
	u8 dcb_tc;
#endif
	enum ixgbe_fc_mode last_lfc_mode;

	int num_q_vectors;	/* current number of q_vectors for device */
	int max_q_vectors;	/* upper limit of q_vectors for device */
	struct ixgbe_ring_feature ring_feature[RING_F_ARRAY_SIZE];
	struct msix_entry *msix_entries;

#ifndef HAVE_NETDEV_STATS_IN_NETDEV
	struct net_device_stats net_stats;
#endif
#ifndef IXGBE_NO_LRO
	struct ixgbe_lro_stats lro_stats;
#endif

#ifdef ETHTOOL_TEST
	u32 test_icr;
	struct ixgbe_ring test_tx_ring;
	struct ixgbe_ring test_rx_ring;
#endif

	/* structs defined in ixgbe_hw.h */
	struct ixgbe_hw hw;
	u16 msg_enable;
	struct ixgbe_hw_stats stats;
#ifndef IXGBE_NO_LLI
	u32 lli_port;
	u32 lli_size;
	u32 lli_etype;
	u32 lli_vlan_pri;
#endif /* IXGBE_NO_LLI */

	u32 *config_space;
	u64 tx_busy;
	unsigned int tx_ring_count;
	unsigned int rx_ring_count;

	u32 link_speed;
	bool link_up;
	unsigned long link_check_timeout;

	struct timer_list service_timer;
	struct work_struct service_task;

	struct hlist_head fdir_filter_list;
	unsigned long fdir_overflow; /* number of times ATR was backed off */
	union ixgbe_atr_input fdir_mask;
	int fdir_filter_count;
	u32 fdir_pballoc;
	u32 atr_sample_rate;
	spinlock_t fdir_perfect_lock;

#ifdef IXGBE_FCOE
	struct ixgbe_fcoe fcoe;
#endif /* IXGBE_FCOE */
	u8 __iomem *io_addr;	/* Mainly for iounmap use */
	u32 wol;

	u16 bd_number;

	char eeprom_id[32];
	u16 eeprom_cap;
	bool netdev_registered;
	u32 interrupt_event;
#ifdef HAVE_ETHTOOL_SET_PHYS_ID
	u32 led_reg;
#endif

#ifdef HAVE_PTP_1588_CLOCK
	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_caps;
	struct work_struct ptp_tx_work;
	struct sk_buff *ptp_tx_skb;
	struct hwtstamp_config tstamp_config;
	unsigned long ptp_tx_start;
	unsigned long last_overflow_check;
	unsigned long last_rx_ptp_check;
	spinlock_t tmreg_lock;
	struct cyclecounter hw_cc;
	struct timecounter hw_tc;
	u32 base_incval;
	u32 tx_hwtstamp_timeouts;
	u32 rx_hwtstamp_cleared;
	void (*ptp_setup_sdp) (struct ixgbe_adapter *);
#endif /* HAVE_PTP_1588_CLOCK */

	DECLARE_BITMAP(active_vfs, IXGBE_MAX_VF_FUNCTIONS);
	unsigned int num_vfs;
	struct vf_data_storage *vfinfo;
	int vf_rate_link_speed;
	struct vf_macvlans vf_mvs;
	struct vf_macvlans *mv_list;
#ifdef CONFIG_PCI_IOV
	u32 timer_event_accumulator;
	u32 vferr_refcount;
#endif
	struct ixgbe_mac_addr *mac_table;
#ifdef IXGBE_SYSFS
#ifdef IXGBE_HWMON
	struct hwmon_buff ixgbe_hwmon_buff;
#endif /* IXGBE_HWMON */
#else /* IXGBE_SYSFS */
#ifdef IXGBE_PROCFS
	struct proc_dir_entry *eth_dir;
	struct proc_dir_entry *info_dir;
	u64 old_lsc;
	struct proc_dir_entry *therm_dir[IXGBE_MAX_SENSORS];
	struct ixgbe_therm_proc_data therm_data[IXGBE_MAX_SENSORS];
#endif /* IXGBE_PROCFS */
#endif /* IXGBE_SYSFS */

#ifdef HAVE_IXGBE_DEBUG_FS
	struct dentry *ixgbe_dbg_adapter;
#endif /*HAVE_IXGBE_DEBUG_FS*/
	u8 default_up;
#ifdef HAVE_TX_MQ
#ifndef HAVE_NETDEV_SELECT_QUEUE
	unsigned int indices;
#endif
#endif
#ifdef ENABLE_DNA
	struct {
		u8 dna_enabled;
	} dna;
#endif
};

static inline u8 ixgbe_max_rss_indices(struct ixgbe_adapter *adapter)
{
	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82598EB:
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		return IXGBE_MAX_RSS_INDICES;
		break;
	default:
		return 0;
		break;
	}
}

struct ixgbe_fdir_filter {
	struct  hlist_node fdir_node;
	union ixgbe_atr_input filter;
	u16 sw_idx;
	u16 action;
};

enum ixgbe_state_t {
	__IXGBE_TESTING,
	__IXGBE_RESETTING,
	__IXGBE_DOWN,
	__IXGBE_DISABLED,
	__IXGBE_REMOVE,
	__IXGBE_SERVICE_SCHED,
	__IXGBE_SERVICE_INITED,
	__IXGBE_IN_SFP_INIT,
#ifdef HAVE_PTP_1588_CLOCK
	__IXGBE_PTP_RUNNING,
#endif
};

struct ixgbe_cb {
#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
	union {				/* Union defining head/tail partner */
		struct sk_buff *head;
		struct sk_buff *tail;
	};
#endif
	dma_addr_t dma;
#ifndef IXGBE_NO_LRO
	__be32	tsecr;			/* timestamp echo response */
	u32	tsval;			/* timestamp value in host order */
	u32	next_seq;		/* next expected sequence number */
	u16	free;			/* 65521 minus total size */
	u16	mss;			/* size of data portion of packet */
#endif /* IXGBE_NO_LRO */
#ifdef HAVE_VLAN_RX_REGISTER
	u16	vid;			/* VLAN tag */
#endif
	u16	append_cnt;		/* number of skb's appended */
#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
	bool	page_released;
#endif
};
#define IXGBE_CB(skb) ((struct ixgbe_cb *)(skb)->cb)

/* ESX ixgbe CIM IOCTL definition */

#ifdef IXGBE_SYSFS
void ixgbe_sysfs_exit(struct ixgbe_adapter *adapter);
int ixgbe_sysfs_init(struct ixgbe_adapter *adapter);
#endif /* IXGBE_SYSFS */
#ifdef IXGBE_PROCFS
void ixgbe_procfs_exit(struct ixgbe_adapter *adapter);
int ixgbe_procfs_init(struct ixgbe_adapter *adapter);
int ixgbe_procfs_topdir_init(void);
void ixgbe_procfs_topdir_exit(void);
#endif /* IXGBE_PROCFS */

extern struct dcbnl_rtnl_ops dcbnl_ops;
int ixgbe_copy_dcb_cfg(struct ixgbe_adapter *adapter, int tc_max);

u8 ixgbe_dcb_txq_to_tc(struct ixgbe_adapter *adapter, u8 index);

/* needed by ixgbe_main.c */
int ixgbe_validate_mac_addr(u8 *mc_addr);
void ixgbe_check_options(struct ixgbe_adapter *adapter);
void ixgbe_assign_netdev_ops(struct net_device *netdev);

/* needed by ixgbe_ethtool.c */
extern char ixgbe_driver_name[];
extern const char ixgbe_driver_version[];

void ixgbe_up(struct ixgbe_adapter *adapter);
void ixgbe_down(struct ixgbe_adapter *adapter);
void ixgbe_reinit_locked(struct ixgbe_adapter *adapter);
void ixgbe_reset(struct ixgbe_adapter *adapter);
void ixgbe_set_ethtool_ops(struct net_device *netdev);
int ixgbe_setup_rx_resources(struct ixgbe_ring *);
int ixgbe_setup_tx_resources(struct ixgbe_ring *);
void ixgbe_free_rx_resources(struct ixgbe_ring *);
void ixgbe_free_tx_resources(struct ixgbe_ring *);
void ixgbe_configure_rx_ring(struct ixgbe_adapter *,
				    struct ixgbe_ring *);
void ixgbe_configure_tx_ring(struct ixgbe_adapter *,
				    struct ixgbe_ring *);
void ixgbe_update_stats(struct ixgbe_adapter *adapter);
int ixgbe_init_interrupt_scheme(struct ixgbe_adapter *adapter);
void ixgbe_clear_interrupt_scheme(struct ixgbe_adapter *adapter);
bool ixgbe_is_ixgbe(struct pci_dev *pcidev);
netdev_tx_t ixgbe_xmit_frame_ring(struct sk_buff *,
					 struct ixgbe_adapter *,
					 struct ixgbe_ring *);
void ixgbe_unmap_and_free_tx_resource(struct ixgbe_ring *,
					     struct ixgbe_tx_buffer *);
void ixgbe_alloc_rx_buffers(struct ixgbe_ring *, u16);
void ixgbe_configure_rscctl(struct ixgbe_adapter *adapter,
				   struct ixgbe_ring *);
void ixgbe_clear_rscctl(struct ixgbe_adapter *adapter,
			       struct ixgbe_ring *);
void ixgbe_set_rx_mode(struct net_device *netdev);
int ixgbe_write_mc_addr_list(struct net_device *netdev);
int ixgbe_setup_tc(struct net_device *dev, u8 tc);
void ixgbe_tx_ctxtdesc(struct ixgbe_ring *, u32, u32, u32, u32);
void ixgbe_do_reset(struct net_device *netdev);
void ixgbe_write_eitr(struct ixgbe_q_vector *q_vector);
int ixgbe_poll(struct napi_struct *napi, int budget);
void ixgbe_disable_rx_queue(struct ixgbe_adapter *adapter,
				   struct ixgbe_ring *);
void ixgbe_vlan_stripping_enable(struct ixgbe_adapter *adapter);
void ixgbe_vlan_stripping_disable(struct ixgbe_adapter *adapter);
#ifdef ETHTOOL_OPS_COMPAT
int ethtool_ioctl(struct ifreq *ifr);
#endif

#ifdef IXGBE_FCOE
void ixgbe_configure_fcoe(struct ixgbe_adapter *adapter);
int ixgbe_fso(struct ixgbe_ring *tx_ring,
		     struct ixgbe_tx_buffer *first,
		     u8 *hdr_len);
int ixgbe_fcoe_ddp(struct ixgbe_adapter *adapter,
			  union ixgbe_adv_rx_desc *rx_desc,
			  struct sk_buff *skb);
int ixgbe_fcoe_ddp_get(struct net_device *netdev, u16 xid,
			      struct scatterlist *sgl, unsigned int sgc);
#ifdef HAVE_NETDEV_OPS_FCOE_DDP_TARGET
int ixgbe_fcoe_ddp_target(struct net_device *netdev, u16 xid,
				 struct scatterlist *sgl, unsigned int sgc);
#endif /* HAVE_NETDEV_OPS_FCOE_DDP_TARGET */
int ixgbe_fcoe_ddp_put(struct net_device *netdev, u16 xid);
int ixgbe_setup_fcoe_ddp_resources(struct ixgbe_adapter *adapter);
void ixgbe_free_fcoe_ddp_resources(struct ixgbe_adapter *adapter);
#ifdef HAVE_NETDEV_OPS_FCOE_ENABLE
int ixgbe_fcoe_enable(struct net_device *netdev);
int ixgbe_fcoe_disable(struct net_device *netdev);
#else
int ixgbe_fcoe_ddp_enable(struct ixgbe_adapter *adapter);
void ixgbe_fcoe_ddp_disable(struct ixgbe_adapter *adapter);
#endif /* HAVE_NETDEV_OPS_FCOE_ENABLE */
#ifdef CONFIG_DCB
#ifdef HAVE_DCBNL_OPS_GETAPP
u8 ixgbe_fcoe_getapp(struct net_device *netdev);
#endif /* HAVE_DCBNL_OPS_GETAPP */
u8 ixgbe_fcoe_setapp(struct ixgbe_adapter *adapter, u8 up);
#endif /* CONFIG_DCB */
u8 ixgbe_fcoe_get_tc(struct ixgbe_adapter *adapter);
#ifdef HAVE_NETDEV_OPS_FCOE_GETWWN
int ixgbe_fcoe_get_wwn(struct net_device *netdev, u64 *wwn, int type);
#endif
#endif /* IXGBE_FCOE */

#ifdef HAVE_IXGBE_DEBUG_FS
void ixgbe_dbg_adapter_init(struct ixgbe_adapter *adapter);
void ixgbe_dbg_adapter_exit(struct ixgbe_adapter *adapter);
void ixgbe_dbg_init(void);
void ixgbe_dbg_exit(void);
#endif /* HAVE_IXGBE_DEBUG_FS */

#ifdef CONFIG_DCB
#ifdef HAVE_DCBNL_IEEE
s32 ixgbe_dcb_hw_ets(struct ixgbe_hw *hw, struct ieee_ets *ets, int max_frame);
#endif /* HAVE_DCBNL_IEEE */
#endif /* CONFIG_DCB */

int ixgbe_wol_supported(struct ixgbe_adapter *adapter, u16 device_id,
			       u16 subdevice_id);
void ixgbe_clean_rx_ring(struct ixgbe_ring *rx_ring);
int ixgbe_get_settings(struct net_device *netdev,
			      struct ethtool_cmd *ecmd);
int ixgbe_write_uc_addr_list(struct net_device *netdev, int vfn);
void ixgbe_full_sync_mac_table(struct ixgbe_adapter *adapter);
int ixgbe_add_mac_filter(struct ixgbe_adapter *adapter,
				u8 *addr, u16 queue);
int ixgbe_del_mac_filter(struct ixgbe_adapter *adapter,
				u8 *addr, u16 queue);
int ixgbe_available_rars(struct ixgbe_adapter *adapter);
#ifndef HAVE_VLAN_RX_REGISTER
void ixgbe_vlan_mode(struct net_device *, u32);
#endif

#ifdef HAVE_PTP_1588_CLOCK
void ixgbe_ptp_init(struct ixgbe_adapter *adapter);
void ixgbe_ptp_stop(struct ixgbe_adapter *adapter);
void ixgbe_ptp_overflow_check(struct ixgbe_adapter *adapter);
void ixgbe_ptp_rx_hang(struct ixgbe_adapter *adapter);
void ixgbe_ptp_rx_rgtstamp(struct ixgbe_q_vector *q_vector,
				  struct sk_buff *skb);
static inline void ixgbe_ptp_rx_hwtstamp(struct ixgbe_ring *rx_ring,
					 union ixgbe_adv_rx_desc *rx_desc,
					 struct sk_buff *skb)
{

	if (unlikely(!ixgbe_test_staterr(rx_desc, IXGBE_RXDADV_STAT_TS)))
		return;

	ixgbe_ptp_rx_rgtstamp(rx_ring->q_vector, skb);

	/* Update the last_rx_timestamp timer in order to enable watchdog check
	 * for error case of latched timestamp on a dropped packet.
	 */
	rx_ring->last_rx_timestamp = jiffies;
}

int ixgbe_ptp_get_ts_config(struct ixgbe_adapter *adapter, struct ifreq *ifr);
int ixgbe_ptp_set_ts_config(struct ixgbe_adapter *adapter, struct ifreq *ifr);
void ixgbe_ptp_start_cyclecounter(struct ixgbe_adapter *adapter);
void ixgbe_ptp_reset(struct ixgbe_adapter *adapter);
void ixgbe_ptp_check_pps_event(struct ixgbe_adapter *adapter, u32 eicr);
#endif /* HAVE_PTP_1588_CLOCK */
#ifdef CONFIG_PCI_IOV
void ixgbe_sriov_reinit(struct ixgbe_adapter *adapter);
#endif

void ixgbe_set_rx_drop_en(struct ixgbe_adapter *adapter);
#endif /* _IXGBE_H_ */
