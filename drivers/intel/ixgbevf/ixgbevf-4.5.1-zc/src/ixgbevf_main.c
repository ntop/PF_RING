// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 1999 - 2018 Intel Corporation. */


/******************************************************************************
 Copyright (c)2006 - 2007 Myricom, Inc. for some LRO specific code
******************************************************************************/
#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <linux/sctp.h>
#ifdef NETIF_F_TSO
#include <net/checksum.h>
#ifdef NETIF_F_TSO6
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#endif
#endif
#ifdef SIOCETHTOOL
#include <linux/ethtool.h>
#endif
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
#include <linux/if_vlan.h>
#endif

#include "ixgbevf.h"

#ifdef HAVE_PF_RING
#include "pf_ring.h"

static unsigned int enable_debug = 0;
module_param(enable_debug, uint, 0644);
MODULE_PARM_DESC(enable_debug, "Set to 1 to enable debug tracing into the syslog");
#endif

#ifdef HAVE_XDP_SUPPORT
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/atomic.h>

#endif /* HAVE_XDP_SUPPORT */
#define RELEASE_TAG

#define DRV_VERSION __stringify(4.5.1) RELEASE_TAG
#define DRV_SUMMARY __stringify(Intel(R) 10GbE PCI Express Virtual Function Driver)
const char ixgbevf_driver_version[] = DRV_VERSION;
char ixgbevf_driver_name[] = "ixgbevf";
static const char ixgbevf_driver_string[] = DRV_SUMMARY;
static const char ixgbevf_copyright[] = "Copyright(c) 1999 - 2018 Intel Corporation.";

static struct ixgbevf_info ixgbevf_82599_vf_info = {
	.mac	= ixgbe_mac_82599_vf,
	.flags	= 0,
};

static struct ixgbevf_info ixgbevf_X540_vf_info = {
	.mac	= ixgbe_mac_X540_vf,
	.flags	= 0,
};

static struct ixgbevf_info ixgbevf_X550_vf_info = {
	.mac	= ixgbe_mac_X550_vf,
	.flags	= 0,
};

static struct ixgbevf_info ixgbevf_X550EM_x_vf_info = {
	.mac	= ixgbe_mac_X550EM_x_vf,
	.flags	= 0,
};

static struct ixgbevf_info ixgbevf_X550EM_a_vf_info = {
	.mac	= ixgbe_mac_X550EM_a_vf,
	.flags	= 0,
};

enum ixgbevf_boards {
	board_82599_vf,
	board_X540_vf,
	board_X550_vf,
	board_X550EM_x_vf,
	board_X550EM_a_vf,
};

static const struct ixgbevf_info *ixgbevf_info_tbl[] = {
	[board_82599_vf]	= &ixgbevf_82599_vf_info,
	[board_X540_vf]		= &ixgbevf_X540_vf_info,
	[board_X550_vf]		= &ixgbevf_X550_vf_info,
	[board_X550EM_x_vf]	= &ixgbevf_X550EM_x_vf_info,
	[board_X550EM_a_vf]	= &ixgbevf_X550EM_a_vf_info,
};

/* ixgbevf_pci_tbl - PCI Device ID Table
 *
 * Wildcard entries (PCI_ANY_ID) should come last
 * Last entry must be all 0s
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
static struct pci_device_id ixgbevf_pci_tbl[] = {
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_VF), board_82599_vf },
#if IS_ENABLED(CONFIG_PCI_HYPERV)
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_VF_HV), board_82599_vf },
#endif
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X540_VF), board_X540_vf },
#if IS_ENABLED(CONFIG_PCI_HYPERV)
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X540_VF_HV), board_X540_vf },
#endif
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X550_VF), board_X550_vf },
#if IS_ENABLED(CONFIG_PCI_HYPERV)
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X550_VF_HV), board_X550_vf },
#endif
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X550EM_X_VF), board_X550EM_x_vf },
#if IS_ENABLED(CONFIG_PCI_HYPERV)
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X550EM_X_VF_HV), board_X550EM_x_vf },
#endif
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X550EM_A_VF), board_X550EM_a_vf },
#if IS_ENABLED(CONFIG_PCI_HYPERV)
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X550EM_A_VF_HV), board_X550EM_a_vf },
#endif
	/* required last entry */
	{ .device = 0 }
};
MODULE_DEVICE_TABLE(pci, ixgbevf_pci_tbl);

MODULE_AUTHOR("Intel Corporation, <linux.nics@intel.com>");
MODULE_DESCRIPTION("Intel(R) 10 Gigabit Virtual Function Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

#define DEFAULT_DEBUG_LEVEL_SHIFT 3

static void ixgbevf_service_event_schedule(struct ixgbevf_adapter *adapter)
{
	if (!test_bit(__IXGBEVF_DOWN, &adapter->state) &&
	    !test_bit(__IXGBEVF_REMOVING, &adapter->state) &&
	    !test_and_set_bit(__IXGBEVF_SERVICE_SCHED, &adapter->state))
		schedule_work(&adapter->service_task);
}

static void ixgbevf_service_event_complete(struct ixgbevf_adapter *adapter)
{
	BUG_ON(!test_bit(__IXGBEVF_SERVICE_SCHED, &adapter->state));

	/* flush memory to make sure state is correct before next watchdog */
	smp_mb__before_atomic();
	clear_bit(__IXGBEVF_SERVICE_SCHED, &adapter->state);
}

/* forward decls */
static void ixgbevf_queue_reset_subtask(struct ixgbevf_adapter *adapter);
static void ixgbevf_set_itr(struct ixgbevf_q_vector *q_vector);
static void ixgbevf_free_all_rx_resources(struct ixgbevf_adapter *adapter);
static bool ixgbevf_can_reuse_rx_page(struct ixgbevf_rx_buffer *rx_buffer);
static void ixgbevf_reuse_rx_page(struct ixgbevf_ring *rx_ring,
				  struct ixgbevf_rx_buffer *old_buff);

static void ixgbevf_remove_adapter(struct ixgbe_hw *hw)
{
	struct ixgbevf_adapter *adapter = hw->back;

	if (IXGBE_REMOVED(hw->hw_addr))
		return;
	hw->hw_addr = NULL;
	DPRINTK(DRV, ERR, "Adapter removed\n");
	if (test_bit(__IXGBEVF_SERVICE_INITED, &adapter->state))
		ixgbevf_service_event_schedule(adapter);
}

static void ixgbevf_check_remove(struct ixgbe_hw *hw, u32 reg)
{
       u32 value;

       /* The following check not only optimizes a bit by not
        * performing a read on the status register when the
        * register just read was a status register read that
        * returned IXGBE_FAILED_READ_REG. It also blocks any
        * potential recursion.
        */
       if (reg == IXGBE_VFSTATUS) {
               ixgbevf_remove_adapter(hw);
               return;
       }
       value = IXGBE_READ_REG(hw, IXGBE_VFSTATUS);
       if (value == IXGBE_FAILED_READ_REG)
               ixgbevf_remove_adapter(hw);
}

static u32 ixgbevf_validate_register_read(struct ixgbe_hw *hw, u32 reg)
{
	int i;
	u32 value;
	u8 __iomem *reg_addr;

	reg_addr = READ_ONCE(hw->hw_addr);
	if (IXGBE_REMOVED(reg_addr))
		return IXGBE_FAILED_READ_REG;
	for (i = 0; i < IXGBE_DEAD_READ_RETRIES; ++i) {
		value = readl(reg_addr + reg);
		if (value != IXGBE_DEAD_READ_REG)
			break;
	}
	if (value == IXGBE_DEAD_READ_REG)
		pr_info("%s: register %x read unchanged\n", __func__, reg);
	else
		pr_info("%s: register %x read recovered after %d retries\n",
			__func__, reg, i + 1);
	return value;
}

u32 ixgbe_read_reg(struct ixgbe_hw *hw, u32 reg)
{
	u32 value;
	u8 __iomem *reg_addr;

	reg_addr = READ_ONCE(hw->hw_addr);
	if (IXGBE_REMOVED(reg_addr))
		return IXGBE_FAILED_READ_REG;
	value = readl(reg_addr + reg);
	if (unlikely(value == IXGBE_FAILED_READ_REG))
		ixgbevf_check_remove(hw, reg);
	if (unlikely(value == IXGBE_DEAD_READ_REG))
		value = ixgbevf_validate_register_read(hw, reg);
	return value;
}

static u64 ixgbevf_get_tx_completed(struct ixgbevf_ring *ring)
{
	return ring->stats.packets;
}

#if IS_ENABLED(CONFIG_PCI_HYPERV)
/**
 * ixgbevf_hv_set_rar_vf - set device MAC address Hyper-V variant
 * @hw: pointer to hardware structure
 * @index: Receive address register to write
 * @addr: Address to put into receive address register
 * @vmdq: Unused in this implementation
 * @enable_addr: Unused in this implementation
 *
 * We don't really allow setting the device MAC address. However,
 * if the address being set is the permanent MAC address we will
 * permit that.
 **/
s32 ixgbevf_hv_set_rar_vf(struct ixgbe_hw *hw, u32 index, u8 *addr,
			  u32 vmdq, u32 enable_addr)
{
	if (ether_addr_equal(addr, hw->mac.perm_addr))
		return 0;

	return -EOPNOTSUPP;
}

/**
 * Hyper-V variant; the VF/PF communication is through the PCI
 * config space.
 * @hw: pointer to hardware structure
 */
s32 ixgbevf_hv_reset_hw_vf(struct ixgbe_hw *hw)
{
	struct ixgbevf_adapter *adapter = hw->back;
#if IS_ENABLED(CONFIG_PCI_MMCONFIG)
	int i;

	for (i = 0; i < 6; i++)
		pci_read_config_byte(adapter->pdev,
				     (i + IXGBE_HV_RESET_OFFSET),
				     &hw->mac.perm_addr[i]);
	return 0;
#else

	dev_err(&adapter->pdev->dev,
		"PCI_MMCONFIG needs to be enabled for Hyper-V\n");
	return -EOPNOTSUPP;
#endif
}

#endif
static u32 ixgbevf_get_tx_pending(struct ixgbevf_ring *ring)
{
	struct ixgbevf_adapter *adapter = netdev_priv(ring->netdev);
	struct ixgbe_hw *hw = &adapter->hw;

	u32 head = IXGBE_READ_REG(hw, IXGBE_VFTDH(ring->reg_idx));
	u32 tail = IXGBE_READ_REG(hw, IXGBE_VFTDT(ring->reg_idx));

	if (head != tail)
		return (head < tail) ?
			tail - head : (tail + ring->count - head);

	return 0;
}

static inline bool ixgbevf_check_tx_hang(struct ixgbevf_ring *tx_ring)
{
	u32 tx_done = ixgbevf_get_tx_completed(tx_ring);
	u32 tx_done_old = tx_ring->tx_stats.tx_done_old;
	u32 tx_pending = ixgbevf_get_tx_pending(tx_ring);

	clear_check_for_tx_hang(tx_ring);

	/*
	 * Check for a hung queue, but be thorough. This verifies
	 * that a transmit has been completed since the previous
	 * check AND there is at least one packet pending. The
	 * ARMED bit is set to indicate a potential hang.
	 */
	if ((tx_done_old == tx_done) && tx_pending) {
		/* make sure it is true for two checks in a row */
		return test_and_set_bit(__IXGBEVF_HANG_CHECK_ARMED,
					&tx_ring->state);
	}
	/* reset the countdown */
	clear_bit(__IXGBEVF_HANG_CHECK_ARMED, &tx_ring->state);

	/* update completed stats and continue */
	tx_ring->tx_stats.tx_done_old = tx_done;

	return false;
}

static void ixgbevf_tx_timeout_reset(struct ixgbevf_adapter *adapter)
{

#ifdef HAVE_PF_RING
	/* tx hang detected while in use from userspace (this is expected),
	 * avoid card reset while application is running on top of ZC */
	if (atomic_read(&adapter->pfring_zc.usage_counter) > 0)
		return;
#endif	

	/* Do the reset outside of interrupt context */
	if (!test_bit(__IXGBEVF_DOWN, &adapter->state)) {
		set_bit(__IXGBEVF_RESET_REQUESTED, &adapter->state);
		ixgbevf_service_event_schedule(adapter);
	}
}

/**
 * ixgbevf_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 **/
static void ixgbevf_tx_timeout(struct net_device *netdev)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);

	ixgbevf_tx_timeout_reset(adapter);
}


/**
 * ixgbevf_clean_tx_irq - Reclaim resources after transmit completes
 * @q_vector: board private structure
 * @tx_ring: tx ring to clean
 * @napi_budget: Used to determine if we are in netpoll
 **/
static bool ixgbevf_clean_tx_irq(struct ixgbevf_q_vector *q_vector,
				 struct ixgbevf_ring *tx_ring, int napi_budget)
{
	struct ixgbevf_adapter *adapter = q_vector->adapter;
	struct ixgbevf_tx_buffer *tx_buffer;
	union ixgbe_adv_tx_desc *tx_desc;
	unsigned int total_bytes = 0, total_packets = 0;
	unsigned int budget = tx_ring->count / 2;
	unsigned int i = tx_ring->next_to_clean;

#ifdef HAVE_PF_RING
	if (atomic_read(&adapter->pfring_zc.usage_counter) > 0)
		return true;
#endif

	if (test_bit(__IXGBEVF_DOWN, &adapter->state))
		return true;

	tx_buffer = &tx_ring->tx_buffer_info[i];
	tx_desc = IXGBEVF_TX_DESC(tx_ring, i);
	i -= tx_ring->count;

	do {
		union ixgbe_adv_tx_desc *eop_desc = tx_buffer->next_to_watch;

		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc)
			break;

		/* prevent any other reads prior to eop_desc */
		smp_rmb();

		/* if DD is not set pending work has not been completed */
		if (!(eop_desc->wb.status & cpu_to_le32(IXGBE_TXD_STAT_DD)))
			break;

		/* clear next_to_watch to prevent false hangs */
		tx_buffer->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buffer->bytecount;
		total_packets += tx_buffer->gso_segs;

		/* free the skb */
#ifdef HAVE_XDP_SUPPORT
		if (ring_is_xdp(tx_ring))
			page_frag_free(tx_buffer->data);
		else
			napi_consume_skb(tx_buffer->skb, napi_budget);
#else
		napi_consume_skb(tx_buffer->skb, napi_budget);
#endif

		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buffer, dma),
				 dma_unmap_len(tx_buffer, len),
				 DMA_TO_DEVICE);

		/* clear tx_buffer data */
		dma_unmap_len_set(tx_buffer, len, 0);

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			tx_buffer++;
			tx_desc++;
			i++;
			if (unlikely(!i)) {
				i -= tx_ring->count;
				tx_buffer = tx_ring->tx_buffer_info;
				tx_desc = IXGBEVF_TX_DESC(tx_ring, 0);
			}

			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buffer, len)) {
				dma_unmap_page(tx_ring->dev,
					       dma_unmap_addr(tx_buffer, dma),
					       dma_unmap_len(tx_buffer, len),
					       DMA_TO_DEVICE);
				dma_unmap_len_set(tx_buffer, len, 0);
			}
		}

		/* move us one more past the eop_desc for start of next pkt */
		tx_buffer++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->count;
			tx_buffer = tx_ring->tx_buffer_info;
			tx_desc = IXGBEVF_TX_DESC(tx_ring, 0);
		}

		/* issue prefetch for next Tx descriptor */
		prefetch(tx_desc);

		/* update budget accounting */
		budget--;
	} while (likely(budget));

	i += tx_ring->count;
	tx_ring->next_to_clean = i;
	u64_stats_update_begin(&tx_ring->syncp);
	tx_ring->stats.bytes += total_bytes;
	tx_ring->stats.packets += total_packets;
	u64_stats_update_end(&tx_ring->syncp);
	q_vector->tx.total_bytes += total_bytes;
	q_vector->tx.total_packets += total_packets;

	if (check_for_tx_hang(tx_ring) && ixgbevf_check_tx_hang(tx_ring)) {
		struct ixgbe_hw *hw = &adapter->hw;
		union ixgbe_adv_tx_desc *eop_desc;

		eop_desc = tx_ring->tx_buffer_info[i].next_to_watch;

		pr_err("Detected Tx Unit Hang%s\n"
		       "  Tx Queue             <%d>\n"
		       "  TDH, TDT             <%x>, <%x>\n"
		       "  next_to_use          <%x>\n"
		       "  next_to_clean        <%x>\n"
		       "tx_buffer_info[next_to_clean]\n"
		       "  next_to_watch	       <%p>\n"
		       "  eop_desc->wb.status  <%x>\n"
		       "  time_stamp           <%lx>\n"
		       "  jiffies              <%lx>\n",
		       ring_is_xdp(tx_ring) ? " XDP" : "",
		       tx_ring->queue_index,
		       IXGBE_READ_REG(hw, IXGBE_VFTDH(tx_ring->reg_idx)),
		       IXGBE_READ_REG(hw, IXGBE_VFTDT(tx_ring->reg_idx)),
		       tx_ring->next_to_use, i,
		       eop_desc, (eop_desc ? eop_desc->wb.status : 0),
		       tx_ring->tx_buffer_info[i].time_stamp, jiffies);

		if (!ring_is_xdp(tx_ring))
			netif_stop_subqueue(tx_ring->netdev,
					    tx_ring->queue_index);

		/* schedule immediate reset if we believe we hung */
		ixgbevf_tx_timeout_reset(adapter);

		return true;
	}

	if (ring_is_xdp(tx_ring))
		return !!budget;

	netdev_tx_completed_queue(txring_txq(tx_ring),
				  total_packets, total_bytes);

#define TX_WAKE_THRESHOLD (DESC_NEEDED * 2)
	if (unlikely(total_packets && netif_carrier_ok(tx_ring->netdev) &&
		     (ixgbevf_desc_unused(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();
#ifdef HAVE_TX_MQ
		if (__netif_subqueue_stopped(tx_ring->netdev,
					     tx_ring->queue_index) &&
		    !test_bit(__IXGBEVF_DOWN, &adapter->state)) {
			netif_wake_subqueue(tx_ring->netdev,
					    tx_ring->queue_index);
			++tx_ring->tx_stats.restart_queue;
		}
#else
		if (netif_queue_stopped(tx_ring->netdev) &&
		    !test_bit(__IXGBEVF_DOWN, &adapter->state)) {
			netif_wake_queue(tx_ring->netdev);
			++tx_ring->tx_stats.restart_queue;
		}
#endif
	}

	return !!budget;
}

#ifdef HAVE_VLAN_RX_REGISTER
static void ixgbevf_rx_vlan(struct ixgbevf_ring *rx_ring,
			    union ixgbe_adv_rx_desc *rx_desc,
			    struct sk_buff *skb)
{
	struct net_device *dev = rx_ring->netdev;

#ifdef NETIF_F_HW_VLAN_CTAG_RX
	if ((dev->features & NETIF_F_HW_VLAN_CTAG_RX) &&
#else
	if ((dev->features & NETIF_F_HW_VLAN_RX) &&
#endif
	    ixgbevf_test_staterr(rx_desc, IXGBE_RXD_STAT_VP))
		IXGBE_CB(skb)->vid = le16_to_cpu(rx_desc->wb.upper.vlan);
	else
		IXGBE_CB(skb)->vid = 0;
}

/**
 * ixgbevf_receive_skb - Send a completed packet up the stack
 * @q_vector: structure containing interrupt and ring information
 * @skb: packet to send up
 **/
static void ixgbevf_receive_skb(struct ixgbevf_q_vector *q_vector,
				struct sk_buff *skb)
{
	struct ixgbevf_adapter *adapter = q_vector->adapter;
	u16 vlan_tag = IXGBE_CB(skb)->vid;
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	struct vlan_group **vlgrp = &adapter->vlgrp;

	if (vlan_tag & VLAN_VID_MASK && *vlgrp != NULL) {

		if (q_vector->netpoll_rx)
			vlan_hwaccel_rx(skb, *vlgrp, vlan_tag);
		else
			vlan_gro_receive(&q_vector->napi,
					 *vlgrp, vlan_tag, skb);
	} else {
#endif /* NETIF_F_HW_VLAN_TX || NETIF_F_HW_CLAN_CTAG_TX */
		if (q_vector->netpoll_rx)
			netif_rx(skb);
		else
			napi_gro_receive(&q_vector->napi, skb);
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	}
#endif /* NETIF_F_HW_VLAN_TX || NETIF_F_HW_CLAN_CTAG_TX */
}
#endif /* HAVE_VLAN_RX_REGISTER */

/**
 * ixgbevf_rx_skb - Helper function to determine proper Rx method
 * @q_vector: structure containing interrupt and ring information
 * @skb: packet to send up
 **/
static void ixgbevf_rx_skb(struct ixgbevf_q_vector *q_vector,
			   struct sk_buff *skb)
{
#ifdef HAVE_NDO_BUSY_POLL
	skb_mark_napi_id(skb, &q_vector->napi);

	if (ixgbevf_qv_busy_polling(q_vector) || q_vector->netpoll_rx) {
		netif_receive_skb(skb);
		/* exit early if we busy polled */
		return;
	}
#endif /* HAVE_NDO_BUSY_POLL */
#ifdef HAVE_VLAN_RX_REGISTER
	ixgbevf_receive_skb(q_vector, skb);
#else
#ifndef HAVE_NDO_BUSY_POLL
	if (q_vector->netpoll_rx)
		netif_rx(skb);
	else
#endif
		napi_gro_receive(&q_vector->napi, skb);

#endif
#ifndef NETIF_F_GRO
	q_vector->adapter->netdev->last_rx = jiffies;
#endif
}

#ifdef NETIF_F_RXHASH
#define IXGBE_RSS_L4_TYPES_MASK \
	((1ul << IXGBE_RXDADV_RSSTYPE_IPV4_TCP) | \
	 (1ul << IXGBE_RXDADV_RSSTYPE_IPV4_UDP) | \
	 (1ul << IXGBE_RXDADV_RSSTYPE_IPV6_TCP) | \
	 (1ul << IXGBE_RXDADV_RSSTYPE_IPV6_UDP))

static inline void ixgbevf_rx_hash(struct ixgbevf_ring *ring,
				   union ixgbe_adv_rx_desc *rx_desc,
				   struct sk_buff *skb)
{
	u16 rss_type;

	if (!(ring->netdev->features & NETIF_F_RXHASH))
		return;

	rss_type = le16_to_cpu(rx_desc->wb.lower.lo_dword.hs_rss.pkt_info) &
		   IXGBE_RXDADV_RSSTYPE_MASK;

	if (!rss_type)
		return;

	skb_set_hash(skb, le32_to_cpu(rx_desc->wb.lower.hi_dword.rss),
		     (IXGBE_RSS_L4_TYPES_MASK & (1ul << rss_type)) ?
		     PKT_HASH_TYPE_L4 : PKT_HASH_TYPE_L3);
}
#endif /* NETIF_F_RXHASH */

/**
 * ixgbevf_rx_checksum - indicate in skb if hw indicated a good cksum
 * @ring: structure containig ring specific data
 * @rx_desc: current Rx descriptor being processed
 * @skb: skb currently being received and modified
 */
static inline void ixgbevf_rx_checksum(struct ixgbevf_ring *ring,
				       union ixgbe_adv_rx_desc *rx_desc,
				       struct sk_buff *skb)
{
	skb_checksum_none_assert(skb);

	/* Rx csum disabled */
	if (!(ring->netdev->features & NETIF_F_RXCSUM))
		return;

	/* if IP and error */
	if (ixgbevf_test_staterr(rx_desc, IXGBE_RXD_STAT_IPCS) &&
	    ixgbevf_test_staterr(rx_desc, IXGBE_RXDADV_ERR_IPE)) {
		ring->rx_stats.csum_err++;
		return;
	}

	if (!ixgbevf_test_staterr(rx_desc, IXGBE_RXD_STAT_L4CS))
		return;

	if (ixgbevf_test_staterr(rx_desc, IXGBE_RXDADV_ERR_TCPE)) {
		__le16 pkt_info = rx_desc->wb.lower.lo_dword.hs_rss.pkt_info;

		/* 82599 errata, UDP frames with a 0 checksum can be marked as
		 * checksum errors.
		 */
		if ((pkt_info & cpu_to_le16(IXGBE_RXDADV_PKTTYPE_UDP)) &&
		    test_bit(__IXGBEVF_RX_CSUM_UDP_ZERO_ERR, &ring->state))
			return;

		ring->rx_stats.csum_err++;
		return;
	}

	/* It must be a TCP or UDP packet with a valid checksum */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
}

/**
 * ixgbevf_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being populated
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the checksum, VLAN, protocol, and other fields within
 * the skb.
 */
static void ixgbevf_process_skb_fields(struct ixgbevf_ring *rx_ring,
				       union ixgbe_adv_rx_desc *rx_desc,
				       struct sk_buff *skb)
{
#ifdef NETIF_F_RXHASH
	ixgbevf_rx_hash(rx_ring, rx_desc, skb);
#endif /* NETIF_F_RXHASH */
	ixgbevf_rx_checksum(rx_ring, rx_desc, skb);
#ifdef HAVE_VLAN_RX_REGISTER
	ixgbevf_rx_vlan(rx_ring, rx_desc, skb);
#else
	if (ixgbevf_test_staterr(rx_desc, IXGBE_RXD_STAT_VP)) {
		u16 vid = le16_to_cpu(rx_desc->wb.upper.vlan);
		unsigned long *active_vlans = netdev_priv(rx_ring->netdev);

		if (test_bit(vid & VLAN_VID_MASK, active_vlans))
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), vid);
	}
#endif

	skb->protocol = eth_type_trans(skb, rx_ring->netdev);
}

static
struct ixgbevf_rx_buffer *ixgbevf_get_rx_buffer(struct ixgbevf_ring *rx_ring,
						const unsigned int size)
{
	struct ixgbevf_rx_buffer *rx_buffer;

	rx_buffer = &rx_ring->rx_buffer_info[rx_ring->next_to_clean];
	prefetchw(rx_buffer->page);

	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(rx_ring->dev,
				      rx_buffer->dma,
				      rx_buffer->page_offset,
				      size,
				      DMA_FROM_DEVICE);

	rx_buffer->pagecnt_bias--;

	return rx_buffer;
}

static void ixgbevf_put_rx_buffer(struct ixgbevf_ring *rx_ring,
				  struct ixgbevf_rx_buffer *rx_buffer,
				  struct sk_buff *skb)
{
#if defined(HAVE_STRUCT_DMA_ATTRS) && defined(HAVE_SWIOTLB_SKIP_CPU_SYNC)
	DEFINE_DMA_ATTRS(attrs);

	dma_set_attr(DMA_ATTR_SKIP_CPU_SYNC, &attrs);
	dma_set_attr(DMA_ATTR_WEAK_ORDERING, &attrs);

#endif
	if (ixgbevf_can_reuse_rx_page(rx_buffer)) {
		/* hand second half of page back to the ring */
		ixgbevf_reuse_rx_page(rx_ring, rx_buffer);
	} else {
		if (IS_ERR(skb))
			/* We are not reusing the buffer so unmap it and free
			 * any references we are holding to it
			 */
			dma_unmap_page_attrs(rx_ring->dev, rx_buffer->dma,
					     ixgbevf_rx_pg_size(rx_ring),
					     DMA_FROM_DEVICE,
#if defined(HAVE_STRUCT_DMA_ATTRS) && defined(HAVE_SWIOTLB_SKIP_CPU_SYNC)
					     &attrs);
#else
					     IXGBEVF_RX_DMA_ATTR);
#endif
		__page_frag_cache_drain(rx_buffer->page,
					rx_buffer->pagecnt_bias);
	}

	/* clear contents of rx_buffer */
	rx_buffer->page = NULL;
}

/**
 * ixgbevf_is_non_eop - process handling of non-EOP buffers
 * @rx_ring: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 *
 * This function updates next to clean.  If the buffer is an EOP buffer
 * this function exits returning false, otherwise it will place the
 * sk_buff in the next buffer to be chained and return true indicating
 * that this is in fact a non-EOP buffer.
 **/
static bool ixgbevf_is_non_eop(struct ixgbevf_ring *rx_ring,
			       union ixgbe_adv_rx_desc *rx_desc)
{
	u32 ntc = rx_ring->next_to_clean + 1;

	/* fetch, update, and store next to clean */
	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;

	prefetch(IXGBEVF_RX_DESC(rx_ring, ntc));

	if (likely(ixgbevf_test_staterr(rx_desc, IXGBE_RXD_STAT_EOP)))
		return false;

	return true;
}

static inline unsigned int ixgbevf_rx_offset(struct ixgbevf_ring *rx_ring)
{
	return ring_uses_build_skb(rx_ring) ? IXGBEVF_SKB_PAD : 0;
}

static bool ixgbevf_alloc_mapped_page(struct ixgbevf_ring *rx_ring,
				      struct ixgbevf_rx_buffer *bi)
{
	struct page *page = bi->page;
	dma_addr_t dma;
#if defined(HAVE_STRUCT_DMA_ATTRS) && defined(HAVE_SWIOTLB_SKIP_CPU_SYNC)
	DEFINE_DMA_ATTRS(attrs);

	dma_set_attr(DMA_ATTR_SKIP_CPU_SYNC, &attrs);
	dma_set_attr(DMA_ATTR_WEAK_ORDERING, &attrs);
#endif

	/* since we are recycling buffers we should seldom need to alloc */
	if (likely(page))
		return true;

	/* alloc new page for storage */
	page = dev_alloc_pages(ixgbevf_rx_pg_order(rx_ring));
	if (unlikely(!page)) {
		rx_ring->rx_stats.alloc_rx_page_failed++;
		return false;
	}

	/* map page for use */
	dma = dma_map_page_attrs(rx_ring->dev, page, 0,
				 ixgbevf_rx_pg_size(rx_ring),
				 DMA_FROM_DEVICE,
#if defined(HAVE_STRUCT_DMA_ATTRS) && defined(HAVE_SWIOTLB_SKIP_CPU_SYNC)
				 &attrs);
#else
				 IXGBEVF_RX_DMA_ATTR);
#endif

	/* if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(rx_ring->dev, dma)) {
		__free_pages(page, ixgbevf_rx_pg_order(rx_ring));

		rx_ring->rx_stats.alloc_rx_page_failed++;
		return false;
	}

	bi->dma = dma;
	bi->page = page;
	bi->page_offset = ixgbevf_rx_offset(rx_ring);
	bi->pagecnt_bias = 1;
	rx_ring->rx_stats.alloc_rx_page++;

	return true;
}

#ifdef HAVE_PF_RING

static void ixgbevf_disable_rx_queue(struct ixgbevf_adapter *adapter, struct ixgbevf_ring *ring);

static void ixgbevf_irq_enable_queues(struct ixgbevf_adapter *adapter, u32 qmask);
static void ixgbevf_irq_disable_queues(struct ixgbevf_adapter *adapter, u32 qmask);

static void ixgbevf_configure_rx_ring(struct ixgbevf_adapter *adapter, struct ixgbevf_ring *ring);
static void ixgbevf_configure_tx_ring(struct ixgbevf_adapter *adapter, struct ixgbevf_ring *ring);

static void ixgbevf_clean_rx_ring(struct ixgbevf_ring *rx_ring);
static void ixgbevf_clean_tx_ring(struct ixgbevf_ring *tx_ring);

int ring_is_not_empty(struct ixgbevf_ring *rx_ring) {
	union ixgbe_adv_rx_desc *rx_desc;
	u32 staterr;
	int i;

	for (i = 0; i < rx_ring->count; i++) {
		rx_desc = IXGBEVF_RX_DESC(rx_ring, i);
		staterr = le32_to_cpu(rx_desc->wb.upper.status_error);
		if (staterr & IXGBE_RXD_STAT_DD) 
			return 1;
	}

	return 0;
}

int wait_packet_function_ptr(void *data, int mode)
{
	struct ixgbevf_ring *rx_ring = (struct ixgbevf_ring*)data;
	struct ixgbevf_adapter *adapter = netdev_priv(rx_ring->netdev);
	struct ixgbevf_q_vector *q_vector = rx_ring->q_vector;
	int new_packets;

	if(unlikely(enable_debug))
		printk("%s: [mode=%d/%s][queueId=%d]\n",
		       __FUNCTION__, mode, mode == 1 ? "enable int" : "disable int",
		       rx_ring->queue_index);

	if(mode == 1 /* Enable interrupt */) {

		new_packets = ring_is_not_empty(rx_ring);

		if (!new_packets) {
			rx_ring->pfring_zc.rx_tx.rx.interrupt_received = 0;

			if (!rx_ring->pfring_zc.rx_tx.rx.interrupt_enabled) {
				if (adapter->hw.mac.type != ixgbe_mac_82598EB)
					ixgbevf_irq_enable_queues(adapter, BIT(q_vector->v_idx));

				rx_ring->pfring_zc.rx_tx.rx.interrupt_enabled = 1;

				if(unlikely(enable_debug))
	 				printk("%s: Packet not arrived yet: enabling interrupts, queue=%d\n",
					       __FUNCTION__, q_vector->v_idx);
			}

		} else {
			rx_ring->pfring_zc.rx_tx.rx.interrupt_received = 1;
		}

		if(unlikely(enable_debug))
			printk("%s: Packet received: %d\n", __FUNCTION__, new_packets);

		return new_packets;
	} else {
		/* Disable interrupts */

		if (adapter->hw.mac.type != ixgbe_mac_82598EB)
			ixgbevf_irq_disable_queues(adapter, BIT(q_vector->v_idx));

		rx_ring->pfring_zc.rx_tx.rx.interrupt_enabled = 0;

		if (unlikely(enable_debug))
			printk("%s: Disabled interrupts, queue = %d\n", __FUNCTION__, q_vector->v_idx);

		return 0;
 	}
}

/* ********************************** */

int wake_up_pfring_zc_socket(struct ixgbevf_ring *rx_ring)
{
	if (atomic_read(&rx_ring->pfring_zc.queue_in_use)) {
		if (waitqueue_active(&rx_ring->pfring_zc.rx_tx.rx.packet_waitqueue)) {
			if (ring_is_not_empty(rx_ring)) {
				rx_ring->pfring_zc.rx_tx.rx.interrupt_received = 1;
				wake_up_interruptible(&rx_ring->pfring_zc.rx_tx.rx.packet_waitqueue);
				return 1;
			}
		}
	}
	return 0;
}

/* ********************************** */

int notify_function_ptr(void *rx_data, void *tx_data, u_int8_t device_in_use) 
{
	struct ixgbevf_ring    *rx_ring = (struct ixgbevf_ring *) rx_data;
	struct ixgbevf_ring    *tx_ring = (struct ixgbevf_ring *) tx_data;
	struct ixgbevf_ring    *xx_ring = (rx_ring != NULL) ? rx_ring : tx_ring;
	struct ixgbevf_adapter *adapter;
	int i;
  
	if (xx_ring == NULL) return -1; /* safety check*/

	adapter = netdev_priv(xx_ring->netdev);

	if(device_in_use) { /* free all memory */

		if (atomic_inc_return(&adapter->pfring_zc.usage_counter) == 1 /* first user */) {
			try_module_get(THIS_MODULE); /* ++ */

			/* wait for ixgbe_clean_rx_irq to complete the current receive if any
			 * and ixgbe_clean_tx_irq to reclaim resources */
			usleep_range(100, 200);
		}

		if (rx_ring != NULL && atomic_inc_return(&rx_ring->pfring_zc.queue_in_use) == 1 /* first user */) {

			ixgbevf_clean_rx_ring(rx_ring);
			IXGBE_WRITE_REG(&adapter->hw, IXGBE_VFRDH(rx_ring->reg_idx), 0);
			IXGBE_WRITE_REG(&adapter->hw, IXGBE_VFRDT(rx_ring->reg_idx), 0);

			ixgbevf_irq_disable_queues(adapter, ((u64)1 << rx_ring->q_vector->v_idx));
		}

		if (tx_ring != NULL && atomic_inc_return(&tx_ring->pfring_zc.queue_in_use) == 1 /* first user */) {
			/* Note: this will also reset BQL with netdev_tx_reset_queue to avoid 
 			 * false tx hangs detected by dev_watchdog */
			ixgbevf_clean_tx_ring(tx_ring);
		}

	} else { /* restore card memory */

		if (rx_ring != NULL && atomic_dec_return(&rx_ring->pfring_zc.queue_in_use) == 0 /* last user */) {
			u32 rxdctl;

			/* disable queue to avoid issues while updating state 
			 * ixgbevf_configure_rx_ring will re-enable it */
			rxdctl = IXGBE_READ_REG(&adapter->hw, IXGBE_VFRXDCTL(rx_ring->reg_idx));
			ixgbevf_disable_rx_queue(adapter, rx_ring);
 
			for (i=0; i<rx_ring->count; i++) {
				union ixgbe_adv_rx_desc *rx_desc = IXGBEVF_RX_DESC(rx_ring, i);
				rx_desc->read.pkt_addr = 0;
				rx_desc->read.hdr_addr = 0;
			}
		
			ixgbevf_configure_rx_ring(adapter, rx_ring);
			rmb();

			ixgbevf_irq_disable_queues(adapter, ((u64)1 << rx_ring->q_vector->v_idx));
		}

		if (tx_ring != NULL && atomic_dec_return(&tx_ring->pfring_zc.queue_in_use) == 0 /* last user */) {
			/* Restore TX */
			tx_ring->next_to_clean = IXGBE_READ_REG(&adapter->hw, IXGBE_VFTDT(tx_ring->reg_idx));
       
			for(i=0; i<tx_ring->count; i++) {
				struct ixgbevf_tx_buffer *tx_buffer = &tx_ring->tx_buffer_info[i];
				tx_buffer->next_to_watch = NULL;
				tx_buffer->skb = NULL;
			}

			ixgbevf_configure_tx_ring(adapter, tx_ring);
			rmb();
    		}

    		if(atomic_dec_return(&adapter->pfring_zc.usage_counter) == 0 /* last user */)
			module_put(THIS_MODULE);  /* -- */
	}

	if(unlikely(enable_debug))
		printk("[PF_RING-ZC] %s %s@%d is %sIN use\n", __FUNCTION__,
		       xx_ring->netdev->name, xx_ring->queue_index, device_in_use ? "" : "NOT ");

	return 0;
}

/* ********************************** */

zc_dev_model pfring_zc_dev_model(struct ixgbe_hw *hw)
{
	return intel_ixgbe_vf;
}
#endif

/**
 * ixgbevf_alloc_rx_buffers - Replace used receive buffers; packet split
 * @rx_ring: rx descriptor ring (for a specific queue) to setup buffers on
 * @cleaned_count: number of buffers to replace
 **/
static void ixgbevf_alloc_rx_buffers(struct ixgbevf_ring *rx_ring,
				     u16 cleaned_count)
{
	union ixgbe_adv_rx_desc *rx_desc;
	struct ixgbevf_rx_buffer *bi;
	unsigned int i = rx_ring->next_to_use;

	/* nothing to do or no valid netdev defined */
	if (!cleaned_count || !rx_ring->netdev)
		return;

	rx_desc = IXGBEVF_RX_DESC(rx_ring, i);
	bi = &rx_ring->rx_buffer_info[i];
	i -= rx_ring->count;

	do {
		if (!ixgbevf_alloc_mapped_page(rx_ring, bi))
			break;

		/* sync the buffer for use by the device */
		dma_sync_single_range_for_device(rx_ring->dev, bi->dma,
						 bi->page_offset,
						 ixgbevf_rx_bufsz(rx_ring),
						 DMA_FROM_DEVICE);

		/* Refresh the desc even if pkt_addr didn't change
		 * because each write-back erases this info.
		 */
		rx_desc->read.pkt_addr = cpu_to_le64(bi->dma + bi->page_offset);

		rx_desc++;
		bi++;
		i++;
		if (unlikely(!i)) {
			rx_desc = IXGBEVF_RX_DESC(rx_ring, 0);
			bi = rx_ring->rx_buffer_info;
			i -= rx_ring->count;
		}

		/* clear the length for the next_to_use descriptor */
		rx_desc->wb.upper.length = 0;

		cleaned_count--;
	} while (cleaned_count);

	i += rx_ring->count;

	if (rx_ring->next_to_use != i) {
		/* record the next descriptor to use */
		rx_ring->next_to_use = i;

		/* update next to alloc since we have filled the ring */
		rx_ring->next_to_alloc = i;

		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.  (Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64).
		 */
		wmb();
		writel(i, rx_ring->tail);
	}
}

/**
 * ixgbevf_cleanup_headers - Correct corrupted or empty headers
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being fixed
 *
 * Check for corrupted packet headers caused by senders on the local L2
 * embedded NIC switch not setting up their Tx Descriptors right.  These
 * should be very rare.
 *
 * Also address the case where we are pulling data in on pages only
 * and as such no data is present in the skb header.
 *
 * In addition if skb is not at least 60 bytes we need to pad it so that
 * it is large enough to qualify as a valid Ethernet frame.
 *
 * Returns true if an error was encountered and skb was freed.
 */
static bool ixgbevf_cleanup_headers(struct ixgbevf_ring *rx_ring,
				    union ixgbe_adv_rx_desc *rx_desc,
				    struct sk_buff *skb)
{
	/* XDP packets use error pointer so abort at this point */
	if (IS_ERR(skb))
		return true;

	/* verify that the packet does not have any known errors */
	if (unlikely(ixgbevf_test_staterr(rx_desc,
					  IXGBE_RXDADV_ERR_FRAME_ERR_MASK))) {
		struct net_device *netdev = rx_ring->netdev;
		if (!(netdev->features & NETIF_F_RXALL)) {
			dev_kfree_skb_any(skb);
			return true;
		}
	}

	/* if eth_skb_pad returns an error the skb was freed */
	if (eth_skb_pad(skb))
		return true;

	return false;
}

/* ixgbevf_reuse_rx_page - page flip buffer and store it back on the ring
 * @rx_ring: rx descriptor ring to store buffers on
 * @old_buff: donor buffer to have page reused
 *
 * Synchronizes page for reuse by the adapter
 */
static void ixgbevf_reuse_rx_page(struct ixgbevf_ring *rx_ring,
				  struct ixgbevf_rx_buffer *old_buff)
{
	struct ixgbevf_rx_buffer *new_buff;
	u16 nta = rx_ring->next_to_alloc;

	new_buff = &rx_ring->rx_buffer_info[nta];

	/* update, and store next to alloc */
	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	/* transfer page from old buffer to new buffer */
	new_buff->page = old_buff->page;
	new_buff->dma = old_buff->dma;
	new_buff->page_offset = old_buff->page_offset;
	new_buff->pagecnt_bias = old_buff->pagecnt_bias;
}

static inline bool ixgbevf_page_is_reserved(struct page *page)
{
	return (page_to_nid(page) != numa_mem_id()) || page_is_pfmemalloc(page);
}

static bool ixgbevf_can_reuse_rx_page(struct ixgbevf_rx_buffer *rx_buffer)
{
	unsigned int pagecnt_bias = rx_buffer->pagecnt_bias;
	struct page *page = rx_buffer->page;

	/* avoid re-using remote pages */
	if (unlikely(ixgbevf_page_is_reserved(page)))
		return false;

#if (PAGE_SIZE < 8192)
	/* if we are only owner of page we can reuse it */
#ifdef HAVE_PAGE_COUNT_BULK_UPDATE
	if (unlikely((page_ref_count(page) - pagecnt_bias) > 1))
#else
	if (unlikely((page_count(page) - pagecnt_bias) > 1))
#endif
		return false;

#else
#define IXGBEVF_LAST_OFFSET \
	(SKB_WITH_OVERHEAD(PAGE_SIZE) - IXGBEVF_RXBUFFER_2048)

	if (rx_buffer->page_offset > IXGBEVF_LAST_OFFSET)
		return false;

#endif
#ifdef HAVE_PAGE_COUNT_BULK_UPDATE
	/* If we have drained the page fragment pool we need to update
	 * the pagecnt_bias and page count so that we fully restock the
	 * number of references the driver holds.
	 */
	if (unlikely(!pagecnt_bias)) {
		page_ref_add(page, USHRT_MAX);
		rx_buffer->pagecnt_bias = USHRT_MAX;
	}

#else /* !HAVE_PAGE_COUNT_BULK_UPDATE */
	/* Even if we own the page, we are not allowed to use atomic_set()
	 * This would break get_page_unless_zero() users.
	 */
	if (likely(!pagecnt_bias)) {
		page_ref_inc(page);
		rx_buffer->pagecnt_bias = 1;
	}

#endif /* !HAVE_PAGE_COUNT_BULK_UPDATE */
	return true;
}

/**
 * ixgbevf_add_rx_frag - Add contents of Rx buffer to sk_buff
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: buffer containing page to add
 * @skb: sk_buff to place the data into
 * @size: size of buffer to be added
 *
 * This function will add the data contained in rx_buffer->page to the skb.
 */
static void ixgbevf_add_rx_frag(struct ixgbevf_ring *rx_ring,
				struct ixgbevf_rx_buffer *rx_buffer,
				struct sk_buff *skb,
				unsigned int size)
{
#if (PAGE_SIZE < 8192)
	unsigned int truesize = ixgbevf_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = ring_uses_build_skb(rx_ring) ?
				SKB_DATA_ALIGN(IXGBEVF_SKB_PAD + size) :
				SKB_DATA_ALIGN(size);
#endif

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rx_buffer->page,
			rx_buffer->page_offset, size, truesize);
#if (PAGE_SIZE < 8192)
	rx_buffer->page_offset ^= truesize;
#else
	rx_buffer->page_offset += truesize;
#endif

}

static
struct sk_buff *ixgbevf_construct_skb(struct ixgbevf_ring *rx_ring,
				      struct ixgbevf_rx_buffer *rx_buffer,
				      struct xdp_buff *xdp,
				      union ixgbe_adv_rx_desc *rx_desc)
{
	unsigned int size = xdp->data_end - xdp->data;
#if (PAGE_SIZE < 8192)
	unsigned int truesize = ixgbevf_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = SKB_DATA_ALIGN(xdp->data_end -
					       xdp->data_hard_start);
#endif
	unsigned int headlen;
	struct sk_buff *skb;

	/* prefetch first cache line of first page */
	prefetch(xdp->data);
#if L1_CACHE_BYTES < 128
	prefetch(xdp->data + L1_CACHE_BYTES);
#endif
	/* Note, we get here by enabling legacy-rx via:
	 *
	 *    ethtool --set-priv-flags <dev> legacy-rx on
	 *
	 * In this mode, we currently get 0 extra XDP headroom as
	 * opposed to having legacy-rx off, where we process XDP
	 * packets going to stack via ixgbevf_build_skb().
	 *
	 * For ixgbevf_construct_skb() mode it means that the
	 * xdp->data_meta will always point to xdp->data, since
	 * the helper cannot expand the head. Should this ever
	 * changed in future for legacy-rx mode on, then lets also
	 * add xdp->data_meta handling here.
	 */

	/* allocate a skb to store the frags */
	skb = napi_alloc_skb(&rx_ring->q_vector->napi, IXGBEVF_RX_HDR_SIZE);
	if (unlikely(!skb))
		return NULL;

	/* Determine available headroom for copy */
	headlen = size;
	if (headlen > IXGBEVF_RX_HDR_SIZE)
		headlen = eth_get_headlen(xdp->data, IXGBEVF_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	memcpy(__skb_put(skb, headlen), xdp->data,
	       ALIGN(headlen, sizeof(long)));

	/* update all of the pointers */
	size -= headlen;
	if (size) {
		skb_add_rx_frag(skb, 0, rx_buffer->page,
				(xdp->data + headlen) -
					page_address(rx_buffer->page),
				size, truesize);
#if (PAGE_SIZE < 8192)
		rx_buffer->page_offset ^= truesize;
#else
		rx_buffer->page_offset += truesize;
#endif
	} else {
		rx_buffer->pagecnt_bias++;
	}

	return skb;
}

static inline void ixgbevf_irq_enable_queues(struct ixgbevf_adapter *adapter,
					     u32 qmask)
{
	struct ixgbe_hw *hw = &adapter->hw;

	IXGBE_WRITE_REG(hw, IXGBE_VTEIMS, qmask);
}

#ifdef HAVE_PF_RING
static inline void ixgbevf_irq_disable_queues(struct ixgbevf_adapter *adapter,
					     u32 qmask)
{
	struct ixgbe_hw *hw = &adapter->hw;

	IXGBE_WRITE_REG(hw, IXGBE_VTEIMC, qmask);
}
#endif

#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
static struct sk_buff *ixgbevf_build_skb(struct ixgbevf_ring *rx_ring,
					 struct ixgbevf_rx_buffer *rx_buffer,
					 struct xdp_buff *xdp,
					 union ixgbe_adv_rx_desc *rx_desc)
{
#ifdef HAVE_XDP_BUFF_DATA_META
	unsigned int metasize = xdp->data - xdp->data_meta;
	void *va = xdp->data_meta;
#else
	void *va = xdp->data;
#endif /* HAVE_XDP_BUFF_DATA_META */
#if (PAGE_SIZE < 8192)
	unsigned int truesize = ixgbevf_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) +
				SKB_DATA_ALIGN(xdp->data_end -
					       xdp->data_hard_start);
#endif
	struct sk_buff *skb;

	/* Prefetch first cache line of first page. If xdp->data_meta
	 * is unused, this points to xdp->data, otherwise, we likely
	 * have a consumer accessing first few bytes of meta data,
	 * and then actual data.
	 */
	prefetch(va);
#if L1_CACHE_BYTES < 128
	prefetch(va + L1_CACHE_BYTES);
#endif

	/* build an skb around the page buffer */
	skb = build_skb(xdp->data_hard_start, truesize);
	if (unlikely(!skb))
		return NULL;

	/* update pointers within the skb to store the data */
	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	__skb_put(skb, xdp->data_end - xdp->data);
#ifdef HAVE_XDP_BUFF_DATA_META
	if (metasize)
		skb_metadata_set(skb, metasize);
#endif /* HAVE_XDP_BUFF_DATA_META */

	/* update buffer offset */
#if (PAGE_SIZE < 8192)
	rx_buffer->page_offset ^= truesize;
#else
	rx_buffer->page_offset += truesize;
#endif

	return skb;
}

#endif /* HAVE_SWIOTLB_SKIP_CPU_SYNC */
#define IXGBE_TXD_CMD (IXGBE_TXD_CMD_EOP | \
		       IXGBE_TXD_CMD_RS)

#define IXGBEVF_XDP_PASS 0
#define IXGBEVF_XDP_CONSUMED 1
#define IXGBEVF_XDP_TX 2

#ifdef HAVE_XDP_SUPPORT
static int ixgbevf_xmit_xdp_ring(struct ixgbevf_ring *ring,
				 struct xdp_buff *xdp)
{
	struct ixgbevf_tx_buffer *tx_buffer;
	union ixgbe_adv_tx_desc *tx_desc;
	u32 len, cmd_type;
	dma_addr_t dma;
	u16 i;

	len = xdp->data_end - xdp->data;

	if (unlikely(!ixgbevf_desc_unused(ring)))
		return IXGBEVF_XDP_CONSUMED;

	dma = dma_map_single(ring->dev, xdp->data, len, DMA_TO_DEVICE);
	if (dma_mapping_error(ring->dev, dma))
		return IXGBEVF_XDP_CONSUMED;

	/* record the location of the first descriptor for this packet */
	i = ring->next_to_use;
	tx_buffer = &ring->tx_buffer_info[i];

	dma_unmap_len_set(tx_buffer, len, len);
	dma_unmap_addr_set(tx_buffer, dma, dma);
	tx_buffer->data = xdp->data;
	tx_buffer->bytecount = len;
	tx_buffer->gso_segs = 1;
	tx_buffer->protocol = 0;

	/* Populate minimal context descriptor that will provide for the
	 * fact that we are expected to process Ethernet frames.
	 */
	if (!test_bit(__IXGBEVF_TX_XDP_RING_PRIMED, &ring->state)) {
		struct ixgbe_adv_tx_context_desc *context_desc;

		set_bit(__IXGBEVF_TX_XDP_RING_PRIMED, &ring->state);

		context_desc = IXGBEVF_TX_CTXTDESC(ring, 0);
		context_desc->vlan_macip_lens	=
			cpu_to_le32(ETH_HLEN << IXGBE_ADVTXD_MACLEN_SHIFT);
		context_desc->seqnum_seed	= 0;
		context_desc->type_tucmd_mlhl	=
			cpu_to_le32(IXGBE_TXD_CMD_DEXT |
				    IXGBE_ADVTXD_DTYP_CTXT);
		context_desc->mss_l4len_idx	= 0;

		i = 1;
	}

	/* put descriptor type bits */
	cmd_type = IXGBE_ADVTXD_DTYP_DATA |
		   IXGBE_ADVTXD_DCMD_DEXT |
		   IXGBE_ADVTXD_DCMD_IFCS;
	cmd_type |= len | IXGBE_TXD_CMD;

	tx_desc = IXGBEVF_TX_DESC(ring, i);
	tx_desc->read.buffer_addr = cpu_to_le64(dma);

	tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);
	tx_desc->read.olinfo_status =
			cpu_to_le32((len << IXGBE_ADVTXD_PAYLEN_SHIFT) |
				    IXGBE_ADVTXD_CC);

	/* Avoid any potential race with cleanup */
	smp_wmb();

	/* set next_to_watch value indicating a packet is present */
	i++;
	if (i == ring->count)
		i = 0;

	tx_buffer->next_to_watch = tx_desc;
	ring->next_to_use = i;

	return IXGBEVF_XDP_TX;
}

#endif /* HAVE_XDP_SUPPORT */
static struct sk_buff *
ixgbevf_run_xdp(struct ixgbevf_adapter __maybe_unused *adapter,
		struct ixgbevf_ring __maybe_unused *rx_ring,
		struct xdp_buff __maybe_unused *xdp)
{
	int result = IXGBEVF_XDP_PASS;
#ifdef HAVE_XDP_SUPPORT
	struct ixgbevf_ring *xdp_ring;
	struct bpf_prog *xdp_prog;
	u32 act;

	rcu_read_lock();
	xdp_prog = READ_ONCE(rx_ring->xdp_prog);

	if (!xdp_prog)
		goto xdp_out;

	act = bpf_prog_run_xdp(xdp_prog, xdp);
	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
		xdp_ring = adapter->xdp_ring[rx_ring->queue_index];
		result = ixgbevf_xmit_xdp_ring(xdp_ring, xdp);
		break;
	default:
		bpf_warn_invalid_xdp_action(act);
		/* fallthrough */
	case XDP_ABORTED:
		trace_xdp_exception(rx_ring->netdev, xdp_prog, act);
		/* fallthrough -- handle aborts by dropping packet */
	case XDP_DROP:
		result = IXGBEVF_XDP_CONSUMED;
		break;
	}
xdp_out:
	rcu_read_unlock();
#endif /* HAVE_XDP_SUPPORT */

	return ERR_PTR(-result);
}

static void ixgbevf_rx_buffer_flip(struct ixgbevf_ring *rx_ring,
				   struct ixgbevf_rx_buffer *rx_buffer,
				   unsigned int size)
{
#if (PAGE_SIZE < 8192)
	unsigned int truesize = ixgbevf_rx_pg_size(rx_ring) / 2;

	rx_buffer->page_offset ^= truesize;
#else
	unsigned int truesize = ring_uses_build_skb(rx_ring) ?
				SKB_DATA_ALIGN(IXGBEVF_SKB_PAD + size) :
				SKB_DATA_ALIGN(size);

	rx_buffer->page_offset += truesize;
#endif
}

static int ixgbevf_clean_rx_irq(struct ixgbevf_q_vector *q_vector,
				 struct ixgbevf_ring *rx_ring,
				 int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	struct ixgbevf_adapter *adapter = q_vector->adapter;
	u16 cleaned_count = ixgbevf_desc_unused(rx_ring);
	struct sk_buff *skb = rx_ring->skb;
	bool xdp_xmit = false;
	struct xdp_buff xdp;

#ifdef HAVE_PF_RING
	if (atomic_read(&adapter->pfring_zc.usage_counter) > 0) {
		wake_up_pfring_zc_socket(rx_ring);
		return !!budget;
	}
#endif

	xdp.data = NULL;
	xdp.data_end = NULL;
#ifdef HAVE_XDP_BUFF_RXQ
	xdp.rxq = &rx_ring->xdp_rxq;
#endif /* HAVE_XDP_BUFF_RXQ */

	while (likely(total_rx_packets < budget)) {
		struct ixgbevf_rx_buffer *rx_buffer;
		union ixgbe_adv_rx_desc *rx_desc;
		unsigned int size;

		/* return some buffers to hardware, one at a time is too slow */
		if (cleaned_count >= IXGBEVF_RX_BUFFER_WRITE) {
			ixgbevf_alloc_rx_buffers(rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		rx_desc = IXGBEVF_RX_DESC(rx_ring, rx_ring->next_to_clean);
		size = le16_to_cpu(rx_desc->wb.upper.length);
		if (!size)
			break;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * RXD_STAT_DD bit is set
		 */
		rmb();

		/* retrieve a buffer from the ring */
		rx_buffer = ixgbevf_get_rx_buffer(rx_ring, size);

		if (!skb) {
			xdp.data = page_address(rx_buffer->page) +
				   rx_buffer->page_offset;
#ifdef HAVE_XDP_BUFF_DATA_META
			xdp.data_meta = xdp.data;
#endif /* HAVE_XDP_BUFF_DATA_META */
			xdp.data_hard_start = xdp.data -
					      ixgbevf_rx_offset(rx_ring);
			xdp.data_end = xdp.data + size;

			skb = ixgbevf_run_xdp(adapter, rx_ring, &xdp);
		}

		if (IS_ERR(skb)) {
			if (PTR_ERR(skb) == -IXGBEVF_XDP_TX) {
				xdp_xmit = true;
				ixgbevf_rx_buffer_flip(rx_ring, rx_buffer,
						       size);
			} else {
				rx_buffer->pagecnt_bias++;
			}
			total_rx_packets++;
			total_rx_bytes += size;
		} else if (skb) {
			ixgbevf_add_rx_frag(rx_ring, rx_buffer, skb, size);
#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
		} else if (ring_uses_build_skb(rx_ring)) {
			skb = ixgbevf_build_skb(rx_ring, rx_buffer,
						&xdp, rx_desc);
#endif /* HAVE_SWIOTLB_SKIP_CPU_SYNC */
		} else {
			skb = ixgbevf_construct_skb(rx_ring, rx_buffer,
						    &xdp, rx_desc);
		}

		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			rx_ring->rx_stats.alloc_rx_buff_failed++;
			rx_buffer->pagecnt_bias++;
			break;
		}

		ixgbevf_put_rx_buffer(rx_ring, rx_buffer, skb);
		cleaned_count++;

#ifdef HAVE_PF_RING
		/* CRC strip (offload disabled) */
		// skb->tail -= 4, skb->len -= 4;
#endif

		/* fetch next buffer in frame if non-eop */
		if (ixgbevf_is_non_eop(rx_ring, rx_desc))
			continue;

		/* verify the packet layout is correct */
		if (ixgbevf_cleanup_headers(rx_ring, rx_desc, skb)) {
			skb = NULL;
			continue;
		}

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* Workaround hardware that can't do proper VEPA multicast
		 * source pruning.
		 */
		if ((skb->pkt_type == PACKET_BROADCAST ||
		    skb->pkt_type == PACKET_MULTICAST) &&
		    ether_addr_equal(rx_ring->netdev->dev_addr,
				     eth_hdr(skb)->h_source)) {
			dev_kfree_skb_irq(skb);
			continue;
		}

		/* populate checksum, VLAN, and protocol */
		ixgbevf_process_skb_fields(rx_ring, rx_desc, skb);

		ixgbevf_rx_skb(q_vector, skb);

		/* reset skb pointer */
		skb = NULL;

		/* update budget accounting */
		total_rx_packets++;
	}

	/* place incomplete frames back on ring for completion */
	rx_ring->skb = skb;

	if (xdp_xmit) {
		struct ixgbevf_ring *xdp_ring =
			adapter->xdp_ring[rx_ring->queue_index];

		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.
		 */
		wmb();
		writel(xdp_ring->next_to_use, xdp_ring->tail);
	}

	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->stats.packets += total_rx_packets;
	rx_ring->stats.bytes += total_rx_bytes;
	u64_stats_update_end(&rx_ring->syncp);
	q_vector->rx.total_packets += total_rx_packets;
	q_vector->rx.total_bytes += total_rx_bytes;
	q_vector->netpoll_rx = false;

	return total_rx_packets;
}

/**
 * ixgbevf_poll - NAPI polling calback
 * @napi: napi struct with our devices info in it
 * @budget: amount of work driver is allowed to do this pass, in packets
 *
 * This function will clean more than one or more rings associated with a
 * q_vector.
 **/
static int ixgbevf_poll(struct napi_struct *napi, int budget)
{
	struct ixgbevf_q_vector *q_vector =
		container_of(napi, struct ixgbevf_q_vector, napi);
	struct ixgbevf_adapter *adapter = q_vector->adapter;
	struct ixgbevf_ring *ring;
	int per_ring_budget, work_done = 0;
	bool clean_complete = true;

#ifdef HAVE_PF_RING
	if (atomic_read(&adapter->pfring_zc.usage_counter) > 0) {
		ixgbevf_for_each_ring(ring, q_vector->rx)
			wake_up_pfring_zc_socket(ring);
		napi_complete(napi);
		return 0;
	}
#endif

	ixgbevf_for_each_ring(ring, q_vector->tx) {
		if (!ixgbevf_clean_tx_irq(q_vector, ring, budget))
			clean_complete = false;
	}

	if (budget <= 0)
		return budget;
#ifdef HAVE_NDO_BUSY_POLL
	if (test_bit(NAPI_STATE_NPSVC, &napi->state))
		return budget;

	if (!ixgbevf_qv_lock_napi(q_vector))
		return budget;
#endif

	/* attempt to distribute budget to each queue fairly, but don't allow
	 * the budget to go below 1 because we'll exit polling */
	if (q_vector->rx.count > 1)
		per_ring_budget = max(budget/q_vector->rx.count, 1);
	else
		per_ring_budget = budget;

	ixgbevf_for_each_ring(ring, q_vector->rx) {
		int cleaned = ixgbevf_clean_rx_irq(q_vector, ring,
						   per_ring_budget);
		work_done += cleaned;
		if (cleaned >= per_ring_budget)
			clean_complete = false;
	}

#ifdef HAVE_NDO_BUSY_POLL
	ixgbevf_qv_unlock_napi(q_vector);

#endif
#ifndef HAVE_NETDEV_NAPI_LIST
	if (!netif_running(adapter->netdev))
		clean_complete = true;

#endif
	/* If all work not completed, return budget and keep polling */
	if (!clean_complete)
		return budget;
	/* all work done, exit the polling mode */
	napi_complete_done(napi, work_done);
	if (adapter->rx_itr_setting == 1)
		ixgbevf_set_itr(q_vector);
	if (!test_bit(__IXGBEVF_DOWN, &adapter->state) &&
	    !test_bit(__IXGBEVF_REMOVING, &adapter->state))
		ixgbevf_irq_enable_queues(adapter,
					  BIT(q_vector->v_idx));

	return 0;
}

/**
 * ixgbevf_write_eitr - write VTEITR register in hardware specific way
 * @q_vector: structure containing interrupt and ring information
 */
void ixgbevf_write_eitr(struct ixgbevf_q_vector *q_vector)
{
	struct ixgbevf_adapter *adapter = q_vector->adapter;
	struct ixgbe_hw *hw = &adapter->hw;
	int v_idx = q_vector->v_idx;
	u32 itr_reg = q_vector->itr & IXGBE_MAX_EITR;

	/*
	 * set the WDIS bit to not clear the timer bits and cause an
	 * immediate assertion of the interrupt
	 */
	itr_reg |= IXGBE_EITR_CNT_WDIS;

	IXGBE_WRITE_REG(hw, IXGBE_VTEITR(v_idx), itr_reg);
}

#ifdef HAVE_NDO_BUSY_POLL
/* must be called with local_bh_disable()d */
static int ixgbevf_busy_poll_recv(struct napi_struct *napi)
{
	struct ixgbevf_q_vector *q_vector =
			container_of(napi, struct ixgbevf_q_vector, napi);
	struct ixgbevf_adapter *adapter = q_vector->adapter;
	struct ixgbevf_ring  *ring;
	int found = 0;

	if (test_bit(__IXGBEVF_DOWN, &adapter->state))
		return LL_FLUSH_FAILED;

	if (!ixgbevf_qv_lock_poll(q_vector))
		return LL_FLUSH_BUSY;

	ixgbevf_for_each_ring(ring, q_vector->rx) {
		found = ixgbevf_clean_rx_irq(q_vector, ring, 4);
#ifdef BP_EXTENDED_STATS
		if (found)
			ring->stats.cleaned += found;
		else
			ring->stats.misses++;
#endif
		if (found)
			break;
	}

	ixgbevf_qv_unlock_poll(q_vector);

	return found;
}
#endif /* HAVE_NDO_BUSY_POLL */

/**
 * ixgbevf_set_ivar - set IVAR registers - maps interrupt causes to vectors
 * @adapter: pointer to adapter struct
 * @direction: 0 for Rx, 1 for Tx, -1 for other causes
 * @queue: queue to map the corresponding interrupt to
 * @msix_vector: the vector to map to the corresponding queue
 *
 */
static void ixgbevf_set_ivar(struct ixgbevf_adapter *adapter, s8 direction,
			     u8 queue, u8 msix_vector)
{
	u32 ivar, index;
	struct ixgbe_hw *hw = &adapter->hw;
	if (direction == -1) {
		/* other causes */
		msix_vector |= IXGBE_IVAR_ALLOC_VAL;
		ivar = IXGBE_READ_REG(hw, IXGBE_VTIVAR_MISC);
		ivar &= ~0xFF;
		ivar |= msix_vector;
		IXGBE_WRITE_REG(hw, IXGBE_VTIVAR_MISC, ivar);
	} else {
		/* tx or rx causes */
		msix_vector |= IXGBE_IVAR_ALLOC_VAL;
		index = ((16 * (queue & 1)) + (8 * direction));
		ivar = IXGBE_READ_REG(hw, IXGBE_VTIVAR(queue >> 1));
		ivar &= ~(0xFF << index);
		ivar |= (msix_vector << index);
		IXGBE_WRITE_REG(hw, IXGBE_VTIVAR(queue >> 1), ivar);
	}
}

/**
 * ixgbevf_configure_msix - Configure MSI-X hardware
 * @adapter: board private structure
 *
 * ixgbevf_configure_msix sets up the hardware to properly generate MSI-X
 * interrupts.
 **/
static void ixgbevf_configure_msix(struct ixgbevf_adapter *adapter)
{
	struct ixgbevf_q_vector *q_vector;
	int v_idx;

	adapter->eims_enable_mask = 0;

	/*
	 * Populate the IVAR table and set the ITR values to the
	 * corresponding register.
	 */
	for (v_idx = 0; v_idx < adapter->num_q_vectors; v_idx++) {
		struct ixgbevf_ring *ring;
		q_vector = adapter->q_vector[v_idx];

		ixgbevf_for_each_ring(ring, q_vector->rx)
			ixgbevf_set_ivar(adapter, 0, ring->reg_idx, v_idx);

		ixgbevf_for_each_ring(ring, q_vector->tx)
			ixgbevf_set_ivar(adapter, 1, ring->reg_idx, v_idx);

		if (q_vector->tx.ring && !q_vector->rx.ring) {
			/* tx only vector */
			if (adapter->tx_itr_setting == 1)
				q_vector->itr = IXGBE_12K_ITR;
			else
				q_vector->itr = adapter->tx_itr_setting;
		} else {
			/* rx or rx/tx vector */
			if (adapter->rx_itr_setting == 1)
				q_vector->itr = IXGBE_20K_ITR;
			else
				q_vector->itr = adapter->rx_itr_setting;
		}

		/* add q_vector eims value to global eims_enable_mask */
		adapter->eims_enable_mask |= BIT(v_idx);

		ixgbevf_write_eitr(q_vector);
	}

	ixgbevf_set_ivar(adapter, -1, 1, v_idx);
	/* setup eims_other and add value to global eims_enable_mask */
	adapter->eims_other = BIT(v_idx);
	adapter->eims_enable_mask |= adapter->eims_other;
}

enum latency_range {
	lowest_latency = 0,
	low_latency = 1,
	bulk_latency = 2,
	latency_invalid = 255
};

/**
 * ixgbevf_update_itr - update the dynamic ITR value based on statistics
 * @q_vector: structure containing interrupt and ring information
 * @ring_container: structure containing ring performance data
 *
 *      Stores a new ITR value based on packets and byte
 *      counts during the last interrupt.  The advantage of per interrupt
 *      computation is faster updates and more accurate ITR for the current
 *      traffic pattern.  Constants in this function were computed
 *      based on theoretical maximum wire speed and thresholds were set based
 *      on testing data as well as attempting to minimize response time
 *      while increasing bulk throughput.
 *      this functionality is controlled by the InterruptThrottleRate module
 *      parameter (see ixgbevf_param.c)
 **/
static void ixgbevf_update_itr(struct ixgbevf_q_vector *q_vector,
			       struct ixgbevf_ring_container *ring_container)
{
	int bytes = ring_container->total_bytes;
	int packets = ring_container->total_packets;
	u32 timepassed_us;
	u64 bytes_perint;
	u8 itr_setting = ring_container->itr;

	if (packets == 0)
		return;

	/* simple throttlerate management
	 *    0-20MB/s lowest (100000 ints/s)
	 *   20-100MB/s low   (20000 ints/s)
	 *  100-1249MB/s bulk (12000 ints/s)
	 */
	/* what was last interrupt timeslice? */
	timepassed_us = q_vector->itr >> 2;
	bytes_perint = bytes / timepassed_us; /* bytes/usec */

	switch (itr_setting) {
	case lowest_latency:
		if (bytes_perint > 10) {
			itr_setting = low_latency;
		}
		break;
	case low_latency:
		if (bytes_perint > 20) {
			itr_setting = bulk_latency;
		}
		else if (bytes_perint <= 10) {
			itr_setting = lowest_latency;
		}
		break;
	case bulk_latency:
		if (bytes_perint <= 20) {
			itr_setting = low_latency;
		}
		break;
	}

	/* clear work counters since we have the values we need */
	ring_container->total_bytes = 0;
	ring_container->total_packets = 0;

	/* write updated itr to ring container */
	ring_container->itr = itr_setting;
}

static void ixgbevf_set_itr(struct ixgbevf_q_vector *q_vector)
{
	u32 new_itr = q_vector->itr;
	u8 current_itr;

	ixgbevf_update_itr(q_vector, &q_vector->tx);
	ixgbevf_update_itr(q_vector, &q_vector->rx);

	current_itr = max(q_vector->rx.itr, q_vector->tx.itr);

	switch (current_itr) {
	/* counts and packets in update_itr are dependent on these numbers */
	case lowest_latency:
		new_itr = IXGBE_100K_ITR;
		break;
	case low_latency:
		new_itr = IXGBE_20K_ITR;
		break;
	case bulk_latency:
		new_itr = IXGBE_12K_ITR;
		break;
	default:
		break;
	}

	if (new_itr != q_vector->itr) {
		/* do an exponential smoothing */
		new_itr = (10 * new_itr * q_vector->itr) /
			  ((9 * new_itr) + q_vector->itr);

		/* save the algorithm value here */
		q_vector->itr = new_itr;

		ixgbevf_write_eitr(q_vector);
	}
}

static irqreturn_t ixgbevf_msix_other(int __always_unused irq, void *data)
{
	struct ixgbevf_adapter *adapter = data;
	struct ixgbe_hw *hw = &adapter->hw;

	hw->mac.get_link_status = 1;

	ixgbevf_service_event_schedule(adapter);

	IXGBE_WRITE_REG(hw, IXGBE_VTEIMS, adapter->eims_other);

	return IRQ_HANDLED;
}

/**
 * ixgbevf_msix_clean_rings - single unshared vector rx clean (all queues)
 * @irq: unused
 * @data: pointer to our q_vector struct for this interrupt vector
 **/
static irqreturn_t ixgbevf_msix_clean_rings(int __always_unused irq, void *data)
{
	struct ixgbevf_q_vector *q_vector = data;

	/* EIAM disabled interrupts (on this vector) for us */
	if (q_vector->rx.ring || q_vector->tx.ring)
		napi_schedule_irqoff(&q_vector->napi);

	return IRQ_HANDLED;
}

/**
 * ixgbevf_request_msix_irqs - Initialize MSI-X interrupts
 * @adapter: board private structure
 *
 * ixgbevf_request_msix_irqs allocates MSI-X vectors and requests
 * interrupts from the kernel.
 **/
static int ixgbevf_request_msix_irqs(struct ixgbevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	unsigned int ri = 0, ti = 0;
	int vector, err;

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct ixgbevf_q_vector *q_vector = adapter->q_vector[vector];
		struct msix_entry *entry = &adapter->msix_entries[vector];

		if (q_vector->tx.ring && q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name),
				 "%s-TxRx-%u", netdev->name, ri++);
			ti++;
		} else if (q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name),
				 "%s-rx-%u", netdev->name, ri++);
		} else if (q_vector->tx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name),
				 "%s-tx-%u", netdev->name, ti++);
		} else {
			/* skip this unused q_vector */
			continue;
		}
		err = request_irq(entry->vector, &ixgbevf_msix_clean_rings, 0,
				  q_vector->name, q_vector);
		if (err) {
			DPRINTK(PROBE, ERR,
			        "request_irq failed for MSIX interrupt "
			        "Error: %d\n", err);
			goto free_queue_irqs;
		}
	}

	err = request_irq(adapter->msix_entries[vector].vector,
			  &ixgbevf_msix_other, 0, netdev->name, adapter);
	if (err) {
		DPRINTK(PROBE, ERR,
		        "request_irq for msix_other failed: %d\n", err);
		goto free_queue_irqs;
	}

	return 0;

free_queue_irqs:
	while (vector) {
		vector--;
		free_irq(adapter->msix_entries[vector].vector,
			 adapter->q_vector[vector]);
	}
	/* This failure is non-recoverable - it indicates the system is
	 * out of MSIX vector resources and the VF driver cannot run
	 * without them.  Set the number of q vectors to zero
	 * indicating that not enough can be allocated.  The error
	 * will be returned to the user indicating device open failed.
	 * Any further attempts to force the driver to open will also
	 * fail.  The only way to recover is to unload the driver and
	 * reload it again.  If the system has recovered some MSIX
	 * vectors then it may succeed.
	 */
	adapter->num_q_vectors = 0;
	return err;
}

/**
 * ixgbevf_request_irq - initialize interrupts
 * @adapter: board private structure
 *
 * Attempts to configure interrupts using the best available
 * capabilities of the hardware and kernel.
 **/
static int ixgbevf_request_irq(struct ixgbevf_adapter *adapter)
{
	int err = 0;

	err = ixgbevf_request_msix_irqs(adapter);

	if (err)
		DPRINTK(PROBE, ERR, "request_irq failed, Error %d\n", err);

	return err;
}

static void ixgbevf_free_irq(struct ixgbevf_adapter *adapter)
{
	int vector;

	if (!adapter->msix_entries)
		return;

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct ixgbevf_q_vector *q_vector = adapter->q_vector[vector];
		struct msix_entry *entry = &adapter->msix_entries[vector];

		/* free only the irqs that were actually requested */
		if (!q_vector->rx.ring && !q_vector->tx.ring)
			continue;

		free_irq(entry->vector, q_vector);
	}

	free_irq(adapter->msix_entries[vector].vector, adapter);
}

/**
 * ixgbevf_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
static inline void ixgbevf_irq_disable(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int vector;

	IXGBE_WRITE_REG(hw, IXGBE_VTEIAM, 0);
	IXGBE_WRITE_REG(hw, IXGBE_VTEIMC, ~0);
	IXGBE_WRITE_REG(hw, IXGBE_VTEIAC, 0);

	IXGBE_WRITE_FLUSH(hw);

	for (vector = 0; vector < adapter->num_q_vectors; vector++)
		synchronize_irq(adapter->msix_entries[vector].vector);

	synchronize_irq(adapter->msix_entries[vector].vector);
}

/**
 * ixgbevf_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 **/
static inline void ixgbevf_irq_enable(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;

	IXGBE_WRITE_REG(hw, IXGBE_VTEIAM, adapter->eims_enable_mask);
	IXGBE_WRITE_REG(hw, IXGBE_VTEIAC, adapter->eims_enable_mask);
	IXGBE_WRITE_REG(hw, IXGBE_VTEIMS, adapter->eims_enable_mask);
}

/**
 * ixgbevf_configure_tx_ring - Configure 82599 VF Tx ring after Reset
 * @adapter: board private structure
 * @ring: structure containing ring specific data
 *
 * Configure the Tx descriptor ring after a reset.
 **/
static void ixgbevf_configure_tx_ring(struct ixgbevf_adapter *adapter,
				      struct ixgbevf_ring *ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u64 tdba = ring->dma;
	int wait_loop = 10;
	u32 txdctl = IXGBE_TXDCTL_ENABLE;
	u8 reg_idx = ring->reg_idx;

	/* disable queue to avoid issues while updating state */
	IXGBE_WRITE_REG(hw, IXGBE_VFTXDCTL(reg_idx), IXGBE_TXDCTL_SWFLSH);
	IXGBE_WRITE_FLUSH(hw);

	IXGBE_WRITE_REG(hw, IXGBE_VFTDBAL(reg_idx), tdba & DMA_BIT_MASK(32));
	IXGBE_WRITE_REG(hw, IXGBE_VFTDBAH(reg_idx), tdba >> 32);
	IXGBE_WRITE_REG(hw, IXGBE_VFTDLEN(reg_idx),
			ring->count * sizeof(union ixgbe_adv_tx_desc));

	/* disable head writeback */
	IXGBE_WRITE_REG(hw, IXGBE_VFTDWBAH(reg_idx), 0);
	IXGBE_WRITE_REG(hw, IXGBE_VFTDWBAL(reg_idx), 0);


	/* enable relaxed ordering */
	IXGBE_WRITE_REG(hw, IXGBE_VFDCA_TXCTRL(reg_idx),
			(IXGBE_DCA_TXCTRL_DESC_RRO_EN |
			 IXGBE_DCA_TXCTRL_DATA_RRO_EN));

	/* reset head and tail pointers */
	IXGBE_WRITE_REG(hw, IXGBE_VFTDH(reg_idx), 0);
	IXGBE_WRITE_REG(hw, IXGBE_VFTDT(reg_idx), 0);
	ring->tail = adapter->io_addr + IXGBE_VFTDT(reg_idx);

	/* reset ntu and ntc to place SW in sync with hardwdare */
	ring->next_to_clean = 0;
	ring->next_to_use = 0;

	/* set WTHRESH to encourage burst writeback, it should not be set
	 * higher than 1 when ITR is 0 as it could cause false TX hangs
	 *
	 * In order to avoid issues WTHRESH + PTHRESH should always be equal
	 * to or less than the number of on chip descriptors, which is
	 * currently 40.
	 */
	if (!ring->q_vector || (ring->q_vector->itr < 8))
		txdctl |= (1 << 16);    /* WTHRESH = 1 */
	else
		txdctl |= (8 << 16);    /* WTHRESH = 8 */

	/* Setting PTHRESH to 32 both improves performance */
	txdctl |= (1u << 8) |   /* HTHRESH = 1 */
		   32;          /* PTHRESH = 32 */

	/* reinitialize tx_buffer_info */
	memset(ring->tx_buffer_info, 0,
	       sizeof(struct ixgbevf_tx_buffer) * ring->count);

	clear_bit(__IXGBEVF_HANG_CHECK_ARMED, &ring->state);
	clear_bit(__IXGBEVF_TX_XDP_RING_PRIMED, &ring->state);

	IXGBE_WRITE_REG(hw, IXGBE_VFTXDCTL(reg_idx), txdctl);

	/* poll to verify queue is enabled */
	do {
		msleep(1);
		txdctl = IXGBE_READ_REG(hw, IXGBE_VFTXDCTL(reg_idx));
	}  while (--wait_loop && !(txdctl & IXGBE_TXDCTL_ENABLE));
	if (!wait_loop)
		DPRINTK(HW, DEBUG, "Could not enable Tx Queue %d\n", reg_idx);
}

/**
 * ixgbevf_configure_tx - Configure 82599 VF Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void ixgbevf_configure_tx(struct ixgbevf_adapter *adapter)
{
	u32 i;

	/* Setup the HW Tx Head and Tail descriptor pointers */
	for (i = 0; i < adapter->num_tx_queues; i++)
		ixgbevf_configure_tx_ring(adapter, adapter->tx_ring[i]);
	for (i = 0; i < adapter->num_xdp_queues; i++)
		ixgbevf_configure_tx_ring(adapter, adapter->xdp_ring[i]);
}

static void ixgbevf_configure_srrctl(struct ixgbevf_adapter *adapter,
				     struct ixgbevf_ring *ring, int index)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 srrctl;

	srrctl = IXGBE_SRRCTL_DROP_EN;

	srrctl |= IXGBEVF_RX_HDR_SIZE << IXGBE_SRRCTL_BSIZEHDRSIZE_SHIFT;
	if (ring_uses_large_buffer(ring))
		srrctl |= IXGBEVF_RXBUFFER_3072 >> IXGBE_SRRCTL_BSIZEPKT_SHIFT;
	else
		srrctl |= IXGBEVF_RXBUFFER_2048 >> IXGBE_SRRCTL_BSIZEPKT_SHIFT;
	srrctl |= IXGBE_SRRCTL_DESCTYPE_ADV_ONEBUF;

	IXGBE_WRITE_REG(hw, IXGBE_VFSRRCTL(index), srrctl);
}

static void ixgbevf_setup_psrtype(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;

	/* PSRTYPE must be initialized in 82599 */
	u32 psrtype = IXGBE_PSRTYPE_TCPHDR | IXGBE_PSRTYPE_UDPHDR |
		      IXGBE_PSRTYPE_IPV4HDR | IXGBE_PSRTYPE_IPV6HDR |
		      IXGBE_PSRTYPE_L2HDR;

	if (adapter->num_rx_queues > 1)
		psrtype |= BIT(29);

	IXGBE_WRITE_REG(hw, IXGBE_VFPSRTYPE, psrtype);
}

#define IXGBEVF_MAX_RX_DESC_POLL 10
static void ixgbevf_disable_rx_queue(struct ixgbevf_adapter *adapter,
				     struct ixgbevf_ring *ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int wait_loop = IXGBEVF_MAX_RX_DESC_POLL;
	u32 rxdctl;
	u8 reg_idx = ring->reg_idx;

	if (IXGBE_REMOVED(hw->hw_addr))
		return;
	rxdctl = IXGBE_READ_REG(hw, IXGBE_VFRXDCTL(reg_idx));
	rxdctl &= ~IXGBE_RXDCTL_ENABLE;

	/* write value back with RXDCTL.ENABLE bit cleared */
	IXGBE_WRITE_REG(hw, IXGBE_VFRXDCTL(reg_idx), rxdctl);

	/* the hardware may take up to 100us to really disable the rx queue */
	do {
		udelay(10);
		rxdctl = IXGBE_READ_REG(hw, IXGBE_VFRXDCTL(reg_idx));
	} while (--wait_loop && (rxdctl & IXGBE_RXDCTL_ENABLE));

	if (!wait_loop)
		DPRINTK(PROBE, ERR,
			"RXDCTL.ENABLE queue %d not cleared while polling\n",
                        reg_idx);
}

static void ixgbevf_rx_desc_queue_enable(struct ixgbevf_adapter *adapter,
					 struct ixgbevf_ring *ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int wait_loop = IXGBEVF_MAX_RX_DESC_POLL;
	u32 rxdctl;
	u8 reg_idx = ring->reg_idx;

	if (IXGBE_REMOVED(hw->hw_addr))
		return;
	do {
		usleep_range(1000, 2000);
		rxdctl = IXGBE_READ_REG(hw, IXGBE_VFRXDCTL(reg_idx));
	} while (--wait_loop && !(rxdctl & IXGBE_RXDCTL_ENABLE));

	if (!wait_loop)
		DPRINTK(PROBE, ERR,
			"RXDCTL.ENABLE queue %d not set while polling\n",
                        reg_idx);
}

/**
 * ixgbevf_init_rss_key - Initialize adapter RSS key
 * @adapter: device handle
 *
 * Allocates and initializes the RSS key if it is not allocated.
 */
static inline int ixgbevf_init_rss_key(struct ixgbevf_adapter *adapter)
{
	u32 *rss_key;

	if (!adapter->rss_key) {
		rss_key = kzalloc(IXGBEVF_RSS_HASH_KEY_SIZE, GFP_KERNEL);
		if (unlikely(!rss_key))
			return -ENOMEM;

		netdev_rss_key_fill(rss_key, IXGBEVF_RSS_HASH_KEY_SIZE);
		adapter->rss_key = rss_key;
	}

	return 0;
}

static void ixgbevf_setup_vfmrqc(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 vfmrqc = 0, vfreta = 0;
	u16 rss_i = adapter->num_rx_queues;
	u8 i, j;

	/* Fill out hash function seeds */
	for (i = 0; i < IXGBEVF_VFRSSRK_REGS; i++)
		IXGBE_WRITE_REG(hw, IXGBE_VFRSSRK(i), adapter->rss_key[i]);

	for (i = 0, j = 0; i < IXGBEVF_X550_VFRETA_SIZE; i++, j++) {
		if (j == rss_i)
			j = 0;

		adapter->rss_indir_tbl[i] = j;

		vfreta |= j << (i & 0x3) * 8;
		if ((i & 3) == 3) {
			IXGBE_WRITE_REG(hw, IXGBE_VFRETA(i >> 2), vfreta);
			vfreta = 0;
		}
	}

	/* Perform hash on these packet types */
	vfmrqc |= IXGBE_MRQC_RSS_FIELD_IPV4 |
		IXGBE_MRQC_RSS_FIELD_IPV4_TCP |
		IXGBE_MRQC_RSS_FIELD_IPV6 |
		IXGBE_MRQC_RSS_FIELD_IPV6_TCP;

	vfmrqc |= IXGBE_MRQC_RSSEN;

	IXGBE_WRITE_REG(hw, IXGBE_VFMRQC, vfmrqc);
}

static void ixgbevf_configure_rx_ring(struct ixgbevf_adapter *adapter,
				      struct ixgbevf_ring *ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	union ixgbe_adv_rx_desc *rx_desc;
	u64 rdba = ring->dma;
	u32 rxdctl;
	u8 reg_idx = ring->reg_idx;

	/* disable queue to avoid issues while updating state */
	rxdctl = IXGBE_READ_REG(hw, IXGBE_VFRXDCTL(reg_idx));
	ixgbevf_disable_rx_queue(adapter, ring);

	IXGBE_WRITE_REG(hw, IXGBE_VFRDBAL(reg_idx), rdba & DMA_BIT_MASK(32));
	IXGBE_WRITE_REG(hw, IXGBE_VFRDBAH(reg_idx), rdba >> 32);
	IXGBE_WRITE_REG(hw, IXGBE_VFRDLEN(reg_idx),
			ring->count * sizeof(union ixgbe_adv_rx_desc));

#ifndef CONFIG_SPARC
	/* enable relaxed ordering */
	IXGBE_WRITE_REG(hw, IXGBE_VFDCA_RXCTRL(reg_idx),
			IXGBE_DCA_RXCTRL_DESC_RRO_EN);
#else
	IXGBE_WRITE_REG(hw, IXGBE_VFDCA_RXCTRL(reg_idx),
			IXGBE_DCA_RXCTRL_DESC_RRO_EN |
			IXGBE_DCA_RXCTRL_DATA_WRO_EN);
#endif

	/* reset head and tail pointers */
	IXGBE_WRITE_REG(hw, IXGBE_VFRDH(reg_idx), 0);
	IXGBE_WRITE_REG(hw, IXGBE_VFRDT(reg_idx), 0);
	ring->tail = adapter->io_addr + IXGBE_VFRDT(reg_idx);

	/* initialize rx_buffer_info */
	memset(ring->rx_buffer_info, 0,
	       sizeof(struct ixgbevf_rx_buffer) * ring->count);

	/* initialize Rx descriptor 0 */
	rx_desc = IXGBEVF_RX_DESC(ring, 0);
	rx_desc->wb.upper.length = 0;

	/* reset ntu and ntc to place SW in sync with hardwdare */
	ring->next_to_clean = 0;
	ring->next_to_use = 0;
	ring->next_to_alloc = 0;

	ixgbevf_configure_srrctl(adapter, ring, reg_idx);

	/* RXDCTL.RLPML does not work on 82599 */
	if (adapter->hw.mac.type != ixgbe_mac_82599_vf) {
		rxdctl &= ~(IXGBE_RXDCTL_RLPMLMASK |
			    IXGBE_RXDCTL_RLPML_EN);

#if (PAGE_SIZE < 8192)
		/* Limit the maximum frame size so we don't overrun the skb */
		if (ring_uses_build_skb(ring) &&
		    !ring_uses_large_buffer(ring))
			rxdctl |= IXGBEVF_MAX_FRAME_BUILD_SKB |
				  IXGBE_RXDCTL_RLPML_EN;
#endif
	}

	rxdctl |= IXGBE_RXDCTL_ENABLE | IXGBE_RXDCTL_VME;
	IXGBE_WRITE_REG(hw, IXGBE_VFRXDCTL(reg_idx), rxdctl);

	ixgbevf_rx_desc_queue_enable(adapter, ring);
	ixgbevf_alloc_rx_buffers(ring, ixgbevf_desc_unused(ring));
}

#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
static void ixgbevf_set_rx_buffer_len(struct ixgbevf_adapter *adapter,
				      struct ixgbevf_ring *rx_ring)
{
	struct net_device *netdev = adapter->netdev;
	unsigned int max_frame = netdev->mtu + ETH_HLEN + ETH_FCS_LEN;

	/* set build_skb and buffer size flags */
	clear_ring_build_skb_enabled(rx_ring);
	clear_ring_uses_large_buffer(rx_ring);

	if (adapter->flags & IXGBEVF_FLAGS_LEGACY_RX)
		return;

	set_ring_build_skb_enabled(rx_ring);

	if (PAGE_SIZE < 8192) {
		if (max_frame <= IXGBEVF_MAX_FRAME_BUILD_SKB)
			return;

		set_ring_uses_large_buffer(rx_ring);
	}
}

#endif /* HAVE_SWIOTLB_SKIP_CPU_SYNC */
/**
 * ixgbevf_configure_rx - Configure 82599 VF Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void ixgbevf_configure_rx(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	int i, ret;

	ixgbevf_setup_psrtype(adapter);
	if (hw->mac.type >= ixgbe_mac_X550_vf)
		ixgbevf_setup_vfmrqc(adapter);

	spin_lock_bh(&adapter->mbx_lock);
	ret = hw->mac.ops.set_rlpml(hw, netdev->mtu + ETH_HLEN + ETH_FCS_LEN);
	spin_unlock_bh(&adapter->mbx_lock);
	if (ret)
		DPRINTK(HW, DEBUG, "Failed to set MTU at %d\n", netdev->mtu);

	/* Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring
	 */
	for (i = 0; i < adapter->num_rx_queues; i++) {
		struct ixgbevf_ring *rx_ring = adapter->rx_ring[i];

#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
		ixgbevf_set_rx_buffer_len(adapter, rx_ring);
#endif
		ixgbevf_configure_rx_ring(adapter, rx_ring);
	}
}

#ifdef HAVE_VLAN_RX_REGISTER
static void ixgbevf_vlan_rx_register(struct net_device *netdev,
				     struct vlan_group *grp)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	int i, j;
	u32 ctrl;

	adapter->vlgrp = grp;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		j = adapter->rx_ring[i]->reg_idx;
		ctrl = IXGBE_READ_REG(hw, IXGBE_VFRXDCTL(j));
		ctrl |= IXGBE_RXDCTL_VME;
		IXGBE_WRITE_REG(hw, IXGBE_VFRXDCTL(j), ctrl);
	}
}
#endif /* HAVE_VLAN_RX_REGISTER */

#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
#ifdef NETIF_F_HW_VLAN_CTAG_TX
static int ixgbevf_vlan_rx_add_vid(struct net_device *netdev,
				   __always_unused __be16 proto, u16 vid)
#else /* !NETIF_F_HW_VLAN_CTAG_TX */
static int ixgbevf_vlan_rx_add_vid(struct net_device *netdev, u16 vid)
#endif /* NETIF_F_HW_VLAN_CTAG_TX */
#else
static void ixgbevf_vlan_rx_add_vid(struct net_device *netdev, u16 vid)
#endif
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
#ifndef HAVE_NETDEV_VLAN_FEATURES
	struct net_device *v_netdev;
#endif /* HAVE_NETDEV_VLAN_FEATURES */
	int ret_val;

	spin_lock_bh(&adapter->mbx_lock);

	/* add VID to filter table */
	ret_val = hw->mac.ops.set_vfta(hw, vid, 0, true, false);

	spin_unlock_bh(&adapter->mbx_lock);

	if (ret_val) {
		printk(KERN_ERR "VF could not set VLAN %d\n", vid);
	} else {
#ifndef HAVE_NETDEV_VLAN_FEATURES

		/*
		 * Copy feature flags from netdev to the vlan netdev for this
		 * vid.  This allows things like TSO to bubble down to our
		 * vlan device.
		 */
		if (adapter->vlgrp) {
			v_netdev = vlan_group_get_device(adapter->vlgrp, vid);
			if (v_netdev) {
				v_netdev->features |= adapter->netdev->features;
				vlan_group_set_device(adapter->vlgrp,
						      vid, v_netdev);
			}
		}
#endif /* HAVE_NETDEV_VLAN_FEATURES */
#ifndef HAVE_VLAN_RX_REGISTER
		if (vid < VLAN_N_VID)
			set_bit(vid, adapter->active_vlans);
#endif
	}

#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
	return ret_val;
#endif
}

#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
#ifdef NETIF_F_HW_VLAN_CTAG_RX
static int ixgbevf_vlan_rx_kill_vid(struct net_device *netdev,
				  __always_unused __be16 proto, u16 vid)
#else /* !NETIF_F_HW_VLAN_CTAG_RX */
static int ixgbevf_vlan_rx_kill_vid(struct net_device *netdev, u16 vid)
#endif /* NETIF_F_HW_VLAN_CTAG_RX */
#else
static void ixgbevf_vlan_rx_kill_vid(struct net_device *netdev, u16 vid)
#endif
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;

#ifndef HAVE_NETDEV_VLAN_FEATURES
	if (!test_bit(__IXGBEVF_DOWN, &adapter->state))
		ixgbevf_irq_disable(adapter);

	vlan_group_set_device(adapter->vlgrp, vid, NULL);

	if (!test_bit(__IXGBEVF_DOWN, &adapter->state))
		ixgbevf_irq_enable(adapter);
#endif

	spin_lock_bh(&adapter->mbx_lock);

	/* remove VID from filter table */
	hw->mac.ops.set_vfta(hw, vid, 0, false, false);

	spin_unlock_bh(&adapter->mbx_lock);

#ifndef HAVE_VLAN_RX_REGISTER
	clear_bit(vid, adapter->active_vlans);
#endif
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
	return 0;
#endif
}

static void ixgbevf_restore_vlan(struct ixgbevf_adapter *adapter)
{
	u16 vid;

#ifdef HAVE_VLAN_RX_REGISTER
	ixgbevf_vlan_rx_register(adapter->netdev, adapter->vlgrp);

	if (adapter->vlgrp) {
		for (vid = 0; vid < VLAN_N_VID; vid++) {
			if (!vlan_group_get_device(adapter->vlgrp, vid))
				continue;
#ifdef NETIF_F_HW_VLAN_CTAG_RX
			ixgbevf_vlan_rx_add_vid(adapter->netdev,
						htons(ETH_P_8021Q),
						vid);
#else
			ixgbevf_vlan_rx_add_vid(adapter->netdev, vid);
#endif /* NETIF_F_HW_VLAN_CTAG_RX */
		}
	}
#else /* !HAVE_VLAN_RX_REGISTER */
	for_each_set_bit(vid, adapter->active_vlans, VLAN_N_VID)
#ifdef NETIF_F_HW_VLAN_CTAG_RX
		ixgbevf_vlan_rx_add_vid(adapter->netdev, htons(ETH_P_8021Q),
					vid);
#else
		ixgbevf_vlan_rx_add_vid(adapter->netdev, vid);
#endif
#endif /* HAVE_VLAN_RX_REGISTER */
}
#endif /* NETIF_F_HW_VLAN_TX || NETIF_F_HW_VLAN_CTAG_TX*/

static u8 *ixgbevf_addr_list_itr(struct ixgbe_hw __maybe_unused *hw, u8 **mc_addr_ptr,
				 u32 *vmdq)
{
#ifdef NETDEV_HW_ADDR_T_MULTICAST
	struct netdev_hw_addr *mc_ptr;
#else
	struct dev_mc_list *mc_ptr;
#endif
	u8 *addr = *mc_addr_ptr;
	*vmdq = 0;

#ifdef NETDEV_HW_ADDR_T_MULTICAST
	mc_ptr = container_of(addr, struct netdev_hw_addr, addr[0]);
	if (mc_ptr->list.next) {
		struct netdev_hw_addr *ha;

		ha = list_entry(mc_ptr->list.next, struct netdev_hw_addr, list);
		*mc_addr_ptr = ha->addr;
	}
#else
	mc_ptr = container_of(addr, struct dev_mc_list, dmi_addr[0]);
	if (mc_ptr->next)
		*mc_addr_ptr = mc_ptr->next->dmi_addr;
#endif
	else
		*mc_addr_ptr = NULL;

	return addr;
}

#ifdef NETDEV_HW_ADDR_T_UNICAST
static int ixgbevf_write_uc_addr_list(struct net_device *netdev)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	int count = 0;

	if (!netdev_uc_empty(netdev)) {
		struct netdev_hw_addr *ha;
		netdev_for_each_uc_addr(ha, netdev) {
			hw->mac.ops.set_uc_addr(hw, ++count, ha->addr);
			udelay(200);
		}
	} else {
		/*
		 * If the list is empty then send message to PF driver to
		 * clear all macvlans on this VF.
		 */
		hw->mac.ops.set_uc_addr(hw, 0, NULL);
	}

	return count;
}

#endif
/**
 * ixgbevf_set_rx_mode - Multicast and unicast set
 * @netdev: network interface device structure
 *
 * The set_rx_method entry point is called whenever the multicast address
 * list, unicast address list or the network interface flags are updated.
 * This routine is responsible for configuring the hardware for proper
 * multicast mode and configuring requested unicast filters.
 **/
static void ixgbevf_set_rx_mode(struct net_device *netdev)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	unsigned int flags = netdev->flags;
	int xcast_mode;
	u8 *addr_list = NULL;
	int addr_count = 0;

	/* request the most inclusive mode we need */
	if (flags & IFF_PROMISC)
		xcast_mode = IXGBEVF_XCAST_MODE_PROMISC;
	else if (flags & IFF_ALLMULTI)
		xcast_mode = IXGBEVF_XCAST_MODE_ALLMULTI;
	else if (flags & (IFF_BROADCAST | IFF_MULTICAST))
		xcast_mode = IXGBEVF_XCAST_MODE_MULTI;
	else
		xcast_mode = IXGBEVF_XCAST_MODE_NONE;

	/* reprogram multicast list */
	addr_count = netdev_mc_count(netdev);
	if (addr_count)
#ifdef NETDEV_HW_ADDR_T_MULTICAST
	{
		struct netdev_hw_addr *ha;

		ha = list_first_entry(&netdev->mc.list,
			struct netdev_hw_addr, list);
		addr_list = ha->addr;
	}
#else
		addr_list = netdev->mc_list->dmi_addr;
#endif
	spin_lock_bh(&adapter->mbx_lock);

	hw->mac.ops.update_xcast_mode(hw, xcast_mode);

	hw->mac.ops.update_mc_addr_list(hw, addr_list, addr_count,
					ixgbevf_addr_list_itr, false);

#ifdef NETDEV_HW_ADDR_T_UNICAST
	ixgbevf_write_uc_addr_list(netdev);
#endif

	spin_unlock_bh(&adapter->mbx_lock);
}

static void ixgbevf_napi_enable_all(struct ixgbevf_adapter *adapter)
{
	int q_idx;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++) {
#ifdef HAVE_NDO_BUSY_POLL
		ixgbevf_qv_init_lock(adapter->q_vector[q_idx]);
#endif
		napi_enable(&adapter->q_vector[q_idx]->napi);
	}
}

static void ixgbevf_napi_disable_all(struct ixgbevf_adapter *adapter)
{
	int q_idx;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++) {
		napi_disable(&adapter->q_vector[q_idx]->napi);
#ifdef HAVE_NDO_BUSY_POLL
		while(!ixgbevf_qv_disable(adapter->q_vector[q_idx])) {
			pr_info("QV %d locked\n", q_idx);
			usleep_range(1000, 20000);
		}
#endif /* HAVE_NDO_BUSY_POLL */
	}
}

static int ixgbevf_configure_dcb(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	unsigned int def_q = 0;
	unsigned int num_tcs = 0;
	unsigned int num_rx_queues = adapter->num_rx_queues;
	unsigned int num_tx_queues = adapter->num_tx_queues;
	int err;

	spin_lock_bh(&adapter->mbx_lock);

	/* fetch queue configuration from the PF */
	err = ixgbevf_get_queues(hw, &num_tcs, &def_q);

	spin_unlock_bh(&adapter->mbx_lock);

	if (err)
		return err;

	if (num_tcs > 1) {
		/* we need only one Tx queue */
		num_tx_queues = 1;

		/* update default Tx ring register index */
		adapter->tx_ring[0]->reg_idx = def_q;

		/* we need as many queues as traffic classes */
		num_rx_queues = num_tcs;
	}

	/* if we have a bad config abort request queue reset */
	if ((adapter->num_rx_queues != num_rx_queues) ||
	    (adapter->num_tx_queues != num_tx_queues)) {
		/* force mailbox timeout to prevent further messages */
		hw->mbx.timeout = 0;

		/* wait for watchdog to come around and bail us out */
		set_bit(__IXGBEVF_QUEUE_RESET_REQUESTED, &adapter->state);
	}

	return 0;
}

static void ixgbevf_configure(struct ixgbevf_adapter *adapter)
{
	ixgbevf_configure_dcb(adapter);

	ixgbevf_set_rx_mode(adapter->netdev);

#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	ixgbevf_restore_vlan(adapter);

#endif
	ixgbevf_configure_tx(adapter);
	ixgbevf_configure_rx(adapter);

#ifdef HAVE_PF_RING
	{
		struct ixgbe_hw *hw = &adapter->hw;
		int i;
		u16 cache_line_size = 64;
 
		for (i = 0; i < adapter->num_rx_queues; i++) {
			struct ixgbevf_ring *rx_ring = adapter->rx_ring[i];
			struct ixgbevf_ring *tx_ring = adapter->tx_ring[i];	     
			mem_ring_info rx_info = { 0 };
			mem_ring_info tx_info = { 0 };
			u16 rx_buf_len;

			if (ring_uses_large_buffer(rx_ring))
				rx_buf_len = IXGBEVF_RXBUFFER_3072;
			else
				rx_buf_len = IXGBEVF_RXBUFFER_2048;

			init_waitqueue_head(&rx_ring->pfring_zc.rx_tx.rx.packet_waitqueue);

			rx_info.num_queues = adapter->num_rx_queues;
			rx_info.packet_memory_num_slots     = rx_ring->count;
			rx_info.packet_memory_slot_len      = ALIGN(rx_buf_len, cache_line_size);
			rx_info.descr_packet_memory_tot_len = rx_ring->size;
	      
			tx_info.num_queues = adapter->num_tx_queues;
			tx_info.packet_memory_num_slots     = tx_ring->count;
			tx_info.packet_memory_slot_len      = rx_info.packet_memory_slot_len;
			tx_info.descr_packet_memory_tot_len = tx_ring->size;
	     
			if(unlikely(enable_debug))
				printk("%s: [rx-ring=%u/%u/%u][tx-ring=%u/%u/%u]\n", __FUNCTION__,
				  rx_info.packet_memory_num_slots,
				  rx_info.packet_memory_slot_len,
				  rx_ring->size,
				  tx_info.packet_memory_num_slots,
				  tx_info.packet_memory_slot_len,
				  tx_ring->size);
 
			pf_ring_zc_dev_handler(add_device_mapping,
			  &rx_info,
			  &tx_info,
			  rx_ring->desc, /* Packet descriptors */
			  tx_ring->desc, /* Packet descriptors */
			  (void *) rx_ring->netdev->mem_start,
			  rx_ring->netdev->mem_end - rx_ring->netdev->mem_start,
			  rx_ring->queue_index, /* Channel Id */
			  rx_ring->netdev,
			  rx_ring->dev, /* for DMA mapping */
			  pfring_zc_dev_model(hw),
			  rx_ring->netdev->dev_addr,
			  &rx_ring->pfring_zc.rx_tx.rx.packet_waitqueue,
			  &rx_ring->pfring_zc.rx_tx.rx.interrupt_received,
			  (void *) rx_ring,
			  (void *) tx_ring,
			  wait_packet_function_ptr,
			  notify_function_ptr
			);
	    	}
	}
#endif
}

static void ixgbevf_save_reset_stats(struct ixgbevf_adapter *adapter)
{
	/* Only save pre-reset stats if there are some */
	if (adapter->stats.vfgprc || adapter->stats.vfgptc) {
		adapter->stats.saved_reset_vfgprc += adapter->stats.vfgprc -
			adapter->stats.base_vfgprc;
		adapter->stats.saved_reset_vfgptc += adapter->stats.vfgptc -
			adapter->stats.base_vfgptc;
		adapter->stats.saved_reset_vfgorc += adapter->stats.vfgorc -
			adapter->stats.base_vfgorc;
		adapter->stats.saved_reset_vfgotc += adapter->stats.vfgotc -
			adapter->stats.base_vfgotc;
		adapter->stats.saved_reset_vfmprc += adapter->stats.vfmprc -
			adapter->stats.base_vfmprc;
	}
}

static void ixgbevf_init_last_counter_stats(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;

	adapter->stats.last_vfgprc = IXGBE_READ_REG(hw, IXGBE_VFGPRC);
	adapter->stats.last_vfgorc = IXGBE_READ_REG(hw, IXGBE_VFGORC_LSB);
	adapter->stats.last_vfgorc |=
		(((u64)(IXGBE_READ_REG(hw, IXGBE_VFGORC_MSB))) << 32);
	adapter->stats.last_vfgptc = IXGBE_READ_REG(hw, IXGBE_VFGPTC);
	adapter->stats.last_vfgotc = IXGBE_READ_REG(hw, IXGBE_VFGOTC_LSB);
	adapter->stats.last_vfgotc |=
		(((u64)(IXGBE_READ_REG(hw, IXGBE_VFGOTC_MSB))) << 32);
	adapter->stats.last_vfmprc = IXGBE_READ_REG(hw, IXGBE_VFMPRC);

	adapter->stats.base_vfgprc = adapter->stats.last_vfgprc;
	adapter->stats.base_vfgorc = adapter->stats.last_vfgorc;
	adapter->stats.base_vfgptc = adapter->stats.last_vfgptc;
	adapter->stats.base_vfgotc = adapter->stats.last_vfgotc;
	adapter->stats.base_vfmprc = adapter->stats.last_vfmprc;
}

static void ixgbevf_negotiate_api(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int api[] = { ixgbe_mbox_api_13,
		      ixgbe_mbox_api_12,
		      ixgbe_mbox_api_11,
		      ixgbe_mbox_api_10,
		      ixgbe_mbox_api_unknown };
	int err = 0, idx = 0;

	spin_lock_bh(&adapter->mbx_lock);

	while (api[idx] != ixgbe_mbox_api_unknown) {
		err = hw->mac.ops.negotiate_api_version(hw, api[idx]);
		if (!err)
			break;
		idx++;
	}

	spin_unlock_bh(&adapter->mbx_lock);
}

static void ixgbevf_up_complete(struct ixgbevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct ixgbe_hw *hw = &adapter->hw;

#ifdef CONFIG_NETDEVICES_MULTIQUEUE
	if (adapter->num_tx_queues > 1)
		netdev->features |= NETIF_F_MULTI_QUEUE;

#endif
	ixgbevf_configure_msix(adapter);

	spin_lock_bh(&adapter->mbx_lock);

	if (is_valid_ether_addr(hw->mac.addr))
		hw->mac.ops.set_rar(hw, 0, hw->mac.addr,
				0, IXGBE_RAH_AV);
	else
		hw->mac.ops.set_rar(hw, 0, hw->mac.perm_addr,
				0, IXGBE_RAH_AV);

	spin_unlock_bh(&adapter->mbx_lock);

	smp_mb__before_atomic();
	clear_bit(__IXGBEVF_DOWN, &adapter->state);
	ixgbevf_napi_enable_all(adapter);

	/* clear any pending interrupts, may auto mask */
	IXGBE_READ_REG(hw, IXGBE_VTEICR);
	ixgbevf_irq_enable(adapter);

	/* enable transmits */
	netif_tx_start_all_queues(netdev);

	ixgbevf_save_reset_stats(adapter);
	ixgbevf_init_last_counter_stats(adapter);

	hw->mac.get_link_status = 1;
	mod_timer(&adapter->service_timer, jiffies);
}

void ixgbevf_up(struct ixgbevf_adapter *adapter)
{
	ixgbevf_configure(adapter);

	ixgbevf_up_complete(adapter);
}

/**
 * ixgbevf_clean_rx_ring - Free Rx Buffers per Queue
 * @rx_ring: ring to free buffers from
 **/
static void ixgbevf_clean_rx_ring(struct ixgbevf_ring *rx_ring)
{
	u16 i = rx_ring->next_to_clean;
#if defined(HAVE_STRUCT_DMA_ATTRS) && defined(HAVE_SWIOTLB_SKIP_CPU_SYNC)
	DEFINE_DMA_ATTRS(attrs);

	dma_set_attr(DMA_ATTR_SKIP_CPU_SYNC, &attrs);
	dma_set_attr(DMA_ATTR_WEAK_ORDERING, &attrs);
#endif

	/* Free Rx ring sk_buff */
	if (rx_ring->skb) {
		dev_kfree_skb(rx_ring->skb);
		rx_ring->skb = NULL;
	}

	/* Free all the Rx ring pages */
	while (i != rx_ring->next_to_alloc) {
		struct ixgbevf_rx_buffer *rx_buffer;

		rx_buffer = &rx_ring->rx_buffer_info[i];

		/* Invalidate cache lines that may have been written to by
		 * device so that we avoid corrupting memory.
		 */
		dma_sync_single_range_for_cpu(rx_ring->dev,
					      rx_buffer->dma,
					      rx_buffer->page_offset,
					      ixgbevf_rx_bufsz(rx_ring),
					      DMA_FROM_DEVICE);

		/* free resources associated with mapping */
		dma_unmap_page_attrs(rx_ring->dev,
				     rx_buffer->dma,
				     ixgbevf_rx_pg_size(rx_ring),
				     DMA_FROM_DEVICE,
#if defined(HAVE_STRUCT_DMA_ATTRS) && defined(HAVE_SWIOTLB_SKIP_CPU_SYNC)
				     &attrs);
#else
				     IXGBEVF_RX_DMA_ATTR);
#endif

		__page_frag_cache_drain(rx_buffer->page,
					rx_buffer->pagecnt_bias);

		i++;
		if (i == rx_ring->count)
			i = 0;
	}

	rx_ring->next_to_alloc = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
}

/**
 * ixgbevf_clean_tx_ring - Free Tx Buffers
 * @tx_ring: ring to be cleaned
 **/
static void ixgbevf_clean_tx_ring(struct ixgbevf_ring *tx_ring)
{
	u16 i = tx_ring->next_to_clean;
	struct ixgbevf_tx_buffer *tx_buffer = &tx_ring->tx_buffer_info[i];

	while (i != tx_ring->next_to_use) {
		union ixgbe_adv_tx_desc *eop_desc, *tx_desc;

		/* Free all the Tx ring sk_buffs */
#ifdef HAVE_XDP_SUPPORT
		if (ring_is_xdp(tx_ring))
			page_frag_free(tx_buffer->data);
		else
			dev_kfree_skb_any(tx_buffer->skb);
#else
		dev_kfree_skb_any(tx_buffer->skb);
#endif

		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buffer, dma),
				 dma_unmap_len(tx_buffer, len),
				 DMA_TO_DEVICE);

		/* check for eop_desc to determine the end of the packet */
		eop_desc = tx_buffer->next_to_watch;
		tx_desc = IXGBEVF_TX_DESC(tx_ring, i);

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			tx_buffer++;
			tx_desc++;
			i++;
			if (unlikely(i == tx_ring->count)) {
				i = 0;
				tx_buffer = tx_ring->tx_buffer_info;
				tx_desc = IXGBEVF_TX_DESC(tx_ring, 0);
			}

			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buffer, len))
				dma_unmap_page(tx_ring->dev,
					       dma_unmap_addr(tx_buffer, dma),
					       dma_unmap_len(tx_buffer, len),
					       DMA_TO_DEVICE);
		}

		/* move us one more past the eop_desc for start of next pkt */
		tx_buffer++;
		i++;
		if (unlikely(i == tx_ring->count)) {
			i = 0;
			tx_buffer = tx_ring->tx_buffer_info;
		}
	}

	/* reset BQL for queue */
	if (!ring_is_xdp(tx_ring))
		netdev_tx_reset_queue(txring_txq(tx_ring));

	/* reset next_to_use and next_to_clean */
	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;
}

/**
 * ixgbevf_clean_all_rx_rings - Free Rx Buffers for all queues
 * @adapter: board private structure
 **/
static void ixgbevf_clean_all_rx_rings(struct ixgbevf_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		ixgbevf_clean_rx_ring(adapter->rx_ring[i]);
}

/**
 * ixgbevf_clean_all_tx_rings - Free Tx Buffers for all queues
 * @adapter: board private structure
 **/
static void ixgbevf_clean_all_tx_rings(struct ixgbevf_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		ixgbevf_clean_tx_ring(adapter->tx_ring[i]);
	for (i = 0; i < adapter->num_xdp_queues; i++)
		ixgbevf_clean_tx_ring(adapter->xdp_ring[i]);
}

void ixgbevf_down(struct ixgbevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct ixgbe_hw *hw = &adapter->hw;
	int i;

	/* signal that we are down to the interrupt handler */
	if (test_and_set_bit(__IXGBEVF_DOWN, &adapter->state))
		return; /* do nothing if already down */

	/* disable all enabled rx queues */
	for (i = 0; i < adapter->num_rx_queues; i++)
		ixgbevf_disable_rx_queue(adapter, adapter->rx_ring[i]);

	usleep_range(10000, 20000);

	netif_tx_stop_all_queues(netdev);

	/* call carrier off first to avoid false dev_watchdog timeouts */
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	ixgbevf_irq_disable(adapter);

	ixgbevf_napi_disable_all(adapter);

	del_timer_sync(&adapter->service_timer);

	/* disable transmits in the hardware now that interrupts are off */
	for (i = 0; i < adapter->num_tx_queues; i++) {
		u8 reg_idx = adapter->tx_ring[i]->reg_idx;
		IXGBE_WRITE_REG(hw, IXGBE_VFTXDCTL(reg_idx),
				IXGBE_TXDCTL_SWFLSH);
	}

	for (i = 0; i < adapter->num_xdp_queues; i++) {
		u8 reg_idx = adapter->xdp_ring[i]->reg_idx;

		IXGBE_WRITE_REG(hw, IXGBE_VFTXDCTL(reg_idx),
				IXGBE_TXDCTL_SWFLSH);
	}

#ifdef HAVE_PCI_ERS
	if (!pci_channel_offline(adapter->pdev))
#endif
		ixgbevf_reset(adapter);

#ifdef HAVE_PF_RING
	{
		int i;

		for (i = 0; i < adapter->num_rx_queues; i++) {
			pf_ring_zc_dev_handler(remove_device_mapping,
			  NULL, /* rx_info */
			  NULL, /* tx_info */
			  NULL, /* Packet descriptors */
			  NULL, /* Packet descriptors */
			  NULL, /* mem_start */
			  0, /* mem_end - mem_start, */
			  adapter->rx_ring[i]->queue_index, /* Channel Id */
			  adapter->rx_ring[i]->netdev,
			  adapter->rx_ring[i]->dev, /* for DMA mapping */
			  pfring_zc_dev_model(hw),
			  adapter->rx_ring[i]->netdev->dev_addr,
			  &adapter->rx_ring[i]->pfring_zc.rx_tx.rx.packet_waitqueue,
			  &adapter->rx_ring[i]->pfring_zc.rx_tx.rx.interrupt_received,
			  (void *) adapter->rx_ring[i],
			  (void *) adapter->tx_ring[i],
			  NULL, /* wait_packet_function_ptr */
			  NULL /* notify_function_ptr */
			);
		}
	}
#endif

	ixgbevf_clean_all_tx_rings(adapter);
	ixgbevf_clean_all_rx_rings(adapter);
}

void ixgbevf_reinit_locked(struct ixgbevf_adapter *adapter)
{
	WARN_ON(in_interrupt());

	while (test_and_set_bit(__IXGBEVF_RESETTING, &adapter->state))
		msleep(1);

	ixgbevf_down(adapter);
	ixgbevf_up(adapter);

	clear_bit(__IXGBEVF_RESETTING, &adapter->state);
}

void ixgbevf_reset(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;

	if (IXGBE_REMOVED(hw->hw_addr))
		return;
	if (hw->mac.ops.reset_hw(hw)) {
		DPRINTK(PROBE, ERR, "PF still resetting\n");
	} else {
		hw->mac.ops.init_hw(hw);
		ixgbevf_negotiate_api(adapter);
	}

	if (is_valid_ether_addr(adapter->hw.mac.addr)) {
		ether_addr_copy(netdev->dev_addr, adapter->hw.mac.addr);
		ether_addr_copy(netdev->perm_addr, adapter->hw.mac.addr);
	}

	adapter->last_reset = jiffies;
}

static int ixgbevf_acquire_msix_vectors(struct ixgbevf_adapter *adapter,
					int vectors)
{
	int vector_threshold;

	/* We'll want at least 2 (vector_threshold):
	 * 1) TxQ[0] + RxQ[0] handler
	 * 2) Other (Link Status Change, etc.)
	 */
	vector_threshold = MIN_MSIX_COUNT;

	/* The more we get, the more we will assign to Tx/Rx Cleanup
	 * for the separate queues...where Rx Cleanup >= Tx Cleanup.
	 * Right now, we simply care about how many we'll get; we'll
	 * set them up later while requesting irq's.
	 */
	vectors = pci_enable_msix_range(adapter->pdev, adapter->msix_entries,
					vector_threshold, vectors);

	if (vectors < 0) {
		DPRINTK(HW, DEBUG, "Unable to allocate MSI-X interrupts\n");
		kfree(adapter->msix_entries);
		adapter->msix_entries = NULL;
		return vectors;
	}

	/* Adjust for only the vectors we'll use, which is the number of
	 * vectors we were allocated.
	 */
	adapter->num_q_vectors = vectors - NON_Q_VECTORS;

	return 0;
}

/**
 * ixgbevf_set_num_queues - Allocate queues for device, feature dependent
 * @adapter: board private structure to initialize
 *
 * This is the top level queue allocation routine.  The order here is very
 * important, starting with the "most" number of features turned on at once,
 * and ending with the smallest set of features.  This way large combinations
 * can be allocated if they're turned on, and smaller combinations are the
 * fallthrough conditions.
 *
 **/
static void ixgbevf_set_num_queues(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	unsigned int def_q = 0;
	unsigned int num_tcs = 0;
	int err;

	/* Start with base case */
	adapter->num_rx_queues = 1;
	adapter->num_tx_queues = 1;
	adapter->num_xdp_queues = 0;

	spin_lock_bh(&adapter->mbx_lock);

	/* fetch queue configuration from the PF */
	err = ixgbevf_get_queues(hw, &num_tcs, &def_q);

	spin_unlock_bh(&adapter->mbx_lock);

	if (err)
		return;

	/* we need as many queues as traffic classes */
	if (num_tcs > 1) {
		adapter->num_rx_queues = num_tcs;
	} else {
		u16 rss = min_t(u16, num_online_cpus(), IXGBEVF_MAX_RSS_QUEUES);
#ifdef HAVE_PF_RING
		rss = 1;
#endif

		switch (hw->api_version) {
		case ixgbe_mbox_api_11:
		case ixgbe_mbox_api_12:
		case ixgbe_mbox_api_13:
			if (adapter->xdp_prog &&
			    hw->mac.max_tx_queues == rss)
				rss = rss > 3 ? 2 : 1;

			adapter->num_rx_queues = rss;
#ifdef HAVE_TX_MQ
			adapter->num_tx_queues = rss;
#endif
			adapter->num_xdp_queues = adapter->xdp_prog ? rss : 0;
		default:
			break;
		}
	}
}

/**
 * ixgbevf_set_interrupt_capability - set MSI-X or FAIL if not supported
 * @adapter: board private structure to initialize
 *
 * Attempt to configure the interrupts using the best available
 * capabilities of the hardware and the kernel.
 */
static int ixgbevf_set_interrupt_capability(struct ixgbevf_adapter *adapter)
{
	int vector, v_budget;

	/* It's easy to be greedy for MSI-X vectors, but it really
	 * doesn't do us much good if we have a lot more vectors
	 * than CPU's.  So let's be conservative and only ask for
	 * (roughly) the same number of vectors as there are CPU's.
	 * The default is to use pairs of vectors.
	 */
	v_budget = max(adapter->num_rx_queues, adapter->num_tx_queues);
	v_budget = min_t(int, v_budget, num_online_cpus());
	v_budget += NON_Q_VECTORS;

	adapter->msix_entries = kcalloc(v_budget,
					sizeof(struct msix_entry), GFP_KERNEL);
	if (!adapter->msix_entries) {
		return -ENOMEM;
	}

	for (vector = 0; vector < v_budget; vector++)
		adapter->msix_entries[vector].entry = vector;

	/* A failure in MSI-X entry allocation isn't fatal, but the VF driver
	 * does not support any other modes, so we will simply fail here. Note
	 * that we clean up the msix_entries pointer else-where.
	 */
	return ixgbevf_acquire_msix_vectors(adapter, v_budget);
}

static void ixgbevf_add_ring(struct ixgbevf_ring *ring,
			     struct ixgbevf_ring_container *head)
{
	ring->next = head->ring;
	head->ring = ring;
	head->count++;
}

/**
 * ixgbevf_alloc_q_vector - Allocate memory for a single interrupt vector
 * @adapter: board private structure to initialize
 * @v_idx: index of vector in adapter struct
 * @txr_count: number of Tx rings for q vector
 * @txr_idx: index of first Tx ring to assign
 * @xdp_count: total number of XDP rings to allocate
 * @xdp_idx: index of first XDP ring to allocate
 * @rxr_count: number of Rx rings for q vector
 * @rxr_idx: index of first Rx ring to assign
 *
 * We allocate one q_vector.  If allocation fails we return -ENOMEM.
 **/
static int ixgbevf_alloc_q_vector(struct ixgbevf_adapter *adapter, int v_idx,
				  int txr_count, int txr_idx,
				  int xdp_count, int xdp_idx,
				  int rxr_count, int rxr_idx)
{
	struct ixgbevf_q_vector *q_vector;
	int reg_idx = txr_idx + xdp_idx;
	struct ixgbevf_ring *ring;
	int ring_count, size;

	ring_count = txr_count + xdp_count + rxr_count;
	size = sizeof(*q_vector) + (sizeof(*ring) * ring_count);

	/* allocate q_vector and rings */
	q_vector = kzalloc(size, GFP_KERNEL);
	if (!q_vector)
		return -ENOMEM;

	/* initialize NAPI */
	netif_napi_add(adapter->netdev, &q_vector->napi, ixgbevf_poll, 64);

	/* tie q_vector and adapter together */
	adapter->q_vector[v_idx] = q_vector;
	q_vector->adapter = adapter;
	q_vector->v_idx = v_idx;

	/* initialize pointer to rings */
	ring = q_vector->ring;

	while (txr_count) {
		/* assign generic ring traits */
		ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Tx values */
		ixgbevf_add_ring(ring, &q_vector->tx);

		/* apply Tx specific ring traits */
		ring->count = adapter->tx_ring_count;
		ring->queue_index = txr_idx;
		ring->reg_idx = reg_idx;

		/* assign ring to adapter */
		 adapter->tx_ring[txr_idx] = ring;

		/* update count and index */
		txr_count--;
		txr_idx++;
		reg_idx++;

		/* push pointer to next ring */
		ring++;
	}

	while (xdp_count) {
		/* assign generic ring traits */
		ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Tx values */
		ixgbevf_add_ring(ring, &q_vector->tx);

		/* apply Tx specific ring traits */
		ring->count = adapter->tx_ring_count;
		ring->queue_index = xdp_idx;
		ring->reg_idx = reg_idx;
		set_ring_xdp(ring);

		/* assign ring to adapter */
		adapter->xdp_ring[xdp_idx] = ring;

		/* update count and index */
		xdp_count--;
		xdp_idx++;
		reg_idx++;

		/* push pointer to next ring */
		ring++;
	}

	while (rxr_count) {
		/* assign generic ring traits */
		ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Rx values */
		ixgbevf_add_ring(ring, &q_vector->rx);

		/* 82599 errata, UDP frames with a 0 checksum
		 * can be marked as checksum errors.
		 */
		if (adapter->hw.mac.type == ixgbe_mac_82599_vf)
			set_bit(__IXGBEVF_RX_CSUM_UDP_ZERO_ERR, &ring->state);

		/* apply Rx specific ring traits */
		ring->count = adapter->rx_ring_count;
		ring->queue_index = rxr_idx;
		ring->reg_idx = rxr_idx;

		/* assign ring to adapter */
		adapter->rx_ring[rxr_idx] = ring;

		/* update count and index */
		rxr_count--;
		rxr_idx++;

		/* push pointer to next ring */
		ring++;
	}
#ifndef HAVE_NETIF_NAPI_ADD_CALLS_NAPI_HASH_ADD
#ifdef HAVE_NDO_BUSY_POLL

	napi_hash_add(&q_vector->napi);
#endif
#endif

	return 0;
}

/**
 * ixgbevf_free_q_vector - Free memory allocated for specific interrupt vector
 * @adapter: board private structure to initialize
 * @v_idx: index of vector in adapter struct
 *
 * This function frees the memory allocated to the q_vector.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 **/
static void ixgbevf_free_q_vector(struct ixgbevf_adapter *adapter, int v_idx)
{
	struct ixgbevf_q_vector *q_vector = adapter->q_vector[v_idx];
	struct ixgbevf_ring *ring;

	ixgbevf_for_each_ring(ring, q_vector->tx) {
		if (ring_is_xdp(ring))
			adapter->xdp_ring[ring->queue_index] = NULL;
		else
			adapter->tx_ring[ring->queue_index] = NULL;
	}

	ixgbevf_for_each_ring(ring, q_vector->rx)
		adapter->rx_ring[ring->queue_index] = NULL;

	adapter->q_vector[v_idx] = NULL;
#ifdef HAVE_NDO_BUSY_POLL
	napi_hash_del(&q_vector->napi);
#endif
	netif_napi_del(&q_vector->napi);

	/* ixgbe_get_stats64() might access the rings on this vector,
	 * we must wait a grace period before freeing it.
	 */
	kfree_rcu(q_vector, rcu);
}

/**
 * ixgbevf_alloc_q_vectors - Allocate memory for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * We allocate one q_vector per queue interrupt.  If allocation fails we
 * return -ENOMEM.
 **/
static int ixgbevf_alloc_q_vectors(struct ixgbevf_adapter *adapter)
{
	int q_vectors = adapter->num_q_vectors;
	int rxr_remaining = adapter->num_rx_queues;
	int txr_remaining = adapter->num_tx_queues;
	int xdp_remaining = adapter->num_xdp_queues;
	int rxr_idx = 0, txr_idx = 0, xdp_idx = 0, v_idx = 0;
	int err;

	if (q_vectors >= (rxr_remaining + txr_remaining + xdp_remaining)) {
		for (; rxr_remaining; v_idx++, q_vectors--) {
			int rqpv = DIV_ROUND_UP(rxr_remaining, q_vectors);
			err = ixgbevf_alloc_q_vector(adapter, v_idx,
						     0, 0, 0, 0, rqpv, rxr_idx);
			if (err)
				goto err_out;

			/* update counts and index */
			rxr_remaining -= rqpv;
			rxr_idx += rqpv;
		}
	}

	for (; q_vectors; v_idx++, q_vectors--) {
		int rqpv = DIV_ROUND_UP(rxr_remaining, q_vectors);
		int tqpv = DIV_ROUND_UP(txr_remaining, q_vectors);
		int xqpv = DIV_ROUND_UP(xdp_remaining, q_vectors);

		err = ixgbevf_alloc_q_vector(adapter, v_idx,
					     tqpv, txr_idx,
					     xqpv, xdp_idx,
					     rqpv, rxr_idx);

		if (err)
			goto err_out;

		/* update counts and index */
		rxr_remaining -= rqpv;
		rxr_idx += rqpv;
		txr_remaining -= tqpv;
		txr_idx += tqpv;
		xdp_remaining -= xqpv;
		xdp_idx += xqpv;
	}

	return 0;

err_out:
	adapter->num_tx_queues = 0;
	adapter->num_xdp_queues = 0;
	adapter->num_rx_queues = 0;
	adapter->num_q_vectors = 0;

	while (v_idx--)
		ixgbevf_free_q_vector(adapter, v_idx);

	return -ENOMEM;
}

/**
 * ixgbevf_free_q_vectors - Free memory allocated for interrupt vectors
 * @adapter: board private structure to initialize
 *
 * This function frees the memory allocated to the q_vectors.  In addition if
 * NAPI is enabled it will delete any references to the NAPI struct prior
 * to freeing the q_vector.
 **/
static void ixgbevf_free_q_vectors(struct ixgbevf_adapter *adapter)
{
	int v_idx = adapter->num_q_vectors;

	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;
	adapter->num_q_vectors = 0;

	while (v_idx--)
		ixgbevf_free_q_vector(adapter, v_idx);
}

/**
 * ixgbevf_reset_interrupt_capability - Reset MSIX setup
 * @adapter: board private structure
 *
 **/
static void ixgbevf_reset_interrupt_capability(struct ixgbevf_adapter *adapter)
{
	if (!adapter->msix_entries)
		return;

	pci_disable_msix(adapter->pdev);
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
}

/**
 * ixgbevf_init_interrupt_scheme - Determine if MSIX is supported and init
 * @adapter: board private structure to initialize
 *
 **/
static int ixgbevf_init_interrupt_scheme(struct ixgbevf_adapter *adapter)
{
	struct pci_dev *pdev = adapter->pdev;
	int err;

	/* Number of supported queues */
	ixgbevf_set_num_queues(adapter);

	err = ixgbevf_set_interrupt_capability(adapter);
	if (err) {
		dev_err(&pdev->dev, "Unable to setup interrupt capabilities\n");
		goto err_set_interrupt;
	}

	err = ixgbevf_alloc_q_vectors(adapter);
	if (err) {
		dev_err(&pdev->dev, "Unable to allocate memory for queue vectors\n");
		goto err_alloc_q_vectors;
	}

#ifdef HAVE_XDP_SUPPORT
	dev_info(&pdev->dev, "Multiqueue %s: Rx Queue count = %u, Tx Queue count = %u XDP Queue count %u\n",
		 (adapter->num_rx_queues > 1) ? "Enabled" : "Disabled",
		 adapter->num_rx_queues, adapter->num_tx_queues,
		 adapter->num_xdp_queues);
#else
	dev_info(&pdev->dev, "Multiqueue %s: Rx Queue count = %u, Tx Queue count = %u\n",
		 (adapter->num_rx_queues > 1) ? "Enabled" : "Disabled",
		 adapter->num_rx_queues, adapter->num_tx_queues);
#endif /* HAVE_XDP_SUPPORT */

	set_bit(__IXGBEVF_DOWN, &adapter->state);

	return 0;
err_alloc_q_vectors:
	ixgbevf_reset_interrupt_capability(adapter);
err_set_interrupt:
	return err;
}

/**
 * ixgbevf_clear_interrupt_scheme - Clear the current interrupt scheme settings
 * @adapter: board private structure to clear interrupt scheme on
 *
 * We go through and clear interrupt specific resources and reset the structure
 * to pre-load conditions
 **/
static void ixgbevf_clear_interrupt_scheme(struct ixgbevf_adapter *adapter)
{
	adapter->num_tx_queues = 0;
	adapter->num_xdp_queues = 0;
	adapter->num_rx_queues = 0;

	ixgbevf_free_q_vectors(adapter);
	ixgbevf_reset_interrupt_capability(adapter);
}

/**
 * ixgbevf_sw_init - Initialize general software structures
 * (struct ixgbevf_adapter)
 * @adapter: board private structure to initialize
 *
 * ixgbevf_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 **/
static int __devinit ixgbevf_sw_init(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	struct net_device *netdev = adapter->netdev;
	int err;

	/* PCI config space info */

	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);
	hw->subsystem_vendor_id = pdev->subsystem_vendor;
	hw->subsystem_device_id = pdev->subsystem_device;

#if IS_ENABLED(CONFIG_PCI_HYPERV)
	switch (hw->device_id) {
	case IXGBE_DEV_ID_82599_VF_HV:
	case IXGBE_DEV_ID_X540_VF_HV:
	case IXGBE_DEV_ID_X550_VF_HV:
	case IXGBE_DEV_ID_X550EM_X_VF_HV:
	case IXGBE_DEV_ID_X550EM_A_VF_HV:
		ixgbevf_hv_init_ops_vf(hw);
		break;
	default:
		ixgbe_init_ops_vf(hw);
		break;
	}
#else
	ixgbe_init_ops_vf(hw);
#endif
	hw->mbx.ops.init_params(hw);

	if (hw->mac.type >= ixgbe_mac_X550_vf) {
		err = ixgbevf_init_rss_key(adapter);
		if (err)
			return err;
	}

	/* assume legacy case in which PF would only give VF 2 queues */
	hw->mac.max_tx_queues = 2;
	hw->mac.max_rx_queues = 2;

	/* lock to protect mailbox accesses */
	spin_lock_init(&adapter->mbx_lock);

	err = hw->mac.ops.reset_hw(hw);
	if (err) {
		dev_info(pci_dev_to_dev(pdev),
			 "PF still in reset state.  Is the PF interface up?\n");
	} else {
		err = hw->mac.ops.init_hw(hw);
		if (err) {
			dev_err(pci_dev_to_dev(pdev),
				"init_shared_code failed: %d\n", err);
			return err;
		}
		ixgbevf_negotiate_api(adapter);
		err = hw->mac.ops.get_mac_addr(hw, hw->mac.addr);
		if (err)
			dev_info(&pdev->dev, "Error reading MAC address\n");
		else if (is_zero_ether_addr(adapter->hw.mac.addr))
			dev_info(&pdev->dev,
				 "MAC address not assigned by administrator.\n");
		ether_addr_copy(netdev->dev_addr, hw->mac.addr);
	}

	if (!is_valid_ether_addr(netdev->dev_addr)) {
		dev_info(&pdev->dev, "Assigning random MAC address\n");
		eth_hw_addr_random(netdev);
		ether_addr_copy(hw->mac.addr, netdev->dev_addr);
		ether_addr_copy(hw->mac.perm_addr, netdev->dev_addr);
	}

	/* Enable dynamic interrupt throttling rates */
	adapter->rx_itr_setting = 1;
	adapter->tx_itr_setting = 1;

	/* set default ring sizes */
	adapter->tx_ring_count = IXGBEVF_DEFAULT_TXD;
	adapter->rx_ring_count = IXGBEVF_DEFAULT_RXD;

	/* enable rx csum by default */
	adapter->flags |= IXGBE_FLAG_RX_CSUM_ENABLED;

	set_bit(__IXGBEVF_DOWN, &adapter->state);

	return 0;
}

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
		u64 current_counter = (current_counter_msb << 32) |      \
			current_counter_lsb;                             \
		if (current_counter < last_counter)			 \
			counter += 0x1000000000LL;			 \
		last_counter = current_counter;				 \
		counter &= 0xFFFFFFF000000000LL;			 \
		counter |= current_counter;				 \
	}
/**
 * ixgbevf_update_stats - Update the board statistics counters.
 * @adapter: board private structure
 **/
void ixgbevf_update_stats(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u64 restart_queue = 0, tx_busy = 0;
	u64 alloc_rx_page_failed = 0, alloc_rx_buff_failed = 0;
	u64 alloc_rx_page = 0, hw_csum_rx_error = 0;
	int i;

	if (test_bit(__IXGBEVF_DOWN, &adapter->state) ||
	    test_bit(__IXGBEVF_RESETTING, &adapter->state))
		return;

	UPDATE_VF_COUNTER_32bit(IXGBE_VFGPRC, adapter->stats.last_vfgprc,
				adapter->stats.vfgprc);
	UPDATE_VF_COUNTER_32bit(IXGBE_VFGPTC, adapter->stats.last_vfgptc,
				adapter->stats.vfgptc);
	UPDATE_VF_COUNTER_36bit(IXGBE_VFGORC_LSB, IXGBE_VFGORC_MSB,
				adapter->stats.last_vfgorc,
				adapter->stats.vfgorc);
	UPDATE_VF_COUNTER_36bit(IXGBE_VFGOTC_LSB, IXGBE_VFGOTC_MSB,
				adapter->stats.last_vfgotc,
				adapter->stats.vfgotc);
	UPDATE_VF_COUNTER_32bit(IXGBE_VFMPRC, adapter->stats.last_vfmprc,
				adapter->stats.vfmprc);

	for (i = 0;  i  < adapter->num_rx_queues;  i++) {
		struct ixgbevf_ring *rx_ring = adapter->rx_ring[i];

		hw_csum_rx_error += rx_ring->rx_stats.csum_err;
		alloc_rx_page_failed += rx_ring->rx_stats.alloc_rx_page_failed;
		alloc_rx_buff_failed += rx_ring->rx_stats.alloc_rx_buff_failed;
		alloc_rx_page += rx_ring->rx_stats.alloc_rx_page;
	}

	adapter->hw_csum_rx_error = hw_csum_rx_error;
	adapter->alloc_rx_page_failed = alloc_rx_page_failed;
	adapter->alloc_rx_buff_failed = alloc_rx_buff_failed;
	adapter->alloc_rx_page = alloc_rx_page;

	for (i = 0; i < adapter->num_tx_queues; i++) {
		struct ixgbevf_ring *tx_ring = adapter->rx_ring[i];

		restart_queue += tx_ring->tx_stats.restart_queue;
		tx_busy += tx_ring->tx_stats.tx_busy;
	}
	adapter->restart_queue = restart_queue;
	adapter->tx_busy = tx_busy;
}

/**
 * ixgbevf_service_timer - Timer Call-back
 * @t: pointer to timer_list struct
 **/
static void ixgbevf_service_timer(struct timer_list *t)
{
	struct ixgbevf_adapter *adapter = from_timer(adapter, t,
						     service_timer);

	/* Reset the timer */
	mod_timer(&adapter->service_timer, (HZ * 2) + jiffies);

	ixgbevf_service_event_schedule(adapter);
}

static void ixgbevf_reset_subtask(struct ixgbevf_adapter *adapter)
{
	if (!test_and_clear_bit(__IXGBEVF_RESET_REQUESTED, &adapter->state))
		return;

	rtnl_lock();

	/* If we're already down or resetting, just bail */
	if (test_bit(__IXGBEVF_DOWN, &adapter->state) ||
	    test_bit(__IXGBEVF_REMOVING, &adapter->state) ||
	    test_bit(__IXGBEVF_RESETTING, &adapter->state)) {
		rtnl_unlock();
		return;
	}

	adapter->tx_timeout_count++;

	ixgbevf_reinit_locked(adapter);
	rtnl_unlock();
}

/**
 * ixgbevf_check_hang_subtask - check for hung queues and dropped interrupts
 * @adapter: pointer to the device adapter structure
 *
 * This function serves two purposes.  First it strobes the interrupt lines
 * in order to make certain interrupts are occurring.  Secondly it sets the
 * bits needed to check for TX hangs.  As a result we should immediately
 * determine if a hang has occurred.
 */
static void ixgbevf_check_hang_subtask(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 eics = 0;
	int i;

	/* If we're down or resetting, just bail */
	if (test_bit(__IXGBEVF_DOWN, &adapter->state) ||
	    test_bit(__IXGBEVF_RESETTING, &adapter->state))
		return;

	/* Force detection of hung controller */
	if (netif_carrier_ok(adapter->netdev)) {
		for (i = 0; i < adapter->num_tx_queues; i++)
			set_check_for_tx_hang(adapter->tx_ring[i]);
		for (i = 0; i < adapter->num_xdp_queues; i++)
			set_check_for_tx_hang(adapter->xdp_ring[i]);
	}

	/* get one bit for every active Tx/Rx interrupt vector */
	for (i = 0; i < adapter->num_q_vectors; i++) {
		struct ixgbevf_q_vector *qv = adapter->q_vector[i];

		if (qv->rx.ring || qv->tx.ring)
			eics |= BIT(i);
	}

	/* Cause software interrupt to ensure rings are cleaned */
	IXGBE_WRITE_REG(hw, IXGBE_VTEICS, eics);
}

/**
 * ixgbevf_watchdog_update_link - update the link status
 * @adapter: pointer to the device adapter structure
 **/
static void ixgbevf_watchdog_update_link(struct ixgbevf_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 link_speed = adapter->link_speed;
	bool link_up = adapter->link_up;
	s32 err;

	spin_lock_bh(&adapter->mbx_lock);

	err = hw->mac.ops.check_link(hw, &link_speed, &link_up, false);

	spin_unlock_bh(&adapter->mbx_lock);

	/* if check for link returns error we will need to reset */
	if (err && time_after(jiffies, adapter->last_reset + (10 * HZ))) {
		set_bit(__IXGBEVF_RESET_REQUESTED, &adapter->state);
		link_up = false;
	}

	adapter->link_up = link_up;
	adapter->link_speed = link_speed;
}

/**
 * ixgbevf_watchdog_link_is_up - update netif_carrier status and
 *				 print link up message
 * @adapter: pointer to the device adapter structure
 **/
static void ixgbevf_watchdog_link_is_up(struct ixgbevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	const char *speed_str;

	/* only continue if link was previously down */
	if (netif_carrier_ok(netdev))
		return;

	switch (adapter->link_speed) {
	case IXGBE_LINK_SPEED_10GB_FULL:
		speed_str = "10 Gbps";
		break;
	case IXGBE_LINK_SPEED_5GB_FULL:
		speed_str = "5 Gbps";
		break;
	case IXGBE_LINK_SPEED_2_5GB_FULL:
		speed_str = "2.5 Gbps";
		break;
	case IXGBE_LINK_SPEED_1GB_FULL:
		speed_str = "1 Gbps";
		break;
	case IXGBE_LINK_SPEED_100_FULL:
		speed_str = "100 Mbps";
		break;
	case IXGBE_LINK_SPEED_10_FULL:
		speed_str = "10 Mbps";
		break;
	default:
		speed_str = "unknown speed";
		break;
	}
	dev_info(&adapter->pdev->dev, "NIC Link is Up %s\n", speed_str);

	netif_carrier_on(netdev);
}

/**
 * ixgbevf_watchdog_link_is_down - update netif_carrier status and
 *				   print link down message
 * @adapter: pointer to the adapter structure
 **/
static void ixgbevf_watchdog_link_is_down(struct ixgbevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	adapter->link_speed = 0;

	/* only continue if link was up previously */
	if (!netif_carrier_ok(netdev))
		return;

	dev_info(&adapter->pdev->dev, "NIC Link is Down\n");

	netif_carrier_off(netdev);
}

/**
 * ixgbevf_watchdog_subtask - worker thread to bring link up
 * @adapter: pointer to the device adapter structure
 **/
static void ixgbevf_watchdog_subtask(struct ixgbevf_adapter *adapter)
{

	/* if interface is down do nothing */
	if (test_bit(__IXGBEVF_DOWN, &adapter->state) ||
	    test_bit(__IXGBEVF_RESETTING, &adapter->state))
		return;

	ixgbevf_watchdog_update_link(adapter);

	if (adapter->link_up)
		ixgbevf_watchdog_link_is_up(adapter);
	else
		ixgbevf_watchdog_link_is_down(adapter);

	ixgbevf_update_stats(adapter);
}

/**
 * ixgbevf_service_task - manages and runs subtasks
 * @work: pointer to work_struct containing our data
 **/
static void ixgbevf_service_task(struct work_struct *work)
{
	struct ixgbevf_adapter *adapter = container_of(work,
						       struct ixgbevf_adapter,
						       service_task);
	struct ixgbe_hw *hw = &adapter->hw;

	if (IXGBE_REMOVED(hw->hw_addr)) {
		if (!test_bit(__IXGBEVF_DOWN, &adapter->state)) {
			rtnl_lock();
			ixgbevf_down(adapter);
			rtnl_unlock();
		}
		ixgbevf_service_event_complete(adapter);
		return;
	}

	ixgbevf_queue_reset_subtask(adapter);
	ixgbevf_reset_subtask(adapter);
	ixgbevf_watchdog_subtask(adapter);
	ixgbevf_check_hang_subtask(adapter);

	ixgbevf_service_event_complete(adapter);
}

/**
 * ixgbevf_free_tx_resources - Free Tx Resources per Queue
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 **/
void ixgbevf_free_tx_resources(struct ixgbevf_ring *tx_ring)
{
	ixgbevf_clean_tx_ring(tx_ring);

	vfree(tx_ring->tx_buffer_info);
	tx_ring->tx_buffer_info = NULL;

	/* if not set, then don't free */
	if (!tx_ring->desc)
		return;

	dma_free_coherent(tx_ring->dev, tx_ring->size,
			  tx_ring->desc, tx_ring->dma);

	tx_ring->desc = NULL;
}

/**
 * ixgbevf_free_all_tx_resources - Free Tx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all transmit software resources
 **/
static void ixgbevf_free_all_tx_resources(struct ixgbevf_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		if (adapter->tx_ring[i]->desc)
			ixgbevf_free_tx_resources(adapter->tx_ring[i]);
	for (i = 0; i < adapter->num_xdp_queues; i++)
		if (adapter->xdp_ring[i]->desc)
			ixgbevf_free_tx_resources(adapter->xdp_ring[i]);
}

/**
 * ixgbevf_setup_tx_resources - allocate Tx resources (Descriptors)
 * @tx_ring: tx descriptor ring (for a specific queue) to setup
 *
 * Return 0 on success, negative on failure
 **/
int ixgbevf_setup_tx_resources(struct ixgbevf_ring *tx_ring)
{
	int size;

	size = sizeof(struct ixgbevf_tx_buffer) * tx_ring->count;
	tx_ring->tx_buffer_info = vmalloc(size);
	if (!tx_ring->tx_buffer_info)
		goto err;

	u64_stats_init(&tx_ring->syncp);

	/* round up to nearest 4K */
	tx_ring->size = tx_ring->count * sizeof(union ixgbe_adv_tx_desc);
	tx_ring->size = ALIGN(tx_ring->size, 4096);

	tx_ring->desc = dma_alloc_coherent(tx_ring->dev, tx_ring->size,
					   &tx_ring->dma, GFP_KERNEL);
	if (!tx_ring->desc)
		goto err;

	return 0;

err:
	vfree(tx_ring->tx_buffer_info);
	tx_ring->tx_buffer_info = NULL;
	dev_err(tx_ring->dev, "Unable to allocate memory for the Tx descriptor ring\n");
	return -ENOMEM;
}

/**
 * ixgbevf_setup_all_tx_resources - allocate all queues Tx resources
 * @adapter: board private structure
 *
 * If this function returns with an error, then it's possible one or
 * more of the rings is populated (while the rest are not).  It is the
 * callers duty to clean those orphaned rings.
 *
 * Return 0 on success, negative on failure
 **/
static int ixgbevf_setup_all_tx_resources(struct ixgbevf_adapter *adapter)
{
	int i, j = 0, err = 0;

	for (i = 0; i < adapter->num_tx_queues; i++) {
		err = ixgbevf_setup_tx_resources(adapter->tx_ring[i]);
		if (!err)
			continue;
		DPRINTK(PROBE, ERR, "Allocation for Tx Queue %u failed\n", i);
		goto err_setup_tx;
	}

	for (j = 0; j < adapter->num_xdp_queues; j++) {
		err = ixgbevf_setup_tx_resources(adapter->xdp_ring[j]);
		if (!err)
			continue;
		hw_dbg(&adapter->hw, "Allocation for XDP Queue %u failed\n", j);
		goto err_setup_tx;
	}

	return 0;
err_setup_tx:
	/* rewind the index freeing the rings as we go */
	while (j--)
		ixgbevf_free_tx_resources(adapter->xdp_ring[j]);
	while (i--)
		ixgbevf_free_tx_resources(adapter->tx_ring[i]);

	return err;
}

/**
 * ixgbevf_setup_rx_resources - allocate Rx resources (Descriptors)
 * @adapter: board private structure
 * @rx_ring: Rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 **/
int ixgbevf_setup_rx_resources(struct ixgbevf_adapter *adapter,
			       struct ixgbevf_ring *rx_ring)
{
	int size;

	size = sizeof(struct ixgbevf_rx_buffer) * rx_ring->count;
	rx_ring->rx_buffer_info = vmalloc(size);
	if (!rx_ring->rx_buffer_info)
		goto err;

	u64_stats_init(&rx_ring->syncp);

	/* Round up to nearest 4K */
	rx_ring->size = rx_ring->count * sizeof(union ixgbe_adv_rx_desc);
	rx_ring->size = ALIGN(rx_ring->size, 4096);

	rx_ring->desc = dma_alloc_coherent(rx_ring->dev, rx_ring->size,
					   &rx_ring->dma, GFP_KERNEL);

	if (!rx_ring->desc)
		goto err;

#ifdef HAVE_XDP_BUFF_RXQ
	/* XDP RX-queue info */
	if (xdp_rxq_info_reg(&rx_ring->xdp_rxq, adapter->netdev,
			     rx_ring->queue_index) < 0)
		goto err;

#endif /* HAVE_XDP_BUFF_RXQ */
	rx_ring->xdp_prog = adapter->xdp_prog;

	return 0;
err:
	vfree(rx_ring->rx_buffer_info);
	rx_ring->rx_buffer_info = NULL;
	dev_err(rx_ring->dev, "Unable to allocate memory for the Rx descriptor ring\n");
	return -ENOMEM;
}

/**
 * ixgbevf_setup_all_rx_resources - allocate all queues Rx resources
 * @adapter: board private structure
 *
 * If this function returns with an error, then it's possible one or
 * more of the rings is populated (while the rest are not).  It is the
 * callers duty to clean those orphaned rings.
 *
 * Return 0 on success, negative on failure
 **/
static int ixgbevf_setup_all_rx_resources(struct ixgbevf_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		err = ixgbevf_setup_rx_resources(adapter, adapter->rx_ring[i]);
		if (!err)
			continue;
		DPRINTK(PROBE, ERR, "Allocation for Rx Queue %u failed\n", i);
		goto err_setup_rx;
	}

	return 0;
err_setup_rx:
	/* rewind the index freeing the rings as we go */
	while (i--)
		ixgbevf_free_rx_resources(adapter->rx_ring[i]);
	return err;
}

/**
 * ixgbevf_free_rx_resources - Free Rx Resources
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 **/
void ixgbevf_free_rx_resources(struct ixgbevf_ring *rx_ring)
{
	ixgbevf_clean_rx_ring(rx_ring);

	rx_ring->xdp_prog = NULL;
#ifdef HAVE_XDP_BUFF_RXQ
	xdp_rxq_info_unreg(&rx_ring->xdp_rxq);
#endif /* HAVE_XDP_BUFF_RXQ */
	vfree(rx_ring->rx_buffer_info);
	rx_ring->rx_buffer_info = NULL;

	dma_free_coherent(rx_ring->dev, rx_ring->size,
			  rx_ring->desc, rx_ring->dma);

	rx_ring->desc = NULL;
}

/**
 * ixgbevf_free_all_rx_resources - Free Rx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all receive software resources
 **/
static void ixgbevf_free_all_rx_resources(struct ixgbevf_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		if (adapter->rx_ring[i]->desc)
			ixgbevf_free_rx_resources(adapter->rx_ring[i]);
}

/**
 * ixgbevf_open - Called when a network interface is made active
 * @netdev: network interface device structure
 *
 * Returns 0 on success, negative value on failure
 *
 * The open entry point is called when a network interface is made
 * active by the system (IFF_UP).  At this point all resources needed
 * for transmit and receive operations are allocated, the interrupt
 * handler is registered with the OS, the watchdog timer is started,
 * and the stack is notified that the interface is ready.
 **/
int ixgbevf_open(struct net_device *netdev)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	int err;

#ifdef HAVE_PF_RING
	if (adapter->pfring_zc.zombie) {
		printk("%s() bringing up interface previously brought down while in use by ZC, ignoring\n", __FUNCTION__);
		adapter->pfring_zc.zombie = false;
		return 0;
	}
#endif

	/* A previous failure to open the device because of a lack of
	 * available MSIX vector resources may have reset the number
	 * of q vectors variable to zero.  The only way to recover
	 * is to unload/reload the driver and hope that the system has
	 * been able to recover some MSIX vector resources.
	 */
	if (!adapter->num_q_vectors)
		return -ENOMEM;

	if (hw->adapter_stopped) {
		ixgbevf_reset(adapter);
		/* if adapter is still stopped then PF isn't up and
		 * the vf can't start. */
		if (hw->adapter_stopped) {
			err = IXGBE_ERR_MBX;
			DPRINTK(DRV, ERR, "Unable to start - perhaps the PF"
				"Driver isn't up yet\n");
			goto err_setup_reset;
		}
	}

	/* disallow open during test */
	if (test_bit(__IXGBEVF_TESTING, &adapter->state))
		return -EBUSY;

	netif_carrier_off(netdev);

	/* allocate transmit descriptors */
	err = ixgbevf_setup_all_tx_resources(adapter);
	if (err)
		goto err_setup_tx;

	/* allocate receive descriptors */
	err = ixgbevf_setup_all_rx_resources(adapter);
	if (err)
		goto err_setup_rx;

	ixgbevf_configure(adapter);

	err = ixgbevf_request_irq(adapter);
	if (err)
		goto err_req_irq;

	/* Notify the stack of the actual queue counts. */
	err = netif_set_real_num_tx_queues(netdev, adapter->num_tx_queues);
	if (err)
		goto err_set_queues;

	err = netif_set_real_num_rx_queues(netdev, adapter->num_rx_queues);
	if (err)
		goto err_set_queues;

	ixgbevf_up_complete(adapter);

	return 0;

err_set_queues:
	ixgbevf_free_irq(adapter);
err_req_irq:
	ixgbevf_free_all_rx_resources(adapter);
err_setup_rx:
	ixgbevf_free_all_tx_resources(adapter);
err_setup_tx:
	ixgbevf_reset(adapter);
err_setup_reset:

	return err;
}

/**
 * ixgbevf_close_suspend - actions necessary to both suspend and close flows
 * @adapter: the private adapter struct
 *
 * This function should contain the necessary work common to both suspending
 * and closing of the device.
 */
static void ixgbevf_close_suspend(struct ixgbevf_adapter *adapter)
{
		ixgbevf_down(adapter);
		ixgbevf_free_irq(adapter);
		ixgbevf_free_all_tx_resources(adapter);
		ixgbevf_free_all_rx_resources(adapter);
}

/**
 * ixgbevf_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 **/
int ixgbevf_close(struct net_device *netdev)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);

#ifdef HAVE_PF_RING
	if (atomic_read(&adapter->pfring_zc.usage_counter) > 0) {
		printk("%s() bringing interface down while in use by ZC, ignoring\n", __FUNCTION__);
		adapter->pfring_zc.zombie = true;
		return 0;
	}
#endif

	if (netif_device_present(netdev))
		ixgbevf_close_suspend(adapter);

	return 0;
}

static void ixgbevf_queue_reset_subtask(struct ixgbevf_adapter *adapter)
{
	struct net_device *dev = adapter->netdev;

	if (!test_and_clear_bit(__IXGBEVF_QUEUE_RESET_REQUESTED,
				&adapter->state))
		return;

	/* if interface is down do nothing */
	if (test_bit(__IXGBEVF_DOWN, &adapter->state) ||
	    test_bit(__IXGBEVF_RESETTING, &adapter->state))
		return;

	/*
	 * Hardware has to reinitialize queues and interrupts to
	 * match packet buffer alignment. Unfortunately, the
	 * hardware is not flexible enough to do this dynamically.
	 */
	rtnl_lock();

	/* disable running interface */
	if (netif_running(dev))
		ixgbevf_close(dev);

	/* free and reallocate queues */
	ixgbevf_clear_interrupt_scheme(adapter);
	ixgbevf_init_interrupt_scheme(adapter);

	/* reenable running interface */
	if (netif_running(dev))
		ixgbevf_open(dev);

	rtnl_unlock();
}

static void ixgbevf_tx_ctxtdesc(struct ixgbevf_ring *tx_ring,
				u32 vlan_macip_lens, u32 type_tucmd,
				u32 mss_l4len_idx)
{
	struct ixgbe_adv_tx_context_desc *context_desc;
	u16 i = tx_ring->next_to_use;

	context_desc = IXGBEVF_TX_CTXTDESC(tx_ring, i);

	i++;
	tx_ring->next_to_use = (i < tx_ring->count) ? i : 0;

	/* set bits to identify this as an advanced context descriptor */
	type_tucmd |= IXGBE_TXD_CMD_DEXT | IXGBE_ADVTXD_DTYP_CTXT;

	context_desc->vlan_macip_lens	= cpu_to_le32(vlan_macip_lens);
	context_desc->seqnum_seed	= 0;
	context_desc->type_tucmd_mlhl	= cpu_to_le32(type_tucmd);
	context_desc->mss_l4len_idx	= cpu_to_le32(mss_l4len_idx);
}

static int ixgbevf_tso(struct ixgbevf_ring *tx_ring,
		       struct ixgbevf_tx_buffer *first,
		       u8 *hdr_len)
{
#ifndef NETIF_F_TSO
	return 0;
#else
	u32 vlan_macip_lens, type_tucmd, mss_l4len_idx;
	struct sk_buff *skb = first->skb;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		unsigned char *hdr;
	} l4;
	u32 paylen, l4_offset;
	int err;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (!skb_is_gso(skb))
		return 0;

	err = skb_cow_head(skb, 0);
	if (err)
		return err;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_checksum_start(skb);

	/* ADV DTYP TUCMD MKRLOC/ISCSIHEDLEN */
	type_tucmd = IXGBE_ADVTXD_TUCMD_L4T_TCP;

	/* initialize outer IP header fields */
	if (ip.v4->version == 4) {
		unsigned char *csum_start = skb_checksum_start(skb);
		unsigned char *trans_start = ip.hdr + (ip.v4->ihl * 4);


		/* IP header will have to cancel out any data that
		 * is not a part of the outer IP header
		 */
		ip.v4->check = csum_fold(csum_partial(trans_start,
						      csum_start - trans_start,
						      0));
		type_tucmd |= IXGBE_ADVTXD_TUCMD_IPV4;
		ip.v4->tot_len = 0;
		first->tx_flags |= IXGBE_TX_FLAGS_TSO |
				   IXGBE_TX_FLAGS_CSUM |
				   IXGBE_TX_FLAGS_IPV4;
	} else {
		ip.v6->payload_len = 0;
		first->tx_flags |= IXGBE_TX_FLAGS_TSO |
				   IXGBE_TX_FLAGS_CSUM;
	}

	/* determine offset of inner transport header */
	l4_offset = l4.hdr - skb->data;

	/* compute length of segmentation header */
	*hdr_len = (l4.tcp->doff * 4)  + l4_offset;

	/* remove payload length from inner checksum */
	paylen = skb->len - l4_offset;
	csum_replace_by_diff(&l4.tcp->check, htonl(paylen));

	/* update gso size and bytecount with header size */
	first->gso_segs = skb_shinfo(skb)->gso_segs;
	first->bytecount += (first->gso_segs - 1) * *hdr_len;

	/* mss_l4len_id: use 1 as index for TSO */
	mss_l4len_idx = (*hdr_len - l4_offset) << IXGBE_ADVTXD_L4LEN_SHIFT;
	mss_l4len_idx |= skb_shinfo(skb)->gso_size << IXGBE_ADVTXD_MSS_SHIFT;
	mss_l4len_idx |= (1u << IXGBE_ADVTXD_IDX_SHIFT);

	/* vlan_macip_lens: HEADLEN, MACLEN, VLAN tag */
	vlan_macip_lens = l4.hdr - ip.hdr;
	vlan_macip_lens |= (ip.hdr - skb->data) << IXGBE_ADVTXD_MACLEN_SHIFT;
	vlan_macip_lens |= first->tx_flags & IXGBE_TX_FLAGS_VLAN_MASK;

	ixgbevf_tx_ctxtdesc(tx_ring, vlan_macip_lens,
			    type_tucmd, mss_l4len_idx);

	return 1;
#endif
}

static inline bool ixgbevf_ipv6_csum_is_sctp(struct sk_buff *skb)
{
	unsigned int offset = 0;

	ipv6_find_hdr(skb, &offset, IPPROTO_SCTP, NULL, NULL);

	return offset == skb_checksum_start_offset(skb);
}

static void ixgbevf_tx_csum(struct ixgbevf_ring *tx_ring,
			    struct ixgbevf_tx_buffer *first)
{
	struct sk_buff *skb = first->skb;
	u32 vlan_macip_lens = 0;
	u32 type_tucmd = 0;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		goto no_csum;

	switch (skb->csum_offset) {
	case offsetof(struct tcphdr, check):
		type_tucmd = IXGBE_ADVTXD_TUCMD_L4T_TCP;
		/* fall through */
	case offsetof(struct udphdr, check):
		break;
	case offsetof(struct sctphdr, checksum):
		/* validate this is actual an SCTP request */
		if (((first->protocol == htons(ETH_P_IP)) &&
		     (ip_hdr(skb)->protocol == IPPROTO_SCTP)) ||
		    ((first->protocol == htons(ETH_P_IPV6)) &&
		     ixgbevf_ipv6_csum_is_sctp(skb))) {
			type_tucmd = IXGBE_ADVTXD_TUCMD_L4T_SCTP;
			break;
		}
		/* fall through */
	default:
		skb_checksum_help(skb);
		goto no_csum;
	}

	/* update TX checksum flag */
	first->tx_flags |= IXGBE_TX_FLAGS_CSUM;
	vlan_macip_lens = skb_checksum_start_offset(skb) -
			  skb_network_offset(skb);

no_csum:
	/* vlan_macip_lens: MACLEN, VLAN tag */
	vlan_macip_lens |= skb_network_offset(skb) << IXGBE_ADVTXD_MACLEN_SHIFT;
	vlan_macip_lens |= first->tx_flags & IXGBE_TX_FLAGS_VLAN_MASK;

	ixgbevf_tx_ctxtdesc(tx_ring, vlan_macip_lens, type_tucmd, 0);
}

static __le32 ixgbevf_tx_cmd_type(u32 tx_flags)
{
	/* set type for advanced descriptor with frame checksum insertion */
	__le32 cmd_type = cpu_to_le32(IXGBE_ADVTXD_DTYP_DATA |
				      IXGBE_ADVTXD_DCMD_IFCS |
				      IXGBE_ADVTXD_DCMD_DEXT);

	/* set HW vlan bit if vlan is present */
	if (tx_flags & IXGBE_TX_FLAGS_VLAN)
		cmd_type |= cpu_to_le32(IXGBE_ADVTXD_DCMD_VLE);

	/* set segmentation enable bits for TSO/FSO */
	if (tx_flags & IXGBE_TX_FLAGS_TSO)
		cmd_type |= cpu_to_le32(IXGBE_ADVTXD_DCMD_TSE);

	return cmd_type;
}

static void ixgbevf_tx_olinfo_status(union ixgbe_adv_tx_desc *tx_desc,
				     u32 tx_flags, unsigned int paylen)
{
	__le32 olinfo_status = cpu_to_le32(paylen << IXGBE_ADVTXD_PAYLEN_SHIFT);

	/* enable L4 checksum for TSO and TX checksum offload */
	if (tx_flags & IXGBE_TX_FLAGS_CSUM)
		olinfo_status |= cpu_to_le32(IXGBE_ADVTXD_POPTS_TXSM);

	/* enble IPv4 checksum for TSO */
	if (tx_flags & IXGBE_TX_FLAGS_IPV4)
		olinfo_status |= cpu_to_le32(IXGBE_ADVTXD_POPTS_IXSM);

	/* use index 1 context for TSO/FSO/FCOE */
	if (tx_flags & IXGBE_TX_FLAGS_TSO)
		olinfo_status |= cpu_to_le32(1u << IXGBE_ADVTXD_IDX_SHIFT);

	/*
	 * Check Context must be set if Tx switch is enabled, which it
	 * always is for case where virtual functions are running
	 */
	olinfo_status |= cpu_to_le32(IXGBE_ADVTXD_CC);

	tx_desc->read.olinfo_status = olinfo_status;
}

static int __ixgbevf_maybe_stop_tx(struct ixgbevf_ring *tx_ring, int size)
{
	netif_stop_subqueue(tx_ring->netdev, tx_ring->queue_index);
	/* Herbert's original patch had:
	 *  smp_mb__after_netif_stop_queue();
	 * but since that doesn't exist yet, just open code it.
	 */
	smp_mb();

	/* We need to check again in a case another CPU has just
	 * made room available.
	 */
	if (likely(ixgbevf_desc_unused(tx_ring) < size))
		return -EBUSY;

	/* A reprieve! - use start_queue because it doesn't call schedule */
	netif_start_subqueue(tx_ring->netdev, tx_ring->queue_index);
	++tx_ring->tx_stats.restart_queue;

	return 0;
}

static inline int ixgbevf_maybe_stop_tx(struct ixgbevf_ring *tx_ring, int size)
{
	if (likely(ixgbevf_desc_unused(tx_ring) >= size))
		return 0;
	return __ixgbevf_maybe_stop_tx(tx_ring, size);
}

static void ixgbevf_tx_map(struct ixgbevf_ring *tx_ring,
			   struct ixgbevf_tx_buffer *first,
			   const u8 hdr_len)
{
	struct sk_buff *skb = first->skb;
	struct ixgbevf_tx_buffer *tx_buffer;
	union ixgbe_adv_tx_desc *tx_desc;
	struct skb_frag_struct *frag;
	dma_addr_t dma;
	unsigned int data_len, size;
	u32 tx_flags = first->tx_flags;
	__le32 cmd_type = ixgbevf_tx_cmd_type(tx_flags);
	u16 i = tx_ring->next_to_use;
#ifdef HAVE_PF_RING
	struct ixgbevf_adapter *adapter = netdev_priv(tx_ring->netdev);

	if (atomic_read(&adapter->pfring_zc.usage_counter) > 0)
		return; /* We don't allow apps to send data */	
#endif

	tx_desc = IXGBEVF_TX_DESC(tx_ring, i);

	ixgbevf_tx_olinfo_status(tx_desc, tx_flags, skb->len - hdr_len);

	size = skb_headlen(skb);
	data_len = skb->data_len;

	dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);

	tx_buffer = first;

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		if (dma_mapping_error(tx_ring->dev, dma))
			goto dma_error;

		/* record length, and DMA address */
		dma_unmap_len_set(tx_buffer, len, size);
		dma_unmap_addr_set(tx_buffer, dma, dma);

		tx_desc->read.buffer_addr = cpu_to_le64(dma);

		while (unlikely(size > IXGBE_MAX_DATA_PER_TXD)) {
			tx_desc->read.cmd_type_len =
				cmd_type | cpu_to_le32(IXGBE_MAX_DATA_PER_TXD);

			i++;
			tx_desc++;
			if (i == tx_ring->count) {
				tx_desc = IXGBEVF_TX_DESC(tx_ring, 0);
				i = 0;
			}
			tx_desc->read.olinfo_status = 0;

			dma += IXGBE_MAX_DATA_PER_TXD;
			size -= IXGBE_MAX_DATA_PER_TXD;

			tx_desc->read.buffer_addr = cpu_to_le64(dma);
		}

		if (likely(!data_len))
			break;

		tx_desc->read.cmd_type_len = cmd_type | cpu_to_le32(size);

		i++;
		tx_desc++;
		if (i == tx_ring->count) {
			tx_desc = IXGBEVF_TX_DESC(tx_ring, 0);
			i = 0;
		}
		tx_desc->read.olinfo_status = 0;

		size = skb_frag_size(frag);
		data_len -= size;

		dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size,
				       DMA_TO_DEVICE);

		tx_buffer = &tx_ring->tx_buffer_info[i];
	}

	/* write last descriptor with RS and EOP bits */
	cmd_type |= cpu_to_le32(size) | cpu_to_le32(IXGBE_TXD_CMD);
	tx_desc->read.cmd_type_len = cmd_type;

	netdev_tx_sent_queue(txring_txq(tx_ring), first->bytecount);

	/* set the timestamp */
	first->time_stamp = jiffies;

#ifndef HAVE_TRANS_START_IN_QUEUE
	tx_ring->netdev->trans_start = first->time_stamp;
#endif
	/*
	 * Force memory writes to complete before letting h/w know there
	 * are new descriptors to fetch.  (Only applicable for weak-ordered
	 * memory model archs, such as IA-64).
	 *
	 * We also need this memory barrier to make certain all of the
	 * status bits have been updated before next_to_watch is written.
	 */
	wmb();

	/* set next_to_watch value indicating a packet is present */
	first->next_to_watch = tx_desc;

	i++;
	if (i == tx_ring->count)
		i = 0;

	tx_ring->next_to_use = i;

	ixgbevf_maybe_stop_tx(tx_ring, DESC_NEEDED);

#ifdef HAVE_SKB_XMIT_MORE
	if (!skb->xmit_more || netif_xmit_stopped(txring_txq(tx_ring))) {
		writel(i, tx_ring->tail);

		/* we need this if more than one processor can write to our tail
		 * at a time, it synchronizes IO on IA64/Altix systems
		 */
		mmiowb();
	}
#else
	/* notify HW of packet */
	writel(i, tx_ring->tail);

	/* we need this if more than one processor can write to our tail
	 * at a time, it synchronizes IO on IA64/Altix systems
	 */
	mmiowb();
#endif /* HAVE_SKB_XMIT_MORE */

	return;
dma_error:
	dev_err(tx_ring->dev, "TX DMA map failed\n");
	tx_buffer = &tx_ring->tx_buffer_info[i];

	/* clear dma mappings for failed tx_buffer_info map */
	while (tx_buffer != first) {
		if (dma_unmap_len(tx_buffer, len))
			dma_unmap_page(tx_ring->dev,
				       dma_unmap_addr(tx_buffer, dma),
				       dma_unmap_len(tx_buffer, len),
				       DMA_TO_DEVICE);
		dma_unmap_len_set(tx_buffer, len, 0);

		if (i-- == 0)
			i += tx_ring->count;
		tx_buffer = &tx_ring->tx_buffer_info[i];
	}

	if (dma_unmap_len(tx_buffer, len))
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buffer, dma),
				 dma_unmap_len(tx_buffer, len),
				 DMA_TO_DEVICE);
	dma_unmap_len_set(tx_buffer, len, 0);

	dev_kfree_skb_any(tx_buffer->skb);
	tx_buffer->skb = NULL;

	tx_ring->next_to_use = i;
}

static int ixgbevf_xmit_frame_ring(struct sk_buff *skb,
				   struct ixgbevf_ring *tx_ring)
{
	struct ixgbevf_tx_buffer *first;
	int tso;
	u32 tx_flags = 0;
	u16 count = TXD_USE_COUNT(skb_headlen(skb));
	unsigned short f;
	__be16 protocol = skb->protocol;
	u8 hdr_len = 0;
#ifdef HAVE_PF_RING
	struct ixgbevf_adapter *adapter = netdev_priv(tx_ring->netdev);
#endif
	/*
	 * if this is an LLDP ether frame then drop it - VFs do not
	 * forward LLDP frames.
	 */
	if (ntohs(skb->protocol) == 0x88CC) {
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

#ifdef HAVE_PF_RING
	/* We don't allow legacy send when in zc mode */
	if (atomic_read(&adapter->pfring_zc.usage_counter) > 0) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
#endif

	/*
	 * need: 1 descriptor per page * PAGE_SIZE/IXGBE_MAX_DATA_PER_TXD,
	 *       + 1 desc for skb_headlen/IXGBE_MAX_DATA_PER_TXD,
	 *       + 2 desc gap to keep tail from touching head,
	 *       + 1 desc for context descriptor,
	 * otherwise try next time
	 */
	for (f = 0; f < skb_shinfo(skb)->nr_frags; f++)
		count += TXD_USE_COUNT(skb_shinfo(skb)->frags[f].size);

	if (ixgbevf_maybe_stop_tx(tx_ring, count + 3)) {
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	/* software timestamp */
	skb_tx_timestamp(skb);

	/* record the location of the first descriptor for this packet */
	first = &tx_ring->tx_buffer_info[tx_ring->next_to_use];
	first->skb = skb;
	first->bytecount = skb->len;
	first->gso_segs = 1;

#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	if (skb_vlan_tag_present(skb)) {
		tx_flags |= skb_vlan_tag_get(skb);
		tx_flags <<= IXGBE_TX_FLAGS_VLAN_SHIFT;
		tx_flags |= IXGBE_TX_FLAGS_VLAN;
	/* else if it is a SW VLAN check the next protocol and store the tag */
	} else if (protocol == __constant_htons(ETH_P_8021Q)) {
		struct vlan_hdr *vhdr, _vhdr;
		vhdr = skb_header_pointer(skb, ETH_HLEN, sizeof(_vhdr), &_vhdr);
		if (!vhdr)
			goto out_drop;

		protocol = vhdr->h_vlan_encapsulated_proto;
		tx_flags |= ntohs(vhdr->h_vlan_TCI) <<
				  IXGBE_TX_FLAGS_VLAN_SHIFT;
	}
#endif /* NETIF_F_HW_VLAN_TX || NETIF_F_HW_VLAN_CTAG_TX */

	/* record initial flags and protocol */
	first->tx_flags = tx_flags;
	first->protocol = protocol;

	tso = ixgbevf_tso(tx_ring, first, &hdr_len);
	if (tso < 0)
		goto out_drop;
	else if (!tso)
		ixgbevf_tx_csum(tx_ring, first);

	ixgbevf_tx_map(tx_ring, first, hdr_len);

	return NETDEV_TX_OK;

out_drop:
	dev_kfree_skb_any(first->skb);
	first->skb = NULL;

	return NETDEV_TX_OK;
}

static netdev_tx_t ixgbevf_xmit_frame(struct sk_buff *skb,
				      struct net_device *netdev)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbevf_ring *tx_ring;

	if (skb->len <= 0) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/* The minimum packet size for olinfo paylen is 17 so pad the skb
	 * in order to meet this minimum size requirement.
	 */
	if (skb_put_padto(skb, 17))
		return NETDEV_TX_OK;

#ifdef HAVE_TX_MQ
	tx_ring = adapter->tx_ring[skb->queue_mapping];
#else
	tx_ring = adapter->tx_ring[0];
#endif
	return ixgbevf_xmit_frame_ring(skb, tx_ring);
}

/**
 * ixgbevf_set_mac - Change the Ethernet Address of the NIC
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
static int ixgbevf_set_mac(struct net_device *netdev, void *p)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	struct sockaddr *addr = p;
	int err;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	spin_lock_bh(&adapter->mbx_lock);

	err = hw->mac.ops.set_rar(hw, 0, addr->sa_data, 0, IXGBE_RAH_AV);

	spin_unlock_bh(&adapter->mbx_lock);

	if (err)
		return -EPERM;

	ether_addr_copy(hw->mac.addr, addr->sa_data);
	ether_addr_copy(hw->mac.perm_addr, addr->sa_data);
	ether_addr_copy(netdev->dev_addr, addr->sa_data);

	return 0;
}

/**
 * ixgbevf_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 **/
static int ixgbevf_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN;
	int ret;

#ifndef HAVE_NETDEVICE_MIN_MAX_MTU
	/* MTU < 68 is an error and causes problems on some kernels */
	if ((new_mtu < 68) || (max_frame > IXGBE_MAX_JUMBO_FRAME_SIZE))
		return -EINVAL;

#endif
	/* prevent MTU being changed to a size unsupported by XDP */
	if (adapter->xdp_prog) {
		dev_warn(&adapter->pdev->dev, "MTU cannot be changed while XDP program is loaded\n");
		return -EPERM;
	}

	spin_lock_bh(&adapter->mbx_lock);

	/* notify the PF of our intent to use this size of frame */
	ret = hw->mac.ops.set_rlpml(hw, max_frame);
	spin_unlock_bh(&adapter->mbx_lock);
	if (ret)
		return -EINVAL;

	DPRINTK(PROBE, INFO, "changing MTU from %d to %d\n",
	        netdev->mtu, new_mtu);

	/* set new MTU */
	netdev->mtu = new_mtu;

	if (netif_running(netdev))
		ixgbevf_reinit_locked(adapter);

	return 0;
}

#ifdef ETHTOOL_OPS_COMPAT
static int ixgbevf_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	switch (cmd) {
	case SIOCETHTOOL:
		return ethtool_ioctl(ifr);
	default:
		return -EOPNOTSUPP;
	}
}
#endif

#ifdef CONFIG_NET_POLL_CONTROLLER
/**
 * Polling 'interrupt' - used by things like netconsole to send skbs
 * without having to re-enable interrupts. It's not called while
 * the interrupt routine is executing.
 * @netdev: network interface device structure
 **/
static void ixgbevf_netpoll(struct net_device *netdev)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	int i;

	/* if interface is down do nothing */
	if (test_bit(__IXGBEVF_DOWN, &adapter->state))
		return;

	for (i = 0; i < adapter->num_q_vectors; i++) {
		adapter->q_vector[i]->netpoll_rx = true;
		ixgbevf_msix_clean_rings(0, adapter->q_vector[i]);
	}
}
#endif /* CONFIG_NET_POLL_CONTROLLER */


#ifndef USE_REBOOT_NOTIFIER
static int ixgbevf_suspend(struct pci_dev *pdev, pm_message_t __maybe_unused state)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
#ifdef CONFIG_PM
	int retval = 0;
#endif

	rtnl_lock();
	netif_device_detach(netdev);

	if (netif_running(netdev))
		ixgbevf_close_suspend(adapter);

	ixgbevf_clear_interrupt_scheme(adapter);
	rtnl_unlock();

#ifdef CONFIG_PM
	retval = pci_save_state(pdev);
	if (retval)
		return retval;

#endif
	if (!test_and_set_bit(__IXGBEVF_DISABLED, &adapter->state))
		pci_disable_device(pdev);

	return 0;
}

#ifdef CONFIG_PM
static int ixgbevf_resume(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	u32 err;

	pci_restore_state(pdev);
	/*
	 * pci_restore_state clears dev->state_saved so call
	 * pci_save_state to restore it.
	 */
	pci_save_state(pdev);

	err = pci_enable_device_mem(pdev);
	if (err) {
		dev_err(&pdev->dev, "Cannot enable PCI device from suspend\n");
		return err;
	}

	adapter->hw.hw_addr = adapter->io_addr;
	smp_mb__before_atomic();
	clear_bit(__IXGBEVF_DISABLED, &adapter->state);
	pci_set_master(pdev);

	ixgbevf_reset(adapter);

	rtnl_lock();
	err = ixgbevf_init_interrupt_scheme(adapter);
	if (!err && netif_running(netdev))
		err = ixgbevf_open(netdev);
	rtnl_unlock();
	if (err)
		return err;

	netif_device_attach(netdev);

	return err;
}
#endif /* CONFIG_PM */

static void ixgbevf_shutdown(struct pci_dev *pdev)
{
	ixgbevf_suspend(pdev, PMSG_SUSPEND);
}
#endif /* USE_REBOOT_NOTIFIER */

#ifdef HAVE_NDO_GET_STATS64
static void ixgbevf_get_tx_ring_stats(struct rtnl_link_stats64 *stats,
				      const struct ixgbevf_ring *ring)
{
	u64 bytes, packets;
	unsigned int start;

	if (ring) {
		do {
			start = u64_stats_fetch_begin_irq(&ring->syncp);
			bytes = ring->stats.bytes;
			packets = ring->stats.packets;
		} while (u64_stats_fetch_retry_irq(&ring->syncp, start));
		stats->tx_bytes += bytes;
		stats->tx_packets += packets;
	}
}

#ifdef HAVE_VOID_NDO_GET_STATS64
static void ixgbevf_get_stats64(struct net_device *netdev,
				struct rtnl_link_stats64 *stats)
#else
static struct rtnl_link_stats64 *ixgbevf_get_stats64(struct net_device *netdev,
						struct rtnl_link_stats64 *stats)
#endif
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
	unsigned int start;
	u64 bytes, packets;
	const struct ixgbevf_ring *ring;
	int i;

	stats->multicast = adapter->stats.vfmprc - adapter->stats.base_vfmprc;

	rcu_read_lock();
	for (i = 0; i < adapter->num_rx_queues; i++) {
		ring = adapter->rx_ring[i];
		do {
			start = u64_stats_fetch_begin_irq(&ring->syncp);
			bytes = ring->stats.bytes;
			packets = ring->stats.packets;
		} while (u64_stats_fetch_retry_irq(&ring->syncp, start));
		stats->rx_bytes += bytes;
		stats->rx_packets += packets;
	}

	for (i = 0; i < adapter->num_tx_queues; i++) {
		ring = adapter->tx_ring[i];
		ixgbevf_get_tx_ring_stats(stats, ring);
	}

	for (i = 0; i < adapter->num_xdp_queues; i++) {
		ring = adapter->xdp_ring[i];
		ixgbevf_get_tx_ring_stats(stats, ring);
	}
	rcu_read_unlock();
#ifndef HAVE_VOID_NDO_GET_STATS64

	return stats;
#endif
}
#else /* HAVE_NDO_GET_STATS64 */
/**
 * ixgbevf_get_stats - Get System Network Statistics
 * @netdev: network interface device structure
 *
 * Returns the address of the device statistics structure.
 * The statistics are actually updated from the timer callback.
 **/
static struct net_device_stats *ixgbevf_get_stats(struct net_device *netdev)
{
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);
#ifdef HAVE_NETDEV_STATS_IN_NETDEV
	struct net_device_stats *net_stats = &netdev->stats;
#else
	struct net_device_stats *net_stats = &adapter->net_stats;
#endif
	const struct ixgbevf_ring *ring;
	unsigned long bytes = 0, packets = 0;
	int i;

	net_stats->multicast = adapter->stats.vfmprc -
			       adapter->stats.base_vfmprc;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		ring = adapter->rx_ring[i];
		bytes += ring->stats.bytes;
		packets += ring->stats.packets;
	}
	net_stats->rx_bytes = bytes;
	net_stats->rx_packets = packets;
	bytes = 0;
	packets = 0;

	for (i = 0; i < adapter->num_tx_queues; i++) {
		ring = adapter->tx_ring[i];
		bytes += ring->stats.bytes;
		packets += ring->stats.packets;
	}
	net_stats->tx_bytes = bytes;
	net_stats->tx_packets = packets;

	/* only return the current stats */
	return net_stats;
}
#endif /* HAVE_NDO_GET_STATS64 */
#ifdef NETIF_F_GSO_PARTIAL

#define IXGBEVF_MAX_MAC_HDR_LEN		127
#define IXGBEVF_MAX_NETWORK_HDR_LEN	511

static netdev_features_t
ixgbevf_features_check(struct sk_buff *skb, struct net_device *dev,
		       netdev_features_t features)
{
	unsigned int network_hdr_len, mac_hdr_len;

	/* Make certain the headers can be described by a context descriptor */
	mac_hdr_len = skb_network_header(skb) - skb->data;
	if (unlikely(mac_hdr_len > IXGBEVF_MAX_MAC_HDR_LEN))
		return features & ~(NETIF_F_HW_CSUM |
				    NETIF_F_SCTP_CRC |
				    NETIF_F_HW_VLAN_CTAG_TX |
				    NETIF_F_TSO |
				    NETIF_F_TSO6);

	network_hdr_len = skb_checksum_start(skb) - skb_network_header(skb);
	if (unlikely(network_hdr_len >  IXGBEVF_MAX_NETWORK_HDR_LEN))
		return features & ~(NETIF_F_HW_CSUM |
				    NETIF_F_SCTP_CRC |
				    NETIF_F_TSO |
				    NETIF_F_TSO6);

	/* We can only support IPV4 TSO in tunnels if we can mangle the
	 * inner IP ID field, so strip TSO if MANGLEID is not supported.
	 */
	if (skb->encapsulation && !(features & NETIF_F_TSO_MANGLEID))
		features &= ~NETIF_F_TSO;

	return features;
}
#endif /* NETIF_F_GSO_PARTIAL */

#ifdef HAVE_XDP_SUPPORT
static int ixgbevf_xdp_setup(struct net_device *dev, struct bpf_prog *prog)
{
	int i, frame_size = dev->mtu + ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN;
	struct ixgbevf_adapter *adapter = netdev_priv(dev);
	struct bpf_prog *old_prog;

	/* verify ixgbevf ring attributes are sufficient for XDP */
	for (i = 0; i < adapter->num_rx_queues; i++) {
		struct ixgbevf_ring *ring = adapter->rx_ring[i];

		if (frame_size > ixgbevf_rx_bufsz(ring))
			return -EINVAL;
	}

	old_prog = xchg(&adapter->xdp_prog, prog);

	/* If transitioning XDP modes reconfigure rings */
	if (!!prog != !!old_prog) {
		/* Hardware has to reinitialize queues and interrupts to
		 * match packet buffer alignment. Unfortunately, the
		 * hardware is not flexible enough to do this dynamically.
		 */
		if (netif_running(dev))
			ixgbevf_close(dev);

		ixgbevf_clear_interrupt_scheme(adapter);
		ixgbevf_init_interrupt_scheme(adapter);

		if (netif_running(dev))
			ixgbevf_open(dev);
	} else {
		for (i = 0; i < adapter->num_rx_queues; i++)
			xchg(&adapter->rx_ring[i]->xdp_prog, adapter->xdp_prog);
	}

	if (old_prog)
		bpf_prog_put(old_prog);

	return 0;
}

#ifdef HAVE_NDO_BPF
static int ixgbevf_xdp(struct net_device *dev, struct netdev_bpf *xdp)
#else
static int ixgbevf_xdp(struct net_device *dev, struct netdev_xdp *xdp)
#endif /* HAVE_NDO_BPF */
{
	struct ixgbevf_adapter *adapter = netdev_priv(dev);

	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return ixgbevf_xdp_setup(dev, xdp->prog);
	case XDP_QUERY_PROG:
#ifndef NO_NETDEV_BPF_PROG_ATTACHED
                xdp->prog_attached = !!(adapter->xdp_prog);
#endif /* !NO_NETDEV_BPF_PROG_ATTACHED */
		xdp->prog_id = adapter->xdp_prog ?
			       adapter->xdp_prog->aux->id : 0;
		return 0;
	default:
		return -EINVAL;
	}
}

#endif /* HAVE_XDP_SUPPORT */
#ifdef HAVE_NET_DEVICE_OPS
static const struct net_device_ops ixgbevf_netdev_ops = {
	.ndo_open		= ixgbevf_open,
	.ndo_stop		= ixgbevf_close,
	.ndo_start_xmit		= ixgbevf_xmit_frame,
	.ndo_set_rx_mode	= ixgbevf_set_rx_mode,
#ifdef HAVE_NDO_GET_STATS64
	.ndo_get_stats64	= ixgbevf_get_stats64,
#else
	.ndo_get_stats		= ixgbevf_get_stats,
#endif
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= ixgbevf_set_mac,
#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	.extended.ndo_change_mtu = ixgbevf_change_mtu,
#else
	.ndo_change_mtu		= ixgbevf_change_mtu,
#endif
#ifdef ETHTOOL_OPS_COMPAT
	.ndo_do_ioctl		= ixgbevf_ioctl,
#endif
	.ndo_tx_timeout		= ixgbevf_tx_timeout,
#ifdef HAVE_VLAN_RX_REGISTER
	.ndo_vlan_rx_register	= ixgbevf_vlan_rx_register,
#endif
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	.ndo_vlan_rx_add_vid	= ixgbevf_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= ixgbevf_vlan_rx_kill_vid,
#endif
#ifndef HAVE_RHEL6_NET_DEVICE_EXTENDED
#ifdef HAVE_NDO_BUSY_POLL
	.ndo_busy_poll		= ixgbevf_busy_poll_recv,
#endif /* HAVE_NDO_BUSY_POLL */
#endif /* !HAVE_RHEL6_NET_DEVICE_EXTENDED */
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= ixgbevf_netpoll,
#endif
#if defined(NETIF_F_GSO_PARTIAL)
	.ndo_features_check	= ixgbevf_features_check,
#elif defined(HAVE_PASSTHRU_FEATURES_CHECK)
	.ndo_features_check	= passthru_features_check,
#endif
#ifdef HAVE_XDP_SUPPORT
#ifdef HAVE_NDO_BPF
	.ndo_bpf		= ixgbevf_xdp,
#else
	.ndo_xdp		= ixgbevf_xdp,
#endif /* HAVE_NDO_BPF */
#endif /* HAVE_XDP_SUPPORT */
};
#endif /* HAVE_NET_DEVICE_OPS */

static void ixgbevf_assign_netdev_ops(struct net_device *dev)
{
#ifdef HAVE_NET_DEVICE_OPS
	dev->netdev_ops = &ixgbevf_netdev_ops;
#else /* HAVE_NET_DEVICE_OPS */
	dev->open = ixgbevf_open;
	dev->stop = ixgbevf_close;

	dev->hard_start_xmit = ixgbevf_xmit_frame;

	dev->get_stats = ixgbevf_get_stats;
	dev->set_multicast_list = ixgbevf_set_rx_mode;
	dev->set_mac_address = ixgbevf_set_mac;
	dev->change_mtu = ixgbevf_change_mtu;
#ifdef ETHTOOL_OPS_COMPAT
	dev->do_ioctl = ixgbevf_ioctl;
#endif
#ifdef HAVE_TX_TIMEOUT
	dev->tx_timeout = ixgbevf_tx_timeout;
#endif
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	dev->vlan_rx_register = ixgbevf_vlan_rx_register;
	dev->vlan_rx_add_vid = ixgbevf_vlan_rx_add_vid;
	dev->vlan_rx_kill_vid = ixgbevf_vlan_rx_kill_vid;
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	dev->poll_controller = ixgbevf_netpoll;
#endif
#endif /* HAVE_NET_DEVICE_OPS */

#ifdef HAVE_RHEL6_NET_DEVICE_EXTENDED
#ifdef HAVE_NDO_BUSY_POLL
	netdev_extended(dev)->ndo_busy_poll = ixgbevf_busy_poll_recv;
#endif /* HAVE_NDO_BUSY_POLL */
#endif /* HAVE_RHEL6_NET_DEVICE_EXTENDED */

	ixgbevf_set_ethtool_ops(dev);
	dev->watchdog_timeo = 5 * HZ;
}

/**
 * ixgbevf_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in ixgbevf_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * ixgbevf_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int __devinit ixgbevf_probe(struct pci_dev *pdev,
				   const struct pci_device_id *ent)
{
	struct net_device *netdev;
	struct ixgbevf_adapter *adapter = NULL;
#ifdef HAVE_NETDEVICE_MIN_MAX_MTU
	unsigned int min_mtu, max_mtu;
#endif
	struct ixgbe_hw *hw = NULL;
	int err, pci_using_dac;
	const struct ixgbevf_info *ei = ixgbevf_info_tbl[ent->driver_data];
	bool disable_dev = false;
#ifdef HAVE_NDO_SET_FEATURES
#ifndef HAVE_RHEL6_NET_DEVICE_OPS_EXT
	netdev_features_t hw_features;
#else
	u32 hw_features;
#endif
#endif /* HAVE_NDO_SET_FEATURES */

	err = pci_enable_device(pdev);
	if (err)
		return err;

	if (!dma_set_mask_and_coherent(pci_dev_to_dev(pdev),
				       DMA_BIT_MASK(64))) {
		pci_using_dac = 1;
	} else {
		err = dma_set_mask_and_coherent(pci_dev_to_dev(pdev),
						DMA_BIT_MASK(32));
		if (err) {
			dev_err(pci_dev_to_dev(pdev), "No usable DMA configuration, aborting\n");
			goto err_dma;
		}
		pci_using_dac = 0;
	}

	err = pci_request_regions(pdev, ixgbevf_driver_name);
	if (err) {
		dev_err(pci_dev_to_dev(pdev),
			"pci_request_regions failed 0x%x\n", err);
		goto err_pci_reg;
	}

	pci_enable_pcie_error_reporting(pdev);

	pci_set_master(pdev);

#ifdef HAVE_TX_MQ
	netdev = alloc_etherdev_mq(sizeof(struct ixgbevf_adapter), MAX_TX_QUEUES);
#else
	netdev = alloc_etherdev(sizeof(struct ixgbevf_adapter));
#endif
	if (!netdev) {
		err = -ENOMEM;
		goto err_alloc_etherdev;
	}

	SET_NETDEV_DEV(netdev, &pdev->dev);

	adapter = netdev_priv(netdev);

	adapter->netdev = netdev;
	adapter->pdev = pdev;
	hw = &adapter->hw;
	hw->back = adapter;

	hw->mac.type = ei->mac;
	adapter->flags = ei->flags;
	adapter->msg_enable = (1 << DEFAULT_DEBUG_LEVEL_SHIFT) - 1;

#ifdef HAVE_PCI_ERS
	/*
	 * call save state here in standalone driver because it relies on
	 * adapter struct to exist, and needs to call netdev_priv
	 */
	pci_save_state(pdev);

#endif
	hw->hw_addr = ioremap(pci_resource_start(pdev, 0),
			      pci_resource_len(pdev, 0));
	adapter->io_addr = hw->hw_addr;
	if (!hw->hw_addr) {
		err = -EIO;
		goto err_ioremap;
	}

#ifdef HAVE_PF_RING
	netdev->mem_start = pci_resource_start(pdev, 0);
	netdev->mem_end = netdev->mem_start + pci_resource_len(pdev, 0);
#endif

	ixgbevf_assign_netdev_ops(netdev);

	/* setup the private structure */
	err = ixgbevf_sw_init(adapter);
	if (err)
		goto err_sw_init;

#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	netdev->features = NETIF_F_SG |
#ifdef NETIF_F_TSO
			   NETIF_F_TSO |
#ifdef NETIF_F_TSO6
			   NETIF_F_TSO6 |
#endif /* NETIF_F_TSO6 */
#endif /* NETIF_F_TSO */
			   NETIF_F_RXCSUM |
			   NETIF_F_HW_CSUM |
			   NETIF_F_SCTP_CRC;

#else /* !defined(NETIF_F_HW_VLAN_TX) || !defined(NETIF_F_HW_VLAN_CTAG_TX) */
	netdev->features = NETIF_F_SG | NETIF_F_HW_CSUM;

#endif/* defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX) */
#ifdef NETIF_F_GSO_PARTIAL

	netdev->gso_partial_features = NETIF_F_GSO_GRE |
				       NETIF_F_GSO_GRE_CSUM |
#ifdef NETIF_F_GSO_IPXIP4
				       NETIF_F_GSO_IPXIP4 |
#ifdef NETIF_F_GSO_IPXIP6
				       NETIF_F_GSO_IPXIP6 |
#endif
#else
				       NETIF_F_GSO_IPIP |
				       NETIF_F_GSO_SIT |
#endif
				       NETIF_F_GSO_UDP_TUNNEL |
				       NETIF_F_GSO_UDP_TUNNEL_CSUM;

	netdev->features |= netdev->gso_partial_features |
			    NETIF_F_GSO_PARTIAL;
#endif /* NETIF_F_GSO_PARTIAL */
#ifdef HAVE_NDO_SET_FEATURES
	/* copy netdev features into list of user selectable features */
#ifndef HAVE_RHEL6_NET_DEVICE_OPS_EXT
	hw_features = netdev->hw_features;
#else
	hw_features = get_netdev_hw_features(netdev);
#endif /* HAVE_RHEL6_NET_DEVICE_OPS_EXT */

	hw_features |= netdev->features;
#else
#ifdef NETIF_F_GRO
        netdev->features |= NETIF_F_GRO;
#endif /* NETIF_F_GRO */
#endif /* HAVE_NDO_SET_FEATURES */
#ifdef HAVE_NDO_SET_FEATURES
#ifdef HAVE_RHEL6_NET_DEVICE_OPS_EXT
	set_netdev_hw_features(netdev, hw_features);
#else
	netdev->hw_features = hw_features;
#endif
#endif /* HAVE_NDO_SET_FEATURES */

	if (pci_using_dac)
		netdev->features |= NETIF_F_HIGHDMA;

#ifdef HAVE_NETDEV_VLAN_FEATURES
	netdev->vlan_features |= netdev->features;
#ifdef NETIF_F_GSO_PARTIAL
	netdev->vlan_features |= NETIF_F_TSO_MANGLEID;
#endif
#endif /* HAVE_NETDEV_VLAN_FEATURES */
#ifdef HAVE_MPLS_FEATURES
	netdev->mpls_features |= NETIF_F_HW_CSUM;
#endif
#ifdef HAVE_SKB_INNER_NETWORK_HEADER
	netdev->hw_enc_features |= netdev->vlan_features;
#endif

	/* set this bit last since it cannot be part of vlan_features */
#ifdef NETIF_F_HW_VLAN_CTAG_TX
	netdev->features |= NETIF_F_HW_VLAN_CTAG_TX |
			    NETIF_F_HW_VLAN_CTAG_RX |
			    NETIF_F_HW_VLAN_CTAG_FILTER;
#endif
#ifdef NETIF_F_HW_VLAN_TX
	netdev->features |= NETIF_F_HW_VLAN_TX |
			    NETIF_F_HW_VLAN_RX |
			    NETIF_F_HW_VLAN_FILTER;
#endif
	/* The HW MAC address was set and/or determined in sw_init */
	ether_addr_copy(netdev->dev_addr, adapter->hw.mac.addr);
	ether_addr_copy(netdev->perm_addr, adapter->hw.mac.addr);

	if (!is_valid_ether_addr(netdev->dev_addr)) {
		dev_info(pci_dev_to_dev(pdev),
			 "ixgbevf: invalid MAC address\n");
		err = -EIO;
		goto err_sw_init;
	}
#ifdef HAVE_NETDEVICE_MIN_MAX_MTU

	/* MTU range: 68 - 1504 or 9710 */
	min_mtu = ETH_MIN_MTU;
	switch (adapter->hw.api_version) {
	case ixgbe_mbox_api_11:
	case ixgbe_mbox_api_12:
	case ixgbe_mbox_api_13:
		max_mtu = IXGBE_MAX_JUMBO_FRAME_SIZE -
			  (ETH_HLEN + ETH_FCS_LEN);
		break;
	default:
		if (adapter->hw.mac.type != ixgbe_mac_82599_vf)
			max_mtu = IXGBE_MAX_JUMBO_FRAME_SIZE -
				  (ETH_HLEN + ETH_FCS_LEN);
		else
			max_mtu = ETH_DATA_LEN + ETH_FCS_LEN;
		break;
	}

#ifdef HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
	netdev->extended->min_mtu = min_mtu;
	netdev->extended->max_mtu = max_mtu;
#else
	netdev->min_mtu = min_mtu;
	netdev->max_mtu = max_mtu;
#endif
#endif

	timer_setup(&adapter->service_timer, ixgbevf_service_timer, 0);

	if (IXGBE_REMOVED(hw->hw_addr)) {
		err = -EIO;
		goto err_sw_init;
	}
	INIT_WORK(&adapter->service_task, ixgbevf_service_task);
	set_bit(__IXGBEVF_SERVICE_INITED, &adapter->state);
	clear_bit(__IXGBEVF_SERVICE_SCHED, &adapter->state);

	err = ixgbevf_init_interrupt_scheme(adapter);
	if (err)
		goto err_sw_init;

	strcpy(netdev->name, "eth%d");

	err = register_netdev(netdev);
	if (err)
		goto err_register;

	pci_set_drvdata(pdev, netdev);
	netif_carrier_off(netdev);

	netif_tx_stop_all_queues(netdev);
	ixgbevf_init_last_counter_stats(adapter);

	/* print the MAC address */
	dev_info(&pdev->dev, "%02x:%02x:%02x:%02x:%02x:%02x\n",
		 netdev->dev_addr[0], netdev->dev_addr[1],
		 netdev->dev_addr[2], netdev->dev_addr[3],
		 netdev->dev_addr[4], netdev->dev_addr[5]);

	switch (hw->mac.type) {
	case ixgbe_mac_X550_vf:
		DPRINTK(PROBE, INFO, "Intel(R) X550 Virtual Function\n");
		break;
	case ixgbe_mac_X540_vf:
		DPRINTK(PROBE, INFO, "Intel(R) X540 Virtual Function\n");
		break;
	case ixgbe_mac_82599_vf:
	default:
		DPRINTK(PROBE, INFO, "Intel(R) 82599 Virtual Function\n");
		break;
	}

#ifdef NETIF_F_GRO
        if (netdev->features & NETIF_F_GRO)
                DPRINTK(PROBE, INFO, "GRO is enabled\n");
#endif

	DPRINTK(PROBE, INFO, "%s\n", ixgbevf_driver_string);
	return 0;

err_register:
	ixgbevf_clear_interrupt_scheme(adapter);
err_sw_init:
	ixgbevf_reset_interrupt_capability(adapter);
	iounmap(adapter->io_addr);
	kfree(adapter->rss_key);
err_ioremap:
	disable_dev = !test_and_set_bit(__IXGBEVF_DISABLED, &adapter->state);
	free_netdev(netdev);
err_alloc_etherdev:
	pci_release_regions(pdev);
err_pci_reg:
err_dma:
	if (!adapter || disable_dev)
		pci_disable_device(pdev);
	return err;
}

/**
 * ixgbevf_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * ixgbevf_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/
static void __devexit ixgbevf_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct ixgbevf_adapter *adapter;
	bool disable_dev;

	if (!netdev)
		return;

	adapter = netdev_priv(netdev);

	set_bit(__IXGBEVF_REMOVING, &adapter->state);
	cancel_work_sync(&adapter->service_task);

	if (netdev->reg_state == NETREG_REGISTERED)
		unregister_netdev(netdev);

	ixgbevf_clear_interrupt_scheme(adapter);

	iounmap(adapter->io_addr);
	pci_release_regions(pdev);

	DPRINTK(PROBE, INFO, "Remove complete\n");

	kfree(adapter->rss_key);
	disable_dev = !test_and_set_bit(__IXGBEVF_DISABLED, &adapter->state);
	free_netdev(netdev);

	pci_disable_pcie_error_reporting(pdev);

	if (disable_dev)
		pci_disable_device(pdev);
}

/**
 * ixgbevf_io_error_detected - called when PCI error is detected
 * @pdev: Pointer to PCI device
 * @state: The current pci connection state
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 */
static pci_ers_result_t ixgbevf_io_error_detected(struct pci_dev *pdev,
						  pci_channel_state_t state)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);

	if (!test_bit(__IXGBEVF_SERVICE_INITED, &adapter->state))
		return PCI_ERS_RESULT_DISCONNECT;

	rtnl_lock();
	netif_device_detach(netdev);

	if (netif_running(netdev))
		ixgbevf_close_suspend(adapter);

	if (state == pci_channel_io_perm_failure) {
		rtnl_unlock();
		return PCI_ERS_RESULT_DISCONNECT;
	}

	if (!test_and_set_bit(__IXGBEVF_DISABLED, &adapter->state))
		pci_disable_device(pdev);
	rtnl_unlock();

	/* Request a slot slot reset. */
	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * ixgbevf_io_slot_reset - called after the pci bus has been reset.
 * @pdev: Pointer to PCI device
 *
 * Restart the card from scratch, as if from a cold-boot. Implementation
 * resembles the first-half of the ixgbevf_resume routine.
 */
static pci_ers_result_t ixgbevf_io_slot_reset(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct ixgbevf_adapter *adapter = netdev_priv(netdev);

	if (pci_enable_device_mem(pdev)) {
		dev_err(&pdev->dev,
			"Cannot re-enable PCI device after reset.\n");
		return PCI_ERS_RESULT_DISCONNECT;
	}

	adapter->hw.hw_addr = adapter->io_addr;
	smp_mb__before_atomic();
	clear_bit(__IXGBEVF_DISABLED, &adapter->state);
	pci_set_master(pdev);

	ixgbevf_reset(adapter);

	return PCI_ERS_RESULT_RECOVERED;
}

/**
 * ixgbevf_io_resume - called when traffic can start flowing again.
 * @pdev: Pointer to PCI device
 *
 * This callback is called when the error recovery driver tells us that
 * its OK to resume normal operation. Implementation resembles the
 * second-half of the ixgbevf_resume routine.
 */
static void ixgbevf_io_resume(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);

	rtnl_lock();
	if (netif_running(netdev))
		ixgbevf_open(netdev);

	netif_device_attach(netdev);
	rtnl_unlock();
}

struct net_device *ixgbevf_hw_to_netdev(const struct ixgbe_hw *hw)
{
	return ((struct ixgbevf_adapter *)hw->back)->netdev;
}

struct ixgbevf_msg *ixgbevf_hw_to_msg(const struct ixgbe_hw *hw)
{
	struct ixgbevf_adapter *adapter =
		container_of(hw, struct ixgbevf_adapter, hw);
	return (struct ixgbevf_msg *)&adapter->msg_enable;
}

/* PCI Error Recovery (ERS) */
static struct pci_error_handlers ixgbevf_err_handler = {
	.error_detected = ixgbevf_io_error_detected,
	.slot_reset = ixgbevf_io_slot_reset,
	.resume = ixgbevf_io_resume,
};

static struct pci_driver ixgbevf_driver = {
	.name     = ixgbevf_driver_name,
	.id_table = ixgbevf_pci_tbl,
	.probe    = ixgbevf_probe,
	.remove   = __devexit_p(ixgbevf_remove),
#ifdef CONFIG_PM
	/* Power Management Hooks */
	.suspend  = ixgbevf_suspend,
	.resume   = ixgbevf_resume,
#endif
#ifndef USE_REBOOT_NOTIFIER
	.shutdown = ixgbevf_shutdown,
#endif
	.err_handler = &ixgbevf_err_handler
};

/**
 * ixgbevf_init_module - Driver Registration Routine
 *
 * ixgbevf_init_module is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 **/
static int __init ixgbevf_init_module(void)
{
	int ret;
	printk(KERN_INFO "ixgbevf: %s - version %s\n", ixgbevf_driver_string,
	       ixgbevf_driver_version);

	printk(KERN_INFO "%s\n", ixgbevf_copyright);

	ret = pci_register_driver(&ixgbevf_driver);
	return ret;
}

module_init(ixgbevf_init_module);

/**
 * ixgbevf_exit_module - Driver Exit Cleanup Routine
 *
 * ixgbevf_exit_module is called just before the driver is removed
 * from memory.
 **/
static void __exit ixgbevf_exit_module(void)
{
	pci_unregister_driver(&ixgbevf_driver);
}

module_exit(ixgbevf_exit_module);

/* ixgbevf_main.c */
