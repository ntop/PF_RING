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

/******************************************************************************
 Copyright (c)2006 - 2007 Myricom, Inc. for some LRO specific code
******************************************************************************/
#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_sched.h>
#include <linux/ipv6.h>
#ifdef NETIF_F_TSO
#include <net/checksum.h>
#ifdef NETIF_F_TSO6
#include <net/ip6_checksum.h>
#endif
#endif
#ifdef SIOCETHTOOL
#include <linux/ethtool.h>
#endif

#include <linux/if_bridge.h>
#include "ixgbe.h"



#include "ixgbe_dcb_82599.h"
#include "ixgbe_sriov.h"

char ixgbe_driver_name[] = "ixgbe";
static const char ixgbe_driver_string[] =
			      "Intel(R) 10 Gigabit PCI Express Network Driver";
#define DRV_HW_PERF

#define FPGA

#define DRIVERIOV

#ifdef ENABLE_DNA
#undef DRIVERIOV
#define DRIVERIOV "-DNA"
#endif

#define VMDQ_TAG

#define BYPASS_TAG

#define DRV_VERSION	__stringify(3.21.2) DRIVERIOV DRV_HW_PERF FPGA \
			VMDQ_TAG BYPASS_TAG
const char ixgbe_driver_version[] = DRV_VERSION;
static const char ixgbe_copyright[] =
				"Copyright (c) 1999-2014 Intel Corporation.";

/* ixgbe_pci_tbl - PCI Device ID Table
 *
 * Wildcard entries (PCI_ANY_ID) should come last
 * Last entry must be all 0s
 *
 * { Vendor ID, Device ID, SubVendor ID, SubDevice ID,
 *   Class, Class Mask, private data (not used) }
 */
static DEFINE_PCI_DEVICE_TABLE(ixgbe_pci_tbl) = {
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82598)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82598AF_DUAL_PORT)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82598AF_SINGLE_PORT)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82598AT)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82598AT2)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82598EB_CX4)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82598_CX4_DUAL_PORT)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82598_DA_DUAL_PORT)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82598_SR_DUAL_PORT_EM)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82598EB_XF_LR)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82598EB_SFP_LOM)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82598_BX)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_KX4)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_XAUI_LOM)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_KR)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_SFP)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_SFP_EM)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_KX4_MEZZ)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_CX4)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_BACKPLANE_FCOE)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_SFP_FCOE)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_T3_LOM)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_COMBO_BACKPLANE)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X540T)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_SFP_SF2)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_LS)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599EN_SFP)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_SFP_SF_QP)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_82599_QSFP_SF_QP)},
	{PCI_VDEVICE(INTEL, IXGBE_DEV_ID_X540T1)},
	/* required last entry */
	{0, }
};
MODULE_DEVICE_TABLE(pci, ixgbe_pci_tbl);

#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
static int ixgbe_notify_dca(struct notifier_block *, unsigned long event,
			    void *p);
static struct notifier_block dca_notifier = {
	.notifier_call	= ixgbe_notify_dca,
	.next		= NULL,
	.priority	= 0
};

#endif
MODULE_AUTHOR("Intel Corporation, <linux.nics@intel.com>");
MODULE_DESCRIPTION("Intel(R) 10 Gigabit PCI Express Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

#define DEFAULT_DEBUG_LEVEL_SHIFT 3

#ifdef ENABLE_DNA
#include "ixgbe_dna.c"
#endif

static bool ixgbe_check_cfg_remove(struct ixgbe_hw *hw, struct pci_dev *pdev);

static int ixgbe_read_pci_cfg_word_parent(struct ixgbe_hw *hw,
					  u32 reg, u16 *value)
{
	struct ixgbe_adapter *adapter = hw->back;
	struct pci_dev *parent_dev;
	struct pci_bus *parent_bus;
	int pos;

	parent_bus = adapter->pdev->bus->parent;
	if (!parent_bus)
		return IXGBE_ERR_FEATURE_NOT_SUPPORTED;

	parent_dev = parent_bus->self;
	if (!parent_dev)
		return IXGBE_ERR_FEATURE_NOT_SUPPORTED;

	pos = pci_find_capability(parent_dev, PCI_CAP_ID_EXP);
	if (!pos)
		return IXGBE_ERR_FEATURE_NOT_SUPPORTED;

	pci_read_config_word(parent_dev, pos + reg, value);
	if (*value == IXGBE_FAILED_READ_CFG_WORD &&
	    ixgbe_check_cfg_remove(hw, parent_dev))
		return IXGBE_ERR_FEATURE_NOT_SUPPORTED;
	return 0;
}

/**
 *  ixgbe_get_parent_bus_info - Set PCI bus info beyond switch
 *  @hw: pointer to hardware structure
 *
 *  Sets the PCI bus info (speed, width, type) within the ixgbe_hw structure
 *  when the device is behind a switch.
 **/
static s32 ixgbe_get_parent_bus_info(struct ixgbe_hw *hw)
{
	u16 link_status = 0;
	int err;

	hw->bus.type = ixgbe_bus_type_pci_express;

	/* Get the negotiated link width and speed from PCI config space of the
	 * parent, as this device is behind a switch
	 */
	err = ixgbe_read_pci_cfg_word_parent(hw, 18, &link_status);

	/* If the read fails, fallback to default */
	if (err)
		link_status = IXGBE_READ_PCIE_WORD(hw, IXGBE_PCI_LINK_STATUS);

	ixgbe_set_pci_config_data_generic(hw, link_status);

	return 0;
}

/**
 * ixgbe_check_from_parent - determine whether to use parent for PCIe info
 * @hw: hw specific details
 *
 * This function is used by probe to determine whether a device's PCIe info
 * (speed, width, etc) should be obtained from the parent bus or directly. This
 * is useful for specialized device configurations containing PCIe bridges.
 */
static inline bool ixgbe_pcie_from_parent(struct ixgbe_hw *hw)
{
	switch (hw->device_id) {
	case IXGBE_DEV_ID_82599_QSFP_SF_QP:
	case IXGBE_DEV_ID_82599_SFP_SF_QP:
		return true;
	default:
		return false;
	}
}

static void ixgbe_check_minimum_link(struct ixgbe_adapter *adapter,
				     int expected_gts)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int max_gts = 0;

	switch (hw->bus.speed) {
	case ixgbe_bus_speed_2500:
		/* 8b/10b encoding reduces max throughput by 20% */
		max_gts = 2 * hw->bus.width;
		break;
	case ixgbe_bus_speed_5000:
		/* 8b/10b encoding reduces max throughput by 20% */
		max_gts = 4 * hw->bus.width;
		break;
	case ixgbe_bus_speed_8000:
		/* 128b/130b encoding has less than 2% impact on throughput */
		max_gts = 8 * hw->bus.width;
		break;
	default:
		e_dev_warn("Unable to determine PCI Express throughput.\n");
		return;
	}

	e_dev_info("PCI Express bandwidth of %dGT/s available\n",
		   max_gts);
	e_dev_info("(Speed:%s, Width: x%d, Encoding Loss:%s)\n",
		   (hw->bus.speed == ixgbe_bus_speed_8000 ? "8.0GT/s" :
		    hw->bus.speed == ixgbe_bus_speed_5000 ? "5.0GT/s" :
		    hw->bus.speed == ixgbe_bus_speed_2500 ? "2.5GT/s" :
		    "Unknown"),
		   hw->bus.width,
		   (hw->bus.speed == ixgbe_bus_speed_2500 ? "20%" :
		    hw->bus.speed == ixgbe_bus_speed_5000 ? "20%" :
		    hw->bus.speed == ixgbe_bus_speed_8000 ? "<2%" :
		    "Unknown"));

	if (max_gts < expected_gts) {
		e_dev_warn("This is not sufficient for optimal performance of this card.\n");
		e_dev_warn("For optimal performance, at least %dGT/s of bandwidth is required.\n",
			expected_gts);
		e_dev_warn("A slot with more lanes and/or higher speed is suggested.\n");
	}
}

/**
 * ixgbe_enumerate_functions - Get the number of ports this device has
 * @adapter: adapter structure
 *
 * This function enumerates the phsyical functions co-located on a single slot,
 * in order to determine how many ports a device has. This is most useful in
 * determining the required GT/s of PCIe bandwidth necessary for optimal
 * performance.
 **/
static inline int ixgbe_enumerate_functions(struct ixgbe_adapter *adapter)
{
	struct list_head *entry;
	int physfns = 0;

	/* Some cards can not use the generic count PCIe functions method,
	 * because they are behind a parent switch, so we hardcode these to
	 * correct number of ports.
	 */
	if (ixgbe_pcie_from_parent(&adapter->hw)) {
		physfns = 4;
	} else {
		list_for_each(entry, &adapter->pdev->bus_list) {
#ifdef CONFIG_PCI_IOV
			struct pci_dev *pdev =
				list_entry(entry, struct pci_dev, bus_list);
			/* don't count virtual functions */
			if (pdev->is_virtfn)
				continue;
#endif
			physfns++;
		}
	}

	return physfns;
}

static void ixgbe_service_event_schedule(struct ixgbe_adapter *adapter)
{
	if (!test_bit(__IXGBE_DOWN, &adapter->state) &&
	    !test_bit(__IXGBE_REMOVE, &adapter->state) &&
	    !test_and_set_bit(__IXGBE_SERVICE_SCHED, &adapter->state))
		schedule_work(&adapter->service_task);
}

static void ixgbe_service_event_complete(struct ixgbe_adapter *adapter)
{
	BUG_ON(!test_bit(__IXGBE_SERVICE_SCHED, &adapter->state));

	/* flush memory to make sure state is correct before next watchog */
	smp_mb__before_clear_bit();
	clear_bit(__IXGBE_SERVICE_SCHED, &adapter->state);
}

static void ixgbe_remove_adapter(struct ixgbe_hw *hw)
{
	struct ixgbe_adapter *adapter = hw->back;

	if (!hw->hw_addr)
		return;
	hw->hw_addr = NULL;
	e_dev_err("Adapter removed\n");
	if (test_bit(__IXGBE_SERVICE_INITED, &adapter->state))
		ixgbe_service_event_schedule(adapter);
}

void ixgbe_check_remove(struct ixgbe_hw *hw, u32 reg)
{
	u32 value;

	/* The following check not only optimizes a bit by not
	 * performing a read on the status register when the
	 * register just read was a status register read that
	 * returned IXGBE_FAILED_READ_REG. It also blocks any
	 * potential recursion.
	 */
	if (reg == IXGBE_STATUS) {
		ixgbe_remove_adapter(hw);
		return;
	}
	value = IXGBE_READ_REG(hw, IXGBE_STATUS);
	if (value == IXGBE_FAILED_READ_REG)
		ixgbe_remove_adapter(hw);
}

static void ixgbe_release_hw_control(struct ixgbe_adapter *adapter)
{
	u32 ctrl_ext;

	/* Let firmware take over control of h/w */
	ctrl_ext = IXGBE_READ_REG(&adapter->hw, IXGBE_CTRL_EXT);
	IXGBE_WRITE_REG(&adapter->hw, IXGBE_CTRL_EXT,
			ctrl_ext & ~IXGBE_CTRL_EXT_DRV_LOAD);
}

static void ixgbe_get_hw_control(struct ixgbe_adapter *adapter)
{
	u32 ctrl_ext;

	/* Let firmware know the driver has taken over */
	ctrl_ext = IXGBE_READ_REG(&adapter->hw, IXGBE_CTRL_EXT);
	IXGBE_WRITE_REG(&adapter->hw, IXGBE_CTRL_EXT,
			ctrl_ext | IXGBE_CTRL_EXT_DRV_LOAD);
}

/*
 * ixgbe_set_ivar - set the IVAR registers, mapping interrupt causes to vectors
 * @adapter: pointer to adapter struct
 * @direction: 0 for Rx, 1 for Tx, -1 for other causes
 * @queue: queue to map the corresponding interrupt to
 * @msix_vector: the vector to map to the corresponding queue
 *
 */
static void ixgbe_set_ivar(struct ixgbe_adapter *adapter, s8 direction,
			   u8 queue, u8 msix_vector)
{
	u32 ivar, index;
	struct ixgbe_hw *hw = &adapter->hw;
	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		msix_vector |= IXGBE_IVAR_ALLOC_VAL;
		if (direction == -1)
			direction = 0;
		index = (((direction * 64) + queue) >> 2) & 0x1F;
		ivar = IXGBE_READ_REG(hw, IXGBE_IVAR(index));
		ivar &= ~(0xFF << (8 * (queue & 0x3)));
		ivar |= (msix_vector << (8 * (queue & 0x3)));
		IXGBE_WRITE_REG(hw, IXGBE_IVAR(index), ivar);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		if (direction == -1) {
			/* other causes */
			msix_vector |= IXGBE_IVAR_ALLOC_VAL;
			index = ((queue & 1) * 8);
			ivar = IXGBE_READ_REG(&adapter->hw, IXGBE_IVAR_MISC);
			ivar &= ~(0xFF << index);
			ivar |= (msix_vector << index);
			IXGBE_WRITE_REG(&adapter->hw, IXGBE_IVAR_MISC, ivar);
			break;
		} else {
			/* tx or rx causes */
			msix_vector |= IXGBE_IVAR_ALLOC_VAL;
			index = ((16 * (queue & 1)) + (8 * direction));
			ivar = IXGBE_READ_REG(hw, IXGBE_IVAR(queue >> 1));
			ivar &= ~(0xFF << index);
			ivar |= (msix_vector << index);
			IXGBE_WRITE_REG(hw, IXGBE_IVAR(queue >> 1), ivar);
			break;
		}
	default:
		break;
	}
}

static inline void ixgbe_irq_rearm_queues(struct ixgbe_adapter *adapter,
					  u64 qmask)
{
	u32 mask;

	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82598EB:
		mask = (IXGBE_EIMS_RTX_QUEUE & qmask);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EICS, mask);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		mask = (qmask & 0xFFFFFFFF);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EICS_EX(0), mask);
		mask = (qmask >> 32);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EICS_EX(1), mask);
		break;
	default:
		break;
	}
}

void ixgbe_unmap_and_free_tx_resource(struct ixgbe_ring *ring,
				      struct ixgbe_tx_buffer *tx_buffer)
{
	if (tx_buffer->skb) {
		dev_kfree_skb_any(tx_buffer->skb);
		if (dma_unmap_len(tx_buffer, len))
			dma_unmap_single(ring->dev,
					 dma_unmap_addr(tx_buffer, dma),
					 dma_unmap_len(tx_buffer, len),
					 DMA_TO_DEVICE);
	} else if (dma_unmap_len(tx_buffer, len)) {
		dma_unmap_page(ring->dev,
			       dma_unmap_addr(tx_buffer, dma),
			       dma_unmap_len(tx_buffer, len),
			       DMA_TO_DEVICE);
	}
	tx_buffer->next_to_watch = NULL;
	tx_buffer->skb = NULL;
	dma_unmap_len_set(tx_buffer, len, 0);
	/* tx_buffer_info must be completely set up in the transmit path */
}

static void ixgbe_update_xoff_rx_lfc(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct ixgbe_hw_stats *hwstats = &adapter->stats;
	int i;
	u32 data;

	if ((hw->fc.current_mode != ixgbe_fc_full) &&
	    (hw->fc.current_mode != ixgbe_fc_rx_pause))
		return;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		data = IXGBE_READ_REG(hw, IXGBE_LXOFFRXC);
		break;
	default:
		data = IXGBE_READ_REG(hw, IXGBE_LXOFFRXCNT);
	}
	hwstats->lxoffrxc += data;

	/* refill credits (no tx hang) if we received xoff */
	if (!data)
		return;

	for (i = 0; i < adapter->num_tx_queues; i++)
		clear_bit(__IXGBE_HANG_CHECK_ARMED,
			  &adapter->tx_ring[i]->state);
}

static void ixgbe_update_xoff_received(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct ixgbe_hw_stats *hwstats = &adapter->stats;
	u32 xoff[8] = {0};
	int i;
	bool pfc_en = adapter->dcb_cfg.pfc_mode_enable;

#ifdef HAVE_DCBNL_IEEE
	if (adapter->ixgbe_ieee_pfc)
		pfc_en |= !!(adapter->ixgbe_ieee_pfc->pfc_en);

#endif
	if (!(adapter->flags & IXGBE_FLAG_DCB_ENABLED) || !pfc_en) {
		ixgbe_update_xoff_rx_lfc(adapter);
		return;
	}

	/* update stats for each tc, only valid with PFC enabled */
	for (i = 0; i < MAX_TX_PACKET_BUFFERS; i++) {
		switch (hw->mac.type) {
		case ixgbe_mac_82598EB:
			xoff[i] = IXGBE_READ_REG(hw, IXGBE_PXOFFRXC(i));
			break;
		default:
			xoff[i] = IXGBE_READ_REG(hw, IXGBE_PXOFFRXCNT(i));
		}
		hwstats->pxoffrxc[i] += xoff[i];
	}

	/* disarm tx queues that have received xoff frames */
	for (i = 0; i < adapter->num_tx_queues; i++) {
		struct ixgbe_ring *tx_ring = adapter->tx_ring[i];
		u8 tc = tx_ring->dcb_tc;

		if ((tc <= 7) && (xoff[tc]))
			clear_bit(__IXGBE_HANG_CHECK_ARMED, &tx_ring->state);
	}
}

static u64 ixgbe_get_tx_completed(struct ixgbe_ring *ring)
{
	return ring->stats.packets;
}

static u64 ixgbe_get_tx_pending(struct ixgbe_ring *ring)
{
	struct ixgbe_adapter *adapter = ring->q_vector->adapter;
	struct ixgbe_hw *hw = &adapter->hw;

	u32 head = IXGBE_READ_REG(hw, IXGBE_TDH(ring->reg_idx));
	u32 tail = IXGBE_READ_REG(hw, IXGBE_TDT(ring->reg_idx));

	return ((head <= tail) ? tail : tail + ring->count) - head;
}

static bool ixgbe_check_tx_hang(struct ixgbe_ring *tx_ring)
{
	u32 tx_done = ixgbe_get_tx_completed(tx_ring);
	u32 tx_done_old = tx_ring->tx_stats.tx_done_old;
	u32 tx_pending = ixgbe_get_tx_pending(tx_ring);
	bool ret = false;

	clear_check_for_tx_hang(tx_ring);

	/*
	 * Check for a hung queue, but be thorough. This verifies
	 * that a transmit has been completed since the previous
	 * check AND there is at least one packet pending. The
	 * ARMED bit is set to indicate a potential hang. The
	 * bit is cleared if a pause frame is received to remove
	 * false hang detection due to PFC or 802.3x frames. By
	 * requiring this to fail twice we avoid races with
	 * PFC clearing the ARMED bit and conditions where we
	 * run the check_tx_hang logic with a transmit completion
	 * pending but without time to complete it yet.
	 */
	if ((tx_done_old == tx_done) && tx_pending) {
		/* make sure it is true for two checks in a row */
		ret = test_and_set_bit(__IXGBE_HANG_CHECK_ARMED,
				       &tx_ring->state);
	} else {
		/* update completed stats and continue */
		tx_ring->tx_stats.tx_done_old = tx_done;
		/* reset the countdown */
		clear_bit(__IXGBE_HANG_CHECK_ARMED, &tx_ring->state);
	}

	return ret;
}

/**
 * ixgbe_tx_timeout_reset - initiate reset due to Tx timeout
 * @adapter: driver private struct
 **/
static void ixgbe_tx_timeout_reset(struct ixgbe_adapter *adapter)
{

	/* Do the reset outside of interrupt context */
	if (!test_bit(__IXGBE_DOWN, &adapter->state)) {
		adapter->flags2 |= IXGBE_FLAG2_RESET_REQUESTED;
		ixgbe_service_event_schedule(adapter);
	}
}

/**
 * ixgbe_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 **/
static void ixgbe_tx_timeout(struct net_device *netdev)
{
struct ixgbe_adapter *adapter = netdev_priv(netdev);
	bool real_tx_hang = false;
	int i;

#define TX_TIMEO_LIMIT 16000
	for (i = 0; i < adapter->num_tx_queues; i++) {
		struct ixgbe_ring *tx_ring = adapter->tx_ring[i];
		if (check_for_tx_hang(tx_ring) && ixgbe_check_tx_hang(tx_ring))
			real_tx_hang = true;
	}

	if (real_tx_hang) {
		ixgbe_tx_timeout_reset(adapter);
	} else {
		e_info(drv, "Fake Tx hang detected with timeout of %d "
			"seconds\n", netdev->watchdog_timeo/HZ);

		/* fake Tx hang - increase the kernel timeout */
		if (netdev->watchdog_timeo < TX_TIMEO_LIMIT)
			netdev->watchdog_timeo *= 2;
	}
}

/**
 * ixgbe_clean_tx_irq - Reclaim resources after transmit completes
 * @q_vector: structure containing interrupt and ring information
 * @tx_ring: tx ring to clean
 **/
static bool ixgbe_clean_tx_irq(struct ixgbe_q_vector *q_vector,
			       struct ixgbe_ring *tx_ring)
{
	struct ixgbe_adapter *adapter = q_vector->adapter;
	struct ixgbe_tx_buffer *tx_buffer;
	union ixgbe_adv_tx_desc *tx_desc;
	unsigned int total_bytes = 0, total_packets = 0;
	unsigned int budget = q_vector->tx.work_limit;
	unsigned int i = tx_ring->next_to_clean;

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled)
		return(true);
#endif

	if (test_bit(__IXGBE_DOWN, &adapter->state))
		return true;

	tx_buffer = &tx_ring->tx_buffer_info[i];
	tx_desc = IXGBE_TX_DESC(tx_ring, i);
	i -= tx_ring->count;

	do {
		union ixgbe_adv_tx_desc *eop_desc = tx_buffer->next_to_watch;

		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc)
			break;

		/* prevent any other reads prior to eop_desc */
		read_barrier_depends();

		/* if DD is not set pending work has not been completed */
		if (!(eop_desc->wb.status & cpu_to_le32(IXGBE_TXD_STAT_DD)))
			break;

		/* clear next_to_watch to prevent false hangs */
		tx_buffer->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buffer->bytecount;
		total_packets += tx_buffer->gso_segs;

		/* free the skb */
		dev_kfree_skb_any(tx_buffer->skb);

		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buffer, dma),
				 dma_unmap_len(tx_buffer, len),
				 DMA_TO_DEVICE);

		/* clear tx_buffer data */
		tx_buffer->skb = NULL;
		dma_unmap_len_set(tx_buffer, len, 0);

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			tx_buffer++;
			tx_desc++;
			i++;
			if (unlikely(!i)) {
				i -= tx_ring->count;
				tx_buffer = tx_ring->tx_buffer_info;
				tx_desc = IXGBE_TX_DESC(tx_ring, 0);
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
			tx_desc = IXGBE_TX_DESC(tx_ring, 0);
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

	if (check_for_tx_hang(tx_ring) && ixgbe_check_tx_hang(tx_ring)) {
		/* schedule immediate reset if we believe we hung */
		struct ixgbe_hw *hw = &adapter->hw;
		e_err(drv, "Detected Tx Unit Hang\n"
			"  Tx Queue             <%d>\n"
			"  TDH, TDT             <%x>, <%x>\n"
			"  next_to_use          <%x>\n"
			"  next_to_clean        <%x>\n",
			tx_ring->queue_index,
			IXGBE_READ_REG(hw, IXGBE_TDH(tx_ring->reg_idx)),
			IXGBE_READ_REG(hw, IXGBE_TDT(tx_ring->reg_idx)),
			tx_ring->next_to_use, i);
		e_err(drv, "tx_buffer_info[next_to_clean]\n"
			"  time_stamp           <%lx>\n"
			"  jiffies              <%lx>\n",
			tx_ring->tx_buffer_info[i].time_stamp, jiffies);

		netif_stop_subqueue(netdev_ring(tx_ring),
				    ring_queue_index(tx_ring));

		e_info(probe,
		       "tx hang %d detected on queue %d, resetting adapter\n",
		       adapter->tx_timeout_count + 1, tx_ring->queue_index);

		ixgbe_tx_timeout_reset(adapter);

		/* the adapter is about to reset, no point in enabling stuff */
		return true;
	}

	netdev_tx_completed_queue(netdev_get_tx_queue(tx_ring->netdev,
						      tx_ring->queue_index),
				  total_packets, total_bytes);

#define TX_WAKE_THRESHOLD (DESC_NEEDED * 2)
	if (unlikely(total_packets && netif_carrier_ok(netdev_ring(tx_ring)) &&
		     (ixgbe_desc_unused(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();
#ifdef HAVE_TX_MQ
		if (__netif_subqueue_stopped(netdev_ring(tx_ring),
					     ring_queue_index(tx_ring))
		    && !test_bit(__IXGBE_DOWN, &q_vector->adapter->state)) {
			netif_wake_subqueue(netdev_ring(tx_ring),
					    ring_queue_index(tx_ring));
			++tx_ring->tx_stats.restart_queue;
		}
#else
		if (netif_queue_stopped(netdev_ring(tx_ring)) &&
		    !test_bit(__IXGBE_DOWN, &q_vector->adapter->state)) {
			netif_wake_queue(netdev_ring(tx_ring));
			++tx_ring->tx_stats.restart_queue;
		}
#endif
	}

	return !!budget;
}

#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
static void ixgbe_update_tx_dca(struct ixgbe_adapter *adapter,
				struct ixgbe_ring *tx_ring,
				int cpu)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 txctrl = 0;
	u16 reg_offset;

	if (adapter->flags & IXGBE_FLAG_DCA_ENABLED)
		txctrl = dca3_get_tag(tx_ring->dev, cpu);

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		reg_offset = IXGBE_DCA_TXCTRL(tx_ring->reg_idx);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		reg_offset = IXGBE_DCA_TXCTRL_82599(tx_ring->reg_idx);
		txctrl <<= IXGBE_DCA_TXCTRL_CPUID_SHIFT_82599;
		break;
	default:
		/* for unknown hardware do not write register */
		return;
	}

	/*
	 * We can enable relaxed ordering for reads, but not writes when
	 * DCA is enabled.  This is due to a known issue in some chipsets
	 * which will cause the DCA tag to be cleared.
	 */
	txctrl |= IXGBE_DCA_TXCTRL_DESC_RRO_EN |
		  IXGBE_DCA_TXCTRL_DATA_RRO_EN |
		  IXGBE_DCA_TXCTRL_DESC_DCA_EN;

	IXGBE_WRITE_REG(hw, reg_offset, txctrl);
}

static void ixgbe_update_rx_dca(struct ixgbe_adapter *adapter,
				struct ixgbe_ring *rx_ring,
				int cpu)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 rxctrl = 0;
	u8 reg_idx = rx_ring->reg_idx;

#ifdef ENABLE_DNA
	//if(adapter->dna.dna_enabled)
	//if(unlikely(enable_debug))
	printk("[DNA] Setting DCA affinity for %s@%d to core %d\n", 
	       adapter->netdev->name, reg_idx, cpu);
#endif

	if (adapter->flags & IXGBE_FLAG_DCA_ENABLED)
		rxctrl = dca3_get_tag(rx_ring->dev, cpu);

	switch (hw->mac.type) {
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		rxctrl <<= IXGBE_DCA_RXCTRL_CPUID_SHIFT_82599;
		break;
	default:
		break;
	}

	/*
	 * We can enable relaxed ordering for reads, but not writes when
	 * DCA is enabled.  This is due to a known issue in some chipsets
	 * which will cause the DCA tag to be cleared.
	 */
	rxctrl |= IXGBE_DCA_RXCTRL_DESC_RRO_EN |
		  IXGBE_DCA_RXCTRL_DATA_DCA_EN |
		  IXGBE_DCA_RXCTRL_DESC_DCA_EN;

	IXGBE_WRITE_REG(hw, IXGBE_DCA_RXCTRL(reg_idx), rxctrl);
}

static void ixgbe_update_dca(struct ixgbe_q_vector *q_vector)
{
	struct ixgbe_adapter *adapter = q_vector->adapter;
	struct ixgbe_ring *ring;
	int cpu = get_cpu();
#ifdef ENABLE_DNA
	int selected_cpu;
	
	if(adapter->dna.dna_enabled) {
		selected_cpu = numa_cpu_affinity[adapter->bd_number];
		if (selected_cpu != -1)
			if (cpu_online(selected_cpu))
				cpu = selected_cpu;
	}
#endif

	if (q_vector->cpu == cpu)
		goto out_no_update;

	ixgbe_for_each_ring(ring, q_vector->tx)
		ixgbe_update_tx_dca(adapter, ring, cpu);

	ixgbe_for_each_ring(ring, q_vector->rx)
		ixgbe_update_rx_dca(adapter, ring, cpu);

	q_vector->cpu = cpu;
out_no_update:
	put_cpu();
}

static void ixgbe_setup_dca(struct ixgbe_adapter *adapter)
{
	int v_idx;

	/* always use CB2 mode, difference is masked in the CB driver */
	if (adapter->flags & IXGBE_FLAG_DCA_ENABLED)
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_DCA_CTRL,
				IXGBE_DCA_CTRL_DCA_MODE_CB2);
	else
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_DCA_CTRL,
				IXGBE_DCA_CTRL_DCA_DISABLE);

	for (v_idx = 0; v_idx < adapter->num_q_vectors; v_idx++) {
		adapter->q_vector[v_idx]->cpu = -1;
		ixgbe_update_dca(adapter->q_vector[v_idx]);
	}
}

static int __ixgbe_notify_dca(struct device *dev, void *data)
{
	struct ixgbe_adapter *adapter = dev_get_drvdata(dev);
	unsigned long event = *(unsigned long *)data;

	if (!(adapter->flags & IXGBE_FLAG_DCA_CAPABLE))
		return 0;

	switch (event) {
	case DCA_PROVIDER_ADD:
		/* if we're already enabled, don't do it again */
		if (adapter->flags & IXGBE_FLAG_DCA_ENABLED)
			break;
		if (dca_add_requester(dev) == 0) {
			adapter->flags |= IXGBE_FLAG_DCA_ENABLED;
			IXGBE_WRITE_REG(&adapter->hw, IXGBE_DCA_CTRL, 2);
#ifdef ENABLE_DNA
			printk("[DNA] DCA enabled on %s\n", adapter->netdev->name);
#endif
			break;
		}
		/* Fall Through since DCA is disabled. */
	case DCA_PROVIDER_REMOVE:
		if (adapter->flags & IXGBE_FLAG_DCA_ENABLED) {
			dca_remove_requester(dev);
			adapter->flags &= ~IXGBE_FLAG_DCA_ENABLED;
			IXGBE_WRITE_REG(&adapter->hw, IXGBE_DCA_CTRL, 1);
		}
		break;
	}

	return 0;
}

#endif /* CONFIG_DCA or CONFIG_DCA_MODULE */
#ifdef NETIF_F_RXHASH
#define IXGBE_RSS_L4_TYPES_MASK \
	((1ul << IXGBE_RXDADV_RSSTYPE_IPV4_TCP) | \
	 (1ul << IXGBE_RXDADV_RSSTYPE_IPV4_UDP) | \
	 (1ul << IXGBE_RXDADV_RSSTYPE_IPV6_TCP) | \
	 (1ul << IXGBE_RXDADV_RSSTYPE_IPV6_UDP) | \
	 (1ul << IXGBE_RXDADV_RSSTYPE_IPV6_TCP_EX) | \
	 (1ul << IXGBE_RXDADV_RSSTYPE_IPV6_UDP_EX))

static inline void ixgbe_rx_hash(struct ixgbe_ring *ring,
				 union ixgbe_adv_rx_desc *rx_desc,
				 struct sk_buff *skb)
{
	u16 rss_type; 

	if (!(netdev_ring(ring)->features & NETIF_F_RXHASH))
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
#ifdef IXGBE_FCOE
/**
 * ixgbe_rx_is_fcoe - check the rx desc for incoming pkt type
 * @ring: structure containing ring specific data
 * @rx_desc: advanced rx descriptor
 *
 * Returns : true if it is FCoE pkt
 */
static inline bool ixgbe_rx_is_fcoe(struct ixgbe_ring *ring,
				    union ixgbe_adv_rx_desc *rx_desc)
{
	__le16 pkt_info = rx_desc->wb.lower.lo_dword.hs_rss.pkt_info;

	return test_bit(__IXGBE_RX_FCOE, &ring->state) &&
	       ((pkt_info & cpu_to_le16(IXGBE_RXDADV_PKTTYPE_ETQF_MASK)) ==
		(cpu_to_le16(IXGBE_ETQF_FILTER_FCOE <<
			     IXGBE_RXDADV_PKTTYPE_ETQF_SHIFT)));
}

#endif /* IXGBE_FCOE */
/**
 * ixgbe_rx_checksum - indicate in skb if hw indicated a good cksum
 * @ring: structure containing ring specific data
 * @rx_desc: current Rx descriptor being processed
 * @skb: skb currently being received and modified
 **/
static inline void ixgbe_rx_checksum(struct ixgbe_ring *ring,
				     union ixgbe_adv_rx_desc *rx_desc,
				     struct sk_buff *skb)
{
	skb_checksum_none_assert(skb);

	/* Rx csum disabled */
	if (!(netdev_ring(ring)->features & NETIF_F_RXCSUM))
		return;

	/* if IP and error */
	if (ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_IPCS) &&
	    ixgbe_test_staterr(rx_desc, IXGBE_RXDADV_ERR_IPE)) {
		ring->rx_stats.csum_err++;
		return;
	}

	if (!ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_L4CS))
		return;

	if (ixgbe_test_staterr(rx_desc, IXGBE_RXDADV_ERR_TCPE)) {
		__le16 pkt_info = rx_desc->wb.lower.lo_dword.hs_rss.pkt_info;

		/*
		 * 82599 errata, UDP frames with a 0 checksum can be marked as
		 * checksum errors.
		 */
		if ((pkt_info & cpu_to_le16(IXGBE_RXDADV_PKTTYPE_UDP)) &&
		    test_bit(__IXGBE_RX_CSUM_UDP_ZERO_ERR, &ring->state))
			return;

		ring->rx_stats.csum_err++;
		return;
	}

	/* It must be a TCP or UDP packet with a valid checksum */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
}

static inline void ixgbe_release_rx_desc(struct ixgbe_ring *rx_ring, u32 val)
{
	rx_ring->next_to_use = val;
#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT

	/* update next to alloc since we have filled the ring */
	rx_ring->next_to_alloc = val;
#endif
	/*
	 * Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.  (Only
	 * applicable for weak-ordered memory model archs,
	 * such as IA-64).
	 */
	wmb();
	ixgbe_write_tail(rx_ring, val);
}

#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
static bool ixgbe_alloc_mapped_skb(struct ixgbe_ring *rx_ring,
				   struct ixgbe_rx_buffer *bi)
{
	struct sk_buff *skb = bi->skb;
	dma_addr_t dma = bi->dma;

	if (unlikely(dma))
		return true;

	if (likely(!skb)) {
		skb = netdev_alloc_skb_ip_align(netdev_ring(rx_ring),
						rx_ring->rx_buf_len);
		if (unlikely(!skb)) {
			rx_ring->rx_stats.alloc_rx_buff_failed++;
			return false;
		}

		bi->skb = skb;

	}

	dma = dma_map_single(rx_ring->dev, skb->data,
			     rx_ring->rx_buf_len, DMA_FROM_DEVICE);

	/*
	 * if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(rx_ring->dev, dma)) {
		dev_kfree_skb_any(skb);
		bi->skb = NULL;

		rx_ring->rx_stats.alloc_rx_buff_failed++;
		return false;
	}

	bi->dma = dma;
	return true;
}

#else
static bool ixgbe_alloc_mapped_page(struct ixgbe_ring *rx_ring,
				    struct ixgbe_rx_buffer *bi)
{
	struct page *page = bi->page;
	dma_addr_t dma = bi->dma;

	/* since we are recycling buffers we should seldom need to alloc */
	if (likely(dma))
		return true;

	/* alloc new page for storage */
	if (likely(!page)) {
		page = alloc_pages(GFP_ATOMIC | __GFP_COLD | __GFP_COMP,
				   ixgbe_rx_pg_order(rx_ring));
		if (unlikely(!page)) {
			rx_ring->rx_stats.alloc_rx_page_failed++;
			return false;
		}
		bi->page = page;
	}

	/* map page for use */
	dma = dma_map_page(rx_ring->dev, page, 0,
			   ixgbe_rx_pg_size(rx_ring), DMA_FROM_DEVICE);

	/*
	 * if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(rx_ring->dev, dma)) {
		__free_pages(page, ixgbe_rx_pg_order(rx_ring));
		bi->page = NULL;

		rx_ring->rx_stats.alloc_rx_page_failed++;
		return false;
	}

	bi->dma = dma;
	bi->page_offset = 0;

	return true;
}

#endif /* CONFIG_IXGBE_DISABLE_PACKET_SPLIT */
/**
 * ixgbe_alloc_rx_buffers - Replace used receive buffers
 * @rx_ring: ring to place buffers on
 * @cleaned_count: number of buffers to replace
 **/
void ixgbe_alloc_rx_buffers(struct ixgbe_ring *rx_ring, u16 cleaned_count)
{
	union ixgbe_adv_rx_desc *rx_desc;
	struct ixgbe_rx_buffer *bi;
	u16 i = rx_ring->next_to_use;
#ifdef ENABLE_DNA
	struct ixgbe_adapter *adapter = netdev_priv(rx_ring->netdev);

	if(adapter->dna.dna_enabled) {
		if(rx_ring->netdev)
			dna_ixgbe_alloc_rx_buffers(rx_ring);
		return;
	}
#endif

	/* nothing to do */
	if (!cleaned_count)
		return;

	rx_desc = IXGBE_RX_DESC(rx_ring, i);
	bi = &rx_ring->rx_buffer_info[i];
	i -= rx_ring->count;

	do {
#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
		if (!ixgbe_alloc_mapped_skb(rx_ring, bi))
#else
		if (!ixgbe_alloc_mapped_page(rx_ring, bi))
#endif
			break;

		/*
		 * Refresh the desc even if buffer_addrs didn't change
		 * because each write-back erases this info.
		 */
#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
		rx_desc->read.pkt_addr = cpu_to_le64(bi->dma);
#else
		rx_desc->read.pkt_addr = cpu_to_le64(bi->dma + bi->page_offset);
#endif

		rx_desc++;
		bi++;
		i++;
		if (unlikely(!i)) {
			rx_desc = IXGBE_RX_DESC(rx_ring, 0);
			bi = rx_ring->rx_buffer_info;
			i -= rx_ring->count;
		}

		/* clear the hdr_addr for the next_to_use descriptor */
		rx_desc->read.hdr_addr = 0;

		cleaned_count--;
	} while (cleaned_count);

	i += rx_ring->count;

	if (rx_ring->next_to_use != i)
		ixgbe_release_rx_desc(rx_ring, i);
}

#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
/**
 * ixgbe_merge_active_tail - merge active tail into lro skb
 * @tail: pointer to active tail in frag_list
 *
 * This function merges the length and data of an active tail into the
 * skb containing the frag_list.  It resets the tail's pointer to the head,
 * but it leaves the heads pointer to tail intact.
 **/
static inline struct sk_buff *ixgbe_merge_active_tail(struct sk_buff *tail)
{
	struct sk_buff *head = IXGBE_CB(tail)->head;

	if (!head)
		return tail;

	head->len += tail->len;
	head->data_len += tail->len;
	head->truesize += tail->truesize;

	IXGBE_CB(tail)->head = NULL;

	return head;
}

/**
 * ixgbe_add_active_tail - adds an active tail into the skb frag_list
 * @head: pointer to the start of the skb
 * @tail: pointer to active tail to add to frag_list
 *
 * This function adds an active tail to the end of the frag list.  This tail
 * will still be receiving data so we cannot yet ad it's stats to the main
 * skb.  That is done via ixgbe_merge_active_tail.
 **/
static inline void ixgbe_add_active_tail(struct sk_buff *head,
					 struct sk_buff *tail)
{
	struct sk_buff *old_tail = IXGBE_CB(head)->tail;

	if (old_tail) {
		ixgbe_merge_active_tail(old_tail);
		old_tail->next = tail;
	} else {
		skb_shinfo(head)->frag_list = tail;
	}

	IXGBE_CB(tail)->head = head;
	IXGBE_CB(head)->tail = tail;
}

/**
 * ixgbe_close_active_frag_list - cleanup pointers on a frag_list skb
 * @head: pointer to head of an active frag list
 *
 * This function will clear the frag_tail_tracker pointer on an active
 * frag_list and returns true if the pointer was actually set
 **/
static inline bool ixgbe_close_active_frag_list(struct sk_buff *head)
{
	struct sk_buff *tail = IXGBE_CB(head)->tail;

	if (!tail)
		return false;

	ixgbe_merge_active_tail(tail);

	IXGBE_CB(head)->tail = NULL;

	return true;
}

#endif
#ifdef HAVE_VLAN_RX_REGISTER
/**
 * ixgbe_receive_skb - Send a completed packet up the stack
 * @q_vector: structure containing interrupt and ring information
 * @skb: packet to send up
 **/
static void ixgbe_receive_skb(struct ixgbe_q_vector *q_vector,
			      struct sk_buff *skb)
{
	u16 vlan_tag = IXGBE_CB(skb)->vid;

#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	if (vlan_tag & VLAN_VID_MASK) {
		/* by placing vlgrp at start of structure we can alias it */
		struct vlan_group **vlgrp = netdev_priv(skb->dev);
		if (!*vlgrp)
			dev_kfree_skb_any(skb);
		else if (q_vector->netpoll_rx)
			vlan_hwaccel_rx(skb, *vlgrp, vlan_tag);
		else
			vlan_gro_receive(&q_vector->napi,
					 *vlgrp, vlan_tag, skb);
	} else {
#endif /* NETIF_F_HW_VLAN_TX || NETIF_F_HW_VLAN_CTAG_TX */
		if (q_vector->netpoll_rx)
			netif_rx(skb);
		else
			napi_gro_receive(&q_vector->napi, skb);
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	}
#endif /* NETIF_F_HW_VLAN_TX || NETIF_F_HW_VLAN_CTAG_TX */
}

#endif /* HAVE_VLAN_RX_REGISTER */
#ifndef IXGBE_NO_LRO
/**
 * ixgbe_can_lro - returns true if packet is TCP/IPV4 and LRO is enabled
 * @rx_ring: structure containing ring specific data
 * @rx_desc: pointer to the rx descriptor
 * @skb: pointer to the skb to be merged
 *
 **/
static inline bool ixgbe_can_lro(struct ixgbe_ring *rx_ring,
				 union ixgbe_adv_rx_desc *rx_desc,
				 struct sk_buff *skb)
{
	struct iphdr *iph = (struct iphdr *)skb->data;
	__le16 pkt_info = rx_desc->wb.lower.lo_dword.hs_rss.pkt_info;

	/* verify hardware indicates this is IPv4/TCP */
	if (!(pkt_info & cpu_to_le16(IXGBE_RXDADV_PKTTYPE_IPV4)) ||
	    !(pkt_info & cpu_to_le16(IXGBE_RXDADV_PKTTYPE_TCP)))
		return false;

	/* .. and RSC is not already enabled */
	if (ring_is_rsc_enabled(rx_ring))
		return false;

	/* .. and LRO is enabled */
	if (!(netdev_ring(rx_ring)->features & NETIF_F_LRO))
		return false;

	/* .. and we are not in promiscuous mode */
	if (netdev_ring(rx_ring)->flags & IFF_PROMISC)
		return false;

	/* .. and the header is large enough for us to read IP/TCP fields */
	if (!pskb_may_pull(skb, sizeof(struct ixgbe_lrohdr)))
		return false;

	/* .. and there are no VLANs on packet */
	if (skb->protocol != __constant_htons(ETH_P_IP))
		return false;

	/* .. and we are version 4 with no options */
	if (*(u8 *)iph != 0x45)
		return false;

	/* .. and the packet is not fragmented */
	if (iph->frag_off & htons(IP_MF | IP_OFFSET))
		return false;

	/* .. and that next header is TCP */
	if (iph->protocol != IPPROTO_TCP)
		return false;

	return true;
}

static inline struct ixgbe_lrohdr *ixgbe_lro_hdr(struct sk_buff *skb)
{
	return (struct ixgbe_lrohdr *)skb->data;
}

/**
 * ixgbe_lro_flush - Indicate packets to upper layer.
 *
 * Update IP and TCP header part of head skb if more than one
 * skb's chained and indicate packets to upper layer.
 **/
static void ixgbe_lro_flush(struct ixgbe_q_vector *q_vector,
			    struct sk_buff *skb)
{
	struct ixgbe_lro_list *lrolist = &q_vector->lrolist;

	__skb_unlink(skb, &lrolist->active);

	if (IXGBE_CB(skb)->append_cnt) {
		struct ixgbe_lrohdr *lroh = ixgbe_lro_hdr(skb);

#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
		/* close any active lro contexts */
		ixgbe_close_active_frag_list(skb);

#endif
		/* incorporate ip header and re-calculate checksum */
		lroh->iph.tot_len = ntohs(skb->len);
		lroh->iph.check = 0;

		/* header length is 5 since we know no options exist */
		lroh->iph.check = ip_fast_csum((u8 *)lroh, 5);

		/* clear TCP checksum to indicate we are an LRO frame */
		lroh->th.check = 0;

		/* incorporate latest timestamp into the tcp header */
		if (IXGBE_CB(skb)->tsecr) {
			lroh->ts[2] = IXGBE_CB(skb)->tsecr;
			lroh->ts[1] = htonl(IXGBE_CB(skb)->tsval);
		}
#ifdef NETIF_F_GSO

		skb_shinfo(skb)->gso_size = IXGBE_CB(skb)->mss;
		skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
#endif
	}

#ifdef HAVE_VLAN_RX_REGISTER
	ixgbe_receive_skb(q_vector, skb);
#else
	napi_gro_receive(&q_vector->napi, skb);
#endif
	lrolist->stats.flushed++;
}

static void ixgbe_lro_flush_all(struct ixgbe_q_vector *q_vector)
{
	struct ixgbe_lro_list *lrolist = &q_vector->lrolist;
	struct sk_buff *skb, *tmp;

	skb_queue_reverse_walk_safe(&lrolist->active, skb, tmp)
		ixgbe_lro_flush(q_vector, skb);
}

/*
 * ixgbe_lro_header_ok - Main LRO function.
 **/
static void ixgbe_lro_header_ok(struct sk_buff *skb)
{
	struct ixgbe_lrohdr *lroh = ixgbe_lro_hdr(skb);
	u16 opt_bytes, data_len;

#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
	IXGBE_CB(skb)->tail = NULL;
#endif
	IXGBE_CB(skb)->tsecr = 0;
	IXGBE_CB(skb)->append_cnt = 0;
	IXGBE_CB(skb)->mss = 0;

	/* ensure that the checksum is valid */
	if (skb->ip_summed != CHECKSUM_UNNECESSARY)
		return;

	/* If we see CE codepoint in IP header, packet is not mergeable */
	if (INET_ECN_is_ce(ipv4_get_dsfield(&lroh->iph)))
		return;

	/* ensure no bits set besides ack or psh */
	if (lroh->th.fin || lroh->th.syn || lroh->th.rst ||
	    lroh->th.urg || lroh->th.ece || lroh->th.cwr ||
	    !lroh->th.ack)
		return;

	/* store the total packet length */
	data_len = ntohs(lroh->iph.tot_len);

	/* remove any padding from the end of the skb */
	__pskb_trim(skb, data_len);

	/* remove header length from data length */
	data_len -= sizeof(struct ixgbe_lrohdr);

	/*
	 * check for timestamps. Since the only option we handle are timestamps,
	 * we only have to handle the simple case of aligned timestamps
	 */
	opt_bytes = (lroh->th.doff << 2) - sizeof(struct tcphdr);
	if (opt_bytes != 0) {
		if ((opt_bytes != TCPOLEN_TSTAMP_ALIGNED) ||
		    !pskb_may_pull(skb, sizeof(struct ixgbe_lrohdr) +
					TCPOLEN_TSTAMP_ALIGNED) ||
		    (lroh->ts[0] != htonl((TCPOPT_NOP << 24) |
					     (TCPOPT_NOP << 16) |
					     (TCPOPT_TIMESTAMP << 8) |
					      TCPOLEN_TIMESTAMP)) ||
		    (lroh->ts[2] == 0)) {
			return;
		}

		IXGBE_CB(skb)->tsval = ntohl(lroh->ts[1]);
		IXGBE_CB(skb)->tsecr = lroh->ts[2];

		data_len -= TCPOLEN_TSTAMP_ALIGNED;
	}

	/* record data_len as mss for the packet */
	IXGBE_CB(skb)->mss = data_len;
	IXGBE_CB(skb)->next_seq = ntohl(lroh->th.seq);
}

#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
static void ixgbe_merge_frags(struct sk_buff *lro_skb, struct sk_buff *new_skb)
{
	struct skb_shared_info *sh_info;
	struct skb_shared_info *new_skb_info;
	unsigned int data_len;

	sh_info = skb_shinfo(lro_skb);
	new_skb_info = skb_shinfo(new_skb);

	/* copy frags into the last skb */
	memcpy(sh_info->frags + sh_info->nr_frags,
	       new_skb_info->frags,
	       new_skb_info->nr_frags * sizeof(skb_frag_t));

	/* copy size data over */
	sh_info->nr_frags += new_skb_info->nr_frags;
	data_len = IXGBE_CB(new_skb)->mss;
	lro_skb->len += data_len;
	lro_skb->data_len += data_len;
	lro_skb->truesize += data_len;

	/* wipe record of data from new_skb and free it */
	new_skb_info->nr_frags = 0;
	new_skb->len = new_skb->data_len = 0;
	dev_kfree_skb_any(new_skb);
}

#endif /* CONFIG_IXGBE_DISABLE_PACKET_SPLIT */
/**
 * ixgbe_lro_receive - if able, queue skb into lro chain
 * @q_vector: structure containing interrupt and ring information
 * @new_skb: pointer to current skb being checked
 *
 * Checks whether the skb given is eligible for LRO and if that's
 * fine chains it to the existing lro_skb based on flowid. If an LRO for
 * the flow doesn't exist create one.
 **/
static void ixgbe_lro_receive(struct ixgbe_q_vector *q_vector,
			      struct sk_buff *new_skb)
{
	struct sk_buff *lro_skb;
	struct ixgbe_lro_list *lrolist = &q_vector->lrolist;
	struct ixgbe_lrohdr *lroh = ixgbe_lro_hdr(new_skb);
	__be32 saddr = lroh->iph.saddr;
	__be32 daddr = lroh->iph.daddr;
	__be32 tcp_ports = *(__be32 *)&lroh->th;
#ifdef HAVE_VLAN_RX_REGISTER
	u16 vid = IXGBE_CB(new_skb)->vid;
#else
	u16 vid = new_skb->vlan_tci;
#endif

	ixgbe_lro_header_ok(new_skb);

	/*
	 * we have a packet that might be eligible for LRO,
	 * so see if it matches anything we might expect
	 */
	skb_queue_walk(&lrolist->active, lro_skb) {
		u16 data_len;

		if (*(__be32 *)&ixgbe_lro_hdr(lro_skb)->th != tcp_ports ||
		    ixgbe_lro_hdr(lro_skb)->iph.saddr != saddr ||
		    ixgbe_lro_hdr(lro_skb)->iph.daddr != daddr)
			continue;

#ifdef HAVE_VLAN_RX_REGISTER
		if (IXGBE_CB(lro_skb)->vid != vid)
#else
		if (lro_skb->vlan_tci != vid)
#endif
			continue;

		/* out of order packet */
		if (IXGBE_CB(lro_skb)->next_seq !=
		    IXGBE_CB(new_skb)->next_seq) {
			ixgbe_lro_flush(q_vector, lro_skb);
			IXGBE_CB(new_skb)->mss = 0;
			break;
		}

		/* TCP timestamp options have changed */
		if (!IXGBE_CB(lro_skb)->tsecr != !IXGBE_CB(new_skb)->tsecr) {
			ixgbe_lro_flush(q_vector, lro_skb);
			break;
		}

		/* make sure timestamp values are increasing */
		if (IXGBE_CB(lro_skb)->tsecr &&
		    IXGBE_CB(lro_skb)->tsval > IXGBE_CB(new_skb)->tsval) {
			ixgbe_lro_flush(q_vector, lro_skb);
			IXGBE_CB(new_skb)->mss = 0;
			break;
		}

		data_len = IXGBE_CB(new_skb)->mss;

		/* Check for all of the above below
		 *   malformed header
		 *   no tcp data
		 *   resultant packet would be too large
		 *   new skb is larger than our current mss
		 *   data would remain in header
		 *   we would consume more frags then the sk_buff contains
		 *   ack sequence numbers changed
		 *   window size has changed
		 */
		if (data_len == 0 ||
		    data_len > IXGBE_CB(lro_skb)->mss ||
		    data_len > IXGBE_CB(lro_skb)->free ||
#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
		    data_len != new_skb->data_len ||
		    skb_shinfo(new_skb)->nr_frags >=
		    (MAX_SKB_FRAGS - skb_shinfo(lro_skb)->nr_frags) ||
#endif
		    ixgbe_lro_hdr(lro_skb)->th.ack_seq != lroh->th.ack_seq ||
		    ixgbe_lro_hdr(lro_skb)->th.window != lroh->th.window) {
			ixgbe_lro_flush(q_vector, lro_skb);
			break;
		}

		/* Remove IP and TCP header */
		skb_pull(new_skb, new_skb->len - data_len);

		/* update timestamp and timestamp echo response */
		IXGBE_CB(lro_skb)->tsval = IXGBE_CB(new_skb)->tsval;
		IXGBE_CB(lro_skb)->tsecr = IXGBE_CB(new_skb)->tsecr;

		/* update sequence and free space */
		IXGBE_CB(lro_skb)->next_seq += data_len;
		IXGBE_CB(lro_skb)->free -= data_len;

		/* update append_cnt */
		IXGBE_CB(lro_skb)->append_cnt++;

#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
		/* if header is empty pull pages into current skb */
		ixgbe_merge_frags(lro_skb, new_skb);
#else
		/* chain this new skb in frag_list */
		ixgbe_add_active_tail(lro_skb, new_skb);
#endif

		if ((data_len < IXGBE_CB(lro_skb)->mss) || lroh->th.psh ||
		    skb_shinfo(lro_skb)->nr_frags == MAX_SKB_FRAGS) {
			ixgbe_lro_hdr(lro_skb)->th.psh |= lroh->th.psh;
			ixgbe_lro_flush(q_vector, lro_skb);
		}

		lrolist->stats.coal++;
		return;
	}

	if (IXGBE_CB(new_skb)->mss && !lroh->th.psh) {
		/* if we are at capacity flush the tail */
		if (skb_queue_len(&lrolist->active) >= IXGBE_LRO_MAX) {
			lro_skb = skb_peek_tail(&lrolist->active);
			if (lro_skb)
				ixgbe_lro_flush(q_vector, lro_skb);
		}

		/* update sequence and free space */
		IXGBE_CB(new_skb)->next_seq += IXGBE_CB(new_skb)->mss;
		IXGBE_CB(new_skb)->free = 65521 - new_skb->len;

		/* .. and insert at the front of the active list */
		__skb_queue_head(&lrolist->active, new_skb);

		lrolist->stats.coal++;
		return;
	}

	/* packet not handled by any of the above, pass it to the stack */
#ifdef HAVE_VLAN_RX_REGISTER
	ixgbe_receive_skb(q_vector, new_skb);
#else
	napi_gro_receive(&q_vector->napi, new_skb);
#endif /* HAVE_VLAN_RX_REGISTER */
}

#endif /* IXGBE_NO_LRO */
#if !defined(CONFIG_IXGBE_DISABLE_PACKET_SPLIT) || defined(NETIF_F_GSO)
/**
 * ixgbe_get_headlen - determine size of header for RSC/LRO/GRO/FCOE
 * @data: pointer to the start of the headers
 * @max_len: total length of section to find headers in
 *
 * This function is meant to determine the length of headers that will
 * be recognized by hardware for LRO, GRO, and RSC offloads.  The main
 * motivation of doing this is to only perform one pull for IPv4 TCP
 * packets so that we can do basic things like calculating the gso_size
 * based on the average data per packet.
 **/
static unsigned int ixgbe_get_headlen(unsigned char *data,
				      unsigned int max_len)
{
	union {
		unsigned char *network;
		/* l2 headers */
		struct ethhdr *eth;
		struct vlan_hdr *vlan;
		/* l3 headers */
		struct iphdr *ipv4;
		struct ipv6hdr *ipv6;
	} hdr;
	__be16 protocol;
	u8 nexthdr = 0;	/* default to not TCP */
	u8 hlen;

	/* this should never happen, but better safe than sorry */
	if (max_len < ETH_HLEN)
		return max_len;

	/* initialize network frame pointer */
	hdr.network = data;

	/* set first protocol and move network header forward */
	protocol = hdr.eth->h_proto;
	hdr.network += ETH_HLEN;

	/* handle any vlan tag if present */
	if (protocol == __constant_htons(ETH_P_8021Q)) {
		if ((hdr.network - data) > (max_len - VLAN_HLEN))
			return max_len;

		protocol = hdr.vlan->h_vlan_encapsulated_proto;
		hdr.network += VLAN_HLEN;
	}

	/* handle L3 protocols */
	if (protocol == __constant_htons(ETH_P_IP)) {
		if ((hdr.network - data) > (max_len - sizeof(struct iphdr)))
			return max_len;

		/* access ihl as a u8 to avoid unaligned access on ia64 */
		hlen = (hdr.network[0] & 0x0F) << 2;

		/* verify hlen meets minimum size requirements */
		if (hlen < sizeof(struct iphdr))
			return hdr.network - data;

		/* record next protocol if header is present */
		if (!(hdr.ipv4->frag_off & htons(IP_OFFSET)))
			nexthdr = hdr.ipv4->protocol;
#ifdef NETIF_F_TSO6
	} else if (protocol == __constant_htons(ETH_P_IPV6)) {
		if ((hdr.network - data) > (max_len - sizeof(struct ipv6hdr)))
			return max_len;

		/* record next protocol */
		nexthdr = hdr.ipv6->nexthdr;
		hlen = sizeof(struct ipv6hdr);
#endif /* NETIF_F_TSO6 */
#ifdef IXGBE_FCOE
	} else if (protocol == __constant_htons(ETH_P_FCOE)) {
		if ((hdr.network - data) > (max_len - FCOE_HEADER_LEN))
			return max_len;
		hlen = FCOE_HEADER_LEN;
#endif
	} else {
		return hdr.network - data;
	}

	/* relocate pointer to start of L4 header */
	hdr.network += hlen;

	/* finally sort out TCP/UDP */
	if (nexthdr == IPPROTO_TCP) {
		if ((hdr.network - data) > (max_len - sizeof(struct tcphdr)))
			return max_len;

		/* access doff as a u8 to avoid unaligned access on ia64 */
		hlen = (hdr.network[12] & 0xF0) >> 2;

		/* verify hlen meets minimum size requirements */
		if (hlen < sizeof(struct tcphdr))
			return hdr.network - data;

		hdr.network += hlen;
	} else if (nexthdr == IPPROTO_UDP) {
		if ((hdr.network - data) > (max_len - sizeof(struct udphdr)))
			return max_len;

		hdr.network += sizeof(struct udphdr);
	}

	/*
	 * If everything has gone correctly hdr.network should be the
	 * data section of the packet and will be the end of the header.
	 * If not then it probably represents the end of the last recognized
	 * header.
	 */
	if ((hdr.network - data) < max_len)
		return hdr.network - data;
	else
		return max_len;
}

#endif /* !CONFIG_IXGBE_DISABLE_PACKET_SPLIT || NETIF_F_GSO */
#ifdef NETIF_F_GSO
static void ixgbe_set_rsc_gso_size(struct ixgbe_ring *ring,
				   struct sk_buff *skb)
{
#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
	u16 hdr_len = skb_headlen(skb);
#else
	u16 hdr_len = ixgbe_get_headlen(skb->data, skb_headlen(skb));
#endif

	/* set gso_size to avoid messing up TCP MSS */
	skb_shinfo(skb)->gso_size = DIV_ROUND_UP((skb->len - hdr_len),
						 IXGBE_CB(skb)->append_cnt);
	skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
}

#endif /* NETIF_F_GSO */
static void ixgbe_update_rsc_stats(struct ixgbe_ring *rx_ring,
				   struct sk_buff *skb)
{
	/* if append_cnt is 0 then frame is not RSC */
	if (!IXGBE_CB(skb)->append_cnt)
		return;

	rx_ring->rx_stats.rsc_count += IXGBE_CB(skb)->append_cnt;
	rx_ring->rx_stats.rsc_flush++;

#ifdef NETIF_F_GSO
	ixgbe_set_rsc_gso_size(rx_ring, skb);

#endif
	/* gso_size is computed using append_cnt so always clear it last */
	IXGBE_CB(skb)->append_cnt = 0;
}

static void ixgbe_rx_vlan(struct ixgbe_ring *ring,
			  union ixgbe_adv_rx_desc *rx_desc,
			  struct sk_buff *skb)
{
#ifdef NETIF_F_HW_VLAN_CTAG_RX
	if ((netdev_ring(ring)->features & NETIF_F_HW_VLAN_CTAG_RX) &&
#else
	if ((netdev_ring(ring)->features & NETIF_F_HW_VLAN_RX) &&
#endif
	    ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_VP))
#ifndef HAVE_VLAN_RX_REGISTER
		__vlan_hwaccel_put_tag(skb,
				       htons(ETH_P_8021Q),
				       le16_to_cpu(rx_desc->wb.upper.vlan));
#else
		IXGBE_CB(skb)->vid = le16_to_cpu(rx_desc->wb.upper.vlan);
	else
		IXGBE_CB(skb)->vid = 0;
#endif
}

/**
 * ixgbe_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being populated
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the hash, checksum, VLAN, timestamp, protocol, and
 * other fields within the skb.
 **/
static void ixgbe_process_skb_fields(struct ixgbe_ring *rx_ring,
				     union ixgbe_adv_rx_desc *rx_desc,
				     struct sk_buff *skb)
{
#ifdef HAVE_PTP_1588_CLOCK
	u32 flags = rx_ring->q_vector->adapter->flags;

#endif
	ixgbe_update_rsc_stats(rx_ring, skb);

#ifdef NETIF_F_RXHASH
	ixgbe_rx_hash(rx_ring, rx_desc, skb);

#endif /* NETIF_F_RXHASH */
	ixgbe_rx_checksum(rx_ring, rx_desc, skb);
#ifdef HAVE_PTP_1588_CLOCK
	if (unlikely(flags & IXGBE_FLAG_RX_HWTSTAMP_ENABLED))
		ixgbe_ptp_rx_hwtstamp(rx_ring, rx_desc, skb);

#endif
	ixgbe_rx_vlan(rx_ring, rx_desc, skb);

	skb_record_rx_queue(skb, ring_queue_index(rx_ring));

	skb->protocol = eth_type_trans(skb, netdev_ring(rx_ring));
}

static void ixgbe_rx_skb(struct ixgbe_q_vector *q_vector,
			 struct ixgbe_ring *rx_ring,
			 union ixgbe_adv_rx_desc *rx_desc,
			 struct sk_buff *skb)
{
#ifdef CONFIG_NET_RX_BUSY_POLL
	skb_mark_napi_id(skb, &q_vector->napi);

	if (ixgbe_qv_busy_polling(q_vector) || q_vector->netpoll_rx) {
		netif_receive_skb(skb);
		/* exit early if we busy polled */
		return;
	}
#endif

#ifndef IXGBE_NO_LRO
	if (ixgbe_can_lro(rx_ring, rx_desc, skb))
		ixgbe_lro_receive(q_vector, skb);
	else
#endif
#ifdef HAVE_VLAN_RX_REGISTER
		ixgbe_receive_skb(q_vector, skb);
#else
		napi_gro_receive(&q_vector->napi, skb);
#endif
#ifndef NETIF_F_GRO

	netdev_ring(rx_ring)->last_rx = jiffies;
#endif
}

/**
 * ixgbe_is_non_eop - process handling of non-EOP buffers
 * @rx_ring: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 * @skb: Current socket buffer containing buffer in progress
 *
 * This function updates next to clean.  If the buffer is an EOP buffer
 * this function exits returning false, otherwise it will place the
 * sk_buff in the next buffer to be chained and return true indicating
 * that this is in fact a non-EOP buffer.
 **/
static bool ixgbe_is_non_eop(struct ixgbe_ring *rx_ring,
			     union ixgbe_adv_rx_desc *rx_desc,
			     struct sk_buff *skb)
{
#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
	struct sk_buff *next_skb;
#endif
	u32 ntc = rx_ring->next_to_clean + 1;

	/* fetch, update, and store next to clean */
	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;

	prefetch(IXGBE_RX_DESC(rx_ring, ntc));

	/* update RSC append count if present */
	if (ring_is_rsc_enabled(rx_ring)) {
		__le32 rsc_enabled = rx_desc->wb.lower.lo_dword.data &
				     cpu_to_le32(IXGBE_RXDADV_RSCCNT_MASK);

		if (unlikely(rsc_enabled)) {
			u32 rsc_cnt = le32_to_cpu(rsc_enabled);

			rsc_cnt >>= IXGBE_RXDADV_RSCCNT_SHIFT;
			IXGBE_CB(skb)->append_cnt += rsc_cnt - 1;

			/* update ntc based on RSC value */
			ntc = le32_to_cpu(rx_desc->wb.upper.status_error);
			ntc &= IXGBE_RXDADV_NEXTP_MASK;
			ntc >>= IXGBE_RXDADV_NEXTP_SHIFT;
		}
	}

	/* if we are the last buffer then there is nothing else to do */
	if (likely(ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_EOP)))
		return false;

	/* place skb in next buffer to be received */
#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
	next_skb = rx_ring->rx_buffer_info[ntc].skb;

	ixgbe_add_active_tail(skb, next_skb);
	IXGBE_CB(next_skb)->head = skb;
#else
	rx_ring->rx_buffer_info[ntc].skb = skb;
#endif
	rx_ring->rx_stats.non_eop_descs++;

	return true;
}

#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
/**
 * ixgbe_pull_tail - ixgbe specific version of skb_pull_tail
 * @skb: pointer to current skb being adjusted
 *
 * This function is an ixgbe specific version of __pskb_pull_tail.  The
 * main difference between this version and the original function is that
 * this function can make several assumptions about the state of things
 * that allow for significant optimizations versus the standard function.
 * As a result we can do things like drop a frag and maintain an accurate
 * truesize for the skb.
 */
static void ixgbe_pull_tail(struct sk_buff *skb)
{
	struct skb_frag_struct *frag = &skb_shinfo(skb)->frags[0];
	unsigned char *va;
	unsigned int pull_len;

	/*
	 * it is valid to use page_address instead of kmap since we are
	 * working with pages allocated out of the lomem pool per
	 * alloc_page(GFP_ATOMIC)
	 */
	va = skb_frag_address(frag);

	/*
	 * we need the header to contain the greater of either ETH_HLEN or
	 * 60 bytes if the skb->len is less than 60 for skb_pad.
	 */
	pull_len = ixgbe_get_headlen(va, IXGBE_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	skb_copy_to_linear_data(skb, va, ALIGN(pull_len, sizeof(long)));

	/* update all of the pointers */
	skb_frag_size_sub(frag, pull_len);
	frag->page_offset += pull_len;
	skb->data_len -= pull_len;
	skb->tail += pull_len;
}

/**
 * ixgbe_dma_sync_frag - perform DMA sync for first frag of SKB
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @skb: pointer to current skb being updated
 *
 * This function provides a basic DMA sync up for the first fragment of an
 * skb.  The reason for doing this is that the first fragment cannot be
 * unmapped until we have reached the end of packet descriptor for a buffer
 * chain.
 */
static void ixgbe_dma_sync_frag(struct ixgbe_ring *rx_ring,
				struct sk_buff *skb)
{
	/* if the page was released unmap it, else just sync our portion */
	if (unlikely(IXGBE_CB(skb)->page_released)) {
		dma_unmap_page(rx_ring->dev, IXGBE_CB(skb)->dma,
			       ixgbe_rx_pg_size(rx_ring), DMA_FROM_DEVICE);
		IXGBE_CB(skb)->page_released = false;
	} else {
		dma_sync_single_range_for_cpu(rx_ring->dev,
					  IXGBE_CB(skb)->dma,
					  skb_shinfo(skb)->frags[0].page_offset,
					  ixgbe_rx_bufsz(rx_ring),
					  DMA_FROM_DEVICE);
	}
	IXGBE_CB(skb)->dma = 0;
}

/**
 * ixgbe_cleanup_headers - Correct corrupted or empty headers
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
 **/
static bool ixgbe_cleanup_headers(struct ixgbe_ring *rx_ring,
				  union ixgbe_adv_rx_desc *rx_desc,
				  struct sk_buff *skb)
{
	/* verify that the packet does not have any known errors */
	if (unlikely(ixgbe_test_staterr(rx_desc,
					IXGBE_RXDADV_ERR_FRAME_ERR_MASK))) {
		dev_kfree_skb_any(skb);
		return true;
	}

	/* place header in linear portion of buffer */
	if (skb_is_nonlinear(skb))
		ixgbe_pull_tail(skb);

#ifdef IXGBE_FCOE
	/* do not attempt to pad FCoE Frames as this will disrupt DDP */
	if (ixgbe_rx_is_fcoe(rx_ring, rx_desc))
		return false;

#endif
	/* if skb_pad returns an error the skb was freed */
	if (unlikely(skb->len < 60)) {
		int pad_len = 60 - skb->len;

		if (skb_pad(skb, pad_len))
			return true;
		__skb_put(skb, pad_len);
	}

	return false;
}

/**
 * ixgbe_reuse_rx_page - page flip buffer and store it back on the ring
 * @rx_ring: rx descriptor ring to store buffers on
 * @old_buff: donor buffer to have page reused
 *
 * Synchronizes page for reuse by the adapter
 **/
static void ixgbe_reuse_rx_page(struct ixgbe_ring *rx_ring,
				struct ixgbe_rx_buffer *old_buff)
{
	struct ixgbe_rx_buffer *new_buff;
	u16 nta = rx_ring->next_to_alloc;

	new_buff = &rx_ring->rx_buffer_info[nta];

	/* update, and store next to alloc */
	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	/* transfer page from old buffer to new buffer */
	new_buff->page = old_buff->page;
	new_buff->dma = old_buff->dma;
	new_buff->page_offset = old_buff->page_offset;

	/* sync the buffer for use by the device */
	dma_sync_single_range_for_device(rx_ring->dev, new_buff->dma,
					 new_buff->page_offset,
					 ixgbe_rx_bufsz(rx_ring),
					 DMA_FROM_DEVICE);
}

static bool ixgbe_can_reuse_rx_page(struct ixgbe_ring *rx_ring,
				    struct ixgbe_rx_buffer *rx_buffer,
				    struct page *page,
				    unsigned int truesize)
{
#if (PAGE_SIZE >= 8192)
	unsigned int last_offset = ixgbe_rx_pg_size(rx_ring) -
				   ixgbe_rx_bufsz(rx_ring);

#endif
	/* avoid re-using remote pages */
	if (unlikely(page_to_nid(page) != numa_node_id()))
		return false;

#if (PAGE_SIZE < 8192)
	/* if we are only owner of page we can reuse it */
	if (unlikely(page_count(page) != 1))
		return false;

	/* flip page offset to other buffer */
	rx_buffer->page_offset ^= truesize;

#else
	/* move offset up to the next cache line */
	rx_buffer->page_offset += truesize;

	if (rx_buffer->page_offset > last_offset)
		return false;
#endif

	/* bump ref count on page before it is given to the stack */
	get_page(page);

	return true;
}

/**
 * ixgbe_add_rx_frag - Add contents of Rx buffer to sk_buff
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: buffer containing page to add
 * @rx_desc: descriptor containing length of buffer written by hardware
 * @skb: sk_buff to place the data into
 *
 * This function will add the data contained in rx_buffer->page to the skb.
 * This is done either through a direct copy if the data in the buffer is
 * less than the skb header size, otherwise it will just attach the page as
 * a frag to the skb.
 *
 * The function will then update the page offset if necessary and return
 * true if the buffer can be reused by the adapter.
 **/
static bool ixgbe_add_rx_frag(struct ixgbe_ring *rx_ring,
			      struct ixgbe_rx_buffer *rx_buffer,
			      union ixgbe_adv_rx_desc *rx_desc,
			      struct sk_buff *skb)
{
	struct page *page = rx_buffer->page;
	unsigned int size = le16_to_cpu(rx_desc->wb.upper.length);
#if (PAGE_SIZE < 8192)
	unsigned int truesize = ixgbe_rx_bufsz(rx_ring);
#else
	unsigned int truesize = ALIGN(size, L1_CACHE_BYTES);
#endif

	if ((size <= IXGBE_RX_HDR_SIZE) && !skb_is_nonlinear(skb)) {
		unsigned char *va = page_address(page) + rx_buffer->page_offset;

		memcpy(__skb_put(skb, size), va, ALIGN(size, sizeof(long)));

		/* we can reuse buffer as-is, just make sure it is local */
		if (likely(page_to_nid(page) == numa_node_id()))
			return true;

		/* this page cannot be reused so discard it */
		put_page(page);
		return false;
	}

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page,
			rx_buffer->page_offset, size, truesize);

	return ixgbe_can_reuse_rx_page(rx_ring, rx_buffer, page, truesize);
}

static struct sk_buff *ixgbe_fetch_rx_buffer(struct ixgbe_ring *rx_ring,
					     union ixgbe_adv_rx_desc *rx_desc)
{
	struct ixgbe_rx_buffer *rx_buffer;
	struct sk_buff *skb;
	struct page *page;

	rx_buffer = &rx_ring->rx_buffer_info[rx_ring->next_to_clean];
	page = rx_buffer->page;
	prefetchw(page);

	skb = rx_buffer->skb;

	if (likely(!skb)) {
		void *page_addr = page_address(page) +
				  rx_buffer->page_offset;

		/* prefetch first cache line of first page */
		prefetch(page_addr);
#if L1_CACHE_BYTES < 128
		prefetch(page_addr + L1_CACHE_BYTES);
#endif

		/* allocate a skb to store the frags */
		skb = netdev_alloc_skb_ip_align(netdev_ring(rx_ring),
						IXGBE_RX_HDR_SIZE);
		if (unlikely(!skb)) {
			rx_ring->rx_stats.alloc_rx_buff_failed++;
			return NULL;
		}

		/*
		 * we will be copying header into skb->data in
		 * pskb_may_pull so it is in our interest to prefetch
		 * it now to avoid a possible cache miss
		 */
		prefetchw(skb->data);

		/*
		 * Delay unmapping of the first packet. It carries the
		 * header information, HW may still access the header
		 * after the writeback.  Only unmap it when EOP is
		 * reached
		 */
		if (likely(ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_EOP)))
			goto dma_sync;

		IXGBE_CB(skb)->dma = rx_buffer->dma;
	} else {
		if (ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_EOP))
			ixgbe_dma_sync_frag(rx_ring, skb);

dma_sync:
		/* we are reusing so sync this buffer for CPU use */
		dma_sync_single_range_for_cpu(rx_ring->dev,
					      rx_buffer->dma,
					      rx_buffer->page_offset,
					      ixgbe_rx_bufsz(rx_ring),
					      DMA_FROM_DEVICE);
	}

	/* pull page into skb */
	if (ixgbe_add_rx_frag(rx_ring, rx_buffer, rx_desc, skb)) {
		/* hand second half of page back to the ring */
		ixgbe_reuse_rx_page(rx_ring, rx_buffer);
	} else if (IXGBE_CB(skb)->dma == rx_buffer->dma) {
		/* the page has been released from the ring */
		IXGBE_CB(skb)->page_released = true;
	} else {
		/* we are not reusing the buffer so unmap it */
		dma_unmap_page(rx_ring->dev, rx_buffer->dma,
			       ixgbe_rx_pg_size(rx_ring),
			       DMA_FROM_DEVICE);
	}

	/* clear contents of buffer_info */
	rx_buffer->skb = NULL;
	rx_buffer->dma = 0;
	rx_buffer->page = NULL;

	return skb;
}

/**
 * ixgbe_clean_rx_irq - Clean completed descriptors from Rx ring - bounce buf
 * @q_vector: structure containing interrupt and ring information
 * @rx_ring: rx descriptor ring to transact packets on
 * @budget: Total limit on number of packets to process
 *
 * This function provides a "bounce buffer" approach to Rx interrupt
 * processing.  The advantage to this is that on systems that have
 * expensive overhead for IOMMU access this provides a means of avoiding
 * it by maintaining the mapping of the page to the syste.
 *
 * Returns amount of work completed.
 **/
static int ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector,
			       struct ixgbe_ring *rx_ring,
			       int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
#ifdef IXGBE_FCOE
	int ddp_bytes = 0;
#endif /* IXGBE_FCOE */
	u16 cleaned_count = ixgbe_desc_unused(rx_ring);
#ifdef ENABLE_DNA
	struct ixgbe_adapter *adapter = q_vector->adapter;
	if(adapter->dna.dna_enabled)
		return(dna_ixgbe_clean_rx_irq(q_vector, rx_ring, budget));
#endif

	do {
		union ixgbe_adv_rx_desc *rx_desc;
		struct sk_buff *skb;

		/* return some buffers to hardware, one at a time is too slow */
		if (cleaned_count >= IXGBE_RX_BUFFER_WRITE) {
			ixgbe_alloc_rx_buffers(rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		rx_desc = IXGBE_RX_DESC(rx_ring, rx_ring->next_to_clean);

		if (!ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_DD))
			break;

		/*
		 * This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * RXD_STAT_DD bit is set
		 */
		rmb();

		/* retrieve a buffer from the ring */
		skb = ixgbe_fetch_rx_buffer(rx_ring, rx_desc);

		/* exit if we failed to retrieve a buffer */
		if (!skb)
			break;

		cleaned_count++;

		/* place incomplete frames back on ring for completion */
		if (ixgbe_is_non_eop(rx_ring, rx_desc, skb))
			continue;

		/* verify the packet layout is correct */
		if (ixgbe_cleanup_headers(rx_ring, rx_desc, skb))
			continue;

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* populate checksum, timestamp, VLAN, and protocol */
		ixgbe_process_skb_fields(rx_ring, rx_desc, skb);

#ifdef IXGBE_FCOE
		/* if ddp, not passing to ULD unless for FCP_RSP or error */
		if (ixgbe_rx_is_fcoe(rx_ring, rx_desc)) {
			ddp_bytes = ixgbe_fcoe_ddp(q_vector->adapter,
						   rx_desc, skb);
			if (!ddp_bytes) {
				dev_kfree_skb_any(skb);
#ifndef NETIF_F_GRO
				netdev_ring(rx_ring)->last_rx = jiffies;
#endif
				continue;
			}
		}

#endif /* IXGBE_FCOE */
		ixgbe_rx_skb(q_vector, rx_ring, rx_desc, skb);

		/* update budget accounting */
		total_rx_packets++;
	} while (likely(total_rx_packets < budget));

#ifdef IXGBE_FCOE
	/* include DDPed FCoE data */
	if (ddp_bytes > 0) {
		unsigned int mss;

		mss = netdev_ring(rx_ring)->mtu - sizeof(struct fcoe_hdr) -
			sizeof(struct fc_frame_header) -
			sizeof(struct fcoe_crc_eof);
		if (mss > 512)
			mss &= ~511;
		total_rx_bytes += ddp_bytes;
		total_rx_packets += DIV_ROUND_UP(ddp_bytes, mss);
	}

#endif /* IXGBE_FCOE */
	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->stats.packets += total_rx_packets;
	rx_ring->stats.bytes += total_rx_bytes;
	u64_stats_update_end(&rx_ring->syncp);
	q_vector->rx.total_packets += total_rx_packets;
	q_vector->rx.total_bytes += total_rx_bytes;
	q_vector->netpoll_rx = false;

	if (cleaned_count)
		ixgbe_alloc_rx_buffers(rx_ring, cleaned_count);

#ifndef IXGBE_NO_LRO
	ixgbe_lro_flush_all(q_vector);

#endif /* IXGBE_NO_LRO */
	return total_rx_packets;
}

#else /* CONFIG_IXGBE_DISABLE_PACKET_SPLIT */
/**
 * ixgbe_clean_rx_irq - Clean completed descriptors from Rx ring - legacy
 * @q_vector: structure containing interrupt and ring information
 * @rx_ring: rx descriptor ring to transact packets on
 * @budget: Total limit on number of packets to process
 *
 * This function provides a legacy approach to Rx interrupt
 * handling.  This version will perform better on systems with a low cost
 * dma mapping API.
 *
 * Returns amount of work completed.
 **/
static int ixgbe_clean_rx_irq(struct ixgbe_q_vector *q_vector,
			       struct ixgbe_ring *rx_ring,
			       int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
#ifdef IXGBE_FCOE
	int ddp_bytes = 0;
#endif /* IXGBE_FCOE */
	u16 len = 0;
	u16 cleaned_count = ixgbe_desc_unused(rx_ring);
#ifdef ENABLE_DNA	
	struct ixgbe_adapter *adapter = q_vector->adapter;
	if(adapter->dna.dna_enabled)
		return(dna_ixgbe_clean_rx_irq(q_vector, rx_ring, budget));
#endif

	do {
		struct ixgbe_rx_buffer *rx_buffer;
		union ixgbe_adv_rx_desc *rx_desc;
		struct sk_buff *skb;
		u16 ntc;

		/* return some buffers to hardware, one at a time is too slow */
		if (cleaned_count >= IXGBE_RX_BUFFER_WRITE) {
			ixgbe_alloc_rx_buffers(rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		ntc = rx_ring->next_to_clean;
		rx_desc = IXGBE_RX_DESC(rx_ring, ntc);
		rx_buffer = &rx_ring->rx_buffer_info[ntc];

		if (!ixgbe_test_staterr(rx_desc, IXGBE_RXD_STAT_DD))
			break;

		/*
		 * This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we know the
		 * RXD_STAT_DD bit is set
		 */
		rmb();

		skb = rx_buffer->skb;

		prefetch(skb->data);

		len = le16_to_cpu(rx_desc->wb.upper.length);
		/* pull the header of the skb in */
		__skb_put(skb, len);

		/*
		 * Delay unmapping of the first packet. It carries the
		 * header information, HW may still access the header after
		 * the writeback.  Only unmap it when EOP is reached
		 */
		if (!IXGBE_CB(skb)->head) {
			IXGBE_CB(skb)->dma = rx_buffer->dma;
		} else {
			skb = ixgbe_merge_active_tail(skb);
			dma_unmap_single(rx_ring->dev,
					 rx_buffer->dma,
					 rx_ring->rx_buf_len,
					 DMA_FROM_DEVICE);
		}

		/* clear skb reference in buffer info structure */
		rx_buffer->skb = NULL;
		rx_buffer->dma = 0;

		cleaned_count++;

		if (ixgbe_is_non_eop(rx_ring, rx_desc, skb))
			continue;

		dma_unmap_single(rx_ring->dev,
				 IXGBE_CB(skb)->dma,
				 rx_ring->rx_buf_len,
				 DMA_FROM_DEVICE);

		IXGBE_CB(skb)->dma = 0;

		if (ixgbe_close_active_frag_list(skb) &&
		    !IXGBE_CB(skb)->append_cnt) {
			/* if we got here without RSC the packet is invalid */
			dev_kfree_skb_any(skb);
			continue;
		}

		/* ERR_MASK will only have valid bits if EOP set */
		if (unlikely(ixgbe_test_staterr(rx_desc,
					   IXGBE_RXDADV_ERR_FRAME_ERR_MASK))) {
			dev_kfree_skb_any(skb);
			continue;
		}

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* populate checksum, timestamp, VLAN, and protocol */
		ixgbe_process_skb_fields(rx_ring, rx_desc, skb);

#ifdef IXGBE_FCOE
		/* if ddp, not passing to ULD unless for FCP_RSP or error */
		if (ixgbe_rx_is_fcoe(rx_ring, rx_desc)) {
			ddp_bytes = ixgbe_fcoe_ddp(q_vector->adapter,
						   rx_desc, skb);
			if (!ddp_bytes) {
				dev_kfree_skb_any(skb);
#ifndef NETIF_F_GRO
				netdev_ring(rx_ring)->last_rx = jiffies;
#endif
				continue;
			}
		}

#endif /* IXGBE_FCOE */
		ixgbe_rx_skb(q_vector, rx_ring, rx_desc, skb);

		/* update budget accounting */
		total_rx_packets++;
	} while (likely(total_rx_packets < budget));

#ifdef IXGBE_FCOE
	/* include DDPed FCoE data */
	if (ddp_bytes > 0) {
		unsigned int mss;

		mss = netdev_ring(rx_ring)->mtu - sizeof(struct fcoe_hdr) -
			sizeof(struct fc_frame_header) -
			sizeof(struct fcoe_crc_eof);
		if (mss > 512)
			mss &= ~511;
		total_rx_bytes += ddp_bytes;
		total_rx_packets += DIV_ROUND_UP(ddp_bytes, mss);
	}

#endif /* IXGBE_FCOE */
	rx_ring->stats.packets += total_rx_packets;
	rx_ring->stats.bytes += total_rx_bytes;
	q_vector->rx.total_packets += total_rx_packets;
	q_vector->rx.total_bytes += total_rx_bytes;
	q_vector->netpoll_rx = false;

	if (cleaned_count)
		ixgbe_alloc_rx_buffers(rx_ring, cleaned_count);

#ifndef IXGBE_NO_LRO
	ixgbe_lro_flush_all(q_vector);

#endif /* IXGBE_NO_LRO */
	return total_rx_packets;
}

#endif /* CONFIG_IXGBE_DISABLE_PACKET_SPLIT */
#ifdef CONFIG_NET_RX_BUSY_POLL
/* must be called with local_bh_disable()d */
static int ixgbe_busy_poll_recv(struct napi_struct *napi)
{
	struct ixgbe_q_vector *q_vector =
			container_of(napi, struct ixgbe_q_vector, napi);
	struct ixgbe_adapter *adapter = q_vector->adapter;
	struct ixgbe_ring  *ring;
	int found = 0;

	if (test_bit(__IXGBE_DOWN, &adapter->state))
		return LL_FLUSH_FAILED;

	if (!ixgbe_qv_lock_poll(q_vector))
		return LL_FLUSH_BUSY;

	ixgbe_for_each_ring(ring, q_vector->rx) {
		found = ixgbe_clean_rx_irq(q_vector, ring, 4);
#ifdef BP_EXTENDED_STATS
		if (found)
			ring->stats.cleaned += found;
		else
			ring->stats.misses++;
#endif
		if (found)
			break;
	}

	ixgbe_qv_unlock_poll(q_vector);

	return found;
}

#endif /* CONFIG_NET_RX_BUSY_POLL */
/**
 * ixgbe_configure_msix - Configure MSI-X hardware
 * @adapter: board private structure
 *
 * ixgbe_configure_msix sets up the hardware to properly generate MSI-X
 * interrupts.
 **/
static void ixgbe_configure_msix(struct ixgbe_adapter *adapter)
{
	int v_idx;
	u32 mask;

	/* Populate MSIX to EITR Select */
	if (adapter->num_vfs >= 32) {
		u32 eitrsel = (1 << (adapter->num_vfs - 32)) - 1;
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EITRSEL, eitrsel);
	}

	/*
	 * Populate the IVAR table and set the ITR values to the
	 * corresponding register.
	 */
	for (v_idx = 0; v_idx < adapter->num_q_vectors; v_idx++) {
		struct ixgbe_q_vector *q_vector = adapter->q_vector[v_idx];
		struct ixgbe_ring *ring;

		ixgbe_for_each_ring(ring, q_vector->rx)
			ixgbe_set_ivar(adapter, 0, ring->reg_idx, v_idx);

		ixgbe_for_each_ring(ring, q_vector->tx)
			ixgbe_set_ivar(adapter, 1, ring->reg_idx, v_idx);

		ixgbe_write_eitr(q_vector);
	}

	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82598EB:
		ixgbe_set_ivar(adapter, -1, IXGBE_IVAR_OTHER_CAUSES_INDEX,
			       v_idx);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		ixgbe_set_ivar(adapter, -1, 1, v_idx);
		break;
	default:
		break;
	}
	IXGBE_WRITE_REG(&adapter->hw, IXGBE_EITR(v_idx), 1950);

	/* set up to autoclear timer, and the vectors */
	mask = IXGBE_EIMS_ENABLE_MASK;
	mask &= ~(IXGBE_EIMS_OTHER |
		  IXGBE_EIMS_MAILBOX |
		  IXGBE_EIMS_LSC);

	IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIAC, mask);
}

enum latency_range {
	lowest_latency = 0,
	low_latency = 1,
	bulk_latency = 2,
	latency_invalid = 255
};

/**
 * ixgbe_update_itr - update the dynamic ITR value based on statistics
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
 *      parameter (see ixgbe_param.c)
 **/
static void ixgbe_update_itr(struct ixgbe_q_vector *q_vector,
			     struct ixgbe_ring_container *ring_container)
{
	int bytes = ring_container->total_bytes;
	int packets = ring_container->total_packets;
	u32 timepassed_us;
	u64 bytes_perint;
	u8 itr_setting = ring_container->itr;

	if (packets == 0)
		return;

	/* simple throttlerate management
	 *   0-10MB/s   lowest (100000 ints/s)
	 *  10-20MB/s   low    (20000 ints/s)
	 *  20-1249MB/s bulk   (8000 ints/s)
	 */
	/* what was last interrupt timeslice? */
	timepassed_us = q_vector->itr >> 2;
	if (timepassed_us == 0)
		return;
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
		} else if (bytes_perint <= 10) {
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

/**
 * ixgbe_write_eitr - write EITR register in hardware specific way
 * @q_vector: structure containing interrupt and ring information
 *
 * This function is made to be called by ethtool and by the driver
 * when it needs to update EITR registers at runtime.  Hardware
 * specific quirks/differences are taken care of here.
 */
void ixgbe_write_eitr(struct ixgbe_q_vector *q_vector)
{
	struct ixgbe_adapter *adapter = q_vector->adapter;
	struct ixgbe_hw *hw = &adapter->hw;
	int v_idx = q_vector->v_idx;
	u32 itr_reg = q_vector->itr & IXGBE_MAX_EITR;

	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82598EB:
		/* must write high and low 16 bits to reset counter */
		itr_reg |= (itr_reg << 16);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		/*
		 * set the WDIS bit to not clear the timer bits and cause an
		 * immediate assertion of the interrupt
		 */
		itr_reg |= IXGBE_EITR_CNT_WDIS;
		break;
	default:
		break;
	}
	IXGBE_WRITE_REG(hw, IXGBE_EITR(v_idx), itr_reg);
}

static void ixgbe_set_itr(struct ixgbe_q_vector *q_vector)
{
	u32 new_itr = q_vector->itr;
	u8 current_itr;

	ixgbe_update_itr(q_vector, &q_vector->tx);
	ixgbe_update_itr(q_vector, &q_vector->rx);

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
		new_itr = IXGBE_8K_ITR;
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

		ixgbe_write_eitr(q_vector);
	}
}

/**
 * ixgbe_check_overtemp_subtask - check for over temperature
 * @adapter: pointer to adapter
 **/
static void ixgbe_check_overtemp_subtask(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 eicr = adapter->interrupt_event;

	if (test_bit(__IXGBE_DOWN, &adapter->state))
		return;

	if (!(adapter->flags2 & IXGBE_FLAG2_TEMP_SENSOR_CAPABLE) &&
	    !(adapter->flags2 & IXGBE_FLAG2_TEMP_SENSOR_EVENT))
		return;

	adapter->flags2 &= ~IXGBE_FLAG2_TEMP_SENSOR_EVENT;

	switch (hw->device_id) {
	case IXGBE_DEV_ID_82599_T3_LOM:
		/*
		 * Since the warning interrupt is for both ports
		 * we don't have to check if:
		 *  - This interrupt wasn't for our port.
		 *  - We may have missed the interrupt so always have to
		 *    check if we  got a LSC
		 */
		if (!(eicr & IXGBE_EICR_GPI_SDP0) &&
		    !(eicr & IXGBE_EICR_LSC))
			return;

		if (!(eicr & IXGBE_EICR_LSC) && hw->mac.ops.check_link) {
			u32 speed;
			bool link_up = false;

			hw->mac.ops.check_link(hw, &speed, &link_up, false);

			if (link_up)
				return;
		}

		/* Check if this is not due to overtemp */
		if (hw->phy.ops.check_overtemp(hw) != IXGBE_ERR_OVERTEMP)
			return;

		break;
	default:
		if (!(eicr & IXGBE_EICR_GPI_SDP0))
			return;
		break;
	}
	e_crit(drv,
	       "Network adapter has been stopped because it has over heated. "
	       "Restart the computer. If the problem persists, "
	       "power off the system and replace the adapter\n");

	adapter->interrupt_event = 0;
}

static void ixgbe_check_fan_failure(struct ixgbe_adapter *adapter, u32 eicr)
{
	struct ixgbe_hw *hw = &adapter->hw;

	if ((adapter->flags & IXGBE_FLAG_FAN_FAIL_CAPABLE) &&
	    (eicr & IXGBE_EICR_GPI_SDP1)) {
		e_crit(probe, "Fan has stopped, replace the adapter\n");
		/* write to clear the interrupt */
		IXGBE_WRITE_REG(hw, IXGBE_EICR, IXGBE_EICR_GPI_SDP1);
	}
}

static void ixgbe_check_overtemp_event(struct ixgbe_adapter *adapter, u32 eicr)
{
	if (!(adapter->flags2 & IXGBE_FLAG2_TEMP_SENSOR_CAPABLE))
		return;

	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82599EB:
		/*
		 * Need to check link state so complete overtemp check
		 * on service task
		 */
		if (((eicr & IXGBE_EICR_GPI_SDP0) || (eicr & IXGBE_EICR_LSC)) &&
		    (!test_bit(__IXGBE_DOWN, &adapter->state))) {
			adapter->interrupt_event = eicr;
			adapter->flags2 |= IXGBE_FLAG2_TEMP_SENSOR_EVENT;
			ixgbe_service_event_schedule(adapter);
			return;
		}
		return;
	case ixgbe_mac_X540:
		if (!(eicr & IXGBE_EICR_TS))
			return;
		break;
	default:
		return;
	}

	e_crit(drv,
	       "Network adapter has been stopped because it has over heated. "
	       "Restart the computer. If the problem persists, "
	       "power off the system and replace the adapter\n");
}

static void ixgbe_check_sfp_event(struct ixgbe_adapter *adapter, u32 eicr)
{
	struct ixgbe_hw *hw = &adapter->hw;

	if (eicr & IXGBE_EICR_GPI_SDP2) {
		/* Clear the interrupt */
		IXGBE_WRITE_REG(hw, IXGBE_EICR, IXGBE_EICR_GPI_SDP2);
		if (!test_bit(__IXGBE_DOWN, &adapter->state)) {
			adapter->flags2 |= IXGBE_FLAG2_SFP_NEEDS_RESET;
			ixgbe_service_event_schedule(adapter);
		}
	}

	if (eicr & IXGBE_EICR_GPI_SDP1) {
		/* Clear the interrupt */
		IXGBE_WRITE_REG(hw, IXGBE_EICR, IXGBE_EICR_GPI_SDP1);
		if (!test_bit(__IXGBE_DOWN, &adapter->state)) {
			adapter->flags |= IXGBE_FLAG_NEED_LINK_CONFIG;
			ixgbe_service_event_schedule(adapter);
		}
	}
}

static void ixgbe_check_lsc(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;

	adapter->lsc_int++;
	adapter->flags |= IXGBE_FLAG_NEED_LINK_UPDATE;
	adapter->link_check_timeout = jiffies;
	if (!test_bit(__IXGBE_DOWN, &adapter->state)) {
		IXGBE_WRITE_REG(hw, IXGBE_EIMC, IXGBE_EIMC_LSC);
		IXGBE_WRITE_FLUSH(hw);
		ixgbe_service_event_schedule(adapter);
	}
}

static void ixgbe_irq_enable_queues(struct ixgbe_adapter *adapter, u64 qmask)
{
	u32 mask;
	struct ixgbe_hw *hw = &adapter->hw;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		mask = (IXGBE_EIMS_RTX_QUEUE & qmask);
		IXGBE_WRITE_REG(hw, IXGBE_EIMS, mask);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		mask = (qmask & 0xFFFFFFFF);
		if (mask)
			IXGBE_WRITE_REG(hw, IXGBE_EIMS_EX(0), mask);
		mask = (qmask >> 32);
		if (mask)
			IXGBE_WRITE_REG(hw, IXGBE_EIMS_EX(1), mask);
		break;
	default:
		break;
	}
	/* skip the flush */
}

#ifdef ENABLE_DNA 
void ixgbe_irq_disable_queues(struct ixgbe_adapter *adapter, u64 qmask)
{
	u32 mask;
	struct ixgbe_hw *hw = &adapter->hw;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		mask = (IXGBE_EIMS_RTX_QUEUE & qmask);
		IXGBE_WRITE_REG(hw, IXGBE_EIMC, mask);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		mask = (qmask & 0xFFFFFFFF);
		if (mask)
			IXGBE_WRITE_REG(hw, IXGBE_EIMC_EX(0), mask);
		mask = (qmask >> 32);
		if (mask)
			IXGBE_WRITE_REG(hw, IXGBE_EIMC_EX(1), mask);
		break;
	default:
		break;
	}
	/* skip the flush */
}
#endif

/**
 * ixgbe_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 **/
static inline void ixgbe_irq_enable(struct ixgbe_adapter *adapter, bool queues,
				    bool flush)
{
	u32 mask = (IXGBE_EIMS_ENABLE_MASK & ~IXGBE_EIMS_RTX_QUEUE);

	/* don't reenable LSC while waiting for link */
	if (adapter->flags & IXGBE_FLAG_NEED_LINK_UPDATE)
		mask &= ~IXGBE_EIMS_LSC;

	if (adapter->flags2 & IXGBE_FLAG2_TEMP_SENSOR_CAPABLE)
		switch (adapter->hw.mac.type) {
		case ixgbe_mac_82599EB:
			mask |= IXGBE_EIMS_GPI_SDP0;
			break;
		case ixgbe_mac_X540:
			mask |= IXGBE_EIMS_TS;
			break;
		default:
			break;
		}
	if (adapter->flags & IXGBE_FLAG_FAN_FAIL_CAPABLE)
		mask |= IXGBE_EIMS_GPI_SDP1;
	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82599EB:
		mask |= IXGBE_EIMS_GPI_SDP1;
		mask |= IXGBE_EIMS_GPI_SDP2;
	case ixgbe_mac_X540:
		mask |= IXGBE_EIMS_ECC;
		mask |= IXGBE_EIMS_MAILBOX;
#ifdef HAVE_PTP_1588_CLOCK
		mask |= IXGBE_EIMS_TIMESYNC;
#endif

		break;
	default:
		break;
	}

	if ((adapter->flags & IXGBE_FLAG_FDIR_HASH_CAPABLE) &&
	    !(adapter->flags2 & IXGBE_FLAG2_FDIR_REQUIRES_REINIT))
		mask |= IXGBE_EIMS_FLOW_DIR;

	IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIMS, mask);
	if (queues)
		ixgbe_irq_enable_queues(adapter, ~0);
	if (flush)
		IXGBE_WRITE_FLUSH(&adapter->hw);
}

static irqreturn_t ixgbe_msix_other(int irq, void *data)
{
	struct ixgbe_adapter *adapter = data;
	struct ixgbe_hw *hw = &adapter->hw;
	u32 eicr;

	/*
	 * Workaround for Silicon errata #26 on 82598.  Use clear-by-write
	 * instead of clear-by-read.  Reading with EICS will return the
	 * interrupt causes without clearing, which later be done
	 * with the write to EICR.
	 */
	eicr = IXGBE_READ_REG(hw, IXGBE_EICS);

	/* The lower 16bits of the EICR register are for the queue interrupts
	 * which should be masked here in order to not accidently clear them if
	 * the bits are high when ixgbe_msix_other is called. There is a race
	 * condition otherwise which results in possible performance loss
	 * especially if the ixgbe_msix_other interrupt is triggering
	 * consistently (as it would when PPS is turned on for the X540 device)
	 */
	eicr &= 0xFFFF0000;

	IXGBE_WRITE_REG(hw, IXGBE_EICR, eicr);

	if (eicr & IXGBE_EICR_LSC)
		ixgbe_check_lsc(adapter);

	if (eicr & IXGBE_EICR_MAILBOX)
		ixgbe_msg_task(adapter);

	switch (hw->mac.type) {
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		if (eicr & IXGBE_EICR_ECC) {
			e_info(link, "Received unrecoverable ECC Err,"
			       "initiating reset.\n");
			adapter->flags2 |= IXGBE_FLAG2_RESET_REQUESTED;
			ixgbe_service_event_schedule(adapter);
			IXGBE_WRITE_REG(hw, IXGBE_EICR, IXGBE_EICR_ECC);
		}
#ifdef HAVE_TX_MQ
		/* Handle Flow Director Full threshold interrupt */
		if (eicr & IXGBE_EICR_FLOW_DIR) {
			int reinit_count = 0;
			int i;
			for (i = 0; i < adapter->num_tx_queues; i++) {
				struct ixgbe_ring *ring = adapter->tx_ring[i];
				if (test_and_clear_bit(
						      __IXGBE_TX_FDIR_INIT_DONE,
						      &ring->state))
					reinit_count++;
			}
			if (reinit_count) {
				/* no more flow director interrupts until
				 * after init
				 */
				IXGBE_WRITE_REG(hw, IXGBE_EIMC,
						IXGBE_EIMC_FLOW_DIR);
				adapter->flags2 |=
					IXGBE_FLAG2_FDIR_REQUIRES_REINIT;
				ixgbe_service_event_schedule(adapter);
			}
		}
#endif
		ixgbe_check_sfp_event(adapter, eicr);
		ixgbe_check_overtemp_event(adapter, eicr);
		break;
	default:
		break;
	}

	ixgbe_check_fan_failure(adapter, eicr);

#ifdef HAVE_PTP_1588_CLOCK
	if (unlikely(eicr & IXGBE_EICR_TIMESYNC))
	    ixgbe_ptp_check_pps_event(adapter, eicr);
#endif

	/* re-enable the original interrupt state, no lsc, no queues */
	if (!test_bit(__IXGBE_DOWN, &adapter->state))
		ixgbe_irq_enable(adapter, false, false);

	return IRQ_HANDLED;
}

static irqreturn_t ixgbe_msix_clean_rings(int irq, void *data)
{
	struct ixgbe_q_vector *q_vector = data;

	/* EIAM disabled interrupts (on this vector) for us */

	if (q_vector->rx.ring || q_vector->tx.ring)
		napi_schedule(&q_vector->napi);

	return IRQ_HANDLED;
}

/**
 * ixgbe_poll - NAPI polling RX/TX cleanup routine
 * @napi: napi struct with our devices info in it
 * @budget: amount of work driver is allowed to do this pass, in packets
 *
 * This function will clean all queues associated with a q_vector.
 **/
int ixgbe_poll(struct napi_struct *napi, int budget)
{
	struct ixgbe_q_vector *q_vector =
			       container_of(napi, struct ixgbe_q_vector, napi);
	struct ixgbe_adapter *adapter = q_vector->adapter;
	struct ixgbe_ring *ring;
	int per_ring_budget;
	bool clean_complete = true;

#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
	if (adapter->flags & IXGBE_FLAG_DCA_ENABLED)
		ixgbe_update_dca(q_vector);

#endif
	ixgbe_for_each_ring(ring, q_vector->tx)
		clean_complete &= ixgbe_clean_tx_irq(q_vector, ring);

#ifdef CONFIG_NET_RX_BUSY_POLL
	if (test_bit(NAPI_STATE_NPSVC, &napi->state))
		return budget;

	if (!ixgbe_qv_lock_napi(q_vector))
		return budget;
#endif

	/* attempt to distribute budget to each queue fairly, but don't allow
	 * the budget to go below 1 because we'll exit polling */
	if (q_vector->rx.count > 1)
		per_ring_budget = max(budget/q_vector->rx.count, 1);
	else
		per_ring_budget = budget;

	ixgbe_for_each_ring(ring, q_vector->rx)
	clean_complete &= (ixgbe_clean_rx_irq(q_vector, ring,
					      per_ring_budget)
			   < per_ring_budget);

#ifdef CONFIG_NET_RX_BUSY_POLL
	ixgbe_qv_unlock_napi(q_vector);
#endif

#ifndef HAVE_NETDEV_NAPI_LIST
	if (!netif_running(adapter->netdev))
		clean_complete = true;

#endif
	/* If all work not completed, return budget and keep polling */
	if (!clean_complete)
		return budget;

	/* all work done, exit the polling mode */
	napi_complete(napi);
	if (adapter->rx_itr_setting == 1)
		ixgbe_set_itr(q_vector);
#ifdef ENABLE_DNA
	if(!adapter->dna.dna_enabled)
#endif
	if (!test_bit(__IXGBE_DOWN, &adapter->state))
		ixgbe_irq_enable_queues(adapter, ((u64)1 << q_vector->v_idx));

	return 0;
}

/**
 * ixgbe_request_msix_irqs - Initialize MSI-X interrupts
 * @adapter: board private structure
 *
 * ixgbe_request_msix_irqs allocates MSI-X vectors and requests
 * interrupts from the kernel.
 **/
static int ixgbe_request_msix_irqs(struct ixgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int vector, err;
	int ri = 0, ti = 0;

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct ixgbe_q_vector *q_vector = adapter->q_vector[vector];
		struct msix_entry *entry = &adapter->msix_entries[vector];

		if (q_vector->tx.ring && q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "TxRx", ri++);
			ti++;
		} else if (q_vector->rx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "rx", ri++);
		} else if (q_vector->tx.ring) {
			snprintf(q_vector->name, sizeof(q_vector->name) - 1,
				 "%s-%s-%d", netdev->name, "tx", ti++);
		} else {
			/* skip this unused q_vector */
			continue;
		}
		err = request_irq(entry->vector, &ixgbe_msix_clean_rings, 0,
				  q_vector->name, q_vector);
		if (err) {
			e_err(probe, "request_irq failed for MSIX interrupt '%s' "
			      "Error: %d\n", q_vector->name, err);
			goto free_queue_irqs;
		}
#ifdef HAVE_IRQ_AFFINITY_HINT
		/* If Flow Director is enabled, set interrupt affinity */
		if (adapter->flags & IXGBE_FLAG_FDIR_HASH_CAPABLE) {
			/* assign the mask for this irq */
			irq_set_affinity_hint(entry->vector,
					      &q_vector->affinity_mask);
		}
#endif /* HAVE_IRQ_AFFINITY_HINT */
	}

	err = request_irq(adapter->msix_entries[vector].vector,
			  ixgbe_msix_other, 0, netdev->name, adapter);
	if (err) {
		e_err(probe, "request_irq for msix_other failed: %d\n", err);
		goto free_queue_irqs;
	}

	return 0;

free_queue_irqs:
	while (vector) {
		vector--;
#ifdef HAVE_IRQ_AFFINITY_HINT
		irq_set_affinity_hint(adapter->msix_entries[vector].vector,
				      NULL);
#endif
		free_irq(adapter->msix_entries[vector].vector,
			 adapter->q_vector[vector]);
	}
	adapter->flags &= ~IXGBE_FLAG_MSIX_ENABLED;
	pci_disable_msix(adapter->pdev);
	kfree(adapter->msix_entries);
	adapter->msix_entries = NULL;
	return err;
}

/**
 * ixgbe_intr - legacy mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 **/
static irqreturn_t ixgbe_intr(int irq, void *data)
{
	struct ixgbe_adapter *adapter = data;
	struct ixgbe_hw *hw = &adapter->hw;
	struct ixgbe_q_vector *q_vector = adapter->q_vector[0];
	u32 eicr;

	/*
	 * Workaround for silicon errata #26 on 82598.  Mask the interrupt
	 * before the read of EICR.
	 */
	IXGBE_WRITE_REG(hw, IXGBE_EIMC, IXGBE_IRQ_CLEAR_MASK);

	/* for NAPI, using EIAM to auto-mask tx/rx interrupt bits on read
	 * therefore no explicit interrupt disable is necessary */
	eicr = IXGBE_READ_REG(hw, IXGBE_EICR);
	if (!eicr) {
		/*
		 * shared interrupt alert!
		 * make sure interrupts are enabled because the read will
		 * have disabled interrupts due to EIAM
		 * finish the workaround of silicon errata on 82598.  Unmask
		 * the interrupt that we masked before the EICR read.
		 */
		if (!test_bit(__IXGBE_DOWN, &adapter->state))
			ixgbe_irq_enable(adapter, true, true);
		return IRQ_NONE;	/* Not our interrupt */
	}

	if (eicr & IXGBE_EICR_LSC)
		ixgbe_check_lsc(adapter);

	switch (hw->mac.type) {
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		if (eicr & IXGBE_EICR_ECC) {
			e_info(link, "Received unrecoverable ECC Err,"
			       "initiating reset.\n");
			adapter->flags2 |= IXGBE_FLAG2_RESET_REQUESTED;
			ixgbe_service_event_schedule(adapter);
			IXGBE_WRITE_REG(hw, IXGBE_EICR, IXGBE_EICR_ECC);
		}
		ixgbe_check_sfp_event(adapter, eicr);
		ixgbe_check_overtemp_event(adapter, eicr);
		break;
	default:
		break;
	}

	ixgbe_check_fan_failure(adapter, eicr);
#ifdef HAVE_PTP_1588_CLOCK
	if (unlikely(eicr & IXGBE_EICR_TIMESYNC))
	    ixgbe_ptp_check_pps_event(adapter, eicr);
#endif

	/* would disable interrupts here but EIAM disabled it */
	napi_schedule(&q_vector->napi);

	/*
	 * re-enable link(maybe) and non-queue interrupts, no flush.
	 * ixgbe_poll will re-enable the queue interrupts
	 */
	if (!test_bit(__IXGBE_DOWN, &adapter->state))
		ixgbe_irq_enable(adapter, false, false);

	return IRQ_HANDLED;
}

/**
 * ixgbe_request_irq - initialize interrupts
 * @adapter: board private structure
 *
 * Attempts to configure interrupts using the best available
 * capabilities of the hardware and kernel.
 **/
static int ixgbe_request_irq(struct ixgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int err;

	if (adapter->flags & IXGBE_FLAG_MSIX_ENABLED)
		err = ixgbe_request_msix_irqs(adapter);
	else if (adapter->flags & IXGBE_FLAG_MSI_ENABLED)
		err = request_irq(adapter->pdev->irq, &ixgbe_intr, 0,
				  netdev->name, adapter);
	else
		err = request_irq(adapter->pdev->irq, &ixgbe_intr, IRQF_SHARED,
				  netdev->name, adapter);

	if (err)
		e_err(probe, "request_irq failed, Error %d\n", err);

	return err;
}

static void ixgbe_free_irq(struct ixgbe_adapter *adapter)
{
	int vector;

	if (!(adapter->flags & IXGBE_FLAG_MSIX_ENABLED)) {
		free_irq(adapter->pdev->irq, adapter);
		return;
	}

	for (vector = 0; vector < adapter->num_q_vectors; vector++) {
		struct ixgbe_q_vector *q_vector = adapter->q_vector[vector];
		struct msix_entry *entry = &adapter->msix_entries[vector];

		/* free only the irqs that were actually requested */
		if (!q_vector->rx.ring && !q_vector->tx.ring)
			continue;

#ifdef HAVE_IRQ_AFFINITY_HINT
		/* clear the affinity_mask in the IRQ descriptor */
		irq_set_affinity_hint(entry->vector, NULL);

#endif
		free_irq(entry->vector, q_vector);
	}

	free_irq(adapter->msix_entries[vector++].vector, adapter);
}

/**
 * ixgbe_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
static inline void ixgbe_irq_disable(struct ixgbe_adapter *adapter)
{
	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82598EB:
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIMC, ~0);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIMC, 0xFFFF0000);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIMC_EX(0), ~0);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EIMC_EX(1), ~0);
		break;
	default:
		break;
	}
	IXGBE_WRITE_FLUSH(&adapter->hw);
	if (adapter->flags & IXGBE_FLAG_MSIX_ENABLED) {
		int vector;

		for (vector = 0; vector < adapter->num_q_vectors; vector++)
			synchronize_irq(adapter->msix_entries[vector].vector);

		synchronize_irq(adapter->msix_entries[vector++].vector);
	} else {
		synchronize_irq(adapter->pdev->irq);
	}
}

/**
 * ixgbe_configure_msi_and_legacy - Initialize PIN (INTA...) and MSI interrupts
 *
 **/
static void ixgbe_configure_msi_and_legacy(struct ixgbe_adapter *adapter)
{
	struct ixgbe_q_vector *q_vector = adapter->q_vector[0];

	ixgbe_write_eitr(q_vector);

	ixgbe_set_ivar(adapter, 0, 0, 0);
	ixgbe_set_ivar(adapter, 1, 0, 0);

	e_info(hw, "Legacy interrupt IVAR setup done\n");
}

/**
 * ixgbe_configure_tx_ring - Configure 8259x Tx ring after Reset
 * @adapter: board private structure
 * @ring: structure containing ring specific data
 *
 * Configure the Tx descriptor ring after a reset.
 **/
void ixgbe_configure_tx_ring(struct ixgbe_adapter *adapter,
			     struct ixgbe_ring *ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u64 tdba = ring->dma;
	int wait_loop = 10;
	u32 txdctl = IXGBE_TXDCTL_ENABLE;
	u8 reg_idx = ring->reg_idx;

	/* disable queue to avoid issues while updating state */
	IXGBE_WRITE_REG(hw, IXGBE_TXDCTL(reg_idx), IXGBE_TXDCTL_SWFLSH);
	IXGBE_WRITE_FLUSH(hw);

	IXGBE_WRITE_REG(hw, IXGBE_TDBAL(reg_idx), tdba & DMA_BIT_MASK(32));
	IXGBE_WRITE_REG(hw, IXGBE_TDBAH(reg_idx), tdba >> 32);
	IXGBE_WRITE_REG(hw, IXGBE_TDLEN(reg_idx),
			ring->count * sizeof(union ixgbe_adv_tx_desc));

	/* disable head writeback */
	IXGBE_WRITE_REG(hw, IXGBE_TDWBAH(reg_idx), 0);
	IXGBE_WRITE_REG(hw, IXGBE_TDWBAL(reg_idx), 0);

	/* reset head and tail pointers */
	IXGBE_WRITE_REG(hw, IXGBE_TDH(reg_idx), 0);
	IXGBE_WRITE_REG(hw, IXGBE_TDT(reg_idx), 0);
#ifndef NO_LER_WRITE_CHECKS
	ring->adapter_present = &hw->hw_addr;
#endif /* NO_LER_WRITE_CHECKS */
	ring->tail = adapter->io_addr + IXGBE_TDT(reg_idx);

	/* reset ntu and ntc to place SW in sync with hardwdare */
	ring->next_to_clean = 0;
	ring->next_to_use = 0;

	/*
	 * set WTHRESH to encourage burst writeback, it should not be set
	 * higher than 1 when:
	 * - ITR is 0 as it could cause false TX hangs
	 * - ITR is set to > 100k int/sec and BQL is enabled
	 *
	 * In order to avoid issues WTHRESH + PTHRESH should always be equal
	 * to or less than the number of on chip descriptors, which is
	 * currently 40.
	 */
#if IS_ENABLED(CONFIG_BQL)
	if (!ring->q_vector || (ring->q_vector->itr < IXGBE_100K_ITR))
#else
	if (!ring->q_vector || (ring->q_vector->itr < 8))
#endif
		txdctl |= (1 << 16);	/* WTHRESH = 1 */
	else
		txdctl |= (8 << 16);	/* WTHRESH = 8 */

	/*
	 * Setting PTHRESH to 32 both improves performance
	 * and avoids a TX hang with DFP enabled
	 */
	txdctl |= (1 << 8) |	/* HTHRESH = 1 */
		   32;		/* PTHRESH = 32 */

	/* reinitialize flowdirector state */
	if (adapter->flags & IXGBE_FLAG_FDIR_HASH_CAPABLE) {
		ring->atr_sample_rate = adapter->atr_sample_rate;
		ring->atr_count = 0;
		set_bit(__IXGBE_TX_FDIR_INIT_DONE, &ring->state);
	} else {
		ring->atr_sample_rate = 0;
	}

	/* initialize XPS */
	if (!test_and_set_bit(__IXGBE_TX_XPS_INIT_DONE, &ring->state)) {
		struct ixgbe_q_vector *q_vector = ring->q_vector;

		if (q_vector)
			netif_set_xps_queue(adapter->netdev,
					    &q_vector->affinity_mask,
					    ring->queue_index);
	}

	clear_bit(__IXGBE_HANG_CHECK_ARMED, &ring->state);

	/* enable queue */
	IXGBE_WRITE_REG(hw, IXGBE_TXDCTL(reg_idx), txdctl);

	/* TXDCTL.EN will return 0 on 82598 if link is down, so skip it */
	if (hw->mac.type == ixgbe_mac_82598EB &&
	    !(IXGBE_READ_REG(hw, IXGBE_LINKS) & IXGBE_LINKS_UP))
		return;

	/* poll to verify queue is enabled */
	do {
		msleep(1);
		txdctl = IXGBE_READ_REG(hw, IXGBE_TXDCTL(reg_idx));
	} while (--wait_loop && !(txdctl & IXGBE_TXDCTL_ENABLE));
	if (!wait_loop)
		e_err(drv, "Could not enable Tx Queue %d\n", reg_idx);
}

static void ixgbe_setup_mtqc(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 rttdcs, mtqc;
	u8 tcs = netdev_get_num_tc(adapter->netdev);

	if (hw->mac.type == ixgbe_mac_82598EB)
		return;

	/* disable the arbiter while setting MTQC */
	rttdcs = IXGBE_READ_REG(hw, IXGBE_RTTDCS);
	rttdcs |= IXGBE_RTTDCS_ARBDIS;
	IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, rttdcs);

	/* set transmit pool layout */
	if (adapter->flags & IXGBE_FLAG_VMDQ_ENABLED) {
		mtqc = IXGBE_MTQC_VT_ENA;
		if (tcs > 4)
			mtqc |= IXGBE_MTQC_RT_ENA | IXGBE_MTQC_8TC_8TQ;
		else if (tcs > 1)
			mtqc |= IXGBE_MTQC_RT_ENA | IXGBE_MTQC_4TC_4TQ;
		else if (adapter->ring_feature[RING_F_RSS].indices == 4)
			mtqc |= IXGBE_MTQC_32VF;
		else
			mtqc |= IXGBE_MTQC_64VF;
	} else {
		if (tcs > 4)
			mtqc = IXGBE_MTQC_RT_ENA | IXGBE_MTQC_8TC_8TQ;
		else if (tcs > 1)
			mtqc = IXGBE_MTQC_RT_ENA | IXGBE_MTQC_4TC_4TQ;
		else
			mtqc = IXGBE_MTQC_64Q_1PB;
	}

	IXGBE_WRITE_REG(hw, IXGBE_MTQC, mtqc);

	/* Enable Security TX Buffer IFG for multiple pb */
	if (tcs) {
		u32 sectx = IXGBE_READ_REG(hw, IXGBE_SECTXMINIFG);
		sectx |= IXGBE_SECTX_DCB;
		IXGBE_WRITE_REG(hw, IXGBE_SECTXMINIFG, sectx);
	}

	/* re-enable the arbiter */
	rttdcs &= ~IXGBE_RTTDCS_ARBDIS;
	IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, rttdcs);
}

/**
 * ixgbe_configure_tx - Configure 8259x Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void ixgbe_configure_tx(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 dmatxctl;
	u32 i;

#ifdef CONFIG_NETDEVICES_MULTIQUEUE
	if (adapter->num_tx_queues > 1)
		adapter->netdev->features |= NETIF_F_MULTI_QUEUE;
	else
		adapter->netdev->features &= ~NETIF_F_MULTI_QUEUE;

#endif
	ixgbe_setup_mtqc(adapter);

	if (hw->mac.type != ixgbe_mac_82598EB) {
		/* DMATXCTL.EN must be before Tx queues are enabled */
		dmatxctl = IXGBE_READ_REG(hw, IXGBE_DMATXCTL);
		dmatxctl |= IXGBE_DMATXCTL_TE;
		IXGBE_WRITE_REG(hw, IXGBE_DMATXCTL, dmatxctl);
	}

	/* Setup the HW Tx Head and Tail descriptor pointers */
	for (i = 0; i < adapter->num_tx_queues; i++)
		ixgbe_configure_tx_ring(adapter, adapter->tx_ring[i]);
}

static void ixgbe_enable_rx_drop(struct ixgbe_adapter *adapter,
				 struct ixgbe_ring *ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u8 reg_idx = ring->reg_idx;
	u32 srrctl = IXGBE_READ_REG(hw, IXGBE_SRRCTL(reg_idx));

	srrctl |= IXGBE_SRRCTL_DROP_EN;

	IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(reg_idx), srrctl);
}

static void ixgbe_disable_rx_drop(struct ixgbe_adapter *adapter,
				  struct ixgbe_ring *ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u8 reg_idx = ring->reg_idx;
	u32 srrctl = IXGBE_READ_REG(hw, IXGBE_SRRCTL(reg_idx));

	srrctl &= ~IXGBE_SRRCTL_DROP_EN;

	IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(reg_idx), srrctl);
}

void ixgbe_set_rx_drop_en(struct ixgbe_adapter *adapter)
{
	int i;
	bool pfc_en = adapter->dcb_cfg.pfc_mode_enable;

#ifdef HAVE_DCBNL_IEEE
	if (adapter->ixgbe_ieee_pfc)
		pfc_en |= !!(adapter->ixgbe_ieee_pfc->pfc_en);

#endif
	/*
	 * We should set the drop enable bit if:
	 *  SR-IOV is enabled
	 *   or
	 *  Number of Rx queues > 1 and flow control is disabled
	 *
	 *  This allows us to avoid head of line blocking for security
	 *  and performance reasons.
	 */
	if (adapter->num_vfs || (adapter->num_rx_queues > 1 &&
	    !(adapter->hw.fc.current_mode & ixgbe_fc_tx_pause) && !pfc_en)) {
		for (i = 0; i < adapter->num_rx_queues; i++)
			ixgbe_enable_rx_drop(adapter, adapter->rx_ring[i]);
	} else {
		for (i = 0; i < adapter->num_rx_queues; i++)
			ixgbe_disable_rx_drop(adapter, adapter->rx_ring[i]);
	}
}

#define IXGBE_SRRCTL_BSIZEHDRSIZE_SHIFT 2

static void ixgbe_configure_srrctl(struct ixgbe_adapter *adapter,
				   struct ixgbe_ring *rx_ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 srrctl;
	u8 reg_idx = rx_ring->reg_idx;

	if (hw->mac.type == ixgbe_mac_82598EB) {
		u16 mask = adapter->ring_feature[RING_F_RSS].mask;

		/* program one srrctl register per VMDq index */
		if (adapter->flags & IXGBE_FLAG_VMDQ_ENABLED)
			mask = adapter->ring_feature[RING_F_VMDQ].mask;

		/*
		 * if VMDq is not active we must program one srrctl register
		 * per RSS queue since we have enabled RDRXCTL.MVMEN
		 */
		reg_idx &= mask;

		/* divide by the first bit of the mask to get the indices */
		if (reg_idx)
			reg_idx /= ((~mask) + 1) & mask;

#ifdef ENABLE_DNA
		if(adapter->dna.dna_enabled) {
			if(adapter->num_rx_queues > 1) {
				/* We need to set DROPEN on all available queues so that
				   when a queue is full, all other queues keep receiving packets */
				u32 i, val, flag = 0, rxctl;

				for(i=0; i<adapter->num_rx_queues; i++) {
					if(i == 0)
						val = 1;
					else
						val = 2 << (i-1);

					flag |= val;
				}

				IXGBE_WRITE_REG(&adapter->hw, IXGBE_DROPEN, flag);

				/* Enable Descriptor Monitor Bypass */
				rxctl = IXGBE_READ_REG(&adapter->hw, IXGBE_RXCTRL);
				rxctl |= ~IXGBE_RXCTRL_DMBYPS;
				IXGBE_WRITE_REG(&adapter->hw, IXGBE_RXCTRL, rxctl);

				if(0)
					printk("[DNA] 82598 [# queues: %u][flag: %02X][RXCTRL: %02X]\n",
					       adapter->num_rx_queues, flag, IXGBE_READ_REG(&adapter->hw, IXGBE_RXCTRL));
				/* NOTE: this code does not seem to work as it should, thus
				   we maintain the dna_clean_rx_irq for 82598 */
			}
		}
#endif
	}

	/* configure header buffer length, needed for RSC */
	srrctl = IXGBE_RX_HDR_SIZE << IXGBE_SRRCTL_BSIZEHDRSIZE_SHIFT;

	/* configure the packet buffer length */
#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
	srrctl |= ALIGN(rx_ring->rx_buf_len, 1024) >>
		  IXGBE_SRRCTL_BSIZEPKT_SHIFT;
#else
	srrctl |= ixgbe_rx_bufsz(rx_ring) >> IXGBE_SRRCTL_BSIZEPKT_SHIFT;
#endif

	/* configure descriptor type */
	srrctl |= IXGBE_SRRCTL_DESCTYPE_ADV_ONEBUF;

#ifdef ENABLE_DNA
	/* This is used for 82599 to drop packets when a queue is full */
	if(adapter->dna.dna_enabled && adapter->hw.mac.type != ixgbe_mac_82598EB)
		srrctl |= IXGBE_SRRCTL_DROP_EN;
#endif

	IXGBE_WRITE_REG(hw, IXGBE_SRRCTL(reg_idx), srrctl);
}

static void ixgbe_setup_mrqc(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	static const u32 seed[10] = { 0xE291D73D, 0x1805EC6C, 0x2A94B30D,
			  0xA54F2BEC, 0xEA49AF7C, 0xE214AD3D, 0xB855AABE,
			  0x6A3E67EA, 0x14364D17, 0x3BED200D};
	u32 mrqc = 0, reta = 0;
	u32 rxcsum;
	int i, j, reta_entries = 128;
	int indices_multi;
	u16 rss_i = adapter->ring_feature[RING_F_RSS].indices;

	/*
	 * Program table for at least 2 queues w/ SR-IOV so that VFs can
	 * make full use of any rings they may have.  We will use the
	 * PSRTYPE register to control how many rings we use within the PF.
	 */
	if ((adapter->flags & IXGBE_FLAG_SRIOV_ENABLED) && (rss_i < 2))
		rss_i = 2;

	/* Fill out hash function seeds */
	for (i = 0; i < 10; i++)
		IXGBE_WRITE_REG(hw, IXGBE_RSSRK(i), seed[i]);

	/* Fill out the redirection table as follows:
	 * 82598: 128 (8 bit wide) entries containing pair of 4 bit RSS indices
	 * 82599/X540: 128 (8 bit wide) entries containing 4 bit RSS index
	 */
	if (adapter->hw.mac.type == ixgbe_mac_82598EB)
		indices_multi = 0x11;
	else
		indices_multi = 0x1;

	for (i = 0, j = 0; i < reta_entries; i++, j++) {
		if (j == rss_i)
			j = 0;
		reta = (reta << 8) | (j * indices_multi);
		if ((i & 3) == 3) {
			if (i < 128)
				IXGBE_WRITE_REG(hw, IXGBE_RETA(i >> 2), reta);
		}
	}

	/* Disable indicating checksum in descriptor, enables RSS hash */
	rxcsum = IXGBE_READ_REG(hw, IXGBE_RXCSUM);
	rxcsum |= IXGBE_RXCSUM_PCSD;
	IXGBE_WRITE_REG(hw, IXGBE_RXCSUM, rxcsum);

	if (adapter->hw.mac.type == ixgbe_mac_82598EB) {
		if (adapter->ring_feature[RING_F_RSS].mask)
			mrqc = IXGBE_MRQC_RSSEN;
	} else {
		u8 tcs = netdev_get_num_tc(adapter->netdev);

		if (adapter->flags & IXGBE_FLAG_VMDQ_ENABLED) {
			if (tcs > 4)
				mrqc = IXGBE_MRQC_VMDQRT8TCEN;	/* 8 TCs */
			else if (tcs > 1)
				mrqc = IXGBE_MRQC_VMDQRT4TCEN;	/* 4 TCs */
			else if (adapter->ring_feature[RING_F_RSS].indices == 4)
				mrqc = IXGBE_MRQC_VMDQRSS32EN;
			else
				mrqc = IXGBE_MRQC_VMDQRSS64EN;
		} else {
			if (tcs > 4)
				mrqc = IXGBE_MRQC_RTRSS8TCEN;
			else if (tcs > 1)
				mrqc = IXGBE_MRQC_RTRSS4TCEN;
			else
				mrqc = IXGBE_MRQC_RSSEN;
		}
	}

	/* Perform hash on these packet types */
	mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4 |
		IXGBE_MRQC_RSS_FIELD_IPV4_TCP |
		IXGBE_MRQC_RSS_FIELD_IPV6 |
		IXGBE_MRQC_RSS_FIELD_IPV6_TCP;

	if (adapter->flags2 & IXGBE_FLAG2_RSS_FIELD_IPV4_UDP)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV4_UDP;
	if (adapter->flags2 & IXGBE_FLAG2_RSS_FIELD_IPV6_UDP)
		mrqc |= IXGBE_MRQC_RSS_FIELD_IPV6_UDP;

	IXGBE_WRITE_REG(hw, IXGBE_MRQC, mrqc);
}

/**
 * ixgbe_clear_rscctl - disable RSC for the indicated ring
 * @adapter: address of board private structure
 * @ring: structure containing ring specific data
 **/
void ixgbe_clear_rscctl(struct ixgbe_adapter *adapter,
			struct ixgbe_ring *ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 rscctrl;
	u8 reg_idx = ring->reg_idx;

	rscctrl = IXGBE_READ_REG(hw, IXGBE_RSCCTL(reg_idx));
	rscctrl &= ~IXGBE_RSCCTL_RSCEN;
	IXGBE_WRITE_REG(hw, IXGBE_RSCCTL(reg_idx), rscctrl);

	clear_ring_rsc_enabled(ring);
}

/**
 * ixgbe_configure_rscctl - enable RSC for the indicated ring
 * @adapter:    address of board private structure
 * @ring: structure containing ring specific data
 **/
void ixgbe_configure_rscctl(struct ixgbe_adapter *adapter,
			    struct ixgbe_ring *ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 rscctrl;
	u8 reg_idx = ring->reg_idx;

	if (!ring_is_rsc_enabled(ring))
		return;

	rscctrl = IXGBE_READ_REG(hw, IXGBE_RSCCTL(reg_idx));
	rscctrl |= IXGBE_RSCCTL_RSCEN;
	/*
	 * we must limit the number of descriptors so that the
	 * total size of max desc * buf_len is not greater
	 * than 65536
	 */
#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
#if (MAX_SKB_FRAGS >= 16)
	rscctrl |= IXGBE_RSCCTL_MAXDESC_16;
#elif (MAX_SKB_FRAGS >= 8)
	rscctrl |= IXGBE_RSCCTL_MAXDESC_8;
#elif (MAX_SKB_FRAGS >= 4)
	rscctrl |= IXGBE_RSCCTL_MAXDESC_4;
#else
	rscctrl |= IXGBE_RSCCTL_MAXDESC_1;
#endif
#else /* CONFIG_IXGBE_DISABLE_PACKET_SPLIT */
	if (ring->rx_buf_len <= IXGBE_RXBUFFER_4K)
		rscctrl |= IXGBE_RSCCTL_MAXDESC_16;
	else if (ring->rx_buf_len <= IXGBE_RXBUFFER_8K)
		rscctrl |= IXGBE_RSCCTL_MAXDESC_8;
	else
		rscctrl |= IXGBE_RSCCTL_MAXDESC_4;
#endif
	IXGBE_WRITE_REG(hw, IXGBE_RSCCTL(reg_idx), rscctrl);
}

static void ixgbe_rx_desc_queue_enable(struct ixgbe_adapter *adapter,
				       struct ixgbe_ring *ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int wait_loop = IXGBE_MAX_RX_DESC_POLL;
	u32 rxdctl;
	u8 reg_idx = ring->reg_idx;

	if (IXGBE_REMOVED(hw->hw_addr))
		return;
	/* RXDCTL.EN will return 0 on 82598 if link is down, so skip it */
	if (hw->mac.type == ixgbe_mac_82598EB &&
	    !(IXGBE_READ_REG(hw, IXGBE_LINKS) & IXGBE_LINKS_UP))
		return;

	do {
		msleep(1);
		rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(reg_idx));
	} while (--wait_loop && !(rxdctl & IXGBE_RXDCTL_ENABLE));

	if (!wait_loop) {
		e_err(drv, "RXDCTL.ENABLE on Rx queue %d "
		      "not set within the polling period\n", reg_idx);
	}
}

void ixgbe_disable_rx_queue(struct ixgbe_adapter *adapter,
			    struct ixgbe_ring *ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int wait_loop = IXGBE_MAX_RX_DESC_POLL;
	u32 rxdctl;
	u8 reg_idx = ring->reg_idx;

	if (IXGBE_REMOVED(hw->hw_addr))
		return;
	rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(reg_idx));
	rxdctl &= ~IXGBE_RXDCTL_ENABLE;

	/* write value back with RXDCTL.ENABLE bit cleared */
	IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(reg_idx), rxdctl);

	if (hw->mac.type == ixgbe_mac_82598EB &&
	    !(IXGBE_READ_REG(hw, IXGBE_LINKS) & IXGBE_LINKS_UP))
		return;

	/* the hardware may take up to 100us to really disable the rx queue */
	do {
		udelay(10);
		rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(reg_idx));
	} while (--wait_loop && (rxdctl & IXGBE_RXDCTL_ENABLE));

	if (!wait_loop) {
		e_err(drv, "RXDCTL.ENABLE on Rx queue %d not cleared within "
		      "the polling period\n", reg_idx);
	}
}

void ixgbe_configure_rx_ring(struct ixgbe_adapter *adapter,
			     struct ixgbe_ring *ring)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u64 rdba = ring->dma;
	u32 rxdctl;
	u8 reg_idx = ring->reg_idx;

	/* disable queue to avoid issues while updating state */
	rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(reg_idx));
	ixgbe_disable_rx_queue(adapter, ring);

	IXGBE_WRITE_REG(hw, IXGBE_RDBAL(reg_idx), rdba & DMA_BIT_MASK(32));
	IXGBE_WRITE_REG(hw, IXGBE_RDBAH(reg_idx), rdba >> 32);
	IXGBE_WRITE_REG(hw, IXGBE_RDLEN(reg_idx),
			ring->count * sizeof(union ixgbe_adv_rx_desc));

	/* reset head and tail pointers */
	IXGBE_WRITE_REG(hw, IXGBE_RDH(reg_idx), 0);
	IXGBE_WRITE_REG(hw, IXGBE_RDT(reg_idx), 0);
#ifndef NO_LER_WRITE_CHECKS
	ring->adapter_present = &hw->hw_addr;
#endif /* NO_LER_WRITE_CHECKS */
	ring->tail = adapter->io_addr + IXGBE_RDT(reg_idx);

	/* reset ntu and ntc to place SW in sync with hardwdare */
	ring->next_to_clean = 0;
	ring->next_to_use = 0;
#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
	ring->next_to_alloc = 0;
#endif

	ixgbe_configure_srrctl(adapter, ring);
        /* In ESX, RSCCTL configuration is done by on demand */
	ixgbe_configure_rscctl(adapter, ring);

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		/*
		 * enable cache line friendly hardware writes:
		 * PTHRESH=32 descriptors (half the internal cache),
		 * this also removes ugly rx_no_buffer_count increment
		 * HTHRESH=4 descriptors (to minimize latency on fetch)
		 * WTHRESH=8 burst writeback up to two cache lines
		 */
		rxdctl &= ~0x3FFFFF;
		rxdctl |=  0x080420;
		break;
	case ixgbe_mac_X540:
		rxdctl &= ~(IXGBE_RXDCTL_RLPMLMASK | IXGBE_RXDCTL_RLPML_EN);
#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
		/* If operating in IOV mode set RLPML for X540 */
		if (!(adapter->flags & IXGBE_FLAG_SRIOV_ENABLED))
			break;
		rxdctl |= ring->rx_buf_len | IXGBE_RXDCTL_RLPML_EN;
#endif /* CONFIG_IXGBE_DISABLE_PACKET_SPLIT */
		break;
	default:
		break;
	}

	/* enable receive descriptor ring */
	rxdctl |= IXGBE_RXDCTL_ENABLE;
	IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(reg_idx), rxdctl);

	ixgbe_rx_desc_queue_enable(adapter, ring);
	ixgbe_alloc_rx_buffers(ring, ixgbe_desc_unused(ring));
}

static void ixgbe_setup_psrtype(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int rss_i = adapter->ring_feature[RING_F_RSS].indices;
	int p;

	/* PSRTYPE must be initialized in non 82598 adapters */
	u32 psrtype = IXGBE_PSRTYPE_TCPHDR |
		      IXGBE_PSRTYPE_UDPHDR |
		      IXGBE_PSRTYPE_IPV4HDR |
		      IXGBE_PSRTYPE_L2HDR |
		      IXGBE_PSRTYPE_IPV6HDR;

	if (hw->mac.type == ixgbe_mac_82598EB)
		return;

	if (rss_i > 3)
		psrtype |= 2 << 29;
	else if (rss_i > 1)
		psrtype |= 1 << 29;

	for (p = 0; p < adapter->num_rx_pools; p++)
		IXGBE_WRITE_REG(hw, IXGBE_PSRTYPE(VMDQ_P(p)), psrtype);
}

static void ixgbe_configure_virtualization(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 reg_offset, vf_shift;
	u32 gcr_ext, vmdctl;
	int i;

	if (!(adapter->flags & IXGBE_FLAG_VMDQ_ENABLED))
		return;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		vmdctl = IXGBE_READ_REG(hw, IXGBE_VMD_CTL);
		vmdctl |= IXGBE_VMD_CTL_VMDQ_EN;
		IXGBE_WRITE_REG(hw, IXGBE_VMD_CTL, vmdctl);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		vmdctl = IXGBE_READ_REG(hw, IXGBE_VT_CTL);
		vmdctl |= IXGBE_VT_CTL_VT_ENABLE;
		vmdctl &= ~IXGBE_VT_CTL_POOL_MASK;
		vmdctl |= VMDQ_P(0) << IXGBE_VT_CTL_POOL_SHIFT;
		if (adapter->num_vfs)
			vmdctl |= IXGBE_VT_CTL_REPLEN;
		IXGBE_WRITE_REG(hw, IXGBE_VT_CTL, vmdctl);

		for (i = 1; i < adapter->num_rx_pools; i++) {
			u32 vmolr;
			int pool = VMDQ_P(i);

			/*
			* accept untagged packets until a vlan tag
			* is specifically set for the VMDQ queue/pool
			*/
			vmolr = IXGBE_READ_REG(hw, IXGBE_VMOLR(pool));
			vmolr |= IXGBE_VMOLR_AUPE;
			IXGBE_WRITE_REG(hw, IXGBE_VMOLR(pool), vmolr);
		}

		vf_shift = VMDQ_P(0) % 32;
		reg_offset = (VMDQ_P(0) >= 32) ? 1 : 0;

		/* Enable only the PF pools for Tx/Rx */
		IXGBE_WRITE_REG(hw, IXGBE_VFRE(reg_offset), (~0) << vf_shift);
		IXGBE_WRITE_REG(hw, IXGBE_VFRE(reg_offset ^ 1), reg_offset - 1);
		IXGBE_WRITE_REG(hw, IXGBE_VFTE(reg_offset), (~0) << vf_shift);
		IXGBE_WRITE_REG(hw, IXGBE_VFTE(reg_offset ^ 1), reg_offset - 1);
		break;
	default:
		break;
	}

	if (!(adapter->flags & IXGBE_FLAG_SRIOV_ENABLED))
		return;

	/*
	 * Set up VF register offsets for selected VT Mode,
	 * i.e. 32 or 64 VFs for SR-IOV
	 */
	switch (adapter->ring_feature[RING_F_VMDQ].mask) {
	case IXGBE_82599_VMDQ_8Q_MASK:
		gcr_ext = IXGBE_GCR_EXT_VT_MODE_16;
		break;
	case IXGBE_82599_VMDQ_4Q_MASK:
		gcr_ext = IXGBE_GCR_EXT_VT_MODE_32;
		break;
	default:
		gcr_ext = IXGBE_GCR_EXT_VT_MODE_64;
		break;
	}

	IXGBE_WRITE_REG(hw, IXGBE_GCR_EXT, gcr_ext);

	/* enable Tx loopback for VF/PF communication */
	if (adapter->flags & IXGBE_FLAG_SRIOV_L2LOOPBACK_ENABLE)
		IXGBE_WRITE_REG(hw, IXGBE_PFDTXGSWC, IXGBE_PFDTXGSWC_VT_LBEN);
	else
		IXGBE_WRITE_REG(hw, IXGBE_PFDTXGSWC, 0);

	hw->mac.ops.set_mac_anti_spoofing(hw, (adapter->num_vfs != 0),
						adapter->num_vfs);
#ifdef HAVE_VF_SPOOFCHK_CONFIGURE
	for (i = 0; i < adapter->num_vfs; i++) {
		if (!adapter->vfinfo[i].spoofchk_enabled)
			ixgbe_ndo_set_vf_spoofchk(adapter->netdev, i, false);
	}
#endif
}

static void ixgbe_set_rx_buffer_len(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	int max_frame = netdev->mtu + ETH_HLEN + ETH_FCS_LEN;
	struct ixgbe_ring *rx_ring;
	int i;
	u32 mhadd, hlreg0;
#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
	int rx_buf_len;
#endif

#ifdef IXGBE_FCOE
	/* adjust max frame to be able to do baby jumbo for FCoE */
	if ((adapter->flags & IXGBE_FLAG_FCOE_ENABLED) &&
	    (max_frame < IXGBE_FCOE_JUMBO_FRAME_SIZE))
		max_frame = IXGBE_FCOE_JUMBO_FRAME_SIZE;

#endif /* IXGBE_FCOE */

	/* adjust max frame to be at least the size of a standard frame */
	if (max_frame < (ETH_FRAME_LEN + ETH_FCS_LEN))
		max_frame = (ETH_FRAME_LEN + ETH_FCS_LEN);

	mhadd = IXGBE_READ_REG(hw, IXGBE_MHADD);
	if (max_frame != (mhadd >> IXGBE_MHADD_MFS_SHIFT)) {
		mhadd &= ~IXGBE_MHADD_MFS_MASK;
		mhadd |= max_frame << IXGBE_MHADD_MFS_SHIFT;

		IXGBE_WRITE_REG(hw, IXGBE_MHADD, mhadd);
	}

#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
		/* MHADD will allow an extra 4 bytes past for vlan tagged frames */
		max_frame += VLAN_HLEN;

	if (!(adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED) &&
	    (max_frame <= MAXIMUM_ETHERNET_VLAN_SIZE)) {
		rx_buf_len = MAXIMUM_ETHERNET_VLAN_SIZE;
	/*
	 * Make best use of allocation by using all but 1K of a
	 * power of 2 allocation that will be used for skb->head.
	 */
	} else if (max_frame <= IXGBE_RXBUFFER_3K) {
		rx_buf_len = IXGBE_RXBUFFER_3K;
	} else if (max_frame <= IXGBE_RXBUFFER_7K) {
		rx_buf_len = IXGBE_RXBUFFER_7K;
	} else if (max_frame <= IXGBE_RXBUFFER_15K) {
		rx_buf_len = IXGBE_RXBUFFER_15K;
	} else {
		rx_buf_len = IXGBE_MAX_RXBUFFER;
	}

#endif /* CONFIG_IXGBE_DISABLE_PACKET_SPLIT */
	hlreg0 = IXGBE_READ_REG(hw, IXGBE_HLREG0);
	/* set jumbo enable since MHADD.MFS is keeping size locked at
	 * max_frame
	 */
	hlreg0 |= IXGBE_HLREG0_JUMBOEN;
#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled) {
		if(unlikely(enable_debug))
			printk("[DNA] %s(): RX +JUMBOEN mtu=%d max_frame=%d rx_buf_len=%d\n",
	         	       __FUNCTION__, netdev->mtu, max_frame, rx_buf_len);

		hlreg0 &= ~IXGBE_HLREG0_RXCRCSTRP; /* Disable CRC strip */
	}
#endif
	IXGBE_WRITE_REG(hw, IXGBE_HLREG0, hlreg0);

	/*
	 * Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring
	 */
	for (i = 0; i < adapter->num_rx_queues; i++) {
		rx_ring = adapter->rx_ring[i];
		if (adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED)
			set_ring_rsc_enabled(rx_ring);
		else
			clear_ring_rsc_enabled(rx_ring);
#ifdef CONFIG_IXGBE_DISABLE_PACKET_SPLIT

		rx_ring->rx_buf_len = rx_buf_len;

#ifdef IXGBE_FCOE
		if (test_bit(__IXGBE_RX_FCOE, &rx_ring->state) &&
		    (rx_buf_len < IXGBE_FCOE_JUMBO_FRAME_SIZE))
			rx_ring->rx_buf_len = IXGBE_FCOE_JUMBO_FRAME_SIZE;
#endif /* IXGBE_FCOE */
#endif /* CONFIG_IXGBE_DISABLE_PACKET_SPLIT */
	}
}

static void ixgbe_setup_rdrxctl(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 rdrxctl = IXGBE_READ_REG(hw, IXGBE_RDRXCTL);

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		/*
		 * For VMDq support of different descriptor types or
		 * buffer sizes through the use of multiple SRRCTL
		 * registers, RDRXCTL.MVMEN must be set to 1
		 *
		 * also, the manual doesn't mention it clearly but DCA hints
		 * will only use queue 0's tags unless this bit is set.  Side
		 * effects of setting this bit are only that SRRCTL must be
		 * fully programmed [0..15]
		 */
		rdrxctl |= IXGBE_RDRXCTL_MVMEN;
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		/* Disable RSC for ACK packets */
		IXGBE_WRITE_REG(hw, IXGBE_RSCDBU,
		   (IXGBE_RSCDBU_RSCACKDIS | IXGBE_READ_REG(hw, IXGBE_RSCDBU)));
		rdrxctl &= ~IXGBE_RDRXCTL_RSCFRSTSIZE;
		/* hardware requires some bits to be set by default */
		rdrxctl |= (IXGBE_RDRXCTL_RSCACKC | IXGBE_RDRXCTL_FCOE_WRFIX);
		rdrxctl |= IXGBE_RDRXCTL_CRCSTRIP;
#ifdef ENABLE_DNA
		if(adapter->dna.dna_enabled)
			rdrxctl &= ~IXGBE_RDRXCTL_CRCSTRIP; /* Disable CRC strip */
#endif
		break;
	default:
		/* We should do nothing since we don't know this hardware */
		return;
	}

	IXGBE_WRITE_REG(hw, IXGBE_RDRXCTL, rdrxctl);
}


/**
 * ixgbe_configure_rx - Configure 8259x Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void ixgbe_configure_rx(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int i;
	u32 rxctrl, rfctl;

	/* disable receives while setting up the descriptors */
	ixgbe_disable_rx(hw);

	ixgbe_setup_psrtype(adapter);
	ixgbe_setup_rdrxctl(adapter);

	/* RSC Setup */
	rfctl = IXGBE_READ_REG(hw, IXGBE_RFCTL);
	rfctl &= ~IXGBE_RFCTL_RSC_DIS;
	if (!(adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED))
		rfctl |= IXGBE_RFCTL_RSC_DIS;
	IXGBE_WRITE_REG(hw, IXGBE_RFCTL, rfctl);


	/* Program registers for the distribution of queues */
	ixgbe_setup_mrqc(adapter);

	/* set_rx_buffer_len must be called before ring initialization */
	ixgbe_set_rx_buffer_len(adapter);

	/*
	 * Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring
	 */
	for (i = 0; i < adapter->num_rx_queues; i++)
		ixgbe_configure_rx_ring(adapter, adapter->rx_ring[i]);

	rxctrl = IXGBE_READ_REG(hw, IXGBE_RXCTRL);
	/* disable drop enable for 82598 parts */
	if (hw->mac.type == ixgbe_mac_82598EB)
		rxctrl |= IXGBE_RXCTRL_DMBYPS;

	/* enable all receives */
	rxctrl |= IXGBE_RXCTRL_RXEN;
	hw->mac.ops.enable_rx_dma(hw, rxctrl);
}

#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
#ifdef NETIF_F_HW_VLAN_CTAG_TX
static int ixgbe_vlan_rx_add_vid(struct net_device *netdev,
				 __always_unused __be16 proto, u16 vid)
#else /* !NETIF_F_HW_VLAN_CTAG_TX */
static int ixgbe_vlan_rx_add_vid(struct net_device *netdev, u16 vid)
#endif /* NETIF_F_HW_VLAN_CTAG_TX */
#else /* !HAVE_INT_NDO_VLAN_RX_ADD_VID */
static void ixgbe_vlan_rx_add_vid(struct net_device *netdev, u16 vid)
#endif /* HAVE_INT_NDO_VLAN_RX_ADD_VID */
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	int pool_ndx = VMDQ_P(0);

	/* add VID to filter table */
	if (hw->mac.ops.set_vfta) {
#ifndef HAVE_VLAN_RX_REGISTER
		if (vid < VLAN_N_VID)
			set_bit(vid, adapter->active_vlans);
#endif
		hw->mac.ops.set_vfta(hw, vid, pool_ndx, true);
		if (adapter->flags & IXGBE_FLAG_VMDQ_ENABLED) {
			int i;
			switch (adapter->hw.mac.type) {
			case ixgbe_mac_82599EB:
			case ixgbe_mac_X540:
				/* enable vlan id for all pools */
				for (i = 1; i < adapter->num_rx_pools; i++)
					hw->mac.ops.set_vfta(hw, vid,
							     VMDQ_P(i), true);
				break;
			default:
				break;
			}
		}
	}
#ifndef HAVE_NETDEV_VLAN_FEATURES

	/*
	 * Copy feature flags from netdev to the vlan netdev for this vid.
	 * This allows things like TSO to bubble down to our vlan device.
	 * Some vlans, such as VLAN 0 for DCB will not have a v_netdev so
	 * we will not have a netdev that needs updating.
	 */
	if (adapter->vlgrp) {
		struct vlan_group *vlgrp = adapter->vlgrp;
		struct net_device *v_netdev = vlan_group_get_device(vlgrp, vid);
		if (v_netdev) {
			v_netdev->features |= netdev->features;
			vlan_group_set_device(vlgrp, vid, v_netdev);
		}
	}
#endif /* HAVE_NETDEV_VLAN_FEATURES */
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
	return 0;
#endif
}

#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
#ifdef NETIF_F_HW_VLAN_CTAG_RX
static int ixgbe_vlan_rx_kill_vid(struct net_device *netdev,
				  __always_unused __be16 proto, u16 vid)
#else /* !NETIF_F_HW_VLAN_CTAG_RX */
static int ixgbe_vlan_rx_kill_vid(struct net_device *netdev, u16 vid)
#endif /* NETIF_F_HW_VLAN_CTAG_RX */
#else
static void ixgbe_vlan_rx_kill_vid(struct net_device *netdev, u16 vid)
#endif
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	int pool_ndx = VMDQ_P(0);

	/* User is not allowed to remove vlan ID 0 */
	if (!vid)
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
		return 0;
#else
		return;
#endif

#ifdef HAVE_VLAN_RX_REGISTER
	if (!test_bit(__IXGBE_DOWN, &adapter->state))
		ixgbe_irq_disable(adapter);

	vlan_group_set_device(adapter->vlgrp, vid, NULL);

	if (!test_bit(__IXGBE_DOWN, &adapter->state))
		ixgbe_irq_enable(adapter, true, true);

#endif /* HAVE_VLAN_RX_REGISTER */
	/* remove VID from filter table */
	if (hw->mac.ops.set_vfta) {
		hw->mac.ops.set_vfta(hw, vid, pool_ndx, false);
		if (adapter->flags & IXGBE_FLAG_VMDQ_ENABLED) {
			int i;
			switch (adapter->hw.mac.type) {
			case ixgbe_mac_82599EB:
			case ixgbe_mac_X540:
				/* remove vlan id from all pools */
				for (i = 1; i < adapter->num_rx_pools; i++)
					hw->mac.ops.set_vfta(hw, vid, VMDQ_P(i),
							     false);
				break;
			default:
				break;
			}
		}
	}
#ifndef HAVE_VLAN_RX_REGISTER

	clear_bit(vid, adapter->active_vlans);
#endif
#ifdef HAVE_INT_NDO_VLAN_RX_ADD_VID
	return 0;
#endif
}

#ifdef HAVE_8021P_SUPPORT
/**
 * ixgbe_vlan_stripping_disable - helper to disable vlan tag stripping
 * @adapter: driver data
 */
void ixgbe_vlan_stripping_disable(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 vlnctrl;
	int i;

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled)
		return;
#endif

	/* leave vlan tag stripping enabled for DCB */
	if (adapter->flags & IXGBE_FLAG_DCB_ENABLED)
		return;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		vlnctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
		vlnctrl &= ~IXGBE_VLNCTRL_VME;
		IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlnctrl);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		for (i = 0; i < adapter->num_rx_queues; i++) {
			u8 reg_idx = adapter->rx_ring[i]->reg_idx;
			vlnctrl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(reg_idx));
			vlnctrl &= ~IXGBE_RXDCTL_VME;
			IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(reg_idx), vlnctrl);
		}
		break;
	default:
		break;
	}
}

#endif
/**
 * ixgbe_vlan_stripping_enable - helper to enable vlan tag stripping
 * @adapter: driver data
 */
void ixgbe_vlan_stripping_enable(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 vlnctrl;
	int i;

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled)
		return;
#endif

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		vlnctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);
		vlnctrl |= IXGBE_VLNCTRL_VME;
		IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlnctrl);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		for (i = 0; i < adapter->num_rx_queues; i++) {
			u8 reg_idx = adapter->rx_ring[i]->reg_idx;
			vlnctrl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(reg_idx));
			vlnctrl |= IXGBE_RXDCTL_VME;
			IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(reg_idx), vlnctrl);
		}
		break;
	default:
		break;
	}
}

#ifdef HAVE_VLAN_RX_REGISTER
static void ixgbe_vlan_mode(struct net_device *netdev, struct vlan_group *grp)
#else
void ixgbe_vlan_mode(struct net_device *netdev, u32 features)
#endif
{
#if defined(HAVE_VLAN_RX_REGISTER) || defined(HAVE_8021P_SUPPORT)
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
#endif
#ifdef HAVE_8021P_SUPPORT
	bool enable;
#endif

#ifdef HAVE_VLAN_RX_REGISTER
	if (!test_bit(__IXGBE_DOWN, &adapter->state))
		ixgbe_irq_disable(adapter);

	adapter->vlgrp = grp;

	if (!test_bit(__IXGBE_DOWN, &adapter->state))
		ixgbe_irq_enable(adapter, true, true);
#endif
#ifdef HAVE_8021P_SUPPORT
#ifdef HAVE_VLAN_RX_REGISTER
	enable = (grp || (adapter->flags & IXGBE_FLAG_DCB_ENABLED));
#else
#ifdef NETIF_F_HW_VLAN_CTAG_RX
	enable = !!(features & NETIF_F_HW_VLAN_CTAG_RX);
#else
	enable = !!(features & NETIF_F_HW_VLAN_RX);
#endif /* NETIF_F_HW_VLAN_CTAG_RX */
#endif /* HAVE_VLAN_RX_REGISTER */
	if (enable)
		/* enable VLAN tag insert/strip */
		ixgbe_vlan_stripping_enable(adapter);
	else
		/* disable VLAN tag insert/strip */
		ixgbe_vlan_stripping_disable(adapter);

#endif /* HAVE_8021P_SUPPORT */
}

static void ixgbe_restore_vlan(struct ixgbe_adapter *adapter)
{
#ifdef HAVE_VLAN_RX_REGISTER
	ixgbe_vlan_mode(adapter->netdev, adapter->vlgrp);

	/*
	 * add vlan ID 0 and enable vlan tag stripping so we
	 * always accept priority-tagged traffic
	 */
#ifdef NETIF_F_HW_VLAN_CTAG_RX
	ixgbe_vlan_rx_add_vid(adapter->netdev, htons(ETH_P_8021Q), 0);
#else
	ixgbe_vlan_rx_add_vid(adapter->netdev, 0);
#endif
#ifndef HAVE_8021P_SUPPORT
	ixgbe_vlan_stripping_enable(adapter);
#endif
	if (adapter->vlgrp) {
		u16 vid;
		for (vid = 0; vid < VLAN_N_VID; vid++) {
			if (!vlan_group_get_device(adapter->vlgrp, vid))
				continue;
#ifdef NETIF_F_HW_VLAN_CTAG_RX
			ixgbe_vlan_rx_add_vid(adapter->netdev,
					      htons(ETH_P_8021Q), vid);
#else
			ixgbe_vlan_rx_add_vid(adapter->netdev, vid);
#endif
		}
	}
#else
	struct net_device *netdev = adapter->netdev;
	u16 vid;

	ixgbe_vlan_mode(netdev, netdev->features);

	for_each_set_bit(vid, adapter->active_vlans, VLAN_N_VID)
#ifdef NETIF_F_HW_VLAN_CTAG_RX
		ixgbe_vlan_rx_add_vid(netdev, htons(ETH_P_8021Q), vid);
#else
		ixgbe_vlan_rx_add_vid(netdev, vid);
#endif
#endif
}

#endif
static u8 *ixgbe_addr_list_itr(struct ixgbe_hw *hw, u8 **mc_addr_ptr, u32 *vmdq)
{
#ifdef NETDEV_HW_ADDR_T_MULTICAST
	struct netdev_hw_addr *mc_ptr;
#else
	struct dev_mc_list *mc_ptr;
#endif
#ifdef CONFIG_PCI_IOV
	struct ixgbe_adapter *adapter = hw->back;
#endif /* CONFIG_PCI_IOV */
	u8 *addr = *mc_addr_ptr;

	/* VMDQ_P implicitely uses the adapter struct when CONFIG_PCI_IOV is
	 * defined, so we have to wrap the pointer above correctly to prevent
	 * a warning.
	 */
	*vmdq = VMDQ_P(0);

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

/**
 * ixgbe_write_mc_addr_list - write multicast addresses to MTA
 * @netdev: network interface device structure
 *
 * Writes multicast address list to the MTA hash table.
 * Returns: -ENOMEM on failure
 *                0 on no addresses written
 *                X on writing X addresses to MTA
 **/
int ixgbe_write_mc_addr_list(struct net_device *netdev)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
#ifdef NETDEV_HW_ADDR_T_MULTICAST
	struct netdev_hw_addr *ha;
#endif
	u8  *addr_list = NULL;
	int addr_count = 0;

	if (!hw->mac.ops.update_mc_addr_list)
		return -ENOMEM;

	if (!netif_running(netdev))
		return 0;


	if (netdev_mc_empty(netdev)) {
		hw->mac.ops.update_mc_addr_list(hw, NULL, 0,
						ixgbe_addr_list_itr, true);
	} else {
#ifdef NETDEV_HW_ADDR_T_MULTICAST
		ha = list_first_entry(&netdev->mc.list,
				      struct netdev_hw_addr, list);
		addr_list = ha->addr;
#else
		addr_list = netdev->mc_list->dmi_addr;
#endif
		addr_count = netdev_mc_count(netdev);

		hw->mac.ops.update_mc_addr_list(hw, addr_list, addr_count,
						ixgbe_addr_list_itr, true);
	}

#ifdef CONFIG_PCI_IOV
	ixgbe_restore_vf_multicasts(adapter);
#endif
	return addr_count;
}


void ixgbe_full_sync_mac_table(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int i;
	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		if (adapter->mac_table[i].state & IXGBE_MAC_STATE_IN_USE) {
			hw->mac.ops.set_rar(hw, i, adapter->mac_table[i].addr,
						adapter->mac_table[i].queue,
						IXGBE_RAH_AV);
		} else {
			hw->mac.ops.clear_rar(hw, i);
		}
	}
}

static void ixgbe_sync_mac_table(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int i;
	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		if (adapter->mac_table[i].state & IXGBE_MAC_STATE_MODIFIED) {
			if (adapter->mac_table[i].state &
					IXGBE_MAC_STATE_IN_USE) {
				hw->mac.ops.set_rar(hw, i,
						adapter->mac_table[i].addr,
						adapter->mac_table[i].queue,
						IXGBE_RAH_AV);
			} else {
				hw->mac.ops.clear_rar(hw, i);
			}
			adapter->mac_table[i].state &=
				~(IXGBE_MAC_STATE_MODIFIED);
		}
	}
}

int ixgbe_available_rars(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int i, count = 0;

	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		if (adapter->mac_table[i].state == 0)
			count++;
	}
	return count;
}

int ixgbe_add_mac_filter(struct ixgbe_adapter *adapter, u8 *addr, u16 queue)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int i;

	if (is_zero_ether_addr(addr))
		return -EINVAL;

	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		if (adapter->mac_table[i].state & IXGBE_MAC_STATE_IN_USE) {
			continue;
		}
		adapter->mac_table[i].state |= (IXGBE_MAC_STATE_MODIFIED |
						IXGBE_MAC_STATE_IN_USE);
		memcpy(adapter->mac_table[i].addr, addr, ETH_ALEN);
		adapter->mac_table[i].queue = queue;
		ixgbe_sync_mac_table(adapter);
		return i;
	}
	return -ENOMEM;
}

static void ixgbe_flush_sw_mac_table(struct ixgbe_adapter *adapter)
{
	int i;
	struct ixgbe_hw *hw = &adapter->hw;

	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		adapter->mac_table[i].state |= IXGBE_MAC_STATE_MODIFIED;
		adapter->mac_table[i].state &= ~IXGBE_MAC_STATE_IN_USE;
		memset(adapter->mac_table[i].addr, 0, ETH_ALEN);
		adapter->mac_table[i].queue = 0;
	}
	ixgbe_sync_mac_table(adapter);
}


int ixgbe_del_mac_filter(struct ixgbe_adapter *adapter, u8* addr, u16 queue)
{
	/* search table for addr, if found, set to 0 and sync */
	int i;
	struct ixgbe_hw *hw = &adapter->hw;

	if (is_zero_ether_addr(addr))
		return -EINVAL;

	for (i = 0; i < hw->mac.num_rar_entries; i++) {
		if (ether_addr_equal(addr, adapter->mac_table[i].addr) &&
		    adapter->mac_table[i].queue == queue) {
			adapter->mac_table[i].state |= IXGBE_MAC_STATE_MODIFIED;
			adapter->mac_table[i].state &= ~IXGBE_MAC_STATE_IN_USE;
			memset(adapter->mac_table[i].addr, 0, ETH_ALEN);
			adapter->mac_table[i].queue = 0;
			ixgbe_sync_mac_table(adapter);
			return 0;
		}
	}
	return -ENOMEM;
}
#ifdef HAVE_SET_RX_MODE
/**
 * ixgbe_write_uc_addr_list - write unicast addresses to RAR table
 * @netdev: network interface device structure
 *
 * Writes unicast address list to the RAR table.
 * Returns: -ENOMEM on failure/insufficient address space
 *                0 on no addresses written
 *                X on writing X addresses to the RAR table
 **/
int ixgbe_write_uc_addr_list(struct net_device *netdev, int vfn)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	int count = 0;

	/* return ENOMEM indicating insufficient memory for addresses */
	if (netdev_uc_count(netdev) > ixgbe_available_rars(adapter))
		return -ENOMEM;

	if (!netdev_uc_empty(netdev)) {
#ifdef NETDEV_HW_ADDR_T_UNICAST
		struct netdev_hw_addr *ha;
#else
		struct dev_mc_list *ha;
#endif
		netdev_for_each_uc_addr(ha, netdev) {
#ifdef NETDEV_HW_ADDR_T_UNICAST
			ixgbe_del_mac_filter(adapter, ha->addr, vfn);
			ixgbe_add_mac_filter(adapter, ha->addr, vfn);
#else
			ixgbe_del_mac_filter(adapter, ha->da_addr, vfn);
			ixgbe_add_mac_filter(adapter, ha->da_addr, vfn);
#endif
			count++;
		}
	}
	return count;
}

#endif
/**
 * ixgbe_set_rx_mode - Unicast, Multicast and Promiscuous mode set
 * @netdev: network interface device structure
 *
 * The set_rx_method entry point is called whenever the unicast/multicast
 * address list or the network interface flags are updated.  This routine is
 * responsible for configuring the hardware for proper unicast, multicast and
 * promiscuous mode.
 **/
void ixgbe_set_rx_mode(struct net_device *netdev)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	u32 fctrl, vmolr = IXGBE_VMOLR_BAM | IXGBE_VMOLR_AUPE;
	u32 vlnctrl;
	int count;

	/* Check for Promiscuous and All Multicast modes */
	fctrl = IXGBE_READ_REG(hw, IXGBE_FCTRL);
	vlnctrl = IXGBE_READ_REG(hw, IXGBE_VLNCTRL);

	/* set all bits that we expect to always be set */
	fctrl |= IXGBE_FCTRL_BAM;
	fctrl |= IXGBE_FCTRL_DPF; /* discard pause frames when FC enabled */
	fctrl |= IXGBE_FCTRL_PMCF;

	/* clear the bits we are changing the status of */
	fctrl &= ~(IXGBE_FCTRL_UPE | IXGBE_FCTRL_MPE);
	vlnctrl  &= ~(IXGBE_VLNCTRL_VFE | IXGBE_VLNCTRL_CFIEN);
	if (netdev->flags & IFF_PROMISC) {
		hw->addr_ctrl.user_set_promisc = true;
		fctrl |= (IXGBE_FCTRL_UPE | IXGBE_FCTRL_MPE);
		vmolr |= IXGBE_VMOLR_MPE;
		/* Only disable hardware filter vlans in promiscuous mode
		 * if SR-IOV and VMDQ are disabled - otherwise ensure
		 * that hardware VLAN filters remain enabled.
		 */
		if ((adapter->flags & (IXGBE_FLAG_VMDQ_ENABLED |
				       IXGBE_FLAG_SRIOV_ENABLED)))
			vlnctrl |= (IXGBE_VLNCTRL_VFE | IXGBE_VLNCTRL_CFIEN);
	} else {
		if (netdev->flags & IFF_ALLMULTI) {
			fctrl |= IXGBE_FCTRL_MPE;
			vmolr |= IXGBE_VMOLR_MPE;
		}
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
		/* enable hardware vlan filtering */
		vlnctrl |= IXGBE_VLNCTRL_VFE;
#endif
		hw->addr_ctrl.user_set_promisc = false;
	}
#ifdef HAVE_SET_RX_MODE
	/* Write the unicast MAC address filter list */
	count = ixgbe_write_uc_addr_list(netdev, VMDQ_P(0));
	if (count < 0) {
		fctrl |= IXGBE_FCTRL_UPE;
		vmolr |= IXGBE_VMOLR_ROPE;
	}
#endif
	/*
	 * Write addresses to the MTA, if the attempt fails
	 * then we should just turn on promiscuous mode so
	 * that we can at least receive multicast traffic
	 */
	count = ixgbe_write_mc_addr_list(netdev);
	if (count < 0) {
		fctrl |= IXGBE_FCTRL_MPE;
		vmolr |= IXGBE_VMOLR_MPE;
	} else if (count) {
		vmolr |= IXGBE_VMOLR_ROMPE;
	}

	if (hw->mac.type != ixgbe_mac_82598EB) {
		vmolr |= IXGBE_READ_REG(hw, IXGBE_VMOLR(VMDQ_P(0))) &
			 ~(IXGBE_VMOLR_MPE | IXGBE_VMOLR_ROMPE |
			   IXGBE_VMOLR_ROPE);
		IXGBE_WRITE_REG(hw, IXGBE_VMOLR(VMDQ_P(0)), vmolr);
	}

	IXGBE_WRITE_REG(hw, IXGBE_VLNCTRL, vlnctrl);
	IXGBE_WRITE_REG(hw, IXGBE_FCTRL, fctrl);
}

static void ixgbe_napi_enable_all(struct ixgbe_adapter *adapter)
{
	struct ixgbe_q_vector *q_vector;
	int q_idx;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++) {
		q_vector = adapter->q_vector[q_idx];
#ifdef CONFIG_NET_RX_BUSY_POLL
		ixgbe_qv_init_lock(adapter->q_vector[q_idx]);
#endif
		napi_enable(&q_vector->napi);
	}
}

static void ixgbe_napi_disable_all(struct ixgbe_adapter *adapter)
{
	struct ixgbe_q_vector *q_vector;
	int q_idx;

	for (q_idx = 0; q_idx < adapter->num_q_vectors; q_idx++) {
		q_vector = adapter->q_vector[q_idx];
		napi_disable(&q_vector->napi);
#ifdef CONFIG_NET_RX_BUSY_POLL
		while(!ixgbe_qv_disable(adapter->q_vector[q_idx])) {
			pr_info("QV %d locked\n", q_idx);
			usleep_range(1000, 20000);
		}
#endif
	}
}

#ifdef HAVE_DCBNL_IEEE
s32 ixgbe_dcb_hw_ets(struct ixgbe_hw *hw, struct ieee_ets *ets, int max_frame)
{
	__u16 refill[IEEE_8021QAZ_MAX_TCS], max[IEEE_8021QAZ_MAX_TCS];
	__u8 prio_type[IEEE_8021QAZ_MAX_TCS];
	int i;

	/* naively give each TC a bwg to map onto CEE hardware */
	__u8 bwg_id[IEEE_8021QAZ_MAX_TCS] = {0, 1, 2, 3, 4, 5, 6, 7};

	/* Map TSA onto CEE prio type */
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		switch (ets->tc_tsa[i]) {
		case IEEE_8021QAZ_TSA_STRICT:
			prio_type[i] = 2;
			break;
		case IEEE_8021QAZ_TSA_ETS:
			prio_type[i] = 0;
			break;
		default:
			/* Hardware only supports priority strict or
			 * ETS transmission selection algorithms if
			 * we receive some other value from dcbnl
			 * throw an error
			 */
			return -EINVAL;
		}
	}

	ixgbe_dcb_calculate_tc_credits(ets->tc_tx_bw, refill, max, max_frame);
	return ixgbe_dcb_hw_config(hw, refill, max,
				   bwg_id, prio_type, ets->prio_tc);
}

#endif
/*
 * ixgbe_configure_dcb - Configure DCB hardware
 * @adapter: ixgbe adapter struct
 *
 * This is called by the driver on open to configure the DCB hardware.
 * This is also called by the gennetlink interface when reconfiguring
 * the DCB state.
 */
static void ixgbe_configure_dcb(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct net_device *dev = adapter->netdev;

	int max_frame = dev->mtu + ETH_HLEN + ETH_FCS_LEN;

	if (!(adapter->flags & IXGBE_FLAG_DCB_ENABLED)) {
		if (hw->mac.type == ixgbe_mac_82598EB)
			netif_set_gso_max_size(dev, 65536);
		return;
	}

	if (hw->mac.type == ixgbe_mac_82598EB)
		netif_set_gso_max_size(dev, 32768);

#ifdef IXGBE_FCOE
	if (dev->features & NETIF_F_FCOE_MTU)
		max_frame = max_t(int, max_frame,
				  IXGBE_FCOE_JUMBO_FRAME_SIZE);
#endif /* IXGBE_FCOE */

#ifdef HAVE_DCBNL_IEEE
	if (adapter->dcbx_cap & DCB_CAP_DCBX_VER_IEEE) {
		if (adapter->ixgbe_ieee_ets)
			ixgbe_dcb_hw_ets(&adapter->hw,
					 adapter->ixgbe_ieee_ets,
					 max_frame);

		if (adapter->ixgbe_ieee_pfc && adapter->ixgbe_ieee_ets) {
			struct ieee_pfc *pfc = adapter->ixgbe_ieee_pfc;
			u8 *tc = adapter->ixgbe_ieee_ets->prio_tc;

			ixgbe_dcb_config_pfc(&adapter->hw, pfc->pfc_en, tc);
		}
	} else
#endif /* HAVE_DCBNL_IEEE */
	{
		ixgbe_dcb_calculate_tc_credits_cee(hw,
						   &adapter->dcb_cfg,
						   max_frame,
						   IXGBE_DCB_TX_CONFIG);
		ixgbe_dcb_calculate_tc_credits_cee(hw,
						   &adapter->dcb_cfg,
						   max_frame,
						   IXGBE_DCB_RX_CONFIG);
		ixgbe_dcb_hw_config_cee(hw, &adapter->dcb_cfg);
	}

	/* Enable RSS Hash per TC */
	if (hw->mac.type != ixgbe_mac_82598EB) {
		u32 msb = 0;
		u16 rss_i = adapter->ring_feature[RING_F_RSS].indices - 1;

		while (rss_i) {
			msb++;
			rss_i >>= 1;
		}

		/* write msb to all 8 TCs in one write */
		IXGBE_WRITE_REG(hw, IXGBE_RQTC, msb * 0x11111111);
	}
}

#ifndef IXGBE_NO_LLI
static void ixgbe_configure_lli_82599(struct ixgbe_adapter *adapter)
{
	u16 port;

	if (adapter->lli_etype) {
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_L34T_IMIR(0),
				(IXGBE_IMIR_LLI_EN_82599 |
				 IXGBE_IMIR_SIZE_BP_82599 |
				 IXGBE_IMIR_CTRL_BP_82599));
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_ETQS(0), IXGBE_ETQS_LLI);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_ETQF(0),
				(adapter->lli_etype | IXGBE_ETQF_FILTER_EN));
	}

	if (adapter->lli_port) {
		port = swab16(adapter->lli_port);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_L34T_IMIR(0),
				(IXGBE_IMIR_LLI_EN_82599 |
				 IXGBE_IMIR_SIZE_BP_82599 |
				 IXGBE_IMIR_CTRL_BP_82599));
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_FTQF(0),
				(IXGBE_FTQF_POOL_MASK_EN |
				 (IXGBE_FTQF_PRIORITY_MASK <<
				  IXGBE_FTQF_PRIORITY_SHIFT) |
				 (IXGBE_FTQF_DEST_PORT_MASK <<
				  IXGBE_FTQF_5TUPLE_MASK_SHIFT)));
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_SDPQF(0), (port << 16));
	}

	if (adapter->flags & IXGBE_FLAG_LLI_PUSH) {
		switch (adapter->hw.mac.type) {
		case ixgbe_mac_82599EB:
			IXGBE_WRITE_REG(&adapter->hw, IXGBE_L34T_IMIR(0),
					(IXGBE_IMIR_LLI_EN_82599 |
					 IXGBE_IMIR_SIZE_BP_82599 |
					 IXGBE_IMIR_CTRL_PSH_82599 |
					 IXGBE_IMIR_CTRL_SYN_82599 |
					 IXGBE_IMIR_CTRL_URG_82599 |
					 IXGBE_IMIR_CTRL_ACK_82599 |
					 IXGBE_IMIR_CTRL_RST_82599 |
					 IXGBE_IMIR_CTRL_FIN_82599));
			IXGBE_WRITE_REG(&adapter->hw, IXGBE_LLITHRESH,
					0xfc000000);
			break;
		case ixgbe_mac_X540:
			IXGBE_WRITE_REG(&adapter->hw, IXGBE_L34T_IMIR(0),
					(IXGBE_IMIR_LLI_EN_82599 |
					 IXGBE_IMIR_SIZE_BP_82599 |
					 IXGBE_IMIR_CTRL_PSH_82599));
			break;
		default:
			break;
		}
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_FTQF(0),
				(IXGBE_FTQF_POOL_MASK_EN |
				 (IXGBE_FTQF_PRIORITY_MASK <<
				  IXGBE_FTQF_PRIORITY_SHIFT) |
				 (IXGBE_FTQF_5TUPLE_MASK_MASK <<
				  IXGBE_FTQF_5TUPLE_MASK_SHIFT)));

		IXGBE_WRITE_REG(&adapter->hw, IXGBE_SYNQF, 0x80000100);
	}

	if (adapter->lli_size) {
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_L34T_IMIR(0),
				(IXGBE_IMIR_LLI_EN_82599 |
				 IXGBE_IMIR_CTRL_BP_82599));
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_LLITHRESH,
				adapter->lli_size);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_FTQF(0),
				(IXGBE_FTQF_POOL_MASK_EN |
				 (IXGBE_FTQF_PRIORITY_MASK <<
				  IXGBE_FTQF_PRIORITY_SHIFT) |
				 (IXGBE_FTQF_5TUPLE_MASK_MASK <<
				  IXGBE_FTQF_5TUPLE_MASK_SHIFT)));
	}

	if (adapter->lli_vlan_pri) {
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_IMIRVP,
				(IXGBE_IMIRVP_PRIORITY_EN |
				 adapter->lli_vlan_pri));
	}
}

static void ixgbe_configure_lli(struct ixgbe_adapter *adapter)
{
	u16 port;

	/* lli should only be enabled with MSI-X and MSI */
	if (!(adapter->flags & IXGBE_FLAG_MSI_ENABLED) &&
	    !(adapter->flags & IXGBE_FLAG_MSIX_ENABLED))
		return;
	if (adapter->hw.mac.type != ixgbe_mac_82598EB) {
		ixgbe_configure_lli_82599(adapter);
		return;
	}

	if (adapter->lli_port) {
		/* use filter 0 for port */
		port = swab16(adapter->lli_port);
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_IMIR(0),
				(port | IXGBE_IMIR_PORT_IM_EN));
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_IMIREXT(0),
				(IXGBE_IMIREXT_SIZE_BP |
				 IXGBE_IMIREXT_CTRL_BP));
	}

	if (adapter->flags & IXGBE_FLAG_LLI_PUSH) {
		/* use filter 1 for push flag */
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_IMIR(1),
				(IXGBE_IMIR_PORT_BP | IXGBE_IMIR_PORT_IM_EN));
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_IMIREXT(1),
				(IXGBE_IMIREXT_SIZE_BP |
				 IXGBE_IMIREXT_CTRL_PSH));
	}

	if (adapter->lli_size) {
		/* use filter 2 for size */
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_IMIR(2),
				(IXGBE_IMIR_PORT_BP | IXGBE_IMIR_PORT_IM_EN));
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_IMIREXT(2),
				(adapter->lli_size | IXGBE_IMIREXT_CTRL_BP));
	}
}

#endif /* IXGBE_NO_LLI */
/* Additional bittime to account for IXGBE framing */
#define IXGBE_ETH_FRAMING 20

/*
 * ixgbe_hpbthresh - calculate high water mark for flow control
 *
 * @adapter: board private structure to calculate for
 * @pb - packet buffer to calculate
 */
static int ixgbe_hpbthresh(struct ixgbe_adapter *adapter, int pb)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct net_device *dev = adapter->netdev;
	int link, tc, kb, marker;
	u32 dv_id, rx_pba;

	/* Calculate max LAN frame size */
	tc = link = dev->mtu + ETH_HLEN + ETH_FCS_LEN + IXGBE_ETH_FRAMING;

#ifdef IXGBE_FCOE
	/* FCoE traffic class uses FCOE jumbo frames */
	if ((dev->features & NETIF_F_FCOE_MTU) &&
	    (tc < IXGBE_FCOE_JUMBO_FRAME_SIZE) &&
	    (pb == netdev_get_prio_tc_map(dev, adapter->fcoe.up)))
		tc = IXGBE_FCOE_JUMBO_FRAME_SIZE;

#endif
	/* Calculate delay value for device */
	switch (hw->mac.type) {
	case ixgbe_mac_X540:
		dv_id = IXGBE_DV_X540(link, tc);
		break;
	default:
		dv_id = IXGBE_DV(link, tc);
		break;
	}

	/* Loopback switch introduces additional latency */
	if (adapter->flags & IXGBE_FLAG_SRIOV_ENABLED)
		dv_id += IXGBE_B2BT(tc);

	/* Delay value is calculated in bit times convert to KB */
	kb = IXGBE_BT2KB(dv_id);
	rx_pba = IXGBE_READ_REG(hw, IXGBE_RXPBSIZE(pb)) >> 10;

	marker = rx_pba - kb;

	/* It is possible that the packet buffer is not large enough
	 * to provide required headroom. In this case throw an error
	 * to user and a do the best we can.
	 */
	if (marker < 0) {
		e_warn(drv, "Packet Buffer(%i) can not provide enough"
			    "headroom to suppport flow control."
			    "Decrease MTU or number of traffic classes\n", pb);
		marker = tc + 1;
	}

	return marker;
}

/*
 * ixgbe_lpbthresh - calculate low water mark for for flow control
 *
 * @adapter: board private structure to calculate for
 * @pb - packet buffer to calculate
 */
static int ixgbe_lpbthresh(struct ixgbe_adapter *adapter, int pb)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct net_device *dev = adapter->netdev;
	int tc;
	u32 dv_id;

	/* Calculate max LAN frame size */
	tc = dev->mtu + ETH_HLEN + ETH_FCS_LEN;

#ifdef IXGBE_FCOE
	/* FCoE traffic class uses FCOE jumbo frames */
	if ((dev->features & NETIF_F_FCOE_MTU) &&
	    (tc < IXGBE_FCOE_JUMBO_FRAME_SIZE) &&
	    (pb == netdev_get_prio_tc_map(dev, adapter->fcoe.up)))
		tc = IXGBE_FCOE_JUMBO_FRAME_SIZE;

#endif
	/* Calculate delay value for device */
	switch (hw->mac.type) {
	case ixgbe_mac_X540:
		dv_id = IXGBE_LOW_DV_X540(tc);
		break;
	default:
		dv_id = IXGBE_LOW_DV(tc);
		break;
	}

	/* Delay value is calculated in bit times convert to KB */
	return IXGBE_BT2KB(dv_id);
}

/*
 * ixgbe_pbthresh_setup - calculate and setup high low water marks
 */
static void ixgbe_pbthresh_setup(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int num_tc = netdev_get_num_tc(adapter->netdev);
	int i;

	if (!num_tc)
		num_tc = 1;


	for (i = 0; i < num_tc; i++) {
		hw->fc.high_water[i] = ixgbe_hpbthresh(adapter, i);
		hw->fc.low_water[i] = ixgbe_lpbthresh(adapter, i);

		/* Low water marks must not be larger than high water marks */
		if (hw->fc.low_water[i] > hw->fc.high_water[i])
			hw->fc.low_water[i] = 0;
	}

	for (; i < IXGBE_DCB_MAX_TRAFFIC_CLASS; i++)
		hw->fc.high_water[i] = 0;
}

static void ixgbe_configure_pb(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int hdrm;
	u8 tc = netdev_get_num_tc(adapter->netdev);

	if (adapter->flags & IXGBE_FLAG_FDIR_HASH_CAPABLE ||
	    adapter->flags & IXGBE_FLAG_FDIR_PERFECT_CAPABLE)
		hdrm = 32 << adapter->fdir_pballoc;
	else
		hdrm = 0;

	hw->mac.ops.setup_rxpba(hw, tc, hdrm, PBA_STRATEGY_EQUAL);
	ixgbe_pbthresh_setup(adapter);
}

static void ixgbe_fdir_filter_restore(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct hlist_node *node;
	struct ixgbe_fdir_filter *filter;

	spin_lock(&adapter->fdir_perfect_lock);

	if (!hlist_empty(&adapter->fdir_filter_list))
		ixgbe_fdir_set_input_mask_82599(hw, &adapter->fdir_mask, 
				adapter->cloud_mode);

	hlist_for_each_entry_safe(filter, node,
				  &adapter->fdir_filter_list, fdir_node) {
		ixgbe_fdir_write_perfect_filter_82599(hw,
				&filter->filter,
				filter->sw_idx,
				(filter->action == IXGBE_FDIR_DROP_QUEUE) ?
				IXGBE_FDIR_DROP_QUEUE :
				adapter->rx_ring[filter->action]->reg_idx,
				adapter->cloud_mode);
	}

	spin_unlock(&adapter->fdir_perfect_lock);
}

static void ixgbe_configure(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;

	ixgbe_configure_pb(adapter);
	ixgbe_configure_dcb(adapter);

	/*
	 * We must restore virtualization before VLANs or else
	 * the VLVF registers will not be populated
	 */
	ixgbe_configure_virtualization(adapter);

	ixgbe_set_rx_mode(adapter->netdev);
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	ixgbe_restore_vlan(adapter);
#endif

	if (adapter->hw.mac.type == ixgbe_mac_82599EB ||
	    adapter->hw.mac.type == ixgbe_mac_X540)
		hw->mac.ops.disable_sec_rx_path(hw);

	if (adapter->flags & IXGBE_FLAG_FDIR_HASH_CAPABLE) {
		ixgbe_init_fdir_signature_82599(&adapter->hw,
						adapter->fdir_pballoc);
	} else if (adapter->flags & IXGBE_FLAG_FDIR_PERFECT_CAPABLE) {
		ixgbe_init_fdir_perfect_82599(&adapter->hw,
					      adapter->fdir_pballoc, adapter->cloud_mode);
		ixgbe_fdir_filter_restore(adapter);
	}

	if (adapter->hw.mac.type == ixgbe_mac_82599EB ||
	    adapter->hw.mac.type == ixgbe_mac_X540)
		hw->mac.ops.enable_sec_rx_path(hw);

#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
	/* configure DCA */
	ixgbe_setup_dca(adapter);

#endif
#ifdef IXGBE_FCOE
	/* configure FCoE L2 filters, redirection table, and Rx control */
	ixgbe_configure_fcoe(adapter);

#endif /* IXGBE_FCOE */
	ixgbe_configure_tx(adapter);
	ixgbe_configure_rx(adapter);
}

static bool ixgbe_is_sfp(struct ixgbe_hw *hw)
{
	switch (hw->phy.type) {
	case ixgbe_phy_sfp_avago:
	case ixgbe_phy_sfp_ftl:
	case ixgbe_phy_sfp_intel:
	case ixgbe_phy_sfp_unknown:
	case ixgbe_phy_sfp_passive_tyco:
	case ixgbe_phy_sfp_passive_unknown:
	case ixgbe_phy_sfp_active_unknown:
	case ixgbe_phy_sfp_ftl_active:
	case ixgbe_phy_qsfp_passive_unknown:
	case ixgbe_phy_qsfp_active_unknown:
	case ixgbe_phy_qsfp_intel:
	case ixgbe_phy_qsfp_unknown:
		return true;
	case ixgbe_phy_nl:
		if (hw->mac.type == ixgbe_mac_82598EB)
			return true;
	default:
		return false;
	}
}

/**
 * ixgbe_sfp_link_config - set up SFP+ link
 * @adapter: pointer to private adapter struct
 **/
static void ixgbe_sfp_link_config(struct ixgbe_adapter *adapter)
{
	/*
	 * We are assuming the worst case scenerio here, and that
	 * is that an SFP was inserted/removed after the reset
	 * but before SFP detection was enabled.  As such the best
	 * solution is to just start searching as soon as we start
	 */
	if (adapter->hw.mac.type == ixgbe_mac_82598EB)
		adapter->flags2 |= IXGBE_FLAG2_SEARCH_FOR_SFP;

	adapter->flags2 |= IXGBE_FLAG2_SFP_NEEDS_RESET;
}

/**
 * ixgbe_non_sfp_link_config - set up non-SFP+ link
 * @hw: pointer to private hardware struct
 *
 * Returns 0 on success, negative on failure
 **/
static int ixgbe_non_sfp_link_config(struct ixgbe_hw *hw)
{
	u32 speed;
	bool autoneg, link_up = false;
	u32 ret = IXGBE_ERR_LINK_SETUP;

	if (hw->mac.ops.check_link)
		ret = hw->mac.ops.check_link(hw, &speed, &link_up, false);

	if (ret)
		goto link_cfg_out;

	speed = hw->phy.autoneg_advertised;
	if ((!speed) && (hw->mac.ops.get_link_capabilities))
		ret = hw->mac.ops.get_link_capabilities(hw, &speed,
							&autoneg);
	if (ret)
		goto link_cfg_out;

	if (hw->mac.ops.setup_link)
		ret = hw->mac.ops.setup_link(hw, speed, link_up);
link_cfg_out:
	return ret;
}

/**
 * ixgbe_clear_vf_stats_counters - Clear out VF stats after reset
 * @adapter: board private structure
 *
 * On a reset we need to clear out the VF stats or accounting gets
 * messed up because they're not clear on read.
 **/
static void ixgbe_clear_vf_stats_counters(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int i;

	for (i = 0; i < adapter->num_vfs; i++) {
		adapter->vfinfo[i].last_vfstats.gprc =
			IXGBE_READ_REG(hw, IXGBE_PVFGPRC(i));
		adapter->vfinfo[i].saved_rst_vfstats.gprc +=
			adapter->vfinfo[i].vfstats.gprc;
		adapter->vfinfo[i].vfstats.gprc = 0;
		adapter->vfinfo[i].last_vfstats.gptc =
			IXGBE_READ_REG(hw, IXGBE_PVFGPTC(i));
		adapter->vfinfo[i].saved_rst_vfstats.gptc +=
			adapter->vfinfo[i].vfstats.gptc;
		adapter->vfinfo[i].vfstats.gptc = 0;
		adapter->vfinfo[i].last_vfstats.gorc =
			IXGBE_READ_REG(hw, IXGBE_PVFGORC_LSB(i));
		adapter->vfinfo[i].saved_rst_vfstats.gorc +=
			adapter->vfinfo[i].vfstats.gorc;
		adapter->vfinfo[i].vfstats.gorc = 0;
		adapter->vfinfo[i].last_vfstats.gotc =
			IXGBE_READ_REG(hw, IXGBE_PVFGOTC_LSB(i));
		adapter->vfinfo[i].saved_rst_vfstats.gotc +=
			adapter->vfinfo[i].vfstats.gotc;
		adapter->vfinfo[i].vfstats.gotc = 0;
		adapter->vfinfo[i].last_vfstats.mprc =
			IXGBE_READ_REG(hw, IXGBE_PVFMPRC(i));
		adapter->vfinfo[i].saved_rst_vfstats.mprc +=
			adapter->vfinfo[i].vfstats.mprc;
		adapter->vfinfo[i].vfstats.mprc = 0;
	}
}

static void ixgbe_setup_gpie(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 gpie = 0;

	if (adapter->flags & IXGBE_FLAG_MSIX_ENABLED) {
		gpie = IXGBE_GPIE_MSIX_MODE | IXGBE_GPIE_PBA_SUPPORT |
		       IXGBE_GPIE_OCD;
		gpie |= IXGBE_GPIE_EIAME;
		/*
		 * use EIAM to auto-mask when MSI-X interrupt is asserted
		 * this saves a register write for every interrupt
		 */
		switch (hw->mac.type) {
		case ixgbe_mac_82598EB:
			IXGBE_WRITE_REG(hw, IXGBE_EIAM, IXGBE_EICS_RTX_QUEUE);
			break;
		case ixgbe_mac_82599EB:
		case ixgbe_mac_X540:
		default:
			IXGBE_WRITE_REG(hw, IXGBE_EIAM_EX(0), 0xFFFFFFFF);
			IXGBE_WRITE_REG(hw, IXGBE_EIAM_EX(1), 0xFFFFFFFF);
			break;
		}
	} else {
		/* legacy interrupts, use EIAM to auto-mask when reading EICR,
		 * specifically only auto mask tx and rx interrupts */
		IXGBE_WRITE_REG(hw, IXGBE_EIAM, IXGBE_EICS_RTX_QUEUE);
	}

	/* XXX: to interrupt immediately for EICS writes, enable this */
	/* gpie |= IXGBE_GPIE_EIMEN; */

	if (adapter->flags & IXGBE_FLAG_SRIOV_ENABLED) {
		gpie &= ~IXGBE_GPIE_VTMODE_MASK;

		switch (adapter->ring_feature[RING_F_VMDQ].mask) {
		case IXGBE_82599_VMDQ_8Q_MASK:
			gpie |= IXGBE_GPIE_VTMODE_16;
			break;
		case IXGBE_82599_VMDQ_4Q_MASK:
			gpie |= IXGBE_GPIE_VTMODE_32;
			break;
		default:
			gpie |= IXGBE_GPIE_VTMODE_64;
			break;
		}
	}

	/* Enable Thermal over heat sensor interrupt */
	if (adapter->flags2 & IXGBE_FLAG2_TEMP_SENSOR_CAPABLE)
		switch (adapter->hw.mac.type) {
		case ixgbe_mac_82599EB:
			gpie |= IXGBE_SDP0_GPIEN;
			break;
		default:
			break;
		}

	/* Enable fan failure interrupt */
	if (adapter->flags & IXGBE_FLAG_FAN_FAIL_CAPABLE)
		gpie |= IXGBE_SDP1_GPIEN;

	if (hw->mac.type == ixgbe_mac_82599EB) {
		gpie |= IXGBE_SDP1_GPIEN;
		gpie |= IXGBE_SDP2_GPIEN;
	}

	IXGBE_WRITE_REG(hw, IXGBE_GPIE, gpie);
}

static void ixgbe_up_complete(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int err;
	u32 ctrl_ext;

	ixgbe_get_hw_control(adapter);
	ixgbe_setup_gpie(adapter);

	if (adapter->flags & IXGBE_FLAG_MSIX_ENABLED)
		ixgbe_configure_msix(adapter);
	else
		ixgbe_configure_msi_and_legacy(adapter);

	/* enable the optics for 82599 SFP+ fiber */
	if (hw->mac.ops.enable_tx_laser)
		hw->mac.ops.enable_tx_laser(hw);

	smp_mb__before_clear_bit();
	clear_bit(__IXGBE_DOWN, &adapter->state);
	ixgbe_napi_enable_all(adapter);
#ifndef IXGBE_NO_LLI
	ixgbe_configure_lli(adapter);
#endif

	if (ixgbe_is_sfp(hw)) {
		ixgbe_sfp_link_config(adapter);
	} else {
		err = ixgbe_non_sfp_link_config(hw);
		if (err)
			e_err(probe, "link_config FAILED %d\n", err);
	}

	/* clear any pending interrupts, may auto mask */
	IXGBE_READ_REG(hw, IXGBE_EICR);
	ixgbe_irq_enable(adapter, true, true);

	/*
	 * If this adapter has a fan, check to see if we had a failure
	 * before we enabled the interrupt.
	 */
	if (adapter->flags & IXGBE_FLAG_FAN_FAIL_CAPABLE) {
		u32 esdp = IXGBE_READ_REG(hw, IXGBE_ESDP);
		if (esdp & IXGBE_ESDP_SDP1)
			e_crit(drv, "Fan has stopped, replace the adapter\n");
	}

	/* enable transmits */
	netif_tx_start_all_queues(adapter->netdev);

	/* bring the link up in the watchdog, this could race with our first
	 * link up interrupt but shouldn't be a problem */
	adapter->flags |= IXGBE_FLAG_NEED_LINK_UPDATE;
	adapter->link_check_timeout = jiffies;
	mod_timer(&adapter->service_timer, jiffies);

	ixgbe_clear_vf_stats_counters(adapter);
	/* Set PF Reset Done bit so PF/VF Mail Ops can work */
	ctrl_ext = IXGBE_READ_REG(hw, IXGBE_CTRL_EXT);
	ctrl_ext |= IXGBE_CTRL_EXT_PFRSTD;
	IXGBE_WRITE_REG(hw, IXGBE_CTRL_EXT, ctrl_ext);
}

void ixgbe_reinit_locked(struct ixgbe_adapter *adapter)
{
	WARN_ON(in_interrupt());
	/* put off any impending NetWatchDogTimeout */
	adapter->netdev->trans_start = jiffies;

	while (test_and_set_bit(__IXGBE_RESETTING, &adapter->state))
		usleep_range(1000, 2000);
	ixgbe_down(adapter);
	/*
	 * If SR-IOV enabled then wait a bit before bringing the adapter
	 * back up to give the VFs time to respond to the reset.  The
	 * two second wait is based upon the watchdog timer cycle in
	 * the VF driver.
	 */
	if (adapter->flags & IXGBE_FLAG_SRIOV_ENABLED)
		msleep(2000);
	ixgbe_up(adapter);
	clear_bit(__IXGBE_RESETTING, &adapter->state);
}

void ixgbe_up(struct ixgbe_adapter *adapter)
{
	/* hardware has been reset, we need to reload some things */
	ixgbe_configure(adapter);

	ixgbe_up_complete(adapter);
}


void ixgbe_reset(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	int err;
	u8 old_addr[ETH_ALEN];

	if (IXGBE_REMOVED(hw->hw_addr))
		return;
	/* lock SFP init bit to prevent race conditions with the watchdog */
	while (test_and_set_bit(__IXGBE_IN_SFP_INIT, &adapter->state))
		usleep_range(1000, 2000);

	/* clear all SFP and link config related flags while holding SFP_INIT */
	adapter->flags2 &= ~(IXGBE_FLAG2_SEARCH_FOR_SFP |
			     IXGBE_FLAG2_SFP_NEEDS_RESET);
	adapter->flags &= ~IXGBE_FLAG_NEED_LINK_CONFIG;

	err = hw->mac.ops.init_hw(hw);
	switch (err) {
	case 0:
	case IXGBE_ERR_SFP_NOT_PRESENT:
	case IXGBE_ERR_SFP_NOT_SUPPORTED:
		break;
	case IXGBE_ERR_MASTER_REQUESTS_PENDING:
		e_dev_err("master disable timed out\n");
		break;
	case IXGBE_ERR_EEPROM_VERSION:
		/* We are running on a pre-production device, log a warning */
		e_dev_warn("This device is a pre-production adapter/LOM. "
			   "Please be aware there may be issues associated "
			   "with your hardware.  If you are experiencing "
			   "problems please contact your Intel or hardware "
			   "representative who provided you with this "
			   "hardware.\n");
		break;
	default:
		e_dev_err("Hardware Error: %d\n", err);
	}

	clear_bit(__IXGBE_IN_SFP_INIT, &adapter->state);
	/* do not flush user set addresses */
	memcpy(old_addr, &adapter->mac_table[0].addr, netdev->addr_len);
	ixgbe_flush_sw_mac_table(adapter);
	memcpy(&adapter->mac_table[0].addr, old_addr, netdev->addr_len);
	adapter->mac_table[0].queue = VMDQ_P(0);
	adapter->mac_table[0].state = (IXGBE_MAC_STATE_DEFAULT |
					IXGBE_MAC_STATE_IN_USE);
	hw->mac.ops.set_rar(hw, 0, adapter->mac_table[0].addr,
				adapter->mac_table[0].queue,
				IXGBE_RAH_AV);

	/* update SAN MAC vmdq pool selection */
	if (hw->mac.san_mac_rar_index)
		hw->mac.ops.set_vmdq_san_mac(hw, VMDQ_P(0));

#ifdef HAVE_PTP_1588_CLOCK
	if (test_bit(__IXGBE_PTP_RUNNING, &adapter->state))
		ixgbe_ptp_reset(adapter);
#endif

}

/**
 * ixgbe_clean_rx_ring - Free Rx Buffers per Queue
 * @rx_ring: ring to free buffers from
 **/
void ixgbe_clean_rx_ring(struct ixgbe_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;
	unsigned long size;
	u16 i;
#ifdef ENABLE_DNA
	struct ixgbe_adapter *adapter = netdev_priv(rx_ring->netdev);
#endif

	/* ring already cleared, nothing to do */
	if (!rx_ring->rx_buffer_info)
		return;

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < rx_ring->count; i++) {
		struct ixgbe_rx_buffer *rx_buffer;

		rx_buffer = &rx_ring->rx_buffer_info[i];
#ifdef ENABLE_DNA
		if(!adapter->dna.dna_enabled) {
#endif
		if (rx_buffer->skb) {
			struct sk_buff *skb = rx_buffer->skb;
#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
			if (IXGBE_CB(skb)->page_released) {
				dma_unmap_page(dev,
					       IXGBE_CB(skb)->dma,
					       ixgbe_rx_bufsz(rx_ring),
					       DMA_FROM_DEVICE);
				IXGBE_CB(skb)->page_released = false;
			}
#else
			/* We need to clean up RSC frag lists */
			skb = ixgbe_merge_active_tail(skb);
			if (ixgbe_close_active_frag_list(skb))
				dma_unmap_single(dev,
						 IXGBE_CB(skb)->dma,
						 rx_ring->rx_buf_len,
						 DMA_FROM_DEVICE);
			IXGBE_CB(skb)->dma = 0;
#endif
			dev_kfree_skb(skb);
		}
		rx_buffer->skb = NULL;
#ifdef ENABLE_DNA
		}
#endif
		if (rx_buffer->dma)
#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
			dma_unmap_page(dev, rx_buffer->dma,
				       ixgbe_rx_pg_size(rx_ring),
				       DMA_FROM_DEVICE);
#else
			dma_unmap_single(dev,
					 rx_buffer->dma,
					 rx_ring->rx_buf_len,
					 DMA_FROM_DEVICE);
#endif
		rx_buffer->dma = 0;
#ifndef CONFIG_IXGBE_DISABLE_PACKET_SPLIT
#ifdef ENABLE_DNA
		if(!adapter->dna.dna_enabled) {
#endif
		if (rx_buffer->page)
			__free_pages(rx_buffer->page,
				     ixgbe_rx_pg_order(rx_ring));
		rx_buffer->page = NULL;
#ifdef ENABLE_DNA
		}
#endif
#endif
	}

	size = sizeof(struct ixgbe_rx_buffer) * rx_ring->count;
	memset(rx_ring->rx_buffer_info, 0, size);

	/* Zero out the descriptor ring */
	memset(rx_ring->desc, 0, rx_ring->size);
#ifdef ENABLE_DNA

	if(adapter->dna.dna_enabled) {
		struct ixgbe_ring *tx_ring = adapter->tx_ring[rx_ring->queue_index];
		struct pfring_hooks *hook = (struct pfring_hooks*)rx_ring->netdev->pfring_ptr;
		struct ixgbe_hw *hw = &adapter->hw;
		u_int i;
		mem_ring_info rx_info = {0};
		mem_ring_info tx_info = {0};

		if(hook) {
			if(tx_ring->dna.memory_allocated) {
				memset(tx_ring->desc, 0, tx_ring->size);
				tx_ring->next_to_clean = 0;
				tx_ring->next_to_use = 0;

				if(unlikely(enable_debug)) 
					printk("[DNA] %s(): Deallocating TX DMA memory\n", __FUNCTION__);

				tx_ring->dna.memory_allocated = 0;
				for(i=0; i<tx_ring->dna.num_memory_pages; i++) {
					free_contiguous_memory(tx_ring->dna.rx_tx.tx.packet_memory[i],
					  tx_ring->dna.tot_packet_memory,
					  tx_ring->dna.mem_order);
					tx_ring->dna.rx_tx.tx.packet_memory[i] = 0;
				}
			}

			if(rx_ring->dna.memory_allocated) {
				if(unlikely(enable_debug)) 
					printk("[DNA] %s(): Deallocating RX DMA memory\n", __FUNCTION__);

				for(i=0; i<rx_ring->dna.num_memory_pages; i++) {
					free_contiguous_memory(rx_ring->dna.rx_tx.rx.packet_memory[i],
					  rx_ring->dna.tot_packet_memory, rx_ring->dna.mem_order);
					rx_ring->dna.rx_tx.rx.packet_memory[i] = 0;
				}

				/* De-register with PF_RING: one per channel	*/

				rx_info.packet_memory_num_chunks = rx_ring->dna.num_memory_pages;
				rx_info.packet_memory_chunk_len	 = rx_ring->dna.tot_packet_memory;
				rx_info.packet_memory_num_slots	 = rx_ring->dna.packet_num_slots;
				rx_info.packet_memory_slot_len	 = rx_ring->dna.packet_slot_len;
				rx_info.descr_packet_memory_tot_len = 2 * rx_ring->size;
	
				tx_info.packet_memory_num_chunks = tx_ring->dna.num_memory_pages;
				tx_info.packet_memory_chunk_len	 = tx_ring->dna.tot_packet_memory;
				tx_info.packet_memory_num_slots	 = tx_ring->dna.packet_num_slots;
				tx_info.packet_memory_slot_len	 = tx_ring->dna.packet_slot_len;
				tx_info.descr_packet_memory_tot_len = 2 * tx_ring->size;

				hook->zc_dev_handler(remove_device_mapping,
					dna_driver,
					&rx_info,
					&tx_info,
					0, //rx_ring->dna.rx_tx.rx.packet_memory,
					NULL, //rx_ring->desc, /* Packet descriptors */
					0, //tx_ring->dna.rx_tx.tx.packet_memory,
					NULL, //tx_ring->desc, /* Packet descriptors */
					(void*)rx_ring->netdev->mem_start,
					rx_ring->netdev->mem_end - rx_ring->netdev->mem_start,
					rx_ring->queue_index, /* Channel Id */
					rx_ring->netdev,
					rx_ring->dev,
					dna_model(hw),
					rx_ring->netdev->dev_addr,
					&rx_ring->dna.rx_tx.rx.packet_waitqueue,
					&rx_ring->dna.rx_tx.rx.interrupt_received,
					(void*)rx_ring, (void*)tx_ring,
					NULL, //wait_packet_function_ptr,
					NULL //notify_function_ptr
				);

				rx_ring->dna.memory_allocated = 0;
			}
		}
	}
#endif
}

/**
 * ixgbe_clean_tx_ring - Free Tx Buffers
 * @tx_ring: ring to be cleaned
 **/
static void ixgbe_clean_tx_ring(struct ixgbe_ring *tx_ring)
{
	struct ixgbe_tx_buffer *tx_buffer_info;
	unsigned long size;
	u16 i;
#ifdef ENABLE_DNA
	struct ixgbe_adapter *adapter = netdev_priv(tx_ring->netdev);
#endif

	/* ring already cleared, nothing to do */
	if (!tx_ring->tx_buffer_info)
		return;

	/* Free all the Tx ring sk_buffs */
	for (i = 0; i < tx_ring->count; i++) {
		tx_buffer_info = &tx_ring->tx_buffer_info[i];
#ifdef ENABLE_DNA
		if(!adapter->dna.dna_enabled)
#endif
		ixgbe_unmap_and_free_tx_resource(tx_ring, tx_buffer_info);
	}

	netdev_tx_reset_queue(netdev_get_tx_queue(tx_ring->netdev,
						  tx_ring->queue_index));

	size = sizeof(struct ixgbe_tx_buffer) * tx_ring->count;
	memset(tx_ring->tx_buffer_info, 0, size);

	/* Zero out the descriptor ring */
	memset(tx_ring->desc, 0, tx_ring->size);
}

/**
 * ixgbe_clean_all_rx_rings - Free Rx Buffers for all queues
 * @adapter: board private structure
 **/
static void ixgbe_clean_all_rx_rings(struct ixgbe_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_rx_queues; i++)
		ixgbe_clean_rx_ring(adapter->rx_ring[i]);
}

/**
 * ixgbe_clean_all_tx_rings - Free Tx Buffers for all queues
 * @adapter: board private structure
 **/
static void ixgbe_clean_all_tx_rings(struct ixgbe_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		ixgbe_clean_tx_ring(adapter->tx_ring[i]);
}

static void ixgbe_fdir_filter_exit(struct ixgbe_adapter *adapter)
{
	struct hlist_node *node;
	struct ixgbe_fdir_filter *filter;

	spin_lock(&adapter->fdir_perfect_lock);

	hlist_for_each_entry_safe(filter, node,
				  &adapter->fdir_filter_list, fdir_node) {
		hlist_del(&filter->fdir_node);
		kfree(filter);
	}
	adapter->fdir_filter_count = 0;

	spin_unlock(&adapter->fdir_perfect_lock);
}

void ixgbe_down(struct ixgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct ixgbe_hw *hw = &adapter->hw;
	int i;

	/* signal that we are down to the interrupt handler */
	if (test_and_set_bit(__IXGBE_DOWN, &adapter->state))
		return; /* do nothing if already down */

	/* disable receives */
	ixgbe_disable_rx(hw);

	/* disable all enabled rx queues */
	for (i = 0; i < adapter->num_rx_queues; i++)
		/* this call also flushes the previous write */
		ixgbe_disable_rx_queue(adapter, adapter->rx_ring[i]);

	usleep_range(10000, 20000);

	netif_tx_stop_all_queues(netdev);

	/* call carrier off first to avoid false dev_watchdog timeouts */
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	ixgbe_irq_disable(adapter);

	ixgbe_napi_disable_all(adapter);

	adapter->flags2 &= ~(IXGBE_FLAG2_FDIR_REQUIRES_REINIT |
			     IXGBE_FLAG2_RESET_REQUESTED);
	adapter->flags &= ~IXGBE_FLAG_NEED_LINK_UPDATE;

	del_timer_sync(&adapter->service_timer);

	if (adapter->num_vfs) {
		/* Clear EITR Select mapping */
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_EITRSEL, 0);

		/* Mark all the VFs as inactive */
		for (i = 0 ; i < adapter->num_vfs; i++)
			adapter->vfinfo[i].clear_to_send = 0;

		/* ping all the active vfs to let them know we are going down */
		ixgbe_ping_all_vfs(adapter);

		/* Disable all VFTE/VFRE TX/RX */
		ixgbe_disable_tx_rx(adapter);
	}

	/* disable transmits in the hardware now that interrupts are off */
	for (i = 0; i < adapter->num_tx_queues; i++) {
		u8 reg_idx = adapter->tx_ring[i]->reg_idx;
		IXGBE_WRITE_REG(hw, IXGBE_TXDCTL(reg_idx), IXGBE_TXDCTL_SWFLSH);
	}

	/* Disable the Tx DMA engine on 82599 and X540 */
	switch (hw->mac.type) {
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		IXGBE_WRITE_REG(hw, IXGBE_DMATXCTL,
				(IXGBE_READ_REG(hw, IXGBE_DMATXCTL) &
				 ~IXGBE_DMATXCTL_TE));
		break;
	default:
		break;
	}

#ifdef HAVE_PCI_ERS
	if (!pci_channel_offline(adapter->pdev))
#endif
		ixgbe_reset(adapter);

	/* power down the optics for 82599 SFP+ fiber */
	if (hw->mac.ops.disable_tx_laser)
		hw->mac.ops.disable_tx_laser(hw);

	ixgbe_clean_all_tx_rings(adapter);
	ixgbe_clean_all_rx_rings(adapter);
}

/**
 * ixgbe_sw_init - Initialize general software structures (struct ixgbe_adapter)
 * @adapter: board private structure to initialize
 *
 * ixgbe_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 **/
static int __devinit ixgbe_sw_init(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	int err;
	unsigned int fdir;
	u32 fwsm;
#ifdef CONFIG_DCB
	struct ixgbe_dcb_tc_config *tc;
	int j, bwg_pct;
#endif /* CONFIG_DCB */

#ifdef ENABLE_DNA
	if(    mtu != adapter->netdev->mtu
	   &&  mtu >= 68 
	   && (mtu + ETH_HLEN + ETH_FCS_LEN) <= IXGBE_MAX_JUMBO_FRAME_SIZE) {
	
        	if(unlikely(enable_debug))
			printk("[DNA] %s(): Setting mtu (%d) to %d\n",
	        	       __FUNCTION__, adapter->netdev->mtu, mtu);

		adapter->netdev->mtu = mtu;
	}
#endif

	/* PCI config space info */

	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);
	if (hw->revision_id == IXGBE_FAILED_READ_CFG_BYTE &&
	    ixgbe_check_cfg_remove(hw, pdev)) {
		e_err(probe, "read of revision id failed\n");
		err = -ENODEV;
		goto out;
	}
	hw->subsystem_vendor_id = pdev->subsystem_vendor;
	hw->subsystem_device_id = pdev->subsystem_device;

	err = ixgbe_init_shared_code(hw);
	if (err) {
		e_err(probe, "init_shared_code failed: %d\n", err);
		goto out;
	}
	adapter->mac_table = kzalloc(sizeof(struct ixgbe_mac_addr) *
				     hw->mac.num_rar_entries,
				     GFP_ATOMIC);

	/* Set common capability flags and settings */
#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
	adapter->flags |= IXGBE_FLAG_DCA_CAPABLE;
#endif
#ifdef IXGBE_FCOE
	adapter->flags |= IXGBE_FLAG_FCOE_CAPABLE;
	adapter->flags &= ~IXGBE_FLAG_FCOE_ENABLED;
#ifdef CONFIG_DCB
	/* Default traffic class to use for FCoE */
	adapter->fcoe.up = IXGBE_FCOE_DEFUP;
	adapter->fcoe.up_set = IXGBE_FCOE_DEFUP;
#endif /* IXGBE_DCB */
#endif /* IXGBE_FCOE */
	adapter->flags2 |= IXGBE_FLAG2_RSC_CAPABLE;
	fdir = min_t(int, IXGBE_MAX_FDIR_INDICES, num_online_cpus());
	adapter->ring_feature[RING_F_FDIR].limit = fdir;
	adapter->max_q_vectors = IXGBE_MAX_MSIX_Q_VECTORS_82599;

	/* Set MAC specific capability flags and exceptions */
	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		adapter->flags |= IXGBE_FLAGS_82598_INIT;
		adapter->flags2 &= ~IXGBE_FLAG2_RSC_CAPABLE;

		if (hw->device_id == IXGBE_DEV_ID_82598AT)
			adapter->flags |= IXGBE_FLAG_FAN_FAIL_CAPABLE;

		adapter->max_q_vectors = IXGBE_MAX_MSIX_Q_VECTORS_82598;
		adapter->ring_feature[RING_F_FDIR].limit = 0;
#ifdef IXGBE_FCOE
		adapter->flags &= ~IXGBE_FLAG_FCOE_CAPABLE;
#ifdef CONFIG_DCB
		adapter->fcoe.up = 0;
		adapter->fcoe.up_set = 0;
#endif /* IXGBE_DCB */
#endif /* IXGBE_FCOE */
		break;
	case ixgbe_mac_82599EB:
		adapter->flags |= IXGBE_FLAGS_82599_INIT;
		if (hw->device_id == IXGBE_DEV_ID_82599_T3_LOM)
			adapter->flags2 |= IXGBE_FLAG2_TEMP_SENSOR_CAPABLE;
#ifndef IXGBE_NO_SMART_SPEED
		hw->phy.smart_speed = ixgbe_smart_speed_on;
#else
		hw->phy.smart_speed = ixgbe_smart_speed_off;
#endif
		break;
	case ixgbe_mac_X540:
		adapter->flags |= IXGBE_FLAGS_X540_INIT;
		fwsm = IXGBE_READ_REG(hw, IXGBE_FWSM);
		if (fwsm & IXGBE_FWSM_TS_ENABLED)
			adapter->flags2 |= IXGBE_FLAG2_TEMP_SENSOR_CAPABLE;
		break;
	default:
		break;
	}

#ifdef IXGBE_FCOE
	/* FCoE support exists, always init the FCoE lock */
	spin_lock_init(&adapter->fcoe.lock);

#endif
	/* n-tuple support exists, always init our spinlock */
	spin_lock_init(&adapter->fdir_perfect_lock);

#ifdef CONFIG_DCB
	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
	case ixgbe_mac_82599EB:
		adapter->dcb_cfg.num_tcs.pg_tcs = 8;
		adapter->dcb_cfg.num_tcs.pfc_tcs = 8;
		break;
	case ixgbe_mac_X540:
		adapter->dcb_cfg.num_tcs.pg_tcs = 4;
		adapter->dcb_cfg.num_tcs.pfc_tcs = 4;
		break;
	default:
		adapter->dcb_cfg.num_tcs.pg_tcs = 1;
		adapter->dcb_cfg.num_tcs.pfc_tcs = 1;
		break;
	}

	/* Configure DCB traffic classes */
	bwg_pct = 100 / adapter->dcb_cfg.num_tcs.pg_tcs;
	for (j = 0; j < adapter->dcb_cfg.num_tcs.pg_tcs; j++) {
		tc = &adapter->dcb_cfg.tc_config[j];
		tc->path[IXGBE_DCB_TX_CONFIG].bwg_id = 0;
		tc->path[IXGBE_DCB_TX_CONFIG].bwg_percent = bwg_pct;
		tc->path[IXGBE_DCB_RX_CONFIG].bwg_id = 0;
		tc->path[IXGBE_DCB_RX_CONFIG].bwg_percent = bwg_pct;
		tc->pfc = ixgbe_dcb_pfc_disabled;
	}

	/* reset back to TC 0 */
	tc = &adapter->dcb_cfg.tc_config[0];

	/* total of all TCs bandwidth needs to be 100 */
	bwg_pct += 100 % adapter->dcb_cfg.num_tcs.pg_tcs;
	tc->path[IXGBE_DCB_TX_CONFIG].bwg_percent = bwg_pct;
	tc->path[IXGBE_DCB_RX_CONFIG].bwg_percent = bwg_pct;

	/* Initialize default user to priority mapping, UPx->TC0 */
	tc->path[IXGBE_DCB_TX_CONFIG].up_to_tc_bitmap = 0xFF;
	tc->path[IXGBE_DCB_RX_CONFIG].up_to_tc_bitmap = 0xFF;

	adapter->dcb_cfg.bw_percentage[IXGBE_DCB_TX_CONFIG][0] = 100;
	adapter->dcb_cfg.bw_percentage[IXGBE_DCB_RX_CONFIG][0] = 100;
	adapter->dcb_cfg.rx_pba_cfg = ixgbe_dcb_pba_equal;
	adapter->dcb_cfg.pfc_mode_enable = false;
	adapter->dcb_cfg.round_robin_enable = false;
	adapter->dcb_set_bitmap = 0x00;
	adapter->dcbx_cap = DCB_CAP_DCBX_HOST | DCB_CAP_DCBX_VER_CEE;
	memcpy(&adapter->temp_dcb_cfg, &adapter->dcb_cfg,
	       sizeof(adapter->temp_dcb_cfg));

#endif
	if (hw->mac.type == ixgbe_mac_82599EB ||
	    hw->mac.type == ixgbe_mac_X540)
		hw->mbx.ops.init_params(hw);

	/* default flow control settings */
#ifdef ENABLE_DNA
	hw->fc.requested_mode = ixgbe_fc_none;
	hw->fc.current_mode = ixgbe_fc_none;	/* init for ethtool output */
#else
	hw->fc.requested_mode = ixgbe_fc_full;
	hw->fc.current_mode = ixgbe_fc_full;	/* init for ethtool output */
#endif

	adapter->last_lfc_mode = hw->fc.current_mode;
	ixgbe_pbthresh_setup(adapter);
	hw->fc.pause_time = IXGBE_DEFAULT_FCPAUSE;
	hw->fc.send_xon = true;
#ifdef ENABLE_DNA
	hw->fc.disable_fc_autoneg = true;
#else
	hw->fc.disable_fc_autoneg = false;
#endif

#ifdef ENABLE_DNA
	adapter->tx_ring_count = max(num_tx_slots, (u32)IXGBE_MIN_TXD);
	adapter->tx_ring_count = min(adapter->tx_ring_count, (u32)IXGBE_MAX_TXD);
	adapter->tx_ring_count = ALIGN(adapter->tx_ring_count,IXGBE_REQ_TX_DESCRIPTOR_MULTIPLE);

	adapter->rx_ring_count = max(num_rx_slots, (u32)IXGBE_MIN_RXD);
	adapter->rx_ring_count = min(adapter->rx_ring_count, (u32)IXGBE_MAX_RXD);
	adapter->rx_ring_count = ALIGN(adapter->rx_ring_count,IXGBE_REQ_RX_DESCRIPTOR_MULTIPLE);
#else
	/* set default ring sizes */
	adapter->tx_ring_count = IXGBE_DEFAULT_TXD;
	adapter->rx_ring_count = IXGBE_DEFAULT_RXD;
#endif

	/* set default work limits */
	adapter->tx_work_limit = IXGBE_DEFAULT_TX_WORK;
	adapter->rx_work_limit = IXGBE_DEFAULT_RX_WORK;

	set_bit(__IXGBE_DOWN, &adapter->state);
out:
	return err;
}

/**
 * ixgbe_setup_tx_resources - allocate Tx resources (Descriptors)
 * @tx_ring:    tx descriptor ring (for a specific queue) to setup
 *
 * Return 0 on success, negative on failure
 **/
int ixgbe_setup_tx_resources(struct ixgbe_ring *tx_ring)
{
	struct device *dev = tx_ring->dev;
#ifndef ENABLE_DNA
	int orig_node = dev_to_node(dev);
#endif
	int numa_node = -1;
	int size;
#ifdef ENABLE_DNA
	int selected_cpu;
        int desc_copies = 1;
        struct ixgbe_adapter *adapter = netdev_priv(tx_ring->netdev);

        if(adapter->dna.dna_enabled)
		desc_copies = 2; /* Alloc shadow descriptors */

	selected_cpu = numa_cpu_affinity[adapter->bd_number];
	if (selected_cpu != -1) {
		if (cpu_online(selected_cpu)) {
			numa_node = cpu_to_node(selected_cpu);
			if (node_online(numa_node)) {
				tx_ring->q_vector->numa_node = numa_node;
				e_dev_info("selected numa node %d for tx memory allocation\n", 
				           numa_node);
			} else {
				printk("[DNA] %s(): Warning: numa node %d is not available\n",
				       __FUNCTION__, numa_node);
				numa_node = -1;
			}
		} else {
			printk("[DNA] %s(): Warning: cpu %d is not available\n",
			       __FUNCTION__, selected_cpu);
		}
	}
#endif

	size = sizeof(struct ixgbe_tx_buffer) * tx_ring->count;

#ifdef ENABLE_DNA
	if (numa_node == -1)
#endif
	if (tx_ring->q_vector)
		numa_node = tx_ring->q_vector->numa_node;

	tx_ring->tx_buffer_info = vzalloc_node(size, numa_node);
	if (!tx_ring->tx_buffer_info)
		tx_ring->tx_buffer_info = vzalloc(size);
	if (!tx_ring->tx_buffer_info)
		goto err;

	/* round up to nearest 4K */
	tx_ring->size = tx_ring->count * sizeof(union ixgbe_adv_tx_desc);
	tx_ring->size = ALIGN(tx_ring->size, 4096);

	set_dev_node(dev, numa_node);
	tx_ring->desc = dma_alloc_coherent(dev,
#ifdef ENABLE_DNA
					   desc_copies *
#endif
					   tx_ring->size,
					   &tx_ring->dma,
					   GFP_KERNEL);
#ifndef ENABLE_DNA
	set_dev_node(dev, orig_node);
#endif
	if (!tx_ring->desc)
		tx_ring->desc = dma_alloc_coherent(dev, 
#ifdef ENABLE_DNA
						   desc_copies *
#endif
						   tx_ring->size,
						   &tx_ring->dma, GFP_KERNEL);
	if (!tx_ring->desc)
		goto err;

	return 0;

err:
	vfree(tx_ring->tx_buffer_info);
	tx_ring->tx_buffer_info = NULL;
	dev_err(dev, "Unable to allocate memory for the Tx descriptor ring\n");
	return -ENOMEM;
}

/**
 * ixgbe_setup_all_tx_resources - allocate all queues Tx resources
 * @adapter: board private structure
 *
 * If this function returns with an error, then it's possible one or
 * more of the rings is populated (while the rest are not).  It is the
 * callers duty to clean those orphaned rings.
 *
 * Return 0 on success, negative on failure
 **/
static int ixgbe_setup_all_tx_resources(struct ixgbe_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_tx_queues; i++) {
		err = ixgbe_setup_tx_resources(adapter->tx_ring[i]);
		if (!err)
			continue;

		e_err(probe, "Allocation for Tx Queue %u failed\n", i);
		goto err_setup_tx;
	}

	return 0;
err_setup_tx:
	/* rewind the index freeing the rings as we go */
	while (i--)
		ixgbe_free_tx_resources(adapter->tx_ring[i]);
	return err;
}

/**
 * ixgbe_setup_rx_resources - allocate Rx resources (Descriptors)
 * @rx_ring:    rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 **/
int ixgbe_setup_rx_resources(struct ixgbe_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;
#ifndef ENABLE_DNA
	int orig_node = dev_to_node(dev);
#endif
	int numa_node = -1;
	int size;
#ifdef ENABLE_DNA
	int selected_cpu;
        int desc_copies = 1;
        struct ixgbe_adapter *adapter = netdev_priv(rx_ring->netdev);

        if(adapter->dna.dna_enabled)
		desc_copies = 2; /* Alloc shadow descriptors */

	selected_cpu = numa_cpu_affinity[adapter->bd_number];
	if (selected_cpu != -1) {
		if (cpu_online(selected_cpu)) {
			numa_node = cpu_to_node(selected_cpu);
			if (node_online(numa_node)) {
				rx_ring->q_vector->numa_node = numa_node;
				e_dev_info("selected numa node %d for rx memory allocation\n", 
				           numa_node);
			} else {
				printk("[DNA] %s(): Warning: numa node %d is not available\n",
				       __FUNCTION__, numa_node);
				numa_node = -1;
			}
		} else {
			printk("[DNA] %s(): Warning: cpu %d is not available\n",
			       __FUNCTION__, selected_cpu);
		}
	}
#endif

	size = sizeof(struct ixgbe_rx_buffer) * rx_ring->count;

#ifdef ENABLE_DNA
	if (numa_node == -1)
#endif
	if (rx_ring->q_vector)
		numa_node = rx_ring->q_vector->numa_node;

	rx_ring->rx_buffer_info = vzalloc_node(size, numa_node);
	if (!rx_ring->rx_buffer_info)
		rx_ring->rx_buffer_info = vzalloc(size);
	if (!rx_ring->rx_buffer_info)
		goto err;

	/* Round up to nearest 4K */
	rx_ring->size = rx_ring->count * sizeof(union ixgbe_adv_rx_desc);
	rx_ring->size = ALIGN(rx_ring->size, 4096);

	set_dev_node(dev, numa_node);
	rx_ring->desc = dma_alloc_coherent(dev,
#ifdef ENABLE_DNA
					   desc_copies *
#endif
					   rx_ring->size,
					   &rx_ring->dma,
					   GFP_KERNEL);
#ifndef ENABLE_DNA
	set_dev_node(dev, orig_node);
#endif
	if (!rx_ring->desc)
		rx_ring->desc = dma_alloc_coherent(dev, 
#ifdef ENABLE_DNA
						   desc_copies *
#endif
						   rx_ring->size,
						   &rx_ring->dma, GFP_KERNEL);
	if (!rx_ring->desc)
		goto err;

	return 0;
err:
	vfree(rx_ring->rx_buffer_info);
	rx_ring->rx_buffer_info = NULL;
	dev_err(dev, "Unable to allocate memory for the Rx descriptor ring\n");
	return -ENOMEM;
}

/**
 * ixgbe_setup_all_rx_resources - allocate all queues Rx resources
 * @adapter: board private structure
 *
 * If this function returns with an error, then it's possible one or
 * more of the rings is populated (while the rest are not).  It is the
 * callers duty to clean those orphaned rings.
 *
 * Return 0 on success, negative on failure
 **/
static int ixgbe_setup_all_rx_resources(struct ixgbe_adapter *adapter)
{
	int i, err = 0;

	for (i = 0; i < adapter->num_rx_queues; i++) {
		err = ixgbe_setup_rx_resources(adapter->rx_ring[i]);
		if (!err) {
			continue;
		}

		e_err(probe, "Allocation for Rx Queue %u failed\n", i);
		goto err_setup_rx;
	}

#ifdef IXGBE_FCOE
	err = ixgbe_setup_fcoe_ddp_resources(adapter);
	if (!err)
#endif
		return 0;
err_setup_rx:
	/* rewind the index freeing the rings as we go */
	while (i--)
		ixgbe_free_rx_resources(adapter->rx_ring[i]);
	return err;
}

/**
 * ixgbe_free_tx_resources - Free Tx Resources per Queue
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 **/
void ixgbe_free_tx_resources(struct ixgbe_ring *tx_ring)
{
#ifdef ENABLE_DNA
        int desc_copies = 1;
        struct ixgbe_adapter *adapter = netdev_priv(tx_ring->netdev);

        if(adapter->dna.dna_enabled)
		desc_copies = 2; /* Alloc shadow descriptors */
#endif

	ixgbe_clean_tx_ring(tx_ring);

	vfree(tx_ring->tx_buffer_info);
	tx_ring->tx_buffer_info = NULL;

	/* if not set, then don't free */
	if (!tx_ring->desc)
		return;

	dma_free_coherent(tx_ring->dev, 
#ifdef ENABLE_DNA
			  desc_copies *
#endif
			  tx_ring->size,
			  tx_ring->desc, tx_ring->dma);
	tx_ring->desc = NULL;
}

/**
 * ixgbe_free_all_tx_resources - Free Tx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all transmit software resources
 **/
static void ixgbe_free_all_tx_resources(struct ixgbe_adapter *adapter)
{
	int i;

	for (i = 0; i < adapter->num_tx_queues; i++)
		ixgbe_free_tx_resources(adapter->tx_ring[i]);
}

/**
 * ixgbe_free_rx_resources - Free Rx Resources
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 **/
void ixgbe_free_rx_resources(struct ixgbe_ring *rx_ring)
{
#ifdef ENABLE_DNA
        int desc_copies = 1;
        struct ixgbe_adapter *adapter = netdev_priv(rx_ring->netdev);

        if(adapter->dna.dna_enabled)
		desc_copies = 2; /* Alloc shadow descriptors */
#endif

	ixgbe_clean_rx_ring(rx_ring);

	vfree(rx_ring->rx_buffer_info);
	rx_ring->rx_buffer_info = NULL;

	/* if not set, then don't free */
	if (!rx_ring->desc)
		return;

	dma_free_coherent(rx_ring->dev, 
#ifdef ENABLE_DNA
			  desc_copies *
#endif
			  rx_ring->size,
			  rx_ring->desc, rx_ring->dma);

	rx_ring->desc = NULL;
}

/**
 * ixgbe_free_all_rx_resources - Free Rx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all receive software resources
 **/
static void ixgbe_free_all_rx_resources(struct ixgbe_adapter *adapter)
{
	int i;

#ifdef IXGBE_FCOE
	ixgbe_free_fcoe_ddp_resources(adapter);

#endif
	for (i = 0; i < adapter->num_rx_queues; i++)
		ixgbe_free_rx_resources(adapter->rx_ring[i]);
}

/**
 * ixgbe_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 **/
static int ixgbe_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN;

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled) {
		printk("[DNA] MTU resize at runtime is not YET supported on DNA\n");
		return -EINVAL;
	}
#endif

	/* MTU < 68 is an error and causes problems on some kernels */
	if ((new_mtu < 68) || (max_frame > IXGBE_MAX_JUMBO_FRAME_SIZE))
		return -EINVAL;

	/*
	 * For 82599EB we cannot allow legacy VFs to enable their receive
	 * paths when MTU greater than 1500 is configured.  So display a
	 * warning that legacy VFs will be disabled.
	 */
	if ((adapter->flags & IXGBE_FLAG_SRIOV_ENABLED) &&
	    (adapter->hw.mac.type == ixgbe_mac_82599EB) &&
	    (max_frame > (ETH_FRAME_LEN + ETH_FCS_LEN)))
		e_warn(probe, "Setting MTU > 1500 will disable legacy VFs\n");

	e_info(probe, "changing MTU from %d to %d\n", netdev->mtu, new_mtu);

	/* must set new MTU before calling down or up */
	netdev->mtu = new_mtu;

	if (netif_running(netdev))
		ixgbe_reinit_locked(adapter);

	return 0;
}

/**
 * ixgbe_open - Called when a network interface is made active
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
static int ixgbe_open(struct net_device *netdev)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	int err;

	/* disallow open during test */
	if (test_bit(__IXGBE_TESTING, &adapter->state))
		return -EBUSY;

	netif_carrier_off(netdev);

	/* allocate transmit descriptors */
	err = ixgbe_setup_all_tx_resources(adapter);
	if (err)
		goto err_setup_tx;

	/* allocate receive descriptors */
	err = ixgbe_setup_all_rx_resources(adapter);
	if (err)
		goto err_setup_rx;

	ixgbe_configure(adapter);

	err = ixgbe_request_irq(adapter);
	if (err)
		goto err_req_irq;

	/* Notify the stack of the actual queue counts. */
	netif_set_real_num_tx_queues(netdev,
				     adapter->num_rx_pools > 1 ? 1 :
				     adapter->num_tx_queues);

	err = netif_set_real_num_rx_queues(netdev,
					   adapter->num_rx_pools > 1 ? 1 :
					   adapter->num_rx_queues);
	if (err)
		goto err_set_queues;

#ifdef HAVE_PTP_1588_CLOCK
	ixgbe_ptp_init(adapter);
#endif /* HAVE_PTP_1588_CLOCK*/

	ixgbe_up_complete(adapter);

	return 0;

err_set_queues:
	ixgbe_free_irq(adapter);
err_req_irq:
	ixgbe_free_all_rx_resources(adapter);
err_setup_rx:
	ixgbe_free_all_tx_resources(adapter);
err_setup_tx:
	ixgbe_reset(adapter);

	return err;
}

/**
 * ixgbe_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 **/
static int ixgbe_close(struct net_device *netdev)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

#ifdef HAVE_PTP_1588_CLOCK
	ixgbe_ptp_stop(adapter);
#endif

	ixgbe_down(adapter);
	ixgbe_free_irq(adapter);

	ixgbe_fdir_filter_exit(adapter);

	ixgbe_free_all_tx_resources(adapter);
	ixgbe_free_all_rx_resources(adapter);

	ixgbe_release_hw_control(adapter);

	return 0;
}

#ifdef CONFIG_PM
static int ixgbe_resume(struct pci_dev *pdev)
{
	struct ixgbe_adapter *adapter = pci_get_drvdata(pdev);
	struct net_device *netdev = adapter->netdev;
	u32 err;

	adapter->hw.hw_addr = adapter->io_addr;
	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);
	/*
	 * pci_restore_state clears dev->state_saved so call
	 * pci_save_state to restore it.
	 */
	pci_save_state(pdev);

	err = pci_enable_device_mem(pdev);
	if (err) {
		e_dev_err("Cannot enable PCI device from suspend\n");
		return err;
	}
	smp_mb__before_clear_bit();
	clear_bit(__IXGBE_DISABLED, &adapter->state);
	pci_set_master(pdev);

	pci_wake_from_d3(pdev, false);

	ixgbe_reset(adapter);

	IXGBE_WRITE_REG(&adapter->hw, IXGBE_WUS, ~0);

	rtnl_lock();

	err = ixgbe_init_interrupt_scheme(adapter);
	if (!err && netif_running(netdev))
		err = ixgbe_open(netdev);

	rtnl_unlock();

	if (err)
		return err;

	netif_device_attach(netdev);

	return 0;
}
#endif /* CONFIG_PM */

/*
 * __ixgbe_shutdown is not used when power management
 * is disabled on older kernels (<2.6.12). causes a compile
 * warning/error, because it is defined and not used.
 */
#if defined(CONFIG_PM) || !defined(USE_REBOOT_NOTIFIER)
static int __ixgbe_shutdown(struct pci_dev *pdev, bool *enable_wake)
{
	struct ixgbe_adapter *adapter = pci_get_drvdata(pdev);
	struct net_device *netdev = adapter->netdev;
	struct ixgbe_hw *hw = &adapter->hw;
	u32 ctrl, fctrl;
	u32 wufc = adapter->wol;
#ifdef CONFIG_PM
	int retval = 0;
#endif

	netif_device_detach(netdev);

	rtnl_lock();

	if (netif_running(netdev)) {
		ixgbe_down(adapter);
		ixgbe_free_irq(adapter);

		ixgbe_free_all_tx_resources(adapter);
		ixgbe_free_all_rx_resources(adapter);
	}

	ixgbe_clear_interrupt_scheme(adapter);

	rtnl_unlock();

#ifdef CONFIG_PM
	retval = pci_save_state(pdev);
	if (retval)
		return retval;

#endif

	/* this won't stop link of managebility or WoL is enabled */
	if (hw->mac.type == ixgbe_mac_82599EB)
		ixgbe_stop_mac_link_on_d3_82599(hw);

	if (wufc) {
		ixgbe_set_rx_mode(netdev);

		/* enable the optics for 82599 SFP+ fiber as we can WoL */
		if (hw->mac.ops.enable_tx_laser)
			hw->mac.ops.enable_tx_laser(hw);

		/* turn on all-multi mode if wake on multicast is enabled */
		if (wufc & IXGBE_WUFC_MC) {
			fctrl = IXGBE_READ_REG(hw, IXGBE_FCTRL);
			fctrl |= IXGBE_FCTRL_MPE;
			IXGBE_WRITE_REG(hw, IXGBE_FCTRL, fctrl);
		}

		ctrl = IXGBE_READ_REG(hw, IXGBE_CTRL);
		ctrl |= IXGBE_CTRL_GIO_DIS;
		IXGBE_WRITE_REG(hw, IXGBE_CTRL, ctrl);

		IXGBE_WRITE_REG(hw, IXGBE_WUFC, wufc);
	} else {
		IXGBE_WRITE_REG(hw, IXGBE_WUC, 0);
		IXGBE_WRITE_REG(hw, IXGBE_WUFC, 0);
	}


	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		pci_wake_from_d3(pdev, false);
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		pci_wake_from_d3(pdev, !!wufc);
		break;
	default:
		break;
	}

	*enable_wake = !!wufc;

	ixgbe_release_hw_control(adapter);

	if (!test_and_set_bit(__IXGBE_DISABLED, &adapter->state))
		pci_disable_device(pdev);

	return 0;
}
#endif /* defined(CONFIG_PM) || !defined(USE_REBOOT_NOTIFIER) */

#ifdef CONFIG_PM
static int ixgbe_suspend(struct pci_dev *pdev, pm_message_t state)
{
	int retval;
	bool wake;

	retval = __ixgbe_shutdown(pdev, &wake);
	if (retval)
		return retval;

	if (wake) {
		pci_prepare_to_sleep(pdev);
	} else {
		pci_wake_from_d3(pdev, false);
		pci_set_power_state(pdev, PCI_D3hot);
	}

	return 0;
}
#endif /* CONFIG_PM */

#ifndef USE_REBOOT_NOTIFIER
static void ixgbe_shutdown(struct pci_dev *pdev)
{
	bool wake;

	__ixgbe_shutdown(pdev, &wake);

	if (system_state == SYSTEM_POWER_OFF) {
		pci_wake_from_d3(pdev, wake);
		pci_set_power_state(pdev, PCI_D3hot);
	}
}

#endif
#ifdef HAVE_NDO_GET_STATS64
/**
 * ixgbe_get_stats64 - Get System Network Statistics
 * @netdev: network interface device structure
 * @stats: storage space for 64bit statistics
 *
 * Returns 64bit statistics, for use in the ndo_get_stats64 callback. This
 * function replaces ixgbe_get_stats for kernels which support it.
 */
static struct rtnl_link_stats64 *ixgbe_get_stats64(struct net_device *netdev,
						   struct rtnl_link_stats64 *stats)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	int i;

	rcu_read_lock();
	for (i = 0; i < adapter->num_rx_queues; i++) {
		struct ixgbe_ring *ring = ACCESS_ONCE(adapter->rx_ring[i]);
		u64 bytes, packets;
		unsigned int start;

		if (ring) {
			do {
				start = u64_stats_fetch_begin_bh(&ring->syncp);
				packets = ring->stats.packets;
				bytes   = ring->stats.bytes;
			} while (u64_stats_fetch_retry_bh(&ring->syncp, start));
			stats->rx_packets += packets;
			stats->rx_bytes   += bytes;
		}
	}

	for (i = 0; i < adapter->num_tx_queues; i++) {
		struct ixgbe_ring *ring = ACCESS_ONCE(adapter->tx_ring[i]);
		u64 bytes, packets;
		unsigned int start;

		if (ring) {
			do {
				start = u64_stats_fetch_begin_bh(&ring->syncp);
				packets = ring->stats.packets;
				bytes   = ring->stats.bytes;
			} while (u64_stats_fetch_retry_bh(&ring->syncp, start));
			stats->tx_packets += packets;
			stats->tx_bytes   += bytes;
		}
	}
	rcu_read_unlock();
	/* following stats updated by ixgbe_watchdog_task() */
	stats->multicast	= netdev->stats.multicast;
	stats->rx_errors	= netdev->stats.rx_errors;
	stats->rx_length_errors	= netdev->stats.rx_length_errors;
	stats->rx_crc_errors	= netdev->stats.rx_crc_errors;
	stats->rx_missed_errors	= netdev->stats.rx_missed_errors;
	return stats;
}
#else
/**
 * ixgbe_get_stats - Get System Network Statistics
 * @netdev: network interface device structure
 *
 * Returns the address of the device statistics structure.
 * The statistics are actually updated from the timer callback.
 **/
static struct net_device_stats *ixgbe_get_stats(struct net_device *netdev)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	/* update the stats data */
	ixgbe_update_stats(adapter);

#ifdef HAVE_NETDEV_STATS_IN_NETDEV
	/* only return the current stats */
	return &netdev->stats;
#else
	/* only return the current stats */
	return &adapter->net_stats;
#endif /* HAVE_NETDEV_STATS_IN_NETDEV */
}
#endif
/**
 * ixgbe_update_stats - Update the board statistics counters.
 * @adapter: board private structure
 **/
void ixgbe_update_stats(struct ixgbe_adapter *adapter)
{
#ifdef HAVE_NETDEV_STATS_IN_NETDEV
	struct net_device_stats *net_stats = &adapter->netdev->stats;
#else
	struct net_device_stats *net_stats = &adapter->net_stats;
#endif /* HAVE_NETDEV_STATS_IN_NETDEV */
	struct ixgbe_hw *hw = &adapter->hw;
	struct ixgbe_hw_stats *hwstats = &adapter->stats;
	u64 total_mpc = 0;
	u32 i, missed_rx = 0, mpc, bprc, lxon, lxoff, xon_off_tot;
	u64 non_eop_descs = 0, restart_queue = 0, tx_busy = 0;
	u64 alloc_rx_page_failed = 0, alloc_rx_buff_failed = 0;
	u64 bytes = 0, packets = 0, hw_csum_rx_error = 0;
#ifndef IXGBE_NO_LRO
	u32 flushed = 0, coal = 0;
#endif

	if (test_bit(__IXGBE_DOWN, &adapter->state) ||
	    test_bit(__IXGBE_RESETTING, &adapter->state))
		return;

	if (adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED) {
		u64 rsc_count = 0;
		u64 rsc_flush = 0;
		for (i = 0; i < adapter->num_rx_queues; i++) {
			rsc_count += adapter->rx_ring[i]->rx_stats.rsc_count;
			rsc_flush += adapter->rx_ring[i]->rx_stats.rsc_flush;
		}
		adapter->rsc_total_count = rsc_count;
		adapter->rsc_total_flush = rsc_flush;
	}

#ifndef IXGBE_NO_LRO
	for (i = 0; i < adapter->num_q_vectors; i++) {
		struct ixgbe_q_vector *q_vector = adapter->q_vector[i];
		if (!q_vector)
			continue;
		flushed += q_vector->lrolist.stats.flushed;
		coal += q_vector->lrolist.stats.coal;
	}
	adapter->lro_stats.flushed = flushed;
	adapter->lro_stats.coal = coal;

#endif
	for (i = 0; i < adapter->num_rx_queues; i++) {
		struct ixgbe_ring *rx_ring = adapter->rx_ring[i];
		non_eop_descs += rx_ring->rx_stats.non_eop_descs;
		alloc_rx_page_failed += rx_ring->rx_stats.alloc_rx_page_failed;
		alloc_rx_buff_failed += rx_ring->rx_stats.alloc_rx_buff_failed;
		hw_csum_rx_error += rx_ring->rx_stats.csum_err;
		bytes += rx_ring->stats.bytes;
		packets += rx_ring->stats.packets;

	}
	adapter->non_eop_descs = non_eop_descs;
	adapter->alloc_rx_page_failed = alloc_rx_page_failed;
	adapter->alloc_rx_buff_failed = alloc_rx_buff_failed;
	adapter->hw_csum_rx_error = hw_csum_rx_error;
#ifdef ENABLE_DNA
	/* Avoid that the stats updated by DNA are cleared 
	   with those (wrong) that are inside the driver */
	if(adapter->dna.dna_enabled) {
		net_stats->rx_bytes = hwstats->gorc;
		net_stats->rx_packets = hwstats->gprc;
	} else {
#endif
	net_stats->rx_bytes = bytes;
	net_stats->rx_packets = packets;
#ifdef ENABLE_DNA
	}
#endif

	bytes = 0;
	packets = 0;
	/* gather some stats to the adapter struct that are per queue */
	for (i = 0; i < adapter->num_tx_queues; i++) {
		struct ixgbe_ring *tx_ring = adapter->tx_ring[i];
		restart_queue += tx_ring->tx_stats.restart_queue;
		tx_busy += tx_ring->tx_stats.tx_busy;
		bytes += tx_ring->stats.bytes;
		packets += tx_ring->stats.packets;
	}
	adapter->restart_queue = restart_queue;
	adapter->tx_busy = tx_busy;
#ifdef ENABLE_DNA
	/* Avoid that the stats updated by DNA are cleared 
	   with those (wrong) that are inside the driver */
	if(adapter->dna.dna_enabled) {
		net_stats->tx_bytes = hwstats->gotc;
		net_stats->tx_packets = hwstats->gptc;
	} else {
#endif
	net_stats->tx_bytes = bytes;
	net_stats->tx_packets = packets;
#ifdef ENABLE_DNA
	}
#endif

	hwstats->crcerrs += IXGBE_READ_REG(hw, IXGBE_CRCERRS);

	/* 8 register reads */
	for (i = 0; i < 8; i++) {
		/* for packet buffers not used, the register should read 0 */
#ifdef ENABLE_DNA
		if(!adapter->dna.dna_enabled) {
#endif
		mpc = IXGBE_READ_REG(hw, IXGBE_MPC(i));
		missed_rx += mpc;
		hwstats->mpc[i] += mpc;
		total_mpc += hwstats->mpc[i];
#ifdef ENABLE_DNA
		}
#endif
		hwstats->pxontxc[i] += IXGBE_READ_REG(hw, IXGBE_PXONTXC(i));
		hwstats->pxofftxc[i] += IXGBE_READ_REG(hw, IXGBE_PXOFFTXC(i));
		switch (hw->mac.type) {
		case ixgbe_mac_82598EB:
#ifdef ENABLE_DNA
			if(!adapter->dna.dna_enabled)
#endif
			hwstats->rnbc[i] += IXGBE_READ_REG(hw, IXGBE_RNBC(i));
			hwstats->qbtc[i] += IXGBE_READ_REG(hw, IXGBE_QBTC(i));
			hwstats->qbrc[i] += IXGBE_READ_REG(hw, IXGBE_QBRC(i));
			hwstats->pxonrxc[i] +=
				IXGBE_READ_REG(hw, IXGBE_PXONRXC(i));
			break;
		case ixgbe_mac_82599EB:
		case ixgbe_mac_X540:
			hwstats->pxonrxc[i] +=
				IXGBE_READ_REG(hw, IXGBE_PXONRXCNT(i));
			break;
		default:
			break;
		}
	}

	/*16 register reads */
	for (i = 0; i < 16; i++) {
		hwstats->qptc[i] += IXGBE_READ_REG(hw, IXGBE_QPTC(i));
		hwstats->qprc[i] += IXGBE_READ_REG(hw, IXGBE_QPRC(i));
		if ((hw->mac.type == ixgbe_mac_82599EB) ||
		    (hw->mac.type == ixgbe_mac_X540)) {
			hwstats->qbtc[i] += IXGBE_READ_REG(hw, IXGBE_QBTC_L(i));
			IXGBE_READ_REG(hw, IXGBE_QBTC_H(i)); /* to clear */
			hwstats->qbrc[i] += IXGBE_READ_REG(hw, IXGBE_QBRC_L(i));
			IXGBE_READ_REG(hw, IXGBE_QBRC_H(i)); /* to clear */
		}
	}

	hwstats->gprc += IXGBE_READ_REG(hw, IXGBE_GPRC);
	/* work around hardware counting issue */
	hwstats->gprc -= missed_rx;

	ixgbe_update_xoff_received(adapter);

	/* 82598 hardware only has a 32 bit counter in the high register */
	switch (hw->mac.type) {
	case ixgbe_mac_82598EB:
		hwstats->lxonrxc += IXGBE_READ_REG(hw, IXGBE_LXONRXC);
		hwstats->gorc += IXGBE_READ_REG(hw, IXGBE_GORCH);
		hwstats->gotc += IXGBE_READ_REG(hw, IXGBE_GOTCH);
		hwstats->tor += IXGBE_READ_REG(hw, IXGBE_TORH);
		break;
	case ixgbe_mac_X540:
		/* OS2BMC stats are X540 only*/
		hwstats->o2bgptc += IXGBE_READ_REG(hw, IXGBE_O2BGPTC);
		hwstats->o2bspc += IXGBE_READ_REG(hw, IXGBE_O2BSPC);
		hwstats->b2ospc += IXGBE_READ_REG(hw, IXGBE_B2OSPC);
		hwstats->b2ogprc += IXGBE_READ_REG(hw, IXGBE_B2OGPRC);
	case ixgbe_mac_82599EB:
#ifdef ENABLE_DNA
		if(!adapter->dna.dna_enabled)
#endif
		for (i = 0; i < 16; i++)
			adapter->hw_rx_no_dma_resources +=
					     IXGBE_READ_REG(hw, IXGBE_QPRDC(i));
		hwstats->gorc += IXGBE_READ_REG(hw, IXGBE_GORCL);
		IXGBE_READ_REG(hw, IXGBE_GORCH); /* to clear */
		hwstats->gotc += IXGBE_READ_REG(hw, IXGBE_GOTCL);
		IXGBE_READ_REG(hw, IXGBE_GOTCH); /* to clear */
		hwstats->tor += IXGBE_READ_REG(hw, IXGBE_TORL);
		IXGBE_READ_REG(hw, IXGBE_TORH); /* to clear */
		hwstats->lxonrxc += IXGBE_READ_REG(hw, IXGBE_LXONRXCNT);
#ifdef HAVE_TX_MQ
		hwstats->fdirmatch += IXGBE_READ_REG(hw, IXGBE_FDIRMATCH);
		hwstats->fdirmiss += IXGBE_READ_REG(hw, IXGBE_FDIRMISS);
#endif /* HAVE_TX_MQ */
#ifdef IXGBE_FCOE
		hwstats->fccrc += IXGBE_READ_REG(hw, IXGBE_FCCRC);
		hwstats->fclast += IXGBE_READ_REG(hw, IXGBE_FCLAST);
		hwstats->fcoerpdc += IXGBE_READ_REG(hw, IXGBE_FCOERPDC);
		hwstats->fcoeprc += IXGBE_READ_REG(hw, IXGBE_FCOEPRC);
		hwstats->fcoeptc += IXGBE_READ_REG(hw, IXGBE_FCOEPTC);
		hwstats->fcoedwrc += IXGBE_READ_REG(hw, IXGBE_FCOEDWRC);
		hwstats->fcoedwtc += IXGBE_READ_REG(hw, IXGBE_FCOEDWTC);
		/* Add up per cpu counters for total ddp alloc fail */
		if (adapter->fcoe.ddp_pool) {
			struct ixgbe_fcoe *fcoe = &adapter->fcoe;
			struct ixgbe_fcoe_ddp_pool *ddp_pool;
			unsigned int cpu;
			u64 noddp = 0, noddp_ext_buff = 0;
			for_each_possible_cpu(cpu) {
				ddp_pool = per_cpu_ptr(fcoe->ddp_pool, cpu);
				noddp += ddp_pool->noddp;
				noddp_ext_buff += ddp_pool->noddp_ext_buff;
			}
			hwstats->fcoe_noddp = noddp;
			hwstats->fcoe_noddp_ext_buff = noddp_ext_buff;
		}

#endif /* IXGBE_FCOE */
		break;
	default:
		break;
	}
	bprc = IXGBE_READ_REG(hw, IXGBE_BPRC);
	hwstats->bprc += bprc;
	hwstats->mprc += IXGBE_READ_REG(hw, IXGBE_MPRC);
	if (hw->mac.type == ixgbe_mac_82598EB)
		hwstats->mprc -= bprc;
	hwstats->roc += IXGBE_READ_REG(hw, IXGBE_ROC);
	hwstats->prc64 += IXGBE_READ_REG(hw, IXGBE_PRC64);
	hwstats->prc127 += IXGBE_READ_REG(hw, IXGBE_PRC127);
	hwstats->prc255 += IXGBE_READ_REG(hw, IXGBE_PRC255);
	hwstats->prc511 += IXGBE_READ_REG(hw, IXGBE_PRC511);
	hwstats->prc1023 += IXGBE_READ_REG(hw, IXGBE_PRC1023);
	hwstats->prc1522 += IXGBE_READ_REG(hw, IXGBE_PRC1522);
	hwstats->rlec += IXGBE_READ_REG(hw, IXGBE_RLEC);
	lxon = IXGBE_READ_REG(hw, IXGBE_LXONTXC);
	hwstats->lxontxc += lxon;
	lxoff = IXGBE_READ_REG(hw, IXGBE_LXOFFTXC);
	hwstats->lxofftxc += lxoff;
	hwstats->gptc += IXGBE_READ_REG(hw, IXGBE_GPTC);
	hwstats->mptc += IXGBE_READ_REG(hw, IXGBE_MPTC);
	/*
	 * 82598 errata - tx of flow control packets is included in tx counters
	 */
	xon_off_tot = lxon + lxoff;
	hwstats->gptc -= xon_off_tot;
	hwstats->mptc -= xon_off_tot;
	hwstats->gotc -= (xon_off_tot * (ETH_ZLEN + ETH_FCS_LEN));
	hwstats->ruc += IXGBE_READ_REG(hw, IXGBE_RUC);
	hwstats->rfc += IXGBE_READ_REG(hw, IXGBE_RFC);
	hwstats->rjc += IXGBE_READ_REG(hw, IXGBE_RJC);
	hwstats->tpr += IXGBE_READ_REG(hw, IXGBE_TPR);
	hwstats->ptc64 += IXGBE_READ_REG(hw, IXGBE_PTC64);
	hwstats->ptc64 -= xon_off_tot;
	hwstats->ptc127 += IXGBE_READ_REG(hw, IXGBE_PTC127);
	hwstats->ptc255 += IXGBE_READ_REG(hw, IXGBE_PTC255);
	hwstats->ptc511 += IXGBE_READ_REG(hw, IXGBE_PTC511);
	hwstats->ptc1023 += IXGBE_READ_REG(hw, IXGBE_PTC1023);
	hwstats->ptc1522 += IXGBE_READ_REG(hw, IXGBE_PTC1522);
	hwstats->bptc += IXGBE_READ_REG(hw, IXGBE_BPTC);
	/* Fill out the OS statistics structure */
	net_stats->multicast = hwstats->mprc;

	/* Rx Errors */
	net_stats->rx_errors = hwstats->crcerrs +
				       hwstats->rlec;
	net_stats->rx_dropped = 0;
	net_stats->rx_length_errors = hwstats->rlec;
	net_stats->rx_crc_errors = hwstats->crcerrs;
	net_stats->rx_missed_errors = total_mpc;

	/*
	 * VF Stats Collection - skip while resetting because these
	 * are not clear on read and otherwise you'll sometimes get
	 * crazy values.
	 */
	if (!test_bit(__IXGBE_RESETTING, &adapter->state)) {
		for (i = 0; i < adapter->num_vfs; i++) {
			UPDATE_VF_COUNTER_32bit(IXGBE_PVFGPRC(i),	      \
					adapter->vfinfo[i].last_vfstats.gprc, \
					adapter->vfinfo[i].vfstats.gprc);
			UPDATE_VF_COUNTER_32bit(IXGBE_PVFGPTC(i),	      \
					adapter->vfinfo[i].last_vfstats.gptc, \
					adapter->vfinfo[i].vfstats.gptc);
			UPDATE_VF_COUNTER_36bit(IXGBE_PVFGORC_LSB(i),	      \
					IXGBE_PVFGORC_MSB(i),		      \
					adapter->vfinfo[i].last_vfstats.gorc, \
					adapter->vfinfo[i].vfstats.gorc);
			UPDATE_VF_COUNTER_36bit(IXGBE_PVFGOTC_LSB(i),	      \
					IXGBE_PVFGOTC_MSB(i),		      \
					adapter->vfinfo[i].last_vfstats.gotc, \
					adapter->vfinfo[i].vfstats.gotc);
			UPDATE_VF_COUNTER_32bit(IXGBE_PVFMPRC(i),	      \
					adapter->vfinfo[i].last_vfstats.mprc, \
					adapter->vfinfo[i].vfstats.mprc);
		}
	}
}

#ifdef HAVE_TX_MQ
/**
 * ixgbe_fdir_reinit_subtask - worker thread to reinit FDIR filter table
 * @adapter - pointer to the device adapter structure
 **/
static void ixgbe_fdir_reinit_subtask(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	int i;

	if (!(adapter->flags2 & IXGBE_FLAG2_FDIR_REQUIRES_REINIT))
		return;

	adapter->flags2 &= ~IXGBE_FLAG2_FDIR_REQUIRES_REINIT;

	/* if interface is down do nothing */
	if (test_bit(__IXGBE_DOWN, &adapter->state))
		return;

	/* do nothing if we are not using signature filters */
	if (!(adapter->flags & IXGBE_FLAG_FDIR_HASH_CAPABLE))
		return;

	adapter->fdir_overflow++;

	if (ixgbe_reinit_fdir_tables_82599(hw) == 0) {
		for (i = 0; i < adapter->num_tx_queues; i++)
			set_bit(__IXGBE_TX_FDIR_INIT_DONE,
				&(adapter->tx_ring[i]->state));
		/* re-enable flow director interrupts */
		IXGBE_WRITE_REG(hw, IXGBE_EIMS, IXGBE_EIMS_FLOW_DIR);
	} else {
		e_err(probe, "failed to finish FDIR re-initialization, "
		      "ignored adding FDIR ATR filters\n");
	}
}

#endif /* HAVE_TX_MQ */
/**
 * ixgbe_check_hang_subtask - check for hung queues and dropped interrupts
 * @adapter - pointer to the device adapter structure
 *
 * This function serves two purposes.  First it strobes the interrupt lines
 * in order to make certain interrupts are occurring.  Secondly it sets the
 * bits needed to check for TX hangs.  As a result we should immediately
 * determine if a hang has occurred.
 */
static void ixgbe_check_hang_subtask(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u64 eics = 0;
	int i;

	/* If we're down or resetting, just bail */
	if (test_bit(__IXGBE_DOWN, &adapter->state) ||
	    test_bit(__IXGBE_REMOVE, &adapter->state) ||
	    test_bit(__IXGBE_RESETTING, &adapter->state))
		return;

	/* Force detection of hung controller */
	if (netif_carrier_ok(adapter->netdev)) {
		for (i = 0; i < adapter->num_tx_queues; i++)
			set_check_for_tx_hang(adapter->tx_ring[i]);
	}

	if (!(adapter->flags & IXGBE_FLAG_MSIX_ENABLED)) {
		/*
		 * for legacy and MSI interrupts don't set any bits
		 * that are enabled for EIAM, because this operation
		 * would set *both* EIMS and EICS for any bit in EIAM
		 */
		IXGBE_WRITE_REG(hw, IXGBE_EICS,
			(IXGBE_EICS_TCP_TIMER | IXGBE_EICS_OTHER));
	} else {
		/* get one bit for every active tx/rx interrupt vector */
		for (i = 0; i < adapter->num_q_vectors; i++) {
			struct ixgbe_q_vector *qv = adapter->q_vector[i];
			if (qv->rx.ring || qv->tx.ring)
				eics |= ((u64)1 << i);
		}
	}

	/* Cause software interrupt to ensure rings are cleaned */
	ixgbe_irq_rearm_queues(adapter, eics);
}

/**
 * ixgbe_watchdog_update_link - update the link status
 * @adapter - pointer to the device adapter structure
 * @link_speed - pointer to a u32 to store the link_speed
 **/
static void ixgbe_watchdog_update_link(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 link_speed = adapter->link_speed;
	bool link_up = adapter->link_up;
	bool pfc_en = adapter->dcb_cfg.pfc_mode_enable;

	if (!(adapter->flags & IXGBE_FLAG_NEED_LINK_UPDATE))
		return;

	if (hw->mac.ops.check_link) {
		hw->mac.ops.check_link(hw, &link_speed, &link_up, false);
	} else {
		/* always assume link is up, if no check link function */
		link_speed = IXGBE_LINK_SPEED_10GB_FULL;
		link_up = true;
	}

#ifdef HAVE_DCBNL_IEEE
	if (adapter->ixgbe_ieee_pfc)
		pfc_en |= !!(adapter->ixgbe_ieee_pfc->pfc_en);

#endif
	if (link_up && !((adapter->flags & IXGBE_FLAG_DCB_ENABLED) && pfc_en)) {
		hw->mac.ops.fc_enable(hw);
		ixgbe_set_rx_drop_en(adapter);
	}

	if (link_up ||
	    time_after(jiffies, (adapter->link_check_timeout +
				 IXGBE_TRY_LINK_TIMEOUT))) {
		adapter->flags &= ~IXGBE_FLAG_NEED_LINK_UPDATE;
		IXGBE_WRITE_REG(hw, IXGBE_EIMS, IXGBE_EIMC_LSC);
		IXGBE_WRITE_FLUSH(hw);
	}

	adapter->link_up = link_up;
	adapter->link_speed = link_speed;
}

static void ixgbe_update_default_up(struct ixgbe_adapter *adapter)
{
	u8 up = 0;
#ifdef HAVE_DCBNL_IEEE
	struct net_device *netdev = adapter->netdev;
	struct dcb_app app = {
			      .selector = DCB_APP_IDTYPE_ETHTYPE,
			      .protocol = 0,
			     };
	up = dcb_getapp(netdev, &app);
#endif

#ifdef IXGBE_FCOE
	adapter->default_up = (up > 1) ? (ffs(up) - 1) : 0;
#else
	adapter->default_up = up;
#endif
}

/**
 * ixgbe_watchdog_link_is_up - update netif_carrier status and
 *                             print link up message
 * @adapter - pointer to the device adapter structure
 **/
static void ixgbe_watchdog_link_is_up(struct ixgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct ixgbe_hw *hw = &adapter->hw;
	u32 link_speed = adapter->link_speed;
	bool flow_rx, flow_tx;

	/* only continue if link was previously down */
	if (netif_carrier_ok(netdev))
		return;

	adapter->flags2 &= ~IXGBE_FLAG2_SEARCH_FOR_SFP;

	switch (hw->mac.type) {
	case ixgbe_mac_82598EB: {
		u32 frctl = IXGBE_READ_REG(hw, IXGBE_FCTRL);
		u32 rmcs = IXGBE_READ_REG(hw, IXGBE_RMCS);
		flow_rx = !!(frctl & IXGBE_FCTRL_RFCE);
		flow_tx = !!(rmcs & IXGBE_RMCS_TFCE_802_3X);
	}
		break;
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540: {
		u32 mflcn = IXGBE_READ_REG(hw, IXGBE_MFLCN);
		u32 fccfg = IXGBE_READ_REG(hw, IXGBE_FCCFG);
		flow_rx = !!(mflcn & IXGBE_MFLCN_RFCE);
		flow_tx = !!(fccfg & IXGBE_FCCFG_TFCE_802_3X);
	}
		break;
	default:
		flow_tx = false;
		flow_rx = false;
		break;
	}

#ifdef HAVE_PTP_1588_CLOCK
	adapter->last_rx_ptp_check = jiffies;

	if (test_bit(__IXGBE_PTP_RUNNING, &adapter->state))
		ixgbe_ptp_start_cyclecounter(adapter);

#endif
	e_info(drv, "NIC Link is Up %s, Flow Control: %s\n",
	       (link_speed == IXGBE_LINK_SPEED_10GB_FULL ?
	       "10 Gbps" :
	       (link_speed == IXGBE_LINK_SPEED_1GB_FULL ?
	       "1 Gbps" :
	       (link_speed == IXGBE_LINK_SPEED_100_FULL ?
	       "100 Mbps" :
	       "unknown speed"))),
	       ((flow_rx && flow_tx) ? "RX/TX" :
	       (flow_rx ? "RX" :
	       (flow_tx ? "TX" : "None"))));

	netif_carrier_on(netdev);
#ifdef IFLA_VF_MAX
	ixgbe_check_vf_rate_limit(adapter);
#endif /* IFLA_VF_MAX */
	netif_tx_wake_all_queues(netdev);

	/* update the default user priority for VFs */
	ixgbe_update_default_up(adapter);

	/* ping all the active vfs to let them know link has changed */
	ixgbe_ping_all_vfs(adapter);
}

/**
 * ixgbe_watchdog_link_is_down - update netif_carrier status and
 *                               print link down message
 * @adapter - pointer to the adapter structure
 **/
static void ixgbe_watchdog_link_is_down(struct ixgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct ixgbe_hw *hw = &adapter->hw;

	adapter->link_up = false;
	adapter->link_speed = 0;

	/* only continue if link was up previously */
	if (!netif_carrier_ok(netdev))
		return;

	/* poll for SFP+ cable when link is down */
	if (ixgbe_is_sfp(hw) && hw->mac.type == ixgbe_mac_82598EB)
		adapter->flags2 |= IXGBE_FLAG2_SEARCH_FOR_SFP;

#ifdef HAVE_PTP_1588_CLOCK
	if (test_bit(__IXGBE_PTP_RUNNING, &adapter->state))
		ixgbe_ptp_start_cyclecounter(adapter);

#endif
	e_info(drv, "NIC Link is Down\n");
	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	/* ping all the active vfs to let them know link has changed */
	ixgbe_ping_all_vfs(adapter);
}

/**
 * ixgbe_watchdog_flush_tx - flush queues on link down
 * @adapter - pointer to the device adapter structure
 **/
static void ixgbe_watchdog_flush_tx(struct ixgbe_adapter *adapter)
{
	int i;
	int some_tx_pending = 0;

	if (!netif_carrier_ok(adapter->netdev)) {
		for (i = 0; i < adapter->num_tx_queues; i++) {
			struct ixgbe_ring *tx_ring = adapter->tx_ring[i];
			if (tx_ring->next_to_use != tx_ring->next_to_clean) {
				some_tx_pending = 1;
				break;
			}
		}

		if (some_tx_pending) {
			/* We've lost link, so the controller stops DMA,
			 * but we've got queued Tx work that's never going
			 * to get done, so reset controller to flush Tx.
			 * (Do the reset outside of interrupt context).
			 */
			e_warn(drv, "initiating reset due to lost link with pending Tx work\n");
			adapter->flags2 |= IXGBE_FLAG2_RESET_REQUESTED;
		}
	}
}

static void ixgbe_spoof_check(struct ixgbe_adapter *adapter)
{
	u32 ssvpc;

	/* Do not perform spoof check for 82598 or if in non-IOV mode */
	if (adapter->hw.mac.type == ixgbe_mac_82598EB ||
	    adapter->num_vfs == 0)
		return;

	ssvpc = IXGBE_READ_REG(&adapter->hw, IXGBE_SSVPC);

	/*
	 * ssvpc register is cleared on read, if zero then no
	 * spoofed packets in the last interval.
	 */
	if (!ssvpc)
		return;

	e_warn(drv, "%d Spoofed packets detected\n", ssvpc);
}

/**
 * ixgbe_watchdog_subtask - check and bring link up
 * @adapter - pointer to the device adapter structure
 **/
static void ixgbe_watchdog_subtask(struct ixgbe_adapter *adapter)
{
	/* if interface is down do nothing */
	if (test_bit(__IXGBE_DOWN, &adapter->state) ||
	    test_bit(__IXGBE_REMOVE, &adapter->state) ||
	    test_bit(__IXGBE_RESETTING, &adapter->state))
		return;

	ixgbe_watchdog_update_link(adapter);

	if (adapter->link_up)
		ixgbe_watchdog_link_is_up(adapter);
	else
		ixgbe_watchdog_link_is_down(adapter);

	ixgbe_spoof_check(adapter);
	ixgbe_update_stats(adapter);

	ixgbe_watchdog_flush_tx(adapter);
}

/**
 * ixgbe_sfp_detection_subtask - poll for SFP+ cable
 * @adapter - the ixgbe adapter structure
 **/
static void ixgbe_sfp_detection_subtask(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	s32 err;

	/* not searching for SFP so there is nothing to do here */
	if (!(adapter->flags2 & IXGBE_FLAG2_SEARCH_FOR_SFP) &&
	    !(adapter->flags2 & IXGBE_FLAG2_SFP_NEEDS_RESET))
		return;

	/* someone else is in init, wait until next service event */
	if (test_and_set_bit(__IXGBE_IN_SFP_INIT, &adapter->state))
		return;

	err = hw->phy.ops.identify_sfp(hw);
	if (err == IXGBE_ERR_SFP_NOT_SUPPORTED)
		goto sfp_out;

	if (err == IXGBE_ERR_SFP_NOT_PRESENT) {
		/* If no cable is present, then we need to reset
		 * the next time we find a good cable. */
		adapter->flags2 |= IXGBE_FLAG2_SFP_NEEDS_RESET;
	}

	/* exit on error */
	if (err)
		goto sfp_out;

	/* exit if reset not needed */
	if (!(adapter->flags2 & IXGBE_FLAG2_SFP_NEEDS_RESET))
		goto sfp_out;

	adapter->flags2 &= ~IXGBE_FLAG2_SFP_NEEDS_RESET;

	/*
	 * A module may be identified correctly, but the EEPROM may not have
	 * support for that module.  setup_sfp() will fail in that case, so
	 * we should not allow that module to load.
	 */
	if (hw->mac.type == ixgbe_mac_82598EB)
		err = hw->phy.ops.reset(hw);
	else
		err = hw->mac.ops.setup_sfp(hw);

	if (err == IXGBE_ERR_SFP_NOT_SUPPORTED)
		goto sfp_out;

	adapter->flags |= IXGBE_FLAG_NEED_LINK_CONFIG;
	e_info(probe, "detected SFP+: %d\n", hw->phy.sfp_type);

sfp_out:
	clear_bit(__IXGBE_IN_SFP_INIT, &adapter->state);

	if ((err == IXGBE_ERR_SFP_NOT_SUPPORTED) &&
	    adapter->netdev_registered) {
		e_dev_err("failed to initialize because an unsupported "
			  "SFP+ module type was detected.\n");
		e_dev_err("Reload the driver after installing a "
			  "supported module.\n");
		unregister_netdev(adapter->netdev);
		adapter->netdev_registered = false;
	}
}

/**
 * ixgbe_sfp_link_config_subtask - set up link SFP after module install
 * @adapter - the ixgbe adapter structure
 **/
static void ixgbe_sfp_link_config_subtask(struct ixgbe_adapter *adapter)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 speed;
	bool autoneg = false;

	if (!(adapter->flags & IXGBE_FLAG_NEED_LINK_CONFIG))
		return;

	/* someone else is in init, wait until next service event */
	if (test_and_set_bit(__IXGBE_IN_SFP_INIT, &adapter->state))
		return;

	adapter->flags &= ~IXGBE_FLAG_NEED_LINK_CONFIG;

	speed = hw->phy.autoneg_advertised;
	if ((!speed) && (hw->mac.ops.get_link_capabilities)) {
		hw->mac.ops.get_link_capabilities(hw, &speed, &autoneg);
		/* setup the highest link when no autoneg */
		if (!autoneg) {
			if (speed & IXGBE_LINK_SPEED_10GB_FULL)
				speed = IXGBE_LINK_SPEED_10GB_FULL;
		}
	}

	if (hw->mac.ops.setup_link)
		hw->mac.ops.setup_link(hw, speed, true);

	adapter->flags |= IXGBE_FLAG_NEED_LINK_UPDATE;
	adapter->link_check_timeout = jiffies;
	clear_bit(__IXGBE_IN_SFP_INIT, &adapter->state);
}

#ifdef CONFIG_PCI_IOV
static void ixgbe_check_for_bad_vf(struct ixgbe_adapter *adapter)
{
	int vf;
	struct ixgbe_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	u32 gpc;
	u32 ciaa, ciad;

	gpc = IXGBE_READ_REG(hw, IXGBE_TXDGPC);
	if (gpc) /* If incrementing then no need for the check below */
		return;
	/*
	 * Check to see if a bad DMA write target from an errant or
	 * malicious VF has caused a PCIe error.  If so then we can
	 * issue a VFLR to the offending VF(s) and then resume without
	 * requesting a full slot reset.
	 */

	for (vf = 0; vf < adapter->num_vfs; vf++) {
		ciaa = (vf << 16) | 0x80000000;
		/* 32 bit read so align, we really want status at offset 6 */
		ciaa |= PCI_COMMAND;
		IXGBE_WRITE_REG(hw, IXGBE_CIAA_82599, ciaa);
		ciad = IXGBE_READ_REG(hw, IXGBE_CIAD_82599);
		ciaa &= 0x7FFFFFFF;
		/* disable debug mode asap after reading data */
		IXGBE_WRITE_REG(hw, IXGBE_CIAA_82599, ciaa);
		/* Get the upper 16 bits which will be the PCI status reg */
		ciad >>= 16;
		if (ciad & PCI_STATUS_REC_MASTER_ABORT) {
			netdev_err(netdev, "VF %d Hung DMA\n", vf);
			/* Issue VFLR */
			ciaa = (vf << 16) | 0x80000000;
			ciaa |= 0xA8;
			IXGBE_WRITE_REG(hw, IXGBE_CIAA_82599, ciaa);
			ciad = 0x00008000;  /* VFLR */
			IXGBE_WRITE_REG(hw, IXGBE_CIAD_82599, ciad);
			ciaa &= 0x7FFFFFFF;
			IXGBE_WRITE_REG(hw, IXGBE_CIAA_82599, ciaa);
		}
	}
}

#endif
/**
 * ixgbe_service_timer - Timer Call-back
 * @data: pointer to adapter cast into an unsigned long
 **/
static void ixgbe_service_timer(unsigned long data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	unsigned long next_event_offset;
	bool ready = true;

	/* poll faster when waiting for link */
	if (adapter->flags & IXGBE_FLAG_NEED_LINK_UPDATE)
		next_event_offset = HZ / 10;
	else
		next_event_offset = HZ * 2;

#ifdef CONFIG_PCI_IOV
	/*
	 * don't bother with SR-IOV VF DMA hang check if there are
	 * no VFs or the link is down
	 */
	if (!adapter->num_vfs ||
	    (adapter->flags & IXGBE_FLAG_NEED_LINK_UPDATE))
		goto normal_timer_service;

	/* If we have VFs allocated then we must check for DMA hangs */
	ixgbe_check_for_bad_vf(adapter);
	next_event_offset = HZ / 50;
	adapter->timer_event_accumulator++;

	if (adapter->timer_event_accumulator >= 100)
		adapter->timer_event_accumulator = 0;
	else
		ready = false;

normal_timer_service:
#endif
	/* Reset the timer */
	mod_timer(&adapter->service_timer, next_event_offset + jiffies);

	if (ready)
		ixgbe_service_event_schedule(adapter);
}

static void ixgbe_reset_subtask(struct ixgbe_adapter *adapter)
{
	if (!(adapter->flags2 & IXGBE_FLAG2_RESET_REQUESTED))
		return;

	adapter->flags2 &= ~IXGBE_FLAG2_RESET_REQUESTED;

	/* If we're already down or resetting, just bail */
	if (test_bit(__IXGBE_DOWN, &adapter->state) ||
	    test_bit(__IXGBE_REMOVE, &adapter->state) ||
	    test_bit(__IXGBE_RESETTING, &adapter->state))
		return;

	netdev_err(adapter->netdev, "Reset adapter\n");
	adapter->tx_timeout_count++;

	rtnl_lock();
	ixgbe_reinit_locked(adapter);
	rtnl_unlock();
}

/**
 * ixgbe_service_task - manages and runs subtasks
 * @work: pointer to work_struct containing our data
 **/
static void ixgbe_service_task(struct work_struct *work)
{
	struct ixgbe_adapter *adapter = container_of(work,
						     struct ixgbe_adapter,
						     service_task);
#if 0 /* ifdef ENABLE_DNA */
	struct ixgbe_hw *hw = &adapter->hw;
	struct ethtool_pauseparam pause;

	if (hw->fc.requested_mode != ixgbe_fc_none || hw->fc.disable_fc_autoneg == false) {
		pause.rx_pause = pause.tx_pause = pause.autoneg = false;
		adapter->netdev->ethtool_ops->set_pauseparam(adapter->netdev, &pause);
	}
#endif

	if (IXGBE_REMOVED(adapter->hw.hw_addr)) {
		if (!test_bit(__IXGBE_DOWN, &adapter->state)) {
			rtnl_lock();
			ixgbe_down(adapter);
			rtnl_unlock();
		}
		ixgbe_service_event_complete(adapter);
		return;
	}
	ixgbe_reset_subtask(adapter);
	ixgbe_sfp_detection_subtask(adapter);
	ixgbe_sfp_link_config_subtask(adapter);
	ixgbe_check_overtemp_subtask(adapter);
	ixgbe_watchdog_subtask(adapter);
#ifdef HAVE_TX_MQ
	ixgbe_fdir_reinit_subtask(adapter);
#endif
	ixgbe_check_hang_subtask(adapter);
#ifdef HAVE_PTP_1588_CLOCK
	if (test_bit(__IXGBE_PTP_RUNNING, &adapter->state)) {
		ixgbe_ptp_overflow_check(adapter);
		ixgbe_ptp_rx_hang(adapter);
	}
#endif

	ixgbe_service_event_complete(adapter);
}


static int ixgbe_tso(struct ixgbe_ring *tx_ring,
		     struct ixgbe_tx_buffer *first,
		     u8 *hdr_len)
{
#ifdef NETIF_F_TSO
	struct sk_buff *skb = first->skb;
	u32 vlan_macip_lens, type_tucmd;
	u32 mss_l4len_idx, l4len;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (!skb_is_gso(skb))
#endif /* NETIF_F_TSO */
		return 0;
#ifdef NETIF_F_TSO

	if (skb_header_cloned(skb)) {
		int err = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
		if (err)
			return err;
	}

	/* ADV DTYP TUCMD MKRLOC/ISCSIHEDLEN */
	type_tucmd = IXGBE_ADVTXD_TUCMD_L4T_TCP;

	if (first->protocol == __constant_htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);
		iph->tot_len = 0;
		iph->check = 0;
		tcp_hdr(skb)->check = ~csum_tcpudp_magic(iph->saddr,
							 iph->daddr, 0,
							 IPPROTO_TCP,
							 0);
		type_tucmd |= IXGBE_ADVTXD_TUCMD_IPV4;
		first->tx_flags |= IXGBE_TX_FLAGS_TSO |
				   IXGBE_TX_FLAGS_CSUM |
				   IXGBE_TX_FLAGS_IPV4;
#ifdef NETIF_F_TSO6
	} else if (skb_is_gso_v6(skb)) {
		ipv6_hdr(skb)->payload_len = 0;
		tcp_hdr(skb)->check =
		    ~csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
				     &ipv6_hdr(skb)->daddr,
				     0, IPPROTO_TCP, 0);
		first->tx_flags |= IXGBE_TX_FLAGS_TSO |
				   IXGBE_TX_FLAGS_CSUM;
#endif
	}

	/* compute header lengths */
	l4len = tcp_hdrlen(skb);
	*hdr_len = skb_transport_offset(skb) + l4len;

	/* update gso size and bytecount with header size */
	first->gso_segs = skb_shinfo(skb)->gso_segs;
	first->bytecount += (first->gso_segs - 1) * *hdr_len;

	/* mss_l4len_id: use 0 as index for TSO */
	mss_l4len_idx = l4len << IXGBE_ADVTXD_L4LEN_SHIFT;
	mss_l4len_idx |= skb_shinfo(skb)->gso_size << IXGBE_ADVTXD_MSS_SHIFT;

	/* vlan_macip_lens: HEADLEN, MACLEN, VLAN tag */
	vlan_macip_lens = skb_network_header_len(skb);
	vlan_macip_lens |= skb_network_offset(skb) << IXGBE_ADVTXD_MACLEN_SHIFT;
	vlan_macip_lens |= first->tx_flags & IXGBE_TX_FLAGS_VLAN_MASK;

	ixgbe_tx_ctxtdesc(tx_ring, vlan_macip_lens, 0, type_tucmd,
			  mss_l4len_idx);

	return 1;
#endif
}

static void ixgbe_tx_csum(struct ixgbe_ring *tx_ring,
			  struct ixgbe_tx_buffer *first)
{
	struct sk_buff *skb = first->skb;
	u32 vlan_macip_lens = 0;
	u32 mss_l4len_idx = 0;
	u32 type_tucmd = 0;

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		if (!(first->tx_flags & IXGBE_TX_FLAGS_HW_VLAN) &&
		    !(first->tx_flags & IXGBE_TX_FLAGS_CC))
			return;
	} else {
		u8 l4_hdr = 0;
		switch (first->protocol) {
		case __constant_htons(ETH_P_IP):
			vlan_macip_lens |= skb_network_header_len(skb);
			type_tucmd |= IXGBE_ADVTXD_TUCMD_IPV4;
			l4_hdr = ip_hdr(skb)->protocol;
			break;
#ifdef NETIF_F_IPV6_CSUM
		case __constant_htons(ETH_P_IPV6):
			vlan_macip_lens |= skb_network_header_len(skb);
			l4_hdr = ipv6_hdr(skb)->nexthdr;
			break;
#endif
		default:
			if (unlikely(net_ratelimit())) {
				dev_warn(tx_ring->dev,
				 "partial checksum but proto=%x!\n",
				 first->protocol);
			}
			break;
		}

		switch (l4_hdr) {
		case IPPROTO_TCP:
			type_tucmd |= IXGBE_ADVTXD_TUCMD_L4T_TCP;
			mss_l4len_idx = tcp_hdrlen(skb) <<
					IXGBE_ADVTXD_L4LEN_SHIFT;
			break;
#ifdef HAVE_SCTP
		case IPPROTO_SCTP:
			type_tucmd |= IXGBE_ADVTXD_TUCMD_L4T_SCTP;
			mss_l4len_idx = sizeof(struct sctphdr) <<
					IXGBE_ADVTXD_L4LEN_SHIFT;
			break;
#endif
		case IPPROTO_UDP:
			mss_l4len_idx = sizeof(struct udphdr) <<
					IXGBE_ADVTXD_L4LEN_SHIFT;
			break;
		default:
			if (unlikely(net_ratelimit())) {
				dev_warn(tx_ring->dev,
				 "partial checksum but l4 proto=%x!\n",
				 l4_hdr);
			}
			break;
		}

		/* update TX checksum flag */
		first->tx_flags |= IXGBE_TX_FLAGS_CSUM;
	}

	/* vlan_macip_lens: MACLEN, VLAN tag */
	vlan_macip_lens |= skb_network_offset(skb) << IXGBE_ADVTXD_MACLEN_SHIFT;
	vlan_macip_lens |= first->tx_flags & IXGBE_TX_FLAGS_VLAN_MASK;

	ixgbe_tx_ctxtdesc(tx_ring, vlan_macip_lens, 0,
			  type_tucmd, mss_l4len_idx);
}

#define IXGBE_SET_FLAG(_input, _flag, _result) \
	((_flag <= _result) ? \
	 ((u32)(_input & _flag) * (_result / _flag)) : \
	 ((u32)(_input & _flag) / (_flag / _result)))

static u32 ixgbe_tx_cmd_type(u32 tx_flags)
{
	/* set type for advanced descriptor with frame checksum insertion */
	u32 cmd_type = IXGBE_ADVTXD_DTYP_DATA |
		       IXGBE_ADVTXD_DCMD_DEXT |
		       IXGBE_ADVTXD_DCMD_IFCS;

	/* set HW vlan bit if vlan is present */
	cmd_type |= IXGBE_SET_FLAG(tx_flags, IXGBE_TX_FLAGS_HW_VLAN,
				   IXGBE_ADVTXD_DCMD_VLE);

	/* set segmentation enable bits for TSO/FSO */
	cmd_type |= IXGBE_SET_FLAG(tx_flags, IXGBE_TX_FLAGS_TSO,
				   IXGBE_ADVTXD_DCMD_TSE);

	/* set timestamp bit if present */
	cmd_type |= IXGBE_SET_FLAG(tx_flags, IXGBE_TX_FLAGS_TSTAMP,
				   IXGBE_ADVTXD_MAC_TSTAMP);

	return cmd_type;
}

static void ixgbe_tx_olinfo_status(union ixgbe_adv_tx_desc *tx_desc,
				   u32 tx_flags, unsigned int paylen)
{
	u32 olinfo_status = paylen << IXGBE_ADVTXD_PAYLEN_SHIFT;

	/* enable L4 checksum for TSO and TX checksum offload */
	olinfo_status |= IXGBE_SET_FLAG(tx_flags,
					IXGBE_TX_FLAGS_CSUM,
					IXGBE_ADVTXD_POPTS_TXSM);

	/* enble IPv4 checksum for TSO */
	olinfo_status |= IXGBE_SET_FLAG(tx_flags,
					IXGBE_TX_FLAGS_IPV4,
					IXGBE_ADVTXD_POPTS_IXSM);

	/*
	 * Check Context must be set if Tx switch is enabled, which it
	 * always is for case where virtual functions are running
	 */
	olinfo_status |= IXGBE_SET_FLAG(tx_flags,
					IXGBE_TX_FLAGS_CC,
					IXGBE_ADVTXD_CC);

	tx_desc->read.olinfo_status = cpu_to_le32(olinfo_status);
}

#define IXGBE_TXD_CMD (IXGBE_TXD_CMD_EOP | \
		       IXGBE_TXD_CMD_RS)

static void ixgbe_tx_map(struct ixgbe_ring *tx_ring,
			 struct ixgbe_tx_buffer *first,
			 const u8 hdr_len)
{
	struct sk_buff *skb = first->skb;
	struct ixgbe_tx_buffer *tx_buffer;
	union ixgbe_adv_tx_desc *tx_desc;
	struct skb_frag_struct *frag;
	dma_addr_t dma;
	unsigned int data_len, size;
	u32 tx_flags = first->tx_flags;
	u32 cmd_type = ixgbe_tx_cmd_type(tx_flags);
	u16 i = tx_ring->next_to_use;
#ifdef ENABLE_DNA
        struct ixgbe_adapter *adapter = netdev_priv(tx_ring->netdev);

        if(adapter->dna.dna_enabled)
		return; /* We don't allow apps to send data */	
#endif

	tx_desc = IXGBE_TX_DESC(tx_ring, i);

	ixgbe_tx_olinfo_status(tx_desc, tx_flags, skb->len - hdr_len);

	size = skb_headlen(skb);
	data_len = skb->data_len;

#ifdef IXGBE_FCOE
	if (tx_flags & IXGBE_TX_FLAGS_FCOE) {
		if (data_len < sizeof(struct fcoe_crc_eof)) {
			size -= sizeof(struct fcoe_crc_eof) - data_len;
			data_len = 0;
		} else {
			data_len -= sizeof(struct fcoe_crc_eof);
		}
	}

#endif
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
				cpu_to_le32(cmd_type ^ IXGBE_MAX_DATA_PER_TXD);

			i++;
			tx_desc++;
			if (i == tx_ring->count) {
				tx_desc = IXGBE_TX_DESC(tx_ring, 0);
				i = 0;
			}
			tx_desc->read.olinfo_status = 0;

			dma += IXGBE_MAX_DATA_PER_TXD;
			size -= IXGBE_MAX_DATA_PER_TXD;

			tx_desc->read.buffer_addr = cpu_to_le64(dma);
		}

		if (likely(!data_len))
			break;

		tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type ^ size);

		i++;
		tx_desc++;
		if (i == tx_ring->count) {
			tx_desc = IXGBE_TX_DESC(tx_ring, 0);
			i = 0;
		}
		tx_desc->read.olinfo_status = 0;

#ifdef IXGBE_FCOE
		size = min_t(unsigned int, data_len, skb_frag_size(frag));
#else
		size = skb_frag_size(frag);
#endif
		data_len -= size;

		dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size,
				       DMA_TO_DEVICE);

		tx_buffer = &tx_ring->tx_buffer_info[i];
	}

	/* write last descriptor with RS and EOP bits */
	cmd_type |= size | IXGBE_TXD_CMD;
	tx_desc->read.cmd_type_len = cpu_to_le32(cmd_type);

	netdev_tx_sent_queue(netdev_get_tx_queue(tx_ring->netdev,
						 tx_ring->queue_index),
			     first->bytecount);

	/* set the timestamp */
	first->time_stamp = jiffies;

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

	/* notify HW of packet */
	ixgbe_write_tail(tx_ring, i);

	/*
	 * we need this if more than one processor can write to our tail
	 * at a time, it synchronizes IO on IA64/Altix systems
	 */
	mmiowb();

	return;
dma_error:
	dev_err(tx_ring->dev, "TX DMA map failed\n");

	/* clear dma mappings for failed tx_buffer_info map */
	for (;;) {
		tx_buffer = &tx_ring->tx_buffer_info[i];
		ixgbe_unmap_and_free_tx_resource(tx_ring, tx_buffer);
		if (tx_buffer == first)
			break;
		if (i == 0)
			i = tx_ring->count;
		i--;
	}

	tx_ring->next_to_use = i;
}

static void ixgbe_atr(struct ixgbe_ring *ring,
		      struct ixgbe_tx_buffer *first)
{
	struct ixgbe_q_vector *q_vector = ring->q_vector;
	union ixgbe_atr_hash_dword input = { .dword = 0 };
	union ixgbe_atr_hash_dword common = { .dword = 0 };
	union {
		unsigned char *network;
		struct iphdr *ipv4;
		struct ipv6hdr *ipv6;
	} hdr;
	struct tcphdr *th;
	unsigned int hlen;
	__be16 vlan_id;

	/* if ring doesn't have a interrupt vector, cannot perform ATR */
	if (!q_vector)
		return;

	/* do nothing if sampling is disabled */
	if (!ring->atr_sample_rate)
		return;

	ring->atr_count++;

	/* snag network header to get L4 type and address */
	hdr.network = skb_network_header(first->skb);

	/* Currently only IPv4/IPv6 with TCP is supported */
	if (first->protocol == __constant_htons(ETH_P_IP)) {
		if (hdr.ipv4->protocol != IPPROTO_TCP)
			return;

		/* access ihl as a u8 to avoid unaligned access on ia64 */
		hlen = (hdr.network[0] & 0x0F) << 2;
	} else if (first->protocol == __constant_htons(ETH_P_IPV6)) {
		if (hdr.ipv6->nexthdr != IPPROTO_TCP)
			return;

		hlen = sizeof(struct ipv6hdr);
	} else {
		return;
	}

	th = (struct tcphdr *)(hdr.network + hlen);

	/* skip this packet since it is invalid or the socket is closing */
	if (!th || th->fin)
		return;

	/* sample on all syn packets or once every atr sample count */
	if (!th->syn && (ring->atr_count < ring->atr_sample_rate))
		return;

	/* reset sample count */
	ring->atr_count = 0;

	vlan_id = htons(first->tx_flags >> IXGBE_TX_FLAGS_VLAN_SHIFT);

	/*
	 * src and dst are inverted, think how the receiver sees them
	 *
	 * The input is broken into two sections, a non-compressed section
	 * containing vm_pool, vlan_id, and flow_type.  The rest of the data
	 * is XORed together and stored in the compressed dword.
	 */
	input.formatted.vlan_id = vlan_id;

	/*
	 * since src port and flex bytes occupy the same word XOR them together
	 * and write the value to source port portion of compressed dword
	 */
	if (first->tx_flags & (IXGBE_TX_FLAGS_SW_VLAN | IXGBE_TX_FLAGS_HW_VLAN))
		common.port.src ^= th->dest ^ __constant_htons(ETH_P_8021Q);
	else
		common.port.src ^= th->dest ^ first->protocol;
	common.port.dst ^= th->source;

	if (first->protocol == __constant_htons(ETH_P_IP)) {
		input.formatted.flow_type = IXGBE_ATR_FLOW_TYPE_TCPV4;
		common.ip ^= hdr.ipv4->saddr ^ hdr.ipv4->daddr;
	} else {
		input.formatted.flow_type = IXGBE_ATR_FLOW_TYPE_TCPV6;
		common.ip ^= hdr.ipv6->saddr.s6_addr32[0] ^
			     hdr.ipv6->saddr.s6_addr32[1] ^
			     hdr.ipv6->saddr.s6_addr32[2] ^
			     hdr.ipv6->saddr.s6_addr32[3] ^
			     hdr.ipv6->daddr.s6_addr32[0] ^
			     hdr.ipv6->daddr.s6_addr32[1] ^
			     hdr.ipv6->daddr.s6_addr32[2] ^
			     hdr.ipv6->daddr.s6_addr32[3];
	}

	/* This assumes the Rx queue and Tx queue are bound to the same CPU */
	ixgbe_fdir_add_signature_filter_82599(&q_vector->adapter->hw,
					      input, common, ring->queue_index);
}

static int __ixgbe_maybe_stop_tx(struct ixgbe_ring *tx_ring, u16 size)
{
	netif_stop_subqueue(netdev_ring(tx_ring), ring_queue_index(tx_ring));
	/* Herbert's original patch had:
	 *  smp_mb__after_netif_stop_queue();
	 * but since that doesn't exist yet, just open code it. */
	smp_mb();

	/* We need to check again in a case another CPU has just
	 * made room available. */
	if (likely(ixgbe_desc_unused(tx_ring) < size))
		return -EBUSY;

	/* A reprieve! - use start_queue because it doesn't call schedule */
	netif_start_subqueue(netdev_ring(tx_ring), ring_queue_index(tx_ring));
	++tx_ring->tx_stats.restart_queue;
	return 0;
}

static inline int ixgbe_maybe_stop_tx(struct ixgbe_ring *tx_ring, u16 size)
{
	if (likely(ixgbe_desc_unused(tx_ring) >= size))
		return 0;
	return __ixgbe_maybe_stop_tx(tx_ring, size);
}

#ifdef HAVE_NETDEV_SELECT_QUEUE
#ifdef IXGBE_FCOE
#if defined(HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK)
static u16 ixgbe_select_queue(struct net_device *dev, struct sk_buff *skb,
			      __always_unused void *accel,
			      select_queue_fallback_t fallback)
#elif defined(HAVE_NDO_SELECT_QUEUE_ACCEL)
static u16 ixgbe_select_queue(struct net_device *dev, struct sk_buff *skb,
			      __always_unused void *accel)
#else
static u16 ixgbe_select_queue(struct net_device *dev, struct sk_buff *skb)
#endif /* HAVE_NDO_SELECT_QUEUE_ACCEL */
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	struct ixgbe_ring_feature *f;
	int txq;

	/*
	 * only execute the code below if protocol is FCoE
	 * or FIP and we have FCoE enabled on the adapter
	 */
	switch (vlan_get_protocol(skb)) {
	case __constant_htons(ETH_P_FCOE):
	case __constant_htons(ETH_P_FIP):
		adapter = netdev_priv(dev);

		if (adapter->flags & IXGBE_FLAG_FCOE_ENABLED)
			break;
	default:
#ifdef HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK
		return fallback(dev, skb);
#else
		return __netdev_pick_tx(dev, skb);
#endif
	}

	f = &adapter->ring_feature[RING_F_FCOE];

	txq = skb_rx_queue_recorded(skb) ? skb_get_rx_queue(skb) :
					   smp_processor_id();

	while (txq >= f->indices)
		txq -= f->indices;

	return txq + f->offset;
}

#endif /* IXGBE_FCOE */
#endif /* HAVE_NETDEV_SELECT_QUEUE */
netdev_tx_t ixgbe_xmit_frame_ring(struct sk_buff *skb,
			  struct ixgbe_adapter *adapter,
			  struct ixgbe_ring *tx_ring)
{
	struct ixgbe_tx_buffer *first;
	int tso;
	u32 tx_flags = 0;
#if PAGE_SIZE > IXGBE_MAX_DATA_PER_TXD
	unsigned short f;
#endif
	u16 count = TXD_USE_COUNT(skb_headlen(skb));
	__be16 protocol = skb->protocol;
	u8 hdr_len = 0;

#ifdef ENABLE_DNA
	/* We don't allow legacy send when in DNA */
        if(adapter->dna.dna_enabled) {
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
#if PAGE_SIZE > IXGBE_MAX_DATA_PER_TXD
	for (f = 0; f < skb_shinfo(skb)->nr_frags; f++)
		count += TXD_USE_COUNT(skb_shinfo(skb)->frags[f].size);
#else
	count += skb_shinfo(skb)->nr_frags;
#endif
	if (ixgbe_maybe_stop_tx(tx_ring, count + 3)) {
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	/* record the location of the first descriptor for this packet */
	first = &tx_ring->tx_buffer_info[tx_ring->next_to_use];
	first->skb = skb;
	first->bytecount = skb->len;
	first->gso_segs = 1;

	/* if we have a HW VLAN tag being added default to the HW one */
	if (vlan_tx_tag_present(skb)) {
		tx_flags |= vlan_tx_tag_get(skb) << IXGBE_TX_FLAGS_VLAN_SHIFT;
		tx_flags |= IXGBE_TX_FLAGS_HW_VLAN;
	/* else if it is a SW VLAN check the next protocol and store the tag */
	} else if (protocol == __constant_htons(ETH_P_8021Q)) {
		struct vlan_hdr *vhdr, _vhdr;
		vhdr = skb_header_pointer(skb, ETH_HLEN, sizeof(_vhdr), &_vhdr);
		if (!vhdr)
			goto out_drop;

		protocol = vhdr->h_vlan_encapsulated_proto;
		tx_flags |= ntohs(vhdr->h_vlan_TCI) <<
				  IXGBE_TX_FLAGS_VLAN_SHIFT;
		tx_flags |= IXGBE_TX_FLAGS_SW_VLAN;
	}

	skb_tx_timestamp(skb);

#ifdef HAVE_PTP_1588_CLOCK
	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)) {
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
		tx_flags |= IXGBE_TX_FLAGS_TSTAMP;

		/* schedule check for Tx timestamp */
		adapter->ptp_tx_skb = skb_get(skb);
		adapter->ptp_tx_start = jiffies;
		schedule_work(&adapter->ptp_tx_work);
	}

#endif
#ifdef CONFIG_PCI_IOV
	/*
	 * Use the l2switch_enable flag - would be false if the DMA
	 * Tx switch had been disabled.
	 */
	if (adapter->flags & IXGBE_FLAG_SRIOV_L2SWITCH_ENABLE)
		tx_flags |= IXGBE_TX_FLAGS_CC;

#endif
#ifdef HAVE_TX_MQ
	if ((adapter->flags & IXGBE_FLAG_DCB_ENABLED) &&
	    ((tx_flags & (IXGBE_TX_FLAGS_HW_VLAN | IXGBE_TX_FLAGS_SW_VLAN)) ||
	     (skb->priority != TC_PRIO_CONTROL))) {
		tx_flags &= ~IXGBE_TX_FLAGS_VLAN_PRIO_MASK;
#ifdef IXGBE_FCOE
		/* for FCoE with DCB, we force the priority to what
		 * was specified by the switch */
		if ((adapter->flags & IXGBE_FLAG_FCOE_ENABLED) &&
		    ((protocol == __constant_htons(ETH_P_FCOE)) ||
		     (protocol == __constant_htons(ETH_P_FIP))))
			tx_flags |= adapter->fcoe.up <<
				    IXGBE_TX_FLAGS_VLAN_PRIO_SHIFT;
		else
#endif /* IXGBE_FCOE */
			tx_flags |= skb->priority <<
				    IXGBE_TX_FLAGS_VLAN_PRIO_SHIFT;
		if (tx_flags & IXGBE_TX_FLAGS_SW_VLAN) {
			struct vlan_ethhdr *vhdr;
			if (skb_header_cloned(skb) &&
			    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
				goto out_drop;
			vhdr = (struct vlan_ethhdr *)skb->data;
			vhdr->h_vlan_TCI = htons(tx_flags >>
						 IXGBE_TX_FLAGS_VLAN_SHIFT);
		} else {
			tx_flags |= IXGBE_TX_FLAGS_HW_VLAN;
		}
	}

#endif /* HAVE_TX_MQ */
	/* record initial flags and protocol */
	first->tx_flags = tx_flags;
	first->protocol = protocol;

#ifdef IXGBE_FCOE
	/* setup tx offload for FCoE */
	if ((protocol == __constant_htons(ETH_P_FCOE)) &&
	    (tx_ring->netdev->features & (NETIF_F_FSO | NETIF_F_FCOE_CRC))) {
		tso = ixgbe_fso(tx_ring, first, &hdr_len);
		if (tso < 0)
			goto out_drop;

		goto xmit_fcoe;
	}

#endif /* IXGBE_FCOE */
	tso = ixgbe_tso(tx_ring, first, &hdr_len);
	if (tso < 0)
		goto out_drop;
	else if (!tso)
		ixgbe_tx_csum(tx_ring, first);

	/* add the ATR filter if ATR is on */
	if (test_bit(__IXGBE_TX_FDIR_INIT_DONE, &tx_ring->state))
		ixgbe_atr(tx_ring, first);

#ifdef IXGBE_FCOE
xmit_fcoe:
#endif /* IXGBE_FCOE */
	ixgbe_tx_map(tx_ring, first, hdr_len);

#ifndef HAVE_TRANS_START_IN_QUEUE
	netdev_ring(tx_ring)->trans_start = jiffies;

#endif
	ixgbe_maybe_stop_tx(tx_ring, DESC_NEEDED);

	return NETDEV_TX_OK;

out_drop:
	dev_kfree_skb_any(first->skb);
	first->skb = NULL;

	return NETDEV_TX_OK;
}

static netdev_tx_t ixgbe_xmit_frame(struct sk_buff *skb,
				    struct net_device *netdev)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_ring *tx_ring;
#ifdef HAVE_TX_MQ
	unsigned int r_idx = skb->queue_mapping;
#endif

	if (!netif_carrier_ok(netdev)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	/*
	 * The minimum packet size for olinfo paylen is 17 so pad the skb
	 * in order to meet this minimum size requirement.
	 */
	if (unlikely(skb->len < 17)) {
		if (skb_pad(skb, 17 - skb->len))
			return NETDEV_TX_OK;
		skb->len = 17;
	}

#ifdef HAVE_TX_MQ
	if (r_idx >= adapter->num_tx_queues)
		r_idx = r_idx % adapter->num_tx_queues;
	tx_ring = adapter->tx_ring[r_idx];
#else
	tx_ring = adapter->tx_ring[0];
#endif
	return ixgbe_xmit_frame_ring(skb, adapter, tx_ring);
}

/**
 * ixgbe_set_mac - Change the Ethernet Address of the NIC
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
static int ixgbe_set_mac(struct net_device *netdev, void *p)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	struct sockaddr *addr = p;
	int ret;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	ixgbe_del_mac_filter(adapter, hw->mac.addr, VMDQ_P(0));
	memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);
	memcpy(hw->mac.addr, addr->sa_data, netdev->addr_len);


	/* set the correct pool for the new PF MAC address in entry 0 */
	ret = ixgbe_add_mac_filter(adapter, hw->mac.addr, VMDQ_P(0));
	return (ret > 0 ? 0 : ret);
}

#if defined(HAVE_NETDEV_STORAGE_ADDRESS) && defined(NETDEV_HW_ADDR_T_SAN)
/**
 * ixgbe_add_sanmac_netdev - Add the SAN MAC address to the corresponding
 * netdev->dev_addr_list
 * @netdev: network interface device structure
 *
 * Returns non-zero on failure
 **/
static int ixgbe_add_sanmac_netdev(struct net_device *dev)
{
	int err = 0;
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	struct ixgbe_hw *hw = &adapter->hw;

	if (is_valid_ether_addr(hw->mac.san_addr)) {
		rtnl_lock();
		err = dev_addr_add(dev, hw->mac.san_addr,
				   NETDEV_HW_ADDR_T_SAN);
		rtnl_unlock();

		/* update SAN MAC vmdq pool selection */
		hw->mac.ops.set_vmdq_san_mac(hw, VMDQ_P(0));
	}
	return err;
}

/**
 * ixgbe_del_sanmac_netdev - Removes the SAN MAC address to the corresponding
 * netdev->dev_addr_list
 * @netdev: network interface device structure
 *
 * Returns non-zero on failure
 **/
static int ixgbe_del_sanmac_netdev(struct net_device *dev)
{
	int err = 0;
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	struct ixgbe_mac_info *mac = &adapter->hw.mac;

	if (is_valid_ether_addr(mac->san_addr)) {
		rtnl_lock();
		err = dev_addr_del(dev, mac->san_addr, NETDEV_HW_ADDR_T_SAN);
		rtnl_unlock();
	}
	return err;
}

#endif /* (HAVE_NETDEV_STORAGE_ADDRESS) && defined(NETDEV_HW_ADDR_T_SAN) */

static int ixgbe_mdio_read(struct net_device *netdev, int prtad, int devad,
			   u16 addr)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;
	u16 value;
	int rc;

	if (prtad != hw->phy.addr)
		return -EINVAL;
	rc = hw->phy.ops.read_reg(hw, addr, devad, &value);
	if (!rc)
		rc = value;
	return rc;
}

static int ixgbe_mdio_write(struct net_device *netdev, int prtad, int devad,
			    u16 addr, u16 value)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	struct ixgbe_hw *hw = &adapter->hw;

	if (prtad != hw->phy.addr)
		return -EINVAL;
	return hw->phy.ops.write_reg(hw, addr, devad, value);
}

static int ixgbe_mii_ioctl(struct net_device *netdev, struct ifreq *ifr,
			   int cmd)
{
	struct mii_ioctl_data *mii = (struct mii_ioctl_data *) &ifr->ifr_data;
	int prtad, devad, ret;

	prtad = (mii->phy_id & MDIO_PHY_ID_PRTAD) >> 5;
	devad = (mii->phy_id & MDIO_PHY_ID_DEVAD);

	if (cmd == SIOCGMIIREG) {
		ret = ixgbe_mdio_read(netdev, prtad, devad, mii->reg_num);
		if (ret < 0)
			return ret;
		mii->val_out = ret;
		return 0;
	} else {
		return ixgbe_mdio_write(netdev, prtad, devad, mii->reg_num,
					mii->val_in);
	}
}

static int ixgbe_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
#ifdef HAVE_PTP_1588_CLOCK
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

#endif
	switch (cmd) {
#ifdef HAVE_PTP_1588_CLOCK
#ifdef SIOCGHWTSTAMP
	case SIOCGHWTSTAMP:
		return ixgbe_ptp_get_ts_config(adapter, ifr);
#endif
	case SIOCSHWTSTAMP:
		return ixgbe_ptp_set_ts_config(adapter, ifr);
#endif
#ifdef ETHTOOL_OPS_COMPAT
	case SIOCETHTOOL:
		return ethtool_ioctl(ifr);
#endif
	case SIOCGMIIREG:
	case SIOCSMIIREG:
		return ixgbe_mii_ioctl(netdev, ifr, cmd);
	default:
		return -EOPNOTSUPP;
	}
}

#ifdef CONFIG_NET_POLL_CONTROLLER
/*
 * Polling 'interrupt' - used by things like netconsole to send skbs
 * without having to re-enable interrupts. It's not called while
 * the interrupt routine is executing.
 */
static void ixgbe_netpoll(struct net_device *netdev)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	/* if interface is down do nothing */
	if (test_bit(__IXGBE_DOWN, &adapter->state))
		return;

	if (adapter->flags & IXGBE_FLAG_MSIX_ENABLED) {
		int i;
		for (i = 0; i < adapter->num_q_vectors; i++) {
			adapter->q_vector[i]->netpoll_rx = true;
			ixgbe_msix_clean_rings(0, adapter->q_vector[i]);
		}
	} else {
		ixgbe_intr(0, adapter);
	}
}
#endif /* CONFIG_NET_POLL_CONTROLLER */

/* ixgbe_validate_rtr - verify 802.1Qp to Rx packet buffer mapping is valid.
 * @adapter: pointer to ixgbe_adapter
 * @tc: number of traffic classes currently enabled
 *
 * Configure a valid 802.1Qp to Rx packet buffer mapping ie confirm
 * 802.1Q priority maps to a packet buffer that exists.
 */
static void ixgbe_validate_rtr(struct ixgbe_adapter *adapter, u8 tc)
{
	struct ixgbe_hw *hw = &adapter->hw;
	u32 reg, rsave;
	int i;

	/* 82598 have a static priority to TC mapping that can not
	 * be changed so no validation is needed.
	 */
	if (hw->mac.type == ixgbe_mac_82598EB)
		return;

	reg = IXGBE_READ_REG(hw, IXGBE_RTRUP2TC);
	rsave = reg;

	for (i = 0; i < IXGBE_DCB_MAX_TRAFFIC_CLASS; i++) {
		u8 up2tc = reg >> (i * IXGBE_RTRUP2TC_UP_SHIFT);

		/* If up2tc is out of bounds default to zero */
		if (up2tc > tc)
			reg &= ~(0x7 << IXGBE_RTRUP2TC_UP_SHIFT);
	}

	if (reg != rsave)
		IXGBE_WRITE_REG(hw, IXGBE_RTRUP2TC, reg);

	return;
}

/**
 * ixgbe_set_prio_tc_map - Configure netdev prio tc map
 * @adapter: Pointer to adapter struct
 *
 * Populate the netdev user priority to tc map
 */
static void ixgbe_set_prio_tc_map(struct ixgbe_adapter *adapter)
{
#ifdef HAVE_DCBNL_IEEE
	struct net_device *dev = adapter->netdev;
	struct ixgbe_dcb_config *dcb_cfg = &adapter->dcb_cfg;
	struct ieee_ets *ets = adapter->ixgbe_ieee_ets;
	u8 prio;

	for (prio = 0; prio < IXGBE_DCB_MAX_USER_PRIORITY; prio++) {
		u8 tc = 0;

		if (adapter->dcbx_cap & DCB_CAP_DCBX_VER_CEE)
			tc = ixgbe_dcb_get_tc_from_up(dcb_cfg, 0, prio);
		else if (ets)
			tc = ets->prio_tc[prio];

		netdev_set_prio_tc_map(dev, prio, tc);
	}
#endif
}

/**
 * ixgbe_setup_tc - routine to configure net_device for multiple traffic
 * classes.
 *
 * @netdev: net device to configure
 * @tc: number of traffic classes to enable
 */
int ixgbe_setup_tc(struct net_device *dev, u8 tc)
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	struct ixgbe_hw *hw = &adapter->hw;

	/* Hardware supports up to 8 traffic classes */
	if (tc > adapter->dcb_cfg.num_tcs.pg_tcs ||
	    (hw->mac.type == ixgbe_mac_82598EB &&
	     tc < IXGBE_DCB_MAX_TRAFFIC_CLASS))
		return -EINVAL;

	/* Hardware has to reinitialize queues and interrupts to
	 * match packet buffer alignment. Unfortunately, the
	 * hardware is not flexible enough to do this dynamically.
	 */
	if (netif_running(dev))
		ixgbe_close(dev);
	ixgbe_clear_interrupt_scheme(adapter);

	if (tc) {
		netdev_set_num_tc(dev, tc);
		ixgbe_set_prio_tc_map(adapter);

		adapter->flags |= IXGBE_FLAG_DCB_ENABLED;

		if (adapter->hw.mac.type == ixgbe_mac_82598EB) {
			adapter->last_lfc_mode = adapter->hw.fc.requested_mode;
			adapter->hw.fc.requested_mode = ixgbe_fc_none;
		}
	} else {
		netdev_reset_tc(dev);

		if (adapter->hw.mac.type == ixgbe_mac_82598EB)
			adapter->hw.fc.requested_mode = adapter->last_lfc_mode;

		adapter->flags &= ~IXGBE_FLAG_DCB_ENABLED;

		adapter->temp_dcb_cfg.pfc_mode_enable = false;
		adapter->dcb_cfg.pfc_mode_enable = false;
	}

	ixgbe_init_interrupt_scheme(adapter);
	ixgbe_validate_rtr(adapter, tc);
	if (netif_running(dev))
		ixgbe_open(dev);

	return 0;
}

#ifdef CONFIG_PCI_IOV
void ixgbe_sriov_reinit(struct ixgbe_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	rtnl_lock();
	ixgbe_setup_tc(netdev,
		       netdev_get_num_tc(netdev));
	rtnl_unlock();
}

#endif
void ixgbe_do_reset(struct net_device *netdev)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);

	if (netif_running(netdev))
		ixgbe_reinit_locked(adapter);
	else
		ixgbe_reset(adapter);
}

#ifdef HAVE_NDO_SET_FEATURES
static netdev_features_t ixgbe_fix_features(struct net_device *netdev,
					    netdev_features_t features)
{
#if defined(CONFIG_DCB) || defined(IXGBE_NO_LRO)
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
#endif

#ifdef CONFIG_DCB
	if (adapter->flags & IXGBE_FLAG_DCB_ENABLED)
#ifdef NETIF_F_HW_VLAN_CTAG_RX
		features |= NETIF_F_HW_VLAN_CTAG_RX;
#else
		features |= NETIF_F_HW_VLAN_RX;
#endif
#endif

	/* If Rx checksum is disabled, then RSC/LRO should also be disabled */
	if (!(features & NETIF_F_RXCSUM))
		features &= ~NETIF_F_LRO;

#ifdef IXGBE_NO_LRO
	/* Turn off LRO if not RSC capable */
	if (!(adapter->flags2 & IXGBE_FLAG2_RSC_CAPABLE))
		features &= ~NETIF_F_LRO;

#endif
	return features;
}

static int ixgbe_set_features(struct net_device *netdev,
			      netdev_features_t features)
{
	struct ixgbe_adapter *adapter = netdev_priv(netdev);
	bool need_reset = false;

	/* Make sure RSC matches LRO, reset if change */
	if (!(features & NETIF_F_LRO)) {
		if (adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED)
			need_reset = true;
		adapter->flags2 &= ~IXGBE_FLAG2_RSC_ENABLED;
	} else if ((adapter->flags2 & IXGBE_FLAG2_RSC_CAPABLE) &&
		   !(adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED)) {
		if (adapter->rx_itr_setting == 1 ||
		    adapter->rx_itr_setting > IXGBE_MIN_RSC_ITR) {
			adapter->flags2 |= IXGBE_FLAG2_RSC_ENABLED;
			need_reset = true;
		} else if ((netdev->features ^ features) & NETIF_F_LRO) {
#ifdef IXGBE_NO_LRO
			e_info(probe, "rx-usecs set too low, "
			       "disabling RSC\n");
#else
			e_info(probe, "rx-usecs set too low, "
			       "falling back to software LRO\n");
#endif
		}
	}

	/*
	 * Check if Flow Director n-tuple support was enabled or disabled.  If
	 * the state changed, we need to reset.
	 */
	switch (features & NETIF_F_NTUPLE) {
	case NETIF_F_NTUPLE:
		/* turn off ATR, enable perfect filters and reset */
		if (!(adapter->flags & IXGBE_FLAG_FDIR_PERFECT_CAPABLE))
			need_reset = true;

		adapter->flags &= ~IXGBE_FLAG_FDIR_HASH_CAPABLE;
		adapter->flags |= IXGBE_FLAG_FDIR_PERFECT_CAPABLE;
		break;
	default:
		/* turn off perfect filters, enable ATR and reset */
		if (adapter->flags & IXGBE_FLAG_FDIR_PERFECT_CAPABLE)
			need_reset = true;

		adapter->flags &= ~IXGBE_FLAG_FDIR_PERFECT_CAPABLE;

		/* We cannot enable ATR if VMDq is enabled */
		if (adapter->flags & IXGBE_FLAG_VMDQ_ENABLED)
			break;

		/* We cannot enable ATR if we have 2 or more traffic classes */
		if (netdev_get_num_tc(netdev) > 1)
			break;

		/* We cannot enable ATR if RSS is disabled */
		if (adapter->ring_feature[RING_F_RSS].limit <= 1)
			break;

		/* A sample rate of 0 indicates ATR disabled */
		if (!adapter->atr_sample_rate)
			break;

		adapter->flags |= IXGBE_FLAG_FDIR_HASH_CAPABLE;
		break;
	}

#ifdef NETIF_F_HW_VLAN_CTAG_RX
	if (features & NETIF_F_HW_VLAN_CTAG_RX)
#else
	if (features & NETIF_F_HW_VLAN_RX)
#endif
		ixgbe_vlan_stripping_enable(adapter);
	else
		ixgbe_vlan_stripping_disable(adapter);

	if (need_reset)
		ixgbe_do_reset(netdev);

	return 0;

}
#endif /* HAVE_NDO_SET_FEATURES */

#ifdef HAVE_FDB_OPS
#ifdef USE_CONST_DEV_UC_CHAR
static int ixgbe_ndo_fdb_add(struct ndmsg *ndm, struct nlattr *tb[],
			     struct net_device *dev,
			     const unsigned char *addr,
			     u16 flags)
#else
static int ixgbe_ndo_fdb_add(struct ndmsg *ndm,
			     struct net_device *dev,
			     unsigned char *addr,
			     u16 flags)
#endif
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	int err;

	if (!(adapter->flags & IXGBE_FLAG_SRIOV_ENABLED))
		return -EOPNOTSUPP;

	/* Hardware does not support aging addresses so if a
	 * ndm_state is given only allow permanent addresses
	 */
	if (ndm->ndm_state && !(ndm->ndm_state & NUD_PERMANENT)) {
		pr_info("%s: FDB only supports static addresses\n",
			ixgbe_driver_name);
		return -EINVAL;
	}

	if (is_unicast_ether_addr(addr) || is_link_local_ether_addr(addr)) {
		u32 rar_uc_entries = IXGBE_MAX_PF_MACVLANS;

		if (netdev_uc_count(dev) < rar_uc_entries)
			err = dev_uc_add_excl(dev, addr);
		else
			err = -ENOMEM;
	} else if (is_multicast_ether_addr(addr)) {
		err = dev_mc_add_excl(dev, addr);
	} else {
		err = -EINVAL;
	}

	/* Only return duplicate errors if NLM_F_EXCL is set */
	if (err == -EEXIST && !(flags & NLM_F_EXCL))
		err = 0;

	return err;
}

#ifndef USE_DEFAULT_FDB_DEL_DUMP
#ifdef USE_CONST_DEV_UC_CHAR
static int ixgbe_ndo_fdb_del(struct ndmsg *ndm,
			     struct net_device *dev,
			     const unsigned char *addr)
#else
static int ixgbe_ndo_fdb_del(struct ndmsg *ndm,
			     struct net_device *dev,
			     unsigned char *addr)
#endif
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	int err = -EOPNOTSUPP;

	if (ndm->ndm_state & NUD_PERMANENT) {
		pr_info("%s: FDB only supports static addresses\n",
			ixgbe_driver_name);
		return -EINVAL;
	}

	if (adapter->flags & IXGBE_FLAG_SRIOV_ENABLED) {
		if (is_unicast_ether_addr(addr))
			err = dev_uc_del(dev, addr);
		else if (is_multicast_ether_addr(addr))
			err = dev_mc_del(dev, addr);
		else
			err = -EINVAL;
	}

	return err;
}

static int ixgbe_ndo_fdb_dump(struct sk_buff *skb,
			      struct netlink_callback *cb,
			      struct net_device *dev,
			      int idx)
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);

	if (adapter->flags & IXGBE_FLAG_SRIOV_ENABLED)
		idx = ndo_dflt_fdb_dump(skb, cb, dev, idx);

	return idx;
}
#endif /* USE_DEFAULT_FDB_DEL_DUMP */

#ifdef HAVE_BRIDGE_ATTRIBS
static int ixgbe_ndo_bridge_setlink(struct net_device *dev,
				    struct nlmsghdr *nlh)
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	struct nlattr *attr, *br_spec;
	int rem;

	if (!(adapter->flags & IXGBE_FLAG_SRIOV_ENABLED))
		return -EOPNOTSUPP;

	br_spec = nlmsg_find_attr(nlh, sizeof(struct ifinfomsg), IFLA_AF_SPEC);

	nla_for_each_nested(attr, br_spec, rem) {
		__u16 mode;
		u32 reg = 0;

		if (nla_type(attr) != IFLA_BRIDGE_MODE)
			continue;

		mode = nla_get_u16(attr);
		if (mode == BRIDGE_MODE_VEPA) {
			reg = 0;
			adapter->flags &= ~IXGBE_FLAG_SRIOV_L2LOOPBACK_ENABLE;
		} else if (mode == BRIDGE_MODE_VEB) {
			reg = IXGBE_PFDTXGSWC_VT_LBEN;
			adapter->flags |= IXGBE_FLAG_SRIOV_L2LOOPBACK_ENABLE;
		} else
			return -EINVAL;

		IXGBE_WRITE_REG(&adapter->hw, IXGBE_PFDTXGSWC, reg);

		e_info(drv, "enabling bridge mode: %s\n",
			mode == BRIDGE_MODE_VEPA ? "VEPA" : "VEB");
	}

	return 0;
}

#ifdef HAVE_BRIDGE_FILTER
static int ixgbe_ndo_bridge_getlink(struct sk_buff *skb, u32 pid, u32 seq,
				    struct net_device *dev,
				    u32 filter_mask)
#else
static int ixgbe_ndo_bridge_getlink(struct sk_buff *skb, u32 pid, u32 seq,
				    struct net_device *dev)
#endif
{
	struct ixgbe_adapter *adapter = netdev_priv(dev);
	u16 mode;

	if (!(adapter->flags & IXGBE_FLAG_SRIOV_ENABLED))
		return 0;

	if (adapter->flags & IXGBE_FLAG_SRIOV_L2LOOPBACK_ENABLE)
		mode = BRIDGE_MODE_VEB;
	else
		mode = BRIDGE_MODE_VEPA;

	return ndo_dflt_bridge_getlink(skb, pid, seq, dev, mode);
}
#endif /* HAVE_BRIDGE_ATTRIBS */
#endif /* HAVE_FDB_OPS */

#ifdef HAVE_NET_DEVICE_OPS
static const struct net_device_ops ixgbe_netdev_ops = {
	.ndo_open		= ixgbe_open,
	.ndo_stop		= ixgbe_close,
	.ndo_start_xmit		= ixgbe_xmit_frame,
#ifdef IXGBE_FCOE
	.ndo_select_queue	= ixgbe_select_queue,
#else
#ifndef HAVE_MQPRIO
	.ndo_select_queue	= __netdev_pick_tx,
#endif
#endif
	.ndo_set_rx_mode	= ixgbe_set_rx_mode,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= ixgbe_set_mac,
	.ndo_change_mtu		= ixgbe_change_mtu,
	.ndo_tx_timeout		= ixgbe_tx_timeout,
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	.ndo_vlan_rx_add_vid	= ixgbe_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= ixgbe_vlan_rx_kill_vid,
#endif
	.ndo_do_ioctl		= ixgbe_ioctl,
#ifdef IFLA_VF_MAX
	.ndo_set_vf_mac		= ixgbe_ndo_set_vf_mac,
	.ndo_set_vf_vlan	= ixgbe_ndo_set_vf_vlan,
	.ndo_set_vf_tx_rate	= ixgbe_ndo_set_vf_bw,
#ifdef HAVE_VF_SPOOFCHK_CONFIGURE
	.ndo_set_vf_spoofchk	= ixgbe_ndo_set_vf_spoofchk,
#endif
	.ndo_get_vf_config	= ixgbe_ndo_get_vf_config,
#endif
#ifdef HAVE_NDO_GET_STATS64
	.ndo_get_stats64	= ixgbe_get_stats64,
#else
	.ndo_get_stats		= ixgbe_get_stats,
#endif /* HAVE_NDO_GET_STATS64 */
#ifdef HAVE_SETUP_TC
	.ndo_setup_tc		= ixgbe_setup_tc,
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= ixgbe_netpoll,
#endif
#ifdef CONFIG_NET_RX_BUSY_POLL
	.ndo_busy_poll		= ixgbe_busy_poll_recv,
#endif /* CONFIG_NET_RX_BUSY_POLL */
#ifdef IXGBE_FCOE
	.ndo_fcoe_ddp_setup = ixgbe_fcoe_ddp_get,
#ifdef HAVE_NETDEV_OPS_FCOE_DDP_TARGET
	.ndo_fcoe_ddp_target = ixgbe_fcoe_ddp_target,
#endif
	.ndo_fcoe_ddp_done = ixgbe_fcoe_ddp_put,
#ifdef HAVE_NETDEV_OPS_FCOE_ENABLE
	.ndo_fcoe_enable = ixgbe_fcoe_enable,
	.ndo_fcoe_disable = ixgbe_fcoe_disable,
#endif
#ifdef HAVE_NETDEV_OPS_FCOE_GETWWN
	.ndo_fcoe_get_wwn = ixgbe_fcoe_get_wwn,
#endif
#endif /* IXGBE_FCOE */
#ifdef HAVE_NDO_SET_FEATURES
	.ndo_set_features = ixgbe_set_features,
	.ndo_fix_features = ixgbe_fix_features,
#endif /* HAVE_NDO_SET_FEATURES */
#ifdef HAVE_VLAN_RX_REGISTER
	.ndo_vlan_rx_register	= &ixgbe_vlan_mode,
#endif
#ifdef HAVE_FDB_OPS
	.ndo_fdb_add		= ixgbe_ndo_fdb_add,
#ifndef USE_DEFAULT_FDB_DEL_DUMP
	.ndo_fdb_del		= ixgbe_ndo_fdb_del,
	.ndo_fdb_dump		= ixgbe_ndo_fdb_dump,
#endif
#ifdef HAVE_BRIDGE_ATTRIBS
	.ndo_bridge_setlink	= ixgbe_ndo_bridge_setlink,
	.ndo_bridge_getlink	= ixgbe_ndo_bridge_getlink,
#endif /* HAVE_BRIDGE_ATTRIBS */
#endif
};

#endif /* HAVE_NET_DEVICE_OPS */



void ixgbe_assign_netdev_ops(struct net_device *dev)
{
#ifdef HAVE_NET_DEVICE_OPS
	dev->netdev_ops = &ixgbe_netdev_ops;
#else /* HAVE_NET_DEVICE_OPS */
	dev->open = &ixgbe_open;
	dev->stop = &ixgbe_close;
	dev->hard_start_xmit = &ixgbe_xmit_frame;
	dev->get_stats = &ixgbe_get_stats;
#ifdef HAVE_SET_RX_MODE
	dev->set_rx_mode = &ixgbe_set_rx_mode;
#endif
	dev->set_multicast_list = &ixgbe_set_rx_mode;
	dev->set_mac_address = &ixgbe_set_mac;
	dev->change_mtu = &ixgbe_change_mtu;
	dev->do_ioctl = &ixgbe_ioctl;
#ifdef HAVE_TX_TIMEOUT
	dev->tx_timeout = &ixgbe_tx_timeout;
#endif
#if defined(NETIF_F_HW_VLAN_TX) || defined(NETIF_F_HW_VLAN_CTAG_TX)
	dev->vlan_rx_register = &ixgbe_vlan_mode;
	dev->vlan_rx_add_vid = &ixgbe_vlan_rx_add_vid;
	dev->vlan_rx_kill_vid = &ixgbe_vlan_rx_kill_vid;
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	dev->poll_controller = &ixgbe_netpoll;
#endif
#ifdef HAVE_NETDEV_SELECT_QUEUE
#ifdef IXGBE_FCOE
	dev->select_queue = &ixgbe_select_queue;
#else
	dev->select_queue = &__netdev_pick_tx;
#endif
#endif /* HAVE_NETDEV_SELECT_QUEUE */
#endif /* HAVE_NET_DEVICE_OPS */
	ixgbe_set_ethtool_ops(dev);
	dev->watchdog_timeo = 5 * HZ;
}


/**
 * ixgbe_wol_supported - Check whether device supports WoL
 * @adapter: the adapter private structure
 * @device_id: the device ID
 * @subdev_id: the subsystem device ID
 *
 * This function is used by probe and ethtool to determine
 * which devices have WoL support
 *
 **/
int ixgbe_wol_supported(struct ixgbe_adapter *adapter, u16 device_id,
			u16 subdevice_id)
{
	int is_wol_supported = 0;
	struct ixgbe_hw *hw = &adapter->hw;
	u16 wol_cap = adapter->eeprom_cap & IXGBE_DEVICE_CAPS_WOL_MASK;

	switch (device_id) {
	case IXGBE_DEV_ID_82599_SFP:
		/* Only these subdevices could supports WOL */
		switch (subdevice_id) {
		case IXGBE_SUBDEV_ID_82599_560FLR:
		case IXGBE_SUBDEV_ID_82599_LOM_SNAP6:
		case IXGBE_SUBDEV_ID_82599_SFP_WOL0:
		case IXGBE_SUBDEV_ID_82599_SFP_2OCP:
			/* only support first port */
			if (hw->bus.func != 0)
				break;
		case IXGBE_SUBDEV_ID_82599_SP_560FLR:
		case IXGBE_SUBDEV_ID_82599_SFP:
		case IXGBE_SUBDEV_ID_82599_RNDC:
		case IXGBE_SUBDEV_ID_82599_ECNA_DP:
		case IXGBE_SUBDEV_ID_82599_LOM_SFP:
		case IXGBE_SUBDEV_ID_82599_SFP_1OCP:
			is_wol_supported = 1;
			break;
		}
		break;
	case IXGBE_DEV_ID_82599EN_SFP:
		/* Only these subdevices support WoL */
		switch (subdevice_id) {
		case IXGBE_SUBDEV_ID_82599EN_SFP_OCP1:
			is_wol_supported = 1;
			break;
		}
		break;
	case IXGBE_DEV_ID_82599_COMBO_BACKPLANE:
		/* All except this subdevice support WOL */
		if (subdevice_id != IXGBE_SUBDEV_ID_82599_KX4_KR_MEZZ)
			is_wol_supported = 1;
		break;
	case IXGBE_DEV_ID_82599_KX4:
		is_wol_supported = 1;
		break;
	case IXGBE_DEV_ID_X540T:
	case IXGBE_DEV_ID_X540T1:
		/* check eeprom to see if enabled wol */
		if ((wol_cap == IXGBE_DEVICE_CAPS_WOL_PORT0_1) ||
		    ((wol_cap == IXGBE_DEVICE_CAPS_WOL_PORT0) &&
		     (hw->bus.func == 0))) {
			is_wol_supported = 1;
		}
		break;
	}

	return is_wol_supported;
}

/**
 * ixgbe_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in ixgbe_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * ixgbe_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int __devinit ixgbe_probe(struct pci_dev *pdev,
				 const struct pci_device_id *ent)
{
	struct net_device *netdev;
	struct ixgbe_adapter *adapter = NULL;
	struct ixgbe_hw *hw = NULL;
	static int cards_found;
	int err, pci_using_dac, expected_gts;
	u16 offset = 0;
	u16 eeprom_verh = 0, eeprom_verl = 0;
	u16 eeprom_cfg_blkh = 0, eeprom_cfg_blkl = 0;
	u32 etrack_id;
	u16 build, major, patch;
	char *info_string, *i_s_var;
	u8 part_str[IXGBE_PBANUM_LENGTH];
	enum ixgbe_mac_type mac_type = ixgbe_mac_unknown;
#ifdef HAVE_TX_MQ
	unsigned int indices = MAX_TX_QUEUES;
#endif /* HAVE_TX_MQ */
#ifdef IXGBE_FCOE
	u16 device_caps;
#endif

	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	if (!dma_set_mask(pci_dev_to_dev(pdev), DMA_BIT_MASK(64)) &&
	    !dma_set_coherent_mask(pci_dev_to_dev(pdev), DMA_BIT_MASK(64))) {
		pci_using_dac = 1;
	} else {
		err = dma_set_mask(pci_dev_to_dev(pdev), DMA_BIT_MASK(32));
		if (err) {
			err = dma_set_coherent_mask(pci_dev_to_dev(pdev),
						    DMA_BIT_MASK(32));
			if (err) {
				dev_err(pci_dev_to_dev(pdev), "No usable DMA "
					"configuration, aborting\n");
				goto err_dma;
			}
		}
		pci_using_dac = 0;
	}

	err = pci_request_selected_regions(pdev, pci_select_bars(pdev,
					   IORESOURCE_MEM), ixgbe_driver_name);
	if (err) {
		dev_err(pci_dev_to_dev(pdev),
			"pci_request_selected_regions failed 0x%x\n", err);
		goto err_pci_reg;
	}

	/*
	 * The mac_type is needed before we have the adapter is  set up
	 * so rather than maintain two devID -> MAC tables we dummy up
	 * an ixgbe_hw stuct and use ixgbe_set_mac_type.
	 */
	hw = vmalloc(sizeof(struct ixgbe_hw));
	if (!hw) {
		pr_info("Unable to allocate memory for early mac "
			"check\n");
	} else {
		hw->vendor_id = pdev->vendor;
		hw->device_id = pdev->device;
		ixgbe_set_mac_type(hw);
		mac_type = hw->mac.type;
		vfree(hw);
	}

	/*
	 * Workaround of Silicon errata on 82598. Disable LOs in the PCI switch
	 * port to which the 82598 is connected to prevent duplicate
	 * completions caused by LOs.  We need the mac type so that we only
	 * do this on 82598 devices, ixgbe_set_mac_type does this for us if
	 * we set it's device ID.
	 */
	if (mac_type == ixgbe_mac_82598EB)
		pci_disable_link_state(pdev, PCIE_LINK_STATE_L0S);

	pci_enable_pcie_error_reporting(pdev);

	pci_set_master(pdev);

#ifdef HAVE_TX_MQ
	if (mac_type == ixgbe_mac_82598EB) {
#ifdef CONFIG_DCB
		indices = IXGBE_MAX_DCB_INDICES * 4;
#else /* __VMKLNX__ */
		indices = IXGBE_MAX_RSS_INDICES;
#endif
	}

	netdev = alloc_etherdev_mq(sizeof(struct ixgbe_adapter), indices);
#else /* HAVE_TX_MQ */
	netdev = alloc_etherdev(sizeof(struct ixgbe_adapter));
#endif /* HAVE_TX_MQ */
	if (!netdev) {
		err = -ENOMEM;
		goto err_alloc_etherdev;
	}

	SET_NETDEV_DEV(netdev, pci_dev_to_dev(pdev));

	adapter = netdev_priv(netdev);
	pci_set_drvdata(pdev, adapter);
#ifdef HAVE_TX_MQ
#ifndef HAVE_NETDEV_SELECT_QUEUE
	adapter->indices = indices;
#endif
#endif
	adapter->netdev = netdev;
	adapter->pdev = pdev;
	hw = &adapter->hw;
	hw->back = adapter;
	adapter->msg_enable = (1 << DEFAULT_DEBUG_LEVEL_SHIFT) - 1;

#ifdef HAVE_PCI_ERS
	/*
	 * call save state here in standalone driver because it relies on
	 * adapter struct to exist, and needs to call netdev_priv
	 */
	pci_save_state(pdev);

#endif
#ifndef ENABLE_DNA
	hw->hw_addr = ioremap(pci_resource_start(pdev, 0),
			      pci_resource_len(pdev, 0));
#else
	{
		unsigned long	mmio_start;
		int		mmio_len;

		hw->hw_addr = ioremap((mmio_start = pci_resource_start(pdev, 0)),
				      (mmio_len = pci_resource_len(pdev, 0)));

		netdev->mem_start = mmio_start;
		netdev->mem_end = mmio_start + mmio_len;

		if(unlikely(enable_debug))
			printk("[DNA] [mmio_start=0x%lx][mmio_len=0x%x]\n", mmio_start, mmio_len);
	}
#endif
	adapter->io_addr = hw->hw_addr;
	if (!hw->hw_addr) {
		err = -EIO;
		goto err_ioremap;
	}

	ixgbe_assign_netdev_ops(netdev);

	strncpy(netdev->name, pci_name(pdev), sizeof(netdev->name) - 1);

	adapter->bd_number = cards_found;

	/* setup the private structure */
	err = ixgbe_sw_init(adapter);
	if (err)
		goto err_sw_init;

	/* Make it possible the adapter to be woken up via WOL */
	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_WUS, ~0);
		break;
	default:
		break;
	}

	/*
	 * If we have a fan, this is as early we know, warn if we
	 * have had a failure.
	 */
	if (adapter->flags & IXGBE_FLAG_FAN_FAIL_CAPABLE) {
		u32 esdp = IXGBE_READ_REG(hw, IXGBE_ESDP);
		if (esdp & IXGBE_ESDP_SDP1)
			e_crit(probe, "Fan has stopped, replace the adapter\n");
	}

	/*
	 * check_options must be called before setup_link to set up
	 * hw->fc completely
	 */
	ixgbe_check_options(adapter);

	/* reset_hw fills in the perm_addr as well */
	hw->phy.reset_if_overtemp = true;
	err = hw->mac.ops.reset_hw(hw);
	hw->phy.reset_if_overtemp = false;
	if (err == IXGBE_ERR_SFP_NOT_PRESENT &&
	    hw->mac.type == ixgbe_mac_82598EB) {
		err = 0;
	} else if (err == IXGBE_ERR_SFP_NOT_SUPPORTED) {
		e_dev_err("failed to load because an unsupported SFP+ or QSFP "
			  "module type was detected.\n");
		e_dev_err("Reload the driver after installing a supported "
			  "module.\n");
		goto err_sw_init;
	} else if (err) {
		e_dev_err("HW Init failed: %d\n", err);
		goto err_sw_init;
	}

#ifdef CONFIG_PCI_IOV
#ifdef HAVE_SRIOV_CONFIGURE
	if (adapter->num_vfs > 0) {
		e_dev_warn("Enabling SR-IOV VFs using the max_vfs module parameter is deprecated.\n");
		e_dev_warn("Please use the pci sysfs interface instead. Ex:\n");
		e_dev_warn("echo '%d' > /sys/bus/pci/devices/%04x:%02x:%02x.%1x/sriov_numvfs\n",
			   adapter->num_vfs,
			   pci_domain_nr(pdev->bus),
			   pdev->bus->number,
			   PCI_SLOT(pdev->devfn),
			   PCI_FUNC(pdev->devfn)
			   );
	}

#endif
	ixgbe_enable_sriov(adapter);

#endif /* CONFIG_PCI_IOV */
	netdev->features |= NETIF_F_SG |
			    NETIF_F_IP_CSUM;

#ifdef NETIF_F_IPV6_CSUM
	netdev->features |= NETIF_F_IPV6_CSUM;
#endif

#ifdef NETIF_F_HW_VLAN_CTAG_TX
	netdev->features |= NETIF_F_HW_VLAN_CTAG_TX |
			    NETIF_F_HW_VLAN_CTAG_RX;
#endif

#ifdef NETIF_F_HW_VLAN_TX
	netdev->features |= NETIF_F_HW_VLAN_TX |
			    NETIF_F_HW_VLAN_RX;
#endif
#ifdef NETIF_F_TSO
	netdev->features |= NETIF_F_TSO;
#endif /* NETIF_F_TSO */
#ifdef NETIF_F_TSO6
	netdev->features |= NETIF_F_TSO6;
#endif /* NETIF_F_TSO6 */
#ifdef NETIF_F_RXHASH
	netdev->features |= NETIF_F_RXHASH;
#endif /* NETIF_F_RXHASH */

	netdev->features |= NETIF_F_RXCSUM;

#ifdef HAVE_NDO_SET_FEATURES
	/* copy netdev features into list of user selectable features */
	netdev->hw_features |= netdev->features;

	/* give us the option of enabling RSC/LRO later */
#ifdef IXGBE_NO_LRO
	if (adapter->flags2 & IXGBE_FLAG2_RSC_CAPABLE)
#endif
		netdev->hw_features |= NETIF_F_LRO;

#else
#ifdef NETIF_F_GRO

	/* this is only needed on kernels prior to 2.6.39 */
	netdev->features |= NETIF_F_GRO;
#endif /* NETIF_F_GRO */
#endif

#ifdef NETIF_F_HW_VLAN_CTAG_TX
	/* set this bit last since it cannot be part of hw_features */
	netdev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;
#endif
#ifdef NETIF_F_HW_VLAN_TX
	/* set this bit last since it cannot be part of hw_features */
	netdev->features |= NETIF_F_HW_VLAN_FILTER;
#endif
	switch (adapter->hw.mac.type) {
	case ixgbe_mac_82599EB:
	case ixgbe_mac_X540:
		netdev->features |= NETIF_F_SCTP_CSUM;
#ifdef HAVE_NDO_SET_FEATURES
		netdev->hw_features |= NETIF_F_SCTP_CSUM |
				       NETIF_F_NTUPLE;
#endif
		break;
	default:
		break;
	}

#ifdef HAVE_NETDEV_VLAN_FEATURES
	netdev->vlan_features |= NETIF_F_SG |
				 NETIF_F_IP_CSUM |
				 NETIF_F_IPV6_CSUM |
				 NETIF_F_TSO |
				 NETIF_F_TSO6;

#endif /* HAVE_NETDEV_VLAN_FEATURES */
	if (netdev->features & NETIF_F_LRO) {
		if ((adapter->flags2 & IXGBE_FLAG2_RSC_CAPABLE) &&
		    ((adapter->rx_itr_setting == 1) ||
		     (adapter->rx_itr_setting > IXGBE_MIN_RSC_ITR))) {
			adapter->flags2 |= IXGBE_FLAG2_RSC_ENABLED;
		} else if (adapter->flags2 & IXGBE_FLAG2_RSC_CAPABLE) {
#ifdef IXGBE_NO_LRO
			e_dev_info("InterruptThrottleRate set too high, "
				   "disabling RSC\n");
#else
			e_dev_info("InterruptThrottleRate set too high, "
				   "falling back to software LRO\n");
#endif
		}
	}
#ifdef IFF_UNICAST_FLT
	netdev->priv_flags |= IFF_UNICAST_FLT;
#endif
#ifdef IFF_SUPP_NOFCS
	netdev->priv_flags |= IFF_SUPP_NOFCS;
#endif
#ifdef CONFIG_DCB
	netdev->dcbnl_ops = &dcbnl_ops;
#endif

#ifdef IXGBE_FCOE
#ifdef NETIF_F_FSO
	if (adapter->flags & IXGBE_FLAG_FCOE_CAPABLE) {
		unsigned int fcoe_l;

		hw->mac.ops.get_device_caps(hw, &device_caps);
		if (device_caps & IXGBE_DEVICE_CAPS_FCOE_OFFLOADS) {
			adapter->flags &= ~IXGBE_FLAG_FCOE_ENABLED;
			adapter->flags &= ~IXGBE_FLAG_FCOE_CAPABLE;
			e_dev_info("FCoE offload feature is not available. "
				   "Disabling FCoE offload feature\n");
		} else {
			netdev->features |= NETIF_F_FSO |
					    NETIF_F_FCOE_CRC;
#ifndef HAVE_NETDEV_OPS_FCOE_ENABLE
			ixgbe_fcoe_ddp_enable(adapter);
			adapter->flags |= IXGBE_FLAG_FCOE_ENABLED;
			netdev->features |= NETIF_F_FCOE_MTU;
#endif /* HAVE_NETDEV_OPS_FCOE_ENABLE */
		}

		fcoe_l = min_t(int, IXGBE_FCRETA_SIZE, num_online_cpus());
		adapter->ring_feature[RING_F_FCOE].limit = fcoe_l;

#ifdef HAVE_NETDEV_VLAN_FEATURES
		netdev->vlan_features |= NETIF_F_FSO |
					 NETIF_F_FCOE_CRC |
					 NETIF_F_FCOE_MTU;
#endif /* HAVE_NETDEV_VLAN_FEATURES */
	}
#endif /* NETIF_F_FSO */
#endif /* IXGBE_FCOE */
	if (pci_using_dac) {
		netdev->features |= NETIF_F_HIGHDMA;
#ifdef HAVE_NETDEV_VLAN_FEATURES
		netdev->vlan_features |= NETIF_F_HIGHDMA;
#endif /* HAVE_NETDEV_VLAN_FEATURES */
	}

	/* make sure the EEPROM is good */
	if (hw->eeprom.ops.validate_checksum &&
	    (hw->eeprom.ops.validate_checksum(hw, NULL) < 0)) {
		e_dev_err("The EEPROM Checksum Is Not Valid\n");
		err = -EIO;
		goto err_sw_init;
	}

	memcpy(netdev->dev_addr, hw->mac.perm_addr, netdev->addr_len);
#ifdef ETHTOOL_GPERMADDR
	memcpy(netdev->perm_addr, hw->mac.perm_addr, netdev->addr_len);

	if (ixgbe_validate_mac_addr(netdev->perm_addr)) {
		e_dev_err("invalid MAC address\n");
		err = -EIO;
		goto err_sw_init;
	}
#else
	if (ixgbe_validate_mac_addr(netdev->dev_addr)) {
		e_dev_err("invalid MAC address\n");
		err = -EIO;
		goto err_sw_init;
	}
#endif
	memcpy(&adapter->mac_table[0].addr, hw->mac.perm_addr,
	       netdev->addr_len);
	adapter->mac_table[0].queue = VMDQ_P(0);
	adapter->mac_table[0].state = (IXGBE_MAC_STATE_DEFAULT |
				       IXGBE_MAC_STATE_IN_USE);
	hw->mac.ops.set_rar(hw, 0, adapter->mac_table[0].addr,
			    adapter->mac_table[0].queue,
			    IXGBE_RAH_AV);

	setup_timer(&adapter->service_timer, &ixgbe_service_timer,
		    (unsigned long) adapter);

	if (IXGBE_REMOVED(hw->hw_addr)) {
		err = -EIO;
		goto err_sw_init;
	}
	INIT_WORK(&adapter->service_task, ixgbe_service_task);
	set_bit(__IXGBE_SERVICE_INITED, &adapter->state);
	clear_bit(__IXGBE_SERVICE_SCHED, &adapter->state);

	err = ixgbe_init_interrupt_scheme(adapter);
	if (err)
		goto err_sw_init;

	/* WOL not supported for all devices */
	adapter->wol = 0;
	hw->eeprom.ops.read(hw, 0x2c, &adapter->eeprom_cap);
	if (ixgbe_wol_supported(adapter, pdev->device, pdev->subsystem_device))
		adapter->wol = IXGBE_WUFC_MAG;

	hw->wol_enabled = !!(adapter->wol);

	device_set_wakeup_enable(pci_dev_to_dev(adapter->pdev), adapter->wol);

	/*
	 * Save off EEPROM version number and Option Rom version which
	 * together make a unique identify for the eeprom
	 */
	hw->eeprom.ops.read(hw, 0x2e, &eeprom_verh);
	hw->eeprom.ops.read(hw, 0x2d, &eeprom_verl);
	etrack_id = (eeprom_verh << 16) | eeprom_verl;

	hw->eeprom.ops.read(hw, 0x17, &offset);

	/* Make sure offset to SCSI block is valid */
	if (!(offset == 0x0) && !(offset == 0xffff)) {
		hw->eeprom.ops.read(hw, offset + 0x84, &eeprom_cfg_blkh);
		hw->eeprom.ops.read(hw, offset + 0x83, &eeprom_cfg_blkl);

		/* Only display Option Rom if exist */
		if (eeprom_cfg_blkl && eeprom_cfg_blkh) {
			major = eeprom_cfg_blkl >> 8;
			build = (eeprom_cfg_blkl << 8) | (eeprom_cfg_blkh >> 8);
			patch = eeprom_cfg_blkh & 0x00ff;

			snprintf(adapter->eeprom_id, sizeof(adapter->eeprom_id),
				 "0x%08x, %d.%d.%d", etrack_id, major, build,
				 patch);
		} else {
			snprintf(adapter->eeprom_id, sizeof(adapter->eeprom_id),
				 "0x%08x", etrack_id);
		}
	} else {
		snprintf(adapter->eeprom_id, sizeof(adapter->eeprom_id),
			 "0x%08x", etrack_id);
	}

	/* reset the hardware with the new settings */
	err = hw->mac.ops.start_hw(hw);
	if (err == IXGBE_ERR_EEPROM_VERSION) {
		/* We are running on a pre-production device, log a warning */
		e_dev_warn("This device is a pre-production adapter/LOM. "
			   "Please be aware there may be issues associated "
			   "with your hardware.  If you are experiencing "
			   "problems please contact your Intel or hardware "
			   "representative who provided you with this "
			   "hardware.\n");
	}
	/* pick up the PCI bus settings for reporting later */
	if (ixgbe_pcie_from_parent(hw))
		ixgbe_get_parent_bus_info(hw);
	else
		if (hw->mac.ops.get_bus_info)
			hw->mac.ops.get_bus_info(hw);

#ifdef ENABLE_DNA
	dna_check_enable_adapter(adapter);
	if(adapter->dna.dna_enabled)
		strcpy(netdev->name, "dna%d");
	else
#endif
	strcpy(netdev->name, "eth%d");
	err = register_netdev(netdev);
	if (err)
		goto err_register;

	adapter->netdev_registered = true;

	/* power down the optics for 82599 SFP+ fiber */
	if (hw->mac.ops.disable_tx_laser)
		hw->mac.ops.disable_tx_laser(hw);

	/* carrier off reporting is important to ethtool even BEFORE open */
	netif_carrier_off(netdev);
	/* keep stopping all the transmit queues for older kernels */
	netif_tx_stop_all_queues(netdev);

#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
	if (adapter->flags & IXGBE_FLAG_DCA_CAPABLE) {
		err = dca_add_requester(pci_dev_to_dev(pdev));
		switch (err) {
		case 0:
			adapter->flags |= IXGBE_FLAG_DCA_ENABLED;
			ixgbe_setup_dca(adapter);
#ifdef ENABLE_DNA
			printk("[DNA] DCA enabled on %s\n", netdev->name);
#endif
			break;
		/* -19 is returned from the kernel when no provider is found */
		case -19:
			e_info(rx_err, "No DCA provider found. Please "
			       "start ioatdma for DCA functionality.\n");
			break;
		default:
			e_info(probe, "DCA registration failed: %d\n", err);
			break;
		}
	}
#endif

	/* print all messages at the end so that we use our eth%d name */

	/* calculate the expected PCIe bandwidth required for optimal
	 * performance. Note that some older parts will never have enough
	 * bandwidth due to being older generation PCIe parts. We clamp these
	 * parts to ensure that no warning is displayed, as this could confuse
	 * users otherwise. */
	switch(hw->mac.type) {
	case ixgbe_mac_82598EB:
		expected_gts = min(ixgbe_enumerate_functions(adapter) * 10, 16);
		break;
	default:
		expected_gts = ixgbe_enumerate_functions(adapter) * 10;
		break;
	}
	ixgbe_check_minimum_link(adapter, expected_gts);

	/* First try to read PBA as a string */
	err = ixgbe_read_pba_string(hw, part_str, IXGBE_PBANUM_LENGTH);
	if (err)
		strncpy(part_str, "Unknown", IXGBE_PBANUM_LENGTH);
	if (ixgbe_is_sfp(hw) && hw->phy.sfp_type != ixgbe_sfp_type_not_present)
		e_info(probe, "MAC: %d, PHY: %d, SFP+: %d, PBA No: %s\n",
		       hw->mac.type, hw->phy.type, hw->phy.sfp_type, part_str);
	else
		e_info(probe, "MAC: %d, PHY: %d, PBA No: %s\n",
		      hw->mac.type, hw->phy.type, part_str);

	e_dev_info("%02x:%02x:%02x:%02x:%02x:%02x\n",
		   netdev->dev_addr[0], netdev->dev_addr[1],
		   netdev->dev_addr[2], netdev->dev_addr[3],
		   netdev->dev_addr[4], netdev->dev_addr[5]);

#define INFO_STRING_LEN 255
	info_string = kzalloc(INFO_STRING_LEN, GFP_KERNEL);
	if (!info_string) {
		e_err(probe, "allocation for info string failed\n");
		goto no_info_string;
	}
	i_s_var = info_string;
	i_s_var += sprintf(info_string, "Enabled Features: ");
	i_s_var += sprintf(i_s_var, "RxQ: %d TxQ: %d ",
			   adapter->num_rx_queues, adapter->num_tx_queues);
#ifdef IXGBE_FCOE
	if (adapter->flags & IXGBE_FLAG_FCOE_ENABLED)
		i_s_var += sprintf(i_s_var, "FCoE ");
#endif
	if (adapter->flags & IXGBE_FLAG_FDIR_HASH_CAPABLE)
		i_s_var += sprintf(i_s_var, "FdirHash ");
	if (adapter->flags & IXGBE_FLAG_DCB_ENABLED)
		i_s_var += sprintf(i_s_var, "DCB ");
	if (adapter->flags & IXGBE_FLAG_DCA_ENABLED)
		i_s_var += sprintf(i_s_var, "DCA ");
	if (adapter->flags2 & IXGBE_FLAG2_RSC_ENABLED)
		i_s_var += sprintf(i_s_var, "RSC ");
#ifndef IXGBE_NO_LRO
	else if (netdev->features & NETIF_F_LRO)
		i_s_var += sprintf(i_s_var, "LRO ");
#endif

	BUG_ON(i_s_var > (info_string + INFO_STRING_LEN));
	/* end features printing */
	e_info(probe, "%s\n", info_string);
	kfree(info_string);
no_info_string:
#ifdef CONFIG_PCI_IOV
	if (adapter->flags & IXGBE_FLAG_SRIOV_ENABLED) {
		int i;
		for (i = 0; i < adapter->num_vfs; i++)
			ixgbe_vf_configuration(pdev, (i | 0x10000000));
	}
#endif

	/* firmware requires blank driver version */
	if (hw->mac.ops.set_fw_drv_ver)
		hw->mac.ops.set_fw_drv_ver(hw, 0xFF, 0xFF, 0xFF, 0xFF);

#if defined(HAVE_NETDEV_STORAGE_ADDRESS) && defined(NETDEV_HW_ADDR_T_SAN)
	/* add san mac addr to netdev */
	ixgbe_add_sanmac_netdev(netdev);

#endif /* (HAVE_NETDEV_STORAGE_ADDRESS) && (NETDEV_HW_ADDR_T_SAN) */
	e_info(probe, "Intel(R) 10 Gigabit Network Connection\n");
	cards_found++;

#ifdef IXGBE_SYSFS
	if (ixgbe_sysfs_init(adapter))
		e_err(probe, "failed to allocate sysfs resources\n");
#else
#ifdef IXGBE_PROCFS
	if (ixgbe_procfs_init(adapter))
		e_err(probe, "failed to allocate procfs resources\n");
#endif /* IXGBE_PROCFS */
#endif /* IXGBE_SYSFS */
#ifdef HAVE_IXGBE_DEBUG_FS

	ixgbe_dbg_adapter_init(adapter);
#endif /* HAVE_IXGBE_DEBUG_FS */

	/* Need link setup for MNG FW, else wait for IXGBE_UP */
	if (ixgbe_mng_enabled(hw) && hw->mac.ops.setup_link)
		hw->mac.ops.setup_link(hw,
			IXGBE_LINK_SPEED_10GB_FULL | IXGBE_LINK_SPEED_1GB_FULL,
			true);

	return 0;

err_register:
	ixgbe_clear_interrupt_scheme(adapter);
	ixgbe_release_hw_control(adapter);
err_sw_init:
#ifdef CONFIG_PCI_IOV
	ixgbe_disable_sriov(adapter);
#endif /* CONFIG_PCI_IOV */
	adapter->flags2 &= ~IXGBE_FLAG2_SEARCH_FOR_SFP;
	kfree(adapter->mac_table);
	iounmap(adapter->io_addr);
err_ioremap:
	free_netdev(netdev);
err_alloc_etherdev:
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));
err_pci_reg:
err_dma:
	if (!test_and_set_bit(__IXGBE_DISABLED, &adapter->state))
		pci_disable_device(pdev);
	return err;
}

/**
 * ixgbe_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * ixgbe_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/
static void __devexit ixgbe_remove(struct pci_dev *pdev)
{
	struct ixgbe_adapter *adapter = pci_get_drvdata(pdev);
	struct net_device *netdev = adapter->netdev;

#ifdef HAVE_IXGBE_DEBUG_FS
	ixgbe_dbg_adapter_exit(adapter);

#endif /*HAVE_IXGBE_DEBUG_FS */
	set_bit(__IXGBE_REMOVE, &adapter->state);
	cancel_work_sync(&adapter->service_task);

#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
	if (adapter->flags & IXGBE_FLAG_DCA_ENABLED) {
		adapter->flags &= ~IXGBE_FLAG_DCA_ENABLED;
		dca_remove_requester(pci_dev_to_dev(pdev));
		IXGBE_WRITE_REG(&adapter->hw, IXGBE_DCA_CTRL,
				IXGBE_DCA_CTRL_DCA_DISABLE);
	}

#endif
#ifdef IXGBE_SYSFS
	ixgbe_sysfs_exit(adapter);
#else
#ifdef IXGBE_PROCFS
	ixgbe_procfs_exit(adapter);
#endif /* IXGBE_PROCFS */
#endif /* IXGBE-SYSFS */

#if defined(HAVE_NETDEV_STORAGE_ADDRESS) && defined(NETDEV_HW_ADDR_T_SAN)
	/* remove the added san mac */
	ixgbe_del_sanmac_netdev(netdev);

#endif /* (HAVE_NETDEV_STORAGE_ADDRESS) && (NETDEV_HW_ADDR_T_SAN) */
	if (adapter->netdev_registered) {
		unregister_netdev(netdev);
		adapter->netdev_registered = false;
	}

#ifdef CONFIG_PCI_IOV
	ixgbe_disable_sriov(adapter);
#endif /* CONFIG_PCI_IOV */

#ifdef IXGBE_FCOE
#ifndef HAVE_NETDEV_OPS_FCOE_ENABLE
	ixgbe_fcoe_ddp_disable(adapter);

#endif
#endif /* IXGBE_FCOE */
	ixgbe_clear_interrupt_scheme(adapter);
	ixgbe_release_hw_control(adapter);

#ifdef HAVE_DCBNL_IEEE
	kfree(adapter->ixgbe_ieee_pfc);
	kfree(adapter->ixgbe_ieee_ets);

#endif
	iounmap(adapter->io_addr);
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));

	kfree(adapter->mac_table);
	free_netdev(netdev);

	pci_disable_pcie_error_reporting(pdev);

	if (!test_and_set_bit(__IXGBE_DISABLED, &adapter->state))
		pci_disable_device(pdev);
}

static bool ixgbe_check_cfg_remove(struct ixgbe_hw *hw, struct pci_dev *pdev)
{
	u16 value;

	pci_read_config_word(pdev, PCI_VENDOR_ID, &value);
	if (value == IXGBE_FAILED_READ_CFG_WORD) {
		ixgbe_remove_adapter(hw);
		return true;
	}
	return false;
}

u16 ixgbe_read_pci_cfg_word(struct ixgbe_hw *hw, u32 reg)
{
	struct ixgbe_adapter *adapter = hw->back;
	u16 value;

	if (IXGBE_REMOVED(hw->hw_addr))
		return IXGBE_FAILED_READ_CFG_WORD;
	pci_read_config_word(adapter->pdev, reg, &value);
	if (value == IXGBE_FAILED_READ_CFG_WORD &&
	    ixgbe_check_cfg_remove(hw, adapter->pdev))
		return IXGBE_FAILED_READ_CFG_WORD;
	return value;
}

#ifdef HAVE_PCI_ERS
#ifdef CONFIG_PCI_IOV
static u32 ixgbe_read_pci_cfg_dword(struct ixgbe_hw *hw, u32 reg)
{
	struct ixgbe_adapter *adapter = hw->back;
	u32 value;

	if (IXGBE_REMOVED(hw->hw_addr))
		return IXGBE_FAILED_READ_CFG_DWORD;
	pci_read_config_dword(adapter->pdev, reg, &value);
	if (value == IXGBE_FAILED_READ_CFG_DWORD &&
	    ixgbe_check_cfg_remove(hw, adapter->pdev))
		return IXGBE_FAILED_READ_CFG_DWORD;
	return value;
}
#endif /* CONFIG_PCI_IOV */
#endif /* HAVE_PCI_ERS */

void ixgbe_write_pci_cfg_word(struct ixgbe_hw *hw, u32 reg, u16 value)
{
	struct ixgbe_adapter *adapter = hw->back;

	if (IXGBE_REMOVED(hw->hw_addr))
		return;
	pci_write_config_word(adapter->pdev, reg, value);
}

void ewarn(struct ixgbe_hw *hw, const char *st, u32 status)
{
	struct ixgbe_adapter *adapter = hw->back;

	netif_warn(adapter, drv, adapter->netdev,  "%s", st);
}

#ifdef HAVE_PCI_ERS
/**
 * ixgbe_io_error_detected - called when PCI error is detected
 * @pdev: Pointer to PCI device
 * @state: The current pci connection state
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 */
static pci_ers_result_t ixgbe_io_error_detected(struct pci_dev *pdev,
						pci_channel_state_t state)
{
	struct ixgbe_adapter *adapter = pci_get_drvdata(pdev);
	struct net_device *netdev = adapter->netdev;

#ifdef CONFIG_PCI_IOV
	struct ixgbe_hw *hw = &adapter->hw;
	struct pci_dev *bdev, *vfdev;
	u32 dw0, dw1, dw2, dw3;
	int vf, pos;
	u16 req_id, pf_func;

	if (adapter->hw.mac.type == ixgbe_mac_82598EB ||
	    adapter->num_vfs == 0)
		goto skip_bad_vf_detection;

	bdev = pdev->bus->self;
	while (bdev && (pci_pcie_type(bdev) != PCI_EXP_TYPE_ROOT_PORT))
		bdev = bdev->bus->self;

	if (!bdev)
		goto skip_bad_vf_detection;

	pos = pci_find_ext_capability(bdev, PCI_EXT_CAP_ID_ERR);
	if (!pos)
		goto skip_bad_vf_detection;

	dw0 = ixgbe_read_pci_cfg_dword(hw, pos + PCI_ERR_HEADER_LOG);
	dw1 = ixgbe_read_pci_cfg_dword(hw, pos + PCI_ERR_HEADER_LOG + 4);
	dw2 = ixgbe_read_pci_cfg_dword(hw, pos + PCI_ERR_HEADER_LOG + 8);
	dw3 = ixgbe_read_pci_cfg_dword(hw, pos + PCI_ERR_HEADER_LOG + 12);
	if (IXGBE_REMOVED(hw->hw_addr))
		goto skip_bad_vf_detection;

	req_id = dw1 >> 16;
	/* On the 82599 if bit 7 of the requestor ID is set then it's a VF */
	if (!(req_id & 0x0080))
		goto skip_bad_vf_detection;

	pf_func = req_id & 0x01;
	if ((pf_func & 1) == (pdev->devfn & 1)) {
		unsigned int device_id;

		vf = (req_id & 0x7F) >> 1;
		e_dev_err("VF %d has caused a PCIe error\n", vf);
		e_dev_err("TLP: dw0: %8.8x\tdw1: %8.8x\tdw2: "
				"%8.8x\tdw3: %8.8x\n",
		dw0, dw1, dw2, dw3);
		switch (adapter->hw.mac.type) {
		case ixgbe_mac_82599EB:
			device_id = IXGBE_82599_VF_DEVICE_ID;
			break;
		case ixgbe_mac_X540:
			device_id = IXGBE_X540_VF_DEVICE_ID;
			break;
		default:
			device_id = 0;
			break;
		}

		/* Find the pci device of the offending VF */
		vfdev = pci_get_device(PCI_VENDOR_ID_INTEL, device_id, NULL);
		while (vfdev) {
			if (vfdev->devfn == (req_id & 0xFF))
				break;
			vfdev = pci_get_device(PCI_VENDOR_ID_INTEL,
					       device_id, vfdev);
		}
		/*
		 * There's a slim chance the VF could have been hot plugged,
		 * so if it is no longer present we don't need to issue the
		 * VFLR.  Just clean up the AER in that case.
		 */
		if (vfdev) {
			e_dev_err("Issuing VFLR to VF %d\n", vf);
			pci_write_config_dword(vfdev, 0xA8, 0x00008000);
			/* Free device reference count */
			pci_dev_put(vfdev);
		}

		pci_cleanup_aer_uncorrect_error_status(pdev);
	}

	/*
	 * Even though the error may have occurred on the other port
	 * we still need to increment the vf error reference count for
	 * both ports because the I/O resume function will be called
	 * for both of them.
	 */
	adapter->vferr_refcount++;

	return PCI_ERS_RESULT_RECOVERED;

skip_bad_vf_detection:
#endif /* CONFIG_PCI_IOV */
	if (!test_bit(__IXGBE_SERVICE_INITED, &adapter->state))
		return PCI_ERS_RESULT_DISCONNECT;

	rtnl_lock();
	netif_device_detach(netdev);

	if (state == pci_channel_io_perm_failure) {
		rtnl_unlock();
		return PCI_ERS_RESULT_DISCONNECT;
	}

	if (netif_running(netdev))
		ixgbe_down(adapter);

	if (!test_and_set_bit(__IXGBE_DISABLED, &adapter->state))
		pci_disable_device(pdev);
	rtnl_unlock();

	/* Request a slot reset. */
	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * ixgbe_io_slot_reset - called after the pci bus has been reset.
 * @pdev: Pointer to PCI device
 *
 * Restart the card from scratch, as if from a cold-boot.
 */
static pci_ers_result_t ixgbe_io_slot_reset(struct pci_dev *pdev)
{
	struct ixgbe_adapter *adapter = pci_get_drvdata(pdev);
	pci_ers_result_t result;

	if (pci_enable_device_mem(pdev)) {
		e_err(probe, "Cannot re-enable PCI device after reset.\n");
		result = PCI_ERS_RESULT_DISCONNECT;
	} else {
		smp_mb__before_clear_bit();
		clear_bit(__IXGBE_DISABLED, &adapter->state);
		adapter->hw.hw_addr = adapter->io_addr;
		pci_set_master(pdev);
		pci_restore_state(pdev);
		/*
		 * After second error pci->state_saved is false, this
		 * resets it so EEH doesn't break.
		 */
		pci_save_state(pdev);

		pci_wake_from_d3(pdev, false);

		adapter->flags2 |= IXGBE_FLAG2_RESET_REQUESTED;
		ixgbe_service_event_schedule(adapter);

		IXGBE_WRITE_REG(&adapter->hw, IXGBE_WUS, ~0);
		result = PCI_ERS_RESULT_RECOVERED;
	}

	pci_cleanup_aer_uncorrect_error_status(pdev);

	return result;
}

/**
 * ixgbe_io_resume - called when traffic can start flowing again.
 * @pdev: Pointer to PCI device
 *
 * This callback is called when the error recovery driver tells us that
 * its OK to resume normal operation.
 */
static void ixgbe_io_resume(struct pci_dev *pdev)
{
	struct ixgbe_adapter *adapter = pci_get_drvdata(pdev);
	struct net_device *netdev = adapter->netdev;

#ifdef CONFIG_PCI_IOV
	if (adapter->vferr_refcount) {
		e_info(drv, "Resuming after VF err\n");
		adapter->vferr_refcount--;
		return;
	}

#endif
	if (netif_running(netdev))
		ixgbe_up(adapter);

	netif_device_attach(netdev);
}

#ifdef HAVE_CONST_STRUCT_PCI_ERROR_HANDLERS
static const struct pci_error_handlers ixgbe_err_handler = {
#else
static struct pci_error_handlers ixgbe_err_handler = {
#endif
	.error_detected = ixgbe_io_error_detected,
	.slot_reset = ixgbe_io_slot_reset,
	.resume = ixgbe_io_resume,
};
#endif /* HAVE_PCI_ERS */

struct net_device *ixgbe_hw_to_netdev(const struct ixgbe_hw *hw)
{
	return ((struct ixgbe_adapter *)hw->back)->netdev;
}
struct ixgbe_msg *ixgbe_hw_to_msg(const struct ixgbe_hw *hw)
{
	struct ixgbe_adapter *adapter =
		container_of(hw, struct ixgbe_adapter, hw);
	return (struct ixgbe_msg *)&adapter->msg_enable;
}

static struct pci_driver ixgbe_driver = {
	.name     = ixgbe_driver_name,
	.id_table = ixgbe_pci_tbl,
	.probe    = ixgbe_probe,
	.remove   = __devexit_p(ixgbe_remove),
#ifdef CONFIG_PM
	.suspend  = ixgbe_suspend,
	.resume   = ixgbe_resume,
#endif
#ifndef USE_REBOOT_NOTIFIER
	.shutdown = ixgbe_shutdown,
#endif
#ifdef HAVE_SRIOV_CONFIGURE
	.sriov_configure = ixgbe_pci_sriov_configure,
#endif
#ifdef HAVE_PCI_ERS
	.err_handler = &ixgbe_err_handler
#endif
};

bool ixgbe_is_ixgbe(struct pci_dev *pcidev)
{
	if (pci_dev_driver(pcidev) != &ixgbe_driver)
		return false;
	else
		return true;
}

/**
 * ixgbe_init_module - Driver Registration Routine
 *
 * ixgbe_init_module is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 **/
static int __init ixgbe_init_module(void)
{
	int ret;
	pr_info("%s - version %s\n", ixgbe_driver_string, ixgbe_driver_version);
	pr_info("%s\n", ixgbe_copyright);


#ifdef IXGBE_PROCFS
	if (ixgbe_procfs_topdir_init())
		pr_info("Procfs failed to initialize topdir\n");
#endif

#ifdef HAVE_IXGBE_DEBUG_FS
	ixgbe_dbg_init();
#endif /* HAVE_IXGBE_DEBUG_FS */
#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
	dca_register_notify(&dca_notifier);
#endif

	ret = pci_register_driver(&ixgbe_driver);
	return ret;
}

module_init(ixgbe_init_module);

/**
 * ixgbe_exit_module - Driver Exit Cleanup Routine
 *
 * ixgbe_exit_module is called just before the driver is removed
 * from memory.
 **/
static void __exit ixgbe_exit_module(void)
{
#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
	dca_unregister_notify(&dca_notifier);
#endif
	pci_unregister_driver(&ixgbe_driver);
#ifdef IXGBE_PROCFS
	ixgbe_procfs_topdir_exit();
#endif
#ifdef HAVE_IXGBE_DEBUG_FS
	ixgbe_dbg_exit();
#endif /* HAVE_IXGBE_DEBUG_FS */
}

#if defined(CONFIG_DCA) || defined(CONFIG_DCA_MODULE)
static int ixgbe_notify_dca(struct notifier_block *nb, unsigned long event,
			    void *p)
{
	int ret_val;

	ret_val = driver_for_each_device(&ixgbe_driver.driver, NULL, &event,
					 __ixgbe_notify_dca);

	return ret_val ? NOTIFY_BAD : NOTIFY_DONE;
}
#endif
module_exit(ixgbe_exit_module);

/* ixgbe_main.c */

