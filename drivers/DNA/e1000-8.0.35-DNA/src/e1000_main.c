/*******************************************************************************

  Intel PRO/1000 Linux driver
  Copyright(c) 1999 - 2010 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/netdevice.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#ifdef NETIF_F_TSO
#include <net/checksum.h>
#ifdef NETIF_F_TSO6
#include <net/ip6_checksum.h>
#endif
#endif
#ifdef SIOCGMIIPHY
#include <linux/mii.h>
#endif
#ifdef SIOCETHTOOL
#include <linux/ethtool.h>
#endif
#ifdef NETIF_F_HW_VLAN_TX
#include <linux/if_vlan.h>
#endif

#include "e1000.h"

char e1000_driver_name[] = "e1000";
static char e1000_driver_string[] = "Intel(R) PRO/1000 Network Driver";

#ifdef CONFIG_E1000_NAPI
#define DRV_NAPI "-NAPI"
#else
#define DRV_NAPI
#endif

#define DRV_DEBUG

#define DRV_HW_PERF

#ifdef ENABLE_DNA
#undef DRV_HW_PERF
#define DRV_HW_PERF  "-DNA"
#endif


#define DRV_VERSION "8.0.35" DRV_NAPI DRV_DEBUG DRV_HW_PERF
const char e1000_driver_version[] = DRV_VERSION;
static const char e1000_copyright[] = "Copyright (c) 1999-2010 Intel Corporation.";

#ifdef ENABLE_DNA
#include "e1000_dna.c"
#endif

/* e1000_pci_tbl - PCI Device ID Table
 *
 * Last entry must be all 0s
 *
 * Macro expands to...
 *   {PCI_DEVICE(PCI_VENDOR_ID_INTEL, device_id)}
 */
static struct pci_device_id e1000_pci_tbl[] = {
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82542),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82543GC_FIBER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82543GC_COPPER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82544EI_COPPER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82544EI_FIBER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82544GC_COPPER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82544GC_LOM),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82540EM),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82545EM_COPPER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82546EB_COPPER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82545EM_FIBER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82546EB_FIBER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82541EI),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82541ER_LOM),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82540EM_LOM),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82540EP_LOM),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82540EP),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82541EI_MOBILE),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82547EI),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82547EI_MOBILE),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82546EB_QUAD_COPPER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82540EP_LP),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82545GM_COPPER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82545GM_FIBER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82545GM_SERDES),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82547GI),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82541GI),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82541GI_MOBILE),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82541ER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82546GB_COPPER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82546GB_FIBER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82546GB_SERDES),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82541GI_LF),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82546GB_PCIE),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82546GB_QUAD_COPPER),
	INTEL_E1000_ETHERNET_DEVICE(E1000_DEV_ID_82546GB_QUAD_COPPER_KSP3),
	/* required last entry */
	{0,}
};

MODULE_DEVICE_TABLE(pci, e1000_pci_tbl);

static int e1000_setup_tx_resources(struct e1000_adapter *adapter,
                                    struct e1000_tx_ring *tx_ring);
static int e1000_setup_rx_resources(struct e1000_adapter *adapter,
                                    struct e1000_rx_ring *rx_ring);
static void e1000_free_tx_resources(struct e1000_adapter *adapter,
                                    struct e1000_tx_ring *tx_ring);
static void e1000_free_rx_resources(struct e1000_adapter *adapter,
                                    struct e1000_rx_ring *rx_ring);

static int e1000_init_module(void);
static void e1000_exit_module(void);
static int e1000_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
static void __devexit e1000_remove(struct pci_dev *pdev);
static int e1000_alloc_rings(struct e1000_adapter *adapter);
static int e1000_sw_init(struct e1000_adapter *adapter);
static int e1000_open(struct net_device *netdev);
static int e1000_close(struct net_device *netdev);
static void e1000_configure(struct e1000_adapter *adapter);
static void e1000_configure_tx(struct e1000_adapter *adapter);
static void e1000_configure_rx(struct e1000_adapter *adapter);
static void e1000_setup_rctl(struct e1000_adapter *adapter);
static void e1000_clean_all_tx_rings(struct e1000_adapter *adapter);
static void e1000_clean_all_rx_rings(struct e1000_adapter *adapter);
static void e1000_clean_tx_ring(struct e1000_adapter *adapter,
                                struct e1000_tx_ring *tx_ring);
static void e1000_clean_rx_ring(struct e1000_adapter *adapter,
                                struct e1000_rx_ring *rx_ring);
static void e1000_set_multi(struct net_device *netdev);
static void e1000_update_phy_info(unsigned long data);
static void e1000_update_phy_info_task(struct work_struct *work);
static void e1000_watchdog(unsigned long data);
static void e1000_watchdog_task(struct work_struct *work);
static void e1000_82547_tx_fifo_stall(unsigned long data);
static void e1000_82547_tx_fifo_stall_task(struct work_struct *work);
static int e1000_xmit_frame(struct sk_buff *skb, struct net_device *netdev);
static void e1000_phy_read_status(struct e1000_adapter *adapter);
static struct net_device_stats * e1000_get_stats(struct net_device *netdev);
static int e1000_change_mtu(struct net_device *netdev, int new_mtu);
static int e1000_set_mac(struct net_device *netdev, void *p);
static irqreturn_t e1000_intr(int irq, void *data);
static bool e1000_clean_tx_irq(struct e1000_adapter *adapter,
                                    struct e1000_tx_ring *tx_ring);
#ifdef CONFIG_E1000_NAPI
static int e1000_poll(struct napi_struct *napi, int budget);
static bool e1000_clean_rx_irq(struct e1000_adapter *adapter,
                                    struct e1000_rx_ring *rx_ring,
                                    int *work_done, int work_to_do);
static bool e1000_clean_jumbo_rx_irq(struct e1000_adapter *adapter,
                                          struct e1000_rx_ring *rx_ring,
                                          int *work_done, int work_to_do);
static void e1000_alloc_jumbo_rx_buffers(struct e1000_adapter *adapter,
                                         struct e1000_rx_ring *rx_ring,
                                         int cleaned_count);
#else
static bool e1000_clean_rx_irq(struct e1000_adapter *adapter,
                                    struct e1000_rx_ring *rx_ring);
#endif
static void e1000_alloc_rx_buffers(struct e1000_adapter *adapter,
                                   struct e1000_rx_ring *rx_ring,
                                   int cleaned_count);
static int e1000_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd);
#ifdef SIOCGMIIPHY
static int e1000_mii_ioctl(struct net_device *netdev, struct ifreq *ifr,
                           int cmd);
#endif
static void e1000_enter_82542_rst(struct e1000_adapter *adapter);
static void e1000_leave_82542_rst(struct e1000_adapter *adapter);
static void e1000_tx_timeout(struct net_device *dev);
static void e1000_reset_task(struct work_struct *work);
static void e1000_smartspeed(struct e1000_adapter *adapter);
static int e1000_82547_fifo_workaround(struct e1000_adapter *adapter,
                                       struct sk_buff *skb);

#ifdef NETIF_F_HW_VLAN_TX
static void e1000_vlan_rx_register(struct net_device *netdev,
                                   struct vlan_group *grp);
static void e1000_vlan_rx_add_vid(struct net_device *netdev, u16 vid);
static void e1000_vlan_rx_kill_vid(struct net_device *netdev, u16 vid);
static void e1000_restore_vlan(struct e1000_adapter *adapter);
#endif

#if defined(CONFIG_PM) || defined(USE_REBOOT_NOTIFIER)
static int e1000_suspend(struct pci_dev *pdev, pm_message_t state);
#endif
#ifdef CONFIG_PM
static int e1000_resume(struct pci_dev *pdev);
#endif
#ifndef USE_REBOOT_NOTIFIER
static void e1000_shutdown(struct pci_dev *pdev);
#else
static int e1000_notify_reboot(struct notifier_block *, unsigned long event,
                               void *ptr);
static struct notifier_block e1000_notifier_reboot = {
	.notifier_call	= e1000_notify_reboot,
	.next		= NULL,
	.priority	= 0
};
#endif

#ifdef CONFIG_NET_POLL_CONTROLLER
/* for netdump / net console */
static void e1000_netpoll (struct net_device *netdev);
#endif

#define COPYBREAK_DEFAULT 256
static unsigned int copybreak __read_mostly = COPYBREAK_DEFAULT;
module_param(copybreak, uint, 0644);
MODULE_PARM_DESC(copybreak,
	"Maximum size of packet that is copied to a new buffer on receive");

static int ignore_64bit_dma = 0;
module_param(ignore_64bit_dma, int, 0444);
MODULE_PARM_DESC(ignore_64bit_dma, "Ignore 64-bit DMA (DAC) capability");

#ifdef HAVE_PCI_ERS
static pci_ers_result_t e1000_io_error_detected(struct pci_dev *pdev,
                     pci_channel_state_t state);
static pci_ers_result_t e1000_io_slot_reset(struct pci_dev *pdev);
static void e1000_io_resume(struct pci_dev *pdev);

static struct pci_error_handlers e1000_err_handler = {
	.error_detected = e1000_io_error_detected,
	.slot_reset = e1000_io_slot_reset,
	.resume = e1000_io_resume,
};
#endif

static struct pci_driver e1000_driver = {
	.name     = e1000_driver_name,
	.id_table = e1000_pci_tbl,
	.probe    = e1000_probe,
	.remove   = __devexit_p(e1000_remove),
#ifdef CONFIG_PM
	/* Power Management Hooks */
	.suspend  = e1000_suspend,
	.resume   = e1000_resume,
#endif
#ifndef USE_REBOOT_NOTIFIER
	.shutdown = e1000_shutdown,
#endif
#ifdef HAVE_PCI_ERS
	.err_handler = &e1000_err_handler
#endif
};

MODULE_AUTHOR("Intel Corporation, <linux.nics@intel.com>");
MODULE_DESCRIPTION("Intel(R) PRO/1000 Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

static int debug = NETIF_MSG_DRV | NETIF_MSG_PROBE;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "Debug level (0=none,...,16=all)");

/**
 * e1000_init_module - Driver Registration Routine
 *
 * e1000_init_module is the first routine called when the driver is
 * loaded. All it does is register with the PCI subsystem.
 **/
static int __init e1000_init_module(void)
{
	int ret;
	printk(KERN_INFO "%s - version %s\n",
	       e1000_driver_string, e1000_driver_version);

	printk(KERN_INFO "%s\n", e1000_copyright);

	ret = pci_register_driver(&e1000_driver);
#ifdef USE_REBOOT_NOTIFIER
	if (ret >= 0) {
		register_reboot_notifier(&e1000_notifier_reboot);
	}
#endif
	if (copybreak != COPYBREAK_DEFAULT) {
		if (copybreak == 0)
			printk(KERN_INFO "e1000: copybreak disabled\n");
		else
			printk(KERN_INFO "e1000: copybreak enabled for "
			       "packets <= %u bytes\n", copybreak);
	}
	return ret;
}

module_init(e1000_init_module);

/**
 * e1000_exit_module - Driver Exit Cleanup Routine
 *
 * e1000_exit_module is called just before the driver is removed
 * from memory.
 **/
static void __exit e1000_exit_module(void)
{
#ifdef USE_REBOOT_NOTIFIER
	unregister_reboot_notifier(&e1000_notifier_reboot);
#endif
	pci_unregister_driver(&e1000_driver);
}

module_exit(e1000_exit_module);

static int e1000_request_irq(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int irq_flags, err = 0;

	irq_flags = IRQF_SHARED;

	err = request_irq(adapter->pdev->irq, &e1000_intr, irq_flags,
	                  netdev->name, netdev);
	if (err)
		DPRINTK(PROBE, ERR, "Unable to allocate interrupt Error: %d\n",
		        err);

	return err;
}

static void e1000_free_irq(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	free_irq(adapter->pdev->irq, netdev);
}

/**
 * e1000_irq_disable - Mask off interrupt generation on the NIC
 * @adapter: board private structure
 **/
static void e1000_irq_disable(struct e1000_adapter *adapter)
{
	E1000_WRITE_REG(&adapter->hw, E1000_IMC, ~0);
	E1000_WRITE_FLUSH(&adapter->hw);
	synchronize_irq(adapter->pdev->irq);
}

/**
 * e1000_irq_enable - Enable default interrupt generation settings
 * @adapter: board private structure
 **/

static void e1000_irq_enable(struct e1000_adapter *adapter)
{
	E1000_WRITE_REG(&adapter->hw, E1000_IMS, IMS_ENABLE_MASK);
	E1000_WRITE_FLUSH(&adapter->hw);

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled) 
	  adapter->dna.interrupt_enabled = 1;
#endif
}
#ifdef NETIF_F_HW_VLAN_TX

static void e1000_update_mng_vlan(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	u16 vid = adapter->hw.mng_cookie.vlan_id;
	u16 old_vid = adapter->mng_vlan_id;
	if (adapter->vlgrp) {
		if (!vlan_group_get_device(adapter->vlgrp, vid)) {
			if (adapter->hw.mng_cookie.status &
				E1000_MNG_DHCP_COOKIE_STATUS_VLAN) {
				e1000_vlan_rx_add_vid(netdev, vid);
				adapter->mng_vlan_id = vid;
			} else {
				adapter->mng_vlan_id = E1000_MNG_VLAN_NONE;
			}

			if ((old_vid != (u16)E1000_MNG_VLAN_NONE) &&
					(vid != old_vid) &&
			    !vlan_group_get_device(adapter->vlgrp, old_vid))
				e1000_vlan_rx_kill_vid(netdev, old_vid);
		} else {
			adapter->mng_vlan_id = vid;
		}
	}
}
#endif

static void e1000_init_manageability(struct e1000_adapter *adapter)
{
	if (adapter->en_mng_pt) {
		u32 manc = E1000_READ_REG(&adapter->hw, E1000_MANC);

		/* disable hardware interception of ARP */
		manc &= ~(E1000_MANC_ARP_EN);

		E1000_WRITE_REG(&adapter->hw, E1000_MANC, manc);
	}
}

static void e1000_release_manageability(struct e1000_adapter *adapter)
{
	if (adapter->en_mng_pt) {
		u32 manc = E1000_READ_REG(&adapter->hw, E1000_MANC);

		/* re-enable hardware interception of ARP */
		manc |= E1000_MANC_ARP_EN;

		/* This is asymmetric with init_manageability, as we want to
		 * ensure that MNG2HOST filters are still enabled after this
		 * driver is unloaded as other host drivers such as PXE also
		 * may require these filters. */

		/* XXX stop the hardware watchdog ? */

		E1000_WRITE_REG(&adapter->hw, E1000_MANC, manc);
	}
}

/**
 * e1000_configure - configure the hardware for RX and TX
 * @adapter: private board structure
 **/
static void e1000_configure(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct e1000_rx_ring *ring = adapter->rx_ring;

	e1000_set_multi(netdev);

#ifdef NETIF_F_HW_VLAN_TX
	e1000_restore_vlan(adapter);
#endif
	e1000_init_manageability(adapter);

#ifdef ENABLE_DNA
	if (adapter->dna.dna_enabled)
	  init_dna(adapter);
#endif
	e1000_configure_tx(adapter);
	e1000_setup_rctl(adapter);
	e1000_configure_rx(adapter);
	/* call E1000_DESC_UNUSED which always leaves
	 * at least 1 descriptor unused to make sure
	 * next_to_use != next_to_clean */
	adapter->alloc_rx_buf(adapter, ring, E1000_DESC_UNUSED(ring));
}

int e1000_up(struct e1000_adapter *adapter)
{
	/* hardware has been reset, we need to reload some things */
	e1000_configure(adapter);

	clear_bit(__E1000_DOWN, &adapter->state);

#ifdef CONFIG_E1000_NAPI
	napi_enable(&adapter->rx_ring->napi);

#endif

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled)
	  e1000_irq_disable(adapter);
	else
#else
	e1000_irq_enable(adapter);
#endif

	/* fire a link change interrupt to start the watchdog */
	E1000_WRITE_REG(&adapter->hw, E1000_ICS, E1000_ICS_LSC);
	return 0;
}

void e1000_down(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	u32 tctl, rctl;

	/* disable receives in the hardware */
	rctl = E1000_READ_REG(&adapter->hw, E1000_RCTL);
	E1000_WRITE_REG(&adapter->hw, E1000_RCTL, rctl & ~E1000_RCTL_EN);
	/* flush and sleep below */

	netif_tx_disable(netdev);

	/* disable transmits in the hardware */
	tctl = E1000_READ_REG(&adapter->hw, E1000_TCTL);
	tctl &= ~E1000_TCTL_EN;
	E1000_WRITE_REG(&adapter->hw, E1000_TCTL, tctl);
	/* flush both disables and wait for them to finish */
	E1000_WRITE_FLUSH(&adapter->hw);
	msleep(10);

#ifdef CONFIG_E1000_NAPI
	napi_disable(&adapter->rx_ring->napi);

#endif
	e1000_irq_disable(adapter);

	/* signal that we're down so the interrupt handler does not
	 * reschedule our watchdog timer */
	set_bit(__E1000_DOWN, &adapter->state);

	del_timer_sync(&adapter->tx_fifo_stall_timer);
	del_timer_sync(&adapter->watchdog_timer);
	del_timer_sync(&adapter->phy_info_timer);

	netif_carrier_off(netdev);
	adapter->link_speed = 0;
	adapter->link_duplex = 0;

	e1000_reset(adapter);
	e1000_clean_all_tx_rings(adapter);
	e1000_clean_all_rx_rings(adapter);
}

static void e1000_reinit_safe(struct e1000_adapter *adapter)
{
	while (test_and_set_bit(__E1000_RESETTING, &adapter->state))
		msleep(1);
	rtnl_lock();
	e1000_down(adapter);
	e1000_up(adapter);
	rtnl_unlock();
	clear_bit(__E1000_RESETTING, &adapter->state);
}

void e1000_reinit_locked(struct e1000_adapter *adapter)
{
	/* if rtnl_lock is not held the call path is bogus */
	ASSERT_RTNL();
	WARN_ON(in_interrupt());
	while (test_and_set_bit(__E1000_RESETTING, &adapter->state))
		msleep(1);
	e1000_down(adapter);
	e1000_up(adapter);
	clear_bit(__E1000_RESETTING, &adapter->state);
}

void e1000_reset(struct e1000_adapter *adapter)
{
	struct e1000_mac_info *mac = &adapter->hw.mac;
	struct e1000_fc_info *fc = &adapter->hw.fc;
	u32 pba = 0, tx_space, min_tx_space, min_rx_space;
	bool legacy_pba_adjust = false;
	u16 hwm;

	/* Repartition Pba for greater than 9k mtu
	 * To take effect CTRL.RST is required.
	 */

	switch (mac->type) {
	case e1000_82542:
	case e1000_82543:
	case e1000_82544:
	case e1000_82540:
	case e1000_82541:
	case e1000_82541_rev_2:
		legacy_pba_adjust = true;
		pba = E1000_PBA_48K;
		break;
	case e1000_82545:
	case e1000_82545_rev_3:
	case e1000_82546:
	case e1000_82546_rev_3:
		pba = E1000_PBA_48K;
		break;
	case e1000_82547:
	case e1000_82547_rev_2:
		legacy_pba_adjust = true;
		pba = E1000_PBA_30K;
		break;
	case e1000_undefined:
	case e1000_num_macs:
		break;
	}

	if (legacy_pba_adjust == true) {
		if (adapter->max_frame_size > E1000_RXBUFFER_8192)
			pba -= 8; /* allocate more FIFO for Tx */

		if (mac->type == e1000_82547) {
			adapter->tx_fifo_head = 0;
			adapter->tx_head_addr = pba << E1000_TX_HEAD_ADDR_SHIFT;
			adapter->tx_fifo_size =
				(E1000_PBA_40K - pba) << E1000_PBA_BYTES_SHIFT;
			atomic_set(&adapter->tx_fifo_stall, 0);
		}
	} else if (adapter->max_frame_size > ETH_FRAME_LEN + ETH_FCS_LEN) {
		/* adjust PBA for jumbo frames */
		E1000_WRITE_REG(&adapter->hw, E1000_PBA, pba);

		/* To maintain wire speed transmits, the Tx FIFO should be
		 * large enough to accommodate two full transmit packets,
		 * rounded up to the next 1KB and expressed in KB.  Likewise,
		 * the Rx FIFO should be large enough to accommodate at least
		 * one full receive packet and is similarly rounded up and
		 * expressed in KB. */
		pba = E1000_READ_REG(&adapter->hw, E1000_PBA);
		/* upper 16 bits has Tx packet buffer allocation size in KB */
		tx_space = pba >> 16;
		/* lower 16 bits has Rx packet buffer allocation size in KB */
		pba &= 0xffff;
		/* the tx fifo also stores 16 bytes of information about the tx
		 * but don't include ethernet FCS because hardware appends it */
		min_tx_space = (adapter->max_frame_size +
		                sizeof(struct e1000_tx_desc) -
		                ETH_FCS_LEN) * 2;
		min_tx_space = ALIGN(min_tx_space, 1024);
		min_tx_space >>= 10;
		/* software strips receive CRC, so leave room for it */
		min_rx_space = adapter->max_frame_size;
		min_rx_space = ALIGN(min_rx_space, 1024);
		min_rx_space >>= 10;

		/* If current Tx allocation is less than the min Tx FIFO size,
		 * and the min Tx FIFO size is less than the current Rx FIFO
		 * allocation, take space away from current Rx allocation */
		if (tx_space < min_tx_space &&
		    ((min_tx_space - tx_space) < pba)) {
			pba = pba - (min_tx_space - tx_space);

			/* PCI/PCIx hardware has PBA alignment constraints */
			switch (mac->type) {
			case e1000_82545 ... e1000_82546_rev_3:
				pba &= ~(E1000_PBA_8K - 1);
				break;
			default:
				break;
			}

			/* if short on rx space, rx wins and must trump tx
			 * adjustment or use Early Receive if available */
			if (pba < min_rx_space) {
				pba = min_rx_space;
			}
		}
	}

	E1000_WRITE_REG(&adapter->hw, E1000_PBA, pba);

	/* flow control settings */
	/* The high water mark must be low enough to fit one full frame
	 * (or the size used for early receive) above it in the Rx FIFO.
	 * Set it to the lower of:
	 * - 90% of the Rx FIFO size, and
	 * - the full Rx FIFO size minus the early receive size (for parts
	 *   with ERT support assuming ERT set to E1000_ERT_2048), or
	 * - the full Rx FIFO size minus one full frame */
	hwm = min(((pba << 10) * 9 / 10),
		  ((pba << 10) - adapter->max_frame_size));

	fc->high_water = hwm & 0xFFF8;	/* 8-byte granularity */
	fc->low_water = fc->high_water - 8;

	fc->pause_time = E1000_FC_PAUSE_TIME;
	fc->send_xon = 1;
	fc->current_mode = fc->requested_mode;

	/* Allow time for pending master requests to run */
	e1000_reset_hw(&adapter->hw);

	if (mac->type >= e1000_82544)
		E1000_WRITE_REG(&adapter->hw, E1000_WUC, 0);

	if (e1000_init_hw(&adapter->hw))
		DPRINTK(PROBE, ERR, "Hardware Error\n");
#ifdef NETIF_F_HW_VLAN_TX
	e1000_update_mng_vlan(adapter);
#endif
	/* if (adapter->hwflags & HWFLAGS_PHY_PWR_BIT) { */
	if (mac->type >= e1000_82544 &&
	    mac->type <= e1000_82547_rev_2 &&
	    mac->autoneg == 1 &&
	    adapter->hw.phy.autoneg_advertised == ADVERTISE_1000_FULL) {
		u32 ctrl = E1000_READ_REG(&adapter->hw, E1000_CTRL);
		/* clear phy power management bit if we are in gig only mode,
		 * which if enabled will attempt negotiation to 100Mb, which
		 * can cause a loss of link at power off or driver unload */
		ctrl &= ~E1000_CTRL_SWDPIN3;
		E1000_WRITE_REG(&adapter->hw, E1000_CTRL, ctrl);
	}

	/* Enable h/w to recognize an 802.1Q VLAN Ethernet packet */
	E1000_WRITE_REG(&adapter->hw, E1000_VET, ETHERNET_IEEE_VLAN_TYPE);

	e1000_reset_adaptive(&adapter->hw);
	e1000_get_phy_info(&adapter->hw);

	e1000_release_manageability(adapter);
}

#ifdef HAVE_NET_DEVICE_OPS
static const struct net_device_ops e1000_netdev_ops = {
	.ndo_open		= e1000_open,
	.ndo_stop		= e1000_close,
	.ndo_start_xmit		= e1000_xmit_frame,
	.ndo_get_stats		= e1000_get_stats,
	.ndo_set_multicast_list	= e1000_set_multi,
	.ndo_set_mac_address	= e1000_set_mac,
	.ndo_change_mtu		= e1000_change_mtu,
	.ndo_do_ioctl		= e1000_ioctl,
	.ndo_tx_timeout		= e1000_tx_timeout,
	.ndo_validate_addr	= eth_validate_addr,

	.ndo_vlan_rx_register	= e1000_vlan_rx_register,
	.ndo_vlan_rx_add_vid	= e1000_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= e1000_vlan_rx_kill_vid,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= e1000_netpoll,
#endif
};

#endif /* HAVE_NET_DEVICE_OPS */
/**
 * e1000_probe - Device Initialization Routine
 * @pdev: PCI device information struct
 * @ent: entry in e1000_pci_tbl
 *
 * Returns 0 on success, negative on failure
 *
 * e1000_probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 **/
static int __devinit e1000_probe(struct pci_dev *pdev,
                                 const struct pci_device_id *ent)
{
	struct net_device *netdev;
	struct e1000_adapter *adapter;

	static int cards_found = 0;
	static int global_quad_port_a = 0; /* global ksp3 port a indication */
	int i, err, pci_using_dac;
	u16 eeprom_data = 0;
	u16 eeprom_apme_mask = E1000_EEPROM_APME;
	if ((err = pci_enable_device(pdev)))
		return err;

	if (!ignore_64bit_dma &&
	    !(err = dma_set_mask(pci_dev_to_dev(pdev), DMA_BIT_MASK(64))) &&
	    !(err = dma_set_coherent_mask(pci_dev_to_dev(pdev),
					  DMA_BIT_MASK(64)))) {
		pci_using_dac = 1;
	} else {
		if ((err = dma_set_mask(pci_dev_to_dev(pdev), DMA_BIT_MASK(32))) &&
		    (err = dma_set_coherent_mask(pci_dev_to_dev(pdev),
						 DMA_BIT_MASK(32)))) {
			E1000_ERR("No usable DMA configuration, aborting\n");
			goto err_dma;
		}
		pci_using_dac = 0;
	}

	if ((err = pci_request_regions(pdev, e1000_driver_name)))
		goto err_pci_reg;

	pci_set_master(pdev);

	err = -ENOMEM;
	netdev = alloc_etherdev(sizeof(struct e1000_adapter));
	if (!netdev)
		goto err_alloc_etherdev;

	SET_MODULE_OWNER(netdev);
	SET_NETDEV_DEV(netdev, &pdev->dev);

	pci_set_drvdata(pdev, netdev);
#ifdef HAVE_PCI_ERS
	err = pci_save_state(pdev);
	if (err)
		goto err_ioremap;

#endif /* HAVE_PCI_ERS */
	adapter = netdev_priv(netdev);
	adapter->netdev = netdev;
	adapter->pdev = pdev;
	adapter->hw.back = adapter;
	adapter->msg_enable = (1 << debug) - 1;

	err = -EIO;
	adapter->hw.hw_addr = ioremap(pci_resource_start(pdev, BAR_0),
	                              pci_resource_len(pdev, BAR_0));
	if (!adapter->hw.hw_addr)
		goto err_ioremap;

	for (i = BAR_1; i <= BAR_5; i++) {
		if (pci_resource_len(pdev, i) == 0)
			continue;
		if (pci_resource_flags(pdev, i) & IORESOURCE_IO) {
			adapter->hw.io_base = pci_resource_start(pdev, i);
			break;
		}
	}

#ifdef HAVE_NET_DEVICE_OPS
	netdev->netdev_ops = &e1000_netdev_ops;
#else
	netdev->open = &e1000_open;
	netdev->stop = &e1000_close;
	netdev->hard_start_xmit = &e1000_xmit_frame;
	netdev->get_stats = &e1000_get_stats;
	netdev->set_multicast_list = &e1000_set_multi;
	netdev->set_mac_address = &e1000_set_mac;
	netdev->change_mtu = &e1000_change_mtu;
	netdev->do_ioctl = &e1000_ioctl;
#ifdef HAVE_TX_TIMEOUT
	netdev->tx_timeout = &e1000_tx_timeout;
#endif
#ifdef NETIF_F_HW_VLAN_TX
	netdev->vlan_rx_register = e1000_vlan_rx_register;
	netdev->vlan_rx_add_vid = e1000_vlan_rx_add_vid;
	netdev->vlan_rx_kill_vid = e1000_vlan_rx_kill_vid;
#endif
#ifdef CONFIG_NET_POLL_CONTROLLER
	netdev->poll_controller = e1000_netpoll;
#endif
#endif /* HAVE_NET_DEVICE_OPS */
	e1000_set_ethtool_ops(netdev);
	netdev->watchdog_timeo = 5 * HZ;

	strncpy(netdev->name, pci_name(pdev), sizeof(netdev->name) - 1);

	adapter->bd_number = cards_found;

	/* setup the private structure */
	if ((err = e1000_sw_init(adapter)))
		goto err_sw_init;

	err = -EIO;
	if ((err = e1000_init_mac_params(&adapter->hw)))
		goto err_hw_init;

	if ((err = e1000_init_nvm_params(&adapter->hw)))
		goto err_hw_init;

	if ((err = e1000_init_phy_params(&adapter->hw)))
		goto err_hw_init;

	e1000_get_bus_info(&adapter->hw);

	e1000_init_script_state_82541(&adapter->hw, true);
	e1000_set_tbi_compatibility_82543(&adapter->hw, true);

	adapter->hw.phy.autoneg_wait_to_complete = false;
	adapter->hw.mac.adaptive_ifs = true;

	/* Copper options */

	if (adapter->hw.phy.media_type == e1000_media_type_copper) {
		adapter->hw.phy.mdix = AUTO_ALL_MODES;
		adapter->hw.phy.disable_polarity_correction = false;
		adapter->hw.phy.ms_type = E1000_MASTER_SLAVE;
	}

	if (e1000_check_reset_block(&adapter->hw))
		DPRINTK(PROBE, INFO, "PHY reset is blocked due to SOL/IDER session.\n");

#ifdef MAX_SKB_FRAGS
	if (adapter->hw.mac.type >= e1000_82543) {
#ifdef NETIF_F_HW_VLAN_TX
		netdev->features = NETIF_F_SG |
				   NETIF_F_HW_CSUM |
				   NETIF_F_HW_VLAN_TX |
				   NETIF_F_HW_VLAN_RX |
				   NETIF_F_HW_VLAN_FILTER;
#else
		netdev->features = NETIF_F_SG | NETIF_F_HW_CSUM;
#endif
	}

#ifdef NETIF_F_TSO
	if ((adapter->hw.mac.type >= e1000_82544) &&
	   (adapter->hw.mac.type != e1000_82547)) {
		adapter->flags |= E1000_FLAG_HAS_TSO;
		netdev->features |= NETIF_F_TSO;
	}

#endif

#ifdef HAVE_NETDEV_VLAN_FEATURES
	if (adapter->hw.mac.type >= e1000_82543) {
		netdev->vlan_features |= NETIF_F_SG;
		netdev->vlan_features |= NETIF_F_HW_CSUM;
	}

#ifdef NETIF_F_TSO
	if ((adapter->hw.mac.type >= e1000_82544) &&
	   (adapter->hw.mac.type != e1000_82547)) {
		netdev->vlan_features |= NETIF_F_TSO;
	}

#endif /* NETIF_F_TSO */
#endif /* HAVE_NETDEV_VLAN_FEATURES */

	if (pci_using_dac) {
		netdev->features |= NETIF_F_HIGHDMA;
#ifdef HAVE_NETDEV_VLAN_FEATURES
		netdev->vlan_features |= NETIF_F_HIGHDMA;
#endif
	}
#endif

	/* Hardware features, flags and workarounds */
	if (adapter->hw.mac.type >= e1000_82540) {
		adapter->flags |= E1000_FLAG_HAS_SMBUS;
		adapter->flags |= E1000_FLAG_HAS_INTR_MODERATION;
	}

	if (adapter->hw.mac.type == e1000_82543)
		adapter->flags |= E1000_FLAG_BAD_TX_CARRIER_STATS_FD;

	adapter->en_mng_pt = e1000_enable_mng_pass_thru(&adapter->hw);

	/* before reading the NVM, reset the controller to
	 * put the device in a known good starting state */

	e1000_reset_hw(&adapter->hw);

	/* make sure we don't intercept ARP packets until we're up */
	e1000_release_manageability(adapter);

	/* make sure the NVM is good */

	if (e1000_validate_nvm_checksum(&adapter->hw) < 0) {
		DPRINTK(PROBE, ERR, "The NVM Checksum Is Not Valid\n");
		err = -EIO;
		goto err_eeprom;
	}

	/* copy the MAC address out of the NVM */

	if (e1000_read_mac_addr(&adapter->hw))
		DPRINTK(PROBE, ERR, "NVM Read Error\n");
	memcpy(netdev->dev_addr, adapter->hw.mac.addr, netdev->addr_len);
#ifdef ETHTOOL_GPERMADDR
	memcpy(netdev->perm_addr, adapter->hw.mac.addr, netdev->addr_len);

	if (!is_valid_ether_addr(netdev->perm_addr)) {
#else
	if (!is_valid_ether_addr(netdev->dev_addr)) {
#endif
		DPRINTK(PROBE, ERR, "Invalid MAC Address\n");
		err = -EIO;
		goto err_eeprom;
	}

	init_timer(&adapter->tx_fifo_stall_timer);
	adapter->tx_fifo_stall_timer.function = &e1000_82547_tx_fifo_stall;
	adapter->tx_fifo_stall_timer.data = (unsigned long) adapter;

	init_timer(&adapter->watchdog_timer);
	adapter->watchdog_timer.function = &e1000_watchdog;
	adapter->watchdog_timer.data = (unsigned long) adapter;

	init_timer(&adapter->phy_info_timer);
	adapter->phy_info_timer.function = &e1000_update_phy_info;
	adapter->phy_info_timer.data = (unsigned long) adapter;

	INIT_WORK(&adapter->fifo_stall_task, e1000_82547_tx_fifo_stall_task);
	INIT_WORK(&adapter->reset_task, e1000_reset_task);
	INIT_WORK(&adapter->phy_info_task, e1000_update_phy_info_task);
	INIT_WORK(&adapter->watchdog_task, e1000_watchdog_task);

	e1000_check_options(adapter);

	/* Initial Wake on LAN setting
	 * If APM wake is enabled in the EEPROM,
	 * enable the ACPI Magic Packet filter
	 */

	switch (adapter->hw.mac.type) {
	case e1000_82542:
	case e1000_82543:
		break;
	case e1000_82544:
		e1000_read_nvm(&adapter->hw,
			NVM_INIT_CONTROL2_REG, 1, &eeprom_data);
		eeprom_apme_mask = E1000_EEPROM_82544_APM;
		break;
	case e1000_82546:
	case e1000_82546_rev_3:
		if (adapter->hw.bus.func == 1) {
			e1000_read_nvm(&adapter->hw,
				NVM_INIT_CONTROL3_PORT_B, 1, &eeprom_data);
			break;
		}
		/* Fall Through */
	default:
		e1000_read_nvm(&adapter->hw,
			NVM_INIT_CONTROL3_PORT_A, 1, &eeprom_data);
		break;
	}
	if (eeprom_data & eeprom_apme_mask)
		adapter->eeprom_wol |= E1000_WUFC_MAG;

	/* now that we have the eeprom settings, apply the special cases
	 * where the eeprom may be wrong or the board simply won't support
	 * wake on lan on a particular port */
	switch (pdev->device) {
	case E1000_DEV_ID_82546GB_PCIE:
		adapter->eeprom_wol = 0;
		break;
	case E1000_DEV_ID_82546EB_FIBER:
	case E1000_DEV_ID_82546GB_FIBER:
		/* Wake events only supported on port A for dual fiber
		 * regardless of eeprom setting */
		if (E1000_READ_REG(&adapter->hw, E1000_STATUS) &
		    E1000_STATUS_FUNC_1)
			adapter->eeprom_wol = 0;
		break;
	case E1000_DEV_ID_82546GB_QUAD_COPPER_KSP3:
		/* if quad port adapter, disable WoL on all but port A */
		if (global_quad_port_a != 0)
			adapter->eeprom_wol = 0;
		else
			adapter->flags |= E1000_FLAG_QUAD_PORT_A;
		/* Reset for multiple quad port adapters */
		if (++global_quad_port_a == 4)
			global_quad_port_a = 0;
		break;
	}

	/* initialize the wol settings based on the eeprom settings */
	adapter->wol = adapter->eeprom_wol;
	device_set_wakeup_enable(pci_dev_to_dev(adapter->pdev), adapter->wol);

	/* print bus type/speed/width info */
	{
	struct e1000_hw *hw = &adapter->hw;
	DPRINTK(PROBE, INFO, "(PCI%s:%s:%s) ",
		((hw->bus.type == e1000_bus_type_pcix) ? "-X" :
		 (hw->bus.type == e1000_bus_type_pci_express ? " Express":"")),
		((hw->bus.speed == e1000_bus_speed_2500) ? "2.5Gb/s" :
		 (hw->bus.speed == e1000_bus_speed_133) ? "133MHz" :
		 (hw->bus.speed == e1000_bus_speed_120) ? "120MHz" :
		 (hw->bus.speed == e1000_bus_speed_100) ? "100MHz" :
		 (hw->bus.speed == e1000_bus_speed_66) ? "66MHz" : "33MHz"),
		((hw->bus.width == e1000_bus_width_64) ? "64-bit" :
		 (hw->bus.width == e1000_bus_width_pcie_x4) ? "Width x4" :
		 (hw->bus.width == e1000_bus_width_pcie_x1) ? "Width x1" :
		 "32-bit"));
	}

	for (i = 0; i < 6; i++)
		printk("%2.2x%c", netdev->dev_addr[i], i == 5 ? '\n' : ':');

#ifdef ENABLE_DNA
	memset(&adapter->dna, 0, sizeof(adapter->dna));
	dna_check_enable_adapter(adapter);
#endif

	/* reset the hardware with the new settings */
	e1000_reset(adapter);

	/* tell the stack to leave us alone until e1000_open() is called */
	netif_carrier_off(netdev);
	netif_stop_queue(netdev);

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled)
	  strncpy(netdev->name, "dna%d", sizeof(netdev->name) - 1);
	else
#endif
	strcpy(netdev->name, "eth%d");
	err = register_netdev(netdev);
	if (err)
		goto err_register;

	DPRINTK(PROBE, INFO, "Intel(R) PRO/1000 Network Connection\n");

	cards_found++;
	return 0;

err_register:
err_hw_init:
err_eeprom:
	if (!e1000_check_reset_block(&adapter->hw))
		e1000_phy_hw_reset(&adapter->hw);

	if (adapter->hw.flash_address)
		iounmap(adapter->hw.flash_address);

	kfree(adapter->tx_ring);
	kfree(adapter->rx_ring);
err_sw_init:
	iounmap(adapter->hw.hw_addr);
err_ioremap:
	free_netdev(netdev);
err_alloc_etherdev:
	pci_release_regions(pdev);
err_pci_reg:
err_dma:
	pci_disable_device(pdev);
	return err;
}

/**
 * e1000_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * e1000_remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 **/
static void __devexit e1000_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);

	/* flush_scheduled work may reschedule our watchdog task, so
	 * explicitly disable watchdog tasks from being rescheduled  */
	set_bit(__E1000_DOWN, &adapter->state);
	del_timer_sync(&adapter->tx_fifo_stall_timer);
	del_timer_sync(&adapter->watchdog_timer);
	del_timer_sync(&adapter->phy_info_timer);

	cancel_work_sync(&adapter->phy_info_task);
	cancel_work_sync(&adapter->fifo_stall_task);
	cancel_work_sync(&adapter->watchdog_task);
	cancel_work_sync(&adapter->reset_task);

	e1000_release_manageability(adapter);

	unregister_netdev(netdev);

	if (!e1000_check_reset_block(&adapter->hw))
		e1000_phy_hw_reset(&adapter->hw);

#ifdef CONFIG_E1000_NAPI
	netif_napi_del(&adapter->rx_ring->napi);
#endif
	kfree(adapter->tx_ring);
	kfree(adapter->rx_ring);

	iounmap(adapter->hw.hw_addr);
	if (adapter->hw.flash_address)
		iounmap(adapter->hw.flash_address);
	pci_release_regions(pdev);

	free_netdev(netdev);

	pci_disable_device(pdev);
}

/**
 * e1000_sw_init - Initialize general software structures (struct e1000_adapter)
 * @adapter: board private structure to initialize
 *
 * e1000_sw_init initializes the Adapter private data structure.
 * Fields are initialized based on PCI device information and
 * OS network device settings (MTU size).
 **/
static int __devinit e1000_sw_init(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;

	/* PCI config space info */

	hw->vendor_id = pdev->vendor;
	hw->device_id = pdev->device;
	hw->subsystem_vendor_id = pdev->subsystem_vendor;
	hw->subsystem_device_id = pdev->subsystem_device;

	pci_read_config_byte(pdev, PCI_REVISION_ID, &hw->revision_id);

	pci_read_config_word(pdev, PCI_COMMAND, &hw->bus.pci_cmd_word);

	adapter->rx_buffer_len = MAXIMUM_ETHERNET_VLAN_SIZE;
	adapter->max_frame_size = netdev->mtu + ETH_HLEN + ETH_FCS_LEN;
	adapter->min_frame_size = ETH_ZLEN + ETH_FCS_LEN;

	hw->fc.requested_mode = e1000_fc_default;

	/* Initialize the hardware-specific values */
	if (e1000_setup_init_funcs(hw, false)) {
		DPRINTK(PROBE, ERR, "Hardware Initialization Failure\n");
		return -EIO;
	}

	if (e1000_alloc_rings(adapter)) {
		DPRINTK(PROBE, ERR, "Unable to allocate memory for queues\n");
		return -ENOMEM;
	}

#ifdef CONFIG_E1000_NAPI
	netif_napi_add(adapter->netdev, &adapter->rx_ring->napi, e1000_poll, 64);

#endif
	/* Explicitly disable IRQ since the NIC can be in any state. */
	e1000_irq_disable(adapter);

	spin_lock_init(&adapter->stats_lock);

	set_bit(__E1000_DOWN, &adapter->state);
	return 0;
}

/**
 * e1000_alloc_rings - Allocate memory for all rings
 * @adapter: board private structure to initialize
 **/
static int __devinit e1000_alloc_rings(struct e1000_adapter *adapter)
{
	adapter->tx_ring = kzalloc(sizeof(struct e1000_tx_ring), GFP_KERNEL);
	if (!adapter->tx_ring)
		return -ENOMEM;

	adapter->rx_ring = kzalloc(sizeof(struct e1000_rx_ring), GFP_KERNEL);
	if (!adapter->rx_ring) {
		kfree(adapter->tx_ring);
		return -ENOMEM;
	}

	return E1000_SUCCESS;
}


/**
 * e1000_open - Called when a network interface is made active
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
static int e1000_open(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	int err;
	/* disallow open during test */
	if (test_bit(__E1000_TESTING, &adapter->state))
		return -EBUSY;

	/* allocate transmit descriptors */
	err = e1000_setup_all_tx_resources(adapter);
	if (err)
		goto err_setup_tx;

	/* allocate receive descriptors */
	err = e1000_setup_all_rx_resources(adapter);
	if (err)
		goto err_setup_rx;

	if (adapter->hw.phy.media_type == e1000_media_type_copper)
		e1000_power_up_phy(&adapter->hw);

#ifdef NETIF_F_HW_VLAN_TX
	adapter->mng_vlan_id = E1000_MNG_VLAN_NONE;
	if ((adapter->hw.mng_cookie.status &
	     E1000_MNG_DHCP_COOKIE_STATUS_VLAN)) {
		e1000_update_mng_vlan(adapter);
	}
#endif

	/* before we allocate an interrupt, we must be ready to handle it.
	 * Setting DEBUG_SHIRQ in the kernel makes it fire an interrupt
	 * as soon as we call pci_request_irq, so we have to setup our
	 * clean_rx handler before we do so.  */
	e1000_configure(adapter);


	err = e1000_request_irq(adapter);
	if (err)
		goto err_req_irq;

	/* From here on the code is the same as e1000_up() */
	clear_bit(__E1000_DOWN, &adapter->state);

#ifdef CONFIG_E1000_NAPI
	napi_enable(&adapter->rx_ring->napi);

#endif
	e1000_irq_enable(adapter);

	/* fire a link status change interrupt to start the watchdog */
	E1000_WRITE_REG(&adapter->hw, E1000_ICS, E1000_ICS_LSC);

	return E1000_SUCCESS;

err_req_irq:
	/* Power down the PHY so no link is implied when interface is down *
	 * The PHY cannot be powered down if any of the following is true *
	 * (a) WoL is enabled
	 * (b) AMT is active
	 * (c) SoL/IDER session is active */
	if (!adapter->wol && adapter->hw.mac.type >= e1000_82540 &&
	   adapter->hw.phy.media_type == e1000_media_type_copper)
		e1000_power_down_phy(&adapter->hw);
	e1000_free_all_rx_resources(adapter);
err_setup_rx:
	e1000_free_all_tx_resources(adapter);
err_setup_tx:
	e1000_reset(adapter);

	return err;
}

/**
 * e1000_close - Disables a network interface
 * @netdev: network interface device structure
 *
 * Returns 0, this is not allowed to fail
 *
 * The close entry point is called when an interface is de-activated
 * by the OS.  The hardware is still under the drivers control, but
 * needs to be disabled.  A global MAC reset is issued to stop the
 * hardware, and all transmit and receive resources are freed.
 **/
static int e1000_close(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	WARN_ON(test_bit(__E1000_RESETTING, &adapter->state));
	e1000_down(adapter);
	/* Power down the PHY so no link is implied when interface is down *
	 * The PHY cannot be powered down if any of the following is true *
	 * (a) WoL is enabled
	 * (b) AMT is active
	 * (c) SoL/IDER session is active */
	if (!adapter->wol && adapter->hw.mac.type >= e1000_82540 &&
	   adapter->hw.phy.media_type == e1000_media_type_copper)
		e1000_power_down_phy(&adapter->hw);
	e1000_free_irq(adapter);

	e1000_free_all_tx_resources(adapter);
	e1000_free_all_rx_resources(adapter);

#ifdef NETIF_F_HW_VLAN_TX
	/* kill manageability vlan ID if supported, but not if a vlan with
	 * the same ID is registered on the host OS (let 8021q kill it) */
	if ((adapter->hw.mng_cookie.status &
			  E1000_MNG_DHCP_COOKIE_STATUS_VLAN) &&
	     !(adapter->vlgrp &&
	       vlan_group_get_device(adapter->vlgrp, adapter->mng_vlan_id))) {
		e1000_vlan_rx_kill_vid(netdev, adapter->mng_vlan_id);
	}
#endif

	return 0;
}

/**
 * e1000_check_64k_bound - check that memory doesn't cross 64kB boundary
 * @adapter: address of board private structure
 * @start: address of beginning of memory
 * @len: length of memory
 **/
static bool e1000_check_64k_bound(struct e1000_adapter *adapter,
                                       void *start, unsigned long len)
{
	unsigned long begin = (unsigned long) start;
	unsigned long end = begin + len;

	/* First rev 82545 and 82546 need to not allow any memory
	 * write location to cross 64k boundary due to errata 23 */
	if (adapter->hw.mac.type == e1000_82545 ||
	    adapter->hw.mac.type == e1000_82546) {
		return ((begin ^ (end - 1)) >> 16) != 0 ? false : true;
	}

	return true;
}

/**
 * e1000_setup_tx_resources - allocate Tx resources (Descriptors)
 * @adapter: board private structure
 * @tx_ring:    tx descriptor ring (for a specific queue) to setup
 *
 * Return 0 on success, negative on failure
 **/
static int e1000_setup_tx_resources(struct e1000_adapter *adapter,
                                    struct e1000_tx_ring *tx_ring)
{
	struct pci_dev *pdev = adapter->pdev;
	int size;

	size = sizeof(struct e1000_buffer) * tx_ring->count;
	tx_ring->buffer_info = vmalloc(size);
	if (!tx_ring->buffer_info) {
		DPRINTK(PROBE, ERR,
		"Unable to allocate memory for the transmit descriptor ring\n");
		return -ENOMEM;
	}
	memset(tx_ring->buffer_info, 0, size);

	/* round up to nearest 4K */

	tx_ring->size = tx_ring->count * sizeof(struct e1000_tx_desc);
	tx_ring->size = ALIGN(tx_ring->size, 4096);

	tx_ring->desc = dma_alloc_coherent(pci_dev_to_dev(pdev), 
#ifdef ENABLE_DNA
					   (adapter->dna.dna_enabled ? 2 /* shadow descriptors */ : 1) * 
#endif
					   tx_ring->size,
	                                   &tx_ring->dma, GFP_KERNEL);
	if (!tx_ring->desc) {
setup_tx_desc_die:
		vfree(tx_ring->buffer_info);
		DPRINTK(PROBE, ERR,
		"Unable to allocate memory for the transmit descriptor ring\n");
		return -ENOMEM;
	}

	/* Fix for errata 23, can't cross 64kB boundary */
	if (!e1000_check_64k_bound(adapter, tx_ring->desc, tx_ring->size)) {
		void *olddesc = tx_ring->desc;
		dma_addr_t olddma = tx_ring->dma;
		DPRINTK(TX_ERR, ERR, "tx_ring align check failed: %u bytes "
				     "at %p\n", tx_ring->size, tx_ring->desc);
		/* Try again, without freeing the previous */
		tx_ring->desc = dma_alloc_coherent(pci_dev_to_dev(pdev),
						   tx_ring->size,
		                                   &tx_ring->dma, GFP_KERNEL);
		/* Failed allocation, critical failure */
		if (!tx_ring->desc) {
			dma_free_coherent(pci_dev_to_dev(pdev), tx_ring->size,
					  olddesc, olddma);
			goto setup_tx_desc_die;
		}

		if (!e1000_check_64k_bound(adapter, tx_ring->desc,
		                           tx_ring->size)) {
			/* give up */
			dma_free_coherent(pci_dev_to_dev(pdev), tx_ring->size,
					  tx_ring->desc, tx_ring->dma);
			dma_free_coherent(pci_dev_to_dev(pdev), tx_ring->size,
					  olddesc, olddma);
			DPRINTK(PROBE, ERR,
				"Unable to allocate aligned memory "
				"for the transmit descriptor ring\n");
			vfree(tx_ring->buffer_info);
			return -ENOMEM;
		} else {
			/* Free old allocation, new allocation was successful */
			dma_free_coherent(pci_dev_to_dev(pdev), tx_ring->size,
					  olddesc, olddma);
		}
	}
	memset(tx_ring->desc, 0, tx_ring->size);

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	return 0;
}

/**
 * e1000_setup_all_tx_resources - wrapper to allocate Tx resources
 * @adapter: board private structure
 *
 * this allocates tx resources, return 0 on success, negative
 * on failure
 **/
int e1000_setup_all_tx_resources(struct e1000_adapter *adapter)
{
	int err = 0;

	err = e1000_setup_tx_resources(adapter, adapter->tx_ring);
	if (err)
		DPRINTK(PROBE, ERR, "Allocation for Tx Queue failed\n");

	return err;
}

/**
 * e1000_configure_tx - Configure 8254x Transmit Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Tx unit of the MAC after a reset.
 **/
static void e1000_configure_tx(struct e1000_adapter *adapter)
{
	u64 tdba;
	struct e1000_hw *hw = &adapter->hw;
	u32 tdlen, tctl, tipg;
	u32 ipgr1, ipgr2;

	/* Setup the HW Tx Head and Tail descriptor pointers */
	tdba = adapter->tx_ring->dma;
	tdlen = adapter->tx_ring->count * sizeof(struct e1000_tx_desc);
	E1000_WRITE_REG(hw, E1000_TDBAL(0), (tdba & 0x00000000ffffffffULL));
	E1000_WRITE_REG(hw, E1000_TDBAH(0), (tdba >> 32));
	E1000_WRITE_REG(hw, E1000_TDLEN(0), tdlen);
	E1000_WRITE_REG(hw, E1000_TDH(0), 0);
	E1000_WRITE_REG(hw, E1000_TDT(0), 0);
	adapter->tx_ring->tdh = E1000_REGISTER(hw, E1000_TDH(0));
	adapter->tx_ring->tdt = E1000_REGISTER(hw, E1000_TDT(0));


	/* Set the default values for the Tx Inter Packet Gap timer */
	if (adapter->hw.mac.type <= e1000_82547_rev_2 &&
	    (hw->phy.media_type == e1000_media_type_fiber ||
	     hw->phy.media_type == e1000_media_type_internal_serdes))
		tipg = DEFAULT_82543_TIPG_IPGT_FIBER;
	else
		tipg = DEFAULT_82543_TIPG_IPGT_COPPER;

	switch (hw->mac.type) {
	case e1000_82542:
		tipg = DEFAULT_82542_TIPG_IPGT;
		ipgr1 = DEFAULT_82542_TIPG_IPGR1;
		ipgr2 = DEFAULT_82542_TIPG_IPGR2;
		break;
	default:
		ipgr1 = DEFAULT_82543_TIPG_IPGR1;
		ipgr2 = DEFAULT_82543_TIPG_IPGR2;
		break;
	}
	tipg |= ipgr1 << E1000_TIPG_IPGR1_SHIFT;
	tipg |= ipgr2 << E1000_TIPG_IPGR2_SHIFT;
	E1000_WRITE_REG(hw, E1000_TIPG, tipg);

	/* Set the Tx Interrupt Delay register */

	E1000_WRITE_REG(hw, E1000_TIDV, adapter->tx_int_delay);
	if (adapter->flags & E1000_FLAG_HAS_INTR_MODERATION)
		E1000_WRITE_REG(hw, E1000_TADV, adapter->tx_abs_int_delay);

	/* Program the Transmit Control Register */

	tctl = E1000_READ_REG(hw, E1000_TCTL);
	tctl &= ~E1000_TCTL_CT;
	tctl |= E1000_TCTL_PSP | E1000_TCTL_RTLC |
		(E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT);

	e1000_config_collision_dist(hw);

	/* Setup Transmit Descriptor Settings for eop descriptor */
	adapter->txd_cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS;

	/* only set IDE if we are delaying interrupts using the timers */
	if (adapter->tx_int_delay)
		adapter->txd_cmd |= E1000_TXD_CMD_IDE;

	if (hw->mac.type < e1000_82543)
		adapter->txd_cmd |= E1000_TXD_CMD_RPS;
	else
		adapter->txd_cmd |= E1000_TXD_CMD_RS;

	/* Cache if we're 82544 running in PCI-X because we'll
	 * need this to apply a workaround later in the send path. */
	if (hw->mac.type == e1000_82544 &&
	    hw->bus.type == e1000_bus_type_pcix)
		adapter->pcix_82544 = 1;

	E1000_WRITE_REG(hw, E1000_TCTL, tctl);

}

/**
 * e1000_setup_rx_resources - allocate Rx resources (Descriptors)
 * @adapter: board private structure
 * @rx_ring:    rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 **/
static int e1000_setup_rx_resources(struct e1000_adapter *adapter,
                                    struct e1000_rx_ring *rx_ring)
{
	struct pci_dev *pdev = adapter->pdev;
	int size, desc_len;

	size = sizeof(struct e1000_rx_buffer) * rx_ring->count;
	rx_ring->buffer_info = vmalloc(size);
	if (!rx_ring->buffer_info) {
		DPRINTK(PROBE, ERR,
		"Unable to allocate memory for the receive descriptor ring\n");
		return -ENOMEM;
	}
	memset(rx_ring->buffer_info, 0, size);

	desc_len = sizeof(struct e1000_rx_desc);

	/* Round up to nearest 4K */

	rx_ring->size = rx_ring->count * desc_len;
	rx_ring->size = ALIGN(rx_ring->size, 4096);

	rx_ring->desc = dma_alloc_coherent(pci_dev_to_dev(pdev), 
#ifdef ENABLE_DNA
					   (adapter->dna.dna_enabled ? 2 /* shadow descriptors */ : 1) * 
#endif
					   rx_ring->size,
	                                   &rx_ring->dma, GFP_KERNEL);

	if (!rx_ring->desc) {
		DPRINTK(PROBE, ERR,
		"Unable to allocate memory for the receive descriptor ring\n");
setup_rx_desc_die:
		vfree(rx_ring->buffer_info);
		return -ENOMEM;
	}

	/* Fix for errata 23, can't cross 64kB boundary */
	if (!e1000_check_64k_bound(adapter, rx_ring->desc, rx_ring->size)) {
		void *olddesc = rx_ring->desc;
		dma_addr_t olddma = rx_ring->dma;
		DPRINTK(RX_ERR, ERR, "rx_ring align check failed: %u bytes "
				     "at %p\n", rx_ring->size, rx_ring->desc);
		/* Try again, without freeing the previous */
		rx_ring->desc = dma_alloc_coherent(pci_dev_to_dev(pdev),
						   rx_ring->size,
		                    		   &rx_ring->dma, GFP_KERNEL);
		/* Failed allocation, critical failure */
		if (!rx_ring->desc) {
			dma_free_coherent(pci_dev_to_dev(pdev), rx_ring->size, olddesc,
			                    olddma);
			DPRINTK(PROBE, ERR,
				"Unable to allocate memory "
				"for the receive descriptor ring\n");
			goto setup_rx_desc_die;
		}

		if (!e1000_check_64k_bound(adapter, rx_ring->desc,
		                           rx_ring->size)) {
			/* give up */
			dma_free_coherent(pci_dev_to_dev(pdev), rx_ring->size,
					  rx_ring->desc, rx_ring->dma);
			dma_free_coherent(pci_dev_to_dev(pdev), rx_ring->size,
					  olddesc, olddma);
			DPRINTK(PROBE, ERR,
				"Unable to allocate aligned memory "
				"for the receive descriptor ring\n");
			goto setup_rx_desc_die;
		} else {
			/* Free old allocation, new allocation was successful */
			dma_free_coherent(pci_dev_to_dev(pdev), rx_ring->size,
					  olddesc, olddma);
		}
	}
	memset(rx_ring->desc, 0, rx_ring->size);

	/* set up ring defaults */
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
	rx_ring->rx_skb_top = NULL;
	rx_ring->adapter = adapter;

	return 0;
}

/**
 * e1000_setup_all_rx_resources - wrapper to allocate Rx resources
 * @adapter: board private structure
 *
 * this allocates rx resources, return 0 on success, negative on failure
 **/
int e1000_setup_all_rx_resources(struct e1000_adapter *adapter)
{
	int err = 0;

	err = e1000_setup_rx_resources(adapter, adapter->rx_ring);
	if (err)
		DPRINTK(PROBE, ERR, "Allocation for Rx Queue failed\n");

	return err;
}

#define PAGE_USE_COUNT(S) (((S) >> PAGE_SHIFT) + \
			(((S) & (PAGE_SIZE - 1)) ? 1 : 0))
/**
 * e1000_setup_rctl - configure the receive control registers
 * @adapter: Board private structure
 **/
static void e1000_setup_rctl(struct e1000_adapter *adapter)
{
	u32 rctl;

	rctl = E1000_READ_REG(&adapter->hw, E1000_RCTL);

	rctl &= ~(3 << E1000_RCTL_MO_SHIFT);

	rctl |= E1000_RCTL_EN | E1000_RCTL_BAM |
		E1000_RCTL_LBM_NO | E1000_RCTL_RDMTS_HALF |
		(adapter->hw.mac.mc_filter_type << E1000_RCTL_MO_SHIFT);

	/* disable the stripping of CRC because it breaks
	 * BMC firmware connected over SMBUS
	if (adapter->hw.mac.type > e1000_82543)
		rctl |= E1000_RCTL_SECRC;
	*/

	if (e1000_tbi_sbp_enabled_82543(&adapter->hw))
		rctl |= E1000_RCTL_SBP;
	else
		rctl &= ~E1000_RCTL_SBP;

	if (adapter->netdev->mtu <= ETH_DATA_LEN)
		rctl &= ~E1000_RCTL_LPE;
	else
		rctl |= E1000_RCTL_LPE;

	/* Setup buffer sizes */
	rctl &= ~E1000_RCTL_SZ_4096;
	rctl |= E1000_RCTL_BSEX;
	switch (adapter->rx_buffer_len) {
		case E1000_RXBUFFER_2048:
		default:
			rctl |= E1000_RCTL_SZ_2048;
			rctl &= ~E1000_RCTL_BSEX;
			break;
		case E1000_RXBUFFER_4096:
			rctl |= E1000_RCTL_SZ_4096;
			break;
		case E1000_RXBUFFER_8192:
			rctl |= E1000_RCTL_SZ_8192;
			break;
		case E1000_RXBUFFER_16384:
			rctl |= E1000_RCTL_SZ_16384;
			break;
	}

	E1000_WRITE_REG(&adapter->hw, E1000_RCTL, rctl);
}

/**
 * e1000_configure_rx - Configure 8254x Receive Unit after Reset
 * @adapter: board private structure
 *
 * Configure the Rx unit of the MAC after a reset.
 **/
static void e1000_configure_rx(struct e1000_adapter *adapter)
{
	u64 rdba;
	struct e1000_hw *hw = &adapter->hw;
	u32 rdlen, rctl, rxcsum;
#ifdef CONFIG_E1000_NAPI
	if ((adapter->netdev->mtu > MAXIMUM_ETHERNET_VLAN_SIZE) &&
	   (hw->mac.type != e1000_82544 )) {
		rdlen = adapter->rx_ring->count *
		        sizeof(struct e1000_rx_desc);
		adapter->clean_rx = e1000_clean_jumbo_rx_irq;
		adapter->alloc_rx_buf = e1000_alloc_jumbo_rx_buffers;
	} else
#endif /* CONFIG_E1000_NAPI */
	{
		rdlen = adapter->rx_ring->count *
			sizeof(struct e1000_rx_desc);
		adapter->clean_rx = e1000_clean_rx_irq;
		adapter->alloc_rx_buf = e1000_alloc_rx_buffers;
	}

	/* disable receives while setting up the descriptors */
	rctl = E1000_READ_REG(hw, E1000_RCTL);
	E1000_WRITE_REG(hw, E1000_RCTL, rctl & ~E1000_RCTL_EN);
	/* do not flush or delay here, causes some strange problem
	 * on SERDES connected SFP modules */

	/* set the Receive Delay Timer Register */
	E1000_WRITE_REG(hw, E1000_RDTR, adapter->rx_int_delay);

	if (adapter->flags & E1000_FLAG_HAS_INTR_MODERATION) {
		E1000_WRITE_REG(hw, E1000_RADV, adapter->rx_abs_int_delay);
		if (adapter->itr_setting != 0)
			E1000_WRITE_REG(hw, E1000_ITR,
				1000000000 / (adapter->itr * 256));
	}

	/* Setup the HW Rx Head and Tail Descriptor Pointers and
	 * the Base and Length of the Rx Descriptor Ring */
	rdba = adapter->rx_ring->dma;
	E1000_WRITE_REG(hw, E1000_RDBAL(0), (rdba & 0x00000000ffffffffULL));
	E1000_WRITE_REG(hw, E1000_RDBAH(0), (rdba >> 32));
	E1000_WRITE_REG(hw, E1000_RDLEN(0), rdlen);
	E1000_WRITE_REG(hw, E1000_RDH(0), 0);
	E1000_WRITE_REG(hw, E1000_RDT(0), 0);
	adapter->rx_ring->rdh = E1000_REGISTER(hw, E1000_RDH(0));
	adapter->rx_ring->rdt = E1000_REGISTER(hw, E1000_RDT(0));

	if (hw->mac.type >= e1000_82543) {
		/* Enable 82543 Receive Checksum Offload for TCP and UDP */
		rxcsum = E1000_READ_REG(hw, E1000_RXCSUM);
		if (adapter->rx_csum == true) {
			rxcsum |= E1000_RXCSUM_TUOFL;
		} else {
			rxcsum &= ~E1000_RXCSUM_TUOFL;
			/* don't need to clear IPPCSE as it defaults to 0 */
		}
		E1000_WRITE_REG(hw, E1000_RXCSUM, rxcsum);
	}

	/* Enable Receives */
	E1000_WRITE_REG(hw, E1000_RCTL, rctl);
}

/**
 * e1000_free_tx_resources - Free Tx Resources per Queue
 * @adapter: board private structure
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 **/
static void e1000_free_tx_resources(struct e1000_adapter *adapter,
                                    struct e1000_tx_ring *tx_ring)
{
	struct pci_dev *pdev = adapter->pdev;

	e1000_clean_tx_ring(adapter, tx_ring);

	vfree(tx_ring->buffer_info);
	tx_ring->buffer_info = NULL;

	dma_free_coherent(pci_dev_to_dev(pdev), 
#ifdef ENABLE_DNA
			  (adapter->dna.dna_enabled ? 2 /* shadow descriptors */ : 1) * 
#endif
			  tx_ring->size, tx_ring->desc,
			  tx_ring->dma);

	tx_ring->desc = NULL;
}

/**
 * e1000_free_all_tx_resources - Free Tx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all transmit software resources
 **/
void e1000_free_all_tx_resources(struct e1000_adapter *adapter)
{
	e1000_free_tx_resources(adapter, adapter->tx_ring);
}

static void e1000_unmap_and_free_tx_resource(struct e1000_adapter *adapter,
                                             struct e1000_buffer *buffer_info)
{
	if (buffer_info->dma) {
		if (buffer_info->mapped_as_page)
			dma_unmap_page(pci_dev_to_dev(adapter->pdev),
				       buffer_info->dma,
				       buffer_info->length,
				       DMA_TO_DEVICE);
		else
			dma_unmap_single(pci_dev_to_dev(adapter->pdev),
					 buffer_info->dma,
					 buffer_info->length,
					 DMA_TO_DEVICE);
		buffer_info->dma = 0;
	}
	if (buffer_info->skb) {
		dev_kfree_skb_any(buffer_info->skb);
		buffer_info->skb = NULL;
	}
	/* buffer_info must be completely set up in the transmit path */
}

/**
 * e1000_clean_tx_ring - Free Tx Buffers
 * @adapter: board private structure
 * @tx_ring: ring to be cleaned
 **/
static void e1000_clean_tx_ring(struct e1000_adapter *adapter,
                                struct e1000_tx_ring *tx_ring)
{
	struct e1000_buffer *buffer_info;
	unsigned long size;
	unsigned int i;

	/* Free all the Tx ring sk_buffs */
#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled) {
	  struct pci_dev *pdev = adapter->pdev;
	  
	  if(adapter->dna.tx_packet_memory[0] != 0) {
	    printk("[DNA] e1000_clean_tx_ring(%s)\n", adapter->netdev->name);
	    
	    for (i = 0; i < tx_ring->count; i++) {
	      buffer_info = &tx_ring->buffer_info[i];
	      
	      if (buffer_info->dma) {
		pci_unmap_single(pdev, buffer_info->dma,
				 adapter->rx_buffer_len,
				   PCI_DMA_TODEVICE);
	      }
	    }
	    
	    printk("[DNA] Deallocating TX DMA memory\n");
	    
	    for(i=0; i<adapter->dna.num_memory_pages; i++) {
	      free_contiguous_memory(adapter->dna.tx_packet_memory[i],
				     adapter->dna.tot_packet_memory,
				     adapter->dna.mem_order);
	      adapter->dna.tx_packet_memory[i] = 0;
	    }
	  }	  
	} else {
#endif

	for (i = 0; i < tx_ring->count; i++) {
		buffer_info = &tx_ring->buffer_info[i];
		e1000_unmap_and_free_tx_resource(adapter, buffer_info);
	}

#ifdef ENABLE_DNA
        }
#endif

	size = sizeof(struct e1000_buffer) * tx_ring->count;
	memset(tx_ring->buffer_info, 0, size);

	/* Zero out the descriptor ring */

	memset(tx_ring->desc, 0, tx_ring->size);

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;
	tx_ring->last_tx_tso = 0;

	writel(0, adapter->hw.hw_addr + tx_ring->tdh);
	writel(0, adapter->hw.hw_addr + tx_ring->tdt);
}

/**
 * e1000_clean_all_tx_rings - Free Tx Buffers for all queues
 * @adapter: board private structure
 **/
static void e1000_clean_all_tx_rings(struct e1000_adapter *adapter)
{
	e1000_clean_tx_ring(adapter, adapter->tx_ring);
}

/**
 * e1000_free_rx_resources - Free Rx Resources
 * @adapter: board private structure
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 **/
static void e1000_free_rx_resources(struct e1000_adapter *adapter,
                                    struct e1000_rx_ring *rx_ring)
{
	struct pci_dev *pdev = adapter->pdev;

	e1000_clean_rx_ring(adapter, rx_ring);

	vfree(rx_ring->buffer_info);
	rx_ring->buffer_info = NULL;

	dma_free_coherent(pci_dev_to_dev(pdev), 
#ifdef ENABLE_DNA
			  (adapter->dna.dna_enabled ? 2 /* shadow descriptors */ : 1) * 
#endif
			  rx_ring->size, rx_ring->desc,
			  rx_ring->dma);

	rx_ring->desc = NULL;
}

/**
 * e1000_free_all_rx_resources - Free Rx Resources for All Queues
 * @adapter: board private structure
 *
 * Free all receive software resources
 **/
void e1000_free_all_rx_resources(struct e1000_adapter *adapter)
{
	e1000_free_rx_resources(adapter, adapter->rx_ring);
}

/**
 * e1000_clean_rx_ring - Free Rx Buffers per Queue
 * @adapter: board private structure
 * @rx_ring: ring to free buffers from
 **/
static void e1000_clean_rx_ring(struct e1000_adapter *adapter,
                                struct e1000_rx_ring *rx_ring)
{
	struct e1000_rx_buffer *buffer_info;
	struct pci_dev *pdev = adapter->pdev;
	unsigned long size;
	unsigned int i;

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled) {
	  struct e1000_tx_ring *tx_ring = adapter->tx_ring;
	  mem_ring_info         rx_info = {0}; 
	  mem_ring_info         tx_info = {0}; 

	  if(adapter->dna.rx_packet_memory[0] != 0) {
	    printk("[DNA] e1000_clean_rx_ring(%lu,%s)\n",
		   adapter->dna.rx_packet_memory[0],
		   adapter->netdev->name);

	    for (i = 0; i < rx_ring->count; i++) {
	      buffer_info = &rx_ring->buffer_info[i];

	      if (buffer_info->dma) {
#if 0
		if(0)
		  printk("[DNA] Unmapping buffer %d [ptr=%p]"
			 "[len=%d][%s][%lu]\n",
			 i, (void*)buffer_info->dma,
			 adapter->dna.packet_slot_len,
			 adapter->netdev->name,
			 adapter->dna.rx_packet_memory);
#endif

		pci_unmap_single(pdev, buffer_info->dma,
				 adapter->rx_buffer_len,
				 PCI_DMA_FROMDEVICE);
	      }
	    }

	    if(adapter->dna.rx_packet_memory[0] != 0) {
	      int i;
	      struct pfring_hooks *hook = (struct pfring_hooks*)adapter->netdev->pfring_ptr;

	      printk("[DNA] Deallocating DMA memory\n");

	      for(i=0; i<adapter->dna.num_memory_pages; i++) {
		free_contiguous_memory(adapter->dna.rx_packet_memory[i],
				       adapter->dna.tot_packet_memory,
				       adapter->dna.mem_order);
		adapter->dna.rx_packet_memory[i] = 0;
	      }

	      /* De-register with PF_RING */

	      rx_info.packet_memory_num_chunks    = 1;
	      rx_info.packet_memory_chunk_len     = adapter->dna.tot_packet_memory;
	      rx_info.packet_memory_num_slots     = adapter->dna.packet_num_slots;
	      rx_info.packet_memory_slot_len      = adapter->dna.packet_slot_len;
	      rx_info.descr_packet_memory_tot_len = 2 * rx_ring->size;
  
	      tx_info.packet_memory_num_chunks    = 1;
	      tx_info.packet_memory_chunk_len     = adapter->dna.tot_packet_memory;
	      tx_info.packet_memory_num_slots     = adapter->dna.packet_num_slots;
	      tx_info.packet_memory_slot_len      = adapter->dna.packet_slot_len;
	      tx_info.descr_packet_memory_tot_len = 2 * tx_ring->size;

	      hook->zc_dev_handler(remove_device_mapping,
					    dna_driver,
					    &rx_info,
					    &tx_info,
					    0, //adapter->dna.rx_packet_memory,
					    NULL, //rx_ring->desc,
					    0, //adapter->dna.tx_packet_memory,
					    NULL, //tx_ring->desc, /* Packet descriptors */
					    (void*)pci_resource_start(adapter->pdev, BAR_0),
					    pci_resource_len(adapter->pdev, BAR_0),
					    0, /* Channel Id */
					    adapter->netdev,
					    &pdev->dev,
					    intel_e1000,
					    adapter->netdev->dev_addr,
					    &adapter->dna.packet_waitqueue,
					    &adapter->dna.interrupt_received,
					    (void*)adapter, NULL,
					    NULL, NULL);

	      printk("[DNA] Disabled DNA on %s\n", adapter->netdev->name);
	    } else
	      printk("[DNA] WARNING Deallocating DMA memory is NULL\n");

	    /* Zero out the descriptor ring */
	    memset(rx_ring->desc, 0, rx_ring->size);

	    rx_ring->next_to_clean = 0;
	    rx_ring->next_to_use = 0;

	    writel(0, adapter->hw.hw_addr + rx_ring->rdh);
	    writel(0, adapter->hw.hw_addr + rx_ring->rdt);
	  }

	  return;	  
	}
#endif

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < rx_ring->count; i++) {
		buffer_info = &rx_ring->buffer_info[i];
		if (buffer_info->dma &&
		    adapter->clean_rx == e1000_clean_rx_irq) {
			dma_unmap_single(pci_dev_to_dev(pdev), buffer_info->dma,
			                 adapter->rx_buffer_len,
			                 DMA_FROM_DEVICE);
#ifdef CONFIG_E1000_NAPI
		} else if (buffer_info->dma &&
		           adapter->clean_rx == e1000_clean_jumbo_rx_irq) {
			dma_unmap_page(pci_dev_to_dev(pdev), buffer_info->dma,
				       PAGE_SIZE, DMA_FROM_DEVICE);
#endif /* CONFIG_E1000_NAPI */
		}

		buffer_info->dma = 0;
		if (buffer_info->page) {
			put_page(buffer_info->page);
			buffer_info->page = NULL;
		}
		if (buffer_info->skb) {
			dev_kfree_skb(buffer_info->skb);
			buffer_info->skb = NULL;
		}
	}

#ifdef CONFIG_E1000_NAPI
	/* there also may be some cached data from a chained receive */
	if (rx_ring->rx_skb_top) {
		dev_kfree_skb(rx_ring->rx_skb_top);
		rx_ring->rx_skb_top = NULL;
	}
#endif

	size = sizeof(struct e1000_rx_buffer) * rx_ring->count;
	memset(rx_ring->buffer_info, 0, size);

	/* Zero out the descriptor ring */

	memset(rx_ring->desc, 0, rx_ring->size);

	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
	adapter->flags &= ~E1000_FLAG_IS_DISCARDING;

	writel(0, adapter->hw.hw_addr + rx_ring->rdh);
	writel(0, adapter->hw.hw_addr + rx_ring->rdt);
}

/**
 * e1000_clean_all_rx_rings - Free Rx Buffers for all queues
 * @adapter: board private structure
 **/
static void e1000_clean_all_rx_rings(struct e1000_adapter *adapter)
{
	e1000_clean_rx_ring(adapter, adapter->rx_ring);
}

/* The 82542 2.0 (revision 2) needs to have the receive unit in reset
 * and memory write and invalidate disabled for certain operations
 */
static void e1000_enter_82542_rst(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	u32 rctl;

	if (adapter->hw.mac.type != e1000_82542)
		return;
	if (adapter->hw.revision_id != E1000_REVISION_2)
		return;

	e1000_pci_clear_mwi(&adapter->hw);

	rctl = E1000_READ_REG(&adapter->hw, E1000_RCTL);
	rctl |= E1000_RCTL_RST;
	E1000_WRITE_REG(&adapter->hw, E1000_RCTL, rctl);
	E1000_WRITE_FLUSH(&adapter->hw);
	mdelay(5);

	if (netif_running(netdev))
		e1000_clean_all_rx_rings(adapter);
}

static void e1000_leave_82542_rst(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	u32 rctl;

	if (adapter->hw.mac.type != e1000_82542)
		return;
	if (adapter->hw.revision_id != E1000_REVISION_2)
		return;

	rctl = E1000_READ_REG(&adapter->hw, E1000_RCTL);
	rctl &= ~E1000_RCTL_RST;
	E1000_WRITE_REG(&adapter->hw, E1000_RCTL, rctl);
	E1000_WRITE_FLUSH(&adapter->hw);
	mdelay(5);

	if (adapter->hw.bus.pci_cmd_word & PCI_COMMAND_INVALIDATE)
		e1000_pci_set_mwi(&adapter->hw);

	if (netif_running(netdev)) {
		/* No need to loop, because 82542 supports only 1 queue */
		struct e1000_rx_ring *ring = adapter->rx_ring;
		e1000_configure_rx(adapter);
		adapter->alloc_rx_buf(adapter, ring, E1000_DESC_UNUSED(ring));
	}
}

/**
 * e1000_set_mac - Change the Ethernet Address of the NIC
 * @netdev: network interface device structure
 * @p: pointer to an address structure
 *
 * Returns 0 on success, negative on failure
 **/
static int e1000_set_mac(struct net_device *netdev, void *p)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	/* 82542 2.0 needs to be in reset to write receive address registers */

	if (adapter->hw.mac.type == e1000_82542)
		e1000_enter_82542_rst(adapter);

	memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);
	memcpy(adapter->hw.mac.addr, addr->sa_data, netdev->addr_len);

	e1000_rar_set(&adapter->hw, adapter->hw.mac.addr, 0);

	if (adapter->hw.mac.type == e1000_82542)
		e1000_leave_82542_rst(adapter);

	return 0;
}

/**
 * e1000_set_multi - Multicast and Promiscuous mode set
 * @netdev: network interface device structure
 *
 * The set_multi entry point is called whenever the multicast address
 * list or the network interface flags are updated.  This routine is
 * responsible for configuring the hardware for proper multicast,
 * promiscuous mode, and all-multi behavior.
 **/
static void e1000_set_multi(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
#ifdef NETDEV_HW_ADDR_T_MULTICAST
	struct netdev_hw_addr *ha;
#else
	struct dev_mc_list *ha;
#endif
	u8  *mta_list;
	u32 rctl;
	int i;

	/* Check for Promiscuous and All Multicast modes */

	rctl = E1000_READ_REG(hw, E1000_RCTL);

	if (netdev->flags & IFF_PROMISC) {
		rctl |= (E1000_RCTL_UPE | E1000_RCTL_MPE);

		/* disable VLAN filters */
		rctl &= ~E1000_RCTL_VFE;
	} else {
		if (netdev->flags & IFF_ALLMULTI) {
			rctl |= E1000_RCTL_MPE;
			rctl &= ~E1000_RCTL_UPE;
		} else {
			rctl &= ~(E1000_RCTL_UPE | E1000_RCTL_MPE);
		}
#ifdef NETIF_F_HW_VLAN_TX

		/* enable VLAN filters if there's a VLAN */
		if (adapter->vlgrp)
			rctl |= E1000_RCTL_VFE;
#endif
	}
	E1000_WRITE_REG(hw, E1000_RCTL, rctl);

	/* 82542 2.0 needs to be in reset to write receive address registers */

	if (hw->mac.type == e1000_82542)
		e1000_enter_82542_rst(adapter);

	mta_list = kmalloc(netdev_mc_count(netdev) * 6, GFP_ATOMIC);
	if (!mta_list)
		return;

	/* The shared function expects a packed array of only addresses. */
	i = 0;
	netdev_for_each_mc_addr(ha, netdev)
#ifdef NETDEV_HW_ADDR_T_MULTICAST
		memcpy(mta_list + (i++ * ETH_ALEN), ha->addr, ETH_ALEN);
#else
		memcpy(mta_list + (i++ * ETH_ALEN), ha->dmi_addr, ETH_ALEN);
#endif

	e1000_update_mc_addr_list(hw, mta_list, i);
	kfree(mta_list);

	if (hw->mac.type == e1000_82542)
		e1000_leave_82542_rst(adapter);
}

/* Need to wait a few seconds after link up to get diagnostic information from
 * the phy */
static void e1000_update_phy_info(unsigned long data)
{
	struct e1000_adapter *adapter = (struct e1000_adapter *) data;
	schedule_work(&adapter->phy_info_task);
}

static void e1000_update_phy_info_task(struct work_struct *work)
{
	struct e1000_adapter *adapter = container_of(work,
	                                             struct e1000_adapter,
	                                             phy_info_task);
	rtnl_lock();
	e1000_get_phy_info(&adapter->hw);
	rtnl_unlock();
}

/**
 * e1000_82547_tx_fifo_stall - Timer Call-back
 * @data: pointer to adapter cast into an unsigned long
 **/
static void e1000_82547_tx_fifo_stall(unsigned long data)
{
	struct e1000_adapter *adapter = (struct e1000_adapter *) data;
	schedule_work(&adapter->fifo_stall_task);
}

/**
 * e1000_82547_tx_fifo_stall_task - task to complete work
 * @work: work struct contained inside adapter struct
 **/
static void e1000_82547_tx_fifo_stall_task(struct work_struct *work)
{
	struct e1000_adapter *adapter = container_of(work,
	                                             struct e1000_adapter,
	                                             fifo_stall_task);
	struct net_device *netdev = adapter->netdev;
	u32 tctl;

	rtnl_lock();
	if (atomic_read(&adapter->tx_fifo_stall)) {
		if ((E1000_READ_REG(&adapter->hw, E1000_TDT(0)) ==
		    E1000_READ_REG(&adapter->hw, E1000_TDH(0))) &&
		   (E1000_READ_REG(&adapter->hw, E1000_TDFT) ==
		    E1000_READ_REG(&adapter->hw, E1000_TDFH)) &&
		   (E1000_READ_REG(&adapter->hw, E1000_TDFTS) ==
		    E1000_READ_REG(&adapter->hw, E1000_TDFHS))) {
			tctl = E1000_READ_REG(&adapter->hw, E1000_TCTL);
			E1000_WRITE_REG(&adapter->hw, E1000_TCTL,
					tctl & ~E1000_TCTL_EN);
			E1000_WRITE_REG(&adapter->hw, E1000_TDFT,
					adapter->tx_head_addr);
			E1000_WRITE_REG(&adapter->hw, E1000_TDFH,
					adapter->tx_head_addr);
			E1000_WRITE_REG(&adapter->hw, E1000_TDFTS,
					adapter->tx_head_addr);
			E1000_WRITE_REG(&adapter->hw, E1000_TDFHS,
					adapter->tx_head_addr);
			E1000_WRITE_REG(&adapter->hw, E1000_TCTL, tctl);
			E1000_WRITE_FLUSH(&adapter->hw);

			adapter->tx_fifo_head = 0;
			atomic_set(&adapter->tx_fifo_stall, 0);
			netif_wake_queue(netdev);
		} else if (!test_bit(__E1000_DOWN, &adapter->state))
			mod_timer(&adapter->tx_fifo_stall_timer, jiffies + 1);
	}
	rtnl_unlock();
}

bool e1000_has_link(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	bool link_active = false;
	s32 ret_val = 0;

	/* get_link_status is set on LSC (link status) interrupt or
	 * rx sequence error interrupt.  get_link_status will stay
	 * false until the e1000_check_for_link establishes link
	 * for copper adapters ONLY
	 */
	switch (hw->phy.media_type) {
	case e1000_media_type_copper:
		if (hw->mac.get_link_status) {
			ret_val = e1000_check_for_link(hw);
			link_active = !hw->mac.get_link_status;
		} else {
			link_active = true;
		}
		break;
	case e1000_media_type_fiber:
		ret_val = e1000_check_for_link(hw);
		link_active = !!(E1000_READ_REG(hw, E1000_STATUS) &
		                 E1000_STATUS_LU);
		break;
	case e1000_media_type_internal_serdes:
		ret_val = e1000_check_for_link(hw);
		link_active = adapter->hw.mac.serdes_has_link;
		break;
	default:
	case e1000_media_type_unknown:
		break;
	}

	if ((ret_val == E1000_ERR_PHY) && (hw->phy.type == e1000_phy_igp_3) &&
	    (E1000_READ_REG(&adapter->hw, E1000_CTRL) & E1000_PHY_CTRL_GBE_DISABLE)) {
		DPRINTK(LINK, INFO,
			"Gigabit has been disabled, downgrading speed\n");
	}

	return link_active;
}

/**
 * e1000_watchdog - Timer Call-back
 * @data: pointer to adapter cast into an unsigned long
 **/
static void e1000_watchdog(unsigned long data)
{
	struct e1000_adapter *adapter = (struct e1000_adapter *) data;

	/* Do the rest outside of interrupt context */
	schedule_work(&adapter->watchdog_task);
}

static void e1000_watchdog_task(struct work_struct *work)
{
	struct e1000_adapter *adapter = container_of(work,
	                                struct e1000_adapter, watchdog_task);
	struct net_device *netdev = adapter->netdev;
	struct e1000_mac_info *mac = &adapter->hw.mac;
	struct e1000_tx_ring *tx_ring;
	u32 link, tctl;
	int tx_pending = 0;

	link = e1000_has_link(adapter);
	if ((netif_carrier_ok(netdev)) && link)
		goto link_up;

	if (link) {
		if (!netif_carrier_ok(netdev)) {
			u32 ctrl;
#ifdef SIOCGMIIPHY
			/* update snapshot of PHY registers on LSC */
			e1000_phy_read_status(adapter);
#endif
			e1000_get_speed_and_duplex(&adapter->hw,
			                           &adapter->link_speed,
			                           &adapter->link_duplex);

			ctrl = E1000_READ_REG(&adapter->hw, E1000_CTRL);
			DPRINTK(LINK, INFO, "NIC Link is Up %d Mbps %s, "
			        "Flow Control: %s\n",
			        adapter->link_speed,
			        adapter->link_duplex == FULL_DUPLEX ?
			        "Full Duplex" : "Half Duplex",
			        ((ctrl & E1000_CTRL_TFCE) && (ctrl &
			        E1000_CTRL_RFCE)) ? "RX/TX" : ((ctrl &
			        E1000_CTRL_RFCE) ? "RX" : ((ctrl &
			        E1000_CTRL_TFCE) ? "TX" : "None" )));

			/* adjust the timeout factor according to speed/duplex */
			adapter->tx_timeout_factor = 1;
			switch (adapter->link_speed) {
			case SPEED_10:
				adapter->tx_timeout_factor = 16;
				break;
			case SPEED_100:
				/* maybe add some timeout factor ? */
				break;
			}

#ifdef NETIF_F_TSO
			/* disable TSO for pcie and 10/100 speeds, to avoid
			 * some hardware issues */
			if (!(adapter->flags & E1000_FLAG_TSO_FORCE) &&
			    adapter->hw.bus.type == e1000_bus_type_pci_express){
				switch (adapter->link_speed) {
				case SPEED_10:
				case SPEED_100:
					DPRINTK(PROBE,INFO,
				        "10/100 speed: disabling TSO\n");
					netdev->features &= ~NETIF_F_TSO;
#ifdef NETIF_F_TSO6
					netdev->features &= ~NETIF_F_TSO6;
#endif
					break;
				case SPEED_1000:
					netdev->features |= NETIF_F_TSO;
#ifdef NETIF_F_TSO6
					netdev->features |= NETIF_F_TSO6;
#endif
					break;
				default:
					/* oops */
					break;
				}
			}
#endif

			/* enable transmits in the hardware, need to do this
			 * after setting TARC0 */
			tctl = E1000_READ_REG(&adapter->hw, E1000_TCTL);
			tctl |= E1000_TCTL_EN;
			E1000_WRITE_REG(&adapter->hw, E1000_TCTL, tctl);

			netif_carrier_on(netdev);
			netif_wake_queue(netdev);

			if (!test_bit(__E1000_DOWN, &adapter->state))
				mod_timer(&adapter->phy_info_timer,
				          round_jiffies(jiffies + 2 * HZ));
			adapter->smartspeed = 0;
		}
	} else {
		if (netif_carrier_ok(netdev)) {
			adapter->link_speed = 0;
			adapter->link_duplex = 0;
			DPRINTK(LINK, INFO, "NIC Link is Down\n");
			netif_carrier_off(netdev);
			netif_stop_queue(netdev);

			if (!test_bit(__E1000_DOWN, &adapter->state))
				mod_timer(&adapter->phy_info_timer,
				          round_jiffies(jiffies + 2 * HZ));
		}

		e1000_smartspeed(adapter);
	}

link_up:
	e1000_update_stats(adapter);

	mac->tx_packet_delta = adapter->stats.tpt - adapter->tpt_old;
	adapter->tpt_old = adapter->stats.tpt;
	mac->collision_delta = adapter->stats.colc - adapter->colc_old;
	adapter->colc_old = adapter->stats.colc;

	adapter->gorc = adapter->stats.gorc - adapter->gorc_old;
	adapter->gorc_old = adapter->stats.gorc;
	adapter->gotc = adapter->stats.gotc - adapter->gotc_old;
	adapter->gotc_old = adapter->stats.gotc;

	e1000_update_adaptive(&adapter->hw);

	if (!netif_carrier_ok(netdev)) {
		tx_ring = adapter->tx_ring;
		tx_pending |= (E1000_DESC_UNUSED(tx_ring) +
		               tx_ring->step  < tx_ring->count);
		if (tx_pending) {
			/* We've lost link, so the controller stops DMA,
			 * but we've got queued Tx work that's never going
			 * to get done, so reset controller to flush Tx.
			 * (Do the reset outside of interrupt context). */
			adapter->tx_timeout_count++;
			schedule_work(&adapter->reset_task);
		}
	}

	/* Simple mode for Interrupt Throttle Rate (ITR) */
	if (adapter->hw.mac.type >= e1000_82540 && adapter->itr_setting == 4) {
		/*
		 * Symmetric Tx/Rx gets a reduced ITR=2000;
		 * Total asymmetrical Tx or Rx gets ITR=8000;
		 * everyone else is between 2000-8000.
		 */
		u32 goc = (adapter->gotc + adapter->gorc) / 10000;
		u32 dif = (adapter->gotc > adapter->gorc ?
			    adapter->gotc - adapter->gorc :
			    adapter->gorc - adapter->gotc) / 10000;
		u32 itr = goc > 0 ? (dif * 6000 / goc + 2000) : 8000;

		E1000_WRITE_REG(&adapter->hw, E1000_ITR, 1000000000 / (itr * 256));
	}

	/* Cause software interrupt to ensure rx ring is cleaned */
	E1000_WRITE_REG(&adapter->hw, E1000_ICS, E1000_ICS_RXDMT0);

	/* Force detection of hung controller every watchdog period */
	adapter->detect_tx_hung = true;

	/* Reset the timer */
	if (!test_bit(__E1000_DOWN, &adapter->state))
		mod_timer(&adapter->watchdog_timer,
		          round_jiffies(jiffies + 2 * HZ));
}

enum latency_range {
	lowest_latency = 0,
	low_latency = 1,
	bulk_latency = 2,
	latency_invalid = 255
};

/**
 * e1000_update_itr - update the dynamic ITR value based on statistics
 * @adapter: pointer to adapter
 * @itr_setting: current adapter->itr
 * @packets: the number of packets during this measurement interval
 * @bytes: the number of bytes during this measurement interval
 *
 *      Stores a new ITR value based on packets and byte
 *      counts during the last interrupt.  The advantage of per interrupt
 *      computation is faster updates and more accurate ITR for the current
 *      traffic pattern.  Constants in this function were computed
 *      based on theoretical maximum wire speed and thresholds were set based
 *      on testing data as well as attempting to minimize response time
 *      while increasing bulk throughput.
 *      this functionality is controlled by the InterruptThrottleRate module
 *      parameter (see e1000_param.c)
 **/
static unsigned int e1000_update_itr(struct e1000_adapter *adapter,
                                     u16 itr_setting, int packets,
                                     int bytes)
{
	unsigned int retval = itr_setting;

	if (unlikely(!(adapter->flags & E1000_FLAG_HAS_INTR_MODERATION)))
		goto update_itr_done;

	if (packets == 0)
		goto update_itr_done;

	switch (itr_setting) {
	case lowest_latency:
		/* handle TSO and jumbo frames */
		if (bytes/packets > 8000)
			retval = bulk_latency;
		else if ((packets < 5) && (bytes > 512)) {
			retval = low_latency;
		}
		break;
	case low_latency:  /* 50 usec aka 20000 ints/s */
		if (bytes > 10000) {
			/* this if handles the TSO accounting */
			if (bytes/packets > 8000) {
				retval = bulk_latency;
			} else if ((packets < 10) || ((bytes/packets) > 1200)) {
				retval = bulk_latency;
			} else if ((packets > 35)) {
				retval = lowest_latency;
			}
		} else if (bytes/packets > 2000) {
			retval = bulk_latency;
		} else if (packets <= 2 && bytes < 512) {
			retval = lowest_latency;
		}
		break;
	case bulk_latency: /* 250 usec aka 4000 ints/s */
		if (bytes > 25000) {
			if (packets > 35) {
				retval = low_latency;
			}
		} else if (bytes < 6000) {
			retval = low_latency;
		}
		break;
	}

update_itr_done:
	return retval;
}

static void e1000_set_itr(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u16 current_itr;
	u32 new_itr = adapter->itr;

	if (unlikely(!(adapter->flags & E1000_FLAG_HAS_INTR_MODERATION)))
		return;

	/* for non-gigabit speeds, just fix the interrupt rate at 4000 */
	if (unlikely(adapter->link_speed != SPEED_1000)) {
		current_itr = 0;
		new_itr = 4000;
		goto set_itr_now;
	}

	adapter->tx_itr = e1000_update_itr(adapter,
	                            adapter->tx_itr,
	                            adapter->total_tx_packets,
	                            adapter->total_tx_bytes);
	/* conservative mode (itr 3) eliminates the lowest_latency setting */
	if (adapter->itr_setting == 3 && adapter->tx_itr == lowest_latency)
		adapter->tx_itr = low_latency;

	adapter->rx_itr = e1000_update_itr(adapter,
	                            adapter->rx_itr,
	                            adapter->total_rx_packets,
	                            adapter->total_rx_bytes);
	/* conservative mode (itr 3) eliminates the lowest_latency setting */
	if (adapter->itr_setting == 3 && adapter->rx_itr == lowest_latency)
		adapter->rx_itr = low_latency;

	current_itr = max(adapter->rx_itr, adapter->tx_itr);

	switch (current_itr) {
	/* counts and packets in update_itr are dependent on these numbers */
	case lowest_latency:
		new_itr = 70000;
		break;
	case low_latency:
		new_itr = 20000; /* aka hwitr = ~200 */
		break;
	case bulk_latency:
		new_itr = 4000;
		break;
	default:
		break;
	}

set_itr_now:
	if (new_itr != adapter->itr) {
		/* this attempts to bias the interrupt rate towards Bulk
		 * by adding intermediate steps when interrupt rate is
		 * increasing */
		new_itr = new_itr > adapter->itr ?
		             min(adapter->itr + (new_itr >> 2), new_itr) :
		             new_itr;
		adapter->itr = new_itr;
		E1000_WRITE_REG(hw, E1000_ITR, 1000000000 / (new_itr * 256));
	}

	return;
}

#define E1000_TX_FLAGS_CSUM		0x00000001
#define E1000_TX_FLAGS_VLAN		0x00000002
#define E1000_TX_FLAGS_TSO		0x00000004
#define E1000_TX_FLAGS_IPV4		0x00000008
#define E1000_TX_FLAGS_VLAN_MASK	0xffff0000
#define E1000_TX_FLAGS_VLAN_SHIFT	16

static int e1000_tso(struct e1000_adapter *adapter,
                     struct e1000_tx_ring *tx_ring, struct sk_buff *skb)
{
#ifdef NETIF_F_TSO
	struct e1000_context_desc *context_desc;
	struct e1000_buffer *buffer_info;
	unsigned int i;
	u32 cmd_length = 0;
	u16 ipcse = 0, tucse, mss;
	u8 ipcss, ipcso, tucss, tucso, hdr_len;
	int err;

	if (skb_is_gso(skb)) {
		if (skb_header_cloned(skb)) {
			err = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
			if (err)
				return err;
		}

		hdr_len = skb_transport_offset(skb) + tcp_hdrlen(skb);
		mss = skb_shinfo(skb)->gso_size;
		if (skb->protocol == htons(ETH_P_IP)) {
			struct iphdr *iph = ip_hdr(skb);
			iph->tot_len = 0;
			iph->check = 0;
			tcp_hdr(skb)->check = ~csum_tcpudp_magic(iph->saddr,
								 iph->daddr, 0,
								 IPPROTO_TCP,
								 0);
			cmd_length = E1000_TXD_CMD_IP;
			ipcse = skb_transport_offset(skb) - 1;
#ifdef NETIF_F_TSO6
		} else if (skb_shinfo(skb)->gso_type == SKB_GSO_TCPV6) {
			ipv6_hdr(skb)->payload_len = 0;
			tcp_hdr(skb)->check =
				~csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
						 &ipv6_hdr(skb)->daddr,
						 0, IPPROTO_TCP, 0);
			ipcse = 0;
#endif
		}
		ipcss = skb_network_offset(skb);
		ipcso = (void *)&(ip_hdr(skb)->check) - (void *)skb->data;
		tucss = skb_transport_offset(skb);
		tucso = (void *)&(tcp_hdr(skb)->check) - (void *)skb->data;
		tucse = 0;

		cmd_length |= (E1000_TXD_CMD_DEXT | E1000_TXD_CMD_TSE |
			       E1000_TXD_CMD_TCP | (skb->len - (hdr_len)));

		i = tx_ring->next_to_use;
		context_desc = E1000_CONTEXT_DESC(*tx_ring, i);
		buffer_info = &tx_ring->buffer_info[i];

		context_desc->lower_setup.ip_fields.ipcss  = ipcss;
		context_desc->lower_setup.ip_fields.ipcso  = ipcso;
		context_desc->lower_setup.ip_fields.ipcse  = cpu_to_le16(ipcse);
		context_desc->upper_setup.tcp_fields.tucss = tucss;
		context_desc->upper_setup.tcp_fields.tucso = tucso;
		context_desc->upper_setup.tcp_fields.tucse = cpu_to_le16(tucse);
		context_desc->tcp_seg_setup.fields.mss     = cpu_to_le16(mss);
		context_desc->tcp_seg_setup.fields.hdr_len = hdr_len;
		context_desc->cmd_and_length = cpu_to_le32(cmd_length);

		buffer_info->time_stamp = jiffies;
		buffer_info->next_to_watch = i;

		E1000_TX_DESC_INC(tx_ring,i);
		tx_ring->next_to_use = i;

		return true;
	}
#endif

	return false;
}

static bool e1000_tx_csum(struct e1000_adapter *adapter,
                               struct e1000_tx_ring *tx_ring,
                               struct sk_buff *skb)
{
	struct e1000_context_desc *context_desc;
	struct e1000_buffer *buffer_info;
	unsigned int i;
	u8 css;
	u32 cmd_len = E1000_TXD_CMD_DEXT;

	if (unlikely(skb->ip_summed != CHECKSUM_PARTIAL))
		return false;

	switch (skb->protocol) {
	case __constant_htons(ETH_P_IP):
		if (ip_hdr(skb)->protocol == IPPROTO_TCP)
			cmd_len |= E1000_TXD_CMD_TCP;
		break;
	case __constant_htons(ETH_P_IPV6):
		/* XXX not handling all IPV6 headers */
		if (ipv6_hdr(skb)->nexthdr == IPPROTO_TCP)
			cmd_len |= E1000_TXD_CMD_TCP;
		break;
	default:
		if (unlikely(net_ratelimit())) {
			DPRINTK(PROBE, WARNING, "checksum_partial proto=%x!\n",
			        skb->protocol);
		}
		break;
	}

	css = skb_transport_offset(skb);

	i = tx_ring->next_to_use;
	buffer_info = &tx_ring->buffer_info[i];
	context_desc = E1000_CONTEXT_DESC(*tx_ring, i);

	context_desc->lower_setup.ip_config = 0;
	context_desc->upper_setup.tcp_fields.tucss = css;
	context_desc->upper_setup.tcp_fields.tucso = css +
							skb->csum_offset;
	context_desc->upper_setup.tcp_fields.tucse = 0;
	context_desc->tcp_seg_setup.data = 0;
	context_desc->cmd_and_length = cpu_to_le32(cmd_len);

	buffer_info->time_stamp = jiffies;
	buffer_info->next_to_watch = i;

	E1000_TX_DESC_INC(tx_ring,i);
	tx_ring->next_to_use = i;

	return true;
}

static int e1000_tx_map(struct e1000_adapter *adapter,
                        struct e1000_tx_ring *tx_ring,
                        struct sk_buff *skb, unsigned int first,
                        unsigned int max_per_txd, unsigned int nr_frags,
                        unsigned int mss)
{
	struct e1000_buffer *buffer_info;
	unsigned int len = skb->len;
	unsigned int offset = 0, size, count = 0, i;
#ifdef MAX_SKB_FRAGS
	unsigned int f;
	len -= skb->data_len;
#endif

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled)
	  return count; /* No legacy send in DNA mode */
#endif

	i = tx_ring->next_to_use;

	while (len) {
		buffer_info = &tx_ring->buffer_info[i];
		size = min(len, max_per_txd);
#ifdef NETIF_F_TSO
		/* Workaround for Controller erratum --
		 * descriptor for non-tso packet in a linear SKB that follows a
		 * tso gets written back prematurely before the data is fully
		 * DMA'd to the controller */
		if (tx_ring->last_tx_tso && !skb_is_gso(skb)) {
			tx_ring->last_tx_tso = 0;
			if (!skb->data_len)
				size -= 4;
		}

		/* Workaround for premature desc write-backs
		 * in TSO mode.  Append 4-byte sentinel desc */
		if (unlikely(mss && !nr_frags && size == len && size > 8))
			size -= 4;
#endif
		/* work-around for errata 10 and it applies
		 * to all controllers in PCI-X mode
		 * The fix is to make sure that the first descriptor of a
		 * packet is smaller than 2048 - 16 - 16 (or 2016) bytes
		 */
		if (unlikely((adapter->hw.bus.type == e1000_bus_type_pcix) &&
		                (size > 2015) && count == 0))
		        size = 2015;

		/* Workaround for potential 82544 hang in PCI-X.  Avoid
		 * terminating buffers within evenly-aligned dwords. */
		if (unlikely(adapter->pcix_82544 &&
		   !((unsigned long)(skb->data + offset + size - 1) & 4) &&
		   size > 4))
			size -= 4;

		buffer_info->length = size;
		/* set time_stamp *before* dma to help avoid a possible race */
		buffer_info->time_stamp = jiffies;
		buffer_info->dma =
			dma_map_single(pci_dev_to_dev(adapter->pdev),
				       skb->data + offset,
				       size,
				       DMA_TO_DEVICE);
		buffer_info->mapped_as_page = false;
		buffer_info->next_to_watch = i;

		len -= size;
		offset += size;
		count++;
		E1000_TX_DESC_INC(tx_ring,i);
	}

#ifdef MAX_SKB_FRAGS
	for (f = 0; f < nr_frags; f++) {
		struct skb_frag_struct *frag;

		frag = &skb_shinfo(skb)->frags[f];
		len = frag->size;
		offset = frag->page_offset;

		while (len) {
			buffer_info = &tx_ring->buffer_info[i];
			size = min(len, max_per_txd);
#ifdef NETIF_F_TSO
			/* Workaround for premature desc write-backs
			 * in TSO mode.  Append 4-byte sentinel desc */
			if (unlikely(mss && f == (nr_frags-1) && size == len && size > 8))
				size -= 4;
#endif
			/* Workaround for potential 82544 hang in PCI-X.
			 * Avoid terminating buffers within evenly-aligned
			 * dwords. */
			if (unlikely(adapter->pcix_82544 &&
			    !((unsigned long)(page_to_phys(frag->page) + offset
			                      + size - 1) & 4) &&
			    size > 4))
				size -= 4;

			buffer_info->length = size;
			buffer_info->time_stamp = jiffies;
			buffer_info->dma =
				dma_map_page(pci_dev_to_dev(adapter->pdev),
					     frag->page,
					     offset,
					     size,
					     DMA_TO_DEVICE);
			buffer_info->mapped_as_page = true;
			buffer_info->next_to_watch = i;

			len -= size;
			offset += size;
			count++;
			E1000_TX_DESC_INC(tx_ring,i);
		}
	}
#endif
	E1000_TX_DESC_DEC(tx_ring,i);
	tx_ring->buffer_info[i].skb = skb;
	tx_ring->buffer_info[first].next_to_watch = i;

	return count;
}

static void e1000_tx_queue(struct e1000_adapter *adapter,
                           struct e1000_tx_ring *tx_ring,
                           int tx_flags, int count)
{
	struct e1000_tx_desc *tx_desc = NULL;
	struct e1000_buffer *buffer_info;
	u32 txd_upper = 0, txd_lower = E1000_TXD_CMD_IFCS;
	unsigned int i;

	if (likely(tx_flags & E1000_TX_FLAGS_TSO)) {
		txd_lower |= E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D |
		             E1000_TXD_CMD_TSE;
		txd_upper |= E1000_TXD_POPTS_TXSM << 8;

		if (likely(tx_flags & E1000_TX_FLAGS_IPV4))
			txd_upper |= E1000_TXD_POPTS_IXSM << 8;
	}

	if (likely(tx_flags & E1000_TX_FLAGS_CSUM)) {
		txd_lower |= E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D;
		txd_upper |= E1000_TXD_POPTS_TXSM << 8;
	}

	if (unlikely(tx_flags & E1000_TX_FLAGS_VLAN)) {
		txd_lower |= E1000_TXD_CMD_VLE;
		txd_upper |= (tx_flags & E1000_TX_FLAGS_VLAN_MASK);
	}

	i = tx_ring->next_to_use;

	while (count--) {
		buffer_info = &tx_ring->buffer_info[i];
		tx_desc = E1000_TX_DESC(*tx_ring, i);
		tx_desc->buffer_addr = cpu_to_le64(buffer_info->dma);
		tx_desc->lower.data =
			cpu_to_le32(txd_lower | buffer_info->length);
		tx_desc->upper.data = cpu_to_le32(txd_upper);
		E1000_TX_DESC_INC(tx_ring,i);
	}

	tx_desc->lower.data |= cpu_to_le32(adapter->txd_cmd);

	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.  (Only
	 * applicable for weak-ordered memory model archs,
	 * such as IA-64). */
	wmb();

	tx_ring->next_to_use = i;
	writel(i, adapter->hw.hw_addr + tx_ring->tdt);
	/* we need this if more than one processor can write to our tail
	 * at a time, it synchronizes IO on IA64/Altix systems */
	mmiowb();
}

#define E1000_FIFO_HDR			0x10
#define E1000_82547_PAD_LEN		0x3E0

/**
 * 82547 workaround to avoid controller hang in half-duplex environment.
 * The workaround is to avoid queuing a large packet that would span
 * the internal Tx FIFO ring boundary by notifying the stack to resend
 * the packet at a later time.  This gives the Tx FIFO an opportunity to
 * flush all packets.  When that occurs, we reset the Tx FIFO pointers
 * to the beginning of the Tx FIFO.
 **/
static int e1000_82547_fifo_workaround(struct e1000_adapter *adapter,
                                       struct sk_buff *skb)
{
	u32 fifo_space = adapter->tx_fifo_size - adapter->tx_fifo_head;
	u32 skb_fifo_len = skb->len + E1000_FIFO_HDR;

	skb_fifo_len = ALIGN(skb_fifo_len, E1000_FIFO_HDR);

	if (adapter->link_duplex != HALF_DUPLEX)
		goto no_fifo_stall_required;

	if (atomic_read(&adapter->tx_fifo_stall))
		return 1;

	if (skb_fifo_len >= (E1000_82547_PAD_LEN + fifo_space)) {
		atomic_set(&adapter->tx_fifo_stall, 1);
		return 1;
	}

no_fifo_stall_required:
	adapter->tx_fifo_head += skb_fifo_len;
	if (adapter->tx_fifo_head >= adapter->tx_fifo_size)
		adapter->tx_fifo_head -= adapter->tx_fifo_size;
	return 0;
}

static int __e1000_maybe_stop_tx(struct net_device *netdev,
                                 struct e1000_tx_ring *tx_ring, int size)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	netif_stop_queue(netdev);
	/* Herbert's original patch had:
	 *  smp_mb__after_netif_stop_queue();
	 * but since that doesn't exist yet, just open code it. */
	smp_mb();

	/* We need to check again in a case another CPU has just
	 * made room available. */
	if (likely(E1000_DESC_UNUSED(tx_ring) < ((size) * tx_ring->step)))
		return -EBUSY;

	/* A reprieve! */
	netif_start_queue(netdev);
	++adapter->restart_queue;
	return 0;
}

static int e1000_maybe_stop_tx(struct net_device *netdev,
                               struct e1000_tx_ring *tx_ring, int size)
{
	if (likely(E1000_DESC_UNUSED(tx_ring) >= ((size) * tx_ring->step)))
		return 0;
	return __e1000_maybe_stop_tx(netdev, tx_ring, size);
}

#define TXD_USE_COUNT(S, X) (((S) >> (X)) + 1 )
static int e1000_xmit_frame(struct sk_buff *skb, struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_tx_ring *tx_ring = adapter->tx_ring;
	unsigned int max_txd_pwr = adapter->tx_desc_pwr;
	unsigned int first, max_per_txd = (1 << max_txd_pwr);
	unsigned int tx_flags = 0;
	unsigned int len = skb->len;
	unsigned int nr_frags = 0;
	unsigned int mss = 0;
	int count = 0;
	int tso;
#ifdef MAX_SKB_FRAGS
	unsigned int f;
	len -= skb->data_len;
#endif

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled) {
	  dev_kfree_skb_any(skb);
	  return NETDEV_TX_OK; /* No legacy send in DNA mode */
	}
#endif

	if (test_bit(__E1000_DOWN, &adapter->state)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (unlikely(skb->len <= 0)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
	/* On PCIX HW, there have been rare TXHangs caused by custom apps
	 * sending frames with skb->len == 16 (macdest+macsrc+protocol+2bytes).
	 * Such frames are not transmitted by registered protocols, so are
	 * only a problem for experimental code.
	 * Pad all 16 byte packets with an additional byte to work-around this
	 * problem case.
	 */
	if (skb->len < 17) {
		if (skb_padto(skb, 17))
			return NETDEV_TX_OK;
		skb->len = 17;
	}


#ifdef NETIF_F_TSO
	mss = skb_shinfo(skb)->gso_size;
	/* The controller does a simple calculation to
	 * make sure there is enough room in the FIFO before
	 * initiating the DMA for each buffer.  The calc is:
	 * 4 = ceil(buffer len/mss).  To make sure we don't
	 * overrun the FIFO, adjust the max buffer len if mss
	 * drops. */
	if (mss) {
		u8 hdr_len;
		max_per_txd = min(mss << 2, max_per_txd);
		max_txd_pwr = fls(max_per_txd) - 1;

		/* TSO Workaround */
		hdr_len = skb_transport_offset(skb) + tcp_hdrlen(skb);
		if (skb->data_len && (hdr_len == (skb->len - skb->data_len))) {
			switch (adapter->hw.mac.type) {
				unsigned int pull_size;
			case e1000_82544:
				/* Make sure we have room to chop off 4 bytes,
				 * and that the end alignment will work out to
				 * this hardware's requirements
				 * NOTE: this is a TSO only workaround
				 * if end byte alignment not correct move us
				 * into the next dword */
				if ((unsigned long)(skb_tail_pointer(skb) - 1) & 4)
					break;
				pull_size = min((unsigned int)4, skb->data_len);
				if (!__pskb_pull_tail(skb, pull_size)) {
					DPRINTK(DRV, ERR,
						"__pskb_pull_tail failed.\n");
					dev_kfree_skb_any(skb);
					return NETDEV_TX_OK;
				}
				len = skb->len - skb->data_len;
				break;
			default:
				/* do nothing */
				break;
			}
		}
	}

	/* reserve a descriptor for the offload context */
	if ((mss) || (skb->ip_summed == CHECKSUM_PARTIAL))
		count++;
	count++;
#else
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		count++;
#endif

#ifdef NETIF_F_TSO
	/* Controller Erratum workaround */
	if (!skb->data_len && tx_ring->last_tx_tso && !skb_is_gso(skb))
		count++;
#endif

	count += TXD_USE_COUNT(len, max_txd_pwr);

	if (adapter->pcix_82544)
		count++;

	/* work-around for errata 10 and it applies to all controllers
	 * in PCI-X mode, so add one more descriptor to the count
	 */
	if (unlikely((adapter->hw.bus.type == e1000_bus_type_pcix) &&
			(len > 2015)))
		count++;

#ifdef MAX_SKB_FRAGS
	nr_frags = skb_shinfo(skb)->nr_frags;
	for (f = 0; f < nr_frags; f++)
		count += TXD_USE_COUNT(skb_shinfo(skb)->frags[f].size,
				       max_txd_pwr);
	if (adapter->pcix_82544)
		count += nr_frags;

#endif

	/* need: count + 2 desc gap to keep tail from touching
	 * head, otherwise try next time */
	if (unlikely(e1000_maybe_stop_tx(netdev, tx_ring, count + 2)))
		return NETDEV_TX_BUSY;

	if (unlikely(adapter->hw.mac.type == e1000_82547)) {
		if (unlikely(e1000_82547_fifo_workaround(adapter, skb))) {
			netif_stop_queue(netdev);
			if (!test_bit(__E1000_DOWN, &adapter->state))
				mod_timer(&adapter->tx_fifo_stall_timer,
				          jiffies + 1);
			return NETDEV_TX_BUSY;
		}
	}

#ifdef NETIF_F_HW_VLAN_TX
	if (unlikely(adapter->vlgrp && vlan_tx_tag_present(skb))) {
		tx_flags |= E1000_TX_FLAGS_VLAN;
		tx_flags |= (vlan_tx_tag_get(skb) << E1000_TX_FLAGS_VLAN_SHIFT);
	}
#endif

	first = tx_ring->next_to_use;

	tso = e1000_tso(adapter, tx_ring, skb);
	if (tso < 0) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (likely(tso)) {
		if (likely(adapter->hw.mac.type != e1000_82544))
			tx_ring->last_tx_tso = 1;
		tx_flags |= E1000_TX_FLAGS_TSO;
	} else if (likely(e1000_tx_csum(adapter, tx_ring, skb)))
		tx_flags |= E1000_TX_FLAGS_CSUM;

	if (likely(skb->protocol == htons(ETH_P_IP)))
		tx_flags |= E1000_TX_FLAGS_IPV4;

	e1000_tx_queue(adapter, tx_ring, tx_flags,
	               e1000_tx_map(adapter, tx_ring, skb, first,
	                            max_per_txd, nr_frags, mss));

	netdev->trans_start = jiffies;

	/* Make sure there is space in the ring for the next send. */
	e1000_maybe_stop_tx(netdev, tx_ring, MAX_SKB_FRAGS + 2);

	return NETDEV_TX_OK;
}


/**
 * e1000_tx_timeout - Respond to a Tx Hang
 * @netdev: network interface device structure
 **/
static void e1000_tx_timeout(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	/* Do the reset outside of interrupt context */
	adapter->tx_timeout_count++;
	schedule_work(&adapter->reset_task);
}

static void e1000_reset_task(struct work_struct *work)
{
	struct e1000_adapter *adapter;
	adapter = container_of(work, struct e1000_adapter, reset_task);

	e1000_reinit_safe(adapter);
}

/**
 * e1000_get_stats - Get System Network Statistics
 * @netdev: network interface device structure
 *
 * Returns the address of the device statistics structure.
 * The statistics are actually updated from the timer callback.
 **/
static struct net_device_stats * e1000_get_stats(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	/* only return the current stats */
	return &adapter->net_stats;
}

/**
 * e1000_change_mtu - Change the Maximum Transfer Unit
 * @netdev: network interface device structure
 * @new_mtu: new value for maximum frame size
 *
 * Returns 0 on success, negative on failure
 **/
static int e1000_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN;

	if ((new_mtu < 68) || (max_frame > MAX_JUMBO_FRAME_SIZE)) {
		DPRINTK(PROBE, ERR, "Invalid MTU setting\n");
		return -EINVAL;
	}

	/* Adapter-specific max frame size limits. */
	switch (adapter->hw.mac.type) {
	case e1000_undefined:
	case e1000_82542:
		if (max_frame > ETH_FRAME_LEN + ETH_FCS_LEN) {
			DPRINTK(PROBE, ERR, "Jumbo Frames not supported.\n");
			return -EINVAL;
		}
		break;
	default:
		/* Capable of supporting up to MAX_JUMBO_FRAME_SIZE limit. */
		break;
	}

	while (test_and_set_bit(__E1000_RESETTING, &adapter->state))
		msleep(1);
	/* e1000_down has a dependency on max_frame_size */
	adapter->max_frame_size = max_frame;
	if (netif_running(netdev))
		e1000_down(adapter);

	/* NOTE: netdev_alloc_skb reserves 16 bytes, and typically NET_IP_ALIGN
	 * means we reserve 2 more, this pushes us to allocate from the next
	 * larger slab size.
	 * i.e. RXBUFFER_2048 --> size-4096 slab
	 *  however with the new *_jumbo_rx* routines, jumbo receives will use
	 *  fragmented skbs */

	/* Due to a HW errata, the 82544 should not use the jumbo routines, and
	 * so will have to handle jumbo frames within one descriptor.
 	 */
 	if (adapter->hw.mac.type == e1000_82544) {
		if (max_frame <= E1000_RXBUFFER_2048)
			adapter->rx_buffer_len = E1000_RXBUFFER_2048;
		else if (max_frame <= E1000_RXBUFFER_4096)
			adapter->rx_buffer_len = E1000_RXBUFFER_4096;
		else if (max_frame <= E1000_RXBUFFER_8192)
			adapter->rx_buffer_len = E1000_RXBUFFER_8192;
		else if (max_frame <= E1000_RXBUFFER_16384)
			adapter->rx_buffer_len = E1000_RXBUFFER_16384;
	} else {
		if (max_frame <= E1000_RXBUFFER_2048)
			adapter->rx_buffer_len = E1000_RXBUFFER_2048;
	#ifdef CONFIG_E1000_NAPI
		else
			adapter->rx_buffer_len = E1000_RXBUFFER_4096;
	#else
		else if (max_frame <= E1000_RXBUFFER_4096)
			adapter->rx_buffer_len = E1000_RXBUFFER_4096;
		else if (max_frame <= E1000_RXBUFFER_8192)
			adapter->rx_buffer_len = E1000_RXBUFFER_8192;
		else if (max_frame <= E1000_RXBUFFER_16384)
			adapter->rx_buffer_len = E1000_RXBUFFER_16384;
	#endif
	}
	/* adjust allocation if LPE protects us, and we aren't using SBP */
	if (!e1000_tbi_sbp_enabled_82543(&adapter->hw) &&
	    ((max_frame == ETH_FRAME_LEN + ETH_FCS_LEN) ||
	     (max_frame == MAXIMUM_ETHERNET_VLAN_SIZE)))
		adapter->rx_buffer_len = MAXIMUM_ETHERNET_VLAN_SIZE;

	DPRINTK(PROBE, INFO, "changing MTU from %d to %d\n",
	        netdev->mtu, new_mtu);
	netdev->mtu = new_mtu;

	if (netif_running(netdev))
		e1000_up(adapter);
	else
		e1000_reset(adapter);

	clear_bit(__E1000_RESETTING, &adapter->state);

	return 0;
}

/**
 * e1000_update_stats - Update the board statistics counters
 * @adapter: board private structure
 **/
void e1000_update_stats(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
#ifdef HAVE_PCI_ERS
	struct pci_dev *pdev = adapter->pdev;
#endif
	unsigned long irq_flags;
	u16 phy_tmp;

#define PHY_IDLE_ERROR_COUNT_MASK 0x00FF

	/*
	 * Prevent stats update while adapter is being reset, or if the pci
	 * connection is down.
	 */
	if (adapter->link_speed == 0)
		return;
#ifdef HAVE_PCI_ERS
	if (pci_channel_offline(pdev))
		return;
#endif

	spin_lock_irqsave(&adapter->stats_lock, irq_flags);

	/* these counters are modified from e1000_adjust_tbi_stats,
	 * called from the interrupt context, so they must only
	 * be written while holding adapter->stats_lock
	 */

	adapter->stats.crcerrs += E1000_READ_REG(hw, E1000_CRCERRS);
	adapter->stats.gprc += E1000_READ_REG(hw, E1000_GPRC);
	adapter->stats.gorc += E1000_READ_REG(hw, E1000_GORCL);
	E1000_READ_REG(hw, E1000_GORCH); /* Clear gorc */
	adapter->stats.bprc += E1000_READ_REG(hw, E1000_BPRC);
	adapter->stats.mprc += E1000_READ_REG(hw, E1000_MPRC);
	adapter->stats.roc += E1000_READ_REG(hw, E1000_ROC);

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled) {
	/* mpc stats are read from userpace in DNA mode */
	} else {
#endif
	adapter->stats.mpc += E1000_READ_REG(hw, E1000_MPC);
#ifdef ENABLE_DNA
	}
#endif

	adapter->stats.scc += E1000_READ_REG(hw, E1000_SCC);
	adapter->stats.ecol += E1000_READ_REG(hw, E1000_ECOL);
	adapter->stats.mcc += E1000_READ_REG(hw, E1000_MCC);
	adapter->stats.latecol += E1000_READ_REG(hw, E1000_LATECOL);
	adapter->stats.dc += E1000_READ_REG(hw, E1000_DC);
	adapter->stats.xonrxc += E1000_READ_REG(hw, E1000_XONRXC);
	adapter->stats.xontxc += E1000_READ_REG(hw, E1000_XONTXC);
	adapter->stats.xoffrxc += E1000_READ_REG(hw, E1000_XOFFRXC);
	adapter->stats.xofftxc += E1000_READ_REG(hw, E1000_XOFFTXC);
	adapter->stats.gptc += E1000_READ_REG(hw, E1000_GPTC);
	adapter->stats.gotc += E1000_READ_REG(hw, E1000_GOTCL);
	E1000_READ_REG(hw, E1000_GOTCH); /* Clear gotc */
	adapter->stats.rnbc += E1000_READ_REG(hw, E1000_RNBC);
	adapter->stats.ruc += E1000_READ_REG(hw, E1000_RUC);

	adapter->stats.mptc += E1000_READ_REG(hw, E1000_MPTC);
	adapter->stats.bptc += E1000_READ_REG(hw, E1000_BPTC);

	/* used for adaptive IFS */

	hw->mac.tx_packet_delta = E1000_READ_REG(hw, E1000_TPT);
	adapter->stats.tpt += hw->mac.tx_packet_delta;
	hw->mac.collision_delta = E1000_READ_REG(hw, E1000_COLC);
	adapter->stats.colc += hw->mac.collision_delta;

	if (hw->mac.type >= e1000_82543) {
		adapter->stats.algnerrc += E1000_READ_REG(hw, E1000_ALGNERRC);
		adapter->stats.rxerrc += E1000_READ_REG(hw, E1000_RXERRC);
		adapter->stats.tncrs += E1000_READ_REG(hw, E1000_TNCRS);
		adapter->stats.cexterr += E1000_READ_REG(hw, E1000_CEXTERR);
		adapter->stats.tsctc += E1000_READ_REG(hw, E1000_TSCTC);
		adapter->stats.tsctfc += E1000_READ_REG(hw, E1000_TSCTFC);
	}

	/* Fill out the OS statistics structure */
	adapter->net_stats.multicast = adapter->stats.mprc;
	adapter->net_stats.collisions = adapter->stats.colc;

	/* Rx Errors */

	/* RLEC on some newer hardware can be incorrect so build
	* our own version based on RUC and ROC */
	adapter->net_stats.rx_errors = adapter->stats.rxerrc +
		adapter->stats.crcerrs + adapter->stats.algnerrc +
		adapter->stats.ruc + adapter->stats.roc +
		adapter->stats.cexterr;
	adapter->net_stats.rx_length_errors = adapter->stats.ruc +
	                                      adapter->stats.roc;
	adapter->net_stats.rx_crc_errors = adapter->stats.crcerrs;
	adapter->net_stats.rx_frame_errors = adapter->stats.algnerrc;
	adapter->net_stats.rx_missed_errors = adapter->stats.mpc;

	/* Tx Errors */
	adapter->net_stats.tx_errors = adapter->stats.ecol +
	                               adapter->stats.latecol;
	adapter->net_stats.tx_aborted_errors = adapter->stats.ecol;
	adapter->net_stats.tx_window_errors = adapter->stats.latecol;
	if ((adapter->flags & E1000_FLAG_BAD_TX_CARRIER_STATS_FD) &&
	    adapter->link_duplex == FULL_DUPLEX) {
		adapter->net_stats.tx_carrier_errors = 0;
		adapter->stats.tncrs = 0;
	} else {
		adapter->net_stats.tx_carrier_errors = adapter->stats.tncrs;
	}

	/* Tx Dropped needs to be maintained elsewhere */

	/* Phy Stats */
	if (hw->phy.media_type == e1000_media_type_copper) {
		if ((adapter->link_speed == SPEED_1000) &&
		   (!e1000_read_phy_reg(hw, PHY_1000T_STATUS, &phy_tmp))) {
			phy_tmp &= PHY_IDLE_ERROR_COUNT_MASK;
			adapter->phy_stats.idle_errors += phy_tmp;
		}

		if ((hw->mac.type <= e1000_82546) &&
		   (hw->phy.type == e1000_phy_m88) &&
		   !e1000_read_phy_reg(hw, M88E1000_RX_ERR_CNTR, &phy_tmp))
			adapter->phy_stats.receive_errors += phy_tmp;
	}

	/* Management Stats */
	if (adapter->flags & E1000_FLAG_HAS_SMBUS) {
		adapter->stats.mgptc += E1000_READ_REG(hw, E1000_MGTPTC);
		adapter->stats.mgprc += E1000_READ_REG(hw, E1000_MGTPRC);
		adapter->stats.mgpdc += E1000_READ_REG(hw, E1000_MGTPDC);
	}

	spin_unlock_irqrestore(&adapter->stats_lock, irq_flags);
}
#ifdef SIOCGMIIPHY

/**
 * e1000_phy_read_status - Update the PHY register status snapshot
 * @adapter: board private structure
 **/
static void e1000_phy_read_status(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_phy_regs *phy = &adapter->phy_regs;
	int ret_val = E1000_SUCCESS;
	unsigned long irq_flags;


	spin_lock_irqsave(&adapter->stats_lock, irq_flags);

	if (E1000_READ_REG(hw, E1000_STATUS)& E1000_STATUS_LU) {
		ret_val = e1000_read_phy_reg(hw, PHY_CONTROL, &phy->bmcr);
		ret_val |= e1000_read_phy_reg(hw, PHY_STATUS, &phy->bmsr);
		ret_val |= e1000_read_phy_reg(hw, PHY_AUTONEG_ADV,
		                              &phy->advertise);
		ret_val |= e1000_read_phy_reg(hw, PHY_LP_ABILITY, &phy->lpa);
		ret_val |= e1000_read_phy_reg(hw, PHY_AUTONEG_EXP,
		                              &phy->expansion);
		ret_val |= e1000_read_phy_reg(hw, PHY_1000T_CTRL,
		                              &phy->ctrl1000);
		ret_val |= e1000_read_phy_reg(hw, PHY_1000T_STATUS,
		                              &phy->stat1000);
		ret_val |= e1000_read_phy_reg(hw, PHY_EXT_STATUS,
		                              &phy->estatus);
		if (ret_val)
			DPRINTK(DRV, WARNING, "Error reading PHY register\n");
	} else {
		/* Do not read PHY registers if link is not up
		 * Set values to typical power-on defaults */
		phy->bmcr = (BMCR_SPEED1000 | BMCR_ANENABLE | BMCR_FULLDPLX);
		phy->bmsr = (BMSR_100FULL | BMSR_100HALF | BMSR_10FULL |
		             BMSR_10HALF | BMSR_ESTATEN | BMSR_ANEGCAPABLE |
		             BMSR_ERCAP);
		phy->advertise = (ADVERTISE_PAUSE_ASYM | ADVERTISE_PAUSE_CAP |
		                  ADVERTISE_ALL | ADVERTISE_CSMA);
		phy->lpa = 0;
		phy->expansion = EXPANSION_ENABLENPAGE;
		phy->ctrl1000 = ADVERTISE_1000FULL;
		phy->stat1000 = 0;
		phy->estatus = (ESTATUS_1000_TFULL | ESTATUS_1000_THALF);
	}

	spin_unlock_irqrestore(&adapter->stats_lock, irq_flags);
}
#endif


/**
 * e1000_intr - Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 **/
static irqreturn_t e1000_intr(int irq, void *data)
{
	struct net_device *netdev = data;
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 icr = E1000_READ_REG(hw, E1000_ICR);

	if (unlikely((!icr)))
		return IRQ_NONE;  /* Not our interrupt */

	/*
	 * we might have caused the interrupt, but the above
	 * read cleared it, and just in case the driver is
	 * down there is nothing to do so return handled
	 */
	if (unlikely(test_bit(__E1000_DOWN, &adapter->state)))
		return IRQ_HANDLED;

	if (unlikely(icr & (E1000_ICR_RXSEQ | E1000_ICR_LSC))) {
		hw->mac.get_link_status = 1;

		/* guard against interrupt when we're going down */
		if (!test_bit(__E1000_DOWN, &adapter->state))
			mod_timer(&adapter->watchdog_timer, jiffies + 1);
	}

#ifdef CONFIG_E1000_NAPI
	if (likely(napi_schedule_prep(&adapter->rx_ring->napi))) {
		/* disable interrupts, without the synchronize_irq bit */
		E1000_WRITE_REG(hw, E1000_IMC, ~0);
		E1000_WRITE_FLUSH(&adapter->hw);

		adapter->total_tx_bytes = 0;
		adapter->total_tx_packets = 0;
		adapter->total_rx_bytes = 0;
		adapter->total_rx_packets = 0;
		__napi_schedule(&adapter->rx_ring->napi);
	}
#else
	/* Writing IMC and IMS is needed for 82547.
	 * Due to Hub Link bus being occupied, an interrupt
	 * de-assertion message is not able to be sent.
	 * When an interrupt assertion message is generated later,
	 * two messages are re-ordered and sent out.
	 * That causes APIC to think 82547 is in de-assertion
	 * state, while 82547 is in assertion state, resulting
	 * in dead lock. Writing IMC forces 82547 into
	 * de-assertion state.
	 */
	if (hw->mac.type == e1000_82547 || hw->mac.type == e1000_82547_rev_2)
		E1000_WRITE_REG(hw, E1000_IMC, ~0);

	adapter->total_tx_bytes = 0;
	adapter->total_rx_bytes = 0;
	adapter->total_tx_packets = 0;
	adapter->total_rx_packets = 0;

	adapter->clean_rx(adapter, adapter->rx_ring);
	e1000_clean_tx_irq(adapter, adapter->tx_ring);

	if (likely(adapter->itr_setting & 3))
		e1000_set_itr(adapter);

	if (hw->mac.type == e1000_82547 || hw->mac.type == e1000_82547_rev_2)
		if (!test_bit(__E1000_DOWN, &adapter->state))
			e1000_irq_enable(adapter);

#endif
	return IRQ_HANDLED;
}

#ifdef CONFIG_E1000_NAPI
/**
 * e1000_poll - NAPI Rx polling callback
 * @napi: struct associated with this polling callback
 * @budget: amount of packets driver is allowed to process this poll
 **/
static int e1000_poll(struct napi_struct *napi, int budget)
{
	struct e1000_rx_ring *rx_ring = container_of(napi, struct e1000_rx_ring,
	                                             napi);
	struct e1000_adapter *adapter = rx_ring->adapter;
	bool tx_clean_complete;
	int work_done = 0;

	tx_clean_complete = e1000_clean_tx_irq(adapter, adapter->tx_ring);

	adapter->clean_rx(adapter, adapter->rx_ring, &work_done, budget);

	if (!tx_clean_complete)
		work_done = budget;

#ifndef HAVE_NETDEV_NAPI_LIST
	if (!netif_running(adapter->netdev))
		work_done = 0;

#endif
	/* If no Tx and not enough Rx work done, exit the polling mode */
	if (work_done < budget) {
		if (likely(adapter->itr_setting & 3))
			e1000_set_itr(adapter);
		napi_complete(napi);
		if (!test_bit(__E1000_DOWN, &adapter->state))
			e1000_irq_enable(adapter);

	}

	return work_done;
}

#endif
/**
 * e1000_clean_tx_irq - Reclaim resources after transmit completes
 * @adapter: board private structure
 *
 * the return value indicates if transmit processing was completed
 **/
static bool e1000_clean_tx_irq(struct e1000_adapter *adapter,
                               struct e1000_tx_ring *tx_ring)
{
	struct net_device *netdev = adapter->netdev;
	struct e1000_tx_desc *tx_desc, *eop_desc;
	struct e1000_buffer *buffer_info;
	unsigned int i, eop;
#ifdef CONFIG_E1000_NAPI
	unsigned int count = 0;
#endif
	bool cleaned = false;
	bool retval = true;
	unsigned int total_tx_bytes=0, total_tx_packets=0;

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled) {
	  if(0)
	    printk(KERN_WARNING "DNA: e1000_clean_tx_irq(%s): "
		   "woken up\n", adapter->netdev->name);
	  return(TRUE);
	}
#endif

	i = tx_ring->next_to_clean;
	eop = tx_ring->buffer_info[i].next_to_watch;
	eop_desc = E1000_TX_DESC(*tx_ring, eop);

	while (eop_desc->upper.data & cpu_to_le32(E1000_TXD_STAT_DD)) {
		/* Value of eop could change between read and DD check */
		if (unlikely(eop != tx_ring->buffer_info[i].next_to_watch))
			goto cont_loop;

		for (cleaned = false; !cleaned; ) {
			tx_desc = E1000_TX_DESC(*tx_ring, i);
			buffer_info = &tx_ring->buffer_info[i];
			cleaned = (i == eop);

			if (cleaned) {
				struct sk_buff *skb = buffer_info->skb;
#ifdef NETIF_F_TSO
				unsigned int segs, bytecount;
				segs = skb_shinfo(skb)->gso_segs ?: 1;
				/* multiply data chunks by size of headers */
				bytecount = ((segs - 1) * skb_headlen(skb)) +
				            skb->len;
				total_tx_packets += segs;
				total_tx_bytes += bytecount;
#else
				total_tx_packets++;
				total_tx_bytes += skb->len;
#endif
			}
			e1000_unmap_and_free_tx_resource(adapter, buffer_info);
			tx_desc->upper.data = 0;
			E1000_TX_DESC_INC(tx_ring,i);
		}

cont_loop:
		eop = tx_ring->buffer_info[i].next_to_watch;
		eop_desc = E1000_TX_DESC(*tx_ring, eop);
#ifdef CONFIG_E1000_NAPI
#define E1000_TX_WEIGHT 64
		/* weight of a sort for tx, to avoid endless transmit cleanup */
		if (count++ == E1000_TX_WEIGHT) {
			retval = false;
			break;
		}
#endif
	}

	tx_ring->next_to_clean = i;

#define TX_WAKE_THRESHOLD 32
	if (unlikely(cleaned && netif_carrier_ok(netdev) &&
		     E1000_DESC_UNUSED(tx_ring) >= TX_WAKE_THRESHOLD)) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();

		if (netif_queue_stopped(netdev) &&
		    !(test_bit(__E1000_DOWN, &adapter->state))) {
			netif_wake_queue(netdev);
			++adapter->restart_queue;
		}
	}

	if (adapter->detect_tx_hung) {
		/* Detect a transmit hang in hardware, this serializes the
		 * check with the clearing of time_stamp and movement of i */
		adapter->detect_tx_hung = false;
		if (tx_ring->buffer_info[eop].dma &&
		    time_after(jiffies, tx_ring->buffer_info[eop].time_stamp +
		               (adapter->tx_timeout_factor * HZ))
		    && !(E1000_READ_REG(&adapter->hw, E1000_STATUS) &
		         E1000_STATUS_TXOFF)) {

			/* detected Tx unit hang */
			DPRINTK(DRV, ERR, "Detected Tx Unit Hang\n"
					"  Tx Queue             <%lu>\n"
					"  TDH                  <%x>\n"
					"  TDT                  <%x>\n"
					"  next_to_use          <%x>\n"
					"  next_to_clean        <%x>\n"
					"buffer_info[next_to_clean]\n"
					"  time_stamp           <%lx>\n"
					"  next_to_watch        <%x>\n"
					"  jiffies              <%lx>\n"
					"  next_to_watch.status <%x>\n",
				(unsigned long)((tx_ring - adapter->tx_ring) /
					sizeof(struct e1000_tx_ring)),
				readl(adapter->hw.hw_addr + tx_ring->tdh),
				readl(adapter->hw.hw_addr + tx_ring->tdt),
				tx_ring->next_to_use,
				tx_ring->next_to_clean,
				tx_ring->buffer_info[eop].time_stamp,
				eop,
				jiffies,
				eop_desc->upper.fields.status);
			netif_stop_queue(netdev);
		}
	}
	adapter->total_tx_bytes += total_tx_bytes;
	adapter->total_tx_packets += total_tx_packets;
	adapter->net_stats.tx_bytes += total_tx_bytes;
	adapter->net_stats.tx_packets += total_tx_packets;
	return retval;
}

/**
 * e1000_rx_checksum - Receive Checksum Offload for 82543
 * @adapter:     board private structure
 * @status_err:  receive descriptor status and error fields
 * @csum:        receive descriptor csum field
 * @sk_buff:     socket buffer with received data
 **/
static void e1000_rx_checksum(struct e1000_adapter *adapter, u32 status_err,
                              u32 csum, struct sk_buff *skb)
{
	u16 status = (u16)status_err;
	u8 errors = (u8)(status_err >> 24);
	skb->ip_summed = CHECKSUM_NONE;

	/* 82543 or newer only */
	if (unlikely(adapter->hw.mac.type < e1000_82543)) return;
	/* Ignore Checksum bit is set */
	if (unlikely(status & E1000_RXD_STAT_IXSM)) return;
	/* TCP/UDP checksum error bit is set */
	if (unlikely(errors & E1000_RXD_ERR_TCPE)) {
		/* let the stack verify checksum errors */
		adapter->hw_csum_err++;
		return;
	}
	/* TCP/UDP Checksum has not been calculated */
	if (adapter->hw.mac.type <= e1000_82547_rev_2) {
		if (!(status & E1000_RXD_STAT_TCPCS))
			return;
	} else {
		if (!(status & (E1000_RXD_STAT_TCPCS | E1000_RXD_STAT_UDPCS)))
			return;
	}
	/* It must be a TCP or UDP packet with a valid checksum */
	if (likely(status & E1000_RXD_STAT_TCPCS)) {
		/* TCP checksum is good */
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	adapter->hw_csum_good++;
}

/**
 * e1000_receive_skb - helper function to handle rx indications
 * @adapter: board private structure
 * @status: descriptor status field as written by hardware
 * @vlan: descriptor vlan field as written by hardware (no le/be conversion)
 * @skb: pointer to sk_buff to be indicated to stack
 **/
static void e1000_receive_skb(struct e1000_adapter *adapter, u8 status,
                              u16 vlan, struct sk_buff *skb)
{
	skb->protocol = eth_type_trans(skb, adapter->netdev);

#ifdef CONFIG_E1000_NAPI
#ifdef NETIF_F_HW_VLAN_TX
	if ((unlikely(adapter->vlgrp && (status & E1000_RXD_STAT_VP))))
		vlan_gro_receive(&adapter->rx_ring->napi, adapter->vlgrp,
				 le16_to_cpu(vlan) & E1000_RXD_SPC_VLAN_MASK,
				 skb);
	else
		napi_gro_receive(&adapter->rx_ring->napi, skb);
#else
	napi_gro_receive(skb);
#endif
#else /* CONFIG_E1000_NAPI */
#ifdef NETIF_F_HW_VLAN_TX
	if (unlikely(adapter->vlgrp && (status & E1000_RXD_STAT_VP)))
		vlan_hwaccel_rx(skb, adapter->vlgrp,
		                le16_to_cpu(vlan) & E1000_RXD_SPC_VLAN_MASK);
	else
		netif_rx(skb);
#else
	netif_rx(skb);
#endif
#endif /* CONFIG_E1000_NAPI */
}

#ifdef CONFIG_E1000_NAPI
/* NOTE: these new jumbo frame routines rely on NAPI because of the
 * pskb_may_pull call, which eventually must call kmap_atomic which you cannot
 * call from hard irq context */

/**
 * e1000_consume_page - helper function
 **/
static void e1000_consume_page(struct e1000_rx_buffer *bi, struct sk_buff *skb,
                               u16 length)
{
	bi->page = NULL;
	skb->len += length;
	skb->data_len += length;
	skb->truesize += length;
}

/**
 * e1000_clean_jumbo_rx_irq - Send received data up the network stack; legacy
 * @adapter: board private structure
 *
 * the return value indicates whether actual cleaning was done, there
 * is no guarantee that everything was cleaned
 **/
static bool e1000_clean_jumbo_rx_irq(struct e1000_adapter *adapter,
                                          struct e1000_rx_ring *rx_ring,
                                          int *work_done, int work_to_do)
{
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_rx_desc *rx_desc, *next_rxd;
	struct e1000_rx_buffer *buffer_info, *next_buffer;
	unsigned long irq_flags;
	u32 length;
	unsigned int i;
	int cleaned_count = 0;
	bool cleaned = false;
	unsigned int total_rx_bytes=0, total_rx_packets=0;

	i = rx_ring->next_to_clean;
	rx_desc = E1000_RX_DESC(*rx_ring, i);
	buffer_info = &rx_ring->buffer_info[i];

	while (rx_desc->status & E1000_RXD_STAT_DD) {
		struct sk_buff *skb;
		u8 status;

		if (*work_done >= work_to_do)
			break;
		(*work_done)++;

		status = rx_desc->status;
		skb = buffer_info->skb;
		buffer_info->skb = NULL;

		if (++i == rx_ring->count) i = 0;
		next_rxd = E1000_RX_DESC(*rx_ring, i);
		prefetch(next_rxd);

		next_buffer = &rx_ring->buffer_info[i];

		cleaned = true;
		cleaned_count++;
		dma_unmap_page(pci_dev_to_dev(pdev),
		               buffer_info->dma,
		               PAGE_SIZE,
		               DMA_FROM_DEVICE);
		buffer_info->dma = 0;

		length = le16_to_cpu(rx_desc->length);

		/* errors is only valid for DD + EOP descriptors */
		if (unlikely((status & E1000_RXD_STAT_EOP) &&
		    (rx_desc->errors & E1000_RXD_ERR_FRAME_ERR_MASK))) {
			u8 last_byte = *(skb->data + length - 1);
			if (TBI_ACCEPT(&adapter->hw, status,
			              rx_desc->errors, length, last_byte,
			              adapter->min_frame_size,
			              adapter->max_frame_size)) {
				spin_lock_irqsave(&adapter->stats_lock,
				                  irq_flags);
				e1000_tbi_adjust_stats_82543(&adapter->hw,
				                      &adapter->stats,
				                      length, skb->data,
				                      adapter->max_frame_size);
				spin_unlock_irqrestore(&adapter->stats_lock,
				                       irq_flags);
				length--;
			} else {
				/* recycle both page and skb */
				buffer_info->skb = skb;
				/* an error means any chain goes out the window
				 * too */
				if (rx_ring->rx_skb_top)
					dev_kfree_skb(rx_ring->rx_skb_top);
				rx_ring->rx_skb_top = NULL;
				goto next_desc;
			}
		}

#define rxtop rx_ring->rx_skb_top
		if (!(status & E1000_RXD_STAT_EOP)) {
			/* this descriptor is only the beginning (or middle) */
			if (!rxtop) {
				/* this is the beginning of a chain */
				rxtop = skb;
				skb_fill_page_desc(rxtop, 0, buffer_info->page,
				                   0, length);
			} else {
				/* this is the middle of a chain */
				skb_fill_page_desc(rxtop,
				    skb_shinfo(rxtop)->nr_frags,
				    buffer_info->page, 0, length);
				/* re-use the skb, only consumed the page */
				buffer_info->skb = skb;
			}
			e1000_consume_page(buffer_info, rxtop, length);
			goto next_desc;
		} else {
			if (rxtop) {
				/* end of the chain */
				skb_fill_page_desc(rxtop,
				    skb_shinfo(rxtop)->nr_frags,
				    buffer_info->page, 0, length);
				/* re-use the current skb, we only consumed the
				 * page */
				buffer_info->skb = skb;
				skb = rxtop;
				rxtop = NULL;
				e1000_consume_page(buffer_info, skb, length);
			} else {
				/* no chain, got EOP, this buf is the packet
				 * copybreak to save the put_page/alloc_page */
				if (length <= copybreak &&
				    skb_tailroom(skb) >= length) {
					u8 *vaddr;
					vaddr = kmap_atomic(buffer_info->page,
					                   KM_SKB_DATA_SOFTIRQ);
					memcpy(skb_tail_pointer(skb), vaddr, length);
					kunmap_atomic(vaddr,
					              KM_SKB_DATA_SOFTIRQ);
					/* re-use the page, so don't erase
					 * buffer_info->page */
					skb_put(skb, length);
				} else {
					skb_fill_page_desc(skb, 0,
					                   buffer_info->page, 0,
				                           length);
					e1000_consume_page(buffer_info, skb,
					                   length);
				}
			}
		}

		/* Receive Checksum Offload XXX recompute due to CRC strip? */
		e1000_rx_checksum(adapter,
		                  (u32)(status) |
		                  ((u32)(rx_desc->errors) << 24),
		                  le16_to_cpu(rx_desc->csum), skb);

		pskb_trim(skb, skb->len - 4);

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;
		total_rx_packets++;

		/* eth type trans needs skb->data to point to something */
		if (!pskb_may_pull(skb, ETH_HLEN)) {
			DPRINTK(DRV, ERR, "__pskb_pull_tail failed.\n");
			dev_kfree_skb(skb);
			goto next_desc;
		}

		e1000_receive_skb(adapter, status, rx_desc->special, skb);

		netdev->last_rx = jiffies;

next_desc:
		rx_desc->status = 0;

		/* return some buffers to hardware, one at a time is too slow */
		if (unlikely(cleaned_count >= E1000_RX_BUFFER_WRITE)) {
			adapter->alloc_rx_buf(adapter, rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		/* use prefetched values */
		rx_desc = next_rxd;
		buffer_info = next_buffer;
	}
	rx_ring->next_to_clean = i;

	cleaned_count = E1000_DESC_UNUSED(rx_ring);
	if (cleaned_count)
		adapter->alloc_rx_buf(adapter, rx_ring, cleaned_count);

	adapter->total_rx_packets += total_rx_packets;
	adapter->total_rx_bytes += total_rx_bytes;
	adapter->net_stats.rx_bytes += total_rx_bytes;
	adapter->net_stats.rx_packets += total_rx_packets;
	return cleaned;
}
#endif /* NAPI */


/**
 * e1000_clean_rx_irq - Send received data up the network stack; legacy
 * @adapter: board private structure
 *
 * the return value indicates whether actual cleaning was done, there
 * is no guarantee that everything was cleaned
 **/
#ifdef CONFIG_E1000_NAPI
static bool e1000_clean_rx_irq(struct e1000_adapter *adapter,
			       struct e1000_rx_ring *rx_ring,
			       int *work_done, int work_to_do)
#else
static bool e1000_clean_rx_irq(struct e1000_adapter *adapter,
                                    struct e1000_rx_ring *rx_ring)
#endif
{
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_rx_desc *rx_desc, *next_rxd;
	struct e1000_rx_buffer *buffer_info, *next_buffer;
	unsigned long irq_flags;
	u32 length;
	unsigned int i;
	int cleaned_count = 0;
	bool cleaned = false;
	unsigned int total_rx_bytes=0, total_rx_packets=0;

#ifdef ENABLE_DNA
        if(adapter->dna.dna_enabled) {
	  return(dna_e1000_clean_rx_irq(adapter, rx_ring, work_done));
	}
#endif

	i = rx_ring->next_to_clean;
	rx_desc = E1000_RX_DESC(*rx_ring, i);
	buffer_info = &rx_ring->buffer_info[i];
	
	while (rx_desc->status & E1000_RXD_STAT_DD) {
		struct sk_buff *skb;
		u8 status;

#ifdef CONFIG_E1000_NAPI
		if (*work_done >= work_to_do)
			break;
		(*work_done)++;
#endif
		status = rx_desc->status;
		skb = buffer_info->skb;
		buffer_info->skb = NULL;

		prefetch(skb->data - NET_IP_ALIGN);

		if (++i == rx_ring->count) i = 0;
		next_rxd = E1000_RX_DESC(*rx_ring, i);
		prefetch(next_rxd);

		next_buffer = &rx_ring->buffer_info[i];

		cleaned = true;
		cleaned_count++;
		dma_unmap_single(pci_dev_to_dev(pdev),
		                 buffer_info->dma,
		                 adapter->rx_buffer_len,
		                 DMA_FROM_DEVICE);
		buffer_info->dma = 0;

		length = le16_to_cpu(rx_desc->length);

		/* !EOP means multiple descriptors were used to store a single
		 * packet, if thats the case we need to toss it.  In fact, we
		 * to toss every packet with the EOP bit clear and the next
		 * frame that _does_ have the EOP bit set, as it is by
		 * definition only a frame fragment
		 */
		if (unlikely(!(status & E1000_RXD_STAT_EOP)))
			adapter->flags |= E1000_FLAG_IS_DISCARDING;

		if (adapter->flags & E1000_FLAG_IS_DISCARDING) {
			/* All receives must fit into a single buffer */
			E1000_DBG("%s: Receive packet consumed multiple"
				  " buffers\n", netdev->name);
			/* recycle */
			buffer_info->skb = skb;
			if (status & E1000_RXD_STAT_EOP)
				adapter->flags &= ~E1000_FLAG_IS_DISCARDING;
			goto next_desc;
		}

		if (unlikely(rx_desc->errors & E1000_RXD_ERR_FRAME_ERR_MASK)) {
			u8 last_byte = *(skb->data + length - 1);
			if (TBI_ACCEPT(&adapter->hw, status,
			              rx_desc->errors, length, last_byte,
			              adapter->min_frame_size,
			              adapter->max_frame_size)) {
				spin_lock_irqsave(&adapter->stats_lock,
				                  irq_flags);
				e1000_tbi_adjust_stats_82543(&adapter->hw,
				                      &adapter->stats,
				                      length, skb->data,
				                      adapter->max_frame_size);
				spin_unlock_irqrestore(&adapter->stats_lock,
				                       irq_flags);
				length--;
			} else {
				/* recycle */
				buffer_info->skb = skb;
				goto next_desc;
			}
		}

		/* adjust length to remove Ethernet CRC, this must be
		 * done after the TBI_ACCEPT workaround above */
		length -= 4;

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += length;
		total_rx_packets++;

		/* code added for copybreak, this should improve
		 * performance for small packets with large amounts
		 * of reassembly being done in the stack */
		if (length < copybreak) {
			struct sk_buff *new_skb =
			    netdev_alloc_skb_ip_align(netdev, length);
			if (new_skb) {
				skb_copy_to_linear_data_offset(new_skb,
				                               -NET_IP_ALIGN,
				                               (skb->data -
				                                NET_IP_ALIGN),
				                               (length +
				                                NET_IP_ALIGN));
				/* save the skb in buffer_info as good */
				buffer_info->skb = skb;
				skb = new_skb;
			}
			/* else just continue with the old one */
		}
		/* end copybreak code */
		skb_put(skb, length);

		/* Receive Checksum Offload */
		e1000_rx_checksum(adapter,
				  (u32)(status) |
				  ((u32)(rx_desc->errors) << 24),
				  le16_to_cpu(rx_desc->csum), skb);

		e1000_receive_skb(adapter, status, rx_desc->special, skb);

		netdev->last_rx = jiffies;

next_desc:
		rx_desc->status = 0;

		/* return some buffers to hardware, one at a time is too slow */
		if (unlikely(cleaned_count >= E1000_RX_BUFFER_WRITE)) {
			adapter->alloc_rx_buf(adapter, rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		/* use prefetched values */
		rx_desc = next_rxd;
		buffer_info = next_buffer;
	}
	rx_ring->next_to_clean = i;

	cleaned_count = E1000_DESC_UNUSED(rx_ring);
	if (cleaned_count)
		adapter->alloc_rx_buf(adapter, rx_ring, cleaned_count);

	adapter->total_rx_packets += total_rx_packets;
	adapter->total_rx_bytes += total_rx_bytes;
	adapter->net_stats.rx_bytes += total_rx_bytes;
	adapter->net_stats.rx_packets += total_rx_packets;
	return cleaned;
}

#ifdef CONFIG_E1000_NAPI
/**
 * e1000_alloc_jumbo_rx_buffers - Replace used jumbo receive buffers
 * @adapter: address of board private structure
 * @rx_ring: pointer to receive ring structure
 * @cleaned_count: number of buffers to allocate this pass
 **/
static void e1000_alloc_jumbo_rx_buffers(struct e1000_adapter *adapter,
                                         struct e1000_rx_ring *rx_ring,
                                         int cleaned_count)
{
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_rx_desc *rx_desc;
	struct e1000_rx_buffer *buffer_info;
	struct sk_buff *skb;
	unsigned int i;
	unsigned int bufsz = 256 -
	                     NET_SKB_PAD /*for skb_reserve */ -
	                     NET_IP_ALIGN;

	i = rx_ring->next_to_use;
	buffer_info = &rx_ring->buffer_info[i];

	while (cleaned_count--) {
		skb = buffer_info->skb;
		if (skb) {
			skb_trim(skb, 0);
			goto check_page;
		}

		skb = netdev_alloc_skb_ip_align(netdev, bufsz);
		if (unlikely(!skb)) {
			/* Better luck next round */
			adapter->alloc_rx_buff_failed++;
			break;
		}

		/* Fix for errata 23, can't cross 64kB boundary */
		if (!e1000_check_64k_bound(adapter, skb->data, bufsz)) {
			struct sk_buff *oldskb = skb;
			DPRINTK(PROBE, ERR, "skb align check failed: %u bytes "
					     "at %p\n", bufsz, skb->data);
			/* Try again, without freeing the previous */
			skb = netdev_alloc_skb_ip_align(netdev, bufsz);
			/* Failed allocation, critical failure */
			if (!skb) {
				dev_kfree_skb(oldskb);
				adapter->alloc_rx_buff_failed++;
				break;
			}

			if (!e1000_check_64k_bound(adapter, skb->data, bufsz)) {
				/* give up */
				dev_kfree_skb(skb);
				dev_kfree_skb(oldskb);
				adapter->alloc_rx_buff_failed++;
				break; /* while !buffer_info->skb */
			}

			/* Use new allocation */
			dev_kfree_skb(oldskb);
		}

		buffer_info->skb = skb;
check_page:
		/* allocate a new page if necessary */
		if (!buffer_info->page) {
			buffer_info->page = alloc_page(GFP_ATOMIC);
			if (unlikely(!buffer_info->page)) {
				adapter->alloc_rx_buff_failed++;
				break;
			}
		}

		if (!buffer_info->dma)
			buffer_info->dma = dma_map_page(pci_dev_to_dev(pdev),
			                                buffer_info->page, 0,
			                                PAGE_SIZE,
			                                DMA_FROM_DEVICE);

		rx_desc = E1000_RX_DESC(*rx_ring, i);
		rx_desc->buffer_addr = cpu_to_le64(buffer_info->dma);

		if (unlikely(++i == rx_ring->count))
			i = 0;
		buffer_info = &rx_ring->buffer_info[i];
	}

	if (likely(rx_ring->next_to_use != i)) {
		rx_ring->next_to_use = i;
		if (unlikely(i-- == 0))
			i = (rx_ring->count - 1);

		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.  (Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64). */
		wmb();
		writel(i, adapter->hw.hw_addr + rx_ring->rdt);
	}
}
#endif /* NAPI */

/**
 * e1000_alloc_rx_buffers - Replace used receive buffers; legacy & extended
 * @adapter: address of board private structure
 **/
static void e1000_alloc_rx_buffers(struct e1000_adapter *adapter,
                                   struct e1000_rx_ring *rx_ring,
                                   int cleaned_count)
{
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_rx_desc *rx_desc;
	struct e1000_rx_buffer *buffer_info;
	struct sk_buff *skb;
	unsigned int i;
	unsigned int bufsz = adapter->rx_buffer_len;

#ifdef ENABLE_DNA
	if(adapter->dna.dna_enabled) {
	  alloc_dna_memory(adapter);
	  return;
	}
#endif

	i = rx_ring->next_to_use;
	buffer_info = &rx_ring->buffer_info[i];

	while (cleaned_count--) {
		skb = buffer_info->skb;
		if (skb) {
			skb_trim(skb, 0);
			goto map_skb;
		}

		skb = netdev_alloc_skb_ip_align(netdev, bufsz);
		if (unlikely(!skb)) {
			/* Better luck next round */
			adapter->alloc_rx_buff_failed++;
			break;
		}

		/* Fix for errata 23, can't cross 64kB boundary */
		if (!e1000_check_64k_bound(adapter, skb->data, bufsz)) {
			struct sk_buff *oldskb = skb;
			DPRINTK(RX_ERR, ERR, "skb align check failed: %u bytes "
					     "at %p\n", bufsz, skb->data);
			/* Try again, without freeing the previous */
			skb = netdev_alloc_skb_ip_align(netdev, bufsz);
			/* Failed allocation, critical failure */
			if (!skb) {
				dev_kfree_skb(oldskb);
				adapter->alloc_rx_buff_failed++;
				break;
			}

			if (!e1000_check_64k_bound(adapter, skb->data, bufsz)) {
				/* give up */
				dev_kfree_skb(skb);
				dev_kfree_skb(oldskb);
				adapter->alloc_rx_buff_failed++;
				break; /* while !buffer_info->skb */
			}

			/* Use new allocation */
			dev_kfree_skb(oldskb);
		}

		buffer_info->skb = skb;
map_skb:
		buffer_info->dma = dma_map_single(pci_dev_to_dev(pdev),
						  skb->data,
						  adapter->rx_buffer_len,
						  DMA_FROM_DEVICE);

		/* Fix for errata 23, can't cross 64kB boundary */
		if (!e1000_check_64k_bound(adapter,
					(void *)(unsigned long)buffer_info->dma,
					adapter->rx_buffer_len)) {
			DPRINTK(RX_ERR, ERR,
				"dma align check failed: %u bytes at %p\n",
				adapter->rx_buffer_len,
				(void *)(unsigned long)buffer_info->dma);
			dev_kfree_skb(skb);
			buffer_info->skb = NULL;

			dma_unmap_single(pci_dev_to_dev(pdev), buffer_info->dma,
					 adapter->rx_buffer_len,
					 DMA_FROM_DEVICE);
			buffer_info->dma = 0;

			adapter->alloc_rx_buff_failed++;
			break; /* while !buffer_info->skb */
		}
		rx_desc = E1000_RX_DESC(*rx_ring, i);
		rx_desc->buffer_addr = cpu_to_le64(buffer_info->dma);

		if (unlikely(++i == rx_ring->count))
			i = 0;
		buffer_info = &rx_ring->buffer_info[i];
	}

	if (likely(rx_ring->next_to_use != i)) {
		rx_ring->next_to_use = i;
		if (unlikely(i-- == 0))
			i = (rx_ring->count - 1);

		/* Force memory writes to complete before letting h/w
		 * know there are new descriptors to fetch.  (Only
		 * applicable for weak-ordered memory model archs,
		 * such as IA-64). */
		wmb();
		writel(i, adapter->hw.hw_addr + rx_ring->rdt);
	}
}

/**
 * e1000_smartspeed - Workaround for SmartSpeed on 82541 and 82547 controllers.
 * @adapter:
 **/
static void e1000_smartspeed(struct e1000_adapter *adapter)
{
	struct e1000_mac_info *mac = &adapter->hw.mac;
	struct e1000_phy_info *phy = &adapter->hw.phy;
	u16 phy_status;
	u16 phy_ctrl;

	if ((phy->type != e1000_phy_igp) || !mac->autoneg ||
	    !(phy->autoneg_advertised & ADVERTISE_1000_FULL))
		return;

	if (adapter->smartspeed == 0) {
		/* If Master/Slave config fault is asserted twice,
		 * we assume back-to-back */
		e1000_read_phy_reg(&adapter->hw, PHY_1000T_STATUS, &phy_status);
		if (!(phy_status & SR_1000T_MS_CONFIG_FAULT)) return;
		e1000_read_phy_reg(&adapter->hw, PHY_1000T_STATUS, &phy_status);
		if (!(phy_status & SR_1000T_MS_CONFIG_FAULT)) return;
		e1000_read_phy_reg(&adapter->hw, PHY_1000T_CTRL, &phy_ctrl);
		if (phy_ctrl & CR_1000T_MS_ENABLE) {
			phy_ctrl &= ~CR_1000T_MS_ENABLE;
			e1000_write_phy_reg(&adapter->hw, PHY_1000T_CTRL,
					    phy_ctrl);
			adapter->smartspeed++;
			if (!e1000_phy_setup_autoneg(&adapter->hw) &&
			   !e1000_read_phy_reg(&adapter->hw, PHY_CONTROL,
				   	       &phy_ctrl)) {
				phy_ctrl |= (MII_CR_AUTO_NEG_EN |
					     MII_CR_RESTART_AUTO_NEG);
				e1000_write_phy_reg(&adapter->hw, PHY_CONTROL,
						    phy_ctrl);
			}
		}
		return;
	} else if (adapter->smartspeed == E1000_SMARTSPEED_DOWNSHIFT) {
		/* If still no link, perhaps using 2/3 pair cable */
		e1000_read_phy_reg(&adapter->hw, PHY_1000T_CTRL, &phy_ctrl);
		phy_ctrl |= CR_1000T_MS_ENABLE;
		e1000_write_phy_reg(&adapter->hw, PHY_1000T_CTRL, phy_ctrl);
		if (!e1000_phy_setup_autoneg(&adapter->hw) &&
		   !e1000_read_phy_reg(&adapter->hw, PHY_CONTROL, &phy_ctrl)) {
			phy_ctrl |= (MII_CR_AUTO_NEG_EN |
				     MII_CR_RESTART_AUTO_NEG);
			e1000_write_phy_reg(&adapter->hw, PHY_CONTROL, phy_ctrl);
		}
	}
	/* Restart process after E1000_SMARTSPEED_MAX iterations */
	if (adapter->smartspeed++ == E1000_SMARTSPEED_MAX)
		adapter->smartspeed = 0;
}

/**
 * e1000_ioctl -
 * @netdev:
 * @ifreq:
 * @cmd:
 **/
static int e1000_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	switch (cmd) {
#ifdef SIOCGMIIPHY
	case SIOCGMIIPHY:
	case SIOCGMIIREG:
	case SIOCSMIIREG:
		return e1000_mii_ioctl(netdev, ifr, cmd);
#endif
#ifdef ETHTOOL_OPS_COMPAT
	case SIOCETHTOOL:
		return ethtool_ioctl(ifr);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

#ifdef SIOCGMIIPHY
/**
 * e1000_mii_ioctl -
 * @netdev:
 * @ifreq:
 * @cmd:
 **/
static int e1000_mii_ioctl(struct net_device *netdev, struct ifreq *ifr,
                           int cmd)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct mii_ioctl_data *data = if_mii(ifr);

	if (adapter->hw.phy.media_type != e1000_media_type_copper)
		return -EOPNOTSUPP;

	switch (cmd) {
	case SIOCGMIIPHY:
		data->phy_id = adapter->hw.phy.addr;
		break;
	case SIOCGMIIREG:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		switch (data->reg_num & 0x1F) {
		case MII_BMCR:
			data->val_out = adapter->phy_regs.bmcr;
			break;
		case MII_BMSR:
			data->val_out = adapter->phy_regs.bmsr;
			break;
		case MII_PHYSID1:
			data->val_out = (adapter->hw.phy.id >> 16);
			break;
		case MII_PHYSID2:
			data->val_out = (adapter->hw.phy.id & 0xFFFF);
			break;
		case MII_ADVERTISE:
			data->val_out = adapter->phy_regs.advertise;
			break;
		case MII_LPA:
			data->val_out = adapter->phy_regs.lpa;
			break;
		case MII_EXPANSION:
			data->val_out = adapter->phy_regs.expansion;
			break;
		case MII_CTRL1000:
			data->val_out = adapter->phy_regs.ctrl1000;
			break;
		case MII_STAT1000:
			data->val_out = adapter->phy_regs.stat1000;
			break;
		case MII_ESTATUS:
			data->val_out = adapter->phy_regs.estatus;
			break;
		default:
			return -EIO;
		}
		break;
	case SIOCSMIIREG:
	default:
		return -EOPNOTSUPP;
	}
	return E1000_SUCCESS;
}
#endif

void e1000_pci_set_mwi(struct e1000_hw *hw)
{
	struct e1000_adapter *adapter = hw->back;
	int ret_val = pci_set_mwi(adapter->pdev);

	if (ret_val)
		DPRINTK(PROBE, ERR, "Error in setting MWI\n");
}

void e1000_pci_clear_mwi(struct e1000_hw *hw)
{
	struct e1000_adapter *adapter = hw->back;

	pci_clear_mwi(adapter->pdev);
}

void e1000_read_pci_cfg(struct e1000_hw *hw, u32 reg, u16 *value)
{
	struct e1000_adapter *adapter = hw->back;

	pci_read_config_word(adapter->pdev, reg, value);
}

void e1000_write_pci_cfg(struct e1000_hw *hw, u32 reg, u16 *value)
{
	struct e1000_adapter *adapter = hw->back;

	pci_write_config_word(adapter->pdev, reg, *value);
}

s32 e1000_read_pcie_cap_reg(struct e1000_hw *hw, u32 reg, u16 *value)
{
	struct e1000_adapter *adapter = hw->back;
	u16 cap_offset;

	cap_offset = pci_find_capability(adapter->pdev, PCI_CAP_ID_EXP);
	if (!cap_offset)
		return -E1000_ERR_CONFIG;

	pci_read_config_word(adapter->pdev, cap_offset + reg, value);

	return E1000_SUCCESS;
}

#ifdef NETIF_F_HW_VLAN_TX
static void e1000_vlan_rx_register(struct net_device *netdev,
                                   struct vlan_group *grp)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	u32 ctrl, rctl;

	if (!test_bit(__E1000_DOWN, &adapter->state))
		e1000_irq_disable(adapter);
	adapter->vlgrp = grp;

	if (grp) {
		/* enable VLAN tag insert/strip */
		ctrl = E1000_READ_REG(&adapter->hw, E1000_CTRL);
		ctrl |= E1000_CTRL_VME;
		E1000_WRITE_REG(&adapter->hw, E1000_CTRL, ctrl);

		/* enable VLAN receive filtering */
		rctl = E1000_READ_REG(&adapter->hw, E1000_RCTL);
		if (!(netdev->flags & IFF_PROMISC))
			rctl |= E1000_RCTL_VFE;
		rctl &= ~E1000_RCTL_CFIEN;
		E1000_WRITE_REG(&adapter->hw, E1000_RCTL, rctl);
		e1000_update_mng_vlan(adapter);
	} else {
		/* disable VLAN tag insert/strip */
		ctrl = E1000_READ_REG(&adapter->hw, E1000_CTRL);
		ctrl &= ~E1000_CTRL_VME;
		E1000_WRITE_REG(&adapter->hw, E1000_CTRL, ctrl);

		/* disable VLAN filtering */
		rctl = E1000_READ_REG(&adapter->hw, E1000_RCTL);
		rctl &= ~E1000_RCTL_VFE;
		E1000_WRITE_REG(&adapter->hw, E1000_RCTL, rctl);
		if (adapter->mng_vlan_id !=
		    (u16)E1000_MNG_VLAN_NONE) {
			e1000_vlan_rx_kill_vid(netdev, adapter->mng_vlan_id);
			adapter->mng_vlan_id = E1000_MNG_VLAN_NONE;
		}
	}

	if (!test_bit(__E1000_DOWN, &adapter->state))
		e1000_irq_enable(adapter);
}

static void e1000_vlan_rx_add_vid(struct net_device *netdev, u16 vid)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	u32 vfta, index;
#ifndef HAVE_NETDEV_VLAN_FEATURES
	struct net_device *v_netdev;
#endif

	if ((adapter->hw.mng_cookie.status &
	     E1000_MNG_DHCP_COOKIE_STATUS_VLAN) &&
	    (vid == adapter->mng_vlan_id))
		return;
	/* add VID to filter table */
	index = (vid >> 5) & 0x7F;
	vfta = E1000_READ_REG_ARRAY(&adapter->hw, E1000_VFTA, index);
	vfta |= (1 << (vid & 0x1F));
	e1000_write_vfta(&adapter->hw, index, vfta);

#ifndef HAVE_NETDEV_VLAN_FEATURES

	/* Copy feature flags from netdev to the vlan netdev for this vid.
	 * This allows things like TSO to bubble down to our vlan device.
	 */
	if (adapter->vlgrp) {
		v_netdev = vlan_group_get_device(adapter->vlgrp, vid);
		if (v_netdev) {
			v_netdev->features |= adapter->netdev->features;
			vlan_group_set_device(adapter->vlgrp, vid, v_netdev);
		}
	}
#endif
}

static void e1000_vlan_rx_kill_vid(struct net_device *netdev, u16 vid)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	u32 vfta, index;

	if (!test_bit(__E1000_DOWN, &adapter->state))
		e1000_irq_disable(adapter);
	vlan_group_set_device(adapter->vlgrp, vid, NULL);
	if (!test_bit(__E1000_DOWN, &adapter->state))
		e1000_irq_enable(adapter);

	/* remove VID from filter table */
	index = (vid >> 5) & 0x7F;
	vfta = E1000_READ_REG_ARRAY(&adapter->hw, E1000_VFTA, index);
	vfta &= ~(1 << (vid & 0x1F));
	e1000_write_vfta(&adapter->hw, index, vfta);
}

static void e1000_restore_vlan(struct e1000_adapter *adapter)
{
	e1000_vlan_rx_register(adapter->netdev, adapter->vlgrp);

	if (adapter->vlgrp) {
		u16 vid;
		for (vid = 0; vid < VLAN_N_VID; vid++) {
			if (!vlan_group_get_device(adapter->vlgrp, vid))
				continue;
			e1000_vlan_rx_add_vid(adapter->netdev, vid);
		}
	}
}
#endif

int e1000_set_spd_dplx(struct e1000_adapter *adapter, u16 spddplx)
{
	struct e1000_mac_info *mac = &adapter->hw.mac;

	mac->autoneg = 0;

	/* Fiber NICs only allow 1000 gbps Full duplex */
	if ((adapter->hw.phy.media_type == e1000_media_type_fiber) &&
		spddplx != (SPEED_1000 + DUPLEX_FULL)) {
		DPRINTK(PROBE, ERR, "Unsupported Speed/Duplex configuration\n");
		return -EINVAL;
	}

	switch (spddplx) {
	case SPEED_10 + DUPLEX_HALF:
		mac->forced_speed_duplex = ADVERTISE_10_HALF;
		break;
	case SPEED_10 + DUPLEX_FULL:
		mac->forced_speed_duplex = ADVERTISE_10_FULL;
		break;
	case SPEED_100 + DUPLEX_HALF:
		mac->forced_speed_duplex = ADVERTISE_100_HALF;
		break;
	case SPEED_100 + DUPLEX_FULL:
		mac->forced_speed_duplex = ADVERTISE_100_FULL;
		break;
	case SPEED_1000 + DUPLEX_FULL:
		mac->autoneg = 1;
		adapter->hw.phy.autoneg_advertised = ADVERTISE_1000_FULL;
		break;
	case SPEED_1000 + DUPLEX_HALF: /* not supported */
	default:
		DPRINTK(PROBE, ERR, "Unsupported Speed/Duplex configuration\n");
		return -EINVAL;
	}
	return 0;
}

#ifdef USE_REBOOT_NOTIFIER
/* only want to do this for 2.4 kernels? */
static int e1000_notify_reboot(struct notifier_block *nb,
                               unsigned long event, void *p)
{
	struct pci_dev *pdev = NULL;

	switch (event) {
	case SYS_DOWN:
	case SYS_HALT:
	case SYS_POWER_OFF:
		while ((pdev = pci_find_device(PCI_ANY_ID, PCI_ANY_ID, pdev))) {
			if (pci_dev_driver(pdev) == &e1000_driver)
				e1000_suspend(pdev, PMSG_SUSPEND);
		}
	}
	return NOTIFY_DONE;
}
#endif

static int __e1000_shutdown(struct pci_dev *pdev, bool *enable_wake)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);
	u32 ctrl, ctrl_ext, rctl, status;
	u32 wufc = adapter->wol;
#ifdef CONFIG_PM
	int retval = 0;
#endif

	netif_device_detach(netdev);

	if (netif_running(netdev)) {
		WARN_ON(test_bit(__E1000_RESETTING, &adapter->state));
		e1000_down(adapter);
		e1000_free_irq(adapter);
	}

#ifdef CONFIG_PM
	retval = pci_save_state(pdev);
	if (retval)
		return retval;
#endif

	status = E1000_READ_REG(&adapter->hw, E1000_STATUS);
	if (status & E1000_STATUS_LU)
		wufc &= ~E1000_WUFC_LNKC;

	if (wufc) {
		e1000_setup_rctl(adapter);
		e1000_set_multi(netdev);

		/* turn on all-multi mode if wake on multicast is enabled */
		if (wufc & E1000_WUFC_MC) {
			rctl = E1000_READ_REG(&adapter->hw, E1000_RCTL);
			rctl |= E1000_RCTL_MPE;
			E1000_WRITE_REG(&adapter->hw, E1000_RCTL, rctl);
		}

		if (adapter->hw.mac.type >= e1000_82540) {
			ctrl = E1000_READ_REG(&adapter->hw, E1000_CTRL);
			/* advertise wake from D3Cold */
			#define E1000_CTRL_ADVD3WUC 0x00100000
			/* phy power management enable */
			#define E1000_CTRL_EN_PHY_PWR_MGMT 0x00200000
			ctrl |= E1000_CTRL_ADVD3WUC |
				E1000_CTRL_EN_PHY_PWR_MGMT;
			E1000_WRITE_REG(&adapter->hw, E1000_CTRL, ctrl);
		}

		if (adapter->hw.phy.media_type == e1000_media_type_fiber ||
		   adapter->hw.phy.media_type == e1000_media_type_internal_serdes) {
			/* keep the laser running in D3 */
			ctrl_ext = E1000_READ_REG(&adapter->hw, E1000_CTRL_EXT);
			ctrl_ext |= E1000_CTRL_EXT_SDP3_DATA;
			E1000_WRITE_REG(&adapter->hw, E1000_CTRL_EXT, ctrl_ext);
		}

		/* Allow time for pending master requests to run */
		e1000_disable_pcie_master(&adapter->hw);

		E1000_WRITE_REG(&adapter->hw, E1000_WUC, E1000_WUC_PME_EN);
		E1000_WRITE_REG(&adapter->hw, E1000_WUFC, wufc);
	} else {
		E1000_WRITE_REG(&adapter->hw, E1000_WUC, 0);
		E1000_WRITE_REG(&adapter->hw, E1000_WUFC, 0);
	}

	*enable_wake =!!wufc;

	e1000_release_manageability(adapter);

	/* make sure adapter isn't asleep if manageability is enabled */
	if (adapter->en_mng_pt)
		*enable_wake = true;

	pci_disable_device(pdev);

	return 0;
}

#if defined(CONFIG_PM) || defined(USE_REBOOT_NOTIFIER)
static int e1000_suspend(struct pci_dev *pdev, pm_message_t state)
{
	int retval;
	bool wake;

	retval = __e1000_shutdown(pdev, &wake);
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
#endif

#ifdef CONFIG_PM
static int e1000_resume(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);
	u32 err;

	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);
	pci_save_state(pdev);
	if ((err = pci_enable_device(pdev))) {
		printk(KERN_ERR "e1000: Cannot enable PCI device from suspend\n");
		return err;
	}
	pci_set_master(pdev);

	pci_enable_wake(pdev, PCI_D3hot, 0);
	pci_enable_wake(pdev, PCI_D3cold, 0);

	if (netif_running(netdev) && (err = e1000_request_irq(adapter)))
		return err;

	if (adapter->hw.phy.media_type == e1000_media_type_copper)
		e1000_power_up_phy(&adapter->hw);
	e1000_reset(adapter);
	E1000_WRITE_REG(&adapter->hw, E1000_WUS, ~0);

	e1000_init_manageability(adapter);

	if (netif_running(netdev))
		e1000_up(adapter);

	netif_device_attach(netdev);

	return 0;
}
#endif

#ifndef USE_REBOOT_NOTIFIER
static void e1000_shutdown(struct pci_dev *pdev)
{
	bool wake;

	__e1000_shutdown(pdev, &wake);

	if (system_state == SYSTEM_POWER_OFF) {
		pci_wake_from_d3(pdev, wake);
		pci_set_power_state(pdev, PCI_D3hot);
	}
}
#endif

#ifdef CONFIG_NET_POLL_CONTROLLER
/*
 * Polling 'interrupt' - used by things like netconsole to send skbs
 * without having to re-enable interrupts. It's not called while
 * the interrupt routine is executing.
 */
static void e1000_netpoll(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	disable_irq(adapter->pdev->irq);
	e1000_intr(adapter->pdev->irq, netdev);

	e1000_clean_tx_irq(adapter, adapter->tx_ring);
#ifndef CONFIG_E1000_NAPI
	adapter->clean_rx(adapter, adapter->rx_ring);
#endif
	enable_irq(adapter->pdev->irq);
}
#endif

#ifdef HAVE_PCI_ERS
/**
 * e1000_io_error_detected - called when PCI error is detected
 * @pdev: Pointer to PCI device
 * @state: The current pci connection state
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 */
static pci_ers_result_t e1000_io_error_detected(struct pci_dev *pdev,
                                                pci_channel_state_t state)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);

	netif_device_detach(netdev);

	if (netif_running(netdev))
		e1000_down(adapter);
	pci_disable_device(pdev);

	/* Request a slot slot reset. */
	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * e1000_io_slot_reset - called after the pci bus has been reset.
 * @pdev: Pointer to PCI device
 *
 * Restart the card from scratch, as if from a cold-boot. Implementation
 * resembles the first-half of the e1000_resume routine.
 */
static pci_ers_result_t e1000_io_slot_reset(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);

	if (pci_enable_device(pdev)) {
		printk(KERN_ERR "e1000: Cannot re-enable PCI device after reset.\n");
		return PCI_ERS_RESULT_DISCONNECT;
	}
	pci_set_master(pdev);

	pci_enable_wake(pdev, PCI_D3hot, 0);
	pci_enable_wake(pdev, PCI_D3cold, 0);

	e1000_reset(adapter);
	E1000_WRITE_REG(&adapter->hw, E1000_WUS, ~0);

	return PCI_ERS_RESULT_RECOVERED;
}

/**
 * e1000_io_resume - called when traffic can start flowing again.
 * @pdev: Pointer to PCI device
 *
 * This callback is called when the error recovery driver tells us that
 * its OK to resume normal operation. Implementation resembles the
 * second-half of the e1000_resume routine.
 */
static void e1000_io_resume(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);

	e1000_init_manageability(adapter);

	if (netif_running(netdev)) {
		if (e1000_up(adapter)) {
			printk("e1000: can't bring device back up after reset\n");
			return;
		}
	}

	netif_device_attach(netdev);
}
#endif /* HAVE_PCI_ERS */

/* e1000_main.c */
