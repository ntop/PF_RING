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
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#include "ixgbe.h"
#include "ixgbe_common.h"
#include "ixgbe_type.h"

#ifdef IXGBE_PROCFS
#ifndef IXGBE_SYSFS

#include <linux/module.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/device.h>
#include <linux/netdevice.h>

static struct proc_dir_entry *ixgbe_top_dir = NULL;

static struct net_device_stats *procfs_get_stats(struct net_device *netdev)
{
#ifndef HAVE_NETDEV_STATS_IN_NETDEV
	struct ixgbe_adapter *adapter;
#endif
	if (netdev == NULL)
		return NULL;

#ifdef HAVE_NETDEV_STATS_IN_NETDEV
	/* only return the current stats */
	return &netdev->stats;
#else
	adapter = netdev_priv(netdev);

	/* only return the current stats */
	return &adapter->net_stats;
#endif /* HAVE_NETDEV_STATS_IN_NETDEV */
}

bool ixgbe_thermal_present(struct ixgbe_adapter *adapter)
{
	s32 status;
	if (adapter == NULL)
		return false;
	status = ixgbe_init_thermal_sensor_thresh_generic(&(adapter->hw));
	if (status != 0)
		return false;

	return true;
}

static int ixgbe_fwbanner(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	return snprintf(page, count, "%s\n", adapter->eeprom_id);
}

static int ixgbe_porttype(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");
	return snprintf(page, count, "%d\n",
			test_bit(__IXGBE_DOWN, &adapter->state));
}

static int ixgbe_portspeed(char *page, char __always_unused **start,
			   off_t __always_unused off, int count,
			   int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	int speed = 0;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	switch (adapter->link_speed) {
	case IXGBE_LINK_SPEED_100_FULL:
		speed = 1;
		break;
	case IXGBE_LINK_SPEED_1GB_FULL:
		speed = 10;
		break;
	case IXGBE_LINK_SPEED_10GB_FULL:
		speed = 100;
		break;
	}
	return snprintf(page, count, "%d\n", speed);
}

static int ixgbe_wqlflag(char *page, char __always_unused **start,
			 off_t __always_unused off, int count,
			 int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	return snprintf(page, count, "%d\n", adapter->wol);
}

static int ixgbe_xflowctl(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct ixgbe_hw *hw;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(page, count, "error: no hw data\n");

	return snprintf(page, count, "%d\n", hw->fc.current_mode);
}

static int ixgbe_rxdrops(char *page, char __always_unused **start,
			 off_t __always_unused off, int count,
			 int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct net_device_stats *net_stats;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");
	net_stats  = procfs_get_stats(adapter->netdev);
	if (net_stats == NULL)
		return snprintf(page, count, "error: no net stats\n");

	return snprintf(page, count, "%lu\n",
			net_stats->rx_dropped);
}

static int ixgbe_rxerrors(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct net_device_stats *net_stats;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");
	net_stats  = procfs_get_stats(adapter->netdev);
	if (net_stats == NULL)
		return snprintf(page, count, "error: no net stats\n");

	return snprintf(page, count, "%lu\n", net_stats->rx_errors);
}

static int ixgbe_rxupacks(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(page, count, "error: no hw data\n");

	return snprintf(page, count, "%d\n", IXGBE_READ_REG(hw, IXGBE_TPR));
}

static int ixgbe_rxmpacks(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(page, count, "error: no hw data\n");

	return snprintf(page, count, "%d\n", IXGBE_READ_REG(hw, IXGBE_MPRC));
}

static int ixgbe_rxbpacks(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(page, count, "error: no hw data\n");

	return snprintf(page, count, "%d\n", IXGBE_READ_REG(hw, IXGBE_BPRC));
}

static int ixgbe_txupacks(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(page, count, "error: no hw data\n");

	return snprintf(page, count, "%d\n", IXGBE_READ_REG(hw, IXGBE_TPT));
}

static int ixgbe_txmpacks(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(page, count, "error: no hw data\n");

	return snprintf(page, count, "%d\n", IXGBE_READ_REG(hw, IXGBE_MPTC));
}

static int ixgbe_txbpacks(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(page, count, "error: no hw data\n");

	return snprintf(page, count, "%d\n", IXGBE_READ_REG(hw, IXGBE_BPTC));
}

static int ixgbe_txerrors(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct net_device_stats *net_stats;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");
	net_stats  = procfs_get_stats(adapter->netdev);
	if (net_stats == NULL)
		return snprintf(page, count, "error: no net stats\n");

	return snprintf(page, count, "%lu\n",
			net_stats->tx_errors);
}

static int ixgbe_txdrops(char *page, char __always_unused **start,
			 off_t __always_unused off, int count,
			 int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct net_device_stats *net_stats;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");
	net_stats  = procfs_get_stats(adapter->netdev);
	if (net_stats == NULL)
		return snprintf(page, count, "error: no net stats\n");

	return snprintf(page, count, "%lu\n",
			net_stats->tx_dropped);
}

static int ixgbe_rxframes(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct net_device_stats *net_stats;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");
	net_stats  = procfs_get_stats(adapter->netdev);
	if (net_stats == NULL)
		return snprintf(page, count, "error: no net stats\n");

	return snprintf(page, count, "%lu\n",
			net_stats->rx_packets);
}

static int ixgbe_rxbytes(char *page, char __always_unused **start,
			 off_t __always_unused off, int count,
			 int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct net_device_stats *net_stats;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");
	net_stats  = procfs_get_stats(adapter->netdev);
	if (net_stats == NULL)
		return snprintf(page, count, "error: no net stats\n");

	return snprintf(page, count, "%lu\n",
			net_stats->rx_bytes);
}

static int ixgbe_txframes(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct net_device_stats *net_stats;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");
	net_stats  = procfs_get_stats(adapter->netdev);
	if (net_stats == NULL)
		return snprintf(page, count, "error: no net stats\n");

	return snprintf(page, count, "%lu\n",
			net_stats->tx_packets);
}

static int ixgbe_txbytes(char *page, char __always_unused **start,
			 off_t __always_unused off, int count,
			 int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct net_device_stats *net_stats;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");
	net_stats  = procfs_get_stats(adapter->netdev);
	if (net_stats == NULL)
		return snprintf(page, count, "error: no net stats\n");

	return snprintf(page, count, "%lu\n",
			net_stats->tx_bytes);
}

static int ixgbe_linkstat(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	int bitmask = 0;
	u32 link_speed;
	bool link_up = false;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(page, count, "error: no hw data\n");

	if (!test_bit(__IXGBE_DOWN, &adapter->state))
		bitmask |= 1;

	if (hw->mac.ops.check_link)
		hw->mac.ops.check_link(hw, &link_speed, &link_up, false);
	else
		/* always assume link is up, if no check link function */
		link_up = true;
	if (link_up)
		bitmask |= 2;

	if (adapter->old_lsc != adapter->lsc_int) {
		bitmask |= 4;
		adapter->old_lsc = adapter->lsc_int;
	}

	return snprintf(page, count, "0x%X\n", bitmask);
}

static int ixgbe_funcid(char *page, char __always_unused **start,
			off_t __always_unused off, int count,
			int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct ixgbe_hw *hw;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(page, count, "error: no hw data\n");

	return snprintf(page, count, "0x%X\n", hw->bus.func);
}

static int ixgbe_funcvers(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void __always_unused *data)
{
	return snprintf(page, count, "%s\n", ixgbe_driver_version);
}

static int ixgbe_macburn(char *page, char __always_unused **start,
			 off_t __always_unused off, int count,
			 int __always_unused *eof, void *data)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(page, count, "error: no hw data\n");

	return snprintf(page, count, "0x%02X%02X%02X%02X%02X%02X\n",
		       (unsigned int)hw->mac.perm_addr[0],
		       (unsigned int)hw->mac.perm_addr[1],
		       (unsigned int)hw->mac.perm_addr[2],
		       (unsigned int)hw->mac.perm_addr[3],
		       (unsigned int)hw->mac.perm_addr[4],
		       (unsigned int)hw->mac.perm_addr[5]);
}

static int ixgbe_macadmn(char *page, char __always_unused **start,
			 off_t __always_unused off, int count,
			 int __always_unused *eof, void *data)
{
	struct ixgbe_hw *hw;
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(page, count, "error: no hw data\n");

	return snprintf(page, count, "0x%02X%02X%02X%02X%02X%02X\n",
		       (unsigned int)hw->mac.addr[0],
		       (unsigned int)hw->mac.addr[1],
		       (unsigned int)hw->mac.addr[2],
		       (unsigned int)hw->mac.addr[3],
		       (unsigned int)hw->mac.addr[4],
		       (unsigned int)hw->mac.addr[5]);
}

static int ixgbe_maclla1(char *page, char __always_unused **start,
			 off_t __always_unused off, int count,
			 int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct ixgbe_hw *hw;
	int rc;
	u16 eeprom_buff[6];
	u16 first_word = 0x37;
	const u16 word_count = ARRAY_SIZE(eeprom_buff);

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	hw = &adapter->hw;
	if (hw == NULL)
		return snprintf(page, count, "error: no hw data\n");

	rc = hw->eeprom.ops.read_buffer(hw, first_word, 1, &first_word);
	if (rc != 0)
		return snprintf(page, count, "error: reading pointer to the EEPROM\n");

	if (first_word != 0x0000 && first_word != 0xFFFF) {
		rc = hw->eeprom.ops.read_buffer(hw, first_word, word_count,
					eeprom_buff);
		if (rc != 0)
			return snprintf(page, count, "error: reading buffer\n");
	} else {
		memset(eeprom_buff, 0, sizeof(eeprom_buff));
	}

	switch (hw->bus.func) {
	case 0:
		return snprintf(page, count, "0x%04X%04X%04X\n",
				eeprom_buff[0],
				eeprom_buff[1],
				eeprom_buff[2]);
	case 1:
		return snprintf(page, count, "0x%04X%04X%04X\n",
				eeprom_buff[3],
				eeprom_buff[4],
				eeprom_buff[5]);
	}
	return snprintf(page, count, "unexpected port %d\n", hw->bus.func);
}

static int ixgbe_mtusize(char *page, char __always_unused **start,
			 off_t __always_unused off, int count,
			 int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct net_device *netdev;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");
	netdev = adapter->netdev;
	if (netdev == NULL)
		return snprintf(page, count, "error: no net device\n");

	return snprintf(page, count, "%d\n", netdev->mtu);
}

static int ixgbe_featflag(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	int bitmask = 0;
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct net_device *netdev;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");
	netdev = adapter->netdev;
	if (netdev == NULL)
		return snprintf(page, count, "error: no net device\n");
	if (adapter->netdev->features & NETIF_F_RXCSUM)
		bitmask |= 1;
	return snprintf(page, count, "%d\n", bitmask);
}

static int ixgbe_lsominct(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void __always_unused *data)
{
	return snprintf(page, count, "%d\n", 1);
}

static int ixgbe_prommode(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	struct net_device *netdev;

	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");
	netdev = adapter->netdev;
	if (netdev == NULL)
		return snprintf(page, count, "error: no net device\n");

	return snprintf(page, count, "%d\n",
			netdev->flags & IFF_PROMISC);
}

static int ixgbe_txdscqsz(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	return snprintf(page, count, "%d\n", adapter->tx_ring[0]->count);
}

static int ixgbe_rxdscqsz(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	return snprintf(page, count, "%d\n", adapter->rx_ring[0]->count);
}

static int ixgbe_rxqavg(char *page, char __always_unused **start,
			off_t __always_unused off, int count,
			int __always_unused *eof, void *data)
{
	int index;
	int diff = 0;
	u16 ntc;
	u16 ntu;
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	for (index = 0; index < adapter->num_rx_queues; index++) {
		ntc = adapter->rx_ring[index]->next_to_clean;
		ntu = adapter->rx_ring[index]->next_to_use;

		if (ntc >= ntu)
			diff += (ntc - ntu);
		else
			diff += (adapter->rx_ring[index]->count - ntu + ntc);
	}
	if (adapter->num_rx_queues <= 0)
		return snprintf(page, count,
				"can't calculate, number of queues %d\n",
				adapter->num_rx_queues);
	return snprintf(page, count, "%d\n", diff/adapter->num_rx_queues);
}

static int ixgbe_txqavg(char *page, char __always_unused **start,
			off_t __always_unused off, int count,
			int __always_unused *eof, void *data)
{
	int index;
	int diff = 0;
	u16 ntc;
	u16 ntu;
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	for (index = 0; index < adapter->num_tx_queues; index++) {
		ntc = adapter->tx_ring[index]->next_to_clean;
		ntu = adapter->tx_ring[index]->next_to_use;

		if (ntc >= ntu)
			diff += (ntc - ntu);
		else
			diff += (adapter->tx_ring[index]->count - ntu + ntc);
	}
	if (adapter->num_tx_queues <= 0)
		return snprintf(page, count,
				"can't calculate, number of queues %d\n",
				adapter->num_tx_queues);
	return snprintf(page, count, "%d\n",
			diff/adapter->num_tx_queues);
}

static int ixgbe_iovotype(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void __always_unused *data)
{
	return snprintf(page, count, "2\n");
}

static int ixgbe_funcnbr(char *page, char __always_unused **start,
			 off_t __always_unused off, int count,
			 int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	return snprintf(page, count, "%d\n", adapter->num_vfs);
}

static int ixgbe_pciebnbr(char *page, char __always_unused **start,
			  off_t __always_unused off, int count,
			  int __always_unused *eof, void *data)
{
	struct ixgbe_adapter *adapter = (struct ixgbe_adapter *)data;
	if (adapter == NULL)
		return snprintf(page, count, "error: no adapter\n");

	return snprintf(page, count, "%d\n", adapter->pdev->bus->number);
}

static int ixgbe_therm_location(char *page, char __always_unused **start,
				off_t __always_unused off, int count,
				int __always_unused *eof, void *data)
{
	struct ixgbe_therm_proc_data *therm_data =
		(struct ixgbe_therm_proc_data *)data;

	if (therm_data == NULL)
		return snprintf(page, count, "error: no therm_data\n");

	return snprintf(page, count, "%d\n", therm_data->sensor_data->location);
}


static int ixgbe_therm_maxopthresh(char *page, char __always_unused **start,
				   off_t __always_unused off, int count,
				   int __always_unused *eof, void *data)
{
	struct ixgbe_therm_proc_data *therm_data =
		(struct ixgbe_therm_proc_data *)data;

	if (therm_data == NULL)
		return snprintf(page, count, "error: no therm_data\n");

	return snprintf(page, count, "%d\n",
			therm_data->sensor_data->max_op_thresh);
}


static int ixgbe_therm_cautionthresh(char *page, char __always_unused **start,
				     off_t __always_unused off, int count,
				     int __always_unused *eof, void *data)
{
	struct ixgbe_therm_proc_data *therm_data =
		(struct ixgbe_therm_proc_data *)data;

	if (therm_data == NULL)
		return snprintf(page, count, "error: no therm_data\n");

	return snprintf(page, count, "%d\n",
			therm_data->sensor_data->caution_thresh);
}

static int ixgbe_therm_temp(char *page, char __always_unused **start,
			    off_t __always_unused off, int count,
			    int __always_unused *eof, void *data)
{
	s32 status;
	struct ixgbe_therm_proc_data *therm_data =
		(struct ixgbe_therm_proc_data *)data;

	if (therm_data == NULL)
		return snprintf(page, count, "error: no therm_data\n");

	status = ixgbe_get_thermal_sensor_data_generic(therm_data->hw);
	if (status != 0)
		snprintf(page, count, "error: status %d returned\n", status);

	return snprintf(page, count, "%d\n", therm_data->sensor_data->temp);
}


struct ixgbe_proc_type {
	char name[32];
	int (*read)(char*, char**, off_t, int, int*, void*);
};

struct ixgbe_proc_type ixgbe_proc_entries[] = {
	{"fwbanner", &ixgbe_fwbanner},
	{"porttype", &ixgbe_porttype},
	{"portspeed", &ixgbe_portspeed},
	{"wqlflag", &ixgbe_wqlflag},
	{"xflowctl", &ixgbe_xflowctl},
	{"rxdrops", &ixgbe_rxdrops},
	{"rxerrors", &ixgbe_rxerrors},
	{"rxupacks", &ixgbe_rxupacks},
	{"rxmpacks", &ixgbe_rxmpacks},
	{"rxbpacks", &ixgbe_rxbpacks},
	{"txdrops", &ixgbe_txdrops},
	{"txerrors", &ixgbe_txerrors},
	{"txupacks", &ixgbe_txupacks},
	{"txmpacks", &ixgbe_txmpacks},
	{"txbpacks", &ixgbe_txbpacks},
	{"rxframes", &ixgbe_rxframes},
	{"rxbytes", &ixgbe_rxbytes},
	{"txframes", &ixgbe_txframes},
	{"txbytes", &ixgbe_txbytes},
	{"linkstat", &ixgbe_linkstat},
	{"funcid", &ixgbe_funcid},
	{"funcvers", &ixgbe_funcvers},
	{"macburn", &ixgbe_macburn},
	{"macadmn", &ixgbe_macadmn},
	{"maclla1", &ixgbe_maclla1},
	{"mtusize", &ixgbe_mtusize},
	{"featflag", &ixgbe_featflag},
	{"lsominct", &ixgbe_lsominct},
	{"prommode", &ixgbe_prommode},
	{"txdscqsz", &ixgbe_txdscqsz},
	{"rxdscqsz", &ixgbe_rxdscqsz},
	{"txqavg", &ixgbe_txqavg},
	{"rxqavg", &ixgbe_rxqavg},
	{"iovotype", &ixgbe_iovotype},
	{"funcnbr", &ixgbe_funcnbr},
	{"pciebnbr", &ixgbe_pciebnbr},
	{"", NULL}
};

struct ixgbe_proc_type ixgbe_internal_entries[] = {
	{"location", &ixgbe_therm_location},
	{"temp", &ixgbe_therm_temp},
	{"cautionthresh", &ixgbe_therm_cautionthresh},
	{"maxopthresh", &ixgbe_therm_maxopthresh},
	{"", NULL}
};

void ixgbe_del_proc_entries(struct ixgbe_adapter *adapter)
{
	int index;
	int i;
	char buf[16];	/* much larger than the sensor number will ever be */

	if (ixgbe_top_dir == NULL)
		return;

	for (i = 0; i < IXGBE_MAX_SENSORS; i++) {
		if (adapter->therm_dir[i] == NULL)
			continue;

		for (index = 0; ; index++) {
			if (ixgbe_internal_entries[index].read == NULL)
				break;

			 remove_proc_entry(ixgbe_internal_entries[index].name,
					   adapter->therm_dir[i]);
		}
		snprintf(buf, sizeof(buf), "sensor_%d", i);
		remove_proc_entry(buf, adapter->info_dir);
	}

	if (adapter->info_dir != NULL) {
		for (index = 0; ; index++) {
			if (ixgbe_proc_entries[index].read == NULL)
				break;
			remove_proc_entry(ixgbe_proc_entries[index].name,
					  adapter->info_dir);
		}
		remove_proc_entry("info", adapter->eth_dir);
	}

	if (adapter->eth_dir != NULL)
		remove_proc_entry(pci_name(adapter->pdev), ixgbe_top_dir);
}

/* called from ixgbe_main.c */
void ixgbe_procfs_exit(struct ixgbe_adapter *adapter)
{
	ixgbe_del_proc_entries(adapter);
}

int ixgbe_procfs_topdir_init()
{
	ixgbe_top_dir = proc_mkdir("driver/ixgbe", NULL);
	if (ixgbe_top_dir == NULL)
		return -ENOMEM;

	return 0;
}

void ixgbe_procfs_topdir_exit()
{
	remove_proc_entry("driver/ixgbe", NULL);
}

/* called from ixgbe_main.c */
int ixgbe_procfs_init(struct ixgbe_adapter *adapter)
{
	int rc = 0;
	int index;
	int i;
	char buf[16];	/* much larger than the sensor number will ever be */

	adapter->eth_dir = NULL;
	adapter->info_dir = NULL;
	for (i = 0; i < IXGBE_MAX_SENSORS; i++)
		adapter->therm_dir[i] = NULL;

	if (ixgbe_top_dir == NULL) {
		rc = -ENOMEM;
		goto fail;
	}

	adapter->eth_dir = proc_mkdir(pci_name(adapter->pdev), ixgbe_top_dir);
	if (adapter->eth_dir == NULL) {
		rc = -ENOMEM;
		goto fail;
	}

	adapter->info_dir = proc_mkdir("info", adapter->eth_dir);
	if (adapter->info_dir == NULL) {
		rc = -ENOMEM;
		goto fail;
	}
	for (index = 0; ; index++) {
		if (ixgbe_proc_entries[index].read == NULL)
			break;
		if (!(create_proc_read_entry(ixgbe_proc_entries[index].name,
					   0444,
					   adapter->info_dir,
					   ixgbe_proc_entries[index].read,
					   adapter))) {

			rc = -ENOMEM;
			goto fail;
		}
	}
	if (ixgbe_thermal_present(adapter) == false)
		goto exit;

	for (i = 0; i < IXGBE_MAX_SENSORS; i++) {

		if (adapter->hw.mac.thermal_sensor_data.sensor[i].location ==
		    0)
			continue;

		snprintf(buf, sizeof(buf), "sensor_%d", i);
		adapter->therm_dir[i] = proc_mkdir(buf, adapter->info_dir);
		if (adapter->therm_dir[i] == NULL) {
			rc = -ENOMEM;
			goto fail;
		}
		for (index = 0; ; index++) {
			if (ixgbe_internal_entries[index].read == NULL)
				break;
			/*
			 * therm_data struct contains pointer the read func
			 * will be needing
			 */
			adapter->therm_data[i].hw = &adapter->hw;
			adapter->therm_data[i].sensor_data =
				&adapter->hw.mac.thermal_sensor_data.sensor[i];

			if (!(create_proc_read_entry(
					   ixgbe_internal_entries[index].name,
					   0444,
					   adapter->therm_dir[i],
					   ixgbe_internal_entries[index].read,
					   &adapter->therm_data[i]))) {
				rc = -ENOMEM;
				goto fail;
			}
		}
	}
	goto exit;

fail:
	ixgbe_del_proc_entries(adapter);
exit:
	return rc;
}

#endif /* !IXGBE_SYSFS */
#endif /* IXGBE_PROCFS */
