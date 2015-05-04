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

/* ethtool support for e1000 */

#include <linux/netdevice.h>

#ifdef SIOCETHTOOL
#include <linux/ethtool.h>

#include "e1000.h"
#include "e1000_82541.h"
#ifdef NETIF_F_HW_VLAN_TX
#include <linux/if_vlan.h>
#endif

#ifdef ETHTOOL_OPS_COMPAT
#include "kcompat_ethtool.c"
#endif

#ifdef ETHTOOL_GSTATS
struct e1000_stats {
	char stat_string[ETH_GSTRING_LEN];
	int sizeof_stat;
	int stat_offset;
};

#define E1000_STAT(m) sizeof(((struct e1000_adapter *)0)->m), \
		      offsetof(struct e1000_adapter, m)
static const struct e1000_stats e1000_gstrings_stats[] = {
	{ "rx_packets", E1000_STAT(stats.gprc) },
	{ "tx_packets", E1000_STAT(stats.gptc) },
	{ "rx_bytes", E1000_STAT(stats.gorc) },
	{ "tx_bytes", E1000_STAT(stats.gotc) },
	{ "rx_broadcast", E1000_STAT(stats.bprc) },
	{ "tx_broadcast", E1000_STAT(stats.bptc) },
	{ "rx_multicast", E1000_STAT(stats.mprc) },
	{ "tx_multicast", E1000_STAT(stats.mptc) },
	{ "rx_errors", E1000_STAT(net_stats.rx_errors) },
	{ "tx_errors", E1000_STAT(net_stats.tx_errors) },
	{ "tx_dropped", E1000_STAT(net_stats.tx_dropped) },
	{ "multicast", E1000_STAT(stats.mprc) },
	{ "collisions", E1000_STAT(stats.colc) },
	{ "rx_length_errors", E1000_STAT(net_stats.rx_length_errors) },
	{ "rx_over_errors", E1000_STAT(net_stats.rx_over_errors) },
	{ "rx_crc_errors", E1000_STAT(stats.crcerrs) },
	{ "rx_frame_errors", E1000_STAT(net_stats.rx_frame_errors) },
	{ "rx_no_buffer_count", E1000_STAT(stats.rnbc) },
	{ "rx_missed_errors", E1000_STAT(stats.mpc) },
	{ "tx_aborted_errors", E1000_STAT(stats.ecol) },
	{ "tx_carrier_errors", E1000_STAT(stats.tncrs) },
	{ "tx_fifo_errors", E1000_STAT(net_stats.tx_fifo_errors) },
	{ "tx_heartbeat_errors", E1000_STAT(net_stats.tx_heartbeat_errors) },
	{ "tx_window_errors", E1000_STAT(stats.latecol) },
	{ "tx_abort_late_coll", E1000_STAT(stats.latecol) },
	{ "tx_deferred_ok", E1000_STAT(stats.dc) },
	{ "tx_single_coll_ok", E1000_STAT(stats.scc) },
	{ "tx_multi_coll_ok", E1000_STAT(stats.mcc) },
	{ "tx_timeout_count", E1000_STAT(tx_timeout_count) },
	{ "tx_restart_queue", E1000_STAT(restart_queue) },
	{ "rx_long_length_errors", E1000_STAT(stats.roc) },
	{ "rx_short_length_errors", E1000_STAT(stats.ruc) },
	{ "rx_align_errors", E1000_STAT(stats.algnerrc) },
	{ "tx_tcp_seg_good", E1000_STAT(stats.tsctc) },
	{ "tx_tcp_seg_failed", E1000_STAT(stats.tsctfc) },
	{ "rx_flow_control_xon", E1000_STAT(stats.xonrxc) },
	{ "rx_flow_control_xoff", E1000_STAT(stats.xoffrxc) },
	{ "tx_flow_control_xon", E1000_STAT(stats.xontxc) },
	{ "tx_flow_control_xoff", E1000_STAT(stats.xofftxc) },
	{ "rx_long_byte_count", E1000_STAT(stats.gorc) },
	{ "rx_csum_offload_good", E1000_STAT(hw_csum_good) },
	{ "rx_csum_offload_errors", E1000_STAT(hw_csum_err) },
	{ "alloc_rx_buff_failed", E1000_STAT(alloc_rx_buff_failed) },
	{ "tx_smbus", E1000_STAT(stats.mgptc) },
	{ "rx_smbus", E1000_STAT(stats.mgprc) },
	{ "dropped_smbus", E1000_STAT(stats.mgpdc) },
};

#define E1000_QUEUE_STATS_LEN 0
#define E1000_GLOBAL_STATS_LEN	\
	sizeof(e1000_gstrings_stats) / sizeof(struct e1000_stats)
#define E1000_STATS_LEN (E1000_GLOBAL_STATS_LEN + E1000_QUEUE_STATS_LEN)
#endif /* ETHTOOL_GSTATS */
#ifdef ETHTOOL_TEST
static const char e1000_gstrings_test[][ETH_GSTRING_LEN] = {
	"Register test  (offline)", "Eeprom test    (offline)",
	"Interrupt test (offline)", "Loopback test  (offline)",
	"Link test   (on/offline)"
};
#define E1000_TEST_LEN sizeof(e1000_gstrings_test) / ETH_GSTRING_LEN
#endif /* ETHTOOL_TEST */

static int e1000_get_settings(struct net_device *netdev,
                              struct ethtool_cmd *ecmd)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 status;

	if (hw->phy.media_type == e1000_media_type_copper) {

		ecmd->supported = (SUPPORTED_10baseT_Half |
		                   SUPPORTED_10baseT_Full |
		                   SUPPORTED_100baseT_Half |
		                   SUPPORTED_100baseT_Full |
		                   SUPPORTED_1000baseT_Full|
		                   SUPPORTED_Autoneg |
		                   SUPPORTED_TP);
		if (hw->phy.type == e1000_phy_ife)
			ecmd->supported &= ~SUPPORTED_1000baseT_Full;
		ecmd->advertising = ADVERTISED_TP;

		if (hw->mac.autoneg == 1) {
			ecmd->advertising |= ADVERTISED_Autoneg;
			/* the e1000 autoneg seems to match ethtool nicely */
			ecmd->advertising |= hw->phy.autoneg_advertised;
		}

		ecmd->port = PORT_TP;
		ecmd->phy_address = hw->phy.addr;

		if (hw->mac.type == e1000_82543)
			ecmd->transceiver = XCVR_EXTERNAL;
		else
			ecmd->transceiver = XCVR_INTERNAL;

	} else {
		ecmd->supported   = (SUPPORTED_1000baseT_Full |
				     SUPPORTED_FIBRE |
				     SUPPORTED_Autoneg);

		ecmd->advertising = (ADVERTISED_1000baseT_Full |
				     ADVERTISED_FIBRE |
				     ADVERTISED_Autoneg);

		ecmd->port = PORT_FIBRE;

		if (hw->mac.type >= e1000_82545)
			ecmd->transceiver = XCVR_INTERNAL;
		else
			ecmd->transceiver = XCVR_EXTERNAL;
	}

	status = E1000_READ_REG(&adapter->hw, E1000_STATUS);

	if (status & E1000_STATUS_LU) {

		if ((status & E1000_STATUS_SPEED_1000) ||
		    hw->phy.media_type != e1000_media_type_copper)
			ecmd->speed = SPEED_1000;
		else if (status & E1000_STATUS_SPEED_100)
			ecmd->speed = SPEED_100;
		else
			ecmd->speed = SPEED_10;

		if ((status & E1000_STATUS_FD) ||
		    hw->phy.media_type != e1000_media_type_copper)
			ecmd->duplex = DUPLEX_FULL;
		else
			ecmd->duplex = DUPLEX_HALF;
	} else {
		ecmd->speed = -1;
		ecmd->duplex = -1;
	}

	ecmd->autoneg = ((hw->phy.media_type == e1000_media_type_fiber) ||
			 hw->mac.autoneg) ? AUTONEG_ENABLE : AUTONEG_DISABLE;
	return 0;
}

static int e1000_set_settings(struct net_device *netdev,
                              struct ethtool_cmd *ecmd)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;

	/* If speed is 1000, autoneg cannot be turned off */
	if ((ecmd->autoneg == 0) && (ecmd->speed == SPEED_1000) &&
	    (ecmd->duplex = DUPLEX_FULL))
		return -EINVAL;

	/* When SoL/IDER sessions are active, autoneg/speed/duplex
	 * cannot be changed */
	if (e1000_check_reset_block(hw)) {
		DPRINTK(DRV, ERR, "Cannot change link characteristics "
		        "when SoL/IDER is active.\n");
		return -EINVAL;
	}

	while (test_and_set_bit(__E1000_RESETTING, &adapter->state))
		msleep(1);

	if (ecmd->autoneg == AUTONEG_ENABLE) {
		hw->mac.autoneg = 1;
		if (hw->phy.media_type == e1000_media_type_fiber)
			hw->phy.autoneg_advertised = ADVERTISED_1000baseT_Full |
			                             ADVERTISED_FIBRE |
			                             ADVERTISED_Autoneg;
		else
			hw->phy.autoneg_advertised = ecmd->advertising |
			                             ADVERTISED_TP |
			                             ADVERTISED_Autoneg;
		ecmd->advertising = hw->phy.autoneg_advertised;
		if (adapter->fc_autoneg)
			hw->fc.requested_mode = e1000_fc_default;
	} else {
		if (e1000_set_spd_dplx(adapter, ecmd->speed + ecmd->duplex)) {
			clear_bit(__E1000_RESETTING, &adapter->state);
			return -EINVAL;
		}
	}

	/* reset the link */

	if (netif_running(adapter->netdev)) {
		e1000_down(adapter);
		e1000_up(adapter);
	} else {
		e1000_reset(adapter);
	}

	clear_bit(__E1000_RESETTING, &adapter->state);
	return 0;
}

static u32 e1000_get_link(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_mac_info *mac = &adapter->hw.mac;

	/*
	 * If the link is not reported up to netdev, interrupts are disabled,
	 * and so the physical link state may have changed since we last
	 * looked. Set get_link_status to make sure that the true link
	 * state is interrogated, rather than pulling a cached and possibly
	 * stale link state from the driver.
	 */
	if (!netif_carrier_ok(netdev))
		mac->get_link_status = 1;

	return e1000_has_link(adapter);
}

static void e1000_get_pauseparam(struct net_device *netdev,
                                 struct ethtool_pauseparam *pause)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;

	pause->autoneg =
		(adapter->fc_autoneg ? AUTONEG_ENABLE : AUTONEG_DISABLE);

	if (hw->fc.current_mode == e1000_fc_rx_pause)
		pause->rx_pause = 1;
	else if (hw->fc.current_mode == e1000_fc_tx_pause)
		pause->tx_pause = 1;
	else if (hw->fc.current_mode == e1000_fc_full) {
		pause->rx_pause = 1;
		pause->tx_pause = 1;
	}
}

static int e1000_set_pauseparam(struct net_device *netdev,
                                struct ethtool_pauseparam *pause)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	int retval = 0;

	adapter->fc_autoneg = pause->autoneg;

	while (test_and_set_bit(__E1000_RESETTING, &adapter->state))
		msleep(1);

	if (pause->rx_pause && pause->tx_pause)
		hw->fc.current_mode = e1000_fc_full;
	else if (pause->rx_pause && !pause->tx_pause)
		hw->fc.current_mode = e1000_fc_rx_pause;
	else if (!pause->rx_pause && pause->tx_pause)
		hw->fc.current_mode = e1000_fc_tx_pause;
	else if (!pause->rx_pause && !pause->tx_pause)
		hw->fc.current_mode = e1000_fc_none;

	hw->fc.requested_mode = hw->fc.current_mode;

	if (adapter->fc_autoneg == AUTONEG_ENABLE) {
		hw->fc.current_mode = e1000_fc_default;
		if (netif_running(adapter->netdev)) {
			e1000_down(adapter);
			e1000_up(adapter);
		} else {
			e1000_reset(adapter);
		}
	} else {
		retval = ((hw->phy.media_type == e1000_media_type_fiber) ?
			  e1000_setup_link(hw) : e1000_force_mac_fc(hw));
	}

	clear_bit(__E1000_RESETTING, &adapter->state);
	return retval;
}

static u32 e1000_get_rx_csum(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	return adapter->rx_csum;
}

static int e1000_set_rx_csum(struct net_device *netdev, u32 data)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	adapter->rx_csum = data;

	if (netif_running(netdev))
		e1000_reinit_locked(adapter);
	else
		e1000_reset(adapter);
	return 0;
}

static u32 e1000_get_tx_csum(struct net_device *netdev)
{
	return (netdev->features & NETIF_F_HW_CSUM) != 0;
}

static int e1000_set_tx_csum(struct net_device *netdev, u32 data)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	if (adapter->hw.mac.type < e1000_82543) {
		if (!data)
			return -EINVAL;
		return 0;
	}

	if (data)
		netdev->features |= NETIF_F_HW_CSUM;
	else
		netdev->features &= ~NETIF_F_HW_CSUM;

	return 0;
}

#ifdef NETIF_F_TSO
static int e1000_set_tso(struct net_device *netdev, u32 data)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
#ifndef HAVE_NETDEV_VLAN_FEATURES
	int i;
	struct net_device *v_netdev;
#endif
	if (!(adapter->flags & E1000_FLAG_HAS_TSO))
		return data ? -EINVAL : 0;

	if (data) {
		netdev->features |= NETIF_F_TSO;
	} else {
		netdev->features &= ~NETIF_F_TSO;
#ifndef HAVE_NETDEV_VLAN_FEATURES
#ifdef NETIF_F_HW_VLAN_TX
		/* disable TSO on all VLANs if they're present */
		if (!adapter->vlgrp)
			goto tso_out;
		for (i = 0; i < VLAN_GROUP_ARRAY_LEN; i++) {
			v_netdev = vlan_group_get_device(adapter->vlgrp, i);
			if (!v_netdev)
				continue;

			v_netdev->features &= ~NETIF_F_TSO;
			vlan_group_set_device(adapter->vlgrp, i, v_netdev);
		}
#endif
#endif
	}
#ifndef HAVE_NETDEV_VLAN_FEATURES
#ifdef NETIF_F_HW_VLAN_TX
tso_out:
#endif
#endif
	DPRINTK(PROBE, INFO, "TSO is %s\n", data ? "Enabled" : "Disabled");
	adapter->flags |= E1000_FLAG_TSO_FORCE;
	return 0;
}
#endif /* NETIF_F_TSO */

static u32 e1000_get_msglevel(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	return adapter->msg_enable;
}

static void e1000_set_msglevel(struct net_device *netdev, u32 data)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	adapter->msg_enable = data;
}

static int e1000_get_regs_len(struct net_device *netdev)
{
#define E1000_REGS_LEN 32
	return E1000_REGS_LEN * sizeof(u32);
}

static void e1000_get_regs(struct net_device *netdev,
                           struct ethtool_regs *regs, void *p)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 *regs_buff = p;
	u16 phy_data;

	memset(p, 0, E1000_REGS_LEN * sizeof(u32));

	regs->version = (1 << 24) | (hw->revision_id << 16) | hw->device_id;

	regs_buff[0]  = E1000_READ_REG(hw, E1000_CTRL);
	regs_buff[1]  = E1000_READ_REG(hw, E1000_STATUS);

	regs_buff[2]  = E1000_READ_REG(hw, E1000_RCTL);
	regs_buff[3]  = E1000_READ_REG(hw, E1000_RDLEN(0));
	regs_buff[4]  = E1000_READ_REG(hw, E1000_RDH(0));
	regs_buff[5]  = E1000_READ_REG(hw, E1000_RDT(0));
	regs_buff[6]  = E1000_READ_REG(hw, E1000_RDTR);

	regs_buff[7]  = E1000_READ_REG(hw, E1000_TCTL);
	regs_buff[8]  = E1000_READ_REG(hw, E1000_TDLEN(0));
	regs_buff[9]  = E1000_READ_REG(hw, E1000_TDH(0));
	regs_buff[10] = E1000_READ_REG(hw, E1000_TDT(0));
	regs_buff[11] = E1000_READ_REG(hw, E1000_TIDV);

	regs_buff[12] = adapter->hw.phy.type;  /* PHY type (IGP=1, M88=0) */
	if (hw->phy.type == e1000_phy_igp) {
		e1000_write_phy_reg(hw, IGP01E1000_PHY_PAGE_SELECT,
				    IGP01E1000_PHY_AGC_A);
		e1000_read_phy_reg(hw, IGP01E1000_PHY_AGC_A &
				   IGP01E1000_PHY_PAGE_SELECT, &phy_data);
		regs_buff[13] = (u32)phy_data; /* cable length */
		e1000_write_phy_reg(hw, IGP01E1000_PHY_PAGE_SELECT,
				    IGP01E1000_PHY_AGC_B);
		e1000_read_phy_reg(hw, IGP01E1000_PHY_AGC_B &
				   IGP01E1000_PHY_PAGE_SELECT, &phy_data);
		regs_buff[14] = (u32)phy_data; /* cable length */
		e1000_write_phy_reg(hw, IGP01E1000_PHY_PAGE_SELECT,
				    IGP01E1000_PHY_AGC_C);
		e1000_read_phy_reg(hw, IGP01E1000_PHY_AGC_C &
				   IGP01E1000_PHY_PAGE_SELECT, &phy_data);
		regs_buff[15] = (u32)phy_data; /* cable length */
		e1000_write_phy_reg(hw, IGP01E1000_PHY_PAGE_SELECT,
				    IGP01E1000_PHY_AGC_D);
		e1000_read_phy_reg(hw, IGP01E1000_PHY_AGC_D &
				   IGP01E1000_PHY_PAGE_SELECT, &phy_data);
		regs_buff[16] = (u32)phy_data; /* cable length */
		regs_buff[17] = 0; /* extended 10bt distance (not needed) */
		e1000_write_phy_reg(hw, IGP01E1000_PHY_PAGE_SELECT, 0x0);
		e1000_read_phy_reg(hw, IGP01E1000_PHY_PORT_STATUS &
				   IGP01E1000_PHY_PAGE_SELECT, &phy_data);
		regs_buff[18] = (u32)phy_data; /* cable polarity */
		e1000_write_phy_reg(hw, IGP01E1000_PHY_PAGE_SELECT,
				    IGP01E1000_PHY_PCS_INIT_REG);
		e1000_read_phy_reg(hw, IGP01E1000_PHY_PCS_INIT_REG &
				   IGP01E1000_PHY_PAGE_SELECT, &phy_data);
		regs_buff[19] = (u32)phy_data; /* cable polarity */
		regs_buff[20] = 0; /* polarity correction enabled (always) */
		regs_buff[22] = 0; /* phy receive errors (unavailable) */
		regs_buff[23] = regs_buff[18]; /* mdix mode */
		e1000_write_phy_reg(hw, IGP01E1000_PHY_PAGE_SELECT, 0x0);
	} else {
		e1000_read_phy_reg(hw, M88E1000_PHY_SPEC_STATUS, &phy_data);
		regs_buff[13] = (u32)phy_data; /* cable length */
		regs_buff[14] = 0;  /* Dummy (to align w/ IGP phy reg dump) */
		regs_buff[15] = 0;  /* Dummy (to align w/ IGP phy reg dump) */
		regs_buff[16] = 0;  /* Dummy (to align w/ IGP phy reg dump) */
		e1000_read_phy_reg(hw, M88E1000_PHY_SPEC_CTRL, &phy_data);
		regs_buff[17] = (u32)phy_data; /* extended 10bt distance */
		regs_buff[18] = regs_buff[13]; /* cable polarity */
		regs_buff[19] = 0;  /* Dummy (to align w/ IGP phy reg dump) */
		regs_buff[20] = regs_buff[17]; /* polarity correction */
		/* phy receive errors */
		regs_buff[22] = adapter->phy_stats.receive_errors;
		regs_buff[23] = regs_buff[13]; /* mdix mode */
	}
	regs_buff[21] = adapter->phy_stats.idle_errors;  /* phy idle errors */
	e1000_read_phy_reg(hw, PHY_1000T_STATUS, &phy_data);
	regs_buff[24] = (u32)phy_data;  /* phy local receiver status */
	regs_buff[25] = regs_buff[24];  /* phy remote receiver status */
	if (hw->mac.type >= e1000_82540 &&
	    hw->phy.media_type == e1000_media_type_copper) {
		regs_buff[26] = E1000_READ_REG(hw, E1000_MANC);
	}
}

static int e1000_get_eeprom_len(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	return adapter->hw.nvm.word_size * 2;
}

static int e1000_get_eeprom(struct net_device *netdev,
                            struct ethtool_eeprom *eeprom, u8 *bytes)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u16 *eeprom_buff;
	int first_word, last_word;
	int ret_val = 0;
	u16 i;

	if (eeprom->len == 0)
		return -EINVAL;

	eeprom->magic = hw->vendor_id | (hw->device_id << 16);

	first_word = eeprom->offset >> 1;
	last_word = (eeprom->offset + eeprom->len - 1) >> 1;

	eeprom_buff = kmalloc(sizeof(u16) *
			(last_word - first_word + 1), GFP_KERNEL);
	if (!eeprom_buff)
		return -ENOMEM;

	if (hw->nvm.type == e1000_nvm_eeprom_spi)
		ret_val = e1000_read_nvm(hw, first_word,
		                         last_word - first_word + 1,
		                         eeprom_buff);
	else {
		for (i = 0; i < last_word - first_word + 1; i++)
			if ((ret_val = e1000_read_nvm(hw, first_word + i, 1,
			                              &eeprom_buff[i])))
				break;
	}

	/* Device's eeprom is always little-endian, word addressable */
	for (i = 0; i < last_word - first_word + 1; i++)
		le16_to_cpus(&eeprom_buff[i]);

	memcpy(bytes, (u8 *)eeprom_buff + (eeprom->offset & 1),
			eeprom->len);
	kfree(eeprom_buff);

	return ret_val;
}

static int e1000_set_eeprom(struct net_device *netdev,
                            struct ethtool_eeprom *eeprom, u8 *bytes)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u16 *eeprom_buff;
	void *ptr;
	int max_len, first_word, last_word, ret_val = 0;
	u16 i;

	if (eeprom->len == 0)
		return -EOPNOTSUPP;

	if (eeprom->magic != (hw->vendor_id | (hw->device_id << 16)))
		return -EFAULT;

	max_len = hw->nvm.word_size * 2;

	first_word = eeprom->offset >> 1;
	last_word = (eeprom->offset + eeprom->len - 1) >> 1;
	eeprom_buff = kmalloc(max_len, GFP_KERNEL);
	if (!eeprom_buff)
		return -ENOMEM;

	ptr = (void *)eeprom_buff;

	if (eeprom->offset & 1) {
		/* need read/modify/write of first changed EEPROM word */
		/* only the second byte of the word is being modified */
		ret_val = e1000_read_nvm(hw, first_word, 1,
					    &eeprom_buff[0]);
		ptr++;
	}
	if (((eeprom->offset + eeprom->len) & 1) && (ret_val == 0)) {
		/* need read/modify/write of last changed EEPROM word */
		/* only the first byte of the word is being modified */
		ret_val = e1000_read_nvm(hw, last_word, 1,
		                  &eeprom_buff[last_word - first_word]);
	}

	/* Device's eeprom is always little-endian, word addressable */
	for (i = 0; i < last_word - first_word + 1; i++)
		le16_to_cpus(&eeprom_buff[i]);

	memcpy(ptr, bytes, eeprom->len);

	for (i = 0; i < last_word - first_word + 1; i++)
		eeprom_buff[i] = cpu_to_le16(eeprom_buff[i]);

	ret_val = e1000_write_nvm(hw, first_word,
	                          last_word - first_word + 1, eeprom_buff);

	/* Update the checksum over the first part of the EEPROM if needed */
	if ((ret_val == 0) && (first_word <= NVM_CHECKSUM_REG))
		e1000_update_nvm_checksum(hw);

	kfree(eeprom_buff);
	return ret_val;
}

static void e1000_get_drvinfo(struct net_device *netdev,
                              struct ethtool_drvinfo *drvinfo)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	strncpy(drvinfo->driver,  e1000_driver_name, 32);
	strncpy(drvinfo->version, e1000_driver_version, 32);
	strcpy(drvinfo->fw_version, "N/A");
	strncpy(drvinfo->bus_info, pci_name(adapter->pdev), 32);
	drvinfo->n_stats = E1000_STATS_LEN;
	drvinfo->testinfo_len = E1000_TEST_LEN;
	drvinfo->regdump_len = e1000_get_regs_len(netdev);
	drvinfo->eedump_len = e1000_get_eeprom_len(netdev);
}

static void e1000_get_ringparam(struct net_device *netdev,
                                struct ethtool_ringparam *ring)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	enum e1000_mac_type mac_type = adapter->hw.mac.type;
	struct e1000_tx_ring *tx_ring = adapter->tx_ring;
	struct e1000_rx_ring *rx_ring = adapter->rx_ring;

	ring->rx_max_pending = (mac_type < e1000_82544) ? E1000_MAX_RXD :
		E1000_MAX_82544_RXD;
	ring->tx_max_pending = (mac_type < e1000_82544) ? E1000_MAX_TXD :
		E1000_MAX_82544_TXD;
	ring->rx_mini_max_pending = 0;
	ring->rx_jumbo_max_pending = 0;
	ring->rx_pending = rx_ring->count;
	ring->tx_pending = tx_ring->count;
	ring->rx_mini_pending = 0;
	ring->rx_jumbo_pending = 0;
}

static int e1000_set_ringparam(struct net_device *netdev,
                               struct ethtool_ringparam *ring)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	enum e1000_mac_type mac_type = adapter->hw.mac.type;
	struct e1000_tx_ring *tx_ring, *tx_old;
	struct e1000_rx_ring *rx_ring, *rx_old;
	int err, tx_ring_size, rx_ring_size;

	if ((ring->rx_mini_pending) || (ring->rx_jumbo_pending))
		return -EINVAL;

	tx_ring_size = sizeof(struct e1000_tx_ring);
	rx_ring_size = sizeof(struct e1000_rx_ring);

	while (test_and_set_bit(__E1000_RESETTING, &adapter->state))
		msleep(1);

	if (netif_running(adapter->netdev))
		e1000_down(adapter);

	tx_old = adapter->tx_ring;
	rx_old = adapter->rx_ring;

	err = -ENOMEM;
	tx_ring = kzalloc(tx_ring_size, GFP_KERNEL);
	if (!tx_ring)
		goto err_alloc_tx;
	/* use a memcpy to save any previously configured
	 * items like napi structs from having to be
	 * reinitialized */
	memcpy(tx_ring, tx_old, tx_ring_size);

	rx_ring = kzalloc(rx_ring_size, GFP_KERNEL);
	if (!rx_ring)
		goto err_alloc_rx;
	memcpy(rx_ring, rx_old, rx_ring_size);

	adapter->tx_ring = tx_ring;
	adapter->rx_ring = rx_ring;

	rx_ring->count = max(ring->rx_pending,(u32)E1000_MIN_RXD);
	rx_ring->count = min(rx_ring->count,(u32)(mac_type < e1000_82544 ?
		E1000_MAX_RXD : E1000_MAX_82544_RXD));
	rx_ring->count = ALIGN(rx_ring->count, REQ_RX_DESCRIPTOR_MULTIPLE);

	tx_ring->count = max(ring->tx_pending,(u32)E1000_MIN_TXD);
	tx_ring->count = min(tx_ring->count,(u32)(mac_type < e1000_82544 ?
		E1000_MAX_TXD : E1000_MAX_82544_TXD));
	tx_ring->count = ALIGN(tx_ring->count, REQ_TX_DESCRIPTOR_MULTIPLE);

	if (netif_running(adapter->netdev)) {
		/* Try to get new resources before deleting old */
		if ((err = e1000_setup_all_rx_resources(adapter)))
			goto err_setup_rx;
		if ((err = e1000_setup_all_tx_resources(adapter)))
			goto err_setup_tx;

		/* restore the old in order to free it,
		 * then add in the new */
		adapter->rx_ring = rx_old;
		adapter->tx_ring = tx_old;
		e1000_free_all_rx_resources(adapter);
		e1000_free_all_tx_resources(adapter);
		kfree(tx_old);
		kfree(rx_old);
		adapter->rx_ring = rx_ring;
		adapter->tx_ring = tx_ring;
		if ((err = e1000_up(adapter)))
			goto err_setup;
	}

	clear_bit(__E1000_RESETTING, &adapter->state);
	return 0;
err_setup_tx:
	e1000_free_all_rx_resources(adapter);
err_setup_rx:
	adapter->rx_ring = rx_old;
	adapter->tx_ring = tx_old;
	kfree(rx_ring);
err_alloc_rx:
	kfree(tx_ring);
err_alloc_tx:
	e1000_up(adapter);
err_setup:
	clear_bit(__E1000_RESETTING, &adapter->state);
	return err;
}

static bool reg_pattern_test(struct e1000_adapter *adapter, u64 *data,
			     int reg, int offset, u32 mask, u32 write)
{
	u32 pat, val;
	static const u32 test[] =
		{0x5A5A5A5A, 0xA5A5A5A5, 0x00000000, 0xFFFFFFFF};
	for (pat = 0; pat < ARRAY_SIZE(test); pat++) {
		E1000_WRITE_REG_ARRAY(&adapter->hw, reg, offset,
		                      (test[pat] & write));
		val = E1000_READ_REG_ARRAY(&adapter->hw, reg, offset);
		if (val != (test[pat] & write & mask)) {
			DPRINTK(DRV, ERR, "pattern test reg %04X failed: got "
			        "0x%08X expected 0x%08X\n",
			        E1000_REGISTER(&adapter->hw, reg) + offset,
			        val, (test[pat] & write & mask));
			*data = E1000_REGISTER(&adapter->hw, reg);
			return 1;
		}
	}
	return 0;
}

static bool reg_set_and_check(struct e1000_adapter *adapter, u64 *data,
			      int reg, u32 mask, u32 write)
{
	u32 val;
	E1000_WRITE_REG(&adapter->hw, reg, write & mask);
	val = E1000_READ_REG(&adapter->hw, reg);
	if ((write & mask) != (val & mask)) {
		DPRINTK(DRV, ERR, "set/check reg %04X test failed: got 0x%08X"
		        "expected 0x%08X\n", reg, (val & mask), (write & mask));
		*data = E1000_REGISTER(&adapter->hw, reg);
		return 1;
	}
	return 0;
}
#define REG_PATTERN_TEST_ARRAY(reg, offset, mask, write)                       \
	do {                                                                   \
		if (reg_pattern_test(adapter, data, reg, offset, mask, write)) \
			return 1;                                              \
	} while (0)
#define REG_PATTERN_TEST(reg, mask, write)                                     \
	REG_PATTERN_TEST_ARRAY(reg, 0, mask, write)

#define REG_SET_AND_CHECK(reg, mask, write)                                    \
	do {                                                                   \
		if (reg_set_and_check(adapter, data, reg, mask, write))       \
			return 1;                                              \
	} while (0)

static int e1000_reg_test(struct e1000_adapter *adapter, u64 *data)
{
	struct e1000_mac_info *mac = &adapter->hw.mac;
	u32 value, before, after;
	u32 i, toggle;

	/* The status register is Read Only, so a write should fail.
	 * Some bits that get toggled are ignored.
	 */
	toggle = 0xFFFFF833;

	before = E1000_READ_REG(&adapter->hw, E1000_STATUS);
	value = (E1000_READ_REG(&adapter->hw, E1000_STATUS) & toggle);
	E1000_WRITE_REG(&adapter->hw, E1000_STATUS, toggle);
	after = E1000_READ_REG(&adapter->hw, E1000_STATUS) & toggle;
	if (value != after) {
		DPRINTK(DRV, ERR, "failed STATUS register test got: "
		        "0x%08X expected: 0x%08X\n", after, value);
		*data = 1;
		return 1;
	}
	/* restore previous status */
	E1000_WRITE_REG(&adapter->hw, E1000_STATUS, before);

	REG_PATTERN_TEST(E1000_FCAL, 0xFFFFFFFF, 0xFFFFFFFF);
	REG_PATTERN_TEST(E1000_FCAH, 0x0000FFFF, 0xFFFFFFFF);
	REG_PATTERN_TEST(E1000_FCT, 0x0000FFFF, 0xFFFFFFFF);
	REG_PATTERN_TEST(E1000_VET, 0x0000FFFF, 0xFFFFFFFF);
	REG_PATTERN_TEST(E1000_RDTR, 0x0000FFFF, 0xFFFFFFFF);
	REG_PATTERN_TEST(E1000_RDBAH(0), 0xFFFFFFFF, 0xFFFFFFFF);
	REG_PATTERN_TEST(E1000_RDLEN(0), 0x000FFF80, 0x000FFFFF);
	REG_PATTERN_TEST(E1000_RDH(0), 0x0000FFFF, 0x0000FFFF);
	REG_PATTERN_TEST(E1000_RDT(0), 0x0000FFFF, 0x0000FFFF);
	REG_PATTERN_TEST(E1000_FCRTH, 0x0000FFF8, 0x0000FFF8);
	REG_PATTERN_TEST(E1000_FCTTV, 0x0000FFFF, 0x0000FFFF);
	REG_PATTERN_TEST(E1000_TIPG, 0x3FFFFFFF, 0x3FFFFFFF);
	REG_PATTERN_TEST(E1000_TDBAH(0), 0xFFFFFFFF, 0xFFFFFFFF);
	REG_PATTERN_TEST(E1000_TDLEN(0), 0x000FFF80, 0x000FFFFF);

	REG_SET_AND_CHECK(E1000_RCTL, 0xFFFFFFFF, 0x00000000);

	before = 0x06DFB3FE;
	REG_SET_AND_CHECK(E1000_RCTL, before, 0x003FFFFB);
	REG_SET_AND_CHECK(E1000_TCTL, 0xFFFFFFFF, 0x00000000);

	if (mac->type >= e1000_82543) {

		REG_SET_AND_CHECK(E1000_RCTL, before, 0xFFFFFFFF);
		REG_PATTERN_TEST(E1000_RDBAL(0), 0xFFFFFFF0, 0xFFFFFFFF);
		REG_PATTERN_TEST(E1000_TXCW, 0xC000FFFF, 0x0000FFFF);
		REG_PATTERN_TEST(E1000_TDBAL(0), 0xFFFFFFF0, 0xFFFFFFFF);
		REG_PATTERN_TEST(E1000_TIDV, 0x0000FFFF, 0x0000FFFF);
		for (i = 0; i < mac->rar_entry_count; i++) {
			REG_PATTERN_TEST_ARRAY(E1000_RA, ((i << 1) + 1),
			                       0x8003FFFF, 0xFFFFFFFF);
		}

	} else {

		REG_SET_AND_CHECK(E1000_RCTL, 0xFFFFFFFF, 0x01FFFFFF);
		REG_PATTERN_TEST(E1000_RDBAL(0), 0xFFFFF000, 0xFFFFFFFF);
		REG_PATTERN_TEST(E1000_TXCW, 0x0000FFFF, 0x0000FFFF);
		REG_PATTERN_TEST(E1000_TDBAL(0), 0xFFFFF000, 0xFFFFFFFF);

	}

	for (i = 0; i < mac->mta_reg_count; i++)
		REG_PATTERN_TEST_ARRAY(E1000_MTA, i, 0xFFFFFFFF, 0xFFFFFFFF);

	*data = 0;
	return 0;
}

static int e1000_eeprom_test(struct e1000_adapter *adapter, u64 *data)
{
	u16 temp;
	u16 checksum = 0;
	u16 i;

	*data = 0;
	/* Read and add up the contents of the EEPROM */
	for (i = 0; i < (NVM_CHECKSUM_REG + 1); i++) {
		if ((e1000_read_nvm(&adapter->hw, i, 1, &temp)) < 0) {
			*data = 1;
			break;
		}
		checksum += temp;
	}

	/* If Checksum is not Correct return error else test passed */
	if ((checksum != (u16) NVM_SUM) && !(*data))
		*data = 2;

	return *data;
}

static irqreturn_t e1000_test_intr(int irq, void *data)
{
	struct net_device *netdev = (struct net_device *) data;
	struct e1000_adapter *adapter = netdev_priv(netdev);

	adapter->test_icr |= E1000_READ_REG(&adapter->hw, E1000_ICR);

	return IRQ_HANDLED;
}

static int e1000_intr_test(struct e1000_adapter *adapter, u64 *data)
{
	struct net_device *netdev = adapter->netdev;
	u32 mask, i=0, shared_int = true;
	u32 irq = adapter->pdev->irq;

	*data = 0;

	/* NOTE: we don't test MSI interrupts here, yet */
	/* Hook up test interrupt handler just for this test */
	if (!request_irq(irq, &e1000_test_intr, IRQF_PROBE_SHARED, netdev->name,
	                 netdev))
		shared_int = false;
	else if (request_irq(irq, &e1000_test_intr, IRQF_SHARED,
	         netdev->name, netdev)) {
		*data = 1;
		return -1;
	}
	DPRINTK(HW, INFO, "testing %s interrupt\n",
	        (shared_int ? "shared" : "unshared"));

	/* Disable all the interrupts */
	E1000_WRITE_REG(&adapter->hw, E1000_IMC, 0xFFFFFFFF);
	E1000_WRITE_FLUSH(&adapter->hw);
	msleep(10);

	/* Test each interrupt */
	for (; i < 10; i++) {

		/* Interrupt to test */
		mask = 1 << i;

		if (!shared_int) {
			/* Disable the interrupt to be reported in
			 * the cause register and then force the same
			 * interrupt and see if one gets posted.  If
			 * an interrupt was posted to the bus, the
			 * test failed.
			 */
			adapter->test_icr = 0;
			E1000_WRITE_REG(&adapter->hw, E1000_IMC, mask);
			E1000_WRITE_REG(&adapter->hw, E1000_ICS, mask);
			E1000_WRITE_FLUSH(&adapter->hw);
			msleep(10);

			if (adapter->test_icr & mask) {
				*data = 3;
				break;
			}
		}

		/* Enable the interrupt to be reported in
		 * the cause register and then force the same
		 * interrupt and see if one gets posted.  If
		 * an interrupt was not posted to the bus, the
		 * test failed.
		 */
		adapter->test_icr = 0;
		E1000_WRITE_REG(&adapter->hw, E1000_IMS, mask);
		E1000_WRITE_REG(&adapter->hw, E1000_ICS, mask);
		E1000_WRITE_FLUSH(&adapter->hw);
		msleep(10);

		if (!(adapter->test_icr & mask)) {
			*data = 4;
			break;
		}

		if (!shared_int) {
			/* Disable the other interrupts to be reported in
			 * the cause register and then force the other
			 * interrupts and see if any get posted.  If
			 * an interrupt was posted to the bus, the
			 * test failed.
			 */
			adapter->test_icr = 0;
			E1000_WRITE_REG(&adapter->hw, E1000_IMC,
			                ~mask & 0x00007FFF);
			E1000_WRITE_REG(&adapter->hw, E1000_ICS,
			                ~mask & 0x00007FFF);
			E1000_WRITE_FLUSH(&adapter->hw);
			msleep(10);

			if (adapter->test_icr) {
				*data = 5;
				break;
			}
		}
	}

	/* Disable all the interrupts */
	E1000_WRITE_REG(&adapter->hw, E1000_IMC, 0xFFFFFFFF);
	E1000_WRITE_FLUSH(&adapter->hw);
	msleep(10);

	/* Unhook test interrupt handler */
	free_irq(irq, netdev);

	return *data;
}

static void e1000_free_desc_rings(struct e1000_adapter *adapter)
{
	struct e1000_tx_ring *tx_ring = &adapter->test_tx_ring;
	struct e1000_rx_ring *rx_ring = &adapter->test_rx_ring;
	struct pci_dev *pdev = adapter->pdev;
	int i;

	if (tx_ring->desc && tx_ring->buffer_info) {
		for (i = 0; i < tx_ring->count; i++) {
			if (tx_ring->buffer_info[i].dma)
				dma_unmap_single(pci_dev_to_dev(pdev),
						 tx_ring->buffer_info[i].dma,
						 tx_ring->buffer_info[i].length,
						 DMA_TO_DEVICE);
			if (tx_ring->buffer_info[i].skb)
				dev_kfree_skb(tx_ring->buffer_info[i].skb);
		}
	}

	if (rx_ring->desc && rx_ring->buffer_info) {
		for (i = 0; i < rx_ring->count; i++) {
			if (rx_ring->buffer_info[i].dma)
				dma_unmap_single(pci_dev_to_dev(pdev),
						 rx_ring->buffer_info[i].dma,
						 E1000_RXBUFFER_2048,
						 DMA_FROM_DEVICE);
			if (rx_ring->buffer_info[i].skb)
				dev_kfree_skb(rx_ring->buffer_info[i].skb);
		}
	}

	if (tx_ring->desc) {
		dma_free_coherent(pci_dev_to_dev(pdev), tx_ring->size,
				  tx_ring->desc, tx_ring->dma);
		tx_ring->desc = NULL;
	}
	if (rx_ring->desc) {
		dma_free_coherent(pci_dev_to_dev(pdev), rx_ring->size,
				  rx_ring->desc, rx_ring->dma);
		rx_ring->desc = NULL;
	}

	kfree(tx_ring->buffer_info);
	tx_ring->buffer_info = NULL;
	kfree(rx_ring->buffer_info);
	rx_ring->buffer_info = NULL;

	return;
}

static int e1000_setup_desc_rings(struct e1000_adapter *adapter)
{
	struct e1000_tx_ring *tx_ring = &adapter->test_tx_ring;
	struct e1000_rx_ring *rx_ring = &adapter->test_rx_ring;
	struct pci_dev *pdev = adapter->pdev;
	u32 rctl;
	int i, ret_val;

	/* Setup Tx descriptor ring and Tx buffers */

	if (!tx_ring->count)
		tx_ring->count = E1000_DEFAULT_TXD;

	if (!(tx_ring->buffer_info = kcalloc(tx_ring->count,
	                                     sizeof(struct e1000_buffer),
	                                     GFP_KERNEL))) {
		ret_val = 1;
		goto err_nomem;
	}

	tx_ring->size = tx_ring->count * sizeof(struct e1000_tx_desc);
	tx_ring->size = ALIGN(tx_ring->size, 4096);
	if (!(tx_ring->desc = dma_alloc_coherent(pci_dev_to_dev(pdev),
						 tx_ring->size, &tx_ring->dma,
						 GFP_KERNEL))) {
		ret_val = 2;
		goto err_nomem;
	}
	tx_ring->next_to_use = tx_ring->next_to_clean = 0;

	E1000_WRITE_REG(&adapter->hw, E1000_TDBAL(0),
			((u64) tx_ring->dma & 0x00000000FFFFFFFF));
	E1000_WRITE_REG(&adapter->hw, E1000_TDBAH(0), ((u64) tx_ring->dma >> 32));
	E1000_WRITE_REG(&adapter->hw, E1000_TDLEN(0),
			tx_ring->count * sizeof(struct e1000_tx_desc));
	E1000_WRITE_REG(&adapter->hw, E1000_TDH(0), 0);
	E1000_WRITE_REG(&adapter->hw, E1000_TDT(0), 0);
	E1000_WRITE_REG(&adapter->hw, E1000_TCTL,
			E1000_TCTL_MULR |
			E1000_TCTL_PSP | E1000_TCTL_EN |
			E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT |
			E1000_COLLISION_DISTANCE << E1000_COLD_SHIFT);

	for (i = 0; i < tx_ring->count; i++) {
		struct e1000_tx_desc *tx_desc = E1000_TX_DESC(*tx_ring, i);
		struct sk_buff *skb;
		unsigned int size = 1024;

		if (!(skb = alloc_skb(size, GFP_KERNEL))) {
			ret_val = 3;
			goto err_nomem;
		}
		skb_put(skb, size);
		tx_ring->buffer_info[i].skb = skb;
		tx_ring->buffer_info[i].length = skb->len;
		tx_ring->buffer_info[i].dma =
			dma_map_single(pci_dev_to_dev(pdev), skb->data,
				       skb->len, DMA_TO_DEVICE);
		tx_desc->buffer_addr = cpu_to_le64(tx_ring->buffer_info[i].dma);
		tx_desc->lower.data = cpu_to_le32(skb->len);
		tx_desc->lower.data |= cpu_to_le32(E1000_TXD_CMD_EOP |
						   E1000_TXD_CMD_IFCS);
		if (adapter->hw.mac.type < e1000_82543)
			tx_desc->lower.data |= E1000_TXD_CMD_RPS;
		else
			tx_desc->lower.data |= E1000_TXD_CMD_RS;

		tx_desc->upper.data = 0;
	}

	/* Setup Rx descriptor ring and Rx buffers */

	if (!rx_ring->count)
		rx_ring->count = E1000_DEFAULT_RXD;

	if (!(rx_ring->buffer_info = kcalloc(rx_ring->count,
	                                     sizeof(struct e1000_rx_buffer),
	                                     GFP_KERNEL))) {
		ret_val = 4;
		goto err_nomem;
	}

	rx_ring->size = rx_ring->count * sizeof(struct e1000_rx_desc);
	if (!(rx_ring->desc = dma_alloc_coherent(pci_dev_to_dev(pdev),
						 rx_ring->size, &rx_ring->dma,
						 GFP_KERNEL))) {
		ret_val = 5;
		goto err_nomem;
	}
	rx_ring->next_to_use = rx_ring->next_to_clean = 0;

	rctl = E1000_READ_REG(&adapter->hw, E1000_RCTL);
	E1000_WRITE_REG(&adapter->hw, E1000_RCTL, rctl & ~E1000_RCTL_EN);
	E1000_WRITE_REG(&adapter->hw, E1000_RDBAL(0),
			((u64) rx_ring->dma & 0xFFFFFFFF));
	E1000_WRITE_REG(&adapter->hw, E1000_RDBAH(0), ((u64) rx_ring->dma >> 32));
	E1000_WRITE_REG(&adapter->hw, E1000_RDLEN(0), rx_ring->size);
	E1000_WRITE_REG(&adapter->hw, E1000_RDH(0), 0);
	E1000_WRITE_REG(&adapter->hw, E1000_RDT(0), 0);
	rctl = E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SZ_2048 |
		E1000_RCTL_LBM_NO | E1000_RCTL_RDMTS_HALF |
		(adapter->hw.mac.mc_filter_type << E1000_RCTL_MO_SHIFT);
	E1000_WRITE_REG(&adapter->hw, E1000_RCTL, rctl);

	for (i = 0; i < rx_ring->count; i++) {
		struct e1000_rx_desc *rx_desc = E1000_RX_DESC(*rx_ring, i);
		struct sk_buff *skb;

		if (!(skb = alloc_skb(E1000_RXBUFFER_2048 + NET_IP_ALIGN,
				GFP_KERNEL))) {
			ret_val = 6;
			goto err_nomem;
		}
		skb_reserve(skb, NET_IP_ALIGN);
		rx_ring->buffer_info[i].skb = skb;
		rx_ring->buffer_info[i].dma =
			dma_map_single(pci_dev_to_dev(pdev), skb->data,
				       E1000_RXBUFFER_2048, DMA_FROM_DEVICE);
		rx_desc->buffer_addr = cpu_to_le64(rx_ring->buffer_info[i].dma);
		memset(skb->data, 0x00, skb->len);
	}

	return 0;

err_nomem:
	e1000_free_desc_rings(adapter);
	return ret_val;
}

static void e1000_phy_disable_receiver(struct e1000_adapter *adapter)
{
	/* Write out to PHY registers 29 and 30 to disable the Receiver. */
	e1000_write_phy_reg(&adapter->hw, 29, 0x001F);
	e1000_write_phy_reg(&adapter->hw, 30, 0x8FFC);
	e1000_write_phy_reg(&adapter->hw, 29, 0x001A);
	e1000_write_phy_reg(&adapter->hw, 30, 0x8FF0);
}

static void e1000_phy_reset_clk_and_crs(struct e1000_adapter *adapter)
{
	u16 phy_reg;

	/* Because we reset the PHY above, we need to re-force TX_CLK in the
	 * Extended PHY Specific Control Register to 25MHz clock.  This
	 * value defaults back to a 2.5MHz clock when the PHY is reset.
	 */
	e1000_read_phy_reg(&adapter->hw, M88E1000_EXT_PHY_SPEC_CTRL, &phy_reg);
	phy_reg |= M88E1000_EPSCR_TX_CLK_25;
	e1000_write_phy_reg(&adapter->hw,
		M88E1000_EXT_PHY_SPEC_CTRL, phy_reg);

	/* In addition, because of the s/w reset above, we need to enable
	 * CRS on TX.  This must be set for both full and half duplex
	 * operation.
	 */
	e1000_read_phy_reg(&adapter->hw, M88E1000_PHY_SPEC_CTRL, &phy_reg);
	phy_reg |= M88E1000_PSCR_ASSERT_CRS_ON_TX;
	e1000_write_phy_reg(&adapter->hw,
		M88E1000_PHY_SPEC_CTRL, phy_reg);
}

static int e1000_nonintegrated_phy_loopback(struct e1000_adapter *adapter)
{
	u32 ctrl_reg;
	u16 phy_reg;

	/* Setup the Device Control Register for PHY loopback test. */

	ctrl_reg = E1000_READ_REG(&adapter->hw, E1000_CTRL);
	ctrl_reg |= (E1000_CTRL_ILOS |		/* Invert Loss-Of-Signal */
		     E1000_CTRL_FRCSPD |	/* Set the Force Speed Bit */
		     E1000_CTRL_FRCDPX |	/* Set the Force Duplex Bit */
		     E1000_CTRL_SPD_1000 |	/* Force Speed to 1000 */
		     E1000_CTRL_FD);		/* Force Duplex to FULL */

	E1000_WRITE_REG(&adapter->hw, E1000_CTRL, ctrl_reg);

	/* Read the PHY Specific Control Register (0x10) */
	e1000_read_phy_reg(&adapter->hw, M88E1000_PHY_SPEC_CTRL, &phy_reg);

	/* Clear Auto-Crossover bits in PHY Specific Control Register
	 * (bits 6:5).
	 */
	phy_reg &= ~M88E1000_PSCR_AUTO_X_MODE;
	e1000_write_phy_reg(&adapter->hw, M88E1000_PHY_SPEC_CTRL, phy_reg);

	/* Perform software reset on the PHY */
	e1000_phy_commit(&adapter->hw);

	/* Have to setup TX_CLK and TX_CRS after software reset */
	e1000_phy_reset_clk_and_crs(adapter);

	e1000_write_phy_reg(&adapter->hw, PHY_CONTROL, 0x8100);

	/* Wait for reset to complete. */
	udelay(500);

	/* Have to setup TX_CLK and TX_CRS after software reset */
	e1000_phy_reset_clk_and_crs(adapter);

	/* Write out to PHY registers 29 and 30 to disable the Receiver. */
	e1000_phy_disable_receiver(adapter);

	/* Set the loopback bit in the PHY control register. */
	e1000_read_phy_reg(&adapter->hw, PHY_CONTROL, &phy_reg);
	phy_reg |= MII_CR_LOOPBACK;
	e1000_write_phy_reg(&adapter->hw, PHY_CONTROL, phy_reg);

	/* Setup TX_CLK and TX_CRS one more time. */
	e1000_phy_reset_clk_and_crs(adapter);

	/* Check Phy Configuration */
	e1000_read_phy_reg(&adapter->hw, PHY_CONTROL, &phy_reg);
	if (phy_reg != 0x4100)
		 return 9;

	e1000_read_phy_reg(&adapter->hw, M88E1000_EXT_PHY_SPEC_CTRL, &phy_reg);
	if (phy_reg != 0x0070)
		return 10;

	e1000_read_phy_reg(&adapter->hw, 29, &phy_reg);
	if (phy_reg != 0x001A)
		return 11;

	return 0;
}

static int e1000_integrated_phy_loopback(struct e1000_adapter *adapter)
{
	u32 ctrl_reg = 0;
	u32 stat_reg = 0;

	adapter->hw.mac.autoneg = false;

	if (adapter->hw.phy.type == e1000_phy_m88) {
		/* Auto-MDI/MDIX Off */
		e1000_write_phy_reg(&adapter->hw,
				    M88E1000_PHY_SPEC_CTRL, 0x0808);
		/* reset to update Auto-MDI/MDIX */
		e1000_write_phy_reg(&adapter->hw, PHY_CONTROL, 0x9140);
		/* autoneg off */
		e1000_write_phy_reg(&adapter->hw, PHY_CONTROL, 0x8140);
	} else if (adapter->hw.phy.type == e1000_phy_gg82563)
		e1000_write_phy_reg(&adapter->hw,
		                    GG82563_PHY_KMRN_MODE_CTRL,
		                    0x1CC);

	ctrl_reg = E1000_READ_REG(&adapter->hw, E1000_CTRL);

	if (adapter->hw.phy.type == e1000_phy_ife) {
		/* force 100, set loopback */
		e1000_write_phy_reg(&adapter->hw, PHY_CONTROL, 0x6100);

		/* Now set up the MAC to the same speed/duplex as the PHY. */
		ctrl_reg &= ~E1000_CTRL_SPD_SEL; /* Clear the speed sel bits */
		ctrl_reg |= (E1000_CTRL_FRCSPD | /* Set the Force Speed Bit */
			     E1000_CTRL_FRCDPX | /* Set the Force Duplex Bit */
			     E1000_CTRL_SPD_100 |/* Force Speed to 100 */
			     E1000_CTRL_FD);	 /* Force Duplex to FULL */
	} else {
		/* force 1000, set loopback */
		e1000_write_phy_reg(&adapter->hw, PHY_CONTROL, 0x4140);

		/* Now set up the MAC to the same speed/duplex as the PHY. */
		ctrl_reg = E1000_READ_REG(&adapter->hw, E1000_CTRL);
		ctrl_reg &= ~E1000_CTRL_SPD_SEL; /* Clear the speed sel bits */
		ctrl_reg |= (E1000_CTRL_FRCSPD | /* Set the Force Speed Bit */
			     E1000_CTRL_FRCDPX | /* Set the Force Duplex Bit */
			     E1000_CTRL_SPD_1000 |/* Force Speed to 1000 */
			     E1000_CTRL_FD);	 /* Force Duplex to FULL */
	}

	if (adapter->hw.phy.media_type == e1000_media_type_copper &&
	   adapter->hw.phy.type == e1000_phy_m88) {
		ctrl_reg |= E1000_CTRL_ILOS; /* Invert Loss of Signal */
	} else {
		/* Set the ILOS bit on the fiber Nic if half duplex link is
		 * detected. */
		stat_reg = E1000_READ_REG(&adapter->hw, E1000_STATUS);
		if ((stat_reg & E1000_STATUS_FD) == 0)
			ctrl_reg |= (E1000_CTRL_ILOS | E1000_CTRL_SLU);
	}

	E1000_WRITE_REG(&adapter->hw, E1000_CTRL, ctrl_reg);

	/* Disable the receiver on the PHY so when a cable is plugged in, the
	 * PHY does not begin to autoneg when a cable is reconnected to the NIC.
	 */
	if (adapter->hw.phy.type == e1000_phy_m88)
		e1000_phy_disable_receiver(adapter);

	udelay(500);

	return 0;
}

static int e1000_set_phy_loopback(struct e1000_adapter *adapter)
{
	u16 phy_reg = 0;
	u16 count = 0;

	switch (adapter->hw.mac.type) {
	case e1000_82543:
		if (adapter->hw.phy.media_type == e1000_media_type_copper) {
			/* Attempt to setup Loopback mode on Non-integrated PHY.
			 * Some PHY registers get corrupted at random, so
			 * attempt this 10 times.
			 */
			while (e1000_nonintegrated_phy_loopback(adapter) &&
			      count++ < 10);
			if (count < 11)
				return 0;
		}
		break;

	case e1000_82544:
	case e1000_82540:
	case e1000_82545:
	case e1000_82545_rev_3:
	case e1000_82546:
	case e1000_82546_rev_3:
	case e1000_82541:
	case e1000_82541_rev_2:
	case e1000_82547:
	case e1000_82547_rev_2:
		return e1000_integrated_phy_loopback(adapter);
		break;

	default:
		/* Default PHY loopback work is to read the MII
		 * control register and assert bit 14 (loopback mode).
		 */
		e1000_read_phy_reg(&adapter->hw, PHY_CONTROL, &phy_reg);
		phy_reg |= MII_CR_LOOPBACK;
		e1000_write_phy_reg(&adapter->hw, PHY_CONTROL, phy_reg);
		return 0;
		break;
	}

	return 8;
}

static int e1000_setup_loopback_test(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 rctl;

	if (hw->phy.media_type == e1000_media_type_fiber ||
	    hw->phy.media_type == e1000_media_type_internal_serdes) {
		switch (hw->mac.type) {
		case e1000_82545:
		case e1000_82546:
		case e1000_82545_rev_3:
		case e1000_82546_rev_3:
			return e1000_set_phy_loopback(adapter);
			break;
		default:
			rctl = E1000_READ_REG(hw, E1000_RCTL);
			rctl |= E1000_RCTL_LBM_TCVR;
			E1000_WRITE_REG(hw, E1000_RCTL, rctl);
			return 0;
		}
	} else if (hw->phy.media_type == e1000_media_type_copper)
		return e1000_set_phy_loopback(adapter);

	return 7;
}

static void e1000_loopback_cleanup(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 rctl;
	u16 phy_reg;

	rctl = E1000_READ_REG(hw, E1000_RCTL);
	rctl &= ~(E1000_RCTL_LBM_TCVR | E1000_RCTL_LBM_MAC);
	E1000_WRITE_REG(hw, E1000_RCTL, rctl);

	hw->mac.autoneg = true;
	if (hw->phy.type == e1000_phy_gg82563)
		e1000_write_phy_reg(hw, GG82563_PHY_KMRN_MODE_CTRL, 0x180);
	e1000_read_phy_reg(hw, PHY_CONTROL, &phy_reg);
	if (phy_reg & MII_CR_LOOPBACK) {
		phy_reg &= ~MII_CR_LOOPBACK;
		e1000_write_phy_reg(hw, PHY_CONTROL, phy_reg);
		e1000_phy_commit(hw);
	}
}

static void e1000_create_lbtest_frame(struct sk_buff *skb,
                                      unsigned int frame_size)
{
	memset(skb->data, 0xFF, frame_size);
	frame_size &= ~1;
	memset(&skb->data[frame_size / 2], 0xAA, frame_size / 2 - 1);
	memset(&skb->data[frame_size / 2 + 10], 0xBE, 1);
	memset(&skb->data[frame_size / 2 + 12], 0xAF, 1);
}

static int e1000_check_lbtest_frame(struct sk_buff *skb, unsigned int frame_size)
{
	frame_size &= ~1;
	if (*(skb->data + 3) == 0xFF) {
		if ((*(skb->data + frame_size / 2 + 10) == 0xBE) &&
		   (*(skb->data + frame_size / 2 + 12) == 0xAF)) {
			return 0;
		}
	}
	return 13;
}

static int e1000_run_loopback_test(struct e1000_adapter *adapter)
{
	struct e1000_tx_ring *tx_ring = &adapter->test_tx_ring;
	struct e1000_rx_ring *rx_ring = &adapter->test_rx_ring;
	struct pci_dev *pdev = adapter->pdev;
	int i, j, k, l, lc, good_cnt, ret_val=0;
	unsigned long time;

	E1000_WRITE_REG(&adapter->hw, E1000_RDT(0), rx_ring->count - 1);

	/* Calculate the loop count based on the largest descriptor ring
	 * The idea is to wrap the largest ring a number of times using 64
	 * send/receive pairs during each loop
	 */

	if (rx_ring->count <= tx_ring->count)
		lc = ((tx_ring->count / 64) * 2) + 1;
	else
		lc = ((rx_ring->count / 64) * 2) + 1;

	k = l = 0;
	for (j = 0; j <= lc; j++) { /* loop count loop */
		for (i = 0; i < 64; i++) { /* send the packets */
			e1000_create_lbtest_frame(tx_ring->buffer_info[k].skb,
					1024);
			dma_sync_single_for_device(pci_dev_to_dev(pdev),
					tx_ring->buffer_info[k].dma,
				    	tx_ring->buffer_info[k].length,
				    	DMA_TO_DEVICE);
			if (unlikely(++k == tx_ring->count)) k = 0;
		}
		E1000_WRITE_REG(&adapter->hw, E1000_TDT(0), k);
		E1000_WRITE_FLUSH(&adapter->hw);
		msleep(200);
		time = jiffies; /* set the start time for the receive */
		good_cnt = 0;
		do { /* receive the sent packets */
			dma_sync_single_for_cpu(pci_dev_to_dev(pdev),
			                rx_ring->buffer_info[l].dma,
			                E1000_RXBUFFER_2048,
			                DMA_FROM_DEVICE);

			ret_val = e1000_check_lbtest_frame(
					rx_ring->buffer_info[l].skb,
				   	1024);
			if (!ret_val)
				good_cnt++;
			if (unlikely(++l == rx_ring->count)) l = 0;
			/* time + 20 msecs (200 msecs on 2.4) is more than
			 * enough time to complete the receives, if it's
			 * exceeded, break and error off
			 */
		} while (good_cnt < 64 && jiffies < (time + 20));
		if (good_cnt != 64) {
			ret_val = 13; /* ret_val is the same as mis-compare */
			break;
		}
		if (jiffies >= (time + 20)) {
			ret_val = 14; /* error code for time out error */
			break;
		}
	} /* end loop count loop */
	return ret_val;
}

static int e1000_loopback_test(struct e1000_adapter *adapter, u64 *data)
{
	/* PHY loopback cannot be performed if SoL/IDER
	 * sessions are active */
	if (e1000_check_reset_block(&adapter->hw)) {
		DPRINTK(DRV, ERR, "Cannot do PHY loopback test "
		        "when SoL/IDER is active.\n");
		*data = 0;
		goto out;
	}

	if ((*data = e1000_setup_desc_rings(adapter)))
		goto out;
	if ((*data = e1000_setup_loopback_test(adapter)))
		goto err_loopback;
	*data = e1000_run_loopback_test(adapter);
	e1000_loopback_cleanup(adapter);

err_loopback:
	e1000_free_desc_rings(adapter);
out:
	return *data;
}

static int e1000_link_test(struct e1000_adapter *adapter, u64 *data)
{
	*data = 0;
	if (adapter->hw.phy.media_type == e1000_media_type_internal_serdes) {
		int i = 0;
		adapter->hw.mac.serdes_has_link = false;

		/* On some blade server designs, link establishment
		 * could take as long as 2-3 minutes */
		do {
			e1000_check_for_link(&adapter->hw);
			if (adapter->hw.mac.serdes_has_link == true)
				return *data;
			msleep(20);
		} while (i++ < 3750);

		*data = 1;
	} else {
		e1000_check_for_link(&adapter->hw);
		if (adapter->hw.mac.autoneg)
			msleep(4000);

		if (!(E1000_READ_REG(&adapter->hw, E1000_STATUS) & E1000_STATUS_LU)) {
			*data = 1;
		}
	}
	return *data;
}

static void e1000_diag_test(struct net_device *netdev,
                            struct ethtool_test *eth_test, u64 *data)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	u16 autoneg_advertised;
	u8 forced_speed_duplex, autoneg;
	bool if_running = netif_running(netdev);

	set_bit(__E1000_TESTING, &adapter->state);
	if (eth_test->flags == ETH_TEST_FL_OFFLINE) {
		/* Offline tests */

		/* save speed, duplex, autoneg settings */
		autoneg_advertised = adapter->hw.phy.autoneg_advertised;
		forced_speed_duplex = adapter->hw.mac.forced_speed_duplex;
		autoneg = adapter->hw.mac.autoneg;

		DPRINTK(HW, INFO, "offline testing starting\n");

		/* Link test performed before hardware reset so autoneg doesn't
		 * interfere with test result */
		if (e1000_link_test(adapter, &data[4]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		if (if_running)
			/* indicate we're in test mode */
			dev_close(netdev);
		else
			e1000_reset(adapter);

		if (e1000_reg_test(adapter, &data[0]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		e1000_reset(adapter);
		if (e1000_eeprom_test(adapter, &data[1]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		e1000_reset(adapter);
		if (e1000_intr_test(adapter, &data[2]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		e1000_reset(adapter);
		/* make sure the phy is powered up */
		if (adapter->hw.phy.media_type == e1000_media_type_copper)
			e1000_power_up_phy(&adapter->hw);
		if (e1000_loopback_test(adapter, &data[3]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		/* restore speed, duplex, autoneg settings */
		adapter->hw.phy.autoneg_advertised = autoneg_advertised;
		adapter->hw.mac.forced_speed_duplex = forced_speed_duplex;
		adapter->hw.mac.autoneg = autoneg;

		/* force this routine to wait until autoneg complete/timeout */
		adapter->hw.phy.autoneg_wait_to_complete = true;
		e1000_reset(adapter);
		adapter->hw.phy.autoneg_wait_to_complete = false;

		clear_bit(__E1000_TESTING, &adapter->state);
		if (if_running)
			dev_open(netdev);
	} else {
		DPRINTK(HW, INFO, "online testing starting\n");
		/* Online tests */
		if (e1000_link_test(adapter, &data[4]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		/* Online tests aren't run; pass by default */
		data[0] = 0;
		data[1] = 0;
		data[2] = 0;
		data[3] = 0;

		clear_bit(__E1000_TESTING, &adapter->state);
	}
	msleep_interruptible(4 * 1000);
}

static int e1000_wol_exclusion(struct e1000_adapter *adapter,
                               struct ethtool_wolinfo *wol)
{
	struct e1000_hw *hw = &adapter->hw;
	int retval = 1; /* fail by default */

	switch (hw->device_id) {
	case E1000_DEV_ID_82542:
	case E1000_DEV_ID_82543GC_FIBER:
	case E1000_DEV_ID_82543GC_COPPER:
	case E1000_DEV_ID_82544EI_FIBER:
	case E1000_DEV_ID_82546EB_QUAD_COPPER:
	case E1000_DEV_ID_82545EM_FIBER:
	case E1000_DEV_ID_82545EM_COPPER:
	case E1000_DEV_ID_82546GB_QUAD_COPPER:
	case E1000_DEV_ID_82546GB_PCIE:
		/* these don't support WoL at all */
		wol->supported = 0;
		break;
	case E1000_DEV_ID_82546EB_FIBER:
	case E1000_DEV_ID_82546GB_FIBER:
		/* Wake events not supported on port B */
		if (E1000_READ_REG(hw, E1000_STATUS) & E1000_STATUS_FUNC_1) {
			wol->supported = 0;
			break;
		}
		/* return success for non excluded adapter ports */
		retval = 0;
		break;
	case E1000_DEV_ID_82546GB_QUAD_COPPER_KSP3:
		/* quad port adapters only support WoL on port A */
		if (!(adapter->flags & E1000_FLAG_QUAD_PORT_A)) {
			wol->supported = 0;
			break;
		}
		/* return success for non excluded adapter ports */
		retval = 0;
		break;
	default:
		/* dual port cards only support WoL on port A from now on
		 * unless it was enabled in the eeprom for port B
		 * so exclude FUNC_1 ports from having WoL enabled */
		if (E1000_READ_REG(hw, E1000_STATUS) & E1000_STATUS_FUNC_1 &&
		    !adapter->eeprom_wol) {
			wol->supported = 0;
			break;
		}

		retval = 0;
	}

	return retval;
}

static void e1000_get_wol(struct net_device *netdev,
                          struct ethtool_wolinfo *wol)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	wol->supported = WAKE_UCAST | WAKE_MCAST |
	                 WAKE_BCAST | WAKE_MAGIC;
	wol->wolopts = 0;

	/* this function will set ->supported = 0 and return 1 if wol is not
	 * supported by this hardware */
	if (e1000_wol_exclusion(adapter, wol) ||
	    !device_can_wakeup(&adapter->pdev->dev))
		return;

	/* apply any specific unsupported masks here */
	switch (adapter->hw.device_id) {
	case E1000_DEV_ID_82546GB_QUAD_COPPER_KSP3:
		/* KSP3 does not support UCAST wake-ups */
		wol->supported &= ~WAKE_UCAST;

		if (adapter->wol & E1000_WUFC_EX)
			DPRINTK(DRV, ERR, "Interface does not support "
		        "directed (unicast) frame wake-up packets\n");
		break;
	default:
		break;
	}

	if (adapter->wol & E1000_WUFC_EX)
		wol->wolopts |= WAKE_UCAST;
	if (adapter->wol & E1000_WUFC_MC)
		wol->wolopts |= WAKE_MCAST;
	if (adapter->wol & E1000_WUFC_BC)
		wol->wolopts |= WAKE_BCAST;
	if (adapter->wol & E1000_WUFC_MAG)
		wol->wolopts |= WAKE_MAGIC;

	return;
}

static int e1000_set_wol(struct net_device *netdev,
                         struct ethtool_wolinfo *wol)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;

	if (wol->wolopts & (WAKE_PHY | WAKE_ARP | WAKE_MAGICSECURE))
		return -EOPNOTSUPP;

	if (e1000_wol_exclusion(adapter, wol))
		return wol->wolopts ? -EOPNOTSUPP : 0;

	switch (hw->device_id) {
	case E1000_DEV_ID_82546GB_QUAD_COPPER_KSP3:
		if (wol->wolopts & WAKE_UCAST) {
			DPRINTK(DRV, ERR, "Interface does not support "
		        "directed (unicast) frame wake-up packets\n");
			return -EOPNOTSUPP;
		}
		break;
	default:
		break;
	}

	/* these settings will always override what we currently have */
	adapter->wol = 0;

	if (wol->wolopts & WAKE_UCAST)
		adapter->wol |= E1000_WUFC_EX;
	if (wol->wolopts & WAKE_MCAST)
		adapter->wol |= E1000_WUFC_MC;
	if (wol->wolopts & WAKE_BCAST)
		adapter->wol |= E1000_WUFC_BC;
	if (wol->wolopts & WAKE_MAGIC)
		adapter->wol |= E1000_WUFC_MAG;

	return 0;
}
#ifdef HAVE_ETHTOOL_SET_PHYS_ID
static int e1000_set_phys_id(struct net_device *netdev,
			     enum ethtool_phys_id_state state)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		e1000_setup_led(hw);
		return 2;

	case ETHTOOL_ID_ON:
		e1000_led_on(hw);
		break;

	case ETHTOOL_ID_OFF:
		e1000_led_off(hw);
		break;

	case ETHTOOL_ID_INACTIVE:
		e1000_cleanup_led(hw);
	}

	return 0;
}

#else
/* toggle LED 4 times per second = 2 "blinks" per second */
#define E1000_ID_INTERVAL	(HZ/4)

/* bit defines for adapter->led_status */
#define E1000_LED_ON		0

static void e1000_led_blink_callback(unsigned long data)
{
	struct e1000_adapter *adapter = (struct e1000_adapter *) data;

	if (test_and_change_bit(E1000_LED_ON, &adapter->led_status))
		e1000_led_off(&adapter->hw);
	else
		e1000_led_on(&adapter->hw);

	mod_timer(&adapter->blink_timer, jiffies + E1000_ID_INTERVAL);
}

static int e1000_phys_id(struct net_device *netdev, u32 data)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	if (!data)
		data = INT_MAX;

	if (!adapter->blink_timer.function) {
		init_timer(&adapter->blink_timer);
		adapter->blink_timer.function = e1000_led_blink_callback;
		adapter->blink_timer.data = (unsigned long) adapter;
	}
	e1000_setup_led(&adapter->hw);
	mod_timer(&adapter->blink_timer, jiffies);
	msleep_interruptible(data * 1000);
	del_timer_sync(&adapter->blink_timer);

	e1000_led_off(&adapter->hw);
	clear_bit(E1000_LED_ON, &adapter->led_status);
	e1000_cleanup_led(&adapter->hw);

	return 0;
}
#endif /* HAVE_ETHTOOL_SET_PHYS_ID */

static int e1000_get_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *ec)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	if (adapter->itr_setting <= 4)
		ec->rx_coalesce_usecs = adapter->itr_setting;
	else
		ec->rx_coalesce_usecs = 1000000 / adapter->itr_setting;

	return 0;
}

static int e1000_set_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *ec)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	if ((ec->rx_coalesce_usecs > E1000_MAX_ITR_USECS) ||
	    ((ec->rx_coalesce_usecs > 4) &&
	     (ec->rx_coalesce_usecs < E1000_MIN_ITR_USECS)) ||
	    (ec->rx_coalesce_usecs == 2))
		return -EINVAL;

	if (!(adapter->flags & E1000_FLAG_HAS_INTR_MODERATION))
		return -ENOTSUPP;

	if (ec->rx_coalesce_usecs == 4) {
		adapter->itr = adapter->itr_setting = 4;
	} else if (ec->rx_coalesce_usecs <= 3) {
		adapter->itr = 20000;
		adapter->itr_setting = ec->rx_coalesce_usecs;
	} else {
		adapter->itr = (1000000 / ec->rx_coalesce_usecs);
		adapter->itr_setting = adapter->itr & ~3;
	}

	if (adapter->itr_setting != 0)
		E1000_WRITE_REG(&adapter->hw, E1000_ITR,
			1000000000 / (adapter->itr * 256));
	else
		E1000_WRITE_REG(&adapter->hw, E1000_ITR, 0);

	return 0;
}

static int e1000_nway_reset(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	if (netif_running(netdev))
		e1000_reinit_locked(adapter);
	return 0;
}

#ifdef HAVE_ETHTOOL_GET_SSET_COUNT
static int e1000_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_TEST:
		return E1000_TEST_LEN;
	case ETH_SS_STATS:
		return E1000_STATS_LEN;
	default:
		return -EOPNOTSUPP;
	}
}
#else
static int e1000_get_stats_count(struct net_device *netdev)
{
	return E1000_STATS_LEN;
}

static int e1000_diag_test_count(struct net_device *netdev)
{
	return E1000_TEST_LEN;
}
#endif

static void e1000_get_ethtool_stats(struct net_device *netdev,
                                    struct ethtool_stats *stats, u64 *data)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	int i;

	e1000_update_stats(adapter);
	for (i = 0; i < E1000_GLOBAL_STATS_LEN; i++) {
		char *p = (char *)adapter+e1000_gstrings_stats[i].stat_offset;
		data[i] = (e1000_gstrings_stats[i].sizeof_stat ==
			sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
	}
/*	BUG_ON(i != E1000_STATS_LEN); */
}

static void e1000_get_strings(struct net_device *netdev, u32 stringset,
                              u8 *data)
{
	u8 *p = data;
	int i;

	switch (stringset) {
	case ETH_SS_TEST:
		memcpy(data, *e1000_gstrings_test,
			E1000_TEST_LEN*ETH_GSTRING_LEN);
		break;
	case ETH_SS_STATS:
		for (i = 0; i < E1000_GLOBAL_STATS_LEN; i++) {
			memcpy(p, e1000_gstrings_stats[i].stat_string,
			       ETH_GSTRING_LEN);
			p += ETH_GSTRING_LEN;
		}
/*		BUG_ON(p - data != E1000_STATS_LEN * ETH_GSTRING_LEN); */
		break;
	}
}

static struct ethtool_ops e1000_ethtool_ops = {
	.get_settings           = e1000_get_settings,
	.set_settings           = e1000_set_settings,
	.get_drvinfo            = e1000_get_drvinfo,
	.get_regs_len           = e1000_get_regs_len,
	.get_regs               = e1000_get_regs,
	.get_wol                = e1000_get_wol,
	.set_wol                = e1000_set_wol,
	.get_msglevel           = e1000_get_msglevel,
	.set_msglevel           = e1000_set_msglevel,
	.nway_reset             = e1000_nway_reset,
	.get_link               = e1000_get_link,
	.get_eeprom_len         = e1000_get_eeprom_len,
	.get_eeprom             = e1000_get_eeprom,
	.set_eeprom             = e1000_set_eeprom,
	.get_ringparam          = e1000_get_ringparam,
	.set_ringparam          = e1000_set_ringparam,
	.get_pauseparam         = e1000_get_pauseparam,
	.set_pauseparam         = e1000_set_pauseparam,
	.get_rx_csum            = e1000_get_rx_csum,
	.set_rx_csum            = e1000_set_rx_csum,
	.get_tx_csum            = e1000_get_tx_csum,
	.set_tx_csum            = e1000_set_tx_csum,
	.get_sg                 = ethtool_op_get_sg,
	.set_sg                 = ethtool_op_set_sg,
#ifdef NETIF_F_TSO
	.get_tso                = ethtool_op_get_tso,
	.set_tso                = e1000_set_tso,
#endif
#ifdef HAVE_ETHTOOL_GET_SSET_COUNT
	.get_sset_count         = e1000_get_sset_count,
#else
	.self_test_count        = e1000_diag_test_count,
	.get_stats_count        = e1000_get_stats_count,
#endif
	.self_test              = e1000_diag_test,
	.get_strings            = e1000_get_strings,
#ifdef HAVE_ETHTOOL_SET_PHYS_ID
	.set_phys_id		= e1000_set_phys_id,
#else
	.phys_id                = e1000_phys_id,
#endif
	.get_ethtool_stats      = e1000_get_ethtool_stats,
#ifdef HAVE_ETHTOOL_GET_PERM_ADDR
	.get_perm_addr          = ethtool_op_get_perm_addr,
#endif
	.get_coalesce           = e1000_get_coalesce,
	.set_coalesce           = e1000_set_coalesce,
};

void e1000_set_ethtool_ops(struct net_device *netdev)
{
	SET_ETHTOOL_OPS(netdev, &e1000_ethtool_ops);
}
#endif	/* SIOCETHTOOL */
