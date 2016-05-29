/*******************************************************************************
 *
 * Intel(R) 40-10 Gigabit Ethernet Connection Network Driver
 * Copyright(c) 2013 - 2016 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 ******************************************************************************/

/* ethtool support for i40e */

#include "i40e.h"
#include "i40e_diag.h"

#ifdef SIOCETHTOOL
#ifndef ETH_GSTRING_LEN
#define ETH_GSTRING_LEN 32

#endif
#ifdef ETHTOOL_GSTATS
struct i40e_stats {
	char stat_string[ETH_GSTRING_LEN];
	int sizeof_stat;
	int stat_offset;
};

#define I40E_STAT(_type, _name, _stat) { \
	.stat_string = _name, \
	.sizeof_stat = FIELD_SIZEOF(_type, _stat), \
	.stat_offset = offsetof(_type, _stat) \
}

#ifdef HAVE_NDO_GET_STATS64
#define I40E_NETDEV_STAT(_net_stat) \
		I40E_STAT(struct rtnl_link_stats64, #_net_stat, _net_stat)
#else
#define I40E_NETDEV_STAT(_net_stat) \
		I40E_STAT(struct net_device_stats, #_net_stat, _net_stat)
#endif
#define I40E_PF_STAT(_name, _stat) \
		I40E_STAT(struct i40e_pf, _name, _stat)
#define I40E_VSI_STAT(_name, _stat) \
		I40E_STAT(struct i40e_vsi, _name, _stat)
#define I40E_VEB_STAT(_name, _stat) \
		I40E_STAT(struct i40e_veb, _name, _stat)

static const struct i40e_stats i40e_gstrings_net_stats[] = {
	I40E_NETDEV_STAT(rx_packets),
	I40E_NETDEV_STAT(tx_packets),
	I40E_NETDEV_STAT(rx_bytes),
	I40E_NETDEV_STAT(tx_bytes),
	I40E_NETDEV_STAT(rx_errors),
	I40E_NETDEV_STAT(tx_errors),
	I40E_NETDEV_STAT(rx_dropped),
	I40E_NETDEV_STAT(tx_dropped),
	I40E_NETDEV_STAT(collisions),
	I40E_NETDEV_STAT(rx_length_errors),
	I40E_NETDEV_STAT(rx_crc_errors),
};

static const struct i40e_stats i40e_gstrings_veb_stats[] = {
	I40E_VEB_STAT("rx_bytes", stats.rx_bytes),
	I40E_VEB_STAT("tx_bytes", stats.tx_bytes),
	I40E_VEB_STAT("rx_unicast", stats.rx_unicast),
	I40E_VEB_STAT("tx_unicast", stats.tx_unicast),
	I40E_VEB_STAT("rx_multicast", stats.rx_multicast),
	I40E_VEB_STAT("tx_multicast", stats.tx_multicast),
	I40E_VEB_STAT("rx_broadcast", stats.rx_broadcast),
	I40E_VEB_STAT("tx_broadcast", stats.tx_broadcast),
	I40E_VEB_STAT("rx_discards", stats.rx_discards),
	I40E_VEB_STAT("tx_discards", stats.tx_discards),
	I40E_VEB_STAT("tx_errors", stats.tx_errors),
	I40E_VEB_STAT("rx_unknown_protocol", stats.rx_unknown_protocol),
};

static const struct i40e_stats i40e_gstrings_misc_stats[] = {
	I40E_VSI_STAT("rx_unicast", eth_stats.rx_unicast),
	I40E_VSI_STAT("tx_unicast", eth_stats.tx_unicast),
	I40E_VSI_STAT("rx_multicast", eth_stats.rx_multicast),
	I40E_VSI_STAT("tx_multicast", eth_stats.tx_multicast),
	I40E_VSI_STAT("rx_broadcast", eth_stats.rx_broadcast),
	I40E_VSI_STAT("tx_broadcast", eth_stats.tx_broadcast),
	I40E_VSI_STAT("rx_unknown_protocol", eth_stats.rx_unknown_protocol),
	I40E_VSI_STAT("tx_linearize", tx_linearize),
	I40E_VSI_STAT("tx_force_wb", tx_force_wb),
	I40E_VSI_STAT("tx_lost_interrupt", tx_lost_interrupt),
	I40E_VSI_STAT("rx_alloc_fail", rx_buf_failed),
	I40E_VSI_STAT("rx_pg_alloc_fail", rx_page_failed),
};

/* These PF_STATs might look like duplicates of some NETDEV_STATs,
 * but they are separate.  This device supports Virtualization, and
 * as such might have several netdevs supporting VMDq and FCoE going
 * through a single port.  The NETDEV_STATs are for individual netdevs
 * seen at the top of the stack, and the PF_STATs are for the physical
 * function at the bottom of the stack hosting those netdevs.
 *
 * The PF_STATs are appended to the netdev stats only when ethtool -S
 * is queried on the base PF netdev, not on the VMDq or FCoE netdev.
 */
static struct i40e_stats i40e_gstrings_stats[] = {
	I40E_PF_STAT("rx_bytes", stats.eth.rx_bytes),
	I40E_PF_STAT("tx_bytes", stats.eth.tx_bytes),
	I40E_PF_STAT("rx_unicast", stats.eth.rx_unicast),
	I40E_PF_STAT("tx_unicast", stats.eth.tx_unicast),
	I40E_PF_STAT("rx_multicast", stats.eth.rx_multicast),
	I40E_PF_STAT("tx_multicast", stats.eth.tx_multicast),
	I40E_PF_STAT("rx_broadcast", stats.eth.rx_broadcast),
	I40E_PF_STAT("tx_broadcast", stats.eth.tx_broadcast),
	I40E_PF_STAT("tx_errors", stats.eth.tx_errors),
	I40E_PF_STAT("rx_dropped", stats.eth.rx_discards),
	I40E_PF_STAT("tx_dropped_link_down", stats.tx_dropped_link_down),
	I40E_PF_STAT("rx_crc_errors", stats.crc_errors),
	I40E_PF_STAT("illegal_bytes", stats.illegal_bytes),
	I40E_PF_STAT("mac_local_faults", stats.mac_local_faults),
	I40E_PF_STAT("mac_remote_faults", stats.mac_remote_faults),
	I40E_PF_STAT("tx_timeout", tx_timeout_count),
	I40E_PF_STAT("rx_csum_bad", hw_csum_rx_error),
	I40E_PF_STAT("rx_length_errors", stats.rx_length_errors),
	I40E_PF_STAT("link_xon_rx", stats.link_xon_rx),
	I40E_PF_STAT("link_xoff_rx", stats.link_xoff_rx),
	I40E_PF_STAT("link_xon_tx", stats.link_xon_tx),
	I40E_PF_STAT("link_xoff_tx", stats.link_xoff_tx),
	I40E_PF_STAT("rx_size_64", stats.rx_size_64),
	I40E_PF_STAT("rx_size_127", stats.rx_size_127),
	I40E_PF_STAT("rx_size_255", stats.rx_size_255),
	I40E_PF_STAT("rx_size_511", stats.rx_size_511),
	I40E_PF_STAT("rx_size_1023", stats.rx_size_1023),
	I40E_PF_STAT("rx_size_1522", stats.rx_size_1522),
	I40E_PF_STAT("rx_size_big", stats.rx_size_big),
	I40E_PF_STAT("tx_size_64", stats.tx_size_64),
	I40E_PF_STAT("tx_size_127", stats.tx_size_127),
	I40E_PF_STAT("tx_size_255", stats.tx_size_255),
	I40E_PF_STAT("tx_size_511", stats.tx_size_511),
	I40E_PF_STAT("tx_size_1023", stats.tx_size_1023),
	I40E_PF_STAT("tx_size_1522", stats.tx_size_1522),
	I40E_PF_STAT("tx_size_big", stats.tx_size_big),
	I40E_PF_STAT("rx_undersize", stats.rx_undersize),
	I40E_PF_STAT("rx_fragments", stats.rx_fragments),
	I40E_PF_STAT("rx_oversize", stats.rx_oversize),
	I40E_PF_STAT("rx_jabber", stats.rx_jabber),
	I40E_PF_STAT("VF_admin_queue_requests", vf_aq_requests),
	I40E_PF_STAT("arq_overflows", arq_overflows),
#ifdef HAVE_PTP_1588_CLOCK
	I40E_PF_STAT("rx_hwtstamp_cleared", rx_hwtstamp_cleared),
#endif /* HAVE_PTP_1588_CLOCK */
	I40E_PF_STAT("fdir_flush_cnt", fd_flush_cnt),
	I40E_PF_STAT("fdir_atr_match", stats.fd_atr_match),
	I40E_PF_STAT("fdir_atr_tunnel_match", stats.fd_atr_tunnel_match),
	I40E_PF_STAT("fdir_atr_status", stats.fd_atr_status),
	I40E_PF_STAT("fdir_sb_match", stats.fd_sb_match),
	I40E_PF_STAT("fdir_sb_status", stats.fd_sb_status),
#ifdef I40E_ADD_PROBES
	I40E_PF_STAT("tx_tcp_segments", tcp_segs),
	I40E_PF_STAT("tx_tcp_cso", tx_tcp_cso),
	I40E_PF_STAT("tx_udp_cso", tx_udp_cso),
	I40E_PF_STAT("tx_sctp_cso", tx_sctp_cso),
	I40E_PF_STAT("tx_ip4_cso", tx_ip4_cso),
	I40E_PF_STAT("rx_tcp_cso", rx_tcp_cso),
	I40E_PF_STAT("rx_udp_cso", rx_udp_cso),
	I40E_PF_STAT("rx_sctp_cso", rx_sctp_cso),
	I40E_PF_STAT("rx_ip4_cso", rx_ip4_cso),
	I40E_PF_STAT("rx_tcp_cso_error", rx_tcp_cso_err),
	I40E_PF_STAT("rx_udp_cso_error", rx_udp_cso_err),
	I40E_PF_STAT("rx_sctp_cso_error", rx_sctp_cso_err),
	I40E_PF_STAT("rx_ip4_cso_error", rx_ip4_cso_err),
#endif

	/* LPI stats */
	I40E_PF_STAT("tx_lpi_status", stats.tx_lpi_status),
	I40E_PF_STAT("rx_lpi_status", stats.rx_lpi_status),
	I40E_PF_STAT("tx_lpi_count", stats.tx_lpi_count),
	I40E_PF_STAT("rx_lpi_count", stats.rx_lpi_count),
};

#ifdef I40E_FCOE
static const struct i40e_stats i40e_gstrings_fcoe_stats[] = {
	I40E_VSI_STAT("fcoe_bad_fccrc", fcoe_stats.fcoe_bad_fccrc),
	I40E_VSI_STAT("rx_fcoe_dropped", fcoe_stats.rx_fcoe_dropped),
	I40E_VSI_STAT("rx_fcoe_packets", fcoe_stats.rx_fcoe_packets),
	I40E_VSI_STAT("rx_fcoe_dwords", fcoe_stats.rx_fcoe_dwords),
	I40E_VSI_STAT("fcoe_ddp_count", fcoe_stats.fcoe_ddp_count),
	I40E_VSI_STAT("fcoe_last_error", fcoe_stats.fcoe_last_error),
	I40E_VSI_STAT("tx_fcoe_packets", fcoe_stats.tx_fcoe_packets),
	I40E_VSI_STAT("tx_fcoe_dwords", fcoe_stats.tx_fcoe_dwords),
};

#endif /* I40E_FCOE */
#define I40E_QUEUE_STATS_LEN(n) \
	(((struct i40e_netdev_priv *)netdev_priv((n)))->vsi->num_queue_pairs \
	    * 2 /* Tx and Rx together */                                     \
	    * (sizeof(struct i40e_queue_stats) / sizeof(u64)))
#define I40E_GLOBAL_STATS_LEN	ARRAY_SIZE(i40e_gstrings_stats)
#define I40E_NETDEV_STATS_LEN   ARRAY_SIZE(i40e_gstrings_net_stats)
#define I40E_MISC_STATS_LEN	ARRAY_SIZE(i40e_gstrings_misc_stats)
#ifdef I40E_FCOE
#define I40E_FCOE_STATS_LEN	ARRAY_SIZE(i40e_gstrings_fcoe_stats)
#define I40E_VSI_STATS_LEN(n)	(I40E_NETDEV_STATS_LEN + \
				 I40E_FCOE_STATS_LEN + \
				 I40E_MISC_STATS_LEN + \
				 I40E_QUEUE_STATS_LEN((n)))
#else
#define I40E_VSI_STATS_LEN(n)   (I40E_NETDEV_STATS_LEN + \
				 I40E_MISC_STATS_LEN + \
				 I40E_QUEUE_STATS_LEN((n)))
#endif /* I40E_FCOE */
#define I40E_PFC_STATS_LEN ( \
		(FIELD_SIZEOF(struct i40e_pf, stats.priority_xoff_rx) + \
		 FIELD_SIZEOF(struct i40e_pf, stats.priority_xon_rx) + \
		 FIELD_SIZEOF(struct i40e_pf, stats.priority_xoff_tx) + \
		 FIELD_SIZEOF(struct i40e_pf, stats.priority_xon_tx) + \
		 FIELD_SIZEOF(struct i40e_pf, stats.priority_xon_2_xoff)) \
		 / sizeof(u64))
#define I40E_VEB_TC_STATS_LEN ( \
		(FIELD_SIZEOF(struct i40e_veb, tc_stats.tc_rx_packets) + \
		 FIELD_SIZEOF(struct i40e_veb, tc_stats.tc_rx_bytes) + \
		 FIELD_SIZEOF(struct i40e_veb, tc_stats.tc_tx_packets) + \
		 FIELD_SIZEOF(struct i40e_veb, tc_stats.tc_tx_bytes)) \
		 / sizeof(u64))
#define I40E_VEB_STATS_LEN	ARRAY_SIZE(i40e_gstrings_veb_stats)
#define I40E_VEB_STATS_TOTAL	(I40E_VEB_STATS_LEN + I40E_VEB_TC_STATS_LEN)
#define I40E_PF_STATS_LEN(n)	(I40E_GLOBAL_STATS_LEN + \
				 I40E_PFC_STATS_LEN + \
				 I40E_VSI_STATS_LEN((n)))

#endif /* ETHTOOL_GSTATS */
#ifdef ETHTOOL_TEST
enum i40e_ethtool_test_id {
	I40E_ETH_TEST_REG = 0,
	I40E_ETH_TEST_EEPROM,
	I40E_ETH_TEST_INTR,
	I40E_ETH_TEST_LOOPBACK,
	I40E_ETH_TEST_LINK,
};

static const char i40e_gstrings_test[][ETH_GSTRING_LEN] = {
	"Register test  (offline)",
	"Eeprom test    (offline)",
	"Interrupt test (offline)",
	"Loopback test  (offline)",
	"Link test   (on/offline)"
};

#define I40E_TEST_LEN (sizeof(i40e_gstrings_test) / ETH_GSTRING_LEN)

#endif /* ETHTOOL_TEST */
static int i40e_del_cloud_filter_ethtool(struct i40e_pf *pf,
					 struct ethtool_rxnfc *cmd);

#ifdef HAVE_ETHTOOL_GET_SSET_COUNT
static const char i40e_priv_flags_strings_gl[][ETH_GSTRING_LEN] = {
	"MFP",
	"LinkPolling",
	"flow-director-atr",
	"veb-stats",
	"hw-atr-eviction",
	"vf-true-promisc-support",
};

#define I40E_PRIV_FLAGS_GL_STR_LEN ARRAY_SIZE(i40e_priv_flags_strings_gl)

static const char i40e_priv_flags_strings[][ETH_GSTRING_LEN] = {
	"MFP",
	"LinkPolling",
	"flow-director-atr",
	"veb-stats",
	"hw-atr-eviction",
};

#define I40E_PRIV_FLAGS_STR_LEN ARRAY_SIZE(i40e_priv_flags_strings)

#endif /* HAVE_ETHTOOL_GET_SSET_COUNT */

/**
 * i40e_partition_setting_complaint - generic complaint for MFP restriction
 * @pf: the PF struct
 **/
static void i40e_partition_setting_complaint(struct i40e_pf *pf)
{
	dev_info(&pf->pdev->dev,
		 "The link settings are allowed to be changed only from the first partition of a given port. Please switch to the first partition in order to change the setting.\n");
}

/**
 * i40e_get_settings_link_up - Get the Link settings for when link is up
 * @hw: hw structure
 * @ecmd: ethtool command to fill in
 * @netdev: network interface device structure
 *
 * Reports link settings that can be determined when link is up
 **/
static void i40e_get_settings_link_up(struct i40e_hw *hw,
				      struct ethtool_cmd *ecmd,
				      struct net_device *netdev,
				      struct i40e_pf *pf)
{
	struct i40e_link_status *hw_link_info = &hw->phy.link_info;
	u32 link_speed = hw_link_info->link_speed;

	/* Initialize supported and advertised settings based on phy settings */
	switch (hw_link_info->phy_type) {
	case I40E_PHY_TYPE_40GBASE_CR4:
	case I40E_PHY_TYPE_40GBASE_CR4_CU:
		ecmd->supported = SUPPORTED_Autoneg |
				  SUPPORTED_40000baseCR4_Full;
		ecmd->advertising = ADVERTISED_Autoneg |
				    ADVERTISED_40000baseCR4_Full;
		break;
	case I40E_PHY_TYPE_XLAUI:
	case I40E_PHY_TYPE_XLPPI:
	case I40E_PHY_TYPE_40GBASE_AOC:
		ecmd->supported = SUPPORTED_40000baseCR4_Full;
		break;
	case I40E_PHY_TYPE_40GBASE_SR4:
		ecmd->supported = SUPPORTED_40000baseSR4_Full;
		break;
	case I40E_PHY_TYPE_40GBASE_LR4:
		ecmd->supported = SUPPORTED_40000baseLR4_Full;
		break;
	case I40E_PHY_TYPE_10GBASE_SR:
	case I40E_PHY_TYPE_10GBASE_LR:
	case I40E_PHY_TYPE_1000BASE_SX:
	case I40E_PHY_TYPE_1000BASE_LX:
		ecmd->supported = SUPPORTED_10000baseT_Full;
		if (hw_link_info->module_type[2] & I40E_MODULE_TYPE_1000BASE_SX ||
		    hw_link_info->module_type[2] & I40E_MODULE_TYPE_1000BASE_LX) {
			ecmd->supported |= SUPPORTED_1000baseT_Full;
			if (hw_link_info->requested_speeds & I40E_LINK_SPEED_1GB)
				ecmd->advertising |= ADVERTISED_1000baseT_Full;
		}
		if (hw_link_info->requested_speeds & I40E_LINK_SPEED_10GB)
			ecmd->advertising |= ADVERTISED_10000baseT_Full;
		break;
	case I40E_PHY_TYPE_10GBASE_T:
	case I40E_PHY_TYPE_1000BASE_T:
		ecmd->supported = SUPPORTED_Autoneg |
				  SUPPORTED_10000baseT_Full |
				  SUPPORTED_1000baseT_Full;
		ecmd->advertising = ADVERTISED_Autoneg;
		if (hw_link_info->requested_speeds & I40E_LINK_SPEED_10GB)
			ecmd->advertising |= ADVERTISED_10000baseT_Full;
		if (hw_link_info->requested_speeds & I40E_LINK_SPEED_1GB)
			ecmd->advertising |= ADVERTISED_1000baseT_Full;
		/* adding 100baseT support for 10GBASET_PHY */
		if (pf->flags & I40E_FLAG_HAVE_10GBASET_PHY) {
			ecmd->supported |= SUPPORTED_100baseT_Full;
			ecmd->advertising |= ADVERTISED_100baseT_Full |
					     ADVERTISED_1000baseT_Full |
					     ADVERTISED_10000baseT_Full;
		}
		break;
	case I40E_PHY_TYPE_1000BASE_T_OPTICAL:
		ecmd->supported = SUPPORTED_Autoneg |
				  SUPPORTED_1000baseT_Full;
		ecmd->advertising = ADVERTISED_Autoneg |
				    ADVERTISED_1000baseT_Full;
		break;
	case I40E_PHY_TYPE_100BASE_TX:
		ecmd->supported = SUPPORTED_Autoneg |
				  SUPPORTED_100baseT_Full;
		if (hw_link_info->requested_speeds & I40E_LINK_SPEED_100MB)
			ecmd->advertising |= ADVERTISED_100baseT_Full;
		/* firmware detects 10G phy as 100M phy at 100M speed */
		if (pf->flags & I40E_FLAG_HAVE_10GBASET_PHY) {
			ecmd->supported |= SUPPORTED_10000baseT_Full |
					   SUPPORTED_1000baseT_Full;
			ecmd->advertising |= ADVERTISED_Autoneg |
					     ADVERTISED_100baseT_Full |
					     ADVERTISED_1000baseT_Full |
					     ADVERTISED_10000baseT_Full;
		}
		break;
	case I40E_PHY_TYPE_10GBASE_CR1_CU:
	case I40E_PHY_TYPE_10GBASE_CR1:
		ecmd->supported = SUPPORTED_Autoneg |
				  SUPPORTED_10000baseT_Full;
		ecmd->advertising = ADVERTISED_Autoneg |
				    ADVERTISED_10000baseT_Full;
		break;
	case I40E_PHY_TYPE_XAUI:
	case I40E_PHY_TYPE_XFI:
	case I40E_PHY_TYPE_SFI:
	case I40E_PHY_TYPE_10GBASE_SFPP_CU:
	case I40E_PHY_TYPE_10GBASE_AOC:
		ecmd->supported = SUPPORTED_10000baseT_Full;
		break;
	case I40E_PHY_TYPE_SGMII:
		ecmd->supported = SUPPORTED_Autoneg |
				  SUPPORTED_1000baseT_Full;
		if (hw_link_info->requested_speeds & I40E_LINK_SPEED_1GB)
			ecmd->advertising |= ADVERTISED_1000baseT_Full;
		if (pf->flags & I40E_FLAG_100M_SGMII_CAPABLE) {
			ecmd->supported |= SUPPORTED_100baseT_Full;
			if (hw_link_info->requested_speeds &
			    I40E_LINK_SPEED_100MB)
				ecmd->advertising |= ADVERTISED_100baseT_Full;
		}
		break;
	/* Backplane is set based on supported phy types in get_settings
	 * so don't set anything here but don't warn either
	 */
	case I40E_PHY_TYPE_40GBASE_KR4:
	case I40E_PHY_TYPE_20GBASE_KR2:
	case I40E_PHY_TYPE_10GBASE_KR:
	case I40E_PHY_TYPE_10GBASE_KX4:
	case I40E_PHY_TYPE_1000BASE_KX:
		break;
	default:
		/* if we got here and link is up something bad is afoot */
		netdev_info(netdev, "WARNING: Link is up but PHY type 0x%x is not recognized.\n",
			    hw_link_info->phy_type);
	}

	/* Set speed and duplex */
	switch (link_speed) {
	case I40E_LINK_SPEED_40GB:
		ethtool_cmd_speed_set(ecmd, SPEED_40000);
		break;
	case I40E_LINK_SPEED_20GB:
		ethtool_cmd_speed_set(ecmd, SPEED_20000);
		break;
	case I40E_LINK_SPEED_10GB:
		ethtool_cmd_speed_set(ecmd, SPEED_10000);
		break;
	case I40E_LINK_SPEED_1GB:
		ethtool_cmd_speed_set(ecmd, SPEED_1000);
		break;
	case I40E_LINK_SPEED_100MB:
		ethtool_cmd_speed_set(ecmd, SPEED_100);
		break;
	default:
		break;
	}
	ecmd->duplex = DUPLEX_FULL;
}

/**
 * i40e_get_settings_link_down - Get the Link settings for when link is down
 * @hw: hw structure
 * @ecmd: ethtool command to fill in
 *
 * Reports link settings that can be determined when link is down
 **/
static void i40e_get_settings_link_down(struct i40e_hw *hw,
					struct ethtool_cmd *ecmd, struct i40e_pf *pf)
{
	enum i40e_aq_capabilities_phy_type phy_types = hw->phy.phy_types;

	/* link is down and the driver needs to fall back on
	 * supported phy types to figure out what info to display
	 */
	ecmd->supported = 0x0;
	ecmd->advertising = 0x0;
	if (phy_types & I40E_CAP_PHY_TYPE_SGMII) {
		ecmd->supported |= SUPPORTED_Autoneg |
				SUPPORTED_1000baseT_Full;
		ecmd->advertising |= ADVERTISED_Autoneg |
				     ADVERTISED_1000baseT_Full;
		if (pf->flags & I40E_FLAG_100M_SGMII_CAPABLE) {
			ecmd->supported |= SUPPORTED_100baseT_Full;
			ecmd->advertising |= ADVERTISED_100baseT_Full;
		}
	}
	if (phy_types & I40E_CAP_PHY_TYPE_XAUI ||
	    phy_types & I40E_CAP_PHY_TYPE_XFI ||
	    phy_types & I40E_CAP_PHY_TYPE_SFI ||
	    phy_types & I40E_CAP_PHY_TYPE_10GBASE_SFPP_CU ||
	    phy_types & I40E_CAP_PHY_TYPE_10GBASE_AOC)
		ecmd->supported |= SUPPORTED_10000baseT_Full;
	if (phy_types & I40E_CAP_PHY_TYPE_10GBASE_CR1_CU ||
	    phy_types & I40E_CAP_PHY_TYPE_10GBASE_CR1 ||
	    phy_types & I40E_CAP_PHY_TYPE_10GBASE_T ||
	    phy_types & I40E_CAP_PHY_TYPE_10GBASE_SR ||
	    phy_types & I40E_CAP_PHY_TYPE_10GBASE_LR) {
		ecmd->supported |= SUPPORTED_Autoneg |
				   SUPPORTED_10000baseT_Full;
		ecmd->advertising |= ADVERTISED_Autoneg |
				     ADVERTISED_10000baseT_Full;
	}
	if (phy_types & I40E_CAP_PHY_TYPE_XLAUI ||
	    phy_types & I40E_CAP_PHY_TYPE_XLPPI ||
	    phy_types & I40E_CAP_PHY_TYPE_40GBASE_AOC)
		ecmd->supported |= SUPPORTED_40000baseCR4_Full;
	if (phy_types & I40E_CAP_PHY_TYPE_40GBASE_CR4_CU ||
	    phy_types & I40E_CAP_PHY_TYPE_40GBASE_CR4) {
		ecmd->supported |= SUPPORTED_Autoneg |
				  SUPPORTED_40000baseCR4_Full;
		ecmd->advertising |= ADVERTISED_Autoneg |
				    ADVERTISED_40000baseCR4_Full;
	}
	if ((phy_types & I40E_CAP_PHY_TYPE_100BASE_TX) &&
	    !(phy_types & I40E_CAP_PHY_TYPE_1000BASE_T)) {
		ecmd->supported |= SUPPORTED_Autoneg |
				   SUPPORTED_100baseT_Full;
		ecmd->advertising |= ADVERTISED_Autoneg |
				     ADVERTISED_100baseT_Full;
	}
	if (phy_types & I40E_CAP_PHY_TYPE_1000BASE_T ||
	    phy_types & I40E_CAP_PHY_TYPE_1000BASE_SX ||
	    phy_types & I40E_CAP_PHY_TYPE_1000BASE_LX ||
	    phy_types & I40E_CAP_PHY_TYPE_1000BASE_T_OPTICAL) {
		ecmd->supported |= SUPPORTED_Autoneg |
				   SUPPORTED_1000baseT_Full;
		ecmd->advertising |= ADVERTISED_Autoneg |
				     ADVERTISED_1000baseT_Full;
	}
	if (phy_types & I40E_CAP_PHY_TYPE_40GBASE_SR4)
		ecmd->supported |= SUPPORTED_40000baseSR4_Full;
	if (phy_types & I40E_CAP_PHY_TYPE_40GBASE_LR4)
		ecmd->supported |= SUPPORTED_40000baseLR4_Full;

	/* With no link speed and duplex are unknown */
	ethtool_cmd_speed_set(ecmd, SPEED_UNKNOWN);
	ecmd->duplex = DUPLEX_UNKNOWN;
}

/**
 * i40e_get_settings - Get Link Speed and Duplex settings
 * @netdev: network interface device structure
 * @ecmd: ethtool command
 *
 * Reports speed/duplex settings based on media_type
 **/
static int i40e_get_settings(struct net_device *netdev,
			     struct ethtool_cmd *ecmd)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;
	struct i40e_hw *hw = &pf->hw;
	struct i40e_link_status *hw_link_info = &hw->phy.link_info;
	bool link_up = hw_link_info->link_info & I40E_AQ_LINK_UP;

	if (link_up)
		i40e_get_settings_link_up(hw, ecmd, netdev, pf);
	else
		i40e_get_settings_link_down(hw, ecmd, pf);

	/* Now set the settings that don't rely on link being up/down */

	/* For backplane, supported and advertised are only reliant on the
	 * phy types the NVM specifies are supported.
	 */
	if (hw->device_id == I40E_DEV_ID_KX_B ||
	    hw->device_id == I40E_DEV_ID_KX_C ||
	    hw->device_id == I40E_DEV_ID_20G_KR2 ||
	    hw->device_id ==  I40E_DEV_ID_20G_KR2_A) {
		ecmd->supported = SUPPORTED_Autoneg;
		ecmd->advertising = ADVERTISED_Autoneg;
		if (hw->phy.phy_types & I40E_CAP_PHY_TYPE_40GBASE_KR4) {
			ecmd->supported |= SUPPORTED_40000baseKR4_Full;
			ecmd->advertising |= ADVERTISED_40000baseKR4_Full;
		}
		if (hw->phy.phy_types & I40E_CAP_PHY_TYPE_20GBASE_KR2) {
			ecmd->supported |= SUPPORTED_20000baseKR2_Full;
			ecmd->advertising |= ADVERTISED_20000baseKR2_Full;
		}
		if (hw->phy.phy_types & I40E_CAP_PHY_TYPE_10GBASE_KR) {
			ecmd->supported |= SUPPORTED_10000baseKR_Full;
			ecmd->advertising |= ADVERTISED_10000baseKR_Full;
		}
		if (hw->phy.phy_types & I40E_CAP_PHY_TYPE_10GBASE_KX4) {
			ecmd->supported |= SUPPORTED_10000baseKX4_Full;
			ecmd->advertising |= ADVERTISED_10000baseKX4_Full;
		}
		if (hw->phy.phy_types & I40E_CAP_PHY_TYPE_1000BASE_KX) {
			ecmd->supported |= SUPPORTED_1000baseKX_Full;
			ecmd->advertising |= ADVERTISED_1000baseKX_Full;
		}
	}

	/* Set autoneg settings */
	ecmd->autoneg = (hw_link_info->an_info & I40E_AQ_AN_COMPLETED ?
			  AUTONEG_ENABLE : AUTONEG_DISABLE);

	/* Set media type settings */
	switch (hw->phy.media_type) {
	case I40E_MEDIA_TYPE_BACKPLANE:
		ecmd->supported |= SUPPORTED_Autoneg |
				   SUPPORTED_Backplane;
		ecmd->advertising |= ADVERTISED_Autoneg |
				     ADVERTISED_Backplane;
		ecmd->port = PORT_NONE;
		break;
	case I40E_MEDIA_TYPE_BASET:
		ecmd->supported |= SUPPORTED_TP;
		ecmd->advertising |= ADVERTISED_TP;
		ecmd->port = PORT_TP;
		break;
	case I40E_MEDIA_TYPE_DA:
	case I40E_MEDIA_TYPE_CX4:
		ecmd->supported |= SUPPORTED_FIBRE;
		ecmd->advertising |= ADVERTISED_FIBRE;
		ecmd->port = PORT_DA;
		break;
	case I40E_MEDIA_TYPE_FIBER:
		ecmd->supported |= SUPPORTED_FIBRE;
		ecmd->port = PORT_FIBRE;
		break;
	case I40E_MEDIA_TYPE_UNKNOWN:
	default:
		ecmd->port = PORT_OTHER;
		break;
	}

	/* Set transceiver */
	ecmd->transceiver = XCVR_EXTERNAL;

	/* Set flow control settings */
	ecmd->supported |= SUPPORTED_Pause;

	switch (hw->fc.requested_mode) {
	case I40E_FC_FULL:
		ecmd->advertising |= ADVERTISED_Pause;
		break;
	case I40E_FC_TX_PAUSE:
		ecmd->advertising |= ADVERTISED_Asym_Pause;
		break;
	case I40E_FC_RX_PAUSE:
		ecmd->advertising |= (ADVERTISED_Pause |
				      ADVERTISED_Asym_Pause);
		break;
	default:
		ecmd->advertising &= ~(ADVERTISED_Pause |
				       ADVERTISED_Asym_Pause);
		break;
	}

	return 0;
}

/**
 * i40e_set_settings - Set Speed and Duplex
 * @netdev: network interface device structure
 * @ecmd: ethtool command
 *
 * Set speed/duplex per media_types advertised/forced
 **/
static int i40e_set_settings(struct net_device *netdev,
			     struct ethtool_cmd *ecmd)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_aq_get_phy_abilities_resp abilities;
	struct i40e_aq_set_phy_config config;
	struct i40e_pf *pf = np->vsi->back;
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_hw *hw = &pf->hw;
	struct ethtool_cmd safe_ecmd;
	i40e_status status = 0;
	bool change = false;
	int err = 0;
	u8 autoneg;
	u32 advertise;
	u32 old_ethtool_advertising = 0;

	/* Changing port settings is not supported if this isn't the
	 * port's controlling PF
	 */
	if (hw->partition_id != 1) {
		i40e_partition_setting_complaint(pf);
		return -EOPNOTSUPP;
	}

	if (vsi != pf->vsi[pf->lan_vsi])
		return -EOPNOTSUPP;

	if (hw->phy.media_type != I40E_MEDIA_TYPE_BASET &&
	    hw->phy.media_type != I40E_MEDIA_TYPE_FIBER &&
	    hw->phy.media_type != I40E_MEDIA_TYPE_BACKPLANE &&
	    hw->phy.link_info.link_info & I40E_AQ_LINK_UP)
		return -EOPNOTSUPP;

	if (hw->device_id == I40E_DEV_ID_KX_B ||
	    hw->device_id == I40E_DEV_ID_KX_C ||
	    hw->device_id == I40E_DEV_ID_20G_KR2 ||
	    hw->device_id == I40E_DEV_ID_20G_KR2_A) {
		netdev_info(netdev, "Changing settings is not supported on backplane.\n");
		return -EOPNOTSUPP;
	}

	/* get our own copy of the bits to check against */
	memset(&safe_ecmd, 0, sizeof(struct ethtool_cmd));
	i40e_get_settings(netdev, &safe_ecmd);

	/* save autoneg and speed out of ecmd */
	autoneg = ecmd->autoneg;
	advertise = ecmd->advertising;

	/* set autoneg and speed back to what they currently are */
	ecmd->autoneg = safe_ecmd.autoneg;
	ecmd->advertising = safe_ecmd.advertising;

	/* Due to a bug in ethtool versions < 3.6 this check is necessary */
	old_ethtool_advertising = ecmd->supported &
				  (ADVERTISED_10baseT_Half |
				   ADVERTISED_10baseT_Full |
				   ADVERTISED_100baseT_Half |
				   ADVERTISED_100baseT_Full |
				   ADVERTISED_1000baseT_Half |
				   ADVERTISED_1000baseT_Full |
				   ADVERTISED_2500baseX_Full |
				   ADVERTISED_10000baseT_Full);
	old_ethtool_advertising |= (old_ethtool_advertising |
				   ADVERTISED_20000baseMLD2_Full |
				   ADVERTISED_20000baseKR2_Full);

	if (advertise == old_ethtool_advertising)
		netdev_info(netdev, "If you are not setting advertising to %x then you may have an old version of ethtool. Please update.\n",
			    advertise);
	ecmd->cmd = safe_ecmd.cmd;
	/* If ecmd and safe_ecmd are not the same now, then they are
	 * trying to set something that we do not support
	 */
	if (memcmp(ecmd, &safe_ecmd, sizeof(struct ethtool_cmd)))
		return -EOPNOTSUPP;

	while (test_bit(__I40E_CONFIG_BUSY, &vsi->state))
		usleep_range(1000, 2000);

	/* Get the current phy config */
	status = i40e_aq_get_phy_capabilities(hw, false, false, &abilities,
					      NULL);
	if (status)
		return -EAGAIN;

	/* Copy abilities to config in case autoneg is not
	 * set below
	 */
	memset(&config, 0, sizeof(struct i40e_aq_set_phy_config));
	config.abilities = abilities.abilities;

	/* Check autoneg */
	if (autoneg == AUTONEG_ENABLE) {
		/* If autoneg was not already enabled */
		if (!(hw->phy.link_info.an_info & I40E_AQ_AN_COMPLETED)) {
			/* If autoneg is not supported, return error */
			if (!(safe_ecmd.supported & SUPPORTED_Autoneg)) {
				netdev_info(netdev, "Autoneg not supported on this phy\n");
				return -EINVAL;
			}
			/* Autoneg is allowed to change */
			config.abilities = abilities.abilities |
					   I40E_AQ_PHY_ENABLE_AN;
			change = true;
		}
	} else {
		/* If autoneg is currently enabled */
		if (hw->phy.link_info.an_info & I40E_AQ_AN_COMPLETED) {
			/* If autoneg is supported 10GBASE_T is the only phy
			 * that can disable it, so otherwise return error
			 */
			if (safe_ecmd.supported & SUPPORTED_Autoneg &&
			    hw->phy.link_info.phy_type != I40E_PHY_TYPE_10GBASE_T) {
				netdev_info(netdev, "Autoneg cannot be disabled on this phy\n");
				return -EINVAL;
			}
			/* Autoneg is allowed to change */
			config.abilities = abilities.abilities &
					   ~I40E_AQ_PHY_ENABLE_AN;
			change = true;
		}
	}

	if (advertise & ~safe_ecmd.supported)
		return -EINVAL;

	if (advertise & ADVERTISED_100baseT_Full)
		config.link_speed |= I40E_LINK_SPEED_100MB;
	if (advertise & ADVERTISED_1000baseT_Full ||
	    advertise & ADVERTISED_1000baseKX_Full)
		config.link_speed |= I40E_LINK_SPEED_1GB;
	if (advertise & ADVERTISED_10000baseT_Full ||
	    advertise & ADVERTISED_10000baseKX4_Full ||
	    advertise & ADVERTISED_10000baseKR_Full)
		config.link_speed |= I40E_LINK_SPEED_10GB;
	if (advertise & ADVERTISED_20000baseKR2_Full)
		config.link_speed |= I40E_LINK_SPEED_20GB;
	if (advertise & ADVERTISED_40000baseKR4_Full ||
	    advertise & ADVERTISED_40000baseCR4_Full ||
	    advertise & ADVERTISED_40000baseSR4_Full ||
	    advertise & ADVERTISED_40000baseLR4_Full)
		config.link_speed |= I40E_LINK_SPEED_40GB;

	/* If speed didn't get set, set it to what it currently is.
	 * This is needed because if advertise is 0 (as it is when autoneg
	 * is disabled) then speed won't get set.
	 */
	if (!config.link_speed)
		config.link_speed = abilities.link_speed;

	if (change || (abilities.link_speed != config.link_speed)) {
		/* copy over the rest of the abilities */
		config.phy_type = abilities.phy_type;
		config.eee_capability = abilities.eee_capability;
		config.eeer = abilities.eeer_val;
		config.low_power_ctrl = abilities.d3_lpan;

		/* save the requested speeds */
		hw->phy.link_info.requested_speeds = config.link_speed;
		/* set link and auto negotiation so changes take effect */
		config.abilities |= I40E_AQ_PHY_ENABLE_ATOMIC_LINK;
		/* If link is up put link down */
		if (hw->phy.link_info.link_info & I40E_AQ_LINK_UP) {
			/* Tell the OS link is going down, the link will go
			 * back up when fw says it is ready asynchronously
			 */
			i40e_print_link_message(vsi, false);
			netif_carrier_off(netdev);
			netif_tx_stop_all_queues(netdev);
		}

		/* make the aq call */
		status = i40e_aq_set_phy_config(hw, &config, NULL);
		if (status) {
			netdev_info(netdev, "Set phy config failed, err %s aq_err %s\n",
				    i40e_stat_str(hw, status),
				    i40e_aq_str(hw, hw->aq.asq_last_status));
			return -EAGAIN;
		}

		status = i40e_update_link_info(hw);
		if (status)
			netdev_dbg(netdev, "Updating link info failed with err %s aq_err %s\n",
				   i40e_stat_str(hw, status),
				   i40e_aq_str(hw, hw->aq.asq_last_status));

	} else {
		netdev_info(netdev, "Nothing changed, exiting without setting anything.\n");
	}

	return err;
}

static int i40e_nway_reset(struct net_device *netdev)
{
	/* restart autonegotiation */
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;
	struct i40e_hw *hw = &pf->hw;
	bool link_up = hw->phy.link_info.link_info & I40E_AQ_LINK_UP;
	i40e_status ret = 0;

	ret = i40e_aq_set_link_restart_an(hw, link_up, NULL);
	if (ret) {
		netdev_info(netdev, "link restart failed, err %s aq_err %s\n",
			    i40e_stat_str(hw, ret),
			    i40e_aq_str(hw, hw->aq.asq_last_status));
		return -EIO;
	}

	return 0;
}

/**
 * i40e_get_pauseparam -  Get Flow Control status
 * Return tx/rx-pause status
 **/
static void i40e_get_pauseparam(struct net_device *netdev,
				struct ethtool_pauseparam *pause)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;
	struct i40e_hw *hw = &pf->hw;
	struct i40e_dcbx_config *dcbx_cfg = &hw->local_dcbx_config;

	pause->autoneg = hw->phy.link_info.an_info & I40E_AQ_AN_COMPLETED;

	/* PFC enabled so report LFC as off */
	if (dcbx_cfg->pfc.pfcenable) {
		pause->rx_pause = 0;
		pause->tx_pause = 0;
		return;
	}

	if (hw->fc.current_mode == I40E_FC_RX_PAUSE) {
		pause->rx_pause = 1;
	} else if (hw->fc.current_mode == I40E_FC_TX_PAUSE) {
		pause->tx_pause = 1;
	} else if (hw->fc.current_mode == I40E_FC_FULL) {
		pause->rx_pause = 1;
		pause->tx_pause = 1;
	}
}

/**
 * i40e_set_pauseparam - Set Flow Control parameter
 * @netdev: network interface device structure
 * @pause: return tx/rx flow control status
 **/
static int i40e_set_pauseparam(struct net_device *netdev,
			       struct ethtool_pauseparam *pause)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_hw *hw = &pf->hw;
	struct i40e_link_status *hw_link_info = &hw->phy.link_info;
	struct i40e_dcbx_config *dcbx_cfg = &hw->local_dcbx_config;
	bool link_up = hw_link_info->link_info & I40E_AQ_LINK_UP;
	i40e_status status;
	u8 aq_failures;
	int err = 0;

	/* Changing the port's flow control is not supported if this isn't the
	 * port's controlling PF
	 */
	if (hw->partition_id != 1) {
		i40e_partition_setting_complaint(pf);
		return -EOPNOTSUPP;
	}

	if (vsi != pf->vsi[pf->lan_vsi])
		return -EOPNOTSUPP;

	if (pause->autoneg != (hw_link_info->an_info & I40E_AQ_AN_COMPLETED)) {
		netdev_info(netdev, "To change autoneg please use: ethtool -s <dev> autoneg <on|off>\n");
		return -EOPNOTSUPP;
	}

	/* If we have link and don't have autoneg */
	if (!test_bit(__I40E_DOWN, &pf->state) &&
	    !(hw_link_info->an_info & I40E_AQ_AN_COMPLETED)) {
		/* Send message that it might not necessarily work*/
		netdev_info(netdev, "Autoneg did not complete so changing settings may not result in an actual change.\n");
	}

	if (dcbx_cfg->pfc.pfcenable) {
		netdev_info(netdev,
			 "Priority flow control enabled. Cannot set link flow control.\n");
		return -EOPNOTSUPP;
	}

	if (pause->rx_pause && pause->tx_pause)
		hw->fc.requested_mode = I40E_FC_FULL;
	else if (pause->rx_pause && !pause->tx_pause)
		hw->fc.requested_mode = I40E_FC_RX_PAUSE;
	else if (!pause->rx_pause && pause->tx_pause)
		hw->fc.requested_mode = I40E_FC_TX_PAUSE;
	else if (!pause->rx_pause && !pause->tx_pause)
		hw->fc.requested_mode = I40E_FC_NONE;
	else
		 return -EINVAL;

	/* Tell the OS link is going down, the link will go back up when fw
	 * says it is ready asynchronously
	 */
	i40e_print_link_message(vsi, false);
	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	/* Set the fc mode and only restart an if link is up*/
	status = i40e_set_fc(hw, &aq_failures, link_up);

	if (aq_failures & I40E_SET_FC_AQ_FAIL_GET) {
		netdev_info(netdev, "Set fc failed on the get_phy_capabilities call with err %s aq_err %s\n",
			    i40e_stat_str(hw, status),
			    i40e_aq_str(hw, hw->aq.asq_last_status));
		err = -EAGAIN;
	}
	if (aq_failures & I40E_SET_FC_AQ_FAIL_SET) {
		netdev_info(netdev, "Set fc failed on the set_phy_config call with err %s aq_err %s\n",
			    i40e_stat_str(hw, status),
			    i40e_aq_str(hw, hw->aq.asq_last_status));
		err = -EAGAIN;
	}
	if (aq_failures & I40E_SET_FC_AQ_FAIL_UPDATE) {
		netdev_info(netdev, "Set fc failed on the get_link_info call with err %s aq_err %s\n",
			    i40e_stat_str(hw, status),
			    i40e_aq_str(hw, hw->aq.asq_last_status));
		err = -EAGAIN;
	}

	if (!test_bit(__I40E_DOWN, &pf->state)) {
		/* Give it a little more time to try to come back */
		msleep(75);
		if (!test_bit(__I40E_DOWN, &pf->state))
			return i40e_nway_reset(netdev);
	}

	return err;
}

#ifndef HAVE_NDO_SET_FEATURES
static u32 i40e_get_rx_csum(struct net_device *netdev)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;

	return pf->flags & I40E_FLAG_RX_CSUM_ENABLED;
}

static int i40e_set_rx_csum(struct net_device *netdev, u32 data)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;

	if (data)
		pf->flags |= I40E_FLAG_RX_CSUM_ENABLED;
	else
		pf->flags &= ~I40E_FLAG_RX_CSUM_ENABLED;

	return 0;
}

static u32 i40e_get_tx_csum(struct net_device *netdev)
{
	return (netdev->features & NETIF_F_IP_CSUM) != 0;
}

static int i40e_set_tx_csum(struct net_device *netdev, u32 data)
{
	if (data) {
#ifdef NETIF_F_IPV6_CSUM
		netdev->features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
#else
		netdev->features |= NETIF_F_IP_CSUM;
#endif
		netdev->features |= NETIF_F_SCTP_CRC;
	} else {
#ifdef NETIF_F_IPV6_CSUM
		netdev->features &= ~(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
				      NETIF_F_SCTP_CRC);
#else
		netdev->features &= ~(NETIF_F_IP_CSUM | NETIF_F_SCTP_CRC);
#endif
	}

	return 0;
}

static int i40e_set_tso(struct net_device *netdev, u32 data)
{
	if (data) {
		netdev->features |= NETIF_F_TSO;
		netdev->features |= NETIF_F_TSO6;
	} else {
#ifndef HAVE_NETDEV_VLAN_FEATURES
		struct i40e_netdev_priv *np = netdev_priv(netdev);
		/* disable TSO on all VLANs if they're present */
		if (np->vsi->vlgrp) {
			int i;
			struct net_device *v_netdev;

			for (i = 0; i < VLAN_GROUP_ARRAY_LEN; i++) {
				v_netdev =
				       vlan_group_get_device(np->vsi->vlgrp, i);
				if (v_netdev) {
					v_netdev->features &= ~NETIF_F_TSO;
					v_netdev->features &= ~NETIF_F_TSO6;
					vlan_group_set_device(np->vsi->vlgrp, i,
							      v_netdev);
				}
			}
		}
#endif /* HAVE_NETDEV_VLAN_FEATURES */
		netdev->features &= ~NETIF_F_TSO;
		netdev->features &= ~NETIF_F_TSO6;
	}

	return 0;
}
#ifdef ETHTOOL_GFLAGS
static int i40e_set_flags(struct net_device *netdev, u32 data)
{
#ifdef ETHTOOL_GRXRINGS
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;
#endif
	u32 supported_flags = 0;
	bool need_reset = false;
	int rc;

#ifdef NETIF_F_RXHASH
	supported_flags |= ETH_FLAG_RXHASH;

#endif
#ifdef ETHTOOL_GRXRINGS
	if (!(pf->flags & I40E_FLAG_MFP_ENABLED))
		supported_flags |= ETH_FLAG_NTUPLE;
#endif
	rc = ethtool_op_set_flags(netdev, data, supported_flags);
	if (rc)
		return rc;

	/* if state changes we need to update pf->flags and maybe reset */
#ifdef ETHTOOL_GRXRINGS
	need_reset = i40e_set_ntuple(pf, netdev->features);
#endif /* ETHTOOL_GRXRINGS */
	if (need_reset)
		i40e_do_reset(pf, BIT(__I40E_PF_RESET_REQUESTED));

	return 0;
}
#endif /* ETHTOOL_GFLAGS */

#endif /* HAVE_NDO_SET_FEATURES */
static u32 i40e_get_msglevel(struct net_device *netdev)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;

	return pf->msg_enable;
}

static void i40e_set_msglevel(struct net_device *netdev, u32 data)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;

	if (I40E_DEBUG_USER & data)
		pf->hw.debug_mask = data;
	pf->msg_enable = data;
}

static int i40e_get_regs_len(struct net_device *netdev)
{
	int reg_count = 0;
	int i;

	for (i = 0; i40e_reg_list[i].offset != 0; i++)
		reg_count += i40e_reg_list[i].elements;

	return reg_count * sizeof(u32);
}

static void i40e_get_regs(struct net_device *netdev, struct ethtool_regs *regs,
			  void *p)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;
	struct i40e_hw *hw = &pf->hw;
	u32 *reg_buf = p;
	unsigned int i, j, ri;
	u32 reg;

	/* Tell ethtool which driver-version-specific regs output we have.
	 *
	 * At some point, if we have ethtool doing special formatting of
	 * this data, it will rely on this version number to know how to
	 * interpret things.  Hence, this needs to be updated if/when the
	 * diags register table is changed.
	 */
	regs->version = 1;

	/* loop through the diags reg table for what to print */
	ri = 0;
	for (i = 0; i40e_reg_list[i].offset != 0; i++) {
		for (j = 0; j < i40e_reg_list[i].elements; j++) {
			reg = i40e_reg_list[i].offset
				+ (j * i40e_reg_list[i].stride);
			reg_buf[ri++] = rd32(hw, reg);
		}
	}

}

static int i40e_get_eeprom(struct net_device *netdev,
			   struct ethtool_eeprom *eeprom, u8 *bytes)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_hw *hw = &np->vsi->back->hw;
	struct i40e_pf *pf = np->vsi->back;
	int ret_val = 0, len, offset;
	u8 *eeprom_buff;
	u16 i, sectors;
	bool last;
	u32 magic;

#define I40E_NVM_SECTOR_SIZE  4096
	if (eeprom->len == 0)
		return -EINVAL;

	/* check for NVMUpdate access method */
	magic = hw->vendor_id | (hw->device_id << 16);
	if (eeprom->magic && eeprom->magic != magic) {
		struct i40e_nvm_access *cmd = (struct i40e_nvm_access *)eeprom;
		int errno = 0;

		/* make sure it is the right magic for NVMUpdate */
		if ((eeprom->magic >> 16) != hw->device_id)
			errno = -EINVAL;
		else if (test_bit(__I40E_RESET_RECOVERY_PENDING, &pf->state) ||
			 test_bit(__I40E_RESET_INTR_RECEIVED, &pf->state))
			errno = -EBUSY;
		else
			ret_val = i40e_nvmupd_command(hw, cmd, bytes, &errno);

		if ((errno || ret_val) && (hw->debug_mask & I40E_DEBUG_NVM))
			dev_info(&pf->pdev->dev,
				 "NVMUpdate read failed err=%d status=0x%x errno=%d module=%d offset=0x%x size=%d\n",
				 ret_val, hw->aq.asq_last_status, errno,
				 (u8)(cmd->config & I40E_NVM_MOD_PNT_MASK),
				 cmd->offset, cmd->data_size);

		return errno;
	}

	/* normal ethtool get_eeprom support */
	eeprom->magic = hw->vendor_id | (hw->device_id << 16);

	eeprom_buff = kzalloc(eeprom->len, GFP_KERNEL);
	if (!eeprom_buff)
		return -ENOMEM;

	ret_val = i40e_acquire_nvm(hw, I40E_RESOURCE_READ);
	if (ret_val) {
		dev_info(&pf->pdev->dev,
			 "Failed Acquiring NVM resource for read err=%d status=0x%x\n",
			 ret_val, hw->aq.asq_last_status);
		goto free_buff;
	}

	sectors = eeprom->len / I40E_NVM_SECTOR_SIZE;
	sectors += (eeprom->len % I40E_NVM_SECTOR_SIZE) ? 1 : 0;
	len = I40E_NVM_SECTOR_SIZE;
	last = false;
	for (i = 0; i < sectors; i++) {
		if (i == (sectors - 1)) {
			len = eeprom->len - (I40E_NVM_SECTOR_SIZE * i);
			last = true;
		}
		offset = eeprom->offset + (I40E_NVM_SECTOR_SIZE * i),
		ret_val = i40e_aq_read_nvm(hw, 0x0, offset, len,
				(u8 *)eeprom_buff + (I40E_NVM_SECTOR_SIZE * i),
				last, NULL);
		if (ret_val && hw->aq.asq_last_status == I40E_AQ_RC_EPERM) {
			dev_info(&pf->pdev->dev,
				 "read NVM failed, invalid offset 0x%x\n",
				 offset);
			break;
		} else if (ret_val &&
			   hw->aq.asq_last_status == I40E_AQ_RC_EACCES) {
			dev_info(&pf->pdev->dev,
				 "read NVM failed, access, offset 0x%x\n",
				 offset);
			break;
		} else if (ret_val) {
			dev_info(&pf->pdev->dev,
				 "read NVM failed offset %d err=%d status=0x%x\n",
				 offset, ret_val, hw->aq.asq_last_status);
			break;
		}
	}

	i40e_release_nvm(hw);
	memcpy(bytes, (u8 *)eeprom_buff, eeprom->len);
free_buff:
	kfree(eeprom_buff);
	return ret_val;
}

static int i40e_get_eeprom_len(struct net_device *netdev)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_hw *hw = &np->vsi->back->hw;
	u32 val;

	val = (rd32(hw, I40E_GLPCI_LBARCTRL)
		& I40E_GLPCI_LBARCTRL_FL_SIZE_MASK)
		>> I40E_GLPCI_LBARCTRL_FL_SIZE_SHIFT;
	/* register returns value in power of 2, 64Kbyte chunks. */
	val = (64 * 1024) * BIT(val);
	return val;
}

static int i40e_set_eeprom(struct net_device *netdev,
			   struct ethtool_eeprom *eeprom, u8 *bytes)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_hw *hw = &np->vsi->back->hw;
	struct i40e_pf *pf = np->vsi->back;
	struct i40e_nvm_access *cmd = (struct i40e_nvm_access *)eeprom;
	int ret_val = 0;
	int errno = 0;
	u32 magic;

	/* normal ethtool set_eeprom is not supported */
	magic = hw->vendor_id | (hw->device_id << 16);
	if (eeprom->magic == magic)
		errno = -EOPNOTSUPP;
	/* check for NVMUpdate access method */
	else if (!eeprom->magic || (eeprom->magic >> 16) != hw->device_id)
		errno = -EINVAL;
	else if (test_bit(__I40E_RESET_RECOVERY_PENDING, &pf->state) ||
		 test_bit(__I40E_RESET_INTR_RECEIVED, &pf->state))
		errno = -EBUSY;
	else
		ret_val = i40e_nvmupd_command(hw, cmd, bytes, &errno);

	if ((errno || ret_val) && (hw->debug_mask & I40E_DEBUG_NVM))
		dev_info(&pf->pdev->dev,
			 "NVMUpdate write failed err=%d status=0x%x errno=%d module=%d offset=0x%x size=%d\n",
			 ret_val, hw->aq.asq_last_status, errno,
			 (u8)(cmd->config & I40E_NVM_MOD_PNT_MASK),
			 cmd->offset, cmd->data_size);

	return errno;
}

static void i40e_get_drvinfo(struct net_device *netdev,
			     struct ethtool_drvinfo *drvinfo)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;

	strlcpy(drvinfo->driver, i40e_driver_name, sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, i40e_driver_version_str,
		sizeof(drvinfo->version));
	strlcpy(drvinfo->fw_version, i40e_nvm_version_str(&pf->hw),
		sizeof(drvinfo->fw_version));
	strlcpy(drvinfo->bus_info, pci_name(pf->pdev),
		sizeof(drvinfo->bus_info));
#ifdef HAVE_ETHTOOL_GET_SSET_COUNT
	if (pf->hw.pf_id == 0)
		drvinfo->n_priv_flags = I40E_PRIV_FLAGS_GL_STR_LEN;
	else
		drvinfo->n_priv_flags = I40E_PRIV_FLAGS_STR_LEN;
#endif
}

static void i40e_get_ringparam(struct net_device *netdev,
			       struct ethtool_ringparam *ring)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;
	struct i40e_vsi *vsi = pf->vsi[pf->lan_vsi];

	ring->rx_max_pending = I40E_MAX_NUM_DESCRIPTORS;
	ring->tx_max_pending = I40E_MAX_NUM_DESCRIPTORS;
	ring->rx_mini_max_pending = 0;
	ring->rx_jumbo_max_pending = 0;
	ring->rx_pending = vsi->rx_rings[0]->count;
	ring->tx_pending = vsi->tx_rings[0]->count;
	ring->rx_mini_pending = 0;
	ring->rx_jumbo_pending = 0;
}

static int i40e_set_ringparam(struct net_device *netdev,
			      struct ethtool_ringparam *ring)
{
	struct i40e_ring *tx_rings = NULL, *rx_rings = NULL;
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;
	u32 new_rx_count, new_tx_count;
	int i, err = 0;

	if ((ring->rx_mini_pending) || (ring->rx_jumbo_pending))
		return -EINVAL;

	if (ring->tx_pending > I40E_MAX_NUM_DESCRIPTORS ||
	    ring->tx_pending < I40E_MIN_NUM_DESCRIPTORS ||
	    ring->rx_pending > I40E_MAX_NUM_DESCRIPTORS ||
	    ring->rx_pending < I40E_MIN_NUM_DESCRIPTORS) {
		netdev_info(netdev,
			    "Descriptors requested (Tx: %d / Rx: %d) out of range [%d-%d]\n",
			    ring->tx_pending, ring->rx_pending,
			    I40E_MIN_NUM_DESCRIPTORS, I40E_MAX_NUM_DESCRIPTORS);
		return -EINVAL;
	}

	new_tx_count = ALIGN(ring->tx_pending, I40E_REQ_DESCRIPTOR_MULTIPLE);
	new_rx_count = ALIGN(ring->rx_pending, I40E_REQ_DESCRIPTOR_MULTIPLE);

	/* if nothing to do return success */
	if ((new_tx_count == vsi->tx_rings[0]->count) &&
	    (new_rx_count == vsi->rx_rings[0]->count))
		return 0;

	while (test_and_set_bit(__I40E_CONFIG_BUSY, &pf->state))
		usleep_range(1000, 2000);

	if (!netif_running(vsi->netdev)) {
		/* simple case - set for the next time the netdev is started */
		for (i = 0; i < vsi->num_queue_pairs; i++) {
			vsi->tx_rings[i]->count = new_tx_count;
			vsi->rx_rings[i]->count = new_rx_count;
		}
		goto done;
	}

	/* We can't just free everything and then setup again,
	 * because the ISRs in MSI-X mode get passed pointers
	 * to the Tx and Rx ring structs.
	 */

	/* alloc updated Tx resources */
	if (new_tx_count != vsi->tx_rings[0]->count) {
		netdev_info(netdev,
			    "Changing Tx descriptor count from %d to %d\n",
			    vsi->tx_rings[0]->count, new_tx_count);
		tx_rings = kcalloc(vsi->alloc_queue_pairs,
				   sizeof(struct i40e_ring), GFP_KERNEL);
		if (!tx_rings) {
			err = -ENOMEM;
			goto done;
		}

		for (i = 0; i < vsi->num_queue_pairs; i++) {
			/* clone ring and setup updated count */
			tx_rings[i] = *vsi->tx_rings[i];
			tx_rings[i].count = new_tx_count;
			/* the desc and bi pointers will be reallocated in the
			 * setup call
			 */
			tx_rings[i].desc = NULL;
			tx_rings[i].rx_bi = NULL;
			err = i40e_setup_tx_descriptors(&tx_rings[i]);
			if (err) {
				while (i) {
					i--;
					i40e_free_tx_resources(&tx_rings[i]);
				}
				kfree(tx_rings);
				tx_rings = NULL;

				goto done;
			}
		}
	}

	/* alloc updated Rx resources */
	if (new_rx_count != vsi->rx_rings[0]->count) {
		netdev_info(netdev,
			    "Changing Rx descriptor count from %d to %d\n",
			    vsi->rx_rings[0]->count, new_rx_count);
		rx_rings = kcalloc(vsi->alloc_queue_pairs,
				   sizeof(struct i40e_ring), GFP_KERNEL);
		if (!rx_rings) {
			err = -ENOMEM;
			goto free_tx;
		}

		for (i = 0; i < vsi->num_queue_pairs; i++) {
			/* this is to allow wr32 to have something to write to
			 * during early allocation of rx buffers
			 */
			u32 __iomem faketail = 0;
			struct i40e_ring *ring;
			u16 unused;

			/* clone ring and setup updated count */
			rx_rings[i] = *vsi->rx_rings[i];
			rx_rings[i].count = new_rx_count;
			/* the desc and bi pointers will be reallocated in the
			 * setup call
			 */
			rx_rings[i].desc = NULL;
			rx_rings[i].rx_bi = NULL;
			rx_rings[i].tail = (u8 __iomem *)&faketail;
			err = i40e_setup_rx_descriptors(&rx_rings[i]);
			if (err)
				goto rx_unwind;

			/* now allocate the rx buffers to make sure the OS
			 * has enough memory, any failure here means abort
			 */
			ring = &rx_rings[i];
			unused = I40E_DESC_UNUSED(ring);
			err = i40e_alloc_rx_buffers(ring, unused);
rx_unwind:
			if (err) {
				do {
					i40e_free_rx_resources(&rx_rings[i]);
				} while (i--);
				kfree(rx_rings);
				rx_rings = NULL;

				goto free_tx;
			}
		}
	}

	/* Bring interface down, copy in the new ring info,
	 * then restore the interface
	 */
	i40e_down(vsi);

	if (tx_rings) {
		for (i = 0; i < vsi->num_queue_pairs; i++) {
			i40e_free_tx_resources(vsi->tx_rings[i]);
			*vsi->tx_rings[i] = tx_rings[i];
		}
		kfree(tx_rings);
		tx_rings = NULL;
	}

	if (rx_rings) {
		for (i = 0; i < vsi->num_queue_pairs; i++) {
			i40e_free_rx_resources(vsi->rx_rings[i]);
			/* get the real tail offset */
			rx_rings[i].tail = vsi->rx_rings[i]->tail;
			/* this is to fake out the allocation routine
			 * into thinking it has to realloc everything
			 * but the recycling logic will let us re-use
			 * the buffers allocated above
			 */
			rx_rings[i].next_to_use = 0;
			rx_rings[i].next_to_clean = 0;
			rx_rings[i].next_to_alloc = 0;
			/* do a struct copy */
			*vsi->rx_rings[i] = rx_rings[i];
		}
		kfree(rx_rings);
		rx_rings = NULL;
	}

	i40e_up(vsi);

free_tx:
	/* error cleanup if the Rx allocations failed after getting Tx */
	if (tx_rings) {
		for (i = 0; i < vsi->num_queue_pairs; i++)
			i40e_free_tx_resources(&tx_rings[i]);
		kfree(tx_rings);
		tx_rings = NULL;
	}

done:
	clear_bit(__I40E_CONFIG_BUSY, &pf->state);

	return err;
}

#ifndef HAVE_ETHTOOL_GET_SSET_COUNT
static int i40e_get_stats_count(struct net_device *netdev)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;

	if (vsi == pf->vsi[pf->lan_vsi] && pf->hw.partition_id == 1) {
		if ((pf->lan_veb != I40E_NO_VEB) &&
		    (pf->flags & I40E_FLAG_VEB_STATS_ENABLED))
			return I40E_PF_STATS_LEN(netdev) + I40E_VEB_STATS_TOTAL;
		else
			return I40E_PF_STATS_LEN(netdev);
	else
		return I40E_VSI_STATS_LEN(netdev);
}

#else /* HAVE_ETHTOOL_GET_SSET_COUNT */
static int i40e_get_sset_count(struct net_device *netdev, int sset)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;

	switch (sset) {
	case ETH_SS_TEST:
		return I40E_TEST_LEN;
	case ETH_SS_STATS:
		if (vsi == pf->vsi[pf->lan_vsi] && pf->hw.partition_id == 1) {
			int len = I40E_PF_STATS_LEN(netdev);

			if ((pf->lan_veb != I40E_NO_VEB) &&
			    (pf->flags & I40E_FLAG_VEB_STATS_ENABLED))
				len += I40E_VEB_STATS_TOTAL;
			return len;
		} else {
			return I40E_VSI_STATS_LEN(netdev);
		}
	case ETH_SS_PRIV_FLAGS:
		if (pf->hw.pf_id == 0)
			return I40E_PRIV_FLAGS_GL_STR_LEN;
		else
			return I40E_PRIV_FLAGS_STR_LEN;
	default:
		return -EOPNOTSUPP;
	}
}

#endif /* HAVE_ETHTOOL_GET_SSET_COUNT */
static void i40e_get_ethtool_stats(struct net_device *netdev,
				   struct ethtool_stats *stats, u64 *data)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_ring *tx_ring, *rx_ring;
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;
	int i = 0;
	char *p;
	unsigned int j;

#ifdef HAVE_NDO_GET_STATS64
	struct rtnl_link_stats64 *net_stats = i40e_get_vsi_stats_struct(vsi);
	unsigned int start;
#else
	struct net_device_stats *net_stats = i40e_get_vsi_stats_struct(vsi);
#endif

	i40e_update_stats(vsi);

	for (j = 0; j < I40E_NETDEV_STATS_LEN; j++) {
		p = (char *)net_stats + i40e_gstrings_net_stats[j].stat_offset;
		data[i++] = (i40e_gstrings_net_stats[j].sizeof_stat ==
			sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
	}
	for (j = 0; j < I40E_MISC_STATS_LEN; j++) {
		p = (char *)vsi + i40e_gstrings_misc_stats[j].stat_offset;
		data[i++] = (i40e_gstrings_misc_stats[j].sizeof_stat ==
			    sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
	}
#ifdef I40E_FCOE
	for (j = 0; j < I40E_FCOE_STATS_LEN; j++) {
		p = (char *)vsi + i40e_gstrings_fcoe_stats[j].stat_offset;
		data[i++] = (i40e_gstrings_fcoe_stats[j].sizeof_stat ==
			sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
	}
#endif
	rcu_read_lock();
	for (j = 0; j < vsi->num_queue_pairs; j++) {
		tx_ring = ACCESS_ONCE(vsi->tx_rings[j]);

		if (!tx_ring)
			continue;

		/* process Tx ring statistics */
#ifdef HAVE_NDO_GET_STATS64
		do {
			start = u64_stats_fetch_begin_irq(&tx_ring->syncp);
#endif
			data[i] = tx_ring->stats.packets;
			data[i + 1] = tx_ring->stats.bytes;
#ifdef HAVE_NDO_GET_STATS64
		} while (u64_stats_fetch_retry_irq(&tx_ring->syncp, start));
#endif
		i += 2;

		/* Rx ring is the 2nd half of the queue pair */
		rx_ring = &tx_ring[1];
#ifdef HAVE_NDO_GET_STATS64
		do {
			start = u64_stats_fetch_begin_irq(&rx_ring->syncp);
#endif
			data[i] = rx_ring->stats.packets;
			data[i + 1] = rx_ring->stats.bytes;
#ifdef HAVE_NDO_GET_STATS64
		} while (u64_stats_fetch_retry_irq(&rx_ring->syncp, start));
#endif
		i += 2;
	}
	rcu_read_unlock();
	if (vsi != pf->vsi[pf->lan_vsi] || pf->hw.partition_id != 1)
		return;

	if ((pf->lan_veb != I40E_NO_VEB) &&
	    (pf->flags & I40E_FLAG_VEB_STATS_ENABLED)) {
		struct i40e_veb *veb = pf->veb[pf->lan_veb];

		for (j = 0; j < I40E_VEB_STATS_LEN; j++) {
			p = (char *)veb;
			p += i40e_gstrings_veb_stats[j].stat_offset;
			data[i++] = (i40e_gstrings_veb_stats[j].sizeof_stat ==
				     sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
		}
		for (j = 0; j < I40E_MAX_TRAFFIC_CLASS; j++) {
			data[i++] = veb->tc_stats.tc_tx_packets[j];
			data[i++] = veb->tc_stats.tc_tx_bytes[j];
			data[i++] = veb->tc_stats.tc_rx_packets[j];
			data[i++] = veb->tc_stats.tc_rx_bytes[j];
		}
	}
	for (j = 0; j < I40E_GLOBAL_STATS_LEN; j++) {
		p = (char *)pf + i40e_gstrings_stats[j].stat_offset;
		data[i++] = (i40e_gstrings_stats[j].sizeof_stat ==
			     sizeof(u64)) ? *(u64 *)p : *(u32 *)p;
	}
	for (j = 0; j < I40E_MAX_USER_PRIORITY; j++) {
		data[i++] = pf->stats.priority_xon_tx[j];
		data[i++] = pf->stats.priority_xoff_tx[j];
	}
	for (j = 0; j < I40E_MAX_USER_PRIORITY; j++) {
		data[i++] = pf->stats.priority_xon_rx[j];
		data[i++] = pf->stats.priority_xoff_rx[j];
	}
	for (j = 0; j < I40E_MAX_USER_PRIORITY; j++)
		data[i++] = pf->stats.priority_xon_2_xoff[j];
}

static void i40e_get_strings(struct net_device *netdev, u32 stringset,
			     u8 *data)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;
	char *p = (char *)data;
	unsigned int i;

	switch (stringset) {
	case ETH_SS_TEST:
		for (i = 0; i < I40E_TEST_LEN; i++) {
			memcpy(data, i40e_gstrings_test[i], ETH_GSTRING_LEN);
			data += ETH_GSTRING_LEN;
		}
		break;
	case ETH_SS_STATS:
		for (i = 0; i < I40E_NETDEV_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 i40e_gstrings_net_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}
		for (i = 0; i < I40E_MISC_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 i40e_gstrings_misc_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}
#ifdef I40E_FCOE
		for (i = 0; i < I40E_FCOE_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "%s",
				 i40e_gstrings_fcoe_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}
#endif
		for (i = 0; i < vsi->num_queue_pairs; i++) {
			snprintf(p, ETH_GSTRING_LEN, "tx-%u.tx_packets", i);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN, "tx-%u.tx_bytes", i);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN, "rx-%u.rx_packets", i);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN, "rx-%u.rx_bytes", i);
			p += ETH_GSTRING_LEN;
		}
		if (vsi != pf->vsi[pf->lan_vsi] || pf->hw.partition_id != 1)
			return;

		if ((pf->lan_veb != I40E_NO_VEB) &&
		    (pf->flags & I40E_FLAG_VEB_STATS_ENABLED)) {
			for (i = 0; i < I40E_VEB_STATS_LEN; i++) {
				snprintf(p, ETH_GSTRING_LEN, "veb.%s",
					i40e_gstrings_veb_stats[i].stat_string);
				p += ETH_GSTRING_LEN;
			}
			for (i = 0; i < I40E_MAX_TRAFFIC_CLASS; i++) {
				snprintf(p, ETH_GSTRING_LEN,
					 "veb.tc_%u_tx_packets", i);
				p += ETH_GSTRING_LEN;
				snprintf(p, ETH_GSTRING_LEN,
					 "veb.tc_%u_tx_bytes", i);
				p += ETH_GSTRING_LEN;
				snprintf(p, ETH_GSTRING_LEN,
					 "veb.tc_%u_rx_packets", i);
				p += ETH_GSTRING_LEN;
				snprintf(p, ETH_GSTRING_LEN,
					 "veb.tc_%u_rx_bytes", i);
				p += ETH_GSTRING_LEN;
			}
		}
		for (i = 0; i < I40E_GLOBAL_STATS_LEN; i++) {
			snprintf(p, ETH_GSTRING_LEN, "port.%s",
				 i40e_gstrings_stats[i].stat_string);
			p += ETH_GSTRING_LEN;
		}
		for (i = 0; i < I40E_MAX_USER_PRIORITY; i++) {
			snprintf(p, ETH_GSTRING_LEN,
				 "port.tx_priority_%u_xon", i);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN,
				 "port.tx_priority_%u_xoff", i);
			p += ETH_GSTRING_LEN;
		}
		for (i = 0; i < I40E_MAX_USER_PRIORITY; i++) {
			snprintf(p, ETH_GSTRING_LEN,
				 "port.rx_priority_%u_xon", i);
			p += ETH_GSTRING_LEN;
			snprintf(p, ETH_GSTRING_LEN,
				 "port.rx_priority_%u_xoff", i);
			p += ETH_GSTRING_LEN;
		}
		for (i = 0; i < I40E_MAX_USER_PRIORITY; i++) {
			snprintf(p, ETH_GSTRING_LEN,
				 "port.rx_priority_%u_xon_2_xoff", i);
			p += ETH_GSTRING_LEN;
		}
		/* BUG_ON(p - data != I40E_STATS_LEN * ETH_GSTRING_LEN); */
		break;
#ifdef HAVE_ETHTOOL_GET_SSET_COUNT
	case ETH_SS_PRIV_FLAGS:
		if (pf->hw.pf_id == 0) {
			for (i = 0; i < I40E_PRIV_FLAGS_GL_STR_LEN; i++) {
				memcpy(data, i40e_priv_flags_strings_gl[i],
				       ETH_GSTRING_LEN);
				data += ETH_GSTRING_LEN;
			}
		} else {
			for (i = 0; i < I40E_PRIV_FLAGS_STR_LEN; i++) {
				memcpy(data, i40e_priv_flags_strings[i],
				       ETH_GSTRING_LEN);
				data += ETH_GSTRING_LEN;
			}
		}
		break;
#endif
	default:
		break;
	}
}

#ifdef HAVE_ETHTOOL_GET_TS_INFO
static int i40e_get_ts_info(struct net_device *dev,
			    struct ethtool_ts_info *info)
{
#ifdef HAVE_PTP_1588_CLOCK
	struct i40e_pf *pf = i40e_netdev_to_pf(dev);

	/* only report HW timestamping if PTP is enabled */
	if (!(pf->flags & I40E_FLAG_PTP))
		return ethtool_op_get_ts_info(dev, info);

	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
				SOF_TIMESTAMPING_RX_SOFTWARE |
				SOF_TIMESTAMPING_SOFTWARE |
				SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;

	if (pf->ptp_clock)
		info->phc_index = ptp_clock_index(pf->ptp_clock);
	else
		info->phc_index = -1;

	info->tx_types = BIT(HWTSTAMP_TX_OFF) | BIT(HWTSTAMP_TX_ON);

	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) |
			   BIT(HWTSTAMP_FILTER_PTP_V1_L4_SYNC) |
			   BIT(HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_EVENT) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L2_EVENT) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L4_EVENT) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_SYNC) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L2_SYNC) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L4_SYNC) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_DELAY_REQ) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ) |
			   BIT(HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ);

	return 0;
#else /* HAVE_PTP_1588_CLOCK */
	return ethtool_op_get_ts_info(dev, info);
#endif /* HAVE_PTP_1588_CLOCK */
}

#endif /* HAVE_ETHTOOL_GET_TS_INFO */
static int i40e_link_test(struct net_device *netdev, u64 *data)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;
	i40e_status status;
	bool link_up = false;

	netif_info(pf, hw, netdev, "link test\n");
	status = i40e_get_link_status(&pf->hw, &link_up);
	if (status != I40E_SUCCESS) {
		netif_err(pf, drv, netdev, "link query timed out, please retry test\n");
		*data = 1;
		return *data;
	}

	if (link_up)
		*data = 0;
	else
		*data = 1;

	return *data;
}

static int i40e_reg_test(struct net_device *netdev, u64 *data)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;

	netif_info(pf, hw, netdev, "register test\n");
	*data = i40e_diag_reg_test(&pf->hw);

	return *data;
}

static int i40e_eeprom_test(struct net_device *netdev, u64 *data)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;

	netif_info(pf, hw, netdev, "eeprom test\n");
	*data = i40e_diag_eeprom_test(&pf->hw);

	/* forcebly clear the NVM Update state machine */
	pf->hw.nvmupd_state = I40E_NVMUPD_STATE_INIT;

	return *data;
}

static int i40e_intr_test(struct net_device *netdev, u64 *data)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;
	u16 swc_old = pf->sw_int_count;

	netif_info(pf, hw, netdev, "interrupt test\n");
	wr32(&pf->hw, I40E_PFINT_DYN_CTL0,
	     (I40E_PFINT_DYN_CTL0_INTENA_MASK |
	      I40E_PFINT_DYN_CTL0_SWINT_TRIG_MASK |
	      I40E_PFINT_DYN_CTL0_ITR_INDX_MASK |
	      I40E_PFINT_DYN_CTL0_SW_ITR_INDX_ENA_MASK |
	      I40E_PFINT_DYN_CTL0_SW_ITR_INDX_MASK));
	usleep_range(1000, 2000);
	*data = (swc_old == pf->sw_int_count);

	return *data;
}

static int i40e_loopback_test(struct net_device *netdev, u64 *data)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;

	netif_info(pf, hw, netdev, "loopback test not implemented\n");
	*data = 0;

	return *data;
}

#ifndef HAVE_ETHTOOL_GET_SSET_COUNT
static int i40e_diag_test_count(struct net_device *netdev)
{
	return I40E_TEST_LEN;
}

#endif /* HAVE_ETHTOOL_GET_SSET_COUNT */
static inline bool i40e_active_vfs(struct i40e_pf *pf)
{
	struct i40e_vf *vfs = pf->vf;
	int i;

	for (i = 0; i < pf->num_alloc_vfs; i++)
		if (test_bit(I40E_VF_STAT_ACTIVE, &vfs[i].vf_states))
			return true;
	return false;
}

static inline bool i40e_active_vmdqs(struct i40e_pf *pf)
{
	struct i40e_vsi **vsi = pf->vsi;
	int i;

	for (i = 0; i < pf->num_alloc_vsi; i++) {
		if (!vsi[i])
			continue;
		if (vsi[i]->type == I40E_VSI_VMDQ2)
			return true;
	}

	return false;
}

static void i40e_diag_test(struct net_device *netdev,
			   struct ethtool_test *eth_test, u64 *data)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	bool if_running = netif_running(netdev);
	struct i40e_pf *pf = np->vsi->back;

	if (eth_test->flags == ETH_TEST_FL_OFFLINE) {
		/* Offline tests */
		netif_info(pf, drv, netdev, "offline testing starting\n");

		set_bit(__I40E_TESTING, &pf->state);

		if (i40e_active_vfs(pf) || i40e_active_vmdqs(pf)) {
			dev_warn(&pf->pdev->dev,
				 "Please take active VFs and Netqueues offline and restart the adapter before running NIC diagnostics\n");
			data[I40E_ETH_TEST_REG]		= 1;
			data[I40E_ETH_TEST_EEPROM]	= 1;
			data[I40E_ETH_TEST_INTR]	= 1;
			data[I40E_ETH_TEST_LOOPBACK]	= 1;
			data[I40E_ETH_TEST_LINK]	= 1;
			eth_test->flags |= ETH_TEST_FL_FAILED;
			clear_bit(__I40E_TESTING, &pf->state);
			goto skip_ol_tests;
		}

		/* If the device is online then take it offline */
		if (if_running)
			/* indicate we're in test mode */
			i40e_close(netdev);
		else
			/* This reset does not affect link - if it is
			 * changed to a type of reset that does affect
			 * link then the following link test would have
			 * to be moved to before the reset
			 */
			i40e_do_reset(pf, BIT(__I40E_PF_RESET_REQUESTED));

		if (i40e_link_test(netdev, &data[I40E_ETH_TEST_LINK]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		if (i40e_eeprom_test(netdev, &data[I40E_ETH_TEST_EEPROM]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		if (i40e_intr_test(netdev, &data[I40E_ETH_TEST_INTR]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		if (i40e_loopback_test(netdev, &data[I40E_ETH_TEST_LOOPBACK]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		/* run reg test last, a reset is required after it */
		if (i40e_reg_test(netdev, &data[I40E_ETH_TEST_REG]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		clear_bit(__I40E_TESTING, &pf->state);
		i40e_do_reset(pf, BIT(__I40E_PF_RESET_REQUESTED));

		if (if_running)
			i40e_open(netdev);
	} else {
		/* Online tests */
		netif_info(pf, drv, netdev, "online testing starting\n");

		if (i40e_link_test(netdev, &data[I40E_ETH_TEST_LINK]))
			eth_test->flags |= ETH_TEST_FL_FAILED;

		/* Offline only tests, not run in online; pass by default */
		data[I40E_ETH_TEST_REG] = 0;
		data[I40E_ETH_TEST_EEPROM] = 0;
		data[I40E_ETH_TEST_INTR] = 0;
		data[I40E_ETH_TEST_LOOPBACK] = 0;
	}

skip_ol_tests:

	netif_info(pf, drv, netdev, "testing finished\n");
}

static void i40e_get_wol(struct net_device *netdev,
			 struct ethtool_wolinfo *wol)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;
	struct i40e_hw *hw = &pf->hw;
	u16 wol_nvm_bits;

	/* NVM bit on means WoL disabled for the port */
	i40e_read_nvm_word(hw, I40E_SR_NVM_WAKE_ON_LAN, &wol_nvm_bits);
	if ((BIT(hw->port) & wol_nvm_bits) || (hw->partition_id != 1)) {
		wol->supported = 0;
		wol->wolopts = 0;
	} else {
		wol->supported = WAKE_MAGIC;
		wol->wolopts = (pf->wol_en ? WAKE_MAGIC : 0);
	}
}

/**
 * i40e_set_wol - set the WakeOnLAN configuration
 * @netdev: the netdev in question
 * @wol: the ethtool WoL setting data
 **/
static int i40e_set_wol(struct net_device *netdev, struct ethtool_wolinfo *wol)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_hw *hw = &pf->hw;
	u16 wol_nvm_bits;

	/* WoL not supported if this isn't the controlling PF on the port */
	if (hw->partition_id != 1) {
		i40e_partition_setting_complaint(pf);
		return -EOPNOTSUPP;
	}

	if (vsi != pf->vsi[pf->lan_vsi])
		return -EOPNOTSUPP;

	/* NVM bit on means WoL disabled for the port */
	i40e_read_nvm_word(hw, I40E_SR_NVM_WAKE_ON_LAN, &wol_nvm_bits);
	if (BIT(hw->port) & wol_nvm_bits)
		return -EOPNOTSUPP;

	/* only magic packet is supported */
	if (wol->wolopts && (wol->wolopts != WAKE_MAGIC))
		return -EOPNOTSUPP;

	/* is this a new value? */
	if (pf->wol_en != !!wol->wolopts) {
		pf->wol_en = !!wol->wolopts;
		device_set_wakeup_enable(&pf->pdev->dev, pf->wol_en);
	}

	return 0;
}

#ifdef HAVE_ETHTOOL_SET_PHYS_ID
static int i40e_set_phys_id(struct net_device *netdev,
			    enum ethtool_phys_id_state state)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	i40e_status ret = I40E_SUCCESS;
	struct i40e_pf *pf = np->vsi->back;
	struct i40e_hw *hw = &pf->hw;
	int blink_freq = 2;
	u16 temp_status;

	switch (state) {
	case ETHTOOL_ID_ACTIVE:
		if (!(pf->flags & I40E_FLAG_HAVE_10GBASET_PHY)) {
			pf->led_status = i40e_led_get(hw);
		} else {
			i40e_aq_set_phy_debug(hw, I40E_PHY_DEBUG_PORT, NULL);
			ret = i40e_led_get_phy(hw, &temp_status,
					       &pf->phy_led_val);
			pf->led_status = temp_status;
		}
		return blink_freq;
	case ETHTOOL_ID_ON:
		if (!(pf->flags & I40E_FLAG_HAVE_10GBASET_PHY))
			i40e_led_set(hw, 0xf, false);
		else
			ret = i40e_led_set_phy(hw, true, pf->led_status, 0);
		break;
	case ETHTOOL_ID_OFF:
		if (!(pf->flags & I40E_FLAG_HAVE_10GBASET_PHY))
			i40e_led_set(hw, 0x0, false);
		else
			ret = i40e_led_set_phy(hw, false, pf->led_status, 0);
		break;
	case ETHTOOL_ID_INACTIVE:
		if (!(pf->flags & I40E_FLAG_HAVE_10GBASET_PHY)) {
			i40e_led_set(hw, false, pf->led_status);
		} else {
			ret = i40e_led_set_phy(hw, false, pf->led_status,
					       (pf->phy_led_val |
					       I40E_PHY_LED_MODE_ORIG));
			i40e_aq_set_phy_debug(hw, 0, NULL);
		}
		break;
	default:
		break;
	}
		if (ret)
			return -ENOENT;
		else
			return 0;
}
#else /* HAVE_ETHTOOL_SET_PHYS_ID */
static int i40e_phys_id(struct net_device *netdev, u32 data)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_pf *pf = np->vsi->back;
	struct i40e_hw *hw = &pf->hw;
	i40e_status ret = I40E_SUCCESS;
	u16 temp_status;
	int i;

	if (!(pf->flags & I40E_FLAG_HAVE_10GBASET_PHY)) {
		pf->led_status = i40e_led_get(hw);
	} else {
		ret = i40e_led_get_phy(hw, &temp_status,
				       &pf->phy_led_val);
		pf->led_status = temp_status;
	}

	if (!data || data > 300)
		data = 300;

	/* 10GBaseT PHY controls led's through PHY, not MAC */
	for (i = 0; i < (data * 1000); i += 400) {
		if (!(pf->flags & I40E_FLAG_HAVE_10GBASET_PHY))
			i40e_led_set(hw, 0xF, false);
		else
			ret = i40e_led_set_phy(hw, true, pf->led_status, 0);
		msleep_interruptible(200);
		if (!(pf->flags & I40E_FLAG_HAVE_10GBASET_PHY))
			i40e_led_set(hw, 0x0, false);
		else
			ret = i40e_led_set_phy(hw, false, pf->led_status, 0);
		msleep_interruptible(200);
	}
	if (!(pf->flags & I40E_FLAG_HAVE_10GBASET_PHY))
		i40e_led_set(hw, pf->led_status, false);
	else
		ret = i40e_led_set_phy(hw, false, pf->led_status,
				       (pf->led_status |
				       I40E_PHY_LED_MODE_ORIG));

	if (ret)
		return -ENOENT;
	else
		return 0;
}
#endif /* HAVE_ETHTOOL_SET_PHYS_ID */

/* NOTE: i40e hardware uses a conversion factor of 2 for Interrupt
 * Throttle Rate (ITR) ie. ITR(1) = 2us ITR(10) = 20 us, and also
 * 125us (8000 interrupts per second) == ITR(62)
 */

static int i40e_get_coalesce(struct net_device *netdev,
			     struct ethtool_coalesce *ec)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_vsi *vsi = np->vsi;

	ec->tx_max_coalesced_frames_irq = vsi->work_limit;
	ec->rx_max_coalesced_frames_irq = vsi->work_limit;

	if (ITR_IS_DYNAMIC(vsi->rx_itr_setting))
		ec->use_adaptive_rx_coalesce = 1;

	if (ITR_IS_DYNAMIC(vsi->tx_itr_setting))
		ec->use_adaptive_tx_coalesce = 1;

	ec->rx_coalesce_usecs = vsi->rx_itr_setting & ~I40E_ITR_DYNAMIC;
	ec->tx_coalesce_usecs = vsi->tx_itr_setting & ~I40E_ITR_DYNAMIC;
	/* we use the _usecs_high to store/set the interrupt rate limit
	 * that the hardware supports, that almost but not quite
	 * fits the original intent of the ethtool variable,
	 * the rx_coalesce_usecs_high limits total interrupts
	 * per second from both tx/rx sources.
	 */
	ec->rx_coalesce_usecs_high = vsi->int_rate_limit;
	ec->tx_coalesce_usecs_high = vsi->int_rate_limit;

	return 0;
}

static int i40e_set_coalesce(struct net_device *netdev,
			     struct ethtool_coalesce *ec)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_q_vector *q_vector;
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;
	struct i40e_hw *hw = &pf->hw;
	u16 vector;
	int i;

	if (ec->tx_max_coalesced_frames_irq || ec->rx_max_coalesced_frames_irq)
		vsi->work_limit = ec->tx_max_coalesced_frames_irq;

	/* tx_coalesce_usecs_high is ignored, use rx-usecs-high to adjust limit */
	if (ec->tx_coalesce_usecs_high != vsi->int_rate_limit) {
		netif_info(pf, drv, netdev, "tx-usecs-high is not used, please program rx-usecs-high\n");
		return -EINVAL;
	}

	if (ec->rx_coalesce_usecs_high >= INTRL_REG_TO_USEC(I40E_MAX_INTRL)) {
		netif_info(pf, drv, netdev, "Invalid value, rx-usecs-high range is 0-235\n");
		return -EINVAL;
	}

	vector = vsi->base_vector;
	if ((ec->rx_coalesce_usecs >= (I40E_MIN_ITR << 1)) &&
	    (ec->rx_coalesce_usecs <= (I40E_MAX_ITR << 1))) {
		vsi->rx_itr_setting = ec->rx_coalesce_usecs;
	} else if (ec->rx_coalesce_usecs == 0) {
		vsi->rx_itr_setting = ec->rx_coalesce_usecs;
		if (ec->use_adaptive_rx_coalesce)
			netif_info(pf, drv, netdev, "rx-usecs=0, need to disable adaptive-rx for a complete disable\n");
	} else {
		netif_info(pf, drv, netdev, "Invalid value, rx-usecs range is 0-8160\n");
		return -EINVAL;
	}

	vsi->int_rate_limit = ec->rx_coalesce_usecs_high;

	if ((ec->tx_coalesce_usecs >= (I40E_MIN_ITR << 1)) &&
	    (ec->tx_coalesce_usecs <= (I40E_MAX_ITR << 1))) {
		vsi->tx_itr_setting = ec->tx_coalesce_usecs;
	} else if (ec->tx_coalesce_usecs == 0) {
		vsi->tx_itr_setting = ec->tx_coalesce_usecs;
		if (ec->use_adaptive_tx_coalesce)
			netif_info(pf, drv, netdev, "tx-usecs=0, need to disable adaptive-tx for a complete disable\n");
	} else {
		netif_info(pf, drv, netdev, "Invalid value, tx-usecs range is 0-8160\n");
		return -EINVAL;
	}

	if (ec->use_adaptive_rx_coalesce)
		vsi->rx_itr_setting |= I40E_ITR_DYNAMIC;
	else
		vsi->rx_itr_setting &= ~I40E_ITR_DYNAMIC;

	if (ec->use_adaptive_tx_coalesce)
		vsi->tx_itr_setting |= I40E_ITR_DYNAMIC;
	else
		vsi->tx_itr_setting &= ~I40E_ITR_DYNAMIC;

	for (i = 0; i < vsi->num_q_vectors; i++, vector++) {
		u16 intrl = INTRL_USEC_TO_REG(vsi->int_rate_limit);

		q_vector = vsi->q_vectors[i];
		q_vector->rx.itr = ITR_TO_REG(vsi->rx_itr_setting);
		wr32(hw, I40E_PFINT_ITRN(0, vector - 1), q_vector->rx.itr);
		q_vector->tx.itr = ITR_TO_REG(vsi->tx_itr_setting);
		wr32(hw, I40E_PFINT_ITRN(1, vector - 1), q_vector->tx.itr);
		wr32(hw, I40E_PFINT_RATEN(vector - 1), intrl);
		i40e_flush(hw);
	}

	return 0;
}

#ifdef ETHTOOL_SRXNTUPLE
/* We need to keep this around for kernels 2.6.33 - 2.6.39 in order to avoid
 * a null pointer dereference as it was assumend if the NETIF_F_NTUPLE flag
 * was defined that this function was present.
 */
static int i40e_set_rx_ntuple(struct net_device *dev,
			      struct ethtool_rx_ntuple *cmd)
{
	return -EOPNOTSUPP;
}

#endif /* ETHTOOL_SRXNTUPLE */
#ifdef ETHTOOL_GRXRINGS
/**
 * i40e_get_rss_hash_opts - Get RSS hash Input Set for each flow type
 * @pf: pointer to the physical function struct
 * @cmd: ethtool rxnfc command
 *
 * Returns Success if the flow is supported, else Invalid Input.
 **/
static int i40e_get_rss_hash_opts(struct i40e_pf *pf, struct ethtool_rxnfc *cmd)
{
	struct i40e_hw *hw = &pf->hw;
	u8 flow_pctype = 0;
	u64 i_set = 0;

	cmd->data = 0;

	switch (cmd->flow_type) {
	case TCP_V4_FLOW:
		flow_pctype = I40E_FILTER_PCTYPE_NONF_IPV4_TCP;
		break;
	case UDP_V4_FLOW:
		flow_pctype = I40E_FILTER_PCTYPE_NONF_IPV4_UDP;
		break;
	case TCP_V6_FLOW:
		flow_pctype = I40E_FILTER_PCTYPE_NONF_IPV6_TCP;
		break;
	case UDP_V6_FLOW:
		flow_pctype = I40E_FILTER_PCTYPE_NONF_IPV6_UDP;
		break;
	case SCTP_V4_FLOW:
	case AH_ESP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case IPV4_FLOW:
	case SCTP_V6_FLOW:
	case AH_ESP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case IPV6_FLOW:
		/* Default is src/dest for IP, no matter the L4 hashing */
		cmd->data |= RXH_IP_SRC | RXH_IP_DST;
		break;
	default:
		return -EINVAL;
	}

	/* Read flow based hash input set register */
	if (flow_pctype) {
		i_set = (u64)i40e_read_rx_ctl(hw, I40E_GLQF_HASH_INSET(0,
					      flow_pctype)) |
			((u64)i40e_read_rx_ctl(hw, I40E_GLQF_HASH_INSET(1,
					       flow_pctype)) << 32);
	}

	/* Process bits of hash input set */
	if (i_set) {
		if (i_set & BIT_ULL(I40E_L4_SRC_SHIFT))
			cmd->data |= RXH_L4_B_0_1;
		if (i_set & BIT_ULL(I40E_L4_DST_SHIFT))
			cmd->data |= RXH_L4_B_2_3;

		if (cmd->flow_type == TCP_V4_FLOW ||
		    cmd->flow_type == UDP_V4_FLOW) {
			if (i_set & BIT_ULL(I40E_L3_SRC_SHIFT))
				cmd->data |= RXH_IP_SRC;
			if (i_set & BIT_ULL(I40E_L3_DST_SHIFT))
				cmd->data |= RXH_IP_DST;
		} else if (cmd->flow_type == TCP_V6_FLOW ||
			  cmd->flow_type == UDP_V6_FLOW) {
			if (i_set & BIT_ULL(I40E_L3_V6_SRC_SHIFT))
				cmd->data |= RXH_IP_SRC;
			if (i_set & BIT_ULL(I40E_L3_V6_DST_SHIFT))
				cmd->data |= RXH_IP_DST;
		}
	}

	return 0;
}

/**
 * i40e_get_rx_filter_ids - Populates the rule count of a command
 * @pf: Pointer to the physical function struct
 * @cmd: The command to get or set Rx flow classification rules
 * @rule_locs: Array of used rule locations
 *
 * This function populates both the total and actual rule count of
 * the ethtool flow classification command
 *
 * Returns 0 on success or -EMSGSIZE if entry not found
 **/
static int i40e_get_rx_filter_ids(struct i40e_pf *pf,
				  struct ethtool_rxnfc *cmd,
				  u32 *rule_locs)
{
	struct i40e_fdir_filter *f_rule;
	struct i40e_cloud_filter *c_rule;
	struct hlist_node *node2;
	unsigned int cnt = 0;

	/* report total rule count */
	cmd->data = i40e_get_fd_cnt_all(pf);

	hlist_for_each_entry_safe(f_rule, node2,
				  &pf->fdir_filter_list, fdir_node) {
		if (cnt == cmd->rule_cnt)
			return -EMSGSIZE;

		rule_locs[cnt] = f_rule->fd_id;
		cnt++;
	}

	/* find the cloud filter rule ids */
	hlist_for_each_entry_safe(c_rule, node2,
				  &pf->cloud_filter_list, cloud_node) {
		if (cnt == cmd->rule_cnt)
			return -EMSGSIZE;

		rule_locs[cnt] = c_rule->id;
		cnt++;
	}

	cmd->rule_cnt = cnt;

	return 0;
}

/**
 * i40e_get_ethtool_fdir_entry - Look up a filter based on Rx flow
 * @pf: Pointer to the physical function struct
 * @cmd: The command to get or set Rx flow classification rules
 *
 * This function looks up a filter based on the Rx flow classification
 * command and fills the flow spec info for it if found
 *
 * Returns 0 on success or -EINVAL if filter not found
 **/
static int i40e_get_ethtool_fdir_entry(struct i40e_pf *pf,
				       struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp =
			(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct i40e_fdir_filter *rule = NULL;
	struct hlist_node *node2;

	hlist_for_each_entry_safe(rule, node2,
				  &pf->fdir_filter_list, fdir_node) {
		if (fsp->location <= rule->fd_id)
			break;
	}

	if (!rule || fsp->location != rule->fd_id)
		return -EINVAL;

	fsp->flow_type = rule->flow_type;
	if (fsp->flow_type == IP_USER_FLOW) {
		fsp->h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
		fsp->h_u.usr_ip4_spec.proto = 0;
		fsp->m_u.usr_ip4_spec.proto = 0;
	}

	/* Reverse the src and dest notion, since the HW views them from
	 * Tx perspective where as the user expects it from Rx filter view.
	 */
	fsp->h_u.tcp_ip4_spec.psrc = rule->dst_port;
	fsp->h_u.tcp_ip4_spec.pdst = rule->src_port;
	fsp->h_u.tcp_ip4_spec.ip4src = rule->dst_ip[0];
	fsp->h_u.tcp_ip4_spec.ip4dst = rule->src_ip[0];

	if (rule->dest_ctl == I40E_FILTER_PROGRAM_DESC_DEST_DROP_PACKET)
		fsp->ring_cookie = RX_CLS_FLOW_DISC;
	else
		fsp->ring_cookie = rule->q_index;

	if (rule->dest_vsi != pf->vsi[pf->lan_vsi]->id) {
		struct i40e_vsi *vsi;

		vsi = i40e_find_vsi_from_id(pf, rule->dest_vsi);
		if (vsi && vsi->type == I40E_VSI_SRIOV) {
			fsp->h_ext.data[1] = cpu_to_be32(vsi->vf_id);
			fsp->m_ext.data[1] = cpu_to_be32(0x1);
		}
	}

	/* Present the value of user-def as part of get filters */
	if (i40e_is_flex_filter(rule)) {
		fsp->h_ext.data[1] = (__be32)((rule->flex_bytes[3] << 16) |
				      rule->flex_bytes[2]);
		fsp->m_ext.data[1] = (__be32)((rule->flex_mask[3] << 16) |
				      rule->flex_mask[2]);
		fsp->flow_type |= FLOW_EXT;
	}

	return 0;
}

#define VXLAN_PORT	8472

/**
 * i40e_get_cloud_filter_entry - get a cloud filter by loc
 * @pf: pointer to the physical function struct
 * @cmd: The command to get or set Rx flow classification rules
 *
 * get cloud filter by loc.
 * Returns 0 if success.
 **/
static int i40e_get_cloud_filter_entry(struct i40e_pf *pf,
				       struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp =
			(struct ethtool_rx_flow_spec *)&cmd->fs;
	static const u8 mac_broadcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	struct i40e_cloud_filter *rule, *filter = NULL;
	struct hlist_node *node2;
	__be32 tena;
	int i;

	hlist_for_each_entry_safe(rule, node2,
				  &pf->cloud_filter_list, cloud_node) {
		/* filter found */
		if (rule->id == fsp->location)
			filter = rule;

		/* bail out if we've passed the likely location in the list */
		if (rule->id >= fsp->location)
			break;

	}
	if (!filter) {
		dev_info(&pf->pdev->dev, "No cloud filter with loc %d\n",
			fsp->location);
		return -ENOENT;
	}

	/* check for VF as a cloud filter target */
	for (i = 0; i < pf->num_alloc_vsi; i++) {
		if (!pf->vsi[i] || pf->vsi[i]->seid != filter->seid)
			continue;

		if (pf->vsi[i]->type == I40E_VSI_SRIOV)
			fsp->h_ext.data[1] = cpu_to_be32(pf->vsi[i]->vf_id);
		else if (pf->vsi[i]->type == I40E_VSI_MAIN)
			fsp->h_ext.data[1] = cpu_to_be32(0xffff);
		break;
	}

	ether_addr_copy(fsp->h_u.ether_spec.h_dest, filter->outer_mac);
	ether_addr_copy(fsp->h_u.ether_spec.h_source, filter->inner_mac);

	tena = cpu_to_be32(filter->tenant_id);
	memcpy(&fsp->h_ext.data[0], &tena, sizeof(tena));

	fsp->ring_cookie = filter->queue_id;
	if (filter->flags & I40E_CLOUD_FIELD_OMAC)
		ether_addr_copy(fsp->m_u.ether_spec.h_dest, mac_broadcast);
	if (filter->flags & I40E_CLOUD_FIELD_IMAC)
		ether_addr_copy(fsp->m_u.ether_spec.h_source, mac_broadcast);
	if (filter->flags & I40E_CLOUD_FIELD_IVLAN)
		fsp->h_ext.vlan_tci = filter->inner_vlan;
	if (filter->flags & I40E_CLOUD_FIELD_TEN_ID)
		*(__be32 *)&fsp->h_ext.data[0] = cpu_to_be32(filter->tenant_id);
	else
		*(__be32 *)&fsp->h_ext.data[0] = cpu_to_be32(~0);

	if (filter->flags & I40E_CLOUD_FIELD_IIP) {
		fsp->flow_type = IP_USER_FLOW;
		fsp->h_u.usr_ip4_spec.ip4dst = filter->inner_ip[0];
		fsp->h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
	} else {
		fsp->flow_type = ETHER_FLOW;
	}

	fsp->flow_type |= FLOW_EXT;

	return 0;
}

/**
 * i40e_get_rxnfc - command to get RX flow classification rules
 * @netdev: network interface device structure
 * @cmd: ethtool rxnfc command
 *
 * Returns Success if the command is supported.
 **/
static int i40e_get_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd,
#ifdef HAVE_ETHTOOL_GET_RXNFC_VOID_RULE_LOCS
			  void *rule_locs)
#else
			  u32 *rule_locs)
#endif
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = vsi->num_queue_pairs;
		ret = 0;
		break;
	case ETHTOOL_GRXFH:
		ret = i40e_get_rss_hash_opts(pf, cmd);
		break;
	case ETHTOOL_GRXCLSRLCNT:
		cmd->rule_cnt = pf->fdir_pf_active_filters;
		cmd->rule_cnt += pf->num_cloud_filters;
		/* report total rule count */
		cmd->data = i40e_get_fd_cnt_all(pf);
		ret = 0;
		break;
	case ETHTOOL_GRXCLSRULE:
		ret = i40e_get_ethtool_fdir_entry(pf, cmd);
		/* if no such fdir filter then try the cloud list */
		if (ret)
			ret = i40e_get_cloud_filter_entry(pf, cmd);
		break;
	case ETHTOOL_GRXCLSRLALL:
#ifdef HAVE_ETHTOOL_GET_RXNFC_VOID_RULE_LOCS
		ret = i40e_get_rx_filter_ids(pf, cmd, (u32 *)rule_locs);
#else
		ret = i40e_get_rx_filter_ids(pf, cmd, rule_locs);
#endif
		break;
	default:
		break;
	}

	return ret;
}

/**
 * i40e_get_rss_hash_bits - Read RSS Hash bits from register
 * @nfc: pointer to user request
 * @i_setc bits currently set
 *
 * Returns value of bits to be set per user request
 **/
static u64 i40e_get_rss_hash_bits(struct ethtool_rxnfc *nfc, u64 i_setc)
{
	u64 i_set = i_setc;
	u64 src_l3 = 0, dst_l3 = 0;

	if (nfc->data & RXH_L4_B_0_1)
		i_set |= BIT_ULL(I40E_L4_SRC_SHIFT);
	else
		i_set &= ~BIT_ULL(I40E_L4_SRC_SHIFT);
	if (nfc->data & RXH_L4_B_2_3)
		i_set |= BIT_ULL(I40E_L4_DST_SHIFT);
	else
		i_set &= ~BIT_ULL(I40E_L4_DST_SHIFT);

	if (nfc->flow_type == TCP_V6_FLOW || nfc->flow_type == UDP_V6_FLOW) {
		src_l3 = I40E_L3_V6_SRC_SHIFT;
		dst_l3 = I40E_L3_V6_DST_SHIFT;
	} else if (nfc->flow_type == TCP_V4_FLOW ||
		  nfc->flow_type == UDP_V4_FLOW) {
		src_l3 = I40E_L3_SRC_SHIFT;
		dst_l3 = I40E_L3_DST_SHIFT;
	} else {
		/* Any other flow type are not supported here */
		return i_set;
	}

	if (nfc->data & RXH_IP_SRC)
		i_set |= BIT_ULL(src_l3);
	else
		i_set &= ~BIT_ULL(src_l3);
	if (nfc->data & RXH_IP_DST)
		i_set |= BIT_ULL(dst_l3);
	else
		i_set &= ~BIT_ULL(dst_l3);

	return i_set;
}

/**
 * i40e_set_rss_hash_opt - Enable/Disable flow types for RSS hash
 * @pf: pointer to the physical function struct
 * @cmd: ethtool rxnfc command
 *
 * Returns Success if the flow input set is supported.
 **/
static int i40e_set_rss_hash_opt(struct i40e_pf *pf, struct ethtool_rxnfc *nfc)
{
	struct i40e_hw *hw = &pf->hw;
	u64 hena = (u64)i40e_read_rx_ctl(hw, I40E_PFQF_HENA(0)) |
		   ((u64)i40e_read_rx_ctl(hw, I40E_PFQF_HENA(1)) << 32);
	u8 flow_pctype = 0;
	u64 i_set, i_setc;

	if (pf->flags & I40E_FLAG_MFP_ENABLED) {
		dev_err(&pf->pdev->dev,
			"Change of RSS hash input set is not supported when MFP mode is enabled\n");
		return -EOPNOTSUPP;
	}

	/* RSS does not support anything other than hashing
	 * to queues on src and dst IPs and ports
	 */
	if (nfc->data & ~(RXH_IP_SRC | RXH_IP_DST |
			  RXH_L4_B_0_1 | RXH_L4_B_2_3))
		return -EINVAL;

	switch (nfc->flow_type) {
	case TCP_V4_FLOW:
		flow_pctype = I40E_FILTER_PCTYPE_NONF_IPV4_TCP;
		if (pf->flags & I40E_FLAG_MULTIPLE_TCP_UDP_RSS_PCTYPE)
			hena |=
			  BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV4_TCP_SYN_NO_ACK);
		break;
	case TCP_V6_FLOW:
		flow_pctype = I40E_FILTER_PCTYPE_NONF_IPV6_TCP;
		if (pf->flags & I40E_FLAG_MULTIPLE_TCP_UDP_RSS_PCTYPE)
			hena |=
			  BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV4_TCP_SYN_NO_ACK);
		if (pf->flags & I40E_FLAG_MULTIPLE_TCP_UDP_RSS_PCTYPE)
			hena |=
			  BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV6_TCP_SYN_NO_ACK);
		break;
	case UDP_V4_FLOW:
		flow_pctype = I40E_FILTER_PCTYPE_NONF_IPV4_UDP;
		if (pf->flags & I40E_FLAG_MULTIPLE_TCP_UDP_RSS_PCTYPE)
			hena |=
			  BIT_ULL(I40E_FILTER_PCTYPE_NONF_UNICAST_IPV4_UDP) |
			  BIT_ULL(I40E_FILTER_PCTYPE_NONF_MULTICAST_IPV4_UDP);

		hena |= BIT_ULL(I40E_FILTER_PCTYPE_FRAG_IPV4);
		break;
	case UDP_V6_FLOW:
		flow_pctype = I40E_FILTER_PCTYPE_NONF_IPV6_UDP;
		if (pf->flags & I40E_FLAG_MULTIPLE_TCP_UDP_RSS_PCTYPE)
			hena |=
			  BIT_ULL(I40E_FILTER_PCTYPE_NONF_UNICAST_IPV6_UDP) |
			  BIT_ULL(I40E_FILTER_PCTYPE_NONF_MULTICAST_IPV6_UDP);

		hena |= BIT_ULL(I40E_FILTER_PCTYPE_FRAG_IPV6);
		break;
	case AH_ESP_V4_FLOW:
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case SCTP_V4_FLOW:
		if ((nfc->data & RXH_L4_B_0_1) ||
		    (nfc->data & RXH_L4_B_2_3))
			return -EINVAL;
		hena |= BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV4_OTHER);
		break;
	case AH_ESP_V6_FLOW:
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case SCTP_V6_FLOW:
		if ((nfc->data & RXH_L4_B_0_1) ||
		    (nfc->data & RXH_L4_B_2_3))
			return -EINVAL;
		hena |= BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV6_OTHER);
		break;
	case IPV4_FLOW:
		hena |= BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV4_OTHER) |
			BIT_ULL(I40E_FILTER_PCTYPE_FRAG_IPV4);
		break;
	case IPV6_FLOW:
		hena |= BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV6_OTHER) |
			BIT_ULL(I40E_FILTER_PCTYPE_FRAG_IPV6);
		break;
	default:
		return -EINVAL;
	}

	if (flow_pctype) {
		i_setc = (u64)i40e_read_rx_ctl(hw, I40E_GLQF_HASH_INSET(0,
					       flow_pctype)) |
			((u64)i40e_read_rx_ctl(hw, I40E_GLQF_HASH_INSET(1,
					       flow_pctype)) << 32);
		i_set = i40e_get_rss_hash_bits(nfc, i_setc);
		i40e_write_rx_ctl(hw, I40E_GLQF_HASH_INSET(0, flow_pctype),
				  (u32)i_set);
		i40e_write_rx_ctl(hw, I40E_GLQF_HASH_INSET(1, flow_pctype),
				  (u32)(i_set >> 32));
		hena |= BIT_ULL(flow_pctype);
	}

	i40e_write_rx_ctl(hw, I40E_PFQF_HENA(0), (u32)hena);
	i40e_write_rx_ctl(hw, I40E_PFQF_HENA(1), (u32)(hena >> 32));
	i40e_flush(hw);

	return 0;
}

/**
 * i40e_handle_flex_filter_del - Update FD_INSET upon deletion of flex filter
 * @vsi: Pointer to the targeted VSI
 * @flow_type: Type of flow
 * @flex_mask_bit: Bit index used in INSET register
 *
 * This function updates FD_INSET for flex filter if filter (using flex bytes)
 * count (based on flow_type) reaches zero.
 **/
static void i40e_handle_flex_filter_del(struct i40e_vsi *vsi,
					u8 flow_type,
					u64 flex_mask_bit)
{
	u8 idx;
	u64 val = 0;
	u64 *input_set = NULL;
	int flex_filter_cnt = 0;
	u32 fsize = 0, src = 0;
	struct hlist_node *node2;
	struct i40e_fdir_filter *rule;
	struct i40e_pf *pf = vsi->back;
	bool clean_flex_pit = false;
	bool update_flex_pit6 = false;
	bool update_flex_pit7 = false;
	u32 flex_pit6 = 0, flex_pit7 = 0;
	u8 pit_idx = I40E_FLEX_PIT_IDX_START_L4;
	u64 dest_word_l4, dest_word6, dest_word7;

	switch (flow_type & FLOW_TYPE_MASK) {
	case TCP_V4_FLOW:
		idx = I40E_FILTER_PCTYPE_NONF_IPV4_TCP;
		input_set = &pf->fd_tcp4_input_set;
		break;

	case UDP_V4_FLOW:
		idx = I40E_FILTER_PCTYPE_NONF_IPV4_UDP;
		input_set = &pf->fd_udp4_input_set;
		break;

	case IP_USER_FLOW:
		idx = I40E_FILTER_PCTYPE_NONF_IPV4_OTHER;
		input_set = &pf->fd_ip4_input_set;
		pit_idx = I40E_FLEX_PIT_IDX_START_L3;
		clean_flex_pit = true;
		break;

	default:
		return;
	}

	/* To support TCP/UDP flow simultaneously, update either all
	 * relevant register or only needed.
	 */
	if (pit_idx == I40E_FLEX_PIT_IDX_START_L4) {
		flex_pit6 = i40e_read_rx_ctl(&pf->hw,
					     I40E_PRTQF_FLX_PIT(pit_idx));
		flex_pit7 = i40e_read_rx_ctl(&pf->hw,
					     I40E_PRTQF_FLX_PIT(pit_idx + 1));
		if ((!flex_pit6) || (!flex_pit7))
			return;

		dest_word7 = I40E_FLEX_PIT_GET_DST(flex_pit7);
		dest_word6 = I40E_FLEX_PIT_GET_DST(flex_pit6);
		/* If dest_word7 or dest_word6 is UNUSED, it is safe to clear
		 * all relevant register
		 */
		if ((dest_word6 == I40E_FLEX_DEST_UNUSED) ||
		    (dest_word7 == I40E_FLEX_DEST_UNUSED)) {
			clean_flex_pit = true;
		} else {
			/* Which dest word is used based on 'flex_mask_bit' */
			dest_word_l4 = I40E_FLEX_DEST_L4;
			if (flex_mask_bit & I40E_FLEX_51_MASK)
				dest_word_l4++;
			 /* Otherwise figure out which register needs update */
			if (dest_word6 == dest_word_l4)
				update_flex_pit6 = true;
			else if (dest_word7 == dest_word_l4)
				update_flex_pit7 = true;
		}
	}

	hlist_for_each_entry_safe(rule, node2,
				  &pf->fdir_filter_list, fdir_node) {
		if (i40e_is_flex_filter(rule) && (rule->flow_type == flow_type))
			flex_filter_cnt++;
	}

	/* Do not update value of input set register if flow based flex filter
	 * (flow director filter which utilize bytes from payload as part of
	 * input set) count is non-zero
	 */
	if (flex_filter_cnt)
		return;

	/* Read flow specific input set register */
	val = i40e_read_fd_input_set(pf, idx);
	if (!(val & flex_mask_bit))
		return;

	/* Update bit mask as needed */
	val &= ~flex_mask_bit;

	/* Write flow specific input set register */
	i40e_write_fd_input_set(pf, idx, val);

	/* Update values of FLX_PIT registers */
	if (clean_flex_pit) {
		for (idx = pit_idx; idx < (pit_idx + 3); idx++)
			i40e_write_rx_ctl(&pf->hw, I40E_PRTQF_FLX_PIT(idx), 0);

		/* Time to reset value of input set based on flow-type */
		if (input_set && (!(*input_set))) {
			i40e_write_fd_input_set(pf, idx, *input_set);
			*input_set = 0;
		}
	} else if (update_flex_pit6) {
		fsize = I40E_FLEX_PIT_GET_FSIZE(flex_pit6);
		src = I40E_FLEX_PIT_GET_SRC(flex_pit6);
	} else if (update_flex_pit7) {
		fsize = I40E_FLEX_PIT_GET_FSIZE(flex_pit7);
		src = I40E_FLEX_PIT_GET_SRC(flex_pit7);
		pit_idx++;
	}

	if (fsize)
		i40e_write_rx_ctl(&pf->hw, I40E_PRTQF_FLX_PIT(pit_idx),
				  I40E_FLEX_PREP_VAL(I40E_FLEX_DEST_UNUSED,
						     fsize, src));
}

/**
 * i40e_match_fdir_input_set - Match a new filter against an existing one
 * @rule: The filter already added
 * @input: The new filter to comapre against
 *
 * Returns true if the two input set match
 **/
static bool i40e_match_fdir_input_set(struct i40e_fdir_filter *rule,
				      struct i40e_fdir_filter *input)
{
	if ((rule->dst_ip[0] != input->dst_ip[0]) ||
	    (rule->src_ip[0] != input->src_ip[0]) ||
	    (rule->dst_port != input->dst_port) ||
	    (rule->src_port != input->src_port) ||
	    (rule->flow_type != input->flow_type) ||
	    (rule->ip4_proto != input->ip4_proto) ||
	    (rule->sctp_v_tag != input->sctp_v_tag) ||
	    (rule->q_index != input->q_index))
		return false;

	/* handle flex_filter, decide based upon pattern equality */
	if (i40e_is_flex_filter(rule) &&
	    (rule->flex_bytes[3] != input->flex_bytes[3]))
		return false;

	return true;
}

/**
 * i40e_update_ethtool_fdir_entry - Updates the fdir filter entry
 * @vsi: Pointer to the targeted VSI
 * @input: The filter to update or NULL to indicate deletion
 * @sw_idx: Software index to the filter
 *
 * This function updates (or deletes) a Flow Director entry from
 * the hlist of the corresponding PF
 *
 * Returns 0 on success
 **/
static int i40e_update_ethtool_fdir_entry(struct i40e_vsi *vsi,
					  struct i40e_fdir_filter *input,
					  u16 sw_idx)
{
	struct i40e_fdir_filter *rule, *parent;
	struct i40e_pf *pf = vsi->back;
	struct hlist_node *node2;
	int err = -ENOENT;

	parent = NULL;
	rule = NULL;

	hlist_for_each_entry_safe(rule, node2,
				  &pf->fdir_filter_list, fdir_node) {
		/* rule id found, or passed its spot in the list */
		if (rule->fd_id >= sw_idx)
			break;
		parent = rule;
	}

	/* is there is an old rule occupying our target filter slot? */
	if (rule && (rule->fd_id == sw_idx)) {

		/* if this is an identical rule, don't change anything */
		if (input && i40e_match_fdir_input_set(rule, input))
			return 0;

		/* remove the list entry because we're either deleting
		 * the old rule or we're replacing it with a new rule
		 */
		err = i40e_add_del_fdir(vsi, rule, false);
		hlist_del(&rule->fdir_node);
		pf->fdir_pf_active_filters--;

		/* Was it flex filter and deemed for deletion */
		if (i40e_is_flex_filter(rule) && (!input))
			i40e_handle_flex_filter_del(vsi, rule->flow_type,
						    rule->flex_mask_bit);
		kfree(rule);
	}

	/* If no input this was a delete, err should be 0 if a rule was
	 * successfully found and removed from the list else -ENOENT
	 */
	if (!input)
		return err;

	/* initialize node and set software index */
	INIT_HLIST_NODE(&input->fdir_node);

	/* add filter to the ordered list */
	if (parent)
		hlist_add_behind(&input->fdir_node, &parent->fdir_node);
	else
		hlist_add_head(&input->fdir_node, &pf->fdir_filter_list);

	/* update counts */
	pf->fdir_pf_active_filters++;

	return 0;
}

/**
 * i40e_del_fdir_entry - Deletes a Flow Director filter entry
 * @vsi: Pointer to the targeted VSI
 * @cmd: The command to get or set Rx flow classification rules
 *
 * The function removes a Flow Director filter entry from the
 * hlist of the corresponding PF
 *
 * Returns 0 on success
 */
static int i40e_del_fdir_entry(struct i40e_vsi *vsi,
			       struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp =
		(struct ethtool_rx_flow_spec *)&cmd->fs;
	struct i40e_pf *pf = vsi->back;
	int ret = 0;

	if (test_bit(__I40E_RESET_RECOVERY_PENDING, &pf->state) ||
	    test_bit(__I40E_RESET_INTR_RECEIVED, &pf->state))
		return -EBUSY;

	if (test_bit(__I40E_FD_FLUSH_REQUESTED, &pf->state))
		return -EBUSY;

	ret = i40e_update_ethtool_fdir_entry(vsi, NULL, fsp->location);

	i40e_fdir_check_and_reenable(pf);
	return ret;
}

/**
 * i40e_program_flex_filter - Program flex filter
 *
 * @vsi: pointer to the targeted VSI
 * @flex_pit: value prepared to be written into flex PIT register
 * @flex_pit6: flex pit[6] register value
 * @offset_in_words: offset in packet (unit word)
 * @src_word_off: user specified offset in words
 * @dest_word: word location to be used in field vector
 * @pit_idx: PIT register index
 * @ort_idx: ORT register index
 * @ort_val: value to be written in ORT register
 *
 * This function programs relevant FLX_PIT registers, shuffles/updates the
 * value as needed to support simultaneous flows (such as TCP4/UDP4/IP4).
 **/
static int i40e_program_flex_filter(struct i40e_vsi *vsi, u32 flex_pit,
				    u32 flex_pit6, u32 offset_in_words,
				    u32 src_word_off, u32 dest_word,
				    u32 pit_idx, u32 ort_idx, u32 ort_val)
{
	struct i40e_pf *pf;
	u32 curr_src_off = 0, curr_fsize = 0, fsize = 0;

	pf = vsi->back;

	/* Program starting FLX_PIT register */
	if (!flex_pit6) {
		i40e_write_rx_ctl(&pf->hw,
				  I40E_PRTQF_FLX_PIT(pit_idx), flex_pit);
	} else {
		/* This is needed to support simultaneous flex filter for flow
		 * types TCP4 and UDP4.
		 * Program FLX_PIT[6] and FLX_PIT[7] correctly, if needed
		 * program the value read from FLX_PIT6 into register FLX_PIT7,
		 * adjust value for FLX_PIT6 if required.
		 */
		curr_src_off = I40E_FLEX_PIT_GET_SRC(flex_pit6);
		curr_fsize = I40E_FLEX_PIT_GET_FSIZE(flex_pit6);

		if (offset_in_words == curr_src_off) {
			netif_err(pf, drv, vsi->netdev,
				  "Filter exist whose offset w.r.t it's payload matches with the filter being added. This breaks device programming rules, hence unsupported\n");
			return -EINVAL;
		} else if (offset_in_words < curr_src_off) {
			/* Program value of FLX_PIT6 into
			 * FLX_PIT7 and reprogram PIT6 with
			 * modified value and program PIT8
			 * as per rule
			 */

			/* Adjust FSIZE of FLX_PIT[6]*/
			fsize = curr_src_off - offset_in_words;

			/* Program FLX_PIT[6] */
			i40e_write_rx_ctl(&pf->hw, I40E_PRTQF_FLX_PIT(pit_idx),
					  I40E_FLEX_PREP_VAL(dest_word,
							     fsize,
							     src_word_off));
			/* Save value of FLX_PIT6, to be written into
			 * FLX_PIT[7]
			 */
			flex_pit = flex_pit6;

			/* Make sure src_word_off is correct for last
			 * FLX_PIT register in this case
			 */
			offset_in_words = curr_src_off + curr_fsize;
		} else {
			/* Make sure src_word_off is correct for last
			 * FLX_PIT register in this case
			 */
			offset_in_words = offset_in_words +
					  I40E_FLEX_PIT_GET_FSIZE(flex_pit);
		}

		/* Program FLX_PIT[7] */
		pit_idx++;
		i40e_write_rx_ctl(&pf->hw, I40E_PRTQF_FLX_PIT(pit_idx),
				  flex_pit);
		goto program_last_flx_pit;
	}

	/* Propgram FLX_PIT register:
	 * FLX_PIT[3] for L3 flow and FLX_PIT[7] for L4 flow
	 */
	pit_idx++;
	offset_in_words++;
	i40e_write_rx_ctl(&pf->hw, I40E_PRTQF_FLX_PIT(pit_idx),
			  I40E_FLEX_PREP_VAL(I40E_FLEX_DEST_UNUSED,
					     1, offset_in_words));
	/* Update before label because in other case, where jump
	 * is taken, values are updated correctly
	 */
	offset_in_words++;

program_last_flx_pit:
	/* FLX_PIT[8] in case of L4 flow or FLX_PIT[3] in case of L3 flow */
	pit_idx++;
	i40e_write_rx_ctl(&pf->hw, I40E_PRTQF_FLX_PIT(pit_idx),
			  I40E_FLEX_PREP_VAL(I40E_FLEX_DEST_UNUSED,
					     1, offset_in_words));
	i40e_write_rx_ctl(&pf->hw, I40E_GLQF_ORT(ort_idx), ort_val);

	return 0;
}

/**
 * i40e_validate_flex_filter_params - Validate flex filter params (user-def)
 * @vsi: pointer to the targeted VSI
 * @input: pointer to filter
 * @offset: offset in packet
 * @header_len: Header len based on flow-type
 * @mask: inset mask for flex filter
 * @flow_based_cnt: flex filter count based on flow-type
 * @word_offset_in_payload: offset in unit words w.r.t payload
 *
 * This function validates 'offset' (mask) to make sure it satisfies device
 * programming rule.
 **/
static int i40e_validate_flex_filter_params(struct i40e_vsi *vsi,
					    struct i40e_fdir_filter *input,
					    u16 offset, u16 header_len,
					    u64 *mask, u16 *flow_based_cnt,
					    u32 word_offset_in_payload)
{
	struct i40e_pf *pf;
	struct hlist_node *node2;
	struct i40e_fdir_filter *rule;
	u16 existing_mask, specified_mask;

	pf = vsi->back;

	/* 'offset' needs to be within 0...480 bytes */
	if (offset >= I40E_MAX_PARSE_BYTE) {
		netif_err(pf, drv, vsi->netdev, "Max valid offset in unit word is %u, user passed %u\n",
			  I40E_MAX_PARSE_BYTE, offset);
		return -EINVAL;
	}

	/* 'offset' shall not be somewhere within header (L2/L3/L4) */
	if (offset < header_len) {
		netif_err(pf, drv, vsi->netdev, "Specified offset (%u) is referring to bytes in headers (bytes 0-%u), it should be somewhere in payload.\n",
			  offset, header_len);
		return -EINVAL;
	}

	/* Check for word boundary */
	if (offset & 0x1) {
		netif_err(pf, drv, vsi->netdev, "User specified mask address %u rounded down to word boundary %lu\n",
			  offset, sizeof(u16));
		return -EINVAL;
	}

	if (word_offset_in_payload >= I40E_MAX_SRC_WORD_OFFSET) {
		netif_err(pf, drv, vsi->netdev, "Max. allowed bytes in payload are %u, but user specified offset %u\n",
			  (I40E_MAX_SRC_WORD_OFFSET << 1),
			  word_offset_in_payload);
		return -EINVAL;
	}

	/* Does filter with flex byte for given flow-type exist and if offset
	 * (aka flex mask) of that existing filter is different, it is
	 * considered change in input set mask.
	 * Since we are allowing only one mask (aka offset) for each flow type,
	 * flag an error and fail the call.
	 */
	hlist_for_each_entry_safe(rule, node2,
				  &pf->fdir_filter_list, fdir_node) {
		if (!i40e_is_flex_filter(rule))
			continue;
		existing_mask = ~(be16_to_cpu(rule->flex_mask[3]));
		specified_mask = ~(be16_to_cpu(input->flex_mask[3]));
		if (rule->flow_type == input->flow_type) {
			if (existing_mask != specified_mask) {
				/* This is like change in INPUT set mask
				 * (aka 'offset') when used flex payload for
				 * a given flow-type.
				 */
				netif_err(pf, drv, vsi->netdev,
					  "Previous flex filter(ID: %u) exists for flow-type %u whose flex mask (aka 'offset'): %u is different from current mask :%u specified. Please delete previous flex filter and try again.\n",
					  input->fd_id,
					  input->flow_type & FLOW_TYPE_MASK,
					  existing_mask, specified_mask);
				return -EINVAL;
			}
			/* Keep track of flex filter cnt per flow */
			(*flow_based_cnt)++;
			*mask = rule->flex_mask_bit;
		}
	}

	return 0;
}

/**
 * i40e_handle_input_set - Detect and handle input set changes
 * @vsi: pointer to the targeted VSI
 * @fsp: pointer to RX flow classification spec
 * @input: pointer to filter
 *
 * Reads register, detect change in input set based on existing register
 * value and what user has passed. Update input set mask register if needed.
 **/
static int i40e_handle_input_set(struct i40e_vsi *vsi,
				 struct ethtool_rx_flow_spec *fsp,
				 struct i40e_fdir_filter *input)
{
	u8 idx;
	u64 val = 0;
	int ret = 0;
	u16 flow_based_filter_cnt = 0;
	u32 fsize = 1;
	u32 flex_pit6 = 0;
	u64 *input_set = NULL;
	u16 offset = 0, header_len = 0;
	bool inset_mask_change = false;
	u16 flex_flow_based_filter_cnt = 0;
	u32 dest_word = I40E_FLEX_DEST_L4;
	u32 ort_idx = I40E_L4_GLQF_ORT_IDX;
	u32 ort_val = I40E_L4_GLQF_ORT_VAL;
	u64 flex_mask_bit = I40E_FLEX_50_MASK;
	u32 pit_idx = I40E_FLEX_PIT_IDX_START_L4;
	u32 src_word_off = 0, offset_in_words = 0, flex_pit = 0;
	struct i40e_pf *pf;
	u32 dest_ip_addr = 0;
	struct hlist_node *node2;
	struct i40e_cloud_filter *cloud_rule;

	if (unlikely(!vsi))
		return -EINVAL;

	pf = vsi->back;
	switch (fsp->flow_type & FLOW_TYPE_MASK) {
	case TCP_V4_FLOW:
		idx = I40E_FILTER_PCTYPE_NONF_IPV4_TCP;
		header_len = I40E_TCPIP_DUMMY_PACKET_LEN;
		input_set = &pf->fd_tcp4_input_set;
		flow_based_filter_cnt = pf->fd_tcp4_filter_cnt;
		break;

	case UDP_V4_FLOW:
		idx = I40E_FILTER_PCTYPE_NONF_IPV4_UDP;
		header_len = I40E_UDPIP_DUMMY_PACKET_LEN;
		input_set = &pf->fd_udp4_input_set;
		flow_based_filter_cnt = pf->fd_udp4_filter_cnt;
		break;

	case IP_USER_FLOW:
		idx = I40E_FILTER_PCTYPE_NONF_IPV4_OTHER;
		header_len = I40E_IP_DUMMY_PACKET_LEN;
		dest_word = I40E_FLEX_DEST_L3;
		pit_idx = I40E_FLEX_PIT_IDX_START_L3;
		flex_mask_bit = I40E_FLEX_53_MASK;
		input_set = &pf->fd_ip4_input_set;
		ort_idx = I40E_L3_GLQF_ORT_IDX;
		ort_val = I40E_L3_GLQF_ORT_VAL;
		flow_based_filter_cnt = pf->fd_ip4_filter_cnt;
		break;

	/* Extend this in future for SCTP4, IPV6, IPV6(TCP/UDP/SCTP), and  L2 */
	default:
		/* for all other flow types */
		return 0;
	}

	/* Always read current value from device */
	val = i40e_read_fd_input_set(pf, idx);

	/* Save once (default value read from device)
	 * It is used upon ntuple off/on and when all filters are deleted
	 * for a given flow.
	 */
	if (input_set && (!(*input_set)))
		*input_set = val;

	if (!i40e_is_flex_filter(input))
		goto skip_flex_payload;

	/* Treating mask as 'offset' in packet */
	offset = ~(be16_to_cpu(input->flex_mask[3]));

	/* zero based word index relative to start of payload */
	src_word_off = (offset - header_len) >> 1;
	offset_in_words = src_word_off;

	/* Validate user-def params, specifically mask */
	ret = i40e_validate_flex_filter_params(vsi, input, offset, header_len,
					       &flex_mask_bit,
					       &flex_flow_based_filter_cnt,
					       src_word_off);
	if (ret)
		return ret;

	/* zero based word index relative to start of payload */
	src_word_off = (offset - header_len) >> 1;
	offset_in_words = src_word_off;

	/* To avoid reading for L3 flows */
	if (pit_idx == I40E_FLEX_PIT_IDX_START_L4)
		flex_pit6 = i40e_read_rx_ctl(&pf->hw,
					     I40E_PRTQF_FLX_PIT(pit_idx));

	/* Only applicable for L4 flow and only when FLX_PIT6 is valid */
	if (flex_pit6 && (pit_idx == I40E_FLEX_PIT_IDX_START_L4)) {
		if (flex_flow_based_filter_cnt) {
			if (flex_mask_bit == I40E_FLEX_51_MASK)
				/* Use next dest-word in field vector to be in
				 * sync with flex_mask_bit
				 */
				dest_word++;
		} else {
			/* Use next dest-word in field vector */
			dest_word++;
			/* likewise update mask bit */
			flex_mask_bit = I40E_FLEX_51_MASK;
		}
	}

	/* Store which FLEX WORD being used. Useful during delete filter */
	input->flex_mask_bit = flex_mask_bit;

	/* Prep value for FLX_PIT register */
	flex_pit = I40E_FLEX_PREP_VAL(dest_word, fsize, src_word_off);

	/* Do we have cloud filter which has at least one destination
	 * IP address (applicable only in case of tunnel) as part of
	 * input set? This is unsupported configuration in the context of
	 * filter with flexible payload
	 */
	hlist_for_each_entry_safe(cloud_rule, node2,
				  &pf->cloud_filter_list, cloud_node) {
		dest_ip_addr = be32_to_cpu(cloud_rule->inner_ip[0]);
		if (dest_ip_addr) {
			netif_err(pf, drv, vsi->netdev,
				  "Previous cloud filter exist with at least one destination IP address %pI4 as part of input set. Please delete that cloud filter (ID: %u) and try again\n",
				  &dest_ip_addr, cloud_rule->id);
			return -EINVAL;
		}
	}

	/* Set correponsing bit in input set mask register, and mark change */
	if (!(val & flex_mask_bit)) {
		inset_mask_change = true;
		val |= flex_mask_bit;
	}

skip_flex_payload:
	/* Default input set (TCP/UDP/SCTP) contains following
	 * fields: srcip + dest ip + src port + dest port
	 * For SCTP, there is one extra field, "verification tag"
	 */
	if (val & I40E_L3_SRC_MASK) {
		if (!fsp->h_u.tcp_ip4_spec.ip4src) {
			val &= ~I40E_L3_SRC_MASK;
			inset_mask_change = true;
		}
	} else {
		if (fsp->h_u.tcp_ip4_spec.ip4src) {
			val |= I40E_L3_SRC_MASK;
			inset_mask_change = true;
		}
	}
	if (val & I40E_L3_DST_MASK) {
		if (!fsp->h_u.tcp_ip4_spec.ip4dst) {
			val &= ~I40E_L3_DST_MASK;
			inset_mask_change = true;
		}
	} else {
		if (fsp->h_u.tcp_ip4_spec.ip4dst) {
			val |= I40E_L3_DST_MASK;
			inset_mask_change = true;
		}
	}
	if (val & I40E_L4_SRC_MASK) {
		if (!fsp->h_u.tcp_ip4_spec.psrc) {
			val &= ~I40E_L4_SRC_MASK;
			inset_mask_change = true;
		}
	} else {
		if (fsp->h_u.tcp_ip4_spec.psrc) {
			val |= I40E_L4_SRC_MASK;
			inset_mask_change = true;
		}
	}
	if (val & I40E_L4_DST_MASK) {
		if (!fsp->h_u.tcp_ip4_spec.pdst) {
			val &= ~I40E_L4_DST_MASK;
			inset_mask_change = true;
		}
	} else {
		if (fsp->h_u.tcp_ip4_spec.pdst) {
			val |= I40E_L4_DST_MASK;
			inset_mask_change = true;
		}
	}

	/* Handle the scenario where previous input set mask for given
	 * flow-type indicates usage of flex payload, whereas current
	 * filter being added is not using flexible payload.
	 * In another words, changing from tuple which had flex bytes as part of
	 * tuple to tuples where no flex bytes are used.
	 *
	 * Extend following check as more FLEX_5x_MASK are used.
	 */
	if (val & (I40E_FLEX_50_MASK | I40E_FLEX_51_MASK |
	    I40E_FLEX_52_MASK | I40E_FLEX_53_MASK)) {
		if (!i40e_is_flex_filter(input))
			inset_mask_change = true;
	}

	if (!inset_mask_change)
		return 0;

	if (pf->flags & I40E_FLAG_MFP_ENABLED) {
		netif_err(pf, drv, vsi->netdev, "Change of input set is not supported when MFP mode is enabled\n");
		return -EOPNOTSUPP;
	}
	if (flex_flow_based_filter_cnt || flow_based_filter_cnt) {
		netif_err(pf, drv, vsi->netdev, "Change of input set is not supported when there are existing filters(%u) for specified flow-type: %u. Please delete them and re-try\n",
			  (flex_flow_based_filter_cnt) ?
			  flex_flow_based_filter_cnt : flow_based_filter_cnt,
			  fsp->flow_type & FLOW_TYPE_MASK);
		return -EOPNOTSUPP;
	}

	if (I40E_DEBUG_FD & pf->hw.debug_mask)
		netif_info(pf, drv, vsi->netdev, "FD_INSET mask is changing to 0x%016llx\n",
			   val);

	/* Program FLX_PIT registers to support flex filter */
	if (flex_pit) {
		ret = i40e_program_flex_filter(vsi, flex_pit, flex_pit6,
					       offset_in_words, src_word_off,
					       dest_word, pit_idx,
					       ort_idx, ort_val);
		if (ret)
			return ret;
	}

	/* Update input mask register since input set mask changed */
	i40e_write_fd_input_set(pf, idx, val);

	netif_info(pf, drv, vsi->netdev, "Input set mask has been changed. Please note that, it affects specified interface and any other related/derived interfaces\n");

	return 0;
}

/**
 * i40e_add_fdir_ethtool - Add/Remove Flow Director filters
 * @vsi: pointer to the targeted VSI
 * @cmd: command to get or set RX flow classification rules
 *
 * Add Flow Director filters for a specific flow spec based on their
 * protocol.  Returns 0 if the filters were successfully added.
 **/
static int i40e_add_fdir_ethtool(struct i40e_vsi *vsi,
				 struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp;
	struct i40e_fdir_filter *input;
	struct i40e_pf *pf;
	int ret = -EINVAL;
	u16 vf_id;

	if (!vsi)
		return -EINVAL;
	pf = vsi->back;

	if (!(pf->flags & I40E_FLAG_FD_SB_ENABLED))
		return -EOPNOTSUPP;

	if (pf->auto_disable_flags & I40E_FLAG_FD_SB_ENABLED)
		return -ENOSPC;

	if (test_bit(__I40E_RESET_RECOVERY_PENDING, &pf->state) ||
	    test_bit(__I40E_RESET_INTR_RECEIVED, &pf->state))
		return -EBUSY;

	if (test_bit(__I40E_FD_FLUSH_REQUESTED, &pf->state))
		return -EBUSY;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;
	if (fsp->location >= (pf->hw.func_caps.fd_filters_best_effort +
			      pf->hw.func_caps.fd_filters_guaranteed)) {
		return -EINVAL;
	}

	if ((fsp->ring_cookie != RX_CLS_FLOW_DISC) &&
	    (fsp->ring_cookie >= vsi->num_queue_pairs))
		return -EINVAL;

	input = kzalloc(sizeof(*input), GFP_KERNEL);
	if (!input)
		return -ENOMEM;

	if (fsp->ring_cookie == RX_CLS_FLOW_DISC)
		input->dest_ctl = I40E_FILTER_PROGRAM_DESC_DEST_DROP_PACKET;
	else
		input->dest_ctl =
			     I40E_FILTER_PROGRAM_DESC_DEST_DIRECT_PACKET_QINDEX;

	input->fd_id = fsp->location;
	input->q_index = fsp->ring_cookie;
	input->flex_off = 0;
	input->pctype = 0;
	input->dest_vsi = vsi->id;
	input->fd_status = I40E_FILTER_PROGRAM_DESC_FD_STATUS_FD_ID;
	input->cnt_index  = I40E_FD_SB_STAT_IDX(pf->hw.pf_id);
	input->flow_type = fsp->flow_type;
	input->ip4_proto = fsp->h_u.usr_ip4_spec.proto;

	/* Reverse the src and dest notion, since the HW expects them to be from
	 * Tx perspective where as the input from user is from Rx filter view.
	 */
	input->dst_port = fsp->h_u.tcp_ip4_spec.psrc;
	input->src_port = fsp->h_u.tcp_ip4_spec.pdst;
	input->dst_ip[0] = fsp->h_u.tcp_ip4_spec.ip4src;
	input->src_ip[0] = fsp->h_u.tcp_ip4_spec.ip4dst;

	/* Deciding factor, whether it is flex filter or filter for VF
	 * is value of 'mask' (user-def N m)
	 * If mask is specified then treat it as flex filter
	 * otherwise this filter is for VF.
	 * This distinction is needed due to overloading usage of
	 * user-def field.
	 */
	if (fsp->m_ext.data[1] == cpu_to_be32(~0)) {
		vf_id = be32_to_cpu(fsp->h_ext.data[1]);
		if (vf_id >= pf->num_alloc_vfs) {
			netif_info(pf, drv, vsi->netdev,
				   "Invalid VF id %d\n", vf_id);
			goto free_input;
		}
		/* Find vsi id from vf id and override dest vsi */
		input->dest_vsi = pf->vf[vf_id].lan_vsi_id;
		if (input->q_index >= pf->vf[vf_id].num_queue_pairs) {
			netif_info(pf, drv, vsi->netdev,
				   "Invalid queue id %d for VF %d\n",
				   input->q_index, vf_id);
			goto free_input;
		}
	} else {
		/* flex filter is supported only for main VSI */
		if (vsi->type != I40E_VSI_MAIN) {
			netif_err(pf, drv, vsi->netdev,
				  "Unsupported interface type for adding filter using user-defs\n");
			goto free_input;
		}

		/* initialized to known values */
		input->flex_bytes[2] = 0;
		input->flex_bytes[3] = 0;
		input->flex_mask[2] = 0;
		input->flex_mask[3] = 0;
		if ((fsp->h_ext.data[0] == cpu_to_be32(0x0)) &&
		    (fsp->h_ext.data[1] != cpu_to_be32(~0))) {
			input->flex_bytes[2] = fsp->h_ext.data[1];
			if (input->flex_bytes[2]) {
				netif_err(pf, drv, vsi->netdev,
					  "Only one word is supported for flex filter\n");
				goto free_input;
			}
			/* Store only relevant section of user-defs */
			input->flex_bytes[3] = fsp->h_ext.data[1] >> 16;
			input->flex_mask[3] = fsp->m_ext.data[1] >> 16;
		}
	}

	/*  Detect and handle change for input set mask */
	ret = i40e_handle_input_set(vsi, fsp, input);
	if (ret) {
		netif_err(pf, drv, vsi->netdev, "Unable to handle change in input set mask\n");
		goto free_input;
	}

	ret = i40e_add_del_fdir(vsi, input, true);
free_input:
	if (ret)
		kfree(input);
	else {
		(void)i40e_del_cloud_filter_ethtool(pf, cmd);
		i40e_update_ethtool_fdir_entry(vsi, input, fsp->location);
	}

	return ret;
}

/**
 * i40e_cloud_filter_mask2flags- Convert cloud filter details to filter type
 * @pf: pointer to the physical function struct
 * @fsp: RX flow classification rules
 * @flags: Resultant combination of all the fields to decide the tuple
 *
 * The general trick in setting these flags is that if the mask field for
 * a value is non-zero, then the field itself was set to something, so we
 * use this to tell us what has been selected.
 *
 * Returns 0 if a valid filter type was identified.
 **/
static int i40e_cloud_filter_mask2flags(struct i40e_pf *pf,
					struct ethtool_rx_flow_spec *fsp,
					u8 *flags)
{
	u32 tenant_id;
	u8 i = 0;

	*flags = 0;

	switch (fsp->flow_type & FLOW_TYPE_MASK) {
	case ETHER_FLOW:
		/* use is_broadcast and is_zero to check for all 0xf or 0 */
		if (is_broadcast_ether_addr(fsp->m_u.ether_spec.h_dest)) {
			i |= I40E_CLOUD_FIELD_OMAC;
		} else if (is_zero_ether_addr(fsp->m_u.ether_spec.h_dest)) {
			i &= ~I40E_CLOUD_FIELD_OMAC;
		} else {
			dev_info(&pf->pdev->dev, "Bad ether dest mask %pM\n",
				 fsp->m_u.ether_spec.h_dest);
			return I40E_ERR_CONFIG;
		}

		if (is_broadcast_ether_addr(fsp->m_u.ether_spec.h_source)) {
			i |= I40E_CLOUD_FIELD_IMAC;
		} else if (is_zero_ether_addr(fsp->m_u.ether_spec.h_source)) {
			i &= ~I40E_CLOUD_FIELD_IMAC;
		} else {
			dev_info(&pf->pdev->dev, "Bad ether source mask %pM\n",
				 fsp->m_u.ether_spec.h_source);
			return I40E_ERR_CONFIG;
		}
		break;

	case IP_USER_FLOW:
		if (fsp->m_u.usr_ip4_spec.ip4dst == cpu_to_be32(0xffffffff)) {
			i |= I40E_CLOUD_FIELD_IIP;
		} else if (!fsp->m_u.usr_ip4_spec.ip4dst) {
			i &= ~I40E_CLOUD_FIELD_IIP;
		} else {
			dev_info(&pf->pdev->dev, "Bad ip dst mask 0x%08x\n",
				 be32_to_cpu(fsp->m_u.usr_ip4_spec.ip4dst));
			return I40E_ERR_CONFIG;
		}
		break;

	default:
		return I40E_ERR_CONFIG;
	}

	switch (be16_to_cpu(fsp->m_ext.vlan_tci)) {
	case 0xffff:
		if (fsp->h_ext.vlan_tci & cpu_to_be16(~0x7fff)) {
			dev_info(&pf->pdev->dev, "Bad vlan %u\n",
				 be16_to_cpu(fsp->h_ext.vlan_tci));
			return I40E_ERR_CONFIG;
		}
		i |= I40E_CLOUD_FIELD_IVLAN;
		break;
	case 0:
		i &= ~I40E_CLOUD_FIELD_IVLAN;
		break;
	default:
		dev_info(&pf->pdev->dev, "Bad vlan mask %u\n",
			 be16_to_cpu(fsp->m_ext.vlan_tci));
		return I40E_ERR_CONFIG;
	}

	/* we already know that the user-def field was set, that's how we
	 * got here, so we don't need to check that.  However, we need to
	 * see if 0xffffffff or a non-zero three-byte tenant id was set.
	 */
	tenant_id = be32_to_cpu(fsp->h_ext.data[0]);
	if (tenant_id && tenant_id <= 0xffffff) {
		i |= I40E_CLOUD_FIELD_TEN_ID;
	} else if (tenant_id == 0xffffffff || tenant_id == 0) {
		i &= ~I40E_CLOUD_FIELD_TEN_ID;
	} else {
		dev_info(&pf->pdev->dev, "Bad tenant/vxlan id %d\n", tenant_id);
		return I40E_ERR_CONFIG;
	}

	*flags = i;
	return I40E_SUCCESS;
}

/**
 * i40e_add_cloud_filter_ethtool - Add cloud filter
 * @pf: pointer to the physical function struct
 * @cmd: The command to get or set Rx flow classification rules
 *
 * Add cloud filter for a specific flow spec.
 * Returns 0 if the filter were successfully added.
 **/
static int i40e_add_cloud_filter_ethtool(struct i40e_pf *pf,
					 struct ethtool_rxnfc *cmd)
{
	struct i40e_cloud_filter *rule, *parent, *filter = NULL;
	struct ethtool_rx_flow_spec *fsp;
	struct hlist_node *node2;
	struct i40e_vsi *dst_vsi;
	u16 vf_id, vsi_idx;
	u8 flags = 0;
	int ret;

	if (test_bit(__I40E_RESET_RECOVERY_PENDING, &pf->state) ||
	    test_bit(__I40E_RESET_INTR_RECEIVED, &pf->state))
		return -EBUSY;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;
	if (fsp->m_ext.data[1] == cpu_to_be32(0xffffffff)) {
		vf_id = (u16)be32_to_cpu(fsp->h_ext.data[1]);
		/* if Vf id >= num_vfs, program a filter for PF Main VSI */
		if (vf_id >= pf->num_alloc_vfs) {
			dev_info(&pf->pdev->dev,
				 "Out of range vf_id %d, adding the cloud filter to PF\n",
				 vf_id);
			dst_vsi = pf->vsi[pf->lan_vsi];
		} else {
			vsi_idx = pf->vf[vf_id].lan_vsi_idx;
			dst_vsi = pf->vsi[vsi_idx];
			if (!dst_vsi) {
				dev_info(&pf->pdev->dev,
					 "Invalid vf_id %d\n", vf_id);
				return -EINVAL;
			}
		}
	} else if (!fsp->m_ext.data[1]) {
		dst_vsi = pf->vsi[pf->lan_vsi];
	} else {
		return -EINVAL;
	}

	if (fsp->ring_cookie == ~0) {
		dev_info(&pf->pdev->dev, "No drop option for cloud filters\n");
		return -EINVAL;
	} else if (fsp->ring_cookie >= dst_vsi->num_queue_pairs) {
		dev_info(&pf->pdev->dev,
			 "Invalid queue_id %llu\n", fsp->ring_cookie);
		return -EINVAL;
	}

	ret = i40e_cloud_filter_mask2flags(pf, fsp, &flags);
	if (ret || !flags) {
		dev_info(&pf->pdev->dev, "Invalid mask config, flags = %d\n",
			 flags);
		return -EINVAL;
	}

	/* if filter exists with same id, delete the old one */
	parent = NULL;
	hlist_for_each_entry_safe(rule, node2,
				  &pf->cloud_filter_list, cloud_node) {
		/* filter exists with the id */
		if (rule->id == fsp->location)
			filter = rule;

		/* bail out if we've passed the likely location in the list */
		if (rule->id >= fsp->location)
			break;

		/* track where we left off */
		parent = rule;
	}
	if (filter && (filter->id == fsp->location)) {
		/* found it in the cloud list, so remove it */
		ret = i40e_add_del_cloud_filter(pf, filter, false);
		if (ret && (pf->hw.aq.asq_last_status != I40E_AQ_RC_ENOENT)) {
			dev_info(&pf->pdev->dev,
				 "fail to delete old cloud filter, err %s, aq_err %s\n",
				 i40e_stat_str(&pf->hw, ret),
				 i40e_aq_str(&pf->hw,
					     pf->hw.aq.asq_last_status));
			return i40e_aq_rc_to_posix(ret,
						   pf->hw.aq.asq_last_status);
		}
		hlist_del(&filter->cloud_node);
		kfree(filter);
		pf->num_cloud_filters--;
	} else {
		/* not in the cloud list, so check the PF's fdir list */
		(void)i40e_del_fdir_entry(pf->vsi[pf->lan_vsi], cmd);
	}

	/* Presence of cloud filter and flex filter is mutually exclusive */
	if (pf->fd_flex_filter_cnt) {
		dev_err(&pf->pdev->dev,
			"Filters(%d) using user-def (flexible payload) are present. Please delete them and try again\n",
			pf->fd_flex_filter_cnt);
		return I40E_NOT_SUPPORTED;
	}

	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
	if (!filter)
		return -ENOMEM;

	filter->id = fsp->location;
	filter->seid = dst_vsi->seid;

	switch (fsp->flow_type & FLOW_TYPE_MASK) {
	case ETHER_FLOW:
		ether_addr_copy(filter->outer_mac,
				fsp->h_u.ether_spec.h_dest);
		ether_addr_copy(filter->inner_mac,
				fsp->h_u.ether_spec.h_source);
		break;

	case IP_USER_FLOW:
		if (flags & I40E_CLOUD_FIELD_TEN_ID) {
			dev_info(&pf->pdev->dev, "Tenant id not allowed for ip filter\n");
			return I40E_ERR_CONFIG;
		}
		filter->inner_ip[0] = fsp->h_u.usr_ip4_spec.ip4dst;
		break;

	default:
		dev_info(&pf->pdev->dev, "unknown flow type 0x%x\n",
			 (fsp->flow_type & FLOW_TYPE_MASK));
		kfree(filter);
		return I40E_ERR_CONFIG;
	}

	if (be32_to_cpu(fsp->h_ext.data[0]) != 0xffffffff) {
		filter->tenant_id = be32_to_cpu(fsp->h_ext.data[0]);
		filter->tunnel_type = I40E_AQC_ADD_CLOUD_TNL_TYPE_VXLAN;
	} else {
		/* L3 VEB filter for non-tunneled packets or a tuple w/o vni  */
		filter->tenant_id = 0;
		filter->tunnel_type = I40E_CLOUD_TNL_TYPE_NONE;
	}
	filter->queue_id = fsp->ring_cookie;
	filter->flags = flags;
	filter->inner_vlan = fsp->h_ext.vlan_tci;

	ret = i40e_add_del_cloud_filter(pf, filter, true);
	if (ret) {
		kfree(filter);
		dev_info(&pf->pdev->dev,
			 "fail to add cloud filter, err = %d\n", ret);
		return i40e_aq_rc_to_posix(ret, pf->hw.aq.asq_last_status);
	}

	/* add filter to the ordered list */
	INIT_HLIST_NODE(&filter->cloud_node);
	if (parent)
		hlist_add_behind(&filter->cloud_node, &parent->cloud_node);
	else
		hlist_add_head(&filter->cloud_node, &pf->cloud_filter_list);
	pf->num_cloud_filters++;

	return 0;
}

/**
 * i40e_del_cloud_filter_ethtool - del vxlan filter
 * @pf: pointer to the physical function struct
 * @cmd: RX flow classification rules
 *
 * Delete vxlan filter for a specific flow spec.
 * Returns 0 if the filter was successfully deleted.
 **/
static int i40e_del_cloud_filter_ethtool(struct i40e_pf *pf,
					 struct ethtool_rxnfc *cmd)
{
	struct i40e_cloud_filter *rule, *filter = NULL;
	struct ethtool_rx_flow_spec *fsp;
	struct hlist_node *node2;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;
	hlist_for_each_entry_safe(rule, node2,
				  &pf->cloud_filter_list, cloud_node) {
		/* filter found */
		if (rule->id == fsp->location)
			filter = rule;

		/* bail out if we've passed the likely location in the list */
		if (rule->id >= fsp->location)
			break;
	}
	if (!filter)
		return -ENOENT;

	/* remove filter from the list even if failed to remove from device */
	(void)i40e_add_del_cloud_filter(pf, filter, false);
	hlist_del(&filter->cloud_node);
	kfree(filter);
	pf->num_cloud_filters--;

	return 0;
}

/**
 * i40e_set_rxnfc - command to set RX flow classification rules
 * @netdev: network interface device structure
 * @cmd: ethtool rxnfc command
 *
 * Returns Success if the command is supported.
 **/
static int i40e_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct ethtool_rx_flow_spec *fsp;
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_SRXFH:
		ret = i40e_set_rss_hash_opt(pf, cmd);
		break;

	case ETHTOOL_SRXCLSRLINS:
		/* if the user-def mask is non-zero, then something was set
		 * in the user-def value to ask us to set up a cloud filter
		 * specifying a target VF rather than flow director filter
		 */
		fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;
		/* Following check qualifies it to be cloud filter */
		if ((fsp->m_ext.data[0] == cpu_to_be32(~0)) &&
		    (fsp->m_ext.data[1] == cpu_to_be32(~0))) {
			if (!(pf->flags & I40E_FLAG_MFP_ENABLED))
				ret = i40e_add_cloud_filter_ethtool(pf, cmd);
		} else {
			ret = i40e_add_fdir_ethtool(vsi, cmd);
		}
		break;

	case ETHTOOL_SRXCLSRLDEL:
		ret = i40e_del_fdir_entry(vsi, cmd);
		if (ret == -ENOENT)
			ret = i40e_del_cloud_filter_ethtool(pf, cmd);
		break;

	default:
		break;
	}

	return ret;
}

#endif /* ETHTOOL_GRXRINGS */
#ifdef ETHTOOL_SCHANNELS
/**
 * i40e_max_channels - get Max number of combined channels supported
 * @vsi: vsi pointer
 **/
static unsigned int i40e_max_channels(struct i40e_vsi *vsi)
{
	/* TODO: This code assumes DCB and FD is disabled for now. */
	return vsi->alloc_queue_pairs;
}

/**
 * i40e_get_channels - Get the current channels enabled and max supported etc.
 * @netdev: network interface device structure
 * @ch: ethtool channels structure
 *
 * We don't support separate tx and rx queues as channels. The other count
 * represents how many queues are being used for control. max_combined counts
 * how many queue pairs we can support. They may not be mapped 1 to 1 with
 * q_vectors since we support a lot more queue pairs than q_vectors.
 **/
static void i40e_get_channels(struct net_device *dev,
			       struct ethtool_channels *ch)
{
	struct i40e_netdev_priv *np = netdev_priv(dev);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;

	/* report maximum channels */
	ch->max_combined = i40e_max_channels(vsi);

	/* report info for other vector */
	ch->other_count = (pf->flags & I40E_FLAG_FD_SB_ENABLED) ? 1 : 0;
	ch->max_other = ch->other_count;

	/* Note: This code assumes DCB is disabled for now. */
	ch->combined_count = vsi->num_queue_pairs;
}

/**
 * i40e_set_channels - Set the new channels count.
 * @netdev: network interface device structure
 * @ch: ethtool channels structure
 *
 * The new channels count may not be the same as requested by the user
 * since it gets rounded down to a power of 2 value.
 **/
static int i40e_set_channels(struct net_device *dev,
			      struct ethtool_channels *ch)
{
	struct i40e_netdev_priv *np = netdev_priv(dev);
	unsigned int count = ch->combined_count;
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;
	int new_count;

	/* We do not support setting channels for any other VSI at present */
	if (vsi->type != I40E_VSI_MAIN)
		return -EINVAL;

	/* verify they are not requesting separate vectors */
	if (!count || ch->rx_count || ch->tx_count)
		return -EINVAL;

	/* verify other_count has not changed */
	if (ch->other_count != ((pf->flags & I40E_FLAG_FD_SB_ENABLED) ? 1 : 0))
		return -EINVAL;

	/* verify the number of channels does not exceed hardware limits */
	if (count > i40e_max_channels(vsi))
		return -EINVAL;

	/* update feature limits from largest to smallest supported values */
	/* TODO: Flow director limit, DCB etc */

	/* use rss_reconfig to rebuild with new queue count and update traffic
	 * class queue mapping
	 */
	new_count = i40e_reconfig_rss_queues(pf, count);
	if (new_count > 0)
		return 0;
	else
		return -EINVAL;
}

#endif /* ETHTOOL_SCHANNELS */

#if defined(ETHTOOL_GRSSH) && !defined(HAVE_ETHTOOL_GSRSSH)
/**
 * i40e_get_rxfh_key_size - get the RSS hash key size
 * @netdev: network interface device structure
 *
 * Returns the table size.
 **/
static u32 i40e_get_rxfh_key_size(struct net_device *netdev)
{
	return I40E_HKEY_ARRAY_SIZE;
}
#endif /* ETHTOOL_GRSSH */

#ifdef ETHTOOL_GRXFHINDIR
#ifdef HAVE_ETHTOOL_GRXFHINDIR_SIZE
/**
 * i40e_get_rxfh_indir_size - get the rx flow hash indirection table size
 * @netdev: network interface device structure
 *
 * Returns the table size.
 **/
static u32 i40e_get_rxfh_indir_size(struct net_device *netdev)
{
	return I40E_HLUT_ARRAY_SIZE;
}

#if defined(ETHTOOL_GRSSH) && !defined(HAVE_ETHTOOL_GSRSSH)
#ifdef HAVE_RXFH_HASHFUNC
static int i40e_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key,
			 u8 *hfunc)
#else
/**
 * i40e_get_rxfh - get the rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 * @key: hash key
 *
 * Reads the indirection table directly from the hardware. Always returns 0.
 **/
static int i40e_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key)
#endif
#else
/**
 * i40e_get_rxfh - get the rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 *
 * Reads the indirection table directly from the hardware. Always returns 0.
 **/
static int i40e_get_rxfh_indir(struct net_device *netdev, u32 *indir)
#endif /* ETHTOOL_GRSSH */
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_vsi *vsi = np->vsi;
	u8 *lut, *seed = NULL;
	int ret;
	u16 i;

#ifdef HAVE_RXFH_HASHFUNC
	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;

#endif
	if (!indir)
		return 0;

#if defined(ETHTOOL_GRSSH) && !defined(HAVE_ETHTOOL_GSRSSH)
	seed = key;
#endif
	lut = kzalloc(I40E_HLUT_ARRAY_SIZE, GFP_KERNEL);
	if (!lut)
		return -ENOMEM;
	ret = i40e_get_rss(vsi, seed, lut, I40E_HLUT_ARRAY_SIZE);
	if (ret)
		goto out;
	for (i = 0; i < I40E_HLUT_ARRAY_SIZE; i++)
		indir[i] = (u32)(lut[i]);

out:
	kfree(lut);

	return ret;
}
#else
/**
 * i40e_get_rxfh_indir - get the rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 *
 * Reads the indirection table directly from the hardware. Returns 0 or -EINVAL
 * if the supplied table isn't large enough.
 **/
static int i40e_get_rxfh_indir(struct net_device *netdev,
			       struct ethtool_rxfh_indir *indir)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_vsi *vsi = np->vsi;
	u8 *lut;
	int ret;
	u16 i;

	if (indir->size < I40E_HLUT_ARRAY_SIZE)
		return -EINVAL;

	lut = kzalloc(I40E_HLUT_ARRAY_SIZE, GFP_KERNEL);
	if (!lut)
		return -ENOMEM;
	ret = i40e_get_rss(vsi, NULL, lut, I40E_HLUT_ARRAY_SIZE);
	if (ret)
		goto out;
	for (i = 0; i < I40E_HLUT_ARRAY_SIZE; i++)
		indir->ring_index[i] = (u32)(lut[i]);
	indir->size = I40E_HLUT_ARRAY_SIZE;

out:
	kfree(lut);

	return ret;
}

#endif /* HAVE_ETHTOOL_GRXFHINDIR_SIZE */
#endif /* ETHTOOL_GRXFHINDIR */
#ifdef ETHTOOL_SRXFHINDIR
#ifdef HAVE_ETHTOOL_GRXFHINDIR_SIZE
#if defined(ETHTOOL_SRSSH) && !defined(HAVE_ETHTOOL_GSRSSH)
/**
 * i40e_set_rxfh - set the rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 * @key: hash key
 *
 * Returns -EINVAL if the table specifies an invalid queue id, otherwise
 * returns 0 after programming the table.
 **/
#ifdef HAVE_RXFH_HASHFUNC
static int i40e_set_rxfh(struct net_device *netdev, const u32 *indir,
			 const u8 *key, const u8 hfunc)
#else
static int i40e_set_rxfh(struct net_device *netdev, const u32 *indir,
			 const u8 *key)
#endif
#else
/**
 * i40e_set_rxfh_indir - set the rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 *
 * Returns -EINVAL if the table specifies an invalid queue id, otherwise
 * returns 0 after programming the table.
 **/
static int i40e_set_rxfh_indir(struct net_device *netdev, const u32 *indir)
#endif /* EHTTOOL_SRSSH */
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_vsi *vsi = np->vsi;
	u8 *seed = NULL;
	u16 i;

#ifdef HAVE_RXFH_HASHFUNC
	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;
#endif
	if (!indir)
		return 0;

	/* Verify user input. */
	for (i = 0; i < I40E_HLUT_ARRAY_SIZE; i++) {
		if (indir[i] >= vsi->rss_size)
			return -EINVAL;
	}

#if defined(ETHTOOL_SRSSH) && !defined(HAVE_ETHTOOL_GSRSSH)
	if (key) {
		if (!vsi->rss_hkey_user) {
			vsi->rss_hkey_user = kzalloc(I40E_HKEY_ARRAY_SIZE,
						     GFP_KERNEL);
			if (!vsi->rss_hkey_user)
				return -ENOMEM;
		}
		memcpy(vsi->rss_hkey_user, key, I40E_HKEY_ARRAY_SIZE);
		seed = vsi->rss_hkey_user;
	}
#endif
	if (!vsi->rss_lut_user) {
		vsi->rss_lut_user = kzalloc(I40E_HLUT_ARRAY_SIZE, GFP_KERNEL);
		if (!vsi->rss_lut_user)
			return -ENOMEM;
	}

	/* Each 32 bits pointed by 'indir' is stored with a lut entry */
	for (i = 0; i < I40E_HLUT_ARRAY_SIZE; i++)
		vsi->rss_lut_user[i] = (u8)(indir[i]);

	return i40e_config_rss(vsi, seed, vsi->rss_lut_user,
			       I40E_HLUT_ARRAY_SIZE);
}
#else
/**
 * i40e_set_rxfh_indir - set the rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 *
 * Returns -EINVAL if the table specifies an invalid queue id, otherwise
 * returns 0 after programming the table.
 **/
static int i40e_set_rxfh_indir(struct net_device *netdev,
				 const struct ethtool_rxfh_indir *indir)
{
	struct i40e_netdev_priv *np = netdev_priv(netdev);
	struct i40e_vsi *vsi = np->vsi;
	u16 i;

	if (indir->size < I40E_HLUT_ARRAY_SIZE)
		return -EINVAL;

	/* Verify user input. */
	for (i = 0; i < (I40E_PFQF_HLUT_MAX_INDEX + 1) * 4; i++) {
		if (indir->ring_index[i] >= vsi->rss_size)
			return -EINVAL;
	}

	if (!vsi->rss_lut_user) {
		vsi->rss_lut_user = kzalloc(I40E_HLUT_ARRAY_SIZE, GFP_KERNEL);
		if (!vsi->rss_lut_user)
			return -ENOMEM;
	}

	/* Each 32 bits pointed by 'ring_index' is stored with a lut entry */
	for (i = 0; i < I40E_HLUT_ARRAY_SIZE; i++)
		vsi->rss_lut_user[i] = (u8)(indir->ring_index[i]);

	return i40e_config_rss(vsi, NULL, vsi->rss_lut_user,
			       I40E_HLUT_ARRAY_SIZE);
}
#endif /* HAVE_ETHTOOL_GRXFHINDIR_SIZE */
#endif /* ETHTOOL_SRXFHINDIR */

#ifdef HAVE_ETHTOOL_GET_SSET_COUNT
/**
 * i40e_get_priv_flags - report device private flags
 * @dev: network interface device structure
 *
 * The get string set count and the string set should be matched for each
 * flag returned.  Add new strings for each flag to the i40e_priv_flags_strings
 * array.
 *
 * Returns a u32 bitmap of flags.
 **/
static u32 i40e_get_priv_flags(struct net_device *dev)
{
	struct i40e_netdev_priv *np = netdev_priv(dev);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;
	u32 ret_flags = 0;

	ret_flags |= pf->flags & I40E_FLAG_MFP_ENABLED ?
		I40E_PRIV_FLAGS_MFP_FLAG : 0;
	ret_flags |= pf->flags & I40E_FLAG_LINK_POLLING_ENABLED ?
		I40E_PRIV_FLAGS_LINKPOLL_FLAG : 0;
	ret_flags |= pf->flags & I40E_FLAG_FD_ATR_ENABLED ?
		I40E_PRIV_FLAGS_FD_ATR : 0;
	ret_flags |= pf->flags & I40E_FLAG_VEB_STATS_ENABLED ?
		I40E_PRIV_FLAGS_VEB_STATS : 0;
	ret_flags |= pf->auto_disable_flags & I40E_FLAG_HW_ATR_EVICT_CAPABLE ?
		0 : I40E_PRIV_FLAGS_HW_ATR_EVICT;
	if (pf->hw.pf_id == 0) {
		ret_flags |= pf->flags & I40E_FLAG_TRUE_PROMISC_SUPPORT ?
			I40E_PRIV_FLAGS_TRUE_PROMISC_SUPPORT : 0;
	}

	return ret_flags;
}

/**
 * i40e_set_priv_flags - set private flags
 * @dev: network interface device structure
 * @flags: bit flags to be set
 **/
static int i40e_set_priv_flags(struct net_device *dev, u32 flags)
{
	struct i40e_netdev_priv *np = netdev_priv(dev);
	struct i40e_vsi *vsi = np->vsi;
	struct i40e_pf *pf = vsi->back;
	u16 sw_flags = 0, valid_flags = 0;
	bool reset_required = false;
	bool promisc_change = false;
	int ret;

	/* NOTE: MFP is not settable */

	if (flags & I40E_PRIV_FLAGS_LINKPOLL_FLAG)
		pf->flags |= I40E_FLAG_LINK_POLLING_ENABLED;
	else
		pf->flags &= ~I40E_FLAG_LINK_POLLING_ENABLED;

	/* allow the user to control the state of the Flow
	 * Director ATR (Application Targeted Routing) feature
	 * of the driver
	 */
	if (flags & I40E_PRIV_FLAGS_FD_ATR) {
		pf->flags |= I40E_FLAG_FD_ATR_ENABLED;
	} else {
		pf->flags &= ~I40E_FLAG_FD_ATR_ENABLED;
		pf->auto_disable_flags |= I40E_FLAG_FD_ATR_ENABLED;
	}

	if ((flags & I40E_PRIV_FLAGS_VEB_STATS) &&
	    !(pf->flags & I40E_FLAG_VEB_STATS_ENABLED)) {
		pf->flags |= I40E_FLAG_VEB_STATS_ENABLED;
		reset_required = true;
	} else if (!(flags & I40E_PRIV_FLAGS_VEB_STATS) &&
		   (pf->flags & I40E_FLAG_VEB_STATS_ENABLED)) {
		pf->flags &= ~I40E_FLAG_VEB_STATS_ENABLED;
		reset_required = true;
	}

	if (pf->hw.pf_id == 0) {
		if ((flags & I40E_PRIV_FLAGS_TRUE_PROMISC_SUPPORT) &&
		    !(pf->flags & I40E_FLAG_TRUE_PROMISC_SUPPORT)) {
			pf->flags |= I40E_FLAG_TRUE_PROMISC_SUPPORT;
			promisc_change = true;
		} else if (!(flags & I40E_PRIV_FLAGS_TRUE_PROMISC_SUPPORT) &&
			   (pf->flags & I40E_FLAG_TRUE_PROMISC_SUPPORT)) {
			pf->flags &= ~I40E_FLAG_TRUE_PROMISC_SUPPORT;
			promisc_change = true;
		}
	}
	if (promisc_change) {
		if (!(pf->flags & I40E_FLAG_TRUE_PROMISC_SUPPORT))
			sw_flags = I40E_AQ_SET_SWITCH_CFG_PROMISC;
		valid_flags = I40E_AQ_SET_SWITCH_CFG_PROMISC;
		ret = i40e_aq_set_switch_config(&pf->hw, sw_flags, valid_flags,
						NULL);
		if (ret && pf->hw.aq.asq_last_status != I40E_AQ_RC_ESRCH) {
			dev_info(&pf->pdev->dev,
				 "couldn't set switch config bits, err %s aq_err %s\n",
				 i40e_stat_str(&pf->hw, ret),
				 i40e_aq_str(&pf->hw,
					     pf->hw.aq.asq_last_status));
			/* not a fatal problem, just keep going */
		}
	}

	if ((flags & I40E_PRIV_FLAGS_HW_ATR_EVICT) &&
				   (pf->flags & I40E_FLAG_HW_ATR_EVICT_CAPABLE))
		pf->auto_disable_flags &= ~I40E_FLAG_HW_ATR_EVICT_CAPABLE;
	else
		pf->auto_disable_flags |= I40E_FLAG_HW_ATR_EVICT_CAPABLE;

	/* if needed, issue reset to cause things to take effect */
	if (reset_required)
		i40e_do_reset(pf, BIT(__I40E_PF_RESET_REQUESTED));

	return 0;
}
#endif /* HAVE_ETHTOOL_GET_SSET_COUNT */

static const struct ethtool_ops i40e_ethtool_ops = {
	.get_settings		= i40e_get_settings,
	.set_settings		= i40e_set_settings,
	.get_drvinfo		= i40e_get_drvinfo,
	.get_regs_len		= i40e_get_regs_len,
	.get_regs		= i40e_get_regs,
	.nway_reset		= i40e_nway_reset,
	.get_link		= ethtool_op_get_link,
	.get_wol		= i40e_get_wol,
	.set_wol		= i40e_set_wol,
	.set_eeprom		= i40e_set_eeprom,
	.get_eeprom_len		= i40e_get_eeprom_len,
	.get_eeprom		= i40e_get_eeprom,
	.get_ringparam		= i40e_get_ringparam,
	.set_ringparam		= i40e_set_ringparam,
	.get_pauseparam		= i40e_get_pauseparam,
	.set_pauseparam		= i40e_set_pauseparam,
	.get_msglevel		= i40e_get_msglevel,
	.set_msglevel		= i40e_set_msglevel,
#ifndef HAVE_NDO_SET_FEATURES
	.get_rx_csum		= i40e_get_rx_csum,
	.set_rx_csum		= i40e_set_rx_csum,
	.get_tx_csum		= i40e_get_tx_csum,
	.set_tx_csum		= i40e_set_tx_csum,
	.get_sg			= ethtool_op_get_sg,
	.set_sg			= ethtool_op_set_sg,
	.get_tso		= ethtool_op_get_tso,
	.set_tso		= i40e_set_tso,
#ifdef ETHTOOL_GFLAGS
	.get_flags		= ethtool_op_get_flags,
	.set_flags		= i40e_set_flags,
#endif
#endif /* HAVE_NDO_SET_FEATURES */
#ifdef ETHTOOL_GRXRINGS
	.get_rxnfc		= i40e_get_rxnfc,
	.set_rxnfc		= i40e_set_rxnfc,
#ifdef ETHTOOL_SRXNTUPLE
	.set_rx_ntuple		= i40e_set_rx_ntuple,
#endif
#endif
#ifndef HAVE_ETHTOOL_GET_SSET_COUNT
	.self_test_count	= i40e_diag_test_count,
#endif /* HAVE_ETHTOOL_GET_SSET_COUNT */
	.self_test		= i40e_diag_test,
	.get_strings		= i40e_get_strings,
#ifndef HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT
#ifdef HAVE_ETHTOOL_SET_PHYS_ID
	.set_phys_id		= i40e_set_phys_id,
#else
	.phys_id		= i40e_phys_id,
#endif /* HAVE_ETHTOOL_SET_PHYS_ID */
#endif /* HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT */
#ifndef HAVE_ETHTOOL_GET_SSET_COUNT
	.get_stats_count	= i40e_get_stats_count,
#else /* HAVE_ETHTOOL_GET_SSET_COUNT */
	.get_sset_count		= i40e_get_sset_count,
	.get_priv_flags		= i40e_get_priv_flags,
	.set_priv_flags		= i40e_set_priv_flags,
#endif /* HAVE_ETHTOOL_GET_SSET_COUNT */
	.get_ethtool_stats	= i40e_get_ethtool_stats,
#ifdef HAVE_ETHTOOL_GET_PERM_ADDR
	.get_perm_addr		= ethtool_op_get_perm_addr,
#endif
	.get_coalesce		= i40e_get_coalesce,
	.set_coalesce		= i40e_set_coalesce,
#if defined(ETHTOOL_SRSSH) && !defined(HAVE_ETHTOOL_GSRSSH)
	.get_rxfh_key_size	= i40e_get_rxfh_key_size,
#endif
#ifndef HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT
#ifdef ETHTOOL_GRXFHINDIR
#ifdef HAVE_ETHTOOL_GRXFHINDIR_SIZE
	.get_rxfh_indir_size	= i40e_get_rxfh_indir_size,
#endif /* HAVE_ETHTOOL_GRXFHINDIR_SIZE */
#ifdef ETHTOOL_GRSSH
	.get_rxfh		= i40e_get_rxfh,
#else
	.get_rxfh_indir		= i40e_get_rxfh_indir,
#endif /* ETHTOOL_GRSSH */
#endif /* ETHTOOL_GRXFHINDIR */
#ifdef ETHTOOL_SRXFHINDIR
#ifdef ETHTOOL_SRSSH
	.set_rxfh		= i40e_set_rxfh,
#else
	.set_rxfh_indir		= i40e_set_rxfh_indir,
#endif /* ETHTOOL_SRSSH */
#endif /* ETHTOOL_SRXFHINDIR */
#ifdef ETHTOOL_SCHANNELS
	.get_channels		= i40e_get_channels,
	.set_channels		= i40e_set_channels,
#endif
#ifdef HAVE_ETHTOOL_GET_TS_INFO
	.get_ts_info		= i40e_get_ts_info,
#endif /* HAVE_ETHTOOL_GET_TS_INFO */
#endif /* HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT */
};

#ifdef HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT
static const struct ethtool_ops_ext i40e_ethtool_ops_ext = {
	.size			= sizeof(struct ethtool_ops_ext),
	.get_ts_info		= i40e_get_ts_info,
	.set_phys_id		= i40e_set_phys_id,
	.get_channels		= i40e_get_channels,
	.set_channels		= i40e_set_channels,
	.get_rxfh_indir_size	= i40e_get_rxfh_indir_size,
	.get_rxfh_indir		= i40e_get_rxfh_indir,
	.set_rxfh_indir		= i40e_set_rxfh_indir,
};

void i40e_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &i40e_ethtool_ops;
	set_ethtool_ops_ext(netdev, &i40e_ethtool_ops_ext);
}
#else
void i40e_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &i40e_ethtool_ops;
}
#endif /* HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT */
#endif /* SIOCETHTOOL */
