// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2013, Intel Corporation. */

/* ethtool support for iavf */
#include "iavf.h"

#ifdef SIOCETHTOOL
#include <linux/uaccess.h>

#ifndef ETH_GSTRING_LEN
#define ETH_GSTRING_LEN 32
#endif

#ifdef ETHTOOL_OPS_COMPAT
#include "kcompat_ethtool.c"
#endif

#include "iavf_ethtool_stats.h"

#define VF_STAT(_name, _stat) \
	IAVF_STAT(struct iavf_adapter, _name, _stat)

static const struct iavf_stats iavf_gstrings_stats[] = {
	VF_STAT("rx_bytes", current_stats.rx_bytes),
	VF_STAT("rx_unicast", current_stats.rx_unicast),
	VF_STAT("rx_multicast", current_stats.rx_multicast),
	VF_STAT("rx_broadcast", current_stats.rx_broadcast),
	VF_STAT("rx_discards", current_stats.rx_discards),
	VF_STAT("rx_unknown_protocol", current_stats.rx_unknown_protocol),
	VF_STAT("tx_bytes", current_stats.tx_bytes),
	VF_STAT("tx_unicast", current_stats.tx_unicast),
	VF_STAT("tx_multicast", current_stats.tx_multicast),
	VF_STAT("tx_broadcast", current_stats.tx_broadcast),
	VF_STAT("tx_discards", current_stats.tx_discards),
	VF_STAT("tx_errors", current_stats.tx_errors),
	VF_STAT("tx_hwtstamp_skipped", ptp.tx_hwtstamp_skipped),
	VF_STAT("tx_hwtstamp_timeouts", ptp.tx_hwtstamp_timeouts),
#ifdef IAVF_ADD_PROBES
	VF_STAT("tx_tcp_segments", tcp_segs),
	VF_STAT("tx_udp_segments", udp_segs),
	VF_STAT("tx_tcp_cso", tx_tcp_cso),
	VF_STAT("tx_udp_cso", tx_udp_cso),
	VF_STAT("tx_sctp_cso", tx_sctp_cso),
	VF_STAT("tx_ip4_cso", tx_ip4_cso),
	VF_STAT("tx_vlano", tx_vlano),
	VF_STAT("tx_ad_vlano", tx_ad_vlano),
	VF_STAT("rx_tcp_cso", rx_tcp_cso),
	VF_STAT("rx_udp_cso", rx_udp_cso),
	VF_STAT("rx_sctp_cso", rx_sctp_cso),
	VF_STAT("rx_ip4_cso", rx_ip4_cso),
	VF_STAT("rx_vlano", rx_vlano),
	VF_STAT("rx_ad_vlano", rx_ad_vlano),
	VF_STAT("rx_tcp_cso_error", rx_tcp_cso_err),
	VF_STAT("rx_udp_cso_error", rx_udp_cso_err),
	VF_STAT("rx_sctp_cso_error", rx_sctp_cso_err),
	VF_STAT("rx_ip4_cso_error", rx_ip4_cso_err),
#endif
};

#define IAVF_STATS_LEN	ARRAY_SIZE(iavf_gstrings_stats)

#define IAVF_QUEUE_STATS_LEN	(ARRAY_SIZE(iavf_gstrings_queue_stats) + \
				 ARRAY_SIZE(iavf_gstrings_queue_stats_poll))
#define IAVF_TX_QUEUE_STATS_LEN ARRAY_SIZE(iavf_gstrings_queue_stats_tx)
#define IAVF_RX_QUEUE_STATS_LEN ARRAY_SIZE(iavf_gstrings_queue_stats_rx)
#define IAVF_VECTOR_STATS_LEN ARRAY_SIZE(iavf_gstrings_queue_stats_vector)

#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
/* For now we have one and only one private flag and it is only defined
 * when we have support for the SKIP_CPU_SYNC DMA attribute.  Instead
 * of leaving all this code sitting around empty we will strip it unless
 * our one private flag is actually available.
 */
struct iavf_priv_flags {
	char flag_string[ETH_GSTRING_LEN];
	u32 flag;
	bool read_only;
};

#define IAVF_PRIV_FLAG(_name, _flag, _read_only) { \
	.flag_string = _name, \
	.flag = _flag, \
	.read_only = _read_only, \
}

static const struct iavf_priv_flags iavf_gstrings_priv_flags[] = {
	IAVF_PRIV_FLAG("legacy-rx", IAVF_FLAG_LEGACY_RX, 0),
};

#define IAVF_PRIV_FLAGS_STR_LEN ARRAY_SIZE(iavf_gstrings_priv_flags)

static const struct iavf_priv_flags iavf_gstrings_chnl_priv_flags[] = {
	IAVF_PRIV_FLAG("channel-pkt-inspect-optimize",
		       IAVF_FLAG_CHNL_PKT_OPT_ENA, 0),
};
#define IAVF_CHNL_PRIV_FLAGS_STR_LEN ARRAY_SIZE(iavf_gstrings_chnl_priv_flags)

#endif /* HAVE_SWIOTLB_SKIP_CPU_SYNC */

/**
 * iavf_get_link_ksettings - Get Link Speed and Duplex settings
 * @netdev: network interface device structure
 * @cmd: ethtool command
 *
 * Reports speed/duplex settings. Because this is a VF, we don't know what
 * kind of link we really have, so we fake it.
 **/
static int iavf_get_link_ksettings(struct net_device *netdev,
				   struct ethtool_link_ksettings *cmd)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);

	ethtool_link_ksettings_zero_link_mode(cmd, supported);
	ethtool_link_ksettings_zero_link_mode(cmd, advertising);

	cmd->base.autoneg = AUTONEG_DISABLE;
	cmd->base.port = PORT_NONE;
	cmd->base.duplex = DUPLEX_FULL;

#ifdef VIRTCHNL_VF_CAP_ADV_LINK_SPEED
	if (ADV_LINK_SUPPORT(adapter)) {
		if (adapter->link_speed_mbps &&
		    adapter->link_speed_mbps < U32_MAX)
			cmd->base.speed = adapter->link_speed_mbps;
		else
			cmd->base.speed = SPEED_UNKNOWN;

		return 0;
	}

#endif /* VIRTCHNL_VF_CAP_ADV_LINK_SPEED */
	switch (adapter->link_speed) {
	case VIRTCHNL_LINK_SPEED_40GB:
		cmd->base.speed = SPEED_40000;
		break;
	case VIRTCHNL_LINK_SPEED_25GB:
#ifdef SPEED_25000
		cmd->base.speed = SPEED_25000;
#else
		netdev_info(netdev,
			    "Speed is 25G, display not supported by this version of ethtool.\n");
#endif
		break;
	case VIRTCHNL_LINK_SPEED_20GB:
		cmd->base.speed = SPEED_20000;
		break;
	case VIRTCHNL_LINK_SPEED_10GB:
		cmd->base.speed = SPEED_10000;
		break;
	case VIRTCHNL_LINK_SPEED_5GB:
		cmd->base.speed = SPEED_5000;
		break;
	case VIRTCHNL_LINK_SPEED_2_5GB:
		cmd->base.speed = SPEED_2500;
		break;
	case VIRTCHNL_LINK_SPEED_1GB:
		cmd->base.speed = SPEED_1000;
		break;
	case VIRTCHNL_LINK_SPEED_100MB:
		cmd->base.speed = SPEED_100;
		break;
	default:
		cmd->base.speed = SPEED_UNKNOWN;
		break;
	}

	return 0;
}

#ifndef ETHTOOL_GLINKSETTINGS
/**
 * iavf_get_settings - Get Link Speed and Duplex settings
 * @netdev: network interface device structure
 * @ecmd: ethtool command
 *
 * Reports speed/duplex settings based on media type.  Since we've backported
 * the new API constructs to use in the old API, this ends up just being
 * a wrapper to iavf_get_link_ksettings.
 **/
static int iavf_get_settings(struct net_device *netdev,
			       struct ethtool_cmd *ecmd)
{
	struct ethtool_link_ksettings ks;

	iavf_get_link_ksettings(netdev, &ks);
	_kc_ethtool_ksettings_to_cmd(&ks, ecmd);
	ecmd->transceiver = XCVR_EXTERNAL;
	return 0;
}
#endif /* !ETHTOOL_GLINKSETTINGS */

/**
 * iavf_get_sset_count - Get length of string set
 * @netdev: network interface device structure
 * @sset: id of string set
 *
 * Reports size of various string tables.
 **/
static int iavf_get_sset_count(struct net_device *netdev, int sset)
{
	/* Report the maximum number queues, even if not every queue is
	 * currently configured. Since allocation of queues is in pairs,
	 * use netdev->real_num_tx_queues * 2. The real_num_tx_queues is set
	 * at device creation and never changes.
	 */
	if (sset == ETH_SS_STATS)
		return IAVF_STATS_LEN +
			(IAVF_QUEUE_STATS_LEN * 2 *
			 netdev->real_num_tx_queues) +
			((IAVF_TX_QUEUE_STATS_LEN + IAVF_RX_QUEUE_STATS_LEN +
			 IAVF_VECTOR_STATS_LEN) * netdev->real_num_tx_queues);
#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
	else if (sset == ETH_SS_PRIV_FLAGS)
		return IAVF_PRIV_FLAGS_STR_LEN + IAVF_PRIV_FLAGS_STR_LEN;
#endif
	else
		return -EINVAL;
}

/**
 * iavf_get_ethtool_stats - report device statistics
 * @netdev: network interface device structure
 * @stats: ethtool statistics structure
 * @data: pointer to data buffer
 *
 * All statistics are added to the data buffer as an array of u64.
 **/
static void iavf_get_ethtool_stats(struct net_device *netdev,
				   struct ethtool_stats *stats, u64 *data)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	unsigned int i;

	/* Explicitly request stats refresh */
	iavf_schedule_request_stats(adapter);

	iavf_add_ethtool_stats(&data, adapter, iavf_gstrings_stats);

	rcu_read_lock();
	/* As num_active_queues describe both tx and rx queues, we can use
	 * it to iterate over rings' stats.
	 */
	for (i = 0; i < adapter->num_active_queues; i++) {
		struct iavf_ring *ring;

		/* Tx rings stats */
		ring = &adapter->tx_rings[i];
		iavf_add_queue_stats(&data, ring);
		iavf_add_queue_stats_chnl(&data, ring, IAVF_CHNL_STAT_POLL);
		iavf_add_queue_stats_chnl(&data, ring, IAVF_CHNL_STAT_TX);

		/* Rx rings stats */
		ring = &adapter->rx_rings[i];
		iavf_add_queue_stats(&data, ring);
		iavf_add_queue_stats_chnl(&data, ring, IAVF_CHNL_STAT_POLL);
		iavf_add_queue_stats_chnl(&data, ring, IAVF_CHNL_STAT_RX);
		iavf_add_queue_stats_chnl(&data, ring, IAVF_CHNL_STAT_VECTOR);
	}
	rcu_read_unlock();
}

#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
/**
 * iavf_get_priv_flag_strings - Get private flag strings
 * @netdev: network interface device structure
 * @data: buffer for string data
 *
 * Builds the private flags string table
 **/
static void iavf_get_priv_flag_strings(struct net_device *netdev, u8 *data)
{
	unsigned int i;

	for (i = 0; i < IAVF_PRIV_FLAGS_STR_LEN; i++) {
		snprintf(data, ETH_GSTRING_LEN, "%s",
			 iavf_gstrings_priv_flags[i].flag_string);
		data += ETH_GSTRING_LEN;
	}

	for (i = 0; i < IAVF_CHNL_PRIV_FLAGS_STR_LEN; i++) {
		snprintf(data, ETH_GSTRING_LEN, "%s",
			 iavf_gstrings_chnl_priv_flags[i].flag_string);
		data += ETH_GSTRING_LEN;
	}
}
#endif

/**
 * iavf_get_stat_strings - Get stat strings
 * @netdev: network interface device structure
 * @data: buffer for string data
 *
 * Builds the statistics string table
 **/
static void iavf_get_stat_strings(struct net_device *netdev, u8 *data)
{
	unsigned int i;

	iavf_add_stat_strings(&data, iavf_gstrings_stats);

	/* Queues are always allocated in pairs, so we just use
	 * real_num_tx_queues for both Tx and Rx queues.
	 */
	for (i = 0; i < netdev->real_num_tx_queues; i++) {
		iavf_add_stat_strings(&data, iavf_gstrings_queue_stats,
				      "tx", i);
		iavf_add_stat_strings(&data, iavf_gstrings_queue_stats_poll,
				      "tx", i);
		iavf_add_stat_strings(&data, iavf_gstrings_queue_stats_tx,
				      "tx", i);
		iavf_add_stat_strings(&data, iavf_gstrings_queue_stats,
				      "rx", i);
		iavf_add_stat_strings(&data, iavf_gstrings_queue_stats_poll,
				      "rx", i);
		iavf_add_stat_strings(&data, iavf_gstrings_queue_stats_rx,
				      "rx", i);
		iavf_add_stat_strings(&data, iavf_gstrings_queue_stats_vector,
				      "rx", i);
	}
}

/**
 * iavf_get_strings - Get string set
 * @netdev: network interface device structure
 * @sset: id of string set
 * @data: buffer for string data
 *
 * Builds string tables for various string sets
 **/
static void iavf_get_strings(struct net_device *netdev, u32 sset, u8 *data)
{
	switch (sset) {
	case ETH_SS_STATS:
		iavf_get_stat_strings(netdev, data);
		break;
#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
	case ETH_SS_PRIV_FLAGS:
		iavf_get_priv_flag_strings(netdev, data);
		break;
#endif
	default:
		break;
	}
}

#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
/**
 * iavf_get_priv_flags - report device private flags
 * @netdev: network interface device structure
 *
 * The get string set count and the string set should be matched for each
 * flag returned.  Add new strings for each flag to the iavf_gstrings_priv_flags
 * array.
 *
 * Returns a u32 bitmap of flags.
 **/
static u32 iavf_get_priv_flags(struct net_device *netdev)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	const struct iavf_priv_flags *priv_flags;
	u32 i, ret_flags = 0;

	for (i = 0; i < IAVF_PRIV_FLAGS_STR_LEN; i++) {
		priv_flags = &iavf_gstrings_priv_flags[i];

		if (priv_flags->flag & adapter->flags)
			ret_flags |= BIT(i);
	}

	for (i = 0; i < IAVF_CHNL_PRIV_FLAGS_STR_LEN; i++) {
		priv_flags = &iavf_gstrings_chnl_priv_flags[i];

		if (priv_flags->flag & adapter->chnl_perf_flags)
			ret_flags |= BIT(i + IAVF_PRIV_FLAGS_STR_LEN);
	}

	return ret_flags;
}

/**
 * iavf_determine_priv_flag_change - detect any change in private flags
 * @priv_flags: Ptr to private flags array
 * @num: count of private flags
 * @bit_offset: "offset" into unified view of bits
 * @flags: bit flags to be set
 * @orig: Ptr to flags
 * @changed_flags: bits changed (based on orig and new value)
 *
 * Detect any changes in priv flags and return those changed bits
 **/
static int
iavf_determine_priv_flag_change(const struct iavf_priv_flags *priv_flags,
				int num, int bit_offset, u32 flags, u32 *orig,
				u32 *changed_flags)
{
	u32 orig_flags = READ_ONCE(*orig);
	u32 new_flags;
	int i;

	new_flags = orig_flags;

	for (i = 0; i < num; i++) {
		if (flags & BIT(i + bit_offset))
			new_flags |= priv_flags->flag;
		else
			new_flags &= ~(priv_flags->flag);

		if (priv_flags->read_only &&
		    ((orig_flags ^ new_flags) & ~BIT(i)))
			return -EOPNOTSUPP;
		priv_flags++;
	}

	/* Before we finalize any flag changes, any checks which we need to
	 * perform to determine if the new flags will be supported should go
	 * here...
	 */

	/* Compare and exchange the new flags into place. If we failed, that
	 * is if cmpxchg returns anything but the old value, this means
	 * something else must have modified the flags variable since we
	 * copied it. We'll just punt with an error and log something in the
	 * message buffer.
	 */
	if (cmpxchg(orig, orig_flags, new_flags) != orig_flags)
		return -EAGAIN;

	*changed_flags = orig_flags ^ new_flags;
	return 0;
}

/**
 * iavf_set_priv_flags - set private flags
 * @netdev: network interface device structure
 * @flags: bit flags to be set
 **/
static int iavf_set_priv_flags(struct net_device *netdev, u32 flags)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	u32 changed_chnl_flags;
	u32 changed_flags;
	int ret;

	ret = iavf_determine_priv_flag_change(&iavf_gstrings_priv_flags[0],
					      IAVF_PRIV_FLAGS_STR_LEN, 0,
					      flags, &adapter->flags,
					      &changed_flags);
	if (ret) {
		if (ret == -EAGAIN)
			dev_warn(&adapter->pdev->dev,
				 "Unable to update adapter->flags as it was modified by another thread...\n");
		return ret;
	}

	ret = iavf_determine_priv_flag_change(&iavf_gstrings_chnl_priv_flags[0],
					      IAVF_CHNL_PRIV_FLAGS_STR_LEN,
					      IAVF_PRIV_FLAGS_STR_LEN,
					      flags, &adapter->chnl_perf_flags,
					      &changed_chnl_flags);
	if (ret) {
		if (ret == -EAGAIN)
			dev_warn(&adapter->pdev->dev,
				 "Unable to update adapter->chnl_perf_flags as it was modified by another thread...\n");
		return ret;
	}

	/* Process any additional changes needed as a result of flag changes.
	 * The changed_flags value reflects the list of bits that were changed
	 * in the code above.
	 */

	/* issue a reset to force legacy-rx change to take effect */
	if (changed_flags & IAVF_FLAG_LEGACY_RX) {
		if (netif_running(netdev))
			iavf_schedule_reset(adapter);
	}
	/* Process any additional changes needed as a result of change
	 * in channel specific flag(s)
	 */
	iavf_setup_ch_info(adapter, changed_chnl_flags);

	return 0;
}
#endif /* HAVE_SWIOTLB_SKIP_CPU_SYNC */
#ifndef HAVE_NDO_SET_FEATURES
/**
 * iavf_get_rx_csum - Get RX checksum settings
 * @netdev: network interface device structure
 *
 * Returns true or false depending upon RX checksum enabled.
 **/
static u32 iavf_get_rx_csum(struct net_device *netdev)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);

	return adapter->flags & IAVF_FLAG_RX_CSUM_ENABLED;
}

/**
 * iavf_set_rx_csum - Set RX checksum settings
 * @netdev: network interface device structure
 * @data: RX checksum setting (boolean)
 *
 **/
static int iavf_set_rx_csum(struct net_device *netdev, u32 data)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);

	if (data)
		adapter->flags |= IAVF_FLAG_RX_CSUM_ENABLED;
	else
		adapter->flags &= ~IAVF_FLAG_RX_CSUM_ENABLED;

	return 0;
}

/**
 * iavf_get_tx_csum - Get TX checksum settings
 * @netdev: network interface device structure
 *
 * Returns true or false depending upon TX checksum enabled.
 **/
static u32 iavf_get_tx_csum(struct net_device *netdev)
{
	return (netdev->features & NETIF_F_IP_CSUM) != 0;
}

/**
 * iavf_set_tx_csum - Set TX checksum settings
 * @netdev: network interface device structure
 * @data: TX checksum setting (boolean)
 *
 **/
static int iavf_set_tx_csum(struct net_device *netdev, u32 data)
{
	if (data)
		netdev->features |= (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM);
	else
		netdev->features &= ~(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM);

	return 0;
}

/**
 * iavf_set_tso - Set TX segmentation offload settings
 * @netdev: network interface device structure
 * @data: TSO setting (boolean)
 *
 **/
static int iavf_set_tso(struct net_device *netdev, u32 data)
{
	if (data) {
		netdev->features |= NETIF_F_TSO;
		netdev->features |= NETIF_F_TSO6;
	} else {
		netif_tx_stop_all_queues(netdev);
		netdev->features &= ~NETIF_F_TSO;
		netdev->features &= ~NETIF_F_TSO6;
#ifndef HAVE_NETDEV_VLAN_FEATURES
		/* disable TSO on all VLANs if they're present */
		if (adapter->vsi.vlgrp) {
			struct iavf_adapter *adapter = netdev_priv(netdev);
			struct vlan_group *vlgrp = adapter->vsi.vlgrp;
			struct net_device *v_netdev;
			int i;

			for (i = 0; i < VLAN_GROUP_ARRAY_LEN; i++) {
				v_netdev = vlan_group_get_device(vlgrp, i);
				if (v_netdev) {
					v_netdev->features &= ~NETIF_F_TSO;
					v_netdev->features &= ~NETIF_F_TSO6;
					vlan_group_set_device(vlgrp, i,
							      v_netdev);
				}
			}
		}
#endif
		netif_tx_start_all_queues(netdev);
	}
	return 0;
}

#endif /* HAVE_NDO_SET_FEATURES */
/**
 * iavf_get_msglevel - Get debug message level
 * @netdev: network interface device structure
 *
 * Returns current debug message level.
 **/
static u32 iavf_get_msglevel(struct net_device *netdev)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);

	return adapter->msg_enable;
}

/**
 * iavf_set_msglevel - Set debug message level
 * @netdev: network interface device structure
 * @data: message level
 *
 * Set current debug message level. Higher values cause the driver to
 * be noisier.
 **/
static void iavf_set_msglevel(struct net_device *netdev, u32 data)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);

	if (IAVF_DEBUG_USER & data)
		adapter->hw.debug_mask = data;
	adapter->msg_enable = data;
}

/**
 * iavf_get_drvinfo - Get driver info
 * @netdev: network interface device structure
 * @drvinfo: ethool driver info structure
 *
 * Returns information about the driver and device for display to the user.
 **/
static void iavf_get_drvinfo(struct net_device *netdev,
			     struct ethtool_drvinfo *drvinfo)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);

	strlcpy(drvinfo->driver, iavf_driver_name, 32);
	strlcpy(drvinfo->version, iavf_driver_version, 32);
	strlcpy(drvinfo->fw_version, "N/A", 4);
	strlcpy(drvinfo->bus_info, pci_name(adapter->pdev), 32);
#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
	drvinfo->n_priv_flags = IAVF_PRIV_FLAGS_STR_LEN;
#endif
}

/**
 * iavf_get_ringparam - Get ring parameters
 * @netdev: network interface device structure
 * @ring: ethtool ringparam structure
 * @ker: unused kernel ethtool ringparam structure
 * @extack: unused netlink extended ACK structure
 *
 * Returns current ring parameters. TX and RX rings are reported separately,
 * but the number of rings is not reported.
 **/
#ifdef HAVE_ETHTOOL_EXTENDED_RINGPARAMS
static void
iavf_get_ringparam(struct net_device *netdev,
		   struct ethtool_ringparam *ring,
		   struct kernel_ethtool_ringparam __always_unused *ker,
		   struct netlink_ext_ack __always_unused *extack)
#else
static void iavf_get_ringparam(struct net_device *netdev,
			       struct ethtool_ringparam *ring)
#endif /* HAVE_ETHTOOL_EXTENDED_RINGPARAMS */
{
	struct iavf_adapter *adapter = netdev_priv(netdev);

	ring->rx_max_pending = IAVF_MAX_RXD;
	ring->tx_max_pending = IAVF_MAX_TXD;
	ring->rx_pending = adapter->rx_desc_count;
	ring->tx_pending = adapter->tx_desc_count;
}

/**
 * iavf_set_ringparam - Set ring parameters
 * @netdev: network interface device structure
 * @ring: ethtool ringparam structure
 * @ker: unused kernel ethtool ringparam structure
 * @extack: unused netlink extended ACK structure
 *
 * Sets ring parameters. TX and RX rings are controlled separately, but the
 * number of rings is not specified, so all rings get the same settings.
 **/
#ifdef HAVE_ETHTOOL_EXTENDED_RINGPARAMS
static int
iavf_set_ringparam(struct net_device *netdev,
		   struct ethtool_ringparam *ring,
		   struct kernel_ethtool_ringparam __always_unused *ker,
		   struct netlink_ext_ack __always_unused *extack)
#else
static int iavf_set_ringparam(struct net_device *netdev,
			      struct ethtool_ringparam *ring)
#endif /* HAVE_ETHTOOL_EXTENDED_RINGPARAMS */
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	u32 new_rx_count, new_tx_count;

	if ((ring->rx_mini_pending) || (ring->rx_jumbo_pending))
		return -EINVAL;

	if ((adapter->state == __IAVF_RESETTING) ||
	    ((adapter->state == __IAVF_RUNNING) &&
	     (adapter->flags & IAVF_FLAG_QUEUES_DISABLED)))
		return -EAGAIN;

	if (ring->tx_pending > IAVF_MAX_TXD ||
	    ring->tx_pending < IAVF_MIN_TXD ||
	    ring->rx_pending > IAVF_MAX_RXD ||
	    ring->rx_pending < IAVF_MIN_RXD) {
		netdev_err(netdev, "Descriptors requested (Tx: %d / Rx: %d) out of range [%d-%d] (increment %d)\n",
			   ring->tx_pending, ring->rx_pending, IAVF_MIN_TXD,
			   IAVF_MAX_RXD, IAVF_REQ_DESCRIPTOR_MULTIPLE);
		return -EINVAL;
	}

	new_tx_count = ALIGN(ring->tx_pending, IAVF_REQ_DESCRIPTOR_MULTIPLE);
	if (new_tx_count != ring->tx_pending)
		netdev_info(netdev, "Requested Tx descriptor count rounded up to %d\n",
			    new_tx_count);

	new_rx_count = ALIGN(ring->rx_pending, IAVF_REQ_DESCRIPTOR_MULTIPLE);
	if (new_rx_count != ring->rx_pending)
		netdev_info(netdev, "Requested Rx descriptor count rounded up to %d\n",
			    new_rx_count);

	/* if nothing to do return success */
	if ((new_tx_count == adapter->tx_desc_count) &&
	    (new_rx_count == adapter->rx_desc_count)) {
		netdev_dbg(netdev, "Nothing to change, descriptor count is same as requested\n");
		return 0;
	}

	if (new_tx_count != adapter->tx_desc_count) {
		netdev_info(netdev, "Changing Tx descriptor count from %d to %d\n",
			    adapter->tx_desc_count, new_tx_count);
		adapter->tx_desc_count = new_tx_count;
	}

	if (new_rx_count != adapter->rx_desc_count) {
		netdev_info(netdev, "Changing Rx descriptor count from %d to %d\n",
			    adapter->rx_desc_count, new_rx_count);
		adapter->rx_desc_count = new_rx_count;
	}

	if (netif_running(netdev))
		iavf_schedule_reset(adapter);

	return 0;
}

/**
 * __iavf_get_coalesce - get per-queue coalesce settings
 * @netdev: the netdev to check
 * @ec: ethtool coalesce data structure
 * @queue: which queue to pick
 *
 * Gets the per-queue settings for coalescence. Specifically Rx and Tx usecs
 * are per queue. If queue is <0 then we default to queue 0 as the
 * representative value.
 **/
static int __iavf_get_coalesce(struct net_device *netdev,
			       struct ethtool_coalesce *ec, int queue)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	struct iavf_ring *rx_ring, *tx_ring;

	/* Rx and Tx usecs per queue value. If user doesn't specify the
	 * queue, return queue 0's value to represent.
	 */
	if (queue < 0)
		queue = 0;
	else if (queue >= adapter->num_active_queues)
		return -EINVAL;

	rx_ring = &adapter->rx_rings[queue];
	tx_ring = &adapter->tx_rings[queue];

	if (ITR_IS_DYNAMIC(rx_ring->itr_setting))
		ec->use_adaptive_rx_coalesce = 1;

	if (ITR_IS_DYNAMIC(tx_ring->itr_setting))
		ec->use_adaptive_tx_coalesce = 1;

	ec->rx_coalesce_usecs = rx_ring->itr_setting & ~IAVF_ITR_DYNAMIC;
	ec->tx_coalesce_usecs = tx_ring->itr_setting & ~IAVF_ITR_DYNAMIC;

	return 0;
}

/**
 * iavf_get_coalesce - Get interrupt coalescing settings
 * @netdev: network interface device structure
 * @ec: ethtool coalesce structure
 * @kec: kernel coalesce parameter
 * @extack: kernel extack parameter
 *
 * Returns current coalescing settings. This is referred to elsewhere in the
 * driver as Interrupt Throttle Rate, as this is how the hardware describes
 * this functionality. Note that if per-queue settings have been modified this
 * only represents the settings of queue 0.
 **/
#ifdef HAVE_ETHTOOL_COALESCE_EXTACK
static int
iavf_get_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		  struct kernel_ethtool_coalesce __maybe_unused *kec,
		  struct netlink_ext_ack __maybe_unused *extack)
#else
static int iavf_get_coalesce(struct net_device *netdev,
			     struct ethtool_coalesce *ec)
#endif /* HAVE_ETHTOOL_COALESCE_EXTACK */
{
	return __iavf_get_coalesce(netdev, ec, -1);
}

#ifdef ETHTOOL_PERQUEUE
/**
 * iavf_get_per_queue_coalesce - get coalesce values for specific queue
 * @netdev: netdev to read
 * @ec: coalesce settings from ethtool
 * @queue: the queue to read
 *
 * Read specific queue's coalesce settings.
 **/
static int iavf_get_per_queue_coalesce(struct net_device *netdev, u32 queue,
				       struct ethtool_coalesce *ec)
{
	return __iavf_get_coalesce(netdev, ec, queue);
}
#endif /* ETHTOOL_PERQUEUE */

/**
 * iavf_set_itr_per_queue - set ITR values for specific queue
 * @adapter: the VF adapter struct to set values for
 * @ec: coalesce settings from ethtool
 * @queue: the queue to modify
 *
 * Change the ITR settings for a specific queue.
 **/
static int iavf_set_itr_per_queue(struct iavf_adapter *adapter,
				  struct ethtool_coalesce *ec, int queue)
{
	struct iavf_ring *rx_ring = &adapter->rx_rings[queue];
	struct iavf_ring *tx_ring = &adapter->tx_rings[queue];
	struct iavf_q_vector *q_vector;
	u16 itr_setting;

	itr_setting = rx_ring->itr_setting & ~IAVF_ITR_DYNAMIC;

	if (ec->rx_coalesce_usecs != itr_setting &&
	    ec->use_adaptive_rx_coalesce) {
		netif_info(adapter, drv, adapter->netdev,
			   "Rx interrupt throttling cannot be changed if adaptive-rx is enabled\n");
		return -EINVAL;
	}

	itr_setting = tx_ring->itr_setting & ~IAVF_ITR_DYNAMIC;

	if (ec->tx_coalesce_usecs != itr_setting &&
	    ec->use_adaptive_tx_coalesce) {
		netif_info(adapter, drv, adapter->netdev,
			   "Tx interrupt throttling cannot be changed if adaptive-tx is enabled\n");
		return -EINVAL;
	}

	rx_ring->itr_setting = ITR_REG_ALIGN(ec->rx_coalesce_usecs);
	tx_ring->itr_setting = ITR_REG_ALIGN(ec->tx_coalesce_usecs);

	rx_ring->itr_setting |= IAVF_ITR_DYNAMIC;
	if (!ec->use_adaptive_rx_coalesce)
		rx_ring->itr_setting ^= IAVF_ITR_DYNAMIC;

	tx_ring->itr_setting |= IAVF_ITR_DYNAMIC;
	if (!ec->use_adaptive_tx_coalesce)
		tx_ring->itr_setting ^= IAVF_ITR_DYNAMIC;

	q_vector = rx_ring->q_vector;
	q_vector->rx.target_itr = ITR_TO_REG(rx_ring->itr_setting);

	q_vector = tx_ring->q_vector;
	q_vector->tx.target_itr = ITR_TO_REG(tx_ring->itr_setting);

	/* The interrupt handler itself will take care of programming
	 * the Tx and Rx ITR values based on the values we have entered
	 * into the q_vector, no need to write the values now.
	 */
	return 0;
}

/**
 * __iavf_set_coalesce - set coalesce settings for particular queue
 * @netdev: the netdev to change
 * @ec: ethtool coalesce settings
 * @queue: the queue to change
 *
 * Sets the coalesce settings for a particular queue.
 **/
static int __iavf_set_coalesce(struct net_device *netdev,
			       struct ethtool_coalesce *ec, int queue)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	int i;

	if (ec->rx_coalesce_usecs == 0) {
		if (ec->use_adaptive_rx_coalesce)
			netif_info(adapter, drv, netdev, "rx-usecs=0, need to disable adaptive-rx for a complete disable\n");
	} else if ((ec->rx_coalesce_usecs < IAVF_MIN_ITR) ||
		   (ec->rx_coalesce_usecs > IAVF_MAX_ITR)) {
		netif_info(adapter, drv, netdev, "Invalid value, rx-usecs range is 0-8160\n");
		return -EINVAL;
	}

	if (ec->tx_coalesce_usecs == 0) {
		if (ec->use_adaptive_tx_coalesce)
			netif_info(adapter, drv, netdev, "tx-usecs=0, need to disable adaptive-tx for a complete disable\n");
	} else if ((ec->tx_coalesce_usecs < IAVF_MIN_ITR) ||
		   (ec->tx_coalesce_usecs > IAVF_MAX_ITR)) {
		netif_info(adapter, drv, netdev, "Invalid value, tx-usecs range is 0-8160\n");
		return -EINVAL;
	}

	/* Rx and Tx usecs has per queue value. If user doesn't specify the
	 * queue, apply to all queues.
	 */
	if (queue < 0) {
		for (i = 0; i < adapter->num_active_queues; i++)
			if (iavf_set_itr_per_queue(adapter, ec, i))
				return -EINVAL;
	} else if (queue < adapter->num_active_queues) {
		if (iavf_set_itr_per_queue(adapter, ec, queue))
			return -EINVAL;
	} else {
		netif_info(adapter, drv, netdev, "Invalid queue value, queue range is 0 - %d\n",
			   adapter->num_active_queues - 1);
		return -EINVAL;
	}

	return 0;
}

/**
 * iavf_set_coalesce - Set interrupt coalescing settings
 * @netdev: network interface device structure
 * @ec: ethtool coalesce structure
 * @kec: kernel coalesce parameter
 * @extack: kernel extack parameter
 *
 * Change current coalescing settings for every queue.
 **/
#ifdef HAVE_ETHTOOL_COALESCE_EXTACK
static int
iavf_set_coalesce(struct net_device *netdev, struct ethtool_coalesce *ec,
		  struct kernel_ethtool_coalesce __maybe_unused *kec,
		  struct netlink_ext_ack __maybe_unused *extack)
#else
static int iavf_set_coalesce(struct net_device *netdev,
			     struct ethtool_coalesce *ec)
#endif /* HAVE_ETHTOOL_COALESCE_EXTACK */
{
	return __iavf_set_coalesce(netdev, ec, -1);
}

#ifdef ETHTOOL_PERQUEUE
/**
 * iavf_set_per_queue_coalesce - set specific queue's coalesce settings
 * @netdev: the netdev to change
 * @ec: ethtool's coalesce settings
 * @queue: the queue to modify
 *
 * Modifies a specific queue's coalesce settings.
 */
static int iavf_set_per_queue_coalesce(struct net_device *netdev, u32 queue,
				       struct ethtool_coalesce *ec)
{
	return __iavf_set_coalesce(netdev, ec, queue);
}
#endif /* ETHTOOL_PERQUEUE */

#ifdef ETHTOOL_GRXRINGS
/**
 * iavf_get_rxnfc - command to get RX flow classification rules
 * @netdev: network interface device structure
 * @cmd: ethtool rxnfc command
 * @rule_locs: pointer to store rule locations
 *
 * Returns Success if the command is supported.
 **/
static int iavf_get_rxnfc(struct net_device *netdev,
			  struct ethtool_rxnfc *cmd,
#ifdef HAVE_ETHTOOL_GET_RXNFC_VOID_RULE_LOCS
			  void *rule_locs)
#else
			  u32 *rule_locs)
#endif
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = adapter->num_active_queues;
		ret = 0;
		break;
	case ETHTOOL_GRXFH:
		netdev_info(netdev,
			    "RSS hash info is not available to vf, use pf.\n");
		break;
	default:
		break;
	}

	return ret;
}
#endif /* ETHTOOL_GRXRINGS */
#ifdef ETHTOOL_GCHANNELS
/**
 * iavf_get_channels: get the number of channels supported by the device
 * @netdev: network interface device structure
 * @ch: channel information structure
 *
 * For the purposes of our device, we only use combined channels, i.e. a tx/rx
 * queue pair. Report one extra channel to match our "other" MSI-X vector.
 **/
static void iavf_get_channels(struct net_device *netdev,
			      struct ethtool_channels *ch)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);

	/* Report maximum channels */
	ch->max_combined = adapter->vsi_res->num_queue_pairs;

	ch->max_other = NONQ_VECS;
	ch->other_count = NONQ_VECS;

	ch->combined_count = adapter->num_active_queues;
}

/**
 * iavf_set_channels: set the new channel count
 * @netdev: network interface device structure
 * @ch: channel information structure
 *
 * Negotiate a new number of channels with the PF then do a reset.  During
 * reset we'll realloc queues and fix the RSS table.  Returns 0 on success,
 * negative on failure.
 **/
static int iavf_set_channels(struct net_device *netdev,
			     struct ethtool_channels *ch)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	u32 num_req = ch->combined_count;
	int i;

#ifdef __TC_MQPRIO_MODE_MAX
	if (iavf_is_adq_enabled(adapter)) {
		dev_info(&adapter->pdev->dev, "Cannot set channels since ADQ is enabled.\n");
		return -EOPNOTSUPP;
	}
#endif /* __TC_MQPRIO_MODE_MAX */

	/* All of these should have already been checked by ethtool before this
	 * even gets to us, but just to be sure.
	 */
	if (num_req == 0 || num_req > adapter->vsi_res->num_queue_pairs)
		return -EINVAL;

	if (num_req == adapter->num_active_queues)
		return 0;

	if (ch->rx_count || ch->tx_count || ch->other_count != NONQ_VECS)
		return -EINVAL;

	adapter->num_req_queues = num_req;
	adapter->flags |= IAVF_FLAG_REINIT_ITR_NEEDED;
	iavf_schedule_reset(adapter);

	/* wait for the reset is done */
	for (i = 0; i < IAVF_RESET_WAIT_COMPLETE_COUNT; i++) {
		msleep(IAVF_RESET_WAIT_MS);
		if (adapter->flags & IAVF_FLAG_RESET_PENDING)
			continue;
		break;
	}
	if (i == IAVF_RESET_WAIT_COMPLETE_COUNT) {
		adapter->flags &= ~IAVF_FLAG_REINIT_ITR_NEEDED;
		adapter->num_active_queues = num_req;
		return -EOPNOTSUPP;
	}

	return 0;
}

#endif /* ETHTOOL_GCHANNELS */

#if defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)
/**
 * iavf_get_rxfh_key_size - get the RSS hash key size
 * @netdev: network interface device structure
 *
 * Returns the table size.
 **/
static u32 iavf_get_rxfh_key_size(struct net_device *netdev)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);

	return adapter->rss_key_size;
}

/**
 * iavf_get_rxfh_indir_size - get the rx flow hash indirection table size
 * @netdev: network interface device structure
 *
 * Returns the table size.
 **/
static u32 iavf_get_rxfh_indir_size(struct net_device *netdev)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);

	return adapter->rss_lut_size;
}

/**
 * iavf_get_rxfh - get the rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 * @key: hash key
 * @hfunc: hash function in use
 *
 * Reads the indirection table directly from the hardware. Always returns 0.
 **/
#ifdef HAVE_RXFH_HASHFUNC
static int iavf_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key,
			 u8 *hfunc)
#else
static int iavf_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key)
#endif
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	u16 i;

#ifdef HAVE_RXFH_HASHFUNC
	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;

#endif

	if (key)
		memcpy(key, adapter->rss_key, adapter->rss_key_size);

	if (indir)
		/* Each 32 bits pointed by 'indir' is stored with a lut entry */
		for (i = 0; i < adapter->rss_lut_size; i++)
			indir[i] = (u32)adapter->rss_lut[i];

	return 0;
}

/**
 * iavf_set_rxfh - set the rx flow hash indirection table
 * @netdev: network interface device structure
 * @indir: indirection table
 * @key: hash key
 * @hfunc: hash function to use
 *
 * Returns -EINVAL if the table specifies an invalid queue id, otherwise
 * returns 0 after programming the table.
 **/
#ifdef HAVE_RXFH_HASHFUNC
static int iavf_set_rxfh(struct net_device *netdev, const u32 *indir,
			   const u8 *key, const u8 hfunc)
#else
#ifdef HAVE_RXFH_NONCONST
static int iavf_set_rxfh(struct net_device *netdev, u32 *indir, u8 *key)
#else
static int iavf_set_rxfh(struct net_device *netdev, const u32 *indir,
			   const u8 *key)
#endif /* HAVE_RXFH_NONCONST */
#endif /* HAVE_RXFH_HASHFUNC */
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	u16 i;

#ifdef __TC_MQPRIO_MODE_MAX
	if (iavf_is_adq_enabled(adapter)) {
		dev_info(&adapter->pdev->dev,
			 "Change in RSS params is not supported when ADQ is configured.\n");
		return -EOPNOTSUPP;
	}
#endif /* __TC_MQPRIO_MODE_MAX */

#ifdef HAVE_RXFH_HASHFUNC
	/* Only support toeplitz hash function */
	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;
#endif

	if (indir) {
		/* Verify user input. */
		for (i = 0; i < adapter->rss_lut_size; i++) {
			if (indir[i] >= adapter->num_active_queues)
				return -EINVAL;
		}
	}

	if (!key && !indir)
		return 0;

	if (key)
		memcpy(adapter->rss_key, key, adapter->rss_key_size);

	if (indir) {
		/* Each 32 bits pointed by 'indir' is stored with a lut entry */
		for (i = 0; i < adapter->rss_lut_size; i++)
			adapter->rss_lut[i] = (u8)(indir[i]);
	}

	return iavf_config_rss(adapter);
}
#endif /* ETHTOOL_GRSSH && ETHTOOL_SRSSH */

#ifdef HAVE_ETHTOOL_GET_TS_INFO
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
/**
 * iavf_get_ts_info - Report available timestamping capabilities
 * @netdev: the netdevice to report for
 * @info: structure to fill in
 *
 * Based on device features enabled, report the Tx and Rx timestamp
 * capabilities, as well as the PTP hardware clock index to user space.
 */
static int iavf_get_ts_info(struct net_device *netdev, struct ethtool_ts_info *info)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);

	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
				SOF_TIMESTAMPING_RX_SOFTWARE |
				SOF_TIMESTAMPING_SOFTWARE;

	if (iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_TX_TSTAMP)) {
		info->so_timestamping |= SOF_TIMESTAMPING_TX_HARDWARE |
					 SOF_TIMESTAMPING_RAW_HARDWARE;
		info->tx_types = BIT(HWTSTAMP_TX_OFF) | BIT(HWTSTAMP_TX_ON);
	}

	/* Rx timestamps are only supported on the flexible descriptors. Do
	 * not report support unless we both have the capability and
	 * configured with the appropriate descriptor format
	 */
	if (iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_RX_TSTAMP) &&
	    adapter->rxdid == VIRTCHNL_RXDID_2_FLEX_SQ_NIC) {
		info->so_timestamping |= SOF_TIMESTAMPING_RX_HARDWARE |
					 SOF_TIMESTAMPING_RAW_HARDWARE;
		info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) | BIT(HWTSTAMP_FILTER_ALL);
	}

	if (adapter->ptp.initialized)
		info->phc_index = ptp_clock_index(adapter->ptp.clock);
	else
		info->phc_index = -1;

	return 0;
}
#endif /* CONFIG_PTP_1588_CLOCK */
#endif /* HAVE_ETHTOOL_GET_TS_INFO */

static const struct ethtool_ops iavf_ethtool_ops = {
#ifdef ETHTOOL_COALESCE_USECS
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				     ETHTOOL_COALESCE_USE_ADAPTIVE,
#endif /* ETHTOOL_COALESCE_USECS */
	.get_drvinfo		= iavf_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_ringparam		= iavf_get_ringparam,
	.set_ringparam		= iavf_set_ringparam,
#ifndef HAVE_NDO_SET_FEATURES
	.get_rx_csum		= iavf_get_rx_csum,
	.set_rx_csum		= iavf_set_rx_csum,
	.get_tx_csum		= iavf_get_tx_csum,
	.set_tx_csum		= iavf_set_tx_csum,
	.get_sg			= ethtool_op_get_sg,
	.set_sg			= ethtool_op_set_sg,
	.get_tso		= ethtool_op_get_tso,
	.set_tso		= iavf_set_tso,
#endif /* HAVE_NDO_SET_FEATURES */
	.get_strings		= iavf_get_strings,
	.get_ethtool_stats	= iavf_get_ethtool_stats,
	.get_sset_count		= iavf_get_sset_count,
#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
	.get_priv_flags		= iavf_get_priv_flags,
	.set_priv_flags		= iavf_set_priv_flags,
#endif
	.get_msglevel		= iavf_get_msglevel,
	.set_msglevel		= iavf_set_msglevel,
	.get_coalesce		= iavf_get_coalesce,
	.set_coalesce		= iavf_set_coalesce,
#ifdef ETHTOOL_PERQUEUE
	.get_per_queue_coalesce = iavf_get_per_queue_coalesce,
	.set_per_queue_coalesce = iavf_set_per_queue_coalesce,
#endif
#ifdef ETHTOOL_GRXRINGS
	.get_rxnfc		= iavf_get_rxnfc,
#endif
#ifndef HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT
#if defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)
	.get_rxfh_key_size	= iavf_get_rxfh_key_size,
	.get_rxfh_indir_size	= iavf_get_rxfh_indir_size,
	.get_rxfh		= iavf_get_rxfh,
	.set_rxfh		= iavf_set_rxfh,
#endif /* ETHTOOL_GRSSH && ETHTOOL_SRSSH */
#ifdef ETHTOOL_GCHANNELS
	.get_channels		= iavf_get_channels,
	.set_channels		= iavf_set_channels,
#endif
#endif /* HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT */
#ifdef ETHTOOL_GLINKSETTINGS
	.get_link_ksettings	= iavf_get_link_ksettings,
#else
	.get_settings		= iavf_get_settings,
#endif /* ETHTOOL_GLINKSETTINGS */
#ifdef HAVE_ETHTOOL_GET_TS_INFO
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	.get_ts_info		= iavf_get_ts_info,
#endif
#endif
};

#ifdef HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT
static const struct ethtool_ops_ext iavf_ethtool_ops_ext = {
	.size			= sizeof(struct ethtool_ops_ext),
	.get_channels		= iavf_get_channels,
	.set_channels		= iavf_set_channels,
#if defined(ETHTOOL_GRSSH) && defined(ETHTOOL_SRSSH)
	.get_rxfh_key_size	= iavf_get_rxfh_key_size,
	.get_rxfh_indir_size	= iavf_get_rxfh_indir_size,
	.get_rxfh		= iavf_get_rxfh,
	.set_rxfh		= iavf_set_rxfh,
#endif /* ETHTOOL_GRSSH && ETHTOOL_SRSSH */
};
#endif /* HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT */

/**
 * iavf_set_ethtool_ops - Initialize ethtool ops struct
 * @netdev: network interface device structure
 *
 * Sets ethtool ops struct in our netdev so that ethtool can call
 * our functions.
 **/
void iavf_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &iavf_ethtool_ops;
#ifdef HAVE_RHEL6_ETHTOOL_OPS_EXT_STRUCT
	set_ethtool_ops_ext(netdev, &iavf_ethtool_ops_ext);
#endif
}

#endif /* SIOCETHTOOL */
