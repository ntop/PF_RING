/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice.h"
#include "ice_eswitch.h"
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include "ice_devlink.h"
#endif /* CONFIG_NET_DEVLINK */
#include "ice_sriov.h"
#include "ice_tc_lib.h"
#include "ice_lib.h"
#ifdef HAVE_DEVLINK_RATE_NODE_CREATE
#include "ice_dcb_lib.h"
#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */

#ifdef HAVE_NDO_GET_PHYS_PORT_NAME
/**
 * ice_repr_get_sw_port_id - get port ID associated with representor
 * @repr: pointer to port representor
 */
static int ice_repr_get_sw_port_id(struct ice_repr *repr)
{
	return repr->src_vsi->back->hw.port_info->lport;
}

/**
 * ice_repr_get_phys_port_name - get phys port name
 * @netdev: pointer to port representor netdev
 * @buf: write here port name
 * @len: max length of buf
 */
static int
ice_repr_get_phys_port_name(struct net_device *netdev, char *buf, size_t len)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_repr *repr = np->repr;
	int res;

#if IS_ENABLED(CONFIG_NET_DEVLINK)
	/* Devlink port is registered and devlink core is taking care of name formatting. */
	if (repr->vf->devlink_port.devlink)
		return -EOPNOTSUPP;
#endif /* CONFIG_NET_DEVLINK */

	res = snprintf(buf, len, "pf%dvfr%d", ice_repr_get_sw_port_id(repr),
		       repr->id);
	if (res <= 0)
		return -EOPNOTSUPP;
	return 0;
}
#endif /* HAVE_NDO_GET_PHYS_PORT_NAME */

/**
 * ice_repr_inc_tx_stats - increment Tx statistic by one packet
 * @repr: repr to increment stats on
 * @len: length of the packet
 * @ret: value returned by xmit function
 */
void ice_repr_inc_tx_stats(struct ice_repr *repr, unsigned int len, int ret)
{
	struct ice_repr_pcpu_stats *stats;

	if (unlikely(ret != NET_XMIT_SUCCESS && ret != NET_XMIT_CN)) {
		this_cpu_inc(repr->stats->tx_drops);
		return;
	}

	stats = this_cpu_ptr(repr->stats);
	u64_stats_update_begin(&stats->syncp);
	stats->tx_packets++;
	stats->tx_bytes += len;
	u64_stats_update_end(&stats->syncp);
}

/**
 * ice_repr_inc_rx_stats - increment Rx statistic by one packet
 * @netdev: repr netdev to increment stats on
 * @len: length of the packet
 */
void ice_repr_inc_rx_stats(const struct net_device *netdev, unsigned int len)
{
	struct ice_repr *repr = ice_netdev_to_repr(netdev);
	struct ice_repr_pcpu_stats *stats;

	stats = this_cpu_ptr(repr->stats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += len;
	u64_stats_update_end(&stats->syncp);
}

/**
 * ice_repr_get_stats64 - get VF stats for VFPR use
 * @netdev: pointer to port representor netdev
 * @stats: pointer to struct where stats can be stored
 */
#ifdef HAVE_VOID_NDO_GET_STATS64
static void
#else
static struct rtnl_link_stats64 *
#endif
ice_repr_get_stats64(struct net_device *netdev, struct rtnl_link_stats64 *stats)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	const struct ice_eth_stats *eth_stats;
	struct ice_vsi *vsi;

	if (ice_is_vf_disabled(np->repr->vf))
#ifdef HAVE_VOID_NDO_GET_STATS64
		return;
#else
		return stats;
#endif
	vsi = np->repr->src_vsi;

	ice_update_vsi_stats(vsi);
	eth_stats = &vsi->eth_stats;

	stats->tx_packets = eth_stats->tx_unicast + eth_stats->tx_broadcast +
			    eth_stats->tx_multicast;
	stats->rx_packets = eth_stats->rx_unicast + eth_stats->rx_broadcast +
			    eth_stats->rx_multicast;
	stats->tx_bytes = eth_stats->tx_bytes;
	stats->rx_bytes = eth_stats->rx_bytes;
	stats->multicast = eth_stats->rx_multicast;
	stats->tx_errors = eth_stats->tx_errors;
	stats->tx_dropped = eth_stats->tx_discards;
	stats->rx_dropped = eth_stats->rx_discards;
#ifndef HAVE_VOID_NDO_GET_STATS64

	return stats;
#endif
}

/**
 * ice_netdev_to_repr - Get port representor for given netdevice
 * @netdev: pointer to port representor netdev
 */
struct ice_repr *ice_netdev_to_repr(const struct net_device *netdev)
{
	const struct ice_netdev_priv *np = netdev_priv(netdev);

	return np->repr;
}

/**
 * ice_repr_set_link - set PR link
 * @reprs: radix_tree of representors
 * @repr_id: id of the repr to set link on
 * @link: true - up, false - down
 *
 * Called when upper device link is changed.
 */
void ice_repr_set_link(struct radix_tree_root *reprs, u32 repr_id, bool link)
{
	struct ice_repr *repr =
		(struct ice_repr *)radix_tree_lookup(reprs, repr_id);
	unsigned int flags;

	if (!repr)
		return;

	flags = repr->netdev->flags;
	flags = link ? flags | IFF_UP : flags & ~IFF_UP;
	dev_change_flags(repr->netdev, flags, NULL);
}

/**
 * ice_repr_open - Enable port representor's network interface
 * @netdev: network interface device structure
 *
 * The open entry point is called when a port representor's network
 * interface is made active by the system (IFF_UP). Corresponding
 * VF is notified about link status change.
 *
 * Returns 0 on success
 */
static int ice_repr_open(struct net_device *netdev)
{
	struct ice_repr *repr = ice_netdev_to_repr(netdev);
	struct ice_vf *vf;

	vf = repr->vf;
	vf->link_forced = true;
	vf->link_up = true;
	ice_vc_notify_vf_link_state(vf);

	netif_carrier_on(netdev);
	netif_tx_start_all_queues(netdev);

	return 0;
}

/**
 * ice_repr_stop - Disable port representor's network interface
 * @netdev: network interface device structure
 *
 * The stop entry point is called when a port representor's network
 * interface is de-activated by the system. Corresponding
 * VF is notified about link status change.
 *
 * Returns 0 on success
 */
static int ice_repr_stop(struct net_device *netdev)
{
	struct ice_repr *repr = ice_netdev_to_repr(netdev);
	struct ice_vf *vf;

	vf = repr->vf;
	vf->link_forced = true;
	vf->link_up = false;
	ice_vc_notify_vf_link_state(vf);

	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	return 0;
}

#if IS_ENABLED(CONFIG_NET_DEVLINK) && defined(HAVE_DEVLINK_PORT_ATTR_PCI_VF)
#ifdef HAVE_NDO_GET_DEVLINK_PORT
#ifndef HAVE_SET_NETDEV_DEVLINK_PORT
static struct devlink_port *
ice_repr_get_devlink_port(struct net_device *netdev)
{
	struct ice_repr *repr = ice_netdev_to_repr(netdev);

	return &repr->vf->devlink_port;
}
#endif /* !HAVE_SET_NETDEV_DEVLINK_PORT */
#endif /* HAVE_NDO_GET_DEVLINK_PORT */
#endif /* CONFIG_NET_DEVLINK && HAVE_DEVLINK_PORT_ATTR_PCI_VF */
#if defined(HAVE_NDO_OFFLOAD_STATS) || defined(HAVE_RHEL7_EXTENDED_OFFLOAD_STATS)
/**
 * ice_repr_sp_stats64 - get slow path stats for port representor
 * @dev: network interface device structure
 * @stats: netlink stats structure
 */
static int
ice_repr_sp_stats64(const struct net_device *dev,
		    struct rtnl_link_stats64 *stats)
{
	struct ice_repr *repr = ice_netdev_to_repr(dev);
	int i;

	for_each_possible_cpu(i) {
		u64 tbytes, tpkts, tdrops, rbytes, rpkts;
		struct ice_repr_pcpu_stats *repr_stats;
		unsigned int start;

		repr_stats = per_cpu_ptr(repr->stats, i);
		do {
			start = u64_stats_fetch_begin(&repr_stats->syncp);
			tbytes = repr_stats->tx_bytes;
			tpkts = repr_stats->tx_packets;
			tdrops = repr_stats->tx_drops;
			rbytes = repr_stats->rx_bytes;
			rpkts = repr_stats->rx_packets;
		} while (u64_stats_fetch_retry(&repr_stats->syncp, start));

		stats->tx_bytes += tbytes;
		stats->tx_packets += tpkts;
		stats->tx_dropped += tdrops;
		stats->rx_bytes += rbytes;
		stats->rx_packets += rpkts;
	}

	return 0;
}

static bool
ice_repr_ndo_has_offload_stats(const struct net_device *dev, int attr_id)
{
	return attr_id == IFLA_OFFLOAD_XSTATS_CPU_HIT;
}

static int
ice_repr_ndo_get_offload_stats(int attr_id, const struct net_device *dev,
			       void *sp)
{
	if (attr_id == IFLA_OFFLOAD_XSTATS_CPU_HIT)
		return ice_repr_sp_stats64(dev, (struct rtnl_link_stats64 *)sp);

	return -EINVAL;
}
#endif /* HAVE_NDO_OFFLOAD_STATS || HAVE_RHEL7_EXTENDED_OFFLOAD_STATS */

#ifdef HAVE_TC_SETUP_CLSFLOWER
static int
ice_repr_setup_tc_cls_flower(struct ice_repr *repr,
			     struct flow_cls_offload *flower)
{
	switch (flower->command) {
	case FLOW_CLS_REPLACE:
		return ice_add_cls_flower(repr->netdev, repr->src_vsi, flower);
	case FLOW_CLS_DESTROY:
		return ice_del_cls_flower(repr->src_vsi, flower);
	default:
		return -EINVAL;
	}
}
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
static int
ice_repr_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
			   void *cb_priv)
{
	struct flow_cls_offload *flower = type_data;
	struct ice_netdev_priv *np = cb_priv;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		return ice_repr_setup_tc_cls_flower(np->repr, flower);
	default:
		return -EOPNOTSUPP;
	}
}

static LIST_HEAD(ice_repr_block_cb_list);
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

static int
#ifdef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
ice_repr_setup_tc(struct net_device *netdev, enum tc_setup_type type,
		  void *type_data)
#elif defined(HAVE_NDO_SETUP_TC_CHAIN_INDEX)
ice_repr_setup_tc(struct net_device *netdev, u32 __always_unused handle,
		  __always_unused chain_index, __be16 proto,
		  struct tc_to_netdev *tc)
#else
ice_repr_setup_tc(struct net_device *netdev, u32 __always_unused handle,
		  __be16 __always_unused proto, struct tc_to_netdev *tc)
#endif
{
#ifndef HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
	struct tc_cls_flower_offload *cls_flower = tc->cls_flower;
	unsigned int type = tc->type;
#elif !defined(HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO)
	struct tc_cls_flower_offload *cls_flower = type_data;
#endif /* HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV */
	struct ice_netdev_priv *np = netdev_priv(netdev);

	switch (type) {
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
	case TC_SETUP_BLOCK:
		return flow_block_cb_setup_simple((struct flow_block_offload *)
						  type_data,
						  &ice_repr_block_cb_list,
						  ice_repr_setup_tc_block_cb,
						  np, np, true);
#elif !defined(HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV) || !defined(HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO)
	case TC_SETUP_CLSFLOWER:
		return ice_repr_setup_tc_cls_flower(np->repr, cls_flower);
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
	default:
		return -EOPNOTSUPP;
	}
}
#endif /* HAVE_TC_SETUP_CLSFLOWER */

#ifndef HAVE_NETDEV_MIN_MAX_MTU
/**
 * ice_repr_change_mtu - NDO callback to change the MTU on port representor
 * @netdev: network interface device structure
 * @new_mtu: new value for MTU
 *
 * Returns 0 on success, negative on failure
 */
static int ice_repr_change_mtu(struct net_device *netdev, int new_mtu)
{
	int err;

	err = ice_check_mtu_valid(netdev, new_mtu);
	if (err)
		return err;

	netdev->mtu = (unsigned int)new_mtu;

	return 0;
}
#endif /* !HAVE_NETDEV_MIN_MAX_MTU */

static const struct net_device_ops ice_repr_netdev_ops = {
#ifdef HAVE_NDO_GET_PHYS_PORT_NAME
	.ndo_get_phys_port_name = ice_repr_get_phys_port_name,
#endif /* HAVE_NDO_GET_PHYS_PORT_NAME */
	.ndo_get_stats64 = ice_repr_get_stats64,
	.ndo_open = ice_repr_open,
	.ndo_stop = ice_repr_stop,
#if IS_ENABLED(CONFIG_NET_DEVLINK)
	.ndo_start_xmit = ice_eswitch_port_start_xmit,
#ifndef HAVE_NETDEV_MIN_MAX_MTU
#ifdef HAVE_NETDEV_EXTENDED_MIN_MAX_MTU
	.extended.ndo_change_mtu = ice_repr_change_mtu,
#else
	.ndo_change_mtu = ice_repr_change_mtu,
#endif /* HAVE_NETDEV_EXTENDED_MIN_MAX_MTU */
#endif /* HAVE_NETDEV_MIN_MAX_MTU */
#ifdef HAVE_DEVLINK_PORT_ATTR_PCI_VF
#ifdef HAVE_NDO_GET_DEVLINK_PORT
#ifndef HAVE_SET_NETDEV_DEVLINK_PORT
	.ndo_get_devlink_port = ice_repr_get_devlink_port,
#endif /* !HAVE_SET_NETDEV_DEVLINK_PORT */
#endif /* HAVE_NDO_GET_DEVLINK_PORT */
#endif /* HAVE_DEVLINK_PORT_ATTR_PCI_VF */
#ifdef HAVE_TC_SETUP_CLSFLOWER
#ifdef HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC
	.extended.ndo_setup_tc_rh = ice_repr_setup_tc,
#else
	.ndo_setup_tc = ice_repr_setup_tc,
#endif /* HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC */
#endif /* HAVE_TC_SETUP_CLSFLOWER */
#endif /* CONFIG_NET_DEVLINK */
#ifdef HAVE_NDO_OFFLOAD_STATS
	.ndo_has_offload_stats = ice_repr_ndo_has_offload_stats,
	.ndo_get_offload_stats = ice_repr_ndo_get_offload_stats,
#elif defined(HAVE_RHEL7_EXTENDED_OFFLOAD_STATS)
	.extended.ndo_has_offload_stats = ice_repr_ndo_has_offload_stats,
	.extended.ndo_get_offload_stats = ice_repr_ndo_get_offload_stats,
#endif
};

/**
 * ice_is_port_repr_netdev - Check if a given netdevice is a port representor
 * netdev
 * @netdev: pointer to netdev
 */
bool ice_is_port_repr_netdev(const struct net_device *netdev)
{
	return netdev && (netdev->netdev_ops == &ice_repr_netdev_ops);
}

/**
 * ice_repr_reg_netdev - register port representor netdev
 * @netdev: pointer to port representor netdev
 */
static int
ice_repr_reg_netdev(struct net_device *netdev)
{
	eth_hw_addr_random(netdev);
	netdev->netdev_ops = &ice_repr_netdev_ops;
	ice_set_ethtool_repr_ops(netdev);

#ifdef NETIF_F_HW_TC
	netdev->hw_features |= NETIF_F_HW_TC;
#endif /* NETIF_F_HW_TC */

	netif_carrier_off(netdev);
	netif_tx_stop_all_queues(netdev);

	return register_netdev(netdev);
}

#if IS_ENABLED(CONFIG_NET_DEVLINK)
#ifdef HAVE_DEVLINK_RATE_NODE_CREATE
static void ice_repr_remove_node(struct devlink_port *devlink_port)
{
	devl_lock(devlink_port->devlink);
	devl_rate_leaf_destroy(devlink_port);
	devl_unlock(devlink_port->devlink);
}
#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */
#endif /* CONFIG_NET_DEVLINK */

static void ice_repr_rem(struct ice_repr *repr)
{
	free_percpu(repr->stats);
	free_netdev(repr->netdev);
	kfree(repr);
}

/**
 * ice_repr_rem_vf - remove representor from VF
 * @repr: pointer to representor structure
 */
void ice_repr_rem_vf(struct ice_repr *repr)
{
	unregister_netdev(repr->netdev);
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#ifdef HAVE_DEVLINK_RATE_NODE_CREATE
	ice_repr_remove_node(&repr->vf->devlink_port);
#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */
#ifdef HAVE_DEVLINK_PORT_ATTR_PCI_VF
	ice_devlink_destroy_vf_port(repr->vf);
#endif /* HAVE_DEVLINK_PORT_ATTR_PCI_VF */
#endif /* CONFIG_NET_DEVLINK */
	ice_virtchnl_set_dflt_ops(repr->vf);
	ice_repr_rem(repr);
}

static void ice_repr_set_tx_topology(struct ice_pf *pf)
{
#ifdef HAVE_DEVLINK_RATE_NODE_CREATE
	struct devlink *devlink = priv_to_devlink(pf);

#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */
	if (!ice_is_switchdev_running(pf))
		return;

#if IS_ENABLED(CONFIG_NET_DEVLINK)
#ifdef HAVE_DEVLINK_RATE_NODE_CREATE
	/* only export if RDMA and DCB disabled */
	if (ice_is_aux_ena(pf) &&
	    ice_is_rdma_ena(pf) &&
	    ice_is_rdma_aux_loaded(pf))
		return;
	if (ice_is_dcb_active(pf))
		return;
	devlink = priv_to_devlink(pf);
	ice_devlink_rate_init_tx_topology(devlink, ice_get_main_vsi(pf));
#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */
#endif /* CONFIG_NET_DEVLINK */
}

/**
 * ice_repr_add - add representor for generic VSI
 * @pf: pointer to PF structure
 * @src_vsi: pointer to VSI structure of device to represent
 * @parent_mac: device MAC address
 */
static struct ice_repr *
ice_repr_add(struct ice_pf *pf, struct ice_vsi *src_vsi, const u8 *parent_mac)
{
	struct ice_netdev_priv *np;
	struct ice_repr *repr;
	int err;

	repr = kzalloc(sizeof(*repr), GFP_KERNEL);
	if (!repr)
		return (struct ice_repr *)ERR_PTR(-ENOMEM);

	repr->netdev = alloc_etherdev(sizeof(struct ice_netdev_priv));
	if (!repr->netdev) {
		err =  -ENOMEM;
		goto err_alloc;
	}

	repr->stats = netdev_alloc_pcpu_stats(struct ice_repr_pcpu_stats);
	if (!repr->stats) {
		err = -ENOMEM;
		goto err_stats;
	}

	repr->src_vsi = src_vsi;
	repr->id = src_vsi->vsi_num;
	np = netdev_priv(repr->netdev);
	np->repr = repr;

	ether_addr_copy(repr->parent_mac, parent_mac);

	return repr;
err_stats:
	free_netdev(repr->netdev);
err_alloc:
	kfree(repr);
	return (struct ice_repr *)ERR_PTR(err);
}

/**
 * ice_repr_add_vf - add representor for VF
 * @vf: pointer to VF structure
 */
struct ice_repr *ice_repr_add_vf(struct ice_vf *vf)
{
	struct ice_repr *repr;
	struct ice_vsi *vsi;
	int err;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return (struct ice_repr *)ERR_PTR(-ENOENT);
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#ifdef HAVE_DEVLINK_PORT_ATTR_PCI_VF

	err = ice_devlink_create_vf_port(vf);
	if (err)
		return (struct ice_repr *)ERR_PTR(err);
#endif /* HAVE_DEVLINK_PORT_ATTR_PCI_VF */
#endif /* CONFIG_NET_DEVLINK */

	repr = ice_repr_add(vf->pf, vsi, vf->hw_lan_addr.addr);
	if (IS_ERR(repr)) {
		err = PTR_ERR(repr);
		goto err_repr_add;
	}

	repr->vf = vf;

#ifdef HAVE_NETDEV_EXTENDED_MIN_MAX_MTU
	repr->netdev->extended->min_mtu = ETH_MIN_MTU;
	repr->netdev->extended->max_mtu = ICE_MAX_MTU;
#endif /* HAVE_NETDEV_EXTENDED_MIN_MAX_MTU */
#ifdef HAVE_NETDEV_MIN_MAX_MTU
	repr->netdev->min_mtu = ETH_MIN_MTU;
	repr->netdev->max_mtu = ICE_MAX_MTU;
#endif /* HAVE_NETDEV_MIN_MAX_MTU */

	SET_NETDEV_DEV(repr->netdev, ice_pf_to_dev(vf->pf));
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#ifdef HAVE_DEVLINK_PORT_ATTR_PCI_VF
#ifdef HAVE_SET_NETDEV_DEVLINK_PORT
	SET_NETDEV_DEVLINK_PORT(repr->netdev, &vf->devlink_port);
#endif /* HAVE_SET_NETDEV_DEVLINK_PORT */
#endif /* HAVE_DEVLINK_PORT_ATTR_PCI_VF */
#endif /* CONFIG_NET_DEVLINK */
	err = ice_repr_reg_netdev(repr->netdev);
	if (err)
		goto err_netdev;

#if IS_ENABLED(CONFIG_NET_DEVLINK)
#ifdef HAVE_DEVLINK_PORT_ATTR_PCI_VF
#ifndef HAVE_SET_NETDEV_DEVLINK_PORT
	devlink_port_type_eth_set(&vf->devlink_port, repr->netdev);
#endif /* !HAVE_SET_NETDEV_DEVLINK_PORT */
#endif /* HAVE_DEVLINK_PORT_ATTR_PCI_VF */
#endif /* CONFIG_NET_DEVLINK */

	ice_virtchnl_set_repr_ops(vf);
	ice_repr_set_tx_topology(vf->pf);

	return repr;

err_netdev:
	ice_repr_rem(repr);
err_repr_add:
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#ifdef HAVE_DEVLINK_PORT_ATTR_PCI_VF
	ice_devlink_destroy_vf_port(vf);
#endif /* HAVE_DEVLINK_PORT_ATTR_PCI_VF */
#endif /* CONFIG_NET_DEVLINK */
	return (struct ice_repr *)ERR_PTR(err);
}

/**
 * ice_repr_start_tx_queues - start Tx queues of port representor
 * @repr: pointer to repr structure
 */
void ice_repr_start_tx_queues(struct ice_repr *repr)
{
	netif_carrier_on(repr->netdev);
	netif_tx_start_all_queues(repr->netdev);
}

/**
 * ice_repr_stop_tx_queues - stop Tx queues of port representor
 * @repr: pointer to repr structure
 */
void ice_repr_stop_tx_queues(struct ice_repr *repr)
{
	netif_carrier_off(repr->netdev);
	netif_tx_stop_all_queues(repr->netdev);
}
