/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_REPR_H_
#define _ICE_REPR_H_

struct ice_repr_pcpu_stats {
	struct u64_stats_sync syncp;
	u64 rx_packets;
	u64 rx_bytes;
	u64 tx_packets;
	u64 tx_bytes;
	u64 tx_drops;
};

struct ice_repr {
	struct ice_vsi *src_vsi;
	struct ice_vf *vf;
	struct net_device *netdev;
	struct metadata_dst *dst;
	struct ice_repr_pcpu_stats __percpu *stats;
	u32 id;
	u8 parent_mac[ETH_ALEN];
};

struct ice_repr *ice_repr_add_vf(struct ice_vf *vf);
void ice_repr_rem_vf(struct ice_repr *repr);
void ice_repr_start_tx_queues(struct ice_repr *repr);
void ice_repr_stop_tx_queues(struct ice_repr *repr);
void ice_repr_inc_tx_stats(struct ice_repr *repr, unsigned int len, int ret);
void ice_repr_inc_rx_stats(const struct net_device *netdev, unsigned int len);
#if IS_ENABLED(CONFIG_NET_DEVLINK)
void ice_repr_set_link(struct radix_tree_root *reprs, u32 repr_id, bool link);
struct ice_repr *ice_netdev_to_repr(const struct net_device *netdev);
bool ice_is_port_repr_netdev(const struct net_device *netdev);
#else
static inline struct ice_repr *
ice_netdev_to_repr(const struct net_device *netdev) { return NULL; }
static inline
bool ice_is_port_repr_netdev(const struct net_device *netdev) { return false; }
static inline void
ice_repr_set_link(struct radix_tree_root *reprs, u32 repr_id, bool link) { }
#endif /* CONFIG_NET_DEVLINK */
#endif
