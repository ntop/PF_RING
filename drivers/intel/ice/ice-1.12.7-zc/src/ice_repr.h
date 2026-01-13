/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _ICE_REPR_H_
#define _ICE_REPR_H_

struct ice_repr {
	struct ice_vsi *src_vsi;
	struct ice_vf *vf;
	struct ice_q_vector *q_vector;
	struct net_device *netdev;
	struct metadata_dst *dst;
	/* info about slow path MAC rule  */
	struct ice_rule_query_data *mac_rule;
	u8 rule_added;
};

int ice_repr_add_for_all_vfs(struct ice_pf *pf);
void ice_repr_rem_from_all_vfs(struct ice_pf *pf);
void ice_repr_start_tx_queues(struct ice_repr *repr);
void ice_repr_stop_tx_queues(struct ice_repr *repr);
#ifdef HAVE_METADATA_PORT_INFO
void ice_repr_set_traffic_vsi(struct ice_repr *repr, struct ice_vsi *vsi);
#endif /* HAVE_METADATA_PORT_INFO */
#if IS_ENABLED(CONFIG_NET_DEVLINK)
bool ice_is_port_repr_netdev(struct net_device *netdev);
struct ice_repr *ice_netdev_to_repr(struct net_device *netdev);
#else
static inline
bool ice_is_port_repr_netdev(struct net_device *netdev) { return false; }
static inline
struct ice_repr *ice_netdev_to_repr(struct net_device *netdev) { return NULL; }
#endif /* CONFIG_NET_DEVLINK */
#endif
