/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _ICE_LAG_H_
#define _ICE_LAG_H_
#ifdef HAVE_NETDEV_UPPER_INFO

#include <linux/netdevice.h>
#include "ice.h"

#define ICE_LAG_INVALID_PORT 0xFF
#define ICE_LAG_SINGLE_FILTER_SIZE 0xC

/* LAG roles for netdev */
enum ice_lag_role {
	ICE_LAG_NONE,
	ICE_LAG_PRIMARY,
	ICE_LAG_BACKUP,
	ICE_LAG_UNSET
};

struct ice_pf;

struct ice_lag_netdev_list {
	struct list_head node;
	struct net_device *netdev;
};

/* LAG info struct */
struct ice_lag {
	struct ice_pf *pf; /* backlink to PF struct */
	struct iidc_rdma_qset_params rdma_qset[IEEE_8021QAZ_MAX_TCS];
	struct ice_vsi *rdma_vsi;
	struct net_device *netdev; /* this PF's netdev */
	struct net_device *upper_netdev; /* upper bonding netdev */
	struct list_head *netdev_head;
	struct notifier_block notif_block;
	int bond_id; /* identify which bond we are in */
	s32 bond_mode;
	u8 bonded:1; /* currently bonded */
	u8 primary:1; /* this is primary */
	u8 handler:1; /* did we register a rx_netdev_handler */
	/* each thing blocking bonding will increment this value by one.
	 * If this value is zero, then bonding is allowed.
	 */
	u8 role;
	struct ice_rule_query_data fltr;
	u16 action_idx;
};

/* LAG workqueue struct */
struct ice_lag_work {
	struct work_struct lag_task;
	struct ice_lag_netdev_list netdev_list;
	struct ice_lag *lag;
	unsigned long event;
	struct net_device *event_netdev;
	union {
		struct netdev_notifier_changeupper_info changeupper_info;
		struct netdev_notifier_bonding_info bonding_info;
	} info;
};

int ice_init_lag(struct ice_pf *pf);
int ice_lag_move_node_sync(struct ice_hw *old_hw, struct ice_hw *new_hw,
			   struct ice_vsi *new_vsi,
			   struct iidc_rdma_qset_params *qset);
void ice_deinit_lag(struct ice_pf *pf);
struct ice_lag *ice_lag_find_primary(struct ice_lag *lag);
#endif /* HAVE_NETDEV_UPPER_INFO */
#endif /* _ICE_LAG_H_ */
