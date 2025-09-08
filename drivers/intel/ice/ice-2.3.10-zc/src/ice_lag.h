/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_LAG_H_
#define _ICE_LAG_H_
#ifdef HAVE_NETDEV_UPPER_INFO

#include <linux/netdevice.h>
#include "ice.h"

#define ICE_LAG_INVALID_PORT		0xFF
#define ICE_LAG_RESET_RETRIES		5
#define ICE_LAG_SINGLE_FILTER_SIZE	0xC

#define ICE_PRI_IDX 0x0
#define ICE_SEC_IDX 0x1

struct ice_pf;

struct ice_lag_netdev_list {
	struct list_head node;
	struct net_device *netdev;
};

/* LAG info struct */
struct ice_lag {
	struct ice_pf *pf; /* backlink to PF struct */
	struct iidc_rdma_qset_params rdma_qset[IEEE_8021QAZ_MAX_TCS];
	struct iidc_rdma_multi_qset_params rdma_qsets[IEEE_8021QAZ_MAX_TCS];
	struct ice_vsi *rdma_vsi;
	struct net_device *netdev; /* this PF's netdev */
	struct net_device *upper_netdev; /* upper bonding netdev */
	struct list_head *netdev_head;
	struct notifier_block notif_block;
	s32 bond_mode;
	int bond_id; /* identify which bond we are in */
	u16 bond_swid; /* swid for primary interface */
	u8 active_port; /* lport value for the current active port */
	bool sriov_enabled; /* whether bond is in SR-IOV mode */
	u8 bonded:1; /* currently bonded */
	u8 primary:1; /* this is primary */
	u16 pf_recipe;
	u16 lport_recipe;
	u16 pf_rx_rule_id;
	u16 pf_tx_rule_id;
	u16 cp_rule_idx;
	u16 lport_rule_idx;
	/* each thing blocking bonding will increment this value by one.
	 * If this value is zero, then bonding is allowed.
	 */
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
		struct netdev_notifier_info notifier_info;
	} info;
};

void ice_lag_move_new_vf_nodes(struct ice_vf *vf);
int ice_init_lag(struct ice_pf *pf);
int
ice_lag_move_node(struct ice_lag *lag, u8 oldport, u8 newport, u8 tc, u32 teid,
		  u16 qs_handle);
int ice_lag_move_node_sync(struct ice_hw *old_hw, struct ice_hw *new_hw,
			   struct ice_vsi *new_vsi,
			   struct iidc_rdma_qset_params *qset);
void ice_lag_aa_failover(struct ice_lag *lag, struct iidc_core_dev_info *cdev,
			 u8 dest, bool locked);
void ice_deinit_lag(struct ice_pf *pf);
void
ice_lag_aa_reclaim_nodes(struct iidc_core_dev_info *cdev,
			 struct iidc_rdma_multi_qset_params *qset);
void ice_lag_rebuild(struct ice_pf *pf);
bool ice_lag_is_switchdev_running(struct ice_pf *pf);
void ice_lag_move_vf_nodes_cfg(struct ice_lag *lag, u8 src_prt, u8 dst_prt);
#endif /* HAVE_NETDEV_UPPER_INFO */
#endif /* _ICE_LAG_H_ */
