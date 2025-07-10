/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

/* Link Aggregation code */

#include "ice.h"
#include "ice_lib.h"
#ifdef HAVE_NETDEV_UPPER_INFO
#include "ice_lag.h"

static DEFINE_IDA(ice_lag_ida);

/**
 * netif_is_same_ice - determine if netdev is on the same ice NIC as local PF
 * @pf: local PF struct
 * @netdev: netdev we are evaluating
 */
static bool netif_is_same_ice(struct ice_pf *pf, struct net_device *netdev)
{
	struct ice_netdev_priv *np;
	struct ice_pf *test_pf;
	struct ice_vsi *vsi;

	if (!netif_is_ice(netdev))
		return false;

	np = netdev_priv(netdev);
	if (!np)
		return false;

	vsi = np->vsi;
	if (!vsi)
		return false;

	test_pf = vsi->back;
	if (!test_pf)
		return false;

	if (pf->pdev->bus != test_pf->pdev->bus ||
	    pf->pdev->slot != test_pf->pdev->slot)
		return false;

	return true;
}

/**
 * ice_netdev_to_lag - return pointer to associated lag struct from netdev
 * @netdev: pointer to net_device struct
 */
static struct ice_lag *ice_netdev_to_lag(struct net_device *netdev)
{
	struct ice_netdev_priv *np;
	struct ice_vsi *vsi;

	if (!netif_is_ice(netdev))
		return NULL;

	np = netdev_priv(netdev);
	if (!np)
		return NULL;

	vsi = np->vsi;
	if (!vsi)
		return NULL;

	return vsi->back->lag;
}

/**
 * ice_lag_find_primary - return the lag struct for primary interface in a bond
 * @lag: lag info struct
 */
struct ice_lag *ice_lag_find_primary(struct ice_lag *lag)
{
	struct ice_lag *primary_lag = NULL;
	struct list_head *tmp;

	list_for_each(tmp, lag->netdev_head) {
		struct ice_lag_netdev_list *entry;
		struct ice_lag *tmp_lag;

		entry = list_entry(tmp, struct ice_lag_netdev_list, node);
		tmp_lag = ice_netdev_to_lag(entry->netdev);
		if (tmp_lag && tmp_lag->primary) {
			primary_lag = tmp_lag;
			break;
		}
	}

	return primary_lag;
}

/**
 * ice_plug_aux_dev_lock - plug aux dev while handling lag mutex lock
 * @cdev: pointer to struct for aux device
 * @name: name of aux dev to use in plug call
 * @lag: pointer to lag struct containing the mutex to unlock/lock
 */
static void ice_plug_aux_dev_lock(struct iidc_core_dev_info *cdev,
				  const char *name, struct ice_lag *lag)
{
	mutex_unlock(&lag->pf->lag_mutex);
	ice_plug_aux_dev(cdev, name);
	mutex_lock(&lag->pf->lag_mutex);
}

/**
 * ice_unplug_aux_dev_lock - unplug aux dev while handling lag mutex lock
 * @cdev: pointer to struct for aux device
 * @lag: pointer to lag struct containing the mutex to unlock/lock
 */
static void ice_unplug_aux_dev_lock(struct iidc_core_dev_info *cdev,
				    struct ice_lag *lag)
{
	mutex_unlock(&lag->pf->lag_mutex);
	ice_unplug_aux_dev(cdev);
	mutex_lock(&lag->pf->lag_mutex);
}

#define ICE_LAG_NUM_RULES		0x1
#define ICE_LAG_LA_VSI_S		3
#define ICE_LAG_LA_VALID		BIT(16)
#define ICE_LAG_RES_SUBSCRIBE		BIT(15)
#define ICE_LAG_RES_SHARED		BIT(14)

/**
 * ice_lag_add_lg_action - add a large action to redirect RDMA traffic
 * @hw: pointer to the HW struct
 * @lkup: recipe for lookup
 * @rinfo: information related to rule that needs to be programmed
 * @entry: return struct for recipe_id, rule_id and vsi_handle.
 */
static int
ice_lag_add_lg_action(struct ice_hw *hw, struct ice_adv_lkup_elem *lkup,
		      struct ice_adv_rule_info *rinfo,
		      struct ice_rule_query_data *entry)
{
	struct ice_sw_rule_lkup_rx_tx *s_rule = NULL;
	struct ice_pf *pf = hw->back;
	const struct ice_dummy_pkt_profile *profile;
	u16 rule_buf_sz, vsi_handle, rid = 0;
	int ret = 0;
	u32 act = 0;

	if (!entry)
		return -EINVAL;

	if (entry->rid || entry->rule_id) {
		dev_warn(ice_pf_to_dev(pf), "Error: Secondary interface already has filter defined\n");
		return -EINVAL;
	}
	if (!hw->switch_info->prof_res_bm_init) {
		hw->switch_info->prof_res_bm_init = 1;
		ice_init_prof_result_bm(hw);
	}

	profile = ice_find_dummy_packet(lkup, 1, rinfo->tun_type);

	vsi_handle = rinfo->sw_act.vsi_handle;
	if (!ice_is_vsi_valid(hw, vsi_handle)) {
		dev_warn(ice_pf_to_dev(pf), "VSI not valid for adding Lg Action\n");
		return -EINVAL;
	}

	ret = ice_add_adv_recipe(hw, lkup, 1, rinfo, &rid);
	if (ret) {
		dev_warn(ice_pf_to_dev(pf), "Failed adding advance recipe\n");
		return ret;
	}

	rule_buf_sz = struct_size(s_rule, hdr_data, 0) + profile->pkt_len;
	s_rule = kzalloc(rule_buf_sz, GFP_KERNEL);
	if (!s_rule)
		return -ENOMEM;

	act = (rinfo->lg_id << ICE_SINGLE_ACT_PTR_VAL_S) | ICE_SINGLE_ACT_PTR |
	      ICE_SINGLE_ACT_PTR_HAS_FWD | ICE_SINGLE_ACT_PTR_BIT |
	      ICE_SINGLE_ACT_LAN_ENABLE | ICE_SINGLE_ACT_LB_ENABLE;

	s_rule->hdr.type = cpu_to_le16(ICE_AQC_SW_RULES_T_LKUP_RX);
	s_rule->src = cpu_to_le16(hw->port_info->lport);
	s_rule->recipe_id = cpu_to_le16(rid);
	s_rule->act = cpu_to_le32(act);

	ret = ice_fill_adv_dummy_packet(lkup, 1, s_rule, profile);
	if (ret) {
		dev_warn(ice_pf_to_dev(pf), "Could not file dummy packet for Lg Action\n");
		goto ice_lag_lg_act_err;
	}

	ret = ice_aq_sw_rules(hw, s_rule, rule_buf_sz, 1,
			      ice_aqc_opc_add_sw_rules, NULL);
	if (ret) {
		dev_warn(ice_pf_to_dev(pf), "Fail adding switch rule for Lg Action\n");
		goto ice_lag_lg_act_err;
	}

	entry->rid = rid;
	entry->rule_id = le16_to_cpu(s_rule->index);
	entry->vsi_handle = rinfo->sw_act.vsi_handle;

ice_lag_lg_act_err:
	kfree(s_rule);
	return ret;
}

/**
 * ice_lag_add_prune_list - Add primary's VSI to secondary's prune list
 * @lag: lag info struct
 * @event_pf: PF struct for interface we are modifying prune list on
 */
static void ice_lag_add_prune_list(struct ice_lag *lag, struct ice_pf *event_pf)
{
	u16 rule_buf_sz, vsi_list_id, prim_vsi_num, event_vsi_idx;
	struct ice_sw_rule_vsi_list *s_rule = NULL;
	struct ice_sw_recipe *recp_list;
	const u16 num_vsi = 1;
	struct device *dev;

	recp_list = &event_pf->hw.switch_info->recp_list[ICE_SW_LKUP_VLAN];
	dev = ice_pf_to_dev(lag->pf);
	prim_vsi_num = lag->pf->vsi[0]->vsi_num;
	event_vsi_idx = event_pf->vsi[0]->idx;

	if (!ice_find_vsi_list_entry(recp_list, event_vsi_idx, &vsi_list_id)) {
		dev_dbg(dev, "Could not locate prune list when setting up RDMA on LAG\n");
		return;
	}

	rule_buf_sz = struct_size(s_rule, vsi, num_vsi);
	s_rule = kzalloc(rule_buf_sz, GFP_KERNEL);
	if (!s_rule)
		return;

	s_rule->hdr.type = cpu_to_le16(ICE_AQC_SW_RULES_T_PRUNE_LIST_SET);
	s_rule->index = cpu_to_le16(vsi_list_id);
	s_rule->number_vsi = cpu_to_le16(num_vsi);
	s_rule->vsi[0] = cpu_to_le16(prim_vsi_num);

	if (ice_aq_sw_rules(&lag->pf->hw, (struct ice_aqc_sw_rules *)s_rule,
			    rule_buf_sz, 1, ice_aqc_opc_update_sw_rules, NULL))
		dev_warn(dev, "Error adding VSI prune list\n");
	kfree(s_rule);
}

/**
 * ice_lag_del_prune_list - Reset Secondary's prune list to just its own VSI
 * @lag: local Secondary interface's ice_lag struct
 * @event_pf: PF struct for unlinking interface
 */
static void ice_lag_del_prune_list(struct ice_lag *lag, struct ice_pf *event_pf)
{
	u16 vsi_num, vsi_idx, rule_buf_sz, vsi_list_id;
	struct ice_sw_rule_vsi_list *s_rule = NULL;
	struct ice_sw_recipe *recp_list;
	const u16 num_vsi = 1;
	struct device *dev;

	recp_list = &event_pf->hw.switch_info->recp_list[ICE_SW_LKUP_VLAN];
	dev = ice_pf_to_dev(lag->pf);
	vsi_num = lag->pf->vsi[0]->vsi_num;
	vsi_idx = event_pf->vsi[0]->idx;

	if (!ice_find_vsi_list_entry(recp_list, vsi_idx, &vsi_list_id)) {
		dev_dbg(dev, "Could not locate prune list when unwinding RDMA on LAG\n");
		return;
	}

	rule_buf_sz = struct_size(s_rule, vsi, num_vsi);
	s_rule = kzalloc(rule_buf_sz, GFP_KERNEL);
	if (!s_rule)
		return;

	s_rule->hdr.type = cpu_to_le16(ICE_AQC_SW_RULES_T_PRUNE_LIST_CLEAR);
	s_rule->index = cpu_to_le16(vsi_list_id);
	s_rule->number_vsi = cpu_to_le16(num_vsi);
	s_rule->vsi[0] = cpu_to_le16(vsi_num);

	if (ice_aq_sw_rules(&lag->pf->hw, s_rule, rule_buf_sz, 1,
			    ice_aqc_opc_update_sw_rules, NULL))
		dev_warn(dev, "Error clearing VSI prune list\n");

	kfree(s_rule);
}

/**
 * ice_lag_rdma_create_fltr - Create switch rule to redirect RoCEv2 traffic
 * @lag: lag info struct
 */
static int ice_lag_rdma_create_fltr(struct ice_lag *lag)
{
	struct ice_aqc_alloc_free_res_elem *sw_buf;
	struct ice_aqc_res_elem *sw_ele;
	struct ice_lag *primary_lag;
	struct ice_vsi *primary_vsi;
	struct ice_netdev_priv *np;
	u16 buf_len;
	int ret = 0;

	if (!lag->primary)
		primary_lag = ice_lag_find_primary(lag);
	else
		primary_lag = lag;

	if (!primary_lag)
		return -EINVAL;

	np = netdev_priv(primary_lag->netdev);
	primary_vsi = np->vsi;

	buf_len = struct_size(sw_buf, elem, ICE_LAG_NUM_RULES);
	sw_buf = kzalloc(buf_len, GFP_KERNEL);
	if (!sw_buf)
		return -ENOMEM;

	sw_buf->num_elems = cpu_to_le16(ICE_LAG_NUM_RULES);
	sw_buf->res_type = cpu_to_le16(ICE_AQC_RES_TYPE_WIDE_TABLE_1 |
				       ICE_LAG_RES_SHARED);
	if (lag->primary) {
		struct ice_sw_rule_lg_act *s_rule;
		u32 large_action = 0x0;
		u16 rule_sz;

		dev_dbg(ice_pf_to_dev(lag->pf), "Configuring filter on Primary\n");
		/* Allocate a shared Large Action on primary interface
		 * This allows for the creation of a filter
		 * to direct traffic from one interface to another.
		 */
		ret = ice_aq_alloc_free_res(&lag->pf->hw, ICE_LAG_NUM_RULES,
					    sw_buf, buf_len,
					    ice_aqc_opc_alloc_res, NULL);
		if (ret) {
			dev_dbg(ice_pf_to_dev(lag->pf),
				"Failed Allocating Lg Action item %d\n", ret);
			goto create_fltr_out;
		}

		sw_ele = &sw_buf->elem[0];
		lag->action_idx = le16_to_cpu(sw_ele->e.flu_resp);

		large_action |= (primary_vsi->vsi_num << ICE_LAG_LA_VSI_S) |
				ICE_LAG_LA_VALID;

		rule_sz = struct_size(s_rule, act, ICE_LAG_NUM_RULES);
		s_rule = kzalloc(rule_sz, GFP_KERNEL);
		if (!s_rule) {
			ret = -ENOMEM;
			goto create_fltr_out;
		}
		/* Fill out add switch rule structure */
		s_rule->hdr.type = cpu_to_le16(ICE_AQC_SW_RULES_T_LG_ACT);
		s_rule->index = cpu_to_le16(lag->action_idx);
		s_rule->size = cpu_to_le16(ICE_LAG_NUM_RULES);
		s_rule->act[0] = cpu_to_le32(large_action);

		/* call add switch rule */
		ret = ice_aq_sw_rules(&lag->pf->hw, s_rule, rule_sz,
				      ICE_LAG_NUM_RULES,
				      ice_aqc_opc_add_sw_rules, NULL);
		kfree(s_rule);
		if (ret)
			dev_dbg(ice_pf_to_dev(lag->pf),
				"Failed configuring shared Lg Action item %d\n",
				ret);
	} else {
		struct ice_adv_rule_info rule_info = { 0 };
		struct ice_adv_lkup_elem *item;

		dev_dbg(ice_pf_to_dev(lag->pf), "Configuring filter on Secondary\n");
		sw_buf->res_type |= cpu_to_le16(ICE_LAG_RES_SUBSCRIBE);
		sw_buf->elem[0].e.flu_resp =
			cpu_to_le16(primary_lag->action_idx);

		/* Subscribe to shared large action on non-primary interface.
		 * This allows this PF to use shared item to direct RDMA
		 * traffic to another interface's resource.
		 */
		ret = ice_aq_alloc_free_res(&lag->pf->hw, ICE_LAG_NUM_RULES,
					    sw_buf, buf_len,
					    ice_aqc_opc_alloc_res, NULL);
		if (ret) {
			dev_dbg(ice_pf_to_dev(lag->pf),
				"Failed subscribing to Lg Action item %d\n",
				ret);
			goto create_fltr_out;
		}

		/* Add switch rule */
		item = kzalloc(sizeof(*item), GFP_KERNEL);
		if (!item) {
			ret = -ENOMEM;
			goto create_fltr_out;
		}

		item->type = ICE_UDP_ILOS;
		memcpy(&item->h_u.l4_hdr.dst_port, "\x12\xB7", 2);
		memset(&item->m_u.l4_hdr.dst_port, 0xFF, 2);

		rule_info.sw_act.src = lag->pf->hw.port_info->lport;
		rule_info.sw_act.fltr_act = ICE_LG_ACTION;
		rule_info.sw_act.vsi_handle = primary_vsi->idx;
		rule_info.sw_act.flag |= ICE_FLTR_RX;
		rule_info.priority = 7;
		rule_info.lg_id = primary_lag->action_idx;
		rule_info.tun_type = ICE_SW_TUN_AND_NON_TUN;

		ret = ice_lag_add_lg_action(&lag->pf->hw, item, &rule_info,
					    &lag->fltr);
		kfree(item);
	}

create_fltr_out:
	kfree(sw_buf);
	return ret;
}

/**
 * ice_lag_rdma_del_fltr - Delete switch rule filter for RoCEv2 traffic
 * @lag: lag info struct
 */
static void ice_lag_rdma_del_fltr(struct ice_lag *lag)
{
	struct ice_rule_query_data *rm_entry = &lag->fltr;
	struct ice_sw_rule_lkup_rx_tx *s_rule;
	struct ice_hw *hw = &lag->pf->hw;
	u16 rule_buf_sz;

	if (!rm_entry->rid || !rm_entry->rule_id)
		return;

	rule_buf_sz = sizeof(struct ice_sw_rule_lkup_rx_tx);
	s_rule = kzalloc(rule_buf_sz, GFP_KERNEL);
	if (!s_rule)
		return;

	s_rule->act = 0;
	s_rule->index = cpu_to_le16(rm_entry->rule_id);
	s_rule->hdr_len = 0;
	if (ice_aq_sw_rules(hw, (struct ice_aqc_sw_rules *)s_rule,
			    rule_buf_sz, 1,
			    ice_aqc_opc_remove_sw_rules, NULL))
		dev_warn(ice_pf_to_dev(lag->pf),
			 "Failed to remove RDMA switch rule\n");

	rm_entry->rid = 0;
	rm_entry->rule_id = 0;

	kfree(s_rule);
}

/**
 * ice_lag_rdma_del_action - free / unsub large action
 * @lag: LAG structure of the primary interface
 */
static void ice_lag_rdma_del_action(struct ice_lag *lag)
{
	struct ice_aqc_alloc_free_res_elem *sw_buf;
	struct ice_lag *primary_lag;
	const u16 buf_len = struct_size(sw_buf, elem, 1);
	int ret;

	if (lag->primary)
		primary_lag = lag;
	else
		primary_lag = ice_lag_find_primary(lag);

	if (!primary_lag)
		return;

	sw_buf = kzalloc(buf_len, GFP_KERNEL);
	if (!sw_buf)
		return;

	sw_buf->num_elems = cpu_to_le16(ICE_LAG_NUM_RULES);
	sw_buf->res_type = cpu_to_le16(ICE_AQC_RES_TYPE_WIDE_TABLE_1);
	sw_buf->elem[0].e.flu_resp = cpu_to_le16(primary_lag->action_idx);

	ret = ice_aq_alloc_free_res(&lag->pf->hw, ICE_LAG_NUM_RULES,
				    sw_buf, buf_len, ice_aqc_opc_free_res,
				    NULL);
	if (ret)
		dev_warn(ice_pf_to_dev(lag->pf),
			 "Failed to delete/unsub from large action %d\n",
			 ret);

	kfree(sw_buf);
}

/**
 * ice_lag_set_primary - set PF LAG state as Primary
 * @lag: LAG info struct
 */
static void ice_lag_set_primary(struct ice_lag *lag)
{
	struct ice_pf *pf = lag->pf;

	if (!pf)
		return;

	/* No previous primary interface */
	if (lag->role == ICE_LAG_UNSET) {
		lag->role = ICE_LAG_PRIMARY;
		return;
	}

	/* Taking primary role from previous primary */
	if (lag->role == ICE_LAG_BACKUP) {
		lag->role = ICE_LAG_PRIMARY;
		return;
	}

	dev_warn(ice_pf_to_dev(pf), "%s: Attempt to be Primary, but incompatible state. %d\n",
		 netdev_name(lag->netdev), lag->role);
}

/**
 * ice_lag_set_backup - set PF LAG state to Backup
 * @lag: LAG info struct
 */
static void ice_lag_set_backup(struct ice_lag *lag)
{
	struct ice_pf *pf = lag->pf;

	if (!pf)
		return;

	/* No previous backup interface */
	if (lag->role == ICE_LAG_UNSET) {
		lag->role = ICE_LAG_BACKUP;
		return;
	}

	/* Moving to backup from active role */
	if (lag->role == ICE_LAG_PRIMARY) {
		lag->role = ICE_LAG_BACKUP;
		return;
	}

	dev_dbg(ice_pf_to_dev(pf), "%s: Attempt to be Backup, but incompatible state %d\n",
		netdev_name(lag->netdev), lag->role);
}

/**
 * ice_display_lag_info - print LAG info
 * @lag: LAG info struct
 */
static void ice_display_lag_info(struct ice_lag *lag)
{
	const char *name, *upper, *role, *bonded, *primary;
	struct device *dev = &lag->pf->pdev->dev;

	name = lag->netdev ? netdev_name(lag->netdev) : "unset";
	upper = lag->upper_netdev ? netdev_name(lag->upper_netdev) : "unset";
	primary = lag->primary ? "TRUE" : "FALSE";
	bonded = lag->bonded ? "BONDED" : "UNBONDED";

	switch (lag->role) {
	case ICE_LAG_NONE:
		role = "NONE";
		break;
	case ICE_LAG_PRIMARY:
		role = "PRIMARY";
		break;
	case ICE_LAG_BACKUP:
		role = "BACKUP";
		break;
	case ICE_LAG_UNSET:
		role = "UNSET";
		break;
	default:
		role = "ERROR";
	}

	dev_dbg(dev, "%s %s, upper:%s, role:%s, primary:%s\n", name,
		bonded, upper, role, primary);
}

/**
 * ice_is_bond_rdma_cap - check bond netdevs for RDMA compliance
 * @lag: pointer to local lag struct
 */
static bool ice_is_bond_rdma_cap(struct ice_lag *lag)
{
	struct list_head *tmp;

	list_for_each(tmp, lag->netdev_head) {
		struct ice_dcbx_cfg *dcb_cfg, *peer_dcb_cfg;
		struct ice_lag_netdev_list *entry;
		struct ice_netdev_priv *peer_np;
		struct net_device *peer_netdev;
		struct ice_vsi *vsi, *peer_vsi;

		entry = list_entry(tmp, struct ice_lag_netdev_list, node);
		peer_netdev = entry->netdev;
		/* non ice netdevs can't be used for RDMA */
		if (!netif_is_ice(peer_netdev)) {
			netdev_info(lag->netdev, "Found non-ice netdev %s\n",
				    netdev_name(peer_netdev));
			return false;
		}

		peer_np = netdev_priv(peer_netdev);
		vsi = ice_get_main_vsi(lag->pf);
		peer_vsi = peer_np->vsi;

		/* interfaces on different devices cannot be used for RDMA */
		if (lag->pf->pdev->bus != peer_vsi->back->pdev->bus ||
		    lag->pf->pdev->slot != peer_vsi->back->pdev->slot) {
			netdev_info(lag->netdev, "Found netdev %s on different device\n",
				    netdev_name(peer_netdev));
			return false;
		}

		dcb_cfg = &vsi->port_info->qos_cfg.local_dcbx_cfg;
		peer_dcb_cfg = &peer_vsi->port_info->qos_cfg.local_dcbx_cfg;

		/* interfaces with different DCB config cannot be used for
		 * RDMA
		 */
		if (memcmp(dcb_cfg, peer_dcb_cfg,
			   sizeof(struct ice_dcbx_cfg))) {
			netdev_info(lag->netdev, "Found netdev %s with different DCB config\n",
				    netdev_name(peer_netdev));
			return false;
		}
	}

	return true;
}

/**
 * ice_lag_chk_rdma - verify aggregate valid to support RDMA
 * @lag: LAG struct for this interface
 * @ptr: opaque data for netdev event info
 */
static void ice_lag_chk_rdma(struct ice_lag *lag, void *ptr)
{
	struct net_device *event_netdev, *event_upper;
	struct iidc_core_dev_info *cdev;

	/* if we are not primary, or this event for a netdev not in our
	 * bond, then we don't need to evaluate.
	 */
	if (!lag->primary)
		return;

	event_netdev = netdev_notifier_info_to_dev(ptr);
	rcu_read_lock();
	event_upper = netdev_master_upper_dev_get_rcu(event_netdev);
	rcu_read_unlock();
	if (event_upper != lag->upper_netdev)
		return;

	cdev = ice_find_cdev_info_by_id(lag->pf, IIDC_RDMA_ID);
	if (!cdev)
		return;

	if (cdev->rdma_protocol != IIDC_RDMA_PROTOCOL_ROCEV2)
		goto unplug_out;

	if (!ice_is_bond_rdma_cap(lag))
		goto unplug_out;

	ice_set_rdma_cap(lag->pf);
	if (!ice_is_reset_in_progress(lag->pf->state))
		ice_plug_aux_dev_lock(cdev, IIDC_RDMA_ROCE_NAME, lag);

	return;

unplug_out:
	ice_clear_rdma_cap(lag->pf);
	ice_unplug_aux_dev_lock(cdev, lag);
}

/**
 * ice_lag_info_event - handle NETDEV_BONDING_INFO event
 * @lag: LAG info struct
 * @ptr: opaque data pointer
 *
 * ptr is to be cast to (netdev_notifier_bonding_info *)
 */
static void ice_lag_info_event(struct ice_lag *lag, void *ptr)
{
	struct netdev_notifier_bonding_info *info;
	struct netdev_bonding_info *bonding_info;
	struct net_device *event_netdev;
	const char *lag_netdev_name;

	event_netdev = netdev_notifier_info_to_dev(ptr);
	if (!netif_is_ice(event_netdev))
		return;
	info = ptr;
	lag_netdev_name = netdev_name(lag->netdev);
	bonding_info = &info->bonding_info;

	if (event_netdev != lag->netdev || !lag->bonded || !lag->upper_netdev)
		return;

	if (strcmp(bonding_info->slave.slave_name, lag_netdev_name)) {
		netdev_dbg(lag->netdev, "Bonding event recv, but slave info not for us\n");
		goto lag_out;
	}

	if (bonding_info->slave.state)
		ice_lag_set_backup(lag);
	else
		ice_lag_set_primary(lag);

lag_out:
	ice_display_lag_info(lag);
}

/**
 * ice_lag_move_node - move scheduling node for RDMA LAG failover
 * @lag: lag info struct
 * @oldport: number of previous active port
 * @newport: number of new active port
 * @tc: traffic class of the qset node to move
 * @teid: id of node that is moving
 * @qs_handle: qset handle in rdma space
 */
int
ice_lag_move_node(struct ice_lag *lag, u8 oldport, u8 newport, u8 tc, u32 teid,
		  u16 qs_handle)
{
	struct ice_hw *old_hw = NULL, *new_hw = NULL;
	u16 max_rdmaqs[ICE_MAX_TRAFFIC_CLASS] = {};
	struct ice_aqc_move_rdma_qset_buffer *buf;
	struct ice_sched_node *node, *new_parent;
	struct ice_aqc_move_rdma_qset_cmd *cmd;
	struct ice_vsi *new_vsi = NULL;
	struct net_device *tmp_nd;
	struct ice_aq_desc desc;
	int err;

	max_rdmaqs[tc]++;

	/* locate the HW struct for old and new ports */
	rcu_read_lock();
	for_each_netdev_rcu(&init_net, tmp_nd) {
		struct ice_netdev_priv *tmp_ndp;
		struct ice_lag *tmp_lag;
		struct ice_vsi *tmp_vsi;
		struct ice_hw *tmp_hw;

		if (!netif_is_ice(tmp_nd))
			continue;

		tmp_ndp = netdev_priv(tmp_nd);
		tmp_vsi = tmp_ndp->vsi;
		tmp_lag = tmp_vsi->back->lag;
		if (!tmp_lag || !tmp_lag->bonded ||
		    tmp_lag->bond_id != lag->bond_id)
			continue;

		tmp_hw = &tmp_vsi->back->hw;
		if (tmp_hw->port_info->lport == oldport)
			old_hw = tmp_hw;

		if (tmp_hw->port_info->lport == newport) {
			new_vsi = tmp_vsi;
			new_hw = tmp_hw;
		}
	}
	rcu_read_unlock();

	if (!old_hw || !new_hw || !new_vsi) {
		dev_warn(ice_pf_to_dev(lag->pf),
			 "Could not locate resources to move node\n");
		return -EINVAL;
	}

	node = ice_sched_find_node_by_teid(old_hw->port_info->root, teid);
	if (!node) {
		dev_dbg(ice_pf_to_dev(lag->pf),
			"did not find teid %d in old port, checking new\n",
			teid);
		node = ice_sched_find_node_by_teid(new_hw->port_info->root,
						   teid);
		if (!node) {
			dev_warn(ice_pf_to_dev(lag->pf),
				 "Failed to find TEID %d to move for TC %d\n",
				 teid, tc);
			return -EINVAL;
		}
	}

	err = ice_cfg_vsi_rdma(new_hw->port_info, new_vsi->idx,
			       new_vsi->tc_cfg.ena_tc, max_rdmaqs);
	if (err) {
		dev_warn(ice_pf_to_dev(lag->pf), "Failed configuring port RDMA\n");
		return err;
	}

	cmd = &desc.params.move_rdma_qset;
	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_move_rdma_qset);

	cmd->num_rdma_qset = 1;
	cmd->flags = ICE_AQC_PF_MODE_KEEP_OWNERSHIP;
	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);

	buf = kzalloc(ICE_LAG_SINGLE_FILTER_SIZE, GFP_ATOMIC);
	if (!buf)
		return -ENOMEM;

	new_parent = ice_sched_get_free_qparent(new_hw->port_info, new_vsi->idx,
						tc, ICE_SCHED_NODE_OWNER_RDMA);
	if (!new_parent) {
		dev_warn(ice_pf_to_dev(lag->pf), "Could not find free qparent\n");
		err = -EINVAL;
		goto node_move_err;
	}

	buf->src_parent_teid = node->info.parent_teid;
	buf->dest_parent_teid = new_parent->info.node_teid;
	buf->descs[0].qset_teid = cpu_to_le16(teid);
	buf->descs[0].tx_qset_id = cpu_to_le16(qs_handle);

	err = ice_aq_send_cmd(&lag->pf->hw, &desc, buf,
			      ICE_LAG_SINGLE_FILTER_SIZE, NULL);
	if (!err)
		ice_sched_update_parent(new_parent, node);
	else
		dev_warn(ice_pf_to_dev(lag->pf), "Failed to move LAG sched node\n");

node_move_err:
	kfree(buf);
	return err;
}

/**
 * ice_lag_move_nodes - move scheduling nodes for RDMA LAG failover
 * @lag: lag info struct
 * @oldport: number of previous active port
 * @newport: number of new active port
 */
static void ice_lag_move_nodes(struct ice_lag *lag, u8 oldport, u8 newport)
{
	int err;
	u8 i;

	ice_for_each_traffic_class(i)
		if (lag->rdma_qset[i].teid) {
			err = ice_lag_move_node(lag, oldport, newport, i,
						lag->rdma_qset[i].teid,
						lag->rdma_qset[i].qs_handle);
			if (err)
				dev_err(&lag->pf->pdev->dev, "Error moving qset for TC %d: %d\n",
					i, err);
		}
}

/**
 * ice_lag_reclaim_node - reclaim node for specific TC back to original owner
 * @lag: ice_lag struct for primary interface
 * @active_hw: ice_hw struct for the currently active interface
 * @tc: which TC to reclaim qset node for
 */
static int
ice_lag_reclaim_node(struct ice_lag *lag, struct ice_hw *active_hw, u8 tc)
{
	struct ice_aqc_move_rdma_qset_buffer *buf;
	struct ice_sched_node *node, *new_parent;
	struct ice_aqc_move_rdma_qset_cmd *cmd;
	struct ice_aq_desc desc;
	struct ice_hw *prim_hw;

	prim_hw = &lag->pf->hw;
	node = ice_sched_find_node_by_teid(prim_hw->port_info->root,
					   lag->rdma_qset[tc].teid);
	if (!node) {
		dev_warn(ice_pf_to_dev(lag->pf), "Cannot find node to reclaim for TC %d\n",
			 tc);
		return -EINVAL;
	}

	cmd = &desc.params.move_rdma_qset;
	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_move_rdma_qset);

	cmd->num_rdma_qset = 1;
	cmd->flags = ICE_AQC_PF_MODE_KEEP_OWNERSHIP;
	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);

	new_parent = ice_sched_get_free_qparent(prim_hw->port_info,
						lag->pf->vsi[0]->idx, tc,
						ICE_SCHED_NODE_OWNER_RDMA);
	if (!new_parent) {
		dev_warn(ice_pf_to_dev(lag->pf), "Could not find free qparent\n");
		return -EINVAL;
	}

	buf = kzalloc(ICE_LAG_SINGLE_FILTER_SIZE, GFP_ATOMIC);
	if (!buf)
		return -ENOMEM;

	buf->src_parent_teid = node->info.parent_teid;
	buf->dest_parent_teid = new_parent->info.node_teid;
	buf->descs[0].qset_teid = cpu_to_le16(lag->rdma_qset[tc].teid);
	buf->descs[0].tx_qset_id = cpu_to_le16(lag->rdma_qset[tc].qs_handle);

	if (!ice_aq_send_cmd(&lag->pf->hw, &desc, buf,
			     ICE_LAG_SINGLE_FILTER_SIZE, NULL))
		node->info.parent_teid = new_parent->info.node_teid;

	kfree(buf);
	return 0;
}

/**
 * ice_lag_reclaim_nodes - helper function to reclaim nodes back to originator
 * @lag: ice_lag struct for primary interface
 * @active_hw: ice_hw struct for the currently active interface
 */
static void ice_lag_reclaim_nodes(struct ice_lag *lag, struct ice_hw *active_hw)
{
	u8 tc;

	ice_for_each_traffic_class(tc)
		if (lag->rdma_qset[tc].teid) {
			if (ice_lag_reclaim_node(lag, active_hw, tc))
				dev_err(ice_pf_to_dev(lag->pf), "Error reclaiming qset for TC %d\n",
					tc);
		}
}

/**
 * ice_lag_move_node_sync - move RDMA nodes out of sync with bonding events
 * @old_hw: HW struct where the node currently resides
 * @new_hw: HW struct where node is moving to
 * @new_vsi: new vsi that will be parent to node
 * @qset: params of the qset that is moving
 *
 * When qsets are allocated or freed on a bonded interface by the RDMA aux
 * driver making calls into the IDC interface, depending on the state of that
 * aggregate, it might be necessary to move the scheduleing nodes for that
 * qset to a different interfaces tree.  This happens without the advent of a
 * netdev bonding info event. ice_lag_move_node_sync will handle that case.
 */
int ice_lag_move_node_sync(struct ice_hw *old_hw, struct ice_hw *new_hw,
			   struct ice_vsi *new_vsi,
			   struct iidc_rdma_qset_params *qset)
{
	u16 max_rdmaqs[ICE_MAX_TRAFFIC_CLASS] = {};
	struct ice_aqc_move_rdma_qset_buffer *buf;
	struct ice_sched_node *node, *new_parent;
	struct ice_aqc_move_rdma_qset_cmd *cmd;
	struct ice_aq_desc desc;
	struct ice_hw *prim_hw;
	struct ice_pf *old_pf;
	int ret = 0;

	max_rdmaqs[qset->tc]++;

	node = ice_sched_find_node_by_teid(old_hw->port_info->root, qset->teid);
	if (!node) {
		node = ice_sched_find_node_by_teid(new_hw->port_info->root,
						   qset->teid);
		if (!node)
			return -ENOMEM;
	}

	cmd = &desc.params.move_rdma_qset;
	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_move_rdma_qset);
	cmd->num_rdma_qset = 1;
	cmd->flags = ICE_AQC_PF_MODE_KEEP_OWNERSHIP;
	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);

	buf = kzalloc(ICE_LAG_SINGLE_FILTER_SIZE, GFP_ATOMIC);
	if (!buf)
		return -ENOMEM;

	ice_cfg_vsi_rdma(new_hw->port_info, new_vsi->idx,
			 new_vsi->tc_cfg.ena_tc, max_rdmaqs);

	new_parent = ice_sched_get_free_qparent(new_hw->port_info, new_vsi->idx,
						qset->tc,
						ICE_SCHED_NODE_OWNER_RDMA);
	if (!new_parent) {
		ret = -ENOMEM;
		goto node_sync_out;
	}

	old_pf = old_hw->back;
	if (old_pf->lag->primary)
		prim_hw = old_hw;
	else
		prim_hw = new_hw;

	buf->src_parent_teid = node->info.parent_teid;
	buf->dest_parent_teid = new_parent->info.node_teid;
	buf->descs[0].qset_teid = cpu_to_le16(qset->teid);
	buf->descs[0].tx_qset_id = cpu_to_le16(qset->qs_handle);
	ice_aq_send_cmd(prim_hw, &desc, buf, ICE_LAG_SINGLE_FILTER_SIZE, NULL);
	node->info.parent_teid = new_parent->info.node_teid;

node_sync_out:
	kfree(buf);
	return ret;
}

/**
 * ice_lag_link - handle LAG link event
 * @lag: LAG info struct
 */
static void ice_lag_link(struct ice_lag *lag)
{
	struct iidc_core_dev_info *cdev;
	struct ice_pf *pf = lag->pf;

	if (lag->bonded)
		dev_warn(ice_pf_to_dev(pf), "%s Already part of a bond\n",
			 netdev_name(lag->netdev));

	cdev = ice_find_cdev_info_by_id(pf, IIDC_RDMA_ID);
	if (cdev && lag->primary)
		cdev->rdma_active_port = lag->pf->hw.port_info->lport;
	ice_clear_rdma_cap(pf);
	ice_unplug_aux_dev_lock(cdev, lag);

	lag->bonded = true;
	lag->role = ICE_LAG_UNSET;
}

/**
 * ice_lag_unlink - handle unlink event
 * @lag: LAG info struct
 */
static void ice_lag_unlink(struct ice_lag *lag)
{
	struct iidc_core_dev_info *cdev;
	struct ice_pf *pf = lag->pf;

	if (!lag->bonded) {
		netdev_dbg(lag->netdev, "bonding unlink event on non-LAG netdev\n");
		return;
	}

	/* Unplug aux dev from aggregate interface if primary*/
	if (lag->primary) {
		lag->primary = false;
		cdev = ice_find_cdev_info_by_id(pf, IIDC_RDMA_ID);
		if (cdev) {
			ice_unplug_aux_dev_lock(cdev, lag);
			ice_clear_rdma_cap(pf);
			cdev->rdma_active_port = ICE_LAG_INVALID_PORT;
			cdev->rdma_ports[ICE_PRI_IDX] = IIDC_RDMA_INVALID_PORT;
			cdev->rdma_port_bitmap &= ~IIDC_RDMA_PRIMARY_PORT;
			cdev->bond_aa = false;
		}
	} else {
		struct ice_lag *primary_lag;

		primary_lag = ice_lag_find_primary(lag);
		if (primary_lag) {
			u8 pri_port, act_port, loc_port;

			cdev = ice_find_cdev_info_by_id(primary_lag->pf,
							IIDC_RDMA_ID);
			if (cdev) {
				act_port = cdev->rdma_active_port;
				pri_port = primary_lag->pf->hw.port_info->lport;
				loc_port = pf->hw.port_info->lport;
				if (cdev->bond_aa) {
					u8 port;

					port = IIDC_RDMA_PRIMARY_PORT;
					cdev->rdma_port_bitmap &=
						~IIDC_RDMA_SECONDARY_PORT;
					ice_lag_aa_failover(primary_lag, cdev,
							    port, false);
					cdev->rdma_ports[ICE_SEC_IDX] =
						IIDC_RDMA_INVALID_PORT;
				} else {
					if (act_port == loc_port)
						ice_lag_move_nodes(primary_lag,
								   loc_port,
								   pri_port);
				}
			}
		}
	}

	lag->bonded = false;
	lag->role = ICE_LAG_NONE;
	lag->upper_netdev = NULL;
	ice_set_rdma_cap(pf);
	cdev = ice_find_cdev_info_by_id(pf, IIDC_RDMA_ID);
	if (cdev) {
		const char *name;

		if (cdev->rdma_protocol == IIDC_RDMA_PROTOCOL_IWARP)
			name = IIDC_RDMA_IWARP_NAME;
		else
			name = IIDC_RDMA_ROCE_NAME;
		if (!ice_is_reset_in_progress(lag->pf->state))
			ice_plug_aux_dev_lock(cdev, name, lag);
	}
}

/**
 * ice_lag_changeupper_event - handle LAG changeupper event
 * @lag: lag info struct
 * @ptr: opaque pointer data
 *
 * ptr is to be cast into netdev_notifier_changeupper_info
 */
static void ice_lag_changeupper_event(struct ice_lag *lag, void *ptr)
{
	struct netdev_notifier_changeupper_info *info;
	struct net_device *netdev;

	info = ptr;
	netdev = netdev_notifier_info_to_dev(ptr);

	/* not for this netdev */
	if (netdev != lag->netdev)
		return;

	if (info->linking) {
		struct ice_lag *primary_lag;

		lag->upper_netdev = info->upper_dev;
		/* If there is not already a primary interface in the LAG,
		 * then mark this one as primary.
		 * In the case RDMA is supported, this will be the only PCI
		 * device that will initiate communication and supply resource
		 * for the RDMA auxiliary driver
		 */
		primary_lag  = ice_lag_find_primary(lag);
		if (primary_lag) {
			lag->bond_id = primary_lag->bond_id;
			if (netif_is_same_ice(primary_lag->pf, netdev))
				if (ice_lag_rdma_create_fltr(lag))
					netdev_warn(lag->netdev, "Error creating RoCEv2 filter\n");

		} else {
			lag->bond_id = ida_alloc(&ice_lag_ida, GFP_KERNEL);
			lag->primary = true;
			lag->rdma_vsi = lag->pf->vsi[0];
			if (ice_lag_rdma_create_fltr(lag))
				netdev_warn(lag->netdev, "Error creating RoCEv2 filter\n");
		}

		ice_lag_link(lag);
	} else {
		if (!lag->primary) {
			ice_lag_rdma_del_fltr(lag);
		} else {
			ida_simple_remove(&ice_lag_ida, lag->bond_id);
		}

		lag->bond_id = -1;
		ice_lag_rdma_del_action(lag);
		ice_lag_unlink(lag);
	}

	ice_display_lag_info(lag);
}

/**
 * ice_lag_aa_failover - handle sched node moving for active-active bonds
 * @lag: lag struct for primary PF
 * @cdev: auxiliary device struct
 * @dest: destination port (primary 0x01 or secondary 0x02)
 * @locked: is the aux dev lock held in this call chain
 *
 * This function will determine by the state of the cdev and lag struct elements
 * whether to move all, none, or some of the sched nodes to the destination port
 */
void ice_lag_aa_failover(struct ice_lag *lag, struct iidc_core_dev_info *cdev,
			 u8 dest, bool locked)
{
	struct iidc_event *event = NULL;
	u8 all = 0;
	int i;

	/* if the destination port is not up, don't move resources there */
	if (!(cdev->rdma_port_bitmap & dest))
		return;

	if (cdev->adev && !locked)
		device_lock(&cdev->adev->dev);

	if (cdev->adev) {
		event = kzalloc(sizeof(*event), GFP_ATOMIC);
		if (event) {
			set_bit(IIDC_EVENT_FAILOVER_START, event->type);
			ice_send_event_to_aux_no_lock(cdev, event);
		}
	}

	/* if both ports not active, move all resources to new active port */
	all = cdev->rdma_port_bitmap ^ IIDC_RDMA_BOTH_PORT;

	ice_for_each_traffic_class(i) {
		struct iidc_rdma_multi_qset_params *qsets;
		u16 qsh;

		qsets = lag->rdma_qsets;
		if (dest == IIDC_RDMA_PRIMARY_PORT) {
			if (qsets[i].teid[ICE_PRI_IDX] &&
			    cdev->rdma_ports[ICE_PRI_IDX] !=
			    IIDC_RDMA_INVALID_PORT &&
			    qsets[i].qset_port[ICE_PRI_IDX] != dest) {
				qsh = qsets[i].qs_handle[ICE_PRI_IDX];
				ice_lag_move_node(lag,
						  cdev->rdma_ports[ICE_SEC_IDX],
						  cdev->rdma_ports[ICE_PRI_IDX],
						  i,
						  qsets[i].teid[ICE_PRI_IDX],
						  qsh);
				qsets[i].qset_port[ICE_PRI_IDX] = dest;
			}
			if (all && qsets[i].teid[ICE_SEC_IDX] &&
			    cdev->rdma_ports[ICE_PRI_IDX] !=
			    IIDC_RDMA_INVALID_PORT &&
			    qsets[i].qset_port[ICE_SEC_IDX] != dest) {
				qsh = qsets[i].qs_handle[ICE_SEC_IDX];
				ice_lag_move_node(lag,
						  cdev->rdma_ports[ICE_SEC_IDX],
						  cdev->rdma_ports[ICE_PRI_IDX],
						  i,
						  qsets[i].teid[ICE_SEC_IDX],
						  qsh);
				qsets[i].qset_port[ICE_SEC_IDX] = dest;
			}
		} else {
			if (qsets[i].teid[ICE_SEC_IDX] &&
			    cdev->rdma_ports[ICE_SEC_IDX] !=
			    IIDC_RDMA_INVALID_PORT &&
			    qsets[i].qset_port[ICE_SEC_IDX] != dest) {
				qsh = qsets[i].qs_handle[ICE_SEC_IDX];
				ice_lag_move_node(lag,
						  cdev->rdma_ports[ICE_PRI_IDX],
						  cdev->rdma_ports[ICE_SEC_IDX],
						  i,
						  qsets[i].teid[ICE_SEC_IDX],
						  qsh);
				qsets[i].qset_port[ICE_SEC_IDX] = dest;
			}
			if (all && qsets[i].teid[ICE_PRI_IDX] &&
			    cdev->rdma_ports[ICE_SEC_IDX] !=
			    IIDC_RDMA_INVALID_PORT &&
			    qsets[i].qset_port[ICE_PRI_IDX] != dest) {
				qsh = qsets[i].qs_handle[ICE_PRI_IDX];
				ice_lag_move_node(lag,
						  cdev->rdma_ports[ICE_PRI_IDX],
						  cdev->rdma_ports[ICE_SEC_IDX],
						  i,
						  qsets[i].teid[ICE_PRI_IDX],
						  qsh);
				qsets[i].qset_port[ICE_PRI_IDX] = dest;
			}
		}
	}
	if (event) {
		clear_bit(IIDC_EVENT_FAILOVER_START, event->type);
		set_bit(IIDC_EVENT_FAILOVER_FINISH, event->type);
		ice_send_event_to_aux_no_lock(cdev, event);
		kfree(event);
	}
	if (cdev->adev && !locked)
		device_unlock(&cdev->adev->dev);
}

/**
 * ice_lag_monitor_link - main PF detect if nodes need to move on unlink
 * @lag: lag info struct
 * @ptr: opaque data containing notifier event
 *
 * This function is for the primary interface to monitor interfaces leaving the
 * aggregate, and if they own scheduling nodes to move them back to the primary.
 * Also maintain the prune lists for interfaces entering or leaving the
 * aggregate.
 */
static void ice_lag_monitor_link(struct ice_lag *lag, void *ptr)
{
	struct ice_hw *prim_hw, *event_hw, *active_hw = NULL;
	struct netdev_notifier_changeupper_info *info;
	struct ice_netdev_priv *event_np;
	struct iidc_core_dev_info *cdev;
	struct net_device *event_netdev;
	u8 event_port, prim_port;
	struct iidc_event *event;
	struct ice_pf *event_pf;

	if (!lag->primary)
		return;

	event_netdev = netdev_notifier_info_to_dev(ptr);
	/* only ice interfaces should be considered for this function */
	if (!netif_is_ice(event_netdev))
		return;

	event_np = netdev_priv(event_netdev);
	event_pf = event_np->vsi->back;
	event_hw = &event_pf->hw;
	event_port = event_hw->port_info->lport;
	prim_hw = &lag->pf->hw;
	prim_port = prim_hw->port_info->lport;

	info = ptr;
	if (info->linking) {
		struct net_device *event_upper;

		/* If linking port is not the primary, then we need
		 * to add the primary's VSI to linking ports prune
		 * list
		 */
		rcu_read_lock();
		event_upper = netdev_master_upper_dev_get_rcu(event_netdev);
		rcu_read_unlock();
		if (prim_port != event_port && event_upper == lag->upper_netdev)
			ice_lag_add_prune_list(lag, event_pf);
	} else {
		if (prim_port != event_port) {
			/* If un-linking port is not the primary, then we need
			 * to remove the primary's VSI from un-linking ports
			 * prune list
			 */
			ice_lag_del_prune_list(lag, event_pf);
		} else {
			struct list_head *tmp;

			/* Primary VSI leaving bond, need to remove its
			 * VSI from all remaining interfaces prune lists
			 */
			list_for_each(tmp, lag->netdev_head) {
				struct ice_lag_netdev_list *entry;
				struct net_device *nd;

				entry = list_entry(tmp,
						   struct ice_lag_netdev_list,
						   node);
				nd = entry->netdev;

				if (!netif_is_ice(nd))
					continue;

				if (nd && nd != lag->netdev) {
					struct ice_netdev_priv *np;
					struct ice_vsi *vsi;
					struct ice_pf *pf;

					np = netdev_priv(nd);
					if (!np)
						continue;
					vsi = np->vsi;
					if (!vsi)
						continue;
					pf = vsi->back;
					if (pf && pf->lag) {
						ice_lag_del_prune_list(lag, pf);
						pf->lag->bond_id = -1;
					}
				}
			}
		}
	}

	/* End of linking functionality */
	if (info->linking || (!ice_is_aux_ena(lag->pf) ||
			      !ice_is_rdma_ena(lag->pf)))
		return;

	cdev = ice_find_cdev_info_by_id(lag->pf, IIDC_RDMA_ID);
	if (!cdev)
		return;

	if (cdev->bond_aa) {
		ice_lag_aa_reclaim_nodes(cdev, lag->rdma_qsets);
		return;
	}

	if ((cdev->rdma_active_port != event_port &&
	     prim_port != event_port) ||
	    (cdev->rdma_active_port == event_port &&
	     prim_port == event_port))
		return;

	/* non-primary active port or primary non-active has left the
	 * aggregate. Need to perform early failover and move nodes back
	 * to primary port.  This will allow us to either continue RDMA
	 * communication on the primary port or cease RDMA communication
	 * cleanly if the primary port has left the aggregate.
	 */
	if (event_port == prim_port) {
		struct list_head *tmp;

		list_for_each(tmp, lag->netdev_head) {
			struct ice_lag_netdev_list *entry;
			struct ice_netdev_priv *active_np;
			struct net_device *tmp_netdev;
			struct ice_vsi *active_vsi;

			entry = list_entry(tmp, struct ice_lag_netdev_list,
					   node);
			tmp_netdev = entry->netdev;
			if (!tmp_netdev)
				continue;

			active_np = netdev_priv(tmp_netdev);
			if (!active_np)
				continue;

			active_vsi = active_np->vsi;
			if (!active_vsi)
				continue;

			if (active_vsi->back->hw.port_info->lport ==
			    cdev->rdma_active_port) {
				active_hw = &active_vsi->back->hw;
				break;
			}
		}
	} else {
		active_hw = event_hw;
	}
	if (!active_hw) {
		dev_warn(ice_pf_to_dev(lag->pf), "Could not find Active Port HW struct\n");
		return;
	}

	if (!cdev->adev)
		return;

	device_lock(&cdev->adev->dev);
	event = kzalloc(sizeof(*event), GFP_ATOMIC);
	if (event) {
		set_bit(IIDC_EVENT_FAILOVER_START, event->type);
		ice_send_event_to_aux_no_lock(cdev, event);
	}

	dev_warn(ice_pf_to_dev(lag->pf), "Moving nodes from %d to %d\n",
		 cdev->rdma_active_port, prim_port);
	ice_lag_reclaim_nodes(lag, active_hw);

	cdev->rdma_active_port = prim_port;

	if (event) {
		clear_bit(IIDC_EVENT_FAILOVER_START, event->type);
		set_bit(IIDC_EVENT_FAILOVER_FINISH, event->type);
		ice_send_event_to_aux_no_lock(cdev, event);
		kfree(event);
	}
	device_unlock(&cdev->adev->dev);
}

/**
 * ice_lag_monitor_act_back - main PF keep track of which port is active
 * @lag: lag info struct
 * @cdev: auxiliary device struct
 * @b_info: bonding_info
 * @event_netdev: net_device struct for target netdev
 *
 * This function is for the primary PF to monitor changes in which port is
 * active in an active-backup bond, and handle changes for RDMA functionality
 */
static void ice_lag_monitor_act_back(struct ice_lag *lag,
				     struct iidc_core_dev_info *cdev,
				     struct netdev_bonding_info *b_info,
				     struct net_device *event_netdev)
{
	struct ice_netdev_priv *event_np;
	u8 prim_port, event_port;
	struct ice_pf *event_pf;

	event_np = netdev_priv(event_netdev);
	event_pf = event_np->vsi->back;
	event_port = event_pf->hw.port_info->lport;
	prim_port = lag->pf->hw.port_info->lport;

	/* first time setting active port for this aggregate */
	if (cdev->rdma_active_port == ICE_LAG_INVALID_PORT &&
	    !b_info->slave.state) {
		cdev->rdma_active_port = event_port;
		if (prim_port != event_port) {
			struct iidc_event *event;

			if (!cdev->adev)
				return;

			device_lock(&cdev->adev->dev);
			/* start failover process for RDMA */
			event = kzalloc(sizeof(*event), GFP_ATOMIC);
			if (event) {
				set_bit(IIDC_EVENT_FAILOVER_START,
					event->type);
				ice_send_event_to_aux_no_lock(cdev, event);
			}

			dev_dbg(ice_pf_to_dev(lag->pf), "Moving nodes from %d to %d\n",
				prim_port, event_port);
			ice_lag_move_nodes(lag, prim_port, event_port);

			if (event) {
				clear_bit(IIDC_EVENT_FAILOVER_START,
					  event->type);
				set_bit(IIDC_EVENT_FAILOVER_FINISH,
					event->type);
				ice_send_event_to_aux_no_lock(cdev, event);
				kfree(event);
			}
			device_unlock(&cdev->adev->dev);
		}
		return;
	}

	/* new active port */
	if (!b_info->slave.state && cdev->rdma_active_port != event_port) {
		struct iidc_event *event;

		if (!cdev->adev)
			return;
		device_lock(&cdev->adev->dev);
		/* start failover process for RDMA */
		event = kzalloc(sizeof(*event), GFP_ATOMIC);
		if (event) {
			set_bit(IIDC_EVENT_FAILOVER_START, event->type);
			ice_send_event_to_aux_no_lock(cdev, event);
		}

		dev_dbg(ice_pf_to_dev(lag->pf), "Moving nodes from %d to %d\n",
			cdev->rdma_active_port, event_port);
		ice_lag_move_nodes(lag, cdev->rdma_active_port, event_port);
		cdev->rdma_active_port = event_port;

		if (event) {
			clear_bit(IIDC_EVENT_FAILOVER_START, event->type);
			set_bit(IIDC_EVENT_FAILOVER_FINISH, event->type);
			ice_send_event_to_aux_no_lock(cdev, event);
			kfree(event);
		}
		device_unlock(&cdev->adev->dev);
	}
}

/**
 * ice_lag_monitor_act_act - main PF keep track of which port is active
 * @lag: lag info struct
 * @cdev: auxiliary device struct
 * @b_info: bonding_info
 * @event_netdev: net_device struct for target netdev
 *
 * This function is for the primary PF to monitor changes in which port is
 * active in an active-backup bond, and handle changes for RDMA functionality
 */
static void ice_lag_monitor_act_act(struct ice_lag *lag,
				    struct iidc_core_dev_info *cdev,
				    struct netdev_bonding_info *b_info,
				    struct net_device *event_netdev)
{
	struct ice_netdev_priv *event_np;
	u8 prim_port, event_port;
	struct ice_pf *event_pf;

	event_np = netdev_priv(event_netdev);
	event_pf = event_np->vsi->back;
	event_port = event_pf->hw.port_info->lport;
	prim_port = lag->pf->hw.port_info->lport;

	if (b_info->slave.link == BOND_LINK_UP) {
		if (prim_port == event_port) {
			cdev->rdma_port_bitmap |= IIDC_RDMA_PRIMARY_PORT;
			if (cdev->rdma_ports[ICE_PRI_IDX] ==
			    IIDC_RDMA_INVALID_PORT)
				cdev->rdma_ports[ICE_PRI_IDX] = event_port;
			ice_lag_aa_failover(lag, cdev, IIDC_RDMA_PRIMARY_PORT,
					    false);
		} else {
			cdev->rdma_port_bitmap |= IIDC_RDMA_SECONDARY_PORT;
			if (cdev->rdma_ports[ICE_SEC_IDX] ==
			    IIDC_RDMA_INVALID_PORT)
				cdev->rdma_ports[ICE_SEC_IDX] = event_port;
			ice_lag_aa_failover(lag, cdev, IIDC_RDMA_SECONDARY_PORT,
					    false);
		}
	} else {
		if (prim_port == event_port) {
			cdev->rdma_port_bitmap &= ~IIDC_RDMA_PRIMARY_PORT;
			if (cdev->rdma_ports[ICE_PRI_IDX] ==
			    IIDC_RDMA_INVALID_PORT)
				cdev->rdma_ports[ICE_PRI_IDX] = event_port;
			ice_lag_aa_failover(lag, cdev, IIDC_RDMA_SECONDARY_PORT,
					    false);
		} else {
			cdev->rdma_port_bitmap &= ~IIDC_RDMA_SECONDARY_PORT;
			if (cdev->rdma_ports[ICE_SEC_IDX] ==
			    IIDC_RDMA_INVALID_PORT)
				cdev->rdma_ports[ICE_SEC_IDX] = event_port;
			ice_lag_aa_failover(lag, cdev, IIDC_RDMA_PRIMARY_PORT,
					    false);
		}
	}
}

/**
 * ice_lag_monitor_info - call subfunction based on bonding mode
 * @lag: lag info struct
 * @ptr: opaque data containing notifier event
 */
static void ice_lag_monitor_info(struct ice_lag *lag, void *ptr)
{
	struct net_device *event_netdev, *event_upper;
	struct netdev_notifier_bonding_info *info;
	struct netdev_bonding_info *bonding_info;
	struct iidc_core_dev_info *cdev;

	if (!lag->primary)
		return;

	cdev = ice_find_cdev_info_by_id(lag->pf, IIDC_RDMA_ID);
	if (!cdev)
		return;

	event_netdev = netdev_notifier_info_to_dev(ptr);
	rcu_read_lock();
	event_upper = netdev_master_upper_dev_get_rcu(event_netdev);
	rcu_read_unlock();
	if (!netif_is_ice(event_netdev) || event_upper != lag->upper_netdev)
		return;

	info = ptr;
	bonding_info = &info->bonding_info;

	if (bonding_info->master.bond_mode == BOND_MODE_ACTIVEBACKUP) {
		cdev->bond_aa = 0;
		ice_lag_monitor_act_back(lag, cdev, bonding_info, event_netdev);
	} else {
		cdev->bond_aa = 1;
		ice_lag_monitor_act_act(lag, cdev, bonding_info, event_netdev);
	}
}

/**
 * ice_lag_process_event - process a task assigned to the lag_wq
 * @work: pointer to work_struct
 */
static void ice_lag_process_event(struct work_struct *work)
{
	struct ice_lag_work *lag_work;
	struct net_device *netdev;
	struct list_head *tmp, *n;

	lag_work = container_of(work, struct ice_lag_work, lag_task);
	if (!lag_work->lag || !lag_work->lag->pf)
		return;

	mutex_lock(&lag_work->lag->pf->lag_mutex);

	lag_work->lag->netdev_head = &lag_work->netdev_list.node;

	switch (lag_work->event) {
	case NETDEV_CHANGEUPPER:
		if (ice_is_feature_supported(lag_work->lag->pf, ICE_F_LAG))
			ice_lag_monitor_link(lag_work->lag,
					     &lag_work->info.changeupper_info);
		ice_lag_changeupper_event(lag_work->lag,
					  &lag_work->info.changeupper_info);
		break;
	case NETDEV_BONDING_INFO:
		if (ice_is_feature_supported(lag_work->lag->pf, ICE_F_LAG)) {
			ice_lag_monitor_info(lag_work->lag,
					     &lag_work->info.bonding_info);
			ice_lag_chk_rdma(lag_work->lag,
					 &lag_work->info.bonding_info);
		}
		ice_lag_info_event(lag_work->lag, &lag_work->info.bonding_info);
		break;
	case NETDEV_UNREGISTER:
		netdev = lag_work->info.bonding_info.info.dev;
		if (netdev == lag_work->lag->netdev && lag_work->lag->bonded)
			ice_lag_unlink(lag_work->lag);
		break;
	default:
		break;
	}

	/* cleanup resources allocated for this work item */
	list_for_each_safe(tmp, n, &lag_work->netdev_list.node) {
		struct ice_lag_netdev_list *entry;

		entry = list_entry(tmp, struct ice_lag_netdev_list, node);
		list_del(&entry->node);
		kfree(entry);
	}
	lag_work->lag->netdev_head = NULL;

	mutex_unlock(&lag_work->lag->pf->lag_mutex);

	kfree(work);
}

/**
 * ice_lag_event_handler - handle LAG events from netdev
 * @notif_blk: notifier block registered by this netdev
 * @event: event type
 * @ptr: opaque data containing notifier event
 */
static int
ice_lag_event_handler(struct notifier_block *notif_blk, unsigned long event,
		      void *ptr)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(ptr);
	struct net_device *upper_netdev;
	struct ice_lag_work *lag_work;
	struct ice_lag *lag;

	if (event != NETDEV_CHANGEUPPER && event != NETDEV_BONDING_INFO &&
	    event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	if (!(netdev->priv_flags & IFF_BONDING))
		return NOTIFY_DONE;

	lag = container_of(notif_blk, struct ice_lag, notif_block);

	if (!lag->netdev)
		return NOTIFY_DONE;

	/* Check that the netdev is in the working namespace */
	if (!net_eq(dev_net(netdev), &init_net))
		return NOTIFY_DONE;

	/* This memory will be freed at the end of ice_lag_process_event */
	lag_work = kzalloc(sizeof(*lag_work), GFP_KERNEL);
	if (!lag_work)
		return -ENOMEM;

	lag_work->event_netdev = netdev;
	lag_work->lag = lag;
	lag_work->event = event;
	if (event == NETDEV_CHANGEUPPER) {
		struct netdev_notifier_changeupper_info *info;

		info = ptr;
		upper_netdev = info->upper_dev;
	} else {
		upper_netdev = netdev_master_upper_dev_get(netdev);
	}

	INIT_LIST_HEAD(&lag_work->netdev_list.node);
	if (upper_netdev) {
		struct ice_lag_netdev_list *nd_list;
		struct net_device *tmp_nd;

		for_each_netdev(&init_net, tmp_nd) {
			if (netdev_master_upper_dev_get(tmp_nd) ==
			    upper_netdev) {
				nd_list = kzalloc(sizeof(*nd_list), GFP_KERNEL);
				if (!nd_list)
					continue;

				nd_list->netdev = tmp_nd;
				list_add(&nd_list->node,
					 &lag_work->netdev_list.node);
			}
		}
	}

	memcpy(&lag_work->info, ptr, sizeof(lag_work->info));
	INIT_WORK(&lag_work->lag_task, ice_lag_process_event);
	queue_work(ice_lag_wq, &lag_work->lag_task);
	return NOTIFY_DONE;
}

/**
 * ice_register_lag_handler - register LAG handler on netdev
 * @lag: lag info struct
 */
static int ice_register_lag_handler(struct ice_lag *lag)
{
	struct device *dev = ice_pf_to_dev(lag->pf);
	struct notifier_block *notif_blk;

	notif_blk = &lag->notif_block;

	if (!notif_blk->notifier_call) {
		notif_blk->notifier_call = ice_lag_event_handler;
		if (register_netdevice_notifier(notif_blk)) {
			notif_blk->notifier_call = NULL;
			dev_err(dev, "FAIL register LAG event handler!\n");
			return -EINVAL;
		}
		dev_dbg(dev, "LAG event handler registered\n");
	}
	return 0;
}

/**
 * ice_unregister_lag_handler - unregister LAG handler on netdev
 * @lag: lag info struct
 */
static void ice_unregister_lag_handler(struct ice_lag *lag)
{
	struct device *dev = ice_pf_to_dev(lag->pf);
	struct notifier_block *notif_blk;

	notif_blk = &lag->notif_block;
	if (notif_blk->notifier_call) {
		unregister_netdevice_notifier(notif_blk);
		dev_dbg(dev, "LAG event handler unregistered\n");
	}
}

/**
 * ice_lag_check_nvm_support - Check for NVM support for LAG
 * @pf: PF struct
 */
static void ice_lag_check_nvm_support(struct ice_pf *pf)
{
	struct ice_hw_dev_caps *caps;

	caps = &pf->hw.dev_caps;
	if (caps->common_cap.roce_lag)
		ice_set_feature_support(pf, ICE_F_LAG);
	else
		ice_clear_feature_support(pf, ICE_F_LAG);
}

/**
 * ice_init_lag - initialize support for LAG
 * @pf: PF struct
 *
 * Alloc memory for LAG structs and initialize the elements.
 * Memory will be freed in ice_deinit_lag
 */
int ice_init_lag(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_lag *lag;
	struct ice_vsi *vsi;
	int err;
	u8 i;

	ice_lag_check_nvm_support(pf);
	if (!ice_is_feature_supported(pf, ICE_F_LAG))
		return 0;

	pf->lag = kzalloc(sizeof(*lag), GFP_KERNEL);
	if (!pf->lag)
		return -ENOMEM;
	lag = pf->lag;

	vsi = ice_get_main_vsi(pf);
	if (!vsi) {
		dev_err(dev, "couldn't get main vsi, link aggregation init fail\n");
		err = -EIO;
		goto lag_error;
	}

	lag->pf = pf;
	lag->netdev = vsi->netdev;
	lag->role = ICE_LAG_NONE;
	lag->bonded = false;
	lag->bond_id = -1;
	lag->upper_netdev = NULL;
	lag->notif_block.notifier_call = NULL;
	lag->netdev_head = NULL;
	ice_for_each_traffic_class(i)
		memset(&pf->lag->rdma_qset[i], 0,
		       sizeof(struct iidc_rdma_qset_params));

	err = ice_register_lag_handler(lag);
	if (err) {
		dev_warn(dev, "INIT LAG: Failed to register event handler\n");
		goto lag_error;
	}

	ice_display_lag_info(lag);

	dev_dbg(dev, "INIT LAG complete\n");
	return 0;

lag_error:
	kfree(lag);
	pf->lag = NULL;
	return err;
}

/**
 * ice_deinit_lag - Clean up LAG
 * @pf: PF struct
 *
 * Clean up kernel LAG info and free memory
 * This function is meant to only be called on driver remove/shutdown
 */
void ice_deinit_lag(struct ice_pf *pf)
{
	struct ice_lag *lag;

	lag = pf->lag;

	if (!lag)
		return;

	if (lag->pf)
		ice_unregister_lag_handler(lag);

	flush_workqueue(ice_lag_wq);

	kfree(lag);

	pf->lag = NULL;
}
#endif /* HAVE_NETDEV_UPPER_INFO */
