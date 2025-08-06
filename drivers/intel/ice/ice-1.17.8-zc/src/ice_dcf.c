/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice.h"

static const enum ice_adminq_opc aqc_permitted_tbl[] = {
	/* Generic Firmware Admin commands */
	ice_aqc_opc_get_ver,
	ice_aqc_opc_req_res,
	ice_aqc_opc_release_res,
	ice_aqc_opc_list_func_caps,
	ice_aqc_opc_list_dev_caps,

	ice_aqc_opc_get_vlan_mode_parameters,

	/* Package Configuration Admin Commands */
	ice_aqc_opc_update_pkg,
	ice_aqc_opc_get_pkg_info_list,

	/* PHY commands */
	ice_aqc_opc_get_phy_caps,
	ice_aqc_opc_get_link_status,

	/* Switch Block */
	ice_aqc_opc_get_sw_cfg,
	ice_aqc_opc_alloc_res,
	ice_aqc_opc_free_res,
	ice_aqc_opc_add_recipe,
	ice_aqc_opc_recipe_to_profile,
	ice_aqc_opc_get_recipe,
	ice_aqc_opc_get_recipe_to_profile,
	ice_aqc_opc_add_sw_rules,
	ice_aqc_opc_update_sw_rules,
	ice_aqc_opc_remove_sw_rules,

	/* ACL commands */
	ice_aqc_opc_alloc_acl_tbl,
	ice_aqc_opc_dealloc_acl_tbl,
	ice_aqc_opc_alloc_acl_actpair,
	ice_aqc_opc_dealloc_acl_actpair,
	ice_aqc_opc_alloc_acl_scen,
	ice_aqc_opc_dealloc_acl_scen,
	ice_aqc_opc_alloc_acl_counters,
	ice_aqc_opc_dealloc_acl_counters,
	ice_aqc_opc_dealloc_acl_res,
	ice_aqc_opc_update_acl_scen,
	ice_aqc_opc_program_acl_actpair,
	ice_aqc_opc_program_acl_prof_extraction,
	ice_aqc_opc_program_acl_prof_ranges,
	ice_aqc_opc_program_acl_entry,
	ice_aqc_opc_query_acl_prof,
	ice_aqc_opc_query_acl_prof_ranges,
	ice_aqc_opc_query_acl_scen,
	ice_aqc_opc_query_acl_entry,
	ice_aqc_opc_query_acl_actpair,
	ice_aqc_opc_query_acl_counter,

	/* QoS */
	ice_aqc_opc_query_port_ets,
};

/**
 * ice_dcf_aq_cmd_permitted - validate the AdminQ command permitted or not
 * @desc: descriptor describing the command
 */
bool ice_dcf_aq_cmd_permitted(struct ice_aq_desc *desc)
{
	u16 opc = le16_to_cpu(desc->opcode);
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(aqc_permitted_tbl); i++)
		if (opc == aqc_permitted_tbl[i])
			return true;

	return false;
}

/**
 * ice_dcf_is_acl_aq_cmd - check if the AdminQ command is ACL command
 * @desc: descriptor describing the command
 */
bool ice_dcf_is_acl_aq_cmd(struct ice_aq_desc *desc)
{
	u16 opc = le16_to_cpu(desc->opcode);

	if (opc >= ice_aqc_opc_alloc_acl_tbl &&
	    opc <= ice_aqc_opc_query_acl_counter)
		return true;

	return false;
}

/**
 * ice_dcf_is_udp_tunnel_aq_cmd - check if the AdminQ command is UDP tunnel
 * command
 * @desc: descriptor describing the command
 * @aq_buf: AdminQ buffer
 */
bool ice_dcf_is_udp_tunnel_aq_cmd(struct ice_aq_desc *desc, u8 *aq_buf)
{
	struct ice_buf_hdr *pkg_buf;

	if (!aq_buf)
		return false;

	if (le16_to_cpu(desc->opcode) != ice_aqc_opc_update_pkg)
		return false;

	pkg_buf = (struct ice_buf_hdr *)aq_buf;
	/* section count for udp tunnel command is always 2 */
	if (le16_to_cpu(pkg_buf->section_count) != 2)
		return false;

	if (le32_to_cpu(pkg_buf->section_entry[0].type) ==
	    ICE_SID_RXPARSER_BOOST_TCAM ||
	    le32_to_cpu(pkg_buf->section_entry[0].type) ==
	    ICE_SID_TXPARSER_BOOST_TCAM)
		return true;

	return false;
}

/**
 * ice_is_vf_adq_enabled - Check if any VF has ADQ enabled
 * @pf: pointer to the PF structure
 * @vf_id: on true return, the first VF ID that we found had ADQ enabled
 *
 * Return true if any VF has ADQ enabled. Return false otherwise.
 */
static bool ice_is_vf_adq_enabled(struct ice_pf *pf, u16 *vf_id)
{
	bool adq_enabled = false;
	struct ice_vf *vf;
	unsigned int bkt;

	rcu_read_lock();
	ice_for_each_vf_rcu(pf, bkt, vf) {
		if (vf->adq_enabled) {
			*vf_id = vf->vf_id;
			adq_enabled = true;
			break;
		}
	}
	rcu_read_unlock();

	return adq_enabled;
}

/**
 * ice_vf_chnl_fltrs_enabled - Check if a VF has TC filters enabled
 * @pf: pointer to the PF structure
 * @vf_id: on true return, the first VF ID that we found had TC filters
 *
 * Return true if any VF has TC filters. Return false otherwise.
 */
static bool ice_vf_chnl_fltrs_enabled(struct ice_pf *pf, u16 *vf_id)
{
	bool chnl_fltrs_enabled = false;
	struct ice_vf *vf;
	unsigned int bkt;

	rcu_read_lock();
	ice_for_each_vf_rcu(pf, bkt, vf) {
		if (vf->num_dmac_chnl_fltrs) {
			*vf_id = vf->vf_id;
			chnl_fltrs_enabled = true;
			break;
		}
	}
	rcu_read_unlock();

	return chnl_fltrs_enabled;
}

/**
 * ice_check_dcf_allowed - check if DCF is allowed based on various checks
 * @vf: pointer to the VF to check
 */
bool ice_check_dcf_allowed(struct ice_vf *vf)
{
	struct ice_switch_info *sw;
	struct ice_pf *pf = vf->pf;
	struct device *dev;
	u16 i;

	dev = ice_pf_to_dev(pf);

	if (vf->vf_id != ICE_DCF_VFID) {
		dev_err(dev, "VF %d requested DCF capability, but only VF %d is allowed to request DCF capability\n",
			vf->vf_id, ICE_DCF_VFID);
		return false;
	}

	if (!vf->trusted) {
		dev_err(dev, "VF needs to be trusted to configure DCF capability\n");
		return false;
	}

	/* DCF and ADQ are mutually exclusive. */
#ifdef NETIF_F_HW_TC
	if (ice_is_adq_active(pf)) {
		dev_err(dev, "ADQ on PF is currently enabled. Device Control Functionality cannot be enabled.\n");
		return false;
	}
#endif /* NETIF_F_HW_TC */

	if (ice_is_vf_adq_enabled(pf, &i)) {
		dev_err(dev, "ADQ on VF %d is currently enabled. Device Control Functionality cannot be enabled.\n",
			i);
		return false;
	}

#ifdef HAVE_TC_SETUP_CLSFLOWER
	if (!hlist_empty(&pf->tc_flower_fltr_list)) {
		dev_err(dev, "TC filters on PF are currently in use. Device Control Functionality cannot be enabled.\n");
		return false;
	}
#endif /* HAVE_TC_SETUP_CLSFLOWER */

	if (ice_vf_chnl_fltrs_enabled(pf, &i)) {
		dev_err(dev, "TC filters on VF %d are currently in use. Device Control Functionality cannot be enabled.\n",
			i);
		return false;
	}

#ifdef HAVE_NDO_DFWD_OPS
	if (ice_is_offloaded_macvlan_ena(pf)) {
		dev_err(dev, "L2 Forwarding Offload is currently enabled. Device Control Functionality cannot be enabled.\n");
		return false;
	}
#endif /* HAVE_NDO_DFWD_OPS */

	sw = pf->hw.switch_info;
	for (i = 0; i < ICE_MAX_NUM_RECIPES; i++) {
		if (sw->recp_list[i].adv_rule) {
			dev_err(dev, "Advanced switch filters are currently in use. Device Control Functionality cannot be enabled.\n");
			return false;
		}
	}
	return true;
}

/**
 * ice_is_dcf_enabled - Check the DCF enabled status of the associated PF
 * @pf: PF instance
 */
bool ice_is_dcf_enabled(struct ice_pf *pf)
{
	return !!pf->dcf.vf;
}

/**
 * ice_is_vf_dcf - helper to check if the assigned VF is a DCF
 * @vf: the assigned VF to be checked
 */
bool ice_is_vf_dcf(struct ice_vf *vf)
{
	return vf == vf->pf->dcf.vf;
}

/**
 * ice_dcf_get_state - Get DCF state of the associated PF
 * @pf: PF instance
 */
enum ice_dcf_state ice_dcf_get_state(struct ice_pf *pf)
{
	return pf->dcf.vf ? pf->dcf.state : ICE_DCF_STATE_OFF;
}

/**
 * ice_dcf_state_str - convert DCF state code to a string
 * @state: the DCF state code to convert
 */
static const char *ice_dcf_state_str(enum ice_dcf_state state)
{
	switch (state) {
	case ICE_DCF_STATE_OFF:
		return "ICE_DCF_STATE_OFF";
	case ICE_DCF_STATE_ON:
		return "ICE_DCF_STATE_ON";
	case ICE_DCF_STATE_BUSY:
		return "ICE_DCF_STATE_BUSY";
	case ICE_DCF_STATE_PAUSE:
		return "ICE_DCF_STATE_PAUSE";
	}

	return "ICE_DCF_STATE_UNKNOWN";
}

/**
 * ice_dcf_set_state - Set DCF state for the associated PF
 * @pf: PF instance
 * @state: new DCF state
 */
void ice_dcf_set_state(struct ice_pf *pf, enum ice_dcf_state state)
{
	dev_dbg(ice_pf_to_dev(pf), "DCF state is changing from %s to %s\n",
		ice_dcf_state_str(pf->dcf.state),
		ice_dcf_state_str(state));

	pf->dcf.state = state;
}

/**
 * ice_dcf_rm_sw_rule_to_vsi - remove switch rule of "forward to VSI"
 * @pf: pointer to the PF struct
 * @s_entry: pointer to switch rule entry to remove
 */
static int
ice_dcf_rm_sw_rule_to_vsi(struct ice_pf *pf,
			  struct ice_dcf_sw_rule_entry *s_entry)
{
	struct ice_sw_rule_lkup_rx_tx *s_rule;
	u16 s_rule_sz;
	int status;

	s_rule_sz = struct_size(s_rule, hdr_data, 0);
	s_rule = kzalloc(s_rule_sz, GFP_KERNEL);
	if (!s_rule)
		return -ENOMEM;

	s_rule->hdr.type = cpu_to_le16(ICE_AQC_SW_RULES_T_LKUP_RX);
	s_rule->act = 0;
	s_rule->hdr_len = 0;
	s_rule->index = cpu_to_le16(s_entry->rule_id);
	status = ice_aq_sw_rules(&pf->hw, s_rule, s_rule_sz, 1,
				 ice_aqc_opc_remove_sw_rules, NULL);
	kfree(s_rule);
	if (status)
		return -EIO;

	list_del(&s_entry->list_entry);
	kfree(s_entry);
	return 0;
}

/**
 * ice_dcf_rm_sw_rule_to_vsi_list - remove switch rule of "forward to VSI list"
 * @pf: pointer to the PF struct
 * @s_entry: pointer to switch rule entry to remove
 */
static int
ice_dcf_rm_sw_rule_to_vsi_list(struct ice_pf *pf,
			       struct ice_dcf_sw_rule_entry *s_entry)
{
	struct ice_dcf_vsi_list_info *vsi_list_info = s_entry->vsi_list_info;
	struct ice_aqc_alloc_free_res_elem *res_buf;
	struct ice_sw_rule_vsi_list *s_rule;
	u16 res_buf_sz;
	u16 s_rule_sz;
	u16 vsi_id;
	int status;
	int i = 0;

	if (!vsi_list_info)
		return -EINVAL;

	/* The VSI list is empty, it can be freed immediately */
	if (!vsi_list_info->vsi_count)
		goto free_vsi_list;

	s_rule_sz = struct_size(s_rule, vsi, vsi_list_info->vsi_count);
	s_rule = kzalloc(s_rule_sz, GFP_KERNEL);
	if (!s_rule)
		return -ENOMEM;

	s_rule->hdr.type = cpu_to_le16(ICE_AQC_SW_RULES_T_VSI_LIST_CLEAR);
	s_rule->index = cpu_to_le16(vsi_list_info->list_id);
	s_rule->number_vsi = cpu_to_le16(vsi_list_info->vsi_count);
	for_each_set_bit(vsi_id, vsi_list_info->hw_vsi_map, ICE_HW_VSI_ID_MAX)
		s_rule->vsi[i++] = cpu_to_le16(vsi_id);

	bitmap_zero(vsi_list_info->hw_vsi_map, ICE_HW_VSI_ID_MAX);
	vsi_list_info->vsi_count = 0;

	status = ice_aq_sw_rules(&pf->hw, s_rule, s_rule_sz, 1,
				 ice_aqc_opc_update_sw_rules, NULL);
	kfree(s_rule);
	if (status)
		return -EIO;

free_vsi_list:
	res_buf_sz = struct_size(res_buf, elem, 1);
	res_buf = kzalloc(res_buf_sz, GFP_KERNEL);
	if (!res_buf)
		return -ENOMEM;

	res_buf->res_type = cpu_to_le16(ICE_AQC_RES_TYPE_VSI_LIST_REP);
	res_buf->num_elems = cpu_to_le16(1);
	res_buf->elem[0].e.sw_resp = cpu_to_le16(vsi_list_info->list_id);
	status = ice_aq_alloc_free_res(&pf->hw, 1, res_buf, res_buf_sz,
				       ice_aqc_opc_free_res, NULL);
	kfree(res_buf);
	if (status)
		return -EIO;

	list_del(&vsi_list_info->list_entry);
	kfree(vsi_list_info);
	s_entry->vsi_list_info = NULL;

	return ice_dcf_rm_sw_rule_to_vsi(pf, s_entry);
}

/**
 * ice_dcf_rm_vsi_from_list - remove VSI from switch rule forward VSI list
 * @pf: pointer to the PF struct
 * @vsi_list_info: pointer to the VSI list info
 * @hw_vsi_id: the Hardware VSI number
 */
static int
ice_dcf_rm_vsi_from_list(struct ice_pf *pf,
			 struct ice_dcf_vsi_list_info *vsi_list_info,
			 u16 hw_vsi_id)
{
	struct ice_sw_rule_vsi_list *s_rule;
	u16 s_rule_sz;
	int status;

	if (!vsi_list_info || !vsi_list_info->vsi_count ||
	    !test_bit(hw_vsi_id, vsi_list_info->hw_vsi_map))
		return -ENOENT;

	s_rule_sz = struct_size(s_rule, vsi, 1);
	s_rule = kzalloc(s_rule_sz, GFP_KERNEL);
	if (!s_rule)
		return -ENOMEM;

	s_rule->hdr.type = cpu_to_le16(ICE_AQC_SW_RULES_T_VSI_LIST_CLEAR);
	s_rule->index = cpu_to_le16(vsi_list_info->list_id);
	s_rule->number_vsi = cpu_to_le16(1);
	s_rule->vsi[0] = cpu_to_le16(hw_vsi_id);
	status = ice_aq_sw_rules(&pf->hw, s_rule, s_rule_sz, 1,
				 ice_aqc_opc_update_sw_rules, NULL);
	kfree(s_rule);
	if (status)
		return -EIO;

	/* When the VF resets gracefully, it should keep the VSI list and its
	 * rule, just clears the VSI from list, so that the DCF can replay the
	 * rule by updating this VF to list successfully.
	 */
	vsi_list_info->vsi_count--;
	clear_bit(hw_vsi_id, vsi_list_info->hw_vsi_map);

	return 0;
}

/**
 * ice_rm_dcf_sw_vsi_rule - remove switch rules added by DCF to VSI
 * @pf: pointer to the PF struct
 * @vf: VF to remove switch rules for
 */
void ice_rm_dcf_sw_vsi_rule(struct ice_pf *pf, struct ice_vf *vf)
{
	struct ice_dcf_sw_rule_entry *s_entry, *tmp;
	struct ice_vsi *vsi;
	int ret;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return;

	list_for_each_entry_safe(s_entry, tmp, &pf->dcf.sw_rule_head,
				 list_entry)
		if (s_entry->fltr_act == ICE_FWD_TO_VSI_LIST) {
			ret = ice_dcf_rm_vsi_from_list(pf,
						       s_entry->vsi_list_info,
						       vsi->vsi_num);
			if (ret && ret != -ENOENT)
				ice_dev_err_errno(ice_pf_to_dev(pf), ret,
						  "Failed to remove VSI %u from VSI list",
						  vsi->vsi_num);
		} else if (s_entry->fwd_id.hw_vsi_id == vsi->vsi_num) {
			ret = ice_dcf_rm_sw_rule_to_vsi(pf, s_entry);
			if (ret)
				ice_dev_err_errno(ice_pf_to_dev(pf), ret,
						  "Failed to remove VSI %u switch rule",
						  vsi->vsi_num);
		}
}

/**
 * ice_dcf_init_sw_rule_mgmt - initializes DCF rule filter mngt struct
 * @pf: pointer to the PF struct
 */
void ice_dcf_init_sw_rule_mgmt(struct ice_pf *pf)
{
	INIT_LIST_HEAD(&pf->dcf.sw_rule_head);
	INIT_LIST_HEAD(&pf->dcf.vsi_list_info_head);
}

/**
 * ice_rm_all_dcf_sw_rules - remove switch rules configured by DCF
 * @pf: pointer to the PF struct
 */
void ice_rm_all_dcf_sw_rules(struct ice_pf *pf)
{
	struct ice_dcf_vsi_list_info *vsi_list_info, *list_info_tmp;
	struct ice_dcf_sw_rule_entry *sw_rule, *rule_tmp;
	u16 rule_id, list_id;
	int ret;

	list_for_each_entry_safe(sw_rule, rule_tmp, &pf->dcf.sw_rule_head,
				 list_entry)
		if (sw_rule->fltr_act == ICE_FWD_TO_VSI_LIST) {
			list_id = sw_rule->fwd_id.vsi_list_id;
			rule_id = sw_rule->rule_id;
			ret = ice_dcf_rm_sw_rule_to_vsi_list(pf, sw_rule);
			if (ret)
				ice_dev_err_errno(ice_pf_to_dev(pf), ret,
						  "Failed to remove switch rule 0x%04x with list id %u",
						  rule_id, list_id);
		} else {
			rule_id = sw_rule->rule_id;
			ret = ice_dcf_rm_sw_rule_to_vsi(pf, sw_rule);
			if (ret)
				ice_dev_err_errno(ice_pf_to_dev(pf), ret,
						  "Failed to remove switch rule 0x%04x",
						  rule_id);
		}

	/* clears rule filter management data if AdminQ command has error */
	list_for_each_entry_safe(vsi_list_info, list_info_tmp,
				 &pf->dcf.vsi_list_info_head,
				 list_entry) {
		list_del(&vsi_list_info->list_entry);
		kfree(vsi_list_info);
	}

	list_for_each_entry_safe(sw_rule, rule_tmp, &pf->dcf.sw_rule_head,
				 list_entry) {
		list_del(&sw_rule->list_entry);
		kfree(sw_rule);
	}
}

/**
 * ice_clear_dcf_acl_cfg - clear DCF ACL configuration for the PF
 * @pf: pointer to the PF info
 */
void ice_clear_dcf_acl_cfg(struct ice_pf *pf)
{
	if (pf->hw.dcf_caps & DCF_ACL_CAP) {
		ice_acl_destroy_tbl(&pf->hw);
		ice_init_acl(pf);
	}
}

/**
 * ice_dcf_is_acl_capable - check if DCF ACL capability enabled
 * @hw: pointer to the hardware info
 */
bool ice_dcf_is_acl_capable(struct ice_hw *hw)
{
	return hw->dcf_caps & DCF_ACL_CAP;
}

/**
 * ice_clear_dcf_udp_tunnel_cfg - clear DCF UDP tunnel configuration for the PF
 * @pf: pointer to the PF info
 */
void ice_clear_dcf_udp_tunnel_cfg(struct ice_pf *pf)
{
	if (pf->hw.dcf_caps & DCF_UDP_TUNNEL_CAP)
		ice_destroy_tunnel(&pf->hw, 0, true);
}

/**
 * ice_dcf_is_udp_tunnel_capable - check if DCF UDP tunnel capability enabled
 * @hw: pointer to the hardware info
 */
bool ice_dcf_is_udp_tunnel_capable(struct ice_hw *hw)
{
	return hw->dcf_caps & DCF_UDP_TUNNEL_CAP;
}

/**
 * ice_dcf_find_vsi_list_info - find the VSI list by ID.
 * @pf: pointer to the PF info
 * @vsi_list_id: VSI list ID
 */
static struct ice_dcf_vsi_list_info *
ice_dcf_find_vsi_list_info(struct ice_pf *pf, u16 vsi_list_id)
{
	struct ice_dcf_vsi_list_info *list_info;

	list_for_each_entry(list_info, &pf->dcf.vsi_list_info_head, list_entry)
		if (list_info->list_id == vsi_list_id)
			return list_info;

	return NULL;
}

/**
 * ice_dcf_add_vsi_id - add new VSI ID into list.
 * @vsi_list_info: pointer to the VSI list info
 * @hw_vsi_id: the VSI ID
 */
static void
ice_dcf_add_vsi_id(struct ice_dcf_vsi_list_info *vsi_list_info, u16 hw_vsi_id)
{
	if (!test_and_set_bit(hw_vsi_id, vsi_list_info->hw_vsi_map))
		vsi_list_info->vsi_count++;
}

/**
 * ice_dcf_del_vsi_id - delete the VSI ID from list.
 * @vsi_list_info: pointer to the VSI list info
 * @hw_vsi_id: the VSI ID
 */
static void
ice_dcf_del_vsi_id(struct ice_dcf_vsi_list_info *vsi_list_info, u16 hw_vsi_id)
{
	if (test_and_clear_bit(hw_vsi_id, vsi_list_info->hw_vsi_map))
		vsi_list_info->vsi_count--;
}

/**
 * ice_dcf_parse_alloc_vsi_list_res - parse the allocate VSI list resource
 * @pf: pointer to the PF info
 * @res: pointer to the VSI list resource
 */
static enum virtchnl_status_code
ice_dcf_parse_alloc_vsi_list_res(struct ice_pf *pf,
				 struct ice_aqc_res_elem *res)
{
	struct ice_dcf_vsi_list_info *vsi_list_info;
	u16 list_id = le16_to_cpu(res->e.sw_resp);

	vsi_list_info = ice_dcf_find_vsi_list_info(pf, list_id);
	if (vsi_list_info)
		return VIRTCHNL_STATUS_SUCCESS;

	vsi_list_info = kzalloc(sizeof(*vsi_list_info), GFP_KERNEL);
	if (!vsi_list_info)
		return VIRTCHNL_STATUS_ERR_NO_MEMORY;

	vsi_list_info->list_id = list_id;
	list_add(&vsi_list_info->list_entry, &pf->dcf.vsi_list_info_head);

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_dcf_parse_free_vsi_list_res - parse the free VSI list resource
 * @pf: pointer to the PF info
 * @res: pointer to the VSI list resource
 */
static enum virtchnl_status_code
ice_dcf_parse_free_vsi_list_res(struct ice_pf *pf,
				struct ice_aqc_res_elem *res)
{
	struct ice_dcf_vsi_list_info *vsi_list_info;
	u16 list_id = le16_to_cpu(res->e.sw_resp);

	vsi_list_info = ice_dcf_find_vsi_list_info(pf, list_id);
	if (!vsi_list_info)
		return VIRTCHNL_STATUS_ERR_PARAM;

	if (vsi_list_info->vsi_count)
		dev_warn(ice_pf_to_dev(pf),
			 "VSI list %u still has %u VSIs to be removed!\n",
			 list_id, vsi_list_info->vsi_count);

	if (vsi_list_info->sw_rule)
		vsi_list_info->sw_rule->vsi_list_info = NULL;

	list_del(&vsi_list_info->list_entry);
	kfree(vsi_list_info);

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_dcf_set_vsi_list - set the VSI to VSI list
 * @pf: pointer to the PF info
 * @vsi_list: pointer to the VSI ID list to be set
 */
static enum virtchnl_status_code
ice_dcf_set_vsi_list(struct ice_pf *pf, struct ice_sw_rule_vsi_list *vsi_list)
{
	struct ice_dcf_vsi_list_info *vsi_list_info;
	int i;

	vsi_list_info =
		ice_dcf_find_vsi_list_info(pf, le16_to_cpu(vsi_list->index));
	if (!vsi_list_info)
		return VIRTCHNL_STATUS_ERR_PARAM;

	for (i = 0; i < le16_to_cpu(vsi_list->number_vsi); i++)
		ice_dcf_add_vsi_id(vsi_list_info,
				   le16_to_cpu(vsi_list->vsi[i]));

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_dcf_clear_vsi_list - clear the VSI from VSI list
 * @pf: pointer to the PF info
 * @vsi_list: pointer to the VSI ID list to be cleared
 */
static enum virtchnl_status_code
ice_dcf_clear_vsi_list(struct ice_pf *pf, struct ice_sw_rule_vsi_list *vsi_list)
{
	struct ice_dcf_vsi_list_info *vsi_list_info;
	int i;

	vsi_list_info =
		ice_dcf_find_vsi_list_info(pf, le16_to_cpu(vsi_list->index));
	if (!vsi_list_info)
		return VIRTCHNL_STATUS_ERR_PARAM;

	for (i = 0; i < le16_to_cpu(vsi_list->number_vsi); i++)
		ice_dcf_del_vsi_id(vsi_list_info,
				   le16_to_cpu(vsi_list->vsi[i]));

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_dcf_find_sw_rule - find the switch rule by ID.
 * @pf: pointer to the PF info
 * @rule_id: switch rule ID
 */
static struct ice_dcf_sw_rule_entry *
ice_dcf_find_sw_rule(struct ice_pf *pf, u16 rule_id)
{
	struct ice_dcf_sw_rule_entry *sw_rule;

	list_for_each_entry(sw_rule, &pf->dcf.sw_rule_head, list_entry)
		if (sw_rule->rule_id == rule_id)
			return sw_rule;

	return NULL;
}

/**
 * ice_dcf_parse_add_sw_rule_data - parse the add switch rule data
 * @pf: pointer to the PF info
 * @lkup: pointer to the add switch rule data
 */
static enum virtchnl_status_code
ice_dcf_parse_add_sw_rule_data(struct ice_pf *pf,
			       struct ice_sw_rule_lkup_rx_tx *lkup)
{
	struct ice_dcf_sw_rule_entry *sw_rule;
	u32 act;

	sw_rule = kzalloc(sizeof(*sw_rule), GFP_KERNEL);
	if (!sw_rule)
		return VIRTCHNL_STATUS_ERR_NO_MEMORY;

	act = le32_to_cpu(lkup->act);
	sw_rule->fltr_act = ICE_FWD_TO_VSI;
	sw_rule->fwd_id.hw_vsi_id = FIELD_GET(ICE_SINGLE_ACT_VSI_ID_M, act);
	sw_rule->rule_id = le16_to_cpu(lkup->index);

	list_add(&sw_rule->list_entry, &pf->dcf.sw_rule_head);

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_dcf_parse_updt_sw_rule_data - parse the update switch rule data
 * @pf: pointer to the PF info
 * @lkup: pointer to the update switch rule data
 */
static enum virtchnl_status_code
ice_dcf_parse_updt_sw_rule_data(struct ice_pf *pf,
				struct ice_sw_rule_lkup_rx_tx *lkup)
{
	struct ice_dcf_vsi_list_info *vsi_list_info;
	struct ice_dcf_sw_rule_entry *sw_rule;
	u16 vsi_list_id, rule_id;
	u32 act;

	rule_id = le16_to_cpu(lkup->index);
	sw_rule = ice_dcf_find_sw_rule(pf, rule_id);
	if (!sw_rule)
		return VIRTCHNL_STATUS_ERR_PARAM;

	act = le32_to_cpu(lkup->act);
	if (!(act & ICE_SINGLE_ACT_VSI_LIST)) {
		u16 vsi_hw_id = FIELD_GET(ICE_SINGLE_ACT_VSI_ID_M, act);

		sw_rule->fltr_act = ICE_FWD_TO_VSI;
		sw_rule->fwd_id.hw_vsi_id = vsi_hw_id;

		return VIRTCHNL_STATUS_SUCCESS;
	}

	vsi_list_id = FIELD_GET(ICE_SINGLE_ACT_VSI_LIST_ID_M, act);
	if (sw_rule->vsi_list_info) {
		if (sw_rule->vsi_list_info->list_id == vsi_list_id)
			return VIRTCHNL_STATUS_SUCCESS;

		dev_err(ice_pf_to_dev(pf),
			"The switch rule 0x%04x is running on VSI list %u\n",
			rule_id, sw_rule->vsi_list_info->list_id);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	vsi_list_info = ice_dcf_find_vsi_list_info(pf, vsi_list_id);
	if (!vsi_list_info) {
		dev_err(ice_pf_to_dev(pf),
			"No VSI list %u found to bind the switch rule 0x%04x\n",
			vsi_list_id, rule_id);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	if (vsi_list_info->sw_rule) {
		if (vsi_list_info->sw_rule->rule_id == rule_id)
			return VIRTCHNL_STATUS_SUCCESS;

		dev_err(ice_pf_to_dev(pf),
			"The VSI list %u is running on switch rule 0x%04x\n",
			vsi_list_id, vsi_list_info->sw_rule->rule_id);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	vsi_list_info->sw_rule = sw_rule;

	sw_rule->fltr_act = ICE_FWD_TO_VSI_LIST;
	sw_rule->fwd_id.vsi_list_id = vsi_list_id;
	sw_rule->vsi_list_info = vsi_list_info;

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_dcf_parse_rm_sw_rule_data - parse the remove switch rule data
 * @pf: pointer to the PF info
 * @lkup: pointer to the remove switch rule data
 */
static enum virtchnl_status_code
ice_dcf_parse_rm_sw_rule_data(struct ice_pf *pf,
			      struct ice_sw_rule_lkup_rx_tx *lkup)
{
	u16 rule_id = le16_to_cpu(lkup->index);
	struct ice_dcf_sw_rule_entry *sw_rule, *tmp;

	list_for_each_entry_safe(sw_rule, tmp, &pf->dcf.sw_rule_head,
				 list_entry)
		if (sw_rule->rule_id == rule_id) {
			list_del(&sw_rule->list_entry);
			kfree(sw_rule);
		}

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_dcf_handle_add_sw_rule_rsp - handle the add switch rule response
 * @pf: pointer to the PF info
 * @aq_buf: pointer to the add switch rule command buffer
 */
static enum virtchnl_status_code
ice_dcf_handle_add_sw_rule_rsp(struct ice_pf *pf, u8 *aq_buf)
{
	enum virtchnl_status_code status = VIRTCHNL_STATUS_SUCCESS;
	struct ice_aqc_sw_rules_elem_hdr *em =
		(struct ice_aqc_sw_rules_elem_hdr *)aq_buf;
	u16 type = le16_to_cpu(em->type);

	if (type == ICE_AQC_SW_RULES_T_VSI_LIST_SET)
		status = ice_dcf_set_vsi_list(pf,
			(struct ice_sw_rule_vsi_list *)em);
	else if (type == ICE_AQC_SW_RULES_T_LKUP_RX)
		status = ice_dcf_parse_add_sw_rule_data(pf,
			(struct ice_sw_rule_lkup_rx_tx *)em);

	return status;
}

/**
 * ice_dcf_handle_updt_sw_rule_rsp - handle the update switch rule response
 * @pf: pointer to the PF info
 * @aq_buf: pointer to the update switch rule command buffer
 */
static enum virtchnl_status_code
ice_dcf_handle_updt_sw_rule_rsp(struct ice_pf *pf, u8 *aq_buf)
{
	enum virtchnl_status_code status = VIRTCHNL_STATUS_SUCCESS;
	struct ice_aqc_sw_rules_elem_hdr *em =
		(struct ice_aqc_sw_rules_elem_hdr *)aq_buf;
	u16 type = le16_to_cpu(em->type);

	if (type == ICE_AQC_SW_RULES_T_VSI_LIST_SET)
		status = ice_dcf_set_vsi_list(pf,
			(struct ice_sw_rule_vsi_list *)em);
	else if (type == ICE_AQC_SW_RULES_T_VSI_LIST_CLEAR)
		status = ice_dcf_clear_vsi_list(pf,
			(struct ice_sw_rule_vsi_list *)em);
	else if (type == ICE_AQC_SW_RULES_T_LKUP_RX)
		status = ice_dcf_parse_updt_sw_rule_data(pf,
			(struct ice_sw_rule_lkup_rx_tx *)em);

	return status;
}

/**
 * ice_dcf_handle_rm_sw_rule_rsp - handle the remove switch rule response
 * @pf: pointer to the PF info
 * @aq_buf: pointer to the remove switch rule command buffer
 */
static enum virtchnl_status_code
ice_dcf_handle_rm_sw_rule_rsp(struct ice_pf *pf, u8 *aq_buf)
{
	enum virtchnl_status_code status = VIRTCHNL_STATUS_SUCCESS;
	struct ice_aqc_sw_rules_elem_hdr *em =
		(struct ice_aqc_sw_rules_elem_hdr *)aq_buf;
	u16 type = le16_to_cpu(em->type);

	if (type == ICE_AQC_SW_RULES_T_LKUP_RX)
		status = ice_dcf_parse_rm_sw_rule_data(pf,
			(struct ice_sw_rule_lkup_rx_tx *)em);

	return status;
}

/**
 * ice_dcf_handle_alloc_res_rsp - handle the allocate resource response
 * @pf: pointer to the PF info
 * @aq_buf: pointer to the allocate resource command buffer
 */
static enum virtchnl_status_code
ice_dcf_handle_alloc_res_rsp(struct ice_pf *pf, u8 *aq_buf)
{
	enum virtchnl_status_code status = VIRTCHNL_STATUS_SUCCESS;
	struct ice_aqc_alloc_free_res_elem *res_buf =
		 (struct ice_aqc_alloc_free_res_elem *)aq_buf;
	u16 type = FIELD_GET(ICE_AQC_RES_TYPE_M,
			     le16_to_cpu(res_buf->res_type));

	if (type == ICE_AQC_RES_TYPE_VSI_LIST_REP)
		status = ice_dcf_parse_alloc_vsi_list_res(pf,
							  &res_buf->elem[0]);

	return status;
}

/**
 * ice_dcf_handle_free_res_rsp - handle the free resource response
 * @pf: pointer to the PF info
 * @aq_buf: pointer to the free resource command buffer
 */
static enum virtchnl_status_code
ice_dcf_handle_free_res_rsp(struct ice_pf *pf, u8 *aq_buf)
{
	enum virtchnl_status_code status = VIRTCHNL_STATUS_SUCCESS;
	struct ice_aqc_alloc_free_res_elem *res_buf =
		 (struct ice_aqc_alloc_free_res_elem *)aq_buf;
	u16 type = FIELD_GET(ICE_AQC_RES_TYPE_M,
			     le16_to_cpu(res_buf->res_type));

	if (type == ICE_AQC_RES_TYPE_VSI_LIST_REP)
		status = ice_dcf_parse_free_vsi_list_res(pf,
							 &res_buf->elem[0]);

	return status;
}

/**
 * ice_dcf_handle_udp_tunnel_rsp - handle the update package response
 * @pf: pointer to the PF info
 * @aq_desc: descriptor describing the command
 * @aq_buf: pointer to the package update command buffer
 */
static enum virtchnl_status_code
ice_dcf_handle_udp_tunnel_rsp(struct ice_pf *pf, struct ice_aq_desc *aq_desc,
			      u8 *aq_buf)
{
	struct ice_boost_tcam_section *sect;
	struct ice_buf_hdr *pkg_buf;
	struct ice_hw *hw = &pf->hw;
	u16 port_key, inv_port_key;
	u16 offset;
	u16 addr;
	u8 count;
	u16 i, j;

	mutex_lock(&hw->tnl_lock);
	pkg_buf = (struct ice_buf_hdr *)aq_buf;
	offset = le16_to_cpu(pkg_buf->section_entry[0].offset);
	sect = (struct ice_boost_tcam_section *)(((u8 *)pkg_buf) + offset);
	count = le16_to_cpu(sect->count);

	for (i = 0; i < hw->tnl.count && i < ICE_TUNNEL_MAX_ENTRIES; i++)
		for (j = 0; j < count; j++) {
			addr = le16_to_cpu(sect->tcam[j].addr);
			inv_port_key =
			    le16_to_cpu(sect->tcam[j].key.key.hv_dst_port_key);
			port_key =
			    le16_to_cpu(sect->tcam[j].key.key2.hv_dst_port_key);
			if (hw->tnl.tbl[i].valid &&
			    hw->tnl.tbl[i].boost_addr == addr) {
				/* It's tunnel destroy command if the key and
				 * inverse key is the same.
				 */
				if (port_key == inv_port_key) {
					hw->tnl.tbl[i].in_use = false;
					hw->tnl.tbl[i].port = 0;
					hw->tnl.tbl[i].ref = 0;
				} else {
					hw->tnl.tbl[i].port = port_key;
					hw->tnl.tbl[i].in_use = true;
					hw->tnl.tbl[i].ref = 1;
				}
			}
		}

	if (ice_is_tunnel_empty(&pf->hw))
		hw->dcf_caps &= ~DCF_UDP_TUNNEL_CAP;
	else
		hw->dcf_caps |= DCF_UDP_TUNNEL_CAP;
	mutex_unlock(&hw->tnl_lock);

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_dcf_post_aq_send_cmd - get the data from firmware successful response
 * @pf: pointer to the PF info
 * @aq_desc: descriptor describing the command
 * @aq_buf: the AdminQ command buffer
 */
enum virtchnl_status_code
ice_dcf_post_aq_send_cmd(struct ice_pf *pf, struct ice_aq_desc *aq_desc,
			 u8 *aq_buf)
{
	enum virtchnl_status_code status = VIRTCHNL_STATUS_SUCCESS;
	u16 opc = le16_to_cpu(aq_desc->opcode);

	if (!aq_buf)
		return VIRTCHNL_STATUS_SUCCESS;

	switch (opc) {
	case ice_aqc_opc_add_sw_rules:
		status = ice_dcf_handle_add_sw_rule_rsp(pf, aq_buf);
		break;
	case ice_aqc_opc_update_sw_rules:
		status = ice_dcf_handle_updt_sw_rule_rsp(pf, aq_buf);
		break;
	case ice_aqc_opc_remove_sw_rules:
		status = ice_dcf_handle_rm_sw_rule_rsp(pf, aq_buf);
		break;
	case ice_aqc_opc_alloc_res:
		status = ice_dcf_handle_alloc_res_rsp(pf, aq_buf);
		break;
	case ice_aqc_opc_free_res:
		status = ice_dcf_handle_free_res_rsp(pf, aq_buf);
		break;
	case ice_aqc_opc_update_pkg:
		if (ice_dcf_is_udp_tunnel_aq_cmd(aq_desc, aq_buf))
			status = ice_dcf_handle_udp_tunnel_rsp(pf, aq_desc,
							       aq_buf);
		break;
	}

	return status;
}

/**
 * ice_dcf_update_acl_rule_info - update DCF ACL rule info
 * @pf: pointer to the PF info
 * @desc: descriptor describing the command
 * @aq_buf: the AdminQ command buffer
 */
enum virtchnl_status_code
ice_dcf_update_acl_rule_info(struct ice_pf *pf, struct ice_aq_desc *desc,
			     u8 *aq_buf)
{
	struct ice_acl_scen *scen, *tmp;
	struct ice_acl_tbl *tbl;
	u16 scen_id;

	switch (le16_to_cpu(desc->opcode)) {
	case ice_aqc_opc_alloc_acl_tbl:
		if (pf->hw.acl_tbl)
			return VIRTCHNL_STATUS_ERR_PARAM;
		tbl = devm_kzalloc(ice_pf_to_dev(pf), sizeof(*tbl),
				   GFP_ATOMIC);
		if (!tbl)
			return VIRTCHNL_STATUS_ERR_PARAM;
		tbl->id = le16_to_cpu(((struct ice_aqc_acl_generic *)
					aq_buf)->alloc_id);
		INIT_LIST_HEAD(&tbl->scens);
		pf->hw.acl_tbl = tbl;
		break;
	case ice_aqc_opc_dealloc_acl_tbl:
		list_for_each_entry_safe(scen, tmp, &pf->hw.acl_tbl->scens,
					 list_entry) {
			list_del(&scen->list_entry);
			devm_kfree(ice_pf_to_dev(pf), scen);
		}
		devm_kfree(ice_pf_to_dev(pf), pf->hw.acl_tbl);
		pf->hw.acl_tbl = NULL;
		break;
	case ice_aqc_opc_alloc_acl_scen:
		scen = devm_kzalloc(ice_pf_to_dev(pf), sizeof(*scen),
				    GFP_ATOMIC);
		if (!scen)
			return VIRTCHNL_STATUS_ERR_PARAM;
		INIT_LIST_HEAD(&scen->list_entry);
		scen_id = le16_to_cpu(desc->params.alloc_scen.ops.resp.scen_id);
		scen->id = scen_id;
		list_add(&scen->list_entry, &pf->hw.acl_tbl->scens);
		break;
	case ice_aqc_opc_dealloc_acl_scen:
		list_for_each_entry_safe(scen, tmp, &pf->hw.acl_tbl->scens,
					 list_entry) {
			if (le16_to_cpu(desc->params.dealloc_scen.scen_id) ==
			    scen->id) {
				list_del(&scen->list_entry);
				devm_kfree(ice_pf_to_dev(pf), scen);
			}
		}
		break;
	}

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_dcf_pre_aq_send_cmd - check if it needs to send the command to firmware
 * @vf: pointer to the VF info
 * @aq_desc: descriptor describing the command
 * @aq_buf: the AdminQ command buffer
 * @aq_buf_size: the AdminQ command buffer size
 */
bool
ice_dcf_pre_aq_send_cmd(struct ice_vf *vf, struct ice_aq_desc *aq_desc,
			u8 *aq_buf, u16 aq_buf_size)
{
	struct ice_pf *pf = vf->pf;

	switch (le16_to_cpu(aq_desc->opcode)) {
	case ice_aqc_opc_update_sw_rules:
	{
		struct ice_dcf_vsi_list_info *vsi_list_info;
		struct ice_sw_rule_vsi_list *s_rule;
		u16 list_id, vsi_id;

		if (aq_buf_size < struct_size(s_rule, vsi, 1))
			break;

		s_rule = (typeof(s_rule))aq_buf;
		if (le16_to_cpu(s_rule->hdr.type) !=
					ICE_AQC_SW_RULES_T_VSI_LIST_CLEAR ||
		    le16_to_cpu(s_rule->number_vsi) != 1)
			break;

		list_id = le16_to_cpu(s_rule->index);
		vsi_list_info = ice_dcf_find_vsi_list_info(pf, list_id);
		if (!vsi_list_info)
			break;

		vsi_id = le16_to_cpu(s_rule->vsi[0]);
		if (vsi_id >= ICE_HW_VSI_ID_MAX ||
		    test_bit(vsi_id, vsi_list_info->hw_vsi_map))
			break;

		/* The VSI is removed from list already, no need to send the
		 * command to firmware.
		 */
		return true;
	}
	case ice_aqc_opc_remove_sw_rules:
	{
		struct ice_sw_rule_lkup_rx_tx *s_rule;
		u16 rule_id;

		if (aq_buf_size < struct_size(s_rule, hdr_data, 0))
			break;

		s_rule = (struct ice_sw_rule_lkup_rx_tx *)aq_buf;
		if (le16_to_cpu(s_rule->hdr.type) != ICE_AQC_SW_RULES_T_LKUP_RX)
			break;

		rule_id = le16_to_cpu(s_rule->index);
		if (ice_dcf_find_sw_rule(pf, rule_id))
			break;

		/* The switch rule is removed already, no need to send the
		 * command to firmware.
		 */
		return true;
	}

	default:
		break;
	}

	return false;
}
