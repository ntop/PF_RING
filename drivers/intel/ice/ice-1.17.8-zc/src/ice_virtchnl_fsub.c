/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice.h"
#include "ice_base.h"
#include "ice_lib.h"

#define to_sub_conf_from_desc(p) \
	container_of(p, struct ice_flow_sub_conf, fsub_fltr)

struct ice_flow_sub_fltr {
	struct list_head fltr_node;
	struct ice_adv_lkup_elem *list;
	struct ice_adv_rule_info rule_info;
	struct ice_rule_query_data rule_data;
};

struct ice_flow_sub_conf {
	u32 flow_id;
	struct ice_flow_sub_fltr fsub_fltr;
};

/**
 * ice_vc_fsub_param_check
 * @vf: pointer to the VF structure
 * @vsi_id: VF relative VSI ID
 *
 * Check for the valid VSI ID, PF's state and VF's state
 *
 * Return: 0 on success, and -EINVAL on error.
 */
static int
ice_vc_fsub_param_check(struct ice_vf *vf, u16 vsi_id)
{
	struct device *dev;
	struct ice_pf *pf;

	pf = vf->pf;
	dev = ice_pf_to_dev(pf);

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		dev_dbg(dev, "The state is not activeted for VF: %d\n",
			vf->vf_id);
		return -EPERM;
	}

	if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_FSUB_PF)) {
		dev_dbg(dev, "Invalid VF capability flag for VF: %d\n",
			vf->vf_id);
		return -EACCES;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vsi_id)) {
		dev_dbg(dev, "Invalid vsi_id for VF: %d\n", vf->vf_id);
		return -EINVAL;
	}

	if (!ice_get_vf_vsi(vf)) {
		dev_dbg(dev, "Get vsi failed for VF: %d\n", vf->vf_id);
		return -ENOENT;
	}

	if (!vf->trusted) {
		dev_dbg(dev, "It is not trusted for VF: %d\n", vf->vf_id);
		return -EACCES;
	}

	return 0;
}

/**
 * is_zero_buffer
 * @buffer: pointer to the input buffer
 * @size: size of the input buffer
 *
 * Detect the input buffer if it is zero or not
 *
 * Returns true if buffer contains only zeroes, false otherwise.
 */
static bool
is_zero_buffer(const u8 *buffer, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		if (buffer[i] != 0)
			return false;
	}

	return true;
}

/**
 * ice_vc_parse_fsub_pattern
 * @vf: pointer to the VF info
 * @fltr: virtual channel add cmd buffer
 * @conf: fsub filter configuration
 * @lkups_cnt: num of entries in the fsub lkups array
 *
 * Parse the virtual channel fsub's pattern and store them into @list
 * and @rule_info
 *
 * Return: 0 on success, and other on error.
 */
static int
ice_vc_parse_fsub_pattern(struct ice_vf *vf,
			  struct virtchnl_flow_sub *fltr,
			  struct ice_flow_sub_conf *conf,
			  u16 *lkups_cnt)
{
	struct ice_adv_rule_info *rule_info = &conf->fsub_fltr.rule_info;
	struct ice_adv_lkup_elem *list = conf->fsub_fltr.list;
	struct virtchnl_proto_hdrs *proto = &fltr->proto_hdrs;
	enum ice_sw_tunnel_type tun_type = ICE_NON_TUN;
	bool ipv6_valid = false;
	bool ipv4_valid = false;
	bool udp_valid = false;
	bool tcp_valid = false;
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_pf *pf;
	int i, count;
	u16 idx = 0;

	pf = vf->pf;
	dev = ice_pf_to_dev(pf);

	vsi = ice_get_main_vsi(pf);
	if (!vsi) {
		dev_dbg(dev, "Get main vsi for VF %d failed\n", vf->vf_id);
		return -EINVAL;
	}

	count = proto->count - VIRTCHNL_MAX_NUM_PROTO_HDRS;
	if (count > VIRTCHNL_MAX_NUM_PROTO_HDRS_W_MSK || count < 0) {
		dev_dbg(dev, "Invalid protocol count: 0x%x for VF %d\n",
			proto->count, vf->vf_id);
		return -EINVAL;
	}

	for (i = 0; i < count; i++) {
		struct virtchnl_proto_hdr_w_msk *hdr =
					&proto->proto_hdr_w_msk[i];
		struct vlan_hdr *vlan_spec, *vlan_mask;
		struct ipv6hdr *ip6_spec, *ip6_mask;
		struct ethhdr *eth_spec, *eth_mask;
		struct tcphdr *tcp_spec, *tcp_mask;
		struct udphdr *udp_spec, *udp_mask;
		struct iphdr *ip4_spec, *ip4_mask;

		switch (hdr->type) {
		case VIRTCHNL_PROTO_HDR_IPV4:
			ipv4_valid = true;
			break;
		case VIRTCHNL_PROTO_HDR_IPV6:
			ipv6_valid = true;
			break;
		case VIRTCHNL_PROTO_HDR_UDP:
			udp_valid = true;
			break;
		case VIRTCHNL_PROTO_HDR_TCP:
			tcp_valid = true;
			break;
		default:
			break;
		}

		if (is_zero_buffer(hdr->buffer_spec,
				   sizeof(hdr->buffer_spec)) ||
		    is_zero_buffer(hdr->buffer_mask,
				   sizeof(hdr->buffer_mask))) {
			if (hdr->type == VIRTCHNL_PROTO_HDR_ETH) {
				/**
				 * make sure to include PF's MAC address
				 * when adding FSUB filter
				 */
				struct ice_ether_hdr *h;
				struct ice_ether_hdr *m;

				list[idx].type = ICE_MAC_OFOS;

				h = &list[idx].h_u.eth_hdr;
				m = &list[idx].m_u.eth_hdr;

				ether_addr_copy(h->dst_addr,
						vsi->netdev->dev_addr);
				eth_broadcast_addr(m->dst_addr);

				idx++;
			}

			continue;
		}

		switch (hdr->type) {
		case VIRTCHNL_PROTO_HDR_ETH:
		{
			struct ice_ether_hdr *h;
			struct ice_ether_hdr *m;

			eth_spec = (struct ethhdr *)hdr->buffer_spec;
			eth_mask = (struct ethhdr *)hdr->buffer_mask;

			list[idx].type = ICE_MAC_OFOS;

			h = &list[idx].h_u.eth_hdr;
			m = &list[idx].m_u.eth_hdr;
			if (!is_zero_ether_addr(eth_mask->h_dest)) {
				if (!ether_addr_equal(eth_spec->h_dest,
						      vsi->netdev->dev_addr))
					return -EINVAL;

				ether_addr_copy(h->dst_addr,
						eth_spec->h_dest);
				ether_addr_copy(m->dst_addr,
						eth_mask->h_dest);
			} else {
				/**
				 * make sure to include PF's MAC address
				 * when adding FSUB filter
				 */
				ether_addr_copy(h->dst_addr,
						vsi->netdev->dev_addr);
				eth_broadcast_addr(m->dst_addr);
			}

			if (!is_zero_ether_addr(eth_mask->h_source)) {
				ether_addr_copy(h->src_addr,
						eth_spec->h_source);
				ether_addr_copy(m->src_addr,
						eth_mask->h_source);
			}

			idx++;

			if (eth_mask->h_proto) {
				list[idx].type = ICE_ETYPE_OL;
				list[idx].h_u.ethertype.ethtype_id =
					eth_spec->h_proto;
				list[idx].m_u.ethertype.ethtype_id =
					eth_mask->h_proto;
				idx++;
			}

			break;
		}
		case VIRTCHNL_PROTO_HDR_IPV4:
		{
			ip4_spec = (struct iphdr *)hdr->buffer_spec;
			ip4_mask = (struct iphdr *)hdr->buffer_mask;

			list[idx].type = ICE_IPV4_OFOS;

			if (ip4_mask->saddr) {
				list[idx].h_u.ipv4_hdr.src_addr =
						ip4_spec->saddr;
				list[idx].m_u.ipv4_hdr.src_addr =
						ip4_mask->saddr;
			}

			if (ip4_mask->daddr) {
				list[idx].h_u.ipv4_hdr.dst_addr =
						ip4_spec->daddr;
				list[idx].m_u.ipv4_hdr.dst_addr =
						ip4_mask->daddr;
			}

			if (ip4_mask->ttl) {
				list[idx].h_u.ipv4_hdr.time_to_live =
						ip4_spec->ttl;
				list[idx].m_u.ipv4_hdr.time_to_live =
						ip4_mask->ttl;
			}

			if (ip4_mask->protocol) {
				if ((ip4_spec->protocol &
				     ip4_mask->protocol) ==
				    ICE_IPV4_PROTO_NVGRE)
					tun_type = ICE_SW_TUN_AND_NON_TUN;

				list[idx].h_u.ipv4_hdr.protocol =
						ip4_spec->protocol;
				list[idx].m_u.ipv4_hdr.protocol =
						ip4_mask->protocol;
			}

			if (ip4_mask->tos) {
				list[idx].h_u.ipv4_hdr.tos =
						ip4_spec->tos;
				list[idx].m_u.ipv4_hdr.tos =
						ip4_mask->tos;
			}

			idx++;

			break;
		}
		case VIRTCHNL_PROTO_HDR_IPV6:
		{
			struct ice_ipv6_hdr *h;
			struct ice_ipv6_hdr *m;

			ip6_spec = (struct ipv6hdr *)hdr->buffer_spec;
			ip6_mask = (struct ipv6hdr *)hdr->buffer_mask;

			list[idx].type = ICE_IPV6_OFOS;

			h = &list[idx].h_u.ipv6_hdr;
			m = &list[idx].m_u.ipv6_hdr;

			if (!is_zero_buffer(ip6_mask->saddr.s6_addr,
					    sizeof(ip6_mask->saddr))) {
				memcpy(h->src_addr,
				       ip6_spec->saddr.in6_u.u6_addr8,
				       sizeof(ip6_spec->saddr));
				memcpy(m->src_addr,
				       ip6_mask->saddr.in6_u.u6_addr8,
				       sizeof(ip6_mask->saddr));
			}

			if (!is_zero_buffer(ip6_mask->daddr.s6_addr,
					    sizeof(ip6_mask->daddr))) {
				memcpy(h->dst_addr,
				       ip6_spec->daddr.in6_u.u6_addr8,
				       sizeof(ip6_spec->daddr));
				memcpy(m->dst_addr,
				       ip6_mask->daddr.in6_u.u6_addr8,
				       sizeof(ip6_mask->daddr));
			}

			if (ip6_mask->nexthdr) {
				h->next_hdr = ip6_spec->nexthdr;
				m->next_hdr = ip6_mask->nexthdr;
			}

			if (ip6_mask->hop_limit) {
				h->hop_limit = ip6_spec->hop_limit;
				m->hop_limit = ip6_mask->hop_limit;
			}

			if (ip6_mask->priority || ip6_mask->flow_lbl[0]) {
				struct ice_le_ver_tc_flow vtf_s, vtf_m;

				vtf_s.u.fld.version = 0;
				vtf_s.u.fld.flow_label = 0;
				vtf_s.u.fld.tc =
					((u8)(ip6_spec->priority) << 4) |
					(ip6_spec->flow_lbl[0] >> 4);
				h->be_ver_tc_flow = cpu_to_be32(vtf_s.u.val);

				vtf_m.u.fld.version = 0;
				vtf_m.u.fld.flow_label = 0;
				vtf_m.u.fld.tc =
					((u8)(ip6_mask->priority) << 4) |
					(ip6_mask->flow_lbl[0] >> 4);
				m->be_ver_tc_flow = cpu_to_be32(vtf_m.u.val);
			}

			idx++;

			break;
		}
		case VIRTCHNL_PROTO_HDR_UDP:
		{
			udp_spec = (struct udphdr *)hdr->buffer_spec;
			udp_mask = (struct udphdr *)hdr->buffer_mask;

			list[idx].type = ICE_UDP_ILOS;

			if (udp_mask->source) {
				list[idx].h_u.l4_hdr.src_port =
					udp_spec->source;
				list[idx].m_u.l4_hdr.src_port =
					udp_mask->source;
			}

			if (udp_mask->dest) {
				list[idx].h_u.l4_hdr.dst_port =
					udp_spec->dest;
				list[idx].m_u.l4_hdr.dst_port =
					udp_mask->dest;
			}

			idx++;

			break;
		}
		case VIRTCHNL_PROTO_HDR_TCP:
		{
			tcp_spec = (struct tcphdr *)hdr->buffer_spec;
			tcp_mask = (struct tcphdr *)hdr->buffer_mask;

			list[idx].type = ICE_TCP_IL;

			if (tcp_mask->source) {
				list[idx].h_u.l4_hdr.src_port =
					tcp_spec->source;
				list[idx].m_u.l4_hdr.src_port =
					tcp_mask->source;
			}

			if (tcp_mask->dest) {
				list[idx].h_u.l4_hdr.dst_port =
					tcp_spec->dest;
				list[idx].m_u.l4_hdr.dst_port =
					tcp_mask->dest;
			}

			idx++;

			break;
		}
		case VIRTCHNL_PROTO_HDR_S_VLAN:
		{
			vlan_spec = (struct vlan_hdr *)hdr->buffer_spec;
			vlan_mask = (struct vlan_hdr *)hdr->buffer_mask;

			list[idx].type = ICE_VLAN_OFOS;

			if (vlan_mask->h_vlan_TCI) {
				list[idx].h_u.vlan_hdr.vlan =
					vlan_spec->h_vlan_TCI;
				list[idx].m_u.vlan_hdr.vlan =
					vlan_mask->h_vlan_TCI;
			}

			idx++;

			break;
		}
		default:
			dev_err(dev, "Invalid header type 0x:%x for VF %d\n",
				hdr->type, vf->vf_id);
			return -EINVAL;
		}
	}

	if (tun_type == ICE_NON_TUN) {
		if (ipv4_valid && tcp_valid)
			tun_type = ICE_SW_IPV4_TCP;
		else if (ipv4_valid && udp_valid)
			tun_type = ICE_SW_IPV4_UDP;
		else if (ipv6_valid && tcp_valid)
			tun_type = ICE_SW_IPV6_TCP;
		else if (ipv6_valid && udp_valid)
			tun_type = ICE_SW_IPV6_UDP;
	}

	rule_info->tun_type = tun_type;
	rule_info->sw_act.flag |= ICE_FLTR_RX;
	rule_info->add_dir_lkup = true;
	rule_info->priority = ICE_FSUB_PRI_BASE - fltr->priority;

	*lkups_cnt = idx;

	return 0;
}

/**
 * ice_vc_parse_fsub_action
 * @vf: pointer to the VF info
 * @fltr: virtual channel add cmd buffer
 * @conf: fsub filter configuration
 *
 * Parse the virtual channel fsub's action and store them into @rule_info
 *
 * Return: 0 on success, and other on error.
 */
static int
ice_vc_parse_fsub_action(struct ice_vf *vf,
			 struct virtchnl_flow_sub *fltr,
			 struct ice_flow_sub_conf *conf)
{
	struct ice_adv_rule_info *rule_info = &conf->fsub_fltr.rule_info;
	struct virtchnl_filter_action_set *as = &fltr->actions;
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_vsi *vsi;
	u32 reg, rxq_id = 0;
	u16 base_queue = 0;
	int i;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		dev_dbg(dev, "Get vsi for VF %d failed\n", vf->vf_id);
		return -EINVAL;
	}

	if (as->count > VIRTCHNL_MAX_NUM_ACTIONS) {
		dev_dbg(dev, "Invalid action numbers: 0x%x for VF %d\n",
			as->count, vf->vf_id);
		return -EINVAL;
	}

	/* fsub filter default action is to VF */
	rule_info->sw_act.fltr_act = ICE_FWD_TO_VSI;

	for (i = 0; i < as->count; i++) {
		struct virtchnl_filter_action *action = &as->actions[i];

		switch (action->type) {
		case VIRTCHNL_ACTION_DROP:
			break;
		case VIRTCHNL_ACTION_QUEUE:
			rule_info->sw_act.fltr_act = ICE_FWD_TO_Q;
			rxq_id = action->act_conf.queue.index;
			break;
		case VIRTCHNL_ACTION_Q_REGION:
			rule_info->sw_act.fltr_act = ICE_FWD_TO_QGRP;
			rxq_id = action->act_conf.queue.index;
			rule_info->sw_act.qgrp_size =
					action->act_conf.queue.region;
			break;
		default:
			dev_dbg(dev, "Invalid action type 0x:%x for VF %d\n",
				action->type, vf->vf_id);
			break;
		}
	}

	rule_info->sw_act.vsi_handle = vsi->idx;
	rule_info->sw_act.src = rule_info->sw_act.vsi_handle;
	rule_info->sw_act.flag = ICE_FLTR_RX;

	if (rule_info->sw_act.fltr_act != ICE_FWD_TO_VSI) {
		reg = rd32(&vf->pf->hw, PFLAN_RX_QALLOC);
		if (reg & PFLAN_RX_QALLOC_VALID_M) {
			base_queue = reg & PFLAN_RX_QALLOC_FIRSTQ_M;
		} else {
			dev_dbg(dev, "Failed to get Rx base queue index");
			return -EINVAL;
		}

		rule_info->sw_act.fwd_id.q_id =
				vsi->rxq_map[rxq_id] + base_queue;
	}

	return 0;
}

/**
 * ice_vc_fsub_insert_entry
 * @vf: pointer to the VF info
 * @conf: SWITCH configuration for each filter
 * @id: pointer to ID value allocated by driver
 *
 * Insert SWITCH conf entry into list and allocate ID for this filter
 *
 * Return: 0 true success, and other on error.
 */
static int
ice_vc_fsub_insert_entry(struct ice_vf *vf,
			 struct ice_flow_sub_conf *conf,
			 u32 *id)
{
	struct ice_flow_sub_fltr *fsub_fltr = &conf->fsub_fltr;
	int i;

	/* alloc ID corresponding with conf */
	i = idr_alloc(&vf->fsub.fsub_rule_idr, conf, 0,
		      ICE_FSUB_MAX_FLTRS, GFP_KERNEL);
	if (i < 0)
		return i;
	*id = i;

	list_add(&fsub_fltr->fltr_node, &vf->fsub.fsub_rule_list);
	return 0;
}

/**
 * ice_vc_fsub_lookup_entry - lookup SWITCH conf entry by ID value
 * @vf: pointer to the VF info
 * @id: filter rule's ID
 *
 * Return: NULL on error, and other on success.
 */
static struct ice_flow_sub_conf *
ice_vc_fsub_lookup_entry(struct ice_vf *vf, u32 id)
{
	return idr_find(&vf->fsub.fsub_rule_idr, id);
}

/**
 * ice_vc_fsub_remove_entry - remove SWITCH conf entry by ID value
 * @vf: pointer to the VF info
 * @conf: SWITCH configuration for each filter
 * @id: filter rule's ID
 */
static void
ice_vc_fsub_remove_entry(struct ice_vf *vf,
			 struct ice_flow_sub_conf *conf,
			 u32 id)
{
	struct ice_flow_sub_fltr *fsub_fltr = &conf->fsub_fltr;

	idr_remove(&vf->fsub.fsub_rule_idr, id);
	list_del(&fsub_fltr->fltr_node);
}

/**
 * ice_vf_fsub_init - init SWITCH resource for VF
 * @vf: pointer to the VF info
 */
void ice_vf_fsub_init(struct ice_vf *vf)
{
	struct ice_vf_fsub *fsub = &vf->fsub;

	idr_init(&fsub->fsub_rule_idr);
	INIT_LIST_HEAD(&fsub->fsub_rule_list);
}

/**
 * ice_vc_flow_sub_fltr - subscribe flow filter for VF by the msg buffer
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Return: 0 on success, and other on error.
 */
int ice_vc_flow_sub_fltr(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_fsub_prgm_status status =
				VIRTCHNL_FSUB_FAILURE_RULE_INVALID;
	struct virtchnl_flow_sub *fltr = (struct virtchnl_flow_sub *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	u32 v_opcode = VIRTCHNL_OP_FLOW_SUBSCRIBE;
	struct virtchnl_flow_sub *stat = NULL;
	struct ice_flow_sub_conf *conf;
	struct ice_adv_lkup_elem *list;
	struct device *dev;
	struct ice_pf *pf;
	u16 lkups_cnt = 0;
	int lkups_num = 0;
	int ret;

	pf = vf->pf;
	dev = ice_pf_to_dev(pf);

	ret = ice_vc_fsub_param_check(vf, fltr->vsi_id);
	if (ret) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		dev_dbg(dev, "Parameter check for VF %d failed\n", vf->vf_id);
		goto err_exit;
	}

	conf = kzalloc(sizeof(*conf), GFP_KERNEL);
	if (!conf) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		dev_dbg(dev, "Alloc conf for VF %d failed\n", vf->vf_id);
		goto err_exit;
	}

	if (fltr->proto_hdrs.count >= VIRTCHNL_MAX_NUM_PROTO_HDRS) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		dev_dbg(dev, "Invalid protocol header count for VF %d\n",
			vf->vf_id);
		goto err_free_conf;
	}

	/**
	 * reserve one more memory slot for ETH
	 * which may consume 2 lookup items
	 */
	lkups_num = fltr->proto_hdrs.count - VIRTCHNL_MAX_NUM_PROTO_HDRS + 1;
	if (lkups_num < 1) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		dev_dbg(dev, "Invalid fsub filter for VF %d\n", vf->vf_id);
		goto err_free_conf;
	}

	list = kzalloc(lkups_num * sizeof(*list), GFP_KERNEL);
	if (!list) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		dev_dbg(dev, "Alloc list for VF %d failed\n", vf->vf_id);
		goto err_free_conf;
	}
	conf->fsub_fltr.list = list;

	if (!ice_vc_validate_pattern(vf, &fltr->proto_hdrs)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		status = VIRTCHNL_FSUB_FAILURE_RULE_INVALID;
		dev_dbg(dev, "Invalid FSUB filter from VF %d\n", vf->vf_id);
		goto err_free;
	}

	if (fltr->validate_only) {
		v_ret = VIRTCHNL_STATUS_SUCCESS;
		status = VIRTCHNL_FSUB_SUCCESS;
		goto err_free;
	}

	ret = ice_vc_parse_fsub_pattern(vf, fltr, conf, &lkups_cnt);
	if (ret) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		status = VIRTCHNL_FSUB_FAILURE_RULE_INVALID;
		dev_dbg(dev, "Parse FSUB pattern from VF %d\n", vf->vf_id);
		goto err_free;
	}

	ret = ice_vc_parse_fsub_action(vf, fltr, conf);
	if (ret) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		status = VIRTCHNL_FSUB_FAILURE_RULE_INVALID;
		dev_dbg(dev, "Parse FSUB action from VF %d\n", vf->vf_id);
		goto err_free;
	}

	ret = ice_add_adv_rule(&pf->hw, conf->fsub_fltr.list, lkups_cnt,
			       &conf->fsub_fltr.rule_info,
			       &conf->fsub_fltr.rule_data);
	if (ret) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		if (ret == -EEXIST)
			status = VIRTCHNL_FSUB_FAILURE_RULE_EXIST;
		else
			status = VIRTCHNL_FSUB_FAILURE_RULE_INVALID;
		dev_dbg(dev,
			"Subscribe flow rule failed from VF %d, ret = %08x\n",
			vf->vf_id, ret);
		goto err_free;
	}

	ret = ice_vc_fsub_insert_entry(vf, conf, &conf->flow_id);
	if (ret) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		status = VIRTCHNL_FSUB_FAILURE_RULE_NORESOURCE;
		dev_dbg(dev, "VF %d: insert FSUB list failed\n", vf->vf_id);
		goto err_free;
	}

	fltr->flow_id = conf->flow_id;

	ret = ice_vc_send_msg_to_vf(vf, v_opcode, v_ret, (u8 *)fltr,
				    sizeof(*fltr));

	return ret;

err_free:
	kfree(conf->fsub_fltr.list);
err_free_conf:
	kfree(conf);

err_exit:
	stat = kzalloc(sizeof(*stat), GFP_KERNEL);
	if (!stat) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		dev_dbg(dev, "Alloc stat for VF %d failed\n", vf->vf_id);
		ret = ice_vc_send_msg_to_vf(vf, v_opcode, v_ret, NULL, 0);
		return ret;
	}

	stat->status = status;
	ret = ice_vc_send_msg_to_vf(vf, v_opcode, v_ret, (u8 *)stat,
				    sizeof(*stat));

	kfree(stat);
	return ret;
}

/**
 * ice_vc_flow_unsub_fltr - unsubscribe flow filter for VF by the msg buffer
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Return: 0 on success, and other on error.
 */
int ice_vc_flow_unsub_fltr(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_fsub_prgm_status status =
				VIRTCHNL_FSUB_FAILURE_RULE_INVALID;
	struct virtchnl_flow_unsub *fltr = (struct virtchnl_flow_unsub *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	u32 v_opcode = VIRTCHNL_OP_FLOW_UNSUBSCRIBE;
	struct virtchnl_flow_unsub *stat = NULL;
	struct ice_flow_sub_conf *conf;
	struct device *dev;
	struct ice_pf *pf;
	int ret;

	pf = vf->pf;
	dev = ice_pf_to_dev(pf);

	ret = ice_vc_fsub_param_check(vf, fltr->vsi_id);
	if (ret) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		dev_dbg(dev, "Parameter check for VF %d failed\n", vf->vf_id);
		goto err_exit;
	}

	conf = ice_vc_fsub_lookup_entry(vf, fltr->flow_id);
	if (!conf) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		status = VIRTCHNL_FSUB_FAILURE_RULE_NONEXIST;
		dev_dbg(dev, "VF %d: FSUB invalid flow_id:0x%X\n",
			vf->vf_id, fltr->flow_id);
		goto err_exit;
	}

	/* remove advance rule */
	ret = ice_rem_adv_rule_by_id(&pf->hw, &conf->fsub_fltr.rule_data);
	if (ret) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		status = VIRTCHNL_FSUB_FAILURE_RULE_NORESOURCE;
		dev_dbg(dev, "Delete FSUB filter from VF %d\n", vf->vf_id);
		goto err_exit;
	}

	ice_vc_fsub_remove_entry(vf, conf, fltr->flow_id);

	ret = ice_vc_send_msg_to_vf(vf, v_opcode, v_ret, (u8 *)fltr,
				    sizeof(*fltr));

	kfree(conf->fsub_fltr.list);
	kfree(conf);
	return ret;

err_exit:
	stat = kzalloc(sizeof(*stat), GFP_KERNEL);
	if (!stat) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		dev_dbg(dev, "Alloc stat for VF %d failed\n", vf->vf_id);
		ret = ice_vc_send_msg_to_vf(vf, v_opcode, v_ret, NULL, 0);
		return ret;
	}

	stat->status = status;
	ret = ice_vc_send_msg_to_vf(vf, v_opcode, v_ret, (u8 *)stat,
				    sizeof(*stat));

	kfree(stat);
	return ret;
}

/**
 * ice_vf_fsub_exit - destroy SWITCH resource for VF
 * @vf: pointer to the VF info
 */
void ice_vf_fsub_exit(struct ice_vf *vf)
{
	struct ice_flow_sub_fltr *desc, *temp;
	struct ice_pf *pf = vf->pf;
	struct device *dev;

	dev = ice_pf_to_dev(pf);

	list_for_each_entry_safe(desc, temp, &vf->fsub.fsub_rule_list,
				 fltr_node) {
		struct ice_flow_sub_conf *conf = to_sub_conf_from_desc(desc);
		struct ice_rule_query_data *rule;
		int ret = 0;

		rule = &conf->fsub_fltr.rule_data;
		ret = ice_rem_adv_rule_by_id(&pf->hw, rule);
		if (ret) {
			dev_dbg(dev,
				"VF %d: Failed to unsub flow filter, rule_id = %d\n",
				vf->vf_id, rule->rule_id);
		}

		list_del(&desc->fltr_node);
		kfree(conf->fsub_fltr.list);
		kfree(conf);
	}

	idr_destroy(&vf->fsub.fsub_rule_idr);
}
