/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

/* ACL support for ice */

#include "ice.h"
#include "ice_lib.h"
#include "ice_flow.h"
#include "ice_fdir.h"

/* Default ACL Action priority */
#define ICE_ACL_ACT_PRIO	3

/* Number of action */
#define ICE_ACL_NUM_ACT		1

/**
 * ice_acl_set_ip4_addr_seg
 * @seg: flow segment for programming
 *
 * Set the IPv4 source and destination address mask for the given flow segment
 */
static void ice_acl_set_ip4_addr_seg(struct ice_flow_seg_info *seg)
{
	u16 val_loc, mask_loc;

	/* IP source address */
	val_loc = offsetof(struct ice_fdir_fltr, ip.v4.src_ip);
	mask_loc = offsetof(struct ice_fdir_fltr, mask.v4.src_ip);

	ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_SA, val_loc,
			 mask_loc, ICE_FLOW_FLD_OFF_INVAL, false);

	/* IP destination address */
	val_loc = offsetof(struct ice_fdir_fltr, ip.v4.dst_ip);
	mask_loc = offsetof(struct ice_fdir_fltr, mask.v4.dst_ip);

	ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_DA, val_loc,
			 mask_loc, ICE_FLOW_FLD_OFF_INVAL, false);
}

/**
 * ice_acl_set_ip4_port_seg
 * @seg: flow segment for programming
 * @l4_proto: Layer 4 protocol to program
 *
 * Set the source and destination port for the given flow segment based on the
 * provided layer 4 protocol
 */
static int
ice_acl_set_ip4_port_seg(struct ice_flow_seg_info *seg,
			 enum ice_flow_seg_hdr l4_proto)
{
	enum ice_flow_field src_port, dst_port;
	u16 val_loc, mask_loc;
	int err;

	err = ice_ntuple_l4_proto_to_port(l4_proto, &src_port, &dst_port);
	if (err)
		return err;

	/* Layer 4 source port */
	val_loc = offsetof(struct ice_fdir_fltr, ip.v4.src_port);
	mask_loc = offsetof(struct ice_fdir_fltr, mask.v4.src_port);

	ice_flow_set_fld(seg, src_port, val_loc, mask_loc,
			 ICE_FLOW_FLD_OFF_INVAL, false);

	/* Layer 4 destination port */
	val_loc = offsetof(struct ice_fdir_fltr, ip.v4.dst_port);
	mask_loc = offsetof(struct ice_fdir_fltr, mask.v4.dst_port);

	ice_flow_set_fld(seg, dst_port, val_loc, mask_loc,
			 ICE_FLOW_FLD_OFF_INVAL, false);

	return 0;
}

/**
 * ice_acl_set_ip4_seg
 * @seg: flow segment for programming
 * @tcp_ip4_spec: mask data from ethtool
 * @l4_proto: Layer 4 protocol to program
 *
 * Set the mask data into the flow segment to be used to program HW
 * table based on provided L4 protocol for IPv4
 */
static int
ice_acl_set_ip4_seg(struct ice_flow_seg_info *seg,
		    struct ethtool_tcpip4_spec *tcp_ip4_spec,
		    enum ice_flow_seg_hdr l4_proto)
{
	int err;

	err = ice_ntuple_check_ip4_seg(tcp_ip4_spec);
	if (err)
		return err;

	ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_IPV4 | l4_proto);
	ice_acl_set_ip4_addr_seg(seg);

	return ice_acl_set_ip4_port_seg(seg, l4_proto);
}

/**
 * ice_acl_set_ip4_usr_seg
 * @seg: flow segment for programming
 * @usr_ip4_spec: ethtool userdef packet offset
 *
 * Set the offset data into the flow segment to be used to program HW
 * table for IPv4
 */
static int
ice_acl_set_ip4_usr_seg(struct ice_flow_seg_info *seg,
			struct ethtool_usrip4_spec *usr_ip4_spec)
{
	int err;

	err = ice_ntuple_check_ip4_usr_seg(usr_ip4_spec);
	if (err)
		return err;

	ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_IPV4);
	ice_acl_set_ip4_addr_seg(seg);

	return 0;
}

/**
 * ice_acl_set_ether_seg
 * @seg: flow segment for programming
 * @eth_spec: mask data from ethtool
 */
static int
ice_acl_set_ether_seg(struct ice_flow_seg_info *seg,
		      struct ethhdr *eth_spec)
{
	u16 val_loc, mask_loc;

	ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_ETH);

	val_loc = offsetof(struct ice_fdir_fltr, eth.h_proto);
	mask_loc = offsetof(struct ice_fdir_fltr, eth_mask.h_proto);
	ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_ETH_TYPE, val_loc, mask_loc,
			 ICE_FLOW_FLD_OFF_INVAL, false);

	val_loc = offsetof(struct ice_fdir_fltr, eth.h_source);
	mask_loc = offsetof(struct ice_fdir_fltr, eth_mask.h_source);
	ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_ETH_SA, val_loc, mask_loc,
			 ICE_FLOW_FLD_OFF_INVAL, false);

	val_loc = offsetof(struct ice_fdir_fltr, eth.h_dest);
	mask_loc = offsetof(struct ice_fdir_fltr, eth_mask.h_dest);
	ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_ETH_DA, val_loc,
			 mask_loc, ICE_FLOW_FLD_OFF_INVAL, false);

	return 0;
}

/**
 * ice_acl_check_input_set - Checks that a given ACL input set is valid
 * @pf: ice PF structure
 * @fsp: pointer to ethtool Rx flow specification
 *
 * Returns 0 on success and negative values for failure
 */
static int
ice_acl_check_input_set(struct ice_pf *pf, struct ethtool_rx_flow_spec *fsp)
{
	struct ice_fd_hw_prof *hw_prof = NULL;
	struct ice_flow_prof *prof = NULL;
	struct ice_flow_seg_info *old_seg;
	struct ice_flow_seg_info *seg;
	enum ice_fltr_ptype fltr_type;
	struct ice_hw *hw = &pf->hw;
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);
	seg = devm_kzalloc(dev, sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return -ENOMEM;

	switch (fsp->flow_type & ~FLOW_EXT) {
	case TCP_V4_FLOW:
		err = ice_acl_set_ip4_seg(seg, &fsp->m_u.tcp_ip4_spec,
					  ICE_FLOW_SEG_HDR_TCP);
		break;
	case UDP_V4_FLOW:
		err = ice_acl_set_ip4_seg(seg, &fsp->m_u.tcp_ip4_spec,
					  ICE_FLOW_SEG_HDR_UDP);
		break;
	case SCTP_V4_FLOW:
		err = ice_acl_set_ip4_seg(seg, &fsp->m_u.tcp_ip4_spec,
					  ICE_FLOW_SEG_HDR_SCTP);
		break;
	case IPV4_USER_FLOW:
		err = ice_acl_set_ip4_usr_seg(seg, &fsp->m_u.usr_ip4_spec);
		break;
	case ETHER_FLOW:
		if (!fsp->m_ext.vlan_tci && !fsp->m_ext.vlan_etype) {
			err = ice_acl_set_ether_seg(seg, &fsp->m_u.ether_spec);
			break;
		}

		dev_warn(dev, "VLAN and masks are not allowed in one filter");
		err = -EOPNOTSUPP;

		break;
	default:
		err = -EOPNOTSUPP;
	}
	if (err)
		goto err_exit;

	fltr_type = ice_ethtool_flow_to_fltr(fsp->flow_type & ~FLOW_EXT);

	if (!hw->acl_prof) {
		hw->acl_prof = devm_kcalloc(dev, ICE_FLTR_PTYPE_MAX,
					    sizeof(*hw->acl_prof), GFP_KERNEL);
		if (!hw->acl_prof) {
			err = -ENOMEM;
			goto err_exit;
		}
	}
	if (!hw->acl_prof[fltr_type]) {
		hw->acl_prof[fltr_type] = devm_kzalloc(dev,
						       sizeof(**hw->acl_prof),
						       GFP_KERNEL);
		if (!hw->acl_prof[fltr_type]) {
			err = -ENOMEM;
			goto err_acl_prof_exit;
		}
		hw->acl_prof[fltr_type]->cnt = 0;
	}

	hw_prof = hw->acl_prof[fltr_type];
	old_seg = hw_prof->fdir_seg[0];
	if (old_seg) {
		/* This flow_type already has an input set.
		 * If it matches the requested input set then we are
		 * done. If it's different then it's an error.
		 */
		if (!memcmp(old_seg, seg, sizeof(*seg))) {
			devm_kfree(dev, seg);
			return 0;
		}

		err = -EINVAL;
		goto err_acl_prof_flow_exit;
	}

	/* Adding a profile for the given flow specification with no
	 * actions (NULL) and zero actions 0.
	 */
	err = ice_flow_add_prof(hw, ICE_BLK_ACL, ICE_FLOW_RX, seg, 1,
				NULL, 0, &prof);
	if (err)
		goto err_exit;

	hw_prof->fdir_seg[0] = seg;
	hw_prof->prof_id[0] = prof->id;
	return 0;

err_acl_prof_flow_exit:
	devm_kfree(dev, hw->acl_prof[fltr_type]);
err_acl_prof_exit:
	devm_kfree(dev, hw->acl_prof);
err_exit:
	devm_kfree(dev, seg);

	return err;
}

/**
 * ice_acl_add_rule_ethtool - Adds an ACL rule
 * @vsi: pointer to target VSI
 * @cmd: command to add or delete ACL rule
 *
 * Returns 0 on success and negative values for failure
 */
int ice_acl_add_rule_ethtool(struct ice_vsi *vsi, struct ethtool_rxnfc *cmd)
{
	struct ice_flow_action acts[ICE_ACL_NUM_ACT];
	struct ethtool_rx_flow_spec *fsp;
	struct ice_fd_hw_prof *hw_prof;
	struct ice_fdir_fltr *input;
	enum ice_fltr_ptype flow;
	struct device *dev;
	struct ice_pf *pf;
	struct ice_hw *hw;
	u64 entry_h = 0;
	int act_cnt;
	int ret;

	if (!vsi || !cmd)
		return -EINVAL;

	pf = vsi->back;
	hw = &pf->hw;
	dev = ice_pf_to_dev(pf);

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	ret = ice_acl_check_input_set(pf, fsp);
	if (ret)
		return ret;

	/* Add new rule */
	input = devm_kzalloc(dev, sizeof(*input), GFP_KERNEL);
	if (!input)
		return -ENOMEM;

	ret = ice_ntuple_set_input_set(vsi, ICE_BLK_ACL, fsp, input);
	if (ret)
		goto free_input;

	mutex_lock(&hw->fdir_fltr_lock);
	if (ice_fdir_is_dup_fltr(hw, input)) {
		ret = -EINVAL;
		goto release_lock;
	}
	mutex_unlock(&hw->fdir_fltr_lock);

	memset(&acts, 0, sizeof(acts));
	act_cnt = 1;
	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
		acts[0].type = ICE_FLOW_ACT_DROP;
		acts[0].data.acl_act.mdid = ICE_MDID_RX_PKT_DROP;
		acts[0].data.acl_act.prio = ICE_ACL_ACT_PRIO;
		acts[0].data.acl_act.value = cpu_to_le16(0x1);
	} else {
		acts[0].type = ICE_FLOW_ACT_FWD_QUEUE;
		acts[0].data.acl_act.mdid = ICE_MDID_RX_DST_Q;
		acts[0].data.acl_act.prio = ICE_ACL_ACT_PRIO;
		acts[0].data.acl_act.value = cpu_to_le16(input->q_index);
	}

	flow = ice_ethtool_flow_to_fltr(fsp->flow_type & ~FLOW_EXT);
	hw_prof = hw->acl_prof[flow];

	ret = ice_flow_add_entry(hw, ICE_BLK_ACL, hw_prof->prof_id[0],
				 fsp->location, vsi->idx, ICE_FLOW_PRIO_NORMAL,
				 input, acts, act_cnt, &entry_h);
	if (ret) {
		dev_err(dev, "Could not add flow entry %d\n", flow);
		goto free_input;
	}

	if (!hw_prof->cnt || vsi->idx != hw_prof->vsi_h[hw_prof->cnt - 1]) {
		hw_prof->vsi_h[hw_prof->cnt] = vsi->idx;
		hw_prof->entry_h[hw_prof->cnt++][0] = entry_h;
	}

	input->acl_fltr = true;
	/* input struct is added to the HW filter list */
	mutex_lock(&hw->fdir_fltr_lock);
	ice_ntuple_update_list_entry(pf, input, fsp->location);

release_lock:
	mutex_unlock(&hw->fdir_fltr_lock);
free_input:
	if (ret)
		devm_kfree(dev, input);

	return ret;
}
