// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

#include <linux/if_ether.h>
#include "ice_vsi_vlan_ops.h"
#include "ice_type.h"
#include "ice_fltr.h"
#include "ice_lib.h"
#include "ice.h"

static void print_invalid_tpid(struct ice_vsi *vsi, u16 tpid)
{
	dev_err(ice_pf_to_dev(vsi->back), "%s %d specified invalid VLAN tpid 0x%04x\n",
		ice_vsi_type_str(vsi->type), vsi->idx, tpid);
}

/**
 * add_vlan - default add VLAN implementation for all VSI types
 * @vsi: VSI being configured
 * @vlan: VLAN filter to add
 */
static int add_vlan(struct ice_vsi *vsi, struct ice_vlan vlan)
{
	int err = 0;

	if (vlan.tpid != ETH_P_8021Q) {
		print_invalid_tpid(vsi, vlan.tpid);
		return -EINVAL;
	}

	if (!ice_fltr_add_vlan(vsi, vlan.vid, vlan.fwd_act)) {
		vsi->num_vlan++;
	} else {
		err = -ENODEV;
		dev_err(ice_pf_to_dev(vsi->back), "Failure Adding VLAN %d on VSI %i\n",
			vlan.vid, vsi->vsi_num);
	}

	return err;
}

/**
 * del_vlan - default del VLAN implementation for all VSI types
 * @vsi: VSI being configured
 * @vlan: VLAN filter to delete
 */
static int del_vlan(struct ice_vsi *vsi, struct ice_vlan vlan)
{
	struct ice_pf *pf = vsi->back;
	enum ice_status status;
	struct device *dev;
	int err = 0;

	dev = ice_pf_to_dev(pf);

	if (vlan.tpid != ETH_P_8021Q) {
		print_invalid_tpid(vsi, vlan.tpid);
		return -EINVAL;
	}

	status = ice_fltr_remove_vlan(vsi, vlan.vid, vlan.fwd_act);
	if (!status) {
		vsi->num_vlan--;
	} else if (status != ICE_ERR_DOES_NOT_EXIST) {
		dev_err(dev, "Error removing VLAN %d on VSI %i error: %s\n",
			vlan.vid, vsi->vsi_num, ice_stat_str(status));
		err = ice_status_to_errno(status);
	}

	return err;
}

static int ena_stripping(struct ice_vsi *vsi, const u16 tpid)
{
	if (tpid != ETH_P_8021Q) {
		print_invalid_tpid(vsi, tpid);
		return -EINVAL;
	}

	return ice_vsi_manage_vlan_stripping(vsi, true);
}

static int dis_stripping(struct ice_vsi *vsi)
{
	return ice_vsi_manage_vlan_stripping(vsi, false);
}

static int ena_insertion(struct ice_vsi *vsi, const u16 tpid)
{
	if (tpid != ETH_P_8021Q) {
		print_invalid_tpid(vsi, tpid);
		return -EINVAL;
	}

	return ice_vsi_manage_vlan_insertion(vsi);
}

static int dis_insertion(struct ice_vsi *vsi)
{
	return ice_vsi_manage_vlan_insertion(vsi);
}

/**
 * ice_vsi_manage_pvid - Enable or disable port VLAN for VSI
 * @vsi: the VSI to update
 * @pvid_info: VLAN ID and QoS used to set the PVID VSI context field
 * @enable: true for enable PVID false for disable
 */
static int ice_vsi_manage_pvid(struct ice_vsi *vsi, u16 pvid_info, bool enable)
{
	struct ice_hw *hw = &vsi->back->hw;
	struct ice_aqc_vsi_props *info;
	struct ice_vsi_ctx *ctxt;
	enum ice_status status;
	int ret = 0;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->info = vsi->info;
	info = &ctxt->info;
	if (enable) {
		info->vlan_flags = ICE_AQ_VSI_VLAN_MODE_UNTAGGED |
			ICE_AQ_VSI_PVLAN_INSERT_PVID |
			ICE_AQ_VSI_VLAN_EMOD_STR;
		info->sw_flags2 |= ICE_AQ_VSI_SW_FLAG_RX_VLAN_PRUNE_ENA;
	} else {
		info->vlan_flags = ICE_AQ_VSI_VLAN_EMOD_NOTHING |
			ICE_AQ_VSI_VLAN_MODE_ALL;
		info->sw_flags2 &= ~ICE_AQ_VSI_SW_FLAG_RX_VLAN_PRUNE_ENA;
	}

	info->pvid = cpu_to_le16(pvid_info);
	info->valid_sections = cpu_to_le16(ICE_AQ_VSI_PROP_VLAN_VALID |
					   ICE_AQ_VSI_PROP_SW_VALID);

	status = ice_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_info(ice_hw_to_dev(hw), "update VSI for port VLAN failed, err %s aq_err %s\n",
			 ice_stat_str(status),
			 ice_aq_str(hw->adminq.sq_last_status));
		ret = -EIO;
		goto out;
	}

	vsi->info.vlan_flags = info->vlan_flags;
	vsi->info.sw_flags2 = info->sw_flags2;
	vsi->info.pvid = info->pvid;
out:
	kfree(ctxt);
	return ret;
}

static int set_port_vlan(struct ice_vsi *vsi, struct ice_vlan vlan)
{
	u16 port_vlan_info;

	if (vlan.tpid != ETH_P_8021Q)
		return -EINVAL;

	if (vlan.prio > 7)
		return -EINVAL;

	port_vlan_info = vlan.vid | (vlan.prio << VLAN_PRIO_SHIFT);

	return ice_vsi_manage_pvid(vsi, port_vlan_info, true);
}

void ice_vsi_init_vlan_ops(struct ice_vsi *vsi)
{
	vsi->vlan_ops.add_vlan = add_vlan;
	vsi->vlan_ops.del_vlan = del_vlan;
	vsi->vlan_ops.ena_stripping = ena_stripping;
	vsi->vlan_ops.dis_stripping = dis_stripping;
	vsi->vlan_ops.ena_insertion = ena_insertion;
	vsi->vlan_ops.dis_insertion = dis_insertion;
	vsi->vlan_ops.set_port_vlan = set_port_vlan;
}
