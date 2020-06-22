// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

#include "ice.h"
#include "ice_base.h"
#include "ice_lib.h"

/**
 * ice_validate_vf_id - helper to check if VF ID is valid
 * @pf: pointer to the PF structure
 * @vf_id: the ID of the VF to check
 */
static int ice_validate_vf_id(struct ice_pf *pf, int vf_id)
{
	if (vf_id >= pf->num_alloc_vfs) {
		dev_err(ice_pf_to_dev(pf), "Invalid VF ID: %d\n", vf_id);
		return -EINVAL;
	}
	return 0;
}

/**
 * ice_check_vf_init - helper to check if VF init complete
 * @pf: pointer to the PF structure
 * @vf: the pointer to the VF to check
 */
static int ice_check_vf_init(struct ice_pf *pf, struct ice_vf *vf)
{
	if (!test_bit(ICE_VF_STATE_INIT, vf->vf_states)) {
		dev_err(ice_pf_to_dev(pf), "VF ID: %d in reset. Try again.\n",
			vf->vf_id);
		return -EBUSY;
	}
	return 0;
}

/**
 * ice_err_to_virt_err - translate errors for VF return code
 * @ice_err: error return code
 */
static enum virtchnl_status_code ice_err_to_virt_err(enum ice_status ice_err)
{
	switch (ice_err) {
	case ICE_SUCCESS:
		return VIRTCHNL_STATUS_SUCCESS;
	case ICE_ERR_BAD_PTR:
	case ICE_ERR_INVAL_SIZE:
	case ICE_ERR_DEVICE_NOT_SUPPORTED:
	case ICE_ERR_PARAM:
	case ICE_ERR_CFG:
		return VIRTCHNL_STATUS_ERR_PARAM;
	case ICE_ERR_NO_MEMORY:
		return VIRTCHNL_STATUS_ERR_NO_MEMORY;
	case ICE_ERR_NOT_READY:
	case ICE_ERR_RESET_FAILED:
	case ICE_ERR_FW_API_VER:
	case ICE_ERR_AQ_ERROR:
	case ICE_ERR_AQ_TIMEOUT:
	case ICE_ERR_AQ_FULL:
	case ICE_ERR_AQ_NO_WORK:
	case ICE_ERR_AQ_EMPTY:
		return VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
	default:
		return VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
	}
}

/**
 * ice_vc_vf_broadcast - Broadcast a message to all VFs on PF
 * @pf: pointer to the PF structure
 * @v_opcode: operation code
 * @v_retval: return value
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 */
static void
ice_vc_vf_broadcast(struct ice_pf *pf, enum virtchnl_ops v_opcode,
		    enum virtchnl_status_code v_retval, u8 *msg, u16 msglen)
{
	struct ice_hw *hw = &pf->hw;
	int i;

	ice_for_each_vf(pf, i) {
		struct ice_vf *vf = &pf->vf[i];

		/* Not all vfs are enabled so skip the ones that are not */
		if (!test_bit(ICE_VF_STATE_INIT, vf->vf_states) &&
		    !test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states))
			continue;

		/* Ignore return value on purpose - a given VF may fail, but
		 * we need to keep going and send to all of them
		 */
		ice_aq_send_msg_to_vf(hw, vf->vf_id, v_opcode, v_retval, msg,
				      msglen, NULL);
	}
}

/**
 * ice_set_pfe_link - Set the link speed/status of the virtchnl_pf_event
 * @vf: pointer to the VF structure
 * @pfe: pointer to the virtchnl_pf_event to set link speed/status for
 * @ice_link_speed: link speed specified by ICE_AQ_LINK_SPEED_*
 * @link_up: whether or not to set the link up/down
 */
static void
ice_set_pfe_link(struct ice_vf *vf, struct virtchnl_pf_event *pfe,
		 int ice_link_speed, bool link_up)
{
	if (vf->driver_caps & VIRTCHNL_VF_CAP_ADV_LINK_SPEED) {
		pfe->event_data.link_event_adv.link_status = link_up;
		/* Speed in Mbps */
		pfe->event_data.link_event_adv.link_speed =
			ice_conv_link_speed_to_virtchnl(true, ice_link_speed);
	} else {
		pfe->event_data.link_event.link_status = link_up;
		/* Legacy method for virtchnl link speeds */
		pfe->event_data.link_event.link_speed =
			(enum virtchnl_link_speed)
			ice_conv_link_speed_to_virtchnl(false, ice_link_speed);
	}
}

/**
 * ice_vf_has_no_qs_ena - check if the VF has any Rx or Tx queues enabled
 * @vf: the VF to check
 *
 * Returns true if the VF has no Rx and no Tx queues enabled and returns false
 * otherwise
 */
static bool ice_vf_has_no_qs_ena(struct ice_vf *vf)
{
	return (!bitmap_weight(vf->rxq_ena, ICE_MAX_RSS_QS_PER_VF) &&
		!bitmap_weight(vf->txq_ena, ICE_MAX_RSS_QS_PER_VF));
}

/**
 * ice_is_vf_link_up - check if the VF's link is up
 * @vf: VF to check if link is up
 */
static bool ice_is_vf_link_up(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;

	if (ice_check_vf_init(pf, vf))
		return false;

	if (test_bit(__ICE_BAD_EEPROM, pf->state))
		return false;

	if (ice_vf_has_no_qs_ena(vf))
		return false;
	else if (vf->link_forced)
		return vf->link_up;
	else
		return pf->hw.port_info->phy.link_info.link_info &
			ICE_AQ_LINK_UP;
}

/**
 * ice_vc_notify_vf_link_state - Inform a VF of link status
 * @vf: pointer to the VF structure
 *
 * send a link status message to a single VF
 */
static void ice_vc_notify_vf_link_state(struct ice_vf *vf)
{
	struct virtchnl_pf_event pfe = { 0 };
	struct ice_hw *hw = &vf->pf->hw;


	pfe.event = VIRTCHNL_EVENT_LINK_CHANGE;
	pfe.severity = PF_EVENT_SEVERITY_INFO;

	if (ice_is_vf_link_up(vf))
		ice_set_pfe_link(vf, &pfe,
				 hw->port_info->phy.link_info.link_speed, true);
	else
		ice_set_pfe_link(vf, &pfe, ICE_AQ_LINK_SPEED_UNKNOWN, false);

	ice_aq_send_msg_to_vf(hw, vf->vf_id, VIRTCHNL_OP_EVENT,
			      VIRTCHNL_STATUS_SUCCESS, (u8 *)&pfe,
			      sizeof(pfe), NULL);
}

/**
 * ice_free_vf_res - Free a VF's resources
 * @vf: pointer to the VF info
 */
static void ice_free_vf_res(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	int i, last_vector_idx;

	/* First, disable VF's configuration API to prevent OS from
	 * accessing the VF's VSI after it's freed or invalidated.
	 */
	clear_bit(ICE_VF_STATE_INIT, vf->vf_states);

	/* free VSI and disconnect it from the parent uplink */
	if (vf->lan_vsi_idx) {
		ice_vsi_release(pf->vsi[vf->lan_vsi_idx]);
		vf->lan_vsi_idx = 0;
		vf->lan_vsi_num = 0;
		vf->num_mac = 0;
	}

	last_vector_idx = vf->first_vector_idx + pf->num_vf_msix - 1;

	/* clear VF MDD event information */
	memset(&vf->mdd_tx_events, 0, sizeof(vf->mdd_tx_events));
	memset(&vf->mdd_rx_events, 0, sizeof(vf->mdd_rx_events));

	/* do the accounting and remove additional ADQ VSI's */
	if (vf->adq_enabled && vf->ch[0].vsi_idx) {
		u8 tc;

		for (tc = 0; tc < vf->num_tc; tc++) {
			/* At this point VSI0 is already released so don't
			 * release it again and only clear their values in
			 * structure variables
			 */
			if (tc)
				ice_vsi_release(pf->vsi[vf->ch[tc].vsi_idx]);
			vf->ch[tc].vsi_idx = 0;
			vf->ch[tc].vsi_num = 0;
		}
	}

	/* Disable interrupts so that VF starts in a known state */
	for (i = vf->first_vector_idx; i <= last_vector_idx; i++) {
		wr32(&pf->hw, GLINT_DYN_CTL(i), GLINT_DYN_CTL_CLEARPBA_M);
		ice_flush(&pf->hw);
	}
	/* reset some of the state variables keeping track of the resources */
	clear_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states);
	clear_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states);
}

/**
 * ice_dis_vf_mappings
 * @vf: pointer to the VF structure
 */
static void ice_dis_vf_mappings(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	int first, last, v;
	struct ice_hw *hw;

	hw = &pf->hw;
	vsi = pf->vsi[vf->lan_vsi_idx];

	dev = ice_pf_to_dev(pf);
	wr32(hw, VPINT_ALLOC(vf->vf_id), 0);
	wr32(hw, VPINT_ALLOC_PCI(vf->vf_id), 0);

	first = vf->first_vector_idx;
	last = first + pf->num_vf_msix - 1;
	for (v = first; v <= last; v++) {
		u32 reg;

		reg = (((1 << GLINT_VECT2FUNC_IS_PF_S) &
			GLINT_VECT2FUNC_IS_PF_M) |
		       ((hw->pf_id << GLINT_VECT2FUNC_PF_NUM_S) &
			GLINT_VECT2FUNC_PF_NUM_M));
		wr32(hw, GLINT_VECT2FUNC(v), reg);
	}

	if (vsi->tx_mapping_mode == ICE_VSI_MAP_CONTIG)
		wr32(hw, VPLAN_TX_QBASE(vf->vf_id), 0);
	else
		dev_err(dev, "Scattered mode for VF Tx queues is not yet implemented\n");

	if (vsi->rx_mapping_mode == ICE_VSI_MAP_CONTIG)
		wr32(hw, VPLAN_RX_QBASE(vf->vf_id), 0);
	else
		dev_err(dev, "Scattered mode for VF Rx queues is not yet implemented\n");
}

/**
 * ice_sriov_free_msix_res - Reset/free any used MSIX resources
 * @pf: pointer to the PF structure
 *
 * Since no MSIX entries are taken from the pf->irq_tracker then just clear
 * the pf->sriov_base_vector.
 *
 * Returns 0 on success, and -EINVAL on error.
 */
static int ice_sriov_free_msix_res(struct ice_pf *pf)
{
	struct ice_res_tracker *res;

	if (!pf)
		return -EINVAL;

	res = pf->irq_tracker;
	if (!res)
		return -EINVAL;

	/* give back irq_tracker resources used */
	WARN_ON(pf->sriov_base_vector < res->num_entries);

	pf->sriov_base_vector = 0;

	return 0;
}

/**
 * ice_set_vf_state_qs_dis - Set VF queues state to disabled
 * @vf: pointer to the VF structure
 */
void ice_set_vf_state_qs_dis(struct ice_vf *vf)
{
	/* Clear Rx/Tx enabled queues flag */
	bitmap_zero(vf->txq_ena, ICE_MAX_RSS_QS_PER_VF);
	bitmap_zero(vf->rxq_ena, ICE_MAX_RSS_QS_PER_VF);
	clear_bit(ICE_VF_STATE_QS_ENA, vf->vf_states);
}

/**
 * ice_dis_vf_qs - Disable the VF queues
 * @vf: pointer to the VF structure
 */
static void ice_dis_vf_qs(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	vsi = pf->vsi[vf->lan_vsi_idx];

	ice_vsi_stop_lan_tx_rings(vsi, ICE_NO_RESET, vf->vf_id);
	ice_vsi_stop_all_rx_rings(vsi);
	ice_set_vf_state_qs_dis(vf);
}

/**
 * ice_free_vfs - Free all VFs
 * @pf: pointer to the PF structure
 */
void ice_free_vfs(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	int tmp, i;

	if (!pf->vf)
		return;

	while (test_and_set_bit(__ICE_VF_DIS, pf->state))
		usleep_range(1000, 2000);

	/* Avoid wait time by stopping all VFs at the same time */
	ice_for_each_vf(pf, i)
		if (test_bit(ICE_VF_STATE_QS_ENA, pf->vf[i].vf_states))
			ice_dis_vf_qs(&pf->vf[i]);

	/* Disable IOV before freeing resources. This lets any VF drivers
	 * running in the host get themselves cleaned up before we yank
	 * the carpet out from underneath their feet.
	 */
	if (!pci_vfs_assigned(pf->pdev))
		pci_disable_sriov(pf->pdev);
	else
		dev_warn(dev, "VFs are assigned - not disabling SR-IOV\n");

	tmp = pf->num_alloc_vfs;
	pf->num_vf_qps = 0;
	pf->num_alloc_vfs = 0;
	for (i = 0; i < tmp; i++) {
		if (test_bit(ICE_VF_STATE_INIT, pf->vf[i].vf_states)) {
			/* disable VF qp mappings and set VF disable state */
			ice_dis_vf_mappings(&pf->vf[i]);
			set_bit(ICE_VF_STATE_DIS, pf->vf[i].vf_states);
			ice_free_vf_res(&pf->vf[i]);
		}
	}

	if (ice_sriov_free_msix_res(pf))
		dev_err(dev, "Failed to free MSIX resources used by SR-IOV\n");

	devm_kfree(dev, pf->vf);
	pf->vf = NULL;

	/* This check is for when the driver is unloaded while VFs are
	 * assigned. Setting the number of VFs to 0 through sysfs is caught
	 * before this function ever gets called.
	 */
	if (!pci_vfs_assigned(pf->pdev)) {
		int vf_id;

		/* Acknowledge VFLR for all VFs. Without this, VFs will fail to
		 * work correctly when SR-IOV gets re-enabled.
		 */
		for (vf_id = 0; vf_id < tmp; vf_id++) {
			u32 reg_idx, bit_idx;

			reg_idx = (hw->func_caps.vf_base_id + vf_id) / 32;
			bit_idx = (hw->func_caps.vf_base_id + vf_id) % 32;
			wr32(hw, GLGEN_VFLRSTAT(reg_idx), BIT(bit_idx));
		}
	}
	clear_bit(__ICE_VF_DIS, pf->state);
	clear_bit(ICE_FLAG_SRIOV_ENA, pf->flags);
}

/**
 * ice_trigger_vf_reset - Reset a VF on HW
 * @vf: pointer to the VF structure
 * @is_vflr: true if VFLR was issued, false if not
 * @is_pfr: true if the reset was triggered due to a previous PFR
 *
 * Trigger hardware to start a reset for a particular VF. Expects the caller
 * to wait the proper amount of time to allow hardware to reset the VF before
 * it cleans up and restores VF functionality.
 */
static void ice_trigger_vf_reset(struct ice_vf *vf, bool is_vflr, bool is_pfr)
{
	struct ice_pf *pf = vf->pf;
	u32 reg, reg_idx, bit_idx;
	struct device *dev;
	struct ice_hw *hw;
	int vf_abs_id, i;

	dev = ice_pf_to_dev(pf);
	hw = &pf->hw;
	vf_abs_id = vf->vf_id + hw->func_caps.vf_base_id;

	/* Inform VF that it is no longer active, as a warning */
	clear_bit(ICE_VF_STATE_ACTIVE, vf->vf_states);

	/* Disable VF's configuration API during reset. The flag is re-enabled
	 * in ice_alloc_vf_res(), when it's safe again to access VF's VSI.
	 * It's normally disabled in ice_free_vf_res(), but it's safer
	 * to do it earlier to give some time to finish to any VF config
	 * functions that may still be running at this point.
	 */
	clear_bit(ICE_VF_STATE_INIT, vf->vf_states);

	/* VF_MBX_ARQLEN is cleared by PFR, so the driver needs to clear it
	 * in the case of VFR. If this is done for PFR, it can mess up VF
	 * resets because the VF driver may already have started cleanup
	 * by the time we get here.
	 */
	if (!is_pfr)
		wr32(hw, VF_MBX_ARQLEN(vf->vf_id), 0);

	/* In the case of a VFLR, the HW has already reset the VF and we
	 * just need to clean up, so don't hit the VFRTRIG register.
	 */
	if (!is_vflr) {
		/* reset VF using VPGEN_VFRTRIG reg */
		reg = rd32(hw, VPGEN_VFRTRIG(vf->vf_id));
		reg |= VPGEN_VFRTRIG_VFSWR_M;
		wr32(hw, VPGEN_VFRTRIG(vf->vf_id), reg);
	}
	/* clear the VFLR bit in GLGEN_VFLRSTAT */
	reg_idx = (vf_abs_id) / 32;
	bit_idx = (vf_abs_id) % 32;
	wr32(hw, GLGEN_VFLRSTAT(reg_idx), BIT(bit_idx));
	ice_flush(hw);

	wr32(hw, PF_PCI_CIAA,
	     VF_DEVICE_STATUS | (vf_abs_id << PF_PCI_CIAA_VF_NUM_S));
	for (i = 0; i < ICE_PCI_CIAD_WAIT_COUNT; i++) {
		reg = rd32(hw, PF_PCI_CIAD);
		/* no transactions pending so stop polling */
		if ((reg & VF_TRANS_PENDING_M) == 0)
			break;

		dev_err(dev, "VF %d PCI transactions stuck\n", vf->vf_id);
		udelay(ICE_PCI_CIAD_WAIT_DELAY_US);
	}
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
		dev_info(ice_hw_to_dev(hw), "update VSI for port VLAN failed, err %d aq_err %d\n",
			 status, hw->adminq.sq_last_status);
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

/**
 * ice_vf_vsi_setup - Set up a VF VSI
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 * @vf_id: defines VF ID to which this VSI connects.
 * @type: VSI type
 * @tc: Traffic class number for VF ADQ
 *
 * Returns pointer to the successfully allocated VSI struct on success,
 * otherwise returns NULL on failure.
 */
static struct ice_vsi *
ice_vf_vsi_setup(struct ice_pf *pf, struct ice_port_info *pi, u16 vf_id,
		 enum ice_vsi_type type, u8 __maybe_unused tc)
{
	return ice_vsi_setup(pf, pi, type, vf_id, NULL, tc);
}

/**
 * ice_calc_vf_first_vector_idx - Calculate MSIX vector index in the PF space
 * @pf: pointer to PF structure
 * @vf: pointer to VF that the first MSIX vector index is being calculated for
 *
 * This returns the first MSIX vector index in PF space that is used by this VF.
 * This index is used when accessing PF relative registers such as
 * GLINT_VECT2FUNC and GLINT_DYN_CTL.
 * This will always be the OICR index in the AVF driver so any functionality
 * using vf->first_vector_idx for queue configuration will have to increment by
 * 1 to avoid meddling with the OICR index.
 */
static int ice_calc_vf_first_vector_idx(struct ice_pf *pf, struct ice_vf *vf)
{
	return pf->sriov_base_vector + vf->vf_id * pf->num_vf_msix;
}

/**
 * ice_alloc_vsi_res - Setup VF VSI and its resources
 * @vf: pointer to the VF structure
 * @tc: traffic class for ADQ
 *
 * Returns 0 on success, negative value on failure
 */
static int ice_alloc_vsi_res(struct ice_vf *vf, u8 tc)
{
	struct ice_pf *pf = vf->pf;
	LIST_HEAD(tmp_add_list);
	u8 broadcast[ETH_ALEN];
	struct ice_vsi *vsi;
	u64 max_tx_rate = 0;
	struct device *dev;
	int status = 0;

	dev = ice_pf_to_dev(pf);
	/* first vector index is the VFs OICR index */
	vf->first_vector_idx = ice_calc_vf_first_vector_idx(pf, vf);

	vsi = ice_vf_vsi_setup(pf, pf->hw.port_info, vf->vf_id, ICE_VSI_VF, tc);
	if (!vsi) {
		dev_err(dev, "Failed to create VF VSI\n");
		return -ENOMEM;
	}

	if (!tc) {
		vf->lan_vsi_idx = vsi->idx;
		vf->lan_vsi_num = vsi->vsi_num;

		/* Check if port VLAN exist before and restore it accordingly */
		if (vf->port_vlan_info) {
			ice_vsi_manage_pvid(vsi, vf->port_vlan_info, true);
			if (ice_vsi_add_vlan(vsi,
					     vf->port_vlan_info & VLAN_VID_MASK,
					     ICE_FWD_TO_VSI))
				dev_warn(ice_pf_to_dev(pf), "Failed to add Port VLAN %d filter for VF %d\n",
					 vf->port_vlan_info & VLAN_VID_MASK,
					 vf->vf_id);
		} else {
			/* set VLAN 0 filter by default when no port VLAN is
			 * enabled. If a port VLAN is enabled we don't want
			 * untagged broadcast/multicast traffic seen on the VF
			 * interface.
			 */
			if (ice_vsi_add_vlan(vsi, 0, ICE_FWD_TO_VSI))
				dev_warn(ice_pf_to_dev(pf), "Failed to add VLAN 0 filter for VF %d, MDD events will trigger. Reset the VF, disable spoofchk, or enable 8021q module on the guest\n",
					 vf->vf_id);
		}

		eth_broadcast_addr(broadcast);

		status = ice_add_mac_to_list(vsi, &tmp_add_list, broadcast,
					     ICE_FWD_TO_VSI);
		if (status)
			goto ice_alloc_vsi_res_exit;

		if (is_valid_ether_addr(vf->dflt_lan_addr.addr)) {
			status = ice_add_mac_to_list(vsi, &tmp_add_list,
						     vf->dflt_lan_addr.addr,
						     ICE_FWD_TO_VSI);
			if (status)
				goto ice_alloc_vsi_res_exit;
		}

		status = ice_add_mac(&pf->hw, &tmp_add_list);
		if (status)
			dev_err(dev, "could not add mac filters error %d\n",
				status);
		else
			vf->num_mac = 1;
	}

	/* allocate additional VSIs based on TC information for ADQ */
	if (vf->adq_enabled && vf->num_tc) {
		/* save default VF VSI info in VF channel structure since
		 * it's considered as TC 0
		 */
		vf->ch[tc].vsi_idx = vsi->idx;
		vf->ch[tc].vsi_num = vsi->vsi_num;
		vsi->vf_adq_tc = tc;
	}

	/* Configure VSI-VF bandwidth if the rate specified */
	if (vf->tx_rate)
		max_tx_rate = vf->tx_rate;
	else if (vf->ch[tc].max_tx_rate)
		max_tx_rate = vf->ch[tc].max_tx_rate;

	if (max_tx_rate) {
		status = ice_cfg_vsi_bw_lmt_per_tc(vsi->port_info, vsi->idx,
						   0, ICE_MAX_BW,
						   max_tx_rate * 1000);
		if (status)
			dev_err(dev, "Unable to set tx rate VF%d, error code %d\n",
				vf->vf_id, status);
	}
	/* Clear this bit after VF initialization since we shouldn't reclaim
	 * and reassign interrupts for synchronous or asynchronous VFR events.
	 * We don't want to reconfigure interrupts since AVF driver doesn't
	 * expect vector assignment to be changed unless there is a request for
	 * more vectors.
	 */
ice_alloc_vsi_res_exit:
	ice_free_fltr_list(dev, &tmp_add_list);
	return status;
}

/**
 * ice_alloc_vf_res - Allocate VF resources
 * @vf: pointer to the VF structure
 */
static int ice_alloc_vf_res(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	int tx_rx_queue_left;
	int status;

	/* Update number of VF queues, in case VF had requested for queue
	 * changes
	 */
	tx_rx_queue_left = min_t(int, ice_get_avail_txq_count(pf),
				 ice_get_avail_rxq_count(pf));
	tx_rx_queue_left += pf->num_vf_qps;
	if (vf->num_req_qs && vf->num_req_qs <= tx_rx_queue_left &&
	    vf->num_req_qs != vf->num_vf_qs)
		vf->num_vf_qs = vf->num_req_qs;

	/* setup VF VSI and necessary resources */
	status = ice_alloc_vsi_res(vf, 0);
	if (status)
		goto ice_alloc_vf_res_exit;

	/* allocate additional VSIs based on TC information for ADQ.
	 * vf->num_tc determines whether we're enabling or disabling ADQ.
	 * This variable is set with number of TCs during enabling and set to
	 * '0' when disabling.
	 */
	if (vf->adq_enabled && vf->num_tc) {
		struct device *dev = ice_pf_to_dev(pf);
		u8 tc;

		if (tx_rx_queue_left > vf->num_tc) {
			for (tc = 1; tc < vf->num_tc; tc++) {
				status = ice_alloc_vsi_res(vf, tc);
				if (status) {
					vf->adq_enabled = false;
					dev_err(dev, "VF%d : unable to allocate VSI resources, disabling ADQ\n",
						vf->vf_id);
					goto ice_alloc_vf_res_exit;
				}
			}
		} else {
			dev_info(dev, "VF%d : Not enough queues to allocate, disabling ADQ\n",
				 vf->vf_id);
			vf->adq_enabled = false;
		}
	}

	if (vf->trusted)
		set_bit(ICE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps);
	else
		clear_bit(ICE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps);

	/* VF is now completely initialized */
	set_bit(ICE_VF_STATE_INIT, vf->vf_states);

	return status;

ice_alloc_vf_res_exit:
	ice_free_vf_res(vf);
	return status;
}

/**
 * ice_ena_vf_mappings
 * @vf: pointer to the VF structure
 *
 * Enable VF vectors and queues allocation by writing the details into
 * respective registers.
 */
static void ice_ena_vf_mappings(struct ice_vf *vf)
{
	int abs_vf_id, abs_first, abs_last;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	int first, last, v;
	struct ice_hw *hw;
	u16 txq, rxq;
	u32 reg;

	dev = ice_pf_to_dev(pf);
	hw = &pf->hw;
	first = vf->first_vector_idx;
	last = (first + pf->num_vf_msix) - 1;
	abs_first = first + pf->hw.func_caps.common_cap.msix_vector_first_id;
	abs_last = (abs_first + pf->num_vf_msix) - 1;
	abs_vf_id = vf->vf_id + hw->func_caps.vf_base_id;
	vsi = pf->vsi[vf->lan_vsi_idx];

	if (vf->adq_enabled && vf->num_tc) {
		u16 offset, num_qps;

		offset = vf->ch[vf->num_tc - 1].offset;
		num_qps = vf->ch[vf->num_tc - 1].num_qps;
		txq = offset + num_qps;
		rxq = offset + num_qps;
	} else {
		txq = vsi->alloc_txq;
		rxq = vsi->alloc_rxq;
	}

	/* VF Vector allocation */
	reg = (((abs_first << VPINT_ALLOC_FIRST_S) & VPINT_ALLOC_FIRST_M) |
	       ((abs_last << VPINT_ALLOC_LAST_S) & VPINT_ALLOC_LAST_M) |
	       VPINT_ALLOC_VALID_M);
	wr32(hw, VPINT_ALLOC(vf->vf_id), reg);

	reg = (((abs_first << VPINT_ALLOC_PCI_FIRST_S)
		 & VPINT_ALLOC_PCI_FIRST_M) |
	       ((abs_last << VPINT_ALLOC_PCI_LAST_S) & VPINT_ALLOC_PCI_LAST_M) |
	       VPINT_ALLOC_PCI_VALID_M);
	wr32(hw, VPINT_ALLOC_PCI(vf->vf_id), reg);
	/* map the interrupts to its functions */
	for (v = first; v <= last; v++) {
		reg = (((abs_vf_id << GLINT_VECT2FUNC_VF_NUM_S) &
			GLINT_VECT2FUNC_VF_NUM_M) |
		       ((hw->pf_id << GLINT_VECT2FUNC_PF_NUM_S) &
			GLINT_VECT2FUNC_PF_NUM_M));
		wr32(hw, GLINT_VECT2FUNC(v), reg);
	}

	/* Map mailbox interrupt. We put an explicit 0 here to remind us that
	 * VF admin queue interrupts will go to VF MSI-X vector 0.
	 */
	wr32(hw, VPINT_MBX_CTL(abs_vf_id), VPINT_MBX_CTL_CAUSE_ENA_M | 0);
	/* set regardless of mapping mode */
	wr32(hw, VPLAN_TXQ_MAPENA(vf->vf_id), VPLAN_TXQ_MAPENA_TX_ENA_M);

	/* VF Tx queues allocation */
	if (vsi->tx_mapping_mode == ICE_VSI_MAP_CONTIG) {
		/* set the VF PF Tx queue range
		 * VFNUMQ value should be set to (number of queues - 1). A value
		 * of 0 means 1 queue and a value of 255 means 256 queues
		 */
		reg = (((vsi->txq_map[0] << VPLAN_TX_QBASE_VFFIRSTQ_S) &
			VPLAN_TX_QBASE_VFFIRSTQ_M) |
		       (((txq - 1) << VPLAN_TX_QBASE_VFNUMQ_S) &
			VPLAN_TX_QBASE_VFNUMQ_M));
		wr32(hw, VPLAN_TX_QBASE(vf->vf_id), reg);
	} else {
		dev_err(dev, "Scattered mode for VF Tx queues is not yet implemented\n");
	}

	/* set regardless of mapping mode */
	wr32(hw, VPLAN_RXQ_MAPENA(vf->vf_id), VPLAN_RXQ_MAPENA_RX_ENA_M);

	/* VF Rx queues allocation */
	if (vsi->rx_mapping_mode == ICE_VSI_MAP_CONTIG) {
		/* set the VF PF Rx queue range
		 * VFNUMQ value should be set to (number of queues - 1). A value
		 * of 0 means 1 queue and a value of 255 means 256 queues
		 */
		reg = (((vsi->rxq_map[0] << VPLAN_RX_QBASE_VFFIRSTQ_S) &
			VPLAN_RX_QBASE_VFFIRSTQ_M) |
		       (((rxq - 1) << VPLAN_RX_QBASE_VFNUMQ_S) &
			VPLAN_RX_QBASE_VFNUMQ_M));
		wr32(hw, VPLAN_RX_QBASE(vf->vf_id), reg);
	} else {
		dev_err(dev, "Scattered mode for VF Rx queues is not yet implemented\n");
	}
}

/**
 * ice_determine_res
 * @pf: pointer to the PF structure
 * @avail_res: available resources in the PF structure
 * @max_res: maximum resources that can be given per VF
 * @min_res: minimum resources that can be given per VF
 *
 * Returns non-zero value if resources (queues/vectors) are available or
 * returns zero if PF cannot accommodate for all num_alloc_vfs.
 */
static int
ice_determine_res(struct ice_pf *pf, u16 avail_res, u16 max_res, u16 min_res)
{
	bool checked_min_res = false;
	int res;

	/* start by checking if PF can assign max number of resources for
	 * all num_alloc_vfs.
	 * if yes, return number per VF
	 * If no, divide by 2 and roundup, check again
	 * repeat the loop till we reach a point where even minimum resources
	 * are not available, in that case return 0
	 */
	res = max_res;
	while ((res >= min_res) && !checked_min_res) {
		int num_all_res;

		num_all_res = pf->num_alloc_vfs * res;
		if (num_all_res <= avail_res)
			return res;

		if (res == min_res)
			checked_min_res = true;

		res = DIV_ROUND_UP(res, 2);
	}
	return 0;
}

/**
 * ice_calc_vf_reg_idx - Calculate the VF's register index in the PF space
 * @vf: VF to calculate the register index for
 * @q_vector: a q_vector associated to the VF
 * @tc: Traffic class number for VF ADQ
 */
int ice_calc_vf_reg_idx(struct ice_vf *vf, struct ice_q_vector *q_vector,
			u8 __maybe_unused tc)
{
	struct ice_pf *pf;
	u32 reg_idx;

	if (!vf || !q_vector)
		return -EINVAL;

	pf = vf->pf;
	/* always add one to account for the OICR being the first MSIX */
	reg_idx = pf->sriov_base_vector + pf->num_vf_msix * vf->vf_id +
		  q_vector->v_idx + 1;

	if (tc && vf->adq_enabled && vf->num_tc)
		return reg_idx + vf->ch[tc].offset;
	else
		return reg_idx;
}

/**
 * ice_get_max_valid_res_idx - Get the max valid resource index
 * @res: pointer to the resource to find the max valid index for
 *
 * Start from the end of the ice_res_tracker and return right when we find the
 * first res->list entry with the ICE_RES_VALID_BIT set. This function is only
 * valid for SR-IOV because it is the only consumer that manipulates the
 * res->end and this is always called when res->end is set to res->num_entries.
 */
static int ice_get_max_valid_res_idx(struct ice_res_tracker *res)
{
	int i;

	if (!res)
		return -EINVAL;

	for (i = res->num_entries - 1; i >= 0; i--)
		if (res->list[i] & ICE_RES_VALID_BIT)
			return i;

	return 0;
}

/**
 * ice_sriov_set_msix_res - Set any used MSIX resources
 * @pf: pointer to PF structure
 * @num_msix_needed: number of MSIX vectors needed for all SR-IOV VFs
 *
 * This function allows SR-IOV resources to be taken from the end of the PF's
 * allowed HW MSIX vectors so that the irq_tracker will not be affected. We
 * just set the pf->sriov_base_vector and return success.
 *
 * If there are not enough resources available, return an error. This should
 * always be caught by ice_check_avail_res().
 *
 * Return 0 on success, and -EINVAL when there are not enough MSIX vectors in
 * in the PF's space available for SR-IOV.
 */
static int ice_sriov_set_msix_res(struct ice_pf *pf, u16 num_msix_needed)
{
	u16 total_vectors = pf->hw.func_caps.common_cap.num_msix_vectors;
	int vectors_used = pf->irq_tracker->num_entries;
	int sriov_base_vector;

	sriov_base_vector = total_vectors - num_msix_needed;

	/* make sure we only grab irq_tracker entries from the list end and
	 * that we have enough available MSIX vectors
	 */
	if (sriov_base_vector < vectors_used)
		return -EINVAL;

	pf->sriov_base_vector = sriov_base_vector;

	return 0;
}

/**
 * ice_check_avail_res - check if vectors and queues are available
 * @pf: pointer to the PF structure
 *
 * This function is where we calculate actual number of resources for VF VSIs,
 * we don't reserve ahead of time during probe. Returns success if vectors and
 * queues resources are available, otherwise returns error code
 */
static int ice_check_avail_res(struct ice_pf *pf)
{
	int max_valid_res_idx = ice_get_max_valid_res_idx(pf->irq_tracker);
	struct device *dev = ice_pf_to_dev(pf);
	u16 num_msix, num_txq, num_rxq;
	int v;

	if (!pf->num_alloc_vfs || max_valid_res_idx < 0)
		return -EINVAL;

	/* Grab from HW interrupt common pool. If we allocate fewer VFs, we
	 * get more vectors and can enable more queues per VF. Note that this
	 * does not grab any vectors from the SW pool already allocated.
	 *
	 * Small VFs - 4 vectors, 4 queues
	 * Medium VFs - 16 vectors, 16 queues
	 *
	 * While more vectors can be assigned to a VF, the RSS LUT
	 * is only 4 bits wide, so we can only do 16 queues of RSS
	 * per VF.
	 *
	 * ADQ sizes:
	 * Small ADQ VFs - 4 vectors, 4 TCs, 16 queues total (4 queue/int)
	 * Medium ADQ VFs - 16 vectors, 4 TCs, 16 queues total (1 queue/int)
	 */
	v = (pf->hw.func_caps.common_cap.num_msix_vectors -
	     pf->irq_tracker->num_entries) / pf->num_alloc_vfs;
	if (v >= ICE_NUM_VF_MSIX_MED) {
		num_msix = ICE_NUM_VF_MSIX_MED;
	} else if (v >= ICE_NUM_VF_MSIX_SMALL) {
		num_msix = ICE_NUM_VF_MSIX_SMALL;
	} else if (v >= ICE_MIN_INTR_PER_VF) {
		num_msix = ICE_MIN_INTR_PER_VF;
	} else {
		dev_err(&pf->pdev->dev,
			"Not enough vectors to support %d VFs\n",
			pf->num_alloc_vfs);
		return -EIO;
	}

	/* Grab from the common pool
	 * start by requesting Default queues (4 as supported by AVF driver),
	 * Note that, the main difference between queues and vectors is, latter
	 * can only be reserved at init time but queues can be requested by VF
	 * at runtime through Virtchnl, that is the reason we start by reserving
	 * few queues.
	 */
	num_txq = ice_determine_res(pf, ice_get_avail_txq_count(pf),
				    min_t(u16, num_msix - 1,
					  ICE_MAX_RSS_QS_PER_VF),
				    ICE_MIN_QS_PER_VF);

	num_rxq = ice_determine_res(pf, ice_get_avail_rxq_count(pf),
				    min_t(u16, num_msix - 1,
					  ICE_MAX_RSS_QS_PER_VF),
				    ICE_MIN_QS_PER_VF);

	if (!num_txq || !num_rxq) {
		dev_err(&pf->pdev->dev, "Not enough queues to support %d VFs\n",
			pf->num_alloc_vfs);
		return -EIO;
	}

	if (ice_sriov_set_msix_res(pf, num_msix * pf->num_alloc_vfs)) {
		dev_err(&pf->pdev->dev, "Unable to set MSI-X resources for %d VFs\n",
			pf->num_alloc_vfs);
		return -EINVAL;
	}

	/* Since the AVF driver works with only queue pairs, it expects to
	 * have an equal of number of Rx and Tx queues. Take the minimum of
	 * available Tx or Rx queues.
	 */
	pf->num_vf_qps = min_t(int, num_txq, num_rxq);
	pf->num_vf_msix = num_msix;
	dev_info(dev, "Enabling %d VFs with %d vectors and %d queues per VF\n",
		 pf->num_alloc_vfs, num_msix, pf->num_vf_qps);

	return 0;
}

/**
 * ice_cleanup_and_realloc_vf - Clean up VF and reallocate resources after reset
 * @vf: pointer to the VF structure
 *
 * Cleanup a VF after the hardware reset is finished. Expects the caller to
 * have verified whether the reset is finished properly, and ensure the
 * minimum amount of wait time has passed. Reallocate VF resources back to make
 * VF state active
 */
static void ice_cleanup_and_realloc_vf(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct ice_hw *hw;
	u32 reg;

	hw = &pf->hw;

	/* PF software completes the flow by notifying VF that reset flow is
	 * completed. This is done by enabling hardware by clearing the reset
	 * bit in the VPGEN_VFRTRIG reg and setting VFR_STATE in the VFGEN_RSTAT
	 * register to VFR completed (done at the end of this function)
	 * By doing this we allow HW to access VF memory at any point. If we
	 * did it any sooner, HW could access memory while it was being freed
	 * in ice_free_vf_res(), causing an IOMMU fault.
	 *
	 * On the other hand, this needs to be done ASAP, because the VF driver
	 * is waiting for this to happen and may report a timeout. It's
	 * harmless, but it gets logged into Guest OS kernel log, so best avoid
	 * it.
	 */
	reg = rd32(hw, VPGEN_VFRTRIG(vf->vf_id));
	reg &= ~VPGEN_VFRTRIG_VFSWR_M;
	wr32(hw, VPGEN_VFRTRIG(vf->vf_id), reg);

	/* reallocate VF resources to finish resetting the VSI state */
	if (!ice_alloc_vf_res(vf)) {
		ice_ena_vf_mappings(vf);
		set_bit(ICE_VF_STATE_ACTIVE, vf->vf_states);
		clear_bit(ICE_VF_STATE_DIS, vf->vf_states);
	}

	/* Tell the VF driver the reset is done. This needs to be done only
	 * after VF has been fully initialized, because the VF driver may
	 * request resources immediately after setting this flag.
	 */
	wr32(hw, VFGEN_RSTAT(vf->vf_id), VIRTCHNL_VFR_VFACTIVE);
}

/**
 * ice_vf_set_vsi_promisc - set given VF VSI to given promiscuous mode(s)
 * @vf: pointer to the VF info
 * @vsi: the VSI being configured
 * @promisc_m: mask of promiscuous config bits
 * @rm_promisc: promisc flag request from the VF to remove or add filter
 *
 * This function configures VF VSI promiscuous mode, based on the VF requests,
 * for Unicast, Multicast and VLAN
 */
static enum ice_status
ice_vf_set_vsi_promisc(struct ice_vf *vf, struct ice_vsi *vsi, u8 promisc_m,
		       bool rm_promisc)
{
	struct ice_pf *pf = vf->pf;
	enum ice_status status = 0;
	struct ice_hw *hw;

	hw = &pf->hw;
	if (vsi->num_vlan) {
		status = ice_set_vlan_vsi_promisc(hw, vsi->idx, promisc_m,
						  rm_promisc);
	} else if (vf->port_vlan_info) {
		if (rm_promisc)
			status = ice_clear_vsi_promisc(hw, vsi->idx, promisc_m,
						       vf->port_vlan_info);
		else
			status = ice_set_vsi_promisc(hw, vsi->idx, promisc_m,
						     vf->port_vlan_info);
	} else {
		if (rm_promisc)
			status = ice_clear_vsi_promisc(hw, vsi->idx, promisc_m,
						       0);
		else
			status = ice_set_vsi_promisc(hw, vsi->idx, promisc_m,
						     0);
	}

	return status;
}

/**
 * ice_config_res_vfs - Finalize allocation of VFs resources in one go
 * @pf: pointer to the PF structure
 *
 * This function is being called as last part of resetting all VFs, or when
 * configuring VFs for the first time, where there is no resource to be freed
 * Returns true if resources were properly allocated for all VFs, and false
 * otherwise.
 */
static bool ice_config_res_vfs(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	int v;

	if (ice_check_avail_res(pf)) {
		dev_err(dev, "Cannot allocate VF resources, try with fewer number of VFs\n");
		return false;
	}

	/* rearm global interrupts */
	if (test_and_clear_bit(__ICE_OICR_INTR_DIS, pf->state))
		ice_irq_dynamic_ena(hw, NULL, NULL);

	/* Finish resetting each VF and allocate resources */
	ice_for_each_vf(pf, v) {
		struct ice_vf *vf = &pf->vf[v];

		vf->num_vf_qs = pf->num_vf_qps;
		dev_dbg(dev, "VF-id %d has %d queues configured\n", vf->vf_id,
			vf->num_vf_qs);
		ice_cleanup_and_realloc_vf(vf);
	}

	ice_flush(hw);
	clear_bit(__ICE_VF_DIS, pf->state);

	return true;
}

/**
 * ice_reset_all_vfs - reset all allocated VFs in one go
 * @pf: pointer to the PF structure
 * @is_vflr: true if VFLR was issued, false if not
 *
 * First, tell the hardware to reset each VF, then do all the waiting in one
 * chunk, and finally finish restoring each VF after the wait. This is useful
 * during PF routines which need to reset all VFs, as otherwise it must perform
 * these resets in a serialized fashion.
 *
 * Returns true if any VFs were reset, and false otherwise.
 */
bool ice_reset_all_vfs(struct ice_pf *pf, bool is_vflr)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	struct ice_vf *vf;
	int v, i;

	/* If we don't have any VFs, then there is nothing to reset */
	if (!pf->num_alloc_vfs)
		return false;

	/* If VFs have been disabled, there is no need to reset */
	if (test_and_set_bit(__ICE_VF_DIS, pf->state))
		return false;

	/* Begin reset on all VFs at once */
	ice_for_each_vf(pf, v)
		ice_trigger_vf_reset(&pf->vf[v], is_vflr, true);

	ice_for_each_vf(pf, v) {
		struct ice_vsi *vsi;

		vf = &pf->vf[v];
		vsi = pf->vsi[vf->lan_vsi_idx];
		if (test_bit(ICE_VF_STATE_QS_ENA, vf->vf_states))
			ice_dis_vf_qs(vf);
		ice_dis_vsi_txq(vsi->port_info, vsi->idx, 0, 0, NULL, NULL,
				NULL, ICE_VF_RESET, vf->vf_id, NULL);
	}

	/* HW requires some time to make sure it can flush the FIFO for a VF
	 * when it resets it. Poll the VPGEN_VFRSTAT register for each VF in
	 * sequence to make sure that it has completed. We'll keep track of
	 * the VFs using a simple iterator that increments once that VF has
	 * finished resetting.
	 */
	for (i = 0, v = 0; i < 10 && v < pf->num_alloc_vfs; i++) {
		/* Check each VF in sequence */
		while (v < pf->num_alloc_vfs) {
			u32 reg;

			vf = &pf->vf[v];
			reg = rd32(hw, VPGEN_VFRSTAT(vf->vf_id));
			if (!(reg & VPGEN_VFRSTAT_VFRD_M)) {
				/* only delay if the check failed */
				usleep_range(10, 20);
				break;
			}

			/* If the current VF has finished resetting, move on
			 * to the next VF in sequence.
			 */
			v++;
		}
	}


	/* Display a warning if at least one VF didn't manage to reset in
	 * time, but continue on with the operation.
	 */
	if (v < pf->num_alloc_vfs)
		dev_warn(dev, "VF reset check timeout\n");


	/* free VF resources to begin resetting the VSI state */
	ice_for_each_vf(pf, v) {
		vf = &pf->vf[v];

		ice_free_vf_res(vf);

		/* Free VF queues as well, and reallocate later.
		 * If a given VF has different number of queues
		 * configured, the request for update will come
		 * via mailbox communication.
		 */
		vf->num_vf_qs = 0;
	}

	if (ice_sriov_free_msix_res(pf))
		dev_err(dev, "Failed to free MSIX resources used by SR-IOV\n");

	if (!ice_config_res_vfs(pf))
		return false;

	return true;
}

/**
 * ice_is_vf_disabled
 * @vf: pointer to the VF info
 *
 * Returns true if the PF or VF is disabled, false otherwise.
 */
static bool ice_is_vf_disabled(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;

	/* If the PF has been disabled, there is no need resetting VF until
	 * PF is active again. Similarly, if the VF has been disabled, this
	 * means something else is resetting the VF, so we shouldn't continue.
	 * Otherwise, set disable VF state bit for actual reset, and continue.
	 */
	return (test_bit(__ICE_VF_DIS, pf->state) ||
		test_bit(ICE_VF_STATE_DIS, vf->vf_states));
}

/**
 * ice_reset_vf - Reset a particular VF
 * @vf: pointer to the VF structure
 * @is_vflr: true if VFLR was issued, false if not
 *
 * Returns true if the VF is reset, false otherwise.
 */
bool ice_reset_vf(struct ice_vf *vf, bool is_vflr)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_hw *hw;
	bool rsd = false;
	u8 promisc_m;
	u32 reg;
	int i;

	dev = ice_pf_to_dev(pf);

	if (ice_is_vf_disabled(vf)) {
		dev_dbg(dev, "VF is already disabled, there is no need for resetting it, telling VM, all is fine %d\n",
			vf->vf_id);
		return true;
	}

	/* Set VF disable bit state here, before triggering reset */
	set_bit(ICE_VF_STATE_DIS, vf->vf_states);
	ice_trigger_vf_reset(vf, is_vflr, false);

	vsi = pf->vsi[vf->lan_vsi_idx];

	if (test_bit(ICE_VF_STATE_QS_ENA, vf->vf_states))
		ice_dis_vf_qs(vf);

	/* Call Disable LAN Tx queue AQ whether or not queues are
	 * enabled. This is needed for successful completion of VFR.
	 */
	ice_dis_vsi_txq(vsi->port_info, vsi->idx, 0, 0, NULL, NULL,
			NULL, ICE_VF_RESET, vf->vf_id, NULL);

	hw = &pf->hw;
	/* poll VPGEN_VFRSTAT reg to make sure
	 * that reset is complete
	 */
	for (i = 0; i < 10; i++) {
		/* VF reset requires driver to first reset the VF and then
		 * poll the status register to make sure that the reset
		 * completed successfully.
		 */
		reg = rd32(hw, VPGEN_VFRSTAT(vf->vf_id));
		if (reg & VPGEN_VFRSTAT_VFRD_M) {
			rsd = true;
			break;
		}

		/* only sleep if the reset is not done */
		usleep_range(10, 20);
	}

	/* Display a warning if VF didn't manage to reset in time, but need to
	 * continue on with the operation.
	 */
	if (!rsd)
		dev_warn(dev, "VF reset check timeout on VF %d\n", vf->vf_id);

	/* disable promiscuous modes in case they were enabled
	 * ignore any error if disabling process failed
	 */
	if (test_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states) ||
	    test_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states)) {
		if (vf->port_vlan_info ||  vsi->num_vlan)
			promisc_m = ICE_UCAST_VLAN_PROMISC_BITS;
		else
			promisc_m = ICE_UCAST_PROMISC_BITS;

		vsi = pf->vsi[vf->lan_vsi_idx];
		if (ice_vf_set_vsi_promisc(vf, vsi, promisc_m, true))
			dev_err(dev, "disabling promiscuous mode failed\n");
	}

	/* free VF resources to begin resetting the VSI state */
	ice_free_vf_res(vf);

	ice_cleanup_and_realloc_vf(vf);

	ice_flush(hw);

	return true;
}

/**
 * ice_vc_notify_link_state - Inform all VFs on a PF of link status
 * @pf: pointer to the PF structure
 */
void ice_vc_notify_link_state(struct ice_pf *pf)
{
	int i;

	ice_for_each_vf(pf, i)
		ice_vc_notify_vf_link_state(&pf->vf[i]);
}

/**
 * ice_vc_notify_reset - Send pending reset message to all VFs
 * @pf: pointer to the PF structure
 *
 * indicate a pending reset to all VFs on a given PF
 */
void ice_vc_notify_reset(struct ice_pf *pf)
{
	struct virtchnl_pf_event pfe;

	if (!pf->num_alloc_vfs)
		return;

	pfe.event = VIRTCHNL_EVENT_RESET_IMPENDING;
	pfe.severity = PF_EVENT_SEVERITY_CERTAIN_DOOM;
	ice_vc_vf_broadcast(pf, VIRTCHNL_OP_EVENT, VIRTCHNL_STATUS_SUCCESS,
			    (u8 *)&pfe, sizeof(struct virtchnl_pf_event));
}

/**
 * ice_vc_notify_vf_reset - Notify VF of a reset event
 * @vf: pointer to the VF structure
 */
static void ice_vc_notify_vf_reset(struct ice_vf *vf)
{
	struct virtchnl_pf_event pfe;
	struct ice_pf *pf;

	if (!vf)
		return;

	pf = vf->pf;
	if (ice_validate_vf_id(pf, vf->vf_id))
		return;

	/* Bail out if VF is in disabled state, neither initialized, nor active
	 * state - otherwise proceed with notifications
	 */
	if ((!test_bit(ICE_VF_STATE_INIT, vf->vf_states) &&
	     !test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) ||
	    test_bit(ICE_VF_STATE_DIS, vf->vf_states))
		return;

	pfe.event = VIRTCHNL_EVENT_RESET_IMPENDING;
	pfe.severity = PF_EVENT_SEVERITY_CERTAIN_DOOM;
	ice_aq_send_msg_to_vf(&pf->hw, vf->vf_id, VIRTCHNL_OP_EVENT,
			      VIRTCHNL_STATUS_SUCCESS, (u8 *)&pfe, sizeof(pfe),
			      NULL);
}


/**
 * ice_alloc_vfs - Allocate and set up VFs resources
 * @pf: pointer to the PF structure
 * @num_alloc_vfs: number of VFs to allocate
 */
static int ice_alloc_vfs(struct ice_pf *pf, u16 num_alloc_vfs)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	struct ice_vf *vfs;
	int i, ret;

	/* Disable global interrupt 0 so we don't try to handle the VFLR. */
	wr32(hw, GLINT_DYN_CTL(pf->oicr_idx),
	     ICE_ITR_NONE << GLINT_DYN_CTL_ITR_INDX_S);
	set_bit(__ICE_OICR_INTR_DIS, pf->state);
	ice_flush(hw);

	ret = pci_enable_sriov(pf->pdev, num_alloc_vfs);
	if (ret) {
		pf->num_alloc_vfs = 0;
		goto err_unroll_intr;
	}
	/* allocate memory */
	vfs = devm_kcalloc(dev, num_alloc_vfs, sizeof(*vfs), GFP_KERNEL);
	if (!vfs) {
		ret = -ENOMEM;
		goto err_pci_disable_sriov;
	}
	pf->vf = vfs;
	pf->num_alloc_vfs = num_alloc_vfs;

	/* apply default profile */
	ice_for_each_vf(pf, i) {
		vfs[i].pf = pf;
		vfs[i].vf_id = i;
		vfs[i].vf_sw_id = pf->first_sw;
		/* assign default capabilities */
		set_bit(ICE_VIRTCHNL_VF_CAP_L2, &vfs[i].vf_caps);
		vfs[i].spoofchk = true;
	}

	/* VF resources get allocated with initialization */
	if (!ice_config_res_vfs(pf)) {
		ret = -EIO;
		goto err_unroll_sriov;
	}

	return ret;

err_unroll_sriov:
	pf->vf = NULL;
	devm_kfree(dev, vfs);
	vfs = NULL;
	pf->num_alloc_vfs = 0;
err_pci_disable_sriov:
	pci_disable_sriov(pf->pdev);
err_unroll_intr:
	/* rearm interrupts here */
	ice_irq_dynamic_ena(hw, NULL, NULL);
	clear_bit(__ICE_OICR_INTR_DIS, pf->state);
	return ret;
}

/**
 * ice_pci_sriov_ena - Enable or change number of VFs
 * @pf: pointer to the PF structure
 * @num_vfs: number of VFs to allocate
 */
static int ice_pci_sriov_ena(struct ice_pf *pf, int num_vfs)
{
	int pre_existing_vfs = pci_num_vf(pf->pdev);
	struct device *dev = ice_pf_to_dev(pf);
	int err;

	if (!ice_pf_state_is_nominal(pf)) {
		dev_err(dev, "Cannot enable SR-IOV, device not ready\n");
		return -EBUSY;
	}

	if (!test_bit(ICE_FLAG_SRIOV_CAPABLE, pf->flags)) {
		dev_err(dev, "This device is not capable of SR-IOV\n");
		return -EOPNOTSUPP;
	}

	if (pre_existing_vfs && pre_existing_vfs != num_vfs)
		ice_free_vfs(pf);
	else if (pre_existing_vfs && pre_existing_vfs == num_vfs)
		return num_vfs;

	if (num_vfs > pf->num_vfs_supported) {
		dev_err(dev, "Can't enable %d VFs, max VFs supported is %d\n",
			num_vfs, pf->num_vfs_supported);
		return -ENOTSUPP;
	}

	dev_info(dev, "Allocating %d VFs\n", num_vfs);
	err = ice_alloc_vfs(pf, num_vfs);
	if (err) {
		dev_err(dev, "Failed to enable SR-IOV: %d\n", err);
		return err;
	}

	set_bit(ICE_FLAG_SRIOV_ENA, pf->flags);
	return num_vfs;
}


/**
 * ice_sriov_configure - Enable or change number of VFs via sysfs
 * @pdev: pointer to a pci_dev structure
 * @num_vfs: number of VFs to allocate
 *
 * This function is called when the user updates the number of VFs in sysfs.
 */
int ice_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct ice_pf *pf = pci_get_drvdata(pdev);
	struct device *dev = ice_pf_to_dev(pf);

	if (test_bit(__ICE_RECOVERY_MODE, pf->state)) {
		dev_err(dev, "SR-IOV cannot be configured - Device is in Recovery Mode\n");
		return -EOPNOTSUPP;
	}

	if (ice_is_safe_mode(pf)) {
		dev_err(dev, "SR-IOV cannot be configured - Device is in Safe Mode\n");
		return -EOPNOTSUPP;
	}

	if (num_vfs)
		return ice_pci_sriov_ena(pf, num_vfs);

	if (!pci_vfs_assigned(pdev)) {
		ice_free_vfs(pf);
	} else {
		dev_err(dev, "can't free VFs because some are assigned to VMs.\n");
		return -EBUSY;
	}

	return 0;
}

/**
 * ice_process_vflr_event - Free VF resources via IRQ calls
 * @pf: pointer to the PF structure
 *
 * called from the VFLR IRQ handler to
 * free up VF resources and state variables
 */
void ice_process_vflr_event(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;
	int vf_id;
	u32 reg;

	if (!test_and_clear_bit(__ICE_VFLR_EVENT_PENDING, pf->state) ||
	    !pf->num_alloc_vfs)
		return;

	ice_for_each_vf(pf, vf_id) {
		struct ice_vf *vf = &pf->vf[vf_id];
		u32 reg_idx, bit_idx;

		reg_idx = (hw->func_caps.vf_base_id + vf_id) / 32;
		bit_idx = (hw->func_caps.vf_base_id + vf_id) % 32;
		/* read GLGEN_VFLRSTAT register to find out the flr VFs */
		reg = rd32(hw, GLGEN_VFLRSTAT(reg_idx));
		if (reg & BIT(bit_idx))
			/* GLGEN_VFLRSTAT bit will be cleared in ice_reset_vf */
			ice_reset_vf(vf, true);
	}
}

/**
 * ice_vc_reset_vf - Perform software reset on the VF after informing the AVF
 * @vf: pointer to the VF info
 */
static void ice_vc_reset_vf(struct ice_vf *vf)
{
	ice_vc_notify_vf_reset(vf);
	ice_reset_vf(vf, false);
}

/**
 * ice_get_vf_from_pfq - get the VF who owns the PF space queue passed in
 * @pf: PF used to index all VFs
 * @pfq: queue index relative to the PF's function space
 *
 * If no VF is found who owns the pfq then return NULL, otherwise return a
 * pointer to the VF who owns the pfq
 */
static struct ice_vf *ice_get_vf_from_pfq(struct ice_pf *pf, u16 pfq)
{
	int vf_id;

	ice_for_each_vf(pf, vf_id) {
		struct ice_vf *vf = &pf->vf[vf_id];
		struct ice_vsi *vsi;
		u16 rxq_idx;

		vsi = pf->vsi[vf->lan_vsi_idx];

		ice_for_each_rxq(vsi, rxq_idx)
			if (vsi->rxq_map[rxq_idx] == pfq)
				return vf;
	}

	return NULL;
}

/**
 * ice_globalq_to_pfq - convert from global queue index to PF space queue index
 * @pf: PF used for conversion
 * @globalq: global queue index used to convert to PF space queue index
 */
static u32 ice_globalq_to_pfq(struct ice_pf *pf, u32 globalq)
{
	return globalq - pf->hw.func_caps.common_cap.rxq_first_id;
}

/**
 * ice_vf_lan_overflow_event - handle LAN overflow event for a VF
 * @pf: PF that the LAN overflow event happened on
 * @event: structure holding the event information for the LAN overflow event
 *
 * Determine if the LAN overflow event was caused by a VF queue. If it was not
 * caused by a VF, do nothing. If a VF caused this LAN overflow event trigger a
 * reset on the offending VF.
 */
void
ice_vf_lan_overflow_event(struct ice_pf *pf, struct ice_rq_event_info *event)
{
	u32 gldcb_rtctq, queue;
	struct ice_vf *vf;

	gldcb_rtctq = le32_to_cpu(event->desc.params.lan_overflow.prtdcb_ruptq);
	dev_dbg(ice_pf_to_dev(pf), "GLDCB_RTCTQ: 0x%08x\n", gldcb_rtctq);

	/* event returns device global Rx queue number */
	queue = (gldcb_rtctq & GLDCB_RTCTQ_RXQNUM_M) >>
		GLDCB_RTCTQ_RXQNUM_S;

	vf = ice_get_vf_from_pfq(pf, ice_globalq_to_pfq(pf, queue));
	if (!vf)
		return;

	ice_vc_reset_vf(vf);
}

/**
 * ice_vc_send_msg_to_vf - Send message to VF
 * @vf: pointer to the VF info
 * @v_opcode: virtual channel opcode
 * @v_retval: virtual channel return value
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 *
 * send msg to VF
 */
static int
ice_vc_send_msg_to_vf(struct ice_vf *vf, u32 v_opcode,
		      enum virtchnl_status_code v_retval, u8 *msg, u16 msglen)
{
	enum ice_status aq_ret;
	struct device *dev;
	struct ice_pf *pf;

	if (!vf)
		return -EINVAL;

	pf = vf->pf;
	if (ice_validate_vf_id(pf, vf->vf_id))
		return -EINVAL;

	dev = ice_pf_to_dev(pf);

	/* single place to detect unsuccessful return values */
	if (v_retval) {
		vf->num_inval_msgs++;
		dev_info(dev, "VF %d failed opcode %d, retval: %d\n", vf->vf_id,
			 v_opcode, v_retval);
		if (vf->num_inval_msgs > ICE_DFLT_NUM_INVAL_MSGS_ALLOWED) {
			dev_err(dev, "Number of invalid messages exceeded for VF %d\n",
				vf->vf_id);
			dev_err(dev, "Use PF Control I/F to enable the VF\n");
			set_bit(ICE_VF_STATE_DIS, vf->vf_states);
			return -EIO;
		}
	} else {
		vf->num_valid_msgs++;
		/* reset the invalid counter, if a valid message is received. */
		vf->num_inval_msgs = 0;
	}

	aq_ret = ice_aq_send_msg_to_vf(&pf->hw, vf->vf_id, v_opcode, v_retval,
				       msg, msglen, NULL);
	if (aq_ret && pf->hw.mailboxq.sq_last_status != ICE_AQ_RC_ENOSYS) {
		dev_info(dev, "Unable to send the message to VF %d ret %d aq_err %d\n",
			 vf->vf_id, aq_ret, pf->hw.mailboxq.sq_last_status);
		return -EIO;
	}

	return 0;
}

/**
 * ice_vc_get_ver_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to request the API version used by the PF
 */
static int ice_vc_get_ver_msg(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_version_info info = {
		VIRTCHNL_VERSION_MAJOR, VIRTCHNL_VERSION_MINOR
	};

	vf->vf_ver = *(struct virtchnl_version_info *)msg;
	/* VFs running the 1.0 API expect to get 1.0 back or they will cry. */
	if (VF_IS_V10(&vf->vf_ver))
		info.minor = VIRTCHNL_VERSION_MINOR_NO_VF_CAPS;

	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_VERSION,
				     VIRTCHNL_STATUS_SUCCESS, (u8 *)&info,
				     sizeof(struct virtchnl_version_info));
}

/**
 * ice_vc_get_vf_res_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to request its resources
 */
static int ice_vc_get_vf_res_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vf_resource *vfres = NULL;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	int len = 0;
	int ret;

	if (ice_check_vf_init(pf, vf)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	len = sizeof(struct virtchnl_vf_resource);

	vfres = kzalloc(len, GFP_KERNEL);
	if (!vfres) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}
	if (VF_IS_V11(&vf->vf_ver))
		vf->driver_caps = *(u32 *)msg;
	else
		vf->driver_caps = VIRTCHNL_VF_OFFLOAD_L2 |
				  VIRTCHNL_VF_OFFLOAD_RSS_REG |
				  VIRTCHNL_VF_OFFLOAD_VLAN;

	vfres->vf_cap_flags = VIRTCHNL_VF_OFFLOAD_L2;
	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!vsi->info.pvid)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_VLAN;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RSS_PF) {
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_PF;
	} else {
		if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RSS_AQ)
			vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_AQ;
		else
			vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_REG;
	}

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RSS_PCTYPE_V2)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_PCTYPE_V2;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ENCAP)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ENCAP;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_POLLING)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RX_POLLING;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_WB_ON_ITR)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_WB_ON_ITR;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_REQ_QUEUES)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_REQ_QUEUES;

	if (vf->driver_caps & VIRTCHNL_VF_CAP_ADV_LINK_SPEED)
		vfres->vf_cap_flags |= VIRTCHNL_VF_CAP_ADV_LINK_SPEED;

#ifdef __TC_MQPRIO_MODE_MAX
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ADQ;
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ADQ_V2;
#endif /* __TC_MQPRIO_MODE_MAX */

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_USO)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_USO;

	vfres->num_vsis = 1;
	/* Tx and Rx queue are equal for VF */
	vfres->num_queue_pairs = vsi->num_txq;
	vfres->max_vectors = pf->num_vf_msix;
	vfres->rss_key_size = ICE_VSIQF_HKEY_ARRAY_SIZE;
	vfres->rss_lut_size = ICE_VSIQF_HLUT_ARRAY_SIZE;

	vfres->vsi_res[0].vsi_id = vf->lan_vsi_num;
	vfres->vsi_res[0].vsi_type = VIRTCHNL_VSI_SRIOV;
	vfres->vsi_res[0].num_queue_pairs = vsi->num_txq;
	ether_addr_copy(vfres->vsi_res[0].default_mac_addr,
			vf->dflt_lan_addr.addr);

	/* match guest capabilities */
	vf->driver_caps = vfres->vf_cap_flags;

	set_bit(ICE_VF_STATE_ACTIVE, vf->vf_states);

err:
	/* send the response back to the VF */
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_VF_RESOURCES, v_ret,
				    (u8 *)vfres, len);

	kfree(vfres);
	return ret;
}

/**
 * ice_vc_reset_vf_msg
 * @vf: pointer to the VF info
 *
 * called from the VF to reset itself,
 * unlike other virtchnl messages, PF driver
 * doesn't send the response back to the VF
 */
static void ice_vc_reset_vf_msg(struct ice_vf *vf)
{
	if (test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states))
		ice_reset_vf(vf, false);
}

/**
 * ice_find_vsi_from_id
 * @pf: the PF structure to search for the VSI
 * @id: ID of the VSI it is searching for
 *
 * searches for the VSI with the given ID
 */
static struct ice_vsi *ice_find_vsi_from_id(struct ice_pf *pf, u16 id)
{
	int i;

	ice_for_each_vsi(pf, i)
		if (pf->vsi[i] && pf->vsi[i]->vsi_num == id)
			return pf->vsi[i];

	return NULL;
}

/**
 * ice_vc_isvalid_vsi_id
 * @vf: pointer to the VF info
 * @vsi_id: VF relative VSI ID
 *
 * check for the valid VSI ID
 */
static bool ice_vc_isvalid_vsi_id(struct ice_vf *vf, u16 vsi_id)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	vsi = ice_find_vsi_from_id(pf, vsi_id);

	return (vsi && (vsi->vf_id == vf->vf_id));
}

/**
 * ice_vc_isvalid_q_id
 * @vf: pointer to the VF info
 * @vsi_id: VSI ID
 * @qid: VSI relative queue ID
 *
 * check for the valid queue ID
 */
static bool ice_vc_isvalid_q_id(struct ice_vf *vf, u16 vsi_id, u8 qid)
{
	struct ice_vsi *vsi = ice_find_vsi_from_id(vf->pf, vsi_id);
	/* allocated Tx and Rx queues should be always equal for VF VSI */
	return (vsi && (qid < vsi->alloc_txq));
}

/**
 * ice_vc_isvalid_ring_len
 * @ring_len: length of ring
 *
 * check for the valid ring count, should be multiple of ICE_REQ_DESC_MULTIPLE
 * or zero
 */
static bool ice_vc_isvalid_ring_len(u16 ring_len)
{
	return ring_len == 0 ||
	       (ring_len >= ICE_MIN_NUM_DESC &&
		ring_len <= ICE_MAX_NUM_DESC &&
		!(ring_len % ICE_REQ_DESC_MULTIPLE));
}

/**
 * ice_vc_config_rss_key
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Configure the VF's RSS key
 */
static int ice_vc_config_rss_key(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_rss_key *vrk =
		(struct virtchnl_rss_key *)msg;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vrk->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (vrk->key_len != ICE_VSIQF_HKEY_ARRAY_SIZE) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!test_bit(ICE_FLAG_RSS_ENA, vf->pf->flags)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (ice_set_rss(vsi, vrk->key, NULL, 0))
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_RSS_KEY, v_ret,
				     NULL, 0);
}

/**
 * ice_vc_config_rss_lut
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Configure the VF's RSS LUT
 */
static int ice_vc_config_rss_lut(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_rss_lut *vrl = (struct virtchnl_rss_lut *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vrl->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (vrl->lut_entries != ICE_VSIQF_HLUT_ARRAY_SIZE) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!test_bit(ICE_FLAG_RSS_ENA, vf->pf->flags)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (ice_set_rss(vsi, NULL, vrl->lut, ICE_VSIQF_HLUT_ARRAY_SIZE))
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_RSS_LUT, v_ret,
				     NULL, 0);
}

/**
 * ice_set_vf_spoofchk
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @ena: flag to enable or disable feature
 *
 * Enable or disable VF spoof checking
 */
int ice_set_vf_spoofchk(struct net_device *netdev, int vf_id, bool ena)
{
	struct ice_netdev_priv *np = netdev_priv(netdev);
	struct ice_pf *pf = np->vsi->back;
	struct ice_vsi_ctx *ctx;
	struct ice_vsi *vf_vsi;
	enum ice_status status;
	struct device *dev;
	struct ice_vf *vf;
	int ret = 0;

	dev = ice_pf_to_dev(pf);
	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];

	if (ice_check_vf_init(pf, vf))
		return -EBUSY;

	vf_vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vf_vsi) {
		netdev_err(netdev, "VSI %d for VF %d is null\n",
			   vf->lan_vsi_idx, vf->vf_id);
		return -EINVAL;
	}

	if (vf_vsi->type != ICE_VSI_VF) {
		netdev_err(netdev, "Type %d of VSI %d for VF %d is no ICE_VSI_VF\n",
			   vf_vsi->type, vf_vsi->vsi_num, vf->vf_id);
		return -ENODEV;
	}

	if (ena == vf->spoofchk) {
		dev_dbg(dev, "VF spoofchk already %s\n", ena ? "ON" : "OFF");
		return 0;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->info.sec_flags = vf_vsi->info.sec_flags;
	ctx->info.valid_sections = cpu_to_le16(ICE_AQ_VSI_PROP_SECURITY_VALID);
	if (ena) {
		ctx->info.sec_flags |=
			ICE_AQ_VSI_SEC_FLAG_ENA_MAC_ANTI_SPOOF |
			(ICE_AQ_VSI_SEC_TX_VLAN_PRUNE_ENA <<
			 ICE_AQ_VSI_SEC_TX_PRUNE_ENA_S);
	} else {
		ctx->info.sec_flags &=
			~(ICE_AQ_VSI_SEC_FLAG_ENA_MAC_ANTI_SPOOF |
			  (ICE_AQ_VSI_SEC_TX_VLAN_PRUNE_ENA <<
			   ICE_AQ_VSI_SEC_TX_PRUNE_ENA_S));
	}

	status = ice_update_vsi(&pf->hw, vf_vsi->idx, ctx, NULL);
	if (status) {
		dev_err(dev, "Failed to %sable spoofchk on VF %d VSI %d\n error %d\n",
			ena ? "en" : "dis", vf->vf_id, vf_vsi->vsi_num, status);
		ret = -EIO;
		goto out;
	}

	/* only update spoofchk state and VSI context on success */
	vf_vsi->info.sec_flags = ctx->info.sec_flags;
	vf->spoofchk = ena;

out:
	kfree(ctx);
	return ret;
}

/**
 * ice_is_any_vf_in_promisc - check if any VF(s) are in promiscuous mode
 * @pf: PF structure for accessing VF(s)
 *
 * Return false if no VF(s) are in unicast and/or multicast promiscuous mode,
 * else return true
 */
bool ice_is_any_vf_in_promisc(struct ice_pf *pf)
{
	int vf_idx;

	ice_for_each_vf(pf, vf_idx) {
		struct ice_vf *vf = &pf->vf[vf_idx];

		/* found a VF that has promiscuous mode configured */
		if (test_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states) ||
		    test_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states))
			return true;
	}

	return false;
}

/**
 * ice_vc_cfg_promiscuous_mode_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to configure VF VSIs promiscuous mode
 */
static int ice_vc_cfg_promiscuous_mode_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_promisc_info *info =
	    (struct virtchnl_promisc_info *)msg;
	enum ice_status status = 0;
	struct ice_pf *pf = vf->pf;
	bool rm_promisc = false;
	struct ice_vsi *vsi;
	struct device *dev;
	u8 promisc_m = 0;
	int ret = 0;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, info->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	dev = ice_pf_to_dev(pf);
	if (!test_bit(ICE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps)) {
		dev_err(dev, "Unprivileged VF %d is attempting to configure promiscuous mode\n",
			vf->vf_id);
		/* Leave v_ret alone, lie to the VF on purpose. */
		goto error_param;
	}

	rm_promisc = !(info->flags & FLAG_VF_UNICAST_PROMISC) &&
		!(info->flags & FLAG_VF_MULTICAST_PROMISC);

	if (vsi->num_vlan || vf->port_vlan_info) {
		struct ice_vsi *pf_vsi = ice_get_main_vsi(pf);
		struct net_device *pf_netdev;

		if (!pf_vsi) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		pf_netdev = pf_vsi->netdev;

		ret = ice_set_vf_spoofchk(pf_netdev, vf->vf_id, rm_promisc);
		if (ret) {
			dev_err(ice_pf_to_dev(vsi->back), "Failed to update spoofchk to %s for VF %d VSI %d when setting promiscuous mode\n",
				rm_promisc ? "ON" : "OFF", vf->vf_id,
				vsi->vsi_num);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		}

		ret = ice_cfg_vlan_pruning(vsi, true, !rm_promisc);
		if (ret) {
			dev_err(dev, "Failed to configure VLAN pruning in promiscuous mode\n");
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}
	}

	if (!test_bit(ICE_FLAG_VF_TRUE_PROMISC_ENA, pf->flags)) {
		bool set_dflt_vsi = !!(info->flags & FLAG_VF_UNICAST_PROMISC);

		if (set_dflt_vsi && !ice_is_dflt_vsi_in_use(pf->first_sw))
			/* only attempt to set the default forwarding VSI if
			 * it's not currently set
			 */
			ret = ice_set_dflt_vsi(pf->first_sw, vsi);
		else if (!set_dflt_vsi &&
			 ice_is_vsi_dflt_vsi(pf->first_sw, vsi))
			/* only attempt to free the default forwarding VSI if we
			 * are the owner
			 */
			ret = ice_clear_dflt_vsi(pf->first_sw);

		if (ret) {
			dev_err(dev, "%sable VF %d as the default VSI failed, error %d\n",
				set_dflt_vsi ? "en" : "dis", vf->vf_id, ret);
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
			goto error_param;
		}
	} else {
		if (info->flags & FLAG_VF_UNICAST_PROMISC) {
			if (vf->port_vlan_info || vsi->num_vlan)
				promisc_m = ICE_UCAST_VLAN_PROMISC_BITS;
			else
				promisc_m = ICE_UCAST_PROMISC_BITS;
		} else if (info->flags & FLAG_VF_MULTICAST_PROMISC) {
			if (vf->port_vlan_info || vsi->num_vlan)
				promisc_m = ICE_MCAST_VLAN_PROMISC_BITS;
			else
				promisc_m = ICE_MCAST_PROMISC_BITS;
		} else {
			if (vf->port_vlan_info || vsi->num_vlan)
				promisc_m = ICE_UCAST_VLAN_PROMISC_BITS;
			else
				promisc_m = ICE_UCAST_PROMISC_BITS;
		}

		/* Configure multicast/unicast with or without VLAN promiscuous
		 * mode
		 */
		status = ice_vf_set_vsi_promisc(vf, vsi, promisc_m, rm_promisc);
		if (status) {
			dev_err(dev, "%sable Tx/Rx filter promiscuous mode on VF-%d failed, error: %d\n",
				rm_promisc ? "dis" : "en", vf->vf_id, status);
			v_ret = ice_err_to_virt_err(status);
			goto error_param;
		} else {
			dev_dbg(dev, "%sable Tx/Rx filter promiscuous mode on VF-%d succeeded\n",
				rm_promisc ? "dis" : "en", vf->vf_id);
		}
	}

	if (info->flags & FLAG_VF_MULTICAST_PROMISC)
		set_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states);
	else
		clear_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states);

	if (info->flags & FLAG_VF_UNICAST_PROMISC)
		set_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states);
	else
		clear_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states);

error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_get_stats_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to get VSI stats
 */
static int ice_vc_get_stats_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_queue_select *vqs =
		(struct virtchnl_queue_select *)msg;
	struct ice_eth_stats stats = { 0 };
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vqs->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	ice_update_eth_stats(vsi);

	stats = vsi->eth_stats;

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_STATS, v_ret,
				     (u8 *)&stats, sizeof(stats));
}

/**
 * ice_vf_q_id_get_vsi_q_id
 * @vf: pointer to the VF info
 * @vf_q_id: VF relitive queue ID
 * @t_tc: traffic class for indexing the VSIs
 * @vqs: the VFs virtual queue selection
 * @vsi_p: pointer to VSI pointer, which changes based on TC for ADQ
 * @t_v_id: VSI ID of the queue ID
 * @t_q_id: queue ID of the VSI
 *
 * Provides ADQ queue enablement support by mapping the VF queue ID and TC to
 * VSI ID and queue ID. Call while iterating through VF queue IDs, VF VSIs and
 * TCs.
 */
static void ice_vf_q_id_get_vsi_q_id(struct ice_vf *vf, u16 vf_q_id, u16 *t_tc,
				     struct virtchnl_queue_select *vqs,
				     struct ice_vsi **vsi_p, u16 *t_v_id,
				     u16 *t_q_id)
{
	struct ice_vsi *vsi = *vsi_p;
	u32 max_chnl_tc;
	u16 tc = *t_tc;

	max_chnl_tc = ice_vc_get_max_chnl_tc_allowed(vf);

	/* If VF queue ID is not included in primary VF VSI (TC0 queues 0-3),
	 * then get the next VSI allocated to the VF.
	 */
	if (tc + 1 < max_chnl_tc && vf_q_id == vf->ch[tc + 1].offset &&
	    tc < vf->num_tc) {
		vsi = vf->pf->vsi[vf->ch[tc + 1].vsi_idx];
		tc++;
	}

	/* If TC is non-zero and ADQ is enabled, then the VF queue ID is for a
	 * non-primary VSIs.
	 */
	if (tc && vf->adq_enabled && vf->num_tc) {
		*t_v_id = vsi->vsi_num;
		*t_q_id = vf_q_id % vf->ch[tc].offset;
	} else {
		*t_v_id = vqs->vsi_id;
		*t_q_id = vf_q_id;
	}

	*vsi_p = vsi;
	*t_tc = tc;
}

/**
 * ice_vc_validate_vqs_bitmaps - validate Rx/Tx queue bitmaps from VIRTCHNL
 * @vqs: virtchnl_queue_select structure containing bitmaps to validate
 *
 * Return true on successful validation, else false
 */
static bool ice_vc_validate_vqs_bitmaps(struct virtchnl_queue_select *vqs)
{
	if ((!vqs->rx_queues && !vqs->tx_queues) ||
	    vqs->rx_queues >= BIT(ICE_MAX_RSS_QS_PER_VF) ||
	    vqs->tx_queues >= BIT(ICE_MAX_RSS_QS_PER_VF))
		return false;

	return true;
}

/**
 * ice_vc_ena_qs_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to enable all or specific queue(s)
 */
static int ice_vc_ena_qs_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_queue_select *vqs =
	    (struct virtchnl_queue_select *)msg;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	unsigned long q_map;
	u16 v_id, q_id = 0;
	u16 vf_q_id = 0;
	u16 tc = 0;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vqs->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_validate_vqs_bitmaps(vqs)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	/* Enable only Rx rings, Tx rings were enabled by the FW when the
	 * Tx queue group list was configured and the context bits were
	 * programmed using ice_vsi_cfg_txqs
	 */
	q_map = vqs->rx_queues;
	for_each_set_bit(vf_q_id, &q_map, ICE_MAX_RSS_QS_PER_VF) {
		ice_vf_q_id_get_vsi_q_id(vf, vf_q_id, &tc, vqs, &vsi,
					 &v_id, &q_id);

		if (!ice_vc_isvalid_q_id(vf, v_id, q_id)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		/* Skip queue if enabled */
		if (test_bit(vf_q_id, vf->rxq_ena))
			continue;

		if (ice_vsi_ctrl_one_rx_ring(vsi, true, q_id, true)) {
			dev_err(ice_pf_to_dev(vsi->back), "Failed to enable Rx ring %d on VSI %d\n",
				vf_q_id, vsi->vsi_num);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		set_bit(vf_q_id, vf->rxq_ena);
	}

	tc = 0;
	vsi = pf->vsi[vf->lan_vsi_idx];
	q_map = vqs->tx_queues;
	for_each_set_bit(vf_q_id, &q_map, ICE_MAX_RSS_QS_PER_VF) {
		ice_vf_q_id_get_vsi_q_id(vf, vf_q_id, &tc, vqs, &vsi,
					 &v_id, &q_id);

		if (!ice_vc_isvalid_q_id(vf, v_id, q_id)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		/* Skip queue if enabled */
		if (test_bit(vf_q_id, vf->txq_ena))
			continue;

		set_bit(vf_q_id, vf->txq_ena);
	}

	/* Set flag to indicate that queues are enabled */
	if (v_ret == VIRTCHNL_STATUS_SUCCESS)
		set_bit(ICE_VF_STATE_QS_ENA, vf->vf_states);

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_QUEUES, v_ret,
				     NULL, 0);
}

/**
 * ice_vc_dis_qs_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to disable all or specific
 * queue(s)
 */
static int ice_vc_dis_qs_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_queue_select *vqs =
	    (struct virtchnl_queue_select *)msg;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	unsigned long q_map;
	u16 vf_q_id;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states) &&
	    !test_bit(ICE_VF_STATE_QS_ENA, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vqs->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_validate_vqs_bitmaps(vqs)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (vqs->tx_queues) {
		q_map = vqs->tx_queues;

		for_each_set_bit(vf_q_id, &q_map, ICE_MAX_RSS_QS_PER_VF) {
			struct ice_ring *ring = vsi->tx_rings[vf_q_id];
			struct ice_txq_meta txq_meta = { 0 };

			if (!ice_vc_isvalid_q_id(vf, vqs->vsi_id, vf_q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			/* Skip queue if not enabled */
			if (!test_bit(vf_q_id, vf->txq_ena))
				continue;

			ice_fill_txq_meta(vsi, ring, &txq_meta);

			if (ice_vsi_stop_tx_ring(vsi, ICE_NO_RESET, vf->vf_id,
						 ring, &txq_meta)) {
				dev_err(ice_pf_to_dev(vsi->back), "Failed to stop Tx ring %d on VSI %d\n",
					vf_q_id, vsi->vsi_num);
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			/* Clear enabled queues flag */
			clear_bit(vf_q_id, vf->txq_ena);
		}
	}

	q_map = vqs->rx_queues;
	/* speed up Rx queue disable by batching them if possible */
	if (q_map &&
	    bitmap_equal(&q_map, vf->rxq_ena, ICE_MAX_RSS_QS_PER_VF)) {
		if (ice_vsi_stop_all_rx_rings(vsi)) {
			dev_err(ice_pf_to_dev(vsi->back), "Failed to stop all Rx rings on VSI %d\n",
				vsi->vsi_num);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		bitmap_zero(vf->rxq_ena, ICE_MAX_RSS_QS_PER_VF);
	} else if (q_map) {
		for_each_set_bit(vf_q_id, &q_map, ICE_MAX_RSS_QS_PER_VF) {
			if (!ice_vc_isvalid_q_id(vf, vqs->vsi_id, vf_q_id)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			/* Skip queue if not enabled */
			if (!test_bit(vf_q_id, vf->rxq_ena))
				continue;

			if (ice_vsi_ctrl_one_rx_ring(vsi, false, vf_q_id,
						     true)) {
				dev_err(ice_pf_to_dev(vsi->back), "Failed to stop Rx ring %d on VSI %d\n",
					vf_q_id, vsi->vsi_num);
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			/* Clear enabled queues flag */
			clear_bit(vf_q_id, vf->rxq_ena);
		}
	}

	/* Clear enabled queues flag */
	if (v_ret == VIRTCHNL_STATUS_SUCCESS && ice_vf_has_no_qs_ena(vf))
		clear_bit(ICE_VF_STATE_QS_ENA, vf->vf_states);

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_QUEUES, v_ret,
				     NULL, 0);
}

/**
 * ice_cfg_interrupt
 * @vf: pointer to the VF info
 * @vsi: the VSI being configured
 * @vector_id: vector ID
 * @tc: traffic class number for ADQ
 * @map: vector map for mapping vectors to queues
 * @q_vector: structure for interrupt vector
 * configure the IRQ to queue map
 */
static int
ice_cfg_interrupt(struct ice_vf *vf, struct ice_vsi *vsi, u16 vector_id,
		  u8 __maybe_unused tc, struct virtchnl_vector_map *map,
		  struct ice_q_vector *q_vector)
{
	u16 vsi_q_id, vsi_q_id_idx;
	unsigned long qmap;

	q_vector->num_ring_rx = 0;
	q_vector->num_ring_tx = 0;

	qmap = map->rxq_map;
	for_each_set_bit(vsi_q_id_idx, &qmap, ICE_MAX_RSS_QS_PER_VF) {
		if (tc && vf->adq_enabled && vf->num_tc)
			vsi_q_id = vsi_q_id_idx % vf->ch[tc].offset;
		else
			vsi_q_id = vsi_q_id_idx;

		if (!ice_vc_isvalid_q_id(vf, vsi->vsi_num, vsi_q_id))
			return VIRTCHNL_STATUS_ERR_PARAM;

		q_vector->num_ring_rx++;
		q_vector->rx.itr_idx = map->rxitr_idx;
		vsi->rx_rings[vsi_q_id]->q_vector = q_vector;
		ice_cfg_rxq_interrupt(vsi, vsi_q_id, vector_id,
				      q_vector->rx.itr_idx);
	}

	qmap = map->txq_map;
	for_each_set_bit(vsi_q_id_idx, &qmap, ICE_MAX_RSS_QS_PER_VF) {
		if (tc && vf->adq_enabled && vf->num_tc)
			vsi_q_id = vsi_q_id_idx % vf->ch[tc].offset;
		else
			vsi_q_id = vsi_q_id_idx;

		if (!ice_vc_isvalid_q_id(vf, vsi->vsi_num, vsi_q_id))
			return VIRTCHNL_STATUS_ERR_PARAM;

		q_vector->num_ring_tx++;
		q_vector->tx.itr_idx = map->txitr_idx;
		vsi->tx_rings[vsi_q_id]->q_vector = q_vector;
		ice_cfg_txq_interrupt(vsi, vsi_q_id, vector_id,
				      q_vector->tx.itr_idx);
	}

	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_vc_cfg_irq_map_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to configure the IRQ to queue map
 */
static int ice_vc_cfg_irq_map_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	u16 num_q_vectors_mapped, tc = 0, v_id, vector_id;
	struct virtchnl_irq_map_info *irqmap_info;
	struct virtchnl_vector_map *map;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	u16 vector_id_ch;
	int i;

	irqmap_info = (struct virtchnl_irq_map_info *)msg;
	num_q_vectors_mapped = irqmap_info->num_vectors;

	/* Check to make sure number of VF vectors mapped is not greater than
	 * number of VF vectors originally allocated, and check that
	 * there is actually at least a single VF queue vector mapped
	 */
	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states) ||
	    pf->num_vf_msix < num_q_vectors_mapped ||
	    !num_q_vectors_mapped) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < num_q_vectors_mapped; i++) {
		struct ice_q_vector *q_vector;

		map = &irqmap_info->vecmap[i];

		vector_id = map->vector_id;
		v_id = map->vsi_id;
		/* vector_id is always 0-based for each VF, and can never be
		 * larger than or equal to the max allowed interrupts per VF
		 */
		if (!(vector_id < pf->num_vf_msix) ||
		    !ice_vc_isvalid_vsi_id(vf, v_id) ||
		    (!vector_id && (map->rxq_map || map->txq_map))) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		/* No need to map VF miscellaneous or rogue vector */
		if (!vector_id)
			continue;

		/* Subtract non queue vector from vector_id passed by VF
		 * to get actual number of VSI queue vector array index
		 */
		if (tc && vf->adq_enabled && vf->num_tc)
			vector_id_ch = vector_id - vf->ch[tc].offset;
		else
			vector_id_ch = vector_id;

		q_vector = vsi->q_vectors[vector_id_ch - ICE_NONQ_VECS_VF];
		if (!q_vector) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

		/* lookout for the invalid queue index */

		v_ret = (enum virtchnl_status_code)ice_cfg_interrupt(vf,
								     vsi,
								     vector_id,
								     tc,
								     map,
								     q_vector);
		if (v_ret)
			goto error_param;

		if (vector_id == vf->ch[tc + 1].offset) {
			vsi = pf->vsi[vf->ch[tc + 1].vsi_idx];
			tc++;
		}
	}

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_IRQ_MAP, v_ret,
				     NULL, 0);
}

/**
 * ice_vc_cfg_qs_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * called from the VF to configure the Rx/Tx queues
 */
static int ice_vc_cfg_qs_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vsi_queue_config_info *qci =
	    (struct virtchnl_vsi_queue_config_info *)msg;
	struct virtchnl_queue_pair_info *qpi;
	u16 num_rxq = 0, num_txq = 0;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	u16 j = 0, idx = 0;
	int i, q_idx;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, qci->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	/* check for number of queues is done in ice_alloc_vf_res() function
	 * for ADQ
	 */
	if (vf->adq_enabled && vf->num_tc)
		goto skip_num_queues_check;

	if (qci->num_queue_pairs > ICE_MAX_RSS_QS_PER_VF ||
	    qci->num_queue_pairs > min_t(u16, vsi->alloc_txq, vsi->alloc_rxq)) {
		dev_err(ice_pf_to_dev(pf), "VF-%d requesting more than supported number of queues: %d\n",
			vf->vf_id, min_t(u16, vsi->alloc_txq, vsi->alloc_rxq));
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

skip_num_queues_check:
	for (i = 0; i < qci->num_queue_pairs; i++) {
		qpi = &qci->qpair[i];
		if (vf->adq_enabled && vf->num_tc)
			goto skip_non_adq_checks;

		if (qpi->txq.vsi_id != qci->vsi_id ||
		    qpi->rxq.vsi_id != qci->vsi_id ||
		    qpi->rxq.queue_id != qpi->txq.queue_id ||
		    qpi->txq.headwb_enabled ||
		    !ice_vc_isvalid_ring_len(qpi->txq.ring_len) ||
		    !ice_vc_isvalid_ring_len(qpi->rxq.ring_len) ||
		    !ice_vc_isvalid_q_id(vf, qci->vsi_id,
					 qpi->txq.queue_id)) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto error_param;
		}

skip_non_adq_checks:
		if (vf->adq_enabled && vf->num_tc) {
			q_idx = j;
			vsi = ice_find_vsi_from_id(vf->pf, vf->ch[idx].vsi_num);
			if (!vsi) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		} else {
			q_idx = i;
		}

		/* copy Tx queue info from VF into VSI */
		if (qpi->txq.ring_len > 0) {
			num_txq++;
			vsi->tx_rings[q_idx]->dma = qpi->txq.dma_ring_addr;
			vsi->tx_rings[q_idx]->count = qpi->txq.ring_len;
		}

		/* copy Rx queue info from VF into VSI */
		if (qpi->rxq.ring_len > 0) {
			num_rxq++;
			vsi->rx_rings[q_idx]->dma = qpi->rxq.dma_ring_addr;
			vsi->rx_rings[q_idx]->count = qpi->rxq.ring_len;

			if (qpi->rxq.databuffer_size != 0 &&
			    (qpi->rxq.databuffer_size > ((16 * 1024) - 128) ||
			     qpi->rxq.databuffer_size < 1024)) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
			vsi->rx_buf_len = qpi->rxq.databuffer_size;
			vsi->rx_rings[q_idx]->rx_buf_len = vsi->rx_buf_len;
			if (qpi->rxq.max_pkt_size >= (16 * 1024) ||
			    qpi->rxq.max_pkt_size < 64) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
		}

		vsi->max_frame = qpi->rxq.max_pkt_size;

		/* For ADQ there can be up to 4 VSIs with max 4 queues each.
		 * VF does not know about these additional VSIs and all
		 * it cares is about its own queues. PF configures these queues
		 * to its appropriate VSIs based on TC mapping
		 */
		if (vf->adq_enabled && vf->num_tc) {
			if (j == (vf->ch[idx].num_qps - 1)) {
				idx++;
				j = 0; /* resetting the queue count */
			} else {
				j++;
			}
		}
	}

	/* VF can request to configure less than allocated queues
	 * or default allocated queues. So update the VSI with new number
	 */
	if (vf->adq_enabled && vf->num_tc) {
		for (i = 0; i < vf->num_tc; i++) {
			vsi = ice_find_vsi_from_id(vf->pf, vf->ch[i].vsi_num);
			if (!vsi) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}
			vsi->num_txq = vf->ch[i].num_qps;
			vsi->num_rxq = vf->ch[i].num_qps;
			/* All queues of VF VSI are in TC 0 */
			vsi->tc_cfg.tc_info[0].qcount_tx = vf->ch[i].num_qps;
			vsi->tc_cfg.tc_info[0].qcount_rx = vf->ch[i].num_qps;

			if (ice_vsi_cfg_lan_txqs(vsi) || ice_vsi_cfg_rxqs(vsi))
				v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		}
	} else {
		vsi->num_txq = num_txq;
		vsi->num_rxq = num_rxq;
		/* All queues of VF VSI are in TC 0 */
		vsi->tc_cfg.tc_info[0].qcount_tx = num_txq;
		vsi->tc_cfg.tc_info[0].qcount_rx = num_rxq;

		if (ice_vsi_cfg_lan_txqs(vsi) || ice_vsi_cfg_rxqs(vsi))
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
	}

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_CONFIG_VSI_QUEUES, v_ret,
				     NULL, 0);
}

/**
 * ice_is_vf_trusted
 * @vf: pointer to the VF info
 */
static bool ice_is_vf_trusted(struct ice_vf *vf)
{
	return test_bit(ICE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps);
}

/**
 * ice_can_vf_change_mac
 * @vf: pointer to the VF info
 *
 * Return true if the VF is allowed to change its MAC filters, false otherwise
 */
static bool ice_can_vf_change_mac(struct ice_vf *vf)
{
	/* If the VF MAC address has been set administratively (via the
	 * ndo_set_vf_mac command), then deny permission to the VF to
	 * add/delete unicast MAC addresses, unless the VF is trusted
	 */
	if (vf->pf_set_mac && !ice_is_vf_trusted(vf))
		return false;

	return true;
}

/**
 * ice_vc_add_mac_addr - attempt to add the MAC address passed in
 * @vf: pointer to the VF info
 * @vsi: pointer to the VF's VSI
 * @mac_addr: MAC address to add
 */
static int
ice_vc_add_mac_addr(struct ice_vf *vf, struct ice_vsi *vsi, u8 *mac_addr)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	enum ice_status status;

	/* default unicast MAC already added */
	if (ether_addr_equal(mac_addr, vf->dflt_lan_addr.addr))
		return 0;

	if (is_unicast_ether_addr(mac_addr) && !ice_can_vf_change_mac(vf)) {
		dev_err(dev, "VF attempting to override administratively set MAC address, bring down and up the VF interface to resume normal operation\n");
		return 0;
	}

	status = ice_vsi_cfg_mac_fltr(vsi, mac_addr, true);
	if (status == ICE_ERR_ALREADY_EXISTS) {
		dev_dbg(dev, "MAC %pM already exists for VF %d\n", mac_addr,
			vf->vf_id);
		return -EEXIST;
	} else if (status) {
		dev_err(dev, "Failed to add MAC %pM for VF %d\n, error %d\n",
			mac_addr, vf->vf_id, status);
		return -EIO;
	}

	/* only set dflt_lan_addr once */
	if (is_zero_ether_addr(vf->dflt_lan_addr.addr) &&
	    is_unicast_ether_addr(mac_addr))
		ether_addr_copy(vf->dflt_lan_addr.addr, mac_addr);

	vf->num_mac++;

	return 0;
}

/**
 * ice_vc_del_mac_addr - attempt to delete the MAC address passed in
 * @vf: pointer to the VF info
 * @vsi: pointer to the VF's VSI
 * @mac_addr: MAC address to delete
 */
static int
ice_vc_del_mac_addr(struct ice_vf *vf, struct ice_vsi *vsi, u8 *mac_addr)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	enum ice_status status;

	if (!ice_can_vf_change_mac(vf) &&
	    ether_addr_equal(mac_addr, vf->dflt_lan_addr.addr))
		return 0;

	status = ice_vsi_cfg_mac_fltr(vsi, mac_addr, false);
	if (status == ICE_ERR_DOES_NOT_EXIST) {
		dev_dbg(dev, "MAC %pM does not exist for VF %d\n", mac_addr,
			vf->vf_id);
		return -ENOENT;
	} else if (status) {
		dev_err(dev, "Failed to delete MAC %pM for VF %d, error %d\n",
			mac_addr, vf->vf_id, status);
		return -EIO;
	}

	if (ether_addr_equal(mac_addr, vf->dflt_lan_addr.addr))
		eth_zero_addr(vf->dflt_lan_addr.addr);

	vf->num_mac--;

	return 0;
}

/**
 * ice_vc_handle_mac_addr_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 * @set: true if MAC filters are being set, false otherwise
 *
 * add guest MAC address filter
 */
static int
ice_vc_handle_mac_addr_msg(struct ice_vf *vf, u8 *msg, bool set)
{
	int (*ice_vc_cfg_mac)
		(struct ice_vf *vf, struct ice_vsi *vsi, u8 *mac_addr);
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_ether_addr_list *al =
	    (struct virtchnl_ether_addr_list *)msg;
	struct ice_pf *pf = vf->pf;
	enum virtchnl_ops vc_op;
	struct ice_vsi *vsi;
	int i;

	if (set) {
		vc_op = VIRTCHNL_OP_ADD_ETH_ADDR;
		ice_vc_cfg_mac = ice_vc_add_mac_addr;
	} else {
		vc_op = VIRTCHNL_OP_DEL_ETH_ADDR;
		ice_vc_cfg_mac = ice_vc_del_mac_addr;
	}

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states) ||
	    !ice_vc_isvalid_vsi_id(vf, al->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto handle_mac_exit;
	}

	if (set && !ice_is_vf_trusted(vf) &&
	    (vf->num_mac + al->num_elements) > ICE_MAX_MACADDR_PER_VF) {
		dev_err(ice_pf_to_dev(pf), "Can't add more MAC addresses, because VF-%d is not trusted, switch the VF to trusted mode in order to add more functionalities\n",
			vf->vf_id);
		/* There is no need to let VF know about not being trusted
		 * to add more MAC addr, so we can just return success message.
		 */
		v_ret = VIRTCHNL_STATUS_SUCCESS;
		goto handle_mac_exit;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto handle_mac_exit;
	}

	for (i = 0; i < al->num_elements; i++) {
		u8 *mac_addr = al->list[i].addr;
		int result;

		if (is_broadcast_ether_addr(mac_addr) ||
		    is_zero_ether_addr(mac_addr))
			continue;

		result = ice_vc_cfg_mac(vf, vsi, mac_addr);
		if (result == -EEXIST || result == -ENOENT) {
			continue;
		} else if (result) {
			v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
			goto handle_mac_exit;
		}
	}

handle_mac_exit:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, vc_op, v_ret, NULL, 0);
}

/**
 * ice_vc_add_mac_addr_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * add guest MAC address filter
 */
static int ice_vc_add_mac_addr_msg(struct ice_vf *vf, u8 *msg)
{
	return ice_vc_handle_mac_addr_msg(vf, msg, true);
}

/**
 * ice_vc_del_mac_addr_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * remove guest MAC address filter
 */
static int ice_vc_del_mac_addr_msg(struct ice_vf *vf, u8 *msg)
{
	return ice_vc_handle_mac_addr_msg(vf, msg, false);
}

/**
 * ice_vc_request_qs_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * VFs get a default number of queues but can use this message to request a
 * different number. If the request is successful, PF will reset the VF and
 * return 0. If unsuccessful, PF will send message informing VF of number of
 * available queue pairs via virtchnl message response to VF.
 */
static int ice_vc_request_qs_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vf_res_request *vfres =
		(struct virtchnl_vf_res_request *)msg;
	u16 req_queues = vfres->num_queue_pairs;
	struct ice_pf *pf = vf->pf;
	u16 max_allowed_vf_queues;
	u16 tx_rx_queue_left;
	u16 cur_queues;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	cur_queues = vf->num_vf_qs;
	tx_rx_queue_left = min_t(u16, ice_get_avail_txq_count(pf),
				 ice_get_avail_rxq_count(pf));
	max_allowed_vf_queues = tx_rx_queue_left + cur_queues;
	if (!req_queues) {
		dev_err(dev, "VF %d tried to request 0 queues. Ignoring.\n",
			vf->vf_id);
	} else if (req_queues > ICE_MAX_RSS_QS_PER_VF) {
		dev_err(dev, "VF %d tried to request more than %d queues.\n",
			vf->vf_id, ICE_MAX_RSS_QS_PER_VF);
		vfres->num_queue_pairs = ICE_MAX_RSS_QS_PER_VF;
	} else if (req_queues > cur_queues &&
		   req_queues - cur_queues > tx_rx_queue_left) {
		dev_warn(dev, "VF %d requested %u more queues, but only %u left.\n",
			 vf->vf_id, req_queues - cur_queues, tx_rx_queue_left);
		vfres->num_queue_pairs = min_t(u16, max_allowed_vf_queues,
					       ICE_MAX_RSS_QS_PER_VF);
	} else {
		/* request is successful, then reset VF */
		vf->num_req_qs = req_queues;
		ice_vc_reset_vf(vf);
		dev_info(dev, "VF %d granted request of %u queues.\n",
			 vf->vf_id, req_queues);
		return 0;
	}

error_param:
	/* send the response to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_REQUEST_QUEUES,
				     v_ret, (u8 *)vfres, sizeof(*vfres));
}

#ifdef IFLA_VF_VLAN_INFO_MAX
/**
 * ice_set_vf_port_vlan
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @vlan_id: VLAN ID being set
 * @qos: priority setting
 * @vlan_proto: VLAN protocol
 *
 * program VF Port VLAN ID and/or QoS
 */
int
ice_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id, u8 qos,
		     __be16 vlan_proto)
#else
int
ice_set_vf_port_vlan(struct net_device *netdev, int vf_id, u16 vlan_id, u8 qos)
#endif /* IFLA_VF_VLAN_INFO_MAX */
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_vf *vf;
	u16 vlanprio;
	int ret = 0;

	dev = ice_pf_to_dev(pf);
	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	if (vlan_id >= VLAN_N_VID || qos > 7) {
		dev_err(dev, "Invalid Port VLAN parameters for VF %d, ID %d, QoS %d\n",
			vf_id, vlan_id, qos);
		return -EINVAL;
	}

#ifdef IFLA_VF_VLAN_INFO_MAX
	if (vlan_proto != htons(ETH_P_8021Q)) {
		dev_err(dev, "VF VLAN protocol is not supported\n");
		return -EPROTONOSUPPORT;
	}
#endif

	vf = &pf->vf[vf_id];
	vsi = pf->vsi[vf->lan_vsi_idx];
	if (ice_check_vf_init(pf, vf))
		return -EBUSY;

	vlanprio = vlan_id | (qos << VLAN_PRIO_SHIFT);

	if (vf->port_vlan_info == vlanprio) {
		/* duplicate request, so just return success */
		dev_dbg(dev, "Duplicate pvid %d request\n", vlanprio);
		return ret;
	}

	if (vlan_id || qos) {
		/* remove VLAN 0 filter set by default when transitioning from
		 * no port VLAN to a port VLAN. No change to old port VLAN on
		 * failure.
		 */
		ret = ice_vsi_kill_vlan(vsi, 0);
		if (ret)
			return ret;
		ret = ice_vsi_manage_pvid(vsi, vlanprio, true);
		if (ret)
			return ret;
	} else {
		/* add VLAN 0 filter back when transitioning from port VLAN to
		 * no port VLAN. No change to old port VLAN on failure.
		 */
		ret = ice_vsi_add_vlan(vsi, 0, ICE_FWD_TO_VSI);
		if (ret)
			return ret;
		ret = ice_vsi_manage_pvid(vsi, 0, false);
		if (ret)
			goto error_manage_pvid;
	}

	if (vlan_id) {
		dev_info(dev, "Setting VLAN %d, QOS 0x%x on VF %d\n", vlan_id,
			 qos, vf_id);

		/* add VLAN filter for the port VLAN */
		ret = ice_vsi_add_vlan(vsi, vlan_id, ICE_FWD_TO_VSI);
		if (ret)
			goto error_manage_pvid;
	}
	/* remove old port VLAN filter with valid VLAN ID or QoS fields */
	if (vf->port_vlan_info)
		ice_vsi_kill_vlan(vsi, vf->port_vlan_info & VLAN_VID_MASK);

	/* keep port VLAN information persistent on resets */
	vf->port_vlan_info = le16_to_cpu(vsi->info.pvid);

error_manage_pvid:
	return ret;
}

/**
 * ice_vf_vlan_offload_ena - determine if capabilities support VLAN offloads
 * @caps: VF driver negotiated capabilities
 *
 * Return true if VIRTCHNL_VF_OFFLOAD_VLAN capability is set, else return false
 */
static bool ice_vf_vlan_offload_ena(u32 caps)
{
	return !!(caps & VIRTCHNL_VF_OFFLOAD_VLAN);
}

/**
 * ice_vc_process_vlan_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 * @add_v: Add VLAN if true, otherwise delete VLAN
 *
 * Process virtchnl op to add or remove programmed guest VLAN ID
 */
static int ice_vc_process_vlan_msg(struct ice_vf *vf, u8 *msg, bool add_v)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_vlan_filter_list *vfl =
	    (struct virtchnl_vlan_filter_list *)msg;
	struct ice_pf *pf = vf->pf;
	bool vlan_promisc = false;
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_hw *hw;
	int status = 0;
	u8 promisc_m;
	int i;

	dev = ice_pf_to_dev(pf);
	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vf_vlan_offload_ena(vf->driver_caps)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vc_isvalid_vsi_id(vf, vfl->vsi_id)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < vfl->num_elements; i++) {
		if (vfl->vlan_id[i] >= VLAN_N_VID) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			dev_err(dev, "invalid VF VLAN id %d\n",
				vfl->vlan_id[i]);
			goto error_param;
		}
	}

	hw = &pf->hw;
	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (add_v && !ice_is_vf_trusted(vf) &&
	    vsi->num_vlan >= ICE_MAX_VLAN_PER_VF) {
		dev_info(dev, "VF-%d is not trusted, switch the VF to trusted mode, in order to add more VLAN addresses\n",
			 vf->vf_id);
		/* There is no need to let VF know about being not trusted,
		 * so we can just return success message here
		 */
		goto error_param;
	}

	if (vsi->info.pvid) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if ((test_bit(ICE_VF_STATE_UC_PROMISC, vf->vf_states) ||
	     test_bit(ICE_VF_STATE_MC_PROMISC, vf->vf_states)) &&
	    test_bit(ICE_FLAG_VF_TRUE_PROMISC_ENA, pf->flags))
		vlan_promisc = true;

	if (add_v) {
		for (i = 0; i < vfl->num_elements; i++) {
			u16 vid = vfl->vlan_id[i];

			if (!ice_is_vf_trusted(vf) &&
			    vsi->num_vlan >= ICE_MAX_VLAN_PER_VF) {
				dev_info(dev, "VF-%d is not trusted, switch the VF to trusted mode, in order to add more VLAN addresses\n",
					 vf->vf_id);
				/* There is no need to let VF know about being
				 * not trusted, so we can just return success
				 * message here as well.
				 */
				goto error_param;
			}

			/* we add VLAN 0 by default for each VF so we can enable
			 * Tx VLAN anti-spoof without triggering MDD events so
			 * we don't need to add it again here
			 */
			if (!vid)
				continue;

			status = ice_vsi_add_vlan(vsi, vid, ICE_FWD_TO_VSI);
			if (status) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			/* Enable VLAN pruning when non-zero VLAN is added */
			if (!vlan_promisc && vid &&
			    !ice_vsi_is_vlan_pruning_ena(vsi)) {
				status = ice_cfg_vlan_pruning(vsi, true, false);
				if (status) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					dev_err(dev, "Enable VLAN pruning on VLAN ID: %d failed error-%d\n",
						vid, status);
					goto error_param;
				}
			} else if (vlan_promisc) {
				/* Enable Ucast/Mcast VLAN promiscuous mode */
				promisc_m = ICE_PROMISC_VLAN_TX |
					    ICE_PROMISC_VLAN_RX;

				status = ice_set_vsi_promisc(hw, vsi->idx,
							     promisc_m, vid);
				if (status) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					dev_err(dev, "Enable Unicast/multicast promiscuous mode on VLAN ID:%d failed error-%d\n",
						vid, status);
				}
			}
		}
	} else {
		/* In case of non_trusted VF, number of VLAN elements passed
		 * to PF for removal might be greater than number of VLANs
		 * filter programmed for that VF - So, use actual number of
		 * VLANS added earlier with add VLAN opcode. In order to avoid
		 * removing VLAN that doesn't exist, which result to sending
		 * erroneous failed message back to the VF
		 */
		int num_vf_vlan;

		num_vf_vlan = vsi->num_vlan;
		for (i = 0; i < vfl->num_elements && i < num_vf_vlan; i++) {
			u16 vid = vfl->vlan_id[i];

			/* we add VLAN 0 by default for each VF so we can enable
			 * Tx VLAN anti-spoof without triggering MDD events so
			 * we don't want a VIRTCHNL request to remove it
			 */
			if (!vid)
				continue;

			/* Make sure ice_vsi_kill_vlan is successful before
			 * updating VLAN information
			 */
			status = ice_vsi_kill_vlan(vsi, vid);
			if (status) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto error_param;
			}

			/* Disable VLAN pruning when only VLAN 0 is left */
			if (vsi->num_vlan == 1 &&
			    ice_vsi_is_vlan_pruning_ena(vsi))
				ice_cfg_vlan_pruning(vsi, false, false);

			/* Disable Unicast/Multicast VLAN promiscuous mode */
			if (vlan_promisc) {
				promisc_m = ICE_PROMISC_VLAN_TX |
					    ICE_PROMISC_VLAN_RX;

				ice_clear_vsi_promisc(hw, vsi->idx,
						      promisc_m, vid);
			}
		}
	}

error_param:
	/* send the response to the VF */
	if (add_v)
		return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ADD_VLAN, v_ret,
					     NULL, 0);
	else
		return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DEL_VLAN, v_ret,
					     NULL, 0);
}

/**
 * ice_vc_add_vlan_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * Add and program guest VLAN ID
 */
static int ice_vc_add_vlan_msg(struct ice_vf *vf, u8 *msg)
{
	return ice_vc_process_vlan_msg(vf, msg, true);
}

/**
 * ice_vc_remove_vlan_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * remove programmed guest VLAN ID
 */
static int ice_vc_remove_vlan_msg(struct ice_vf *vf, u8 *msg)
{
	return ice_vc_process_vlan_msg(vf, msg, false);
}

/**
 * ice_vc_ena_vlan_stripping
 * @vf: pointer to the VF info
 *
 * Enable VLAN header stripping for a given VF
 */
static int ice_vc_ena_vlan_stripping(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vf_vlan_offload_ena(vf->driver_caps)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (ice_vsi_manage_vlan_stripping(vsi, true))
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;

error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_VLAN_STRIPPING,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_dis_vlan_stripping
 * @vf: pointer to the VF info
 *
 * Disable VLAN header stripping for a given VF
 */
static int ice_vc_dis_vlan_stripping(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (!ice_vf_vlan_offload_ena(vf->driver_caps)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto error_param;
	}

	if (ice_vsi_manage_vlan_stripping(vsi, false))
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;

error_param:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_VLAN_STRIPPING,
				     v_ret, NULL, 0);
}

/**
 * ice_vc_get_rss_hena - return the RSS HENA bits allowed by the hardware
 * @vf: pointer to the VF info
 */
static int ice_vc_get_rss_hena(struct ice_vf *vf)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct virtchnl_rss_hena *vrh = NULL;
	int len = 0, ret;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!test_bit(ICE_FLAG_RSS_ENA, vf->pf->flags)) {
		dev_err(ice_pf_to_dev(vf->pf), "RSS not supported by PF\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	len = sizeof(struct virtchnl_rss_hena);
	vrh = kzalloc(len, GFP_KERNEL);
	if (!vrh) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}

	vrh->hena = ICE_DEFAULT_RSS_HENA;
err:
	/* send the response back to the VF */
	ret = ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_GET_RSS_HENA_CAPS, v_ret,
				    (u8 *)vrh, len);
	kfree(vrh);
	return ret;
}

#ifdef HAVE_TC_SETUP_CLSFLOWER
/**
 * ice_validate_cloud_filter
 * @vf: pointer to the VF info
 * @tc_filter: pointer to virtchnl_filter
 *
 * This function validates cloud filter programmed as TC filter for ADQ
 */
static int
ice_validate_cloud_filter(struct ice_vf *vf, struct virtchnl_filter *tc_filter)
{
	struct virtchnl_l4_spec mask = tc_filter->mask.tcp_spec;
	struct virtchnl_l4_spec data = tc_filter->data.tcp_spec;
	struct ice_pf *pf = vf->pf;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	if (!tc_filter->action) {
		dev_err(dev, "VF %d: Currently ADQ doesn't support Drop Action\n",
			vf->vf_id);
		return -EOPNOTSUPP;
	}

	/* Check filter if it's programmed for advanced mode or basic mode.
	 * There are two ADQ modes (for VF only),
	 * 1. Basic mode: intended to allow as many filter options as possible
	 *		  to be added to a VF in Non-trusted mode. Main goal is
	 *		  to add filters to its own MAC and VLAN ID.
	 * 2. Advanced mode: is for allowing filters to be applied other than
	 *		  its own MAC or VLAN. This mode requires the VF to be
	 *		  Trusted.
	 */
	if (mask.dst_mac[0] && !mask.dst_ip[0]) {
		/* As of now supporting, MAC filter if MAC address is the
		 * default LAN addr for this VF
		 */
		if (!ice_mac_fltr_exist(&pf->hw, data.dst_mac,
					vf->lan_vsi_idx)) {
			dev_err(dev, "Destination MAC %pM doesn't belong to VF %d\n",
				data.dst_mac, vf->vf_id);
			return -EINVAL;
		}
	} else if (!test_bit(ICE_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps)) {
		/* Check if VF is trusted */
		dev_err(dev, "VF %d not trusted, make VF trusted to add ADQ filters\n",
			vf->vf_id);
		return -EOPNOTSUPP;
	}

	if (mask.dst_mac[0] & data.dst_mac[0]) {
		if (is_broadcast_ether_addr(data.dst_mac) ||
		    is_zero_ether_addr(data.dst_mac)) {
			dev_err(dev, "VF %d: Invalid Dest MAC addr %pM\n",
				vf->vf_id, data.dst_mac);
			return -EINVAL;
		}
	}

	if (mask.src_mac[0] & data.src_mac[0]) {
		if (is_broadcast_ether_addr(data.src_mac) ||
		    is_zero_ether_addr(data.src_mac)) {
			dev_err(dev, "VF %d: Invalid Source MAC addr %pM\n",
				vf->vf_id, data.src_mac);
			return -EINVAL;
		}
	}

	if (mask.dst_port & data.dst_port) {
		if (!data.dst_port) {
			dev_err(dev, "VF %d: Invalid Dest port\n", vf->vf_id);
			return -EINVAL;
		}
	}

	if (mask.src_port & data.src_port) {
		if (!data.src_port) {
			dev_err(dev, "VF %d: Invalid Source port\n", vf->vf_id);
			return -EINVAL;
		}
	}

	if (mask.vlan_id & data.vlan_id) {
		if (ntohs(data.vlan_id) >= VLAN_N_VID) {
			dev_err(dev, "VF %d: invalid VLAN ID\n", vf->vf_id);
			return -EINVAL;
		}
		/* Validate VLAN for the VF the same way we do for the PF */
		if (!ice_vlan_fltr_exist(&pf->hw, ntohs(data.vlan_id),
					 vf->lan_vsi_idx)) {
			dev_err(dev, "specified VLAN %u doesn't belong to this VF %d\n",
				ntohs(data.vlan_id), vf->vf_id);
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * ice_del_all_adv_switch_fltr
 * @vf: pointer to the VF info
 *
 * This function deletes all advanced switch filters specific to the VF and
 * releases filter memory and updates all book-keeping. This function to be
 * used when delete channel message is received before deleting channel VSIs
 */
static void ice_del_all_adv_switch_fltr(struct ice_vf *vf)
{
	struct ice_rule_query_data rule;
	struct ice_tc_flower_fltr *f;
	struct ice_pf *pf = vf->pf;
	struct hlist_node *node;
	struct device *dev;
	int err;
	int i;

	dev = ice_pf_to_dev(pf);
	hlist_for_each_entry_safe(f, node, &vf->tc_flower_fltr_list,
				  tc_flower_node) {
		if (!f->dest_vsi)
			continue;

		/* Deleting TC filter */
		rule.rid = f->rid;
		rule.rule_id = f->rule_id;
		rule.vsi_handle = f->dest_id;
		err = ice_rem_adv_rule_by_id(&pf->hw, &rule);
		if (err)
			dev_err(dev, "VF %d: Failed to delete switch filter for VSI handle %u, err %d\n",
				vf->vf_id, f->dest_id, err);

		/* book-keeping and update filter type if filter count
		 * reached zero
		 */
		f->dest_vsi->num_chnl_fltr--;
		hlist_del(&f->tc_flower_node);
		devm_kfree(dev, f);
		vf->num_tc_flower_fltrs--;
	}

	/* Reset VF channel filter type to be INVALID */
	for (i = 1; i < vf->num_tc; i++)
		vf->ch[i].fltr_type = ICE_CHNL_FLTR_TYPE_INVALID;
}

/**
 * ice_get_tc_flower_fltr - locate the TC flower filter
 * @vf: pointer to the VF info
 * @fltr: pointer to the tc_flower filter
 * @mask: ptr to filter mask (representing filter data specification)
 *
 * This function is used to locate specific filter in filter list. It returns
 * NULL if unable to locate such filter otherwise returns found filter
 */
static struct ice_tc_flower_fltr *
ice_get_tc_flower_fltr(struct ice_vf *vf, struct ice_tc_flower_fltr *fltr,
		       struct virtchnl_l4_spec *mask)
{
	struct ice_tc_flower_lyr_2_4_hdrs *hdrs;
	struct ice_tc_flower_fltr *f;
	struct hlist_node *node;

	hdrs = &fltr->outer_headers;
	if (!hdrs)
		return NULL;

	hlist_for_each_entry_safe(f, node,
				  &vf->tc_flower_fltr_list, tc_flower_node) {
		struct ice_tc_flower_lyr_2_4_hdrs *f_hdrs;

		if (!f->dest_vsi || fltr->dest_vsi != f->dest_vsi ||
		    fltr->dest_vsi->idx != f->dest_vsi->idx)
			continue;

		f_hdrs = &f->outer_headers;
		if ((mask->dst_port && hdrs->dst_port != f_hdrs->dst_port) ||
		    (mask->src_port && hdrs->src_port != f_hdrs->src_port) ||
		    (mask->src_mac[0] &&
		    !ether_addr_equal(hdrs->src_mac, f_hdrs->src_mac)) ||
		    (mask->dst_mac[0] &&
		    !ether_addr_equal(hdrs->dst_mac, f_hdrs->dst_mac)))
			continue;

		/* for ipv4 data to be valid, only first byte of mask is set */
		if (hdrs->n_proto == ETH_P_IP && mask->dst_ip[0])
			if (memcmp(&hdrs->ip.v4.dst_ip, &f_hdrs->ip.v4.dst_ip,
				   sizeof(hdrs->ip.v4.dst_ip)))
				continue;
		/* for ipv6, mask is set for all sixteen bytes (4 words) */
		if (hdrs->n_proto == ETH_P_IPV6 && mask->dst_ip[3])
			if (memcmp(&hdrs->ip.v6.dst_ip6, &f_hdrs->ip.v6.dst_ip6,
				   sizeof(hdrs->ip.v6.dst_ip6)))
				continue;
		if (mask->vlan_id && hdrs->vlan_hdr.vlan_id !=
		    f_hdrs->vlan_hdr.vlan_id)
			continue;

		/* if reached here, means found matching filter entry */
		return f;
	}

	return NULL;
}

/**
 * ice_vc_chnl_fltr_state_verify - verify general state of VF
 * @vf: pointer to the VF info
 * @vcf: pointer to virtchannel_filter
 *
 * This function performs general validartion including validation of filter
 * message and content
 */
static enum virtchnl_status_code
ice_vc_chnl_fltr_state_verify(struct ice_vf *vf, struct virtchnl_filter *vcf)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	u32 max_tc_allowed;
	struct device *dev;

	dev = ice_pf_to_dev(pf);
	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states))
		return VIRTCHNL_STATUS_ERR_PARAM;

	if (!vf->adq_enabled) {
		dev_err(dev, "VF %d: ADQ is not enabled, can't apply switch filter\n",
			vf->vf_id);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		dev_err(dev, "VF %d: No corresponding VF VSI\n", vf->vf_id);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	max_tc_allowed = ice_vc_get_max_chnl_tc_allowed(vf);
	if (vcf->action == VIRTCHNL_ACTION_TC_REDIRECT &&
	    vcf->action_meta >= max_tc_allowed) {
		dev_err(dev, "VF %d: Err: action(%u)_meta(TC): %u >= max_tc_allowed (%u)\n",
			vf->vf_id, vcf->action, vcf->action_meta,
			max_tc_allowed);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	/* enforce supported flow_type based on negotiated capability */
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2) {
		if (!(vcf->flow_type == VIRTCHNL_TCP_V4_FLOW ||
		      vcf->flow_type == VIRTCHNL_TCP_V6_FLOW ||
		      vcf->flow_type == VIRTCHNL_UDP_V4_FLOW ||
		      vcf->flow_type == VIRTCHNL_UDP_V6_FLOW)) {
			dev_err(ice_pf_to_dev(pf), "VF %d: Invalid input/s, unsupported flow_type %u\n",
				vf->vf_id, vcf->flow_type);
			return VIRTCHNL_STATUS_ERR_PARAM;
		}
	} else {
		if (!(vcf->flow_type == VIRTCHNL_TCP_V4_FLOW ||
		      vcf->flow_type == VIRTCHNL_TCP_V6_FLOW)){
			dev_err(ice_pf_to_dev(pf), "VF %d: Invalid input/s, unsupported flow_type %u\n",
				vf->vf_id, vcf->flow_type);
			return VIRTCHNL_STATUS_ERR_PARAM;
		}
	}

	if (ice_validate_cloud_filter(vf, vcf)) {
		dev_err(dev, "VF %d: Invalid input/s, can't apply switch filter\n",
			vf->vf_id);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	/* filter state fully verified, return SUCCESS */
	return VIRTCHNL_STATUS_SUCCESS;
}

/**
 * ice_setup_fltr - populate fields in TC flower filter structure
 * @vf: ptr to VF
 * @vcf: ptr to virt channel message
 * @fltr: pointer to the TC filter structure
 * @dest_vsi: pointer to destination VSI for filter
 * @tc_class: TC number when action type to FWD_TO_VSI, counter index when
 *	      action is count, queue number when action is FWD_TO_QUEUE,
 *	      queue group ID when action is FWD_TO_QGRP
 */
static void
ice_setup_fltr(struct ice_vf *vf, struct ice_tc_flower_fltr *fltr,
	       struct virtchnl_filter *vcf, struct ice_vsi *dest_vsi,
	       int tc_class)
{
	struct virtchnl_l4_spec *mask = &vcf->mask.tcp_spec;
	struct virtchnl_l4_spec *tcf = &vcf->data.tcp_spec;
	struct ice_tc_flower_lyr_2_4_hdrs *hdrs;
	int i;

	memset(fltr, 0, sizeof(*fltr));

	hdrs = &fltr->outer_headers;
	if (!hdrs)
		return;

	/* parse destination MAC address */
	for (i = 0; i < ETH_ALEN; i++)
		hdrs->dst_mac[i] = mask->dst_mac[i] & tcf->dst_mac[i];
	if (!is_zero_ether_addr(hdrs->dst_mac))
		fltr->flags |= ICE_TC_FLWR_FIELD_DST_MAC;

	/* parse source MAC address */
	for (i = 0; i < ETH_ALEN; i++)
		hdrs->src_mac[i] = mask->src_mac[i] & tcf->src_mac[i];
	if (!is_zero_ether_addr(hdrs->src_mac))
		fltr->flags |= ICE_TC_FLWR_FIELD_SRC_MAC;

	hdrs->vlan_hdr.vlan_id = mask->vlan_id & tcf->vlan_id;
	if (hdrs->vlan_hdr.vlan_id)
		fltr->flags |= ICE_TC_FLWR_FIELD_VLAN;
	hdrs->dst_port = mask->dst_port & tcf->dst_port;
	if (hdrs->dst_port)
		fltr->flags |= ICE_TC_FLWR_FIELD_DEST_L4_PORT;
	hdrs->src_port = mask->src_port & tcf->src_port;
	if (hdrs->src_port)
		fltr->flags |= ICE_TC_FLWR_FIELD_SRC_L4_PORT;

	if (vcf->flow_type == VIRTCHNL_TCP_V4_FLOW ||
	    vcf->flow_type == VIRTCHNL_UDP_V4_FLOW) {
		hdrs->n_proto = ETH_P_IP;
		if (mask->dst_ip[0] & tcf->dst_ip[0]) {
			memcpy(&hdrs->ip.v4.dst_ip, tcf->dst_ip,
			       ARRAY_SIZE(tcf->dst_ip));
			fltr->flags |= ICE_TC_FLWR_FIELD_DEST_IPV4;
		}
		if (mask->src_ip[0] & tcf->src_ip[0]) {
			memcpy(&hdrs->ip.v4.src_ip, tcf->src_ip,
			       ARRAY_SIZE(tcf->src_ip));
			fltr->flags |= ICE_TC_FLWR_FIELD_SRC_IPV4;
		}
	} else if (vcf->flow_type == VIRTCHNL_TCP_V6_FLOW ||
		   vcf->flow_type == VIRTCHNL_UDP_V6_FLOW) {
		hdrs->n_proto = ETH_P_IPV6;
		if (mask->dst_ip[3] & tcf->dst_ip[3]) {
			memcpy(&hdrs->ip.v6.dst_ip6, tcf->dst_ip,
			       sizeof(hdrs->ip.v6.dst_ip6));
			fltr->flags |= ICE_TC_FLWR_FIELD_DEST_IPV6;
		}
		if (mask->src_ip[3] & tcf->src_ip[3]) {
			memcpy(&hdrs->ip.v6.src_ip6, tcf->src_ip,
			       sizeof(hdrs->ip.v6.src_ip6));
			fltr->flags |= ICE_TC_FLWR_FIELD_SRC_IPV6;
		}
	}

	/* get the VSI to which the TC belongs to */
	fltr->dest_vsi = dest_vsi;
	if (vcf->action == VIRTCHNL_ACTION_TC_REDIRECT)
		fltr->action.fltr_act = ICE_FWD_TO_VSI;
	else
		fltr->action.fltr_act = ICE_DROP_PACKET;

	/* make sure to include VF's MAC address when adding ADQ filter */
	if ((!(fltr->flags & ICE_TC_FLWR_FIELD_DST_MAC)) &&
	    fltr->action.fltr_act == ICE_FWD_TO_VSI) {
		fltr->flags |= ICE_TC_FLWR_FIELD_DST_MAC;
		ether_addr_copy(hdrs->dst_mac, vf->dflt_lan_addr.addr);
	}

	/* 'tc_class' could be TC/QUEUE/QUEUE_GRP number */
	fltr->action.tc_class = tc_class;

	/* must to set the tunnel_type to be INVALID, otherwise if left as zero,
	 * it gets treated as VxLAN tunnel since definition of VxLAN tunnel
	 * type is zero
	 */
	fltr->tunnel_type = TNL_LAST;

	/* set ip_proto in headers based on flow_type which is part of VIRTCHNL
	 * message, "add filter"
	 */
	if (vcf->flow_type == VIRTCHNL_TCP_V4_FLOW ||
	    vcf->flow_type == VIRTCHNL_TCP_V6_FLOW)
		hdrs->ip_proto = IPPROTO_TCP;
	else
		hdrs->ip_proto = IPPROTO_UDP;
}

/**
 * ice_vc_del_switch_filter
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * This function deletes a cloud filter programmed as TC filter for ADQ
 */
static int ice_vc_del_switch_filter(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_filter *vcf = (struct virtchnl_filter *)msg;
	struct virtchnl_l4_spec *mask = &vcf->mask.tcp_spec;
	struct ice_rule_query_data rule;
	enum virtchnl_status_code v_ret;
	struct ice_tc_flower_fltr fltr;
	struct ice_tc_flower_fltr *f;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *dest_vsi;
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);
	v_ret = ice_vc_chnl_fltr_state_verify(vf, vcf);
	if (v_ret) {
		dev_err(dev, "VF %d: failed to verify ADQ state during filter message processing\n",
			vf->vf_id);
		goto err;
	}

	dest_vsi = pf->vsi[vf->ch[vcf->action_meta].vsi_idx];

	/* prepare the TC flower filter based on input */
	ice_setup_fltr(vf, &fltr, vcf, dest_vsi, vcf->action_meta);

	/* locate the filter in VF tc_flower filter list */
	f = ice_get_tc_flower_fltr(vf, &fltr, mask);
	if (!f) {
		dev_err(dev, "VF %d: Invalid input/s, unable to locate filter due to mismatch\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* Deleting TC filter */
	rule.rid = f->rid;
	rule.rule_id = f->rule_id;
	rule.vsi_handle = f->dest_id;
	err = ice_rem_adv_rule_by_id(&pf->hw, &rule);
	if (err) {
		dev_err(dev, "VF %d: Failed to delete switch filter for tc %u, err %d\n",
			vf->vf_id, vcf->action_meta, err);
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		goto err;
	}

	/* book-keeping and update filter type if filter count reached zero */
	dest_vsi->num_chnl_fltr--;

	/* reset filter type for channel if channel filter
	 * count reaches zero
	 */
	if (!dest_vsi->num_chnl_fltr)
		vf->ch[vcf->action_meta].fltr_type = ICE_CHNL_FLTR_TYPE_INVALID;

	hlist_del(&f->tc_flower_node);
	devm_kfree(dev, f);
	vf->num_tc_flower_fltrs--;

	v_ret = VIRTCHNL_STATUS_SUCCESS;
err:
	/* send the response back to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DEL_CLOUD_FILTER, v_ret,
				     NULL, 0);
}

/**
 * ice_vc_add_switch_filter
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * This function adds a switch filter programmed as TC filter for ADQ
 */
static int ice_vc_add_switch_filter(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_filter *vcf = (struct virtchnl_filter *)msg;
	struct ice_tc_flower_fltr *fltr = NULL;
	enum virtchnl_status_code v_ret;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *dest_vsi;
	struct device *dev;
	int ret;

	dev = ice_pf_to_dev(pf);
	v_ret = ice_vc_chnl_fltr_state_verify(vf, vcf);
	if (v_ret) {
		dev_err(dev, "VF %d: failed to verify ADQ state during filter message processing\n",
			vf->vf_id);
		goto err;
	}

	dest_vsi = pf->vsi[vf->ch[vcf->action_meta].vsi_idx];

	fltr = devm_kzalloc(dev, sizeof(*fltr), GFP_KERNEL);
	if (!fltr) {
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto err;
	}

	/* prepare the TC flower filter based on input */
	ice_setup_fltr(vf, fltr, vcf, dest_vsi, vcf->action_meta);

	/* call function which adds advanced switch filter */
	ret = ice_add_tc_flower_adv_fltr(pf->vsi[vf->lan_vsi_idx], fltr);
	if (ret) {
		dev_err(dev, "Failed to add TC Flower filter using advance filter recipe\n");
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		devm_kfree(dev, fltr);
		goto err;
	}

	INIT_HLIST_NODE(&fltr->tc_flower_node);
	hlist_add_head(&fltr->tc_flower_node, &vf->tc_flower_fltr_list);
	vf->num_tc_flower_fltrs++;

	v_ret = VIRTCHNL_STATUS_SUCCESS;
	vf->adq_fltr_ena = true;

err:
	/* send the response back to the VF */
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ADD_CLOUD_FILTER, v_ret,
				     NULL, 0);
}

/**
 * ice_conv_virtchnl_speed_to_mbps
 * @virt_speed: virt speed that needs to be converted from
 *
 * convert virt channel speeds to mbps, return link speed on success,
 * '0' otherwise
 */
static u32 ice_conv_virtchnl_speed_to_mbps(u16 virt_speed)
{
	u32 speed, link_speed;

	speed = ice_conv_link_speed_to_virtchnl(false, virt_speed);

       /* get link speed in MB to validate rate limit */
	switch (speed) {
	case VIRTCHNL_LINK_SPEED_100MB:
		link_speed = SPEED_100;
		break;
	case VIRTCHNL_LINK_SPEED_1GB:
		link_speed = SPEED_1000;
		break;
	case VIRTCHNL_LINK_SPEED_10GB:
		link_speed = SPEED_10000;
		break;
	case VIRTCHNL_LINK_SPEED_20GB:
		link_speed = SPEED_20000;
		break;
	case VIRTCHNL_LINK_SPEED_25GB:
		link_speed = SPEED_25000;
		break;
	case VIRTCHNL_LINK_SPEED_40GB:
		link_speed = SPEED_40000;
		break;
	default:
		/* on failure to detect link speed the expectation of the caller
		 * to this function is '0'.
		 */
		link_speed = 0;
		break;
	}

	return link_speed;
}

/**
 * ice_vc_add_qch_msg: Add queue channel and enable ADQ
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 */
static int ice_vc_add_qch_msg(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_tc_info *tci =
		(struct virtchnl_tc_info *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_pf *pf = vf->pf;
	int i, adq_request_qps = 0;
	struct ice_link_status *ls;
	u64 total_max_rate = 0;
	u32 max_tc_allowed;
	struct device *dev;
	u16 total_qs = 0;
	u32 link_speed;

	dev = ice_pf_to_dev(pf);
	ls = &pf->hw.port_info->phy.link_info;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* check if VF has negotiated this capability before anything else */
	if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ)) {
		dev_dbg(dev, "VF %d attempting to enable ADQ, but hasn't properly negotiated that capability\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* Currently ADQ and DCB are mutually exclusive and keeping in sync
	 * with PF, don't allow VF ADQ configuration when DCB Firmware LLDP
	 * agent is already running/enabled.
	 */
	if (test_bit(ICE_FLAG_FW_LLDP_AGENT, pf->flags)) {
		dev_err(dev, "FW LLDP is enabled, cannot enable ADQ on VF %d\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* ADQ cannot be applied if spoof check is ON */
	if (vf->spoofchk) {
		dev_err(dev, "Spoof check is ON, turn it OFF to enable ADQ\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	max_tc_allowed = ice_vc_get_max_chnl_tc_allowed(vf);
	/* max number of traffic classes for VF currently capped at 4 for legacy
	 * ADQ and 16 for ADQ V2.
	 */
	if (!tci->num_tc || tci->num_tc > max_tc_allowed) {
		dev_dbg(dev, "VF %d trying to set %u TCs, valid range 1-%u TCs per VF\n",
			vf->vf_id, tci->num_tc, max_tc_allowed);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* validate queues for each TC */
	for (i = 0; i < tci->num_tc; i++) {
		if (!tci->list[i].count) {
			dev_err(dev, "VF %d: TC %d trying to set %u queues, should be > 0 per TC\n",
				vf->vf_id, i, tci->list[i].count);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}
		total_qs += tci->list[i].count;
	}

	if (total_qs > ICE_MAX_RSS_QS_PER_VF) {
		dev_err(dev, "VF %d: Total number of queues of all TCs cannot exceed %u\n",
			vf->vf_id, ICE_MAX_RSS_QS_PER_VF);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* Speed in Mbps */
	if (vf->driver_caps & VIRTCHNL_VF_CAP_ADV_LINK_SPEED)
		link_speed = ice_conv_link_speed_to_virtchnl(true,
							     ls->link_speed);
	else
		link_speed = ice_conv_virtchnl_speed_to_mbps(ls->link_speed);

	if (!link_speed) {
		dev_err(dev, "Cannot detect link speed on VF %d\n", vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	for (i = 0; i < tci->num_tc; i++)
		if (tci->list[i].max_tx_rate)
			total_max_rate += tci->list[i].max_tx_rate;

	if (total_max_rate > link_speed) {
		dev_err(dev, "Invalid tx rate specified for ADQ on VF %d\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* need Max VF queues but already have default number of queues */
	adq_request_qps = ICE_MAX_RSS_QS_PER_VF - pf->num_vf_qps;

	if (ice_get_avail_txq_count(pf) < adq_request_qps) {
		dev_err(dev, "No queues left to allocate to VF %d\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_NO_MEMORY;
		goto err;
	} else {
		/* we need to allocate max VF queues to enable ADQ so as to
		 * make sure ADQ enabled VF always gets back queues when it
		 * goes through a reset.
		 */
		vf->num_vf_qs = ICE_MAX_RSS_QS_PER_VF;
	}

	/* parse data from the queue channel info */
	vf->num_tc = tci->num_tc;

	for (i = 0; i < vf->num_tc; i++) {
		if (tci->list[i].max_tx_rate)
			vf->ch[i].max_tx_rate = tci->list[i].max_tx_rate;

		vf->ch[i].num_qps = tci->list[i].count;
		vf->ch[i].offset = tci->list[i].offset;
	}

	/* set this flag only after making sure all inputs are sane */
	vf->adq_enabled = true;
	/* initialize filter enable flag, set it only if filters are applied */
	vf->adq_fltr_ena = false;

	/* reset the VF in order to allocate resources. Don't reset if ADQ_V2
	 * capability is negotiated, since in that case AVF driver will request
	 * for a reset.
	 */
	if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2)) {
		ice_vc_notify_vf_reset(vf);
		ice_reset_vf(vf, false);
	}
	/* send the response to the VF */
err:
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2)
		return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_CHANNELS,
					     v_ret, (u8 *)tci, sizeof(*tci));
	else
		return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_ENABLE_CHANNELS,
					     v_ret, NULL, 0);
}

/**
 * ice_vc_del_qch_msg
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * delete the additional VSIs which are created as part of ADQ
 */
static int ice_vc_del_qch_msg(struct ice_vf *vf, u8 *msg)
{
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	struct device *dev;
	u8 tc;

	dev = ice_pf_to_dev(pf);

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (vf->adq_enabled) {
		/* stop all Tx/Rx rings and clean them before deleting the ADQ
		 * resources, if not it will throw fail to set the LAN Tx queue
		 * context error. Do this only if the ADQ_V2 capability is 'not'
		 * negotiated. This is to keep the backward compatibility.
		 */
		if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2) &&
		    ice_is_vf_link_up(vf)) {
			for (tc = 0; tc < vf->num_tc; tc++) {
				vsi = pf->vsi[vf->ch[tc].vsi_idx];
				if (!vsi) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto err;
				}
				ice_down(vsi);
			}
		}

		/* delete all ADQ filters for given VF */
		if (vf->num_tc > 1)
			ice_del_all_adv_switch_fltr(vf);

		/* this order of code is very important, if num_tc is not
		 * cleared, VF again rebuilds as ADQ enabled clearly contrary
		 * to what we're trying to do. Also clearing num_tc before
		 * deleting ADQ filters leads to the condition where the code
		 * will try to delete filters when none are configured.
		 */
		vf->num_tc = 0;
		dev_info(ice_pf_to_dev(pf), "Deleting Queue Channels for ADQ on VF %d\n",
			 vf->vf_id);

		/* reset needs to happen first, before we clear the adq_enabled
		 * flag, since freeing up of ADQ resources happens based off of
		 * this flag in reset path. Doing a reset after clearing the
		 * flag will leave the ADQ resources in zombie state which in
		 * turn creates undesired problems such as system lock up, stack
		 * trace etc.,
		 * Also we shouldn't be doing a reset if ADQ flag is cleared in
		 * some other place, hence sending the failure response back to
		 * the VF.
		 */
		if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2)) {
			ice_vc_notify_vf_reset(vf);
			ice_reset_vf(vf, false);
			if (ice_is_vf_link_up(vf)) {
				/* bring the VSI 0 back up again */
				vsi = pf->vsi[vf->ch[0].vsi_idx];
				if (!vsi) {
					v_ret = VIRTCHNL_STATUS_ERR_PARAM;
					goto err;
				}
				ice_up(vsi);
			}
		}
		vf->adq_enabled = false;
	} else {
		dev_info(dev, "VF %d trying to delete queue channels but ADQ isn't enabled\n",
			 vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
	}

	/* send the response to the VF */
err:
	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2)
		return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_CHANNELS,
					     v_ret, msg,
					     sizeof(struct virtchnl_tc_info));
	else
		return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_DISABLE_CHANNELS,
					     v_ret, NULL, 0);
}
#endif /* HAVE_TC_SETUP_CLSFLOWER */

/**
 * ice_vc_set_rss_hena - set RSS HENA bits for the VF
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 */
static int ice_vc_set_rss_hena(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_rss_hena *vrh = (struct virtchnl_rss_hena *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	if (!test_bit(ICE_VF_STATE_ACTIVE, vf->vf_states)) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (!test_bit(ICE_FLAG_RSS_ENA, pf->flags)) {
		dev_err(ice_pf_to_dev(pf), "RSS not supported by PF\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	v_ret = ice_err_to_virt_err(ice_add_avf_rss_cfg(&pf->hw,
							vsi->idx, vrh->hena));

	/* send the response to the VF */
err:
	return ice_vc_send_msg_to_vf(vf, VIRTCHNL_OP_SET_RSS_HENA, v_ret,
				      NULL, 0);
}

/**
 * ice_vc_rdma_msg - send msg to RDMA PF from VF
 * @vf: pointer to VF info
 * @msg: pointer to msg buffer
 * @len: length of the message
 *
 * This function is called indirectly from the AQ clean function.
 */
static int ice_vc_rdma_msg(struct ice_vf *vf, u8 *msg, u16 len)
{
	struct ice_peer_dev *rdma_peer;
	int ret;

	rdma_peer = vf->pf->rdma_peer;
	if (!rdma_peer) {
		pr_err("Invalid RDMA peer attempted to send message to peer\n");
		return -EIO;
	}

	if (!rdma_peer->peer_ops || !rdma_peer->peer_ops->vc_receive) {
		pr_err("Incomplete RMDA peer attempting to send msg\n");
		return -EINVAL;
	}

	ret = rdma_peer->peer_ops->vc_receive(rdma_peer, vf->vf_id, msg, len);
	if (ret)
		pr_err("Failed to send message to RDMA peer, error %d\n", ret);

	return ret;
}

/**
 * ice_vf_init_vlan_stripping - enable/disable VLAN stripping on initialization
 * @vf: VF to enable/disable VLAN stripping for on initialization
 *
 * If the VIRTCHNL_VF_OFFLOAD_VLAN flag is set enable VLAN stripping, else if
 * the flag is cleared then we want to disable stripping. For example, the flag
 * will be cleared when port VLANs are configured by the administrator before
 * passing the VF to the guest or if the AVF driver doesn't support VLAN
 * offloads.
 */
static int ice_vf_init_vlan_stripping(struct ice_vf *vf)
{
	struct ice_vsi *vsi = vf->pf->vsi[vf->lan_vsi_idx];

	if (!vsi)
		return -EINVAL;

	/* don't modify stripping if port VLAN is configured */
	if (vsi->info.pvid)
		return 0;

	if (ice_vf_vlan_offload_ena(vf->driver_caps))
		return ice_vsi_manage_vlan_stripping(vsi, true);
	else
		return ice_vsi_manage_vlan_stripping(vsi, false);
}

/**
 * ice_vc_process_vf_msg - Process request from VF
 * @pf: pointer to the PF structure
 * @event: pointer to the AQ event
 *
 * called from the common asq/arq handler to
 * process request from VF
 */
void ice_vc_process_vf_msg(struct ice_pf *pf, struct ice_rq_event_info *event)
{
	u32 v_opcode = le32_to_cpu(event->desc.cookie_high);
	s16 vf_id = le16_to_cpu(event->desc.retval);
	u16 msglen = event->msg_len;
	u8 *msg = event->msg_buf;
	struct ice_vf *vf = NULL;
	struct device *dev;
	int err = 0;

	dev = ice_pf_to_dev(pf);
	if (ice_validate_vf_id(pf, vf_id)) {
		err = -EINVAL;
		goto error_handler;
	}

	vf = &pf->vf[vf_id];
	/* Check if VF is disabled. */
	if (test_bit(ICE_VF_STATE_DIS, vf->vf_states)) {
		err = -EPERM;
		goto error_handler;
	}

	/* Perform basic checks on the msg */
	err = virtchnl_vc_validate_vf_msg(&vf->vf_ver, v_opcode, msg, msglen);
	if (err) {
		if (err == VIRTCHNL_STATUS_ERR_PARAM)
			err = -EPERM;
		else
			err = -EINVAL;
	}

error_handler:
	if (err) {
		ice_vc_send_msg_to_vf(vf, v_opcode, VIRTCHNL_STATUS_ERR_PARAM,
				      NULL, 0);
		dev_err(dev, "Invalid message from VF %d, opcode %d, len %d, error %d\n",
			vf_id, v_opcode, msglen, err);
		return;
	}
	switch (v_opcode) {
	case VIRTCHNL_OP_VERSION:
		err = ice_vc_get_ver_msg(vf, msg);
		break;
	case VIRTCHNL_OP_GET_VF_RESOURCES:
		err = ice_vc_get_vf_res_msg(vf, msg);
		if (ice_vf_init_vlan_stripping(vf))
			dev_err(ice_pf_to_dev(pf), "Failed to initialize VLAN stripping for VF %d\n",
				vf->vf_id);
		ice_vc_notify_vf_link_state(vf);
		break;
	case VIRTCHNL_OP_RESET_VF:
		ice_vc_reset_vf_msg(vf);
		break;
	case VIRTCHNL_OP_ADD_ETH_ADDR:
		err = ice_vc_add_mac_addr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_ETH_ADDR:
		err = ice_vc_del_mac_addr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_VSI_QUEUES:
		err = ice_vc_cfg_qs_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ENABLE_QUEUES:
		err = ice_vc_ena_qs_msg(vf, msg);
		ice_vc_notify_vf_link_state(vf);
		break;
	case VIRTCHNL_OP_DISABLE_QUEUES:
		err = ice_vc_dis_qs_msg(vf, msg);
		break;
	case VIRTCHNL_OP_REQUEST_QUEUES:
		err = ice_vc_request_qs_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_IRQ_MAP:
		err = ice_vc_cfg_irq_map_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_RSS_KEY:
		err = ice_vc_config_rss_key(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_RSS_LUT:
		err = ice_vc_config_rss_lut(vf, msg);
		break;
	case VIRTCHNL_OP_GET_STATS:
		err = ice_vc_get_stats_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE:
		err = ice_vc_cfg_promiscuous_mode_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ADD_VLAN:
		err = ice_vc_add_vlan_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_VLAN:
		err = ice_vc_remove_vlan_msg(vf, msg);
		break;
	case VIRTCHNL_OP_GET_RSS_HENA_CAPS:
		err = ice_vc_get_rss_hena(vf);
		break;
	case VIRTCHNL_OP_SET_RSS_HENA:
		err = ice_vc_set_rss_hena(vf, msg);
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING:
		err = ice_vc_ena_vlan_stripping(vf);
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING:
		err = ice_vc_dis_vlan_stripping(vf);
		break;
#ifdef HAVE_TC_SETUP_CLSFLOWER
	case VIRTCHNL_OP_ENABLE_CHANNELS:
		err = ice_vc_add_qch_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ADD_CLOUD_FILTER:
		err = ice_vc_add_switch_filter(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_CLOUD_FILTER:
		err = ice_vc_del_switch_filter(vf, msg);
		break;
	case VIRTCHNL_OP_DISABLE_CHANNELS:
		err = ice_vc_del_qch_msg(vf, msg);
		break;
#endif /* HAVE_TC_SETUP_FLOWER */
	case VIRTCHNL_OP_IWARP:
		err = ice_vc_rdma_msg(vf, msg, msglen);
		break;
	case VIRTCHNL_OP_UNKNOWN:
	default:
		dev_err(dev, "Unsupported opcode %d from VF %d\n", v_opcode,
			vf_id);
		err = ice_vc_send_msg_to_vf(vf, v_opcode,
					    VIRTCHNL_STATUS_ERR_NOT_SUPPORTED,
					    NULL, 0);
		break;
	}
	if (err) {
		/* Helper function cares less about error return values here
		 * as it is busy with pending work.
		 */
		dev_info(dev, "PF failed to honor VF %d, opcode %d, error %d\n",
			 vf_id, v_opcode, err);
	}
}

/**
 * ice_get_vf_cfg
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @ivi: VF configuration structure
 *
 * return VF configuration
 */
int
ice_get_vf_cfg(struct net_device *netdev, int vf_id, struct ifla_vf_info *ivi)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vf *vf;

	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];

	if (ice_check_vf_init(pf, vf))
		return -EBUSY;

	ivi->vf = vf_id;
	ether_addr_copy(ivi->mac, vf->dflt_lan_addr.addr);

	/* VF configuration for VLAN and applicable QoS */
	ivi->vlan = vf->port_vlan_info & VLAN_VID_MASK;
	ivi->qos = (vf->port_vlan_info & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;

#ifdef HAVE_NDO_SET_VF_TRUST
	ivi->trusted = vf->trusted;
#endif /* HAVE_NDO_SET_VF_TRUST */
	ivi->spoofchk = vf->spoofchk;
#ifdef HAVE_NDO_SET_VF_LINK_STATE
	if (!vf->link_forced)
		ivi->linkstate = IFLA_VF_LINK_STATE_AUTO;
	else if (vf->link_up)
		ivi->linkstate = IFLA_VF_LINK_STATE_ENABLE;
	else
		ivi->linkstate = IFLA_VF_LINK_STATE_DISABLE;
#endif
#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
	ivi->max_tx_rate = vf->tx_rate;
	ivi->min_tx_rate = 0;
#else
	ivi->tx_rate = vf->tx_rate;
#endif
	return 0;
}

/**
 * ice_wait_on_vf_reset
 * @vf: The VF being resseting
 *
 * Poll to make sure a given VF is ready after reset
 */
static void ice_wait_on_vf_reset(struct ice_vf *vf)
{
	int i;

	for (i = 0; i < ICE_MAX_VF_RESET_WAIT; i++) {
		if (test_bit(ICE_VF_STATE_INIT, vf->vf_states))
			break;
		msleep(20);
	}
}

/**
 * ice_set_vf_mac
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @mac: MAC address
 *
 * program VF MAC address
 */
int ice_set_vf_mac(struct net_device *netdev, int vf_id, u8 *mac)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vf *vf;
	int ret = 0;

	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];
	/* Don't set MAC on disabled VF */
	if (ice_is_vf_disabled(vf))
		return -EINVAL;

	/* In case VF is in reset mode, wait until it is completed. Depending
	 * on factors like queue disabling routine, this could take ~250ms
	 */
	ice_wait_on_vf_reset(vf);

	if (ice_check_vf_init(pf, vf))
		return -EBUSY;

	if (is_zero_ether_addr(mac) || is_multicast_ether_addr(mac)) {
		netdev_err(netdev, "%pM not a valid unicast address\n", mac);
		return -EINVAL;
	}

	/* copy MAC into dflt_lan_addr and trigger a VF reset. The reset
	 * flow will use the updated dflt_lan_addr and add a MAC filter
	 * using ice_add_mac. Also set pf_set_mac to indicate that the PF has
	 * set the MAC address for this VF.
	 */
	ether_addr_copy(vf->dflt_lan_addr.addr, mac);
	vf->pf_set_mac = true;
	netdev_info(netdev, "MAC on VF %d set to %pM. VF driver will be reinitialized\n",
		    vf_id, mac);

	ice_vc_reset_vf(vf);
	return ret;
}

#ifdef HAVE_NDO_SET_VF_TRUST
/**
 * ice_set_vf_trust
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @trusted: Boolean value to enable/disable trusted VF
 *
 * Enable or disable a given VF as trusted
 */
int ice_set_vf_trust(struct net_device *netdev, int vf_id, bool trusted)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
#ifdef HAVE_TC_SETUP_CLSFLOWER
	struct ice_vsi *vsi;
#endif /* HAVE_TC_SETUP_CLSFLOWER */
	struct device *dev;
	struct ice_vf *vf;
#ifdef HAVE_TC_SETUP_CLSFLOWER
	int tc;
#endif /* HAVE_TC_SETUP_CLSFLOWER */

	dev = ice_pf_to_dev(pf);
	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];
	/* Don't set Trusted Mode on disabled VF */
	if (ice_is_vf_disabled(vf))
		return -EINVAL;

	/* In case VF is in reset mode, wait until it is completed. Depending
	 * on factors like queue disabling routine, this could take ~250ms
	 */
	ice_wait_on_vf_reset(vf);

	if (ice_check_vf_init(pf, vf))
		return -EBUSY;

	/* Check if already trusted */
	if (trusted == vf->trusted)
		return 0;

	vf->trusted = trusted;

#ifdef HAVE_TC_SETUP_CLSFLOWER
	/* VF ADQ has two different modes when it comes to applying the switch
	 * filters
	 * 1. basic mode: only dst MAC and dst VLAN filters supported
	 * 2. advanced mode: all combination of filters including dst MAC and
	 *			dst VLAN ex:
	 *	a. dst IP + dst PORT
	 *	b. dst MAC + src PORT
	 *	c. dst MAC + dst PORT
	 * basic mode is for 'untrusted VFs' and advanced mode is only for
	 * 'trusted VFs'. When a VF is toggled from being 'trusted' to
	 * 'untrusted' we remove all filters irrespective if it's basic or
	 * advanced.
	 * when ADQ is enabled we need to do ice_down irrespective if VF is
	 * 'trusted' or not and delete switch filters only if a 'trusted' VF
	 * is made 'untrusted'.
	 */
	if (vf->adq_enabled) {
		if (ice_is_vf_link_up(vf)) {
			for (tc = 0; tc < vf->num_tc; tc++) {
				vsi = pf->vsi[vf->ch[tc].vsi_idx];
				if (vsi)
					ice_down(vsi);
			}
		}
		if (!vf->trusted && vf->adq_fltr_ena) {
			dev_info(dev, "VF %u toggled to untrusted, deleting all ADQ filters\n",
				 vf_id);
			ice_del_all_adv_switch_fltr(vf);
		}
	}
#endif /* HAVE_TC_SETUP_CLSFLOWER */

	ice_vc_reset_vf(vf);
	dev_info(dev, "VF %u is now %strusted\n", vf_id, trusted ? "" : "un");

#ifdef HAVE_TC_SETUP_CLSFLOWER
	if (vf->adq_enabled && ice_is_vf_link_up(vf)) {
		for (tc = 0; tc < vf->num_tc; tc++) {
			vsi = pf->vsi[vf->ch[tc].vsi_idx];

			if (vsi)
				ice_up(vsi);
		}
	}
#endif /* HAVE_TC_SETUP_CLSFLOWER */

	return 0;
}

#endif /* HAVE_NDO_SET_VF_TRUST */
#ifdef HAVE_NDO_SET_VF_LINK_STATE
/**
 * ice_set_vf_link_state
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @link_state: required link state
 *
 * Set VF's link state, irrespective of physical link state status
 */
int ice_set_vf_link_state(struct net_device *netdev, int vf_id, int link_state)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_vf *vf;

	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];
	if (ice_check_vf_init(pf, vf))
		return -EBUSY;

	/* disallow link state change if eeprom is corrupted */
	if (test_bit(__ICE_BAD_EEPROM, pf->state))
		return -EOPNOTSUPP;

	switch (link_state) {
	case IFLA_VF_LINK_STATE_AUTO:
		vf->link_forced = false;
		break;
	case IFLA_VF_LINK_STATE_ENABLE:
		vf->link_forced = true;
		vf->link_up = true;
		break;
	case IFLA_VF_LINK_STATE_DISABLE:
		vf->link_forced = true;
		vf->link_up = false;
		break;
	default:
		return -EINVAL;
	}

	ice_vc_notify_vf_link_state(vf);

	return 0;
}
#endif /* HAVE_NDO_SET_VF_LINK_STATE */

/**
 * ice_set_vf_bw
 * @netdev: network interface device structure
 * @vf_id: VF identifier
 * @min_tx_rate: Minimum Tx rate
 * @max_tx_rate: Maximum Tx rate
 *
 * Set VF Tx rate based on the scheduler limit
 */
#ifdef HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
int
ice_set_vf_bw(struct net_device *netdev, int vf_id,
	      int __always_unused min_tx_rate, int max_tx_rate)
#else
int ice_set_vf_bw(struct net_device *netdev, int vf_id, int max_tx_rate)
#endif
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	enum ice_status status = 0;
	struct ice_port_info *p_info;
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_vf *vf;

	dev = ice_pf_to_dev(pf);
	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];
	vsi = pf->vsi[vf->lan_vsi_idx];
	p_info = vsi->port_info;

	if (ice_check_vf_init(pf, vf))
		return -EBUSY;

	/* Validate rate_limit requested to be within permissible values */
	if (max_tx_rate &&
	    (max_tx_rate < (ICE_SCHED_MIN_BW / 1000) ||
	     max_tx_rate > (ICE_SCHED_MAX_BW / 1000))) {
		dev_err(dev, "Invalid tx rate %d specified for VF %d\n",
			max_tx_rate, vf->vf_id);
		return -EINVAL;
	}

	/* Set BW back to default, when user set max_tx_rate to 0 */
	if (vf->tx_rate && max_tx_rate == 0)
		status = ice_cfg_vsi_bw_dflt_lmt_per_tc(p_info, vsi->idx, 0,
							ICE_MAX_BW);
	else
		status = ice_cfg_vsi_bw_lmt_per_tc(p_info, vsi->idx, 0,
						   ICE_MAX_BW,
						   max_tx_rate * 1000);
	if (status) {
		dev_err(dev, "Unable to set tx rate, error code %d\n", status);
		return -EIO;
	}

	/* Keeping vf->tx_rate in Mbps */
	vf->tx_rate = max_tx_rate;
	return 0;
}

#ifdef HAVE_VF_STATS
/**
 * ice_get_vf_stats - populate some stats for the VF
 * @netdev: the netdev of the PF
 * @vf_id: the host OS identifier (0-255)
 * @vf_stats: pointer to the OS memory to be initialized
 */
int ice_get_vf_stats(struct net_device *netdev, int vf_id,
		     struct ifla_vf_stats *vf_stats)
{
	struct ice_pf *pf = ice_netdev_to_pf(netdev);
	struct ice_eth_stats *stats;
	struct ice_vsi *vsi;
	struct ice_vf *vf;

	if (ice_validate_vf_id(pf, vf_id))
		return -EINVAL;

	vf = &pf->vf[vf_id];

	if (ice_check_vf_init(pf, vf))
		return -EBUSY;

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi)
		return -EINVAL;

	ice_update_eth_stats(vsi);
	stats = &vsi->eth_stats;

	memset(vf_stats, 0, sizeof(*vf_stats));

	vf_stats->rx_packets = stats->rx_unicast + stats->rx_broadcast +
		stats->rx_multicast;
	vf_stats->tx_packets = stats->tx_unicast + stats->tx_broadcast +
		stats->tx_multicast;
	vf_stats->rx_bytes   = stats->rx_bytes;
	vf_stats->tx_bytes   = stats->tx_bytes;
	vf_stats->broadcast  = stats->rx_broadcast;
	vf_stats->multicast  = stats->rx_multicast;
#ifdef HAVE_VF_STATS_DROPPED
	vf_stats->rx_dropped = stats->rx_discards;
	vf_stats->tx_dropped = stats->tx_discards;
#endif

	return 0;
}
#endif /* HAVE_VF_STATS */

/**
 * ice_print_vfs_mdd_event - print VFs malicious driver detect event
 * @pf: pointer to the PF structure
 *
 * Called from ice_handle_mdd_event to rate limit and print VFs MDD events.
 */
void ice_print_vfs_mdd_events(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	int i;

	/* check that there are pending MDD events to print */
	if (!test_and_clear_bit(__ICE_MDD_VF_PRINT_PENDING, pf->state))
		return;

	/* VF MDD event logs are rate limited to one second intervals */
	if (time_is_after_jiffies(pf->last_printed_mdd_jiffies + HZ * 1))
		return;

	pf->last_printed_mdd_jiffies = jiffies;

	ice_for_each_vf(pf, i) {
		struct ice_vf *vf = &pf->vf[i];

		/* only print Rx MDD event message if there are new events */
		if (vf->mdd_rx_events.count != vf->mdd_rx_events.last_printed) {
			vf->mdd_rx_events.last_printed =
							vf->mdd_rx_events.count;

			dev_info(dev, "%d Rx Malicious Driver Detection events detected on PF %d VF %d MAC %pM. mdd-auto-reset-vfs=%s\n",
				 vf->mdd_rx_events.count, hw->pf_id, i,
				 vf->dflt_lan_addr.addr,
				 test_bit(ICE_FLAG_MDD_AUTO_RESET_VF, pf->flags)
					  ? "on" : "off");
		}

		/* only print Tx MDD event message if there are new events */
		if (vf->mdd_tx_events.count != vf->mdd_tx_events.last_printed) {
			vf->mdd_tx_events.last_printed =
							vf->mdd_tx_events.count;

			dev_info(dev, "%d Tx Malicious Driver Detection events detected on PF %d VF %d MAC %pM.\n",
				 vf->mdd_tx_events.count, hw->pf_id, i,
				 vf->dflt_lan_addr.addr);
		}
	}
}
