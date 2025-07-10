/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice.h"
#include "ice_lib.h"
#include "ice_vf_adq.h"
#include "ice_tc_lib.h"
#include "ice_vf_lib_private.h"

struct ice_vsi *ice_get_vf_adq_vsi(struct ice_vf *vf, u8 tc)
{
	return vf->pf->vsi[vf->ch[tc].vsi_idx];
}

/**
 * ice_is_vf_adq_ena - is VF ADQ enabled
 * @vf: pointer to the VF info
 *
 * This function returns true if VF ADQ is enabled. It is must to check
 * VF's num_tc as well, it must be more than ICE_VF_CHNL_START_TC for
 * valid ADQ configuration
 */
bool ice_is_vf_adq_ena(struct ice_vf *vf)
{
	return vf->adq_enabled && (vf->num_tc > ICE_VF_CHNL_START_TC);
}

/**
 * ice_vf_adq_vsi_stop_rings - stops the VF ADQ VSI rings
 * @vf: pointer to the VF info
 * @tc: VF ADQ TC number
 *
 * This function stops Tx and Rx ring specific to VF ADQ VSI
 */
static void ice_vf_adq_vsi_stop_rings(struct ice_vf *vf, int tc)
{
	struct ice_vsi *vsi = ice_get_vf_adq_vsi(vf, tc);

	if (!vsi)
		return;
	ice_vsi_stop_lan_tx_rings(vsi, ICE_NO_RESET, vf->vf_id);
	ice_vsi_stop_all_rx_rings(vsi);
}

/**
 * ice_vf_adq_vsi_disable_txqs - disable Tx queues for VF ADQ
 * @vf: pointer to the VF info
 * @tc: VF ADQ TC number
 *
 * This function disabled Tx queues specific to VF ADQ VSI
 */
static void ice_vf_adq_vsi_disable_txqs(struct ice_vf *vf, int tc)
{
	struct ice_vsi *vsi = ice_get_vf_adq_vsi(vf, tc);

	if (!vsi)
		return;
	ice_dis_vsi_txq(vsi->port_info, vf->ch[tc].vsi_idx, 0, 0, NULL, NULL,
			NULL, vf->vf_ops->reset_type, vf->vf_id, NULL);
}

/**
 * ice_vf_adq_invalidate_vsi - invalidate vsi_idx/vsi_num to remove VSI access
 * @vf: VF that ADQ VSI is being invalidated on
 * @tc: TC used to access channel specific vsi_idx/vsi_num
 */
static void ice_vf_adq_invalidate_vsi(struct ice_vf *vf, u8 tc)
{
	vf->ch[tc].vsi_idx = ICE_NO_VSI;
	vf->ch[tc].vsi_num = ICE_NO_VSI;
}

/**
 * ice_vf_adq_vsi_valid - is ADQ VSI valid?
 * @vf: VF that ADQ VSI is being validated
 * @tc: TC used to access channel specific vsi_idx/vsi_num
 *
 * vsi_idx must be non-zero, and vsi_idx and vsi_num must not be ICE_NO_VSI
 */
bool ice_vf_adq_vsi_valid(struct ice_vf *vf, u8 tc)
{
	return (vf->ch[tc].vsi_idx && vf->ch[tc].vsi_idx != ICE_NO_VSI &&
		vf->ch[tc].vsi_num != ICE_NO_VSI);
}

/**
 * ice_vf_adq_vsi_release - release VF ADQ VSI resources
 * @vf: VF that ADQ VSI is being released on
 * @tc: TC used to access channel specific VSI
 *
 * This function stops Tx and Rx queues if specified, disables Tx queues if
 * specified, releases VSI resources, and invalidates it
 *
 */
static void ice_vf_adq_vsi_release(struct ice_vf *vf, u8 tc)
{
	ice_vsi_release(ice_get_vf_adq_vsi(vf, tc));
	ice_vf_adq_invalidate_vsi(vf, tc);
}

/**
 * ice_vf_adq_cfg_cleanup - invalidate the VF's channel software info
 * @vf: VF that ADQ VSI is being released on
 * @tc: TC used to access channel specific VSI
 *
 * This function invalidates software data structures specific to channel
 * such as num_qps, tx_rate, etc... This is called from places like:
 * when ADQ VSI is released either from rebuild path "ice_vf_adq_release"
 * or during rebuild ADQ config if failed to create/setup VF ADQ VSIs
 */
static void ice_vf_adq_cfg_cleanup(struct ice_vf *vf, u8 tc)
{
	vf->ch[tc].num_qps = 0;
	vf->ch[tc].offset = 0;
	vf->ch[tc].max_tx_rate = 0;
}

#ifdef HAVE_TC_SETUP_CLSFLOWER
/**
 * ice_del_all_adv_switch_fltr
 * @vf: pointer to the VF info
 *
 * This function deletes all advanced switch filters specific to the VF and
 * releases filter memory and updates all book-keeping. This function to be
 * used when delete channel message is received before deleting channel VSIs
 */
void ice_del_all_adv_switch_fltr(struct ice_vf *vf)
{
	struct ice_tc_flower_fltr *f;
	struct ice_pf *pf = vf->pf;
	struct hlist_node *node;
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);
	hlist_for_each_entry_safe(f, node, &vf->tc_flower_fltr_list,
				  tc_flower_node) {
		if (!f->dest_vsi)
			continue;

		/* Deleting TC filter */
		err = ice_rem_adv_rule_by_fltr(&pf->hw, f);
		if (err) {
			if (err == -ENOENT)
				dev_dbg(dev, "VF %d: filter (rule_id %u) for dest VSI %u DOES NOT EXIST in hw table\n",
					vf->vf_id, f->rule_id,
					f->dest_vsi_handle);
			else
				dev_err(dev, "VF %d: Failed to delete switch filter for VSI handle %u, err %d\n",
					vf->vf_id, f->dest_vsi_handle, err);
		}

		/* book-keeping and update filter type if filter count
		 * reached zero
		 */
		f->dest_vsi->num_chnl_fltr--;
		hlist_del(&f->tc_flower_node);
		devm_kfree(dev, f);
		vf->num_dmac_chnl_fltrs--;
	}
}
#endif /* HAVE_TC_SETUP_CLSFLOWER */

/**
 * ice_vf_adq_release - perform VF ADQ resource cleanup only
 * @vf: pointer to the VF structure
 *
 * Delete all VF ADQ filters, release VF ADQ VSIs, cleanup internal data
 * structues which keeps track of per TC infor including TC0. This function
 * is invoked only when VFLR based VF Reset.
 */
void ice_vf_adq_release(struct ice_vf *vf)
{
	u8 tc;

	/* no ADQ configured, nothing to do */
	if (!ice_is_vf_adq_ena(vf))
		return;

#ifdef HAVE_TC_SETUP_CLSFLOWER
	/* release VF ADQ specific filters and eventually VF driver
	 * will trigger replay of VF ADQ filters as needed, just like
	 * other MAC, VLAN filters
	 */
	ice_del_all_adv_switch_fltr(vf);
#endif

	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		if (!ice_vf_adq_vsi_valid(vf, tc))
			continue;
		/* Tx queues are disabled before VF reset is scheduled as part
		 * of VFLR flow. Disabling TX queues again causes error
		 * such as EINVAL from admin command because underlying
		 * scheduler configs are cleared as part of disabling once
		 */
		if (test_bit(ICE_VF_STATE_QS_ENA, vf->vf_states))
			ice_vf_adq_vsi_stop_rings(vf, tc);
		ice_vf_adq_vsi_release(vf, tc);
		/* clear per TC info to avoid stale information such as
		 * num_qps, tx_rate, etc...
		 */
		ice_vf_adq_cfg_cleanup(vf, tc);
	}

	/* to avoid rebuilding of VF ADQ VSIs by mistake */
	vf->adq_enabled = false;
	vf->num_tc = 0;

	/* main VF VSI should be built with default, hence clear related
	 * data structures otherwise vf->ch[0].num_qps and tx_rate will
	 * still have stale information as stored from "add channel"
	 * virtchnl message
	 */
	ice_vf_adq_cfg_cleanup(vf, 0);
}

/**
 * ice_vf_adq_vsi_setup - Set up a VF channel VSI
 * @vf: VF to setup VSI for
 * @tc: TC to setup the channel VSI for
 */
static struct ice_vsi *ice_vf_adq_vsi_setup(struct ice_vf *vf, u8 tc)
{
	struct ice_vsi_cfg_params params = {};
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;

	params.type = ICE_VSI_VF;
	params.port_info = ice_vf_get_port_info(vf);
	params.vf = vf;
	params.tc = tc;
	params.flags = ICE_VSI_FLAG_INIT;

	vsi = ice_vsi_setup(pf, &params);
	if (!vsi) {
		dev_err(ice_pf_to_dev(pf), "Failed to create VF ADQ VSI for TC %d\n",
			tc);
		ice_vf_adq_invalidate_vsi(vf, tc);
		return NULL;
	}

	vf->ch[tc].vsi_idx = vsi->idx;
	vf->ch[tc].vsi_num = vsi->vsi_num;

	return vsi;
}

/**
 * ice_vf_rebuild_adq_port_vlan_cfg - set the port VLAN for VF ADQ VSIs
 * @vf: VF to add MAC filters for
 *
 * Called after a VF ADQ VSI has been re-added/rebuilt during reset.
 */
static int ice_vf_rebuild_adq_port_vlan_cfg(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	int err, tc;

	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		struct ice_vsi *vsi;

		if (!ice_vf_adq_vsi_valid(vf, tc))
			continue;

		vsi = ice_get_vf_adq_vsi(vf, tc);
		err = ice_vf_rebuild_host_vlan_cfg(vf, vsi);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "failed to configure port VLAN via VSI parameters for VF %u, ADQ VSI(num %u)",
					  vf->vf_id, vsi->vsi_num);
			return err;
		}
	}
	return 0;
}

/**
 * ice_vf_rebuild_adq_spoofchk_cfg - set the spoofchk config for VF ADQ VSIs
 * @vf: VF to set spoofchk for
 *
 * Called after a VF ADQ VSI has been re-added/rebuilt during reset.
 */
static int ice_vf_rebuild_adq_spoofchk_cfg(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	int err, tc;

	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		struct ice_vsi *vsi;

		if (!ice_vf_adq_vsi_valid(vf, tc))
			continue;

		vsi = ice_get_vf_adq_vsi(vf, tc);
		err = ice_vsi_apply_spoofchk(vsi, vf->spoofchk);
		if (err) {
			ice_dev_err_errno(dev, err,
					  "failed to configure spoofchk via VSI parameters for VF %u, ADQ VSI(num %u)",
					  vf->vf_id, vsi->vsi_num);
			return err;
		}
	}
	return 0;
}

/**
 * ice_vf_rebuild_adq_aggregator_node - move ADQ VSIs into aggregator node
 * @vf: VF to rebuild ADQ VSI(s) Tx rate configuration on
 *
 * If VF ADQ is enabled, replay scheduler aggregator node config
 */
static void ice_vf_rebuild_adq_aggregator_node(struct ice_vf *vf)
{
	int tc;

	if (!ice_is_vf_adq_ena(vf))
		return;

	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		struct ice_vsi *vsi;

		if (!ice_vf_adq_vsi_valid(vf, tc))
			continue;
		vsi = ice_get_vf_adq_vsi(vf, tc);
		ice_vf_rebuild_aggregator_node_cfg(vsi);
	}
}

/**
 * ice_vf_rebuild_adq_tx_rate_cfg - rebuild ADQ VSI(s) Tx rate configuration
 * @vf: VF to rebuild ADQ VSI(s) Tx rate configuration on
 */
static void ice_vf_rebuild_adq_tx_rate_cfg(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);
	struct ice_vsi *vsi;
	u64 max_tx_rate;
	u8 tc;

	if (!ice_is_vf_adq_ena(vf))
		return;

	/* Host may have set Tx rate for VF, but use the TC0's specified
	 * max Tx rate for main VF VSI.
	 * Iterate thru' all VSI (hence for loop starts with zero) shared by
	 * given VF and set the BW limit if specified as part of
	 * VF ADQ TC config
	 */
	for (tc = 0; tc < vf->num_tc; tc++) {
		if (!ice_vf_adq_vsi_valid(vf, tc))
			continue;

		max_tx_rate = vf->ch[tc].max_tx_rate;
		if (!max_tx_rate)
			continue;

		if (!tc && vf->max_tx_rate)
			dev_dbg(dev, "Host managed VF rate limit %u for VF %d are being changed to %llu\n",
				vf->max_tx_rate, vf->vf_id, max_tx_rate);

		vsi = ice_get_vf_adq_vsi(vf, tc);
		if (ice_set_max_bw_limit(vsi, max_tx_rate * 1000))
			dev_err(dev, "Unable to set Tx rate %llu in Mbps for VF %u TC %d\n",
				max_tx_rate, vf->vf_id, tc);
	}
}

/**
 * ice_vf_rebuild_adq_host_cfg - host admin config is persistent across reset
 * @vf: VF to rebuild ADQ host configuration on
 */
void ice_vf_rebuild_adq_host_cfg(struct ice_vf *vf)
{
	struct device *dev = ice_pf_to_dev(vf->pf);

	ice_vf_rebuild_adq_aggregator_node(vf);
	ice_vf_rebuild_adq_tx_rate_cfg(vf);
	if (ice_vf_rebuild_adq_port_vlan_cfg(vf))
		dev_err(dev, "failed to rebuild port VLAN configuration for ADQ enabled VF %u\n",
			vf->vf_id);
	if (ice_vf_rebuild_adq_spoofchk_cfg(vf))
		dev_err(dev, "failed to rebuild spoofchk configuration for ADQ enabled VF %u\n",
			vf->vf_id);
}

/**
 * ice_vf_recreate_adq_vsi - release and recreate each ADQ VSI
 * @vf: VF to re-apply ADQ configuration for
 *
 * This is only called when a single VF is being reset (i.e. VFR, VFLR, host VF
 * configuration change, etc.).
 *
 * This cannot be called for the reset all VFs case as ice_vf_adq_vsi_release()
 * will fail because there are no VF VSI(s) in firmware at this point.
 */
int ice_vf_recreate_adq_vsi(struct ice_vf *vf)
{
	struct ice_vsi *vsi;
	u8 tc;

	if (!ice_is_vf_adq_ena(vf))
		return 0;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return -EINVAL;

	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		if (ice_vf_adq_vsi_valid(vf, tc)) {
			ice_vf_adq_vsi_stop_rings(vf, tc);
			ice_vf_adq_vsi_disable_txqs(vf, tc);
			ice_vf_adq_vsi_release(vf, tc);
		}

		if (!ice_vf_adq_vsi_setup(vf, tc)) {
			dev_err(ice_pf_to_dev(vf->pf), "failed to setup ADQ VSI for VF %u, TC %d, disabling VF ADQ VSI\n",
				vf->vf_id, tc);
			goto adq_cfg_failed;
		}
	}

	/* must to store away TC0's info because it is used later */
	vf->ch[0].vsi_idx = vsi->idx;
	vf->ch[0].vsi_num = vsi->vsi_num;

	return 0;

adq_cfg_failed:
	/* perform VSI release for ADQ VSI if some of them were
	 * created successfully.
	 */
	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		if (ice_vf_adq_vsi_valid(vf, tc)) {
			ice_vf_adq_vsi_disable_txqs(vf, tc);
			ice_vf_adq_vsi_release(vf, tc);
		}
		ice_vf_adq_cfg_cleanup(vf, tc);
	}
	vf->adq_enabled = false;
	vf->num_tc = 0;
	/* Upon failure also clean up tc=0 specific info from
	 * software data structs, to avoid having stale info
	 */
	ice_vf_adq_invalidate_vsi(vf, 0);
	ice_vf_adq_cfg_cleanup(vf, 0);
	return -ENOMEM;
}

/**
 * ice_vf_rebuild_adq_vsi - rebuild ADQ VSI(s) on the VF
 * @vf: VF to rebuild ADQ VSI(s) on
 */
int ice_vf_rebuild_adq_vsi(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *vsi;
	int tc;

	/* no ADQ configured, nothing to do */
	if (!ice_is_vf_adq_ena(vf))
		return 0;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return -EINVAL;

	for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
		int ret;

		if (!ice_vf_adq_vsi_valid(vf, tc))
			continue;

		vsi = ice_get_vf_adq_vsi(vf, tc);
		ret = ice_vsi_rebuild(vsi, ICE_VSI_FLAG_INIT);
		if (ret) {
			dev_err(ice_pf_to_dev(pf), "failed to rebuild ADQ VSI for VF %u, disabling VF ADQ VSI\n",
				vf->vf_id);
			vf->adq_enabled = false;
			ice_vf_adq_invalidate_vsi(vf, tc);
			return ret;
		}

		vsi->vsi_num = ice_get_hw_vsi_num(&pf->hw, vsi->idx);
		vf->ch[tc].vsi_num = vsi->vsi_num;
		vf->ch[tc].vsi_idx = vsi->idx;
	}

	/* must to store away TC0's info because it is use later */
	vf->ch[0].vsi_idx = vsi->idx;
	vf->ch[0].vsi_num = vsi->vsi_num;

	return 0;
}

/**
 * ice_vf_get_tc_based_qid - get the updated QID based on offset
 * @qid: queue ID
 * @offset : TC specific queue offset
 *
 * This function returns updated queueID based on offset. This is
 * meant to be used only with VF ADQ. Queue ID will always be
 * 0-based from the specified offset
 */
u16 ice_vf_get_tc_based_qid(u16 qid, u16 offset)
{
	return (qid >= offset) ? (qid - offset) : qid;
}

/**
 * ice_vf_q_id_get_vsi_q_id
 * @vf: pointer to the VF info
 * @vf_q_id: VF relative queue ID
 * @t_tc: traffic class for indexing the VSIs
 * @vqs: the VFs virtual queue selection
 * @vsi_p: pointer to VSI pointer, which changes based on TC for ADQ
 * @q_id: queue ID of the VSI
 *
 * provides ADQ queue enablement support by mapping the VF queue ID and TC to
 * VSI ID and queue ID. call while iterating through VF queue IDs, VF VSIs and
 * TCs.
 */
void ice_vf_q_id_get_vsi_q_id(struct ice_vf *vf, u16 vf_q_id, u16 *t_tc,
			      struct virtchnl_queue_select *vqs,
			      struct ice_vsi **vsi_p, u16 *q_id)
{
	struct ice_vsi *vsi = *vsi_p;
	u32 max_chnl_tc;
	u16 tc = *t_tc;

	max_chnl_tc = ice_vc_get_max_chnl_tc_allowed(vf);

	/* Update the VSI and TC based on per TC queue region and offset */
	if (tc + 1U < max_chnl_tc && vf_q_id == vf->ch[tc + 1].offset &&
	    tc < vf->num_tc && ice_is_vf_adq_ena(vf)) {
		vsi = vf->pf->vsi[vf->ch[tc + 1].vsi_idx];
		tc++;
	}

	/* Update queue_id based on TC if TC is VF ADQ TC, then
	 * use VF ADQ VSI otherwise main VF VSI
	 */
	if (tc >= ICE_VF_CHNL_START_TC && ice_is_vf_adq_ena(vf))
		*q_id = ice_vf_get_tc_based_qid(vf_q_id, vf->ch[tc].offset);
	else
		*q_id = vf_q_id;

	*vsi_p = vsi;
	*t_tc = tc;
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
	} else if (!ice_is_vf_trusted(vf)) {
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
	struct ice_tc_l2_hdr *l2_key;
	struct ice_tc_l3_hdr *l3_key;
	struct ice_tc_l4_hdr *l4_key;
	struct ice_tc_flower_fltr *f;
	struct hlist_node *node;

	hdrs = &fltr->outer_headers;
	if (!hdrs)
		return NULL;

	l2_key = &hdrs->l2_key;
	l3_key = &hdrs->l3_key;
	l4_key = &hdrs->l4_key;

	hlist_for_each_entry_safe(f, node,
				  &vf->tc_flower_fltr_list, tc_flower_node) {
		struct ice_tc_flower_lyr_2_4_hdrs *f_hdrs;

		if (!f->dest_vsi || fltr->dest_vsi != f->dest_vsi ||
		    fltr->dest_vsi->idx != f->dest_vsi->idx)
			continue;

		f_hdrs = &f->outer_headers;

		/* handle L2 fields if specified and do not match */
		if ((mask->src_mac[0] &&
		     !ether_addr_equal(l2_key->src_mac,
		     f_hdrs->l2_key.src_mac)) ||
		    (mask->dst_mac[0] &&
		     !ether_addr_equal(l2_key->dst_mac,
		     f_hdrs->l2_key.dst_mac)))
			continue;

		/* handle VLAN if specified and do not match  */
		if (mask->vlan_id && hdrs->vlan_hdr.vlan_id !=
		    f_hdrs->vlan_hdr.vlan_id)
			continue;

		/* handle L3 IPv4 if specified and do not match
		 * for ipv4 data to be valid, check only first dword of mask
		 */
		if (l2_key->n_proto == htons(ETH_P_IP))
			if ((mask->dst_ip[0] &&
			     l3_key->dst_ipv4 != f_hdrs->l3_key.dst_ipv4) ||
			    (mask->src_ip[0] &&
			     l3_key->src_ipv4 != f_hdrs->l3_key.src_ipv4))
				continue;

		/* handle L3 IPv6 if specified and do not match
		 * for ipv6 to be valid, last dword from mask must be valid
		 * hence check only last dword of mask
		 */
		if (l2_key->n_proto == htons(ETH_P_IPV6) && mask->dst_ip[3])
			if (memcmp(&l3_key->ip.v6.dst_ip6,
				   &f_hdrs->l3_key.ip.v6.dst_ip6,
				   sizeof(l3_key->ip.v6.dst_ip6)))
				continue;
		if (l2_key->n_proto == htons(ETH_P_IPV6) && mask->src_ip[3])
			if (memcmp(&l3_key->ip.v6.src_ip6,
				   &f_hdrs->l3_key.ip.v6.src_ip6,
				   sizeof(l3_key->ip.v6.src_ip6)))
				continue;

		/* make sure "ip_proto" is same */
		if (l3_key->ip_proto != f_hdrs->l3_key.ip_proto)
			continue;

		/* handle L4 fields if specified and do not match */
		if ((mask->dst_port &&
		     l4_key->dst_port != f_hdrs->l4_key.dst_port) ||
		    (mask->src_port &&
		     l4_key->src_port != f_hdrs->l4_key.src_port))
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
 * This function performs general validation including validation of filter
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

	if (!ice_is_vf_adq_ena(vf)) {
		dev_err(dev, "VF %d: ADQ is not enabled, can't apply switch filter\n",
			vf->vf_id);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(dev, "VF %d: No corresponding VF VSI\n", vf->vf_id);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	if (vcf->action != VIRTCHNL_ACTION_TC_REDIRECT) {
		dev_err(dev, "VF %d: filter action(%d) not supported when ADQ is configured\n",
			vf->vf_id, vcf->action);
		return VIRTCHNL_STATUS_ERR_PARAM;
	}

	max_tc_allowed = ice_vc_get_max_chnl_tc_allowed(vf);
	if (vcf->action_meta >= max_tc_allowed) {
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

	memset(fltr, 0, sizeof(*fltr));

	hdrs = &fltr->outer_headers;
	if (!hdrs)
		return;

	/* copy L2 MAC address and MAC mask */
	ether_addr_copy(hdrs->l2_key.dst_mac, tcf->dst_mac);
	ether_addr_copy(hdrs->l2_mask.dst_mac, mask->dst_mac);
	if (!is_zero_ether_addr(hdrs->l2_key.dst_mac))
		fltr->flags |= ICE_TC_FLWR_FIELD_DST_MAC;

	/* copy L2 source address and MAC mask */
	ether_addr_copy(hdrs->l2_key.src_mac, tcf->src_mac);
	ether_addr_copy(hdrs->l2_mask.src_mac, mask->src_mac);
	if (!is_zero_ether_addr(hdrs->l2_key.src_mac))
		fltr->flags |= ICE_TC_FLWR_FIELD_SRC_MAC;

	/* copy VLAN info */
	hdrs->vlan_hdr.vlan_id = mask->vlan_id & tcf->vlan_id;
	if (hdrs->vlan_hdr.vlan_id)
		fltr->flags |= ICE_TC_FLWR_FIELD_VLAN;

	/* copy L4 fields */
	hdrs->l4_key.dst_port = mask->dst_port & tcf->dst_port;
	hdrs->l4_mask.dst_port = mask->dst_port;
	if (hdrs->l4_key.dst_port)
		fltr->flags |= ICE_TC_FLWR_FIELD_DEST_L4_PORT;

	hdrs->l4_key.src_port = mask->src_port & tcf->src_port;
	hdrs->l4_mask.src_port = mask->src_port;
	if (hdrs->l4_key.src_port)
		fltr->flags |= ICE_TC_FLWR_FIELD_SRC_L4_PORT;

	/* copy L3 fields, IPv4[6] */
	if (vcf->flow_type == VIRTCHNL_TCP_V4_FLOW ||
	    vcf->flow_type == VIRTCHNL_UDP_V4_FLOW) {
		struct ice_tc_l3_hdr *key, *msk;

		key = &hdrs->l3_key;
		msk = &hdrs->l3_mask;

		/* set n_proto based on flow_type */
		hdrs->l2_key.n_proto = htons(ETH_P_IP);
		if (mask->dst_ip[0] & tcf->dst_ip[0]) {
			key->dst_ipv4 = tcf->dst_ip[0];
			msk->dst_ipv4 = mask->dst_ip[0];
			fltr->flags |= ICE_TC_FLWR_FIELD_DEST_IPV4;
		}
		if (mask->src_ip[0] & tcf->src_ip[0]) {
			key->src_ipv4 = tcf->src_ip[0];
			msk->src_ipv4 = mask->src_ip[0];
			fltr->flags |= ICE_TC_FLWR_FIELD_SRC_IPV4;
		}
	} else if (vcf->flow_type == VIRTCHNL_TCP_V6_FLOW ||
		   vcf->flow_type == VIRTCHNL_UDP_V6_FLOW) {
		struct ice_tc_l3_hdr *key, *msk;

		key = &hdrs->l3_key;
		msk = &hdrs->l3_mask;

		/* set n_proto based on flow_type */
		hdrs->l2_key.n_proto = htons(ETH_P_IPV6);
		if (mask->dst_ip[3] & tcf->dst_ip[3]) {
			memcpy(&key->ip.v6.dst_ip6, tcf->dst_ip,
			       sizeof(key->ip.v6.dst_ip6));
			memcpy(&msk->ip.v6.dst_ip6, mask->dst_ip,
			       sizeof(msk->ip.v6.dst_ip6));
			fltr->flags |= ICE_TC_FLWR_FIELD_DEST_IPV6;
		}
		if (mask->src_ip[3] & tcf->src_ip[3]) {
			memcpy(&key->ip.v6.src_ip6, tcf->src_ip,
			       sizeof(key->ip.v6.src_ip6));
			memcpy(&msk->ip.v6.src_ip6, mask->src_ip,
			       sizeof(msk->ip.v6.src_ip6));
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
		ether_addr_copy(hdrs->l2_key.dst_mac, vf->dev_lan_addr.addr);
		eth_broadcast_addr(hdrs->l2_mask.dst_mac);
	}

	/* 'tc_class' could be TC/QUEUE/QUEUE_GRP number */
	fltr->action.fwd.tc.tc_class = tc_class;

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
		hdrs->l3_key.ip_proto = IPPROTO_TCP;
	else
		hdrs->l3_key.ip_proto = IPPROTO_UDP;
}

/**
 * ice_vc_del_switch_filter
 * @vf: pointer to the VF info
 * @msg: pointer to the msg buffer
 *
 * This function deletes a cloud filter programmed as TC filter for ADQ
 */
int ice_vc_del_switch_filter(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_filter *vcf = (struct virtchnl_filter *)msg;
	struct virtchnl_l4_spec *mask = &vcf->mask.tcp_spec;
	enum virtchnl_status_code v_ret;
	struct ice_tc_flower_fltr fltr;
	struct ice_tc_flower_fltr *f;
	struct ice_pf *pf = vf->pf;
	struct ice_vsi *dest_vsi;
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);
	/* Advanced switch filters and DCF are mutually exclusive. */
	if (ice_is_dcf_enabled(pf)) {
		dev_err(dev, "Device Control Functionality is currently enabled. Advanced switch filters cannot be deleted.\n");
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err;
	}

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
	err = ice_rem_adv_rule_by_fltr(&pf->hw, f);
	if (err) {
		dev_err(dev, "VF %d: Failed to delete switch filter for tc %u, err %d\n",
			vf->vf_id, vcf->action_meta, err);
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		goto err;
	}

	/* book-keeping and update filter type if filter count reached zero */
	dest_vsi->num_chnl_fltr--;

	hlist_del(&f->tc_flower_node);
	devm_kfree(dev, f);
	if (f->flags & ICE_TC_FLWR_FIELD_DST_MAC)
		vf->num_dmac_chnl_fltrs--;
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
 *
 * General info about filtering mode:
 * VF ADQ has two different modes when it comes to applying the switch
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
int ice_vc_add_switch_filter(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_filter *vcf = (struct virtchnl_filter *)msg;
	struct ice_tc_flower_fltr *fltr = NULL;
	enum virtchnl_status_code v_ret;
	struct ice_vsi *dest_vsi, *vsi;
	struct ice_pf *pf = vf->pf;
	struct device *dev;
	int ret;

	dev = ice_pf_to_dev(pf);
	/* Advanced switch filters and DCF are mutually exclusive. */
	if (ice_is_dcf_enabled(pf)) {
		dev_err(dev, "Device Control Functionality is currently enabled. Advanced switch filters cannot be added\n");
		v_ret = VIRTCHNL_STATUS_ERR_NOT_SUPPORTED;
		goto err;
	}

	v_ret = ice_vc_chnl_fltr_state_verify(vf, vcf);
	if (v_ret) {
		dev_err(dev, "VF %d: failed to verify ADQ state during filter message processing\n",
			vf->vf_id);
		goto err;
	}

	vsi = ice_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(dev, "VF %d: No corresponding VF VSI\n", vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
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
	ret = ice_add_tc_flower_adv_fltr(vsi, fltr);
	if (ret) {
		dev_err(dev, "Failed to add TC Flower filter using advance filter recipe\n");
		v_ret = VIRTCHNL_STATUS_ERR_ADMIN_QUEUE_ERROR;
		devm_kfree(dev, fltr);
		goto err;
	}

	INIT_HLIST_NODE(&fltr->tc_flower_node);
	hlist_add_head(&fltr->tc_flower_node, &vf->tc_flower_fltr_list);
	if (fltr->flags & ICE_TC_FLWR_FIELD_DST_MAC)
		vf->num_dmac_chnl_fltrs++;

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
int ice_vc_add_qch_msg(struct ice_vf *vf, u8 *msg)
{
	struct virtchnl_tc_info *tci =
		(struct virtchnl_tc_info *)msg;
	enum virtchnl_status_code v_ret = VIRTCHNL_STATUS_SUCCESS;
	struct ice_pf *pf = vf->pf;
	int adq_request_qps = 0;
	struct ice_link_status *ls;
	u16 available_vsis = 0;
	u64 total_max_rate = 0;
	u32 max_tc_allowed;
	struct device *dev;
	u32 total_qs = 0;
	u32 link_speed;
	unsigned int i;

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

	/* VF ADQ and DCF are mutually exclusive. */
	if (ice_is_dcf_enabled(pf)) {
		dev_err(dev, "Device Control Functionality is currently enabled. VF ADQ cannot be enabled\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* ADQ cannot be applied if spoof check is ON */
	if (vf->spoofchk) {
		dev_err(dev, "Spoof check is ON, turn it OFF to enable ADQ\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	ice_for_each_vsi(pf, i) {
		if (!pf->vsi[i])
			++available_vsis;
	}

	if (available_vsis < tci->num_tc - 1) {
		dev_err(dev, "Not enough VSIs left to enable ADQ on VF %d\n",
			vf->vf_id);
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
		if ((u32)tci->list[i].offset + (u32)tci->list[i].count >
		    (u32)ICE_MAX_DFLT_QS_PER_VF) {
			dev_err(dev, "VF %d: Incorrect offset or count for TC %d\n",
				vf->vf_id, i);
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}
		total_qs += tci->list[i].count;
	}

	if (total_qs > ICE_MAX_DFLT_QS_PER_VF) {
		dev_err(dev, "VF %d: Total number of queues of all TCs cannot exceed %u\n",
			vf->vf_id, ICE_MAX_DFLT_QS_PER_VF);
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

	for (i = 0; i < tci->num_tc; i++) {
		if (tci->list[i].max_tx_rate > link_speed) {
			v_ret = VIRTCHNL_STATUS_ERR_PARAM;
			goto err;
		}

		if (tci->list[i].max_tx_rate)
			total_max_rate += tci->list[i].max_tx_rate;
	}

	if (total_max_rate > link_speed) {
		dev_err(dev, "Invalid tx rate specified for ADQ on VF %d\n",
			vf->vf_id);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (vf->max_tx_rate && total_max_rate > vf->max_tx_rate) {
		dev_err(dev, "Invalid tx rate specified for ADQ on VF %d, total_max_rate %llu Mpbs > host set max_tx_rate %u Mbps\n",
			vf->vf_id, total_max_rate, vf->max_tx_rate);
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	/* need Max VF queues but already have default number of queues */
	adq_request_qps = ICE_MAX_DFLT_QS_PER_VF - pf->vfs.num_qps_per;

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
		vf->num_vf_qs = ICE_MAX_DFLT_QS_PER_VF;
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
	if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2))
		ice_reset_vf(vf, ICE_VF_RESET_NOTIFY);

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
int ice_vc_del_qch_msg(struct ice_vf *vf, u8 *msg)
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

	/* VF ADQ and DCF are mutually exclusive. */
	if (ice_is_dcf_enabled(pf)) {
		dev_err(dev, "Device Control Functionality is currently enabled. VF ADQ cannot be enabled\n");
		v_ret = VIRTCHNL_STATUS_ERR_PARAM;
		goto err;
	}

	if (ice_is_vf_adq_ena(vf)) {
		/* if ADQ_V2 is set, perform inline cleanup of ADQ resources and
		 * return success and eventually VF driver will initiate reset
		 * as per design
		 */
		if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ_V2) {
			dev_info(ice_pf_to_dev(pf),
				 "Deleting Queue Channels for ADQ on VF %d and ADQ_V2 is set\n",
				 vf->vf_id);

			/* release VF ADQ filters and VSIs inline */
			ice_vf_adq_release(vf);
			v_ret = VIRTCHNL_STATUS_SUCCESS;
			goto err;
		}

#ifdef HAVE_TC_SETUP_CLSFLOWER
		/* delete all ADQ filters for given VF */
		ice_del_all_adv_switch_fltr(vf);
#endif /* HAVE_TC_SETUP_CLSFLOWER */

		/* stop all Tx/Rx rings and clean them before deleting the ADQ
		 * resources, if not it will throw fail to set the LAN Tx queue
		 * context error. This is needed irrespective of ADQ_V2. Channel
		 * related TC starts at 1. Don't down the VSI and related
		 * resources for TC 0 because it is primary VF VSI and downing
		 * that VSI is handled somewhere else.
		 */
		for (tc = ICE_VF_CHNL_START_TC; tc < vf->num_tc; tc++) {
			vsi = ice_get_vf_adq_vsi(vf, tc);
			if (!vsi) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto err;
			}
			if (vf->ch[tc].vsi_num) {
				set_bit(ICE_VSI_DOWN, vsi->state);
				ice_down(vsi);
			}
		}

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
		ice_reset_vf(vf, ICE_VF_RESET_NOTIFY);
		if (ice_is_vf_link_up(vf)) {
			/* bring the VSI 0 back up again */
			vsi = ice_get_vf_adq_vsi(vf, 0);
			if (!vsi) {
				v_ret = VIRTCHNL_STATUS_ERR_PARAM;
				goto err;
			}
			ice_up(vsi);
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

/**
 * ice_vf_adq_total_max_tx_rate - cummulative max_tx_rate when VF ADQ is enabled
 * @vf: Pointer to VF
 *
 * This function cummulative max Tx rate of all TCs if VF ADQ is enabled
 */
u64 ice_vf_adq_total_max_tx_rate(struct ice_vf *vf)
{
	u64 cummulative_max_tx_rate = 0;
	int i;

	if (!ice_is_vf_adq_ena(vf))
		return 0;

	for (i = 0; i < vf->num_tc; i++)
		cummulative_max_tx_rate += vf->ch[i].max_tx_rate;

	return cummulative_max_tx_rate;
}
#endif /* HAVE_TC_SETUP_CLSFLOWER */
