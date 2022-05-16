// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2021, Intel Corporation. */

#include "ice_type.h"
#include "ice_common.h"
#include "ice_ioctl.h"
#include "ice_sched_cfg.h"
#include "ice_sched.h"
#include "ice_lib.h"

/**
 * ice_get_rl_type - mapping QoS rl_type to corresponding ice_rl_type
 * @value: value for mapping
 */
static enum ice_rl_type ice_get_rl_type(enum ice_qos_rl_type value)
{
	switch (value) {
	case ICE_QOS_MIN_BW:
		return ICE_MIN_BW;
	case ICE_QOS_MAX_BW:
		return ICE_MAX_BW;
	default:
		return ICE_UNKNOWN_BW;
	}
};

/**
 * ice_sched_cfg_set_bw_lmt - set BW limit per port
 * @pf: pointer to PF structure
 * @cfg_data: pointer to configuration structure
 */
int ice_sched_cfg_set_bw_lmt(struct ice_pf *pf,
			     ice_cfg_set_bw_lmt_data *cfg_data)
{
	enum ice_rl_type rl_type = ice_get_rl_type(cfg_data->bw_cfg.rl_type);
	struct ice_port_info *pi;
	enum ice_status status;

	pi = ice_find_port_info(&pf->hw, cfg_data->port);
	if (!pi)
		return -EINVAL;

	status = ice_cfg_tc_node_bw_lmt(pi, cfg_data->tc,
					rl_type, cfg_data->bw_cfg.bw);
	return ice_status_to_errno(status);
}

/**
 * ice_sched_cfg_rm_bw_lmt - remove BW limit per port
 * @pf: pointer to PF structure
 * @cfg_data: pointer to configuration structure
 */
int ice_sched_cfg_rm_bw_lmt(struct ice_pf *pf,
			    ice_cfg_rm_bw_lmt_data *cfg_data)
{
	enum ice_rl_type rl_type = ice_get_rl_type(cfg_data->bw_cfg.rl_type);
	struct ice_port_info *pi;
	enum ice_status status;

	pi = ice_find_port_info(&pf->hw, cfg_data->port);
	if (!pi)
		return -EINVAL;

	status = ice_cfg_tc_node_bw_dflt_lmt(pi, cfg_data->tc, rl_type);
	return ice_status_to_errno(status);
}

/**
 * ice_sched_cfg_bw_alloc - allocate BW limit per port
 * @pf: pointer to PF structure
 * @cfg_data: pointer to configuration structure
 */
int ice_sched_cfg_bw_alloc(struct ice_pf *pf,
			   ice_cfg_bw_alloc_data *cfg_data)
{
	enum ice_rl_type rl_type = ice_get_rl_type(cfg_data->bw_cfg.rl_type);
	struct ice_port_info *pi;
	enum ice_status status;

	pi = ice_find_port_info(&pf->hw, cfg_data->port);
	if (!pi)
		return -EINVAL;

	status = ice_cfg_tc_node_bw_alloc(pi, cfg_data->tc,
					  rl_type, cfg_data->bw_cfg.bw_alloc);
	return ice_status_to_errno(status);
}

/**
 * ice_sched_cfg_vf_set_bw_lmt - set BW limit configuration per VF
 * @pf: pointer to PF structure
 * @cfg_data: pointer to configuration structure
 */
int ice_sched_cfg_vf_set_bw_lmt(struct ice_pf *pf,
				ice_cfg_vf_set_bw_lmt_data *cfg_data)
{
	enum ice_rl_type rl_type = ice_get_rl_type(cfg_data->bw_cfg.rl_type);
	struct ice_port_info *pi;
	enum ice_status status;
	struct ice_vsi *vsi;
	struct ice_vf *vf;

	vf = ice_get_vf_by_id(pf, cfg_data->vf_num);
	if (!vf)
		return -EINVAL;

	pi = &pf->hw.port_info[vf->port_assoc];
	vsi = ice_get_vf_vsi(vf);
	status = ice_cfg_vsi_bw_lmt_per_tc(pi, vsi->idx, cfg_data->tc,
					   rl_type, cfg_data->bw_cfg.bw);
	ice_put_vf(vf);
	return ice_status_to_errno(status);
}

/**
 * ice_sched_cfg_vf_rm_bw_lmt - remove BW limit per VF
 * @pf: pointer to PF structure
 * @cfg_data: pointer to configuration structure
 */
int ice_sched_cfg_vf_rm_bw_lmt(struct ice_pf *pf,
			       ice_cfg_vf_rm_bw_lmt_data *cfg_data)
{
	enum ice_rl_type rl_type = ice_get_rl_type(cfg_data->bw_cfg.rl_type);
	struct ice_port_info *pi;
	enum ice_status status;
	struct ice_vsi *vsi;
	struct ice_vf *vf;

	vf = ice_get_vf_by_id(pf, cfg_data->vf_num);
	if (!vf)
		return -EINVAL;

	pi = &pf->hw.port_info[vf->port_assoc];
	vsi = ice_get_vf_vsi(vf);
	status = ice_cfg_vsi_bw_dflt_lmt_per_tc(pi, vsi->idx, cfg_data->tc,
						rl_type);
	ice_put_vf(vf);
	return ice_status_to_errno(status);
}

/**
 * ice_sched_cfg_vf_bw_alloc - allocate BW limit per VF
 * @pf: pointer to PF structure
 * @cfg_data: pointer to configuration structure
 */
int ice_sched_cfg_vf_bw_alloc(struct ice_pf *pf,
			      ice_cfg_vf_bw_alloc_data *cfg_data)
{
	enum ice_rl_type rl_type = ice_get_rl_type(cfg_data->bw_cfg.rl_type);
	u8 bw_alloc[ICE_MAX_TRAFFIC_CLASS];
	u8 tcmap = BIT(cfg_data->tc);
	struct ice_port_info *pi;
	enum ice_status status;
	struct ice_vsi *vsi;
	struct ice_vf *vf;

	if (cfg_data->tc >= ICE_MAX_TRAFFIC_CLASS)
		return -EINVAL;

	bw_alloc[cfg_data->tc] = cfg_data->bw_cfg.bw_alloc;

	vf = ice_get_vf_by_id(pf, cfg_data->vf_num);
	if (!vf)
		return -EINVAL;

	pi = &pf->hw.port_info[vf->port_assoc];
	vsi = ice_get_vf_vsi(vf);
	status = ice_cfg_vsi_bw_alloc(pi, vsi->idx, tcmap,
				      rl_type, &bw_alloc[0]);
	ice_put_vf(vf);
	return ice_status_to_errno(status);
}

/**
 * ice_sched_cfg_q_set_bw_lmt - set BW limit per queue
 * @pf: pointer to PF structure
 * @cfg_data: pointer to configuration structure
 */
int ice_sched_cfg_q_set_bw_lmt(struct ice_pf *pf,
			       ice_cfg_q_set_bw_lmt_data *cfg_data)
{
	enum ice_rl_type rl_type = ice_get_rl_type(cfg_data->bw_cfg.rl_type);
	struct ice_port_info *pi;
	enum ice_status status;
	struct ice_vsi *vsi;
	struct ice_vf *vf;
	u16 q_handle;

	vf = ice_get_vf_by_id(pf, cfg_data->vf_num);
	if (!vf)
		return -EINVAL;

	pi = &pf->hw.port_info[vf->port_assoc];
	vsi = ice_get_vf_vsi(vf);

	if (cfg_data->q_num >= vsi->alloc_txq ||
	    cfg_data->tc != vsi->tx_rings[cfg_data->q_num]->tc ||
	    vsi->tx_rings[cfg_data->q_num]->txq_teid == 0) {
		ice_put_vf(vf);
		return -EINVAL;
	}

	q_handle = vsi->tx_rings[cfg_data->q_num]->q_handle;

	status = ice_cfg_q_bw_lmt(pi, vsi->idx, cfg_data->tc, q_handle,
				  rl_type, cfg_data->bw_cfg.bw);
	ice_put_vf(vf);
	return ice_status_to_errno(status);
}

/**
 * ice_sched_cfg_q_rm_bw_lmt - remove BW limit per queue
 * @pf: pointer to PF structure
 * @cfg_data: pointer to configuration structure
 */
int ice_sched_cfg_q_rm_bw_lmt(struct ice_pf *pf,
			      ice_cfg_q_rm_bw_lmt_data *cfg_data)
{
	enum ice_rl_type rl_type = ice_get_rl_type(cfg_data->bw_cfg.rl_type);
	struct ice_port_info *pi;
	enum ice_status status;
	struct ice_vsi *vsi;
	struct ice_vf *vf;
	u16 q_handle;

	vf = ice_get_vf_by_id(pf, cfg_data->vf_num);
	if (!vf)
		return -EINVAL;

	pi = &pf->hw.port_info[vf->port_assoc];
	vsi = ice_get_vf_vsi(vf);

	if (cfg_data->q_num >= vsi->alloc_txq ||
	    cfg_data->tc != vsi->tx_rings[cfg_data->q_num]->tc ||
	    vsi->tx_rings[cfg_data->q_num]->txq_teid == 0) {
		ice_put_vf(vf);
		return -EINVAL;
	}

	q_handle = vsi->tx_rings[cfg_data->q_num]->q_handle;

	status = ice_cfg_q_bw_dflt_lmt(pi, vsi->idx, cfg_data->tc, q_handle,
				       rl_type);
	ice_put_vf(vf);
	return ice_status_to_errno(status);
}
