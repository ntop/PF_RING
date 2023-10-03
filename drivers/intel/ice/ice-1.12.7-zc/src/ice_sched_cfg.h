/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _ICE_SCHED_CFG_H_
#define _ICE_SCHED_CFG_H_

int ice_sched_cfg_set_bw_lmt(struct ice_pf *pf,
			     ice_cfg_set_bw_lmt_data *cfg_data);
int ice_sched_cfg_rm_bw_lmt(struct ice_pf *pf,
			    ice_cfg_rm_bw_lmt_data *cfg_data);
int ice_sched_cfg_bw_alloc(struct ice_pf *pf,
			   ice_cfg_bw_alloc_data *cfg_data);

int ice_sched_cfg_vf_set_bw_lmt(struct ice_pf *pf,
				ice_cfg_vf_set_bw_lmt_data *cfg_data);
int ice_sched_cfg_vf_rm_bw_lmt(struct ice_pf *pf,
			       ice_cfg_vf_rm_bw_lmt_data *cfg_data);
int ice_sched_cfg_vf_bw_alloc(struct ice_pf *pf,
			      ice_cfg_vf_bw_alloc_data *cfg_data);

int ice_sched_cfg_q_set_bw_lmt(struct ice_pf *pf,
			       ice_cfg_q_set_bw_lmt_data *cfg_data);
int ice_sched_cfg_q_rm_bw_lmt(struct ice_pf *pf,
			      ice_cfg_q_rm_bw_lmt_data *cfg_data);

#endif /* _ICE_SCHED_CFG_H_ */
