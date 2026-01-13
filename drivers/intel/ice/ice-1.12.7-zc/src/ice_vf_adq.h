/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _ICE_VF_ADQ_H_
#define _ICE_VF_ADQ_H_

struct ice_vsi *ice_get_vf_adq_vsi(struct ice_vf *vf, u8 tc);
bool ice_is_vf_adq_ena(struct ice_vf *vf);
bool ice_vf_adq_vsi_valid(struct ice_vf *vf, u8 tc);
void ice_del_all_adv_switch_fltr(struct ice_vf *vf);
void ice_vf_adq_release(struct ice_vf *vf);
void ice_vf_rebuild_adq_host_cfg(struct ice_vf *vf);
int ice_vf_recreate_adq_vsi(struct ice_vf *vf);
int ice_vf_rebuild_adq_vsi(struct ice_vf *vf);
u16 ice_vf_get_tc_based_qid(u16 qid, u16 offset);
void ice_vf_q_id_get_vsi_q_id(struct ice_vf *vf, u16 vf_q_id, u16 *t_tc,
			      struct virtchnl_queue_select *vqs,
			      struct ice_vsi **vsi_p, u16 *vsi_id,
			      u16 *q_id);
int ice_vc_del_switch_filter(struct ice_vf *vf, u8 *msg);
int ice_vc_add_switch_filter(struct ice_vf *vf, u8 *msg);
int ice_vc_add_qch_msg(struct ice_vf *vf, u8 *msg);
int ice_vc_del_qch_msg(struct ice_vf *vf, u8 *msg);
u64 ice_vf_adq_total_max_tx_rate(struct ice_vf *vf);

#endif /* _ICE_VF_ADQ_H_ */
