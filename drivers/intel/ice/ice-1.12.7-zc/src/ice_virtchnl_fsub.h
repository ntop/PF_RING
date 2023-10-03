/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _ICE_VIRTCHNL_FSUB_H_
#define _ICE_VIRTCHNL_FSUB_H_

struct ice_vf;
struct ice_pf;
struct ice_vsi;

#define ICE_IPV4_PROTO_NVGRE	0x002F
#define ICE_FSUB_MAX_FLTRS	16384
#define ICE_FSUB_PRI_BASE	6

/* VF FSUB information structure */
struct ice_vf_fsub {
	struct idr fsub_rule_idr;
	struct list_head fsub_rule_list;
};

void ice_vf_fsub_init(struct ice_vf *vf);
int ice_vc_flow_sub_fltr(struct ice_vf *vf, u8 *msg);
int ice_vc_flow_unsub_fltr(struct ice_vf *vf, u8 *msg);
void ice_vf_fsub_exit(struct ice_vf *vf);
#endif /* _ICE_VIRTCHNL_FSUB_H_ */
