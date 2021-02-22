/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _ICE_VSI_VLAN_OPS_H_
#define _ICE_VSI_VLAN_OPS_H_

#include "ice_type.h"

struct ice_vsi;

struct ice_vlan {
	u16 tpid;
	u16 vid;
	u8 prio;
	enum ice_sw_fwd_act_type fwd_act;
};

#define ICE_VLAN(tpid, vid, prio, fwd_action)	\
	(struct ice_vlan){ tpid, vid, prio, fwd_action }

struct ice_vsi_vlan_ops {
	int (*add_vlan)(struct ice_vsi *vsi, struct ice_vlan vlan);
	int (*del_vlan)(struct ice_vsi *vsi, struct ice_vlan vlan);
	int (*ena_stripping)(struct ice_vsi *vsi, const u16 tpid);
	int (*dis_stripping)(struct ice_vsi *vsi);
	int (*ena_insertion)(struct ice_vsi *vsi, const u16 tpid);
	int (*dis_insertion)(struct ice_vsi *vsi);
	int (*set_port_vlan)(struct ice_vsi *vsi, struct ice_vlan vlan);
};

void ice_vsi_init_vlan_ops(struct ice_vsi *vsi);

#endif /* _ICE_VSI_VLAN_OPS_H_ */

