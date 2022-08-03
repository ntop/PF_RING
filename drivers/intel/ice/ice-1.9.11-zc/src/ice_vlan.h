/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _ICE_VLAN_H_
#define _ICE_VLAN_H_

#include <linux/types.h>
#include "ice_type.h"

struct ice_vlan {
	u16 tpid;
	u16 vid;
	u8 prio;
	enum ice_sw_fwd_act_type fwd_act;
};

#define ICE_VLAN(tpid, vid, prio, fwd_action)	\
	((struct ice_vlan){ tpid, vid, prio, fwd_action })
#endif /* _ICE_VLAN_H_ */
