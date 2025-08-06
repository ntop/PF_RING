/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_MK_GRP_H_
#define _ICE_MK_GRP_H_

struct ice_mk_grp_item {
	int idx;
	u8 markers[8];
};

void ice_mk_grp_dump(struct ice_hw *hw, struct ice_mk_grp_item *item);
struct ice_mk_grp_item *ice_mk_grp_table_get(struct ice_hw *hw);
#endif /* _ICE_MK_GRP_H_ */
