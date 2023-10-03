/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _ICE_PEER_SUPPORT_H_
#define _ICE_PEER_SUPPORT_H_
int ice_init_peer(struct ice_pf *pf);
void ice_deinit_peer(struct ice_pf *pf);
void ice_remove_peer(struct ice_pf *pf);
#endif /* _ICE_PEER_SUPPORT_H_ */
