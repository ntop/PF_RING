/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

/* Intel(R) Ethernet Connection E800 Series Linux Driver IEPS extensions */

#ifndef _ICE_IEPS_H_
#define _ICE_IEPS_H_

#include "ieps_peer.h"
#include "iidc.h"

int ice_ieps_entry(struct iidc_core_dev_info *obj, void *arg);

void ice_cdev_init_ieps_info(struct ice_hw *hw,
			     enum iidc_ieps_nac_mode *nac_mode);
void ice_ieps_handle_link_event(struct ice_hw *hw);
enum ieps_peer_status ice_ieps_get_link_state_speed(struct ice_hw *hw,
						    bool *link_up,
						    u16 *link_speed);
enum ieps_peer_status ice_ieps_exec_cpi(struct ice_hw *hw,
					struct ieps_peer_cpi_cmd_resp *cpi);
void ice_ieps_init_lm_ops(struct ice_hw *hw, bool en_fw_ops);
#endif /* _ICE_IEPS_H_ */
