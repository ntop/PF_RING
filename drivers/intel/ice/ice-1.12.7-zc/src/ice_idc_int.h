/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _ICE_IDC_INT_H_
#define _ICE_IDC_INT_H_

#include "iidc.h"

#define ICE_MAX_NUM_AUX		4

struct ice_pf;
void ice_send_event_to_auxs(struct ice_pf *pf, struct iidc_event *event);
struct iidc_auxiliary_drv
*ice_get_auxiliary_drv(struct iidc_core_dev_info *cdev_info);
void ice_send_event_to_aux_no_lock(struct iidc_core_dev_info *cdev, void *data);

void ice_cdev_info_update_vsi(struct iidc_core_dev_info *cdev_info,
			      struct ice_vsi *vsi);
int ice_unroll_cdev_info(struct iidc_core_dev_info *cdev_info, void *data);
struct iidc_core_dev_info
*ice_find_cdev_info_by_id(struct ice_pf *pf, int cdev_info_id);
void ice_send_vf_reset_to_aux(struct iidc_core_dev_info *cdev_info, u16 vf_id);
bool ice_is_rdma_aux_loaded(struct ice_pf *pf);

#endif /* !_ICE_IDC_INT_H_ */
