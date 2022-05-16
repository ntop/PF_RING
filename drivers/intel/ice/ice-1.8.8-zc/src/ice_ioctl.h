/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _ICE_IOCTL_H_
#define _ICE_IOCTL_H_

#include "ice.h"
#include "ice_ioctl_user.h"

typedef struct ice_qos_tc_cfg ice_cfg_set_bw_lmt_data;
typedef struct ice_qos_tc_cfg ice_cfg_rm_bw_lmt_data;
typedef struct ice_qos_tc_cfg ice_cfg_bw_alloc_data;

typedef struct ice_qos_vf_cfg ice_cfg_vf_set_bw_lmt_data;
typedef struct ice_qos_vf_cfg ice_cfg_vf_rm_bw_lmt_data;
typedef struct ice_qos_vf_cfg ice_cfg_vf_bw_alloc_data;

typedef struct ice_qos_q_cfg ice_cfg_q_set_bw_lmt_data;
typedef struct ice_qos_q_cfg ice_cfg_q_rm_bw_lmt_data;

typedef int (*ice_ioctl_cb_fn_t)(struct ice_pf *pf,
				 unsigned long arg,
				 u16 size);

void init_ioctl(struct device *dev, struct cdev *cdev);
void deinit_ioctl(struct cdev *cdev);

#endif /* _ICE_IOCTL_H_ */
