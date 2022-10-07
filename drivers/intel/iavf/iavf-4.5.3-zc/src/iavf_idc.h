/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2013, Intel Corporation. */

#ifndef _IAVF_IDC_H_
#define _IAVF_IDC_H_

#include "iidc.h"

struct iavf_adapter;

void iavf_idc_init_task(struct work_struct *work);
void iavf_idc_init(struct iavf_adapter *adapter);
void iavf_idc_deinit(struct iavf_adapter *adapter);
void iavf_idc_vc_receive(struct iavf_adapter *adapter, u8 *msg, u16 msglen);

#endif /* _IAVF_IDC_H_ */
