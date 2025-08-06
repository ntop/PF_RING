/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_HWMON_H_
#define _ICE_HWMON_H_

#ifdef HAVE_HWMON_DEVICE_REGISTER_WITH_INFO
void ice_hwmon_init(struct ice_pf *pf);
void ice_hwmon_exit(struct ice_pf *pf);
#endif /* HAVE_HWMON_DEVICE_REGISTER_WITH_INFO */

#endif /* _ICE_HWMON_H_ */
