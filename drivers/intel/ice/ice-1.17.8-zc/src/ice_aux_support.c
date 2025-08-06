/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice.h"
#include "ice_lib.h"
#include "ice_aux_support.h"
#include "ice_idc_int.h"

int ice_init_aux(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	int err;

	if (!ice_is_aux_ena(pf)) {
		dev_warn(dev, "Aux drivers are not supported on this device\n");
		return 0;
	}

	pf->cdev_infos = devm_kcalloc(dev, IIDC_MAX_NUM_AUX,
				      sizeof(*pf->cdev_infos), GFP_KERNEL);
	if (!pf->cdev_infos)
		return -ENOMEM;

	err = ice_init_aux_devices(pf);
	if (err) {
		dev_err(dev, "Failed to initialize aux devs: %d\n",
			err);
		return -EIO;
	}

	return err;
}

void ice_deinit_aux(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);

	ice_for_each_aux(pf, NULL, ice_unroll_cdev_info);
	devm_kfree(dev, pf->cdev_infos);
	pf->cdev_infos = NULL;
}
