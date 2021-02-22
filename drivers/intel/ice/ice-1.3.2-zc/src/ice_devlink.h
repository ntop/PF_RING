/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _ICE_DEVLINK_H_
#define _ICE_DEVLINK_H_

#if IS_ENABLED(CONFIG_NET_DEVLINK)
struct ice_pf *ice_allocate_pf(struct device *dev);

int ice_devlink_register(struct ice_pf *pf);
void ice_devlink_unregister(struct ice_pf *pf);
void ice_devlink_params_publish(struct ice_pf *pf);
void ice_devlink_params_unpublish(struct ice_pf *pf);
int ice_devlink_create_port(struct ice_vsi *vsi);
void ice_devlink_destroy_port(struct ice_vsi *vsi);
#else /* CONFIG_NET_DEVLINK */
static inline struct ice_pf *ice_allocate_pf(struct device *dev)
{
	return devm_kzalloc(dev, sizeof(struct ice_pf), GFP_KERNEL);
}

static inline int ice_devlink_register(struct ice_pf *pf) { return 0; }
#define ice_devlink_unregister(pf) do {} while (0)
#define ice_devlink_params_publish(pf) do {} while (0)
#define ice_devlink_params_unpublish(pf) do {} while (0)
static inline int ice_devlink_create_port(struct ice_vsi *vsi) { return 0; }
#define ice_devlink_destroy_port(vsi) do {} while (0)
#endif /* !CONFIG_NET_DEVLINK */

#if IS_ENABLED(CONFIG_NET_DEVLINK) && defined(HAVE_DEVLINK_REGIONS)
void ice_devlink_init_regions(struct ice_pf *pf);
void ice_devlink_destroy_regions(struct ice_pf *pf);
#else
#define ice_devlink_init_regions(pf) do {} while (0)
#define ice_devlink_destroy_regions(pf) do {} while (0)
#endif

#endif /* _ICE_DEVLINK_H_ */
