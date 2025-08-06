/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_DEVLINK_H_
#define _ICE_DEVLINK_H_

#if IS_ENABLED(CONFIG_NET_DEVLINK)
struct ice_pf *ice_allocate_pf(struct device *dev);

void ice_devlink_register(struct ice_pf *pf);
void ice_devlink_unregister(struct ice_pf *pf);
int ice_devlink_register_params(struct ice_pf *pf);
void ice_devlink_unregister_params(struct ice_pf *pf);
#ifdef HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT
int ice_devlink_register_resources(struct ice_pf *pf);
void ice_devlink_unregister_resources(struct ice_pf *pf);
#else
static inline int ice_devlink_register_resources(struct ice_pf *pf)
{
	return 0;
}

static inline void ice_devlink_unregister_resources(struct ice_pf *pf) { }
#endif /* HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT */
int ice_devlink_create_pf_port(struct ice_pf *pf);
void ice_devlink_destroy_pf_port(struct ice_pf *pf);
#ifdef HAVE_DEVLINK_PORT_ATTR_PCI_VF
int ice_devlink_create_vf_port(struct ice_vf *vf);
void ice_devlink_destroy_vf_port(struct ice_vf *vf);
#endif /* HAVE_DEVLINK_PORT_ATTR_PCI_VF */
#else /* CONFIG_NET_DEVLINK */
static inline struct ice_pf *ice_allocate_pf(struct device *dev)
{
	return devm_kzalloc(dev, sizeof(struct ice_pf), GFP_KERNEL);
}

static inline void ice_devlink_register(struct ice_pf *pf) { }
static inline void ice_devlink_unregister(struct ice_pf *pf) { }
static inline int ice_devlink_register_params(struct ice_pf *pf) { return 0; }
static inline void ice_devlink_unregister_params(struct ice_pf *pf) { }
static inline int ice_devlink_register_resources(struct ice_pf *pf)
{
	return 0;
}

static inline void ice_devlink_unregister_resources(struct ice_pf *pf) { }
static inline int ice_devlink_create_pf_port(struct ice_pf *pf) { return 0; }
static inline void ice_devlink_destroy_pf_port(struct ice_pf *pf) { }
#ifdef HAVE_DEVLINK_PORT_ATTR_PCI_VF
static inline int ice_devlink_create_vf_port(struct ice_vf *vf) { return 0; }
static inline void ice_devlink_destroy_vf_port(struct ice_vf *vf) { }
#endif /* HAVE_DEVLINK_PORT_ATTR_PCI_VF */
#endif /* !CONFIG_NET_DEVLINK */

#if IS_ENABLED(CONFIG_NET_DEVLINK) && defined(HAVE_DEVLINK_REGIONS)
void ice_devlink_init_regions(struct ice_pf *pf);
void ice_devlink_destroy_regions(struct ice_pf *pf);
#else
static inline void ice_devlink_init_regions(struct ice_pf *pf) { }
static inline void ice_devlink_destroy_regions(struct ice_pf *pf) { }
#endif

int ice_devlink_tc_params_register(struct ice_vsi *vsi);
void ice_devlink_tc_params_unregister(struct ice_vsi *vsi);

#ifdef HAVE_DEVLINK_RATE_NODE_CREATE
int ice_devlink_rate_init_tx_topology(struct devlink *devlink, struct ice_vsi *vsi);
void ice_tear_down_devlink_rate_tree(struct ice_pf *pf);
void ice_devlink_rate_clear_tx_topology(struct ice_vsi *vsi);
#endif /* HAVE_DEVLINK_RATE_NODE_CREATE */

#endif /* _ICE_DEVLINK_H_ */
