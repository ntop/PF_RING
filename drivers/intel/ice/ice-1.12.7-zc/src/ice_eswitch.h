/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _ICE_ESWITCH_H_
#define _ICE_ESWITCH_H_
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include <net/devlink.h>

void ice_eswitch_release(struct ice_pf *pf);
int ice_eswitch_configure(struct ice_pf *pf);
int ice_eswitch_rebuild(struct ice_pf *pf);
int ice_eswitch_mode_get(struct devlink *devlink, u16 *mode);
void ice_eswitch_stop_all_tx_queues(struct ice_pf *pf);
int ice_eswitch_add_vf_mac_rule(struct ice_pf *pf, struct ice_vf *vf,
				const u8 *mac);
void ice_eswitch_replay_vf_mac_rule(struct ice_vf *vf);
void ice_eswitch_del_vf_mac_rule(struct ice_vf *vf);

#ifdef HAVE_METADATA_PORT_INFO
void ice_eswitch_set_target_vsi(struct sk_buff *skb,
				struct ice_tx_offload_params *off);
void ice_eswitch_update_repr(struct ice_vsi *vsi);
#else
static inline
void ice_eswitch_set_target_vsi(struct sk_buff *skb, struct ice_tx_offload_params *off) { }
static inline void ice_eswitch_update_repr(struct ice_vsi *vsi) { }
#endif /* HAVE_METADATA_PORT_INFO */
netdev_tx_t
ice_eswitch_port_start_xmit(struct sk_buff *skb, struct net_device *netdev);
#ifdef HAVE_DEVLINK_ESWITCH_OPS_EXTACK
#ifdef HAVE_METADATA_PORT_INFO
int ice_eswitch_mode_set(struct devlink *devlink, u16 mode,
			 struct netlink_ext_ack *extack);
#else
static inline int
ice_eswitch_mode_set(struct devlink __always_unused *devlink,
		     u16 __always_unused mode,
		     struct netlink_ext_ack __always_unused *extack)
{
	return -EOPNOTSUPP;
}
#endif /* HAVE_METADATA_PORT_INFO */
#else
#ifdef HAVE_METADATA_PORT_INFO
int ice_eswitch_mode_set(struct devlink *devlink, u16 mode);
#else
static inline int ice_eswitch_mode_set(struct devlink __always_unused *devlink,
				       u16 __always_unused mode)
{
	return -EOPNOTSUPP;
}
#endif /* HAVE_METADATA_PORT_INFO */
#endif /* HAVE_DEVLINK_ESWITCH_OPS_EXTACK */
bool ice_is_eswitch_mode_switchdev(struct ice_pf *pf);
#else /* !CONFIG_NET_DEVLINK */
static inline void ice_eswitch_release(struct ice_pf *pf) { }
static inline
void ice_eswitch_set_target_vsi(struct sk_buff *skb, struct ice_tx_offload_params *off) { }
static inline void ice_eswitch_update_repr(struct ice_vsi *vsi) { }
static inline void ice_eswitch_stop_all_tx_queues(struct ice_pf *pf) { }
static inline void ice_eswitch_replay_vf_mac_rule(struct ice_vf *vf) { }
static inline void ice_eswitch_del_vf_mac_rule(struct ice_vf *vf) { }

static inline int
ice_eswitch_add_vf_mac_rule(struct ice_pf *pf, struct ice_vf *vf,
			    const u8 *mac)
{
	return 0;
}

static inline int
ice_eswitch_configure(struct ice_pf *pf)
{
	return 0;
}

static inline bool
ice_is_eswitch_mode_switchdev(struct ice_pf __always_unused *pf)
{
	return false;
}

static inline int
ice_eswitch_rebuild(struct ice_pf __always_unused *pf)
{
	return 0;
}

static inline netdev_tx_t
ice_eswitch_port_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	return 0;
}
#endif /* CONFIG_NET_DEVLINK */
#endif
