/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _ICE_IDC_INT_H_
#define _ICE_IDC_INT_H_

#include "ice.h"
#include "ice_idc.h"

enum ice_peer_dev_state {
	ICE_PEER_DEV_STATE_INIT,
	ICE_PEER_DEV_STATE_PROBED,
	ICE_PEER_DEV_STATE_OPENING,
	ICE_PEER_DEV_STATE_OPENED,
	ICE_PEER_DEV_STATE_PREP_RST,
	ICE_PEER_DEV_STATE_PREPPED,
	ICE_PEER_DEV_STATE_CLOSING,
	ICE_PEER_DEV_STATE_CLOSED,
	ICE_PEER_DEV_STATE_REMOVED,
	ICE_PEER_DEV_STATE_API_RDY,
	ICE_PEER_DEV_STATE_NBITS,               /* must be last */
};

enum ice_peer_drv_state {
	ICE_PEER_DRV_STATE_MBX_RDY,
	ICE_PEER_DRV_STATE_NBITS,               /* must be last */
};

struct ice_peer_drv_int {
	struct ice_peer_drv *peer_drv;

	/* States associated with peer driver */
	DECLARE_BITMAP(state, ICE_PEER_DRV_STATE_NBITS);

	/* if this peer_dev is the originator of an event, these are the
	 * most recent events of each type
	 */
	struct ice_event current_events[ICE_EVENT_NBITS];
};

#define ICE_MAX_PEER_NAME 64

struct ice_peer_dev_int {
	struct ice_peer_dev peer_dev;
	struct ice_peer_drv_int *peer_drv_int; /* driver private structure */
	char plat_name[ICE_MAX_PEER_NAME];
	struct ice_peer_dev_platform_data plat_data;

	/* if this peer_dev is the originator of an event, these are the
	 * most recent events of each type
	 */
	struct ice_event current_events[ICE_EVENT_NBITS];
	/* Events a peer has registered to be notified about */
	DECLARE_BITMAP(events, ICE_EVENT_NBITS);

	/* States associated with peer device */
	DECLARE_BITMAP(state, ICE_PEER_DEV_STATE_NBITS);
	struct mutex peer_dev_state_mutex; /* peer_dev state mutex */

	/* per peer workqueue */
	struct workqueue_struct *ice_peer_wq;

	struct work_struct peer_prep_task;
	struct work_struct peer_close_task;

	enum ice_close_reason rst_type;
};

static inline struct
ice_peer_dev_int *peer_to_ice_dev_int(struct ice_peer_dev *peer_dev)
{
	return peer_dev ? container_of(peer_dev, struct ice_peer_dev_int,
				       peer_dev) : NULL;
}

static inline struct
ice_peer_dev *ice_get_peer_dev(struct ice_peer_dev_int *peer_dev_int)
{
	if (peer_dev_int)
		return &peer_dev_int->peer_dev;
	else
		return NULL;
}

#if IS_ENABLED(CONFIG_MFD_CORE)
int ice_peer_update_vsi(struct ice_peer_dev_int *peer_dev_int, void *data);
int ice_close_peer_for_reset(struct ice_peer_dev_int *peer_dev_int, void *data);
int ice_unroll_peer(struct ice_peer_dev_int *peer_dev_int, void *data);
int ice_unreg_peer_device(struct ice_peer_dev_int *peer_dev_int, void *data);
int ice_peer_close(struct ice_peer_dev_int *peer_dev_int, void *data);
int ice_peer_check_for_reg(struct ice_peer_dev_int *peer_dev_int, void *data);
int
ice_finish_init_peer_device(struct ice_peer_dev_int *peer_dev_int, void *data);
static inline bool ice_validate_peer_dev(struct ice_peer_dev *peer_dev)
{
	struct ice_peer_dev_int *peer_dev_int;
	struct ice_pf *pf;

	if (!peer_dev || !peer_dev->pdev)
		return false;

	if (!peer_dev->peer_ops)
		return false;

	pf = pci_get_drvdata(peer_dev->pdev);
	if (!pf)
		return false;

	peer_dev_int = peer_to_ice_dev_int(peer_dev);
	if (!peer_dev_int)
		return false;

	if (test_bit(ICE_PEER_DEV_STATE_REMOVED, peer_dev_int->state) ||
	    test_bit(ICE_PEER_DEV_STATE_INIT, peer_dev_int->state))
		return false;

	return true;
}
#else /* !CONFIG_MFD_CORE */
static inline int
ice_peer_update_vsi(struct ice_peer_dev_int *peer_dev_int, void *data)
{
	return 0;
}

static inline int
ice_close_peer_for_reset(struct ice_peer_dev_int *peer_dev_int, void *data)
{
	return 0;
}

static inline int
ice_unroll_peer(struct ice_peer_dev_int *peer_dev_int, void *data)
{
	return 0;
}

static inline int
ice_unreg_peer_device(struct ice_peer_dev_int *peer_dev_int, void *data)
{
	return 0;
}

static inline int
ice_peer_close(struct ice_peer_dev_int *peer_dev_int, void *data)
{
	return 0;
}

static inline int
ice_peer_check_for_reg(struct ice_peer_dev_int *peer_dev_int, void *data)
{
	return 0;
}

static inline int
ice_finish_init_peer_device(struct ice_peer_dev_int *peer_dev_int, void *data)
{
	return 0;
}

static inline bool ice_validate_peer_dev(struct ice_peer_dev *peer)
{
	return true;
}

#endif /* !CONFIG_MFD_CORE */

#endif /* !_ICE_IDC_INT_H_ */
