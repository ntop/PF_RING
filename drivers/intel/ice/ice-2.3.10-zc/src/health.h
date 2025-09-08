/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _HEALTH_H_
#define _HEALTH_H_

#include "kcompat.h"
#include <linux/types.h>

struct ice_pf;
struct ice_tx_ring;

enum ice_mdd_src {
	ICE_MDD_SRC_TX_PQM,
	ICE_MDD_SRC_TX_TCLAN,
	ICE_MDD_SRC_TX_TDPU,
	ICE_MDD_SRC_RX,
};

#ifdef HAVE_DEVLINK_HEALTH

/**
 * struct ice_health couples all ice devlink health reporters and accompanied
 * data
 */
struct ice_health {
	struct devlink_health_reporter *mdd;
	struct devlink_health_reporter *tx_hang;
};

void ice_health_init(struct ice_pf *pf);
void ice_health_deinit(struct ice_pf *pf);
void ice_health_clear(struct ice_pf *pf);

void ice_devlink_report_mdd_event(struct ice_pf *pf, enum ice_mdd_src src,
				  u8 pf_num, u16 vf_num, u8 event, u16 queue);
void ice_report_tx_hang(struct ice_pf *pf, struct ice_tx_ring *tx_ring,
			u16 vsi_num, u32 head, u32 intr);

#else /* HAVE_DEVLINK_HEALTH */

static inline void ice_health_init(struct ice_pf *pf) {}
static inline void ice_health_deinit(struct ice_pf *pf) {}
static inline void ice_health_clear(struct ice_pf *pf) {}

static inline
void ice_devlink_report_mdd_event(struct ice_pf *pf, enum ice_mdd_src src,
				  u8 pf_num, u16 vf_num, u8 event, u16 queue) {}
static inline
void ice_report_tx_hang(struct ice_pf *pf, struct ice_tx_ring *tx_ring,
			u16 vsi_num, u32 head, u32 intr) {}

#endif /* HAVE_DEVLINK_HEALTH */
#endif /* _HEALTH_H_ */
