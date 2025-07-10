/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_MIGRATION_PRIVATE_H_
#define _ICE_MIGRATION_PRIVATE_H_

/* This header file is for exposing functions in ice_migration.c to
 * files which will be compiled in ice.ko.
 * Functions which may be used by other files which will be compiled
 * in ice-vfio-pic.ko should be exposed as part of ice_migration.h.
 */

#if IS_ENABLED(CONFIG_VFIO_PCI_CORE) && defined(HAVE_LMV1_SUPPORT)
void ice_migration_save_vf_msg(struct ice_vf *vf,
			       struct ice_rq_event_info *event);
void ice_migration_fix_msg_vsi(struct ice_vf *vf, u32 v_opcode, u8 *msg);
u32 ice_migration_supported_caps(void);
#else
static inline void
ice_migration_save_vf_msg(struct ice_vf *vf,
			  struct ice_rq_event_info *event) { }
static inline u32
ice_migration_supported_caps(void)
{
	return 0xFFFFFFFF;
}
#endif /* CONFIG_VFIO_PCI_CORE && HAVE_LMV1_SUPPORT */

#endif /* _ICE_MIGRATION_PRIVATE_H_ */
