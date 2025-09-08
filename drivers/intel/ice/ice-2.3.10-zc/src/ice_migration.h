/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_MIGRATION_H_
#define _ICE_MIGRATION_H_

#include "kcompat.h"
#include <linux/kvm_host.h>

#define IAVF_QRX_TAIL_MAX 256
#if IS_ENABLED(CONFIG_VFIO_PCI_CORE) && defined(HAVE_LMV1_SUPPORT)
void *ice_migration_get_vf(struct pci_dev *vf_pdev);
void ice_migration_init_vf(void *opaque);
void ice_migration_uninit_vf(void *opaque);
int ice_migration_suspend_vf(void *opaque);
int ice_migration_save_devstate(void *opaque, u8 *buf, u64 buf_sz);
int ice_migration_restore_devstate(void *opaque, const u8 *buf, u64 buf_sz,
				   struct kvm *kvm);
#else
static inline void *ice_migration_get_vf(struct pci_dev *vf_pdev)
{
	return NULL;
}

static inline void ice_migration_init_vf(void *opaque) { }
static inline void ice_migration_uninit_vf(void *opaque) { }

static inline int ice_migration_suspend_vf(void *opaque)
{
	return 0;
}

static inline int ice_migration_save_devstate(void *opaque, u8 *buf, u64 buf_sz)
{
	return 0;
}

static inline int ice_migration_restore_devstate(void *opaque, const u8 *buf,
						 u64 buf_sz, struct kvm *kvm)
{
	return 0;
}
#endif /* CONFIG_VFIO_PCI_CORE && HAVE_LMV1_SUPPORT */

#endif /* _ICE_MIGRATION_H_ */
