/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _ICE_VDCM_H_
#define _ICE_VDCM_H_

#include "ice.h"
#include <linux/uuid.h>
#if IS_ENABLED(CONFIG_VFIO_MDEV)
#include <linux/mdev.h>
#endif /* CONFIG_VFIO_MDEV */
#include <linux/vfio.h>
#include <linux/iommu.h>
#if IS_ENABLED(CONFIG_IRQ_BYPASS_MANAGER)
#include <linux/irqbypass.h>
#endif /* CONFIG_IRQ_BYPASS_MANAGER */

#define ICE_VDCM_CFG_SIZE 256
#define ICE_VDCM_BAR0_SIZE SZ_64M

struct ice_vdcm_irq_ctx {
	struct eventfd_ctx *trigger;
	char *name;
	unsigned int irq;
#if IS_ENABLED(CONFIG_IRQ_BYPASS_MANAGER)
	struct irq_bypass_producer producer;
#endif /* CONFIG_IRQ_BYPASS_MANAGER */
};

/**
 * struct ice_vdcm - The abstraction for VDCM
 *
 * @dev:		linux device for this VDCM
 * @parent_dev:		linux parent device for this VDCM
 * @vfio_group:		vfio group for this device
 * @pci_cfg_space:	PCI configuration space buffer
 * @vma_lock:		protects access to vma_list
 * @vma_list:		linked list for VMA
 * @ctx:		IRQ context
 * @num_ctx:		number of requested IRQ context
 * @irq_type:		IRQ type
 * @adi:		ADI attribute
 */
struct ice_vdcm {
	/* Common attribute */
	struct device *dev;
	struct device *parent_dev;
	struct vfio_group *vfio_group;

	u8 pci_cfg_space[ICE_VDCM_CFG_SIZE];
	struct mutex vma_lock;		/* protects access to vma_list */
	struct list_head vma_list;

	/* IRQ context */
	struct ice_vdcm_irq_ctx *ctx;
	unsigned int num_ctx;
	unsigned int irq_type;

	/* Device Specific */
	struct ice_adi *adi;
};

/**
 * struct ice_adi - Assignable Device Interface attribute
 *
 * This structure defines the device specific resource and callbacks
 *
 * It is expected to be embedded in a private container structure allocated by
 * the driver. Use container_of to get the private structure pointer back from
 * a pointer to the ice_adi structure.
 *
 * @get_vector_num: get number of vectors assigned to this ADI
 * @get_vector_irq: get OS IRQ number per vector
 * @reset: This function is called when VDCM wants to reset ADI
 * @cfg_pasid: This function is called when VDCM wants to configure ADI's PASID
 * @close: This function is called when VDCM wants to close ADI
 * @read_reg32: This function is called when VDCM wants to read ADI register
 * @write_reg32: This function is called when VDCM wants to write ADI register
 * @get_sparse_mmap_hpa: This function is called when VDCM wants to get ADI HPA
 * @get_sparse_mmap_num: This function is called when VDCM wants to get
 *			 the number of sparse memory areas
 * @get_sparse_mmap_area: This function is called when VDCM wants to get
 *			  layout of sparse memory
 */
struct ice_adi {
	int (*get_vector_num)(struct ice_adi *adi);
	int (*get_vector_irq)(struct ice_adi *adi, u32 vector);
	int (*reset)(struct ice_adi *adi);
	int (*cfg_pasid)(struct ice_adi *adi, u32 pasid, bool ena);
	int (*close)(struct ice_adi *adi);
	u32 (*read_reg32)(struct ice_adi *adi, size_t offs);
	void (*write_reg32)(struct ice_adi *adi, size_t offs, u32 val);
	int (*get_sparse_mmap_hpa)(struct ice_adi *adi, u32 index, u64 pg_off,
				   u64 *addr);
	int (*get_sparse_mmap_num)(struct ice_adi *adi);
	int (*get_sparse_mmap_area)(struct ice_adi *adi, int index,
				    u64 *offset, u64 *size);
};

#if IS_ENABLED(CONFIG_VFIO_MDEV) && defined(HAVE_PASID_SUPPORT)
struct ice_adi *ice_vdcm_alloc_adi(struct device *dev, void *token);
void ice_vdcm_free_adi(struct ice_adi *adi);
void ice_vdcm_pre_rebuild_irqctx(void *token);
int ice_vdcm_rebuild_irqctx(void *token);
int ice_vdcm_zap(void *token);
int ice_vdcm_init(struct pci_dev *pdev);
void ice_vdcm_deinit(struct pci_dev *pdev);
#else
static inline int ice_vdcm_init(struct pci_dev *pdev)
{
	return 0;
}

static inline void ice_vdcm_deinit(struct pci_dev *pdev) { }
#endif /* CONFIG_VFIO_MDEV && HAVE_PASID_SUPPORT */

#endif /* _ICE_VDCM_H_ */
