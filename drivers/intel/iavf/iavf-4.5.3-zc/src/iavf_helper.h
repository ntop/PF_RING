/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2013, Intel Corporation. */

#ifndef _IAVF_HELPER_H_
#define _IAVF_HELPER_H_

#include "iavf_alloc.h"

/**
 * iavf_allocate_dma_mem_d - OS specific memory alloc for shared code
 * @hw:   pointer to the HW structure
 * @mem:  ptr to mem struct to fill out
 * @mtype: unused parameter for documenting memory type of dma
 * @size: size of memory requested
 * @alignment: what to align the allocation to
 **/
inline int iavf_allocate_dma_mem_d(struct iavf_hw *hw,
				   struct iavf_dma_mem *mem,
				   __always_unused enum iavf_memory_type mtype,
				   u64 size, u32 alignment)
{
	struct iavf_adapter *nf = (struct iavf_adapter *)hw->back;

	mem->size = ALIGN(size, alignment);
#ifdef HAVE_DMA_ALLOC_COHERENT_ZEROES_MEM
	mem->va = dma_alloc_coherent(&nf->pdev->dev, mem->size,
				     &mem->pa, GFP_KERNEL);
#else /* HAVE_DMA_ALLOC_COHERENT_ZEROES_MEM */
	mem->va = dma_zalloc_coherent(&nf->pdev->dev, mem->size,
				      &mem->pa, GFP_KERNEL);
#endif /* HAVE_DMA_ALLOC_COHERENT_ZEROES_MEM */
	if (!mem->va)
		return -ENOMEM;

	return 0;
}

/**
 * iavf_free_dma_mem_d - OS specific memory free for shared code
 * @hw:   pointer to the HW structure
 * @mem:  ptr to mem struct to free
 **/
inline int iavf_free_dma_mem_d(struct iavf_hw *hw, struct iavf_dma_mem *mem)
{
	struct iavf_adapter *nf = (struct iavf_adapter *)hw->back;

	dma_free_coherent(&nf->pdev->dev, mem->size, mem->va, mem->pa);
	mem->va = NULL;
	mem->pa = 0;
	mem->size = 0;

	return 0;
}

/**
 * iavf_allocate_virt_mem_d - OS specific memory alloc for shared code
 * @hw:   pointer to the HW structure
 * @mem:  ptr to mem struct to fill out
 * @size: size of memory requested
 **/
inline int iavf_allocate_virt_mem_d(struct iavf_hw *hw,
				    struct iavf_virt_mem *mem,
				    u32 size)
{
	mem->size = size;
	mem->va = kzalloc(size, GFP_KERNEL);

	if (!mem->va)
		return -ENOMEM;

	return 0;
}

/**
 * iavf_free_virt_mem_d - OS specific memory free for shared code
 * @hw:   pointer to the HW structure
 * @mem:  ptr to mem struct to free
 **/
inline int iavf_free_virt_mem_d(struct iavf_hw *hw, struct iavf_virt_mem *mem)
{
	/* it's ok to kfree a NULL pointer */
	kfree(mem->va);
	mem->va = NULL;
	mem->size = 0;

	return 0;
}

/* prototype */
inline void iavf_destroy_spinlock_d(struct iavf_spinlock *sp);
inline void iavf_acquire_spinlock_d(struct iavf_spinlock *sp);
inline void iavf_release_spinlock_d(struct iavf_spinlock *sp);

/**
 * iavf_init_spinlock_d - OS specific spinlock init for shared code
 * @sp: pointer to a spinlock declared in driver space
 **/
static inline void iavf_init_spinlock_d(struct iavf_spinlock *sp)
{
	mutex_init((struct mutex *)sp);
}

/**
 * iavf_acquire_spinlock_d - OS specific spinlock acquire for shared code
 * @sp: pointer to a spinlock declared in driver space
 **/
inline void iavf_acquire_spinlock_d(struct iavf_spinlock *sp)
{
	mutex_lock((struct mutex *)sp);
}

/**
 * iavf_release_spinlock_d - OS specific spinlock release for shared code
 * @sp: pointer to a spinlock declared in driver space
 **/
inline void iavf_release_spinlock_d(struct iavf_spinlock *sp)
{
	mutex_unlock((struct mutex *)sp);
}

/**
 * iavf_destroy_spinlock_d - OS specific spinlock destroy for shared code
 * @sp: pointer to a spinlock declared in driver space
 **/
inline void iavf_destroy_spinlock_d(struct iavf_spinlock *sp)
{
	mutex_destroy((struct mutex *)sp);
}
#endif /* _IAVF_HELPER_H_ */
