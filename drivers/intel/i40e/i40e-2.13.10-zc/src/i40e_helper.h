/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2013 - 2020 Intel Corporation. */

#ifndef _I40E_HELPER_H_
#define _I40E_HELPER_H_

#include "i40e_alloc.h"

/**
 * i40e_allocate_dma_mem_d - OS specific memory alloc for shared code
 * @hw:   pointer to the HW structure
 * @mem:  ptr to mem struct to fill out
 * @mtype: memory type identifier (unused)
 * @size: size of memory requested
 * @alignment: what to align the allocation to
 **/
inline int i40e_allocate_dma_mem_d(struct i40e_hw *hw,
				   struct i40e_dma_mem *mem,
				   __always_unused enum i40e_memory_type mtype,
				   u64 size, u32 alignment)
{
	struct i40e_pf *nf = (struct i40e_pf *)hw->back;

	mem->size = ALIGN(size, alignment);
#ifdef HAVE_DMA_ALLOC_COHERENT_ZEROES_MEM
	mem->va = dma_alloc_coherent(&nf->pdev->dev, mem->size,
				     &mem->pa, GFP_KERNEL);
#else
	mem->va = dma_zalloc_coherent(&nf->pdev->dev, mem->size,
				      &mem->pa, GFP_KERNEL);
#endif
	if (!mem->va)
		return -ENOMEM;

	return 0;
}

/**
 * i40e_free_dma_mem_d - OS specific memory free for shared code
 * @hw:   pointer to the HW structure
 * @mem:  ptr to mem struct to free
 **/
inline int i40e_free_dma_mem_d(struct i40e_hw *hw, struct i40e_dma_mem *mem)
{
	struct i40e_pf *nf = (struct i40e_pf *)hw->back;

	dma_free_coherent(&nf->pdev->dev, mem->size, mem->va, mem->pa);
	mem->va = NULL;
	mem->pa = 0;
	mem->size = 0;

	return 0;
}

/**
 * i40e_allocate_virt_mem_d - OS specific memory alloc for shared code
 * @hw:   pointer to the HW structure
 * @mem:  ptr to mem struct to fill out
 * @size: size of memory requested
 **/
inline int i40e_allocate_virt_mem_d(struct i40e_hw *hw,
				    struct i40e_virt_mem *mem,
				    u32 size)
{
	mem->size = size;
	mem->va = kzalloc(size, GFP_KERNEL);

	if (!mem->va)
		return -ENOMEM;

	return 0;
}

/**
 * i40e_free_virt_mem_d - OS specific memory free for shared code
 * @hw:   pointer to the HW structure
 * @mem:  ptr to mem struct to free
 **/
inline int i40e_free_virt_mem_d(struct i40e_hw *hw, struct i40e_virt_mem *mem)
{
	/* it's ok to kfree a NULL pointer */
	kfree(mem->va);
	mem->va = NULL;
	mem->size = 0;

	return 0;
}

/* prototype */
inline void i40e_destroy_spinlock_d(struct i40e_spinlock *sp);
inline void i40e_acquire_spinlock_d(struct i40e_spinlock *sp);
inline void i40e_release_spinlock_d(struct i40e_spinlock *sp);

/**
 * i40e_init_spinlock_d - OS specific spinlock init for shared code
 * @sp: pointer to a spinlock declared in driver space
 **/
static inline void i40e_init_spinlock_d(struct i40e_spinlock *sp)
{
	mutex_init((struct mutex *)sp);
}

/**
 * i40e_acquire_spinlock_d - OS specific spinlock acquire for shared code
 * @sp: pointer to a spinlock declared in driver space
 **/
inline void i40e_acquire_spinlock_d(struct i40e_spinlock *sp)
{
	mutex_lock((struct mutex *)sp);
}

/**
 * i40e_release_spinlock_d - OS specific spinlock release for shared code
 * @sp: pointer to a spinlock declared in driver space
 **/
inline void i40e_release_spinlock_d(struct i40e_spinlock *sp)
{
	mutex_unlock((struct mutex *)sp);
}

/**
 * i40e_destroy_spinlock_d - OS specific spinlock destroy for shared code
 * @sp: pointer to a spinlock declared in driver space
 **/
inline void i40e_destroy_spinlock_d(struct i40e_spinlock *sp)
{
	mutex_destroy((struct mutex *)sp);
}
#endif /* _I40E_HELPER_H_ */
