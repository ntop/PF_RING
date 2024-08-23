/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2022 Intel Corporation */
#ifndef IRDMA_OSDEP_H
#define IRDMA_OSDEP_H

#include <linux/etherdevice.h>
#include <linux/sizes.h>
#include <linux/pci.h>
#ifdef FIELD_PREP
#include <linux/bitfield.h>
#endif
#include <crypto/hash.h>
#include <rdma/ib_verbs.h>
#include <linux/workqueue.h>
#if defined(__OFED_4_8__)
#define refcount_t atomic_t
#define refcount_inc atomic_inc
#define refcount_dec_and_test atomic_dec_and_test
#define refcount_set atomic_set
#else
#include <linux/refcount.h>
#endif /* OFED_4_8 */

#include "distro_ver.h"
#ifdef RHEL_RELEASE_CODE
#if (RHEL_RELEASE_CODE == RHEL_RELEASE_VERSION(9, 3)) && defined(CONFIG_X86_64)
#undef mb
#define mb __mb
#undef wmb
#define wmb __wmb
#undef rmb
#define rmb __rmb
#endif /* (RHEL_RELEASE_CODE == RHEL_RELEASE_VERSION(9, 3)) && defined(CONFIG_X86_64) */
#endif /* RHEL_RELEASE_CODE */

#define STATS_TIMER_DELAY	60000

/*
 * See include/linux/compiler_attributes.h in kernel >=5.4 for fallthrough.
 * This code really should be in irdma_kcompat.h but to cover shared code
 * it had to be here.
 * The two #if checks implements fallthrough definition for kernels < 5.4
 * The first check is for new compiler, GCC >= 5.0.  If code in compiler_attributes.h
 * is not invoked and compiler supports  __has_attribute.
 * If fallthrough is not defined after the first check, the second check against fallthrough
 * will define the macro for the older compiler.
 */
#if !defined(fallthrough) && !defined(__GCC4_has_attribute___noclone__) && defined(__has_attribute)
# define fallthrough __attribute__((__fallthrough__))
#endif
#ifndef fallthrough
# define fallthrough do {} while (0)
#endif
#ifndef ibdev_dbg
#define ibdev_dbg(ibdev, fmt, ...)  dev_dbg(&((ibdev)->dev), fmt, ##__VA_ARGS__)
#define ibdev_err(ibdev, fmt, ...)  dev_err(&((ibdev)->dev), fmt, ##__VA_ARGS__)
#define ibdev_warn(ibdev, fmt, ...) dev_warn(&((ibdev)->dev), fmt, ##__VA_ARGS__)
#define ibdev_info(ibdev, fmt, ...) dev_info(&((ibdev)->dev), fmt, ##__VA_ARGS__)
#else
#define irdma_dbg(idev, fmt, ...)				\
do {								\
	struct ib_device *ibdev = irdma_get_ibdev(idev);	\
	if (ibdev)						\
		ibdev_dbg(ibdev, fmt, ##__VA_ARGS__);		\
	else							\
		dev_dbg(idev_to_dev(idev), fmt, ##__VA_ARGS__);	\
} while (0)
#endif
#ifndef struct_size
#define struct_size(ptr, member, count)	\
	(sizeof(*(ptr)) + sizeof(*(ptr)->member) * (count))
#endif

struct irdma_dma_info {
	dma_addr_t *dmaaddrs;
};

struct irdma_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
} __packed;

struct irdma_virt_mem {
	void *va;
	u32 size;
} __packed;

struct irdma_sc_vsi;
struct irdma_sc_dev;
struct irdma_sc_qp;
struct irdma_puda_buf;
struct irdma_puda_cmpl_info;
struct irdma_update_sds_info;
struct irdma_hmc_fcn_info;
struct irdma_hw;
struct irdma_pci_f;
struct irdma_vchnl_req;
struct irdma_vchnl_manage_pble_info;

#ifndef FIELD_PREP

#if defined(__OFED_4_8__)
/* Special handling for 7.2/OFED. The GENMASK macros need to be updated */
#undef GENMASK
#define GENMASK(h, l) \
	(((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#undef GENMASK_ULL
#define GENMASK_ULL(h, l) \
	(((~0ULL) << (l)) & (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))
#endif
/* Compat for rdma-core-27.0 and OFED 4.8/RHEL 7.2. Not for UPSTREAM */
#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define FIELD_PREP(_mask, _val)                                                \
	({                                                                     \
		((typeof(_mask))(_val) << __bf_shf(_mask)) & (_mask);          \
	})

#define FIELD_GET(_mask, _reg)                                                 \
	({                                                                     \
		(typeof(_mask))(((_reg) & (_mask)) >> __bf_shf(_mask));        \
	})
#endif /* FIELD_PREP */
struct ib_device *to_ibdev(struct irdma_sc_dev *dev);
void irdma_ieq_mpa_crc_ae(struct irdma_sc_dev *dev, struct irdma_sc_qp *qp);
int irdma_ieq_check_mpacrc(struct shash_desc *desc, void *addr, u32 len,
			   u32 val);
struct irdma_sc_qp *irdma_ieq_get_qp(struct irdma_sc_dev *dev,
				     struct irdma_puda_buf *buf);
void irdma_send_ieq_ack(struct irdma_sc_qp *qp);
void irdma_ieq_update_tcpip_info(struct irdma_puda_buf *buf, u16 len,
				 u32 seqnum);
void irdma_free_hash_desc(struct shash_desc *hash_desc);
int irdma_init_hash_desc(struct shash_desc **hash_desc);
int irdma_puda_get_tcpip_info(struct irdma_puda_cmpl_info *info,
			      struct irdma_puda_buf *buf);
int irdma_cqp_sds_cmd(struct irdma_sc_dev *dev,
		      struct irdma_update_sds_info *info);
int irdma_cqp_manage_hmc_fcn_cmd(struct irdma_sc_dev *dev,
				 struct irdma_hmc_fcn_info *hmcfcninfo,
				 u16 *pmf_idx);
void *irdma_remove_cqp_head(struct irdma_sc_dev *dev);
void irdma_term_modify_qp(struct irdma_sc_qp *qp, u8 next_state, u8 term,
			  u8 term_len);
void irdma_terminate_done(struct irdma_sc_qp *qp, int timeout_occurred);
void irdma_terminate_start_timer(struct irdma_sc_qp *qp);
void irdma_terminate_del_timer(struct irdma_sc_qp *qp);
void irdma_hw_stats_start_timer(struct irdma_sc_vsi *vsi);
void irdma_hw_stats_stop_timer(struct irdma_sc_vsi *vsi);
void wr32(struct irdma_hw *hw, u32 reg, u32 val);
u32 rd32(struct irdma_hw *hw, u32 reg);
u64 rd64(struct irdma_hw *hw, u32 reg);
int irdma_map_vm_page_list(struct irdma_hw *hw, void *va, dma_addr_t *pg_dma,
			   u32 pg_cnt);
void irdma_unmap_vm_page_list(struct irdma_hw *hw, dma_addr_t *pg_dma, u32 pg_cnt);
#define bitmap_free(bitmap) kfree(bitmap)
#endif /* IRDMA_OSDEP_H */
