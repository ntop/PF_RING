/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2018 - 2024 Intel Corporation */
#ifndef IRDMA_KCOMPAT_H
#define IRDMA_KCOMPAT_H

#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/mii.h>
#include <linux/vmalloc.h>
#include <linux/irq.h>
#include <linux/hugetlb.h>
#include <asm/io.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_umem.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <rdma/uverbs_ioctl.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
#include <linux/kconfig.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
#include <net/secure_seq.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
#include <asm-generic/io-64-nonatomic-lo-hi.h>
#else
#include <linux/io-64-nonatomic-lo-hi.h>
#endif

#if !defined(__OFED_BUILD__) && !defined(__OFED_4_8__)
#include "irdma_kcompat_gen.h"
#endif
#include "distro_ver.h"

#if defined(__OFED_BUILD__) || defined(__OFED_4_8__)
#include "ofed_kcompat.h"
#elif defined(RHEL_RELEASE_CODE)
#include "rhel_kcompat.h"
#elif defined(CONFIG_SUSE_KERNEL)
#include "suse_kcompat.h"
#elif defined(UTS_UBUNTU_RELEASE_ABI)
#include "ubuntu_kcompat.h"
#elif defined(ORACLE_REL)
#include "oracle_kcompat.h"
#else
#include "linux_kcompat.h"
#endif

#ifndef MAX_PAGE_ORDER
#define MAX_PAGE_ORDER MAX_ORDER
#endif

#ifndef IB_QP_ATTR_STANDARD_BITS
#define IB_QP_ATTR_STANDARD_BITS GENMASK(20, 0)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
#define ENABLE_DUP_CM_NAME_WA
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)) */

#define TASKLET_DATA_TYPE	unsigned long
#define TASKLET_FUNC_TYPE	void (*)(TASKLET_DATA_TYPE)

#define tasklet_setup(tasklet, callback)				\
	tasklet_init((tasklet), (TASKLET_FUNC_TYPE)(callback),		\
		      (TASKLET_DATA_TYPE)(tasklet))

#define from_tasklet(var, callback_tasklet, tasklet_fieldname) \
	container_of(callback_tasklet, typeof(*var), tasklet_fieldname)

/* Mapping IRDMA driver ID to I40IW till we are in k.org */
#define RDMA_DRIVER_IRDMA 9

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0))
#define TIMER_DATA_TYPE		unsigned long
#define TIMER_FUNC_TYPE		void (*)(TIMER_DATA_TYPE)

#define timer_setup(timer, callback, flags)				\
	__setup_timer((timer), (TIMER_FUNC_TYPE)(callback),		\
		      (TIMER_DATA_TYPE)(timer), (flags))

#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)
#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)) */

#if !defined(__OFED_BUILD__) && !defined(__OFED_4_8__)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#define dma_alloc_coherent dma_zalloc_coherent
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#define IB_GET_NETDEV_OP_NOT_DEPRECATED
#endif

#ifdef USE_KMAP
#define kmap_local_page kmap
#define kunmap_local(sq_base) kunmap(iwqp->page)
#endif

/*************************QUERY PKEY*********************************************/
/* https://lore.kernel.org/linux-rdma/9DD61F30A802C4429A01CA4200E302A7010659C72C@fmsmsx124.amr.corp.intel.com/
 * This series removes query pkey callback from iWARP providers as it really
 * is not required as per the protocol. Also IB core is updated to not expose
 * pkey related sysfs attributes for iw_devices. Prior to 5.9, query pkey is mandatory
 * for iWARP providers.
 */
#ifdef IB_IW_PKEY
#ifdef QUERY_PKEY_V1
static inline int irdma_iw_query_pkey(struct ib_device *ibdev, u8 port, u16 index,
				      u16 *pkey)
#elif defined(QUERY_PKEY_V2)
static inline int irdma_iw_query_pkey(struct ib_device *ibdev, u32 port, u16 index,
				      u16 *pkey)
#endif
{
	*pkey = 0;
	return 0;
}
#endif
/*******************************************************************************/

struct dst_entry *irdma_get_fl6_dst(struct sockaddr_in6 *, struct sockaddr_in6 *);
struct neighbour *irdma_get_neigh_ipv6(struct dst_entry *, struct sockaddr_in6 *);
struct neighbour *irdma_get_neigh_ipv4(struct rtable *, __be32 *);

struct irdma_mr;
struct irdma_cq;
struct irdma_cq_buf;
struct irdma_srq;
struct irdma_ucontext;
void kc_set_loc_seq_num_mss(struct irdma_cm_node *cm_node);
u32 irdma_create_stag(struct irdma_device *iwdev);
void irdma_free_stag(struct irdma_device *iwdev, u32 stag);
int irdma_hw_alloc_mw(struct irdma_device *iwdev, struct irdma_mr *iwmr);
void irdma_cq_free_rsrc(struct irdma_pci_f *rf, struct irdma_cq *iwcq);
void irdma_srq_free_rsrc(struct irdma_pci_f *rf, struct irdma_srq *iwsrq);
int irdma_process_resize_list(struct irdma_cq *iwcq, struct irdma_device *iwdev, struct irdma_cq_buf *lcqe_buf);

#ifdef IRDMA_SET_DRIVER_ID
#define kc_set_driver_id(ibdev) ibdev.driver_id = RDMA_DRIVER_I40IW
#else
#define kc_set_driver_id(x)
#endif /* IRDMA_SET_DRIVER_ID */
/*****************************************************************************/


/*********************************************************/
#ifndef ether_addr_copy
#define ether_addr_copy(mac_addr, new_mac_addr) memcpy(mac_addr, new_mac_addr, ETH_ALEN)
#endif
#ifndef eth_zero_addr
#define eth_zero_addr(mac_addr) memset(mac_addr, 0x00, ETH_ALEN)
#endif

#define bitmap_zalloc(nbits, flags) kcalloc(BITS_TO_LONGS(nbits), sizeof(unsigned long), flags)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35)
#define irdma_for_each_ipv6_addr(ifp, tmp, idev) list_for_each_entry_safe(ifp, tmp, &idev->addr_list, if_list)
#else
#define irdma_for_each_ipv6_addr(ifp, tmp, idev) for (ifp = idev->addr_list; ifp != NULL; ifp = ifp->if_next)
#endif /* >= 2.6.35 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
#define netdev_master_upper_dev_get irdma_netdev_master_upper_dev_get
struct net_device *irdma_netdev_master_upper_dev_get(struct net_device *);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0)
#define neigh_release(neigh)
#endif /* < 3.1.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
#define ip_route_output irdma_ip_route_output
struct rtable *irdma_ip_route_output(struct net *, __be32, __be32, u8, int);
#endif /* < 2.6.39 */
#endif /* < 3.9.0 */

#ifdef IB_FW_VERSION_NAME_MAX
void irdma_get_dev_fw_str(struct ib_device *dev, char *str);
#else
void irdma_get_dev_fw_str(struct ib_device *dev, char *str, size_t str_len);
#endif /* IB_FW_VERSION_NAME_MAX */

/*****************************************************************************/

struct dst_entry *irdma_get_fl6_dst(struct sockaddr_in6 *src_addr,
				    struct sockaddr_in6 *dst_addr);
struct neighbour *irdma_get_neigh_ipv6(struct dst_entry *dst,
				       struct sockaddr_in6 *dst_ipaddr);
struct neighbour *irdma_get_neigh_ipv4(struct rtable *rt, __be32 *dst_ipaddr);

#ifdef IB_IW_MANDATORY_AH_OP
#ifdef CREATE_AH_VER_0
struct ib_ah *irdma_create_ah_stub(struct ib_pd *ibpd,
				   struct ib_ah_attr *attr);
#elif defined(CREATE_AH_VER_1_1)
struct ib_ah *irdma_create_ah_stub(struct ib_pd *ibpd,
				   struct ib_ah_attr *attr,
				   struct ib_udata *udata);
#elif defined(CREATE_AH_VER_1_2)
struct ib_ah *irdma_create_ah_stub(struct ib_pd *ibpd,
				   struct rdma_ah_attr *attr,
				   struct ib_udata *udata);
#endif

int irdma_destroy_ah_stub(struct ib_ah *ibah);
#endif /* IB_IW_MANDATORY_AH_OP */

#ifdef CREATE_AH_VER_5
int irdma_create_ah_v2(struct ib_ah *ib_ah,
		       struct rdma_ah_attr *attr, u32 flags,
		       struct ib_udata *udata);
int irdma_create_ah(struct ib_ah *ibah,
		    struct rdma_ah_init_attr *attr,
		    struct ib_udata *udata);
#endif

#ifdef CREATE_AH_VER_4
struct ib_ah *irdma_create_ah(struct ib_pd *ibpd,
			      struct rdma_ah_attr *attr,
			      struct ib_udata *udata);
#endif

#ifdef CREATE_AH_VER_3
struct ib_ah *irdma_create_ah(struct ib_pd *ibpd,
			      struct rdma_ah_attr *attr,
			      u32 flags,
			      struct ib_udata *udata);
#endif

#ifdef CREATE_AH_VER_2
int irdma_create_ah(struct ib_ah *ib_ah,
		    struct rdma_ah_attr *attr, u32 flags,
		    struct ib_udata *udata);
#endif

#ifdef CREATE_AH_VER_1_1
struct ib_ah *irdma_create_ah(struct ib_pd *ibpd,
			      struct ib_ah_attr *attr,
			      struct ib_udata *udata);
void irdma_ether_copy(u8 *dmac, struct ib_ah_attr *attr);
#endif
#if defined(CREATE_AH_VER_1_2)
struct ib_ah *irdma_create_ah(struct ib_pd *ibpd,
			      struct rdma_ah_attr *attr,
			      struct ib_udata *udata);
void irdma_ether_copy(u8 *dmac, struct rdma_ah_attr *attr);
#endif

#if defined(CREATE_AH_VER_0)
struct ib_ah *irdma_create_ah(struct ib_pd *ibpd,
			      struct ib_ah_attr *attr);
#endif

#ifdef DESTROY_AH_VER_4
int irdma_destroy_ah(struct ib_ah *ibah, u32 ah_flags);
#endif

#ifdef DESTROY_AH_VER_3
void irdma_destroy_ah(struct ib_ah *ibah, u32 flags);
#endif

#ifdef DESTROY_AH_VER_2
int irdma_destroy_ah(struct ib_ah *ibah, u32 flags);
#endif

#ifdef DESTROY_AH_VER_1
int irdma_destroy_ah(struct ib_ah *ibah);
#endif

#ifdef CREATE_CQ_VER_3
int irdma_create_cq(struct ib_cq *ibcq,
		    const struct ib_cq_init_attr *attr,
		    struct ib_udata *udata);
#endif

#ifdef CREATE_CQ_VER_2
struct ib_cq *irdma_create_cq(struct ib_device *ibdev,
			      const struct ib_cq_init_attr *attr,
			      struct ib_udata *udata);
#endif

#ifdef CREATE_CQ_VER_1
struct ib_cq *irdma_create_cq(struct ib_device *ibdev,
			      const struct ib_cq_init_attr *attr,
			      struct ib_ucontext *context,
			      struct ib_udata *udata);
#endif

/* functions called by irdma_create_qp and irdma_free_qp_rsrc */
int irdma_validate_qp_attrs(struct ib_qp_init_attr *init_attr,
			    struct irdma_device *iwdev);

void irdma_setup_virt_qp(struct irdma_device *iwdev,
			 struct irdma_qp *iwqp,
			 struct irdma_qp_init_info *init_info);

int irdma_setup_kmode_qp(struct irdma_device *iwdev,
			 struct irdma_qp *iwqp,
			 struct irdma_qp_init_info *info,
			 struct ib_qp_init_attr *init_attr);

int irdma_setup_umode_qp(struct ib_udata *udata,
			 struct irdma_device *iwdev,
			 struct irdma_qp *iwqp,
			 struct irdma_qp_init_info *info,
			 struct ib_qp_init_attr *init_attr);

void irdma_roce_fill_and_set_qpctx_info(struct irdma_qp *iwqp,
					struct irdma_qp_host_ctx_info *ctx_info);

void irdma_iw_fill_and_set_qpctx_info(struct irdma_qp *iwqp,
				      struct irdma_qp_host_ctx_info *ctx_info);

int irdma_cqp_create_qp_cmd(struct irdma_qp *iwqp);

void irdma_free_qp_rsrc(struct irdma_qp *iwqp);

void irdma_dealloc_push_page(struct irdma_pci_f *rf,
			     struct irdma_qp *iwqp);

#ifdef IRDMA_ALLOC_MW_VER_2
int irdma_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata);
#endif

#ifdef IRDMA_ALLOC_MW_VER_1
struct ib_mw *irdma_alloc_mw(struct ib_pd *pd, enum ib_mw_type type,
			     struct ib_udata *udata);
#endif

#ifdef CREATE_QP_VER_2
int irdma_create_qp(struct ib_qp *ibqp,
		    struct ib_qp_init_attr *init_attr,
		    struct ib_udata *udata);
#endif

#ifdef CREATE_QP_VER_1
struct ib_qp *irdma_create_qp(struct ib_pd *ibpd,
			      struct ib_qp_init_attr *init_attr,
			      struct ib_udata *udata);
#endif

int irdma_hw_alloc_stag(struct irdma_device *iwdev,
			struct irdma_mr *iwmr);

#ifdef IRDMA_ALLOC_MR_VER_1
struct ib_mr *irdma_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			     u32 max_num_sg, struct ib_udata *udata);
#endif

#ifdef IRDMA_ALLOC_MR_VER_0
struct ib_mr *irdma_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type, u32 max_num_sg);
#endif

#ifdef ALLOC_UCONTEXT_VER_2
int irdma_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata);
#endif

#ifdef ALLOC_UCONTEXT_VER_1
struct ib_ucontext *irdma_alloc_ucontext(struct ib_device *ibdev, struct ib_udata *udata);
#endif

#ifdef DEALLOC_UCONTEXT_VER_2
void irdma_dealloc_ucontext(struct ib_ucontext *context);
#endif

#ifdef DEALLOC_UCONTEXT_VER_1
int irdma_dealloc_ucontext(struct ib_ucontext *context);
#endif

#if defined(ETHER_COPY_VER_2)
void irdma_ether_copy(u8 *dmac, struct rdma_ah_attr *attr);
#endif

#if defined(ETHER_COPY_VER_1)
void irdma_ether_copy(u8 *dmac, struct ib_ah_attr *attr);
#endif

#ifdef ALLOC_PD_VER_3
int irdma_alloc_pd(struct ib_pd *pd, struct ib_udata *udata);
#endif

#ifdef ALLOC_PD_VER_2
int irdma_alloc_pd(struct ib_pd *pd,
		   struct ib_ucontext *context,
		   struct ib_udata *udata);
#endif

#ifdef ALLOC_PD_VER_1
struct ib_pd *irdma_alloc_pd(struct ib_device *ibdev,
			     struct ib_ucontext *context,
			     struct ib_udata *udata);
#endif

#ifdef DEALLOC_PD_VER_4
int irdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);
#endif

#ifdef DEALLOC_PD_VER_3
void irdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);
#endif

#ifdef DEALLOC_PD_VER_2
void irdma_dealloc_pd(struct ib_pd *ibpd);
#endif

#ifdef DEALLOC_PD_VER_1
int irdma_dealloc_pd(struct ib_pd *ibpd);
#endif

int irdma_add_gid(struct ib_device *device,
		  u8 port_num,
		  unsigned int index,
		  const union ib_gid *gid,
		  const struct ib_gid_attr *attr,
		  void **context);

int irdma_del_gid(struct ib_device *device,
		  u8 port_num,
		  unsigned int index,
		  void **context);

#ifdef IRDMA_DESTROY_CQ_VER_4
int irdma_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata);
#endif

#ifdef IRDMA_DESTROY_CQ_VER_3
void irdma_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata);
#endif

#ifdef IRDMA_DESTROY_CQ_VER_2
int irdma_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata);
#endif

#ifdef IRDMA_DESTROY_CQ_VER_1
int irdma_destroy_cq(struct ib_cq *ib_cq);
#endif

#ifdef IRDMA_DESTROY_SRQ_VER_3
int irdma_destroy_srq(struct ib_srq *ibsrq, struct ib_udata *udata);
#endif

#ifdef IRDMA_DESTROY_SRQ_VER_2
void irdma_destroy_srq(struct ib_srq *ibsrq, struct ib_udata *udata);
#endif

#ifdef IRDMA_DESTROY_SRQ_VER_1
int irdma_destroy_srq(struct ib_srq *ibsrq);
#endif

#ifdef DESTROY_QP_VER_2
int irdma_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata);
#define kc_irdma_destroy_qp(ibqp, udata) irdma_destroy_qp(ibqp, udata)
#endif

#ifdef DESTROY_QP_VER_1
int irdma_destroy_qp(struct ib_qp *ibqp);
#define kc_irdma_destroy_qp(ibqp, udata) irdma_destroy_qp(ibqp)
#endif

#ifdef DEREG_MR_VER_2
int irdma_dereg_mr(struct ib_mr *ib_mr, struct ib_udata *udata);
#endif

#ifdef DEREG_MR_VER_1
int irdma_dereg_mr(struct ib_mr *ib_mr);
#endif

int irdma_hwdereg_mr(struct ib_mr *ib_mr);

#ifdef REREG_MR_VER_1
int irdma_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start, u64 len,
			u64 virt, int new_access, struct ib_pd *new_pd,
			struct ib_udata *udata);
#endif

#ifdef REREG_MR_VER_2
struct ib_mr *irdma_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start,
				  u64 len, u64 virt, int new_access,
				  struct ib_pd *new_pd,
				  struct ib_udata *udata);
#endif

int irdma_hwreg_mr(struct irdma_device *iwdev, struct irdma_mr *iwmr,
		   u16 access);

struct ib_mr *irdma_rereg_mr_trans(struct irdma_mr *iwmr, u64 start, u64 len,
				   u64 virt, struct ib_udata *udata);

struct irdma_pbl *irdma_get_pbl(unsigned long va,
				struct list_head *pbl_list);

#ifndef HAVE_IB_UMEM_NUM_DMA_BLOCKS
/* Introduced in this series https://lore.kernel.org/linux-rdma/0-v2-270386b7e60b+28f4-umem_1_jgg@nvidia.com/
 * An irdma version helper doing same for older functions with difference that iova is passed in
 * as opposed to derived from umem->iova.
 */
static inline size_t irdma_ib_umem_num_dma_blocks(struct ib_umem *umem, unsigned long pgsz, u64 iova)
{
    /* some older OFED distros do not have ALIGN_DOWN */
#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#endif

	return (size_t)((ALIGN(iova + umem->length, pgsz) -
			 ALIGN_DOWN(iova, pgsz))) / pgsz;
}
#endif

#ifdef NEED_RDMA_UMEM_BLOCK_ITER_NEXT
/*
 * IB block DMA iterator
 *
 * Iterates the DMA-mapped SGL in contiguous memory blocks aligned
 * to a HW supported page size.
 */
struct kc_ib_block_iter {
	/* internal states */
	struct scatterlist *__sg;	/* sg holding the current aligned block */
	dma_addr_t __dma_addr;		/* unaligned DMA address of this block */
	size_t __sg_numblocks;		/* ib_umem_num_dma_blocks() */
	unsigned int __sg_nents;	/* number of SG entries */
	unsigned int __sg_advance;	/* number of bytes to advance in sg in next step */
	unsigned int __pg_bit;		/* alignment of current block */
};

void kc__rdma_block_iter_start(struct kc_ib_block_iter *biter,
			       struct scatterlist *sglist,
			       unsigned int nents,
			       unsigned long pgsz);
bool kc__rdma_block_iter_next(struct kc_ib_block_iter *biter);

/**
 * rdma_block_iter_dma_address - get the aligned dma address of the current
 * block held by the block iterator.
 * @biter: block iterator holding the memory block
 */
static inline dma_addr_t
kc_rdma_block_iter_dma_address(struct kc_ib_block_iter *biter)
{
	return biter->__dma_addr & ~(BIT_ULL(biter->__pg_bit) - 1);
}

/**
 * rdma_for_each_block - iterate over contiguous memory blocks of the sg list
 * @sglist: sglist to iterate over
 * @biter: block iterator holding the memory block
 * @nents: maximum number of sg entries to iterate over
 * @pgsz: best HW supported page size to use
 *
 * Callers may use rdma_block_iter_dma_address() to get each
 * blocks aligned DMA address.
 */
#define kc_rdma_for_each_block(sglist, biter, nents, pgsz)		\
	for (kc__rdma_block_iter_start(biter, sglist, nents, pgsz);	\
	     kc__rdma_block_iter_next(biter);)

static inline void
kc__rdma_umem_block_iter_start(struct kc_ib_block_iter *biter,
			       struct ib_umem *umem,
			       unsigned long pgsz)
{
#ifdef HAVE_IB_UMEM_SG_HEAD
	kc__rdma_block_iter_start(biter, umem->sg_head.sgl, umem->nmap,
				  pgsz);
#else
	kc__rdma_block_iter_start(biter, umem->sgt_append.sgt.sgl,
				  umem->sgt_append.sgt.nents, pgsz);
#endif /* HAVE_IB_UMEM_SG_HEAD */
	biter->__sg_advance = ib_umem_offset(umem) & ~(pgsz - 1);
#ifdef HAVE_IB_UMEM_NUM_DMA_BLOCKS
	biter->__sg_numblocks = ib_umem_num_dma_blocks(umem, pgsz);
#else
	biter->__sg_numblocks =
		irdma_ib_umem_num_dma_blocks(umem, pgsz, umem->address);
#endif
}

static inline bool
kc__rdma_umem_block_iter_next(struct kc_ib_block_iter *biter)
{
	return kc__rdma_block_iter_next(biter) && biter->__sg_numblocks--;
}


/**
 * rdma_umem_for_each_dma_block - iterate over contiguous DMA blocks of the umem
 * @umem: umem to iterate over
 * @pgsz: Page size to split the list into
 *
 * pgsz must be <= PAGE_SIZE or computed by ib_umem_find_best_pgsz(). The
 * returned DMA blocks will be aligned to pgsz and span the range:
 * ALIGN_DOWN(umem->address, pgsz) to ALIGN(umem->address + umem->length, pgsz)
 */
#define kc_rdma_umem_for_each_dma_block(umem, biter, pgsz)                        \
	for (kc__rdma_umem_block_iter_start(biter, umem, pgsz);                  \
	     kc__rdma_umem_block_iter_next(biter);)

#undef rdma_umem_for_each_dma_block
#define rdma_umem_for_each_dma_block kc_rdma_umem_for_each_dma_block
#define ib_block_iter kc_ib_block_iter
#define rdma_block_iter_dma_address kc_rdma_block_iter_dma_address
#define __rdma_umem_block_iter_start kc__rdma_umem_block_iter_start
#define __rdma_block_iter_next kc__rdma_block_iter_next

#endif /* NEED_RDMA_UMEM_BLOCK_ITER_NEXT */


#ifdef COPY_USER_PGADDR_VER_1
void irdma_copy_user_pgaddrs(struct irdma_mr *iwmr, u64 *pbl,
			     enum irdma_pble_level level);
#endif

void irdma_del_memlist(struct irdma_mr *iwmr,
		       struct irdma_ucontext *ucontext);

void irdma_unregister_rdma_device(struct ib_device *ibdev);
#ifndef RDMA_MMAP_DB_SUPPORT
int rdma_user_mmap_io(struct ib_ucontext *ucontext, struct vm_area_struct *vma,
		      unsigned long pfn, unsigned long size, pgprot_t prot);
#endif
void irdma_release_ib_devname(struct irdma_device *iwdev);
char *irdma_set_ib_devname(struct irdma_device *iwdev);
void irdma_disassociate_ucontext(struct ib_ucontext *context);
int kc_irdma_set_roce_cm_info(struct irdma_qp *iwqp,
			      struct ib_qp_attr *attr,
			      u16 *vlan_id);
int kc_irdma_create_sysfs_file(struct ib_device *ibdev);
struct irdma_device *kc_irdma_get_device(struct net_device *netdev);
void kc_irdma_put_device(struct irdma_device *iwdev);
void kc_set_roce_uverbs_cmd_mask(struct irdma_device *iwdev);
void kc_set_rdma_uverbs_cmd_mask(struct irdma_device *iwdev);

#ifdef QUERY_GID_ROCE_V2
int irdma_query_gid_roce(struct ib_device *ibdev, u32 port, int index,
			 union ib_gid *gid);
#elif defined(QUERY_GID_ROCE_V1)
int irdma_query_gid_roce(struct ib_device *ibdev, u8 port, int index,
			 union ib_gid *gid);
#endif

#ifdef MODIFY_PORT_V2
int irdma_modify_port(struct ib_device *ibdev, u32 port, int mask,
		      struct ib_port_modify *props);
#elif defined(MODIFY_PORT_V1)
int irdma_modify_port(struct ib_device *ibdev, u8 port, int mask,
		      struct ib_port_modify *props);
#endif

#ifdef QUERY_PKEY_V2
int irdma_query_pkey(struct ib_device *ibdev, u32 port, u16 index,
		     u16 *pkey);
#elif defined(QUERY_PKEY_V1)
int irdma_query_pkey(struct ib_device *ibdev, u8 port, u16 index,
		     u16 *pkey);
#endif

#ifdef ROCE_PORT_IMMUTABLE_V2
int irdma_roce_port_immutable(struct ib_device *ibdev, u32 port_num,
			      struct ib_port_immutable *immutable);
#elif defined(ROCE_PORT_IMMUTABLE_V1)
int irdma_roce_port_immutable(struct ib_device *ibdev, u8 port_num,
			      struct ib_port_immutable *immutable);
#endif

#ifdef IW_PORT_IMMUTABLE_V2
int irdma_iw_port_immutable(struct ib_device *ibdev, u32 port_num,
			    struct ib_port_immutable *immutable);
#elif defined(IW_PORT_IMMUTABLE_V1)
int irdma_iw_port_immutable(struct ib_device *ibdev, u8 port_num,
			    struct ib_port_immutable *immutable);
#endif

#ifdef ALLOC_HW_STATS_V3
struct rdma_hw_stats *irdma_alloc_hw_port_stats(struct ib_device *ibdev,
						u32 port_num);
#endif
#ifdef ALLOC_HW_STATS_V2
struct rdma_hw_stats *irdma_alloc_hw_stats(struct ib_device *ibdev,
					   u32 port_num);
#endif
#ifdef ALLOC_HW_STATS_V1
struct rdma_hw_stats *irdma_alloc_hw_stats(struct ib_device *ibdev,
					   u8 port_num);
#endif

#ifdef GET_HW_STATS_V2
int irdma_get_hw_stats(struct ib_device *ibdev,
		       struct rdma_hw_stats *stats, u32 port_num,
		       int index);
#elif defined(GET_HW_STATS_V1)
int irdma_get_hw_stats(struct ib_device *ibdev,
		       struct rdma_hw_stats *stats, u8 port_num,
		       int index);
#endif

#ifdef QUERY_GID_V2
int irdma_query_gid(struct ib_device *ibdev, u32 port, int index,
		    union ib_gid *gid);
#elif defined(QUERY_GID_V1)
int irdma_query_gid(struct ib_device *ibdev, u8 port, int index,
		    union ib_gid *gid);
#endif

#ifdef GET_LINK_LAYER_V2
enum rdma_link_layer irdma_get_link_layer(struct ib_device *ibdev,
					  u32 port_num);
#elif defined(GET_LINK_LAYER_V1)
enum rdma_link_layer irdma_get_link_layer(struct ib_device *ibdev,
					  u8 port_num);
#endif

#ifdef QUERY_PORT_V2
int irdma_query_port(struct ib_device *ibdev, u32 port,
		     struct ib_port_attr *props);
#elif defined(QUERY_PORT_V1)
int irdma_query_port(struct ib_device *ibdev, u8 port,
		     struct ib_port_attr *props);
#endif

u16 kc_rdma_get_udp_sport(u32 fl, u32 lqpn, u32 rqpn);
void irdma_clean_cqes(struct irdma_qp *iwqp, struct irdma_cq *iwcq);
void irdma_remove_push_mmap_entries(struct irdma_qp *iwqp);
#ifndef NETDEV_TO_IBDEV_SUPPORT
struct ib_device *ib_device_get_by_netdev(struct net_device *ndev, int driver_id);
void ib_unregister_device_put(struct ib_device *device);
#endif

#if defined(DEREG_MR_VER_2) && defined(HAS_IB_SET_DEVICE_OP)
#define kc_free_lsmm_dereg_mr(iwdev, iwqp) \
	((iwdev)->ibdev.ops.dereg_mr((iwqp)->lsmm_mr, NULL))
#elif defined(DEREG_MR_VER_2) && !defined(HAS_IB_SET_DEVICE_OP)
#define kc_free_lsmm_dereg_mr(iwdev, iwqp) \
	((iwdev)->ibdev.dereg_mr((iwqp)->lsmm_mr, NULL))
#elif !defined(DEREG_MR_VER_2) && defined(HAS_IB_SET_DEVICE_OP)
#define kc_free_lsmm_dereg_mr(iwdev, iwqp) \
	((iwdev)->ibdev.ops.dereg_mr((iwqp)->lsmm_mr))
#else
#define kc_free_lsmm_dereg_mr(iwdev, iwqp) \
	((iwdev)->ibdev.dereg_mr((iwqp)->lsmm_mr))
#endif

static inline int cq_validate_flags(u32 flags, u8 hw_rev)
{
	/* GEN1/2 does not support CQ create flags */
	if (hw_rev <= IRDMA_GEN_2)
		return flags ? -EOPNOTSUPP : 0;

	return flags & ~IB_UVERBS_CQ_FLAGS_TIMESTAMP_COMPLETION ? -EOPNOTSUPP : 0;
}

#ifdef COPY_USER_PGADDR_VER_1
static inline u64 *irdma_next_pbl_addr(u64 *pbl, struct irdma_pble_info **pinfo,
				       u32 *idx)
{
	*idx += 1;
	if (!(*pinfo) || *idx != (*pinfo)->cnt)
		return ++pbl;
	*idx = 0;
	(*pinfo)++;

	return (*pinfo)->addr;
}
#endif /* COPY_USER_PGADDR_VER_1 */

#ifdef NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
/* ida_alloc(), ida_alloc_min(), ida_alloc_max(), ida_alloc_range(), and
 * ida_free() were added in commit 5ade60dda43c ("ida: add new API").
 *
 * Also, using "0" as the "end" argument (3rd argument) to ida_simple_get() is
 * considered the max value, which is why it's used in ida_alloc() and
 * ida_alloc_min().
 */
static inline int ida_alloc(struct ida *ida, gfp_t gfp)
{
	return ida_simple_get(ida, 0, 0, gfp);
}

static inline int ida_alloc_min(struct ida *ida, unsigned int min, gfp_t gfp)
{
	return ida_simple_get(ida, min, 0, gfp);
}

static inline int ida_alloc_max(struct ida *ida, unsigned int max, gfp_t gfp)
{
	return ida_simple_get(ida, 0, max, gfp);
}

static inline int
ida_alloc_range(struct ida *ida, unsigned int min, unsigned int max, gfp_t gfp)
{
	return ida_simple_get(ida, min, max, gfp);
}

static inline void ida_free(struct ida *ida, unsigned int id)
{
	ida_simple_remove(ida, id);
}
#endif /* NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE */
#ifdef IB_GET_ETH_SPEED
int ib_get_eth_speed(struct ib_device *dev, u32 port_num, u8 *speed, u8 *width);
#endif
#ifdef IRDMA_IRQ_UPDATE_AFFINITY
/**
 * irq_update_affinity_hint - Update the affinity hint
 * @irq:	Interrupt to update
 * @m:		cpumask pointer (NULL to clear the hint)
 *
 * Updates the affinity hint, but does not change the affinity of the interrupt.
 */
static inline int
irq_update_affinity_hint(unsigned int irq, const struct cpumask *m)
{
	return irq_set_affinity_hint(irq, m);
}
#endif /* IRDMA_IRQ_UPDATE_AFFINITY */
#ifdef IRDMA_AUX_GET_SET_DRV_DATA
static inline void *auxiliary_get_drvdata(struct auxiliary_device *auxdev)
{
	return dev_get_drvdata(&auxdev->dev);
}

static inline void auxiliary_set_drvdata(struct auxiliary_device *auxdev, void *data)
{
	dev_set_drvdata(&auxdev->dev, data);
}
#endif /* IRDMA_AUX_GET_DRV_DATA */
#endif /* IRDMA_KCOMPAT_H_ */
