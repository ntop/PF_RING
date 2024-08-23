/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2020 - 2022 Intel Corporation */
#ifndef LINUX_KCOMPAT_H
#define LINUX_KCOMPAT_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
#define IB_DEV_CAPS_VER_2
#endif

/* IB_IW_PKEY */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
#define IB_IW_PKEY
#endif

/* KMAP_LOCAL_PAGE */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define USE_KMAP
#endif

/* CREATE_AH */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#define CREATE_AH_VER_5
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define CREATE_AH_VER_2
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define CREATE_AH_VER_3
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
#define CREATE_AH_VER_1_2
#define ETHER_COPY_VER_2
#else
#define CREATE_AH_VER_1_1
#define ETHER_COPY_VER_1
#endif

/* DESTROY_AH */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define DESTROY_AH_VER_4
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define DESTROY_AH_VER_3
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define DESTROY_AH_VER_2
#else
#define DESTROY_AH_VER_1
#endif
#endif
#endif

/* CREAT_QP */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
#define CREATE_QP_VER_2
#define GLOBAL_QP_MEM
#else
#define CREATE_QP_VER_1
#endif

/* DESTROY_QP */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
#define DESTROY_QP_VER_1
#define kc_irdma_destroy_qp(ibqp, udata) irdma_destroy_qp(ibqp)
#else
#define DESTROY_QP_VER_2
#define kc_irdma_destroy_qp(ibqp, udata) irdma_destroy_qp(ibqp, udata)
#endif

/* CREATE_CQ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define CREATE_CQ_VER_3
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define CREATE_CQ_VER_2
#else
#define CREATE_CQ_VER_1
#endif

/* ALLOC_UCONTEXT/ DEALLOC_UCONTEXT */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
#define ALLOC_UCONTEXT_VER_1
#define DEALLOC_UCONTEXT_VER_1
#else
#define ALLOC_UCONTEXT_VER_2
#define DEALLOC_UCONTEXT_VER_2
#endif

/* ALLOC_PD , DEALLOC_PD */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define DEALLOC_PD_VER_4
#define ALLOC_PD_VER_3
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define ALLOC_PD_VER_3
#define DEALLOC_PD_VER_3
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
#define ALLOC_PD_VER_2
#define DEALLOC_PD_VER_2
#else
#define ALLOC_PD_VER_1
#define DEALLOC_PD_VER_1
#endif
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
#define ALLOC_HW_STATS_STRUCT_V2
#else
#define ALLOC_HW_STATS_STRUCT_V1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#define ALLOC_HW_STATS_V3
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#define ALLOC_HW_STATS_V2
#else
#define ALLOC_HW_STATS_V1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#define QUERY_GID_ROCE_V2
#define MODIFY_PORT_V2
#define QUERY_PKEY_V2
#define ROCE_PORT_IMMUTABLE_V2
#define GET_HW_STATS_V2
#define GET_LINK_LAYER_V2
#define IW_PORT_IMMUTABLE_V2
#define QUERY_GID_V2
#define QUERY_PORT_V2
#else
#define QUERY_GID_ROCE_V1
#define MODIFY_PORT_V1
#define QUERY_PKEY_V1
#define ROCE_PORT_IMMUTABLE_V1
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define IW_PORT_IMMUTABLE_V1
#define QUERY_GID_V1
#define QUERY_PORT_V1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
#define VMA_DATA
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
/* https://lore.kernel.org/linux-rdma/20191217210406.GC17227@ziepe.ca/
 * This series adds mmap DB support and also extends rdma_user_mmap_io API
 * with an extra param
 */
#define RDMA_MMAP_DB_SUPPORT
#endif

/* IRDMA_ALLOC_MW */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define IRDMA_ALLOC_MW_VER_2
#else
#define IRDMA_ALLOC_MW_VER_1
#endif

/* IRDMA_ALLOC_MR */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0))
#define IRDMA_ALLOC_MR_VER_1
#else
#define IRDMA_ALLOC_MR_VER_0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
#define IB_UVERBS_CQ_FLAGS_TIMESTAMP_COMPLETION IB_CQ_FLAGS_TIMESTAMP_COMPLETION
#endif

/* IRDMA_DESTROY_CQ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 3)
#define IRDMA_DESTROY_CQ_VER_4
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define IRDMA_DESTROY_CQ_VER_3
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define IRDMA_DESTROY_CQ_VER_2
#else
#define IRDMA_DESTROY_CQ_VER_1
#endif /* LINUX_VERSION_CODE */

/* IRDMA_DESTROY_SRQ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define IRDMA_DESTROY_SRQ_VER_3
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define IRDMA_DESTROY_SRQ_VER_2
#else
#define IRDMA_DESTROY_SRQ_VER_1
#endif /* LINUX_VERSION_CODE */

/* max_sge, ip_gid, gid_attr_network_type, deref_sgid_attr */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
#define NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
#define set_max_sge(props, rf)  \
	((props)->max_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags)
#define kc_set_props_ip_gid_caps(props) \
	((props)->port_cap_flags  |= IB_PORT_IP_BASED_GIDS)
#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	ib_gid_to_network_type(gid_type, gid)
#define kc_deref_sgid_attr(sgid_attr)        (sgid_attr.ndev)
#define rdma_query_gid(ibdev, port, index, gid) \
	ib_get_cached_gid(ibdev, port, index, gid, NULL)
#define IB_GET_CACHED_GID
#else
#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)
#define kc_set_props_ip_gid_caps(props)	((props)->ip_gids = true)
#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
#define kc_typeq_ib_wr const
#else
#define kc_typeq_ib_wr
#endif

/* ib_register_device */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, NULL)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0))
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, NULL)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name)
#else
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, dev)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define HAS_IB_SET_DEVICE_OP
#endif /* >= 5.0.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
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

#define kc_set_ibdev_add_del_gid(ibdev) do {   \
	ibdev->add_gid = irdma_add_gid;  \
	ibdev->del_gid = irdma_del_gid;  \
} while (0)
#else
#define kc_set_ibdev_add_del_gid(ibdev)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll)
#else
#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)
#endif /* < 4.20.0 */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0))
#define IRDMA_SET_DRIVER_ID
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0))
#define kc_rdma_udata_to_drv_context(ibpd, udata) to_ucontext((ibpd)->uobject->context)
#define SET_BEST_PAGE_SZ_V1
#else
#define SET_BEST_PAGE_SZ_V2
#define kc_rdma_udata_to_drv_context(ibpd, udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0))
#define UVERBS_CMD_MASK
#else
#define USE_QP_ATTRS_STANDARD
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
#define SET_PCIDEV_PARENT
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
#define ib_umem_get(udata, addr, size, access, dmasync) \
	ib_umem_get(pd->uobject->context, addr, size, access, dmasync)
#define ib_device_put(dev)
#define ib_alloc_device(irdma_device, ibdev) \
	((struct irdma_device *)ib_alloc_device(sizeof(struct irdma_device)))
#else
#define NETDEV_TO_IBDEV_SUPPORT
#define IB_DEALLOC_DRIVER_SUPPORT
#endif /* < 5.1.0 */

/******PORT_PHYS_STATE enums***************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0))
enum ib_port_phys_state {
	IB_PORT_PHYS_STATE_SLEEP = 1,
	IB_PORT_PHYS_STATE_POLLING = 2,
	IB_PORT_PHYS_STATE_DISABLED = 3,
	IB_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING = 4,
	IB_PORT_PHYS_STATE_LINK_UP = 5,
	IB_PORT_PHYS_STATE_LINK_ERROR_RECOVERY = 6,
	IB_PORT_PHYS_STATE_PHY_TEST = 7,
};
#endif
/*********************************************************/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#else
#define kc_get_ucontext(udata) to_ucontext(context)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define IN_IFADDR
#else
#define FOR_IFA
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
struct ib_ucontext *irdma_alloc_ucontext(struct ib_device *ibdev, struct ib_udata *udata);
int irdma_dealloc_ucontext(struct ib_ucontext *context);
struct ib_pd *irdma_alloc_pd(struct ib_device *ibdev, struct ib_ucontext *context, struct ib_udata *udata);
int irdma_dealloc_pd(struct ib_pd *ibpd);
#else
int irdma_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata);
void irdma_dealloc_ucontext(struct ib_ucontext *context);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
int irdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);
int irdma_alloc_pd(struct ib_pd *pd, struct ib_udata *udata);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
int irdma_alloc_pd(struct ib_pd *pd, struct ib_udata *udata);
void irdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);
#else
int irdma_alloc_pd(struct ib_pd *pd, struct ib_ucontext *context, struct ib_udata *udata);
void irdma_dealloc_pd(struct ib_pd *ibpd);
#endif
#endif
#endif

/*****SETUP DMA_DEVICE***************************************************/
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#define set_ibdev_dma_device(ibdev, dev)	\
	ibdev.dma_device = dev
#else
#define set_ibdev_dma_device(ibdev, dev)
#endif /* < 4.11.0 */
/*********************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
#define rdma_ah_attr ib_ah_attr
#define ah_attr_to_dmac(attr) ((attr).dmac)
#else
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#endif /* < 4.12.0 */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)) &&	\
(LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0))
#define IB_RESOLVE_ETH_DMAC
#endif /* >= 4.10.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#define wait_queue_entry __wait_queue
#endif /* < 4.13.0 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
#define IRDMA_ADD_DEL_GID
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
#define SET_ROCE_CM_INFO_VER_1
#define IB_IW_MANDATORY_AH_OP
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
#define SET_ROCE_CM_INFO_VER_2
#else
#define SET_ROCE_CM_INFO_VER_3
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define IB_UMEM_GET_V3
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
#define IB_UMEM_GET_V2
#else
#define IB_UMEM_GET_V1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define DEREG_MR_VER_2
#else
#define DEREG_MR_VER_1
#endif

/* REREG MR  */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#define REREG_MR_VER_2
#else
#define REREG_MR_VER_1
#endif
/* DMABUF */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#define SET_DMABUF
#endif
/* IRDMA_IRQ_UPDATE_AFFINITY */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)) &&	\
(LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0))
#define IRDMA_IRQ_UPDATE_AFFINITY
#define IRDMA_AUX_GET_SET_DRV_DATA
#endif
#endif /* LINUX_KCOMPAT_H */
