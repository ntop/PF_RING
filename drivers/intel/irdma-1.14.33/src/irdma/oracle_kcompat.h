/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2020 - 2022 Intel Corporation */
#ifndef ORACLE_KCOMPAT_H
#define ORACLE_KCOMPAT_H

/* IB_IW_PKEY */
#define IB_IW_PKEY

/* KMAP_LOCAL_PAGE */
#define USE_KMAP

/* CREATE_AH */
#define CREATE_AH_VER_5

/* DESTROY_AH */
#define DESTROY_AH_VER_3

/* CREAT_QP */
#define CREATE_QP_VER_1

/* DESTROY_QP */
#define DESTROY_QP_VER_2
#define kc_irdma_destroy_qp(ibqp, udata) irdma_destroy_qp(ibqp, udata)

/* CREATE_CQ */
#define CREATE_CQ_VER_3

/* ALLOC_UCONTEXT/ DEALLOC_UCONTEXT */
#define ALLOC_UCONTEXT_VER_2
#define DEALLOC_UCONTEXT_VER_2

/* ALLOC_PD , DEALLOC_PD */
#define ALLOC_PD_VER_3
#define DEALLOC_PD_VER_3

#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_HW_STATS_V2

#define QUERY_GID_ROCE_V2
#define MODIFY_PORT_V2
#define QUERY_PKEY_V2
#define ROCE_PORT_IMMUTABLE_V2
#define GET_HW_STATS_V2
#define GET_LINK_LAYER_V2
#define IW_PORT_IMMUTABLE_V2
#define QUERY_GID_V2
#define QUERY_PORT_V2


/* IRDMA_ALLOC_MW */
#define IRDMA_ALLOC_MW_VER_1

/* IRDMA_ALLOC_MR */
#define IRDMA_ALLOC_MR_VER_1

/* IRDMA_DESTROY_CQ */
#define IRDMA_DESTROY_CQ_VER_3

/* max_sge, ip_gid, gid_attr_network_type, deref_sgid_attr */
#define set_max_sge(props, rf)  do {   \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
} while (0)
#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)
#define kc_deref_sgid_attr(sgid_attr)    ((sgid_attr)->ndev)

#define kc_typeq_ib_wr const

/* ib_register_device */
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, dev)

#define HAS_IB_SET_DEVICE_OP

#define kc_set_ibdev_add_del_gid(ibdev)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)

#define SET_BEST_PAGE_SZ_V2
#define kc_rdma_udata_to_drv_context(ibpd, udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)

#define UVERBS_CMD_MASK

#define NETDEV_TO_IBDEV_SUPPORT
#define IB_DEALLOC_DRIVER_SUPPORT

#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)

#define IN_IFADDR

int irdma_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata);
void irdma_dealloc_ucontext(struct ib_ucontext *context);
int irdma_alloc_pd(struct ib_pd *pd, struct ib_udata *udata);
void irdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata);

/*****SETUP DMA_DEVICE***************************************************/
#define set_ibdev_dma_device(ibdev, dev)
/*********************************************************/

#define ah_attr_to_dmac(attr) ((attr).roce.dmac)

#define SET_ROCE_CM_INFO_VER_3

#define IB_UMEM_GET_V1

#define DEREG_MR_VER_2

/* REREG MR  */
#define REREG_MR_VER_1

#endif /* ORACLE_KCOMPAT_H */

