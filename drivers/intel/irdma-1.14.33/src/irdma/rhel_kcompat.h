/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2020 - 2022 Intel Corporation */
#ifndef RHEL_KCOMPAT_H
#define RHEL_KCOMPAT_H

#ifdef RHEL_9_2
#define ALLOC_HW_STATS_V3
#define ALLOC_HW_STATS_STRUCT_V2
#define ALLOC_PD_VER_3
#define ALLOC_UCONTEXT_VER_2
#define CREATE_AH_VER_5
#define CREATE_QP_VER_2
#define GLOBAL_QP_MEM
#define CREATE_CQ_VER_3
#define DESTROY_AH_VER_4
#define DEALLOC_PD_VER_4
#define DESTROY_QP_VER_2
#define DEALLOC_UCONTEXT_VER_2
#define DEREG_MR_VER_2
#define GET_HW_STATS_V2
#define GET_LINK_LAYER_V2
#define HAS_IB_SET_DEVICE_OP
#define IB_DEV_CAPS_VER_2
#define IB_DEALLOC_DRIVER_SUPPORT
#define IW_PORT_IMMUTABLE_V2
#define IB_UMEM_GET_V3
#define IN_IFADDR
#define IRDMA_ALLOC_MW_VER_2
#define IRDMA_DESTROY_CQ_VER_4
#define IRDMA_DESTROY_SRQ_VER_3
#define IRDMA_ALLOC_MR_VER_0
#define MODIFY_PORT_V2
#define NETDEV_TO_IBDEV_SUPPORT
#define QUERY_GID_V2
#define QUERY_GID_ROCE_V2
#define QUERY_PKEY_V2
#define QUERY_PORT_V2
#define REREG_MR_VER_2
#define SET_DMABUF
#define ROCE_PORT_IMMUTABLE_V2
#define RDMA_MMAP_DB_SUPPORT
#define SET_BEST_PAGE_SZ_V2
#define SET_ROCE_CM_INFO_VER_3

#define kc_set_ibdev_add_del_gid(ibdev)
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, dev)
#define kc_rdma_udata_to_drv_context(ibpd, udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_typeq_ib_wr const

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)
#endif /* RHEL_9_2 */

#ifdef RHEL_9_1
#define ALLOC_HW_STATS_V3
#define ALLOC_HW_STATS_STRUCT_V2
#define ALLOC_PD_VER_3
#define ALLOC_UCONTEXT_VER_2
#define CREATE_AH_VER_5
#define CREATE_QP_VER_2
#define GLOBAL_QP_MEM
#define CREATE_CQ_VER_3
#define DESTROY_AH_VER_4
#define DEALLOC_PD_VER_4
#define DESTROY_QP_VER_2
#define DEALLOC_UCONTEXT_VER_2
#define DEREG_MR_VER_2
#define GET_HW_STATS_V2
#define GET_LINK_LAYER_V2
#define HAS_IB_SET_DEVICE_OP
#define IB_DEALLOC_DRIVER_SUPPORT
#define IW_PORT_IMMUTABLE_V2
#define IB_UMEM_GET_V3
#define IN_IFADDR
#define IRDMA_ALLOC_MW_VER_2
#define IRDMA_DESTROY_CQ_VER_4
#define IRDMA_DESTROY_SRQ_VER_3
#define IRDMA_ALLOC_MR_VER_0
#define MODIFY_PORT_V2
#define NETDEV_TO_IBDEV_SUPPORT
#define QUERY_GID_V2
#define QUERY_GID_ROCE_V2
#define QUERY_PKEY_V2
#define QUERY_PORT_V2
#define REREG_MR_VER_2
#define SET_DMABUF
#define ROCE_PORT_IMMUTABLE_V2
#define RDMA_MMAP_DB_SUPPORT
#define SET_BEST_PAGE_SZ_V2
#define SET_ROCE_CM_INFO_VER_3

#define kc_set_ibdev_add_del_gid(ibdev)
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, dev)
#define kc_rdma_udata_to_drv_context(ibpd, udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_typeq_ib_wr const

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)
#endif /* RHEL_9_1 */

#ifdef RHEL_9_0
#define ALLOC_HW_STATS_V3
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_3
#define ALLOC_UCONTEXT_VER_2
#define CREATE_AH_VER_5
#define CREATE_QP_VER_1
#define CREATE_CQ_VER_3
#define DESTROY_AH_VER_4
#define DEALLOC_PD_VER_4
#define DESTROY_QP_VER_2
#define DEALLOC_UCONTEXT_VER_2
#define DEREG_MR_VER_2
#define GET_HW_STATS_V2
#define GET_LINK_LAYER_V2
#define HAS_IB_SET_DEVICE_OP
#define IB_DEALLOC_DRIVER_SUPPORT
#define IW_PORT_IMMUTABLE_V2
#define IB_UMEM_GET_V3
#define IN_IFADDR
#define IRDMA_ALLOC_MW_VER_2
#define IRDMA_DESTROY_CQ_VER_4
#define IRDMA_DESTROY_SRQ_VER_3
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_IRQ_UPDATE_AFFINITY
#define IRDMA_AUX_GET_SET_DRV_DATA
#define MODIFY_PORT_V2
#define NETDEV_TO_IBDEV_SUPPORT
#define QUERY_GID_V2
#define QUERY_GID_ROCE_V2
#define QUERY_PKEY_V2
#define QUERY_PORT_V2
#define REREG_MR_VER_2
#define ROCE_PORT_IMMUTABLE_V2
#define RDMA_MMAP_DB_SUPPORT
#define SET_BEST_PAGE_SZ_V2
#define SET_ROCE_CM_INFO_VER_3

#define kc_set_ibdev_add_del_gid(ibdev)
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, dev)
#define kc_rdma_udata_to_drv_context(ibpd, udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_typeq_ib_wr const

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)
#endif /* RHEL_9_0 */

#ifdef RHEL_8_8
#define ALLOC_HW_STATS_V3
#define ALLOC_HW_STATS_STRUCT_V2
#define ALLOC_PD_VER_3
#define ALLOC_UCONTEXT_VER_2
#define CREATE_AH_VER_5
#define CREATE_QP_VER_2
#define GLOBAL_QP_MEM
#define CREATE_CQ_VER_3
#define DESTROY_AH_VER_4
#define DEALLOC_PD_VER_4
#define DESTROY_QP_VER_2
#define DEALLOC_UCONTEXT_VER_2
#define DEREG_MR_VER_2
#define GET_HW_STATS_V2
#define GET_LINK_LAYER_V2
#define HAS_IB_SET_DEVICE_OP
#define IB_DEALLOC_DRIVER_SUPPORT
#define IW_PORT_IMMUTABLE_V2
#define IB_UMEM_GET_V2
#define IB_DEV_CAPS_VER_2
#define IN_IFADDR
#define IRDMA_ALLOC_MW_VER_2
#define IRDMA_DESTROY_CQ_VER_4
#define IRDMA_DESTROY_SRQ_VER_3
#define IRDMA_ALLOC_MR_VER_0
#define MODIFY_PORT_V2
#define NETDEV_TO_IBDEV_SUPPORT
#define QUERY_GID_V2
#define QUERY_GID_ROCE_V2
#define QUERY_PKEY_V2
#define QUERY_PORT_V2
#define REREG_MR_VER_2
#define ROCE_PORT_IMMUTABLE_V2
#define RDMA_MMAP_DB_SUPPORT
#define SET_BEST_PAGE_SZ_V2
#define SET_ROCE_CM_INFO_VER_3
#define GET_NETDEV_OP_V2

#define kc_set_ibdev_add_del_gid(ibdev)
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, dev)
#define kc_rdma_udata_to_drv_context(ibpd, udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_typeq_ib_wr const

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)
#endif /* RHEL_8_8 */

#ifdef RHEL_8_7
#define ALLOC_HW_STATS_V3
#define ALLOC_HW_STATS_STRUCT_V2
#define ALLOC_PD_VER_3
#define ALLOC_UCONTEXT_VER_2
#define CREATE_AH_VER_5
#define CREATE_QP_VER_2
#define GLOBAL_QP_MEM
#define CREATE_CQ_VER_3
#define DESTROY_AH_VER_4
#define DEALLOC_PD_VER_4
#define DESTROY_QP_VER_2
#define DEALLOC_UCONTEXT_VER_2
#define DEREG_MR_VER_2
#define GET_HW_STATS_V2
#define GET_LINK_LAYER_V2
#define HAS_IB_SET_DEVICE_OP
#define IB_DEALLOC_DRIVER_SUPPORT
#define IW_PORT_IMMUTABLE_V2
#define IB_UMEM_GET_V2
#define IN_IFADDR
#define IRDMA_ALLOC_MW_VER_2
#define IRDMA_DESTROY_CQ_VER_4
#define IRDMA_DESTROY_SRQ_VER_3
#define IRDMA_ALLOC_MR_VER_0
#define MODIFY_PORT_V2
#define NETDEV_TO_IBDEV_SUPPORT
#define QUERY_GID_V2
#define QUERY_GID_ROCE_V2
#define QUERY_PKEY_V2
#define QUERY_PORT_V2
#define REREG_MR_VER_2
#define ROCE_PORT_IMMUTABLE_V2
#define RDMA_MMAP_DB_SUPPORT
#define SET_BEST_PAGE_SZ_V2
#define SET_ROCE_CM_INFO_VER_3
#define GET_NETDEV_OP_V2

#define kc_set_ibdev_add_del_gid(ibdev)
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, dev)
#define kc_rdma_udata_to_drv_context(ibpd, udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_typeq_ib_wr const

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)
#endif /* RHEL_8_7 */

#ifdef RHEL_8_6
#define ALLOC_HW_STATS_V3
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_3
#define ALLOC_UCONTEXT_VER_2
#define CREATE_AH_VER_5
#define CREATE_QP_VER_1
#define CREATE_CQ_VER_3
#define DESTROY_AH_VER_4
#define DEALLOC_PD_VER_4
#define DESTROY_QP_VER_2
#define DEALLOC_UCONTEXT_VER_2
#define DEREG_MR_VER_2
#define GET_HW_STATS_V2
#define GET_LINK_LAYER_V2
#define HAS_IB_SET_DEVICE_OP
#define IB_DEALLOC_DRIVER_SUPPORT
#define IW_PORT_IMMUTABLE_V2
#define IB_UMEM_GET_V2
#define IN_IFADDR
#define IRDMA_ALLOC_MW_VER_2
#define IRDMA_DESTROY_CQ_VER_4
#define IRDMA_DESTROY_SRQ_VER_3
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_IRQ_UPDATE_AFFINITY
#define IRDMA_AUX_GET_SET_DRV_DATA
#define MODIFY_PORT_V2
#define NETDEV_TO_IBDEV_SUPPORT
#define QUERY_GID_V2
#define QUERY_GID_ROCE_V2
#define QUERY_PKEY_V2
#define QUERY_PORT_V2
#define REREG_MR_VER_2
#define ROCE_PORT_IMMUTABLE_V2
#define RDMA_MMAP_DB_SUPPORT
#define SET_BEST_PAGE_SZ_V2
#define SET_ROCE_CM_INFO_VER_3
#define GET_NETDEV_OP_V2

#define kc_set_ibdev_add_del_gid(ibdev)
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, dev)
#define kc_rdma_udata_to_drv_context(ibpd, udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_typeq_ib_wr const

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)
#endif /* RHEL_8_6 */

#ifdef RHEL_8_5
#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_3
#define ALLOC_UCONTEXT_VER_2
#define CREATE_AH_VER_5
#define CREATE_QP_VER_1
#define CREATE_CQ_VER_3
#define DESTROY_AH_VER_4
#define DEALLOC_PD_VER_4
#define DESTROY_QP_VER_2
#define DEALLOC_UCONTEXT_VER_2
#define DEREG_MR_VER_2
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define HAS_IB_SET_DEVICE_OP
#define IB_DEALLOC_DRIVER_SUPPORT
#define IB_IW_PKEY
#define IW_PORT_IMMUTABLE_V1
#define IB_UMEM_GET_V2
#define IN_IFADDR
#define IRDMA_ALLOC_MW_VER_2
#define IRDMA_DESTROY_CQ_VER_4
#define IRDMA_DESTROY_SRQ_VER_3
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_IRQ_UPDATE_AFFINITY
#define IRDMA_AUX_GET_SET_DRV_DATA
#define MODIFY_PORT_V1
#define NETDEV_TO_IBDEV_SUPPORT
#define QUERY_GID_V1
#define QUERY_GID_ROCE_V1
#define QUERY_PKEY_V1
#define QUERY_PORT_V1
#define REREG_MR_VER_2
#define ROCE_PORT_IMMUTABLE_V1
#define RDMA_MMAP_DB_SUPPORT
#define SET_BEST_PAGE_SZ_V2
#define SET_ROCE_CM_INFO_VER_3
#define USE_KMAP

#define kc_set_ibdev_add_del_gid(ibdev)
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, dev)
#define kc_rdma_udata_to_drv_context(ibpd, udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_typeq_ib_wr const

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)
#endif /* RHEL_8_5 */

#ifdef RHEL_8_4
#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_3
#define ALLOC_UCONTEXT_VER_2
#define CREATE_AH_VER_5
#define CREATE_QP_VER_1
#define CREATE_CQ_VER_3
#define DESTROY_AH_VER_3
#define DEALLOC_PD_VER_3
#define DESTROY_QP_VER_2
#define DEALLOC_UCONTEXT_VER_2
#define DEREG_MR_VER_2
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define HAS_IB_SET_DEVICE_OP
#define IB_DEALLOC_DRIVER_SUPPORT
#define IB_IW_PKEY
#define IW_PORT_IMMUTABLE_V1
#define IB_UMEM_GET_V2
#define IN_IFADDR
#define IRDMA_ALLOC_MW_VER_1
#define IRDMA_DESTROY_CQ_VER_3
#define IRDMA_DESTROY_SRQ_VER_2
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_IRQ_UPDATE_AFFINITY
#define IRDMA_AUX_GET_SET_DRV_DATA
#define MODIFY_PORT_V1
#define NETDEV_TO_IBDEV_SUPPORT
#define QUERY_GID_V1
#define QUERY_GID_ROCE_V1
#define QUERY_PKEY_V1
#define QUERY_PORT_V1
#define REREG_MR_VER_1
#define ROCE_PORT_IMMUTABLE_V1
#define RDMA_MMAP_DB_SUPPORT
#define SET_BEST_PAGE_SZ_V2
#define SET_ROCE_CM_INFO_VER_3
#define UVERBS_CMD_MASK
#define USE_KMAP
#define SET_PCIDEV_PARENT

#define kc_set_ibdev_add_del_gid(ibdev)
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name)
#define kc_rdma_udata_to_drv_context(ibpd, udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_typeq_ib_wr const

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)
#endif /* RHEL_8_4 */

#ifdef RHEL_8_3

#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_3
#define ALLOC_UCONTEXT_VER_2
#define CREATE_AH_VER_2
#define CREATE_CQ_VER_3
#define CREATE_QP_VER_1
#define DEALLOC_PD_VER_3
#define DEALLOC_UCONTEXT_VER_2
#define DEREG_MR_VER_2
#define DESTROY_AH_VER_3
#define DESTROY_QP_VER_2
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define HAS_IB_SET_DEVICE_OP
#define NETDEV_TO_IBDEV_SUPPORT
#define IB_DEALLOC_DRIVER_SUPPORT
#define IB_IW_PKEY
#define IB_UMEM_GET_V2
#define IN_IFADDR
#define IRDMA_ALLOC_MR_VER_1
#define IRDMA_ALLOC_MW_VER_1
#define IRDMA_DESTROY_CQ_VER_3
#define IRDMA_DESTROY_SRQ_VER_2
#define IRDMA_IRQ_UPDATE_AFFINITY
#define IRDMA_AUX_GET_SET_DRV_DATA
#define IW_PORT_IMMUTABLE_V1
#define MODIFY_PORT_V1
#define QUERY_GID_V1
#define QUERY_GID_ROCE_V1
#define QUERY_PKEY_V1
#define QUERY_PORT_V1
#define REREG_MR_VER_1
#define ROCE_PORT_IMMUTABLE_V1
#define RDMA_MMAP_DB_SUPPORT
#define SET_BEST_PAGE_SZ_V2
#define SET_ROCE_CM_INFO_VER_3
#define UVERBS_CMD_MASK
#define USE_KMAP
#define SET_PCIDEV_PARENT

#define kc_set_ibdev_add_del_gid(ibdev)
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name)
#define kc_rdma_udata_to_drv_context(ibpd, udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_typeq_ib_wr const

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)
#endif /* RHEL_8_3 */

#ifdef RHEL_7_9
enum ib_port_phys_state {
	IB_PORT_PHYS_STATE_SLEEP = 1,
	IB_PORT_PHYS_STATE_POLLING = 2,
	IB_PORT_PHYS_STATE_DISABLED = 3,
	IB_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING = 4,
	IB_PORT_PHYS_STATE_LINK_UP = 5,
	IB_PORT_PHYS_STATE_LINK_ERROR_RECOVERY = 6,
	IB_PORT_PHYS_STATE_PHY_TEST = 7,
};

#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_1
#define ALLOC_UCONTEXT_VER_1
#define CREATE_AH_VER_4
#define CREATE_CQ_VER_1
#define CREATE_QP_VER_1
#define DEALLOC_PD_VER_1
#define DEALLOC_UCONTEXT_VER_1
#define DEREG_MR_VER_1
#define DESTROY_AH_VER_1
#define CREATE_QP_VER_1
#define DESTROY_QP_VER_1
#define FOR_IFA
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define IB_UMEM_GET_V1
#define IB_IW_PKEY
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_ALLOC_MW_VER_1
#define IRDMA_DESTROY_CQ_VER_1
#define IRDMA_DESTROY_SRQ_VER_1
#define IRDMA_IRQ_UPDATE_AFFINITY
#define IRDMA_AUX_GET_SET_DRV_DATA
#define IW_PORT_IMMUTABLE_V1
#define MODIFY_PORT_V1
#define QUERY_GID_V1
#define QUERY_GID_ROCE_V1
#define QUERY_PKEY_V1
#define QUERY_PORT_V1
#define REREG_MR_VER_1
#define ROCE_PORT_IMMUTABLE_V1
#define SET_BEST_PAGE_SZ_V1
#define SET_ROCE_CM_INFO_VER_2
#define UVERBS_CMD_MASK
#define VMA_DATA
#define USE_KMAP
#define NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
#define SET_PCIDEV_PARENT

#define kc_set_ibdev_add_del_gid(ibdev)
#define wait_queue_entry __wait_queue
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, NULL)
#define kc_typeq_ib_wr const
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props) ((props)->ip_gids = true)
#define ib_device_put(dev)
#define kc_get_ucontext(udata) to_ucontext(context)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_rdma_udata_to_drv_context(ibpd, udata) to_ucontext((ibpd)->uobject->context)

#define ib_alloc_device(irdma_device, ibdev) \
	((struct irdma_device *)ib_alloc_device(sizeof(struct irdma_device)))

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)

#define ib_umem_get(udata, addr, size, access, dmasync) \
	ib_umem_get(pd->uobject->context, addr, size, access, dmasync)

#endif

#ifdef RHEL_8_2
#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_3
#define ALLOC_UCONTEXT_VER_2
#define CREATE_AH_VER_2
#define CREATE_CQ_VER_3
#define CREATE_QP_VER_1
#define DESTROY_AH_VER_3
#define CREATE_QP_VER_1
#define DESTROY_QP_VER_2
#define DEALLOC_PD_VER_3
#define DEALLOC_UCONTEXT_VER_2
#define DEREG_MR_VER_2
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define HAS_IB_SET_DEVICE_OP
#define NETDEV_TO_IBDEV_SUPPORT
#define IB_DEALLOC_DRIVER_SUPPORT
#define IB_IW_PKEY
#define IB_UMEM_GET_V1
#define IN_IFADDR
#define IRDMA_ALLOC_MR_VER_1
#define IRDMA_ALLOC_MW_VER_1
#define IRDMA_DESTROY_CQ_VER_3
#define IRDMA_DESTROY_SRQ_VER_2
#define IRDMA_IRQ_UPDATE_AFFINITY
#define IRDMA_AUX_GET_SET_DRV_DATA
#define IW_PORT_IMMUTABLE_V1
#define MODIFY_PORT_V1
#define QUERY_GID_V1
#define QUERY_GID_ROCE_V1
#define QUERY_PKEY_V1
#define QUERY_PORT_V1
#define REREG_MR_VER_1
#define ROCE_PORT_IMMUTABLE_V1
#define SET_BEST_PAGE_SZ_V2
#define SET_ROCE_CM_INFO_VER_3
#define UVERBS_CMD_MASK
#define USE_KMAP
#define SET_PCIDEV_PARENT

#define kc_set_ibdev_add_del_gid(ibdev)
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props)	((props)->ip_gids = true)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name)
#define kc_rdma_udata_to_drv_context(ibpd, udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define kc_get_ucontext(udata) rdma_udata_to_drv_context(udata, struct irdma_ucontext, ibucontext)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_typeq_ib_wr const

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)
#endif /* RHEL_8_2 */

#ifdef RHEL_8_1
enum ib_port_phys_state {
	IB_PORT_PHYS_STATE_SLEEP = 1,
	IB_PORT_PHYS_STATE_POLLING = 2,
	IB_PORT_PHYS_STATE_DISABLED = 3,
	IB_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING = 4,
	IB_PORT_PHYS_STATE_LINK_UP = 5,
	IB_PORT_PHYS_STATE_LINK_ERROR_RECOVERY = 6,
	IB_PORT_PHYS_STATE_PHY_TEST = 7,
};

#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_1
#define ALLOC_UCONTEXT_VER_1
#define CREATE_AH_VER_3
#define CREATE_CQ_VER_1
#define CREATE_QP_VER_1
#define DESTROY_AH_VER_2
#define DEALLOC_UCONTEXT_VER_1
#define DEALLOC_PD_VER_1
#define DEREG_MR_VER_1
#define DESTROY_QP_VER_1
#define FOR_IFA
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define HAS_IB_SET_DEVICE_OP
#define IB_GET_NETDEV_OP_NOT_DEPRECATED
#define IB_IW_PKEY
#define IB_UMEM_GET_V1
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_ALLOC_MW_VER_1
#define IRDMA_DESTROY_CQ_VER_1
#define IRDMA_DESTROY_SRQ_VER_1
#define IRDMA_SET_DRIVER_ID
#define IRDMA_IRQ_UPDATE_AFFINITY
#define IRDMA_AUX_GET_SET_DRV_DATA
#define IW_PORT_IMMUTABLE_V1
#define MODIFY_PORT_V1
#define QUERY_GID_V1
#define QUERY_GID_ROCE_V1
#define QUERY_PKEY_V1
#define QUERY_PORT_V1
#define REREG_MR_VER_1
#define ROCE_PORT_IMMUTABLE_V1
#define SET_BEST_PAGE_SZ_V1
#define SET_ROCE_CM_INFO_VER_2
#define UVERBS_CMD_MASK
#define VMA_DATA
#define USE_KMAP
#define SET_PCIDEV_PARENT

#define kc_irdma_destroy_qp(ibqp, udata) irdma_destroy_qp(ibqp)
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, NULL)
#define kc_typeq_ib_wr const
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props)	((props)->ip_gids = true)
#define kc_set_ibdev_add_del_gid(ibdev)
#define ib_device_put(dev)
#define kc_get_ucontext(udata) to_ucontext(context)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_rdma_udata_to_drv_context(ibpd, udata) to_ucontext((ibpd)->uobject->context)

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)

#define ib_umem_get(udata, addr, size, access, dmasync) \
	ib_umem_get(pd->uobject->context, addr, size, access, dmasync)
#endif /* RHEL_8_1 */

#ifdef RHEL_7_8
enum ib_port_phys_state {
	IB_PORT_PHYS_STATE_SLEEP = 1,
	IB_PORT_PHYS_STATE_POLLING = 2,
	IB_PORT_PHYS_STATE_DISABLED = 3,
	IB_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING = 4,
	IB_PORT_PHYS_STATE_LINK_UP = 5,
	IB_PORT_PHYS_STATE_LINK_ERROR_RECOVERY = 6,
	IB_PORT_PHYS_STATE_PHY_TEST = 7,
};

#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_1
#define ALLOC_UCONTEXT_VER_1
#define CREATE_AH_VER_4
#define CREATE_CQ_VER_1
#define CREATE_QP_VER_1
#define DEALLOC_PD_VER_1
#define DEALLOC_UCONTEXT_VER_1
#define DEREG_MR_VER_1
#define DESTROY_AH_VER_1
#define DESTROY_QP_VER_1
#define FOR_IFA
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define IB_IW_PKEY
#define IB_UMEM_GET_V1
#define IRDMA_ALLOC_MW_VER_1
#define IRDMA_DESTROY_CQ_VER_1
#define IRDMA_DESTROY_SRQ_VER_1
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_IRQ_UPDATE_AFFINITY
#define IRDMA_AUX_GET_SET_DRV_DATA
#define IW_PORT_IMMUTABLE_V1
#define MODIFY_PORT_V1
#define QUERY_GID_V1
#define QUERY_GID_ROCE_V1
#define QUERY_PKEY_V1
#define QUERY_PORT_V1
#define REREG_MR_VER_1
#define ROCE_PORT_IMMUTABLE_V1
#define SET_BEST_PAGE_SZ_V1
#define SET_ROCE_CM_INFO_VER_2
#define UVERBS_CMD_MASK
#define VMA_DATA
#define USE_KMAP
#define NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
#define SET_PCIDEV_PARENT

#define kc_set_ibdev_add_del_gid(ibdev)
#define wait_queue_entry __wait_queue
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, NULL)
#define kc_typeq_ib_wr const
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props)	((props)->ip_gids = true)
#define ib_device_put(dev)
#define kc_get_ucontext(udata) to_ucontext(context)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_rdma_udata_to_drv_context(ibpd, udata) to_ucontext((ibpd)->uobject->context)

#define ib_alloc_device(irdma_device, ibdev) \
	((struct irdma_device *)ib_alloc_device(sizeof(struct irdma_device)))

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)

#define ib_umem_get(udata, addr, size, access, dmasync) \
	ib_umem_get(pd->uobject->context, addr, size, access, dmasync)
#endif /* RHEL_7_8 */

#ifdef RHEL_7_7
enum ib_port_phys_state {
	IB_PORT_PHYS_STATE_SLEEP = 1,
	IB_PORT_PHYS_STATE_POLLING = 2,
	IB_PORT_PHYS_STATE_DISABLED = 3,
	IB_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING = 4,
	IB_PORT_PHYS_STATE_LINK_UP = 5,
	IB_PORT_PHYS_STATE_LINK_ERROR_RECOVERY = 6,
	IB_PORT_PHYS_STATE_PHY_TEST = 7,
};

#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_1
#define ALLOC_UCONTEXT_VER_1
#define CREATE_AH_VER_4
#define CREATE_CQ_VER_1
#define CREATE_QP_VER_1
#define DEALLOC_PD_VER_1
#define DEALLOC_UCONTEXT_VER_1
#define DEREG_MR_VER_1
#define DESTROY_AH_VER_1
#define DESTROY_QP_VER_1
#define FOR_IFA
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define IB_IW_PKEY
#define IB_UMEM_GET_V1
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_ALLOC_MW_VER_1
#define IRDMA_DESTROY_CQ_VER_1
#define IRDMA_DESTROY_SRQ_VER_1
#define IRDMA_IRQ_UPDATE_AFFINITY
#define IRDMA_AUX_GET_SET_DRV_DATA
#define IW_PORT_IMMUTABLE_V1
#define MODIFY_PORT_V1
#define QUERY_GID_V1
#define QUERY_GID_ROCE_V1
#define QUERY_PKEY_V1
#define QUERY_PORT_V1
#define REREG_MR_VER_1
#define ROCE_PORT_IMMUTABLE_V1
#define SET_BEST_PAGE_SZ_V1
#define SET_ROCE_CM_INFO_VER_2
#define UVERBS_CMD_MASK
#define VMA_DATA
#define USE_KMAP
#define NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
#define SET_PCIDEV_PARENT

#define kc_set_ibdev_add_del_gid(ibdev)
#define wait_queue_entry __wait_queue
#define kc_ib_register_device(device, name, dev) ib_register_device(device, name, NULL)
#define kc_typeq_ib_wr const
#define kc_deref_sgid_attr(sgid_attr)        ((sgid_attr)->ndev)
#define kc_set_props_ip_gid_caps(props)	((props)->ip_gids = true)
#define ib_device_put(dev)
#define kc_get_ucontext(udata) to_ucontext(context)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_rdma_udata_to_drv_context(ibpd, udata) to_ucontext((ibpd)->uobject->context)

#define ib_alloc_device(irdma_device, ibdev) \
	((struct irdma_device *)ib_alloc_device(sizeof(struct irdma_device)))

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	rdma_gid_attr_network_type(sgid_attr)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask)

#define ib_umem_get(udata, addr, size, access, dmasync) \
	ib_umem_get(pd->uobject->context, addr, size, access, dmasync)
#endif /* RHEL_7_7 */

#ifdef RHEL_8_0
enum ib_port_phys_state {
	IB_PORT_PHYS_STATE_SLEEP = 1,
	IB_PORT_PHYS_STATE_POLLING = 2,
	IB_PORT_PHYS_STATE_DISABLED = 3,
	IB_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING = 4,
	IB_PORT_PHYS_STATE_LINK_UP = 5,
	IB_PORT_PHYS_STATE_LINK_ERROR_RECOVERY = 6,
	IB_PORT_PHYS_STATE_PHY_TEST = 7,
};

#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_1
#define ALLOC_UCONTEXT_VER_1
#define CREATE_AH_VER_1_2
#define CREATE_CQ_VER_1
#define CREATE_QP_VER_1
#define DESTROY_AH_VER_1
#define DESTROY_QP_VER_1
#define DEALLOC_UCONTEXT_VER_1
#define DEALLOC_PD_VER_1
#define DEREG_MR_VER_1
#define ETHER_COPY_VER_2
#define FOR_IFA
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define IB_UMEM_GET_V1
#define IB_GET_CACHED_GID
#define IB_IW_MANDATORY_AH_OP
#define IB_IW_PKEY
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_ALLOC_MW_VER_1
#define IRDMA_DESTROY_CQ_VER_1
#define IRDMA_DESTROY_SRQ_VER_1
#define IRDMA_SET_DRIVER_ID
#define IRDMA_IRQ_UPDATE_AFFINITY
#define IRDMA_AUX_GET_SET_DRV_DATA
#define IW_PORT_IMMUTABLE_V1
#define MODIFY_PORT_V1
#define QUERY_GID_V1
#define QUERY_GID_ROCE_V1
#define QUERY_PKEY_V1
#define QUERY_PORT_V1
#define REREG_MR_VER_1
#define ROCE_PORT_IMMUTABLE_V1
#define SET_BEST_PAGE_SZ_V1
#define SET_ROCE_CM_INFO_VER_1
#define UVERBS_CMD_MASK
#define VMA_DATA
#define USE_KMAP
#define NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
#define SET_PCIDEV_PARENT

#define kc_ib_register_device(device, name, dev) ib_register_device(device, NULL)
#define kc_typeq_ib_wr
#define kc_deref_sgid_attr(sgid_attr)        (sgid_attr.ndev)
#define kc_set_props_ip_gid_caps(props)	((props)->ip_gids = true)
#define ib_device_put(dev)
#define kc_get_ucontext(udata) to_ucontext(context)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)
#define kc_rdma_udata_to_drv_context(ibpd, udata) to_ucontext((ibpd)->uobject->context)

#define ib_alloc_device(irdma_device, ibdev) \
	((struct irdma_device *)ib_alloc_device(sizeof(struct irdma_device)))

#define rdma_query_gid(ibdev, port, index, gid) \
	ib_get_cached_gid(ibdev, port, index, gid, NULL)

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	ib_gid_to_network_type(gid_type, gid)

#define set_max_sge(props, rf)  do {    \
	((props)->max_send_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	((props)->max_recv_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags); \
	} while (0)

#define kc_set_ibdev_add_del_gid(ibdev)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll)

#define ib_umem_get(udata, addr, size, access, dmasync) \
	ib_umem_get(pd->uobject->context, addr, size, access, dmasync)

#define rdma_query_gid(ibdev, port, index, gid) \
	ib_get_cached_gid(ibdev, port, index, gid, NULL)
#endif /* RHEL_8_0 */

#ifdef RHEL_7_6
enum ib_port_phys_state {
	IB_PORT_PHYS_STATE_SLEEP = 1,
	IB_PORT_PHYS_STATE_POLLING = 2,
	IB_PORT_PHYS_STATE_DISABLED = 3,
	IB_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING = 4,
	IB_PORT_PHYS_STATE_LINK_UP = 5,
	IB_PORT_PHYS_STATE_LINK_ERROR_RECOVERY = 6,
	IB_PORT_PHYS_STATE_PHY_TEST = 7,
};

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

#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_1
#define ALLOC_UCONTEXT_VER_1
#define CREATE_AH_VER_1_2
#define CREATE_CQ_VER_1
#define CREATE_QP_VER_1
#define DEALLOC_PD_VER_1
#define DEALLOC_UCONTEXT_VER_1
#define DEREG_MR_VER_1
#define DESTROY_AH_VER_1
#define DESTROY_QP_VER_1
#define ETHER_COPY_VER_2
#define FOR_IFA
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define IB_GET_CACHED_GID
#define IB_IW_MANDATORY_AH_OP
#define IB_IW_PKEY
#define IB_UMEM_GET_V1
#define IW_PORT_IMMUTABLE_V1
#define IRDMA_ADD_DEL_GID
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_ALLOC_MW_VER_1
#define IRDMA_DESTROY_CQ_VER_1
#define IRDMA_DESTROY_SRQ_VER_1
#define MODIFY_PORT_V1
#define QUERY_GID_V1
#define QUERY_GID_ROCE_V1
#define QUERY_PKEY_V1
#define QUERY_PORT_V1
#define REREG_MR_VER_1
#define ROCE_PORT_IMMUTABLE_V1
#define SET_BEST_PAGE_SZ_V1
#define SET_ROCE_CM_INFO_VER_1
#define UVERBS_CMD_MASK
#define VMA_DATA
#define USE_KMAP
#define NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
#define SET_PCIDEV_PARENT

#define wait_queue_entry __wait_queue
#define kc_ib_register_device(device, name, dev) ib_register_device(device, NULL)
#define kc_typeq_ib_wr
#define kc_deref_sgid_attr(sgid_attr)        (sgid_attr.ndev)
#define kc_rdma_udata_to_drv_context(ibpd, udata) to_ucontext((ibpd)->uobject->context)
#define ib_device_put(dev)
#define kc_get_ucontext(udata) to_ucontext(context)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)

#define ib_alloc_device(irdma_device, ibdev) \
	((struct irdma_device *)ib_alloc_device(sizeof(struct irdma_device)))

#define rdma_query_gid(ibdev, port, index, gid) \
	ib_get_cached_gid(ibdev, port, index, gid, NULL)

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	ib_gid_to_network_type(gid_type, gid)

#define set_max_sge(props, rf)  \
	((props)->max_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags)

#define kc_set_props_ip_gid_caps(props) \
	((props)->port_cap_flags  |= IB_PORT_IP_BASED_GIDS)

#define kc_set_ibdev_add_del_gid(ibdev) do {   \
	ibdev->add_gid = irdma_add_gid;  \
	ibdev->del_gid = irdma_del_gid;  \
} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll)

#define ib_umem_get(udata, addr, size, access, dmasync) \
	ib_umem_get(pd->uobject->context, addr, size, access, dmasync)

#define rdma_query_gid(ibdev, port, index, gid) \
	ib_get_cached_gid(ibdev, port, index, gid, NULL)
#endif /* RHEL_7_6 */

#ifdef RHEL_7_5
enum ib_port_phys_state {
	IB_PORT_PHYS_STATE_SLEEP = 1,
	IB_PORT_PHYS_STATE_POLLING = 2,
	IB_PORT_PHYS_STATE_DISABLED = 3,
	IB_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING = 4,
	IB_PORT_PHYS_STATE_LINK_UP = 5,
	IB_PORT_PHYS_STATE_LINK_ERROR_RECOVERY = 6,
	IB_PORT_PHYS_STATE_PHY_TEST = 7,
};

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

#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_1
#define ALLOC_UCONTEXT_VER_1
#define CREATE_AH_VER_1_2
#define CREATE_CQ_VER_1
#define CREATE_QP_VER_1
#define DEALLOC_PD_VER_1
#define DEALLOC_UCONTEXT_VER_1
#define DEREG_MR_VER_1
#define DESTROY_AH_VER_1
#define DESTROY_QP_VER_1
#define ETHER_COPY_VER_2
#define FOR_IFA
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define IB_IW_MANDATORY_AH_OP
#define IB_IW_PKEY
#define IB_UMEM_GET_V1
#define IRDMA_ADD_DEL_GID
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_ALLOC_MW_VER_1
#define IRDMA_DESTROY_CQ_VER_1
#define IRDMA_DESTROY_SRQ_VER_1
#define IW_PORT_IMMUTABLE_V1
#define MODIFY_PORT_V1
#define QUERY_GID_V1
#define QUERY_GID_ROCE_V1
#define QUERY_PKEY_V1
#define QUERY_PORT_V1
#define REREG_MR_VER_1
#define ROCE_PORT_IMMUTABLE_V1
#define SET_BEST_PAGE_SZ_V1
#define SET_ROCE_CM_INFO_VER_1
#define UVERBS_CMD_MASK
#define VMA_DATA
#define USE_KMAP
#define NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
#define SET_PCIDEV_PARENT

#define wait_queue_entry __wait_queue
#define kc_ib_register_device(device, name, dev) ib_register_device(device, NULL)
#define kc_typeq_ib_wr
#define kc_deref_sgid_attr(sgid_attr)        (sgid_attr.ndev)
#define kc_rdma_udata_to_drv_context(ibpd, udata) to_ucontext((ibpd)->uobject->context)
#define ib_device_put(dev)
#define kc_get_ucontext(udata) to_ucontext(context)
#define set_ibdev_dma_device(ibdev, dev)
#define ah_attr_to_dmac(attr) ((attr).roce.dmac)

#define ib_alloc_device(irdma_device, ibdev) \
	((struct irdma_device *)ib_alloc_device(sizeof(struct irdma_device)))

#define rdma_query_gid(ibdev, port, index, gid) \
	ib_get_cached_gid(ibdev, port, index, gid, NULL)

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	ib_gid_to_network_type(gid_type, gid)

#define set_max_sge(props, rf)  \
	((props)->max_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags)

#define kc_set_props_ip_gid_caps(props) \
	((props)->port_cap_flags  |= IB_PORT_IP_BASED_GIDS)

#define kc_set_ibdev_add_del_gid(ibdev) do {   \
	ibdev->add_gid = irdma_add_gid;  \
	ibdev->del_gid = irdma_del_gid;  \
} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll)

#define ib_umem_get(udata, addr, size, access, dmasync) \
	ib_umem_get(pd->uobject->context, addr, size, access, dmasync)

#define rdma_query_gid(ibdev, port, index, gid) \
	ib_get_cached_gid(ibdev, port, index, gid, NULL)
#endif /* RHEL_7_5 */

#ifdef RHEL_7_4
enum ib_port_phys_state {
	IB_PORT_PHYS_STATE_SLEEP = 1,
	IB_PORT_PHYS_STATE_POLLING = 2,
	IB_PORT_PHYS_STATE_DISABLED = 3,
	IB_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING = 4,
	IB_PORT_PHYS_STATE_LINK_UP = 5,
	IB_PORT_PHYS_STATE_LINK_ERROR_RECOVERY = 6,
	IB_PORT_PHYS_STATE_PHY_TEST = 7,
};

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

#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_1
#define ALLOC_UCONTEXT_VER_1
#define CREATE_AH_VER_1_1
#define CREATE_CQ_VER_1
#define CREATE_QP_VER_1
#define DEALLOC_UCONTEXT_VER_1
#define DEALLOC_PD_VER_1
#define DEREG_MR_VER_1
#define DESTROY_AH_VER_1
#define DESTROY_QP_VER_1
#define ETHER_COPY_VER_1
#define FOR_IFA
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define IB_IW_PKEY
#define IB_IW_MANDATORY_AH_OP
#define IB_GET_CACHED_GID
#define IB_UMEM_GET_V1
#define IRDMA_ADD_DEL_GID
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_ALLOC_MW_VER_1
#define IRDMA_DESTROY_CQ_VER_1
#define IRDMA_DESTROY_SRQ_VER_1
#define IW_PORT_IMMUTABLE_V1
#define MODIFY_PORT_V1
#define QUERY_GID_V1
#define QUERY_GID_ROCE_V1
#define QUERY_PKEY_V1
#define QUERY_PORT_V1
#define REREG_MR_VER_1
#define ROCE_PORT_IMMUTABLE_V1
#define SET_BEST_PAGE_SZ_V1
#define SET_ROCE_CM_INFO_VER_1
#define UVERBS_CMD_MASK
#define VMA_DATA
#define USE_KMAP
#define NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
#define SET_PCIDEV_PARENT

#define wait_queue_entry __wait_queue
#define kc_ib_register_device(device, name, dev) ib_register_device(device, NULL)
#define kc_typeq_ib_wr
#define kc_deref_sgid_attr(sgid_attr)        (sgid_attr.ndev)
#define kc_rdma_udata_to_drv_context(ibpd, udata) to_ucontext((ibpd)->uobject->context)
#define ib_device_put(dev)
#define kc_get_ucontext(udata) to_ucontext(context)
#define rdma_ah_attr ib_ah_attr
#define ah_attr_to_dmac(attr) ((attr).dmac)

#define ib_alloc_device(irdma_device, ibdev) \
	((struct irdma_device *)ib_alloc_device(sizeof(struct irdma_device)))

#define rdma_query_gid(ibdev, port, index, gid) \
	ib_get_cached_gid(ibdev, port, index, gid, NULL)

#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	ib_gid_to_network_type(gid_type, gid)

#define set_max_sge(props, rf)  \
	((props)->max_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags)

#define kc_set_props_ip_gid_caps(props) \
	((props)->port_cap_flags  |= IB_PORT_IP_BASED_GIDS)

#define kc_set_ibdev_add_del_gid(ibdev) do {   \
	ibdev->add_gid = irdma_add_gid;  \
	ibdev->del_gid = irdma_del_gid;  \
} while (0)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll)

#define ib_umem_get(udata, addr, size, access, dmasync) \
	ib_umem_get(pd->uobject->context, addr, size, access, dmasync)

#define set_ibdev_dma_device(ibdev, dev)	\
	ibdev.dma_device = dev

#define rdma_query_gid(ibdev, port, index, gid) \
	ib_get_cached_gid(ibdev, port, index, gid, NULL)
#endif /* RHEL_7_4 */
#endif /* RHEL_KCOMPAT_H */
