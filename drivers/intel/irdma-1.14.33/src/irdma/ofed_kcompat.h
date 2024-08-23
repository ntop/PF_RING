/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2020 - 2023 Intel Corporation */
#ifndef OFED_KCOMPAT_H
#define OFED_KCOMPAT_H

#include <linux/sizes.h>
#if defined(RHEL_7_2)
#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/limits.h>
#include <linux/spinlock_types.h>
#include <uapi/rdma/ib_user_verbs.h>

#define kstrtobool strtobool

#define refcount_inc atomic_inc
#define refcount_read atomic_read
#define refcount_set atomic_set
#define refcount_dec atomic_dec
#define refcount_dec_and_test atomic_dec_and_test
#define refcount_sub_and_test atomic_sub_and_test
#define refcount_add atomic_add
#define refcount_inc_not_zero atomic_inc_not_zero
#define rdma_ah_attr ib_ah_attr
#define ah_attr_to_dmac(attr) ((attr).dmac)
#define ib_device_put(dev)

#define ib_alloc_device(irdma_device, ibdev) \
	((struct irdma_device *)ib_alloc_device(sizeof(struct irdma_device)))

#define set_ibdev_dma_device(ibdev, dev)        \
	ibdev.dma_device = dev

struct irdma_cm_node;
struct irdma_device;
struct irdma_pci_f;
struct irdma_qp;

enum ib_mtu ib_mtu_int_to_enum(int mtu);

enum ib_port_phys_state {
	IB_PORT_PHYS_STATE_SLEEP = 1,
	IB_PORT_PHYS_STATE_POLLING = 2,
	IB_PORT_PHYS_STATE_DISABLED = 3,
	IB_PORT_PHYS_STATE_PORT_CONFIGURATION_TRAINING = 4,
	IB_PORT_PHYS_STATE_LINK_UP = 5,
	IB_PORT_PHYS_STATE_LINK_ERROR_RECOVERY = 6,
	IB_PORT_PHYS_STATE_PHY_TEST = 7,
};

#define kc_set_props_ip_gid_caps(props) \
	((props)->port_cap_flags  |= IB_PORT_IP_BASED_GIDS)
#define kc_rdma_gid_attr_network_type(sgid_attr, gid_type, gid) \
	ib_gid_to_network_type(gid_type, gid)
#define kc_deref_sgid_attr(sgid_attr)        (sgid_attr.ndev)
#define rdma_query_gid(ibdev, port, index, gid) \
	ib_get_cached_gid(ibdev, port, index, gid, NULL)
#define kc_rdma_udata_to_drv_context(ibpd, udata) to_ucontext((ibpd)->uobject->context)
#define kc_get_ucontext(udata) to_ucontext(context)
#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll)
#define kc_typeq_ib_wr
#define kc_ib_register_device(device, name, dev) ib_register_device(device, NULL)
#define kc_set_ibdev_add_del_gid(ibdev) do {   \
	ibdev->add_gid = irdma_add_gid;  \
	ibdev->del_gid = irdma_del_gid;  \
} while (0)
#define wait_queue_entry __wait_queue

#define ALLOC_HW_STATS_V1
#define ALLOC_HW_STATS_STRUCT_V1
#define ALLOC_PD_VER_1
#define ALLOC_UCONTEXT_VER_1
#define COPY_USER_PGADDR_VER_1
#define CREATE_AH_VER_0
#define CREATE_CQ_VER_1
#define CREATE_QP_VER_1
#define DEALLOC_PD_VER_1
#define DEALLOC_UCONTEXT_VER_1
#define DEREG_MR_VER_1
#define DESTROY_AH_VER_1
#define DESTROY_QP_VER_1
#define ETHER_COPY_VER_1
#define FOR_IFA
#define IB_GET_ETH_SPEED
#define GET_HW_STATS_V1
#define GET_LINK_LAYER_V1
#define IB_GET_CACHED_GID
#define IB_IW_MANDATORY_AH_OP
#define IB_IW_PKEY
#define IB_MTU_CONVERSIONS
#define IB_UMEM_GET_V0
#define IB_USER_VERBS_EX_CMD_MODIFY_QP IB_USER_VERBS_CMD_MODIFY_QP
#define IRDMA_ADD_DEL_GID
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
#define SET_ROCE_CM_INFO_VER_1
#define UVERBS_CMD_MASK
#define VMA_DATA
#define USE_KMAP
#define NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
#define SET_PCIDEV_PARENT

enum ib_uverbs_ex_create_cq_flags {
	IB_UVERBS_CQ_FLAGS_TIMESTAMP_COMPLETION = 1 << 0,
	IB_UVERBS_CQ_FLAGS_IGNORE_OVERRUN = 1 << 1,
};

enum rdma_create_ah_flags {
	/* In a sleepable context */
	RDMA_CREATE_AH_SLEEPABLE = BIT(0),
};

#define set_max_sge(props, rf)  \
	((props)->max_sge = (rf)->sc_dev.hw_attrs.uk_attrs.max_hw_wq_frags)

#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof_field(TYPE, MEMBER))

#endif /* RHEL_7_2 */

#if defined(RHEL_7_2) || defined(RHEL_7_4)
#ifdef MODULE
#undef MODULE_DEVICE_TABLE
#define MODULE_DEVICE_TABLE(type, name)					\
extern typeof(name) __mod_##type##__##name##_device_table		\
  __attribute__ ((unused, alias(__stringify(name))))
#endif /* MODULE */
#endif /* RHEL_7_2 or RHEL_7_4 */

#if defined(RHEL_7_4) || defined(RHEL_7_5) || defined(RHEL_7_6)
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
#define COPY_USER_PGADDR_VER_1
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
#define IRDMA_ADD_DEL_GID
#define IRDMA_ALLOC_MR_VER_0
#define IRDMA_ALLOC_MW_VER_1
#define IRDMA_SET_DRIVER_ID
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

#define kc_set_ibdev_add_del_gid(ibdev)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll)

#define ib_umem_get(udata, addr, size, access, dmasync) \
	ib_umem_get(pd->uobject->context, addr, size, access, dmasync)

#endif /* RHEL_7_5 */

#if defined(RHEL_7_2) || defined(RHEL_7_4) || defined(SLES_12_SP_3)
static inline void addrconf_addr_eui48(u8 *deui, const char *const addr)
{
	memcpy(deui, addr, 3);
	deui[3] = 0xFF;
	deui[4] = 0xFE;
	memcpy(deui + 5, addr + 3, 3);
	deui[0] ^= 2;
}

#define ETHER_ADDR_TO_U64

#endif /* defined(RHEL_7_2) || defined(RHEL_7_4) || defined(SLES_12_SP_3) */
#if defined(SLES_15) || defined(SLES_12_SP_4) || defined(SLES_12_SP_3)
#ifdef SLES_12_SP_3
#define wait_queue_entry __wait_queue
#endif

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
#define COPY_USER_PGADDR_VER_1
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
#define IRDMA_ADD_DEL_GID
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

#define kc_set_ibdev_add_del_gid(ibdev)

#define kc_ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll) \
	ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll)

#define ib_umem_get(udata, addr, size, access, dmasync) \
	ib_umem_get(pd->uobject->context, addr, size, access, dmasync)
#endif /* SLES_15 */

#endif /* OFED_KCOMPAT_H */
