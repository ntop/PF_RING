// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2018 - 2024 Intel Corporation */
#include "main.h"

#define IRDMA_ROCE_UDP_ENCAP_VALID_PORT_MIN (0xC000)

static u16 kc_rdma_flow_label_to_udp_sport(u32 fl)
{
	u32 fl_low = fl & 0x03FFF;
	u32 fl_high = fl & 0xFC000;

	fl_low ^= fl_high >> 14;

	return (u16)(fl_low | IRDMA_ROCE_UDP_ENCAP_VALID_PORT_MIN);
}

#define IRDMA_GRH_FLOWLABEL_MASK (0x000FFFFF)

static u32 kc_rdma_calc_flow_label(u32 lqpn, u32 rqpn)
{
	u64 fl = (u64)lqpn * rqpn;

	fl ^= fl >> 20;
	fl ^= fl >> 40;

	return (u32)(fl & IRDMA_GRH_FLOWLABEL_MASK);
}

u16 kc_rdma_get_udp_sport(u32 fl, u32 lqpn, u32 rqpn)
{
	if (!fl)
		fl = kc_rdma_calc_flow_label(lqpn, rqpn);
	return kc_rdma_flow_label_to_udp_sport(fl);
}

struct dst_entry *irdma_get_fl6_dst(struct sockaddr_in6 *src_addr,
				    struct sockaddr_in6 *dst_addr)
{
	struct dst_entry *dst = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	struct flowi6 fl6 = {};

	fl6.daddr = dst_addr->sin6_addr;
	fl6.saddr = src_addr->sin6_addr;
	if (ipv6_addr_type(&fl6.daddr) & IPV6_ADDR_LINKLOCAL)
		fl6.flowi6_oif = dst_addr->sin6_scope_id;

	dst = ip6_route_output(&init_net, NULL, &fl6);
#else
	struct flowi fl = {};

	ipv6_addr_copy(&fl.fl6_dst, &dst_addr->sin6_addr);
	ipv6_addr_copy(&fl.fl6_src, &src_addr->sin6_addr);
	if (ipv6_addr_type(&fl.fl6_dst) & IPV6_ADDR_LINKLOCAL)
		fl.oif = dst_addr->sin6_scope_id;

	dst = ip6_route_output(&init_net, NULL, &fl);
#endif /* >= 2.6.39 */
	return dst;
}

struct neighbour *irdma_get_neigh_ipv6(struct dst_entry *dst,
				       struct sockaddr_in6 *dst_ipaddr)
{
	struct neighbour *neigh = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
	neigh = dst_neigh_lookup(dst, dst_ipaddr);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(3, 0, 0)
	neigh = dst->_neighbour;
#else
	neigh = dst->neighbour;
#endif /* >= 3.1.0 */
	return neigh;
}

struct neighbour *irdma_get_neigh_ipv4(struct rtable *rt, __be32 *dst_ipaddr)
{
	struct neighbour *neigh = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
	neigh = dst_neigh_lookup(&rt->dst, dst_ipaddr);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(3, 0, 0)
	neigh = rt->dst._neighbour;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
	neigh = rt->u.dst.neighbour;
#else
	neigh = rt->dst.neighbour;
#endif /* >= 3.1.0 */
	return neigh;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
struct net_device *irdma_netdev_master_upper_dev_get(struct net_device *netdev)
{
	return netdev->master;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)
struct rtable *irdma_ip_route_output(struct net *net, __be32 daddr,
				     __be32 saddr, u8 tos, int oif)
{
	struct flowi fl = {};
	struct rtable *rt;
	int ret;

	fl.nl_u.ip4_u.daddr = daddr;
	fl.nl_u.ip4_u.saddr = saddr;
	fl.oif = oif;
	ret = ip_route_output_key(net, &rt, &fl);
	return rt;
}

#endif /* 2.6.39 */
#endif /* 3.9.0 */
#ifdef IB_FW_VERSION_NAME_MAX
void irdma_get_dev_fw_str(struct ib_device *dev,
			  char *str)
{
	struct irdma_device *iwdev = to_iwdev(dev);

	snprintf(str, IB_FW_VERSION_NAME_MAX, "%u.%u",
		 irdma_fw_major_ver(&iwdev->rf->sc_dev),
		 irdma_fw_minor_ver(&iwdev->rf->sc_dev));
}
#else
void irdma_get_dev_fw_str(struct ib_device *dev,
			  char *str,
			  size_t str_len)
{
	struct irdma_device *iwdev = to_iwdev(dev);

	snprintf(str, str_len, "%u.%u",
		 irdma_fw_major_ver(&iwdev->rf->sc_dev),
		 irdma_fw_minor_ver(&iwdev->rf->sc_dev));
}
#endif /* IB_FW_VERSION_NAME_MAX */

#ifdef IRDMA_ADD_DEL_GID
int irdma_add_gid(struct ib_device *device,
		  u8 port_num,
		  unsigned int index,
		  const union ib_gid *gid,
		  const struct ib_gid_attr *attr,
		  void **context)
{
	return 0;
}

int irdma_del_gid(struct ib_device *device,
		  u8 port_num,
		  unsigned int index,
		  void **context)
{
	return 0;
}
#endif /* < 4.17.0 */

#ifdef IRDMA_ALLOC_MR_VER_1
/**
 * irdma_alloc_mr - register stag for fast memory registration
 * @pd: ibpd pointer
 * @mr_type: memory for stag registrion
 * @max_num_sg: man number of pages
 * @udata: user data
 */
struct ib_mr *irdma_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			     u32 max_num_sg, struct ib_udata *udata)
{
#elif defined(IRDMA_ALLOC_MR_VER_0)
/**
 * irdma_alloc_mr - register stag for fast memory registration
 * @pd: ibpd pointer
 * @mr_type: memory for stag registrion
 * @max_num_sg: man number of pages
 */
struct ib_mr *irdma_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			     u32 max_num_sg)
{
#endif
	struct irdma_device *iwdev = to_iwdev(pd->device);
	struct irdma_pble_alloc *palloc;
	struct irdma_pbl *iwpbl;
	struct irdma_mr *iwmr;
	int status;
	u32 stag;
	int err_code = -ENOMEM;

	iwmr = kzalloc(sizeof(*iwmr), GFP_KERNEL);
	if (!iwmr)
		return ERR_PTR(-ENOMEM);

	stag = irdma_create_stag(iwdev);
	if (!stag) {
		err_code = -ENOMEM;
		goto err;
	}

	iwmr->stag = stag;
	iwmr->ibmr.rkey = stag;
	iwmr->ibmr.lkey = stag;
	iwmr->ibmr.pd = pd;
	iwmr->ibmr.device = pd->device;
	iwpbl = &iwmr->iwpbl;
	iwpbl->iwmr = iwmr;
	iwmr->type = IRDMA_MEMREG_TYPE_MEM;
	palloc = &iwpbl->pble_alloc;
	iwmr->page_cnt = max_num_sg;
	/* Assume system PAGE_SIZE as the sg page sizes are unknown. */
	iwmr->len = max_num_sg * PAGE_SIZE;
	status = irdma_get_pble(iwdev->rf->pble_rsrc, palloc, iwmr->page_cnt,
				false);
	if (status)
		goto err_get_pble;

	err_code = irdma_hw_alloc_stag(iwdev, iwmr);
	if (err_code)
		goto err_alloc_stag;

	iwpbl->pbl_allocated = true;

	return &iwmr->ibmr;
err_alloc_stag:
	irdma_free_pble(iwdev->rf->pble_rsrc, palloc);
err_get_pble:
	irdma_free_stag(iwdev, stag);
err:
	kfree(iwmr);

	return ERR_PTR(err_code);
}

#define IRDMA_ALLOC_UCTX_MIN_REQ_LEN offsetofend(struct irdma_alloc_ucontext_req, rsvd8)
#define IRDMA_ALLOC_UCTX_MIN_RESP_LEN offsetofend(struct irdma_alloc_ucontext_resp, rsvd)
#ifdef ALLOC_UCONTEXT_VER_2
/**
 * irdma_alloc_ucontext - Allocate the user context data structure
 * @uctx: context
 * @udata: user data
 *
 * This keeps track of all objects associated with a particular
 * user-mode client.
 */
int irdma_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata)
{
	struct ib_device *ibdev = uctx->device;
	struct irdma_device *iwdev = to_iwdev(ibdev);
	struct irdma_alloc_ucontext_req req = {};
	struct irdma_alloc_ucontext_resp uresp = {};
	struct irdma_ucontext *ucontext = to_ucontext(uctx);
	struct irdma_uk_attrs *uk_attrs = &iwdev->rf->sc_dev.hw_attrs.uk_attrs;

	if (udata->inlen < IRDMA_ALLOC_UCTX_MIN_REQ_LEN ||
	    udata->outlen < IRDMA_ALLOC_UCTX_MIN_RESP_LEN)
		return -EINVAL;

	if (ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen)))
		return -EINVAL;

	if (req.userspace_ver < 4 || req.userspace_ver > IRDMA_ABI_VER)
		goto ver_error;

	ucontext->iwdev = iwdev;
	ucontext->abi_ver = req.userspace_ver;

	if (!(req.comp_mask & IRDMA_SUPPORT_WQE_FORMAT_V2) &&
	    uk_attrs->hw_rev >= IRDMA_GEN_3)
		return -EOPNOTSUPP;

	if (req.comp_mask & IRDMA_ALLOC_UCTX_USE_RAW_ATTR)
		ucontext->use_raw_attrs = true;

	/* GEN_1 support for libi40iw */
	if (udata->outlen == IRDMA_ALLOC_UCTX_MIN_RESP_LEN) {
		if (uk_attrs->hw_rev != IRDMA_GEN_1)
			return -EOPNOTSUPP;

		ucontext->legacy_mode = true;
		uresp.max_qps = iwdev->rf->max_qp;
		uresp.max_pds = iwdev->rf->sc_dev.hw_attrs.max_hw_pds;
		uresp.wq_size = iwdev->rf->sc_dev.hw_attrs.max_qp_wr * 2;
		uresp.kernel_ver = req.userspace_ver;
		if (ib_copy_to_udata(udata, &uresp, min(sizeof(uresp), udata->outlen)))
			return -EFAULT;
	} else {
		u64 bar_off;

		uresp.kernel_ver = IRDMA_ABI_VER;
		uresp.feature_flags = uk_attrs->feature_flags;
		uresp.max_hw_wq_frags = uk_attrs->max_hw_wq_frags;
		uresp.max_hw_read_sges = uk_attrs->max_hw_read_sges;
		uresp.max_hw_inline = uk_attrs->max_hw_inline;
		uresp.max_hw_rq_quanta = uk_attrs->max_hw_rq_quanta;
		uresp.max_hw_wq_quanta = uk_attrs->max_hw_wq_quanta;
		uresp.max_hw_sq_chunk = uk_attrs->max_hw_sq_chunk;
		uresp.max_hw_cq_size = uk_attrs->max_hw_cq_size;
		uresp.min_hw_cq_size = uk_attrs->min_hw_cq_size;
		uresp.hw_rev = uk_attrs->hw_rev;
		uresp.comp_mask |= IRDMA_ALLOC_UCTX_USE_RAW_ATTR;
		uresp.min_hw_wq_size = uk_attrs->min_hw_wq_size;
		uresp.comp_mask |= IRDMA_ALLOC_UCTX_MIN_HW_WQ_SIZE;
		uresp.max_hw_srq_quanta = uk_attrs->max_hw_srq_quanta;
		uresp.comp_mask |= IRDMA_ALLOC_UCTX_MAX_HW_SRQ_QUANTA;
		uresp.max_hw_push_len = uk_attrs->max_hw_push_len;
		uresp.comp_mask |= IRDMA_SUPPORT_MAX_HW_PUSH_LEN;

		bar_off =
		    (uintptr_t)iwdev->rf->sc_dev.hw_regs[IRDMA_DB_ADDR_OFFSET];
#ifdef RDMA_MMAP_DB_SUPPORT
		ucontext->db_mmap_entry =
			irdma_user_mmap_entry_insert(ucontext, bar_off,
						     IRDMA_MMAP_IO_NC,
						     &uresp.db_mmap_key);
#else
		spin_lock_init(&ucontext->mmap_tbl_lock);
		ucontext->db_mmap_entry =
			irdma_user_mmap_entry_add_hash(ucontext, bar_off,
						       IRDMA_MMAP_IO_NC,
						       &uresp.db_mmap_key);
#endif /* RDMA_MMAP_DB_SUPPORT */
		if (!ucontext->db_mmap_entry) {
#ifndef RDMA_MMAP_DB_SUPPORT
#endif
			return -ENOMEM;
		}

		if (ib_copy_to_udata(udata, &uresp,
				     min(sizeof(uresp), udata->outlen))) {
#ifdef RDMA_MMAP_DB_SUPPORT
			rdma_user_mmap_entry_remove(ucontext->db_mmap_entry);
#else
			irdma_user_mmap_entry_del_hash(ucontext->db_mmap_entry);
#endif
			return -EFAULT;
		}
	}

	INIT_LIST_HEAD(&ucontext->cq_reg_mem_list);
	spin_lock_init(&ucontext->cq_reg_mem_list_lock);
	INIT_LIST_HEAD(&ucontext->qp_reg_mem_list);
	spin_lock_init(&ucontext->qp_reg_mem_list_lock);
	INIT_LIST_HEAD(&ucontext->srq_reg_mem_list);
	spin_lock_init(&ucontext->srq_reg_mem_list_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
	INIT_LIST_HEAD(&ucontext->vma_list);
	mutex_init(&ucontext->vma_list_mutex);
#endif

#ifdef CONFIG_DEBUG_FS
	irdma_dbg_save_ucontext(iwdev, ucontext);
#endif
	return 0;

ver_error:
	ibdev_err(&iwdev->ibdev,
		  "Invalid userspace driver version detected. Detected version %d, should be %d\n",
		  req.userspace_ver, IRDMA_ABI_VER);
	return -EINVAL;
}
#endif

#ifdef ALLOC_UCONTEXT_VER_1
/**
 * irdma_alloc_ucontext - Allocate the user context data structure
 * @ibdev: ib device pointer
 * @udata: user data
 *
 * This keeps track of all objects associated with a particular
 * user-mode client.
 */
struct ib_ucontext *irdma_alloc_ucontext(struct ib_device *ibdev, struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(ibdev);
	struct irdma_alloc_ucontext_req req = {};
	struct irdma_alloc_ucontext_resp uresp = {};
	struct irdma_ucontext *ucontext;
	struct irdma_uk_attrs *uk_attrs = &iwdev->rf->sc_dev.hw_attrs.uk_attrs;

	if (udata->inlen < IRDMA_ALLOC_UCTX_MIN_REQ_LEN ||
	    udata->outlen < IRDMA_ALLOC_UCTX_MIN_RESP_LEN)
		return ERR_PTR(-EINVAL);

	if (ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen)))
		return ERR_PTR(-EINVAL);

	if (req.userspace_ver < 4 || req.userspace_ver > IRDMA_ABI_VER)
		goto ver_error;

	if (!(req.comp_mask & IRDMA_SUPPORT_WQE_FORMAT_V2) &&
	    uk_attrs->hw_rev >= IRDMA_GEN_3)
		return ERR_PTR(-EOPNOTSUPP);

	ucontext = kzalloc(sizeof(*ucontext), GFP_KERNEL);
	if (!ucontext)
		return ERR_PTR(-ENOMEM);

	ucontext->iwdev = iwdev;
	ucontext->abi_ver = req.userspace_ver;

	if (req.comp_mask & IRDMA_ALLOC_UCTX_USE_RAW_ATTR)
		ucontext->use_raw_attrs = true;

	/* GEN_1 legacy support with libi40iw */
	if (udata->outlen == IRDMA_ALLOC_UCTX_MIN_RESP_LEN) {
		if (uk_attrs->hw_rev != IRDMA_GEN_1) {
			kfree(ucontext);
			return ERR_PTR(-EOPNOTSUPP);
		}

		ucontext->legacy_mode = true;
		uresp.max_qps = iwdev->rf->max_qp;
		uresp.max_pds = iwdev->rf->sc_dev.hw_attrs.max_hw_pds;
		uresp.wq_size = iwdev->rf->sc_dev.hw_attrs.max_qp_wr * 2;
		uresp.kernel_ver = req.userspace_ver;
		if (ib_copy_to_udata(udata, &uresp, min(sizeof(uresp), udata->outlen))) {
			kfree(ucontext);
			return ERR_PTR(-EFAULT);
		}
	} else {
		u64 bar_off;

		uresp.kernel_ver = IRDMA_ABI_VER;
		uresp.feature_flags = uk_attrs->feature_flags;
		uresp.max_hw_wq_frags = uk_attrs->max_hw_wq_frags;
		uresp.max_hw_read_sges = uk_attrs->max_hw_read_sges;
		uresp.max_hw_inline = uk_attrs->max_hw_inline;
		uresp.max_hw_rq_quanta = uk_attrs->max_hw_rq_quanta;
		uresp.max_hw_wq_quanta = uk_attrs->max_hw_wq_quanta;
		uresp.max_hw_sq_chunk = uk_attrs->max_hw_sq_chunk;
		uresp.max_hw_cq_size = uk_attrs->max_hw_cq_size;
		uresp.min_hw_cq_size = uk_attrs->min_hw_cq_size;
		uresp.hw_rev = uk_attrs->hw_rev;
		uresp.comp_mask |= IRDMA_ALLOC_UCTX_USE_RAW_ATTR;
		uresp.min_hw_wq_size = uk_attrs->min_hw_wq_size;
		uresp.comp_mask |= IRDMA_ALLOC_UCTX_MIN_HW_WQ_SIZE;
		uresp.max_hw_srq_quanta = uk_attrs->max_hw_srq_quanta;
		uresp.comp_mask |= IRDMA_ALLOC_UCTX_MAX_HW_SRQ_QUANTA;
		uresp.max_hw_push_len = uk_attrs->max_hw_push_len;
		uresp.comp_mask |= IRDMA_SUPPORT_MAX_HW_PUSH_LEN;

		bar_off =
		(uintptr_t)iwdev->rf->sc_dev.hw_regs[IRDMA_DB_ADDR_OFFSET];

#ifdef RDMA_MMAP_DB_SUPPORT
		ucontext->db_mmap_entry =
		    irdma_user_mmap_entry_insert(ucontext, bar_off,
						 IRDMA_MMAP_IO_NC,
						 &uresp.db_mmap_key);

#else
		spin_lock_init(&ucontext->mmap_tbl_lock);
		ucontext->db_mmap_entry =
		    irdma_user_mmap_entry_add_hash(ucontext, bar_off,
						   IRDMA_MMAP_IO_NC,
						   &uresp.db_mmap_key);
#endif /* RDMA_MMAP_DB_SUPPORT */
		if (!ucontext->db_mmap_entry) {
#ifndef RDMA_MMAP_DB_SUPPORT
#endif
			kfree(ucontext);
			return ERR_PTR(-ENOMEM);
		}

		if (ib_copy_to_udata(udata, &uresp,
				     min(sizeof(uresp), udata->outlen))) {
#ifdef RDMA_MMAP_DB_SUPPORT
			rdma_user_mmap_entry_remove(ucontext->db_mmap_entry);
#else
			irdma_user_mmap_entry_del_hash(ucontext->db_mmap_entry);
#endif
			kfree(ucontext);
			return ERR_PTR(-EFAULT);
		}
	}

	INIT_LIST_HEAD(&ucontext->cq_reg_mem_list);
	spin_lock_init(&ucontext->cq_reg_mem_list_lock);
	INIT_LIST_HEAD(&ucontext->qp_reg_mem_list);
	spin_lock_init(&ucontext->qp_reg_mem_list_lock);
	INIT_LIST_HEAD(&ucontext->srq_reg_mem_list);
	spin_lock_init(&ucontext->srq_reg_mem_list_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
	INIT_LIST_HEAD(&ucontext->vma_list);
	mutex_init(&ucontext->vma_list_mutex);
#endif

#ifdef CONFIG_DEBUG_FS
	irdma_dbg_save_ucontext(iwdev, ucontext);
#endif
	return &ucontext->ibucontext;

ver_error:
	ibdev_err(&iwdev->ibdev,
		  "Invalid userspace driver version detected. Detected version %d, should be %d\n",
		  req.userspace_ver, IRDMA_ABI_VER);
	return ERR_PTR(-EINVAL);
}
#endif

#ifdef DEALLOC_UCONTEXT_VER_2
/**
 * irdma_dealloc_ucontext - deallocate the user context data structure
 * @context: user context created during alloc
 */
void irdma_dealloc_ucontext(struct ib_ucontext *context)
{
	struct irdma_ucontext *ucontext = to_ucontext(context);

#ifdef RDMA_MMAP_DB_SUPPORT
	rdma_user_mmap_entry_remove(ucontext->db_mmap_entry);
#else
	irdma_user_mmap_entry_del_hash(ucontext->db_mmap_entry);
#endif
#ifdef CONFIG_DEBUG_FS
	irdma_dbg_free_ucontext(ucontext);
#endif

	return;
}
#endif

#ifdef DEALLOC_UCONTEXT_VER_1
/**
 * irdma_dealloc_ucontext - deallocate the user context data structure
 * @context: user context created during alloc
 */
int irdma_dealloc_ucontext(struct ib_ucontext *context)
{
	struct irdma_ucontext *ucontext = to_ucontext(context);

#ifdef RDMA_MMAP_DB_SUPPORT
	rdma_user_mmap_entry_remove(ucontext->db_mmap_entry);
#else
	irdma_user_mmap_entry_del_hash(ucontext->db_mmap_entry);
#endif
#ifdef CONFIG_DEBUG_FS
	irdma_dbg_free_ucontext(ucontext);
#endif
	kfree(ucontext);

	return 0;
}
#endif

#define IRDMA_ALLOC_PD_MIN_RESP_LEN offsetofend(struct irdma_alloc_pd_resp, rsvd)
#ifdef ALLOC_PD_VER_3
/**
 * irdma_alloc_pd - allocate protection domain
 * @pd: protection domain
 * @udata: user data
 */
int irdma_alloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct irdma_pd *iwpd = to_iwpd(pd);
	struct irdma_device *iwdev = to_iwdev(pd->device);
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
	struct irdma_pci_f *rf = iwdev->rf;
	struct irdma_alloc_pd_resp uresp = {};
	struct irdma_sc_pd *sc_pd;
	u32 pd_id = 0;
	int err;

	if (udata && udata->outlen < IRDMA_ALLOC_PD_MIN_RESP_LEN)
		return -EINVAL;

	err = irdma_alloc_rsrc(rf, rf->allocated_pds, rf->max_pd, &pd_id,
			       &rf->next_pd);
	if (err)
		return err;

	iwpd->push_idx = IRDMA_INVALID_PUSH_PAGE_INDEX;
	mutex_init(&iwpd->push_alloc_mutex);

	sc_pd = &iwpd->sc_pd;
	if (udata) {
		struct irdma_ucontext *ucontext =
			rdma_udata_to_drv_context(udata, struct irdma_ucontext,
						  ibucontext);

		irdma_sc_pd_init(dev, sc_pd, pd_id, ucontext->abi_ver);
		uresp.pd_id = pd_id;
		if (ib_copy_to_udata(udata, &uresp,
				     min(sizeof(uresp), udata->outlen))) {
			err = -EFAULT;
			goto error;
		}
	} else {
		irdma_sc_pd_init(dev, sc_pd, pd_id, IRDMA_ABI_VER);
	}

	return 0;

error:

	irdma_free_rsrc(rf, rf->allocated_pds, pd_id);

	return err;
}
#endif

#ifdef ALLOC_PD_VER_2
/**
 * irdma_alloc_pd - allocate protection domain
 * @pd: protection domain
 * @context: user context
 * @udata: user data
 */
int irdma_alloc_pd(struct ib_pd *pd, struct ib_ucontext *context, struct ib_udata *udata)
{
	struct irdma_pd *iwpd = to_iwpd(pd);
	struct irdma_device *iwdev = to_iwdev(pd->device);
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
	struct irdma_pci_f *rf = iwdev->rf;
	struct irdma_alloc_pd_resp uresp = {};
	struct irdma_sc_pd *sc_pd;
	u32 pd_id = 0;
	int err;

	if (udata && udata->outlen < IRDMA_ALLOC_PD_MIN_RESP_LEN)
		return -EINVAL;

	err = irdma_alloc_rsrc(rf, rf->allocated_pds, rf->max_pd, &pd_id,
			       &rf->next_pd);
	if (err)
		return err;

	iwpd->push_idx = IRDMA_INVALID_PUSH_PAGE_INDEX;
	mutex_init(&iwpd->push_alloc_mutex);

	sc_pd = &iwpd->sc_pd;
	if (udata) {
		struct irdma_ucontext *ucontext = to_ucontext(context);

		irdma_sc_pd_init(dev, sc_pd, pd_id, ucontext->abi_ver);
		uresp.pd_id = pd_id;
		if (ib_copy_to_udata(udata, &uresp,
				     min(sizeof(uresp), udata->outlen))) {
			err = -EFAULT;
			goto error;
		}
	} else {
		irdma_sc_pd_init(dev, sc_pd, pd_id, IRDMA_ABI_VER);
	}

	return 0;

error:

	irdma_free_rsrc(rf, rf->allocated_pds, pd_id);

	return err;
}
#endif

#ifdef ALLOC_PD_VER_1
/**
 * irdma_alloc_pd - allocate protection domain
 * @ibdev: IB device
 * @context: user context
 * @udata: user data
 */
struct ib_pd *irdma_alloc_pd(struct ib_device *ibdev, struct ib_ucontext *context, struct ib_udata *udata)
{
	struct irdma_pd *iwpd;
	struct irdma_device *iwdev = to_iwdev(ibdev);
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
	struct irdma_pci_f *rf = iwdev->rf;
	struct irdma_alloc_pd_resp uresp = {};
	struct irdma_sc_pd *sc_pd;
	u32 pd_id = 0;
	int err;

	err = irdma_alloc_rsrc(rf, rf->allocated_pds, rf->max_pd, &pd_id,
			       &rf->next_pd);
	if (err)
		return ERR_PTR(err);

	iwpd = kzalloc(sizeof(*iwpd), GFP_KERNEL);
	if (!iwpd) {
		err = -ENOMEM;
		goto free_res;
	}

	iwpd->push_idx = IRDMA_INVALID_PUSH_PAGE_INDEX;
	mutex_init(&iwpd->push_alloc_mutex);

	sc_pd = &iwpd->sc_pd;
	if (udata) {
		struct irdma_ucontext *ucontext = to_ucontext(context);

		irdma_sc_pd_init(dev, sc_pd, pd_id, ucontext->abi_ver);
		uresp.pd_id = pd_id;
		if (ib_copy_to_udata(udata, &uresp,
				     min(sizeof(uresp), udata->outlen))) {
			err = -EFAULT;
			goto error;
		}
	} else {
		irdma_sc_pd_init(dev, sc_pd, pd_id, IRDMA_ABI_VER);
	}

	return &iwpd->ibpd;

error:
	kfree(iwpd);
free_res:

	irdma_free_rsrc(rf, rf->allocated_pds, pd_id);

	return ERR_PTR(err);
}

#endif

#ifdef DEALLOC_PD_VER_4
int irdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct irdma_pd *iwpd = to_iwpd(ibpd);
	struct irdma_device *iwdev = to_iwdev(ibpd->device);

	irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_pds, iwpd->sc_pd.pd_id);
	return 0;
}

#endif

#ifdef DEALLOC_PD_VER_3
void irdma_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct irdma_pd *iwpd = to_iwpd(ibpd);
	struct irdma_device *iwdev = to_iwdev(ibpd->device);

	irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_pds, iwpd->sc_pd.pd_id);
}

#endif

#ifdef DEALLOC_PD_VER_2
void irdma_dealloc_pd(struct ib_pd *ibpd)
{
	struct irdma_pd *iwpd = to_iwpd(ibpd);
	struct irdma_device *iwdev = to_iwdev(ibpd->device);

	irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_pds, iwpd->sc_pd.pd_id);
}
#endif

#ifdef DEALLOC_PD_VER_1
int irdma_dealloc_pd(struct ib_pd *ibpd)
{
	struct irdma_pd *iwpd = to_iwpd(ibpd);
	struct irdma_device *iwdev = to_iwdev(ibpd->device);

	irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_pds, iwpd->sc_pd.pd_id);
	kfree(iwpd);
	return 0;
}
#endif

static void irdma_fill_ah_info(struct irdma_ah_info *ah_info,
			       const struct ib_gid_attr *sgid_attr,
			       union irdma_sockaddr *sgid_addr,
			       union irdma_sockaddr *dgid_addr,
			       u8 *dmac, u8 net_type)
{
	if (net_type == RDMA_NETWORK_IPV4) {
		ah_info->ipv4_valid = true;
		ah_info->dest_ip_addr[0] =
				ntohl(dgid_addr->saddr_in.sin_addr.s_addr);
		ah_info->src_ip_addr[0] =
				ntohl(sgid_addr->saddr_in.sin_addr.s_addr);
		ah_info->do_lpbk = irdma_ipv4_is_lpb(ah_info->src_ip_addr[0],
						     ah_info->dest_ip_addr[0]);
		if (ipv4_is_multicast(dgid_addr->saddr_in.sin_addr.s_addr)) {
			irdma_mcast_mac_v4(ah_info->dest_ip_addr, dmac);
		}
	} else {
		irdma_copy_ip_ntohl(ah_info->dest_ip_addr,
				    dgid_addr->saddr_in6.sin6_addr.in6_u.u6_addr32);
		irdma_copy_ip_ntohl(ah_info->src_ip_addr,
				    sgid_addr->saddr_in6.sin6_addr.in6_u.u6_addr32);
		ah_info->do_lpbk = irdma_ipv6_is_lpb(ah_info->src_ip_addr,
						     ah_info->dest_ip_addr);
		if (rdma_is_multicast_addr(&dgid_addr->saddr_in6.sin6_addr)) {
			irdma_mcast_mac_v6(ah_info->dest_ip_addr, dmac);
		}
	}
}

#ifdef SET_ROCE_CM_INFO_VER_3
static u8 irdma_roce_get_vlan_prio(struct net_device __rcu *ndev_rcu, u8 prio)
{
	struct net_device *ndev;

	rcu_read_lock();
	ndev = rcu_dereference(ndev_rcu);
	if (!ndev)
		goto exit;
	if (is_vlan_dev(ndev)) {
		u16 vlan_qos = vlan_dev_get_egress_qos_mask(ndev, prio);

		prio = (vlan_qos & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
	}
exit:
	rcu_read_unlock();
	return prio;
}
#else
static inline u8 irdma_roce_get_vlan_prio(struct net_device *ndev, u8 prio)
{
	if (ndev && is_vlan_dev(ndev)) {
		u16 vprio = vlan_dev_get_egress_qos_mask(ndev, prio);

		return (vprio & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
	}
	return prio;
}

#endif
static int irdma_create_ah_vlan_tag(struct irdma_device *iwdev,
				    struct irdma_ah_info *ah_info,
				    const struct ib_gid_attr *sgid_attr,
				    u8 *dmac)
{
	u16 vlan_prio;

#if !defined(CREATE_AH_VER_2) && !defined(CREATE_AH_VER_5)
	if (sgid_attr->ndev && is_vlan_dev(sgid_attr->ndev))
		ah_info->vlan_tag = vlan_dev_vlan_id(sgid_attr->ndev);
	else
		ah_info->vlan_tag = VLAN_N_VID;

#endif
	ah_info->dst_arpindex = irdma_add_arp(iwdev->rf,
					      ah_info->dest_ip_addr, dmac);

	if (ah_info->dst_arpindex == -1)
		return -EINVAL;

	if (ah_info->vlan_tag >= VLAN_N_VID && iwdev->dcb_vlan_mode)
		ah_info->vlan_tag = 0;

	if (ah_info->vlan_tag < VLAN_N_VID) {
		ah_info->insert_vlan_tag = true;
		vlan_prio = (u16)irdma_roce_get_vlan_prio(sgid_attr->ndev,
							  rt_tos2priority(ah_info->tc_tos));
		ah_info->vlan_tag |= vlan_prio << VLAN_PRIO_SHIFT;
	}
#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	if (iwdev->roce_dcqcn_en || iwdev->roce_dctcp_en) {
		ah_info->tc_tos &= ~ECN_CODE_PT_MASK;
		ah_info->tc_tos |= ECN_CODE_PT_VAL;
	}
#else
	if (iwdev->roce_dcqcn_en) {
		ah_info->tc_tos &= ~ECN_CODE_PT_MASK;
		ah_info->tc_tos |= ECN_CODE_PT_VAL;
	}
#endif

	return 0;
}

static int irdma_create_ah_wait(struct irdma_pci_f *rf,
				struct irdma_sc_ah *sc_ah, bool sleep)
{
	int ret;

	if (!sleep) {
		int cnt = rf->sc_dev.hw_attrs.max_cqp_compl_wait_time_ms *
			  CQP_TIMEOUT_THRESHOLD;
		struct irdma_cqp_request *cqp_request =
			sc_ah->ah_info.cqp_request;

		do {
			irdma_cqp_ce_handler(rf, &rf->ccq.sc_cq);
			mdelay(1);
		} while (!READ_ONCE(cqp_request->request_done) && --cnt);

		if (cnt && !cqp_request->compl_info.op_ret_val) {
			irdma_put_cqp_request(&rf->cqp, cqp_request);
			sc_ah->ah_info.ah_valid = true;
		} else {
			ret = !cnt ? -ETIMEDOUT : -EINVAL;
			ibdev_err(&rf->iwdev->ibdev, "CQP create AH error ret = %d opt_ret_val = %d",
				  ret, cqp_request->compl_info.op_ret_val);
			irdma_put_cqp_request(&rf->cqp, cqp_request);
			if (!cnt && !rf->reset) {
				rf->reset = true;
				rf->gen_ops.request_reset(rf);
			}
			return ret;
		}
	}

	return 0;
}

#ifndef CREATE_AH_VER_0
static bool irdma_ah_exists(struct irdma_device *iwdev,
			    struct irdma_ah *new_ah)
{
	struct irdma_ah *ah;
	u32 save_ah_id = new_ah->sc_ah.ah_info.ah_idx;
	u32 key = new_ah->sc_ah.ah_info.dest_ip_addr[0] ^
		  new_ah->sc_ah.ah_info.dest_ip_addr[1] ^
		  new_ah->sc_ah.ah_info.dest_ip_addr[2] ^
		  new_ah->sc_ah.ah_info.dest_ip_addr[3];

	hash_for_each_possible(iwdev->ah_hash_tbl, ah, list, key) {
		/* Set ah_id the same so memcp can work */
		new_ah->sc_ah.ah_info.ah_idx = ah->sc_ah.ah_info.ah_idx;
		if (!memcmp(&ah->sc_ah.ah_info, &new_ah->sc_ah.ah_info,
			    sizeof(ah->sc_ah.ah_info))) {
			refcount_inc(&ah->refcnt);
			new_ah->parent_ah = ah;
			return true;
		}
	}
	new_ah->sc_ah.ah_info.ah_idx = save_ah_id;
	/* Add new AH to list */
	ah = kmemdup(new_ah, sizeof(*new_ah), GFP_KERNEL);
	if (!ah)
		return false;
	new_ah->parent_ah = ah;
	hash_add(iwdev->ah_hash_tbl, &ah->list, key);

	iwdev->ah_list_cnt++;
	if (iwdev->ah_list_cnt > iwdev->ah_list_hwm)
		iwdev->ah_list_hwm = iwdev->ah_list_cnt;
	refcount_set(&ah->refcnt, 1);

	return false;
}
#endif

#define IRDMA_CREATE_AH_MIN_RESP_LEN offsetofend(struct irdma_create_ah_resp, rsvd)
#if defined(CREATE_AH_VER_3) || defined(CREATE_AH_VER_4)
/**
 * irdma_create_ah_sleepable - create address handle
 * @ibpd: Protection Domain for AH
 * @attr: address handle attributes
 * @sleep: wait for creation
 * @udata: user data
 *
 * returns a pointer to an address handle
 */
static struct ib_ah *irdma_create_ah_sleepable(struct ib_pd *ibpd,
					       struct rdma_ah_attr *attr,
					       bool sleep,
					       struct ib_udata *udata)
{
	struct irdma_pd *pd = to_iwpd(ibpd);
	struct irdma_device *iwdev = to_iwdev(ibpd->device);
	struct irdma_ah *ah;
	const struct ib_gid_attr *sgid_attr;
	struct irdma_pci_f *rf = iwdev->rf;
	struct irdma_sc_ah *sc_ah;
	u32 ah_id = 0;
	struct irdma_ah_info *ah_info;
	struct irdma_create_ah_resp uresp = {};
	union irdma_sockaddr sgid_addr, dgid_addr;
	int err;
	u8 dmac[ETH_ALEN];

	if (udata && udata->outlen < IRDMA_CREATE_AH_MIN_RESP_LEN)
		return ERR_PTR(-EINVAL);

	err = irdma_alloc_rsrc(rf, rf->allocated_ahs,
			       rf->max_ah, &ah_id, &rf->next_ah);
	if (err)
		return ERR_PTR(err);

	ah = kzalloc(sizeof(*ah), GFP_ATOMIC);
	if (!ah) {
		irdma_free_rsrc(rf, rf->allocated_ahs, ah_id);
		return ERR_PTR(-ENOMEM);
	}

	ah->pd = pd;
	sc_ah = &ah->sc_ah;
	sc_ah->ah_info.ah_idx = ah_id;
	sc_ah->ah_info.vsi = &iwdev->vsi;
	irdma_sc_init_ah(&rf->sc_dev, sc_ah);
	ah->sgid_index = attr->grh.sgid_index;
	memcpy(&ah->dgid, &attr->grh.dgid, sizeof(ah->dgid));
	sgid_attr = attr->grh.sgid_attr;
	rdma_gid2ip((struct sockaddr *)&sgid_addr, &sgid_attr->gid);
	rdma_gid2ip((struct sockaddr *)&dgid_addr, &attr->grh.dgid);
	ah->av.attrs = *attr;
	ah->av.net_type = kc_rdma_gid_attr_network_type(sgid_attr,
							sgid_attr.gid_type,
							&sgid);
	ah_info = &sc_ah->ah_info;
	ah_info->ah_idx = ah_id;
	ah_info->pd_idx = pd->sc_pd.pd_id;
	ether_addr_copy(ah_info->mac_addr, iwdev->netdev->dev_addr);
	if (attr->ah_flags & IB_AH_GRH) {
		ah_info->flow_label = attr->grh.flow_label;
		ah_info->hop_ttl = attr->grh.hop_limit;
		ah_info->tc_tos = attr->grh.traffic_class;
	}
	ether_addr_copy(dmac, attr->roce.dmac);

	irdma_fill_ah_info(ah_info, sgid_attr, &sgid_addr, &dgid_addr,
			   dmac, ah->av.net_type);
	err = irdma_create_ah_vlan_tag(iwdev, ah_info, sgid_attr, dmac);
	if (err)
		goto err_gid_l2;

	if (sleep) {
		mutex_lock(&iwdev->ah_tbl_lock);
		if (irdma_ah_exists(iwdev, ah)) {
			irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs,
					ah_id);
			ah_id = 0;
#ifdef CONFIG_DEBUG_FS
			iwdev->ah_reused++;
#endif
			goto exit;
		}
	}

	err = irdma_ah_cqp_op(iwdev->rf, sc_ah, IRDMA_OP_AH_CREATE,
			      sleep, NULL, sc_ah);
	if (err) {
		ibdev_dbg(&iwdev->ibdev, "CQP-OP Create AH fail");
		goto err_ah_create;
	}

	err = irdma_create_ah_wait(rf, sc_ah, sleep);
	if (err)
		goto err_gid_l2;

exit:
	if (udata) {
		uresp.ah_id = ah->sc_ah.ah_info.ah_idx;
		err = ib_copy_to_udata(udata, &uresp, min(sizeof(uresp), udata->outlen));
		if (err) {
			if (!ah->parent_ah ||
			    (ah->parent_ah && refcount_dec_and_test(&ah->parent_ah->refcnt))) {
				irdma_ah_cqp_op(iwdev->rf, &ah->sc_ah,
						IRDMA_OP_AH_DESTROY, false, NULL, ah);
				ah_id = ah->sc_ah.ah_info.ah_idx;
				goto err_ah_create;
			}
			goto err_unlock;
		}
	}
	if (sleep)
		mutex_unlock(&iwdev->ah_tbl_lock);

	return &ah->ibah;

err_ah_create:
	if (ah->parent_ah) {
		hash_del(&ah->parent_ah->list);
		kfree(ah->parent_ah);
		iwdev->ah_list_cnt--;
	}
err_unlock:
	if (sleep)
		mutex_unlock(&iwdev->ah_tbl_lock);
err_gid_l2:
	kfree(ah);
	if (ah_id)
		irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah_id);

	return ERR_PTR(err);
}
#endif

#ifdef CREATE_AH_VER_3
/**
 * irdma_create_ah - create address handle
 * @ibpd: Protection Domain for AH
 * @attr: address handle attributes
 * @flags: AH flags to wait
 * @udata: user data
 *
 * returns a pointer to an address handle
 */
struct ib_ah *irdma_create_ah(struct ib_pd *ibpd,
			      struct rdma_ah_attr *attr,
			      u32 flags,
			      struct ib_udata *udata)
{
	bool sleep = (flags & RDMA_CREATE_AH_SLEEPABLE) != 0;

	return irdma_create_ah_sleepable(ibpd, attr, sleep, udata);
}
#endif
#ifdef CREATE_AH_VER_4
/**
 * irdma_create_ah - create address handle
 * @ibpd: ptr to pd
 * @attr: address handle attributes
 * @udata: user data
 *
 * returns a pointer to an address handle
 */
struct ib_ah *irdma_create_ah(struct ib_pd *ibpd,
			      struct rdma_ah_attr *attr,
			      struct ib_udata *udata)
{
	bool sleep = udata ? true : false;

	return irdma_create_ah_sleepable(ibpd, attr, sleep, udata);
}
#endif

#ifdef CREATE_AH_VER_2
/**
 * irdma_create_ah - create address handle
 * @ib_ah: ptr to AH
 * @attr: address handle attributes
 * @flags: AH flags to wait
 * @udata: user data
 *
 * returns 0 on success, error otherwise
 */
int irdma_create_ah(struct ib_ah *ib_ah,
		    struct rdma_ah_attr *attr, u32 flags,
		    struct ib_udata *udata)
#elif defined(CREATE_AH_VER_5)
int irdma_create_ah_v2(struct ib_ah *ib_ah,
		       struct rdma_ah_attr *attr, u32 flags,
		       struct ib_udata *udata)
#endif
#if defined(CREATE_AH_VER_2) || defined(CREATE_AH_VER_5)
{
	struct irdma_pd *pd = to_iwpd(ib_ah->pd);
	struct irdma_ah *ah = container_of(ib_ah, struct irdma_ah, ibah);
	struct irdma_device *iwdev = to_iwdev(ib_ah->pd->device);
	const struct ib_gid_attr *sgid_attr;
	struct irdma_pci_f *rf = iwdev->rf;
	struct irdma_sc_ah *sc_ah;
	u32 ah_id = 0;
	struct irdma_ah_info *ah_info;
	struct irdma_create_ah_resp uresp = {};
	union irdma_sockaddr sgid_addr, dgid_addr;
	int err;
	u8 dmac[ETH_ALEN];
	bool sleep = (flags & RDMA_CREATE_AH_SLEEPABLE) != 0;

	if (udata && udata->outlen < IRDMA_CREATE_AH_MIN_RESP_LEN)
		return -EINVAL;

	err = irdma_alloc_rsrc(rf, rf->allocated_ahs,
			       rf->max_ah, &ah_id, &rf->next_ah);

	if (err)
		return err;

	ah->pd = pd;
	sc_ah = &ah->sc_ah;
	sc_ah->ah_info.ah_idx = ah_id;
	sc_ah->ah_info.vsi = &iwdev->vsi;
	irdma_sc_init_ah(&rf->sc_dev, sc_ah);
	ah->sgid_index = attr->grh.sgid_index;
	memcpy(&ah->dgid, &attr->grh.dgid, sizeof(ah->dgid));
	sgid_attr = attr->grh.sgid_attr;

	rdma_gid2ip((struct sockaddr *)&sgid_addr, &sgid_attr->gid);
	rdma_gid2ip((struct sockaddr *)&dgid_addr, &attr->grh.dgid);
	ah->av.attrs = *attr;
	ah->av.net_type = kc_rdma_gid_attr_network_type(sgid_attr,
							sgid_attr.gid_type,
							&sgid);

	ah_info = &sc_ah->ah_info;
	ah_info->ah_idx = ah_id;
	ah_info->pd_idx = pd->sc_pd.pd_id;
	err = rdma_read_gid_l2_fields(sgid_attr, &ah_info->vlan_tag,
				      ah_info->mac_addr);

	if (err)
		goto err_gid_l2;

	if (attr->ah_flags & IB_AH_GRH) {
		ah_info->flow_label = attr->grh.flow_label;
		ah_info->hop_ttl = attr->grh.hop_limit;
		ah_info->tc_tos = attr->grh.traffic_class;
	}

	ether_addr_copy(dmac, attr->roce.dmac);

	irdma_fill_ah_info(ah_info, sgid_attr, &sgid_addr, &dgid_addr,
			   dmac, ah->av.net_type);

	err = irdma_create_ah_vlan_tag(iwdev, ah_info, sgid_attr, dmac);
	if (err)
		goto err_gid_l2;

	if (sleep) {
		mutex_lock(&iwdev->ah_tbl_lock);
		if (irdma_ah_exists(iwdev, ah)) {
			irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah_id);
			ah_id = 0;
#ifdef CONFIG_DEBUG_FS
			iwdev->ah_reused++;
#endif
			goto exit;
		}
	}

	err = irdma_ah_cqp_op(iwdev->rf, sc_ah, IRDMA_OP_AH_CREATE,
			      sleep, NULL, sc_ah);
	if (err) {
		ibdev_dbg(&iwdev->ibdev, "CQP-OP Create AH fail");
		goto err_ah_create;
	}

	err = irdma_create_ah_wait(rf, sc_ah, sleep);
	if (err)
		goto err_gid_l2;

exit:
	if (udata) {
		uresp.ah_id = ah->sc_ah.ah_info.ah_idx;
		err = ib_copy_to_udata(udata, &uresp, min(sizeof(uresp), udata->outlen));
		if (err) {
			if (!ah->parent_ah ||
			    (ah->parent_ah && refcount_dec_and_test(&ah->parent_ah->refcnt))) {
				irdma_ah_cqp_op(iwdev->rf, &ah->sc_ah,
						IRDMA_OP_AH_DESTROY, false, NULL, ah);
				ah_id = ah->sc_ah.ah_info.ah_idx;
				goto err_ah_create;
			}
			goto err_unlock;
		}
	}
	if (sleep)
		mutex_unlock(&iwdev->ah_tbl_lock);
	return 0;
err_ah_create:
	if (ah->parent_ah) {
		hash_del(&ah->parent_ah->list);
		kfree(ah->parent_ah);
		iwdev->ah_list_cnt--;
	}
err_unlock:
	if (sleep)
		mutex_unlock(&iwdev->ah_tbl_lock);
err_gid_l2:
	if (ah_id)
		irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah_id);

	return err;
}
#endif

#ifdef CREATE_AH_VER_6
/**
 * irdma_create_ah - create address handle
 * @ib_ah: ptr to AH
 * @attr: address handle attributes
 * @flags: AH flags to wait
 * @udata: user data
 *
 * returns 0 on success, error otherwise
 */
int irdma_create_ah(struct ib_ah *ib_ah,
		    struct ib_ah_attr *attr, u32 flags,
		    struct ib_udata *udata)
{
	struct irdma_pd *pd = to_iwpd(ib_ah->pd);
	struct irdma_ah *ah = container_of(ib_ah, struct irdma_ah, ibah);
	struct irdma_device *iwdev = to_iwdev(ib_ah->pd->device);
	union ib_gid sgid;
	struct ib_gid_attr sgid_attr;
	struct irdma_pci_f *rf = iwdev->rf;
	struct irdma_sc_ah *sc_ah;
	u32 ah_id = 0;
	struct irdma_ah_info *ah_info;
	struct irdma_create_ah_resp uresp = {};
	union irdma_sockaddr sgid_addr, dgid_addr;
	int err;
	u8 dmac[ETH_ALEN];
	bool sleep = (flags & RDMA_CREATE_AH_SLEEPABLE) != 0;

	if (udata && udata->outlen < IRDMA_CREATE_AH_MIN_RESP_LEN)
		return -EINVAL;

	err = irdma_alloc_rsrc(rf, rf->allocated_ahs,
			       rf->max_ah, &ah_id, &rf->next_ah);

	if (err)
		return err;

	ah->pd = pd;
	sc_ah = &ah->sc_ah;
	sc_ah->ah_info.ah_idx = ah_id;
	sc_ah->ah_info.vsi = &iwdev->vsi;
	irdma_sc_init_ah(&rf->sc_dev, sc_ah);
	ah->sgid_index = attr->grh.sgid_index;
	memcpy(&ah->dgid, &attr->grh.dgid, sizeof(ah->dgid));
	rcu_read_lock();
	err = ib_get_cached_gid(&iwdev->ibdev, attr->port_num,
				attr->grh.sgid_index, &sgid, &sgid_attr);
	rcu_read_unlock();
	if (err) {
		ibdev_dbg(&iwdev->ibdev,
			  "VERBS: GID lookup at idx=%d with port=%d failed\n",
			  attr->grh.sgid_index, attr->port_num);
		err = -EINVAL;
		goto err_gid_l2;
	}
	rdma_gid2ip((struct sockaddr *)&sgid_addr, &sgid);
	rdma_gid2ip((struct sockaddr *)&dgid_addr, &attr->grh.dgid);
	ah->av.attrs = *attr;
	ah->av.net_type = kc_rdma_gid_attr_network_type(sgid_attr,
							sgid_attr.gid_type,
							&sgid);

	if (kc_deref_sgid_attr(sgid_attr))
		dev_put(kc_deref_sgid_attr(sgid_attr));

	ah_info = &sc_ah->ah_info;
	ah_info->ah_idx = ah_id;
	ah_info->pd_idx = pd->sc_pd.pd_id;
	ether_addr_copy(ah_info->mac_addr, iwdev->netdev->dev_addr);

	if (attr->ah_flags & IB_AH_GRH) {
		ah_info->flow_label = attr->grh.flow_label;
		ah_info->hop_ttl = attr->grh.hop_limit;
		ah_info->tc_tos = attr->grh.traffic_class;
	}

	ether_addr_copy(dmac, attr->dmac);

	irdma_fill_ah_info(ah_info, &sgid_attr, &sgid_addr, &dgid_addr,
			   dmac, ah->av.net_type);

	err = irdma_create_ah_vlan_tag(iwdev, ah_info, &sgid_attr, dmac);
	if (err)
		goto err_gid_l2;

	if (sleep) {
		mutex_lock(&iwdev->ah_tbl_lock);
		if (irdma_ah_exists(iwdev, ah)) {
			irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah_id);
			ah_id = 0;
#ifdef CONFIG_DEBUG_FS
			iwdev->ah_reused++;
#endif
			goto exit;
		}
	}

	err = irdma_ah_cqp_op(iwdev->rf, sc_ah, IRDMA_OP_AH_CREATE,
			      sleep, NULL, sc_ah);
	if (err) {
		ibdev_dbg(&iwdev->ibdev, "CQP-OP Create AH fail");
		goto err_ah_create;
	}

	err = irdma_create_ah_wait(rf, sc_ah, sleep);
	if (err)
		goto err_gid_l2;

exit:
	if (udata) {
		uresp.ah_id = ah->sc_ah.ah_info.ah_idx;
		err = ib_copy_to_udata(udata, &uresp, min(sizeof(uresp), udata->outlen));
		if (err) {
			if (!ah->parent_ah ||
			    (ah->parent_ah && refcount_dec_and_test(&ah->parent_ah->refcnt))) {
				irdma_ah_cqp_op(iwdev->rf, &ah->sc_ah,
						IRDMA_OP_AH_DESTROY, false, NULL, ah);
				ah_id = ah->sc_ah.ah_info.ah_idx;
				goto err_ah_create;
			}
			goto err_unlock;
		}
	}
	if (sleep)
		mutex_unlock(&iwdev->ah_tbl_lock);

	return 0;
err_ah_create:
	if (ah->parent_ah) {
		hash_del(&ah->parent_ah->list);
		kfree(ah->parent_ah);
		iwdev->ah_list_cnt--;
	}
err_unlock:
	if (sleep)
		mutex_unlock(&iwdev->ah_tbl_lock);
err_gid_l2:
	if (ah_id)
		irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah_id);

	return err;
}
#endif /* CREATE_AH_VER_6 */

#ifdef CREATE_AH_VER_5
/**
 * irdma_create_ah - create address handle
 * @ibah: ptr to AH
 * @init_attr: address handle attributes
 * @udata: user data
 *
 * returns a pointer to an address handle
 */
int irdma_create_ah(struct ib_ah *ibah,
		    struct rdma_ah_init_attr *init_attr,
		    struct ib_udata *udata)
{
	return irdma_create_ah_v2(ibah, init_attr->ah_attr, init_attr->flags, udata);
}
#endif

#if defined(ETHER_COPY_VER_1)
void irdma_ether_copy(u8 *dmac, struct ib_ah_attr *attr)
{
	ether_addr_copy(dmac, attr->dmac);
}
#endif

#if defined(ETHER_COPY_VER_2)
void irdma_ether_copy(u8 *dmac, struct rdma_ah_attr *attr)
{
	ether_addr_copy(dmac, attr->roce.dmac);
}
#endif

#ifdef IB_IW_MANDATORY_AH_OP
#ifdef CREATE_AH_VER_0
struct ib_ah *irdma_create_ah_stub(struct ib_pd *ibpd,
				   struct ib_ah_attr *attr)
#elif defined(CREATE_AH_VER_1_1)
struct ib_ah *irdma_create_ah_stub(struct ib_pd *ibpd,
				   struct ib_ah_attr *attr,
				   struct ib_udata *udata)
#elif defined(CREATE_AH_VER_1_2)
struct ib_ah *irdma_create_ah_stub(struct ib_pd *ibpd,
				   struct rdma_ah_attr *attr,
				   struct ib_udata *udata)
#elif defined(CREATE_AH_VER_6)
int irdma_create_ah_stub(struct ib_ah *ib_ah,
			 struct ib_ah_attr *attr, u32 flags,
			 struct ib_udata *udata)
#endif
{
#ifdef CREATE_AH_VER_6
	return -ENOSYS;
#else
	return ERR_PTR(-ENOSYS);
#endif
}

#ifdef DESTROY_AH_VER_3
void irdma_destroy_ah_stub(struct ib_ah *ibah, u32 flags)
{
	return;
}
#else
int irdma_destroy_ah_stub(struct ib_ah *ibah)
{
	return -ENOSYS;
}
#endif

#endif /* IB_IW_MANDATORY_AH_OP */
#ifdef CREATE_AH_VER_1_1
/**
 * irdma_create_ah - create address handle
 * @ibpd: ptr to pd
 * @attr: address handle attributes
 * @udata: user data
 *
 * returns a pointer to an address handle
 */
struct ib_ah *irdma_create_ah(struct ib_pd *ibpd,
			      struct ib_ah_attr *attr,
			      struct ib_udata *udata)
#elif defined(CREATE_AH_VER_1_2)
struct ib_ah *irdma_create_ah(struct ib_pd *ibpd,
			      struct rdma_ah_attr *attr,
			      struct ib_udata *udata)
#endif
#if defined(CREATE_AH_VER_1_1) || defined(CREATE_AH_VER_1_2)
{
	struct irdma_pd *pd = to_iwpd(ibpd);
	struct irdma_device *iwdev = to_iwdev(ibpd->device);
	struct irdma_ah *ah;
#ifdef IB_GET_CACHED_GID
	union ib_gid sgid;
	struct ib_gid_attr sgid_attr;
#else
	const struct ib_gid_attr *sgid_attr;
#endif
	struct irdma_pci_f *rf = iwdev->rf;
	struct irdma_sc_ah *sc_ah;
	u32 ah_id = 0;
	struct irdma_ah_info *ah_info;
	struct irdma_create_ah_resp uresp = {};
	union irdma_sockaddr sgid_addr, dgid_addr;
	int err;
	u8 dmac[ETH_ALEN];
	bool sleep = udata ? true : false;

	if (udata && udata->outlen < IRDMA_CREATE_AH_MIN_RESP_LEN)
		return ERR_PTR(-EINVAL);

	err = irdma_alloc_rsrc(rf, rf->allocated_ahs,
			       rf->max_ah, &ah_id, &rf->next_ah);

	if (err)
		return ERR_PTR(err);

	ah = kzalloc(sizeof(*ah), GFP_ATOMIC);
	if (!ah) {
		irdma_free_rsrc(rf, rf->allocated_ahs, ah_id);
		return ERR_PTR(-ENOMEM);
	}

	ah->pd = pd;
	sc_ah = &ah->sc_ah;
	sc_ah->ah_info.ah_idx = ah_id;
	sc_ah->ah_info.vsi = &iwdev->vsi;
	irdma_sc_init_ah(&rf->sc_dev, sc_ah);
	ah->sgid_index = attr->grh.sgid_index;
	memcpy(&ah->dgid, &attr->grh.dgid, sizeof(ah->dgid));
#ifdef IB_GET_CACHED_GID
	rcu_read_lock();
	err = ib_get_cached_gid(&iwdev->ibdev, attr->port_num,
				attr->grh.sgid_index, &sgid, &sgid_attr);
	rcu_read_unlock();
	if (err) {
		ibdev_dbg(&iwdev->ibdev,
			  "GID lookup at idx=%d with port=%d failed\n",
			  attr->grh.sgid_index, attr->port_num);
		err = -EINVAL;
		goto err_gid_l2;
	}
	rdma_gid2ip((struct sockaddr *)&sgid_addr, &sgid);
#else
	sgid_attr = attr->grh.sgid_attr;
	rdma_gid2ip((struct sockaddr *)&sgid_addr, &sgid_attr->gid);
#endif
	rdma_gid2ip((struct sockaddr *)&dgid_addr, &attr->grh.dgid);
	ah->av.attrs = *attr;
	ah->av.net_type = kc_rdma_gid_attr_network_type(sgid_attr,
							sgid_attr.gid_type,
							&sgid);

#ifdef IB_GET_CACHED_GID
	if (kc_deref_sgid_attr(sgid_attr))
		dev_put(kc_deref_sgid_attr(sgid_attr));
#endif

	ah_info = &sc_ah->ah_info;
	ah_info->ah_idx = ah_id;
	ah_info->pd_idx = pd->sc_pd.pd_id;

	ether_addr_copy(ah_info->mac_addr, iwdev->netdev->dev_addr);
	if (attr->ah_flags & IB_AH_GRH) {
		ah_info->flow_label = attr->grh.flow_label;
		ah_info->hop_ttl = attr->grh.hop_limit;
		ah_info->tc_tos = attr->grh.traffic_class;
	}

#if defined(HPM_FBSD) || defined(IB_RESOLVE_ETH_DMAC)
	if (udata) {
		err = ib_resolve_eth_dmac(ibpd->device, attr);
		if (err)
			goto err_gid_l2;
	}
#endif
	irdma_ether_copy(dmac, attr);

#ifdef IB_GET_CACHED_GID
	irdma_fill_ah_info(ah_info, &sgid_attr, &sgid_addr, &dgid_addr,
			   dmac, ah->av.net_type);

	err = irdma_create_ah_vlan_tag(iwdev, ah_info, &sgid_attr, dmac);
#else /* IB_GET_CACHED_GID */
	irdma_fill_ah_info(ah_info, sgid_attr, &sgid_addr, &dgid_addr,
			   dmac, ah->av.net_type);

	err = irdma_create_ah_vlan_tag(iwdev, ah_info, sgid_attr, dmac);
#endif /* IB_GET_CACHED_GID */
	if (err)
		goto err_gid_l2;

	if (sleep) {
		mutex_lock(&iwdev->ah_tbl_lock);
		if (irdma_ah_exists(iwdev, ah)) {
			irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah_id);
			ah_id = 0;
			#ifdef CONFIG_DEBUG_FS
			iwdev->ah_reused++;
			#endif
			goto exit;
		}
	}

	err = irdma_ah_cqp_op(iwdev->rf, sc_ah, IRDMA_OP_AH_CREATE,
			      sleep, NULL, sc_ah);
	if (err) {
		ibdev_dbg(&iwdev->ibdev, "VERBS: CQP-OP Create AH fail");
		goto err_ah_create;
	}

	err = irdma_create_ah_wait(rf, sc_ah, sleep);
	if (err)
		goto err_gid_l2;

exit:
	if (udata) {
		uresp.ah_id = ah->sc_ah.ah_info.ah_idx;
		err = ib_copy_to_udata(udata, &uresp, min(sizeof(uresp), udata->outlen));
		if (err) {
			if (!ah->parent_ah ||
			    (ah->parent_ah && refcount_dec_and_test(&ah->parent_ah->refcnt))) {
				irdma_ah_cqp_op(iwdev->rf, &ah->sc_ah,
						IRDMA_OP_AH_DESTROY, false, NULL, ah);
				ah_id = ah->sc_ah.ah_info.ah_idx;
				goto err_ah_create;
			}
			goto err_unlock;
		}
	}
	if (sleep)
		mutex_unlock(&iwdev->ah_tbl_lock);

	return &ah->ibah;
err_ah_create:
	if (ah->parent_ah) {
		hash_del(&ah->parent_ah->list);
		kfree(ah->parent_ah);
		iwdev->ah_list_cnt--;
	}
err_unlock:
	if (sleep)
		mutex_unlock(&iwdev->ah_tbl_lock);
err_gid_l2:
	kfree(ah);
	if (ah_id)
		irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah_id);

	return ERR_PTR(err);
}
#endif

#ifdef CREATE_AH_VER_0
struct ib_ah *irdma_create_ah(struct ib_pd *ibpd, struct ib_ah_attr *attr)
{
	struct irdma_pd *pd = to_iwpd(ibpd);
	struct irdma_device *iwdev = to_iwdev(ibpd->device);
	struct irdma_ah *ah;
	struct irdma_pci_f *rf = iwdev->rf;
	union ib_gid sgid;
	struct ib_gid_attr sgid_attr;
	struct irdma_sc_ah *sc_ah;
	u32 ah_id;
	struct irdma_ah_info *ah_info;
	union irdma_sockaddr sgid_addr, dgid_addr;
	int err;
	u8 dmac[ETH_ALEN];

	err = irdma_alloc_rsrc(rf, rf->allocated_ahs,
			       rf->max_ah, &ah_id, &rf->next_ah);

	if (err)
		return ERR_PTR(err);

	ah = kzalloc(sizeof(*ah), GFP_ATOMIC);
	if (!ah) {
		irdma_free_rsrc(rf, rf->allocated_ahs, ah_id);
		return ERR_PTR(-ENOMEM);
	}

	ah->pd = pd;
	sc_ah = &ah->sc_ah;
	sc_ah->ah_info.ah_idx = ah_id;
	sc_ah->ah_info.vsi = &iwdev->vsi;
	irdma_sc_init_ah(&rf->sc_dev, sc_ah);
	ah->sgid_index = attr->grh.sgid_index;
	memcpy(&ah->dgid, &attr->grh.dgid, sizeof(ah->dgid));
	rcu_read_lock();

	err = ib_get_cached_gid(&iwdev->ibdev, attr->port_num,
				attr->grh.sgid_index, &sgid, &sgid_attr);
	rcu_read_unlock();
	if (err) {
		ibdev_dbg(&iwdev->ibdev,
			  "VERBS: GID lookup at idx=%d with port=%d failed\n",
			  attr->grh.sgid_index, attr->port_num);
		err = -EINVAL;
		goto error;
	}
	rdma_gid2ip((struct sockaddr *)&sgid_addr, &sgid);
	rdma_gid2ip((struct sockaddr *)&dgid_addr, &attr->grh.dgid);
	ah->av.attrs = *attr;
	ah->av.net_type = kc_rdma_gid_attr_network_type(sgid_attr,
							sgid_attr.gid_type,
							&sgid);
	if (kc_deref_sgid_attr(sgid_attr))
		dev_put(kc_deref_sgid_attr(sgid_attr));

	ah_info = &sc_ah->ah_info;
	ah_info->ah_idx = ah_id;
	ah_info->pd_idx = pd->sc_pd.pd_id;

	ether_addr_copy(ah_info->mac_addr, iwdev->netdev->dev_addr);
	if (attr->ah_flags & IB_AH_GRH) {
		ah_info->flow_label = attr->grh.flow_label;
		ah_info->hop_ttl = attr->grh.hop_limit;
		ah_info->tc_tos = attr->grh.traffic_class;
	}

	irdma_ether_copy(dmac, attr);

	irdma_fill_ah_info(ah_info, &sgid_attr, &sgid_addr, &dgid_addr,
			   dmac, ah->av.net_type);

	err = irdma_create_ah_vlan_tag(iwdev, ah_info, &sgid_attr, dmac);
	if (err)
		goto error;

	err = irdma_ah_cqp_op(iwdev->rf, sc_ah, IRDMA_OP_AH_CREATE,
			      false, NULL, sc_ah);
	if (err) {
		ibdev_dbg(&iwdev->ibdev,
			  "VERBS: CQP-OP Create AH fail");
		goto error;
	}

	err = irdma_create_ah_wait(rf, sc_ah, false);
	if (err)
		goto error;

	return &ah->ibah;
error:
	kfree(ah);
	irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah_id);
	return ERR_PTR(err);
}

#endif
#ifdef CREATE_QP_VER_2
/**
 * irdma_free_qp_rsrc - free up memory resources for qp
 * @iwqp: qp ptr (user or kernel)
 */
void irdma_free_qp_rsrc(struct irdma_qp *iwqp)
{
	struct irdma_device *iwdev = iwqp->iwdev;
	struct irdma_pci_f *rf = iwdev->rf;
	u32 qp_num = iwqp->ibqp.qp_num;

	irdma_ieq_cleanup_qp(iwdev->vsi.ieq, &iwqp->sc_qp);
	irdma_dealloc_push_page(rf, iwqp);
	if (iwqp->sc_qp.vsi) {
		irdma_qp_rem_qos(&iwqp->sc_qp);
		iwqp->sc_qp.dev->ws_remove(iwqp->sc_qp.vsi,
					   iwqp->sc_qp.user_pri);
	}

	if (qp_num > 2)
		irdma_free_rsrc(rf, rf->allocated_qps, qp_num);
	dma_free_coherent(rf->sc_dev.hw->device, iwqp->q2_ctx_mem.size,
			  iwqp->q2_ctx_mem.va, iwqp->q2_ctx_mem.pa);
	iwqp->q2_ctx_mem.va = NULL;
	dma_free_coherent(rf->sc_dev.hw->device, iwqp->kqp.dma_mem.size,
			  iwqp->kqp.dma_mem.va, iwqp->kqp.dma_mem.pa);
	iwqp->kqp.dma_mem.va = NULL;
	kfree(iwqp->kqp.sq_wrid_mem);
	kfree(iwqp->kqp.rq_wrid_mem);
	kfree(iwqp->sg_list);
}

/**
 * irdma_create_qp - create qp
 * @ibqp: ptr of qp
 * @init_attr: attributes for qp
 * @udata: user data for create qp
 */
int irdma_create_qp(struct ib_qp *ibqp,
		    struct ib_qp_init_attr *init_attr,
		    struct ib_udata *udata)
{
#define IRDMA_CREATE_QP_MIN_REQ_LEN offsetofend(struct irdma_create_qp_req, user_compl_ctx)
#define IRDMA_CREATE_QP_MIN_RESP_LEN offsetofend(struct irdma_create_qp_resp, rsvd)
	struct ib_pd *ibpd = ibqp->pd;
	struct irdma_pd *iwpd = to_iwpd(ibpd);
	struct irdma_device *iwdev = to_iwdev(ibpd->device);
	struct irdma_pci_f *rf = iwdev->rf;
	struct irdma_qp *iwqp = to_iwqp(ibqp);
	struct irdma_create_qp_resp uresp = {};
	u32 qp_num = 0;
	u32 next_qp;
	int ret;
	int err_code;
	struct irdma_sc_qp *qp;
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_uk_attrs *uk_attrs = &dev->hw_attrs.uk_attrs;
	struct irdma_qp_init_info init_info = {};
	struct irdma_qp_host_ctx_info *ctx_info;
	struct irdma_srq *iwsrq;
	bool srq_valid = false;
	u32 srq_id = 0;

	if (init_attr->srq) {
		iwsrq = to_iwsrq(init_attr->srq);
		srq_valid = true;
		srq_id = iwsrq->srq_num;
		init_attr->cap.max_recv_sge = uk_attrs->max_hw_wq_frags;
		init_attr->cap.max_recv_wr = 4;
		init_info.qp_uk_init_info.srq_uk = &iwsrq->sc_srq.srq_uk;
	}
	err_code = irdma_validate_qp_attrs(init_attr, iwdev);
	if (err_code)
		return err_code;

	if (udata && (udata->inlen < IRDMA_CREATE_QP_MIN_REQ_LEN ||
		      udata->outlen < IRDMA_CREATE_QP_MIN_RESP_LEN))
		return -EINVAL;

	init_info.vsi = &iwdev->vsi;
	init_info.qp_uk_init_info.uk_attrs = uk_attrs;
	init_info.qp_uk_init_info.sq_size = init_attr->cap.max_send_wr;
	init_info.qp_uk_init_info.rq_size = init_attr->cap.max_recv_wr;
	init_info.qp_uk_init_info.max_sq_frag_cnt = init_attr->cap.max_send_sge;
	init_info.qp_uk_init_info.max_rq_frag_cnt = init_attr->cap.max_recv_sge;
	init_info.qp_uk_init_info.max_inline_data = init_attr->cap.max_inline_data;

	iwqp->sg_list = kcalloc(uk_attrs->max_hw_wq_frags, sizeof(*iwqp->sg_list),
				GFP_KERNEL);
	if (!iwqp->sg_list)
		return -ENOMEM;

	qp = &iwqp->sc_qp;
	qp->qp_uk.back_qp = iwqp;
	qp->qp_uk.lock = &iwqp->lock;
	qp->push_idx = IRDMA_INVALID_PUSH_PAGE_INDEX;

	iwqp->iwdev = iwdev;
	iwqp->q2_ctx_mem.size = ALIGN(IRDMA_Q2_BUF_SIZE + IRDMA_QP_CTX_SIZE,
				      256);
	iwqp->q2_ctx_mem.va = dma_alloc_coherent(dev->hw->device,
						 iwqp->q2_ctx_mem.size,
						 &iwqp->q2_ctx_mem.pa,
						 GFP_KERNEL);
	if (!iwqp->q2_ctx_mem.va) {
		kfree(iwqp->sg_list);
		return -ENOMEM;
	}

	init_info.q2 = iwqp->q2_ctx_mem.va;
	init_info.q2_pa = iwqp->q2_ctx_mem.pa;
	init_info.host_ctx = (__le64 *)(init_info.q2 + IRDMA_Q2_BUF_SIZE);
	init_info.host_ctx_pa = init_info.q2_pa + IRDMA_Q2_BUF_SIZE;

	if (init_attr->qp_type == IB_QPT_GSI) {
		qp_num = 1;
	} else {
		get_random_bytes(&next_qp, sizeof(next_qp));
		next_qp %= rf->max_qp;
		err_code = irdma_alloc_rsrc(rf, rf->allocated_qps, rf->max_qp,
					    &qp_num, &next_qp);
	}
	if (err_code)
		goto error;

	iwqp->iwpd = iwpd;
	iwqp->ibqp.qp_num = qp_num;
	qp = &iwqp->sc_qp;
	iwqp->iwscq = to_iwcq(init_attr->send_cq);
	iwqp->iwrcq = to_iwcq(init_attr->recv_cq);
	iwqp->host_ctx.va = init_info.host_ctx;
	iwqp->host_ctx.pa = init_info.host_ctx_pa;
	iwqp->host_ctx.size = IRDMA_QP_CTX_SIZE;

	init_info.pd = &iwpd->sc_pd;
	init_info.qp_uk_init_info.qp_id = qp_num;
	if (!rdma_protocol_roce(&iwdev->ibdev, 1))
		init_info.qp_uk_init_info.first_sq_wq = 1;
	iwqp->ctx_info.qp_compl_ctx = (uintptr_t)qp;
	init_waitqueue_head(&iwqp->waitq);
	init_waitqueue_head(&iwqp->mod_qp_waitq);

	if (udata) {
		init_info.qp_uk_init_info.abi_ver = iwpd->sc_pd.abi_ver;
		err_code = irdma_setup_umode_qp(udata, iwdev, iwqp, &init_info, init_attr);
	} else {
		if (uk_attrs->hw_rev <= IRDMA_GEN_2)
			INIT_DELAYED_WORK(&iwqp->dwork_flush, irdma_flush_worker);
		init_info.qp_uk_init_info.abi_ver = IRDMA_ABI_VER;
		err_code = irdma_setup_kmode_qp(iwdev, iwqp, &init_info, init_attr);
	}

	if (err_code) {
		ibdev_dbg(&iwdev->ibdev, "setup qp failed\n");
		goto error;
	}

	if (rdma_protocol_roce(&iwdev->ibdev, 1)) {
		if (init_attr->qp_type == IB_QPT_RC) {
			init_info.qp_uk_init_info.type = IRDMA_QP_TYPE_ROCE_RC;
			init_info.qp_uk_init_info.qp_caps = IRDMA_SEND_WITH_IMM |
							    IRDMA_WRITE_WITH_IMM |
							    IRDMA_ROCE;
		} else {
			init_info.qp_uk_init_info.type = IRDMA_QP_TYPE_ROCE_UD;
			init_info.qp_uk_init_info.qp_caps = IRDMA_SEND_WITH_IMM |
							    IRDMA_ROCE;
		}
	} else {
		init_info.qp_uk_init_info.type = IRDMA_QP_TYPE_IWARP;
		init_info.qp_uk_init_info.qp_caps = IRDMA_WRITE_WITH_IMM;
	}

#ifndef __OFED_4_8__
	if (dev->hw_attrs.uk_attrs.hw_rev > IRDMA_GEN_1)
		init_info.qp_uk_init_info.qp_caps |= IRDMA_PUSH_MODE;

#endif
	ret = irdma_sc_qp_init(qp, &init_info);
	if (ret) {
		err_code = -EPROTO;
		ibdev_dbg(&iwdev->ibdev, "qp_init fail\n");
		goto error;
	}

	ctx_info = &iwqp->ctx_info;
	ctx_info->srq_valid = srq_valid;
	ctx_info->srq_id = srq_id;
	ctx_info->send_cq_num = iwqp->iwscq->sc_cq.cq_uk.cq_id;
	ctx_info->rcv_cq_num = iwqp->iwrcq->sc_cq.cq_uk.cq_id;

	if (rdma_protocol_roce(&iwdev->ibdev, 1))
		irdma_roce_fill_and_set_qpctx_info(iwqp, ctx_info);
	else
		irdma_iw_fill_and_set_qpctx_info(iwqp, ctx_info);

	err_code = irdma_cqp_create_qp_cmd(iwqp);
	if (err_code)
		goto error;

	refcount_set(&iwqp->refcnt, 1);
	spin_lock_init(&iwqp->lock);
	spin_lock_init(&iwqp->sc_qp.pfpdu.lock);
	iwqp->sig_all = (init_attr->sq_sig_type == IB_SIGNAL_ALL_WR) ? 1 : 0;
	rf->qp_table[qp_num] = iwqp;

	if (rdma_protocol_roce(&iwdev->ibdev, 1)) {
		if (dev->ws_add(&iwdev->vsi, 0)) {
			irdma_cqp_qp_destroy_cmd(&rf->sc_dev, &iwqp->sc_qp);
			err_code = -EINVAL;
			goto error;
		}

		irdma_qp_add_qos(&iwqp->sc_qp);
	}

	if (udata) {
		/* GEN_1 legacy support with libi40iw does not have expanded uresp struct */
		if (udata->outlen == IRDMA_CREATE_QP_MIN_RESP_LEN) {
			uresp.lsmm = 1;
			uresp.push_idx = IRDMA_INVALID_PUSH_PAGE_INDEX_GEN_1;
		} else {
			if (rdma_protocol_iwarp(&iwdev->ibdev, 1)) {
				uresp.lsmm = 1;
				if (qp->qp_uk.start_wqe_idx) {
					uresp.comp_mask |= IRDMA_CREATE_QP_USE_START_WQE_IDX;
					uresp.start_wqe_idx = qp->qp_uk.start_wqe_idx;
				}
			}
		}
		uresp.actual_sq_size = init_info.qp_uk_init_info.sq_size;
		uresp.actual_rq_size = init_info.qp_uk_init_info.rq_size;
		uresp.qp_id = qp_num;
		uresp.qp_caps = qp->qp_uk.qp_caps;

		err_code = ib_copy_to_udata(udata, &uresp,
					    min(sizeof(uresp), udata->outlen));
		if (err_code) {
			ibdev_dbg(&iwdev->ibdev, "VERBS: copy_to_udata failed\n");
			kc_irdma_destroy_qp(&iwqp->ibqp, udata);
			return err_code;
		}
	}

	init_completion(&iwqp->free_qp);
	return 0;

error:
	irdma_free_qp_rsrc(iwqp);

	return err_code;
}
#endif /* CREATE_QP_VER_2 */
#ifdef CREATE_QP_VER_1
/**
 * irdma_free_qp_rsrc - free up memory resources for qp
 * @iwqp: qp ptr (user or kernel)
 */
void irdma_free_qp_rsrc(struct irdma_qp *iwqp)
{
	struct irdma_device *iwdev = iwqp->iwdev;
	struct irdma_pci_f *rf = iwdev->rf;
	u32 qp_num = iwqp->ibqp.qp_num;

	irdma_ieq_cleanup_qp(iwdev->vsi.ieq, &iwqp->sc_qp);
	irdma_dealloc_push_page(rf, iwqp);
	if (iwqp->sc_qp.vsi) {
		irdma_qp_rem_qos(&iwqp->sc_qp);
		iwqp->sc_qp.dev->ws_remove(iwqp->sc_qp.vsi,
					   iwqp->sc_qp.user_pri);
	}

	if (qp_num > 2)
		irdma_free_rsrc(rf, rf->allocated_qps, qp_num);
	dma_free_coherent(rf->sc_dev.hw->device, iwqp->q2_ctx_mem.size,
			  iwqp->q2_ctx_mem.va, iwqp->q2_ctx_mem.pa);
	iwqp->q2_ctx_mem.va = NULL;
	dma_free_coherent(rf->sc_dev.hw->device, iwqp->kqp.dma_mem.size,
			  iwqp->kqp.dma_mem.va, iwqp->kqp.dma_mem.pa);
	iwqp->kqp.dma_mem.va = NULL;
	kfree(iwqp->kqp.sq_wrid_mem);
	kfree(iwqp->kqp.rq_wrid_mem);
	kfree(iwqp->sg_list);
	kfree(iwqp);
}

/**
 * irdma_create_qp - create qp
 * @ibpd: ptr of pd
 * @init_attr: attributes for qp
 * @udata: user data for create qp
 */
struct ib_qp *irdma_create_qp(struct ib_pd *ibpd,
			      struct ib_qp_init_attr *init_attr,
			      struct ib_udata *udata)
{
#define IRDMA_CREATE_QP_MIN_REQ_LEN offsetofend(struct irdma_create_qp_req, user_compl_ctx)
#define IRDMA_CREATE_QP_MIN_RESP_LEN offsetofend(struct irdma_create_qp_resp, rsvd)
	struct irdma_pd *iwpd = to_iwpd(ibpd);
	struct irdma_device *iwdev = to_iwdev(ibpd->device);
	struct irdma_pci_f *rf = iwdev->rf;
	struct irdma_qp *iwqp;
	struct irdma_create_qp_resp uresp = {};
	u32 qp_num = 0;
	u32 next_qp;
	int ret;
	int err_code;
	struct irdma_sc_qp *qp;
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_uk_attrs *uk_attrs = &dev->hw_attrs.uk_attrs;
	struct irdma_qp_init_info init_info = {};
	struct irdma_qp_host_ctx_info *ctx_info;
	struct irdma_srq *iwsrq;
	bool srq_valid = false;
	u32 srq_id = 0;

	if (init_attr->srq) {
		iwsrq = to_iwsrq(init_attr->srq);
		srq_valid = true;
		srq_id = iwsrq->srq_num;
		init_attr->cap.max_recv_sge = uk_attrs->max_hw_wq_frags;
		init_attr->cap.max_recv_wr = 4;
		init_info.qp_uk_init_info.srq_uk = &iwsrq->sc_srq.srq_uk;
	}
	err_code = irdma_validate_qp_attrs(init_attr, iwdev);
	if (err_code)
		return ERR_PTR(err_code);

	if (udata && (udata->inlen < IRDMA_CREATE_QP_MIN_REQ_LEN ||
		      udata->outlen < IRDMA_CREATE_QP_MIN_RESP_LEN))
		return ERR_PTR(-EINVAL);

	init_info.vsi = &iwdev->vsi;
	init_info.qp_uk_init_info.uk_attrs = uk_attrs;
	init_info.qp_uk_init_info.sq_size = init_attr->cap.max_send_wr;
	init_info.qp_uk_init_info.rq_size = init_attr->cap.max_recv_wr;
	init_info.qp_uk_init_info.max_sq_frag_cnt = init_attr->cap.max_send_sge;
	init_info.qp_uk_init_info.max_rq_frag_cnt = init_attr->cap.max_recv_sge;
	init_info.qp_uk_init_info.max_inline_data = init_attr->cap.max_inline_data;

	iwqp = kzalloc(sizeof(*iwqp), GFP_KERNEL);
	if (!iwqp)
		return ERR_PTR(-ENOMEM);

	iwqp->sg_list = kcalloc(uk_attrs->max_hw_wq_frags, sizeof(*iwqp->sg_list),
				GFP_KERNEL);
	if (!iwqp->sg_list) {
		kfree(iwqp);
		return ERR_PTR(-ENOMEM);
	}

	qp = &iwqp->sc_qp;
	qp->qp_uk.back_qp = iwqp;
	qp->qp_uk.lock = &iwqp->lock;
	qp->push_idx = IRDMA_INVALID_PUSH_PAGE_INDEX;

	iwqp->iwdev = iwdev;
	iwqp->q2_ctx_mem.size = ALIGN(IRDMA_Q2_BUF_SIZE + IRDMA_QP_CTX_SIZE,
				      256);
	iwqp->q2_ctx_mem.va = dma_alloc_coherent(dev->hw->device,
						 iwqp->q2_ctx_mem.size,
						 &iwqp->q2_ctx_mem.pa,
						 GFP_KERNEL);
	if (!iwqp->q2_ctx_mem.va) {
		kfree(iwqp->sg_list);
		kfree(iwqp);
		return ERR_PTR(-ENOMEM);
	}

	init_info.q2 = iwqp->q2_ctx_mem.va;
	init_info.q2_pa = iwqp->q2_ctx_mem.pa;
	init_info.host_ctx = (__le64 *)(init_info.q2 + IRDMA_Q2_BUF_SIZE);
	init_info.host_ctx_pa = init_info.q2_pa + IRDMA_Q2_BUF_SIZE;

	if (init_attr->qp_type == IB_QPT_GSI) {
		qp_num = 1;
	} else {
		get_random_bytes(&next_qp, sizeof(next_qp));
		next_qp %= rf->max_qp;
		err_code = irdma_alloc_rsrc(rf, rf->allocated_qps, rf->max_qp,
					    &qp_num, &next_qp);
	}
	if (err_code)
		goto error;

	iwqp->iwpd = iwpd;
	iwqp->ibqp.qp_num = qp_num;
	qp = &iwqp->sc_qp;
	iwqp->iwscq = to_iwcq(init_attr->send_cq);
	iwqp->iwrcq = to_iwcq(init_attr->recv_cq);
	iwqp->host_ctx.va = init_info.host_ctx;
	iwqp->host_ctx.pa = init_info.host_ctx_pa;
	iwqp->host_ctx.size = IRDMA_QP_CTX_SIZE;

	init_info.pd = &iwpd->sc_pd;
	init_info.qp_uk_init_info.qp_id = qp_num;
	if (!rdma_protocol_roce(&iwdev->ibdev, 1))
		init_info.qp_uk_init_info.first_sq_wq = 1;
	iwqp->ctx_info.qp_compl_ctx = (uintptr_t)qp;
	init_waitqueue_head(&iwqp->waitq);
	init_waitqueue_head(&iwqp->mod_qp_waitq);

	if (udata) {
		init_info.qp_uk_init_info.abi_ver = iwpd->sc_pd.abi_ver;
		err_code = irdma_setup_umode_qp(udata, iwdev, iwqp, &init_info, init_attr);
	} else {
		if (uk_attrs->hw_rev <= IRDMA_GEN_2)
			INIT_DELAYED_WORK(&iwqp->dwork_flush, irdma_flush_worker);
		init_info.qp_uk_init_info.abi_ver = IRDMA_ABI_VER;
		err_code = irdma_setup_kmode_qp(iwdev, iwqp, &init_info, init_attr);
	}

	if (err_code) {
		ibdev_dbg(&iwdev->ibdev, "VERBS: setup qp failed\n");
		goto error;
	}

	if (rdma_protocol_roce(&iwdev->ibdev, 1)) {
		if (init_attr->qp_type == IB_QPT_RC) {
			init_info.qp_uk_init_info.type = IRDMA_QP_TYPE_ROCE_RC;
			init_info.qp_uk_init_info.qp_caps = IRDMA_SEND_WITH_IMM |
							    IRDMA_WRITE_WITH_IMM |
							    IRDMA_ROCE;
		} else {
			init_info.qp_uk_init_info.type = IRDMA_QP_TYPE_ROCE_UD;
			init_info.qp_uk_init_info.qp_caps = IRDMA_SEND_WITH_IMM |
							    IRDMA_ROCE;
		}
	} else {
		init_info.qp_uk_init_info.type = IRDMA_QP_TYPE_IWARP;
		init_info.qp_uk_init_info.qp_caps = IRDMA_WRITE_WITH_IMM;
	}

#ifndef __OFED_4_8__
	if (dev->hw_attrs.uk_attrs.hw_rev > IRDMA_GEN_1)
		init_info.qp_uk_init_info.qp_caps |= IRDMA_PUSH_MODE;

#endif
	ret = irdma_sc_qp_init(qp, &init_info);
	if (ret) {
		err_code = -EPROTO;
		ibdev_dbg(&iwdev->ibdev, "VERBS: qp_init fail\n");
		goto error;
	}

	ctx_info = &iwqp->ctx_info;
	ctx_info->srq_valid = srq_valid;
	ctx_info->srq_id = srq_id;
	ctx_info->send_cq_num = iwqp->iwscq->sc_cq.cq_uk.cq_id;
	ctx_info->rcv_cq_num = iwqp->iwrcq->sc_cq.cq_uk.cq_id;

	if (rdma_protocol_roce(&iwdev->ibdev, 1))
		irdma_roce_fill_and_set_qpctx_info(iwqp, ctx_info);
	else
		irdma_iw_fill_and_set_qpctx_info(iwqp, ctx_info);

	err_code = irdma_cqp_create_qp_cmd(iwqp);
	if (err_code)
		goto error;

	refcount_set(&iwqp->refcnt, 1);
	spin_lock_init(&iwqp->lock);
	spin_lock_init(&iwqp->sc_qp.pfpdu.lock);
	iwqp->sig_all = (init_attr->sq_sig_type == IB_SIGNAL_ALL_WR) ? 1 : 0;
	rf->qp_table[qp_num] = iwqp;

	if (rdma_protocol_roce(&iwdev->ibdev, 1)) {
		if (dev->ws_add(&iwdev->vsi, 0)) {
			irdma_cqp_qp_destroy_cmd(&rf->sc_dev, &iwqp->sc_qp);
			err_code = -EINVAL;
			goto error;
		}

		irdma_qp_add_qos(&iwqp->sc_qp);
	}

	if (udata) {
		/* GEN_1 legacy support with libi40iw does not have expanded uresp struct */
		if (udata->outlen == IRDMA_CREATE_QP_MIN_RESP_LEN) {
			uresp.lsmm = 1;
			uresp.push_idx = IRDMA_INVALID_PUSH_PAGE_INDEX_GEN_1;
		} else {
			if (rdma_protocol_iwarp(&iwdev->ibdev, 1)) {
				uresp.lsmm = 1;
				if (qp->qp_uk.start_wqe_idx) {
					uresp.comp_mask |= IRDMA_CREATE_QP_USE_START_WQE_IDX;
					uresp.start_wqe_idx = qp->qp_uk.start_wqe_idx;
				}
			}
		}
		uresp.actual_sq_size = init_info.qp_uk_init_info.sq_size;
		uresp.actual_rq_size = init_info.qp_uk_init_info.rq_size;
		uresp.qp_id = qp_num;
		uresp.qp_caps = qp->qp_uk.qp_caps;

		err_code = ib_copy_to_udata(udata, &uresp,
					    min(sizeof(uresp), udata->outlen));
		if (err_code) {
			ibdev_dbg(&iwdev->ibdev, "VERBS: copy_to_udata failed\n");
			kc_irdma_destroy_qp(&iwqp->ibqp, udata);
			return ERR_PTR(err_code);
		}
	}

	init_completion(&iwqp->free_qp);
	return &iwqp->ibqp;

error:
	irdma_free_qp_rsrc(iwqp);

	return ERR_PTR(err_code);
}

#endif /* CREATE_QP_VER_1 */
/**
 * irdma_destroy_qp - destroy qp
 * @ibqp: qp's ib pointer also to get to device's qp address
 * @udata: user data
 */
#ifdef DESTROY_QP_VER_2
int irdma_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
#endif
#if defined(DESTROY_QP_VER_1)
int irdma_destroy_qp(struct ib_qp *ibqp)
#endif
{
	struct irdma_qp *iwqp = to_iwqp(ibqp);
	struct irdma_device *iwdev = iwqp->iwdev;

	if (iwqp->sc_qp.qp_uk.destroy_pending)
		goto free_rsrc;
	iwqp->sc_qp.qp_uk.destroy_pending = true;

	if (iwqp->iwarp_state >= IRDMA_QP_STATE_IDLE)
		irdma_modify_qp_to_err(&iwqp->sc_qp);

	if (!iwqp->user_mode) {
		if (iwqp->iwscq) {
			irdma_clean_cqes(iwqp, iwqp->iwscq);
			if (iwqp->iwrcq != iwqp->iwscq)
				irdma_clean_cqes(iwqp, iwqp->iwrcq);
		}
	}
	irdma_qp_rem_ref(&iwqp->ibqp);
	wait_for_completion(&iwqp->free_qp);
	irdma_free_lsmm_rsrc(iwqp);
	if (!iwdev->rf->reset && irdma_cqp_qp_destroy_cmd(&iwdev->rf->sc_dev, &iwqp->sc_qp))
		return (iwdev->rf->rdma_ver <= IRDMA_GEN_2 && !iwqp->user_mode) ? 0 : -ENOTRECOVERABLE;
free_rsrc:
	irdma_remove_push_mmap_entries(iwqp);
	irdma_free_qp_rsrc(iwqp);

	return 0;
}

/**
 * irdma_create_cq - create cq
 * @ibcq: CQ allocated
 * @attr: attributes for cq
 * @udata: user data
 */
#ifdef CREATE_CQ_VER_3
int irdma_create_cq(struct ib_cq *ibcq,
		    const struct ib_cq_init_attr *attr,
		    struct ib_udata *udata)
#elif defined(CREATE_CQ_VER_2)
struct ib_cq *irdma_create_cq(struct ib_device *ibdev,
			      const struct ib_cq_init_attr *attr,
			      struct ib_udata *udata)
#elif defined(CREATE_CQ_VER_1)
struct ib_cq *irdma_create_cq(struct ib_device *ibdev,
			      const struct ib_cq_init_attr *attr,
			      struct ib_ucontext *context,
			      struct ib_udata *udata)
#endif
{
#define IRDMA_CREATE_CQ_MIN_REQ_LEN offsetofend(struct irdma_create_cq_req, user_cq_buf)
#define IRDMA_CREATE_CQ_MIN_RESP_LEN offsetofend(struct irdma_create_cq_resp, cq_size)
#ifdef CREATE_CQ_VER_3
	struct ib_device *ibdev = ibcq->device;
#endif
	struct irdma_device *iwdev = to_iwdev(ibdev);
	struct irdma_pci_f *rf = iwdev->rf;
#ifdef CREATE_CQ_VER_3
	struct irdma_cq *iwcq = to_iwcq(ibcq);
#else
	struct irdma_cq *iwcq;
#endif
	u32 cq_num = 0;
	struct irdma_sc_cq *cq;
	struct irdma_sc_dev *dev = &rf->sc_dev;
	struct irdma_cq_init_info info = {};
	int status;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct irdma_cq_uk_init_info *ukinfo = &info.cq_uk_init_info;
	unsigned long flags;
	int err_code;
	int entries = attr->cqe;
	bool cqe_64byte_ena;

#ifdef CREATE_CQ_VER_3
	err_code = cq_validate_flags(attr->flags, dev->hw_attrs.uk_attrs.hw_rev);
	if (err_code)
		return err_code;

	if (udata && (udata->inlen < IRDMA_CREATE_CQ_MIN_REQ_LEN ||
		      udata->outlen < IRDMA_CREATE_CQ_MIN_RESP_LEN))
		return -EINVAL;
#else
	err_code = cq_validate_flags(attr->flags, dev->hw_attrs.uk_attrs.hw_rev);
	if (err_code)
		return ERR_PTR(err_code);

	if (udata && (udata->inlen < IRDMA_CREATE_CQ_MIN_REQ_LEN ||
		      udata->outlen < IRDMA_CREATE_CQ_MIN_RESP_LEN))
		return ERR_PTR(-EINVAL);

	iwcq = kzalloc(sizeof(*iwcq), GFP_KERNEL);
	if (!iwcq)
		return ERR_PTR(-ENOMEM);
#endif
	err_code = irdma_alloc_rsrc(rf, rf->allocated_cqs, rf->max_cq, &cq_num,
				    &rf->next_cq);
	if (err_code)
#ifdef CREATE_CQ_VER_3
		return err_code;
#else
		goto error;
#endif
	cq = &iwcq->sc_cq;
	cq->back_cq = iwcq;
	refcount_set(&iwcq->refcnt, 1);
	spin_lock_init(&iwcq->lock);
	INIT_LIST_HEAD(&iwcq->resize_list);
	INIT_LIST_HEAD(&iwcq->cmpl_generated);
	info.dev = dev;
	ukinfo->cq_size = max(entries, 4);
	ukinfo->cq_id = cq_num;
	cqe_64byte_ena = (dev->hw_attrs.uk_attrs.feature_flags & IRDMA_FEATURE_64_BYTE_CQE) ? true : false;
	ukinfo->avoid_mem_cflct = cqe_64byte_ena;
	iwcq->ibcq.cqe = info.cq_uk_init_info.cq_size;
	atomic_set(&iwcq->armed, 0);
	if (attr->comp_vector < rf->ceqs_count)
		info.ceq_id = attr->comp_vector;
	info.ceq_id_valid = true;
	info.ceqe_mask = 1;
	info.type = IRDMA_CQ_TYPE_IWARP;
	info.vsi = &iwdev->vsi;

	if (udata) {
		struct irdma_ucontext *ucontext;
		struct irdma_create_cq_req req = {};
		struct irdma_cq_mr *cqmr;
		struct irdma_pbl *iwpbl;
		struct irdma_pbl *iwpbl_shadow;
		struct irdma_cq_mr *cqmr_shadow;

		iwcq->user_mode = true;
		ucontext = kc_get_ucontext(udata);

		if (ib_copy_from_udata(&req, udata,
				       min(sizeof(req), udata->inlen))) {
			err_code = -EFAULT;
			goto cq_free_rsrc;
		}

		spin_lock_irqsave(&ucontext->cq_reg_mem_list_lock, flags);
		iwpbl = irdma_get_pbl((unsigned long)req.user_cq_buf,
				      &ucontext->cq_reg_mem_list);
		spin_unlock_irqrestore(&ucontext->cq_reg_mem_list_lock, flags);
		if (!iwpbl) {
			err_code = -EPROTO;
			goto cq_free_rsrc;
		}
		iwcq->iwpbl = iwpbl;
		iwcq->cq_mem_size = 0;
		cqmr = &iwpbl->cq_mr;

		if (rf->sc_dev.hw_attrs.uk_attrs.feature_flags &
		    IRDMA_FEATURE_CQ_RESIZE && !ucontext->legacy_mode) {
			spin_lock_irqsave(&ucontext->cq_reg_mem_list_lock, flags);
			iwpbl_shadow = irdma_get_pbl((unsigned long)req.user_shadow_area,
						     &ucontext->cq_reg_mem_list);
			spin_unlock_irqrestore(&ucontext->cq_reg_mem_list_lock, flags);

			if (!iwpbl_shadow) {
				err_code = -EPROTO;
				goto cq_free_rsrc;
			}
			iwcq->iwpbl_shadow = iwpbl_shadow;
			cqmr_shadow = &iwpbl_shadow->cq_mr;
			info.shadow_area_pa = cqmr_shadow->cq_pbl.addr;
			cqmr->split = true;
		} else {
			info.shadow_area_pa = cqmr->shadow;
		}
		if (iwpbl->pbl_allocated) {
			info.virtual_map = true;
			info.pbl_chunk_size = 1;
			info.first_pm_pbl_idx = cqmr->cq_pbl.idx;
		} else {
			info.cq_base_pa = cqmr->cq_pbl.addr;
		}
	} else {
		/* Kmode allocations */
		int rsize;

		if (entries < 1 || entries > rf->max_cqe) {
			err_code = -EINVAL;
			goto cq_free_rsrc;
		}

		entries++;
		if (!cqe_64byte_ena && dev->hw_attrs.uk_attrs.hw_rev >= IRDMA_GEN_2)
			entries *= 2;
		ukinfo->cq_size = entries;

		if (cqe_64byte_ena)
			rsize = info.cq_uk_init_info.cq_size * sizeof(struct irdma_extended_cqe);
		else
			rsize = info.cq_uk_init_info.cq_size * sizeof(struct irdma_cqe);
		iwcq->kmem.size = ALIGN(round_up(rsize, IRDMA_HW_PAGE_SIZE),
					IRDMA_HW_PAGE_SIZE);
		iwcq->kmem.va = dma_alloc_coherent(dev->hw->device,
						   iwcq->kmem.size,
						   &iwcq->kmem.pa, GFP_KERNEL);
		if (!iwcq->kmem.va) {
			err_code = -ENOMEM;
			goto cq_free_rsrc;
		}

		iwcq->kmem_shadow.size = ALIGN(IRDMA_SHADOW_AREA_SIZE << 3,
					       64);
		iwcq->kmem_shadow.va = dma_alloc_coherent(dev->hw->device,
							  iwcq->kmem_shadow.size,
							  &iwcq->kmem_shadow.pa,
							  GFP_KERNEL);

		if (!iwcq->kmem_shadow.va) {
			err_code = -ENOMEM;
			goto cq_kmem_free;
		}
		info.shadow_area_pa = iwcq->kmem_shadow.pa;
		ukinfo->shadow_area = iwcq->kmem_shadow.va;
		ukinfo->cq_base = iwcq->kmem.va;
		info.cq_base_pa = iwcq->kmem.pa;
	}

	info.shadow_read_threshold = min(info.cq_uk_init_info.cq_size / 2,
					 (u32)IRDMA_MAX_CQ_READ_THRESH);
	if (irdma_sc_cq_init(cq, &info)) {
		ibdev_dbg(&iwdev->ibdev, "VERBS: init cq fail\n");
		err_code = -EPROTO;
		goto cq_kmem_free;
	}

	cqp_request = irdma_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request) {
		err_code = -ENOMEM;
		goto cq_kmem_free;
	}
	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = IRDMA_OP_CQ_CREATE;
	cqp_info->post_sq = 1;
	cqp_info->in.u.cq_create.cq = cq;
	cqp_info->in.u.cq_create.check_overflow = true;
	cqp_info->in.u.cq_create.scratch = (uintptr_t)cqp_request;
	status = irdma_handle_cqp_op(rf, cqp_request);
	irdma_put_cqp_request(&rf->cqp, cqp_request);
	if (status) {
		err_code = -ENOMEM;
		goto cq_kmem_free;
	}

	if (udata) {
		struct irdma_create_cq_resp resp = {};

		resp.cq_id = info.cq_uk_init_info.cq_id;
		resp.cq_size = info.cq_uk_init_info.cq_size;
		if (ib_copy_to_udata(udata, &resp,
				     min(sizeof(resp), udata->outlen))) {
			ibdev_dbg(&iwdev->ibdev, "VERBS: copy to user data\n");
			err_code = -EPROTO;
			goto cq_destroy;
		}
	}

	rf->cq_table[cq_num] = iwcq;
	init_completion(&iwcq->free_cq);

#ifdef CREATE_CQ_VER_3
	return 0;
#else
	return &iwcq->ibcq;
#endif
cq_destroy:
	irdma_cq_wq_destroy(rf, cq);
cq_kmem_free:
	if (!iwcq->user_mode) {
		dma_free_coherent(dev->hw->device, iwcq->kmem.size,
				  iwcq->kmem.va, iwcq->kmem.pa);
		iwcq->kmem.va = NULL;
		dma_free_coherent(dev->hw->device, iwcq->kmem_shadow.size,
				  iwcq->kmem_shadow.va, iwcq->kmem_shadow.pa);
		iwcq->kmem_shadow.va = NULL;
	}
cq_free_rsrc:
	irdma_free_rsrc(rf, rf->allocated_cqs, cq_num);
#ifdef CREATE_CQ_VER_3
	return err_code;
#else
error:
	kfree(iwcq);
	return ERR_PTR(err_code);
#endif
}

#ifdef NEED_RDMA_UMEM_BLOCK_ITER_NEXT
void kc__rdma_block_iter_start(struct kc_ib_block_iter *biter,
				struct scatterlist *sglist, unsigned int nents,
				unsigned long pgsz)
{
	memset(biter, 0, sizeof(*biter));
	biter->__sg = sglist;
	biter->__sg_nents = nents;

	/* Driver provides best block size to use */
	biter->__pg_bit = __fls(pgsz);
}

bool kc__rdma_block_iter_next(struct kc_ib_block_iter *biter)
{
	unsigned int block_offset;
	unsigned int sg_delta;

	if (!biter->__sg_nents || !biter->__sg)
		return false;

	biter->__dma_addr = sg_dma_address(biter->__sg) + biter->__sg_advance;
	block_offset = biter->__dma_addr & (BIT_ULL(biter->__pg_bit) - 1);
	sg_delta = BIT_ULL(biter->__pg_bit) - block_offset;

	if (sg_dma_len(biter->__sg) - biter->__sg_advance > sg_delta) {
		biter->__sg_advance += sg_delta;
	} else {
		biter->__sg_advance = 0;
		biter->__sg = sg_next(biter->__sg);
		biter->__sg_nents--;
	}

	return true;
}
#endif /* NEED_RDMA_UMEM_BLOCK_ITER_NEXT */

#ifdef COPY_USER_PGADDR_VER_1
void irdma_copy_user_pgaddrs(struct irdma_mr *iwmr, u64 *pbl,
			     enum irdma_pble_level level)
{
	struct ib_umem *region = iwmr->region;
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	int chunk_pages, entry, i;
	struct scatterlist *sg;
	u64 pg_addr = 0;
	struct irdma_pble_alloc *palloc = &iwpbl->pble_alloc;
	struct irdma_pble_info *pinfo;
	u32 idx = 0;
	u32 pbl_cnt = 0;

	pinfo = (level == PBLE_LEVEL_1) ? NULL : palloc->level2.leaf;
	for_each_sg(region->sg_head.sgl, sg, region->nmap, entry) {
		chunk_pages = DIV_ROUND_UP(sg_dma_len(sg), iwmr->page_size);
		if (iwmr->type == IRDMA_MEMREG_TYPE_QP && !iwpbl->qp_mr.sq_page)
			iwpbl->qp_mr.sq_page = sg_page(sg);
		for (i = 0; i < chunk_pages; i++) {
			pg_addr = sg_dma_address(sg) + (i * iwmr->page_size);
			if ((entry + i) == 0)
				*pbl = pg_addr & iwmr->page_msk;
			else if (!(pg_addr & ~iwmr->page_msk))
				*pbl = pg_addr;
			else
				continue;
			if (++pbl_cnt == palloc->total_cnt)
				break;
			pbl = irdma_next_pbl_addr(pbl, &pinfo, &idx);
		}
	}
}
#endif

/**
 * irdma_destroy_ah - Destroy address handle
 * @ibah: pointer to address handle
 * @ah_flags: destroy flags
 */
#if defined(DESTROY_AH_VER_4)
int irdma_destroy_ah(struct ib_ah *ibah, u32 ah_flags)
{
	struct irdma_device *iwdev = to_iwdev(ibah->device);
	struct irdma_ah *ah = to_iwah(ibah);

	if (ah->parent_ah) {
		mutex_lock(&iwdev->ah_tbl_lock);
		if (!refcount_dec_and_test(&ah->parent_ah->refcnt)) {
			mutex_unlock(&iwdev->ah_tbl_lock);
			return 0;
		}
		hash_del(&ah->parent_ah->list);
		kfree(ah->parent_ah);
		iwdev->ah_list_cnt--;
		mutex_unlock(&iwdev->ah_tbl_lock);
	}
	irdma_ah_cqp_op(iwdev->rf, &ah->sc_ah, IRDMA_OP_AH_DESTROY,
			false, NULL, ah);

	irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs,
			ah->sc_ah.ah_info.ah_idx);

	return 0;
}
#endif

#if defined(DESTROY_AH_VER_3)
void irdma_destroy_ah(struct ib_ah *ibah, u32 ah_flags)
{
	struct irdma_device *iwdev = to_iwdev(ibah->device);
	struct irdma_ah *ah = to_iwah(ibah);

	if (ah->parent_ah) {
		mutex_lock(&iwdev->ah_tbl_lock);
		if (!refcount_dec_and_test(&ah->parent_ah->refcnt)) {
			mutex_unlock(&iwdev->ah_tbl_lock);
			return;
		}
		hash_del(&ah->parent_ah->list);
		kfree(ah->parent_ah);
		iwdev->ah_list_cnt--;
		mutex_unlock(&iwdev->ah_tbl_lock);
	}
	irdma_ah_cqp_op(iwdev->rf, &ah->sc_ah, IRDMA_OP_AH_DESTROY,
			false, NULL, ah);

	irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs,
			ah->sc_ah.ah_info.ah_idx);
}
#endif

#if defined(DESTROY_AH_VER_2)
int irdma_destroy_ah(struct ib_ah *ibah, u32 ah_flags)
{
	struct irdma_device *iwdev = to_iwdev(ibah->device);
	struct irdma_ah *ah = to_iwah(ibah);

	if (ah->parent_ah) {
		mutex_lock(&iwdev->ah_tbl_lock);
		if (!refcount_dec_and_test(&ah->parent_ah->refcnt)) {
			mutex_unlock(&iwdev->ah_tbl_lock);
			goto done;
		}
		hash_del(&ah->parent_ah->list);
		kfree(ah->parent_ah);
		iwdev->ah_list_cnt--;
		mutex_unlock(&iwdev->ah_tbl_lock);
	}
	irdma_ah_cqp_op(iwdev->rf, &ah->sc_ah, IRDMA_OP_AH_DESTROY,
			false, NULL, ah);

	irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs,
			ah->sc_ah.ah_info.ah_idx);

done:
	kfree(ah);
	return 0;
}
#endif

#if defined(DESTROY_AH_VER_1)
int irdma_destroy_ah(struct ib_ah *ibah)
{
	struct irdma_device *iwdev = to_iwdev(ibah->device);
	struct irdma_ah *ah = to_iwah(ibah);

	if (ah->parent_ah) {
		mutex_lock(&iwdev->ah_tbl_lock);
		if (!refcount_dec_and_test(&ah->parent_ah->refcnt)) {
			mutex_unlock(&iwdev->ah_tbl_lock);
			goto done;
		}
		hash_del(&ah->parent_ah->list);
		kfree(ah->parent_ah);
		iwdev->ah_list_cnt--;
		mutex_unlock(&iwdev->ah_tbl_lock);
	}
	irdma_ah_cqp_op(iwdev->rf, &ah->sc_ah, IRDMA_OP_AH_DESTROY,
			false, NULL, ah);

	irdma_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs,
			ah->sc_ah.ah_info.ah_idx);

done:
	kfree(ah);
	return 0;
}
#endif

#ifdef DEREG_MR_VER_2
int irdma_dereg_mr(struct ib_mr *ib_mr, struct ib_udata *udata)
#else
int irdma_dereg_mr(struct ib_mr *ib_mr)
#endif
{
	struct irdma_mr *iwmr = to_iwmr(ib_mr);
	struct irdma_device *iwdev = to_iwdev(ib_mr->device);
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	int ret;

	if (iwmr->type != IRDMA_MEMREG_TYPE_MEM) {
		if (iwmr->region) {
			struct irdma_ucontext *ucontext;
#ifdef DEREG_MR_VER_2

			ucontext = rdma_udata_to_drv_context(udata,
							     struct irdma_ucontext,
							     ibucontext);
#else
			struct ib_pd *ibpd = ib_mr->pd;

			ucontext = to_ucontext(ibpd->uobject->context);
#endif
			irdma_del_memlist(iwmr, ucontext);
		}
		goto done;
	}

	ret = irdma_hwdereg_mr(ib_mr);
	if (ret)
		return ret;

	irdma_free_stag(iwdev, iwmr->stag);
done:
	if (iwpbl->pbl_allocated)
		irdma_free_pble(iwdev->rf->pble_rsrc, &iwpbl->pble_alloc);

	if (iwmr->region)
		ib_umem_release(iwmr->region);

	kfree(iwmr);

	return 0;
}

#ifdef REREG_MR_VER_1
/*
 *  irdma_rereg_user_mr - Re-Register a user memory region
 *  @ibmr: ib mem to access iwarp mr pointer
 *  @flags: bit mask to indicate which of the attr's of MR modified
 *  @start: virtual start address
 *  @len: length of mr
 *  @virt: virtual address
 *  @new access flags: bit mask of access flags
 *  @new_pd: ptr of pd
 *  @udata: user data
 */
int irdma_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start, u64 len,
			u64 virt, int new_access, struct ib_pd *new_pd,
			struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(ib_mr->device);
	struct irdma_mr *iwmr = to_iwmr(ib_mr);
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	int ret;

	if (len > iwdev->rf->sc_dev.hw_attrs.max_mr_size)
		return -EINVAL;

	if (flags & ~(IB_MR_REREG_TRANS | IB_MR_REREG_PD | IB_MR_REREG_ACCESS))
		return -EOPNOTSUPP;

	ret = irdma_hwdereg_mr(ib_mr);
	if (ret)
		return ret;

	if (flags & IB_MR_REREG_ACCESS)
		iwmr->access = new_access;

	if (flags & IB_MR_REREG_PD) {
		iwmr->ibmr.pd = new_pd;
		iwmr->ibmr.device = new_pd->device;
	}

	if (flags & IB_MR_REREG_TRANS) {
		if (iwpbl->pbl_allocated) {
			irdma_free_pble(iwdev->rf->pble_rsrc,
					&iwpbl->pble_alloc);
			iwpbl->pbl_allocated = false;
		}
		if (iwmr->region) {
			ib_umem_release(iwmr->region);
			iwmr->region = NULL;
		}

		ib_mr = irdma_rereg_mr_trans(iwmr, start, len, virt, udata);
		if (IS_ERR(ib_mr))
			return PTR_ERR(ib_mr);

	} else {
		ret = irdma_hwreg_mr(iwdev, iwmr, iwmr->access);
		if (ret)
			return ret;
	}

	return 0;
}
#endif
#ifdef REREG_MR_VER_2
/*
 *  irdma_rereg_user_mr - Re-Register a user memory region(MR)
 *  @ibmr: ib mem to access iwarp mr pointer
 *  @flags: bit mask to indicate which of the attr's of MR modified
 *  @start: virtual start address
 *  @len: length of mr
 *  @virt: virtual address
 *  @new_access: bit mask of access flags
 *  @new_pd: ptr of pd
 *  @udata: user data
 *
 *  Return:
 *  NULL - Success, existing MR updated
 *  ERR_PTR - error occurred
 */
struct ib_mr *irdma_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start,
				  u64 len, u64 virt, int new_access,
				  struct ib_pd *new_pd,
				  struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(ib_mr->device);
	struct irdma_mr *iwmr = to_iwmr(ib_mr);
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	int ret;

	if (len > iwdev->rf->sc_dev.hw_attrs.max_mr_size)
		return ERR_PTR(-EINVAL);

	if (flags & ~(IB_MR_REREG_TRANS | IB_MR_REREG_PD | IB_MR_REREG_ACCESS))
		return ERR_PTR(-EOPNOTSUPP);

	ret = irdma_hwdereg_mr(ib_mr);
	if (ret)
		return ERR_PTR(ret);

	if (flags & IB_MR_REREG_ACCESS)
		iwmr->access = new_access;

	if (flags & IB_MR_REREG_PD) {
		iwmr->ibmr.pd = new_pd;
		iwmr->ibmr.device = new_pd->device;
	}

	if (flags & IB_MR_REREG_TRANS) {
		if (iwpbl->pbl_allocated) {
			irdma_free_pble(iwdev->rf->pble_rsrc,
					&iwpbl->pble_alloc);
			iwpbl->pbl_allocated = false;
		}
		if (iwmr->region) {
			ib_umem_release(iwmr->region);
			iwmr->region = NULL;
		}

		ib_mr = irdma_rereg_mr_trans(iwmr, start, len, virt, udata);
		if (IS_ERR(ib_mr))
			return ib_mr;
	} else {
		ret = irdma_hwreg_mr(iwdev, iwmr, iwmr->access);
		if (ret)
			return ERR_PTR(ret);
	}

	return NULL;
}
#endif
#ifdef SET_ROCE_CM_INFO_VER_3

int kc_irdma_set_roce_cm_info(struct irdma_qp *iwqp, struct ib_qp_attr *attr,
			      u16 *vlan_id)
{
	const struct ib_gid_attr *sgid_attr;
	int ret;
	struct irdma_av *av = &iwqp->roce_ah.av;

	sgid_attr = attr->ah_attr.grh.sgid_attr;
	if (kc_deref_sgid_attr(sgid_attr)) {
		ret = rdma_read_gid_l2_fields(sgid_attr, vlan_id,
					      iwqp->ctx_info.roce_info->mac_addr);
		if (ret)
			return ret;
	}

	av->net_type = kc_rdma_gid_attr_network_type(sgid_attr,
						     sgid_attr->gid_type,
						     &sgid);

	rdma_gid2ip((struct sockaddr *)&av->sgid_addr, &sgid_attr->gid);

	iwqp->ctx_info.user_pri = irdma_roce_get_vlan_prio(sgid_attr->ndev,
							   iwqp->ctx_info.user_pri);
	iwqp->sc_qp.user_pri = iwqp->ctx_info.user_pri;

	return 0;
}
#endif

#ifdef SET_ROCE_CM_INFO_VER_2
int kc_irdma_set_roce_cm_info(struct irdma_qp *iwqp, struct ib_qp_attr *attr,
			      u16 *vlan_id)
{
	const struct ib_gid_attr *sgid_attr;
	struct irdma_av *av = &iwqp->roce_ah.av;

	sgid_attr = attr->ah_attr.grh.sgid_attr;
	if (kc_deref_sgid_attr(sgid_attr)) {
		*vlan_id = rdma_vlan_dev_vlan_id(kc_deref_sgid_attr(sgid_attr));
		ether_addr_copy(iwqp->ctx_info.roce_info->mac_addr,
				kc_deref_sgid_attr(sgid_attr)->dev_addr);
	}
	av->net_type = kc_rdma_gid_attr_network_type(sgid_attr,
						     sgid_attr->gid_type,
						     &sgid);
	rdma_gid2ip((struct sockaddr *)&av->sgid_addr, &sgid_attr->gid);
	iwqp->ctx_info.user_pri = irdma_roce_get_vlan_prio(sgid_attr->ndev,
							   iwqp->ctx_info.user_pri);
	iwqp->sc_qp.user_pri = iwqp->ctx_info.user_pri;

	return 0;
}
#endif

#ifdef SET_ROCE_CM_INFO_VER_1
int kc_irdma_set_roce_cm_info(struct irdma_qp *iwqp, struct ib_qp_attr *attr,
			      u16 *vlan_id)
{
	int ret;
	union ib_gid sgid;
	struct ib_gid_attr sgid_attr;
	struct irdma_av *av = &iwqp->roce_ah.av;

	ret = ib_get_cached_gid(iwqp->ibqp.device, attr->ah_attr.port_num,
				attr->ah_attr.grh.sgid_index, &sgid,
				&sgid_attr);
	if (ret)
		return ret;

	if (kc_deref_sgid_attr(sgid_attr)) {
		*vlan_id = rdma_vlan_dev_vlan_id(kc_deref_sgid_attr(sgid_attr));
		ether_addr_copy(iwqp->ctx_info.roce_info->mac_addr,
				kc_deref_sgid_attr(sgid_attr)->dev_addr);
	}

	av->net_type = kc_rdma_gid_attr_network_type(sgid_attr,
						     sgid_attr.gid_type,
						     &sgid);
	rdma_gid2ip((struct sockaddr *)&av->sgid_addr, &sgid);
	iwqp->ctx_info.user_pri = irdma_roce_get_vlan_prio(sgid_attr.ndev,
							   iwqp->ctx_info.user_pri);
	dev_put(kc_deref_sgid_attr(sgid_attr));
	iwqp->sc_qp.user_pri = iwqp->ctx_info.user_pri;

	return 0;
}

#endif
#ifdef IRDMA_DESTROY_CQ_VER_4
/**
 * irdma_destroy_cq - destroy cq
 * @ib_cq: cq pointer
 * @udata: user data
 */
int irdma_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(ib_cq->device);
	struct irdma_cq *iwcq = to_iwcq(ib_cq);
	struct irdma_sc_cq *cq = &iwcq->sc_cq;
	struct irdma_sc_dev *dev = cq->dev;
	struct irdma_sc_ceq *ceq = dev->ceq[cq->ceq_id];
	struct irdma_ceq *iwceq = container_of(ceq, struct irdma_ceq, sc_ceq);
	unsigned long flags;

	spin_lock_irqsave(&iwcq->lock, flags);
	if (!list_empty(&iwcq->cmpl_generated))
		irdma_remove_cmpls_list(iwcq);
	if (!list_empty(&iwcq->resize_list))
		irdma_process_resize_list(iwcq, iwdev, NULL);
	spin_unlock_irqrestore(&iwcq->lock, flags);

	irdma_cq_rem_ref(ib_cq);
	wait_for_completion(&iwcq->free_cq);

	irdma_cq_wq_destroy(iwdev->rf, cq);

	spin_lock_irqsave(&iwceq->ce_lock, flags);
	irdma_sc_cleanup_ceqes(cq, ceq);
	spin_unlock_irqrestore(&iwceq->ce_lock, flags);
	irdma_cq_free_rsrc(iwdev->rf, iwcq);

	return 0;
}

#endif /* IRDMA_DESTROY_CQ_VER_4 */
#ifdef IRDMA_DESTROY_CQ_VER_3
/**
 * irdma_destroy_cq - destroy cq
 * @ib_cq: cq pointer
 * @udata: user data
 */
void irdma_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(ib_cq->device);
	struct irdma_cq *iwcq = to_iwcq(ib_cq);
	struct irdma_sc_cq *cq = &iwcq->sc_cq;
	struct irdma_sc_dev *dev = cq->dev;
	struct irdma_sc_ceq *ceq = dev->ceq[cq->ceq_id];
	struct irdma_ceq *iwceq = container_of(ceq, struct irdma_ceq, sc_ceq);
	unsigned long flags;

	spin_lock_irqsave(&iwcq->lock, flags);
	if (!list_empty(&iwcq->cmpl_generated))
		irdma_remove_cmpls_list(iwcq);
	if (!list_empty(&iwcq->resize_list))
		irdma_process_resize_list(iwcq, iwdev, NULL);
	spin_unlock_irqrestore(&iwcq->lock, flags);

	irdma_cq_rem_ref(ib_cq);
	wait_for_completion(&iwcq->free_cq);

	irdma_cq_wq_destroy(iwdev->rf, cq);

	spin_lock_irqsave(&iwceq->ce_lock, flags);
	irdma_sc_cleanup_ceqes(cq, ceq);
	spin_unlock_irqrestore(&iwceq->ce_lock, flags);
	irdma_cq_free_rsrc(iwdev->rf, iwcq);
}

#endif /* IRDMA_DESTROY_CQ_VER_3 */
#ifdef IRDMA_DESTROY_CQ_VER_2
/**
 * irdma_destroy_cq - destroy cq
 * @ib_cq: cq pointer
 * @udata: user data
 */
int irdma_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(ib_cq->device);
	struct irdma_cq *iwcq = to_iwcq(ib_cq);
	struct irdma_sc_cq *cq = &iwcq->sc_cq;
	struct irdma_sc_dev *dev = cq->dev;
	struct irdma_sc_ceq *ceq = dev->ceq[cq->ceq_id];
	struct irdma_ceq *iwceq = container_of(ceq, struct irdma_ceq, sc_ceq);
	unsigned long flags;

	spin_lock_irqsave(&iwcq->lock, flags);
	if (!list_empty(&iwcq->cmpl_generated))
		irdma_remove_cmpls_list(iwcq);
	if (!list_empty(&iwcq->resize_list))
		irdma_process_resize_list(iwcq, iwdev, NULL);
	spin_unlock_irqrestore(&iwcq->lock, flags);

	irdma_cq_rem_ref(ib_cq);
	wait_for_completion(&iwcq->free_cq);

	irdma_cq_wq_destroy(iwdev->rf, cq);

	spin_lock_irqsave(&iwceq->ce_lock, flags);
	irdma_sc_cleanup_ceqes(cq, ceq);
	spin_unlock_irqrestore(&iwceq->ce_lock, flags);

	irdma_cq_free_rsrc(iwdev->rf, iwcq);
	kfree(iwcq);

	return 0;
}

#endif /* IRDMA_DESTROY_CQ_VER_2 */
#ifdef IRDMA_DESTROY_CQ_VER_1
/**
 * irdma_destroy_cq - destroy cq
 * @ib_cq: cq pointer
 */
int irdma_destroy_cq(struct ib_cq *ib_cq)
{
	struct irdma_device *iwdev = to_iwdev(ib_cq->device);
	struct irdma_cq *iwcq = to_iwcq(ib_cq);
	struct irdma_sc_cq *cq = &iwcq->sc_cq;
	struct irdma_sc_dev *dev = cq->dev;
	struct irdma_sc_ceq *ceq = dev->ceq[cq->ceq_id];
	struct irdma_ceq *iwceq = container_of(ceq, struct irdma_ceq, sc_ceq);
	unsigned long flags;

	spin_lock_irqsave(&iwcq->lock, flags);
	if (!list_empty(&iwcq->cmpl_generated))
		irdma_remove_cmpls_list(iwcq);
	if (!list_empty(&iwcq->resize_list))
		irdma_process_resize_list(iwcq, iwdev, NULL);
	spin_unlock_irqrestore(&iwcq->lock, flags);

	irdma_cq_rem_ref(ib_cq);
	wait_for_completion(&iwcq->free_cq);

	irdma_cq_wq_destroy(iwdev->rf, cq);

	spin_lock_irqsave(&iwceq->ce_lock, flags);
	irdma_sc_cleanup_ceqes(cq, ceq);
	spin_unlock_irqrestore(&iwceq->ce_lock, flags);

	irdma_cq_free_rsrc(iwdev->rf, iwcq);
	kfree(iwcq);

	return 0;
}

#endif /* IRDMA_DESTROY_CQ_VER_1 */
#ifdef IRDMA_DESTROY_SRQ_VER_3
/**
 * irdma_destroy_srq - destroy srq
 * @ibsrq: srq pointer
 * @udata: user data
 */
int irdma_destroy_srq(struct ib_srq *ibsrq, struct ib_udata *udata)
{
	struct irdma_device *iwdev  = to_iwdev(ibsrq->device);
	struct irdma_srq *iwsrq  = to_iwsrq(ibsrq);
	struct irdma_sc_srq *srq = &iwsrq->sc_srq;

	irdma_srq_rem_ref(ibsrq);
	wait_for_completion(&iwsrq->free_srq);

	irdma_srq_wq_destroy(iwdev->rf, srq);
	irdma_srq_free_rsrc(iwdev->rf, iwsrq);
	kfree(iwsrq->sg_list);
	return 0;
}

#endif /* IRDMA_DESTROY_SRQ_VER_3 */
#ifdef IRDMA_DESTROY_SRQ_VER_2
/**
 * irdma_destroy_srq - destroy srq
 * @ibsrq: srq pointer
 * @udata: user data
 */
void irdma_destroy_srq(struct ib_srq *ibsrq, struct ib_udata *udata)
{
	struct irdma_device *iwdev  = to_iwdev(ibsrq->device);
	struct irdma_srq *iwsrq  = to_iwsrq(ibsrq);
	struct irdma_sc_srq *srq = &iwsrq->sc_srq;

	irdma_srq_rem_ref(ibsrq);
	wait_for_completion(&iwsrq->free_srq);

	irdma_srq_wq_destroy(iwdev->rf, srq);
	irdma_srq_free_rsrc(iwdev->rf, iwsrq);
	kfree(iwsrq->sg_list);
}

#endif /* IRDMA_DESTROY_SRQ_VER_2 */
#ifdef IRDMA_DESTROY_SRQ_VER_1
/**
 * irdma_destroy_srq - destroy srq
 * @ibsrq: srq pointer
 */
int irdma_destroy_srq(struct ib_srq *ibsrq)
{
	struct irdma_device *iwdev  = to_iwdev(ibsrq->device);
	struct irdma_srq *iwsrq  = to_iwsrq(ibsrq);
	struct irdma_sc_srq *srq = &iwsrq->sc_srq;

	irdma_srq_rem_ref(ibsrq);
	wait_for_completion(&iwsrq->free_srq);

	irdma_srq_wq_destroy(iwdev->rf, srq);
	irdma_srq_free_rsrc(iwdev->rf, iwsrq);
	kfree(iwsrq->sg_list);
	kfree(iwsrq);
	return 0;
}

#endif /* IRDMA_DESTROY_SRQ_VER_1 */
#ifdef IRDMA_ALLOC_MW_VER_2
/**
 * irdma_alloc_mw - Allocate memory window
 * @ibmw: Memory Window
 * @udata: user data pointer
 */
int irdma_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(ibmw->device);
	struct irdma_mr *iwmr = to_iwmw(ibmw);
	int err_code;
	u32 stag;

	/* This is required for Linux kernels < 5.1, where MW type
	 * is not validated in ib_uverbs_alloc_mw function.
	 */
	if (ibmw->type != IB_MW_TYPE_1 && ibmw->type != IB_MW_TYPE_2)
		return -EINVAL;

	stag = irdma_create_stag(iwdev);
	if (!stag)
		return -ENOMEM;

	iwmr->stag = stag;
	ibmw->rkey = stag;

	err_code = irdma_hw_alloc_mw(iwdev, iwmr);
	if (err_code) {
		irdma_free_stag(iwdev, stag);
		return err_code;
	}

	return 0;
}

#endif /* IRDMA_ALLOC_MW_VER_2 */
#ifdef IRDMA_ALLOC_MW_VER_1
/**
 * irdma_alloc_mw - Allocate memory window
 * @pd: Protection domain
 * @type: Window type
 * @udata: user data pointer
 */
struct ib_mw *irdma_alloc_mw(struct ib_pd *pd, enum ib_mw_type type,
			     struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(pd->device);
	struct irdma_mr *iwmr;
	int err_code;
	u32 stag;

	/* This is required for Linux kernels < 5.1, where MW type
	 * is not validated in ib_uverbs_alloc_mw function.
	 */
	if (type != IB_MW_TYPE_1 && type != IB_MW_TYPE_2)
		return ERR_PTR(-EINVAL);

	iwmr = kzalloc(sizeof(*iwmr), GFP_KERNEL);
	if (!iwmr)
		return ERR_PTR(-ENOMEM);

	stag = irdma_create_stag(iwdev);
	if (!stag) {
		kfree(iwmr);
		return ERR_PTR(-ENOMEM);
	}

	iwmr->stag = stag;
	iwmr->ibmw.rkey = stag;
	iwmr->ibmw.pd = pd;
	iwmr->ibmw.type = type;
	iwmr->ibmw.device = pd->device;

	err_code = irdma_hw_alloc_mw(iwdev, iwmr);
	if (err_code) {
		irdma_free_stag(iwdev, stag);
		kfree(iwmr);
		return ERR_PTR(err_code);
	}

	return &iwmr->ibmw;
}

#endif /* IRDMA_ALLOC_MW_VER_1 */
/**
 * kc_set_loc_seq_num_mss - Set local seq number and mss
 * @cm_node: cm node info
 */
void kc_set_loc_seq_num_mss(struct irdma_cm_node *cm_node)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
	if (cm_node->ipv4) {
		cm_node->tcp_cntxt.loc_seq_num = secure_tcp_seq(htonl(cm_node->loc_addr[0]),
								htonl(cm_node->rem_addr[0]),
								htons(cm_node->loc_port),
								htons(cm_node->rem_port));
		if (cm_node->iwdev->vsi.mtu > 1500 &&
		    2 * cm_node->iwdev->vsi.mtu > cm_node->iwdev->rcv_wnd)
			cm_node->tcp_cntxt.mss = 1500 - IRDMA_MTU_TO_MSS_IPV4;
		else
			cm_node->tcp_cntxt.mss = cm_node->iwdev->vsi.mtu - IRDMA_MTU_TO_MSS_IPV4;
	} else if (IS_ENABLED(CONFIG_IPV6)) {
		__be32 loc[4] = {
			htonl(cm_node->loc_addr[0]), htonl(cm_node->loc_addr[1]),
			htonl(cm_node->loc_addr[2]), htonl(cm_node->loc_addr[3])
		};
		__be32 rem[4] = {
			htonl(cm_node->rem_addr[0]), htonl(cm_node->rem_addr[1]),
			htonl(cm_node->rem_addr[2]), htonl(cm_node->rem_addr[3])
		};
		cm_node->tcp_cntxt.loc_seq_num = secure_tcpv6_seq(loc, rem,
								  htons(cm_node->loc_port),
								  htons(cm_node->rem_port));
		if (cm_node->iwdev->vsi.mtu > 1500 &&
		    2 * cm_node->iwdev->vsi.mtu > cm_node->iwdev->rcv_wnd)
			cm_node->tcp_cntxt.mss = 1500 - IRDMA_MTU_TO_MSS_IPV6;
		else
			cm_node->tcp_cntxt.mss = cm_node->iwdev->vsi.mtu - IRDMA_MTU_TO_MSS_IPV6;
	}
#else
	cm_node->tcp_cntxt.loc_seq_num = htonl(current_kernel_time().tv_nsec);
	if (cm_node->iwdev->vsi.mtu > 1500 &&
	    2 * cm_node->iwdev->vsi.mtu > cm_node->iwdev->rcv_wnd)
		cm_node->tcp_cntxt.mss = (cm_node->ipv4) ?
					 (1500 - IRDMA_MTU_TO_MSS_IPV4) :
					 (1500 - IRDMA_MTU_TO_MSS_IPV6);
	else
		cm_node->tcp_cntxt.mss = (cm_node->ipv4) ?
					 (cm_node->iwdev->vsi.mtu - IRDMA_MTU_TO_MSS_IPV4) :
					 (cm_node->iwdev->vsi.mtu - IRDMA_MTU_TO_MSS_IPV6);
#endif
}

#ifdef VMA_DATA
struct irdma_vma_data {
	struct list_head list;
	struct vm_area_struct *vma;
	struct mutex *vma_list_mutex; /* protect the vma_list */
};

/**
 * irdma_vma_open -
 * @vma: User VMA
 */
static void irdma_vma_open(struct vm_area_struct *vma)
{
	vma->vm_ops = NULL;
}

/**
 * irdma_vma_close - Remove vma data from vma list
 * @vma: User VMA
 */
static void irdma_vma_close(struct vm_area_struct *vma)
{
	struct irdma_vma_data *vma_data;

	vma_data = vma->vm_private_data;
	vma->vm_private_data = NULL;
	vma_data->vma = NULL;
	mutex_lock(vma_data->vma_list_mutex);
	list_del(&vma_data->list);
	mutex_unlock(vma_data->vma_list_mutex);
	kfree(vma_data);
}

static const struct vm_operations_struct irdma_vm_ops = {
	.open = irdma_vma_open,
	.close = irdma_vma_close
};

/**
 * irdma_set_vma_data - Save vma data in context list
 * @vma: User VMA
 * @context: ib user context
 */
static int irdma_set_vma_data(struct vm_area_struct *vma,
			      struct irdma_ucontext *context)
{
	struct list_head *vma_head = &context->vma_list;
	struct irdma_vma_data *vma_entry;

	vma_entry = kzalloc(sizeof(*vma_entry), GFP_KERNEL);
	if (!vma_entry)
		return -ENOMEM;

	vma->vm_private_data = vma_entry;
	vma->vm_ops = &irdma_vm_ops;

	vma_entry->vma = vma;
	vma_entry->vma_list_mutex = &context->vma_list_mutex;

	mutex_lock(&context->vma_list_mutex);
	list_add(&vma_entry->list, vma_head);
	mutex_unlock(&context->vma_list_mutex);

	return 0;
}

/**
 * irdma_disassociate_ucontext - Disassociate user context
 * @context: ib user context
 */
void irdma_disassociate_ucontext(struct ib_ucontext *context)
{
	struct irdma_ucontext *ucontext = to_ucontext(context);

	struct irdma_vma_data *vma_data, *n;
	struct vm_area_struct *vma;

	mutex_lock(&ucontext->vma_list_mutex);
	list_for_each_entry_safe(vma_data, n, &ucontext->vma_list, list) {
		vma = vma_data->vma;
		zap_vma_ptes(vma, vma->vm_start, PAGE_SIZE);

		vma->vm_flags &= ~(VM_SHARED | VM_MAYSHARE);
		vma->vm_ops = NULL;
		list_del(&vma_data->list);
		kfree(vma_data);
	}
	mutex_unlock(&ucontext->vma_list_mutex);
}

int rdma_user_mmap_io(struct ib_ucontext *context, struct vm_area_struct *vma,
		      unsigned long pfn, unsigned long size, pgprot_t prot)
{
	if (io_remap_pfn_range(vma,
			       vma->vm_start,
			       pfn,
			       size,
			       prot))
			return -EAGAIN;

	return irdma_set_vma_data(vma, to_ucontext(context));
}
#else
/**
 * irdma_disassociate_ucontext - Disassociate user context
 * @context: ib user context
 */
void irdma_disassociate_ucontext(struct ib_ucontext *context)
{
}
#endif /* RDMA_MMAP_DB_SUPPORT */

#ifndef NETDEV_TO_IBDEV_SUPPORT
struct ib_device *ib_device_get_by_netdev(struct net_device *netdev, int driver_id)
{
	struct irdma_device *iwdev;
	struct irdma_handler *hdl;
	unsigned long flags;

	spin_lock_irqsave(&irdma_handler_lock, flags);
	list_for_each_entry(hdl, &irdma_handlers, list) {
		iwdev = hdl->iwdev;
		if (netdev == iwdev->netdev) {
			spin_unlock_irqrestore(&irdma_handler_lock,
					       flags);
			return &iwdev->ibdev;
		}
	}
	spin_unlock_irqrestore(&irdma_handler_lock, flags);

	return NULL;
}

void ib_unregister_device_put(struct ib_device *device)
{
	ib_unregister_device(device);
}

#endif /* NETDEV_TO_IBDEV_SUPPORT */
/**
 * irdma_query_gid_roce - Query port GID for Roce
 * @ibdev: device pointer from stack
 * @port: port number
 * @index: Entry index
 * @gid: Global ID
 */
#ifdef QUERY_GID_ROCE_V2
int irdma_query_gid_roce(struct ib_device *ibdev, u32 port, int index,
			 union ib_gid *gid)
#elif defined(QUERY_GID_ROCE_V1)
int irdma_query_gid_roce(struct ib_device *ibdev, u8 port, int index,
			 union ib_gid *gid)
#endif
{
	int ret;

	ret = rdma_query_gid(ibdev, port, index, gid);
	if (ret == -EAGAIN) {
		memcpy(gid, &zgid, sizeof(*gid));
		return 0;
	}

	return ret;
}

/**
 * irdma_modify_port - modify port attributes
 * @ibdev: device pointer from stack
 * @port: port number for query
 * @mask: Property mask
 * @props: returning device attributes
 */
#ifdef MODIFY_PORT_V2
int irdma_modify_port(struct ib_device *ibdev, u32 port, int mask,
		      struct ib_port_modify *props)
#elif defined(MODIFY_PORT_V1)
int irdma_modify_port(struct ib_device *ibdev, u8 port, int mask,
		      struct ib_port_modify *props)
#endif
{
	if (port > 1)
		return -EINVAL;

	return 0;
}

/**
 * irdma_query_pkey - Query partition key
 * @ibdev: device pointer from stack
 * @port: port number
 * @index: index of pkey
 * @pkey: pointer to store the pkey
 */
#ifdef QUERY_PKEY_V2
int irdma_query_pkey(struct ib_device *ibdev, u32 port, u16 index,
		     u16 *pkey)
#elif defined(QUERY_PKEY_V1)
int irdma_query_pkey(struct ib_device *ibdev, u8 port, u16 index,
		     u16 *pkey)
#endif
{
	if (index >= IRDMA_PKEY_TBL_SZ)
		return -EINVAL;

	*pkey = IRDMA_DEFAULT_PKEY;
	return 0;
}

#ifdef ROCE_PORT_IMMUTABLE_V2
int irdma_roce_port_immutable(struct ib_device *ibdev, u32 port_num,
			      struct ib_port_immutable *immutable)
#elif defined(ROCE_PORT_IMMUTABLE_V1)
int irdma_roce_port_immutable(struct ib_device *ibdev, u8 port_num,
			      struct ib_port_immutable *immutable)
#endif
{
	struct ib_port_attr attr;
	int err;

	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	err = ib_query_port(ibdev, port_num, &attr);
	if (err)
		return err;

	immutable->max_mad_size = IB_MGMT_MAD_SIZE;
	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;

	return 0;
}

#ifdef IW_PORT_IMMUTABLE_V2
int irdma_iw_port_immutable(struct ib_device *ibdev, u32 port_num,
			    struct ib_port_immutable *immutable)
#elif defined(IW_PORT_IMMUTABLE_V1)
int irdma_iw_port_immutable(struct ib_device *ibdev, u8 port_num,
			    struct ib_port_immutable *immutable)
#endif
{
	struct ib_port_attr attr;
	int err;

	immutable->core_cap_flags = RDMA_CORE_PORT_IWARP;
	err = ib_query_port(ibdev, port_num, &attr);
	if (err)
		return err;
	immutable->gid_tbl_len = 1;

	return 0;
}

/**
 * irdma_query_port - get port attributes
 * @ibdev: device pointer from stack
 * @port: port number for query
 * @props: returning device attributes
 */
#ifdef QUERY_PORT_V2
int irdma_query_port(struct ib_device *ibdev, u32 port,
		     struct ib_port_attr *props)
#elif defined(QUERY_PORT_V1)
int irdma_query_port(struct ib_device *ibdev, u8 port,
		     struct ib_port_attr *props)
#endif
{
	struct irdma_device *iwdev = to_iwdev(ibdev);
	struct net_device *netdev = iwdev->netdev;

	/* no need to zero out pros here. done by caller */

	props->max_mtu = IB_MTU_4096;
	props->active_mtu = ib_mtu_int_to_enum(netdev->mtu);
	props->lid = 1;
	props->lmc = 0;
	props->sm_lid = 0;
	props->sm_sl = 0;
	if (netif_carrier_ok(netdev) && netif_running(netdev)) {
		props->state = IB_PORT_ACTIVE;
		props->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	} else {
		props->state = IB_PORT_DOWN;
		props->phys_state = IB_PORT_PHYS_STATE_DISABLED;
	}
	ib_get_eth_speed(ibdev, port, &props->active_speed, &props->active_width);

	if (rdma_protocol_roce(ibdev, 1)) {
		props->gid_tbl_len = 32;
		kc_set_props_ip_gid_caps(props);
		props->pkey_tbl_len = IRDMA_PKEY_TBL_SZ;
	} else {
		props->gid_tbl_len = 1;
	}
	props->qkey_viol_cntr = 0;
	props->port_cap_flags |= IB_PORT_CM_SUP | IB_PORT_REINIT_SUP;
	props->max_msg_sz = iwdev->rf->sc_dev.hw_attrs.max_hw_outbound_msg_size;

	return 0;
}

#ifdef ALLOC_HW_STATS_STRUCT_V1
static const char *const irdma_hw_stat_names[] = {
	/* gen1 - 32-bit */
	[IRDMA_HW_STAT_INDEX_IP4RXDISCARD]      = "ip4InDiscards",
	[IRDMA_HW_STAT_INDEX_IP4RXTRUNC]        = "ip4InTruncatedPkts",
	[IRDMA_HW_STAT_INDEX_IP4TXNOROUTE]      = "ip4OutNoRoutes",
	[IRDMA_HW_STAT_INDEX_IP6RXDISCARD]      = "ip6InDiscards",
	[IRDMA_HW_STAT_INDEX_IP6RXTRUNC]        = "ip6InTruncatedPkts",
	[IRDMA_HW_STAT_INDEX_IP6TXNOROUTE]      = "ip6OutNoRoutes",
	[IRDMA_HW_STAT_INDEX_RXVLANERR]         = "rxVlanErrors",
	/* gen1 - 64-bit */
	[IRDMA_HW_STAT_INDEX_IP4RXOCTS]         = "ip4InOctets",
	[IRDMA_HW_STAT_INDEX_IP4RXPKTS]         = "ip4InPkts",
	[IRDMA_HW_STAT_INDEX_IP4RXFRAGS]        = "ip4InReasmRqd",
	[IRDMA_HW_STAT_INDEX_IP4RXMCPKTS]       = "ip4InMcastPkts",
	[IRDMA_HW_STAT_INDEX_IP4TXOCTS]         = "ip4OutOctets",
	[IRDMA_HW_STAT_INDEX_IP4TXPKTS]         = "ip4OutPkts",
	[IRDMA_HW_STAT_INDEX_IP4TXFRAGS]        = "ip4OutSegRqd",
	[IRDMA_HW_STAT_INDEX_IP4TXMCPKTS]       = "ip4OutMcastPkts",
	[IRDMA_HW_STAT_INDEX_IP6RXOCTS]         = "ip6InOctets",
	[IRDMA_HW_STAT_INDEX_IP6RXPKTS]         = "ip6InPkts",
	[IRDMA_HW_STAT_INDEX_IP6RXFRAGS]        = "ip6InReasmRqd",
	[IRDMA_HW_STAT_INDEX_IP6RXMCPKTS]       = "ip6InMcastPkts",
	[IRDMA_HW_STAT_INDEX_IP6TXOCTS]         = "ip6OutOctets",
	[IRDMA_HW_STAT_INDEX_IP6TXPKTS]         = "ip6OutPkts",
	[IRDMA_HW_STAT_INDEX_IP6TXFRAGS]        = "ip6OutSegRqd",
	[IRDMA_HW_STAT_INDEX_IP6TXMCPKTS]       = "ip6OutMcastPkts",
	[IRDMA_HW_STAT_INDEX_RDMARXRDS]         = "InRdmaReads",
	[IRDMA_HW_STAT_INDEX_RDMARXSNDS]        = "InRdmaSends",
	[IRDMA_HW_STAT_INDEX_RDMARXWRS]         = "InRdmaWrites",
	[IRDMA_HW_STAT_INDEX_RDMATXRDS]         = "OutRdmaReads",
	[IRDMA_HW_STAT_INDEX_RDMATXSNDS]        = "OutRdmaSends",
	[IRDMA_HW_STAT_INDEX_RDMATXWRS]         = "OutRdmaWrites",
	[IRDMA_HW_STAT_INDEX_RDMAVBND]          = "RdmaBnd",
	[IRDMA_HW_STAT_INDEX_RDMAVINV]          = "RdmaInv",

	/* gen2 - 32-bit */
	[IRDMA_HW_STAT_INDEX_RXRPCNPHANDLED]    = "cnpHandled",
	[IRDMA_HW_STAT_INDEX_RXRPCNPIGNORED]    = "cnpIgnored",
	[IRDMA_HW_STAT_INDEX_TXNPCNPSENT]       = "cnpSent",
	/* gen2 - 64-bit */
	[IRDMA_HW_STAT_INDEX_IP4RXMCOCTS]       = "ip4InMcastOctets",
	[IRDMA_HW_STAT_INDEX_IP4TXMCOCTS]       = "ip4OutMcastOctets",
	[IRDMA_HW_STAT_INDEX_IP6RXMCOCTS]       = "ip6InMcastOctets",
	[IRDMA_HW_STAT_INDEX_IP6TXMCOCTS]       = "ip6OutMcastOctets",
	[IRDMA_HW_STAT_INDEX_UDPRXPKTS]         = "RxUDP",
	[IRDMA_HW_STAT_INDEX_UDPTXPKTS]         = "TxUDP",
	[IRDMA_HW_STAT_INDEX_RXNPECNMARKEDPKTS] = "RxECNMrkd",
	[IRDMA_HW_STAT_INDEX_TCPRTXSEG]         = "RetransSegs",
	[IRDMA_HW_STAT_INDEX_TCPRXOPTERR]       = "InOptErrors",
	[IRDMA_HW_STAT_INDEX_TCPRXPROTOERR]     = "InProtoErrors",
	[IRDMA_HW_STAT_INDEX_TCPRXSEGS]         = "InSegs",
	[IRDMA_HW_STAT_INDEX_TCPTXSEG]          = "OutSegs",

	/* gen3 */
	[IRDMA_HW_STAT_INDEX_RNR_SENT]          = "RNR sent",
	[IRDMA_HW_STAT_INDEX_RNR_RCVD]          = "RNR received",
	[IRDMA_HW_STAT_INDEX_RDMAORDLMTCNT]     = "ord limit count",
	[IRDMA_HW_STAT_INDEX_RDMAIRDLMTCNT]     = "ird limit count",
	[IRDMA_HW_STAT_INDEX_RDMARXATS]         = "Rx ATS",
	[IRDMA_HW_STAT_INDEX_RDMATXATS]         = "Tx ATS",
	[IRDMA_HW_STAT_INDEX_NAKSEQERR]         = "Nak Sequence Error",
	[IRDMA_HW_STAT_INDEX_NAKSEQERR_IMPLIED] = "Nak Sequence Error Implied",
	[IRDMA_HW_STAT_INDEX_RTO]               = "RTO",
	[IRDMA_HW_STAT_INDEX_RXOOOPKTS]         = "Rcvd Out of order packets",
	[IRDMA_HW_STAT_INDEX_ICRCERR]           = "CRC errors",
};

#endif /* ALLOC_HW_STATS_STRUCT_V1 */
#ifdef ALLOC_HW_STATS_V3
/**
 * irdma_alloc_hw_port_stats - Allocate a hw stats structure
 * @ibdev: device pointer from stack
 * @port_num: port number
 */
struct rdma_hw_stats *irdma_alloc_hw_port_stats(struct ib_device *ibdev,
						u32 port_num)
{
#endif
#ifdef ALLOC_HW_STATS_V2
/**
 * irdma_alloc_hw_stats - Allocate a hw stats structure
 * @ibdev: device pointer from stack
 * @port_num: port number
 */
struct rdma_hw_stats *irdma_alloc_hw_stats(struct ib_device *ibdev,
					   u32 port_num)
{
#endif
#ifdef ALLOC_HW_STATS_V1
/**
 * irdma_alloc_hw_stats - Allocate a hw stats structure
 * @ibdev: device pointer from stack
 * @port_num: port number
 */
struct rdma_hw_stats *irdma_alloc_hw_stats(struct ib_device *ibdev,
					   u8 port_num)
{
#endif
	struct irdma_device *iwdev = to_iwdev(ibdev);
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;

	int num_counters = dev->hw_attrs.max_stat_idx;
	unsigned long lifespan = RDMA_HW_STATS_DEFAULT_LIFESPAN;

	/*
	 * PFs get the default update lifespan, but VFs only update once
	 * per second
	 */
	if (!dev->privileged)
		lifespan = 1000;
#ifdef ALLOC_HW_STATS_STRUCT_V2
	return rdma_alloc_hw_stats_struct(irdma_hw_stat_descs, num_counters,
					  lifespan);
#else
	return rdma_alloc_hw_stats_struct(irdma_hw_stat_names, num_counters,
					  lifespan);
#endif
}

/**
 * irdma_get_hw_stats - Populates the rdma_hw_stats structure
 * @ibdev: device pointer from stack
 * @stats: stats pointer from stack
 * @port_num: port number
 * @index: which hw counter the stack is requesting we update
 */
#ifdef GET_HW_STATS_V2
int irdma_get_hw_stats(struct ib_device *ibdev,
		       struct rdma_hw_stats *stats, u32 port_num,
		       int index)
#elif defined(GET_HW_STATS_V1)
int irdma_get_hw_stats(struct ib_device *ibdev,
		       struct rdma_hw_stats *stats, u8 port_num,
		       int index)
#endif
{
	struct irdma_device *iwdev = to_iwdev(ibdev);
	struct irdma_dev_hw_stats *hw_stats = &iwdev->vsi.pestat->hw_stats;

	if (iwdev->rf->rdma_ver >= IRDMA_GEN_2)
		irdma_cqp_gather_stats_cmd(&iwdev->rf->sc_dev, iwdev->vsi.pestat, true);
	else
		irdma_cqp_gather_stats_gen1(&iwdev->rf->sc_dev, iwdev->vsi.pestat);

	memcpy(&stats->value[0], hw_stats, sizeof(u64) * stats->num_counters);

	return stats->num_counters;
}

/**
 * irdma_query_gid - Query port GID
 * @ibdev: device pointer from stack
 * @port: port number
 * @index: Entry index
 * @gid: Global ID
 */
#ifdef QUERY_GID_V2
int irdma_query_gid(struct ib_device *ibdev, u32 port, int index,
		    union ib_gid *gid)
#elif defined(QUERY_GID_V1)
int irdma_query_gid(struct ib_device *ibdev, u8 port, int index,
		    union ib_gid *gid)
#endif
{
	struct irdma_device *iwdev = to_iwdev(ibdev);

	memset(gid->raw, 0, sizeof(gid->raw));
	ether_addr_copy(gid->raw, iwdev->netdev->dev_addr);

	return 0;
}

#ifdef GET_LINK_LAYER_V2
enum rdma_link_layer irdma_get_link_layer(struct ib_device *ibdev,
					  u32 port_num)
#elif defined(GET_LINK_LAYER_V1)
enum rdma_link_layer irdma_get_link_layer(struct ib_device *ibdev,
					  u8 port_num)
#endif
{
	return IB_LINK_LAYER_ETHERNET;
}

#ifdef IB_MTU_CONVERSIONS

inline enum ib_mtu ib_mtu_int_to_enum(int mtu)
{
	if (mtu >= 4096)
		return IB_MTU_4096;
	else if (mtu >= 2048)
		return IB_MTU_2048;
	else if (mtu >= 1024)
		return IB_MTU_1024;
	else if (mtu >= 512)
		return IB_MTU_512;
	else
		return IB_MTU_256;
}
#endif

#ifdef UVERBS_CMD_MASK
inline void kc_set_roce_uverbs_cmd_mask(struct irdma_device *iwdev)
{
	iwdev->ibdev.uverbs_cmd_mask |=
		BIT_ULL(IB_USER_VERBS_CMD_ATTACH_MCAST) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_AH) |
		BIT_ULL(IB_USER_VERBS_CMD_DESTROY_AH) |
		BIT_ULL(IB_USER_VERBS_CMD_DETACH_MCAST);
}

inline void kc_set_rdma_uverbs_cmd_mask(struct irdma_device *iwdev)
{
	iwdev->ibdev.uverbs_cmd_mask =
		BIT_ULL(IB_USER_VERBS_CMD_GET_CONTEXT) |
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_DEVICE) |
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_PORT) |
		BIT_ULL(IB_USER_VERBS_CMD_ALLOC_PD) |
		BIT_ULL(IB_USER_VERBS_CMD_DEALLOC_PD) |
		BIT_ULL(IB_USER_VERBS_CMD_REG_MR) |
		BIT_ULL(IB_USER_VERBS_CMD_REREG_MR) |
		BIT_ULL(IB_USER_VERBS_CMD_DEREG_MR) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_RESIZE_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_DESTROY_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_REQ_NOTIFY_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_CREATE_QP) |
		BIT_ULL(IB_USER_VERBS_CMD_MODIFY_QP) |
		BIT_ULL(IB_USER_VERBS_CMD_QUERY_QP) |
		BIT_ULL(IB_USER_VERBS_CMD_POLL_CQ) |
		BIT_ULL(IB_USER_VERBS_CMD_DESTROY_QP) |
		BIT_ULL(IB_USER_VERBS_CMD_POST_RECV) |
		BIT_ULL(IB_USER_VERBS_CMD_POST_SEND);
	if (iwdev->rf->rdma_ver >= IRDMA_GEN_3)
		iwdev->ibdev.uverbs_cmd_mask |=
			BIT_ULL(IB_USER_VERBS_CMD_ALLOC_MW) |
			BIT_ULL(IB_USER_VERBS_CMD_BIND_MW) |
			BIT_ULL(IB_USER_VERBS_CMD_DEALLOC_MW) |
			BIT_ULL(IB_USER_VERBS_CMD_CREATE_SRQ) |
			BIT_ULL(IB_USER_VERBS_CMD_MODIFY_SRQ) |
			BIT_ULL(IB_USER_VERBS_CMD_QUERY_SRQ) |
			BIT_ULL(IB_USER_VERBS_CMD_DESTROY_SRQ) |
			BIT_ULL(IB_USER_VERBS_CMD_POST_SRQ_RECV);
	iwdev->ibdev.uverbs_ex_cmd_mask =
		BIT_ULL(IB_USER_VERBS_EX_CMD_MODIFY_QP) |
		BIT_ULL(IB_USER_VERBS_EX_CMD_QUERY_DEVICE);

	if (iwdev->rf->rdma_ver >= IRDMA_GEN_2)
		iwdev->ibdev.uverbs_ex_cmd_mask |= BIT_ULL(IB_USER_VERBS_EX_CMD_CREATE_CQ);
}
#endif

#ifdef ENABLE_DUP_CM_NAME_WA
static DEFINE_IDA(irdma_devname_ida);
void irdma_release_ib_devname(struct irdma_device *iwdev)
{
	if (iwdev->name_id < 0)
		return;
	ida_simple_remove(&irdma_devname_ida, iwdev->name_id);
}

char *irdma_set_ib_devname(struct irdma_device *iwdev)
{
	const char *name = iwdev->lag_mode ? "irdma_bond%d" : "irdma%d";
	int i;

	i = ida_alloc(&irdma_devname_ida, GFP_KERNEL);
	iwdev->name_id = i;
	if (i < 0)
		strcpy(iwdev->ib_devname, name);
	else
		snprintf(iwdev->ib_devname, sizeof(iwdev->ib_devname), name, i);
	return iwdev->ib_devname;
}

#else /* ENABLE_DUP_CM_NAME_WA */
void irdma_release_ib_devname(struct irdma_device *iwdev)
{
}

char *irdma_set_ib_devname(struct irdma_device *iwdev)
{
	const char *name = iwdev->lag_mode ? "irdma_bond%d" : "irdma%d";

	strcpy(iwdev->ib_devname, name);

	return iwdev->ib_devname;
}
#endif /* ENABLE_DUP_CM_NAME_WA */
#ifdef IB_GET_ETH_SPEED

int ib_get_eth_speed(struct ib_device *ibdev, u32 port_num, u8 *speed, u8 *width)
{
	struct net_device *netdev = ibdev->get_netdev(ibdev, port_num);
	u32 netdev_speed;
	struct ethtool_cmd cmd;
	int rc;

	if (!netdev)
		return -ENODEV;

	rtnl_lock();
	rc = __ethtool_get_settings(netdev, &cmd);
	rtnl_unlock();
	netdev_speed = ethtool_cmd_speed(&cmd);
	dev_put(netdev);

	if (rc || netdev_speed == (u32)SPEED_UNKNOWN) {
		netdev_speed = SPEED_1000;
		pr_warn("%s speed is unknown, defaulting to %u\n", netdev->name,
			netdev_speed);
	}
	if (netdev_speed <= SPEED_1000) {
		*width = IB_WIDTH_1X;
		*speed = IB_SPEED_SDR;
	} else if (netdev_speed <= SPEED_10000) {
		*width = IB_WIDTH_1X;
		*speed = IB_SPEED_FDR10;
	} else if (netdev_speed <= SPEED_20000) {
		*width = IB_WIDTH_4X;
		*speed = IB_SPEED_DDR;
	} else if (netdev_speed <= SPEED_25000) {
		*width = IB_WIDTH_1X;
		*speed = IB_SPEED_EDR;
	} else if (netdev_speed <= SPEED_40000) {
		*width = IB_WIDTH_4X;
		*speed = IB_SPEED_FDR10;
	} else {
		*width = IB_WIDTH_4X;
		*speed = IB_SPEED_EDR;
	}

	return 0;
}
#endif /* IB_GET_ETH_SPEED */
#ifdef	ETHER_ADDR_TO_U64

u64 ether_addr_to_u64(const u8 *eth_add)
{
	int idx;
	u64 u64_eth_add;

	for (idx = 0, u64_eth_add = 0; idx < ETH_ALEN; idx++)
		u64_eth_add = u64_eth_add << 8 | eth_add[idx];

	return u64_eth_add;
}
#endif /* ETHER_ADDR_TO_U64 */
