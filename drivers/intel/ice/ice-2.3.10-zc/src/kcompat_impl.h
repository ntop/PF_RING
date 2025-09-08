/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _KCOMPAT_IMPL_H_
#define _KCOMPAT_IMPL_H_

#ifdef HAVE_STRING_HELPERS_H
#include <linux/string_helpers.h>
#endif /* HAVE_STRING_HELPERS_H */

#ifdef HAVE_STRING_CHOICES_H
#include <linux/string_choices.h>
#endif /* HAVE_STRING_CHOICES_H */

/* devlink support */
#if IS_ENABLED(CONFIG_NET_DEVLINK)

/*
 * This change is adding buffer in enum value for ice_devlink_param_id.
 *
 * In upstream / OOT compiled from source it is safe to use
 * DEVLINK_PARAM_GENERIC_ID_MAX as first value for ice_devlink_param_id
 * enum.
 *
 * In case of binary release (for Secure Boot purpose) this caused issue
 * with supporting multiple kernels because backport made by SLES changed
 * value of DEVLINK_PARAM_GENERIC_ID_MAX. This caused -EINVAL to
 * be returned by devlink_params_register() because
 * ICE_DEVLINK_PARAM_ID_FW_MGMT_MINSREV (compiled on older kernel) was equal
 * to DEVLINK_PARAM_GENERIC_ID_MAX (in newer kernel).
 */
#define DEVLINK_PARAM_GENERIC_ID_MAX __KC_DEVLINK_PARAM_GENERIC_ID_MAX
#include <net/devlink.h>
#undef DEVLINK_PARAM_GENERIC_ID_MAX
#define DEVLINK_PARAM_GENERIC_ID_MAX (__KC_DEVLINK_PARAM_GENERIC_ID_MAX + 32)
#endif /* CONFIG_DEVLINK */

/* This file contains implementations of backports from various kernels. It
 * must rely only on NEED_<FLAG> and HAVE_<FLAG> checks. It must not make any
 * checks to determine the kernel version when deciding whether to include an
 * implementation.
 *
 * All new implementations must go in this file, and legacy implementations
 * should be migrated to the new format over time.
 */

/* The same kcompat code is used here and auxiliary module. To avoid
 * duplication and functions redefitions in some scenarios, include the
 * auxiliary kcompat implementation here.
 */
#include "auxiliary_compat.h"

/* generic network stack functions */

/* NEED_NETDEV_TXQ_BQL_PREFETCH
 *
 * functions
 * netdev_txq_bql_complete_prefetchw()
 * netdev_txq_bql_enqueue_prefetchw()
 *
 * were added in kernel 4.20 upstream commit
 * 535114539bb2 ("net: add netdev_txq_bql_{enqueue, complete}_prefetchw()
 * helpers")
 */
#ifdef NEED_NETDEV_TXQ_BQL_PREFETCH
/**
 *      netdev_txq_bql_enqueue_prefetchw - prefetch bql data for write
 *      @dev_queue: pointer to transmit queue
 *
 * BQL enabled drivers might use this helper in their ndo_start_xmit(),
 * to give appropriate hint to the CPU.
 */
static inline
void netdev_txq_bql_enqueue_prefetchw(struct netdev_queue *dev_queue)
{
#ifdef CONFIG_BQL
	prefetchw(&dev_queue->dql.num_queued);
#endif
}

/**
 *      netdev_txq_bql_complete_prefetchw - prefetch bql data for write
 *      @dev_queue: pointer to transmit queue
 *
 * BQL enabled drivers might use this helper in their TX completion path,
 * to give appropriate hint to the CPU.
 */
static inline
void netdev_txq_bql_complete_prefetchw(struct netdev_queue *dev_queue)
{
#ifdef CONFIG_BQL
	prefetchw(&dev_queue->dql.limit);
#endif
}
#endif /* NEED_NETDEV_TXQ_BQL_PREFETCH */

/* NEED_NETDEV_TX_SENT_QUEUE
 *
 * __netdev_tx_sent_queue was added in kernel 4.20 upstream commit
 * 3e59020abf0f ("net: bql: add __netdev_tx_sent_queue()")
 */
#ifdef NEED_NETDEV_TX_SENT_QUEUE
/* Variant of netdev_tx_sent_queue() for drivers that are aware
 * that they should not test BQL status themselves.
 * We do want to change __QUEUE_STATE_STACK_XOFF only for the last
 * skb of a batch.
 * Returns true if the doorbell must be used to kick the NIC.
 */
static inline bool __netdev_tx_sent_queue(struct netdev_queue *dev_queue,
					  unsigned int bytes,
					  bool xmit_more)
{
	if (xmit_more) {
#ifdef CONFIG_BQL
		dql_queued(&dev_queue->dql, bytes);
#endif
		return netif_tx_queue_stopped(dev_queue);
	}
	netdev_tx_sent_queue(dev_queue, bytes);
	return true;
}
#endif /* NEED_NETDEV_TX_SENT_QUEUE */

/*HAVE_NETIF_SUBQUEUE_MAYBE_STOP
 *
 * netif_subqueue_maybe_stop was added in kernel 6.3 upstream commit
 * c91c46de6bbc ("net: provide macros for commonly copied lockless queue
 * stop/wake code")
 */
#ifndef HAVE_NETIF_SUBQUEUE_MAYBE_STOP
#define netif_txq_try_stop(txq, get_desc, start_thrs)			\
	({								\
		int _res;						\
									\
		netif_tx_stop_queue(txq);				\
		/* Producer index and stop bit must be visible		\
		 * to consumer before we recheck.			\
		 * Pairs with a barrier in __netif_txq_completed_wake(). \
		 */							\
		smp_mb__after_atomic();					\
									\
		/* We need to check again in a case another		\
		 * CPU has just made room available.			\
		 */							\
		_res = 0;						\
		if (unlikely(get_desc >= start_thrs)) {			\
			netif_tx_start_queue(txq);			\
			_res = -1;					\
		}							\
		_res;							\
	})

/**
 * netif_txq_maybe_stop() - locklessly stop a Tx queue, if needed
 * @txq:	struct netdev_queue to stop/start
 * @get_desc:	get current number of free descriptors (see requirements below!)
 * @stop_thrs:	minimal number of available descriptors for queue to be left
 *		enabled
 * @start_thrs:	minimal number of descriptors to re-enable the queue, can be
 *		equal to @stop_thrs or higher to avoid frequent waking
 *
 * All arguments may be evaluated multiple times, beware of side effects.
 * @get_desc must be a formula or a function call, it must always
 * return up-to-date information when evaluated!
 * Expected to be used from ndo_start_xmit, see the comment on top of the file.
 *
 * Returns:
 *	 0 if the queue was stopped
 *	 1 if the queue was left enabled
 *	-1 if the queue was re-enabled (raced with waking)
 */
#define netif_txq_maybe_stop(txq, get_desc, stop_thrs, start_thrs)	\
	({								\
		int _res;						\
									\
		_res = 1;						\
		if (unlikely(get_desc < stop_thrs))			\
			_res = netif_txq_try_stop(txq, get_desc, start_thrs); \
		_res;							\
	})

#define netif_subqueue_maybe_stop(dev, idx, get_desc, stop_thrs, start_thrs) \
	({								\
		struct netdev_queue *txq;				\
									\
		txq = netdev_get_tx_queue(dev, idx);			\
		netif_txq_maybe_stop(txq, get_desc, stop_thrs, start_thrs); \
	})
#endif /* !HAVE_NETIF_SUBQUEUE_MAYBE_STOP */

/* NEED_NET_PREFETCH
 *
 * net_prefetch was introduced by commit f468f21b7af0 ("net: Take common
 * prefetch code structure into a function")
 *
 * This function is trivial to re-implement in full.
 */
#ifdef NEED_NET_PREFETCH
static inline void net_prefetch(void *p)
{
	prefetch(p);
#if L1_CACHE_BYTES < 128
	prefetch((u8 *)p + L1_CACHE_BYTES);
#endif
}
#endif /* NEED_NET_PREFETCH */

/* NEED_SKB_FRAG_OFF and NEED_SKB_FRAG_OFF_ADD
 *
 * skb_frag_off and skb_frag_off_add were added in upstream commit
 * 7240b60c98d6 ("linux: Add skb_frag_t page_offset accessors")
 *
 * Implementing the wrappers directly for older kernels which still have the
 * old implementation of skb_frag_t is trivial.
 *
 * LTS 4.19 backported the define for skb_frag_off in 4.19.201.
 * d94d95ae0dd0 ("gro: ensure frag0 meets IP header alignment")
 * Need to exclude defining skb_frag_off for 4.19.X where X > 200
 */
#ifdef NEED_SKB_FRAG_OFF
static inline unsigned int skb_frag_off(const skb_frag_t *frag)
{
	return frag->page_offset;
}
#endif /* NEED_SKB_FRAG_OFF */
#ifdef NEED_SKB_FRAG_OFF_ADD
static inline void skb_frag_off_add(skb_frag_t *frag, int delta)
{
	frag->page_offset += delta;
}
#endif /* NEED_SKB_FRAG_OFF_ADD */

/*
 * NEED_DMA_ATTRS, NEED_DMA_ATTRS_PTR and related functions
 *
 * dma_map_page_attrs and dma_unmap_page_attrs were added in upstream commit
 * 0495c3d36794 ("dma: add calls for dma_map_page_attrs and
 * dma_unmap_page_attrs")
 *
 * Implementing these calls in this way makes RHEL7.4 compile (which doesn't
 * have these) and all newer kernels compile fine, while using only the new
 * calls with no ifdeffery.
 *
 * In kernel 4.10 the commit ("dma-mapping: use unsigned long for dma_attrs")
 * switched the argument from struct dma_attrs * to unsigned long.
 *
 * __page_frag_cache_drain was implemented in 2017, but __page_frag_drain came
 * with the above series for _attrs, and seems to have been backported at the
 * same time.
 *
 * Please note SLES12.SP3 and RHEL7.5 and newer have all three of these
 * already.
 *
 * If need be in the future for some reason, we could make a separate NEED_
 * define for __page_frag_cache_drain, but not yet.
 *
 * For clarity: there are three states:
 * 1) no attrs
 * 2) attrs but with a pointer to a struct dma_attrs
 * 3) attrs but with unsigned long type
 */
#ifdef NEED_DMA_ATTRS
static inline
dma_addr_t __kc_dma_map_page_attrs(struct device *dev, struct page *page,
				   size_t offset, size_t size,
				   enum dma_data_direction dir,
				   unsigned long __always_unused attrs)
{
	return dma_map_page(dev, page, offset, size, dir);
}
#define dma_map_page_attrs __kc_dma_map_page_attrs

static inline
void __kc_dma_unmap_page_attrs(struct device *dev,
			       dma_addr_t addr, size_t size,
			       enum dma_data_direction dir,
			       unsigned long __always_unused attrs)
{
	dma_unmap_page(dev, addr, size, dir);
}
#define dma_unmap_page_attrs __kc_dma_unmap_page_attrs

static inline void __page_frag_cache_drain(struct page *page,
					   unsigned int count)
{
#ifdef HAVE_PAGE_COUNT_BULK_UPDATE
	if (!page_ref_sub_and_test(page, count))
		return;

	init_page_count(page);
#else
	WARN_ON(count > 1);
	if (!count)
		return;
#endif
	__free_pages(page, compound_order(page));
}
#elif defined(NEED_DMA_ATTRS_PTR)
static inline
dma_addr_t __kc_dma_map_page_attrs_long(struct device *dev, struct page *page,
				   size_t offset, size_t size,
				   enum dma_data_direction dir,
				   unsigned long attrs)
{
	struct dma_attrs dmaattrs = {};

	if (attrs & DMA_ATTR_SKIP_CPU_SYNC)
		dma_set_attr(DMA_ATTR_SKIP_CPU_SYNC, &dmaattrs);

	if (attrs & DMA_ATTR_WEAK_ORDERING)
		dma_set_attr(DMA_ATTR_WEAK_ORDERING, &dmaattrs);

	return dma_map_page_attrs(dev, page, offset, size, dir, &dmaattrs);
}
#define dma_map_page_attrs __kc_dma_map_page_attrs_long
/* there is a nasty macro buried in dma-mapping.h which reroutes dma_map_page
 * and dma_unmap_page to attribute versions, so take control of that macro and
 * fix it here. */
#ifdef dma_map_page
#undef dma_map_page
#define dma_map_page(a,b,c,d,r) dma_map_page_attrs(a,b,c,d,r,0)
#endif

static inline
void __kc_dma_unmap_page_attrs_long(struct device *dev,
			       dma_addr_t addr, size_t size,
			       enum dma_data_direction dir,
			       unsigned long attrs)
{
	struct dma_attrs dmaattrs = {};

	if (attrs & DMA_ATTR_SKIP_CPU_SYNC)
		dma_set_attr(DMA_ATTR_SKIP_CPU_SYNC, &dmaattrs);

	if (attrs & DMA_ATTR_WEAK_ORDERING)
		dma_set_attr(DMA_ATTR_WEAK_ORDERING, &dmaattrs);

	dma_unmap_page_attrs(dev, addr, size, dir, &dmaattrs);
}
#define dma_unmap_page_attrs __kc_dma_unmap_page_attrs_long
#ifdef dma_unmap_page
#undef dma_unmap_page
#define dma_unmap_page(a,b,c,r) dma_unmap_page_attrs(a,b,c,r,0)
#endif
#endif /* NEED_DMA_ATTRS_PTR */

/*
 * NETIF_F_HW_L2FW_DOFFLOAD related functions
 *
 * Support for NETIF_F_HW_L2FW_DOFFLOAD was first introduced upstream by
 * commit a6cc0cfa72e0 ("net: Add layer 2 hardware acceleration operations for
 * macvlan devices")
 */
#ifdef NETIF_F_HW_L2FW_DOFFLOAD

#include <linux/if_macvlan.h>

/* NEED_MACVLAN_ACCEL_PRIV
 *
 * macvlan_accel_priv is an accessor function that replaced direct access to
 * the macvlan->fwd_priv variable. It was introduced in commit 7d775f63470c
 * ("macvlan: Rename fwd_priv to accel_priv and add accessor function")
 *
 * Implement the new wrapper name by simply accessing the older
 * macvlan->fwd_priv name.
 */
#ifdef NEED_MACVLAN_ACCEL_PRIV
static inline void *macvlan_accel_priv(struct net_device *dev)
{
	struct macvlan_dev *macvlan = netdev_priv(dev);

	return macvlan->fwd_priv;
}
#endif /* NEED_MACVLAN_ACCEL_PRIV */

/* NEED_MACVLAN_RELEASE_L2FW_OFFLOAD
 *
 * macvlan_release_l2fw_offload was introduced upstream by commit 53cd4d8e4dfb
 * ("macvlan: Provide function for interfaces to release HW offload")
 *
 * Implementing this is straight forward, but we must be careful to use
 * fwd_priv instead of accel_priv. Note that both the change to accel_priv and
 * introduction of this function happened in the same release.
 */
#ifdef NEED_MACVLAN_RELEASE_L2FW_OFFLOAD
static inline int macvlan_release_l2fw_offload(struct net_device *dev)
{
	struct macvlan_dev *macvlan = netdev_priv(dev);

	macvlan->fwd_priv = NULL;
	return dev_uc_add(macvlan->lowerdev, dev->dev_addr);
}
#endif /* NEED_MACVLAN_RELEASE_L2FW_OFFLOAD */

/* NEED_MACVLAN_SUPPORTS_DEST_FILTER
 *
 * macvlan_supports_dest_filter was introduced upstream by commit 6cb1937d4eff
 * ("macvlan: Add function to test for destination filtering support")
 *
 * The implementation doesn't rely on anything new and is trivial to backport
 * for kernels that have NETIF_F_HW_L2FW_DOFFLOAD support.
 */
#ifdef NEED_MACVLAN_SUPPORTS_DEST_FILTER
static inline bool macvlan_supports_dest_filter(struct net_device *dev)
{
	struct macvlan_dev *macvlan = netdev_priv(dev);

	return macvlan->mode == MACVLAN_MODE_PRIVATE ||
	       macvlan->mode == MACVLAN_MODE_VEPA ||
	       macvlan->mode == MACVLAN_MODE_BRIDGE;
}
#endif /* NEED_MACVLAN_SUPPORTS_DEST_FILTER */

#endif /* NETIF_F_HW_L2FW_DOFFLOAD */

/* tc functions */

/* NEED_FLOW_INDR_BLOCK_CB_REGISTER
 *
 * __flow_indr_block_cb_register and __flow_indr_block_cb_unregister were
 * added in upstream commit 4e481908c51b ("flow_offload: move tc indirect
 * block to flow offload")
 *
 * This was a simple rename so we can just translate from the old
 * naming scheme with a macro.
 */
#ifdef NEED_FLOW_INDR_BLOCK_CB_REGISTER
#define __flow_indr_block_cb_register __tc_indr_block_cb_register
#define __flow_indr_block_cb_unregister __tc_indr_block_cb_unregister
#endif

/* devlink support */
#if IS_ENABLED(CONFIG_NET_DEVLINK)

/* NEED_DEVLINK_FMSG_PUT
 *
 * devlink_fmsg_put was introduced upstream by commit 346947223bac ("devlink:
 * add devlink_fmsg_put() macro") as a way to simplify adding data to
 * a devlink health report based on its type.
 *
 * For older kernels, it is straight forward to re-implement here. Note that
 * it does require _Generic support from the compiler.
 */
#ifdef NEED_DEVLINK_FMSG_PUT
#define devlink_fmsg_put(fmsg, name, value) (			\
	_Generic((value),					\
		bool :		devlink_fmsg_bool_pair_put,	\
		u8 :		devlink_fmsg_u8_pair_put,	\
		u16 :		devlink_fmsg_u32_pair_put,	\
		u32 :		devlink_fmsg_u32_pair_put,	\
		u64 :		devlink_fmsg_u64_pair_put,	\
		int :		devlink_fmsg_u32_pair_put,	\
		char * :	devlink_fmsg_string_pair_put,	\
		const char * :	devlink_fmsg_string_pair_put)	\
	(fmsg, name, (value)))
#endif /* NEED_DEVLINK_FMSG_PUT */

/* NEED_DEVLINK_FLASH_UPDATE_STATUS_NOTIFY
 *
 * devlink_flash_update_status_notify, _begin_notify, and _end_notify were
 * added by upstream commit 191ed2024de9 ("devlink: allow driver to update
 * progress of flash update")
 *
 * For older kernels that lack the netlink messages, convert the functions
 * into no-ops.
 */
#ifdef NEED_DEVLINK_FLASH_UPDATE_STATUS_NOTIFY
static inline void
devlink_flash_update_begin_notify(struct devlink __always_unused *devlink)
{
}

static inline void
devlink_flash_update_end_notify(struct devlink __always_unused *devlink)
{
}

static inline void
devlink_flash_update_status_notify(struct devlink __always_unused *devlink,
				   const char __always_unused *status_msg,
				   const char __always_unused *component,
				   unsigned long __always_unused done,
				   unsigned long __always_unused total)
{
}
#endif /* NEED_DEVLINK_FLASH_UPDATE_STATUS_NOTIFY */

#ifndef HAVE_DEVLINK_FLASH_UPDATE_PARAMS
struct devlink_flash_update_params {
	const char *file_name;
	const char *component;
	u32 overwrite_mask;
};
#endif /* !HAVE_DEVLINK_FLASH_UPDATE_PARAMS */

#ifndef HAVE_DEVLINK_FLASH_UPDATE_PARAMS_OVERWRITE_MASK
#ifndef DEVLINK_FLASH_OVERWRITE_SETTINGS
#define DEVLINK_FLASH_OVERWRITE_SETTINGS BIT(0)
#endif

#ifndef DEVLINK_FLASH_OVERWRITE_IDENTIFIERS
#define DEVLINK_FLASH_OVERWRITE_IDENTIFIERS BIT(1)
#endif

#define DEVLINK_SUPPORT_FLASH_UPDATE_COMPONENT          BIT(0)
#define DEVLINK_SUPPORT_FLASH_UPDATE_OVERWRITE_MASK     BIT(1)
#endif /* HAVE_DEVLINK_FLASH_UPDATE_PARAMS_OVERWRITE_MASK */

/* NEED_DEVLINK_FLASH_UPDATE_TIMEOUT_NOTIFY
 *
 * devlink_flash_update_timeout_notify was added by upstream commit
 * f92970c694b3 ("devlink: add timeout information to status_notify").
 *
 * For older kernels, just convert timeout notifications into regular status
 * notification messages without timeout information.
 */
#ifdef NEED_DEVLINK_FLASH_UPDATE_TIMEOUT_NOTIFY
static inline void
devlink_flash_update_timeout_notify(struct devlink *devlink,
				    const char *status_msg,
				    const char *component,
				    unsigned long __always_unused timeout)
{
	devlink_flash_update_status_notify(devlink, status_msg, component, 0, 0);
}
#endif /* NEED_DEVLINK_FLASH_UPDATE_TIMEOUT_NOTIFY */

/*
 * NEED_DEVLINK_PORT_ATTRS_SET_STRUCT
 *
 * HAVE_DEVLINK_PORT_ATTRS_SET_PORT_FLAVOUR
 * HAVE_DEVLINK_PORT_ATTRS_SET_SWITCH_ID
 *
 * devlink_port_attrs_set was introduced by commit b9ffcbaf56d3 ("devlink:
 * introduce devlink_port_attrs_set")
 *
 * It's function signature has changed multiple times over several kernel
 * releases:
 *
 * commit 5ec1380a21bb ("devlink: extend attrs_set for setting port
 * flavours") added the ability to set port flavour. (Note that there is no
 * official kernel release with devlink_port_attrs_set without the flavour
 * argument, as they were introduced in the same series.)
 *
 * commit bec5267cded2 ("net: devlink: extend port attrs for switch ID") added
 * the ability to set the switch ID (HAVE_DEVLINK_PORT_ATTRS_SET_SWITCH_ID)
 *
 * Finally commit 71ad8d55f8e5 ("devlink: Replace devlink_port_attrs_set
 * parameters with a struct") refactored to pass devlink_port_attrs struct
 * instead of individual parameters. (!NEED_DEVLINK_PORT_ATTRS_SET_STRUCT)
 *
 * We want core drivers to just use the latest form that takes
 * a devlink_port_attrs structure. Note that this structure did exist as part
 * of <net/devlink.h> but was never used directly by driver code prior to the
 * function parameter change. For this reason, the implementation always
 * relies on _kc_devlink_port_attrs instead of what was defined in the kernel.
 */
#ifdef NEED_DEVLINK_PORT_ATTRS_SET_STRUCT

#ifndef HAVE_DEVLINK_PORT_ATTRS_SET_PORT_FLAVOUR
enum devlink_port_flavour {
	DEVLINK_PORT_FLAVOUR_PHYSICAL,
	DEVLINK_PORT_FLAVOUR_CPU,
	DEVLINK_PORT_FLAVOUR_DSA,
	DEVLINK_PORT_FLAVOUR_PCI_PF,
	DEVLINK_PORT_FLAVOUR_PCI_VF,
};
#endif

struct _kc_devlink_port_phys_attrs {
	u32 port_number;
	u32 split_subport_number;
};

struct _kc_devlink_port_pci_pf_attrs {
	u16 pf;
};

struct _kc_devlink_port_pci_vf_attrs {
	u16 pf;
	u16 vf;
};

struct _kc_devlink_port_attrs {
	u8 split:1,
	   splittable:1;
	u32 lanes;
	enum devlink_port_flavour flavour;
	struct netdev_phys_item_id switch_id;
	union {
		struct _kc_devlink_port_phys_attrs phys;
		struct _kc_devlink_port_pci_pf_attrs pci_pf;
		struct _kc_devlink_port_pci_vf_attrs pci_vf;
	};
};

#define devlink_port_attrs _kc_devlink_port_attrs

static inline void
_kc_devlink_port_attrs_set(struct devlink_port *devlink_port,
			   struct _kc_devlink_port_attrs *attrs)
{
#if defined(HAVE_DEVLINK_PORT_ATTRS_SET_SWITCH_ID)
	devlink_port_attrs_set(devlink_port, attrs->flavour, attrs->phys.port_number,
			       attrs->split, attrs->phys.split_subport_number,
			       attrs->switch_id.id, attrs->switch_id.id_len);
#elif defined(HAVE_DEVLINK_PORT_ATTRS_SET_PORT_FLAVOUR)
	devlink_port_attrs_set(devlink_port, attrs->flavour, attrs->phys.port_number,
			       attrs->split, attrs->phys.split_subport_number);
#else
	if (attrs->split)
		devlink_port_split_set(devlink_port, attrs->phys.port_number);
#endif
}

#define devlink_port_attrs_set _kc_devlink_port_attrs_set

#endif /* NEED_DEVLINK_PORT_ATTRS_SET_STRUCT */

/*
 * NEED_DEVLINK_ALLOC_SETS_DEV
 *
 * Since commit 919d13a7e455 ("devlink: Set device as early as possible"), the
 * devlink device pointer is set by devlink_alloc instead of by
 * devlink_register.
 *
 * devlink_alloc now includes the device pointer in its signature, while
 * devlink_register no longer includes it.
 *
 * This implementation provides a replacement for devlink_alloc which will
 * take and then silently discard the extra dev pointer.
 *
 * To use devlink_register, drivers must check
 * HAVE_DEVLINK_REGISTER_SETS_DEV. Note that we can't easily provide
 * a backport of the change to devlink_register directly. Although the dev
 * pointer is accessible from the devlink pointer through the driver private
 * section, it is device driver specific and is not easily accessible in
 * compat code.
 */
#ifdef NEED_DEVLINK_ALLOC_SETS_DEV
static inline struct devlink *
_kc_devlink_alloc(const struct devlink_ops *ops, size_t priv_size,
		  struct device * __always_unused dev)
{
	return devlink_alloc(ops, priv_size);
}
#define devlink_alloc _kc_devlink_alloc
#endif /* NEED_DEVLINK_ALLOC_SETS_DEV */

#ifdef HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT
#ifdef NEED_DEVLINK_UNLOCKED_RESOURCE
/*
 * NEED_DEVLINK_UNLOCKED_RESOURCE
 *
 * Handle devlink API change introduced in:
 * c223d6a4bf ("net: devlink: add unlocked variants of devlink_resource*()
 * functions")
 * 644a66c60f ("net: devlink: convert reload command to take implicit
 * devlink->lock")
 *
 * devl_resource_size_get() does not take devlink->lock where
 * devlink_resource_size_get() takes devlink->lock, but we do not introduce
 * locking in the driver as taking the lock in devlink_reload() was added
 * upstream in the same version as API change.
 *
 * We have to rely on distro maintainers properly backporting of both mentioned
 * commits for OOT driver to work properly.
 * In case of backporting only c223d6a4bf assert inside
 * devl_resource_size_get() will trigger kernel WARNING,
 * In case of backporting only 644a66c60f devlink_resource_size_get() will
 * attempt to take the lock second time.
 */
static inline int devl_resource_size_get(struct devlink *devlink,
					 u64 resource_id,
					 u64 *p_resource_size)
{
	return devlink_resource_size_get(devlink, resource_id, p_resource_size);
}
#endif /* NEED_DEVLINK_UNLOCKED_RESOURCE */
#endif /* HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT */

#ifdef NEED_DEVLINK_TO_DEV
/*
 * Commit 2131463 ("devlink: Reduce struct devlink exposure")
 * removed devlink struct fields from header to avoid exposure
 * and added devlink_to_dev and related functions to access
 * them instead.
 */
static inline struct device *
devlink_to_dev(const struct devlink *devlink)
{
	return devlink->dev;
}
#endif /* NEED_DEVLINK_TO_DEV */

#ifdef NEED_DEVL_LOCK
static inline void devl_lock(struct devlink *devlink)
{
}

static inline void devl_unlock(struct devlink *devlink)
{
}
#endif /* NEED_DEVL_LOCK */

#ifdef NEED_DEVL_RESOURCE_REGISTER
static inline int
devl_resource_register(struct devlink *devlink, const char *resource_name,
		       u64 resource_size, u64 resource_id,
		       u64 parent_resource_id,
		       const struct devlink_resource_size_params *size_params)
{
	int err;

	devl_unlock(devlink);
	err = devlink_resource_register(devlink, resource_name, resource_size,
					resource_id, parent_resource_id,
					size_params);
	devl_lock(devlink);

	return err;
}

static inline void devl_resources_unregister(struct devlink *devlink)
{
	devl_unlock(devlink);
#ifdef NEED_DEVLINK_RESOURCES_UNREGISTER_NO_RESOURCE
	devlink_resources_unregister(devlink, NULL);
#else
	devlink_resources_unregister(devlink);
#endif /* NEED_DEVLINK_RESOURCES_UNREGISTER_NO_RESOURCE */
	devl_lock(devlink);
}

static inline void
devl_resource_occ_get_register(struct devlink *devlink, u64 resource_id,
			       devlink_resource_occ_get_t *occ_get,
			       void *occ_get_priv)
{
	devl_unlock(devlink);
	devlink_resource_occ_get_register(devlink, resource_id, occ_get,
					  occ_get_priv);
	devl_lock(devlink);
}

static inline void devl_resource_occ_get_unregister(struct devlink *devlink,
						    u64 resource_id)
{
	devl_unlock(devlink);
	devlink_resource_occ_get_unregister(devlink, resource_id);
	devl_lock(devlink);
}
#endif /* NEED_DEVL_RESOURCE_REGISTER */

#ifdef NEED_DEVL_PORT_REGISTER
static inline int devl_port_register(struct devlink *devlink,
				     struct devlink_port *devlink_port,
				     unsigned int port_index)
{
	int err;

	devl_unlock(devlink);
	err = devlink_port_register(devlink, devlink_port, port_index);
	devl_lock(devlink);

	return err;
}

static inline void devl_port_unregister(struct devlink_port *devlink_port)
{
	devl_unlock(devlink_port->devlink);
	devlink_port_unregister(devlink_port);
	devl_lock(devlink_port->devlink);
}
#endif /* NEED_DEVL_PORT_REGISTER */

#ifdef HAVE_DEVLINK_REGIONS
#ifdef NEED_DEVL_REGION_CREATE

struct _kc_devlink_region {
	void *devlink;
};

static inline struct devlink_region
*devl_region_create(struct devlink *devlink,
		    const struct devlink_region_ops *ops,
		    u32 region_max_snapshots, u64 region_size)
{
	struct devlink_region *region;

	devl_unlock(devlink);
#ifdef NEED_DEVLINK_REGION_CREATE_OPS
	region = devlink_region_create(devlink, ops->name, region_max_snapshots,
				       region_size);
#else
	region = devlink_region_create(devlink, ops, region_max_snapshots,
				       region_size);
#endif /* NEED_DEVLINK_REGION_CREATE_OPS */
	devl_lock(devlink);

	return region;
}

static inline void devl_region_destroy(struct devlink_region *region)
{
	devl_unlock(((struct _kc_devlink_region *)(region))->devlink);
	devlink_region_destroy(region);
	devl_lock(((struct _kc_devlink_region *)(region))->devlink);
}
#endif /* NEED_DEVL_REGION_CREATE */
#endif /* HAVE_DEVLINK_REGIONS */

#ifdef NEED_DEVL_PARAMS_REGISTER
static inline int devl_params_register(struct devlink *devlink,
				       const struct devlink_param *params,
				       size_t params_count)
{
	int err;

	devl_unlock(devlink);
	err = devlink_params_register(devlink, params, params_count);
	devl_lock(devlink);

	return err;
}

static inline void devl_params_unregister(struct devlink *devlink,
					  const struct devlink_param *params,
					  size_t params_count)
{
	devl_unlock(devlink);
	devlink_params_unregister(devlink, params, params_count);
	devl_lock(devlink);
}
#endif /* NEED_DEVL_PARAMS_REGISTER */

#ifdef NEED_DEVL_REGISTER
static inline int devl_register(struct devlink *devlink)
{
	devl_unlock(devlink);
#ifdef HAVE_DEVLINK_REGISTER_SETS_DEV
	devlink_register(devlink, devlink->dev);
#else
	devlink_register(devlink);
#endif /* HAVE_DEVLINK_REGISTER_SETS_DEV */
	devl_lock(devlink);

	return 0;
}

static inline void devl_unregister(struct devlink *devlink)
{
	devl_unlock(devlink);
	devlink_unregister(devlink);
	devl_lock(devlink);
}
#endif /* NEED_DEVL_REGISTER */

#ifdef HAVE_DEVLINK_HEALTH
#ifdef NEED_DEVL_HEALTH_REPORTER_CREATE

struct kc_devlink_health_reporter {
	struct list_head list;
	void *priv;
	const struct devlink_health_reporter_ops *ops;
	struct devlink *devlink;
};

static inline struct devlink_health_reporter *
devl_health_reporter_create(struct devlink *devlink,
			    const struct devlink_health_reporter_ops *ops,
			    u64 graceful_period, void *priv)
{
	struct devlink_health_reporter *reporter;

	devl_unlock(devlink);
#ifdef NEED_DEVLINK_HEALTH_DEFAULT_AUTO_RECOVER
	reporter = devlink_health_reporter_create(devlink, ops, graceful_period,
						  !!ops->recover, priv);
#else
	reporter = devlink_health_reporter_create(devlink, ops, graceful_period,
						  priv);
#endif /* NEED_DEVLINK_HEALTH_DEFAULT_AUTO_RECOVER */
	devl_lock(devlink);

	return reporter;
}

static inline void
devl_health_reporter_destroy(struct devlink_health_reporter *reporter)
{
	devl_unlock(((struct kc_devlink_health_reporter *)(reporter))->devlink);
	devlink_health_reporter_destroy(reporter);
	devl_lock(((struct kc_devlink_health_reporter *)(reporter))->devlink);
}
#endif /* NEED_DEVL_HEALTH_REPORTER_CREATE */

#ifdef NEED_DEVLINK_FMSG_DUMP_SKB
/**
 * devlink_fmsg_dump_skb - Dump sk_buffer structure
 * @fmsg: devlink formatted message pointer
 * @skb: pointer to skb
 *
 * Dump diagnostic information about sk_buff structure, like headroom, length,
 * tailroom, MAC, etc.
 */
static inline void devlink_fmsg_dump_skb(struct devlink_fmsg *fmsg,
					 const struct sk_buff *skb)
{
	struct skb_shared_info *sh = skb_shinfo(skb);
	struct sock *sk = skb->sk;
	bool has_mac, has_trans;

	has_mac = skb_mac_header_was_set(skb);
	has_trans = skb_transport_header_was_set(skb);

	devlink_fmsg_pair_nest_start(fmsg, "skb");
	devlink_fmsg_obj_nest_start(fmsg);
	devlink_fmsg_put(fmsg, "actual len", skb->len);
	devlink_fmsg_put(fmsg, "head len", skb_headlen(skb));
	devlink_fmsg_put(fmsg, "data len", skb->data_len);
	devlink_fmsg_put(fmsg, "tail len", skb_tailroom(skb));
	devlink_fmsg_put(fmsg, "MAC", has_mac ? skb->mac_header : -1);
	devlink_fmsg_put(fmsg, "MAC len",
			 has_mac ? skb_mac_header_len(skb) : -1);
	devlink_fmsg_put(fmsg, "network hdr", skb->network_header);
	devlink_fmsg_put(fmsg, "network hdr len",
			 has_trans ? skb_network_header_len(skb) : -1);
	devlink_fmsg_put(fmsg, "transport hdr",
			 has_trans ? skb->transport_header : -1);
	devlink_fmsg_put(fmsg, "csum", (__force u32)skb->csum);
	devlink_fmsg_put(fmsg, "csum_ip_summed", (u8)skb->ip_summed);
	devlink_fmsg_put(fmsg, "csum_complete_sw", !!skb->csum_complete_sw);
	devlink_fmsg_put(fmsg, "csum_valid", !!skb->csum_valid);
	devlink_fmsg_put(fmsg, "csum_level", (u8)skb->csum_level);
	devlink_fmsg_put(fmsg, "sw_hash", !!skb->sw_hash);
	devlink_fmsg_put(fmsg, "l4_hash", !!skb->l4_hash);
	devlink_fmsg_put(fmsg, "proto", ntohs(skb->protocol));
	devlink_fmsg_put(fmsg, "pkt_type", (u8)skb->pkt_type);
	devlink_fmsg_put(fmsg, "iif", skb->skb_iif);

	if (sk) {
		devlink_fmsg_pair_nest_start(fmsg, "sk");
		devlink_fmsg_obj_nest_start(fmsg);
		devlink_fmsg_put(fmsg, "family", sk->sk_type);
		devlink_fmsg_put(fmsg, "type", sk->sk_type);
		devlink_fmsg_put(fmsg, "proto", sk->sk_protocol);
		devlink_fmsg_obj_nest_end(fmsg);
		devlink_fmsg_pair_nest_end(fmsg);
	}

	devlink_fmsg_obj_nest_end(fmsg);
	devlink_fmsg_pair_nest_end(fmsg);

	devlink_fmsg_pair_nest_start(fmsg, "shinfo");
	devlink_fmsg_obj_nest_start(fmsg);
	devlink_fmsg_put(fmsg, "tx_flags", sh->tx_flags);
	devlink_fmsg_put(fmsg, "nr_frags", sh->nr_frags);
	devlink_fmsg_put(fmsg, "gso_size", sh->gso_size);
	devlink_fmsg_put(fmsg, "gso_type", sh->gso_type);
	devlink_fmsg_put(fmsg, "gso_segs", sh->gso_segs);
	devlink_fmsg_obj_nest_end(fmsg);
	devlink_fmsg_pair_nest_end(fmsg);
}
#endif /* NEED_DEVLINK_FMSG_DUMP_SKB */
#endif /* HAVE_DEVLINK_HEALTH */
#endif /* CONFIG_NET_DEVLINK */

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

/* dev_printk implementations */

/* NEED_DEV_LEVEL_ONCE
 *
 * The dev_*_once family of printk functions was introduced by commit
 * e135303bd5be ("device: Add dev_<level>_once variants")
 *
 * The implementation is very straight forward so we will just implement them
 * as-is here.
 *
 * Note that this assumes all dev_*_once macros exist if dev_level_once was
 * found.
 */
#ifdef NEED_DEV_LEVEL_ONCE
#ifdef CONFIG_PRINTK
#define dev_level_once(dev_level, dev, fmt, ...)			\
do {									\
	static bool __print_once __read_mostly;				\
									\
	if (!__print_once) {						\
		__print_once = true;					\
		dev_level(dev, fmt, ##__VA_ARGS__);			\
	}								\
} while (0)
#else
#define dev_level_once(dev_level, dev, fmt, ...)			\
do {									\
	if (0)								\
		dev_level(dev, fmt, ##__VA_ARGS__);			\
} while (0)
#endif

#define dev_emerg_once(dev, fmt, ...)					\
	dev_level_once(dev_emerg, dev, fmt, ##__VA_ARGS__)
#define dev_alert_once(dev, fmt, ...)					\
	dev_level_once(dev_alert, dev, fmt, ##__VA_ARGS__)
#define dev_crit_once(dev, fmt, ...)					\
	dev_level_once(dev_crit, dev, fmt, ##__VA_ARGS__)
#define dev_err_once(dev, fmt, ...)					\
	dev_level_once(dev_err, dev, fmt, ##__VA_ARGS__)
#define dev_warn_once(dev, fmt, ...)					\
	dev_level_once(dev_warn, dev, fmt, ##__VA_ARGS__)
#define dev_notice_once(dev, fmt, ...)					\
	dev_level_once(dev_notice, dev, fmt, ##__VA_ARGS__)
#define dev_info_once(dev, fmt, ...)					\
	dev_level_once(dev_info, dev, fmt, ##__VA_ARGS__)
#define dev_dbg_once(dev, fmt, ...)					\
	dev_level_once(dev_dbg, dev, fmt, ##__VA_ARGS__)
#endif /* NEED_DEV_LEVEL_ONCE */

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO

/* NEED_TC_CLS_CAN_OFFLOAD_AND_CHAIN0
 *
 * tc_cls_can_offload_and_chain0 was added by upstream commit
 * 878db9f0f26d ("pkt_cls: add new tc cls helper to check offload flag and
 * chain index").
 *
 * This patch backports this function for older kernels by calling
 * tc_can_offload() directly.
 */
#ifdef NEED_TC_CLS_CAN_OFFLOAD_AND_CHAIN0
#include <net/pkt_cls.h>
static inline bool
tc_cls_can_offload_and_chain0(const struct net_device *dev,
			      struct tc_cls_common_offload *common)
{
	if (!tc_can_offload(dev))
		return false;
	if (common->chain_index)
		return false;

	return true;
}
#endif /* NEED_TC_CLS_CAN_OFFLOAD_AND_CHAIN0 */
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */

/* NEED_TC_SETUP_QDISC_MQPRIO
 *
 * TC_SETUP_QDISC_MQPRIO was added by upstream commit
 * 575ed7d39e2f ("net_sch: mqprio: Change TC_SETUP_MQPRIO to
 * TC_SETUP_QDISC_MQPRIO").
 *
 * For older kernels which are using TC_SETUP_MQPRIO
 */
#ifdef NEED_TC_SETUP_QDISC_MQPRIO
#define TC_SETUP_QDISC_MQPRIO TC_SETUP_MQPRIO
#endif /* NEED_TC_SETUP_QDISC_MQPRIO */

#ifdef NEED_TCF_MIRRED_DEV
/* NEED_TCF_MIRRED_DEV
 *
 * tcf_mirred_dev was introduced by upstream commit 9f8a739e72f1 ("act_mirred:
 * get rid of tcfm_ifindex from struct tcf_mirred"), which replaced
 * tcf_mirred_ifindex.
 */
#define tcf_mirred_dev(a) \
	rtnl_dereference(to_mirred(a)->tcfm_dev)
#endif /* NEED_TCF_MIRRED_DEV */

#ifdef NEED_TCF_MIRRED_EGRESS_REDIRECT
/* NEED_TCF_MIRRED_EGRESS_REDIRECT
 *
 * is_tcf_mirred_egress_redirect was added by upstream commit 5724b8b56947
 * ("net/sched: tc_mirred: Rename public predicates 'is_tcf_mirred_redirect'
 * and 'is_tcf_mirred_mirror'"), and is a simple rename of
 * is_tcf_mirred_redirect.
 */
#define is_tcf_mirred_egress_redirect(a) is_tcf_mirred_redirect(a)
#endif /* NEED_TCF_MIRRED_EGRESS_REDIRECT */

#ifdef NEED_FLOW_BLOCK_BINDER_TYPE
/* NEED_FLOW_BLOCK_BINDER_TYPE
 *
 * The TCF_BLOCK_BINDER_TYPE enumerations were renamed by commit 32f8c4093ac3
 * ("net: flow_offload: rename TCF_BLOCK_BINDER_TYPE_* to
 * FLOW_BLOCK_BINDER_TYPE_*")
 */
#define FLOW_BLOCK_BINDER_TYPE_UNSPEC TCF_BLOCK_BINDER_TYPE_UNSPEC
#define FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS \
	TCF_BLOCK_BINDER_TYPE_CLSACT_INGRESS
#define FLOW_BLOCK_BINDER_TYPE_CLSACT_EGRESS \
	TCF_BLOCK_BINDER_TYPE_CLSACT_EGRESS
#endif /* NEED_FLOW_BLOCK_BINDER_TYPE */

#ifdef NEED_FLOW_BLOCK_BIND
/* NEED_FLOW_BLOCK_BIND
 *
 * The TCF_BLOCK_BIND and TCF_BLOCK_UNBIND were renamed by commit 9c0e189ec988
 * ("net: flow_offload: rename TC_BLOCK_{UN}BIND to FLOW_BLOCK_{UN}BIND")
 */
#define FLOW_BLOCK_BIND TC_BLOCK_BIND
#define FLOW_BLOCK_UNBIND TC_BLOCK_UNBIND
#endif /* NEED_FLOW_BLOCK_BIND */

#ifdef NEED_FLOW_BLOCK_CB_SETUP_SIMPLE
/* NEED_FLOW_BLOCK_CB_SETUP_SIMPLE
 *
 * flow_block_cb_setup_simple was introduced by commit 4e95bc268b91
 * ("net: flow_offload: add flow_block_cb_setup_simple()") along with several
 * related macros.
 *
 * These are only used by drivers if HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO is
 * true.
 */
#define FLOW_CLS_REPLACE TC_CLSFLOWER_REPLACE
#define FLOW_CLS_DESTROY TC_CLSFLOWER_DESTROY
#define FLOW_CLS_STATS TC_CLSFLOWER_STATS
#define FLOW_CLS_TMPLT_CREATE TC_CLSFLOWER_TMPLT_CREATE
#define FLOW_CLS_TMPLT_DESTROY TC_CLSFLOWER_TMPLT_DESTROY

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
#include <net/pkt_cls.h>

int _kc_flow_block_cb_setup_simple(struct flow_block_offload *f,
				   struct list_head *driver_list,
				   tc_setup_cb_t *cb,
				   void *cb_ident, void *cb_priv,
				   bool ingress_only);

#define flow_block_cb_setup_simple(f, driver_list, cb, cb_ident, cb_priv, \
				   ingress_only) \
	_kc_flow_block_cb_setup_simple(f, driver_list, cb, cb_ident, cb_priv, \
			       ingress_only)
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
#endif /* NEED_FLOW_BLOCK_CB_SETUP_SIMPLE */

/* ART/TSC functions */
#ifdef HAVE_PTP_CROSSTIMESTAMP
/* NEED_CONVERT_ART_NS_TO_TSC
 *
 * convert_art_ns_to_tsc was added by upstream commit fc804f65d462 ("x86/tsc:
 * Convert ART in nanoseconds to TSC").
 *
 * This function is similar to convert_art_to_tsc, but expects the input in
 * terms of nanoseconds, rather than ART cycles. We implement this by
 * accessing the tsc_khz value and performing the proper calculation. In order
 * to access the correct clock object on returning, we use the function
 * convert_art_to_tsc, because the art_related_clocksource is inaccessible.
 */
#if defined(CONFIG_X86) && defined(NEED_CONVERT_ART_NS_TO_TSC)
#include <asm/tsc.h>

static inline struct system_counterval_t convert_art_ns_to_tsc(u64 art_ns)
{
	struct system_counterval_t system;
	u64 tmp, res, rem;

	rem = do_div(art_ns, USEC_PER_SEC);

	res = art_ns * tsc_khz;
	tmp = rem * tsc_khz;

	do_div(tmp, USEC_PER_SEC);
	res += tmp;

	system = convert_art_to_tsc(art_ns);
	system.cycles = res;

	return system;
}
#endif /* CONFIG_X86 && NEED_CONVERT_ART_NS_TO_TSC */
#endif /* HAVE_PTP_CROSSTIMESTAMP */

/* PTP functions and definitions */
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
#include <linux/ptp_clock_kernel.h>
#include <linux/ptp_clock.h>

/* PTP_* ioctl flags
 *
 * PTP_PEROUT_ONE_SHOT and PTP_PEROUT_DUTY_CYCLE were added by commit
 * f65b71aa25a6 ("ptp: add ability to configure duty cycle for periodic
 * output")
 *
 * PTP_PEROUT_PHASE was added in commit b6bd41363a1c ("ptp: introduce
 * a phase offset in the periodic output request")
 *
 * PTP_STRICT_FLAGS was added in commit 6138e687c7b6 ("ptp: Introduce strict
 * checking of external time stamp options.")
 *
 * These flags control behavior for the periodic output PTP ioctl. For older
 * kernels, we define the flags as 0. This allows bitmask checks on flags to
 * work as expected, since these feature flags will become no-ops on kernels
 * that lack support.
 *
 * Drivers can check if the relevant feature is actually supported by using an
 * '#if' on the flag instead of an '#ifdef'
 */
#ifndef PTP_PEROUT_PHASE
#define PTP_PEROUT_PHASE 0
#endif

#ifndef PTP_PEROUT_DUTY_CYCLE
#define PTP_PEROUT_DUTY_CYCLE 0
#endif

#ifndef PTP_STRICT_FLAGS
#define PTP_STRICT_FLAGS 0
#endif

#ifndef PTP_PEROUT_PHASE
/* PTP_PEROUT_PHASE
 *
 * The PTP_PEROUT_PHASE flag was added in commit b6bd41363a1c ("ptp: introduce
 * a phase offset in the periodic output request") as a way for userspace to
 * request a phase-offset periodic output that starts on some arbitrary
 * multiple of the clock period.
 *
 * For older kernels, define this flag to 0 so that checks for if it is
 * enabled will always fail. Drivers should use '#if PTP_PEROUT_PHASE' to
 * determine if the kernel has phase support, and use the flag as normal for
 * checking supported flags or if the flag is enabled for a given request.
 */
#define PTP_PEROUT_PHASE 0
#endif

#endif /* CONFIG_PTP_1588_CLOCK */

/*
 * NEED_PTP_SYSTEM_TIMESTAMP
 *
 * Upstream commit 361800876f80 ("ptp: add PTP_SYS_OFFSET_EXTENDED
 * ioctl") introduces new ioctl, driver and helper functions.
 *
 * Required for PhotonOS 3.0 to correctly support backport of
 * PTP patches introduced in Linux Kernel version 5.0 on 4.x kernels
 */
#ifdef NEED_PTP_SYSTEM_TIMESTAMP
struct ptp_system_timestamp {
	struct timespec64 pre_ts;
	struct timespec64 post_ts;
};

static inline void
ptp_read_system_prets(struct ptp_system_timestamp *sts) { }

static inline void
ptp_read_system_postts(struct ptp_system_timestamp *sts) { }
#endif /* !NEED_PTP_SYSTEM_TIMESTAMP */

#ifdef NEED_PTP_CLASSIFY_RAW
/* NEED_PTP_CLASSIFY_RAW
 *
 * The ptp_classify_raw() function was introduced into <linux/ptp_classify.h>
 * as part of commit 164d8c666521 ("net: ptp: do not reimplement PTP/BPF
 * classifier").
 *
 * The kernel does provide the classifier BPF program since commit
 * 15f0127d1d18 ("net: added a BPF to help drivers detect PTP packets.").
 * However, it requires initializing the BPF filter properly and that varies
 * depending on the kernel version.
 *
 * The only current uses for this function in our drivers is to enhance
 * debugging messages. Rather than re-implementing the function just return
 * PTP_CLASS_NONE indicating that it could not identify any PTP frame.
 */
#include <linux/ptp_classify.h>

static inline unsigned int ptp_classify_raw(struct sk_buff *skb)
{
	return PTP_CLASS_NONE;
}
#endif /* NEED_PTP_CLASSIFY_RAW */

#ifdef NEED_PTP_PARSE_HEADER
/* NEED_PTP_PARSE_HEADER
 *
 * The ptp_parse_header() function was introduced upstream in commit
 * bdfbb63c314a ("ptp: Add generic ptp v2 header parsing function").
 *
 * Since it is straight forward to implement, do so.
 */
#include <linux/ptp_classify.h>

struct clock_identity {
	u8 id[8];
};

struct port_identity {
	struct clock_identity	clock_identity;
	__be16			port_number;
};

struct ptp_header {
	u8			tsmt;  /* transportSpecific | messageType */
	u8			ver;   /* reserved          | versionPTP  */
	__be16			message_length;
	u8			domain_number;
	u8			reserved1;
	u8			flag_field[2];
	__be64			correction;
	__be32			reserved2;
	struct port_identity	source_port_identity;
	__be16			sequence_id;
	u8			control;
	u8			log_message_interval;
} __packed;

static inline struct ptp_header *ptp_parse_header(struct sk_buff *skb,
						  unsigned int type)
{
#if defined(CONFIG_NET_PTP_CLASSIFY)
	u8 *ptr = skb_mac_header(skb);

	if (type & PTP_CLASS_VLAN)
		ptr += VLAN_HLEN;

	switch (type & PTP_CLASS_PMASK) {
	case PTP_CLASS_IPV4:
		ptr += IPV4_HLEN(ptr) + UDP_HLEN;
		break;
	case PTP_CLASS_IPV6:
		ptr += IP6_HLEN + UDP_HLEN;
		break;
	case PTP_CLASS_L2:
		break;
	default:
		return NULL;
	}

	ptr += ETH_HLEN;

	/* Ensure that the entire header is present in this packet. */
	if (ptr + sizeof(struct ptp_header) > skb->data + skb->len)
		return NULL;

	return (struct ptp_header *)ptr;
#else
	return NULL;
#endif
}
#endif /* NEED_PTP_PARSE_HEADER */

#ifdef NEED_CPU_LATENCY_QOS_RENAME
/* NEED_CPU_LATENCY_QOS_RENAME
 *
 * The PM_QOS_CPU_DMA_LATENCY definition was removed in 67b06ba01857 ("PM:
 * QoS: Drop PM_QOS_CPU_DMA_LATENCY and rename related functions"). The
 * related functions were renamed to use "cpu_latency_qos_" prefix.
 *
 * Use wrapper functions to map the new API onto the API available in older
 * kernels.
 */
#include <linux/pm_qos.h>
static inline void
cpu_latency_qos_add_request(struct pm_qos_request *req, s32 value)
{
	pm_qos_add_request(req, PM_QOS_CPU_DMA_LATENCY, value);
}

static inline void
cpu_latency_qos_update_request(struct pm_qos_request *req, s32 new_value)
{
	pm_qos_update_request(req, new_value);
}

static inline void
cpu_latency_qos_remove_request(struct pm_qos_request *req)
{
	pm_qos_remove_request(req);
}
#endif /* NEED_CPU_LATENCY_QOS_RENAME */

#ifdef NEED_DECLARE_STATIC_KEY_FALSE
/* NEED_DECLARE_STATIC_KEY_FALSE
 *
 * DECLARE_STATIC_KEY_FALSE was added by upstream commit b8fb03785d4d
 * ("locking/static_keys: Provide DECLARE and well as DEFINE macros")
 *
 * The definition is now necessary to handle the xdpdrv work with more than 64
 * cpus
 */
#ifdef HAVE_STRUCT_STATIC_KEY_FALSE
#define DECLARE_STATIC_KEY_FALSE(name) extern struct static_key_false name
#else
#define DECLARE_STATIC_KEY_FALSE(name) extern struct static_key name
#endif /* HAVE_STRUCT_STATIC_KEY_FALSE */
#endif /* NEED_DECLARE_STATIC_KEY_FALSE */

#ifdef NEED_DEFINE_STATIC_KEY_FALSE
/* NEED_DEFINE_STATIC_KEY_FALSE
 *
 * DEFINE_STATIC_KEY_FALSE was added by upstream commit 11276d5306b8
 * ("locking/static_keys: Add a new static_key interface")
 *
 * The definition is now necessary to handle the xdpdrv work with more than 64
 * cpus
 */
#define DEFINE_STATIC_KEY_FALSE(name) \
	struct static_key name = STATIC_KEY_INIT_FALSE
#endif /* NEED_DEFINE_STATIC_KEY_FALSE */

#ifdef NEED_STATIC_BRANCH_LIKELY
/* NEED_STATIC_BRANCH_LIKELY
 *
 * static_branch_likely, static_branch_unlikely,
 * static_branch_inc, static_branch_dec was added by upstream commit
 * 11276d5306b8 ("locking/static_keys: Add a new
 * static_key interface")
 *
 * The definition is now necessary to handle the xdpdrv work with more than 64
 * cpus
 *
 * Note that we include all four definitions if static_branch_likely cannot be
 * found in <linux/jump_label.h>.
 */
#define static_branch_likely(x)		likely(static_key_enabled(x))
#define static_branch_unlikely(x)	unlikely(static_key_enabled(x))

#define static_branch_inc(x)		static_key_slow_inc(x)
#define static_branch_dec(x)		static_key_slow_dec(x)

#endif /* NEED_STATIC_BRANCH_LIKELY */

/* PCI related stuff */

/* NEED_PCI_AER_CLEAR_NONFATAL_STATUS
 *
 * 894020fdd88c ("PCI/AER: Rationalize error status register clearing") has
 * renamed pci_cleanup_aer_uncorrect_error_status to more sane name.
 */
#ifdef NEED_PCI_AER_CLEAR_NONFATAL_STATUS
#define pci_aer_clear_nonfatal_status	pci_cleanup_aer_uncorrect_error_status
#endif /* NEED_PCI_AER_CLEAR_NONFATAL_STATUS */

#ifdef NEED_NETDEV_XDP_STRUCT
#define netdev_bpf netdev_xdp
#endif /* NEED_NETDEV_XDP_STRUCT */

#ifdef NEED_NO_NETDEV_PROG_XDP_WARN_ACTION
#ifdef HAVE_XDP_SUPPORT
#include <linux/filter.h>
static inline void
_kc_bpf_warn_invalid_xdp_action(__maybe_unused struct net_device *dev,
				__maybe_unused struct bpf_prog *prog, u32 act)
{
	bpf_warn_invalid_xdp_action(act);
}

#define bpf_warn_invalid_xdp_action(dev, prog, act) \
	_kc_bpf_warn_invalid_xdp_action(dev, prog, act)
#endif /* HAVE_XDP_SUPPORT */
#endif /* HAVE_NETDEV_PROG_XDP_WARN_ACTION */

/* NEED_ETH_HW_ADDR_SET
 *
 * eth_hw_addr_set was added by upstream commit
 * 48eab831ae8b ("net: create netdev->dev_addr assignment helpers")
 *
 * Using eth_hw_addr_set became required in 5.17, when the dev_addr field in
 * the netdev struct was constified. See 48eab831ae8b ("net: create
 * netdev->dev_addr assignment helpers")
 */
#ifdef NEED_ETH_HW_ADDR_SET
static inline void eth_hw_addr_set(struct net_device *dev, const u8 *addr)
{
	ether_addr_copy(dev->dev_addr, addr);
}
#endif /* NEED_ETH_HW_ADDR_SET */

#ifdef NEED_ETH_GET_HEADLEN
/* This is missing on pre 3.18 kernels, most notably on 3.10 used for ESX
 * certification.
 */

/* include headers needed for get_headlen function */
#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
#include <scsi/fc/fc_fcoe.h>
#endif
#ifdef HAVE_SCTP
#include <linux/sctp.h>
#endif
u32 eth_get_headlen(unsigned char *data, unsigned int max_len)
{
	union {
		unsigned char *network;
		/* l2 headers */
		struct ethhdr *eth;
		struct vlan_hdr *vlan;
		/* l3 headers */
		struct iphdr *ipv4;
		struct ipv6hdr *ipv6;
	} hdr;
	__be16 proto;
	u8 nexthdr = 0;	/* default to not TCP */
	u8 hlen;

	/* this should never happen, but better safe than sorry */
	if (max_len < ETH_HLEN)
		return max_len;

	/* initialize network frame pointer */
	hdr.network = data;

	/* set first protocol and move network header forward */
	proto = hdr.eth->h_proto;
	hdr.network += ETH_HLEN;

again:
	switch (proto) {
	/* handle any vlan tag if present */
	case __constant_htons(ETH_P_8021AD):
	case __constant_htons(ETH_P_8021Q):
		if ((hdr.network - data) > (max_len - VLAN_HLEN))
			return max_len;

		proto = hdr.vlan->h_vlan_encapsulated_proto;
		hdr.network += VLAN_HLEN;
		goto again;
	/* handle L3 protocols */
	case __constant_htons(ETH_P_IP):
		if ((hdr.network - data) > (max_len - sizeof(struct iphdr)))
			return max_len;

		/* access ihl as a u8 to avoid unaligned access on ia64 */
		hlen = (hdr.network[0] & 0x0F) << 2;

		/* verify hlen meets minimum size requirements */
		if (hlen < sizeof(struct iphdr))
			return hdr.network - data;

		/* record next protocol if header is present */
		if (!(hdr.ipv4->frag_off & htons(IP_OFFSET)))
			nexthdr = hdr.ipv4->protocol;

		hdr.network += hlen;
		break;
#ifdef NETIF_F_TSO6
	case __constant_htons(ETH_P_IPV6):
		if ((hdr.network - data) > (max_len - sizeof(struct ipv6hdr)))
			return max_len;

		/* record next protocol */
		nexthdr = hdr.ipv6->nexthdr;
		hdr.network += sizeof(struct ipv6hdr);
		break;
#endif /* NETIF_F_TSO6 */
#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
	case __constant_htons(ETH_P_FCOE):
		hdr.network += FCOE_HEADER_LEN;
		break;
#endif
	default:
		return hdr.network - data;
	}

	/* finally sort out L4 */
	switch (nexthdr) {
	case IPPROTO_TCP:
		if ((hdr.network - data) > (max_len - sizeof(struct tcphdr)))
			return max_len;

		/* access doff as a u8 to avoid unaligned access on ia64 */
		hdr.network += max_t(u8, sizeof(struct tcphdr),
				     (hdr.network[12] & 0xF0) >> 2);

		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		hdr.network += sizeof(struct udphdr);
		break;
#ifdef HAVE_SCTP
	case IPPROTO_SCTP:
		hdr.network += sizeof(struct sctphdr);
		break;
#endif
	}

	/*
	 * If everything has gone correctly hdr.network should be the
	 * data section of the packet and will be the end of the header.
	 * If not then it probably represents the end of the last recognized
	 * header.
	 */
	return min_t(unsigned int, hdr.network - data, max_len);
}
#endif /* NEED_ETH_GET_HEADLEN */

/* NEED_ETH_GET_HEADLEN_NET_DEVICE_ARG
 *
 *
 * eth_get_headlen was modified by upstream commit
 * 59753ce8b196 ("ethernet: constify eth_get_headlen()'s data argument")
 * c43f1255b866 ("net: pass net_device argument to the eth_get_headlen")
 *
 * This allows core driver code to simply call eth_get_headlen with all
 * 3 parameters, and have kcompat automatically drop it depending on what
 * the kernel supports.

 * For kernels older than 3.18, eth_get_headlen didn't exist.
 */

#ifdef NEED_ETH_GET_HEADLEN_NET_DEVICE_ARG
static inline u32
__kc_eth_get_headlen(const struct net_device __always_unused *dev,
		void *data, unsigned int len)
{
	return eth_get_headlen(data, len);
}

#define eth_get_headlen(dev, data, len) __kc_eth_get_headlen(dev, data, len)
#endif /* NEED_ETH_GET_HEADLEN_NET_DEVICE_ARG */

#ifdef NEED_JIFFIES_64_TIME_IS_MACROS
/* NEED_JIFFIES_64_TIME_IS_MACROS
 *
 * The jiffies64 time_is_* macros were introduced upstream by 3740dcdf8a77
 * ("jiffies: add time comparison functions for 64 bit jiffies") in Linux 4.9.
 *
 * Support for 64-bit jiffies has been available since the initial import of
 * Linux into git in 2005, so its safe to just implement the macros as-is
 * here.
 */
#define time_is_before_jiffies64(a) time_after64(get_jiffies_64(), a)
#define time_is_after_jiffies64(a) time_before64(get_jiffies_64(), a)
#define time_is_before_eq_jiffies64(a) time_after_eq64(get_jiffies_64(), a)
#define time_is_after_eq_jiffies64(a) time_before_eq64(get_jiffies_64(), a)
#endif /* NEED_JIFFIES_64_TIME_IS_MACROS */

#ifdef NEED_INDIRECT_CALL_WRAPPER_MACROS
/* NEED_INDIRECT_CALL_WRAPPER_MACROS
 *
 * The INDIRECT_CALL_* macros were introduced upstream as upstream commit
 * 283c16a2dfd3 ("indirect call wrappers: helpers to speed-up indirect calls
 * of builtin") which landed in Linux 5.0
 *
 * These are easy to implement directly.
 */
#ifdef CONFIG_RETPOLINE
#define INDIRECT_CALL_1(f, f1, ...)					\
	({								\
		likely(f == f1) ? f1(__VA_ARGS__) : f(__VA_ARGS__);	\
	})
#define INDIRECT_CALL_2(f, f2, f1, ...)					\
	({								\
		likely(f == f2) ? f2(__VA_ARGS__) :			\
				  INDIRECT_CALL_1(f, f1, __VA_ARGS__);	\
	})

#define INDIRECT_CALLABLE_DECLARE(f)	f
#define INDIRECT_CALLABLE_SCOPE
#else /* !CONFIG_RETPOLINE */
#define INDIRECT_CALL_1(f, f1, ...) f(__VA_ARGS__)
#define INDIRECT_CALL_2(f, f2, f1, ...) f(__VA_ARGS__)
#define INDIRECT_CALLABLE_DECLARE(f)
#define INDIRECT_CALLABLE_SCOPE		static
#endif /* CONFIG_RETPOLINE */
#endif /* NEED_INDIRECT_CALL_WRAPPER_MACROS */

#ifdef NEED_INDIRECT_CALL_3_AND_4
/* NEED_INDIRECT_CALL_3_AND_4
 * Support for the 3 and 4 call variants was added in upstream commit
 * e678e9ddea96 ("indirect_call_wrapper: extend indirect wrapper to support up
 * to 4 calls")
 *
 * These are easy to implement directly.
 */

#ifdef CONFIG_RETPOLINE
#define INDIRECT_CALL_3(f, f3, f2, f1, ...)					\
	({									\
		likely(f == f3) ? f3(__VA_ARGS__) :				\
				  INDIRECT_CALL_2(f, f2, f1, __VA_ARGS__);	\
	})
#define INDIRECT_CALL_4(f, f4, f3, f2, f1, ...)					\
	({									\
		likely(f == f4) ? f4(__VA_ARGS__) :				\
				  INDIRECT_CALL_3(f, f3, f2, f1, __VA_ARGS__);	\
	})
#else /* !CONFIG_RETPOLINE */
#define INDIRECT_CALL_3(f, f3, f2, f1, ...) f(__VA_ARGS__)
#define INDIRECT_CALL_4(f, f4, f3, f2, f1, ...) f(__VA_ARGS__)
#endif /* CONFIG_RETPOLINE */
#endif /* NEED_INDIRECT_CALL_3_AND_4 */

#ifdef NEED_EXPORT_INDIRECT_CALLABLE
/* NEED_EXPORT_INDIRECT_CALLABLE
 *
 * Support for EXPORT_INDIRECT_CALLABLE was added in upstream commit
 * 0053859496ba ("net: add EXPORT_INDIRECT_CALLABLE wrapper")
 *
 * These are easy to implement directly.
 */
#ifdef CONFIG_RETPOLINE
#define EXPORT_INDIRECT_CALLABLE(f)	EXPORT_SYMBOL(f)
#else
#define EXPORT_INDIRECT_CALLABLE(f)
#endif /* CONFIG_RETPOLINE */
#endif /* NEED_EXPORT_INDIRECT_CALLABLE */

/* NEED_DEVM_KASPRINTF and NEED_DEVM_KVASPRINTF
 *
 * devm_kvasprintf and devm_kasprintf were added by commit
 * 75f2a4ead5d5 ("devres: Add devm_kasprintf and devm_kvasprintf API")
 * in Linux 3.17.
 */
#ifdef NEED_DEVM_KVASPRINTF
__printf(3, 0) char *devm_kvasprintf(struct device *dev, gfp_t gfp,
				     const char *fmt, va_list ap);
#endif /* NEED_DEVM_KVASPRINTF */

#ifdef NEED_DEVM_KASPRINTF
__printf(3, 4) char *devm_kasprintf(struct device *dev, gfp_t gfp,
				    const char *fmt, ...);
#endif /* NEED_DEVM_KASPRINTF */

#ifdef NEED_XSK_UMEM_GET_RX_FRAME_SIZE
#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifndef xsk_umem_get_rx_frame_size
static inline u32 _xsk_umem_get_rx_frame_size(struct xdp_umem *umem)
{
	return umem->chunk_size_nohr - XDP_PACKET_HEADROOM;
}

#define xsk_umem_get_rx_frame_size _xsk_umem_get_rx_frame_size
#endif /* xsk_umem_get_rx_frame_size */
#endif /* HAVE_AF_XDP_ZC_SUPPORT */
#endif

#ifdef NEED_XSK_BUFF_POOL_RENAME
#define XDP_SETUP_XSK_POOL XDP_SETUP_XSK_UMEM
#define xsk_get_pool_from_qid xdp_get_umem_from_qid
#define xsk_pool_get_rx_frame_size xsk_umem_get_rx_frame_size
#define xsk_pool_set_rxq_info xsk_buff_set_rxq_info
#define xsk_pool_dma_unmap xsk_buff_dma_unmap
#define xsk_pool_dma_map xsk_buff_dma_map
#define xsk_tx_peek_desc xsk_umem_consume_tx
#define xsk_tx_release xsk_umem_consume_tx_done
#define xsk_tx_completed xsk_umem_complete_tx
#define xsk_uses_need_wakeup xsk_umem_uses_need_wakeup
#endif /* NEED_XSK_BUFF_POOL_RENAME */

#ifdef NEED_PCI_IOV_VF_ID
/* NEED_PCI_IOV_VF_ID
 *
 * pci_iov_vf_id were added by commit 21ca9fb62d468 ("PCI/IOV:
 * Add pci_iov_vf_id() to get VF index") in Linux 5.18
 */
int _kc_pci_iov_vf_id(struct pci_dev *dev);
#define pci_iov_vf_id _kc_pci_iov_vf_id
#endif /* NEED_PCI_IOV_VF_ID */

/* NEED_MUL_U64_U64_DIV_U64
 *
 * mul_u64_u64_div_u64 was introduced in Linux 5.9 as part of commit
 * 3dc167ba5729 ("sched/cputime: Improve cputime_adjust()")
 */
#ifdef NEED_MUL_U64_U64_DIV_U64
u64 mul_u64_u64_div_u64(u64 a, u64 mul, u64 div);
#endif /* NEED_MUL_U64_U64_DIV_U64 */

/* NEED_ROUNDUP_U64 and NEED_DIV_U64_ROUND_UP and NEED_DIV_U64_ROUND_CLOSEST
 *
 * roundup_u64 and DIV_U64_FOUND_UP were introduced by commit 1d4ce389da2b
 * ("ice: add and use roundup_u64 instead of open coding equivalent"). They
 * are straight forward to re-implement here.
 */
#ifdef NEED_DIV_U64_ROUND_UP
#define DIV_U64_ROUND_UP(ll, d)		\
	({ u32 _tmp = (d); div_u64((ll) + _tmp - 1, _tmp); })
#endif /* NEED_DIV_U64_ROUND_UP */

#ifdef NEED_ROUNDUP_U64
static inline u64 roundup_u64(u64 x, u32 y)
{
	return DIV_U64_ROUND_UP(x, y) * y;
}
#endif /* NEED_ROUNDUP_U64 */

#ifdef NEED_DIV_U64_ROUND_CLOSEST
#define DIV_U64_ROUND_CLOSEST(dividend, divisor)	\
	({ u32 _tmp = (divisor); div_u64((u64)(dividend) + _tmp / 2, _tmp); })
#endif /* NEED_DIV_U64_ROUND_CLOSEST */

#ifdef NEED_LINKMODE_ZERO
static inline void linkmode_zero(unsigned long *dst)
{
	bitmap_zero(dst, __ETHTOOL_LINK_MODE_MASK_NBITS);
}

static inline void linkmode_copy(unsigned long *dst, const unsigned long *src)
{
	bitmap_copy(dst, src, __ETHTOOL_LINK_MODE_MASK_NBITS);
}

static inline void linkmode_and(unsigned long *dst, const unsigned long *a,
				const unsigned long *b)
{
	bitmap_and(dst, a, b, __ETHTOOL_LINK_MODE_MASK_NBITS);
}

static inline void linkmode_or(unsigned long *dst, const unsigned long *a,
				const unsigned long *b)
{
	bitmap_or(dst, a, b, __ETHTOOL_LINK_MODE_MASK_NBITS);
}

static inline bool linkmode_empty(const unsigned long *src)
{
	return bitmap_empty(src, __ETHTOOL_LINK_MODE_MASK_NBITS);
}

static inline int linkmode_andnot(unsigned long *dst, const unsigned long *src1,
				  const unsigned long *src2)
{
	return bitmap_andnot(dst, src1, src2,  __ETHTOOL_LINK_MODE_MASK_NBITS);
}

static inline void linkmode_set_bit(int nr, volatile unsigned long *addr)
{
	__set_bit(nr, addr);
}

static inline void linkmode_clear_bit(int nr, volatile unsigned long *addr)
{
	__clear_bit(nr, addr);
}

static inline void linkmode_change_bit(int nr, volatile unsigned long *addr)
{
	__change_bit(nr, addr);
}

static inline int linkmode_test_bit(int nr, volatile unsigned long *addr)
{
	return test_bit(nr, addr);
}

static inline int linkmode_equal(const unsigned long *src1,
				 const unsigned long *src2)
{
	return bitmap_equal(src1, src2, __ETHTOOL_LINK_MODE_MASK_NBITS);
}
#else /* !NEED_LINKMODE_ZERO */
#include <linux/linkmode.h>
#endif /* NEED_LINKMODE_ZERO */

#ifdef NEED_LINKMODE_SET_BIT_ARRAY
static inline void linkmode_set_bit_array(const int *array, int array_size,
					  unsigned long *addr)
{
	int i;

	for (i = 0; i < array_size; i++)
		linkmode_set_bit(array[i], addr);
}
#endif /* NEED_LINKMODE_SET_BIT_ARRAY */

#ifdef NEED_ETHTOOL_LINK_MODE_BIT_INDICES
/* Link mode bit indices */
enum ethtool_link_mode_bit_indices {
	ETHTOOL_LINK_MODE_10baseT_Half_BIT      = 0,
	ETHTOOL_LINK_MODE_10baseT_Full_BIT      = 1,
	ETHTOOL_LINK_MODE_100baseT_Half_BIT     = 2,
	ETHTOOL_LINK_MODE_100baseT_Full_BIT     = 3,
	ETHTOOL_LINK_MODE_1000baseT_Half_BIT    = 4,
	ETHTOOL_LINK_MODE_1000baseT_Full_BIT    = 5,
	ETHTOOL_LINK_MODE_Autoneg_BIT           = 6,
	ETHTOOL_LINK_MODE_TP_BIT                = 7,
	ETHTOOL_LINK_MODE_AUI_BIT               = 8,
	ETHTOOL_LINK_MODE_MII_BIT               = 9,
	ETHTOOL_LINK_MODE_FIBRE_BIT             = 10,
	ETHTOOL_LINK_MODE_BNC_BIT               = 11,
	ETHTOOL_LINK_MODE_10000baseT_Full_BIT   = 12,
	ETHTOOL_LINK_MODE_Pause_BIT             = 13,
	ETHTOOL_LINK_MODE_Asym_Pause_BIT        = 14,
	ETHTOOL_LINK_MODE_2500baseX_Full_BIT    = 15,
	ETHTOOL_LINK_MODE_Backplane_BIT         = 16,
	ETHTOOL_LINK_MODE_1000baseKX_Full_BIT   = 17,
	ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT = 18,
	ETHTOOL_LINK_MODE_10000baseKR_Full_BIT  = 19,
	ETHTOOL_LINK_MODE_10000baseR_FEC_BIT    = 20,
	ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT = 21,
	ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT = 22,
	ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT = 23,
	ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT = 24,
	ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT = 25,
	ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT = 26,
	ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT = 27,
	ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT = 28,
	ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT = 29,
	ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT = 30,
#ifdef ETHTOOL_GLINKSETTINGS
	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT	= 31,
	ETHTOOL_LINK_MODE_25000baseKR_Full_BIT	= 32,
	ETHTOOL_LINK_MODE_25000baseSR_Full_BIT	= 33,
	ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT	= 34,
	ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT	= 35,
	ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT	= 36,
	ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT	= 37,
	ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT	= 38,
	ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT	= 39,
	ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT		= 40,
	ETHTOOL_LINK_MODE_1000baseX_Full_BIT	= 41,
	ETHTOOL_LINK_MODE_10000baseCR_Full_BIT	= 42,
	ETHTOOL_LINK_MODE_10000baseSR_Full_BIT	= 43,
	ETHTOOL_LINK_MODE_10000baseLR_Full_BIT	= 44,
	ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT	= 45,
	ETHTOOL_LINK_MODE_10000baseER_Full_BIT	= 46,
	ETHTOOL_LINK_MODE_2500baseT_Full_BIT	= 47,
	ETHTOOL_LINK_MODE_5000baseT_Full_BIT	= 48,

	ETHTOOL_LINK_MODE_FEC_NONE_BIT	= 49,
	ETHTOOL_LINK_MODE_FEC_RS_BIT	= 50,
	ETHTOOL_LINK_MODE_FEC_BASER_BIT	= 51,

	__ETHTOOL_LINK_MODE_LAST
	  = ETHTOOL_LINK_MODE_FEC_BASER_BIT,
#else

	/* Last allowed bit for __ETHTOOL_LINK_MODE_LEGACY_MASK is bit
	 * 31. Please do NOT define any SUPPORTED_* or ADVERTISED_*
	 * macro for bits > 31. The only way to use indices > 31 is to
	 * use the new ETHTOOL_GLINKSETTINGS/ETHTOOL_SLINKSETTINGS API.
	 */

	__ETHTOOL_LINK_MODE_LAST
	  = ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT,
#endif /* !ETHTOOL_GLINKSETTINGS */
};
#endif /* NEED_ETHTOOL_LINK_MODE_BIT_INDICES */

#if defined(NEED_FLOW_MATCH) && defined(HAVE_TC_SETUP_CLSFLOWER)
/* NEED_FLOW_MATCH
 *
 * flow_match*, FLOW_DISSECTOR_MATCH, flow_rule*, flow_rule_match_key, and
 * tc_cls_flower_offload_flow_rule were added by commit
 * 8f2566225ae2 ("flow_offload: add flow_rule and flow_match structures and use
 * them") in Linux 5.1.
 */

#include <net/pkt_cls.h>

struct flow_match {
	struct flow_dissector	*dissector;
	void			*mask;
	void			*key;
};

struct flow_match_basic {
	struct flow_dissector_key_basic *key, *mask;
};

struct flow_match_control {
	struct flow_dissector_key_control *key, *mask;
};

struct flow_match_eth_addrs {
	struct flow_dissector_key_eth_addrs *key, *mask;
};

#ifndef HAVE_TC_FLOWER_VLAN_IN_TAGS
struct flow_match_vlan {
	struct flow_dissector_key_vlan *key, *mask;
};
#endif /* HAVE_TC_FLOWER_VLAN_IN_TAGS */

struct flow_match_ipv4_addrs {
	struct flow_dissector_key_ipv4_addrs *key, *mask;
};

struct flow_match_ipv6_addrs {
	struct flow_dissector_key_ipv6_addrs *key, *mask;
};

#ifdef HAVE_FLOW_DISSECTOR_KEY_IP
struct flow_match_ip {
	struct flow_dissector_key_ip *key, *mask;
};
#endif /* HAVE_FLOW_DISSECTOR_KEY_IP */

struct flow_match_ports {
	struct flow_dissector_key_ports *key, *mask;
};

#ifdef HAVE_TC_FLOWER_ENC
struct flow_match_enc_keyid {
	struct flow_dissector_key_keyid *key, *mask;
};
#endif /* HAVE_TC_FLOWER_ENC */

struct flow_rule {
	struct flow_match	match;
};

static inline struct flow_rule *
tc_cls_flower_offload_flow_rule(struct tc_cls_flower_offload *tc_flow_cmd)
{
	return (struct flow_rule *)&tc_flow_cmd->dissector;
}

static inline bool flow_rule_match_key(const struct flow_rule *rule,
				       enum flow_dissector_key_id key)
{
	return dissector_uses_key(rule->match.dissector, key);
}

#define FLOW_DISSECTOR_MATCH(__rule, __type, __out)				\
	const struct flow_match *__m = &(__rule)->match;			\
	struct flow_dissector *__d = (__m)->dissector;				\
										\
	(__out)->key = skb_flow_dissector_target(__d, __type, (__m)->key);	\
	(__out)->mask = skb_flow_dissector_target(__d, __type, (__m)->mask);	\

static inline void
flow_rule_match_basic(const struct flow_rule *rule,
		      struct flow_match_basic *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_BASIC, out);
}

static inline void
flow_rule_match_control(const struct flow_rule *rule,
			struct flow_match_control *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_CONTROL, out);
}

static inline void
flow_rule_match_eth_addrs(const struct flow_rule *rule,
			  struct flow_match_eth_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS, out);
}

#ifndef HAVE_TC_FLOWER_VLAN_IN_TAGS
static inline void
flow_rule_match_vlan(const struct flow_rule *rule, struct flow_match_vlan *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_VLAN, out);
}
#endif /* HAVE_TC_FLOWER_VLAN_IN_TAGS */

static inline void
flow_rule_match_ipv4_addrs(const struct flow_rule *rule,
			   struct flow_match_ipv4_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS, out);
}

static inline void
flow_rule_match_ipv6_addrs(const struct flow_rule *rule,
			   struct flow_match_ipv6_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS, out);
}

#ifdef HAVE_FLOW_DISSECTOR_KEY_IP
static inline void
flow_rule_match_ip(const struct flow_rule *rule, struct flow_match_ip *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IP, out);
}
#endif /* HAVE_FLOW_DISSECTOR_KEY_IP */

static inline void
flow_rule_match_ports(const struct flow_rule *rule,
		      struct flow_match_ports *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_PORTS, out);
}

#ifdef HAVE_TC_FLOWER_ENC
static inline void
flow_rule_match_enc_control(const struct flow_rule *rule,
			    struct flow_match_control *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_CONTROL, out);
}

static inline void
flow_rule_match_enc_ipv4_addrs(const struct flow_rule *rule,
			       struct flow_match_ipv4_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS, out);
}

static inline void
flow_rule_match_enc_ipv6_addrs(const struct flow_rule *rule,
			       struct flow_match_ipv6_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS, out);
}

#ifdef HAVE_FLOW_DISSECTOR_KEY_IP
#ifdef HAVE_FLOW_DISSECTOR_KEY_ENC_IP
static inline void
flow_rule_match_enc_ip(const struct flow_rule *rule, struct flow_match_ip *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IP, out);
}
#endif /* HAVE_FLOW_DISSECTOR_KEY_ENC_IP */
#endif /* HAVE_FLOW_DISSECTOR_KEY_IP */

static inline void
flow_rule_match_enc_ports(const struct flow_rule *rule,
			  struct flow_match_ports *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_PORTS, out);
}

static inline void
flow_rule_match_enc_keyid(const struct flow_rule *rule,
			  struct flow_match_enc_keyid *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_KEYID, out);
}
#endif /* HAVE_TC_FLOWER_ENC */
#endif /* NEED_FLOW_MATCH && HAVE_TC_SETUP_CLSFLOWER */

/* bitfield / bitmap */

/* NEED_BITMAP_COPY_CLEAR_TAIL
 *
 * backport
 * c724f193619c ("bitmap: new bitmap_copy_safe and bitmap_{from,to}_arr32")
 */
#ifdef NEED_BITMAP_COPY_CLEAR_TAIL
/* Copy bitmap and clear tail bits in last word */
static inline void
bitmap_copy_clear_tail(unsigned long *dst, const unsigned long *src, unsigned int nbits)
{
	bitmap_copy(dst, src, nbits);
	if (nbits % BITS_PER_LONG)
		dst[nbits / BITS_PER_LONG] &= BITMAP_LAST_WORD_MASK(nbits);
}
#endif /* NEED_BITMAP_COPY_CLEAR_TAIL */

/* NEED_BITMAP_FROM_ARR32
 *
 * backport
 * c724f193619c ("bitmap: new bitmap_copy_safe and bitmap_{from,to}_arr32")
 */
#ifdef NEED_BITMAP_FROM_ARR32
#if BITS_PER_LONG == 64
/**
 * bitmap_from_arr32 - copy the contents of u32 array of bits to bitmap
 * @bitmap: array of unsigned longs, the destination bitmap
 * @buf: array of u32 (in host byte order), the source bitmap
 * @nbits: number of bits in @bitmap
 */
static inline void bitmap_from_arr32(unsigned long *bitmap, const u32 *buf,
				     unsigned int nbits)
{
	unsigned int i, halfwords;

	halfwords = DIV_ROUND_UP(nbits, 32);
	for (i = 0; i < halfwords; i++) {
		bitmap[i/2] = (unsigned long) buf[i];
		if (++i < halfwords)
			bitmap[i/2] |= ((unsigned long) buf[i]) << 32;
	}

	/* Clear tail bits in last word beyond nbits. */
	if (nbits % BITS_PER_LONG)
		bitmap[(halfwords - 1) / 2] &= BITMAP_LAST_WORD_MASK(nbits);
}
#else /* BITS_PER_LONG == 64 */
/*
 * On 32-bit systems bitmaps are represented as u32 arrays internally, and
 * therefore conversion is not needed when copying data from/to arrays of u32.
 */
#define bitmap_from_arr32(bitmap, buf, nbits)			\
	bitmap_copy_clear_tail((unsigned long *) (bitmap),	\
			       (const unsigned long *) (buf), (nbits))
#endif /* BITS_PER_LONG == 64 */
#endif /* NEED_BITMAP_FROM_ARR32 */

/* NEED_BITMAP_TO_ARR32
 *
 * backport
 * c724f193619c ("bitmap: new bitmap_copy_safe and bitmap_{from,to}_arr32")
 */
#ifdef NEED_BITMAP_TO_ARR32
#if BITS_PER_LONG == 64
/**
 * bitmap_to_arr32 - copy the contents of bitmap to a u32 array of bits
 *  @buf: array of u32 (in host byte order), the dest bitmap
 *  @bitmap: array of unsigned longs, the source bitmap
 *  @nbits: number of bits in @bitmap
 */
static inline void bitmap_to_arr32(u32 *buf, const unsigned long *bitmap,
				   unsigned int nbits)
{
	unsigned int i, halfwords;

	halfwords = DIV_ROUND_UP(nbits, 32);
	for (i = 0; i < halfwords; i++) {
		buf[i] = (u32) (bitmap[i/2] & UINT_MAX);
		if (++i < halfwords)
			buf[i] = (u32) (bitmap[i/2] >> 32);
	}

	/* Clear tail bits in last element of array beyond nbits. */
	if (nbits % BITS_PER_LONG)
		buf[halfwords - 1] &= (u32) (UINT_MAX >> ((-nbits) & 31));
}
#else
/*
 * On 32-bit systems bitmaps are represented as u32 arrays internally, and
 * therefore conversion is not needed when copying data from/to arrays of u32.
 */
#define bitmap_to_arr32(buf, bitmap, nbits)			\
	bitmap_copy_clear_tail((unsigned long *) (buf),		\
			       (const unsigned long *) (bitmap), (nbits))
#endif /* BITS_PER_LONG == 64 */
#endif /* NEED_BITMAP_TO_ARR32 */

#ifndef HAVE_INCLUDE_BITFIELD
/* linux/bitfield.h has been added in Linux 4.9 in upstream commit
 * 3e9b3112ec74 ("add basic register-field manipulation macros")
 */
#define __bf_shf(x) (__builtin_ffsll(x) - 1)

#define __BF_FIELD_CHECK(_mask, _reg, _val, _pfx)			\
	({								\
		BUILD_BUG_ON_MSG(!__builtin_constant_p(_mask),		\
				 _pfx "mask is not constant");		\
		BUILD_BUG_ON_MSG(!(_mask), _pfx "mask is zero");	\
		BUILD_BUG_ON_MSG(__builtin_constant_p(_val) ?		\
				 ~((_mask) >> __bf_shf(_mask)) & (_val) : 0, \
				 _pfx "value too large for the field"); \
		BUILD_BUG_ON_MSG((_mask) > (typeof(_reg))~0ull,		\
				 _pfx "type of reg too small for mask"); \
		__BUILD_BUG_ON_NOT_POWER_OF_2((_mask) +			\
					      (1ULL << __bf_shf(_mask))); \
	})

/**
 * FIELD_PREP() - prepare a bitfield element
 * @_mask: shifted mask defining the field's length and position
 * @_val:  value to put in the field
 *
 * FIELD_PREP() masks and shifts up the value.  The result should
 * be combined with other fields of the bitfield using logical OR.
 */
#define FIELD_PREP(_mask, _val)						\
	({								\
		__BF_FIELD_CHECK(_mask, 0ULL, _val, "FIELD_PREP: ");	\
		((typeof(_mask))(_val) << __bf_shf(_mask)) & (_mask);	\
	})

/**
 * FIELD_GET() - extract a bitfield element
 * @_mask: shifted mask defining the field's length and position
 * @_reg:  value of entire bitfield
 *
 * FIELD_GET() extracts the field specified by @_mask from the
 * bitfield passed in as @_reg by masking and shifting it down.
 */
#define FIELD_GET(_mask, _reg)						\
	({								\
		__BF_FIELD_CHECK(_mask, _reg, 0U, "FIELD_GET: ");	\
		(typeof(_mask))(((_reg) & (_mask)) >> __bf_shf(_mask));	\
	})
#endif /* HAVE_INCLUDE_BITFIELD */

#ifdef NEED_BITFIELD_FIELD_MAX
/* linux/bitfield.h has FIELD_MAX added to it in Linux 5.7 in upstream
 * commit e31a50162feb ("bitfield.h: add FIELD_MAX() and field_max()")
 */
/**
 * FIELD_MAX() - produce the maximum value representable by a field
 * @_mask: shifted mask defining the field's length and position
 *
 * FIELD_MAX() returns the maximum value that can be held in the field
 * specified by @_mask.
 */
#define FIELD_MAX(_mask)						\
	({								\
		__BF_FIELD_CHECK(_mask, 0ULL, 0ULL, "FIELD_MAX: ");	\
		(typeof(_mask))((_mask) >> __bf_shf(_mask));		\
	})
#endif /* HAVE_BITFIELD_FIELD_MAX */

#ifdef NEED_BITFIELD_FIELD_FIT
/**
 * FIELD_FIT() - check if value fits in the field
 * @_mask: shifted mask defining the field's length and position
 * @_val:  value to test against the field
 *
 * Return: true if @_val can fit inside @_mask, false if @_val is too big.
 */
#define FIELD_FIT(_mask, _val)						\
	({								\
		__BF_FIELD_CHECK(_mask, 0ULL, 0ULL, "FIELD_FIT: ");	\
		!((((typeof(_mask))_val) << __bf_shf(_mask)) & ~(_mask)); \
	})
#endif /* NEED_BITFIELD_FIELD_FIT */

#ifdef NEED_BITFIELD_FIELD_MASK
/**
 * linux/bitfield.h has field_mask() along with *_encode_bits() in 4.16:
 * 00b0c9b82663 ("Add primitives for manipulating bitfields both in host and fixed-endian.")
 *
 */
extern void __compiletime_error("value doesn't fit into mask")
__field_overflow(void);
extern void __compiletime_error("bad bitfield mask")
__bad_mask(void);
static __always_inline u64 field_multiplier(u64 field)
{
	if ((field | (field - 1)) & ((field | (field - 1)) + 1))
		__bad_mask();
	return field & -field;
}
static __always_inline u64 field_mask(u64 field)
{
	return field / field_multiplier(field);
}
#define ____MAKE_OP(type,base,to,from)					\
static __always_inline __##type type##_encode_bits(base v, base field)	\
{									\
	if (__builtin_constant_p(v) && (v & ~field_mask(field)))	\
		__field_overflow();					\
	return to((v & field_mask(field)) * field_multiplier(field));	\
}									\
static __always_inline __##type type##_replace_bits(__##type old,	\
					base val, base field)		\
{									\
	return (old & ~to(field)) | type##_encode_bits(val, field);	\
}									\
static __always_inline void type##p_replace_bits(__##type *p,		\
					base val, base field)		\
{									\
	*p = (*p & ~to(field)) | type##_encode_bits(val, field);	\
}									\
static __always_inline base type##_get_bits(__##type v, base field)	\
{									\
	return (from(v) & field)/field_multiplier(field);		\
}
#define __MAKE_OP(size)							\
	____MAKE_OP(le##size,u##size,cpu_to_le##size,le##size##_to_cpu)	\
	____MAKE_OP(be##size,u##size,cpu_to_be##size,be##size##_to_cpu)	\
	____MAKE_OP(u##size,u##size,,)
__MAKE_OP(16)
__MAKE_OP(32)
__MAKE_OP(64)
#undef __MAKE_OP
#undef ____MAKE_OP
#endif

#ifdef NEED_BUILD_BUG_ON
/* Force a compilation error if a constant expression is not a power of 2 */
#define __BUILD_BUG_ON_NOT_POWER_OF_2(n)	\
	BUILD_BUG_ON(((n) & ((n) - 1)) != 0)

/**
 * BUILD_BUG_ON_MSG - break compile if a condition is true & emit supplied
 *		      error message.
 * @condition: the condition which the compiler should know is false.
 *
 * See BUILD_BUG_ON for description.
 */
#define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)

/**
 * BUILD_BUG_ON - break compile if a condition is true.
 * @condition: the condition which the compiler should know is false.
 *
 * If you have some code which relies on certain constants being equal, or
 * some other compile-time-evaluated condition, you should use BUILD_BUG_ON to
 * detect if someone changes it.
 */
#define BUILD_BUG_ON(condition) \
	BUILD_BUG_ON_MSG(condition, "BUILD_BUG_ON failed: " #condition)
#endif /* NEED_BUILD_BUG_ON */

#ifdef NEED_IN_TASK
#define in_hardirq()		(hardirq_count())
#define in_serving_softirq()	(softirq_count() & SOFTIRQ_OFFSET)
#define in_task()		(!(in_nmi() | in_hardirq() | \
				 in_serving_softirq()))
#endif /* NEED_IN_TASK */

/*
 * NEED_NETIF_NAPI_ADD_NO_WEIGHT
 *
 * Upstream commit b48b89f9c189 ("net: drop the weight argument from
 * netif_napi_add") removes weight argument from function call.
 *
 * Our drivers always used default weight, which is 64.
 *
 * Define NEED_NETIF_NAPI_ADD_NO_WEIGHT on kernels 3.10+ to use old
 * implementation. Undef for 6.1+ where new function was introduced.
 * RedHat 9.2 required using no weight parameter option.
 */
#ifdef NEED_NETIF_NAPI_ADD_NO_WEIGHT
static inline void
_kc_netif_napi_add(struct net_device *dev, struct napi_struct *napi,
		   int (*poll)(struct napi_struct *, int))
{
	return netif_napi_add(dev, napi, poll, NAPI_POLL_WEIGHT);
}

/* RHEL7 complains about redefines. Undef first, then define compat wrapper */
#ifdef netif_napi_add
#undef netif_napi_add
#endif
#define netif_napi_add _kc_netif_napi_add
#endif /* NEED_NETIF_NAPI_ADD_NO_WEIGHT */

/*
 * NEED_ETHTOOL_SPRINTF
 *
 * Upstream commit 7888fe53b706 ("ethtool: Add common function for filling out
 * strings") introduced ethtool_sprintf, which landed in Linux v5.13
 *
 * The function implementation is moved to kcompat.c since the compiler
 * complains it can never be inlined for the function with variable argument
 * lists.
 */
#ifdef NEED_ETHTOOL_SPRINTF
__printf(2, 3) void ethtool_sprintf(u8 **data, const char *fmt, ...);
#endif /* NEED_ETHTOOL_SPRINTF */

/*
 * NEED_SYSFS_MATCH_STRING
 *
 * Upstream commit e1fe7b6a7b37 ("lib/string: add sysfs_match_string helper")
 * introduced a helper for looking up strings in an array - it's pure algo stuff
 * that is easy to backport if needed.
 * Instead of covering sysfs_streq() by yet another flag just copy it.
 */
#ifdef NEED_SYSFS_MATCH_STRING
/*
 * sysfs_streq - return true if strings are equal, modulo trailing newline
 * @s1: one string
 * @s2: another string
 *
 * This routine returns true iff two strings are equal, treating both
 * NUL and newline-then-NUL as equivalent string terminations.  It's
 * geared for use with sysfs input strings, which generally terminate
 * with newlines but are compared against values without newlines.
 */
static inline bool _kc_sysfs_streq(const char *s1, const char *s2)
{
	while (*s1 && *s1 == *s2) {
		s1++;
		s2++;
	}

	if (*s1 == *s2)
		return true;
	if (!*s1 && *s2 == '\n' && !s2[1])
		return true;
	if (*s1 == '\n' && !s1[1] && !*s2)
		return true;
	return false;
}

/*
 * __sysfs_match_string - matches given string in an array
 * @array: array of strings
 * @n: number of strings in the array or -1 for NULL terminated arrays
 * @str: string to match with
 *
 * Returns index of @str in the @array or -EINVAL, just like match_string().
 * Uses sysfs_streq instead of strcmp for matching.
 *
 * This routine will look for a string in an array of strings up to the
 * n-th element in the array or until the first NULL element.
 *
 * Historically the value of -1 for @n, was used to search in arrays that
 * are NULL terminated. However, the function does not make a distinction
 * when finishing the search: either @n elements have been compared OR
 * the first NULL element was found.
 */
static inline int _kc___sysfs_match_string(const char * const *array, size_t n,
					   const char *str)
{
	const char *item;
	int index;

	for (index = 0; index < n; index++) {
		item = array[index];
		if (!item)
			break;
		if (sysfs_streq(item, str))
			return index;
	}

	return -EINVAL;
}

#define sysfs_match_string(_a, _s) \
	_kc___sysfs_match_string(_a, ARRAY_SIZE(_a), _s)

#endif /* NEED_SYSFS_MATCH_STRING */

/*
 * NEED_SYSFS_EMIT
 *
 * Upstream introduced following function in
 * commit 2efc459d06f1 ("sysfs: Add sysfs_emit and sysfs_emit_at to format sysfs output")
 *
 * The function implementation is moved to kcompat.c since the compiler
 * complains it can never be inlined for the function with variable argument
 * lists.
 */
#ifdef NEED_SYSFS_EMIT
__printf(2, 3) int sysfs_emit(char *buf, const char *fmt, ...);
#endif /* NEED_SYSFS_EMIT */

/*
 * HAVE_U64_STATS_FETCH_BEGIN_IRQ
 * HAVE_U64_STATS_FETCH_RETRY_IRQ
 *
 * Upstream commit 44b0c2957adc ("u64_stats: Streamline the implementation")
 * marks u64_stats_fetch_begin_irq() and u64_stats_fetch_retry_irq()
 * as obsolete. Their functionality is combined with: u64_stats_fetch_begin()
 * and u64_stats_fetch_retry().
 *
 * Upstream commit dec5efcffad4 ("u64_stat: Remove the obsolete fetch_irq()
 * variants.") removes u64_stats_fetch_begin_irq() and
 * u64_stats_fetch_retry_irq().
 *
 * Map u64_stats_fetch_begin() and u64_stats_fetch_retry() to the _irq()
 * variants on the older kernels to allow the same driver code working on
 * both old and new kernels.
 */
#ifdef HAVE_U64_STATS_FETCH_BEGIN_IRQ
#define u64_stats_fetch_begin _kc_u64_stats_fetch_begin

static inline unsigned int
_kc_u64_stats_fetch_begin(const struct u64_stats_sync *syncp)
{
	return u64_stats_fetch_begin_irq(syncp);
}
#endif /* HAVE_U64_STATS_FETCH_BEGIN_IRQ */

#ifdef HAVE_U64_STATS_FETCH_RETRY_IRQ
#define u64_stats_fetch_retry _kc_u64_stats_fetch_retry

static inline bool
_kc_u64_stats_fetch_retry(const struct u64_stats_sync *syncp,
			  unsigned int start)
{
	return u64_stats_fetch_retry_irq(syncp, start);
}
#endif /* HAVE_U64_STATS_FETCH_RETRY_IRQ */

/*
 * NEED_U64_STATS_READ
 * NEED_U64_STATS_SET
 *
 * Upstream commit 316580b69d0 ("u64_stats: provide u64_stats_t type")
 * introduces the u64_stats_t data type and other helper APIs to read,
 * add and increment the stats, in Linux v5.5. Support them on older kernels
 * as well.
 *
 * Upstream commit f2efdb179289 ("u64_stats: Introduce u64_stats_set()")
 * introduces u64_stats_set API to set the u64_stats_t variable with the
 * value provided, in Linux v5.16. Add support for older kernels.
 */
#ifdef NEED_U64_STATS_READ
#if BITS_PER_LONG == 64
#include <asm/local64.h>

typedef struct {
	local64_t	v;
} u64_stats_t;

static inline u64 u64_stats_read(u64_stats_t *p)
{
	return local64_read(&p->v);
}

static inline void u64_stats_add(u64_stats_t *p, unsigned long val)
{
	local64_add(val, &p->v);
}

static inline void u64_stats_inc(u64_stats_t *p)
{
	local64_inc(&p->v);
}
#else
typedef struct {
	u64		v;
} u64_stats_t;

static inline u64 u64_stats_read(u64_stats_t *p)
{
	return p->v;
}

static inline void u64_stats_add(u64_stats_t *p, unsigned long val)
{
	p->v += val;
}

static inline void u64_stats_inc(u64_stats_t *p)
{
	p->v++;
}
#endif /* BITS_PER_LONG == 64 */
#endif /* NEED_U64_STATS_READ */

#ifdef NEED_U64_STATS_SET
#if BITS_PER_LONG == 64
static inline void u64_stats_set(u64_stats_t *p, u64 val)
{
	local64_set(&p->v, val);
}
#else
static inline void u64_stats_set(u64_stats_t *p, u64 val)
{
	p->v = val;
}
#endif /* BITS_PER_LONG == 64 */
#endif /* NEED_U64_STATS_SET */

/*
 * NEED_DEVM_KFREE
 * NEED_DEVM_KZALLOC
 *
 * Upstream commit 9ac7849e35f7 ("devres: device resource management")
 * Implement device resource management to allocate and free the resource
 * for driver
 */
#ifdef NEED_DEVM_KFREE
#define devm_kfree(dev, p) kfree(p)
#else
/* Since commit 0571967dfb5d ("devres: constify p in devm_kfree()") the
 * devm_kfree function has accepted a const void * parameter. Since commit
 * cad064f1bd52 ("devres: handle zero size in devm_kmalloc()"), it has also
 * accepted a NULL pointer safely. However, the null pointer acceptance is in
 * devres.c and thus cannot be checked by kcompat-generator.sh. To handle
 * this, unconditionally replace devm_kfree with a variant that both accepts
 * a const void * pointer and handles a NULL value correctly.
 */
static inline void _kc_devm_kfree(struct device *dev, const void *p)
{
	if (p)
		devm_kfree(dev, (void *)p);
}
#define devm_kfree _kc_devm_kfree
#endif /* NEED_DEVM_KFREE */

#ifdef NEED_DEVM_KZALLOC
#define devm_kzalloc(dev, size, flags) kzalloc(size, flags)
#endif /* NEED_DEVM_KZALLOC */

#ifdef NEED_DEVM_KCALLOC
/* NEED_DEVM_KCALLOC
 *
 * Since commit 64c862a839a8 ("devres: add kernel standard devm_k.alloc
 * functions"), the kernel has provided several devres variants of the
 * standard allocation functions.
 */
#define devm_kcalloc(dev, cnt, size, flags) \
	devm_kzalloc(dev, array_size((cnt), (size)), flags)
#endif /* NEED_DEVM_KCALLOC */

#ifdef NEED_DEVM_KSTRDUP
/* NEED_DEVM_KSTRDUP
 *
 * devm_kstrdup was introduced upstream by commit e31108cad3de ("devres:
 * introduce API "devm_kstrdup"").
 */
char *_kc_devm_kstrdup(struct device *dev, const char *s, gfp_t gfp);
#define devm_kstrdup(dev, s, gfp) _kc_devm_kstrdup(dev, s, gfp)
#endif /* NEED_DEVM_KSTRDUP */

#ifdef NEED_DEVM_KMEMDUP
/* NEED_DEVM_KMEMDUP
 *
 * devm_kmemdup was introduced upstream by commit 3046365bb470 ("devres:
 * introduce API "devm_kmemdup").
 */
void *_kc_devm_kmemdup(struct device *dev, const void *src, size_t len,
		       gfp_t gfp);
#define devm_kmemdup _kc_devm_kmemdup
#endif /* NEED_DEVM_KMEMDUP */

/* NEED_DIFF_BY_SCALED_PPM
 *
 * diff_by_scaled_ppm and adjust_by_scaled_ppm were introduced in
 * kernel 6.1 by upstream commit 1060707e3809 ("ptp: introduce helpers
 * to adjust by scaled parts per million").
 */
#ifdef NEED_DIFF_BY_SCALED_PPM
static inline bool
diff_by_scaled_ppm(u64 base, long scaled_ppm, u64 *diff)
{
	bool negative = false;

	if (scaled_ppm < 0) {
		negative = true;
		scaled_ppm = -scaled_ppm;
	}

	*diff = mul_u64_u64_div_u64(base, (u64)scaled_ppm,
				    1000000ULL << 16);

	return negative;
}

static inline u64
adjust_by_scaled_ppm(u64 base, long scaled_ppm)
{
	u64 diff;

	if (diff_by_scaled_ppm(base, scaled_ppm, &diff))
		return base - diff;

	return base + diff;
}
#endif /* NEED_DIFF_BY_SCALED_PPM */

#ifndef HAVE_PCI_MSIX_CAN_ALLOC_DYN
static inline bool pci_msix_can_alloc_dyn(struct pci_dev __always_unused *dev)
{
	return false;
}
#endif /* !HAVE_PCI_MSIX_CAN_ALLOC_DYN */

#if !defined(HAVE_PCI_MSIX_ALLOC_IRQ_AT) && !defined(HAVE_PCI_MSIX_FREE_IRQ)
struct msi_map {
	int	index;
	int	virq;
};
#endif /* !HAVE_PCI_MSIX_ALLOC_IRQ_AT && !HAVE_PCI_MSIX_FREE_IRQ */

#ifndef HAVE_PCI_MSIX_ALLOC_IRQ_AT
#define MSI_ANY_INDEX		UINT_MAX
struct irq_affinity_desc;

static inline struct msi_map
pci_msix_alloc_irq_at(struct pci_dev __always_unused *dev,
		      unsigned int __always_unused index,
		      const struct irq_affinity_desc __always_unused *affdesc)
{
	struct msi_map map = { .index = -ENOTSUPP  };
	return map;
}
#endif /* !HAVE_PCI_MSIX_ALLOC_IRQ_AT */

#ifndef HAVE_PCI_MSIX_FREE_IRQ
static inline void
pci_msix_free_irq(struct pci_dev __always_unused *dev,
		  struct msi_map __always_unused map)
{
}
#endif /* !HAVE_PCI_MSIX_FREE_IRQ */

#ifdef NEED_PCIE_PTM_ENABLED
/* NEED_PCIE_PTM_ENABLED
 *
 * pcie_ptm_enabled was added by upstream commit 014408cd624e
 * ("PCI: Add pcie_ptm_enabled()").
 *
 * It is easy to implement directly.
 */
static inline bool pcie_ptm_enabled(struct pci_dev *dev)
{
#if defined(HAVE_STRUCT_PCI_DEV_PTM_ENABLED) && defined(CONFIG_PCIE_PTM)
	if (!dev)
		return false;

	return dev->ptm_enabled;
#else /* !HAVE_STRUCT_PCI_DEV_PTM_ENABLED || !CONFIG_PCIE_PTM */
	return false;
#endif /* HAVE_STRUCT_PCI_DEV_PTM_ENBED && CONFIG_PCIE_PTM */
}
#endif /* NEED_PCIE_PTM_ENABLED */

/* NEED_PCI_ENABLE_PTM
 *
 * commit ac6c26da29c1 made this function private
 * commit 1d71eb53e451 made this function public again
 * This declares/defines the function for kernels missing it in linux/pci.h
 */
#ifdef NEED_PCI_ENABLE_PTM
#ifdef CONFIG_PCIE_PTM
int pci_enable_ptm(struct pci_dev *dev, u8 *granularity);
#else
static inline int pci_enable_ptm(struct pci_dev *dev, u8 *granularity)
{ return -EINVAL; }
#endif /* CONFIG_PCIE_PTM */
#endif /* NEED_PCI_ENABLE_PTM */

#ifdef NEED_PCI_DISABLE_PTM
/* NEED_PCI_DISABLE_PTM
 *
 * This declares/defines the function for kernels missing it in linux/pci.h
 */
void pci_disable_ptm(struct pci_dev *dev);
#endif /* NEED_PCI_DISABLE_PTM */

/* NEED_PCIE_FLR
 * NEED_PCIE_FLR_RETVAL
 *
 * pcie_flr() was added in the past, but wasn't generally available until 4.12
 * commit a60a2b73ba69 (4.12) made this function available as an extern
 * commit 91295d79d658 (4.17) made this function return int instead of void

 * This declares/defines the function for kernels missing it or needing a
 * retval in linux/pci.h
 */
#ifdef NEED_PCIE_FLR
static inline int pcie_flr(struct pci_dev *dev)
{
	u32 cap;

	pcie_capability_read_dword(dev, PCI_EXP_DEVCAP, &cap);
	if (!(cap & PCI_EXP_DEVCAP_FLR))
		return -ENOTTY;

	if (!pci_wait_for_pending_transaction(dev))
		dev_err(&dev->dev, "timed out waiting for pending transaction; performing function level reset anyway\n");

	pcie_capability_set_word(dev, PCI_EXP_DEVCTL, PCI_EXP_DEVCTL_BCR_FLR);
	msleep(100);
	return 0;
}
#endif /* NEED_PCIE_FLR */
#ifdef NEED_PCIE_FLR_RETVAL
static inline int _kc_pcie_flr(struct pci_dev *dev)
{
	pcie_flr(dev);
	return 0;
}
#define pcie_flr(dev) _kc_pcie_flr((dev))
#endif /* NEED_PCIE_FLR_RETVAL */

/* NEED_DEV_PAGE_IS_REUSABLE
 *
 * dev_page_is_reusable was introduced by
 * commit bc38f30f8dbc ("net:  introduce common dev_page_is_reusable()")
 *
 * This function is trivial to re-implement in full.
 */
#ifdef NEED_DEV_PAGE_IS_REUSABLE
static inline bool dev_page_is_reusable(struct page *page)
{
	return likely(page_to_nid(page) == numa_mem_id() &&
		      !page_is_pfmemalloc(page));
}
#endif /* NEED_DEV_PAGE_IS_REUSABLE */

#ifdef NEED_NAPI_ALLOC_SKB
static inline
struct sk_buff *kc_napi_alloc_skb(struct napi_struct *napi, unsigned int len)
{
	return __napi_alloc_skb(napi, len, GFP_ATOMIC | __GFP_NOWARN);
}

#define napi_alloc_skb(napi, len) kc_napi_alloc_skb(napi, len)
#endif /* NEED_NAPI_ALLOC_SKB */

/* NEED_NAPI_BUILD_SKB
 *
 * napi_build_skb was introduced by
 * commit f450d539c05a: ("skbuff: introduce {,__}napi_build_skb() which reuses NAPI cache heads")
 *
 * This function is a more efficient version of build_skb().
 */
#ifdef NEED_NAPI_BUILD_SKB
static inline
struct sk_buff *napi_build_skb(void *data, unsigned int frag_size)
{
	return build_skb(data, frag_size);
}
#endif /* NEED_NAPI_BUILD_SKB */

/* NEED_DEBUGFS_LOOKUP
 *
 * Old RHELs (7.2-7.4) do not have this backported. Create a stub and always
 * return NULL. Should not affect important features workflow and allows the
 * driver to compile on older kernels.
 */
#ifdef NEED_DEBUGFS_LOOKUP

#include <linux/debugfs.h>

static inline struct dentry *
debugfs_lookup(const char *name, struct dentry *parent)
{
	return NULL;
}
#endif /* NEED_DEBUGFS_LOOKUP */

/* NEED_DEBUGFS_LOOKUP_AND_REMOVE
 *
 * Upstream commit dec9b2f1e0455("debugfs: add debugfs_lookup_and_remove()")
 *
 * Should work the same as upstream equivalent.
 */
#ifdef NEED_DEBUGFS_LOOKUP_AND_REMOVE

#include <linux/debugfs.h>

static inline void
debugfs_lookup_and_remove(const char *name, struct dentry *parent)
{
	struct dentry *dentry;

	dentry = debugfs_lookup(name, parent);
	if (!dentry)
		return;

	debugfs_remove(dentry);
	dput(dentry);
}
#endif /* NEED_DEBUGFS_LOOKUP_AND_REMOVE */

/* NEED_FS_FILE_DENTRY
 *
 * this is simple impl of file_dentry() (introduced in v4.6, backported to
 * stable mainline 4.5 and 4.6 kernels)
 *
 * prior to file_dentry() existence logic of this function was open-coded,
 * and if given kernel has had not backported it, then "oversimplification bugs"
 * are present there anyway.
 */
#ifdef NEED_FS_FILE_DENTRY
static inline struct dentry *file_dentry(const struct file *file)
{
	return file->f_path.dentry;
}
#endif /* NEED_FS_FILE_DENTRY */

/* NEED_CLASS_CREATE_WITHOUT_OWNER
 *
 * Upstream removed owner argument form helper macro class_create in
 * 1aaba11da9aa ("remove module * from class_create()")
 *
 * In dcfbb67e48a2 ("use lock_class_key already present in struct subsys_private")
 * the macro was removed completely.
 *
 * class_create no longer has owner/module param as it was not used.
 */
#ifdef NEED_CLASS_CREATE_WITHOUT_OWNER
static inline struct class *_kc_class_create(const char *name)
{
	return class_create(THIS_MODULE, name);
}
#ifdef class_create
#undef class_create
#endif
#define class_create _kc_class_create
#endif /* NEED_CLASS_CREATE_WITHOUT_OWNER */

/* NEED_LOWER_16_BITS and NEED_UPPER_16_BITS
 *
 * Upstream commit 03cb4473be92 ("ice: add low level PTP clock access
 * functions") introduced the lower_16_bits() and upper_16_bits() macros. They
 * are straight forward to implement if missing.
 */
#ifdef NEED_LOWER_16_BITS
#define lower_16_bits(n) ((u16)((n) & 0xffff))
#endif /* NEED_LOWER_16_BITS */

#ifdef NEED_UPPER_16_BITS
#define upper_16_bits(n) ((u16)((n) >> 16))
#endif /* NEED_UPPER_16_BITS */

#ifdef NEED_HWMON_CHANNEL_INFO
#define HWMON_CHANNEL_INFO(stype, ...)	\
	(&(struct hwmon_channel_info) {	\
		.type = hwmon_##stype,	\
		.config = (u32 []) {	\
			__VA_ARGS__, 0	\
		}			\
	})
#endif /* NEED_HWMON_CHANNEL_INFO */

/* NEED_ASSIGN_BIT
 *
 * Upstream commit 5307e2ad69ab ("bitops: Introduce assign_bit()") added helper
 * assign_bit() to replace if check for setting/clearing bits.
 */
#ifdef NEED_ASSIGN_BIT
static inline void assign_bit(long nr, unsigned long *addr, bool value)
{
	if (value)
		set_bit(nr, addr);
	else
		clear_bit(nr, addr);
}
#endif /* NEED_ASSIGN_BIT */

/*
 * __has_builtin is supported on gcc >= 10, clang >= 3 and icc >= 21.
 * In the meantime, to support gcc < 10, we implement __has_builtin
 * by hand.
 */
#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif

/* NEED___STRUCT_SIZE
 *
 * 9f7d69c5cd23 ("fortify: Convert to struct vs member helpers") of kernel v6.2
 * has added two following macros, one of them used by DEFINE_FLEX()
 */
#ifdef NEED___STRUCT_SIZE
/*
 * When the size of an allocated object is needed, use the best available
 * mechanism to find it. (For cases where sizeof() cannot be used.)
 */
#if __has_builtin(__builtin_dynamic_object_size)
#define __struct_size(p)       __builtin_dynamic_object_size(p, 0)
#define __member_size(p)       __builtin_dynamic_object_size(p, 1)
#else
#define __struct_size(p)       __builtin_object_size(p, 0)
#define __member_size(p)       __builtin_object_size(p, 1)
#endif
#endif /* NEED___STRUCT_SIZE */

/* NEED_KREALLOC_ARRAY
 *
 * krealloc_array was added by upstream commit
 * f0dbd2bd1c22 ("mm: slab: provide krealloc_array()").
 *
 * For older kernels, add a new API wrapper around krealloc().
 */
#ifdef NEED_KREALLOC_ARRAY
static inline void *__must_check krealloc_array(void *p,
						size_t new_n,
						size_t new_size,
						gfp_t flags)
{
	size_t bytes;

	if (unlikely(check_mul_overflow(new_n, new_size, &bytes)))
		return NULL;

	return krealloc(p, bytes, flags);
}
#endif /* NEED_KREALLOC_ARRAY */

/* NEED_KMEM_CACHE_ALLOC_LRU
 *
 * Added in commit 88f2ef73fd66 ("mm: introduce kmem_cache_alloc_lru"),
 * later changed to macro.
 *
 * This improves memory usage, and fallbacks to old impl when lru is NULL,
 * or just when non "_lru" variant is called. We will do that.
 */
#ifdef NEED_KMEM_CACHE_ALLOC_LRU
static inline void *
kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru, gfp_t gfpflags)
{
	return kmem_cache_alloc(s, gfpflags);
}
#endif /* NEED_KMEM_CACHE_ALLOC_LRU */

/* NEED_XDP_DO_FLUSH
 *
 * Upstream commit 1d233886dd90 ("xdp: Use bulking for non-map XDP_REDIRECT
 * and consolidate code paths") replaced xdp_do_flush_map with xdp_do_flush
 * and 7f04bd109d4c ("net: Tree wide: Replace xdp_do_flush_map() with
 * xdp_do_flush()") cleaned up related code.
 */
#ifdef NEED_XDP_DO_FLUSH
static inline void xdp_do_flush(void)
{
	xdp_do_flush_map();
}
#endif /* NEED_XDP_DO_FLUSH */

#ifdef NEED_XDP_FEATURES
enum netdev_xdp_act {
	NETDEV_XDP_ACT_BASIC = 1,
	NETDEV_XDP_ACT_REDIRECT = 2,
	NETDEV_XDP_ACT_NDO_XMIT = 4,
	NETDEV_XDP_ACT_XSK_ZEROCOPY = 8,
	NETDEV_XDP_ACT_HW_OFFLOAD = 16,
	NETDEV_XDP_ACT_RX_SG = 32,
	NETDEV_XDP_ACT_NDO_XMIT_SG = 64,

	NETDEV_XDP_ACT_MASK = 127,
};

typedef u32 xdp_features_t;

static inline void
xdp_set_features_flag(struct net_device *dev, xdp_features_t val)
{
}

static inline void xdp_clear_features_flag(struct net_device *dev)
{
}

static inline void
xdp_features_set_redirect_target(struct net_device *dev, bool support_sg)
{
}

static inline void xdp_features_clear_redirect_target(struct net_device *dev)
{
}
#endif /* NEED_XDP_FEATURES */

#ifdef NEED_FIND_NEXT_BIT_WRAP
/* NEED_FIND_NEXT_BIT_WRAP
 *
 * The find_next_bit_wrap function was added by commit 6cc18331a987
 * ("lib/find_bit: add find_next{,_and}_bit_wrap")
 *
 * For older kernels, define find_next_bit_wrap function that calls
 * find_next_bit function and find_first_bit macro.
 */
static inline
unsigned long find_next_bit_wrap(const unsigned long *addr,
				 unsigned long size, unsigned long offset)
{
	unsigned long bit = find_next_bit(addr, size, offset);

	if (bit < size)
		return bit;

	bit = find_first_bit(addr, offset);
	return bit < offset ? bit : size;
}
#endif /* NEED_FIND_NEXT_BIT_WRAP */

#ifdef NEED_IS_CONSTEXPR
/* __is_constexpr() macro has moved acros 3 upstream kernel headers:
 * commit 3c8ba0d61d04 ("kernel.h: Retain constant expression output for max()/min()")
 * introduced it in kernel.h, for kernel v4.17
 * commit b296a6d53339 ("kernel.h: split out min()/max() et al. helpers") moved
 * it to minmax.h;
 * commit f747e6667ebb ("linux/bits.h: fix compilation error with GENMASK")
 * moved it to its current location of const.h
 */
/*
 * This returns a constant expression while determining if an argument is
 * a constant expression, most importantly without evaluating the argument.
 * Glory to Martin Uecker <Martin.Uecker@med.uni-goettingen.de>
 */
#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))
#endif /* NEED_IS_CONSTEXPR */

/* NEED_DECLARE_FLEX_ARRAY
 *
 * Upstream commit 3080ea5553 ("stddef: Introduce DECLARE_FLEX_ARRAY() helper")
 * introduces DECLARE_FLEX_ARRAY to support flexible arrays in unions or
 * alone in a structure.
 */
#ifdef NEED_DECLARE_FLEX_ARRAY
#define DECLARE_FLEX_ARRAY(TYPE, NAME)	\
	struct { \
		struct { } __empty_ ## NAME; \
		TYPE NAME[]; \
	}
#endif /* NEED_DECLARE_FLEX_ARRAY */

#ifdef NEED_LIST_COUNT_NODES
/* list_count_nodes was added as part of the list.h API by commit 4d70c74659d9
 * ("i915: Move list_count() to list.h as list_count_nodes() for broader use")
 * This landed in Linux v6.3
 *
 * Its straightforward to directly implement the basic loop.
 */
static inline size_t list_count_nodes(struct list_head *head)
{
	struct list_head *pos;
	size_t count = 0;

	list_for_each(pos, head)
		count++;

	return count;
}
#endif /* NEED_LIST_COUNT_NODES */
#ifdef NEED_STATIC_ASSERT
/*
 * NEED_STATIC_ASSERT Introduced with upstream commit 6bab69c6501
 * ("build_bug.h: add wrapper for _Static_assert")
 *  * Available for kernels >= 5.1
 *
 *  Macro for _Static_assert GCC keyword (C11)
 */
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)
#endif /* NEED_STATIC_ASSERT */

#ifdef NEED_ETH_TYPE_VLAN
#include <linux/if_vlan.h>
/**
 * eth_type_vlan was added in commit fe19c4f971a5 ("lan: Check for vlan ethernet
 * types for 8021.q or 802.1ad").
 *
 * eth_type_vlan - check for valid vlan ether type.
 * @ethertype: ether type to check
 *
 * Returns true if the ether type is a vlan ether type.
 */
static inline bool eth_type_vlan(__be16 ethertype)
{
	switch (ethertype) {
	case htons(ETH_P_8021Q):
	case htons(ETH_P_8021AD):
		return true;
	default:
		return false;
	}
}
#endif /* NEED_ETH_TYPE_VLAN */

#ifdef NEED___STRUCT_GROUP
/**
 * __struct_group() - Create a mirrored named and anonyomous struct
 *
 * @TAG: The tag name for the named sub-struct (usually empty)
 * @NAME: The identifier name of the mirrored sub-struct
 * @ATTRS: Any struct attributes (usually empty)
 * @MEMBERS: The member declarations for the mirrored structs
 *
 * Used to create an anonymous union of two structs with identical layout
 * and size: one anonymous and one named. The former's members can be used
 * normally without sub-struct naming, and the latter can be used to
 * reason about the start, end, and size of the group of struct members.
 * The named struct can also be explicitly tagged for layer reuse, as well
 * as both having struct attributes appended.
 */
#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
	union { \
		struct { MEMBERS } ATTRS; \
		struct TAG { MEMBERS } ATTRS NAME; \
	}
#endif /* NEED___STRUCT_GROUP */

#ifdef NEED_STRUCT_GROUP
/**
 * struct_group() - Wrap a set of declarations in a mirrored struct
 *
 * @NAME: The identifier name of the mirrored sub-struct
 * @MEMBERS: The member declarations for the mirrored structs
 *
 * Used to create an anonymous union of two structs with identical
 * layout and size: one anonymous and one named. The former can be
 * used normally without sub-struct naming, and the latter can be
 * used to reason about the start, end, and size of the group of
 * struct members.
 */
#define struct_group(NAME, MEMBERS...)  \
	__struct_group(/* no tag */, NAME, /* no attrs */, MEMBERS)

/**
 * struct_group_tagged() - Create a struct_group with a reusable tag
 *
 * @TAG: The tag name for the named sub-struct
 * @NAME: The identifier name of the mirrored sub-struct
 * @MEMBERS: The member declarations for the mirrored structs
 *
 * Used to create an anonymous union of two structs with identical
 * layout and size: one anonymous and one named. The former can be
 * used normally without sub-struct naming, and the latter can be
 * used to reason about the start, end, and size of the group of
 * struct members. Includes struct tag argument for the named copy,
 * so the specified layout can be reused later.
 */
#define struct_group_tagged(TAG, NAME, MEMBERS...) \
	__struct_group(TAG, NAME, /* no attrs */, MEMBERS)
#endif /* NEED_STRUCT_GROUP */

#ifdef NEED_READ_POLL_TIMEOUT
/*
 * 5f5323a14cad ("iopoll: introduce read_poll_timeout macro")
 * Added in kernel 5.8
 */
#define read_poll_timeout(op, val, cond, sleep_us, timeout_us, \
				sleep_before_read, args...) \
({ \
	u64 __timeout_us = (timeout_us); \
	unsigned long __sleep_us = (sleep_us); \
	ktime_t __timeout = ktime_add_us(ktime_get(), __timeout_us); \
	might_sleep_if((__sleep_us) != 0); \
	if (sleep_before_read && __sleep_us) \
		usleep_range((__sleep_us >> 2) + 1, __sleep_us); \
	for (;;) { \
		(val) = op(args); \
		if (cond) \
			break; \
		if (__timeout_us && \
		    ktime_compare(ktime_get(), __timeout) > 0) { \
			(val) = op(args); \
			break; \
		} \
		if (__sleep_us) \
			usleep_range((__sleep_us >> 2) + 1, __sleep_us); \
		cpu_relax(); \
	} \
	(cond) ? 0 : -ETIMEDOUT; \
})

#endif /* NEED_READ_POLL_TIMEOUT */
#ifdef NEED_READ_POLL_TIMEOUT_ATOMIC
#define read_poll_timeout_atomic(op, val, cond, delay_us, timeout_us, \
					delay_before_read, args...) \
({ \
	u64 __timeout_us = (timeout_us); \
	s64 __left_ns = __timeout_us * NSEC_PER_USEC; \
	unsigned long __delay_us = (delay_us); \
	u64 __delay_ns = __delay_us * NSEC_PER_USEC; \
	if (delay_before_read && __delay_us) { \
		udelay(__delay_us); \
		if (__timeout_us) \
			__left_ns -= __delay_ns; \
	} \
	for (;;) { \
		(val) = op(args); \
		if (cond) \
			break; \
		if (__timeout_us && __left_ns < 0) { \
			(val) = op(args); \
			break; \
		} \
		if (__delay_us) { \
			udelay(__delay_us); \
			if (__timeout_us) \
				__left_ns -= __delay_ns; \
		} \
		cpu_relax(); \
		if (__timeout_us) \
			__left_ns--; \
	} \
	(cond) ? 0 : -ETIMEDOUT; \
})
#endif /* NEED_READ_POLL_TIMEOUT_ATOMIC */
#if !defined(NEED_READ_POLL_TIMEOUT) || !defined(NEED_READ_POLL_TIMEOUT_ATOMIC)
#include <linux/iopoll.h>
#endif /* !NEED_READ_POLL_TIMEOUT || !NEED_READ_POLL_TIMEOUT_ATOMIC */

#ifndef HAVE_DPLL_LOCK_STATUS_ERROR
/* Copied from include/uapi/linux/dpll.h to have common dpll status enums
 * between sysfs and dpll subsystem based solutions.
 * cf4f0f1e1c465 ("dpll: extend uapi by lock status error attribute")
 * Added in kernel 6.9
 */
enum dpll_lock_status_error {
	DPLL_LOCK_STATUS_ERROR_NONE = 1,
	DPLL_LOCK_STATUS_ERROR_UNDEFINED,
	DPLL_LOCK_STATUS_ERROR_MEDIA_DOWN,
	DPLL_LOCK_STATUS_ERROR_FRACTIONAL_FREQUENCY_OFFSET_TOO_HIGH,

	/* private: */
	__DPLL_LOCK_STATUS_ERROR_MAX,
	DPLL_LOCK_STATUS_ERROR_MAX = (__DPLL_LOCK_STATUS_ERROR_MAX - 1)
};

#endif /* HAVE_DPLL_LOCK_STATUS_ERROR */

#ifdef NEED_DPLL_NETDEV_PIN_SET
#define dpll_netdev_pin_set netdev_dpll_pin_set
#define dpll_netdev_pin_clear netdev_dpll_pin_clear
#endif /* NEED_DPLL_NETDEV_PIN_SET */

#ifdef NEED_RADIX_TREE_EMPTY
static inline bool radix_tree_empty(struct radix_tree_root *root)
{
	return !root->rnode;
}
#endif /* NEED_RADIX_TREE_EMPTY */

#ifdef NEED_SET_SCHED_FIFO
/*
 * 7318d4cc14c8 ("sched: Provide sched_set_fifo()")
 * Added in kernel 5.9,
 * converted to a macro for kcompat
 */
#include <linux/sched.h>

#ifdef NEED_SCHED_PARAM
#include <uapi/linux/sched/types.h>
#endif /* NEED_SCHED_PARAM */
#ifdef NEED_RT_H
#include <linux/sched/rt.h>
#else/* NEED_RT_H */
#include <linux/sched/prio.h>
#endif /* NEED_RT_H */
#define sched_set_fifo(p)						   \
({									   \
	struct sched_param sp = { .sched_priority = MAX_RT_PRIO / 2 };	   \
									   \
	WARN_ON_ONCE(sched_setscheduler_nocheck((p), SCHED_FIFO,&sp) != 0);\
})
#endif /* NEED_SET_SCHED_FIFO */

#ifndef HAVE_ETHTOOL_KEEE
#ifndef __ETHTOOL_DECLARE_LINK_MODE_MASK
#define __ETHTOOL_DECLARE_LINK_MODE_MASK(name)		\
	DECLARE_BITMAP(name, __ETHTOOL_LINK_MODE_MASK_NBITS)
#endif /* __ETHTOOL_DECLARE_LINK_MODE_MASK */
struct ethtool_keee {
	__ETHTOOL_DECLARE_LINK_MODE_MASK(supported);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(advertised);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(lp_advertised);
	u32	tx_lpi_timer;
	bool	tx_lpi_enabled;
	bool	eee_active;
	bool	eee_enabled;
};

void eee_to_keee(struct ethtool_keee *keee,
		 const struct ethtool_eee *eee);

void ethtool_convert_legacy_u32_to_link_mode(unsigned long *dst,
					     u32 legacy_u32);
bool ethtool_convert_link_mode_to_legacy_u32(u32 *legacy_u32,
					     const unsigned long *src);
bool ethtool_eee_use_linkmodes(const struct ethtool_keee *eee);

void keee_to_eee(struct ethtool_eee *eee,
		 const struct ethtool_keee *keee);

#ifndef HAVE_MII_EEE_CAP1_MOD_LINKMODE
#include <linux/mdio.h>
#define _kc_linkmode_mod_bit(_nr, _addr, set) do {\
		const int nr = _nr;		\
		unsigned long  *addr = _addr;	\
		if (set)			\
			set_bit(nr, addr);	\
		else				\
			clear_bit(nr, addr);	\
	} while (false)

static inline void mii_eee_cap1_mod_linkmode_t(unsigned long *adv, u32 val)
{
	_kc_linkmode_mod_bit(ETHTOOL_LINK_MODE_100baseT_Full_BIT,
			     adv, val & MDIO_EEE_100TX);
	_kc_linkmode_mod_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT,
			     adv, val & MDIO_EEE_1000T);
	_kc_linkmode_mod_bit(ETHTOOL_LINK_MODE_10000baseT_Full_BIT,
			     adv, val & MDIO_EEE_10GT);
	_kc_linkmode_mod_bit(ETHTOOL_LINK_MODE_1000baseKX_Full_BIT,
			     adv, val & MDIO_EEE_1000KX);
	_kc_linkmode_mod_bit(ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT,
			     adv, val & MDIO_EEE_10GKX4);
	_kc_linkmode_mod_bit(ETHTOOL_LINK_MODE_10000baseKR_Full_BIT,
			     adv, val & MDIO_EEE_10GKR);
}

static inline u32 linkmode_to_mii_eee_cap1_t(unsigned long *adv)
{
	u32 result = 0;

	if (test_bit(ETHTOOL_LINK_MODE_100baseT_Full_BIT, adv))
		result |= MDIO_EEE_100TX;
	if (test_bit(ETHTOOL_LINK_MODE_1000baseT_Full_BIT, adv))
		result |= MDIO_EEE_1000T;
	if (test_bit(ETHTOOL_LINK_MODE_10000baseT_Full_BIT, adv))
		result |= MDIO_EEE_10GT;
	if (test_bit(ETHTOOL_LINK_MODE_1000baseKX_Full_BIT, adv))
		result |= MDIO_EEE_1000KX;
	if (test_bit(ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT, adv))
		result |= MDIO_EEE_10GKX4;
	if (test_bit(ETHTOOL_LINK_MODE_10000baseKR_Full_BIT, adv))
		result |= MDIO_EEE_10GKR;

	return result;
}
#endif /* !HAVE_MII_EEE_CAP1_MOD_LINKMODE */
#endif /* !HAVE_ETHTOOL_KEEE */

#ifdef HAVE_ASSIGN_STR_2_PARAMS
#define _kc__assign_str(dst, src) __assign_str(dst, src)
#else
#define _kc__assign_str(dst, src) __assign_str(dst)
#endif

#if defined(NEED_DIM_END_SAMPLE_BY_POINTER) && defined(HAVE_CONFIG_DIMLIB)
#include <linux/dim.h>

/* Since commit 61bf0009a765 ("dim: pass dim_sample to net_dim() by reference")
 * the net_dim function has accepted a const struct dim_sample * parameter
 * instead of passing struct dim_sample by value.
 */
static inline void _kc_net_dim(struct dim *dim,
			       const struct dim_sample *end_sample)
{
	if (end_sample)
		net_dim(dim, *end_sample);
}

#define net_dim(_dim, _dim_sample) _kc_net_dim(_dim, _dim_sample)
#endif

#ifdef NEED_XSK_BUFF_DMA_SYNC_FOR_CPU_NO_POOL
#include <net/xdp_sock_drv.h>
static inline void
_kc_xsk_buff_dma_sync_for_cpu(struct xdp_buff *xdp)
{
	struct xdp_buff_xsk *xskb = container_of(xdp, struct xdp_buff_xsk, xdp);

	xsk_buff_dma_sync_for_cpu(xdp, xskb->pool);
}

#define xsk_buff_dma_sync_for_cpu(xdp) \
	_kc_xsk_buff_dma_sync_for_cpu(xdp)
#endif /* NEED_XSK_BUFF_DMA_SYNC_FOR_CPU_NO_POOL */

#ifdef NEED_XDP_CONVERT_BUFF_TO_FRAME
#define xdp_convert_buff_to_frame convert_to_xdp_frame
#endif

#ifdef NEED_STR_ENABLED_DISABLED
static inline const char *str_enable_disable(bool v)
{
	return v ? "enable" : "disable";
}

static inline const char *str_enabled_disabled(bool v)
{
	return v ? "enabled" : "disabled";
}

static inline const char *str_read_write(bool v)
{
	return v ? "read" : "write";
}

static inline const char *str_on_off(bool v)
{
	return v ? "on" : "off";
}

static inline const char *str_yes_no(bool v)
{
	return v ? "yes" : "no";
}
#endif /* NEED_STR_ENABLED_DISABLED */
#if !defined(HAVE_LINUX_REFCOUNT_TYPES_HEADER) && !defined(HAVE_LINUX_REFCOUNT_HEADER)

	typedef struct refcount_struct {
		atomic_t refs;
	} refcount_t;
#endif /* HAVE_LINUX_REFCOUNT_TYPES_HEADER && HAVE_LINUX_REFCOUNT_HEADER */

#ifdef NEED_TIMER_DELETE
#define timer_delete del_timer
#define timer_delete_sync del_timer_sync
#endif /* NEED_TIMER_DELETE */

/* Since commit 3652117f8548 ("eventfd: simplify eventfd_signal()") the
 * eventfd_signal() function only takes a single argument. The second
 * argument was only ever passed as 1.
 */
#ifdef NEED_EVENTFD_SIGNAL_NO_COUNTER
static inline
void _kc_eventfd_signal(struct eventfd_ctx *ctx)
{
	eventfd_signal(ctx, 1);
}
#define eventfd_signal(ctx) _kc_eventfd_signal(ctx)
#endif /* NEED_EVENTFD_SIGNAL_NO_COUNTER */

#ifdef NEED_TIMER_CONTAINER_OF
#define timer_container_of(var, callback_timer, timer_fieldname) \
	from_timer(var, callback_timer, timer_fieldname)
#endif /* NEED_TIMER_CONTAINER_OF */
#endif /* _KCOMPAT_IMPL_H_ */
