/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _KCOMPAT_IMPL_H_
#define _KCOMPAT_IMPL_H_

/* This file contains implementations of backports from various kernels. It
 * must rely only on NEED_<FLAG> and HAVE_<FLAG> checks. It must not make any
 * checks to determine the kernel version when deciding whether to include an
 * implementation.
 *
 * All new implementations must go in this file, and legacy implementations
 * should be migrated to the new format over time.
 */

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

#include <net/devlink.h>

#ifdef HAVE_DEVLINK_REGIONS
/* NEED_DEVLINK_REGION_CREATE_OPS
 *
 * The ops parameter to devlink_region_create was added by commit e8937681797c
 * ("devlink: prepare to support region operations")
 *
 * For older kernels, define _kc_devlink_region_create that takes an ops
 * parameter, and calls the old implementation function by extracting the name
 * from the structure.
 */
#ifdef NEED_DEVLINK_REGION_CREATE_OPS
struct devlink_region_ops {
	const char *name;
	void (*destructor)(const void *data);
};

static inline struct devlink_region *
_kc_devlink_region_create(struct devlink *devlink,
			  const struct devlink_region_ops *ops,
			  u32 region_max_snapshots, u64 region_size)
{
	return devlink_region_create(devlink, ops->name, region_max_snapshots,
				     region_size);
}

#define devlink_region_create _kc_devlink_region_create
#endif /* NEED_DEVLINK_REGION_CREATE_OPS */
#endif /* HAVE_DEVLINK_REGIONS */

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

#ifndef DEVLINK_FLASH_OVERWRITE_SETTINGS
#define DEVLINK_FLASH_OVERWRITE_SETTINGS BIT(0)
#endif

#ifndef DEVLINK_FLASH_OVERWRITE_IDENTIFIERS
#define DEVLINK_FLASH_OVERWRITE_IDENTIFIERS BIT(1)
#endif
#endif /* !HAVE_DEVLINK_FLASH_UPDATE_PARAMS */

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

#ifdef NEED_DEVLINK_RESOURCES_UNREGISTER_NO_RESOURCE
/*
 * NEED_DEVLINK_RESOURCES_UNREGISTER_NO_RESOURCE
 *
 * Commit 4c897cfc46 ("devlink: Simplify devlink resources unregister call")
 * removed struct devlink_resource *resource parameter from
 * devlink_resources_unregister() function, if NULL is passed as a resource
 * parameter old version of devlink_resources_unregister() behaves the same
 * way as new implementation removing all resources from:
 * &devlink->resource_list.
 */
static inline void
_kc_devlink_resources_unregister(struct devlink *devlink)
{
	return devlink_resources_unregister(devlink, NULL);
}

#define devlink_resources_unregister _kc_devlink_resources_unregister
#endif /* NEED_DEVLINK_RESOURCES_UNREGISTER_NO_RESOURCE */
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
#ifdef NEED_CONVERT_ART_NS_TO_TSC
#ifdef CONFIG_X86
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
#else /* CONFIG_X86 */
static inline struct system_counterval_t convert_art_ns_to_tsc(u64 art_ns)
{
	WARN_ONCE(1, "%s is only supported on X86", __func__);
	return (struct system_counterval_t){};
}
#endif /* !CONFIG_X86 */
#endif /* NEED_CONVERT_ART_NS_TO_TSC */
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

#ifdef NEED_BUS_FIND_DEVICE_CONST_DATA
/* NEED_BUS_FIND_DEVICE_CONST_DATA
 *
 * bus_find_device() was updated in upstream commit 418e3ea157ef
 * ("bus_find_device: Unify the match callback with class_find_device")
 * to take a const void *data parameter and also have the match() function
 * passed in take a const void *data parameter.
 *
 * all of the kcompat below makes it so the caller can always just call
 * bus_find_device() according to the upstream kernel without having to worry
 * about const vs. non-const arguments.
 */
struct _kc_bus_find_device_custom_data {
	const void *real_data;
	int (*real_match)(struct device *dev, const void *data);
};

static inline int _kc_bus_find_device_wrapped_match(struct device *dev, void *data)
{
	struct _kc_bus_find_device_custom_data *custom_data = data;

	return custom_data->real_match(dev, custom_data->real_data);
}

static inline struct device *
_kc_bus_find_device(struct bus_type *type, struct device *start,
		    const void *data,
		    int (*match)(struct device *dev, const void *data))
{
	struct _kc_bus_find_device_custom_data custom_data = {};

	custom_data.real_data = data;
	custom_data.real_match = match;

	return bus_find_device(type, start, &custom_data,
			       _kc_bus_find_device_wrapped_match);
}

/* force callers of bus_find_device() to call _kc_bus_find_device() on kernels
 * where NEED_BUS_FIND_DEVICE_CONST_DATA is defined
 */
#define bus_find_device(type, start, data, match) \
	_kc_bus_find_device(type, start, data, match)
#endif /* NEED_BUS_FIND_DEVICE_CONST_DATA */

#if defined(NEED_DEV_PM_DOMAIN_ATTACH) && defined(NEED_DEV_PM_DOMAIN_DETACH)
#include <linux/acpi.h>
/* NEED_DEV_PM_DOMAIN_ATTACH and NEED_DEV_PM_DOMAIN_DETACH
 *
 * dev_pm_domain_attach() and dev_pm_domain_detach() were added in upstream
 * commit 46420dd73b80 ("PM / Domains: Add APIs to attach/detach a PM domain for
 * a device"). To support older kernels and OSVs that don't have these API, just
 * implement how older versions worked by directly calling acpi_dev_pm_attach()
 * and acpi_dev_pm_detach().
 */
static inline int dev_pm_domain_attach(struct device *dev, bool power_on)
{
	if (dev->pm_domain)
		return 0;

	if (ACPI_HANDLE(dev))
		return acpi_dev_pm_attach(dev, true);

	return 0;
}

static inline void dev_pm_domain_detach(struct device *dev, bool power_off)
{
	if (ACPI_HANDLE(dev))
		acpi_dev_pm_detach(dev, true);
}
#else /* NEED_DEV_PM_DOMAIN_ATTACH && NEED_DEV_PM_DOMAIN_DETACH */
/* it doesn't make sense to compat only one of these functions, and it is
 * likely either a failure in kcompat-generator.sh or a failed distribution
 * backport if this occurs. Don't try to support it.
 */
#ifdef NEED_DEV_PM_DOMAIN_ATTACH
#error "NEED_DEV_PM_DOMAIN_ATTACH defined but NEED_DEV_PM_DOMAIN_DETACH not defined???"
#endif /* NEED_DEV_PM_DOMAIN_ATTACH */
#ifdef NEED_DEV_PM_DOMAIN_DETACH
#error "NEED_DEV_PM_DOMAIN_DETACH defined but NEED_DEV_PM_DOMAIN_ATTACH not defined???"
#endif /* NEED_DEV_PM_DOMAIN_DETACH */
#endif /* NEED_DEV_PM_DOMAIN_ATTACH && NEED_DEV_PM_DOMAIN_DETACH */

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

#ifdef NEED_XSK_BUFF_DMA_SYNC_FOR_CPU
#ifdef HAVE_MEM_TYPE_XSK_BUFF_POOL
#include <net/xdp_sock_drv.h>
static inline void
_kc_xsk_buff_dma_sync_for_cpu(struct xdp_buff *xdp,
			      void __always_unused *pool)
{
	xsk_buff_dma_sync_for_cpu(xdp);
}

#define xsk_buff_dma_sync_for_cpu(xdp, pool) \
	_kc_xsk_buff_dma_sync_for_cpu(xdp, pool)
#endif /* HAVE_MEM_TYPE_XSK_BUFF_POOL */
#endif /* NEED_XSK_BUFF_DMA_SYNC_FOR_CPU */

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

#ifndef HAVE_LINKMODE
static inline void linkmode_set_bit(int nr, volatile unsigned long *addr)
{
	__set_bit(nr, addr);
}

static inline void linkmode_zero(unsigned long *dst)
{
	bitmap_zero(dst, __ETHTOOL_LINK_MODE_MASK_NBITS);
}
#endif /* !HAVE_LINKMODE */

#ifndef ETHTOOL_GLINKSETTINGS
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

	/* Last allowed bit for __ETHTOOL_LINK_MODE_LEGACY_MASK is bit
	 * 31. Please do NOT define any SUPPORTED_* or ADVERTISED_*
	 * macro for bits > 31. The only way to use indices > 31 is to
	 * use the new ETHTOOL_GLINKSETTINGS/ETHTOOL_SLINKSETTINGS API.
	 */

	__ETHTOOL_LINK_MODE_LAST
	  = ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT,
};
#endif /* !ETHTOOL_GLINKSETTINGS */

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
 * The function is easy to directly implement.
 */
#ifdef NEED_ETHTOOL_SPRINTF
static inline
__printf(2, 3) void ethtool_sprintf(u8 **data, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(*data, ETH_GSTRING_LEN, fmt, args);
	va_end(args);

	*data += ETH_GSTRING_LEN;
}
#endif /* NEED_ETHTOOL_SPRINTF */

/*
 * NEED_SYSFS_EMIT
 *
 * Upstream introduced following function in
 * commit 2efc459d06f1 ("sysfs: Add sysfs_emit and sysfs_emit_at to format sysfs output")
 */
#ifdef NEED_SYSFS_EMIT
static inline __printf(2, 3)
int sysfs_emit(char *buf, const char *fmt, ...)
{
	va_list args;
	int len;

	if (WARN(!buf || offset_in_page(buf),
		 "invalid sysfs_emit: buf:%p\n", buf))
		return 0;

	va_start(args, fmt);
	len = vscnprintf(buf, PAGE_SIZE, fmt, args);
	va_end(args);

	return len;
}
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
static inline void _kc_devm_kfree(struct device *dev, void *p)
{
	/* Upstream devm_kfree() has this NULL check since
	 * commit cad064f1bd52 ("devres: handle zero size in devm_kmalloc()"),
	 * but it's done in devres.c (not header), so we could NOT use
	 * kcompat generator to check for it's presence.
	 */
	if (p)
		devm_kfree(dev, p);
}
#define devm_kfree _kc_devm_kfree
#endif /* NEED_DEVM_KFREE */

#ifdef NEED_DEVM_KZALLOC
#define devm_kzalloc(dev, size, flags) kzalloc(size, flags)
#endif /* NEED_DEVM_KZALLOC */

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

/* NEED_CLASS_CREATE_WITH_MODULE_PARAM
 *
 * Upstream removed owner argument form helper macro class_create in
 * 1aaba11da9aa ("remove module * from class_create()")
 *
 * In dcfbb67e48a2 ("use lock_class_key already present in struct subsys_private")
 * the macro was removed completely.
 *
 * class_create no longer has owner/module param as it was not used.
 */
#ifdef NEED_CLASS_CREATE_WITH_MODULE_PARAM
static inline struct class *_kc_class_create(const char *name)
{
	return class_create(THIS_MODULE, name);
}
#ifdef class_create
#undef class_create
#endif
#define class_create _kc_class_create
#endif /* NEED_CLASS_CREATE_WITH_MODULE_PARAM */

#endif /* _KCOMPAT_IMPL_H_ */
