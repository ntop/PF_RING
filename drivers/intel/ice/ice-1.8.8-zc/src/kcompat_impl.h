/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

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

/*
 * generic network stack functions
 */

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

/*
 * tc functions
 */

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

/*
 * devlink support
 */
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

/*
 * dev_printk implementations
 */

/* NEED_DEV_PRINTK_ONCE
 *
 * The dev_*_once family of printk functions was introduced by commit
 * e135303bd5be ("device: Add dev_<level>_once variants")
 *
 * The implementation is very straight forward so we will just implement them
 * as-is here.
 */
#ifdef NEED_DEV_PRINTK_ONCE
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
#endif /* NEED_DEV_PRINTK_ONCE */

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

/*
 * ART/TSC functions
 */
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

/*
 * PTP functions and definitions
 */
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

#ifdef NEED_DEV_PM_DOMAIN_ATTACH_DETACH
#include <linux/acpi.h>
/* NEED_DEV_PM_DOMAIN_ATTACH_DETACH
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
#endif /* NEED_DEV_PM_DOMAIN_ATTACH_DETACH */

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
 * DECLARE_STATIC_KEY_FALSE was added by upstream commit
 * 525e0ac4d2b2 ("locking/static_keys: Provide DECLARE and
 * well as DEFINE macros")
 *
 * The definition is now necessary to handle
 * the xdpdrv work with more than 64 cpus
 */
#define DECLARE_STATIC_KEY_FALSE(name)	\
	extern struct static_key_false name
#endif /* NEED_DECLARE_STATIC_KEY_FALSE */

#ifdef NEED_DEFINE_STATIC_KEY_FALSE
/* NEED_DEFINE_STATIC_KEY_FALSE
 *
 * DEFINE_STATIC_KEY_FALSE was added by upstream commit
 * 11276d5306b8 ("locking/static_keys: Add a new
 * static_key interface")
 *
 * The definition is now necessary to handle
 * the xdpdrv work with more than 64 cpus
 */
#define DECLARE_STATIC_KEY_FALSE(name) extern struct static_key name

#define DEFINE_STATIC_KEY_FALSE(name) \
	struct static_key name = STATIC_KEY_INIT_FALSE
#endif /* NEED_DEFINE_STATIC_KEY_FALSE */

#ifdef NEED_STATIC_BRANCH
/* NEED_STATIC_BRANCH
 *
 * static_branch_likely, static_branch_unlikely,
 * static_branch_inc, static_branch_dec was added by upstream commit
 * 11276d5306b8 ("locking/static_keys: Add a new
 * static_key interface")
 *
 * The definition is now necessary to handle
 * the xdpdrv work with more than 64 cpus
 */
#define static_branch_likely(x)		likely(static_key_enabled(x))
#define static_branch_unlikely(x)	unlikely(static_key_enabled(x))

#define static_branch_inc(x)		static_key_slow_inc(x)
#define static_branch_dec(x)		static_key_slow_dec(x)

#endif /* NEED_STATIC_BRANCH */

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

#ifdef NEED_ETH_HW_ADDR_SET
void _kc_eth_hw_addr_set(struct net_device *dev, const void *addr);
#ifndef eth_hw_addr_set
#define eth_hw_addr_set(dev, addr) \
	_kc_eth_hw_addr_set(dev, addr)
#endif /* eth_hw_addr_set */
#endif /* NEED_ETH_HW_ADDR_SET */

#endif /* _KCOMPAT_IMPL_H_ */
