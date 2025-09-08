/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_OSDEP_H_
#define _ICE_OSDEP_H_

#include "kcompat.h"
#ifdef NEED_CLEANUP_API
#include "kcompat_cleanup.h"
#endif
#include <linux/types.h>
#ifdef HAVE_INCLUDE_BITFIELD
#include <linux/bitfield.h>
#endif /* HAVE_INCLUDE_BITFIELD */
#include <linux/bitops.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <linux/io.h>
#ifndef NEED_READ_POLL_TIMEOUT
#include <linux/iopoll.h>
#endif /* !NEED_READ_POLL_TIMEOUT */
#include <linux/pci_ids.h>
#include <linux/types.h>

struct ice_hw;

/**
 * struct ice_hw_addr_map - a single hardware address memory map
 * @addr: iomem address of the start of this map
 * @start: register offset at the start of this map, inclusive bound
 * @end: register offset at the end of this map, exclusive bound
 * @bar: the BAR this map is for
 *
 * Structure representing one map of a device BAR register space. Stored as
 * part of the ice_hw_addr structure in an array ordered by the start offset.
 *
 * The addr value is an iomem address returned by ioremap. The start indicates
 * the first register offset this map is valid for. The end indicates the end
 * of the map, and is an exclusive bound.
 */
struct ice_hw_addr_map {
	void __iomem *addr;
	resource_size_t start;
	resource_size_t end;
	int bar;
};

/**
 * struct ice_hw_addr - a list of hardware address memory maps
 * @nr: the number of maps made
 * @maps: flexible array of maps made during device initialization
 *
 * Structure representing a series of sparse maps of the device BAR 0 address
 * space to kernel addresses. Users must convert a register offset to an iomem
 * address using ice_get_hw_addr.
 */
struct ice_hw_addr {
	unsigned int nr;
	struct ice_hw_addr_map maps[];
};

void __iomem *ice_get_hw_addr(struct ice_hw *hw, resource_size_t reg);

#define wr32(a, reg, value)	writel((value), ice_get_hw_addr((a), (reg)))
#define rd32(a, reg)		readl(ice_get_hw_addr((a), (reg)))
#define wr64(a, reg, value)	writeq((value), ice_get_hw_addr((a), (reg)))
#define rd64(a, reg)		readq(ice_get_hw_addr((a), (reg)))

#define rd32_poll_timeout(a, addr, val, cond, delay_us, timeout_us) \
	read_poll_timeout(rd32, val, cond, delay_us, timeout_us, false, a, addr)
#define rd32_poll_timeout_atomic(a, addr, val, cond, delay_us, timeout_us) \
	read_poll_timeout_atomic(rd32, val, cond, delay_us, timeout_us, false, \
				 a, addr)

#define rd32_poll_timeout_atomic(a, addr, val, cond, delay_us, timeout_us) \
	read_poll_timeout_atomic(rd32, val, cond, delay_us, timeout_us, false, \
				 a, addr)
#define vlock_rd32_poll_timeout(a, addr, val, cond, delay_us_sleepable,      \
				delay_us_nonsleepable, timeout_us_sleepable, \
				timeout_us_nonsleepable, vlock)              \
	((vlock)->sleepable ?                                                \
		rd32_poll_timeout(a, addr, val, cond, delay_us_sleepable,    \
				  timeout_us_sleepable) :                    \
		rd32_poll_timeout_atomic(a, addr, val, cond,                 \
					 delay_us_nonsleepable,              \
					 timeout_us_nonsleepable))

#define ice_flush(a)		rd32((a), GLGEN_STAT)

#define ICE_M(m, s)		((m ## UL) << (s))

struct ice_dma_mem {
	void *va;
	dma_addr_t pa;
	size_t size;
};

struct device *ice_hw_to_dev(struct ice_hw *hw);

#ifdef CONFIG_SYMBOLIC_ERRNAME
/**
 * ice_print_errno - logs message with appended error
 * @func: logging function (such as dev_err, netdev_warn, etc.)
 * @obj: first argument that func takes
 * @code: standard error code (negative integer)
 * @fmt: format string (without "\n" in the end)
 *
 * Uses kernel logging function of your choice to log provided message
 * with error code and (if allowed by kernel) its symbolic
 * representation apended. All additional format arguments can be
 * added at the end.
 * Supports only functions that take an additional
 * argument before formatted string.
 */
#define ice_print_errno(func, obj, code, fmt, args...) ({		\
	long code_ = (code);						\
	BUILD_BUG_ON(fmt[strlen(fmt) - 1] == '\n');			\
	func(obj, fmt ", error: %ld (%pe)\n",				\
	     ##args, code_, ERR_PTR(code_));				\
})
/**
 * ice_err_arg - replaces error code as a logging function argument
 * @err: standard error code (negative integer)
 */
#define ice_err_arg(err) ERR_PTR(err)
/**
 * ice_err_format - replaces %(l)d format corresponding to an error code
 */
#define ice_err_format() "%pe"
#else
#define ice_print_errno(func, obj, code, fmt, args...) ({		\
	BUILD_BUG_ON(fmt[strlen(fmt) - 1] == '\n');			\
	func(obj, fmt ", error: %ld\n",	 ##args, (long)code);		\
})
#define ice_err_arg(err) ((long)err)
#define ice_err_format() "%ld"
#endif /* CONFIG_SYMBOLIC_ERRNAME */
#define ice_dev_err_errno(dev, code, fmt, args...)			\
	ice_print_errno(dev_err, dev, code, fmt, ##args)
#define ice_dev_warn_errno(dev, code, fmt, args...)			\
	ice_print_errno(dev_warn, dev, code, fmt, ##args)
#define ice_dev_info_errno(dev, code, fmt, args...)			\
	ice_print_errno(dev_info, dev, code, fmt, ##args)
#define ice_dev_dbg_errno(dev, code, fmt, args...)			\
	ice_print_errno(dev_dbg, dev, code, fmt, ##args)

#ifdef CONFIG_DYNAMIC_DEBUG
#define ice_debug(hw, type, fmt, args...) \
	dev_dbg(ice_hw_to_dev(hw), fmt, ##args)

#define _ice_debug_array(hw, type, prefix, rowsize, groupsize, buf, len) \
	print_hex_dump_debug(prefix, DUMP_PREFIX_OFFSET,		 \
			     rowsize, groupsize, buf, len, false)
#else /* CONFIG_DYNAMIC_DEBUG */
#define ice_debug(hw, type, fmt, args...)			\
do {								\
	if ((type) & (hw)->debug_mask)				\
		dev_info(ice_hw_to_dev(hw), fmt, ##args);	\
} while (0)

#ifdef DEBUG
#define _ice_debug_array(hw, type, prefix, rowsize, groupsize, buf, len) \
do {								\
	if ((type) & (hw)->debug_mask)				\
		print_hex_dump_debug(prefix, DUMP_PREFIX_OFFSET,\
				     rowsize, groupsize, buf,	\
				     len, false);		\
} while (0)

#else /* DEBUG */
#define _ice_debug_array(hw, type, prefix, rowsize, groupsize, buf, len) \
do {								\
	struct ice_hw *hw_l = hw;				\
	if ((type) & (hw_l)->debug_mask) {			\
		u16 len_l = len;				\
		u8 *buf_l = buf;				\
		int i;						\
		for (i = 0; i < (len_l - 16); i += 16)		\
			ice_debug(hw_l, type, "0x%04X  %16ph\n",\
				  i, ((buf_l) + i));		\
		if (i < len_l)					\
			ice_debug(hw_l, type, "0x%04X  %*ph\n", \
				  i, ((len_l) - i), ((buf_l) + i));\
	}							\
} while (0)

#endif /* DEBUG */
#endif /* CONFIG_DYNAMIC_DEBUG */

#define ice_debug_array(hw, type, rowsize, groupsize, buf, len) \
	_ice_debug_array(hw, type, KBUILD_MODNAME, rowsize, groupsize, buf, len)

#define ice_debug_array_w_prefix(hw, type, prefix, buf, len) \
	_ice_debug_array(hw, type, prefix, 16, 1, buf, len)

#endif /* _ICE_OSDEP_H_ */
