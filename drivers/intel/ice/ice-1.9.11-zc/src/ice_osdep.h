/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

#ifndef _ICE_OSDEP_H_
#define _ICE_OSDEP_H_

#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/bitops.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/pci_ids.h>
#include "kcompat.h"

#define wr32(a, reg, value)	writel((value), ((a)->hw_addr + (reg)))
#define rd32(a, reg)		readl((a)->hw_addr + (reg))
#define wr64(a, reg, value)	writeq((value), ((a)->hw_addr + (reg)))
#define rd64(a, reg)		readq((a)->hw_addr + (reg))

#define ice_flush(a)		rd32((a), GLGEN_STAT)

#define ICE_M(m, s)		((m) << (s))

struct ice_dma_mem {
	void *va;
	dma_addr_t pa;
	size_t size;
};

struct ice_hw;
struct device *ice_hw_to_dev(struct ice_hw *hw);

#define ice_info_fwlog(hw, rowsize, groupsize, buf, len)	\
	print_hex_dump(KERN_INFO, " FWLOG: ",			\
		       DUMP_PREFIX_NONE,			\
		       rowsize, groupsize, buf,			\
		       len, false)

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

#define ice_debug_array(hw, type, rowsize, groupsize, buf, len) \
	print_hex_dump_debug(KBUILD_MODNAME " ",		\
			     DUMP_PREFIX_OFFSET, rowsize,	\
			     groupsize, buf, len, false)
#else
#define ice_debug(hw, type, fmt, args...)			\
do {								\
	if ((type) & (hw)->debug_mask)				\
		dev_info(ice_hw_to_dev(hw), fmt, ##args);	\
} while (0)

#ifdef DEBUG
#define ice_debug_array(hw, type, rowsize, groupsize, buf, len) \
do {								\
	if ((type) & (hw)->debug_mask)				\
		print_hex_dump_debug(KBUILD_MODNAME,		\
				     DUMP_PREFIX_OFFSET,	\
				     rowsize, groupsize, buf,	\
				     len, false);		\
} while (0)

#else
#define ice_debug_array(hw, type, rowsize, groupsize, buf, len) \
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

#endif /* _ICE_OSDEP_H_ */
