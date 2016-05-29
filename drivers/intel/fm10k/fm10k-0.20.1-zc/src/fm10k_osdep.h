/* Intel(R) Ethernet Switch Host Interface Driver
 * Copyright(c) 2013 - 2016 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 */

/* glue for the OS independent part of fm10k
 * includes register access macros
 */

#ifndef _FM10K_OSDEP_H_
#define _FM10K_OSDEP_H_
#include "kcompat.h"

/* forward declaration */
struct fm10k_hw;

#define FM10K_REMOVED(hw_addr) unlikely(!(hw_addr))

/* PCI configuration read */
u16 fm10k_read_pci_cfg_word(struct fm10k_hw *hw, u32 reg);

/* read operations, indexed using DWORDS */
u32 fm10k_read_reg(struct fm10k_hw *hw, int reg);
#define fm10k_read_reg_array(hw, reg, idx) fm10k_read_reg((hw), (reg) + (idx))

/* write operations, indexed using DWORDS */
#define fm10k_write_reg(hw, reg, val) \
do { \
	u32 __iomem *hw_addr = ACCESS_ONCE((hw)->hw_addr); \
	if (!FM10K_REMOVED(hw_addr)) \
		writel((val), &hw_addr[(reg)]); \
} while (0)
#define fm10k_write_reg_array(hw, reg, idx, val) \
	fm10k_write_reg((hw), (reg) + (idx), (val))

/* Switch register write operations, index using DWORDS */
#define fm10k_write_sw_reg(hw, reg, val) \
do { \
	u32 __iomem *sw_addr = ACCESS_ONCE((hw)->sw_addr); \
	if (!FM10K_REMOVED(sw_addr)) \
		writel((val), &sw_addr[(reg)]); \
} while (0)

/* read ctrl register which has no clear on read fields as PCIe flush */
#define fm10k_write_flush(hw) fm10k_read_reg((hw), FM10K_CTRL)

/* used by shared code to declare unused parameters */
#define UNREFERENCED_XPARAMETER
#define UNREFERENCED_1PARAMETER(_p)			\
	uninitialized_var(_p)
#define UNREFERENCED_2PARAMETER(_p, _q) do {		\
	uninitialized_var(_p);				\
	uninitialized_var(_q);				\
} while (0)
#define UNREFERENCED_3PARAMETER(_p, _q, _r) do {	\
	uninitialized_var(_p);				\
	uninitialized_var(_q);				\
	uninitialized_var(_r);				\
} while (0)
#define UNREFERENCED_4PARAMETER(_p, _q, _r, _s) do {	\
	uninitialized_var(_p);				\
	uninitialized_var(_q);				\
	uninitialized_var(_r);				\
	uninitialized_var(_s);				\
} while (0)

#endif /* _FM10K_OSDEP_H_ */
