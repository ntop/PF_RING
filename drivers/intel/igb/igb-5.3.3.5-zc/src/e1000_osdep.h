/*******************************************************************************

  Intel(R) Gigabit Ethernet Linux driver
  Copyright(c) 2007-2015 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  Linux NICS <linux.nics@intel.com>
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

/* glue for the OS independent part of e1000
 * includes register access macros
 */

#ifndef _E1000_OSDEP_H_
#define _E1000_OSDEP_H_

#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/sched.h>
#include "kcompat.h"

#define usec_delay(x) udelay(x)
#define usec_delay_irq(x) udelay(x)
#ifndef msec_delay
#define msec_delay(x) do { \
	/* Don't mdelay in interrupt context! */ \
	if (in_interrupt()) \
		BUG(); \
	else \
		msleep(x); \
} while (0)

/* Some workarounds require millisecond delays and are run during interrupt
 * context.  Most notably, when establishing link, the phy may need tweaking
 * but cannot process phy register reads/writes faster than millisecond
 * intervals...and we establish link due to a "link status change" interrupt.
 */
#define msec_delay_irq(x) mdelay(x)

#define E1000_READ_REG(x, y) e1000_read_reg(x, y)
#endif

#define PCI_COMMAND_REGISTER   PCI_COMMAND
#define CMD_MEM_WRT_INVALIDATE PCI_COMMAND_INVALIDATE
#define ETH_ADDR_LEN           ETH_ALEN

#ifdef __BIG_ENDIAN
#define E1000_BIG_ENDIAN __BIG_ENDIAN
#endif

#ifdef DEBUG
#define DEBUGOUT(S) pr_debug(S)
#define DEBUGOUT1(S, A...) pr_debug(S, ## A)
#else
#define DEBUGOUT(S)
#define DEBUGOUT1(S, A...)
#endif

#ifdef DEBUG_FUNC
#define DEBUGFUNC(F) DEBUGOUT(F "\n")
#else
#define DEBUGFUNC(F)
#endif
#define DEBUGOUT2 DEBUGOUT1
#define DEBUGOUT3 DEBUGOUT2
#define DEBUGOUT7 DEBUGOUT3

#define E1000_REGISTER(a, reg) reg

/* forward declaration */
struct e1000_hw;

/* write operations, indexed using DWORDS */
#define E1000_WRITE_REG(hw, reg, val) \
do { \
	u8 __iomem *hw_addr = ACCESS_ONCE((hw)->hw_addr); \
	if (!E1000_REMOVED(hw_addr)) \
		writel((val), &hw_addr[(reg)]); \
} while (0)

u32 e1000_read_reg(struct e1000_hw *hw, u32 reg);

#define E1000_WRITE_REG_ARRAY(hw, reg, idx, val) \
	E1000_WRITE_REG((hw), (reg) + ((idx) << 2), (val))

#define E1000_READ_REG_ARRAY(hw, reg, idx) ( \
		e1000_read_reg((hw), (reg) + ((idx) << 2)))

#define E1000_READ_REG_ARRAY_DWORD E1000_READ_REG_ARRAY
#define E1000_WRITE_REG_ARRAY_DWORD E1000_WRITE_REG_ARRAY

#define E1000_WRITE_REG_ARRAY_WORD(a, reg, offset, value) ( \
	writew((value), ((a)->hw_addr + E1000_REGISTER(a, reg) + \
	((offset) << 1))))

#define E1000_READ_REG_ARRAY_WORD(a, reg, offset) ( \
	readw((a)->hw_addr + E1000_REGISTER(a, reg) + ((offset) << 1)))

#define E1000_WRITE_REG_ARRAY_BYTE(a, reg, offset, value) ( \
	writeb((value), ((a)->hw_addr + E1000_REGISTER(a, reg) + (offset))))

#define E1000_READ_REG_ARRAY_BYTE(a, reg, offset) ( \
	readb((a)->hw_addr + E1000_REGISTER(a, reg) + (offset)))

#define E1000_WRITE_REG_IO(a, reg, offset) do { \
	outl(reg, ((a)->io_base));                  \
	outl(offset, ((a)->io_base + 4)); \
	} while (0)

#define E1000_WRITE_FLUSH(a) E1000_READ_REG(a, E1000_STATUS)

#define E1000_WRITE_FLASH_REG(a, reg, value) ( \
	writel((value), ((a)->flash_address + reg)))

#define E1000_WRITE_FLASH_REG16(a, reg, value) ( \
	writew((value), ((a)->flash_address + reg)))

#define E1000_READ_FLASH_REG(a, reg) (readl((a)->flash_address + reg))

#define E1000_READ_FLASH_REG16(a, reg) (readw((a)->flash_address + reg))

#define E1000_REMOVED(h) unlikely(!(h))

#endif /* _E1000_OSDEP_H_ */
