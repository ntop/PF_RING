/*******************************************************************************

  Intel 10 Gigabit PCI Express Linux driver
  Copyright (c) 1999 - 2014 Intel Corporation.

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
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/


/* glue for the OS independent part of ixgbe
 * includes register access macros
 */

#ifndef _IXGBE_OSDEP_H_
#define _IXGBE_OSDEP_H_

#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/if_ether.h>
#include <linux/sched.h>
#include "kcompat.h"


#ifndef msleep
#define msleep(x)	do { if (in_interrupt()) { \
				/* Don't mdelay in interrupt context! */ \
				BUG(); \
			} else { \
				msleep(x); \
			} } while (0)

#endif

#undef ASSERT

#ifdef DBG
#define hw_dbg(hw, S, A...)	printk(KERN_DEBUG S, ## A)
#else
#define hw_dbg(hw, S, A...)	do {} while (0)
#endif

struct ixgbe_hw;
struct ixgbe_msg {
	u16 msg_enable;
};
struct net_device *ixgbe_hw_to_netdev(const struct ixgbe_hw *hw);
struct ixgbe_msg *ixgbe_hw_to_msg(const struct ixgbe_hw *hw);

#define e_dev_info(format, arg...) \
	dev_info(pci_dev_to_dev(adapter->pdev), format, ## arg)
#define e_dev_warn(format, arg...) \
	dev_warn(pci_dev_to_dev(adapter->pdev), format, ## arg)
#define e_dev_err(format, arg...) \
	dev_err(pci_dev_to_dev(adapter->pdev), format, ## arg)
#define e_dev_notice(format, arg...) \
	dev_notice(pci_dev_to_dev(adapter->pdev), format, ## arg)
#define e_dbg(msglvl, format, arg...) \
	netif_dbg(adapter, msglvl, adapter->netdev, format, ## arg)
#define e_info(msglvl, format, arg...) \
	netif_info(adapter, msglvl, adapter->netdev, format, ## arg)
#define e_err(msglvl, format, arg...) \
	netif_err(adapter, msglvl, adapter->netdev, format, ## arg)
#define e_warn(msglvl, format, arg...) \
	netif_warn(adapter, msglvl, adapter->netdev, format, ## arg)
#define e_crit(msglvl, format, arg...) \
	netif_crit(adapter, msglvl, adapter->netdev, format, ## arg)


#define IXGBE_FAILED_READ_REG 0xffffffffU
#define IXGBE_FAILED_READ_CFG_DWORD 0xffffffffU
#define IXGBE_FAILED_READ_CFG_WORD 0xffffU
#define IXGBE_FAILED_READ_CFG_BYTE 0xffU
#define IXGBE_WRITE_REG_ARRAY(a, reg, offset, value) \
	IXGBE_WRITE_REG((a), (reg) + ((offset) << 2), (value))

#define IXGBE_READ_REG_ARRAY(a, reg, offset) ( \
	IXGBE_READ_REG((a), (reg) + ((offset) << 2)))

#ifndef writeq
#define writeq(val, addr)	do { writel((u32) (val), addr); \
				     writel((u32) (val >> 32), (addr + 4)); \
				} while (0);
#endif

#define IXGBE_WRITE_FLUSH(a) IXGBE_READ_REG(a, IXGBE_STATUS)

void ixgbe_check_remove(struct ixgbe_hw *hw, u32 reg);
extern u16 ixgbe_read_pci_cfg_word(struct ixgbe_hw *hw, u32 reg);
extern void ixgbe_write_pci_cfg_word(struct ixgbe_hw *hw, u32 reg, u16 value);
extern void ewarn(struct ixgbe_hw *hw, const char *str, u32 status);

#define IXGBE_READ_PCIE_WORD ixgbe_read_pci_cfg_word
#define IXGBE_WRITE_PCIE_WORD ixgbe_write_pci_cfg_word
#define IXGBE_EEPROM_GRANT_ATTEMPS 100
#define IXGBE_HTONL(_i) htonl(_i)
#define IXGBE_NTOHL(_i) ntohl(_i)
#define IXGBE_NTOHS(_i) ntohs(_i)
#define IXGBE_CPU_TO_LE32(_i) cpu_to_le32(_i)
#define IXGBE_LE32_TO_CPUS(_i) le32_to_cpus(_i)
#define EWARN(H, W, S) ewarn(H, W, S)

enum {
	IXGBE_ERROR_SOFTWARE,
	IXGBE_ERROR_POLLING,
	IXGBE_ERROR_INVALID_STATE,
	IXGBE_ERROR_UNSUPPORTED,
	IXGBE_ERROR_ARGUMENT,
	IXGBE_ERROR_CAUTION,
};

#define ERROR_REPORT(level, format, arg...) do {			\
	switch (level) {						\
	case IXGBE_ERROR_SOFTWARE:					\
	case IXGBE_ERROR_CAUTION:					\
	case IXGBE_ERROR_POLLING:					\
		netif_dbg(ixgbe_hw_to_msg(hw), drv, ixgbe_hw_to_netdev(hw), \
			  format, ## arg);				\
		break;							\
	case IXGBE_ERROR_INVALID_STATE:					\
	case IXGBE_ERROR_UNSUPPORTED:					\
	case IXGBE_ERROR_ARGUMENT:					\
		netif_err(ixgbe_hw_to_msg(hw), hw, ixgbe_hw_to_netdev(hw), \
			  format, ## arg);				\
		break;							\
	default:							\
		break;							\
	}								\
} while (0)

#define ERROR_REPORT1 ERROR_REPORT
#define ERROR_REPORT2 ERROR_REPORT
#define ERROR_REPORT3 ERROR_REPORT
#endif /* _IXGBE_OSDEP_H_ */
