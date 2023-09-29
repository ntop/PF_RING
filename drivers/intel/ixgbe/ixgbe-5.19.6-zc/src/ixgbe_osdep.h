/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 1999 - 2023 Intel Corporation */

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

#define IXGBE_CPU_TO_BE16(_x) cpu_to_be16(_x)
#define IXGBE_BE16_TO_CPU(_x) be16_to_cpu(_x)
#define IXGBE_CPU_TO_BE32(_x) cpu_to_be32(_x)
#define IXGBE_BE32_TO_CPU(_x) be32_to_cpu(_x)

#define msec_delay(_x) msleep(_x)

#define usec_delay(_x) udelay(_x)

#define STATIC static

#define IOMEM __iomem

#ifdef DBG
#define ASSERT(_x)		BUG_ON(!(_x))
#else
#define ASSERT(_x)		do {} while (0)
#endif

#define DEBUGFUNC(S)		do {} while (0)

#define IXGBE_SFP_DETECT_RETRIES	2

struct ixgbe_hw;
struct ixgbe_msg {
	u16 msg_enable;
};
struct net_device *ixgbe_hw_to_netdev(const struct ixgbe_hw *hw);
struct ixgbe_msg *ixgbe_hw_to_msg(const struct ixgbe_hw *hw);

#ifdef DBG
#define hw_dbg(hw, format, arg...) \
	netdev_dbg(ixgbe_hw_to_netdev(hw), format, ## arg)
#else
#define hw_dbg(hw, format, arg...) do {} while (0)
#endif

#define hw_err(hw, format, arg...) \
	netdev_err(ixgbe_hw_to_netdev(hw), format, ## arg)
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

#define IXGBE_DEAD_READ_RETRIES 10
#define IXGBE_DEAD_READ_REG 0xdeadbeefU
#define IXGBE_FAILED_READ_REG 0xffffffffU
#define IXGBE_FAILED_READ_RETRIES 5
#define IXGBE_FAILED_READ_CFG_DWORD 0xffffffffU
#define IXGBE_FAILED_READ_CFG_WORD 0xffffU
#define IXGBE_FAILED_READ_CFG_BYTE 0xffU

#define IXGBE_WRITE_REG_ARRAY(a, reg, offset, value) \
	IXGBE_WRITE_REG((a), (reg) + ((offset) << 2), (value))

#define IXGBE_READ_REG(h, r) ixgbe_read_reg(h, r, false)
#define IXGBE_R32_Q(h, r) ixgbe_read_reg(h, r, true)
#define IXGBE_R8_Q(h, r) readb(READ_ONCE(h->hw_addr) + r)

#define IXGBE_READ_REG_ARRAY(a, reg, offset) ( \
	IXGBE_READ_REG((a), (reg) + ((offset) << 2)))

#ifndef writeq
#define writeq(val, addr)	do { writel((u32) (val), addr); \
				     writel((u32) (val >> 32), (addr + 4)); \
				} while (0);
#endif

#define IXGBE_WRITE_FLUSH(a) IXGBE_READ_REG(a, IXGBE_STATUS)

u32 ixgbe_read_reg(struct ixgbe_hw *, u32 reg, bool quiet);
extern u16 ixgbe_read_pci_cfg_word(struct ixgbe_hw *hw, u32 reg);
extern void ixgbe_write_pci_cfg_word(struct ixgbe_hw *hw, u32 reg, u16 value);
extern void ewarn(struct ixgbe_hw *hw, const char *str);

#define IXGBE_READ_PCIE_WORD ixgbe_read_pci_cfg_word
#define IXGBE_WRITE_PCIE_WORD ixgbe_write_pci_cfg_word
#define IXGBE_EEPROM_GRANT_ATTEMPS 100
#define IXGBE_HTONL(_i) htonl(_i)
#define IXGBE_NTOHL(_i) ntohl(_i)
#define IXGBE_NTOHS(_i) ntohs(_i)
#define IXGBE_CPU_TO_LE32(_i) cpu_to_le32(_i)
#define IXGBE_CPU_TO_LE16(_i) cpu_to_le16(_i)
#define IXGBE_LE16_TO_CPU(_i) le16_to_cpu(_i)
#define IXGBE_LE32_TO_CPU(_i) le32_to_cpu(_i)
#define IXGBE_LE32_TO_CPUS(_i) le32_to_cpus(_i)
#define IXGBE_LE64_TO_CPU(_i) le64_to_cpu(_i)
#define EWARN(H, W) ewarn(H, W)

enum {
	IXGBE_ERROR_SOFTWARE,
	IXGBE_ERROR_POLLING,
	IXGBE_ERROR_INVALID_STATE,
	IXGBE_ERROR_UNSUPPORTED,
	IXGBE_ERROR_ARGUMENT,
	IXGBE_ERROR_CAUTION,
};

#define ERROR_REPORT(level, format, arg...) do {				\
	switch (level) {							\
	case IXGBE_ERROR_SOFTWARE:						\
	case IXGBE_ERROR_CAUTION:						\
	case IXGBE_ERROR_POLLING:						\
		netif_warn(ixgbe_hw_to_msg(hw), drv, ixgbe_hw_to_netdev(hw),	\
			   format, ## arg);					\
		break;								\
	case IXGBE_ERROR_INVALID_STATE:						\
	case IXGBE_ERROR_UNSUPPORTED:						\
	case IXGBE_ERROR_ARGUMENT:						\
		netif_err(ixgbe_hw_to_msg(hw), hw, ixgbe_hw_to_netdev(hw),	\
			  format, ## arg);					\
		break;								\
	default:								\
		break;								\
	}									\
} while (0)

#define ERROR_REPORT1 ERROR_REPORT
#define ERROR_REPORT2 ERROR_REPORT
#define ERROR_REPORT3 ERROR_REPORT

#define UNREFERENCED_XPARAMETER
#define UNREFERENCED_1PARAMETER(_p) do {		\
	uninitialized_var(_p);				\
} while (0)
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

#endif /* _IXGBE_OSDEP_H_ */
