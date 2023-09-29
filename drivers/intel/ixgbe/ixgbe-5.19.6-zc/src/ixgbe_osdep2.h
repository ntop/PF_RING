/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 1999 - 2023 Intel Corporation */

#ifndef _IXGBE_OSDEP2_H_
#define _IXGBE_OSDEP2_H_

static inline bool ixgbe_removed(void __iomem *addr)
{
	return unlikely(!addr);
}
#define IXGBE_REMOVED(a) ixgbe_removed(a)

static inline void IXGBE_WRITE_REG(struct ixgbe_hw *hw, u32 reg, u32 value)
{
	u8 __iomem *reg_addr;

	reg_addr = READ_ONCE(hw->hw_addr);
	if (IXGBE_REMOVED(reg_addr))
		return;
#ifdef DBG
	{
		struct net_device *netdev = ixgbe_hw_to_netdev(hw);

		switch (reg) {
		case IXGBE_EIMS:
		case IXGBE_EIMC:
		case IXGBE_EIAM:
		case IXGBE_EIAC:
		case IXGBE_EICR:
		case IXGBE_EICS:
			netdev_info(netdev,
				    "%s: Reg - 0x%05X, value - 0x%08X\n",
				    __func__, reg, value);
		}
	}
#endif /* DBG */
	writel(value, reg_addr + reg);
}

static inline void IXGBE_WRITE_REG64(struct ixgbe_hw *hw, u32 reg, u64 value)
{
	u8 __iomem *reg_addr;

	reg_addr = READ_ONCE(hw->hw_addr);
	if (IXGBE_REMOVED(reg_addr))
		return;
	writeq(value, reg_addr + reg);
}

#endif /* _IXGBE_OSDEP2_H_ */
