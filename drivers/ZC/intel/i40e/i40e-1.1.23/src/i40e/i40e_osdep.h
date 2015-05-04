/*******************************************************************************
 *
 * Intel Ethernet Controller XL710 Family Linux Driver
 * Copyright(c) 2013 - 2014 Intel Corporation.
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
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 ******************************************************************************/

#ifndef _I40E_OSDEP_H_
#define _I40E_OSDEP_H_

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/tcp.h>
#include <linux/pci.h>
#include <linux/highuid.h>

#include <linux/io.h>
#include <asm-generic/int-ll64.h>

#ifndef readq
static inline __u64 readq(const volatile void __iomem *addr)
{
	const volatile u32 __iomem *p = addr;
	u32 low, high;

	low = readl(p);
	high = readl(p + 1);

	return low + ((u64)high << 32);
}
#endif

#ifndef writeq
static inline void writeq(__u64 val, volatile void __iomem *addr)
{
	writel(val, addr);
	writel(val >> 32, addr + 4);
}
#endif
#include "kcompat.h"

/* File to be the magic between shared code and
 * actual OS primitives
 */

#undef ASSERT

#define hw_dbg(hw, S, A...)	do {} while (0)

#define I40E_TRACE_REG 0
#define wr32(a, reg, value)	writel((value), ((a)->hw_addr + (reg)))
#define rd32(a, reg)		readl((a)->hw_addr + (reg))

#define wr64(a, reg, value)	writeq((value), ((a)->hw_addr + (reg)))
#define rd64(a, reg)		readq((a)->hw_addr + (reg))
#define i40e_flush(a)		readl((a)->hw_addr + I40E_GLGEN_STAT)

/* memory allocation tracking */
struct i40e_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
} __packed;

#define i40e_allocate_dma_mem(h, m, unused, s, a) \
			i40e_allocate_dma_mem_d(h, m, s, a)
#define i40e_free_dma_mem(h, m) i40e_free_dma_mem_d(h, m)

struct i40e_virt_mem {
	void *va;
	u32 size;
} __packed;

#define i40e_allocate_virt_mem(h, m, s) i40e_allocate_virt_mem_d(h, m, s)
#define i40e_free_virt_mem(h, m) i40e_free_virt_mem_d(h, m)

#define i40e_debug(h, m, s, ...)                                \
do {                                                            \
	if (((m) & (h)->debug_mask))                            \
		pr_info("i40e %02x.%x " s,                      \
			(h)->bus.device, (h)->bus.func,         \
			##__VA_ARGS__);                         \
} while (0)

/* these things are all directly replaced with sed during the kernel build */
#define INLINE inline


#define CPU_TO_LE16(o) cpu_to_le16(o)
#define CPU_TO_LE32(s) cpu_to_le32(s)
#define CPU_TO_LE64(h) cpu_to_le64(h)
#define LE16_TO_CPU(a) le16_to_cpu(a)
#define LE32_TO_CPU(c) le32_to_cpu(c)
#define LE64_TO_CPU(k) le64_to_cpu(k)

/* SW spinlock */
struct i40e_spinlock {
	struct mutex spinlock;
};

#define i40e_init_spinlock(_sp) i40e_init_spinlock_d(_sp)
#define i40e_acquire_spinlock(_sp) i40e_acquire_spinlock_d(_sp)
#define i40e_release_spinlock(_sp) i40e_release_spinlock_d(_sp)
#define i40e_destroy_spinlock(_sp) i40e_destroy_spinlock_d(_sp)

#define I40E_HTONL(a)		htonl(a)

#define i40e_memset(a, b, c, d)  memset((a), (b), (c))
#define i40e_memcpy(a, b, c, d)  memcpy((a), (b), (c))

typedef enum i40e_status_code i40e_status;
#endif /* _I40E_OSDEP_H_ */
