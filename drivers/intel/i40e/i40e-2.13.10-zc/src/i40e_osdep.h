/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2013 - 2020 Intel Corporation. */

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

#define hw_dbg(h, s, ...) do {					\
		pr_debug("i40e %02x:%02x.%x " s,		\
			(h)->bus.bus_id, (h)->bus.device,	\
			(h)->bus.func, ##__VA_ARGS__);		\
} while (0)


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
};

#define i40e_allocate_dma_mem(h, m, unused, s, a) \
			i40e_allocate_dma_mem_d(h, m, unused, s, a)

#define i40e_free_dma_mem(h, m) i40e_free_dma_mem_d(h, m)

struct i40e_virt_mem {
	void *va;
	u32 size;
};

#define i40e_allocate_virt_mem(h, m, s) i40e_allocate_virt_mem_d(h, m, s)
#define i40e_free_virt_mem(h, m) i40e_free_virt_mem_d(h, m)

#define i40e_debug(h, m, s, ...)				\
do {								\
	if (((m) & (h)->debug_mask))				\
		pr_info("i40e %02x:%02x.%x " s,			\
			(h)->bus.bus_id, (h)->bus.device,	\
			(h)->bus.func, ##__VA_ARGS__);		\
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

static inline void i40e_no_action(struct i40e_spinlock *sp)
{
	/* nothing */
}

/* the locks are initialized in _probe and destroyed in _remove
 * so make sure NOT to implement init/destroy here, as to
 * avoid the i40e_init_adminq code trying to reinitialize
 * the persistent lock memory
 */
#define i40e_init_spinlock(_sp)    i40e_no_action(_sp)
#define i40e_acquire_spinlock(_sp) i40e_acquire_spinlock_d(_sp)
#define i40e_release_spinlock(_sp) i40e_release_spinlock_d(_sp)
#define i40e_destroy_spinlock(_sp) i40e_no_action(_sp)


#define i40e_memset(a, b, c, d)  memset((a), (b), (c))
#define i40e_memcpy(a, b, c, d)  memcpy((a), (b), (c))

typedef enum i40e_status_code i40e_status;
#endif /* _I40E_OSDEP_H_ */
