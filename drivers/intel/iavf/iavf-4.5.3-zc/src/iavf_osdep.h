/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2013, Intel Corporation. */

#ifndef _IAVF_OSDEP_H_
#define _IAVF_OSDEP_H_

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
		pr_debug("iavf %02x:%02x.%x " s,		\
			(h)->bus.bus_id, (h)->bus.device,	\
			(h)->bus.func, ##__VA_ARGS__);		\
} while (0)


#define wr32(a, reg, value)	writel((value), ((a)->hw_addr + (reg)))
#define rd32(a, reg)		readl((a)->hw_addr + (reg))

#define wr64(a, reg, value)	writeq((value), ((a)->hw_addr + (reg)))
#define rd64(a, reg)		readq((a)->hw_addr + (reg))
#define iavf_flush(a)		readl((a)->hw_addr + IAVF_VFGEN_RSTAT)
/* memory allocation tracking */
struct iavf_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
};

#define iavf_allocate_dma_mem(h, m, unused, s, a) \
	iavf_allocate_dma_mem_d(h, m, unused, s, a)

#define iavf_free_dma_mem(h, m) iavf_free_dma_mem_d(h, m)

struct iavf_virt_mem {
	void *va;
	u32 size;
};

#define iavf_allocate_virt_mem(h, m, s) iavf_allocate_virt_mem_d(h, m, s)
#define iavf_free_virt_mem(h, m) iavf_free_virt_mem_d(h, m)

#define iavf_debug(h, m, s, ...)				\
do {								\
	if (((m) & (h)->debug_mask))				\
		pr_info("iavf %02x:%02x.%x " s,			\
			(h)->bus.bus_id, (h)->bus.device,	\
			(h)->bus.func, ##__VA_ARGS__);		\
} while (0)

/* SW spinlock */
struct iavf_spinlock {
	struct mutex spinlock;
};

static inline void iavf_no_action(struct iavf_spinlock *sp)
{
	/* nothing */
}

/* the locks are initialized in _probe and destroyed in _remove
 * so make sure NOT to implement init/destroy here, as to
 * avoid the iavf_init_adminq code trying to reinitialize
 * the persistent lock memory
 */
#define iavf_init_spinlock(_sp)    iavf_no_action(_sp)
#define iavf_acquire_spinlock(_sp) iavf_acquire_spinlock_d(_sp)
#define iavf_release_spinlock(_sp) iavf_release_spinlock_d(_sp)
#define iavf_destroy_spinlock(_sp) iavf_no_action(_sp)

#define IAVF_HTONL(a)		htonl(a)

#define iavf_memset(a, b, c, d)  memset((a), (b), (c))
#define iavf_memcpy(a, b, c, d)  memcpy((a), (b), (c))

#endif /* _IAVF_OSDEP_H_ */
