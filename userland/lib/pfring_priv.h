/*
 *
 * (C) 2005-23 - ntop
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef _PFRING_PRIV_H_
#define _PFRING_PRIV_H_

/* ********************************* */

#ifndef likely
#define likely(x)       __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect((x),0)
#endif

/* ********************************* */

#ifndef min
#define min(a, b) (a <= b ? a : b)
#endif

/* ********************************* */

#ifndef gcc_mb
#define gcc_mb() __asm__ __volatile__("": : :"memory")
#endif

#ifndef smp_rmb
#if defined(__i386__) || defined(__x86_64__)
#define smp_rmb()   asm volatile("lfence":::"memory")
#else /* other architectures (e.g. ARM) */
#define smp_rmb() gcc_mb()
#endif
#endif

#ifndef smp_wmb
#if defined(__i386__) || defined(__x86_64__)
#define smp_wmb()   asm volatile("sfence" ::: "memory")
#else /* other architectures (e.g. ARM) */
#define smp_wmb() gcc_mb()
#endif
#endif

/* ********************************* */

/* See also __builtin_prefetch
 * http://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
 * [x86] https://elixir.bootlin.com/dpdk/v24.07/source/lib/eal/x86/include/rte_prefetch.h
 * [ARM] https://elixir.bootlin.com/dpdk/v24.07/source/lib/eal/arm/include/rte_prefetch_64.h
*/
#if defined(__i386__) || defined(__x86_64__)
#define prefetch(x) __asm volatile("prefetcht0 %0" :: "m" (*(const unsigned long *)x));
#elif defined(__aarch64__)
#define prefetch(x) __asm volatile("PRFM PLDL1KEEP, [%0]" : : "r" (*(const unsigned long *)x));
#else
#define prefetch(x) ();
#warning "Unable to define prefetch for your architecture"
#endif

/* ********************************* */

#endif /* _PFRING_PRIV_H_ */
