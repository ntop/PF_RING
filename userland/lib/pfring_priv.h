/*
 *
 * (C) 2005-2020 - ntop.org
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

#ifndef smp_wmb
#define smp_wmb() gcc_mb()
#endif

#ifndef smp_rmb
#define smp_rmb() gcc_mb()
#endif

/* ********************************* */

/* See also __builtin_prefetch
 * http://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html */
#define prefetch(x) __asm volatile("prefetcht0 %0" :: "m" (*(const unsigned long *)x));

/* ********************************* */

#endif /* _PFRING_PRIV_H_ */
