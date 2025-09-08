/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _KCOMPAT_GCC_H_
#define _KCOMPAT_GCC_H_

#ifndef GCC_VERSION
#define GCC_VERSION (__GNUC__ * 10000		\
		     + __GNUC_MINOR__ * 100	\
		     + __GNUC_PATCHLEVEL__)
#endif /* GCC_VERSION */

/* as GCC_VERSION yields 40201 for any modern clang (checked on clang 7 & 13)
 * we want other means to add workarounds for "old GCC" */
#ifdef __clang__
#define GCC_IS_BELOW(x) 0
#else
#define GCC_IS_BELOW(x) (GCC_VERSION < (x))
#endif

#ifdef __has_attribute
#if __has_attribute(__fallthrough__)
# define fallthrough __attribute__((__fallthrough__))
#else
# define fallthrough do {} while (0)  /* fallthrough */
#endif /* __has_attribute(fallthrough) */
#else
# define fallthrough do {} while (0)  /* fallthrough */
#endif /* __has_attribute */

/*
 * upstream commit 4eb6bd55cfb2 ("compiler.h: drop fallback overflow checkers")
 * removed bunch of code for builitin overflow fallback implementations, that
 * we need for gcc prior to 5.1
 */
#if !GCC_IS_BELOW(50100)
#ifndef COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW
#define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW	1
#endif
#endif /* GCC_VERSION >= 50100 */

#include "kcompat_overflow.h"

/* Backport macros for controlling GCC diagnostics */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0) )
/* Compilers before gcc-4.6 do not understand "#pragma GCC diagnostic push" */
#if GCC_VERSION >= 40600
#define __diag_str1(s)		#s
#define __diag_str(s)		__diag_str1(s)
#define __diag(s)		_Pragma(__diag_str(GCC diagnostic s))
#else
#define __diag(s)
#endif /* GCC_VERSION >= 4.6 */
#define __diag_push()	__diag(push)
#define __diag_pop()	__diag(pop)
#endif /* LINUX_VERSION < 4.18.0 */

#if GCC_IS_BELOW(50000)
/* Workaround for gcc bug - not accepting "(type)" before "{ ... }" as part of
 * static struct initializers [when used with -std=gnu11 switch]
 * https://bugzilla.redhat.com/show_bug.cgi?id=1672652
 *
 * fix was backported to gcc 4.8.5-39 by RedHat, contained in RHEL 7.7
 * workaround here is to just drop that redundant (commented out below) part and
 * redefine kernel macros used by us.
 */

/* Since problematic code could be triggered by print-family (incl. wrappers)
 * invocation, we have to first include headers that contain macros that we are
 * redefining, and only later proceed with the rest of includes.
 */
#include <linux/compiler.h>
#include <linux/dynamic_debug.h>
#include <linux/pci.h>
#include <linux/spinlock.h>

#ifdef __SPIN_LOCK_INITIALIZER
#undef __SPIN_LOCK_UNLOCKED
#define __SPIN_LOCK_UNLOCKED(lockname) \
	/* (spinlock_t) */ __SPIN_LOCK_INITIALIZER(lockname)
#endif /* __SPIN_LOCK_INITIALIZER */

#ifdef __RAW_SPIN_LOCK_INITIALIZER
#undef __RAW_SPIN_LOCK_UNLOCKED
#define __RAW_SPIN_LOCK_UNLOCKED(lockname) \
	/* (raw_spinlock_t) */ __RAW_SPIN_LOCK_INITIALIZER(lockname)
#endif /* __RAW_SPIN_LOCK_INITIALIZER */

#ifndef CONFIG_DEBUG_SPINLOCK
/* raw_spin_lock_init needs __RAW_SPIN_LOCK_UNLOCKED with typecast, so keep the
 * original impl,
 * but enhance it with typecast dropped from __RAW_SPIN_LOCK_UNLOCKED() */
#undef raw_spin_lock_init
#define raw_spin_lock_init(lock)					\
	do { *(lock) = (raw_spinlock_t) __RAW_SPIN_LOCK_UNLOCKED(lock);	\
	} while (0)
#endif /* !CONFIG_DEBUG_SPINLOCK */

#undef STATIC_KEY_INIT_TRUE
#define STATIC_KEY_INIT_TRUE					\
	{ .enabled = { 1 },					\
	  { .type = 1UL } }

#undef STATIC_KEY_INIT_FALSE
#define STATIC_KEY_INIT_FALSE	\
	{ .enabled = { 0 } }

#undef STATIC_KEY_TRUE_INIT
#define STATIC_KEY_TRUE_INIT \
	/* (struct static_key_true) */ { .key = STATIC_KEY_INIT_TRUE }

#undef STATIC_KEY_FALSE_INIT
#define STATIC_KEY_FALSE_INIT \
	/* (struct static_key_false) */ { .key = STATIC_KEY_INIT_FALSE }

#ifdef HAVE_JUMP_LABEL
/* dd_key_init() is used (indirectly) with arg like "(STATIC_KEY_INIT_FALSE)"
 * from DEFINE_DYNAMIC_DEBUG_METADATA(), which, depending on config has many
 * different definitions (including helper macros).
 * To reduce compat code, just consume parens from the arg instead copy-pasting
 * all definitions and slightly changing them. */
#define _KC_SLURP_PARENS(...) __VA_ARGS__
#undef dd_key_init
#define dd_key_init(key, init) key = _KC_SLURP_PARENS init
#endif /* HAVE_JUMP_LABEL */

#undef UUID_INIT
#define UUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)		\
	{{ ((a) >> 24) & 0xff, ((a) >> 16) & 0xff,			\
	   ((a) >> 8) & 0xff, (a) & 0xff,				\
	   ((b) >> 8) & 0xff, (b) & 0xff,				\
	   ((c) >> 8) & 0xff, (c) & 0xff,				\
	   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7)		\
	}}

#endif /* old GCC < 5.0 */

#endif /* _KCOMPAT_GCC_H_ */
