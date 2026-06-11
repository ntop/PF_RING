/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2026 Intel Corporation */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KCOMPAT_CLEANUP_H_
#define _KCOMPAT_CLEANUP_H_

#include <linux/compiler.h>

#ifndef typeof_member
#define typeof_member(T, m)     typeof(((T*)0)->m)
#endif
#ifndef GCC_VERSION
#define GCC_VERSION (__GNUC__ * 10000		\
		     + __GNUC_MINOR__ * 100	\
		     + __GNUC_PATCHLEVEL__)
#endif /* GCC_VERSION */
#define GCC_IS_BELOW(x) (GCC_VERSION < (x))

#if defined __has_attribute
#if __has_attribute(cleanup)
#define HAVE_ATTRIBUTE_CLEANUP
#endif
#else
#if !GCC_IS_BELOW(30306)
#define HAVE_ATTRIBUTE_CLEANUP
#endif
#endif

#ifndef HAVE_ATTRIBUTE_CLEANUP
#error "This compiler is too old, cleanup extension (GCC 3.3.6) is required."
#endif

#if defined(__clang__)
/*
 * Clang prior to 17 is being silly and considers many __cleanup() variables
 * as unused (because they are, their sole purpose is to go out of scope).
 *
 * https://reviews.llvm.org/D152180
 */
#define __cleanup(func) __maybe_unused __attribute__((__cleanup__(func)))
#else /* __clang__ */
/*
 * gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#index-cleanup-variable-attribute
 * clang: https://clang.llvm.org/docs/AttributeReference.html#cleanup
 */
#define __cleanup(func)                 __attribute__((__cleanup__(func)))
#endif /* __clang__ */

/* We do the same style backport as usual with cleanup.h stuff, except it
 * has its own file. So, include the base if it exist:
 */
#ifndef NEED_DEFINE_FREE
#include <linux/cleanup.h>
#endif

#ifdef NEED_DEFINE_FREE
/* there is no cleanup.h stuff at all given by the kernel */
/* cond guards omitted */

#define DEFINE_FREE(_name, _type, _free) \
	static inline void __free_##_name(void *p) { _type _T = *(_type *)p; _free; }

#define __free(_name)	__cleanup(__free_##_name)

#define __get_and_null(p, nullvalue)   \
	({                                  \
		__auto_type __ptr = &(p);   \
		__auto_type __val = *__ptr; \
		*__ptr = nullvalue;         \
		__val;                      \
	})

static inline __must_check
const volatile void * __must_check_fn(const volatile void *val)
{ return val; }

#define no_free_ptr(p) \
	((typeof(p)) __must_check_fn((__force const volatile void *)__get_and_null(p, NULL)))

#define return_ptr(p)	return no_free_ptr(p)

#define DEFINE_CLASS(_name, _type, _exit, _init, _init_args...)		\
typedef _type class_##_name##_t;					\
static inline void class_##_name##_destructor(_type *p)			\
{ _type _T = *p; _exit; }						\
static inline _type class_##_name##_constructor(_init_args)		\
{ _type t = _init; return t; }

#define EXTEND_CLASS(_name, ext, _init, _init_args...)			\
typedef class_##_name##_t class_##_name##ext##_t;			\
static inline void class_##_name##ext##_destructor(class_##_name##_t *p)\
{ class_##_name##_destructor(p); }					\
static inline class_##_name##_t class_##_name##ext##_constructor(_init_args) \
{ class_##_name##_t t = _init; return t; }

#define CLASS(_name, var)						\
	class_##_name##_t var __cleanup(class_##_name##_destructor) =	\
		class_##_name##_constructor

#define guard(_name) \
	CLASS(_name, __UNIQUE_ID(guard))

#define __DEFINE_LOCK_GUARD_1(_name, _type, _lock)			\
static inline class_##_name##_t class_##_name##_constructor(_type *l)	\
{									\
	class_##_name##_t _t = { .lock = l }, *_T = &_t;		\
	_lock;								\
	return _t;							\
}

#define __DEFINE_LOCK_GUARD_0(_name, _lock)				\
static inline class_##_name##_t class_##_name##_constructor(void)	\
{									\
	class_##_name##_t _t = { .lock = (void*)1 },			\
			 *_T __maybe_unused = &_t;			\
	_lock;								\
	return _t;							\
}


#endif /* NEED_DEFINE_FREE */

#ifdef NEED___DEFINE_CLASS_IS_CONDITIONAL
/* If there is very early implementation present, lacking commit
 * fcc22ac5baf0 ("cleanup: Adjust scoped_guard() macros to avoid potential
 * warning"), we must #undef some macros and provide newer versions.
 *
 * If there were no cleanup.h at all, we could also do the same.
 */
#undef scoped_guard
#undef DEFINE_GUARD
#undef DEFINE_LOCK_GUARD_1
#undef DEFINE_LOCK_GUARD_0
#undef __DEFINE_UNLOCK_GUARD

#define __DEFINE_CLASS_IS_CONDITIONAL(_name, _is_cond)	\
static __maybe_unused const bool class_##_name##_is_conditional = _is_cond

#define DEFINE_GUARD(_name, _type, _lock, _unlock) \
	__DEFINE_CLASS_IS_CONDITIONAL(_name, false); \
	DEFINE_CLASS(_name, _type, if (_T) { _unlock; }, ({ _lock; _T; }), _type _T); \
	static inline void * class_##_name##_lock_ptr(class_##_name##_t *_T) \
	{ return (void *)(__force unsigned long)*_T; }

#define __guard_ptr(_name) class_##_name##_lock_ptr
#define __is_cond_ptr(_name) class_##_name##_is_conditional

#define __scoped_guard(_name, _label, args...)				\
	for (CLASS(_name, scope)(args);					\
	     __guard_ptr(_name)(&scope) || !__is_cond_ptr(_name);	\
	     ({ goto _label; }))					\
		if (0) {						\
_label:									\
			break;						\
		} else

#define __DEFINE_UNLOCK_GUARD(_name, _type, _unlock, ...)		\
typedef struct {							\
	_type *lock;							\
	__VA_ARGS__;							\
} class_##_name##_t;							\
									\
static inline void class_##_name##_destructor(class_##_name##_t *_T)	\
{									\
	if (_T->lock) { _unlock; }					\
}									\
									\
static inline void *class_##_name##_lock_ptr(class_##_name##_t *_T)	\
{									\
	return (void *)(__force unsigned long)_T->lock;			\
}

#define scoped_guard(_name, args...)	\
	__scoped_guard(_name, __UNIQUE_ID(label), args)

#define DEFINE_LOCK_GUARD_1(_name, _type, _lock, _unlock, ...)		\
__DEFINE_CLASS_IS_CONDITIONAL(_name, false);				\
__DEFINE_UNLOCK_GUARD(_name, _type, _unlock, __VA_ARGS__)		\
__DEFINE_LOCK_GUARD_1(_name, _type, _lock)

#define DEFINE_LOCK_GUARD_0(_name, _lock, _unlock, ...)			\
__DEFINE_CLASS_IS_CONDITIONAL(_name, false);				\
__DEFINE_UNLOCK_GUARD(_name, void, _unlock, __VA_ARGS__)		\
__DEFINE_LOCK_GUARD_0(_name, _lock)

#endif /* NEED___DEFINE_CLASS_IS_CONDITIONAL */

/* We put "DEFINE" macros invocations here (instead of kernel_impl.h), to
 * have easier time changing them (as changes are most often related).
 *
 * Content is synchronized to upstream commit 0ff41df1cb26 ("Linux 6.15").
 *
 * Please note that most "DEFINE" macros invocations are not covered here, only
 * those that we actually have used in the code. That means that even some of
 * the files we cover could have some invocations in upstream that we miss.
 *
 * Please also note that we could not just put newest version of, say, mutex.h
 * invocations here, as that would force use to replace whole file.
 */

#include <linux/mutex.h>
#ifdef NEED_DEFINE_GUARD_MUTEX
DEFINE_GUARD(mutex, struct mutex *, mutex_lock(_T), mutex_unlock(_T))
#endif

#include <linux/slab.h>
#ifdef NEED_DEFINE_FREE_KFREE
DEFINE_FREE(kfree, void *, if (!IS_ERR_OR_NULL(_T)) kfree(_T))
#endif
#ifdef NEED_DEFINE_FREE_KVFREE
void kvfree(const void *);
DEFINE_FREE(kvfree, void *, if (!IS_ERR_OR_NULL(_T)) kvfree(_T))
#endif

#include <linux/spinlock.h>
/* COND guards omitted */
#ifdef NEED_LOCK_GUARD_FOR_SPINLOCK
DEFINE_LOCK_GUARD_1(raw_spinlock, raw_spinlock_t,
		    raw_spin_lock(_T->lock),
		    raw_spin_unlock(_T->lock))

DEFINE_LOCK_GUARD_1(raw_spinlock_nested, raw_spinlock_t,
		    raw_spin_lock_nested(_T->lock, SINGLE_DEPTH_NESTING),
		    raw_spin_unlock(_T->lock))

DEFINE_LOCK_GUARD_1(raw_spinlock_irq, raw_spinlock_t,
		    raw_spin_lock_irq(_T->lock),
		    raw_spin_unlock_irq(_T->lock))

DEFINE_LOCK_GUARD_1(raw_spinlock_irqsave, raw_spinlock_t,
		    raw_spin_lock_irqsave(_T->lock, _T->flags),
		    raw_spin_unlock_irqrestore(_T->lock, _T->flags),
		    unsigned long flags)

DEFINE_LOCK_GUARD_1(spinlock, spinlock_t,
		    spin_lock(_T->lock),
		    spin_unlock(_T->lock))

DEFINE_LOCK_GUARD_1(spinlock_irq, spinlock_t,
		    spin_lock_irq(_T->lock),
		    spin_unlock_irq(_T->lock))

DEFINE_LOCK_GUARD_1(spinlock_irqsave, spinlock_t,
		    spin_lock_irqsave(_T->lock, _T->flags),
		    spin_unlock_irqrestore(_T->lock, _T->flags),
		    unsigned long flags)
#endif /* NEED_LOCK_GUARD_FOR_SPINLOCK */

#ifdef NEED_LOCK_GUARD_FOR_SPINLOCK_BH
DEFINE_LOCK_GUARD_1(raw_spinlock_bh, raw_spinlock_t,
		    raw_spin_lock_bh(_T->lock),
		    raw_spin_unlock_bh(_T->lock))
DEFINE_LOCK_GUARD_1(spinlock_bh, spinlock_t,
		    spin_lock_bh(_T->lock),
		    spin_unlock_bh(_T->lock))
#endif /* NEED_LOCK_GUARD_FOR_SPINLOCK_BH */

#include <linux/rcupdate.h>
#ifdef NEED_LOCK_GUARD_FOR_RCU
DEFINE_LOCK_GUARD_0(rcu,
	do {
		rcu_read_lock();
		/*
		 * sparse doesn't call the cleanup function,
		 * so just release immediately and don't track
		 * the context. We don't need to anyway, since
		 * the whole point of the guard is to not need
		 * the explicit unlock.
		 */
		__release(RCU);
	} while (0),
	rcu_read_unlock())
#endif

#ifdef NEED_DEFINE_GUARD_DEVLINK
struct devlink;
#ifdef NEED_DEVL_LOCK
static
#endif
 void devl_lock(struct devlink *);
#ifdef NEED_DEVL_LOCK
static
#endif
 void devl_unlock(struct devlink *);
DEFINE_GUARD(devl, struct devlink *, devl_lock(_T), devl_unlock(_T));
#endif

#endif /* _KCOMPAT_CLEANUP_H_ */
