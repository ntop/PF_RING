/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#ifndef __LINUX_OVERFLOW_H
#define __LINUX_OVERFLOW_H

#include <linux/compiler.h>
#include <linux/limits.h>
#include <linux/const.h>

/*
 * prior to commit 54d50897d544 ("linux/kernel.h: split *_MAX and *_MIN macros into <linux/limits.h>")
 * SIZE_MAX was part of kernel.h, which we don't want to include so early on,
 *
 * on old RHELs size_t is also unknown at this point, so just include types.h
 */
#include <linux/types.h>
#ifndef SIZE_MAX
#define SIZE_MAX (~(size_t)0)
#endif

/*
 * In the fallback code below, we need to compute the minimum and
 * maximum values representable in a given type. These macros may also
 * be useful elsewhere, so we provide them outside the
 * COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW block.
 *
 * It would seem more obvious to do something like
 *
 * #define type_min(T) (T)(is_signed_type(T) ? (T)1 << (8*sizeof(T)-1) : 0)
 * #define type_max(T) (T)(is_signed_type(T) ? ((T)1 << (8*sizeof(T)-1)) - 1 : ~(T)0)
 *
 * Unfortunately, the middle expressions, strictly speaking, have
 * undefined behaviour, and at least some versions of gcc warn about
 * the type_max expression (but not if -fsanitize=undefined is in
 * effect; in that case, the warning is deferred to runtime...).
 *
 * The slightly excessive casting in type_min is to make sure the
 * macros also produce sensible values for the exotic type _Bool. [The
 * overflow checkers only almost work for _Bool, but that's
 * a-feature-not-a-bug, since people shouldn't be doing arithmetic on
 * _Bools. Besides, the gcc builtins don't allow _Bool* as third
 * argument.]
 *
 * Idea stolen from
 * https://mail-index.netbsd.org/tech-misc/2007/02/05/0000.html -
 * credit to Christian Biere.
 */
/* The is_signed_type macro is redefined in a few places in various kernel
 * headers. If this header is included at the same time as one of those, we
 * will generate compilation warnings. Since we can't fix every old kernel,
 * rename is_signed_type for this file to _kc_is_signed_type. This prevents
 * the macro name collision, and should be safe since our drivers do not
 * directly call the macro.
 */
#define _kc_is_signed_type(type)       (((type)(-1)) < (type)1)
#define __type_half_max(type) ((type)1 << (8*sizeof(type) - 1 - _kc_is_signed_type(type)))
#define type_max(T) ((T)((__type_half_max(T) - 1) + __type_half_max(T)))
#define type_min(T) ((T)((T)-type_max(T)-(T)1))

/*
 * Avoids triggering -Wtype-limits compilation warning,
 * while using unsigned data types to check a < 0.
 */
#define is_non_negative(a) ((a) > 0 || (a) == 0)
#define is_negative(a) (!(is_non_negative(a)))

#ifdef COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW
/* commit 9b80e4c4ddac ("overflow: Add __must_check attribute to check_*()
 * helpers") added __must_check_overflow
 *
 * Allows for effectively applying __must_check to a macro so we can have
 * both the type-agnostic benefits of the macros while also being able to
 * enforce that the return value is, in fact, checked.
 */
static inline bool __must_check __must_check_overflow(bool overflow)
{
	return unlikely(overflow);
}

/*
 * For simplicity and code hygiene, the fallback code below insists on
 * a, b and *d having the same type (similar to the min() and max()
 * macros), whereas gcc's type-generic overflow checkers accept
 * different types. Hence we don't just make check_add_overflow an
 * alias for __builtin_add_overflow, but add type checks similar to
 * below.
 */
#define check_add_overflow(a, b, d)		\
	__must_check_overflow(__builtin_add_overflow(a, b, d))

#define check_sub_overflow(a, b, d)		\
	__must_check_overflow(__builtin_sub_overflow(a, b, d))

#define check_mul_overflow(a, b, d)		\
	__must_check_overflow(__builtin_mul_overflow(a, b, d))

#else
#ifndef __CHECKER__

/* Checking for unsigned overflow is relatively easy without causing UB. */
#define __unsigned_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a + __b;			\
	*__d < __a;				\
})
#define __unsigned_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a - __b;			\
	__a < __b;				\
})
/*
 * If one of a or b is a compile-time constant, this avoids a division.
 */
#define __unsigned_mul_overflow(a, b, d) ({		\
	typeof(a) __a = (a);				\
	typeof(b) __b = (b);				\
	typeof(d) __d = (d);				\
	(void) (&__a == &__b);				\
	(void) (&__a == __d);				\
	*__d = __a * __b;				\
	__builtin_constant_p(__b) ?			\
	  __b > 0 && __a > type_max(typeof(__a)) / __b : \
	  __a > 0 && __b > type_max(typeof(__b)) / __a;	 \
})

/*
 * For signed types, detecting overflow is much harder, especially if
 * we want to avoid UB. But the interface of these macros is such that
 * we must provide a result in *d, and in fact we must produce the
 * result promised by gcc's builtins, which is simply the possibly
 * wrapped-around value. Fortunately, we can just formally do the
 * operations in the widest relevant unsigned type (u64) and then
 * truncate the result - gcc is smart enough to generate the same code
 * with and without the (u64) casts.
 */

/*
 * Adding two signed integers can overflow only if they have the same
 * sign, and overflow has happened iff the result has the opposite
 * sign.
 */
#define __signed_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (u64)__a + (u64)__b;		\
	(((~(__a ^ __b)) & (*__d ^ __a))	\
		& type_min(typeof(__a))) != 0;	\
})

/*
 * Subtraction is similar, except that overflow can now happen only
 * when the signs are opposite. In this case, overflow has happened if
 * the result has the opposite sign of a.
 */
#define __signed_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (u64)__a - (u64)__b;		\
	((((__a ^ __b)) & (*__d ^ __a))		\
		& type_min(typeof(__a))) != 0;	\
})

/*
 * Signed multiplication is rather hard. gcc always follows C99, so
 * division is truncated towards 0. This means that we can write the
 * overflow check like this:
 *
 * (a > 0 && (b > MAX/a || b < MIN/a)) ||
 * (a < -1 && (b > MIN/a || b < MAX/a) ||
 * (a == -1 && b == MIN)
 *
 * The redundant casts of -1 are to silence an annoying -Wtype-limits
 * (included in -Wextra) warning: When the type is u8 or u16, the
 * __b_c_e in check_mul_overflow obviously selects
 * __unsigned_mul_overflow, but unfortunately gcc still parses this
 * code and warns about the limited range of __b.
 */

#define __signed_mul_overflow(a, b, d) ({				\
	typeof(a) __a = (a);						\
	typeof(b) __b = (b);						\
	typeof(d) __d = (d);						\
	typeof(a) __tmax = type_max(typeof(a));				\
	typeof(a) __tmin = type_min(typeof(a));				\
	(void) (&__a == &__b);						\
	(void) (&__a == __d);						\
	*__d = (u64)__a * (u64)__b;					\
	(__b > 0   && (__a > __tmax/__b || __a < __tmin/__b)) ||	\
	(__b < (typeof(__b))-1  && (__a > __tmin/__b || __a < __tmax/__b)) || \
	(__b == (typeof(__b))-1 && __a == __tmin);			\
})


#define check_add_overflow(a, b, d)					\
	__builtin_choose_expr(_kc_is_signed_type(typeof(a)),		\
			__signed_add_overflow(a, b, d),			\
			__unsigned_add_overflow(a, b, d))

#define check_sub_overflow(a, b, d)					\
	__builtin_choose_expr(_kc_is_signed_type(typeof(a)),		\
			__signed_sub_overflow(a, b, d),			\
			__unsigned_sub_overflow(a, b, d))

#define check_mul_overflow(a, b, d)					\
	__builtin_choose_expr(_kc_is_signed_type(typeof(a)),		\
			__signed_mul_overflow(a, b, d),			\
			__unsigned_mul_overflow(a, b, d))

#endif /* __CHECKER__ */
#endif /* COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW */

/** check_shl_overflow() - Calculate a left-shifted value and check overflow
 *
 * @a: Value to be shifted
 * @s: How many bits left to shift
 * @d: Pointer to where to store the result
 *
 * Computes *@d = (@a << @s)
 *
 * Returns true if '*d' cannot hold the result or when 'a << s' doesn't
 * make sense. Example conditions:
 * - 'a << s' causes bits to be lost when stored in *d.
 * - 's' is garbage (e.g. negative) or so large that the result of
 *   'a << s' is guaranteed to be 0.
 * - 'a' is negative.
 * - 'a << s' sets the sign bit, if any, in '*d'.
 *
 * '*d' will hold the results of the attempted shift, but is not
 * considered "safe for use" if false is returned.
 */
#define check_shl_overflow(a, s, d) ({					\
	typeof(a) _a = a;						\
	typeof(s) _s = s;						\
	typeof(d) _d = d;						\
	u64 _a_full = _a;						\
	unsigned int _to_shift =					\
		_s >= 0 && _s < 8 * sizeof(*d) ? _s : 0;		\
	*_d = (_a_full << _to_shift);					\
	(_to_shift != _s || *_d < 0 || _a < 0 ||			\
		(*_d >> _to_shift) != _a);				\
})

#define __overflows_type_constexpr(x, T) (			\
	is_unsigned_type(typeof(x)) ?				\
		(x) > type_max(typeof(T)) :			\
	is_unsigned_type(typeof(T)) ?				\
		(x) < 0 || (x) > type_max(typeof(T)) :		\
	(x) < type_min(typeof(T)) || (x) > type_max(typeof(T)))

#define __overflows_type(x, T)		({	\
	typeof(T) v = 0;			\
	check_add_overflow((x), v, &v);		\
})

/**
 * overflows_type - helper for checking the overflows between value, variables,
 *		    or data type
 *
 * @n: source constant value or variable to be checked
 * @T: destination variable or data type proposed to store @x
 *
 * Compares the @x expression for whether or not it can safely fit in
 * the storage of the type in @T. @x and @T can have different types.
 * If @x is a constant expression, this will also resolve to a constant
 * expression.
 *
 * Returns: true if overflow can occur, false otherwise.
 */
#define overflows_type(n, T)					\
	__builtin_choose_expr(__is_constexpr(n),		\
			      __overflows_type_constexpr(n, T),	\
			      __overflows_type(n, T))

/**
 * castable_to_type - like __same_type(), but also allows for casted literals
 *
 * @n: variable or constant value
 * @T: variable or data type
 *
 * Unlike the __same_type() macro, this allows a constant value as the
 * first argument. If this value would not overflow into an assignment
 * of the second argument's type, it returns true. Otherwise, this falls
 * back to __same_type().
 */
#define castable_to_type(n, T)						\
	__builtin_choose_expr(__is_constexpr(n),			\
			      !__overflows_type_constexpr(n, T),	\
			      __same_type(n, T))

/**
 * size_mul() - Calculate size_t multiplication with saturation at SIZE_MAX
 * @factor1: first factor
 * @factor2: second factor
 *
 * Returns: calculate @factor1 * @factor2, both promoted to size_t,
 * with any overflow causing the return value to be SIZE_MAX. The
 * lvalue must be size_t to avoid implicit type conversion.
 */
static inline size_t __must_check size_mul(size_t factor1, size_t factor2)
{
	size_t bytes;

	if (check_mul_overflow(factor1, factor2, &bytes))
		return SIZE_MAX;

	return bytes;
}

/**
 * size_add() - Calculate size_t addition with saturation at SIZE_MAX
 * @addend1: first addend
 * @addend2: second addend
 *
 * Returns: calculate @addend1 + @addend2, both promoted to size_t,
 * with any overflow causing the return value to be SIZE_MAX. The
 * lvalue must be size_t to avoid implicit type conversion.
 */
static inline size_t __must_check size_add(size_t addend1, size_t addend2)
{
	size_t bytes;

	if (check_add_overflow(addend1, addend2, &bytes))
		return SIZE_MAX;

	return bytes;
}

/**
 * size_sub() - Calculate size_t subtraction with saturation at SIZE_MAX
 * @minuend: value to subtract from
 * @subtrahend: value to subtract from @minuend
 *
 * Returns: calculate @minuend - @subtrahend, both promoted to size_t,
 * with any overflow causing the return value to be SIZE_MAX. For
 * composition with the size_add() and size_mul() helpers, neither
 * argument may be SIZE_MAX (or the result with be forced to SIZE_MAX).
 * The lvalue must be size_t to avoid implicit type conversion.
 */
static inline size_t __must_check size_sub(size_t minuend, size_t subtrahend)
{
	size_t bytes;

	if (minuend == SIZE_MAX || subtrahend == SIZE_MAX ||
	    check_sub_overflow(minuend, subtrahend, &bytes))
		return SIZE_MAX;

	return bytes;
}

/**
 * array_size() - Calculate size of 2-dimensional array.
 *
 * @a: dimension one
 * @b: dimension two
 *
 * Calculates size of 2-dimensional array: @a * @b.
 *
 * Returns: number of bytes needed to represent the array or SIZE_MAX on
 * overflow.
 */
#define array_size(a, b)	size_mul(a, b)

/**
 * array3_size() - Calculate size of 3-dimensional array.
 *
 * @a: dimension one
 * @b: dimension two
 * @c: dimension three
 *
 * Calculates size of 3-dimensional array: @a * @b * @c.
 *
 * Returns: number of bytes needed to represent the array or SIZE_MAX on
 * overflow.
 */
#define array3_size(a, b, c)	size_mul(size_mul(a, b), c)

/**
 * flex_array_size() - Calculate size of a flexible array member
 *                     within an enclosing structure.
 * @p: Pointer to the structure.
 * @member: Name of the flexible array member.
 * @count: Number of elements in the array.
 *
 * Calculates size of a flexible array of @count number of @member
 * elements, at the end of structure @p.
 *
 * Return: number of bytes needed or SIZE_MAX on overflow.
 */
#define flex_array_size(p, member, count)				\
	__builtin_choose_expr(__is_constexpr(count),			\
		(count) * sizeof(*(p)->member) + __must_be_array((p)->member),	\
		size_mul(count, sizeof(*(p)->member) + __must_be_array((p)->member)))

/**
 * struct_size() - Calculate size of structure with trailing flexible array.
 * @p: Pointer to the structure.
 * @member: Name of the array member.
 * @count: Number of elements in the array.
 *
 * Calculates size of memory needed for structure of @p followed by an
 * array of @count number of @member elements.
 *
 * Return: number of bytes needed or SIZE_MAX on overflow.
 */
#define struct_size(p, member, count)					\
	__builtin_choose_expr(__is_constexpr(count),			\
		sizeof(*(p)) + flex_array_size(p, member, count),	\
		size_add(sizeof(*(p)), flex_array_size(p, member, count)))

/**
 * struct_size_t() - Calculate size of structure with trailing flexible array
 * @type: structure type name.
 * @member: Name of the array member.
 * @count: Number of elements in the array.
 *
 * Calculates size of memory needed for structure @type followed by an
 * array of @count number of @member elements. Prefer using struct_size()
 * when possible instead, to keep calculations associated with a specific
 * instance variable of type @type.
 *
 * Return: number of bytes needed or SIZE_MAX on overflow.
 */
#define struct_size_t(type, member, count)					\
	struct_size((type *)NULL, member, count)

/**
 * _DEFINE_FLEX() - helper macro for DEFINE_FLEX() family.
 * Enables caller macro to pass (different) initializer.
 *
 * @type: structure type name, including "struct" keyword.
 * @name: Name for a variable to define.
 * @member: Name of the array member.
 * @count: Number of elements in the array; must be compile-time const.
 * @initializer: initializer expression (could be empty for no init).
 */
#define _DEFINE_FLEX(type, name, member, count, initializer)			\
	_Static_assert(__builtin_constant_p(count),				\
		       "onstack flex array members require compile-time const count"); \
	union {									\
		u8 bytes[struct_size_t(type, member, count)];			\
		type obj;							\
	} name##_u initializer;							\
	type *name = (type *)&name##_u

/**
 * DEFINE_RAW_FLEX() - Define an on-stack instance of structure with a trailing
 * flexible array member, when it does not have a __counted_by annotation.
 *
 * @type: structure type name, including "struct" keyword.
 * @name: Name for a variable to define.
 * @member: Name of the array member.
 * @count: Number of elements in the array; must be compile-time const.
 *
 * Define a zeroed, on-stack, instance of @type structure with a trailing
 * flexible array member.
 * Use __struct_size(@name) to get compile-time size of it afterwards.
 */
#define DEFINE_RAW_FLEX(type, name, member, count)	\
	_DEFINE_FLEX(type, name, member, count, = {})

/**
 * DEFINE_FLEX() - Define an on-stack instance of structure with a trailing
 * flexible array member.
 *
 * @type: structure type name, including "struct" keyword.
 * @name: Name for a variable to define.
 * @member: Name of the array member.
 * @count: Number of elements in the array; must be compile-time const.
 *
 * Define a zeroed, on-stack, instance of @type structure with a trailing
 * flexible array member.
 * Use __struct_size(@name) to get compile-time size of it afterwards.
 */
#define DEFINE_FLEX(type, name, member, count)			\
	_DEFINE_FLEX(type, name, member, count, = {})

#endif /* __LINUX_OVERFLOW_H */
