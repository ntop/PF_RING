/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _KCOMPAT_SIGIL_H_
#define _KCOMPAT_SIGIL_H_

#define _STUB_0(code_if_true, code_if_false) code_if_false
#define _STUB_1(code_if_true, code_if_false) code_if_true
#define _PASTE(x, y) x ## y
#define PASTE(x, y) _PASTE(x, y)
#define _STUB_CODE(flag) PASTE(_STUB_, IS_ENABLED(flag))

#define DECLARE_OR_STUB(flag, stub_ret, ...)	\
	_STUB_CODE(flag)(,static inline) __VA_ARGS__	\
	_STUB_CODE(flag)(;, { return stub_ret; })

/*
 * DEPAREN ... VANISH taken from SO https://stackoverflow.com/a/62984543
 * It is used to allow wraping $() params in (), so they could contain a comma.
 */
#define DEPAREN(X) ESC(ISH X)
#define ISH(...) ISH __VA_ARGS__
#define ESC(...) ESC_(__VA_ARGS__)
#define ESC_(...) VAN ## __VA_ARGS__
#define VANISH

#define KC_COMMA ,

#ifndef __CHECKER__

/* isn't it cool to write $(FLAG, some code, optional alternative code)  ? :) */
#define $(flag, code_if_true, ...)	\
	_STUB_CODE(flag)(DEPAREN(code_if_true), DEPAREN(__VA_ARGS__))

#define $__(X) X KC_COMMA
#define __$(X) KC_COMMA X

//~ $_(HAVE_NDO_FDB_ADD_VID, u16 vid)
//~ 		->
//~ $(HAVE_NDO_FDB_ADD_VID, (u16 vid, ))
#define $_(flag, param_if_true)	\
	$(flag, ($__(param_if_true)))

//~ _$(HAVE_FOO, u16 val)
//~ 		->
//~ $(HAVE_FOO, (, u16 val))
#define _$(flag, param_if_true)	\
	$(flag, (__$(param_if_true)))

#else /* __CHECKER__ */
/* $ replaced by KC_LOOKUP, for sparse */
#define KC_LOOKUP(flag, code_if_true, ...)	\
	_STUB_CODE(flag)(DEPAREN(code_if_true), DEPAREN(__VA_ARGS__))
#define KC_LOOKUP__(X) X KC_COMMA
#define __KC_LOOKUP(X) KC_COMMA X
#define KC_LOOKUP_(flag, param_if_true)	\
	KC_LOOKUP(flag, (KC_LOOKUP__(param_if_true)))
#define _KC_LOOKUP(flag, param_if_true)	\
	KC_LOOKUP(flag, (__KC_LOOKUP(param_if_true)))
#endif /* __CHECKER__ */

#endif /* _KCOMPAT_SIGIL_H_ */
