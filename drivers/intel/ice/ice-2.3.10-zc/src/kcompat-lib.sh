#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2018-2025 Intel Corporation

# to be sourced

# General shell helpers

# exit with non-zero exit code; if there is only one param:
# exit with msg $1 and exit code from last command (or 99 if = 0)
# otherwise, exit with $1 and use remaining arguments as msg
function die() {
	rc=$?
	if [ $# -gt 1 ]; then
		rc="$1"
		shift
	fi
	[ "$rc" -ne 0 ] || rc=99
	echo >&2 "$@"
	exit $rc
}

# filter out paths that are not files
# input $@, output via echo;
# note: pass `-` for stdin
# note: outputs nothing if all input files are "bad" (eg. not existing), but it
#	is left for caller to decide if this is an erorr condition;
# note: whitespaces are considered "bad" as part of filename, it's an error.
function filter-out-bad-files() {
	if [[ $# = 1 && "$1" = '-' ]]; then
		echo -
		return 0
	fi
	if [ $# = 0 ]; then
		die 10 "no files passed, use '-' when reading from pipe (|)"
	fi
	local any=0 diagmsgs=/dev/stderr re=$'[\t \n]'
	[ -n "${QUIET_COMPAT-}" ] && diagmsgs=/dev/null
	for x in "$@"; do
		if [ -e "$x" ]; then
			if [[ "$x" =~ $re ]]; then
				die 11 "err: filename contains whitespaces: $x."
			fi
			echo "$x"
			any=1
		else
			echo >&"$diagmsgs" filtering "$x" out
		fi
	done
	if [ $any = 0 ]; then
		echo >&"$diagmsgs" 'all files (for given query) filtered out'
	fi
}

# Basics of regexp explained, as a reference for mostly-C programmers:
# (bash) "regexp-$VAR-regexp"  - bash' VARs are placed into "QUOTED" strings
# /\);?$/       - match end of function declaration, $ is end of string
# ^[ \t]*       - (heuristic), anything but comment, eg to exclude function docs
# /STH/, /END/  - (awk), print all lines sice STH matched, up to END, inclusive

# "Whitespace only"
WB='[ \t\n]'

# Helpers below print the thing that is looked for, for further grep'ping/etc.
# That simplifies process of excluding comments or spares us state machine impl.
#
# We take advantage of current/common linux codebase formatting here.
#
# Functions in this section require input file/s passed as args
# (usually one, but more could be supplied in case of renames in kernel),
# '-' could be used as an (only) file argument to read from stdin/pipe.

# wrapper over find-something-decl() functions below, to avoid repetition
# pass $what as $1, $end as $2, and $files to look in as rest of args
function find-decl() {
	test $# -ge 3 # ensure that there are at least 3 params
	local what end files
	what="$1"
	end="$2"
	shift 2
	files="$(filter-out-bad-files "$@")" || die
	if [ -z "$files" ]; then
		return 0
	fi
	# shellcheck disable=SC2086
	awk "
		/^$WB*\*/ {next}
		$what, $end
	" $files
}

# yield $1 function declaration (signature), don't pass return type in $1
# looks only in files specified ($2, $3...)
function find-fun-decl() {
	test $# -ge 2
	local what end
	what="/$WB*([(]\*)?$1$WB*($|[()])/"
	end='/\);?$/'
	shift
	find-decl "$what" "$end" "$@"
}

# yield $1 enum declaration (type/body)
function find-enum-decl() {
	test $# -ge 2
	local what end
	what="/^$WB*enum$WB+$1"' \{$/'
	end='/\};$/'
	shift
	find-decl "$what" "$end" "$@"
}

# yield $1 struct declaration (type/body)
function find-struct-decl() {
	test $# -ge 2
	local what end
	what="/^$WB*struct$WB+$1"' \{$/'
	end='/^\};$/' # that's (^) different from enum-decl
	shift
	find-decl "$what" "$end" "$@"
}

# yield first line of $1 macro definition
function find-macro-decl() {
	test $# -ge 2
	local what end
	# only unindented defines, only whole-word match
	what="/^#define$WB+$1"'([ \t\(]|$)/'
	end=1 # only first line; use find-macro-implementation-decl for full body
	shift
	find-decl "$what" "$end" "$@"
}

# yield full macro implementation
function find-macro-implementation-decl() {
	test $# -ge 2
	local what end
	# only unindented defines, only whole-word match
	what="/^#define$WB+$1"'([ \t\(]|$)/'
	# full implementation, until a line not ending in a backslash.
	# Does not handle macros with comments embedded within the definition.
	end='/[^\\]$/'
	shift
	find-decl "$what" "$end" "$@"
}

# yield first line of $1 typedef definition
# This only handles typedefs where the name is on first line
function find-typedef-decl() {
	test $# -ge 2
	local what end
	# Assumes type name is followed by other ')', '(', or ';', or
	# whitespace
	what="/^typedef$WB.*$1"'[\(\); \t\n]/'
	end='/;$/'
	shift
	find-decl "$what" "$end" "$@"
}

# yield symbol line from Module.symvers
function find-symbol-decl() {
	test $# -ge 2
	local what end
	what="/^0x[0-9a-f]+\t$1\t/"
	end=1 # only one line
	shift
	find-decl "$what" "$end" "$@"
}

# gen() - DSL-like function to wrap around all the other
#
# syntax:
#   gen DEFINE if (KIND [METHOD of]) NAME [(matches|lacks) PATTERN|absent] in <list-of-files>
#   gen DEFINE if string "actual" equals "expected"

# where:
#   DEFINE is HAVE_ or NEED_ #define to print;
#   `if` is there to just read it easier and made syntax easier to check;
#
#   NAME is the name for what we are looking for;
#
#   `if string` can be used to check if a provided string matches an expected
#       value. The define will only be generated if the strings are exactly
#       equal. Otherwise, the define will not be generated. When operating in
#       UNIFDEF_MODE, -DDEFINE is output when the strings are equal, while
#       -UDEFINE is output when the strings are not equal. This is intended
#       for cases where a more complex conditional is required, such as
#       generating a define when multiple different functions exist.
#
#       Ex:
#
#         FUNC1="$(find-fun-decl devlink_foo1 devlink.h)"
#         FUNC2="$(find-fun-decl devlink_foo2 devlink.h)"
#         gen HAVE_FOO_12 if string "${FUNC1:+1}${FUNC2:+1}" equals "11"
#
#   KIND specifies what kind of declaration/definition we are looking for,
#      could be: fun, enum, struct, method, macro, typedef, symbol
#      or 'implementation of macro'
#   for KIND=method, we are looking for function ptr named METHOD in struct
#     named NAME (two optional args are then necessary (METHOD & of));
#
#   for KIND=symbol, we are looking for a symbol definition in the format of
#     Module.symvers. To verify that the symbol is exported by a particular
#     module, the matches syntax can be used.
#
#   for KIND='implementation of macro' we are looking for the full
#     implementation of the macro, not just its first line. This is usually
#     combined with "matches" or "lacks".
#
#   next [optional] args could be used:
#     matches PATTERN - use to grep for the PATTERN within definition
#       (eg, for ext_ack param)
#     lacks - use to add #define only if there is no match of the PATTERN,
#       *but* the NAME is *found*
#     absent - the NAME that we grep for must be not found
#       (ie: function not exisiting)
#
#     without this optional params, behavior is the same as with
#       `matches .` - use to grep just for existence of NAME;
#
#   `in` is there to ease syntax, similar to `if` before.
#
#  <list-of-files> is just space-separate list of files to look in,
#    single (-) for stdin.
#
# PATTERN is an awk pattern, will be wrapped by two slashes (/)
#
# The usual output is a list of "#define <flag>" lines for each flag that has
# a matched definition. When UNIFDEF_MODE is set to a non-zero string, the
# output is instead a sequence of "-D<flag>" for each matched definition, and
# "-U<flag>" for each definition which didn't match.
function gen() {
	test $# -ge 4 || die 20 "too few arguments, $# given, at least 4 needed"
	local define if_kw kind name in_kw # mandatory
	local of_kw method_name operator pattern # optional
	local src_line="${BASH_SOURCE[0]}:${BASH_LINENO[0]}"
	define="$1"
	if_kw="$2"
	kind="$3"
	local orig_args_cnt=$#
	shift 3
	[ "$if_kw" != if ] && die 21 "$src_line: 'if' keyword expected, '$if_kw' given"
	case "$kind" in
	string)
		local actual_str expect_str equals_kw missing_fmt found_fmt

		test $# -ge 3 || die 22 "$src_line: too few arguments, $orig_args_cnt given, at least 6 needed"

		actual_str="$1"
		equals_kw="$2"
		expect_str="$3"
		shift 3

		if [ -z ${UNIFDEF_MODE:+1} ]; then
			found_fmt="#define %s 1\n"
			missing_fmt=""
		else
			found_fmt="-D%s\n"
			missing_fmt="-U%s\n"
		fi

		if [ "${actual_str}" = "${expect_str}" ]; then
			printf -- "$found_fmt" "$define"
		else
			printf -- "$missing_fmt" "$define"
		fi

		return
	;;
	fun|enum|struct|macro|typedef|symbol)
		test $# -ge 3 || die 22 "$src_line: too few arguments, $orig_args_cnt given, at least 6 needed"
		name="$1"
		shift
	;;
	method)
		test $# -ge 5 || die 22 "$src_line: too few arguments, $orig_args_cnt given, at least 8 needed"
		method_name="$1"
		of_kw="$2"
		name="$3"
		shift 3
		[ "$of_kw" != of ] && die 23 "$src_line: 'of' keyword expected, '$of_kw' given"
	;;
	implementation)
		test $# -ge 5 || die 28 "$src_line: too few arguments, $orig_args_cnt given, at least 8 needed"
		of_kw="$1"
		kind="$2"
		name="$3"
		shift 3
		[ "$of_kw" != of ] && die 29 "$src_line: 'of' keyword expected, '$of_kw' given"
		[ "$kind" != macro ] && die 30 "$src_line: implementation only supports 'macro', '$kind' given"
		kind=macro-implementation
	;;
	*) die 24 "$src_line: unknown KIND ($kind) to look for" ;;
	esac
	operator="$1"
	case "$operator" in
	absent)
		pattern='.'
		in_kw="$2"
		shift 2
	;;
	matches|lacks)
		pattern="$2"
		in_kw="$3"
		shift 3
	;;
	in)
		operator=matches
		pattern='.'
		in_kw=in
		shift
	;;
	*) die 25 "$src_line: unknown OPERATOR ($operator) to look for" ;;
	esac
	[ "$in_kw" != in ] && die 26 "$src_line: 'in' keyword expected, '$in_kw' given"
	test $# -ge 1 || die 27 "$src_line: too few arguments, at least one filename expected"

	local first_decl=
	if [ "$kind" = method ]; then
		first_decl="$(find-struct-decl "$name" "$@")" || exit 40
		# prepare params for next lookup phase
		set -- - # overwrite $@ to be single dash (-)
		name="$method_name"
		kind=fun
	elif [[ $# = 1 && "$1" = '-' ]]; then
		# avoid losing stdin provided to gen() due to redirection (<<<)
		first_decl="$(cat -)"
	fi

	local unifdef
	unifdef=${UNIFDEF_MODE:+1}

	# lookup the NAME
	local body
	body="$(find-$kind-decl "$name" "$@" <<< "$first_decl")" || exit 41
	awk -v define="$define" -v pattern="$pattern" -v "$operator"=1 -v unifdef="$unifdef" '
		BEGIN {
			# prepend "identifier boundary" to pattern, also append
			# it, but only for patterns not ending with such already
			#
			# eg: "foo" -> "\bfoo\b"
			#     "struct foo *" -> "\bstruct foo *"

			# Note that mawk does not support "\b", so we have our
			# own approximation, NI
			NI = "[^A-Za-z0-9_]" # "Not an Indentifier"

			if (!match(pattern, NI "$"))
				pattern = pattern "(" NI "|$)"
			pattern = "(^|" NI ")" pattern
		}
		/./ { not_empty = 1 }
		$0 ~ pattern { found = 1 }
		END {
			if (unifdef) {
				found_fmt="-D%s\n"
				missing_fmt="-U%s\n"
			} else {
				found_fmt="#define %s 1\n"
				missing_fmt=""
			}

			if (lacks && !found && not_empty || matches && found || absent && !found)
				printf(found_fmt, define)
			else if (missing_fmt)
				printf(missing_fmt, define)
		}
	' <<< "$body"
}

# check() - Like gen, but return true/false instead of generating output
#
# syntax:
#   See gen(), except do not pass a DEFINE name, or the action keyword.
function check() {
	# Always run check in unifdef mode
	local UNIFDEF_MODE=1

	[[ "$(gen CHECK if "$@")" = "-DCHECK" ]]
}

# tell if given flag is enabled in .config
# return 0 if given flag is enabled, 1 otherwise
# inputs:
# $1 - flag to check (whole word, without _MODULE suffix)
# env flag $CONFIG_FILE
#
# there are two "config" formats supported, to ease up integrators lifes
# .config (without leading #~ prefix):
#~ # CONFIG_ACPI_EC_DEBUGFS is not set
#~ CONFIG_ACPI_AC=y
#~ CONFIG_ACPI_VIDEO=m
# and autoconf.h, which would be:
#~ #define CONFIG_ACPI_AC 1
#~ #define CONFIG_ACPI_VIDEO_MODULE 1
function config_has() {
	grep -qE "^(#define )?$1((_MODULE)? 1|=m|=y)$" "$CONFIG_FILE"
}

# try to locate a suitable config file from KOBJ
#
# On success, the CONFIG_FILE variable will be updated to reflect the full
# path to a configuration file.
#
# Depends on KSRC being set
function find_config_file() {
	local -a CSP
	local file
	local diagmsgs=/dev/stderr

	[ -n "${QUIET_COMPAT-}" ] && diagmsgs=/dev/null

	if ! [ -d "${KSRC-}" ]; then
		return
	fi

	CSP=(
		"$KOBJ/include/generated/autoconf.h"
		"$KOBJ/include/linux/autoconf.h"
		"$KOBJ/.config")

	for file in "${CSP[@]}"; do
		if [ -f $file ]; then
			echo >&"$diagmsgs" "using CONFIG_FILE=$file"
			CONFIG_FILE=$file
			return
		fi
	done
}
