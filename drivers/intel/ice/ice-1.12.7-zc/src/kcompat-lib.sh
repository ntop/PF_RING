#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2018-2023 Intel Corporation

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

# yield first line of $1 typedef definition (simple typedefs only)
# this probably won't handle typedef struct { \n int foo;\n};
function find-typedef-decl() {
	test $# -ge 2
	local what end
	what="/^typedef .* $1"';$/'
	end=1
	shift
	find-decl "$what" "$end" "$@"
}

# gen() - DSL-like function to wrap around all the other
#
# syntax:
#   gen DEFINE if (KIND [METHOD of]) NAME [(matches|lacks) PATTERN|absent] in <list-of-files>

# where:
#   DEFINE is HAVE_ or NEED_ #define to print;
#   `if` is there to just read it easier and made syntax easier to check;
#
#   NAME is the name for what we are looking for;
#
#   KIND specifies what kind of declaration/definition we are looking for,
#      could be: fun, enum, struct, method, macro, typedef,
#      'implementation of macro'
#   for KIND=method, we are looking for function ptr named METHOD in struct
#     named NAME (two optional args are then necessary (METHOD & of));
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
# PATTERN is awk pattern, will be wrapped by two slashes (/)
function gen() {
	test $# -ge 6 || die 20 "too few arguments, $# given, at least 6 needed"
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
	fun|enum|struct|macro|typedef)
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
		first_decl="$(find-struct-decl "$name" "$@")" || exit 28
		# prepare params for next lookup phase
		set -- - # overwrite $@ to be single dash (-)
		name="$method_name"
		kind=fun
	elif [[ $# = 1 && "$1" = '-' ]]; then
		# avoid losing stdin provided to gen() due to redirection (<<<)
		first_decl="$(cat -)"
	fi

	# lookup the NAME
	local body
	body="$(find-$kind-decl "$name" "$@" <<< "$first_decl")" || exit 29
	awk -v define="$define" -v pattern="$pattern" -v "$operator"=1 '
		/./ { not_empty = 1 }
		$0 ~ pattern { found = 1 }
		END {
			if (lacks && !found && not_empty || matches && found || absent && !found)
				print "#define", define
		}
	' <<< "$body"
}
