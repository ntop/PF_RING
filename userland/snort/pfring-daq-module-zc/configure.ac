#												-*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT([pfring-zc-daq-module], [0.1], [deri@ntop.org])
AM_INIT_AUTOMAKE([daq], [0.1])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([daq_pfring_zc.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Enable visibility if we can
AC_ENABLE_VISIBILITY()
# Special compiler flags for ICC, etc.
AC_SF_COMPILER_SETUP()

# Checks for the DAQ API headers and the SFBPF headers/library.
AC_CHECK_DAQ_API
AC_CHECK_SFBPF

# Checks for PF_RING
AC_ARG_WITH( libpfring_includes,
	     [  --with-libpfring-includes=DIR      libpfring include directory],
	     [with_pfring_includes="$withval"], [with_pfring_includes="no"])

AC_ARG_WITH( pfring_kernel_includes,
	     [  --with-pfring-kernel-includes=DIR  pfring kernel include directory],
	     [with_pfring_kernel_includes="$withval"], [with_pfring_kernel_includes="no"])

AC_ARG_WITH( libpfring_libraries,
	     [  --with-libpfring-libraries=DIR     libpfring library directory],
	     [with_pfring_libraries="$withval"], [with_pfring_libraries="no"])

if test -d "${HOME}/PF_RING/"; then
	CPPFLAGS="${CPPFLAGS} -I ${HOME}/PF_RING/userland/lib -I ${HOME}/PF_RING/kernel"
	LDFLAGS="${LDFLAGS} -L${HOME}/PF_RING/userland/lib -lpthread -lnuma"
fi

if test "x$with_pfring_includes" != "xno"; then
	CPPFLAGS="${CPPFLAGS} -I${with_pfring_includes}"
fi

if test "x$with_pfring_kernel_includes" != "xno"; then
	CPPFLAGS="${CPPFLAGS} -I${with_pfring_kernel_includes}"
fi

if test "x$with_pfring_libraries" != "xno"; then
	LDFLAGS="${LDFLAGS} -L${with_pfring_libraries}"
fi

# PF_RING headers/library checks
AC_CHECK_HEADER([pfring.h],  [], [AC_MSG_ERROR([Could not find pfring.h! ])])

AC_CHECK_LIB( [pcap],
              [pfring_open],
	      [LDFLAGS="${LDFLAGS} -lpcap"],
	      [LDFLAGS="${LDFLAGS} -lpfring"],
	      [] )

OLD_LIBS="${LIBS}"
LIBS="${LIBS} -L/opt/napatech3/lib -lntapi"
AC_CHECK_LIB( [ntapi],
	[NT_Init],
	[],
	[LIBS="${OLD_LIBS}"],
	[] )

#LDFLAGS="${LDFLAGS} -L/opt/napatech3/lib -lntapi"],

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
#AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strchr strdup strerror strtol])

# Substitutions

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
