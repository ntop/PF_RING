###########################################################################
#
# Intel Ethernet Controller XL710 Family Linux Driver
# Copyright(c) 2013 - 2015 Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# The full GNU General Public License is included in this distribution in
# the file called "COPYING".
#
# Contact Information:
# e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
# Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
###########################################################################
# Environment tests

ifeq (,$(BUILD_KERNEL))
BUILD_KERNEL=$(shell uname -r)
endif

ifeq (,$(wildcard build.mk))
	DRIVERS :=  $(shell ls -ld i40e* | awk '/^d/ { print $$9 }')
else
	DRIVERS :=  $(shell ls -ld i40e i40evf | awk '/^d/ { print $$9 }')
endif
DIRS :=  $(patsubst %,%/,$(DRIVERS))
SOURCES := $(shell find $(DRIVERS) -name "*.[ch]" | grep -v "\.mod\.c")
MODULES := $(patsubst %,%.ko,$(DRIVERS))
TARGETS := $(join $(DIRS), $(MODULES))
MANFILES := $(patsubst %,%.7,$(DRIVERS))
MANFILES := $(patsubst %,../%,$(MANFILES))
###########################################################################
# Environment tests

# Kernel Search Path
# All the places we look for kernel source
KSP :=  /lib/modules/$(BUILD_KERNEL)/build \
        /lib/modules/$(BUILD_KERNEL)/source \
        /usr/src/linux-$(BUILD_KERNEL) \
        /usr/src/linux-$($(BUILD_KERNEL) | sed 's/-.*//') \
        /usr/src/kernel-headers-$(BUILD_KERNEL) \
        /usr/src/kernel-source-$(BUILD_KERNEL) \
        /usr/src/linux-$($(BUILD_KERNEL) | sed 's/\([0-9]*\.[0-9]*\)\..*/\1/') \
        /usr/src/linux

# prune the list down to only values that exist
# and have an include/config sub-directory
# as of last check, everything beyond 2.6.32 should have include/config
# even in the SLES12 /lib/modules/`uname -r`/build
test_dir = $(shell [ -e $(dir)/include/config ] && echo $(dir))
KSP := $(foreach dir, $(KSP), $(test_dir))

# we will use this first valid entry in the search path
ifeq (,$(KSRC))
  KSRC := $(firstword $(KSP))
endif

ifeq (,$(KSRC))
  $(warning *** Kernel header files not in any of the expected locations.)
  $(warning *** Install the appropriate kernel development package, e.g.)
  $(error kernel-devel, for building kernel modules and try again)
else
ifeq (/lib/modules/$(BUILD_KERNEL)/source, $(KSRC))
  KOBJ :=  /lib/modules/$(BUILD_KERNEL)/build
else
  KOBJ :=  $(KSRC)
endif
endif

# Version file Search Path
VSP :=  $(KOBJ)/include/generated/utsrelease.h \
        $(KOBJ)/include/linux/utsrelease.h \
        $(KOBJ)/include/linux/version.h \
        $(KOBJ)/include/generated/uapi/linux/version.h \
        /boot/vmlinuz.version.h

# Config file Search Path
CSP :=  $(KOBJ)/include/generated/autoconf.h \
        $(KOBJ)/include/linux/autoconf.h \
        /boot/vmlinuz.autoconf.h

# prune the lists down to only files that exist
test_file = $(shell [ -f $(file) ] && echo $(file))
VSP := $(foreach file, $(VSP), $(test_file))
CSP := $(foreach file, $(CSP), $(test_file))

# and use the first valid entry in the Search Paths
ifeq (,$(VERSION_FILE))
  VERSION_FILE := $(firstword $(VSP))
endif
ifeq (,$(CONFIG_FILE))
  CONFIG_FILE := $(firstword $(CSP))
endif

ifeq (,$(wildcard $(VERSION_FILE)))
  $(error Linux kernel source not configured - missing version header file)
endif

ifeq (,$(wildcard $(CONFIG_FILE)))
  $(error Linux kernel source not configured - missing autoconf.h)
endif

# Some helper functions for converting kernel version to version codes
get_kver = $(or $(word ${2},$(subst ., ,${1})),0)
get_kvercode = $(shell [ "${1}" -ge 0 -a "${1}" -le 255 2>/dev/null ] && \
                       [ "${2}" -ge 0 -a "${2}" -le 255 2>/dev/null ] && \
                       [ "${3}" -ge 0 -a "${3}" -le 255 2>/dev/null ] && \
                       printf %d $$(( ( ${1} << 16 ) + ( ${2} << 8 ) + ( ${3} ) )) )

# Convert LINUX_VERSION into LINUX_VERSION_CODE
ifneq (${LINUX_VERSION},)
  LINUX_VERSION_CODE=$(call get_kvercode,$(call get_kver,${LINUX_VERSION},1),$(call get_kver,${LINUX_VERSION},2),$(call get_kver,${LINUX_VERSION},3))
endif

# Honor LINUX_VERSION_CODE
ifneq (${LINUX_VERSION_CODE},)
  $(info Setting LINUX_VERSION_CODE to ${LINUX_VERSION_CODE}$(if ${LINUX_VERSION}, from LINUX_VERSION=${LINUX_VERSION}))
  KVER_CODE := ${LINUX_VERSION_CODE}
  EXTRA_CFLAGS += -DLINUX_VERSION_CODE=${LINUX_VERSION_CODE}
endif

EXTRA_CFLAGS += $(CFLAGS_EXTRA)

# get the kernel version - we use this to find the correct install path
KVER := $(shell $(CC) $(EXTRA_CFLAGS) -E -dM $(VERSION_FILE) | grep UTS_RELEASE | \
        awk '{ print $$3 }' | sed 's/\"//g')

# assume source symlink is the same as build, otherwise adjust KOBJ
ifneq (,$(wildcard /lib/modules/$(KVER)/build))
ifneq ($(KSRC),$(shell readlink /lib/modules/$(KVER)/build))
  KOBJ=/lib/modules/$(KVER)/build
endif
endif

ifeq (${KVER_CODE},)
  KVER_CODE := $(shell $(CC) $(EXTRA_CFLAGS) -E -dM $(VSP) 2> /dev/null |\
                 grep -m 1 LINUX_VERSION_CODE | awk '{ print $$3 }' | sed 's/\"//g')
endif

# set the install path before and after 3.2.0, and handle
# distros like SLES 11 that backported the directories
ifeq (1,$(shell [ -d /lib/modules/$(KVER)/kernel/drivers/net/ethernet/intel ] && echo 1 || echo 0))
INSTDIR := /lib/modules/$(KVER)/kernel/drivers/net/ethernet/intel
else
INSTDIR := /lib/modules/$(KVER)/kernel/drivers/net
endif

# abort the build on kernels older than 2.6.32
ifneq (1,$(shell [ $(KVER_CODE) -ge 132640 ] && echo 1 || echo 0))
  $(error *** Aborting the build. \
          *** This driver is not supported on kernel versions older than 2.6.32)
endif

MANSECTION = 7

ifeq (,$(MANDIR))
  # find the best place to install the man page
  MANPATH := $(shell (manpath 2>/dev/null || echo $MANPATH) | sed 's/:/ /g')
  ifneq (,$(MANPATH))
    # test based on inclusion in MANPATH
    test_dir = $(findstring $(dir), $(MANPATH))
  else
    # no MANPATH, test based on directory existence
    test_dir = $(shell [ -e $(dir) ] && echo $(dir))
  endif
  # our preferred install path
  # should /usr/local/man be in here ?
  MANDIR := /usr/share/man /usr/man
  MANDIR := $(foreach dir, $(MANDIR), $(test_dir))
  MANDIR := $(firstword $(MANDIR))
endif
ifeq (,$(MANDIR))
  # fallback to /usr/man
  MANDIR := /usr/man
endif

# PF_RING
DEBUG_CFLAGS += -g -DDEBUG
CFLAGS_EXTRA += -D HAVE_PF_RING ${DEBUG_CFLAGS}

# kernel build function
# $1 is the relative path of the subdir to build in
# $2 is the kernel build target
kernelbuild = $(shell (\
		if [ -n "$(KOBJ)" ]; then \
			$(MAKE) ccflags-y:="$(CFLAGS_EXTRA)" -C $(KSRC) CONFIG_I40E=m CONFIG_I40EVF=m SUBDIRS=$(realpath $(1)) INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) $(2) ; \
		else \
			$(MAKE) ccflags-y:="$(CFLAGS_EXTRA)" -C $(KSRC) -O $(KOBJ) CONFIG_I40E=m CONFIG_I40EVF=m SUBDIRS=$(realpath $(1)) INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) $(2) ; \
		fi > .tmp ; rm .tmp))


###########################################################################
# Build rules

# We can't use the kernelbuild macro in verbose targets because it gobbles the
# output of the shell.

$(MODULES): $(TARGETS)
	@cp $(TARGETS) .

$(TARGETS): $(SOURCES)
	@for s in $(DRIVERS) ; do \
		if [ -n "$(KOBJ)" ]; then \
			$(MAKE) ccflags-y+="$(CFLAGS_EXTRA)" -C $(KSRC) CONFIG_I40E=m CONFIG_I40EVF=m SUBDIRS=`pwd`/$$s modules ; \
		else \
			$(MAKE) ccflags-y+="$(CFLAGS_EXTRA)" -C $(KSRC) -O $(KOBJ) CONFIG_I40E=m CONFIG_I40EVF=m SUBDIRS=`pwd`/$$s modules ; \
		fi ; \
	done

noisy: $(SOURCES)
	@for s in $(DRIVERS) ; do \
		if [ -n "$(KOBJ)" ]; then \
			$(MAKE) -C $(KSRC) CONFIG_I40E=m CONFIG_I40EVF=m SUBDIRS=`pwd`/$$s V=1 modules ; \
		else \
			$(MAKE) -C $(KSRC) -O $(KOBJ) CONFIG_I40E=m CONFIG_I40EVF=m SUBDIRS=`pwd`/$$s V=1 modules ; \
		fi ; \
	done
	@cp $(TARGETS) .

silent: $(SOURCES)
	$(foreach d, $(DRIVERS), $(call kernelbuild,$(d),modules))
	@cp $(TARGETS) .

sparse: clean $(SOURCES)
	@for s in $(DRIVERS) ; do \
		if [ -n "$(KOBJ)" ]; then \
			$(MAKE) ccflags-y+="$(CFLAGS_EXTRA)" -C $(KSRC) CONFIG_I40E=m CONFIG_I40EVF=m SUBDIRS=`pwd`/$$s C=2 CF="-D__CHECK_ENDIAN__ -Wbitwise -Wcontext" modules ; \
		else \
			$(MAKE) ccflags-y+="$(CFLAGS_EXTRA)" -C $(KSRC) -O $(KOBJ) CONFIG_I40E=m CONFIG_I40EVF=m SUBDIRS=`pwd`/$$s C=2 CF="-D__CHECK_ENDIAN_ -Wbitwise -Wcontext" modules ; \
		fi ; \
	done

ccc: clean $(SOURCES)
	@for s in $(DRIVERS) ; do \
		if [ -n "$(KOBJ)" ]; then \
			$(MAKE) ccflags-y+="$(CFLAGS_EXTRA)" -C $(KSRC) CONFIG_I40E=m CONFIG_I40EVF=m SUBDIRS=`pwd`/$$s coccicheck MODE=report; \
		else \
			$(MAKE) ccflags-y+="$(CFLAGS_EXTRA)" -C $(KSRC) -O $(KOBJ) CONFIG_I40E=m CONFIG_I40EVF=m SUBDIRS=`pwd`/$$s coccicheck MODE=report; \
		fi ; \
	done

manfile:
	$(foreach m, $(DRIVERS), $(shell gzip -c ../$(m).$(MANSECTION) > $(m).$(MANSECTION).gz))

clean:
	$(foreach d, $(DRIVERS), $(call kernelbuild,$(d),clean))
	@-rm -rf *.$(MANSECTION).gz *.ko

install: $(MODULES) manfile
# remove all old versions of the driver
	$(foreach d, $(DRIVERS), $(shell rm -f $(INSTALL_MOD_PATH)$(INSTDIR)/$(d)/$(d).ko))
	$(foreach d, $(DRIVERS), $(shell rm -f $(INSTALL_MOD_PATH)$(INSTDIR)/$(d)/$(d).gz))
	$(foreach d, $(DRIVERS), $(shell rm -f $(INSTALL_MOD_PATH)$(INSTDIR)/$(d)/$(d).ko.xz))
	$(foreach m, $(DRIVERS), $(shell \
		install -D -m 644 $(m).$(MANSECTION).gz $(INSTALL_MOD_PATH)$(MANDIR)/man$(MANSECTION)/$(m).$(MANSECTION).gz ; \
		install -D -m 644 $(m).ko $(INSTALL_MOD_PATH)$(INSTDIR)/$(m)/$(m).ko))
ifeq (,$(INSTALL_MOD_PATH))
	@-/sbin/depmod -a $(KVER) || true
else
	@-/sbin/depmod -b $(INSTALL_MOD_PATH) -a -n $(KVER) > /dev/null || true
endif

uninstall:
	$(foreach d, $(DRIVERS), $(shell rm -f $(INSTALL_MOD_PATH)$(INSTDIR)/$(d)/$(d).ko))
	$(foreach d, $(DRIVERS), $(shell rm -f $(INSTALL_MOD_PATH)$(INSTDIR)/$(d)/$(d).gz))
	$(foreach d, $(DRIVERS), $(shell rm -f $(INSTALL_MOD_PATH)$(INSTDIR)/$(d)/$(d).ko.xz))
	@-/sbin/depmod -a $(KVER)
	$(foreach m, $(DRIVERS), $(shell \
		if [ -e $(INSTALL_MOD_PATH)$(MANDIR)/man$(MANSECTION)/$(m).$(MANSECTION).gz ] ; then \
			rm -f $(INSTALL_MOD_PATH)$(MANDIR)/man$(MANSECTION)/$(m).$(MANSECTION).gz ; \
		fi))

.PHONY: noisy clean manfile silent sparse ccc install uninstall
.NOTPARALLEL:

