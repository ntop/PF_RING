################################################################################
#
# Intel 10 Gigabit PCI Express Linux driver
# Copyright (c) 1999 - 2014 Intel Corporation.
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
# The full GNU General Public License is included in this distribution in
# the file called "COPYING".
#
# Contact Information:
# e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
# Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
#
################################################################################

###########################################################################
# Driver files

# core driver files
CFILES = ixgbe_main.c ixgbe_common.c ixgbe_api.c ixgbe_param.c \
         ixgbe_lib.c ixgbe_ethtool.c kcompat.c ixgbe_82598.c \
         ixgbe_82599.c ixgbe_x540.c \
         ixgbe_sriov.c ixgbe_mbx.c \
         ixgbe_dcb.c ixgbe_dcb_82598.c \
         ixgbe_dcb_82599.c \
         ixgbe_sysfs.c \
         ixgbe_procfs.c \
         ixgbe_phy.c

# PTP support is set by CFLAGS compile directive, so we don't need to compile
# ixgbe_ptp.c unless it is set.
ifneq (,$(findstring -DIXGBE_PTP, $(CFLAGS_EXTRA)))
CFILES += ixgbe_ptp.c
endif

HFILES = ixgbe.h ixgbe_common.h ixgbe_api.h ixgbe_osdep.h kcompat.h \
         ixgbe_sriov.h ixgbe_mbx.h \
         ixgbe_dcb.h \
         ixgbe_phy.h
ifeq (,$(BUILD_KERNEL))
BUILD_KERNEL=$(shell uname -r)
endif

DRIVER_NAME=ixgbe


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
# and have an include/linux sub-directory
test_dir = $(shell [ -e $(dir)/include/linux ] && echo $(dir))
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

# pick a compiler
ifneq (,$(findstring egcs-2.91.66, $(shell cat /proc/version)))
  CC := kgcc gcc cc
else
  CC := gcc cc
endif
test_cc = $(shell $(cc) --version > /dev/null 2>&1 && echo $(cc))
CC := $(foreach cc, $(CC), $(test_cc))
CC := $(firstword $(CC))
ifeq (,$(CC))
  $(error Compiler not found)
endif

# check for ubuntu kernel 3.13.0-24
IS_UBUNTU_3_13_PRE := $(shell uname -a | grep 3.13.0-24 | wc -l)
ifeq (1,$(IS_UBUNTU_3_13_PRE))
  EXTRA_CFLAGS += -DUBUNTU_3_13_PRE
endif

# we need to know what platform the driver is being built on
# some additional features are only built on Intel platforms
ARCH := $(shell uname -m | sed 's/i.86/i386/')
ifeq ($(ARCH),alpha)
  EXTRA_CFLAGS += -ffixed-8 -mno-fp-regs
endif
ifeq ($(ARCH),x86_64)
  EXTRA_CFLAGS += -mcmodel=kernel -mno-red-zone
endif
ifeq ($(ARCH),ppc)
  EXTRA_CFLAGS += -msoft-float
endif
ifeq ($(ARCH),ppc64)
  EXTRA_CFLAGS += -m64 -msoft-float
  LDFLAGS += -melf64ppc
endif

# extra flags for module builds
EXTRA_CFLAGS += -DDRIVER_$(shell echo $(DRIVER_NAME) | tr '[a-z]' '[A-Z]')
EXTRA_CFLAGS += -DDRIVER_NAME=$(DRIVER_NAME)
EXTRA_CFLAGS += -DDRIVER_NAME_CAPS=$(shell echo $(DRIVER_NAME) | tr '[a-z]' '[A-Z]')
# standard flags for module builds
EXTRA_CFLAGS += -DLINUX -D__KERNEL__ -DMODULE -O2 -pipe -Wall
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += $(shell [ -f $(KSRC)/include/linux/modversions.h ] && \
            echo "-DMODVERSIONS -DEXPORT_SYMTAB \
                  -include $(KSRC)/include/linux/modversions.h")

# PF_RING
# # NETIF_F_HW_VLAN_TX - is used to prevent VLAN stripping
# # IXGBE_NO_HW_RSC - is used to disable RSC mode
# # DISABLE_PACKET_SPLIT - is used to disable Packet Split mode
EXTRA_CFLAGS += -DENABLE_DNA -DIXGBE_NO_HW_RSC -DDISABLE_PACKET_SPLIT #-DDISABLE_NETIF_F_HW_VLAN_TX

EXTRA_CFLAGS += $(CFLAGS_EXTRA)

RHC := $(KSRC)/include/linux/rhconfig.h
ifneq (,$(wildcard $(RHC)))
  # 7.3 typo in rhconfig.h
  ifneq (,$(shell $(CC) $(CFLAGS) -E -dM $(RHC) | grep __module__bigmem))
	EXTRA_CFLAGS += -D__module_bigmem
  endif
endif

# get the kernel version - we use this to find the correct install path
KVER := $(shell $(CC) $(EXTRA_CFLAGS) -E -dM $(VERSION_FILE) | grep UTS_RELEASE | \
        awk '{ print $$3 }' | sed 's/\"//g')

# assume source symlink is the same as build, otherwise adjust KOBJ
ifneq (,$(wildcard /lib/modules/$(KVER)/build))
ifneq ($(KSRC),$(shell readlink /lib/modules/$(KVER)/build))
  KOBJ=/lib/modules/$(KVER)/build
endif
endif

KVER_CODE := $(shell $(CC) $(EXTRA_CFLAGS) -E -dM $(VSP) 2>/dev/null |\
	grep -m 1 LINUX_VERSION_CODE | awk '{ print $$3 }' | sed 's/\"//g')

# abort the build on kernels older than 2.4.0
ifneq (1,$(shell [ $(KVER_CODE) -ge 132096 ] && echo 1 || echo 0))
  $(error *** Aborting the build. \
          *** This driver is not supported on kernel versions older than 2.4.0)
endif

# Add DCB netlink source if our kernel is 2.6.23 or newer
ifeq (1,$(shell [ $(KVER_CODE) -ge 132631 ] && echo 1 || echo 0))
  CFILES += ixgbe_dcb_nl.c
endif

# Add FCoE source if FCoE is supported by the kernel
FCOE := $(shell grep -wE 'CONFIG_FCOE|CONFIG_FCOE_MODULE' $(CONFIG_FILE) | \
	awk '{print $$3}')
ifeq ($(FCOE), 1)
  CFILES += ixgbe_fcoe.c
  HFILES += ixgbe_fcoe.h
endif

# Add Debug FS source if DEBUG_FS is supported by the kernel
DEBUGFS := $(shell grep -wE 'CONFIG_DEBUG_FS' $(CONFIG_FILE) | \
	awk '{print $$3}')
ifeq ($(DEBUGFS), 1)
  CFILES += ixgbe_debugfs.c
endif

# set the install path before and after 3.2.0
ifeq (1,$(shell [ $(KVER_CODE) -lt 197120 ] && echo 1 || echo 0))
INSTDIR := /lib/modules/$(KVER)/kernel/drivers/net/$(DRIVER_NAME)
else
INSTDIR := /lib/modules/$(KVER)/kernel/drivers/net/ethernet/intel/$(DRIVER_NAME)
endif

# look for SMP in config.h
SMP := $(shell $(CC) $(EXTRA_CFLAGS) -E -dM $(CONFIG_FILE) | \
         grep -w CONFIG_SMP | awk '{ print $$3 }')
ifneq ($(SMP),1)
  SMP := 0
endif

ifneq ($(SMP),$(shell uname -a | grep SMP > /dev/null 2>&1 && echo 1 || echo 0))
  $(warning ***)
  ifeq ($(SMP),1)
    $(warning *** Warning: kernel source configuration (SMP))
    $(warning *** does not match running kernel (UP))
  else
    $(warning *** Warning: kernel source configuration (UP))
    $(warning *** does not match running kernel (SMP))
  endif
  $(warning *** Continuing with build,)
  $(warning *** resulting driver may not be what you want)
  $(warning ***)
endif

ifeq ($(SMP),1)
  EXTRA_CFLAGS += -D__SMP__
endif


###########################################################################
# Kernel Version Specific rules

ifeq (1,$(shell [ $(KVER_CODE) -ge 132352 ] && echo 1 || echo 0))

# Makefile for 2.5.x and newer kernel
TARGET = $(DRIVER_NAME).ko

# man page
MANSECTION = 7
MANFILE = $(TARGET:.ko=.$(MANSECTION))

ifneq ($(PATCHLEVEL),)
EXTRA_CFLAGS += $(CFLAGS_EXTRA)
obj-m += $(DRIVER_NAME).o
$(DRIVER_NAME)-objs := $(CFILES:.c=.o)
else
default:
ifeq ($(KOBJ),$(KSRC))
	$(MAKE) -C $(KSRC) SUBDIRS=$(shell pwd) modules
else
	$(MAKE) -C $(KSRC) O=$(KOBJ) SUBDIRS=$(shell pwd) modules
endif
endif

else # ifeq (1,$(shell [ $(KVER_CODE) -ge 132352 ] && echo 1 || echo 0))

# Makefile for 2.4.x kernel
TARGET = $(DRIVER_NAME).o

# man page
MANSECTION = 7
MANFILE = $(TARGET:.o=.$(MANSECTION))

# Get rid of compile warnings in kernel header files from SuSE
ifneq (,$(wildcard /etc/SuSE-release))
  EXTRA_CFLAGS += -Wno-sign-compare -fno-strict-aliasing
endif

# Get rid of compile warnings in kernel header files from fedora
ifneq (,$(wildcard /etc/fedora-release))
  EXTRA_CFLAGS += -fno-strict-aliasing
endif
CFLAGS += $(EXTRA_CFLAGS)

.SILENT: $(TARGET)
$(TARGET): $(filter-out $(TARGET), $(CFILES:.c=.o))
	$(LD) $(LDFLAGS) -r $^ -o $@
	echo; echo
	echo "**************************************************"
	echo "** $(TARGET) built for $(KVER)"
	echo -n "** SMP               "
	if [ "$(SMP)" = "1" ]; \
		then echo "Enabled"; else echo "Disabled"; fi
	echo "**************************************************"
	echo

$(CFILES:.c=.o): $(HFILES) Makefile
default:
	$(MAKE)

endif # ifeq (1,$(shell [ $(KVER_CODE) -ge 132352 ] && echo 1 || echo 0))

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

# depmod version for rpm builds
DEPVER := $(shell /sbin/depmod -V 2>/dev/null | \
          awk 'BEGIN {FS="."} NR==1 {print $$2}')

###########################################################################
# Build rules

$(MANFILE).gz: ../$(MANFILE)
	gzip -c $< > $@

install: default $(MANFILE).gz
	# remove all old versions of the driver
	find $(INSTALL_MOD_PATH)/lib/modules/$(KVER) -name $(TARGET) -exec rm -f {} \; || true
	find $(INSTALL_MOD_PATH)/lib/modules/$(KVER) -name $(TARGET).gz -exec rm -f {} \; || true
	install -D -m 644 $(TARGET) $(INSTALL_MOD_PATH)$(INSTDIR)/$(TARGET)
ifeq (,$(INSTALL_MOD_PATH))
	/sbin/depmod -a || true
else
  ifeq ($(DEPVER),1 )
	/sbin/depmod -r $(INSTALL_MOD_PATH) -a || true
  else
	/sbin/depmod -b $(INSTALL_MOD_PATH) -a -n $(KVERSION) > /dev/null || true
  endif
endif
	install -D -m 644 $(MANFILE).gz $(INSTALL_MOD_PATH)$(MANDIR)/man$(MANSECTION)/$(MANFILE).gz
	man -c -P'cat > /dev/null' $(MANFILE:.$(MANSECTION)=) || true

uninstall:
	if [ -e $(INSTDIR)/$(TARGET) ] ; then \
	    rm -f $(INSTDIR)/$(TARGET) ; \
	fi
	/sbin/depmod -a
	if [ -e $(MANDIR)/man$(MANSECTION)/$(MANFILE).gz ] ; then \
		rm -f $(MANDIR)/man$(MANSECTION)/$(MANFILE).gz ; \
	fi

.PHONY: clean install

clean:
ifeq ($(KOBJ),$(KSRC))
	$(MAKE) -C $(KSRC) SUBDIRS=$(shell pwd) clean
else
	$(MAKE) -C $(KSRC) O=$(KOBJ) SUBDIRS=$(shell pwd) clean
endif
	rm -rf $(TARGET) $(TARGET:.ko=.o) $(TARGET:.ko=.mod.c) $(TARGET:.ko=.mod.o) $(CFILES:.c=.o) $(MANFILE).gz .*cmd .tmp_versions
