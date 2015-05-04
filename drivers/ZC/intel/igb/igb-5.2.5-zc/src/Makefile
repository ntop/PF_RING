################################################################################
#
# Intel(R) Gigabit Ethernet Linux driver
# Copyright(c) 2007-2014 Intel Corporation.
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
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <htt;://www.gnu.org/licenses/>.
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
FAMILYC = e1000_82575.c e1000_i210.c
FAMILYH = e1000_82575.h e1000_i210.h

# core driver files
CFILES = igb_main.c $(FAMILYC) e1000_mac.c e1000_nvm.c e1000_phy.c \
	 e1000_manage.c igb_param.c igb_ethtool.c kcompat.c e1000_api.c \
	 e1000_mbx.c igb_vmdq.c igb_procfs.c igb_hwmon.c igb_debugfs.c
HFILES = igb.h e1000_hw.h e1000_osdep.h e1000_defines.h e1000_mac.h \
	 e1000_nvm.h e1000_manage.h $(FAMILYH) kcompat.h e1000_regs.h \
	 e1000_api.h igb_regtest.h e1000_mbx.h igb_vmdq.h
ifeq (,$(BUILD_KERNEL))
BUILD_KERNEL=$(shell uname -r)
endif

# Use IGB_PTP compile flag to enable IEEE-1588 PTP (documented in README)
ifeq ($(filter %IGB_PTP,$(CFLAGS_EXTRA)),-DIGB_PTP)
  CFILES += igb_ptp.c

#else # HAVE_PF_RING force PTP support
#EXTRA_CFLAGS += -DIGB_PTP #HAVE_PF_RING
#CFILES += igb_ptp.c

endif

DRIVER_NAME=igb


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
CSP :=  $(KSRC)/include/generated/autoconf.h \
        $(KSRC)/include/linux/autoconf.h \
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
EXTRA_CFLAGS += -DHAVE_PF_RING -DCONFIG_IGB_DISABLE_PACKET_SPLIT
EXTRA_CFLAGS += $(CFLAGS_EXTRA)

RHC := $(KSRC)/include/linux/rhconfig.h
ifneq (,$(wildcard $(RHC)))
  # 7.3 typo in rhconfig.h
  ifneq (,$(shell $(CC) $(EXTRA_CFLAGS) -E -dM $(RHC) | grep __module__bigmem))
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

# abort the build on kernels older than 2.4.21
ifneq (1,$(shell [ $(KVER_CODE) -ge 132117 ] && echo 1 || echo 0))
  $(error *** Aborting the build. \
          *** This driver '$(KVER_CODE)' is not supported on kernel versions older than 2.4.21, \
              because this driver requires NAPI support.)
endif

# look for PCI in config.h
PCI := $(shell $(CC) $(EXTRA_CFLAGS) -E -dM $(CONFIG_FILE) | \
         grep -w CONFIG_PCI | awk '{ print $$3 }')
ifneq ($(PCI),1)
  $(error *** Aborting the build. \
          *** This driver requires that CONFIG_PCI is enabled)
endif

# set the install path
INSTDIR := /lib/modules/$(KVER)/kernel/drivers/net/$(DRIVER_NAME)

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
	rm -rf $(TARGET) $(TARGET:.ko=.o) $(TARGET:.ko=.mod.c) $(TARGET:.ko=.mod.o) $(CFILES:.c=.o) \
	$(MANFILE).gz .*cmd .tmp_versions Module.markers Module.symvers modules.order
