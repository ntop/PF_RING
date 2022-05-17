# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2018-2021, Intel Corporation.

# When the make command line has the goal 'all' or no goal specified (i.e.
# when compiling the driver) a sub-make of the kernel's Makefile includes
# the kernel configuration (include/config/auto.conf), but if any other
# goal is specified (e.g. install) the kernel configuration does not get
# included.  Set a variable and export it to track over sub-makes.
ifeq ($(MAKELEVEL),0)
  ifeq ($(filter-out all, $(MAKECMDGOALS)),)
    export KERNEL_CONFIG_INCLUDED=1
  endif
endif

# Explicitly set shell to bash, to avoid issues on distros with a different
# default shell. Looking at you, Ubuntu.
SHELL=/bin/bash

ifneq ($(KERNELRELEASE),)
# kbuild part of makefile

#
# Makefile for the Intel(R) Ethernet Connection E800 Series Linux Driver
#

ccflags-y += -I$(src)
subdir-ccflags-y += -I$(src)

obj-m += ice.o

ice-y := ice_main.o	\
	 ice_controlq.o	\
	 ice_common.o	\
	 ice_nvm.o	\
	 ice_switch.o	\
	 ice_sched.o	\
	 ice_base.o	\
	 ice_lib.o	\
	 ice_txrx_lib.o	\
	 ice_txrx.o	\
	 ice_fltr.o	\
	 ice_irq.o	\
	 ice_pf_vsi_vlan_ops.o \
	 ice_vsi_vlan_ops.o \
	 ice_vsi_vlan_lib.o \
	 ice_gnss.o	\
	 ice_tc_lib.o	\
	 ice_fdir.o	\
	 ice_ethtool_fdir.o	\
	 ice_acl_main.o		\
	 ice_acl.o		\
	 ice_acl_ctrl.o		\
	 ice_vlan_mode.o	\
	 ice_flex_pipe.o	\
	 ice_flow.o		\
	 ice_lag.o		\
	 ice_fwlog.o		\
	 ice_ieps.o		\
	 ice_ethtool.o
ice-$(CONFIG_NET_DEVLINK:m=y) += ice_devlink.o ice_fw_update.o
ice-$(CONFIG_NET_DEVLINK:m=y) += ice_eswitch.o ice_repr.o
ice-y += ice_idc.o
ice-$(CONFIG_DEBUG_FS) += ice_debugfs.o
ice-$(CONFIG_PCI_IOV) += ice_virtchnl_allowlist.o
ice-$(CONFIG_PCI_IOV) += ice_dcf.o
ice-$(CONFIG_PCI_IOV) += ice_virtchnl_fdir.o
ice-$(CONFIG_PCI_IOV) +=	\
	ice_sriov.o		\
	ice_vf_mbx.o		\
	ice_vf_vsi_vlan_ops.o	\
	ice_vf_adq.o		\
	ice_virtchnl.o		\
	ice_vf_lib.o
ice-$(CONFIG_PTP_1588_CLOCK:m=y) += ice_ptp.o ice_ptp_hw.o
ice-$(CONFIG_DCB) += ice_dcb.o ice_dcb_nl.o ice_dcb_lib.o
ice-$(CONFIG_RFS_ACCEL) += ice_arfs.o
ice-$(CONFIG_XDP_SOCKETS) += ice_xsk.o
ice-y += kcompat.o
# Use kcompat pldmfw.c if kernel does not provide CONFIG_PLDMFW
ifndef CONFIG_PLDMFW
ice-y += kcompat_pldmfw.o
endif
# Use kcompat DIMLIB if kernel doesn't provide it
ifndef CONFIG_DIMLIB
ice-y += kcompat_dim.o kcompat_net_dim.o
endif

ifeq (${NEED_AUX_BUS},2)
#obj-m += auxiliary.o
endif

else	# ifneq($(KERNELRELEASE),)
# normal makefile

DRIVER := ice

COMMON_MK ?= $(wildcard common.mk)
ifeq (${COMMON_MK},)
  $(error Cannot find common.mk build rules)
else
  include ${COMMON_MK}
endif

# ice does not support building on kernels older than 3.10.0
$(call minimum_kver_check,3,10,0)


# Command to update initramfs or display a warning message
ifeq (${cmd_initrd},)
define cmd_initramfs
@echo "Unable to update initramfs. You may need to do this manually."
endef
else
define cmd_initramfs
@echo "Updating initramfs..."
$(call cmd_initrd)
endef
endif

# PF_RING
DEBUG_CFLAGS += -g -DDEBUG
#CFLAGS_EXTRA += ${DEBUG_CFLAGS}
CFLAGS_EXTRA += -D HAVE_PF_RING

all:
	# PF_RING
	cd ${PF_RING_PATH}/; make
	cp ${PF_RING_PATH}/Module.symvers .
	+$(call kernelbuild,modules)
	@gzip -c ../${DRIVER}.${MANSECTION} > ${DRIVER}.${MANSECTION}.gz
ifneq ($(wildcard lttng),)
	$(MAKE) -C lttng
endif

clean:
	+$(call kernelbuild,clean)
	@-rm -rf *.${MANSECTION}.gz *.ko
ifneq ($(wildcard lttng),)
	$(MAKE) -C lttng clean
endif

# Install kernel module files. This target is called by the RPM specfile when
# generating binary RPMs, and is not expected to modify files outside of the
# build root. Thus, it must not update initramfs, or run depmod.
DDP_PKG_ORIGIN := $(shell ls ../ddp/${DRIVER}-[[:digit:]]*\.[[:digit:]]*\.[[:digit:]]*\.[[:digit:]]*\.pkg 2>/dev/null)
DDP_PKG_NAME := $(shell basename ${DDP_PKG_ORIGIN} 2>/dev/null)
DDP_PKG_DEST_PATH := ${INSTALL_MOD_PATH}/lib/firmware/updates/intel/${DRIVER}/ddp
DDP_PKG_DEST := ${DDP_PKG_DEST_PATH}/${DDP_PKG_NAME}
DDP_PKG_LINK := ${DRIVER}.pkg
modules_install: all
	+$(call kernelbuild,modules_install)
	${auxiliary_post_install}
ifneq (${DDP_PKG_ORIGIN},)
	@# Install DDP package file if provided/required with ice module
	install -D -m 644 ${DDP_PKG_ORIGIN} ${DDP_PKG_DEST}
	(cd ${DDP_PKG_DEST_PATH} && ln -sf ${DDP_PKG_NAME} ${DDP_PKG_LINK})
	install -D -m 644 ../ddp/LICENSE ${DDP_PKG_DEST_PATH}/LICENSE \
		2>/dev/null || true
endif

mandocs_install: all
	install -D -m 644 ${DRIVER}.${MANSECTION}.gz ${INSTALL_MOD_PATH}/${MANDIR}/man${MANSECTION}/${DRIVER}.${MANSECTION}.gz

# After installing all the files, perform necessary work to ensure the system
# will use the new modules. This includes running depmod to update module
# dependencies and updating the initramfs image in case the module is loaded
# during early boot.
install: modules_install mandocs_install
	$(call cmd_depmod)
	$(call cmd_initramfs)

# Remove installed module files. This target is called by the RPM specfile when
# generating binary RPMs, and is not expected to modify files outside of the
# build root. Thus, it must not update the initramfs image or run depmod.
modules_uninstall:
	rm -f ${INSTALL_MOD_PATH}/lib/modules/${KVER}/${INSTALL_MOD_DIR}/${DRIVER}.ko
	${auxiliary_post_uninstall}
ifneq (${DDP_PKG_ORIGIN},)
	@# Uninstall DDP package file if provided/required with ice module
	(cd ${DDP_PKG_DEST_PATH} && \
	 [ `readlink ${DDP_PKG_LINK}` == ${DDP_PKG_NAME} ] && \
	 rm -f ${DDP_PKG_LINK} || true)
	rm -f ${DDP_PKG_DEST} ${DDP_PKG_DEST_PATH}/LICENSE
endif

mandocs_uninstall:
	rm -f ${INSTALL_MOD_PATH}/${MANDIR}/man${MANSECTION}/${DRIVER}.${MANSECTION}.gz 2>/dev/null

# After uninstalling all the files, perform necessary work to restore the
# system back to using the default kernel modules. This includes running depmod
# to update module dependencies and updating the initramfs image.
uninstall: modules_uninstall mandocs_uninstall
	$(call cmd_depmod)
	$(call cmd_initramfs)

auxiliary_info:
	@../scripts/check_aux_bus --verbose --ksrc="${KSRC}" --build-kernel="${BUILD_KERNEL}"

ifeq (${NEED_AUX_BUS},1)
#all: auxiliary_info
endif

help:
	@echo 'Building external (out-of-tree) modules:'
	@echo '  all               - default target, build the module(s) and manpage'
	@echo '  clean             - remove generated files'
	@echo '  modules_install   - install the module(s) only'
	@echo '  mandocs_install   - install the manpage only'
	@echo '  install           - install the module(s) and manpage, and update initramfs'
	@echo '  modules_uninstall - uninstall the module(s) only'
	@echo '  mandocs_uninstall - uninstall the manpage only'
	@echo '  uninstall         - uninstall the module(s) and manpage, and update initramfs'
	@echo '  auxiliary_info    - print information about the auxiliary module'
	@echo ''
	@echo 'Command-line options:'
	@echo '  KSRC=<path>     - Path to kernel source (defaults to running kernel)'
	@echo '  LINUX_VERSION=<x.y.z> - Debug tool to force kernel LINUX_VERSION_CODE for'
	@echo '                          external module(s). *** Use at your own risk! ***'
	@echo '  INSTALL_MOD_PATH=<path> - Prefix added to default module(s) installation path'
	@echo '                            (/lib/modules/$$(KERNELRELEASE)/)'
	@echo '  INSTALL_MOD_DIR=<path> - Install module(s) in subdirectory other than default'
	@echo '                           (.../updates/drivers/net/ethernet/intel/${DRIVER}/)'
	@echo ''

.PHONY: all clean modules_install mandocs_install install modules_uninstall mandocs_uninstall uninstall help auxiliary_info

endif	# ifneq($(KERNELRELEASE),)
