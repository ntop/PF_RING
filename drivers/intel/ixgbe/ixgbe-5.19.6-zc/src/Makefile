# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 1999 - 2023 Intel Corporation

ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
#
# Makefile for the Intel(R) 10GbE PCI Express Linux Network Driver
#

# PF_RING
ccflags-y += -I$(src)
subdir-ccflags-y += -I$(src)

obj-$(CONFIG_IXGBE) += ixgbe.o

define ixgbe-y
	ixgbe_main.o
	ixgbe_api.o
	ixgbe_common.o
	ixgbe_dcb.o
	ixgbe_dcb_82598.o
	ixgbe_dcb_82599.o
	ixgbe_ethtool.o
	ixgbe_lib.o
	ixgbe_mbx.o
	ixgbe_sriov.o
	ixgbe_param.o
	ixgbe_phy.o
	ixgbe_procfs.o
	ixgbe_xsk.o
	ixgbe_82598.o
	ixgbe_82599.o
	ixgbe_x540.o
	ixgbe_x550.o
endef
ixgbe-y := $(strip ${ixgbe-y})

ixgbe-${CONFIG_DCB} += ixgbe_dcb_nl.o

ixgbe-${CONFIG_DEBUG_FS} += ixgbe_debugfs.o

ixgbe-${CONFIG_FCOE:m=y} += ixgbe_fcoe.o

ixgbe-$(CONFIG_PTP_1588_CLOCK:m=y) += ixgbe_ptp.o

ixgbe-${CONFIG_SYSFS} += ixgbe_sysfs.o


ixgbe-y += kcompat.o

else	# ifneq($(KERNELRELEASE),)
# normal makefile

DRIVER := ixgbe

ifeq (,$(wildcard common.mk))
  $(error Cannot find common.mk build rules)
else
  include common.mk
endif

# Check that kernel version is at least 2.6.0, since we don't support 2.4.x
# kernels with the ixgbe driver. We can't use minimum_kver_check since SLES 10
# SP4's Make has a bug which causes $(eval) inside an ifeq conditional to error
# out. This was fixed in Make 3.81, but SLES 10 SP4 does not have a fix for
# this yet.
ifeq (0,$(shell [ ${KVER_CODE} -lt $(call get_kvercode,2,6,0) ]; echo "$?"))
  $(warning *** Aborting the build.)
  $(error This driver is not supported on kernel versions older than 2.6.0)
endif

######################
# Kernel Build Macro #
######################

# PF_RING
DEBUG_CFLAGS += -g -DDEBUG
CFLAGS_EXTRA += -DHAVE_PF_RING -DIXGBE_NO_HW_RSC -DDISABLE_PACKET_SPLIT ${DEBUG_CFLAGS} #-DDISABLE_NETIF_F_HW_VLAN_TX

# customized kernelbuild function
#
# ${1} is the kernel build target
# ${2} may contain extra rules to pass to kernelbuild macro
#
# We customize the kernelbuild target in order to provide our hack to disable
# CONFIG_PTP_1588_CLOCK support should -DNO_PTP_SUPPORT be defined in the extra
# cflags given on the command line.
devkernelbuild = $(call kernelbuild,$(if $(filter -DNO_PTP_SUPPORT,${EXTRA_CFLAGS}),CONFIG_PTP_1588_CLOCK=n) ${2},${1})

# Command to update initramfs or display a warning message
ifeq (${cmd_initrd},)
define cmd_initramfs
@echo "Unable to update initramfs. You may need to do this manually."
endef
else
define cmd_initramfs
@echo "Updating initramfs..."
-@$(call cmd_initrd)
endef
endif

###############
# Build rules #
###############

# Standard compilation, with regular output
default:
	# PF_RING
	cd ${PF_RING_PATH}/; make
	cp ${PF_RING_PATH}/Module.symvers .
	@+$(call devkernelbuild,modules)

# Noisy output, for extra debugging
noisy:
	@+$(call devkernelbuild,modules,V=1)

# Silence any output generated
silent:
	@+$(call devkernelbuild,modules,>/dev/null)

# Enable higher warning level
checkwarnings: clean
	@+$(call devkernelbuild,modules,W=1)

# Run sparse static analyzer
sparse: clean
	@+$(call devkernelbuild,modules,C=2 CF="-D__CHECK_ENDIAN__ -Wbitwise -Wcontext")

# Run coccicheck static analyzer
ccc: clean
	@+$(call devkernelbuild,modules,coccicheck MODE=report))

# Build manfiles
manfile:
	@gzip -c ../${DRIVER}.${MANSECTION} > ${DRIVER}.${MANSECTION}.gz

# Clean the module subdirectories
clean:
	@+$(call devkernelbuild,clean)
	@-rm -rf *.${MANSECTION}.gz *.ko

# Install the modules and manpage
mandocs_install: manfile
	@echo "Copying manpages..."
	@install -D -m 644 ${DRIVER}.${MANSECTION}.gz ${INSTALL_MOD_PATH}${MANDIR}/man${MANSECTION}/${DRIVER}.${MANSECTION}.gz

# Install kernel module files. This target is called by the RPM specfile
# when generating binary RPMs, and is not expected to modify files outside
# of the build root. Thus, it must not update initramfs, or run depmod.
modules_install: default
	@echo "Installing modules..."
	@+$(call devkernelbuild,modules_install)

# After installing all the files, perform necessary work to ensure the
# system will use the new modules. This includes running depmod to update
# module dependencies and updating the initramfs image in case the module is
# loaded during early boot.
install: modules_install mandocs_install
	@echo "Running depmod..."
	$(call cmd_depmod)
	$(call cmd_initramfs)

mandocs_uninstall:
	if [ -e ${INSTALL_MOD_PATH}${MANDIR}/man${MANSECTION}/${DRIVER}.${MANSECTION}.gz ] ; then \
		rm -f ${INSTALL_MOD_PATH}${MANDIR}/man${MANSECTION}/${DRIVER}.${MANSECTION}.gz ; \
	fi;

# Remove installed module files. This target is called by the RPM specfile
# when generating binary RPMs, and is not expected to modify files outside
# of the build root. Thus, it must not update the initramfs image or run
# depmod.
modules_uninstall:
	rm -f ${INSTALL_MOD_PATH}/lib/modules/${KVER}/${INSTALL_MOD_DIR}/${DRIVER}.ko;

# After uninstalling all the files, perform necessary work to restore the
# system back to using the default kernel modules. This includes running
# depmod to update module dependencies and updating the initramfs image.
uninstall: modules_uninstall mandocs_uninstall
	$(call cmd_depmod)
	$(call cmd_initramfs)

########
# Help #
########
help:
	@echo 'Build targets:'
	@echo '  default             - Build module(s) with standard verbosity'
	@echo '  noisy               - Build module(s) with V=1 verbosity -- very noisy'
	@echo '  silent              - Build module(s), squelching all output'
	@echo ''
	@echo 'Static Analysis:'
	@echo '  checkwarnings       - Clean, then build module(s) with W=1 warnings enabled'
	@echo '  sparse              - Clean, then check module(s) using sparse'
	@echo '  ccc                 - Clean, then check module(s) using coccicheck'
	@echo ''
	@echo 'Cleaning targets:'
	@echo '  clean               - Clean files generated by kernel module build'
	@echo ''
	@echo 'Other targets:'
	@echo '  manfile             - Generate a gzipped manpage'
	@echo '  modules_install     - Install the module(s) only'
	@echo '  mandocs_install     - Install the manpage only'
	@echo '  install             - Build then install the module(s) and manpage, and update initramfs'
	@echo '  modules_uninstall   - Uninstall the module(s) only'
	@echo '  mandocs_uninstall   - Uninstall the manpage only'
	@echo '  uninstall           - Uninstall the module(s) and manpage, and update initramfs'
	@echo '  help                - Display this help message'
	@echo ''
	@echo 'Variables:'
	@echo '  LINUX_VERSION       - Debug tool to force kernel LINUX_VERSION_CODE. Use at your own risk.'
	@echo '  W=N                 - Kernel variable for setting warning levels'
	@echo '  V=N                 - Kernel variable for setting output verbosity'
	@echo '  INSTALL_MOD_PATH    - Add prefix for the module and manpage installation path'
	@echo '  INSTALL_MOD_DIR     - Use module directory other than updates/drivers/net/ethernet/intel/${DRIVER}'
	@echo ' Other variables may be available for tuning make process, see'
	@echo ' Kernel Kbuild documentation for more information'

.PHONY: default noisy clean manfile silent sparse ccc install uninstall help

endif	# ifneq($(KERNELRELEASE),)
