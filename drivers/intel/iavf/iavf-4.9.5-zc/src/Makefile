# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2013-2023 Intel Corporation

ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
#
# Makefile for the Intel(R) Ethernet Adaptive Virtual Function Driver
#

ccflags-y += -I$(src)
subdir-ccflags-y += -I$(src)

obj-m += iavf.o

iavf-y := iavf_main.o iavf_ethtool.o iavf_virtchnl.o iavf_adminq.o \
	iavf_common.o iavf_txrx.o iavf_idc.o \
	iavf_synce.o \
	iavf_gnss.o \


iavf-$(CONFIG_PTP_1588_CLOCK:m=y) += iavf_ptp.o

ifeq (${NEED_AUX_BUS},2)
intel_auxiliary-objs := auxiliary.o
obj-m += intel_auxiliary.o
endif

iavf-y += kcompat.o

else	# ifneq($(KERNELRELEASE),)
# normal makefile

DRIVER := iavf

# If the user just wants to print the help output, don't include common.mk or
# perform any other checks. This ensures that running "make help" will always
# work even if kernel-devel is not installed, or if the common.mk fails under
# any other error condition.
ifneq ($(MAKECMDGOALS),help)
include common.mk

# iavf does not support building on kernels older than 2.6.32
$(call minimum_kver_check,2,6,32)
endif

# Command to update initramfs or display a warning message
ifeq (${cmd_initrd},)
define cmd_initramfs
@echo "Unable to update initramfs. You may need to do this manaully."
endef
else
define cmd_initramfs
@echo "Updating initramfs..."
-@$(call cmd_initrd)
endef
endif

# PF_RING
DEBUG_CFLAGS += -g -DDEBUG
CFLAGS_EXTRA += -D HAVE_PF_RING ${DEBUG_CFLAGS}

###############
# Build rules #
###############

# Standard compilation, with regular output
default:
	# PF_RING
	cd ${PF_RING_PATH}/; make
	cp ${PF_RING_PATH}/Module.symvers .
	@+$(call kernelbuild,modules)

# Noisy output, for extra debugging
noisy:
	@+$(call kernelbuild,modules,V=1)

# Silence any output generated
silent:
	@+$(call kernelbuild,modules,>/dev/null)

# Enable higher warning level
checkwarnings: clean
	@+$(call kernelbuild,modules,W=1)

# Run sparse static analyzer
sparse: clean
	@+$(call kernelbuild,modules,C=2 CF="-D__CHECK_ENDIAN__ -Wbitwise -Wcontext")

# Run coccicheck static analyzer
ccc: clean
	@+$(call kernelbuild,modules,coccicheck MODE=report)

# Build manfiles
manfile:
	@gzip -c ../${DRIVER}.${MANSECTION} > ${DRIVER}.${MANSECTION}.gz

# Clean the module subdirectories
clean:
	@+$(call kernelbuild,clean)
	@-rm -rf *.${MANSECTION}.gz *.ko

mandocs_install: manfile
	@echo "Copying manpages..."
	@install -D -m 644 ${DRIVER}.${MANSECTION}.gz ${INSTALL_MOD_PATH}/${MANDIR}/man${MANSECTION}/${DRIVER}.${MANSECTION}.gz

# Install kernel module files. It is not expected to modify files outside of
# the build root. Thus, it must not update initramfs, or run depmod.
modules_install: default
	@echo "Installing modules..."
	@+$(call kernelbuild,modules_install)
	$(MAKE) auxiliary_install
	@echo "Creating /etc/modprobe.d/iavf.conf file ..."
	mkdir -p "${INSTALL_MOD_PATH}/etc/modprobe.d/"
	echo "blacklist i40evf"  >  "${INSTALL_MOD_PATH}/etc/modprobe.d/iavf.conf"

# Install kernel module files without auxiliary. This target is called by the
# RPM specfile when  generating binary RPMs, and is not expected to modify
# files outside of the build root. Thus, it must not update initramfs, or run depmod.
modules_install_no_aux:
	@echo "Installing modules..."
	@+$(call kernelbuild,modules_install)
	@echo "Creating /etc/modprobe.d/iavf.conf file ..."
	mkdir -p "${INSTALL_MOD_PATH}/etc/modprobe.d/"
	echo "blacklist i40evf"  >  "${INSTALL_MOD_PATH}/etc/modprobe.d/iavf.conf"

# After installing all the files, perform necessary work to ensure the system
# will use the new modules. This includes running depmod to update module
# dependencies and updating the initramfs image in case the module is loaded
# during early boot.
install: modules_install
	$(call cmd_depmod)
	$(call cmd_initramfs)
	$(MAKE) mandocs_install

# Target used by rpmbuild spec file
rpm: modules_install
	$(MAKE) mandocs_install

mandocs_uninstall:
	if [ -e ${INSTALL_MOD_PATH}/${MANDIR}/man${MANSECTION}/${DRIVER}.${MANSECTION}.gz ] ; then \
		rm -f ${INSTALL_MOD_PATH}/${MANDIR}/man${MANSECTION}/${DRIVER}.${MANSECTION}.gz ; \
	fi;

# Remove installed module files. This target is called by the RPM specfile when
# generating binary RPMs, and is not expected to modify files outside of the
# build root. Thus, it must not update the initramfs image or run depmod.
modules_uninstall:
	rm -f ${INSTALL_MOD_PATH}/lib/modules/${KVER}/${INSTALL_MOD_DIR}/${DRIVER}.ko;
	rm -f /etc/modprobe.d/iavf.conf;
	$(MAKE) auxiliary_uninstall

# After uninstalling all the files, perform necessary work to restore the
# system back to using the default kernel modules. This includes running depmod
# to update module dependencies and updating the initramfs image.
uninstall: modules_uninstall mandocs_uninstall
	$(call cmd_depmod)
	$(call cmd_initramfs)

auxiliary_info:
	@../scripts/check_aux_bus verbose

auxiliary_install:
	@echo "Installing auxiliary..."
	${auxiliary_post_install}

auxiliary_uninstall:
	${auxiliary_post_uninstall}

ifeq (${NEED_AUX_BUS},1)
all: auxiliary_info
endif

########
# Help #
########
help:
	@echo 'Cleaning targets:'
	@echo '  clean               - Clean files generated by kernel module build'
	@echo ''
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
	@echo 'Other targets:'
	@echo '  manfile             - Generate a gzipped manpage'
	@echo '  modules_install     - install the module(s) only'
	@echo '  mandocs_install     - install the manpage only'
	@echo '  install             - Build then install the module(s) and manpage'
	@echo '  modules_uninstall   - uninstall the module(s) only'
	@echo '  mandocs_uninstall   - uninstall the manpage only'
	@echo '  uninstall           - Uninstall the module(s) and manpage'
	@echo '  auxiliary_info      - Print information about the auxiliary module'
	@echo '  auxiliary_install   - Install compiled auxiliary module'
	@echo '  auxiliary_uninstall - Uninstall auxiliary module'
	@echo '  help                - Display this help message'
	@echo ''
	@echo 'Variables:'
	@echo '  LINUX_VERSION       - Debug tool to force kernel LINUX_VERSION_CODE. Use at your own risk.'
	@echo '  W=N                 - Kernel variable for setting warning levels'
	@echo '  V=N                 - Kernel variable for setting output verbosity'
	@echo '  INSTALL_MOD_PATH    - Add prefix for the module and manpage installation path'
	@echo '  INSTALL_MOD_DIR     - Use module directory other than updates/drivers/net/ethernet/intel/${DRIVER}'
	@echo '  KSRC                - Specifies the full path to the kernel tree to build against'
	@echo ' Other variables may be available for tuning make process, see'
	@echo ' Kernel Kbuild documentation for more information'

.PHONY: default noisy clean manfile silent sparse ccc install uninstall help

endif	# ifneq($(KERNELRELEASE),)
