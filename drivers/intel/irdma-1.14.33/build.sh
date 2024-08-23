#!/bin/bash

# SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
# Copyright (c) 2015 - 2023 Intel Corporation

print_usage() {
	echo
	echo "usage: $0 {ofed} {noinstall} {sparse} {<dir> ...}"
	echo "    ofed      - compile using OFED 4.17 or above modules"
	echo "    noinstall - skip driver installation"
	echo "    sparse    - enforce source code checks (requires sparse)"
	echo "    dir       - extra directory to be searched for header files"
	exit 1
}

get_suse_local_ver() {
	CONFIG_SUSE_KERNEL=`grep " CONFIG_SUSE_KERNEL " $1 | cut -d' ' -f3`
	if [ "$CONFIG_SUSE_KERNEL" == "1" ]; then
		LV=`grep " CONFIG_LOCALVERSION " $1 | cut -d'-' -f2 | sed 's/\.g[[:xdigit:]]\{7\}//'`
		LV_A=`echo $LV | cut -d'.' -f1`
		LV_B=`echo $LV | cut -s -d'.' -f2`
		LV_C=`echo $LV | cut -s -d'.' -f3`
		SLE_LOCALVERSION_CODE=$((LV_A * 65536 + LV_B * 256 + LV_C))
	else
		SLE_LOCALVERSION_CODE=0
	fi
}

cmd_initrd() {
	echo "Updating initramfs..."
	if which dracut > /dev/null 2>&1 ; then
		echo 'dracut --force --omit-drivers  "irdma i40iw"'
		echo "omit_drivers+=\" irdma i40iw \"" > /etc/dracut.conf.d/irdma_omit.conf
		dracut --force --omit-drivers  "irdma i40iw"
	elif which update-initramfs > /dev/null 2>&1 ; then
		echo "update-initramfs -u -k $(uname -r)"
		update-initramfs -u -k $(uname -r)
	else
		echo "Unable to update initramfs. You may need to do this manually."
	fi
}

# Use KSRC if defined.
if [ -z "$KSRC" ]; then

	if [ -z "$BUILD_KERNEL" ]; then
		BUILD_KERNEL=`uname -r`
	fi

	if [ -e /usr/src/kernels/linux-$BUILD_KERNEL/include/config ]; then
		KSRC="/usr/src/kernels/linux-$BUILD_KERNEL/"
	elif [ -e /usr/src/kernels/$BUILD_KERNEL/include/config ]; then
		KSRC="/usr/src/kernels/$BUILD_KERNEL/"
	elif [ -e /lib/modules/$BUILD_KERNEL/build/include/config ]; then
		KSRC="/lib/modules/$BUILD_KERNEL/build/"
	fi

	if [ -z "$KSRC" ]; then
		BUILD_KERNEL=`uname -r | sed 's/\([0-9]*\.[0-9]*\)\..*/\1/'`
		if [ -e /usr/src/kernels/linux-$BUILD_KERNEL/include/config ]; then
			KSRC="/usr/src/kernels/linux-$BUILD_KERNEL/"
		elif [ -e /usr/src/kernels/$BUILD_KERNEL/include/config ]; then
			KSRC="/usr/src/kernels/$BUILD_KERNEL/"
		elif [ -e /lib/modules/$BUILD_KERNEL/build/include/config ]; then
			KSRC="/lib/modules/$BUILD_KERNEL/build/"
		fi
	fi
	export KSRC
else
	if [ -z "$BUILD_KERNEL" ]; then
		found=0
		BUILD_KERNEL=`uname -r`
		if [ -e /usr/src/kernels/linux-$BUILD_KERNEL/include/config ]; then
			found=1
		elif [ -e /usr/src/kernels/$BUILD_KERNEL/include/config ]; then
			found=1
		elif [ -e /lib/modules/$BUILD_KERNEL/build/include/config ]; then
			found=1
		fi

		if [ $found -ne 1 ]; then
			BUILD_KERNEL=`uname -r | sed 's/\([0-9]*\.[0-9]*\)\..*/\1/'`
			if [ -e /usr/src/kernels/linux-$BUILD_KERNEL/include/config ]; then
				found=1
			elif [ -e /usr/src/kernels/$BUILD_KERNEL/include/config ]; then
				found=1
			elif [ -e /lib/modules/$BUILD_KERNEL/build/include/config ]; then
				found=1
			fi
		fi
		if [ $found -ne 1 ]; then
			echo Cannot find BUILD_KERNEL
			exit 1
		fi
	fi
fi

if [ -e ${KSRC}/include/linux/kconfig.h ]; then
	INCLUDE_KCONF_HDR="-include ${KSRC}/include/linux/kconfig.h"
	export INCLUDE_KCONF_HDR
fi

if [ -e ${KSRC}/include/generated/autoconf.h ]; then
	INCLUDE_AUTOCONF_HDR="-include ${KSRC}/include/generated/autoconf.h"
	export INCLUDE_AUTOCONF_HDR
	get_suse_local_ver "${KSRC}/include/generated/autoconf.h"
elif [ -e ${KSRC}/include/linux/autoconf.h ]; then
	INCLUDE_AUTOCONF_HDR="-include ${KSRC}/include/linux/autoconf.h"
	export INCLUDE_AUTOCONF_HDR
	get_suse_local_ver "${KSRC}/include/linux/autoconf.h"
fi

if [ -e ${KSRC}/include/generated/utsrelease.h ]; then
	UTSRELEASE_HDR="-include ${KSRC}/include/generated/utsrelease.h"
	export UTSRELEASE_HDR
fi

USE_OFED=0
NO_INSTALL=0
CHECK=0
CHECK_FLAGS=
EXTRA_INCS=

for arg in "$@"; do
	if [ "$arg" == "ofed" ]; then
		USE_OFED=1
	elif [ "$arg" == "noinstall" ]; then
		NO_INSTALL=1
	elif [ "$arg" == "sparse" ]; then
		CHECK=1
		CHECK_FLAGS="-fdiagnostic-prefix -D__CHECK_ENDIAN__ -Wsparse-error"
	elif [ -d "$arg" ]; then
		EXTRA_INCS+="-I${arg} "
	fi
done

# Generate irdma_kcompat_gen.h
export CONFFILE=$KSRC/include/generated/autoconf.h
chmod +x $PWD/src/irdma/kcompat-generator.sh
GSRC=$KSRC
if [ ! -d ${KSRC}/include/rdma ]; then
	echo "Detect other Debian/SLES include directory using KSRC..."
	# detect other SLES include directory using KSRC
	t=$(dirname $KSRC)/$(basename $KSRC)
	if [ -L "$t" ]; then
		# a symlink
		t=$(readlink -f $t)
	fi
	# SLES
	t=${t%-obj*}
	# Debian
	t=${t/-amd64/-common}
	if [ -d ${t}/include/rdma ]; then
		GSRC=$t
	fi
fi

echo "KSRC: $KSRC"
echo "GSRC: $GSRC"

OUT=$PWD/src/irdma/irdma_kcompat_gen.h KSRC=$GSRC QUIET_COMPAT=1 $PWD/src/irdma/kcompat-generator.sh
if [ $? -ne 0 ]; then
	echo "Failed to generate $PWD/src/irdma/irdma_kcompat_gen.h"
	exit 1
fi
make -C $KSRC CFLAGS_MODULE="${EXTRA_INCS}" M=$PWD/src/irdma clean

which nproc > /dev/null 2>&1
if [ $? -ne 0 ]; then
	nproc=1
else
	nproc=`nproc`
fi

# Run compile-time source code checks if 'sparse' tool is installed
if [ $CHECK -eq 1 ]; then
	SPARSE=`which sparse`
	if [ -n "$SPARSE" ]; then
		echo "Building with source code checker (sparse) enabled"
	else
		echo "Unable to run source code checks if 'sparse' tool is not installed"
		exit 1
	fi
fi

if [ -e "/lib/modules/$BUILD_KERNEL/extern-symvers/intel_auxiliary.symvers" -a \
     -e "/lib/modules/$BUILD_KERNEL/extern-symvers/auxiliary.symvers" ]; then
	echo "WARNING: Two incompatible auxiliary bus drivers installed"
	echo "The irdma driver may not load or may not operate properly"
	ls /lib/modules/$BUILD_KERNEL/extern-symvers/*
fi

if [ -e "/lib/modules/$BUILD_KERNEL/extern-symvers/intel_auxiliary.symvers" ]; then
	KBUILD_EXTRA_SYMBOLS="/lib/modules/$BUILD_KERNEL/extern-symvers/intel_auxiliary.symvers"
	export KBUILD_EXTRA_SYMBOLS
elif [ -e "/lib/modules/$BUILD_KERNEL/extern-symvers/auxiliary.symvers" ]; then
	KBUILD_EXTRA_SYMBOLS="/lib/modules/$BUILD_KERNEL/extern-symvers/auxiliary.symvers"
	export KBUILD_EXTRA_SYMBOLS
fi

if [ "$USE_OFED" == "1" ]; then
	if [ -z "$OFED_OPENIB_PATH" ]; then
		OFED_OPENIB_PATH="/usr/src/openib"
	fi
	if [ ! -e $OFED_OPENIB_PATH ]; then
		echo "Please install OFED development package"
		print_usage
	fi

	if [ -z "$OFED_VERSION_CODE" ]; then
		V1=$(ofed_info | head -1 | cut -d '-' -f 2 | cut -d '.' -f 1)
		V2=$(ofed_info | head -1 | cut -d '-' -f 2 | cut -d '.' -f 2 | cut -d ':' -f 1)
		OFED_VERSION_CODE=$(( ($V1 << 16) + ($V2 << 8) ))
	fi

	if [ ${OFED_VERSION_CODE} -lt $(( (4 << 16) + (8 << 8) )) ]; then
		echo "Unsupported OFED version installed, requires 4.8 or above"
		exit 1
	fi

	KBUILD_EXTRA_SYMBOLS+=" $OFED_OPENIB_PATH/Module.symvers "
	export KBUILD_EXTRA_SYMBOLS

	INCLUDE_COMPAT_HDR="-include $OFED_OPENIB_PATH/include/linux/compat-2.6.h -I$OFED_OPENIB_PATH/include -I$OFED_OPENIB_PATH/include/uapi"
	export INCLUDE_COMPAT_HDR

	# WA required to build RHEL OFED using gcc >= 5.x
	# - silence certain compilation warnings (for RHEL 7.4-7.6)
	KCFLAGS="-Wno-attributes -Wno-address-of-packed-member -Wno-missing-attributes "
	# - make the compiler pretend to be gcc 4.x (for RHEL 7.2)
	KCFLAGS+="-U__GNUC__ -D__GNUC__=4 "
	# WA to prevent including content of kcompat_generated_defs.h
	# from LAN or auxiliary_bus driver, as some macros defined there
	# may be in conflict in those defined in OFEDs compat.h.
	KCFLAGS+="-D_KCOMPAT_GENERATED_DEFS_H_ "
	export KCFLAGS

	if [ ${OFED_VERSION_CODE} == $(( (4 << 16) + (8 << 8) )) ]; then
		make "CFLAGS_MODULE=-DMODULE -DSLE_LOCALVERSION_CODE=${SLE_LOCALVERSION_CODE} -D__OFED_4_8__ -DOFED_VERSION_CODE=${OFED_VERSION_CODE} ${EXTRA_INCS}" -j$nproc -C $KSRC M=$PWD/src/irdma W=1 C=$CHECK CF="$CHECK_FLAGS"
	else
		make "CFLAGS_MODULE=-DMODULE -DSLE_LOCALVERSION_CODE=${SLE_LOCALVERSION_CODE} -D__OFED_BUILD__ -DOFED_VERSION_CODE=${OFED_VERSION_CODE} ${EXTRA_INCS}" -j$nproc -C $KSRC M=$PWD/src/irdma W=1 C=$CHECK CF="$CHECK_FLAGS"
	fi
else
	make "CFLAGS_MODULE=-DMODULE -DSLE_LOCALVERSION_CODE=${SLE_LOCALVERSION_CODE} -DOFED_VERSION_CODE=${OFED_VERSION_CODE} ${EXTRA_INCS}" -j$nproc -C $KSRC M=$PWD/src/irdma W=1 C=$CHECK CF="$CHECK_FLAGS"
fi

if [ $? -eq 0 ]; then
	if [ "$NO_INSTALL" == "0" ]; then
		make -C $KSRC CFLAGS_MODULE="${EXTRA_INCS}" M=$PWD/src/irdma INSTALL_MOD_DIR=updates/drivers/infiniband/hw/irdma C=$CHECK CF="$CHECK_FLAGS" modules_install
		if [ $? -eq 0 ]; then
			rmmod i40iw 2> /dev/null
			rm -f /lib/modules/$BUILD_KERNEL/kernel/drivers/infiniband/hw/i40iw/i40iw.ko 2> /dev/null
			rm -f /lib/modules/$BUILD_KERNEL/updates/drivers/infiniband/hw/i40iw/i40iw.ko 2> /dev/null
			rm -f /lib/modules/$BUILD_KERNEL/kernel/drivers/infiniband/hw/i40iw/i40iw.ko.xz 2> /dev/null
			rm -f /lib/modules/$BUILD_KERNEL/updates/drivers/infiniband/hw/i40iw/i40iw.ko.xz 2> /dev/null
			echo "Creating /etc/modprobe.d/irdma.conf file ..."
			mkdir -p "/etc/modprobe.d/"
			if [ -e "/etc/modprobe.d/irdma.conf" ]; then
				if [ "" = "$(grep 'blacklist i40iw' /etc/modprobe.d/irdma.conf)" ]; then
					echo "blacklist i40iw"  >>  "/etc/modprobe.d/irdma.conf"
					echo "alias i40iw irdma" >> "/etc/modprobe.d/irdma.conf"
				fi
			else
				echo "blacklist i40iw"  >  "/etc/modprobe.d/irdma.conf"
				echo "alias i40iw irdma" >> "/etc/modprobe.d/irdma.conf"
			fi
			depmod -a
			cmd_initrd
		else
			exit 1
		fi
	fi
else
	exit 1
fi
