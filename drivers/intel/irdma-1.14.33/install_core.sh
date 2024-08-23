#!/bin/bash
#   SPDX-License-Identifier: GPL-2.0
#   Copyright(c) 2023 Intel Corporation. All rights reserved.

# $1 is the directory containing the built packages
# assumes directory only contains packages from
# rdma-core.   The directory home directory is probed
# for rdma_core_build* and the directory with the
# highest lexical sort is picked.  To override
# that selection the explicit rpm directory can be passed
# as an argument.
#
# The script assumes that ALL the pages in install directory will be installed.

cleanup () {
	rm -f /tmp/built$$.txt /tmp/installed$$.txt
}

usage()
{
	echo "Usage: $name [-h] [builddir]"
	echo
	echo "Options:"
	echo "-h - print usage"
	echo
	echo "The first arg is the builddir"
	echo "otherwise the \$HOME/rdma_core_build* is used"
}

trap cleanup SIGINT SIGTERM

if [ -r /etc/os-release ]
then
	source /etc/os-release
else
	echo "Unable to determine release"
	exit 1
fi

case $ID in
rhel|rocky|centos|ol|sles|anolis|almalinux|openEuler)
	pkgdirsuffix="rpmbuild/RPMS/$(uname -m)"
	pkgtype=rpm
	;;
ubuntu)
	pkgdirsuffix="."
	pkgtype=deb
	;;
*)
	echo "Unknown distribution"
	exit 1
	;;
esac

cdir=$(pwd)
while getopts 'h' opt
do
	case "$opt" in
	h)
		usage
		exit 0
		;;
	?)
		usage
		exit 1
		;;
	esac
done

if [ -z "$1" ]
then
	# sort order determines
	builddir=$(ls -d ~/rdma_core_build* | tail -1)
	if [ -z "$builddir" -o ! -d "$builddir" ]
	then
		echo build directory cannot be determinted
		exit 1
	fi
	pkgdir=${builddir}/${pkgdirsuffix}
else
	pkgdir=$(realpath -m --relative-to=$cdir $1)
	if ! ls ${pkgdir}/*.${pkgtype} > /dev/null 2>&1
	then
		echo "$pkgdir has no ${pkgtype} packages"
		usage
		exit 1
	fi
fi
if [ ! -d "${pkgdir}" ]
then
	echo ${pkgdir} not found
	usage
	exit 1
fi

get_built()
{
	rm -f /tmp/built$$.txt
	# build a list of package names from built files
	case $pkgtype in
	rpm)
		rpm -qp --qf "%{NAME}\n" *.rpm > /tmp/built$$.txt
		;;
	deb)
		for pkg in $(echo *.deb)
		do
			dpkg -f $pkg Package >> /tmp/built$$.txt
		done
		;;
	esac
}

remove_installed()
{
	rm -f /tmp/installed$$.txt
	case $pkgtype in
	rpm)
		for name in `cat /tmp/built$$.txt` libmana-1 libmana-1-debuginfo
		do
			if rpm -q $name 2>/dev/null
			then
				echo $name >> /tmp/installed$$.txt
			fi
		done
		[ -f /tmp/installed$$.txt ] && rpm -e --nodeps `cat /tmp/installed$$.txt`
		;;
	deb)
		for name in `cat /tmp/built$$.txt`
		do
			if dpkg -l $name > /dev/null 2>&1
			then
				echo $name >> /tmp/installed$$.txt
			fi
		done
		[ -f /tmp/installed$$.txt ] && dpkg -r --force-depends `cat /tmp/installed$$.txt`
		;;
	esac
}

do_install() {
	case $ID in
	rhel|rocky|centos|ol|anolis|almalinux|openEuler)
		get_built
		remove_installed
		if type dnf >/dev/null 2>/dev/null
		then
			dnf install -y *.rpm
		else
			yum install -y *.rpm
		fi
		;;
	sles)
		get_built
		remove_installed
		if zypper install --help | grep -q -- '--allow-unsigned-rpm'
		then
			zypper install -y --allow-unsigned-rpm *.rpm
		elif zypper --help | grep -q -- '--no-gpg-checks'
		then
			zypper --no-gpg-checks install -y *.rpm
		else
			zypper install -y *.rpm
		fi
		;;
	ubuntu)
		get_built
		remove_installed
		dpkg -i  *.deb
		;;
	esac
}

pushd $pkgdir
do_install
cleanup
