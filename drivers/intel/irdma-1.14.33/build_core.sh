#!/bin/bash
#   SPDX-License-Identifier: GPL-2.0
#   Copyright(c) 2023 Intel Corporation. All rights reserved.
#
# This script downloads and builds the rdma-core from git.
# There is support for SLES and RHEL and clones.
#
# The build results are put into ~/rdma_core-build/rpmbuild.
#
# The access is assumed to be there for the following RHEL repos
# AppStream
# BaseOS
# CRB*
#
#	*Note CRB may be called powertools
#
# Access for the additional SLES Package Hub repo is required.
#
# Assuming correct repo access the script will use the spec file to
# load build dependencies automatically and build.

yes_no()
{
	local url=$1
	if [ "$force_download" -eq 1 ]
	then
		return 0
	fi
	while true
	do
		read -p "Downloading from $url, Y or N: " response
		case $response in
		[Yy])
			return 0
			;;
		[Nn])
			return 1
			;;
		esac
	done
}

load_epel9() {
	if [ "$nointernet" -eq 1 ]
	then
		return
	fi
	if [ -z "$epel_rpm" ]
	then
		yes_no https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm || exit 1
		dnf install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm -y
	else
		dnf install $epel_rpm
	fi
}

get_core() {
	local version=$1
	local builddir=$2
	pushd ${builddir}
	if [ -z "$core_tar" ]
	then
		yes_no https://github.com/linux-rdma/rdma-core/releases/download/v${version}/rdma-core-${version}.tar.gz || exit 1
		if wget -O /tmp/rdma-core-${version}.tar.gz https://github.com/linux-rdma/rdma-core/releases/download/v${version}/rdma-core-${version}.tar.gz
		then
			mv /tmp/rdma-core-${version}.tar.gz rdma-core-${version}.tar.gz
			rm -rf rdma-core-${version}
			tar -zxf rdma-core-${version}.tar.gz
		else
			echo "Unable to download rdma-core-${version}.tar.gz"
			exit 1
		fi
	else
		if ! tar -zxf $core_tar
		then
			echo "Unable to extract $core_tar"
			exit 1
		fi
	fi
	popd
}

get_version() {
	local patchdir=$1
	local patchfile=$(echo $patchdir/libirdma-*.patch)
	local version=$(basename $patchfile .patch)
	echo ${version#libirdma-}
}

patch_core() {
	local version=$1
	local builddir=$3
	local patchfile=$2
	pushd ${builddir}/rdma-core-${version}
	patch -p2 < ${patchfile}
	popd
}

get_tar_suffix() {
	local version=$1
	echo $(rpmspec --parse $2 | grep '^Source:' | sed "s/.*${version}\.\(.*\)$/\1/")
}

create_rhel_build() {
	local builddir=$2
	local version=$1
	local version_major=${1%.*}
	local suffix
	pushd ${builddir}
	rm -rf ${builddir}/rpmbuild
	mkdir -p ${builddir}/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS,OTHER}
	# need to copy spec post patch
	cp rdma-core-${version}/redhat/rdma-core.spec ${builddir}/rpmbuild/SPECS
	suffix=$(get_tar_suffix $version ${builddir}/rpmbuild/SPECS/rdma-core.spec)
	tar -zcf ${builddir}/rpmbuild/SOURCES/rdma-core-${version}.${suffix} rdma-core-${version}
	cd ${builddir}/rpmbuild/SPECS
	# probe and install dependencies
	if type dnf >/dev/null 2>/dev/null; then
		dnf install -y dnf-plugins-core rpm-build
		dnf builddep -y rdma-core.spec
	else
		yum install -y yum-utils rpm-build
		yum-builddep -y rdma-core.spec
	fi
	# 0914948e redhat: Support rpmbuild on RHEL9
	sed -i s/"%if 0%{?fedora} >= 33"/"%if 0%{?fedora} >= 33 || 0%{?rhel} >= 9"/g  rdma-core.spec
	[ "$version_major" -gt 49 ] && sed -i 's/-DPYTHON_EXECUTABLE:PATH/-DPython_EXECUTABLE/' rdma-core.spec
	if rpmbuild --noclean -ba --define "_topdir ${builddir}/rpmbuild" rdma-core.spec
	then
		echo "Build succeeded"
	else
		echo "Build failed"
		exit 1
	fi
	popd
}

create_sles_build() {
	local builddir=$2
	local version=$1
	local suffix
	pushd ${builddir}
	rm -rf ${builddir}/rpmbuild
	mkdir -p ${builddir}/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS,OTHER}
	# need to copy spec post patch
	cp rdma-core-${version}/suse/rdma-core.spec ${builddir}/rpmbuild/SPECS
	suffix=$(get_tar_suffix $version ${builddir}/rpmbuild/SPECS/rdma-core.spec)
	touch ${builddir}/rpmbuild//SOURCES/baselibs.conf
	tar -zcf ${builddir}/rpmbuild/SOURCES/rdma-core-${version}.${suffix} rdma-core-${version}
	cd ${builddir}/rpmbuild/SPECS
	# Ensure rpmbuild is here
	zypper install -y rpm-build
	# probe and install dependencies
	rpmspec --parse rdma-core.spec | grep BuildRequires | grep -v curl-mini | cut -d' ' -f2- | xargs -r  zypper install -y
	if rpmbuild --noclean -ba --define "_topdir ${builddir}/rpmbuild" --define '_build_create_debug 1' rdma-core.spec --without=curlmini
	then
		echo "Build succeeded"
	else
		echo "Build failed"
		exit 1
	fi
	popd
}

create_ubuntu_build() {
	local builddir=$2
	local version=$1
	pushd ${builddir}
	rm -rf ${builddir}/debbuild
	cp -r rdma-core-${version} ${builddir}/debbuild
	cd ${builddir}/debbuild
	# apply:
	# 766f88465 debian: Exclude libmana.so from ibverbs-providers
	sed -i 's/so\*/so.\*/' debian/ibverbs-providers.install
	dpkg-checkbuilddeps > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		sudo apt-get install --yes $(dpkg-checkbuilddeps 2>&1 | sed 's/([^)]*) *//g' | sed 's/dpkg-checkbuilddeps:\serror:\sUnmet build dependencies://g')
	fi
	# Build rdma-core
	dh clean --with python3,systemd --builddirectory=build-deb
	dh build --with systemd --builddirectory=build-deb
	if sudo dh binary --with systemd --builddirectory=build-deb
	then
		echo "Build succeeded"
	else
		echo "Build failed"
		exit 1
	fi
}

usage()
{
	echo "Usage: $name [-hyl] [-e epelrpm] [-t coretar]"
	echo
	echo "Options:"
	echo "-h - print usage"
	echo "-y - do download without prompt"
	echo "-l - local (no internet)"
	echo "-t <core tar> - rdma_core download tar ball"
	echo "-e <epel rpm> - epel rpm"
}

if [ -r /etc/os-release ]
then
	source /etc/os-release
else
	echo "Unable to determine release"
	exit 1
fi

name=$(basename $0)
force_download=0
nointernet=0
cdir=$(pwd)
while getopts 'hlye:t:' opt
do
	case "$opt" in
	y)
		force_download=1
		;;
	l)
		nointernet=1
		;;
	e)
		epel_rpm=$(realpath -m --relative-to=$cdir $OPTARG)
		if [ -z "$epel_rpm" -o ! -f $epel_rpm ]
		then
			echo "Invalid epel file: $OPTARG not in $cdir"
			exit 1
		fi
		;;
	t)
		core_tar=$(realpath -m --relative-to=$cdir $OPTARG)
		if [ -z "$core_tar" -o ! -f $core_tar ]
		then
			echo "Invalid coretar file: $OPTARG not in $cdir"
			exit 1
		fi
		;;
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
if [ $nointernet -eq 1 -a -z "$core_tar" ]
then
	echo "ERROR: -l and -t must both be specified"
	usage
	exit 1
fi


# patch defaults for directory of script
patchdir=$(realpath `dirname "$0"`)
CORE_VERSION=$(get_version $patchdir)
builddir=~/rdma_core_build_${CORE_VERSION}
mkdir -p ${builddir}
# determine distro
case $ID in
rhel|rocky|centos|ol|anolis|almalinux|openEuler)
	# RHEL9 needs epel
	if echo $VERSION_ID | grep '^9'
	then
		load_epel9
	fi
	# Download rdma-core from GitHub
	get_core $CORE_VERSION $builddir
	# patch core
	patch_core $CORE_VERSION ${patchdir}/libirdma-${CORE_VERSION}.patch $builddir
	# build rdma-core
	create_rhel_build $CORE_VERSION $builddir
	;;
sles)
	# Download rdma-core from GitHub
	get_core $CORE_VERSION $builddir
	# patch core
	patch_core $CORE_VERSION ${patchdir}/libirdma-${CORE_VERSION}.patch $builddir
	# build rdma-core
	create_sles_build $CORE_VERSION $builddir
	;;
ubuntu)
	# Download rdma-core from GitHub
	get_core $CORE_VERSION $builddir
	# patch core
	patch_core $CORE_VERSION ${patchdir}/libirdma-${CORE_VERSION}.patch $builddir
	# build rdma-core
	create_ubuntu_build $CORE_VERSION $builddir
	;;
*)
	echo "Unknown distribution"
	exit 1
	;;
esac
