#!/bin/bash

SCRIPTPATH="$(cd "$(dirname "$0")"; pwd -P)"
RELEASE="$(cd ${SCRIPTPATH}; cat ../kernel/linux/pf_ring.h | grep RING_VERSION | head -1 | cut -d '"' -f 2)"
MAJOR_RELEASE="$(cd ${SCRIPTPATH}; cat ../kernel/linux/pf_ring.h | grep RING_VERSION | head -1 | cut -d '"' -f 2 | cut -d '.' -f 1)"
REVISION="$(cd ${SCRIPTPATH}; git rev-list --all |wc -l|tr -d '[[:space:]]')"
HASH="$(cd ${SCRIPTPATH}; git rev-parse HEAD)"

LIBPCAP_VERSION="$(cd ${SCRIPTPATH}; ls -d ../userland/libpcap-* | head -n1 | cut -d"-" -f2)"

get_release() {
	echo "${RELEASE}"
	exit 0
}

get_major_release() {
	echo "${MAJOR_RELEASE}"
	exit 0
}

get_revision() {
	echo "${REVISION}"
	exit 0
}

get_version() {
	echo "${RELEASE}-${REVISION}"
	exit 0
}

get_hash() {
	echo "${HASH}"
	exit 0
}

get_libpcap_version() {
	echo "${LIBPCAP_VERSION}"
	exit 0
}

case "$1" in
  --release)
	get_release;
	;;
  --major)
	get_major_release;
	;;
  --revision)
	get_revision;
	;;
  --hash)
	get_hash;
	;;
  --version)
	get_version;
	;;
  --libpcap-version)
	get_libpcap_version;
	;;
  *)
	echo "Usage: ${0} {--hash|--release|--major|--revision|--version|--libpcap-version}"
	exit 1
esac

exit 0
