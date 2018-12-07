#!/bin/bash

SCRIPTPATH="$(cd "$(dirname "$0")"; pwd -P)"
RELEASE="$(cd ${SCRIPTPATH}; cat ../kernel/linux/pf_ring.h | grep RING_VERSION | head -1 | cut -d '"' -f 2)"
REVISION="$(cd ${SCRIPTPATH}; git rev-list --all |wc -l|tr -d '[[:space:]]')"
HASH="$(cd ${SCRIPTPATH}; git rev-parse HEAD)"

get_release() {
	echo "${RELEASE}"
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

case "$1" in
  --release)
	get_release;
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
  *)
	echo "Usage: ${0} {--hash|--release|--revision|--version}"
	exit 1
esac

exit 0
