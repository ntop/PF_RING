#!/bin/sh

set -x

mkdir /rootfs/opt
cp -R /opt/pf_ring /rootfs/opt
cp  /install.sh /rootfs/tmp/

# Testing needed before enabling this:
#chroot /rootfs /tmp/install.sh
