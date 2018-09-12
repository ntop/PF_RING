#!/bin/bash
#
# Create a disk image and run a QEMU VM booting from an ISO (system installation). Example:
# ./vm-boot-cdrom.sh ubuntu-14.04.5-server-amd64.iso
#

qemu-img create -f qcow2 zcvm-amd64.img 10G

qemu-system-x86_64 \
-k en-us \
-drive file=zcvm-amd64.img,if=virtio \
-cdrom $1 \
-boot d \
-m 1024 \
-netdev type=tap,id=tap0,script=if-up.sh,vhost=on -device virtio-net-pci,netdev=tap0,mac=DE:AD:BE:EF:FE:EC  \
-vnc 0.0.0.0:0

