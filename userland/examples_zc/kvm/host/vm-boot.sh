#!/bin/bash
#
# Run a QEMU VM with a QMP control socket to enable ZC support
#

#
# Cloud image download and configuration (as alternative to installing the system with vm-boot-cdrom.sh):
#  wget https://cloud-images.ubuntu.com/xenial/current/xenial-server-cloudimg-amd64-disk1.img
#  mv https://cloud-images.ubuntu.com/xenial/current/xenial-server-cloudimg-amd64-disk1.img zcvm-amd64.img 
#  cloud-localds -H zcvm zcvm-seed.img vm-seed 
# Add the option below to QEMU, and log into the VM with user 'ubuntu' and password 'ubuntu'
# -drive file=zcvm-seed.img,if=virtio \
#

qemu-system-x86_64 \
-enable-kvm \
-cpu host \
-k en-us \
-drive file=zcvm-amd64.img,if=virtio \
-boot c \
-m 512 \
-netdev type=tap,id=guest0,script=if-up.sh,vhost=on -device virtio-net-pci,netdev=guest0,mac=DE:AD:BE:EF:FE:EB  \
-vnc 0.0.0.0:0 \
-chardev socket,path=/tmp/qmp0,server,nowait,id=qmp0 \
-mon chardev=qmp0,mode=control \
$@

