#!/bin/bash
#
# Load the UIO module needed by ZC to attach to a cluster on the guest VM
#

# modprobe acpiphp
# modprobe virtio_console

modprobe uio

cd uio_kernel_module
make
insmod ./uio_ivshmem.ko

