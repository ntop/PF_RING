---
title: "QEMU/KVM Support in PF_RING ZC"
description: "This guide shows how to run a consumer reading from a ZC queue on a KVM virtual machine."
outline: [2, 3]
---
# QEMU/KVM Support in PF_RING ZC

This guide shows how to run a consumer reading from a ZC queue on a KVM virtual machine.

## Prerequisites

- Qemu \>= 1.5.1 and \<= 2.5
- KVM support in Linux kernel (kvm_intel module)

In order to run a PF_RING ZC slave application on top of a QEMU/KVM Virtual Machine, follow these simple steps:

1.  Run the Virtual Machine specifying a monitor socket to QEMU:

```shell
(H) qemu ... -chardev socket,path=/tmp/qmp0,server,nowait,id=qmp0 -mon chardev=qmp0,mode=control
```

(there are some ready-to-use scripts under PF_RING/userland/examples_zc/kvm/host/, see next section for more information)

2.  Load the uio module in the guest. Note that it could be needed to load the hotplug module (acpiphp) and the virtio_console module (virtio_console) according to your linux distribution.

```shell
(G) modprobe uio
(G) cd PF_RING/userland/examples_zc/kvm/guest/uio_kernel_module
(G) make && insmod uio_ivshmem.ko
```

3.  Run the PF_RING ZC master application in the host, listing the monitor sockets of all the running Virtual Machines:

```shell
(H) zbalance_ipc -i zc:eth1 -c 99 -n 2 -m 0 -Q /tmp/qmp0,/tmp/qmp1
```

Alternatively, run a traffic generator in the host, specifying the monitor socket of the running Virtual Machine where a consumer application will receive the generated traffic:

```shell
(H) zsend -c 99 -Q /tmp/qmp0
```

4.  Run the PF_RING ZC slave application in the guest (both read packets from the specified queues):

```shell
(G1) zcount_ipc -i 0 -c 99 -u
(G2) zcount_ipc -i 1 -c 99 -u
```

## Common Issues

If you have problems runnning zcount_ipc (or similar) on the guest with an error like this:

```shell
zcount_ipc -i 0 -c 99 -u
 *** error mmap'ing uio memory region /dev/uio0: Invalid argument ***
dmesg  | tail -n 1
[ 1971.854205] zcount_ipc:3520 map pfn expected mapping type uncached-minus for [mem 0x28000000-0x28000fff], got write-back
```

Edit in /etc/default/grub the line starting with GRUB_CMDLINE_LINUX_DEFAULT and append "nopat", for example:

```text
GRUB_CMDLINE_LINUX_DEFAULT="nopat"
```

Then run:

```shell
update-grub
```

## How to create/boot a Qemu VM

Install latest Qemu according to your Linux distribution, or compile Qemu from source code:

```shell
wget http://wiki.qemu-project.org/download/qemu-*.tar.bz2
tar xvjf qemu-*.tar.bz2 
cd qemu-*
```

On old Qemu versions (\<=2.4) you need to patch the ivshmem component editing hw/misc/ivshmem.c and commenting out line 303 (see <http://patchwork.ozlabs.org/patch/316785/>):

```shell
//qemu_chr_fe_claim_no_fail(chr);
```

Configure/compile/install:

```shell
./configure
make
make install
```

Load the needed KVM and networking modules (this creates a bridge with the provided interface):

```shell
cd PF_RING/userland/examples_zc/kvm/host/
./kvm-load.sh eth1
```

Boot from a linux cdrom iso to install the OS:

```shell
./vm-boot-cdrom.sh ubuntu-16.04.5-server-amd64.iso
```

A VNC client should be used to connect to the VM and setup networking for ssh access. Bridge and TUN/TAP support are needed for networking (bridge module, brctl and tunctl tools). After installation, boot the VM with:

```shell
./vm-boot.sh
```
