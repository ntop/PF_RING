QEMU/KVM Support in PF_RING ZC
==============================

This guide shows how to run a consumer reading from a ZC queue on a KVM virtual machine.

Prerequisites
-------------

- Qemu >= 1.5.1 (latest stable from http://wiki.qemu.org/Download is supported)
- KVM support in Linux kernel (kvm_intel module)

In order to run a PF_RING ZC slave application on top of a QEMU/KVM Virtual Machine, follow these simple steps:

1. Run the Virtual Machine specifying a monitor socket to QEMU:

.. code-block:: console

   (H) qemu ... -chardev socket,path=/tmp/qmp0,server,nowait,id=qmp0 -mon chardev=qmp0,mode=control

(there are some ready-to-use scripts under scripts/, see next section for more informations)

2. Load the hotplug module, the virtio_console module and the uio module in the guest.

.. code-block:: console

   (G) modprobe acpiphp
   (G) modprobe virtio_console
   (G) modprobe uio
   (G) cd uio_kernel_module; make; insmod uio_ivshmem.ko

3. Run the PF_RING ZC master application in the host, listing the monitor sockets of all the running Virtual Machines:

.. code-block:: console

   (H) zbalance_ipc -i zc:eth1 -c 99 -n 2 -m 0 -Q /tmp/qmp0,/tmp/qmp1

Alternatively, run a traffic generator in the host, specifying the monitor socket of the running Virtual Machine 
where a consumer application will receive the generated traffic:

.. code-block:: console

   (H) zsend -c 99 -Q /tmp/qmp0

4. Run the PF_RING ZC slave application in the guest (both read packets from the specified queues):

.. code-block:: console

   (G1) zcount_ipc -i 0 -c 99 -u
   (G2) zcount_ipc -i 1 -c 99 -u

Common Issues
-------------

If you have problems runnning zcount_ipc (or similar) on the guest with an error like this:

.. code-block:: console

   zcount_ipc -i 0 -c 99 -u
    *** error mmap'ing uio memory region /dev/uio0: Invalid argument ***
   dmesg  | tail -n 1
   [ 1971.854205] zcount_ipc:3520 map pfn expected mapping type uncached-minus for [mem 0x28000000-0x28000fff], got write-back

Edit in /etc/default/grub the line starting with GRUB_CMDLINE_LINUX_DEFAULT and append "nopat", for example:

.. code-block:: text

   GRUB_CMDLINE_LINUX_DEFAULT="nopat"

Then run:

.. code-block:: console

   update-grub

How to create/boot a Qemu VM
----------------------------

Download latest stable Qemu (2.4.0):

.. code-block:: console

   wget http://wiki.qemu-project.org/download/qemu-2.4.0.tar.bz2
   tar xvjf qemu-2.4.0.tar.bz2 
   cd qemu-2.4.0

Edit hw/misc/ivshmem.c commenting out line 303 (see http://patchwork.ozlabs.org/patch/316785/):

.. code-block:: console

   //qemu_chr_fe_claim_no_fail(chr);

Configure/compile/install:

.. code-block:: console

   ./configure --prefix=/usr/local/kvm
   make; make install

Load the needed KVM and networking modules:

.. code-block:: console

   cd PF_RING/userland/examples_zc/scripts
   ./kvm-load.sh

Boot from a linux cdrom iso to install the OS:
(the script looks for /root/ubuntu-12.04.2-server-amd64.iso, creating the virtual drive ubuntu-amd64.img, using eth1 for networking)

.. code-block:: console

   ./vm-boot-cdrom.sh

A VNC client should be used to connect to the VM and setup networking for ssh access.
Bridge and TUN/TAP support are needed for networking (bridge module, brctl and tunctl tools).
After installation, boot the VM with:

.. code-block:: console

   ./vm-boot.sh

