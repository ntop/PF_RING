Crash Debug
===========

To diagnose a kernel hang/crash caused by loading one of the modules
provided by pf_ring, you want the system to produce a kernel crash dump (kdump).

This guide shows how to produce one on Ubuntu (kdump is supported but 
not enabled by default).

Requirements
------------

.. code-block:: console

   sudo apt update
   sudo apt install linux-crashdump kdump-tools

If /usr/lib/debug/boot/vmlinux-$(uname -r) doesn't exist, install debug 
kernel symbols:

.. code-block:: console

   sudo apt install linux-image-unsigned-$(uname -r)-dbgsym
   sudo apt install linux-modules-$(uname -r)-dbgsym

The kernel needs pre-reserved memory to boot into the crash kernel after a panic.

.. code-block:: console

   cat /proc/cmdline | grep crashkernel

If empty, edit /etc/default/grub and add crashkernel=512M to this line:

.. code-block:: text

   GRUB_CMDLINE_LINUX_DEFAULT="quiet splash crashkernel=512M"

Then update and reboot:

.. code-block:: console

   sudo update-grub
   sudo reboot

Enable the kdump service:

.. code-block:: console

   sudo systemctl enable --now kdump-tools

Configure where dumps are stored in /etc/default/kdump-tools:

.. code-block:: text

   KDUMP_COREDIR="/var/crash"
   KDUMP_KERNEL="/boot/vmlinuz-$(uname -r)"

Analyze the dump
----------------

Reproduce the crash and analyze the dump with:

.. code-block:: console

   sudo crash /usr/lib/debug/boot/vmlinux-$(uname -r) /var/crash/vmcore

