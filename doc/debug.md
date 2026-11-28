---
title: "Crash Debug"
description: "To diagnose a kernel hang/crash caused by loading one of the modules provided by pfring, you want the system to produce a kernel crash dump (kdump)."
outline: [2, 3]
---
# Crash Debug

To diagnose a kernel hang/crash caused by loading one of the modules provided by pf_ring, you want the system to produce a kernel crash dump (kdump).

This guide shows how to produce one on Ubuntu (kdump is supported but not enabled by default).

## Requirements

```shell
sudo apt update
sudo apt install linux-crashdump kdump-tools
```

If /usr/lib/debug/boot/vmlinux-\$(uname -r) doesn't exist, install debug kernel symbols:

```shell
sudo apt install linux-image-unsigned-$(uname -r)-dbgsym
sudo apt install linux-modules-$(uname -r)-dbgsym
```

The kernel needs pre-reserved memory to boot into the crash kernel after a panic.

```shell
cat /proc/cmdline | grep crashkernel
```

If empty, edit /etc/default/grub and add crashkernel=512M to this line:

```text
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash crashkernel=512M"
```

Then update and reboot:

```shell
sudo update-grub
sudo reboot
```

Enable the kdump service:

```shell
sudo systemctl enable --now kdump-tools
```

Configure where dumps are stored in /etc/default/kdump-tools:

```text
KDUMP_COREDIR="/var/crash"
KDUMP_KERNEL="/boot/vmlinuz-$(uname -r)"
```

## Analyze the dump

Reproduce the crash and analyze the dump with:

```shell
sudo crash /usr/lib/debug/boot/vmlinux-$(uname -r) /var/crash/vmcore
```
