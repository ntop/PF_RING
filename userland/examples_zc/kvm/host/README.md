# QEMU/KVM Scripts

This folder contains a handful of utility scripts to be used for
installing and running QEMU/KVM Virtual Machines to be used with ZC.

1. Load KVM modules and configure a network interface in bridge mode to provide network connectivity to the VMs

```
./kvm-load.sh eth1
```

2. Install the guest system booting from an iso image (first time only), or use a Cloud image editing vm-boot.sh

```
./vm-boot-cdrom.sh ubuntu-16.04.5-server-amd64.iso
```

3. Run the VM 

```
./vm-boot.sh
```

