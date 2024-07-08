Intel Processors
================

The AMD section describes how to configure AMD RYZEN or EPYC CPUs in case of
issues running PF_RING ZC. In fact on AMD it is common to experience issues with
the IOMMU due to the way application memory is provided to the network card with
ZC drivers for directly moving packets with DMA.

On Intel usually everything works just out of the box. However, depending on the
CPU, BIOS and kernel, it may happen to experience a similar issue on Intel CPUs.

The symptom consists of the application being unable to capture traffic or capture
empty packets. Example:

.. code-block:: console

   # pfcount -i zc:enp179s0f0 -v 1
   [RX][if_index=0][hash=4294967295][00:00:00:00:00:00 -> 00:00:00:00:00:00] [eth_type=0x0000] [caplen=1536][len=65531][eth_offset=0][l3_offset=14][l4_offset=0][payload_offset=0]
   [RX][if_index=0][hash=4294967295][00:00:00:00:00:00 -> 00:00:00:00:00:00] [eth_type=0x0000] [caplen=1536][len=65531][eth_offset=0][l3_offset=14][l4_offset=0][payload_offset=0]

In order to fix this you need to disable IOMMU support.

1. (Optional) Set 'IOMMU' (or VT-d / Virtualization Support) to 'Disabled' in the BIOS.

2. Disable intel_iommu in the GRUB boot parameters by appending 'intel_iommu=off' 
to GRUB_CMDLINE_LINUX /etc/default/grub and running 'update-grub' on Ubuntu or 
'grub2-mkconfig -o /boot/grub2/grub.cfg' on CentOS.

Now you should be able to run ZC.

Common Issues
-------------

If you are running a UEFI-based system with CentOS/RHEL please note that
the steps for configuring grub are a bit different. In that case you should
run 'grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg' to update the boot laoder.
