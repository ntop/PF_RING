PCI Passthrough with ZC
=======================

In order to capture traffic from an Intel/ZC interface using PF_RING ZC 
drivers on a VM, you need to assign the network device to the VM in your 
hypervisor configuring the PCI Passthrough. This is available both on 
QEMU/KVM and VMWare (aka DirectPath I/O).

After following the steps below to configure the passthrough, you should 
be able to see the device on the VM using lspci, and load the native ZC 
driver according to the card model.

PCI Passthrough on QEMU/KVM
---------------------------

In order to assign a network device to a VM with virsh, to be used with native PF_RING ZC drivers, follow the following steps:

Edit /etc/default/grub as below:

.. code-block:: text

   GRUB_CMDLINE_LINUX_DEFAULT="intel_iommu=on"

Update grub:

.. code-block:: console

   update-grub
   reboot

Shutdown the VM (in this example ubuntu16):

.. code-block:: console

   virsh shutdown ubuntu16

Identify the network device to assign:

.. code-block:: console

   lspci -D | grep Ethernet
   0000:02:00.0 Ethernet controller: Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection (rev 01)
   0000:02:00.1 Ethernet controller: Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection (rev 01)

Find the device identifier in virsh (assuming that we want to use 0000:02:00.1):
 
.. code-block:: console

   virsh nodedev-list | grep pci_0000_02_00_1
   pci_0000_02_00_1

Detach the device from the host system:

.. code-block:: console

   virsh nodedev-detach pci_0000_02_00_1

Check that no driver on the host system is using the device:

.. code-block:: console

   readlink /sys/bus/pci/devices/0000\:02\:00.1

Edit the VM configuration adding the hostdev entry:

.. code-block:: text

   virsh edit ubuntu16
   
    <hostdev mode='subsystem' type='pci' managed='no'>
      <source>
        <address domain='0x0000' bus='0x02' slot='0x00' function='0x1'/>
      </source>
    </hostdev>

Start the VM:

.. code-block:: console

   virsh start ubuntu16

Possible Errors
---------------

1. if *virsh start ubuntu16* fails with *vfio: error, group 1 is not viable, please ensure all devices within the iommu_group are bound to their vfio bus driver* 
you probably need to detach all pci devices in the same IOMMU group.
List all the devices in the same group:

.. code-block:: console

   dmesg | grep "group 1$"
   [    0.711256] iommu: Adding device 0000:01:00.0 to group 1
   [    0.711261] iommu: Adding device 0000:02:00.0 to group 1
   [    0.711266] iommu: Adding device 0000:02:00.1 to group 1

Detach all the devices in the group:

.. code-block:: console

   virsh nodedev-detach pci_0000_01_00_0
   virsh nodedev-detach pci_0000_02_00_0

PCI Passthrough on VMWare
-------------------------

In order to configure the PCI Passthrough on VMWare, please refer to the 
VMWare documentation according to your VMWare version looking for DirectPath I/O.
