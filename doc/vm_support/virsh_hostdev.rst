PCI Passthrough with ZC on QEMU/KVM
===================================

In order to assign a network device to a VM with virsh, to be used with native PF_RING ZC drivers, follow the following steps:

Edit /etc/default/grub as below:

.. code-block:: text

   GRUB_CMDLINE_LINUX_DEFAULT="intel_iommu=on"

Update grub:

.. code-block:: text

   update-grub
   reboot

Shutdown the VM (in this example ubuntu14):

.. code-block:: text

   virsh shutdown ubuntu14

Identify the network device to assign:

.. code-block:: text

   lspci -D | grep Ethernet
   0000:02:00.0 Ethernet controller: Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection (rev 01)
   0000:02:00.1 Ethernet controller: Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection (rev 01) <-

Find the device identifier in virsh:
 
.. code-block:: text

   virsh nodedev-list | grep pci_0000_02_00_1
   pci_0000_02_00_1

Detach the device from the host system:

.. code-block:: text

   virsh nodedev-detach pci_0000_02_00_1

Check that no driver on the host system is using the device:

.. code-block:: text

   readlink /sys/bus/pci/devices/0000\:02\:00.1

Edit the VM configuration adding the hostdev entry:

.. code-block:: text

   virsh edit ubuntu14
   
    <hostdev mode='subsystem' type='pci' managed='no'>
      <source>
        <address domain='0x0000' bus='0x02' slot='0x00' function='0x1'/>
      </source>
    </hostdev>

Start the VM:

.. code-block:: text

   virsh start ubuntu14

At this point you should be able to see the device on the VM using lspci, and load the ZC driver according to the card model.

