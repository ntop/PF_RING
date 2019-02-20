PF_RING ZC (Zero Copy)
======================

PF_RING can work both on top of standard NIC drivers or on top of specialised drivers. 
The PF_RING kernel module is the same, but based on the drivers being used some 
functionality and performance are different.
For those users who need maximum packet capture speed with 0% CPU utilisation for 
copying packets to the host (i.e. the NAPI polling mechanism is not used) it is possible 
to use ZC (aka new generation DNA) drivers, that allow packets to be read directly from 
the network interface by simultaneously bypassing both the Linux kernel and the PF_RING 
module in a zero-copy fashion.

In ZC both RX and TX operations are supported. As the kernel is bypassed, some PF_RING 
functionality are missing, including in kernel packet filtering (BPF and PF_RING filters).

With PF_RING ZC you can achieve 1/10G wire-rate at any packet size and create 
inter-process and inter-VM clusters (PF_RING ZC is not just a driver, it provides a 
simple yet powerful API). It can be considered as the successor of DNA/LibZero
that offers a single and consistent API based on the lessons learnt on the past 
few years.

Sample applications for testing are available in userland/examples_zc.

These drivers, available in PF_RING/drivers/, are standard drivers with support for the 
PF_RING ZC library. They can be used as standard kernel drivers or in zero-copy 
kernel-bypass mode (using the PF_RING ZC library) adding the prefix "zc:" to the interface
name. 
Once installed, the drivers operate as standard Linux drivers where you can do normal 
networking (e.g. ping or SSH). If you open a device in zero copy using the "zc:" prefix 
the device becomes unavailable to standard networking as it is accessed in zero-copy 
through kernel bypass, as happened with the predecessor DNA. Once the application 
accessing the device is closed, standard networking activities can take place again. 
An interface in ZC mode provides the same performance as DNA.

Example:

.. code-block:: console

   sudo pfcount -i zc:eth0

Note: if you omit 'zc:' you will open the device in standard PF_RING kernel mode (no ZC 
acceleration).

Supported Cards
---------------

In order to exploit ZC, you need a PF_RING aware driver with ZC support, identified by 
the '-zc' suffix. Three driver families are currently available:

- 1 Gbit

  - e1000e (RX and TX)
     - Supported cards: Intel 8254x/8256x/82571/82572/82573/82574/82583
  - igb    (RX and TX)
     - Supported cards: Intel 82575/82576/82580/I210/I350

- 10 Gbit

  - ixgbe/ixgbevf (RX and TX)
     - Supported cards: Intel 82599/X520/X540/X55x

- 10/40 Gbit

  - i40e (RX and TX)
     - Supported cards: Intel X710/XL710

- 10/40/100 Gbit

  - fm10k (RX and TX)
     - Supported cards: FM10420

These drivers can be found in drivers/

Please note that:

* in order to correctly configure the device, it is highly recommended to use systemd
creating a configuration as explained in the `Installing from packages <http://www.ntop.org/guides/pf_ring/get_started/packages_installation.html>`_ section,
or use the *load_driver.sh* script provided with the drivers as explained in the 
`Installing from GIT <http://www.ntop.org/guides/pf_ring/get_started/git_installation.html>`_ section.
* the PF_RING kernel module must be loaded before the ZC driver (systemd and load_driver.sh takes care of this)
* ZC drivers need hugepages (the load_driver.sh script takes care of hugepages configuration). For more informations please read the `Hugepages Support <http://www.ntop.org/guides/pf_ring/hugepages.html>`_ section.

ZC API
------

PF_RING ZC (Zero Copy) is a flexible packet processing framework that allows you to 
achieve 1/10 Gbit line-rate packet processing (both RX and TX) at any packet size. 
It implements zero-copy operations including patterns for inter-process and inter-VM (KVM) 
communications. It can be considered as the successor of DNA/LibZero that offers a single 
and consistent API implementing simple building blocks (queue, worker and pool) that can 
be used from threads, applications and virtual machines.

The following example shows how to create an aggregator+balancer application in 6 lines of code.

.. code-block:: console

   zc = pfring_zc_create_cluster(ID, MTU, MAX_BUFFERS, NULL);
   for (i = 0; i < num_devices; i++)
     inzq[i] = pfring_zc_open_device(zc, devices[i], rx_only);
   for (i = 0; i < num_slaves; i++)
     outzq[i] = pfring_zc_create_queue(zc, QUEUE_LEN);
   zw = pfring_zc_run_balancer(inzq, outzq, num_devices, num_slaves, NULL, NULL, !wait_for_packet, core_id);

PF_RING ZC allows you to forward (both RX and TX) packets in zero-copy for a KVM 
Virtual Machine without using techniques such as PCIe passthrough. Thanks to the 
dynamic creation of ZC devices on VMs, you can capture/send traffic in zero-copy 
from your VM without having to patch the KVM code, or start KVM after your ZC 
devices have been created. In essence now you can do 10 Gbit line rate to your 
KVM using the same command you would use on a physical host, without changing a 
single line of code.

In PF_RING ZC you can use the zero-copy framework even with non-PF_RING-aware drivers. 
This means that you can dispatch, process, originate, and inject packets into the 
zero-copy framework even though they have not been originated from ZC devices. 
Once the packet has been copied (one-copy) to the ZC world, from then onwards the 
packet will always be processed in zero-copy during all his lifetime. For instance the 
zbalance_ipc demo application can read packet in 1-copy mode from a non-PF_RING aware 
device (e.g. a WiFI-device or a Broadcom NIC) and send them inside ZC for performing 
zero-copy operations with them.

