Installing from GIT
===================

PF_RING can be downloaded in source format from GIT at https://github.com/ntop/PF_RING/ 
or installed from packages using our repositories at http://packages.ntop.org as described in the 
`Installing From Packages <http://www.ntop.org/guides/pf_ring/get_started/packages_installation.html>`_ 
section. In this chapter we cover the installation from source code.

Clone our repository to download the PF_RING source code: 

.. code-block:: console

   git clone https://github.com/ntop/PF_RING.git

The PF_RING source code includes:

* The user-space SDK.
* An enhanced version of libpcap that transparently takes advantage of PF_RING.
* The PF_RING kernel module.
* PF_RING ZC drivers.

Kernel Module Installation
--------------------------

In order to compile the PF_RING kernel module you need to have the linux kernel headers 
(or kernel source) installed.

.. code-block:: console

   cd PF_RING/kernel
   make
   sudo make install

Running PF_RING
---------------

Before using any PF_RING application, the pf_ring kernel module should be loaded:

.. code-block:: console

   cd PF_RING/kernel
   sudo insmod ./pf_ring.ko [min_num_slots=N] [enable_tx_capture=1|0] [ enable_ip_defrag=1|0]

Where:

min_num_slots
  Minimum number of packets the kernel module should be able to enqueue (default – 4096).
enable_tx_capture
  Set to 1 to capture outgoing packets, set to 0 to disable capture outgoing packets (default – RX+TX).
enable_ip_defrag
  Set to 1 to enable IP defragmentation, only RX traffic is defragmented (default – disabled)

Example:

.. code-block:: console

   cd PF_RING/kernel
   sudo insmod pf_ring.ko min_num_slots=65536 enable_tx_capture=0

Drivers
-------

If you want to achieve line-rate packet capture at 10 Gigabit and above on Intel adapters, 
you should use `ZC drivers <http://www.ntop.org/guides/pf_ring/zc.html>`_. You can check 
the driver family using ethtool:

.. code-block:: console

   ethtool -i eth1 | grep driver
   driver: ixgbe

and load the corresponding driver using the *load_driver.sh* script in the driver folder:

.. code-block:: console

   cd PF_RING/drivers/intel
   make
   cd ixgbe/ixgbe-*-zc/src
   sudo ./load_driver.sh

Libpfring and Libpcap Installation
----------------------------------

Both libpfring (userspace PF_RING library) and libpcap are distributed in source format. 
They can be compiled and installed as follows:

.. code-block:: console

   cd PF_RING/userland/lib
   ./configure && make
   sudo make install
   cd ../libpcap
   ./configure && make
   sudo make install

Note that legacy statically-linked pcap-based applications need to be recompiled against 
the new PF_RING-enabled libpcap.a in order to take advantage of PF_RING. Do not expect to 
use PF_RING without recompiling your existing application in this case.

Application Examples
--------------------

If you are new to PF_RING, you can start with some examples. The userland/examples folder 
is rich of ready-to-use PF_RING applications:

.. code-block:: console	

   cd PF_RING/userland/examples 
   make

For instance, pfcount allows you to receive packets printing some statistics: 

.. code-block:: console

   sudo ./pfcount -i zc:eth1
   ...
   =========================
   Absolute Stats: [64415543 pkts rcvd][0 pkts dropped]
   Total Pkts=64415543/Dropped=0.0 %
   64'415'543 pkts - 5'410'905'612 bytes [4'293'748.94 pkt/sec - 2'885.39 Mbit/sec]
   =========================
   Actual Stats: 14214472 pkts [1'000.03 ms][14'214'017.15 pps/9.55 Gbps]
   =========================

Another example is pfsend, which allows you to send packets (synthetic packets, 
or optionally a *pcap* file) at an arbitrary rate:

.. code-block:: console

   sudo ./pfsend -f 64byte_packets.pcap -n 0 -i zc:eth1 -r 5
   ...
   TX rate: [current 7'508'239.00 pps/5.05 Gbps][average 7'508'239.00 pps/5.05 Gbps][total 7'508'239.00 pkts]

PF_RING Additional Modules
--------------------------

The PF_RING library has a modular architecture, making it possible to use additional 
capture modules other than the standard PF_RING kernel module. These components are 
enabled at runtime based on the actual adapter being used. PF_RING modules currently 
include support for Accolade, Endace DAG, Exablaze, Fiberblaze, Myricom, Napatech, 
and others, please also read the `Drivers and Modules <http://www.ntop.org/guides/pf_ring/modules/index.html>`_
section.

