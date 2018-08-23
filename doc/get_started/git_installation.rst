Installing from GIT
===================

PF_RING can be downloaded in source format from GIT at https://github.com/ntop/PF_RING/ 
or installed from packages using our repositories at http://packages.ntop.org
In this chapter we cover the installation from source code.

In order to download PF_RING from GIT please clone our repository:

.. code-block:: console

   git clone https://github.com/ntop/PF_RING.git

When you download PF_RING you fetch the following components:

* The PF_RING user-space SDK.
* An enhanced version of the libpcap library that transparently takes advantage of PF_RING if installed, or fallback to the standard behavior if not installed.
* The PF_RING kernel module.
* PF_RING ZC drivers.

Linux Kernel Module Installation
--------------------------------
In order to compile the PF_RING kernel module you need to have the linux kernel headers 
(or kernel source) installed.

.. code-block:: console

   cd <PF_RING PATH>/kernel
   make
   make install

Note that the kernel module installation (via make install) requires root capabilities.

Running PF_RING
---------------
Before using any PF_RING application the pf_ring kernel module should be loaded (as superuser):

.. code-block:: console

   insmod <PF_RING PATH>/kernel/pf_ring.ko [min_num_slots=x][enable_tx_capture=1|0] [ enable_ip_defrag=1|0] [quick_mode=1|0]

Where:

min_num_slots
  Minimum number of ring slots (default – 4096).
enable_tx_capture
  Set to 1 to capture outgoing packets, set to 0 to disable capture outgoing packets (default – RX+TX).
enable_ip_defrag
  Set to 1 to enable IP defragmentation, only rx traffic is defragmented.
quick_mode
  Set to 1 to run at full speed but with up to one socket per interface.

Example:

.. code-block:: console

   cd <PF_RING PATH>/kernel
   insmod pf_ring.ko min_num_slots=8192 enable_tx_capture=0 quick_mode=1

If you want to achieve line-rate packet capture at 10 Gigabit and above, you should use 
ZC drivers. ZC drivers are part of the PF_RING distribution and can be found in drivers/.
Please also read the *PF_RING ZC (Zero Copy)* section.

Libpfring and Libpcap Installation
----------------------------------
Both libpfring (userspace PF_RING library) and libpcap are distributed in source format. They can be compiled as follows:

.. code-block:: console

   cd <PF_RING PATH>/userland/lib
   ./configure
   make
   sudo make install
   cd ../libpcap
   ./configure
   make

Note that:

* the lib is reentrant hence it’s necessary to link your PF_RING-enabled applications also against the -lpthread library.
* Legacy statically-linked pcap-based applications need to be recompiled against the new PF_RING-enabled libpcap.a in order to take advantage of PF_RING. Do not expect to use PF_RING without recompiling your existing application.

Application Examples
--------------------
If you are new to PF_RING, you can start with some examples. The userland/examples folder is rich of ready-to-use PF_RING applications:

.. code-block:: console	

   cd <PF_RING PATH>/userland/examples 
   ls *.c
   alldevs.c      pfcount_82599.c	         pflatency.c  pfwrite.c
   pcap2nspcap.c  pfcount.c	         pfsend.c     preflect.c
   pcount.c       pfcount_multichannel.c    pfsystest.c
   pfbridge.c     pfdump.c		         pfutils.c
   make

For instance, pfcount allows you to receive packets printing some statistics: 

.. code-block:: console

   ./pfcount -i zc:eth1
   ...
   =========================
   Absolute Stats: [64415543 pkts rcvd][0 pkts dropped]
   Total Pkts=64415543/Dropped=0.0 %
   64'415'543 pkts - 5'410'905'612 bytes [4'293'748.94 pkt/sec - 2'885.39 Mbit/sec]
   =========================
   Actual Stats: 14214472 pkts [1'000.03 ms][14'214'017.15 pps/9.55 Gbps]
   =========================

Another example is pfsend, which allows you to send packets (synthetic packets, or optionally a .pcap file can be used) at a specific rate:

.. code-block:: console

   ./pfsend -f 64byte_packets.pcap -n 0 -i zc:eth1 -r 5
   ...
   TX rate: [current 7'508'239.00 pps/5.05 Gbps][average 7'508'239.00 pps/5.05 Gbps][total 7'508'239.00 pkts]

PF_RING Additional Modules
--------------------------
The PF_RING library has a modular architecture, making it possible to use additional 
components other than the standard PF_RING kernel module. These components are 
compiled inside the library according to the supports detected by the configure script. 
PF_RING modules currently include support for Accolade, Endace DAG, Exablaze, Myricom,
Napatech, and others.

