Napatech Support
================

PF_RING has native support for Napatech adapters, the Napatech library
needs to be installed under /opt/napatech3 in order to enable the 
Napatech module at runtime.

Prerequisite
------------

Napatech drivers and SDK installed.

Note: as of PF_RING 6.6 dynamic linking is used and you are able to use
any ntanl driver version.

After installing the Napatech SDK, please make sure the driver is loaded with:

.. code-block:: console

   /opt/napatech3/bin/ntload.sh 
   /opt/napatech3/bin/ntstart.sh 

Installation
------------

In order to get up and running with Napatech when installing from source code,
run the following commands:

.. code-block:: console

   cd PF_RING/kernel && make && sudo insmod pf_ring.ko
   cd ../userland/lib && ./configure && make
   cd ../libpcap && ./configure && make
   cd ../examples && make
   sudo ./pfcount -i nt:0

Please note that:

- installing from repository, all applications are already compiled with Napatech support

- in order to open a port from the Napatech adapter you should specify nt:<PORT>, example:

.. code-block:: console

   pfcount -i nt:0

- in order to open a stream you should specify nt:stream<ID>, example:

.. code-block:: console

   pfcount -i nt:stream0

- streams are logical port aggregations or packet spread (similar to RSS) can be created using the ntpl tool (ntpl -e "<command>")

Command example for ports (2 and 3) aggregation on a single stream (1):

.. code-block:: console

   /opt/napatech3/bin/ntpl -e "Delete = All"
   /opt/napatech3/bin/ntpl -e "Assign[streamid=1] = port == 2,3"

Command example for load balancing of all ports across 16 streams:

.. code-block:: console

   /opt/napatech3/bin/ntpl -e "Delete = All"
   /opt/napatech3/bin/ntpl -e "HashMode = Hash2TupleSorted"
   /opt/napatech3/bin/ntpl -e "Assign[StreamId=(0..15)] = All"

Command example for load balancing port 0 across 4 streams:

.. code-block:: console

   /opt/napatech3/bin/ntpl -e "Delete = All"
   /opt/napatech3/bin/ntpl -e "HashMode = Hash2TupleSorted"
   /opt/napatech3/bin/ntpl -e "Assign[StreamId=(0..3)] = port == 0"

Command example for merging two ports and load balancing them across 24 streams where the first 12 streams are bond on node 0 and the remaining 12 on numa node 1

.. code-block:: console

   /opt/napatech3/bin/ntpl -e "Delete=All"
   /opt/napatech3/bin/ntpl -e "HashMode = Hash5TupleSorted"
   /opt/napatech3/bin/ntpl -e "Setup[NUMANode=0]=Streamid==(0..11)"
   /opt/napatech3/bin/ntpl -e "Setup[NUMANode=1]=Streamid==(12..23)"
   /opt/napatech3/bin/ntpl -e "Assign[streamid=(0..23)]=port==0,1"

- in order to use the Napatech adapter with n2disk the configuration file /opt/napatech3/config/ntservice.ini should contain:

.. code-block:: text

   TimestampFormat = PCAP_NS
   PacketDescriptor = PCAP
   HostBufferSegmentSizeRx = 4

Napatech and Packet Copy
------------------------

If you use the PF_RING (non-ZC) API packets are read in zero-copy. Instead
if you use PF_RING ZC API, a per-packet copy takes place, which is required to move
payload data from Napatech-memory to ZC memory. Keep this in mind!

Transmission Support
--------------------

In order to use Napatech in transmission you need to make sure you have
configured TX properly. Edit /opt/napatech3/config/ntservice.ini and
make sure you have the following sections configured

.. code-block:: text

   [Adapter0]
   ..
   HostBuffersTx = [4,16,0]
   ..

[Debug]
RntcTxEnable=1

Hardware Filtering
------------------

Napatech NICs support full-blown hardware filtering  out of the box. Thanks
to nBPF we convert BPF expressions to hardware filters. This feature is
supported transparently, and thus all PF_RING/libpcap-over-PF_RING can benefit
from it.

Example: 

.. code-block:: console

   pfcount -i nt:3 -f "tcp and port 80 and src host 192.168.1.1"

As Napatech hardware filters are very advanced, filtering happens all in hardware.

