Sample Applications
===================

If you are new to PF_RING, you can start with some examples. The *PF_RING/userland* 
folder is rich of ready-to-use PF_RING applications. They are small standalone applications 
which demonstrate various features of PF_RING. Users interested in getting started with 
PF_RING can test the applications and extend them based on their needs.

- *PF_RING/userland/examples* contains sample application using the PF_RING API
- *PF_RING/userland/examples_zc* contains sample application using the PF_RING ZC API
- *PF_RING/userland/examples_ft* contains sample application using the PF_RING FT API

Please note that the applications features many options to try to cover all use cases,
please check the help (-h) for a full list of options.

Compiling the Applications
--------------------------

To compile the sample application see the `Installing From GIT <https://www.ntop.org/guides/pf_ring/get_started/git_installation.html#libpfring-and-libpcap-installation>`_
section. Please note that if you are installing PF_RING from packages, some of the
sample applications described here are also distributed in binary format with the
*pfring* package.

Basic Packet Capture
--------------------

**pfcount** (in *PF_RING/userland/examples*) is a sample application that allows you 
to capture raw packets and print some statistics. Example:

.. code-block:: console

   sudo ./pfcount -i zc:eth1
   =========================
   Absolute Stats: [64415543 pkts rcvd][0 pkts dropped]
   Total Pkts=64415543/Dropped=0.0 %
   64'415'543 pkts - 5'410'905'612 bytes [4'293'748.94 pkt/sec - 2'885.39 Mbit/sec]
   =========================
   Actual Stats: 14214472 pkts [1'000.03 ms][14'214'017.15 pps/9.55 Gbps]
   =========================

The same application can also be used to parse packets and extract metadata from L2/L3/L4
headers, adding the -v option. Example:

.. code-block:: console

   sudo ./pfcount -i eth1 -v 1
   Dumping statistics on /proc/net/pf_ring/stats/15773-eno1.279
   11:31:41.968485349 [TX][if_index=6][hash=2169540001][00:26:90:D3:CC:F1 -> 0C:C7:7A:CC:C1:4D] [IPv4][192.168.1.20:22 -> 192.168.1.21:34762] [l3_proto=TCP][hash=2169540001][tos=16][tcp_seq_num=415123802] [caplen=254][len=254][eth_offset=0][l3_offset=14][l4_offset=34][payload_offset=66]
   11:31:41.968557503 [TX][if_index=6][hash=2169540001][00:26:90:D3:CC:F1 -> 0C:C7:7A:CC:C1:4D] [IPv4][192.168.1.20:22 -> 192.168.1.21:34762] [l3_proto=TCP][hash=2169540001][tos=16][tcp_seq_num=415123990] [caplen=166][len=166][eth_offset=0][l3_offset=14][l4_offset=34][payload_offset=66]
   11:31:41.968598956 [TX][if_index=6][hash=2169540001][00:26:90:D3:CC:F1 -> 0C:C7:7A:CC:C1:4D] [IPv4][192.168.1.20:22 -> 192.168.1.21:34762] [l3_proto=TCP][hash=2169540001][tos=16][tcp_seq_num=415124090] [caplen=390][len=390][eth_offset=0][l3_offset=14][l4_offset=34][payload_offset=66]

**zcount** (in *PF_RING/userland/examples_zc*) is similar to **pfcount**, however
it is based on the PF_RING ZC API. Example:

.. code-block:: console

   sudo ./zcount -i zc:eth1 -c 10
   =========================
   Absolute Stats: 89415341 pkts (0 drops) - 7510888644 bytes
   Actual Stats: 14'218'113.27 pps (0.00 drops) - 9.55 Gbps
   =========================

Where:

- The interface specified with -i can be any interface (in the example above we are using a ZC driver)
- The number specified with -c is the cluster ID (the ZC API requires a unique identifier to identify a cluster instance)

Basic Packet Transmission
-------------------------

**pfsend** (in *PF_RING/userland/examples*) allows you to generate traffic, forging synthetic 
packets or replaying a *pcap* file.
By default packets are transmitted at the maximum rate supported by the driver, however it is 
possible to use -p <pps> or -r <Gbps> to control the tramsission rate. It is also possible to 
specify the number of packets to send with -n <num>. 

Example with synthetic traffic on a standard interface:

.. code-block:: console

   sudo ./pfsend -i eth1
   TX rate: [current 1'275'650.89 pps/0.86 Gbps][average 1'275'650.89 pps/0.86 Gbps][total 1'275'656.00 pkts]

Useful options:

- -l <length> to specify the packets length
- -n <num> to stop the transmission after <num> packets
- -r <gbps> to specify the transmission rate (Gbit/s)
- -p <pps rate> to specify the transmission rate (Packets/s)
- -M <mac> to specify the source MAC address
- -m <mac> to specify the destination MAC address
- -b <num> specifies the number of different source IPs to be generated
- -S <ip> to specify the source IP
- -D <ip> to specify the destination IP
- -V <version> to specify the IP version (default: 4)
- -L <num> to add a VLAN header (generate <num> different VLAN IDs)

Example replaying a pcap file on a ZC interface, controlling the rate (5 Gbps), sending in loop (-n 0):
 
.. code-block:: console

   sudo ./pfsend -i zc:eth1 -f 64byte_packets.pcap -n 0 -r 5
   TX rate: [current 7'508'239.00 pps/5.05 Gbps][average 7'508'239.00 pps/5.05 Gbps][total 7'508'239.00 pkts]
   
**zsend** (in *PF_RING/userland/examples_zc*) is similar to **pfsend**, however
it is based on the PF_RING ZC API. Example:

.. code-block:: console

   sudo ./zsend -i eth1 -c 10
   =========================
   Absolute Stats: 2'604'538 pkts - 218'781'192 bytes
   Actual Stats: 1'305'510.19 pps - 0.88 Gbps [109672836 bytes / 1.0 sec]
   =========================

Where:

- The interface specified with -i can be any interface (in the example above we are using a standard kernel driver)
- The number specified with -c is the cluster ID (the ZC API requires a unique identifier to identify a cluster instance)

Basic Packet Forwarding
-----------------------

**zbounce** (in *PF_RING/userland/examples_zc*) bridges traffic between an interface pair as a
bump in the wire.

Example:

.. code-block:: console

   sudo ./zbounce -i zc:eth1 -o zc:eth2 -c 10 -b -g 1:2
   =========================
   Absolute Stats: 360 pkts (0 drops) - 57'340 bytes
   Actual Stats: 57.00 pps (0.00 drops) - 0.00 Gbps
   =========================

Where:

- The number specified with -c is the cluster ID (the ZC API requires a unique identifier to identify a cluster instance)
- -b specifies that we want to forward traffic in both directions (otherwise it will forward -i to -o only)
- This sample application uses 1 thread per direction, thus -g requires 2 cores to set the CPU affinity for both threads

Load Balancing
--------------

Multi-Threaded
~~~~~~~~~~~~~~

**zbalance** (in *PF_RING/userland/examples_zc*) is a sample application able to capture traffic
from one or multiple interfaces, and load-balance packets to multiple consumer threads.

.. code-block:: console

   sudo ./zbalance -i eno1 -c 10 -m 1 -r 0 -g 1:2
   Starting balancer with 2 consumer threads..
   =========================
   Thread #0: 17 pkts - 2'723 bytes
   Thread #1: 19 pkts - 3'011 bytes
   =========================
   Absolute Stats: 36 pkts - 5'734 bytes
   Actual Stats: 15.00 pps - 0.00 Gbps
   =========================

Where:

- The interface specified with -i can be a comma-separated list of interfaces
- The number specified with -c is the cluster ID (the ZC API requires a unique identifier to identify a cluster instance)
- With -m it is possible to select the hash function for traffic distribution across threads (please see the help with -h for the list). There are a few built-in options, but it is also possible to define custom distribution functions (please see **zbalance_ipc** for more distribution functions examples)
- The -r option selects the CPU core where the load-balancer thread will be running
- The -g option selects the CPU cores where the consumer threads will be running (as many threads as the number of cores)

Multi-Process
~~~~~~~~~~~~~

**zbalance_ipc** (in *PF_RING/userland/examples_zc*) is a sample application that can be used 
for capturing traffic from one or multiple interfaces, and load-balance packets to multiple consumer 
processes. Please read the `ZC Load-Balancing <https://www.ntop.org/guides/pf_ring/rss.html#zc-load-balancing-zbalance-ipc>`_ 
section to learn more about multi-process load-balancing and this application.

Simple example of traffic aggregation from 2 interfaces, and load-balancing to 2 processes using an IP-based hash:

.. code-block:: console

   zbalance_ipc -i zc:eth1,zc:eth2 -n 2 -m 1 -c 10

Where:
   
- -n specifies the number of egress queues
- -m selects the hash function
- -c specifies the ZC cluster ID

This simple example creates 2 streams. In order to capture traffic from those streams it is possible to use both the standard PF_RING API or the ZC API. 
A consumer application using the standard PF_RING API is able to open each stream as a standard interface passing as name zc:<cluster ID>@<queue ID> (e.g. zc:10@0 and zc:10@1) to the *pfring_open* API. Example with pfcount:

.. code-block:: console

   pfcount -i zc:10@0
   pfcount -i zc:10@1

A consumer application using the ZC API, in order to fully take advantage of the flexible ZC API and work in zero-copy, can open each stream attaching to the queue ID directly through the *pfring_zc_ipc_attach_queue* API. Example with zcount_ipc:

.. code-block:: console

   zcount_ipc -c 10 -i 0
   zcount_ipc -c 10 -i 0

Where:

- -c <id> is the cluster ID specified in zbalance_ipc
- -i <id> is the queue ID

Divide and Conquer
------------------

**zbalance_DC_ipc** (in *PF_RING/userland/examples_zc*) is a sample application able to capture traffic
from multiple interfaces or RSS queues, filter traffic using multiple capture threads, aggregate filtered 
traffic from all interfaces in a single stream, and load-balance packets to multiple consumer processes.

.. code-block:: text

   eth1 \ 
   eth2 - (Filtering Thread 0) \                                    / (Consumer Process 0) 
                                 (FIFO Thread) - (Collector Thread) - (Consumer Process 1) 
   eth2 - (Filtering Thread 1) /                                    \ (Consumer Process 2) 
   eth3 / 

Example capturing traffic from 4 interfaces, using 2 capture/filtering threads, and forwarding load-balanced 
traffic to 3 consumer applications:

.. code-block:: console

   sudo ./zbalance -i zc:eth1,zc:eth2 -i zc:eth2,zc:eth3 -c 10 -m 1 -g 0:1 -r 2 -n 3
   Run your consumers as follows:
	   pfcount -i zc:10@0
	   pfcount -i zc:10@1
	   pfcount -i zc:10@2
   =========================
   Absolute Stats: Recv 534 pkts (0 drops) - Forwarded 534 pkts (0 drops)
   Actual Stats: Recv 211.00 pps (0.00 drops) - Forwarded 211.00 pps (0.00 drops)
   =========================

L7 Flow Classification
----------------------

**ftflow** (in *PF_RING/userland/examples_ft*) is a sample application based on the PF_RING FT API
able to classify traffic up to layer 7. This can also be extended to filter traffic based on the 
application protocol leveraging on the filtering/shunting capabilities of the PF_RING FT API. 
The application prints flows information as soon as flows expire (or terminating the application
in case of active flows). Example:

.. code-block:: console

   sudo ./ftflow -i eno1 -7
   [Flow] l7: SSH, category: 12, srcIp: 192.168.1.222, dstIp: 192.168.1.221, srcPort: 22, dstPort: 34900, protocol: 6, tcpFlags: 0x18, c2s: { Packets: 1, Bytes: 174, First: 1546590146.892275, Last: 1546590146.892275 }, s2c: { Packets: 2, Bytes: 168, First: 1546590146.892518, Last: 1546590150.675197 }, action: default
   [Flow] l7: DHCP, category: 14, srcIp: 0.0.0.0, dstIp: 255.255.255.255, srcPort: 68, dstPort: 67, protocol: 17, tcpFlags: 0x00, c2s: { Packets: 2, Bytes: 684, First: 1546590147.30906, Last: 1546590150.130988 }, s2c: { Packets: 0, Bytes: 0, First: 0.0, Last: 0.0 }, action: default
   [Flow] l7: sFlow, category: 14, srcIp: 192.168.1.222, dstIp: 192.168.1.225, srcPort: 47472, dstPort: 6343, protocol: 17, tcpFlags: 0x00, c2s: { Packets: 2, Bytes: 456, First: 1546590147.324577, Last: 1546590149.308650 }, s2c: { Packets: 0, Bytes: 0, First: 0.0, Last: 0.0 }, action: default
   [Flow] l7: DNS, category: 14, srcIp: 192.168.1.222, dstIp: 8.8.8.8, srcPort: 55522, dstPort: 53, protocol: 17, tcpFlags: 0x00, c2s: { Packets: 1, Bytes: 86, First: 1546590149.13028, Last: 1546590149.13028 }, s2c: { Packets: 1, Bytes: 86, First: 1546590149.30081, Last: 1546590149.30081 }, action: default

Where:

- -7 enables L7 protocol detection through nDPI as described in the `PF_RING FT - nDPI Integration <http://www.ntop.org/guides/pf_ring/ft.html#ndpi-integration>`_ section
- -F <file> loads filtering/shunting rules from a configuration file (see the `L7 Filtering and Shunting <http://www.ntop.org/guides/pf_ring/ft.html#l7-filtering-and-shunting>`_ section)
- -p <file> loads custom protocols to nDPI from a configuration file (see the `example <https://github.com/ntop/nDPI/blob/dev/example/protos.txt>`_)
- -c <file> loads custom categories to nDPI from a configuration file (see the `example <https://github.com/ntop/nDPI/blob/dev/example/mining_hosts.txt>`_)

For further information please read the introduction to `PF_RING FT <http://www.ntop.org/guides/pf_ring/ft.html#api-overview>`_ and the `API documentation <https://www.ntop.org/guides/pf_ring_api/pfring__ft_8h.html>`_.
