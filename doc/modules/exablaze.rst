Exablaze support
================

Prerequisites
-------------

We expect you to have installed the ExaNIC drivers (v. 1.7 or later) and loaded the drivers.

Usage
-----

Using the exanic-config tool, you can see how the NIC has been mapped by Linux to the device name

.. code-block:: console

   exanic-config 
   Device exanic0:
     Hardware type: ExaNIC X10
     Board ID: 0x00
     Temperature: 50.4 C   VCCint: 0.94 V   VCCaux: 1.79 V
     Function: network interface
     Firmware date: 20160420 (Wed Apr 20 00:34:19 2016)
     Port 0:
       Interface: enp6s0
       Port speed: 10000 Mbps
       Port status: enabled, SFP present, signal detected, link active
       MAC filters: 64  IP filters: 128
       Promiscuous mode: off
       Bypass-only mode: off
       MAC address: 64:3f:5f:01:2f:6a
       RX packets: 2151761082  ignored: 2048817419  error: 0  dropped: 0
       TX packets: 293756031
     Port 1:
       Interface: enp6s0d1
       Port speed: 10000 Mbps
       Port status: enabled, SFP present, signal detected, link active
       MAC filters: 64  IP filters: 128
       Promiscuous mode: off
       Bypass-only mode: off
       MAC address: 64:3f:5f:01:2f:6b
       RX packets: 27  ignored: 0  error: 0  dropped: 0
       TX packets: 8

.. code-block:: console

   ifconfig enp6s0
   enp6s0    Link encap:Ethernet  HWaddr 64:3f:5f:01:2f:6a  
             inet6 addr: fe80::663f:5fff:fe01:2f6a/64 Scope:Link
             UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
             RX packets:102941282 errors:0 dropped:0 overruns:0 frame:0
             TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
             collisions:0 txqueuelen:1000 
             RX bytes:6588303265 (6.5 GB)  TX bytes:648 (648.0 B)

.. code-block:: console

   ifconfig enp6s0d1
   enp6s0d1  Link encap:Ethernet  HWaddr 64:3f:5f:01:2f:6b  
             inet6 addr: fe80::663f:5fff:fe01:2f6b/64 Scope:Link
             UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
             RX packets:27 errors:0 dropped:0 overruns:0 frame:0
             TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
             collisions:0 txqueuelen:1000 
             RX bytes:2290 (2.2 KB)  TX bytes:648 (648.0 B)

You can now start the PF_RING apps prepending "exanic:" to the interface name.
Example:

.. code-block:: console

   pfsend -i exanic:enp6s0

.. code-block:: console

   pfcount -i exanic:enp6s0@1

Where @1 means connect the application to RSS queue 1

Hardware Filtering
------------------

Exablaze NICs support (limited, e.g. IPv6 is not supported) hardware filtering
out of the box. Thanks to nBPF we convert BPF expressions to hardware filters.
This feature is supported transparently, and thus all PF_RING/libpcap-over-PF_RING
can benefit from it.

Example: 

.. code-block:: console

   pfcount -i exanic:enp6s0d4 -f "udp and port 3001"

When a BPF filter cannot be mapped 1:1 to a hardware filter, software packet
filtering will take place to guarantee that the specified filter is enforced.
