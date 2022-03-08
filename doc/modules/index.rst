Drivers and Modules
===================

This section contains a description for all the modules and drivers currently available in PF_RING.
Below you can find a comparison of NIC features supported by PF_RING. 

.. toctree::
    :maxdepth: 1
    :numbered:

    af_xdp
    accolade
    dag
    exablaze
    fiberblaze
    intel
    mellanox
    myricom
    napatech
    netcope
    pcap
    stack
    timeline
    sysdig

Supported NICs Comparison
-------------------------

This table below helps you understanding what you can expect when using a given NIC with PF_RING. ntop **does not** endorse any manufacturer (adapters are listed in alphabetical order), so this page is designed to help the reader to select the best NIC/PF_RING comparison for its needs. 

+--------------------------------+----------+--------+----------+------------+---------+----------+----------+
|                                | Accolade | Endace | Exablaze | Fiberblaze |  Intel  | Mellanox | Napatech |
+================================+==========+========+==========+============+=========+==========+==========+
| Max Port Speed (Gbit)          |   100    |   10   |     40   |     100    |   100   |   100    |    100   |
+--------------------------------+----------+--------+----------+------------+---------+----------+----------+
| On-board Memory (*)            |   Yes    |  Yes   |     No   |     Yes    |    No   |    No    |    Yes   |
+--------------------------------+----------+--------+----------+------------+---------+----------+----------+
| Hardware Filtering             |   Yes    |   No   |    Yes   |     Yes    |  ****   |   Yes    |    Yes   |
+--------------------------------+----------+--------+----------+------------+---------+----------+----------+
| Hardware Port Merge            |   Yes    |   No   |     No   |     Yes    |    No   |    No    |    Yes   |
+--------------------------------+----------+--------+----------+------------+---------+----------+----------+
| Hardware Timestamps            |   Yes    |  Yes   |    Yes   |     Yes    |  ****   |   Yes    |    Yes   |
+--------------------------------+----------+--------+----------+------------+---------+----------+----------+
| Pcap Chunk Mode Support (**)   |    No    |   No   |     No   |     Yes    |    No   |    No    |    Yes   |
+--------------------------------+----------+--------+----------+------------+---------+----------+----------+
| Optimized for nProbe           |   Yes    |  Yes   |    Yes   |     Yes    |   Yes   |   ***    |    Yes   |
+--------------------------------+----------+--------+----------+------------+---------+----------+----------+
| nProbe Cento 100Gbit           |   ***    |   No   |     No   |     Yes    |    No   |   Yes    |    Yes   |
+--------------------------------+----------+--------+----------+------------+---------+----------+----------+
| n2disk 1 x 10Gbit Line Rate    |   Yes    |  Yes   |     No   |     Yes    |   Yes   |   Yes    |    Yes   |
+--------------------------------+----------+--------+----------+------------+---------+----------+----------+
| n2disk 2 x 10Gbit Line Rate    |    No    |   No   |     No   |     Yes    |    No   |   ***    |    Yes   |
+--------------------------------+----------+--------+----------+------------+---------+----------+----------+
| n2disk 100Gbit Line Rate       |    No    |   No   |     No   |     Yes    |    No   |    No    |    Yes   |
+--------------------------------+----------+--------+----------+------------+---------+----------+----------+

Note:

* On-board memory helps mitigating traffic spikes/bursts and reduces the probability of packet loss during capture. 
** Pcap chunk mode allows the NIC to deliver many packets in one block to the application, instead of packet-by-packet. Thanks to chunk mode, the application (in particular n2disk) can significantly reduce the CPU load when dumping packets to disk. Please note that in case of index creation while dumping packets, n2disk still needs to iterate packets; even in this case chunk mode can help as it is usually more efficient than packet mode.
*** This needs to be tested or is not applicable due to feature limitation.
**** Supported on some adapters
