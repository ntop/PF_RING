Drivers and Modules
===================

This section contains a description for all the modules and drivers currently available in PF_RING.
Below you can find a comparison of NIC features supported by PF_RING. 

.. toctree::
    :maxdepth: 1
    :numbered:

    af_xdp
    fiberblaze
    intel
    mellanox
    napatech
    pcap
    stack
    timeline
    sysdig

Supported NICs Comparison
-------------------------

This table below helps you understanding what you can expect when using a given NIC with PF_RING. ntop **does not** endorse any manufacturer (adapters are listed in alphabetical order), so this page is designed to help the reader to select the best NIC/PF_RING comparison for its needs. 

+--------------------------------+------------+-----------+-----------+-----------+
|                                | Fiberblaze |   Intel   |  Mellanox |  Napatech |
+================================+============+===========+===========+===========+
| Status                         | Supported  | Supported | Supported | Supported |
+--------------------------------+------------+-----------+-----------+-----------+
| Max Port Speed (Gbit)          |     100    |    100    |    100    |    100    |
+--------------------------------+------------+-----------+-----------+-----------+
| On-board Memory (*)            |     Yes    |     No    |     No    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| Hardware Filtering             |     Yes    |   \*\*\*\*    |    Yes    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| Hardware Port Merge            |     Yes    |     No    |     No    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| Hardware Timestamps            |     Yes    |   \*\*\*\*    |    Yes    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| Pcap Chunk Mode Support (\*\*)   |     Yes    |     No    |     No    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| Optimized for nProbe           |     Yes    |    Yes    |    \*\*\*    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| nProbe Cento 100Gbit           |     Yes    |     No    |    Yes    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| n2disk 1 x 10Gbit Line Rate    |     Yes    |    Yes    |    Yes    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| n2disk 2 x 10Gbit Line Rate    |     Yes    |     No    |    \*\*\*    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| n2disk 100Gbit Line Rate       |     Yes    |     No    |     No    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+

Note:

\* On-board memory helps mitigating traffic spikes/bursts and reduces the probability of packet loss during capture. 
\*\* Pcap chunk mode allows the NIC to deliver many packets in one block to the application, instead of packet-by-packet. Thanks to chunk mode, the application (in particular n2disk) can significantly reduce the CPU load when dumping packets to disk. Please note that in case of index creation while dumping packets, n2disk still needs to iterate packets; even in this case chunk mode can help as it is usually more efficient than packet mode.
\*\*\* This needs to be tested or it is not applicable due to feature limitation.
\*\*\*\* Supported on some adapters
