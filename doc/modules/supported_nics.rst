Supported NICs Comparison
-------------------------

Below you can find a comparison of NIC features supported by PF_RING.

This table below helps you understanding what you can expect when using a given NIC with PF_RING. ntop **does not** endorse any manufacturer (adapters are listed in alphabetical order), so this page is designed to help the reader to select the best NIC/PF_RING comparison for its needs. 

+--------------------------------+------------+-----------+-----------+-----------+
|                                | Fiberblaze |   Intel   |   NVIDIA  |  Napatech |
+================================+============+===========+===========+===========+
| Status                         | Supported  | Supported | Supported | Supported |
+--------------------------------+------------+-----------+-----------+-----------+
| Max Port Speed (Gbit)          |     100    |    100    |    100    |    100    |
+--------------------------------+------------+-----------+-----------+-----------+
| On-board Memory (1)            |     Yes    |     No    |     No    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| Hardware Filtering             |     Yes    |    (4)    |    Yes    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| Hardware Port Merge            |     Yes    |     No    |     No    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| Hardware Timestamps            |     Yes    |    (4)    |    Yes    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| Pcap Chunk Mode Support (2)    |     Yes    |     No    |     No    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| Optimized for nProbe           |     Yes    |    Yes    |    (3)    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| nProbe Cento 100Gbit           |     Yes    |     No    |    Yes    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| n2disk 1 x 10Gbit Line Rate    |     Yes    |    Yes    |    Yes    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| n2disk 2 x 10Gbit Line Rate    |     Yes    |     No    |    (3)    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+
| n2disk 100Gbit Line Rate       |     Yes    |     No    |     No    |    Yes    |
+--------------------------------+------------+-----------+-----------+-----------+

Note:

(1) On-board memory helps mitigating traffic spikes/bursts and reduces the probability of packet loss during capture. 
(2) Pcap chunk mode allows the NIC to deliver many packets in one block to the application, instead of packet-by-packet. Thanks to chunk mode, the application (in particular n2disk) can significantly reduce the CPU load when dumping packets to disk. Please note that in case of index creation while dumping packets, n2disk still needs to iterate packets; even in this case chunk mode can help as it is usually more efficient than packet mode.
(3) This needs to be tested or it is not applicable due to feature limitation.
(4) Supported on some adapters

.. list-table:: Intel Adapters Compatibility
   :widths: 25 15 15 15 15 15
   :header-rows: 1

   * - 
     - e1000e
     - igb
     - ixgbe
     - i40e
     - ice
   * - Link Speed
     - 1 Gbit
     - 1 Gbit
     - 1/10 Gbit
     - 10/40 Gbit
     - 10/25/50/100 Gbit
   * - Supported Cards
     - Intel 8254x/8256x/  
       8257x/8258x
     - Intel 82575/82576/  
       82580/I350
     - Intel 82599/X520/  
       X540/X550
     - Intel X710/XL710
     - Intel E810
   * - Operating System
     - Linux (kernel 2.6.32 or better)
     - Linux (kernel 2.6.32 or better)
     - Linux (kernel 2.6.32 or better)
     - Linux (kernel 2.6.32 or better)
     - Linux (kernel 2.6.32 or better)
   * - Traffic Reception
     - ✓
     - ✓
     - ✓
     - ✓
     - ✓
   * - Traffic Injection
     - ✓
     - ✓
     - ✓
     - ✓
     - ✓
   * - Hw packet filtering
     - 
     - 
     - Intel 82599 only
     - 
     - 
   * - Hw timestamping (nsec)
     - 
     - Intel 82580/I350 only
     - 
     - 
     - 
