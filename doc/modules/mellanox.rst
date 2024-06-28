NVIDIA/Mellanox Support
=======================

PF_RING (8.1 or newer) includes native support for NVIDIA/Mellanox ConnectX-4, ConnectX-5 and ConnectX-6 adapters.
Both packet capture (including RSS, packet hash, hardware timestamp support) and transmission are supported.

Prerequisite
------------

1. Install the *pfring* package by configuring one of our repositories at http://packages.ntop.org.
PF_RING can also be downloaded in source format from GIT at https://github.com/ntop/PF_RING/

2. Install Mellanox OFED/EN from https://www.mellanox.com/products/infiniband-drivers/linux/mlnx_ofed 
This package also installs the *libibverbs* library, which is required in order to use Mellanox adapters 
with PF_RING, as well as other dependencies. Please note that a reduced toolset can be selected for the 
OFED SDK to be used by capture frameworks (the *--dpdk* option is available for that) as in the below example.

.. code-block:: console

   cd MLNX_OFED_LINUX-*
   ./mlnxofedinstall --upstream-libs --dpdk

Note: the OFED *mlnxofedinstall* script used to be called *install* on old SDK versions:

.. code-block:: console

   ./install --upstream-libs --dpdk

Compatibility
-------------

Check the adapter firmware:

.. code-block:: console

   ibv_devinfo

Recommended firmware versions are:

 - ConnectX-4: >= 12.28.2006
 - ConnectX-5: >= 16.21.1000
 - ConnectX-6: >= 20.27.0090
 - ConnectX-6 Dx: >= 22.27.0090

Configuration
-------------

Load the required modules:

.. code-block:: console

   modprobe -a ib_uverbs mlx5_core mlx5_ib

Check that the adapter is recognised and listed by PF_RING:

.. code-block:: console

   pfcount -L -v 1
   Name       SystemName Module  MAC               BusID         NumaNode  Status  License Expiration
   enp1s0f0	  enp1s0f0	 pf_ring B8:CE:F6:8E:DD:5A	0000:01:00.0  -1	      Up	     Valid	 1662797500
   enp1s0f1	  enp1s0f1	 pf_ring B8:CE:F6:8E:DD:5B	0000:01:00.1  -1	      Up	     Valid	 1662797500
   mlx:mlx5_0 enp1s0f0   mlx     B8:CE:F6:8E:DD:5A 0000:00:00.0  -1        Down    Valid   1662797500
   mlx:mlx5_1 enp1s0f1   mlx     B8:CE:F6:8E:DD:5B 0000:00:00.0  -1        Down    Valid   1662797500

Please note that the same interfaces appear twice, as they can se used both using the kernel driver
(creating a socket on *enp1s0f0* for instance) or the *mlx* module in zero-copy mode (creating a
socket on the corresponding *mlx:mlx5_0* interface).

Capturing Traffic
-----------------

In order to capture traffic from a Mellanox adapter using the native *mlx* module mlx:<device> should be
specified as interface name, as reported by *pfcount -L*. Example:

.. code-block:: console

   pfcount -i mlx:mlx5_0

The default size of the RX ring (the maximum number of packets the adapter can keep in the receive
FIFO buffer) is 4K. This can be configured using the PF_RING_RX_QUEUE_SIZE environment variable.
Example:

.. code-block:: console

   PF_RING_RX_QUEUE_SIZE=32768 pfcount -i mlx:mlx5_0

RSS / Multi Queue
~~~~~~~~~~~~~~~~~

Multi-queue support (RSS) is available on Mellanox with the constraint that all queues
should be used in the same process (supporting multiple capture threads).
The number of RSS queues can be set using the standard ethtool command on the kernel
interface. Example for 4 queues:

.. code-block:: console

   ethtool -L enp1s0f0 combined 4

In order to capture traffic from a queue, mlx:<device>@<queue> should be used as interface
name. Example with queue 0:

.. code-block:: console

   pfcount -i mlx:mlx5_0@0

Or to open all queues:

.. code-block:: console

   pfcount_multichannel -i mlx:mlx5_0

Traffic Transmission
--------------------

Packet transmission is also supported on Mellanox (including multiqueue/multithread
transmission when RSS is enabled). The same syntax used for capturing traffic can be 
used to select the TX interface. Example:

.. code-block:: console

   pfsend -i mlx:mlx5_0

Or to send from all queues and scale the transmission performance:

.. code-block:: console

   pfsend_multichannel -i mlx:mlx5_0

Hw Filtering
------------

Mellanox adapters support packet filtering in hw. Up to 64K rules are supported.
In order to set an hw filter the *pfring_add_hw_rule* API should be used.

Sample code for filtering traffic with Mellanox (as well as with other adapters) 
is available in the *pfcount.c* sample application (look for *sample_filtering_rules*).

Filtering rules can be defined as *drop* or *pass*. The default behaviour can be set
with the *pfring_set_default_hw_action* API. When the default is not explicitly set,
this depends on the promiscuous mode: with the promisc set, all traffic is received by 
default (pass), no traffic otherwise (drop). Promisc is set using the *pfring_open* 
flag *PF_RING_PROMISC*.

In order to set a filtering rule, a rule ID (0..65534) should be assigned to the rule.
This is a unique identifier that can be used to remove the rule later on. The ID can
be automatically assigned by the library by using *FILTERING_RULE_AUTO_RULE_ID* as rule ID.

A priority can also be assigned to the rule, in the range 0..2. Two applications capturing 
traffic from the same interface, and setting a pass rule which is matching the same traffic
and with the same priority, will both receive the same traffic. Instead, only the application 
which is setting the higher priority on the rule, would receive the traffic otherwise.

Example setting a filtering rule to drop UDP traffic matching a src IP and destination port:

.. code-block:: c

   pfring_set_default_hw_action(socket, default_pass);
   
   hw_filtering_rule r = { 0 };
   
   r.rule_id = FILTERING_RULE_AUTO_RULE_ID;
   r.priority = 0;
   r.rule_family_type = generic_flow_tuple_rule;
   
   r.rule_family.flow_tuple_rule.action = flow_drop_rule;
   
   r.rule_family.flow_tuple_rule.vlan_id = 10;
   r.rule_family.flow_tuple_rule.ip_version = 4;
   r.rule_family.flow_tuple_rule.src_ip.v4 = src_ip_rule;
   r.rule_family.flow_tuple_rule.protocol = IPPROTO_UDP;
   r.rule_family.flow_tuple_rule.dst_port = 3000;
   
   pfring_add_hw_rule(socket, &r);

Please note that:

- all fields are in host byte order.
- when *FILTERING_RULE_AUTO_RULE_ID* is used, the rule ID assigned by *pfring_add_hw_rule* is returned in r.rule_id.

For a full list of supported fields please take a look at the *generic_flow_tuple_hw_rule* struct.

Example of removing a filtering rule by ID:

.. code-block:: c

   pfring_remove_hw_rule(socket, RULE_ID);

BPF filters are also offloaded to the adapter as long as they can be automatically converted by the nBPF engine into hardware rules. Example:

.. code-block:: console

   pfcount -i mlx:mlx5_0 -f "vlan 10 and host 192.168.1.1"

RoCEv2/RDMA Capture
-------------------

Mellanox adapters support RoCEv2/RDMA traffic natively. This traffic is not captured
in the standard mode as it is handled by the adapter, even if this looks like standard UDP
traffic. In order to enable RoCEv2/RDMA traffic capture, a special sniffing mode should be
enabled through the PF_RING_MLX_SNIFFER_MODE environment variable as below:

.. code-block:: console

   PF_RING_MLX_SNIFFER_MODE=1 ./pfcount -i mlx:mlx5_0 -v 1

Please note that hardware filtering (including BPF offload) does not work when this mode
is enabled.

