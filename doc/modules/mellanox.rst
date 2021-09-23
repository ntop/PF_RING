Mellanox Support
================

PF_RING (8.1 or newer) includes native support for Mellanox ConnectX-4, ConnectX-5 and ConnectX-6 adapters.

Note: this capture module is currently under development, only basic RX capabilities are currently availebl.

Prerequisite
------------

1. Install the *pfring* package by configuring one of our repositories at http://packages.ntop.org.
PF_RING can also be downloaded in source format from GIT at https://github.com/ntop/PF_RING/

2. Install the *libibverbs* library, which is required in order to use Mellanox adapters with PF_RING,
by downloading Mellanox OFED/EN from https://www.mellanox.com/products/infiniband-drivers/linux/mlnx_ofed
and installing it. Please note that a reduced toolset can be selected for the OFED SDK to be used by
capture frameworks (the *--dpdk* option is available for that) as in the below example.
The Mellanox OFED/EN installer installs *libibverbs* as well as other dependencies.

.. code-block:: console

   cd MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64
   ./mlnxofedinstall --upstream-libs --dpdk

Compatibility
-------------

Check the adapter firmware:

.. code-block:: console

   ibv_devinfo

Recommended firmware versions are:

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

In order to capture traffic from a Mellanox adapter using the native *mlx* module, please should specify mlx:<device>
as reported by *pfcount -L*. Example:

.. code-block:: console

   pfcount -i mlx:mlx5_0

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

Traffic Transmission
--------------------

Packet transmission is also supported on Mellanox. The same syntax used for capturing traffic can be used to select the TX interface.
Example:

.. code-block:: console

   pfsend -i mlx:mlx5_0

