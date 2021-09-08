Mellanox Support
================

PF_RING (8.1 or newer) includes native support for Mellanox ConnectX-4, ConnectX-5 and ConnectX-6 adapters.

Note: this capture module is currently under development, only basic RX capabilities are currently availebl.

Prerequisite
------------

The *ibverbs* library is required in order to use Mellanox adapters with PF_RING.
Download Mellanox OFED/EN from https://www.mellanox.com/products/infiniband-drivers/linux/mlnx_ofed
and install it, selecting a toolset usually used also by other capture frameworks. Please note this also
installs *libibverbs*, in addition to other dependencies.

.. code-block:: console

   cd MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64
   ./mlnxofedinstall --upstream-libs --dpdk

Configuration
-------------

Check the adapter firmware:

.. code-block:: console

   ibv_devinfo

Recommended firmware versions are:

 - ConnectX-5: >= 16.21.1000
 - ConnectX-6: >= 20.27.0090
 - ConnectX-6 Dx: >= 22.27.0090

Load the required modules:

.. code-block:: console

   modprobe -a ib_uverbs mlx5_core mlx5_ib

Check that the adapter is recognised and listed by PF_RING:

.. code-block:: console

   pfcount -L -v 1
   Name        SystemName  Module  MAC                BusID         NumaNode  Status  License   Expiration
   mlx:mlx5_0  enp1s0f0    mlx     B8:CE:F6:8E:DD:5A  0000:00:00.0  -1        Down    NotFound  0
   mlx:mlx5_1  enp1s0f1    mlx     B8:CE:F6:8E:DD:5B  0000:00:00.0  -1        Down    NotFound  0

Capturing Traffic
-----------------

In order to capture traffic from a Mellanox adapter using the native *mlx* module, please should specify mlx:<device>
as reported by *pfcount -L*. Example:

.. code-block:: console

   pfcount -i mlx:mlx5_0

Please note that multi-queue support (RSS) is not yet available.

Traffic Transmission
--------------------

Packet transmission is not yet available.

