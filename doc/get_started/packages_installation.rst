Installing from packages
========================

At http://packages.ntop.org we build binary PF_RING packages ready to use.
Please follow the instructions on the web page for configuring the repository
and install *pfring* and *pfring-dkms*. Optionally you can also install
*pfring-drivers-zc-dkms* if you need the ZC drivers for line-rate capture on 
Intel adapters.

An option for configuring PF_RING and drivers is doing it through the nBox GUI. 
In case you are not using the nBox GUI, you can manually configure the packages 
from command line, and use the init scripts (under /etc/init.d or systemctl, 
according to your linux distribution) to automate the kernel module and drivers 
loading. The init script acts as follows:

1. loads the pf_ring.ko kernel module.
2. scans the folders /etc/pf_ring/zc/{e1000e,igb,ixgbe,i40e,fm10k}/ searching files:

   - {e1000e,igb,ixgbe,i40e,fm10k}.conf containing the driver parameters
   - {e1000e,igb,ixgbe,i40e,fm10k}.start that should be just an empty file

3. loads the drivers whose corresponding {e1000e,igb,ixgbe,i40e,fm10k}.start file is present, unloading the vanilla driver.
4. configures hugepages if a ZC driver has been loaded, reading the configuration from /etc/pf_ring/hugepages.conf. Each line (one per CPU) of the configuration file should contain:

.. code-block:: console

   node=<NUMA node id> hugepagenumber=<number of pages>

Note: in order to figure out what is the driver model that you need, please use
ethtool -i <interface>. Example:

.. code-block:: console

   ethtool -i eth1 | grep driver
   driver: ixgbe

Below you can find a configuration example for a dual-port ixgbe card (replace
ixgbe with your actual driver model) with ZC drivers, for other packages/drivers 
configuration steps are similar.

.. code-block:: console

   mkdir -p /etc/pf_ring/zc/ixgbe
   echo "RSS=1,1" > /etc/pf_ring/zc/ixgbe/ixgbe.conf 
   touch /etc/pf_ring/zc/ixgbe/ixgbe.start
   touch /etc/pf_ring/pf_ring.conf
   touch /etc/pf_ring/pf_ring.start
   echo "node=0 hugepagenumber=1024" > /etc/pf_ring/hugepages.conf 
   tree /etc/pf_ring/
   |-- hugepages.conf
   |-- pf_ring.conf
   |-- pf_ring.start
   `-- zc
       `-- ixgbe
           |-- ixgbe.conf
           `-- ixgbe.start

Please note that in this configuration RSS is disabled (RSS=1 means single queue). 
For learning more about RSS and enable multiple queues for hw traffic distribution 
please read the RSS guide.

In order to run the init script, after all the files have been configured,
if you are using systemd please run:

.. code-block:: console

   systemctl start pf_ring
   
Otherwise please use the init.d script:

.. code-block:: console

   /etc/init.d/pf_ring start

You can check that the ZC driver is actually running with:

.. code-block:: console

   cat /proc/net/pf_ring/dev/eth1/info | grep ZC
   Polling Mode:      ZC/NAPI

Note: If you're trying to load a ZC driver on a card that you're currently using as management, you may need to enable `forcestart`. _(Warning: This may break network connectivity, do not attempt on a remote system with no recovery options.)_

.. code-block:: console

   sudo touch /etc/pf_ring/forcestart

Alternatively you can explicitly tell to the init script which are the interfaces you are using as management, and those that you want to use for packet capture, creating a configuration file /etc/pf_ring/interfaces.conf containing:

.. code-block:: console

   MANAGEMENT_INTERFACES="eth0 eth1"
   CAPTURE_INTERFACES="eth2 eth3 eth4 eth5"

