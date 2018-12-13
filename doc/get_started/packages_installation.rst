Installing from packages
========================

Ready-to-use PF_RING packages are available at http://packages.ntop.org,
please follow the instructions on the same page for configuring the repository
and install *pfring* and *pfring-dkms*. Optionally you can also install
*pfring-drivers-zc-dkms* if you need the ZC drivers for line-rate capture 
on Intel adapters.

This section guides you through the PF_RING configuration using the init scripts
(init.d or systemctl according to your linux distribution) contained in the *pfring* 
package, to automate the kernel module and drivers loading. Alternatively please
note that it is possible to automatically configure PF_RING and drivers through the 
nBox GUI.

The init script acts as follows:

1. it loads the pf_ring.ko kernel module reading the module parameters from /etc/pf_ring/pf_ring.conf
2. it scans /etc/pf_ring/zc/{e1000e,igb,ixgbe,ixgbevf,i40e,fm10k}/ searching for the drivers configuration files:

   - {e1000e,igb,ixgbe,ixgbevf,i40e,fm10k}.conf containing the driver parameters
   - {e1000e,igb,ixgbe,ixgbevf,i40e,fm10k}.start that should be just an empty file

3. it loads the drivers whose corresponding {e1000e,igb,ixgbe,ixgbevf,i40e,fm10k}.start file is present, unloading the vanilla driver.
4. if a ZC driver has been loaded, it configures hugepages reading the configuration from /etc/pf_ring/hugepages.conf. Each line (one per CPU) of the configuration file should contain:

.. code-block:: console

   node=<NUMA node id> hugepagenumber=<number of pages> [gid=<GID>]

Below you can find a configuration example for using PF_RING with standard drivers.
In this example we tune the kernel buffer size (min_num_slots parameter) to improve 
the performance and absorbe traffic bursts:

.. code-block:: console

   mkdir -p /etc/pf_ring
   echo "min_num_slots=65536" > /etc/pf_ring/pf_ring.conf

In order to use pf_ring with ZC drivers, you need first of all to figure out what is 
the driver model of your network card. Please use ethtool -i <interface> for that. 
Example:

.. code-block:: console

   ethtool -i eth1 | grep driver
   driver: ixgbe

Below you can find a configuration example for a dual-port ixgbe card with ZC drivers, 
the configuration for other card models is similar (replace ixgbe with your actual driver family).

.. code-block:: console

   sudo mkdir -p /etc/pf_ring/zc/ixgbe
   sudo touch /etc/pf_ring/pf_ring.conf
   echo "node=0 hugepagenumber=1024" | sudo tee /etc/pf_ring/hugepages.conf 
   echo "RSS=1,1" | sudo tee /etc/pf_ring/zc/ixgbe/ixgbe.conf 
   sudo touch /etc/pf_ring/zc/ixgbe/ixgbe.start
   tree /etc/pf_ring/
   |-- hugepages.conf
   |-- pf_ring.conf
   `-- zc
       `-- ixgbe
           |-- ixgbe.conf
           `-- ixgbe.start

Please note that in this configuration RSS is disabled (RSS=1 means single queue). 
For learning more about RSS and enable multiple queues for hw traffic distribution 
please read the `RSS <http://www.ntop.org/guides/pf_ring/rss.html#rss-receive-side-scaling>`_
section.

In order to run the init script, after all the files have been configured,
if your system is using systemd run:

.. code-block:: console

   sudo systemctl start pf_ring
   
Otherwise you can use the init.d script:

.. code-block:: console

   sudo touch /etc/pf_ring/pf_ring.start
   sudo /etc/init.d/pf_ring start

You can check that the ZC driver is actually running with:

.. code-block:: console

   cat /proc/net/pf_ring/dev/eth1/info | grep ZC
   Polling Mode:      ZC/NAPI

Note: If you're trying to load a ZC driver on a card that you're currently using as management, you may need to force it creating a `forcestart` configuration file. _(Warning: This may break network connectivity, do not attempt on a remote system with no recovery options.)_

.. code-block:: console

   sudo touch /etc/pf_ring/forcestart

Alternatively you can explicitly tell to the init script which are the interfaces you are using as management, and those that you want to use for packet capture, creating a configuration file /etc/pf_ring/interfaces.conf containing:

.. code-block:: console

   MANAGEMENT_INTERFACES="eth0 eth1"
   CAPTURE_INTERFACES="eth2 eth3 eth4 eth5"

