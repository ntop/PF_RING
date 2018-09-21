Using Bro with PF_RING
======================

In order to use Bro on top of pf_ring support please follow this guide.

1. Install the "pfring" package (and optionally "pfring-drivers-zc-dkms"
if you want to use ZC drivers) from http://packages.ntop.org as explained
in README.apt_rpm_packages

2. Download Bro sources from https://www.bro.org/download/. Please note that installing Bro from package leads to failures when capturing from multiple PF_RING queues (as explained below).

.. code-block:: console

   wget https://www.bro.org/downloads/release/bro-X.X.X.tar.gz
   tar xvzf bro-*.tar.gz

3. Configure and install Bro

.. code-block:: console

   ./configure --with-pcap=/usr/local/lib
   make
   make install

Please note that on some installations your should tune the LDFLAGS in order
to fix linking issues. Example:

.. code-block:: console

   LDFLAGS="-lpfring -lpcap" ./configure --with-pcap=/usr/local/

4. Make sure Bro is correctly linked to pf_ring-aware libpcap:

.. code-block:: console

   ldd /usr/local/bro/bin/bro | grep pcap
           libpcap.so.1 => /usr/local/lib/libpcap.so.1 (0x00007fa371e33000)

5. Configure the node configuration file (node.cfg) with:

.. code-block:: text

    lb_method=pf_ring 
    lb_procs=<number of processes you want to run>
    pin_cpus=<core affinity for the processes (comma-separated list)>

Example:

.. code-block:: text

   [worker-1]
   type=worker
   host=10.10.10.1
   interface=eth1
   lb_method=pf_ring
   lb_procs=8
   pin_cpus=0,1,2,3,4,5,6,7

If you are running multiple workers setting ls_procs > 1 as in the
example above, Bro needs to setup a pf_ring kernel cluster in order
to split the traffic across the processes (otherwise your get duplicated
data). In order to force this you can append the line below to the 
configuration file (note: '99' in the example below is the cluster ID, 
feel free to replace it with any number).

.. code-block:: text

   env_vars=PCAP_PF_RING_CLUSTER_ID=99

If you installed the ZC drivers, you can configure the number of RSS queues,
as explained in README.apt_rpm_packages (or running "ethtool -L eth1 combined <num>"),
to the same number of processes in lb_procs, and use zc:ethX as interface name.

Example:
		
.. code-block:: text

   [worker-1]
   type=worker
   host=10.10.10.1
   interface=zc:eth1
   lb_method=pf_ring
   lb_procs=8
   pin_cpus=0,1,2,3,4,5,6,7
		
Another option for distributing the load using ZC is using zero-copy software 
distribution with zbalance_ipc. This configuration requires RSS set to single 
queue.
Run zbalance_ipc *before* running bro with:

.. code-block:: console

   zbalance_ipc -i zc:eth1 -c 99 -n 8 -m 1 -g 8

Where:

- -c 99 is the cluster ID
- -n 8 is the number of queues
- -g 8 is core affinity for zbalance_ipc

You should use as interface name zc:<cluster id> as in the example below.

Example:

.. code-block:: text

   [worker-1]
   type=worker
   host=10.10.10.1
   interface=zc:99
   lb_method=pf_ring
   lb_procs=8
   pin_cpus=0,1,2,3,4,5,6,7

PF_RING FT Acceleration
-----------------------

In order to take advantage of the PF_RING FT L7 filtering/shunting, you also need to install nDPI: 

.. code-block:: console
   
   git clone https://github.com/ntop/nDPI.git
   cd nDPI
   ./autogen.sh
   make && sudo make install

.. note::  If you are installing a **stable** version of PF_RING, you should also clone latest stable version of nDPI.

Then you need to create a configuration file with the filtering rules:

.. code-block:: console
   
   # cat /etc/pf_ring/ft-rules.conf
   [filter]
   YouTube = discard
   Netflix = discard

And set the path of the configuration file using the PF_RING_FT_CONF environment variable in your node.cfg file:

.. code-block:: text
   
   [worker-1]
   type=worker
   host=10.10.10.1
   interface=eth1
   lb_method=pf_ring
   lb_procs=8
   pin_cpus=0,1,2,3,4,5,6,7
   env_vars=PF_RING_FT_CONF=/etc/pf_ring/ft-rules.conf

At this point you are ready to run Bro.

For further information about PF_RING FT please read http://www.ntop.org/guides/pf_ring/ft.html
