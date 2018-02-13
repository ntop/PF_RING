Using Snort with PF_RING
========================

Prerequisites
-------------

Make sure you have installed:

   - Snort 2.9 or later
   - Snort with DAQ include files/libraries (0.6.2, 1.1.1, and 2.0). You can do that downloading snort and DAQ from http://www.snort.org/snort-downloads?

Compilation
-----------

.. code-block:: console

   git clone https://github.com/ntop/PF_RING.git
   cd PF_RING/kernel
   make && sudo make install
   
   cd PF_RING/userland/lib
   ./configure && make && sudo make install
   
   cd PF_RING/userland/snort/pfring-daq-module
   autoreconf -ivf
   ./configure
   make

Configure Options
-----------------

If you do not have PF_RING installed, nor in the "$HOME/PF_RING" path, a few configure options are available:

.. code-block:: console

   --with-libpfring-includes=<libpfring include directory>
   --with-pfring-kernel-includes=<pfring kernel include directory>
   --with-libpfring-libraries=<libpfring library directory>

Installation
------------

Install the library with:

.. code-block:: console

   sudo cp .libs/daq_pfring.so /usr/local/lib/daq/

or alternatively with:

.. code-block:: console

   sudo make install

or if you want to run snort without installing it use "--daq-dir=./.libs"

Running snort in IDS mode
-------------------------

.. code-block:: console

   snort --daq-dir=/usr/local/lib/daq --daq pfring --daq-mode passive -i ethX -v -e

It is possible to specify multiple interfaces by using a comma-separated list.

Running snort in IPS mode
-------------------------

.. code-block:: console

   snort --daq-dir=/usr/local/lib/daq --daq pfring  -i ethX:ethY -e -Q

It is possible to specify multiple interface pairs by using a comma-separated list.

PF_RING DAQ Specific Options
----------------------------

1. Kernel Filters

By default, PF_RING kernel filtering rules are added whenever snort's verdict requests to drop specific flows. If you want instead snort (and not PF_RING) drop packets (i.e. don't add automatically PF_RING kernel filtering rules) add:

.. code-block:: console

   --daq-var no-kernel-filters

Kernel filtering rules idle for more than 5 minutes are automatically removed. In order to change the default timeout for idle rules do:

.. code-block:: console

   --daq-var kernel-filters-idle-timeout=<seconds>

2. Socket clustering

PF_RING allows you to distribute packets across multiple processes by using socket clusters. For instance two snort instances bound to the same clusterId receive each a subset of packets so that both can cooperatively share the load. In order to enable this feature do:

.. code-block:: console

   --daq-var clusterid=<comma separated id list>

where an id is a number (i.e. the clusterId), one for each interface. It is also possible to specify the cluster mode, with:

.. code-block:: console

   --daq-var clustermode=<mode>

where valid mode values are:

   - 2 for 2-tuple flow
   - 4 for 4-tuple flow
   - 5 for 5-tuple flow
   - 6 for 6-tuple flow

3. Bind an instance to a core

Proper core insulation, grants snort instances not to step on each other's feet. In order to bind an instance to a specific core do:

.. code-block:: console
   
   --daq-var bindcpu=<core id> 

4. Kernel-level forwarding in IDS mode

If you want to forward incoming packets at kernel level while snort is running in IDS mode, you can specify a destination interface for each ingress interface with:

.. code-block:: console
   
   --daq-var lowlevelbridge=<comma-separated interface list>

5. Fast TX in IPS mode

Since forwarding packets from userspace requires additional copies (thus affecting performances), it is possible to forward at kernel level the packets for which snort gives a positive verdict:

.. code-block:: console

   --daq-var fast-tx

6. Packet capture tuning

It is possible to tune the packet capture activity specifying the poll() timeout:

.. code-block:: console

   --daq-var timeout=<milliseconds>

and the watermark (min number of incoming packets for the poll() to return):

.. code-block:: console

   --daq-var watermark=<packets>

Example of Clustering + Core Binding
------------------------------------

IDS mode:

.. code-block:: console

   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-1 --daq-dir=/usr/local/lib/daq --daq pfring --daq-mode passive -i eth2,eth3 --daq-var lowlevelbridge=eth3,eth2 --daq-var clusterid=10,11 --daq-var bindcpu=1
   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-2 --daq-dir=/usr/local/lib/daq --daq pfring --daq-mode passive -i eth2,eth3 --daq-var lowlevelbridge=eth3,eth2 --daq-var clusterid=10,11 --daq-var bindcpu=2
   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-3 --daq-dir=/usr/local/lib/daq --daq pfring --daq-mode passive -i eth2,eth3 --daq-var lowlevelbridge=eth3,eth2 --daq-var clusterid=10,11 --daq-var bindcpu=3
   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-4 --daq-dir=/usr/local/lib/daq --daq pfring --daq-mode passive -i eth2,eth3 --daq-var lowlevelbridge=eth3,eth2 --daq-var clusterid=10,11 --daq-var bindcpu=4

IPS mode:

.. code-block:: console

   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-1 --daq-dir=/usr/local/lib/daq --daq pfring --daq-mode inline -i eth2:eth3 --daq-var fast-tx=1 --daq-var clusterid=10,11 --daq-var bindcpu=1
   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-2 --daq-dir=/usr/local/lib/daq --daq pfring --daq-mode inline -i eth2:eth3 --daq-var fast-tx=1 --daq-var clusterid=10,11 --daq-var bindcpu=2
   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-3 --daq-dir=/usr/local/lib/daq --daq pfring --daq-mode inline -i eth2:eth3 --daq-var fast-tx=1 --daq-var clusterid=10,11 --daq-var bindcpu=3
   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-4 --daq-dir=/usr/local/lib/daq --daq pfring --daq-mode inline -i eth2:eth3 --daq-var fast-tx=1 --daq-var clusterid=10,11 --daq-var bindcpu=4

