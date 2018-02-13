Using Snort with PF_RING ZC
===========================

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
   
   cd PF_RING/userland/snort/pfring-daq-module-zc
   autoreconf -ivf
   ./configure
   make

Installation
------------

Install the library with:

.. code-block:: console

   sudo cp .libs/daq_pfring_zc.so /usr/local/lib/daq/

or alternatively with:

.. code-block:: console

   sudo make install

or if you want to run snort without installing it use "--daq-dir=./.libs"

Running snort in IDS mode
-------------------------

.. code-block:: console

   snort --daq-dir=/usr/local/lib/daq --daq pfring_zc --daq-mode passive -i zc:ethX --daq-var clusterid=Z -v -e

It is possible to specify multiple interfaces by using a comma-separated list.

Running snort in IPS mode
-------------------------

.. code-block:: console

   snort --daq-dir=/usr/local/lib/daq --daq pfring_zc  -i zc:ethX+zc:ethY --daq-var clusterid=Z -e -Q

It is possible to specify multiple interface pairs by using a comma-separated list.

PF_RING ZC DAQ Specific Options
-------------------------------

1. Cluster ID

Each snort instance creates an internal ZC Cluster, each cluster needs a unique Cluster ID that can be specified with:

.. code-block:: console

   --daq-var clusterid=<cluster id>

2. Bind an instance to a core

Proper core insulation, grants snort instances not to step on each other's feet.
In order to bind an instance to a specific core do:
   
.. code-block:: console

   --daq-var bindcpu=<core id> 

3. IDS forwarding

If you want to forward incoming packets while snort is running in IDS mode, you can specify the ids bridge mode with:
   
.. code-block:: console

   --daq-var idsbridge=1

If you prefer higher forwarding speed instead to analysing every single packet, you can specify a "best-effort" IDS bridge mode with:

.. code-block:: console

   --daq-var idsbridge=2

Napatech Streams and IPS/IDS-Bridge
-----------------------------------

Napatech streams are not network interfaces, this means in case of IPS or IDS bridge mode 
you also need to specify the corresponding port for packet transmission (syntax: <rx port>-<tx port>).

.. code-block:: console

   snort --daq-dir=/usr/local/lib/daq --daq pfring_zc  -i nt:streamX-nt:Z+nt:streamY-nt:W -e -Q

Where Z is the port bound to stream X and W is the port bound to stream Y.

Example of Symmetric RSS + Core Binding
---------------------------------------

IDS mode:

.. code-block:: console

   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-1 --daq-dir=/usr/local/lib/daq --daq pfring_zc --daq-mode passive -i zc:eth2+zc:eth3 --daq-var clusterid=0 --daq-var idsbridge=1 --daq-var bindcpu=1

IPS mode:

.. code-block:: console

   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-1 --daq-dir=/usr/local/lib/daq --daq pfring_zc --daq-mode inline -i zc:eth2+zc:eth3 --daq-var clusterid=0 --daq-var bindcpu=1

IDS with Multiqueue and Symmetric RSS:

.. code-block:: console

   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-1 --daq-dir=/usr/local/lib/daq --daq pfring_zc --daq-mode passive -i zc:eth2@0+zc:eth3@0 --daq-var clusterid=0 --daq-var idsbridge=1 --daq-var bindcpu=0
   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-2 --daq-dir=/usr/local/lib/daq --daq pfring_zc --daq-mode passive -i zc:eth2@1+zc:eth3@1 --daq-var clusterid=1 --daq-var idsbridge=1 --daq-var bindcpu=1
   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-3 --daq-dir=/usr/local/lib/daq --daq pfring_zc --daq-mode passive -i zc:eth2@2+zc:eth3@2 --daq-var clusterid=2 --daq-var idsbridge=1 --daq-var bindcpu=2
   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-4 --daq-dir=/usr/local/lib/daq --daq pfring_zc --daq-mode passive -i zc:eth2@3+zc:eth3@3 --daq-var clusterid=3 --daq-var idsbridge=1 --daq-var bindcpu=3

IPS with Multiqueue and Symmetric RSS:

.. code-block:: console

   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-1 --daq-dir=/usr/local/lib/daq --daq pfring_zc --daq-mode inline -i zc:eth2@0+zc:eth3@0 --daq-var clusterid=0 --daq-var bindcpu=0
   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-2 --daq-dir=/usr/local/lib/daq --daq pfring_zc --daq-mode inline -i zc:eth2@1+zc:eth3@1 --daq-var clusterid=1 --daq-var bindcpu=1
   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-3 --daq-dir=/usr/local/lib/daq --daq pfring_zc --daq-mode inline -i zc:eth2@2+zc:eth3@2 --daq-var clusterid=2 --daq-var bindcpu=2
   snort -q --pid-path /var/run --create-pidfile -D -c /etc/snort/snort.conf -l /var/log/snort/bpbr0/instance-4 --daq-dir=/usr/local/lib/daq --daq pfring_zc --daq-mode inline -i zc:eth2@3+zc:eth3@3 --daq-var clusterid=3 --daq-var bindcpu=3

