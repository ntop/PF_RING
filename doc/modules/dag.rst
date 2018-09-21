Endace DAG Support
==================

PF_RING has native support for Endace DAG adapters, the DAG SDK needs to be installed in order to enable the DAG module at runtime.

Prerequisite
------------

DAG SDK installed. Example from source tarball:

.. code-block:: console

   tar -xvz dag-<version>.tar.gz
   cd dag
   ./configure && make && make install

Installation
------------

In order to get up and running with a DAG adapter just run the following commands.

Load the DAG module:

.. code-block:: console

   dagload

Compile/load pf_ring and sample applications:

.. code-block:: console

   cd PF_RING/kernel; make; sudo insmod pf_ring.ko
   cd ../userland/modules/Endace; ./configure && make && make install
   cd ../../lib; ./configure && make
   cd ../libpcap; ./configure && make
   cd ../examples; make

Run the sample application to make sure everything is working:

.. code-block:: console

   ./pfcount -i dag:0

Please note that in order to open port 0 from the DAG adapter you should specify "dag:0" as interface name, if you want to open stream 2 (default is 0) on port 0 you should specify "dag:0@2".

If you are installing from repository, dag support is already enabled:

.. code-block:: console

   pfcount -i dag:0

