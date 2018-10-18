Using PF_RING with CoreOS
=========================

This guide shows how to run packet processing applications based on PF_RING
inside a container running on CoreOS Container Linux.

Please note that CoreOS ships without compiler toolchain and without kernel sources, 
for this reason compilation happens in a container, using kernel sources of the host system.

PF_RING include scripts to automate modules compilation and installation on CoreOS as 
described below. Please note that a system update changes the kernel requiring modules recompilation.

Installation
------------

Running the build.sh script it will compile and install the pf_ring kernel module and all the ZC drivers.
It is possible to select the pf_ring version to install changing the branch name in the PF_RING_VERSION variable in build.sh.

.. code-block:: console

   git clone https://github.com/ntop/PF_RING.git
   cd PF_RING/package/coreos
   ./build.sh

After that you are ready to load the kernel modules installed on the host under /opt/pf_ring, example:

.. code-block:: console

   sudo insmod /opt/pf_ring/7.2.0-stable/$(cat /etc/os-release|grep VERSION=|cut -d= -f2)/lib64/modules/$(uname -r)/kernel/net/pf_ring/pf_ring.ko

In order to test the drivers you can use the pfring image available on Docker Hub:

.. code-block:: console

   docker run --net=host ntop/pfring:stable pfcount -i enp0s3

