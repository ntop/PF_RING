AF_XDP Support
==============

PF_RING since version 7.5 (note: 7.9 is actually recommended) includes support for AF_XDP adapters,
when compiling from source code this is enabled by default (unless the *--disable-xdp*
configure flag is specified).

Prerequisite
------------

- PF_RING 7.9.0-6671 or later
- Dependencies: libelf-dev
- Kernel: >= 5.4 (configured with `CONFIG_XDP_SOCKETS=y`)
- libbpf with latest AF_XDP support installed from <kernel source>/tools/lib/bpf
- Hugepages loaded

Kernel Version
--------------

Install a kernel >= 5.4, which includes support for unaligned zero-copy buffers. 

Ubuntu 20 LTS currently runs a kernel 5.4 which fully supports AF_XDP. However the HWE kernel 5.8 is recommended as it provides improved AF_XDP support.

Install *libelf-dev*:

.. code-block:: console

   apt install libelf-dev

Install *libbpf* from kernel source:

.. code-block:: console

   cd /usr/src/linux-headers-$(uname -r)/tools/lib/bpf
   sudo make install_lib
   sudo make install_headers
   sudo ldconfig

On Ubuntu 18.04 you can use uktools available at https://github.com/usbkey9/uktools/ following the instructions below:

.. code-block:: console

   git clone https://github.com/usbkey9/uktools && cd uktools
   make

Download and unpack sources for kernel 5.x, it will be used to compile and install libbpf:

.. code-block:: console

   wget http://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.4.2.tar.xz
   tar xvf linux-5.4.2.tar.xz 
   cd linux-5.4.2/tools/lib/bpf
   make
   sudo make install_lib
   sudo make install_headers
   sudo ldconfig

Installation
------------

Install PF_RING as reported in the *Installing from packages* section
on a supported OS with a supported kernel version (e.g. Ubuntu 20) or
compile it from source code. In the latter case AF_XDP support should
be automatically detected and enabled:

.. code-block:: console

   cd PF_RING/userland
   ./configure
   make

Note: the --enable-xdp flag was required on previous pf_ring versions.

Please make sure the below output is printed by the configure script
(this means AF_XDP support is actually detected and enabled).

.. code-block:: console

  checking PF_RING AF_XDP support... yes

Load the driver
---------------

Load vanilla drivers (use recent drivers that include AF_XDP support, PF_RING ZC
drivers should be unloaded as they only support PF_RING ZC mode).

Load Hugepages
--------------

Hugepages are required for the AF_XDP support to work (used for buffers allocation).
When installing from packages following the *Installing from packages* guide it is
only required to create */etc/pf_ring/hugepages.conf*, otherwise hugepages can be
loaded with:

.. code-block:: console

   echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
   mount -t hugetlbfs nodev /dev/hugepages

Usage
-----

You are now ready to run any pf_ring sample application using xdp:<interface>@<queue> as interface name.
Example:

.. code-block:: console

   cd examples
   sudo ./pfcount -i xdp:eth1@0

Please note that with AF_XDP pf_ring attaches to a NIC queue, please disable RSS or open all queues.
