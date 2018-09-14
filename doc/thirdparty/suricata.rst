Using Suricata with PF_RING
===========================

In order to compile Suricata with pf_ring support please follow this guide:

https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Installation_of_Suricata_stable_with_PF_RING_(STABLE)_on_Ubuntu_server_1204

Installation
------------

.. code-block:: console

   git clone https://github.com/ntop/PF_RING.git
   cd PF_RING/kernel
   make && sudo make install
   
   cd PF_RING/userland/lib
   ./configure && make && sudo make install
   
   git clone https://github.com/OISF/suricata
   cd suricata
   git clone https://github.com/OISF/libhtp
   ./autogen.sh
   LIBS="-lrt" ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
     --enable-pfring --with-libpfring-includes=/usr/local/include \
     --with-libpfring-libraries=/usr/local/lib
   make
   sudo make install
   sudo ldconfig
   
   sudo make install-conf
   sudo make install-rules
   
   suricata --build-info | grep PF_RING
   PF_RING support:                         yes

Standard Mode
-------------

In order to run Suricata on standard drivers, leveraging on the PF_RING kernel clustering, run:

.. code-block:: console

   sudo modprobe pf_ring
   
   sudo suricata --pfring-int=eth0 --pfring-cluster-id=99 --pfring-cluster-type=cluster_flow -c /etc/suricata/suricata.yaml

PF_RING ZC Mode
---------------

In order to take advantage of the PF_RING ZC drivers on Intel adapters, you also need to load the ZC driver, according to your nework card model. Example for ixgbe cards:

.. code-block:: console

   cd PF_RING/drivers/ZC/intel/ixgbe/ixgbe-*-zc/src/
   make && sudo ./load_driver.sh
   
   sudo suricata --pfring-int=zc:eth1 -c /etc/suricata/suricata.yaml


PF_RING FT Acceleration
-----------------------

In order to take advantage of the PF_RING FT L7 filtering/shunting, you also need to install nDPI: 

.. code-block:: console
   
   git clone https://github.com/ntop/nDPI.git
   cd nDPI
   ./autogen.sh
   make && sudo make install

Then you need to create a configuration file with the filtering rules:

.. code-block:: console
   
   # cat /etc/pf_ring/ft-rules.conf
   [filter]
   YouTube = discard
   Netflix = discard

And run Suricata setting the path of the configuration file using the PF_RING_FT_CONF environment variable:

.. code-block:: console
   
   PF_RING_FT_CONF=/etc/pf_ring/ft-rules.conf suricata --pfring-int=zc:eth1 -c /etc/suricata/suricata.yaml

For further information about PF_RING FT please read http://www.ntop.org/guides/pf_ring/ft.html

