Accolade Support
================

Prerequisite
------------

PF_RING has native support for Accolade adapters, the Accolade SDK
(v.1.2.26 or later) needs to be installed (under /opt/accolade) in 
order to enable the Accolade module at runtime.

Installation
------------

In order to install the Accolade SDK and drivers run the following 
commands:

.. code-block:: console

   tar xvzf SDK_*.tgz
   cd SDK_*
   cd drv; sudo make install; cd ..
   cd lib; sudo make install; cd ..
   sudo sh -c "echo /opt/accolade/lib/ > /etc/ld.so.conf.d/accolade.conf"

Before running any application please load the driver with:

.. code-block:: console

   sudo sh -c "echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
   sudo insmod /opt/accolade/driver/anic_mem.ko mbytes_per_device=64
   sudo insmod /opt/accolade/driver/anic.ko

Note: with the SDK version <=1.2.26.20180510 the anic_load utility should be used to load the 'anic' module:

.. code-block:: console

   sudo sh -c "echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
   sudo insmod /opt/accolade/driver/anic_mem.ko mbytes_per_device=64
   sudo /opt/accolade/bin/anic_load

Please note that FEC (Forward Error Correction) is disabled by default on Accolade
adapters. If you experience issues bringing up the link when connecting Accolade to 
other adapters, you probably need to enable it (e.g. FM10K on SR4 media run with FEC
enabled). In order to enable it please run anic_load as follows:

.. code-block:: console

   /opt/accolade/bin/anic_load fec_enabled=1,1

If you are running an old firmware and you need to update it, you should
run the following commands: 

.. code-block:: console

   cd SDK_*/tools/; make
   gunzip fpga_*.rbt.gz
   sudo ./anic_fwupdate --id 0 --script fpga_*.rbt
   sudo reboot

Now you are ready to compile and run PF_RING with Accolade support.
Note that if you are installing pfring from packages, Accolade support
is already enabled.

.. code-block:: console

   cd PF_RING/kernel; make
   sudo insmod pf_ring.ko; cd ..
   cd userland; ./configure
   cd lib; make; cd ..
   cd libpcap; ./configure; make; cd ..
   cd examples; make
   sudo ./pfcount -i anic:0

Please note that in order to open port 0 from adapter 0 you should specify anic:DEV:PORT, 
example:

.. code-block:: console

   pfcount -i anic:0:0

or just anic:PORT when using the default adapter 0, example:

.. code-block:: console

   pfcount -i anic:0

Opening a port this way, the full card is initialised, causing issues when opening 
other ports later (previous ports may stop working), this can be avoided using the 
port-to-ring binding as explained later on.

The anic_rx_block_mfl tool included in the Accolade SDK can be used to aggregate 
traffic from multiple ports and setup the card for load-balancing (similar to RSS)
and multi-process applications. 

Example of ports aggregation and load-balancing to 2 rings:

.. code-block:: console

   anic_rx_block_mfl -i 0 --mode=2 

Example of port-to-ring (ring 0 is port 0) binding:

.. code-block:: console

   anic_rx_block_mfl -i 0 --mode=port

In order to open ring 0 from adapter 0 you should specify anic:DEV@RING, example:

.. code-block:: console

   pfcount -i anic:0@0

Note: on SDK version >1.2.26.20180510 the default Accolade 'blocks' setting has
been changed and you might get errors like "ANIC_block_add(ring:0 buf:16) failed, oversubscribed?"
There are two options for setting the number of blocks and solve this error:

1. run anic_rx_block_mfl with --blocks=64 (old default)
2. set the ACCOLADE_RING_BLOCKS env var to 16 (new default) when running pf_ring as anic_rx_block_mfl consumer

Example:

.. code-block:: console

   anic_rx_block_mfl -i 0 --mode=port --blocks=64

Accolade and Packet Copy
------------------------

If you use the PF_RING (non-ZC) API packets are read in zero-copy. Instead
if you use PF_RING ZC API, a per-packet copy takes place, which is required to move
payload data from Accolade memory to ZC memory. Keep this in mind!

Hw Filtering
------------

Accolade adapters support packet filtering in hw. In order to set an
hw filter there are two options:

- Using the standard BPF filter: PF_RING thanks to the nBPF library automatically translates BPF filters into hw filters

- Using the pfring_add_hw_rule() API.

When using the pfring_add_hw_rule() API, as first action we need to set the default 
behaviour for packets, this can be 'pass' or 'drop'. Example:

.. code-block:: c

   hw_filtering_rule r;
   r.rule_family_type = accolade_default;
   r.rule_family.accolade_rule.action = accolade_pass;
   pfring_add_hw_rule(pd, &r);

In order to set a filtering rule, we need to create a rule and assign a rule ID, 
which is a unique identifier for the rule. A standard Accolade firmware supports
up to 32 rules (called 'legacy mode' or 'mode 1'), with IDs from 0 to 31. 
Enhanced Accolade firmwares for 100 Gbit adapters can support up to 1000 rules, 
with IDs from 0 to 999 (called 'mode 2'). PF_RING automatically select 'mode 2' when 
available, and 'mode 1' as fallback. 
It is possible to use the FILTERING_RULE_AUTO_RULE_ID macro as rule.rule_id in order 
to automatically assign the next available rule ID.
Example of setting a filtering rule with 'drop' action for an IPv4 packet:

.. code-block:: c

   hw_filtering_rule r = { 0 };
   r.rule_id = rule_id++;
   r.rule_family_type = accolade_rule;
   r.rule_family.accolade_rule.action = accolade_drop;
   r.rule_family.accolade_rule.ip_version = h->extended_hdr.parsed_pkt.ip_version;
   r.rule_family.accolade_rule.src_addr_bits = 32;
   r.rule_family.accolade_rule.src_addr.v4 = h->extended_hdr.parsed_pkt.ipv4_src;
   r.rule_family.accolade_rule.dst_addr_bits = 32;
   r.rule_family.accolade_rule.dst_addr.v4 = h->extended_hdr.parsed_pkt.ipv4_dst;
   r.rule_family.accolade_rule.protocol = h->extended_hdr.parsed_pkt.l3_proto;
   r.rule_family.accolade_rule.src_port_low = h->extended_hdr.parsed_pkt.l4_src_port;
   r.rule_family.accolade_rule.dst_port_low = h->extended_hdr.parsed_pkt.l4_dst_port;
   pfring_add_hw_rule(pd, &r);

Please note that all fields are in host byte order.

For a full list of supported fields please take a look at the hw_filtering_rule struct.
Please also note that mode 1 and 2 support different fields, please refer to the fields 
description to check what is supported in each mode.

Example of removing a filtering rule by id:

.. code-block:: c

   pfring_remove_hw_rule(pd, rule_id);

TX DMA
------

If you have an Accolade adapter (e.g. 200Ku-Flex) with a firmware supporting 
TX DMA for replaying PCAP files at line-rate up to 100G, you need to enable
both 2MB and 1G hugepages.

First of all you should check that your CPU supports 1G hugepages, running the
command below you should get some output:

.. code-block:: console

   grep pdpe1gb /proc/cpuinfo

In order to make sure that the system is able to reserve 1G pages from physical
memory, it is recommended to add the boot parameters below to GRUB_CMDLINE_LINUX
in /etc/default/grub:

.. code-block:: text

   default_hugepagesz=2MB hugepagesz=1GB hugepages=1 hugepagesz=2M hugepages=1024

In order to apply the changes, update grub and reboot the system:

.. code-block:: console

   sudo update-grub
   sudo reboot

After rebooting the system, you should mount the hugepages and reload the Accolade
driver: 

.. code-block:: console

   sudo sh -c "echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
   sudo mkdir /mnt/hugetlbfs1G
   sudo mount -t hugetlbfs none -opagesize=1G /mnt/hugetlbfs1G
   sudo insmod /opt/accolade/driver/anic_mem.ko mbytes_per_device=64
   sudo /opt/accolade/bin/anic_load

At this point you should be finally able to run the TX tool provided by Accolade,
example:

.. code-block:: console

   cd SDK_*/examples/; make
   sudo ./anic_200k_tx -i 0 -p 0 -r 1000000 mixed.pcap

