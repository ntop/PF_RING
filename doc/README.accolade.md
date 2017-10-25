# Accolade support in PF_RING

## Prerequisite
Accolade SDK v.1.2.17.20150903 or later installed.

PF_RING has native support for Accolade adapters, the Accolade library
needs to be installed (under /opt/accolade) in order to enable the 
Accolade module at runtime.

## Installation
In order to install the Accolade driver run the following commands:

```
tar xvzf SDK_*.tgz
cd SDK_*
cd drv; make install; cd ..
cd lib; make install; cd ..
```

Then load the driver with:

```
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
insmod /opt/accolade/driver/anic_mem.ko mbytes_per_device=64
/opt/accolade/bin/anic_load
```

If you are running an old firmware and you need to update it, you should
run the following commands: 

```
cd SDK_*/tools/
gunzip fpga_*.rbt.gz
./anic_fwupdate --id 0 --script fpga_*.rbt
reboot
```

Now you are ready to compile and run PF_RING with Accolade support.
Note that if you are installing pfring from packages, Accolade support
is already enabled.

```
cd PF_RING/kernel; make
sudo insmod pf_ring.ko; cd ..
cd userland; ./configure
cd lib; make; cd ..
cd libpcap; ./configure; make; cd ..
cd examples; make
sudo ./pfcount -i anic:0
```

Please note that:
 - in order to open port 0 from adapter 0 you should specify "anic:0:0" 
   (anic:DEV:PORT) or just "anic:0" (anic:PORT) if device is 0.
   Opening a port this way, the full card is initialised, causing issues
   when opening other ports later (previous ports stop working): this can
   be avoided using the port-to-ring binding as explained later on.
 - in order to open ring 0 from adapter 0 you should specify "anic:0@0"
   (anic:DEV@RING). This is usually used in combination with
   anic_rx_block_mfl which is used to setup the card for multi-process
   applications. 
   Example of ports aggregation and load-balancing to 2 rings:
     anic_rx_block_mfl -i 0 --mode=2 
   Example of port-to-ring (ring 0 is port 0) binding:
     anic_rx_block_mfl -i 0 --mode=port

## Accolade and Packet Copy
If you use the PF_RING (non-ZC) API packets are read in zero-copy. Instead
if you use PF_RING ZC API, a per-packet copy takes place, which is required to move
payload data from Accolade-memory to ZC memory. Keep this in mind!

## Hw Filtering
Accolade adapters support packet filtering in hw. In order to set an
hw filter there are two options:

- Using the standard BPF filter: PF_RING thanks to the nBPF library 
  automatically translates BPF filters into hw filters

- Using the pfring_add_hw_rule() API.
  Example of setting the default action to 'forward':
```
hw_filtering_rule r = {0};
r.rule_family_type = accolade_default;
r.rule_family.accolade_rule.action = accolade_forward;
pfring_add_hw_rule(pd, &r);
```
  Example of setting a filtering rule with 'drop' action for an IPv4 packet we received:
```
hw_filtering_rule r = { 0 };
r.rule_family_type = accolade_rule;
r.rule_family.accolade_rule.action = accolade_drop;
r.rule_family.accolade_rule.ip_version = h->extended_hdr.parsed_pkt.ip_version;
r.rule_family.accolade_rule.src_addr_bits = 32;
r.rule_family.accolade_rule.src_addr.v4 = h->extended_hdr.parsed_pkt.ipv4_src;
r.rule_family.accolade_rule.protocol = h->extended_hdr.parsed_pkt.l3_proto;
r.rule_family.accolade_rule.src_port_low = h->extended_hdr.parsed_pkt.l4_src_port;
pfring_add_hw_rule(pd, &r);
```
For a full list of supported fields please take a look at the hw_filtering_rule struct.
