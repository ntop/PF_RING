# Accolade support in PF_RING

## Prerequisite
Accolade SDK v.1.2.17.20150903 or later installed.

PF_RING has native support for Accolade adapters, the Accolade library
needs to be installed (under /opt/accolade) in order to enable the 
Accolade module at runtime.

## Installation
In order to get up and running with Accolade just run 
the following commands:

```
tar xvzf SDK_*.tgz
cd SDK_*
cd drv; make install; cd ..
cd lib; make install; cd ..

echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

cd /opt/accolade/
insmod driver/anic_mem.ko mbytes_per_device=64
cd bin
./anic_load

cd PF_RING/kernel
make
sudo insmod pf_ring.ko
cd ../userland/lib
./configure
make
cd ../libpcap
./configure
make
cd ../examples
make
sudo ./pfcount -i anic:0
```

Please note that:
 - in order to open port 0 from adapter 0 you should specify "anic:0:0" 
   (anic:<device>:<port>) or just "anic:0" (anic:<port>) if device is 0.
   Opening a port this way, the full card is initialised, causing issues
   when opening other ports later (previous ports stop working): this can
   be avoided using the port-to-ring binding as explained later on.
 - in order to open ring 0 from adapter 0 you should specify "anic:0@0"
   (anic:<device>@<ring>). This is usually used in combination with
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
