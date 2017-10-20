# Netcope support in PF_RING

PF_RING has native support for Netcope adapters, the Netcope NSF library
needs to be installed in order to enable the Netcope module at runtime.

## Installation
In order to install the Netcope driver run the following commands:

```
./nsf-100g2q-1.3.5.bin
```

Then load the firmware with:

```
csboot -f100 /usr/share/mcs/nsf/1.3.5/nfb-100g2q/100g1/firmware.bit
```

If the NSF firmware is already loaded in the card it's possible to reload it
with the following command:

```
nsftool reload --file=/usr/share/mcs/nsf/1.3.5/nfb-100g2q/100g1/firmware.bit
```

Now you are ready to compile and run PF_RING with Netcope support.
Note that if you are installing pfring from packages, Netcope support
is already enabled.

```
cd PF_RING/kernel; make
sudo insmod pf_ring.ko; cd ..
cd userland; ./configure
cd lib; make; cd ..
cd libpcap; ./configure; make; cd ..
cd examples; make
```

## Usage

In order to run a capture session using a Netcope card, use the nsf prefix:

```
sudo ./pfcount -i nsf:0
```

Please note that:
 - in order to open port 0 from adapter 0 you should specify "nsf:0:0" 
   (nsf:CARD:PORT) or just "anic:0" (anic:PORT) if device is 0.
 - in order to open a single queue, for instance queue 0, from port 0 
   you should specify "anic:0@0" (nsf:CARD@RING).
