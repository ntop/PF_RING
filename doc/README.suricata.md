# PF_RING Support in Suricata

In order to compile Suricata with pf_ring support please follow this guide:

https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Installation_of_Suricata_stable_with_PF_RING_(STABLE)_on_Ubuntu_server_1204

# Installation

```
git clone https://github.com/ntop/PF_RING.git
cd PF_RING/kernel
make && sudo make install

cd PF_RING/userland/lib
./configure && make && sudo make install

git clone https://github.com/inliniac/suricata.git
cd suricata
git clone https://github.com/OISF/libhtp
./autogen.sh
LIBS="-lrt" ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
--enable-pfring --with-libpfring-includes=/usr/local/include \
--with-libpfring-libraries=/usr/local/lib
make
sudo make install
sudo ldconfig

make install-conf
make install-rules

suricata --build-info | grep PF_RING
PF_RING support:                         yes
```

## Standard Mode

```
sudo modprobe pf_ring

sudo suricata --pfring-int=eth0 --pfring-cluster-id=99 --pfring-cluster-type=cluster_flow -c /etc/suricata/suricata.yaml
```

## ZC Mode

```
cd PF_RING/drivers/ZC/intel/ixgbe/ixgbe-*-zc/src/
make && sudo ./load_driver.sh

sudo suricata --pfring-int=zc:eth1 -c /etc/suricata/suricata.yaml
```

