# CoreOS Container Linux PF_RING Drivers

The scripts in this folder compile and install the PF_RING kernel module and drivers on CoreOS Container Linux. 

Please note that CoreOS ships without compiler toolchain and without kernel sources, 
for this reason compilation happens in a container, using kernel sources of the host system.
Please also note that a system update changes the kernel requiring modules recompilation.

## Installation

Running the build.sh script it will compile and install the pf_ring kernel module and all the ZC drivers.
It is possible to select the pf_ring version to install changing the branch name in the PF_RING_VERSION variable in build.sh.

```
git clone https://github.com/ntop/PF_RING.git
cd PF_RING/package/coreos
./build.sh
```

After that you are ready to load the kernel modules installed on the host under /opt/pf_ring, example:

```
sudo insmod /opt/pf_ring/7.2.0-stable/$(cat /etc/os-release|grep VERSION=|cut -d= -f2)/lib64/modules/$(uname -r)/kernel/net/pf_ring/pf_ring.ko
```

## Test

In order to test the drivers you can use the pfring image available on Docker Hub:

```
docker run --net=host ntop/pfring:stable pfcount -i enp0s3
```

## Additional Notes

Kubernetes support will be added asap.

The scripts in this folder are based on https://github.com/BugRoger/coreos-nvidia-driver,
read also https://coreos.com/os/docs/latest/kernel-modules.html for more info.

