Using PF_RING with Bro
----------------------

In order to use Bro on top of pf_ring support please follow this guide.

1. Install the "pfring" package (and optionally "pfring-drivers-zc-dkms"
if you want to use ZC drivers) from http://packages.ntop.org as explained
in README.apt_rpm_packages

2. Download Bro from https://www.bro.org/download/

wget https://www.bro.org/downloads/release/bro-X.X.X.tar.gz
tar xvzf bro-*.tar.gz

3. Configure and install Bro

./configure --with-pcap=/usr/local/lib
make
make install

4. Make sure Bro is correctly linked to pf_ring-aware libpcap:

ldd /usr/local/bro/bin/bro | grep pcap
        libpcap.so.1 => /usr/local/lib/libpcap.so.1 (0x00007fa371e33000)


5. Configure the node configuration file (node.cfg) with:
 lb_method=pf_ring 
 lb_procs=<number of processes you want to run>
 pin_cpus=<core affinity for the processes (comma-separated list)>

Example:

[worker-1]
type=worker
host=10.10.10.1
interface=eth1
lb_method=pf_ring
lb_procs=8
pin_cpus=0,1,2,3,4,5,6,7

If you installed the ZC drivers, you can configure the number of RSS queues,
as explained in README.apt_rpm_packages (or running "ethtool -L eth1 combined <num>"),
to the same number of processes in lb_procs, and use zc:ethX as interface name.

Example:
		
[worker-1]
type=worker
host=10.10.10.1
interface=zc:eth1
lb_method=pf_ring
lb_procs=8
pin_cpus=0,1,2,3,4,5,6,7
		
Another option for distributing the load using ZC is using zero-copy software 
distribution with zbalance_ipc. This configuration requires RSS set to single 
queue.
Run zbalance_ipc *before* running bro with:
zbalance_ipc -i zc:eth1 -c 99 -n 8 -m 1 -g 8
Where:
-c 99 is the cluster ID
-n 8 is the number of queues
-g 8 is core affinity for zbalance_ipc
You should use as interface name zc:<cluster id> as in the example below.

Example:

[worker-1]
type=worker
host=10.10.10.1
interface=zc:99
lb_method=pf_ring
lb_procs=8
pin_cpus=0,1,2,3,4,5,6,7

