Load Balancing / RSS
====================

Processing traffic from the network adapter using a single stream requires 
a single CPU core to be able to keep up with the ingress rate. At high rates
this becames a bottleneck even with lightweight traffic processing due to 
the limited amount of CPU cycles available per packet. Evenly distribute 
traffic from a single interface across multiple streams (aka channels or 
queues) while maintaining flow continuity is usually the best option for
scaling the performance, as long as our application is designed to work
with multiple threads or processes and run on multiple CPU cores.

RSS (Receive Side Scaling)
--------------------------

Almost all Intel (and other vendors) NICs have RSS support, this means they
are able to hash packets in hardware in order to distribute the load across 
multiple RX queues. In some cases RSS is not available or not flexible 
enough (e.g. a custom distribution function is needed) and it can be 
replaced by software distribution using ZC.

In order to configure the number of queues, you can use the RSS parameter at 
insmod time (if you are installing PF_RING ZC drivers from packages you can 
use the configuration file as explained in the installation instructions), passing 
a comma-separated list (one per interface) of numbers (number of queues per
interface). Examples:

Enable as many queues as the number of processors, per interface:

.. code-block:: console

   insmod ixgbe.ko RSS=0,0,0,0

Enable 4 RX queues per interface:
 
.. code-block:: console

   insmod ixgbe.ko RSS=4,4,4,4

Disable multiqueue (1 RX queue per interface):

.. code-block:: console

   insmod ixgbe.ko RSS=1,1,1,1

Alternatively it is possible to configure the number of RX queues at runtime
using ethtool:

.. code-block:: console

   ethtool --set-channels <if> combined 1

RSS distributes the load across the specified number of RX queues based on an 
hash function which is IP-based (or IP/Port-based in case of TCP), in combination 
with an indirection table: queue = indirection_table[hash(packet)]
You can see the content of the indirection table with:

.. code-block:: console

   ethtool -x <if>

It is possible to configure the indirection table by simply applying weights 
to each RX queue using ethtool. For instance if we want all traffic to go to
queue 0, and we configured the card with 4 RX queues, we can use the command
below:

.. code-block:: console

   ethtool -X <if> weight 1 0 0 0

When using PF_RING ZC, RSS is reconfigured by the PF_RING ZC driver on most Intel 
adapter families. However, on some adapters (e.g. *ice* adapters) PF_RING ZC keeps 
the RSS configuration created by the linux driver and ethtool should be used to 
tune RSS settings. For example, to set packet hashing based on the 4-tuple on *ice*
adapters, which is source and destination IP and port (default), it is possible to use:

.. code-block:: console

   ethtool -N enp1s0f1 rx-flow-hash tcp4 sdfn
   ethtool -N enp1s0f1 rx-flow-hash udp4 sdfn

Or to set packet hashing based on the 2-tuple, which is source and destination IP only
it is possible to use:

.. code-block:: console

   ethtool -N enp1s0f1 rx-flow-hash tcp4 sd
   ethtool -N enp1s0f1 rx-flow-hash udp4 sd

Where in 'sdnf' and 'sd':

- s: Source IP address
- d: Destination IP address
- f: Source port
- n: Destination port

RSS with GTP
~~~~~~~~~~~~

When it comes to process GTP traffic at scale, and we want to leverage on RSS
to distribute the packet processing load, using a basic RSS configuration
is often not a viable solution. Let's assume for instance that we want to process
GTP-C traffic using a dediceted process, and load balance GTP-U traffic to
multiple processes or threads: this is possible using an advanced RSS configuration
combined with flow steering. In order to achieve this just follow the steps below:

1. Configure the card with 8 (or any number of) RX queues.

.. code-block:: console

   ethtool --set-channels <if> combined 8

2. Send all GTP-C traffic to the first queue. We use the flow director for this,
supported on most Intel (e.g. E810) and NVIDIA/Mellanox (ConnectX) adapters.

.. code-block:: console

   ethtool -U <if> flow-type udp4 src-port 2123 action 0

(Note: "action 0" means "steer to queue 0")

2. Distribute all non GTP-C traffic to the other queues.

.. code-block:: console

   ethtool -X <if> weight 0 1 1 1 1 1 1 1

(Note: traffic is distributed with queues with weight != 0)

Naming convention
~~~~~~~~~~~~~~~~~

In order to open a specific interface queue, you have to specify the queue ID
using the "@<ID>" suffix. Example:

.. code-block:: console

   pfcount -i zc:eth1@0

Please note that if you configure an interface with multiple RSS queues, and
you open it using ZC with zc:eth1, this is the same as opening zc:eth1@0.
This does not apply in standard kernel mode, where kernel abstracts the
interface and capturing from eth1 means capturing from all the queues. This
happens because ZC is a kernel-bypass technology, thus there is no abstraction,
and the application directly opens an interface queue, which corresponds to the
full interface only when RSS=1.

PF_RING Cluster (Kernel)
------------------------

Since not all network adapters feature RSS support to distribute the load across 
multiple RX queues in hardware, the PF_RING kernel module implements a mechanisms 
named clustering to partition and load-balance traffic across processes. This 
means that different applications opening PF_RING sockets can bind them to a 
specific cluster ID (via pfring_set_cluster) for joining the forces and each 
analyze a portion of the packets.
The way packets are partitioned across cluster sockets is specified in the cluster 
policy. The default policy is per-flow (i.e. all the packets belonging to the same 
5-tuple <proto, ip src/dst, port src/dst>), however there are a few options. This
way all packets belonging to the same flow will go to the same application, preserving
the application logic as traffic will be consistent.
An example of kernel clustering is provided by pfcount:

.. code-block:: console

   pfcount -i eth1 -c 10 -H 5
   
Where:

- -c 10 specifies the Cluster ID
- -H 5 specifies the load-balancing policy:
   -  1 - round-robin
   -  2 - src ip,           dst ip 
   -  3 - src ip, src port, dst ip, dst port
   -  4 - src ip, src port, dst ip, dst port, proto (default)
   -  0 - src ip, src port, dst ip, dst port, proto, vlan
   -  5 - src ip, src port, dst ip, dst port, proto for TCP, src ip, dst ip otherwise
   -  7 - tunneled src ip,           dst ip
   -  8 - tunneled src ip, src port, dst ip, dst port
   -  9 - tunneled src ip, src port, dst ip, dst port, proto (default)
   -  6 - tunneled src ip, src port, dst ip, dst port, proto, vlan
   - 10 - tunneled src ip, src port, dst ip, dst port, proto for TCP, src ip, dst ip otherwise                  
   
Note: kernel clustering cannot be used in combination with ZC driver as ZC is a 
kernel-bypass technology.

ZC Cluster (zbalance_ipc)
-------------------------

There are cases where RSS cannot be used for traffic load-balancing, because:

- it is not always available (e.g. if you are not using an Intel adapter) 
- for some use case it is not flexible enough and a custom distribution function is needed (e.g. tunneled traffic like GTP)
- when the same traffic needs to be delivered to different application, but we are using ZC that locks the network interface (we cannot have multiple applications capturing traffic from the same interface at the same time) 
- when the same traffic needs to be delivered to different application, but we need a different number of streams per application (e.g. we want to load-balance traffic to 4 nProbe instances for Netflow generation, and 1 n2disk instance for traffic recording)

In the above situations, RSS can be replaced by software distribution using ZC,
either writing a custom application on top of the ZC API, or leveraging on the
*zbalance_ipc* application distributed with PF_RING. *zbalance_ipc* is a process
that can be used for capturing traffic from one or more interfaces, and 
load-balancing packets to multiple consumer processes.
Please note that in order to use *zbalance_ipc*, RSS should be disabled.

Example of traffic aggregation from 2 interfaces, and load-balancing to 2 
processes using an IP-based hash:

.. code-block:: console

   zbalance_ipc -i zc:eth1,zc:eth2 -n 2 -m 1 -c 10 -g 1

Where:

- -n specifies the number of egress queues
- -m selects the hash function (there are a few options available, or it is possible to write a custom one)
   - 0: Round-Robin (default)
   - 1: IP hash
   - 2: Fan-out
   - 3: Fan-out (1st) + Round-Robin (2nd, 3rd, ..)
   - 4: GTP hash (Inner IP/Port or GTP-C Seq-Num)
   - 5: GRE hash (Inner or Outer IP)
   - 6: Interface X to queue X
- -g is the core affinity for the capture/distribution thread
- -c specifies the ZC cluster ID

The example above creates 2 streams, that can be opened by a consumer application 
as standard PF_RING interfaces (zc:10@0 and zc:10@1). Example:

.. code-block:: console

   nprobe -i zc:10@0
   nprobe -i zc:10@1

In a similar way, it is possible to load-balance the traffic to multiple
applications, each having multiple threads/processes:

.. code-block:: console

   zbalance_ipc -i zc:eth1,zc:eth2 -n 2,1 -m 1 -c 10 -g 1

Where -n 2,1 means:

- load-balance the traffic to 2 queues
- send a full copy of the traffic to 1 more queue

This is the case for instance of nProbe and n2disk processing the same traffic:

.. code-block:: console

   nprobe -i zc:10@0
   nprobe -i zc:10@1
   n2disk -i zc:10@2 -o /storage

Using ZC Cluster with systemd
-----------------------------

*zbalance_ipc* can be controlled using *systemctl* on operating systems
and distributions that use the *systemd* service manager, configuring the
*cluster* service shipped with the *pfring* package.

Since multiple clusters are often required, multiple instances of the 
*cluster* service may run on the same host. To manage a particular cluster
*<instance>* append *@<instance>* to the *cluster* service name.
Typically, *<instance>* corresponds to the cluster ID (e.g., *10* in the
examples above). The *<instance>* uniquely identifies a service and its 
corresponding configuration file that is located under */etc/cluster/cluster-<instance>.conf*.

For example, to start a *cluster* instance, one can create the following 
configuration file containing all the command line options (see -h) one
per line. Example:

.. code-block:: console

   cat /etc/cluster/cluster-10.conf
   -i=zc:eth1
   -n=2,1
   -m=1
   -c=10
   -g=1

And then start the services with:

.. code-block:: console

   systemctl start cluster@10

Optionally, one may want to enable the service to start at boot with:

.. code-block:: console

   systemctl enable cluster@10

The status of the service can be controlled with:

.. code-block:: console

   systemctl status cluster@10

When using a cluster to feed nprobe or n2disk, it is highly recommended
to use the following naming scheme to make service dependencies explicit:

APPLICATION-cluster_CLUSTERID-INSTANCEID.conf

For example when using nprobe and attaching to cluster 10 queue 0 the configuration
file path would be:

.. code-block:: console

   /etc/nprobe/nprobe-cluster_10-0.conf

The service can be controlled with:

.. code-block:: console

   systemctl status nprobe@cluster_10-0

