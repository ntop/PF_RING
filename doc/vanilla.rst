Vanilla PF_RING
===============

Vanilla PF_RING consists of:

1. The accelerated kernel module that provides low-level packet copying into the PF_RING rings.
2. The user-space PF_RING SDK that provides transparent PF_RING-support to user-space applications.

PF_RING implements a socket type on which user-space applications can speak with the PF_RING kernel module. 
Applications can obtain a PF_RING handle, and issue API calls that are described later in this manual. 
A handle can be bound to a:

1. Physical network interface.
2. A RX queue, only on multi-queue network adapters.
3. To the ‘any’ virtual interface that means packets received/sent on all system interfaces are accepted.

As specified above, packets are read from a memory ring allocated at creation time. 
Incoming packets are copied by the kernel module to the ring, and read by the user-space applications. 
No per-packet memory allocation/deallocation is performed. Once a packet has been read from the ring, 
the space used in the ring for storing the packet just read will be used for accommodating future packets. 
This means that applications willing to keep a packet archive, must store themselves the packets just read 
as the PF_RING will not preserve them.

Packet Filtering
----------------

PF_RING supports both legacy BPF filters (i.e. those supported by pcap-based applications such as tcpdump), 
and also two additional types of filters (named wildcard and precise filters, depending on the fact that 
some or all filter elements are specified) that provide developers a wide choice of options. 
Filters are evaluated inside the PF_RING module thus in kernel. Some modern adapters such as Intel 82599-based 
or Silicom Redirector NICs, support hardware-based filters that are also supported by PF_RING via specified 
API calls (e.g. pfring_add_hw_rule). PF_RING filters (except hw filters) can have an action specified, for 
telling to the PF_RING kernel module what action needs to be performed when a given packet matches the filter. 
Actions include pass/don’t pass the filter to the user space application, stop evaluating the filter chain, or 
reflect packet. In PF_RING, packet reflection is the ability to transmit (unmodified) the packet matching the 
filter onto a network interface (this except the interface on which the packet has been received). The whole 
reflection functionality is implemented inside the PF_RING kernel module, and the only activity requested to 
the user-space application is the filter specification without any further packet processing.

Packet Clustering
-----------------

PF_RING can also increase the performance of packet capture applications by implementing two mechanisms named 
balancing and clustering. These mechanisms allow applications, willing to partition the set of packets to 
process, to handle a portion of the whole packet stream while sending all the remaining packets to the other
members of the cluster. This means that different applications opening PF_RING sockets can bind them to a 
specific cluster Id (via pfring_set_cluster) for joining the forces and each analyze a portion of the packets.

The way packets are partitioned across cluster sockets is specified in the cluster policy that can be either 
per-flow (i.e. all the packets belonging to the same tuple <proto, ip src/dst, port src/dst>) that is the 
default or round-robin. This means that if you select per-flow balancing, all the packets belonging to the 
same flow (i.e. the 5-tuple specified above) will go to the same application, whereas with round-robin all 
the apps will receive the same amount of packets but there is no guarantee that packets belonging to the same 
queue will be received by a single application. So in one hand per-flow balancing allows you to preserve the 
application logic as in this case the application will receive a subset of all packets but this traffic will 
be consistent. On the other hand if you have a specific flow that takes most of the traffic, then the 
application that will handle such flow will be over-flooded by packets and thus the traffic will not be heavily 
balanced.

