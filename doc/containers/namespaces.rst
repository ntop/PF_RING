Network Namespaces
==================

Docker, LXC, are Virtual Environments, with much less overhead compared to Virtual Machines as there is no Guest OS.
Containers are built on the following components:

- cgroups (Control Groups), limit and account resource usage of a collection of processes including CPU/ cores, memory, block I/O, network (tc, iptables).
- Namespaces, isolate and virtualize system resources of a collection of processes, including PIDs, hostnames, user IDs, network, filesystems.

Network namespaces virtualize the network stack: a network namespace is (logically) another copy of the network stack with its own network interfaces, iptables rules, routing tables, sockets.
On creation a network namespace only contains the loopback device, then you can create virtual interfaces or move physical interfaces to the namespace.
A network interface belongs to exactly one network namespace.
Containers usually use virtual interface pairs (veth driver), eth0 in the container namespace is paired (logically cross- connected) with vethXXX in the host namespace.

PF_RING exports sockets informations under /proc/net/pf_ring/, there is a /proc/net/pf_ring/ view for each namespace.

The *ip netns* command can be used to play with network namespaces as in the examples below.

Create a network namespace ns0:

.. code-block:: console

   ip netns add ns0

List all network namespaces:

.. code-block:: console

   ip netns list

Move a network interface eth1 to the network namespace ns0:

.. code-block:: console

   ip link set eth1 netns ns0

List all interfaces registered with pf_ring in the host (default namespace):

.. code-block:: console

   ls /proc/net/pf_ring/dev/

List all interfaces registered with pf_ring in the namespace ns0:

.. code-block:: console
   
   ip netns exec ns0 ls /proc/net/pf_ring/dev/

Bring the interface eth1 up in the namespace ns0:

.. code-block:: console

   ip netns exec ns0 ifconfig eth1 up

Run pfcount in the network namespace ns0 capturing from eth1:

.. code-block:: console

   ip netns exec ns0 pfcount -i eth1

Delete the network namespace ns0 (all interfaces in ns0 will move back to the host default namespace):

.. code-block:: console

   ip netns del ns0
