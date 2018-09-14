PF_RING FT (Flow Table)
=======================

PF_RING FT implements an optimized flow table that can be used to keep track of flows and
extract flow metadata including the L7 protocol thanks to the native integration with nDPI.
Using PF_RING FT it is possible to write an event-driven flow processing application focusing
on the actual flow processing rather then the flow table management and performance, in fact
it provides many hooks that can be used to customize and extend the core table for building 
any type of flow analysis application, including probes, IDSs, IPSs.

.. image:: img/pfring_ft.png

API Overview
------------

Designing and implementing a flow processing application on top of PF_RING FT is quite 
straightforward as it provides a clean API that can be used to do complex things in a 
few lines of code. The following code snippet shows how it is easy to capture traffic 
and export flow informations with PF_RING FT. 

.. code-block:: c

   ft = pfring_ft_create_table(flags, 0, 0, 0);
   
   pfring_ft_set_flow_export_callback(ft, processFlow, NULL);
   
   while (1) {
     if (pfring_recv(pd, &buffer_p, 0, &hdr, 0) > 0)
       action = pfring_ft_process(ft, p, (pfring_ft_pcap_pkthdr *) h);
   }
   
   void processFlow(pfring_ft_flow *flow, void *user){
     pfring_ft_flow_key *k = pfring_ft_flow_get_key(flow);
     pfring_ft_flow_value *v = pfring_ft_flow_get_value(flow);
     /* flow export here with metadata in k and v */
   }

The full example is available on github under `examples_ft <https://github.com/ntop/PF_RING/tree/dev/userland/examples_ft>`_.

Please note that the FT API is capture-agnostic, this means that it is possible to use any capture framework
for capturing raw traffic, in the example above we used PF_RING. When using PF_RING, there is no need to link
additional libraries as PF_RING FT is already part of PF_RING, instead when using other framework, the *libpfring_ft*
available under the `libs <https://github.com/ntop/PF_RING/tree/dev/userland/lib/libs>`_ folder need to be linked.

In order to write an application based on PF_RING FT, the first step is to create a *pfring_ft_table* object,
which represents a flow table instance, this can be done calling *pfring_ft_create_table*:

.. code-block:: c

   pfring_ft_table *ft = pfring_ft_create_table(flags, 0, 0, 0);

The *pfring_ft_create_table* parameters include flags that can be used to enable optional features like
L7 protocol detection based on nDPI (PFRING_FT_TABLE_FLAGS_DPI), and advanced settings to tune the flow
table size.

As introduced before, the flow of an application designed on top of PF_RING FT is event-driven,
before feeding the flow table with raw packets, the application can register for getting notified
when there is a new event through hooks. Those events include:

- New flow (*pfring_ft_set_new_flow_callback*)
- Packet classified (*pfring_ft_set_flow_packet_callback*)
- Flow expiration (*pfring_ft_set_flow_export_callback* or *pfring_ft_set_flow_list_export_callback*)

Registering for events notificaiton means setting a callback that will be called, for instance, when
a flow is expired and should be processed (e.g. exported in case of a Netflow application):

.. code-block:: c

   pfring_ft_set_flow_export_callback(ft, processFlow, NULL);

In this example, *processFlow* is the callback that will be called when the event is triggered.
This callback can access flow information including the flow key (5-tuple) and built-in flow data collected
by FT (please note that the application can extend this data accessing custom metadata with the 
*pfring_ft_flow_value.user* pointer), in order to compute actions based on the flow status. 

.. code-block:: c

   void processFlow(pfring_ft_flow *flow, void *user){
     pfring_ft_flow_value *v = pfring_ft_flow_get_value(flow);
     
     /* Example of printing the L7 protocol for this flow: */
     printf("l7: %s\n", pfring_ft_l7_protocol_name(ft, &v->l7_protocol, buf, sizeof(buf)));
   }

Finally, we need to feed the flow table with raw packets, this is achieved calling *pfring_ft_process* in
the main capture loop for every packet.

.. code-block:: c

   while (1) {
     if (pfring_recv(pd, &buffer_p, 0, &hdr, 0) > 0)
       action = pfring_ft_process(ft, p, (pfring_ft_pcap_pkthdr *) h);
   }

The *pfring_ft_process* function returns an action (default/forward/discard) in case the 
flow has been marked by the application (according to custom policies) or by the built-in filtering engine
as described in the following sections. This is where packet filtering should happen.

Before destroying the flow table with *pfring_ft_destroy_table*, it is recommended to call *pfring_ft_flush*
to process all flows that are still active and have not been exported yet.

For detailed information please refer to the `API documentation <https://www.ntop.org/guides/pf_ring_api/pfring__ft_8h.html>`_.

nDPI Integration
----------------

PF_RING FT is natively integrated with nDPI for providing L7 protocol information out of 
the box. The application itself does not need to deal with the nDPI library directly as 
everything happens behind the scenes. In order to get L7 information in the flow metadata 
in *pfring_ft_flow_value.l7_protocol*, all you need to do is:

1. install the nDPI library available at https://github.com/ntop/nDPI

.. code-block:: console

   git clone https://github.com/ntop/nDPI.git
   cd nDPI
   ./autogen.sh
   make && sudo make install

.. note::  If you are installing a **stable** version of PF_RING, you should also clone latest stable version of nDPI.

2. enable L7 detection through the *PFRING_FT_TABLE_FLAGS_DPI* flag:

.. code-block:: c

   ft = pfring_ft_create_table(PFRING_FT_TABLE_FLAGS_DPI);

3. read the L7 protocol from *pfring_ft_flow_value.l7_protocol*

L7 Filtering and Shunting
-------------------------

PF_RING FT features a L7 filtering engine that can be used for filtering flows based on the application 
protocol, or can be extended with custom policies.
This is usually the case for instance of IPSs, L7 firewalls, other inline applications. 
Using the built-in L7 filtering engine is possible by setting filtering rules through the API 
or through a configuration file.
The API provides functions to filter or shunt traffic (specifying the number of packets for each flow that 
are allowed to pass before discarding them) based on the application protocol. Example:

.. code-block:: c

   pfring_ft_set_filter_protocol_by_name(ft, "UPnP", PFRING_FT_ACTION_DISCARD);
   pfring_ft_set_shunt_protocol_by_name(ft, "SSH", 5);

It is also possible to specify filtering and shunting rules using a configuration file:

.. code-block:: text

   [shunt]
   default = 10
   tcp = 15
   udp = 2
   HTTP = 10
   
   [filter]
   YouTube = discard
   Netflix = discard

This file can be provided to the filtering engine using the *pfring_ft_load_configuration* API:

.. code-block:: c

   pfring_ft_load_configuration(ft, "/etc/ft_rules.conf");

The *pfring_ft_process* API returns PFRING_FT_ACTION_DISCARD as action for packets that should be
discarded according to the filtering or shunting policies.

In addition to the built-in filtering engine, the application can mark flows for filtering or shunting 
them based on custom policies using the *pfring_ft_flow_set_action* API.

IDS Acceleration
----------------

The PF_RING FT L7 filtering engine can also be used for accelerating CPU-bound applications, such as 
IDS/IPSs, shunting flows based on the application protocol. Discarding elephant flows is becoming a 
common yet effective practice for reducing the amount of traffic an IDS/IPS need to inspect (typically 
multimedia traffic), dramatically reducing packet loss and improving the system performance. 

Leveraging on PF_RING FT, any PF_RING-based or Libpcap-based application can take advantage of L7 
shunting without changing a single line of code, all you need to do is to set the *PF_RING_FT_CONF* 
environment variable with the path of the configuration file.

For example, if we want to filter out Youtube and Netflix traffic, we need to create a configuration
file like the one below:

.. code-block:: console
   
   # cat /etc/pf_ring/ft-rules.conf
   [filter]
   YouTube = discard
   Netflix = discard

And run Suricata on top of PF_RING, setting the *PF_RING_FT_CONF* environment variable according
to the configuration file path:

.. code-block:: console
   
   # PF_RING_FT_CONF=/etc/pf_ring/ft-rules.conf suricata --pfring-int=zc:eth1 -c /etc/suricata/suricata.yaml

Please refer to the `Using Suricata with PF_RING <https://www.ntop.org/guides/pf_ring/thirdparty/suricata.html#pf-ring-ft-acceleration>`_ 
and `Using Bro with PF_RING <https://www.ntop.org/guides/pf_ring/thirdparty/bro.html#pf-ring-ft-acceleration>`_
guides for enabling PF_RING FT support in Suricata and Bro. Note that the same acceleration can be used with other 
IDSs like Snort.

