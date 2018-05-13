PF_RING FT (Flow Table)
=======================

PF_RING FT implements a flow table that can be used to keep track of flows and provides 
many hooks to be able to customize and extend it for building any type of application on 
top of it, including probes, IDSs, IPSs.

API
---

Designing and implementing a flow processing application on top of PF_RING FT is quite 
straightforward as it provides a clean API that can be used to do complex things in a 
few lines of code. The following code snippet shows how it is easy to capture traffic 
and export flow informations with PF_RING FT. The full example is available on github 
at https://github.com/ntop/PF_RING/tree/dev/userland/examples_ft. 
For more information about the API, please refer to the Doxygen documentation.

.. code-block:: c

   ft = pfring_ft_create_table(0);
   
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

Where:

1. *pfring_ft_create_table* creates a new flow table
2. *pfring_ft_set_flow_export_callback* sets a callback (processFlow) that will be called 
   when a new flow is created in the flow table
3. *pfring_ft_process* should be called for every packet in order to process and classify it. 

The *pfring_ft_process* function returns an action (default/forward/discard) in case the 
flow has been marked by the filtering engine or by the application according to custom 
policies (this is where packet filtering should happen, based on the action).

The flow of an application designed on top of PF_RING FT is event-driven. Through a few 
hooks it is possible to register to events like:

- New flow (see *pfring_ft_set_new_flow_callback*)
- Packet classified (see *pfring_ft_set_flow_packet_callback*)
- Flow expiration (see *pfring_ft_set_flow_export_callback* and *pfring_ft_set_flow_list_export_callback*)

and access the flow informations in order to compute actions based on the flow status. 
Flow informations can be extended with custom metadata defined by the application (see *pfring_ft_flow_value.user*).

nDPI Integration
----------------

PF_RING FT is natively integrated with nDPI for providing L7 protocol informations out of 
the box. The application itself does not need to deal with the nDPI library directly as 
everything happens behind the scenes. In order to get the L7 protocol in the flow metadata, 
you need to:

1. install the nDPI library available at https://github.com/ntop/nDPI

.. code-block:: console

   git clone https://github.com/ntop/nDPI.git
   ./autogen
   make && make install

2. enable L7 detection through the *PFRING_FT_TABLE_FLAGS_DPI* flag:

.. code-block:: c

   ft = pfring_ft_create_table(PFRING_FT_TABLE_FLAGS_DPI);

3. read the L7 protocol from *pfring_ft_flow_value.l7_protocol*

L7 Filtering and Shunting
-------------------------

PF_RING FT features a L7 filtering engine that can be used by inline applications for 
filtering flows based on the application protocol. In addition to the built-in filtering 
engine, the application can mark flows for filtering or shunting them based on custom policies.
This is possible by setting filtering rules through the API (pfring_ft_set_filter_* / pfring_ft_set_shunt_*) 
or through a configuration file:

.. code-block:: text

   [shunt]
   default = 10
   tcp = 15
   udp = 2
   HTTP = 10
   
   [filter]
   YouTube = discard
   Netflix = discard

The *pfring_ft_process* API returns "discard" as action for packets that should be
discarded according to the filtering or shunting policies.

IDS Acceleration
----------------

The PF_RING FT L7 filtering engine can also be used for accelerating CPU-bound applications, 
such as IDS/IPSs, shunting flows based on the application protocol. Discarding elephant flows 
is becoming a common yet effective practice for reducing the amount of traffic an IDS/IPS need 
to inspect (typically multimedia traffic), dramatically reducing packet loss and improving the 
system performance. Leveraging on PF_RING FT, a PF_RING-based or Libpcap-based application can 
take advantage of L7 shunting without changing a single line of code, all you need to do is to 
set the *PF_RING_FT_CONF* environment variable with the path of the configuration file.
In the example below, we run Suricata on top of PF_RING FT, filtering out Youtube and Netflix
traffic. Please refer to the "Using Suricata with PF_RING" guide for enabling PF_RING support
in Suricata. The same can be achieved with other IDS/IPSs like Bro and Snort.

.. code-block:: console

   # PF_RING_FT_CONF=/etc/pf_ring/ft-rules.conf suricata --pfring-int=zc:eth1 -c /etc/suricata/suricata.yaml
   
   # cat /etc/pf_ring/ft-rules.conf
   [filter]
   YouTube = discard
   Netflix = discard
