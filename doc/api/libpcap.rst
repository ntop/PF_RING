Libpcap API
===========

PF_RING includes a patched libpcap which provides PF_RING acceleration through the
legagy pcap API. Obviously a pcap-based application should be linked against the 
PF_RING-aware libpcap in order to use it. Please expect a performance degradation
with respect to the PF_RING API as the pcap API introduces some more overhead.

API Extensions
--------------

This section lists the extensions added to the legacy pcap API. Please note that
they are not mandatory to operate, a legacy pcap-based application can work on top
of this library with no changes (linking only is required).

* pcap_get_pfring_handle - returns the pfring handle.
* pcap_get_pfring_id - wrapper for the pfring_get_ring_id API.
* pcap_set_master_id - wrapper for the pfring_set_master_id API.
* pcap_set_master - wrapper for the pfring_set_master API.
* pcap_set_application_name - wrapper for the pfring_set_application_name API.
* pcap_set_cluster - wrapper for the pfring_set_cluster API.
* pcap_set_watermark - wrapper for the pfring_set_poll_watermark API.
* pcap_set_poll_watermark_timeout - wrapper for the pfring_set_poll_watermark_timeout API.

Environment Variables
~~~~~~~~~~~~~~~~~~~~~

This section lists environment variables supported the extended pcap library
in order to control the working mode without changing the pcap-based application.

* PCAP_PF_RING_ACTIVE_POLL - set active polling (CPU spinning)
* PCAP_PF_RING_RSS_REHASH - set in-kernel RSS rehash with standard drivers
* PCAP_PF_RING_ALWAYS_SYNC_FD - always sync the file descriptor after receive
* PCAP_PF_RING_ZC_RSS - set symmetric RSS on ZC drivers
* PCAP_PF_RING_STRIP_HW_TIMESTAMP - set hardware timestamping stripping from packets
* PCAP_PF_RING_HW_TIMESTAMP - enable hardware timestamping
* PCAP_PF_RING_USERSPACE_BPF - force userspace BPF in place of in-kernel BPF evaluation
* PCAP_PF_RING_RECV_ONLY - set receive only mode to the socket
* PCAP_PF_RING_APPNAME - set the application name
* PCAP_PF_RING_CLUSTER_ID - set the kernel cluster ID

Environment variables to control the in-kernel cluster distribution function:

* PCAP_PF_RING_USE_CLUSTER_PER_FLOW
* PCAP_PF_RING_USE_CLUSTER_PER_FLOW_2_TUPLE
* PCAP_PF_RING_USE_CLUSTER_PER_FLOW_4_TUPLE
* PCAP_PF_RING_USE_CLUSTER_PER_FLOW_5_TUPLE (Default)
* PCAP_PF_RING_USE_CLUSTER_PER_FLOW_TCP_5_TUPLE
* PCAP_PF_RING_USE_CLUSTER_ROUNDROBIN
* PCAP_PF_RING_USE_CLUSTER_PER_INNER_FLOW
* PCAP_PF_RING_USE_CLUSTER_PER_INNER_FLOW_2_TUPLE
* PCAP_PF_RING_USE_CLUSTER_PER_INNER_FLOW_4_TUPLE
* PCAP_PF_RING_USE_CLUSTER_PER_INNER_FLOW_5_TUPLE
* PCAP_PF_RING_USE_CLUSTER_PER_INNER_FLOW_TCP_5_TUPLE
* PCAP_PF_RING_USE_CLUSTER_PER_FLOW_IP_5_TUPLE
* PCAP_PF_RING_USE_CLUSTER_PER_INNER_FLOW_IP_5_TUPLE
* PCAP_PF_RING_USE_CLUSTER_PER_FLOW_IP_WITH_DUP_TUPLE

