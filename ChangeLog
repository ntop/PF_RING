
---------------------------------------                                                                                                                                                                             
2018-06-12 PF_RING 7.1

* ZC Library
 - New API pfring_zc_pkt_buff_pull / pfring_zc_pkt_buff_push to manage buffer head room
 - New builtin hash pfring_zc_builtin_gre_hash with support for GRE tunneling
   - zbalance_ipc -m 5 option for enabling GRE hashing
 - Support for up to 64 queues in pfring_zc_send_pkt_multi and pfring_zc_distribution_func
 - Fix for attaching to ZC IPC queues from containers

* FT Library (New)
 - L7 flow classification and filtering library
 - Event-driven capture-agnostic API
 - Sample applications
   - ftflow: flow records generation with PF_RING capture
   - ftflow_pcap: flow records generation with PCAP capture
   - ftflow_dpdk: flow records generation with DPDK capture
   - fttest: performance benchmarking tool
   - zbalance_ipc extension to process flows and filter packets

* nBroker (New)
 - Traffic steering and filtering on Intel RRC (FM10K adapters)
 - Daemon to drive the adapter (nbrokerd)
 - API to configure the adapter using a C library (nbrokerlib)
 - Command-line tool with auto-completion to configure the adapter using scripts (nbroker-cli)
 - Low-level library used by nbrokerd to drive the adapter (rrclib)

* PF_RING-aware Libpcap
 - PCAP_PF_RING_USERSPACE_BPF env var to force userspace filtering instead of kernel filtering

* PF_RING Kernel Module
 - Full support for namespaces and containers
 - Fixed skbuff forwarding with fast-tx using reflect_packet
 - Fixed VLAN support in BPF with kernel extensions
 - Fixed support for NetXtreme cards with multiple queues
 - Fixed sw hash filtering for IPv6
 - Fixed intel_82599_perfect_filter_hw_rule VLAN byte order
 - Fixed huge rings (high number of slots or huge slot size)
 - Fixed VLAN offset and packet hash in case of QinQ and VLAN offload
 - Support for Ubuntu 18
 - Support for latest Centos 7 kernel
 - Support for latest Debian 8 kernel

* PF_RING Capture Modules
 - Released source code for FPGA capture modules including Endace, Exablaze, Inveatech, Mellanox, Netcope
 - Accolade lib updates
   - New flag PF_RING_FLOW_OFFLOAD_NOUP to enable flow offload without flow updates (standard raw packets are received, flow id is in the packet hash)
   - Automatically generate the rule ID using rule_id = FILTERING_RULE_AUTO_RULE_ID
   - Support for accolade 200Ku Flex adapters
 - Fiberblaze lib updates
   - Packet recv in chunk mode
 - Fixed extraction from npcap/timeline in case of empty PCAP files in the dump set
 - Endace DAG updates
   - Setting extended_hdr.pkt_hash from ERF FlowID or Packet Signature extension headers if available
   - Support for pfring_set_application_name
   - Support for pfring_dag_findalldevs
 - Napatech lib updates
   - Support for sdk v10

* Drivers
 - e1000e zc driver update v.3.4.0.2
 - i40e zc driver update v.2.4.6
 - ixgbe zc driver update v.5.3.7
 - igb zc driver update v.5.3.5.18
 - Fixed interrupts handling on i40e when in zc mode, this fixes the case where packets are received in batches of 4/8 packets
 - Using nbrokerd for initializing FM10K adapters and configuring the RRC switch

* nBPF
 - Fixed rules constraints

* Misc
 - Reworked init.d systemd support
 - New pf_ringctl script to manage pf_ring and drivers (this is used by init.d/systemd)
 - Documentation improvements, Doxygen integration with "read the docs"

---------------------------------------                                                                                                                                                                             
2017-10-20 PF_RING 7.0

* PF_RING Library
 - Flow offload support
   - New PF_RING_FLOW_OFFLOAD pfring_open() flag to enable hw flow offload on supported cards (received buffers are native metadata)
   - New PF_RING_FLOW_OFFLOAD_NOUPDATES pfring_open() flag to disable flow updates with hw flow offload enabled: only standard raw packets with a flow id are received
   - New PKT_FLAGS_FLOW_OFFLOAD_UPDATE packet flag to indicate flow metadata in the received buffer (generic_flow_update struct)
   - New PKT_FLAGS_FLOW_OFFLOAD_PACKET packet flag to indicate raw packet with flow_id in pkt_hash
   - New PKT_FLAGS_FLOW_OFFLOAD_MARKER packet flag to indicate marked raw packet
 - Fixes for ARM systems

* ZC Library
 - New pfring_zc_set_app_name API
 - PF_RING_ZC_PKT_FLAGS_FLOW_OFFLOAD flag to enable hw flow offload
 - Fixed BPF filters in SPSC queues
 - Fixed hugepages cleanup in case of application dropping privileges
 - Fixed sigbus error on hugepages allocation failure on numa systems
 - Fixed multiple clusters allocation in a single process

* PF_RING-aware Libpcap/Tcpdump
 - Libpcap update v.1.8.1
 - Tcpdump update v.4.9.2

* PF_RING Kernel Module
 - Docker/containers namespaces isolation support
 - Fixed capture on Raspberry Pi
 - Implemented support for VLAN filtering based on interface name (<device name>.<VLAN ID>, where ID = 0 accepts only untagged packets)
 - New cluster types cluster_per_flow_ip_5_tuple/cluster_per_inner_flow_ip_5_tuple to balance 5 tuple with IP traffic, src/dst mac otherwise
 - Fixed hash rule last match, new hash_filtering_rule_stats.inactivity stats

* PF_RING Capture Modules
 - Accolade flow offload support
   - New hw_filtering_rule type accolade_flow_filter_rule to discard or mark a flow
 - Netcope support
   - New hw_filtering_rule type netcope_flow_filter_rule to discard a flow
 - Improved Fiberblaze support
   - pfring_get_device_clock support
   - Ability to set native filters by setting as BPF string 'fbcard:<fb filter>'
   - Fixed TX memory management
   - Fixed subnet BPF filters
   - Fixed drop counter
   - Fixed capture mode
   - Fixed sockets not enabled
   - FPGA error detection
 - Endace DAG update
 - npcap/timeline module compressed pcap extraction fix

* Drivers
 - ixgbe-zc driver update v.5.0.4
 - i40e-zc driver update v.2.2.4

* nBPF
 - Fixed nBPF parser memory leak

* Examples
 - New pfsend option -L <num> to forge <num> VLAN IDs
 - zbalance_ipc improvements
   - Ability to dump output to log file (-l)
   - Fixed privileges drop (-D)

* Misc
 - Fixed systemd dependencies, renamed pfring.service to pf_ring.service
 - New /etc/pf_ring/interfaces.conf configuration file for configuring management and capture interfaces

---------------------------------------                                                                                                                                                                             
2017-04-24 PF_RING 6.6

* PF_RING Library
 - New pfring_findalldevs/pfring_freealldevs API for listing all interfaces supported by pf_ring
 - New timeline module based on libnpcap for seamlessly extracting traffic from a n2disk dumpset using the pf_ring API
 - Dynamic capture modules loading with dlopen support
 - Improved pfring_set_bpf_filter to set hw rules when supported by the network card thanks to the nBPF engine 

* ZC Library
 - New pfring_zc_set_bpf_filter/pfring_zc_remove_bpf_filter API for setting BPF filters to device queues
 - Fixed pfring_zc_queue_is_full for device queues
 - Flushing SPSC queues when a consumer attaches (RX only)

* PF_RING-aware Libpcap/Tcpdump
 - Support for extracting traffix from a n2disk dumpset using libpcap
 - tcpdump upgrade to v.4.9.0

* PF_RING kernel module
 - Support for latest ubuntu and centos stable kernels
 - Support for SCTP and ICMP packet parsing
 - Packet hash improvements
 - Added tunneled IP version to packet metadata
 - Added IP version to sw filters
 - New kernel cluster hash types for tunneled traffic
 - QinQ VLAN parsing
 - Removed deprecated kernel plugins support
 - Promisc fix in case of multiple devices in a single socket

* Drivers
 - Support for latest ubuntu and centos stable kernels
 - FPGA modules/libraries are now loaded at runtime using dlopen
 - RSS support on Intel i211
 - Jumbo frames support on i40e
 - i40e tx optimisations
 - i40e interrupts fixes in case of RSS
 - Fiberblaze capture module with chunk mode support
 - Exablaze capture module 
 - Accolade improvements
 - Endace DAG update and support for streams
 - Myricom ports aggregation fixes, new syntax myri:<port>,<port>

* nBPF
 - New nBPF filtering engine supporting an extended subset of the BPF syntax (tunneled traffic and l7 protocols are supproted)
 - nBPF support for hw filtering on Fiberblaze cards
 - nBPF support for hw filtering on Intel FM10K cards (Silicom PE3100G2DQIR)
 - nBPF support for hw filtering on Exablaze cards
 - nBPF support for hw filtering on Napatech cards and NTPL generation
 - Support for "start <time> and end <time> and <bpf>" when extracting from a n2disk timeline
 - Support for vlan [id], mpls [label], gtp

* Examples
 - pfcount:
   - ability to list interfaces with -L (-v 1 for more info)
   - ability to dump traffic on PCAP file with -o
 - psend:
   - option to force flush per packet (-F)
   - options to specify src/dst IP for packet forging (-S/-D)
   - option to forge packets on the fly instead of at preprocessing time (-O)
   - option to randomize generated ips sequence (-z)
   - ability to generate IPv6 traffic (-V 6)
   - ability to generate mixed v4 and v6 traffic (-V 0)
   - TCP/UDP checksum when reforging
 - zbalance_ipc
   - option to use hw aggregation when supported by the card (-w)
   - IP-based filtering with ZMQ support for rules injection

* Wireshark
 - New extcap module 'ntopdump' for Wireshark 2.x

* Misc
 - Improved systemd support (Ubuntu 16)

---------------------------------------                                                                                                                                                                             
2016-06-07 PF_RING 6.4

* PF_RING Library
 - Improved Myricom support, new naming scheme to improve usability
 - Improved Napatech support, 100G support
 - Improved Accolade support
 - New Invea-Tech support
 - New API pfring_get_metadata to read ZC metadata
 - New pfring_get_interface_speed API
 - New API pfring_version_noring()
 - C++ wrapper improvements
 - Removed DNA legacy

* ZC Library
 - New API pfring_zc_set_device_proc_stats to write /proc stats per device
 - New API pfring_zc_set_device_app_name to write the application name under /proc
 - New API pfring_zc_get_cluster_id to get the cluster ID from a queue
 - New API pfring_zc_check_device_license for reading interface license status
 - New API pfring_zc_get_queue_settings to read buffer len and metadata len from queue
 - New API pfring_zc_get_queue_speed to read the link speed
 - New pfring_zc_open_device flag PF_RING_ZC_DEVICE_NOT_PROMISC to open the device without setting promisc mode
 - New packet metadata flags, including IP/L4 checksum (when available from card offloads)
 - Improved pfring_zc_builtin_gtp_hash

* PF_RING-aware Libpcap/Tcpdump
 - New libpcap v.1.7.4
 - New tcpdump v.4.7.4
 - Libnpcap support to let libpcap-based applications (i.e. tcpdump) read compressed .npcap files produced by n2disk
 - Native nanosecond timestamps support
 - Tcpdump patch to close the pcap handle in case of errors (this avoids breaking ZC queues)

* PF_RING kernel module
 - Fixed BPF support on kernel 4.4.x
 - Fixed RSS support on Centos 6 (it was reporting the wrong number of queues, affecting RSS rehash)
 - Reworked promisc support: handling promisc through the pf_ring kernel module in order to automatically remove it even when applications drop privileges
 - VLAN ID fix in case of vlan stripping offload enabled (it was including priority bits)

* Drivers
 - New i40e-zc v.1.5.18
 - New fm10k-zc v.0.20.1
 - Support for latest Ubuntu 16, RHEL 6.8, Centos 7
 - Fixed i40e-zc initialisation failures due to promisc reset
 - Fixed i40e-zc 'transmit queue 0 timed out'
 - Fixed e1000e-zc memory leak

* Examples
 - Added ability to reforge MAC/IP also when reading packets from pcap file/stdin in pfsend
 - Added -f option for replaying packets from pcap file in zsend
 - Added -o option to pfsend to specify an offset to be used with -b
 - Added -r option to use egress interfaces instead of queues in zbalance_ipc

* Snort DAQ
 - Fixed DAQ-ZC buffer leak in IPC mode
 - Fixed DAQ_DP_ADD_DC support
 - Fixed support for DAQ < 2.0.6

---------------------------------------                                                                                                                                                                             
2015-11-26 PF_RING 6.2

* PF_RING Library
 - Accolade Technology support
 - Myricom/CSPI NICs (ASIC/FPGA) support with APIv4
 - Napatech module compatibility with ntanl v.4.0.1
 - New API pfring_set_packet_slicing for packet slicing (hw support when available)
 - New pfring_open flag PF_RING_ZC_IPONLY_RSS to compute RSS on IP only (not 4-tuple)
 - Reworked pfring_recv_chunk API to handle generic segments
 - Packet-mode with Napatech using pfring_recv also when card is configured as PCAP
 - Improved pfring_print_parsed_pkt with STP support
 - Improved software filtering rules stats
 - Fix for capturing tx packets in stack mode
 - Removed libnuma dependency (using native numa support in PF_RING ZC)
 - Added pfring_config tool to print includes and libs used in the current PF_RING configuration
 - Fixed loops in stack mode (e.g. stack injected packets captured from kernel in 1-copy mode)
 - Fix for IPv6 in pfring_hash_pkt
 - License update to LGPL 2.1

* ZC Library
 - New API pfring_zc_set_rxfh_indir to reprogram RSS REdirection TAble
 - New pfring_zc_open_device flag PF_RING_ZC_DEVICE_CAPTURE_TX to capture also TX direction on standard devices
 - Fixed e1000e caplen
 - Fixed i40e TX
 - Fixed device detach
 - Fixed DAQ-ZC IPC detach
 - Fix for re-running recv after a breakloop in pfring_zc_queue_breakloop
 - Fix for nanoseconds in case of software timestamps with ZC devices

* DNA Library
 - Fixed cluster queues initialisation in Libzero

* PF_RING-aware Libpcap
 - Fixed pcap_brekloop (tcpdump now handles sigterm correctly when there is no traffic)

* PF_RING kernel module
 - Compilation fixes for FC 22 with kernel 4.x
 - Fixed BPF support in Centos 7 (causing crashes)
 - Fixed concurrent /proc updates and interface name clashes

* PF_RING-aware/ZC Drivers
 - New e1000e driver v.3.2.7.1 with kernel 4.x support
 - New igb driver v.5.3.2.2 with kernel 4.x support
 - New ixgbe driver v.4.1.5 with kernel 4.x support
 - New i40e-zc driver v.1.3.39.1 with kernel 4.x support
 - Fixed rx stats in ifconfig/proc/ifstat/etc.
 - Fixed stats with X540
 - ixgbe: forcing drop_en on all queues when an rx queue is open

* DNA Drivers
 - New e1000e driver v.3.2.4.2
 - New igb driver v.5.3.2.2
 - New ixgbe driver v.4.1.2
 - igb hw timestamp change from 40 bit to 64 bit full timestamp

* Examples
 - zbounce: printing direction
 - zbalance_ipc: optimisation to reduce time-pulse thrad load on non-time-sensitive applications
 - pfsend: linux cooked packets support
 - pfsend: ability to specify egress rate in pps

* Snort DAQ
 - Fixed direction and L2 header in the inject function

---------------------------------------                                                                                                                                                                             
2015-03-30 PF_RING 6.0.3

* PF_RING Library
 - New pfring_open() flag PF_RING_USERSPACE_BPF to force userspace BPF instead of in-kernel BPF with standard drivers
 - New API pfring_get_card_settings() to read max packet length and NIC rx/tx ring size
 - New Napatech support
 - Support for up to 64 channels with standard drivers, pfring_set_channel_mask() has a 64bit channel mask parameter now
 - Reworked IPv6 parsing
 - Configure parameter --disable-numa to remove libnuma dependency
 - ARM fixes
 - Minor bpf memory leak fix
 
* ZC Library
 - New pfring_zc_open_device() flag PF_RING_ZC_DEVICE_SW_TIMESTAMP to force sw timestamp
 - New API pfring_zc_get_queue_id() to read SPSC queue ID or interface index
 - New DAQ module for ZC
 - pfring_zc_send() is now returning errno=EMSGSIZE on packet too long
 - Fix for receiving packets from stack using
 - Fix for send_pkt_burst() with IPC SPSC queues
 - Fix for drop stats when using SPSC queues over the standard pf_ring API
 - Fix for /proc stats in IPC mode when using the standard pf_ring API
 - Fix for packet timestamp when using SPSC queues over the standard pf_ring API
 - Fix for stats when inter-process SPSC queues are used

* PF_RING-aware Libpcap
 - New PF_RING-aware libpcap v.1.6.2
 - New .npcap (compressed pcap) files support
 - Fix for libpcap over ZC, reworked poll support

* PF_RING kernel module
 - New eth_type field in kernel filters
 - Reworked BPF support
 - Polling Mode/Breed under /proc is now "ZC" for ZC devices (in place of DNA)
 - Increased max dev name size
 - transparent_mode is now deprecated
 - Fix for 'any' device
 - Fix for kernel >=3.19
 - Fix for hw vlan strip in case of multiple sockets on the same device (standard drivers)
 - Fix for kernel Oops (rx vlan offload check)

* PF_RING-aware/ZC Drivers
 - New Intel i40e (X710/XL710) ZC drivers
 - New ixgbe ZC driver v.3.22.3
 - ixgbe poll fix
 - Fixes for Centos/RH 6.6
 - Fixes for kernel >=3.16

* Examples
 - New zbalance_DC_ipc: a master process balancing packets to multiple consumer processes, 
   using multiple threads for packet filtering in a Divide-and-Conquer fashion,
   with an optional stage for sorting filtered packets before distribution
 - New zreplicator: example application receiving packets from n ingress interfaces and replicating them to m egress interfaces
 - pfcount: -N <num> parameter to exit after reading <num> packets
 - zsend: 
   - IPC support to attach to an external cluster/queue
   - added -P <core> to use pulse-time thread for tx rate control
   - added -Q <sock> to enable VM support (to attach a consumer running in a VM)
 - zbalance_ipc: 
   - ability to create ingress sw queues (instead of opening interfaces) with -i Q (comma-separated list of Q and interfaces is allowed)
   - added daemon mode
   - added pid file
   - proc stats fix
   - interface and per-queue stats with -p
 - pflatency: 
   - added -o <device> and -c <count>
   - max/min/avg stats
 - zfifo fixes

---------------------------------------                                                                                                                                                                             
2014-09-24 PF_RING 6.0.2

* PF_RING Library
 - New Ixia hw timestamp support
 - New sysdig module
 - Userspace bpf filtering with pfring_set_bpf_filter() when kernel-bypass is used (DNA/Libzero/ZC)
 - Fixed fd leak

* ZC Library
 - New API to add/remove hw filters: pfring_zc_add_hw_rule()/pfring_zc_remove_hw_rule()
 - New API to check tx queue status: pfring_zc_queue_is_full()
 - New API to sort traffic based on hw ts: pfring_zc_run_fifo()
 - New API to export stats in /proc: pfring_zc_set_proc_stats()
 - New API to hash packets based on GTP: pfring_zc_builtin_gtp_hash()
 - Hw ts support: new PF_RING_ZC_DEVICE_HW_TIMESTAMP, PF_RING_ZC_DEVICE_STRIP_HW_TIMESTAMP flags
 - Ixia ts support: new PF_RING_ZC_DEVICE_IXIA_TIMESTAMP flag
 - PPPoE support in pfring_zc_builtin_ip_hash()
 - Fix for huge memory allocation
 - Fix for stack injection
 - Fix for ZC cluster destroy

* PF_RING kernel module
 - MPLS support
 - Support for huge rings (new ring version 16)
 - Fixed send for packet len = max frame size + vlan
 - Fix for huge memory allocation with standard pf_ring/libzero
 - Fixed 64 bit division on 32 bit systems
 - Fixed cluster hash
 - Fix for multichannel devices
 - DKMS support

* PF_RING-aware/ZC Drivers
 - Hw filtering support in ixgbe-ZC driver (Intel 82599-based cards)
 - e1000e driver update v.3.0.4.1
 - ixgbe  driver update v.3.21.2
   - numa node fix
   - new parameter allow_tap_1g to handle 1gbit/s TAP
 - DKMS support

* DNA Drivers
 - e1000e driver v.2.5.4 vlan stripping disabled
 - DKMS support

* PF_RING-aware Libpcap
 - New PCAP_PF_RING_RECV_ONLY env var to open socket in rx only
 - Fix for libpcap VLAN issues with LINUX_SLL
 - Fix for cpu spinning on pcap_read_packet()
 - Fix for userspace bpf with libzero/zc virtual interfaces
 - Fix for VLAN filtering

* Examples
 - pfcount: userspace bpf fix
 - pfsend: fixed division by 0 with empty pcaps
 - pfbridge: added bpf support
 - pfdnacluster_master: added PPPoE support to hash
 - New zfifo example
 - zbalance: round-robin mode fix
 - zbalance_ipc
   - ability to spread packets across multiple instances of multiple applications in IP and GTP hash mode
   - ability to configure queue len
   - added support for n2disk10g multithread
 - Added zbalance_ipc zsend zcount zcount_ipc to the Ubuntu package
 - Added zbalance_ipc zsend zcount zcount_ipc to the RPM package

---------------------------------------                                                                                                                                                                             
2014-05-06 PF_RING 6.0.1

* PF_RING ZC
 - New pfring_zc_send_pkt_burst()
 - Fix for e1000e rx
 - Added ZC version in demo apps help

* DNA
 - Fix for pfring_set_tx_watermark()

* Drivers
 - Added numa_cpu_affinity parameter to PF_RING-aware/ZC ixgbe driver
 - PF_RING-aware/ZC drivers update:
   - ixgbe-zc v.3.21.2
   - igb-zc v.5.2.5
 - DNA drivers update:
  - ixgbe-dna v.3.21.2

* Examples
 - pfcount:
   - Added ability to search strings on the payload
   - Added ability to dump on a pcap file the traffic matching strings (-x)
   - Improved ability to dump (-o) traffic on disk and create a log file
   - Handling SIGHUP with -o to close exising dump and create a new one
 - Fixed numa affinity

* PF_RING Kernel module
 - added checksum offload flags to the packet header (when enabled)

---------------------------------------
2014-04-14 PF_RING 6.0.0

* PF_RING ZC
 - Say hello to the new PF_RING ZC library!

* PF_RING API
 - New chunk mode API (for supported cards only):
   - Added PF_RING_CHUNK_MODE pfring_open() flag
   - New pfring_recv_chunk()
 - New pfring_set_bound_dev_name() for setting custom bound device name
 - Added libnuma support for numa node affinity

* Drivers
 - New generation PF_RING-aware drivers with ZC support:
   - e1000e-2.5.4-zc
   - igb-5.0.6-zc
   - ixgbe-3.18.7-zc
 - PF_RING-aware e1000e driver update (v.3.0.4.1)

* Examples
 - New PF_RING ZC examples in userland/examples_zc
 - Moved libzero examples to userland/examples_libzero

---------------------------------------
2014-02-01 PF_RING 5.6.2

* PF_RING Kernel module
 - Added compatibility for new kernels (post 3.10)
 - Redhat compilation fixes

* PF_RING library
 - New pfring_print_pkt()/pfring_print_parsed_pkt()
 - pfring_get_selectable_fd fix: returning -1 on error
 - Doxygen documentation

* Libzero
 - Time-pulse thread support in DNA Cluster (sw nsec ts)
 - Application stats fix for libzero DNA Cluster slave sockets
 - Added libnuma support to DNA Cluster for memory binding

* Libpcap
 - Setting selectable fd via pfring_get_selectable_fd()

* Examples
 - pfdnacluster_master
   - New -o <device> and -f <core id> options to forward packets both to applications and an egress interface
   - Ability to drop privileges with -D <username>
   - Stats under /proc/net/pf_ring/stats
   - New option -q <queue len>
 - Applications stats have duration with msec resolution now

* Drivers
 - New PF_RING-aware netxtreme2-7.8.37 driver (courtesy of Rob G <rgagnon24@gmail.com>)
 - PF_RING-aware igb (5.1.2) and ixgbe (3.19.1) drivers update (courtesy of Pablo Nebrera <pablonebrera@eneotecnologia.com>)
 - ixgbe DNA driver update (3.18.7)
 - igb DNA driver update (5.0.6)
 - e1000e DNA driver update (2.5.4)
 - ixgbe DNA driver pause frames fix
 - igb/ixgbe DNA drivers compilation fixes for Redhat 6.5
 - igb DNA jumbo mtu fix
 - igb DNA drop stats fix
 - DNA drivers fixes for applications calling poll/select directly (e.g. tshark)

---------------------------------------
2013-08-30 PF_RING 5.6.1

* PF_RING Kernel module
 - Added enable_frag_coherence param: handle fragments to keep flow coherence in clusters
 - Cluster add/remove fix

* PF_RING API
 - New pfring_get_link_status() call to check link status up/down

* Examples
 - pfwrite
   - Added cluster id (-c) support
   - Added daemon mode (-b) support
   - Added redis PUBLISH/SUBSCRIBE for IMSI registration/delete
   - Enhanced IMSI tracking
   - Performance fix for GTP tunnels
   - Fixed buffer length issue
 - pfsend
   - Added daemon mode (-d) support
   - Added pid file (-P) support
 - pfdnacluster_master 
   - Added pid file (-P) support

* Libzero
 - DNA Bouncer fix: sometimes the decision function was accessing the wrong buffer

* Snort DAQ
 - Fix for honouring cnt in pfring_daq_acquire()
 - Stats fix

---------------------------------------
2013-06-07 PF_RING 5.6.0

* PF_RING Kernel module
 - Fixed bug that prevented the PF_RING cluster to work properly with specific traffic

* Documentation
 - User's guide translated to russian (courtesy of ridervka@yandex.ru)

* Libzero
 - Fixed bug that caused the DNA bouncer to process the correct packet

* Examples 
 - pfwrite
   - Added support for the microcloud so that for GTP traffic it is possible to dump traffic of specific IMSI phone
   - Added support for mobile networks (2G/3G/LTE) so that we can dump traffic of specific GTP tunnels
 - pfdump: added cluster id support (courtesy of Doug Burks <doug.burks@gmail.com>)

* Snort (PF_RING DAQ)
 - Added microcloud support for notifying into the microcloud those hosts that are victims/attackers
	
---------------------------------------
2013-05-22 PF_RING 5.5.3

* PF_RING Kernel module
 - Support for injecting packets to the stack
 - Added ability to balance tunneled/fragmented packets with the cluster
 - Improved init.d script
 - Packet len fix with GSO enabled, caplen fix with multiple clusters
 - Bug fixes for race condition with rss rehash, memory corruption, transparent mode and tx capture, kernels >= 3.7.

* Drivers
 - Added PF_RING-aware driver for Chelsio cards (cxgb3-2.0.0.1)
 - New release for PF_RING-aware igb (igb-4.1.2)

* DNA
 - Added support for Silicom 10 Gbit hw timestamping commodity NIC card
 - Added pfring_flush_tx_packets() for flushing queued tx packets
 - Fixes for cutting packets to snaplen, e1000-dna rx

* Libzero
 - pfdnacluster_master support for multiple instances of multiple applications
 - Added dna_cluster_set_thread_name() to name the master rx/tx threads
 - Fix for direct forwarding with the DNA Cluster
 - Changed len to a ptr in DNA Bouncer decision function to allow user change forwarded packet content and lenght

* Examples
 - Added ability to replay a packet with pfsend passing hex from stdin
 - Added pfwrite to the package
 - Fix for rate control with huge files in pfsend

---------------------------------------
2013-01-09 PF_RING 5.5.2

* PF_RING library
 - New pfring_open() flag PF_RING_DNA_FIXED_RSS_Q_0 to send all traffic to queue 0.
   Other queues can be selected using hw filters (DNA cards with hw filtering only).
 - Added ability to create a stats file under /proc/net/pf_ring/stats so that
   applications can report stats via the /proc filesystem.
  - pfring_set_application_stats() for reporting stats
  - pfring_get_appl_stats_file_name() for getting the exac filename where the app sets the statistics

* DNA drivers
 - Flow Control disabled by default with the ixgbe-dna driver

* Sample apps
 - New pfdump.c sample app
 - Userspace BPF support with DNA in pfcount.c
 - pfcount.c and pfsend.c update to report stats using pfring_set_application_stats()

* Libzero
 - New experimental pfring_register_zerocopy_tx_ring()
 - New pfdnacluster_mt_rss_frwd sample app (packet forwarding using Libzero
 DNA Cluster for rx/balancing and standard DNA with zero-copy on RSS queues for tx)

* Libpcap
 - pcap_get_pfring_id()
 - pcap_set_master_id()
 - pcap_set_master()
 - pcap_set_application_name()
 - pcap_set_watermark()

* BUG fixes
 - Fix for corrupted VLAN tagged packets
 - Fix for wrong packet len with vlan stripping offload

---------------------------------------
2012-11-24 PF_RING 5.5.1

- updated ixgbe driver to release 3.11.33
- Fixed bug that was causing ixgbe driver not to disable interrupts. This was causing
  a high load on the core handling the interrupts for ixgbe-based card
- libzero: various hugepages improvements and bug fixes
- Added ability to specify PF_RING_RX_PACKET_BOUNCE in pfring_open
- Fixed minor memory leak
- Various improvements to support of hardware timestamp on Silicom Intel-based 10 Gbit adapters
- DNA Bouncer: added direction to pfring_dna_bouncer_decision_func callback (useful in bidirectional mode)
- DNA Cluster: added dna_cluster_set_hugepages_mountpoint() to manually select the hugepages mount point when several are available
- Created architecture specific versions of libzero/DNA for exploiting latest generation of CPUs and thus improve performance
- Update PF_RING-aware igb update (4.0.17)
- Added pf_ring calls to pcap apps

---------------------------------------
2012-11-01 PF_RING 5.5.0

* New libzero features:
  - DNA Cluster: number of per-consumer rx/tx queue slots and number of additional buffers can be configured via dna_cluster_low_level_settings()
  - hugepages support (pfdnacluster_master/pfdnacluster_multithread -u option)

* New PF_RING-aware libpcap features:
  - added PF_RING_ACTIVE_POLL environmental variable to enable active polling when defined to 1
  - enable rehash rss setting env var PF_RING_RSS_REHASH=1
  - cluster type selectable via env vars:
    - PCAP_PF_RING_USE_CLUSTER_PER_FLOW
    - PCAP_PF_RING_USE_CLUSTER_PER_FLOW_2_TUPLE
    - PCAP_PF_RING_USE_CLUSTER_PER_FLOW_4_TUPLE
    - PCAP_PF_RING_USE_CLUSTER_PER_FLOW_TCP_5_TUPLE
    - PCAP_PF_RING_USE_CLUSTER_PER_FLOW_5_TUPLE

* New PF_RING-aware drivers
  - Updated Intel drivers to make them compatible with newer kernels

* New PF_RING library features:
  - new pfring_open() flag PF_RING_HW_TIMESTAMP for enabling hw timestamp

* New PF_RING kernel module features:
  - handle_user_msg hook for sending msg to plugins
  - SO_SEND_MSG_TO_PLUGIN setsockopt for sending msgs from userspace
  - pf_ring_inject_packet_to_ring for inserting packets in a ring identified by <if_index, channel_id>)
  - possibility to redefine the rehash_rss function

* Snort PF_RING-DAQ module:
  - new configure --with-pfring-kernel-includes option
  - fix for -u <uid> -g <gid>

* DNA drivers fixes:
  - Compilation with RHEL 6.3
  - igb drop stats fix

* Sample app new features:
  - new pfcount.c -s option for enabling hw timestamp
  - new pfdnacluster_multithread option for absolute per-interface stats

* Sample apps fixes:
  - vlan parsing
  - compilation fix for HAVE_ZERO not set
  - pfcount fix for reentrant mode
  - core binding fixes

* PF_RING kernel module fixes:
  - channel_id handling
  - fix for hash with cluster type in cluster_per_flow_*
  - important fix for standard pf_ring (BUG #252: extra packets with wrong size)
  - max caplen 16384 increased to 65535 (max 16 bit)
  - fix for handling packets with stripped VLAN IDs

* Misc changes
  - Initial work on changelog maintenance

