# CHANGELOG

---------------------------------------
2023-09-01 PF_RING 8.6

* PF_RING Library
 - New Runtime Manager for injecting and removing filtering rules to the socket via Redis
 - Fix memory leaks in PCAP module
 - Fix caplen/MTU on loopback capture

* PF_RING Kernel Module
 - Add support for probabilistic sampling with kernel capture

* FT Library
 - Improve application protocol guess with nDPI

* PF_RING Capture Modules and ZC Drivers
 - Add initial support for NVIDIA/Mellanox BlueField
 - Add Napatech ns timestamp in PCAP mode
 - Add support for probabilistic sampling with userspace capture
 - Optimize hw timestamping on ice adapters (Intel E810)
 - Fix timestamp support when using the ZC burst API with ice adapters
 - Fix drivers compilation on Kernel 6.x
 - Fix drivers compilation on RH 8.8

* nPCAP
 - Fix memory corruption with big index files

* PF_RING-aware Libpcap/Tcpdump
 - Add PF_RING support to pcap_inject
 - Fix pcap_read_pf_ring return code (number of packets)

* Examples
 - zbalance_ipc: add support for multiple balancer threads when using NVIDIA/Mellanox adapters
 - pfsend: add -c option to balance on dest ip rather than src up
 - pfcount: compute drop rate in packet mode only
 - pfcount: report expired licenses
 - Fix ftflow_dpdk compilation on DPDK 22 or later
 - Fix memory leaks in pcount, alldevs, preflect, ftflow_pcap, 

* Misc
 - Add support for Debian 12
 - Add libelf and libbpf dependencies to packages
 - Add sbsigntool dependency which includes kmodsign required by dkms
 - Add revision to pfring-dkms dependency in packages
 - Fix check for init/systemd presence
 - Cleanup support for legacy adapters

---------------------------------------
2023-01-30 PF_RING 8.4

* PF_RING Library
 - New API pfring_get_ethtool_link_speed
 - Add vlan_id to flow rule struct
 - Add optimization flags to BPF filters compiled with pcap_compile
 - Fix pfring_open_multichannel

* PF_RING Kernel Module
 - Add keep_vlan_offload option to avoid reinserting VLAN header on VLAN interfaces when used inline

* ZC Library
 - New ZC APIs (available on supported adapters)
   - pfring_zc_get_device_clock
   - pfring_zc_set_device_clock
   - pfring_zc_adjust_device_clock
   - pfring_zc_send_pkt_get_time
 - Add new pfring_zc_run_fanout_v3 API to support more than 64 fan-out queues
 - Add support for capturing stack packets, used by zcount and zbalance_ipc

* PF_RING Capture Modules and ZC Drivers
 - New iavf-zc driver to support i40e and ice Virtual Functions
   - Support for VF trust mode on ice adapters (promisc with SR-IOV)
 - Improve ice driver (E810 adapters)
   - Update ice driver to v.1.9.11
   - Add support to get time, set time, adjust time, send get time
 - Improvei the NVIDIA/Mellanox (mlx) driver
   - Extend hardware rules
   - Add support for VLAN filtering
   - Add set_default_hw_action API
   - Fix reported link speed
   - Fix bidirectional rules
   - Fix pfring_poll support
 - Improve the Napatech driver
   - Add nanosecond timestamp capture when using the packet API in PCAP chunk mode
 - Improve the ZC drivers API to support more callbacks
 - Add socket extensions (getsockopt/setsockopt):
   - SO_GET_DEV_STATS (get_stats ZC drivers callback)
   - SO_GET_DEV_TX_TIME (get_tx_time ZC drivers callback)
   - SO_SET_DEV_TIME (set_time ZC drivers callback)
   - SO_SET_ADJ_TIME (adjust_time ZC drivers callback)
 - Add management_only_mode to allow opening multiple sockets on the same ZC interface
 - Update drivers to support latest RH 9.1, Ubuntu 22, Debian kernels

* FT Library
  - Fix double free

* nBPF 
 - Add icmp protocol primitive support

* nPCAP
 - Update npcap lib to support for nanosecond time in packet extraction

* PF_RING-aware Libpcap/Tcpdump
 - Update tcpdump to v.4.99.1
 - Update libpcap to v.1.10.1

* Examples
 - Add ztime example
   - Ability to set/adjust the card clock without capturing/transmitting traffic (external process)
   - Test for the send-get-time feature
 - pfsend
   - Flush queued packets when waiting at real pcap rate and on shutdown
   - Fix headers ranzomization 
   - Fix crash with -z
 - pfsend_multichannel
   - Add support for controlling IPs generated
 - pfcount
   - Add -I option to print interface info in JSON format
 - pfcount_multichannel
   - Print full packet metadata with -v
 - zbalance_ipc
   - Add support for up to 128 queues with -m 1 and -m 2 (new v3 api) 
   - Add -X option to capture TX traffic (standard driver only)
   - Fix check for queues limit
 - zdelay
   - Fix queue size (power of 2)

* Misc
 - Add pfcount_multichannel and pfsend_multichannel to packages
 - Service script (pf_ringctl)
   - Add support for configuring RSS via ethtool
   - Add pre/post scripts for ZC drivers
   - Handle multi-line driver conf file
 - Removed obsolete fm10k driver

---------------------------------------
2022-06-30 PF_RING 8.2

* PF_RING Library
 - New new pfring_get_caplen API
 - New pfring_get_link_type API
 - Add src_ip_mask and dst_ip_mask to generic_flow_rule
 - Add priority to hw_filtering_rule
 - Add module version to device info returned by pfring_findalldevs
 - Refactor device name parsing
 - Use sockaddr_ll in bind (to supports interface names longer than 14 chars)

* ZC Library
 - New Mellanox support for ConnectX 4/5/6 adapters, including hardware offloads for timestamp, filtering, RSS
 - Fix pfring_zc_numa_get_cpu_node

* FT Library
 - Add native support for flow export over ZMQ

* PF_RING Kernel Module
 - Add support for VXLAN
 - Add support for both sockaddr and sockaddr_ll in bind
 - Refactor kernel locking
 - Discard VLAN in hash cluster_per_flow_ip_with_dup_tuple calculation
 - Detect when a process owning a PF_RING socket changes the PID (e.g. fork)
 - Export process PID to userspace
 - Fix compilation on latest kernels for Rocky Linux and RH 8.5, Debian 9, 10, 11, Ubuntu 18, 20, 22
 - Fix net namespace handling
 - Fix crash when renaming /proc entries

* PF_RING Capture Modules
 - Fix drop statistics on Napatech with HBA set

* ZC Drivers
 - New igb-zc driver v.5.10.2
 - New i40e-zc driver v.2.17.4
 - New ice-zc driver v.1.8.8

* nBPF 
 - Fix double free

* Examples
 - New sample application pfsend_multichannel to send traffic using RSS
 - New zdelay application to forward traffic between interfaces, adding a configurable delay
 - pfcount_multichannel: remove limit on number of threads
 - zbalance_ipc: improve hashing modes (e.g. add -Y to control eth type)
 - pfcount:
   - Add -0 to steer all traffic to RSS queueu 0
   - Add -P to set rule priority
 - ftflow_dpdk:
   - Set RSS mode/hf (required on some adapters e.g. Mellanox)
   - Use time from hardware timestamp when available

* Misc
 - Add support for Ubuntu 22
 - Remove nBroker support (fm10k adapters are EOL)

---------------------------------------
2021-08-11 PF_RING 8.0

* PF_RING Library
 - Add pfring_recv_burst API allowing batch receive (when supported by the capture module/adapter)
 - New zero-copy AF_XDP support (reworked), including pfring_recv_burst support
 - Fix breakloop when using pfring_loop

* ZC Library
 - New pfring_zc_pkt_buff_data_from_cluster API to get the packet buffer providing packet handle and cluster
 - New pfring_zc_pkt_data_buff API to get the packet handle providing packet buffer and cluster
 - New pfring_zc_pkt_buff_pull_only API to remove data from the head room of a packet
 - Add PF_RING_ZC_BUFFER_HEAD_ROOM define (buffer head room size)
 - Add PF_RING_ZC_SEND_PKT_MULTI_MAX_QUEUES define (max number of queues in queues_mask)

* FT Library
 - New pfring_ft_api_version API to get the API version
 - New pfring_zc_precompute_cluster_settings API to get memory information before allocating resources
 - Add VXLAN encapsulation support
 - Add tunnel_id to flow metadata
 - Add support for compiling examples with DPDK >=20
 - Fix L7 metadata with short flows

* PF_RING-aware Libpcap/Tcpdump
 - Set 5-tuple clustering as default when using clustering with libpcap

* PF_RING Kernel Module
 - Support for kernel >=5.9
 - Add more info to /proc, including promisc mode and ZC slots info
 - Handle long interface name (error on interface length bigger than 14-char as supported by bind)
 - Fix channel selection when channel is unknown (e.g. VM)
 - Fix triple VLAN tags with hw offload/acceleration
 - Fix check on mapped memory size
 - Fix potential data race in SO_SET_APPL_NAME
 - Fix OOB access

* PF_RING Capture Modules
 - Accolade library update (SDK 1_2_20210714)
 - Napatech library update (SDK 12.7.2.1)
 - Silicom/Fiberblaze library update (SDK 3_5_9_1)
 - Add steer_to_ring and ring_id fields to Accolade rules (accolade_hw_rule)
 - Add support for recv burst on Napatech adapters in chunk mode
 - Add PF_RING_PACKET_CAPTURE_PRIO env var to set hostBufferAllowance on Napatech adapters
 - Rename ACCOLADE_RING_BLOCKS env var to ANIC_RING_BLOCKS on Accolade adapters (default is now 16)
 - Fix Accolade drop counter when capturing from rings
 - Fix extraction of packets with nsec timestamps on Timeline module (n2disk dump)

* ZC Drivers
 - New ice ZC driver v.1.3.2 (Intel Columbiaville / E810 adapters) with symmetric RSS support
 - Support latest kernels, including RH/CentOS 8.4 and Ubuntu 20, for all ZC drivers
 - i40e ZC driver update (v.2.13.10)
 - e1000e ZC driver update (v.3.8.7)

* nBPF 
 - New nBPF primitives 'device <ID>' and 'interface <ID>' to match metadata from Arista MetaWatch devices

* Examples
 - pfcount
   - Add -B option (burst mode)
 - pfsend
   - Add -n <num packets> support with -f <pcap>
   - Add support to reforge src/dst IP from pcap with -S and -D
 - ftflow
   - Add -E option to run extra DPI dissection (e.g. to print JA3 info)
 - zbalance_ipc 
   - Add runtime reload of nDPI protocol configuration file
   - Add -m 7 option (sample distribution based on eth type)
   - Add default configuration file /etc/cluster/cluster.conf (when no option is specified)

* Misc
 - Move libraries and utility scripts from /usr/local to /usr
 - Install pfring-aware tcpdump with packages
 - Add revision to pfring-dkms version

---------------------------------------
2020-10-19 PF_RING 7.8

* PF_RING Library
 - Add support for Device ID and Port ID to the extended packet header
 - Add Arista 7150 Series hw timestamps support (keyframes and packet trailer parsing and stripping)
 - Add Metawatch Metamako hw timestamps support (packet trailer parsing and stripping)
 - errno EINTR is now returned on breakloop
 - Improve XDP support
 - Replace configure --enable-xdp with --disable-xdp (XDP enabled by default when supported)

* ZC Library
 - New PF_RING_ZC_DEVICE_METAWATCH_TIMESTAMP flag to enable Metawatch hw timestamps
 - New pfring_zc_get_pool_id API to get the Pool ID
 - New pfring_zc_run_balancer_v2 pfring_zc_run_fanout_v2 APIs to support filtering functions
 - BPF support in ZC interfaces, standard interfaces and SPSC queues
 - Add support for BPF in TX queues
 - Builtin GTP hash now expose GTP info (flags)
 - Fix CRC strip on ixgbevf

* FT Library
 - New pfring_ft_flow_get_id API to get the flow ID
 - New PFRING_FT_IGNORE_HW_HASH flag to ignore hw packet hash
 - New PKT_FLAGS_FLOW_OFFLOAD_1ST packet flag (first packet of a flow)
 - Add support for flow slicing
 - New API pfring_ft_flow_get_users to get flow users (in case of slicing)
 - Improve application protocol detection
 - Fix bogus-IP headers parsing 

* PF_RING-aware Libpcap/Tcpdump
 - New libpcap v.191
 - New tcpdump v.4.9.3
 - stats.ps_recv now includes packets dropped due to out of buffer space

* PF_RING Kernel Module
 - Fix channels with standard drivers
 - Fix 64-bit channel mask
 - Fix defragmentation of packets with ethernet padding 
 - Fix unnecessary device mapping causing ifindex exhaustion

* PF_RING Capture Modules
 - Update support for Fiberblaze adapters
 - Fix filtering with Accolade adapters

* ZC Drivers
 - New ice ZC driver supporting E800 Series Intel adapters
 - Support for Ubuntu 20 LTS
 - Support for CentOS/RedHat 8.2 
 - Fix queue attach/detach in ixgbe-zc
 - Support for kernel 5.4

* nBPF 
 - Add support for matching Local/Remote IP (new extended-BPF primitives)
 - Support uppercase AND/OR in extended-BPF filters
 - Fix extended-BPF grammar 

* Examples
 - New zfilter_mq_ipc sample app (packet filtering with multiple threads and fanout to multiple consumer processes)
 - ftflow:
   - New -H option to ignore hw hash setting PFRING_FT_IGNORE_HW_HASH
   - New -t option to print stats only
 - ftflow_dpdk
   - New -l option to run loopback tests
   - Add RX/TX ring size configuration
 - pfsend:
   - New -z option to precompute randomized sequence
   - New -W ID[,ID] option to forge VLAN and QinQ VLAN
 - zbalance_ipc:
   - New -x <vlans> option to filter by VLAN ID
   - Add ability to set BPF to egress queues
   - Add ability to refresh BPF filters at runtime
   - New -G <queue>:<version> option to forward GTP-C traffic to a specific queue
 - New zcount -f option to set BPF filters
 - New pfcount -F option (do not strip FCS)
 - New zcount/zcount_ipc -t option to read the packet payload
 - New pcount -e option to set the capture direction
 - Add VLAN to the flows dumped by ftflow
 - Fix transmission of small packets (less than 60 bytes)
 - Fix CPU affinity in ZC sample applications

* Misc
 - Handle failures in service restart during package updates
 - Add linux headers dependency to the pfring-dkms package
 - Add actual version/revision to pfring-drivers-zc-dkms packages
 - Fix installed .so library and links
 - Fix ZC DAQ compilation and API update
 - Fix service scripts to avoid command injections

---------------------------------------
2020-02-18 PF_RING 7.6

* PF_RING Library
 - New pfring_open flag PF_RING_TX_BPF to evaluate the BPF filter also for TX
 - New pfring_open flag PF_RING_FLOW_OFFLOAD_TUNNEL to dissect tunneled traffic in flow-offload mode
 - New pfring_open flag PF_RING_DISCARD_INJECTED_PKTS to discard stack-injected packets

* ZC Library
 - New API call pfring_zc_close_device to close a ZC interface
 - New 'flags' parameter to pfring_zc_create_cluster
 - Fixed memory allocation in case of more than 4GB of buffer size

* FT Library
 - New API call pfring_ft_set_filter_all_protocols to reset all filtering rules
 - New API call pfring_ft_set_license to set a license at runtime
 - New API call pfring_ft_flow_get_ndpi_handle to access the flow nDPI handle
 - New pfring_ft_l7_protocol_id, pfring_ft_get_ndpi_handle to access the nDPI handle
 - New pfring_ft_flow_value status field to get flow termination reason
 - New PFRING_FT_TABLE_FLAGS_DPI_EXTRA flag to enable extra metadata extraction
 - New PFRING_FT_DECODE_TUNNELS flag to decode tunnels, new tunnel_type item in the flow value
 - New flow slicing support (pfring_ft_flow_set_flow_slicing API)
 - Added CAPWAP support
 - Added flow metadata for HTTP/DNS/SSL
 - Added global 'default' section to the rules configuration file
 - Added dpi_min_num_tcp_packets / dpi_min_num_udp_packets to the configuration file
 - Added flow_idle_timeout / flow_lifetime_timeout to the configuration file
 - Added src/dst mac to the exported flow key
 - Added ICMP type/code to flow metadata
 - Added flags to flow metadata
 - Added custom flow actions to be defined by the user
 - Added pfring_ft_load_configuration_ext API
 - Improved protocol detection for some protocols like Skype
 - Improved metadata extraction for some protocols like Telnet
 - Improved pfring_ft_license to return the duration also in demo mode
 - Changed l7_detected callback: this is called before the flow_packet callback now
 - Changed pfring_ft_create_table and pfring_ft_flow_value to allocate user metadata as part of the flow structure
 - Fixed filtering/shunting of custom protocols
 - Fixed protocol detection in case of guess
 - Fixed pfring_ft_set_l7_detected_callback user parameter handling

* PF_RING-aware Libpcap
 - Fixed device name check during socket initialization to handle long interface names
 - Fixed loop break

* PF_RING Kernel Module
 - Added new clustering mode cluster_per_flow_ip_with_dup_tuple
 - Allow any to capture from any namespace (on the host only)
 - Remapping ifindex to an internal device index to handle ifindex growing indefinitely
 - Fixed kernel crash parsing malformed packets (12 nested QinQ VLAN headers with GRE)
 - Fixed possible race condition
 - Fixed QinQ VLAN and VLAN offload support
 - Fixed concurrent access to the ring in case of loopback device and bridge
 - Compilation fixes for kernel 5.x
 - Reworked max ring size check to handle cases like jumbo frames
 - Improved promisc management

* PF_RING Capture Modules
 - New AF_XDP capture module
 - Napatech library update, fixed findalldev
 - Accolade library update, fixed caplen vs orig len, new env var ACCOLADE_FLOW_IDLE_TIMEOUT
 - Myricom library update, license fix with port aggregation
 - DAG library update

* ZC Drivers
 - New ixgbe-zc driver v.5.5.3
 - Support for Intel X550
 - Compilation fixes for kernel 5.x
 - Handling if up/down when the interface is in use by ZC

* nBPF 
 - Added support to match custom fields through a callback (nbpf_set_custom_callback)

* Examples
 - zcount improvements:
   - Added -T option to capture TX
 - zbalance_ipc improvements:
   - Fixed -m 4/5/6 with multiple applications and more than 32 queues
   - New -E option to enable debug mode
   - New -C <FT config file> and -O <nDPI proto file> options
 - ftflow_dpdk improvements:
   - More stats: drops, hw stats, per-queue throughput
   - New options to control the link status, flow control, autoneg, port speed, checksum offload
   - New -P option to set the TX rate
   - New TX test mode and -T option to set the packet len
   - New -F option to enable forwarding
   - New -m <len> option to set the mtu
   - Capture-only mode
   - Forward optimizations
 - ftflow_pcap improvements:
   - Support for processing a PCAP file
   - New -p <proto.txt> option
   - New -F <file> option to configure filtering/shunting rules
 - pfsend improvements:
   - New -8 <num> option to send the same packets <num> times before moving to the next
   - New -B <bpf> option to set a BPF filter
   - New -t option to forge N different source port
   - New -A option to generate increasing number of flows
 - pfcount improvements:
   - New -R option to disable RSS reprogramming
 - pfbridge now discards injected packets

* Misc
 - New pf_ringcfg script to automatically configure pf_ring and drivers
 - New pre/post scripts executed by systemd before/after loading pf_ring and drivers
 - Improved hugepages configuration with multiple nodes
 - npcap lib update, storage utility functions fix for NFS

---------------------------------------
2018-12-19 PF_RING 7.4

* PF_RING Library
 - New pfring_open PF_RING_DO_NOT_STRIP_FCS flag to disable FCS/CRC stripping (when supported by the adapter)
 - Improved support for cross-compilation
 - New PF_RING_FT_CONF environment variable to enable PF_RING FT support and load L7 filtering rules
 - New PF_RING_FT_PROTOCOLS environment variable to load L7 protocols when PF_RING FT for L7 filtering is enabled

* ZC Library
 - New pfring_zc_open_device flag PF_RING_ZC_DO_NOT_STRIP_FCS to disable FCS/CRC stripping (when supported by the adapter)
 - New builtin hash function pfring_zc_builtin_5tuple_hash based on 5-tuple
 - Fixed SPSC queues BPF support
 - Fixed KVM/ivshmem support on Ubuntu 16
 - Fixed pfring_zc_recv_pkt_burst with ixgbe-zc drivers

* FT Library
 - New pfring_ft_set_l7_detected_callback API to set a callback for classified flows/packets (L7 protocol detected)
 - New pfring_ft_set_default_action API to set the default action for classified L7 flows
 - New pfring_ft_flow_get_action API to get the computed/actual flow action asyncronously
 - New pfring_ft_create_table flow_lifetime_timeout parameter to configure the maximum flow duration
 - New pfring_ft_load_ndpi_protocols API to load custom nDPI protocols from a configuration file (example: https://github.com/ntop/nDPI/blob/dev/example/protos.txt)
 - New pfring_ft_is_ndpi_available API to check nDPI availability
 - Added active_flows to pfring_ft_stats to get the number of currently active flows

* PF_RING-aware Libpcap
 - New pcap_get_pfring_handle API to get the PF_RING handle used by Libpcap
 - New PCAP_PF_RING_ALWAYS_SYNC_FD environment variable for applications not using the fd provided by pcap_get_selectable_fd
 - Fix for applications polling from the pcap selectable fd when ZC drivers are used

* PF_RING Kernel Module
 - Updates to support kernel 4.18 or older
 - Fixed 'stack' TX capture in ZC mode
 - Fixed ifindex lookup
 - Fixed promiscuous mode corner cases
 - Fixed arm32 support
 - Fixed IPv6 support in software filtering rules
 - Fixed software hash rules
 - Fixed kernel clustering in case of non-IP packets (sporadically recognized as IP fragments when the fragments cache was enabled)

* PF_RING Capture Modules
 - Timeline module fixes:
   - Fixed extraction of non-IP packets
   - Fixed permissions check when running as unprivileges user, when the user has permissions on the filesystem
 - Accolade module update to support latest SDK API and features
 - Fixed Fiberblaze module bulk mode

* ZC Drivers
 - New ixgbevf ZC driver
 - Drivers updates to support kernel 4.18 or older
 - Fixed sporadic crashes during application startup on high traffic rates
 - Fixed the DKMS packages
 - i40e ZC driver improvements:
   - Forcing symmetric RSS hash on old firmwares
   - Improved interrupts management to fix packets delivered in batches
   - Fixed interrupts management when multiple sockets are active on the same interface (RX+TX or RSS)
 - ixgbe ZC driver improvements:
   - Increased max MTU length to 16K
   - Fixed card reset due to kernel-space TX packets pending while the interface is in use by ZC
 - Improved hardware timestamp support for igb ZC (i350/82580 adapters)

* nBPF 
 - Fixed 'portrange' token in BPF-like filters

* Examples
 - New pftimeline example to extract traffic from a n2disk dump set using the pf_ring API
 - New pfsend -M <mac> option to forge the source MAC address
 - zbalance_ipc improvements:
   - Added -m 6 distribution function (interface X to queue X)
   - Added queues and TX interface stats under /proc (-p)
   - Fixed multiapp (fanout) distribution for more than 32 egress queues
 - ftflow improvements:
   - New -F option to load rules from a configuration file
   - New -p option to load custom protocols
   - Improved output (e.g. printing the flow action)
 - Improved ftflow_dpdk example, added bridging support 
 - Fixed software filtering in pfcount (enabling full headers when filtering is enabled)

* IDS Support (Snort/Bro)
 - Fixed Snort DAQ filtering API
 - Fixed cluster issues on Bro (due to a libpcap symbols issue)

* Misc
 - Improved 'zbalance_ipc' clusters management with systemd:
   - Service improvements to set the status after the cluster process is actually up and running
   - Fixed hugepages memory allocation in case of clusters not using ZC drivers 
 - CoreOS support, pf_ring module and drivers installation scripts
 - Improved service dependencies with systemd with respect to other ntop applications
 - Added GID to the hugepages configuration file to allow nonprivileged users to use ZC applications

---------------------------------------
2018-06-12 PF_RING 7.2

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

