---
title: "pcap Support"
description: "This is a compatibility layer for the libpcap. It allows to receive traffic from both physical adapters and pcap files, seamlessly."
outline: [2, 3]
---
# pcap Support

This is a compatibility layer for the libpcap. It allows to receive traffic from both physical adapters and pcap files, seamlessly.

## Usage

You are now ready to run any pf_ring sample application using pcap:\<interface\> or pcap:\<pcap file path\> as interface name. Example:

```shell
cd examples
./pfcount -i pcap:eth1
./pfcount -i pcap:/home/ntop/traffic.pcap
```
