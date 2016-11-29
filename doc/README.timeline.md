# n2disk "timeline" module for PF_RING

## Overview
This module can be used to seamlessly extract traffic from a n2disk timeline using the PF_RING API.
n2disk is a traffic recording application producing multiple PCAP files (a per-file limit in duration 
or size can be used to control the file size), an index per file, and a timeline for keeping all the 
files in chronological order. Thanks to this module it is possible to query the timeline for specific
packets belonging to the whole dump set in a given time interval, matching a specific BPF filter.

## Requirements
Install pfring and n2disk following the instruction at http://packages.ntop.org according to your 
linux distribution and load the PF_RING kernel module:

```
/etc/init.d/pf_ring forcestart
```

## Creating a dump set with n2disk
This module extracts traffic from a n2disk dump set consisting of PCAP files, index files, and a timeline.
In order to instruct n2disk to create on-the-fly indexes you should use the -I option. The -A \<path\> option
instead should be used to create a timeline in \<path\>.

Command line example:

```
n2disk -i eth1 -o /storage/n2disk/eth1 -I -A /storage/n2disk/eth1/timeline
```

For additional options please refer to the n2disk documentation.

## Using the "timeline" module
In order to tell PF_RING that you want to select the timeline module, you should use the "timeline:" prefix 
followed by the timeline path as interface name. In addition to this, it is mandatory to provide a BPF filter
containing at the beginning the time interval using "start" and "end" tokens, followed by the actual packet 
filter (a subset of the BPF syntax is supported, please refer to the n2disk documentation) as in the example
below:

```
pfcount -i timeline:/storage/n2disk/eth1/timeline -f "start 2016-09-22 8:40:53 and end 2016-09-22 10:43:54 and host 192.168.2.130"
```

## Wireshark support
One of the most common use cases for the timeline module is the Wireshark integration, in fact it is very 
convenient to run wireshark directly on a n2disk timeline, specifying a BPF filter for extracting a small
portion of the whole dump set, and starting the analysis task while the extraction is progressing.
Since you cannot use timeline:<path> as interface name (Wireshark lets you choose PCAP files and devices 
as traffic sources, but it is not aware of n2disk timelines), you have to create a virtual interface 
(which is just a placeholder) bound to your actual timeline, and select it as traffic source. The 
PF_RING-aware libpcap will do all the rest. In order to create the virtual interface please use the 
'n2if' script (under the tools/ folder if you are not using packages). 

Example:

``` 
n2if up -t /storage/n2disk/eth1/timeline -d timeline0
``` 

After creating the virtual interface bound to the timeline, you should be able to run an extraction using 
Wireshark (or tshark).
Please note you should set the env var LD_LIBRARY_PATH with the PCAP-over-PF_RING library installation path 
(default is /usr/local/lib/) in order to force Wireshark to load the correct libpcap. Please also note that
the Wireshark provided by most distros are compiled across libpcap.so.0.8, thus you probably need to create
an ad-hoc symlink:

```
ln -s /usr/local/lib/libpcap.so /usr/local/lib/libpcap.so.0.8 
``` 

At this point you should be able to run Wireshark providing the virtual interface created with n2if
and a BPF filter containing the time interval as described above:

```
LD_LIBRARY_PATH=/usr/local/lib/ tshark -i timeline0  -f "start 2016-09-22 8:40:53 and end 2016-09-22 10:43:54 and host 192.168.2.130"
```

Note: if you are using the Wireshark GUI, you should run just the wireshark command without any option, then
select the virtual interface from the GUI and set a capture filter as above.

```
LD_LIBRARY_PATH=/usr/local/lib/ wireshark
```

