#!/bin/sh

echo "Loading the DAG module"

rmmod dag
rmmod dagmem
modprobe dagmem dsize=512M

sleep 1

/usr/local/bin/dagload

sleep 1

/usr/local/bin/dagconfig -d0 default

sleep 1

/usr/local/bin/dagconfig -d0 mem=256:256

sleep 1

echo "Configuration completed."

echo "If you need to convert a pcap to .erf do"
echo "/usr/local/bin/dagconvert -T pcap:erf -A 8 -i 10k_UDP_Flows.pcap -o 10k_UDP_Flows.erf"
echo "/usr/local/bin/dagflood -f erf/10k_UDP_Flows_512byte.erf -d dag0 -t 10"
