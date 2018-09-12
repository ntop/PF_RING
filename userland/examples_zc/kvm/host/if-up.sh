#!/bin/sh
#
# Add an interface to the bridge
# Do not execute this script directly - this is used by QEMU
#

set -x

switch=br0

if [ -n "$1" ];then
	tunctl -b -t $1
	ifconfig $1 up 0.0.0.0 promisc
	sleep 0.5s
	brctl addif $switch $1
	exit 0
else
	echo "Error: no interface specified"
	exit 1
fi
