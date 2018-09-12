#!/bin/bash
#
# Load KVM modules and create a bridge br0 with the provided interface
# that will be used by the VMs for network connectivity. Example:
# 
# $ ./kvm-load.sh eth1 
#

switch=br0

modprobe kvm_intel
modprobe vhost_net

modprobe tun
modprobe bridge

brctl addbr $switch
brctl addif $switch $1
ifconfig $switch up

