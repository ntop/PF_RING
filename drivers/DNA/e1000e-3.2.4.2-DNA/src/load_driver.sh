#!/bin/bash

# Configure here the network interfaces to activate
IF[0]=dna0
IF[1]=dna1
IF[2]=
IF[3]=

# Remove old modules (if loaded)
rmmod e1000e
rmmod pf_ring

# We assume that you have compiled PF_RING
insmod ../../../../kernel/pf_ring.ko

# Default
insmod ./e1000e.ko

sleep 1

killall irqbalance 

for index in 0 1 2 3
do
  if [ -z ${IF[index]} ]; then
    continue
  fi
  printf "Configuring %s\n" "${IF[index]}"
  ifconfig ${IF[index]} up
#  sleep 1
#  bash ../scripts/set_irq_affinity.sh ${IF[index]}
#  ethtool -A ${IF[index]} autoneg off
#  ethtool -A ${IF[index]} rx off
#  ethtool -A ${IF[index]} tx off
#  ethtool -s ${IF[index]} speed 10000
done
