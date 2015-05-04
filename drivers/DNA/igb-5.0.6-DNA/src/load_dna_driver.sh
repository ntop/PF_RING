#!/bin/bash

# Configure here the network interfaces to activate
IF[0]=dna0
IF[1]=dna1
IF[2]=dna2
IF[3]=dna3
IF[4]=dna4
IF[5]=dna5
IF[6]=dna6
IF[7]=dna7

#service udev start

# Remove old modules (if loaded)
rmmod igb
rmmod pf_ring

# We assume that you have compiled PF_RING
insmod ../../../../kernel/pf_ring.ko

# Disable multiqueue
insmod ./igb.ko RSS=1,1,1,1,1,1,1,1

# Enable multiqueue (auto)
#insmod ./igb.ko RSS=0,0,0,0,0,0,0,0

# Enable 8 queues (you need 8 or more CPU cores)
#insmod ./igb.ko RSS=8,8,8,8,8,8,8,8

sleep 1

killall irqbalance 

for index in 0 1 2 3 4 5 6 7
do
  if [ -z ${IF[index]} ]; then
    continue
  fi
  printf "Configuring %s\n" "${IF[index]}"
  ifconfig ${IF[index]} up
  sleep 1
  bash ../scripts/set_irq_affinity ${IF[index]}
#  ethtool -A ${IF[index]} autoneg off
#  ethtool -A ${IF[index]} rx off
#  ethtool -A ${IF[index]} tx off
#  ethtool -s ${IF[index]} speed 10000
done
