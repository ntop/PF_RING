#!/bin/bash

# Configure here the network interfaces to activate
IF[0]=dna0
IF[1]=dna1
IF[2]=dna2
IF[3]=dna3

#service udev start

# Remove old modules (if loaded)
rmmod ixgbe
rmmod pf_ring

# We assume that you have compiled PF_RING
insmod ../../../../kernel/pf_ring.ko

# As many queues as the number of processors
#insmod ./ixgbe.ko RSS=0,0,0,0

# Disable multiqueue
insmod ./ixgbe.ko RSS=1,1,1,1 num_rx_slots=32768 num_tx_slots=32768

# Configure the number of TX and RX slots
#insmod ./ixgbe.ko RSS=1,1,1,1 num_rx_slots=32768 num_tx_slots=4096

# Enable 16 queues
#insmod ./ixgbe.ko MQ=1,1,1,1 RSS=16,16,16,16

# Enable max number of hw filters
#insmod ./ixgbe.ko RSS=1,1,1,1 FdirPballoc=3,3,3,3

# Set a large MTU (jumbo frame)
#insmod ./ixgbe.ko RSS=1,1,1,1 mtu=9000

# Select the CPU of the NUMA node where per-adapter memory will be allocated
#insmod ./ixgbe.ko RSS=1,1,1,1 numa_cpu_affinity=0,0,0,0

sleep 1

killall irqbalance 

for index in 0 1 2 3
do
  if [ -z ${IF[index]} ]; then
    continue
  fi
  printf "Configuring %s\n" "${IF[index]}"
  ifconfig ${IF[index]} up
  sleep 1
  bash ../scripts/set_irq_affinity ${IF[index]}

  # Flow Control automatically disabled by the driver (no need to use the following commands)
  #ethtool -A ${IF[index]} autoneg off
  #ethtool -A ${IF[index]} rx off
  #ethtool -A ${IF[index]} tx off
  #ethtool -s ${IF[index]} speed 10000

  # Enable n-tuple hw filters
  #ethtool -K ${IF[index]} ntuple on
done
