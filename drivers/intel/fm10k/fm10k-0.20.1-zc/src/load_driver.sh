#!/bin/bash

FAMILY=fm10k
IS_SILICOM=0

#service udev start

# Remove old modules (if loaded)
rmmod fm10k
rmmod pf_ring

HUGEPAGES=1024
if [ `cat /proc/mounts | grep hugetlbfs | wc -l` -eq 0 ]; then
	sync && echo 3 > /proc/sys/vm/drop_caches
	echo $HUGEPAGES > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
	mkdir /mnt/huge
	mount -t hugetlbfs nodev /mnt/huge
fi
AVAILHUGEPAGES=$(grep HugePages_Total /sys/devices/system/node/node0/meminfo | cut -d ':' -f 2|sed 's/ //g')
if [ $AVAILHUGEPAGES -ne $HUGEPAGES ]; then 
	printf "Warning: %s hugepages available, %s requested\n" "$AVAILHUGEPAGES" "$HUGEPAGES"
fi

# We assume that you have compiled PF_RING
insmod ../../../../../kernel/pf_ring.ko

# Required by fm10k
modprobe uio
modprobe ptp
modprobe vxlan

# Load the driver
insmod ./fm10k.ko

sleep 1

killall irqbalance 

INTERFACES=$(cat /proc/net/dev|grep ':'|grep -v 'lo'|grep -v 'sit'|awk -F":" '{print $1}'|tr -d ' ')
for IF in $INTERFACES ; do
	TOCONFIG=$(ethtool -i $IF|grep $FAMILY|wc -l)
        if [ "$TOCONFIG" -eq 1 ]; then
		printf "Configuring %s\n" "$IF"

		# Set number of RSS queues
		ethtool -L $IF combined 1

		# Max number of RX slots
		ethtool -G $IF rx 16384

		# Max number of TX slots
		ethtool -G $IF tx 16384

		# Disabling offloads
		ethtool -K $IF sg off tso off gso off gro off > /dev/null 2>&1

		# Disabling VLAN stripping
		ethtool -K $IF rxvlan off

		# Flow Control automatically disabled by the driver (no need to use the following commands)
		#ethtool -A $IF autoneg off
		#ethtool -A $IF rx off
		#ethtool -A $IF tx off
		#ethtool -s $IF speed 10000

		# Enable n-tuple hw filters
		#ethtool -K $IF ntuple on

		ifconfig $IF up
		sleep 1
		bash ../scripts/set_irq_affinity $IF
	fi
done


if [ "$IS_SILICOM" -eq 1 ]; then
	nohup rdif start &

	sleep 2

	# Configure the switch to act as a standard NIC
	# Note: 
	# 1,2 are the external ports
	# 3,4 are the internal interfaces
	rdifctl set_port_mask 3 1
	rdifctl set_port_mask 1 3
	rdifctl set_port_mask 2 4
	rdifctl set_port_mask 4 2
fi

