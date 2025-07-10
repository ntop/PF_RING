#!/bin/bash

FAMILY=ice

# Remove old modules (if loaded)
rmmod irdma
rmmod ice
rmmod pf_ring

# We assume that you have compiled PF_RING
insmod ../../../../../kernel/pf_ring.ko

# Required by ice
#modprobe ptp
#modprobe vxlan
#modprobe configfs
modprobe gnss

mkdir -p /lib/firmware/updates/intel/ice/ddp
cp -f ../ddp/ice-1.3.35.0.pkg /lib/firmware/updates/intel/ice/ddp/ice.pkg

# Load the driver
insmod ./ice.ko RSS=1,1

# Load the driver - Debug
#insmod ./ice.ko enable_debug=1 RSS=1,1

# Load the driver - Enable RSS
#insmod ./ice.ko RSS=4,4,4,4

# Load the driver - Enable RSS - Debug
#insmod ./ice.ko RSS=4,4,4,4 enable_debug=1

sleep 1

pkill irqbalance 

INTERFACES=$(cat /proc/net/dev|grep ':'|grep -v 'lo'|grep -v 'sit'|awk -F":" '{print $1}'|tr -d ' ')
for IF in $INTERFACES ; do
	TOCONFIG=$(ethtool -i $IF|grep $FAMILY|wc -l)
        if [ "$TOCONFIG" -eq 1 ]; then
		printf "Configuring %s\n" "$IF"

		# Disabling offloads
		ethtool -K $IF sg off tso off gso off gro off > /dev/null 2>&1

		# Disabling VLAN stripping
		ethtool -K $IF rxvlan off

		ethtool -A $IF rx off
		ethtool -A $IF tx off

		ifconfig $IF up

		sleep 1

		bash ../scripts/set_irq_affinity $IF
	fi
done

HUGEPAGES_NUM=1024
HUGEPAGES_PATH=/dev/hugepages
sync && echo 3 > /proc/sys/vm/drop_caches
echo $HUGEPAGES_NUM > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
if [ `cat /proc/mounts | grep hugetlbfs | grep $HUGEPAGES_PATH | wc -l` -eq 0 ]; then
	if [ ! -d $HUGEPAGES_PATH ]; then
		mkdir $HUGEPAGES_PATH
	fi
	mount -t hugetlbfs nodev $HUGEPAGES_PATH
fi
HUGEPAGES_AVAIL=$(grep HugePages_Total /sys/devices/system/node/node0/meminfo | cut -d ':' -f 2|sed 's/ //g')
if [ $HUGEPAGES_AVAIL -ne $HUGEPAGES_NUM ]; then 
	printf "Warning: %s hugepages available, %s requested\n" "$HUGEPAGES_AVAIL" "$HUGEPAGES_NUM"
fi

