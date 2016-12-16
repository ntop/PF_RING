#!/bin/bash

FAMILY=igb

#service udev start

# Remove old modules (if loaded)
rmmod igb
rmmod pf_ring

# Note: for hw timestamping on supported adapters compile with make CFLAGS_EXTRA="-DIGB_PTP"

# We assume that you have compiled PF_RING
insmod ../../../../../kernel/pf_ring.ko

# Disable multiqueue
insmod ./igb.ko RSS=1,1,1,1,1,1,1,1

# As many queues as the number of processors
#insmod ./igb.ko RSS=0,0,0,0,0,0,0,0

sleep 1

killall irqbalance 

INTERFACES=$(cat /proc/net/dev|grep ':'|grep -v 'lo'|grep -v 'sit'|awk -F":" '{print $1}'|tr -d ' ')
for IF in $INTERFACES ; do
	TOCONFIG=$(ethtool -i $IF|grep $FAMILY|wc -l)
        if [ "$TOCONFIG" -eq 1 ]; then
		printf "Configuring %s\n" "$IF"
		ifconfig $IF up
		sleep 1
		
		# Max number of RX slots
		ethtool -G $IF rx 4096

		# Max number of TX slots
		ethtool -G $IF tx 4096
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

