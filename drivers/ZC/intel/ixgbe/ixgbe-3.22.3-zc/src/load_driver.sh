#!/bin/bash

FAMILY=ixgbe

#service udev start

# Remove old modules (if loaded)
rmmod ixgbe
rmmod pf_ring

# We assume that you have compiled PF_RING
insmod ../../../../../../kernel/pf_ring.ko

# Required by ixgbe
modprobe ptp

# As many queues as the number of processors
#insmod ./ixgbe.ko RSS=0,0,0,0

# Disable multiqueue
insmod ./ixgbe.ko RSS=1,1,1,1 

# Low-latency precise transmission rate
#insmod ./ixgbe.ko RSS=1,1,1,1 low_latency_tx=1

# Enable 16 queues
#insmod ./ixgbe.ko MQ=1,1,1,1 RSS=16,16,16,16

# Enable max number of hw filters
#insmod ./ixgbe.ko RSS=1,1,1,1 FdirPballoc=3,3,3,3

# Select the CPU of the NUMA node where per-adapter memory will be allocated
#insmod ./ixgbe.ko RSS=1,1,1,1 numa_cpu_affinity=0,0,0,0

sleep 1

killall irqbalance 

INTERFACES=$(cat /proc/net/dev|grep ':'|grep -v 'lo'|grep -v 'sit'|awk -F":" '{print $1}'|tr -d ' ')
for IF in $INTERFACES ; do
	TOCONFIG=$(ethtool -i $IF|grep $FAMILY|wc -l)
        if [ "$TOCONFIG" -eq 1 ]; then
		printf "Configuring %s\n" "$IF"
		ifconfig $IF up
		sleep 1
		bash ../scripts/set_irq_affinity $IF

		# Max number of RX slots
		ethtool -G $IF rx 32768

		# Max number of TX slots
		ethtool -G $IF tx 32768

		# Disabling VLAN stripping
		ethtool -K $IF rxvlan off

		# Flow Control automatically disabled by the driver (no need to use the following commands)
		#ethtool -A $IF autoneg off
		#ethtool -A $IF rx off
		#ethtool -A $IF tx off
		#ethtool -s $IF speed 10000

		# Enable n-tuple hw filters
		#ethtool -K $IF ntuple on

		# Virtual Functions (host)
		#
		# Add the kernel parameters below to grub and reboot the machine:
		# $ vim /etc/default/grub
		# GRUB_CMDLINE_LINUX_DEFAULT="iommu=1 msi=1 pci=assign-busses intel_iommu=on"
		# $ update-grub && reboot
		#
		# Create a XML file with bus/slot/function of the VF (see lscpi):
		# <interface type='hostdev' managed='yes'>
		#     <source>
		#         <address type='pci' domain='0' bus='11' slot='16' function='0'/>
		#     </source>
		# </interface>
		#
		# Add the VF to the VM configuration:
		# $ virsh attach-device <vm name> <xml file> --config
		#
		# Assign more memory to the VM:
		# $ virsh setmaxmem ubuntu14 2097152 --config
		# $ virsh setmem ubuntu14 2097152
		#
		# Enable 2 Virtual Functions per interface (uncomment the following line before running the script)
		#echo '2' > /sys/bus/pci/devices/$(ethtool -i $IF | grep bus-info | cut -d ' ' -f2)/sriov_numvfs
	fi
done

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

