#!/bin/bash

FAMILY=ixgbevf

# Virtual Functions (host - ixgbe)
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

# Remove old modules (if loaded)
# Note: if we are in the host, pf_ring and ixgbe-zc are running and pf_ring will not be removed (expected)
rmmod ixgbevf
rmmod pf_ring

insmod ../../../../../kernel/pf_ring.ko
insmod ./ixgbevf.ko

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

		# Disabling VLAN stripping
		ethtool -K $IF rxvlan off
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

