#!/bin/bash

FAMILY=iavf

# Virtual Functions (host - i40e)
#
# Add the kernel parameters below to grub and reboot the machine:
# $ vim /etc/default/grub
# GRUB_CMDLINE_LINUX_DEFAULT="iommu=1 msi=1 pci=assign-busses intel_iommu=on"
# $ update-grub && reboot
#
# Note:at least pci=assign-busses is required to fix failures reported in dmesg as below:
#
# i40e 0000:02:00.0 enp2s0f0: SR-IOV enabled with 1 VFs
# i40e 0000:02:00.0: can't enable 1 VFs (bus 03 out of range of [bus 02])
# i40e 0000:02:00.0: Failed to enable PCI sriov: -12
#
# Enable 2 Virtual Functions per interface (uncomment the following line before running the script)
# $ echo '2' > /sys/bus/pci/devices/$(ethtool -i $IF | grep bus-info | cut -d ' ' -f2)/sriov_numvfs
#
# Filter traffic for VF also based on VLAN ID (in addition to MAC address)
# $ ip link set $IF vf $VF_ID vlan $VLAN_ID
#
# Filter traffic for VF based on VLAN ID only (promisc - ignore the MAC address)
# $ ip link set $IF vf $VF_ID vlan $VLAN_ID
# $ ip link set dev $IF vf $VF_ID trust on
#
# Reset VLAN FILTER
# $ ip link set $IF vf $VF_ID vlan 0
#
# Receive all traffic from the physical interface (promisc)
# $ ip link set dev $IF vf $VF_ID trust on
#

# Remove old modules (if loaded)
rmmod iavf
rmmod pf_ring

# We assume that you have compiled PF_RING
insmod ../../../../../kernel/pf_ring.ko

# Required by iavf
modprobe ptp
modprobe vxlan
modprobe configfs

# Load the driver
insmod ./iavf.ko

sleep 1

pkill irqbalance 

INTERFACES=$(cat /proc/net/dev|grep ':'|grep -v 'lo'|grep -v 'sit'|awk -F":" '{print $1}'|tr -d ' ')
for IF in $INTERFACES ; do
	TOCONFIG=$(ethtool -i $IF|grep $FAMILY|wc -l)
        if [ "$TOCONFIG" -eq 1 ]; then
		printf "Configuring %s\n" "$IF"

		# Set number of RSS queues
		ethtool -L $IF combined 1

		# Max number of RX slots
		ethtool -G $IF rx 4096

		# Max number of TX slots
		ethtool -G $IF tx 4096

		# Disabling offloads
		ethtool -K $IF sg off tso off gso off gro off > /dev/null 2>&1

		# Disabling VLAN stripping
		ethtool -K $IF rxvlan off

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

