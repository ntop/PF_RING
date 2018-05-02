#!/bin/bash

FAMILY=fm10k

#service udev start

# Remove old modules (if loaded)
rmmod fm10k
rmmod pf_ring

# We assume that you have compiled PF_RING
insmod ../../../../../kernel/pf_ring.ko

# Required by fm10k
modprobe uio
modprobe ptp
modprobe vxlan

# Load the driver
insmod ./fm10k.ko

# As many queues as the number of processors
#insmod ./ixgbe.ko RSS=0,0,0,0

# Single queue
#insmod ./ixgbe.ko RSS=1,1,1,1

sleep 1

killall irqbalance 

INTERFACES=$(cat /proc/net/dev|grep ':'|grep -v 'lo'|grep -v 'sit'|awk -F":" '{print $1}'|tr -d ' ')
for IF in $INTERFACES ; do
	TOCONFIG=$(ethtool -i $IF|grep $FAMILY|wc -l)
        if [ "$TOCONFIG" -eq 1 ]; then
		printf "Configuring %s\n" "$IF"

		# Set number of RSS queues (equivalent to RSS=1,1,1,1)
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

# In order to initialize the internal switch you need rdif/rdifctl installed
IS_RDIF_INSTALLED=`which rdif | wc -l`
IS_RDIFCTL_INSTALLED=`which rdifctl | wc -l`

if [ "$IS_RDIF_INSTALLED" -eq 1 ]; then
	if [ "$IS_RDIFCTL_INSTALLED" -eq 1 ]; then
		IS_SILICOM=1
	fi
fi

# Comment the line below if you want to configure the switch 
# with rdif/rdifctl (when available) instead of nbrokerd
IS_SILICOM=0

if [ "$IS_SILICOM" -eq 1 ]; then
	rdif stop
	nohup rdif start &

	sleep 4

	# Configure the switch to act as a standard NIC
	# Note: 
	# 1,2 are the external ports
	# 3,4 are the internal interfaces
	rdifctl clear
        rdifctl set_cfg 5
	rdifctl set_port_mask 3 1
	rdifctl set_port_mask 1 3
	rdifctl set_port_mask 2 4
	rdifctl set_port_mask 4 2
	rdifctl dir port 3 redir_port 1
	rdifctl dir port 1 redir_port 3
	rdifctl dir port 2 redir_port 4
	rdifctl dir port 4 redir_port 2
else
	NBROKER_PATH="$(cd ../../../../../userland/nbroker; pwd)"
	if [ ! -e $NBROKER_PATH/nbrokerd/nbrokerd ]; then
		cd $NBROKER_PATH
		./configure && make
	fi
	echo "FM10K switch initialization.."
	nohup $NBROKER_PATH/nbrokerd/nbrokerd -c $NBROKER_PATH/rrclib/etc/rrc/fm_platform_attributes.cfg &
	sleep 12 # It takes a while to initialize the switch
fi

