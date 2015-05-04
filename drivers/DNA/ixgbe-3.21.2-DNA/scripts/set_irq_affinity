# setting up irq affinity according to /proc/interrupts
# 2008-11-25 Robert Olsson
# 2009-02-19 updated by Jesse Brandeburg
#
# > Dave Miller:
# (To get consistent naming in /proc/interrups)
# I would suggest that people use something like:
#	char buf[IFNAMSIZ+6];
#
#	sprintf(buf, "%s-%s-%d",
#	        netdev->name,
#		(RX_INTERRUPT ? "rx" : "tx"),
#		queue->index);
#
#  Assuming a device with two RX and TX queues.
#  This script will assign: 
#
#	eth0-rx-0  CPU0
#	eth0-rx-1  CPU1
#	eth0-tx-0  CPU0
#	eth0-tx-1  CPU1
#

set_affinity()
{
	NUM_CORES=`grep -c ^processor /proc/cpuinfo`
	let "CORE = $VEC % $NUM_CORES"
	if [ $CORE -ge 32 ]
	then
		MASK_FILL=""
		MASK_ZERO="00000000"
		let "IDX = $CORE / 32"
		for ((i=1; i<=$IDX;i++))
		do
			MASK_FILL="${MASK_FILL},${MASK_ZERO}"
		done

		let "CORE -= 32 * $IDX"
		MASK_TMP=$((1<<$CORE))
		MASK=`printf "%X%s" $MASK_TMP $MASK_FILL`
	else
		MASK_TMP=$((1<<$CORE))
		MASK=`printf "%X" $MASK_TMP`
	fi

    printf "%s mask=%s for /proc/irq/%d/smp_affinity\n" $DEV $MASK $IRQ
    printf "%s" $MASK > /proc/irq/$IRQ/smp_affinity
}

if [ "$1" = "" ] ; then
	echo "Description:"
	echo "    This script attempts to bind each queue of a multi-queue NIC"
	echo "    to the same numbered core, ie tx0|rx0 --> cpu0, tx1|rx1 --> cpu1"
	echo "usage:"
	echo "    $0 eth0 [eth1 eth2 eth3]"
fi


# check for irqbalance running
IRQBALANCE_ON=`ps ax | grep -v grep | grep -q irqbalance; echo $?`
if [ "$IRQBALANCE_ON" == "0" ] ; then
	echo " WARNING: irqbalance is running and will"
	echo "          likely override this script's affinitization."
	echo "          Please stop the irqbalance service and/or execute"
	echo "          'killall irqbalance'"
fi

#
# Set up the desired devices.
#

for DEV in $*
do
  for DIR in rx tx TxRx
  do
     MAX=`grep $DEV-$DIR /proc/interrupts | wc -l`
     if [ "$MAX" == "0" ] ; then
       MAX=`egrep -i "$DEV:.*$DIR" /proc/interrupts | wc -l`
     fi
     if [ "$MAX" == "0" ] ; then
       #echo no $DIR vectors found on $DEV
       continue
     fi
     for VEC in `seq 0 1 $MAX`
     do
        IRQ=`cat /proc/interrupts | grep -i $DEV-$DIR-$VEC"$"  | cut  -d:  -f1 | sed "s/ //g"`
        if [ -n  "$IRQ" ]; then
          set_affinity
        else
           IRQ=`cat /proc/interrupts | egrep -i $DEV:v$VEC-$DIR"$"  | cut  -d:  -f1 | sed "s/ //g"`
           if [ -n  "$IRQ" ]; then
             set_affinity
           fi
        fi
     done
  done
done
