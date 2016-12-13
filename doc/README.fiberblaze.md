# Fiberblaze support in PF_RING

## Prerequisites
We expect you to have installed the Fiberblaze drivers and loaded them. Typical commands are

```
# echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
# cd /opt/fiberblaze/driver
# ./load_driver.sh hugepages='2G'
# cd /opt/fiberblaze/bin
# ./configurecard --device fbcard0 --configuration ../fbcard.cfg
```

## Usage
PF_RING-enabled apps see Fiberblaze cards as fbcard:XXXX devices. However due to the Fiberblaze naming, you need to use different device names, depending if you send or receive traffic.

# RX
The naming convention is fbcard:<card_id>:<group name>:<group ring id> where <card_id> is the id of the card we want to open, <group name> is the name of the group specified in fbcard.cfg used by configurecard, and <ring id> (in case of traffic hashing, i.e. Fiberblaze's RSS) if the id of the PRBs.

Example if you have set in fbcard.cfg

```
prbGroup "b"
{
    noPrbs 8
    hash HashPacket
    filter "hash"
}
```

the device names are
```
fbcard:0:b:0
fbcard:0:b:1
...
fbcard:0:b:7
```

Example (receive packets from card 0, group "b, ring 0): 
```
pfcount -i fbcard:0:b:0
```

# TX
The naming convention is fbcard:<card_id>:<port id>. If you have a 4 port NIC, the <port id> will be 0 to 3.

Example (send packets from port 1 of cardId 0):
```
pfsend -i fbcard:0:1
```
