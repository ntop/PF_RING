#!/bin/bash

if [ -z $# ]; then
    ifname=eth0
else
    ifname=$1
    shift
fi

COUNTER=0
while [  $COUNTER -lt 1000 ]; do
../pfcount -i $ifname -v 1 &
sleep 1
killall -9 pfcount
let COUNTER=COUNTER+1 
done
