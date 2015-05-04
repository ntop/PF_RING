#!/bin/bash


COUNTER=0
while [  $COUNTER -lt 1000 ]; do
../pfcount -i eth0 -v &
sleep 1
killall -9 pfcount
let COUNTER=COUNTER+1 
done
