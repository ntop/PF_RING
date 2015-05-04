#!/bin/bash

# This script creates a "fat" libpcap
# that includes the pfring library so
# that legacy pcap-based apps can use it
# without *also* linking against libpfring

if [ ! -f "Makefile" ]; then
./configure
fi

\rm -f libpcap.a
make
\rm -rf fatpcap
mkdir fatpcap
cd fatpcap
ar x ../libpcap.a
ar x ../../lib/libpfring.a
ar rs libpcap.a *.o
mv libpcap.a ..