# Wireshark Accolade Flow Offload Dissector

This directory contains the wireshark dissector for Accolade flow updates
sent when hardware offload is enabled. Please refer to pfflow.c (see userland/examples)
for an example of usage of flow offload in PF_RING.


In order to install this plugin inside wireshark, do:

```
cp Accolade.lua ~/.wireshark/plugins/
```

and restart wireshark.
