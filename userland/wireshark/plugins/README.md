# Wireshark Plugins

This directory contains Wireshark plugins. 

## PF_RING Flow Offload Record Dissector

This is a dissector for PF_RING flow updates, sent when hardware offload is enabled (see Accolade Flow offload). 
Please refer to pfflow.c (see userland/examples) for an example of usage of flow offload in PF_RING.

In order to install this plugin inside Wireshark, do:

```
cp PFRingFlow.lua ~/.wireshark/plugins/
```

and restart Wireshark.
