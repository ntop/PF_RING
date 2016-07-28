/*
 *  Copyright (C) 2016 ntop.org
 *
 *      http://www.ntop.org/
 *
 */
#ifndef INTEL_NIC_FAST_BPF_H
#define INTEL_NIC_FAST_BPF_H

#define MAX_INTEL_DEV 4

typedef enum {
   INTERFACE_1 = 0,
   INTERFACE_2,
   MAX_INTERFACE
} intel_dev_interface_t;


extern int intel_nic_reset(int unit);
extern int intel_nic_interface_init(int unit, intel_dev_interface_t intf);
extern int intel_nic_set_fast_bpf(int unit, intel_dev_interface_t intf, char* bpf);

#endif
