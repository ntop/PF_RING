/*
 *  Copyright (C) 2016 ntop.org
 *
 *      http://www.ntop.org/
 *
 */

#ifndef FAST_BPF_MOD_RDIF_H
#define FAST_BPF_MOD_RDIF_H

#define MAX_INTEL_DEV 4

typedef enum {
  INTERFACE_1 = 0,
  INTERFACE_2,
  MAX_INTERFACE
} fast_bpf_rdif_interface_t;

int fast_bpf_rdif_reset(int unit);
int fast_bpf_rdif_init(int unit, fast_bpf_rdif_interface_t intf);
int fast_bpf_rdif_set_filter(int unit, fast_bpf_rdif_interface_t intf, char *bpf);

#endif
