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

typedef struct { // TODO add instance data here
  int unit;
  fast_bpf_rdif_interface_t intf;
} fast_bpf_rdif_handle_t;

int fast_bpf_rdif_reset(int unit); //TODO needs to be moved to driver init

fast_bpf_rdif_handle_t *fast_bpf_rdif_init(char *ifname);
int fast_bpf_rdif_set_filter(fast_bpf_rdif_handle_t *handle, char *bpf);

#endif
