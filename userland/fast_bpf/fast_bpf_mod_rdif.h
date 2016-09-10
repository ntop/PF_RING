/*
 *  Copyright (C) 2016 ntop.org
 *
 *      http://www.ntop.org/
 *
 */

#ifndef FAST_BPF_MOD_RDIF_H
#define FAST_BPF_MOD_RDIF_H

#ifdef HAVE_REDIRECTOR_F
#include "librdi.h"
#endif

#define MAX_INTEL_DEV 4

typedef enum {
  INTERFACE_1 = 0,
  INTERFACE_2,
  MAX_INTERFACE
} fast_bpf_rdif_interface_t;

typedef struct {
   unsigned int is_and;
   unsigned int src_host;
   unsigned int dst_host;
   unsigned int src_port;
   unsigned int dst_port;
   unsigned int proto;
   unsigned int not_managed;
} check_constraint_t;

typedef struct {
   int action;
#ifdef HAVE_REDIRECTOR_F
   rdi_mem_t rdi_mem;
#endif
} rules_parameter_t;

typedef struct { // TODO add instance data here
  int unit;
  fast_bpf_rdif_interface_t intf;
  check_constraint_t constraint_parameters;
  unsigned int current_rule_id;
  rules_parameter_t rules_parameters;
} fast_bpf_rdif_handle_t;

int fast_bpf_rdif_reset(int unit); //TODO needs to be moved to driver init

fast_bpf_rdif_handle_t *fast_bpf_rdif_init(char *ifname);
int fast_bpf_rdif_set_filter(fast_bpf_rdif_handle_t *handle, char *bpf);
void fast_bpf_rdif_handle_destroy(fast_bpf_rdif_handle_t *handle);

#endif
