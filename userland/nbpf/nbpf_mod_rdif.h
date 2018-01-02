/*
 *  Copyright (C) 2016-2018 ntop.org
 *
 *      http://www.ntop.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef NBPF_MOD_RDIF_H
#define NBPF_MOD_RDIF_H

#ifdef HAVE_REDIRECTOR_F
#include "librdi.h"
#endif

#define MAX_INTEL_DEV 4

typedef enum {
  INTERFACE_1 = 0,
  INTERFACE_2,
  MAX_INTERFACE
} nbpf_rdif_interface_t;

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
  nbpf_rdif_interface_t intf;
  check_constraint_t constraint_parameters;
  unsigned int current_rule_id;
  rules_parameter_t rules_parameters;
} nbpf_rdif_handle_t;

int nbpf_rdif_reset(int unit); //TODO needs to be moved to driver init

nbpf_rdif_handle_t *nbpf_rdif_init(char *ifname);
int nbpf_rdif_set_filter(nbpf_rdif_handle_t *handle, char *bpf);
void nbpf_rdif_destroy(nbpf_rdif_handle_t *handle);

#endif
