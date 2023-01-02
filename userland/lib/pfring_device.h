/*
 *
 * (C) 2005-2018 - ntop
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 *
 */

#ifndef _PFRING_DEVICE_NAME_H_
#define _PFRING_DEVICE_NAME_H_

#include "pfring.h"
#include "pfring_utils.h"

typedef struct pfring_device_elem_s {
  char *ifname;
  u_int16_t vlan_id; // 0 for no vlan
  struct pfring_device_elem_s* next;
} pfring_device_elem;

typedef struct {
  u_int64_t channel_mask;
  pfring_device_elem *elems;
} pfring_device;

void pfring_device_fprint(pfring_device* device, FILE *stream);
void pfring_device_dump(pfring_device* device);
pfring_device* pfring_parse_device_name(char* device_name);
void pfring_device_free(pfring_device* device);

#endif

