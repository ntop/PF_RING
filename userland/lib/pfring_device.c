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

#include "pfring_device.h"

void pfring_device_fprint(pfring_device* device, FILE *stream) {
  uint32_t idx;
  pfring_device_elem* it;

  if (device->channel_mask == RING_ANY_CHANNEL) {
    fprintf(stream, "channel: any\n");
  } else {
    uint64_t tmp_channel_mask = device->channel_mask;
    idx = 0;
    fprintf(stream, "channel:");
    while (tmp_channel_mask) {
      if (tmp_channel_mask & 1) {
        fprintf(stream, " %d", idx);
      }
      tmp_channel_mask = tmp_channel_mask >> 1;
      idx++;
    }
    fprintf(stream, "\n");
  }

  idx = 0;
  fprintf(stream, "elems:\n");
  for (it = device->elems; it != NULL; it=it->next) {
    fprintf(stream, "  elem #%d, ifname: %s, vlan_id: %d\n", idx, it->ifname, it->vlan_id);
  }
}

void pfring_device_dump(pfring_device* device) {
  pfring_device_fprint(device, stdout);
}

void pfring_device_add_elem(pfring_device* device, char *ifname, u_int16_t vlan_id) {
  pfring_device_elem *elem = (pfring_device_elem *)malloc(sizeof(pfring_device_elem));
  elem->ifname = ifname;
  elem->vlan_id = vlan_id;
  elem->next = device->elems;
  device->elems = elem;
}

u_int64_t pfring_parse_channel_mask_string(char* chmask) {
  u_int64_t channel_mask = 0;
  char *tok, *at, *pos;

  /* Syntax
     ethX@1,5       channel 1 and 5
     ethX@1-5       channel 1,2...5
     ethX@1-3,5-7   channel 1,2,3,5,6,7
     */

  at = strdup(chmask);
  pos = NULL;
  tok = strtok_r(at, ",", &pos);

  while(tok != NULL) {
    char *dash = strchr(tok, '-');
    int32_t min_val, max_val, i;

    if(dash) {
      dash[0] = '\0';
      min_val = atoi(tok);
      max_val = atoi(&dash[1]);

    } else
      min_val = max_val = atoi(tok);

    for(i = min_val; i <= max_val; i++)
      channel_mask |= 1 << i;

    tok = strtok_r(NULL, ",", &pos);
  }
  return channel_mask;
}

pfring_device* pfring_parse_device_name(char* device_name) {
  pfring_device* dev = (pfring_device *)malloc(sizeof(pfring_device));
  dev->elems = NULL;
  dev->channel_mask = RING_ANY_CHANNEL;
  char *ch;

  u_int8_t is_braced = 0;
  u_int8_t is_in_vlan = 0;
  u_int16_t vlan_id = 0;
  char *curr_ifname = (char *)malloc(IFNAMSIZ);
  char *curr_ifname_end = curr_ifname;
  for (ch = device_name; *ch != '\0'; ++ch) {
    if (is_braced) {
      if (*ch == ')') {
        is_braced = 0;
        continue;
      } else {
        goto __raw;
      }
    }
    if (is_in_vlan) {
      if ((*ch <= '9') && (*ch >= '0')) {
        vlan_id = vlan_id * 10 + (*ch - '0');
        continue;
      } else if ((*ch == ',') || (*ch == '@')) {
        // down to main routine
      } else {
        return NULL;
      }
    }
    switch (*ch) {
      case '@':
        goto __channel_mask;
      case ',':
        *curr_ifname_end = '\0';
        pfring_device_add_elem(dev, curr_ifname, vlan_id);
        curr_ifname = (char *)malloc(IFNAMSIZ);
        curr_ifname_end = curr_ifname;
        vlan_id = 0;
        is_in_vlan = 0;
        continue;
      case '(':
        is_braced = 1;
        continue;
      case '.':
        is_in_vlan = 1;
        continue;
      default: break;
    }
__raw:
    *curr_ifname_end = *ch;
    curr_ifname_end ++;
    if ((curr_ifname_end - curr_ifname) >= IFNAMSIZ) {
      return NULL;
    }
  }

  if (curr_ifname_end != curr_ifname) {
    *curr_ifname_end = '\0';
    pfring_device_add_elem(dev, curr_ifname, vlan_id);
  }

  return dev;

__channel_mask:
  if (curr_ifname_end != curr_ifname) {
    *curr_ifname_end = '\0';
    pfring_device_add_elem(dev, curr_ifname, vlan_id);
  }

  char* ch_mask_s = ch + 1;
  dev->channel_mask = pfring_parse_channel_mask_string(ch_mask_s);

  return dev;
}

void pfring_device_free(pfring_device* device) {
  pfring_device_elem *it, *to_free;
  if (!device) {
    return;
  }
  for (it = device->elems; it != NULL;) {
    free(it->ifname);
    to_free = it;
    it = it->next;
    free(to_free);
  }
  free(device);
}

