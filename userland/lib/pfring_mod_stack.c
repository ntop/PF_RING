/*
 *
 * (C) 2005-21 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 *
 */

#include "pfring.h"
#include "pfring_mod.h"
#include "pfring_mod_stack.h"

/* **************************************************** */

static int __system_name_lookup(char *name, char *system_name, int system_name_len) {
  pfring_if_t *pfdevs, *pfdev;
  int found = 0;

  pfdevs = pfring_findalldevs();

  if (!pfdevs)
    return 0;

  pfdev = pfdevs;
  while (pfdev != NULL) {

    if (pfdev->name && pfdev->system_name) {
      char *name = pfdev->name;
      char *mod_colon, *at;

      mod_colon = strchr(name, ':');
      if (mod_colon)
        name = &mod_colon[1];

      at = strchr(name, '@');
      if (at)
        at[0] = '\0';

      if (strcmp(pfdev->name, name) == 0) {
        snprintf(system_name, system_name_len, "%s", pfdev->system_name);
        found = 1;
        break;
      }
    }

    pfdev = pfdev->next;
  }

  pfring_freealldevs(pfdevs);

  return found;
}

/* **************************************************** */

int pfring_mod_stack_open(pfring *ring) {
  u_int32_t dummy = 0;
  int rc;

  rc = pfring_mod_open(ring);

  if (rc != 0) {
    char system_name[24];
    char *device_name;

    /* Lookup device bound to a system dev with a different name (e.g. mlx) */
    if (__system_name_lookup(ring->device_name, system_name, sizeof(system_name))) {
      device_name = strdup(system_name);
      if (device_name) {
        free(ring->device_name);
        ring->device_name = device_name;
        rc = pfring_mod_open(ring);
      }
    }
  }

  if (rc != 0) {
    return rc;
  }

  rc = setsockopt(ring->fd, 0, SO_SET_STACK_INJECTION_MODE, &dummy, sizeof(dummy));

  if (rc != 0) {
    pfring_close(ring);
    return rc;
  }

  pfring_set_direction(ring, tx_only_direction);
  pfring_set_socket_mode(ring, send_and_recv_mode);

  /* Only send (inject) and recv (intercept tx) are supported, resetting unused func ptrs */
  ring->set_direction       = NULL; 
  ring->set_cluster         = NULL; 
  ring->remove_from_cluster = NULL; 
  ring->set_master_id       = NULL; 
  ring->set_master          = NULL; 
  ring->enable_rss_rehash   = NULL; 
  ring->set_virtual_device  = NULL; 
  ring->add_hw_rule         = NULL; 
  ring->remove_hw_rule      = NULL; 
  ring->send_last_rx_packet = NULL;

  return 0;
}

/* **************************************************** */

