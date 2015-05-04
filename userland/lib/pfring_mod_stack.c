/*
 *
 * (C) 2005-14 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 */

#include "pfring.h"
#include "pfring_mod.h"
#include "pfring_mod_stack.h"

/* **************************************************** */

int pfring_mod_stack_open(pfring *ring) {
  int rc;
  u_int32_t dummy = 0;

  rc = pfring_mod_open(ring);

  if (rc != 0)
    return rc;

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

