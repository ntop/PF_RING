/*
 *
 * (C) 2012-2018 - ntop.org
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

/* ********************************* */

static int virtual_filtering_device_add_hw_rule(pfring *ring, hw_filtering_rule *rule) {
  return setsockopt(ring->fd, 0, SO_ADD_HW_FILTERING_RULE, rule, sizeof(hw_filtering_rule));
}

static int virtual_filtering_device_remove_hw_rule(pfring *ring, u_int16_t rule_id) {
  return setsockopt(ring->fd, 0, SO_DEL_HW_FILTERING_RULE, &rule_id, sizeof(rule_id));
}

/* ********************************* */

#include "pfring_i82599.c"

/* ********************************* */

void pfring_hw_ft_init(pfring *ring) {
  int rc;
  socklen_t len = sizeof(pfring_device_type);

  rc = getsockopt(ring->fd, 0, SO_GET_DEVICE_TYPE, &ring->ft_device_type, &len);

  if(rc < 0)
    ring->ft_device_type = standard_nic_family;
}

/* ********************************* */

int pfring_hw_ft_set_traffic_policy(pfring *ring, u_int8_t rules_default_accept_policy) {
  return 0;
}

/* ********************************* */

int pfring_hw_ft_add_hw_rule(pfring *ring, hw_filtering_rule *rule) {
  int rc;

  if(!rule)
    return -2;

  switch (ring->ft_device_type) {
    case intel_82599_family:
      rc = virtual_filtering_device_add_hw_rule(ring, rule);
      break;

    case standard_nic_family:
    default:
      rc = 0;
    break;
  }

  return rc;
}

/* ********************************* */

int pfring_hw_ft_remove_hw_rule(pfring *ring, u_int16_t rule_id) {
  int rc;

  switch (ring->ft_device_type) {
    case intel_82599_family:
      rc = virtual_filtering_device_remove_hw_rule(ring, rule_id);
      break;

    case standard_nic_family:
    default:
      rc = 0;
    break;
  }

  return rc;
}

/* ********************************* */

int pfring_hw_ft_handle_hash_filtering_rule(pfring *ring, hash_filtering_rule* rule_to_add, u_char add_rule) {
  int rc;

  if(!rule_to_add)
    return -2;

  switch (ring->ft_device_type) {
    case intel_82599_family:
      if(add_rule)
        rc = i82599_add_hash_filtering_rule(ring, rule_to_add);
      else
        rc = i82599_remove_filtering_rule(ring, rule_to_add->rule_id);
      break;

    case standard_nic_family:
    default:
      rc = 0;
    break;
  }

  return rc;
}

/* ********************************* */

int pfring_hw_ft_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add) {
  int rc;

  if(!rule_to_add)
    return -2;

  switch (ring->ft_device_type) {
    case intel_82599_family:
      rc = i82599_add_filtering_rule(ring, rule_to_add); 
      break;

    case standard_nic_family:
    default:
      rc = 0;
    break;
  }

  return rc;
}

/* ********************************* */

int pfring_hw_ft_remove_filtering_rule(pfring *ring, u_int16_t rule_id) {
  int rc;

  switch (ring->ft_device_type) {
    case intel_82599_family:
      rc = i82599_remove_filtering_rule(ring, rule_id);
      break;

    case standard_nic_family:
    default:
      rc = 0;
    break;
  }

  return rc;
}

