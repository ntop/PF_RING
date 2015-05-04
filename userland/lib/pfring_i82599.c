/*
 *
 * (C) 2011-14 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 */

/* ********************************* */

int i82599_add_hash_filtering_rule(pfring *ring, hash_filtering_rule* rule_to_add) {
  hw_filtering_rule rule;
  memset(&rule, 0, sizeof(rule));

  //if(ring->ft_device_type != intel_82599_family
  //&& ring->dna_dev.mem_info.device_model != intel_ixgbe_82599)
  //  return -4;

  switch(rule_to_add->rule_action) {
  case forward_packet_and_stop_rule_evaluation:
  case forward_packet_add_rule_and_stop_rule_evaluation:
    return 0; /* Nothing to do */

  case dont_forward_packet_and_stop_rule_evaluation:
    break; /* Ok - DROP */

  case reflect_packet_and_stop_rule_evaluation:
  case reflect_packet_and_continue_rule_evaluation:
  case bounce_packet_and_stop_rule_evaluation:
  case bounce_packet_and_continue_rule_evaluation:
  case execute_action_and_continue_rule_evaluation:
  case execute_action_and_stop_rule_evaluation:
  default:
    return -3; /* Not supported */
  }

  rule.rule_id = rule_to_add->rule_id;
  rule.rule_family_type = intel_82599_perfect_filter_rule;
  rule.rule_family.perfect_rule.vlan_id  = rule_to_add->vlan_id;
  rule.rule_family.perfect_rule.proto    = rule_to_add->proto;
  rule.rule_family.perfect_rule.s_addr   = rule_to_add->host_peer_a.v4;
  rule.rule_family.perfect_rule.d_addr   = rule_to_add->host_peer_b.v4;
  rule.rule_family.perfect_rule.s_port   = rule_to_add->port_peer_a;
  rule.rule_family.perfect_rule.d_port   = rule_to_add->port_peer_b;
  rule.rule_family.perfect_rule.queue_id = -1;

  return virtual_filtering_device_add_hw_rule(ring, &rule);
}

/* ********************************* */

int i82599_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add) {
  hw_filtering_rule rule;
  memset(&rule, 0, sizeof(rule));

  //if(ring->ft_device_type != intel_82599_family
  //&& ring->dna_dev.mem_info.device_model != intel_ixgbe_82599)
  //  return -4;

  switch(rule_to_add->rule_action) {
  case forward_packet_and_stop_rule_evaluation:
  case forward_packet_add_rule_and_stop_rule_evaluation:
    return 0; /* Nothing to do */

  case dont_forward_packet_and_stop_rule_evaluation:
    break; /* Ok - DROP */

  case reflect_packet_and_stop_rule_evaluation:
  case reflect_packet_and_continue_rule_evaluation:
  case bounce_packet_and_stop_rule_evaluation:
  case bounce_packet_and_continue_rule_evaluation:
  case execute_action_and_continue_rule_evaluation:
  case execute_action_and_stop_rule_evaluation:
  default:
    return -3; /* Not supported */
  }

  //rule_to_add->balance_id
  //rule_to_add->balance_pool
  //rule_to_add->core_fields.shost_mask.v4 (/32 only)
  //rule_to_add->core_fields.dhost_mask.v4 (/32 only)
  //rule_to_add->core_fields.sport_high    (no range)
  //rule_to_add->core_fields.dport_high    (no range)
  //rule_to_add->core_fields.vlan_id       (no VLAN)
  
  rule.rule_id = rule_to_add->rule_id;
  rule.rule_family_type = intel_82599_five_tuple_rule;
  rule.rule_family.five_tuple_rule.proto    = rule_to_add->core_fields.proto;
  rule.rule_family.five_tuple_rule.s_addr   = rule_to_add->core_fields.shost.v4;
  rule.rule_family.five_tuple_rule.d_addr   = rule_to_add->core_fields.dhost.v4;
  rule.rule_family.five_tuple_rule.s_port   = rule_to_add->core_fields.sport_low;
  rule.rule_family.five_tuple_rule.d_port   = rule_to_add->core_fields.dport_low; 
  rule.rule_family.five_tuple_rule.queue_id = -1;

  return virtual_filtering_device_add_hw_rule(ring, &rule);
}

/* ********************************* */

int i82599_remove_filtering_rule(pfring *ring, u_int16_t rule_id) {
  return virtual_filtering_device_remove_hw_rule(ring, rule_id);
}

