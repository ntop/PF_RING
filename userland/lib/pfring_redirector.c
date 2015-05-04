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

#include <syslog.h>
#include <sys/stat.h>

/* ********************************* */

int redirector_set_traffic_policy(pfring *ring, u_int8_t rules_default_accept_policy) {
  ring->socket_default_accept_policy = rules_default_accept_policy;
  return(rdi_set_cfg(ring->rdi.device_id, rules_default_accept_policy ? 2 /* INLINE_2 */ : 5 /* MON_2 */));
}

/* ********************************* */

void init_redirector(pfring *ring) {
  struct stat buf;

  /* Check if it is likely that a Silicom NIC is present */
  if(stat("/proc/net/rdi", &buf) == 0) {
    int i, done = 0;

    for(i=0; ((!done) && (i < rdi_get_dev_num())); i++) {
      char dev_name[32];
      FILE *fd;

      snprintf(dev_name, sizeof(dev_name), "/proc/net/rdi/dev%d", i);
      fd = fopen(dev_name, "r");

      if(fd != NULL) {
	char buf[64];

	while(fgets(buf, sizeof(buf), fd) != NULL) {
	  if(strstr(buf, ring->device_name) != NULL) {
	    /* d:0.0 dna0 */
	    int port;

	    if(sscanf(&buf[1], ":0.%d", &port) == 1) {
	      ring->rdi.port_id = (int8_t)port;
	      ring->rdi.device_id = i;
	      done = 1;
	    }
	    break;
	  }
	}

	fclose(fd);
      }
    }

    if((ring->rdi.port_id != -1) && (ring->rdi.device_id != -1)) {
      int rc;
      char *cmd = "/bin/rdictl set_cfg 2 > /dev/null";

      /* Temporary patch */
      (void)system(cmd);

      if((rc = rdi_init(ring->rdi.device_id)) < 0) {
	printf("WARNING: unable to initialize redirector [device=%d@port=%d][rc=%d]\n",
	       ring->rdi.device_id, ring->rdi.port_id, rc);
	ring->rdi.port_id = ring->rdi.device_id = -1;
      }
    }

    if(ring->rdi.device_id != -1) {
      if(rdi_clear_rules(ring->rdi.device_id) < 0)
	printf("WARNING: unable to clear rules for device %d\n",
	       ring->rdi.device_id);

      if(redirector_set_traffic_policy(ring, 1 /* accept (default) */) < 0)
	printf("WARNING: unable to set default traffic policy on device %d\n",
	       ring->rdi.device_id);

      syslog(LOG_INFO, "Redirector port: device=%d@port=%d\n",
	     ring->rdi.device_id, ring->rdi.port_id);
    }
  } else
    ring->rdi.port_id = ring->rdi.device_id = -1;
}

/* ********************************* */

static u_int32_t cird2mask(u_int cidr) {
  return((0xffffffff >> (32 - cidr)) << (32 - cidr));
}

/* ********************************* */

int redirector_add_hw_rule(pfring *ring, hw_filtering_rule *rule,
			   filtering_rule* rule_to_add,
			   hash_filtering_rule* hash_rule_to_add) {
  int ret;
  rdi_mem_t rdi_rule;

  if (rule->rule_family_type != silicom_redirector_rule) {
    syslog(LOG_ERR, "Invalid rule family type [rule_family_type=%d]",
	   rule->rule_family_type);
    return -1;
  }

  memset(&rdi_rule, 0, sizeof(rdi_rule));

  rdi_rule.rule_id       = rule->rule_id;
  rdi_rule.port          = rule->rule_family.redirector_rule.rule_port;
  rdi_rule.src_port      = rule->rule_family.redirector_rule.src_port_low;
  rdi_rule.src_port_max  = rule->rule_family.redirector_rule.src_port_high;

  rdi_rule.dst_port      = rule->rule_family.redirector_rule.dst_port_low;
  rdi_rule.dst_port_max  = rule->rule_family.redirector_rule.dst_port_high;
  rdi_rule.src_ip        = rule->rule_family.redirector_rule.src_addr.v4; /* IPv4 only */
  rdi_rule.dst_ip        = rule->rule_family.redirector_rule.dst_addr.v4; /* IPv4 only */
  rdi_rule.src_ip_mask   = cird2mask(rule->rule_family.redirector_rule.src_mask);
  rdi_rule.dst_ip_mask   = cird2mask(rule->rule_family.redirector_rule.dst_mask);
  rdi_rule.ip_protocol   = rule->rule_family.redirector_rule.l3_proto;
  rdi_rule.vlan          = rule->rule_family.redirector_rule.vlan_id_low;
  rdi_rule.vlan_max      = rule->rule_family.redirector_rule.vlan_id_high;
  //? rdi_rule.vlan_mask     = rule->?;

  switch (rule->rule_family.redirector_rule.rule_type) {
    /* *********   DROP RULE    ********* */
    case drop_rule:
      rdi_rule.rule_act = RDI_SET_DROP;
      ret = rdi_add_rule_drop(ring->rdi.device_id, &rdi_rule);
    break;

    /* ********* REDIRECT RULE ********* */
    case redirect_rule:
      rdi_rule.rule_act = RDI_SET_DIR;
      rdi_rule.redir_port = rule->rule_family.redirector_rule.rule_target_port;

      ret = rdi_add_rule_dir(ring->rdi.device_id, &rdi_rule);
    break;

    /* *********  MIRROR RULE  ********* */
    case mirror_rule:
      rdi_rule.rule_act = RDI_SET_MIR;
      rdi_rule.mirror_port = rule->rule_family.redirector_rule.rule_target_port;

      ret = rdi_add_rule_mir(ring->rdi.device_id, &rdi_rule);
    break;

    default:
      ret = -1;
      syslog(LOG_ERR, "Unrecognized rule type [rule_type=%d]", 
	     rule->rule_family.redirector_rule.rule_type);
    break;
  }

  if(ret < 0)
    return ret;
  else {
    /* ret now contains the ID of the rule just added */
    if(rule_to_add)      rule_to_add->rule_id = ret;
    if(hash_rule_to_add) hash_rule_to_add->rule_id = ret;
    ret = rdi_install_rules(ring->rdi.device_id);
  }

  return(ret);
}

/* ********************************* */

int redirector_remove_hw_rule(pfring *ring, u_int16_t rule_id) {
  return(rdi_entry_remove(ring->rdi.device_id, rule_id));
}

/* ********************************* */

int redirector_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add) {
  hw_filtering_rule hw_rule;
  silicom_redirector_hw_rule *silicom;

  /* Convert generic filtering rule into redirector filtering rule */
  memset(&hw_rule, 0, sizeof(hw_rule));
  hw_rule.rule_family_type = silicom_redirector_rule;
  hw_rule.rule_id = rule_to_add->rule_id;
  silicom = &hw_rule.rule_family.redirector_rule;

  switch(rule_to_add->rule_action) {
  case forward_packet_and_stop_rule_evaluation:
  case forward_packet_add_rule_and_stop_rule_evaluation:
  case forward_packet_del_rule_and_stop_rule_evaluation:
    if(ring->socket_default_accept_policy) return(0); /* Nothing to do */
    /*
      2 is the constant to add for connecting source with destination port
      (Broadcom -> Intel basically)
    */
    silicom->rule_type = mirror_rule, silicom->rule_target_port = ring->rdi.port_id + 2;
    break;

  case dont_forward_packet_and_stop_rule_evaluation:
    if(!ring->socket_default_accept_policy) return(0); /* Nothing to do */
    silicom->rule_type = drop_rule;
    break;

  case reflect_packet_and_stop_rule_evaluation:
  case reflect_packet_and_continue_rule_evaluation:
    // silicom->rule_type = ;
    return(-2); /* Not YET supported */
    break;

  case bounce_packet_and_stop_rule_evaluation:
  case bounce_packet_and_continue_rule_evaluation:
  case execute_action_and_continue_rule_evaluation:
  case execute_action_and_stop_rule_evaluation:
    return(-3); /* Not supported */
  }

  silicom->rule_port = ring->rdi.port_id;
  silicom->vlan_id_low = silicom->vlan_id_high = rule_to_add->core_fields.vlan_id;
  silicom->l3_proto = rule_to_add->core_fields.proto;
  memcpy(&silicom->src_addr, &rule_to_add->core_fields.shost, sizeof(ip_addr));
  memcpy(&silicom->dst_addr, &rule_to_add->core_fields.dhost, sizeof(ip_addr));
  silicom->src_mask = rule_to_add->core_fields.shost_mask.v4;
  silicom->dst_mask = rule_to_add->core_fields.dhost_mask.v4;
  silicom->src_port_low = rule_to_add->core_fields.sport_low, silicom->src_port_high = rule_to_add->core_fields.sport_high;
  silicom->dst_port_low = rule_to_add->core_fields.dport_low, silicom->dst_port_high = rule_to_add->core_fields.dport_high;

  return(redirector_add_hw_rule(ring, &hw_rule, rule_to_add, NULL));
}

/* ********************************* */

int redirector_add_hash_filtering_rule(pfring *ring, hash_filtering_rule* rule_to_add) {
  hw_filtering_rule hw_rule;
  silicom_redirector_hw_rule *silicom;
  int rc;

  /* Convert generic filtering rule into redirector filtering rule */
  memset(&hw_rule, 0, sizeof(hw_rule));
  hw_rule.rule_family_type = silicom_redirector_rule;
  hw_rule.rule_id = rule_to_add->rule_id;
  silicom = &hw_rule.rule_family.redirector_rule;

  switch(rule_to_add->rule_action) {
  case forward_packet_and_stop_rule_evaluation:
  case forward_packet_add_rule_and_stop_rule_evaluation:
  case forward_packet_del_rule_and_stop_rule_evaluation:
    if(ring->socket_default_accept_policy) return(0); /* Nothing to do */
    /*
      2 is the constant to add for connecting source with destination port
      (Broadcom -> Intel basically)
    */
    silicom->rule_type = mirror_rule, silicom->rule_target_port = ring->rdi.port_id + 2;
    break;

  case dont_forward_packet_and_stop_rule_evaluation:
    if(!ring->socket_default_accept_policy) return(0); /* Nothing to do */
    silicom->rule_type = drop_rule;
    break;

  case reflect_packet_and_stop_rule_evaluation:
  case reflect_packet_and_continue_rule_evaluation:
    // silicom->rule_type = ;
    return(-2); /* Not YET supported */
    break;

  case bounce_packet_and_stop_rule_evaluation:
  case bounce_packet_and_continue_rule_evaluation:
  case execute_action_and_continue_rule_evaluation:
  case execute_action_and_stop_rule_evaluation:
    return(-3); /* Not supported */
  }

  silicom->rule_port = ring->rdi.port_id;
  silicom->vlan_id_low = silicom->vlan_id_high = rule_to_add->vlan_id;
  silicom->l3_proto = rule_to_add->proto;
  memcpy(&silicom->src_addr, &rule_to_add->host_peer_a, sizeof(ip_addr));
  memcpy(&silicom->dst_addr, &rule_to_add->host_peer_b, sizeof(ip_addr));
  silicom->src_mask = 0xFFFFFFFF, silicom->dst_mask = 0xFFFFFFFF;
  silicom->src_port_low = rule_to_add->port_peer_a, silicom->src_port_high = rule_to_add->port_peer_a;
  silicom->dst_port_low = rule_to_add->port_peer_b, silicom->dst_port_high = rule_to_add->port_peer_b;

  rc = redirector_add_hw_rule(ring, &hw_rule, NULL, rule_to_add);

  if(rc < 0) return(rc);

  /* Add reverse direction */
  memcpy(&silicom->src_addr, &rule_to_add->host_peer_b, sizeof(ip_addr));
  memcpy(&silicom->dst_addr, &rule_to_add->host_peer_a, sizeof(ip_addr));
  silicom->src_port_low = rule_to_add->port_peer_b, silicom->src_port_high = rule_to_add->port_peer_b;
  silicom->dst_port_low = rule_to_add->port_peer_a, silicom->dst_port_high = rule_to_add->port_peer_a;

  return(redirector_add_hw_rule(ring, &hw_rule, NULL, rule_to_add));
}

/* ********************************* */

int redirector_remove_filtering_rule(pfring *ring, u_int16_t rule_id) {
  return(redirector_remove_hw_rule(ring, rule_id));
}

/* ********************************* */
