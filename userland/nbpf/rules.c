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

#include "nbpf.h"

/* 
 * Note: for setting the rule in pf_ring (kernel filters):
 * 0. pfring_toggle_filtering_policy(ring, 0 to drop by default)
 * 1. allocate a "filtering_rule"
 * 2. set:
 *    - "filtering_rule.core_fields"  = "filtering_rule_list_item.fields"
 *    - "filtering_rule.rule.rule_id" = "++i"
 *    - "filtering_rule.rule_action"  = "forward_packet_and_stop_rule_evaluation"
 */

//#define DEBUG
#ifdef DEBUG
#include <stdio.h>
#define DEBUG_PRINTF(fmt, ...) do {printf("[debug][%s:%d] " fmt, __FILE__, __LINE__, ## __VA_ARGS__); } while (0)
#else
#define DEBUG_PRINTF(fmt, ...)
#endif

#ifndef max
#define max(a, b) (a >= b ? a : b)
#endif

/***************************************************************************/

static nbpf_rule_list_item_t *allocate_filtering_rule_list_item() {
  nbpf_rule_list_item_t *item;
  item = (nbpf_rule_list_item_t *) calloc(1, sizeof(nbpf_rule_list_item_t));
  item->next = NULL;
  return item;
}

/* ********************************************************************** */

static nbpf_rule_block_list_item_t *allocate_filtering_rule_block_list_item() {
  nbpf_rule_block_list_item_t *block;
  block = (nbpf_rule_block_list_item_t*)calloc(1, sizeof(nbpf_rule_block_list_item_t));
  block->rule_list_head = NULL;
  block->next = NULL;
  return block;
}

/* ********************************************************************** */

static int num_filtering_rule_list_items(nbpf_rule_list_item_t *list) {
  int i = 0;
  while (list != NULL) {
    list = list->next;
    i++;
  }
  return i;
}

/* ********************************************************************** */

void nbpf_rule_list_free(nbpf_rule_list_item_t *list) {
  nbpf_rule_list_item_t *zombie;

  while (list != NULL) {
    zombie = list;
    list = list->next;
    free(zombie);
  }
}

/* ********************************************************************** */

/* Not used
static void free_filtering_rule_block_list_items(nbpf_rule_block_list_item_t *blocks) {
  nbpf_rule_block_list_item_t *zombie_block;

  zombie_block = blocks;
  while (blocks != NULL) {
    nbpf_rule_list_free(zombie_block->rule_list_head);
    zombie_block = blocks;
    blocks = blocks->next;
    free(zombie_block);
  }
}
*/

/* ********************************************************************** */

static u_int8_t __empty_mac[6] = { 0 };

static /* inline */ int is_empty_mac(u_int8_t mac[6]) {
  return memcmp(mac, __empty_mac, 6) == 0;
}

/* ********************************************************************** */

static u_int8_t __empty_ipv6[16] = { 0 };

static /* inline */ int is_empty_ipv6(u_int8_t ipv6[16]) {
  return memcmp(ipv6, __empty_ipv6, 16) == 0;
}

/* ********************************************************************** */

static void primitive_to_wildcard_filter(nbpf_rule_list_item_t *f, nbpf_node_t *n) {
  switch(n->qualifiers.protocol) {
    case NBPF_Q_LINK:
      if (n->qualifiers.address == NBPF_Q_VLAN) {
        f->fields.vlan = 1;
        if (n->vlan_id_defined)
          f->fields.vlan_id = n->vlan_id;
      } else if (n->qualifiers.address == NBPF_Q_MPLS) {
        f->fields.mpls = 1;
        if (n->mpls_label_defined)
          f->fields.mpls_label = n->mpls_label;
      } else if (n->qualifiers.address == NBPF_Q_PROTO) {
        DEBUG_PRINTF("Ethernet protocol cannot be compared with wildcard filters\n");  
      }
      if (n->protocol == 0x800)
        f->fields.ip_version = 4;
      else if (n->protocol == 0x86DD)
        f->fields.ip_version = 6;
      break;
    case NBPF_Q_DEFAULT:
    case NBPF_Q_IP:
    case NBPF_Q_IPV6:
      if (n->qualifiers.address == NBPF_Q_PROTO)
        f->fields.proto = (u_int8_t) (n->protocol); 
      break;
    case NBPF_Q_TCP:
      f->fields.proto = 6;
      break;
    case NBPF_Q_UDP:
      f->fields.proto = 17;
      break;
    case NBPF_Q_SCTP:
      f->fields.proto = 132;
      break;
    case NBPF_Q_GTP:
      f->fields.gtp = 1; /* TODO do we need to handle version? */
    default:
      DEBUG_PRINTF("Unexpected protocol qualifier (%d)\n", __LINE__);
  }

  if (n->qualifiers.address == NBPF_Q_PROTO_REL) {
    f->fields.byte_match = (nbpf_rule_core_fields_byte_match_t *) calloc(1, sizeof(nbpf_rule_core_fields_byte_match_t));
    if (f->fields.byte_match == NULL)
      DEBUG_PRINTF("Memory allocation error (%d)\n", __LINE__);
    else {
      f->fields.byte_match->protocol = n->byte_match.protocol;
      f->fields.byte_match->offset   = n->byte_match.offset;
      f->fields.byte_match->mask     = n->byte_match.mask;
      f->fields.byte_match->relop    = n->byte_match.relop;
      f->fields.byte_match->value    = n->byte_match.value;
      f->fields.byte_match->next     = NULL;
    }
  }
    
  switch(n->qualifiers.direction) {
    case NBPF_Q_SRC:
    case NBPF_Q_AND:
      memcpy(f->fields.smac, n->mac, 6);
      if(n->ip) {
        f->fields.ip_version = 4;
        f->fields.shost.v4 = n->ip;
        f->fields.shost_mask.v4 = n->mask;
      } else if (!is_empty_ipv6(n->ip6)) {
        f->fields.ip_version = 6;
        memcpy(f->fields.shost.v6.u6_addr.u6_addr8, n->ip6, 16);
        memcpy(f->fields.shost_mask.v6.u6_addr.u6_addr8, n->mask6, 16);
      }
      f->fields.sport_low = n->port_from;
      f->fields.sport_high = n->port_to;
      if (n->qualifiers.direction != NBPF_Q_AND)
        break;
    case NBPF_Q_DST:
      memcpy(f->fields.dmac, n->mac, 6);
      if(n->ip) {
        f->fields.ip_version = 4;
        f->fields.dhost.v4 = n->ip;
        f->fields.dhost_mask.v4 = n->mask;
      } else if (!is_empty_ipv6(n->ip6)) {
        f->fields.ip_version = 6;
        memcpy(f->fields.dhost.v6.u6_addr.u6_addr8, n->ip6, 16);
        memcpy(f->fields.dhost_mask.v6.u6_addr.u6_addr8, n->mask6, 16);
      }
      f->fields.dport_low = n->port_from;
      f->fields.dport_high = n->port_to;
      break;
    case NBPF_Q_DEFAULT:
    case NBPF_Q_OR:
      memcpy(f->fields.smac, n->mac, 6);
      if(n->ip) {
        f->fields.ip_version = 4;
        f->fields.shost.v4 = n->ip;
        f->fields.shost_mask.v4 = n->mask;
      } else if (!is_empty_ipv6(n->ip6)) {
        f->fields.ip_version = 6;
        memcpy(f->fields.shost.v6.u6_addr.u6_addr8, n->ip6, 16);
        memcpy(f->fields.shost_mask.v6.u6_addr.u6_addr8, n->mask6, 16);
      }
      f->fields.sport_low = n->port_from;
      f->fields.sport_high = n->port_to;
      if (!is_empty_mac(n->mac) || n->ip || !is_empty_ipv6(n->ip6) || n->port_from)
        f->bidirectional = 1;
      break;
    default:
      DEBUG_PRINTF("Unexpected direction qualifier (%d)\n", __LINE__);
  }
}

/* ********************************************************************** */

static int merge_wildcard_vlan(nbpf_rule_list_item_t *f, nbpf_rule_list_item_t *f1) {
  if (f1->fields.vlan)
    f->fields.vlan = 1;
  if (f1->fields.vlan_id) {
    if (f->fields.vlan_id) {
      DEBUG_PRINTF("Conflict merging filters on VLAN\n");
      return -1;
    }
    f->fields.vlan_id = f1->fields.vlan_id;
  }
  return 0;
}

static int merge_wildcard_mpls(nbpf_rule_list_item_t *f, nbpf_rule_list_item_t *f1) {
  if (f1->fields.mpls)
    f->fields.mpls = 1;
  if (f1->fields.mpls_label) {
    if (f->fields.mpls_label) {
      DEBUG_PRINTF("Conflict merging filters on MPLS\n");
      return -1;
    }
    f->fields.mpls_label = f1->fields.mpls_label;
  }
  return 0;
}

static int merge_wildcard_proto(nbpf_rule_list_item_t *f, nbpf_rule_list_item_t *f1) {
  if (f1->fields.proto) {
    if (f->fields.proto) {
      DEBUG_PRINTF("Conflict merging filters on protocol\n");
      return -1;
    }
    f->fields.proto = f1->fields.proto;
  }
  return 0;
}

static int merge_wildcard_proto_rel(nbpf_rule_list_item_t *f, nbpf_rule_list_item_t *f1) {
  if (f1->fields.byte_match != NULL) {
    nbpf_rule_core_fields_byte_match_t *o = f1->fields.byte_match, *list = NULL, *prev = NULL, *tmp;
    while (o != NULL) {
      tmp = (nbpf_rule_core_fields_byte_match_t *) calloc(1, sizeof(nbpf_rule_core_fields_byte_match_t));
      if (tmp == NULL) {
        DEBUG_PRINTF("Memory allocation error\n"); 
        break;
      }
      memcpy(tmp, o, sizeof(nbpf_rule_core_fields_byte_match_t));
      tmp->next = NULL;

      if (list == NULL) list = tmp;
      if (prev != NULL) prev->next = tmp;
      prev = tmp;
      
      o = o->next;
    }

    if (f->fields.byte_match == NULL) 
      f->fields.byte_match = list;
    else {
      nbpf_rule_core_fields_byte_match_t *last = f->fields.byte_match;
      while (last->next != NULL) last = last->next;
      last->next = list;
    }
  }

  return 0;
}

static int merge_wildcard_smac(nbpf_rule_list_item_t *f, nbpf_rule_list_item_t *f1, u_int8_t swap) {
  if (!is_empty_mac(f1->fields.smac)) {
    if (!is_empty_mac(!swap ? f->fields.smac : f->fields.dmac)) {
      DEBUG_PRINTF("Conflict merging filters on dst mac\n");
      return -1;
    }
    memcpy(!swap ? f->fields.smac : f->fields.dmac, f1->fields.smac, 6);
  }
  return 0;
}

static int merge_wildcard_dmac(nbpf_rule_list_item_t *f, nbpf_rule_list_item_t *f1, u_int8_t swap) {
  if (!is_empty_mac(f1->fields.dmac)) {
    if (!is_empty_mac(!swap ? f->fields.dmac : f->fields.smac)) {
      DEBUG_PRINTF("Conflict merging filters on src mac\n");
      return -1;
    }
    memcpy(!swap ? f->fields.dmac : f->fields.smac, f1->fields.dmac, 6);
  }
  return 0;
}

static int merge_wildcard_shost(nbpf_rule_list_item_t *f, nbpf_rule_list_item_t *f1, u_int8_t swap) {
  if (f1->fields.shost.v4) {
    if ((!swap ? f->fields.shost.v4 : f->fields.dhost.v4)) {
      DEBUG_PRINTF("Conflict merging filters on src ip\n");
      return -1;
    }
    if (!swap) {
      f->fields.shost.v4 = f1->fields.shost.v4;
      f->fields.shost_mask.v4 = f1->fields.shost_mask.v4;
    } else {
      f->fields.dhost.v4 = f1->fields.shost.v4;
      f->fields.dhost_mask.v4 = f1->fields.shost_mask.v4;
    }
  }
  return 0;
}

static int merge_wildcard_dhost(nbpf_rule_list_item_t *f, nbpf_rule_list_item_t *f1, u_int8_t swap) {
  if (f1->fields.dhost.v4) {
    if ((!swap ? f->fields.dhost.v4 : f->fields.shost.v4)) {
      DEBUG_PRINTF("Conflict merging filters on dst ip\n");
      return -1;
    }
    if (!swap) {
      f->fields.dhost.v4 = f1->fields.dhost.v4;
      f->fields.dhost_mask.v4 = f1->fields.dhost_mask.v4;
    } else {
      f->fields.shost.v4 = f1->fields.dhost.v4;
      f->fields.shost_mask.v4 = f1->fields.dhost_mask.v4;
    }
  }
  return 0;
}

static int merge_wildcard_shost6(nbpf_rule_list_item_t *f, nbpf_rule_list_item_t *f1, u_int8_t swap) {
  if (!is_empty_ipv6(f1->fields.shost.v6.u6_addr.u6_addr8)) {
    if (!is_empty_ipv6(!swap ? f->fields.shost.v6.u6_addr.u6_addr8 : f->fields.dhost.v6.u6_addr.u6_addr8)) {
      DEBUG_PRINTF("Conflict merging filters on src ipv6\n");
      return -1;
    }
    if (!swap) {
      memcpy(f->fields.shost.v6.u6_addr.u6_addr8, f1->fields.shost.v6.u6_addr.u6_addr8, 16);
      memcpy(f->fields.shost_mask.v6.u6_addr.u6_addr8, f1->fields.shost_mask.v6.u6_addr.u6_addr8, 16);
    } else {
      memcpy(f->fields.dhost.v6.u6_addr.u6_addr8, f1->fields.shost.v6.u6_addr.u6_addr8, 16);
      memcpy(f->fields.dhost_mask.v6.u6_addr.u6_addr8, f1->fields.shost_mask.v6.u6_addr.u6_addr8, 16);
    }
  }
  return 0;
}

static int merge_wildcard_dhost6(nbpf_rule_list_item_t *f, nbpf_rule_list_item_t *f1, u_int8_t swap) {
  if (!is_empty_ipv6(f1->fields.dhost.v6.u6_addr.u6_addr8)) {
    if (!is_empty_ipv6(!swap ? f->fields.dhost.v6.u6_addr.u6_addr8 : f->fields.shost.v6.u6_addr.u6_addr8)) {
      DEBUG_PRINTF("Conflict merging filters on dst ipv6\n");
      return -1;
    }
    if (!swap) {
      memcpy(f->fields.dhost.v6.u6_addr.u6_addr8, f1->fields.dhost.v6.u6_addr.u6_addr8, 16);
      memcpy(f->fields.dhost_mask.v6.u6_addr.u6_addr8, f1->fields.dhost_mask.v6.u6_addr.u6_addr8, 16);
    } else {
      memcpy(f->fields.shost.v6.u6_addr.u6_addr8, f1->fields.dhost.v6.u6_addr.u6_addr8, 16);
      memcpy(f->fields.shost_mask.v6.u6_addr.u6_addr8, f1->fields.dhost_mask.v6.u6_addr.u6_addr8, 16);
    }
  }
  return 0;
}

static int merge_wildcard_sport(nbpf_rule_list_item_t *f, nbpf_rule_list_item_t *f1, u_int8_t swap) {
  if (f1->fields.sport_low) {
    if ((!swap ? f->fields.sport_low : f->fields.dport_low)) {
      DEBUG_PRINTF("Conflict merging filters on src port\n");
      return -1;
    }
    if (!swap) {
      f->fields.sport_low = f1->fields.sport_low;
      f->fields.sport_high = f1->fields.sport_high;
    } else {
      f->fields.dport_low = f1->fields.sport_low;
      f->fields.dport_high = f1->fields.sport_high;
    }
  }
  return 0;
}

static int merge_wildcard_dport(nbpf_rule_list_item_t *f, nbpf_rule_list_item_t *f1, u_int8_t swap) {
  if (f1->fields.dport_low) {
    if ((!swap ? f->fields.dport_low : f->fields.sport_low)) {
      DEBUG_PRINTF("Conflict merging filters on dst port\n");
      return -1;
    }
    if (!swap) {
      f->fields.dport_low = f1->fields.dport_low;
      f->fields.dport_high = f1->fields.dport_high;
    } else {
      f->fields.sport_low = f1->fields.dport_low;
      f->fields.sport_high = f1->fields.dport_high;
    }
  }
  return 0;
}

static nbpf_rule_list_item_t *merge_wildcard_filters_single(nbpf_rule_list_item_t *f1, nbpf_rule_list_item_t *f2, u_int8_t swap1, u_int8_t swap2) {
  nbpf_rule_list_item_t *f;
  int rc;

  /* checking rules constraints */

  if (f1->fields.ip_version && f2->fields.ip_version && 
      f1->fields.ip_version != f2->fields.ip_version)
    return NULL; /* error: merging v4 AND v6 */
 
  /* merging */

  f = allocate_filtering_rule_list_item();
  if (f == NULL)
    return NULL;

  f->bidirectional = 0;

  rc = merge_wildcard_vlan(f, f1); if (rc != 0) goto exit;
  rc = merge_wildcard_vlan(f, f2); if (rc != 0) goto exit;

  rc = merge_wildcard_mpls(f, f1); if (rc != 0) goto exit;
  rc = merge_wildcard_mpls(f, f2); if (rc != 0) goto exit;

  rc = merge_wildcard_proto(f, f1); if (rc != 0) goto exit;
  rc = merge_wildcard_proto(f, f2); if (rc != 0) goto exit;

  rc = merge_wildcard_proto_rel(f, f1); if (rc != 0) goto exit;
  rc = merge_wildcard_proto_rel(f, f2); if (rc != 0) goto exit;

  rc = merge_wildcard_smac(f, f1, swap1); if (rc != 0) goto exit;
  rc = merge_wildcard_smac(f, f2, swap2); if (rc != 0) goto exit;

  rc = merge_wildcard_dmac(f, f1, swap1); if (rc != 0) goto exit;
  rc = merge_wildcard_dmac(f, f2, swap2); if (rc != 0) goto exit;

  if (f->fields.ip_version && f1->fields.ip_version &&
    f->fields.ip_version != f1->fields.ip_version) {
    DEBUG_PRINTF("Conflict merging filters with different IP version\n");
    rc = -1;
    goto exit;
  }

  if (f1->fields.ip_version == 4) {
    f->fields.ip_version = 4;
    rc = merge_wildcard_shost(f, f1, swap1); if (rc != 0) goto exit;
    rc = merge_wildcard_dhost(f, f1, swap1); if (rc != 0) goto exit;
  } else if (f1->fields.ip_version == 6) {
    f->fields.ip_version = 6;
    rc = merge_wildcard_shost6(f, f1, swap1); if (rc != 0) goto exit;
    rc = merge_wildcard_dhost6(f, f1, swap1); if (rc != 0) goto exit;
  }

  if (f->fields.ip_version && f2->fields.ip_version &&
    f->fields.ip_version != f2->fields.ip_version) {
    DEBUG_PRINTF("Conflict merging filters with different IP version\n");
    rc = -1;
    goto exit;
  }

  if (f2->fields.ip_version == 4) {
    f->fields.ip_version = 4;
    rc = merge_wildcard_shost(f, f2, swap2); if (rc != 0) goto exit;
    rc = merge_wildcard_dhost(f, f2, swap2); if (rc != 0) goto exit;
  } else if (f2->fields.ip_version == 6) {
    f->fields.ip_version = 6;
    rc = merge_wildcard_shost6(f, f2, swap2); if (rc != 0) goto exit;
    rc = merge_wildcard_dhost6(f, f2, swap2); if (rc != 0) goto exit;
  }

  merge_wildcard_sport(f, f1, swap1); if (rc != 0) goto exit;
  merge_wildcard_sport(f, f2, swap2); if (rc != 0) goto exit;

  merge_wildcard_dport(f, f1, swap1); if (rc != 0) goto exit;
  merge_wildcard_dport(f, f2, swap2); if (rc != 0) goto exit;

  if (f1->fields.gtp && f2->fields.gtp && f1->fields.gtp != f2->fields.gtp) {
    DEBUG_PRINTF("Conflict merging filters with different GTP version\n");
    rc = -1;
    goto exit;
  }
  if (f1->fields.gtp) f->fields.gtp = f1->fields.gtp;
  if (f2->fields.gtp) f->fields.gtp = f2->fields.gtp;

exit:
  if (rc != 0) {
    free(f);
    f = NULL;
  }

  return f; 
}

static nbpf_rule_list_item_t *merge_wildcard_filters(nbpf_rule_list_item_t *f1, nbpf_rule_list_item_t *f2) {
  nbpf_rule_list_item_t *f, *last;

  last = f = merge_wildcard_filters_single(f1, f2, 0, 0);
  if (last == NULL) return NULL;

  if (f1->bidirectional) {
    last->next = merge_wildcard_filters_single(f1, f2, 1, 0);
    last = last->next;
    if (last == NULL) { nbpf_rule_list_free(f); return NULL; }
  }

  if (f2->bidirectional) {
    last->next = merge_wildcard_filters_single(f1, f2, 0, 1);
    last = last->next;
    if (last == NULL) { nbpf_rule_list_free(f); return NULL; }

    if (f1->bidirectional) {
      last->next = merge_wildcard_filters_single(f1, f2, 1, 1);
      last = last->next;
      if (last == NULL) { nbpf_rule_list_free(f); return NULL; }
    }
  }

  return f;
}

/* ********************************************************************** */
 
static nbpf_rule_list_item_t *merge_filtering_rule_lists(nbpf_rule_list_item_t *headl, nbpf_rule_list_item_t *headr) {
  nbpf_rule_list_item_t *head = NULL, *tail = NULL, *tmp, *headr_tmp, *headl_tmp;

  if (headl == NULL)
    return headr;
  
  if (headr == NULL)
    return headl;

  headl_tmp = headl;
  while (headl_tmp != NULL) {
    headr_tmp = headr;
    while (headr_tmp != NULL) {

      tmp = merge_wildcard_filters(headl_tmp, headr_tmp);

      if (tmp == NULL) {
        nbpf_rule_list_free(head);
        head = NULL;
        goto exit;
      }

      if (head == NULL) /* first item */
        head = tmp;
      else
        tail->next = tmp;

      while (tmp->next != NULL)
        tmp = tmp->next;
      tail = tmp;

      headr_tmp = headr_tmp->next;
    }

    headl_tmp = headl_tmp->next; 
  }

exit:
  nbpf_rule_list_free(headl);
  nbpf_rule_list_free(headr);

  return head;
}

/* ********************************************************************** */

static nbpf_rule_list_item_t *chain_filtering_rule_lists(nbpf_rule_list_item_t *headl, nbpf_rule_list_item_t *headr) {
  nbpf_rule_list_item_t *head = NULL, *tail;

  if (headl == NULL)
    return headr;
  
  if (headr == NULL)
    return headl;

  tail = headl;
  while (tail->next != NULL)
    tail = tail->next;
  tail->next = headr;
  head = headl;

  return head;
}

/***************************************************************************/

nbpf_rule_list_item_t *generate_pfring_wildcard_filters(nbpf_node_t *n) {
  nbpf_rule_list_item_t *head = NULL, *headl, *headr;

  if (n == NULL)
    return NULL;

  switch(n->type) {
    case N_EMPTY:
      head = allocate_filtering_rule_list_item();      
      if (head == NULL)
        return NULL;
      break;

    case N_PRIMITIVE:
      head = allocate_filtering_rule_list_item();      
      if (head == NULL)
        return NULL;

      primitive_to_wildcard_filter(head, n);

      break;
    case N_AND:
      headl = generate_pfring_wildcard_filters(n->l);
      headr = generate_pfring_wildcard_filters(n->r); 

      if (headl == NULL || headr == NULL) {
        if (headl != NULL) nbpf_rule_list_free(headl);
        if (headr != NULL) nbpf_rule_list_free(headr);
        return NULL;
      }

      head = merge_filtering_rule_lists(headl, headr);

      break;
    case N_OR:
      headl = generate_pfring_wildcard_filters(n->l);
      headr = generate_pfring_wildcard_filters(n->r);

      if (headl == NULL || headr == NULL) {
        if (headl != NULL) nbpf_rule_list_free(headl);
        if (headr != NULL) nbpf_rule_list_free(headr);
        return NULL;
      }

      head = chain_filtering_rule_lists(headl, headr);

      break;
    default:
      DEBUG_PRINTF("Unexpected node type\n");
      return NULL;
  }
  
  return head;
}

/***************************************************************************/

nbpf_rule_block_list_item_t *generate_wildcard_filters_blocks(nbpf_node_t *n) {
  nbpf_rule_list_item_t *head = NULL;
  nbpf_rule_block_list_item_t *block, *blockl, *blockr, *tail_block;

  if (n == NULL)
    return NULL;

  switch(n->type) {
    case N_EMPTY:
      block = allocate_filtering_rule_block_list_item();
      block->rule_list_head = head = allocate_filtering_rule_list_item();
      if (head == NULL) /* memory allocation failure */
        return NULL;
      break;

    case N_PRIMITIVE:
      block = allocate_filtering_rule_block_list_item();
      block->rule_list_head = head = allocate_filtering_rule_list_item();
      if (head == NULL) /* memory allocation failure */
        return NULL;

      primitive_to_wildcard_filter(head, n);

      break;
    case N_AND:
      blockl = generate_wildcard_filters_blocks(n->l);
      blockr = generate_wildcard_filters_blocks(n->r); 
      
      if (blockl == NULL && blockr == NULL) {
        return NULL; /* error */
      } else if (blockl == NULL) {
        block = blockr;
      } else if (blockr == NULL) {
        block = blockl;
      } else {
        if (blockl->next == NULL && blockr->next == NULL /* single blocks */ &&
	    (num_filtering_rule_list_items(blockl->rule_list_head) == 1 || 
             num_filtering_rule_list_items(blockr->rule_list_head) == 1 )) {

	  blockl->rule_list_head = merge_filtering_rule_lists(
	    blockl->rule_list_head,
	    blockr->rule_list_head);

          if (blockl->rule_list_head == NULL) {
            DEBUG_PRINTF("Error merging AND block into rule list\n");
            free(blockl);
            return NULL; /* error */
          }

          free(blockr);
	} else {
	  /* chaining AND blocks */
          tail_block = blockl;
	  while (tail_block->next != NULL)
	    tail_block = tail_block->next;
	  tail_block->next = blockr;
	}
	
	block = blockl;
      }

      break;
    case N_OR:
      blockl = generate_wildcard_filters_blocks(n->l);
      blockr = generate_wildcard_filters_blocks(n->r);
  
      /* Note that according to the constraints it expects single blocks from each subtree */

      if (blockl == NULL && blockr == NULL) {
        return NULL; /* error */
      } else if (blockl == NULL) {
        block = blockr;
      } else if (blockr == NULL) {
        block = blockl;
      } else {

        blockl->rule_list_head = chain_filtering_rule_lists(
	  blockl->rule_list_head,
	  blockr->rule_list_head);

        block = blockl;

	free(blockr);
      }
      
      break;
    default:
      DEBUG_PRINTF("Unexpected node type\n");
      return NULL;
  }
  
  return block;
}

/***************************************************************************/

nbpf_rule_block_list_item_t *move_wildcard_filters_blocks_to_contiguous_memory(nbpf_rule_block_list_item_t *blocks) {
  nbpf_rule_block_list_item_t *bitem, *new_bitem, *prev_bitem, *zombie_bitem;
  nbpf_rule_list_item_t *fitem, *new_fitem, *prev_fitem, *zombie_fitem;
  int bnum = 0, fnum = 0;
  u_char *contiguous_memory;
  u_int32_t mem_offset = 0;

  /* counting number of blocks and rules */
  bitem = blocks;
  while (bitem != NULL) {
    bnum++;
    fitem = bitem->rule_list_head;
    while (fitem != NULL) {
      fnum++;
      fitem = fitem->next;
    }
    bitem = bitem->next;
  }

  contiguous_memory = (u_char *) malloc((bnum * sizeof(*bitem)) + (fnum * sizeof(*fitem)));
  
  if (contiguous_memory == NULL)
    return NULL;

  bitem = blocks;
  prev_bitem = NULL;
  while (bitem != NULL) {
    /* moving block */
    new_bitem = (nbpf_rule_block_list_item_t *) &contiguous_memory[mem_offset];
    mem_offset += sizeof(*new_bitem);
    
    memcpy(new_bitem, bitem, sizeof(*new_bitem));
    new_bitem->next = NULL;
    
    if (prev_bitem != NULL) /* not first */
      prev_bitem->next = new_bitem; 
    prev_bitem = new_bitem; 

    prev_fitem = NULL;
    fitem = bitem->rule_list_head;
    while (fitem != NULL) {

      /* moving rule */
      new_fitem = (nbpf_rule_list_item_t *) &contiguous_memory[mem_offset];
      mem_offset += sizeof(*new_fitem);

      memcpy(new_fitem, fitem, sizeof(*new_fitem));
      new_fitem->next = NULL;

      if (prev_fitem != NULL) /* not first */
        prev_fitem->next = new_fitem;
      else /* first item of the list */
        new_bitem->rule_list_head = new_fitem;
      prev_fitem = new_fitem;

      zombie_fitem = fitem;
      fitem = fitem->next;
      free(zombie_fitem);
    }

    zombie_bitem = bitem;
    bitem = bitem->next;
    free(zombie_bitem);
  }

  return (nbpf_rule_block_list_item_t *) contiguous_memory;
}

/***************************************************************************/

int check_filter_constraints(nbpf_node_t *n, int max_nesting_level) {
  if (n == NULL) {
    DEBUG_PRINTF("Empty operator subtree\n");
    return 0; /* empty and/or operators not allowed */
  }

  if (n->not_rule) {
    DEBUG_PRINTF("NOT operator not supported on capture filters\n");
    return 0;
  }

  switch(n->type) {
    case N_EMPTY:
      n->level = 0;
      break;
    case N_PRIMITIVE:
      n->level = 0;
      break;
    case N_AND:
    case N_OR:
      if (!check_filter_constraints(n->l, max_nesting_level)) return 0;
      if (!check_filter_constraints(n->r, max_nesting_level)) return 0;

      n->level = max(n->l->level, n->r->level);

      if (n->type == N_AND && (n->l->type == N_OR || n->r->type == N_OR)) {
        n->level++;
	if (n->level > max_nesting_level) {
          DEBUG_PRINTF("Too many nested levels (%d) or different operators mixed: not supported with capture filters\n", n->level);
	  return 0;
	}
      }

      break;
    default:
      DEBUG_PRINTF("Unexpected node type\n");
      return 0;
  }
  
  return 1;
}

/* ********************************************************************** */

int nbpf_check_rules_constraints(nbpf_tree_t *tree, int max_nesting_level) {
  return check_filter_constraints(tree->root, max_nesting_level);
}

/* ********************************************************************** */

nbpf_rule_list_item_t *nbpf_generate_rules(nbpf_tree_t *tree) {
  /* Note: nesting level = 1 is what is supported by hw filters generation */
  if (!nbpf_check_rules_constraints(tree, 1))
    return NULL;

  return generate_pfring_wildcard_filters(tree->root);
}

/* ********************************************************************** */

nbpf_rule_block_list_item_t *nbpf_generate_optimized_rules(nbpf_tree_t *tree) {
  nbpf_rule_block_list_item_t *blocks;

  if (!nbpf_check_rules_constraints(tree, 1))
    return NULL;

  if ((blocks = generate_wildcard_filters_blocks(tree->root)) == NULL)
    return NULL;
  
  blocks = move_wildcard_filters_blocks_to_contiguous_memory(blocks);

  return blocks;
}

/* ********************************************************************** */

void nbpf_rule_block_list_free(nbpf_rule_block_list_item_t* b) {
  free(b); /* Note: it uses contiguous memory for all blocks */
}

/* ********************************************************************** */

