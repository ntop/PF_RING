/*
 *  Copyright (C) 2016 ntop.org
 *
 *      http://www.ntop.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 */

#include "fast_bpf.h"

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
#ifdef DEBUG_PRINTF
#define DEBUG_PRINTF(fmt, ...) do {printf("[debug][%s:%d] " fmt, __file__, __line__, ## __va_args__); } while (0)
#else
#define DEBUG_PRINTF(fmt, ...)
#endif

#ifndef max
#define max(a, b) (a >= b ? a : b)
#endif

/***************************************************************************/

static fast_bpf_rule_list_item_t *allocate_filtering_rule_list_item() {
  fast_bpf_rule_list_item_t *item;
  item = (fast_bpf_rule_list_item_t *) calloc(1, sizeof(fast_bpf_rule_list_item_t));
  item->next = NULL;
  return item;
}

/* ********************************************************************** */

static fast_bpf_rule_block_list_item_t *allocate_filtering_rule_block_list_item() {
  fast_bpf_rule_block_list_item_t *block;
  block = (fast_bpf_rule_block_list_item_t*)calloc(1, sizeof(fast_bpf_rule_block_list_item_t));
  block->rule_list_head = NULL;
  block->next = NULL;
  return block;
}

/* ********************************************************************** */

static int num_filtering_rule_list_items(fast_bpf_rule_list_item_t *list) {
  int i = 0;
  while (list != NULL) {
    list = list->next;
    i++;
  }
  return i;
}

/* ********************************************************************** */

void fast_bpf_rule_list_free(fast_bpf_rule_list_item_t *list) {
  fast_bpf_rule_list_item_t *zombie;

  while (list != NULL) {
    zombie = list;
    list = list->next;
    free(zombie);
  }
}

/* ********************************************************************** */

/* Not used
static void free_filtering_rule_block_list_items(fast_bpf_rule_block_list_item_t *blocks) {
  fast_bpf_rule_block_list_item_t *zombie_block;

  zombie_block = blocks;
  while (blocks != NULL) {
    fast_bpf_rule_list_free(zombie_block->rule_list_head);
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

static void primitive_to_wildcard_filter(fast_bpf_rule_list_item_t *f, fast_bpf_node_t *n) {
  switch(n->qualifiers.protocol) {
    case Q_LINK:
      if (n->qualifiers.address == Q_VLAN) {
        if (n->vlan_id_defined)
          f->fields.vlan_id = n->vlan_id;
        else
          DEBUG_PRINTF("VLAN id must be specified with wildcard filters (presence check not available)\n");
      } else if (n->qualifiers.address == Q_PROTO) {
        DEBUG_PRINTF("Ethernet protocol cannot be compared with wildcard filters\n");  
      }
      if (n->protocol == 0x800)
        f->fields.ip_version = 4;
      else if (n->protocol == 0x86DD)
        f->fields.ip_version = 6;
      break;
    case Q_DEFAULT:
    case Q_IP:
    case Q_IPV6:
      if (n->qualifiers.address == Q_PROTO)
        f->fields.proto = (u_int8_t) (n->protocol); 
      break;
    case Q_TCP:
      f->fields.proto = 6;
      break;
    case Q_UDP:
      f->fields.proto = 17;
      break;
    case Q_SCTP:
      f->fields.proto = 132;
      break;
    default:
      DEBUG_PRINTF("Unexpected protocol qualifier (%d)\n", __LINE__);
  }

  switch(n->qualifiers.direction) {
    case Q_SRC:
    case Q_AND:
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
      if (n->qualifiers.direction != Q_AND)
        break;
    case Q_DST:
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
    case Q_DEFAULT:
    case Q_OR:
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

static int merge_wildcard_vlan(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1) {
  if (f1->fields.vlan_id) {
    if (f->fields.vlan_id) {
      DEBUG_PRINTF("Conflict merging filters on vlan\n");
      return -1;
    }
    f->fields.vlan_id = f1->fields.vlan_id;
  }
  return 0;
}

static int merge_wildcard_proto(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1) {
  if (f1->fields.proto) {
    if (f->fields.proto) {
      DEBUG_PRINTF("Conflict merging filters on protocol\n");
      return -1;
    }
    f->fields.proto = f1->fields.proto;
  }
  return 0;
}

static int merge_wildcard_smac(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1, u_int8_t swap) {
  if (!is_empty_mac(f1->fields.smac)) {
    if (!is_empty_mac(!swap ? f->fields.smac : f->fields.dmac)) {
      DEBUG_PRINTF("Conflict merging filters on dst mac\n");
      return -1;
    }
    memcpy(!swap ? f->fields.smac : f->fields.dmac, f1->fields.smac, 6);
  }
  return 0;
}

static int merge_wildcard_dmac(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1, u_int8_t swap) {
  if (!is_empty_mac(f1->fields.dmac)) {
    if (!is_empty_mac(!swap ? f->fields.dmac : f->fields.smac)) {
      DEBUG_PRINTF("Conflict merging filters on src mac\n");
      return -1;
    }
    memcpy(!swap ? f->fields.dmac : f->fields.smac, f1->fields.dmac, 6);
  }
  return 0;
}

static int merge_wildcard_shost(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1, u_int8_t swap) {
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

static int merge_wildcard_dhost(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1, u_int8_t swap) {
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

static int merge_wildcard_shost6(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1, u_int8_t swap) {
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

static int merge_wildcard_dhost6(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1, u_int8_t swap) {
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

static int merge_wildcard_sport(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1, u_int8_t swap) {
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

static int merge_wildcard_dport(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1, u_int8_t swap) {
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

static fast_bpf_rule_list_item_t *merge_wildcard_filters_single(fast_bpf_rule_list_item_t *f1, fast_bpf_rule_list_item_t *f2, u_int8_t swap1, u_int8_t swap2) {
  fast_bpf_rule_list_item_t *f;
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

  rc = merge_wildcard_proto(f, f1); if (rc != 0) goto exit;
  rc = merge_wildcard_proto(f, f2); if (rc != 0) goto exit;

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

exit:
  if (rc != 0) {
    free(f);
    f = NULL;
  }

  return f; 
}

static fast_bpf_rule_list_item_t *merge_wildcard_filters(fast_bpf_rule_list_item_t *f1, fast_bpf_rule_list_item_t *f2) {
  fast_bpf_rule_list_item_t *f, *last;

  last = f = merge_wildcard_filters_single(f1, f2, 0, 0);
  if (last == NULL) return NULL;

  if (f1->bidirectional) {
    last->next = merge_wildcard_filters_single(f1, f2, 1, 0);
    last = last->next;
    if (last == NULL) { fast_bpf_rule_list_free(f); return NULL; }
  }

  if (f2->bidirectional) {
    last->next = merge_wildcard_filters_single(f1, f2, 0, 1);
    last = last->next;
    if (last == NULL) { fast_bpf_rule_list_free(f); return NULL; }

    if (f1->bidirectional) {
      last->next = merge_wildcard_filters_single(f1, f2, 1, 1);
      last = last->next;
      if (last == NULL) { fast_bpf_rule_list_free(f); return NULL; }
    }
  }

  return f;
}

/* ********************************************************************** */
 
static fast_bpf_rule_list_item_t *merge_filtering_rule_lists(fast_bpf_rule_list_item_t *headl, fast_bpf_rule_list_item_t *headr) {
  fast_bpf_rule_list_item_t *head = NULL, *tail = NULL, *tmp, *headr_tmp, *headl_tmp;

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
        fast_bpf_rule_list_free(head);
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
  fast_bpf_rule_list_free(headl);
  fast_bpf_rule_list_free(headr);

  return head;
}

/* ********************************************************************** */

static fast_bpf_rule_list_item_t *chain_filtering_rule_lists(fast_bpf_rule_list_item_t *headl, fast_bpf_rule_list_item_t *headr) {
  fast_bpf_rule_list_item_t *head = NULL, *tail;

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

fast_bpf_rule_list_item_t *generate_pfring_wildcard_filters(fast_bpf_node_t *n) {
  fast_bpf_rule_list_item_t *head = NULL, *headl, *headr;

  if (n == NULL)
    return NULL;

  switch(n->type) {
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
        if (headl != NULL) fast_bpf_rule_list_free(headl);
        if (headr != NULL) fast_bpf_rule_list_free(headr);
        return NULL;
      }

      head = merge_filtering_rule_lists(headl, headr);

      break;
    case N_OR:
      headl = generate_pfring_wildcard_filters(n->l);
      headr = generate_pfring_wildcard_filters(n->r);

      if (headl == NULL || headr == NULL) {
        if (headl != NULL) fast_bpf_rule_list_free(headl);
        if (headr != NULL) fast_bpf_rule_list_free(headr);
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

fast_bpf_rule_block_list_item_t *generate_optimized_wildcard_filters(fast_bpf_node_t *n) {
  fast_bpf_rule_list_item_t *head = NULL;
  fast_bpf_rule_block_list_item_t *block, *blockl, *blockr, *tail_block;

  if (n == NULL)
    return NULL;

  switch(n->type) {
    case N_PRIMITIVE:
      block = allocate_filtering_rule_block_list_item();
      block->rule_list_head = head = allocate_filtering_rule_list_item();
      if (head == NULL) /* memory allocation failure */
        return NULL;

      primitive_to_wildcard_filter(head, n);

      break;
    case N_AND:
      blockl = generate_optimized_wildcard_filters(n->l);
      blockr = generate_optimized_wildcard_filters(n->r); 
      
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
      blockl = generate_optimized_wildcard_filters(n->l);
      blockr = generate_optimized_wildcard_filters(n->r);
  
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

fast_bpf_rule_block_list_item_t *move_optimized_wildcard_filters_to_contiguous_memory(fast_bpf_rule_block_list_item_t *blocks) {
  fast_bpf_rule_block_list_item_t *bitem, *new_bitem, *prev_bitem, *zombie_bitem;
  fast_bpf_rule_list_item_t *fitem, *new_fitem, *prev_fitem, *zombie_fitem;
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
    new_bitem = (fast_bpf_rule_block_list_item_t *) &contiguous_memory[mem_offset];
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
      new_fitem = (fast_bpf_rule_list_item_t *) &contiguous_memory[mem_offset];
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

  return (fast_bpf_rule_block_list_item_t *) contiguous_memory;
}

/***************************************************************************/

int check_filter_constraints(fast_bpf_node_t *n, int max_nesting_level) {
  if (n == NULL) {
    DEBUG_PRINTF("Empty operator subtree\n");
    return 0; /* empty and/or operators not allowed */
  }

  if (n->not_rule) {
    DEBUG_PRINTF("NOT operator not supported on capture filters\n");
    return 0;
  }

  switch(n->type) {
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

int fast_bpf_check_rules_constraints(fast_bpf_tree_t *tree, int max_nesting_level) {
  return check_filter_constraints(tree->root, max_nesting_level);
}

/* ********************************************************************** */

fast_bpf_rule_list_item_t *fast_bpf_generate_rules(fast_bpf_tree_t *tree) {
  if (!fast_bpf_check_rules_constraints(tree, 0 /* default */))
    return NULL;

  return generate_pfring_wildcard_filters(tree->root);
}

/* ********************************************************************** */

fast_bpf_rule_block_list_item_t *fast_bpf_generate_optimized_rules(fast_bpf_tree_t *tree) {
  fast_bpf_rule_block_list_item_t *blocks;

  if (!fast_bpf_check_rules_constraints(tree, 0 /* default */))
    return NULL;

  if ((blocks = generate_optimized_wildcard_filters(tree->root)) == NULL)
    return NULL;
  
  blocks = move_optimized_wildcard_filters_to_contiguous_memory(blocks);

  return blocks;
}

/* ********************************************************************** */

void fast_bpf_rule_block_list_free(fast_bpf_rule_block_list_item_t* b) {
  free(b); /* Note: it uses contiguous memory for all blocks */
}

/* ********************************************************************** */

