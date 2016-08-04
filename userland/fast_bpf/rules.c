/*
 *  Copyright (C) 2016 ntop.org
 *
 *      http://www.ntop.org/
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
  item = (fast_bpf_rule_list_item_t*)calloc(1, sizeof(fast_bpf_rule_list_item_t));
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
      break;
    case Q_DEFAULT:
    case Q_IP:
    case Q_IPV6:
      if (n->qualifiers.address == Q_PROTO)
        f->fields.proto =(u_int8_t)(n->protocol);
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
        f->fields.shost.v4 = n->ip;
        f->fields.shost_mask.v4 = n->mask;
      } else {
	if (!is_empty_ipv6(n->ip6)) {
          memcpy(f->fields.shost.v6.s6_addr, n->ip6, 16);
          memcpy(f->fields.shost_mask.v6.s6_addr, n->mask6, 16);
	}
      }
      f->fields.sport_low = n->port_from;
      f->fields.sport_high = n->port_to;
      if (n->qualifiers.direction != Q_AND)
        break;
    case Q_DST:
      memcpy(f->fields.dmac, n->mac, 6);
      if(n->ip) {
        f->fields.dhost.v4 = n->ip;
        f->fields.dhost_mask.v4 = n->mask;
      } else {
	if (!is_empty_ipv6(n->ip6)) {
          memcpy(f->fields.dhost.v6.s6_addr, n->ip6, 16);
          memcpy(f->fields.dhost_mask.v6.s6_addr, n->mask6, 16);
	}
      }
      f->fields.dport_low = n->port_from;
      f->fields.dport_high = n->port_to;
      break;
    case Q_DEFAULT:
    case Q_OR:
      memcpy(f->fields.smac, n->mac, 6);
      if(n->ip) {
        f->fields.shost.v4 = n->ip;
        f->fields.shost_mask.v4 = n->mask;

      } else {
	if (!is_empty_ipv6(n->ip6)) {
          memcpy(f->fields.shost.v6.s6_addr, n->ip6, 16);
          memcpy(f->fields.shost_mask.v6.s6_addr, n->mask6, 16);
	}
      }
      f->fields.sport_low = n->port_from;
      f->fields.sport_high = n->port_to;
      f->bidirectional = 1;
      break;
    default:
      DEBUG_PRINTF("Unexpected direction qualifier (%d)\n", __LINE__);
  }
}

/* ********************************************************************** */

static void merge_wildcard_vlan(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1) {
  if (f1->fields.vlan_id) {
    if (!f->fields.vlan_id)
      f->fields.vlan_id = f1->fields.vlan_id;
    else DEBUG_PRINTF("Conflict merging filters on vlan\n");
  }
}

static void merge_wildcard_proto(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1) {
  if (f1->fields.proto) {
    if (!f->fields.proto)
      f->fields.proto = f1->fields.proto;
    else DEBUG_PRINTF("Conflict merging filters on protocol\n");
  }
}

static void merge_wildcard_smac(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1) {
  if (!is_empty_mac(f1->fields.smac)) {
    if (is_empty_mac(f->fields.smac)) {
      memcpy(f->fields.smac, f1->fields.smac, 6);
    } else {
      if (f1->bidirectional) {
        if (is_empty_mac(f->fields.dmac)) {
	  memcpy(f->fields.dmac, f1->fields.smac, 6);
	} else DEBUG_PRINTF("Conflict merging filters on dst mac\n");
      } else DEBUG_PRINTF("Conflict merging filters on src mac\n");
    }
  }
}

static void merge_wildcard_dmac(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1) {
  if (!is_empty_mac(f1->fields.dmac)) {
    if (is_empty_mac(f->fields.dmac)) {
      memcpy(f->fields.dmac, f1->fields.dmac, 6);
    } else {
      if (f1->bidirectional) {
        if (is_empty_mac(f->fields.smac)) {
	  memcpy(f->fields.smac, f1->fields.dmac, 6);
	} else DEBUG_PRINTF("Conflict merging filters on src mac\n");
      } else DEBUG_PRINTF("Conflict merging filters on dst mac\n");
    }
  }
}

#if 0
static void merge_wildcard_shost(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1) {
  if (f1->fields.shost.v4) {
    if (!f->fields.shost.v4) {
      f->fields.shost.v4 = f1->fields.shost.v4;
      f->fields.shost_mask.v4 = f1->fields.shost_mask.v4;
    } else {
      if (f1->bidirectional) {
        if (!f->fields.dhost.v4) {
	  f->fields.dhost.v4 = f1->fields.shost.v4;
	  f->fields.dhost_mask.v4 = f1->fields.shost_mask.v4;
	} else DEBUG_PRINTF("Conflict merging filters on dst (src) ip %08X -> %08X\n", f1->fields.shost.v4, f->fields.dhost.v4);
      } else DEBUG_PRINTF("Conflict merging filters on src ip\n");
    }
  }
}

static void merge_wildcard_dhost(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1) {
  if (f1->fields.dhost.v4) {
    if (!f->fields.dhost.v4) {
      f->fields.dhost.v4 = f1->fields.dhost.v4;
      f->fields.dhost_mask.v4 = f1->fields.dhost_mask.v4;
    } else {
      if (f1->bidirectional) {
        if (!f->fields.shost.v4) {
	  f->fields.shost.v4 = f1->fields.dhost.v4;
	  f->fields.shost_mask.v4 = f1->fields.dhost_mask.v4;
	} else DEBUG_PRINTF("Conflict merging filters on src (dst) ip %08X -> %08X\n", f1->fields.dhost.v4, f->fields.shost.v4);
      } else DEBUG_PRINTF("Conflict merging filters on dst ip\n");
    }
  }
}
#endif

static void merge_wildcard_shost6(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1) {
  if (!is_empty_ipv6(f1->fields.shost.v6.s6_addr)) {
    if (is_empty_ipv6(f->fields.shost.v6.s6_addr)) {
      memcpy(f->fields.shost.v6.s6_addr, f1->fields.shost.v6.s6_addr, 16);
      memcpy(f->fields.shost_mask.v6.s6_addr, f1->fields.shost_mask.v6.s6_addr, 16);
    } else {
      if (f1->bidirectional) {
        if (is_empty_ipv6(f->fields.dhost.v6.s6_addr)) {
	  memcpy(f->fields.dhost.v6.s6_addr, f1->fields.shost.v6.s6_addr, 16);
	  memcpy(f->fields.dhost_mask.v6.s6_addr, f1->fields.shost_mask.v6.s6_addr, 16);
	} else DEBUG_PRINTF("Conflict merging filters on dst ipv6\n");
      } else DEBUG_PRINTF("Conflict merging filters on src ipv6\n");
    }
  }
}

static void merge_wildcard_dhost6(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1) {
  if (!is_empty_ipv6(f1->fields.dhost.v6.s6_addr)) {
    if (is_empty_ipv6(f->fields.dhost.v6.s6_addr)) {
      memcpy(f->fields.dhost.v6.s6_addr, f1->fields.dhost.v6.s6_addr, 16);
      memcpy(f->fields.dhost_mask.v6.s6_addr, f1->fields.dhost_mask.v6.s6_addr, 16);
    } else {
      if (f1->bidirectional) {
        if (is_empty_ipv6(f->fields.shost.v6.s6_addr)) {
	  memcpy(f->fields.shost.v6.s6_addr, f1->fields.dhost.v6.s6_addr, 16);
	  memcpy(f->fields.shost_mask.v6.s6_addr, f1->fields.dhost_mask.v6.s6_addr, 16);
	} else DEBUG_PRINTF("Conflict merging filters on src ipv6\n");
      } else DEBUG_PRINTF("Conflict merging filters on dst ipv6\n");
    }
  }
}

static void merge_wildcard_sport(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1) {
  if (f1->fields.sport_low) {
    if (!f->fields.sport_low) {
      f->fields.sport_low = f1->fields.sport_low;
      f->fields.sport_high = f1->fields.sport_high;
    } else {
      if (f1->bidirectional) {
        if (!f->fields.dport_low) {
	  f->fields.dport_low = f1->fields.sport_low;
	  f->fields.dport_high = f1->fields.sport_high;
	} else DEBUG_PRINTF("Conflict merging filters on dst port\n");
      } else DEBUG_PRINTF("Conflict merging filters on src port\n");
    }
  }
}

static void merge_wildcard_dport(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1) {
  if (f1->fields.dport_low) {
    if (!f->fields.dport_low) {
      f->fields.dport_low = f1->fields.dport_low;
      f->fields.dport_high = f1->fields.dport_high;
    } else {
      if (f1->bidirectional) {
        if (!f->fields.sport_low) {
	  f->fields.sport_low = f1->fields.dport_low;
	  f->fields.sport_high = f1->fields.dport_high;
	} else DEBUG_PRINTF("Conflict merging filters on src port\n");
      } else DEBUG_PRINTF("Conflict merging filters on dst port\n");
    }
  }
}

static void merge_wildcard_filters(fast_bpf_rule_list_item_t *f, fast_bpf_rule_list_item_t *f1,
				   fast_bpf_rule_list_item_t *f2) {
  if (f1->bidirectional != f2->bidirectional) {
    DEBUG_PRINTF("Mergind bidirectional rule with unidirectional rule\n");
    f->bidirectional = 1; /* default bidirectional */
  } else {
    f->bidirectional = f1->bidirectional;
  }

  merge_wildcard_vlan(f, f1);
  merge_wildcard_vlan(f, f2);

  merge_wildcard_proto(f, f1);
  merge_wildcard_proto(f, f2);

  merge_wildcard_smac(f, f1); 
  merge_wildcard_smac(f, f2); 

  merge_wildcard_dmac(f, f1); 
  merge_wildcard_dmac(f, f2); 

  merge_wildcard_shost6(f, f1); 
  merge_wildcard_shost6(f, f2); 

  merge_wildcard_dhost6(f, f1); 
  merge_wildcard_dhost6(f, f2);

  /* IPv6 merge is also merging IPv4 as they share the union
  merge_wildcard_shost(f, f1); 
  merge_wildcard_shost(f, f2); 

  merge_wildcard_dhost(f, f1); 
  merge_wildcard_dhost(f, f2); 
  */

  merge_wildcard_sport(f, f1); 
  merge_wildcard_sport(f, f2); 

  merge_wildcard_dport(f, f1); 
  merge_wildcard_dport(f, f2); 
}

/* ********************************************************************** */
 
static fast_bpf_rule_list_item_t *merge_filtering_rule_lists(fast_bpf_rule_list_item_t *headl, fast_bpf_rule_list_item_t *headr) {
  fast_bpf_rule_list_item_t *head = NULL, *tail = NULL, *tmp, *headr_tmp;

  if (headl == NULL)
    return headr;
  
  if (headr == NULL)
    return headl;

  while (headl != NULL) {
    headr_tmp = headr;
    while (headr_tmp != NULL) {
      tmp = allocate_filtering_rule_list_item();
      if (head == NULL) /* first item */
        head = tmp;
      else
        tail->next = tmp;
      tail = tmp;

      merge_wildcard_filters(tail, headl, headr_tmp);

      headr_tmp = headr_tmp->next;
    }

    tmp = headl; 
    headl = headl->next; 
    free(tmp);
  }

  while (headr != NULL) { 
    tmp = headr; 
    headr = headr->next; 
    free(tmp); 
  }

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
      
      primitive_to_wildcard_filter(head, n);

      break;
    case N_AND:
      headl = generate_pfring_wildcard_filters(n->l);
      headr = generate_pfring_wildcard_filters(n->r); 

      head = merge_filtering_rule_lists(headl, headr);

      break;
    case N_OR:
      headl = generate_pfring_wildcard_filters(n->l);
      headr = generate_pfring_wildcard_filters(n->r);
  
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
      
      primitive_to_wildcard_filter(head, n);

      break;
    case N_AND:
      blockl = generate_optimized_wildcard_filters(n->l);
      blockr = generate_optimized_wildcard_filters(n->r); 
      
      if (blockl == NULL) {
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

      if (blockl == NULL) {
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

  contiguous_memory = (u_char*)malloc((bnum * sizeof(*bitem)) + (fnum * sizeof(*fitem)));
  
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

#if 0
static /* inline */ int get_primitive_family(fast_bpf_node_t *n) {
  switch(n->qualifiers.address) {
    case Q_DEFAULT:
    case Q_HOST: 
    case Q_NET:
      switch(n->qualifiers.protocol) {
        case Q_LINK:
          return Q_LINK;
        case Q_DEFAULT:
        case Q_IP:
        case Q_IPV6:
          return Q_IP;
	default:
	  DEBUG_PRINTF("Unexpected protocol qualifier (%d)\n", __LINE__);
      }
      break;
    case Q_PORT:
    case Q_PORTRANGE:
      switch(n->qualifiers.protocol) {
        case Q_TCP:
        case Q_UDP:
        case Q_SCTP:
          return Q_PORT;
	default:
	  DEBUG_PRINTF("Unexpected protocol qualifier (%d)\n", __LINE__);
      }
      break;
    case Q_PROTO:
      return Q_PROTO;
      break;
    case Q_L7_PROTO:
      return Q_L7_PROTO;
      break;
    default:
      DEBUG_PRINTF("Unexpected address qualifier (%d)\n", __LINE__);
  }
  return Q_UNDEF;
}
#endif

/* ********************************************************************** */

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
#if 0
      n->family = get_primitive_family(n);
#endif
      break;
    case N_AND:
    case N_OR:
      if (!check_filter_constraints(n->l, max_nesting_level)) return 0;
      if (!check_filter_constraints(n->r, max_nesting_level)) return 0;

      n->level = max(n->l->level, n->r->level);

#if 0 /* mixed families -> new level */
      if (n->l->family != n->r->family) {
	n->family = Q_UNDEF;
        n->level++;
	if (n->level > 1) {
          DEBUG_PRINTF("Too many nested levels or different types mixed\n");
	  return 0;
	}
      } else {
        n->family = n->l->family; 
      }
      
      if (((n->level == n->l->level) && (n->l->type != N_PRIMITIVE) && (n->l->type != n->type)) ||
          ((n->level == n->r->level) && (n->r->type != N_PRIMITIVE) && (n->r->type != n->type))) {
	DEBUG_PRINTF("Mixed operators on the same nesting level\n");
	return 0;
      }
#else /* mixed operators -> new level */
      if (((n->l->type != N_PRIMITIVE) && (n->l->type != n->type)) ||
          ((n->r->type != N_PRIMITIVE) && (n->r->type != n->type))) {
        n->level++;
	if (n->level > max_nesting_level) {
          DEBUG_PRINTF("Too many nested levels (%d) or different operators mixed: not supported with capture filters\n", n->level);
	  return 0;
	}
      }
#endif

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
  if (!fast_bpf_check_rules_constraints(tree, 1 /* default */))
    return NULL;

  return generate_pfring_wildcard_filters(tree->root);
}

/* ********************************************************************** */

fast_bpf_rule_block_list_item_t *fast_bpf_generate_optimized_rules(fast_bpf_tree_t *tree) {
  fast_bpf_rule_block_list_item_t *blocks;

  if (!fast_bpf_check_rules_constraints(tree, 1 /* default */))
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

