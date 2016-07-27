/*
 *  Copyright (C) 2016 ntop.org
 *
 *      http://www.ntop.org/
 *
 */

#include "fast_bpf.h"

//#define DEBUG
#ifdef DEBUG_PRINTF
#define DEBUG_PRINTF(fmt, ...) do {printf("[debug][%s:%d] " fmt, __file__, __line__, ## __va_args__); } while (0)
#else
#define DEBUG_PRINTF(fmt, ...)
#endif

static u_int8_t ignore_mac_addr = 0;
static u_int8_t use_ipv6_l32_match = 0;
static u_int8_t ignore_l3_proto = 0;
static u_int8_t ignore_l7_proto = 0;
static u_int8_t ignore_inner_header = 0;

/***************************************************************************/

static /* inline */ int packet_match_mac(fast_bpf_node_t *n, fast_bpf_pkt_info_t *h) {
  if (ignore_mac_addr)
    return 1;

  switch(n->qualifiers.direction) {
    case Q_SRC:
      if (memcmp(h->smac, n->mac, 6) == 0) return 1;
      break;
    case Q_DST:
      if (memcmp(h->dmac, n->mac, 6) == 0) return 1;
      break;
    case Q_DEFAULT:
    case Q_OR:
      if (memcmp(h->smac, n->mac, 6) == 0 ||
          memcmp(h->dmac, n->mac, 6) == 0) return 1;
      break;
    case Q_AND:
      if (memcmp(h->smac, n->mac, 6) == 0 &&
          memcmp(h->dmac, n->mac, 6) == 0) return 1;
    default:
      DEBUG_PRINTF("Unexpected direction qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_ip(fast_bpf_node_t *n, fast_bpf_pkt_info_t *h) {
  fast_bpf_pkt_info_tuple_t *t = &h->tuple;

  if (n->qualifiers.header == Q_INNER) {
    if (ignore_inner_header) return 1;
    t = &h->tunneled_tuple;
  }

  switch(n->qualifiers.direction) {
    case Q_SRC:
      if((t->ip_src.v4 & n->mask) == n->ip) return 1;
      break;
    case Q_DST:
      if((t->ip_dst.v4 & n->mask) == n->ip) return 1;
      break;
    case Q_DEFAULT:
    case Q_OR:
      if((t->ip_src.v4 & n->mask) == n->ip ||
         (t->ip_dst.v4 & n->mask) == n->ip) return 1;
      break;
    case Q_AND:
      if((t->ip_src.v4 & n->mask) == n->ip &&
         (t->ip_dst.v4 & n->mask) == n->ip) return 1;
      break;
    default:
      DEBUG_PRINTF("Unexpected direction qualifier (%d)\n", __LINE__);
  }
  //DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int match_ip6(u_int32_t *ip6, u_int32_t *rulemask6, u_int32_t *ruleip6) {
  int i;
  if (use_ipv6_l32_match) {
    return ((ip6[3] & rulemask6[3]) == ruleip6[3]);
  } else {
    for (i = 0; i < 4; i++) {
      if ((ip6[i] & rulemask6[i]) != ruleip6[i]) {
        DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
        return 0;
      }
    }
    return 1;
  }
}

/* ********************************************************************** */

static /* inline */ int packet_match_ip6(fast_bpf_node_t *n, fast_bpf_pkt_info_t *h) {
  fast_bpf_pkt_info_tuple_t *t = &h->tuple;

  if (n->qualifiers.header == Q_INNER) {
    if (ignore_inner_header) return 1;
    t = &h->tunneled_tuple;
  }

  switch(n->qualifiers.direction) {
    case Q_SRC:
      if (match_ip6(t->ip_src.v6.s6_addr32, (u_int32_t *) n->mask6, (u_int32_t *) n->ip6)) return 1;
      break;
    case Q_DST:
      if (match_ip6(t->ip_dst.v6.s6_addr32, (u_int32_t *) n->mask6, (u_int32_t *) n->ip6)) return 1;
      break;
    case Q_DEFAULT:
    case Q_OR:
      if (match_ip6(t->ip_src.v6.s6_addr32, (u_int32_t *) n->mask6, (u_int32_t *) n->ip6) ||
          match_ip6(t->ip_dst.v6.s6_addr32, (u_int32_t *) n->mask6, (u_int32_t *) n->ip6)) return 1;
      break;
    case Q_AND:
      if (match_ip6(t->ip_src.v6.s6_addr32, (u_int32_t *) n->mask6, (u_int32_t *) n->ip6) &&
          match_ip6(t->ip_dst.v6.s6_addr32, (u_int32_t *) n->mask6, (u_int32_t *) n->ip6)) return 1;
      break;
    default:
      DEBUG_PRINTF("Unexpected direction qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_port(fast_bpf_node_t *n, fast_bpf_pkt_info_t *h) {
  fast_bpf_pkt_info_tuple_t *t = &h->tuple;
  u_int16_t h_l4_src_port, h_l4_dst_port; 
  u_int16_t h_port_from, h_port_to;

  if (n->qualifiers.header == Q_INNER) {
    if (ignore_inner_header) return 1;
    t = &h->tunneled_tuple;
  }

  h_l4_src_port = ntohs(t->l4_src_port), h_l4_dst_port = ntohs(t->l4_dst_port); 
  h_port_from = ntohs(n->port_from), h_port_to = ntohs(n->port_to);
  switch(n->qualifiers.direction) {
    case Q_SRC:
      if (h_l4_src_port >= h_port_from &&
          h_l4_src_port <= h_port_to) return 1;
      break;
    case Q_DST:
      if (h_l4_dst_port >= h_port_from &&
          h_l4_dst_port <= h_port_to) return 1;
      break;
    case Q_DEFAULT:
    case Q_OR:
      if ((h_l4_src_port >= h_port_from &&
           h_l4_src_port <= h_port_to) ||
	  (h_l4_dst_port >= h_port_from &&
	   h_l4_dst_port <= h_port_to)) return 1;
      break;
    case Q_AND:
      if (h_l4_src_port >= h_port_from &&
          h_l4_src_port <= h_port_to &&
	  h_l4_dst_port >= h_port_from &&
	  h_l4_dst_port <= h_port_to) return 1;
      break;
    default:
      DEBUG_PRINTF("Unexpected direction qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_host(fast_bpf_node_t *n, fast_bpf_pkt_info_t *h) {
  fast_bpf_pkt_info_tuple_t *t = &h->tuple;

  if (n->qualifiers.header == Q_INNER) {
    if (ignore_inner_header) return 1;
    t = &h->tunneled_tuple;
  }
 
  switch(n->qualifiers.protocol) {
    case Q_LINK:
      /* supported qualifiers: Q_HOST/Q_PROTO */
      return packet_match_mac(n, h);
      break;
    case Q_DEFAULT:
    case Q_IP:
      /* supported qualifiers: Q_HOST/Q_NET/Q_PROTO */
      if (t->eth_type == 0x0800)
        return packet_match_ip(n, h);
      break;
    case Q_IPV6:
      /* supported qualifiers: Q_HOST/Q_NET/Q_PROTO */
      if (t->eth_type == 0x86DD)
        return packet_match_ip6(n, h);
      break;
    default:
      DEBUG_PRINTF("Unexpected address qualifier: %d\n", n->qualifiers.protocol); 
  }  
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);

  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_l4(fast_bpf_node_t *n, fast_bpf_pkt_info_t *h) {
  fast_bpf_pkt_info_tuple_t *t = &h->tuple;

  if (n->qualifiers.header == Q_INNER) {
    if (ignore_inner_header) return 1;
    t = &h->tunneled_tuple;
  }
 
  switch(n->qualifiers.protocol) {
    case Q_DEFAULT:
      return packet_match_port(n, h);
      break;
    case Q_TCP:
      if (ignore_l3_proto || t->l3_proto == 6)
        return packet_match_port(n, h);
      break;
    case Q_UDP:
      if (ignore_l3_proto || t->l3_proto == 17)
        return packet_match_port(n, h);
      break;
    case Q_SCTP:
      if (ignore_l3_proto || t->l3_proto == 132)
        return packet_match_port(n, h);
      break;
    default:
      DEBUG_PRINTF("Unexpected protocol qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_proto(fast_bpf_node_t *n, fast_bpf_pkt_info_t *h) {
  fast_bpf_pkt_info_tuple_t *t = &h->tuple;

  if (n->qualifiers.header == Q_INNER) {
    if (ignore_inner_header) return 1;
    t = &h->tunneled_tuple;
  }

  switch(n->qualifiers.protocol) {
    case Q_LINK:
      if (t->eth_type == n->protocol)
        return 1;
      break;
    case Q_DEFAULT:
    case Q_IP:
    case Q_IPV6:
      if (ignore_l3_proto || t->l3_proto == n->protocol)
        return 1;
      break;
    default:
      DEBUG_PRINTF("Unexpected protocol qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_l7_proto(fast_bpf_node_t *n, fast_bpf_pkt_info_t *h) {
  if (ignore_l7_proto || h->master_l7_proto == n->l7protocol || h->l7_proto == n->l7protocol)
    return 1;

  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_vlan(fast_bpf_node_t *n, fast_bpf_pkt_info_t *h) {
  switch(n->qualifiers.protocol) {
    case Q_LINK:
      if (h->vlan_id == n->vlan_id || h->vlan_id_qinq == n->vlan_id)
        return 1;
      break;
    default:
      DEBUG_PRINTF("Unexpected vlan qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_primitive(fast_bpf_node_t *n, fast_bpf_pkt_info_t *h) {
  switch(n->qualifiers.address) {
    case Q_DEFAULT:
    case Q_HOST: 
    case Q_NET:
      return packet_match_host(n, h);
    case Q_PORT:
    case Q_PORTRANGE:
      return packet_match_l4(n, h);
    case Q_PROTO:
      return packet_match_proto(n, h);
    case Q_L7PROTO:
      return packet_match_l7_proto(n, h);
    case Q_VLAN:
      return packet_match_vlan(n, h);
    default:
      DEBUG_PRINTF("Unexpected address qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static int packet_match_filter(fast_bpf_node_t *n, fast_bpf_pkt_info_t *h) {
  if (n == NULL)
    return 1;

  switch(n->type) {
    case N_PRIMITIVE: return !!(n->not_rule- packet_match_primitive(n, h));
    case N_AND:       return !!(n->not_rule- (packet_match_filter(n->l, h) && packet_match_filter(n->r, h)));
    case N_OR:        return !!(n->not_rule- (packet_match_filter(n->l, h) || packet_match_filter(n->r, h)));
    default:          DEBUG_PRINTF("Unexpected node type\n");
  }

  return 0;
}

/* ********************************************************************** */

void fast_bpf_toggle_mac_match(fast_bpf_tree_t *tree, u_int8_t enable) {
  ignore_mac_addr = !enable;
}

void fast_bpf_toggle_ipv6_l32_match(fast_bpf_tree_t *tree, u_int8_t enable) {
  use_ipv6_l32_match = enable;
}

void fast_bpf_toggle_l3_proto_match(fast_bpf_tree_t *tree, u_int8_t enable) {
  ignore_l3_proto = !enable;
}

void fast_bpf_toggle_l7_proto_match(fast_bpf_tree_t *tree, u_int8_t enable) {
  ignore_l7_proto = !enable;
}

void fast_bpf_toggle_inner_header_match(fast_bpf_tree_t *tree, u_int8_t enable) {
  ignore_inner_header = !enable;
}

/***************************************************************************/ 

int fast_bpf_match(fast_bpf_tree_t *tree, fast_bpf_pkt_info_t *h) {
  return packet_match_filter(tree->root, h);
}

/* ********************************************************************** */

