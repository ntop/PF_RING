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

#ifndef WIN32
#include <arpa/inet.h>
#endif
#include <stdio.h>

#include "nbpf.h"

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

static /* inline */ int packet_match_mac(nbpf_node_t *n, nbpf_pkt_info_t *h) {
  if(ignore_mac_addr)
    return 1;

  switch(n->qualifiers.direction) {
    case NBPF_Q_SRC:
      if(memcmp(h->smac, n->mac, 6) == 0) return 1;
      break;
    case NBPF_Q_DST:
      if(memcmp(h->dmac, n->mac, 6) == 0) return 1;
      break;
    case NBPF_Q_DEFAULT:
    case NBPF_Q_OR:
      if(memcmp(h->smac, n->mac, 6) == 0 ||
          memcmp(h->dmac, n->mac, 6) == 0) return 1;
      break;
    case NBPF_Q_AND:
      if(memcmp(h->smac, n->mac, 6) == 0 &&
          memcmp(h->dmac, n->mac, 6) == 0) return 1;
    default:
      DEBUG_PRINTF("Unexpected direction qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_ip(nbpf_node_t *n, nbpf_pkt_info_t *h) {
  nbpf_pkt_info_tuple_t *t = &h->tuple;

  if(n->qualifiers.header == NBPF_Q_INNER) {
    if(ignore_inner_header) return 1;
    t = &h->tunneled_tuple;
  }

  switch(n->qualifiers.direction) {
    case NBPF_Q_SRC:
      if((t->ip_src.v4 & n->mask) == n->ip) return 1;
      break;
    case NBPF_Q_DST:
      if((t->ip_dst.v4 & n->mask) == n->ip) return 1;
      break;
    case NBPF_Q_DEFAULT:
    case NBPF_Q_OR:
      if((t->ip_src.v4 & n->mask) == n->ip ||
         (t->ip_dst.v4 & n->mask) == n->ip) return 1;
      break;
    case NBPF_Q_AND:
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
  if(use_ipv6_l32_match) {
    return ((ip6[3] & rulemask6[3]) == ruleip6[3]);
  } else {
    for (i = 0; i < 4; i++) {
      if((ip6[i] & rulemask6[i]) != ruleip6[i]) {
        DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
        return 0;
      }
    }
    return 1;
  }
}

/* ********************************************************************** */

static /* inline */ int packet_match_ip6(nbpf_node_t *n, nbpf_pkt_info_t *h) {
  nbpf_pkt_info_tuple_t *t = &h->tuple;

  if(n->qualifiers.header == NBPF_Q_INNER) {
    if(ignore_inner_header) return 1;
    t = &h->tunneled_tuple;
  }

  switch(n->qualifiers.direction) {
    case NBPF_Q_SRC:
      if(match_ip6(t->ip_src.v6.u6_addr.u6_addr32, (u_int32_t *) n->mask6, (u_int32_t *) n->ip6)) return 1;
      break;
    case NBPF_Q_DST:
      if(match_ip6(t->ip_dst.v6.u6_addr.u6_addr32, (u_int32_t *) n->mask6, (u_int32_t *) n->ip6)) return 1;
      break;
    case NBPF_Q_DEFAULT:
    case NBPF_Q_OR:
      if(match_ip6(t->ip_src.v6.u6_addr.u6_addr32, (u_int32_t *) n->mask6, (u_int32_t *) n->ip6) ||
          match_ip6(t->ip_dst.v6.u6_addr.u6_addr32, (u_int32_t *) n->mask6, (u_int32_t *) n->ip6)) return 1;
      break;
    case NBPF_Q_AND:
      if(match_ip6(t->ip_src.v6.u6_addr.u6_addr32, (u_int32_t *) n->mask6, (u_int32_t *) n->ip6) &&
          match_ip6(t->ip_dst.v6.u6_addr.u6_addr32, (u_int32_t *) n->mask6, (u_int32_t *) n->ip6)) return 1;
      break;
    default:
      DEBUG_PRINTF("Unexpected direction qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_port(nbpf_node_t *n, nbpf_pkt_info_t *h) {
  nbpf_pkt_info_tuple_t *t = &h->tuple;
  u_int16_t h_l4_src_port, h_l4_dst_port; 
  u_int16_t h_port_from, h_port_to;

  if(n->qualifiers.header == NBPF_Q_INNER) {
    if(ignore_inner_header) return 1;
    t = &h->tunneled_tuple;
  }

  h_l4_src_port = ntohs(t->l4_src_port), h_l4_dst_port = ntohs(t->l4_dst_port); 
  h_port_from = ntohs(n->port_from), h_port_to = ntohs(n->port_to);
  switch(n->qualifiers.direction) {
    case NBPF_Q_SRC:
      if(h_l4_src_port >= h_port_from &&
          h_l4_src_port <= h_port_to) return 1;
      break;
    case NBPF_Q_DST:
      if(h_l4_dst_port >= h_port_from &&
          h_l4_dst_port <= h_port_to) return 1;
      break;
    case NBPF_Q_DEFAULT:
    case NBPF_Q_OR:
      if((h_l4_src_port >= h_port_from &&
           h_l4_src_port <= h_port_to) ||
	  (h_l4_dst_port >= h_port_from &&
	   h_l4_dst_port <= h_port_to)) return 1;
      break;
    case NBPF_Q_AND:
      if(h_l4_src_port >= h_port_from &&
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

static /* inline */ int packet_match_host(nbpf_node_t *n, nbpf_pkt_info_t *h) {
  nbpf_pkt_info_tuple_t *t = &h->tuple;

  if(n->qualifiers.header == NBPF_Q_INNER) {
    if(ignore_inner_header) return 1;
    t = &h->tunneled_tuple;
  }
 
  switch(n->qualifiers.protocol) {
    case NBPF_Q_LINK:
      /* supported qualifiers: NBPF_Q_HOST/NBPF_Q_PROTO */
      return packet_match_mac(n, h);
      break;
    case NBPF_Q_DEFAULT:
    case NBPF_Q_IP:
      /* supported qualifiers: NBPF_Q_HOST/NBPF_Q_NET/NBPF_Q_PROTO */
      if(t->eth_type == 0x0800)
        return packet_match_ip(n, h);
      break;
    case NBPF_Q_IPV6:
      /* supported qualifiers: NBPF_Q_HOST/NBPF_Q_NET/NBPF_Q_PROTO */
      if(t->eth_type == 0x86DD)
        return packet_match_ip6(n, h);
      break;
    default:
      DEBUG_PRINTF("Unexpected address qualifier: %d\n", n->qualifiers.protocol); 
  }  
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);

  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_l4(nbpf_node_t *n, nbpf_pkt_info_t *h) {
  nbpf_pkt_info_tuple_t *t = &h->tuple;

  if(n->qualifiers.header == NBPF_Q_INNER) {
    if(ignore_inner_header) return 1;
    t = &h->tunneled_tuple;
  }
 
  switch(n->qualifiers.protocol) {
    case NBPF_Q_DEFAULT:
      return packet_match_port(n, h);
      break;
    case NBPF_Q_TCP:
      if(ignore_l3_proto || t->l3_proto == 6)
        return packet_match_port(n, h);
      break;
    case NBPF_Q_UDP:
      if(ignore_l3_proto || t->l3_proto == 17)
        return packet_match_port(n, h);
      break;
    case NBPF_Q_SCTP:
      if(ignore_l3_proto || t->l3_proto == 132)
        return packet_match_port(n, h);
      break;
    default:
      DEBUG_PRINTF("Unexpected protocol qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_proto(nbpf_node_t *n, nbpf_pkt_info_t *h) {
  nbpf_pkt_info_tuple_t *t = &h->tuple;

  if(n->qualifiers.header == NBPF_Q_INNER) {
    if(ignore_inner_header) return 1;
    t = &h->tunneled_tuple;
  }

  switch(n->qualifiers.protocol) {
    case NBPF_Q_LINK:
      if(t->eth_type == n->protocol)
        return 1;
      break;
    case NBPF_Q_DEFAULT:
    case NBPF_Q_IP:
    case NBPF_Q_IPV6:
      if(ignore_l3_proto || t->l3_proto == n->protocol)
        return 1;
      break;
    default:
      DEBUG_PRINTF("Unexpected protocol qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_l7_proto(nbpf_node_t *n, nbpf_pkt_info_t *h) {
  if(ignore_l7_proto || h->master_l7_proto == n->l7protocol || h->l7_proto == n->l7protocol)
    return 1;

  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_vlan(nbpf_node_t *n, nbpf_pkt_info_t *h) {
  switch(n->qualifiers.protocol) {
    case NBPF_Q_LINK:
      if(h->vlan_id == n->vlan_id || h->vlan_id_qinq == n->vlan_id)
        return 1;
      break;
    default:
      DEBUG_PRINTF("Unexpected vlan qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static /* inline */ int packet_match_primitive(nbpf_node_t *n, nbpf_pkt_info_t *h) {
  switch(n->qualifiers.address) {
    case NBPF_Q_DEFAULT:
    case NBPF_Q_HOST: 
    case NBPF_Q_NET:
      return packet_match_host(n, h);
    case NBPF_Q_PORT:
    case NBPF_Q_PORTRANGE:
      return packet_match_l4(n, h);
    case NBPF_Q_PROTO:
      return packet_match_proto(n, h);
    case NBPF_Q_PROTO_REL:
      return 0; /* TODO packet_match_proto_rel(n, h, pkt); note this requires packet data */
    case NBPF_Q_L7PROTO:
      return packet_match_l7_proto(n, h);
    case NBPF_Q_VLAN:
      return packet_match_vlan(n, h);
    default:
      DEBUG_PRINTF("Unexpected address qualifier (%d)\n", __LINE__);
  }
  DEBUG_PRINTF("%s returning false\n", __FUNCTION__);
  return 0;
}

/* ********************************************************************** */

static int packet_match_filter(nbpf_node_t *n, nbpf_pkt_info_t *h) {
  if(n == NULL)
    return 1;

  switch(n->type) {
    case N_PRIMITIVE: return !!(n->not_rule- packet_match_primitive(n, h));
    case N_AND:       return !!(n->not_rule- (packet_match_filter(n->l, h) && packet_match_filter(n->r, h)));
    case N_OR:        return !!(n->not_rule- (packet_match_filter(n->l, h) || packet_match_filter(n->r, h)));
    case N_EMPTY:     return 1;
    default:          DEBUG_PRINTF("Unexpected node type\n");
  }

  return 0;
}

/* ********************************************************************** */

void nbpf_toggle_mac_match(nbpf_tree_t *tree, u_int8_t enable) {
  ignore_mac_addr = !enable;
}

void nbpf_toggle_ipv6_l32_match(nbpf_tree_t *tree, u_int8_t enable) {
  use_ipv6_l32_match = enable;
}

void nbpf_toggle_l3_proto_match(nbpf_tree_t *tree, u_int8_t enable) {
  ignore_l3_proto = !enable;
}

void nbpf_toggle_l7_proto_match(nbpf_tree_t *tree, u_int8_t enable) {
  ignore_l7_proto = !enable;
}

void nbpf_toggle_inner_header_match(nbpf_tree_t *tree, u_int8_t enable) {
  ignore_inner_header = !enable;
}

/***************************************************************************/ 

int nbpf_match(nbpf_tree_t *tree, nbpf_pkt_info_t *h) {
  return packet_match_filter(tree->root, h);
}

/* *********************************************************** */

static char hex[] = "0123456789ABCDEF";

char* bpf_ethtoa(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return buf;
}

/* ********************************************************************** */

char* bpf_intoaV4(unsigned int addr, char* buf, u_int bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  retStr = (char*)(cp+1);

  return retStr;
}

/* *********************************************************** */

void bpf_append_str(char *cmd, u_int cmd_len, int num_cmds,
		    u_int8_t upper, char *str) {
  int l = strlen(cmd);
  const char *and = upper ? " AND " : " and ";
    
  if(cmd_len > l)
    snprintf(&cmd[l], cmd_len-l, "%s%s",
	     (num_cmds > 0) ? and : "", str);
}

/* ****************************************************** */

/* Napatech does not like short IPv6 address format */

char* bpf_intoaV6(struct nbpf_in6_addr *ipv6, char* buf, u_short bufLen) {
  int i, len = 0;
  
  buf[0] = '\0';

  for(i = 0; i<16; i++) {
    char tmp[8];
    
    snprintf(tmp, sizeof(tmp), "%02X", ipv6->u6_addr.u6_addr8[i] & 0xFF);
    len += snprintf(&buf[len], bufLen-len, "%s%s", (i > 0) ? ":" : "", tmp);
  }

  return(buf);
}

/* ****************************************************** */
