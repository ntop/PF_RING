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

#ifndef NBPF_H
#define NBPF_H

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

struct nbpf_in6_addr {
  union {
    u_int8_t   u6_addr8[16];
    u_int16_t  u6_addr16[8];
    u_int32_t  u6_addr32[4];
  } u6_addr;  /* 128-bit IP6 address */
};

typedef union {
  struct nbpf_in6_addr v6;
  u_int32_t v4;
} __attribute__((packed))
nbpf_ip_addr;

/***************************************************************************/

/* Header qualifiers */
#define NBPF_Q_OUTER		1
#define NBPF_Q_INNER		2

/* Protocol qualifiers */
#define NBPF_Q_LINK		1
#define NBPF_Q_IP		2
#define NBPF_Q_SCTP		3
#define NBPF_Q_TCP		4
#define NBPF_Q_UDP		5
#define NBPF_Q_IPV6		6
#define NBPF_Q_GTP		7

/* Direction qualifiers */
#define NBPF_Q_SRC		1
#define NBPF_Q_DST		2
#define NBPF_Q_OR		3
#define NBPF_Q_AND		4

/* Address qualifiers */
#define NBPF_Q_HOST		1
#define NBPF_Q_NET		2
#define NBPF_Q_PORT		3
#define NBPF_Q_PROTO		5
#define NBPF_Q_PORTRANGE	7
#define NBPF_Q_VLAN		8
#define NBPF_Q_MPLS		9
#define NBPF_Q_L7PROTO	10

/* Common qualifiers */
#define NBPF_Q_DEFAULT	0
#define NBPF_Q_UNDEF		255

/* Node types */
#define N_PRIMITIVE     1
#define N_AND           2
#define N_OR            3

/***************************************************************************/

typedef struct {
  u_int8_t header;
  u_int8_t protocol;
  u_int8_t direction;
  u_int8_t address;
} __attribute__((packed))
nbpf_qualifiers_t;

struct nbpf_node;

typedef struct nbpf_node {
  int type;
  int level;
  nbpf_qualifiers_t qualifiers;
  u_int8_t not_rule;
  u_int8_t vlan_id_defined, mpls_label_defined;
  u_int8_t __padding;
  u_int16_t vlan_id;
  u_int16_t mpls_label;
  u_int8_t mac[6];
  u_int8_t ip6[16], mask6[16];
  u_int32_t ip, mask;
  u_int16_t port_from, port_to;
  u_int16_t protocol;
  u_int16_t l7protocol;

  struct nbpf_node *l;
  struct nbpf_node *r;
} __attribute__((packed))
nbpf_node_t;

typedef struct {
  nbpf_node_t *root;
  int compatibility_level; /* external use */
} __attribute__((packed))
nbpf_tree_t;

/***************************************************************************/

typedef int (*l7protocol_by_name_func)(const char *name);

/***************************************************************************/

/* nBPF API */

nbpf_tree_t *nbpf_parse(const char *bpf_filter, l7protocol_by_name_func l7proto_by_name_callback);
void nbpf_free(nbpf_tree_t *t);

/***************************************************************************/

/* nBPF Tree Match API */

typedef struct nbpf_pkt_info_tuple {
  u_int16_t eth_type;
  u_int8_t ip_version;
  u_int8_t l3_proto, ip_tos;
  nbpf_ip_addr ip_src, ip_dst;
  u_int16_t l4_src_port, l4_dst_port;
} __attribute__((packed))
nbpf_pkt_info_tuple_t;

typedef struct {
  u_int8_t  dmac[6], smac[6];
  u_int16_t vlan_id, vlan_id_qinq;
  u_int16_t master_l7_proto, l7_proto;
  nbpf_pkt_info_tuple_t tuple;
  nbpf_pkt_info_tuple_t tunneled_tuple;
} __attribute__((packed))
nbpf_pkt_info_t;

void nbpf_toggle_mac_match(nbpf_tree_t *tree, u_int8_t enable);
void nbpf_toggle_ipv6_l32_match(nbpf_tree_t *tree, u_int8_t enable);
void nbpf_toggle_l3_proto_match(nbpf_tree_t *tree, u_int8_t enable);
void nbpf_toggle_l7_proto_match(nbpf_tree_t *tree, u_int8_t enable);
void nbpf_toggle_inner_header_match(nbpf_tree_t *tree, u_int8_t enable);

int nbpf_match(nbpf_tree_t *tree, nbpf_pkt_info_t *h);

/***************************************************************************/

/* nBPF Filtering Rules Generation API */

typedef struct {
  u_int8_t smac[6], dmac[6]; 
  u_int8_t proto; /* tcp, udp, sctp */
  u_int8_t ip_version;
  u_int8_t gtp, vlan, mpls;
  u_int8_t __padding;
  u_int16_t vlan_id, l7_proto;
  u_int16_t mpls_label;
  nbpf_ip_addr shost, dhost;
  nbpf_ip_addr shost_mask, dhost_mask;
  u_int16_t sport_low, sport_high;
  u_int16_t dport_low, dport_high;
} __attribute__((packed))
nbpf_rule_core_fields_t;

struct nbpf_rule_list_item;

typedef struct nbpf_rule_list_item {
  nbpf_rule_core_fields_t fields;
  int bidirectional;
  struct nbpf_rule_list_item *next;
} __attribute__((packed))
nbpf_rule_list_item_t;

struct nbpf_rule_block_list_item;

typedef struct nbpf_rule_block_list_item {
  nbpf_rule_list_item_t *rule_list_head;
  struct nbpf_rule_block_list_item *next;
} __attribute__((packed))
nbpf_rule_block_list_item_t;

int nbpf_check_rules_constraints(nbpf_tree_t *tree, int max_nesting_level);

nbpf_rule_list_item_t *nbpf_generate_rules(nbpf_tree_t *tree);
void nbpf_rule_list_free(nbpf_rule_list_item_t *list);

nbpf_rule_block_list_item_t *nbpf_generate_optimized_rules(nbpf_tree_t *tree);
void nbpf_rule_block_list_free(nbpf_rule_block_list_item_t *blocks);

void bpf_append_str(char *cmd, u_int cmd_len, int num_cmds, char *str);
char *bpf_ethtoa(const u_char *ep, char *buf);
char *bpf_intoaV4(unsigned int addr, char* buf, u_int bufLen);
char *bpf_intoaV6(struct nbpf_in6_addr *ipv6, char* buf, u_short bufLen);

/***************************************************************************/

#endif

