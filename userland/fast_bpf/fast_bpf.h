/*
 *  Copyright (C) 2016 ntop.org
 *
 *      http://www.ntop.org/
 *
 */

#ifndef FAST_BPF_H
#define FAST_BPF_H

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

#ifndef RING_VERSION
typedef union {
  struct in6_addr v6;
  u_int32_t v4;
} __attribute__((packed))
ip_addr;
#endif

/***************************************************************************/

/* Header qualifiers */
#define Q_OUTER		1
#define Q_INNER		2

/* Protocol qualifiers */
#define Q_LINK		1
#define Q_IP		2
#define Q_SCTP		5
#define Q_TCP		6
#define Q_UDP		7
#define Q_IPV6		17

/* Direction qualifiers */
#define Q_SRC		1
#define Q_DST		2
#define Q_OR		3
#define Q_AND		4

/* Address qualifiers */
#define Q_HOST		1
#define Q_NET		2
#define Q_PORT		3
#define Q_PROTO		5
#define Q_PORTRANGE	7
#define Q_VLAN		8
#define Q_L7PROTO	9

/* Common qualifiers */
#define Q_DEFAULT	0
#define Q_UNDEF		255

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
fast_bpf_qualifiers_t;

struct fast_bpf_node;

typedef struct fast_bpf_node {
  int type;
  int level;
  fast_bpf_qualifiers_t qualifiers;
  u_int8_t not;
  u_int8_t not_rule;
  u_int8_t vlan_id_defined;
  u_int8_t __padding;
  u_int16_t vlan_id;
  u_int8_t mac[6];
  u_int8_t ip6[16], mask6[16];
  u_int32_t ip, mask;
  u_int16_t port_from, port_to;
  u_int16_t protocol;
  u_int16_t l7protocol;

  struct fast_bpf_node *l;
  struct fast_bpf_node *r;
} __attribute__((packed))
fast_bpf_node_t;

typedef struct {
  fast_bpf_node_t *root;
} __attribute__((packed))
fast_bpf_tree_t;

/***************************************************************************/

typedef int (*l7protocol_by_name_func)(const char *name);

/***************************************************************************/

/* Fast-BPF API */

fast_bpf_tree_t *fast_bpf_parse(char *bpf_filter, l7protocol_by_name_func l7proto_by_name_callback);
void fast_bpf_free(fast_bpf_tree_t *t);

/***************************************************************************/

/* Fast-BPF Tree Match API */

typedef struct fast_bpf_pkt_info_tuple {
  u_int16_t eth_type;
  u_int8_t ip_version;
  u_int8_t l3_proto, ip_tos;
  ip_addr ip_src, ip_dst;
  u_int16_t l4_src_port, l4_dst_port;
} __attribute__((packed))
fast_bpf_pkt_info_tuple_t;

typedef struct {
  u_int8_t  dmac[6], smac[6];
  u_int16_t vlan_id, vlan_id_qinq;
  u_int16_t master_l7_proto, l7_proto;
  fast_bpf_pkt_info_tuple_t tuple;
  fast_bpf_pkt_info_tuple_t tunneled_tuple;
} __attribute__((packed))
fast_bpf_pkt_info_t;

void fast_bpf_toggle_mac_match(fast_bpf_tree_t *tree, u_int8_t enable);
void fast_bpf_toggle_ipv6_l32_match(fast_bpf_tree_t *tree, u_int8_t enable);
void fast_bpf_toggle_l3_proto_match(fast_bpf_tree_t *tree, u_int8_t enable);
void fast_bpf_toggle_l7_proto_match(fast_bpf_tree_t *tree, u_int8_t enable);
void fast_bpf_toggle_inner_header_match(fast_bpf_tree_t *tree, u_int8_t enable);

int fast_bpf_match(fast_bpf_tree_t *tree, fast_bpf_pkt_info_t *h);

/***************************************************************************/

/* Fast-BPF Filtering Rules Generation API */

typedef struct {
  u_int8_t  smac[6], dmac[6]; 
  u_int8_t  proto; /* tcp, udp, sctp */
  u_int16_t vlan_id, l7_proto;
  ip_addr   shost, dhost;
  ip_addr   shost_mask, dhost_mask;
  u_int16_t sport_low, sport_high;
  u_int16_t dport_low, dport_high;
} __attribute__((packed))
fast_bpf_rule_core_fields_t;

struct fast_bpf_rule_list_item;

typedef struct fast_bpf_rule_list_item {
  fast_bpf_rule_core_fields_t fields;
  int bidirectional;
  struct fast_bpf_rule_list_item *next;
} __attribute__((packed))
fast_bpf_rule_list_item_t;

struct fast_bpf_rule_block_list_item;

typedef struct fast_bpf_rule_block_list_item {
  fast_bpf_rule_list_item_t *rule_list_head;
  struct fast_bpf_rule_block_list_item *next;
} __attribute__((packed))
fast_bpf_rule_block_list_item_t;

int fast_bpf_check_rules_constraints(fast_bpf_tree_t *tree, int max_nesting_level);
fast_bpf_rule_list_item_t *fast_bpf_generate_rules(fast_bpf_tree_t *tree);
fast_bpf_rule_block_list_item_t *fast_bpf_generate_optimized_rules(fast_bpf_tree_t *tree);
void fast_bpf_rule_block_list_free(fast_bpf_rule_block_list_item_t *blocks);

/***************************************************************************/

#endif

