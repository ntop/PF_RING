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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
#include <unistd.h>
#else
#include <getopt.h>
#endif

#include "nbpf.h"
#include "nbpf_mod_napatech.h"
#include "nbpf_mod_fiberblaze.h"

/* ****************************************** */

static char *dir_to_string(int dirq) {
  switch(dirq) {
    case NBPF_Q_SRC: return "Src"; 
    case NBPF_Q_DST: return "Dst";
    case NBPF_Q_AND: return "SrcAndDst";
    case NBPF_Q_OR: 
    default:         return "SrcOrDst";
  }
}

/* ****************************************** */

static char __addr[8];

static char *addr_to_string(int addrq) {
  switch(addrq) {
    case NBPF_Q_NET:       return "Net";
    case NBPF_Q_PORT:      return "Port";
    case NBPF_Q_PROTO:     return "Proto";
    case NBPF_Q_PROTO_REL: return "ProtoRelByteMatch";
    case NBPF_Q_PORTRANGE: return "PortRange";
    case NBPF_Q_VLAN:      return "VLAN";
    case NBPF_Q_MPLS:      return "MPLS";
    case NBPF_Q_L7PROTO:   return "L7Proto";
    case NBPF_Q_HOST:      return "Host";
    default:
      snprintf(__addr, sizeof(__addr), "(%d)", addrq);
      return __addr;
  }
}

/* ****************************************** */

static char __proto[8];

static char *proto_to_string(int protoq) {
  switch(protoq) {
    case NBPF_Q_LINK: return "Eth";
    case NBPF_Q_IP:   return "IP";
    case NBPF_Q_SCTP: return "SCTP";
    case NBPF_Q_TCP:  return "TCP";
    case NBPF_Q_UDP:  return "UDP";
    case NBPF_Q_IPV6: return "IP6";
    case NBPF_Q_GTP:  return "GTP";
    default:
      snprintf(__proto, sizeof(__proto), "%d", protoq);
      return __proto;
  }
}

/* ****************************************** */

static char *relop_to_string(int relop) {
  switch(relop) {
    case NBPF_R_EQ: return "==";
    case NBPF_R_NE: return "!=";
    case NBPF_R_LT: return  "<";
    case NBPF_R_LE: return "<=";
    case NBPF_R_GT: return  ">";
    case NBPF_R_GE: return ">=";
    default:        return  "?";
  }
}

/* ****************************************** */

static void print_padding(char ch, int n) {
  int i;

  for(i = 0; i < n; i++)
    putchar(ch);
}

/* ****************************************** */

static void dump_tree(nbpf_node_t *n, int level) {
  char tmp[32];

  if(n == NULL)
    return;

  dump_tree(n->r, level + 1);

  print_padding('\t', level);

  printf("%s", n->not_rule ? "!" : "");

  switch(n->type) {
    case N_EMPTY:
      printf("EMPTY");
      break;
    case N_PRIMITIVE:

      if(n->qualifiers.header == NBPF_Q_INNER)
        printf(" INNER");

      if(n->qualifiers.direction)
        printf(" %s", dir_to_string(n->qualifiers.direction));

      if(n->qualifiers.address)
        printf(" %s", addr_to_string(n->qualifiers.address));

      if(n->qualifiers.protocol)
        printf(" Proto:%s", proto_to_string(n->qualifiers.protocol));

      if(n->qualifiers.protocol == NBPF_Q_LINK) {
        if(n->qualifiers.address == NBPF_Q_VLAN) {
          printf(" VLAN");
          if(n->vlan_id_defined) printf(":%u", n->vlan_id);
        } else if(n->qualifiers.address == NBPF_Q_MPLS) {
          printf(" MPLS");
          if(n->mpls_label_defined) printf(":%u", n->mpls_label);
        } else {
          printf(" MAC:%s", bpf_ethtoa(n->mac, tmp));
        }

      } else if(n->qualifiers.address == NBPF_Q_HOST || n->qualifiers.address == NBPF_Q_NET) {
        if(n->qualifiers.protocol == NBPF_Q_IP || n->ip) {
          if(n->qualifiers.address == NBPF_Q_DEFAULT || n->qualifiers.address == NBPF_Q_HOST) {
            printf(" IP:%s", bpf_intoaV4(ntohl(n->ip), tmp, sizeof(tmp)));
          } else if(n->qualifiers.address == NBPF_Q_NET) {
            printf(" Net:%s", bpf_intoaV4(ntohl(n->ip & n->mask), tmp, sizeof(tmp)));
    	  }
        } else {
  	  printf(" IPv6: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X",
  	         n->ip6[0], n->ip6[1], n->ip6[2],  n->ip6[3],  n->ip6[4],  n->ip6[5],  n->ip6[6],  n->ip6[7],
  	         n->ip6[8], n->ip6[9], n->ip6[10], n->ip6[11], n->ip6[12], n->ip6[13], n->ip6[14], n->ip6[15]);
        }

      } else if(n->qualifiers.address == NBPF_Q_PORT) {
        printf(" Port:%d", ntohs(n->port_from));
	if(n->port_to != n->port_from) printf("-%d", ntohs(n->port_to));

      } else if(n->qualifiers.address == NBPF_Q_L7PROTO) {
        printf(" L7Proto:%d", n->l7protocol);

      } else if(n->protocol) {
        printf(" L4Proto:%d", n->protocol);

        if(n->qualifiers.address == NBPF_Q_PROTO_REL)
          printf(" %u[%u] & %u %s %u", n->protocol,  n->byte_match.offset, 
            n->byte_match.mask, relop_to_string(n->byte_match.relop), n->byte_match.value);
      }

      break;
    case N_AND:
      printf("AND");
      break;
    case N_OR:
      printf("OR");
      break;
    default:
      printf("?");
  }

  printf("\n");

  dump_tree(n->l, level + 1);
}

/* *********************************************************** */

void dump_rule(nbpf_rule_core_fields_t *c) {

  if(c->ip_version) printf("[IPv%d] ", c->ip_version);

  if(c->vlan) {
    if(c->vlan_id) printf("[VLAN: %u] ", c->vlan_id);
    else            printf("[VLAN] ");
  }
  if(c->mpls) {
    if(c->mpls_label) printf("[MPLS: %u] ", c->mpls_label);
    else               printf("[MPLS] ");
  }
  if(c->proto)      printf("[L4 Proto: %u] ", c->proto);

  if(!c->ip_version || c->ip_version == 4) {
    char a[32];

    printf("[");

    if(c->shost.v4) printf("%s", bpf_intoaV4(ntohl(c->shost.v4), a, sizeof(a)));
    else printf("*");
    printf(":");
    if(c->sport_low) {
      printf("%u", ntohs(c->sport_low));
      if(c->sport_high && c->sport_high != c->sport_low) printf("-%u", ntohs(c->sport_high));
    } else printf("*");

    printf(" -> ");

    if(c->dhost.v4) printf("%s", bpf_intoaV4(ntohl(c->dhost.v4), a, sizeof(a)));
    else printf("*");
    printf(":");
    if(c->dport_low) {
      printf("%u", ntohs(c->dport_low));
      if(c->dport_high && c->dport_high != c->dport_low) printf("-%u", ntohs(c->dport_high));
    } else printf("*");

    printf("] ");
  } else if(c->ip_version == 6) {
    char a[64];

    printf("[");

    if(c->shost.v4) printf("[%s]", bpf_intoaV6(&c->shost.v6, a, sizeof(a)));
    else printf("*");
    printf(":");
    if(c->sport_low) {
      printf("%u", ntohs(c->sport_low));
      if(c->sport_high && c->sport_high != c->sport_low) printf("-%u", ntohs(c->sport_high));
    } else printf("*");

    printf(" -> ");

    if(c->dhost.v4) printf("[%s]", bpf_intoaV6(&c->dhost.v6, a, sizeof(a)));
    else printf("*");
    printf(":");
    if(c->dport_low) {
      printf("%u", ntohs(c->dport_low));
      if(c->dport_high && c->dport_high != c->dport_low) printf("-%u", ntohs(c->dport_high));
    } else printf("*");

    printf("] ");
  }

  if (c->byte_match) {
    nbpf_rule_core_fields_byte_match_t *b = c->byte_match;
    while (b != NULL) {
      printf("[Byte Match: %u[%u]] ", b->protocol, b->offset);
      b = b->next;
    }
  }

  if(c->gtp) printf("[GTP] ");
}

/* *********************************************************** */

void dump_rules(nbpf_rule_list_item_t *pun) {
  u_int id = 1;

  /* Scan the list and set the single rule */
  while(pun != NULL) {
    nbpf_rule_core_fields_t *c = &pun->fields;

    printf("[%u] ", id);

    dump_rule(c);

    if(pun->bidirectional) printf("[BIDIRECTIONAL] ");
    printf("\n");

    pun = pun->next;
  }
}

/* *********************************************************** */

int napatech_cmd(void *opt, char *cmd) {
  printf("/opt/napatech3/bin/ntpl -e '%s'\n", cmd);
  return(0);
}

/* *********************************************************** */

void napatech_dump_rules(nbpf_rule_list_item_t *pun) {
  u_int8_t port_id = 0, stream_id = 1;

  printf("\n"
	 "Napatech Rules\n"
	 "---------------\n");

  bpf_init_napatech_rules(stream_id, NULL, napatech_cmd);

  /* Scan the list and set the single rule */

  while(pun != NULL) {
    char cmd[256] = { 0 };
      
    bpf_rule_to_napatech(stream_id, port_id, NULL, cmd, sizeof(cmd), &pun->fields, napatech_cmd);

    pun = pun->next;
  }
}

/* *********************************************************** */

void fiberblaze_dump_rules(nbpf_rule_list_item_t *pun) {
  char cmd[256];
  
  printf("\n"
	 "Fiberblaze Rules\n"
	 "---------------\n"
	 "%s\n",
	 bpf_rules_to_fiberblaze(pun, cmd, sizeof(cmd)));
}

/* *********************************************************** */

void help() {
  printf("nbpftest [-n][-F] -f \"BPF filter\"\n"
	 "\nUsage:\n"
	 "-n             | Dump rules in Napatech format\n"
	 "-F             | Dump rules in Fiberblaze format\n");
  exit(0);
}

/* *********************************************************** */

int main(int argc, char *argv[]) {
  nbpf_tree_t *tree;
  nbpf_pkt_info_t pkt;
  nbpf_rule_list_item_t *pun;
  int dump_napatech = 0, dump_fiberblaze = 0;
  char *filter = NULL, c;

  while((c = getopt(argc, argv, "hFf:n")) != '?') {
    if(c == -1) break;

    switch(c) {
    case 'h':
      help();
      break;

    case 'f':
      filter = optarg;
      break;

    case 'F':
      dump_fiberblaze = 1;
      break;

    case 'n':
      dump_napatech = 1;
      break;
    }
  }

  if(filter == NULL)
    help();

  if((tree = nbpf_parse(filter, NULL)) == NULL) {
    printf("Parse error\n");
    return -1;
  }

  printf("Dumping BPF Tree\n----------------\n");
  dump_tree(tree->root, 0);

  /* Generates rules list */
  if((pun = nbpf_generate_rules(tree)) == NULL) {
    printf("Error: filtering rules cannot be generated for the provided filter\n");
    nbpf_free(tree);
    return -1;
  }

  printf("\nDumping Rules\n-------------\n");

  dump_rules(pun);

  if(dump_napatech)   napatech_dump_rules(pun);
  if(dump_fiberblaze) fiberblaze_dump_rules(pun);

  nbpf_rule_list_free(pun);

  printf("\nTesting Filtering\n-----------------\n");

  memset(&pkt, 0, sizeof(pkt));

  pkt.vlan_id = 34;
  pkt.tuple.l3_proto = 17;
  pkt.tuple.l4_src_port = htons(34);
  pkt.tuple.l4_dst_port = htons(345);
  pkt.l7_proto = 7;
  printf("VlanID=%u Proto=%u SrcPort=%u DstPort=%u L7Proto=%u -> %s\n",
    pkt.vlan_id,
    pkt.tuple.l3_proto,
    ntohs(pkt.tuple.l4_src_port),
    ntohs(pkt.tuple.l4_dst_port),
    pkt.l7_proto,
    nbpf_match(tree, &pkt) ? "MATCHED" : "DISCARDED");

  nbpf_free(tree);

#if 0
  nbpf_rdif_handle_t *rdif_handle = nbpf_rdif_init("eth1");

  if(rdif_handle == NULL) {
    printf("RDIF Init error\n");
    return -1;
  }

  if(!nbpf_rdif_set_filter(rdif_handle, argv[1])){
    printf("RDIF Set BPF error\n");
    return -1;
  }

  printf("RDIF Set BPF OK\n");
#endif

  return(0);
}
