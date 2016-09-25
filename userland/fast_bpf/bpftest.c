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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fast_bpf.h"
#include "bpf_mod_napatech.h"

static char *dir_to_string[] =   { "SrcOrDst", "Src", "Dst", "SrcOrDst", "SrcAndDst", "?", "?", "?", "?" };
static char *addr_to_string[] =  { "Host", "Host", "Net", "Port", "?", "Proto", "?", "PortRange", "VLAN" };
static char *proto_to_string[] = { "IP", "Eth", "IP", "?", "?", "SCTP", "TCP", "UDP" };

/* ****************************************** */

static void print_padding(char ch, int n) {
  int i;
  for (i = 0; i < n; i++)
    putchar(ch);
}

/* ****************************************** */

static void dump_tree(fast_bpf_node_t *n, int level) {
  char type_str[1024];
  char tmp[32];

  if (n == NULL)
    return;

  switch(n->type) {
    case N_PRIMITIVE:
      type_str[0] = '\0';

      if (n->qualifiers.header == Q_INNER)
        sprintf(type_str, "%s INNER", type_str);

      sprintf(type_str, "%s %s %s", type_str,
        dir_to_string[n->qualifiers.direction],
	addr_to_string[n->qualifiers.address]);

      if (n->qualifiers.protocol <= Q_UDP)
        sprintf(type_str, "%s Proto:%s", type_str, proto_to_string[n->qualifiers.protocol]);
      else if (n->qualifiers.protocol == Q_IPV6)
        sprintf(type_str, "%s Proto:%s", type_str, "IPv6");
      else
        sprintf(type_str, "%s Proto:%d", type_str, n->qualifiers.protocol);

      if (n->qualifiers.protocol == Q_LINK) {
        if (n->qualifiers.address == Q_VLAN) {
          sprintf(type_str, "%s VLAN", type_str);
          if (n->vlan_id_defined) sprintf(type_str, "%s:%u", type_str, n->vlan_id);
        } else {
          sprintf(type_str, "%s MAC:%s", type_str, bpf_ethtoa(n->mac, tmp));
        }

      } else if (n->qualifiers.protocol == Q_DEFAULT || n->qualifiers.protocol == Q_IP) {
        if (n->qualifiers.address == Q_DEFAULT || n->qualifiers.address == Q_HOST) {
          sprintf(type_str, "%s IP:%s", type_str, bpf_intoaV4(ntohl(n->ip), tmp, sizeof(tmp)));
        } else if (n->qualifiers.address == Q_NET) {
          sprintf(type_str, "%s Net:%s", type_str, bpf_intoaV4(ntohl(n->ip & n->mask), tmp, sizeof(tmp)));
	}

      } else if (n->qualifiers.protocol == Q_IPV6) {
	sprintf(type_str, "%s IPv6: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X", type_str,
	        n->ip6[0], n->ip6[1], n->ip6[2],  n->ip6[3],  n->ip6[4],  n->ip6[5],  n->ip6[6],  n->ip6[7],
	        n->ip6[8], n->ip6[9], n->ip6[10], n->ip6[11], n->ip6[12], n->ip6[13], n->ip6[14], n->ip6[15]);
      }

      if (n->qualifiers.address == Q_PORT) {
        sprintf(type_str, "%s Port:%d", type_str, ntohs(n->port_from));
	if (n->port_to != n->port_from) sprintf(type_str, "%s-%d", type_str, ntohs(n->port_to));
      }

      break;
    case N_AND:
      sprintf(type_str, "AND");
      break;
    case N_OR:
      sprintf(type_str, "OR");
      break;
    default:
      sprintf(type_str, "?");
  }

  dump_tree(n->r, level + 1);
  print_padding('\t', level);
  printf("%s%s\n", n->not_expr ? "!" : "", type_str);
  dump_tree(n->l, level + 1);
}

/* *********************************************************** */

void dump_rule(u_int id, fast_bpf_rule_core_fields_t *c) {
  printf("[%u] ", id);

  if(c->ip_version) printf("[IPv%d] ", c->ip_version);

  if(c->vlan_id) printf("[VLAN: %u]", c->vlan_id);
  if(c->proto)   printf("[L4 Proto: %u]", c->proto);

  if(!c->ip_version || c->ip_version == 4) {
    char a[32];

    printf("[");

    if (c->shost.v4) printf("%s", bpf_intoaV4(ntohl(c->shost.v4), a, sizeof(a)));
    else printf("*");
    printf(":");
    if (c->sport_low) {
      printf("%u", ntohs(c->sport_low));
      if (c->sport_high && c->sport_high != c->sport_low) printf("-%u", ntohs(c->sport_high));
    } else printf("*");

    printf(" -> ");

    if (c->dhost.v4) printf("%s", bpf_intoaV4(ntohl(c->dhost.v4), a, sizeof(a)));
    else printf("*");
    printf(":");
    if (c->dport_low) {
      printf("%u", ntohs(c->dport_low));
      if (c->dport_high && c->dport_high != c->dport_low) printf("-%u", ntohs(c->dport_high));
    } else printf("*");

    printf("]");

  } else if(c->ip_version == 6) {
    //TODO

  }

  printf("\n");
}

/* *********************************************************** */

void dump_rules(fast_bpf_rule_block_list_item_t *punBlock) {
  fast_bpf_rule_block_list_item_t *currPun = punBlock;
  u_int id = 1;

  /* Scan the list and set the single rule */
  while(currPun != NULL) {
    fast_bpf_rule_list_item_t *pun = currPun->rule_list_head;

    while(pun != NULL) {
      fast_bpf_rule_core_fields_t *c = &pun->fields;

      dump_rule(id++, c);

      pun = pun->next;
    }

    currPun = currPun->next;
  }
}

/* *********************************************************** */

void napatech_cmd(char *cmd) {
  printf("/opt/napatech3/bin/ntpl -e '%s'\n", cmd);
}

/* *********************************************************** */

void napatech_dump_rules(fast_bpf_rule_block_list_item_t *punBlock) {
  fast_bpf_rule_block_list_item_t *currPun = punBlock;
  u_int8_t port_id = 0, stream_id = 1;

  printf("\n"
	 "Napatech Rules\n"
	 "---------------\n");

  napatech_cmd("Delete = All");
  napatech_cmd("DefineMacro(\"mUdpSrcPort\",\"Data[DynOffset=DynOffUDPFrame;Offset=0;DataType=ByteStr2]\")");
  napatech_cmd("DefineMacro(\"mUdpDestPort\",\"Data[DynOffset=DynOffUDPFrame;Offset=2;DataType=ByteStr2]\")");
  napatech_cmd("DefineMacro(\"mTcpSrcPort\",\"Data[DynOffset=DynOffTCPFrame;Offset=0;DataType=ByteStr2]\")");
  napatech_cmd("DefineMacro(\"mTcpDestPort\",\"Data[DynOffset=DynOffTCPFrame;Offset=2;DataType=ByteStr2]\")");
  napatech_cmd("DefineMacro(\"mIPv4SrcAddr\",\"Data[DynOffset=DynOffIPv4Frame;Offset=12;DataType=IPv4Addr]\")");
  napatech_cmd("DefineMacro(\"mIPv4DestAddr\",\"Data[DynOffset=DynOffIPv4Frame;Offset=16;DataType=IPv4Addr]\")");
  napatech_cmd("DefineMacro(\"mIPv6SrcAddr\",\"Data[DynOffset=DynOffIPv6Frame;Offset=8;DataType=IPv6Addr]\")");
  napatech_cmd("DefineMacro(\"mIPv6DestAddr\",\"Data[DynOffset=DynOffIPv6Frame;Offset=24;DataType=IPv6Addr]\")");

  /* Scan the list and set the single rule */
  while(currPun != NULL) {
    fast_bpf_rule_list_item_t *pun = currPun->rule_list_head;

    while(pun != NULL) {
      char cmd[256] = { 0 };
      
      rule_to_napatech(stream_id, port_id, cmd, sizeof(cmd), &pun->fields);
      napatech_cmd(cmd);

      pun = pun->next;
    }

    currPun = currPun->next;
  }
}

/* *********************************************************** */

void help() {
  printf("test [-n] -f \"BPF filter\"\n");
  exit(0);
}

/* *********************************************************** */

int main(int argc, char *argv[]) {
  fast_bpf_tree_t *tree;
  fast_bpf_pkt_info_t pkt;
  fast_bpf_rule_block_list_item_t *punBlock;
  int dump_napatech = 0;
  char *filter = NULL, c;

  while((c = getopt(argc, argv, "hf:n")) != '?') {
    if(c == -1) break;

    switch(c) {
    case 'h':
      help();
      break;

    case 'f':
      filter = optarg;
      break;

    case 'n':
      dump_napatech = 1;
      break;
    }
  }

  if (filter == NULL)
    help();

  if ((tree = fast_bpf_parse(filter, NULL)) == NULL) {
    printf("Parse error\n");
    return -1;
  }

  printf("Dumping BPF Tree\n"
         "----------------\n");
  dump_tree(tree->root, 0);

  /* Generates an optimized rules list */
  if((punBlock = fast_bpf_generate_optimized_rules(tree)) == NULL) {
    printf("Error: filter seems to be too complex\n");
    fast_bpf_free(tree);
    return -1;
  }

  printf("\n"
	 "Dumping Rules\n"
	 "-------------\n");

  dump_rules(punBlock);

  if(dump_napatech)
    napatech_dump_rules(punBlock);

  fast_bpf_rule_block_list_free(punBlock);

  printf("\n"
         "Testing Filtering\n"
         "-----------------\n");

  memset(&pkt, 0, sizeof(pkt));

  pkt.vlan_id = 34, pkt.tuple.l4_src_port = htons(34), pkt.tuple.l4_dst_port = htons(345), pkt.l7_proto = 7;
  printf("VlanID=34 SrcPort=34 DstPort=345 L7Proto=7 -> %s\n", fast_bpf_match(tree, &pkt) ? "MATCHED" : "DISCARDED");

  fast_bpf_free(tree);

#if 0
  fast_bpf_rdif_handle_t *rdif_handle = fast_bpf_rdif_init("eth1");

  if (rdif_handle == NULL) {
    printf("RDIF Init error\n");
    return -1;
  }

  if (!fast_bpf_rdif_set_filter(rdif_handle, argv[1])){
    printf("RDIF Set BPF error\n");
    return -1;
  }

  printf("RDIF Set BPF OK\n");
#endif

  return(0);
}
