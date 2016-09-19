#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fast_bpf.h"

/* *********************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    u_int byte;

    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* *********************************************************** */

void dump_rule(u_int id, fast_bpf_rule_core_fields_t *c, u_int8_t revert) {
  printf("[%u] ", id);

  if(c->ip_version) printf("[IPv%d] ", c->ip_version);

  if(c->vlan_id) printf("[VLAN: %u]", c->vlan_id);
  if(c->proto)   printf("[L4 Proto: %u]", c->proto);

  if(c->ip_version == 4) {
    char a[32], b[32];

    if(!revert)
      printf("[%s:%u-%u -> %s:%u-%u]",
	     _intoaV4(ntohl(c->shost.v4), a, sizeof(a)), ntohs(c->sport_low), ntohs(c->sport_high),
	     _intoaV4(ntohl(c->dhost.v4), b, sizeof(b)), ntohs(c->dport_low), ntohs(c->dport_high));
    else
      printf("[%s:%u-%u -> %s:%u-%u]",
	     _intoaV4(ntohl(c->dhost.v4), b, sizeof(b)), ntohs(c->dport_low), ntohs(c->dport_high),
	     _intoaV4(ntohl(c->shost.v4), a, sizeof(a)), ntohs(c->sport_low), ntohs(c->sport_high));

  } else if(c->ip_version == 6) {

  } else {
    if(ntohs(c->sport_low) || ntohs(c->dport_low)) {
      if(!revert)
	printf("[any:%u-%u -> any:%u-%u]", ntohs(c->sport_low), ntohs(c->sport_high), ntohs(c->dport_low), ntohs(c->dport_high));
      else
	printf("[any:%u-%u -> any:%u-%u]", ntohs(c->dport_low), ntohs(c->dport_high), ntohs(c->sport_low), ntohs(c->sport_high));
    }
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

      dump_rule(id++, c, 0);

      if(pun->bidirectional)
	dump_rule(id++, c, 1);

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

void append_str(char *cmd, u_int cmd_len, int num_cmds, char *str) {
  int l = strlen(cmd);
  
  if(cmd_len > l)
    snprintf(&cmd[l], cmd_len-l, "%s%s",
	     (num_cmds > 0) ? " AND " : "", str);
}

/* *********************************************************** */

void napatech_dump_rule(u_int id, fast_bpf_rule_core_fields_t *c, u_int8_t revert) {
  char cmd[1024] = { 0 }, *proto = "", buf[256];
  int num_cmds = 0;

  append_str(cmd, sizeof(cmd), 0, "Assign[StreamId = 1] = ");

  if(c->vlan_id) append_str(cmd, sizeof(cmd), num_cmds++, "((Encapsulation == VLAN)");

  switch(c->proto) {
  case 1:  append_str(cmd, sizeof(cmd), num_cmds++, "(Layer4Protocol == ICMP)"); break;
  case 6:  append_str(cmd, sizeof(cmd), num_cmds++, "(Layer4Protocol == TCP)"), proto = "Tcp";  break;
  case 17: append_str(cmd, sizeof(cmd), num_cmds++, "(Layer4Protocol == UDP)"), proto = "Udp";  break;
  }

  if(c->ip_version == 4) {
    char a[32];
    
    if(c->shost.v4) { snprintf(buf, sizeof(buf), "mIPv4%sAddr(\"%s\")", (!revert) ? "Src" : "Dest", _intoaV4(c->shost.v4, a, sizeof(a))); append_str(cmd, sizeof(cmd), num_cmds++,  buf); }
    if(c->dhost.v4) { snprintf(buf, sizeof(buf), "mIPv4%sAddr(\"%s\")", (!revert) ? "Dest" : "Src", _intoaV4(c->dhost.v4, a, sizeof(a))); append_str(cmd, sizeof(cmd), num_cmds++,  buf); }
  } else if(c->ip_version == 6) {

  }

  if(c->sport_low > 0) { snprintf(buf, sizeof(buf), "m%s%sPort(\"%u\")", proto, (!revert) ? "Src" : "Dest", ntohs(c->sport_low)); append_str(cmd, sizeof(cmd), num_cmds++,  buf); }
  if(c->dport_low > 0) { snprintf(buf, sizeof(buf), "m%s%sPort(\"%u\")", proto, (!revert) ? "Dest" : "Src", ntohs(c->dport_low)); append_str(cmd, sizeof(cmd), num_cmds++,  buf); }

  if(c->vlan_id) append_str(cmd, sizeof(cmd), num_cmds++, ")");

  napatech_cmd(cmd);
}

/* *********************************************************** */

void napatech_dump_rules(fast_bpf_rule_block_list_item_t *punBlock) {
  fast_bpf_rule_block_list_item_t *currPun = punBlock;
  u_int id = 1;

  printf("\n"
	 "Napatech Rules\n"
	 "---------------\n");

  napatech_cmd("Delete = All");
  napatech_cmd("Assign[StreamId=1] = Port == 0");
  napatech_cmd("DefineMacro(\"mUdpSrcPort\",\"Data[DynOffset=DynOffUDPFrame;Offset=0;DataType=ByteStr2] == $1\")");
  napatech_cmd("DefineMacro(\"mUdpDestPort\",\"Data[DynOffset=DynOffUDPFrame;Offset=2;DataType=ByteStr2] == $1\")");
  napatech_cmd("DefineMacro(\"mTcpSrcPort\",\"Data[DynOffset=DynOffTCPFrame;Offset=0;DataType=ByteStr2] == $1\")");
  napatech_cmd("DefineMacro(\"mTcpDestPort\",\"Data[DynOffset=DynOffTCPFrame;Offset=2;DataType=ByteStr2] == $1\")");
  napatech_cmd("DefineMacro(\"mIPv4SrcAddr\",\"Data[DynOffset=DynOffIPv4Frame;Offset=12;DataType=IPv4Addr] == $1\")");
  napatech_cmd("DefineMacro(\"mIPv4DestAddr\",\"Data[DynOffset=DynOffIPv4Frame;Offset=16;DataType=IPv4Addr] == $1\")");
  napatech_cmd("DefineMacro(\"mIPv6SrcAddr\",\"Data[DynOffset=DynOffIPv6Frame;Offset=8;DataType=IPv6Addr] == $1\")");
  napatech_cmd("DefineMacro(\"mIPv6DestAddr\",\"Data[DynOffset=DynOffIPv6Frame;Offset=24;DataType=IPv6Addr] == $1\")");

  /* Scan the list and set the single rule */
  while(currPun != NULL) {
    fast_bpf_rule_list_item_t *pun = currPun->rule_list_head;

    while(pun != NULL) {
      fast_bpf_rule_core_fields_t *c = &pun->fields;

      napatech_dump_rule(id++, c, 0);

      if(pun->bidirectional)
	napatech_dump_rule(id++, c, 1);

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

if(filter == NULL)
  help();

  if ((tree = fast_bpf_parse(filter, NULL)) == NULL) {
    printf("Parse error\n");
    return -1;
  }

  printf("Parse OK\n");

  /* Generates an optimized rules list */
  if((punBlock = fast_bpf_generate_optimized_rules(tree)) == NULL) {
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

  printf("\n");

  memset(&pkt, 0, sizeof(pkt));

  pkt.vlan_id = 34, pkt.tuple.l4_src_port = htons(34), pkt.tuple.l4_dst_port = htons(345), pkt.l7_proto = 7;
  printf("%s\n", fast_bpf_match(tree, &pkt) ? "MATCHED" : "DISCARDED");

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
