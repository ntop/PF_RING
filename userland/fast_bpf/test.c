#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
	     _intoaV4(c->shost.v4, a, sizeof(a)), ntohs(c->sport_low), ntohs(c->sport_high),
	     _intoaV4(c->dhost.v4, b, sizeof(b)), ntohs(c->dport_low), ntohs(c->dport_high));
    else
      printf("[%s:%u-%u -> %s:%u-%u]",
	     _intoaV4(c->dhost.v4, b, sizeof(b)), ntohs(c->dport_low), ntohs(c->dport_high),
	     _intoaV4(c->shost.v4, a, sizeof(a)), ntohs(c->sport_low), ntohs(c->sport_high));
    
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


int main(int argc, char *argv[]) {
  fast_bpf_tree_t *tree;
  fast_bpf_pkt_info_t pkt;
  fast_bpf_rule_block_list_item_t *punBlock;

  if (argc != 2) {
    printf("%s <bpf>\n", argv[0]);
    return -1;
  }

  if ((tree = fast_bpf_parse(argv[1], NULL)) == NULL) {
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
