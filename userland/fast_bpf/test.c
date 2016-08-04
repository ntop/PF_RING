#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fast_bpf.h"

int main(int argc, char *argv[]) {
  fast_bpf_tree_t *tree;
  fast_bpf_pkt_info_t pkt;

  if (argc != 2) {
    printf("%s <bpf>\n", argv[0]);
    return -1;
  }

  if ((tree = fast_bpf_parse(argv[1], NULL)) == NULL) {
    printf("Parse error\n");
    return -1;
  } 
  
  printf("Parse OK\n");
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
