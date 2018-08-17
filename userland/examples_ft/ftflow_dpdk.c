/*
 * (C) 2018 - ntop
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <unistd.h>

#include "ftutils.c"

#include "pfring_ft.h"

#define RX_RING_SIZE     128
#define TX_RING_SIZE     512
#define NUM_MBUFS       8191
#define MBUF_CACHE_SIZE  250
#define BURST_SIZE        32
#define PREFETCH_OFFSET    3

static pfring_ft_table *ft = NULL;
static u_int32_t ft_flags = 0;
static u_int8_t port = 0;
static u_int8_t verbose = 0;

static const struct rte_eth_conf port_conf_default = {
  .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

static inline int port_init(struct rte_mempool *mbuf_pool) {
  struct rte_eth_conf port_conf = port_conf_default;
  const u_int16_t rx_rings = 1, tx_rings = 1;
  int retval;
  u_int16_t q;

  /* 1 RX queue */
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);

  if (retval != 0)
    return retval;

  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0)
      return retval;
  }

  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port), NULL);
    if (retval < 0)
      return retval;
  }

  retval = rte_eth_dev_start(port);

  if (retval < 0)
    return retval;

  rte_eth_promiscuous_enable(port);

  return 0;
}

void processFlow(pfring_ft_flow *flow, void *user){
  pfring_ft_flow_key *k;
  pfring_ft_flow_value *v;
  char buf1[32], buf2[32], buf3[32];
  const char *ip1, *ip2;

  k = pfring_ft_flow_get_key(flow);
  v = pfring_ft_flow_get_value(flow);

  if (k->ip_version == 4){
    ip1 = _intoa(k->saddr.v4, buf1, sizeof(buf1));
    ip2 = _intoa(k->daddr.v4, buf2, sizeof(buf2));
  } else {
    ip1 = inet_ntop(AF_INET6, &k->saddr.v6, buf1, sizeof(buf1));
    ip2 = inet_ntop(AF_INET6, &k->daddr.v6, buf2, sizeof(buf2));
  }

  printf("[Flow] "
         "srcIp: %s, dstIp: %s, srcPort: %u, dstPort: %u, protocol: %u, tcpFlags: 0x%02X, "
         "l7: %s, "
         "c2s: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }, "
         "s2c: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }\n",
         ip1, ip2, k->sport, k->dport, k->protocol, v->direction[s2d_direction].tcp_flags | v->direction[d2s_direction].tcp_flags,
         pfring_ft_l7_protocol_name(ft, &v->l7_protocol, buf3, sizeof(buf3)),
         v->direction[s2d_direction].pkts, v->direction[s2d_direction].bytes, 
         (u_int) v->direction[s2d_direction].first.tv_sec, (u_int) v->direction[s2d_direction].first.tv_usec, 
         (u_int) v->direction[s2d_direction].last.tv_sec,  (u_int) v->direction[s2d_direction].last.tv_usec,
         v->direction[d2s_direction].pkts, v->direction[d2s_direction].bytes, 
         (u_int) v->direction[d2s_direction].first.tv_sec, (u_int) v->direction[d2s_direction].first.tv_usec, 
         (u_int) v->direction[d2s_direction].last.tv_sec,  (u_int) v->direction[d2s_direction].last.tv_usec);

  pfring_ft_flow_free(flow);
}

static void lcore_main(void) {
  pfring_ft_pcap_pkthdr h;
  pfring_ft_ext_pkthdr ext_hdr = { 0 };
  u_int32_t i;

  if (rte_eth_dev_socket_id(port) > 0 && rte_eth_dev_socket_id(port) != (int) rte_socket_id()) {
    printf("WARNING: port %u and processing core %u are on different NUMA nodes\n", port, rte_lcore_id());
  }

  while (1) {
    struct rte_mbuf *bufs[BURST_SIZE];
    u_int16_t num;

    num = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

    if (unlikely(num == 0)) {
      pfring_ft_housekeeping(ft, time(NULL));
      continue;
    }

    for (i = 0; i < PREFETCH_OFFSET && i < num; i++)
      rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));

    for (i = 0; i < num; i++) {
      char *data = rte_pktmbuf_mtod(bufs[i], char *);
      int len = rte_pktmbuf_pkt_len(bufs[i]);
      pfring_ft_action action;

      h.len = h.caplen = len;
      gettimeofday(&h.ts, NULL);

      action = pfring_ft_process(ft, (const u_char *) data, &h, &ext_hdr);
 
      if (verbose) {
        int j;

        printf("[Packet] hex: ");
        for (j = 0; j < len; j++)
          printf("%02X ", data[j]);

        if (action == PFRING_FT_ACTION_DISCARD)
          printf(" [discard]");

        printf("\n");
      }

      rte_pktmbuf_free(bufs[i]);
    }
  }
}

static void print_help(void) {
  printf("ftflow_dpdk - (C) 2018 ntop.org\n");
  printf("Usage: ftflow_dpdk [EAL options] -- [options]\n");
  printf("-p <id>     Port id\n");
  printf("-7          Enable L7 protocol detection (nDPI)\n");
  printf("-v          Verbose (print also raw packets)\n");
  printf("-h          Print this help\n");
}

static int parse_args(int argc, char **argv) {
  int opt, ret;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];
  static struct option lgopts[] = {
    { NULL, 0, 0, 0 }
  };

  argvopt = argv;

  while ((opt = getopt_long(argc, argvopt, "hp:v7", lgopts, &option_index)) != EOF) {
    switch (opt) {
    case 'p':
      if (optarg)
        port = atoi(optarg);
      break;
    case '7':
      ft_flags |= PFRING_FT_TABLE_FLAGS_DPI;
      break;
    case 'v':
      verbose = 1;
      break;
    case 'h':
      print_help();
      exit(0);
      break;
    default:
      print_help();
      return -1;
    }
  }

  if (optind >= 0)
    argv[optind-1] = prgname;

  ret = optind-1;
  optind = 1;
  return ret;
}

int main(int argc, char *argv[]) {
  struct rte_mempool *mbuf_pool;
  u_int8_t num_ports;
  int ret;

  ret = rte_eal_init(argc, argv);

  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  argc -= ret;
  argv += ret;

  ret = parse_args(argc, argv);

  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid flow_classify parameters\n");

  num_ports = rte_eth_dev_count();

  if (port >= num_ports)
    rte_exit(EXIT_FAILURE, "Error: port %u not available\n", port);

  mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  if (port_init(mbuf_pool) != 0)
    rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", port);

  if (rte_lcore_count() > 1)
    printf("WARNING: Too many lcores enabled, only 1 used\n");

  ft = pfring_ft_create_table(ft_flags, 0, 0, 0);

  if (ft == NULL) {
    fprintf(stderr, "pfring_ft_create_table error\n");
    return -1;
  }

  pfring_ft_set_flow_export_callback(ft, processFlow, NULL);

  lcore_main();

  pfring_ft_flush(ft);

  pfring_ft_destroy_table(ft);

  return 0;
}

