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

#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define ALARM_SLEEP        1

/* NOTE: ether_hdr is defined in rte_ether.h */
#define ether_header ether_hdr
#include "ftutils.c"

#include "pfring_ft.h"

#define RX_RING_SIZE     8192
#define TX_RING_SIZE     1024
#define MBUF_CACHE_SIZE   256
#define BURST_SIZE         32
#define PREFETCH_OFFSET     3
#define TX_TEST_PKT_LEN    60

static struct rte_mempool *mbuf_pool = NULL;
static pfring_ft_table *fts[RTE_MAX_LCORE] = { 0 };
static u_int32_t ft_flags = 0;
static u_int8_t port = 0, twin_port = 0xFF;
static u_int8_t num_queues = 1;
static u_int8_t compute_flows = 1;
static u_int8_t do_loop = 1;
static u_int8_t verbose = 0;
static u_int8_t test_tx = 0;

static struct lcore_stats {
  u_int64_t num_pkts;
  u_int64_t num_bytes;
  u_int64_t last_pkts;
  u_int64_t last_bytes;
  u_int64_t tx_num_pkts;
  u_int64_t tx_drops;
  u_int64_t padding[2];
} stats[RTE_MAX_LCORE];

static const struct rte_eth_conf port_conf_default = {
  .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};

/* ************************************ */

static int port_init(void) {
  struct rte_eth_conf port_conf = port_conf_default;
  const u_int16_t rx_rings = num_queues, tx_rings = num_queues;
  int num_mbufs;
  int retval, i;
  u_int16_t q;

  num_mbufs = 2 * (RX_RING_SIZE + TX_RING_SIZE + BURST_SIZE) * num_queues;

  mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", num_mbufs, MBUF_CACHE_SIZE, 0, 
    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n", rte_strerror(rte_errno));

  for (i = 0; i < 2; i++) {
    u_int8_t port_id = (i == 0) ? port : twin_port;
    unsigned int numa_socket_id;
    
    if(port_id == 0xFF || (i == 1 && twin_port == port)) break;

    printf("Configuring port %u...\n", port_id);

    retval = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
    
    if (retval != 0)
      return retval;    

    numa_socket_id = rte_eth_dev_socket_id(port_id);
    
    for (q = 0; q < rx_rings; q++) {
      retval = rte_eth_rx_queue_setup(port_id, q, RX_RING_SIZE, numa_socket_id, NULL, mbuf_pool);
      if (retval < 0)
	return retval;
    }

    for (q = 0; q < tx_rings; q++) {
      retval = rte_eth_tx_queue_setup(port_id, q, TX_RING_SIZE, numa_socket_id, NULL);
      if (retval < 0)
	return retval;
    }

    retval = rte_eth_dev_start(port_id);

    if (retval < 0)
      return retval;

    rte_eth_promiscuous_enable(port_id);
  }
  
  return 0;
}

/* ************************************ */

void processFlow(pfring_ft_flow *flow, void *user) {
  pfring_ft_table *ft = (pfring_ft_table *) user;
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

/* ************************************ */

static void tx_test(u_int16_t queue_id) {
  struct rte_mbuf *tx_bufs[BURST_SIZE];
  u_int32_t i;
  u_int16_t sent;
  int rc;

  printf("Generating traffic on port %u queue %u...\n", port, queue_id);

  while (do_loop) {

    rc = rte_mempool_get_bulk(mbuf_pool, (void **) tx_bufs, BURST_SIZE);

    if (rc) {
      fprintf(stderr, "rte_mempool_get_bulk error\n");
      return;
    }
  
    for (i = 0; i < BURST_SIZE; i++) {
      forge_udp_packet_fast((u_char *) rte_pktmbuf_mtod(tx_bufs[i], char *), 
        TX_TEST_PKT_LEN, stats[queue_id].tx_num_pkts + i);
      tx_bufs[i]->data_len = tx_bufs[i]->pkt_len = TX_TEST_PKT_LEN;
    }

    sent = rte_eth_tx_burst(port, queue_id, tx_bufs, BURST_SIZE);

    stats[queue_id].tx_num_pkts += sent;
    stats[queue_id].tx_drops += (BURST_SIZE - sent);

    for (i = sent; i < BURST_SIZE; i++)
      rte_pktmbuf_free(tx_bufs[i]);
  }
}

/* ************************************ */

static int packet_consumer(__attribute__((unused)) void *arg) {
  unsigned lcore_id = rte_lcore_id();
  u_int16_t queue_id = lcore_id;
  pfring_ft_table *ft;
  pfring_ft_pcap_pkthdr h;
  pfring_ft_ext_pkthdr ext_hdr = { 0 };
  struct rte_mbuf *bufs[BURST_SIZE];
  struct rte_mbuf *tx_bufs[BURST_SIZE];
  u_int16_t num, tx_num, sent;
  u_int32_t i;

  if (queue_id >= num_queues)
    return 0;

  if (test_tx) {
    tx_test(queue_id);
    return 0;
  }

  ft = fts[queue_id];

  printf("Capturing from port %u queue %u...\n", port, queue_id);

  while (do_loop) {
    u_int32_t idx;
    
    for (idx = 0; idx < 2; idx++) {
      u_int8_t port_id      = (idx == 0) ? port      : twin_port;
      u_int8_t twin_port_id = (idx == 0) ? twin_port : port;
      
      if(port_id == 0xFF) continue;

      num = rte_eth_rx_burst(port_id, queue_id, bufs, BURST_SIZE);

      if (unlikely(num == 0)) {
        if (likely(compute_flows))
	  pfring_ft_housekeeping(ft, time(NULL));
	continue;
      }

      for (i = 0; i < PREFETCH_OFFSET && i < num; i++)
	rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));

      tx_num = 0;
      for (i = 0; i < num; i++) {
	char *data = rte_pktmbuf_mtod(bufs[i], char *);
	int len = rte_pktmbuf_pkt_len(bufs[i]);
	pfring_ft_action action = PFRING_FT_ACTION_DEFAULT;
	
        stats[queue_id].num_pkts++;
        stats[queue_id].num_bytes += len + 24;

	if (likely(compute_flows)) {
          h.len = h.caplen = len;
          gettimeofday(&h.ts, NULL);

	  action = pfring_ft_process(ft, (const u_char *) data, &h, &ext_hdr);
        }
 
	if (unlikely(verbose)) {
	  int j;

	  printf("[Q#%u][Packet] len: %u hex: ", queue_id, len);
	  for (j = 0; j < len; j++)
	    printf("%02X ", data[j] & 0xFF);

	  if (action == PFRING_FT_ACTION_DISCARD)
	    printf(" [discard]");

	  printf("\n");
	}

	if ((twin_port_id != 0xFF) && (action != PFRING_FT_ACTION_DISCARD)) {
          tx_bufs[tx_num++] = bufs[i];
        } else {
          rte_pktmbuf_free(bufs[i]);
        }
      }

      if (tx_num > 0) {        
        sent = rte_eth_tx_burst(twin_port_id, queue_id, tx_bufs, tx_num);
        stats[queue_id].tx_num_pkts += sent;
        stats[queue_id].tx_drops += (tx_num - sent);
        for (i = sent; i < tx_num; i++)
          rte_pktmbuf_free(tx_bufs[i]);
      }

    } /* for */
  } /* while */

  return 0;
}

/* ************************************ */

static void print_help(void) {
  printf("ftflow_dpdk - (C) 2018 ntop.org\n");
  printf("Usage: ftflow_dpdk [EAL options] -- [options]\n");
  printf("-p <id>[,<id>]  Port id. Use -p <id>,<id> for bridge mode\n");
  printf("-7              Enable L7 protocol detection (nDPI)\n");
  printf("-n <num cores>  Enable multiple cores/queues (default: 1)\n");
  printf("-0              Do not compute flows (packet capture only)\n");
  printf("-t              Test TX\n");
  printf("-v              Verbose (print also raw packets)\n");
  printf("-h              Print this help\n");
}

/* ************************************ */

static int parse_args(int argc, char **argv) {
  int opt, ret;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];
  static struct option lgopts[] = {
    { NULL, 0, 0, 0 }
  };

  argvopt = argv;

  while ((opt = getopt_long(argc, argvopt, "hn:p:tv07", lgopts, &option_index)) != EOF) {
    switch (opt) {
    case 'n':
      if (optarg) {
        num_queues = atoi(optarg);
      }
      break;
    case 'h':
      print_help();
      exit(0);
      break;
    case 'p':
      if(optarg) {
	char *p = strtok(optarg, ",");

	if(p) {
	  port = atoi(p);
	  p = strtok(NULL, ",");
	  if(p)
	    twin_port = atoi(p);
	}
      }
      break;
    case 't':
      test_tx = 1;
      break;
    case 'v':
      verbose = 1;
      break;
    case '0':
      compute_flows = 0;
      break;
    case '7':
      ft_flags |= PFRING_FT_TABLE_FLAGS_DPI;
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

/* ************************************ */

static void print_stats(void) {
  pfring_ft_stats fstat_sum = { 0 };
  pfring_ft_stats *fstat;
  struct rte_eth_stats pstats = { 0 };
  static struct timeval start_time = { 0 };
  static struct timeval last_time = { 0 };
  struct timeval end_time;
  unsigned long long n_bytes = 0, n_pkts = 0, n_drops = 0;
  unsigned long long tx_n_bytes = 0, tx_n_pkts = 0, tx_n_drops = 0;
  unsigned long long q_n_bytes = 0, q_n_pkts = 0;
  static u_int64_t last_pkts = 0;
  static u_int64_t last_bytes = 0;
  double diff, bytes_diff;
  double delta_last = 0;
  char buf[512];
  int len, q;

  if (start_time.tv_sec == 0)
    gettimeofday(&start_time, NULL);

  gettimeofday(&end_time, NULL);

  if (last_time.tv_sec > 0)
    delta_last = delta_time(&end_time, &last_time);

  memcpy(&last_time, &end_time, sizeof(last_time));

  for (q = 0; q < num_queues; q++) {
    q_n_pkts = stats[q].num_pkts;
    q_n_bytes = stats[q].num_bytes;

    /* Reading port packets/bytes with rte_eth_stats_get
     * n_pkts  += q_n_pkts;
     * n_bytes += q_n_bytes; */

    // if (num_queues > 1) {
      len = snprintf(buf, sizeof(buf), "[Q#%u]   ", q);

      len += snprintf(&buf[len], sizeof(buf) - len,
          "Packets: %llu\t"
          "Bytes: %llu\t", 
          q_n_pkts, 
          q_n_bytes);

      if (delta_last) {
        diff = q_n_pkts - stats[q].last_pkts;
        bytes_diff = q_n_bytes - stats[q].last_bytes;
        bytes_diff /= (1000*1000*1000)/8;

        len += snprintf(&buf[len], sizeof(buf) - len,
            "Throughput: %.3f Mpps (%.3f Gbps)\t",
            ((double) diff / (double)(delta_last/1000)) / 1000000,
            ((double) bytes_diff / (double)(delta_last/1000)));
      }
      stats[q].last_pkts = q_n_pkts;
      stats[q].last_bytes = q_n_bytes;

      if (twin_port != 0xFF || test_tx)
        len += snprintf(&buf[len], sizeof(buf) - len,
            "            \t"
            "TXPackets: %ju\t"
            "            \t"
            "TXDrops: %ju\t",
            stats[q].tx_num_pkts,
            stats[q].tx_drops);

      fprintf(stderr, "%s\n", buf);
    //}

    if ((fstat = pfring_ft_get_stats(fts[q]))) {
      fstat_sum.active_flows += fstat->active_flows;
      fstat_sum.flows += fstat->flows;
      fstat_sum.err_no_room += fstat->err_no_room;
      fstat_sum.err_no_mem += fstat->err_no_mem;
    }
  }

  if (rte_eth_stats_get(port, &pstats) == 0) {
    n_pkts  = pstats.ipackets;
    n_bytes = pstats.ibytes + (n_pkts * 24);
    n_drops = pstats.imissed + pstats.ierrors;
    tx_n_pkts  = pstats.opackets;
    tx_n_bytes = pstats.obytes + (tx_n_pkts * 24);
    tx_n_drops = pstats.oerrors;

    if (twin_port != 0xFF && twin_port != port) {
      if (rte_eth_stats_get(twin_port, &pstats) == 0) {
        n_pkts  += pstats.ipackets;
        n_bytes += pstats.ibytes + (n_pkts * 24);
        n_drops += pstats.imissed + pstats.ierrors;
        tx_n_pkts  += pstats.opackets;
        tx_n_bytes += pstats.obytes + (tx_n_pkts * 24);
        tx_n_drops += pstats.oerrors;
      }
    }
  }

  len = snprintf(buf, sizeof(buf), "[Total] ");

  if (compute_flows)
    len += snprintf(&buf[len], sizeof(buf) - len,
        "ActFlows: %ju\t"
        "TotFlows: %ju\t"
        "Errors: %ju\t",
        fstat_sum.active_flows,
        fstat_sum.flows,
        fstat_sum.err_no_room + fstat_sum.err_no_mem);

  len += snprintf(&buf[len], sizeof(buf) - len,
      "Packets: %llu\t"
      "Bytes: %llu\t",
      n_pkts,
      n_bytes);

  if (delta_last) {
    diff = n_pkts - last_pkts;
    bytes_diff = n_bytes - last_bytes;
    bytes_diff /= (1000*1000*1000)/8;

    len += snprintf(&buf[len], sizeof(buf) - len,
        "Throughput: %.3f Mpps (%.3f Gbps)\t",
        ((double) diff / (double)(delta_last/1000)) / 1000000,
        ((double) bytes_diff / (double)(delta_last/1000)));
  }
  last_pkts = n_pkts;
  last_bytes = n_bytes;

  len += snprintf(&buf[len], sizeof(buf) - len,
      "Drops: %llu\t",
      n_drops);

  if (twin_port != 0xFF)
    len += snprintf(&buf[len], sizeof(buf) - len,
        "TXPackets: %llu\t"
        "TXBytes: %llu\t"
        "TXDrop: %llu\t",
        tx_n_pkts,
        tx_n_bytes,
        tx_n_drops);

  fprintf(stderr, "%s\n---\n", buf);
}

/* ************************************ */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called) return; else called = 1;

  do_loop = 0;
}

/* ************************************ */

void my_sigalarm(int sig) {
  if (!do_loop)
    return;

  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ************************************ */

int main(int argc, char *argv[]) {
  int q, ret;
  unsigned lcore_id;
  
  ret = rte_eal_init(argc, argv);

  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  argc -= ret;
  argv += ret;

  ret = parse_args(argc, argv);

  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid flow_classify parameters\n");

  memset(stats, 0, sizeof(stats));

  if (rte_lcore_count() > num_queues)
    printf("INFO: %u lcores enabled, only %u used\n", rte_lcore_count(), num_queues);

  if (rte_lcore_count() < num_queues) {
    num_queues = rte_lcore_count();
    printf("INFO: only %u lcores enabled, using %u queues\n", rte_lcore_count(), num_queues);
    return -1;
  }

  if (port_init() != 0)
    rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n", port);

  for (q = 0; q < num_queues; q++) {
    fts[q] = pfring_ft_create_table(ft_flags, 0, 0, 0);

    if (fts[q] == NULL) {
      fprintf(stderr, "pfring_ft_create_table error\n");
      return -1;
    }

    pfring_ft_set_flow_export_callback(fts[q], processFlow, fts[q]);
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  rte_eal_mp_remote_launch(packet_consumer, NULL, CALL_MASTER);

  RTE_LCORE_FOREACH_SLAVE(lcore_id) {
    rte_eal_wait_lcore(lcore_id);
  } 

  for (q = 0; q < num_queues; q++)
    pfring_ft_flush(fts[q]);

  for (q = 0; q < num_queues; q++)
    pfring_ft_destroy_table(fts[q]);

  return 0;
}

