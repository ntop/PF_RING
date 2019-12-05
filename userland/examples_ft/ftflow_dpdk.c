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

#ifdef RTE_ETHER_MAX_LEN
#define ether_header rte_ether_hdr
#define ether_addr   rte_ether_addr
#define ETHER_MAX_LEN RTE_ETHER_MAX_LEN
#else
#define ether_header ether_hdr
#endif

#define ALARM_SLEEP        1

#include "ftutils.c"

#include "pfring_ft.h"

#define RX_RING_SIZE      (8*1024)
#define TX_RING_SIZE      (8*1024)
#define MBUF_CACHE_SIZE       256
#define BURST_SIZE             64
#define PREFETCH_OFFSET         3
#define TX_TEST_PKT_LEN        60

//#define SCATTERED_RX_TEST
#ifdef SCATTERED_RX_TEST
#define MBUF_BUF_SIZE     512
#else
#define MBUF_BUF_SIZE    RTE_MBUF_DEFAULT_BUF_SIZE
#endif

#define print_mac_addr(addr) printf("%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8, \
  addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5])

static struct rte_mempool *mbuf_pool[RTE_MAX_LCORE] = { NULL };
static pfring_ft_table *fts[RTE_MAX_LCORE] = { NULL };
static u_int32_t ft_flags = 0;
static u_int8_t port = 0, twin_port = 0xFF;
static u_int8_t num_queues = 1;
static u_int8_t compute_flows = 1;
static u_int8_t do_loop = 1;
static u_int8_t verbose = 0;
static u_int8_t hw_stats = 0;
static u_int8_t fwd = 0;
static u_int8_t test_tx = 0;
static u_int8_t tx_csum_offload = 0;
static u_int8_t set_if_mac = 0;
static u_int8_t promisc = 1;
static u_int16_t mtu = 0;
static u_int16_t port_speed = 0;
static u_int16_t tx_test_pkt_len = TX_TEST_PKT_LEN;
static u_int32_t num_mbufs_per_lcore = 0;
static u_int32_t pps = 0;
static struct ether_addr if_mac = { 0 };

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
  struct rte_eth_fc_conf fc_conf = { 0 };
  int retval, i;
  u_int16_t q;
  char name[64];
  int num_ports;

  if (twin_port == 0xFF || twin_port == port) num_ports = 1;
  else num_ports = 2;

  num_mbufs_per_lcore = 2 * (
    RX_RING_SIZE + 
    TX_RING_SIZE + 
    BURST_SIZE * 2) 
#ifdef SCATTERED_RX_TEST
    * 4
#endif
    * (mtu ? (((mtu + ETHER_MAX_LEN - 1500) / MBUF_BUF_SIZE) + 1) : 1)
  ;

  for (q = 0; q < num_queues; q++) {
    snprintf(name, sizeof(name), "MBUF_POOL_%u", q);

    mbuf_pool[q] = rte_pktmbuf_pool_create(name, num_mbufs_per_lcore, MBUF_CACHE_SIZE, 0, 
      MBUF_BUF_SIZE, rte_socket_id());

    if (mbuf_pool[q] == NULL)
      rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n", rte_strerror(rte_errno));
  }

  for (i = 0; i < num_ports; i++) {
    u_int8_t port_id = (i == 0) ? port : twin_port;
    unsigned int numa_socket_id;
    
    printf("Configuring port %u...\n", port_id);

    fc_conf.mode = RTE_FC_NONE;
    fc_conf.autoneg = 0;

    if (rte_eth_dev_flow_ctrl_set(port_id, &fc_conf) != 0)
      printf("Unable to disable autoneg and flow control\n");

    if (port_speed) {
      switch (port_speed) {
      case   1: port_conf.link_speeds = ETH_LINK_SPEED_1G;   break;
      case  10: port_conf.link_speeds = ETH_LINK_SPEED_10G;  break;
      case  25: port_conf.link_speeds = ETH_LINK_SPEED_25G;  break;
      case  40: port_conf.link_speeds = ETH_LINK_SPEED_40G;  break;
      case  50: port_conf.link_speeds = ETH_LINK_SPEED_50G;  break;
      case 100: port_conf.link_speeds = ETH_LINK_SPEED_100G; break;
      default: break;
      }
      port_conf.link_speeds |= ETH_LINK_SPEED_FIXED;
    }

    if (tx_csum_offload)
      port_conf.txmode.offloads = DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM;

    retval = rte_eth_dev_configure(port_id, num_queues /* RX */, num_queues /* TX */, &port_conf);
    
    if (retval != 0)
      return retval;    

    if (mtu) {
      if (rte_eth_dev_set_mtu(port_id, mtu) != 0)
        printf("Unable to set the MTU\n");
      else
        printf("MTU set to %u on port %u\n", mtu, port_id);
    }

    numa_socket_id = rte_eth_dev_socket_id(port_id);
    
    for (q = 0; q < num_queues; q++) {

      printf("Configuring queue %u...\n", q);

      retval = rte_eth_rx_queue_setup(port_id, q, RX_RING_SIZE, numa_socket_id, NULL, mbuf_pool[q]);

      if (retval < 0)
	return retval;

      retval = rte_eth_tx_queue_setup(port_id, q, TX_RING_SIZE, numa_socket_id, NULL);

      if (retval < 0)
	return retval;
    }

    retval = rte_eth_dev_start(port_id);

    if (retval < 0)
      return retval;

    if (promisc && !set_if_mac)
      rte_eth_promiscuous_enable(port_id);

    if (rte_eth_dev_set_link_up(port_id) < 0)
      printf("Unable to set link up\n");
  }
 
  if (set_if_mac) {
    retval = rte_eth_dev_default_mac_addr_set(port, &if_mac);
    if (retval != 0)
      printf("Unable to set the interface MAC address (%d)\n", retval);
  }
 
  return 0;
}

/* ************************************ */

static void port_close(void) {
  int i;

  for (i = 0; i < 2; i++) {
    u_int8_t port_id = (i == 0) ? port : twin_port;
    
    if (port_id == 0xFF || (i == 1 && twin_port == port)) break;

    printf("Releasing port %u...\n", port_id);

    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
  }
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
#if !(defined(__arm__) || defined(__mips__))
  ticks tick_start = 0, tick_delta = 0;

  if (pps != 0) {
    double td;
    ticks hz = 0;

    /* computing usleep delay */
    tick_start = getticks();
    usleep(1);
    tick_delta = getticks() - tick_start;

    /* computing CPU freq */
    tick_start = getticks();
    usleep(1001);
    hz = (getticks() - tick_start - tick_delta) * 1000 /*kHz -> Hz*/;
    printf("Estimated CPU freq: %lu Hz\n", (long unsigned int)hz);

    td = (double) (hz / pps);
    tick_delta = (ticks) td;
    printf("Rate set to %u pps\n", pps);
  }
#endif

  printf("Generating traffic on port %u queue %u...\n", port, queue_id);

  num_ips = TX_RING_SIZE;

  while (do_loop) {

    rc = rte_mempool_get_bulk(mbuf_pool[queue_id], (void **) tx_bufs, BURST_SIZE);

    if (rc) {
      fprintf(stderr, "rte_mempool_get_bulk error (%d)\n", rc);
      return;
    }
  
    for (i = 0; i < BURST_SIZE; i++) {
      if (tx_bufs[i]->data_len != tx_test_pkt_len) {
        forge_udp_packet_fast((u_char *) rte_pktmbuf_mtod(tx_bufs[i], char *), 
          tx_test_pkt_len, stats[queue_id].tx_num_pkts + i);
        tx_bufs[i]->data_len = tx_bufs[i]->pkt_len = tx_test_pkt_len;
        if (tx_csum_offload)
          tx_bufs[i]->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
      }
    }

    sent = rte_eth_tx_burst(port, queue_id, tx_bufs, BURST_SIZE);

    stats[queue_id].tx_num_pkts += sent;
    stats[queue_id].tx_drops += (BURST_SIZE - sent);

    if (sent < BURST_SIZE)
      rte_mempool_put_bulk(mbuf_pool[queue_id], (void **) &tx_bufs[sent], BURST_SIZE - sent);

#if !(defined(__arm__) || defined(__mips__))
    if (pps > 0) {
      while ((getticks() - tick_start) < (stats[queue_id].tx_num_pkts * tick_delta))
        if (unlikely(!do_loop)) break;
    }
#endif

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
  struct rte_mbuf *mseg;
  u_int16_t num, tx_num, sent;
  u_int32_t num_ports, i;
  u_int8_t ports[2];

  if (queue_id >= num_queues)
    return 0;

  if (test_tx) {
    tx_test(queue_id);
    return 0;
  }

  ports[0] = port;
  num_ports = 1;

  if (twin_port != 0xFF) {
    ports[1] = twin_port;
    num_ports = 2;
  } else {
    fwd = 0;
  }

  ft = fts[queue_id];

  printf("Capturing from port %u queue %u...\n", port, queue_id);

  while (do_loop) {
    u_int32_t idx;
    
    for (idx = 0; idx < num_ports; idx++) {
      u_int8_t in_port      = ports[idx];
      u_int8_t out_port_id = ports[idx^1];
      
      num = rte_eth_rx_burst(in_port, queue_id, bufs, BURST_SIZE);

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
	
	if (likely(compute_flows)) {
          h.len = h.caplen = len;
          gettimeofday(&h.ts, NULL);

	  action = pfring_ft_process(ft, (const u_char *) data, &h, &ext_hdr);
        }
 
        stats[queue_id].num_pkts++;
        stats[queue_id].num_bytes += len + 24;

	if (unlikely(verbose)) {
	  int j;

	  printf("[Q#%u][Packet] len: %u segs: %u", queue_id, len, bufs[i]->nb_segs);

 	  if (action == PFRING_FT_ACTION_DISCARD)
	    printf(" [discard]");
         
          mseg = bufs[i];
          while (mseg && mseg->data_len) {
            printf("\n[data] len: %u hex: ", mseg->data_len);
	    data = rte_pktmbuf_mtod(mseg, char *);
  	    for (j = 0; j < mseg->data_len; j++)
	      printf("%02X ", data[j] & 0xFF);
            mseg = mseg->next;
          }

	  printf("\n");
	}

	if (fwd && action != PFRING_FT_ACTION_DISCARD) {
          tx_bufs[tx_num++] = bufs[i];
        } else {
          rte_pktmbuf_free(bufs[i]);
        }
      }

      if (tx_num > 0) {        
        sent = rte_eth_tx_burst(out_port_id, queue_id, tx_bufs, tx_num);
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
  printf("-p <id>[,<id>]  Port id (up to 2 ports are supported)\n");
  printf("-7              Enable L7 protocol detection (nDPI)\n");
  printf("-n <num cores>  Enable multiple cores/queues (default: 1)\n");
  printf("-0              Do not compute flows (packet capture only)\n");
  printf("-F              Enable forwarding when 2 ports are specified in -p\n");
  printf("-M <addr>       Set the port MAC address\n");
  printf("-U              Do not set promisc\n");
  printf("-S <speed>      Set the port speed in Gbit/s (1/10/25/40/50/100)\n");
  printf("-m <mtu>        Set the MTU\n");
  printf("-t              Test TX\n");
  printf("-T <size>       TX test - packet size\n");
  printf("-K              TX test - enable checksum offload\n");
  printf("-P <pps>        TX test - packet rate (pps)\n");
  printf("-H              Print hardware stats\n");
  printf("-v              Verbose (print raw packets)\n");
  printf("-h              Print this help\n");
}

/* ************************************ */

static int parse_args(int argc, char **argv) {
  int opt, ret;
  char **argvopt;
  int option_index;
  char *prgname = argv[0];
  u_int mac_a, mac_b, mac_c, mac_d, mac_e, mac_f;
  static struct option lgopts[] = {
    { NULL, 0, 0, 0 }
  };

  argvopt = argv;

  while ((opt = getopt_long(argc, argvopt, "FhHm:M:n:p:tUvP:S:T:K07", lgopts, &option_index)) != EOF) {
    switch (opt) {
    case 'F':
      fwd = 1;
      break;
    case 'h':
      print_help();
      exit(0);
      break;
    case 'H':
      hw_stats = 1;
      break;
    case 'M':
      if(sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &mac_a, &mac_b, &mac_c, &mac_d, &mac_e, &mac_f) != 6) {
	printf("Invalid MAC address format (XX:XX:XX:XX:XX:XX)\n");
	exit(0);
      }
      if_mac.addr_bytes[0] = mac_a, if_mac.addr_bytes[1] = mac_b, if_mac.addr_bytes[2] = mac_c,
      if_mac.addr_bytes[3] = mac_d, if_mac.addr_bytes[4] = mac_e, if_mac.addr_bytes[5] = mac_f;
      set_if_mac = 1;
      break;
    case 'm':
      mtu = atoi(optarg);
      break;
    case 'n':
      if (optarg) {
        num_queues = atoi(optarg);
      }
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
      compute_csum = 0;
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
    case 'T':
      tx_test_pkt_len = atoi(optarg);
      if (tx_test_pkt_len < 60) tx_test_pkt_len = 60; 
      break;
    case 'U':
      promisc = 0;
      break;
    case 'P':
      pps = atoi(optarg);
      break;
    case 'S':
      port_speed = atoi(optarg);
      break;
    case 'K':
      tx_csum_offload = 1;
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

static void print_hw_stats(int port_id) {
  struct rte_eth_xstat *xstats;
  struct rte_eth_xstat_name *xstats_names;
  int len, ret, i;

  len = rte_eth_xstats_get(port_id, NULL, 0);

  if (len < 0) {
    fprintf(stderr, "rte_eth_xstats_get(%u) failed: %d\n", port_id, len);
    return;
  }

  xstats = calloc(len, sizeof(*xstats));

  if (xstats == NULL) {
    fprintf(stderr, "Failed to calloc memory for xstats\n");
    return;
  }

  ret = rte_eth_xstats_get(port_id, xstats, len);

  if (ret < 0 || ret > len) {
    free(xstats);
    fprintf(stderr, "rte_eth_xstats_get(%u) len%i failed: %d\n", port_id, len, ret);
    return;
  }

  xstats_names = calloc(len, sizeof(*xstats_names));

  if (xstats_names == NULL) {
    free(xstats);
    fprintf(stderr, "Failed to calloc memory for xstats_names\n");
    return;
  }

  ret = rte_eth_xstats_get_names(port_id, xstats_names, len);

  if (ret < 0 || ret > len) {
    free(xstats);
    free(xstats_names);
    fprintf(stderr, "rte_eth_xstats_get_names(%u) len%i failed: %d\n", port_id, len, ret);
    return;
  }

  fprintf(stderr, "---\nPort %u hw stats:\n", port_id);

  for (i = 0; i < len; i++) {
    if (test_tx && xstats_names[i].name[0] != 't')
      continue;

    fprintf(stderr, "%s:\t%"PRIu64"\n",
      xstats_names[i].name,
      xstats[i].value);
  }

  fprintf(stderr, "---\n");

  free(xstats);
  free(xstats_names);
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
  double diff, bytes_diff;
  double delta_last = 0;
  char buf[512];
  int len, q;

  if (hw_stats) {
    print_hw_stats(port);
    if (twin_port != 0xFF)
      print_hw_stats(twin_port);
  }

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

    if (test_tx) {
      q_n_pkts = stats[q].tx_num_pkts;
      q_n_bytes = q_n_pkts * (tx_test_pkt_len + 24);
    }

    // if (num_queues > 1) {
      len = snprintf(buf, sizeof(buf), "[Q#%u]   ", q);

      if (!test_tx)
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
            "Throughput: %.3f Mpps",
            ((double) diff / (double)(delta_last/1000)) / 1000000);

        len += snprintf(&buf[len], sizeof(buf) - len,
          " (%.3f Gbps)\t",
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

    if (compute_flows && (fstat = pfring_ft_get_stats(fts[q]))) {
      fstat_sum.active_flows += fstat->active_flows;
      fstat_sum.flows += fstat->flows;
      fstat_sum.err_no_room += fstat->err_no_room;
      fstat_sum.err_no_mem += fstat->err_no_mem;
    }
  }

  if (test_tx) {
    /* Calling rte_eth_stats_get just to print perf stats */
    rte_eth_stats_get(port, &pstats);
    return;
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
  struct ether_addr mac_addr;
 
  ret = rte_eal_init(argc, argv);

  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  argc -= ret;
  argv += ret;

  ret = parse_args(argc, argv);

  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid ftflow_dpdk parameters\n");

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

  if (compute_flows) {
    for (q = 0; q < num_queues; q++) {
      fts[q] = pfring_ft_create_table(ft_flags, 0, 0, 0, 0);

      if (fts[q] == NULL) {
        fprintf(stderr, "pfring_ft_create_table error\n");
        return -1;
      }

      pfring_ft_set_flow_export_callback(fts[q], processFlow, fts[q]);
    }
  }

  rte_eth_macaddr_get(port, &mac_addr);
  printf("Port %u MAC address: ", port);
  print_mac_addr(mac_addr);
  printf("\n");

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  rte_eal_mp_remote_launch(packet_consumer, NULL, CALL_MASTER);

  RTE_LCORE_FOREACH_SLAVE(lcore_id) {
    rte_eal_wait_lcore(lcore_id);
  } 

  if (compute_flows) {
    for (q = 0; q < num_queues; q++)
      pfring_ft_flush(fts[q]);

    for (q = 0; q < num_queues; q++)
      pfring_ft_destroy_table(fts[q]);
  }

  port_close();

  return 0;
}

