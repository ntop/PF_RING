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

#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <monetary.h>
#include <locale.h>

#include "pfring.h" /* using pfring_format_numbers() */
#include "pfring_ft.h"

#include "ftutils.c"

#define ALARM_SLEEP 1

pfring_ft_table *ft = NULL;
int bind_core = -1;
int bind_time_pulse_core = -1;
u_int8_t quiet = 0, verbose = 0, do_shutdown = 0, enable_l7 = 0;
u_int64_t num_pkts = 0;
u_int64_t num_bytes = 0;

volatile u_int64_t *pulse_timestamp;

/* ************************************ */

void *time_pulse_thread(void *data) {
  struct timespec tn;

  if (bind_time_pulse_core >= 0)
    bind2core(bind_time_pulse_core);

  while (likely(!do_shutdown)) {
    clock_gettime(CLOCK_REALTIME, &tn);
    *pulse_timestamp = ((u_int64_t) ((u_int64_t) tn.tv_sec << 32) | (tn.tv_nsec/1000));
    usleep(1);
  }

  return NULL;
}

/* *************************************** */

void print_stats() {
  pfring_ft_stats *fstat;
  static struct timeval start_time = { 0 };
  static struct timeval last_time = { 0 };
  struct timeval end_time;
  unsigned long long n_bytes, n_pkts;
  static u_int64_t last_pkts = 0;
  static u_int64_t last_bytes = 0;
  double diff, bytes_diff;
  u_int64_t delta_start;
  double delta_last;
  char buf1[64], buf2[64], timebuf[128];

  if (start_time.tv_sec == 0)
    gettimeofday(&start_time, NULL);
  gettimeofday(&end_time, NULL);

  n_bytes = num_bytes;
  n_pkts = num_pkts;

  if ((fstat = pfring_ft_get_stats(ft))) {
    if (last_time.tv_sec > 0) {
      delta_start = delta_time(&end_time, &start_time);
      delta_last = delta_time(&end_time, &last_time);
      diff = n_pkts - last_pkts;
      bytes_diff = n_bytes - last_bytes;
      bytes_diff /= (1000*1000*1000)/8;

      printf("Duration:    %s\n"
             "Flows:       %ju\n"
             "LookupDepth: %ju\n"
             "Errors:      %ju\n"
             "Packets:     %lu\n"
             "Bytes:       %lu\n"
             "Throughput:  %s pps (%s Gbps)\n"
             "---\n",
             msec2dhmsm(delta_start, timebuf, sizeof(timebuf)),
             fstat->flows,
             fstat->max_lookup_depth,
             fstat->err_no_room + fstat->err_no_mem,
             (long unsigned int) n_pkts,
             (long unsigned int) n_bytes,
	     pfring_format_numbers(((double) diff/(double)(delta_last/1000)),  buf1, sizeof(buf1), 1),
	     pfring_format_numbers(((double) bytes_diff/(double)(delta_last/1000)),  buf2, sizeof(buf2), 1));
    }
  }

  last_pkts = n_pkts;
  last_bytes = n_bytes;
  memcpy(&last_time, &end_time, sizeof(last_time));
}

/* ************************************ */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called) return; else called = 1;

  do_shutdown = 1;
}

/* ************************************ */

void my_sigalarm(int sig) {
  if (do_shutdown)
    return;

  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ******************************** */

void processFlow(pfring_ft_flow *flow, void *user) {
  pfring_ft_flow_key *k;
  pfring_ft_flow_value *v;
  char buf1[32], buf2[32];
  char *ip1, *ip2;

  k = pfring_ft_flow_get_key(flow);
  v = pfring_ft_flow_get_value(flow);

  if (k->ip_version == 4){
    ip1 = _intoa(k->saddr.v4, buf1, sizeof(buf1));
    ip2 = _intoa(k->daddr.v4, buf2, sizeof(buf2));
  } else {
    ip1 = (char *) inet_ntop(AF_INET6, &k->saddr.v6, buf1, sizeof(buf1));
    ip2 = (char *) inet_ntop(AF_INET6, &k->daddr.v6, buf2, sizeof(buf2));
  }

  printf("[Flow] srcIp: %s, dstIp: %s, srcPort: %u, dstPort: %u, protocol: %u, tcpFlags: 0x%02X, "
         "c2s: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }, "
         "s2c: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }\n",
         ip1, ip2, k->sport, k->dport, k->protocol, v->direction[s2d_direction].tcp_flags | v->direction[d2s_direction].tcp_flags,
         v->direction[s2d_direction].pkts, v->direction[s2d_direction].bytes,
         (u_int) v->direction[s2d_direction].first.tv_sec, (u_int) v->direction[s2d_direction].first.tv_usec,
         (u_int) v->direction[s2d_direction].last.tv_sec,  (u_int) v->direction[s2d_direction].last.tv_usec,
         v->direction[d2s_direction].pkts, v->direction[d2s_direction].bytes,
         (u_int) v->direction[d2s_direction].first.tv_sec, (u_int) v->direction[d2s_direction].first.tv_usec,
         (u_int) v->direction[d2s_direction].last.tv_sec,  (u_int) v->direction[d2s_direction].last.tv_usec);
}

/* ******************************** */

void process_packet(const pfring_ft_pcap_pkthdr *h, const u_char *p, const u_char *user_bytes) {
  pfring_ft_ext_pkthdr ext_hdr;
  pfring_ft_action action;

  ext_hdr.hash = 0;

  action = pfring_ft_process(ft, p, h, &ext_hdr);

  num_pkts++;
  num_bytes += h->len + 24;

  if (verbose) {
    char buffer[256];
    buffer[0] = '\0';
    pfring_print_pkt(buffer, sizeof(buffer), p, h->len, h->caplen);
    printf("[Packet]%s %s", action == PFRING_FT_ACTION_DISCARD ? " [discard]" : "", buffer);
  }
}

/* ******************************** */

void packet_consumer() {
  pfring_ft_pcap_pkthdr hdr;
  u_char *forged_packets, *data;
  u_int32_t i, num_forged_packets = 32768;
  u_int32_t packet_len = 64;
  u_int64_t ts;

  memset(&hdr, 0, sizeof(hdr));

  forged_packets = (u_char *) calloc(num_forged_packets, packet_len);

  if (forged_packets == NULL) {
    fprintf(stderr, "Memory allocation failure\n");
    return;
  }

  for (i = 0; i < num_forged_packets; i++)
    forge_udp_packet(&forged_packets[i * packet_len], packet_len, i);

  i = 0;
  while (!do_shutdown) {

    hdr.len = hdr.caplen = packet_len;

    ts = *pulse_timestamp;
    hdr.ts.tv_sec = ts >> 32;
    hdr.ts.tv_usec = (ts << 32) >> 32;

    data = &forged_packets[i * packet_len];

    process_packet(&hdr, data, NULL);

    if (++i == num_forged_packets)
      i = 0;
  }
}

/* *************************************** */

void print_help(void) {
  printf("fttest - (C) 2018 ntop.org\n");
  printf("Flow processing based on PF_RING FT (Flow Table)\n\n");
  printf("-h              Print this help\n");
  printf("-7              Enable L7 protocol detection (nDPI)\n");
  printf("-g <core>       CPU core affinity for packet processing\n");
  printf("-S <core>       CPU core affinity for time generation\n");
  printf("-q              Quiet mode\n");
  printf("-v              Verbose (print also raw packets)\n");
}

/* *************************************** */

int main(int argc, char* argv[]) {
  pthread_t time_thread;
  u_int32_t ft_flags = 0;
  char c;

  while ((c = getopt(argc,argv,"g:hqvS:7")) != '?') {
    if ((c == 255) || (c == -1)) break;

    switch(c) {
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'h':
      print_help();
      exit(0);
      break;
    case 'q':
      quiet = 1;
      break;
    case 'v':
      verbose = 1;
      break;
    case 'S':
      bind_time_pulse_core = atoi(optarg);
      break;
    case '7':
      enable_l7 = 1;
      break;
    }
  }

  bind2node(bind_core);

  if (enable_l7)
    ft_flags |= PFRING_FT_TABLE_FLAGS_DPI;

  ft = pfring_ft_create_table(ft_flags, 0, 0, 0);

  if (ft == NULL) {
    fprintf(stderr, "pfring_ft_create_table error\n");
    return -1;
  }

  /* Example of callback for expired flows */
  //pfring_ft_set_flow_export_callback(ft, processFlow, NULL);

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  pulse_timestamp = calloc(CACHE_LINE_LEN/sizeof(u_int64_t), sizeof(u_int64_t));
  pthread_create(&time_thread, NULL, time_pulse_thread, NULL);
  while (!*pulse_timestamp && !do_shutdown); /* wait for ts */

  if (bind_core >= 0)
    bind2core(bind_core);

  packet_consumer();

  sleep(1);

  pthread_join(time_thread, NULL);

  pfring_ft_flush(ft);

  pfring_ft_destroy_table(ft);

  return 0;
}
