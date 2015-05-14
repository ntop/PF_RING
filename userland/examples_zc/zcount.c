/*
 * (C) 2003-15 - ntop 
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
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <numa.h>

#include "pfring.h"
#include "pfring_zc.h"

#include "zutils.c"

#define ALARM_SLEEP             1
#define MAX_CARD_SLOTS      32768
#define MIN_BUFFER_LEN       1536
#define CACHE_LINE_LEN         64

#define NBUFF      256 /* pow */
#define NBUFFMASK 0xFF /* 256-1 */

//#define USE_BURST_API
#define BURST_LEN   32

pfring_zc_cluster *zc;
pfring_zc_queue *zq;
pfring_zc_pkt_buff *buffers[NBUFF];
u_int32_t lru = 0;

struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
int bind_core = -1;
int bind_time_pulse_core = -1;
int buffer_len;
u_int8_t wait_for_packet = 1, do_shutdown = 0, verbose = 0, add_filtering_rule = 0;
u_int8_t high_stats_refresh = 0, time_pulse = 0;

u_int64_t prev_ns = 0;
u_int64_t threshold_min = 1500, threshold_max = 2500; /* TODO parameters */
u_int64_t threshold_min_count = 0, threshold_max_count = 0;

volatile u_int64_t *pulse_timestamp_ns;

/* ******************************** */

void *time_pulse_thread(void *data) {
  struct timespec tn;

  bind2core(bind_time_pulse_core);

  while (likely(!do_shutdown)) {
    /* clock_gettime takes up to 30 nsec to get the time */
    clock_gettime(CLOCK_REALTIME, &tn);
    *pulse_timestamp_ns = ((u_int64_t) ((u_int64_t) tn.tv_sec * 1000000000) + tn.tv_nsec);
  }

  return NULL;
}

/* ******************************** */

void print_stats() {
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  static u_int64_t lastDrops = 0;
  static u_int64_t lastBytes = 0;
  double pktsDiff, dropsDiff, bytesDiff;
  static struct timeval lastTime;
  char buf1[64], buf2[64], buf3[64];
  unsigned long long nBytes = 0, nPkts = 0, nDrops = 0;
  pfring_zc_stat stats;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  nBytes = numBytes;
  nPkts = numPkts;
  if (pfring_zc_stats(zq, &stats) == 0)
    nDrops = stats.drop;

  fprintf(stderr, "=========================\n"
	  "Absolute Stats: %s pkts (%s drops) - %s bytes\n", 
	  pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)nDrops, buf3, sizeof(buf3), 0),
	  pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

  if(print_all && (lastTime.tv_sec > 0)) {
    char buf[256];

    deltaMillisec = delta_time(&endTime, &lastTime);
    pktsDiff = nPkts-lastPkts;
    dropsDiff = nDrops-lastDrops;
    bytesDiff = nBytes - lastBytes;
    bytesDiff /= (1000*1000*1000)/8;

    if (time_pulse)
      fprintf(stderr, "Thresholds: %ju pkts <%.3fusec %ju pkts >%.3fusec\n", 
        threshold_min_count, (double) threshold_min/1000, 
        threshold_max_count, (double) threshold_max/1000);

    snprintf(buf, sizeof(buf),
	     "Actual Stats: %s pps (%s drops) - %s Gbps",
	     pfring_format_numbers(((double)pktsDiff/(double)(deltaMillisec/1000)),  buf1, sizeof(buf1), 1),
	     pfring_format_numbers(((double)dropsDiff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1),
	     pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)),  buf3, sizeof(buf3), 1));
    fprintf(stderr, "%s\n", buf);
  }
    
  fprintf(stderr, "=========================\n\n");

  lastPkts = nPkts, lastDrops = nDrops, lastBytes = nBytes;
  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  do_shutdown = 1;

  print_stats();
  
  pfring_zc_queue_breakloop(zq);
}

/* *************************************** */

void printHelp(void) {
  printf("zcount - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A simple packet counter application.\n\n");
  printf("Usage:   zcount -i <device> -c <cluster id>\n"
	 "                [-h] [-g <core id>] [-R] [-H] [-S <core id>] [-v] [-a]\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-g <core id>    Bind this app to a core\n");
  printf("-a              Active packet wait\n");
  printf("-R              Test hw filters adding a rule (Intel 82599)\n");
  printf("-H              High stats refresh rate (workaround for drop counter on 1G Intel cards)\n");
  printf("-S <core id>    Pulse-time thread for inter-packet time check\n");
  printf("-v              Verbose\n");
  exit(-1);
}

/* *************************************** */

void print_packet(pfring_zc_pkt_buff *buffer) {
  u_char *pkt_data = pfring_zc_pkt_buff_data(buffer, zq);
  char bigbuf[4096];

  if (buffer->ts.tv_nsec)
    printf("[%u.%u] ", buffer->ts.tv_sec, buffer->ts.tv_nsec);

#if 1
  pfring_print_pkt(bigbuf, sizeof(bigbuf), pkt_data, buffer->len, buffer->len);
  fputs(bigbuf, stdout);
#else
  int i;
  for(i = 0; i < buffer->len; i++)
    printf("%02X ", pkt_data[i]);
  printf("\n");
#endif
}

/* *************************************** */


void *packet_consumer_thread(void *user) {
#ifdef USE_BURST_API
  int i, n;
#endif

  if (bind_core >= 0)
    bind2core(bind_core);

  while(!do_shutdown) {

#ifndef USE_BURST_API
    if(pfring_zc_recv_pkt(zq, &buffers[lru], wait_for_packet) > 0) {

      if (unlikely(time_pulse)) {
        u_int64_t now_ns = *pulse_timestamp_ns;
        u_int64_t diff_ns = now_ns - prev_ns;
        if (diff_ns < threshold_min) threshold_min_count++;
        else if (diff_ns > threshold_max) threshold_max_count++;
        prev_ns = now_ns;
      }

      if (unlikely(verbose))
        print_packet(buffers[lru]);

      numPkts++;
      numBytes += buffers[lru]->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */

      lru++; lru &= NBUFFMASK;
    }
#else
    if((n = pfring_zc_recv_pkt_burst(zq, buffers, BURST_LEN, wait_for_packet)) > 0) {

      if (unlikely(verbose))
        for (i = 0; i < n; i++) 
          print_packet(buffers[i]);

      for (i = 0; i < n; i++) {
        numPkts++;
        numBytes += buffers[i]->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */
      }
    }
#endif

  }

   pfring_zc_sync_queue(zq, rx_only);

  return NULL;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c;
  int i, cluster_id = -1, rc = 0;
  pthread_t my_thread;
  struct timeval timeNow, lastTime;
  pthread_t time_thread;

  lastTime.tv_sec = 0;
  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:g:hi:vRHS:")) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'c':
      cluster_id = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'R':
      add_filtering_rule = 1;
      break;
    case 'H':
      high_stats_refresh = 1;
      break;
    case 'S':
      time_pulse = 1;
      bind_time_pulse_core = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    }
  }
  
  if (device == NULL) printHelp();
  if (cluster_id < 0) printHelp();

  buffer_len = max_packet_len(device);

  zc = pfring_zc_create_cluster(
    cluster_id, 
    buffer_len,
    0, 
    MAX_CARD_SLOTS + NBUFF,
    numa_node_of_cpu(bind_core),
    NULL /* auto hugetlb mountpoint */ 
  );

  if(zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check that pf_ring.ko is loaded and hugetlb fs is mounted\n",
	    strerror(errno));
    return -1;
  }

  zq = pfring_zc_open_device(zc, device, rx_only, 0);

  if(zq == NULL) {
    fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	    strerror(errno), device);
    rc = -1;
    goto cleanup;
  }

  for (i = 0; i < NBUFF; i++) { 

    buffers[i] = pfring_zc_get_packet_handle(zc);

    if (buffers[i] == NULL) {
      fprintf(stderr, "pfring_zc_get_packet_handle error\n");
      rc = -1;
      goto cleanup;
    }
  }

  if(add_filtering_rule) {
    int rc;
    hw_filtering_rule rule;
    intel_82599_perfect_filter_hw_rule *perfect_rule = &rule.rule_family.perfect_rule;

    memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_perfect_filter_rule;
    rule.rule_id = 0, perfect_rule->queue_id = -1, perfect_rule->proto = 17, perfect_rule->s_addr = ntohl(inet_addr("10.0.0.1"));

    rc = pfring_zc_add_hw_rule(zq, &rule);

    if(rc != 0)
      printf("pfring_zc_add_hw_rule(%d) failed: did you enable the FlowDirector (ethtool -K ethX ntuple on)\n", rule.rule_id);
    else
      printf("pfring_zc_add_hw_rule(%d) succeeded: dropping UDP traffic 192.168.30.207:* -> *\n", rule.rule_id);
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  if (time_pulse) {
    pulse_timestamp_ns = calloc(CACHE_LINE_LEN/sizeof(u_int64_t), sizeof(u_int64_t));
    pthread_create(&time_thread, NULL, time_pulse_thread, NULL);
    while (!*pulse_timestamp_ns && !do_shutdown); /* wait for ts */
  }

  pthread_create(&my_thread, NULL, packet_consumer_thread, (void*) NULL);

  if (!verbose) while (!do_shutdown) {
    if (high_stats_refresh) {
      pfring_zc_stat stats;
      pfring_zc_stats(zq, &stats);
      gettimeofday(&timeNow, NULL);
      if (timeNow.tv_sec != lastTime.tv_sec) {
        lastTime.tv_sec = timeNow.tv_sec;
        print_stats();
      }
      usleep(1);
    } else {
      sleep(ALARM_SLEEP);
      print_stats();
    }
  }

  pthread_join(my_thread, NULL);

  sleep(1);

  if (time_pulse)
    pthread_join(time_thread, NULL);

cleanup:

  pfring_zc_destroy_cluster(zc);

  return rc;
}

