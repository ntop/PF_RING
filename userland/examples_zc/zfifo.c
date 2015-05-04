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
#define PREFETCH_BUFFERS     4096
#define QUEUE_LEN            8192

#define VERY_VERBOSE
//#define USE_QUEUE

struct stats {
  u_int64_t __cache_line_padding_p[8];
  u_int64_t tot_recv;
  u_int64_t tot_bytes;
  u_int64_t __cache_line_padding_a[6];
};

pfring_zc_cluster *zc;
pfring_zc_worker *zw;
pfring_zc_queue **inzq;
#ifdef USE_QUEUE
pfring_zc_queue *outzq;
pfring_zc_pkt_buff *buffer;
#endif
pfring_zc_buffer_pool *wsp;


u_int32_t num_devices = 0;
int bind_worker_core = -1;
int bind_timer_core = -1;
int bind_consumer_core = -1;
char **devices = NULL;

struct timeval startTime;
u_int8_t wait_for_packet = 1;
volatile u_int8_t do_shutdown = 0;

struct stats consumers_stats;

//#define DEBUG
#ifdef DEBUG
struct timespec prev = { 0 };
u_int32_t roll_back = 0;
u_int64_t max_roll_back_nsec = 0;
#endif

/* ******************************** */

void print_stats() {
  struct timeval end_time;
  double delta_msec;
  static u_int8_t print_all;
  static u_int64_t last_tot_recv = 0;
  static u_int64_t last_tot_bytes = 0;
  static u_int64_t last_tot_drop = 0;
  static u_int64_t initial_drop = 0;
  double diff_recv, diff_bytes, diff_drop;
  static struct timeval last_time;
  char buf1[64], buf2[64];
  unsigned long long tot_bytes = 0, tot_recv = 0, tot_drop = 0;
  pfring_zc_stat stats;
  int i;

  for (i = 0; i < num_devices; i++)
    if (pfring_zc_stats(inzq[i], &stats) == 0)
      tot_recv += stats.recv, tot_drop += stats.drop;

  tot_bytes = consumers_stats.tot_bytes;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
    initial_drop = tot_drop;
  } else
    print_all = 1;

  gettimeofday(&end_time, NULL);
  delta_msec = delta_time(&end_time, &startTime);

  fprintf(stderr, "=========================\n"
	  "FIFO Stats: %s pkts (%s drops)\n", 
	  pfring_format_numbers((double)tot_recv, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)tot_drop-initial_drop, buf2, sizeof(buf2), 0));

#ifdef VERY_VERBOSE
  fprintf(stderr, "Consumer Stats: %s pkts - %s bytes",
	  pfring_format_numbers((double)consumers_stats.tot_recv, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)consumers_stats.tot_bytes, buf2, sizeof(buf2), 0));
#endif

  if(print_all && (last_time.tv_sec > 0)) {
    delta_msec = delta_time(&end_time, &last_time);
    diff_recv = tot_recv-last_tot_recv;
    diff_bytes = tot_bytes - last_tot_bytes;
    diff_bytes /= (1000*1000*1000)/8;
    diff_drop = tot_drop-last_tot_drop;

#ifdef VERY_VERBOSE
#ifdef USE_QUEUE
    if (pfring_zc_stats(outzq, &stats) == 0)
      fprintf(stderr, " (%s drops)", pfring_format_numbers((double)stats.drop, buf1, sizeof(buf1), 1));
#endif
    fprintf(stderr, " (%s Gbps)\n", pfring_format_numbers(((double)diff_bytes/(double)(delta_msec/1000)),  buf1, sizeof(buf1), 1));
#endif

#ifdef DEBUG
    fprintf(stderr, "%d Out-Of-Order packets (max roll back %ju nsec)\n",
      roll_back, max_roll_back_nsec);
#endif

    fprintf(stderr, "Actual FIFO Stats: %s pps (%s drops)",
	    pfring_format_numbers(((double)diff_recv/(double)(delta_msec/1000)),  buf1, sizeof(buf1), 1),
	    pfring_format_numbers(((double)diff_drop/(double)(delta_msec/1000)),  buf2, sizeof(buf2), 1));
  }
    
  fprintf(stderr, "\n=========================\n\n");

  last_tot_recv = tot_recv, last_tot_bytes = tot_bytes, last_tot_drop = tot_drop;
  last_time.tv_sec = end_time.tv_sec, last_time.tv_usec = end_time.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  do_shutdown = 1;

  print_stats();
  
#ifdef USE_QUEUE
  pfring_zc_queue_breakloop(outzq);
#endif
}

/* ******************************** */

void printHelp(void) {
  printf("zfifo - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A master thread reordering packets from multiple interfaces with\n"
         "hw timestamps support, and delivering them to a consumer thread. (experimental)\n\n");
  printf("Usage:    zfifo -i <device> -c <cluster id>\n"
	 "                [-h] [-r <core id>] [-g <core id>] [-a]\n\n");
  printf("-h              Print this help\n");
  printf("-i <devices>    Comma-separated list of devices\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-r <core id>    Sorter thread core affinity\n");
  //printf("-t <core id>    Timer thread core affinity\n");
  printf("-g <core id>    Consumer thread core affinity\n");
  printf("-a              Active packet wait\n");
  printf("\nExample: zfifo -i zc:eth1,zc:eth2 -c 10 -r 1 -g 2\n");
  exit(-1);
}

/* *************************************** */

int32_t processing_func(pfring_zc_pkt_buff *b, pfring_zc_queue *in_queue, void *user) {
#if 0
  int i;

  for(i = 0; i < b->len; i++)
    printf("%02X ", pfring_zc_pkt_buff_data(b, outzq)[i]);
  printf("\n");
#endif

#ifdef DEBUG
  if (b->ts.tv_sec == prev.tv_sec && b->ts.tv_nsec < prev.tv_nsec) {
    u_int64_t diff = prev.tv_nsec - b->ts.tv_nsec;
    if (diff > max_roll_back_nsec) max_roll_back_nsec = diff;
    roll_back++;
  }
  prev.tv_sec = b->ts.tv_sec, prev.tv_nsec = b->ts.tv_nsec;
#endif

  consumers_stats.tot_recv++;
  consumers_stats.tot_bytes += b->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */

  return 0;
}

/* *************************************** */

#ifdef USE_QUEUE
void *consumer_thread(void *user) {
  pfring_zc_pkt_buff *b = buffer;

  bind2core(bind_consumer_core);

  while (!do_shutdown) {
    if (pfring_zc_recv_pkt(outzq, &b, wait_for_packet) > 0)
      processing_func(b, outzq, NULL);
  }

  pfring_zc_sync_queue(outzq, rx_only);

  return NULL;
}
#endif

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, *dev, c;
  long i;
  int cluster_id = -1;
#ifdef USE_QUEUE
  pthread_t thread;
#endif

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:g:hi:r:t:")) != '?') {
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
      bind_consumer_core = atoi(optarg);
      break;
    case 'r':
      bind_worker_core = atoi(optarg);
      break;
    case 't':
      bind_timer_core = atoi(optarg);
      break;
    }
  }
  
  if (device == NULL) printHelp();
  if (cluster_id < 0) printHelp();

  dev = strtok(device, ",");
  while(dev != NULL) {
    devices = realloc(devices, sizeof(char *) * (num_devices+1));
    devices[num_devices] = strdup(dev);
    num_devices++;
    dev = strtok(NULL, ",");
  }

  if (num_devices < 2) printHelp();

  zc = pfring_zc_create_cluster(
    cluster_id, 
    max_packet_len(devices[0]),
    0,
#ifdef USE_QUEUE
    QUEUE_LEN + 1 + 
#endif
    (num_devices * (MAX_CARD_SLOTS + PREFETCH_BUFFERS)),
    numa_node_of_cpu(bind_worker_core), 
    NULL /* auto hugetlb mountpoint */ 
  );

  if(zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
	    strerror(errno));
    return -1;
  }

  inzq = calloc(num_devices,     sizeof(pfring_zc_queue *));

  for (i = 0; i < num_devices; i++) {
    inzq[i] = pfring_zc_open_device(zc, devices[i], rx_only, PF_RING_ZC_DEVICE_HW_TIMESTAMP);

    if(inzq[0] == NULL) {
      fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	      strerror(errno), devices[i]);
      return -1;
    }
  }

  wsp = pfring_zc_create_buffer_pool(zc, num_devices * PREFETCH_BUFFERS);

  if (wsp == NULL) {
    fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
    return -1;
  }

#ifdef USE_QUEUE
  buffer = pfring_zc_get_packet_handle(zc);

  if (buffer == NULL) {
    fprintf(stderr, "pfring_zc_get_packet_handle error\n");
    return -1;
  }

  outzq = pfring_zc_create_queue(zc, QUEUE_LEN);

  if(outzq == NULL) {
    fprintf(stderr, "pfring_zc_create_queue error [%s]\n", strerror(errno));
    return -1;
  }
#endif

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  printf("Starting sorter and consumer thread..\n");

  zw = pfring_zc_run_fifo(
    inzq, 
#ifdef USE_QUEUE
    outzq,
#else
    NULL,
#endif
    num_devices, 
    wsp,
    NULL /* idle callback */,
#ifdef USE_QUEUE
   NULL,
#else
    processing_func,
#endif
    NULL /* user data */,
    1, /* active wait is mandatory here */ 
    bind_worker_core,
    bind_timer_core
  );

  if(zw == NULL) {
    fprintf(stderr, "pfring_zc_run_fifo error [%s]\n", strerror(errno));
    return -1;
  }

#ifdef USE_QUEUE
  pthread_create(&thread, NULL, consumer_thread, (void *) i);
#endif

  while (!do_shutdown) {
    sleep(ALARM_SLEEP);
    print_stats();
  }
  
#ifdef USE_QUEUE
  pthread_join(thread, NULL);
#endif

  pfring_zc_kill_worker(zw);

  pfring_zc_destroy_cluster(zc);

  return 0;
}

