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

//#define USE_RECV_BURST

#define ALARM_SLEEP               1
#define MAX_CARD_SLOTS        32768
#define SWAP_BUFFERS             16
#define QUEUE_LEN              8192
#define SLAVE_BUFFERS            16
#define CACHE_LINE_LEN           64
#define PULSE_TS_PRECISION_NSEC 100

pfring_zc_cluster *zc;
pfring_zc_queue *inzq;
pfring_zc_queue **outzq;
pfring_zc_buffer_pool **pools;
pfring_zc_multi_queue *mq;
pfring_zc_pkt_buff *ph[SWAP_BUFFERS];

u_int32_t num_slaves = 1;
u_int32_t queue_len = QUEUE_LEN;

int bind_core = -1;
int bind_time_pulse_core = -1;

static struct timeval startTime;

struct volatile_globals {
  unsigned long long numPkts;
  unsigned long long numBytes;
  unsigned long long sentPkts;
  int time_pulse;
  int wait_for_packet;
  int pulse_timestamp_precision_nsec;
  volatile u_int8_t do_shutdown;
  volatile u_int64_t *pulse_timestamp_ns;
};

struct volatile_globals *globals;

/* ******************************** */

void *time_pulse_thread(void *data) {
  struct volatile_globals *g = globals;
  u_int64_t ns;
  struct timespec tn;
#if 1
  u_int64_t pulse_clone = 0;
#endif

  bind2core(bind_time_pulse_core);

  while (likely(!g->do_shutdown)) {
    /* clock_gettime takes up to 30 nsec to get the time */
    clock_gettime(CLOCK_REALTIME, &tn);

    ns = ((u_int64_t) ((u_int64_t) tn.tv_sec * 1000000000) + (tn.tv_nsec));

#if 1 /* reduce cache thrashing*/ 
    if(ns >= pulse_clone + g->pulse_timestamp_precision_nsec /* (avoid updating each cycle) */ ) {
#endif
      *g->pulse_timestamp_ns = ((u_int64_t) ((u_int64_t) tn.tv_sec << 32) | tn.tv_nsec);
#if 1
      pulse_clone = ns;
    }
#endif
  }

  return NULL;
}

/* ******************************** */

void print_stats() {
  static u_int8_t print_all = 0;
  static struct timeval lastTime;
  static u_int64_t lastPkts = 0, lastBytes = 0, lastDrops = 0, lastSlavePkts = 0, lastSlaveDrops = 0; 
  unsigned long long nBytes = 0, nPkts = 0, nDrops = 0, nSlavePkts = 0, nSlaveDrops = 0;
  struct timeval endTime;
  char buf1[64], buf2[64], buf3[64], buf4[64], buf5[64];
  pfring_zc_stat stats; 
  int i;  

  if(startTime.tv_sec == 0)
    gettimeofday(&startTime, NULL);
  else
    print_all = 1;

  gettimeofday(&endTime, NULL);

  nPkts  = globals->numPkts;
  nBytes = globals->numBytes;
  if (pfring_zc_stats(inzq, &stats) == 0)
    nDrops = stats.drop;
  nSlavePkts  = globals->sentPkts;
  for (i = 0; i < num_slaves; i++) 
    if (pfring_zc_stats(outzq[i], &stats) == 0) 
      nSlaveDrops += stats.drop; 

  fprintf(stderr, "=========================\n"
	  "Absolute Stats: Recv %s pkts (%s drops) %s bytes - Forwarded %s pkts (%s drops)\n", 
	  pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)nDrops, buf2, sizeof(buf2), 0),
	  pfring_format_numbers((double)nBytes, buf3, sizeof(buf3), 0),
	  pfring_format_numbers((double)nSlavePkts, buf4, sizeof(buf4), 0),
	  pfring_format_numbers((double)nSlaveDrops, buf5, sizeof(buf5), 0));

  if(print_all && lastTime.tv_sec > 0) {
    double deltaMillisec = delta_time(&endTime, &lastTime);
    double bytesDiff = ((double) (nBytes - lastBytes) * 8) / (1000*1000*1000);
    unsigned long long pktsDiff = nPkts-lastPkts;
    unsigned long long dropsDiff = nDrops - lastDrops;
    unsigned long long slavePktsDiff = nSlavePkts - lastSlavePkts;
    unsigned long long slaveDropsDiff = nSlaveDrops - lastSlaveDrops;

    fprintf(stderr,
	     "Actual Stats: Recv %s pps (%s drops) %s Gbps - Forwarded %s pps (%s drops)\n",
	     pfring_format_numbers(((double)pktsDiff/(double)(deltaMillisec/1000)), buf1, sizeof(buf1), 1),
	     pfring_format_numbers(((double)dropsDiff/(double)(deltaMillisec/1000)), buf2, sizeof(buf2), 1),
	     pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)), buf3, sizeof(buf3), 1),
	     pfring_format_numbers(((double)slavePktsDiff/(double)(deltaMillisec/1000)), buf4, sizeof(buf4), 1),
	     pfring_format_numbers(((double)slaveDropsDiff/(double)(deltaMillisec/1000)), buf5, sizeof(buf5), 1));
  }
    
  fprintf(stderr, "=========================\n\n");

  lastPkts = nPkts, lastBytes = nBytes, lastDrops = nDrops;
  lastSlavePkts = nSlavePkts, lastSlaveDrops = nSlaveDrops;
  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  globals->do_shutdown = 1;

  print_stats();
  
  pfring_zc_queue_breakloop(inzq);
}

/* ******************************** */

void printHelp(void) {
  printf("zfanout_ipc - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A master process sending all ingress packets to all the consumer processes (e.g. zcount_ipc -c <cluster id> -i <consumer id>).\n");
  printf("Note: this is an alternative to zbalance -m 2\n\n");
  printf("Usage: zfanout_ipc -i <device> -c <cluster id> -n <num inst>\n"
	 "                [-h] [-q <len>] [-S <core id>] [-g <core id>] [-a]\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-n <num inst>   Number of application instances\n");
  printf("-q <len>        Number of slots in each queue (default: %u)\n", QUEUE_LEN);
  printf("-S <core id>    Enable Time Pulse thread and bind it to a core\n");
  printf("-g <core id>    Bind this app to a core\n");
  printf("-a              Active packet wait\n");
  exit(-1);
}

/* *************************************** */

void *packet_consumer_thread(void *_id) {
  struct volatile_globals *g = globals;
  pfring_zc_queue *_inzq = inzq;
  pfring_zc_queue **_outzq = outzq;
  pfring_zc_multi_queue *_mq = mq;
  pfring_zc_pkt_buff **_ph = ph;
  u_int32_t _num_slaves = num_slaves;
  int i, ns, flush_tx = 0, toprocess = 0;
#ifdef USE_RECV_BURST
  int nr;
#endif

  bind2core(bind_core);

  while(!g->do_shutdown) {

#ifdef USE_RECV_BURST
    if ((nr = pfring_zc_recv_pkt_burst(_inzq, _ph, SWAP_BUFFERS, 0 /* g->wait_for_packet */)) > 0)
#else
    if (pfring_zc_recv_pkt(_inzq, _ph, 0 /* g->wait_for_packet */) > 0)
#endif
    {

#ifdef USE_RECV_BURST
      toprocess = 0;
      while (toprocess < nr) {
#endif
        pfring_zc_pkt_buff **buff_p = &_ph[toprocess];
        pfring_zc_pkt_buff *buff = *buff_p;

        if (g->time_pulse) {
          u_int64_t pulse_timestamp_ns = *g->pulse_timestamp_ns;
          buff->ts.tv_sec = pulse_timestamp_ns >> 32;
          buff->ts.tv_nsec = pulse_timestamp_ns & 0xffffffff;
        }

        g->numPkts++;
        g->numBytes += buff->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */

        ns = pfring_zc_send_pkt_multi(_mq, buff_p, 0xffffffff, 0);

	//drop += _num_slaves - ns;
        g->sentPkts += ns;

#ifdef USE_RECV_BURST
        toprocess++;
      }
#endif
      flush_tx = 1;

    } else {
      if (flush_tx) {
        for (i = 0; i < _num_slaves; i++) 
          pfring_zc_sync_queue(_outzq[i], tx_only);
        flush_tx = 0;
      }

      if (g->wait_for_packet) 
        usleep(1);
    }

  }

  pfring_zc_sync_queue(_inzq, rx_only);
  for (i = 0; i < _num_slaves; i++) 
    pfring_zc_sync_queue(_outzq[i], tx_only);

  return NULL;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c;
  long i;
  int cluster_id = -1;
  pthread_t my_thread, time_thread;
  int wait_for_packet = 1, time_pulse = 0;
  int pulse_timestamp_precision_nsec = PULSE_TS_PRECISION_NSEC;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:g:hi:n:S:q:P:")) != '?') {
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
    case 'n':
      num_slaves = atoi(optarg);
      break;
    case 'q':
      queue_len = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'S':
      time_pulse = 1;
      bind_time_pulse_core = atoi(optarg);
      break;
    case 'P':
      pulse_timestamp_precision_nsec = atoi(optarg);
      break;
    }
  }
  
  if (device == NULL) printHelp();
  if (cluster_id < 0) printHelp();
  if (num_slaves < 1) printHelp();

  bind2node(bind_core);

  /* volatile global variables initialization */
  globals = calloc(1, sizeof(*globals));
  globals->wait_for_packet = wait_for_packet;
  globals->numPkts = 0;
  globals->numBytes = 0;
  globals->sentPkts = 0;
  globals->time_pulse = time_pulse;
  globals->do_shutdown = 0;
  globals->pulse_timestamp_precision_nsec = pulse_timestamp_precision_nsec;

  zc = pfring_zc_create_cluster(
    cluster_id, 
    max_packet_len(device),
    0,
    MAX_CARD_SLOTS + (num_slaves * (queue_len + SLAVE_BUFFERS)) + SWAP_BUFFERS,
    numa_node_of_cpu(bind_core),
    NULL /* auto hugetlb mountpoint */ 
  );

  if(zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
	    strerror(errno));
    return -1;
  }

  outzq = calloc(num_slaves,  sizeof(pfring_zc_queue *));
  pools = calloc(num_slaves,  sizeof(pfring_zc_buffer_pool *));

  for (i = 0; i < SWAP_BUFFERS; i++) {
    ph[i] = pfring_zc_get_packet_handle(zc);

    if (ph[i] == NULL) {
      fprintf(stderr, "pfring_zc_get_packet_handle error\n");
      return -1;
    }
  }

  inzq = pfring_zc_open_device(zc, device, rx_only, 0);

  if(inzq == NULL) {
    fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
            strerror(errno), device);
    return -1;
  }

  for (i = 0; i < num_slaves; i++) { 
    outzq[i] = pfring_zc_create_queue(zc, queue_len);

    if(outzq[i] == NULL) {
      fprintf(stderr, "pfring_zc_create_queue error [%s]\n", strerror(errno));
      return -1;
    }
  }

  for (i = 0; i < num_slaves; i++) { 
    pools[i] = pfring_zc_create_buffer_pool(zc, SLAVE_BUFFERS);

    if (pools[i] == NULL) {
      fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
      return -1;
    }
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  if (globals->time_pulse) {
    globals->pulse_timestamp_ns = calloc(CACHE_LINE_LEN/sizeof(u_int64_t), sizeof(u_int64_t));
    pthread_create(&time_thread, NULL, time_pulse_thread, NULL);
    while (!*globals->pulse_timestamp_ns && !globals->do_shutdown); /* wait for ts */
  }

  printf("Starting fanout for %d slave applications..\n", num_slaves);

  mq = pfring_zc_create_multi_queue(outzq, num_slaves);
 
  if(mq == NULL) {
    fprintf(stderr, "pfring_zc_create_multi_queue error [%s]\n", strerror(errno));
    return -1;
  }

  pthread_create(&my_thread, NULL, packet_consumer_thread, (void*) NULL);

  while (!globals->do_shutdown) {
    sleep(ALARM_SLEEP);
    print_stats();
  }

  pthread_join(my_thread, NULL);

  if (globals->time_pulse)
    pthread_join(time_thread, NULL);

  sleep(1);

  pfring_zc_destroy_cluster(zc);

  return 0;
}

