/*
 * (C) 2021-21 - ntop 
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

#include "pfring.h"
#include "pfring_zc.h"

#include "zutils.c"

#define ALARM_SLEEP             1
#define MAX_CARD_SLOTS      32768
#define CACHE_LINE_LEN         64

static struct timeval startTime;

u_int32_t time_pulse_resolution = 0;
volatile u_int64_t *pulse_timestamp_ns;

u_int64_t delay_nsec = 0;
u_int8_t wait_for_packet = 1;
u_int8_t flush_packet = 0;
u_int8_t do_shutdown = 0;
u_int8_t verbose = 0;
int time_pulse_core = -1;

pfring_zc_cluster *zc;

struct pair_info {
  u_int64_t __rx_padding 
  __attribute__((__aligned__(64)));

  pfring_zc_queue *inzq;
  pfring_zc_pkt_buff *intmpbuff;

  u_int64_t numPkts;
  u_int64_t numBytes;

   u_int64_t __tx_padding 
  __attribute__((__aligned__(64)));
 
  pfring_zc_queue *outzq;
  pfring_zc_pkt_buff *outtmpbuff;

  u_int64_t numFwdPkts;
  u_int64_t numFwdBytes;

   u_int64_t __shared_padding 
  __attribute__((__aligned__(64)));

  pfring_zc_queue *buffzq;

  char *in_dev;
  char *out_dev;

  int rx_core;
  int tx_core;

  pthread_t rx_thread;
  pthread_t tx_thread;
};

struct pair_info pair[1];

/* ******************************** */

#define SET_TS_FROM_PULSE(p, t) { u_int64_t __pts = t; p->ts.tv_sec = __pts >> 32; p->ts.tv_nsec = __pts & 0xffffffff; }
#define SET_TIMEVAL_FROM_PULSE(tv, t) { u_int64_t __pts = t; tv.tv_sec = __pts >> 32; tv.tv_usec = (__pts & 0xffffffff)/1000; }
#define SET_NS_FROM_PULSE(p, t) { u_int64_t __pts = t; p = ((__pts >> 32) * 1000000000) + (__pts & 0xffffffff); }

void *time_pulse_thread(void *data) {
  u_int64_t ns;
  struct timespec tn;
  u_int64_t pulse_clone = 0;

  if (time_pulse_core >= 0)
    bind2core(time_pulse_core);

  while (likely(!do_shutdown)) {
    /* clock_gettime takes up to 30 nsec to get the time */
    clock_gettime(CLOCK_REALTIME, &tn);

    ns = ((u_int64_t) ((u_int64_t) tn.tv_sec * 1000000000) + (tn.tv_nsec));

    if (ns >= pulse_clone + 100 /* nsec precision (avoid updating each cycle to reduce cache thrashing) */ ) {
      *pulse_timestamp_ns = ((u_int64_t) ((u_int64_t) tn.tv_sec << 32) | tn.tv_nsec);
      pulse_clone = ns;
    }

    if (ns < (pulse_clone + time_pulse_resolution) &&
        (pulse_clone + time_pulse_resolution) - ns >= 100000 /* usleep takes ~55 usec */)
      usleep(1); /* optimisation to reduce load */
  }

  return NULL;
}

/* ******************************** */

void print_stats() {
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  static u_int64_t lastBytes = 0;
  static u_int64_t lastDrops = 0;
  double diff, dropsDiff, bytesDiff;
  static struct timeval lastTime;
  char buf1[64], buf2[64], buf3[64];
  unsigned long long nBytes = 0, nPkts = 0, nDrops = 0;
  unsigned long long nFwdBytes = 0, nFwdPkts = 0, nFwdDrops = 0;
  pfring_zc_stat stats;
  int idx = 0;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else {
    print_all = 1;
  }

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  nBytes += pair[idx].numBytes;
  nPkts += pair[idx].numPkts;
  if (pfring_zc_stats(pair[idx].inzq, &stats) == 0)
    nDrops += stats.drop;

  nFwdBytes += pair[idx].numFwdBytes;
  nFwdPkts += pair[idx].numFwdPkts;
  if (pfring_zc_stats(pair[idx].buffzq, &stats) == 0)
    nFwdDrops += stats.drop;

  fprintf(stderr, "=========================\n");

  if(print_all && (lastTime.tv_sec > 0)) {
    deltaMillisec = delta_time(&endTime, &lastTime);
    diff = nPkts-lastPkts;
    dropsDiff = nDrops-lastDrops;
    bytesDiff = nBytes - lastBytes;
    bytesDiff /= (1000*1000*1000)/8;

    fprintf(stderr, "Actual Stats: RX %s pps (%s drops) %s Gbps\n",
	     pfring_format_numbers(((double)diff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1),
	     pfring_format_numbers(((double)dropsDiff/(double)(deltaMillisec/1000)),  buf1, sizeof(buf1), 1),
	     pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)),  buf3, sizeof(buf3), 1));
  }

  fprintf(stderr, "Absolute Stats: RX %s pkts (%s drops) %s bytes\n", 
	  pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)nDrops, buf3, sizeof(buf3), 0),
	  pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

  fprintf(stderr, "Absolute Stats: TX %s pkts (%s drops) %s bytes\n", 
	  pfring_format_numbers((double)nFwdPkts, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)nFwdDrops, buf3, sizeof(buf3), 0),
	  pfring_format_numbers((double)nFwdBytes, buf2, sizeof(buf2), 0));
   
  fprintf(stderr, "=========================\n\n");
  
  lastPkts = nPkts;
  lastDrops = nDrops;
  lastBytes = nBytes;

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  do_shutdown = 1;

  print_stats();
  
  pfring_zc_queue_breakloop(pair[0].inzq);
}

/* *************************************** */

void printHelp(void) {
  printf("zdelay - (C) 2021 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A packet forwarder application between interfaces, adding a configurable delay to forwarded traffic.\n\n");
  printf("Usage:  zdelay -i <device> -o <device> -c <cluster id> -d <delay usec> -s <link speed Mbps>\n\n");
  printf("-i <device>       Ingress device name\n");
  printf("-o <device>       Egress device name\n");
  printf("-c <cluster id>   Cluster ID\n");
  printf("-d <delay>        Delay (usec)\n");
  printf("-s <link speed>   Link speed (or max expected throughput) to optimize the buffer size (Mbps)\n");
  printf("-I <in core>      Bind RX thread to core\n");
  printf("-O <out core>     Bind RX thread to core\n");
  printf("-T <time core>    Bind time thread to core\n");
  printf("-a                Active packet wait to improve latency (higher cpu load)\n");
  printf("-f                Flush packets immediately to improve latency (lower throughput)\n");
  printf("-v                Verbose\n");
  printf("-h                Print this help\n\n");
  printf("Example: zdelay -i zc:eno1 -o zc:eno2 -c 1 -d 100 -s 1000\n");
  exit(-1);
}

/* *************************************** */

void *rx_consumer_thread(void *_i) {
  struct pair_info *i = (struct pair_info *) _i;
  int tx_queue_not_empty = 0;

  if (i->rx_core >= 0)
    bind2core(i->rx_core);

  while (!do_shutdown) {

    if (pfring_zc_recv_pkt(i->inzq, &i->intmpbuff, 0 /* wait_for_packet */) > 0) {

      if (unlikely(verbose)) {
        char strbuf[4096];
        int strlen = sizeof(strbuf);
        int strused = snprintf(strbuf, strlen, "[%s -> buffer]", i->in_dev);
        pfring_print_pkt(&strbuf[strused], strlen - strused, pfring_zc_pkt_buff_data(i->intmpbuff, i->inzq), i->intmpbuff->len, i->intmpbuff->len);
        fputs(strbuf, stdout);
      }

      if (delay_nsec > 0)
        SET_TS_FROM_PULSE(i->intmpbuff, *pulse_timestamp_ns);

      i->numPkts++;
      i->numBytes += i->intmpbuff->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */
      
      errno = 0;
      while (unlikely(pfring_zc_send_pkt(i->buffzq, &i->intmpbuff, flush_packet) < 0 && errno != EMSGSIZE && !do_shutdown))
        if (wait_for_packet) usleep(1);

      tx_queue_not_empty = 1;
    } else {
      if (tx_queue_not_empty) {
        pfring_zc_sync_queue(i->buffzq, tx_only);
        tx_queue_not_empty = 0;
      }
      if (wait_for_packet) 
        usleep(1);
    }

  }

  if (!flush_packet) pfring_zc_sync_queue(i->buffzq, tx_only);
  pfring_zc_sync_queue(i->inzq, rx_only);

  return NULL;
}

/* *************************************** */

void *tx_consumer_thread(void *_i) {
  struct pair_info *i = (struct pair_info *) _i;
  int tx_queue_not_empty = 0;
  u_int64_t ns, now_ns;
#ifdef DEBUG
  int warn_once = 0;
#endif

  if (i->tx_core >= 0)
    bind2core(i->tx_core);

  while (!do_shutdown) {

    if (pfring_zc_recv_pkt(i->buffzq, &i->outtmpbuff, 0 /* wait_for_packet */) > 0) {

      if (unlikely(verbose)) {
        char strbuf[4096];
        int strlen = sizeof(strbuf);
        int strused = snprintf(strbuf, strlen, "[buffer -> %s]", i->out_dev);
        pfring_print_pkt(&strbuf[strused], strlen - strused, pfring_zc_pkt_buff_data(i->outtmpbuff, i->buffzq), i->outtmpbuff->len, i->outtmpbuff->len);
        fputs(strbuf, stdout);
      }

      /* What about checking if the buffer utilization exceeds the max expected size, and skip the delay check? */

      if (delay_nsec > 0) {
        ns = ((u_int64_t) ((u_int64_t) i->outtmpbuff->ts.tv_sec * 1000000000) + (i->outtmpbuff->ts.tv_nsec));

        do {
          SET_NS_FROM_PULSE(now_ns, *pulse_timestamp_ns);

#ifdef DEBUG
          if (!warn_once) {
            fprintf(stderr, "Now: %ju Received at: %ju Delay: %ju\n", now_ns, ns, delay_nsec);
            warn_once = 1;
          }
#endif

          if (now_ns >= (ns + delay_nsec))
            break;

          if (wait_for_packet) usleep(1);
        } while (!do_shutdown);
      }

      errno = 0;
      while (unlikely(pfring_zc_send_pkt(i->outzq, &i->outtmpbuff, flush_packet) < 0 && errno != EMSGSIZE && !do_shutdown))
        if (wait_for_packet) usleep(1);

      i->numFwdPkts++;
      i->numFwdBytes += i->outtmpbuff->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */

      tx_queue_not_empty = 1;
    } else {
      if (tx_queue_not_empty) {
        pfring_zc_sync_queue(i->outzq, tx_only);
        tx_queue_not_empty = 0;
      }
      if (wait_for_packet) 
        usleep(1);
    }

  }

  if (!flush_packet) pfring_zc_sync_queue(i->outzq, tx_only);
  pfring_zc_sync_queue(i->buffzq, rx_only);

  return NULL;
}

/* *************************************** */

int init_pair(struct pair_info *i, char *in_dev, char *out_dev, u_int32_t queue_len) {

  i->in_dev = in_dev;
  i->out_dev = out_dev;

  i->inzq = pfring_zc_open_device(zc, in_dev, rx_only, 0);

  if(i->inzq == NULL) {
    fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
     	    strerror(errno), in_dev);
    return -1;
  }

  i->outzq = pfring_zc_open_device(zc, out_dev, tx_only, 0);

  if(i->outzq == NULL) {
    fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	    strerror(errno), out_dev);
    return -1;
  }

  i->intmpbuff = pfring_zc_get_packet_handle(zc);

  if (i->intmpbuff == NULL) {
    fprintf(stderr, "pfring_zc_get_packet_handle error\n");
    return -1;
  }

  i->outtmpbuff = pfring_zc_get_packet_handle(zc);

  if (i->outtmpbuff == NULL) {
    fprintf(stderr, "pfring_zc_get_packet_handle error\n");
    return -1;
  }
  
  i->buffzq = pfring_zc_create_queue(zc, queue_len);

  if (i->buffzq == NULL) {
    fprintf(stderr, "pfring_zc_create_queue(%u) error [%s]\n",
            queue_len, strerror(errno));
    return -1;
  }

  return 0;
}

/* *************************************** */
  
u_int64_t compute_buffer_size(u_int32_t delay_usec, u_int64_t link_speed) {
  u_int64_t max_pps = link_speed / ((60+24) * 8);
  double max_ppus = (double) max_pps / 1000000;
  double max_buff_packets = max_ppus * delay_usec;

  printf("Link speed: %.3f Gbps\n", (double) link_speed/1000000000);
  printf("Max packets/sec: %.3f Mpps\n", (double) max_pps/1000000);
  printf("Max buffered packets: %lu\n", (u_int64_t) max_buff_packets);

  return (u_int64_t) max_buff_packets + 512 /* add some margin to handle queue watermark and bursts */;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device1 = NULL, *device2 = NULL;
  char c;
  int cluster_id = DEFAULT_CLUSTER_ID+9;
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  pthread_t time_thread;
  u_int32_t queue_len = 0;
  u_int64_t link_speed_bps = 0;

  pair[0].rx_core = pair[0].tx_core = -1;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:d:I:O:T:hi:o:fs:v")) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'f':
      flush_packet = 1;
      break;
    case 'v':
      verbose = 1;
      break;
    case 'c':
      cluster_id = atoi(optarg);
      break;
    case 'd':
      delay_nsec = (u_int64_t) atoi(optarg) * 1000;
      break;
    case 'i':
      device1 = strdup(optarg);
      break;
    case 'o':
      device2 = strdup(optarg);
      break;
    case 'I':
      pair[0].rx_core = atoi(optarg) % numCPU;
      break;
    case 'O':
      pair[0].tx_core = atoi(optarg) % numCPU;
      break;
    case 't':
      time_pulse_core = atoi(optarg) % numCPU;
      break;
    case 's':
      link_speed_bps = (u_int64_t) atoi(optarg) * 1000000;
      break;
    }
  }
  
  if (device1 == NULL || 
      device2 == NULL ||
      link_speed_bps == 0 ||
      cluster_id < 0)  printHelp();

  pulse_timestamp_ns = calloc(CACHE_LINE_LEN/sizeof(u_int64_t), sizeof(u_int64_t));

  queue_len = compute_buffer_size(delay_nsec/1000, link_speed_bps);

  zc = pfring_zc_create_cluster(
    cluster_id, 
    max_packet_len(device1), 
    0, 
    MAX_CARD_SLOTS + 1 + /* RX */
    queue_len + 1 + /* Buffer */
    MAX_CARD_SLOTS, /* TX */
    pfring_zc_numa_get_cpu_node(pair[0].rx_core), 
    NULL /* auto hugetlb mountpoint */,
    0
  );

  if(zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
	    strerror(errno));
    return -1;
  }

  if (init_pair(&pair[0], device1, device2, queue_len) < 0) 
    return -1;

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  printf("Starting packet forwarding..\n");

  pthread_create(&time_thread, NULL, time_pulse_thread, NULL);
  while (!*pulse_timestamp_ns && !do_shutdown); /* wait for ts */

  pthread_create(&pair[0].tx_thread, NULL, tx_consumer_thread, (void *) &pair[0]);
  pthread_create(&pair[0].rx_thread, NULL, rx_consumer_thread, (void *) &pair[0]);

  if (!verbose) while (!do_shutdown) {
    sleep(ALARM_SLEEP);
    print_stats();
  }

  pthread_join(pair[0].rx_thread, NULL);
  pthread_join(pair[0].tx_thread, NULL);
  pthread_join(time_thread, NULL);

  sleep(1);

  pfring_zc_destroy_cluster(zc);

  return 0;
}

