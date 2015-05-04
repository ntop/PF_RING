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

//#define METADATA_TEST

#define ALARM_SLEEP             1
#define MAX_CARD_SLOTS      32768
#define QUEUE_LEN            8192

pfring_zc_cluster *zc;
pfring_zc_queue **zq;

pfring_zc_pkt_buff **buffers;

u_int32_t num_threads = 0;
int *bind_core = NULL;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
u_int8_t wait_for_packet = 1, flush_packet = 0, do_shutdown = 0;

/* ******************************** */

void print_stats() {
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  static u_int64_t lastBytes = 0;
  double diff, bytesDiff;
  static struct timeval lastTime;
  char buf1[64], buf2[64], buf3[64];
  unsigned long long nBytes = 0, nPkts = 0;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  nBytes = numBytes;
  nPkts = numPkts;

  fprintf(stderr, "=========================\n"
	  "Absolute Stats: %s pkts - %s bytes\n", 
	  pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

  if(print_all && (lastTime.tv_sec > 0)) {
    char buf[256];

    deltaMillisec = delta_time(&endTime, &lastTime);
    diff = nPkts-lastPkts;
    bytesDiff = nBytes - lastBytes;
    bytesDiff /= (1000*1000*1000)/8;

    snprintf(buf, sizeof(buf),
	    "Actual Stats: %s pps - %s Gbps",
	    pfring_format_numbers(((double)diff/(double)(deltaMillisec/1000)), buf2, sizeof(buf2), 1),
	    pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)), buf3, sizeof(buf3), 1));
    fprintf(stderr, "%s\n", buf);
  }
    
  fprintf(stderr, "=========================\n\n");

  lastPkts = nPkts, lastBytes = nBytes;
  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  int i;
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  do_shutdown = 1;

  print_stats();
  
  for (i = 0; i < num_threads; i++)
    pfring_zc_queue_breakloop(zq[i]);
}

/* *************************************** */

void printHelp(void) {
  printf("zpipeline - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A pipeline of threads sending ingress packets to the next thread.\n\n");
  printf("Usage: zpipeline -i <device> -c <cluster id> -g <id:id...>\n"
	 "                [-h] [-a] [-f]\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-g <id:id...>   Threads affinity mask (per pipeline stage)\n");
  printf("-a              Active packet wait\n");
  printf("-f              Flush packets immediately to the next stage (no buffering)\n");
  exit(-1);
}

/* *************************************** */

void *pipeline_stage_thread(void* _id) {
  long id = (long) _id;

  pfring_zc_pkt_buff *b = buffers[id];

  bind2core(bind_core[id]);

  while(!do_shutdown) {

    if(pfring_zc_recv_pkt(zq[id], &b, wait_for_packet) > 0) {

#ifdef METADATA_TEST
      if (id == 0) { /* first pipeline stage */
        static u_int64_t counter = 0;
	u_int64_t *meta_p = (u_int64_t *) b->user;
	*meta_p = counter; 
	counter++;
      }
#endif

      if (id < num_threads-1) { /* send to the next pipeline stage */
        pfring_zc_send_pkt(zq[id+1], &b, flush_packet);
      } else {/* last pipeline stage */

#ifdef METADATA_TEST
	u_int64_t *meta_p = (u_int64_t *) b->user;
	if (*meta_p != numPkts)
	  printf("Buffer Metadata contains unexpected value: %llu != %llu\n", 
	    (long long unsigned) *meta_p, (long long unsigned) numPkts);
#endif

#if 0
        int i;

        for(i = 0; i < b->len; i++)
          printf("%02X ", b->data[i]);
        printf("\n");
#endif

        numPkts++;
        numBytes += b->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */
      }
    }

  }

  if (id < num_threads-1) pfring_zc_sync_queue(zq[id+1], tx_only);
  pfring_zc_sync_queue(zq[id], rx_only);

  return NULL;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c;
  long i;
  int cluster_id = -1;
  char *bind_mask = NULL;
  pthread_t *threads;
  char *id;
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:g:hi:f")) != '?') {
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
      bind_mask = strdup(optarg);
      break;
    case 'f':
      flush_packet = 1;
      break;
    }
  }
  
  if (device == NULL)    printHelp();
  if (cluster_id < 0)    printHelp();
  if (bind_mask == NULL) printHelp();
  id = strtok(bind_mask, ":");
  while(id != NULL) {
    bind_core = realloc(bind_core, sizeof(int) * (num_threads+1));
    bind_core[num_threads] = atoi(id) % numCPU;
    num_threads++;
    id = strtok(NULL, ":");
  }
  if (num_threads < 1) printHelp();

  threads = calloc(num_threads,     sizeof(pthread_t));
  buffers = calloc(num_threads,     sizeof(pfring_zc_pkt_buff *));
  zq =      calloc(num_threads - 1, sizeof(pfring_zc_queue *));

  zc = pfring_zc_create_cluster(
    cluster_id, 
    max_packet_len(device), 
#ifdef METADATA_TEST
    8,
#else
    0,
#endif
    MAX_CARD_SLOTS + (num_threads - 1) * QUEUE_LEN + num_threads, 
    numa_node_of_cpu(bind_core[0]),
    NULL /* auto hugetlb mountpoint */ 
  );

  if(zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
	    strerror(errno));
    return -1;
  }

  for (i = 0; i < num_threads; i++) { 
    buffers[i] = pfring_zc_get_packet_handle(zc);

    if (buffers[i] == NULL) {
      fprintf(stderr, "pfring_zc_get_packet_handle error\n");
      return -1;
    }
  }

  zq[0] = pfring_zc_open_device(zc, device, rx_only, 0);

  if(zq[0] == NULL) {
    fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	    strerror(errno), device);
    return -1;
  }

  for (i = 1; i < num_threads; i++) { 
    zq[i] = pfring_zc_create_queue(zc, QUEUE_LEN);

    if(zq[i] == NULL) {
      fprintf(stderr, "pfring_zc_create_queue error [%s]\n", strerror(errno));
      return -1;
    }
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  printf("Starting pipeline with %d stages..\n", num_threads);

  for (i = 0; i < num_threads; i++)
    pthread_create(&threads[i], NULL, pipeline_stage_thread, (void*) i);

  while (!do_shutdown) {
    sleep(ALARM_SLEEP);
    print_stats();
  }
  
  for (i = 0; i < num_threads; i++)
    pthread_join(threads[i], NULL);

  sleep(1);

  pfring_zc_destroy_cluster(zc);

  return 0;
}

