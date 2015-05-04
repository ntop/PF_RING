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
#include "pfring_mod_sysdig.h"

#include "zutils.c"

#define ALARM_SLEEP             1

pfring_zc_queue *zq;
pfring_zc_buffer_pool *zp;
pfring_zc_pkt_buff *buffer;

static struct timeval startTime;
int bind_core = -1;
int vm_guest = 0;

struct volatile_globals {
  unsigned long long numPkts;
  unsigned long long numBytes;
  int wait_for_packet;
  u_int8_t verbose, dump_as_sysdig_event;
  volatile int do_shutdown;
};

struct volatile_globals *globals;

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

  nBytes = globals->numBytes;
  nPkts = globals->numPkts;
  if (pfring_zc_stats(zq, &stats) == 0)
    nDrops = stats.drop;
  else
    printf("Error reading drop stats\n");

  fprintf(stderr, "=========================\n"
	  "Absolute Stats: %s pkts (%s drops) - %s bytes\n", 
	  pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)nDrops, buf2, sizeof(buf2), 0),
	  pfring_format_numbers((double)nBytes, buf3, sizeof(buf3), 0));

  if(print_all && (lastTime.tv_sec > 0)) {
    char buf[256];

    deltaMillisec = delta_time(&endTime, &lastTime);
    pktsDiff = nPkts-lastPkts;
    dropsDiff = nDrops-lastDrops;
    bytesDiff = nBytes - lastBytes;
    bytesDiff /= (1000*1000*1000)/8;

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

  globals->do_shutdown = 1;

  print_stats();
  
  pfring_zc_queue_breakloop(zq);
}

/* *************************************** */

void printHelp(void) {
  printf("zcount_ipc - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A simple packet counter application consuming packets from a sw queue.\n\n");
  printf("Usage: zcount_ipc -i <queue id> -c <cluster id>\n"
	 "                [-h] [-g <core id>] [-s] [-v] [-u] [-a]\n\n");
  printf("-h              Print this help\n");
  printf("-i <queue id>   Zero queue id\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-g <core_id>    Bind this app to a core\n");
  printf("-a              Active packet wait\n");
  printf("-v              Verbose: print packet data\n");
  printf("-s              In case of -v dump the buffer as sysdig event instead of packet bytes\n");
  printf("-u              Guest VM (master on the host)\n");
  exit(-1);
}

/* *************************************** */

void *packet_consumer_thread(void *_id) {
  struct volatile_globals *g = globals;

  bind2core(bind_core);

  while(!g->do_shutdown) {

    if(pfring_zc_recv_pkt(zq, &buffer, g->wait_for_packet) > 0) {

      if (unlikely(g->verbose)) {
        u_char *pkt_data = pfring_zc_pkt_buff_data(buffer, zq);

        if (buffer->ts.tv_nsec)
          printf("[%u.%u] ", buffer->ts.tv_sec, buffer->ts.tv_nsec);

	if(g->dump_as_sysdig_event) {
	  struct sysdig_event_header *ev = (struct sysdig_event_header*)pkt_data;

	  printf("[cpu_id=%u][tid=%lu][%u|%s]",
		 buffer->hash, ev->thread_id,
		 ev->event_type, sysdig_event2name(ev->event_type));		 
	} else {
	  int i;

	  for(i = 0; i < buffer->len; i++)
	    printf("%02X ", pkt_data[i]);
	}

        printf("\n");
      }

      g->numPkts++;
      g->numBytes += buffer->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */
    }
  }

   pfring_zc_sync_queue(zq, rx_only);

  return NULL;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  int cluster_id = -1, queue_id = -1;
  pthread_t my_thread;
  int wait_for_packet = 1, verbose = 0, dump_as_sysdig_event = 0;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:g:hi:svu")) != '?') {
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
      queue_id = atoi(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 's':
      dump_as_sysdig_event = 1;
      break;
    case 'v':
      verbose = 1;
      break;
    case 'u':
      vm_guest = 1;
      break;
    }
  }
  
  if (cluster_id < 0) printHelp();
  if (queue_id < 0) printHelp();

  bind2node(bind_core);

  /* volatile global variables initialization */
  globals = calloc(1, sizeof(*globals));
  globals->wait_for_packet = wait_for_packet;
  globals->verbose = verbose;
  globals->dump_as_sysdig_event = dump_as_sysdig_event;
  globals->numPkts = 0;
  globals->numBytes = 0;
  globals->do_shutdown = 0;

  if (vm_guest)
    pfring_zc_vm_guest_init(NULL /* auto */);

  zq = pfring_zc_ipc_attach_queue(cluster_id, queue_id, rx_only);

  if(zq == NULL) {
    fprintf(stderr, "pfring_zc_ipc_attach_queue error [%s] Please check that cluster %d is running\n",
	    strerror(errno), cluster_id);
    return -1;
  }

  zp = pfring_zc_ipc_attach_buffer_pool(cluster_id, queue_id);

  if(zp == NULL) {
    fprintf(stderr, "pfring_zc_ipc_attach_buffer_pool error [%s] Please check that cluster %d is running\n",
	    strerror(errno), cluster_id);
    return -1;
  }

  buffer = pfring_zc_get_packet_handle_from_pool(zp);

  if (buffer == NULL) {
    fprintf(stderr, "pfring_zc_get_packet_handle_from_pool error\n");
    return -1;
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  pthread_create(&my_thread, NULL, packet_consumer_thread, (void*) NULL);

  if (!verbose) while (!globals->do_shutdown) {
    sleep(ALARM_SLEEP);
    print_stats();
  }

  pthread_join(my_thread, NULL);

  sleep(1);

  pfring_zc_release_packet_handle_to_pool(zp, buffer);

  pfring_zc_ipc_detach_queue(zq);
  pfring_zc_ipc_detach_buffer_pool(zp);

  return 0;
}

