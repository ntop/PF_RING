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

pfring_zc_cluster *zc;
pfring_zc_queue *inzq, *outzq;
pfring_zc_buffer_pool *zp;
pfring_zc_pkt_buff *tmpbuff;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
int bind_core = -1;
u_int8_t wait_for_packet = 1, flush_packet = 0, do_shutdown = 0, verbose = 0, vm_guest = 0;

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
	     pfring_format_numbers(((double)diff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1),
	     pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)),  buf3, sizeof(buf3), 1));
    fprintf(stderr, "%s\n", buf);
  }
    
  fprintf(stderr, "=========================\n\n");

  lastPkts = nPkts, lastBytes = nBytes;

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  do_shutdown = 1;

  print_stats();
  
  pfring_zc_queue_breakloop(inzq);
}

/* ******************************** */

void my_sigalarm(int sig) {
  if(do_shutdown) return;

  print_stats();

  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* *************************************** */

void printHelp(void) {
  printf("zbounce_ipc - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A packet forwarder application between sw queues.\n\n");
  printf("Usage: zbounce_ipc -i <queue id> -o <queue id> -c <cluster id>\n"
	 "                [-h] [-g <core id>] [-f] [-u] [-a]\n\n");
  printf("-h              Print this help\n");
  printf("-i <queue id>   Ingress zero queue id\n");
  printf("-o <queue id>   Egress zero queue id\n");
  printf("-c <cluster id> cluster id\n");
  printf("-g <core_id>    Bind this app to a core\n");
  printf("-a              Active packet wait\n");
  printf("-f              Flush packets immediately\n");
  printf("-u              Guest VM (master on the host)\n");
  exit(-1);
}

/* *************************************** */

void *packet_consumer_thread(void *data) {

  if (bind_core >= 0)
    bind2core(bind_core);

  while(!do_shutdown) {

    if(pfring_zc_recv_pkt(inzq, &tmpbuff, wait_for_packet) > 0) {

      if (unlikely(verbose)) {
        char bigbuf[4096];
        pfring_print_pkt(bigbuf, sizeof(bigbuf), pfring_zc_pkt_buff_data(tmpbuff, inzq), tmpbuff->len, tmpbuff->len);
        fputs(bigbuf, stdout);
      }
#if 0
      int i;
      u_char *pkt_data = pfring_zc_pkt_buff_data(tmpbuff, inzq),
      for(i = 0; i < tmpbuff->len; i++)
        printf("%02X ", pkt_data[i]);
      printf("\n");
#endif

      numPkts++;
      numBytes += tmpbuff->len + 24; /* 8 Preamble + 4 CRC + 12 IFG */

      while (unlikely(pfring_zc_send_pkt(outzq, &tmpbuff, flush_packet) < 0 && !do_shutdown))
        usleep(1);
    }

  }

  if (!flush_packet) pfring_zc_sync_queue(outzq, tx_only);
  pfring_zc_sync_queue(inzq, rx_only);

  return NULL;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  int cluster_id = -1, in_queue_id = -1, out_queue_id = -1;
  pthread_t my_thread;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:g:hi:o:fvu")) != '?') {
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
    case 'i':
      in_queue_id = atoi(optarg);
      break;
    case 'o':
      out_queue_id = atoi(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'u':
      vm_guest = 1;
      break;
    }
  }
  
  if (in_queue_id < 0)  printHelp();
  if (out_queue_id < 0) printHelp();
  if (cluster_id < 0)   printHelp();

  if (vm_guest)
    pfring_zc_vm_guest_init(NULL /* auto */);

  inzq = pfring_zc_ipc_attach_queue(cluster_id, in_queue_id, rx_only);

  if(inzq == NULL) {
    fprintf(stderr, "pfring_zc_ipc_attach_queue error [%s] Please check that cluster %d is running\n",
	    strerror(errno), cluster_id);
    return -1;
  }

  outzq = pfring_zc_ipc_attach_queue(cluster_id, out_queue_id, tx_only);

  if(outzq == NULL) {
    fprintf(stderr, "pfring_zc_ipc_attach_queue error [%s] Please check that cluster %d is running\n",
	    strerror(errno), cluster_id);
    return -1;
  }

  zp = pfring_zc_ipc_attach_buffer_pool(cluster_id, in_queue_id);

  if(zp == NULL) {
    fprintf(stderr, "pfring_zc_ipc_attach_buffer_pool error [%s] Please check that cluster %d is running\n",
	    strerror(errno), cluster_id);
    return -1;
  }

  tmpbuff = pfring_zc_get_packet_handle_from_pool(zp);

  if (tmpbuff == NULL) {
    fprintf(stderr, "pfring_zc_get_packet_handle_from_pool error\n");
    return -1;
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  if (!verbose) { /* periodic stats */
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  pthread_create(&my_thread, NULL, packet_consumer_thread, (void*) NULL);
  pthread_join(my_thread, NULL);

  sleep(1);

  pfring_zc_release_packet_handle_to_pool(zp, tmpbuff);

  pfring_zc_ipc_detach_queue(inzq);
  pfring_zc_ipc_detach_queue(outzq);
  pfring_zc_ipc_detach_buffer_pool(zp);

  return 0;
}

