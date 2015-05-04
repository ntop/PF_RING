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
#define QUEUE_LEN            4096

typedef struct {
  pfring_zc_queue *inzq;
  pfring_zc_queue *outzq;
  pfring_zc_pkt_buff *buffer;
  pthread_t thread;
  int bind_core;
} forwarder_info_t;

/* *************************************** */

pfring_zc_cluster *zc;
pfring_zc_queue **ipczqs;
pfring_zc_buffer_pool **pools;

u_int32_t num_ipc_queues = 1;
int in_queue_id = -1, out_queue_id = -1;
char *in_device = NULL, *out_device = NULL;

#define RX_FWDR 0
#define TX_FWDR 1
forwarder_info_t forwarder[2];

static struct timeval start_time;
u_int8_t wait_for_packet = 1, flush_packet = 0, do_shutdown = 0, enable_vm_support = 0;

/* ******************************** */

void print_stats() {
  static u_int8_t print_all = 0;
  static struct timeval last_time;
  static unsigned long long last_tot_recv = 0, last_tot_queues_recv = 0;
  unsigned long long tot_recv = 0, tot_drop = 0, tot_queues_recv = 0, tot_queues_drop = 0;
  struct timeval end_time;
  char buf1[64], buf2[64];
  pfring_zc_stat stats;
  int i;

  if(start_time.tv_sec == 0)
    gettimeofday(&start_time, NULL);
  else
    print_all = 1;

  gettimeofday(&end_time, NULL);

  fprintf(stderr, "=========================\nAbsolute Stats: ");

  if (in_device != NULL) {
    if (pfring_zc_stats(forwarder[RX_FWDR].inzq, &stats) == 0)
      tot_recv += stats.recv, tot_drop += stats.drop;

    fprintf(stderr, "Recv %s pkts [Drop %s pkts] ", 
      pfring_format_numbers((double)tot_recv, buf1, sizeof(buf1), 0),
      pfring_format_numbers((double)tot_drop, buf2, sizeof(buf2), 0)
    );
  }

  fprintf(stderr, "Processed ");

  for (i = 0; i < num_ipc_queues; i++) {
    if (pfring_zc_stats(ipczqs[i], &stats) == 0) {
      fprintf(stderr, "Q%u %s pkts ", i, pfring_format_numbers((double) stats.recv, buf1, sizeof(buf1), 0));
      tot_queues_recv += stats.recv, tot_queues_drop += stats.drop;
    }
  }

  /* Average */
  tot_queues_recv /= num_ipc_queues;
  tot_queues_drop /= num_ipc_queues;

  fprintf(stderr, "AVG %s pkts [Drop %s pkts]\n", 
    pfring_format_numbers((double)tot_queues_recv, buf1, sizeof(buf1), 0),
    pfring_format_numbers((double)tot_queues_drop, buf2, sizeof(buf2), 0)
  );

  if(print_all && last_time.tv_sec > 0) {
    double delta_msec = delta_time(&end_time, &last_time);
    unsigned long long diff_recv = tot_recv - last_tot_recv;
    unsigned long long diff_queues_recv = tot_queues_recv - last_tot_queues_recv;

    fprintf(stderr, "Actual Stats: Recv %s pps Processed AVG %s pps\n",
      pfring_format_numbers(((double)diff_recv/(double)(delta_msec/1000)), buf1, sizeof(buf1), 1),
      pfring_format_numbers(((double)diff_queues_recv/(double)(delta_msec/1000)), buf2, sizeof(buf2), 1)
    );
  }
  
  fprintf(stderr, "=========================\n\n");
 
  last_tot_recv = tot_recv, last_tot_queues_recv = tot_queues_recv;
  last_time.tv_sec = end_time.tv_sec, last_time.tv_usec = end_time.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  do_shutdown = 1;

  print_stats();

  if (in_device)  pfring_zc_queue_breakloop(forwarder[RX_FWDR].inzq);
  if (out_device) pfring_zc_queue_breakloop(forwarder[TX_FWDR].inzq);
}

/* *************************************** */

void printHelp(void) {
  printf("zpipeline_ipc - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A master process sending packets from a source interface to a sw queue and from a sw queue to a destination interface (first and last stage of a pipeline)\n\n");
  printf("Usage: zpipeline_ipc -i <device>;<queue> -o <device>;<queue> -n <num queues>\n"
         "                    -c <cluster id> [-r <rx thread core>] [-t <tx thread core>]\n"
	 "                    [-h] [-a] [-f] [-Q <sock list>]\n\n");
  printf("-h                  Print this help\n");
  printf("-i <device>;<queue> Ingress device and destination queue\n");
  printf("-o <device>;<queue> Egress device and source queue\n");
  printf("-c <cluster id>     Cluster id\n");
  printf("-n <num queues>     Number of queues\n");
  printf("-r <rx thread core> Bind the rx thread to a core\n");
  printf("-t <tx thread core> Bind the tx thread to a core\n");
  printf("-a                  Active packet wait\n");
  printf("-f                  Flush packets immediately to the destination queue/egress device (no buffering)\n");
  printf("-Q <sock list>      Enable VM support (comma-separated list of QEMU monitor sockets)\n");
  exit(-1);
}

/* *************************************** */

void *forwarder_thread(void *_info) {
  forwarder_info_t *info = (forwarder_info_t *) _info;
  pfring_zc_pkt_buff *b = info->buffer;

  bind2core(info->bind_core);

  while(!do_shutdown)
    if(pfring_zc_recv_pkt(info->inzq, &b, wait_for_packet) > 0)
      while (unlikely(pfring_zc_send_pkt(info->outzq, &b, flush_packet) < 0 && !do_shutdown)) usleep(1);

  pfring_zc_sync_queue(info->outzq, tx_only);
  pfring_zc_sync_queue(info->inzq,  rx_only);

  return NULL;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  char *in_pair = NULL, *out_pair = NULL;
  char *vm_sockets = NULL, *vm_sock; 
  long i;
  int cluster_id = -1;
  int rc;

  start_time.tv_sec = 0;

  while((c = getopt(argc,argv,"ac:fhi:o:n:Q:r:t:")) != '?') {
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
    case 'f':
      flush_packet = 1;
      break;
    case 'n':
      num_ipc_queues = atoi(optarg);
      break;
    case 'i':
      in_pair = strdup(optarg);
      break;
    case 'o':
      out_pair = strdup(optarg);
      break;
    case 'r':
      forwarder[RX_FWDR].bind_core = atoi(optarg);
      break;
    case 't':
      forwarder[TX_FWDR].bind_core = atoi(optarg);
      break;
    case 'Q':
      enable_vm_support = 1;
      vm_sockets = strdup(optarg);
      break;
    }
  }
  
  if (cluster_id < 0) printHelp();
  if (num_ipc_queues < 1) printHelp();

  if (in_pair != NULL) {
    char *q_id = strchr(in_pair, ';');
    if (q_id == NULL) printHelp();
    q_id[0] = '\0'; q_id++;
    in_device = strdup(in_pair);
    in_queue_id = atoi(q_id);
    if (in_queue_id < 0 || in_queue_id >= num_ipc_queues) printHelp();
  }

  if (out_pair != NULL) {
    char *q_id = strchr(out_pair, ';');
    if (q_id == NULL) printHelp();
    q_id[0] = '\0'; q_id++;
    out_device = strdup(out_pair);
    out_queue_id = atoi(q_id);
    if (out_queue_id < 0 || out_queue_id >= num_ipc_queues) printHelp();
  }

  ipczqs = calloc(num_ipc_queues,  sizeof(pfring_zc_queue *));
  pools =  calloc(num_ipc_queues,  sizeof(pfring_zc_buffer_pool *));

  zc = pfring_zc_create_cluster(
    cluster_id, 
    in_device != NULL ? max_packet_len(in_device) : 1536, 
    0,
    (((in_device != NULL) + (out_device != NULL)) * (MAX_CARD_SLOTS + 1)) + (num_ipc_queues * (QUEUE_LEN + 1)), 
    numa_node_of_cpu(forwarder[RX_FWDR].bind_core),
    NULL /* auto hugetlb mountpoint */ 
  );

  if(zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
	    strerror(errno));
    return -1;
  }

  for (i = 0; i < num_ipc_queues; i++) { 
    ipczqs[i] = pfring_zc_create_queue(zc, QUEUE_LEN);

    if(ipczqs[i] == NULL) {
      fprintf(stderr, "pfring_zc_create_queue error [%s]\n", strerror(errno));
      return -1;
    }
  }

  for (i = 0; i < num_ipc_queues; i++) { 
    pools[i] = pfring_zc_create_buffer_pool(zc, 1);

    if (pools[i] == NULL) {
      fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
      return -1;
    }
  }

  if (in_device != NULL) {
    forwarder[RX_FWDR].inzq = pfring_zc_open_device(zc, in_device, rx_only, 0);
    forwarder[RX_FWDR].outzq = ipczqs[in_queue_id];

    if(forwarder[RX_FWDR].inzq == NULL) {
      fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	      strerror(errno), in_device);
      return -1;
    }

    forwarder[RX_FWDR].buffer = pfring_zc_get_packet_handle(zc);

    if (forwarder[RX_FWDR].buffer == NULL) {
      fprintf(stderr, "pfring_zc_get_packet_handle error\n");
      return -1;
    }

    printf("Forwarding from %s to Q%u\n", in_device, in_queue_id);
  }

  if (out_device != NULL) {
    forwarder[TX_FWDR].inzq = ipczqs[out_queue_id];
    forwarder[TX_FWDR].outzq = pfring_zc_open_device(zc, out_device, tx_only, 0);

    if(forwarder[TX_FWDR].outzq == NULL) {
      fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	      strerror(errno), out_device);
      return -1;
    }

    forwarder[TX_FWDR].buffer = pfring_zc_get_packet_handle(zc);

    if (forwarder[TX_FWDR].buffer == NULL) {
      fprintf(stderr, "pfring_zc_get_packet_handle error\n");
      return -1;
    }
    
    printf("Forwarding from Q%u to %s\n", out_queue_id, out_device);
  }

  if (enable_vm_support) {
    vm_sock = strtok(vm_sockets, ",");
    while(vm_sock != NULL) {

      rc = pfring_zc_vm_register(zc, vm_sock);

      if (rc < 0) {
        fprintf(stderr, "pfring_zc_vm_register error\n");
        return -1;
      }

      vm_sock = strtok(NULL, ",");
    }

    rc = pfring_zc_vm_backend_enable(zc);

    if (rc < 0) {
      fprintf(stderr, "pfring_zc_vm_backend_enable error\n");
      return -1;
    }
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  printf("Starting master with %d queues..\n", num_ipc_queues);

  if (out_device != NULL) pthread_create(&forwarder[TX_FWDR].thread, NULL, forwarder_thread, &forwarder[TX_FWDR]);
  if (in_device  != NULL) pthread_create(&forwarder[RX_FWDR].thread, NULL, forwarder_thread, &forwarder[RX_FWDR]);

  while (!do_shutdown) {
    sleep(ALARM_SLEEP);
    print_stats();
  }
  
  if (out_device != NULL) pthread_join(forwarder[TX_FWDR].thread, NULL);
  if (in_device  != NULL) pthread_join(forwarder[RX_FWDR].thread, NULL);

  pfring_zc_destroy_cluster(zc);

  return 0;
}

