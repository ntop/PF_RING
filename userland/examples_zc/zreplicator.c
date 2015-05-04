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
#define MAX_CARD_SLOTS      32768
#define PREFETCH_BUFFERS        8
#define QUEUE_LEN            8192
#define POOL_SIZE              16
#define CACHE_LINE_LEN         64
#define MAX_NUM_APP	       32

pfring_zc_cluster *zc;
pfring_zc_worker *zw;
pfring_zc_queue **inzqs;
pfring_zc_queue **outzqs;
pfring_zc_multi_queue *outzmq; /* fanout */
pfring_zc_buffer_pool **pools;
pfring_zc_buffer_pool *wsp;

u_int32_t num_in_devices = 0;
char **in_devices = NULL;

u_int32_t num_out_devices = 0;
char **out_devices = NULL;

int cluster_id = -1;
int metadata_len = 0;
int bind_worker_core = -1;
struct timeval start_time;

u_int8_t do_shutdown = 0;


/* ******************************** */

void print_stats() {
  static u_int8_t print_all = 0;
  static struct timeval last_time;
  static unsigned long long last_tot_recv = 0, last_tot_sent = 0, last_tot_drop = 0;
  unsigned long long tot_recv = 0, tot_drop = 0, tot_sent = 0;
  struct timeval end_time;
  char buf1[64], buf2[64], buf3[64];
  pfring_zc_stat stats;
  char stats_buf[1024] = { '\0' };
  int i;
  u_int64_t tot_if_recv = 0, tot_if_drop = 0;

  if(start_time.tv_sec == 0)
    gettimeofday(&start_time, NULL);
  else
    print_all = 1;

  gettimeofday(&end_time, NULL);

  for(i = 0; i < num_in_devices; i++)
    if(pfring_zc_stats(inzqs[i], &stats) == 0)
      tot_recv += stats.recv, tot_drop += stats.drop;

  for(i = 0; i < num_out_devices; i++)
    if(pfring_zc_stats(outzqs[i], &stats) == 0)
      tot_sent += stats.sent;

  fprintf(stderr, "=========================\n"
          "Absolute Stats: Recv %s pkts (%s drops) - Forwarded %s pkts\n",
	  pfring_format_numbers((double)tot_recv, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)tot_drop, buf2, sizeof(buf2), 0),
	  pfring_format_numbers((double)tot_sent, buf3, sizeof(buf3), 0)
	  );


  for(i = 0; i < num_in_devices; i++) {
    if(pfring_zc_stats(inzqs[i], &stats) == 0) {
      tot_if_recv += stats.recv, tot_if_drop += stats.drop;
      fprintf(stderr, "                %s RX %lu pkts Dropped %lu pkts (%.1f %%)\n",
	      in_devices[i], 
	      (long unsigned int)stats.recv,
	      (long unsigned int)stats.drop,
	      stats.recv == 0 ? 0 : ((double)(stats.drop*100)/(double)(stats.recv + stats.drop)));
    }
  }
  snprintf(&stats_buf[strlen(stats_buf)], sizeof(stats_buf)-strlen(stats_buf),
	   "IFPackets:         %lu\n"
	   "tot_if_dropped:         %lu\n",
	   (long unsigned int)tot_if_recv,
	   (long unsigned int)tot_if_drop);

  pfring_zc_set_proc_stats(zc, stats_buf);

  if(print_all && last_time.tv_sec > 0) {
    double delta_msec = delta_time(&end_time, &last_time);
    unsigned long long diff_recv = tot_recv - last_tot_recv;
    unsigned long long diff_drop = tot_drop - last_tot_drop;
    unsigned long long diff_sent = tot_sent - last_tot_sent;

    fprintf(stderr, "Actual Stats: Recv %s pps (%s drops) - Forwarded %s pps\n",
	    pfring_format_numbers(((double)diff_recv/(double)(delta_msec/1000)),  buf1, sizeof(buf1), 1),
	    pfring_format_numbers(((double)diff_drop/(double)(delta_msec/1000)),  buf2, sizeof(buf2), 1),
	    pfring_format_numbers(((double)diff_sent/(double)(delta_msec/1000)),  buf3, sizeof(buf3), 1)
	    );
  }

  fprintf(stderr, "=========================\n\n");

  last_tot_recv = tot_recv, last_tot_drop = tot_drop, last_tot_sent = tot_sent;
  last_time.tv_sec = end_time.tv_sec, last_time.tv_usec = end_time.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  do_shutdown = 1;

  pfring_zc_kill_worker(zw);

  print_stats();
}

/* *************************************** */

void printHelp(void) {
  printf("zreplicator - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("Read packets from multiple ingress devices and replicate it on multipe egress devices.\n\n");
  printf("Usage: zreplicator -i <device> -o <device> -c <cluster id> [-h] [-g <core id>] [-a]\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Ingress devices (comma-separated list)\n");
  printf("-o <device>     Egress devices (comma-separated list)\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-g <core id>    Bind this app to a core\n");
  printf("-a              Active packet wait\n");
  exit(-1);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  char *ingress_devices = NULL, *egress_devices = NULL, *dev;
  long i;
  int  wait_for_packet = 1;

  start_time.tv_sec = 0;

  while((c = getopt(argc,argv, "ac:g:hi:o:")) != '?') {
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
      ingress_devices = strdup(optarg);
      break;
    case 'o':
      egress_devices = strdup(optarg);
      break;
    case 'g':
      bind_worker_core = atoi(optarg);
      break;
    }
  }

  if(cluster_id < 0) printHelp();

  dev = strtok(ingress_devices, ",");
  while(dev != NULL) {
    in_devices = realloc(in_devices, sizeof(char *) * (num_in_devices+1));
    in_devices[num_in_devices] = strdup(dev);
    num_in_devices++;
    dev = strtok(NULL, ",");
  }

  dev = strtok(egress_devices, ",");
  while(dev != NULL) {
    out_devices = realloc(out_devices, sizeof(char *) * (num_out_devices+1));
    out_devices[num_out_devices] = strdup(dev);
    num_out_devices++;
    dev = strtok(NULL, ",");
  }

  if((num_in_devices == 0) || (num_out_devices == 0)) printHelp();

  zc = pfring_zc_create_cluster(cluster_id,
				max_packet_len(in_devices[0]),
				metadata_len,
				((num_in_devices + num_out_devices) * MAX_CARD_SLOTS) + PREFETCH_BUFFERS,
				numa_node_of_cpu(bind_worker_core),
				NULL /* auto hugetlb mountpoint */);
				
  if(zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
	    strerror(errno));
    return -1;
  }

  inzqs  = calloc(num_in_devices, sizeof(pfring_zc_queue *));
  outzqs = calloc(num_out_devices,  sizeof(pfring_zc_queue *));

  for(i = 0; i < num_in_devices; i++) {
    inzqs[i] = pfring_zc_open_device(zc, in_devices[i], rx_only, 0);

    if(inzqs[i] == NULL) {
      fprintf(stderr, "[RX] pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	      strerror(errno), in_devices[i]);
      return -1;
    }
  }

  for(i = 0; i < num_out_devices; i++) {
    outzqs[i] = pfring_zc_open_device(zc, out_devices[i], tx_only, 0);

    if(outzqs[i] == NULL) {
      fprintf(stderr, "[TX] pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	      strerror(errno), out_devices[i]);
      return -1;
    }
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  outzmq = pfring_zc_create_multi_queue(outzqs, num_out_devices);

  if(outzmq == NULL) {
    fprintf(stderr, "pfring_zc_create_multi_queue error [%s]\n", strerror(errno));
    return -1;
  }

  wsp = pfring_zc_create_buffer_pool(zc, PREFETCH_BUFFERS);

  if(wsp == NULL) {
    fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
    return -1;
  }

  zw = pfring_zc_run_fanout(inzqs,
			    outzmq,
			    num_in_devices,
			    wsp,
			    round_robin_bursts_policy,
			    NULL /* idle callback */,
			    NULL /* fanout */,
			    NULL,
			    !wait_for_packet,
			    bind_worker_core);


  if(zw == NULL) {
    fprintf(stderr, "pfring_zc_run_fanout error [%s]\n", strerror(errno));
    return -1;
  }

  while(!do_shutdown) {
    sleep(ALARM_SLEEP);
    print_stats();
  }

  pfring_zc_destroy_cluster(zc);

  return 0;
}

