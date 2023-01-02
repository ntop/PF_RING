/*
 * (C) 2021 - ntop 
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
#include "pfring_mod_sysdig.h"

#include "zutils.c"

#define ALARM_SLEEP              1
#define MAX_CARD_SLOTS       32768
#define PREFETCH_BUFFERS         8
#define QUEUE_LEN             8192
#define POOL_SIZE               16
#define CACHE_LINE_LEN          64
#define MAX_NUM_THREADS	        32
#define IN_POOL_SIZE           256

pfring_zc_cluster *zc;
pfring_zc_worker *tzw[MAX_NUM_THREADS];
pfring_zc_worker *zw;
pfring_zc_queue *inzqs[MAX_NUM_THREADS];
pfring_zc_queue *inoutzqs[MAX_NUM_THREADS];
pfring_zc_queue **outzqs;
pfring_zc_multi_queue *moutzqs; /* fanout */
pfring_zc_buffer_pool *wsp;
pfring_zc_buffer_pool *twsp[MAX_NUM_THREADS];

pfring_zc_worker *zfifo;
pfring_zc_queue *sortedzq;
pfring_zc_buffer_pool *fifosp;

u_int32_t num_consumer_queues = 0;
u_int32_t queue_len = QUEUE_LEN;

u_int32_t num_threads = 0;
char *thread_device[MAX_NUM_THREADS] = { NULL };

int cluster_id = DEFAULT_CLUSTER_ID;
int metadata_len = 0;

int bind_collector_core = -1;
int bind_filtering_core[MAX_NUM_THREADS] = { -1 };
int bind_time_pulse_core = -1;

volatile u_int64_t *pulse_timestamp_ns;

static struct timeval start_time;
u_int8_t wait_for_packet = 1, enable_vm_support = 0, time_pulse = 0, print_interface_stats = 0, daemon_mode = 0;
volatile u_int8_t do_shutdown = 0;

u_int64_t tx_pkts_sent = 0;
u_int64_t tx_pkts_attempted = 0;

/* ******************************** */

#define SET_TS_FROM_PULSE(p, t) { u_int64_t __pts = t; p->ts.tv_sec = __pts >> 32; p->ts.tv_nsec = __pts & 0xffffffff; }

void *time_pulse_thread(void *data) {
  u_int64_t ns;
  struct timespec tn;
#if 1
  u_int64_t pulse_clone = 0;
#endif

  bind2core(bind_time_pulse_core);

  while (likely(!do_shutdown)) {
    /* clock_gettime takes up to 30 nsec to get the time */
    clock_gettime(CLOCK_REALTIME, &tn);

    ns = ((u_int64_t) ((u_int64_t) tn.tv_sec * 1000000000) + (tn.tv_nsec));

#if 1 /* reduce cache thrashing*/ 
    if(ns >= pulse_clone + 100 /* nsec precision (avoid updating each cycle) */ ) {
#endif
      *pulse_timestamp_ns = ((u_int64_t) ((u_int64_t) tn.tv_sec << 32) | tn.tv_nsec);
#if 1
      pulse_clone = ns;
    }
#endif
  }

  return NULL;
}

/* *************************************** */

int64_t filtering_func(pfring_zc_pkt_buff *pkt_handle, pfring_zc_queue *in_queue, void *user) {
  /* TODO check filter and return 0 to discard */
  pkt_handle->hash = 0xffff; /* and to all consumers */
  return 1;
}

/* ******************************** */

void *capture_filter_forward(void *data) {
  long i = (long) data;
  int to_flush = 0;
  pfring_zc_pkt_buff *pkt_handle;

  bind2core(bind_filtering_core[i]);

  pkt_handle = pfring_zc_get_packet_handle_from_pool(twsp[i]);

  while (likely(!do_shutdown)) {
    if (pfring_zc_recv_pkt(inzqs[i], &pkt_handle, wait_for_packet) > 0) {
      if (filtering_func(pkt_handle, inzqs[i], NULL)) {
        if (time_pulse) SET_TS_FROM_PULSE(pkt_handle, *pulse_timestamp_ns);
        pfring_zc_send_pkt(inoutzqs[i], &pkt_handle, 0);
        to_flush = 1;
      }
    } else {
      if (to_flush) {
        pfring_zc_sync_queue(inoutzqs[i], tx_only);
        to_flush = 0;
      }
      usleep(1);
    }
  }

  pfring_zc_sync_queue(inoutzqs[i], tx_only);
  pfring_zc_sync_queue(inzqs[i],    rx_only);

  return NULL;
}

/* ******************************** */

void *collect_forward(void *data) {
  int i, nr;
  int to_flush = 0;
  pfring_zc_pkt_buff *buffers[PREFETCH_BUFFERS];

  bind2core(bind_collector_core);

  for (i = 0; i < PREFETCH_BUFFERS; i++)
    buffers[i] = pfring_zc_get_packet_handle_from_pool(wsp);

  while (likely(!do_shutdown)) {
    u_int tot_rx = 0, num_tx = 0;

    for (i = 0; i < num_threads; i++) {

      nr = pfring_zc_recv_pkt_burst(inoutzqs[i], buffers, PREFETCH_BUFFERS, 0 /* don't wait */);

      if (nr > 0) {
        u_int num_pkts_to_process = 0;

        while(num_pkts_to_process < nr) {
          pfring_zc_pkt_buff **buff_p = &buffers[num_pkts_to_process];
          pfring_zc_pkt_buff *buff    = *buff_p;	  
          u_int64_t egress_mask       = (u_int64_t) buff->hash;
	  
          num_tx += pfring_zc_send_pkt_multi(moutzqs, buff_p, egress_mask, 0);
	
          num_pkts_to_process++;
        }
	
        tot_rx += nr;

        tx_pkts_sent += num_tx;
        tx_pkts_attempted += nr;;
      }
    }

    if (tot_rx == 0) {
      if (to_flush) {
#if 0
	for (u_int i = 0; i < num_consumers; i++)
          pfring_zc_sync_queue(outzqs[i], tx_only);
#endif
	to_flush = 0;
      }
      usleep(1);
    } else {
      to_flush = 1;
    }
  }

  return NULL;
}

/* ******************************** */


void print_stats() {
  static u_int8_t print_all = 0;
  static struct timeval last_time;
  static unsigned long long last_tot_recv = 0, last_tot_slave_recv = 0;
  static unsigned long long last_tot_drop = 0, last_tot_slave_drop = 0;
  unsigned long long tot_recv = 0, tot_drop = 0, tot_slave_recv = 0, tot_slave_drop = 0;
  struct timeval end_time;
  char buf1[64], buf2[64], buf3[64], buf4[64];
  pfring_zc_stat stats;
  char stats_buf[1024];
  char time_buf[128];
  double duration;
  int i;

  if(start_time.tv_sec == 0)
    gettimeofday(&start_time, NULL);
  else
    print_all = 1;

  gettimeofday(&end_time, NULL);

  duration = delta_time(&end_time, &start_time);

  for (i = 0; i < num_threads; i++)
    if (pfring_zc_stats(inzqs[i], &stats) == 0)
      tot_recv += stats.recv, tot_drop += stats.drop;

  for (i = 0; i < num_consumer_queues; i++)
    if (pfring_zc_stats(outzqs[i], &stats) == 0)
      tot_slave_recv += stats.recv, tot_slave_drop += stats.drop;

  if (!daemon_mode) {
    fprintf(stderr, "=========================\n"
            "Absolute Stats: Recv %s pkts (%s drops) - Forwarded %s pkts (%s drops)\n", 
            pfring_format_numbers((double)tot_recv, buf1, sizeof(buf1), 0),
	    pfring_format_numbers((double)tot_drop, buf2, sizeof(buf2), 0),
	    pfring_format_numbers((double)tot_slave_recv, buf3, sizeof(buf3), 0),
	    pfring_format_numbers((double)tot_slave_drop, buf4, sizeof(buf4), 0)
    );

    fprintf(stderr, "MQ Stats: Sent %s pkts - Attempted %s pkts\n",
            pfring_format_numbers((double) tx_pkts_sent,      buf1, sizeof(buf1), 0),
            pfring_format_numbers((double) tx_pkts_attempted, buf2, sizeof(buf2), 0));
  }

  snprintf(stats_buf, sizeof(stats_buf), 
           "ClusterId:         %d\n"
           "TotQueues:         %d\n",
           cluster_id,
           num_consumer_queues);

  snprintf(&stats_buf[strlen(stats_buf)], sizeof(stats_buf)-strlen(stats_buf), 
           "ConsumerQueues:        %d\n", 
           num_consumer_queues);

  snprintf(&stats_buf[strlen(stats_buf)], sizeof(stats_buf)-strlen(stats_buf),
           "Duration:          %s\n"
  	   "Packets:           %lu\n"
	   "Processed:         %lu\n",
           msec2dhmsm(duration, time_buf, sizeof(time_buf)),
	   (long unsigned int)tot_recv,
	   (long unsigned int)tot_slave_recv);

  if (print_interface_stats) {
    int i;
    u_int64_t tot_if_recv = 0, tot_if_drop = 0;
    for (i = 0; i < num_threads; i++) {
      if (pfring_zc_stats(inzqs[i], &stats) == 0) {
        tot_if_recv += stats.recv;
        tot_if_drop += stats.drop;
        if (!daemon_mode) {
          fprintf(stderr, "                %s RX %lu pkts Dropped %lu pkts (%.1f %%)\n", 
                  thread_device[i], stats.recv, stats.drop, 
                  stats.recv == 0 ? 0 : ((double)(stats.drop*100)/(double)(stats.recv + stats.drop)));
        }
      }
    }
    snprintf(&stats_buf[strlen(stats_buf)], sizeof(stats_buf)-strlen(stats_buf),
             "IFPackets:         %lu\n"
  	     "IFDropped:         %lu\n",
	     (long unsigned int)tot_if_recv, 
	     (long unsigned int)tot_if_drop);
  }

  pfring_zc_set_proc_stats(zc, stats_buf);

  if(print_all && last_time.tv_sec > 0) {
    double delta_msec = delta_time(&end_time, &last_time);
    unsigned long long diff_recv = tot_recv - last_tot_recv;
    unsigned long long diff_drop = tot_drop - last_tot_drop;
    unsigned long long diff_slave_recv = tot_slave_recv - last_tot_slave_recv;
    unsigned long long diff_slave_drop = tot_slave_drop - last_tot_slave_drop;

    if (!daemon_mode) {
      fprintf(stderr, "Actual Stats: Recv %s pps (%s drops) - Forwarded %s pps (%s drops)\n",
	      pfring_format_numbers(((double)diff_recv/(double)(delta_msec/1000)),  buf1, sizeof(buf1), 1),
	      pfring_format_numbers(((double)diff_drop/(double)(delta_msec/1000)),  buf2, sizeof(buf2), 1),
	      pfring_format_numbers(((double)diff_slave_recv/(double)(delta_msec/1000)),  buf3, sizeof(buf3), 1),
	      pfring_format_numbers(((double)diff_slave_drop/(double)(delta_msec/1000)),  buf4, sizeof(buf4), 1)
      );
    }
  }
  
  if (!daemon_mode) fprintf(stderr, "=========================\n\n");
 
  last_tot_recv = tot_recv, last_tot_slave_recv = tot_slave_recv;
  last_tot_drop = tot_drop, last_tot_slave_drop = tot_slave_drop;
  last_time.tv_sec = end_time.tv_sec, last_time.tv_usec = end_time.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  int i;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  for (i = 0; i < num_threads; i++)
    pfring_zc_kill_worker(tzw[i]);
  pfring_zc_kill_worker(zw);

  do_shutdown = 1;

  print_stats();
}

/* *************************************** */

void printHelp(void) {
  printf("zfilter_mq_ipc - (C) 2021 ntop\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A master process filtering packets using multiple threads, one per ingress interface,\n");
  printf("and forwarding to multiple consumer processes (round-robin or fanout).\n\n");
  printf("ethX - (Filtering Thread 0) \\                     / (Consumer Process 0) \n");
  printf("                               (Collector Thread) - (Consumer Process 1) \n");
  printf("ethY - (Filtering Thread 1) /                     \\ (Consumer Process 2) \n\n");
  printf("Usage: zfilter_mt_ipc -i <device> -c <cluster id> -n <num inst>\n"
	 "                [-h] [-S <core id>] [-g <core_id>]\n"
	 "                [-N <num>] [-a] [-q <len>] [-Q <sock list>] [-d] \n"
	 "                [-D <username>] [-P <pid file>] \n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device (use multiple -i <devices> to create multiple filtering threads)\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-n <num inst>   Number of IPC consumer processes\n");
  printf("-S <core id>    Enable Time Pulse thread and bind it to a core\n");
  printf("-r <id>         Bind the collector thread to a core\n");
  printf("-g <id>:<id>:.. Bind the filtering threads to a cores\n");
  printf("-q <len>        Number of slots in each queue (default: %u)\n", QUEUE_LEN);
  printf("-a              Active packet wait\n");
  printf("-Q <sock list>  Enable VM support (comma-separated list of QEMU monitor sockets)\n");
  printf("-p              Print per-interface absolute stats\n");
  printf("-d              Daemon mode\n");
  printf("-D <username>   Drop privileges\n");
  printf("-P <pid file>   Write pid to the specified file (daemon mode only)\n");
  exit(-1);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  char *id; 
  char *vm_sockets = NULL, *vm_sock; 
  long i;
  int rc;
  char *pid_file = NULL;
  int opt_argc;
  char **opt_argv;
  char *bind_tworker_mask = NULL;
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  char *user = NULL;
  u_int32_t flags;
  pthread_t time_thread;
  pthread_t filtering_thread[MAX_NUM_THREADS];
  pthread_t collector_thread;
  int buffer_size, tot_buffers;

  start_time.tv_sec = 0;

  if ((argc == 2) && (argv[1][0] != '-')) {
    if (load_args_from_file(argv[1], &opt_argc, &opt_argv) != 0) {
      fprintf(stderr, "Unable to read config file %s\n", argv[1]);
      exit(-1);
    }
  } else {
    opt_argc = argc;
    opt_argv = argv;
  }

  while((c = getopt(opt_argc, opt_argv,"ac:dD:g:hi:n:pQ:q:r:P:S:")) != '?') {
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
    case 'd':
      daemon_mode = 1;
      break;
    case 'D':
      user = strdup(optarg);
      break;
    case 'n':
      num_consumer_queues = atoi(optarg);
      break;
    case 'i':
      thread_device[num_threads] = strdup(optarg);
      num_threads++;
      break;
    case 'g':
      bind_tworker_mask = strdup(optarg);
      break;
    case 'r':
      bind_collector_core = atoi(optarg) % numCPU;
      break;
    case 'p':
      print_interface_stats = 1;
      break;
    case 'Q':
      enable_vm_support = 1;
      vm_sockets = strdup(optarg);
      break;
    case 'q':
      queue_len = upper_power_of_2(atoi(optarg));
      break;
    case 'P':
      pid_file = strdup(optarg);
      break;
    case 'S':
      time_pulse = 1;
      bind_time_pulse_core = atoi(optarg);
      break;
    }
  }
  
  if (num_threads == 0) printHelp();
  if (cluster_id < 0) printHelp();
  if (num_consumer_queues == 0) printHelp();

  if (bind_tworker_mask) {
    i = 0;
    id = strtok(bind_tworker_mask, ":");
    while (id != NULL) {
      bind_filtering_core[i] = atoi(id) % numCPU;
      i++;
      id = strtok(NULL, ":");
    }
  }

  if (daemon_mode)
    daemonize();

  flags = 0;

  if (enable_vm_support)
    flags |= PF_RING_ZC_ENABLE_VM_SUPPORT;

  tot_buffers = 
    (num_threads * MAX_CARD_SLOTS) + 
    (num_threads * (queue_len + PREFETCH_BUFFERS)) + 
    PREFETCH_BUFFERS +
    (num_consumer_queues * (queue_len + POOL_SIZE));

  buffer_size = max_packet_len(thread_device[0]);

  zc = pfring_zc_create_cluster(
    cluster_id, 
    buffer_size,
    metadata_len,
    tot_buffers,
    pfring_zc_numa_get_cpu_node(bind_collector_core),
    NULL /* auto hugetlb mountpoint */,
    flags
  );

  if (zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster(buffers=%u, size=%u) error [%s] Please check your hugetlb configuration\n",
            tot_buffers, buffer_size, strerror(errno));
    return -1;
  }

  outzqs = calloc(num_consumer_queues,  sizeof(pfring_zc_queue *));

  for (i = 0; i < num_consumer_queues; i++) { 
    outzqs[i] = pfring_zc_create_queue(zc, queue_len);

    if(outzqs[i] == NULL) {
      fprintf(stderr, "pfring_zc_create_queue error [%s]\n", strerror(errno));
      return -1;
    }

    if (pfring_zc_create_buffer_pool(zc, POOL_SIZE) == NULL) {
      fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
      return -1;
    }
  }

  moutzqs = pfring_zc_create_multi_queue(outzqs, num_consumer_queues);

  if (moutzqs == NULL) {
    fprintf(stderr, "pfring_zc_create_multi_queue error [%s]\n", strerror(errno));
    return -1;
  }

  for (i = 0; i < num_threads; i++) {

    inzqs[i] = pfring_zc_open_device(zc, thread_device[i], rx_only, 0);

    if (inzqs[i] == NULL) {
      fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
              strerror(errno), thread_device[i]);
      return -1;
    }

    inoutzqs[i] = pfring_zc_create_queue(zc, queue_len);

    if (inoutzqs[i] == NULL) {
      fprintf(stderr, "pfring_zc_create_queue error [%s]\n", strerror(errno));                                             
      return -1;
    }

    twsp[i] = pfring_zc_create_buffer_pool(zc, PREFETCH_BUFFERS);

    if (twsp[i] == NULL) {
      fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
      return -1;
    }
  }

  wsp = pfring_zc_create_buffer_pool(zc, PREFETCH_BUFFERS);

  if (wsp == NULL) {
    fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
    return -1;
  }

  if (enable_vm_support) {
    vm_sock = strtok(vm_sockets, ",");
    while (vm_sock != NULL) {

      rc = pfring_zc_vm_register(zc, vm_sock);

      if (rc < 0) {
        fprintf(stderr, "pfring_zc_vm_register(%s) error\n", vm_sock);
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

  if (pid_file)
    create_pid_file(pid_file);

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  if (time_pulse) {
    pulse_timestamp_ns = calloc(CACHE_LINE_LEN/sizeof(u_int64_t), sizeof(u_int64_t));
    pthread_create(&time_thread, NULL, time_pulse_thread, NULL);
    while (!*pulse_timestamp_ns && !do_shutdown); /* wait for ts */
  }

  printf("Starting %d filtering threads, 1 collector thread, %d consumer queues..\n", num_threads, num_consumer_queues);

  printf("Run your consumers as follows:\n");
  for (i = 0; i < num_consumer_queues; i++)
    printf("\tpfcount -i zc:%d@%lu\n", cluster_id, i);

  pthread_create(&collector_thread, NULL, collect_forward, NULL);

  for (i = 0; i < num_threads; i++)
    pthread_create(&filtering_thread[i], NULL, capture_filter_forward, (void *) i);

  if (user != NULL) {
    if (drop_privileges(user) == 0)
      trace(TRACE_NORMAL, "User changed to %s", user);
    else
      trace(TRACE_ERROR, "Unable to drop privileges");
  }

  while (!do_shutdown) {
    sleep(ALARM_SLEEP);
    print_stats();
  }

  for (i = 0; i < num_threads; i++)
    pthread_join(filtering_thread[i], NULL);

  pthread_join(collector_thread, NULL);

  if (time_pulse)
    pthread_join(time_thread, NULL);

  pfring_zc_destroy_cluster(zc);

  if(pid_file)
    remove_pid_file(pid_file);

  return 0;
}

