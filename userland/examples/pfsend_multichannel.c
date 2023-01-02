/*
 * (C) 2003-23 - ntop 
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
#include <poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pfring.h"

#include "pfutils.c"

#define ALARM_SLEEP             1
#define DEFAULT_SNAPLEN       128
#define MAX_NUM_THREADS        64

struct thread_stats {
  u_int64_t __padding_0[8];

  u_int64_t numPkts;
  u_int64_t numBytes;

  pfring *ring;
  pthread_t pd_thread;
  int core_affinity;

  volatile u_int64_t do_shutdown;

  u_int64_t __padding_1[3];
};

struct packet *pkt_head = NULL;

int verbose = 0, num_channels = 1;
int send_len = DEFAULT_SNAPLEN;
u_int ip_v = 4;

struct timeval startTime;
u_int8_t do_shutdown = 0;
u_int numCPU;

struct thread_stats *threads;

#define DEFAULT_DEVICE     "eth0"

/* ******************************** */

void print_stats() {
  struct timeval endTime;
  double delta_abs;
  static u_int64_t lastPkts[MAX_NUM_THREADS] = { 0 };
  u_int64_t diff;
  static struct timeval lastTime;
  int i;
  unsigned long long bytes_sent = 0, pkt_sent = 0;
  unsigned long long pkt_sent_last = 0;
  double pkt_thpt = 0, tot_thpt = 0, delta_last;
  char buf1[64];

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    return;
  }

  gettimeofday(&endTime, NULL);
  delta_abs = delta_time(&endTime, &startTime);
  delta_last = delta_time(&endTime, &lastTime);

  for(i=0; i < num_channels; i++) {
    bytes_sent += threads[i].numBytes, pkt_sent += threads[i].numPkts;
    double thpt = ((double)8*threads[i].numBytes)/(delta_abs*1000);

    fprintf(stderr, "=========================\n"
            "Absolute Stats: [channel=%d][%u pkts][%s pps][%.2f Mbit/sec]\n",
	    i, (unsigned int)threads[i].numPkts,
            pfring_format_numbers((double)(threads[i].numPkts*1000)/delta_abs, buf1, sizeof(buf1), 1),
            thpt);

    if(lastTime.tv_sec > 0) {
      double pps;
	
      diff = threads[i].numPkts-lastPkts[i];
      pkt_sent_last += diff;
      tot_thpt += thpt;
      pps = ((double)diff/(double)(delta_last/1000));
      fprintf(stderr, "Actual Stats:   [channel=%d][%llu pkts][%.1f ms][%s pps]\n",
	      i, (long long unsigned int)diff, delta_last,
	      pfring_format_numbers(((double)diff/(double)(delta_last/1000)), buf1, sizeof(buf1), 1));
      pkt_thpt += pps;
    }

    lastPkts[i] = threads[i].numPkts;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n");
  fprintf(stderr, "Aggregate stats (all channels): [%llu pkts][%s pps][%.2f Mbit/sec]\n", 
          pkt_sent,
	  pfring_format_numbers((double)(pkt_sent_last*1000)/(double)delta_last, buf1, sizeof(buf1), 1),
          tot_thpt);
  fprintf(stderr, "=========================\n\n");
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  int i;

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();

  for(i=0; i<num_channels; i++) {
    threads[i].do_shutdown = 1;
    fprintf(stderr, "Shutting down socket %d\n", i);
    pfring_shutdown(threads[i].ring);
  }
}

/* ******************************** */

void my_sigalarm(int sig) {
  if (do_shutdown)
    return;
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* *************************************** */

void printHelp(void) {
  printf("pfcount_multichannel\n(C) 2005-23 ntop\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name (No device@channel)\n");
  printf("-l <len>        Packet length\n");
  printf("-b <num>        Reforge source IP with <num> different IPs (balanced traffic)\n");
  printf("-S <ip>         Use <ip> as base source IP for -b (default: 10.0.0.1)\n");
  printf("-D <ip>         Use <ip> as destination IP (default: 192.168.0.1)\n");
  printf("-g <id:id...>   Specifies the thread affinity mask. Each <id> represents\n"
	 "                the core id where the i-th will bind. Example: -g 7:6:5:4\n"
	 "                binds thread <device>@0 on coreId 7, <device>@1 on coreId 6\n"
	 "                and so on.\n");
  printf("-v              Verbose\n");
}

/* ****************************************************** */

struct packet *build_traffic(int num_uniq_pkts) {
  struct packet *p = NULL, *last = NULL, *first = NULL;
  u_char buffer[MAX_PACKET_SIZE];
  int i;

  for (i = 0; i < num_uniq_pkts; i++) {

    forge_udp_packet(buffer, send_len, i, (ip_v != 4 && ip_v != 6) ? (i&0x1 ? 6 : 4) : ip_v);

    p = (struct packet *) malloc(sizeof(struct packet));

    if (p == NULL) { 
      fprintf(stderr, "Unable to allocate memory requested (%s)\n", strerror(errno));
      return NULL;
    }

    if (i == 0) first = p;

    p->id = i;
    p->len = send_len;
    p->ticks_from_beginning = 0;
    p->next = first;
    p->pkt = (u_char *) malloc(p->len);

    if (p->pkt == NULL) {
      fprintf(stderr, "Unable to allocate memory requested (%s)\n", strerror(errno));
      return NULL;
    }

    memcpy(p->pkt, buffer, send_len);

    if (last != NULL) last->next = p;
    last = p;
  }

  return first;
}

/* ****************************************************** */

void* packet_consumer_thread(void* _id) {
  long thread_id = (long)_id;
  struct thread_stats *t = &threads[thread_id];
  struct packet *tosend;
  int send_error_once = 1;
  int flush = 0;
  int rc;

#ifdef HAVE_PTHREAD_SETAFFINITY_NP
  if(numCPU > 1) {
    /* Bind this thread to a specific core */
    cpu_set_t cpuset;
    u_long core_id;
    int s;

    if (t->core_affinity != -1)
      core_id = t->core_affinity % numCPU;
    else
      core_id = (thread_id + 1) % numCPU;

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0)
      fprintf(stderr, "Error while binding thread %ld to core %ld: errno=%i\n", 
              thread_id, core_id, s);
    else {
      printf("Set thread %lu on core %lu/%u\n", thread_id, core_id, numCPU);
    }
  }
#endif

  tosend = pkt_head;

  while(!do_shutdown) {

    rc = pfring_send(t->ring, (char *) tosend->pkt, tosend->len, flush);

    if (unlikely(verbose))
      printf("[%d] pfring_send returned %d\n", tosend->len, rc);

    if (likely(rc >= 0)) {
      t->numPkts++;
      t->numBytes += tosend->len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;
    } else if (rc == PF_RING_ERROR_INVALID_ARGUMENT) {
      if (send_error_once) {
        printf("Attempting to send invalid packet [len: %u][MTU: %u]\n",
	       tosend->len, pfring_get_mtu_size(t->ring));
        send_error_once = 0;
      }
    } else if (rc == PF_RING_ERROR_NOT_SUPPORTED) {
      printf("Transmission is not supporte on the selected interface\n");
      exit(-1);
    } else /* Other rc < 0 */ {
      /* Not enough space in buffer */
      usleep(1);
      continue;
    }

    /* move to the next packet */
    tosend = tosend->next;
  }

  return(NULL);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c, *bind_mask = NULL;
  int rc;
  long i;
  u_int32_t version;
  u_int32_t flags = 0;
  pfring *ring[MAX_NUM_RX_CHANNELS];
  int threads_core_affinity[MAX_NUM_RX_CHANNELS];
  int num_uniq_pkts = 1;

  memset(threads_core_affinity, -1, sizeof(threads_core_affinity));
  startTime.tv_sec = 0;
  numCPU = sysconf( _SC_NPROCESSORS_ONLN );

  srcaddr.s_addr = 0x0100000A /* 10.0.0.1 */;
  dstaddr.s_addr = 0x0100A8C0 /* 192.168.0.1 */;

  while((c = getopt(argc,argv,"hi:l:vb:g:D:S:")) != -1) {
    switch(c) {
    case 'b':
      num_ips = atoi(optarg);
      if(num_ips == 0) num_ips = 1;
      num_uniq_pkts = num_ips;
      break;
    case 'h':
      printHelp();
      return(0);
      break;
    case 'l':
      send_len = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'g':
      bind_mask = strdup(optarg);
      break;
    case 'D':
      inet_aton(optarg, &dstaddr);
      break;
    case 'S':
      inet_aton(optarg, &srcaddr);
      break;
    }
  }

  if(device == NULL) device = DEFAULT_DEVICE;

  if(bind_mask != NULL) {
    char *id = strtok(bind_mask, ":");
    int idx = 0;

    while(id != NULL) {
      threads_core_affinity[idx++] = atoi(id) % numCPU;
      if(idx >= MAX_NUM_THREADS) break;
      id = strtok(NULL, ":");
    }
  }

  bind2node(threads_core_affinity[0]);

  if ((threads = calloc(MAX_NUM_THREADS, sizeof(struct thread_stats))) == NULL)
    return -1;

  pkt_head = build_traffic(num_uniq_pkts);

  if (pkt_head == NULL) {
    fprintf(stderr, "Failure allocating memory for packets\n");
    return -1;
  }

  printf("Generating traffic from %s\n", device);

  flags |= PF_RING_PROMISC; /* hardcode: promisc=1 */

  num_channels = pfring_open_multichannel(device, 1536, flags, ring);
  
  if(num_channels <= 0) {
    fprintf(stderr, "pfring_open_multichannel() returned %d [%s]\n", num_channels, strerror(errno));
    return(-1);
  }

  if (num_channels > MAX_NUM_THREADS) {
     printf("WARNING: Too many channels (%d), using %d channels\n", num_channels, MAX_NUM_THREADS);
     num_channels = MAX_NUM_THREADS;
  } else if (num_channels > numCPU) {
     printf("WARNING: More channels (%d) than available cores (%d), using %d channels\n", num_channels, numCPU, numCPU);
     num_channels = numCPU;
  } else  {
    printf("Found %d channels\n", num_channels);
  }

  pfring_version(ring[0], &version);  
  printf("Using PF_RING v.%d.%d.%d\n",
	 (version & 0xFFFF0000) >> 16,
	 (version & 0x0000FF00) >> 8,
	 version & 0x000000FF);
  
  for(i=0; i<num_channels; i++) {
    char buf[32];
   
    threads[i].ring = ring[i];
    threads[i].core_affinity = threads_core_affinity[i];
 
    snprintf(buf, sizeof(buf), "pfcount_multichannel-thread %ld", i);
    pfring_set_application_name(threads[i].ring, buf);

    if((rc = pfring_set_socket_mode(threads[i].ring, send_only_mode)) != 0)
	fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);

    pfring_enable_ring(threads[i].ring);

    pthread_create(&threads[i].pd_thread, NULL, packet_consumer_thread, (void*)i);
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  for(i=0; i<num_channels; i++) {
    pthread_join(threads[i].pd_thread, NULL);
    pfring_close(threads[i].ring);
  }

  return(0);
}
