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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pfring.h"
#include "pfutils.c"

#define ALARM_SLEEP             1
#define MAX_NUM_THREADS         DNA_CLUSTER_MAX_NUM_SLAVES
#define DEFAULT_DEVICE          "dna0"

u_int numCPU;
static struct timeval startTime;
u_int8_t wait_for_packet = 1, print_interface_stats = 0, do_shutdown = 0;
int rx_bind_core = 1; /* core 0 free if possible */
int hashing_mode = 0;
int bridge_interfaces = 0, use_hugepages = 0, low_latency = 0;
int cluster_id = -1;
pfring_dna_cluster *dna_cluster_handle;

#define DIRECTIONS 2
#define DIR_1 0
#define DIR_2 1
pfring *rss_rings[DIRECTIONS][MAX_NUM_THREADS];

int num_dev = 0;
pfring *pd[DIRECTIONS];
int if_indexes[DIRECTIONS];

int num_threads = 1;
struct thread_info {
  pfring *ring;
  int thread_core_affinity;
  pthread_t pd_thread __attribute__((__aligned__(64)));
  u_int64_t numPkts;
  u_int64_t numBytes __attribute__((__aligned__(64)));
};
struct thread_info thread_stats[MAX_NUM_THREADS];

/* ******************************** */

void print_stats() {
  static u_int64_t lastPkts[MAX_NUM_THREADS] = { 0 };
  static u_int64_t lastRXPkts = 0, lastTXPkts = 0, lastRXProcPkts = 0;
  static struct timeval lastTime;
  pfring_stat pfringStat;
  struct timeval endTime;
  double delta, deltaABS;
  u_int64_t diff;
  u_int64_t RXdiff, TXdiff, RXProcdiff;
  pfring_dna_cluster_stat cluster_stats;
  char buf1[32], buf2[32], buf3[32];
  int i;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    return;
  }

  gettimeofday(&endTime, NULL);
  deltaABS = delta_time(&endTime, &startTime);

  delta = delta_time(&endTime, &lastTime);

  for(i=0; i < num_threads; i++) {
    if(pfring_stats(thread_stats[i].ring, &pfringStat) >= 0) {
      double thpt = ((double)8*thread_stats[i].numBytes)/(deltaABS*1000);

      fprintf(stderr, "=========================\n"
              "Thread %d\n"
	      "Absolute Stats: [%u pkts rcvd][%lu bytes rcvd]\n"
	      "                [%u total pkts][%u pkts dropped (%.1f %%)]\n"
              "                [%s pkt/sec][%.2f Mbit/sec]\n", i,
	      (unsigned int) thread_stats[i].numPkts,
	      (long unsigned int)thread_stats[i].numBytes,
	      (unsigned int) (thread_stats[i].numPkts+pfringStat.drop),
	      (unsigned int) pfringStat.drop,
	      thread_stats[i].numPkts == 0 ? 0 : (double)(pfringStat.drop*100)/(double)(thread_stats[i].numPkts+pfringStat.drop),
              pfring_format_numbers(((double)(thread_stats[i].numPkts*1000)/deltaABS), buf1, sizeof(buf1), 1),
	      thpt);

      if(lastTime.tv_sec > 0) {
	// double pps;
	
	diff = thread_stats[i].numPkts-lastPkts[i];
	// pps = ((double)diff/(double)(delta/1000));
	fprintf(stderr, "Actual   Stats: [%llu pkts][%.1f ms][%s pkt/sec]\n",
		(long long unsigned int) diff, 
		delta,
		pfring_format_numbers(((double)diff/(double)(delta/1000)), buf1, sizeof(buf1), 1));
      }

      lastPkts[i] = thread_stats[i].numPkts;
    }
  }
 
  if(dna_cluster_stats(dna_cluster_handle, &cluster_stats) == 0) {
    if(lastTime.tv_sec > 0) {
      RXdiff = cluster_stats.tot_rx_packets - lastRXPkts; 
      RXProcdiff = cluster_stats.tot_rx_processed - lastRXProcPkts;
      TXdiff = cluster_stats.tot_tx_packets - lastTXPkts; 

      fprintf(stderr, "=========================\n"
                      "Aggregate Actual Stats: [Captured %s pkt/sec][Processed %s pkt/sec][Sent %s pkt/sec]\n",
              pfring_format_numbers(((double)RXdiff/(double)(delta/1000)), buf1, sizeof(buf1), 1),
              pfring_format_numbers(((double)RXProcdiff/(double)(delta/1000)), buf2, sizeof(buf2), 1),
              pfring_format_numbers(((double)TXdiff/(double)(delta/1000)), buf3, sizeof(buf3), 1));
    }

    lastRXPkts = cluster_stats.tot_rx_packets;
    lastRXProcPkts = cluster_stats.tot_rx_processed;
    lastTXPkts = cluster_stats.tot_tx_packets;
  }

  if (print_interface_stats) {
    pfring_stat if_stats;
    fprintf(stderr, "=========================\nInterface Absolute Stats\n");
    for (i = 0; i < num_dev; i++)
      if (pfring_stats(pd[i], &if_stats) >= 0)
        fprintf(stderr, "%s RX [%" PRIu64 " pkts rcvd][%" PRIu64 " pkts dropped (%.1f %%)]\n",
	        pd[i]->device_name, if_stats.recv, if_stats.drop,
		if_stats.recv == 0 ? 0 : ((double)(if_stats.drop*100)/(double)(if_stats.recv + if_stats.drop)));
  }


  fprintf(stderr, "=========================\n\n");
  
  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  int i;

  fprintf(stderr, "Leaving...\n");

  if(called) return;
  else called = 1;

  dna_cluster_disable(dna_cluster_handle);

  print_stats();

  for(i=0; i<num_threads; i++)
    pfring_shutdown(thread_stats[i].ring);

  do_shutdown = 1;
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
  printf("pfdnacluster_mt_rss_frwd - (C) 2012 ntop.org\n\n");
  printf("Forward packets received from a DNA Cluster in zero-copy to a DNA device\n"
         "using a per-thread RSS channel. The \"all rx packets to queue 0\" RSS mode\n"
	 "is applied to the devices involved in order to capture from a single queue.\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Ingress device name\n");
  printf("-o <device>     Egress device name\n");
  printf("-b              Bridge mode (bidirectional)\n");
  printf("-c <id>         DNA Cluster ID\n");
  printf("-n <num>        Number of consumer threads (<= num rss queues)\n");
  printf("-r <core>       Bind the RX thread to a core\n");
  printf("-g <id:id...>   Specifies the thread affinity mask (consumers). Each <id> represents\n"
         "                the codeId where the i-th will bind. Example: -g 7:6:5:4 binds thread\n"
         "                0 on coreId 7, 1 on coreId 6 and so on.\n");
  printf("-m <hash mode>  Hashing modes:\n"
	 "                0 - IP hash (default)\n"
	 "                1 - MAC Address hash\n"
	 "                2 - IP protocol hash\n");
  printf("-a              Active packet wait\n");
  printf("-l              Low latency (worse throughput)\n");
  printf("-u <mountpoint> Use hugepages for packet memory allocation\n");
  printf("-p              Print per-interface absolute stats\n");
  exit(0);
}

/* *************************************** */

static inline u_int32_t master_custom_hash_function(const u_char *buffer, const u_int16_t buffer_len) {
  u_int32_t l3_offset = sizeof(struct compact_eth_hdr);
  u_int16_t eth_type;

  if(hashing_mode == 1 /* MAC hash */)
    return(buffer[3] + buffer[4] + buffer[5] + buffer[9] + buffer[10] + buffer[11]);

  eth_type = (buffer[12] << 8) + buffer[13];

  while (eth_type == 0x8100 /* VLAN */) {
    l3_offset += 4;
    eth_type = (buffer[l3_offset - 2] << 8) + buffer[l3_offset - 1];
  }

  switch (eth_type) {
  case 0x0800:
    {
      /* IPv4 */
      struct compact_ip_hdr *iph;

      if (unlikely(buffer_len < l3_offset + sizeof(struct compact_ip_hdr)))
	return 0;

      iph = (struct compact_ip_hdr *) &buffer[l3_offset];

      if(hashing_mode == 0 /* IP hash */)
	return ntohl(iph->saddr) + ntohl(iph->daddr); /* this can be optimized by avoiding calls to ntohl(), but it can lead to balancing issues */
      else /* IP protocol hash */
	return iph->protocol;
    }
    break;
  case 0x86DD:
    {
      /* IPv6 */
      struct compact_ipv6_hdr *ipv6h;
      u_int32_t *s, *d;

      if (unlikely(buffer_len < l3_offset + sizeof(struct compact_ipv6_hdr)))
	return 0;

      ipv6h = (struct compact_ipv6_hdr *) &buffer[l3_offset];

      if(hashing_mode == 0 /* IP hash */) {
	s = (u_int32_t *) &ipv6h->saddr, d = (u_int32_t *) &ipv6h->daddr;
	return(s[0] + s[1] + s[2] + s[3] + d[0] + d[1] + d[2] + d[3]);
      } else
	return(ipv6h->nexthdr);
    }
    break;
  default:
    return 0; /* Unknown protocol */
  }
}

/* ******************************* */

static int master_distribution_function(const u_char *buffer, const u_int16_t buffer_len, const pfring_dna_cluster_slaves_info *slaves_info, u_int32_t *id_mask, u_int32_t *hash) {
  u_int32_t slave_idx;

  /* computing a bidirectional software hash */
  *hash = master_custom_hash_function(buffer, buffer_len);

  /* balancing on hash */
  slave_idx = (*hash) % slaves_info->num_slaves;
  *id_mask = (1 << slave_idx);

  return DNA_CLUSTER_PASS;
}

/* *************************************** */

void* packet_consumer_thread(void *_id) {
  int rc;
  long thread_id = (long)_id; 
  pfring_pkt_buff *pkt_handle = NULL;
  struct pfring_pkthdr hdr;
 
  if (numCPU > 1) {
#ifdef HAVE_PTHREAD_SETAFFINITY_NP
    /* Bind this thread to a specific core */
    cpu_set_t cpuset;
    u_long core_id;
    int s;

    if (thread_stats[thread_id].thread_core_affinity != -1)
       core_id = thread_stats[thread_id].thread_core_affinity % numCPU;
    else
      core_id = (rx_bind_core + 1 + thread_id) % numCPU; 

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if ((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0)
      fprintf(stderr, "Error while binding thread %ld to core %ld: errno=%i\n", 
	     thread_id, core_id, s);
    else {
      printf("Set thread %lu on core %lu/%u\n", thread_id, core_id, numCPU);
    }
#endif
  }

  memset(&hdr, 0, sizeof(hdr));

  if ((pkt_handle = pfring_alloc_pkt_buff(thread_stats[thread_id].ring)) == NULL) {
    printf("Error allocating pkt buff\n");
    return NULL;
  }

  while (!do_shutdown) {
    /* tx is not enabled in the cluster, but we will send 
     * received packets to a tx ring using zero-copy anyway */
    rc = pfring_recv_pkt_buff(thread_stats[thread_id].ring, pkt_handle, &hdr, wait_for_packet);

    if (rc > 0) {
      if (bridge_interfaces && hdr.extended_hdr.if_index == if_indexes[DIR_2])
        pfring_send_pkt_buff(rss_rings[DIR_2][thread_id], pkt_handle, low_latency /* flush */);
      else
        pfring_send_pkt_buff(rss_rings[DIR_1][thread_id], pkt_handle, low_latency /* flush */);

      thread_stats[thread_id].numPkts++;
      thread_stats[thread_id].numBytes += hdr.len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;
    } else {
      if (!wait_for_packet) 
        usleep(1); //sched_yield();
    }
  }

  return(NULL);
}

/* *************************************** */

int open_rss_rings(char *rss_device, pfring **rss_rings) {
  long i;
  int rc, num_channels;
  
  num_channels = pfring_open_multichannel(rss_device, 1500 /* snaplen */, PF_RING_PROMISC | PF_RING_DNA_FIXED_RSS_Q_0, rss_rings);

  if(num_channels < num_threads) {
    fprintf(stderr, "Error: interface %s has %u channels available, you need at least %u as the number of slave threads\n", 
            rss_device, num_channels, num_threads);
    return -1;
  }

  for(i=0; i<num_channels; i++) {
    char buf[32];
    snprintf(buf, sizeof(buf), "pfdnacluster-%s-channel-%ld", rss_device, i);
    pfring_set_application_name(rss_rings[i], buf);

    if((rc = pfring_set_socket_mode(rss_rings[i], send_only_mode)) != 0)
      fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);
  }

  return 0;
}

/* *************************************** */

int open_rx_ring(char *rx_device) {
  u_int32_t version;
  char buf[32];

  pd[num_dev] = pfring_open(rx_device, 1500 /* snaplen */, PF_RING_PROMISC | PF_RING_DNA_FIXED_RSS_Q_0 /* if RSS is enabled, steer all to queue 0 */);
  if(pd[num_dev] == NULL) {
    printf("pfring_open %s error [%s]\n", rx_device, strerror(errno));
    return(-1);
  }

  if (num_dev == 0) {
    pfring_version(pd[num_dev], &version);
    printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16, 
           (version & 0x0000FF00) >> 8, version & 0x000000FF);
  }

  snprintf(buf, sizeof(buf), "pfdnacluster-%u-%s", cluster_id, rx_device);
  pfring_set_application_name(pd[num_dev], buf);

  if (bridge_interfaces && pfring_get_bound_device_ifindex(pd[num_dev], &if_indexes[num_dev]) < 0) {
    fprintf(stderr, "Error reading interface id\n");
    dna_cluster_destroy(dna_cluster_handle);
    return -1;
  }

  if (bridge_interfaces && num_dev > 0)
    printf("Bridging interfaces %d <-> %d\n", if_indexes[0], if_indexes[1]);

  /* Add the ring we created to the cluster */
  if (dna_cluster_register_ring(dna_cluster_handle, pd[num_dev]) < 0) {
    fprintf(stderr, "Error registering rx socket\n");
    dna_cluster_destroy(dna_cluster_handle);
    return -1;
  }

  num_dev++;
  return 0;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  char buf[32];
  char *bind_mask = NULL;
  char *in_device = NULL, *out_device = NULL, *hugepages_mountpoint = NULL;
  socket_mode mode = recv_only_mode;
  int rc;
  long i;

  memset(rss_rings, 0, sizeof(rss_rings));

  memset(thread_stats, 0, sizeof(thread_stats));
  for (i = 0; i < MAX_NUM_THREADS; i++)
    thread_stats[i].thread_core_affinity = -1;

  numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  startTime.tv_sec = 0;

  while ((c = getopt(argc,argv,"ahi:bc:n:m:r:g:pu:lo:")) != -1) {
    switch (c) {
    case 'a':
      wait_for_packet = 0;
      break;
    case 'r':
      rx_bind_core = atoi(optarg);
      break;
    case 'g':
      bind_mask = strdup(optarg);
      break;
    case 'h':
      printHelp();      
      break;
    case 'i':
      in_device = strdup(optarg);
      break;
    case 'o':
      out_device = strdup(optarg);
      break;
    case 'l':
      low_latency = 1;
      break;
    case 'c':
      cluster_id = atoi(optarg);
      break;
    case 'n':
      num_threads = atoi(optarg);
      break;
    case 'm':
      hashing_mode = atoi(optarg);
      break;
    case 'b':
      bridge_interfaces = 1;
      break;
    case 'p':
      print_interface_stats = 1;
      break;
    case 'u':
      use_hugepages = 1;
      hugepages_mountpoint = strdup(optarg);
      break;
    }
  }

  if (out_device == NULL || cluster_id < 0 || num_threads < 1 || hashing_mode < 0 || hashing_mode > 2) 
    printHelp();

  if (num_threads > MAX_NUM_THREADS) {
    printf("WARNING: You cannot instantiate more than %u slave threads\n", MAX_NUM_THREADS);
    num_threads = MAX_NUM_THREADS;
  }

  if (in_device == NULL) in_device = strdup(DEFAULT_DEVICE);

  if(bind_mask != NULL) {
    char *id = strtok(bind_mask, ":");
    int idx = 0;

    while(id != NULL) {
      thread_stats[idx++].thread_core_affinity = atoi(id) % numCPU;
      if(idx >= num_threads) break;
      id = strtok(NULL, ":");
    }
  }

  bind2node(rx_bind_core);

  if (open_rss_rings(out_device, rss_rings[DIR_1]) < 0)
    return -1;

  if (bridge_interfaces) {
    if (open_rss_rings(in_device, rss_rings[DIR_2]) < 0)
      return -1;
  }

  printf("Capturing from %s", in_device);
  if (bridge_interfaces)
    printf(" and %s", out_device);
  printf("\n");

  /* Create the DNA cluster */
  if ((dna_cluster_handle = dna_cluster_create(cluster_id, 
  					       num_threads, 
					       0
					       /* | DNA_CLUSTER_DCA */
					       | (use_hugepages ? DNA_CLUSTER_HUGEPAGES : 0)
     )) == NULL) {
    fprintf(stderr, "Error creating DNA Cluster\n");
    return(-1);
  }
 
  /* Changing the default settings (experts only) */
  dna_cluster_low_level_settings(dna_cluster_handle, 
                                 8192, // slave rx queue slots
                                 0, // slave tx queue slots
				 // slave additional buffers (available with  alloc/release)
				 1 + rss_rings[DIR_1][0]->dna.dna_dev.mem_info.tx.packet_memory_num_slots +
				 (bridge_interfaces ? rss_rings[DIR_2][0]->dna.dna_dev.mem_info.tx.packet_memory_num_slots : 0)
				 );

  if (use_hugepages) {
    if (dna_cluster_set_hugepages_mountpoint(dna_cluster_handle, hugepages_mountpoint) < 0) {
      fprintf(stderr, "Error setting the hugepages mountpoint: did you mount it?\n");
      return(-1);
    }
  }

  if (dna_cluster_set_mode(dna_cluster_handle, mode) < 0) {
    printf("dna_cluster_set_mode error\n");
    return(-1);
  }

  if (open_rx_ring(in_device) < 0)
    return -1;

  if (bridge_interfaces) {
    if (open_rx_ring(out_device) < 0)
      return -1;
  }

  /* Setting up important details... */
  dna_cluster_set_wait_mode(dna_cluster_handle, !wait_for_packet /* active_wait */);
  dna_cluster_set_cpu_affinity(dna_cluster_handle, rx_bind_core, -1);

  /* The default distribution function allows to balance per IP 
    in a coherent mode (not like RSS that does not do that) */
  if (hashing_mode > 0) {
    dna_cluster_set_distribution_function(dna_cluster_handle, master_distribution_function);
  }

  switch(hashing_mode) {
  case 0:
    printf("Hashing packets per-IP Address\n");
    break;
  case 1:
    printf("Hashing packets per-MAC Address\n");
    break;
  case 2:
    printf("Hashing packets per-IP protocol (TCP, UDP, ICMP...)\n");
    break;
  }

  /* Now enable the cluster */
  if (dna_cluster_enable(dna_cluster_handle) < 0) {
    fprintf(stderr, "Error enabling the engine; dna NICs already in use?\n");
    dna_cluster_destroy(dna_cluster_handle);
    return -1;
  }

  printf("The DNA cluster [id: %u][num consumer threads: %u] is running...\n", 
	 cluster_id, num_threads);

  for (i = 0; i < num_threads; i++) {
    snprintf(buf, sizeof(buf), "dnacluster:%d@%ld", cluster_id, i);
    thread_stats[i].ring = pfring_open(buf, 1500 /* snaplen */, PF_RING_PROMISC);
    if (thread_stats[i].ring == NULL) {
      printf("pfring_open %s error [%s]\n", buf, strerror(errno));
      return(-1);
    }

    snprintf(buf, sizeof(buf), "pfdnacluster_multithread-cluster-%d-thread-%ld", cluster_id, i);
    pfring_set_application_name(thread_stats[i].ring, buf);

    if ((rc = pfring_set_socket_mode(thread_stats[i].ring, mode)) != 0)
      fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);

    /* this call will do the magic making rss_rings[dir][i] a zero-copy ring */
    if ((rc = pfring_register_zerocopy_tx_ring(thread_stats[i].ring, rss_rings[DIR_1][i])) != 0) {
      printf("pfring_register_zerocopy_tx_ring error: %d\n", rc);
      return(-1);
    }

    if (bridge_interfaces) {
      if ((rc = pfring_register_zerocopy_tx_ring(thread_stats[i].ring, rss_rings[DIR_2][i])) != 0) {
        printf("pfring_register_zerocopy_tx_ring error: %d\n", rc);
        return(-1);
      }
    }

    pfring_enable_ring(thread_stats[i].ring);

    pthread_create(&thread_stats[i].pd_thread, NULL, packet_consumer_thread, (void *) i);

    printf("Consumer thread #%ld is running...\n", i);
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  for(i = 0; i < num_threads; i++) {
    pthread_join(thread_stats[i].pd_thread, NULL);
    pfring_close(thread_stats[i].ring);
  }

  dna_cluster_destroy(dna_cluster_handle);

  return(0);
}

