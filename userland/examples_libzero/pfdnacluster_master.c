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
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "pfring.h"
#include "pfutils.c"

#define ALARM_SLEEP            1
#define MAX_NUM_OPTIONS        64
#define MAX_NUM_APP            DNA_CLUSTER_MAX_NUM_SLAVES
#define MAX_NUM_DEV            DNA_CLUSTER_MAX_NUM_SOCKETS
#define DEFAULT_DEVICE         "dna0"

int caplen = 1536;
int daemon_mode = 0;
int num_dev = 0, num_apps = 0, tot_num_slaves = 0;
int instances_per_app[MAX_NUM_APP];
u_int32_t frwd_mask = 0;
pfring *pd[MAX_NUM_DEV];
pfring_dna_cluster *dna_cluster_handle;

u_int8_t wait_for_packet = 1, print_interface_stats = 0, proc_stats_only = 0, do_shutdown = 0, hashing_mode = 0, use_hugepages = 0, time_pulse_thread = 0;
socket_mode mode = recv_only_mode;
int time_pulse_resolution = 0;

static struct timeval startTime;

int cluster_id = -1;

char *device = NULL;
char *frwd_device = NULL;
pfring *frwd_in_ring, *frwd_out_ring;
int frwd_buffers = 0;
int frwd_low_latency = 0;
int rx_bind_core = 0, tx_bind_core = 1, time_pulse_bind_core = 2, frwd_bind_core = 3;
int queue_len = 8192;
#ifdef HAVE_PTHREAD_SETAFFINITY_NP
u_int numCPU;
#endif

/* ******************************** */

void print_stats() {
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static struct timeval lastTime = { 0 };
  char buf0[64], buf1[64], buf2[64];
  u_int64_t RXdiff, TXdiff, RXProcdiff;
  static u_int64_t lastRXPkts = 0, lastTXPkts = 0, lastRXProcPkts = 0;
  unsigned long long nRXPkts = 0, nTXPkts = 0, nRXProcPkts = 0;
  char timeBuffer[128];
  char statsBuf[1024];
  pfring_dna_cluster_stat cluster_stats;
  int i;

  if (startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);

  deltaMillisec = delta_time(&endTime, &startTime);

  if(dna_cluster_stats(dna_cluster_handle, &cluster_stats) == 0) {
    nRXPkts  = cluster_stats.tot_rx_packets;
    nTXPkts  = cluster_stats.tot_tx_packets;
    nRXProcPkts  = cluster_stats.tot_rx_processed;

    if (!daemon_mode && !proc_stats_only) {
      fprintf(stderr, "---\nAbsolute Stats:");
 
      if (mode != send_only_mode) {
        fprintf(stderr, " RX %s pkts", pfring_format_numbers((double)nRXPkts, buf1, sizeof(buf1), 0));
        if (print_all) fprintf(stderr, " [%s pkt/sec]", pfring_format_numbers((double)(nRXPkts*1000)/deltaMillisec, buf1, sizeof(buf1), 1));
      
        fprintf(stderr, " Processed %s pkts", pfring_format_numbers((double)nRXProcPkts, buf1, sizeof(buf1), 0));
        if (print_all) fprintf(stderr, " [%s pkt/sec]", pfring_format_numbers((double)(nRXProcPkts*1000)/deltaMillisec, buf1, sizeof(buf1), 1));
      }
	   
      if (mode != recv_only_mode) {
        fprintf(stderr, " TX %s pkts", pfring_format_numbers((double)nTXPkts, buf1, sizeof(buf1), 0));
        if(print_all) fprintf(stderr, " [%s pkt/sec]", pfring_format_numbers((double)(nTXPkts*1000)/deltaMillisec, buf1, sizeof(buf1), 1));
      }
	        
      fprintf(stderr, "\n");
    }

    snprintf(statsBuf, sizeof(statsBuf), 
             "ClusterId:         %d\n"
             "TotQueues:         %d\n"
             "Applications:      %d\n", 
             cluster_id,
	     tot_num_slaves,
	     num_apps);

    for (i = 0; i < num_apps; i++)
      snprintf(&statsBuf[strlen(statsBuf)], sizeof(statsBuf)-strlen(statsBuf), 
               "App%dQueues:        %d\n", 
	       i, instances_per_app[i]);

    snprintf(&statsBuf[strlen(statsBuf)], sizeof(statsBuf)-strlen(statsBuf),
             "Duration:          %s\n",
	     msec2dhmsm(deltaMillisec, timeBuffer, sizeof(timeBuffer)));

    if (mode != send_only_mode) {
      snprintf(&statsBuf[strlen(statsBuf)], sizeof(statsBuf)-strlen(statsBuf),
  	       "Packets:           %lu\n"
	       "Processed:         %lu\n",
	       (long unsigned int)nRXPkts,
	       (long unsigned int)nRXProcPkts);
    }

    if (mode != recv_only_mode) {
      snprintf(&statsBuf[strlen(statsBuf)], sizeof(statsBuf)-strlen(statsBuf),
	       "SentPackets:       %lu\n",
	       (long unsigned int)nTXPkts);
    }

    if (mode != send_only_mode && print_interface_stats) {
      int i;
      u_int64_t IFRX = 0, IFDrop = 0;
      pfring_stat if_stats;
      for (i = 0; i < num_dev; i++) {
        if (pfring_stats(pd[i], &if_stats) >= 0) {
	  IFRX += if_stats.recv;
	  IFDrop += if_stats.drop;
          if (!daemon_mode && !proc_stats_only)
            fprintf(stderr, "                %s RX %" PRIu64 " pkts Dropped %" PRIu64 " pkts (%.1f %%)\n", 
                    pd[i]->device_name, if_stats.recv, if_stats.drop, 
	            if_stats.recv == 0 ? 0 : ((double)(if_stats.drop*100)/(double)(if_stats.recv + if_stats.drop)));
	}
      }
      snprintf(&statsBuf[strlen(statsBuf)], sizeof(statsBuf)-strlen(statsBuf),
               "IFPackets:         %lu\n"
  	       "IFDropped:         %lu\n",
	       (long unsigned int)IFRX, 
	       (long unsigned int)IFDrop);
    }

    pfring_set_application_stats(pd[0], statsBuf);

    if (!daemon_mode && !proc_stats_only) {
      if(print_all && (lastTime.tv_sec > 0)) {
        deltaMillisec = delta_time(&endTime, &lastTime);
        RXdiff = nRXPkts - lastRXPkts;
        TXdiff = nTXPkts - lastTXPkts;
        RXProcdiff = nRXProcPkts - lastRXProcPkts;

        fprintf(stderr, "Actual Stats:  ");

        if (mode != send_only_mode) {
          fprintf(stderr, " RX %s pkts [%s ms][%s pps]",
	          pfring_format_numbers((double)RXdiff, buf0, sizeof(buf0), 0),
	          pfring_format_numbers(deltaMillisec, buf1, sizeof(buf1), 1),
	          pfring_format_numbers(((double)RXdiff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1));
			   
          fprintf(stderr, " Processed %s pkts [%s ms][%s pps]",
	          pfring_format_numbers((double)RXProcdiff, buf0, sizeof(buf0), 0),
                  pfring_format_numbers(deltaMillisec, buf1, sizeof(buf1), 1),
                  pfring_format_numbers(((double)RXProcdiff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1));
        }
						    
        if (mode != recv_only_mode) {
          fprintf(stderr, " TX %llu pkts [%s ms][%s pps]",
	          (long long unsigned int)TXdiff,
	          pfring_format_numbers(deltaMillisec, buf1, sizeof(buf1), 1),
                  pfring_format_numbers(((double)TXdiff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1));
        }

        fprintf(stderr, "\n");
      }

      lastRXPkts = nRXPkts;
      lastTXPkts = nTXPkts;
      lastRXProcPkts = nRXProcPkts;
      lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
    }
  }
}

/* ******************************** */

void my_sigalarm(int sig) {
  if(do_shutdown)
    return;

  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  trace(TRACE_NORMAL, "Leaving...\n");

  if(called) return; else called = 1;
  
  dna_cluster_disable(dna_cluster_handle);
  
  if (frwd_device) 
    pfring_shutdown(frwd_in_ring);

  do_shutdown = 1;
}

/* *************************************** */

void printHelp(void) {
  printf("pfdnacluster_master - (C) 2012-14 ntop.org\n\n");

  printf("pfdnacluster_master [-a] -i dev\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name (comma-separated list)\n");
  printf("-c <cluster>    Cluster ID\n");
  printf("-n <num>        Number of app instances (comma-separated list for multiple apps)\n");
  printf("-m <hash mode>  Hashing modes:\n"
	 "                0 - IP hash (default)\n"
	 "                1 - MAC Address hash\n"
	 "                2 - IP protocol hash\n"
	 "                3 - Fan-Out\n"
	 "                4 - 5-tuple hash (IP, port, protocol)\n");
  printf("-s              Enable TX thread\n");
  printf("-r <core id>    Bind the RX thread to a core\n");
  printf("-t <core id>    Bind the TX thread to a core (-s only)\n");
  printf("-a              Active packet wait\n");
  printf("-S <core id>    Enable Time Pulse thread and bind it to a core\n");
  printf("-R <nsec>       Time resolution (nsec) when using pulse thread\n");
  printf("-o <device>     Forward both to applications and an egress device\n");
  printf("-f <core id>    Bind the forwarder thread to a core (-o only)\n");
  printf("-u <mountpoint> Use hugepages for packet memory allocation\n");
  printf("-q <len>        Number of slots in each queue (default: %u)\n", queue_len);
  printf("-p              Print per-interface absolute stats\n");
  printf("-d              Daemon mode\n");
  printf("-D <username>   Drop privileges\n");
  printf("-P <pid file>   Write pid to the specified file (daemon mode only)\n");
  exit(0);
}

/* *************************************** */

int init_frwd_socket() {
  int rc; 
  char buf[32];

  frwd_out_ring = pfring_open(frwd_device, caplen, PF_RING_PROMISC);

  if (frwd_out_ring == NULL) {
    trace(TRACE_ERROR, "pfring_open %s error [%s]\n", frwd_device, strerror(errno));
    return -1;
  }

  snprintf(buf, sizeof(buf), "dna-cluster-%d-frwd-out", cluster_id);
  pfring_set_application_name(frwd_out_ring, buf);

  if ((rc = pfring_set_socket_mode(frwd_out_ring, send_only_mode)) != 0)
    trace(TRACE_ERROR, "pfring_set_socket_mode returned [rc=%d]\n", rc);

  frwd_buffers = frwd_out_ring->dna.dna_dev.mem_info.tx.packet_memory_num_slots + 1;

  return 0;
}

/* *************************************** */

int register_frwd_socket() {
  int rc;
  char buf[32];

  snprintf(buf, sizeof(buf), "dnacluster:%d@%d", cluster_id, tot_num_slaves);
  frwd_in_ring = pfring_open(buf, caplen, PF_RING_PROMISC);
  if (frwd_in_ring == NULL) {
    trace(TRACE_ERROR, "pfring_open %s error [%s]\n", buf, strerror(errno));
    return -1;
  }

  snprintf(buf, sizeof(buf), "dna-cluster-%d-frwd-in", cluster_id);
  pfring_set_application_name(frwd_in_ring, buf);

  if ((rc = pfring_set_socket_mode(frwd_in_ring, recv_only_mode)) != 0)
    trace(TRACE_ERROR, "pfring_set_socket_mode returned [rc=%d]\n", rc);

  /* this call will do the magic making frwd_out_ring a zero-copy ring */
  if ((rc = pfring_register_zerocopy_tx_ring(frwd_in_ring, frwd_out_ring)) != 0) {
    trace(TRACE_ERROR, "pfring_register_zerocopy_tx_ring error: %d\n", rc);
    return -1;
  }

  if (pfring_enable_ring(frwd_in_ring) < 0) {
    trace(TRACE_ERROR, "pfring_enable_ring(dnacluster:%d@%d) error: %d\n", cluster_id, tot_num_slaves, rc);
    return -1;
  }

  frwd_mask = 1 << tot_num_slaves;

  return 0;
}

/* *************************************** */

void* frwd_thread(void *user) {
  int rc;
  pfring_pkt_buff *pkt_handle = NULL;
  struct pfring_pkthdr hdr;
 
#ifdef HAVE_PTHREAD_SETAFFINITY_NP
  if (numCPU > 1 && frwd_bind_core != -1) {
    cpu_set_t cpuset;
    u_long core_id = frwd_bind_core % numCPU;

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
      trace(TRACE_ERROR, "Error while binding forwarder thread to core %ld\n", core_id);
    else
      trace(TRACE_NORMAL, "Set forwarder thread on core %lu/%u\n", core_id, numCPU);
  }
#endif

  memset(&hdr, 0, sizeof(hdr));

  if ((pkt_handle = pfring_alloc_pkt_buff(frwd_in_ring)) == NULL) {
    trace(TRACE_ERROR, "Error allocating pkt buff\n");
    sigproc(0);
    return NULL;
  }

  while (!do_shutdown) {
    /* tx is not enabled in the cluster, we will send received packets to the out ring using zero-copy */
    rc = pfring_recv_pkt_buff(frwd_in_ring, pkt_handle, &hdr, wait_for_packet);

    if (rc > 0) {
      pfring_send_pkt_buff(frwd_out_ring, pkt_handle, frwd_low_latency /* flush */);

      /* ignoring return value: best effort */

      //frwd_num_pkts++;
      //frwd_num_bytes += hdr.len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;
    } else { /* active wait */
      //if (!wait_for_packet) usleep(1);
    }
  }

  return NULL;
}

/* *************************************** */

inline u_int32_t master_custom_hash_function(const u_char *buffer, const u_int16_t buffer_len) {
  u_int32_t hash, l3_offset = sizeof(struct compact_eth_hdr), l4_offset;
  u_int16_t eth_type;
  u_int8_t l3_proto;

  if(hashing_mode == 1 /* MAC hash */)
    return(buffer[3] + buffer[4] + buffer[5] + buffer[9] + buffer[10] + buffer[11]);

  eth_type = (buffer[12] << 8) + buffer[13];

  while (eth_type == 0x8100 /* VLAN */ && l3_offset+4 < buffer_len) {
    l3_offset += 4;
    eth_type = (buffer[l3_offset - 2] << 8) + buffer[l3_offset - 1];
  }

  if (eth_type == 0x8864 /* PPPoE */) {
    l3_offset += 8;
    eth_type = 0x0800; /* TODO Check for IPv6 */
  }

  switch (eth_type) {
  case 0x0800:
    {
      /* IPv4 */
      struct compact_ip_hdr *iph;

      if (unlikely(buffer_len < l3_offset + sizeof(struct compact_ip_hdr)))
	return 0;

      iph = (struct compact_ip_hdr *) &buffer[l3_offset];

      if(hashing_mode == 2) /* IP protocol hash */
	return iph->protocol;

      hash = ntohl(iph->saddr) + ntohl(iph->daddr); /* this can be optimized by avoiding calls to ntohl(), but it can lead to balancing issues */

      l3_proto = iph->protocol;
      l4_offset = l3_offset + (iph->ihl * 4);
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

      if(hashing_mode == 2) /* IP protocol hash */
	return(ipv6h->nexthdr);
 
      s = (u_int32_t *) &ipv6h->saddr, d = (u_int32_t *) &ipv6h->daddr;
      return(s[0] + s[1] + s[2] + s[3] + d[0] + d[1] + d[2] + d[3]);
    }
    break;
  default:
    return 0; /* Unknown protocol */
  }

  if(hashing_mode == 0) /* IP hash */
    return hash;

  /* hashing_mode == 4 - 5-tuple hash */
  if(likely(l3_proto == IPPROTO_TCP || l3_proto == IPPROTO_UDP || l3_proto == IPPROTO_SCTP)) {
    struct compact_udp_hdr *udph = (struct compact_udp_hdr *)(&buffer[l4_offset]);
    hash += ntohs(udph->sport) + ntohs(udph->dport);
  } 

  return hash;
}

/* ******************************* */

static int master_distribution_function(const u_char *buffer, const u_int16_t buffer_len, const pfring_dna_cluster_slaves_info *slaves_info, u_int32_t *id_mask, u_int32_t *hash) {
  u_int32_t slave_idx;
  
  /* computing a bidirectional software hash */
  *hash = master_custom_hash_function(buffer, buffer_len);
	   
  /* balancing on hash */
  slave_idx = (*hash) % slaves_info->num_slaves;
  *id_mask = (1 << slave_idx) | frwd_mask;

  return DNA_CLUSTER_PASS; /* DNA_CLUSTER_DROP, DNA_CLUSTER_PASS, DNA_CLUSTER_FRWD */
}

/* ******************************* */

static int multi_app_distribution_function(const u_char *buffer, const u_int16_t buffer_len, const pfring_dna_cluster_slaves_info *slaves_info, u_int32_t *id_mask, u_int32_t *hash) {
  u_int32_t i, offset = 0, app_instance, slaves_mask = 0;

  /* computing a bidirectional software hash */
  *hash = master_custom_hash_function(buffer, buffer_len);

  /* balancing on hash */
  for (i = 0; i < num_apps; i++) {
    app_instance = (*hash) % instances_per_app[i];
    slaves_mask |= (1 << (offset + app_instance));
    offset += instances_per_app[i];
  }

  *id_mask = slaves_mask | frwd_mask;
  return DNA_CLUSTER_PASS; /* DNA_CLUSTER_DROP, DNA_CLUSTER_PASS, DNA_CLUSTER_FRWD */
}

/* ******************************** */

static int fanout_distribution_function(const u_char *buffer, const u_int16_t buffer_len, const pfring_dna_cluster_slaves_info *slaves_info, u_int32_t *id_mask, u_int32_t *hash) {
  u_int32_t n_zero_bits = 32 - slaves_info->num_slaves;

  /* returning slave id bitmap */
  *id_mask = ((0xFFFFFFFF << n_zero_bits) >> n_zero_bits) | frwd_mask;

  return DNA_CLUSTER_PASS; /* DNA_CLUSTER_DROP, DNA_CLUSTER_PASS, DNA_CLUSTER_FRWD */
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  char buf[64];
  u_int32_t version;
  int off, i, j;
  char *dev, *dev_pos = NULL;
  char *applications = NULL, *app, *app_pos = NULL;
  char *pidFileName = NULL;
  char *username = NULL;
  char *hugepages_mountpoint = NULL;
  int opt_argc;
  char **opt_argv;

#ifdef HAVE_PTHREAD_SETAFFINITY_NP
  numCPU = sysconf( _SC_NPROCESSORS_ONLN );
#endif
  startTime.tv_sec = 0;

  if((argc == 2) && (argv[1][0] != '-')) {
    FILE *fd;
    char *tok, cont = 1;
    char line[2048];

    opt_argc = 0;
    opt_argv = (char **) malloc(sizeof(char *) * MAX_NUM_OPTIONS);

    if(opt_argv == NULL)
      exit(-1);

    memset(opt_argv, 0, sizeof(char *) * MAX_NUM_OPTIONS);

    fd = fopen(argv[1], "r");

    if(fd == NULL) {
      trace(TRACE_ERROR, "Unable to read config file %s", argv[1]);
      exit(-1);
    }

    opt_argv[opt_argc++] = strdup(argv[0]);

    while(cont && fgets(line, sizeof(line), fd)) {
      i = 0;
      while(line[i] != '\0') {
	if(line[i] == '=')
	  break;
	else if(line[i] == ' ') {
	  line[i] = '=';
	  break;
	}
	i++;
      }

      tok = strtok(line, "=");

      while(tok != NULL) {
	int len;
	char *argument;

	if(opt_argc >= MAX_NUM_OPTIONS) {
	  int i;

	  trace(TRACE_ERROR, "Too many options (%u)", opt_argc);

	  for(i=0; i<opt_argc; i++)
	    trace(TRACE_ERROR, "[%d][%s]", i, opt_argv[i]);

	  cont = 0;
	  break;
	}

	len = strlen(tok)-1;
	if(tok[len] == '\n')
	  tok[len] = '\0';

	if((tok[0] == '\"') && (tok[strlen(tok)-1] == '\"')) {
	  tok[strlen(tok)-1] = '\0';
	  argument = &tok[1];
	} else
	  argument = tok;

	if(argument[0] != '\0')
	  opt_argv[opt_argc++] = strdup(argument);

	tok = strtok(NULL, "\n");
      }
    }

    fclose(fd);
  } else {
    opt_argc = argc;
    opt_argv = argv;
  }

  while((c = getopt(opt_argc, opt_argv, "ac:r:st:hi:n:m:dD:u:pP:S:o:f:q:R:z")) != -1) {
    switch(c) {
    case 'a':
      wait_for_packet = 0;
      break;
    case 'r':
      rx_bind_core = atoi(optarg);
      break;
    case 't':
      tx_bind_core = atoi(optarg);
      break;
    case 'f':
      frwd_bind_core = atoi(optarg);
      break;
    case 'h':
      printHelp();      
      break;
    case 's':
      mode = send_and_recv_mode;
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'o':
      frwd_device = strdup(optarg);
      break;
    case 'c':
      cluster_id = atoi(optarg);
      break;
    case 'n':
      applications = strdup(optarg);
      break;
    case 'm':
      hashing_mode = atoi(optarg);
      break;
    case 'd':
      daemon_mode = 1;
      break;
    case 'D':
      username = strdup(optarg);
      break;
    case 'p':
      print_interface_stats = 1;
      break;
    case 'P':
      pidFileName = strdup(optarg);
      break;
    case 'S':
      time_pulse_thread = 1;
      time_pulse_bind_core = atoi(optarg);
      break;
    case 'R':
      time_pulse_resolution = atoi(optarg);
    case 'u':
      use_hugepages = 1;
      if (optarg != NULL) hugepages_mountpoint = strdup(optarg);
      break;
    case 'q':
      queue_len = atoi(optarg);
      break;
    case 'z':
      proc_stats_only = 1;
      break;
    }
  }

  if (applications != NULL) {
    app = strtok_r(applications, ",", &app_pos);
    while(app != NULL) {
      instances_per_app[num_apps] = atoi(app);

      if (instances_per_app[num_apps] <= 0)
        printHelp();

      tot_num_slaves += instances_per_app[num_apps];
      num_apps++;

      app = strtok_r(NULL, ",", &app_pos);
    }
  }

  if (num_apps == 0) {
    instances_per_app[0] = 1;
    tot_num_slaves = num_apps = 1;
  }

  if (tot_num_slaves + (frwd_device ? 1 : 0) > MAX_NUM_APP) {
    trace(TRACE_WARNING, "WARNING: You cannot instantiate more than %u slave applications\n", MAX_NUM_APP);
    printHelp();
  }

  if (cluster_id < 0 || hashing_mode < 0 || hashing_mode > 4)
    printHelp();

  if (device == NULL) device = strdup(DEFAULT_DEVICE);

#ifdef HAVE_PTHREAD_SETAFFINITY_NP
  bind2node(rx_bind_core % numCPU);
#endif

  if (daemon_mode)
    daemonize();

  trace(TRACE_NORMAL, "Capturing from %s\n", device);
  
  if (frwd_device) {
    if (init_frwd_socket() < 0)
      return -1;
  }

  /* Create the DNA cluster */
  if ((dna_cluster_handle = dna_cluster_create(cluster_id, 
                                               tot_num_slaves + (frwd_device ? 1 : 0), 
					       0 
					       /* | DNA_CLUSTER_DIRECT_FORWARDING */
                                               /* | DNA_CLUSTER_NO_ADDITIONAL_BUFFERS */
					       /* | DNA_CLUSTER_DCA */
					       | (use_hugepages ? DNA_CLUSTER_HUGEPAGES : 0)
					       | (time_pulse_thread ? DNA_CLUSTER_TIME_PULSE_THREAD : 0)
     )) == NULL) {
    trace(TRACE_ERROR, "Error creating DNA Cluster\n");
    return(-1);
  }

  /* Changing the default settings (experts only) */
  dna_cluster_low_level_settings(dna_cluster_handle, 
    queue_len,                              /* slave rx queue slots */
    mode != recv_only_mode ? queue_len : 0, /* slave tx queue slots */
    frwd_device ? frwd_buffers : 0   /* slave additional buffers (available with  alloc/release) */
  );

  if (use_hugepages) {
    if (dna_cluster_set_hugepages_mountpoint(dna_cluster_handle, hugepages_mountpoint) < 0) {
      trace(TRACE_ERROR, "Error setting the hugepages mountpoint: did you mount it?\n");
      return(-1);
    }
  }

  /* Setting the cluster mode */
  dna_cluster_set_mode(dna_cluster_handle, mode);

  dev = strtok_r(device, ",", &dev_pos);
  while(dev != NULL) {
    pd[num_dev] = pfring_open(dev, caplen, PF_RING_PROMISC);
    if(pd[num_dev] == NULL) {
      trace(TRACE_ERROR, "pfring_open %s error [%s]\n", dev, strerror(errno));
      return(-1);
    }

    if (num_dev == 0) {
      pfring_version(pd[num_dev], &version);
      trace(TRACE_NORMAL, "Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16, 
	     (version & 0x0000FF00) >> 8, version & 0x000000FF);
    }

    snprintf(buf, sizeof(buf), "dna-cluster-%d-socket-%d", cluster_id, num_dev);
    pfring_set_application_name(pd[num_dev], buf);

    /* Add the ring we created to the cluster */
    if (dna_cluster_register_ring(dna_cluster_handle, pd[num_dev]) < 0) {
      trace(TRACE_ERROR, "Error registering rx socket\n");
      dna_cluster_destroy(dna_cluster_handle);
      return -1;
    }

    num_dev++;

    dev = strtok_r(NULL, ",", &dev_pos);

    if (num_dev == MAX_NUM_DEV && dev != NULL) {
      trace(TRACE_ERROR, "Too many devices\n");
      break;
    }
  }

  if (num_dev == 0) {
    dna_cluster_destroy(dna_cluster_handle);
    printHelp();
  }

  /* Setting up important details... */
  dna_cluster_set_wait_mode(dna_cluster_handle, !wait_for_packet /* active_wait */);
  dna_cluster_set_cpu_affinity(dna_cluster_handle, rx_bind_core, tx_bind_core);
  if (time_pulse_thread) dna_cluster_time_pulse_settings(dna_cluster_handle, time_pulse_bind_core, time_pulse_resolution);

  switch(hashing_mode) {
  case 0:
    trace(TRACE_NORMAL, "Hashing packets per-IP Address\n");
    /* The default distribution function already balances per IP in a coherent mode */
    if (num_apps > 1) dna_cluster_set_distribution_function(dna_cluster_handle, multi_app_distribution_function);
    break;
  case 1:
    trace(TRACE_NORMAL, "Hashing packets per-MAC Address\n");
    if (num_apps > 1) dna_cluster_set_distribution_function(dna_cluster_handle, multi_app_distribution_function);
    else dna_cluster_set_distribution_function(dna_cluster_handle, master_distribution_function);
    break;
  case 2:
    trace(TRACE_NORMAL, "Hashing packets per-IP protocol (TCP, UDP, ICMP...)\n");
    if (num_apps > 1) dna_cluster_set_distribution_function(dna_cluster_handle, multi_app_distribution_function);
    else dna_cluster_set_distribution_function(dna_cluster_handle, master_distribution_function);
    break;
  case 3:
    trace(TRACE_NORMAL, "Replicating each packet on all applications (no copy)\n");
    dna_cluster_set_distribution_function(dna_cluster_handle, fanout_distribution_function);
    break;
  case 4:
    trace(TRACE_NORMAL, "Hashing packets using 5-tuple\n");
    dna_cluster_set_distribution_function(dna_cluster_handle, multi_app_distribution_function);
    break;
  }

  /* Now enable the cluster */
  if (dna_cluster_enable(dna_cluster_handle) < 0) {
    trace(TRACE_ERROR, "Error enabling the engine; dna NICs already in use?\n");
    dna_cluster_destroy(dna_cluster_handle);
    return -1;
  }

#if 0
  snprintf(buf, sizeof(buf), "ClusterId:    %d\n", cluster_id);
  snprintf(&buf[strlen(buf)], sizeof(buf)-strlen(buf), "TotQueues:    %d\n", tot_num_slaves);
  snprintf(&buf[strlen(buf)], sizeof(buf)-strlen(buf), "Applications: %d\n", num_apps);
  for (i = 0; i < num_apps; i++)
    snprintf(&buf[strlen(buf)], sizeof(buf)-strlen(buf), "App%dQueues:   %d\n", i, instances_per_app[i]);

  pfring_set_application_stats(pd[0], buf);
#endif

  trace(TRACE_NORMAL, "The DNA cluster [id: %u][num slave apps: %u] is now running...\n", 
	 cluster_id, tot_num_slaves);
  trace(TRACE_NORMAL, "You can now attach to the cluster up to %d slaves as follows:\n", 
         tot_num_slaves);
  if (num_apps == 1) {
    trace(TRACE_NORMAL, "\tpfcount -i dnacluster:%d\n", cluster_id);
  } else {
    off = 0;
    for (i = 0; i < num_apps; i++) {
      trace(TRACE_NORMAL, "Application %u\n", i);
      for (j = 0; j < instances_per_app[i]; j++)
        trace(TRACE_NORMAL, "\tpfcount -i dnacluster:%d@%u\n", cluster_id, off++);
    }
  }

  if (username && !use_hugepages)
    drop_privileges(username);

  if (pidFileName)
    create_pid_file(pidFileName);

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);
  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  if (frwd_device) {
    pthread_t fwdrthread;
    if (register_frwd_socket() < 0) {
      sigproc(0);
    } else {
      pthread_create(&fwdrthread, NULL, frwd_thread, NULL);
      trace(TRACE_NORMAL, "Forwarder thread is running...\n");
      pthread_join(fwdrthread, NULL);
    }
  }

  while (!do_shutdown) sleep(1); /* do something in the main */
 
  dna_cluster_destroy(dna_cluster_handle);

  if (frwd_device)
    pfring_close(frwd_out_ring);

  if(pidFileName)
    remove_pid_file(pidFileName);

  sleep(2);
  return(0);
}

