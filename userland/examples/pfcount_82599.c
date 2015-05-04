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
#include <sys/poll.h>
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
#define DEFAULT_DEVICE     "eth0"
pfring  *pd;
int verbose = 0, num_threads = 1;
pfring_stat pfringStats;
pthread_rwlock_t statsLock;

static struct timeval startTime;
unsigned long long numPkts[MAX_NUM_THREADS] = { 0 }, numBytes[MAX_NUM_THREADS] = { 0 };
u_int8_t wait_for_packet = 1, dna_mode = 0, do_shutdown = 0;
u_int8_t use_extended_pkt_header = 0;

/* ******************************** */

void print_stats() {
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  u_int64_t diff;
  static struct timeval lastTime;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  if(pfring_stats(pd, &pfringStat) >= 0) {
    double thpt;
    int i;
    unsigned long long nBytes = 0, nPkts = 0;

    for(i=0; i < num_threads; i++) {
      nBytes += numBytes[i];
      nPkts += numPkts[i];
    }

    thpt = ((double)8*nBytes)/(deltaMillisec*1000);

    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
	    "Total Pkts=%u/Dropped=%.1f %%\n",
	    (unsigned int)pfringStat.recv, (unsigned int)pfringStat.drop,
	    (unsigned int)(pfringStat.recv+pfringStat.drop),
	    pfringStat.recv == 0 ? 0 :
	    (double)(pfringStat.drop*100)/(double)(pfringStat.recv+pfringStat.drop));
    fprintf(stderr, "%llu pkts - %llu bytes", nPkts, nBytes);

    if(print_all)
      fprintf(stderr, " [%.1f pkt/sec - %.2f Mbit/sec]\n",
	      (double)(nPkts*1000)/deltaMillisec, thpt);
    else
      fprintf(stderr, "\n");

    if(print_all && (lastTime.tv_sec > 0)) {
      deltaMillisec = delta_time(&endTime, &lastTime);
      diff = pfringStat.recv-lastPkts;
      fprintf(stderr, "=========================\n"
	      "Actual Stats: %llu pkts [%.1f ms][%.1f pkt/sec]\n",
	      (long long unsigned int)diff,
	      deltaMillisec, ((double)diff/(double)(deltaMillisec/1000)));
    }

    lastPkts = pfringStat.recv;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n\n");
}

/* ******************************** */

void add_rule(u_int add_rule) {
#if 0
  hash_filtering_rule rule;

  memset(&rule, 0, sizeof(hash_filtering_rule));
  /* 09:40:01.158112 IP 192.168.1.233.2736 > 192.168.99.1.25: Flags [P.], seq 1070303040:1070303070, ack 3485710921, win 65461, length 30 */
  rule.proto = 6, rule.rule_id = 10; rule.rule_action = dont_forward_packet_and_stop_rule_evaluation;
  rule.host4_peer_a = ntohl(inet_addr("192.168.1.233"));
  rule.host4_peer_b = ntohl(inet_addr("192.168.99.1"));

  if(pfring_handle_hash_filtering_rule(pd, &rule, add_rule) < 0)
    printf("pfring_add_hash_filtering_rule(1) failed\n");

  rule.proto = 6, rule.rule_id = 11; rule.rule_action = dont_forward_packet_and_stop_rule_evaluation;
  rule.host4_peer_a = ntohl(inet_addr("192.168.1.233"));
  rule.host4_peer_b = ntohl(inet_addr("192.168.99.1"));

  if(pfring_handle_hash_filtering_rule(pd, &rule, add_rule) < 0)
    printf("pfring_add_hash_filtering_rule(2) failed\n");
#else
  filtering_rule rule;

  memset(&rule, 0, sizeof(rule));

  rule.rule_id = 5;
  rule.rule_action = forward_packet_and_stop_rule_evaluation;
  rule.core_fields.sport_low = 80, rule.core_fields.sport_high = 80;

  if(pfring_add_filtering_rule(pd, &rule) < 0)
    printf("pfring_add_hash_filtering_rule(2) failed\n");
  else
    printf("Rule added successfully...\n");
#endif
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  if(0) {
    add_rule(0);
    printf("Removing filter\n");
  }

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();

  if(num_threads == 1)
    pfring_close(pd);

  exit(0);
}

/* ******************************** */

void my_sigalarm(int sig) {
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ****************************************************** */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ************************************ */

char* intoa(unsigned int addr) {
  static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

  return(_intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

inline char* in6toa(struct in6_addr addr6) {
  static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

  snprintf(buf, sizeof(buf),
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	   addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
	   addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
	   addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
	   addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
	   addr6.s6_addr[15]);

  return(buf);
}

/* ****************************************************** */

char* proto2str(u_short proto) {
  static char protoName[8];

  switch(proto) {
  case IPPROTO_TCP:  return("TCP");
  case IPPROTO_UDP:  return("UDP");
  case IPPROTO_ICMP: return("ICMP");
  default:
    snprintf(protoName, sizeof(protoName), "%d", proto);
    return(protoName);
  }
}

/* ****************************************************** */

static int32_t thiszone;

void dummyProcesssPacket(const struct pfring_pkthdr *h, const u_char *p, long threadId) {
  if(verbose) {
    struct ether_header *ehdr;
    char buf1[32], buf2[32];
    int s;
    uint usec;
    uint nsec=0;

    if(h->ts.tv_sec == 0) {
      memset((void*)&h->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
      pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 5, 1, 1);
    }

    s = (h->ts.tv_sec + thiszone) % 86400;

    if(h->extended_hdr.timestamp_ns) {
      /* be careful with drifts mixing sys time and hw timestamp */
      usec = (h->extended_hdr.timestamp_ns / 1000) % 1000000;
      nsec = h->extended_hdr.timestamp_ns % 1000;
    } else {
      usec = h->ts.tv_usec;
    }

    printf("%02d:%02d:%02d.%06u%03u ",
	   s / 3600, (s % 3600) / 60, s % 60,
	   usec, nsec);

    ehdr = (struct ether_header *) p;

    if(use_extended_pkt_header) {

      printf("%s[if_index=%d]",
        h->extended_hdr.rx_direction ? "[RX]" : "[TX]",
        h->extended_hdr.if_index);

      printf("[%s -> %s] ",
	     etheraddr_string(h->extended_hdr.parsed_pkt.smac, buf1),
	     etheraddr_string(h->extended_hdr.parsed_pkt.dmac, buf2));    

      if(h->extended_hdr.parsed_pkt.offset.vlan_offset)
	printf("[vlan %u] ", h->extended_hdr.parsed_pkt.vlan_id);

      if (h->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/ || h->extended_hdr.parsed_pkt.eth_type == 0x86DD /* IPv6*/) {

        if(h->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/ ) {
	  printf("[IPv4][%s:%d ", intoa(h->extended_hdr.parsed_pkt.ipv4_src), h->extended_hdr.parsed_pkt.l4_src_port);
	  printf("-> %s:%d] ", intoa(h->extended_hdr.parsed_pkt.ipv4_dst), h->extended_hdr.parsed_pkt.l4_dst_port);
        } else {
          printf("[IPv6][%s:%d ",    in6toa(h->extended_hdr.parsed_pkt.ipv6_src), h->extended_hdr.parsed_pkt.l4_src_port);
          printf("-> %s:%d] ", in6toa(h->extended_hdr.parsed_pkt.ipv6_dst), h->extended_hdr.parsed_pkt.l4_dst_port);
        }

	printf("[l3_proto=%s]", proto2str(h->extended_hdr.parsed_pkt.l3_proto));

	if(h->extended_hdr.parsed_pkt.tunnel.tunnel_id != NO_TUNNEL_ID) {
	  printf("[TEID=0x%08X][tunneled_proto=%s]", 
		 h->extended_hdr.parsed_pkt.tunnel.tunnel_id,
		 proto2str(h->extended_hdr.parsed_pkt.tunnel.tunneled_proto));

	  if(h->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/ ) {
	    printf("[IPv4][%s:%d ",
		   intoa(h->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v4),
		   h->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port);
	    printf("-> %s:%d] ", 
		   intoa(h->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v4),
		   h->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port);
	  } else {
	    printf("[IPv6][%s:%d ", 
		   in6toa(h->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6),
		   h->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port);
	    printf("-> %s:%d] ",
		   in6toa(h->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6),
		   h->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port);
	  }	  
	}

	printf("[hash=%u][tos=%d][tcp_seq_num=%u]",
	  h->extended_hdr.pkt_hash,
          h->extended_hdr.parsed_pkt.ipv4_tos, 
	  h->extended_hdr.parsed_pkt.tcp.seq_num);
	
      } else {
	if(h->extended_hdr.parsed_pkt.eth_type == 0x0806 /* ARP */)
	  printf("[ARP]");
	else
	  printf("[eth_type=0x%04X]", h->extended_hdr.parsed_pkt.eth_type);
      }

      printf(" [caplen=%d][len=%d][parsed_header_len=%d][eth_offset=%d][l3_offset=%d][l4_offset=%d][payload_offset=%d]\n",
        h->caplen, h->len, h->extended_hdr.parsed_header_len,
        h->extended_hdr.parsed_pkt.offset.eth_offset,
        h->extended_hdr.parsed_pkt.offset.l3_offset,
        h->extended_hdr.parsed_pkt.offset.l4_offset,
        h->extended_hdr.parsed_pkt.offset.payload_offset);

    } else {
      printf("[%s -> %s][eth_type=0x%04X][caplen=%d][len=%d] (use -m for details)\n",
	     etheraddr_string(ehdr->ether_shost, buf1),
	     etheraddr_string(ehdr->ether_dhost, buf2), 
	     ntohs(ehdr->ether_type),
	     h->caplen, h->len);
    }
  }

  numPkts[threadId]++, numBytes[threadId] += h->len;
}

/* *************************************** */

void printHelp(void) {
  printf("pfcount_82599\n(C) 2011-12 Deri Luca <deri@ntop.org>\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name. Use device@channel for channels\n");
  printf("-n <threads>    Number of polling threads (default %d)\n", num_threads);

  /* printf("-f <filter>     [pfring filter]\n"); */

  printf("-c <cluster id> cluster id\n");
  printf("-e <direction>  0=RX+TX, 1=RX only, 2=TX only\n");
  printf("-l <len>        Capture length\n");
  printf("-a              Active packet wait\n");
  printf("-v              Verbose\n");
}

/* *************************************** */

void* packet_consumer_thread(void* _id) {
  long thread_id = (long)_id;
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );

  if((num_threads > 1) && (numCPU > 1)) {
#ifdef HAVE_PTHREAD_SETAFFINITY_NP
    int s;
    /* Bind this thread to a specific core */
    cpu_set_t cpuset;
    u_long core_id = thread_id % numCPU;

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0)
      printf("Error while binding thread %ld to core %ld: errno=%i\n",
	     thread_id, core_id, s);
    else {
      printf("Set thread %lu on core %lu/%u\n", thread_id, core_id, numCPU);
    }
#endif
  }

  while(1) {
    struct simple_stats {
      u_int64_t num_pkts, num_bytes;
    };

    u_char *buffer;
    struct simple_stats stats;
    struct pfring_pkthdr hdr;
    int rc;
    u_int len;

    if(do_shutdown) break;

    if(pfring_recv(pd, &buffer, 0, &hdr, wait_for_packet) > 0) {
      if(do_shutdown) break;
      dummyProcesssPacket(&hdr, buffer, thread_id);

#ifdef TEST_SEND
      buffer[0] = 0x99;
      buffer[1] = 0x98;
      buffer[2] = 0x97;
      pfring_send(pd, buffer, hdr.caplen);
#endif
    }

    if(0) {
      len = sizeof(stats);
      rc = pfring_get_filtering_rule_stats(pd, 5, (char*)&stats, &len);
      if(rc < 0)
	printf("pfring_get_filtering_rule_stats() failed [rc=%d]\n", rc);
      else {
	printf("[Pkts=%u][Bytes=%u]\n",
	       (unsigned int)stats.num_pkts,
	       (unsigned int)stats.num_bytes);
      }
    }
  }

  return(NULL);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c;
  int flags = PF_RING_PROMISC, snaplen = DEFAULT_SNAPLEN, rc;
  u_int clusterId = 0;
  packet_direction direction = rx_only_direction;
  u_int16_t watermark = 0;

#if 0
  struct sched_param schedparam;

  schedparam.sched_priority = 99;
  if(sched_setscheduler(0, SCHED_FIFO, &schedparam) == -1) {
    printf("error while setting the scheduler, errno=%i\n", errno);
    exit(1);
  }

  mlockall(MCL_CURRENT|MCL_FUTURE);

#undef TEST_PROCESSOR_AFFINITY
#ifdef TEST_PROCESSOR_AFFINITY
  {
    unsigned long new_mask = 1;
    unsigned int len = sizeof(new_mask);
    unsigned long cur_mask;
    pid_t p = 0; /* current process */
    int ret;

    ret = sched_getaffinity(p, len, NULL);
    printf(" sched_getaffinity = %d, len = %u\n", ret, len);

    ret = sched_getaffinity(p, len, &cur_mask);
    printf(" sched_getaffinity = %d, cur_mask = %08lx\n", ret, cur_mask);

    ret = sched_setaffinity(p, len, &new_mask);
    printf(" sched_setaffinity = %d, new_mask = %08lx\n", ret, new_mask);

    ret = sched_getaffinity(p, len, &cur_mask);
    printf(" sched_getaffinity = %d, cur_mask = %08lx\n", ret, cur_mask);
  }
#endif
#endif

  startTime.tv_sec = 0;
  thiszone = gmt_to_local(0);

  while((c = getopt(argc,argv,"hi:c:l:vae:n:w:m")) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'e':
      switch(atoi(optarg)) {
      case rx_and_tx_direction:
      case rx_only_direction:
      case tx_only_direction:
	direction = atoi(optarg);
	break;
      }
      break;
    case 'c':
      clusterId = atoi(optarg);
      break;
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'n':
      num_threads = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'w':
      watermark = atoi(optarg);
      break;
    case 'm':
      use_extended_pkt_header = 1;
      break;
    }
  }

  if(device == NULL) device = DEFAULT_DEVICE;
  if(num_threads > MAX_NUM_THREADS) num_threads = MAX_NUM_THREADS;

  printf("Capturing from %s\n", device);

  if(num_threads > 0)
    pthread_rwlock_init(&statsLock, NULL);

  if(num_threads > 1) flags |= PF_RING_REENTRANT;
  if(use_extended_pkt_header) flags |= PF_RING_LONG_HEADER;

  pd = pfring_open(device, snaplen, flags | PF_RING_PROMISC | PF_RING_DNA_SYMMETRIC_RSS);

  if(pd == NULL) {
    printf("pfring_open error [%s]\n", strerror(errno));
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "pfcount_82599");
    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n",
	   (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8,
	   version & 0x000000FF);
  }

  printf("# Device RX channels: %d\n", pfring_get_num_rx_channels(pd));
  printf("# Polling threads:    %d\n", num_threads);

  if(clusterId > 0) {
    rc = pfring_set_cluster(pd, clusterId, cluster_round_robin);
    printf("pfring_set_cluster returned %d\n", rc);
  }

  if((rc = pfring_set_direction(pd, direction)) != 0)
    printf("pfring_set_direction returned %d (perhaps you use a direction other than rx only with DNA ?)\n", rc);

  if(watermark > 0) {
    if((rc = pfring_set_poll_watermark(pd, watermark)) != 0)
      printf("pfring_set_poll_watermark returned [rc=%d][watermark=%d]\n", rc, watermark);
  }


  if(0) {
    int rc, rule_id = 0;
    hw_filtering_rule rule;
    intel_82599_five_tuple_filter_hw_rule *ft_rule;

    printf("### FTFQ Rule Example ###\n");

    ft_rule = &rule.rule_family.five_tuple_rule;

    if(0) {
      memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_five_tuple_rule;
      rule.rule_id = rule_id++, ft_rule->queue_id = -1, ft_rule->proto = 17; /* udp */
      rc = pfring_add_hw_rule(pd, &rule);
      if(rc != 0)
	printf("pfring_add_hw_rule(%d) failed [rc=%d]\n", rule.rule_id, rc);
      else
	printf("pfring_add_hw_rule(%d) succeeded: dropping UDP traffic\n", rule.rule_id);
    }

    if(0) {
      memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_five_tuple_rule;
      rule.rule_id = rule_id++, ft_rule->queue_id = -1, ft_rule->proto = 6; /* tcp */
      rc = pfring_add_hw_rule(pd, &rule);
      if(rc != 0)
	printf("pfring_add_hw_rule(%d) failed [rc=%d]\n", rule.rule_id, rc);
      else
	printf("pfring_add_hw_rule(%d) succeeded: dropping TCP traffic\n", rule.rule_id);
    }

    if (0) {
      memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_five_tuple_rule;
      rule.rule_id = rule_id++, ft_rule->queue_id = -1, ft_rule->proto = 6, ft_rule->s_addr = ntohl(inet_addr("192.168.30.207"));
      rc = pfring_add_hw_rule(pd, &rule);
      if(rc != 0)
        printf("pfring_add_hw_rule(%d) failed [rc=%d]\n", rule.rule_id, rc);
      else
        printf("pfring_add_hw_rule(%d) succeeded: dropping TCP traffic 192.168.30.207 -> *\n", rule.rule_id);
    }

    if (0) {
      memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_five_tuple_rule;
      rule.rule_id = rule_id++, ft_rule->queue_id = -1, ft_rule->proto = 6, ft_rule->d_addr = ntohl(inet_addr("192.168.30.207"));
      rc = pfring_add_hw_rule(pd, &rule);
      if(rc != 0)
        printf("pfring_add_hw_rule(%d) failed [rc=%d]\n", rule.rule_id, rc);
      else
        printf("pfring_add_hw_rule(%d) succeeded: dropping TCP traffic * -> 192.168.30.207\n", rule.rule_id);
    }

    if (0) {
      memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_five_tuple_rule;
      rule.rule_id = rule_id++, ft_rule->queue_id = -1, ft_rule->proto = 0, ft_rule->d_addr = ntohl(inet_addr("192.168.30.207"));
      rc = pfring_add_hw_rule(pd, &rule);
      if(rc != 0)
        printf("pfring_add_hw_rule(%d) failed [rc=%d]\n", rule.rule_id, rc);
      else
        printf("pfring_add_hw_rule(%d) succeeded: dropping non-TCP/UDP traffic * -> 192.168.30.207\n", rule.rule_id);
    }
  }

  if(1) {
    int rc, rule_id = 0;
    hw_filtering_rule rule;
    intel_82599_perfect_filter_hw_rule *perfect_rule;

    printf("### Perfect Rule Example ###\n");
    /*
      NOTE:
      - valid protocols: UDP or TCP
     */
    perfect_rule = &rule.rule_family.perfect_rule;

    if(1) {
      memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_perfect_filter_rule;
      rule.rule_id = rule_id++, perfect_rule->queue_id = -1, perfect_rule->proto = 6,
	perfect_rule->s_addr = ntohl(inet_addr("192.168.30.207"));
      rc = pfring_add_hw_rule(pd, &rule);
      if(rc != 0)
	printf("pfring_add_hw_rule(%d) failed [rc=%d]: did you enable the FlowDirector (ethtool -K ethX ntuple on)\n", rule.rule_id, rc);
      else
	printf("pfring_add_hw_rule(%d) succeeded: dropping TCP traffic 192.168.30.207:* -> *\n", rule.rule_id);
    }


    if (1) {
      memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_perfect_filter_rule;
      rule.rule_id = rule_id++, perfect_rule->queue_id = -1, perfect_rule->proto = 17,
	perfect_rule->s_addr = ntohl(inet_addr("192.168.30.207"));
      rc = pfring_add_hw_rule(pd, &rule);
      if(rc != 0)
	printf("pfring_add_hw_rule(%d) failed [rc=%d]: did you enable the FlowDirector (ethtool -K ethX ntuple on)\n", rule.rule_id, rc);
      else
	printf("pfring_add_hw_rule(%d) succeeded: dropping UDP traffic 192.168.30.207:* -> *\n", rule.rule_id);
    }
  }

  if(0) {
    int rc, rule_id = 0;
    hw_filtering_rule rule;
    intel_82599_perfect_filter_hw_rule *perfect_rule;

    printf("### Perfect Rule Steering Example ###\n");
    /*
      NOTE:
      - valid protocols: UDP or TCP
     */
    perfect_rule = &rule.rule_family.perfect_rule;

    if(1) {
      memset(&rule, 0, sizeof(rule)), rule.rule_family_type = intel_82599_perfect_filter_rule;
      rule.rule_id = rule_id++, perfect_rule->queue_id = 1, perfect_rule->proto = 17,
	perfect_rule->s_addr = ntohl(inet_addr("5.6.7.9"));
      rc = pfring_add_hw_rule(pd, &rule);
      if(rc != 0)
	printf("pfring_add_hw_rule(%d) failed [rc=%d]: did you enable the FlowDirector (insmod ixgbe.ko FdirMode=2)\n", rule.rule_id, rc);
      else
	printf("pfring_add_hw_rule(%d) succeeded: steering UDP traffic 5.6.7.9:* -> * to queue #1\n", rule.rule_id);
    }
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);


  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  if(dna_mode)
    num_threads = 1;
  else {
    if(num_threads > 1) wait_for_packet = 1;
  }

  pfring_enable_ring(pd);

  if(0) {
    filtering_rule rule;

    memset(&rule, 0, sizeof(rule));

    rule.rule_id = 5;
    rule.rule_action = forward_packet_and_stop_rule_evaluation;
    rule.core_fields.sport_low = 80, rule.core_fields.sport_high = 80;

    if(pfring_add_filtering_rule(pd, &rule) < 0)
      printf("pfring_add_hash_filtering_rule(2) failed\n");
    else
      printf("Rule added successfully...\n");
  }

  if(0) {
    filtering_rule rule;

#define DUMMY_PLUGIN_ID   1

    memset(&rule, 0, sizeof(rule));

    rule.rule_id = 5;
    rule.rule_action = forward_packet_and_stop_rule_evaluation;
    rule.core_fields.proto = 6 /* tcp */;
    // rule.plugin_action.plugin_id = DUMMY_PLUGIN_ID; /* Dummy plugin */
    // rule.extended_fields.filter_plugin_id = DUMMY_PLUGIN_ID; /* Enable packet parsing/filtering */

    if(pfring_add_filtering_rule(pd, &rule) < 0)
      printf("pfring_add_hash_filtering_rule(2) failed\n");
    else
      printf("Rule added successfully...\n");
  }

  if(num_threads > 1) {
    pthread_t my_thread;
    long i;

    for(i=1; i<num_threads; i++)
      pthread_create(&my_thread, NULL, packet_consumer_thread, (void*)i);
  }

  packet_consumer_thread(0);

  pfring_close(pd);

  sleep(3);

  return(0);
}
