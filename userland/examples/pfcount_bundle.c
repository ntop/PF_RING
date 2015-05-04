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
#define DEFAULT_DEVICE     "eth0"

pfring *ring[MAX_NUM_BUNDLE_ELEMENTS];
pfring_bundle bundle;
int verbose = 0;
pfring_stat pfringStats;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
u_int8_t wait_for_packet = 1, dna_mode = 0, do_shutdown = 0, num_ring;

/* ******************************** */

void print_stats() {
  int i;
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts[MAX_NUM_BUNDLE_ELEMENTS] = { 0 };
  u_int64_t diff, tot_pkts, tot_drops;
  static struct timeval lastTime;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  tot_pkts = tot_drops = 0;
  for(i=0; i<bundle.num_sockets; i++)  {
    if(pfring_stats(ring[i], &pfringStat) >= 0) {
      if(print_all && (lastTime.tv_sec > 0)) {
	deltaMillisec = delta_time(&endTime, &lastTime);
	diff = pfringStat.recv-lastPkts[i];
	tot_pkts += diff, tot_drops += pfringStat.drop;
	fprintf(stderr, "[%d] Actual Stats: %llu pkts [%.1f ms][%.1f pkt/sec][%llu drops]\n",
		i, (long long unsigned int)diff,
		deltaMillisec, ((double)diff/(double)(deltaMillisec/1000)),
		(long long unsigned int)pfringStat.drop);
      }
      
      lastPkts[i] = pfringStat.recv;
    }
  }
  
  fprintf(stderr, "\nAggregate Stats:  %llu pkts [%.1f ms][%.1f pkt/sec][%llu drops]\n",
	  (long long unsigned int)tot_pkts,
	  deltaMillisec, ((double)tot_pkts/(double)(deltaMillisec/1000)),
	  (long long unsigned int)tot_drops);

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n");
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();

  pfring_bundle_close(&bundle);

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
    struct ether_header ehdr;
    u_short eth_type, vlan_id;
    char buf1[32], buf2[32];
    struct ip ip;
    int s;
    u_int usec;
    u_int nsec = 0;

    if(h->ts.tv_sec == 0) {
      memset((void*)&h->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
      pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 4, 1, 1);
    }

    s = (h->ts.tv_sec + thiszone) % 86400;

    if (h->extended_hdr.timestamp_ns) {
      /* be careful with drifts mixing sys time and hw timestamp */
      usec = (h->extended_hdr.timestamp_ns / 1000) % 1000000;
      nsec = h->extended_hdr.timestamp_ns % 1000;
    } else {
      usec = h->ts.tv_usec;
    }

    printf("%02d:%02d:%02d.%06u%03u ",
	   s / 3600, (s % 3600) / 60, s % 60,
	   usec, nsec);

#if 0
    for(i=0; i<32; i++)
      printf("%02X ", p[i]);

    printf("\n");
#endif

    if(h->extended_hdr.parsed_header_len > 0) {
      printf("[eth_type=0x%04X]", h->extended_hdr.parsed_pkt.eth_type);
      printf("[l3_proto=%u]", (unsigned int)h->extended_hdr.parsed_pkt.l3_proto);
      
      printf("[%s:%d -> ", (h->extended_hdr.parsed_pkt.eth_type == 0x86DD) ? 
	     in6toa(h->extended_hdr.parsed_pkt.ipv6_src) : intoa(h->extended_hdr.parsed_pkt.ipv4_src), 
	     h->extended_hdr.parsed_pkt.l4_src_port);
      printf("%s:%d] ", (h->extended_hdr.parsed_pkt.eth_type == 0x86DD) ? 
	     in6toa(h->extended_hdr.parsed_pkt.ipv6_dst) : intoa(h->extended_hdr.parsed_pkt.ipv4_dst), 
	     h->extended_hdr.parsed_pkt.l4_dst_port);
      
      printf("[%s -> %s] ",
	     etheraddr_string(h->extended_hdr.parsed_pkt.smac, buf1),
	     etheraddr_string(h->extended_hdr.parsed_pkt.dmac, buf2));
    }

    memcpy(&ehdr, p+h->extended_hdr.parsed_header_len, sizeof(struct ether_header));
    eth_type = ntohs(ehdr.ether_type);

    printf("[%s -> %s][eth_type=0x%04X] ",
	   etheraddr_string(ehdr.ether_shost, buf1),
	   etheraddr_string(ehdr.ether_dhost, buf2), eth_type);


    if(eth_type == 0x8100) {
      vlan_id = (p[14] & 15)*256 + p[15];
      eth_type = (p[16])*256 + p[17];
      printf("[vlan %u] ", vlan_id);
      p+=4;
    }

    if(eth_type == 0x0800) {
      memcpy(&ip, p+h->extended_hdr.parsed_header_len+sizeof(ehdr), sizeof(struct ip));
      printf("[%s]", proto2str(ip.ip_p));
      printf("[%s:%d ", intoa(ntohl(ip.ip_src.s_addr)), h->extended_hdr.parsed_pkt.l4_src_port);
      printf("-> %s:%d] ", intoa(ntohl(ip.ip_dst.s_addr)), h->extended_hdr.parsed_pkt.l4_dst_port);

      printf("[tos=%d][tcp_seq_num=%u][caplen=%d][len=%d][parsed_header_len=%d]"
	     "[eth_offset=%d][l3_offset=%d][l4_offset=%d][payload_offset=%d]\n",
	     h->extended_hdr.parsed_pkt.ipv4_tos, h->extended_hdr.parsed_pkt.tcp.seq_num,
	     h->caplen, h->len, h->extended_hdr.parsed_header_len,
	     h->extended_hdr.parsed_pkt.offset.eth_offset,
	     h->extended_hdr.parsed_pkt.offset.l3_offset,
	     h->extended_hdr.parsed_pkt.offset.l4_offset,
	     h->extended_hdr.parsed_pkt.offset.payload_offset);
      
    } else {
      if(eth_type == 0x0806)
	printf("[ARP]");
      else
	printf("[eth_type=0x%04X]", eth_type);

      printf("[caplen=%d][len=%d][parsed_header_len=%d]"
	     "[eth_offset=%d][l3_offset=%d][l4_offset=%d][payload_offset=%d]\n",
	     h->caplen, h->len, h->extended_hdr.parsed_header_len,
	     h->extended_hdr.parsed_pkt.offset.eth_offset,
	     h->extended_hdr.parsed_pkt.offset.l3_offset,
	     h->extended_hdr.parsed_pkt.offset.l4_offset,
	     h->extended_hdr.parsed_pkt.offset.payload_offset);
    }
  }

  numPkts++, numBytes += h->len;
}

/* *************************************** */

void printHelp(void) {
  printf("pfcount\n(C) 2005-14 ntop.org\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device names (comma-separated list). Use device@channel for channels\n");

  /* printf("-f <filter>     [pfring filter]\n"); */

  printf("-e <direction>  0=RX+TX, 1=RX only, 2=TX only\n");
  printf("-s <string>     String to search on packets\n");
  printf("-l <len>        Capture length\n");
  printf("-w <watermark>  Watermark\n");
  printf("-b <cpu %%>      CPU pergentage priority (0-99)\n");
  printf("-g <core_id>    Bind this app to a core\n");
  printf("-r              Rehash RSS packets\n");
  printf("-a              Active packet wait\n");
  printf("-q              Set FIFO policy (Default: Round Robin)\n");
  printf("-v              Verbose\n");
}

/* *************************************** */

void* packet_consumer(void) {
  u_char* buffer;

  while(1) {
    struct pfring_pkthdr hdr;

    if(do_shutdown) break;
    
    if(pfring_bundle_read(&bundle, &buffer, 0, &hdr, wait_for_packet) > 0) {
      if(do_shutdown) break;
      dummyProcesssPacket(&hdr, buffer, 0);
    } else {
      /* usleep(100); */
    }
  }
  
  return(NULL);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c, *dev, *pos = NULL, *separator = ";,";
  int snaplen = DEFAULT_SNAPLEN;
  u_int16_t watermark = 0;
  bundle_read_policy bundle_policy = pick_round_robin;
  u_int32_t version;
  int bind_core = -1, flags = PF_RING_PROMISC;

  startTime.tv_sec = 0;
  thiszone = gmt_to_local(0);

  while((c = getopt(argc,argv,"hi:dl:vaw:qg:")) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'v':
      flags |= PF_RING_LONG_HEADER;
      watermark = 1;
      verbose = 1;
      break;
      /*
	case 'f':
	bpfFilter = strdup(optarg);
	break;
      */
    case 'w':
      watermark = atoi(optarg);
      break;
    case 'q':
      bundle_policy = pick_fifo;   
    }
  }

  if(device == NULL) device = strdup(DEFAULT_DEVICE);

  bind2node(bind_core);

  printf("Capturing from bundle %s\n", device);
  
  dev = strtok_r(device, separator, &pos);
  num_ring = 0;
  pfring_bundle_init(&bundle, bundle_policy);

  while(dev != NULL) {
    printf("Adding %s to bundle\n", dev);

    ring[num_ring] = pfring_open(dev, snaplen, flags);

    if(ring[num_ring] == NULL) {
      printf("pfring_open error [%s] (perhaps you use quick mode and have already a socket bound to %s ?)\n", 
	     strerror(errno), dev);
      return(-1);
    } 
    
    pfring_set_application_name(ring[num_ring], "pfcount_bundle");
    pfring_version(ring[num_ring], &version);

    if(ring[num_ring]->next_pkt_time == NULL) {
      if(bundle_policy == pick_fifo) {
	printf("FIFO policy has been disabled as %s does not support TS for ordering packets\n", dev);
	bundle.policy = pick_round_robin;
      }
    }

    if(watermark > 0) {
      int rc;

      if((rc = pfring_set_poll_watermark(ring[num_ring], watermark)) != 0)
	printf("pfring_set_poll_watermark returned [rc=%d][watermark=%d]\n", rc, watermark);
    }

    pfring_set_direction(ring[num_ring], rx_only_direction);
    pfring_bundle_add(&bundle, ring[num_ring]);

    num_ring++;    
    dev = strtok_r(NULL, separator, &pos);
  }
  
  printf("Using PF_RING v.%d.%d.%d\n",
	 (version & 0xFFFF0000) >> 16,
	 (version & 0x0000FF00) >> 8,
	 version & 0x000000FF);

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  if(bind_core >= 0)
    bind2core(bind_core);

  packet_consumer();

  pfring_bundle_close(&bundle);

  return(0);
}
