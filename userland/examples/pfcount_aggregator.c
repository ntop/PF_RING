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
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <monetary.h>
#include <locale.h>

#include "pfring.h"
#include "pfutils.c"

#define ALARM_SLEEP             1
#define DEFAULT_SNAPLEN       128
#define DEFAULT_DEVICE     "eth0"
#define MAX_NUM_DEVS           64
//#define VERBOSE_SUPPORT

pfring  *pd[MAX_NUM_DEVS];
struct pollfd pfd[MAX_NUM_DEVS];
int num_devs = 0;
#ifdef VERBOSE_SUPPORT
int verbose = 0;
#endif
pfring_stat pfringStats;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
u_int8_t wait_for_packet = 0, do_shutdown = 0;
int poll_duration = DEFAULT_POLL_DURATION;

/* ******************************** */

void print_stats() {
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  static u_int64_t lastBytes = 0;
  u_int64_t diff, bytesDiff;
  static struct timeval lastTime;
  char buf1[64], buf2[64], buf3[64];
  unsigned long long nBytes = 0, nPkts = 0;
  double thpt;
  int i = 0;
  unsigned long long absolute_recv = 0, absolute_drop = 0;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  for(i=0; i<num_devs; i++) {
    if(pfring_stats(pd[i], &pfringStat) >= 0) {
      absolute_recv = pfringStat.recv;
      absolute_drop = pfringStat.drop;
    }
  }

  nBytes = numBytes;
  nPkts  = numPkts;

  {
    thpt = ((double)8*nBytes)/(deltaMillisec*1000);

    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
	    "Total Pkts=%u/Dropped=%.1f %%\n",
	    (unsigned int)absolute_recv, (unsigned int)absolute_drop,
	    (unsigned int)(absolute_recv+absolute_drop),
	    absolute_recv == 0 ? 0 :
	    (double)(absolute_drop*100)/(double)(absolute_recv+absolute_drop));
    fprintf(stderr, "%s pkts - %s bytes", 
	    pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	    pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

    if(print_all)
      fprintf(stderr, " [%s pkt/sec - %s Mbit/sec]\n",
	      pfring_format_numbers((double)(nPkts*1000)/deltaMillisec, buf1, sizeof(buf1), 1),
	      pfring_format_numbers(thpt, buf2, sizeof(buf2), 1));
    else
      fprintf(stderr, "\n");

    if(print_all && (lastTime.tv_sec > 0)) {
      deltaMillisec = delta_time(&endTime, &lastTime);
      diff = nPkts-lastPkts;
      bytesDiff = nBytes - lastBytes;
      bytesDiff /= (1000*1000*1000)/8;

      fprintf(stderr, "=========================\n"
	      "Actual Stats: %llu pkts [%s ms][%s pps/%s Gbps]\n",
	      (long long unsigned int)diff,
	      pfring_format_numbers(deltaMillisec, buf1, sizeof(buf1), 1),
	      pfring_format_numbers(((double)diff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1),
	      pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)),  buf3, sizeof(buf3), 1)
	      );
    }

    lastPkts = nPkts, lastBytes = nBytes;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n\n");
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;
  int i = 0;

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
  print_stats();

  for(i=0; i<num_devs; i++)
    pfring_close(pd[i]);

  exit(0);
}

/* ******************************** */

void my_sigalarm(int sig) {
  if(do_shutdown)
    return;

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
  if((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if((j = *ep >> 4) != 0)
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
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
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

#ifdef VERBOSE_SUPPORT
static int32_t thiszone;

void verboseProcessing(const struct pfring_pkthdr *h, const u_char *p) {

    struct ether_header ehdr;
    u_short eth_type, vlan_id;
    char buf1[32], buf2[32];
    struct ip ip;
    int s;
    uint usec;
    uint nsec=0;

    if(h->ts.tv_sec == 0) {
      memset((void*)&h->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
      pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 4, 1, 1);
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

    if(h->extended_hdr.parsed_header_len > 0) {
      printf("[eth_type=0x%04X]", 
	     h->extended_hdr.parsed_pkt.eth_type);
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

    printf("[%s][if_index=%d][%s -> %s][eth_type=0x%04X] ",
	   h->extended_hdr.rx_direction ? "RX" : "TX",
	   h->extended_hdr.if_index,
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

      printf("[hash=%u][tos=%d][tcp_seq_num=%u][caplen=%d][len=%d][parsed_header_len=%d]"
	     "[eth_offset=%d][l3_offset=%d][l4_offset=%d][payload_offset=%d]\n",
	     h->extended_hdr.pkt_hash,
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
#endif

/* *************************************** */

void printHelp(void) {
  printf("pfaggregator\n(C) 2005-11 Deri Luca <deri@ntop.org>\n\n");
  printf("-h              Print this help\n");
  printf("-i <devices>    Plus-separated list of devices: ethX+ethY\n");
  printf("-e <direction>  0=RX+TX, 1=RX only, 2=TX only\n");
  printf("-l <len>        Capture length\n");
  printf("-g <core_id>    Bind to a core\n");
  printf("-w <watermark>  Watermark\n");
  printf("-p <poll wait>  Poll wait (msec)\n");
  printf("-b <cpu %%>      CPU pergentage priority (0-99)\n");
  printf("-s              Use poll instead of active wait\n");
#ifdef VERBOSE_SUPPORT
  printf("-v              Verbose\n");
#endif
}

/* *************************************** */

inline int bundlePoll() {
  int i;

  for(i=0; i<num_devs; i++) {
    pfring_sync_indexes_with_kernel(pd[i]);
    pfd[i].events  = POLLIN;
    pfd[i].revents = 0;
  }
  errno = 0;

  return poll(pfd, num_devs, poll_duration);
}

/* *************************************** */

void packetConsumer() {
  u_char *buffer;
  struct pfring_pkthdr hdr;
  memset(&hdr, 0, sizeof(hdr));
  int next = 0, hunger = 0;

  while (!do_shutdown) {

    if (pfring_is_pkt_available(pd[next])) {
      if (pfring_recv(pd[next], &buffer, 0, &hdr, 0 /* wait_for_packet */) > 0) {
#ifdef VERBOSE_SUPPORT
        if (verbose)
          verboseProcessing(&hdr, buffer);
#endif
        numPkts++;
	numBytes += hdr.len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;
      }

      hunger = 0;
    } else hunger++;
    
    if (wait_for_packet && hunger >= num_devs) {
      bundlePoll();
      hunger = 0;
    }

    next = (next+1) % num_devs;
  }
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *devices = NULL, *dev = NULL, *tmp = NULL;
  char c, buf[32];
  u_char mac_address[6] = { 0 };
  int snaplen = DEFAULT_SNAPLEN, rc;
  int bind_core = -1;
  packet_direction direction = rx_and_tx_direction;
  u_int16_t watermark = 0, cpu_percentage = 0;
  u_int32_t version;
  u_int32_t flags = 0;
  int i = 0;

  startTime.tv_sec = 0;
#ifdef VERBOSE_SUPPORT
  thiszone = gmt_to_local(0);
#endif

  while((c = getopt(argc,argv,"hi:l:vse:w:p:b:g:")) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 's':
      wait_for_packet = 1;
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
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'i':
      devices = strdup(optarg);
      break;
#ifdef VERBOSE_SUPPORT
    case 'v':
      verbose = 1;
      break;
#endif
    case 'w':
      watermark = atoi(optarg);
      break;
    case 'b':
      cpu_percentage = atoi(optarg);
      break;
    case 'p':
      poll_duration = atoi(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    }
  }

#ifdef VERBOSE_SUPPORT
  if(verbose)
    watermark = 1;
#endif

  if(devices == NULL) 
    devices = strdup(DEFAULT_DEVICE);

  bind2node(bind_core);

  if(wait_for_packet && (cpu_percentage > 0)) {
    if(cpu_percentage > 99) cpu_percentage = 99;
    pfring_config(cpu_percentage);
  }

  dev = strtok_r(devices, "+", &tmp);
  while(i<MAX_NUM_DEVS && dev != NULL) {
    flags |= PF_RING_PROMISC;
    flags |= PF_RING_DNA_SYMMETRIC_RSS;  /* Note that symmetric RSS is ignored by non-DNA drivers */
    pd[i] = pfring_open(dev, snaplen, flags);

    if(pd[i] == NULL) {
      fprintf(stderr, "pfring_open error [%s] (pf_ring not loaded or perhaps you use quick mode and have already a socket bound to %s ?)\n",
	      strerror(errno), dev);
      return(-1);
    } 

    if (i == 0) {
      pfring_version(pd[i], &version);

      printf("Using PF_RING v.%d.%d.%d\n",
	     (version & 0xFFFF0000) >> 16,
	     (version & 0x0000FF00) >> 8,
	     version & 0x000000FF);
    }
  
    pfring_set_application_name(pd[i], "pfaggregator");

    printf("Capturing from %s", dev);
    if(pfring_get_bound_device_address(pd[i], mac_address) == 0)
      printf(" [%s]\n", etheraddr_string(mac_address, buf));
    else
      printf("\n");

    printf("# Device RX channels: %d\n", pfring_get_num_rx_channels(pd[i]));

    if((rc = pfring_set_direction(pd[i], direction)) != 0)
      ; //fprintf(stderr, "pfring_set_direction returned [rc=%d][direction=%d]\n", rc, direction);

    if((rc = pfring_set_socket_mode(pd[i], recv_only_mode)) != 0)
      fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);

    if(watermark > 0) {
      if((rc = pfring_set_poll_watermark(pd[i], watermark)) != 0)
        fprintf(stderr, "pfring_set_poll_watermark returned [rc=%d][watermark=%d]\n", rc, watermark);
    }

    pfd[i].fd = pfring_get_selectable_fd(pd[i]);

    pfring_enable_ring(pd[i]);

    dev = strtok_r(NULL, "+", &tmp);
    i++;
  }
  num_devs = i;

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

#ifdef VERBOSE_SUPPORT
  if(!verbose) {
#endif
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
#ifdef VERBOSE_SUPPORT
  }
#endif

  if(bind_core >= 0)
    bind2core(bind_core);

  packetConsumer();

  alarm(0);
  sleep(1);

  for (i=0; i < num_devs; i++)
    pfring_close(pd[i]);

  return(0);
}
