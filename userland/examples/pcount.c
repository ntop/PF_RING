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

#include <pcap/pcap.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>

#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 256
pcap_t  *pd;
int verbose = 0;
struct pcap_stat pcapStats;

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;

#define DEFAULT_DEVICE "eth1" /* "e1000" */

int32_t gmt_to_local(time_t t);
int pcap_set_cluster(pcap_t *ring, u_int clusterId);
int pcap_set_application_name(pcap_t *handle, char *name);
char* pfring_format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals);

/* *************************************** */
/*
 * The time difference in microseconds
 */
long delta_time (struct timeval * now,
                 struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }
  return((delta_seconds * 1000000) + delta_microseconds);
}

/* ******************************** */

void print_stats() {
  struct pcap_stat pcapStat;
  struct timeval endTime;
  float deltaSec;
  static u_int64_t lastPkts = 0;
  u_int64_t diff;
  static struct timeval lastTime;
  char buf1[64], buf2[64];

  if(startTime.tv_sec == 0) {
    lastTime.tv_sec = 0;
    gettimeofday(&startTime, NULL);
    return;
  }

  gettimeofday(&endTime, NULL);
  deltaSec = (double)delta_time(&endTime, &startTime)/1000000;

  if(pcap_stats(pd, &pcapStat) >= 0) {
    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
	    "Total Pkts=%u/Dropped=%.1f %%\n",
	    pcapStat.ps_recv, pcapStat.ps_drop, pcapStat.ps_recv-pcapStat.ps_drop,
	    pcapStat.ps_recv == 0 ? 0 : (double)(pcapStat.ps_drop*100)/(double)pcapStat.ps_recv);
    fprintf(stderr, "%llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
	    numPkts, (double)numPkts/deltaSec,
	    numBytes, (double)8*numBytes/(double)(deltaSec*1000000));

    if(lastTime.tv_sec > 0) {
      deltaSec = (double)delta_time(&endTime, &lastTime)/1000000;
      diff = numPkts-lastPkts;
      fprintf(stderr, "=========================\n"
	      "Actual Stats: %s pkts [%.1f ms][%s pkt/sec]\n",
	      pfring_format_numbers(diff, buf1, sizeof(buf1), 0), deltaSec*1000,
	      pfring_format_numbers(((double)diff/(double)(deltaSec)), buf2, sizeof(buf2), 1));
      lastPkts = numPkts;
    }

    fprintf(stderr, "=========================\n");
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  if(called) return; else called = 1;

  print_stats();
  pcap_close(pd);
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

void dummyProcesssPacket(u_char *_deviceId,
			 const struct pcap_pkthdr *h,
			 const u_char *p) {

  // printf("pcap_sendpacket returned %d\n", pcap_sendpacket(pd, p, h->caplen));

  if(verbose) {
    struct ether_header ehdr;
    u_short eth_type, vlan_id;
    char buf1[32], buf2[32];
    struct ip ip;
    struct ip6_hdr ip6;

    int s = (h->ts.tv_sec + thiszone) % 86400;

    printf("%02d:%02d:%02d.%06u ",
	   s / 3600, (s % 3600) / 60, s % 60,
	   (unsigned)h->ts.tv_usec);

    memcpy(&ehdr, p, sizeof(struct ether_header));
    eth_type = ntohs(ehdr.ether_type);
    printf("[%s -> %s] ",
	   etheraddr_string(ehdr.ether_shost, buf1),
	   etheraddr_string(ehdr.ether_dhost, buf2));

    if(eth_type == 0x8100) {
      vlan_id = (p[14] & 15)*256 + p[15];
      eth_type = (p[16])*256 + p[17];
      printf("[vlan %u] ", vlan_id);
      p+=4;
    }
    if(eth_type == 0x0800) {
      memcpy(&ip, p+sizeof(ehdr), sizeof(struct ip));
      printf("[%s]", proto2str(ip.ip_p));
      printf("[%s ", intoa(ntohl(ip.ip_src.s_addr)));
      printf("-> %s] ", intoa(ntohl(ip.ip_dst.s_addr)));
    } else if(eth_type == 0x86DD) {
      memcpy(&ip6, p+sizeof(ehdr), sizeof(struct ip6_hdr));
      printf("[%s ", in6toa(ip6.ip6_src));
      printf("-> %s] ", in6toa(ip6.ip6_dst));
    } else if(eth_type == 0x0806)
      printf("[ARP]");
    else
      printf("[eth_type=0x%04X]", eth_type);

    printf("[caplen=%u][len=%u]\n", h->caplen, h->len);
  }

  if(numPkts == 0) gettimeofday(&startTime, NULL);
  numPkts++, numBytes += h->len;

  if(verbose == 2) {
      int i;

      for(i = 0; i < h->caplen; i++)
        printf("%02X ", p[i]);
      printf("\n");
  }
 }

/* *************************************** */

void printHelp(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  printf("pcount\n(C) 2003-14 Deri Luca <deri@ntop.org>\n");
  printf("-h              [Print help]\n");
  printf("-i <device>     [Device name]\n");
  printf("-f <filter>     [pcap filter]\n");
  printf("-l <len>        [Capture length]\n");
  printf("-S              [Do not strip hw timestamps (if present)]\n");
  printf("-v <mode>       [Verbose [1: verbose, 2: very verbose (print packet payload)]]\n");

  if(pcap_findalldevs(&devpointer, errbuf) == 0) {
    int i = 0;

    printf("\nAvailable devices (-i):\n");
    while(devpointer) {
      printf(" %d. %s\n", i++, devpointer->name);
      devpointer = devpointer->next;
    }
  }
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c, *bpfFilter = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc, snaplen = DEFAULT_SNAPLEN;
  struct bpf_program fcode;
  u_int8_t dont_strip_hw_ts = 0;

#if 0
  struct sched_param schedparam;

  schedparam.sched_priority = 99;
  if(sched_setscheduler(0, SCHED_FIFO, &schedparam) == -1) {
    printf("error while setting the scheduler, errno=%i\n",errno);
    exit(1);
  }

  mlockall(MCL_CURRENT|MCL_FUTURE);

#define TEST_PROCESSOR_AFFINITY
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

  while((c = getopt(argc,argv,"hi:l:v:f:S")) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      exit(0);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'v':
      verbose = atoi(optarg);
      break;
    case 'f':
      bpfFilter = strdup(optarg);
      break;
    case 'S':
      dont_strip_hw_ts = 1;
      break;
    }
  }

  if(device == NULL) {
    if((device = pcap_lookupdev(errbuf)) == NULL) {
      printf("pcap_lookup: %s", errbuf);
      return(-1);
    }
  }

  if(!dont_strip_hw_ts) setenv("PCAP_PF_RING_STRIP_HW_TIMESTAMP", "1", 1);

  printf("Capturing from %s\n", device);

  /* hardcode: promisc=1, to_ms=500 */
  promisc = 1;
  if((pd = pcap_open_live(device, snaplen,
			  promisc, 500, errbuf)) == NULL) {
    printf("pcap_open_live: %s\n", errbuf);
    return(-1);
  }

  if(bpfFilter != NULL) {
    if(pcap_compile(pd, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(pd));
    } else {
      if(pcap_setfilter(pd, &fcode) < 0) {
	printf("pcap_setfilter error: '%s'\n", pcap_geterr(pd));
      }
    }
  }

  pcap_set_application_name(pd, "pcount");

  signal(SIGINT, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  pcap_set_watermark(pd, 128);

  pcap_loop(pd, -1, dummyProcesssPacket, NULL);
  pcap_close(pd);

  return(0);
}
