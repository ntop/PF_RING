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

#include "pfring.h"
//#include "pfutils.c"
#include "../../kernel/plugins/dummy_plugin.h"

#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 128
pfring  *pd;
int verbose = 0;
pfring_stat pfringStats;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;

#define DEFAULT_DEVICE "eth0"

/* *************************************** */

/*
 * The time difference in millisecond
 */
double delta_time (struct timeval * now,
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
  return((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

/* ******************************** */

void print_stats() {
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int64_t lastPkts = 0;
  u_int64_t diff;
  static struct timeval lastTime;

  if(startTime.tv_sec == 0) return;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  if(pfring_stats(pd, &pfringStat) >= 0)
    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
	    "Total Pkts=%u/Dropped=%.1f %%\n",
	    (unsigned int)pfringStat.recv, (unsigned int)pfringStat.drop,
	    (unsigned int)(pfringStat.recv-pfringStat.drop),
	    pfringStat.recv == 0 ? 0 : (double)(pfringStat.drop*100)/(double)pfringStat.recv);
  fprintf(stderr, "%llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
	  numPkts, (double)(numPkts*1000)/deltaMillisec,
	  numBytes, (double)8*numBytes/(double)(deltaMillisec));

  if(lastTime.tv_sec > 0) {
    deltaMillisec = delta_time(&endTime, &lastTime);
    diff = pfringStat.recv-lastPkts;
    fprintf(stderr, "=========================\n"
	    "Actual Stats: %llu pkts [%.1f ms][%.1f pkt/sec]\n",
	    (long long unsigned int)diff, deltaMillisec, 
	    ((double)diff/(double)(deltaMillisec/1000)));
  }

  lastPkts = pfringStat.recv;

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n");
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  if(called) return; else called = 1;

  print_stats();
  pfring_close(pd);
  exit(0);
}

/* ******************************** */

void my_sigalarm(int sig) {
  if(numPkts == 0) gettimeofday(&startTime, NULL);
  print_stats();
  printf("\n");
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


static int32_t thiszone;

/* ****************************************************** */

void dummyProcesssPacket(const struct pfring_pkthdr *h, u_char *p) {
  if(verbose) {
    struct ether_header ehdr;
    u_short eth_type, vlan_id;
    /* char buf1[32], buf2[32]; */
    struct ip ip;
    int s = (h->ts.tv_sec + thiszone) % 86400;

    if(1)
      printf("[%4u]", (unsigned int)(numPkts+1));
    else
      printf("[%4u] %02d:%02d:%02d.%06u ",
	     (unsigned int)(numPkts+1),
	     s / 3600, (s % 3600) / 60, s % 60,
	     (unsigned)h->ts.tv_usec);

    p[h->extended_hdr.parsed_header_len+h->caplen] = '\0';

    memcpy(&ehdr, p+h->extended_hdr.parsed_header_len, sizeof(struct ether_header));
    eth_type = ntohs(ehdr.ether_type);

    if(eth_type == 0x8100) {
      vlan_id = (p[14] & 15)*256 + p[15];
      eth_type = (p[16])*256 + p[17];
      printf("[vlan %u] ", vlan_id);
      p+=4;
    }
    if(eth_type == 0x0800) {
      memcpy(&ip, p+h->extended_hdr.parsed_header_len+sizeof(ehdr), sizeof(struct ip));
      printf("[%s:%d ", intoa(ntohl(ip.ip_src.s_addr)), h->extended_hdr.parsed_pkt.l4_src_port);
      printf("-> %s:%d]", intoa(ntohl(ip.ip_dst.s_addr)), h->extended_hdr.parsed_pkt.l4_dst_port);
    } else if(eth_type == 0x0806)
      printf("[ARP]");
    else
      printf("[eth_type=0x%04X]", eth_type);

    printf("[caplen=%d][len=%d]\n", h->caplen, h->len);
  }

  if(numPkts == 0) gettimeofday(&startTime, NULL);

  numPkts++, numBytes += h->len;
}

/* *************************************** */

void printHelp(void) {
  printf("pfcount\n(C) 2005-12 Deri Luca <deri@ntop.org>\n");
  printf("-h              [Print help]\n");
  printf("-i <device>     [Device name]\n");
  printf("-p <protocol>   [Dummy protocol filter (6=tcp, 17=udp, 1=icmp)]\n");
  printf("-v              [Verbose]\n");
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c;
  int add_rule = 1;
  u_int8_t protocol = 6 /* tcp */;
  filtering_rule rule;
  struct dummy_filter *filter;

  thiszone = gmt_to_local(0);

  while((c = getopt(argc,argv,"hi:c:vp:a" /* "f:" */)) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'p':
      protocol = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
      /*
	case 'f':
	bpfFilter = strdup(optarg);
	break;
      */
    }
  }

  if(device == NULL) device = DEFAULT_DEVICE;

  printf("Capturing from %s\n", device);

  if((pd = pfring_open(device, 1500, PF_RING_PROMISC)) == NULL) {
    printf("pfring_open error [%s]\n", strerror(errno));
    return(-1);
  } else {
    u_int32_t version;

    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n",
	   (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8,
	   version & 0x000000FF);
  }

  if(add_rule)
    pfring_toggle_filtering_policy(pd, 0); /* Default to drop */

  memset(&rule, 0, sizeof(rule));

  rule.rule_id = 5;
  rule.rule_action = forward_packet_and_stop_rule_evaluation;
  rule.core_fields.proto = 6 /* tcp */;
  rule.plugin_action.plugin_id = DUMMY_PLUGIN_ID; /* Dummy plugin */
  rule.extended_fields.filter_plugin_id = DUMMY_PLUGIN_ID; /* Enable packet parsing/filtering */
  filter = (struct dummy_filter*)rule.extended_fields.filter_plugin_data;
  filter->protocol = protocol; 

  if(add_rule) {
    if(pfring_add_filtering_rule(pd, &rule) < 0) {
      printf("pfring_add_filtering_rule() failed\n");
      return(-1);
    }
  }

  signal(SIGINT, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  pfring_enable_ring(pd);

  while(1) {
    u_char *buffer;
    struct pfring_pkthdr hdr;

    if(pfring_recv(pd, &buffer, 0, &hdr, 1) > 0)
      dummyProcesssPacket(&hdr, buffer);
  }

  pfring_close(pd);

  return(0);
}
