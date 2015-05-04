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

#include <pcap.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>

#define ALARM_SLEEP       1
#define DEFAULT_SNAPLEN 256
pcap_t  *pd, *out_pd;
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
#include <pcap.h>


void dummyProcesssPacket(u_char *_deviceId,
			 const struct pcap_pkthdr *h,
			 const u_char *p) {
  printf("pcap_sendpacket returned %d\n", pcap_sendpacket(out_pd, p, h->caplen));
 }

/* *************************************** */

void printHelp(void) {

  printf("preflect\n(C) 2010 Deri Luca <deri@ntop.org>\n");
  printf("-h              [Print help]\n");
  printf("-i <device>     [In device name]\n");
  printf("-o <device>     [Out device name]\n");
  printf("-f <filter>     [pcap filter]\n");
  printf("-l <len>        [Capture length]\n");
  printf("-v              [Verbose]\n");
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, *out_device = NULL, c, *bpfFilter = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc, snaplen = DEFAULT_SNAPLEN;
  struct bpf_program fcode;

  while((c = getopt(argc,argv,"hi:o:l:vf:")) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      return(0);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'o':
      out_device = strdup(optarg);
      break;
    case 'l':
      snaplen = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'f':
      bpfFilter = strdup(optarg);
      break;
    }
  }

  if(out_device == NULL) {
    printHelp();
    return(-1);
  }

  if(device == NULL) {
    if((device = pcap_lookupdev(errbuf)) == NULL) {
      printf("pcap_lookup: %s", errbuf);
      return(-1);
    }
  }
  printf("Capturing from %s\n", device);

  /* hardcode: promisc=1, to_ms=500 */
  promisc = 1;
  if((pd = pcap_open_live(device, snaplen, promisc, 500, errbuf)) == NULL) {
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

  if((out_pd = pcap_open_live(out_device, snaplen, promisc, 500, errbuf)) == NULL) {
    printf("pcap_open_live: %s\n", errbuf);
    return(-1);
  }

  pcap_loop(pd, -1, dummyProcesssPacket, NULL);
  pcap_close(pd);

  return(0);
}
