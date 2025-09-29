/*
 * (C) 2003-25 - ntop 
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include "pfutils.c"

#define ALARM_SLEEP       1
#define DEFAULT_PACKET_LEN 256
#define MAX_PACKET_LEN 1536

pcap_t  *pd;
int packet_len = DEFAULT_PACKET_LEN;
static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
int verbose = 0;
volatile int do_shutdown = 0;

char* pfring_format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals);

/* ******************************** */

void print_stats() {
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
  deltaSec = (double)delta_time(&endTime, &startTime)/1000;

  fprintf(stderr, "=========================\n"
          "Absolute Stats: %llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
	  numPkts, (double)numPkts/deltaSec,
	  numBytes, (double)8*numBytes/(double)(deltaSec*1000));

  if(lastTime.tv_sec > 0) {
    deltaSec = (double)delta_time(&endTime, &lastTime)/1000;
    diff = numPkts-lastPkts;
    fprintf(stderr, "=========================\n"
	    "Actual Stats: %s pkts [%.1f ms][%s pkt/sec]\n",
	    pfring_format_numbers(diff, buf1, sizeof(buf1), 0), deltaSec*1000,
	    pfring_format_numbers(((double)diff/(double)(deltaSec)), buf2, sizeof(buf2), 1));
    lastPkts = numPkts;
  }

  fprintf(stderr, "=========================\n");

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called) return; else called = 1;

  do_shutdown = 1;
  pcap_breakloop(pd);
}

/* ******************************** */

void my_sigalarm(int sig) {
  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* *************************************** */

void sendPackets() {
  unsigned char packet[MAX_PACKET_LEN];
  int rc;

  while (!do_shutdown) {

    forge_udp_packet(packet, packet_len, numPkts /* pkt index */, 4 /* IP version */);

    rc = pcap_sendpacket(pd, packet, packet_len);

    if (rc != 0) {
      //fprintf(stderr, "Error sending the packet: %s (%d)\n", pcap_geterr(pd), rc);
    } else {
      numPkts++;
      numBytes += packet_len;
    }

  }
}

/* *************************************** */

void printHelp(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  printf("pcount\n(C) 2003-25 ntop\n");
  printf("-h              Print help\n");
  printf("-i <device>     Device name\n");
  printf("-l <len>        Packet length (default: %u)\n", DEFAULT_PACKET_LEN);
  printf("-v <mode>       Verbose (1: verbose, 2: very verbose)\n");

  if(pcap_findalldevs(&devpointer, errbuf) == 0) {
    int i = 0;

    printf("\nAvailable devices (-i):\n");
    while(devpointer) {
      printf(" %d. %s [%s]\n", i++, devpointer->name, devpointer->description);
      devpointer = devpointer->next;
    }

    pcap_freealldevs(devpointer);
  }
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL;
  char c;
  char errbuf[PCAP_ERRBUF_SIZE];
  int promisc; 

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"hi:l:v:")) != '?') {
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
      packet_len = atoi(optarg);
      if (packet_len > MAX_PACKET_LEN) packet_len = MAX_PACKET_LEN;
      break;
    case 'v':
      verbose = atoi(optarg);
      break;
    }
  }

  if (device == NULL) {
    printHelp();
    exit(-1);
  }

  printf("Sending to %s\n", device);

  promisc = 1;

  pd = pcap_open_live(device, packet_len, promisc, 1000 /* ms */, errbuf);

  if (pd == NULL) {
    printf("pcap_open_live: %s\n", errbuf);
    return(-1);
  }

  pcap_set_application_name(pd, "psend");

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

  sendPackets();

  print_stats();

  pcap_close(pd);

  return(0);
}

