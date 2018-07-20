/*
 * (C) 2003-2018 - ntop 
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
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <monetary.h>
#include <locale.h>

#include "pfring.h"

#define DEFAULT_SNAPLEN      1536

pfring *pd;
char *out_pcap_file = NULL;
pcap_dumper_t *dumper = NULL;
int quiet = 1;

u_int64_t num_pkts;
u_int64_t num_bytes;

u_int8_t do_shutdown = 0;

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  if (!quiet)
    fprintf(stderr, "Leaving...\n");

  if (called) return; else called = 1;
  do_shutdown = 1;

  pfring_breakloop(pd);
}

/* ****************************************************** */

void process_packet(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes) {
  num_pkts++;
  num_bytes += h->len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;

  if (!h->ts.tv_sec) 
    gettimeofday(&((struct pfring_pkthdr *) h)->ts, NULL);

  pcap_dump((u_char*)dumper, (struct pcap_pkthdr *) h, p);
  pcap_dump_flush(dumper);
}

/* *************************************** */

void print_help(void) {
  time_t timer;
  char time_buffer_start[26], time_buffer_end[26];
  struct tm* tm_info;

  time(&timer);
  tm_info = localtime(&timer);
  strftime(time_buffer_end, sizeof(time_buffer_end), "%Y-%m-%d %H:%M:%S", tm_info);
  timer -= 5 * 60;
  tm_info = localtime(&timer);
  strftime(time_buffer_start, sizeof(time_buffer_start), "%Y-%m-%d %H:%M:%S", tm_info);

  printf("pftimeline - (C) 2018 ntop.org\n");
  printf("Extract traffic from a n2disk timeline using the PF_RING API\n\n");
  printf("-h              Print this help\n");
  printf("-t <path>       Timeline path\n");
  printf("-b <start>      Start date and time\n");
  printf("-e <end>        End date and time\n");
  printf("-f <filter>     BPF filter\n");
  printf("-o <path>       Output file path (default: -)\n");
  printf("\nExample: pftimeline -t /storage -b \"%s\" -e \"%s\" -f \"host 192.168.1.1\" -o - | tshark -i -\n", 
         time_buffer_start, time_buffer_end);
}

/* *************************************** */

void close_dump() {
  if (dumper != NULL) {
    pcap_dump_close(dumper);
    dumper = NULL;
  }
}

/* *************************************** */

void open_dump() {
  char path[256];

  close_dump();

  if (out_pcap_file != NULL && strcmp(out_pcap_file, "-") != 0)
    snprintf(path, sizeof(path), "%s", out_pcap_file);
  else 
    snprintf(path, sizeof(path), "-");

  dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */), path);

  if (dumper == NULL) {
    fprintf(stderr, "Unable to create dump file %s\n", path);
    exit(-1);
  }
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char device[256];
  char *timeline = NULL, *begin = NULL, *end = NULL;
  char c;
  int snaplen = DEFAULT_SNAPLEN;
  int rc;
  u_int32_t flags = 0;
  char *bpf_filter = NULL, *filter;
  u_int32_t version;

  while((c = getopt(argc,argv,"ht:f:b:e:o:")) != '?') {
    if ((c == 255) || (c == -1)) break;

    switch(c) {
    case 'b':
      begin = strdup(optarg);
      break;
    case 'e':
      end = strdup(optarg);
      break;
    case 'f':
      bpf_filter = strdup(optarg);
      break;
    case 'h':
      print_help();
      exit(0);
      break;
    case 't':
      timeline = strdup(optarg);
      break;
    case 'o':
      out_pcap_file = strdup(optarg);
      if (strcmp(out_pcap_file, "-") != 0)
        quiet = 0;
      break;
    }
  }

  if (timeline == NULL || 
      begin == NULL ||
      end == NULL) {
    print_help();
    exit(-1);
  }

  filter = (char *) malloc((bpf_filter ? strlen(bpf_filter) : 0)
                           + strlen(begin) + strlen(end) + 32);

  if (filter == NULL) {
    fprintf(stderr, "Unable to allocate memory");
    exit(-1);
  }

  filter[0] = '\0';

  if (bpf_filter) 
    sprintf(filter, "%s and ", bpf_filter);

  sprintf(&filter[strlen(filter)], "start %s and end %s", begin, end);

  open_dump();

  snprintf(device, sizeof(device), "timeline:%s", timeline);

  pd = pfring_open(device, snaplen, flags);

  if (pd == NULL) {
    fprintf(stderr, "pfring_open error [%s] (pf_ring not loaded or interface %s is down ?)\n",
	    strerror(errno), device);
    exit(-1);
  }

  pfring_set_application_name(pd, "pftimeline");
  pfring_version(pd, &version);

  if (!quiet)
    printf("Using PF_RING v.%d.%d.%d\n",
           (version & 0xFFFF0000) >> 16,
           (version & 0x0000FF00) >> 8,
           version & 0x000000FF);

  rc = pfring_set_bpf_filter(pd, filter);

  if (rc != 0) {
    fprintf(stderr, "pfring_set_bpf_filter(%s) returned %d\n", filter, rc);
    exit(-1);
  } else if (!quiet) {
    printf("Successfully set filter '%s'\n", filter);
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  if (pfring_enable_ring(pd) != 0) {
    fprintf(stderr, "Unable to enable ring :-(\n");
    pfring_close(pd);
    exit(-1);
  }

  pfring_loop(pd, process_packet, (u_char *) NULL, 1);

  pfring_close(pd);

  close_dump();

  if (!quiet)
    printf("%ju packets %ju bytes extracted\n", num_pkts, num_bytes);

  return 0;
}

