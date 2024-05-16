/*
 * (C) 2024 - ntop
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
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <monetary.h>
#include <locale.h>

#include "pfring.h"

#include "pfutils.c"

#define ALARM_SLEEP      1
#define DEFAULT_DEVICE   "nt:0"
#define NO_ZC_BUFFER_LEN 9018
#define MAX_NUM_THREADS  64

pfring *pd = NULL;
int num_threads = 1;
static struct timeval startTime;
u_int8_t do_shutdown = 0, add_rules = 0, quiet = 0, verbose = 0;

struct app_stats {
  u_int64_t numPkts[MAX_NUM_THREADS];
  u_int64_t numBytes[MAX_NUM_THREADS];
};

struct app_stats *stats = NULL;

/* ************************************ */

void print_stats() {
  pfring_stat pfringStat;
  struct timeval endTime;
  double delta_last;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  static u_int64_t lastBytes = 0;
  double diff, bytesDiff;
  static struct timeval lastTime;
  char buf[256], buf1[64], buf2[64], buf3[64], buf4[64], timebuf[128];
  u_int64_t delta_abs;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  delta_last = delta_time(&endTime, &startTime);

  if(pfring_stats(pd, &pfringStat) >= 0) {
    double thpt;
    int i;
    unsigned long long nBytes = 0, nPkts = 0;

    for(i=0; i < num_threads; i++) {
      nBytes += stats->numBytes[i];
      nPkts += stats->numPkts[i];
    }

    delta_abs = delta_time(&endTime, &startTime);
    snprintf(buf, sizeof(buf),
             "Duration: %s\n"
             "Packets:  %lu\n"
             "Dropped:  %lu\n"
             "Bytes:    %lu\n",
             msec2dhmsm(delta_abs, timebuf, sizeof(timebuf)),
             (long unsigned int) nPkts,
             (long unsigned int) pfringStat.drop,
             (long unsigned int) nBytes);
    pfring_set_application_stats(pd, buf);

    thpt = ((double)8*nBytes)/(delta_last*1000);

    fprintf(stderr, "=========================\n"
	    "Absolute Stats: [%s pkts total][%s pkts dropped]",
	    pfring_format_numbers((double)(nPkts + pfringStat.drop), buf2, sizeof(buf2), 0),
	    pfring_format_numbers((double)(pfringStat.drop), buf3, sizeof(buf3), 0));

    fprintf(stderr, "[%.1f%% dropped]",
	    pfringStat.drop == 0 ? 0 : (double)(pfringStat.drop*100)/(double)(nPkts + pfringStat.drop));

    fprintf(stderr, "\n[%s %s rcvd][%s bytes rcvd]",
	    pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
            "pkts",
	    pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

    if(print_all)
      fprintf(stderr, "[%s %s/sec][%s Mbit/sec]\n",
	      pfring_format_numbers((double)(nPkts*1000)/delta_last, buf1, sizeof(buf1), 1),
              "pkt",
	      pfring_format_numbers(thpt, buf2, sizeof(buf2), 1));
    else
      fprintf(stderr, "\n");

    if(print_all && (lastTime.tv_sec > 0)) {
      delta_last = delta_time(&endTime, &lastTime);
      diff = nPkts-lastPkts;
      bytesDiff = nBytes - lastBytes;
      bytesDiff /= (1000*1000*1000)/8;

      snprintf(buf, sizeof(buf),
	      "Actual Stats: [%s %s rcvd][%s ms][%s %s][%s Gbps]",
	      pfring_format_numbers(diff, buf4, sizeof(buf4), 0),
              "pkts",
	      pfring_format_numbers(delta_last, buf1, sizeof(buf1), 1),
	      pfring_format_numbers(((double)diff/(double)(delta_last/1000)),  buf2, sizeof(buf2), 1),
              "pps",
	      pfring_format_numbers(((double)bytesDiff/(double)(delta_last/1000)),  buf3, sizeof(buf3), 1));

      fprintf(stderr, "=========================\n%s\n", buf);
    }

    lastPkts = nPkts, lastBytes = nBytes;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n\n");
}

/* ************************************ */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called) return; else called = 1;

  do_shutdown = 1;

  if (!quiet)
    print_stats();

  pfring_breakloop(pd);
}

/* ******************************** */

void processFlow(pfring_flow_update *flow){
  if (verbose) {
    switch (flow->cause) {
      case PF_RING_FLOW_UPDATE_CAUSE_SW:
        printf("Flow #%lu removed (by FlowWrite)\n", flow->flow_id);
        break;
      case PF_RING_FLOW_UPDATE_CAUSE_TIMEOUT:
        printf("Flow #%lu removed (timeout)\n", flow->flow_id);
        break;
      case PF_RING_FLOW_UPDATE_CAUSE_TCP_TERM:
        printf("Flow #%lu removed (TCP termination)\n", flow->flow_id);
        break;
      case PF_RING_FLOW_UPDATE_CAUSE_PROBE:
        printf("Flow #%lu removed (Software probe?)\n", flow->flow_id);
        break;
      default:
        printf("Flow #%lu removed: unknown cause\n", flow->flow_id);
        break;
    }
  }
}

/* ******************************** */

void processPacket(const struct pfring_pkthdr *h,
		   const u_char *p, const u_char *user_bytes) {
  char buffer[256];
  static u_int64_t flow_id = 0;
  int threadId = 0;

  stats->numPkts[threadId]++;
  stats->numBytes[threadId] += h->len+24 /* 8 Preamble + 4 CRC + 12 IFG */;

  if (verbose) {

    buffer[0] = '\0';
    pfring_print_pkt(buffer, sizeof(buffer), p, h->len, h->len);

    printf("%s ", buffer);

    if (h->extended_hdr.flags & PKT_FLAGS_FLOW_HIT) {
      printf("[HIT]");
    } else if (h->extended_hdr.flags & PKT_FLAGS_FLOW_MISS) {
      printf("[MISS]");
    } else if (h->extended_hdr.flags & PKT_FLAGS_FLOW_UNHANDLED) {
      printf("[UNHANDLED]");
    } else {
      printf("[-]");
    }

    printf("\n");
  }

  memset((void *) &h->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
  pfring_parse_pkt((u_char *) p, (struct pfring_pkthdr *) h, 5, 0, 1);

  /* Discard all future packets for this flow */

  if (add_rules && h->extended_hdr.parsed_pkt.ip_version == 4 /* TODO IPv6 */) {
    hw_filtering_rule rule = { 0 };
    generic_flow_tuple_hw_rule *r = &rule.rule_family.flow_tuple_rule;
    rule.rule_family_type = generic_flow_tuple_rule;

    r->action = ((add_rules == 1) ? flow_drop_rule : flow_pass_rule);
    r->flow_id = flow_id++;
    r->ip_version = h->extended_hdr.parsed_pkt.ip_version;
    r->src_ip.v4 = h->extended_hdr.parsed_pkt.ipv4_src;
    r->dst_ip.v4 = h->extended_hdr.parsed_pkt.ipv4_dst;
    r->src_port = h->extended_hdr.parsed_pkt.l4_src_port;
    r->dst_port = h->extended_hdr.parsed_pkt.l4_dst_port;
    r->protocol = h->extended_hdr.parsed_pkt.l3_proto; 

    if (pfring_add_hw_rule(pd, &rule) < 0) {
      fprintf(stderr, "pfring_add_hw_rule failure\n");
    }
  }
}

/* *************************************** */

void packet_consumer() {
  u_char buffer[NO_ZC_BUFFER_LEN];
  u_char *buffer_p = buffer;
  struct pfring_pkthdr hdr;
  pfring_flow_update flow;

  memset(&hdr, 0, sizeof(hdr));
  memset(&flow, 0, sizeof(flow));

  while(!do_shutdown) {

#if 0
    while (!do_shutdown && pfring_recv_flow(pd, &flow, 0) > 0) {
      /* Process flow */
      processFlow(&flow);
    }
#endif

    if (pfring_recv(pd, &buffer_p, NO_ZC_BUFFER_LEN, &hdr, 0) > 0) {
      /* Process packet */
      processPacket(&hdr, buffer, NULL);
    } else {
      if (do_shutdown)
        break;

      usleep(1);
      //sched_yield();
    }
  }
}

/* *************************************** */

void printHelp(void) {
  printf("pfflow_offload - (C) 2024 ntop\n");
  printf("Flow processing based on hardware offload (Napatech Flow Manager)\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name. Use:\n");
  printf("-r <1|2>        Add hardware flow rules to Drop (1) or Pass (2) packets\n");
  printf("-v              Verbose\n");
  printf("-q              Quiet\n");
}

/* *************************************** */

void my_sigalarm(int sig) {
  if (do_shutdown)
    return;

  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c;
  int promisc, snaplen = 1518, rc;
  u_int32_t flags = 0;
  int bind_core = -1;
  packet_direction direction = rx_only_direction;

  flags |= PF_RING_FLOW_OFFLOAD;

  while ((c = getopt(argc,argv,"g:hi:r:vq")) != '?') {
    if ((c == 255) || (c == -1)) break;

    switch(c) {
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'h':
      printHelp();
      exit(0);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'r':
      add_rules = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case 'q':
      quiet = 1;
      break;
    }
  }

  if (device == NULL) device = DEFAULT_DEVICE;

  bind2node(bind_core);

  if ((stats = calloc(1, sizeof(struct app_stats))) == NULL)
    return -1;

  promisc = 1;

  if (promisc) flags |= PF_RING_PROMISC;

  pd = pfring_open(device, snaplen, flags);

  if (pd == NULL) {
    fprintf(stderr, "pfring_open error [%s] (pf_ring not loaded or interface %s is down ?)\n",
      strerror(errno), device);
    return (-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "pfflow");
    pfring_version(pd, &version);

    if (!quiet) {
      printf("Using PF_RING v.%d.%d.%d\n",
       (version & 0xFFFF0000) >> 16,
       (version & 0x0000FF00) >> 8,
       version & 0x000000FF); 
    }
  }

  pfring_set_direction(pd, direction);

  if ((rc = pfring_set_socket_mode(pd, recv_only_mode)) != 0)
    fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  startTime.tv_sec = 0;

  if(!verbose && !quiet) {
    signal(SIGALRM, my_sigalarm);
    alarm(ALARM_SLEEP);
  }

 if (pfring_enable_ring(pd) != 0) {
    printf("Unable to enable ring :-(\n");
    pfring_close(pd);
    return (-1);
  }

  if (bind_core >= 0)
    bind2core(bind_core);

  packet_consumer();

  sleep(1);

  pfring_close(pd);

  return 0;
}
