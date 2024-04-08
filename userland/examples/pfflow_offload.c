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

#define DEFAULT_DEVICE   "nt:0"
#define NO_ZC_BUFFER_LEN 9018

pfring *pd = NULL;
u_int8_t do_shutdown = 0, wait_for_packet = 1, quiet = 0, verbose = 0;

/* ************************************ */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called) return; else called = 1;

  do_shutdown = 1;

  pfring_breakloop(pd);
}

/* ******************************** */

void processFlow(pfring_flow_update *flow){
  if (!quiet) {
    printf("Flow Update ID = %lu\n", flow->flow_id);
  }
}

/* ******************************** */

void processPacket(const struct pfring_pkthdr *h,
		   const u_char *p, const u_char *user_bytes) {
  char buffer[256];

  if (h->extended_hdr.flags & PKT_FLAGS_FLOW_HIT) {
    //TODO
  } else if (h->extended_hdr.flags & PKT_FLAGS_FLOW_MISS) {
    //TODO
  } else if (h->extended_hdr.flags & PKT_FLAGS_FLOW_UNHANDLED) {
    //TODO
  }

  if (!quiet) {
    buffer[0] = '\0';
    pfring_print_pkt(buffer, sizeof(buffer), p, h->len, h->len);
  }

#if 0
  /* TODO Discard all future packets for this flow */
  hw_filtering_rule r;
  r.rule_family_type = generic_flow_id_rule;
  r.rule_family.flow_id_rule.action = flow_drop_rule;
  r.rule_family.flow_id_rule.thread = 0;
  r.rule_family.flow_id_rule.flow_id = flow_id;
  pfring_add_hw_rule(pd, &r);
#endif
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

    while (!do_shutdown && pfring_recv_flow(pd, &flow, 0) > 0) {
      /* Process flow */
      processFlow(&flow);
    }

    if (pfring_recv(pd, &buffer_p, NO_ZC_BUFFER_LEN, &hdr, 0) > 0) {
      /* Process packet */
      processPacket(&hdr, buffer, NULL);
    } else {
      if (do_shutdown)
        break;

      sched_yield();
    }
  }
}

/* *************************************** */

void printHelp(void) {
  printf("pfflow_offload - (C) 2024 ntop\n");
  printf("Flow processing based on hardware offload (Napatech Flow Manager)\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name. Use:\n");
  printf("-r              Disable raw packets (flow updates only)\n");
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c;
  int promisc, snaplen = 1518, rc;
  u_int32_t flags = 0;
  int bind_core = -1;
  packet_direction direction = rx_only_direction;

  flags |= PF_RING_FLOW_OFFLOAD;

  while ((c = getopt(argc,argv,"ag:hi:")) != '?') {
    if ((c == 255) || (c == -1)) break;

    switch(c) {
    case 'a':
      wait_for_packet = 0;
      break;
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
    }
  }

  if (device == NULL) device = DEFAULT_DEVICE;
  bind2node(bind_core);

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

 if (pfring_enable_ring(pd) != 0) {
    printf("Unable to enable ring :-(\n");
    pfring_close(pd);
    return (-1);
  }

  if (bind_core >= 0)
    bind2core(bind_core);

  //pfring_loop(pd, processPacket, (u_char*)NULL, wait_for_packet);
  packet_consumer();

  sleep(1);

  pfring_close(pd);

  return 0;
}
