/*
 * (C) 2017 - ntop
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

#define DEFAULT_DEVICE     "anic:0"
#define NO_ZC_BUFFER_LEN   9000

pfring *pd;
int verbose = 0, num_threads = 1;
u_int8_t wait_for_packet = 1;

/* ************************************ */

static char *_intoa(unsigned int addr, char* buf, u_short bufLen) {
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

  retStr = (char*)(cp+1);

  return (retStr);
}

/* ************************************ */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called) return; else called = 1;

  pfring_breakloop(pd);
}

/* ******************************** */

void processPacket(const u_char *p, int len, u_int32_t flow_id) {
  char buffer[256];
  hw_filtering_rule r;

  buffer[0] = '\0';
  pfring_print_pkt(buffer, sizeof(buffer), p, len, len);
  printf("Raw Packet with flowID = %u %s", flow_id, buffer);

  /* Discarding all future packets for this flow */

  r.rule_family_type = generic_flow_id_rule;

  /* Note: you can also specify 'flow_mark_rule' here to mark all packets for this flow, 
   * you can check the marker with (h->extended_hdr.flags & PKT_FLAGS_FLOW_OFFLOAD_MARKER) */
  r.rule_family.flow_id_rule.action = flow_drop_rule;

  r.rule_family.flow_id_rule.thread = 0;
  r.rule_family.flow_id_rule.flow_id = flow_id;

  pfring_add_hw_rule(pd, &r);
}

/* ******************************** */

void processFlow(generic_flow_update *flow){
  char buf1[30], buf2[30];
  char *ip1, *ip2;

  if (flow->ip_version == 4){
    ip1 = _intoa(flow->src_ip.v4, buf1, sizeof(buf1));
    ip2 = _intoa(flow->dst_ip.v4, buf2, sizeof(buf2));
  } else {
    ip1 = (char *) inet_ntop(AF_INET6, &flow->src_ip.v6.s6_addr, buf1, sizeof(buf1));
    ip2 = (char *) inet_ntop(AF_INET6, &flow->dst_ip.v6.s6_addr, buf2, sizeof(buf2));
  }

  printf("Flow Update: flowID = %u "
         "srcIp = %s dstIp = %s srcPort = %u dstPort = %u protocol = %u tcpFlags = 0x%02X "
         "fwd: Packets = %u Bytes = %u FirstTime = %ju LastTime = %ju "
         "rev: Packets = %u Bytes = %u FirstTime = %ju LastTime = %ju\n",
	 flow->flow_id, ip1, ip2, flow->src_port, flow->dst_port, flow->l4_protocol, flow->tcp_flags,
         flow->fwd_packets, flow->fwd_bytes, flow->fwd_ts_first>>32, flow->fwd_ts_last >>32, 
         flow->rev_packets, flow->rev_bytes, flow->rev_ts_first>>32, flow->rev_ts_last>>32);
}

/* ******************************** */

void processBuffer(const struct pfring_pkthdr *h,
		   const u_char *p, const u_char *user_bytes) {

  if (h->extended_hdr.flags & PKT_FLAGS_FLOW_OFFLOAD_UPDATE) {
    processFlow((generic_flow_update *) p);
  } else {
    processPacket(p, h->len, h->extended_hdr.pkt_hash);
  }
}

/* *************************************** */

void printHelp(void) {
  printf("pfflow - (C) 2005-17 ntop.org\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name. Use:\n");
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c;
  int promisc, snaplen = 1518, rc;
  u_int32_t flags = 0;
  int bind_core = -1;
  packet_direction direction = rx_only_direction;

  while ((c = getopt(argc,argv,"hi:ag:")) != '?') {
    if ((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      exit(0);
      break;
    case 'a':
      wait_for_packet = 0;
      break;
   case 'i':
      device = strdup(optarg);
      break;
   case 'g':
      bind_core = atoi(optarg);
      break;
    }
  }

  if (device == NULL) device = DEFAULT_DEVICE;
  bind2node(bind_core);

  promisc = 1;

  if (promisc) flags |= PF_RING_PROMISC;
  flags |= PF_RING_FLOW_OFFLOAD;

  pd = pfring_open(device, snaplen, flags);

  if (pd == NULL) {
    fprintf(stderr, "pfring_open error [%s] (pf_ring not loaded or interface %s is down ?)\n",
      strerror(errno), device);
    return (-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "pfcount");
    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n",
     (version & 0xFFFF0000) >> 16,
     (version & 0x0000FF00) >> 8,
     version & 0x000000FF);
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

  pfring_loop(pd, processBuffer, (u_char*)NULL, wait_for_packet);

  sleep(1);

  pfring_close(pd);

  return 0;
}
