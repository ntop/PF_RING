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
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "pfring.h"
#include "pfutils.c"

#define ALARM_SLEEP             1

pfring_stat pfringStats;
char *in_dev = NULL, *out_dev = NULL;
int in_ifindex, out_ifindex;
u_int8_t wait_for_packet = 1, do_shutdown = 0;
static struct timeval startTime;
int mode = 0;
int bidirectional = 0;
int cluster_id = -1;
int flush = 0;
int print_interface_stats = 0;
pfring *pd1, *pd2, *pdb1, *pdb2;
pfring_dna_bouncer *bouncer_handle = NULL, *bouncer_handle2;
u_int numCPU;
int bind_core[2];
struct dir_info {
  u_int64_t __padding __attribute__((__aligned__(64)));
  u_int64_t numPkts;
  u_int64_t numBytes __attribute__((__aligned__(64)));
};
struct dir_info dir_stats[2];

u_int8_t handle_ts_card = 0;

/* ******************************** */

void print_stats() {
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  static u_int64_t lastBytes = 0;
  double diff, bytesDiff;
  static struct timeval lastTime;
  char buf1[64], buf2[64], buf3[64];
  unsigned long long nBytes = 0, nPkts = 0;
  double thpt;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  nBytes = dir_stats[0].numBytes + dir_stats[1].numBytes;
  nPkts  = dir_stats[0].numPkts + dir_stats[1].numPkts;

  {
    thpt = ((double)8*nBytes)/(deltaMillisec*1000);

    fprintf(stderr, "---\nAbsolute Stats: %s pkts - %s bytes", 
	    pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	    pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

    if(print_all)
      fprintf(stderr, " [%s pkt/sec - %s Mbit/sec]\n",
	      pfring_format_numbers((double)(nPkts*1000)/deltaMillisec, buf1, sizeof(buf1), 1),
	      pfring_format_numbers(thpt, buf2, sizeof(buf2), 1));
    else
      fprintf(stderr, "\n");

    if (print_interface_stats) {
      pfring_stat if_stats;

      if (pfring_stats(pd1, &if_stats) >= 0)
        fprintf(stderr, "                %s RX %" PRIu64 " pkts Dropped %" PRIu64 " pkts (%.1f %%)\n", 
                mode == 1 ? "Consumer Queue" : pd1->device_name, if_stats.recv, if_stats.drop,
		if_stats.recv == 0 ? 0 : ((double)(if_stats.drop*100)/(double)(if_stats.recv + if_stats.drop)));

      if (mode == 0 && bidirectional) {
        if (pfring_stats(bidirectional == 2 ? pdb1 : pd2, &if_stats) >= 0)
          fprintf(stderr, "                %s RX %" PRIu64 " pkts Dropped %" PRIu64 " pkts (%.1f %%)\n", 
                  (bidirectional == 2 ? pdb1 : pd2)->device_name, if_stats.recv, if_stats.drop,
		  if_stats.recv == 0 ? 0 : ((double)(if_stats.drop*100)/(double)(if_stats.recv + if_stats.drop)));
      }
    }

    if(print_all && (lastTime.tv_sec > 0)) {
      deltaMillisec = delta_time(&endTime, &lastTime);
      diff = nPkts-lastPkts;
      bytesDiff = nBytes - lastBytes;
      bytesDiff /= (1000*1000*1000)/8;

      fprintf(stderr, "Actual Stats: %llu pkts [%s ms][%s pps/%s Gbps]\n",
	      (long long unsigned int)diff,
	      pfring_format_numbers(deltaMillisec, buf1, sizeof(buf1), 1),
	      pfring_format_numbers(((double)diff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1),
	      pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)),  buf3, sizeof(buf3), 1)
	      );
    }

    lastPkts = nPkts, lastBytes = nBytes;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* ******************************** */

void my_sigalarm(int sig) {
  if(do_shutdown) {
    exit(0);
  }

  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;

  switch (mode) {
  case 0: 
    pfring_dna_bouncer_breakloop(bouncer_handle);
    if (bidirectional == 2)
      pfring_dna_bouncer_breakloop(bouncer_handle2);
  break;
  case 1:
  case 2: 
    pfring_breakloop(pd1);
  break;
  }
}

/* *************************************** */

void printHelp(void) {
 printf("pfdnabounce - (C) 2011-12 ntop.org\n");
 printf("\nForward traffic from -a -> -b device using DNA\n\n");

  printf("pfdnabounce [-v] [-a] -i in_dev\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name (RX)\n");
  printf("-o <device>     Device name (TX)\n");
  printf("-m <mode>       Specifies the library support to use\n"
	 "                0 - DNA Bouncer (default)\n"
	 "                1 - DNA Cluster (use -c <id>)\n"
	 "                2 - Standard DNA\n");
  printf("-c <id>         DNA Cluster id\n");
  printf("-b <mode>       Bridge mode (forward in both directions):\n"
         "                0 - disabled (default)\n"
         "                1 - single thread (DNA Cluster and Bouncer only)\n"
         "                2 - two threads, one per direction (DNA Bouncer only)\n");
  printf("-f              Flush packets immediately (do not use watermarks)\n");
  printf("-g <core id>    Bind this app to a core (with -b 2 use <core id>:<core id>)\n");
  printf("-a              Active packet wait\n");
  printf("-p              Print per-interface absolute stats\n");
  exit(0);
}

/* *************************************** */

int dummyProcessPacketZero(u_int32_t *pkt_len, u_char *pkt, const u_char *user_bytes, u_int8_t direction) {
  struct dir_info *di;
  u_int32_t len = *pkt_len;

#ifdef DEBUG
    int i = 0;
    for(i=0; i<32; i++) printf("%02X ", pkt[i]);
    printf("\n");
#endif

  if(unlikely(handle_ts_card)) {
    u_int8_t ts_len = 0;
    switch(pkt[len-1]) {
      case 0xC3: ts_len = 9; break;
      case 0xC2: ts_len = 5; break;
    }
    // printf("ts_len: %u\n", ts_len);
    len -= ts_len;
  }

  if (bidirectional == 2)
    di = (struct dir_info *) user_bytes;
  else
    di = &dir_stats[direction];

#if 0 /* change something inside the packet */
  {
    u_int16_t *nshort2 = (u_int16_t *) (&pkt[16]);
    u_int16_t *nshort3 = (u_int16_t *) (&pkt[18]);
    u_int16_t newhshort3 = ntohs(*nshort2) + 1;
    //printf(" [>] Changing 0x%04X 0x%04X\n", ntohs(*nshort2), ntohs(*nshort3));
    *nshort2 = *nshort3;
    *nshort3 = htons(newhshort3);
    //printf("to 0x%04X 0x%04X\n", ntohs(*nshort2), ntohs(*nshort3));
  }
#endif

#if 0 /* print the packet */
  {
    char bigbuf[4096];
    int buflen = 0;
    buflen += snprintf(&bigbuf[buflen], sizeof(bigbuf) - buflen, "[Dir %d]", direction);
    pfring_print_pkt(&bigbuf[buflen], sizeof(bigbuf) - buflen, pkt, len, len);
    fputs(bigbuf, stdout);
  }
#endif

  di->numPkts++;
  di->numBytes += len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;

  *pkt_len = len;
  return DNA_BOUNCER_PASS;
}

/* *************************************** */

void packetConsumerLoopZeroCluster() { 
  struct pfring_pkthdr h;
  int tx_ifindex;
  pfring_pkt_buff *pkt_handle = NULL;

  memset(&h, 0, sizeof(h));

  if ((pkt_handle = pfring_alloc_pkt_buff(pd1)) == NULL) {
    printf("Error allocating pkt buff\n");
    return;
  }

  while (!do_shutdown) {
    if (pfring_recv_pkt_buff(pd1, pkt_handle, &h, wait_for_packet) > 0) {

      if (bidirectional && h.extended_hdr.if_index == in_ifindex)
        tx_ifindex = out_ifindex;
      else if (bidirectional && h.extended_hdr.if_index == out_ifindex)
        tx_ifindex = in_ifindex;
      else if (!bidirectional && h.extended_hdr.if_index == in_ifindex)
        tx_ifindex = out_ifindex;
      else {
        /* unexpected packet, skipping */
        printf("Unexpected packet from interface %d: skipping\n", h.extended_hdr.if_index);
        continue;
      }

      if (pfring_set_pkt_buff_ifindex(pd1, pkt_handle, tx_ifindex) == PF_RING_ERROR_INVALID_ARGUMENT) {
        printf("Wrong interface id: skipping packet\n");
        continue;
      }

      pfring_send_pkt_buff(pd1, pkt_handle, flush);
    }

    dir_stats[(h.extended_hdr.if_index == out_ifindex)].numPkts++;
    dir_stats[(h.extended_hdr.if_index == out_ifindex)].numBytes += h.len + 24 /* 8 Preamble + 4 CRC + 12 IFG */; 
  }
}

/* *************************************** */

void dummyProcessPacket(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes) { 

#ifdef DEBUG
    int i = 0;
    for(i=0; i<32; i++) printf("%02X ", p[i]);
    printf("\n");
#endif

  pfring_send(pd2, (char*)p, h->caplen, flush);

  dir_stats[0].numPkts++;
  dir_stats[0].numBytes += h->len + 24 /* 8 Preamble + 4 CRC + 12 IFG */; 
}

/* *************************************** */

void* bouncer_dir2_thread(void *data) {
  if (bind_core[1] >= 0)
    bind2core(bind_core[1]);

  if(pfring_dna_bouncer_loop(bouncer_handle2, dummyProcessPacketZero, (u_char *) &dir_stats[1], wait_for_packet) == -1) {
    printf("Problems while starting bouncer. See dmesg for details.\n");
    exit(-1);
  }
  return NULL;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  char buf[32];
  char *bind_mask = NULL;
  u_int32_t version;
  pthread_t pthread2;

  bind_core[0] = bind_core[1] = -1;

  dir_stats[0].numPkts  = dir_stats[1].numPkts = 0;
  dir_stats[0].numBytes = dir_stats[1].numBytes = 0;

  numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"hai:o:m:b:c:g:fpt")) != -1) {
    switch(c) {
    case 'h':
      printHelp();      
      break;
    case 'a':
      wait_for_packet = 0;
      break;
    case 'i':
      in_dev = strdup(optarg);
      break;
    case 'o':
      out_dev = strdup(optarg);
      break;
    case 'm':
      mode = atoi(optarg);
      break;
    case 'c':
      cluster_id = atoi(optarg);
      break;
    case 'b':
      bidirectional = atoi(optarg);
      break;
    case 'f':
      flush = 1;
      break;
    case 'g':
      bind_mask = strdup(optarg);
      break;
    case 'p':
      print_interface_stats = 1;
      break;
    case 't':
      handle_ts_card = 1;
      break;
    }
  }

  if (in_dev == NULL)  printHelp();
  if (out_dev == NULL) out_dev = strdup(in_dev);
  if (mode < 0 || mode > 2) printHelp();
  if (bidirectional < 0 || bidirectional > 2) printHelp();
  if (bidirectional == 1 && mode != 0 && mode != 1) printHelp();
  if (bidirectional == 2 && mode != 0) printHelp();
  if (bidirectional && strcmp(in_dev, out_dev) == 0) printHelp();
  if (mode == 1 && cluster_id < 0) printHelp();

  if(bind_mask != NULL) {
    char *id;
    if ((id = strtok(bind_mask, ":")) != NULL)
      bind_core[0] = atoi(id) % numCPU;
    if ((id = strtok(NULL, ":")) != NULL)
      bind_core[1] = atoi(id) % numCPU;
  }

  bind2node(bind_core[0]);

  printf("Bouncing packets from %s to %s (%s)\n", in_dev, out_dev, bidirectional ? "two-way" : "one-way");

  if(handle_ts_card) printf("Stripping timestamp before bouncing packets\n");

  switch (mode) {
  case 0:
    if (bidirectional == 2 /* bidirectional with one thread per direction: opening two bouncer, two sockets per bouncer */) {
      pdb1 = pfring_open(out_dev, 1500 /* snaplen */, PF_RING_PROMISC);
      if(pdb1 == NULL) {
        printf("pfring_open %s error [%s]\n", in_dev, strerror(errno));
        return(-1);
      }
      pfring_set_socket_mode(pdb1, recv_only_mode);
      pfring_set_application_name(pdb1, "pfdnabounce");

      pdb2 = pfring_open(in_dev, 1500 /* snaplen */, PF_RING_PROMISC);
      if(pdb2 == NULL) {
        printf("pfring_open %s error [%s]\n", out_dev, strerror(errno));
        return(-1);
      } 
      pfring_set_socket_mode(pdb2, send_only_mode);
      pfring_set_application_name(pdb2, "pfdnabounce");
    }
  /* no break here! */
  case 2:
    pd1 = pfring_open(in_dev, 1500 /* snaplen */, PF_RING_PROMISC);
    if(pd1 == NULL) {
      printf("pfring_open %s error [%s]\n", in_dev, strerror(errno));
      return(-1);
    }
    if (bidirectional != 1)
      pfring_set_socket_mode(pd1, recv_only_mode);

    pd2 = pfring_open(out_dev, 1500 /* snaplen */, bidirectional ? PF_RING_PROMISC : 0);
    if(pd2 == NULL) {
      printf("pfring_open %s error [%s]\n", out_dev, strerror(errno));
      return(-1);
    } 
    if (bidirectional != 1)
      pfring_set_socket_mode(pd2, send_only_mode);
    pfring_set_application_name(pd2, "pfdnabounce");
  break;

  case 1:
    snprintf(buf, sizeof(buf), "dnacluster:%d", cluster_id);
    pd1 = pfring_open(buf, 1500 /* snaplen */, PF_RING_PROMISC);
    if(pd1 == NULL) {
      printf("pfring_open %s error [%s] (please run \"pfdnacluster_master -i %s,%s -c %d -s\")\n", buf, strerror(errno), in_dev, out_dev, cluster_id);
      return(-1);
    }
    pfring_set_socket_mode(pd1, send_and_recv_mode);
  break;
  }

  pfring_version(pd1, &version);
  printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16, 
         (version & 0x0000FF00) >> 8, version & 0x000000FF);

  pfring_set_application_name(pd1, "pfdnabounce");

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  if(bind_core[0] >= 0)
    bind2core(bind_core[0]);

  switch (mode) {
  case 0: 
    printf("Using Libzero DNA Bouncer (zero-copy)\n");

    if ((bouncer_handle = pfring_dna_bouncer_create(pd1, pd2)) == NULL) {
      printf("WARNING: Unable to initialize the DNA Bouncer (ports already in use ?)\n");
      pfring_close(pd1);
      pfring_close(pd2);

      return(-1);
    }

    if (bidirectional == 2) {
      if ((bouncer_handle2 = pfring_dna_bouncer_create(pdb1, pdb2)) == NULL) {
        printf("WARNING: Unable to initialize the second DNA Bouncer (ports already in use ?)\n");
	pfring_dna_bouncer_destroy(bouncer_handle);
        pfring_close(pdb1);
        pfring_close(pdb2);
        return(-1);
      }
      printf("Starting direction 0 thread..\n"); 
      pthread_create(&pthread2, NULL, bouncer_dir2_thread, NULL);
      printf("Starting direction 1 thread..\n"); 
    } else if (bidirectional == 1) {
      if (pfring_dna_bouncer_set_mode(bouncer_handle, two_way_mode) < 0) {
        printf("Error setting the DNA Bouncer to bidirectional\n");
	pfring_dna_bouncer_destroy(bouncer_handle);
	return(-1);
      }
    } 

    if(pfring_dna_bouncer_loop(bouncer_handle, dummyProcessPacketZero, (u_char *) &dir_stats[0], wait_for_packet) == -1) {
      printf("Problems while starting bouncer. See dmesg for details.\n");
    }

    if (bidirectional == 2) {
      pthread_join(pthread2, NULL);
      pfring_dna_bouncer_destroy(bouncer_handle2);
    }
    pfring_dna_bouncer_destroy(bouncer_handle);
  break;
  case 1: 
    printf("Using Libzero DNA Cluster (0-copy)\n");

    if (pfring_get_device_ifindex(pd1, in_dev,  &in_ifindex ) < 0 ||
        pfring_get_device_ifindex(pd1, out_dev, &out_ifindex) < 0) {
       printf("Error retrieving interface id\n");
      pfring_close(pd1);
      return(-1);
    }
   
    pfring_enable_ring(pd1);

    packetConsumerLoopZeroCluster();

    pfring_close(pd1);
  break;
  case 2: 
    printf("Using Standard DNA (1-copy)\n");

    pfring_set_direction(pd1, rx_only_direction);
    pfring_set_direction(pd2, tx_only_direction);

    pfring_enable_ring(pd1);
    pfring_enable_ring(pd2);

    pfring_loop(pd1, dummyProcessPacket, (u_char*) NULL, wait_for_packet);

    pfring_close(pd1);
    pfring_close(pd2);
  break;
  }

  sleep(3);

  return(0);
}
