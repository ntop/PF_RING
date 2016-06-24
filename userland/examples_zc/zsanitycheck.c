/*
 * (C) 2016 - ntop 
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
#include <sys/time.h>
#include <time.h>
#include <sched.h>
#include <stdio.h>

#include "pfring.h"
#include "pfring_zc.h"

#include "zutils.c"

#define BUFFER_LEN 1600

//#define USE_QUEUE
//#define USE_MEMCMP

/* ******************************** */

void sigproc(int sig) {
  exit(-1);
}

/* *************************************** */

void printHelp(void) {
  printf("zsanitycheck - (C) 2016 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("-c <id>         Cluster ID\n");
  printf("-b <num>        Number of buffers to allocate\n");
  printf("-g <id>         Core ID for CPU affinity\n");
  printf("-h              Print this help\n");
  exit(-1);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char c;
  int i, cluster_id = DEFAULT_CLUSTER_ID;
  u_int numCPU = sysconf( _SC_NPROCESSORS_ONLN );
  pfring_zc_cluster *zc;
  pfring_zc_queue *zq;
#ifdef USE_QUEUE
  pfring_zc_pkt_buff *buffer;
#else
  pfring_zc_pkt_buff **buffers;
#endif
  u_int32_t num_buffers = 1024;
  int bind_core = 0;

  while ((c = getopt(argc,argv,"b:c:g:h")) != '?') {
    if ((c == 255) || (c == -1)) break;

    switch (c) {
    case 'b':
      num_buffers = atoi(optarg);
      break;
    case 'c':
      cluster_id = atoi(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg) % numCPU;
      break;
    case 'h':
      printHelp();
      break;
    }
  }
  
  bind2core(bind_core);

#ifndef USE_QUEUE
  buffers = calloc(num_buffers, sizeof(pfring_zc_pkt_buff *));
#endif

  zc = pfring_zc_create_cluster(cluster_id, BUFFER_LEN, 0,
    num_buffers + 1, pfring_zc_numa_get_cpu_node(bind_core), NULL);

  if (zc == NULL) {
    fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
	    strerror(errno));
    return -1;
  }

  zq = pfring_zc_create_queue(zc, 
#ifdef USE_QUEUE
    num_buffers
#else
    32
#endif
  );

  if (zq == NULL) {
    fprintf(stderr, "pfring_zc_create_queue error [%s]\n", strerror(errno));
    return -1;
  }

#ifdef USE_QUEUE
  buffer = pfring_zc_get_packet_handle(zc);

  if (buffer == NULL) {
    fprintf(stderr, "pfring_zc_get_packet_handle error\n");
    return -1;
  }
#else
  for (i = 0; i < num_buffers; i++) { 
    buffers[i] = pfring_zc_get_packet_handle(zc);

    if (buffers[i] == NULL) {
      fprintf(stderr, "pfring_zc_get_packet_handle error\n");
      return -1;
    }
  }
#endif

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  printf("Writing data..\n");

  for (i = 0; i < num_buffers; i++) {
    u_char *data = 
#ifdef USE_QUEUE
      pfring_zc_pkt_buff_data(buffer, zq);
#else
      pfring_zc_pkt_buff_data(buffers[i], zq);
#endif
#ifdef USE_MEMCMP
    memset(data, i & 0xFF, BUFFER_LEN);
#else
    u_int64_t *data64 = (u_int64_t *) data;
    *data64 = i;
#endif
#ifdef USE_QUEUE
    pfring_zc_send_pkt(zq, &buffer, 1);
#endif
  }

  sleep(1);

  printf("Reading data..\n");

  for (i = 0; i < num_buffers; i++) {
#ifdef USE_MEMCMP
    u_char expected_data[BUFFER_LEN];
#endif
    u_char *data;
#ifdef USE_QUEUE
    if (pfring_zc_recv_pkt(zq, &buffer, 0) > 0) {
      data = pfring_zc_pkt_buff_data(buffer, zq);       
    } else {
      printf("No mode buffers (%u read)\n", i);
      break;
    }
#else
    data = pfring_zc_pkt_buff_data(buffers[i], zq);
#endif
#ifdef USE_MEMCMP
    memset(expected_data, i & 0xFF, BUFFER_LEN);
    if (memcmp(data, expected_data, BUFFER_LEN) != 0) {
#else
    u_int64_t *data64 = (u_int64_t *) data;
    if (*data64 != i) {
#endif
      printf("Data on buffers #%u  does not match\n", i);
      break;
    }
  }

  pfring_zc_destroy_cluster(zc);

  if (i == num_buffers)
    printf("Test completed, %u buffers inspected\n", i);

  return 0;
}

