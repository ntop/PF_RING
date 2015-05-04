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
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <numa.h>
#include <ctype.h>

#include "pfring.h"
#include "pfring_zc.h"

#include "zutils.c"

#define POW2(n) ((n & (n - 1)) == 0)

#define ALARM_SLEEP             1
#define CACHE_LINE_LEN         64
#define MAX_CARD_SLOTS      32768
#define QUEUE_LEN            8192

#define NBUFF      256 /* pow 2 */
#define NBUFFMASK 0xFF /* 256-1 */

#define BURST_API
#define BURSTLEN    16 /* pow 2 */

pfring_zc_cluster *zc;
pfring_zc_queue *zq;
pfring_zc_buffer_pool *zp;
pfring_zc_pkt_buff *buffers[NBUFF];

struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;
int cluster_id = -1, queue_id = -1, bind_core = -1, pps = -1, packet_len = 60, num_ips = 0, metadata_len = 0;
u_int64_t num_to_send = 0;
u_int8_t active = 0, flush_packet = 0, append_timestamp = 0, use_pulse_time = 0, enable_vm_support = 0;
#ifdef BURST_API
u_int8_t use_pkt_burst_api = 0;
#endif
u_int8_t n2disk_producer = 0;
u_int32_t n2disk_threads;

u_char stdin_packet[9000];
int stdin_packet_len = 0;

u_int32_t num_queue_buffers = 0, num_consumer_buffers = 0;

volatile int do_shutdown = 0;

int bind_time_pulse_core = -1;
volatile u_int64_t *pulse_timestamp_ns;
volatile u_int64_t *pulse_timestamp_ns_n;

/* *************************************** */

typedef u_int64_t ticks;

static __inline__ ticks getticks(void) {
  u_int32_t a, d;
  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return (((ticks)a) | (((ticks)d) << 32));
}

/* ******************************************* */

void *time_pulse_thread(void *data) {
  struct timespec tn;

  bind2core(bind_time_pulse_core);

  while (likely(!do_shutdown)) {
    /* clock_gettime takes up to 30 nsec to get the time */
    clock_gettime(CLOCK_REALTIME, &tn);
    if (append_timestamp) *pulse_timestamp_ns_n = ((u_int64_t) ((u_int64_t) htonl(tn.tv_sec) << 32) | htonl(tn.tv_nsec));
    if (use_pulse_time)   *pulse_timestamp_ns   = ((u_int64_t) ((u_int64_t) tn.tv_sec * 1000000000) + tn.tv_nsec);
  }

  return NULL;
}

/* ******************************************* */

static inline u_int32_t append_packet_ts(u_char *buffer, u_int32_t buffer_len) {
  u_int32_t *sec  = (u_int32_t *) &buffer[buffer_len];
  u_int32_t *nsec = (u_int32_t *) &buffer[buffer_len + 4];
  u_int64_t ts = *pulse_timestamp_ns_n;
  *sec  = ts >> 32; 
  *nsec = ts & 0xffffffff;
  buffer[buffer_len + 8] = 0xC3;
  return buffer_len + 9;
}

/* ******************************************* */

#include <net/ethernet.h>

struct ip_header {
#if BYTE_ORDER == LITTLE_ENDIAN
  u_int32_t	ihl:4,		/* header length */
    version:4;			/* version */
#else
  u_int32_t	version:4,	/* version */
    ihl:4;			/* header length */
#endif
  u_int8_t	tos;		/* type of service */
  u_int16_t	tot_len;	/* total length */
  u_int16_t	id;		/* identification */
  u_int16_t	frag_off;	/* fragment offset field */
  u_int8_t	ttl;		/* time to live */
  u_int8_t	protocol;	/* protocol */
  u_int16_t	check;		/* checksum */
  u_int32_t saddr, daddr;	/* source and dest address */
};

struct udp_header {
  u_int16_t	source;		/* source port */
  u_int16_t	dest;		/* destination port */
  u_int16_t	len;		/* udp length */
  u_int16_t	check;		/* udp checksum */
};

static u_int32_t in_cksum(unsigned char *buf, unsigned nbytes, u_int32_t sum) {
  uint i;

  for (i = 0; i < (nbytes & ~1U); i += 2) {
    sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  if(i < nbytes) {
    sum += buf [i] << 8;
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  return sum;
}

static u_int32_t wrapsum (u_int32_t sum) {
  sum = ~sum & 0xFFFF;
  return htons(sum);
}

static u_char matrix_buffer[sizeof(struct ether_header) +  sizeof(struct ip_header) + sizeof(struct udp_header)];

static void forge_udp_packet(u_char *buffer, u_int idx) {
  int i;
  struct ip_header *ip_header;
  struct udp_header *udp_header;
  u_int32_t src_ip = 0x0A000000; /* 10.0.0.0 */ 
  u_int32_t dst_ip =  0xC0A80001; /* 192.168.0.1 */
  u_int16_t src_port = 2014, dst_port = 3000;

  if (num_ips == 0) {
    src_ip |= idx & 0xFFFFFF;
  } else if (num_ips > 1) {
    if (POW2(num_ips))
      src_ip |= idx & (num_ips - 1) & 0xFFFFFF;
    else
      src_ip |= (idx % num_ips) & 0xFFFFFF;
  }

#if 0
  memset(buffer, 0, packet_len + 4);
#endif

  if (idx == 0) { /* first packet, precomputing headers */
    for(i = 0; i < 12; i++) buffer[i] = i;
    buffer[12] = 0x08, buffer[13] = 0x00; /* IP */

    ip_header = (struct ip_header*) &buffer[sizeof(struct ether_header)];
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(packet_len-sizeof(struct ether_header));
    ip_header->id = htons(2012);
    ip_header->ttl = 64;
    ip_header->frag_off = htons(0);
    ip_header->protocol = IPPROTO_UDP;
    ip_header->daddr = htonl(dst_ip);
    ip_header->saddr = htonl(src_ip);
    ip_header->check = 0;

    udp_header = (struct udp_header*)(buffer + sizeof(struct ether_header) + sizeof(struct ip_header));
    udp_header->source = htons(src_port);
    udp_header->dest = htons(dst_port);
    udp_header->len = htons(packet_len-sizeof(struct ether_header)-sizeof(struct ip_header));
    udp_header->check = 0;

    memcpy(matrix_buffer, buffer, sizeof(struct ether_header) +  sizeof(struct ip_header) + sizeof(struct udp_header));
  } else {
    memcpy(buffer, matrix_buffer, sizeof(struct ether_header) +  sizeof(struct ip_header) + sizeof(struct udp_header));
  }

  ip_header = (struct ip_header*) &buffer[sizeof(struct ether_header)];
  ip_header->saddr = htonl(src_ip);
  ip_header->check = wrapsum(in_cksum((unsigned char *)ip_header, sizeof(struct ip_header), 0));

#if 0
  i = sizeof(struct ether_header) + sizeof(struct ip_header) + sizeof(struct udp_header);
  udp_header->check = wrapsum(in_cksum((unsigned char *)udp_header, sizeof(struct udp_header),
                                       in_cksum((unsigned char *)&buffer[i], packet_len-i,
						in_cksum((unsigned char *)&ip_header->saddr,
							 2*sizeof(ip_header->saddr),
							 IPPROTO_UDP + ntohs(udp_header->len)))));
#endif
}

/* *************************************** */

int is_fd_ready(int fd) {
  struct timeval timeout = {0};
  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(fd, &fdset);
  return (select(fd+1, &fdset, NULL, NULL, &timeout) == 1);
}

int read_packet_hex(u_char *buf, int buf_len) {
  int i = 0, d, bytes = 0;
  char c;
  char s[3] = {0};

  if (!is_fd_ready(fileno(stdin)))
    return 0;

  while ((d = fgetc(stdin)) != EOF) {
    if (d < 0) break;
    c = (u_char) d;
    if ((c >= '0' && c <= '9') 
     || (c >= 'a' && c <= 'f')
     || (c >= 'A' && c <= 'F')) {
      s[i&0x1] = c;
      if (i&0x1) {
        bytes = (i+1)/2;
        sscanf(s, "%2hhx", &buf[bytes-1]);
	if (bytes == buf_len) break;
      }
      i++;
    }
  }

  return bytes;
}

/* *************************************** */

void print_stats() {
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  static u_int64_t lastBytes = 0;
  double diff, bytesDiff;
  static struct timeval lastTime;
  char buf1[64], buf2[64];
  unsigned long long nBytes = 0, nPkts = 0;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  nBytes = numBytes;
  nPkts = numPkts;

  fprintf(stderr, "=========================\n"
	  "Absolute Stats: %s pkts - %s bytes\n",
	  pfring_format_numbers((double)nPkts, buf1, sizeof(buf1), 0),
	  pfring_format_numbers((double)nBytes, buf2, sizeof(buf2), 0));

  if(print_all && (lastTime.tv_sec > 0)) {
    char buf[256];

    deltaMillisec = delta_time(&endTime, &lastTime);
    diff = nPkts-lastPkts;
    bytesDiff = nBytes - lastBytes;
    bytesDiff /= (1000*1000*1000)/8;

    snprintf(buf, sizeof(buf),
	     "Actual Stats: %s pps - %s Gbps",
	     pfring_format_numbers(((double)diff/(double)(deltaMillisec/1000)),  buf1, sizeof(buf1), 1),
	     pfring_format_numbers(((double)bytesDiff/(double)(deltaMillisec/1000)),  buf2, sizeof(buf2), 1));
     fprintf(stderr, "%s\n", buf);
  }

  fprintf(stderr, "=========================\n\n");

  lastPkts = nPkts, lastBytes = nBytes;

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;
}

/* *************************************** */

void sigproc(int sig) {
  static int called = 0;
  fprintf(stderr, "Leaving...\n");
  if(called) return; else called = 1;

  do_shutdown = 1;

  pfring_zc_queue_breakloop(zq);
}

/* *************************************** */

void printHelp(void) {
  printf("zsend - (C) 2014 ntop.org\n");
  printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
  printf("A traffic generator able to replay synthetic udp packets or hex from standard input.\n"); 
  printf("Usage:    zsend -i <device> -c <cluster id>\n"
	 "                [-h] [-g <core id>] [-p <pps>] [-l <len>] [-n <num>]\n"
	 "                [-b <num>] [-N <num>] [-S <core id>] [-P <core id>]\n"
	 "                [-z] [-a] [-Q <sock>]\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name (optional: do not specify a device to create a cluster with a sw queue)\n");
  printf("-c <cluster id> Cluster id\n");
  printf("-g <core id>    Bind this app to a core\n");
  printf("-p <pps>        Rate (packets/s)\n");
  printf("-l <len>        Packet len (bytes)\n");
  printf("-n <num>        Number of packets\n");
  printf("-b <num>        Number of different IPs\n");
  printf("-N <num>        Simulate a producer for n2disk multi-thread (<num> threads)\n");
  printf("-S <core id>    Append timestamp to packets, bind time-pulse thread to a core\n");
  printf("-P <core id>    Use a time-pulse thread to control transmission rate, bind the thread to a core\n");
  printf("-z              Use burst API\n");
  printf("-a              Active packet wait\n");
  printf("-Q <sock>       Enable VM support to attach a consumer from a VM (<sock> is a QEMU monitor sockets)\n");
  exit(-1);
}

/* *************************************** */

void *send_traffic(void *user) {
  ticks hz, tick_start = 0, tick_delta = 0;
  u_int64_t ts_ns_start = 0, ns_delta = 0;
  u_int32_t buffer_id = 0;
  int sent_bytes;
#ifdef BURST_API
  int i, sent_packets;
#endif

  if (bind_core >= 0)
    bind2core(bind_core);

  if(pps > 0) {
    if (use_pulse_time) {
      ts_ns_start = *pulse_timestamp_ns;
      ns_delta = (double) (1000000000 / pps);
    } else {
      /* cumputing usleep delay */
      tick_start = getticks();
      usleep(1);
      tick_delta = getticks() - tick_start;

      /* cumputing CPU freq */
      tick_start = getticks();
      usleep(1001);
      hz = (getticks() - tick_start - tick_delta) * 1000 /*kHz -> Hz*/;
      printf("Estimated CPU freq: %lu Hz\n", (long unsigned int) hz);

      tick_delta = (double) (hz / pps);
      tick_start = getticks();
    }
  }

#ifdef BURST_API  
  /****** Burst API ******/
  if (use_pkt_burst_api) {
  while (likely(!do_shutdown && (!num_to_send || numPkts < num_to_send))) {

    if (!num_queue_buffers || numPkts < num_queue_buffers + NBUFF || num_ips > 1) { /* forge all buffers 1 time */
      for (i = 0; i < BURSTLEN; i++) {
        buffers[buffer_id + i]->len = packet_len;
        if (stdin_packet_len > 0)
          memcpy(pfring_zc_pkt_buff_data(buffers[buffer_id + i], zq), stdin_packet, stdin_packet_len);
        else
          forge_udp_packet(pfring_zc_pkt_buff_data(buffers[buffer_id + i], zq), numPkts + i);
      }
    }

    /* TODO send unsent packets when a burst is partially sent */
    while (unlikely((sent_packets = pfring_zc_send_pkt_burst(zq, &buffers[buffer_id], BURSTLEN, flush_packet)) <= 0)) {
      if (unlikely(do_shutdown)) break;
      if (!active) usleep(1);
    }

    numPkts += sent_packets;
    numBytes += ((packet_len + 24 /* 8 Preamble + 4 CRC + 12 IFG */ ) * sent_packets);

    buffer_id += BURSTLEN;
    buffer_id &= NBUFFMASK;

    if(pps > 0) {
      u_int8_t synced = 0;
      if (use_pulse_time) {
        while(*pulse_timestamp_ns - ts_ns_start < numPkts * ns_delta && !do_shutdown)
          if (!synced) pfring_zc_sync_queue(zq, tx_only), synced = 1;
      } else {
        while((getticks() - tick_start) < (numPkts * tick_delta))
          if (!synced) pfring_zc_sync_queue(zq, tx_only), synced = 1;
      }
    }

  } 

  } else {
#endif

  /****** Packet API ******/
  while (likely(!do_shutdown && (!num_to_send || numPkts < num_to_send))) {

    buffers[buffer_id]->len = packet_len;

#if 1
    if (!num_queue_buffers || numPkts < num_queue_buffers + NBUFF || num_ips > 1) { /* forge all buffers 1 time */
      if (stdin_packet_len > 0)
        memcpy(pfring_zc_pkt_buff_data(buffers[buffer_id], zq), stdin_packet, stdin_packet_len);
      else
        forge_udp_packet(pfring_zc_pkt_buff_data(buffers[buffer_id], zq), numPkts);
    }
#else
    {
      u_char *pkt_data = pfring_zc_pkt_buff_data(buffers[buffer_id], zq);
      int k;
      u_int8_t j = numPkts;
      for(k = 0; k < buffers[buffer_id]->len; k++)
        pkt_data[k] = j++;
      pkt_data[k-1] = cluster_id;
    }
#endif

    if (append_timestamp)
      buffers[buffer_id]->len = append_packet_ts(pfring_zc_pkt_buff_data(buffers[buffer_id], zq), buffers[buffer_id]->len);

    while (unlikely((sent_bytes = pfring_zc_send_pkt(zq, &buffers[buffer_id], flush_packet)) < 0)) {
      if (unlikely(do_shutdown)) break;
      if (!active) usleep(1);
    }

    numPkts++;
    numBytes += sent_bytes + 24; /* 8 Preamble + 4 CRC + 12 IFG */

    buffer_id++;
    buffer_id &= NBUFFMASK;

    if(pps > 0) {
      u_int8_t synced = 0;
      if (use_pulse_time) {
        while(*pulse_timestamp_ns - ts_ns_start < numPkts * ns_delta && !do_shutdown)
          if (!synced) pfring_zc_sync_queue(zq, tx_only), synced = 1;
      } else {
        while((getticks() - tick_start) < (numPkts * tick_delta))
          if (!synced) pfring_zc_sync_queue(zq, tx_only), synced = 1;
      }
    }
  }

#ifdef BURST_API  
  }
#endif

  if (!flush_packet) 
    pfring_zc_sync_queue(zq, tx_only);

  return NULL;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c;
  pthread_t thread;
  pthread_t time_thread;
  char *vm_sock = NULL;
  int i, rc, ipc_q_attach = 0;

  startTime.tv_sec = 0;

  while((c = getopt(argc,argv,"ab:c:g:hi:n:p:l:zN:S:P:Q:")) != '?') {
    if((c == 255) || (c == -1)) break;

    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'a':
      active = 1;
      break;
    case 'b':
      num_ips = atoi(optarg);
      break;
    case 'c':
      cluster_id = atoi(optarg);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'l':
      packet_len = atoi(optarg);
      break;
    case 'n':
      num_to_send = atoi(optarg);
      break;
    case 'p':
      pps = atoi(optarg);
      /* auto flush on wait flush_packet = 1; */
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'Q':
      enable_vm_support = 1;
      vm_sock = strdup(optarg);
      break;
#ifdef BURST_API
    case 'z':
      use_pkt_burst_api = 1;
      break;
#endif
    case 'N':
      n2disk_producer = 1;
      n2disk_threads = atoi(optarg);
      break;
    case 'S':
      append_timestamp = 1;
      bind_time_pulse_core = atoi(optarg);
      break;
    case 'P':
      use_pulse_time = 1;
      bind_time_pulse_core = atoi(optarg);
      break;
    }
  }

  if (n2disk_producer) 
    device = NULL;

  /* checking if the interface is a queue allocated by an external cluster (ipc) */
  if (device != NULL && is_a_queue(device, &cluster_id, &queue_id)) 
    ipc_q_attach = 1;

  if (cluster_id < 0) printHelp();

  stdin_packet_len = read_packet_hex(stdin_packet, sizeof(stdin_packet));

  if (stdin_packet_len > 0)
    packet_len = stdin_packet_len;

  if (n2disk_producer) {
    if (device != NULL || ipc_q_attach) printHelp();
    if (n2disk_threads < 1) printHelp();
    metadata_len = N2DISK_METADATA;
    num_consumer_buffers += (n2disk_threads * (N2DISK_CONSUMER_QUEUE_LEN + 1)) + N2DISK_PREFETCH_BUFFERS;
  }
 
  if (!ipc_q_attach) {

    if (device != NULL)
      num_queue_buffers = MAX_CARD_SLOTS;
    else
      num_queue_buffers = QUEUE_LEN;

    zc = pfring_zc_create_cluster(
      cluster_id, 
      max_packet_len(device),
      metadata_len, 
      num_queue_buffers + NBUFF + num_consumer_buffers, 
      numa_node_of_cpu(bind_core),
      NULL /* auto hugetlb mountpoint */ 
    );

    if(zc == NULL) {
      fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check your hugetlb configuration\n",
  	      strerror(errno));
      return -1;
    }

    for (i = 0; i < NBUFF; i++) {
      buffers[i] = pfring_zc_get_packet_handle(zc);

      if (buffers[i] == NULL) {
        fprintf(stderr, "pfring_zc_get_packet_handle error\n");
        return -1;
      }
    }

    if (device) {
      zq = pfring_zc_open_device(zc, device, tx_only, 0);
  
      if(zq == NULL) {
        fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
	        strerror(errno), device);
        return -1;
      }

      fprintf(stderr, "Sending packets to %s\n", device);
    } else {
      zq = pfring_zc_create_queue(zc, num_queue_buffers);

      if(zq == NULL) {
        fprintf(stderr, "pfring_zc_create_queue error [%s]\n", strerror(errno));
        return -1;
      }

      if (pfring_zc_create_buffer_pool(zc, n2disk_producer ? (N2DISK_PREFETCH_BUFFERS + n2disk_threads) : 1) == NULL) {
        fprintf(stderr, "pfring_zc_create_buffer_pool error\n");
        return -1;
      }
   
      fprintf(stderr, "Sending packets to cluster %u queue %u\n", cluster_id, 0);

      if (n2disk_producer) {
        char queues_list[256];
        queues_list[0] = '\0';

        for (i = 0; i < n2disk_threads; i++) {
          if(pfring_zc_create_queue(zc, N2DISK_CONSUMER_QUEUE_LEN) == NULL) {
            fprintf(stderr, "pfring_zc_create_queue error [%s]\n", strerror(errno));
            return -1;
          }
          sprintf(&queues_list[strlen(queues_list)], "%d,", i+1);
        }
        queues_list[strlen(queues_list)-1] = '\0';

        fprintf(stderr, "Run n2disk with: --cluster-ipc-attach --cluster-id %d --cluster-ipc-queues %s --cluster-ipc-pool 0\n", cluster_id, queues_list);
      }

    }

    if (enable_vm_support) {
      rc = pfring_zc_vm_register(zc, vm_sock);

      if (rc < 0) {
        fprintf(stderr, "pfring_zc_vm_register(%s) error\n", vm_sock);
        return -1;
      }

      rc = pfring_zc_vm_backend_enable(zc);

      if (rc < 0) {
        fprintf(stderr, "pfring_zc_vm_backend_enable error\n");
        return -1;
      }
    }

  } else { /* IPC */

    fprintf(stderr, "Attaching to cluster %d queue %d (IPC)\n", cluster_id, queue_id);

    zq = pfring_zc_ipc_attach_queue(cluster_id, queue_id, tx_only);

    if(zq == NULL) {
      fprintf(stderr, "pfring_zc_ipc_attach_queue error [%s] Please check that cluster %d is running\n",
  	      strerror(errno), cluster_id);
      return -1;
    }

    zp = pfring_zc_ipc_attach_buffer_pool(cluster_id, queue_id);

    if(zp == NULL) {
      fprintf(stderr, "pfring_zc_ipc_attach_buffer_pool error [%s] Please check that cluster %d is running\n",
  	      strerror(errno), cluster_id);
      return -1;
    }

    for (i = 0; i < NBUFF; i++) {
      buffers[i] = pfring_zc_get_packet_handle_from_pool(zp);

      if (buffers[i] == NULL) {
        fprintf(stderr, "pfring_zc_get_packet_handle_from_pool error\n");
        return -1;
      }
    } 
  }

  signal(SIGINT,  sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT,  sigproc);

  if (use_pulse_time)   pulse_timestamp_ns   = calloc(CACHE_LINE_LEN/sizeof(u_int64_t), sizeof(u_int64_t));
  if (append_timestamp) pulse_timestamp_ns_n = calloc(CACHE_LINE_LEN/sizeof(u_int64_t), sizeof(u_int64_t));
  if (append_timestamp || use_pulse_time) pthread_create(&time_thread, NULL, time_pulse_thread, NULL);
  if (use_pulse_time)   while (!*pulse_timestamp_ns   && !do_shutdown); /* wait for ts */
  if (append_timestamp) while (!*pulse_timestamp_ns_n && !do_shutdown); /* wait for ts */

  pthread_create(&thread, NULL, send_traffic, NULL);

  while (!do_shutdown) {
    sleep(ALARM_SLEEP);
    print_stats();
  }

  pthread_join(thread, NULL);

  print_stats();

  if (append_timestamp || use_pulse_time)
    pthread_join(time_thread, NULL);

  if (!ipc_q_attach) {
    pfring_zc_destroy_cluster(zc);
  } else {
    for (i = 0; i < NBUFF; i++)
      pfring_zc_release_packet_handle_to_pool(zp, buffers[i]);
    pfring_zc_ipc_detach_queue(zq);
    pfring_zc_ipc_detach_buffer_pool(zp);  
  }

  return 0;
}

