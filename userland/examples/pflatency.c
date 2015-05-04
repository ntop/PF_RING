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
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pfring.h"
#include "pfutils.c"

#define MAX_PACKET_LEN 9000

struct packet {
  u_int16_t len;
  char      *data;
};

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

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udp_header {
  u_int16_t	source;		/* source port */
  u_int16_t	dest;		/* destination port */
  u_int16_t	len;		/* udp length */
  u_int16_t	check;		/* udp checksum */
};

static const size_t udp_data_off = sizeof(struct ether_header)+sizeof(struct ip_header)+sizeof(struct udp_header);

pfring  *pdo,*pdi;
char *out_dev = NULL,*in_dev = NULL;
u_int8_t do_shutdown = 0;
int reforge_mac = 0;
char mac_address[6];
int send_len = 60;
int packets_to_send = 1,packets_sent=0,packets_received=0;
int if_index = -1;

#define DEFAULT_DEVICE     "eth0"

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stdout, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
}

/* *************************************** */

void printHelp(void) {
  printf("pflatency - Sends a packet and wait actively for the packet back, computing the rtt latency\n");
  printf("(C) 2012 ntop\n\n");
  printf("-i <device>     Producer device name\n");
  printf("-o <device>     Receiver device name (same as -i by default)\n");
  printf("-l <length>     Packet length to send. Ignored with -f\n");
  printf("-c <count>      Number of packets to send\n");
  printf("-g <core_id>    Bind this app to a core\n");
  printf("-m <dst MAC>    Reforge destination MAC (format AA:BB:CC:DD:EE:FF)\n");
  printf("-x <if index>   Send to the selected interface, if supported\n");
  printf("-h              Print this help\n");
  printf("\nExample for testing the DNA bouncer latency:\n");
  printf("./pfdnabounce -i dna1 -m 0 -g 2 -f -a\n");
  printf("./pflatency -i dna0 -l 60 -g 1\n");
  exit(0);
}

/* ******************************************* */

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 * Borrowed from DHCPd
 */

static u_int32_t in_cksum(unsigned char *buf,
			  unsigned nbytes, u_int32_t sum) {
  uint i;

  /* Checksum all the pairs of bytes first... */
  for (i = 0; i < (nbytes & ~1U); i += 2) {
    sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  /* If there's a single byte left over, checksum it, too.   Network
     byte order is big-endian, so the remaining byte is the high byte. */
  if(i < nbytes) {
#ifdef DEBUG_CHECKSUM_VERBOSE
    debug ("sum = %x", sum);
#endif
    sum += buf [i] << 8;
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  return sum;
}

/* ******************************************* */

static u_int32_t wrapsum (u_int32_t sum) {
  sum = ~sum & 0xFFFF;
  return htons(sum);
}

/* ******************************************* */

static void forge_udp_packet(char *buffer, u_int idx,ticks *sent_in) {
  int i;
  struct ip_header *ip_header;
  struct udp_header *udp_header;
  u_int32_t src_ip = (0x0A000000 + idx) % 0xFFFFFFFF /* from 10.0.0.0 */;
  u_int32_t dst_ip =  0xC0A80001 /* 192.168.0.1 */;
  u_int16_t src_port = 2012, dst_port = 3000;

  /* Reset packet */
  memset(buffer, 0, send_len);

  for(i=0; i<12; i++) buffer[i] = i;
  buffer[12] = 0x08, buffer[13] = 0x00; /* IP */
  if(reforge_mac) memcpy(buffer, mac_address, 6);

  ip_header = (struct ip_header*) &buffer[sizeof(struct ether_header)];
  ip_header->ihl = 5;
  ip_header->version = 4;
  ip_header->tos = 0;
  ip_header->tot_len = htons(send_len-sizeof(struct ether_header));
  ip_header->id = htons(2012);
  ip_header->ttl = 64;
  ip_header->frag_off = htons(0);
  ip_header->protocol = IPPROTO_UDP;
  ip_header->daddr = htonl(dst_ip);
  ip_header->saddr = htonl(src_ip);
  ip_header->check = wrapsum(in_cksum((unsigned char *)ip_header,
			sizeof(struct ip_header), 0));

  udp_header = (struct udp_header*)(buffer + sizeof(struct ether_header) + sizeof(struct ip_header));
  udp_header->source = htons(src_port);
  udp_header->dest = htons(dst_port);
  udp_header->len = htons(send_len-sizeof(struct ether_header)-sizeof(struct ip_header));
  udp_header->check = 0; /* It must be 0 to compute the checksum */


  char *payload = buffer + sizeof(struct ether_header) + sizeof(struct ip_header) + sizeof(struct udp_header);
  *sent_in = getticks();
  memcpy(payload,sent_in,sizeof(*sent_in));

  /*
    http://www.cs.nyu.edu/courses/fall01/G22.2262-001/class11.htm
    http://www.ietf.org/rfc/rfc0761.txt
    http://www.ietf.org/rfc/rfc0768.txt
  */

  #if 0
  i = sizeof(struct ether_header) + sizeof(struct ip_header) + sizeof(struct udp_header);
  /* Don't add latency */
  udp_header->check = wrapsum(in_cksum((unsigned char *)udp_header, sizeof(struct udp_header),
                                       in_cksum((unsigned char *)&buffer[i], send_len-i,
                                       in_cksum((unsigned char *)&ip_header->saddr,
                                                2*sizeof(ip_header->saddr),
                                                IPPROTO_UDP + ntohs(udp_header->len)))));
  #endif
}

/* *************************************** */

static void close_pd() {
  pfring_close(pdo);
  if(pdo != pdi)
    pfring_close(pdi);
}

/* *************************************** */

static ticks calc_lat(const u_char *buf,const ticks hz){
  ticks send_tick;
  memcpy(&send_tick,buf+udp_data_off,sizeof(send_tick));
  const ticks curr_tick = getticks();
  //printf("Packet received with %ld in time %ld. Difference: %ld",send_tick,curr_tick,curr_tick-send_tick);
  //printf("\n%s usec\n", pfring_format_numbers((double) 1000000 /* us */ / ( hz / tick_delta ), buf1, sizeof(buf1), 1));
  return curr_tick - send_tick;
}

static double ticks_to_us(ticks dtick,const ticks hz){
  return ((double) 1000000 /* us */) / ( hz / dtick );
}

int main(int argc, char* argv[]) {
  char buf1[64];
  struct packet packet_to_send = { 0 };
  char c;
  int use_zero_copy_tx = 0;
  u_int mac_a, mac_b, mac_c, mac_d, mac_e, mac_f;
  int bind_core = -1;
  ticks tick_start = 0, tick_delta = 0;
  ticks hz = 0;
  //u_int num_tx_slots = 0;
  int rc;
  u_char *pkt_buffer = NULL;
  struct pfring_pkthdr hdr;
  memset(&hdr, 0, sizeof(hdr));

  ticks max_delay = 0,min_delay=(ticks)-1,sum_delay=0;

  while((c = getopt(argc,argv,"hi:o:g:l:m:x:c:")) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'o':
      out_dev = strdup(optarg);
      break;
    case 'i':
      in_dev = strdup(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'l':
      send_len = atoi(optarg);
      break;
    case 'x':
      if_index = atoi(optarg);
      break;
    case 'm':
      if(sscanf(optarg, "%02X:%02X:%02X:%02X:%02X:%02X", &mac_a, &mac_b, &mac_c, &mac_d, &mac_e, &mac_f) != 6) {
	printf("Invalid MAC address format (XX:XX:XX:XX:XX:XX)\n");
	return(0);
      } else {
	reforge_mac = 1;
	mac_address[0] = mac_a, mac_address[1] = mac_b, mac_address[2] = mac_c;
	mac_address[3] = mac_d, mac_address[4] = mac_e, mac_address[5] = mac_f;
      }
      break;
    case 'c':
      packets_to_send = atoi(optarg);
      break;
    };
  }

  if(out_dev == NULL)  printHelp();

  if(in_dev == NULL) out_dev = in_dev;

  printf("Sending packets on %s. Receiving on %s\n", out_dev,in_dev);

  pdo = pfring_open(out_dev, 1500, PF_RING_PROMISC);
  pdi = (in_dev && strcmp(out_dev, in_dev) != 0) ? pfring_open(in_dev, 1500, PF_RING_PROMISC) : pdo;
  if(pdo == NULL) {
    printf("pfring_open %s error [%s]\n", out_dev, strerror(errno));
    return(-1);
  } else if(pdi == NULL){
    printf("pfring_open %s error [%s]\n", in_dev, strerror(errno));
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pdo, "pfdnasend");
    pfring_set_application_name(pdi, "pfdnasend");
    pfring_version(pdo, &version);
    pfring_version(pdi, &version);

    printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8, version & 0x000000FF);
  }

  if (!pdo->send && pdo->send_ifindex && if_index == -1) {
    printf("Please use -x <if index>\n");
    close_pd();
    return -1;
  } 

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  if(send_len < 60)
    send_len = 60;

  /* cumputing usleep delay */
  tick_start = getticks();
  usleep(1);
  tick_delta = getticks() - tick_start;
    
  /* cumputing CPU freq */
  tick_start = getticks();
  usleep(1001);
  hz = (getticks() - tick_start - tick_delta) * 1000 /*kHz -> Hz*/;

  printf("Estimated CPU freq: %lu Hz\n", (long unsigned int)hz);

  if(bind_core >= 0) bind2core(bind_core);

  pfring_set_socket_mode(pdo, send_and_recv_mode);
  pfring_set_socket_mode(pdi, send_and_recv_mode);
  
  pfring_set_direction(pdo, rx_and_tx_direction);
  pfring_set_direction(pdi, rx_and_tx_direction);

  pfring_set_poll_watermark(pdo, 0);
  pfring_set_poll_watermark(pdi, 0);

  if(pfring_enable_ring(pdo) != 0 || pfring_enable_ring(pdi) != 0) {
    printf("Unable to enable ring :-(\n");
    close_pd();
    return(-1);
  }

  ticks last_sent_tick = 0;

  while(packets_sent < packets_to_send || packets_received < packets_to_send) {
    if(unlikely(do_shutdown))
      break;

    const int recv_rc = pfring_recv(pdi, &pkt_buffer, 0, &hdr, 0);
    if(recv_rc > 0){
      packets_received++;
      
      const ticks curr_ticks_diff = calc_lat(pkt_buffer,hz);
      if(curr_ticks_diff > max_delay) max_delay = curr_ticks_diff;
      if(curr_ticks_diff < min_delay) min_delay = curr_ticks_diff;
      sum_delay += curr_ticks_diff;

      continue;
    }

    if(!(packets_sent < packets_to_send)) /* We have sent all needed packets */
      continue;

    /* We generate packets faster than the latency => a part of latency is waiting to go out */
    /* TODO check somehow if there are packet in the output queue is better */
    /* TODO use pfring_send_get_time */
    const ticks curr_tick = getticks();
    if(ticks_to_us(curr_tick - last_sent_tick,hz) < 1000) /* 1ms between packets */
      continue;

    packet_to_send.len = send_len;
    packet_to_send.data = (char*)malloc(packet_to_send.len);

    if (packet_to_send.data == NULL) {
      printf("Not enough memory\n");
      usleep(1000);
      continue;
    }
    
    forge_udp_packet(packet_to_send.data, 1, &last_sent_tick);
  
    use_zero_copy_tx = 0;
  
  redo:
    if (if_index != -1)
      rc = pfring_send_ifindex(pdo, packet_to_send.data, packet_to_send.len, 1, if_index);
    else if(use_zero_copy_tx)
      /* We pre-filled the TX slots */
      rc = pfring_send(pdo, NULL, packet_to_send.len, 1);
    else
      rc = pfring_send(pdo, packet_to_send.data, packet_to_send.len, 1);
  
    if(rc == PF_RING_ERROR_INVALID_ARGUMENT) {
      printf("Attempting to send invalid packet [len: %u][MTU: %u]%s\n",
	     packet_to_send.len, pdo->mtu_len,
      	     if_index != -1 ? " or using a wrong interface id" : "");
    } else if (rc < 0) {
      goto redo;
    }

    packets_sent++;
  }

  if(packets_received > 0) {
    const double avg_delay = ((double)sum_delay)/packets_to_send;
    printf("\nPackets received: %d\n", packets_received);
    printf("Max delay: %s usec\n", pfring_format_numbers(ticks_to_us(max_delay,hz), buf1, sizeof(buf1), 1));
    printf("Min delay: %s usec\n", pfring_format_numbers(ticks_to_us(min_delay,hz), buf1, sizeof(buf1), 1));
    printf("Avg delay: %s usec\n", pfring_format_numbers(ticks_to_us(avg_delay,hz), buf1, sizeof(buf1), 1));
  } else {
    printf("\nNo packets received => no stats\n");
  }

  close_pd();

  return(0);
}
