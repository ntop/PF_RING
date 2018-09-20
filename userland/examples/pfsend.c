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
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "pfring.h"
#include "pfutils.c"

#define MAX_PACKET_SIZE 9018

struct packet {
  u_int16_t len;
  u_int64_t ticks_from_beginning;
  u_char *pkt;
  struct packet *next;
};

struct ip_header {
#if BYTE_ORDER == LITTLE_ENDIAN
  u_int32_t	ihl:4,		/* header length */
    version:4;			/* version */
#else
  u_int32_t	version:4,			/* version */
    ihl:4;		/* header length */
#endif
  u_int8_t	tos;			/* type of service */
  u_int16_t	tot_len;			/* total length */
  u_int16_t	id;			/* identification */
  u_int16_t	frag_off;			/* fragment offset field */
  u_int8_t	ttl;			/* time to live */
  u_int8_t	protocol;			/* protocol */
  u_int16_t	check;			/* checksum */
  u_int32_t saddr, daddr;	/* source and dest address */
} __attribute__((packed));

struct ip6_header {
  u_int8_t	priority:4,
		version:4;
  u_int8_t	flow_lbl[3];
  u_int16_t	payload_len;
  u_int8_t	nexthdr;
  u_int8_t	hop_limit;
  u_int32_t     saddr[4];
  u_int32_t     daddr[4];
} __attribute__((packed));

struct udp_header {
  u_int16_t	source;		/* source port */
  u_int16_t	dest;		/* destination port */
  u_int16_t	len;		/* udp length */
  u_int16_t	check;		/* udp checksum */
} __attribute__((packed));

struct tcp_header {
  u_int16_t source;
  u_int16_t dest;
  u_int32_t seq;
  u_int32_t ack_seq;
  u_int16_t flags;
  u_int16_t window;
  u_int16_t check;
  u_int16_t urg_ptr;
} __attribute__((packed));

struct packet *pkt_head = NULL;
pfring  *pd;
pfring_stat pfringStats;
char *device = NULL;
u_int8_t wait_for_packet = 1, do_shutdown = 0;
u_int64_t num_pkt_good_sent = 0, last_num_pkt_good_sent = 0;
u_int64_t num_bytes_good_sent = 0, last_num_bytes_good_sent = 0;
struct timeval lastTime, startTime;
int reforge_mac = 0, reforge_ip = 0, on_the_fly_reforging = 0;
struct in_addr srcaddr, dstaddr;
char mac_address[6];
int send_len = 60;
int daemon_mode = 0;
int num_ip = 1, ip_offset = 0;
int forge_vlan = 0, num_vlan = 1;

#define DEFAULT_DEVICE     "eth0"

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
  double deltaMillisec, currentThpt, avgThpt, currentThptBits, currentThptBytes, avgThptBits, avgThptBytes;
  struct timeval now;
  char buf1[64], buf2[64], buf3[64], buf4[64], buf5[64], statsBuf[512], timebuf[128];
  u_int64_t deltaMillisecStart;

  gettimeofday(&now, NULL);
  deltaMillisec = delta_time(&now, &lastTime);
  currentThpt = (double)((num_pkt_good_sent-last_num_pkt_good_sent) * 1000)/deltaMillisec;
  currentThptBytes = (double)((num_bytes_good_sent-last_num_bytes_good_sent) * 1000)/deltaMillisec;
  currentThptBits = currentThptBytes * 8;

  deltaMillisec = delta_time(&now, &startTime);
  avgThpt = (double)(num_pkt_good_sent * 1000)/deltaMillisec;
  avgThptBytes = (double)(num_bytes_good_sent * 1000)/deltaMillisec;
  avgThptBits = avgThptBytes * 8;

  if (!daemon_mode) {
    snprintf(statsBuf, sizeof(statsBuf),
	     "TX rate: [current %s pps/%s Gbps][average %s pps/%s Gbps][total %s pkts]",
	     pfring_format_numbers(currentThpt, buf1, sizeof(buf1), 1),
	     pfring_format_numbers(currentThptBits/(1000*1000*1000), buf2, sizeof(buf2), 1),
	     pfring_format_numbers(avgThpt, buf3, sizeof(buf3), 1),
	     pfring_format_numbers(avgThptBits/(1000*1000*1000),  buf4, sizeof(buf4), 1),
	     pfring_format_numbers(num_pkt_good_sent, buf5, sizeof(buf5), 1));
 
    fprintf(stdout, "%s\n", statsBuf);
  }

  deltaMillisecStart = delta_time(&now, &startTime);
  snprintf(statsBuf, sizeof(statsBuf),
           "Duration:          %s\n"
           "SentPackets:       %lu\n"
           "SentBytes:         %lu\n"
           "CurrentSentPps:    %lu\n"
           "CurrentSentBitps:  %lu\n",
           msec2dhmsm(deltaMillisecStart, timebuf, sizeof(timebuf)),
           (long unsigned int) num_pkt_good_sent,
           (long unsigned int) num_bytes_good_sent,
	   (long unsigned int) currentThpt,
	   (long unsigned int) currentThptBits);
  pfring_set_application_stats(pd, statsBuf);

  memcpy(&lastTime, &now, sizeof(now));
  last_num_pkt_good_sent = num_pkt_good_sent, last_num_bytes_good_sent = num_bytes_good_sent;
}

/* ******************************** */

void my_sigalarm(int sig) {
  if(do_shutdown) return;
  print_stats();
  alarm(1);
  signal(SIGALRM, my_sigalarm);
}

/* ******************************** */

void sigproc(int sig) {
  if(do_shutdown) return;
  fprintf(stdout, "Leaving...\n");
  do_shutdown = 1;
}

/* *************************************** */

void printHelp(void) {
  printf("pfsend - (C) 2011-2018 ntop.org\n");
  printf("Replay synthetic traffic, or a pcap, or a packet in hex format from standard input.\n\n"); 
  printf("pfsend -i out_dev [-a] [-f <.pcap file>] [-g <core_id>] [-h]\n"
         "       [-l <length>] [-n <num>] "
#if !(defined(__arm__) || defined(__mips__))
	 "[-r <rate>] [-p <rate>] "
#endif
	 "[-m <dst MAC>]\n"
	 "       [-w <TX watermark>] [-v]\n\n");
  printf("-a              Active send retry\n");
#if 0
  printf("-b <cpu %%>      CPU pergentage priority (0-99)\n");
#endif
  printf("-f <.pcap file> Send packets as read from a pcap file\n");
  printf("-g <core_id>    Bind this app to a core\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name. Use device\n");
  printf("-l <length>     Packet length to send. Ignored with -f\n");
  printf("-n <num>        Num pkts to send (use 0 for infinite)\n");
#if !(defined(__arm__) || defined(__mips__))
  printf("-r <Gbps rate>  Rate to send (example -r 2.5 sends 2.5 Gbit/sec, -r -1 pcap capture rate)\n");
  printf("-p <pps rate>   Rate to send (example -p 100 send 100 pps)\n");
#endif
  printf("-m <dst MAC>    Reforge destination MAC (format AA:BB:CC:DD:EE:FF)\n");
  printf("-b <num>        Reforge source IP with <num> different IPs (balanced traffic)\n");
  printf("-S <ip>         Use <ip> as base source IP for -b (default: 10.0.0.1)\n");
  printf("-D <ip>         Use <ip> as destination IP (default: 192.168.0.1)\n");
  printf("-V <version>    Generate IP version <version> packets (default: 4, mixed: 0)\n");
  printf("-O              On the fly reforging instead of preprocessing (-b)\n");
  printf("-z              Randomize generated IPs sequence\n");
  printf("-o <num>        Offset for generated IPs (-b) or packets in pcap (-f)\n");
  printf("-L <num>        Forge VLAN packets with <num> different ids\n");
  printf("-F              Force flush for each packet (to avoid bursts, expect low performance)\n");
  printf("-w <watermark>  TX watermark (low value=low latency) [not effective on ZC]\n");
  printf("-d              Daemon mode\n");
  printf("-P <pid file>   Write pid to the specified file (daemon mode only)\n");
  printf("-v              Verbose\n");
  exit(0);
}

/* ******************************************* */

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 * Borrowed from DHCPd
 */

static u_int32_t in_cksum(unsigned char *buf, unsigned nbytes, u_int32_t sum) {
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

static void forge_udp_packet(u_char *buffer, u_int buffer_len, u_int idx, u_int ip_version) {
  struct eth_vlan_hdr *vlan;
  struct ip_header *ip;
  struct ip6_header *ip6;
  struct udp_header *udp;
  u_char *addr;
  int l2_len, ip_len, addr_len, i;

  /* Reset packet */
  memset(buffer, 0, buffer_len);

  l2_len = sizeof(struct ether_header);

  for(i=0; i<12; i++) buffer[i] = i;
  if(reforge_mac) memcpy(buffer, mac_address, 6);

  if (forge_vlan) { 
    vlan = (struct eth_vlan_hdr *) &buffer[l2_len];
    buffer[l2_len-2] = 0x81, buffer[l2_len-1] = 0x00;
    vlan->h_vlan_id = htons((idx % num_vlan) + 1); 
    l2_len += sizeof(struct eth_vlan_hdr);
  }

  if (ip_version == 6) {
    buffer[l2_len-2] = 0x86, buffer[l2_len-1] = 0xDD;
    ip6 = (struct ip6_header*) &buffer[l2_len];
    ip_len = sizeof(*ip6);
    ip6->version = 6;
    ip6->payload_len = htons(buffer_len - l2_len - ip_len);
    ip6->nexthdr = IPPROTO_UDP;
    ip6->hop_limit = 0xFF;
    ip6->saddr[0] = htonl((ntohl(srcaddr.s_addr) + ip_offset + (idx % num_ip)) & 0xFFFFFFFF);
    ip6->daddr[0] = dstaddr.s_addr;
    addr = (u_char *) ip6->saddr;
    addr_len = sizeof(ip6->saddr);
  } else {
    buffer[l2_len-2] = 0x08, buffer[l2_len-1] = 0x00;
    ip = (struct ip_header*) &buffer[l2_len];
    ip_len = sizeof(*ip);
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(buffer_len - l2_len);
    ip->id = htons(2012);
    ip->ttl = 64;
    ip->frag_off = htons(0);
    ip->protocol = IPPROTO_UDP;
    ip->daddr = dstaddr.s_addr;
    ip->saddr = htonl((ntohl(srcaddr.s_addr) + ip_offset + (idx % num_ip)) & 0xFFFFFFFF);
    ip->check = wrapsum(in_cksum((unsigned char *) ip, ip_len, 0));
    addr = (u_char *) &ip->saddr;
    addr_len = sizeof(ip->saddr);
  }

  udp = (struct udp_header*)(buffer + l2_len + ip_len);
  udp->source = htons(2012);
  udp->dest = htons(3000);
  udp->len = htons(buffer_len - l2_len - ip_len);
  udp->check = 0; /* It must be 0 to compute the checksum */

  /*
    http://www.cs.nyu.edu/courses/fall01/G22.2262-001/class11.htm
    http://www.ietf.org/rfc/rfc0761.txt
    http://www.ietf.org/rfc/rfc0768.txt
  */

  i = l2_len + ip_len + sizeof(struct udp_header);
  udp->check = wrapsum(in_cksum((unsigned char *) udp, sizeof(struct udp_header),
                                in_cksum((unsigned char *) &buffer[i], buffer_len - i,
				  in_cksum((unsigned char *) addr, 2 * addr_len,
				    IPPROTO_UDP + ntohs(udp->len)))));
}

/* ******************************************* */

static struct pfring_pkthdr hdr; /* note: this is static to be (re)used by on the fly reforging */

static int reforge_packet(u_char *buffer, u_int buffer_len, u_int idx, u_int use_prev_hdr) {
  struct ip_header *ip_header;

  if (reforge_mac) memcpy(buffer, mac_address, 6);

  if (reforge_ip) {
    if (!use_prev_hdr) {
      memset(&hdr, 0, sizeof(hdr));
      hdr.len = hdr.caplen = buffer_len;

      if (pfring_parse_pkt(buffer, &hdr, 4, 0, 0) < 3)
        return -1;
      if (hdr.extended_hdr.parsed_pkt.ip_version != 4)
        return -1;
    }

    ip_header = (struct ip_header *) &buffer[hdr.extended_hdr.parsed_pkt.offset.l3_offset];
    ip_header->daddr = dstaddr.s_addr;
    ip_header->saddr = htonl((ntohl(srcaddr.s_addr) + ip_offset + (idx % num_ip)) & 0xFFFFFFFF);
    ip_header->check = 0;
    ip_header->check = wrapsum(in_cksum((unsigned char *) ip_header, sizeof(struct ip_header), 0));

    if (hdr.extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP) {
      struct udp_header *udp_header = (struct udp_header *) &buffer[hdr.extended_hdr.parsed_pkt.offset.l4_offset];
      udp_header->check = 0;
      udp_header->check = wrapsum(in_cksum((unsigned char *) udp_header, sizeof(struct udp_header),
                                    in_cksum((unsigned char *) &buffer[hdr.extended_hdr.parsed_pkt.offset.payload_offset], 
                                      buffer_len - hdr.extended_hdr.parsed_pkt.offset.payload_offset,
                                      in_cksum((unsigned char *) &ip_header->saddr, 2 * sizeof(ip_header->saddr),
                                        IPPROTO_UDP + ntohs(udp_header->len)))));
    } else if (hdr.extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP) {
      struct tcp_header *tcp_header = (struct tcp_header *) &buffer[hdr.extended_hdr.parsed_pkt.offset.l4_offset];
      int tcp_hdr_len = hdr.extended_hdr.parsed_pkt.offset.payload_offset - hdr.extended_hdr.parsed_pkt.offset.l4_offset;
      int payload_len = buffer_len - hdr.extended_hdr.parsed_pkt.offset.payload_offset;
      tcp_header->check = 0;
      tcp_header->check = wrapsum(in_cksum((unsigned char *) tcp_header, tcp_hdr_len,
                                   in_cksum((unsigned char *) &buffer[hdr.extended_hdr.parsed_pkt.offset.payload_offset],
                                     payload_len,
                                     in_cksum((unsigned char *) &ip_header->saddr, 2 * sizeof(ip_header->saddr),
                                       IPPROTO_TCP + ntohs(htons(tcp_hdr_len + payload_len))))));
    }
  }

  return 0;
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *pcap_in = NULL, path[255] = { 0 };
  int c, i, j, n, verbose = 0, active_poll = 0;
  u_int mac_a, mac_b, mac_c, mac_d, mac_e, mac_f;
  u_char buffer[MAX_PACKET_SIZE];
  u_int32_t num_to_send = 0;
  int bind_core = -1;
  u_int16_t cpu_percentage = 0;
  double pps = 0;
#if !(defined(__arm__) || defined(__mips__))
  double gbit_s = 0, td;
  ticks tick_start = 0, tick_delta = 0;
#endif
  ticks hz = 0;
  struct packet *tosend;
  int num_uniq_pkts = 1, watermark = 0;
  u_int num_pcap_pkts = 0;
  int send_full_pcap_once = 1;
  char *pidFileName = NULL;
  int send_error_once = 1;
  int randomize = 0;
  int reforging_idx;
  int stdin_packet_len = 0;
  u_int ip_v = 4;
  int flush = 0;

  srandom(time(NULL));

  srcaddr.s_addr = 0x0100000A /* 10.0.0.1 */;
  dstaddr.s_addr = 0x0100A8C0 /* 192.168.0.1 */;

  while((c = getopt(argc, argv, "b:dD:hi:n:g:l:L:o:Oaf:Fr:vm:p:P:S:w:V:z")) != -1) {
    switch(c) {
    case 'b':
      num_ip = atoi(optarg);
      if (num_uniq_pkts < num_ip)
        num_uniq_pkts = num_ip;
      reforge_ip = 1;
      break;
    case 'D':
      inet_aton(optarg, &dstaddr);
      break;
    case 'h':
      printHelp();
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'f':
      pcap_in = strdup(optarg);
      break;
    case 'F':
      flush = 1;
      break;
    case 'n':
      num_to_send = atoi(optarg);
      send_full_pcap_once = 0;
      break;
    case 'o':
      ip_offset = atoi(optarg);
      break;
    case 'O':
      on_the_fly_reforging = 1;
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'l':
      send_len = atoi(optarg);
      if (send_len > MAX_PACKET_SIZE) send_len = MAX_PACKET_SIZE;
      break;
    case 'L':
      forge_vlan = 1;
      num_vlan = atoi(optarg);
      if (num_uniq_pkts < num_vlan)
        num_uniq_pkts = num_vlan;
      break;
    case 'v':
      verbose = 1;
      break;
    case 'a':
      active_poll = 1;
      break;
#if !(defined(__arm__) || defined(__mips__))
    case 'r':
      sscanf(optarg, "%lf", &gbit_s);
      break;
    case 'p':
      sscanf(optarg, "%lf", &pps);
      break;
#endif
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
    case 'S':
      inet_aton(optarg, &srcaddr);
      break;
    case 'w':
      watermark = atoi(optarg);
      break;
    case 'd':
      daemon_mode = 1;
      break;
    case 'P':
      pidFileName = strdup(optarg);
      break;
    case 'V':
      ip_v = atoi(optarg);
      break;
    case 'z':
      randomize = 1;
      break;
    default:
      printHelp();
    }
  }

  if (device == NULL 
      || num_uniq_pkts < 1
      || optind < argc /* Extra argument */)
    printHelp();

  if (num_uniq_pkts > 1000000 && !on_the_fly_reforging)
    printf("Warning: please use -O to reduce memory preallocation when many IPs are configured with -b\n");

  bind2node(bind_core);

  if (daemon_mode)
    daemonize(pidFileName);

  if (pidFileName)
    create_pid_file(pidFileName);

  printf("Sending packets on %s\n", device);

  pd = pfring_open(device, 1500, 0 /* PF_RING_PROMISC */);
  if(pd == NULL) {
    printf("pfring_open error [%s] (pf_ring not loaded or interface %s is down ?)\n", 
           strerror(errno), device);
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "pfsend");
    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8, version & 0x000000FF);
  }

  if(watermark > 0) {
    int rc;

    if((rc = pfring_set_tx_watermark(pd, watermark)) < 0) {
      if (rc == PF_RING_ERROR_NOT_SUPPORTED)
        printf("pfring_set_tx_watermark() now supported on %s\n", device);
      else
        printf("pfring_set_tx_watermark() failed [rc=%d]\n", rc);
    }
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  if(send_len < 60)
    send_len = 60;

  if (ip_v != 4 && send_len < 62)
    send_len = 62; /* min len with IPv6 */

#if !(defined(__arm__) || defined(__mips__))
  if(gbit_s != 0 || pps != 0) {
    /* computing usleep delay */
    tick_start = getticks();
    usleep(1);
    tick_delta = getticks() - tick_start;

    /* computing CPU freq */
    tick_start = getticks();
    usleep(1001);
    hz = (getticks() - tick_start - tick_delta) * 1000 /*kHz -> Hz*/;
    printf("Estimated CPU freq: %lu Hz\n", (long unsigned int)hz);
  }
#endif

  if(pcap_in) {
    char ebuf[256];
    u_char *pkt;
    struct pcap_pkthdr *h;
    pcap_t *pt = pcap_open_offline(pcap_in, ebuf);
    struct timeval beginning = { 0, 0 };
    u_int64_t avg_send_len = 0;
    u_int32_t num_orig_pcap_pkts = 0;

    on_the_fly_reforging = 0;

    if(pt) {
      struct packet *last = NULL;
      int datalink = pcap_datalink(pt);

      if (datalink == DLT_LINUX_SLL)
        printf("Linux 'cooked' packets detected, stripping 2 bytes from header..\n");

      while (1) {
	struct packet *p;
	int rc = pcap_next_ex(pt, &h, (const u_char **) &pkt);

	if(rc <= 0) break;
        
        num_orig_pcap_pkts++;
        if ((num_orig_pcap_pkts-1) < ip_offset) continue;

	if (num_pcap_pkts == 0) {
	  beginning.tv_sec = h->ts.tv_sec;
	  beginning.tv_usec = h->ts.tv_usec;
	}

	p = (struct packet *) malloc(sizeof(struct packet));
	if(p) {
	  p->len = h->caplen;
          if (datalink == DLT_LINUX_SLL) p->len -= 2;
	  p->ticks_from_beginning = (((h->ts.tv_sec - beginning.tv_sec) * 1000000) + (h->ts.tv_usec - beginning.tv_usec)) * hz / 1000000;
	  p->next = NULL;
	  p->pkt = (u_char *)malloc(p->len);

	  if(p->pkt == NULL) {
	    printf("Not enough memory\n");
	    break;
	  } else {
            if (datalink == DLT_LINUX_SLL) {
	      memcpy(p->pkt, pkt, 12);
              memcpy(&p->pkt[12], &pkt[14], p->len - 14);
	    } else {
	      memcpy(p->pkt, pkt, p->len);
            }
	    if(reforge_mac || reforge_ip)
              reforge_packet((u_char *) p->pkt, p->len, ip_offset + num_pcap_pkts, 0); 
	  }

	  if(last) {
	    last->next = p;
	    last = p;
	  } else
	    pkt_head = p, last = p;
	} else {
	  printf("Not enough memory\n");
	  break;
	}

	if(verbose)
	  printf("Read %d bytes packet from pcap file %s [%lu.%lu Secs =  %lu ticks@%luhz from beginning]\n",
		 p->len, pcap_in, h->ts.tv_sec - beginning.tv_sec, h->ts.tv_usec - beginning.tv_usec,
		 (long unsigned int)p->ticks_from_beginning,
		 (long unsigned int)hz);

	avg_send_len += p->len;
	num_pcap_pkts++;
      } /* while */

      if (num_pcap_pkts == 0) {
        printf("Pcap file %s is empty\n", pcap_in);
        pfring_close(pd);
        return(-1);
      }

      avg_send_len /= num_pcap_pkts;

      pcap_close(pt);
      printf("Read %d packets from pcap file %s\n",
	     num_pcap_pkts, pcap_in);
      last->next = pkt_head; /* Loop */
      send_len = avg_send_len;

      if (send_full_pcap_once)
        num_to_send = num_pcap_pkts;
    } else {
      printf("Unable to open file %s\n", pcap_in);
      pfring_close(pd);
      return(-1);
    }
  } else {
    struct packet *p = NULL, *last = NULL;

    if ((stdin_packet_len = read_packet_hex(buffer, sizeof(buffer))) > 0) {
      send_len = stdin_packet_len;
    }

    for (i = 0; i < num_uniq_pkts; i++) {

      if (stdin_packet_len <= 0) {
        forge_udp_packet(buffer, send_len, i, (ip_v != 4 && ip_v != 6) ? (i&0x1 ? 6 : 4) : ip_v);
      } else {
        if (reforge_packet(buffer, send_len, i, 0) != 0) { 
          fprintf(stderr, "Unable to reforge the provided packet\n");
          return -1;
        }
      }

      p = (struct packet *) malloc(sizeof(struct packet));
      if (p == NULL) { 
	fprintf(stderr, "Unable to allocate memory requested (%s)\n", strerror(errno));
	return (-1);
      }

      if (i == 0) pkt_head = p;

      p->len = send_len;
      p->ticks_from_beginning = 0;
      p->next = pkt_head;
      p->pkt = (u_char *) malloc(p->len);

      if (p->pkt == NULL) {
	fprintf(stderr, "Unable to allocate memory requested (%s)\n", strerror(errno));
	return (-1);
      }

      memcpy(p->pkt, buffer, send_len);

      if (last != NULL) last->next = p;
      last = p;

      if (on_the_fly_reforging) {
#if 0
        if (stdin_packet_len <= 0) { /* forge_udp_packet, parsing packet for on the fly reforing */
          memset(&hdr, 0, sizeof(hdr));
          hdr.len = hdr.caplen = p->len;
          if (pfring_parse_pkt(p->pkt, &hdr, 4, 0, 0) < 3) {
            fprintf(stderr, "Unable to reforge the packet (unexpected)\n");
            return -1; 
          }
        }
#endif
        break;
      }
    }
  }

#if !(defined(__arm__) || defined(__mips__))
  if(gbit_s > 0) {
    /* computing max rate */
    pps = ((gbit_s * 1000000000) / 8 /*byte*/) / (8 /*Preamble*/ + send_len + 4 /*CRC*/ + 12 /*IFG*/);
  } else if (gbit_s < 0) {
    /* capture rate */
    pps = -1;
  } /* else use pps */

  if (pps > 0) {
    td = (double) (hz / pps);
    tick_delta = (ticks)td;

    if (gbit_s > 0)
      printf("Rate set to %.2f Gbit/s, %d-byte packets, %.2f pps\n", gbit_s, (send_len + 4 /*CRC*/), pps);
    else
      printf("Rate set to %.2f pps\n", pps);
  }
#endif

  if(bind_core >= 0)
    bind2core(bind_core);

  if(wait_for_packet && (cpu_percentage > 0)) {
    if(cpu_percentage > 99) cpu_percentage = 99;
    pfring_config(cpu_percentage);
  }

  if(!verbose) {
    signal(SIGALRM, my_sigalarm);
    alarm(1);
  }

  gettimeofday(&startTime, NULL);
  memcpy(&lastTime, &startTime, sizeof(startTime));

  pfring_set_socket_mode(pd, send_only_mode);

  if(pfring_enable_ring(pd) != 0) {
    printf("Unable to enable ring :-(\n");
    pfring_close(pd);
    return(-1);
  }

  tosend = pkt_head;
  i = 0;
  reforging_idx = 0;

  pfring_set_application_stats(pd, "Statistics not yet computed: please try again...");
  if(pfring_get_appl_stats_file_name(pd, path, sizeof(path)) != NULL)
    fprintf(stderr, "Dumping statistics on %s\n", path);

#if !(defined(__arm__) || defined(__mips__))
  if(pps != 0)
    tick_start = getticks();
#endif

  if (pps < 0) /* flush for sending at the exact original pcap speed only, otherwise let pf_ring flush when needed) */
    flush = 1;

  while((num_to_send == 0) 
	|| (i < num_to_send)) {
    int rc;

  redo:

    if (unlikely(do_shutdown)) 
      break;

    if (on_the_fly_reforging) {
      if (stdin_packet_len <= 0)
        forge_udp_packet(tosend->pkt, tosend->len, reforging_idx + num_pkt_good_sent, (ip_v != 4 && ip_v != 6) ? (i&0x1 ? 6 : 4) : ip_v);
      else
        reforge_packet(tosend->pkt, tosend->len, reforging_idx + num_pkt_good_sent, 1); 
    }

    rc = pfring_send(pd, (char *) tosend->pkt, tosend->len, flush);

    if (unlikely(verbose))
      printf("[%d] pfring_send(%d) returned %d\n", i, tosend->len, rc);

    if (rc == PF_RING_ERROR_INVALID_ARGUMENT) {
      if (send_error_once) {
        printf("Attempting to send invalid packet [len: %u][MTU: %u]\n",
	       tosend->len, pd->mtu);
        send_error_once = 0;
      }
    } else if (rc < 0) {
      /* Not enough space in buffer */
      if(!active_poll)
	usleep(1);
      goto redo;
    } else {
      num_pkt_good_sent++;
      num_bytes_good_sent += tosend->len + 24 /* 8 Preamble + 4 CRC + 12 IFG */;
    }

    if (randomize) {
      n = random() & 0xF;
      if (on_the_fly_reforging)
        reforging_idx += n;
      else
        for (j = 0; j < n; j++)
          tosend = tosend->next;
    }
    tosend = tosend->next;

#if !(defined(__arm__) || defined(__mips__))
    if(pps > 0) {
      /* rate set */
      while((getticks() - tick_start) < (num_pkt_good_sent * tick_delta))
        if (unlikely(do_shutdown)) break;
    } else if (pps < 0) {
      /* real pcap rate */
      if (tosend->ticks_from_beginning == 0)
        tick_start = getticks(); /* first packet, resetting time */
      while((getticks() - tick_start) < tosend->ticks_from_beginning)
        if (unlikely(do_shutdown)) break;
    }
#endif

    if(num_to_send > 0) i++;
  } /* for */

  print_stats();
  printf("Sent %llu packets\n", (long long unsigned int) num_pkt_good_sent);

  pfring_close(pd);

  if (pidFileName)
    remove_pid_file(pidFileName);

  return(0);
}
