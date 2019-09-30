/*
 * (C) 2003-2019 - ntop 
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

#ifdef HAVE_PF_RING
#include "../lib/config.h"
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

//#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h> /* for CPU_XXXX */
#include <stdarg.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>

#ifndef HAVE_DPDK
#include <netinet/if_ether.h>
#else
#define ETH_ALEN 6
#endif

#ifdef HAVE_PF_RING_ZC
#include "pfring_zc.h"
#endif

#define POW2(n) ((n & (n - 1)) == 0)

struct compact_eth_hdr {
  unsigned char   h_dest[ETH_ALEN];
  unsigned char   h_source[ETH_ALEN];
  u_int16_t       h_proto;
};

struct compact_ip_hdr {
  u_int8_t      ihl:4,
                version:4;
  u_int8_t      tos;
  u_int16_t     tot_len;
  u_int16_t	id;
  u_int16_t	frag_off;
  u_int8_t	ttl;
  u_int8_t	protocol;
  u_int16_t	check;
  u_int32_t	saddr;
  u_int32_t	daddr;
};

struct compact_ipv6_hdr {
  u_int32_t		flow_lbl:24,
  			priority:4,
			version:4;
  u_int16_t		payload_len;
  u_int8_t		nexthdr;
  u_int8_t		hop_limit;
  u_int32_t		saddr[4]; /* struct in6_addr */
  u_int32_t 		daddr[4]; /* struct in6_addr */
};

struct compact_udp_hdr {
  u_int16_t	  sport;
  u_int16_t	  dport;
  u_int16_t	  len;
  u_int16_t	  check;
};

/* ******************************** */

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 * Borrowed from DHCPd
 */
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

/* ******************************** */

static u_int32_t wrapsum (u_int32_t sum) {
  sum = ~sum & 0xFFFF;
  return htons(sum);
}

/* ******************************** */

static int compute_csum = 1;
static int num_ips = 1;

static u_char matrix_buffer[
  sizeof(struct ether_header) + 
  sizeof(struct compact_ip_hdr) + 
  sizeof(struct compact_udp_hdr)
];

static void forge_udp_packet_fast(u_char *buffer, u_int packet_len, u_int idx) {
  int i;
  struct compact_ip_hdr *ip_header;
  struct compact_udp_hdr *udp_header;
  u_int32_t src_ip = 0x0A000000; /* 10.0.0.0 */ 
  u_int32_t dst_ip =  0xC0A80001; /* 192.168.0.1 */
  u_int16_t src_port = 2014-2019, dst_port = 3000;

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

    ip_header = (struct compact_ip_hdr*) &buffer[sizeof(struct ether_header)];
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

    udp_header = (struct compact_udp_hdr *)(buffer + sizeof(struct ether_header) + sizeof(struct compact_ip_hdr));
    udp_header->sport = htons(src_port);
    udp_header->dport = htons(dst_port);
    udp_header->len = htons(packet_len-sizeof(struct ether_header)-sizeof(struct compact_ip_hdr));
    udp_header->check = 0;

    memcpy(matrix_buffer, buffer, sizeof(struct ether_header) +  sizeof(struct compact_ip_hdr) + sizeof(struct compact_udp_hdr));
  } else {
    memcpy(buffer, matrix_buffer, sizeof(struct ether_header) +  sizeof(struct compact_ip_hdr) + sizeof(struct compact_udp_hdr));
  }

  ip_header = (struct compact_ip_hdr*) &buffer[sizeof(struct ether_header)];
  ip_header->saddr = htonl(src_ip);
  if (compute_csum)
    ip_header->check = wrapsum(in_cksum((unsigned char *)ip_header, sizeof(struct compact_ip_hdr), 0));
  else
    ip_header->check = 0;

#if 0
  i = sizeof(struct ether_header) + sizeof(struct compact_ip_hdr) + sizeof(struct compact_udp_hdr);
  udp_header->check = wrapsum(in_cksum((unsigned char *)udp_header, sizeof(struct compact_udp_hdr),
                                       in_cksum((unsigned char *)&buffer[i], packet_len-i,
						in_cksum((unsigned char *)&ip_header->saddr,
							 2*sizeof(ip_header->saddr),
							 IPPROTO_UDP + ntohs(udp_header->len)))));
#endif
}

/* ******************************** */

#if !defined(HAVE_DPDK)
static int ip_offset = 0;
static int reforge_src_mac = 0, reforge_dst_mac = 0;
static int forge_vlan = 0, num_vlan = 1;
static int forge_payload = 0;
static char srcmac[6] = { 0 }, dstmac[6] = { 0 };
static struct in_addr srcaddr = { 0 }, dstaddr = { 0 };

static void forge_udp_packet(u_char *buffer, u_int buffer_len, u_int idx, u_int ip_version) {
  struct eth_vlan_hdr *vlan;
  struct compact_ip_hdr *ip;
  struct compact_ipv6_hdr *ip6;
  struct compact_udp_hdr *udp;
  u_char *addr;
  int l2_len, ip_len, addr_len, i, payload_off;

  /* Reset packet */
  memset(buffer, 0, buffer_len);

  l2_len = sizeof(struct ether_header);

  for(i=0; i<12; i++) buffer[i] = i;
  if(reforge_dst_mac) memcpy(buffer, dstmac, 6);
  if(reforge_src_mac) memcpy(&buffer[6], srcmac, 6);

  if (forge_vlan) { 
    vlan = (struct eth_vlan_hdr *) &buffer[l2_len];
    buffer[l2_len-2] = 0x81, buffer[l2_len-1] = 0x00;
    vlan->h_vlan_id = htons((idx % num_vlan) + 1); 
    l2_len += sizeof(struct eth_vlan_hdr);
  }

  if (ip_version == 6) {
    buffer[l2_len-2] = 0x86, buffer[l2_len-1] = 0xDD;
    ip6 = (struct compact_ipv6_hdr *) &buffer[l2_len];
    ip_len = sizeof(*ip6);
    ip6->version = 6;
    ip6->payload_len = htons(buffer_len - l2_len - ip_len);
    ip6->nexthdr = IPPROTO_UDP;
    ip6->hop_limit = 0xFF;
    ip6->saddr[0] = htonl((ntohl(srcaddr.s_addr) + ip_offset + (idx % num_ips)) & 0xFFFFFFFF);
    ip6->daddr[0] = dstaddr.s_addr;
    addr = (u_char *) ip6->saddr;
    addr_len = sizeof(ip6->saddr);
    payload_off = l2_len + sizeof(struct compact_ipv6_hdr);
  } else {
    buffer[l2_len-2] = 0x08, buffer[l2_len-1] = 0x00;
    ip = (struct compact_ip_hdr *) &buffer[l2_len];
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
    ip->saddr = htonl((ntohl(srcaddr.s_addr) + ip_offset + (idx % num_ips)) & 0xFFFFFFFF);
    ip->check = wrapsum(in_cksum((unsigned char *) ip, ip_len, 0));
    addr = (u_char *) &ip->saddr;
    addr_len = sizeof(ip->saddr);
    payload_off = l2_len + sizeof(struct compact_ip_hdr);
  }

  udp = (struct compact_udp_hdr *)(buffer + l2_len + ip_len);
  udp->sport = htons(2012);
  udp->dport = htons(3000);
  udp->len = htons(buffer_len - l2_len - ip_len);
  udp->check = 0; /* It must be 0 to compute the checksum */

  payload_off += sizeof(struct compact_udp_hdr);
  if (forge_payload)
    for (i = payload_off; i < buffer_len; i++)
      buffer[i] = i;

  /*
    http://www.cs.nyu.edu/courses/fall01/G22.2262-001/class11.htm
    http://www.ietf.org/rfc/rfc0761.txt
    http://www.ietf.org/rfc/rfc0768.txt
  */

  i = l2_len + ip_len + sizeof(struct compact_udp_hdr);
  udp->check = wrapsum(in_cksum((unsigned char *) udp, sizeof(struct compact_udp_hdr),
                                in_cksum((unsigned char *) &buffer[i], buffer_len - i,
				  in_cksum((unsigned char *) addr, 2 * addr_len,
				    IPPROTO_UDP + ntohs(udp->len)))));
}
#endif

/* ******************************** */

void daemonize(void) {
  pid_t pid, sid;

  pid = fork();
  if (pid < 0) exit(EXIT_FAILURE);
  if (pid > 0) exit(EXIT_SUCCESS);

  sid = setsid();
  if (sid < 0) exit(EXIT_FAILURE);

  if ((chdir("/")) < 0) exit(EXIT_FAILURE);

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}

/* ******************************** */

int drop_privileges(const char *username) {
  struct passwd *pw = NULL;

  if (getgid() && getuid()) {
    fprintf(stderr, "privileges are not dropped as we're not superuser\n");
    return -1;
  }

  pw = getpwnam(username);

  if(pw == NULL) {
    username = "nobody";
    pw = getpwnam(username);
  }

  if(pw != NULL) {
    if(setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
      fprintf(stderr, "unable to drop privileges [%s]\n", strerror(errno));
      return -1;
    } else {
      fprintf(stderr, "user changed to %s\n", username);
    }
  } else {
    fprintf(stderr, "unable to locate user %s\n", username);
    return -1;
  }

  umask(0);
  return 0;
}

/* ******************************** */

void create_pid_file(char *pidFile) {
  FILE *fp;

  if (pidFile == NULL) return;

  fp = fopen(pidFile, "w");

  if (fp == NULL) {
    fprintf(stderr, "unable to create pid file %s: %s\n", pidFile, strerror(errno));
    return;
  }

  fprintf(fp, "%d\n", getpid());
  fclose(fp);
}

/* ******************************** */

void remove_pid_file(char *pidFile) {
  if (pidFile == NULL) return;

  unlink(pidFile);
}

/* *************************************** */
/*
 * The time difference in millisecond
 */
double delta_time (struct timeval * now,
		   struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }
  return((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

/* *************************************** */

#define MSEC_IN_DAY    (1000 * 60 * 60 * 24) 
#define MSEC_IN_HOUR   (1000 * 60 * 60)
#define MSEC_IN_MINUTE (1000 * 60)
#define MSEC_IN_SEC    (1000)

char *msec2dhmsm(u_int64_t msec, char *buf, u_int buf_len) {
  snprintf(buf, buf_len, "%u:%02u:%02u:%02u:%03u", 
    (unsigned) (msec / MSEC_IN_DAY), 
    (unsigned) (msec / MSEC_IN_HOUR)   %   24, 
    (unsigned) (msec / MSEC_IN_MINUTE) %   60, 
    (unsigned) (msec / MSEC_IN_SEC)    %   60,
    (unsigned) (msec)                  % 1000
  );
  return(buf);
}

/* *************************************** */

char *_intoa(unsigned int addr, char* buf, u_short bufLen) {
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

/* *************************************** */

int busid2node(int slot, int bus, int device, int function) {
  char path[256];
  FILE *fd;
  int bus_id = -1;

  if (!slot && !bus && !device && !function)
    return bus_id;

  snprintf(path, sizeof(path), "/sys/bus/pci/devices/%04X:%02X:%02X.%X/numa_node", 
    slot, bus, device, function);

  if ((fd = fopen(path, "r")) != NULL) {
    char data[32] = { 0 };

    if (fgets(data, sizeof(data), fd) != NULL)
      bus_id = atoi(data);

    fclose(fd);
  }

  return bus_id;
}

/* *************************************** */

int bind2node(int core_id) {
#ifdef HAVE_PF_RING_ZC
  if (core_id < 0)
    return -1;

  pfring_zc_numa_set_numa_affinity(pfring_zc_numa_get_cpu_node(core_id));
#endif

  return 0;
}

/* *************************************** */

/* Bind this thread to a specific core */

int bindthread2core(pthread_t thread_id, int core_id) {
#ifdef HAVE_PTHREAD_SETAFFINITY_NP
  cpu_set_t cpuset;
  int s;

  if (core_id < 0)
    return -1;

  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);

  if((s = pthread_setaffinity_np(thread_id, sizeof(cpu_set_t), &cpuset)) != 0) {
    fprintf(stderr, "Error while binding to core %u: errno=%i\n", core_id, s);
    return(-1);
  } else {
    return(0);
  }
#else
  fprintf(stderr, "WARNING: your system lacks of pthread_setaffinity_np() (not core binding)\n");
  return(0);
#endif
}

/* *************************************** */

/* Bind the current thread to a core */

int bind2core(int core_id) {
  return(bindthread2core(pthread_self(), core_id));
}

/* *************************************** */

typedef u_int64_t ticks;

static __inline__ ticks getticks(void)
{
#ifdef __ARM_ARCH
  /* 
     Not supported 
     See https://stackoverflow.com/questions/40454157/is-there-an-equivalent-instruction-to-rdtsc-in-arm
  */
  return(0);
#else
  u_int32_t a, d;
  // asm("cpuid"); // serialization

  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return (((ticks)a) | (((ticks)d) << 32));
#endif
}

/* *************************************** */

#if !defined(HAVE_DPDK)
#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__

static int trace_verbosity = 2;
static FILE *trace_file = NULL;

void trace(int trace_level, char *file, int line, char * format, ...) {
  va_list va_ap;
  char buf[2048], out_buf[640];
  char theDate[32];
  const char *extra_msg = "";
  time_t theTime;
  FILE *out_file;

  if (trace_level > trace_verbosity)
    return;

  theTime = time(NULL);

  va_start(va_ap, format);

  memset(buf, 0, sizeof(buf));
  strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

  vsnprintf(buf, sizeof(buf)-1, format, va_ap);

  if (trace_level == 0)
    extra_msg = "ERROR: ";
  else if (trace_level == 1)
    extra_msg = "WARNING: ";

  while (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

  snprintf(out_buf, sizeof(out_buf), "%s [%s:%d] %s%s", theDate, file, line, extra_msg, buf);

  if (trace_file != NULL) out_file = trace_file;
  else if (trace_level == 0) out_file = stderr;
  else out_file = stdout;

  fprintf(out_file, "%s\n", out_buf);
  fflush(out_file);

  va_end(va_ap);
}
#endif

/* *************************************** */

#if !defined(HAVE_DPDK)
static char *etheraddr2string(const u_char *ep, char *buf) {
  const char *hex = "0123456789ABCDEF";
  u_int i, j;
  char *cp;

  cp = buf;
  if((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}
#endif

/* *************************************** */

