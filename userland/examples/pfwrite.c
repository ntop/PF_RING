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

#include <pcap.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>

// #define DEBUG

#define HAVE_PCAP

#include "config.h"

#ifdef HAVE_REDIS
#include <hiredis/hiredis.h>
#endif

#include "pfring.h"
//#include "pfutils.c"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */

#define MAX_NUM_GTP_TUNNELS 8
u_int num_gtp_tunnels = 0;
u_int32_t gtp_tunnels[MAX_NUM_GTP_TUNNELS];

unsigned long long numPkts = 0, numBytes = 0;

struct gtpv1_header {
  u_int8_t flags, message_type;
  u_int16_t total_length;
  u_int32_t tunnel_id;
  u_int16_t sequence_number;
  u_int8_t pdu_nuber, next_ext_header;
} __attribute__((__packed__));

#define DEFAULT_DEVICE "eth0"

pfring *pd;
pcap_dumper_t *dumper = NULL;
FILE *dumper_fd = NULL;
int verbose = 0;
u_int32_t num_pkts=0;
char *imsi = NULL;

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  if(called) return; else called = 1;

  if(dumper)
    pcap_dump_close(dumper);
  else if(dumper_fd)
    fclose(dumper_fd);

  pfring_close(pd);

  printf("\nSaved %d packets on disk\n", num_pkts);
  exit(0);
}

/* *************************************** */

void printHelp(void) {
  printf("pfwrite - (C) 2003-14 Deri Luca <deri@ntop.org>\n");
  printf("-h              [Print help]\n");
  printf("-i <device>     [Device name]\n");
  printf("-w <dump file>  [Dump file path]\n");
  printf("-f <BPF filter> [Ingress BPF filter]\n");
  printf("-c <cluster id> [Cluster id]\n");
#ifdef HAVE_REDIS
  printf("-m <imsi>       [Dump only the specified IMSI traffic (Example: -m 284031122831060)]\n");
#endif
  printf("-g <GTP TEID>   [Dump only the specified tunnel (example -g 94148 [dec] or -g 381CE8C0 [hex])]\n");
  printf("-d              [Save packet digest instead of pcap packets]\n");
  printf("-S              [Do not strip hw timestamps (if present)]\n");
  printf("-b              [Daemonize this application]\n");
  printf("\n"
	 "Please consider using n2disk for dumping\n"
	 "traces at high speed (http://www.ntop.org/products/n2disk/)\n");
}

/* *************************************** */

void daemonize(void) {
  int childpid;

  signal(SIGHUP, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);

  if((childpid = fork()) < 0)
    printf("Occurred while daemonizing (errno=%d)", errno);
  else {
    if(!childpid) { /* child */
      int rc;

      rc = chdir("/");
      if(rc != 0)
	printf("Error while moving to / directory");

      setsid();  /* detach from the terminal */

      fclose(stdin);
      fclose(stdout);
      /* fclose(stderr); */

      /*
       * clear any inherited file mode creation mask
       */
      umask(0);

      /*
       * Use line buffered stdout
       */
      /* setlinebuf (stdout); */
      setvbuf(stdout, (char *)NULL, _IOLBF, 0);
    } else { /* father */
      printf("Parent process is exiting (this is normal). Bye bye...");
      exit(0);
    }
  }
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
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

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ************************************ */

char* intoa(unsigned int addr) {
  static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

  return(_intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

inline char* in6toa(struct in6_addr addr6) {
  static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

  snprintf(buf, sizeof(buf),
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	   addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
	   addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
	   addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
	   addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
	   addr6.s6_addr[15]);

  return(buf);
}

/* ************************************ */

void handleImsi(char *rsp) {
  if(strtok(rsp, ";") != NULL) {
    char *tunnel;
    int i;

    num_gtp_tunnels = 0;
    for(i=0; i<2; i++)
      if((tunnel = strtok(NULL, ";")) != NULL) {
	gtp_tunnels[num_gtp_tunnels] = atoll(tunnel);
	printf("Added GTP tunnel to filter %u/%08X [%s]\n",
	       gtp_tunnels[num_gtp_tunnels], gtp_tunnels[num_gtp_tunnels],
	       tunnel);
	num_gtp_tunnels++;
      }

    printf("Total GTP tunnels: %d\n", num_gtp_tunnels);
  }
}

/* *************************************** */

void deleteImsi() {
  num_gtp_tunnels = 0;
  printf("Total GTP tunnels: %d\n", num_gtp_tunnels);
}

/* *************************************** */

static void* imsi_publisher_thread(void* _id) {
#ifdef HAVE_REDIS
  redisContext *redis = redisConnect("127.0.0.1", 6379);
  redisReply* r;

  if(redis == NULL) {
    printf("WARNING: Unable to connect to local redis 127.0.0.1:6379\n");
    // return(-1);
  } else {
    /* Read initial IMSI tunnel Info */
    if(((r = redisCommand(redis, "GET imsi.%s", imsi)) == NULL) || (r->str == NULL)) {
      handleImsi(r->str);
    }

    while(1) {
      printf("Listening for ucloud events...\n");

      r = redisCommand(redis, "SUBSCRIBE imsi.create");
      freeReplyObject(r);

      r = redisCommand(redis, "SUBSCRIBE imsi.delete");
      freeReplyObject(r);

      while(redisGetReply(redis, (void**)&r) == REDIS_OK) {
	if(r->elements == 3) {
	  if((strcmp(r->element[1]->str, "imsi.create") == 0) && (r->element[2]->str != NULL)) {
	    char *semicolumn = strchr(r->element[2]->str, ';');

	    /* IMSI;IP;Upstream_Tunnel;Downstream_Tunnel */
	    if(semicolumn) {
	      u_int len = strlen(r->element[2]->str)-strlen(semicolumn);

	      if(strncmp(r->element[2]->str, imsi, len) == 0) {
		printf("Found matching IMSI %s\n", r->element[2]->str);
		handleImsi(&semicolumn[1]);
	      }
	    }
	  } else if(strcmp(r->element[1]->str, "imsi.delete") == 0) {
	    /* imsi.delete */

	    if(strcmp(r->element[2]->str, imsi) == 0) {
	      printf("Found matching IMSI %s\n", r->element[2]->str);
	      deleteImsi();
	    }
	  }
	}

	freeReplyObject(r);
      } /* while */

      redisFree(redis);
    } /* while */
  }
#endif

  return(NULL);
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c, *out_dump = NULL;
  u_int flags = 0, dont_strip_hw_ts = 0, dump_digest = 0, cluster_id = 0;
  int32_t thiszone;
  u_char *p;
  char *bpfFilter = NULL;
  struct pfring_pkthdr hdr;
  u_int8_t be_a_daemon = 0;
  pthread_t my_thread;

  while((c = getopt(argc,argv,"hi:w:Sdg:f:c:b"
#ifdef HAVE_REDIS
		    "m:"
#endif
		    )) != -1) {
    switch(c) {
    case 'b':
      be_a_daemon = 1;
      break;

    case 'c':
      cluster_id = atoi(optarg);
      break;

    case 'd':
      dump_digest = 1;
      break;

    case 'h':
      printHelp();
      return(0);
      break;

    case 'w':
      out_dump = strdup(optarg);
      break;

    case 'm':
      imsi = strdup(optarg);
      pthread_create(&my_thread, NULL, imsi_publisher_thread, (void*)NULL);
      break;

    case 'g':
      if(num_gtp_tunnels < MAX_NUM_GTP_TUNNELS) {
	u_int32_t v;

	if(strlen(optarg) == 8)
	  sscanf(optarg, "%08X", &v);
	else
	  v = atoll(optarg);

	gtp_tunnels[num_gtp_tunnels++]=v;
	printf("Added GTP tunnel to filter %u/%08X [%s]\n", v, v, optarg);
      } else
	printf("Too many GTP tunnels defined (-g): ignored\n");
      break;

    case 'i':
      device = strdup(optarg);
      break;

    case 'S':
      dont_strip_hw_ts = 1;
      break;

    case 'f':
      bpfFilter = optarg;
      break;
    }
  }

  if(out_dump == NULL) {
    printHelp();
    return(-1);
  }

  memset(&hdr, 0, sizeof(hdr));

  flags = PF_RING_PROMISC;
  if(dump_digest)       flags |= PF_RING_LONG_HEADER;
  if(!dont_strip_hw_ts) flags |= PF_RING_STRIP_HW_TIMESTAMP;

  if((pd = pfring_open(device, 1520, flags)) == NULL) {
    printf("pfring_open error [%s]\n", strerror(errno));
    return(-1);
  } else
    pfring_set_application_name(pd, "pfwrite");

  thiszone = gmt_to_local(0);
  if(device) printf("Capture device: %s\n", device);
  printf("Dump file path: %s\n", out_dump);

  if(cluster_id > 0) {
    int rc;

    if((rc = pfring_set_cluster(pd, cluster_id, cluster_per_flow_2_tuple)) != 0)
      printf("pfring_set_cluster returned %d\n", rc);
    else
      printf("Bound to clusterId %d\n", cluster_id);
  }

  if(bpfFilter != NULL) {
    int rc = pfring_set_bpf_filter(pd, bpfFilter);

    if(rc != 0)
      printf("pfring_set_bpf_filter(%s) returned %d\n", bpfFilter, rc);
    else
      printf("Successfully set BPF filter '%s'\n", bpfFilter);
  }

  signal(SIGINT, sigproc);

  pfring_enable_ring(pd);

  if(be_a_daemon) daemonize();

  if(dump_digest) {
    if((dumper_fd = fopen(out_dump, "w")) == NULL) {
      printf("Unable to create dump file %s\n", out_dump);
      return(-1);
    }
  } else {
    dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */), out_dump);
    if(dumper == NULL) {
      printf("Unable to create dump file %s\n", out_dump);
      return(-1);
    }
  }

  if(dumper_fd) fprintf(dumper_fd, "# Time\tLen\tEth Type\tVLAN\tL3 Proto\tSrc IP:Port\tDst IP:Port\n");

  while(1) {
    if(pfring_recv(pd, &p, 0, &hdr, 1 /* wait_for_packet */) > 0) {
      if(dumper) {
	u_int8_t to_dump = 0;

	if(imsi != NULL) {
	  if(num_gtp_tunnels > 0) {
	    memset(&hdr.extended_hdr, 0, sizeof(hdr.extended_hdr));

	    pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)&hdr, 5, 0, 0);

#ifdef DEBUG
	    if(hdr.extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/ ) {
	      printf("[IPv4][%s:%d ", intoa(hdr.extended_hdr.parsed_pkt.ipv4_src), hdr.extended_hdr.parsed_pkt.l4_src_port);
	      printf("-> %s:%d] ", intoa(hdr.extended_hdr.parsed_pkt.ipv4_dst), hdr.extended_hdr.parsed_pkt.l4_dst_port);
	    } else {
	      printf("[IPv6][%s:%d ",    in6toa(hdr.extended_hdr.parsed_pkt.ipv6_src), hdr.extended_hdr.parsed_pkt.l4_src_port);
	      printf("-> %s:%d] ", in6toa(hdr.extended_hdr.parsed_pkt.ipv6_dst), hdr.extended_hdr.parsed_pkt.l4_dst_port);
	    }
	    printf("[TEID: %08X]\n", hdr.extended_hdr.parsed_pkt.tunnel.tunnel_id);
#endif

	    if((hdr.extended_hdr.parsed_pkt.tunnel.tunnel_id != 0xFFFFFFFF)
	       && (hdr.extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP)
	       && (((hdr.extended_hdr.parsed_pkt.l4_src_port == 2123) && (hdr.extended_hdr.parsed_pkt.l4_dst_port == 2123))
		   || ((hdr.extended_hdr.parsed_pkt.l4_src_port == 2152) && (hdr.extended_hdr.parsed_pkt.l4_dst_port == 2152)))) {
	      u_int8_t found = 0, i;
	      struct gtpv1_header *g = (struct gtpv1_header*)&p[hdr.extended_hdr.parsed_pkt.offset.payload_offset];

	      if((g->message_type == 0x10) /* Create Request */
		 || (g->message_type == 0x12) /* Update Request */) {
		u_int16_t displ = 12+hdr.extended_hdr.parsed_pkt.offset.payload_offset;

		while(displ < hdr.caplen) {
		  u_int8_t field_id = p[displ];

		  if(field_id == 0x02 /* IMSI */) {
		    int i, j = 0;
		    char *_imsi = (char*)&p[displ+1], u_imsi[24];

		    for(i = 0; i < 8; i++) {
		      if((_imsi[i] & 0x0F) <= 9)
			u_imsi[j++] = (_imsi[i] & 0x0F) + 0x30;
		      if(((_imsi[i] >> 4) & 0x0F) <= 9)
			u_imsi[j++] = ((_imsi[i] >> 4) & 0x0F) + 0x30;
		    }
		    u_imsi[j] = '\0';

		    if(strcmp(imsi, u_imsi) == 0) {
		      to_dump = 1; /* Ok we can dump the packet */
		    } else
		      break;

		    displ += 9;
		    break;
		  } else {
		    switch(field_id) {
		    case 0x03: /* Routing Area Info */
		      displ += 7;
		      break;

		    case 0x14: /* NSAPI */
		      displ += 2;
		      break;

		    case 0x00: /* Ignore */
		    case 0x01: /* Cause */
		    case 0x08: /* Reordering Required */
		    case 0x0E: /* Recovery */
		    case 0x0F: /* Selection Mode */
		    case 0x13: /* Teardown Indicator */
		    case 0xB4: /* PS Handover XID Parameters 7.7.79 */
		      displ += 2;
		      break;

		    case 0x10: /* TEID Data */
		      displ += 5;
		      break;

		    case 0x11: /* TEID Control */
		      displ += 5;
		      break;

		    case 0x1A: /* Charging Characteristics */
		      displ += 3;
		      break;

		    case 0x7F: /* Charging ID */
		      displ += 5;
		      break;

		    default:
		      displ += ntohs(*(u_int16_t*)&p[displ+1]) + 3;
		      break;
		    }
		  }
		} /* while */
	      } else if(g->message_type == 0xFF /* Data */) {
#ifdef DEBUG
		printf("%08X\n", hdr.extended_hdr.parsed_pkt.tunnel.tunnel_id);
#endif
		for(i=0; i<num_gtp_tunnels; i++)
		  if(gtp_tunnels[i] == hdr.extended_hdr.parsed_pkt.tunnel.tunnel_id) {
		    to_dump = 1, found = 1;
		    break;
		  }

		if(!found) continue;
	      } else
		continue;
	    } else
	      continue;
	  }
	} else
	  to_dump = 1;

#ifdef DEBUG
	printf("Dump \n");
#endif

	if(to_dump) {
	  pcap_dump((u_char*)dumper, (struct pcap_pkthdr*)&hdr, p);
	  fprintf(stdout, ".");
	  fflush(stdout);
	  num_pkts++;
	}
      } else {
	u_int32_t s, usec, nsec;

	if(hdr.ts.tv_sec == 0) {
	  memset((void*)&hdr.extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));
	  pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)&hdr, 5, 1, 1);
	}

	s = (hdr.ts.tv_sec + thiszone) % 86400;

	if(hdr.extended_hdr.timestamp_ns) {
	  if (pd->dna.dna_dev.mem_info.device_model != intel_igb_82580 /* other than intel_igb_82580 */)
	    s = ((hdr.extended_hdr.timestamp_ns / 1000000000) + thiszone) % 86400;
	  /* "else" intel_igb_82580 has 40 bit ts, using gettimeofday seconds:
	   * be careful with drifts mixing sys time and hw timestamp */
	  usec = (hdr.extended_hdr.timestamp_ns / 1000) % 1000000;
	  nsec = hdr.extended_hdr.timestamp_ns % 1000;
	} else {
	  usec = hdr.ts.tv_usec, nsec = 0;
	}

	fprintf(dumper_fd, "%02d:%02d:%02d.%06u%03u"
		"\t%d\t%04X\t%u\t%d",
		s / 3600, (s % 3600) / 60, s % 60, usec, nsec,
		hdr.len,
		hdr.extended_hdr.parsed_pkt.eth_type,
		hdr.extended_hdr.parsed_pkt.vlan_id,
		hdr.extended_hdr.parsed_pkt.l3_proto);

	if(hdr.extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4*/ ) {
	  fprintf(dumper_fd, "\t%s:%d\t", intoa(hdr.extended_hdr.parsed_pkt.ipv4_src), hdr.extended_hdr.parsed_pkt.l4_src_port);
	  fprintf(dumper_fd, "\t%s:%d\n", intoa(hdr.extended_hdr.parsed_pkt.ipv4_dst), hdr.extended_hdr.parsed_pkt.l4_dst_port);
	} else if(hdr.extended_hdr.parsed_pkt.eth_type == 0x86DD /* IPv6*/) {
	  fprintf(dumper_fd, "\t%s:%d",    in6toa(hdr.extended_hdr.parsed_pkt.ipv6_src), hdr.extended_hdr.parsed_pkt.l4_src_port);
	  fprintf(dumper_fd, "\t%s:%d\n", in6toa(hdr.extended_hdr.parsed_pkt.ipv6_dst), hdr.extended_hdr.parsed_pkt.l4_dst_port);
	} else
	  fprintf(dumper_fd, "\n");
      }
    }
  }

  if(dumper)
    pcap_dump_close(dumper);
  else if(dumper_fd)
    fclose(dumper_fd);

  pfring_close(pd);

  return(0);
}
