/*
 * (C) 2018-23 - ntop
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
#include "pfring_ft.h"

#include "ftutils.c"

// #define TEST_CALLBACK_NEW_FLOW
// #define TEST_CALLBACK_L7_DETECTED
// #define TEST_CALLBACK_FLOW_PACKET

#define ALARM_SLEEP 1
#define DEFAULT_DEVICE "eth0"

#ifdef HAVE_NDPI
#define PRINT_NDPI_INFO /* Note: this requires linking the nDPI library */
#include "ndpi_api.h"
#endif

pfring *pd = NULL;
pfring_ft_table *ft = NULL;
int bind_core = -1;
int bind_time_pulse_core = -1;
u_int8_t quiet = 0, verbose = 0, stats_only = 0, log_time = 1;
u_int8_t time_pulse = 0, enable_l7 = 0, do_shutdown = 0;
u_int64_t num_pkts = 0, num_bytes = 0, num_flows = 0;
#ifdef PRINT_NDPI_INFO
u_int8_t enable_l7_extra = 0;
#endif

volatile u_int64_t *pulse_timestamp;

/* ************************************ */

void *time_pulse_thread(void *data) {
  struct timespec tn;

  if (bind_time_pulse_core >= 0)
    bind2core(bind_time_pulse_core);

  while (likely(!do_shutdown)) {
    clock_gettime(CLOCK_REALTIME, &tn);
    *pulse_timestamp = ((u_int64_t) ((u_int64_t) tn.tv_sec << 32) | (tn.tv_nsec/1000));
    usleep(1);
  }

  return NULL;
}

/* ************************************ */

void print_stats() {
  pfring_stat stat;
  pfring_ft_stats *fstat;
  static struct timeval start_time = { 0 };
  static struct timeval last_time = { 0 };
  struct timeval end_time;
  unsigned long long n_bytes, n_pkts;
  static u_int64_t last_pkts = 0;
  static u_int64_t last_bytes = 0;
  double diff, bytes_diff;
  u_int64_t delta_start;
  double delta_last;
  char buf[256], buf1[64], buf2[64], timebuf[128];

  if (start_time.tv_sec == 0)
    gettimeofday(&start_time, NULL);
  gettimeofday(&end_time, NULL);

  n_bytes = num_bytes;
  n_pkts = num_pkts;

  if (pfring_stats(pd, &stat) >= 0 && (fstat = pfring_ft_get_stats(ft))) {
    if (last_time.tv_sec > 0) {
      delta_start = delta_time(&end_time, &start_time);
      delta_last = delta_time(&end_time, &last_time);
      diff = n_pkts - last_pkts;
      bytes_diff = n_bytes - last_bytes;
      bytes_diff /= (1000*1000*1000)/8;

      snprintf(buf, sizeof(buf),
             "Duration:   %s\n"
             "ActFlows:   %ju\n"
             "TotFlows:   %ju\n"
             "Errors:     %ju\n"
             "Packets:    %lu\n"
             "Dropped:    %lu\n"
             "Bytes:      %lu\n"
             "Throughput: %s pps (%s Gbps)",
             msec2dhmsm(delta_start, timebuf, sizeof(timebuf)),
             fstat->active_flows,
             fstat->flows,
             fstat->err_no_room + fstat->err_no_mem,
             (long unsigned int) n_pkts,
             (long unsigned int) stat.drop,
             (long unsigned int) n_bytes,
	     pfring_format_numbers(((double) diff/(double)(delta_last/1000)),  buf1, sizeof(buf1), 1),
	     pfring_format_numbers(((double) bytes_diff/(double)(delta_last/1000)),  buf2, sizeof(buf2), 1));

      pfring_set_application_stats(pd, buf);

      if (stats_only)
        fprintf(stderr, "%s\n---\n", buf);
    }
  }

  last_pkts = n_pkts;
  last_bytes = n_bytes;
  memcpy(&last_time, &end_time, sizeof(last_time));
}

/* ************************************ */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stderr, "Leaving...\n");
  if (called) return; else called = 1;

  do_shutdown = 1;

  pfring_breakloop(pd);
}

/* ************************************ */

void my_sigalarm(int sig) {
  if (do_shutdown)
    return;

  print_stats();
  alarm(ALARM_SLEEP);
  signal(SIGALRM, my_sigalarm);
}

/* ******************************** */

#ifdef TEST_CALLBACK_FLOW_PACKET
/* This callback is called after a packet has been processed */
void processFlowPacket(const u_char *data, pfring_ft_packet_metadata *metadata,
		       pfring_ft_flow *flow, void *user) {
  // fprintf(stderr, "Processing packet [payloadLen: %u]\n", metadata->payload_len);

  // Marking the flow to discard all packets (this can be used to implement custom filtering policies)
  // pfring_ft_flow_set_action(flow, PFRING_FT_ACTION_DISCARD);
}
#endif

/* ****************************************************** */

const char *action_to_string(pfring_ft_action action) {
  switch (action) {
    case PFRING_FT_ACTION_FORWARD: return "forward";
    case PFRING_FT_ACTION_DISCARD: return "discard";
    case PFRING_FT_ACTION_DEFAULT: return "default";
    case PFRING_FT_ACTION_USER_1:  return "user_1";
    case PFRING_FT_ACTION_USER_2:  return "user_2";
    case PFRING_FT_ACTION_SLICE:   return "slice";
  }
  return "";
}

/* ******************************** */

const char *status_to_string(pfring_ft_flow_status status) {
  switch (status) {
    case PFRING_FT_FLOW_STATUS_ACTIVE:         return "active";
    case PFRING_FT_FLOW_STATUS_IDLE_TIMEOUT:   return "idle-timeout";
    case PFRING_FT_FLOW_STATUS_ACTIVE_TIMEOUT: return "active-timeout";
    case PFRING_FT_FLOW_STATUS_END_DETECTED:   return "end-of-flow";
    case PFRING_FT_FLOW_STATUS_FORCED_END:     return "forced-end";
    case PFRING_FT_FLOW_STATUS_SLICE_TIMEOUT:  return "slice-timeout";
    case PFRING_FT_FLOW_STATUS_OVERFLOW:       return "table-overflow";
  }
  return "";
}

/* ******************************** */

void print_time() {
  time_t now = time(NULL);
  struct tm* tm_info = localtime(&now);
  char time_buff[26];
  strftime(time_buff, sizeof(time_buff), "%H:%M:%S", tm_info);
  printf("%s ", time_buff);
}

/* ******************************** */

/* This callback is called when a flow expires */
void processFlow(pfring_ft_flow *flow, void *user){
  pfring_ft_flow_key *k;
  pfring_ft_flow_value *v;
  char buf1[64], buf2[64], buf3[32], buf4[32], buf5[32];
  char *ip1, *ip2;

  k = pfring_ft_flow_get_key(flow);
  v = pfring_ft_flow_get_value(flow);

  if (k->ip_version == 4){
    ip1 = _intoa(k->saddr.v4, buf1, sizeof(buf1));
    ip2 = _intoa(k->daddr.v4, buf2, sizeof(buf2));
  } else {
    ip1 = (char *) inet_ntop(AF_INET6, &k->saddr.v6, buf1, sizeof(buf1));
    ip2 = (char *) inet_ntop(AF_INET6, &k->daddr.v6, buf2, sizeof(buf2));
  }

  if (log_time)
    print_time();

  printf("[Flow] ");

  if(enable_l7)
    printf("l7: %s, category: %u, ",
	   pfring_ft_l7_protocol_name(ft, &v->l7_protocol, buf3, sizeof(buf3)), v->l7_protocol.category);

  printf("srcMac: %s, dstMac: %s, vlanId: %u, srcIp: %s, dstIp: %s, srcPort: %u, dstPort: %u, protocol: %u, tcpFlags: 0x%02X, "
         "c2s: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }, "
         "s2c: { Packets: %ju, Bytes: %ju, First: %u.%u, Last: %u.%u }, "
         "status: %s, action: %s",
         etheraddr2string(k->smac, buf4), etheraddr2string(k->dmac, buf5), k->vlan_id,
         ip1, ip2, k->sport, k->dport, k->protocol, v->direction[s2d_direction].tcp_flags | v->direction[d2s_direction].tcp_flags,
         v->direction[s2d_direction].pkts, v->direction[s2d_direction].bytes,
         (u_int) v->direction[s2d_direction].first.tv_sec, (u_int) v->direction[s2d_direction].first.tv_usec,
         (u_int) v->direction[s2d_direction].last.tv_sec,  (u_int) v->direction[s2d_direction].last.tv_usec,
         v->direction[d2s_direction].pkts, v->direction[d2s_direction].bytes,
         (u_int) v->direction[d2s_direction].first.tv_sec, (u_int) v->direction[d2s_direction].first.tv_usec,
         (u_int) v->direction[d2s_direction].last.tv_sec,  (u_int) v->direction[d2s_direction].last.tv_usec,
         status_to_string(v->status),
         action_to_string(pfring_ft_flow_get_action(flow)));

  switch(v->l7_protocol.master_protocol) {
    case 5:
      if (v->l7_metadata.dns.query != NULL)
        printf(", query: %s", v->l7_metadata.dns.query);
      printf(", queryType: %u, replyCode: %u",
        v->l7_metadata.dns.queryType,
        v->l7_metadata.dns.replyCode);
      break;

    case 7:
      if (v->l7_metadata.http.serverName != NULL)
        printf(", hostName: %s", v->l7_metadata.http.serverName);
      if (v->l7_metadata.http.url != NULL)
        printf(", url: %s", v->l7_metadata.http.url);
      if (v->l7_metadata.http.responseCode)
        printf(", responseCode: %u", v->l7_metadata.http.responseCode);
      break;

    case 91:
      if (v->l7_metadata.tls.serverName != NULL)
        printf(", hostName: %s", v->l7_metadata.tls.serverName);
#ifdef PRINT_NDPI_INFO
      if (enable_l7_extra) {
        struct ndpi_flow_struct *ndpi_flow = pfring_ft_flow_get_ndpi_handle(flow);
        if (ndpi_flow->protos.tls_quic.ja3_server[0])
          printf(", ja3s: '%s'", ndpi_flow->protos.tls_quic.ja3_server);
        if (ndpi_flow->protos.tls_quic.ja3_client[0])
          printf(", ja3c: '%s'", ndpi_flow->protos.tls_quic.ja3_client);
      }
#endif
      break;
  }

  printf("\n");

  num_flows++;

  pfring_ft_flow_free(flow);
}

/* ******************************** */

#ifdef TEST_CALLBACK_NEW_FLOW
/* This callback is called when a new flow is created */
void processNewFlow(pfring_ft_flow *flow, void *user){

  if (log_time)
    print_time();

  printf("[New Flow]\n");
}
#endif

/* ******************************** */

#ifdef TEST_CALLBACK_L7_DETECTED
void l7Detected(const u_char *data, pfring_ft_packet_metadata *metadata, pfring_ft_flow *flow, void *user) {
  pfring_ft_flow_value *v;
  char buf[32];

  if (enable_l7) {
    v = pfring_ft_flow_get_value(flow);

    if (log_time)
      print_time();

    printf("[Detected] l7: %s, category: %u, tunnelType: %u\n",
	   pfring_ft_l7_protocol_name(ft, &v->l7_protocol, buf, sizeof(buf)), v->l7_protocol.category, v->tunnel_type);
  }
}
#endif

/* ******************************** */

void process_packet(const struct pfring_pkthdr *h, const u_char *p, const u_char *user_bytes) {
  pfring_ft_pcap_pkthdr *hdr = (pfring_ft_pcap_pkthdr *) h;
  pfring_ft_ext_pkthdr ext_hdr = { 0 };
  u_int64_t ts;
  pfring_ft_action action;

  ext_hdr.hash = h->extended_hdr.pkt_hash;

  if (time_pulse) {
    ts = *pulse_timestamp;
    hdr->ts.tv_sec = ts >> 32;
    hdr->ts.tv_usec = (ts << 32) >> 32;
  }

  action = pfring_ft_process(ft, p, hdr, &ext_hdr);

  num_pkts++;
  num_bytes += h->len + 24;

  if (verbose) {
    char buffer[256];
    buffer[0] = '\0';
    pfring_print_pkt(buffer, sizeof(buffer), p, h->len, h->caplen);
    if (log_time)
      print_time();
    printf("[Packet]%s %s", action == PFRING_FT_ACTION_DISCARD ? " [discard]" : "", buffer);
  }
}

/* ******************************** */

void packet_consumer() {
  struct pfring_pkthdr hdr;
  u_char *buffer_p = NULL;

  memset(&hdr, 0, sizeof(hdr));

  while (!do_shutdown) {
    if (pfring_recv(pd, &buffer_p, 0, &hdr, 0) > 0) {
      process_packet(&hdr, buffer_p, NULL);
    } else {
      if (!pfring_ft_housekeeping(ft, time(NULL))) {
        usleep(1);
      }
    }
  }
}

/* *************************************** */

void print_version(void) {
  char version[32], system_id[64];
  time_t license_expiration, maintenance_expiration;
  int rc;
  
  pfring_ft_version(version);
 
  printf("PF_RING FT v.%s\n" 
         "Copyright 2018-24 ntop\n",
         version);
      
  rc = pfring_ft_license(system_id, &license_expiration, &maintenance_expiration);

  printf("SystemID:      %s\n", system_id);
              
  if (!rc) {
    printf("License:       Invalid license\n");
    if (license_expiration)
      printf("Demo Duration: Until %s\n", ctime_nonl(license_expiration));
  } else {
    printf("License:       Valid license\n");  

    if (license_expiration) {
      printf("License Type:  Time-limited License \n");
      printf("Lic. Duration: Until %s [%u days left]\n", ctime_nonl(license_expiration), days_left(license_expiration));
    } else {
      printf("License Type:  Permanent License\n");
      if (maintenance_expiration == 0 || days_left(maintenance_expiration) <= 0)
        printf("Maintenance:   Expired\n");
      else
        printf("Maintenance:   Until %s [%u days left]\n", ctime_nonl(maintenance_expiration), days_left(maintenance_expiration));
    }
  } 
}

/* *************************************** */

void print_help(void) {
  printf("ftflow - (C) 2018-24 ntop\n");
  printf("Flow processing based on PF_RING FT (Flow Table)\n\n");
  printf("-h              Print this help\n");
  printf("-i <device>     Device name\n");
  printf("-7              Enable L7 protocol detection (nDPI)\n");
  printf("-f <bpf>        Capture filter (BPF)\n");
  printf("-F <file>       Load filtering/shunting rules from file\n");
  printf("-p <file>       Load nDPI custom protocols from file\n");
  printf("-c <file>       Load nDPI categories by host from file\n");
  printf("-g <core>       CPU core affinity\n");
  printf("-S <core>       Enable timer thread and set CPU core affinity\n");
  printf("-s <duration>   Enable flow slicing (set timeout to <duration> seconds\n");
  printf("-H              Ignore hw hash (use with adapters computing asymmetric hash)\n");
#ifdef PRINT_NDPI_INFO
  printf("-E              Enable extra packet dissection in nDPI to extract more metadata\n");
#endif
  printf("-q              Quiet mode\n");
  printf("-d              Debug mode\n");
  printf("-t              Print actual stats\n");
  printf("-v              Verbose (print also raw packets)\n");
  printf("-V              Print version");

  printf("\nFor nDPI categories see for instance\n"
	 "https://github.com/ntop/nDPI/blob/dev/example/mining_hosts.txt\n");
}

/* *************************************** */

int main(int argc, char* argv[]) {
  char *device = NULL, c;
  char *configuration_file = NULL;
  char *categories_file = NULL;
  char *protocols_file = NULL;
  int promisc, snaplen = 1518, rc;
  u_int32_t flags = 0, ft_flags = 0, slice_duration = 0;
  packet_direction direction = rx_and_tx_direction;
  pthread_t time_thread;
  u_int8_t ignore_hw_hash = 0;
  char *filter = NULL;

  while ((c = getopt(argc,argv,"c:dEf:g:hHi:p:qvF:s:S:tV7")) != '?') {
    if ((c == 255) || (c == -1)) break;

    switch(c) {
    case 'c':
      enable_l7 = 1;
      categories_file = strdup(optarg);
      break;
    case 'd':
      pfring_ft_debug();
      break;
#ifdef PRINT_NDPI_INFO
    case 'E':
      enable_l7 = 1;
      enable_l7_extra = 1;
      break;
#endif
    case 'f':
      filter = strdup(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    case 'h':
      print_help();
      exit(0);
      break;
    case 'i':
      device = strdup(optarg);
      break;
    case 'p':
      enable_l7 = 1;
      protocols_file = strdup(optarg);
      break;
    case 'q':
      quiet = 1;
      break;
    case 's':
      slice_duration = atoi(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    case '7':
      enable_l7 = 1;
      break;
    case 'F':
      enable_l7 = 1;
      configuration_file = strdup(optarg);
      break;
    case 'H':
      ignore_hw_hash = 1;
      break;
    case 'S':
      time_pulse = 1;
      bind_time_pulse_core = atoi(optarg);
      break;
    case 'V':
      print_version();
      exit(0);
      break;
    case 't':
      stats_only = 1;
      break;
    }
  }

  if (device == NULL) device = DEFAULT_DEVICE;
  bind2node(bind_core);

  if (enable_l7)
    ft_flags |= PFRING_FT_TABLE_FLAGS_DPI;

#ifdef PRINT_NDPI_INFO
  if (enable_l7_extra)
    ft_flags |= PFRING_FT_TABLE_FLAGS_DPI_EXTRA;
#endif

  if (ignore_hw_hash)
    ft_flags |= PFRING_FT_IGNORE_HW_HASH;

  ft = pfring_ft_create_table(ft_flags, 4000000, 0, 0, 0);

  if (ft == NULL) {
    fprintf(stderr, "pfring_ft_create_table error\n");
    return -1;
  }

  if (slice_duration > 0)
    pfring_ft_flow_set_flow_slicing(ft, slice_duration);

  /* Example of L7 packet filtering rules
  pfring_ft_set_filter_protocol_by_name(ft, "MDNS", PFRING_FT_ACTION_DISCARD);
  pfring_ft_set_filter_protocol_by_name(ft, "UPnP", PFRING_FT_ACTION_DISCARD);
  */

  /* Example of 'drop all' L7 protocols except Skype
  pfring_ft_set_default_action(ft, PFRING_FT_ACTION_DISCARD);
  pfring_ft_set_filter_protocol_by_name(ft, "Skype", PFRING_FT_ACTION_FORWARD);
  */

  /* Example of callback for expired flows */
  if (!stats_only)
    pfring_ft_set_flow_export_callback(ft, processFlow, NULL);

#ifdef TEST_CALLBACK_NEW_FLOW
  /* Example of callback for new flows */
  pfring_ft_set_new_flow_callback(ft, processNewFlow, NULL);
#endif

#ifdef TEST_CALLBACK_L7_DETECTED
  /* Example of callback for L7 detected */
  pfring_ft_set_l7_detected_callback(ft, l7Detected, NULL);
#endif

#ifdef TEST_CALLBACK_FLOW_PACKET
  /* Example of callback for packets that have been successfully processed */
  pfring_ft_set_flow_packet_callback(ft, processFlowPacket, NULL);
#endif

  if (protocols_file) {
    rc = pfring_ft_load_ndpi_protocols(ft, protocols_file);

    if (rc < 0) {
      fprintf(stderr, "Failure loading custom protocols from %s\n", protocols_file);
      return -1;
    }
  }

  if (categories_file) {
    rc = pfring_ft_load_ndpi_categories(ft, categories_file);

    if (rc < 0) {
      fprintf(stderr, "Failure loading categories from %s\n", categories_file);
      return -1;
    }
  }

  if (configuration_file) {
    /* Loading L7 filtering/shunting from configuration file */
    rc = pfring_ft_load_configuration(ft, configuration_file);

    if (rc < 0) {
      fprintf(stderr, "Failure loading rules from %s\n", configuration_file);
      return -1;
    }
  }

  promisc = 1;

  if (promisc)     flags |= PF_RING_PROMISC;
  if (!time_pulse) flags |= PF_RING_TIMESTAMP; /* needed for flow processing */

  pd = pfring_open(device, snaplen, flags);

  if (pd == NULL) {
    fprintf(stderr, "pfring_open error [%s] (pf_ring not loaded or interface %s is down ?)\n",
      strerror(errno), device);
    return -1;
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "ftflow");
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

  if (filter != NULL) {
    rc = pfring_set_bpf_filter(pd, filter);
    if (rc != 0)
      fprintf(stderr, "pfring_set_bpf_filter(%s) returned %d\n", filter, rc);
    else if (!quiet)
      printf("Successfully set BPF filter '%s'\n", filter);
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);

  signal(SIGALRM, my_sigalarm);
  alarm(ALARM_SLEEP);

  if (time_pulse) {
    pulse_timestamp = calloc(CACHE_LINE_LEN/sizeof(u_int64_t), sizeof(u_int64_t));
    pthread_create(&time_thread, NULL, time_pulse_thread, NULL);
    while (!*pulse_timestamp && !do_shutdown); /* wait for ts */
  }

  if (!quiet) {
    if (enable_l7)
      printf("Capturing from %s with nDPI support enabled\n", device);
    else
      printf("Capturing from %s without nDPI support (see -7)\n", device);
  }

  if (pfring_enable_ring(pd) != 0) {
    printf("Unable to enable ring :-(\n");
    pfring_close(pd);
    return -1;
  }

  if (bind_core >= 0)
    bind2core(bind_core);

  packet_consumer();

  sleep(1);

  if (time_pulse)
    pthread_join(time_thread, NULL);

  pfring_close(pd);

  pfring_ft_flush(ft);

  if (!stats_only)
    fprintf(stderr, "%lu exported flows\n", num_flows);

  pfring_ft_destroy_table(ft);

  if (categories_file)    { free(categories_file);    categories_file = NULL;    }
  if (configuration_file) { free(configuration_file); configuration_file = NULL; }
  if (device)             { free(device);             device = NULL;             }
  if (protocols_file)     { free(protocols_file);     protocols_file = NULL;     }

  return 0;
}
