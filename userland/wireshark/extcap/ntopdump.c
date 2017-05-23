/*
 *
 * (C) 2005-16 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 */

#include "pfring.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>

#define NTOPDUMP_INTERFACE "pfring-interface"
#define NTOPDUMP_TIMELINE  "n2disk-timeline"
#define NTOPDUMP_MAX_NBPF_LEN  8192
#define NTOPDUMP_MAX_DATE_LEN  26
#define NTOPDUMP_MAX_NAME_LEN  4096
#define NTOPDUMP_VERSION_MAJOR "0"
#define NTOPDUMP_VERSION_MINOR "1"
#define NTOPDUMP_VERSION_RELEASE "0"

#define EXTCAP_OPT_LIST_INTERFACES	'l'
#define EXTCAP_OPT_VERSION		'v'
#define EXTCAP_OPT_LIST_DLTS		'L'
#define EXTCAP_OPT_INTERFACE		'i'
#define EXTCAP_OPT_CONFIG		'c'
#define EXTCAP_OPT_CAPTURE		'C'
#define EXTCAP_OPT_CAPTURE_FILTER	'f'
#define EXTCAP_OPT_FIFO			'F'
#define EXTCAP_OPT_DEBUG		'D'
#define NTOPDUMP_OPT_HELP		'h'
#define NTOPDUMP_OPT_NAME		'n'
#define NTOPDUMP_OPT_CUSTOM_NAME	'N'
#define NTOPDUMP_OPT_START_TIME		's'
#define NTOPDUMP_OPT_END_TIME		'e'
#define NTOPDUMP_OPT_START_TIME_EPOCH	'S'
#define NTOPDUMP_OPT_END_TIME_EPOCH	'E'

static struct option longopts[] = {
  /* mandatory extcap options */
  { "extcap-interfaces",	no_argument, 		NULL, EXTCAP_OPT_LIST_INTERFACES },
  { "extcap-version", 		optional_argument, 	NULL, EXTCAP_OPT_VERSION },
  { "extcap-dlts", 		no_argument, 		NULL, EXTCAP_OPT_LIST_DLTS },
  { "extcap-interface", 	required_argument, 	NULL, EXTCAP_OPT_INTERFACE },
  { "extcap-config", 		no_argument, 		NULL, EXTCAP_OPT_CONFIG },
  { "capture", 			no_argument, 		NULL, EXTCAP_OPT_CAPTURE },
  { "extcap-capture-filter", 	required_argument,	NULL, EXTCAP_OPT_CAPTURE_FILTER },
  { "fifo", 			required_argument, 	NULL, EXTCAP_OPT_FIFO },
  { "debug", 			optional_argument, 	NULL, EXTCAP_OPT_DEBUG },

  /* custom extcap options */
  { "help", 			no_argument, 		NULL, NTOPDUMP_OPT_HELP },
  { "name", 			required_argument,	NULL, NTOPDUMP_OPT_NAME },
  { "custom-name", 		required_argument, 	NULL, NTOPDUMP_OPT_CUSTOM_NAME },
  { "start", 			required_argument, 	NULL, NTOPDUMP_OPT_START_TIME },
  { "end", 			required_argument, 	NULL, NTOPDUMP_OPT_END_TIME },
  { "start-epoch", 		required_argument, 	NULL, NTOPDUMP_OPT_START_TIME_EPOCH },
  { "end-epoch", 		required_argument, 	NULL, NTOPDUMP_OPT_END_TIME_EPOCH },

  {0, 0, 0, 0}
};

typedef struct _extcap_interface {
  char * interface;
  char * description;

  uint16_t dlt;
  char * dltname;
  char * dltdescription;
} extcap_interface;

static extcap_interface extcap_interfaces[] = {
  { NTOPDUMP_INTERFACE, "PF_RING interface", DLT_EN10MB, NULL, "The EN10MB Ethernet2 DLT" },
  { NTOPDUMP_TIMELINE,  "n2disk timeline" , DLT_EN10MB, NULL, "The EN10MB Ethernet2 DLT" }
};
static size_t extcap_interfaces_num = sizeof(extcap_interfaces) / sizeof(extcap_interface);

static char *extcap_selected_interface   = NULL;
static char *extcap_capture_filter       = NULL;
static char *extcap_capture_fifo         = NULL;
static char *ntopdump_name               = NULL;
static char *ntopdump_start              = NULL;
static char *ntopdump_end                = NULL;
static pfring *pd;

void sigproc(int sig) {
  fprintf(stdout, "Exiting...");
  fflush(stdout);
  if(pd) pfring_breakloop(pd);
}

void extcap_version() {
  /* Print version */
  printf("extcap {version=%s.%s.%s}\n", NTOPDUMP_VERSION_MAJOR, NTOPDUMP_VERSION_MINOR, NTOPDUMP_VERSION_RELEASE);
}

void extcap_list_interfaces() {
  int i;
  
  for(i = 0; i < extcap_interfaces_num; i++) {
    printf("interface {value=%s}{display=%s}\n", extcap_interfaces[i].interface, extcap_interfaces[i].description);    
  }
}

void extcap_dlts() {
  int i;
  
  if(!extcap_selected_interface) return;
  for(i = 0; i < extcap_interfaces_num; i++) {
    extcap_interface *eif = &extcap_interfaces[i];
    if(!strncmp(extcap_selected_interface, eif->interface, strlen(eif->interface))) {
      printf("dlt {number=%u}{name=%s}{display=%s}\n", eif->dlt, eif->interface, eif->dltdescription);
      break;
    }
  }
}

int exec_head(const char *bin, char *line, size_t line_len) {
  FILE *fp;

  fp = popen(bin, "r");

  if (fp == NULL)
    return -1;

  if (fgets(line, line_len-1, fp) == NULL) {
    pclose(fp);
    return -1;
  }

  pclose(fp);
  return 0;
}

float wireshark_version() {
  char line[1035];
  char *version, *rev;
  float v = 0;

  if (exec_head("/usr/bin/wireshark -v", line, sizeof(line)) != 0 &&
      exec_head("/usr/local/bin/wireshark -v", line, sizeof(line)) != 0)
      return 0;

  version = strchr(line, ' ');
  if (version == NULL) return 0;
  version++;
  rev = strchr(version, '.');
  if (rev == NULL) return 0;
  rev++;
  rev = strchr(rev, '.');
  if (rev == NULL) return 0;
  *rev = '\0';

  sscanf(version, "%f", &v);

  return v;
}

void extcap_config() {
  u_int argidx = 0;

  if(!extcap_selected_interface) return;

  if(!strncmp(extcap_selected_interface, NTOPDUMP_INTERFACE, strlen(NTOPDUMP_INTERFACE))) {
    pfring_if_t *dev;
    u_int nameidx;

    nameidx = argidx;
    printf("arg {number=%u}{call=--name}"
	   "{display=Interface Name}{type=radio}"
	   "{tooltip=The interface name}\n", argidx++);
    printf("arg {number=%u}{call=--custom-name}"
	   "{display=Custom Interface Name}{type=string}"
	   "{tooltip=A custom interface name recognized by PF_FING (e.g. zc:99@0)}\n", argidx++);

    dev = pfring_findalldevs();
    while (dev != NULL) {
      printf("value {arg=%u}{value=%s}{display=%s}\n", nameidx, dev->name, dev->name);
      dev = dev->next;
    }

  } else if (!strncmp(extcap_selected_interface, NTOPDUMP_TIMELINE, strlen(NTOPDUMP_TIMELINE))) {
    time_t timer;
    char time_buffer_start[NTOPDUMP_MAX_DATE_LEN], time_buffer_end[NTOPDUMP_MAX_DATE_LEN];
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);
    strftime(time_buffer_end, NTOPDUMP_MAX_DATE_LEN, "%Y-%m-%d %H:%M:%S", tm_info);
    timer -= 5 * 60;
    tm_info = localtime(&timer);
    strftime(time_buffer_start, NTOPDUMP_MAX_DATE_LEN, "%Y-%m-%d %H:%M:%S", tm_info);

    printf("arg {number=%u}{call=--name}"
	   "{display=n2disk timeline path}{type=string}"
	   "{tooltip=The n2disk timeline path (e.g., /storage/n2disk/eth1/timeline)}\n", argidx++);

    if (wireshark_version() > 2.2) {
      printf("arg {number=%u}{call=--start-epoch}"
	     "{display=Start date and time}{type=timestamp}"
	     "{tooltip=The start of the extraction interval}\n", argidx++);
      printf("arg {number=%u}{call=--end-epoch}"
	     "{display=End date and time}{type=timestamp}"
	     "{tooltip=The end of the extraction interval}\n", argidx++);
    } else {
      printf("arg {number=%u}{call=--start}"
	     "{display=Start date and time}{type=string}{default=%s}"
	     "{tooltip=The start of the extraction interval (e.g., %s)}\n", argidx++, time_buffer_start, time_buffer_start);
      printf("arg {number=%u}{call=--end}"
	     "{display=End date and time}{type=string}{default=%s}"
	     "{tooltip=The end of the extraction interval (e.g., %s)}\n", argidx++, time_buffer_end, time_buffer_end);
    }
  }
}

void extcap_capture() {
  pcap_dumper_t *dumper = NULL;
  u_char *buffer_p = NULL;
  struct pfring_pkthdr hdr;
  char *nbpf;
  int rc;

  if ((nbpf = (char*)calloc(NTOPDUMP_MAX_NBPF_LEN + 3 * NTOPDUMP_MAX_DATE_LEN, sizeof(char))) == NULL) {
    fprintf(stderr, "Unable to allocate memory for the nbpf filter");
    return;
  }

  if((dumper = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 16384 /* MTU */), extcap_capture_fifo)) == NULL) {
    fprintf(stderr, "Unable to open the pcap dumper on %s", extcap_capture_fifo);
    return;
  }
  
  if((pd = pfring_open(ntopdump_name, 1520, PF_RING_PROMISC | PF_RING_HW_TIMESTAMP)) == NULL) {
    fprintf(stderr, "Unable to open interface %s", ntopdump_name);
    return;
  }

  if ((signal(SIGINT, sigproc) == SIG_ERR) || (signal(SIGTERM, sigproc) == SIG_ERR) || (signal(SIGQUIT, sigproc) == SIG_ERR)) {
    fprintf(stderr, "Unable to install SIGINT/SIGTERM signal handler");
    return;
  }

  if(extcap_capture_filter && strlen(extcap_capture_filter))
    snprintf(nbpf, NTOPDUMP_MAX_NBPF_LEN - 1, "%s", extcap_capture_filter);

  if(ntopdump_start) {
    sprintf(&nbpf[strlen(nbpf)], "%s start ", strlen(nbpf) ? " and " : "");
    snprintf(&nbpf[strlen(nbpf)], NTOPDUMP_MAX_DATE_LEN - 1, "%s", ntopdump_start);
  }

  if(ntopdump_end) {
    sprintf(&nbpf[strlen(nbpf)], "%s end ", strlen(nbpf) ? " and " : "");
    snprintf(&nbpf[strlen(nbpf)], NTOPDUMP_MAX_DATE_LEN - 1, "%s", ntopdump_end);
  }

  if(strlen(nbpf) && (rc = pfring_set_bpf_filter(pd, nbpf))) {
    fprintf(stderr, "Unable to set nBPF filter %s\nContinuing without nBPF", nbpf);
  }

  /*
  printf("capturing: %s %s %s %s %s %s\n", ntopdump_name,
	 ntopdump_start ? ntopdump_start : "-", ntopdump_end ? ntopdump_end : "-",
	 extcap_capture_filter ? extcap_capture_filter : "-",
	 extcap_capture_fifo ? extcap_capture_fifo : "-", strlen(nbpf) ? nbpf : "-");
  */

  pfring_set_application_name(pd, "wireshark");
  pfring_set_socket_mode(pd, recv_only_mode);

  pfring_enable_ring(pd);
  
  memset(&hdr, 0, sizeof(hdr));
  while(pfring_recv(pd, &buffer_p, 0, &hdr, 1 /* passive wait */) > 0) {
    // fprintf(stdout, "."), fflush(stdout);
    pcap_dump((u_char*)dumper, (struct pcap_pkthdr*)&hdr, buffer_p);
  }

  pcap_dump_close(dumper);
  pfring_close(pd);
  free(nbpf);
  
}

int extcap_print_help() {
  printf("Wireshark extcap plugin by ntop\n");
  printf("Supported interfaces:\n");
  extcap_list_interfaces();
  return 0;
}

int main(int argc, char *argv[]) {
  int option_idx = 0, result;
  time_t epoch;
  char date_str[NTOPDUMP_MAX_DATE_LEN];
  struct tm* tm_info;

  if (argc == 1) {
    extcap_print_help();
    return EXIT_SUCCESS;
  }

  u_int defer_dlts = 0, defer_config = 0, defer_capture = 0;
  while ((result = getopt_long(argc, argv, "h", longopts, &option_idx)) != -1) {
    //fprintf(stderr, "OPT: '--%s' VAL: '%s' \n", longopts[result].name, optarg != NULL ? optarg : "");
    switch (result) {
    /* mandatory extcap options */
    case EXTCAP_OPT_DEBUG:
      break;
    case EXTCAP_OPT_LIST_INTERFACES:
      extcap_version();
      extcap_list_interfaces();
      defer_dlts = defer_config = defer_capture = 0;
      break;
    case EXTCAP_OPT_VERSION:
      extcap_version();
      defer_dlts = defer_config = defer_capture = 0;
      break;
    case EXTCAP_OPT_LIST_DLTS:
      defer_dlts = 1; defer_config = defer_capture = 0;
      break;
    case EXTCAP_OPT_INTERFACE:
      extcap_selected_interface = strndup(optarg, NTOPDUMP_MAX_NAME_LEN);
      break;
    case EXTCAP_OPT_CONFIG:
      defer_config = 1; defer_dlts = defer_capture = 0;
      break;
    case EXTCAP_OPT_CAPTURE:
      defer_capture = 1; defer_dlts = defer_config = 0;
      break;
    case EXTCAP_OPT_CAPTURE_FILTER:
      extcap_capture_filter = strndup(optarg, NTOPDUMP_MAX_NBPF_LEN);
      break;
    case EXTCAP_OPT_FIFO:
      extcap_capture_fifo = strdup(optarg);
      break;

    /* custom ntopdump options */
    case NTOPDUMP_OPT_HELP:
        extcap_print_help();
        return EXIT_SUCCESS;
      break;
    case NTOPDUMP_OPT_NAME:
      if (ntopdump_name == NULL)
        ntopdump_name = strndup(optarg, NTOPDUMP_MAX_NAME_LEN);
      break;
    case NTOPDUMP_OPT_CUSTOM_NAME:
      if (ntopdump_name != NULL) free(ntopdump_name);
      ntopdump_name = strndup(optarg, NTOPDUMP_MAX_NAME_LEN);
      break;
    case NTOPDUMP_OPT_START_TIME:
      if (ntopdump_start == NULL)
        ntopdump_start = strndup(optarg, NTOPDUMP_MAX_DATE_LEN);
      break;
    case NTOPDUMP_OPT_END_TIME:
      if (ntopdump_end == NULL)
        ntopdump_end = strndup(optarg, NTOPDUMP_MAX_DATE_LEN);
      break;
    case NTOPDUMP_OPT_START_TIME_EPOCH:
      if (ntopdump_start != NULL) free(ntopdump_start);
      epoch = atoi(optarg);
      tm_info = localtime(&epoch);
      strftime(date_str, NTOPDUMP_MAX_DATE_LEN, "%Y-%m-%d %H:%M:%S", tm_info);
      ntopdump_start = strndup(date_str, NTOPDUMP_MAX_DATE_LEN);
      break;
    case NTOPDUMP_OPT_END_TIME_EPOCH:
      if (ntopdump_end != NULL) free(ntopdump_end);
      epoch = atoi(optarg);
      tm_info = localtime(&epoch);
      strftime(date_str, NTOPDUMP_MAX_DATE_LEN, "%Y-%m-%d %H:%M:%S", tm_info);
      ntopdump_end = strndup(date_str, NTOPDUMP_MAX_DATE_LEN);
      break;
    }
  }

  if(ntopdump_name && !strcmp(extcap_selected_interface, NTOPDUMP_TIMELINE)) {
    size_t timeline_len = strlen("timeline:") + NTOPDUMP_MAX_NAME_LEN + 1;
    char *timeline = (char*)calloc(timeline_len, sizeof(char));
    sprintf(timeline, "timeline:%s", ntopdump_name);
    free(ntopdump_name);
    ntopdump_name = timeline;
  }
  
  if(defer_dlts) extcap_dlts();
  else if(defer_config) extcap_config();
  else if(defer_capture && ntopdump_name) extcap_capture();

  if(extcap_selected_interface)   free(extcap_selected_interface);
  if(extcap_capture_filter)       free(extcap_capture_filter);
  if(extcap_capture_fifo)         free(extcap_capture_fifo);
  if(ntopdump_name)               free(ntopdump_name);
  if(ntopdump_start)              free(ntopdump_start);
  if(ntopdump_end)                free(ntopdump_end);

  return EXIT_SUCCESS;
}
