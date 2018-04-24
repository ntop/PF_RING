/*
 *  Copyright (C) 2017-2018 ntop.org
 *
 *      http://www.ntop.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "utils.h"

static u_int8_t trace_level = 2;
static u_int8_t use_syslog = 0;
static FILE *trace_out_stream = NULL;

/* ****************************************************** */

void daemonize() {
  pid_t pid, sid;

  pid = fork();
  if (pid < 0) exit(EXIT_FAILURE);
  if (pid > 0) exit(EXIT_SUCCESS); /* Father will leave */

  /* Child */
  sid = setsid();
  if (sid < 0) exit(EXIT_FAILURE);

  if ((chdir("/")) < 0) exit(EXIT_FAILURE);

  close(STDIN_FILENO), close(STDOUT_FILENO), close(STDERR_FILENO);
}

/* ****************************************************** */

int file2argv(char *name, char *path, int *argc_out, char ***argv_out) {
  FILE *fd;
  int opt_argc;
  char **opt_argv;
  char *tok, cont=1;
  char line[2048];
  int i;

  opt_argc = 0;
  opt_argv = (char **) malloc(sizeof(char *) * MAX_NUM_OPTIONS);

  if (opt_argv == NULL)
    return -1;

  memset(opt_argv, 0, sizeof(char *) * MAX_NUM_OPTIONS);

  fd = fopen(path, "r");

  if (fd == NULL) {
    traceEvent(TRACE_ERROR, __FILE__, __LINE__, "Unable to read config file %s", path);
    exit(-1);
  }

  opt_argv[opt_argc++] = strdup(name);

  while (cont && fgets(line, sizeof(line), fd)) {
    /* Accepted syntax:
     * <option>=<value>
     * <option> <value>
     */

    i = strlen(line);
    if (i-- > 0) while (i > 0 && (line[i] == '\n' || line[i] == ' ')) {
      line[i] = '\0';
      i--;
    }

    i = 0;
    while (line[i] != '\0') {
      if (line[i] == '=')
        break;
      else if (line[i] == ' ') {
        line[i] = '=';
        break;
      }

      i++;
    }

    tok = strtok(line, "=");

    while (tok != NULL) {
      char *argument;

      if (opt_argc >= MAX_NUM_OPTIONS) {
	int i;

	traceEvent(TRACE_ERROR, __FILE__, __LINE__, "Too many options (%u)", opt_argc);

	for (i=0; i<opt_argc; i++)
	  traceEvent(TRACE_ERROR, __FILE__, __LINE__, "[%d][%s]", i, opt_argv[i]);

	cont = 0;
	break;
      }

      if ((tok[0] == '\"') && (tok[strlen(tok)-1] == '\"')) {
	tok[strlen(tok)-1] = '\0';
	argument = &tok[1];
      } else
        argument = tok;

      if (argument[0] != '\0')
	opt_argv[opt_argc++] = strdup(argument);

      tok = strtok(NULL, "\n");
    }
  }

  fclose(fd);

  *argc_out = opt_argc;
  *argv_out = opt_argv;

  return 0;
}

/* ****************************************************** */

double delta_msec(struct timeval *now, struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }

  return ((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

/* ****************************************************** */

char* utils_intoaV4(const unsigned int a, char *buf, u_int bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;
  unsigned int addr = a;

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

  return retStr;
}

/* ****************************************************** */

char* utils_intoaV6(const rrc_in6_addr_t *ipv6, char* buf, u_short bufLen) {
  int i, len = 0;
  
  buf[0] = '\0';

  for(i = 0; i<16; i++) {
    char tmp[8];
    
    snprintf(tmp, sizeof(tmp), "%02X", ipv6->u6_addr8[i] & 0xFF);
    len += snprintf(&buf[len], bufLen-len, "%s%s", (i > 0) ? ":" : "", tmp);
  }

  return(buf);
}

/* ****************************************************** */

char *utils_mactoa(const u_int8_t *mac, char *buf, u_short bufLen) {
  snprintf(buf, bufLen, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return buf;
}

/* ****************************************************** */

char *utils_hosttoa(const rrc_ip_addr_t *host, u_short version, char *buf, u_short bufLen) {
  if (version == 4)
    return utils_intoaV4(ntohl(host->v4), buf, bufLen);
  else
    return utils_intoaV6(&host->v6, buf, bufLen);
}

/* ****************************************************** */

void setTraceLevel(u_int8_t l) {
  if(l > TRACE_LEVEL_MAX) l = TRACE_LEVEL_MAX;

  trace_level = l;
}

/* ****************************************************** */

void setTraceFile(FILE *f) {
  trace_out_stream = f;
}

/* ****************************************************** */

void traceEvent(int level, char* file, int line, char * format, ...) {
  va_list va_ap;

  if (level <= trace_level) {
    char buf[2048], out_buf[640];
    char theDate[32], *extra_msg = "";
    time_t theTime = time(NULL);
    FILE *out_file = (trace_out_stream ? trace_out_stream : stdout);

    va_start(va_ap, format);

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    if (level == 0 /* TRACE_ERROR */)
      extra_msg = "ERROR: ";
    else if (level == 1 /* TRACE_WARNING */)
      extra_msg = "WARNING: ";

    while (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

    snprintf(out_buf, sizeof(out_buf), "%s [%s:%d] %s%s", theDate,
	     file, line, extra_msg, buf);

    if (use_syslog) syslog(LOG_INFO, "%s", out_buf);

    fprintf(out_file, "%s\n", out_buf);
    fflush(out_file);

    va_end(va_ap);
  }
}

/* ****************************************************** */

