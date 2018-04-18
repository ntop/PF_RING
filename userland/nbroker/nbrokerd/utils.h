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

#include <stdarg.h>
#include <stdio.h>

#include "rrc.h"

#define MAX_NUM_OPTIONS    64

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__
#define TRACE_DEBUG     4, __FILE__, __LINE__
#define TRACE_LEVEL_MAX 4

void daemonize();
int file2argv(char *name, char *path, int *argc_out, char ***argv_out);
double delta_msec(struct timeval *now, struct timeval * before);
char *utils_intoaV4(const unsigned int addr, char *buf, u_int bufLen);
char *utils_intoaV6(const rrc_in6_addr_t *ipv6, char *buf, u_short bufLen);
char *utils_mactoa(const u_int8_t *mac, char *buf, u_short bufLen);
char *utils_hosttoa(const rrc_ip_addr_t *host, u_short version, char *buf, u_short bufLen);
void setTraceLevel(u_int8_t l);
void setTraceFile(FILE *f);
void traceEvent(int trace_level, char* file, int line, char * format, ...);

