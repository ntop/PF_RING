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

#include "../lib/config.h"

#ifndef __USE_GNU
#define __USE_GNU
#endif

//#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h> /* for CPU_XXXX */

#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>

#ifdef HAVE_LIBNUMA
#include <numa.h>
#endif

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__

typedef u_int64_t ticks;

struct compact_eth_hdr {
  unsigned char   h_dest[ETH_ALEN];
  unsigned char   h_source[ETH_ALEN];
  u_int16_t       h_proto;
};

struct compact_ip_hdr {
  u_int32_t	tot_len:16,
  		tos:8,
		ihl:4,
                version:4;
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
  struct in6_addr	saddr;
  struct in6_addr	daddr;
};

struct compact_udp_hdr {
  u_int16_t	  sport;
  u_int16_t	  dport;
  u_int16_t	  len;
  u_int16_t	  check;
};

/* ******************************** */

void daemonize() {
  pid_t pid, sid;

  pid = fork();
  if (pid < 0) exit(EXIT_FAILURE);
  if (pid > 0) {
#if 0 /* moved out */
    if (pidFile != NULL) {
      FILE *fp = fopen(pidFile, "w");
      fprintf(fp, "%d", pid);
      fclose(fp);
    }
#endif
    exit(EXIT_SUCCESS);
  }

  sid = setsid();
  if (sid < 0) exit(EXIT_FAILURE);

  if ((chdir("/")) < 0) exit(EXIT_FAILURE);

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}

/* ******************************** */

void drop_privileges(char *username) {
  struct passwd *pw = NULL;

  if (getgid() && getuid()) {
    fprintf(stderr, "privileges are not dropped as we're not superuser\n");
    return;
  }

  pw = getpwnam(username);

  if(pw == NULL) {
    username = "nobody";
    pw = getpwnam(username);
  }

  if(pw != NULL) {
    if(setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
      fprintf(stderr, "unable to drop privileges [%s]\n", strerror(errno));
    else
      fprintf(stderr, "user changed to %s\n", username);
  } else {
    fprintf(stderr, "unable to locate user %s\n", username);
  }

  umask(0);
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

int bind2node(int core_id) {
#ifdef HAVE_LIBNUMA
  char node_str[8];

  if (core_id < 0 || numa_available() == -1)
    return -1;

  snprintf(node_str, sizeof(node_str), "%u", numa_node_of_cpu(core_id));
  numa_bind(numa_parse_nodestring(node_str));
#endif

  return 0;
}

/* *************************************** */

/* Bind this thread to a specific core */

int bindthread2core(pthread_t thread_id, u_int core_id) {
#ifdef HAVE_PTHREAD_SETAFFINITY_NP
  cpu_set_t cpuset;
  int s;

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

int bind2core(u_int core_id) {
  return(bindthread2core(pthread_self(), core_id));
}

/* *************************************** */

static __inline__ ticks getticks(void)
{
  u_int32_t a, d;
  // asm("cpuid"); // serialization
  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return (((ticks)a) | (((ticks)d) << 32));
}

/* *************************************** */

#define TRACE_ERROR   0, __FILE__, __LINE__
#define TRACE_WARNING 1, __FILE__, __LINE__
#define TRACE_NORMAL  2, __FILE__, __LINE__

void trace(int trace_level, char *file, int line, char * format, ...) {
  va_list va_ap;
  char buf[2048], out_buf[640];
  char theDate[32], *extra_msg = "";
  time_t theTime = time(NULL);

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
  fprintf(trace_level == 0 ? stderr : stdout, "%s\n", out_buf);

  fflush(stdout);
  va_end(va_ap);
}

/* *************************************** */

