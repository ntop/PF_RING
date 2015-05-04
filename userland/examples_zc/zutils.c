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

#include <ctype.h>

/* *************************************** */

#define N2DISK_METADATA             16
#define N2DISK_CONSUMER_QUEUE_LEN 8192
#define N2DISK_PREFETCH_BUFFERS     32

#define MAX_NUM_OPTIONS             64

/* *************************************** */

int bind2node(int core_id) {
  char node_str[8];

  if (core_id < 0 || numa_available() == -1)
    return -1;

  snprintf(node_str, sizeof(node_str), "%u", numa_node_of_cpu(core_id));
  numa_bind(numa_parse_nodestring(node_str));

  return 0;
}

/* *************************************** */

int bind2core(int core_id) {
  cpu_set_t cpuset;
  int s;

  if (core_id < 0)
    return -1;

  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  if((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0) {
    fprintf(stderr, "Error while binding to core %u: errno=%i\n", core_id, s);
    return -1;
  } else {
    return 0;
  }
}

/* *************************************** */

int max_packet_len(char *device) { 
  pfring *ring;
  pfring_card_settings settings;

  ring = pfring_open(device, 1536, PF_RING_PROMISC | PF_RING_ZC_NOT_REPROGRAM_RSS);

  if (ring == NULL)
    return 1536;

  pfring_get_card_settings(ring, &settings);
  
  pfring_close(ring);

  return settings.max_packet_size;
}

/* *************************************** */

int is_a_queue(char *device, int *cluster_id, int *queue_id) {
  char *tmp;
  char c_id[32], q_id[32];
  int i;

  /* Syntax <number>@<number> or zc:<number>@<number> */

  tmp = strstr(device, "zc:");
  if (tmp != NULL) tmp = &tmp[3];
  else tmp = device;

  i = 0;
  if (tmp[0] == '\0' || tmp[0] == '@') return 0;
  while (tmp[0] != '@' && tmp[0] != '\0') {
    if (!isdigit(tmp[0])) return 0;
    c_id[i++] = tmp[0];
    tmp++;
  }
  c_id[i] = '\0';

  i = 0;
  if (tmp[0] == '@') tmp++;
  if (tmp[0] == '\0') return 0;
  while (tmp[0] != '\0') {
    if (!isdigit(tmp[0])) return 0;
    q_id[i++] = tmp[0];
    tmp++;
  }
  q_id[i] = '\0';

  *cluster_id = atoi(c_id);
  *queue_id = atoi(q_id);

  return 1;
}

/* *************************************** */

static inline int64_t upper_power_of_2(int64_t x) {
  x--;
  x |= x >> 1;
  x |= x >> 2;
  x |= x >> 4;
  x |= x >> 8;
  x |= x >> 16;
  x |= x >> 32;
  x++;
  return x;
}

/* *************************************** */

double delta_time (struct timeval * now, struct timeval * before) {
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

void daemonize() {
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

/* *************************************** */

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

/* *************************************** */

void remove_pid_file(char *pidFile) {
  if (pidFile == NULL) return;

  unlink(pidFile);
}

/* *************************************** */

int load_args_from_file(char *conffile, int *ret_argc, char **ret_argv[]) {
  FILE *fd;
  char *tok, cont = 1;
  char line[2048];
  int opt_argc;
  char **opt_argv;
  int i;

  opt_argc = 0;
  opt_argv = (char **) malloc(sizeof(char *) * MAX_NUM_OPTIONS);

  if (opt_argv == NULL)
    return -1;

  memset(opt_argv, 0, sizeof(char *) * MAX_NUM_OPTIONS);

  fd = fopen(conffile, "r");

  if(fd == NULL) 
    return -1;

  opt_argv[opt_argc++] = "";

  while(cont && fgets(line, sizeof(line), fd)) {
    i = 0;
    while(line[i] != '\0') {
      if(line[i] == '=')
        break;
      else if(line[i] == ' ') {
        line[i] = '=';
        break;
      }
      i++;
    }

    tok = strtok(line, "=");

    while(tok != NULL) {
      int len;
      char *argument;

      if(opt_argc >= MAX_NUM_OPTIONS) {
        int i;

        fprintf(stderr, "Too many options (%u)\n", opt_argc);

	for(i=0; i<opt_argc; i++)
	  fprintf(stderr, "[%d][%s]", i, opt_argv[i]);

	cont = 0;
	break;
      }

      len = strlen(tok)-1;
      if(tok[len] == '\n')
        tok[len] = '\0';

      if((tok[0] == '\"') && (tok[strlen(tok)-1] == '\"')) {
	tok[strlen(tok)-1] = '\0';
	argument = &tok[1];
      } else
        argument = tok;

      if(argument[0] != '\0')
	opt_argv[opt_argc++] = strdup(argument);

      tok = strtok(NULL, "\n");
    }
  }

  fclose(fd);


  *ret_argc = opt_argc;
  *ret_argv = opt_argv;
  return 0;
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


