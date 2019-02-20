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

#include <ctype.h>
#include <sys/types.h>
#include <pwd.h>

#include "../examples/pfutils.c"

/* *************************************** */

#define N2DISK_METADATA             16
#define N2DISK_CONSUMER_QUEUE_LEN 8192
#define N2DISK_PREFETCH_BUFFERS     32

#define MAX_NUM_OPTIONS             64

#define DEFAULT_CLUSTER_ID          99

/* *************************************** */

int max_packet_len(char *device) { 
  pfring *ring;
  pfring_card_settings settings;
  int mtu;

  ring = pfring_open(device, 1536, PF_RING_ZC_NOT_REPROGRAM_RSS);

  if (ring == NULL)
    return 1536;

  pfring_get_card_settings(ring, &settings);

  mtu = pfring_get_mtu_size(ring);

  if (settings.max_packet_size < mtu + 14 /* eth */)
    settings.max_packet_size = mtu + 14 /* eth */ + 4 /* vlan */;
  
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

char *intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    u_int byte = addr & 0xff;

    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
  *--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ****************************************************** */

char *intoaV6(const void *ipv6, char* buf, u_short bufLen) {
  char *ret;

  ret = (char*)inet_ntop(AF_INET6, ipv6, buf, bufLen);

  if(ret == NULL) {
    /* Internal error (buffer too short) */
    buf[0] = '\0';
    return(buf);
  } else
    return(ret);
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

