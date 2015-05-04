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
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pfring.h"
#include "pfutils.c"

/* *************************************** */

int main(int argc, char* argv[]) {
  pfring  *pd;
  char *device, *buffer;
  u_int buffer_len, num_runs, test_len, i, test_id, j;
  struct timeval startTime, endTime;
  double deltaUsec, call_per_sec, thpt, call_duration_usec;

  device = "eth0";
  pd = pfring_open(device, 128, PF_RING_PROMISC);

  if(pd == NULL) {
    printf("pfring_open error(%s) [%s]\n", device, strerror(errno));
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pd, "pfsystest");
    pfring_version(pd, &version);

    printf("Using PF_RING v.%d.%d.%d\n",
	   (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8,
	   version & 0x000000FF);
  }

  if(0) {
    test_id = 64;
    buffer_len = test_id*1024;
    buffer = malloc(buffer_len);

    if(buffer == NULL) { /* oops, couldn't allocate memory */
      fprintf(stderr, "Unable to allocate memory requested (%s)\n", strerror(errno));
      return (-1);
    }

    num_runs = 10000;

    for(j=0; j<=test_id; j++) {
      test_len = j*1024;

      gettimeofday(&startTime, NULL);

      for(i=0; i<num_runs; i++)
	pfring_loopback_test(pd, buffer, buffer_len, test_len);

      gettimeofday(&endTime, NULL);
      deltaUsec = delta_time(&endTime, &startTime);
      call_duration_usec = deltaUsec/((double)num_runs);
      call_per_sec = ((double)num_runs*1000000)/deltaUsec;
      thpt = (double)(call_per_sec * test_len * 8) / (double)1000000000;

      printf("%02d [Test len=%d KB][%.2f calls/sec][%.1f usec/call][Thpt: %.2f Gbps][%s]\n",
	     j, test_len/1024, call_per_sec, call_duration_usec, thpt,
	     (thpt > (double)10) ? "10 Gbit Wire rate" : "No Wire rate");
    }

    free(buffer);

    /* ************************************** */

    test_id = 4;
    buffer_len = test_id*1024*1024;
    buffer = malloc(buffer_len);

    if(buffer == NULL) { /* oops, couldn't allocate memory */
      fprintf(stderr, "Unable to allocate memory requested (%s)\n", strerror(errno));
      return (-1);
    }

    num_runs = 1000;

    for(j=1; j<=test_id; j++) {
      test_len = j*1024*1024;

      gettimeofday(&startTime, NULL);

      for(i=0; i<num_runs; i++)
	pfring_loopback_test(pd, buffer, buffer_len, test_len);

      gettimeofday(&endTime, NULL);
      deltaUsec = delta_time(&endTime, &startTime);
      call_duration_usec = deltaUsec/((double)num_runs);
      call_per_sec = ((double)num_runs*1000000)/deltaUsec;
      thpt = (double)(call_per_sec * test_len * 8) / (double)1000000000;

      printf("%02d [Test len=%d KB][%.2f calls/sec][%.1f usec/call][Thpt: %.2f Gbps][%s]\n",
	     j, test_len/1024, call_per_sec, call_duration_usec, thpt,
	     (thpt > (double)10) ? "10 Gbit Wire rate" : "No Wire rate");
    }

    free(buffer);
  }

  /* ******************************************** */

  test_id = 8;
  buffer_len = test_id*1024*1024;
  buffer = malloc(buffer_len);

  if(buffer == NULL) { /* oops, couldn't allocate memory */
    fprintf(stderr, "Unable to allocate memory requested (%s)\n", strerror(errno));
    return (-1);
  }

  num_runs = 1000;

  for(j=0; j<=test_id; j++) {
    test_len = j*1024*1024;

    gettimeofday(&startTime, NULL);

    for(i=0; i<num_runs; i++)
      pfring_loopback_test(pd, buffer, buffer_len, test_len);

    gettimeofday(&endTime, NULL);
    deltaUsec = delta_time(&endTime, &startTime);
    printf("%02d Test len=%d, %.2f calls/sec [%.1f usec/call]\n", j,
	   test_len, ((double)num_runs*1000)/deltaUsec,
	   deltaUsec/num_runs);
  }

  free(buffer);

  pfring_close(pd);

  return(0);
}
