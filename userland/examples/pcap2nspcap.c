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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <pcap/pcap.h>

#define PCAP_MAGIC          0xa1b2c3d4
#define PCAP_NSEC_MAGIC     0xa1b23c4d

struct pcap_disk_timeval {
  u_int32_t tv_sec;/* seconds */
  u_int32_t tv_usec;/* microseconds */
};

struct pcap_disk_pkthdr {
  struct pcap_disk_timeval ts;/* time stamp */
  u_int32_t caplen;/* length of portion present */
  u_int32_t len;/* length this packet (off wire) */
};

FILE *out_fd = NULL;
char *out_pipe_filename = NULL;
int  out_fd_id, verbose = 0, nsec_ts = 0;
int snaplen = 1514;
char *in_device = NULL;
pcap_t *pd = NULL;

int run();
void write_pcap_header();
void processsPacket(u_char *notUsed,
		    const struct pcap_pkthdr *header,
		    const u_char *packet);

/* ************************************* */

void cleanup(int signal) {
  if(verbose) printf("Cleaning up resource\n");

  if(out_pipe_filename) unlink(out_pipe_filename);
  if(pd)                pcap_close(pd);

  if(signal == SIGPIPE)
    run();
  else {
    if(verbose) printf("Exiting...\n");
    exit(0);
  }
}

/* ************************************* */

int run() {
  char errbuf[PCAP_ERRBUF_SIZE];
  int rc, promisc = 1;

  if((rc = unlink(out_pipe_filename)) != 0) { /* Just to be safe */
    if(verbose) printf("Unlink failed: %d\n", rc);
  } else
    if(verbose) printf("Deleted named pipe %s\n", out_pipe_filename);

  if(verbose) printf("Creating named pipe %s...\n", out_pipe_filename);

  /* read/write permissions for owner, and with read permissions for group and others. */
  if(mkfifo(out_pipe_filename, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH) != 0) {
    printf("ERROR: Unable to create named pipe %s: file already existing ?\n",
	   out_pipe_filename);
    exit(-1);
  }

  if(verbose) printf("Waiting for process to attach to named pipe %s...\n",
		     out_pipe_filename);
  if((out_fd = fopen(out_pipe_filename, "w")) == NULL) {
    printf("ERROR: Unable to write into file %s\n", out_pipe_filename);
    cleanup(-1);
  } else
    out_fd_id = fileno(out_fd);

  pd = pcap_open_live(in_device, snaplen, promisc, 500, errbuf);
  if(pd == NULL) pd = pcap_open_offline(in_device, errbuf);

  if(pd == NULL) {
    printf("ERROR: unable to open pcap device/file %s: %s\n",
	   in_device, errbuf);
    return(-1);
  }

  write_pcap_header();
  pcap_loop(pd, -1, processsPacket, NULL);

  cleanup(-1);

  return(0);
}

/* ************************************* */

static void help() {
  printf("pcap2nspcap [-v] [-n] -i <device> -o <named pipe>\n");
  printf("Usage:\n");
  printf("-v                  | Verbose\n");
  printf("-n                  | Use nsec timestamps\n");
  printf("-i <device>         | Device name from which packets are captured\n");
  printf("-o <named pipe>     | Output named pipe\n");

  printf("\n");
  printf("Example:\n");
  printf("\t# ./pcap2nspcap -i eth0 -o /tmp/mypipe\n");
  printf("\t# tcpdump -n -r /tmp/mypipe\n");

  exit(0);
}

/* ************************************* */

/*
 * put data onto the end of global ring buffer "buf"
 */
void append(char *ptr, int len) {
  int writesize = len;

  while(writesize > 0) {
    int rc = write(out_fd_id, &ptr[len-writesize], writesize);

    if(rc < 0) {
      printf("ERROR: Fatal write error: %s\n", strerror(errno));
      cleanup(SIGPIPE);
    } else
      writesize -= rc;
  }
}

/* ************************************* */

void write_pcap_header() {
  struct pcap_file_header fh;

  /* Add dummy header */
  if(nsec_ts)
    fh.magic = PCAP_NSEC_MAGIC; /* nsec */
  else
    fh.magic = PCAP_MAGIC;      /* usec */

  fh.version_major = 2;
  fh.version_minor = 4;
  fh.thiszone = 0;
  fh.sigfigs = 0;
  fh.snaplen = snaplen;
  fh.linktype = 1;

  append((char *)&fh, sizeof(fh));
}

/* ************************************* */

void processsPacket(u_char *notUsed,
		    const struct pcap_pkthdr *header,
		    const u_char *packet) {
  if(nsec_ts) {
    struct pcap_disk_pkthdr  hdr;
    struct ns_pcaphdr *myhdr = (struct ns_pcaphdr*)header;

    memcpy(&hdr, header, sizeof(hdr));
    hdr.ts.tv_usec = myhdr->ns;

    append((char *)header, sizeof(struct pcap_disk_pkthdr));
  } else
    append((char *)header, sizeof(struct pcap_disk_pkthdr));

  append((char *)packet, header->caplen);
}

 /* ***************************************** */

int main(int argc, char* argv[]) {
  char c;

  while((c = getopt(argc, argv, "hvi:o:n")) != -1) {
    switch(c) {
    case 'i':
      in_device = strdup(optarg);
      break;
    case 'n':
      nsec_ts = 1;
      break;
    case 'o':
      out_pipe_filename = strdup(optarg);
      break;
    case 'v':
      verbose = 1;
      break;
    default:
      help();
      break;
    }
  }

  if((in_device == NULL) || (out_pipe_filename == NULL))
    help();

  signal(SIGQUIT, cleanup);
  signal(SIGTERM, cleanup);
  signal(SIGPIPE, cleanup);

  if(nsec_ts)
    printf("Using nsec timestamps\n");

  run();
  return(0);
}

