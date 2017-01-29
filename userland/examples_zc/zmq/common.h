#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <math.h>
#include <sys/stat.h>
#include <zmq.h>
#include <assert.h>
#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

/* ********************************************** */

#define DEFAULT_ENDPOINT         "tcp://127.0.0.1:5555"
#define MAX_NUM_RULES_PER_MSG    64
#define DEFAULT_RULE_DURATION    60 /* 1 min */
#define DEFAULT_ENCRYPTION_KEY   "kasjfha 98748213^%@^&%#!^&532165^%#@^&tehshj^@&*#@^"
#define DEFAULT_TIMEOUT_MSEC     1000
#define MAGIC_VALUE              0x01032017

/* ********************************************** */

struct filtering_rule {
  uint8_t v4:1 /* IPv4=1, IPv6=0 */, 
          src_ip:1 /* 1=src IP, 0=dst IP */, 
          bidirectional:1 /* 0=one-way rule, 1=bidirectional */, 
          action_accept:1 /* 1=accept, 0=drop*/,
          remove:1 /* 1=remove rule, 0=add rule */,
          pad:3;
  uint16_t duration; /* sec - 0 = forever */
  union {
    uint32_t v4; /* little endian */
    uint8_t v6[16];
  } ip;
};

struct filtering_rules_header {
  u_int16_t request_id, num_rules;
  u_int32_t magic; /* Used to check encryption */
};

struct filtering_rules_request {
  struct filtering_rules_header header;
  struct filtering_rule rules[MAX_NUM_RULES_PER_MSG];
};

/* ****************************************************** */

static inline void xor_encdec(u_char *data, int data_len, u_char *key) {
  int i, y;

  for (i = 0, y = 0; i < data_len; i++) {
    data[i] ^= key[y++];
    if (key[y] == 0) y = 0;
  }
}

/* ****************************************************** */

