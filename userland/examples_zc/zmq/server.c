
#include "server_core.c"

/* ****************************************************** */

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

/* ****************************************************** */

void help() {
  printf("Usage:\nserver [-k <key>]\n\n");
  exit(0);
}

/* ****************************************************** */

int zmq_filtering_rule_handler(struct filtering_rule *rule) {
  char buf[64];

  printf("\t[IPv%d][%s][duration: %u][%s]\n",
    rule->v4 ? 4 : 6,
    rule->bidirectional ? "bidirectional" : (rule->src_ip ? "srcIP" : "dstIP"),
    rule->duration,
    rule->v4 ? intoaV4(ntohl(rule->ip.v4), buf, sizeof(buf)) : intoaV6(&rule->ip.v6, buf, sizeof(buf)));

  return 0;
}

/* ****************************************************** */

int main(int argc, char* argv[]) {
  u_char *encryption_key = (u_char*)DEFAULT_ENCRYPTION_KEY, c;

  while((c = getopt(argc, argv, "k:h")) != 255) {
         switch(c) {
      case 'k':
        encryption_key = (u_char*)optarg;
        break;
      case 'h':
        help();
        break;
      default:
        help();
      }
  }

  zmq_server_listen(DEFAULT_ENDPOINT, encryption_key, zmq_filtering_rule_handler);

  return 0;
}

/* ****************************************************** */

