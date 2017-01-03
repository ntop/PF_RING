
#include "common.h"

/* ***************************************************************************** */

void help() {
  printf("Usage:\n"
         "client [-e <endpoint>] -i <IP> [-a] [-m <mode>] [-d <sec>] [-k <key>] [-t <timeout>]\n\n"
         "-e <endpoint>     | Specify the server address. Default: %s\n"
         "-i <IP>           | The numeric IPv4/v6 address to filter.\n"
         "-a                | Set accept action for this rule. Default: drop\n"
         "-m <mode>         | Set this rule mode: 0 = src IP, 1 = dst IP, 2 = bidirectional. Default: 0\n"
         "-d <sec>          | Specify the rule duration. Use 0 for infinite. Default: %u\n"
         "-k <key>          | Set the symmetric encryption key\n"
         "-t <timeout>      | Set the rule timeout for retransmission (msec). Default: %u msec\n",
         DEFAULT_ENDPOINT, DEFAULT_RULE_DURATION, DEFAULT_TIMEOUT_MSEC);

  printf("\n\nExamples:\n"
         "\tclient -i 192.168.1.1 -a -d 10\n"
         "\tclient -i fe80::57f8:866b:8505:15cf -m 2 -d 120\n"
    );

  exit(0);
}

/* ***************************************************************************** */

void *getClientConnection(void *ctx, char *endpoint) {
  int linger = 0, rc;
  void *client;
  
  client = zmq_socket (ctx, ZMQ_REQ); assert (client);
  zmq_setsockopt(client, ZMQ_LINGER, &linger, sizeof (int));

  rc = zmq_connect(client, endpoint);

  if (rc != 0) {
    printf("Unable to connect to %s\n", endpoint);
    return(NULL);
  }

  return client;
}

/* ***************************************************************************** */

int main(int argc, char* argv[]) {
  unsigned char c;
  int rc;
  void *ctx, *client;
  int request_nbr, timeout_msec = DEFAULT_TIMEOUT_MSEC;
  zmq_pollitem_t poll_items;
  char *endpoint = (char*)DEFAULT_ENDPOINT;
  struct filtering_rules_request req;
  u_char *encryption_key = (u_char*)DEFAULT_ENCRYPTION_KEY;
  zmq_msg_t request;
  int len;         

  memset(&req, 0, sizeof(req));

  req.header.magic = MAGIC_VALUE;
  
  while((c = getopt(argc, argv, "d:e:i:am:t:k:h")) != 255) {
         switch(c) {
    case 'e':
       endpoint = strdup(optarg);
       break;

    case 'i':
       if(strchr(optarg, '.')) {
           req.rules[0].v4 = 1, req.rules[0].ip.v4 = inet_addr(optarg),
           req.header.num_rules = 1;
       } else {
         if(inet_pton(AF_INET6, optarg, &req.rules[0].ip.v6) <= 0)
               printf("Invalid IPv6 address %s\n", optarg);
         else
            req.rules[0].v4 = 0, req.header.num_rules = 1;
       }
       break;

    case 'a':
       req.rules[0].action_accept = 1;
       break;

    case 'k':
       encryption_key = (u_char*)optarg;
       break;

    case 'd':
         req.rules[0].duration = atoi(optarg);
       break;

    case 'm':
       switch(atoi(optarg)) {
       case 0:
         req.rules[0].src_ip = 1;
         break;
       case 1:
         req.rules[0].src_ip = 0;
         break;
       case 2:
         req.rules[0].bidirectional = 1;
         break;
       default:
         printf("Ignored -m value (%s): out of range\n", optarg);
         break;
       }
       break;

    case 't':
       timeout_msec = atoi(optarg);
       break;

    case 'h':
      help();
      break;

    default:
       printf("Unknown option '%c'\n", c);
       help();
       break;
    }
  }

  ctx = zmq_ctx_new (); assert (ctx);
  client = getClientConnection(ctx, endpoint);
  poll_items.socket = client, poll_items.fd = 0;
  poll_items.events = ZMQ_POLLIN, poll_items.revents = 0;

  request_nbr = 0;

resend_msg:

  req.header.request_id = request_nbr;
  printf("Sending message...\n");
  len = sizeof(req.header) + req.header.num_rules*sizeof(struct filtering_rule);
  zmq_msg_init_size (&request, len);
  xor_encdec((u_char*)&req, len, encryption_key); /* Encrypt */
  memcpy(zmq_msg_data(&request), &req, len);
  xor_encdec((u_char*)&req, len, encryption_key); /* Decrypt for next send */
  zmq_msg_send(&request, client, 0);
  zmq_msg_close(&request);

  zmq_poll(&poll_items, 1, timeout_msec);
  if (poll_items.revents & ZMQ_POLLIN) {
    zmq_msg_t reply;
    char msg[256];
      
    zmq_msg_init(&reply);
    zmq_msg_recv(&reply, client, 0);
    len = zmq_msg_size(&reply);
    if (len > sizeof(msg)-1) len = sizeof(msg) - 1;
    snprintf(msg, sizeof(msg), "%s", (char *) zmq_msg_data(&reply));
    msg[len] = '\0';
    printf("Received response %s\n", msg);
    zmq_msg_close(&reply);
  } else {
    printf("Timeout expired: retrying...\n");
    zmq_close(client);
    client = getClientConnection(ctx, endpoint);
    goto resend_msg;
  }

  zmq_close (client);
  zmq_ctx_destroy(ctx);
  return 0;
}
