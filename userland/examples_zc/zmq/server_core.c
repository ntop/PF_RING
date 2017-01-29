
#include "common.h"

static volatile int loop;

/* ****************************************************** */

typedef int (*filtering_rule_handler) (struct filtering_rule *rule);

/* ****************************************************** */

void zmq_server_breakloop() {
  loop = 0;
}

/* ****************************************************** */

int zmq_server_listen(char *endpoint, char *encryption_key, filtering_rule_handler callback) {
  void *context = zmq_ctx_new ();
  void *server;

  loop = 1;

  /*  Socket to talk to clients */
  server = zmq_socket(context, ZMQ_REP);
  if (zmq_bind(server, endpoint) == -1) {
    printf("Unable to bind to %s\n", endpoint);
    return(-1);
  }

  while (loop) {
    zmq_msg_t request;
    size_t msg_len;
    int i;
    struct filtering_rules_request *enc_req, req;
    zmq_msg_t reply;
    const char *rsp;
    int len;
    int rc;

    /* Receiving message  */
    zmq_msg_init(&request);
    rc = zmq_msg_recv(&request, server, ZMQ_DONTWAIT);

    if (rc < 0) {
      if (errno == EAGAIN) usleep(100); /* this is due to ZMQ_DONTWAIT: no msg */
      continue;
    }

    enc_req = (struct filtering_rules_request *) zmq_msg_data(&request);
    msg_len = zmq_msg_size(&request);

    /* Decoding */
    memcpy(&req, enc_req, msg_len);
    xor_encdec((u_char *) &req, msg_len, (u_char *) encryption_key);
    if (req.header.magic != MAGIC_VALUE) {
      printf("Invalid decryption: message discarded\n");
      rsp = "DECODING ERROR";
    } else {
      int rc = 0;

#ifdef DEBUG
      printf("Received: [request_id: %u][num_rules: %u]\n",
        req.header.request_id, req.header.num_rules);
#endif

      for (i=0; i<req.header.num_rules; i++) {
        struct filtering_rule *rule = &req.rules[i];
	if (callback(rule) < 0) rc = -1;
      }

      if (rc == 0)
        rsp = "OK";
      else
        rsp = "ERROR";
    }

    zmq_msg_close (&request);

    /* Sending reply back to client */
    len = strlen(rsp);
    zmq_msg_init_size(&reply, len);
    memcpy(zmq_msg_data(&reply), rsp, len);
    zmq_msg_send(&reply, server, 0);
    zmq_msg_close(&reply);
  }

  zmq_close(server);
  zmq_ctx_destroy(context);

  return 0;
}

/* ****************************************************** */

