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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <zmq.h>

#include "nbroker_api.h"
#include "parser.h"

static const char *zmq_server_address = "tcp://127.0.0.1:5555";

/* ******************************************************* */

static void cmd_queue_init(cmd_queue_t *q) {
  memset(q, 0, sizeof(cmd_queue_t));
  q->tail = CMD_QUEUE_ITEMS - 1;
  q->head = 0;
}

/* Queue consumer */

static inline cmd_desc_t *cmd_queue_next(cmd_queue_t *q) {
  u_int32_t next_tail;

  next_tail = (q->tail + 1) & CMD_QUEUE_ITEMS_MASK;
  if (next_tail != q->head)
    return &q->desc[next_tail];

  return NULL;
}

static inline void cmd_queue_pop(cmd_queue_t *q) {
  u_int32_t next_tail;

  next_tail = (q->tail + 1) & CMD_QUEUE_ITEMS_MASK;
  q->tail = next_tail;
}

/* Queue producer */

static inline cmd_desc_t *cmd_queue_next_free(cmd_queue_t *q) {
  u_int32_t next_head;

  next_head = (q->head + 1) & CMD_QUEUE_ITEMS_MASK;
  if (q->tail != next_head)
    return &q->desc[q->head];

  return NULL;
}

static inline void cmd_queue_push(cmd_queue_t *q) {
  u_int32_t next_head;

  next_head = (q->head + 1) & CMD_QUEUE_ITEMS_MASK;
  q->head = next_head;
}

/* ******************************************************* */

/*
 * Send a command to the broker.
 */
static nbroker_rc_t __nbroker_exec(nbroker_t *broker, const nbroker_command_t *command);

/*
 * Get the active rules list on the device by filter_type.
 * This must be called after a successful __nbroker_exec RRC_RULE_TYPE_LIST_RULES command.
 *
 * @param num_rules will contain the number of rules
 * @param rules will contain the actual rules array, to be free by the caller
 */
static nbroker_rc_t __nbroker_read_rules(nbroker_t *broker, nbroker_filter_type_t type, u_int32_t *num_rules, nbroker_rule_t **rules);

/*
 * Read an RRC port.
 * This must be called after a successful __nbroker_exec
 * RRC_RULE_TYPE_IFNAME_TO_INTERNAL/RRC_RULE_TYPE_IFNAME_TO_EXTERNAL command.
 */
static nbroker_rc_t __nbroker_read_port(nbroker_t *bkr, u_int8_t *port);

/*
 * Read a rule ID.
 * This must be called after a successful
 * nbroker_set_filtering_rule/nbroker_set_steering_rule.
 */
static nbroker_rc_t __nbroker_read_rule_id(nbroker_t *bkr, u_int32_t *rule_id);

#if 0
/*
 * Read rule/port statistics.
 * This must be called after a successful __nbroker_exec RRC_RULE_TYPE_STATS command.
 *
 * @param stats the structure to be filled
 */
static nbroker_rc_t nbroker_read_stats(nbroker_t *broker, nbroker_stats_t *stats);
#endif

/* ******************************************************* */

static nbroker_rc_t __stay_connected(nbroker_t *broker) {
  //int timeout_millisec = 5000; /* seconds */

  if(broker->zmq_context)
    return NBROKER_RC_OK;

  broker->zmq_context = zmq_ctx_new();
  broker->zmq_requester = zmq_socket(broker->zmq_context, ZMQ_REQ);
  
  if(!broker->zmq_requester)
    return NBROKER_RC_INTERNAL_ERROR;

  zmq_connect(broker->zmq_requester, zmq_server_address);

  // zmq_setsockopt(broker->zmq_requester, ZMQ_RCVTIMEO, &timeout_millisec, sizeof(timeout_millisec));

  return NBROKER_RC_OK;
}

/* ******************************************************* */

static void __disconnected(nbroker_t *broker) {
  zmq_close(broker->zmq_requester);
  zmq_ctx_destroy(broker->zmq_context);

  broker->zmq_requester = NULL, broker->zmq_context = NULL;

  /* Reconnect */
  __stay_connected(broker);
}

/* ******************************************************* */

static nbroker_rc_t __send_command_header(nbroker_t *broker) {
  nbroker_command_header_t header;

  header.binary_mark = RRC_BINARY_MARK;
  header.binary_version = RRC_BINARY_VERSION;

  zmq_send(broker->zmq_requester, (char*)&header, sizeof(header), ZMQ_SNDMORE);

  return NBROKER_RC_OK;
}

/* ******************************************************* */

static nbroker_rc_t __read_command_result(nbroker_t *broker) {
  int retv;
  //~ nbroker_command_header_t header;
  nbroker_command_result_t res;

  /* Read the response code */
  if ((retv = zmq_recv(broker->zmq_requester, (char*)&res, sizeof(res), 0)) <= 0) {
    if (! retv) __disconnected(broker);
    return NBROKER_RC_CONNECTION_ERROR;
  }

  return (nbroker_rc_t)res.return_code;
}

/* ******************************************************* */

static nbroker_rc_t __nbroker_exec(nbroker_t *bkr, const nbroker_command_t *command) {
  nbroker_rc_t rc;

  if ((rc = __stay_connected(bkr)) != NBROKER_RC_OK)
    return rc;

  /* Send the command */
  if ((rc = __send_command_header(bkr)) != NBROKER_RC_OK)
    return rc;

  zmq_send(bkr->zmq_requester, (char*)command, sizeof(nbroker_command_t), 0);

  /* Read the response */
  if ((rc = __read_command_result(bkr)) != NBROKER_RC_OK)
    return rc;

  return NBROKER_RC_OK;
}

/* ******************************************************* */

static nbroker_rc_t __nbroker_read_rules(nbroker_t *bkr, nbroker_filter_type_t type, u_int32_t *num_rules, nbroker_rule_t **rules) {
  nbroker_command_rules_result_t res;
  nbroker_command_rule_t recv_rule;
  nbroker_rule_t *alloc_rules;
  int retv;
  u_int32_t i;

  /* Read the rules number */
  if ((retv = zmq_recv(bkr->zmq_requester, (char*)&res, sizeof(res), 0)) <= 0) {
    if (! retv) __disconnected(bkr);
    return NBROKER_RC_CONNECTION_ERROR;
  }

  *num_rules = res.num_rules;

  if (res.num_rules == 0) {
    *rules = NULL;
    return NBROKER_RC_OK;
  }

  alloc_rules = (nbroker_rule_t*) calloc(res.num_rules, sizeof(nbroker_rule_t));
  if (! alloc_rules)
    return NBROKER_RC_INTERNAL_ERROR;

  /* Read the rules */
  for (i = 0; i < res.num_rules; i++) {
    if ((retv = zmq_recv(bkr->zmq_requester, (char*)&recv_rule, sizeof(recv_rule), 0)) <= 0) {
      if (! retv) __disconnected(bkr);
      free(alloc_rules);
      return NBROKER_RC_CONNECTION_ERROR;
    }

    alloc_rules[i].rule_id = recv_rule.rule_id;
    alloc_rules[i].match = recv_rule.match;

    if (type == NBROKER_TYPE_FILTERING)
      alloc_rules[i].u.policy = (recv_rule.u.policy == RRC_POLICY_DROP) ? NBROKER_POLICY_DROP : NBROKER_POLICY_PASS;
    else
      alloc_rules[i].u.steer_to = recv_rule.u.steer_to;
  }

  *rules = alloc_rules;
  return NBROKER_RC_OK;
}

/* ******************************************************* */

nbroker_rc_t nbroker_set_default_policy(nbroker_t *bkr, const char *port, nbroker_policy_t policy) {
  nbroker_command_t command = {0};

  command.type = RRC_RULE_TYPE_ACTION;
  command.action.type = RRC_ACTION_SET_DEFAULT;
  strncpy(command.action.port, port, sizeof(command.action.port));
  command.action.policy = (policy == NBROKER_POLICY_DROP) ? RRC_POLICY_DROP : RRC_POLICY_PASS;

  return __nbroker_exec(bkr, &command);
}

/* ******************************************************* */

nbroker_rc_t nbroker_apply_pending_rules(nbroker_t *bkr) {
  nbroker_command_t command = {0};
  
  command.type = RRC_RULE_TYPE_ACTION;
  command.action.type = RRC_ACTION_APPLY;
  
  return __nbroker_exec(bkr, &command);
}

/* ******************************************************* */

nbroker_rc_t nbroker_set_default_steering(nbroker_t *bkr, const char *port, const char *steer_to) {
  nbroker_command_t command = {0};

  command.type = RRC_RULE_TYPE_ACTION;
  command.action.type = RRC_ACTION_SET_DEFAULT;
  strncpy(command.action.port, port, sizeof(command.action.port));
  strncpy(command.action.redirectionPort, steer_to, sizeof(command.action.redirectionPort));
  command.action.policy = RRC_POLICY_STEER;

  return __nbroker_exec(bkr, &command);
}

/* ******************************************************* */

static nbroker_rc_t __nbroker_set_filtering_rule(nbroker_t *bkr, const char *port, u_int32_t *rule_id,
        const rrc_match_t *match, nbroker_policy_t policy) {
  nbroker_rc_t rc;
  nbroker_command_t command = {0};

  command.type = RRC_RULE_TYPE_ACTION;
  command.action.type = RRC_ACTION_SET;
  strncpy(command.action.port, port, sizeof(command.action.port));
  command.ruleNumber = *rule_id;
  command.action.match = *match;
  command.action.policy = (policy == NBROKER_POLICY_DROP) ? RRC_POLICY_DROP : RRC_POLICY_PASS;

  if ((rc = __nbroker_exec(bkr, &command)) != NBROKER_RC_OK)
    return rc;

  return __nbroker_read_rule_id(bkr, rule_id);
}

/* ******************************************************* */

nbroker_rc_t nbroker_set_filtering_rule(nbroker_t *bkr, const char *port, u_int32_t *rule_id,
        const rrc_match_t *match, nbroker_policy_t policy) {

  if (bkr->flags & NBROKER_FLAGS_FAST) {
    cmd_desc_t *desc;
    desc = cmd_queue_next_free(&bkr->cmdq);
    if (desc != NULL) {
      desc->type = CMD_SET_RULE;
      desc->rule.type = NBROKER_TYPE_FILTERING;
      strncpy(desc->rule.port, port, sizeof(desc->rule.port));
      desc->rule.rule_id = *rule_id;
      memcpy(&desc->rule.match, match, sizeof(desc->rule.match));
      desc->rule.policy = policy;

      cmd_queue_push(&bkr->cmdq);
      return NBROKER_RC_OK;
    } else {
      return NBROKER_RC_BUSY;
    }
  } else {
    return __nbroker_set_filtering_rule(bkr, port, rule_id, match, policy);
  }
}

/* ******************************************************* */

nbroker_rc_t __nbroker_set_steering_rule(nbroker_t *bkr, const char *port, u_int32_t *rule_id,
        const rrc_match_t *match, const char *steer_to) {
  nbroker_rc_t rc;
  nbroker_command_t command = {0};

  command.type = RRC_RULE_TYPE_ACTION;
  command.action.type = RRC_ACTION_SET;
  strncpy(command.action.port, port, sizeof(command.action.port));
  strncpy(command.action.redirectionPort, steer_to, sizeof(command.action.redirectionPort));
  command.ruleNumber = *rule_id;
  command.action.match = *match;
  command.action.policy = RRC_POLICY_STEER;

  if ((rc = __nbroker_exec(bkr, &command)) != NBROKER_RC_OK)
    return rc;

  return __nbroker_read_rule_id(bkr, rule_id);
}

/* ******************************************************* */

nbroker_rc_t nbroker_set_steering_rule(nbroker_t *bkr, const char *port, u_int32_t *rule_id,
        const rrc_match_t *match, const char *steer_to) {

  if (bkr->flags & NBROKER_FLAGS_FAST) {
    cmd_desc_t *desc;
    desc = cmd_queue_next_free(&bkr->cmdq);
    if (desc != NULL) {
      desc->type = CMD_SET_RULE;
      desc->rule.type = NBROKER_TYPE_STEERING;
      strncpy(desc->rule.port, port, sizeof(desc->rule.port));
      desc->rule.rule_id = *rule_id;
      memcpy(&desc->rule.match, match, sizeof(desc->rule.match));
      strncpy(desc->rule.redirectionPort, steer_to, sizeof(desc->rule.redirectionPort));

      cmd_queue_push(&bkr->cmdq);
      return NBROKER_RC_OK;
    } else {
      return NBROKER_RC_BUSY;
    }
  } else {
    return __nbroker_set_steering_rule(bkr, port, rule_id, match, steer_to);
  }
}

/* ******************************************************* */

nbroker_rc_t nbroker_remove_rule_by_id(nbroker_t *bkr, const char *port, u_int32_t rule_id,
        nbroker_filter_type_t filter_type) {
  nbroker_command_t command = {0};

  command.type = RRC_RULE_TYPE_ACTION;
  command.action.type = RRC_ACTION_DELETE;
  strncpy(command.action.port, port, sizeof(command.action.port));
  command.ruleNumber = rule_id;
  command.filter_type = (filter_type == NBROKER_TYPE_FILTERING) ? RRC_RULE_FILTERING : RRC_RULE_STEERING;

  return __nbroker_exec(bkr, &command);
}

/* ******************************************************* */

nbroker_rc_t nbroker_remove_rule_by_match(nbroker_t *bkr, const char *port,
        const rrc_match_t *match, nbroker_filter_type_t filter_type) {
  nbroker_command_t command = {0};

  command.type = RRC_RULE_TYPE_ACTION;
  command.action.type = RRC_ACTION_DELETE;
  strncpy(command.action.port, port, sizeof(command.action.port));
  command.ruleNumber = NBROKER_AUTO_RULE_ID;
  command.action.match = *match;
  command.filter_type = (filter_type == NBROKER_TYPE_FILTERING) ? RRC_RULE_FILTERING : RRC_RULE_STEERING;

  return __nbroker_exec(bkr, &command);
}

/* *********************************************** */

static int ruleSorter(const void *_a, const void *_b) {
  nbroker_rule_t *a = (nbroker_rule_t*)_a;
  nbroker_rule_t *b = (nbroker_rule_t*)_b;

  return(a->rule_id > b->rule_id);
}

/* ******************************************************* */

nbroker_rc_t nbroker_list_rules(nbroker_t *bkr, const char *port, nbroker_filter_type_t filter_type,
        u_int32_t *num_rules, nbroker_rule_t **rules) {
  nbroker_rc_t rc;
  nbroker_command_t command = {0};

  command.type = RRC_RULE_TYPE_LIST_RULES;
  strncpy(command.list_rules.port, port, sizeof(command.action.port));
  command.filter_type = (filter_type == NBROKER_TYPE_FILTERING) ? RRC_RULE_FILTERING : RRC_RULE_STEERING;

  if ((rc = __nbroker_exec(bkr, &command)) != NBROKER_RC_OK)
    return rc;

  if ((rc = __nbroker_read_rules(bkr, filter_type, num_rules, rules)) != NBROKER_RC_OK)
    return rc;

  if ((rc = __read_command_result(bkr)) != NBROKER_RC_OK)
    return rc;

  if(*rules)
    qsort(*rules, *num_rules, sizeof(nbroker_rule_t), ruleSorter);
  
  return rc;
}

/* ******************************************************* */

nbroker_rc_t nbroker_reset_rules(nbroker_t *bkr, const char *port, nbroker_filter_type_t filter_type) {
  nbroker_command_t command = {0};

  command.type = RRC_RULE_TYPE_RESET_RULES;
  strncpy(command.reset_rules.port, port, sizeof(command.reset_rules.port));
  command.filter_type = (filter_type == NBROKER_TYPE_FILTERING) ? RRC_RULE_FILTERING : RRC_RULE_STEERING;

  return __nbroker_exec(bkr, &command);
}

/* ******************************************************* */

nbroker_rc_t nbroker_purge_idle_rules(nbroker_t *bkr, u_int32_t idle_for) {
  nbroker_command_t command = {0};

  command.type = RRC_RULE_TYPE_GARBAGE_COLLECT;
  command.gc.idle_for = idle_for;

  return __nbroker_exec(bkr, &command);
}

/* ******************************************************* */

nbroker_rc_t nbroker_set_auto_purge(nbroker_t *bkr, u_int32_t idle_for) {
  nbroker_command_t command = {0};

  command.type = RRC_RULE_TYPE_AUTO_GARBAGE_COLLECT;
  command.gc.idle_for = idle_for;

  return __nbroker_exec(bkr, &command);
}

/* ******************************************************* */

static nbroker_rc_t __nbroker_read_port(nbroker_t *bkr, u_int8_t *port) {
  nbroker_command_port_conversion_result_t res;
  int retv;

  if ((retv = zmq_recv(bkr->zmq_requester, (char*)&res, sizeof(res), 0)) <= 0) {
    if (! retv) __disconnected(bkr);
    return NBROKER_RC_CONNECTION_ERROR;
  }

  *port = res.port;
  return NBROKER_RC_OK;
}

/* ******************************************************* */

static nbroker_rc_t __nbroker_read_rule_id(nbroker_t *bkr, u_int32_t *rule_id) {
  int retv;

  if ((retv = zmq_recv(bkr->zmq_requester, (char*)rule_id, sizeof(*rule_id), 0)) <= 0) {
    if (! retv) __disconnected(bkr);
    return NBROKER_RC_CONNECTION_ERROR;
  }

  return NBROKER_RC_OK;
}

/* ******************************************************* */

nbroker_rc_t nbroker_ifname_to_internal_port(nbroker_t *bkr, const char *ifname, u_int8_t *port) {
  nbroker_rc_t rc;
  nbroker_command_t command = {0};

  command.type = RRC_RULE_TYPE_IFNAME_TO_INTERNAL;
  strncpy(command.ifname_to_port.port, ifname, sizeof(command.action.port));

  if ((rc = __nbroker_exec(bkr, &command)) != NBROKER_RC_OK)
    return rc;

  return __nbroker_read_port(bkr, port);
}

/* ******************************************************* */

nbroker_rc_t nbroker_ifname_to_external_port(nbroker_t *bkr, const char *ifname, u_int8_t *port) {
  nbroker_rc_t rc;
  nbroker_command_t command = {0};

  command.type = RRC_RULE_TYPE_IFNAME_TO_EXTERNAL;
  strncpy(command.ifname_to_port.port, ifname, sizeof(command.action.port));

  if ((rc = __nbroker_exec(bkr, &command)) != NBROKER_RC_OK)
    return rc;

  return __nbroker_read_port(bkr, port);
}

/* ******************************************************* */

rrc_match_t* nbroker_parse_rule(const char *rule) {
  char err_buf[256];
  return rrc_parse_bpf(rule, err_buf, sizeof(err_buf));
}

/* ******************************************************* */

static void *__commands_queue_thread(void *data) {
  nbroker_t *bkr = (nbroker_t *) data;
  cmd_desc_t *desc;
  
  while (!bkr->breakloop) {

    desc = cmd_queue_next(&bkr->cmdq);

    if (desc != NULL) {
      if (desc->type == CMD_SET_RULE) {
        switch (desc->rule.type) {
          case NBROKER_TYPE_FILTERING:
            __nbroker_set_filtering_rule(bkr, desc->rule.port, &desc->rule.rule_id, &desc->rule.match, desc->rule.policy);
          break;
          case NBROKER_TYPE_STEERING:
            __nbroker_set_steering_rule(bkr, desc->rule.port, &desc->rule.rule_id, &desc->rule.match, desc->rule.redirectionPort);
          break;
        }
      }

      cmd_queue_pop(&bkr->cmdq);
    } else {
      usleep(100);
    }
  }

  return NULL;
}

/* ******************************************************* */

static int __create_commands_queue(nbroker_t *bkr) {

  cmd_queue_init(&bkr->cmdq);

  if (pthread_create(&bkr->cmdqthread, NULL, __commands_queue_thread, (void *) bkr) != 0)
    return -1;

  return 0;
}

/* ******************************************************* */

static void __destroy_commands_queue(nbroker_t *bkr) {
  pthread_join(bkr->cmdqthread, NULL);
}

/* ******************************************************* */

nbroker_rc_t nbroker_init(nbroker_t **bkr, u_int32_t flags) {
  nbroker_rc_t rc;
  nbroker_t *bkr_alloc;

  bkr_alloc = calloc(1, sizeof(nbroker_t));
  if (bkr_alloc == NULL)
    return NBROKER_RC_INTERNAL_ERROR;

  bkr_alloc->flags = flags;

  if (flags & NBROKER_FLAGS_FAST) {
    if (__create_commands_queue(bkr_alloc) != 0) {
      free(bkr_alloc);
      return NBROKER_RC_INTERNAL_ERROR;
    }
  }

  if ((rc = __stay_connected(bkr_alloc)) != NBROKER_RC_OK) {
    if (flags & NBROKER_FLAGS_FAST)
      __destroy_commands_queue(bkr_alloc);
    free(bkr_alloc);
    return rc;
  }      
  
  *bkr = bkr_alloc;
  return NBROKER_RC_OK;
}

/* ******************************************************* */

nbroker_rc_t nbroker_term(nbroker_t *bkr) {
  bkr->breakloop = 1;

  __disconnected(bkr);

  if (bkr->flags & NBROKER_FLAGS_FAST)
    __destroy_commands_queue(bkr);

  free(bkr);
  return NBROKER_RC_OK;
}

/* ******************************************************* */

