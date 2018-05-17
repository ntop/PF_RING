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

#define _GNU_SOURCE 
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/time.h>
#include <pthread.h>
#include <sched.h>
#include <fcntl.h>
#include <zmq.h>

#include "utils.h"
#include "common.h"
#include "rrc.h"
#include "parser.h"
#include "rules_hash.h"

//#define DEBUG

/* Enable this to skip RRC device calls for local testing */
// #define RRC_TEST_ON

#define DEFAULT_IDLE_PURGE_SECONDS 5

/* apply the rules when the clients do not send new rules updates for the specified seconds */
#define RULES_APPLY_IDLE_INTERVAL 2

/* this is the maximum delay for rules apply */
#define RULES_APPLY_MAX_INTERVAL 3

static int daemon_mode = 0;
static time_t last_rules_update = 0;
static time_t apply_pending_since = 0;
static u_int64_t rules_to_apply = 0;
static sig_atomic_t running = 1;
static u_int32_t auto_garbage_collect_idle_for = 0; /* 0: auto garbage collect disabled */
static u_int8_t broker_ready = 0;
/* One hash for each port: one for steering, one for filtering */
static ruleshash_t hashes[MAX_NUM_PORTS*2];
static const char *zmq_server_address = "tcp://127.0.0.1:5555";
static void *zmq_context, *zmq_responder;
static char *rrc_config_file = NULL;

/* ****************************************************** */

typedef struct {
  rrc_port_t *port;
  rrc_filter_type_t filter_type;
  u_int32_t matched_rules;
  time_t older_than;           /* Only used in garbage_collect_callback */
  int rc;
} remove_rules_callback_data_t;

/* ****************************************************** */

static void housekeeping();

/* ****************************************************** */

static void term_zmq() {
  zmq_close(zmq_responder);
  zmq_ctx_destroy(zmq_context);
}

/* ****************************************************** */

/*
  Read this for multiple clients connected to the same server
  https://stackoverflow.com/questions/41803349/how-does-zeromq-req-rep-handle-multiple-clients
*/
static int init_zmq() {
  int timeout_millisec = 5000; /* seconds */

  zmq_context = zmq_ctx_new();
  zmq_responder = zmq_socket(zmq_context, ZMQ_REP);

  if(zmq_bind(zmq_responder, zmq_server_address) != 0) {
    traceEvent(TRACE_ERROR, "Unable to bind ZMQ to address %s", zmq_server_address);
    term_zmq();
    return -1;
  }
 
  zmq_setsockopt(zmq_responder, ZMQ_RCVTIMEO, &timeout_millisec, sizeof(timeout_millisec));

  traceEvent(TRACE_NORMAL, "[ZMQ] Listening at %s", zmq_server_address);

  return 0;
}

/* ****************************************************** */

static void rrc_rule_to_str(const ruleshash_key *key, ruleshash_data *data, char *buf, size_t bufsize);

/* ****************************************************** */

static inline rrc_filter_type_t get_filter_type(u_int8_t filter_type) { 
  return (filter_type == RRC_RULE_FILTERING) ? EGRESS_TRAFFIC : INGRESS_TRAFFIC; 
}

/* ****************************************************** */

static rrc_policy_t command_to_rrc_policy(u_int8_t cmd_policy) {
    switch (cmd_policy) {
        case RRC_POLICY_PASS: return PERMIT;
        case RRC_POLICY_DROP: return DENY;
        case RRC_POLICY_STEER: return REDIRECT;
    }

    traceEvent(TRACE_ERROR, "Invalid command policy: %d", cmd_policy);
    return PERMIT;
}

/* ****************************************************** */

/* These are related one to the other */
static inline ruleshash_t *get_port_hash(int port, rrc_filter_type_t filter_type) { return &hashes[((port - 1) * 2) + (filter_type == EGRESS_TRAFFIC ? 0 : 1)]; }

/* ****************************************************** */

static inline rrc_port_t *hash_idx_to_port(int idx) { return rrc_port_get((idx / 2) + 1); }

/* ****************************************************** */

static inline rrc_filter_type_t hash_idx_to_filter_type(int idx) { return (idx % 2 == 0) ? EGRESS_TRAFFIC : INGRESS_TRAFFIC; }

/* ****************************************************** */

/* NOTE: rrc_get_port should be called right after this to validate the port */
static inline void translate_symbolic_ports(rrc_filter_type_t filter_type, const char *port, const char *redirectionPort, int *main_port, int *steer_port) {

  if(isdigit(port[0]))
    *main_port = atoi(port);
  else {
#ifndef RRC_TEST_ON
    if(filter_type == EGRESS_TRAFFIC)
      *main_port = rrc_ifname_to_phys_port(port);
    else
      *main_port = rrc_get_external_phys_port(rrc_ifname_to_phys_port(port));
#else
    *main_port = 1;
#endif
  }

  if((filter_type == INGRESS_TRAFFIC) && redirectionPort) {
    if(isdigit(redirectionPort[0]))
      *steer_port = atoi(redirectionPort);
    else
#ifndef RRC_TEST_ON
      *steer_port = rrc_get_external_phys_port(rrc_ifname_to_phys_port(redirectionPort));
#else
      *steer_port = 2;
#endif
  }

}

/* ****************************************************** */

static nbroker_rc_t send_return_code(nbroker_rc_t rc, const char *rc_str, char *buf, size_t buf_size, int is_binary, int multiple_msg) {
  nbroker_command_result_t result;

  if (is_binary) {
    result.return_code = (u_int8_t) rc;

    zmq_send(zmq_responder, (char *) &result, sizeof(result), multiple_msg ? ZMQ_SNDMORE : 0);
  } else {
    snprintf(buf, buf_size, "%d %s", rc, rc_str);

    zmq_send(zmq_responder, buf, strlen(buf) + 1, multiple_msg ? ZMQ_SNDMORE : 0);
  }

  return rc;
}

/* *********************************************************** */

static inline nbroker_rc_t send_ok_code(char *buf, size_t buf_size, int is_binary, int extra_rsp_will_follow) {
  return send_return_code(NBROKER_RC_OK, "OK", buf, buf_size, is_binary, extra_rsp_will_follow); 
}

static inline nbroker_rc_t send_unsupported_mode(char *buf, size_t buf_size, int is_binary) {
  return send_return_code(NBROKER_RC_UNSUPPORTED_MODE, is_binary ? "Command not supported in binary mode" : "Command not supported in text mode",
			  buf, buf_size, is_binary, 0);
}

static inline nbroker_rc_t send_command_set_error(char *buf, size_t buf_size, int is_binary) {
  return send_return_code(NBROKER_RC_DEVICE_COMMAND_ERROR,
        "Error while setting the command on the device", buf, buf_size,
			  is_binary, 0);
}

static inline nbroker_rc_t send_invalid_device_port(char *buf, size_t buf_size, int is_binary) {
  return send_return_code(NBROKER_RC_INVALID_DEVICE_PORT, "Invalid device port", buf, buf_size, is_binary, 0);
}

/* ****************************************************** */

/*
 * Receives a command from the socket, either in binary or textual form
 *
 * 0 is returned if socket has been closed
 * 1 is returned on success
 * -1 is returned on failure
 */
static int receive_command(nbroker_command_t **command, char *buf,
			   size_t bufsize, char *errbuf, size_t errbuf_size, int *is_binary) {
  nbroker_command_header_t header;
  int rc;
  char err_buf[128];

  zmq_pollitem_t zmq_items [] = {
    { zmq_responder, 0, ZMQ_POLLIN, 0  }
  };

  if (bufsize < sizeof(header)) {
    traceEvent(TRACE_ERROR, "Invalid buffer size");
    return -1;
  }

  while (running) {

    rc = zmq_poll(zmq_items, 1 /* 1 zmq_items to poll */, 1000 /* 1 sec timeout */);

    if (rc == 0) {
      housekeeping();
      continue;
    } else if(rc < 0) {
      if (errno == EINTR) {
        housekeeping();
        continue; 
      }
      traceEvent(TRACE_ERROR, "Communication error. Leaving...");
      exit(1);
    } else {
      traceEvent(TRACE_DEBUG, "[ZMQ] Command received");
      break;
    }
  }

  if (!running)
    return -1;

  if((rc = zmq_recv(zmq_responder, (char*)&header, sizeof(header), 0)) == -1)
    return(rc);

  if (header.binary_mark == RRC_BINARY_MARK) { /* binary format */

    *is_binary = 1;

    if (header.binary_version != RRC_BINARY_VERSION) {
      traceEvent(TRACE_ERROR, "Unsupported binary version 0x%02x", header.binary_version);
      send_command_set_error(err_buf, sizeof(err_buf), 1);
      return -1;
    }

    *command = (nbroker_command_t *) calloc(sizeof(nbroker_command_t), 1);
    if (*command == NULL) {
      traceEvent(TRACE_ERROR, "Memory allocation failure");
      send_command_set_error(err_buf, sizeof(err_buf), 1);
      return -1;
    }
    
    if ((rc = zmq_recv(zmq_responder, (char*)*command, sizeof(nbroker_command_t), 0)) == -1) {
      traceEvent(TRACE_WARNING, "Error reading the full command");
      free(*command);
      send_command_set_error(err_buf, sizeof(err_buf), 1);
      return rc;
    }

  } else { /* text format */

    *is_binary = 0;

    memcpy(buf, &header, sizeof(nbroker_command_header_t));

    /* read the rest of the message */
    if ((rc = zmq_recv(zmq_responder, buf, bufsize, 0)) == -1) {
      traceEvent(TRACE_DEBUG, "Error reading the full message");
      return rc;
    }

    traceEvent(TRACE_INFO, "[ZMQ] Command: '%s'", buf);

    *command = rrc_parse(buf, errbuf, errbuf_size);

    if (*command == NULL) {
      traceEvent(TRACE_DEBUG, "Error parsing '%s': %s", buf, errbuf);
      send_command_set_error(err_buf, sizeof(err_buf), 0);
      return -1;
    }
  }

  return 1;
}

/* ****************************************************** */

static ruleshash_callback_rc garbage_collect_callback(const ruleshash_key *key, ruleshash_data *data, void *user_data) {
  remove_rules_callback_data_t *working = (remove_rules_callback_data_t*) user_data;

  if(data->last_update < working->older_than) {
#ifndef RRC_TEST_ON
    int rc;

    if((rc = rrc_remove_rule(working->port, data->rule_id, working->filter_type)) == -1) {
      working->rc = rc;
      return RULESHASH_ITER_STOP;
    }
#endif
    return RULESHASH_ITER_DELETE_CONTINUE;
  }

  return RULESHASH_ITER_CONTINUE;
}

/* *********************************************************** */

static ruleshash_callback_rc send_rules_list_callback(const ruleshash_key *key, ruleshash_data *data, void *user_data) {
  char rulebuf[512];

  rrc_rule_to_str(key, data, rulebuf, sizeof(rulebuf));
  
#ifdef DEBUG
  traceEvent(TRACE_DEBUG, "Rule = %s", rulebuf);
#endif

  zmq_send(zmq_responder, rulebuf, strlen(rulebuf) + 1, ZMQ_SNDMORE);

  return RULESHASH_ITER_CONTINUE;
}

/* *********************************************************** */

static ruleshash_callback_rc send_rules_list_binary_callback(const ruleshash_key *key, ruleshash_data *data, void *user_data) {
  nbroker_command_rule_t rule;
  int rc;

  rule.rule_id = data->rule_id;
  rule.match = *key;

  if(data->policy == RRC_POLICY_STEER)
    rule.u.steer_to = data->redirectionPort;
  else
    rule.u.policy = data->policy;

  rc = zmq_send(zmq_responder, (char *) &rule, sizeof(rule), ZMQ_SNDMORE);

  if (rc != sizeof(rule))
    traceEvent(TRACE_ERROR, "zmq_send failure (%d): %s", rc, strerror(errno));

  return RULESHASH_ITER_CONTINUE;
}

/* *********************************************************** */

static int apply_rules(int force) {
  if((rules_to_apply == 0) && (! force))
    return 0;

  /* do this here to prevent multiple applies upon failure */
  apply_pending_since = last_rules_update = time(0);

  traceEvent(TRACE_INFO, "Applying rules...");
#ifndef RRC_TEST_ON
  if(rrc_apply() == -1)
    return -1;
#endif

  rules_to_apply = 0;
  return 0;
}

/* *********************************************************** */

static int periodic_apply() {
  time_t now = time(0);

  if(rules_to_apply && ((now - last_rules_update >= RULES_APPLY_IDLE_INTERVAL) || (now - apply_pending_since >= RULES_APPLY_MAX_INTERVAL))) {
    traceEvent(TRACE_DEBUG, "%d pending rule(s) [now = %u][last_rules_update = %u][apply_pending_since = %u]", 
      rules_to_apply, now, last_rules_update, apply_pending_since);
    return apply_rules(0);
  }

  traceEvent(TRACE_DEBUG, "No pending rules [now = %u][last_rules_update = %u][apply_pending_since = %u]", 
    now, last_rules_update, apply_pending_since);

  return 0;
}

/* *********************************************************** */

static void defer_apply(u_int64_t to_apply) {
  time_t now = time(0);

  traceEvent(TRACE_INFO, "Deferring apply for %d rules", to_apply);

  if(to_apply && rules_to_apply == 0)
    apply_pending_since = now;

  rules_to_apply += to_apply;
  last_rules_update = now;
}

/* *********************************************************** */

static int garbage_collect(time_t idle_for) {
  ruleshash_t *hash;
  int i;
  time_t older_than;
  remove_rules_callback_data_t user_data;
  u_int64_t to_apply = 0;

#ifdef DEBUG
  traceEvent(TRACE_DEBUG, "Garbage collecting...");
#endif

  for (i = 0; i < MAX_NUM_PORTS*2; i++) {
    hash = &hashes[i];
    older_than = time(0) - idle_for;
    user_data.rc = 0;
    user_data.matched_rules = 0;
    user_data.older_than = older_than;
    user_data.filter_type = hash_idx_to_filter_type(i);

#ifndef RRC_TEST_ON
    user_data.port = hash_idx_to_port(i);

    if (user_data.port == NULL) {
      traceEvent(TRACE_ERROR, "Invalid rrc_port_get(%d) response, this should never happen here", i);
      //return 1;
    }
#else
    user_data.port = i;
#endif

    if (user_data.port != NULL) {
      rules_hash_walk(hash, garbage_collect_callback, &user_data);
      to_apply += user_data.matched_rules;

      if (user_data.rc != 0)
        return 1;
    }
  }

  /* NOTE: currently apply is necessary after remove to avoid rule apply issues */
#ifndef RRC_TEST_ON
  if (apply_rules(1) == -1)
    return 1;
#endif
  to_apply = 0;

  /* NOTE: this is only necessary if the above apply_rules will be removed */
#if 0
  if(to_apply != 0)
    defer_apply(to_apply);
#endif

  return 0;
}

/* *********************************************************** */
 
static void show_rrc_rules(nbroker_command_t *cmd, char *rsp, size_t rsp_size) {
  rrc_port_t *port;
  int main_port, steer_port;  
  rrc_filter_type_t filter_type = (cmd->action.policy == RRC_POLICY_STEER) ? INGRESS_TRAFFIC : EGRESS_TRAFFIC;

  translate_symbolic_ports(filter_type, cmd->action.port, cmd->action.redirectionPort, &main_port, &steer_port);

  if((port = rrc_port_get(main_port)) == NULL) {
    snprintf(rsp, rsp_size, "Failure retrieving port number for interface %s", cmd->list_rules.port);
    return;
  }

  rrc_dump_rules(port, filter_type);
  
#if 0
  {
    nbroker_list_rules(rrc, dev->get_name(), NBROKER_TYPE_FILTERING, &num_rules, &rules_list);
    
    if(rules_list) {
      qsort(rules_list, num_rules, sizeof(nbroker_rule_t), ruleSorter);

      for(u_int32_t i = 0; i < num_rules; i++) {
	char rulebuf[256], buf1[32], buf2[32], shost[64], dhost[64], sport[32], dport[32], protobuf[32];

	if(rules_list[i].match.shost.host.v4 == 0)
	  snprintf(shost, sizeof(shost), "any");
	else
	  snprintf(shost, sizeof(shost), "%s/%s",
		   intoaV4(rules_list[i].match.shost.host.v4, buf1, sizeof(buf1)),
		   intoaV4(rules_list[i].match.shost.mask.v4, buf2, sizeof(buf2)));

	if(rules_list[i].match.dhost.host.v4 == 0)
	  snprintf(dhost, sizeof(dhost), "any");
	else
	  snprintf(dhost, sizeof(dhost), "%s/%s",
		   intoaV4(rules_list[i].match.dhost.host.v4, buf1, sizeof(buf1)),
		   intoaV4(rules_list[i].match.dhost.mask.v4, buf2, sizeof(buf2)));

	if(rules_list[i].match.sport.low == 0)
	  snprintf(sport, sizeof(sport), "any");
	else if(rules_list[i].match.sport.low != rules_list[i].match.sport.high)
	  snprintf(sport, sizeof(sport), "%u-%u", ntohs(rules_list[i].match.sport.low), ntohs(rules_list[i].match.sport.high));
	else
	  snprintf(sport, sizeof(sport), "%u", ntohs(rules_list[i].match.sport.low));

	if(rules_list[i].match.dport.low == 0)
	  snprintf(dport, sizeof(dport), "any");
	else if(rules_list[i].match.dport.low != rules_list[i].match.dport.high)
	  snprintf(dport, sizeof(dport), "%u-%u", ntohs(rules_list[i].match.dport.low), ntohs(rules_list[i].match.dport.high));
	else
	  snprintf(dport, sizeof(dport), "%u", ntohs(rules_list[i].match.dport.low));

	switch(rules_list[i].match.proto) {
	case 0:
	  snprintf(protobuf, sizeof(protobuf), "%s", "any");
	  break;
	case 6:
	  snprintf(protobuf, sizeof(protobuf), "%s", "tcp");
	  break;
	case 132:
	  snprintf(protobuf, sizeof(protobuf), "%s", "sctp");
	  break;
	case 17:
	  snprintf(protobuf, sizeof(protobuf), "%s", "udp");
	  break;
	default:
	  snprintf(protobuf, sizeof(protobuf), "%d", rules_list[i].match.proto);
	  break;
	}

	snprintf(rulebuf, sizeof(rulebuf), "%s %s:%s -> %s:%s",
		 protobuf, shost, sport, dhost, dport);

	snprintf(buf, sizeof(buf), "%-6s %-6u %-6s %-32s\n",
		 dev->get_name(), rules_list[i].rule_id, "Filter", rulebuf);
	session->send_data(buf, strlen(buf));
      }

      free(rules_list);
    }
  }
#endif
          
  
  snprintf(rsp, rsp_size, "Hello (%d)", (int)rsp_size);
}

/* *********************************************************** */

static nbroker_rc_t process_command(nbroker_command_t *cmd, char *buf, size_t buf_size, int is_binary) {
  int main_port, steer_port;
  int64_t rc;
  rrc_port_t *port;
  ruleshash_t *hash;
  u_int64_t to_apply = 0;
  nbroker_rc_t command_rv = NBROKER_RC_OK;

  traceEvent(TRACE_DEBUG, "Processing command [%d]", cmd->type);

  switch (cmd->type) {
    case RRC_RULE_TYPE_ACTION: {

#ifdef DEBUG
       traceEvent(TRACE_DEBUG, "Type = ACTION");
#endif

       /* TODO reorganize */
       rrc_filter_type_t filter_type;

      if((cmd->action.type == RRC_ACTION_SET_DEFAULT) || (cmd->action.type == RRC_ACTION_SET)) {
        filter_type = (cmd->action.policy == RRC_POLICY_STEER) ? INGRESS_TRAFFIC : EGRESS_TRAFFIC;
        translate_symbolic_ports(filter_type, cmd->action.port, cmd->action.redirectionPort, &main_port, &steer_port);

#ifndef RRC_TEST_ON
        if((port = rrc_port_get(main_port)) == NULL)
          return send_invalid_device_port(buf, buf_size, is_binary);
#endif

        if(cmd->action.type == RRC_ACTION_SET_DEFAULT)
          cmd->ruleNumber = DEFAULT_RULE_ID;

        hash = get_port_hash(main_port, filter_type);
      }


      switch (cmd->action.type) {
        case RRC_ACTION_SET_DEFAULT:
#ifdef DEBUG
          traceEvent(TRACE_DEBUG, "Action.Type = SET_DEFAULT");
#endif
#ifndef RRC_TEST_ON
          if(rrc_add_default_rule(port, filter_type, command_to_rrc_policy(cmd->action.policy), steer_port) == -1)
            return send_command_set_error(buf, buf_size, is_binary);
#endif
          to_apply++;
          command_rv = send_ok_code(buf, buf_size, is_binary, 0);
          break;

        case RRC_ACTION_SET: {
          u_int32_t rule_id = cmd->ruleNumber;
#ifdef DEBUG
          traceEvent(TRACE_DEBUG, "Action.Type = SET");
#endif

          rc = rules_hash_set(hash, &cmd->action.match, &rule_id, cmd->action.policy, steer_port);

          if(rc < 0)
            return send_return_code(NBROKER_RC_INTERNAL_ERROR, strerror(-rc), buf, buf_size, is_binary, 0);

          if (rc != 0) { /* Rule is not there or should be updated */

            if (rc == 2) { /* Rule should be updated, something has changed */

              traceEvent(TRACE_INFO, "Removing rule %d to insert the new one", rule_id);

#ifndef RRC_TEST_ON
              if(rrc_remove_rule(port, rule_id, filter_type) == -1)
                return send_command_set_error(buf, buf_size, is_binary);

              /* NOTE: currently apply is necessary after remove to avoid rule apply issues */
              if (apply_rules(1) == -1)
                return send_command_set_error(buf, buf_size, is_binary);
#endif
              to_apply = 0;
            }

#ifndef RRC_TEST_ON
            if (rrc_add_rule(port, rule_id, filter_type, &cmd->action.match, command_to_rrc_policy(cmd->action.policy), steer_port) == -1) {
              /* Failure adding rule, removing also from hash */
              rules_hash_delete(hash, &cmd->action.match, rule_id);
              return send_command_set_error(buf, buf_size, is_binary);
            }
#endif
            to_apply++;
          }

          command_rv = send_ok_code(buf, buf_size, is_binary, 1);

          /* Send the rule_id */
          if (is_binary) {
            zmq_send(zmq_responder, (char *) &rule_id, sizeof(rule_id), 0);
          } else {
            char msg[32];
            snprintf(msg, sizeof(msg), "Rule ID = %d", rule_id);
            zmq_send(zmq_responder, msg, strlen(msg) + 1, 0);
          }

          break;
        }

        case RRC_ACTION_DELETE:
#ifdef DEBUG
          traceEvent(TRACE_DEBUG, "Action.Type = DELETE");
#endif
          filter_type = get_filter_type(cmd->filter_type);
          translate_symbolic_ports(filter_type, cmd->action.port, 0, &main_port, &steer_port);

#ifndef RRC_TEST_ON
          if((port = rrc_port_get(main_port)) == NULL)
            return send_invalid_device_port(buf, buf_size, is_binary);
#endif

          hash = get_port_hash(main_port, filter_type);
          rc = rules_hash_delete(hash, &cmd->action.match, cmd->ruleNumber);

          if(rc <= 0) {
            if(rc < 0)
              return send_return_code(NBROKER_RC_INTERNAL_ERROR, strerror(-rc), buf, buf_size, is_binary, 0);
            else
              return send_return_code(NBROKER_RC_RULE_NOT_FOUND, "Rule not found", buf, buf_size, is_binary, 0);
          }

#ifndef RRC_TEST_ON
          if(rrc_remove_rule(port, rc, filter_type) == -1)
            return send_command_set_error(buf, buf_size, is_binary);

          /* NOTE: currently apply is necessary after remove to avoid rule apply issues */
          if(apply_rules(1) == -1)
             return send_command_set_error(buf, buf_size, is_binary);
#endif
          to_apply = 0;

          // to_apply++;

          command_rv = send_ok_code(buf, buf_size, is_binary, 0);
          break;
	  
      case RRC_ACTION_APPLY:
	if(apply_rules(0) == -1)
	  return send_command_set_error(buf, buf_size, is_binary);
	else
	  command_rv = send_ok_code(buf, buf_size, is_binary, 0);
	break;
	    
        default:
          traceEvent(TRACE_ERROR, "Invalid action type %d", cmd->action.type);
          return send_return_code(NBROKER_RC_SYNTAX_ERROR, "Invalid action type", buf, buf_size, is_binary, 0);
      }

      break;
    } case RRC_RULE_TYPE_STATS:
#ifdef DEBUG
       traceEvent(TRACE_DEBUG, "Type = STATS");
#endif
       {
	 char rsp[4096];

	 show_rrc_rules(cmd, rsp, sizeof(rsp));
	 return send_return_code(NBROKER_RC_OK, rsp, buf, buf_size, 0, 0);
       }

    case RRC_RULE_TYPE_SYNC:
#ifdef DEBUG
       traceEvent(TRACE_DEBUG, "Type = SYNC");
#endif
      if(apply_rules(0) == -1)
        return send_command_set_error(buf, buf_size, is_binary);
      to_apply = 0;
      command_rv = send_ok_code(buf, buf_size, is_binary, 0);
      break;

    case RRC_RULE_TYPE_GARBAGE_COLLECT:
#ifdef DEBUG
       traceEvent(TRACE_DEBUG, "Type = GARBAGE_COLLECT");
#endif
      if(garbage_collect(cmd->gc.idle_for ? cmd->gc.idle_for : DEFAULT_IDLE_PURGE_SECONDS) != 0)
        return send_command_set_error(buf, buf_size, is_binary);

      to_apply = 0;
      command_rv = send_ok_code(buf, buf_size, is_binary, 0);
      break;

    case RRC_RULE_TYPE_AUTO_GARBAGE_COLLECT:
#ifdef DEBUG
       traceEvent(TRACE_DEBUG, "Type = AUTO_GARBAGE_COLLECT");
#endif
      auto_garbage_collect_idle_for = cmd->gc.idle_for;
      command_rv = send_ok_code(buf, buf_size, is_binary, 0);
      break;

    case RRC_RULE_TYPE_LIST_RULES:
#ifdef DEBUG
       traceEvent(TRACE_DEBUG, "Type = LIST_RULES");
#endif
      translate_symbolic_ports(get_filter_type(cmd->filter_type), cmd->list_rules.port, 0, &main_port, &steer_port);

#ifndef RRC_TEST_ON
      if((port = rrc_port_get(main_port)) == NULL)
        return send_invalid_device_port(buf, buf_size, is_binary);
#endif

      hash = get_port_hash(main_port, get_filter_type(cmd->filter_type));

      command_rv = send_ok_code(buf, buf_size, is_binary, 1);

      if (is_binary) {
        nbroker_command_rules_result_t res;
        res.num_rules = hash->num_rules;

        rc = zmq_send(zmq_responder, (char*)&res, sizeof(res), ZMQ_SNDMORE);

        if (rc != sizeof(res))
          traceEvent(TRACE_ERROR, "zmq_send failure: %s", strerror(errno));

        rules_hash_walk(hash, send_rules_list_binary_callback, NULL);
      
        send_ok_code(buf, buf_size, is_binary, 0);
      } else {
        snprintf(buf, buf_size, "%d rules", hash->num_rules);
        zmq_send(zmq_responder, buf, strlen(buf) + 1, ZMQ_SNDMORE);

        snprintf(buf, buf_size, "%s", "");
        zmq_send(zmq_responder, buf, strlen(buf) + 1, ZMQ_SNDMORE);

        rules_hash_walk(hash, send_rules_list_callback, NULL);

        snprintf(buf, buf_size, "%s", "");
        zmq_send(zmq_responder, buf, strlen(buf) + 1, 0);
      }

      break;

    case RRC_RULE_TYPE_IFNAME_TO_INTERNAL:
    case RRC_RULE_TYPE_IFNAME_TO_EXTERNAL:
#ifdef DEBUG
       traceEvent(TRACE_DEBUG, "Type = IFNAME_TO_*");
#endif
      if(! is_binary)
        return send_unsupported_mode(buf, buf_size, is_binary);

      main_port = rrc_ifname_to_phys_port(cmd->ifname_to_port.port);

      if(cmd->type == RRC_RULE_TYPE_IFNAME_TO_EXTERNAL)
        main_port = rrc_get_external_phys_port(main_port);

      if(main_port == -1)
        return send_invalid_device_port(buf, buf_size, is_binary);

      traceEvent(TRACE_INFO, "Get %s port: %d", (cmd->type == RRC_RULE_TYPE_IFNAME_TO_EXTERNAL) ? "external" : "internal", main_port);

      command_rv = send_ok_code(buf, buf_size, is_binary, 1);

      if(is_binary) {
        nbroker_command_port_conversion_result_t res;
        res.port = main_port;

        zmq_send(zmq_responder, (char*)&res, sizeof(res), 0);
      }

      break;
    case RRC_RULE_TYPE_RESET_RULES:
#ifdef DEBUG
       traceEvent(TRACE_DEBUG, "Type = RESET_RULES");
#endif
      translate_symbolic_ports(get_filter_type(cmd->filter_type), cmd->reset_rules.port, 0, &main_port, &steer_port);

#ifndef RRC_TEST_ON
      port = rrc_port_get(main_port);

      if(port == NULL)
        return send_invalid_device_port(buf, buf_size, is_binary);

      /* note: no further apply is needed */
      if(rrc_remove_all_rules(port, get_filter_type(cmd->filter_type)) == -1)
        return send_command_set_error(buf, buf_size, is_binary);
#endif

      hash = get_port_hash(main_port, get_filter_type(cmd->filter_type));
      rules_hash_clear(hash);

      command_rv = send_ok_code(buf, buf_size, is_binary, 0);
      break;

    default:
      traceEvent(TRACE_ERROR, "Invalid command type %d", cmd->type);
      return send_return_code(NBROKER_RC_SYNTAX_ERROR, "Invalid command", buf, buf_size, is_binary, 0);
  }

  if(to_apply != 0)
    defer_apply(to_apply);

  return command_rv;
}

/* *********************************************************** */

static void rrc_rule_host_to_str(const rrc_network_t *host, const char *host_s, char *buf, size_t bufsize) {
  size_t cursize = 0;
  char hostbuf[64];

  snprintf(buf + cursize, bufsize - cursize, "%s ", host_s);
  cursize = strlen(buf);
  snprintf(buf + cursize, bufsize - cursize, "%s netmask ", utils_hosttoa(&host->host, host->ip_version, hostbuf, sizeof(hostbuf)));
  cursize = strlen(buf);
  snprintf(buf + cursize, bufsize - cursize, "%s", utils_hosttoa(&host->mask, host->ip_version, hostbuf, sizeof(hostbuf)));
}

/* *********************************************************** */

static void rrc_rule_port_to_str(const rrc_port_range_t *port, const char *port_s, char *buf, size_t bufsize) {
  size_t cursize = 0;

  if(port->high)
    snprintf(buf + cursize, bufsize - cursize, "%s portrang %d-%d", port_s, ntohs(port->low), ntohs(port->high));
  else
    snprintf(buf + cursize, bufsize - cursize, "%s %d", port_s, ntohs(port->low));
}

/* *********************************************************** */

static void rrc_rule_mac_to_str(const u_int8_t *mac, const char *mac_s, char *buf, size_t bufsize) {
  size_t cursize = 0;

  snprintf(buf + cursize, bufsize - cursize, "%s ", mac_s);
  cursize = strlen(buf);
  utils_mactoa(mac, buf + cursize, bufsize - cursize);
}

/* *********************************************************** */

static void rrc_rule_to_str(const ruleshash_key *key, ruleshash_data *data, char *buf, size_t bufsize) {
  const rrc_match_t *match = key;
  static u_int8_t empty_mac[6] = {0};
  char *proto;
  size_t cursize = 0;

  snprintf(buf + cursize, bufsize - cursize, "rule %d", data->rule_id);
  cursize = strlen(buf);
  snprintf(buf + cursize, bufsize - cursize, " ");
  cursize = strlen(buf);

  if(memcmp(match->smac, empty_mac, 6) != 0) {
    rrc_rule_mac_to_str(match->smac, "smac", buf + cursize, bufsize - cursize);
    cursize = strlen(buf);
    snprintf(buf + cursize, bufsize - cursize, " ");
    cursize = strlen(buf);
  }

  if(memcmp(match->dmac, empty_mac, 6) != 0) {
    rrc_rule_mac_to_str(match->dmac, "dmac", buf + cursize, bufsize - cursize);
    cursize = strlen(buf);
    snprintf(buf + cursize, bufsize - cursize, " ");
    cursize = strlen(buf);
  }

  if(match->proto) {
    switch (match->proto) {
      case 6: proto = "tcp"; break;
      case 17: proto = "udp"; break;
      case 132: proto = "sctp"; break;
      default: proto = "";
    }

    if(proto[0])
      snprintf(buf + cursize, bufsize - cursize, "%s", proto);
    else
      snprintf(buf + cursize, bufsize - cursize, "%d", match->proto);

    cursize = strlen(buf);
    snprintf(buf + cursize, bufsize - cursize, " ");
    cursize = strlen(buf);
  }

  if(match->vlan_id) {
    snprintf(buf + cursize, bufsize - cursize, "vlan %d", ntohs(match->vlan_id));
    cursize = strlen(buf);
    snprintf(buf + cursize, bufsize - cursize, " ");
    cursize = strlen(buf);
  }

  if(match->shost.ip_version) {
    rrc_rule_host_to_str(&match->shost, "shost", buf + cursize, bufsize - cursize);
    cursize = strlen(buf);
    snprintf(buf + cursize, bufsize - cursize, " ");
    cursize = strlen(buf);
  }

  if(match->dhost.ip_version) {
    rrc_rule_host_to_str(&match->dhost, "dhost", buf + cursize, bufsize - cursize);
    cursize = strlen(buf);
    snprintf(buf + cursize, bufsize - cursize, " ");
    cursize = strlen(buf);
  }

  if(match->sport.low) {
    rrc_rule_port_to_str(&match->sport, "sport", buf + cursize, bufsize - cursize);
    cursize = strlen(buf);
    snprintf(buf + cursize, bufsize - cursize, " ");
    cursize = strlen(buf);
  }

  if(match->dport.low) {
    rrc_rule_port_to_str(&match->dport, "dport", buf + cursize, bufsize - cursize);
    cursize = strlen(buf);
    snprintf(buf + cursize, bufsize - cursize, " ");
    cursize = strlen(buf);
  }

  if(data->policy == RRC_POLICY_PASS)
    snprintf(buf + cursize, bufsize - cursize, "pass");
  else if(data->policy == RRC_POLICY_DROP)
    snprintf(buf + cursize, bufsize - cursize, "drop");
  else if(data->policy == RRC_POLICY_STEER)
    snprintf(buf + cursize, bufsize - cursize, "steer-to %d", data->redirectionPort);

}

/* *********************************************************** */

static nbroker_rc_t handle_request(nbroker_command_t *cmd, char *errbuf, size_t errbuf_size, int is_binary) {
  nbroker_rc_t rc;
  char reply[256];
#ifdef DEBUG
  struct timeval start, end;
  double msec;
#endif

  if(!cmd) {
    traceEvent(TRACE_DEBUG, "Error reading command");
    send_return_code(NBROKER_RC_SYNTAX_ERROR, errbuf, reply, sizeof(reply), is_binary, 0);
    return NBROKER_RC_SYNTAX_ERROR;
  }

#ifdef DEBUG
  gettimeofday(&start, NULL);
#endif

  rc = process_command(cmd, reply, sizeof(reply), is_binary);

#ifdef DEBUG
  gettimeofday(&end, NULL);
  msec = delta_msec(&end, &start);
  traceEvent(TRACE_DEBUG, "Command execution time: %f msec", msec);
#endif

  free(cmd);
  return rc;
}

/* *********************************************************** */

static void signal_handler(int signal) {
  traceEvent(TRACE_NORMAL, "Terminating... [signal: %u]", signal);
  running = 0;
}

/* *********************************************************** */

static int setup_signal_handlers() {
  struct sigaction sa;

  sa.sa_handler = signal_handler;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask); /* Necessary for ZMQ */

  if (sigaction(SIGINT, &sa, NULL) == -1) {
    traceEvent(TRACE_ERROR, "sigaction(SIGINT) error");
    return -errno;
  }

  if (sigaction(SIGTERM, &sa, NULL) == -1) {
    traceEvent(TRACE_ERROR, "sigaction(SIGTERM) error");
    return -errno;
  }

  if (sigaction(SIGHUP, &sa, NULL) == -1) {
    traceEvent(TRACE_ERROR, "sigaction(SIGHUP) error");
    return -errno;
  }

  signal(SIGPIPE, SIG_IGN);

  return 0;
}

/* ****************************************************** */

static void housekeeping() {
  if((auto_garbage_collect_idle_for != 0) && (time(0) % auto_garbage_collect_idle_for == 0))
    garbage_collect(auto_garbage_collect_idle_for);

  if(periodic_apply() == -1)
    traceEvent(TRACE_ERROR, "Rules apply error");
}

/* ****************************************************** */

int run() {
  int rv;
  char msg_buf[512] = {0}; /* FIXME: this buffer should be a per-client buffer to avoid issues on partial reads in text mode */
  char errbuf[128];
  nbroker_command_t *command;
  int is_binary;
  u_int32_t flags = 0;

  memset(hashes, 0, sizeof(hashes));

  if (init_zmq() < 0)
    return -1;

  if ((rv = setup_signal_handlers()) < 0) {
    traceEvent(TRACE_ERROR, "Cannot setup signal handlers");
    return rv; 
  }

#ifndef RRC_TEST_ON
  /* TEST (remove this) */
#ifdef ENABLE_PORTMASK
  flags |= RRC_INIT_FLAG_PORTMASK;
#endif

  if (rrc_config_file != NULL)
    setenv("FM_LIBERTY_TRAIL_CONFIG_FILE", rrc_config_file, 0);

  traceEvent(TRACE_NORMAL, "RRC initialization..");

  if (rrc_init(flags) != 0) {
    traceEvent(TRACE_ERROR, "Cannot initialize the RRC device");
    return -1;
  }
#endif
  
  traceEvent(TRACE_NORMAL, "RRC successfully initialized. Accepting commands");
  broker_ready = 1;

  last_rules_update = apply_pending_since = time(0);

  while(running) {
    command = NULL;

    if ((receive_command(&command, msg_buf, sizeof(msg_buf), errbuf, sizeof(errbuf), &is_binary) >= 0) && (command != NULL)) {
      handle_request(command, errbuf, sizeof(errbuf), is_binary);
    }

    housekeeping();
  }

  term_zmq();

  return 0;
}

/* ****************************************************** */

static const struct option long_options[] = {
  { "rrc-config-file",             required_argument, NULL, 'c' },
  { "daemon",                      no_argument,       NULL, 'd' },
  { "trace-log",                   required_argument, NULL, 't' },
  { "verbose",                     required_argument, NULL, 'v' },
  { "help",                        no_argument,       NULL, 'h' },
  { NULL,                          no_argument,       NULL,  0  }
};

/* ****************************************************** */

static void help(void) {
  printf("nbrokerd - Copyright 2017-2018 ntop.org\n\n");
  printf("Usage: nbrokerd -h\n\n");
  printf("[--rrc-config-file|-c <path>]               | RRC configuration file\n");
  printf("[--trace-log|-t <path>]                     | Trace log file\n");
  printf("[--verbose|-v <level>]                      | Verbosity level (0: Error, 2: Normal, 4: Debug)\n");
  printf("[--help|-h]                                 | Help\n");
  printf("\n");
  exit(0);
}

/* ****************************************************** */

int main(int argc, char *argv[]) {
  u_char c;
  int opt_argc;
  char **opt_argv;
  int rc;
  FILE *trace_file;
  int verbosity = 2;

  if (argc == 2 && argv[1][0] != '-') { /* configuration file */
    if (file2argv(argv[0], argv[1], &opt_argc, &opt_argv) < 0)
      return -1;
  } else { /* command line */
    opt_argc = argc;
    opt_argv = argv;
  }

  while ((c = getopt_long(opt_argc, opt_argv, "c:dhv:t:", long_options, NULL)) != 255) {
    switch (c) {
      case 'c':
        rrc_config_file = strdup(optarg);
      break;
      case 'd':
        daemon_mode = 1;
      break;
      case 't':
        trace_file = fopen(optarg, "w");
        if (trace_file == NULL) {
          traceEvent(TRACE_WARNING, "Unable to open log file %s", optarg);
        } else {
          setTraceFile(trace_file);
          rrc_set_log_file(trace_file);
        }
      case 'v':
        verbosity = atoi(optarg);
      break;
      case 'h':
      default:
        help();
      break;
    }
  }

  setTraceLevel(verbosity);
  rrc_set_log_level(verbosity);

  if (daemon_mode)
    daemonize();

  traceEvent(TRACE_NORMAL, "Welcome to nbrokerd");
  
  rc = run();

  return rc;
}

/* *********************************************************** */

