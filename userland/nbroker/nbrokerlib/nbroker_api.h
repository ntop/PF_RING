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

#ifndef NBROKER_API
#define NBROKER_API

/**
 * @file nbroker_api.h
 *
 * @brief      nBroker C API header file.
 */

#include <net/if.h>

#include "rrc.h"

/* This can be used in place of the rule_id parameters to enable automatic rule assignment */
#define NBROKER_AUTO_RULE_ID 0

#define NBROKER_FLAGS_FAST     (1 <<  0) /**< nbroker_init() flag: use best-effort rules insert for best insert performance (it does not return errors or the rule id) */

/* ************************************************************* */

typedef enum {
  NBROKER_RC_OK = 0,
  NBROKER_RC_INTERNAL_ERROR,             /* a generic error */
  NBROKER_RC_SYNTAX_ERROR,
  NBROKER_RC_UNSUPPORTED_MODE,           /* the command is not supported in the current text/binary mode */
  NBROKER_RC_INVALID_DEVICE_PORT,
  NBROKER_RC_INVALID_REDIRECTION_PORT,
  NBROKER_RC_RULE_NOT_FOUND,
  NBROKER_RC_RULE_EXISTS,
  NBROKER_RC_DEVICE_COMMAND_ERROR,       /* an error occurred while setting the command on the physical device */
  NBROKER_RC_BAD_BINARY_VERSION,
  NBROKER_RC_CONNECTION_ERROR,
  NBROKER_RC_BUSY,
} nbroker_rc_t;

typedef struct {
  u_int8_t binary_mark;
  u_int8_t binary_version;
} __attribute__((packed))
nbroker_command_header_t;

/* ************************************************************* */

typedef enum {
  NBROKER_POLICY_DROP,
  NBROKER_POLICY_PASS
} nbroker_policy_t;

typedef enum {
  NBROKER_TYPE_FILTERING,
  NBROKER_TYPE_STEERING
} nbroker_filter_type_t;

typedef struct {
  u_int32_t rule_id;          /**< The rule id */
  rrc_match_t match;      /**< The match filter */
  union {
    nbroker_policy_t policy;  /**< The rule policy, only used in filtering rules */
    u_int8_t steer_to;        /**< The redirection port, only used in steering rules */
  } u;
} nbroker_rule_t;

#define CMD_QUEUE_ITEMS 1024 /* pow of 2 */
#define CMD_QUEUE_ITEMS_MASK (CMD_QUEUE_ITEMS - 1)

typedef enum {
  CMD_SET_RULE = 0
} cmd_type_t;

typedef struct {
  cmd_type_t type;
  struct {
    char port[IFNAMSIZ];
    nbroker_filter_type_t type;
    u_int32_t rule_id;
    rrc_match_t match;
    nbroker_policy_t policy;
    char redirectionPort[IFNAMSIZ];
  } rule;
} cmd_desc_t;

typedef struct {
  u_int64_t head;
  u_int64_t tail;
  cmd_desc_t desc[CMD_QUEUE_ITEMS];
} cmd_queue_t;

typedef struct nbroker {
  void *zmq_context, *zmq_requester;
  int breakloop;
  u_int32_t flags;
  pthread_t cmdqthread;
  cmd_queue_t cmdq;
} nbroker_t;

/* ************************************************************* */

/**
 * Init the broker communication.
 * @param bkr The broker handler (out)
 * @param flags Option flags
 * @return The error code
 */
nbroker_rc_t nbroker_init(nbroker_t **bkr, u_int32_t flags);

/**
 * Terminates the broker communication. The broker object is freed.
 * @param bkr The broker handler
 * @return The error code
 */
nbroker_rc_t nbroker_term(nbroker_t *bkr);

/**
 * Set the default policy.
 * The port parameter can be either the symbolic linux name or the numeric port id.
 * @param bkr The broker handler
 * @param port The target port number or interface name
 * @param policy The default policy 
 * @return The error code
 */
nbroker_rc_t nbroker_set_default_policy(nbroker_t *bkr, const char *port, nbroker_policy_t policy);

/**
 * Apply pending rules (if any)
 * @param bkr The broker handler
 * @return The error code
 */
nbroker_rc_t nbroker_apply_pending_rules(nbroker_t *bkr);

/**
 * Set the default port redirection.
 * The port parameter can be either the symbolic linux name or the numeric port id.
 * @param bkr The broker handler
 * @param port The target port number or interface name 
 * @param steer_to The default destination port number or interface name
 * @return The error code
 */
nbroker_rc_t nbroker_set_default_steering(nbroker_t *bkr, const char *port, const char *steer_to);

/**
 * Set a filtering rule for the specified match.
 * On success, the rule_id will contain the newly set rule id.
 * @param bkr The broker handler
 * @param port The target port number or interface name 
 * @param rule_id The rule id. Use NBROKER_AUTO_RULE_ID as rule_id to use the internal rule id management (in/out)
 * @param match The rule to match
 * @param policy The policy
 * @return The error code
 */
nbroker_rc_t nbroker_set_filtering_rule(nbroker_t *bkr, const char *port,
      u_int32_t *rule_id, const rrc_match_t *match, nbroker_policy_t policy);

/**
 * Set a port redirection rule for the specified match.
 * @param bkr The broker handler
 * @param port The target port number or interface name 
 * @param rule_id The rule id. Use NBROKER_AUTO_RULE_ID as rule_id to use the internal rule id management. On success, the rule_id will contain the newly set rule id (in/out). 
 * @param match The rule to match
 * @param steer_to The destination port number or interface name 
 * @return The error code
 */
nbroker_rc_t nbroker_set_steering_rule(nbroker_t *bkr, const char *port,
      u_int32_t *rule_id, const rrc_match_t *match, const char *steer_to);

/**
 * Remove a rule by its rule id.
 * @param bkr The broker handler
 * @param port The target port number or interface name 
 * @param rule_id The rule id
 * @param filter_type The filter type 
 * @return The error code
 */
nbroker_rc_t nbroker_remove_rule_by_id(nbroker_t *bkr, const char *port,
      u_int32_t rule_id, nbroker_filter_type_t filter_type);

/**
 * Remove the first rule matching the specifed match.
 * @param bkr The broker handler
 * @param port The target port number or interface name 
 * @param match The rule to match
 * @param filter_type The filter type 
 * @return The error code
 */
nbroker_rc_t nbroker_remove_rule_by_match(nbroker_t *bkr, const char *port,
      const rrc_match_t *match, nbroker_filter_type_t filter_type);

/**
 * List the active rules of the specified type and port
 * @param bkr The broker handler
 * @param port The target port number or interface name 
 * @param filter type The filter type to filter rules by type 
 * @param num_rules The number of rules (out)
 * @param rules The rules list (out)
 * @return The error code
 */
nbroker_rc_t nbroker_list_rules(nbroker_t *bkr, const char *port,
      nbroker_filter_type_t filter_type, u_int32_t *num_rules, nbroker_rule_t **rules);

/**
 * Reset all the rules of the specified type on the specified port.
 * Note: the default rules are not affected
 * @param bkr The broker handler
 * @param port The target port number or interface name 
 * @param filter_type The filter type 
 * @return The error code
 */
nbroker_rc_t nbroker_reset_rules(nbroker_t *bkr, const char *port, nbroker_filter_type_t filter_type);

/**
 * Purge the rules which have been set more than idle_for seconds ago.
 * @param bkr The broker handler
 * @param idle_for The idle time (sec). Pass 0 for automatic purge.
 * @return The error code
 */
nbroker_rc_t nbroker_purge_idle_rules(nbroker_t *bkr, u_int32_t idle_for);

/**
 * Enable old rules auto-purge. Periodically, rules older than idle_for will be
 * purged.
 * @param bkr The broker handler
 * @param idle_for The idle time (sec). Pass 0 to disable automatic purge.
 * @return The error code
 */
nbroker_rc_t nbroker_set_auto_purge(nbroker_t *bkr, u_int32_t idle_for);

/**
 * Converts a linux interface name to the internal (pci) port index of the device.
 * @param bkr The broker handler
 * @param ifname The interface name
 * @param port The internal port number of the RRC switch bound to the specified interface (out)
 * @return The error code
 */
nbroker_rc_t nbroker_ifname_to_internal_port(nbroker_t *bkr, const char *ifname, u_int8_t *port);

/**
 * Converts a linux interface name to the external port index of the device.
 * @param bkr The broker handler
 * @param ifname The interface name
 * @param port The external port number of the RRC switch bound to the specified interface (out)
 * @return The error code
 */
nbroker_rc_t nbroker_ifname_to_external_port(nbroker_t *bkr, const char *ifname, u_int8_t *port);

/**
 * Parses a rule in the broker BPF syntax and produce a rrc_match_t structure.
 * NOTE: a mutex is aquired while performing grammar parsing.
 * @param rule The BPF filter
 * @return NULL on error, the rrc_match_t rule otherwise (it must be freed by the caller)
 */
rrc_match_t* nbroker_parse_rule(const char *rule);

/* TODO
 * nbroker_rc_t nbroker_get_port_stats(const char *port, nbroker_stats_t *stats);
 * nbroker_rc_t nbroker_get_rule_stats(const char *port, u_int32_t rule_id, nbroker_stats_t *stats);
 */

#endif
