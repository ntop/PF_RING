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

#ifndef COMMON_UTILS_H
#define COMMON_UTILS_H

#include <stdio.h>
#include <stdlib.h>

#include "nbroker_api.h"

//#define DEBUG

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define RRC_ACTION_SET         1
#define RRC_ACTION_DELETE      2
#define RRC_ACTION_SET_DEFAULT 3
#define RRC_ACTION_APPLY       4

#define RRC_POLICY_PASS        1
#define RRC_POLICY_DROP        2
#define RRC_POLICY_STEER       3

#define RRC_RULE_TYPE_ACTION               1
#define RRC_RULE_TYPE_STATS                2
#define RRC_RULE_TYPE_SYNC                 3
#define RRC_RULE_TYPE_GARBAGE_COLLECT      4
#define RRC_RULE_TYPE_LIST_RULES           5
#define RRC_RULE_TYPE_RESET_RULES          6
#define RRC_RULE_TYPE_IFNAME_TO_INTERNAL   7
#define RRC_RULE_TYPE_IFNAME_TO_EXTERNAL   8
#define RRC_RULE_TYPE_AUTO_GARBAGE_COLLECT 9

#define RRC_RULE_FILTERING 1
#define RRC_RULE_STEERING  2

#define RRC_BINARY_MARK    0xEF
#define RRC_BINARY_VERSION 0x01

/* ************************************************************* */

typedef struct {
  u_int8_t type:5 /* RULE_ACTION_* */, policy:3 /* RULE_POLICY_* */;
  char port[IFNAMSIZ];
  char redirectionPort[IFNAMSIZ];
  u_int8_t __padding;
  rrc_match_t match;
} __attribute__((packed))
nbroker_action_command_t;

typedef struct {
  char port[IFNAMSIZ];
} __attribute__((packed))
nbroker_stats_command_t;

typedef struct {
  u_int32_t idle_for;
} __attribute__((packed))
nbroker_gc_command_t;

typedef struct {
  char port[IFNAMSIZ];
} __attribute__((packed))
nbroker_list_rules_command_t;

typedef struct {
  char port[IFNAMSIZ];
} __attribute__((packed))
nbroker_rules_reset_command_t;

typedef struct {
  char port[IFNAMSIZ];
} __attribute__((packed))
nbroker_ifname_to_port_command_t;

typedef struct {
  u_int8_t type:6, filter_type:2 /* RRC_RULE_FILTERING | RRC_RULE_STEERING */;
  u_int8_t __padding[3];
  u_int32_t ruleNumber;

  union {
    nbroker_action_command_t action;
    nbroker_stats_command_t stats;
    nbroker_gc_command_t gc; /* RRC_RULE_TYPE_GARBAGE_COLLECT / RRC_RULE_TYPE_AUTO_GARBAGE_COLLECT */
    nbroker_list_rules_command_t list_rules;
    nbroker_rules_reset_command_t reset_rules;
    nbroker_ifname_to_port_command_t ifname_to_port; /* RRC_RULE_TYPE_IFNAME_TO_INTERNAL / RRC_RULE_TYPE_IFNAME_TO_EXTERNAL */
  };
} __attribute__((packed))
nbroker_command_t;

/* ************************************************************* */

typedef struct {
  u_int8_t return_code;
} __attribute__((packed))
nbroker_command_result_t;

typedef struct {
  u_int32_t num_rules;
} __attribute__((packed))
nbroker_command_rules_result_t;

typedef struct {
  u_int32_t rule_id;
  rrc_match_t match;
  union {
    u_int8_t policy;
    u_int8_t steer_to;
  } u;
} __attribute__((packed))
nbroker_command_rule_t;

typedef struct {
  u_int8_t port;
} __attribute__((packed))
nbroker_command_port_conversion_result_t;

/* ************************************************************* */

#endif
