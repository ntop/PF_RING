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

#ifndef RRC_PARSER_H
#define RRC_PARSER_H

#include <stdio.h>
#include <stdarg.h>

#ifndef WIN32
#include <pthread.h>
#endif

#include "common.h"

typedef struct { 
  void *input_stream;
} rrc_lex_t;

void rrc_action(char *rrc_port);
void rrc_fix_rule(u_int32_t rule_id);
void rrc_action_policy_pass(int pass);
void rrc_action_policy_steer(char *redirection_port);
void rrc_action_type(int action_type);
void rrc_stats(char *rrc_port);
void rrc_sync();
void rrc_gc(u_int32_t idle_for);
void rrc_rules(char *rrc_port);
void rrc_clear(char *rrc_port);
void rrc_src_host(rrc_network_t *host);
void rrc_dst_host(rrc_network_t *host);
void rrc_src_mac(u_char *mac);
void rrc_dst_mac(u_char *mac);
void rrc_dst_port(int port);
void rrc_src_port(int port);
void rrc_src_port_range(int port_from, int port_to);
void rrc_dst_port_range(int port_from, int port_to);
void rrc_set_filtering(int is_filtering);
void rrc_vlan(int vlan_id);
void rrc_protocol(int proto);

void rrc_host(const char *s, rrc_network_t *out);
void rrc_net(const char *net, const char *netmask, int masklen, rrc_network_t *out);
void rrc_net6(const char *net6, int masklen, rrc_network_t *out);

nbroker_command_t* rrc_parse(const char *command, char *err_buf, size_t bufsize);
rrc_match_t* rrc_parse_bpf(const char *bpf, char *err_buf, size_t bufsize);
void rrc_lex_init(rrc_lex_t *, const char *);
void rrc_lex_cleanup(rrc_lex_t *);
void rrc_syntax_error(char * format, ...);

int nblex(void);
int nbparse(void);

int stoi(char *s);
int xdtoi(int c);
#endif /* RRC_PARSER_H */
