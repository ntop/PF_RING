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

#include "parser.h"
#include <ctype.h>
#include "rrc.h"

static u_int32_t errors = 0;
static nbroker_command_t _cmd;
static char *error_buffer = NULL;
static size_t error_buffer_size = 0;

#ifndef WIN32
static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
#endif

static int atoin(const char *s, u_int32_t *addr) {
  u_int n;
  int len;

  *addr = 0;
  len = 0;
  while (1) {
    n = 0;
    while (*s && *s >= '0' && *s <= '9')
      n = n * 10 + *s++ - '0';
    *addr <<= 8;
    *addr |= n & 0xff;
    len += 8;
    if (*s != '.')
      return len;
    ++s;
  }
}

/* ****************************************** */

/* Hex to int */
int xdtoi(int c) {
  if (isdigit(c))
    return c - '0';
  else if (islower(c))
    return c - 'a' + 10;
  else
    return c - 'A' + 10;
}

/* ****************************************** */

/* String to int (atoi with hex '0x' and octal '0' support) */
int stoi(char *s) {
  int base = 10;
  int n = 0;

  if (*s == '0') {
    if (tolower(s[1]) == 'x') {
      base = 16;
      s += 2;
    } else {
      base = 8;
      s += 1;
    }
  }

  while (*s)
    n = n * base + xdtoi(*s++);

  return n;
}

/* ****************************************** */

static struct addrinfo *nametoaddrinfo(const char *name) {
  struct addrinfo hints, *res;
  int rc;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  rc = getaddrinfo(name, NULL, &hints, &res);

  if (rc != 0)
    return NULL;
  
  return res;
}

/* ****************************************** */

void rrc_syntax_error(char *format, ...) {
  va_list va_ap;
  char buf[2048];

  errors++;

  va_start (va_ap, format);
  memset(buf, 0, sizeof(buf));
  vsnprintf(buf, sizeof(buf)-1, format, va_ap);
  while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
  //fprintf(stderr, "Error: %s\n", buf);
  va_end(va_ap);

  if(errors == 1) {
    strncpy(error_buffer, buf, error_buffer_size-1);
    buf[error_buffer_size-1] = '\0';
  }
}

/* ****************************************** */

static void rrc_command_check_action() {
  int match_set;
  rrc_match_t zero_rule;

  memset(&zero_rule, 0, sizeof(zero_rule));
  match_set = (memcmp(&_cmd.action.match, &zero_rule, sizeof(zero_rule)) != 0);
  switch(_cmd.action.type) {
    case RRC_ACTION_SET:
      if (!_cmd.action.port[0]) rrc_syntax_error("Missing RRC port");
      if (!match_set) rrc_syntax_error("Missing match statement");
      if (_cmd.action.policy == 0) rrc_syntax_error("Missing policy");
      if (_cmd.action.policy == RRC_POLICY_STEER && !_cmd.action.redirectionPort[0]) rrc_syntax_error("Missing redirection port");
      break;
    case RRC_ACTION_DELETE:
      if (!_cmd.action.port[0]) rrc_syntax_error("Missing RRC port");
      if (match_set && _cmd.ruleNumber != 0) rrc_syntax_error("Cannot specify both a rule id and a match rule");
      if (!match_set && _cmd.ruleNumber == 0) rrc_syntax_error("A rule id or a match rule must be specified");
      if (_cmd.action.policy) rrc_syntax_error("Unexpected policy");
      if (_cmd.filter_type == 0) rrc_syntax_error("Missing filter type");
      if (_cmd.action.redirectionPort[0]) rrc_syntax_error("Unexpected redirection port");
      break;
    case RRC_ACTION_SET_DEFAULT:
      if (!_cmd.action.port[0]) rrc_syntax_error("Missing RRC port");
      if (_cmd.action.policy == 0) rrc_syntax_error("Missing default policy"); 
      if (_cmd.action.policy == RRC_POLICY_STEER && !_cmd.action.redirectionPort[0]) rrc_syntax_error("Missing redirection port");
      break;
    default:
      rrc_syntax_error("Bad RRC action 0x%x", _cmd.action.type);
  }
}

/* ****************************************** */

static void rrc_command_check_stats() {
  if (_cmd.stats.port == 0) rrc_syntax_error("Missing RRC port");
}

/* ****************************************** */

static void rrc_command_check_sync() {}

/* ****************************************** */

static void rrc_command_check_gc() {}

/* ****************************************** */

static void rrc_command_check_list_rules() {
  if (_cmd.filter_type == 0) rrc_syntax_error("Missing filter type");
}

/* ****************************************** */

static void rrc_command_check_reset_rules() {
  if (_cmd.filter_type == 0) rrc_syntax_error("Missing filter type");
}

/* ****************************************** */

static void rrc_command_checks() {
  if(errors) return;

  switch(_cmd.type) {
    case 0:
      break;
    case RRC_RULE_TYPE_ACTION:
      rrc_command_check_action();
      break;
    case RRC_RULE_TYPE_STATS:
      rrc_command_check_stats();
      break;
    case RRC_RULE_TYPE_SYNC:
      rrc_command_check_sync();
      break;
    case RRC_RULE_TYPE_GARBAGE_COLLECT:
      rrc_command_check_gc();
      break;
    case RRC_RULE_TYPE_LIST_RULES:
      rrc_command_check_list_rules();
      break;
    case RRC_RULE_TYPE_RESET_RULES:
      rrc_command_check_reset_rules();
      break;
    default:
      rrc_syntax_error("Bad RRC command 0x%x", _cmd.type);
  }
}

/* ****************************************** */

static int command_parse(const char *buffer, char *err_buf, size_t bufsize) {
  rrc_lex_t lex;
  memset(&_cmd, 0, sizeof(_cmd));

  rrc_lex_init(&lex, buffer);

  error_buffer = err_buf;
  error_buffer_size = bufsize;

  errors = 0;

  nbparse();

  rrc_command_checks();

  rrc_lex_cleanup(&lex);

  return errors;
}

/* ****************************************** */

void rrc_set_filtering(int is_filtering) {
  if((_cmd.type == RRC_RULE_TYPE_ACTION) && (_cmd.action.type != RRC_ACTION_DELETE))
    rrc_syntax_error("filter type not expected");
  if(_cmd.filter_type)
    rrc_syntax_error("duplicate filter type");

  _cmd.filter_type = is_filtering ? RRC_RULE_FILTERING : RRC_RULE_STEERING;
}

/* ****************************************** */

static void set_host_mask(u_int32_t net, u_int32_t mask, rrc_network_t *out) {
  out->ip_version = 4;
  out->host.v4 = htonl(net);
  out->mask.v4 = htonl(mask);
}

/* ****************************************** */

static nbroker_command_t* __rrc_parse_command_or_bpf(const char *command, char *err_buf, size_t bufsize) {
  int num_errors;

  nbroker_command_t* cmd = (nbroker_command_t*) calloc(sizeof(nbroker_command_t), 1);
  if (cmd == NULL)
    return NULL;

#ifndef WIN32
  pthread_rwlock_wrlock(&lock);
#endif

  num_errors = command_parse(command, err_buf, bufsize);
  memcpy(cmd, &_cmd, sizeof(nbroker_command_t));

#ifndef WIN32
  pthread_rwlock_unlock(&lock);
#endif

  if (num_errors > 0) {
    free(cmd);
    return NULL;
  }

  return cmd;
}

/* ****************************************** */

nbroker_command_t* rrc_parse(const char *command, char *err_buf, size_t bufsize) {
  nbroker_command_t* cmd = __rrc_parse_command_or_bpf(command, err_buf, bufsize);

  if (cmd == NULL)
    return NULL;

  /* Avoid BPF rules only here */
  if (cmd->type == 0) {
    snprintf(err_buf, bufsize, "Invalid BPF command\n");
    return NULL;
  }

  return cmd;
}

/* ****************************************** */

rrc_match_t* rrc_parse_bpf(const char *bpf, char *err_buf, size_t bufsize) {
  rrc_match_t* match;
  nbroker_command_t* cmd = __rrc_parse_command_or_bpf(bpf, err_buf, bufsize);

  if (cmd == NULL)
    return NULL;

  /* BPF rules only here */
  if (cmd->type != 0) {
    snprintf(err_buf, bufsize, "Invalid BPF rule\n");
    free(cmd);
    return NULL;
  }

  match = (rrc_match_t*) malloc(sizeof(rrc_match_t));

  if (match == NULL) {
    free(cmd);
    return NULL;
  }

  *match = cmd->action.match;
  free(cmd);

  return match;
}

/* ****************************************** */

void rrc_host(const char *s, rrc_network_t *out) {
  u_int32_t hh, mask = 0xffffffff;
  int vlen;
 
  vlen = atoin(s, &hh);

  hh <<= 32 - vlen;
  mask <<= 32 - vlen;

  set_host_mask(hh, mask, out);
}

/* ****************************************** */

void rrc_net(const char *net, const char *netmask, 
				 int masklen, rrc_network_t *out) {
  int nlen, mlen;
  u_int32_t nn, mask;

  nlen = atoin(net, &nn);
  nn <<= 32 - nlen;

  if (netmask != NULL) {
    mlen = atoin(netmask, &mask);
    mask <<= 32 - mlen;
    if ((nn & ~mask) != 0)
      rrc_syntax_error("non-network bits set in \"%s mask %s\"", net, netmask);
  } else {
  /* Convert mask len to mask */
    if (masklen > 32)
      rrc_syntax_error("mask length must be <= 32");

    if (masklen == 0)
      mask = 0;
    else
      mask = 0xffffffff << (32 - masklen);

    if ((nn & ~mask) != 0)
      rrc_syntax_error("non-network bits set in \"%s\"", net);
  }

  set_host_mask(nn, mask, out); 
}

/* ****************************************** */

void rrc_net6(const char *net, int masklen, rrc_network_t *out) {
  struct addrinfo *res;
  struct in6_addr *addr;
  struct in6_addr mask;
  u_int32_t *a, *m;

  res = nametoaddrinfo(net);

  if (!res) {
    rrc_syntax_error("invalid ip6 address %s", net);
    return;
  }

  if (res->ai_next)
    rrc_syntax_error("%s resolved to multiple address", net);

  addr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;

  if (sizeof(mask) * 8 < masklen)
    rrc_syntax_error("mask length must be <= %u", (unsigned int)(sizeof(mask) * 8));
  
  memset(&mask, 0, sizeof(mask));
  memset(&mask, 0xff, masklen / 8);
  if (masklen % 8)
    mask.s6_addr[masklen / 8] = (0xff << (8 - masklen % 8)) & 0xff;

  a = (u_int32_t *)addr;
  m = (u_int32_t *)&mask;

  if ((a[0] & ~m[0]) || (a[1] & ~m[1]) || (a[2] & ~m[2]) || (a[3] & ~m[3]))
    rrc_syntax_error("non-network bits set in \"%s/%d\"", net, masklen);

  out->ip_version = 6;
  memcpy(&out->host.v6, a, sizeof(out->host.v6));
  memcpy(&out->mask.v6, m, sizeof(out->mask.v6));

  freeaddrinfo(res);
}

/* ****************************************************** */

static void set_rrc_port(char *field, char *rrc_port) {
  if(field[0]) rrc_syntax_error("duplicate port");
  if(strlen(rrc_port) >= sizeof(_cmd.action.port)) rrc_syntax_error("invalid port name");

  strncpy(field, rrc_port, sizeof(_cmd.action.port));
}

/* ****************************************************** */

void rrc_action(char *rrc_port) {
  set_rrc_port(_cmd.action.port, rrc_port);
}

/* ****************************************************** */

void rrc_fix_rule(u_int32_t rule_id) {
  if(_cmd.ruleNumber != 0)  rrc_syntax_error("Duplicate rule id");
  /* TODO check range - should not be default */
  _cmd.ruleNumber = rule_id;
}

/* ****************************************************** */

void rrc_action_policy_pass(int pass) {
  if(_cmd.action.policy != 0) rrc_syntax_error("Duplicate policy");
  _cmd.action.policy = pass ? RRC_POLICY_PASS : RRC_POLICY_DROP;
}

/* ****************************************************** */

void rrc_action_policy_steer(char *redirection_port) {
  if(_cmd.action.policy != 0) rrc_syntax_error("Duplicate policy");
  _cmd.action.policy = RRC_POLICY_STEER;
  set_rrc_port(_cmd.action.redirectionPort, redirection_port);
}

/* ****************************************************** */

void rrc_action_type(int action_type) {
  _cmd.type = RRC_RULE_TYPE_ACTION;
  _cmd.action.type = action_type;
}

/* ****************************************************** */

void rrc_stats(char *port) {
  _cmd.type = RRC_RULE_TYPE_STATS;
  set_rrc_port(_cmd.stats.port, port);
}

/* ****************************************************** */

void rrc_sync() {
  _cmd.type = RRC_RULE_TYPE_SYNC;
}

/* ****************************************************** */

void rrc_gc(u_int32_t idle_for) {
  _cmd.type = RRC_RULE_TYPE_GARBAGE_COLLECT;
  _cmd.gc.idle_for = idle_for;
}

/* ****************************************************** */

void rrc_rules(char *rrc_port) {
  _cmd.type = RRC_RULE_TYPE_LIST_RULES;
  set_rrc_port(_cmd.list_rules.port, rrc_port);
}

/* ****************************************************** */

void rrc_clear(char *rrc_port) {
  _cmd.type = RRC_RULE_TYPE_RESET_RULES;
  set_rrc_port(_cmd.reset_rules.port, rrc_port);
}

/* ****************************************************** */

void rrc_src_host(rrc_network_t *host) {
  if(_cmd.action.match.shost.ip_version) rrc_syntax_error("Duplicate source host match");
  memcpy(&_cmd.action.match.shost, host, sizeof(_cmd.action.match.shost));
}

/* ****************************************************** */

void rrc_dst_host(rrc_network_t *host) {
  if(_cmd.action.match.dhost.ip_version) rrc_syntax_error("Duplicate destination host match");
  memcpy(&_cmd.action.match.dhost, host, sizeof(_cmd.action.match.dhost));
}

/* ****************************************************** */

static int not_empty_mac(u_char *mac) {
  return mac[0] || mac[1] || mac[2] || mac[3] || mac[4] || mac[5];
}

void rrc_src_mac(u_char *mac) {
  if(not_empty_mac(_cmd.action.match.smac)) rrc_syntax_error("Duplicate source mac match");
  memcpy(_cmd.action.match.smac, mac, sizeof(_cmd.action.match.smac));
}

/* ****************************************************** */

void rrc_dst_mac(u_char *mac) {
  if(not_empty_mac(_cmd.action.match.dmac)) rrc_syntax_error("Duplicate destination mac match");
  memcpy(_cmd.action.match.dmac, mac, sizeof(_cmd.action.match.dmac));
}

/* ****************************************************** */

static int valid_port(int p) {
  return (p>0 && p<65535);
}

/* ****************************************************** */

void rrc_dst_port(int port) {
  if(!valid_port(port)) rrc_syntax_error("Invalid destination port");
  if(_cmd.action.match.dport.low) rrc_syntax_error("Duplicate destination port match");
  _cmd.action.match.dport.low = htons(port);
}

/* ****************************************************** */

void rrc_src_port(int port) {
  if(!valid_port(port)) rrc_syntax_error("Invalid source port");
  if(_cmd.action.match.sport.low) rrc_syntax_error("Duplicate source port match");
  _cmd.action.match.sport.low = htons(port);
}

/* ****************************************************** */

void rrc_src_port_range(int port_from, int port_to) {
  if(!valid_port(port_from)) rrc_syntax_error("Invalid source port low");
  if(!valid_port(port_to)) rrc_syntax_error("Invalid source port high");
  if(_cmd.action.match.sport.low) rrc_syntax_error("Duplicate source port range");
  _cmd.action.match.sport.low = htons(port_from);
  _cmd.action.match.sport.high = htons(port_to);
}

/* ****************************************************** */

void rrc_dst_port_range(int port_from, int port_to) {
  if(!valid_port(port_from)) rrc_syntax_error("Invalid dport low");
  if(!valid_port(port_to)) rrc_syntax_error("Invalid dport high");
  if(_cmd.action.match.dport.low) rrc_syntax_error("Duplicate destination port range");
  _cmd.action.match.dport.low = htons(port_from);
  _cmd.action.match.dport.high = htons(port_to);
}

/* ****************************************************** */

void rrc_vlan(int vlan_id) {
  if(_cmd.action.match.vlan_id) rrc_syntax_error("Duplicate vlan match");
  _cmd.action.match.vlan_id = htons(vlan_id);
}

/* ****************************************************** */

void rrc_protocol(int proto) {
  if(_cmd.action.match.proto) rrc_syntax_error("Duplicate protocol match");
  rrc_match_t *match = &_cmd.action.match;
  match->proto = proto;
}

