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

#include <string.h>

#include "parser.h"
#include "utils.h"

static nbroker_command_t *command = NULL;

static void assert_command_x(const char *cmd, int valid, const char *fail_with) {
  char errbuf[512];

  if(command) free(command);
  command = rrc_parse(cmd, errbuf, sizeof(errbuf));

  if(valid) {
    if(command == NULL) {
      fprintf(stderr, "Failed: command '%s' is not valid: %s - it should be valid\n", cmd, errbuf);
      exit(1);
    }
  } else {
    if(command != NULL) {
      fprintf(stderr, "Failed: command '%s' is valid - it should not be valid\n", cmd);
      exit(1);
    }
    if((fail_with != NULL) && (!strstr(errbuf, fail_with))) {
      fprintf(stderr, "Failed: command '%s' returned '%s' - it does not contain '%s'\n", cmd, errbuf, fail_with);
      exit(1);
    }
  }
}

static void assert_command(const char *cmd, int valid) {
  return assert_command_x(cmd, valid, NULL);
}

#define NUM_BUFS 20
#define BUF_SIZE 128
static int bufi = 0;
static char bufs[NUM_BUFS][BUF_SIZE];

static char* mac_tostring(u_int8_t *mac) {
  char *buf = bufs[bufi++];

  return utils_mactoa(mac, buf, BUF_SIZE);
}

static char* host_tostring(rrc_ip_addr_t *host, u_int8_t version) {
  char *buf = bufs[bufi++];

  return utils_hosttoa(host, version, buf, BUF_SIZE);
}

static int host_equal(rrc_ip_addr_t *host, const char *cmp, int version) {
  return !strcmp(host_tostring(host, version), cmp);
}

static void assert_value(int rv, const char *hint) {
  if(rv != 0) return;

  printf("Error: %s\n", hint);

  /* Dump the command */
  printf("\nCommand: [type=0x%x] [rule=0x%x]\n", command->type, command->ruleNumber);

  switch(command->type) {
    case RRC_RULE_TYPE_ACTION:
      printf("\tACTION: [type=0x%x] [rrc_port=%s,redirection_port=%s] [policy=0x%x]\n", command->action.type,
      command->action.port, command->action.redirectionPort, command->action.policy);

      printf("\tMATCH:\n");
      printf("\t\tsource_mac=%s dest_mac=%s\n", mac_tostring(command->action.match.smac),
        mac_tostring(command->action.match.dmac));
      printf("\t\tproto=%d vlan=%d\n", command->action.match.proto, command->action.match.vlan_id);
      printf("\t\tshost[%d]=%s/%s dhost[%d]=%s/%s\n", command->action.match.shost.ip_version,
        host_tostring(&command->action.match.shost.host, command->action.match.shost.ip_version),
        host_tostring(&command->action.match.shost.mask, command->action.match.shost.ip_version),
        command->action.match.dhost.ip_version,
        host_tostring(&command->action.match.dhost.host, command->action.match.dhost.ip_version),
        host_tostring(&command->action.match.dhost.mask, command->action.match.dhost.ip_version));
      printf("\t\tsport=%d-%d dport=%d-%d\n", command->action.match.sport.low, command->action.match.sport.high,
        command->action.match.dport.low, command->action.match.dport.high);
      
      break;
    case RRC_RULE_TYPE_STATS:
      printf("STATS: [port=%s]\n", command->stats.port);
      break;
    case RRC_RULE_TYPE_SYNC:
      printf("SYNC\n");
      break;
    case RRC_RULE_TYPE_GARBAGE_COLLECT:
      printf("GC: [idle_for=%u]\n", command->gc.idle_for);
      break;
  }

  printf("\n");
  exit(1);
}

int main() {
  /* Valid commands */
  assert_command("sync", 1);
  assert_value(command->type == RRC_RULE_TYPE_SYNC, "Bad sync type");

  assert_command("gc", 1);
  assert_value(command->type == RRC_RULE_TYPE_GARBAGE_COLLECT, "Bad gc type");

  assert_command("gc idle-for 60", 1);
  assert_value(command->gc.idle_for == 60, "Bad idle for");

  assert_command("rules port 1 steering", 1);
  assert_value(!strcmp(command->list_rules.port, "1"), "Bad list_rules rrc_port");
  assert_value(command->filter_type == RRC_RULE_STEERING, "Bad filter type");

  assert_command("stats port 1", 1);
  assert_value(command->type == RRC_RULE_TYPE_STATS, "Bad stats type");
  assert_value(!strcmp(command->stats.port, "1"), "Bad stats port");

  assert_command("stats port 1 rule 1", 1);
  assert_value(command->ruleNumber == 1, "Bad rule number");

  assert_command("delete rule 1 port eth1 filtering", 1);
  assert_value(command->type == RRC_RULE_TYPE_ACTION, "Bad delete action");
  assert_value(command->filter_type == RRC_RULE_FILTERING, "Bad filter type");
  assert_value(command->action.type == RRC_ACTION_DELETE, "Bad delete sub action");

  assert_command("set port 1 match sport 80 drop", 1);
  assert_value(command->type == RRC_RULE_TYPE_ACTION, "Bad set action");
  assert_value(command->action.type == RRC_ACTION_SET, "Bad set sub action");
  assert_value(!strcmp(command->action.port, "1"), "Bad set rrc_port");
  assert_value(command->action.match.sport.low == ntohs(80), "Bad match sport");
  assert_value(command->action.policy == RRC_POLICY_DROP, "Bad set policy");

  assert_command("delete port 2 match sport 80 steering", 1);
  assert_value(command->filter_type == RRC_RULE_STEERING, "Bad filter type");
  assert_value(!strcmp(command->action.port, "2"), "Bad delete rrc_port");

  assert_command("set match sport 80 steer-to 2 port 1", 1);
  assert_value(command->action.policy == RRC_POLICY_STEER, "Bad set policy");
  assert_value(!strcmp(command->action.redirectionPort, "2"), "Bad redirection port");

  assert_command("set drop port 2 match sport 80", 1);

  assert_command("default port 3 drop", 1);
  assert_value(command->type == RRC_RULE_TYPE_ACTION, "Bad default action");
  assert_value(command->action.type == RRC_ACTION_SET_DEFAULT, "Bad default sub action");
  assert_value(!strcmp(command->action.port, "3"), "Bad default port");
  assert_value(command->action.policy == RRC_POLICY_DROP, "Bad default policy");

  assert_command("default port eth1 steer-to eth2", 1);

  assert_command("set drop port 2 match sport 80 dport 1122", 1);
  assert_value(command->action.match.sport.low == ntohs(80), "sport mismatch");
  assert_value(command->action.match.dport.low == ntohs(1122), "dport mismatch");

  assert_command("delete steering port 2 match dhost 192.168.1.1 proto tcp vlan 7", 1);
  assert_value(host_equal(&command->action.match.dhost.host, "192.168.1.1", 4), "dhost mismatch");
  assert_value(command->action.match.proto == 6, "proto mismatch");
  assert_value(command->action.match.vlan_id == ntohs(7), "vlan mismatch");

  assert_command("set port 1 match dhost 192.168.1.1 shost 192.168.1.10 drop", 1);

  /* Commands with missing/invalid parts */
  assert_command_x("delete port eth1 steering", 0, "match rule");
  assert_command_x("delete rule 1 steering", 0, "port");
  assert_command_x("delete port 1 match steering", 0, "match rule");
  assert_command_x("delete port 1 match sport 1", 0, "filter");
  assert_command_x("delete port 1 match sport 1 drop", 0, "policy");
  assert_command_x("delete rule 1 port 1 match sport 1 filtering", 0, "both a rule");

  assert_command_x("set port 1 match sport 80 drop to eth1", 0, "syntax error");
  assert_command_x("set port eth0", 0, "match");
  assert_command_x("set match sport 80 drop", 0, "port");
  assert_command_x("set match sport 80 port eth0 steer", 0, "syntax error");
  assert_command("set match sport 80 port eth0 steer-to", 0);
  assert_command("set match sport eth0 port eth0 drop", 0);

  assert_command("gc port 0", 0);
  assert_command("stats match sport 80", 0);
  assert_command("sync port 0", 0);

  /* Duplicate parts */
  assert_command_x("delete port eth1 port 2 rule 1 filtering", 0, "port");
  assert_command_x("delete port eth1 rule 1 rule 2 filtering", 0, "rule");
  assert_command_x("delete port eth1 match sport 80 match sport 80 steering", 0, "match");
  assert_command("delete port eth1 match sport 80 steering steering", 0);
  assert_command("delete port eth1 match sport 80 steering steer-to 1", 0);
  assert_command("set port eth1 port eth2 match sport 1 drop", 0);
  assert_command("set set port eth1 match sport 2 drop", 0);
  assert_command_x("set port eth1 match sport 2 match sport 2 drop", 0, "match");
  assert_command("set port eth1 match sport 2 pass pass", 0);
  assert_command("set rule 2 port eth1 rule 1 match sport 2 drop", 0);
  assert_command("set port eth1 match sport 2 steer-to eth1 to eth2", 0);
  assert_command("gc older_than 40 older_than 40", 0);
  assert_command("stats port 0 port 1", 0);
  assert_command("stats rule 3 port 0 rule 1", 0);
  assert_command("default drop", 0);
  assert_command("default default drop port eth1", 0);
  assert_command_x("set port 1 match vlan 3 sport 1 vlan 2 drop", 0, "vlan");
  assert_command_x("delete port 1 match sport 1 sport 2 filtering", 0, "source port");
  assert_command_x("delete port 1 match dport 1 dport 2 filtering", 0, "destination port");
  assert_command_x("delete port 1 match dport portrang 2-4 dport 3 filtering", 0, "destination port");
  assert_command_x("delete port 1 match sport portrang 2-4 sport 3 filtering", 0, "source port");
  assert_command_x("set match smac 11:11:22:33:44:55 smac 11:11:22:33:44:55 port 1 drop", 0, "source mac");
  assert_command_x("set match dmac 11:11:22:33:44:55 dmac 11:11:22:33:44:55 port 1 drop", 0, "destination mac");
  assert_command_x("set match shost 192.168.1.1 shost 192.168.1.1 port 2 drop", 0, "source host");
  assert_command_x("set match dhost 192.168.1.1 dhost ::1 drop port 3", 0, "destination host");
  assert_command_x("delete port 1 match proto tcp proto tcp filtering", 0, "proto");
  assert_command("delete port 1 match proto tcp tcp filtering", 0);
  assert_command_x("rules port 1", 0, "filter");

  /* Some BPF tests */
  assert_command("set port eth0 match dport 1 drop", 1);
  assert_value(command->action.match.dport.low == ntohs(1), "Bad dport");

  assert_command("set port eth0 match shost 192.168.1.1 drop", 1);
  assert_value(command->action.match.shost.ip_version == 4, "Bad ipv4 version");
  assert_value(host_equal(&command->action.match.shost.host, "192.168.1.1", 4), "Bad shost");
  assert_value(host_equal(&command->action.match.shost.mask, "255.255.255.255", 4), "Bad shost mask");

  assert_command("set port eth0 match dhost 192.168.1.1 drop", 1);
  assert_value(host_equal(&command->action.match.dhost.host, "192.168.1.1", 4), "Bad dhost");
  assert_value(host_equal(&command->action.match.dhost.mask, "255.255.255.255", 4), "Bad dhost mask");

  assert_command("set port eth0 match proto tcp drop", 1);
  assert_value(command->action.match.proto == 6, "Bad tcp proto");

  assert_command("set port eth0 match proto udp drop", 1);
  assert_value(command->action.match.proto == 17, "Bad udp proto");

  assert_command("set port eth0 match vlan 5 steer-to eth1", 1);
  assert_value(command->action.match.vlan_id == ntohs(5), "Bad vlan");

  assert_command("set port eth0 match dmac 10:00:00:00:00:00 drop", 1);
  assert_value(!strcmp(mac_tostring(command->action.match.dmac), "10:00:00:00:00:00"), "Bad dmac");

  assert_command("set port eth0 match smac 10:00:00:00:00:00 drop", 1);
  assert_value(!strcmp(mac_tostring(command->action.match.smac), "10:00:00:00:00:00"), "Bad smac");

  assert_command("set port eth0 match sport portrang 40-100 drop", 1);
  assert_value(command->action.match.sport.low == ntohs(40), "Bad sport low");
  assert_value(command->action.match.sport.high == ntohs(100), "Bad sport high");

  assert_command("set port eth0 match dport portrang 40-100 drop", 1);
  assert_value(command->action.match.dport.low == ntohs(40), "Bad dport low");
  assert_value(command->action.match.dport.high == ntohs(100), "Bad dport high");

  assert_command("set port eth0 match dport portrang 40-70000 drop", 0);
  assert_command("set port eth0 match sport portrange 10:5 drop", 0);

  assert_command("set port eth0 match shost 192.168.1.0/24 drop", 1);
  

  assert_command("set port eth0 match dhost 192.168.1.0 mask 255.255.255.0 drop", 1);
  assert_value(host_equal(&command->action.match.dhost.host, "192.168.1.0", 4), "Bad dhost masked");
  assert_value(host_equal(&command->action.match.dhost.mask, "255.255.255.0", 4), "Bad dhost masking");

  assert_command_x("set port eth0 match dhost 192.168.1.0/16 drop", 0, "non-network bits");
  assert_command("set port eth0 match dhost 192.168.1.1/32 drop", 1);
  assert_command("set port eth0 match shost 2001:db8::2:1 drop", 1);
  assert_value(host_equal(&command->action.match.shost.host, "20:01:0D:B8:00:00:00:00:00:00:00:00:00:02:00:01", 6), "Bad host v6");

  assert_command("set port eth0 match shost 2001:db8::2:2/127 drop", 1);
  assert_value(command->action.match.shost.ip_version == 6, "Bad ipv6 version");
  assert_value(host_equal(&command->action.match.shost.mask, "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FE", 6), "Bad host v6 mask");

  assert_command("delete port 3 match shost fe80::3252:cbff:fe6c:1d1c filtering", 1);

  puts("** Success **");
  if(command) free(command);
  return 0;
}

