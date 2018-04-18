%{

#include <sys/types.h>
#include <stdlib.h>

#ifndef WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include "ndpi_main.h" 
#endif
  
#include <stdio.h>
#include <string.h>

#include "parser.h"

static void yyerror(const char *msg) {
  rrc_syntax_error("%s", msg);
}

%}

%union {
  int i;
  struct {
    int i1;
    int i2;
  } ii;
  char *s;
  u_char e[6];
  rrc_network_t m;
}

%type   <m> host_spec
%type   <e> EID
%type   <i> pname
%type   <ii> PORT_RANGE
%type   <s> HID HID6 DEFAULT rrc_port INTERFACE
%type   <s> NUM

%token DST_HOST SRC_HOST
%token DST_PORT SRC_PORT
%token DST_MAC SRC_MAC
%token VLAN
%token PROTO
%token NUM INTERFACE
%token PORT PORTRANGE PORT_RANGE
%token SCTP TCP UDP
%token EID
%token HID HID6 IPV6 NETMASK
%token DEFAULT
%token STEERING
%token FILTERING

%token DELETE SET
%token RULE MATCH ACTION
%token PASS DROP STEER_TO

%token STATS
%token RULES
%token SYNC
%token GARBAGE_COLLECT IDLE
%token CLEAR

%%
prog:	  command
	;

null:
	;

command:  action
	| stats
	| sync
	| garbage_collect
	| rules
	| clear
	| bpf_match
	;

action:   SET action_token				{ rrc_action_type(RRC_ACTION_SET); }
	| DELETE action_token				{ rrc_action_type(RRC_ACTION_DELETE); }
	| DEFAULT default_token				{ rrc_action_type(RRC_ACTION_SET_DEFAULT); }
	;
 
action_token: MATCH bpf_match action_token
	| PORT rrc_port	action_token			{ rrc_action($2); }
	| policy action_token
	| rule_token action_token
	| rrc_filtering action_token
	| null
	;

rule_token: RULE NUM					{ rrc_fix_rule(stoi($2)); }
	;

policy:	  PASS						{ rrc_action_policy_pass(1); }
	| DROP						{ rrc_action_policy_pass(0); }
	| STEER_TO rrc_port				{ rrc_action_policy_steer($2); }
	;

default_token: 	PORT rrc_port default_token		{ rrc_action($2); }
	| policy default_token
	| null
	;

stats:	  STATS stats_token
	;

stats_token: PORT rrc_port stats_token			{ rrc_stats($2); }
	| rule_token stats_token
	| null
	;

sync: SYNC						{ rrc_sync(); }
	;

garbage_collect: GARBAGE_COLLECT			{ rrc_gc(0); }
	| GARBAGE_COLLECT IDLE NUM			{ rrc_gc(stoi($3)); }
	;

rules: RULES list_rules_token
	;

list_rules_token: PORT rrc_port list_rules_token	{ rrc_rules($2); }
	| rrc_filtering list_rules_token
	| null
	;

clear: CLEAR clear_rules_token
	;

clear_rules_token: PORT rrc_port clear_rules_token	{ rrc_clear($2); }
	| rrc_filtering clear_rules_token
	| null
	;

rrc_filtering: FILTERING				{ rrc_set_filtering(1); }
	| STEERING					{ rrc_set_filtering(0); }
	;

bpf_match: bpf_term bpf_match
	| null
	;

bpf_term: DST_HOST host_spec				{ rrc_dst_host(&$2); }
	| SRC_HOST host_spec				{ rrc_src_host(&$2); }
	| SRC_MAC EID					{ rrc_src_mac($2); }
	| DST_MAC EID					{ rrc_dst_mac($2); }
	| SRC_PORT NUM					{ rrc_src_port(stoi($2)); }
	| DST_PORT NUM					{ rrc_dst_port(stoi($2)); }
	| SRC_PORT PORTRANGE PORT_RANGE			{ rrc_src_port_range($3.i1, $3.i2); }
	| DST_PORT PORTRANGE PORT_RANGE			{ rrc_dst_port_range($3.i1, $3.i2); }
	| VLAN NUM					{ rrc_vlan(stoi($2)); }
	| PROTO pname					{ rrc_protocol($2); }
	| PROTO NUM					{ rrc_protocol(atoi($2)); }
	;

host_spec: HID '/' NUM          { rrc_net($1, NULL, atoi($3), &$$); }
        | HID NETMASK HID       { rrc_net($1, $3, 0, &$$); }
        | HID                   { rrc_host($1, &$$); }
        | HID6 '/' NUM          { rrc_net6($1, atoi($3), &$$); }
        | HID6                  { rrc_net6($1, 128, &$$); }
	;

pname:	  SCTP			{ $$ = 132; }
	| TCP			{ $$ = 6; }
	| UDP			{ $$ = 17; }
	;

rrc_port: NUM
	| INTERFACE
	;
%%

