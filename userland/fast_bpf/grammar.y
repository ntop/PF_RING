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

#define QSET(q, h, p, d, a) (q).header = (h), (q).protocol = (p), (q).direction = (d), (q).address = (a)

static fast_bpf_qualifiers_t qerr = { Q_UNDEF, Q_UNDEF, Q_UNDEF };

static void yyerror(const char *msg) {
  fast_bpf_syntax_error("%s", msg);
}

%}

%union {
  int i; /* NUM, net */
  u_char *e; /* EIX (mac) */
  char *s; /* HID (ip, subnetv6), HID6 (ipv6, subnetv6), ID (portrange, l7proto) */
  struct {
    fast_bpf_qualifiers_t q;
    fast_bpf_node_t *n;
  } block;
}

%type	<block>	 expr id nid pid term rterm qid
%type	<block>	 head
%type	<i>	 hqual pqual dqual aqual
%type	<i>	 pname pnum
%type	<block>	 and or paren not null prog
%type	<block> other

%token OUTER INNER
%token DST SRC HOST
%token NET NETMASK PORT PORTRANGE PROTO
%token ARP RARP IP SCTP TCP UDP
%token NUM
%token DIR
%token LINK
%token GEQ LEQ NEQ
%token ID EID HID HID6
%token IPV6
%token VLAN
%token L7PROTO

%type	<s> ID
%type	<e> EID
%type	<s> HID HID6
%type	<i> NUM

%left OR AND
%nonassoc  '!'
%%
prog:	  null expr
{
	fast_bpf_set_tree_root($2.n);
}
	| null
	;
null:	  			{ $$.q = qerr; }
	;
expr:	  term
	| expr and term		{ $$.n = fast_bpf_create_and($1.n, $3.n); }
	| expr and id		{ $$.n = fast_bpf_create_and($1.n, $3.n); } 
	| expr or term		{ $$.n = fast_bpf_create_or($1.n, $3.n);  }
	| expr or id		{ $$.n = fast_bpf_create_or($1.n, $3.n);  }
	;
and:	  AND			{ $$ = $<block>0; }
	;
or:	  OR			{ $$ = $<block>0; }
	;
id:	  nid
	| pnum			{ $$.n = fast_bpf_create_n_node((u_int32_t)$1, $$.q = $<block>0.q); }
	| paren pid ')'		{ $$ = $2; }
	;
nid:	  ID			{
				  if($<block>0.q.address != Q_PORTRANGE) /* Note: ID used for numeric portrange only */
				    fast_bpf_syntax_error("'portrange' modifier expected with number ranges");
				  $$.n = fast_bpf_create_portrange_node($1, $$.q = $<block>0.q); 
				}
	| HID '/' NUM		{ $$.n = fast_bpf_create_net_node($1, NULL, $3, $$.q = $<block>0.q); }
	| HID NETMASK HID	{ $$.n = fast_bpf_create_net_node($1,   $3,  0, $$.q = $<block>0.q); }
	| HID			{ $$.n = fast_bpf_create_host_node($1, $<block>0.q); }
	| HID6 '/' NUM		{ $$.n = fast_bpf_create_net6_node($1,  $3, $$.q = $<block>0.q); }
	| HID6			{ $$.n = fast_bpf_create_net6_node($1, 128, $$.q = $<block>0.q); }
	| EID			{ 
				  $$.n = fast_bpf_create_eth_node($1, $$.q = $<block>0.q /* TODO check this */);
				  free($1); /* $1 was allocated by ether_aton() */
				}
	| not id		{ fast_bpf_create_not($2.n); $$ = $2; }
	;
not:	  '!'			{ $$ = $<block>0; }
	;
paren:	  '('			{ $$ = $<block>0; }
	;
pid:	  nid
	| qid and id		{ $$.n = fast_bpf_create_and($1.n, $3.n); }
	| qid or id		{ $$.n = fast_bpf_create_or($1.n, $3.n);  }
	;
qid:	  pnum			{ $$.n = fast_bpf_create_n_node((u_int32_t)$1, $$.q = $<block>0.q); }
	| pid
	;
term:	  rterm
	| not term		{ fast_bpf_create_not($2.n); $$ = $2; }
	;
head:	  hqual pqual dqual aqual	{ QSET($$.q, $1,        $2, $3,        $4); }
	| pqual dqual aqual		{ QSET($$.q, Q_DEFAULT, $1, $2,        $3); }
	| hqual pqual dqual		{ QSET($$.q, $1,        $2, $3,        Q_DEFAULT); }
	| pqual dqual			{ QSET($$.q, Q_DEFAULT, $1, $2,        Q_DEFAULT); }
	| hqual pqual aqual		{ QSET($$.q, $1,        $2, Q_DEFAULT, $3); }
	| pqual aqual			{ QSET($$.q, Q_DEFAULT, $1, Q_DEFAULT, $2); }
	| hqual pqual PROTO		{ QSET($$.q, $1,        $2, Q_DEFAULT, Q_PROTO); }
	| pqual PROTO			{ QSET($$.q, Q_DEFAULT, $1, Q_DEFAULT, Q_PROTO); }
	;
rterm:	  head id		{ $$.n = $2.n; $$.q = $1.q; }
	| L7PROTO ID		{ $$.n = fast_bpf_create_l7_node(0, (char *)$2); }
	| L7PROTO pnum		{ $$.n = fast_bpf_create_l7_node($2, NULL); }
	| paren expr ')'	{ $$.n = $2.n; $$.q = $1.q; /* TODO check this */ }
	| pname			{ $$.n = fast_bpf_create_proto_node($1); $$.q = qerr; }
	| other			{ $$.n = $1.n; $$.q = qerr; }
	;
/* header level qualifiers */
hqual:	  OUTER			{ $$ = Q_OUTER; }
	| INNER			{ $$ = Q_INNER; }
	;
/* protocol level qualifiers */
pqual:	  pname
	|			{ $$ = Q_DEFAULT; }
	;
/* direction qualifiers */
dqual:	  SRC			{ $$ = Q_SRC; }
	| DST			{ $$ = Q_DST; }
	| SRC OR DST		{ $$ = Q_OR; }
	| DST OR SRC		{ $$ = Q_OR; }
	| SRC AND DST		{ $$ = Q_AND; }
	| DST AND SRC		{ $$ = Q_AND; }
	;
/* address type qualifiers */
aqual:	  HOST			{ $$ = Q_HOST; }
	| NET			{ $$ = Q_NET; }
	| PORT			{ $$ = Q_PORT; }
	| PORTRANGE		{ $$ = Q_PORTRANGE; }
	;
/* non-directional address type qualifiers */
pname:	  LINK			{ $$ = Q_LINK; }
	| IP			{ $$ = Q_IP; }
	| SCTP			{ $$ = Q_SCTP; }
	| TCP			{ $$ = Q_TCP; }
	| UDP			{ $$ = Q_UDP; }
	| IPV6			{ $$ = Q_IPV6; }
	;
other:	  VLAN pnum		{ $$.n = fast_bpf_create_vlan_node($2); }
	| VLAN			{ $$.n = fast_bpf_create_vlan_node(-1); }
	;
pnum:	  NUM
	| paren pnum ')'	{ $$ = $2; }
	;
%%

