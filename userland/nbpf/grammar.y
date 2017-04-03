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

#define ARTHSET(a, p, o, m) (a).protocol = (p), (a).offset = (o), (a).mask = (m)

static nbpf_qualifiers_t qerr = { NBPF_Q_UNDEF, NBPF_Q_UNDEF, NBPF_Q_UNDEF };

static void yyerror(const char *msg) {
  nbpf_syntax_error("%s", msg);
}

%}

%union {
  int i; /* NUM, net */
  u_char *e; /* EIX (mac) */
  char *s; /* HID (ip, subnetv6), HID6 (ipv6, subnetv6), ID (portrange, l7proto) */
  nbpf_arth_t a;
  struct {
    nbpf_qualifiers_t q;
    nbpf_node_t *n;
  } block;
}

%type	<block>	expr id nid pid term rterm qid
%type	<block>	head
%type	<i>	hqual pqual dqual aqual
%type   <a>	narth
%type	<i>	pname pnum relop irelop
%type	<block>	and or paren not null prog
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
%token VLAN MPLS GTP
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
	nbpf_set_tree_root($2.n);
}
	| null
	;
null:	  			{ $$.q = qerr; }
	;
expr:	  term
	| expr and term		{ $$.n = nbpf_create_and($1.n, $3.n); }
	| expr and id		{ $$.n = nbpf_create_and($1.n, $3.n); } 
	| expr or term		{ $$.n = nbpf_create_or($1.n, $3.n);  }
	| expr or id		{ $$.n = nbpf_create_or($1.n, $3.n);  }
	;
and:	  AND			{ $$ = $<block>0; }
	;
or:	  OR			{ $$ = $<block>0; }
	;
id:	  nid
	| pnum			{ $$.n = nbpf_create_n_node((u_int32_t)$1, $$.q = $<block>0.q); }
	| paren pid ')'		{ $$ = $2; }
	;
nid:	  ID			{
				  if($<block>0.q.address != NBPF_Q_PORTRANGE) /* Note: ID used for numeric portrange only */
				    nbpf_syntax_error("'portrange' modifier expected with number ranges");
				  $$.n = nbpf_create_portrange_node($1, $$.q = $<block>0.q); 
				}
	| HID '/' NUM		{ $$.n = nbpf_create_net_node($1, NULL, $3, $$.q = $<block>0.q); }
	| HID NETMASK HID	{ $$.n = nbpf_create_net_node($1,   $3,  0, $$.q = $<block>0.q); }
	| HID			{ $$.n = nbpf_create_host_node($1, $<block>0.q); }
	| HID6 '/' NUM		{ $$.n = nbpf_create_net6_node($1,  $3, $$.q = $<block>0.q); }
	| HID6			{ $$.n = nbpf_create_net6_node($1, 128, $$.q = $<block>0.q); }
	| EID			{ 
				  $$.n = nbpf_create_eth_node($1, $$.q = $<block>0.q /* TODO check this */);
				  free($1); /* $1 was allocated by ether_aton() */
				}
	| not id		{ nbpf_create_not($2.n); $$ = $2; }
	;
not:	  '!'			{ $$ = $<block>0; }
	;
paren:	  '('			{ $$ = $<block>0; }
	;
pid:	  nid
	| qid and id		{ $$.n = nbpf_create_and($1.n, $3.n); }
	| qid or id		{ $$.n = nbpf_create_or($1.n, $3.n);  }
	;
qid:	  pnum			{ $$.n = nbpf_create_n_node((u_int32_t)$1, $$.q = $<block>0.q); }
	| pid
	;
term:	  rterm
	| not term		{ nbpf_create_not($2.n); $$ = $2; }
	;
head:	  hqual pqual dqual aqual	{ QSET($$.q, $1,        $2, $3,        $4); }
	| pqual dqual aqual		{ QSET($$.q, NBPF_Q_DEFAULT, $1, $2,        $3); }
	| hqual pqual dqual		{ QSET($$.q, $1,        $2, $3,        NBPF_Q_DEFAULT); }
	| pqual dqual			{ QSET($$.q, NBPF_Q_DEFAULT, $1, $2,        NBPF_Q_DEFAULT); }
	| hqual pqual aqual		{ QSET($$.q, $1,        $2, NBPF_Q_DEFAULT, $3); }
	| pqual aqual			{ QSET($$.q, NBPF_Q_DEFAULT, $1, NBPF_Q_DEFAULT, $2); }
	| hqual pqual PROTO		{ QSET($$.q, $1,        $2, NBPF_Q_DEFAULT, NBPF_Q_PROTO); }
	| pqual PROTO			{ QSET($$.q, NBPF_Q_DEFAULT, $1, NBPF_Q_DEFAULT, NBPF_Q_PROTO); }
	;
rterm:	  head id		{ $$.n = $2.n; $$.q = $1.q; }
	| L7PROTO ID		{ $$.n = nbpf_create_l7_node(0, (char *)$2); }
	| L7PROTO pnum		{ $$.n = nbpf_create_l7_node($2, NULL); }
	| paren expr ')'	{ $$.n = $2.n; $$.q = $1.q; /* TODO check this */ }
	| pname			{ $$.n = nbpf_create_protocol_node($1); $$.q = qerr; }
	| narth relop pnum	{ $$.n = nbpf_create_relation_node($2, $1, $3); $$.q = qerr; }
	| narth irelop pnum	{ $$.n = nbpf_create_relation_node($2, $1, $3); $$.q = qerr; }
	| other			{ $$.n = $1.n; $$.q = qerr; }
	;
/* header level qualifiers */
hqual:	  OUTER			{ $$ = NBPF_Q_OUTER; }
	| INNER			{ $$ = NBPF_Q_INNER; }
	;
/* protocol level qualifiers */
pqual:	  pname
	|			{ $$ = NBPF_Q_DEFAULT; }
	;
/* direction qualifiers */
dqual:	  SRC			{ $$ = NBPF_Q_SRC; }
	| DST			{ $$ = NBPF_Q_DST; }
	| SRC OR DST		{ $$ = NBPF_Q_OR; }
	| DST OR SRC		{ $$ = NBPF_Q_OR; }
	| SRC AND DST		{ $$ = NBPF_Q_AND; }
	| DST AND SRC		{ $$ = NBPF_Q_AND; }
	;
/* address type qualifiers */
aqual:	  HOST			{ $$ = NBPF_Q_HOST; }
	| NET			{ $$ = NBPF_Q_NET; }
	| PORT			{ $$ = NBPF_Q_PORT; }
	| PORTRANGE		{ $$ = NBPF_Q_PORTRANGE; }
	;
/* non-directional address type qualifiers */
pname:	  LINK			{ $$ = NBPF_Q_LINK; }
	| IP			{ $$ = NBPF_Q_IP; }
	| SCTP			{ $$ = NBPF_Q_SCTP; }
	| TCP			{ $$ = NBPF_Q_TCP; }
	| UDP			{ $$ = NBPF_Q_UDP; }
	| IPV6			{ $$ = NBPF_Q_IPV6; }
	;
other:	  VLAN pnum		{ $$.n = nbpf_create_vlan_node($2); }
	| VLAN			{ $$.n = nbpf_create_vlan_node(-1); }
	| MPLS pnum		{ $$.n = nbpf_create_mpls_node($2); }
	| MPLS			{ $$.n = nbpf_create_mpls_node(-1); }
	| GTP			{ $$.n = nbpf_create_gtp_node(); }
	;
relop:    '>'                   { $$ = NBPF_R_GT; }
        | GEQ                   { $$ = NBPF_R_GE; }
        | '='                   { $$ = NBPF_R_EQ; }
        ;
irelop:   LEQ                   { $$ = NBPF_R_LE; }
        | '<'                   { $$ = NBPF_R_LT; }
        | NEQ                   { $$ = NBPF_R_NE; }
        ;
narth:	pname '[' pnum ']'		{ ARTHSET($$, $1, $3, 0xFF); }
        | pname '[' pnum ']' '&' pnum	{ ARTHSET($$, $1, $3, $6); }
	;
pnum:	  NUM
	| paren pnum ')'	{ $$ = $2; }
	;
%%

