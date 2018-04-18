%{

#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netdb.h>
#endif

#include <sys/types.h>

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif

#include "parser.h"
#include "grammar.tab.h"
#include "list.h"

/* String to eth addr. Supported formats:
 *  "xx:xx:xx:xx:xx:xx"
 *  "xx.xx.xx.xx.xx.xx"
 *  "xx-xx-xx-xx-xx-xx"
 *  "xxxx.xxxx.xxxx"
 *  "xxxxxxxxxxxx"
 */
static void ether_aton(char *s, u_char *out) {
  register u_char *ep;
  register u_int d;

  ep = out;

  while (*s) {
    if (*s == ':' || *s == '.' || *s == '-')
      s += 1;
    d = xdtoi(*s++);
    if (isxdigit((unsigned char)*s)) {
      d <<= 4;
      d |= xdtoi(*s++);
    }
    *ep++ = d;
  }
}

struct yystr {
  list_head_t list;
  char str[];
};

static list_head_t yystr_list;

static char *yystrdup(const char *s) {
  char *str = NULL;
  int len = strlen(s);
  struct yystr *m = malloc(sizeof(struct yystr) + len + 1);

  if (m) {
    memcpy(m->str, s, len);
    m->str[len] = '\0';
    str = m->str;
    list_add(&m->list, &yystr_list);
  }

  return str;
}

#define YY_NO_UNPUT

extern YYSTYPE nblval;

%}

%option noinput
%option nounput

N	([0-9]+|(0X|0x)[0-9A-Fa-f]+)
B	([0-9A-Fa-f][0-9A-Fa-f]?)
B2	([0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f])
W	([0-9A-Fa-f][0-9A-Fa-f]?[0-9A-Fa-f]?[0-9A-Fa-f]?)

%a 18400
%o 21500
%e 7600
%k 4550
%p 27600
%n 2000

V6	({W}:{W}:{W}:{W}:{W}:{W}:{W}:{W}|::{W}:{W}:{W}:{W}:{W}:{W}:{W}|{W}::{W}:{W}:{W}:{W}:{W}:{W}|{W}:{W}::{W}:{W}:{W}:{W}:{W}|{W}:{W}:{W}::{W}:{W}:{W}:{W}|{W}:{W}:{W}:{W}::{W}:{W}:{W}|{W}:{W}:{W}:{W}:{W}::{W}:{W}|{W}:{W}:{W}:{W}:{W}:{W}::{W}|{W}:{W}:{W}:{W}:{W}:{W}:{W}::|::{W}:{W}:{W}:{W}:{W}:{W}|{W}::{W}:{W}:{W}:{W}:{W}|{W}:{W}::{W}:{W}:{W}:{W}|{W}:{W}:{W}::{W}:{W}:{W}|{W}:{W}:{W}:{W}::{W}:{W}|{W}:{W}:{W}:{W}:{W}::{W}|{W}:{W}:{W}:{W}:{W}:{W}::|::{W}:{W}:{W}:{W}:{W}|{W}::{W}:{W}:{W}:{W}|{W}:{W}::{W}:{W}:{W}|{W}:{W}:{W}::{W}:{W}|{W}:{W}:{W}:{W}::{W}|{W}:{W}:{W}:{W}:{W}::|::{W}:{W}:{W}:{W}|{W}::{W}:{W}:{W}|{W}:{W}::{W}:{W}|{W}:{W}:{W}::{W}|{W}:{W}:{W}:{W}::|::{W}:{W}:{W}|{W}::{W}:{W}|{W}:{W}::{W}|{W}:{W}:{W}::|::{W}:{W}|{W}::{W}|{W}:{W}::|::{W}|{W}::|::|{W}:{W}:{W}:{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}|::{W}:{W}:{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}|{W}::{W}:{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}|{W}:{W}::{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}|{W}:{W}:{W}::{W}:{W}:{N}\.{N}\.{N}\.{N}|{W}:{W}:{W}:{W}::{W}:{N}\.{N}\.{N}\.{N}|{W}:{W}:{W}:{W}:{W}::{N}\.{N}\.{N}\.{N}|::{W}:{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}|{W}::{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}|{W}:{W}::{W}:{W}:{N}\.{N}\.{N}\.{N}|{W}:{W}:{W}::{W}:{N}\.{N}\.{N}\.{N}|{W}:{W}:{W}:{W}::{N}\.{N}\.{N}\.{N}|::{W}:{W}:{W}:{N}\.{N}\.{N}\.{N}|{W}::{W}:{W}:{N}\.{N}\.{N}\.{N}|{W}:{W}::{W}:{N}\.{N}\.{N}\.{N}|{W}:{W}:{W}::{N}\.{N}\.{N}\.{N}|::{W}:{W}:{N}\.{N}\.{N}\.{N}|{W}::{W}:{N}\.{N}\.{N}\.{N}|{W}:{W}::{N}\.{N}\.{N}\.{N}|::{W}:{N}\.{N}\.{N}\.{N}|{W}::{N}\.{N}\.{N}\.{N}|::{N}\.{N}\.{N}\.{N})

MAC	({B}:{B}:{B}:{B}:{B}:{B}|{B}\-{B}\-{B}\-{B}\-{B}\-{B}|{B}\.{B}\.{B}\.{B}\.{B}\.{B}|{B2}\.{B2}\.{B2}|{B2}{3})

%%
dhost	return DST_HOST;
shost	return SRC_HOST;
dport	return DST_PORT;
sport	return SRC_PORT;
smac	return SRC_MAC;
dmac	return DST_MAC;

sctp	return SCTP;
tcp	return TCP;
udp	return UDP;

mask	return NETMASK;
port	return PORT;
portrang return PORTRANGE;
proto	return PROTO;
vlan	return VLAN;

delete	return DELETE;
set	return SET;
rule	return RULE;
match	return MATCH;
default	return DEFAULT;
pass	return PASS;
drop	return DROP;
steer-to return STEER_TO;
stats	return STATS;
sync	return SYNC;
gc	return GARBAGE_COLLECT;
idle-for return IDLE;
rules	return RULES;
steering return STEERING;
filtering return FILTERING;
clear	return CLEAR;

[ \r\n\t] ;
[+\-*/:\[\]!<>()&|=] return yytext[0];
"=="	return '=';
{MAC}	{ ether_aton((char *)yytext, nblval.e); return EID; }
{N}     { nblval.s = yystrdup((char *)yytext); return NUM; }
({N}\.{N})|({N}\.{N}\.{N})|({N}\.{N}\.{N}\.{N})	{
	nblval.s = yystrdup((char *)yytext); return HID; }
{V6}	{
		struct addrinfo hints, *res;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_flags = AI_NUMERICHOST;
		if (getaddrinfo(yytext, NULL, &hints, &res))
			rrc_syntax_error("bogus IPv6 address %s", yytext);
		else {
			freeaddrinfo(res);
			nblval.s = yystrdup((char *)yytext); return HID6;
		}
	}
{B}:+({B}:+)+ { rrc_syntax_error("bogus ethernet address %s", yytext); }
[0-9]*(-[0-9]*)? {
		char *ptr = (char*)strchr(yytext, '-');
		if(ptr) *ptr = 0;
		nblval.ii.i1 = stoi((char *)yytext);
		if(ptr) {
			nblval.ii.i2 = stoi(ptr+1);
			*ptr = '-';
		} else
			nblval.ii.i2 = 0;

		if (nblval.ii.i1 == nblval.ii.i2) {
			nblval.i = nblval.ii.i1;
			return NUM;
		} else if (nblval.ii.i1 < nblval.ii.i2)
			return PORT_RANGE;
		else
			rrc_syntax_error("invalid port range %s", yytext);
	}
[a-zA-Z0-9.]+ { nblval.s = yystrdup((char *)yytext); return INTERFACE; }
[^ \[\]\t\n\-_.A-Za-z0-9!<>()&|=]+ { rrc_syntax_error("illegal token: %s", yytext); }
.	{ rrc_syntax_error("illegal char '%c'", *yytext); }
%%

void rrc_lex_init(rrc_lex_t *lex, const char *buffer) {
  list_head_init(&yystr_list);
  lex->input_stream = yy_scan_string(buffer);
}

void rrc_lex_cleanup(rrc_lex_t *lex) {
  list_head_t *ptr, *tmp_ptr;
  struct yystr *m;

  if (lex->input_stream != NULL)
    yy_delete_buffer((YY_BUFFER_STATE) lex->input_stream);
  lex->input_stream = NULL;

  /* free strings allocated with yystrdup */
  list_foreach(ptr, tmp_ptr, &yystr_list) {
    m = list_entry(ptr, struct yystr, list);
    list_del(ptr);
    free(m);
  }
}

int yywrap() {
  return 1;
}

