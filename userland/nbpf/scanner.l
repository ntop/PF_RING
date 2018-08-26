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

static inline int xdtoi(int);
static int stoi(char *);
static u_char *ether_aton(char *s);
static char *yystrdup(const char *s);

struct yystr {
  list_head_t list;
  char str[];
};
static list_head_t yystr_list;

#define YY_NO_UNPUT

extern YYSTYPE yylval;

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
dst	return DST;
src	return SRC;

outer	return OUTER;
inner	return INNER;

link|ether|ppp|slip return LINK;
fddi|tr|wlan return LINK;
ip	return IP;
sctp	return SCTP;
tcp	return TCP;
udp	return UDP;
ip6	return IPV6;

host	return HOST;
net	return NET;
mask	return NETMASK;
port	return PORT;
portrange return PORTRANGE;
proto	return PROTO;
l7proto	return L7PROTO;

direction|dir return DIR;
and|"&&" return AND;
or|"||" return OR;
not	return '!';

vlan	return VLAN;
mpls	return MPLS;
gtp	return GTP;

[ \r\n\t] ;
[+\-*/:\[\]!<>()&|=] return yytext[0];
">="	return GEQ;
"<="	return LEQ;
"!="	return NEQ;
"=="	return '=';
{MAC}	{ yylval.e = ether_aton((char *)yytext); return EID; }
{N}	{ yylval.i = stoi((char *)yytext); return NUM; }
({N}\.{N})|({N}\.{N}\.{N})|({N}\.{N}\.{N}\.{N})	{
	yylval.s = yystrdup((char *)yytext); return HID; }
{V6}	{
		struct addrinfo hints, *res;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_flags = AI_NUMERICHOST;
		if (getaddrinfo(yytext, NULL, &hints, &res))
			nbpf_syntax_error("bogus IPv6 address %s", yytext);
		else {
			freeaddrinfo(res);
			yylval.s = yystrdup((char *)yytext); return HID6;
		}
	}
{B}:+({B}:+)+ { nbpf_syntax_error("bogus ethernet address %s", yytext); }
[A-Za-z]+ { yylval.s = yystrdup((char *)yytext); return ID; } // l7proto name
[0-9]*(-[0-9]*)? { yylval.s = yystrdup((char *)yytext); return ID; } // portrange
[^ \[\]\t\n\-_.A-Za-z0-9!<>()&|=]+ { nbpf_syntax_error("illegal token: %s", yytext); }
.	{ nbpf_syntax_error("illegal char '%c'", *yytext); }
%%

void nbpf_lex_init(nbpf_lex_t *lex, const char *buffer) {
  list_head_init(&yystr_list);
  lex->input_stream = yy_scan_string(buffer);
}

void nbpf_lex_cleanup(nbpf_lex_t *lex) {
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

/* Hex to int */
static int xdtoi(int c) {
  if (isdigit(c))
    return c - '0';
  else if (islower(c))
    return c - 'a' + 10;
  else
    return c - 'A' + 10;
}

/* String to int (atoi with hex '0x' and octal '0' support) */
static int stoi(char *s) {
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

/* String to eth addr. Supported formats:
 *  "xx:xx:xx:xx:xx:xx"
 *  "xx.xx.xx.xx.xx.xx"
 *  "xx-xx-xx-xx-xx-xx"
 *  "xxxx.xxxx.xxxx"
 *  "xxxxxxxxxxxx"
 */
static u_char *ether_aton(char *s) {
  register u_char *ep, *e;
  register u_int d;

  e = ep = (u_char *) malloc(6);

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

  return e;
}

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

