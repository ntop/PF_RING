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
#include <windows.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif

#include "parser.h"
#include "grammar.tab.h"

/* TODO free the memory allocated with strdup at the end of filtering rules generation */

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

#define YY_NO_UNPUT

static YY_BUFFER_STATE input_stream;

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
portrang return PORTRANGE;
proto	return PROTO;
l7proto	return L7PROTO;

direction|dir return DIR;
and|"&&" return AND;
or|"||" return OR;
not	return '!';

vlan	return VLAN;

[ \r\n\t] ;
[+\-*/:\[\]!<>()&|=] return yytext[0];
">="	return GEQ;
"<="	return LEQ;
"!="	return NEQ;
"=="	return '=';
{MAC}	{ yylval.e = ether_aton((char *)yytext); return EID; }
{N}	{ yylval.i = stoi((char *)yytext); return NUM; }
({N}\.{N})|({N}\.{N}\.{N})|({N}\.{N}\.{N}\.{N})	{
	yylval.s = strdup((char *)yytext); return HID; }
{V6}	{
		struct addrinfo hints, *res;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_flags = AI_NUMERICHOST;
		if (getaddrinfo(yytext, NULL, &hints, &res))
			fast_bpf_syntax_error("bogus IPv6 address %s", yytext);
		else {
			freeaddrinfo(res);
			yylval.s = strdup((char *)yytext); return HID6;
		}
	}
{B}:+({B}:+)+ { fast_bpf_syntax_error("bogus ethernet address %s", yytext); }
[A-Za-z]+ { yylval.s = strdup((char *)yytext); return ID; } // l7proto name
[0-9]*(-[0-9]*)? { yylval.s = strdup((char *)yytext); return ID; } // portrange
[^ \[\]\t\n\-_.A-Za-z0-9!<>()&|=]+ { fast_bpf_syntax_error("illegal token: %s", yytext); }
.	{ fast_bpf_syntax_error("illegal char '%c'", *yytext); }
%%

void fast_bpf_lex_init(const char *buffer) {
  input_stream = yy_scan_string(buffer);
}

void fast_bpf_lex_cleanup() {
  if (input_stream != NULL)
    yy_delete_buffer(input_stream);
  input_stream = NULL;
}

int yywrap() {
  return 1;
}

