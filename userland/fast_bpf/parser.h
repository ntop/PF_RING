/*
 *  Copyright (C) 2016 ntop.org
 *
 *      http://www.ntop.org/
 *
 */


#ifndef BPF_PARSER_H
#define BPF_PARSER_H

#include <stdio.h>
#include <stdarg.h>

#include "fast_bpf.h"

#ifdef HAVE_NDPI
#include "ndpi_main.h"
#endif

fast_bpf_node_t *fast_bpf_create_and(fast_bpf_node_t *, fast_bpf_node_t *);
fast_bpf_node_t *fast_bpf_create_or(fast_bpf_node_t *, fast_bpf_node_t *);
fast_bpf_node_t *fast_bpf_create_eth_node(const u_char *, fast_bpf_qualifiers_t);
fast_bpf_node_t *fast_bpf_create_n_node(u_int32_t nn, fast_bpf_qualifiers_t q);
fast_bpf_node_t *fast_bpf_create_host_node(const char *s, fast_bpf_qualifiers_t q);
fast_bpf_node_t *fast_bpf_create_portrange_node(const char *, fast_bpf_qualifiers_t);
fast_bpf_node_t *fast_bpf_create_net_node(const char *, const char *, int, fast_bpf_qualifiers_t);
fast_bpf_node_t *fast_bpf_create_net6_node(const char *, int, fast_bpf_qualifiers_t);
fast_bpf_node_t *fast_bpf_create_proto_node(int);
fast_bpf_node_t *fast_bpf_create_vlan_node(int);
fast_bpf_node_t *fast_bpf_create_l7_node(u_int32_t, const char *);
void fast_bpf_create_not(fast_bpf_node_t *);

void fast_bpf_lex_init(const char *);
void fast_bpf_lex_cleanup(void);
void fast_bpf_syntax_error(char * format, ...);
void fast_bpf_set_tree_root(fast_bpf_node_t *n);

int yylex(void);
int yyparse(void);

#endif /* BPF_PARSER_H */
