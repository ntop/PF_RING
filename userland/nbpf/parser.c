/*
 *  Copyright (C) 2016-2018 ntop.org
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

static u_int32_t errors = 0;
static nbpf_tree_t tree_root = { NULL };
static l7protocol_by_name_func l7proto_by_name = NULL;
#ifdef HAVE_NDPI
static struct ndpi_detection_module_struct *ndpi_struct = NULL;
#endif

#ifndef WIN32
static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
#endif

/* ****************************************** */

static nbpf_node_t *alloc_node() {
  nbpf_node_t *n;

  n = (nbpf_node_t *) calloc(1, sizeof(nbpf_node_t));

  if (n == NULL)
    fprintf(stderr, "Error in memory allocation\n");

  return n;
}

/* ****************************************** */

static int atoin(const char *s, u_int32_t *addr) {
  u_int n;
  int len;

  *addr = 0;
  len = 0;
  while (1) {
    n = 0;
    while (*s && *s != '.')
      n = n * 10 + *s++ - '0';
    *addr <<= 8;
    *addr |= n & 0xff;
    len += 8;
    if (*s == '\0')
      return len;
    ++s;
  }
}

/* ****************************************** */

struct addrinfo *nametoaddrinfo(const char *name) {
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

void nbpf_syntax_error(char *format, ...) {
  va_list va_ap;
  char buf[2048];

  errors++;

  va_start (va_ap, format);
  memset(buf, 0, sizeof(buf));
  vsnprintf(buf, sizeof(buf)-1, format, va_ap);
  while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
  /* fprintf(stderr, "Error: %s\n", buf); */
  va_end(va_ap);
}

/* ****************************************** */

void nbpf_set_tree_root(nbpf_node_t *n) {
  tree_root.root = n;
}

/* ****************************************** */

static nbpf_node_t* node_clone(nbpf_node_t *t) {
  nbpf_node_t *root;

  if (t == NULL)
    return NULL;
  
  root = alloc_node();

  if (!root) 
    return NULL; 

  memcpy(root, t, sizeof(nbpf_node_t));
  root->l = node_clone(t->l);
  root->r = node_clone(t->r);
  return root;
}

/* ****************************************** */

nbpf_tree_t* tree_clone(nbpf_tree_t *t) {
  nbpf_tree_t *c = (nbpf_tree_t *) malloc(sizeof(nbpf_tree_t));

  if (!c) 
    return NULL;
  
  c->root = node_clone(t->root);
  return c;
}

/* ****************************************** */

static void node_purge(nbpf_node_t *n) {
  if (n->l) node_purge(n->l);
  if (n->r) node_purge(n->r);
  free(n);
}

/* ****************************************** */

void nbpf_free(nbpf_tree_t *t) {
  if (!t) return;
  if (t->root) node_purge(t->root);
  free(t);
}

/* ****************************************** */

static nbpf_node_t *tree_parse(const char *buffer) {
  nbpf_lex_t lex;

#ifdef HAVE_NDPI
  ndpi_struct = ndpi_init_detection_module();

  if (ndpi_struct == NULL) 
    return NULL;
#endif

  memset(&tree_root, 0, sizeof(tree_root));

  nbpf_lex_init(&lex, buffer);

  errors = 0;
  yyparse();

  nbpf_lex_cleanup(&lex);

  if (errors) {
    return NULL;
  }

#ifdef HAVE_NDPI
  ndpi_exit_detection_module(ndpi_struct);
#endif

  if (tree_root.root == NULL) /* empty filter? */
    tree_root.root = nbpf_create_empty_node();

  return tree_root.root;
}

/* ****************************************** */

nbpf_tree_t *nbpf_parse(const char *bpf_filter, l7protocol_by_name_func l7proto_by_name_callback) {
  nbpf_tree_t *t = (nbpf_tree_t *) malloc(sizeof(nbpf_tree_t));

  if (t == NULL)
    return NULL;

  l7proto_by_name = l7proto_by_name_callback;

#ifndef WIN32
  pthread_rwlock_wrlock(&lock);
#endif

  t->root = tree_parse(bpf_filter);

#ifndef WIN32
  pthread_rwlock_unlock(&lock);
#endif

  if (t->root == NULL) {
    free(t);
    return NULL;
  }

  return t;
}

/* ****************************************** */

nbpf_node_t *nbpf_create_empty_node() {
  nbpf_node_t *n = alloc_node();

  n->type = N_EMPTY;

  return n;
}

/* ****************************************** */

nbpf_node_t *nbpf_create_and(nbpf_node_t *n1, nbpf_node_t *n2) {
  nbpf_node_t *n = alloc_node();
  
  n->type = N_AND; 
  n->l = n1;
  n->r = n2;
  
  return n;
}

/* ****************************************** */

nbpf_node_t *nbpf_create_or(nbpf_node_t *n1, nbpf_node_t *n2) {
  nbpf_node_t *n = alloc_node();

  n->type = N_OR;
  n->l = n1;
  n->r = n2;

  return n;
}

/* ****************************************** */

nbpf_node_t *nbpf_create_portrange_node(const char *range, nbpf_qualifiers_t q) {
  nbpf_node_t *n = alloc_node();
  int proto = q.protocol;
  int port1, port2;
  
  if (proto != NBPF_Q_DEFAULT && proto != NBPF_Q_UDP && proto != NBPF_Q_TCP && proto != NBPF_Q_SCTP)
    nbpf_syntax_error("illegal qualifier of 'portrange'");

  if (sscanf(range, "%d-%d", &port1, &port2) != 2)
    nbpf_syntax_error("illegal 'portrange' value");

  n->type = N_PRIMITIVE;
  n->qualifiers = q;
  n->port_from = htons(port1);
  n->port_to = htons(port2);

  return n;
}

/* ****************************************** */

nbpf_node_t *nbpf_create_eth_node(const u_char *eaddr, nbpf_qualifiers_t q) { 
  nbpf_node_t *n = alloc_node();

  n->type = N_PRIMITIVE;
  n->qualifiers = q;
  memcpy(n->mac, eaddr, sizeof(n->mac));

  switch (q.direction) {
   case NBPF_Q_SRC:
    case NBPF_Q_DST:
    case NBPF_Q_AND:
    case NBPF_Q_OR: case NBPF_Q_DEFAULT:
      break;
    default:
      nbpf_syntax_error("eth address applied to unsupported direction");
  }

  return n;
}

/* ****************************************** */

nbpf_node_t *__nbpf_create_net_node(u_int32_t net, u_int32_t mask, nbpf_qualifiers_t q) {
  nbpf_node_t *n = alloc_node();

  n->type = N_PRIMITIVE;
  n->qualifiers = q;
  n->ip = htonl(net);
  n->mask = htonl(mask);

  switch (q.direction) {
    case NBPF_Q_SRC:
    case NBPF_Q_DST:
    case NBPF_Q_AND:
    case NBPF_Q_OR: case NBPF_Q_DEFAULT:
      break;
    default:
      nbpf_syntax_error("host or net applied to unsupported direction");
  }

  return n;
}

/* ****************************************** */

nbpf_node_t *nbpf_create_host_node(const char *s, nbpf_qualifiers_t q) {
  u_int32_t hh, mask = 0xffffffff;
  int vlen;
  
  if (q.address != NBPF_Q_DEFAULT &&
      q.address != NBPF_Q_HOST &&
      q.address != NBPF_Q_NET /* && 
      q.address != NBPF_Q_GATEWAY */)
    nbpf_syntax_error("ip syntax for host and network only");

  vlen = atoin(s, &hh);

  hh <<= 32 - vlen;
  mask <<= 32 - vlen;

  return __nbpf_create_net_node(hh, mask, q);
}

/* ****************************************** */

nbpf_node_t *nbpf_create_net_node(const char *net, const char *netmask, 
				 int masklen, nbpf_qualifiers_t q) {
  int nlen, mlen;
  u_int32_t nn, mask;

  if (q.address != NBPF_Q_NET)
    nbpf_syntax_error("mask syntax for networks only");

  switch (q.protocol) {
    case NBPF_Q_DEFAULT:
    case NBPF_Q_IP:
      /* Ok */
      break;
    /* case NBPF_Q_ARP:  */
    /* case NBPF_Q_RARP: */
    default:
      nbpf_syntax_error("net mask applied to unsupported protocol");
  }

  nlen = atoin(net, &nn);
  nn <<= 32 - nlen;

  if (netmask != NULL) {
    mlen = atoin(netmask, &mask);
    mask <<= 32 - mlen;
    if ((nn & ~mask) != 0)
      nbpf_syntax_error("non-network bits set in \"%s mask %s\"", net, netmask);
  } else {
  /* Convert mask len to mask */
    if (masklen > 32)
      nbpf_syntax_error("mask length must be <= 32");

    if (masklen == 0)
      mask = 0;
    else
      mask = 0xffffffff << (32 - masklen);

    if ((nn & ~mask) != 0)
      nbpf_syntax_error("non-network bits set in \"%s/%d\"", net, masklen);
  }

  return __nbpf_create_net_node(nn, mask, q); 
}

/* ****************************************** */

nbpf_node_t *nbpf_create_net6_node(const char *net, int masklen, nbpf_qualifiers_t q) {
  nbpf_node_t *n = alloc_node();
  struct addrinfo *res;
  struct in6_addr *addr;
  struct in6_addr mask;
  u_int32_t *a, *m;

  res = nametoaddrinfo(net);

  if (!res)
    nbpf_syntax_error("invalid ip6 address %s", net);

  if (res->ai_next)
    nbpf_syntax_error("%s resolved to multiple address", net);

  addr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;

  if (sizeof(mask) * 8 < masklen)
    nbpf_syntax_error("mask length must be <= %u", (unsigned int)(sizeof(mask) * 8));
  
  memset(&mask, 0, sizeof(mask));
  memset(&mask, 0xff, masklen / 8);
  if (masklen % 8)
    mask.s6_addr[masklen / 8] = (0xff << (8 - masklen % 8)) & 0xff;

  a = (u_int32_t *)addr;
  m = (u_int32_t *)&mask;

  if ((a[0] & ~m[0]) || (a[1] & ~m[1]) || (a[2] & ~m[2]) || (a[3] & ~m[3]))
    nbpf_syntax_error("non-network bits set in \"%s/%d\"", net, masklen);

  switch (q.address) {
    case NBPF_Q_DEFAULT:
    case NBPF_Q_HOST:
      if (masklen != 128)
        nbpf_syntax_error("mask syntax for networks only");
    case NBPF_Q_NET:
      /* Ok */
      break;
    default:
      nbpf_syntax_error("invalid qualifier against IPv6 address");
      freeaddrinfo(res);
      return n; /* a dummy node */
  }

  switch (q.protocol) {
    case NBPF_Q_DEFAULT:
    case NBPF_Q_IPV6:
      /* Ok */
      break;
    default:
      nbpf_syntax_error("invalid proto modifies applied to ipv6");
  }

  n->type = N_PRIMITIVE;
  n->qualifiers = q;
  
  memcpy(n->ip6,   a, sizeof(n->ip6));
  memcpy(n->mask6, m, sizeof(n->mask6));

  switch (q.direction) {
    case NBPF_Q_SRC:
    case NBPF_Q_DST:
    case NBPF_Q_AND:
    case NBPF_Q_OR: case NBPF_Q_DEFAULT:
      break;
    default:
      nbpf_syntax_error("net mask applied to unsupported direction");
  }

  freeaddrinfo(res);
  return n;
}

/* ****************************************** */

nbpf_node_t *nbpf_create_n_node(u_int32_t nn, nbpf_qualifiers_t q) {
  nbpf_node_t *n;
  u_int32_t mask = 0xffffffff;

  switch (q.address) {
    case NBPF_Q_DEFAULT:
    case NBPF_Q_HOST:
    case NBPF_Q_NET:
      if (q.address == NBPF_Q_NET) {
        while (nn && (nn & 0xff000000) == 0) {
          nn <<= 8;
          mask <<= 8;
        }
      }
      
      n = __nbpf_create_net_node(nn, mask, q);

      break;
    case NBPF_Q_PORT:
    case NBPF_Q_PORTRANGE:

      if (q.protocol != NBPF_Q_DEFAULT &&
          q.protocol != NBPF_Q_UDP &&
          q.protocol != NBPF_Q_TCP &&
          q.protocol != NBPF_Q_SCTP)
        nbpf_syntax_error("illegal qualifier of 'port'");
      
      n = alloc_node();

      n->type = N_PRIMITIVE;
      n->qualifiers = q;
      n->port_from = n->port_to = htons(nn);
     
      break;
    case NBPF_Q_PROTO:
      
      n = alloc_node();

      n->type = N_PRIMITIVE;
      n->qualifiers = q;
      n->protocol = nn;
      
      break;
    default:
      nbpf_syntax_error("unexpected number for the specified address qualifier");
      n = alloc_node(); /* a dummy node */
  }

  return n;
}

void nbpf_create_not(nbpf_node_t *n) {
  n->not_rule = !n->not_rule;
}

/* ****************************************************** */

nbpf_node_t *nbpf_create_protocol_node(int proto) { 
  nbpf_node_t *n = alloc_node();

  n->type = N_PRIMITIVE;
  n->qualifiers.address = NBPF_Q_PROTO;

  switch (proto) {
    case NBPF_Q_IP:
    case NBPF_Q_IPV6:
      n->qualifiers.protocol = NBPF_Q_LINK;
      break;
    case NBPF_Q_TCP:
    case NBPF_Q_UDP:
    case NBPF_Q_SCTP:
      n->qualifiers.protocol = NBPF_Q_IP;
      break;
    default:
      nbpf_syntax_error("Unexpected protocol\n"); 
  }

  switch (proto) {
    case NBPF_Q_IP:   n->protocol = 0x800;  break;
    case NBPF_Q_IPV6: n->protocol = 0x86DD; break;
    case NBPF_Q_TCP:  n->protocol = 6;      break;
    case NBPF_Q_UDP:  n->protocol = 17;     break;
    case NBPF_Q_SCTP: n->protocol = 132;    break;
    //default:     n->protocol = proto;  break;
  }

  return n;
}

/* ****************************************************** */

nbpf_node_t *nbpf_create_relation_node(int relop, nbpf_arth_t l, int r) {
  nbpf_node_t *n = nbpf_create_protocol_node(l.protocol);

  n->qualifiers.address = NBPF_Q_PROTO_REL;

  n->byte_match.protocol = l.protocol; /* NBPF_Q_IP, .. */
  n->byte_match.offset = l.offset;
  n->byte_match.mask = l.mask;
  n->byte_match.relop = relop;
  n->byte_match.value = r;

  return n;
}

/* ****************************************************** */

nbpf_node_t *nbpf_create_vlan_node(int vlan_id) { 
  nbpf_node_t *n = alloc_node();

  n->type = N_PRIMITIVE;
  n->qualifiers.protocol = NBPF_Q_LINK;
  n->qualifiers.address = NBPF_Q_VLAN;

  if (vlan_id != -1) {
    n->vlan_id_defined = 1;
    n->vlan_id = vlan_id;
  }

  return n;
}

/* ****************************************************** */

nbpf_node_t *nbpf_create_mpls_node(int label) { 
  nbpf_node_t *n = alloc_node();

  n->type = N_PRIMITIVE;
  n->qualifiers.protocol = NBPF_Q_LINK;
  n->qualifiers.address = NBPF_Q_MPLS;

  if (label != -1) {
    n->mpls_label_defined = 1;
    n->mpls_label = label;
  }

  return n;
}

/* ****************************************************** */

nbpf_node_t *nbpf_create_gtp_node() { 
  nbpf_node_t *n = alloc_node();

  n->type = N_PRIMITIVE;
  n->qualifiers.protocol = NBPF_Q_GTP;

  return n;
}

/* ****************************************************** */

nbpf_node_t *nbpf_create_l7_node(u_int32_t id, const char *name) {
  nbpf_node_t *n = alloc_node();

  n->type = N_PRIMITIVE;
  n->qualifiers.address = NBPF_Q_L7PROTO;
  if (name == NULL)
    n->l7protocol = id;
  else {
    int p = -1;
#ifdef HAVE_NDPI
    int i, num = ndpi_get_num_supported_protocols(ndpi_struct);
    for (i = 0; i < num && p == -1; i++)
      if (strcasecmp(ndpi_get_proto_by_id(ndpi_struct, i), name) == 0)
        p = i;
    if (p == -1) {
      nbpf_syntax_error("Unexpected l7 protocol '%s'\n", name);
      p = 0;
    }
#else
    if (l7proto_by_name != NULL) {
      p = l7proto_by_name(name);
      if (p < 0) p = 0;
    } else {
      nbpf_syntax_error("l7proto with protocol name not supported (nBPF library compiled without nDPI support)\n");
      p = 0;
    }
#endif
    n->l7protocol = p;
  }

  return n;
}

/* *********************************************************** */

int is_emptyv6(struct nbpf_in6_addr *a) {
  int i;

  for(i=0; i<4; i++)
    if(a->u6_addr.u6_addr32[i] != 0)
      return(0);

  return(1);
}

/* ****************************************************** */

