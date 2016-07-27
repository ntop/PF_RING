/*
 *  Copyright (C) 2016 ntop.org
 *
 *      http://www.ntop.org/
 *
 */

#include "parser.h"

static u_int32_t errors = 0;
static fast_bpf_tree_t tree_root = { NULL };
static l7protocol_by_name_func l7proto_by_name = NULL;
#ifdef HAVE_NDPI
static struct ndpi_detection_module_struct *ndpi_struct = NULL;
#endif

/*
static char *dir_to_string[] =   { "SrcOrDst", "Src", "Dst", "SrcOrDst", "SrcAndDst", "?", "?", "?", "?" };
static char *addr_to_string[] =  { "Host", "Host", "Net", "Port", "?", "Proto", "?", "PortRange", "VLAN" };
static char *proto_to_string[] = { "IP", "Eth", "IP", "?", "?", "SCTP", "TCP", "UDP" };
*/

/* ****************************************** */

static fast_bpf_node_t *alloc_node() {
  fast_bpf_node_t *n;

  n = (fast_bpf_node_t *) calloc(1, sizeof(fast_bpf_node_t));

  if (n == NULL) {
    fprintf(stderr, "Error in memory allocation\n");
    /* exit(-1); */
  }

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

void fast_bpf_syntax_error(char *format, ...) {
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

#ifdef DEBUG
static char hex[] = "0123456789ABCDEF";

static char *ethtoa(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return buf;
}

/* ****************************************** */

static char *intoa(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  retStr = (char*)(cp+1);

  return retStr;
}

/* ****************************************** */

static void print_padding(char ch, int n) {
  int i;
  for (i = 0; i < n; i++)
    putchar(ch);
}

/* ****************************************** */

static void print_tree(fast_bpf_node_t *n, int level)
{
  char type_str[1024];
  char tmp[32];

  if (n == NULL)
    return;
  
  switch(n->type) {
    case N_PRIMITIVE:
      sprintf(type_str, "");

      if (n->qualifiers.header == Q_INNER)
        sprintf(type_str, "%s INNER", type_str);

      sprintf(type_str, "%s %s %s", type_str,
        dir_to_string[n->qualifiers.direction], 
	addr_to_string[n->qualifiers.address]);
      
      if (n->qualifiers.protocol <= Q_UDP)
        sprintf(type_str, "%s Proto:%s", type_str, proto_to_string[n->qualifiers.protocol]);
      else if (n->qualifiers.protocol == Q_IPV6)
        sprintf(type_str, "%s Proto:%s", type_str, "IPv6");
      else
        sprintf(type_str, "%s Proto:%d", type_str, n->qualifiers.protocol);


      if (n->qualifiers.protocol == Q_LINK) {
        if (n->qualifiers.address == Q_VLAN) {
          sprintf(type_str, "%s VLAN", type_str);
          if (n->vlan_id_defined) sprintf(type_str, "%s:%u", type_str, n->vlan_id);
        } else {
          sprintf(type_str, "%s MAC:%s", type_str, ethtoa(n->mac, tmp));
        }

      } else if (n->qualifiers.protocol == Q_DEFAULT || n->qualifiers.protocol == Q_IP) {
        if (n->qualifiers.address == Q_DEFAULT || n->qualifiers.address == Q_HOST) {
          sprintf(type_str, "%s IP:%s", type_str, intoa(ntohl(n->ip), tmp, sizeof(tmp)));
        } else if (n->qualifiers.address == Q_NET) {
          sprintf(type_str, "%s Net:%s", type_str, intoa(ntohl(n->ip & n->mask), tmp, sizeof(tmp)));
	}

      } else if (n->qualifiers.protocol == Q_IPV6) {
	sprintf(type_str, "%s IPv6: %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X", type_str,
	        n->ip6[0], n->ip6[1], n->ip6[2],  n->ip6[3],  n->ip6[4],  n->ip6[5],  n->ip6[6],  n->ip6[7],
	        n->ip6[8], n->ip6[9], n->ip6[10], n->ip6[11], n->ip6[12], n->ip6[13], n->ip6[14], n->ip6[15]);
      }

      if (n->qualifiers.address == Q_PORT) {
        sprintf(type_str, "%s Port:%d", type_str, ntohs(n->port_from));
	if (n->port_to != n->port_from) sprintf(type_str, "%s-%d", type_str, ntohs(n->port_to)); 
      }
      
      break;
    case N_AND:
      sprintf(type_str, "AND");
      break;
    case N_OR:
      sprintf(type_str, "OR");
      break;
    default:
      sprintf(type_str, "?");
  }

  print_tree(n->r, level + 1);
  print_padding('\t', level);
  printf("%s%s\n", n->not ? "!" : "", type_str);
  print_tree(n->l, level + 1);
}
#endif

/* ****************************************** */

void fast_bpf_set_tree_root(fast_bpf_node_t *n) {
  tree_root.root = n;
#ifdef DEBUG
  DEBUG_PRINTF("BPF primitives tree:\n\n");
  print_tree(tree_root.root, 0);
  printf("\n");
#endif
}

/* ****************************************** */

static fast_bpf_node_t* node_clone(fast_bpf_node_t *t) {
  fast_bpf_node_t *root;

  if (t == NULL)
    return NULL;
  
  root = alloc_node();

  if (!root) 
    return NULL; 

  memcpy(root, t, sizeof(fast_bpf_node_t));
  root->l = node_clone(t->l);
  root->r = node_clone(t->r);
  return root;
}

/* ****************************************** */

fast_bpf_tree_t* tree_clone(fast_bpf_tree_t *t) {
  fast_bpf_tree_t *c = (fast_bpf_tree_t *) malloc(sizeof(fast_bpf_tree_t));

  if (!c) 
    return NULL;
  
  c->root = node_clone(t->root);
  return c;
}

/* ****************************************** */

static void node_purge(fast_bpf_node_t *n) {
  if (n->l) node_purge(n->l);
  if (n->r) node_purge(n->r);
  free(n);
}

/* ****************************************** */

void fast_bpf_free(fast_bpf_tree_t *t) {
  if (!t) return;
  if (t->root) node_purge(t->root);
  free(t);
}

/* ****************************************** */

static fast_bpf_tree_t *tree_parse(char *buffer) {
#ifdef HAVE_NDPI
  ndpi_struct = ndpi_init_detection_module();

  if (ndpi_struct == NULL) 
    return NULL;
#endif

  fast_bpf_lex_init(buffer);

  errors = 0;
  yyparse();

  fast_bpf_lex_cleanup();

  if (errors) {
    return NULL;
  }

#ifdef HAVE_NDPI
  ndpi_exit_detection_module(ndpi_struct);
#endif

  return &tree_root;
}

/* ****************************************** */

fast_bpf_tree_t *fast_bpf_parse(char *bpf_filter, l7protocol_by_name_func l7proto_by_name_callback) {
  fast_bpf_tree_t *t = (fast_bpf_tree_t *) malloc(sizeof(fast_bpf_tree_t));

  if (t == NULL)
    return NULL;

  l7proto_by_name = l7proto_by_name_callback;

  if (tree_parse(bpf_filter) == NULL) {
    free(t);
    return NULL;
  }

  t->root = tree_root.root;

  return t;
}

/* ****************************************** */

fast_bpf_node_t *fast_bpf_create_and(fast_bpf_node_t *n1, fast_bpf_node_t *n2) {
  fast_bpf_node_t *n = alloc_node();
  
  n->type = N_AND; 
  n->l = n1;
  n->r = n2;
  
  return n;
}

/* ****************************************** */

fast_bpf_node_t *fast_bpf_create_or(fast_bpf_node_t *n1, fast_bpf_node_t *n2) {
  fast_bpf_node_t *n = alloc_node();

  n->type = N_OR;
  n->l = n1;
  n->r = n2;

  return n;
}

/* ****************************************** */

fast_bpf_node_t *fast_bpf_create_portrange_node(const char *range, fast_bpf_qualifiers_t q) {
  fast_bpf_node_t *n = alloc_node();
  int proto = q.protocol;
  int port1, port2;
  
  if (proto != Q_DEFAULT && proto != Q_UDP && proto != Q_TCP && proto != Q_SCTP)
    fast_bpf_syntax_error("illegal qualifier of 'portrange'");

  if (sscanf(range, "%d-%d", &port1, &port2) != 2)
    fast_bpf_syntax_error("illegal 'portrange' value");

  n->type = N_PRIMITIVE;
  n->qualifiers = q;
  n->port_from = htons(port1);
  n->port_to = htons(port2);

  return n;
}

/* ****************************************** */

fast_bpf_node_t *fast_bpf_create_eth_node(const u_char *eaddr, fast_bpf_qualifiers_t q) { 
  fast_bpf_node_t *n = alloc_node();

  n->type = N_PRIMITIVE;
  n->qualifiers = q;
  memcpy(n->mac, eaddr, sizeof(n->mac));

  switch (q.direction) {
   case Q_SRC:
    case Q_DST:
    case Q_AND:
    case Q_OR: case Q_DEFAULT:
      break;
    default:
      fast_bpf_syntax_error("eth address applied to unsupported direction");
  }

  return n;
}

/* ****************************************** */

fast_bpf_node_t *__fast_bpf_create_net_node(u_int32_t net, u_int32_t mask, fast_bpf_qualifiers_t q) {
  fast_bpf_node_t *n = alloc_node();

  n->type = N_PRIMITIVE;
  n->qualifiers = q;
  n->ip = htonl(net);
  n->mask = htonl(mask);

  switch (q.direction) {
    case Q_SRC:
    case Q_DST:
    case Q_AND:
    case Q_OR: case Q_DEFAULT:
      break;
    default:
      fast_bpf_syntax_error("host or net applied to unsupported direction");
  }

  return n;
}

/* ****************************************** */

fast_bpf_node_t *fast_bpf_create_host_node(const char *s, fast_bpf_qualifiers_t q) {
  u_int32_t hh, mask = 0xffffffff;
  int vlen;
  
  if (q.address != Q_DEFAULT &&
      q.address != Q_HOST &&
      q.address != Q_NET /* && 
      q.address != Q_GATEWAY */)
    fast_bpf_syntax_error("ip syntax for host and network only");

  vlen = atoin(s, &hh);

  hh <<= 32 - vlen;
  mask <<= 32 - vlen;

  return __fast_bpf_create_net_node(hh, mask, q);
}

/* ****************************************** */

fast_bpf_node_t *fast_bpf_create_net_node(const char *net, const char *netmask, 
				 int masklen, fast_bpf_qualifiers_t q) {
  int nlen, mlen;
  u_int32_t nn, mask;

  if (q.address != Q_NET)
    fast_bpf_syntax_error("mask syntax for networks only");

  switch (q.protocol) {
    case Q_DEFAULT:
    case Q_IP:
      /* Ok */
      break;
    /* case Q_ARP:  */
    /* case Q_RARP: */
    default:
      fast_bpf_syntax_error("net mask applied to unsupported protocol");
  }

  nlen = atoin(net, &nn);
  nn <<= 32 - nlen;

  if (netmask != NULL) {
    mlen = atoin(netmask, &mask);
    mask <<= 32 - mlen;
    if ((nn & ~mask) != 0)
      fast_bpf_syntax_error("non-network bits set in \"%s mask %s\"", net, netmask);
  } else {
  /* Convert mask len to mask */
    if (masklen > 32)
      fast_bpf_syntax_error("mask length must be <= 32");

    if (masklen == 0)
      mask = 0;
    else
      mask = 0xffffffff << (32 - masklen);

    if ((nn & ~mask) != 0)
      fast_bpf_syntax_error("non-network bits set in \"%s/%d\"", net, masklen);
  }

  return __fast_bpf_create_net_node(nn, mask, q); 
}

/* ****************************************** */

fast_bpf_node_t *fast_bpf_create_net6_node(const char *net, int masklen, fast_bpf_qualifiers_t q) {
  fast_bpf_node_t *n = alloc_node();
  struct addrinfo *res;
  struct in6_addr *addr;
  struct in6_addr mask;
  u_int32_t *a, *m;

  res = nametoaddrinfo(net);

  if (!res)
    fast_bpf_syntax_error("invalid ip6 address %s", net);

  if (res->ai_next)
    fast_bpf_syntax_error("%s resolved to multiple address", net);

  addr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;

  if (sizeof(mask) * 8 < masklen)
    fast_bpf_syntax_error("mask length must be <= %u", (unsigned int)(sizeof(mask) * 8));
  
  memset(&mask, 0, sizeof(mask));
  memset(&mask, 0xff, masklen / 8);
  if (masklen % 8)
    mask.s6_addr[masklen / 8] = (0xff << (8 - masklen % 8)) & 0xff;

  a = (u_int32_t *)addr;
  m = (u_int32_t *)&mask;

  if ((a[0] & ~m[0]) || (a[1] & ~m[1]) || (a[2] & ~m[2]) || (a[3] & ~m[3]))
    fast_bpf_syntax_error("non-network bits set in \"%s/%d\"", net, masklen);

  switch (q.address) {
    case Q_DEFAULT:
    case Q_HOST:
      if (masklen != 128)
        fast_bpf_syntax_error("mask syntax for networks only");
    case Q_NET:
      /* Ok */
      break;
    default:
      fast_bpf_syntax_error("invalid qualifier against IPv6 address");
      freeaddrinfo(res);
      return n; /* a dummy node */
  }

  switch (q.protocol) {
    case Q_DEFAULT:
    case Q_IPV6:
      /* Ok */
      break;
    default:
      fast_bpf_syntax_error("invalid proto modifies applied to ipv6");
  }

  n->type = N_PRIMITIVE;
  n->qualifiers = q;
  
  memcpy(n->ip6,   a, sizeof(n->ip6));
  memcpy(n->mask6, m, sizeof(n->mask6));

  switch (q.direction) {
    case Q_SRC:
    case Q_DST:
    case Q_AND:
    case Q_OR: case Q_DEFAULT:
      break;
    default:
      fast_bpf_syntax_error("net mask applied to unsupported direction");
  }

  freeaddrinfo(res);
  return n;
}

/* ****************************************** */

fast_bpf_node_t *fast_bpf_create_n_node(u_int32_t nn, fast_bpf_qualifiers_t q) {
  fast_bpf_node_t *n;
  u_int32_t mask = 0xffffffff;

  switch (q.address) {
    case Q_DEFAULT:
    case Q_HOST:
    case Q_NET:
      if (q.address == Q_NET) {
        while (nn && (nn & 0xff000000) == 0) {
          nn <<= 8;
          mask <<= 8;
        }
      }
      
      n = __fast_bpf_create_net_node(nn, mask, q);

      break;
    case Q_PORT:
    case Q_PORTRANGE:

      if (q.protocol != Q_DEFAULT &&
          q.protocol != Q_UDP &&
          q.protocol != Q_TCP &&
          q.protocol != Q_SCTP)
        fast_bpf_syntax_error("illegal qualifier of 'port'");
      
      n = alloc_node();

      n->type = N_PRIMITIVE;
      n->qualifiers = q;
      n->port_from = n->port_to = htons(nn);
     
      break;
    case Q_PROTO:
      
      n = alloc_node();

      n->type = N_PRIMITIVE;
      n->qualifiers = q;
      n->protocol = nn;
      
      break;
    default:
      fast_bpf_syntax_error("unexpected number for the specified address qualifier");
      n = alloc_node(); /* a dummy node */
  }

  return n;
}

void fast_bpf_create_not(fast_bpf_node_t *n) {
  n->not_rule = !n->not_rule;
}

/* ****************************************************** */

fast_bpf_node_t *fast_bpf_create_proto_node(int proto) { 
  fast_bpf_node_t *n = alloc_node();

  n->type = N_PRIMITIVE;
  n->qualifiers.protocol = proto;
  n->qualifiers.address = Q_PROTO;

  switch (proto) {
    case Q_IP:
    case Q_IPV6:
      n->qualifiers.protocol = Q_LINK;
      break;
    case Q_TCP:
    case Q_UDP:
    case Q_SCTP:
      n->qualifiers.protocol = Q_IP;
      break;
    default:
      fast_bpf_syntax_error("Unexpected protocol\n"); 
  }

  switch (proto) {
    case Q_IP:   n->protocol = 0x800;  break;
    case Q_IPV6: n->protocol = 0x86DD; break;
    case Q_TCP:  n->protocol = 6;      break;
    case Q_UDP:  n->protocol = 17;     break;
    case Q_SCTP: n->protocol = 132;    break;
  }

  return n;
}

/* ****************************************************** */

fast_bpf_node_t *fast_bpf_create_vlan_node(int vlan_id) { 
  fast_bpf_node_t *n = alloc_node();

  n->type = N_PRIMITIVE;
  n->qualifiers.protocol = Q_LINK;
  n->qualifiers.address = Q_VLAN;

  if (vlan_id != -1) {
    n->vlan_id_defined = 1;
    n->vlan_id = vlan_id;
  }

  return n;
}

/* ****************************************************** */

fast_bpf_node_t *fast_bpf_create_l7_node(u_int32_t id, const char *name) {
  fast_bpf_node_t *n = alloc_node();

  n->type = N_PRIMITIVE;
  n->qualifiers.address = Q_L7PROTO;
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
      fast_bpf_syntax_error("Unexpected l7 protocol '%s'\n", name);
      p = 0;
    }
#else
    if (l7proto_by_name != NULL) {
      p = l7proto_by_name(name);
      if (p < 0) p = 0;
    } else {
      fast_bpf_syntax_error("l7proto with protocol name not supported (FastBPF library compiled without nDPI support)\n");
      p = 0;
    }
#endif
    n->l7protocol = p;
  }

  return n;
}

/* ****************************************************** */

