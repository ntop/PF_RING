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

#include <stdio.h>

#include "nbpf.h"
#include "parser.h"

/* *********************************************************** */

static void bpf_rule_to_fiberblaze(char *cmd, u_int cmd_len,
				   nbpf_rule_core_fields_t *c) {
  char buf[256];
  const char *proto = (c->proto == 6) ? "tcp" : "udp";
  int num_cmds = 0, l, multi = 0;

  if(c->vlan_id) multi++;
  if(c->proto)  multi++;
  if((c->ip_version == 4) && (c->shost.v4 || c->dhost.v4)) multi++;
  if((c->ip_version == 6) && ((!is_emptyv6(&c->shost.v6)) || (!is_emptyv6(&c->dhost.v6)))) multi++;
  if(c->sport_low > 0) multi++;
  if(c->dport_low > 0) multi++;
    
  if(multi > 1)
    cmd[0] = '(', cmd[1] = '\0';

  if(c->vlan_id) {
    snprintf(buf, sizeof(buf), "(vlan.id = %d)", c->vlan_id);
    bpf_append_str(cmd, cmd_len, num_cmds++, 0, buf);
  }

  if(c->proto) {
    snprintf(buf, sizeof(buf), "(ip.protocol = %d)", c->proto);
    bpf_append_str(cmd, cmd_len, num_cmds++, 0, buf);
  }

  if(c->ip_version == 4) {
    char a[32];

    if(c->shost.v4) {
      snprintf(buf, sizeof(buf), "(ip.src = %s/%u)", 
        bpf_intoaV4(ntohl(c->shost.v4 & c->shost_mask.v4), a, sizeof(a)), 
        32 - __builtin_ctz(ntohl(c->shost_mask.v4)));
      bpf_append_str(cmd, cmd_len, num_cmds++, 0, buf);
    }

    if(c->dhost.v4) {
      snprintf(buf, sizeof(buf), "(ip.dst = %s/%u)", 
        bpf_intoaV4(ntohl(c->dhost.v4 & c->dhost_mask.v4), a, sizeof(a)),
        32 - __builtin_ctz(ntohl(c->dhost_mask.v4)));
      bpf_append_str(cmd, cmd_len, num_cmds++, 0,  buf);
    }
  } else if(c->ip_version == 6) {
    char a[64];

    if(!is_emptyv6(&c->shost.v6)) {
      snprintf(buf, sizeof(buf), "(ip6.src = %s)", bpf_intoaV6(&c->shost.v6, a, sizeof(a)));
      bpf_append_str(cmd, cmd_len, num_cmds++, 0, buf);
    }

    if(!is_emptyv6(&c->dhost.v6)) {
      snprintf(buf, sizeof(buf), "(ip6.dst = %s)", bpf_intoaV6(&c->dhost.v6, a, sizeof(a)));
      bpf_append_str(cmd, cmd_len, num_cmds++, 0, buf);
    }
  }

  if(c->sport_low > 0) {
    if(c->sport_low == c->sport_high)
      snprintf(buf, sizeof(buf), "(%s.src = %d)",
	       proto,
	       ntohs(c->sport_low));
    else
      snprintf(buf, sizeof(buf), "(%s.src > %d and %s.src < %d)",
	       proto,
	       ntohs(c->sport_low),
	       proto,
	       ntohs(c->sport_high));

    bpf_append_str(cmd, cmd_len, num_cmds++, 0, buf);
  }

  if(c->dport_low > 0) {
    if(c->dport_low == c->dport_high)
      snprintf(buf, sizeof(buf), "(%s.dst = %d)",
	       proto,
	       ntohs(c->dport_low));
    else
      snprintf(buf, sizeof(buf), "(%s.dst > %d and %s.dst < %d)",
	       proto,
	       ntohs(c->dport_low),
	       proto,
	       ntohs(c->dport_high));
    bpf_append_str(cmd, cmd_len, num_cmds++, 0, buf);
  }

  l = strlen(cmd);

  if((multi > 1) && (l < (cmd_len-3)))
    cmd[l] = ')', cmd[l+1] = '\0';
}

/* *********************************************************** */

char* bpf_rules_to_fiberblaze(nbpf_rule_list_item_t *pun,
			      char *buf, u_int buf_len) {
  int n = 0, l, multi;

  if(pun && pun->next)
    buf[0] = '(', buf[1] = '\0', multi = 1;
  else
    buf[0] = '\0', multi = 0;

  while(pun != NULL) {
    l = strlen(buf);

    if(n > 0) {
      bpf_append_str(&buf[l], buf_len-l-1, 0, 0, " or ");
      l = strlen(buf);
    }

    bpf_rule_to_fiberblaze(&buf[l], buf_len-l-1, &pun->fields);

    pun = pun->next, n++;
  }

  l = strlen(buf);

  if(multi && (l < buf_len-3))
    buf[l] = ')', buf[l+1] = '\0';

  return(buf);
}
