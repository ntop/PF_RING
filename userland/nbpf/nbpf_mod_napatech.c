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

#include <stdio.h>

#include "nbpf.h"
#include "parser.h"

/* *********************************************************** */

void bpf_init_napatech_rules(u_int8_t stream_id, void *opt,
			     int (execCmd)(void *opt, char *cmd)) {
  if(execCmd) execCmd(opt, "DefineMacro(\"mUdpSrcPort\",\"Data[DynOffset=DynOffUDPFrame;Offset=0;DataType=ByteStr2]\")");
  if(execCmd) execCmd(opt, "DefineMacro(\"mUdpDestPort\",\"Data[DynOffset=DynOffUDPFrame;Offset=2;DataType=ByteStr2]\")");
  if(execCmd) execCmd(opt, "DefineMacro(\"mTcpSrcPort\",\"Data[DynOffset=DynOffTCPFrame;Offset=0;DataType=ByteStr2]\")");
  if(execCmd) execCmd(opt, "DefineMacro(\"mTcpDestPort\",\"Data[DynOffset=DynOffTCPFrame;Offset=2;DataType=ByteStr2]\")");
  if(execCmd) execCmd(opt, "DefineMacro(\"mIPv4SrcAddr\",\"Data[DynOffset=DynOffIPv4Frame;Offset=12;DataType=IPv4Addr]\")");
  if(execCmd) execCmd(opt, "DefineMacro(\"mIPv4DestAddr\",\"Data[DynOffset=DynOffIPv4Frame;Offset=16;DataType=IPv4Addr]\")");
  if(execCmd) execCmd(opt, "DefineMacro(\"mIPv6SrcAddr\",\"Data[DynOffset=DynOffIPv6Frame;Offset=8;DataType=IPv6Addr]\")");
  if(execCmd) execCmd(opt, "DefineMacro(\"mIPv6DestAddr\",\"Data[DynOffset=DynOffIPv6Frame;Offset=24;DataType=IPv6Addr]\")");
}

/* *********************************************************** */

void bpf_rule_to_napatech(u_int8_t stream_id, u_int8_t port_id, void *opt,
			  char *cmd, u_int cmd_len,
			  nbpf_rule_core_fields_t *c,
			  int (execCmd)(void *opt, char *cmd)) {
  char *proto = "", buf[256];
  int num_cmds = 0;

  cmd[0] = '\0';
  snprintf(buf, sizeof(buf), "Assign[StreamId = %u] = Port == %u AND ", stream_id, port_id);

  bpf_append_str(cmd, cmd_len, 0, 1, buf);

  if(c->vlan_id)
    bpf_append_str(cmd, cmd_len, num_cmds++, 1, "((Encapsulation == VLAN)");

  switch(c->proto) {
  case 1:  bpf_append_str(cmd, cmd_len, num_cmds++, 1, "(Layer4Protocol == ICMP)"); break;
  case 6:  bpf_append_str(cmd, cmd_len, num_cmds++, 1, "(Layer4Protocol == TCP)"), proto = "Tcp";  break;
  case 17: bpf_append_str(cmd, cmd_len, num_cmds++, 1, "(Layer4Protocol == UDP)"), proto = "Udp";  break;
  }

  if(c->ip_version == 4) {
    char a[32];

    if(c->shost.v4) { 
      snprintf(buf, sizeof(buf), "mIPv4%sAddr == [%s]", "Src", bpf_intoaV4(ntohl(c->shost.v4), a, sizeof(a))); 
      bpf_append_str(cmd, cmd_len, num_cmds++, 1, buf); 
    }
    
    if(c->dhost.v4) { 
      snprintf(buf, sizeof(buf), "mIPv4%sAddr == [%s]", "Dest", bpf_intoaV4(ntohl(c->dhost.v4), a, sizeof(a))); 
      bpf_append_str(cmd, cmd_len, num_cmds++, 1, buf); 
    }
  } else if(c->ip_version == 6) {
    char a[64];

    if(!is_emptyv6(&c->shost.v6)) {    
      snprintf(buf, sizeof(buf), "mIPv6%sAddr == [%s]", "Src", bpf_intoaV6(&c->shost.v6, a, sizeof(a))); 
      bpf_append_str(cmd, cmd_len, num_cmds++, 1, buf); 
    }
    
    if(!is_emptyv6(&c->dhost.v6)) { 
      snprintf(buf, sizeof(buf), "mIPv6%sAddr == [%s]", "Dest", bpf_intoaV6(&c->dhost.v6, a, sizeof(a))); 
      bpf_append_str(cmd, cmd_len, num_cmds++, 1, buf); 
    }
  }

  if(c->sport_low > 0) { 
    snprintf(buf, sizeof(buf), "m%s%sPort == %u", proto, "Src",  ntohs(c->sport_low)); 
    bpf_append_str(cmd, cmd_len, num_cmds++, 1, buf); 
  }

  if(c->dport_low > 0) { 
    snprintf(buf, sizeof(buf), "m%s%sPort == %u", proto, "Dest", ntohs(c->dport_low)); 
    bpf_append_str(cmd, cmd_len, num_cmds++, 1, buf);
  }

  if(c->vlan_id) bpf_append_str(cmd, cmd_len, num_cmds++, 1, ")");

  if(execCmd) execCmd(opt, cmd);
}
