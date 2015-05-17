/*
 *
 * (C) 2005-14 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */


#ifndef _PFRING_UTILS_H_
#define _PFRING_UTILS_H_

#define __LITTLE_ENDIAN_BITFIELD /* FIX */

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
  u_int32_t	tot_len:16,
  		tos:8,
  		ihl:4,
  		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
  u_int32_t	version:4,
  		ihl:4,
  		tos:8,
  		tot_len:16;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
  u_int16_t	id;
#define IP_CE		0x8000
#define IP_DF		0x4000
#define IP_MF		0x2000
#define IP_OFFSET	0x1FFF
  u_int16_t	frag_off;
  u_int8_t	ttl;
  u_int8_t	protocol;
  u_int16_t	check;
  u_int32_t	saddr;
  u_int32_t	daddr;
  /*The options start here. */
};

struct tcphdr {
  u_int16_t	source;
  u_int16_t	dest;
  u_int32_t	seq;
  u_int32_t	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
  u_int16_t	res1:4,
    doff:4,
    fin:1,
    syn:1,
    rst:1,
    psh:1,
    ack:1,
    urg:1,
    ece:1,
    cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
  u_int16_t	doff:4,
    res1:4,
    cwr:1,
    ece:1,
    urg:1,
    ack:1,
    psh:1,
    rst:1,
    syn:1,
    fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
  u_int16_t	window;
  u_int16_t	check;
  u_int16_t	urg_ptr;
};

struct udphdr {
  u_int16_t	source;
  u_int16_t	dest;
  u_int16_t	len;
  u_int16_t	check;
};

#define TH_FIN_MULTIPLIER	0x01
#define TH_SYN_MULTIPLIER	0x02
#define TH_RST_MULTIPLIER	0x04
#define TH_PUSH_MULTIPLIER	0x08
#define TH_ACK_MULTIPLIER	0x10
#define TH_URG_MULTIPLIER	0x20

#endif /* _PFRING_UTILS_H_ */

