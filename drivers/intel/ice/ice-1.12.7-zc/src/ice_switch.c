/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#include "ice_common.h"
#include "ice_switch.h"
#include "ice_flex_type.h"
#include "ice_flow.h"

#define ICE_ETH_DA_OFFSET		0
#define ICE_ETH_ETHTYPE_OFFSET		12
#define ICE_ETH_VLAN_TCI_OFFSET		14
#define ICE_MAX_VLAN_ID			0xFFF
#define ICE_IPV6_ETHER_ID		0x86DD
#define ICE_PPP_IPV6_PROTO_ID		0x0057

/* Dummy ethernet header needed in the ice_sw_rule_*
 * struct to configure any switch filter rules.
 * {DA (6 bytes), SA(6 bytes),
 * Ether type (2 bytes for header without VLAN tag) OR
 * VLAN tag (4 bytes for header with VLAN tag) }
 *
 * Word on Hardcoded values
 * byte 0 = 0x2: to identify it as locally administered DA MAC
 * byte 6 = 0x2: to identify it as locally administered SA MAC
 * byte 12 = 0x81 & byte 13 = 0x00:
 *	In case of VLAN filter first two bytes defines ether type (0x8100)
 *	and remaining two bytes are placeholder for programming a given VLAN ID
 *	In case of Ether type filter it is treated as header without VLAN tag
 *	and byte 12 and 13 is used to program a given Ether type instead
 */
static const u8 dummy_eth_header[DUMMY_ETH_HDR_LEN] = { 0x2, 0, 0, 0, 0, 0,
							0x2, 0, 0, 0, 0, 0,
							0x81, 0, 0, 0};

static const struct ice_dummy_pkt_offsets dummy_gre_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_NVGRE,		34 },
	{ ICE_MAC_IL,		42 },
	{ ICE_ETYPE_IL,		54 },
	{ ICE_IPV4_IL,		56 },
	{ ICE_TCP_IL,		76 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_gre_tcp_packet[] = {
	0x00, 0x00, 0x00, 0x00,	/* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_OL 12 */

	0x45, 0x00, 0x00, 0x3E,	/* ICE_IPV4_OFOS 14 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x2F, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x80, 0x00, 0x65, 0x58,	/* ICE_NVGRE 34 */
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00,	/* ICE_MAC_IL 42 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_IL 54 */

	0x45, 0x00, 0x00, 0x14,	/* ICE_IPV4_IL 56 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00,	/* ICE_TCP_IL 76 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x02, 0x20, 0x00,
	0x00, 0x00, 0x00, 0x00
};

static const struct ice_dummy_pkt_offsets dummy_gre_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_NVGRE,		34 },
	{ ICE_MAC_IL,		42 },
	{ ICE_ETYPE_IL,		54 },
	{ ICE_IPV4_IL,		56 },
	{ ICE_UDP_ILOS,		76 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_gre_udp_packet[] = {
	0x00, 0x00, 0x00, 0x00,	/* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_OL 12 */

	0x45, 0x00, 0x00, 0x3E,	/* ICE_IPV4_OFOS 14 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x2F, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x80, 0x00, 0x65, 0x58,	/* ICE_NVGRE 34 */
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00,	/* ICE_MAC_IL 42 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_IL 54 */

	0x45, 0x00, 0x00, 0x14,	/* ICE_IPV4_IL 56 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00,	/* ICE_UDP_ILOS 76 */
	0x00, 0x08, 0x00, 0x00,
};

static const struct ice_dummy_pkt_offsets dummy_udp_tun_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_UDP_OF,		34 },
	{ ICE_VXLAN,		42 },
	{ ICE_GENEVE,		42 },
	{ ICE_VXLAN_GPE,	42 },
	{ ICE_MAC_IL,		50 },
	{ ICE_ETYPE_IL,		62 },
	{ ICE_IPV4_IL,		64 },
	{ ICE_TCP_IL,		84 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_udp_tun_tcp_packet[] = {
	0x00, 0x00, 0x00, 0x00,  /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_OL 12 */

	0x45, 0x00, 0x00, 0x5a, /* ICE_IPV4_OFOS 14 */
	0x00, 0x01, 0x00, 0x00,
	0x40, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x12, 0xb5, /* ICE_UDP_OF 34 */
	0x00, 0x46, 0x00, 0x00,

	0x00, 0x00, 0x65, 0x58, /* ICE_VXLAN 42 */
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_IL 50 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_IL 62*/

	0x45, 0x00, 0x00, 0x28, /* ICE_IPV4_IL 64 */
	0x00, 0x01, 0x00, 0x00,
	0x40, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_TCP_IL 84 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x02, 0x20, 0x00,
	0x00, 0x00, 0x00, 0x00
};

static const struct ice_dummy_pkt_offsets dummy_udp_tun_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_UDP_OF,		34 },
	{ ICE_VXLAN,		42 },
	{ ICE_GENEVE,		42 },
	{ ICE_VXLAN_GPE,	42 },
	{ ICE_MAC_IL,		50 },
	{ ICE_ETYPE_IL,		62 },
	{ ICE_IPV4_IL,		64 },
	{ ICE_UDP_ILOS,		84 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_udp_tun_udp_packet[] = {
	0x00, 0x00, 0x00, 0x00,  /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_OL 12 */

	0x45, 0x00, 0x00, 0x4e, /* ICE_IPV4_OFOS 14 */
	0x00, 0x01, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x12, 0xb5, /* ICE_UDP_OF 34 */
	0x00, 0x3a, 0x00, 0x00,

	0x00, 0x00, 0x65, 0x58, /* ICE_VXLAN 42 */
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_IL 50 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_IL 62 */

	0x45, 0x00, 0x00, 0x1c, /* ICE_IPV4_IL 64 */
	0x00, 0x01, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_UDP_ILOS 84 */
	0x00, 0x08, 0x00, 0x00,
};

static const struct ice_dummy_pkt_offsets
dummy_gre_ipv6_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_NVGRE,		34 },
	{ ICE_MAC_IL,		42 },
	{ ICE_ETYPE_IL,		54 },
	{ ICE_IPV6_IL,		56 },
	{ ICE_TCP_IL,		96 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_gre_ipv6_tcp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_OL 12 */

	0x45, 0x00, 0x00, 0x66, /* ICE_IPV4_OFOS 14 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x2F, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x80, 0x00, 0x65, 0x58, /* ICE_NVGRE 34 */
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_IL 42 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x86, 0xdd,		/* ICE_ETYPE_IL 54 */

	0x60, 0x00, 0x00, 0x00, /* ICE_IPV6_IL 56 */
	0x00, 0x08, 0x06, 0x40,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_TCP_IL 96 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x02, 0x20, 0x00,
	0x00, 0x00, 0x00, 0x00
};

static const struct ice_dummy_pkt_offsets
dummy_gre_ipv6_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_NVGRE,		34 },
	{ ICE_MAC_IL,		42 },
	{ ICE_ETYPE_IL,		54 },
	{ ICE_IPV6_IL,		56 },
	{ ICE_UDP_ILOS,		96 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_gre_ipv6_udp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_OL 12 */

	0x45, 0x00, 0x00, 0x5a, /* ICE_IPV4_OFOS 14 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x2F, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x80, 0x00, 0x65, 0x58, /* ICE_NVGRE 34 */
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_IL 42 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x86, 0xdd,		/* ICE_ETYPE_IL 54 */

	0x60, 0x00, 0x00, 0x00, /* ICE_IPV6_IL 56 */
	0x00, 0x08, 0x11, 0x40,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_UDP_ILOS 96 */
	0x00, 0x08, 0x00, 0x00,
};

static const struct ice_dummy_pkt_offsets
dummy_udp_tun_ipv6_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_UDP_OF,		34 },
	{ ICE_VXLAN,		42 },
	{ ICE_GENEVE,		42 },
	{ ICE_VXLAN_GPE,	42 },
	{ ICE_MAC_IL,		50 },
	{ ICE_ETYPE_IL,		62 },
	{ ICE_IPV6_IL,		64 },
	{ ICE_TCP_IL,		104 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_udp_tun_ipv6_tcp_packet[] = {
	0x00, 0x00, 0x00, 0x00,	 /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_OL 12 */

	0x45, 0x00, 0x00, 0x6e, /* ICE_IPV4_OFOS 14 */
	0x00, 0x01, 0x00, 0x00,
	0x40, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x12, 0xb5, /* ICE_UDP_OF 34 */
	0x00, 0x5a, 0x00, 0x00,

	0x00, 0x00, 0x65, 0x58, /* ICE_VXLAN 42 */
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_IL 50 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x86, 0xdd,		/* ICE_ETYPE_IL 62 */

	0x60, 0x00, 0x00, 0x00, /* ICE_IPV6_IL 64 */
	0x00, 0x08, 0x06, 0x40,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_TCP_IL 104 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x02, 0x20, 0x00,
	0x00, 0x00, 0x00, 0x00
};

static const struct ice_dummy_pkt_offsets
dummy_udp_tun_ipv6_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_UDP_OF,		34 },
	{ ICE_VXLAN,		42 },
	{ ICE_GENEVE,		42 },
	{ ICE_VXLAN_GPE,	42 },
	{ ICE_MAC_IL,		50 },
	{ ICE_ETYPE_IL,		62 },
	{ ICE_IPV6_IL,		64 },
	{ ICE_UDP_ILOS,		104 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_udp_tun_ipv6_udp_packet[] = {
	0x00, 0x00, 0x00, 0x00,	 /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_OL 12 */

	0x45, 0x00, 0x00, 0x62, /* ICE_IPV4_OFOS 14 */
	0x00, 0x01, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x12, 0xb5, /* ICE_UDP_OF 34 */
	0x00, 0x4e, 0x00, 0x00,

	0x00, 0x00, 0x65, 0x58, /* ICE_VXLAN 42 */
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_IL 50 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x86, 0xdd,		/* ICE_ETYPE_IL 62 */

	0x60, 0x00, 0x00, 0x00, /* ICE_IPV6_IL 64 */
	0x00, 0x08, 0x11, 0x40,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_UDP_ILOS 104 */
	0x00, 0x08, 0x00, 0x00,
};

/* offset info for MAC + IPv4 + UDP dummy packet */
static const struct ice_dummy_pkt_offsets dummy_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_UDP_ILOS,		34 },
	{ ICE_PROTOCOL_LAST,	0 },
};

/* Dummy packet for MAC + IPv4 + UDP */
static const u8 dummy_udp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_OL 12 */

	0x45, 0x00, 0x00, 0x1c, /* ICE_IPV4_OFOS 14 */
	0x00, 0x01, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_UDP_ILOS 34 */
	0x00, 0x08, 0x00, 0x00,

	0x00, 0x00,	/* 2 bytes for 4 byte alignment */
};

/* offset info for MAC + VLAN + IPv4 + UDP dummy packet */
static const struct ice_dummy_pkt_offsets dummy_vlan_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_OFOS,	12 },
	{ ICE_ETYPE_OL,		16 },
	{ ICE_IPV4_OFOS,	18 },
	{ ICE_UDP_ILOS,		38 },
	{ ICE_PROTOCOL_LAST,	0 },
};

/* C-tag (801.1Q), IPv4:UDP dummy packet */
static const u8 dummy_vlan_udp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x81, 0x00, 0x00, 0x00, /* ICE_VLAN_OFOS 12 */

	0x08, 0x00,		/* ICE_ETYPE_OL 16 */

	0x45, 0x00, 0x00, 0x1c, /* ICE_IPV4_OFOS 18 */
	0x00, 0x01, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_UDP_ILOS 38 */
	0x00, 0x08, 0x00, 0x00,

	0x00, 0x00,	/* 2 bytes for 4 byte alignment */
};

/* offset info for MAC + IPv4 + TCP dummy packet */
static const struct ice_dummy_pkt_offsets dummy_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_TCP_IL,		34 },
	{ ICE_PROTOCOL_LAST,	0 },
};

/* Dummy packet for MAC + IPv4 + TCP */
static const u8 dummy_tcp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_OL 12 */

	0x45, 0x00, 0x00, 0x28, /* ICE_IPV4_OFOS 14 */
	0x00, 0x01, 0x00, 0x00,
	0x00, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_TCP_IL 34 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00,	/* 2 bytes for 4 byte alignment */
};

/* offset info for MAC + VLAN (C-tag, 802.1Q) + IPv4 + TCP dummy packet */
static const struct ice_dummy_pkt_offsets dummy_vlan_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_OFOS,	12 },
	{ ICE_ETYPE_OL,		16 },
	{ ICE_IPV4_OFOS,	18 },
	{ ICE_TCP_IL,		38 },
	{ ICE_PROTOCOL_LAST,	0 },
};

/* C-tag (801.1Q), IPv4:TCP dummy packet */
static const u8 dummy_vlan_tcp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x81, 0x00, 0x00, 0x00,	/* ICE_VLAN_OFOS 12 */

	0x08, 0x00,		/* ICE_ETYPE_OL 16 */

	0x45, 0x00, 0x00, 0x28, /* ICE_IPV4_OFOS 18 */
	0x00, 0x01, 0x00, 0x00,
	0x00, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_TCP_IL 38 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00,	/* 2 bytes for 4 byte alignment */
};

static const struct ice_dummy_pkt_offsets dummy_tcp_ipv6_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV6_OFOS,	14 },
	{ ICE_TCP_IL,		54 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_tcp_ipv6_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x86, 0xDD,		/* ICE_ETYPE_OL 12 */

	0x60, 0x00, 0x00, 0x00, /* ICE_IPV6_OFOS 40 */
	0x00, 0x14, 0x06, 0x00, /* Next header is TCP */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_TCP_IL 54 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, /* 2 bytes for 4 byte alignment */
};

/* C-tag (802.1Q): IPv6 + TCP */
static const struct ice_dummy_pkt_offsets
dummy_vlan_tcp_ipv6_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_OFOS,	12 },
	{ ICE_ETYPE_OL,		16 },
	{ ICE_IPV6_OFOS,	18 },
	{ ICE_TCP_IL,		58 },
	{ ICE_PROTOCOL_LAST,	0 },
};

/* C-tag (802.1Q), IPv6 + TCP dummy packet */
static const u8 dummy_vlan_tcp_ipv6_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x81, 0x00, 0x00, 0x00,	/* ICE_VLAN_OFOS 12 */

	0x86, 0xDD,		/* ICE_ETYPE_OL 16 */

	0x60, 0x00, 0x00, 0x00, /* ICE_IPV6_OFOS 18 */
	0x00, 0x14, 0x06, 0x00, /* Next header is TCP */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_TCP_IL 58 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, /* 2 bytes for 4 byte alignment */
};

/* IPv6 + UDP */
static const struct ice_dummy_pkt_offsets dummy_udp_ipv6_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV6_OFOS,	14 },
	{ ICE_UDP_ILOS,		54 },
	{ ICE_PROTOCOL_LAST,	0 },
};

/* IPv6 + UDP dummy packet */
static const u8 dummy_udp_ipv6_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x86, 0xDD,		/* ICE_ETYPE_OL 12 */

	0x60, 0x00, 0x00, 0x00, /* ICE_IPV6_OFOS 40 */
	0x00, 0x10, 0x11, 0x00, /* Next header UDP */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_UDP_ILOS 54 */
	0x00, 0x10, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* needed for ESP packets */
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, /* 2 bytes for 4 byte alignment */
};

/* C-tag (802.1Q): IPv6 + UDP */
static const struct ice_dummy_pkt_offsets
dummy_vlan_udp_ipv6_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_OFOS,	12 },
	{ ICE_ETYPE_OL,		16 },
	{ ICE_IPV6_OFOS,	18 },
	{ ICE_UDP_ILOS,		58 },
	{ ICE_PROTOCOL_LAST,	0 },
};

/* C-tag (802.1Q), IPv6 + UDP dummy packet */
static const u8 dummy_vlan_udp_ipv6_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x81, 0x00, 0x00, 0x00,/* ICE_VLAN_OFOS 12 */

	0x86, 0xDD,		/* ICE_ETYPE_OL 16 */

	0x60, 0x00, 0x00, 0x00, /* ICE_IPV6_OFOS 18 */
	0x00, 0x08, 0x11, 0x00, /* Next header UDP */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_UDP_ILOS 58 */
	0x00, 0x08, 0x00, 0x00,

	0x00, 0x00, /* 2 bytes for 4 byte alignment */
};

/* Outer IPv4 + Outer UDP + GTP + Inner IPv4 + Inner TCP */
static const struct ice_dummy_pkt_offsets dummy_ipv4_gtpu_ipv4_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_UDP_OF,		34 },
	{ ICE_GTP,		42 },
	{ ICE_IPV4_IL,		62 },
	{ ICE_TCP_IL,		82 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_ipv4_gtpu_ipv4_tcp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* Ethernet 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x58, /* IP 14 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x08, 0x68, /* UDP 34 */
	0x00, 0x44, 0x00, 0x00,

	0x34, 0xff, 0x00, 0x34, /* GTP-U Header 42 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x85,

	0x02, 0x00, 0x00, 0x00, /* GTP_PDUSession_ExtensionHeader 54 */
	0x00, 0x00, 0x00, 0x00,

	0x45, 0x00, 0x00, 0x28, /* IP 62 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* TCP 82 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, /* 2 bytes for 4 byte alignment */
};

/* Outer IPv4 + Outer UDP + GTP + Inner IPv4 + Inner UDP */
static const struct ice_dummy_pkt_offsets dummy_ipv4_gtpu_ipv4_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_UDP_OF,		34 },
	{ ICE_GTP,		42 },
	{ ICE_IPV4_IL,		62 },
	{ ICE_UDP_ILOS,		82 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_ipv4_gtpu_ipv4_udp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* Ethernet 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x4c, /* IP 14 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x08, 0x68, /* UDP 34 */
	0x00, 0x38, 0x00, 0x00,

	0x34, 0xff, 0x00, 0x28, /* GTP-U Header 42 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x85,

	0x02, 0x00, 0x00, 0x00, /* GTP_PDUSession_ExtensionHeader 54 */
	0x00, 0x00, 0x00, 0x00,

	0x45, 0x00, 0x00, 0x1c, /* IP 62 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* UDP 82 */
	0x00, 0x08, 0x00, 0x00,

	0x00, 0x00, /* 2 bytes for 4 byte alignment */
};

/* Outer IPv6 + Outer UDP + GTP + Inner IPv4 + Inner TCP */
static const struct ice_dummy_pkt_offsets dummy_ipv4_gtpu_ipv6_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_UDP_OF,		34 },
	{ ICE_GTP,		42 },
	{ ICE_IPV6_IL,		62 },
	{ ICE_TCP_IL,		102 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_ipv4_gtpu_ipv6_tcp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* Ethernet 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x6c, /* IP 14 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x08, 0x68, /* UDP 34 */
	0x00, 0x58, 0x00, 0x00,

	0x34, 0xff, 0x00, 0x48, /* GTP-U Header 42 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x85,

	0x02, 0x00, 0x00, 0x00, /* GTP_PDUSession_ExtensionHeader 54 */
	0x00, 0x00, 0x00, 0x00,

	0x60, 0x00, 0x00, 0x00, /* IPv6 62 */
	0x00, 0x14, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* TCP 102 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, /* 2 bytes for 4 byte alignment */
};

static const struct ice_dummy_pkt_offsets dummy_ipv4_gtpu_ipv6_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_UDP_OF,		34 },
	{ ICE_GTP,		42 },
	{ ICE_IPV6_IL,		62 },
	{ ICE_UDP_ILOS,		102 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_ipv4_gtpu_ipv6_udp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* Ethernet 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x60, /* IP 14 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x08, 0x68, /* UDP 34 */
	0x00, 0x4c, 0x00, 0x00,

	0x34, 0xff, 0x00, 0x3c, /* GTP-U Header 42 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x85,

	0x02, 0x00, 0x00, 0x00, /* GTP_PDUSession_ExtensionHeader 54 */
	0x00, 0x00, 0x00, 0x00,

	0x60, 0x00, 0x00, 0x00, /* IPv6 62 */
	0x00, 0x08, 0x11, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* UDP 102 */
	0x00, 0x08, 0x00, 0x00,

	0x00, 0x00, /* 2 bytes for 4 byte alignment */
};

static const struct ice_dummy_pkt_offsets dummy_ipv6_gtpu_ipv4_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_IPV6_OFOS,	14 },
	{ ICE_UDP_OF,		54 },
	{ ICE_GTP,		62 },
	{ ICE_IPV4_IL,		82 },
	{ ICE_TCP_IL,		102 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_ipv6_gtpu_ipv4_tcp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* Ethernet 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x86, 0xdd,

	0x60, 0x00, 0x00, 0x00, /* IPv6 14 */
	0x00, 0x44, 0x11, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x08, 0x68, /* UDP 54 */
	0x00, 0x44, 0x00, 0x00,

	0x34, 0xff, 0x00, 0x34, /* GTP-U Header 62 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x85,

	0x02, 0x00, 0x00, 0x00, /* GTP_PDUSession_ExtensionHeader 74 */
	0x00, 0x00, 0x00, 0x00,

	0x45, 0x00, 0x00, 0x28, /* IP 82 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* TCP 102 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, /* 2 bytes for 4 byte alignment */
};

static const struct ice_dummy_pkt_offsets dummy_ipv6_gtpu_ipv4_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_IPV6_OFOS,	14 },
	{ ICE_UDP_OF,		54 },
	{ ICE_GTP,		62 },
	{ ICE_IPV4_IL,		82 },
	{ ICE_UDP_ILOS,		102 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_ipv6_gtpu_ipv4_udp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* Ethernet 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x86, 0xdd,

	0x60, 0x00, 0x00, 0x00, /* IPv6 14 */
	0x00, 0x38, 0x11, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x08, 0x68, /* UDP 54 */
	0x00, 0x38, 0x00, 0x00,

	0x34, 0xff, 0x00, 0x28, /* GTP-U Header 62 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x85,

	0x02, 0x00, 0x00, 0x00, /* GTP_PDUSession_ExtensionHeader 74 */
	0x00, 0x00, 0x00, 0x00,

	0x45, 0x00, 0x00, 0x1c, /* IP 82 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* UDP 102 */
	0x00, 0x08, 0x00, 0x00,

	0x00, 0x00, /* 2 bytes for 4 byte alignment */
};

static const struct ice_dummy_pkt_offsets dummy_ipv6_gtpu_ipv6_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_IPV6_OFOS,	14 },
	{ ICE_UDP_OF,		54 },
	{ ICE_GTP,		62 },
	{ ICE_IPV6_IL,		82 },
	{ ICE_TCP_IL,		122 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_ipv6_gtpu_ipv6_tcp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* Ethernet 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x86, 0xdd,

	0x60, 0x00, 0x00, 0x00, /* IPv6 14 */
	0x00, 0x58, 0x11, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x08, 0x68, /* UDP 54 */
	0x00, 0x58, 0x00, 0x00,

	0x34, 0xff, 0x00, 0x48, /* GTP-U Header 62 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x85,

	0x02, 0x00, 0x00, 0x00, /* GTP_PDUSession_ExtensionHeader 74 */
	0x00, 0x00, 0x00, 0x00,

	0x60, 0x00, 0x00, 0x00, /* IPv6 82 */
	0x00, 0x14, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* TCP 122 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, /* 2 bytes for 4 byte alignment */
};

static const struct ice_dummy_pkt_offsets dummy_ipv6_gtpu_ipv6_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_IPV6_OFOS,	14 },
	{ ICE_UDP_OF,		54 },
	{ ICE_GTP,		62 },
	{ ICE_IPV6_IL,		82 },
	{ ICE_UDP_ILOS,		122 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_ipv6_gtpu_ipv6_udp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* Ethernet 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x86, 0xdd,

	0x60, 0x00, 0x00, 0x00, /* IPv6 14 */
	0x00, 0x4c, 0x11, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x08, 0x68, /* UDP 54 */
	0x00, 0x4c, 0x00, 0x00,

	0x34, 0xff, 0x00, 0x3c, /* GTP-U Header 62 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x85,

	0x02, 0x00, 0x00, 0x00, /* GTP_PDUSession_ExtensionHeader 74 */
	0x00, 0x00, 0x00, 0x00,

	0x60, 0x00, 0x00, 0x00, /* IPv6 82 */
	0x00, 0x08, 0x11, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* UDP 122 */
	0x00, 0x08, 0x00, 0x00,

	0x00, 0x00, /* 2 bytes for 4 byte alignment */
};

static const u8 dummy_ipv4_gtpu_ipv4_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x08, 0x00,

	0x45, 0x00, 0x00, 0x44, /* ICE_IPV4_OFOS 14 */
	0x00, 0x00, 0x40, 0x00,
	0x40, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x68, 0x08, 0x68, /* ICE_UDP_OF 34 */
	0x00, 0x00, 0x00, 0x00,

	0x34, 0xff, 0x00, 0x28,  /* ICE_GTP 42 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x85,

	0x02, 0x00, 0x00, 0x00, /* PDU Session extension header */
	0x00, 0x00, 0x00, 0x00,

	0x45, 0x00, 0x00, 0x14, /* ICE_IPV4_IL 62 */
	0x00, 0x00, 0x40, 0x00,
	0x40, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
};

static const
struct ice_dummy_pkt_offsets dummy_ipv4_gtp_no_pay_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_UDP_OF,		34 },
	{ ICE_GTP_NO_PAY,	42 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const
struct ice_dummy_pkt_offsets dummy_ipv6_gtp_no_pay_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_IPV6_OFOS,	14 },
	{ ICE_UDP_OF,		54 },
	{ ICE_GTP_NO_PAY,	62 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_ipv6_gtp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x86, 0xdd,

	0x60, 0x00, 0x00, 0x00, /* ICE_IPV6_OFOS 14 */
	0x00, 0x6c, 0x11, 0x00, /* Next header UDP*/
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x68, 0x08, 0x68, /* ICE_UDP_OF 54 */
	0x00, 0x00, 0x00, 0x00,

	0x30, 0x00, 0x00, 0x28, /* ICE_GTP 62 */
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00,
};

static const struct ice_dummy_pkt_offsets dummy_qinq_ipv4_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_EX,		12 },
	{ ICE_VLAN_IN,		16 },
	{ ICE_ETYPE_OL,		20 },
	{ ICE_IPV4_OFOS,	22 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_qinq_ipv4_pkt[] = {
	0x00, 0x00, 0x00, 0x00,	/* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x91, 0x00, 0x00, 0x00,	/* ICE_VLAN_EX 12 */
	0x81, 0x00, 0x00, 0x00,	/* ICE_VLAN_IN 16 */
	0x08, 0x00,		/* ICE_ETYPE_OL 20 */

	0x45, 0x00, 0x00, 0x14,	/* ICE_IPV4_OFOS 22 */
	0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00,		/* 2 bytes for 4 byte alignment */
};

static const
struct ice_dummy_pkt_offsets dummy_qinq_ipv4_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_EX,		12 },
	{ ICE_VLAN_IN,		16 },
	{ ICE_ETYPE_OL,		20 },
	{ ICE_IPV4_OFOS,	22 },
	{ ICE_UDP_ILOS,		42 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_qinq_ipv4_udp_pkt[] = {
	0x00, 0x00, 0x00, 0x00,	/* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x91, 0x00, 0x00, 0x00,	/* ICE_VLAN_EX 12 */
	0x81, 0x00, 0x00, 0x00,	/* ICE_VLAN_IN 16 */
	0x08, 0x00,		/* ICE_ETYPE_OL 20 */

	0x45, 0x00, 0x00, 0x1c,	/* ICE_IPV4_OFOS 22 */
	0x00, 0x01, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00,	/* ICE_UDP_ILOS 42 */
	0x00, 0x08, 0x00, 0x00,

	0x00, 0x00,		/* 2 bytes for 4 byte alignment */
};

static const
struct ice_dummy_pkt_offsets dummy_qinq_ipv4_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_EX,		12 },
	{ ICE_VLAN_IN,		16 },
	{ ICE_ETYPE_OL,		20 },
	{ ICE_IPV4_OFOS,	22 },
	{ ICE_TCP_IL,		42 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_qinq_ipv4_tcp_pkt[] = {
	0x00, 0x00, 0x00, 0x00,	/* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x91, 0x00, 0x00, 0x00,	/* ICE_VLAN_EX 12 */
	0x81, 0x00, 0x00, 0x00,	/* ICE_VLAN_IN 16 */
	0x08, 0x00,		/* ICE_ETYPE_OL 20 */

	0x45, 0x00, 0x00, 0x28,	/* ICE_IPV4_OFOS 22 */
	0x00, 0x01, 0x00, 0x00,
	0x00, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00,	/* ICE_TCP_IL 42 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00,		/* 2 bytes for 4 byte alignment */
};

static const struct ice_dummy_pkt_offsets dummy_qinq_ipv6_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_EX,		12 },
	{ ICE_VLAN_IN,		16 },
	{ ICE_ETYPE_OL,		20 },
	{ ICE_IPV6_OFOS,	22 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_qinq_ipv6_pkt[] = {
	0x00, 0x00, 0x00, 0x00,	/* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x91, 0x00, 0x00, 0x00,	/* ICE_VLAN_EX 12 */
	0x81, 0x00, 0x00, 0x00,	/* ICE_VLAN_IN 16 */
	0x86, 0xDD,		/* ICE_ETYPE_OL 20 */

	0x60, 0x00, 0x00, 0x00,	/* ICE_IPV6_OFOS 22 */
	0x00, 0x00, 0x3b, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00,		/* 2 bytes for 4 byte alignment */
};

static const
struct ice_dummy_pkt_offsets dummy_qinq_ipv6_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_EX,		12 },
	{ ICE_VLAN_IN,		16 },
	{ ICE_ETYPE_OL,		20 },
	{ ICE_IPV6_OFOS,	22 },
	{ ICE_UDP_ILOS,		62 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_qinq_ipv6_udp_pkt[] = {
	0x00, 0x00, 0x00, 0x00,	/* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x91, 0x00, 0x00, 0x00,	/* ICE_VLAN_EX 12 */
	0x81, 0x00, 0x00, 0x00,	/* ICE_VLAN_IN 16 */
	0x86, 0xDD,		/* ICE_ETYPE_OL 20 */

	0x60, 0x00, 0x00, 0x00,	/* ICE_IPV6_OFOS 22 */
	0x00, 0x08, 0x11, 0x00,	/* Next header UDP */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00,	/* ICE_UDP_ILOS 62 */
	0x00, 0x08, 0x00, 0x00,

	0x00, 0x00,		/* 2 bytes for 4 byte alignment */
};

static const
struct ice_dummy_pkt_offsets dummy_qinq_ipv6_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_EX,		12 },
	{ ICE_VLAN_IN,		16 },
	{ ICE_ETYPE_OL,		20 },
	{ ICE_IPV6_OFOS,	22 },
	{ ICE_TCP_IL,		62 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_qinq_ipv6_tcp_pkt[] = {
	0x00, 0x00, 0x00, 0x00,	/* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x91, 0x00, 0x00, 0x00,	/* ICE_VLAN_EX 12 */
	0x81, 0x00, 0x00, 0x00,	/* ICE_VLAN_IN 16 */
	0x86, 0xDD,		/* ICE_ETYPE_OL 20 */

	0x60, 0x00, 0x00, 0x00,	/* ICE_IPV6_OFOS 22 */
	0x00, 0x14, 0x06, 0x00,	/* Next header TCP */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00,	/* ICE_TCP_IL 62 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00,		/* 2 bytes for 4 byte alignment */
};

static const struct ice_dummy_pkt_offsets dummy_ipv4_l2tpv3_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV4_OFOS,	14 },
	{ ICE_L2TPV3,		34 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_ipv4_l2tpv3_pkt[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x08, 0x00,		/* ICE_ETYPE_OL 12 */

	0x45, 0x00, 0x00, 0x20, /* ICE_IPV4_IL 14 */
	0x00, 0x00, 0x40, 0x00,
	0x40, 0x73, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_L2TPV3 34 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,		/* 2 bytes for 4 bytes alignment */
};

static const struct ice_dummy_pkt_offsets dummy_ipv6_l2tpv3_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_ETYPE_OL,		12 },
	{ ICE_IPV6_OFOS,	14 },
	{ ICE_L2TPV3,		54 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_ipv6_l2tpv3_pkt[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x86, 0xDD,		/* ICE_ETYPE_OL 12 */

	0x60, 0x00, 0x00, 0x00, /* ICE_IPV6_IL 14 */
	0x00, 0x0c, 0x73, 0x40,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_L2TPV3 54 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,		/* 2 bytes for 4 bytes alignment */
};

static const
struct ice_dummy_pkt_offsets dummy_pppoe_ipv4_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_OFOS,	12 },
	{ ICE_ETYPE_OL,		16 },
	{ ICE_PPPOE,		18 },
	{ ICE_IPV4_OFOS,	26 },
	{ ICE_TCP_IL,		46 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_pppoe_ipv4_tcp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x81, 0x00, 0x00, 0x00,	/* ICE_VLAN_OFOS 12 */

	0x88, 0x64,		/* ICE_ETYPE_OL 16 */

	0x11, 0x00, 0x00, 0x00, /* ICE_PPPOE 18 */
	0x00, 0x16,

	0x00, 0x21,		/* PPP Link Layer 24 */

	0x45, 0x00, 0x00, 0x28, /* ICE_IPV4_OFOS 26 */
	0x00, 0x01, 0x00, 0x00,
	0x00, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_TCP_IL 46 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00,		/* 2 bytes for 4 bytes alignment */
};

static const
struct ice_dummy_pkt_offsets dummy_pppoe_ipv4_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_OFOS,	12 },
	{ ICE_ETYPE_OL,		16 },
	{ ICE_PPPOE,		18 },
	{ ICE_IPV4_OFOS,	26 },
	{ ICE_UDP_ILOS,		46 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_pppoe_ipv4_udp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x81, 0x00, 0x00, 0x00, /* ICE_VLAN_OFOS 12 */

	0x88, 0x64,		/* ICE_ETYPE_OL 16 */

	0x11, 0x00, 0x00, 0x00, /* ICE_PPPOE 18 */
	0x00, 0x16,

	0x00, 0x21,		/* PPP Link Layer 24 */

	0x45, 0x00, 0x00, 0x1c, /* ICE_IPV4_OFOS 26 */
	0x00, 0x01, 0x00, 0x00,
	0x00, 0x11, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_UDP_ILOS 46 */
	0x00, 0x08, 0x00, 0x00,

	0x00, 0x00,		/* 2 bytes for 4 bytes alignment */
};

static const
struct ice_dummy_pkt_offsets dummy_pppoe_ipv6_tcp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_OFOS,	12 },
	{ ICE_ETYPE_OL,		16 },
	{ ICE_PPPOE,		18 },
	{ ICE_IPV6_OFOS,	26 },
	{ ICE_TCP_IL,		66 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_pppoe_ipv6_tcp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x81, 0x00, 0x00, 0x00,	/* ICE_VLAN_OFOS 12 */

	0x88, 0x64,		/* ICE_ETYPE_OL 16 */

	0x11, 0x00, 0x00, 0x00, /* ICE_PPPOE 18 */
	0x00, 0x2a,

	0x00, 0x57,		/* PPP Link Layer 24 */

	0x60, 0x00, 0x00, 0x00, /* ICE_IPV6_OFOS 26 */
	0x00, 0x14, 0x06, 0x00, /* Next header is TCP */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_TCP_IL 66 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x50, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00,		/* 2 bytes for 4 bytes alignment */
};

static const
struct ice_dummy_pkt_offsets dummy_pppoe_ipv6_udp_packet_offsets[] = {
	{ ICE_MAC_OFOS,		0 },
	{ ICE_VLAN_OFOS,	12 },
	{ ICE_ETYPE_OL,		16 },
	{ ICE_PPPOE,		18 },
	{ ICE_IPV6_OFOS,	26 },
	{ ICE_UDP_ILOS,		66 },
	{ ICE_PROTOCOL_LAST,	0 },
};

static const u8 dummy_pppoe_ipv6_udp_packet[] = {
	0x00, 0x00, 0x00, 0x00, /* ICE_MAC_OFOS 0 */
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x81, 0x00, 0x00, 0x00, /* ICE_VLAN_OFOS 12 */

	0x88, 0x64,		/* ICE_ETYPE_OL 16 */

	0x11, 0x00, 0x00, 0x00, /* ICE_PPPOE 18 */
	0x00, 0x2a,

	0x00, 0x57,		/* PPP Link Layer 24 */

	0x60, 0x00, 0x00, 0x00, /* ICE_IPV6_OFOS 26 */
	0x00, 0x08, 0x11, 0x00, /* Next header UDP*/
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,

	0x00, 0x00, 0x00, 0x00, /* ICE_UDP_ILOS 66 */
	0x00, 0x08, 0x00, 0x00,

	0x00, 0x00,		/* 2 bytes for 4 bytes alignment */
};

/* this is a recipe to profile association bitmap */
static DECLARE_BITMAP(recipe_to_profile[ICE_MAX_NUM_RECIPES],
			  ICE_MAX_NUM_PROFILES);

/* this is a profile to recipe association bitmap */
static DECLARE_BITMAP(profile_to_recipe[ICE_MAX_NUM_PROFILES],
			  ICE_MAX_NUM_RECIPES);

static void ice_get_recp_to_prof_map(struct ice_hw *hw);

/**
 * ice_collect_result_idx - copy result index values
 * @buf: buffer that contains the result index
 * @recp: the recipe struct to copy data into
 */
static void ice_collect_result_idx(struct ice_aqc_recipe_data_elem *buf,
				   struct ice_sw_recipe *recp)
{
	if (buf->content.result_indx & ICE_AQ_RECIPE_RESULT_EN)
		set_bit(buf->content.result_indx & ~ICE_AQ_RECIPE_RESULT_EN,
		        recp->res_idxs);
}

/**
 * ice_get_tun_type_for_recipe - get tunnel type for the recipe
 * @rid: recipe ID that we are populating
 * @vlan: flag of vlan protocol
 */
static enum ice_sw_tunnel_type ice_get_tun_type_for_recipe(u8 rid, bool vlan)
{
	u8 udp_tun_profile[12] = {10, 11, 12, 16, 17, 18, 22, 23, 24, 25, 26,
				  27};
	u8 gre_profile[12] = {13, 14, 15, 19, 20, 21, 28, 29, 30, 31, 32, 33};
	u8 pppoe_profile[7] = {34, 35, 36, 37, 38, 39, 40};
	u8 non_tun_profile[6] = {4, 5, 6, 7, 8, 9};
	enum ice_sw_tunnel_type tun_type;
	u16 i, j, profile_num = 0;
	bool udp_tun_valid = false;
	bool non_tun_valid = false;
	bool pppoe_valid = false;
	bool gre_valid = false;
	bool gtp_valid = false;
	bool flag_valid = false;

	for (j = 0; j < ICE_MAX_NUM_PROFILES; j++) {
		if (!test_bit(j, recipe_to_profile[rid]))
			continue;
		else
			profile_num++;

		for (i = 0; i < 12; i++) {
			if (gre_profile[i] == j)
				gre_valid = true;
		}

		for (i = 0; i < 12; i++) {
			if (udp_tun_profile[i] == j)
				udp_tun_valid = true;
		}

		for (i = 0; i < 7; i++) {
			if (pppoe_profile[i] == j)
				pppoe_valid = true;
		}

		for (i = 0; i < 6; i++) {
			if (non_tun_profile[i] == j)
				non_tun_valid = true;
		}
	}

	if (!non_tun_valid && udp_tun_valid)
		tun_type = ICE_SW_TUN_UDP;
	else if (!non_tun_valid && gre_valid)
		tun_type = ICE_SW_TUN_NVGRE;
	else if (non_tun_valid &&
		 (udp_tun_valid || gre_valid || gtp_valid || pppoe_valid))
		tun_type = ICE_SW_TUN_AND_NON_TUN;
	else if (non_tun_valid && !udp_tun_valid && !gre_valid && !gtp_valid &&
		 !pppoe_valid)
		tun_type = ICE_NON_TUN;
	else
		tun_type = ICE_NON_TUN;

	if (profile_num == 1 && (flag_valid || non_tun_valid || pppoe_valid)) {
		for (j = 0; j < ICE_MAX_NUM_PROFILES; j++) {
			if (test_bit(j, recipe_to_profile[rid])) {
				switch (j) {
				case ICE_PROFID_IPV4_TCP:
					tun_type = ICE_SW_IPV4_TCP;
					break;
				case ICE_PROFID_IPV4_UDP:
					tun_type = ICE_SW_IPV4_UDP;
					break;
				case ICE_PROFID_IPV6_TCP:
					tun_type = ICE_SW_IPV6_TCP;
					break;
				case ICE_PROFID_IPV6_UDP:
					tun_type = ICE_SW_IPV6_UDP;
					break;
				default:
					break;
				}

				return tun_type;
			}
		}
	}

	return tun_type;
}

/**
 * ice_get_recp_frm_fw - update SW bookkeeping from FW recipe entries
 * @hw: pointer to hardware structure
 * @recps: struct that we need to populate
 * @rid: recipe ID that we are populating
 * @refresh_required: true if we should get recipe to profile mapping from FW
 *
 * This function is used to populate all the necessary entries into our
 * bookkeeping so that we have a current list of all the recipes that are
 * programmed in the firmware.
 */
static int
ice_get_recp_frm_fw(struct ice_hw *hw, struct ice_sw_recipe *recps, u8 rid,
		    bool *refresh_required)
{
	DECLARE_BITMAP(result_bm, ICE_MAX_FV_WORDS);
	struct ice_aqc_recipe_data_elem *tmp;
	u16 num_recps = ICE_MAX_NUM_RECIPES;
	struct ice_prot_lkup_ext *lkup_exts;
	u8 fv_word_idx = 0;
	bool vlan = false;
	u16 sub_recps;
	int status;

	bitmap_zero(result_bm, ICE_MAX_FV_WORDS);

	/* we need a buffer big enough to accommodate all the recipes */
	tmp = devm_kcalloc(ice_hw_to_dev(hw), ICE_MAX_NUM_RECIPES,
			   sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	tmp[0].recipe_indx = rid;
	status = ice_aq_get_recipe(hw, tmp, &num_recps, rid, NULL);
	/* non-zero status meaning recipe doesn't exist */
	if (status)
		goto err_unroll;

	if (!num_recps) {
		status = -EINVAL;
		goto err_unroll;
	}

	/* Get recipe to profile map so that we can get the fv from lkups that
	 * we read for a recipe from FW. Since we want to minimize the number of
	 * times we make this FW call, just make one call and cache the copy
	 * until a new recipe is added. This operation is only required the
	 * first time to get the changes from FW. Then to search existing
	 * entries we don't need to update the cache again until another recipe
	 * gets added.
	 */
	if (*refresh_required) {
		ice_get_recp_to_prof_map(hw);
		*refresh_required = false;
	}

	/* Start populating all the entries for recps[rid] based on lkups from
	 * firmware. Note that we are only creating the root recipe in our
	 * database.
	 */
	lkup_exts = &recps[rid].lkup_exts;

	for (sub_recps = 0; sub_recps < num_recps; sub_recps++) {
		struct ice_aqc_recipe_data_elem root_bufs = tmp[sub_recps];
		struct ice_recp_grp_entry *rg_entry;
		u8 i, prof, idx, prot = 0;
		bool is_root;
		u16 off = 0;

		rg_entry = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*rg_entry),
					GFP_KERNEL);
		if (!rg_entry) {
			status = -ENOMEM;
			goto err_unroll;
		}

		idx = root_bufs.recipe_indx;
		is_root = root_bufs.content.rid & ICE_AQ_RECIPE_ID_IS_ROOT;

		/* Mark all result indices in this chain */
		if (root_bufs.content.result_indx & ICE_AQ_RECIPE_RESULT_EN)
			set_bit(root_bufs.content.result_indx & ~ICE_AQ_RECIPE_RESULT_EN,
				result_bm);

		/* get the first profile that is associated with rid */
		prof = (u8)find_first_bit(recipe_to_profile[idx],
					  ICE_MAX_NUM_PROFILES);
		for (i = 0; i < ICE_NUM_WORDS_RECIPE; i++) {
			u8 lkup_indx = root_bufs.content.lkup_indx[i + 1];

			rg_entry->fv_idx[i] = lkup_indx;
			rg_entry->fv_mask[i] =
				le16_to_cpu(root_bufs.content.mask[i + 1]);

			/* If the recipe is a chained recipe then all its
			 * child recipe's result will have a result index.
			 * To fill fv_words we should not use those result
			 * index, we only need the protocol ids and offsets.
			 * We will skip all the fv_idx which stores result
			 * index in them. We also need to skip any fv_idx which
			 * has ICE_AQ_RECIPE_LKUP_IGNORE or 0 since it isn't a
			 * valid offset value.
			 */
			if (test_bit(rg_entry->fv_idx[i], hw->switch_info->prof_res_bm[prof]) ||
			    rg_entry->fv_idx[i] & ICE_AQ_RECIPE_LKUP_IGNORE ||
			    rg_entry->fv_idx[i] == 0)
				continue;

			ice_find_prot_off(hw, ICE_BLK_SW, prof,
					  rg_entry->fv_idx[i], &prot, &off);
			lkup_exts->fv_words[fv_word_idx].prot_id = prot;
			lkup_exts->fv_words[fv_word_idx].off = off;
			lkup_exts->field_mask[fv_word_idx] =
				rg_entry->fv_mask[i];
			if (prot == ICE_META_DATA_ID_HW &&
			    off == ICE_TUN_FLAG_MDID_OFF(1))
				vlan = true;
			fv_word_idx++;
		}
		/* populate rg_list with the data from the child entry of this
		 * recipe
		 */
		list_add(&rg_entry->l_entry, &recps[rid].rg_list);

		/* Propagate some data to the recipe database */
		recps[idx].is_root = is_root;
		recps[idx].priority = root_bufs.content.act_ctrl_fwd_priority;
		bitmap_zero(recps[idx].res_idxs, ICE_MAX_FV_WORDS);
		if (root_bufs.content.result_indx & ICE_AQ_RECIPE_RESULT_EN) {
			recps[idx].chain_idx = root_bufs.content.result_indx &
				~ICE_AQ_RECIPE_RESULT_EN;
			set_bit(recps[idx].chain_idx, recps[idx].res_idxs);
		} else {
			recps[idx].chain_idx = ICE_INVAL_CHAIN_IND;
		}

		if (!is_root)
			continue;

		/* Only do the following for root recipes entries */
		memcpy(recps[idx].r_bitmap, root_bufs.recipe_bitmap,
		       sizeof(recps[idx].r_bitmap));
		recps[idx].root_rid = root_bufs.content.rid &
			~ICE_AQ_RECIPE_ID_IS_ROOT;
		recps[idx].priority = root_bufs.content.act_ctrl_fwd_priority;
	}

	/* Complete initialization of the root recipe entry */
	lkup_exts->n_val_words = fv_word_idx;
	recps[rid].big_recp = (num_recps > 1);
	recps[rid].n_grp_count = (u8)num_recps;
	recps[rid].tun_type = ice_get_tun_type_for_recipe(rid, vlan);
	recps[rid].root_buf = devm_kmemdup(ice_hw_to_dev(hw), tmp,
					   recps[rid].n_grp_count * sizeof(*recps[rid].root_buf),
					   GFP_KERNEL);
	if (!recps[rid].root_buf)
		goto err_unroll;

	/* Copy result indexes */
	bitmap_copy(recps[rid].res_idxs, result_bm, ICE_MAX_FV_WORDS);
	recps[rid].recp_created = true;

err_unroll:
	devm_kfree(ice_hw_to_dev(hw), tmp);
	return status;
}

/**
 * ice_get_recp_to_prof_map - updates recipe to profile mapping
 * @hw: pointer to hardware structure
 *
 * This function is used to populate recipe_to_profile matrix where index to
 * this array is the recipe ID and the element is the mapping of which profiles
 * is this recipe mapped to.
 */
static void ice_get_recp_to_prof_map(struct ice_hw *hw)
{
	DECLARE_BITMAP(r_bitmap, ICE_MAX_NUM_RECIPES);
	u16 i;

	for (i = 0; i < hw->switch_info->max_used_prof_index + 1; i++) {
		u16 j;

		bitmap_zero(profile_to_recipe[i], ICE_MAX_NUM_RECIPES);
		bitmap_zero(r_bitmap, ICE_MAX_NUM_RECIPES);
		if (ice_aq_get_recipe_to_profile(hw, i, (u8 *)r_bitmap, NULL))
			continue;
		bitmap_copy(profile_to_recipe[i], r_bitmap,
			    ICE_MAX_NUM_RECIPES);
		for_each_set_bit(j, r_bitmap, ICE_MAX_NUM_RECIPES)
			set_bit(i, recipe_to_profile[j]);
	}
}

static bool
ice_vsi_uses_fltr(struct ice_fltr_mgmt_list_entry *fm_entry, u16 vsi_handle);

/**
 * ice_init_def_sw_recp - initialize the recipe book keeping tables
 * @hw: pointer to the HW struct
 * @recp_list: pointer to sw recipe list
 *
 * Allocate memory for the entire recipe table and initialize the structures/
 * entries corresponding to basic recipes.
 */
int
ice_init_def_sw_recp(struct ice_hw *hw, struct ice_sw_recipe **recp_list)
{
	struct ice_sw_recipe *recps;
	u8 i;

	recps = devm_kcalloc(ice_hw_to_dev(hw), ICE_MAX_NUM_RECIPES,
			     sizeof(*recps), GFP_KERNEL);
	if (!recps)
		return -ENOMEM;

	for (i = 0; i < ICE_MAX_NUM_RECIPES; i++) {
		recps[i].root_rid = i;
		INIT_LIST_HEAD(&recps[i].filt_rules);
		INIT_LIST_HEAD(&recps[i].filt_replay_rules);
		INIT_LIST_HEAD(&recps[i].rg_list);
		mutex_init(&recps[i].filt_rule_lock);
	}

	*recp_list = recps;

	return 0;
}

/**
 * ice_aq_get_sw_cfg - get switch configuration
 * @hw: pointer to the hardware structure
 * @buf: pointer to the result buffer
 * @buf_size: length of the buffer available for response
 * @req_desc: pointer to requested descriptor
 * @num_elems: pointer to number of elements
 * @cd: pointer to command details structure or NULL
 *
 * Get switch configuration (0x0200) to be placed in buf.
 * This admin command returns information such as initial VSI/port number
 * and switch ID it belongs to.
 *
 * NOTE: *req_desc is both an input/output parameter.
 * The caller of this function first calls this function with *request_desc set
 * to 0. If the response from f/w has *req_desc set to 0, all the switch
 * configuration information has been returned; if non-zero (meaning not all
 * the information was returned), the caller should call this function again
 * with *req_desc set to the previous value returned by f/w to get the
 * next block of switch configuration information.
 *
 * *num_elems is output only parameter. This reflects the number of elements
 * in response buffer. The caller of this function to use *num_elems while
 * parsing the response buffer.
 */
int
ice_aq_get_sw_cfg(struct ice_hw *hw, struct ice_aqc_get_sw_cfg_resp_elem *buf,
		  u16 buf_size, u16 *req_desc, u16 *num_elems,
		  struct ice_sq_cd *cd)
{
	struct ice_aqc_get_sw_cfg *cmd;
	struct ice_aq_desc desc;
	int status;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_sw_cfg);
	cmd = &desc.params.get_sw_conf;
	cmd->element = cpu_to_le16(*req_desc);

	status = ice_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (!status) {
		*req_desc = le16_to_cpu(cmd->element);
		*num_elems = le16_to_cpu(cmd->num_elems);
	}

	return status;
}

/**
 * ice_dump_sw_cfg - get and print switch config as seen by firmware
 * @hw: ice hardware struct
 */
int ice_dump_sw_cfg(struct ice_hw *hw)
{
	struct ice_aqc_get_sw_cfg_resp_elem *rbuf;
	u16 req_desc = 0;
	u16 num_elems;
	int ret;
	u16 i;

	rbuf = devm_kzalloc(ice_hw_to_dev(hw), ICE_SW_CFG_MAX_BUF_LEN,
			    GFP_KERNEL);
	if (!rbuf)
		return -ENOMEM;

	/* Multiple calls to ice_aq_get_sw_cfg may be required
	 * to get all the switch configuration information. The need
	 * for additional calls is indicated by ice_aq_get_sw_cfg
	 * writing a non-zero value in req_desc.
	 */
	do {
		struct ice_aqc_get_sw_cfg_resp_elem *ele;

		ret = ice_aq_get_sw_cfg(hw, rbuf, ICE_SW_CFG_MAX_BUF_LEN,
					&req_desc, &num_elems, NULL);
		if (ret)
			break;

		for (i = 0, ele = rbuf; i < num_elems; i++, ele++) {
			u16 vsi_port_num, pf_vf_num, swid;

			vsi_port_num = le16_to_cpu(ele->vsi_port_num) &
				ICE_AQC_GET_SW_CONF_RESP_VSI_PORT_NUM_M;

			pf_vf_num = le16_to_cpu(ele->pf_vf_num) &
				ICE_AQC_GET_SW_CONF_RESP_FUNC_NUM_M;

			swid = le16_to_cpu(ele->swid);

			dev_info(ice_hw_to_dev(hw), "element[%d]\n", i);

			switch (le16_to_cpu(ele->vsi_port_num) >>
				ICE_AQC_GET_SW_CONF_RESP_TYPE_S) {
			case ICE_AQC_GET_SW_CONF_RESP_PHYS_PORT:
				dev_info(ice_hw_to_dev(hw),
					 "\tphy_port = %d\n", vsi_port_num);
				break;
			case ICE_AQC_GET_SW_CONF_RESP_VIRT_PORT:
				dev_info(ice_hw_to_dev(hw),
					 "\tvir_port = %d\n", vsi_port_num);
				break;
			case ICE_AQC_GET_SW_CONF_RESP_VSI:
				dev_info(ice_hw_to_dev(hw),
					 "\tvsi_num = %d\n", vsi_port_num);
				break;

			default:
				dev_info(ice_hw_to_dev(hw),
					 "\tincorrect vsi/port type\n");
				ret = -EIO;
				break;
			}

			dev_info(ice_hw_to_dev(hw), "\tswid = %d\n", swid);

			if (le16_to_cpu(ele->pf_vf_num) &
			    ICE_AQC_GET_SW_CONF_RESP_IS_VF)
				dev_info(ice_hw_to_dev(hw), "\tvf_id = %d\n",
					 pf_vf_num);
			else
				dev_info(ice_hw_to_dev(hw), "\tpf_id = %d\n",
					 pf_vf_num);
		}
	} while (req_desc && !ret);

	devm_kfree(ice_hw_to_dev(hw), rbuf);
	return ret;
}

/**
 * ice_alloc_rss_global_lut - allocate a RSS global LUT
 * @hw: pointer to the HW struct
 * @shared_res: true to allocate as a shared resource and false to allocate as a dedicated resource
 * @global_lut_id: output parameter for the RSS global LUT's ID
 */
int ice_alloc_rss_global_lut(struct ice_hw *hw, bool shared_res, u16 *global_lut_id)
{
	struct ice_aqc_alloc_free_res_elem *sw_buf;
	int status;
	u16 buf_len;

	buf_len = struct_size(sw_buf, elem, 1);
	sw_buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len, GFP_KERNEL);
	if (!sw_buf)
		return -ENOMEM;

	sw_buf->num_elems = cpu_to_le16(1);
	sw_buf->res_type = cpu_to_le16(ICE_AQC_RES_TYPE_GLOBAL_RSS_HASH |
				       (shared_res ? ICE_AQC_RES_TYPE_FLAG_SHARED :
				       ICE_AQC_RES_TYPE_FLAG_DEDICATED));

	status = ice_aq_alloc_free_res(hw, 1, sw_buf, buf_len, ice_aqc_opc_alloc_res, NULL);
	if (status) {
		ice_debug(hw, ICE_DBG_RES, "Failed to allocate %s RSS global LUT, status %d\n",
			  shared_res ? "shared" : "dedicated", status);
		goto ice_alloc_global_lut_exit;
	}

	*global_lut_id = le16_to_cpu(sw_buf->elem[0].e.sw_resp);

ice_alloc_global_lut_exit:
	devm_kfree(ice_hw_to_dev(hw), sw_buf);
	return status;
}

/**
 * ice_free_rss_global_lut - free a RSS global LUT
 * @hw: pointer to the HW struct
 * @global_lut_id: ID of the RSS global LUT to free
 */
int ice_free_rss_global_lut(struct ice_hw *hw, u16 global_lut_id)
{
	struct ice_aqc_alloc_free_res_elem *sw_buf;
	u16 buf_len, num_elems = 1;
	int status;

	buf_len = struct_size(sw_buf, elem, num_elems);
	sw_buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len, GFP_KERNEL);
	if (!sw_buf)
		return -ENOMEM;

	sw_buf->num_elems = cpu_to_le16(num_elems);
	sw_buf->res_type = cpu_to_le16(ICE_AQC_RES_TYPE_GLOBAL_RSS_HASH);
	sw_buf->elem[0].e.sw_resp = cpu_to_le16(global_lut_id);

	status = ice_aq_alloc_free_res(hw, num_elems, sw_buf, buf_len, ice_aqc_opc_free_res, NULL);
	if (status)
		ice_debug(hw, ICE_DBG_RES, "Failed to free RSS global LUT %d, status %d\n",
			  global_lut_id, status);

	devm_kfree(ice_hw_to_dev(hw), sw_buf);
	return status;
}

/**
 * ice_alloc_sw - allocate resources specific to switch
 * @hw: pointer to the HW struct
 * @ena_stats: true to turn on VEB stats
 * @shared_res: true for shared resource, false for dedicated resource
 * @sw_id: switch ID returned
 * @counter_id: VEB counter ID returned
 *
 * allocates switch resources (SWID and VEB counter) (0x0208)
 */
int
ice_alloc_sw(struct ice_hw *hw, bool ena_stats, bool shared_res, u16 *sw_id,
	     u16 *counter_id)
{
	struct ice_aqc_alloc_free_res_elem *sw_buf;
	struct ice_aqc_res_elem *sw_ele;
	u16 buf_len;
	int status;

	buf_len = struct_size(sw_buf, elem, 1);
	sw_buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len, GFP_KERNEL);
	if (!sw_buf)
		return -ENOMEM;

	/* Prepare buffer for switch ID.
	 * The number of resource entries in buffer is passed as 1 since only a
	 * single switch/VEB instance is allocated, and hence a single sw_id
	 * is requested.
	 */
	sw_buf->num_elems = cpu_to_le16(1);
	sw_buf->res_type =
		cpu_to_le16(ICE_AQC_RES_TYPE_SWID |
			    (shared_res ? ICE_AQC_RES_TYPE_FLAG_SHARED :
			    ICE_AQC_RES_TYPE_FLAG_DEDICATED));

	status = ice_aq_alloc_free_res(hw, 1, sw_buf, buf_len,
				       ice_aqc_opc_alloc_res, NULL);

	if (status)
		goto ice_alloc_sw_exit;

	sw_ele = &sw_buf->elem[0];
	*sw_id = le16_to_cpu(sw_ele->e.sw_resp);

	if (ena_stats) {
		/* Prepare buffer for VEB Counter */
		enum ice_adminq_opc opc = ice_aqc_opc_alloc_res;
		struct ice_aqc_alloc_free_res_elem *counter_buf;
		struct ice_aqc_res_elem *counter_ele;

		counter_buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len,
					   GFP_KERNEL);
		if (!counter_buf) {
			status = -ENOMEM;
			goto ice_alloc_sw_exit;
		}

		/* The number of resource entries in buffer is passed as 1 since
		 * only a single switch/VEB instance is allocated, and hence a
		 * single VEB counter is requested.
		 */
		counter_buf->num_elems = cpu_to_le16(1);
		counter_buf->res_type =
			cpu_to_le16(ICE_AQC_RES_TYPE_VEB_COUNTER |
				    ICE_AQC_RES_TYPE_FLAG_DEDICATED);
		status = ice_aq_alloc_free_res(hw, 1, counter_buf, buf_len,
					       opc, NULL);

		if (status) {
			devm_kfree(ice_hw_to_dev(hw), counter_buf);
			goto ice_alloc_sw_exit;
		}
		counter_ele = &counter_buf->elem[0];
		*counter_id = le16_to_cpu(counter_ele->e.sw_resp);
		devm_kfree(ice_hw_to_dev(hw), counter_buf);
	}

ice_alloc_sw_exit:
	devm_kfree(ice_hw_to_dev(hw), sw_buf);
	return status;
}

/**
 * ice_free_sw - free resources specific to switch
 * @hw: pointer to the HW struct
 * @sw_id: switch ID returned
 * @counter_id: VEB counter ID returned
 *
 * free switch resources (SWID and VEB counter) (0x0209)
 *
 * NOTE: This function frees multiple resources. It continues
 * releasing other resources even after it encounters error.
 * The error code returned is the last error it encountered.
 */
int ice_free_sw(struct ice_hw *hw, u16 sw_id, u16 counter_id)
{
	struct ice_aqc_alloc_free_res_elem *sw_buf, *counter_buf;
	int status, ret_status;
	u16 buf_len;

	buf_len = struct_size(sw_buf, elem, 1);
	sw_buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len, GFP_KERNEL);
	if (!sw_buf)
		return -ENOMEM;

	/* Prepare buffer to free for switch ID res.
	 * The number of resource entries in buffer is passed as 1 since only a
	 * single switch/VEB instance is freed, and hence a single sw_id
	 * is released.
	 */
	sw_buf->num_elems = cpu_to_le16(1);
	sw_buf->res_type = cpu_to_le16(ICE_AQC_RES_TYPE_SWID);
	sw_buf->elem[0].e.sw_resp = cpu_to_le16(sw_id);

	ret_status = ice_aq_alloc_free_res(hw, 1, sw_buf, buf_len,
					   ice_aqc_opc_free_res, NULL);

	if (ret_status)
		ice_debug(hw, ICE_DBG_SW, "CQ CMD Buffer:\n");

	/* Prepare buffer to free for VEB Counter resource */
	counter_buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len, GFP_KERNEL);
	if (!counter_buf) {
		devm_kfree(ice_hw_to_dev(hw), sw_buf);
		return -ENOMEM;
	}

	/* The number of resource entries in buffer is passed as 1 since only a
	 * single switch/VEB instance is freed, and hence a single VEB counter
	 * is released
	 */
	counter_buf->num_elems = cpu_to_le16(1);
	counter_buf->res_type = cpu_to_le16(ICE_AQC_RES_TYPE_VEB_COUNTER);
	counter_buf->elem[0].e.sw_resp = cpu_to_le16(counter_id);

	status = ice_aq_alloc_free_res(hw, 1, counter_buf, buf_len,
				       ice_aqc_opc_free_res, NULL);
	if (status) {
		ice_debug(hw, ICE_DBG_SW, "VEB counter resource could not be freed\n");
		ret_status = status;
	}

	devm_kfree(ice_hw_to_dev(hw), counter_buf);
	devm_kfree(ice_hw_to_dev(hw), sw_buf);
	return ret_status;
}

/**
 * ice_aq_add_vsi
 * @hw: pointer to the HW struct
 * @vsi_ctx: pointer to a VSI context struct
 * @cd: pointer to command details structure or NULL
 *
 * Add a VSI context to the hardware (0x0210)
 */
static int
ice_aq_add_vsi(struct ice_hw *hw, struct ice_vsi_ctx *vsi_ctx,
	       struct ice_sq_cd *cd)
{
	struct ice_aqc_add_update_free_vsi_resp *res;
	struct ice_aqc_add_get_update_free_vsi *cmd;
	struct ice_aq_desc desc;
	int status;

	cmd = &desc.params.vsi_cmd;
	res = &desc.params.add_update_free_vsi_res;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_add_vsi);

	if (!vsi_ctx->alloc_from_pool)
		cmd->vsi_num = cpu_to_le16(vsi_ctx->vsi_num |
					   ICE_AQ_VSI_IS_VALID);
	cmd->vf_id = vsi_ctx->vf_num;

	cmd->vsi_flags = cpu_to_le16(vsi_ctx->flags);

	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);

	status = ice_aq_send_cmd(hw, &desc, &vsi_ctx->info,
				 sizeof(vsi_ctx->info), cd);

	if (!status) {
		vsi_ctx->vsi_num = le16_to_cpu(res->vsi_num) & ICE_AQ_VSI_NUM_M;
		vsi_ctx->vsis_allocd = le16_to_cpu(res->vsi_used);
		vsi_ctx->vsis_unallocated = le16_to_cpu(res->vsi_free);
	}

	return status;
}

/**
 * ice_aq_free_vsi
 * @hw: pointer to the HW struct
 * @vsi_ctx: pointer to a VSI context struct
 * @keep_vsi_alloc: keep VSI allocation as part of this PF's resources
 * @cd: pointer to command details structure or NULL
 *
 * Free VSI context info from hardware (0x0213)
 */
static int
ice_aq_free_vsi(struct ice_hw *hw, struct ice_vsi_ctx *vsi_ctx,
		bool keep_vsi_alloc, struct ice_sq_cd *cd)
{
	struct ice_aqc_add_update_free_vsi_resp *resp;
	struct ice_aqc_add_get_update_free_vsi *cmd;
	struct ice_aq_desc desc;
	int status;

	cmd = &desc.params.vsi_cmd;
	resp = &desc.params.add_update_free_vsi_res;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_free_vsi);

	cmd->vsi_num = cpu_to_le16(vsi_ctx->vsi_num | ICE_AQ_VSI_IS_VALID);
	if (keep_vsi_alloc)
		cmd->cmd_flags = cpu_to_le16(ICE_AQ_VSI_KEEP_ALLOC);

	status = ice_aq_send_cmd(hw, &desc, NULL, 0, cd);
	if (!status) {
		vsi_ctx->vsis_allocd = le16_to_cpu(resp->vsi_used);
		vsi_ctx->vsis_unallocated = le16_to_cpu(resp->vsi_free);
	}

	return status;
}

/**
 * ice_aq_update_vsi
 * @hw: pointer to the HW struct
 * @vsi_ctx: pointer to a VSI context struct
 * @cd: pointer to command details structure or NULL
 *
 * Update VSI context in the hardware (0x0211)
 */
static int
ice_aq_update_vsi(struct ice_hw *hw, struct ice_vsi_ctx *vsi_ctx,
		  struct ice_sq_cd *cd)
{
	struct ice_aqc_add_update_free_vsi_resp *resp;
	struct ice_aqc_add_get_update_free_vsi *cmd;
	struct ice_aq_desc desc;
	int status;

	cmd = &desc.params.vsi_cmd;
	resp = &desc.params.add_update_free_vsi_res;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_update_vsi);

	cmd->vsi_num = cpu_to_le16(vsi_ctx->vsi_num | ICE_AQ_VSI_IS_VALID);

	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);

	status = ice_aq_send_cmd(hw, &desc, &vsi_ctx->info,
				 sizeof(vsi_ctx->info), cd);

	if (!status) {
		vsi_ctx->vsis_allocd = le16_to_cpu(resp->vsi_used);
		vsi_ctx->vsis_unallocated = le16_to_cpu(resp->vsi_free);
	}

	return status;
}

/**
 * ice_is_vsi_valid - check whether the VSI is valid or not
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 *
 * check whether the VSI is valid or not
 */
bool ice_is_vsi_valid(struct ice_hw *hw, u16 vsi_handle)
{
	return vsi_handle < ICE_MAX_VSI && hw->vsi_ctx[vsi_handle];
}

/**
 * ice_get_hw_vsi_num - return the HW VSI number
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 *
 * return the HW VSI number
 * Caution: call this function only if VSI is valid (ice_is_vsi_valid)
 */
u16 ice_get_hw_vsi_num(struct ice_hw *hw, u16 vsi_handle)
{
	return hw->vsi_ctx[vsi_handle]->vsi_num;
}

/**
 * ice_get_vsi_ctx - return the VSI context entry for a given VSI handle
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 *
 * return the VSI context entry for a given VSI handle
 */
struct ice_vsi_ctx *ice_get_vsi_ctx(struct ice_hw *hw, u16 vsi_handle)
{
	return (vsi_handle >= ICE_MAX_VSI) ? NULL : hw->vsi_ctx[vsi_handle];
}

/**
 * ice_save_vsi_ctx - save the VSI context for a given VSI handle
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 * @vsi: VSI context pointer
 *
 * save the VSI context entry for a given VSI handle
 */
static void
ice_save_vsi_ctx(struct ice_hw *hw, u16 vsi_handle, struct ice_vsi_ctx *vsi)
{
	hw->vsi_ctx[vsi_handle] = vsi;
}

/**
 * ice_clear_vsi_q_ctx - clear VSI queue contexts for all TCs
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 */
static void ice_clear_vsi_q_ctx(struct ice_hw *hw, u16 vsi_handle)
{
	struct ice_vsi_ctx *vsi;
	u8 i;

	vsi = ice_get_vsi_ctx(hw, vsi_handle);
	if (!vsi)
		return;
	ice_for_each_traffic_class(i) {
		if (vsi->lan_q_ctx[i]) {
			devm_kfree(ice_hw_to_dev(hw), vsi->lan_q_ctx[i]);
			vsi->lan_q_ctx[i] = NULL;
		}
		if (vsi->rdma_q_ctx[i]) {
			devm_kfree(ice_hw_to_dev(hw), vsi->rdma_q_ctx[i]);
			vsi->rdma_q_ctx[i] = NULL;
		}
	}
}

/**
 * ice_clear_vsi_ctx - clear the VSI context entry
 * @hw: pointer to the HW struct
 * @vsi_handle: VSI handle
 *
 * clear the VSI context entry
 */
static void ice_clear_vsi_ctx(struct ice_hw *hw, u16 vsi_handle)
{
	struct ice_vsi_ctx *vsi;

	vsi = ice_get_vsi_ctx(hw, vsi_handle);
	if (vsi) {
		ice_clear_vsi_q_ctx(hw, vsi_handle);
		devm_kfree(ice_hw_to_dev(hw), vsi);
		hw->vsi_ctx[vsi_handle] = NULL;
	}
}

/**
 * ice_clear_all_vsi_ctx - clear all the VSI context entries
 * @hw: pointer to the HW struct
 */
void ice_clear_all_vsi_ctx(struct ice_hw *hw)
{
	u16 i;

	for (i = 0; i < ICE_MAX_VSI; i++)
		ice_clear_vsi_ctx(hw, i);
}

/**
 * ice_add_vsi - add VSI context to the hardware and VSI handle list
 * @hw: pointer to the HW struct
 * @vsi_handle: unique VSI handle provided by drivers
 * @vsi_ctx: pointer to a VSI context struct
 * @cd: pointer to command details structure or NULL
 *
 * Add a VSI context to the hardware also add it into the VSI handle list.
 * If this function gets called after reset for existing VSIs then update
 * with the new HW VSI number in the corresponding VSI handle list entry.
 */
int
ice_add_vsi(struct ice_hw *hw, u16 vsi_handle, struct ice_vsi_ctx *vsi_ctx,
	    struct ice_sq_cd *cd)
{
	struct ice_vsi_ctx *tmp_vsi_ctx;
	int status;

	if (vsi_handle >= ICE_MAX_VSI)
		return -EINVAL;
	status = ice_aq_add_vsi(hw, vsi_ctx, cd);
	if (status)
		return status;
	tmp_vsi_ctx = ice_get_vsi_ctx(hw, vsi_handle);
	if (!tmp_vsi_ctx) {
		/* Create a new VSI context */
		tmp_vsi_ctx = devm_kzalloc(ice_hw_to_dev(hw),
					   sizeof(*tmp_vsi_ctx), GFP_KERNEL);
		if (!tmp_vsi_ctx) {
			ice_aq_free_vsi(hw, vsi_ctx, false, cd);
			return -ENOMEM;
		}
		*tmp_vsi_ctx = *vsi_ctx;

		ice_save_vsi_ctx(hw, vsi_handle, tmp_vsi_ctx);
	} else {
		/* update with new HW VSI num */
		tmp_vsi_ctx->vsi_num = vsi_ctx->vsi_num;
	}

	return 0;
}

/**
 * ice_free_vsi- free VSI context from hardware and VSI handle list
 * @hw: pointer to the HW struct
 * @vsi_handle: unique VSI handle
 * @vsi_ctx: pointer to a VSI context struct
 * @keep_vsi_alloc: keep VSI allocation as part of this PF's resources
 * @cd: pointer to command details structure or NULL
 *
 * Free VSI context info from hardware as well as from VSI handle list
 */
int
ice_free_vsi(struct ice_hw *hw, u16 vsi_handle, struct ice_vsi_ctx *vsi_ctx,
	     bool keep_vsi_alloc, struct ice_sq_cd *cd)
{
	int status;

	if (!ice_is_vsi_valid(hw, vsi_handle))
		return -EINVAL;
	vsi_ctx->vsi_num = ice_get_hw_vsi_num(hw, vsi_handle);
	status = ice_aq_free_vsi(hw, vsi_ctx, keep_vsi_alloc, cd);
	if (!status)
		ice_clear_vsi_ctx(hw, vsi_handle);
	return status;
}

/**
 * ice_update_vsi
 * @hw: pointer to the HW struct
 * @vsi_handle: unique VSI handle
 * @vsi_ctx: pointer to a VSI context struct
 * @cd: pointer to command details structure or NULL
 *
 * Update VSI context in the hardware
 */
int
ice_update_vsi(struct ice_hw *hw, u16 vsi_handle, struct ice_vsi_ctx *vsi_ctx,
	       struct ice_sq_cd *cd)
{
	if (!ice_is_vsi_valid(hw, vsi_handle))
		return -EINVAL;
	vsi_ctx->vsi_num = ice_get_hw_vsi_num(hw, vsi_handle);
	return ice_aq_update_vsi(hw, vsi_ctx, cd);
}

/**
 * ice_cfg_iwarp_fltr - enable/disable iWARP filtering on VSI
 * @hw: pointer to HW struct
 * @vsi_handle: VSI SW index
 * @enable: boolean for enable/disable
 */
int
ice_cfg_iwarp_fltr(struct ice_hw *hw, u16 vsi_handle, bool enable)
{
	struct ice_vsi_ctx *ctx, *cached_ctx;
	int status;

	cached_ctx = ice_get_vsi_ctx(hw, vsi_handle);
	if (!cached_ctx)
		return -ENOENT;

	ctx = devm_kcalloc(ice_hw_to_dev(hw), 1, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->info.q_opt_rss = cached_ctx->info.q_opt_rss;
	ctx->info.q_opt_tc = cached_ctx->info.q_opt_tc;
	ctx->info.q_opt_flags = cached_ctx->info.q_opt_flags;

	ctx->info.valid_sections = cpu_to_le16(ICE_AQ_VSI_PROP_Q_OPT_VALID);

	if (enable)
		ctx->info.q_opt_flags |= ICE_AQ_VSI_Q_OPT_PE_FLTR_EN;
	else
		ctx->info.q_opt_flags &= ~ICE_AQ_VSI_Q_OPT_PE_FLTR_EN;

	status = ice_update_vsi(hw, vsi_handle, ctx, NULL);
	if (!status) {
		cached_ctx->info.q_opt_flags = ctx->info.q_opt_flags;
		cached_ctx->info.valid_sections |= ctx->info.valid_sections;
	}

	devm_kfree(ice_hw_to_dev(hw), ctx);
	return status;
}

/**
 * ice_aq_get_vsi_params
 * @hw: pointer to the HW struct
 * @vsi_ctx: pointer to a VSI context struct
 * @cd: pointer to command details structure or NULL
 *
 * Get VSI context info from hardware (0x0212)
 */
int
ice_aq_get_vsi_params(struct ice_hw *hw, struct ice_vsi_ctx *vsi_ctx,
		      struct ice_sq_cd *cd)
{
	struct ice_aqc_add_get_update_free_vsi *cmd;
	struct ice_aqc_get_vsi_resp *resp;
	struct ice_aq_desc desc;
	int status;

	cmd = &desc.params.vsi_cmd;
	resp = &desc.params.get_vsi_resp;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_vsi_params);

	cmd->vsi_num = cpu_to_le16(vsi_ctx->vsi_num | ICE_AQ_VSI_IS_VALID);

	status = ice_aq_send_cmd(hw, &desc, &vsi_ctx->info,
				 sizeof(vsi_ctx->info), cd);
	if (!status) {
		vsi_ctx->vsi_num = le16_to_cpu(resp->vsi_num) &
					ICE_AQ_VSI_NUM_M;
		vsi_ctx->vf_num = resp->vf_id;
		vsi_ctx->vsis_allocd = le16_to_cpu(resp->vsi_used);
		vsi_ctx->vsis_unallocated = le16_to_cpu(resp->vsi_free);
	}

	return status;
}

/**
 * ice_aq_add_update_mir_rule - add/update a mirror rule
 * @hw: pointer to the HW struct
 * @rule_type: Rule Type
 * @dest_vsi: VSI number to which packets will be mirrored
 * @count: length of the list
 * @mr_buf: buffer for list of mirrored VSI numbers
 * @cd: pointer to command details structure or NULL
 * @rule_id: Rule ID
 *
 * Add/Update Mirror Rule (0x260).
 */
int
ice_aq_add_update_mir_rule(struct ice_hw *hw, u16 rule_type, u16 dest_vsi,
			   u16 count, struct ice_mir_rule_buf *mr_buf,
			   struct ice_sq_cd *cd, u16 *rule_id)
{
	struct ice_aqc_add_update_mir_rule *cmd;
	struct ice_aq_desc desc;
	__le16 *mr_list = NULL;
	u16 buf_size = 0;
	int status;

	switch (rule_type) {
	case ICE_AQC_RULE_TYPE_VPORT_INGRESS:
	case ICE_AQC_RULE_TYPE_VPORT_EGRESS:
		/* Make sure count and mr_buf are set for these rule_types */
		if (!(count && mr_buf))
			return -EINVAL;

		buf_size = count * sizeof(__le16);
		mr_list = devm_kzalloc(ice_hw_to_dev(hw), buf_size,
				       GFP_KERNEL);
		if (!mr_list)
			return -ENOMEM;
		break;
	case ICE_AQC_RULE_TYPE_PPORT_INGRESS:
	case ICE_AQC_RULE_TYPE_PPORT_EGRESS:
		/* Make sure count and mr_buf are not set for these
		 * rule_types
		 */
		if (count || mr_buf)
			return -EINVAL;
		break;
	default:
		ice_debug(hw, ICE_DBG_SW, "Error due to unsupported rule_type %u\n", rule_type);
		return -EIO;
	}

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_add_update_mir_rule);

	/* Pre-process 'mr_buf' items for add/update of virtual port
	 * ingress/egress mirroring (but not physical port ingress/egress
	 * mirroring)
	 */
	if (mr_buf) {
		int i;

		for (i = 0; i < count; i++) {
			u16 id;

			id = mr_buf[i].vsi_idx & ICE_AQC_RULE_MIRRORED_VSI_M;

			/* Validate specified VSI number, make sure it is less
			 * than ICE_MAX_VSI, if not return with error.
			 */
			if (id >= ICE_MAX_VSI) {
				ice_debug(hw, ICE_DBG_SW, "Error VSI index (%u) out-of-range\n",
					  id);
				devm_kfree(ice_hw_to_dev(hw), mr_list);
				return -EIO;
			}

			/* add VSI to mirror rule */
			if (mr_buf[i].add)
				mr_list[i] =
					cpu_to_le16(id | ICE_AQC_RULE_ACT_M);
			else /* remove VSI from mirror rule */
				mr_list[i] = cpu_to_le16(id);
		}

		desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);
	}

	cmd = &desc.params.add_update_rule;
	if ((*rule_id) != ICE_INVAL_MIRROR_RULE_ID)
		cmd->rule_id = cpu_to_le16(((*rule_id) & ICE_AQC_RULE_ID_M) |
					   ICE_AQC_RULE_ID_VALID_M);
	cmd->rule_type = cpu_to_le16(rule_type & ICE_AQC_RULE_TYPE_M);
	cmd->num_entries = cpu_to_le16(count);
	cmd->dest = cpu_to_le16(dest_vsi);

	status = ice_aq_send_cmd(hw, &desc, mr_list, buf_size, cd);
	if (!status)
		*rule_id = le16_to_cpu(cmd->rule_id) & ICE_AQC_RULE_ID_M;

	devm_kfree(ice_hw_to_dev(hw), mr_list);

	return status;
}

/**
 * ice_aq_delete_mir_rule - delete a mirror rule
 * @hw: pointer to the HW struct
 * @rule_id: Mirror rule ID (to be deleted)
 * @keep_allocd: if set, the VSI stays part of the PF allocated res,
 *		 otherwise it is returned to the shared pool
 * @cd: pointer to command details structure or NULL
 *
 * Delete Mirror Rule (0x261).
 */
int
ice_aq_delete_mir_rule(struct ice_hw *hw, u16 rule_id, bool keep_allocd,
		       struct ice_sq_cd *cd)
{
	struct ice_aqc_delete_mir_rule *cmd;
	struct ice_aq_desc desc;

	/* rule_id should be in the range 0...63 */
	if (rule_id >= ICE_MAX_NUM_MIRROR_RULES)
		return -EIO;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_del_mir_rule);

	cmd = &desc.params.del_rule;
	rule_id |= ICE_AQC_RULE_ID_VALID_M;
	cmd->rule_id = cpu_to_le16(rule_id);

	if (keep_allocd)
		cmd->flags = cpu_to_le16(ICE_AQC_FLAG_KEEP_ALLOCD_M);

	return ice_aq_send_cmd(hw, &desc, NULL, 0, cd);
}

/**
 * ice_aq_alloc_free_vsi_list
 * @hw: pointer to the HW struct
 * @vsi_list_id: VSI list ID returned or used for lookup
 * @lkup_type: switch rule filter lookup type
 * @opc: switch rules population command type - pass in the command opcode
 *
 * allocates or free a VSI list resource
 */
static int
ice_aq_alloc_free_vsi_list(struct ice_hw *hw, u16 *vsi_list_id,
			   enum ice_sw_lkup_type lkup_type,
			   enum ice_adminq_opc opc)
{
	struct ice_aqc_alloc_free_res_elem *sw_buf;
	struct ice_aqc_res_elem *vsi_ele;
	u16 buf_len;
	int status;

	buf_len = struct_size(sw_buf, elem, 1);
	sw_buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len, GFP_KERNEL);
	if (!sw_buf)
		return -ENOMEM;
	sw_buf->num_elems = cpu_to_le16(1);

	if (lkup_type == ICE_SW_LKUP_MAC ||
	    lkup_type == ICE_SW_LKUP_MAC_VLAN ||
	    lkup_type == ICE_SW_LKUP_ETHERTYPE ||
	    lkup_type == ICE_SW_LKUP_ETHERTYPE_MAC ||
	    lkup_type == ICE_SW_LKUP_PROMISC ||
	    lkup_type == ICE_SW_LKUP_PROMISC_VLAN ||
	    lkup_type == ICE_SW_LKUP_DFLT ||
	    lkup_type == ICE_SW_LKUP_LAST) {
		sw_buf->res_type = cpu_to_le16(ICE_AQC_RES_TYPE_VSI_LIST_REP);
	} else if (lkup_type == ICE_SW_LKUP_VLAN) {
		/* Set SHARED bit on alloc calls for LAG functionality */
		if (opc == ice_aqc_opc_alloc_res)
			sw_buf->res_type =
				cpu_to_le16(ICE_AQC_RES_TYPE_VSI_LIST_PRUNE |
					    ICE_AQC_RES_TYPE_FLAG_SHARED);
		else
			sw_buf->res_type =
				cpu_to_le16(ICE_AQC_RES_TYPE_VSI_LIST_PRUNE);
	} else {
		status = -EINVAL;
		goto ice_aq_alloc_free_vsi_list_exit;
	}

	if (opc == ice_aqc_opc_free_res)
		sw_buf->elem[0].e.sw_resp = cpu_to_le16(*vsi_list_id);

	status = ice_aq_alloc_free_res(hw, 1, sw_buf, buf_len, opc, NULL);
	if (status)
		goto ice_aq_alloc_free_vsi_list_exit;

	if (opc == ice_aqc_opc_alloc_res) {
		vsi_ele = &sw_buf->elem[0];
		*vsi_list_id = le16_to_cpu(vsi_ele->e.sw_resp);
	}

ice_aq_alloc_free_vsi_list_exit:
	devm_kfree(ice_hw_to_dev(hw), sw_buf);
	return status;
}

/**
 * ice_aq_set_storm_ctrl - Sets storm control configuration
 * @hw: pointer to the HW struct
 * @bcast_thresh: represents the upper threshold for broadcast storm control
 * @mcast_thresh: represents the upper threshold for multicast storm control
 * @ctl_bitmask: storm control knobs
 *
 * Sets the storm control configuration (0x0280)
 */
int
ice_aq_set_storm_ctrl(struct ice_hw *hw, u32 bcast_thresh, u32 mcast_thresh,
		      u32 ctl_bitmask)
{
	struct ice_aqc_storm_cfg *cmd;
	struct ice_aq_desc desc;

	cmd = &desc.params.storm_conf;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_set_storm_cfg);

	cmd->bcast_thresh_size = cpu_to_le32(bcast_thresh & ICE_AQ_THRESHOLD_M);
	cmd->mcast_thresh_size = cpu_to_le32(mcast_thresh & ICE_AQ_THRESHOLD_M);
	cmd->storm_ctrl_ctrl = cpu_to_le32(ctl_bitmask);

	return ice_aq_send_cmd(hw, &desc, NULL, 0, NULL);
}

/**
 * ice_aq_get_storm_ctrl - gets storm control configuration
 * @hw: pointer to the HW struct
 * @bcast_thresh: represents the upper threshold for broadcast storm control
 * @mcast_thresh: represents the upper threshold for multicast storm control
 * @ctl_bitmask: storm control knobs
 *
 * Gets the storm control configuration (0x0281)
 */
int
ice_aq_get_storm_ctrl(struct ice_hw *hw, u32 *bcast_thresh, u32 *mcast_thresh,
		      u32 *ctl_bitmask)
{
	struct ice_aq_desc desc;
	int status;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_storm_cfg);

	status = ice_aq_send_cmd(hw, &desc, NULL, 0, NULL);
	if (!status) {
		struct ice_aqc_storm_cfg *resp = &desc.params.storm_conf;

		if (bcast_thresh)
			*bcast_thresh = le32_to_cpu(resp->bcast_thresh_size) &
				ICE_AQ_THRESHOLD_M;
		if (mcast_thresh)
			*mcast_thresh = le32_to_cpu(resp->mcast_thresh_size) &
				ICE_AQ_THRESHOLD_M;
		if (ctl_bitmask)
			*ctl_bitmask = le32_to_cpu(resp->storm_ctrl_ctrl);
	}

	return status;
}

/**
 * ice_aq_sw_rules - add/update/remove switch rules
 * @hw: pointer to the HW struct
 * @rule_list: pointer to switch rule population list
 * @rule_list_sz: total size of the rule list in bytes
 * @num_rules: number of switch rules in the rule_list
 * @opc: switch rules population command type - pass in the command opcode
 * @cd: pointer to command details structure or NULL
 *
 * Add(0x02a0)/Update(0x02a1)/Remove(0x02a2) switch rules commands to firmware
 */
int
ice_aq_sw_rules(struct ice_hw *hw, void *rule_list, u16 rule_list_sz,
		u8 num_rules, enum ice_adminq_opc opc, struct ice_sq_cd *cd)
{
	struct ice_aq_desc desc;
	int status;

	if (opc != ice_aqc_opc_add_sw_rules &&
	    opc != ice_aqc_opc_update_sw_rules &&
	    opc != ice_aqc_opc_remove_sw_rules)
		return -EINVAL;

	ice_fill_dflt_direct_cmd_desc(&desc, opc);

	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);
	desc.params.sw_rules.num_rules_fltr_entry_index =
		cpu_to_le16(num_rules);
	status = ice_aq_send_cmd(hw, &desc, rule_list, rule_list_sz, cd);
	if (opc != ice_aqc_opc_add_sw_rules &&
	    hw->adminq.sq_last_status == ICE_AQ_RC_ENOENT)
		status = -ENOENT;

	return status;
}

/**
 * ice_aq_add_recipe - add switch recipe
 * @hw: pointer to the HW struct
 * @s_recipe_list: pointer to switch rule population list
 * @num_recipes: number of switch recipes in the list
 * @cd: pointer to command details structure or NULL
 *
 * Add(0x0290)
 */
int
ice_aq_add_recipe(struct ice_hw *hw,
		  struct ice_aqc_recipe_data_elem *s_recipe_list,
		  u16 num_recipes, struct ice_sq_cd *cd)
{
	struct ice_aqc_add_get_recipe *cmd;
	struct ice_aq_desc desc;
	u16 buf_size;

	cmd = &desc.params.add_get_recipe;
	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_add_recipe);

	cmd->num_sub_recipes = cpu_to_le16(num_recipes);
	desc.flags |= cpu_to_le16(ICE_AQ_FLAG_RD);

	buf_size = num_recipes * sizeof(*s_recipe_list);

	return ice_aq_send_cmd(hw, &desc, s_recipe_list, buf_size, cd);
}

/**
 * ice_aq_get_recipe - get switch recipe
 * @hw: pointer to the HW struct
 * @s_recipe_list: pointer to switch rule population list
 * @num_recipes: pointer to the number of recipes (input and output)
 * @recipe_root: root recipe number of recipe(s) to retrieve
 * @cd: pointer to command details structure or NULL
 *
 * Get(0x0292)
 *
 * On input, *num_recipes should equal the number of entries in s_recipe_list.
 * On output, *num_recipes will equal the number of entries returned in
 * s_recipe_list.
 *
 * The caller must supply enough space in s_recipe_list to hold all possible
 * recipes and *num_recipes must equal ICE_MAX_NUM_RECIPES.
 */
int
ice_aq_get_recipe(struct ice_hw *hw,
		  struct ice_aqc_recipe_data_elem *s_recipe_list,
		  u16 *num_recipes, u16 recipe_root, struct ice_sq_cd *cd)
{
	struct ice_aqc_add_get_recipe *cmd;
	struct ice_aq_desc desc;
	u16 buf_size;
	int status;

	if (*num_recipes != ICE_MAX_NUM_RECIPES)
		return -EINVAL;

	cmd = &desc.params.add_get_recipe;
	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_recipe);

	cmd->return_index = cpu_to_le16(recipe_root);
	cmd->num_sub_recipes = 0;

	buf_size = *num_recipes * sizeof(*s_recipe_list);

	status = ice_aq_send_cmd(hw, &desc, s_recipe_list, buf_size, cd);
	*num_recipes = le16_to_cpu(cmd->num_sub_recipes);

	return status;
}

/**
 * ice_update_recipe_lkup_idx - update a default recipe based on the lkup_idx
 * @hw: pointer to the HW struct
 * @params: parameters used to update the default recipe
 *
 * This function only supports updating default recipes and it only supports
 * updating a single recipe based on the lkup_idx at a time.
 *
 * This is done as a read-modify-write operation. First, get the current recipe
 * contents based on the recipe's ID. Then modify the field vector index and
 * mask if it's valid at the lkup_idx. Finally, use the add recipe AQ to update
 * the pre-existing recipe with the modifications.
 */
int
ice_update_recipe_lkup_idx(struct ice_hw *hw,
			   struct ice_update_recipe_lkup_idx_params *params)
{
	struct ice_aqc_recipe_data_elem *rcp_list;
	u16 num_recps = ICE_MAX_NUM_RECIPES;
	int status;

	rcp_list = devm_kzalloc(ice_hw_to_dev(hw),
				num_recps * sizeof(*rcp_list), GFP_KERNEL);
	if (!rcp_list)
		return -ENOMEM;

	/* read current recipe list from firmware */
	rcp_list->recipe_indx = params->rid;
	status = ice_aq_get_recipe(hw, rcp_list, &num_recps, params->rid, NULL);
	if (status) {
		ice_debug(hw, ICE_DBG_SW, "Failed to get recipe %d, status %d\n",
			  params->rid, status);
		goto error_out;
	}

	/* only modify existing recipe's lkup_idx and mask if valid, while
	 * leaving all other fields the same, then update the recipe firmware
	 */
	rcp_list->content.lkup_indx[params->lkup_idx] = params->fv_idx;
	if (params->mask_valid)
		rcp_list->content.mask[params->lkup_idx] =
			cpu_to_le16(params->mask);

	if (params->ignore_valid)
		rcp_list->content.lkup_indx[params->lkup_idx] |=
			ICE_AQ_RECIPE_LKUP_IGNORE;

	status = ice_aq_add_recipe(hw, &rcp_list[0], 1, NULL);
	if (status)
		ice_debug(hw, ICE_DBG_SW, "Failed to update recipe %d lkup_idx %d fv_idx %d mask %d mask_valid %s, status %d\n",
			  params->rid, params->lkup_idx, params->fv_idx,
			  params->mask, params->mask_valid ? "true" : "false",
			  status);

error_out:
	devm_kfree(ice_hw_to_dev(hw), rcp_list);
	return status;
}

/**
 * ice_aq_map_recipe_to_profile - Map recipe to packet profile
 * @hw: pointer to the HW struct
 * @profile_id: package profile ID to associate the recipe with
 * @r_bitmap: Recipe bitmap filled in and need to be returned as response
 * @cd: pointer to command details structure or NULL
 * Recipe to profile association (0x0291)
 */
int
ice_aq_map_recipe_to_profile(struct ice_hw *hw, u32 profile_id, u8 *r_bitmap,
			     struct ice_sq_cd *cd)
{
	struct ice_aqc_recipe_to_profile *cmd;
	struct ice_aq_desc desc;

	cmd = &desc.params.recipe_to_profile;
	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_recipe_to_profile);
	cmd->profile_id = cpu_to_le16(profile_id);
	/* Set the recipe ID bit in the bitmask to let the device know which
	 * profile we are associating the recipe to
	 */
	memcpy(cmd->recipe_assoc, r_bitmap, sizeof(cmd->recipe_assoc));

	return ice_aq_send_cmd(hw, &desc, NULL, 0, cd);
}

/**
 * ice_aq_get_recipe_to_profile - Map recipe to packet profile
 * @hw: pointer to the HW struct
 * @profile_id: package profile ID to associate the recipe with
 * @r_bitmap: Recipe bitmap filled in and need to be returned as response
 * @cd: pointer to command details structure or NULL
 * Associate profile ID with given recipe (0x0293)
 */
int
ice_aq_get_recipe_to_profile(struct ice_hw *hw, u32 profile_id, u8 *r_bitmap,
			     struct ice_sq_cd *cd)
{
	struct ice_aqc_recipe_to_profile *cmd;
	struct ice_aq_desc desc;
	int status;

	cmd = &desc.params.recipe_to_profile;
	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_recipe_to_profile);
	cmd->profile_id = cpu_to_le16(profile_id);

	status = ice_aq_send_cmd(hw, &desc, NULL, 0, cd);
	if (!status)
		memcpy(r_bitmap, cmd->recipe_assoc, sizeof(cmd->recipe_assoc));

	return status;
}

/**
 * ice_alloc_recipe - add recipe resource
 * @hw: pointer to the hardware structure
 * @rid: recipe ID returned as response to AQ call
 */
int ice_alloc_recipe(struct ice_hw *hw, u16 *rid)
{
	struct ice_aqc_alloc_free_res_elem *sw_buf;
	u16 buf_len;
	int status;

	buf_len = struct_size(sw_buf, elem, 1);
	sw_buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len, GFP_KERNEL);
	if (!sw_buf)
		return -ENOMEM;

	sw_buf->num_elems = cpu_to_le16(1);
	sw_buf->res_type = cpu_to_le16((ICE_AQC_RES_TYPE_RECIPE <<
					ICE_AQC_RES_TYPE_S) |
					ICE_AQC_RES_TYPE_FLAG_SHARED);
	status = ice_aq_alloc_free_res(hw, 1, sw_buf, buf_len,
				       ice_aqc_opc_alloc_res, NULL);
	if (!status)
		*rid = le16_to_cpu(sw_buf->elem[0].e.sw_resp);
	devm_kfree(ice_hw_to_dev(hw), sw_buf);

	return status;
}

/* ice_init_port_info - Initialize port_info with switch configuration data
 * @pi: pointer to port_info
 * @vsi_port_num: VSI number or port number
 * @type: Type of switch element (port or VSI)
 * @swid: switch ID of the switch the element is attached to
 * @pf_vf_num: PF or VF number
 * @is_vf: true if the element is a VF, false otherwise
 */
static void
ice_init_port_info(struct ice_port_info *pi, u16 vsi_port_num, u8 type,
		   u16 swid, u16 pf_vf_num, bool is_vf)
{
	switch (type) {
	case ICE_AQC_GET_SW_CONF_RESP_PHYS_PORT:
		pi->lport = (u8)(vsi_port_num & ICE_LPORT_MASK);
		pi->sw_id = swid;
		pi->pf_vf_num = pf_vf_num;
		pi->is_vf = is_vf;
		break;
	default:
		ice_debug(pi->hw, ICE_DBG_SW, "incorrect VSI/port type received\n");
		break;
	}
}

/* ice_get_initial_sw_cfg - Get initial port and default VSI data
 * @hw: pointer to the hardware structure
 */
int ice_get_initial_sw_cfg(struct ice_hw *hw)
{
	struct ice_aqc_get_sw_cfg_resp_elem *rbuf;
	u8 num_total_ports;
	u16 req_desc = 0;
	u16 num_elems;
	int status;
	u8 j = 0;
	u16 i;

	num_total_ports = 1;

	rbuf = devm_kzalloc(ice_hw_to_dev(hw), ICE_SW_CFG_MAX_BUF_LEN,
			    GFP_KERNEL);

	if (!rbuf)
		return -ENOMEM;

	/* Multiple calls to ice_aq_get_sw_cfg may be required
	 * to get all the switch configuration information. The need
	 * for additional calls is indicated by ice_aq_get_sw_cfg
	 * writing a non-zero value in req_desc
	 */
	do {
		struct ice_aqc_get_sw_cfg_resp_elem *ele;

		status = ice_aq_get_sw_cfg(hw, rbuf, ICE_SW_CFG_MAX_BUF_LEN,
					   &req_desc, &num_elems, NULL);

		if (status)
			break;

		for (i = 0, ele = rbuf; i < num_elems; i++, ele++) {
			u16 pf_vf_num, swid, vsi_port_num;
			bool is_vf = false;
			u8 res_type;

			vsi_port_num = le16_to_cpu(ele->vsi_port_num) &
				ICE_AQC_GET_SW_CONF_RESP_VSI_PORT_NUM_M;

			pf_vf_num = le16_to_cpu(ele->pf_vf_num) &
				ICE_AQC_GET_SW_CONF_RESP_FUNC_NUM_M;

			swid = le16_to_cpu(ele->swid);

			if (le16_to_cpu(ele->pf_vf_num) &
			    ICE_AQC_GET_SW_CONF_RESP_IS_VF)
				is_vf = true;

			res_type = (u8)(le16_to_cpu(ele->vsi_port_num) >>
					ICE_AQC_GET_SW_CONF_RESP_TYPE_S);

			switch (res_type) {
			case ICE_AQC_GET_SW_CONF_RESP_PHYS_PORT:
			case ICE_AQC_GET_SW_CONF_RESP_VIRT_PORT:
				if (j == num_total_ports) {
					ice_debug(hw, ICE_DBG_SW, "more ports than expected\n");
					status = -EIO;
					goto out;
				}
				ice_init_port_info(hw->port_info,
						   vsi_port_num, res_type, swid,
						   pf_vf_num, is_vf);
				j++;
				break;
			default:
				break;
			}
		}
	} while (req_desc && !status);

out:
	devm_kfree(ice_hw_to_dev(hw), rbuf);
	return status;
}

/**
 * ice_dump_lkup_filters
 * @hw: pointer to the hardware structure
 * @rule_lock: pointer to lock that's protecting filter list
 * @rule_head: pointer to head of filter list
 * @lkup: type of switch lookup rule
 *
 * Helper function that prints all filters for a particular switch
 * lookup type
 */
static void ice_dump_lkup_filters(struct ice_hw *hw, struct mutex *rule_lock,
				  struct list_head *rule_head,
				  enum ice_sw_lkup_type lkup)
{
	struct ice_fltr_mgmt_list_entry *fm_entry;
	char extra_param[128] = {'\0'};
	char mac_addr[ETH_ALEN];

	memset(mac_addr, 0, ETH_ALEN);
	mutex_lock(rule_lock);
	list_for_each_entry(fm_entry, rule_head, list_entry) {
		struct ice_fltr_info *fi = &fm_entry->fltr_info;

		if (lkup == ICE_SW_LKUP_MAC || lkup == ICE_SW_LKUP_PROMISC) {
			ether_addr_copy(mac_addr, fi->l_data.mac.mac_addr);
		} else if (lkup == ICE_SW_LKUP_MAC_VLAN) {
			ether_addr_copy(mac_addr,
					fi->l_data.mac_vlan.mac_addr);
			snprintf(extra_param, sizeof(extra_param),
				 "vlan_id = %d", fi->l_data.mac_vlan.vlan_id);
		} else if (lkup == ICE_SW_LKUP_ETHERTYPE_MAC) {
			ether_addr_copy(mac_addr,
					fi->l_data.ethertype_mac.mac_addr);
			snprintf(extra_param, sizeof(extra_param),
				 "ethertype = %d",
				 fi->l_data.ethertype_mac.ethertype);
		}

		dev_info(ice_hw_to_dev(hw),
			 "\tmac: %pM, vsi_count = %d, fw_act_flag = %d, lb_en = %d, lan_en = %d, filt_act = %d, filt_rule_id = %d %s\n",
			 mac_addr, fm_entry->vsi_count, fi->flag, fi->lb_en,
			 fi->lan_en, fi->fltr_act, fi->fltr_rule_id,
			 extra_param);
	}
	mutex_unlock(rule_lock);
}

/**
 * ice_dump_all_sw_rules
 * @hw: pointer to the hardware structure
 * @lkup: switch rule filter lookup type
 * @recp_list: pointer to recipes
 *
 * Helper function to print filter information of all entries in the list for a
 * given lookup type
 */
static void
ice_dump_all_sw_rules(struct ice_hw *hw, enum ice_sw_lkup_type lkup,
		      struct ice_sw_recipe *recp_list)
{
	struct ice_fltr_mgmt_list_entry *fm_entry;
	struct list_head *rule_head;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	struct ice_fltr_info *fi;

	rule_lock = &recp_list->filt_rule_lock;
	rule_head = &recp_list->filt_rules;

	switch (lkup) {
	case ICE_SW_LKUP_MAC:
		/* dump MAC hash list */
		dev_info(ice_hw_to_dev(hw),
			 "\tDump MAC hash list of lookup type %d\n", lkup);
		ice_dump_lkup_filters(hw, rule_lock, rule_head, lkup);
		break;
	case ICE_SW_LKUP_VLAN:
		/* dump VLAN hash list */
		dev_info(ice_hw_to_dev(hw),
			 "\tDump VLAN hash list of lookup type %d\n", lkup);
		mutex_lock(rule_lock);
		list_for_each_entry(fm_entry, rule_head, list_entry) {
			fi = &fm_entry->fltr_info;
			dev_info(ice_hw_to_dev(hw),
				 "\tvlan_id = %d, vlan_tpid = 0x%04x, vsi_count = %d, vsi_list_id = %d, fw_act_flag = %d, filt_act = %d, lb_en = %d, lan_en = %d, filt_rule_id = %d\n",
				 fi->l_data.vlan.vlan_id,
				 fi->l_data.vlan.tpid_valid ? fi->l_data.vlan.tpid : ETH_P_8021Q,
				 fm_entry->vsi_count, fi->fwd_id.vsi_list_id,
				 fi->flag, fi->lb_en, fi->lan_en,
				 fi->fltr_act, fi->fltr_rule_id);
		}
		mutex_unlock(rule_lock);
		break;
	case ICE_SW_LKUP_MAC_VLAN:
		/* dump MAC VLAN hash list */
		dev_info(ice_hw_to_dev(hw),
			 "\tDump MAC VLAN hash list of lookup type %d\n",
			 lkup);
		ice_dump_lkup_filters(hw, rule_lock, rule_head, lkup);
		break;
	case ICE_SW_LKUP_ETHERTYPE:
		/* dump Ethertype/Ethertype MAC hash list */
		dev_info(ice_hw_to_dev(hw),
			 "\tDump Ethertype hash list of lookup type %d\n",
			 lkup);
		mutex_lock(rule_lock);
		list_for_each_entry(fm_entry, rule_head, list_entry) {
			fi = &fm_entry->fltr_info;
			dev_info(ice_hw_to_dev(hw),
				 "\tethertype = %d, vsi_count = %d, fw_act_flag = %d, filt_act = %d, lb_en = %d, lan_en = %d, filt_rule_id = %d\n",
				 fi->l_data.ethertype_mac.ethertype,
				 fm_entry->vsi_count, fi->flag, fi->fltr_act,
				 fi->lb_en, fi->lan_en, fi->fltr_rule_id);
		}
		mutex_unlock(rule_lock);
		break;
	case ICE_SW_LKUP_ETHERTYPE_MAC:
		/* dump Ethertype/Ethertype MAC hash list */
		dev_info(ice_hw_to_dev(hw),
			 "\tDump Ethertype MAC hash list of lookup type %d\n",
			 lkup);
		ice_dump_lkup_filters(hw, rule_lock, rule_head, lkup);
		break;
	case ICE_SW_LKUP_PROMISC:
		/* dump Promisc mode hash list */
		dev_info(ice_hw_to_dev(hw),
			 "\tDump Promisc/Promisc VLAN mode hash list of lookup type %d\n",
			 lkup);
		dev_info(ice_hw_to_dev(hw),
			 "\tNote: Ignore VLAN in case of Promisc only lookup type & ignore MAC in case of Promisc VLAN lookup type\n");
		ice_dump_lkup_filters(hw, rule_lock, rule_head, lkup);
		break;
	case ICE_SW_LKUP_DFLT:
		dev_info(ice_hw_to_dev(hw),
			 "\tDump Default VSI's VLAN mode hash list of lookup type %d\n",
			 lkup);
		ice_dump_lkup_filters(hw, rule_lock, rule_head, lkup);
		break;
	case ICE_SW_LKUP_PROMISC_VLAN:
	case ICE_SW_LKUP_LAST:
		dev_info(ice_hw_to_dev(hw),
			 "\tDump for this lookup type hasn't been implemented yet\n");
		break;
	}
}

/**
 * ice_fill_sw_info - Helper function to populate lb_en and lan_en
 * @hw: pointer to the hardware structure
 * @fi: filter info structure to fill/update
 *
 * This helper function populates the lb_en and lan_en elements of the provided
 * ice_fltr_info struct using the switch's type and characteristics of the
 * switch rule being configured.
 */
static void ice_fill_sw_info(struct ice_hw *hw, struct ice_fltr_info *fi)
{
	fi->lb_en = false;
	fi->lan_en = false;
	if ((fi->flag & ICE_FLTR_TX) &&
	    (fi->fltr_act == ICE_FWD_TO_VSI ||
	     fi->fltr_act == ICE_FWD_TO_VSI_LIST ||
	     fi->fltr_act == ICE_FWD_TO_Q ||
	     fi->fltr_act == ICE_FWD_TO_QGRP)) {
		/* Setting LB for prune actions will result in replicated
		 * packets to the internal switch that will be dropped.
		 */
		if (fi->lkup_type != ICE_SW_LKUP_VLAN)
			fi->lb_en = true;

		/* Set lan_en to TRUE if
		 * 1. The switch is a VEB AND
		 * 2
		 * 2.1 The lookup is a directional lookup like ethertype,
		 * promiscuous, ethertype-MAC, promiscuous-VLAN
		 * and default-port OR
		 * 2.2 The lookup is VLAN, OR
		 * 2.3 The lookup is MAC with mcast or bcast addr for MAC, OR
		 * 2.4 The lookup is MAC_VLAN with mcast or bcast addr for MAC.
		 *
		 * OR
		 *
		 * The switch is a VEPA.
		 *
		 * In all other cases, the LAN enable has to be set to false.
		 */

		if (hw->evb_veb) {
			if (fi->lkup_type == ICE_SW_LKUP_ETHERTYPE ||
			    fi->lkup_type == ICE_SW_LKUP_PROMISC ||
			    fi->lkup_type == ICE_SW_LKUP_ETHERTYPE_MAC ||
			    fi->lkup_type == ICE_SW_LKUP_PROMISC_VLAN ||
			    fi->lkup_type == ICE_SW_LKUP_DFLT ||
			    fi->lkup_type == ICE_SW_LKUP_VLAN ||
			    (fi->lkup_type == ICE_SW_LKUP_MAC &&
			     !is_unicast_ether_addr(fi->l_data.mac.mac_addr)) ||
			    (fi->lkup_type == ICE_SW_LKUP_MAC_VLAN &&
			     !is_unicast_ether_addr(fi->l_data.mac.mac_addr)))
				fi->lan_en = true;
		} else {
			fi->lan_en = true;
		}
	}
	/* To be able to receive packets coming from the VF on the same PF,
	 * unicast filter needs to be added without LB_EN bit
	 */
	if (fi->flag & ICE_FLTR_RX_LB) {
		fi->lb_en = false;
		fi->lan_en = true;
	}
}

/**
 * ice_fill_sw_rule - Helper function to fill switch rule structure
 * @hw: pointer to the hardware structure
 * @f_info: entry containing packet forwarding information
 * @s_rule: switch rule structure to be filled in based on mac_entry
 * @opc: switch rules population command type - pass in the command opcode
 */
static void
ice_fill_sw_rule(struct ice_hw *hw, struct ice_fltr_info *f_info,
		 struct ice_sw_rule_lkup_rx_tx *s_rule,
		 enum ice_adminq_opc opc)
{
	u16 vlan_id = ICE_MAX_VLAN_ID + 1;
	u16 vlan_tpid = ETH_P_8021Q;
	void *daddr = NULL;
	u16 eth_hdr_sz;
	u8 *eth_hdr;
	u32 act = 0;
	__be16 *off;
	u8 q_rgn;

	if (opc == ice_aqc_opc_remove_sw_rules) {
		s_rule->act = 0;
		s_rule->index = cpu_to_le16(f_info->fltr_rule_id);
		s_rule->hdr_len = 0;
		return;
	}

	eth_hdr_sz = sizeof(dummy_eth_header);
	eth_hdr = s_rule->hdr_data;

	/* initialize the ether header with a dummy header */
	memcpy(eth_hdr, dummy_eth_header, eth_hdr_sz);
	ice_fill_sw_info(hw, f_info);

	switch (f_info->fltr_act) {
	case ICE_FWD_TO_VSI:
		act |= (f_info->fwd_id.hw_vsi_id << ICE_SINGLE_ACT_VSI_ID_S) &
			ICE_SINGLE_ACT_VSI_ID_M;
		if (f_info->lkup_type != ICE_SW_LKUP_VLAN)
			act |= ICE_SINGLE_ACT_VSI_FORWARDING |
				ICE_SINGLE_ACT_VALID_BIT;
		break;
	case ICE_FWD_TO_VSI_LIST:
		act |= ICE_SINGLE_ACT_VSI_LIST;
		act |= (f_info->fwd_id.vsi_list_id <<
			ICE_SINGLE_ACT_VSI_LIST_ID_S) &
			ICE_SINGLE_ACT_VSI_LIST_ID_M;
		if (f_info->lkup_type != ICE_SW_LKUP_VLAN)
			act |= ICE_SINGLE_ACT_VSI_FORWARDING |
				ICE_SINGLE_ACT_VALID_BIT;
		break;
	case ICE_FWD_TO_Q:
		act |= ICE_SINGLE_ACT_TO_Q;
		act |= (f_info->fwd_id.q_id << ICE_SINGLE_ACT_Q_INDEX_S) &
			ICE_SINGLE_ACT_Q_INDEX_M;
		break;
	case ICE_DROP_PACKET:
		act |= ICE_SINGLE_ACT_VSI_FORWARDING | ICE_SINGLE_ACT_DROP |
			ICE_SINGLE_ACT_VALID_BIT;
		break;
	case ICE_FWD_TO_QGRP:
		q_rgn = f_info->qgrp_size > 0 ?
			(u8)ilog2(f_info->qgrp_size) : 0;
		act |= ICE_SINGLE_ACT_TO_Q;
		act |= (f_info->fwd_id.q_id << ICE_SINGLE_ACT_Q_INDEX_S) &
			ICE_SINGLE_ACT_Q_INDEX_M;
		act |= (q_rgn << ICE_SINGLE_ACT_Q_REGION_S) &
			ICE_SINGLE_ACT_Q_REGION_M;
		break;
	default:
		return;
	}

	if (f_info->lb_en)
		act |= ICE_SINGLE_ACT_LB_ENABLE;
	if (f_info->lan_en)
		act |= ICE_SINGLE_ACT_LAN_ENABLE;

	switch (f_info->lkup_type) {
	case ICE_SW_LKUP_MAC:
		daddr = f_info->l_data.mac.mac_addr;
		break;
	case ICE_SW_LKUP_VLAN:
		vlan_id = f_info->l_data.vlan.vlan_id;
		if (f_info->l_data.vlan.tpid_valid)
			vlan_tpid = f_info->l_data.vlan.tpid;
		if (f_info->fltr_act == ICE_FWD_TO_VSI ||
		    f_info->fltr_act == ICE_FWD_TO_VSI_LIST) {
			act |= ICE_SINGLE_ACT_PRUNE;
			act |= ICE_SINGLE_ACT_EGRESS | ICE_SINGLE_ACT_INGRESS;
		}
		break;
	case ICE_SW_LKUP_ETHERTYPE_MAC:
		daddr = f_info->l_data.ethertype_mac.mac_addr;
		fallthrough;
	case ICE_SW_LKUP_ETHERTYPE:
		off = (__force __be16 *)(eth_hdr + ICE_ETH_ETHTYPE_OFFSET);
		*off = cpu_to_be16(f_info->l_data.ethertype_mac.ethertype);
		break;
	case ICE_SW_LKUP_MAC_VLAN:
		daddr = f_info->l_data.mac_vlan.mac_addr;
		vlan_id = f_info->l_data.mac_vlan.vlan_id;
		break;
	case ICE_SW_LKUP_PROMISC_VLAN:
		vlan_id = f_info->l_data.mac_vlan.vlan_id;
		fallthrough;
	case ICE_SW_LKUP_PROMISC:
		daddr = f_info->l_data.mac_vlan.mac_addr;
		break;
	default:
		break;
	}

	s_rule->hdr.type = (f_info->flag & ICE_FLTR_RX) ?
		cpu_to_le16(ICE_AQC_SW_RULES_T_LKUP_RX) :
		cpu_to_le16(ICE_AQC_SW_RULES_T_LKUP_TX);

	/* Recipe set depending on lookup type */
	s_rule->recipe_id = cpu_to_le16(f_info->lkup_type);
	s_rule->src = cpu_to_le16(f_info->src);
	s_rule->act = cpu_to_le32(act);

	if (daddr)
		ether_addr_copy(eth_hdr + ICE_ETH_DA_OFFSET, daddr);

	if (!(vlan_id > ICE_MAX_VLAN_ID)) {
		off = (__force __be16 *)(eth_hdr + ICE_ETH_VLAN_TCI_OFFSET);
		*off = cpu_to_be16(vlan_id);
		off = (__force __be16 *)(eth_hdr + ICE_ETH_ETHTYPE_OFFSET);
		*off = cpu_to_be16(vlan_tpid);
	}

	/* Create the switch rule with the final dummy Ethernet header */
	if (opc != ice_aqc_opc_update_sw_rules)
		s_rule->hdr_len = cpu_to_le16(eth_hdr_sz);
}

/**
 * ice_dump_sw_rules - Function to dump sw rules
 * @hw: pointer to the hardware structure
 * @lkup: rules type to be dumped
 */
void ice_dump_sw_rules(struct ice_hw *hw, enum ice_sw_lkup_type lkup)
{
	ice_dump_all_sw_rules(hw, lkup, &hw->switch_info->recp_list[lkup]);
}

/**
 * ice_add_marker_act
 * @hw: pointer to the hardware structure
 * @m_ent: the management entry for which sw marker needs to be added
 * @sw_marker: sw marker to tag the Rx descriptor with
 * @l_id: large action resource ID
 *
 * Create a large action to hold software marker and update the switch rule
 * entry pointed by m_ent with newly created large action
 */
static int
ice_add_marker_act(struct ice_hw *hw, struct ice_fltr_mgmt_list_entry *m_ent,
		   u16 sw_marker, u16 l_id)
{
	struct ice_sw_rule_lkup_rx_tx *rx_tx;
	struct ice_sw_rule_lg_act *lg_act;
	/* For software marker we need 3 large actions
	 * 1. FWD action: FWD TO VSI or VSI LIST
	 * 2. GENERIC VALUE action to hold the profile ID
	 * 3. GENERIC VALUE action to hold the software marker ID
	 */
	const u16 num_lg_acts = 3;
	u16 lg_act_size;
	u16 rules_size;
	int status;
	u32 act;
	u16 id;

	if (m_ent->fltr_info.lkup_type != ICE_SW_LKUP_MAC)
		return -EINVAL;

	/* Create two back-to-back switch rules and submit them to the HW using
	 * one memory buffer:
	 *    1. Large Action
	 *    2. Look up Tx Rx
	 */
	lg_act_size = (u16)struct_size(lg_act, act, num_lg_acts);
	rules_size = lg_act_size +
		     struct_size(rx_tx, hdr_data, DUMMY_ETH_HDR_LEN);
	lg_act = devm_kzalloc(ice_hw_to_dev(hw), rules_size, GFP_KERNEL);
	if (!lg_act)
		return -ENOMEM;

	rx_tx = (struct ice_sw_rule_lkup_rx_tx *)((u8 *)lg_act + lg_act_size);

	/* Fill in the first switch rule i.e. large action */
	lg_act->hdr.type = cpu_to_le16(ICE_AQC_SW_RULES_T_LG_ACT);
	lg_act->index = cpu_to_le16(l_id);
	lg_act->size = cpu_to_le16(num_lg_acts);

	/* First action VSI forwarding or VSI list forwarding depending on how
	 * many VSIs
	 */
	id = (m_ent->vsi_count > 1) ? m_ent->fltr_info.fwd_id.vsi_list_id :
		m_ent->fltr_info.fwd_id.hw_vsi_id;

	act = ICE_LG_ACT_VSI_FORWARDING | ICE_LG_ACT_VALID_BIT;
	act |= (id << ICE_LG_ACT_VSI_LIST_ID_S) & ICE_LG_ACT_VSI_LIST_ID_M;
	if (m_ent->vsi_count > 1)
		act |= ICE_LG_ACT_VSI_LIST;
	lg_act->act[0] = cpu_to_le32(act);

	/* Second action descriptor type */
	act = ICE_LG_ACT_GENERIC;

	act |= (1 << ICE_LG_ACT_GENERIC_VALUE_S) & ICE_LG_ACT_GENERIC_VALUE_M;
	lg_act->act[1] = cpu_to_le32(act);

	act = (ICE_LG_ACT_GENERIC_OFF_RX_DESC_PROF_IDX <<
	       ICE_LG_ACT_GENERIC_OFFSET_S) & ICE_LG_ACT_GENERIC_OFFSET_M;

	/* Third action Marker value */
	act |= ICE_LG_ACT_GENERIC;
	act |= (sw_marker << ICE_LG_ACT_GENERIC_VALUE_S) &
		ICE_LG_ACT_GENERIC_VALUE_M;

	lg_act->act[2] = cpu_to_le32(act);

	/* call the fill switch rule to fill the lookup Tx Rx structure */
	ice_fill_sw_rule(hw, &m_ent->fltr_info, rx_tx,
			 ice_aqc_opc_update_sw_rules);

	/* Update the action to point to the large action ID */
	rx_tx->act = cpu_to_le32(ICE_SINGLE_ACT_PTR |
				 ((l_id << ICE_SINGLE_ACT_PTR_VAL_S) &
				  ICE_SINGLE_ACT_PTR_VAL_M));

	/* Use the filter rule ID of the previously created rule with single
	 * act. Once the update happens, hardware will treat this as large
	 * action
	 */
	rx_tx->index = cpu_to_le16(m_ent->fltr_info.fltr_rule_id);

	status = ice_aq_sw_rules(hw, lg_act, rules_size, 2,
				 ice_aqc_opc_update_sw_rules, NULL);
	if (!status) {
		m_ent->lg_act_idx = l_id;
		m_ent->sw_marker_id = sw_marker;
	}

	devm_kfree(ice_hw_to_dev(hw), lg_act);
	return status;
}

/**
 * ice_add_counter_act - add/update filter rule with counter action
 * @hw: pointer to the hardware structure
 * @m_ent: the management entry for which counter needs to be added
 * @counter_id: VLAN counter ID returned as part of allocate resource
 * @l_id: large action resource ID
 */
static int
ice_add_counter_act(struct ice_hw *hw, struct ice_fltr_mgmt_list_entry *m_ent,
		    u16 counter_id, u16 l_id)
{
	struct ice_sw_rule_lkup_rx_tx *rx_tx;
	struct ice_sw_rule_lg_act *lg_act;
	/* 2 actions will be added while adding a large action counter */
	const int num_acts = 2;
	u16 lg_act_size;
	u16 rules_size;
	u16 f_rule_id;
	u32 act;
	int status;
	u16 id;

	if (m_ent->fltr_info.lkup_type != ICE_SW_LKUP_MAC)
		return -EINVAL;

	/* Create two back-to-back switch rules and submit them to the HW using
	 * one memory buffer:
	 * 1. Large Action
	 * 2. Look up Tx Rx
	 */
	lg_act_size = (u16)struct_size(lg_act, act, num_acts);
	rules_size = lg_act_size +
		     struct_size(rx_tx, hdr_data, DUMMY_ETH_HDR_LEN);
	lg_act = devm_kzalloc(ice_hw_to_dev(hw), rules_size, GFP_KERNEL);
	if (!lg_act)
		return -ENOMEM;

	rx_tx = (struct ice_sw_rule_lkup_rx_tx *)((u8 *)lg_act +
						      lg_act_size);

	/* Fill in the first switch rule i.e. large action */
	lg_act->hdr.type = cpu_to_le16(ICE_AQC_SW_RULES_T_LG_ACT);
	lg_act->index = cpu_to_le16(l_id);
	lg_act->size = cpu_to_le16(num_acts);

	/* First action VSI forwarding or VSI list forwarding depending on how
	 * many VSIs
	 */
	id = (m_ent->vsi_count > 1) ?  m_ent->fltr_info.fwd_id.vsi_list_id :
		m_ent->fltr_info.fwd_id.hw_vsi_id;

	act = ICE_LG_ACT_VSI_FORWARDING | ICE_LG_ACT_VALID_BIT;
	act |= (id << ICE_LG_ACT_VSI_LIST_ID_S) &
		ICE_LG_ACT_VSI_LIST_ID_M;
	if (m_ent->vsi_count > 1)
		act |= ICE_LG_ACT_VSI_LIST;
	lg_act->act[0] = cpu_to_le32(act);

	/* Second action counter ID */
	act = ICE_LG_ACT_STAT_COUNT;
	act |= (counter_id << ICE_LG_ACT_STAT_COUNT_S) &
		ICE_LG_ACT_STAT_COUNT_M;
	lg_act->act[1] = cpu_to_le32(act);

	/* call the fill switch rule to fill the lookup Tx Rx structure */
	ice_fill_sw_rule(hw, &m_ent->fltr_info, rx_tx,
			 ice_aqc_opc_update_sw_rules);

	act = ICE_SINGLE_ACT_PTR;
	act |= (l_id << ICE_SINGLE_ACT_PTR_VAL_S) & ICE_SINGLE_ACT_PTR_VAL_M;
	rx_tx->act = cpu_to_le32(act);

	/* Use the filter rule ID of the previously created rule with single
	 * act. Once the update happens, hardware will treat this as large
	 * action
	 */
	f_rule_id = m_ent->fltr_info.fltr_rule_id;
	rx_tx->index = cpu_to_le16(f_rule_id);

	status = ice_aq_sw_rules(hw, lg_act, rules_size, 2,
				 ice_aqc_opc_update_sw_rules, NULL);
	if (!status) {
		m_ent->lg_act_idx = l_id;
		m_ent->counter_index = (u8)counter_id;
	}

	devm_kfree(ice_hw_to_dev(hw), lg_act);
	return status;
}

/**
 * ice_create_vsi_list_map
 * @hw: pointer to the hardware structure
 * @vsi_handle_arr: array of VSI handles to set in the VSI mapping
 * @num_vsi: number of VSI handles in the array
 * @vsi_list_id: VSI list ID generated as part of allocate resource
 *
 * Helper function to create a new entry of VSI list ID to VSI mapping
 * using the given VSI list ID
 */
static struct ice_vsi_list_map_info *
ice_create_vsi_list_map(struct ice_hw *hw, u16 *vsi_handle_arr, u16 num_vsi,
			u16 vsi_list_id)
{
	struct ice_switch_info *sw = hw->switch_info;
	struct ice_vsi_list_map_info *v_map;
	int i;

	v_map = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*v_map), GFP_KERNEL);
	if (!v_map)
		return NULL;

	v_map->vsi_list_id = vsi_list_id;
	v_map->ref_cnt = 1;
	for (i = 0; i < num_vsi; i++)
		set_bit(vsi_handle_arr[i], v_map->vsi_map);

	list_add(&v_map->list_entry, &sw->vsi_list_map_head);
	return v_map;
}

/**
 * ice_update_vsi_list_rule
 * @hw: pointer to the hardware structure
 * @vsi_handle_arr: array of VSI handles to form a VSI list
 * @num_vsi: number of VSI handles in the array
 * @vsi_list_id: VSI list ID generated as part of allocate resource
 * @remove: Boolean value to indicate if this is a remove action
 * @opc: switch rules population command type - pass in the command opcode
 * @lkup_type: lookup type of the filter
 *
 * Call AQ command to add a new switch rule or update existing switch rule
 * using the given VSI list ID
 */
static int
ice_update_vsi_list_rule(struct ice_hw *hw, u16 *vsi_handle_arr, u16 num_vsi,
			 u16 vsi_list_id, bool remove, enum ice_adminq_opc opc,
			 enum ice_sw_lkup_type lkup_type)
{
	struct ice_sw_rule_vsi_list *s_rule;
	u16 s_rule_size;
	u16 rule_type;
	int status;
	int i;

	if (!num_vsi)
		return -EINVAL;

	if (lkup_type == ICE_SW_LKUP_MAC ||
	    lkup_type == ICE_SW_LKUP_MAC_VLAN ||
	    lkup_type == ICE_SW_LKUP_ETHERTYPE ||
	    lkup_type == ICE_SW_LKUP_ETHERTYPE_MAC ||
	    lkup_type == ICE_SW_LKUP_PROMISC ||
	    lkup_type == ICE_SW_LKUP_PROMISC_VLAN ||
	    lkup_type == ICE_SW_LKUP_DFLT ||
	    lkup_type == ICE_SW_LKUP_LAST)
		rule_type = remove ? ICE_AQC_SW_RULES_T_VSI_LIST_CLEAR :
			ICE_AQC_SW_RULES_T_VSI_LIST_SET;
	else if (lkup_type == ICE_SW_LKUP_VLAN)
		rule_type = remove ? ICE_AQC_SW_RULES_T_PRUNE_LIST_CLEAR :
			ICE_AQC_SW_RULES_T_PRUNE_LIST_SET;
	else
		return -EINVAL;

	s_rule_size = (u16)struct_size(s_rule, vsi, num_vsi);
	s_rule = devm_kzalloc(ice_hw_to_dev(hw), s_rule_size, GFP_KERNEL);
	if (!s_rule)
		return -ENOMEM;
	for (i = 0; i < num_vsi; i++) {
		if (!ice_is_vsi_valid(hw, vsi_handle_arr[i])) {
			status = -EINVAL;
			goto exit;
		}
		/* AQ call requires hw_vsi_id(s) */
		s_rule->vsi[i] =
			cpu_to_le16(ice_get_hw_vsi_num(hw, vsi_handle_arr[i]));
	}

	s_rule->hdr.type = cpu_to_le16(rule_type);
	s_rule->number_vsi = cpu_to_le16(num_vsi);
	s_rule->index = cpu_to_le16(vsi_list_id);

	status = ice_aq_sw_rules(hw, s_rule, s_rule_size, 1, opc, NULL);

exit:
	devm_kfree(ice_hw_to_dev(hw), s_rule);
	return status;
}

/**
 * ice_create_vsi_list_rule - Creates and populates a VSI list rule
 * @hw: pointer to the HW struct
 * @vsi_handle_arr: array of VSI handles to form a VSI list
 * @num_vsi: number of VSI handles in the array
 * @vsi_list_id: stores the ID of the VSI list to be created
 * @lkup_type: switch rule filter's lookup type
 */
static int
ice_create_vsi_list_rule(struct ice_hw *hw, u16 *vsi_handle_arr, u16 num_vsi,
			 u16 *vsi_list_id, enum ice_sw_lkup_type lkup_type)
{
	int status;

	status = ice_aq_alloc_free_vsi_list(hw, vsi_list_id, lkup_type,
					    ice_aqc_opc_alloc_res);
	if (status)
		return status;

	/* Update the newly created VSI list to include the specified VSIs */
	return ice_update_vsi_list_rule(hw, vsi_handle_arr, num_vsi,
					*vsi_list_id, false,
					ice_aqc_opc_add_sw_rules, lkup_type);
}

/**
 * ice_create_pkt_fwd_rule
 * @hw: pointer to the hardware structure
 * @recp_list: corresponding filter management list
 * @f_entry: entry containing packet forwarding information
 *
 * Create switch rule with given filter information and add an entry
 * to the corresponding filter management list to track this switch rule
 * and VSI mapping
 */
static int
ice_create_pkt_fwd_rule(struct ice_hw *hw, struct ice_sw_recipe *recp_list,
			struct ice_fltr_list_entry *f_entry)
{
	struct ice_fltr_mgmt_list_entry *fm_entry;
	struct ice_sw_rule_lkup_rx_tx *s_rule;
	int status;

	s_rule = devm_kzalloc(ice_hw_to_dev(hw),
			      struct_size(s_rule, hdr_data, DUMMY_ETH_HDR_LEN),
			      GFP_KERNEL);
	if (!s_rule)
		return -ENOMEM;
	fm_entry = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*fm_entry),
				GFP_KERNEL);
	if (!fm_entry) {
		status = -ENOMEM;
		goto ice_create_pkt_fwd_rule_exit;
	}

	fm_entry->fltr_info = f_entry->fltr_info;

	/* Initialize all the fields for the management entry */
	fm_entry->vsi_count = 1;
	fm_entry->lg_act_idx = ICE_INVAL_LG_ACT_INDEX;
	fm_entry->sw_marker_id = ICE_INVAL_SW_MARKER_ID;
	fm_entry->counter_index = ICE_INVAL_COUNTER_ID;

	ice_fill_sw_rule(hw, &fm_entry->fltr_info, s_rule,
			 ice_aqc_opc_add_sw_rules);

	status = ice_aq_sw_rules(hw, s_rule,
				 struct_size(s_rule, hdr_data, DUMMY_ETH_HDR_LEN),
				 1, ice_aqc_opc_add_sw_rules, NULL);
	if (status) {
		devm_kfree(ice_hw_to_dev(hw), fm_entry);
		goto ice_create_pkt_fwd_rule_exit;
	}

	f_entry->fltr_info.fltr_rule_id = le16_to_cpu(s_rule->index);
	fm_entry->fltr_info.fltr_rule_id = le16_to_cpu(s_rule->index);

	/* The book keeping entries will get removed when base driver
	 * calls remove filter AQ command
	 */
	list_add(&fm_entry->list_entry, &recp_list->filt_rules);

ice_create_pkt_fwd_rule_exit:
	devm_kfree(ice_hw_to_dev(hw), s_rule);
	return status;
}

/**
 * ice_update_pkt_fwd_rule
 * @hw: pointer to the hardware structure
 * @f_info: filter information for switch rule
 *
 * Call AQ command to update a previously created switch rule with a
 * VSI list ID
 */
static int
ice_update_pkt_fwd_rule(struct ice_hw *hw, struct ice_fltr_info *f_info)
{
	struct ice_sw_rule_lkup_rx_tx *s_rule;
	int status;

	s_rule = devm_kzalloc(ice_hw_to_dev(hw),
			      struct_size(s_rule, hdr_data, DUMMY_ETH_HDR_LEN),
			      GFP_KERNEL);
	if (!s_rule)
		return -ENOMEM;

	ice_fill_sw_rule(hw, f_info, s_rule, ice_aqc_opc_update_sw_rules);

	s_rule->index = cpu_to_le16(f_info->fltr_rule_id);

	/* Update switch rule with new rule set to forward VSI list */
	status = ice_aq_sw_rules(hw, s_rule,
				 struct_size(s_rule, hdr_data, DUMMY_ETH_HDR_LEN),
				 1, ice_aqc_opc_update_sw_rules, NULL);

	devm_kfree(ice_hw_to_dev(hw), s_rule);
	return status;
}

/**
 * ice_update_sw_rule_bridge_mode
 * @hw: pointer to the HW struct
 *
 * Updates unicast switch filter rules based on VEB/VEPA mode
 */
int ice_update_sw_rule_bridge_mode(struct ice_hw *hw)
{
	struct ice_fltr_mgmt_list_entry *fm_entry;
	struct ice_switch_info *sw = NULL;
	struct list_head *rule_head;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	int status = 0;

	sw = hw->switch_info;

	rule_lock = &sw->recp_list[ICE_SW_LKUP_MAC].filt_rule_lock;
	rule_head = &sw->recp_list[ICE_SW_LKUP_MAC].filt_rules;

	mutex_lock(rule_lock);
	list_for_each_entry(fm_entry, rule_head, list_entry) {
		struct ice_fltr_info *fi = &fm_entry->fltr_info;
		u8 *addr = fi->l_data.mac.mac_addr;

		/* Update unicast Tx rules to reflect the selected
		 * VEB/VEPA mode
		 */
		if ((fi->flag & ICE_FLTR_TX) && is_unicast_ether_addr(addr) &&
		    (fi->fltr_act == ICE_FWD_TO_VSI ||
		     fi->fltr_act == ICE_FWD_TO_VSI_LIST ||
		     fi->fltr_act == ICE_FWD_TO_Q ||
		     fi->fltr_act == ICE_FWD_TO_QGRP)) {
			status = ice_update_pkt_fwd_rule(hw, fi);
			if (status)
				break;
		}
	}

	mutex_unlock(rule_lock);

	return status;
}

/**
 * ice_add_update_vsi_list
 * @hw: pointer to the hardware structure
 * @m_entry: pointer to current filter management list entry
 * @cur_fltr: filter information from the book keeping entry
 * @new_fltr: filter information with the new VSI to be added
 *
 * Call AQ command to add or update previously created VSI list with new VSI.
 *
 * Helper function to do book keeping associated with adding filter information
 * The algorithm to do the book keeping is described below :
 * When a VSI needs to subscribe to a given filter (MAC/VLAN/Ethtype etc.)
 *	if only one VSI has been added till now
 *		Allocate a new VSI list and add two VSIs
 *		to this list using switch rule command
 *		Update the previously created switch rule with the
 *		newly created VSI list ID
 *	if a VSI list was previously created
 *		Add the new VSI to the previously created VSI list set
 *		using the update switch rule command
 */
static int
ice_add_update_vsi_list(struct ice_hw *hw,
			struct ice_fltr_mgmt_list_entry *m_entry,
			struct ice_fltr_info *cur_fltr,
			struct ice_fltr_info *new_fltr)
{
	u16 vsi_list_id = 0;
	int status = 0;

	if ((cur_fltr->fltr_act == ICE_FWD_TO_Q ||
	     cur_fltr->fltr_act == ICE_FWD_TO_QGRP))
		return -EOPNOTSUPP;

	if ((new_fltr->fltr_act == ICE_FWD_TO_Q ||
	     new_fltr->fltr_act == ICE_FWD_TO_QGRP) &&
	    (cur_fltr->fltr_act == ICE_FWD_TO_VSI ||
	     cur_fltr->fltr_act == ICE_FWD_TO_VSI_LIST))
		return -EOPNOTSUPP;

	if (m_entry->vsi_count < 2 && !m_entry->vsi_list_info) {
		/* Only one entry existed in the mapping and it was not already
		 * a part of a VSI list. So, create a VSI list with the old and
		 * new VSIs.
		 */
		struct ice_fltr_info tmp_fltr;
		u16 vsi_handle_arr[2];

		/* A rule already exists with the new VSI being added */
		if (cur_fltr->fwd_id.hw_vsi_id == new_fltr->fwd_id.hw_vsi_id)
			return -EEXIST;

		vsi_handle_arr[0] = cur_fltr->vsi_handle;
		vsi_handle_arr[1] = new_fltr->vsi_handle;
		status = ice_create_vsi_list_rule(hw, &vsi_handle_arr[0], 2,
						  &vsi_list_id,
						  new_fltr->lkup_type);
		if (status)
			return status;

		tmp_fltr = *new_fltr;
		tmp_fltr.fltr_rule_id = cur_fltr->fltr_rule_id;
		tmp_fltr.fltr_act = ICE_FWD_TO_VSI_LIST;
		tmp_fltr.fwd_id.vsi_list_id = vsi_list_id;
		/* Update the previous switch rule of "MAC forward to VSI" to
		 * "MAC fwd to VSI list"
		 */
		status = ice_update_pkt_fwd_rule(hw, &tmp_fltr);
		if (status)
			return status;

		cur_fltr->fwd_id.vsi_list_id = vsi_list_id;
		cur_fltr->fltr_act = ICE_FWD_TO_VSI_LIST;
		m_entry->vsi_list_info =
			ice_create_vsi_list_map(hw, &vsi_handle_arr[0], 2,
						vsi_list_id);

		if (!m_entry->vsi_list_info)
			return -ENOMEM;

		/* If this entry was large action then the large action needs
		 * to be updated to point to FWD to VSI list
		 */
		if (m_entry->sw_marker_id != ICE_INVAL_SW_MARKER_ID)
			status =
			    ice_add_marker_act(hw, m_entry,
					       m_entry->sw_marker_id,
					       m_entry->lg_act_idx);
	} else {
		u16 vsi_handle = new_fltr->vsi_handle;
		enum ice_adminq_opc opcode;

		if (!m_entry->vsi_list_info)
			return -EIO;

		/* A rule already exists with the new VSI being added */
		if (test_bit(vsi_handle, m_entry->vsi_list_info->vsi_map))
			return 0;

		/* Update the previously created VSI list set with
		 * the new VSI ID passed in
		 */
		vsi_list_id = cur_fltr->fwd_id.vsi_list_id;
		opcode = ice_aqc_opc_update_sw_rules;

		status = ice_update_vsi_list_rule(hw, &vsi_handle, 1,
						  vsi_list_id, false, opcode,
						  new_fltr->lkup_type);
		/* update VSI list mapping info with new VSI ID */
		if (!status)
			set_bit(vsi_handle, m_entry->vsi_list_info->vsi_map);
	}
	if (!status)
		m_entry->vsi_count++;
	return status;
}

/**
 * ice_find_rule_entry - Search a rule entry
 * @list_head: head of rule list
 * @f_info: rule information
 *
 * Helper function to search for a given rule entry
 * Returns pointer to entry storing the rule if found
 */
static struct ice_fltr_mgmt_list_entry *
ice_find_rule_entry(struct list_head *list_head,
		    struct ice_fltr_info *f_info)
{
	struct ice_fltr_mgmt_list_entry *list_itr, *ret = NULL;

	list_for_each_entry(list_itr, list_head, list_entry) {
		if (!memcmp(&f_info->l_data, &list_itr->fltr_info.l_data,
			    sizeof(f_info->l_data)) &&
		    f_info->flag == list_itr->fltr_info.flag) {
			ret = list_itr;
			break;
		}
	}
	return ret;
}

/**
 * ice_find_vsi_list_entry - Search VSI list map with VSI count 1
 * @recp_list: VSI lists needs to be searched
 * @vsi_handle: VSI handle to be found in VSI list
 * @vsi_list_id: VSI list ID found containing vsi_handle
 *
 * Helper function to search a VSI list with single entry containing given VSI
 * handle element. This can be extended further to search VSI list with more
 * than 1 vsi_count. Returns pointer to VSI list entry if found.
 */
struct ice_vsi_list_map_info *
ice_find_vsi_list_entry(struct ice_sw_recipe *recp_list, u16 vsi_handle,
			u16 *vsi_list_id)
{
	struct ice_vsi_list_map_info *map_info = NULL;
	struct list_head *list_head;

	list_head = &recp_list->filt_rules;
	if (recp_list->adv_rule) {
		struct ice_adv_fltr_mgmt_list_entry *list_itr;

		list_for_each_entry(list_itr, list_head, list_entry) {
			if (list_itr->vsi_list_info) {
				map_info = list_itr->vsi_list_info;
				if (test_bit(vsi_handle, map_info->vsi_map)) {
					*vsi_list_id = map_info->vsi_list_id;
					return map_info;
				}
			}
		}
	} else {
		struct ice_fltr_mgmt_list_entry *list_itr;

		list_for_each_entry(list_itr, list_head, list_entry) {
			if (list_itr->vsi_count == 1 &&
			    list_itr->vsi_list_info) {
				map_info = list_itr->vsi_list_info;
				if (test_bit(vsi_handle, map_info->vsi_map)) {
					*vsi_list_id = map_info->vsi_list_id;
					return map_info;
				}
			}
		}
	}
	return NULL;
}

/**
 * ice_add_rule_internal - add rule for a given lookup type
 * @hw: pointer to the hardware structure
 * @recp_list: recipe list for which rule has to be added
 * @lport: logic port number on which function add rule
 * @f_entry: structure containing MAC forwarding information
 *
 * Adds or updates the rule lists for a given recipe
 */
static int
ice_add_rule_internal(struct ice_hw *hw, struct ice_sw_recipe *recp_list,
		      u8 lport, struct ice_fltr_list_entry *f_entry)
{
	struct ice_fltr_info *new_fltr, *cur_fltr;
	struct ice_fltr_mgmt_list_entry *m_entry;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	int status = 0;

	if (!ice_is_vsi_valid(hw, f_entry->fltr_info.vsi_handle))
		return -EINVAL;

	/* Load the hw_vsi_id only if the fwd action is fwd to VSI */
	if (f_entry->fltr_info.fltr_act == ICE_FWD_TO_VSI)
		f_entry->fltr_info.fwd_id.hw_vsi_id =
			ice_get_hw_vsi_num(hw, f_entry->fltr_info.vsi_handle);

	rule_lock = &recp_list->filt_rule_lock;

	mutex_lock(rule_lock);
	new_fltr = &f_entry->fltr_info;
	if (new_fltr->flag & ICE_FLTR_RX)
		new_fltr->src = lport;
	else if (new_fltr->flag & (ICE_FLTR_TX | ICE_FLTR_RX_LB))
		new_fltr->src =
			ice_get_hw_vsi_num(hw, f_entry->fltr_info.vsi_handle);

	m_entry = ice_find_rule_entry(&recp_list->filt_rules, new_fltr);
	if (!m_entry) {
		status = ice_create_pkt_fwd_rule(hw, recp_list, f_entry);
		goto exit_add_rule_internal;
	}

	cur_fltr = &m_entry->fltr_info;
	status = ice_add_update_vsi_list(hw, m_entry, cur_fltr, new_fltr);

exit_add_rule_internal:
	mutex_unlock(rule_lock);
	return status;
}

/**
 * ice_remove_vsi_list_rule
 * @hw: pointer to the hardware structure
 * @vsi_list_id: VSI list ID generated as part of allocate resource
 * @lkup_type: switch rule filter lookup type
 *
 * The VSI list should be emptied before this function is called to remove the
 * VSI list.
 */
static int
ice_remove_vsi_list_rule(struct ice_hw *hw, u16 vsi_list_id,
			 enum ice_sw_lkup_type lkup_type)
{
	/* Free the vsi_list resource that we allocated. It is assumed that the
	 * list is empty at this point.
	 */
	return ice_aq_alloc_free_vsi_list(hw, &vsi_list_id, lkup_type,
					    ice_aqc_opc_free_res);
}

/**
 * ice_rem_update_vsi_list
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle of the VSI to remove
 * @fm_list: filter management entry for which the VSI list management needs to
 *           be done
 */
static int
ice_rem_update_vsi_list(struct ice_hw *hw, u16 vsi_handle,
			struct ice_fltr_mgmt_list_entry *fm_list)
{
	enum ice_sw_lkup_type lkup_type;
	u16 vsi_list_id;
	int status = 0;

	if (fm_list->fltr_info.fltr_act != ICE_FWD_TO_VSI_LIST ||
	    fm_list->vsi_count == 0)
		return -EINVAL;

	/* A rule with the VSI being removed does not exist */
	if (!test_bit(vsi_handle, fm_list->vsi_list_info->vsi_map))
		return -ENOENT;

	lkup_type = fm_list->fltr_info.lkup_type;
	vsi_list_id = fm_list->fltr_info.fwd_id.vsi_list_id;
	status = ice_update_vsi_list_rule(hw, &vsi_handle, 1, vsi_list_id, true,
					  ice_aqc_opc_update_sw_rules,
					  lkup_type);
	if (status)
		return status;

	fm_list->vsi_count--;
	clear_bit(vsi_handle, fm_list->vsi_list_info->vsi_map);

	if (fm_list->vsi_count == 1 && lkup_type != ICE_SW_LKUP_VLAN) {
		struct ice_fltr_info tmp_fltr_info = fm_list->fltr_info;
		struct ice_vsi_list_map_info *vsi_list_info =
			fm_list->vsi_list_info;
		u16 rem_vsi_handle;

		rem_vsi_handle = find_first_bit(vsi_list_info->vsi_map,
						ICE_MAX_VSI);
		if (!ice_is_vsi_valid(hw, rem_vsi_handle))
			return -EIO;

		/* Make sure VSI list is empty before removing it below */
		status = ice_update_vsi_list_rule(hw, &rem_vsi_handle, 1,
						  vsi_list_id, true,
						  ice_aqc_opc_update_sw_rules,
						  lkup_type);
		if (status)
			return status;

		tmp_fltr_info.fltr_act = ICE_FWD_TO_VSI;
		tmp_fltr_info.fwd_id.hw_vsi_id =
			ice_get_hw_vsi_num(hw, rem_vsi_handle);
		tmp_fltr_info.vsi_handle = rem_vsi_handle;
		status = ice_update_pkt_fwd_rule(hw, &tmp_fltr_info);
		if (status) {
			ice_debug(hw, ICE_DBG_SW, "Failed to update pkt fwd rule to FWD_TO_VSI on HW VSI %d, error %d\n",
				  tmp_fltr_info.fwd_id.hw_vsi_id, status);
			return status;
		}

		fm_list->fltr_info = tmp_fltr_info;
	}

	if ((fm_list->vsi_count == 1 && lkup_type != ICE_SW_LKUP_VLAN) ||
	    (fm_list->vsi_count == 0 && lkup_type == ICE_SW_LKUP_VLAN)) {
		struct ice_vsi_list_map_info *vsi_list_info =
			fm_list->vsi_list_info;

		/* Remove the VSI list since it is no longer used */
		status = ice_remove_vsi_list_rule(hw, vsi_list_id, lkup_type);
		if (status) {
			ice_debug(hw, ICE_DBG_SW, "Failed to remove VSI list %d, error %d\n",
				  vsi_list_id, status);
			return status;
		}

		list_del(&vsi_list_info->list_entry);
		devm_kfree(ice_hw_to_dev(hw), vsi_list_info);
		fm_list->vsi_list_info = NULL;
	}

	return status;
}

/**
 * ice_remove_rule_internal - Remove a filter rule of a given type
 * @hw: pointer to the hardware structure
 * @recp_list: recipe list for which the rule needs to removed
 * @f_entry: rule entry containing filter information
 */
static int
ice_remove_rule_internal(struct ice_hw *hw, struct ice_sw_recipe *recp_list,
			 struct ice_fltr_list_entry *f_entry)
{
	struct ice_fltr_mgmt_list_entry *list_elem;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	bool remove_rule = false;
	int status = 0;
	u16 vsi_handle;

	if (!ice_is_vsi_valid(hw, f_entry->fltr_info.vsi_handle))
		return -EINVAL;
	f_entry->fltr_info.fwd_id.hw_vsi_id =
		ice_get_hw_vsi_num(hw, f_entry->fltr_info.vsi_handle);

	rule_lock = &recp_list->filt_rule_lock;
	mutex_lock(rule_lock);
	list_elem = ice_find_rule_entry(&recp_list->filt_rules,
					&f_entry->fltr_info);
	if (!list_elem) {
		status = -ENOENT;
		goto exit;
	}

	if (list_elem->fltr_info.fltr_act != ICE_FWD_TO_VSI_LIST) {
		remove_rule = true;
	} else if (!list_elem->vsi_list_info) {
		status = -ENOENT;
		goto exit;
	} else if (list_elem->vsi_list_info->ref_cnt > 1) {
		/* a ref_cnt > 1 indicates that the vsi_list is being
		 * shared by multiple rules. Decrement the ref_cnt and
		 * remove this rule, but do not modify the list, as it
		 * is in-use by other rules.
		 */
		list_elem->vsi_list_info->ref_cnt--;
		remove_rule = true;
	} else {
		/* a ref_cnt of 1 indicates the vsi_list is only used
		 * by one rule. However, the original removal request is only
		 * for a single VSI. Update the vsi_list first, and only
		 * remove the rule if there are no further VSIs in this list.
		 */
		vsi_handle = f_entry->fltr_info.vsi_handle;
		status = ice_rem_update_vsi_list(hw, vsi_handle, list_elem);
		if (status)
			goto exit;
		/* if VSI count goes to zero after updating the VSI list */
		if (list_elem->vsi_count == 0)
			remove_rule = true;
	}

	if (remove_rule) {
		/* Remove the lookup rule */
		struct ice_sw_rule_lkup_rx_tx *s_rule;

		s_rule = devm_kzalloc(ice_hw_to_dev(hw),
				      struct_size(s_rule, hdr_data, 0),
				      GFP_KERNEL);
		if (!s_rule) {
			status = -ENOMEM;
			goto exit;
		}

		ice_fill_sw_rule(hw, &list_elem->fltr_info, s_rule,
				 ice_aqc_opc_remove_sw_rules);

		status = ice_aq_sw_rules(hw, s_rule,
					 struct_size(s_rule, hdr_data, 0),
					 1, ice_aqc_opc_remove_sw_rules, NULL);

		/* Remove a book keeping from the list */
		devm_kfree(ice_hw_to_dev(hw), s_rule);

		if (status)
			goto exit;

		list_del(&list_elem->list_entry);
		devm_kfree(ice_hw_to_dev(hw), list_elem);
	}
exit:
	mutex_unlock(rule_lock);
	return status;
}

/**
 * ice_aq_get_res_alloc - get allocated resources
 * @hw: pointer to the HW struct
 * @num_entries: pointer to u16 to store the number of resource entries returned
 * @buf: pointer to buffer
 * @buf_size: size of buf
 * @cd: pointer to command details structure or NULL
 *
 * The caller-supplied buffer must be large enough to store the resource
 * information for all resource types. Each resource type is an
 * ice_aqc_get_res_resp_elem structure.
 */
int
ice_aq_get_res_alloc(struct ice_hw *hw, u16 *num_entries,
		     struct ice_aqc_get_res_resp_elem *buf, u16 buf_size,
		     struct ice_sq_cd *cd)
{
	struct ice_aqc_get_res_alloc *resp;
	struct ice_aq_desc desc;
	int status;

	if (!buf)
		return -EINVAL;

	if (buf_size < ICE_AQ_GET_RES_ALLOC_BUF_LEN)
		return -EINVAL;

	resp = &desc.params.get_res;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_res_alloc);
	status = ice_aq_send_cmd(hw, &desc, buf, buf_size, cd);

	if (!status && num_entries)
		*num_entries = le16_to_cpu(resp->resp_elem_num);

	return status;
}

/**
 * ice_aq_get_res_descs - get allocated resource descriptors
 * @hw: pointer to the hardware structure
 * @num_entries: number of resource entries in buffer
 * @buf: structure to hold response data buffer
 * @buf_size: size of buffer
 * @res_type: resource type
 * @res_shared: is resource shared
 * @desc_id: input - first desc ID to start; output - next desc ID
 * @cd: pointer to command details structure or NULL
 */
int
ice_aq_get_res_descs(struct ice_hw *hw, u16 num_entries,
		     struct ice_aqc_res_elem *buf, u16 buf_size, u16 res_type,
		     bool res_shared, u16 *desc_id, struct ice_sq_cd *cd)
{
	struct ice_aqc_get_allocd_res_desc *cmd;
	struct ice_aq_desc desc;
	int status;

	cmd = &desc.params.get_res_desc;

	if (!buf)
		return -EINVAL;

	if (buf_size != (num_entries * sizeof(*buf)))
		return -EINVAL;

	ice_fill_dflt_direct_cmd_desc(&desc, ice_aqc_opc_get_allocd_res_desc);

	cmd->ops.cmd.res = cpu_to_le16(((res_type << ICE_AQC_RES_TYPE_S) &
					 ICE_AQC_RES_TYPE_M) | (res_shared ?
					ICE_AQC_RES_TYPE_FLAG_SHARED : 0));
	cmd->ops.cmd.first_desc = cpu_to_le16(*desc_id);

	status = ice_aq_send_cmd(hw, &desc, buf, buf_size, cd);
	if (!status)
		*desc_id = le16_to_cpu(cmd->ops.resp.next_desc);

	return status;
}

/**
 * ice_mac_fltr_exist - does this MAC filter exist for given VSI
 * @hw: pointer to the hardware structure
 * @mac: MAC address to be checked (for MAC filter)
 * @vsi_handle: check MAC filter for this VSI
 */
bool ice_mac_fltr_exist(struct ice_hw *hw, u8 *mac, u16 vsi_handle)
{
	struct ice_fltr_mgmt_list_entry *entry;
	struct list_head *rule_head;
	struct ice_switch_info *sw;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	u16 hw_vsi_id;

	if (!ice_is_vsi_valid(hw, vsi_handle))
		return false;

	hw_vsi_id = ice_get_hw_vsi_num(hw, vsi_handle);
	sw = hw->switch_info;
	rule_head = &sw->recp_list[ICE_SW_LKUP_MAC].filt_rules;
	if (!rule_head)
		return false;

	rule_lock = &sw->recp_list[ICE_SW_LKUP_MAC].filt_rule_lock;
	mutex_lock(rule_lock);
	list_for_each_entry(entry, rule_head, list_entry) {
		struct ice_fltr_info *f_info = &entry->fltr_info;
		u8 *mac_addr = &f_info->l_data.mac.mac_addr[0];

		if (is_zero_ether_addr(mac_addr))
			continue;

		if (f_info->flag != ICE_FLTR_TX ||
		    f_info->src_id != ICE_SRC_ID_VSI ||
		    f_info->lkup_type != ICE_SW_LKUP_MAC ||
		    f_info->fltr_act != ICE_FWD_TO_VSI ||
		    hw_vsi_id != f_info->fwd_id.hw_vsi_id)
			continue;

		if (ether_addr_equal(mac, mac_addr)) {
			mutex_unlock(rule_lock);
			return true;
		}
	}
	mutex_unlock(rule_lock);
	return false;
}

/**
 * ice_vlan_fltr_exist - does this VLAN filter exist for given VSI
 * @hw: pointer to the hardware structure
 * @vlan_id: VLAN ID
 * @vsi_handle: check MAC filter for this VSI
 */
bool ice_vlan_fltr_exist(struct ice_hw *hw, u16 vlan_id, u16 vsi_handle)
{
	struct ice_fltr_mgmt_list_entry *entry;
	struct list_head *rule_head;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	struct ice_switch_info *sw;
	u16 hw_vsi_id;

	if (vlan_id > ICE_MAX_VLAN_ID)
		return false;

	if (!ice_is_vsi_valid(hw, vsi_handle))
		return false;

	hw_vsi_id = ice_get_hw_vsi_num(hw, vsi_handle);
	sw = hw->switch_info;
	rule_head = &sw->recp_list[ICE_SW_LKUP_VLAN].filt_rules;
	if (!rule_head)
		return false;

	rule_lock = &sw->recp_list[ICE_SW_LKUP_VLAN].filt_rule_lock;
	mutex_lock(rule_lock);
	list_for_each_entry(entry, rule_head, list_entry) {
		struct ice_fltr_info *f_info = &entry->fltr_info;
		u16 entry_vlan_id = f_info->l_data.vlan.vlan_id;
		struct ice_vsi_list_map_info *map_info;

		if (entry_vlan_id > ICE_MAX_VLAN_ID)
			continue;

		if (f_info->flag != ICE_FLTR_TX ||
		    f_info->src_id != ICE_SRC_ID_VSI ||
		    f_info->lkup_type != ICE_SW_LKUP_VLAN)
			continue;

		/* Only allowed filter action are FWD_TO_VSI/_VSI_LIST */
		if (f_info->fltr_act != ICE_FWD_TO_VSI &&
		    f_info->fltr_act != ICE_FWD_TO_VSI_LIST)
			continue;

		if (f_info->fltr_act == ICE_FWD_TO_VSI) {
			if (hw_vsi_id != f_info->fwd_id.hw_vsi_id)
				continue;
		} else if (f_info->fltr_act == ICE_FWD_TO_VSI_LIST) {
			/* If filter_action is FWD_TO_VSI_LIST, make sure
			 * that VSI being checked is part of VSI list
			 */
			if (entry->vsi_count == 1 &&
			    entry->vsi_list_info) {
				map_info = entry->vsi_list_info;
				if (!test_bit(vsi_handle, map_info->vsi_map))
					continue;
			}
		}

		if (vlan_id == entry_vlan_id) {
			mutex_unlock(rule_lock);
			return true;
		}
	}
	mutex_unlock(rule_lock);

	return false;
}

/**
 * ice_add_mac_rule - Add a MAC address based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 * @sw: pointer to switch info struct for which function add rule
 * @lport: logic port number on which function add rule
 *
 * IMPORTANT: When the umac_shared flag is set to false and m_list has
 * multiple unicast addresses, the function assumes that all the
 * addresses are unique in a given add_mac call. It doesn't
 * check for duplicates in this case, removing duplicates from a given
 * list should be taken care of in the caller of this function.
 */
static int
ice_add_mac_rule(struct ice_hw *hw, struct list_head *m_list,
		 struct ice_switch_info *sw, u8 lport)
{
	struct ice_sw_recipe *recp_list = &sw->recp_list[ICE_SW_LKUP_MAC];
	struct ice_sw_rule_lkup_rx_tx *s_rule, *r_iter;
	struct ice_fltr_list_entry *m_list_itr;
	struct list_head *rule_head;
	u16 total_elem_left, s_rule_size;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	u16 num_unicast = 0;
	int status = 0;
	u8 elem_sent;

	s_rule = NULL;
	rule_lock = &recp_list->filt_rule_lock;
	rule_head = &recp_list->filt_rules;

	list_for_each_entry(m_list_itr, m_list, list_entry) {
		u8 *add = &m_list_itr->fltr_info.l_data.mac.mac_addr[0];
		u16 vsi_handle;
		u16 hw_vsi_id;

		m_list_itr->fltr_info.flag = ICE_FLTR_TX;
		vsi_handle = m_list_itr->fltr_info.vsi_handle;
		if (!ice_is_vsi_valid(hw, vsi_handle))
			return -EINVAL;
		hw_vsi_id = ice_get_hw_vsi_num(hw, vsi_handle);
		if (m_list_itr->fltr_info.fltr_act == ICE_FWD_TO_VSI)
			m_list_itr->fltr_info.fwd_id.hw_vsi_id = hw_vsi_id;
		/* update the src in case it is VSI num */
		if (m_list_itr->fltr_info.src_id != ICE_SRC_ID_VSI)
			return -EINVAL;
		m_list_itr->fltr_info.src = hw_vsi_id;
		if (m_list_itr->fltr_info.lkup_type != ICE_SW_LKUP_MAC ||
		    is_zero_ether_addr(add))
			return -EINVAL;
		if (is_unicast_ether_addr(add) && !hw->umac_shared) {
			/* Don't overwrite the unicast address */
			mutex_lock(rule_lock);
			if (ice_find_rule_entry(rule_head,
						&m_list_itr->fltr_info)) {
				mutex_unlock(rule_lock);
				continue;
			}
			mutex_unlock(rule_lock);
			num_unicast++;
		} else if (is_multicast_ether_addr(add) ||
			   (is_unicast_ether_addr(add) && hw->umac_shared)) {
			m_list_itr->status =
				ice_add_rule_internal(hw, recp_list, lport,
						      m_list_itr);
			if (m_list_itr->status)
				return m_list_itr->status;
		}
	}

	mutex_lock(rule_lock);
	/* Exit if no suitable entries were found for adding bulk switch rule */
	if (!num_unicast) {
		status = 0;
		goto ice_add_mac_exit;
	}

	/* Allocate switch rule buffer for the bulk update for unicast */
	s_rule_size = struct_size(s_rule, hdr_data, DUMMY_ETH_HDR_LEN);
	s_rule = devm_kcalloc(ice_hw_to_dev(hw), num_unicast, s_rule_size,
			      GFP_KERNEL);
	if (!s_rule) {
		status = -ENOMEM;
		goto ice_add_mac_exit;
	}

	r_iter = s_rule;
	list_for_each_entry(m_list_itr, m_list, list_entry) {
		struct ice_fltr_info *f_info = &m_list_itr->fltr_info;
		u8 *mac_addr = &f_info->l_data.mac.mac_addr[0];

		if (is_unicast_ether_addr(mac_addr)) {
			ice_fill_sw_rule(hw, &m_list_itr->fltr_info, r_iter,
					 ice_aqc_opc_add_sw_rules);
			r_iter = (struct ice_sw_rule_lkup_rx_tx *)
				((u8 *)r_iter + s_rule_size);
		}
	}

	/* Call AQ bulk switch rule update for all unicast addresses */
	r_iter = s_rule;
	/* Call AQ switch rule in AQ_MAX chunk */
	for (total_elem_left = num_unicast; total_elem_left > 0;
	     total_elem_left -= elem_sent) {
		struct ice_sw_rule_lkup_rx_tx *entry = r_iter;

		elem_sent = min_t(u8, total_elem_left,
				  (ICE_AQ_MAX_BUF_LEN / s_rule_size));
		status = ice_aq_sw_rules(hw, entry, elem_sent * s_rule_size,
					 elem_sent, ice_aqc_opc_add_sw_rules,
					 NULL);
		if (status)
			goto ice_add_mac_exit;
		r_iter = (struct ice_sw_rule_lkup_rx_tx *)
			((u8 *)r_iter + (elem_sent * s_rule_size));
	}

	/* Fill up rule ID based on the value returned from FW */
	r_iter = s_rule;
	list_for_each_entry(m_list_itr, m_list, list_entry) {
		struct ice_fltr_info *f_info = &m_list_itr->fltr_info;
		u8 *mac_addr = &f_info->l_data.mac.mac_addr[0];
		struct ice_fltr_mgmt_list_entry *fm_entry;

		if (is_unicast_ether_addr(mac_addr)) {
			f_info->fltr_rule_id =
				le16_to_cpu(r_iter->index);
			f_info->fltr_act = ICE_FWD_TO_VSI;
			/* Create an entry to track this MAC address */
			fm_entry = devm_kzalloc(ice_hw_to_dev(hw),
						sizeof(*fm_entry), GFP_KERNEL);
			if (!fm_entry) {
				status = -ENOMEM;
				goto ice_add_mac_exit;
			}
			fm_entry->fltr_info = *f_info;
			fm_entry->vsi_count = 1;
			/* The book keeping entries will get removed when
			 * base driver calls remove filter AQ command
			 */

			list_add(&fm_entry->list_entry, rule_head);
			r_iter = (struct ice_sw_rule_lkup_rx_tx *)
				((u8 *)r_iter + s_rule_size);
		}
	}

ice_add_mac_exit:
	mutex_unlock(rule_lock);
	if (s_rule)
		devm_kfree(ice_hw_to_dev(hw), s_rule);
	return status;
}

/**
 * ice_add_mac - Add a MAC address based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 *
 * Function add MAC rule for logical port from HW struct
 */
int ice_add_mac(struct ice_hw *hw, struct list_head *m_list)
{
	if (!m_list || !hw)
		return -EINVAL;

	return ice_add_mac_rule(hw, m_list, hw->switch_info,
				hw->port_info->lport);
}

/**
 * ice_add_vlan_internal - Add one VLAN based filter rule
 * @hw: pointer to the hardware structure
 * @recp_list: recipe list for which rule has to be added
 * @f_entry: filter entry containing one VLAN information
 */
static int
ice_add_vlan_internal(struct ice_hw *hw, struct ice_sw_recipe *recp_list,
		      struct ice_fltr_list_entry *f_entry)
{
	struct ice_fltr_mgmt_list_entry *v_list_itr;
	struct ice_fltr_info *new_fltr, *cur_fltr;
	enum ice_sw_lkup_type lkup_type;
	u16 vsi_list_id = 0, vsi_handle;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	int status = 0;

	if (!ice_is_vsi_valid(hw, f_entry->fltr_info.vsi_handle))
		return -EINVAL;

	f_entry->fltr_info.fwd_id.hw_vsi_id =
		ice_get_hw_vsi_num(hw, f_entry->fltr_info.vsi_handle);
	new_fltr = &f_entry->fltr_info;

	/* VLAN ID should only be 12 bits */
	if (new_fltr->l_data.vlan.vlan_id > ICE_MAX_VLAN_ID)
		return -EINVAL;

	if (new_fltr->src_id != ICE_SRC_ID_VSI)
		return -EINVAL;

	new_fltr->src = new_fltr->fwd_id.hw_vsi_id;
	lkup_type = new_fltr->lkup_type;
	vsi_handle = new_fltr->vsi_handle;
	rule_lock = &recp_list->filt_rule_lock;
	mutex_lock(rule_lock);
	v_list_itr = ice_find_rule_entry(&recp_list->filt_rules, new_fltr);
	if (!v_list_itr) {
		struct ice_vsi_list_map_info *map_info = NULL;

		if (new_fltr->fltr_act == ICE_FWD_TO_VSI) {
			/* All VLAN pruning rules use a VSI list. Check if
			 * there is already a VSI list containing VSI that we
			 * want to add. If found, use the same vsi_list_id for
			 * this new VLAN rule or else create a new list.
			 */
			map_info = ice_find_vsi_list_entry(recp_list,
							   vsi_handle,
							   &vsi_list_id);
			if (!map_info) {
				status = ice_create_vsi_list_rule(hw,
								  &vsi_handle,
								  1,
								  &vsi_list_id,
								  lkup_type);
				if (status)
					goto exit;
			}
			/* Convert the action to forwarding to a VSI list. */
			new_fltr->fltr_act = ICE_FWD_TO_VSI_LIST;
			new_fltr->fwd_id.vsi_list_id = vsi_list_id;
		}

		status = ice_create_pkt_fwd_rule(hw, recp_list, f_entry);
		if (!status) {
			v_list_itr = ice_find_rule_entry(&recp_list->filt_rules,
							 new_fltr);
			if (!v_list_itr) {
				status = -ENOENT;
				goto exit;
			}
			/* reuse VSI list for new rule and increment ref_cnt */
			if (map_info) {
				v_list_itr->vsi_list_info = map_info;
				map_info->ref_cnt++;
			} else {
				v_list_itr->vsi_list_info =
					ice_create_vsi_list_map(hw, &vsi_handle,
								1, vsi_list_id);
			}
		}
	} else if (v_list_itr->vsi_list_info->ref_cnt == 1) {
		/* Update existing VSI list to add new VSI ID only if it used
		 * by one VLAN rule.
		 */
		cur_fltr = &v_list_itr->fltr_info;
		status = ice_add_update_vsi_list(hw, v_list_itr, cur_fltr,
						 new_fltr);
	} else {
		/* If VLAN rule exists and VSI list being used by this rule is
		 * referenced by more than 1 VLAN rule. Then create a new VSI
		 * list appending previous VSI with new VSI and update existing
		 * VLAN rule to point to new VSI list ID
		 */
		struct ice_fltr_info tmp_fltr;
		u16 vsi_handle_arr[2];
		u16 cur_handle;

		/* Current implementation only supports reusing VSI list with
		 * one VSI count. We should never hit below condition
		 */
		if (v_list_itr->vsi_count > 1 &&
		    v_list_itr->vsi_list_info->ref_cnt > 1) {
			ice_debug(hw, ICE_DBG_SW, "Invalid configuration: Optimization to reuse VSI list with more than one VSI is not being done yet\n");
			status = -EIO;
			goto exit;
		}

		cur_handle =
			find_first_bit(v_list_itr->vsi_list_info->vsi_map,
				       ICE_MAX_VSI);

		/* A rule already exists with the new VSI being added */
		if (cur_handle == vsi_handle) {
			status = -EEXIST;
			goto exit;
		}

		vsi_handle_arr[0] = cur_handle;
		vsi_handle_arr[1] = vsi_handle;
		status = ice_create_vsi_list_rule(hw, &vsi_handle_arr[0], 2,
						  &vsi_list_id, lkup_type);
		if (status)
			goto exit;

		tmp_fltr = v_list_itr->fltr_info;
		tmp_fltr.fltr_rule_id = v_list_itr->fltr_info.fltr_rule_id;
		tmp_fltr.fwd_id.vsi_list_id = vsi_list_id;
		tmp_fltr.fltr_act = ICE_FWD_TO_VSI_LIST;
		/* Update the previous switch rule to a new VSI list which
		 * includes current VSI that is requested
		 */
		status = ice_update_pkt_fwd_rule(hw, &tmp_fltr);
		if (status)
			goto exit;

		/* before overriding VSI list map info. decrement ref_cnt of
		 * previous VSI list
		 */
		v_list_itr->vsi_list_info->ref_cnt--;

		/* now update to newly created list */
		v_list_itr->fltr_info.fwd_id.vsi_list_id = vsi_list_id;
		v_list_itr->vsi_list_info =
			ice_create_vsi_list_map(hw, &vsi_handle_arr[0], 2,
						vsi_list_id);
		v_list_itr->vsi_count++;
	}

exit:
	mutex_unlock(rule_lock);
	return status;
}

/**
 * ice_add_vlan_rule - Add VLAN based filter rule
 * @hw: pointer to the hardware structure
 * @v_list: list of VLAN entries and forwarding information
 * @sw: pointer to switch info struct for which function add rule
 */
static int
ice_add_vlan_rule(struct ice_hw *hw, struct list_head *v_list,
		  struct ice_switch_info *sw)
{
	struct ice_fltr_list_entry *v_list_itr;
	struct ice_sw_recipe *recp_list;

	recp_list = &sw->recp_list[ICE_SW_LKUP_VLAN];
	list_for_each_entry(v_list_itr, v_list, list_entry) {
		if (v_list_itr->fltr_info.lkup_type != ICE_SW_LKUP_VLAN)
			return -EINVAL;
		v_list_itr->fltr_info.flag = ICE_FLTR_TX;
		v_list_itr->status = ice_add_vlan_internal(hw, recp_list,
							   v_list_itr);
		if (v_list_itr->status)
			return v_list_itr->status;
	}
	return 0;
}

/**
 * ice_add_vlan - Add a VLAN based filter rule
 * @hw: pointer to the hardware structure
 * @v_list: list of VLAN and forwarding information
 *
 * Function add VLAN rule for logical port from HW struct
 */
int ice_add_vlan(struct ice_hw *hw, struct list_head *v_list)
{
	if (!v_list || !hw)
		return -EINVAL;

	return ice_add_vlan_rule(hw, v_list, hw->switch_info);
}

/**
 * ice_add_mac_vlan_rule - Add MAC and VLAN pair based filter rule
 * @hw: pointer to the hardware structure
 * @mv_list: list of MAC and VLAN filters
 * @sw: pointer to switch info struct for which function add rule
 * @lport: logic port number on which function add rule
 *
 * If the VSI on which the MAC-VLAN pair has to be added has Rx and Tx VLAN
 * pruning bits enabled, then it is the responsibility of the caller to make
 * sure to add a VLAN only filter on the same VSI. Packets belonging to that
 * VLAN won't be received on that VSI otherwise.
 */
static int
ice_add_mac_vlan_rule(struct ice_hw *hw, struct list_head *mv_list,
		      struct ice_switch_info *sw, u8 lport)
{
	struct ice_fltr_list_entry *mv_list_itr;
	struct ice_sw_recipe *recp_list;

	if (!mv_list || !hw)
		return -EINVAL;

	recp_list = &sw->recp_list[ICE_SW_LKUP_MAC_VLAN];
	list_for_each_entry(mv_list_itr, mv_list, list_entry) {
		enum ice_sw_lkup_type l_type =
			mv_list_itr->fltr_info.lkup_type;

		if (l_type != ICE_SW_LKUP_MAC_VLAN)
			return -EINVAL;
		mv_list_itr->fltr_info.flag = ICE_FLTR_TX;
		mv_list_itr->status =
			ice_add_rule_internal(hw, recp_list, lport,
					      mv_list_itr);
		if (mv_list_itr->status)
			return mv_list_itr->status;
	}
	return 0;
}

/**
 * ice_add_mac_vlan - Add a MAC VLAN address based filter rule
 * @hw: pointer to the hardware structure
 * @mv_list: list of MAC VLAN addresses and forwarding information
 *
 * Function add MAC VLAN rule for logical port from HW struct
 */
int
ice_add_mac_vlan(struct ice_hw *hw, struct list_head *mv_list)
{
	if (!mv_list || !hw)
		return -EINVAL;

	return ice_add_mac_vlan_rule(hw, mv_list, hw->switch_info,
				     hw->port_info->lport);
}

/**
 * ice_add_eth_mac_rule - Add ethertype and MAC based filter rule
 * @hw: pointer to the hardware structure
 * @em_list: list of ether type MAC filter, MAC is optional
 * @sw: pointer to switch info struct for which function add rule
 * @lport: logic port number on which function add rule
 *
 * This function requires the caller to populate the entries in
 * the filter list with the necessary fields (including flags to
 * indicate Tx or Rx rules).
 */
static int
ice_add_eth_mac_rule(struct ice_hw *hw, struct list_head *em_list,
		     struct ice_switch_info *sw, u8 lport)
{
	struct ice_fltr_list_entry *em_list_itr;

	list_for_each_entry(em_list_itr, em_list, list_entry) {
		struct ice_sw_recipe *recp_list;
		enum ice_sw_lkup_type l_type;

		l_type = em_list_itr->fltr_info.lkup_type;
		recp_list = &sw->recp_list[l_type];

		if (l_type != ICE_SW_LKUP_ETHERTYPE_MAC &&
		    l_type != ICE_SW_LKUP_ETHERTYPE)
			return -EINVAL;

		em_list_itr->status = ice_add_rule_internal(hw, recp_list,
							    lport,
							    em_list_itr);
		if (em_list_itr->status)
			return em_list_itr->status;
	}
	return 0;
}

/**
 * ice_add_eth_mac - Add a ethertype based filter rule
 * @hw: pointer to the hardware structure
 * @em_list: list of ethertype and forwarding information
 *
 * Function add ethertype rule for logical port from HW struct
 */
int
ice_add_eth_mac(struct ice_hw *hw, struct list_head *em_list)
{
	if (!em_list || !hw)
		return -EINVAL;

	return ice_add_eth_mac_rule(hw, em_list, hw->switch_info,
				    hw->port_info->lport);
}

/**
 * ice_remove_eth_mac_rule - Remove an ethertype (or MAC) based filter rule
 * @hw: pointer to the hardware structure
 * @em_list: list of ethertype or ethertype MAC entries
 * @sw: pointer to switch info struct for which function add rule
 */
static int
ice_remove_eth_mac_rule(struct ice_hw *hw, struct list_head *em_list,
			struct ice_switch_info *sw)
{
	struct ice_fltr_list_entry *em_list_itr, *tmp;

	list_for_each_entry_safe(em_list_itr, tmp, em_list, list_entry) {
		struct ice_sw_recipe *recp_list;
		enum ice_sw_lkup_type l_type;

		l_type = em_list_itr->fltr_info.lkup_type;

		if (l_type != ICE_SW_LKUP_ETHERTYPE_MAC &&
		    l_type != ICE_SW_LKUP_ETHERTYPE)
			return -EINVAL;

		recp_list = &sw->recp_list[l_type];
		em_list_itr->status = ice_remove_rule_internal(hw, recp_list,
							       em_list_itr);
		if (em_list_itr->status)
			return em_list_itr->status;
	}
	return 0;
}

/**
 * ice_remove_eth_mac - remove a ethertype based filter rule
 * @hw: pointer to the hardware structure
 * @em_list: list of ethertype and forwarding information
 *
 */
int
ice_remove_eth_mac(struct ice_hw *hw, struct list_head *em_list)
{
	if (!em_list || !hw)
		return -EINVAL;

	return ice_remove_eth_mac_rule(hw, em_list, hw->switch_info);
}

/**
 * ice_get_lg_act_aqc_res_type - get resource type for a large action
 * @res_type: resource type to be filled in case of function success
 * @num_acts: number of actions to hold with a large action entry
 *
 * Get resource type for a large action depending on the number
 * of single actions that it contains.
 */
static int
ice_get_lg_act_aqc_res_type(u16 *res_type, int num_acts)
{
	if (!res_type)
		return -EINVAL;

	/* If num_acts is 1, use ICE_AQC_RES_TYPE_WIDE_TABLE_1.
	 * If num_acts is 2, use ICE_AQC_RES_TYPE_WIDE_TABLE_3.
	 * If num_acts is greater than 2, then use
	 * ICE_AQC_RES_TYPE_WIDE_TABLE_4.
	 * The num_acts cannot be equal to 0 or greater than 4.
	 */
	switch (num_acts) {
	case 1:
		*res_type = ICE_AQC_RES_TYPE_WIDE_TABLE_1;
		break;
	case 2:
		*res_type = ICE_AQC_RES_TYPE_WIDE_TABLE_2;
		break;
	case 3:
	case 4:
		*res_type = ICE_AQC_RES_TYPE_WIDE_TABLE_4;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/**
 * ice_alloc_res_lg_act - add large action resource
 * @hw: pointer to the hardware structure
 * @l_id: large action ID to fill it in
 * @num_acts: number of actions to hold with a large action entry
 */
static int
ice_alloc_res_lg_act(struct ice_hw *hw, u16 *l_id, u16 num_acts)
{
	struct ice_aqc_alloc_free_res_elem *sw_buf;
	u16 buf_len, res_type;
	int status;

	if (!l_id)
		return -EINVAL;

	status = ice_get_lg_act_aqc_res_type(&res_type, num_acts);
	if (status)
		return status;

	/* Allocate resource for large action */
	buf_len = struct_size(sw_buf, elem, 1);
	sw_buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len, GFP_KERNEL);
	if (!sw_buf)
		return -ENOMEM;

	sw_buf->res_type = cpu_to_le16(res_type);
	sw_buf->num_elems = cpu_to_le16(1);

	status = ice_aq_alloc_free_res(hw, 1, sw_buf, buf_len,
				       ice_aqc_opc_alloc_res, NULL);
	if (!status)
		*l_id = le16_to_cpu(sw_buf->elem[0].e.sw_resp);

	devm_kfree(ice_hw_to_dev(hw), sw_buf);

	return status;
}

/**
 * ice_rem_sw_rule_info
 * @hw: pointer to the hardware structure
 * @rule_head: pointer to the switch list structure that we want to delete
 */
static void
ice_rem_sw_rule_info(struct ice_hw *hw, struct list_head *rule_head)
{
	if (!list_empty(rule_head)) {
		struct ice_fltr_mgmt_list_entry *entry;
		struct ice_fltr_mgmt_list_entry *tmp;

		list_for_each_entry_safe(entry, tmp, rule_head, list_entry) {
			list_del(&entry->list_entry);
			devm_kfree(ice_hw_to_dev(hw), entry);
		}
	}
}

/**
 * ice_rem_adv_rule_info
 * @hw: pointer to the hardware structure
 * @rule_head: pointer to the switch list structure that we want to delete
 */
static void
ice_rem_adv_rule_info(struct ice_hw *hw, struct list_head *rule_head)
{
	struct ice_adv_fltr_mgmt_list_entry *tmp_entry;
	struct ice_adv_fltr_mgmt_list_entry *lst_itr;

	if (list_empty(rule_head))
		return;

	list_for_each_entry_safe(lst_itr, tmp_entry, rule_head, list_entry) {
		list_del(&lst_itr->list_entry);
		devm_kfree(ice_hw_to_dev(hw), lst_itr->lkups);
		devm_kfree(ice_hw_to_dev(hw), lst_itr);
	}
}

/**
 * ice_rem_all_sw_rules_info
 * @hw: pointer to the hardware structure
 */
void ice_rem_all_sw_rules_info(struct ice_hw *hw)
{
	struct ice_switch_info *sw = hw->switch_info;
	u8 i;

	for (i = 0; i < ICE_MAX_NUM_RECIPES; i++) {
		struct list_head *rule_head;

		rule_head = &sw->recp_list[i].filt_rules;
		if (!sw->recp_list[i].adv_rule)
			ice_rem_sw_rule_info(hw, rule_head);
		else
			ice_rem_adv_rule_info(hw, rule_head);
		if (sw->recp_list[i].adv_rule &&
		    list_empty(&sw->recp_list[i].filt_rules))
			sw->recp_list[i].adv_rule = false;
	}
}

/**
 * ice_cfg_dflt_vsi - change state of VSI to set/clear default
 * @pi: pointer to the port_info structure
 * @vsi_handle: VSI handle to set as default
 * @set: true to add the above mentioned switch rule, false to remove it
 * @direction: ICE_FLTR_RX or ICE_FLTR_TX
 *
 * add filter rule to set/unset given VSI as default VSI for the switch
 * (represented by swid)
 */
int
ice_cfg_dflt_vsi(struct ice_port_info *pi, u16 vsi_handle, bool set,
		 u8 direction)
{
	struct ice_fltr_list_entry f_list_entry;
	struct ice_sw_recipe *recp_list = NULL;
	struct ice_fltr_info f_info;
	struct ice_hw *hw = pi->hw;
	u8 lport = pi->lport;
	u16 hw_vsi_id;
	int status;

	recp_list = &pi->hw->switch_info->recp_list[ICE_SW_LKUP_DFLT];

	if (!ice_is_vsi_valid(hw, vsi_handle))
		return -EINVAL;

	hw_vsi_id = ice_get_hw_vsi_num(hw, vsi_handle);

	memset(&f_info, 0, sizeof(f_info));

	f_info.lkup_type = ICE_SW_LKUP_DFLT;
	f_info.flag = direction;
	f_info.fltr_act = ICE_FWD_TO_VSI;
	f_info.fwd_id.hw_vsi_id = hw_vsi_id;
	f_info.vsi_handle = vsi_handle;

	if (f_info.flag & ICE_FLTR_RX) {
		f_info.src = pi->lport;
		f_info.src_id = ICE_SRC_ID_LPORT;
	} else if (f_info.flag & ICE_FLTR_TX) {
		f_info.src_id = ICE_SRC_ID_VSI;
		f_info.src = hw_vsi_id;
	}
	f_list_entry.fltr_info = f_info;

	if (set)
		status = ice_add_rule_internal(hw, recp_list, lport,
					       &f_list_entry);
	else
		status = ice_remove_rule_internal(hw, recp_list,
						  &f_list_entry);

	return status;
}

/**
 * ice_check_if_dflt_vsi - check if VSI is default VSI
 * @pi: pointer to the port_info structure
 * @vsi_handle: vsi handle to check for in filter list
 * @rule_exists: indicates if there are any VSI's in the rule list
 *
 * checks if the VSI is in a default VSI list, and also indicates
 * if the default VSI list is empty
 */
bool ice_check_if_dflt_vsi(struct ice_port_info *pi, u16 vsi_handle,
			   bool *rule_exists)
{
	struct ice_fltr_mgmt_list_entry *fm_entry;
	struct list_head *rule_head;
	struct ice_sw_recipe *recp_list;
	struct mutex *rule_lock;
	bool ret = false;
	recp_list = &pi->hw->switch_info->recp_list[ICE_SW_LKUP_DFLT];
	rule_lock = &recp_list->filt_rule_lock;
	rule_head = &recp_list->filt_rules;

	mutex_lock(rule_lock);

	if (rule_exists && !list_empty(rule_head))
		*rule_exists = true;

	list_for_each_entry(fm_entry, rule_head, list_entry) {
		if (ice_vsi_uses_fltr(fm_entry, vsi_handle)) {
			ret = true;
			break;
		}
	}

	mutex_unlock(rule_lock);
	return ret;
}

/**
 * ice_find_ucast_rule_entry - Search for a unicast MAC filter rule entry
 * @list_head: head of rule list
 * @f_info: rule information
 *
 * Helper function to search for a unicast rule entry - this is to be used
 * to remove unicast MAC filter that is not shared with other VSIs on the
 * PF switch.
 *
 * Returns pointer to entry storing the rule if found
 */
static struct ice_fltr_mgmt_list_entry *
ice_find_ucast_rule_entry(struct list_head *list_head,
			  struct ice_fltr_info *f_info)
{
	struct ice_fltr_mgmt_list_entry *list_itr;

	list_for_each_entry(list_itr, list_head, list_entry) {
		if (!memcmp(&f_info->l_data, &list_itr->fltr_info.l_data,
			    sizeof(f_info->l_data)) &&
		    f_info->fwd_id.hw_vsi_id ==
		    list_itr->fltr_info.fwd_id.hw_vsi_id &&
		    f_info->flag == list_itr->fltr_info.flag)
			return list_itr;
	}
	return NULL;
}

/**
 * ice_remove_mac_rule - remove a MAC based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 * @recp_list: list from which function remove MAC address
 *
 * This function removes either a MAC filter rule or a specific VSI from a
 * VSI list for a multicast MAC address.
 *
 * Returns -ENOENT if a given entry was not added by
 * ice_add_mac. Caller should be aware that this call will only work if all
 * the entries passed into m_list were added previously. It will not attempt to
 * do a partial remove of entries that were found.
 */
static int
ice_remove_mac_rule(struct ice_hw *hw, struct list_head *m_list,
		    struct ice_sw_recipe *recp_list)
{
	struct ice_fltr_list_entry *list_itr, *tmp;
	struct mutex *rule_lock; /* Lock to protect filter rule list */

	if (!m_list)
		return -EINVAL;

	rule_lock = &recp_list->filt_rule_lock;
	list_for_each_entry_safe(list_itr, tmp, m_list, list_entry) {
		enum ice_sw_lkup_type l_type = list_itr->fltr_info.lkup_type;
		u8 *add = &list_itr->fltr_info.l_data.mac.mac_addr[0];
		u16 vsi_handle;

		if (l_type != ICE_SW_LKUP_MAC)
			return -EINVAL;

		vsi_handle = list_itr->fltr_info.vsi_handle;
		if (!ice_is_vsi_valid(hw, vsi_handle))
			return -EINVAL;

		list_itr->fltr_info.fwd_id.hw_vsi_id =
					ice_get_hw_vsi_num(hw, vsi_handle);
		if (is_unicast_ether_addr(add) && !hw->umac_shared) {
			/* Don't remove the unicast address that belongs to
			 * another VSI on the switch, since it is not being
			 * shared...
			 */
			mutex_lock(rule_lock);
			if (!ice_find_ucast_rule_entry(&recp_list->filt_rules,
						       &list_itr->fltr_info)) {
				mutex_unlock(rule_lock);
				return -ENOENT;
			}
			mutex_unlock(rule_lock);
		}
		list_itr->status = ice_remove_rule_internal(hw, recp_list,
							    list_itr);
		if (list_itr->status)
			return list_itr->status;
	}
	return 0;
}

/**
 * ice_remove_mac - remove a MAC address based filter rule
 * @hw: pointer to the hardware structure
 * @m_list: list of MAC addresses and forwarding information
 *
 */
int ice_remove_mac(struct ice_hw *hw, struct list_head *m_list)
{
	struct ice_sw_recipe *recp_list;

	recp_list = &hw->switch_info->recp_list[ICE_SW_LKUP_MAC];
	return ice_remove_mac_rule(hw, m_list, recp_list);
}

/**
 * ice_remove_vlan_rule - Remove VLAN based filter rule
 * @hw: pointer to the hardware structure
 * @v_list: list of VLAN entries and forwarding information
 * @recp_list: list from which function remove VLAN
 */
static int
ice_remove_vlan_rule(struct ice_hw *hw, struct list_head *v_list,
		     struct ice_sw_recipe *recp_list)
{
	struct ice_fltr_list_entry *v_list_itr, *tmp;

	list_for_each_entry_safe(v_list_itr, tmp, v_list, list_entry) {
		enum ice_sw_lkup_type l_type = v_list_itr->fltr_info.lkup_type;

		if (l_type != ICE_SW_LKUP_VLAN)
			return -EINVAL;
		v_list_itr->status = ice_remove_rule_internal(hw, recp_list,
							      v_list_itr);
		if (v_list_itr->status)
			return v_list_itr->status;
	}
	return 0;
}

/**
 * ice_remove_vlan - remove a VLAN address based filter rule
 * @hw: pointer to the hardware structure
 * @v_list: list of VLAN and forwarding information
 *
 */
int
ice_remove_vlan(struct ice_hw *hw, struct list_head *v_list)
{
	struct ice_sw_recipe *recp_list;

	if (!v_list || !hw)
		return -EINVAL;

	recp_list = &hw->switch_info->recp_list[ICE_SW_LKUP_VLAN];
	return ice_remove_vlan_rule(hw, v_list, recp_list);
}

/**
 * ice_remove_mac_vlan_rule - Remove MAC VLAN based filter rule
 * @hw: pointer to the hardware structure
 * @v_list: list of MAC VLAN entries and forwarding information
 * @recp_list: list from which function remove MAC VLAN
 */
static int
ice_remove_mac_vlan_rule(struct ice_hw *hw, struct list_head *v_list,
			 struct ice_sw_recipe *recp_list)
{
	struct ice_fltr_list_entry *v_list_itr, *tmp;

	recp_list = &hw->switch_info->recp_list[ICE_SW_LKUP_MAC_VLAN];
	list_for_each_entry_safe(v_list_itr, tmp, v_list, list_entry) {
		enum ice_sw_lkup_type l_type = v_list_itr->fltr_info.lkup_type;

		if (l_type != ICE_SW_LKUP_MAC_VLAN)
			return -EINVAL;
		v_list_itr->status =
			ice_remove_rule_internal(hw, recp_list,
						 v_list_itr);
		if (v_list_itr->status)
			return v_list_itr->status;
	}
	return 0;
}

/**
 * ice_remove_mac_vlan - remove a MAC VLAN address based filter rule
 * @hw: pointer to the hardware structure
 * @mv_list: list of MAC VLAN and forwarding information
 */
int
ice_remove_mac_vlan(struct ice_hw *hw, struct list_head *mv_list)
{
	struct ice_sw_recipe *recp_list;

	if (!mv_list || !hw)
		return -EINVAL;

	recp_list = &hw->switch_info->recp_list[ICE_SW_LKUP_MAC_VLAN];
	return ice_remove_mac_vlan_rule(hw, mv_list, recp_list);
}

/**
 * ice_vsi_uses_fltr - Determine if given VSI uses specified filter
 * @fm_entry: filter entry to inspect
 * @vsi_handle: VSI handle to compare with filter info
 */
static bool
ice_vsi_uses_fltr(struct ice_fltr_mgmt_list_entry *fm_entry, u16 vsi_handle)
{
	return ((fm_entry->fltr_info.fltr_act == ICE_FWD_TO_VSI &&
		 fm_entry->fltr_info.vsi_handle == vsi_handle) ||
		(fm_entry->fltr_info.fltr_act == ICE_FWD_TO_VSI_LIST &&
		 fm_entry->vsi_list_info &&
		 (test_bit(vsi_handle, fm_entry->vsi_list_info->vsi_map))));
}

/**
 * ice_add_entry_to_vsi_fltr_list - Add copy of fltr_list_entry to remove list
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to remove filters from
 * @vsi_list_head: pointer to the list to add entry to
 * @fi: pointer to fltr_info of filter entry to copy & add
 *
 * Helper function, used when creating a list of filters to remove from
 * a specific VSI. The entry added to vsi_list_head is a COPY of the
 * original filter entry, with the exception of fltr_info.fltr_act and
 * fltr_info.fwd_id fields. These are set such that later logic can
 * extract which VSI to remove the fltr from, and pass on that information.
 */
static int
ice_add_entry_to_vsi_fltr_list(struct ice_hw *hw, u16 vsi_handle,
			       struct list_head *vsi_list_head,
			       struct ice_fltr_info *fi)
{
	struct ice_fltr_list_entry *tmp;

	/* this memory is freed up in the caller function
	 * once filters for this VSI are removed
	 */
	tmp = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	tmp->fltr_info = *fi;

	/* Overwrite these fields to indicate which VSI to remove filter from,
	 * so find and remove logic can extract the information from the
	 * list entries. Note that original entries will still have proper
	 * values.
	 */
	tmp->fltr_info.fltr_act = ICE_FWD_TO_VSI;
	tmp->fltr_info.vsi_handle = vsi_handle;
	tmp->fltr_info.fwd_id.hw_vsi_id = ice_get_hw_vsi_num(hw, vsi_handle);

	list_add(&tmp->list_entry, vsi_list_head);

	return 0;
}

/**
 * ice_add_to_vsi_fltr_list - Add VSI filters to the list
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to remove filters from
 * @lkup_list_head: pointer to the list that has certain lookup type filters
 * @vsi_list_head: pointer to the list pertaining to VSI with vsi_handle
 *
 * Locates all filters in lkup_list_head that are used by the given VSI,
 * and adds COPIES of those entries to vsi_list_head (intended to be used
 * to remove the listed filters).
 * Note that this means all entries in vsi_list_head must be explicitly
 * deallocated by the caller when done with list.
 */
static int
ice_add_to_vsi_fltr_list(struct ice_hw *hw, u16 vsi_handle,
			 struct list_head *lkup_list_head,
			 struct list_head *vsi_list_head)
{
	struct ice_fltr_mgmt_list_entry *fm_entry;
	int status = 0;

	/* check to make sure VSI ID is valid and within boundary */
	if (!ice_is_vsi_valid(hw, vsi_handle))
		return -EINVAL;

	list_for_each_entry(fm_entry, lkup_list_head, list_entry) {
		if (!ice_vsi_uses_fltr(fm_entry, vsi_handle))
			continue;

		status = ice_add_entry_to_vsi_fltr_list(hw, vsi_handle,
							vsi_list_head,
							&fm_entry->fltr_info);
		if (status)
			return status;
	}
	return status;
}

/**
 * ice_determine_promisc_mask
 * @fi: filter info to parse
 * @promisc_mask: pointer to mask to be filled in
 *
 * Helper function to determine which ICE_PROMISC_ mask corresponds
 * to given filter into.
 */
static void ice_determine_promisc_mask(struct ice_fltr_info *fi,
				       unsigned long *promisc_mask)
{
	u16 vid = fi->l_data.mac_vlan.vlan_id;
	u8 *macaddr = fi->l_data.mac.mac_addr;
	bool is_rx_lb_fltr = false;
	bool is_tx_fltr = false;

	bitmap_zero(promisc_mask, ICE_PROMISC_MAX);

	if (fi->flag == ICE_FLTR_TX)
		is_tx_fltr = true;
	if (fi->flag == ICE_FLTR_RX_LB)
		is_rx_lb_fltr = true;

	if (is_broadcast_ether_addr(macaddr)) {
		set_bit(is_tx_fltr ? ICE_PROMISC_BCAST_TX : ICE_PROMISC_BCAST_RX,
			promisc_mask);
	} else if (is_multicast_ether_addr(macaddr)) {
		set_bit(is_tx_fltr ? ICE_PROMISC_MCAST_TX : ICE_PROMISC_MCAST_RX,
			promisc_mask);
	} else if (is_unicast_ether_addr(macaddr)) {
		if (is_tx_fltr)
			set_bit(ICE_PROMISC_UCAST_TX, promisc_mask);
		else if (is_rx_lb_fltr)
			set_bit(ICE_PROMISC_UCAST_RX_LB, promisc_mask);
		else
			set_bit(ICE_PROMISC_UCAST_RX, promisc_mask);
	}

	if (vid) {
		set_bit(is_tx_fltr ? ICE_PROMISC_VLAN_TX : ICE_PROMISC_VLAN_RX,
			promisc_mask);
	}
}

/**
 * _ice_get_vsi_promisc - get promiscuous mode of given VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to retrieve info from
 * @promisc_mask: pointer to mask to be filled in
 * @vid: VLAN ID of promisc VLAN VSI
 * @sw: pointer to switch info struct for which function add rule
 * @lkup: switch rule filter lookup type
 */
static int
_ice_get_vsi_promisc(struct ice_hw *hw, u16 vsi_handle,
		     unsigned long *promisc_mask, u16 *vid,
		     struct ice_switch_info *sw, enum ice_sw_lkup_type lkup)
{
	DECLARE_BITMAP(fltr_promisc_mask, ICE_PROMISC_MAX);
	struct ice_fltr_mgmt_list_entry *itr;
	struct list_head *rule_head;
	struct mutex *rule_lock;	/* Lock to protect filter rule list */

	if (!ice_is_vsi_valid(hw, vsi_handle) ||
	    (lkup != ICE_SW_LKUP_PROMISC && lkup != ICE_SW_LKUP_PROMISC_VLAN))
		return -EINVAL;

	*vid = 0;
	rule_head = &sw->recp_list[lkup].filt_rules;
	rule_lock = &sw->recp_list[lkup].filt_rule_lock;

	bitmap_zero(promisc_mask, ICE_PROMISC_MAX);

	mutex_lock(rule_lock);
	list_for_each_entry(itr, rule_head, list_entry) {
		/* Continue if this filter doesn't apply to this VSI or the
		 * VSI ID is not in the VSI map for this filter
		 */
		if (!ice_vsi_uses_fltr(itr, vsi_handle))
			continue;

		ice_determine_promisc_mask(&itr->fltr_info, fltr_promisc_mask);
		bitmap_or(promisc_mask, promisc_mask, fltr_promisc_mask,
			  ICE_PROMISC_MAX);

	}
	mutex_unlock(rule_lock);

	return 0;
}

/**
 * ice_get_vsi_promisc - get promiscuous mode of given VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to retrieve info from
 * @promisc_mask: pointer to mask to be filled in
 * @vid: VLAN ID of promisc VLAN VSI
 */
int
ice_get_vsi_promisc(struct ice_hw *hw, u16 vsi_handle,
		    unsigned long *promisc_mask, u16 *vid)
{
	if (!vid || !promisc_mask || !hw)
		return -EINVAL;

	return _ice_get_vsi_promisc(hw, vsi_handle, promisc_mask,
				    vid, hw->switch_info, ICE_SW_LKUP_PROMISC);
}

/**
 * ice_get_vsi_vlan_promisc - get VLAN promiscuous mode of given VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to retrieve info from
 * @promisc_mask: pointer to mask to be filled in
 * @vid: VLAN ID of promisc VLAN VSI
 */
int
ice_get_vsi_vlan_promisc(struct ice_hw *hw, u16 vsi_handle,
			 unsigned long *promisc_mask, u16 *vid)
{
	if (!hw || !promisc_mask || !vid)
		return -EINVAL;

	return _ice_get_vsi_promisc(hw, vsi_handle, promisc_mask,
				    vid, hw->switch_info,
				    ICE_SW_LKUP_PROMISC_VLAN);
}

/**
 * ice_remove_promisc - Remove promisc based filter rules
 * @hw: pointer to the hardware structure
 * @recp_id: recipe ID for which the rule needs to removed
 * @v_list: list of promisc entries
 */
static int
ice_remove_promisc(struct ice_hw *hw, u8 recp_id,
		   struct list_head *v_list)
{
	struct ice_fltr_list_entry *v_list_itr, *tmp;
	struct ice_sw_recipe *recp_list;

	recp_list = &hw->switch_info->recp_list[recp_id];
	list_for_each_entry_safe(v_list_itr, tmp, v_list, list_entry) {
		v_list_itr->status =
			ice_remove_rule_internal(hw, recp_list, v_list_itr);
		if (v_list_itr->status)
			return v_list_itr->status;
	}
	return 0;
}

/**
 * _ice_clear_vsi_promisc - clear specified promiscuous mode(s)
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to clear mode
 * @promisc_mask: pointer to mask of promiscuous config bits to clear
 * @vid: VLAN ID to clear VLAN promiscuous
 * @sw: pointer to switch info struct for which function add rule
 */
static int
_ice_clear_vsi_promisc(struct ice_hw *hw, u16 vsi_handle,
		       unsigned long *promisc_mask, u16 vid,
		       struct ice_switch_info *sw)
{
	DECLARE_BITMAP(compl_promisc_mask, ICE_PROMISC_MAX);
	DECLARE_BITMAP(fltr_promisc_mask, ICE_PROMISC_MAX);
	struct ice_fltr_list_entry *fm_entry, *tmp;
	struct list_head remove_list_head;
	struct ice_fltr_mgmt_list_entry *itr;
	struct list_head *rule_head;
	struct mutex *rule_lock;	/* Lock to protect filter rule list */
	int status = 0;
	u8 recipe_id;

	if (!ice_is_vsi_valid(hw, vsi_handle))
		return -EINVAL;

	if (test_bit(ICE_PROMISC_VLAN_RX, promisc_mask) &&
	    test_bit(ICE_PROMISC_VLAN_TX, promisc_mask))
		recipe_id = ICE_SW_LKUP_PROMISC_VLAN;
	else
		recipe_id = ICE_SW_LKUP_PROMISC;

	rule_head = &sw->recp_list[recipe_id].filt_rules;
	rule_lock = &sw->recp_list[recipe_id].filt_rule_lock;

	INIT_LIST_HEAD(&remove_list_head);

	mutex_lock(rule_lock);
	list_for_each_entry(itr, rule_head, list_entry) {
		struct ice_fltr_info *fltr_info;
		bitmap_zero(compl_promisc_mask, ICE_PROMISC_MAX);

		if (!ice_vsi_uses_fltr(itr, vsi_handle))
			continue;
		fltr_info = &itr->fltr_info;

		if (recipe_id == ICE_SW_LKUP_PROMISC_VLAN &&
		    vid != fltr_info->l_data.mac_vlan.vlan_id)
			continue;

		ice_determine_promisc_mask(fltr_info, fltr_promisc_mask);
		bitmap_andnot(compl_promisc_mask, fltr_promisc_mask,
			      promisc_mask, ICE_PROMISC_MAX);

		/* Skip if filter is not completely specified by given mask */
		if (!bitmap_empty(compl_promisc_mask, ICE_PROMISC_MAX))
			continue;

		status = ice_add_entry_to_vsi_fltr_list(hw, vsi_handle,
							&remove_list_head,
							fltr_info);
		if (status) {
			mutex_unlock(rule_lock);
			goto free_fltr_list;
		}
	}
	mutex_unlock(rule_lock);

	status = ice_remove_promisc(hw, recipe_id, &remove_list_head);

free_fltr_list:
	list_for_each_entry_safe(fm_entry, tmp, &remove_list_head, list_entry) {
		list_del(&fm_entry->list_entry);
		devm_kfree(ice_hw_to_dev(hw), fm_entry);
	}

	return status;
}

/**
 * ice_clear_vsi_promisc - clear specified promiscuous mode(s) for given VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to clear mode
 * @promisc_mask: pointer to mask of promiscuous config bits to clear
 * @vid: VLAN ID to clear VLAN promiscuous
 */
int
ice_clear_vsi_promisc(struct ice_hw *hw, u16 vsi_handle,
		      unsigned long *promisc_mask, u16 vid)
{
	if (!hw || !promisc_mask)
		return -EINVAL;

	return _ice_clear_vsi_promisc(hw, vsi_handle, promisc_mask,
				      vid, hw->switch_info);
}

/**
 * _ice_set_vsi_promisc - set given VSI to given promiscuous mode(s)
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to configure
 * @promisc_mask: pointer to mask of promiscuous config bits
 * @vid: VLAN ID to set VLAN promiscuous
 * @lport: logical port number to configure promisc mode
 * @sw: pointer to switch info struct for which function add rule
 */
static int
_ice_set_vsi_promisc(struct ice_hw *hw, u16 vsi_handle,
		     unsigned long *promisc_mask, u16 vid, u8 lport,
		     struct ice_switch_info *sw)
{
	enum { UCAST_FLTR = 1, MCAST_FLTR, BCAST_FLTR };
	DECLARE_BITMAP(p_mask, ICE_PROMISC_MAX);
	struct ice_fltr_list_entry f_list_entry;
	bool is_tx_fltr, is_rx_lb_fltr;
	struct ice_fltr_info new_fltr;
	int status = 0;
	u16 hw_vsi_id;
	int pkt_type;
	u8 recipe_id;

	if (!ice_is_vsi_valid(hw, vsi_handle))
		return -EINVAL;
	hw_vsi_id = ice_get_hw_vsi_num(hw, vsi_handle);

	memset(&new_fltr, 0, sizeof(new_fltr));

	/* Do not modify original bitmap */
	bitmap_copy(p_mask, promisc_mask, ICE_PROMISC_MAX);

	if (test_bit(ICE_PROMISC_VLAN_RX, p_mask) &&
	    test_bit(ICE_PROMISC_VLAN_TX, p_mask)) {
		new_fltr.lkup_type = ICE_SW_LKUP_PROMISC_VLAN;
		new_fltr.l_data.mac_vlan.vlan_id = vid;
		recipe_id = ICE_SW_LKUP_PROMISC_VLAN;
	} else {
		new_fltr.lkup_type = ICE_SW_LKUP_PROMISC;
		recipe_id = ICE_SW_LKUP_PROMISC;
	}

	/* Separate filters must be set for each direction/packet type
	 * combination, so we will loop over the mask value, store the
	 * individual type, and clear it out in the input mask as it
	 * is found.
	 */
	while (!bitmap_empty(p_mask, ICE_PROMISC_MAX)) {
		struct ice_sw_recipe *recp_list;
		u8 *mac_addr;

		pkt_type = 0;
		is_tx_fltr = false;
		is_rx_lb_fltr = false;

		if (test_and_clear_bit(ICE_PROMISC_UCAST_RX, p_mask)) {
			pkt_type = UCAST_FLTR;
		} else if (test_and_clear_bit(ICE_PROMISC_UCAST_TX, p_mask)) {
			pkt_type = UCAST_FLTR;
			is_tx_fltr = true;
		} else if (test_and_clear_bit(ICE_PROMISC_MCAST_RX, p_mask)) {
			pkt_type = MCAST_FLTR;
		} else if (test_and_clear_bit(ICE_PROMISC_MCAST_TX, p_mask)) {
			pkt_type = MCAST_FLTR;
			is_tx_fltr = true;
		} else if (test_and_clear_bit(ICE_PROMISC_BCAST_RX, p_mask)) {
			pkt_type = BCAST_FLTR;
		} else if (test_and_clear_bit(ICE_PROMISC_BCAST_TX, p_mask)) {
			pkt_type = BCAST_FLTR;
			is_tx_fltr = true;
		} else if (test_and_clear_bit(ICE_PROMISC_UCAST_RX_LB, p_mask)) {
			pkt_type = UCAST_FLTR;
			is_rx_lb_fltr = true;
		}

		/* Check for VLAN promiscuous flag */
		if (test_bit(ICE_PROMISC_VLAN_RX, p_mask)) {
			clear_bit(ICE_PROMISC_VLAN_RX, p_mask);
		} else if (test_and_clear_bit(ICE_PROMISC_VLAN_TX, p_mask)) {
			is_tx_fltr = true;
		}
		/* Set filter DA based on packet type */
		mac_addr = new_fltr.l_data.mac.mac_addr;
		if (pkt_type == BCAST_FLTR) {
			eth_broadcast_addr(mac_addr);
		} else if (pkt_type == MCAST_FLTR ||
			   pkt_type == UCAST_FLTR) {
			/* Use the dummy ether header DA */
			ether_addr_copy(mac_addr, dummy_eth_header);
			if (pkt_type == MCAST_FLTR)
				mac_addr[0] |= 0x1;	/* Set multicast bit */
		}

		/* Need to reset this to zero for all iterations */
		new_fltr.flag = 0;
		if (is_tx_fltr) {
			new_fltr.flag |= ICE_FLTR_TX;
			new_fltr.src = hw_vsi_id;
		} else if (is_rx_lb_fltr) {
			new_fltr.flag |= ICE_FLTR_RX_LB;
			new_fltr.src = hw_vsi_id;
		} else {
			new_fltr.flag |= ICE_FLTR_RX;
			new_fltr.src = lport;
		}

		new_fltr.fltr_act = ICE_FWD_TO_VSI;
		new_fltr.vsi_handle = vsi_handle;
		new_fltr.fwd_id.hw_vsi_id = hw_vsi_id;
		f_list_entry.fltr_info = new_fltr;
		recp_list = &sw->recp_list[recipe_id];

		status = ice_add_rule_internal(hw, recp_list, lport,
					       &f_list_entry);
		if (status)
			goto set_promisc_exit;
	}

set_promisc_exit:
	return status;
}

/**
 * ice_set_vsi_promisc - set given VSI to given promiscuous mode(s)
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to configure
 * @promisc_mask: pointer to mask of promiscuous config bits
 * @vid: VLAN ID to set VLAN promiscuous
 */
int
ice_set_vsi_promisc(struct ice_hw *hw, u16 vsi_handle,
		    unsigned long *promisc_mask, u16 vid)
{
	if (!hw || !promisc_mask)
		return -EINVAL;

	return _ice_set_vsi_promisc(hw, vsi_handle, promisc_mask, vid,
				    hw->port_info->lport,
				    hw->switch_info);
}

/**
 * _ice_set_vlan_vsi_promisc
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to configure
 * @promisc_mask: pointer to mask of promiscuous config bits
 * @rm_vlan_promisc: Clear VLANs VSI promisc mode
 * @lport: logical port number to configure promisc mode
 * @sw: pointer to switch info struct for which function add rule
 *
 * Configure VSI with all associated VLANs to given promiscuous mode(s)
 */
static int
_ice_set_vlan_vsi_promisc(struct ice_hw *hw, u16 vsi_handle,
			  unsigned long *promisc_mask, bool rm_vlan_promisc,
			  u8 lport, struct ice_switch_info *sw)
{
	struct ice_fltr_list_entry *list_itr, *tmp;
	struct list_head vsi_list_head;
	struct list_head *vlan_head;
	struct mutex *vlan_lock; /* Lock to protect filter rule list */
	int status;
	u16 vlan_id;

	INIT_LIST_HEAD(&vsi_list_head);
	vlan_lock = &sw->recp_list[ICE_SW_LKUP_VLAN].filt_rule_lock;
	vlan_head = &sw->recp_list[ICE_SW_LKUP_VLAN].filt_rules;
	mutex_lock(vlan_lock);
	status = ice_add_to_vsi_fltr_list(hw, vsi_handle, vlan_head,
					  &vsi_list_head);
	mutex_unlock(vlan_lock);
	if (status)
		goto free_fltr_list;

	list_for_each_entry(list_itr, &vsi_list_head, list_entry) {
		/* Avoid enabling or disabling vlan zero twice when in double
		 * vlan mode
		 */
		if (ice_is_dvm_ena(hw) &&
		    list_itr->fltr_info.l_data.vlan.tpid == 0)
			continue;

		vlan_id = list_itr->fltr_info.l_data.vlan.vlan_id;
		if (rm_vlan_promisc)
			status =  _ice_clear_vsi_promisc(hw, vsi_handle,
							 promisc_mask,
							 vlan_id, sw);
		else
			status =  _ice_set_vsi_promisc(hw, vsi_handle,
						       promisc_mask, vlan_id,
						       lport, sw);
		if (status && status != -EEXIST)
			break;
	}

free_fltr_list:
	list_for_each_entry_safe(list_itr, tmp, &vsi_list_head, list_entry) {
		list_del(&list_itr->list_entry);
		devm_kfree(ice_hw_to_dev(hw), list_itr);
	}
	return status;
}

/**
 * ice_set_vlan_vsi_promisc
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to configure
 * @promisc_mask: mask of promiscuous config bits
 * @rm_vlan_promisc: Clear VLANs VSI promisc mode
 *
 * Configure VSI with all associated VLANs to given promiscuous mode(s)
 */
int
ice_set_vlan_vsi_promisc(struct ice_hw *hw, u16 vsi_handle,
			 unsigned long *promisc_mask, bool rm_vlan_promisc)
{
	if (!hw || !promisc_mask)
		return -EINVAL;

	return _ice_set_vlan_vsi_promisc(hw, vsi_handle, promisc_mask,
					 rm_vlan_promisc, hw->port_info->lport,
					 hw->switch_info);
}

/**
 * ice_remove_vsi_lkup_fltr - Remove lookup type filters for a VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to remove filters from
 * @recp_list: recipe list from which function remove fltr
 * @lkup: switch rule filter lookup type
 */
static void
ice_remove_vsi_lkup_fltr(struct ice_hw *hw, u16 vsi_handle,
			 struct ice_sw_recipe *recp_list,
			 enum ice_sw_lkup_type lkup)
{
	struct ice_fltr_list_entry *fm_entry;
	struct list_head remove_list_head;
	struct list_head *rule_head;
	struct ice_fltr_list_entry *tmp;
	struct mutex *rule_lock;	/* Lock to protect filter rule list */
	int status;

	INIT_LIST_HEAD(&remove_list_head);
	rule_lock = &recp_list[lkup].filt_rule_lock;
	rule_head = &recp_list[lkup].filt_rules;
	mutex_lock(rule_lock);
	status = ice_add_to_vsi_fltr_list(hw, vsi_handle, rule_head,
					  &remove_list_head);
	mutex_unlock(rule_lock);
	if (status)
		goto free_fltr_list;

	switch (lkup) {
	case ICE_SW_LKUP_MAC:
		ice_remove_mac_rule(hw, &remove_list_head, &recp_list[lkup]);
		break;
	case ICE_SW_LKUP_VLAN:
		ice_remove_vlan_rule(hw, &remove_list_head, &recp_list[lkup]);
		break;
	case ICE_SW_LKUP_PROMISC:
	case ICE_SW_LKUP_PROMISC_VLAN:
		ice_remove_promisc(hw, (u8)lkup, &remove_list_head);
		break;
	case ICE_SW_LKUP_MAC_VLAN:
		ice_remove_mac_vlan(hw, &remove_list_head);
		break;
	case ICE_SW_LKUP_ETHERTYPE:
	case ICE_SW_LKUP_ETHERTYPE_MAC:
		ice_remove_eth_mac(hw, &remove_list_head);
		break;
	case ICE_SW_LKUP_DFLT:
		ice_debug(hw, ICE_DBG_SW, "Remove filters for this lookup type hasn't been implemented yet\n");
		break;
	case ICE_SW_LKUP_LAST:
		ice_debug(hw, ICE_DBG_SW, "Unsupported lookup type\n");
		break;
	}

free_fltr_list:
	list_for_each_entry_safe(fm_entry, tmp, &remove_list_head, list_entry) {
		list_del(&fm_entry->list_entry);
		devm_kfree(ice_hw_to_dev(hw), fm_entry);
	}
}

/**
 * ice_remove_vsi_fltr_rule - Remove all filters for a VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to remove filters from
 * @sw: pointer to switch info struct
 */
static void
ice_remove_vsi_fltr_rule(struct ice_hw *hw, u16 vsi_handle,
			 struct ice_switch_info *sw)
{
	ice_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->recp_list, ICE_SW_LKUP_MAC);
	ice_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->recp_list, ICE_SW_LKUP_MAC_VLAN);
	ice_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->recp_list, ICE_SW_LKUP_PROMISC);
	ice_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->recp_list, ICE_SW_LKUP_VLAN);
	ice_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->recp_list, ICE_SW_LKUP_DFLT);
	ice_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->recp_list, ICE_SW_LKUP_ETHERTYPE);
	ice_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->recp_list, ICE_SW_LKUP_ETHERTYPE_MAC);
	ice_remove_vsi_lkup_fltr(hw, vsi_handle,
				 sw->recp_list, ICE_SW_LKUP_PROMISC_VLAN);
}

/**
 * ice_remove_vsi_fltr - Remove all filters for a VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle to remove filters from
 */
void ice_remove_vsi_fltr(struct ice_hw *hw, u16 vsi_handle)
{
	ice_remove_vsi_fltr_rule(hw, vsi_handle, hw->switch_info);
}

/**
 * ice_alloc_res_cntr - allocating resource counter
 * @hw: pointer to the hardware structure
 * @type: type of resource
 * @alloc_shared: if set it is shared else dedicated
 * @num_items: number of entries requested for FD resource type
 * @counter_id: counter index returned by AQ call
 */
int
ice_alloc_res_cntr(struct ice_hw *hw, u8 type, u8 alloc_shared, u16 num_items,
		   u16 *counter_id)
{
	struct ice_aqc_alloc_free_res_elem *buf;
	u16 buf_len;
	int status;

	/* Allocate resource */
	buf_len = struct_size(buf, elem, 1);
	buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->num_elems = cpu_to_le16(num_items);
	buf->res_type = cpu_to_le16(((type << ICE_AQC_RES_TYPE_S) &
				      ICE_AQC_RES_TYPE_M) | alloc_shared);

	status = ice_aq_alloc_free_res(hw, 1, buf, buf_len,
				       ice_aqc_opc_alloc_res, NULL);
	if (status)
		goto exit;

	*counter_id = le16_to_cpu(buf->elem[0].e.sw_resp);

exit:
	devm_kfree(ice_hw_to_dev(hw), buf);
	return status;
}

/**
 * ice_free_res_cntr - free resource counter
 * @hw: pointer to the hardware structure
 * @type: type of resource
 * @alloc_shared: if set it is shared else dedicated
 * @num_items: number of entries to be freed for FD resource type
 * @counter_id: counter ID resource which needs to be freed
 */
int
ice_free_res_cntr(struct ice_hw *hw, u8 type, u8 alloc_shared, u16 num_items,
		  u16 counter_id)
{
	struct ice_aqc_alloc_free_res_elem *buf;
	u16 buf_len;
	int status;

	/* Free resource */
	buf_len = struct_size(buf, elem, 1);
	buf = devm_kzalloc(ice_hw_to_dev(hw), buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->num_elems = cpu_to_le16(num_items);
	buf->res_type = cpu_to_le16(((type << ICE_AQC_RES_TYPE_S) &
				      ICE_AQC_RES_TYPE_M) | alloc_shared);
	buf->elem[0].e.sw_resp = cpu_to_le16(counter_id);

	status = ice_aq_alloc_free_res(hw, 1, buf, buf_len,
				       ice_aqc_opc_free_res, NULL);
	if (status)
		ice_debug(hw, ICE_DBG_SW, "counter resource could not be freed\n");

	devm_kfree(ice_hw_to_dev(hw), buf);
	return status;
}

/**
 * ice_alloc_vlan_res_counter - obtain counter resource for VLAN type
 * @hw: pointer to the hardware structure
 * @counter_id: returns counter index
 */
int ice_alloc_vlan_res_counter(struct ice_hw *hw, u16 *counter_id)
{
	return ice_alloc_res_cntr(hw, ICE_AQC_RES_TYPE_VLAN_COUNTER,
				  ICE_AQC_RES_TYPE_FLAG_DEDICATED, 1,
				  counter_id);
}

/**
 * ice_free_vlan_res_counter - Free counter resource for VLAN type
 * @hw: pointer to the hardware structure
 * @counter_id: counter index to be freed
 */
int ice_free_vlan_res_counter(struct ice_hw *hw, u16 counter_id)
{
	return ice_free_res_cntr(hw, ICE_AQC_RES_TYPE_VLAN_COUNTER,
				 ICE_AQC_RES_TYPE_FLAG_DEDICATED, 1,
				 counter_id);
}

/**
 * ice_add_mac_with_sw_marker - add filter with sw marker
 * @hw: pointer to the hardware structure
 * @f_info: filter info structure containing the MAC filter information
 * @sw_marker: sw marker to tag the Rx descriptor with
 */
int
ice_add_mac_with_sw_marker(struct ice_hw *hw, struct ice_fltr_info *f_info,
			   u16 sw_marker)
{
	struct ice_fltr_mgmt_list_entry *m_entry;
	struct ice_fltr_list_entry fl_info;
	struct ice_sw_recipe *recp_list;
	struct list_head l_head;
	struct mutex *rule_lock;	/* Lock to protect filter rule list */
	bool entry_exists;
	u16 lg_act_id;
	int ret;

	if (f_info->fltr_act != ICE_FWD_TO_VSI)
		return -EINVAL;

	if (f_info->lkup_type != ICE_SW_LKUP_MAC)
		return -EINVAL;

	if (sw_marker == ICE_INVAL_SW_MARKER_ID)
		return -EINVAL;

	if (!ice_is_vsi_valid(hw, f_info->vsi_handle))
		return -EINVAL;
	f_info->fwd_id.hw_vsi_id = ice_get_hw_vsi_num(hw, f_info->vsi_handle);

	/* Add filter if it doesn't exist so then the adding of large
	 * action always results in update
	 */

	INIT_LIST_HEAD(&l_head);
	fl_info.fltr_info = *f_info;
	list_add(&fl_info.list_entry, &l_head);

	entry_exists = false;
	ret = ice_add_mac_rule(hw, &l_head, hw->switch_info,
			       hw->port_info->lport);
	if (ret == -EEXIST)
		entry_exists = true;
	else if (ret)
		return ret;

	recp_list = &hw->switch_info->recp_list[ICE_SW_LKUP_MAC];
	rule_lock = &recp_list->filt_rule_lock;
	mutex_lock(rule_lock);
	/* Get the book keeping entry for the filter */
	m_entry = ice_find_rule_entry(&recp_list->filt_rules, f_info);
	if (!m_entry)
		goto exit_error;

	/* If counter action was enabled for this rule then don't enable
	 * sw marker large action
	 */
	if (m_entry->counter_index != ICE_INVAL_COUNTER_ID) {
		ret = -EINVAL;
		goto exit_error;
	}

	/* if same marker was added before */
	if (m_entry->sw_marker_id == sw_marker) {
		ret = -EEXIST;
		goto exit_error;
	}

	/* Allocate a hardware table entry to hold large act. Three actions
	 * for marker based large action
	 */
	ret = ice_alloc_res_lg_act(hw, &lg_act_id, 3);
	if (ret)
		goto exit_error;

	if (lg_act_id == ICE_INVAL_LG_ACT_INDEX)
		goto exit_error;

	/* Update the switch rule to add the marker action */
	ret = ice_add_marker_act(hw, m_entry, sw_marker, lg_act_id);
	if (!ret) {
		mutex_unlock(rule_lock);
		return ret;
	}

exit_error:
	mutex_unlock(rule_lock);
	/* only remove entry if it did not exist previously */
	if (!entry_exists)
		ret = ice_remove_mac(hw, &l_head);

	return ret;
}

/**
 * ice_add_mac_with_counter - add filter with counter enabled
 * @hw: pointer to the hardware structure
 * @f_info: pointer to filter info structure containing the MAC filter
 *          information
 */
int
ice_add_mac_with_counter(struct ice_hw *hw, struct ice_fltr_info *f_info)
{
	struct ice_fltr_mgmt_list_entry *m_entry;
	struct ice_fltr_list_entry fl_info;
	struct ice_sw_recipe *recp_list;
	struct list_head l_head;
	struct mutex *rule_lock;	/* Lock to protect filter rule list */
	bool entry_exist;
	u16 counter_id;
	u16 lg_act_id;
	int ret;

	if (f_info->fltr_act != ICE_FWD_TO_VSI)
		return -EINVAL;

	if (f_info->lkup_type != ICE_SW_LKUP_MAC)
		return -EINVAL;

	if (!ice_is_vsi_valid(hw, f_info->vsi_handle))
		return -EINVAL;
	f_info->fwd_id.hw_vsi_id = ice_get_hw_vsi_num(hw, f_info->vsi_handle);
	recp_list = &hw->switch_info->recp_list[ICE_SW_LKUP_MAC];

	entry_exist = false;

	rule_lock = &recp_list->filt_rule_lock;

	/* Add filter if it doesn't exist so then the adding of large
	 * action always results in update
	 */
	INIT_LIST_HEAD(&l_head);

	fl_info.fltr_info = *f_info;
	list_add(&fl_info.list_entry, &l_head);

	ret = ice_add_mac_rule(hw, &l_head, hw->switch_info,
			       hw->port_info->lport);
	if (ret == -EEXIST)
		entry_exist = true;
	else if (ret)
		return ret;

	mutex_lock(rule_lock);
	m_entry = ice_find_rule_entry(&recp_list->filt_rules, f_info);
	if (!m_entry) {
		ret = -EINVAL;
		goto exit_error;
	}

	/* Don't enable counter for a filter for which sw marker was enabled */
	if (m_entry->sw_marker_id != ICE_INVAL_SW_MARKER_ID) {
		ret = -EINVAL;
		goto exit_error;
	}

	/* If a counter was already enabled then don't need to add again */
	if (m_entry->counter_index != ICE_INVAL_COUNTER_ID) {
		ret = -EEXIST;
		goto exit_error;
	}

	/* Allocate a hardware table entry to VLAN counter */
	ret = ice_alloc_vlan_res_counter(hw, &counter_id);
	if (ret)
		goto exit_error;

	/* Allocate a hardware table entry to hold large act. Two actions for
	 * counter based large action
	 */
	ret = ice_alloc_res_lg_act(hw, &lg_act_id, 2);
	if (ret)
		goto exit_error;

	if (lg_act_id == ICE_INVAL_LG_ACT_INDEX)
		goto exit_error;

	/* Update the switch rule to add the counter action */
	ret = ice_add_counter_act(hw, m_entry, counter_id, lg_act_id);
	if (!ret) {
		mutex_unlock(rule_lock);
		return ret;
	}

exit_error:
	mutex_unlock(rule_lock);
	/* only remove entry if it did not exist previously */
	if (!entry_exist)
		ret = ice_remove_mac(hw, &l_head);

	return ret;
}

/* This is mapping table entry that maps every word within a given protocol
 * structure to the real byte offset as per the specification of that
 * protocol header.
 * for example dst address is 3 words in ethertype header and corresponding
 * bytes are 0, 2, 3 in the actual packet header and src address is at 4, 6, 8
 * IMPORTANT: Every structure part of "ice_prot_hdr" union should have a
 * matching entry describing its field. This needs to be updated if new
 * structure is added to that union.
 */
static const struct ice_prot_ext_tbl_entry ice_prot_ext[ICE_PROTOCOL_LAST] = {
	{ ICE_MAC_OFOS,		{ 0, 2, 4, 6, 8, 10, 12 } },
	{ ICE_MAC_IL,		{ 0, 2, 4, 6, 8, 10, 12 } },
	{ ICE_ETYPE_OL,		{ 0 } },
	{ ICE_ETYPE_IL,		{ 0 } },
	{ ICE_VLAN_OFOS,	{ 2, 0 } },
	{ ICE_IPV4_OFOS,	{ 0, 2, 4, 6, 8, 10, 12, 14, 16, 18 } },
	{ ICE_IPV4_IL,		{ 0, 2, 4, 6, 8, 10, 12, 14, 16, 18 } },
	{ ICE_IPV6_OFOS,	{ 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24,
				 26, 28, 30, 32, 34, 36, 38 } },
	{ ICE_IPV6_IL,		{ 0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24,
				 26, 28, 30, 32, 34, 36, 38 } },
	{ ICE_TCP_IL,		{ 0, 2 } },
	{ ICE_UDP_OF,		{ 0, 2 } },
	{ ICE_UDP_ILOS,		{ 0, 2 } },
	{ ICE_SCTP_IL,		{ 0, 2 } },
	{ ICE_VXLAN,		{ 8, 10, 12, 14 } },
	{ ICE_GENEVE,		{ 8, 10, 12, 14 } },
	{ ICE_VXLAN_GPE,	{ 8, 10, 12, 14 } },
	{ ICE_NVGRE,		{ 0, 2, 4, 6 } },
	{ ICE_GTP,		{ 8, 10, 12, 14, 16, 18, 20, 22 } },
	{ ICE_GTP_NO_PAY,	{ 8, 10, 12, 14 } },
	{ ICE_PPPOE,		{ 0, 2, 4, 6 } },
	{ ICE_PFCP,		{ 8, 10, 12, 14, 16, 18, 20, 22 } },
	{ ICE_L2TPV3,		{ 0, 2, 4, 6, 8, 10 } },
	{ ICE_ESP,		{ 0, 2, 4, 6 } },
	{ ICE_AH,		{ 0, 2, 4, 6, 8, 10 } },
	{ ICE_NAT_T,		{ 8, 10, 12, 14 } },
	{ ICE_VLAN_EX,		{ 2, 0 } },
	{ ICE_VLAN_IN,		{ 2, 0 } },
};

/* The following table describes preferred grouping of recipes.
 * If a recipe that needs to be programmed is a superset or matches one of the
 * following combinations, then the recipe needs to be chained as per the
 * following policy.
 */

static struct ice_protocol_entry ice_prot_id_tbl[ICE_PROTOCOL_LAST] = {
	{ ICE_MAC_OFOS,		ICE_MAC_OFOS_HW },
	{ ICE_MAC_IL,		ICE_MAC_IL_HW },
	{ ICE_ETYPE_OL,		ICE_ETYPE_OL_HW },
	{ ICE_ETYPE_IL,		ICE_ETYPE_IL_HW },
	{ ICE_VLAN_OFOS,	ICE_VLAN_OL_HW },
	{ ICE_IPV4_OFOS,	ICE_IPV4_OFOS_HW },
	{ ICE_IPV4_IL,		ICE_IPV4_IL_HW },
	{ ICE_IPV6_OFOS,	ICE_IPV6_OFOS_HW },
	{ ICE_IPV6_IL,		ICE_IPV6_IL_HW },
	{ ICE_TCP_IL,		ICE_TCP_IL_HW },
	{ ICE_UDP_OF,		ICE_UDP_OF_HW },
	{ ICE_UDP_ILOS,		ICE_UDP_ILOS_HW },
	{ ICE_SCTP_IL,		ICE_SCTP_IL_HW },
	{ ICE_VXLAN,		ICE_UDP_OF_HW },
	{ ICE_GENEVE,		ICE_UDP_OF_HW },
	{ ICE_VXLAN_GPE,	ICE_UDP_OF_HW },
	{ ICE_NVGRE,		ICE_GRE_OF_HW },
	{ ICE_GTP,		ICE_UDP_OF_HW },
	{ ICE_GTP_NO_PAY,	ICE_UDP_ILOS_HW },
	{ ICE_PPPOE,		ICE_PPPOE_HW },
	{ ICE_PFCP,		ICE_UDP_ILOS_HW },
	{ ICE_L2TPV3,		ICE_L2TPV3_HW },
	{ ICE_ESP,		ICE_ESP_HW },
	{ ICE_AH,		ICE_AH_HW },
	{ ICE_NAT_T,		ICE_UDP_ILOS_HW },
	{ ICE_VLAN_EX,		ICE_VLAN_OF_HW },
	{ ICE_VLAN_IN,		ICE_VLAN_OL_HW },
	{ ICE_FLG_DIR,		ICE_META_DATA_ID_HW},
};

/*
 * ice_find_recp - find a recipe
 * @hw: pointer to the hardware structure
 * @lkup_exts: extension sequence to match
 * @tun_type: tunnel type of switch filter
 * @priority: priority of switch filter
 *
 * Returns index of matching recipe, or ICE_MAX_NUM_RECIPES if not found.
 */
static u16 ice_find_recp(struct ice_hw *hw, struct ice_prot_lkup_ext *lkup_exts,
			 enum ice_sw_tunnel_type tun_type, u32 priority)
{
	bool refresh_required = true;
	struct ice_sw_recipe *recp;
	u8 i;

	/* Walk through existing recipes to find a match */
	recp = hw->switch_info->recp_list;
	for (i = 0; i < ICE_MAX_NUM_RECIPES; i++) {
		/* If recipe was not created for this ID, in SW bookkeeping,
		 * check if FW has an entry for this recipe. If the FW has an
		 * entry update it in our SW bookkeeping and continue with the
		 * matching.
		 */
		if (!recp[i].recp_created)
			if (ice_get_recp_frm_fw(hw,
						hw->switch_info->recp_list, i,
						&refresh_required))
				continue;

		/* Skip inverse action recipes */
		if (recp[i].root_buf && recp[i].root_buf->content.act_ctrl &
		    ICE_AQ_RECIPE_ACT_INV_ACT)
			continue;

		/* if number of words we are looking for match */
		if (lkup_exts->n_val_words == recp[i].lkup_exts.n_val_words) {
			struct ice_fv_word *ar = recp[i].lkup_exts.fv_words;
			struct ice_fv_word *be = lkup_exts->fv_words;
			u16 *cr = recp[i].lkup_exts.field_mask;
			u16 *de = lkup_exts->field_mask;
			bool found = true;
			u8 pe, qr;

			/* ar, cr, and qr are related to the recipe words, while
			 * be, de, and pe are related to the lookup words
			 */
			for (pe = 0; pe < lkup_exts->n_val_words; pe++) {
				for (qr = 0; qr < recp[i].lkup_exts.n_val_words;
				     qr++) {
					if (ar[qr].off == be[pe].off &&
					    ar[qr].prot_id == be[pe].prot_id &&
					    cr[qr] == de[pe])
						/* Found the "pe"th word in the
						 * given recipe
						 */
						break;
				}
				/* After walking through all the words in the
				 * "i"th recipe if "p"th word was not found then
				 * this recipe is not what we are looking for.
				 * So break out from this loop and try the next
				 * recipe
				 */
				if (qr >= recp[i].lkup_exts.n_val_words) {
					found = false;
					break;
				}
			}
			/* If for "i"th recipe the found was never set to false
			 * then it means we found our match
			 */
			if (found && priority == recp[i].priority) {
				if (tun_type == recp[i].tun_type ||
				    (recp[i].tun_type == ICE_SW_TUN_UDP &&
				     (tun_type == ICE_SW_TUN_VXLAN_GPE ||
				      tun_type == ICE_SW_TUN_VXLAN ||
				      tun_type == ICE_SW_TUN_GENEVE ||
				      tun_type == ICE_SW_TUN_GENEVE_VLAN ||
				      tun_type == ICE_SW_TUN_VXLAN_VLAN)))
					return i; /* Return the recipe ID */
			}
		}
	}
	return ICE_MAX_NUM_RECIPES;
}

/**
 * ice_change_proto_id_to_dvm - change proto id in prot_id_tbl
 *
 * As protocol id for outer vlan is different in dvm and svm, if dvm is
 * supported protocol array record for outer vlan has to be modified to
 * reflect the value proper for DVM.
 */
void ice_change_proto_id_to_dvm(void)
{
	u8 i;

	for (i = 0; i < ARRAY_SIZE(ice_prot_id_tbl); i++)
		if (ice_prot_id_tbl[i].type == ICE_VLAN_OFOS &&
		    ice_prot_id_tbl[i].protocol_id != ICE_VLAN_OF_HW)
			ice_prot_id_tbl[i].protocol_id = ICE_VLAN_OF_HW;
}

/**
 * ice_prot_type_to_id - get protocol ID from protocol type
 * @type: protocol type
 * @id: pointer to variable that will receive the ID
 *
 * Returns true if found, false otherwise
 */
static bool ice_prot_type_to_id(enum ice_protocol_type type, u8 *id)
{
	u8 i;

	for (i = 0; i < ARRAY_SIZE(ice_prot_id_tbl); i++)
		if (ice_prot_id_tbl[i].type == type) {
			*id = ice_prot_id_tbl[i].protocol_id;
			return true;
		}
	return false;
}

/**
 * ice_fill_valid_words - count valid words
 * @rule: advanced rule with lookup information
 * @lkup_exts: byte offset extractions of the words that are valid
 *
 * calculate valid words in a lookup rule using mask value
 */
static u8
ice_fill_valid_words(struct ice_adv_lkup_elem *rule,
		     struct ice_prot_lkup_ext *lkup_exts)
{
	u8 j, word, prot_id, ret_val;

	if (!ice_prot_type_to_id(rule->type, &prot_id))
		return 0;

	word = lkup_exts->n_val_words;

	for (j = 0; j < sizeof(rule->m_u) / sizeof(u16); j++)
		if (((u16 *)&rule->m_u)[j] &&
		    rule->type < ARRAY_SIZE(ice_prot_ext)) {
			/* No more space to accommodate */
			if (word >= ICE_MAX_CHAIN_WORDS)
				return 0;
			lkup_exts->fv_words[word].off =
				ice_prot_ext[rule->type].offs[j];
			lkup_exts->fv_words[word].prot_id =
				ice_prot_id_tbl[rule->type].protocol_id;
			lkup_exts->field_mask[word] =
				be16_to_cpu(((__force __be16 *)&rule->m_u)[j]);
			word++;
		}

	ret_val = word - lkup_exts->n_val_words;
	lkup_exts->n_val_words = word;

	return ret_val;
}

/**
 * ice_create_first_fit_recp_def - Create a recipe grouping
 * @hw: pointer to the hardware structure
 * @lkup_exts: an array of protocol header extractions
 * @rg_list: pointer to a list that stores new recipe groups
 * @recp_cnt: pointer to a variable that stores returned number of recipe groups
 *
 * Using first fit algorithm, take all the words that are still not done
 * and start grouping them in 4-word groups. Each group makes up one
 * recipe.
 */
static int
ice_create_first_fit_recp_def(struct ice_hw *hw,
			      struct ice_prot_lkup_ext *lkup_exts,
			      struct list_head *rg_list,
			      u8 *recp_cnt)
{
	struct ice_pref_recipe_group *grp = NULL;
	u8 j;

	*recp_cnt = 0;

	if (!lkup_exts->n_val_words) {
		struct ice_recp_grp_entry *entry;

		entry = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*entry),
				     GFP_KERNEL);
		if (!entry)
			return -ENOMEM;
		list_add(&entry->l_entry, rg_list);
		grp = &entry->r_group;
		(*recp_cnt)++;
		grp->n_val_pairs = 0;
	}

	/* Walk through every word in the rule to check if it is not done. If so
	 * then this word needs to be part of a new recipe.
	 */
	for (j = 0; j < lkup_exts->n_val_words; j++)
		if (!test_bit(j, lkup_exts->done)) {
			if (!grp ||
			    grp->n_val_pairs == ICE_NUM_WORDS_RECIPE) {
				struct ice_recp_grp_entry *entry;

				entry = devm_kzalloc(ice_hw_to_dev(hw),
						     sizeof(*entry),
						     GFP_KERNEL);
				if (!entry)
					return -ENOMEM;
				list_add(&entry->l_entry, rg_list);
				grp = &entry->r_group;
				(*recp_cnt)++;
			}

			grp->pairs[grp->n_val_pairs].prot_id =
				lkup_exts->fv_words[j].prot_id;
			grp->pairs[grp->n_val_pairs].off =
				lkup_exts->fv_words[j].off;
			grp->mask[grp->n_val_pairs] = lkup_exts->field_mask[j];
			grp->n_val_pairs++;
		}

	return 0;
}

/**
 * ice_fill_fv_word_index - fill in the field vector indices for a recipe group
 * @hw: pointer to the hardware structure
 * @fv_list: field vector with the extraction sequence information
 * @rg_list: recipe groupings with protocol-offset pairs
 *
 * Helper function to fill in the field vector indices for protocol-offset
 * pairs. These indexes are then ultimately programmed into a recipe.
 */
static int
ice_fill_fv_word_index(struct ice_hw *hw, struct list_head *fv_list,
		       struct list_head *rg_list)
{
	struct ice_sw_fv_list_entry *fv;
	struct ice_recp_grp_entry *rg;
	struct ice_fv_word *fv_ext;

	if (list_empty(fv_list))
		return 0;

	fv = list_first_entry(fv_list, struct ice_sw_fv_list_entry,
			      list_entry);
	fv_ext = fv->fv_ptr->ew;

	list_for_each_entry(rg, rg_list, l_entry) {
		u8 i;

		for (i = 0; i < rg->r_group.n_val_pairs; i++) {
			struct ice_fv_word *pr;
			bool found = false;
			u16 mask;
			u8 j;

			pr = &rg->r_group.pairs[i];
			mask = rg->r_group.mask[i];

			for (j = 0; j < hw->blk[ICE_BLK_SW].es.fvw; j++)
				if (fv_ext[j].prot_id == pr->prot_id &&
				    fv_ext[j].off == pr->off) {
					found = true;

					/* Store index of field vector */
					rg->fv_idx[i] = j;
					rg->fv_mask[i] = mask;
					break;
				}

			/* Protocol/offset could not be found, caller gave an
			 * invalid pair
			 */
			if (!found)
				return -EINVAL;
		}
	}

	return 0;
}

/**
 * ice_find_free_recp_res_idx - find free result indexes for recipe
 * @hw: pointer to hardware structure
 * @profiles: bitmap of profiles that will be associated with the new recipe
 * @free_idx: pointer to variable to receive the free index bitmap
 *
 * The algorithm used here is:
 *	1. When creating a new recipe, create a set P which contains all
 *	   Profiles that will be associated with our new recipe
 *
 *	2. For each Profile p in set P:
 *	    a. Add all recipes associated with Profile p into set R
 *	    b. Optional : PossibleIndexes &= profile[p].possibleIndexes
 *		[initially PossibleIndexes should be 0xFFFFFFFFFFFFFFFF]
 *		i. Or just assume they all have the same possible indexes:
 *			44, 45, 46, 47
 *			i.e., PossibleIndexes = 0x0000F00000000000
 *
 *	3. For each Recipe r in set R:
 *	    a. UsedIndexes |= (bitwise or ) recipe[r].res_indexes
 *	    b. FreeIndexes = UsedIndexes ^ PossibleIndexes
 *
 *	FreeIndexes will contain the bits indicating the indexes free for use,
 *      then the code needs to update the recipe[r].used_result_idx_bits to
 *      indicate which indexes were selected for use by this recipe.
 */
static u16
ice_find_free_recp_res_idx(struct ice_hw *hw, const unsigned long *profiles,
			   unsigned long *free_idx)
{
	DECLARE_BITMAP(possible_idx, ICE_MAX_FV_WORDS);
	DECLARE_BITMAP(recipes, ICE_MAX_NUM_RECIPES);
	DECLARE_BITMAP(used_idx, ICE_MAX_FV_WORDS);
	u16 bit;

	bitmap_zero(possible_idx, ICE_MAX_FV_WORDS);
	bitmap_zero(recipes, ICE_MAX_NUM_RECIPES);
	bitmap_zero(used_idx, ICE_MAX_FV_WORDS);
	bitmap_zero(free_idx, ICE_MAX_FV_WORDS);

	bitmap_set(possible_idx, 0, ICE_MAX_FV_WORDS);

	/* For each profile we are going to associate the recipe with, add the
	 * recipes that are associated with that profile. This will give us
	 * the set of recipes that our recipe may collide with. Also, determine
	 * what possible result indexes are usable given this set of profiles.
	 */
	for_each_set_bit(bit, profiles, ICE_MAX_NUM_PROFILES) {
		bitmap_or(recipes, recipes, profile_to_recipe[bit],
			  ICE_MAX_NUM_RECIPES);
		bitmap_and(possible_idx, possible_idx,
			   hw->switch_info->prof_res_bm[bit],
			   ICE_MAX_FV_WORDS);
	}

	/* For each recipe that our new recipe may collide with, determine
	 * which indexes have been used.
	 */
	for_each_set_bit(bit, recipes, ICE_MAX_NUM_RECIPES)
		bitmap_or(used_idx, used_idx,
			  hw->switch_info->recp_list[bit].res_idxs,
			  ICE_MAX_FV_WORDS);

	bitmap_xor(free_idx, used_idx, possible_idx, ICE_MAX_FV_WORDS);

	/* return number of free indexes */
	return (u16)bitmap_weight(free_idx, ICE_MAX_FV_WORDS);
}

static void ice_set_recipe_index(unsigned long idx, u8 *bitmap)
{
	u32 byte = idx / BITS_PER_BYTE;
	u32 bit = idx % BITS_PER_BYTE;

	if (byte >= 8)
		return;

	bitmap[byte] |= 1 << bit;
}

/**
 * ice_add_sw_recipe - function to call AQ calls to create switch recipe
 * @hw: pointer to hardware structure
 * @rm: recipe management list entry
 * @profiles: bitmap of profiles that will be associated.
 */
static int
ice_add_sw_recipe(struct ice_hw *hw, struct ice_sw_recipe *rm,
		  unsigned long *profiles)
{
	DECLARE_BITMAP(result_idx_bm, ICE_MAX_FV_WORDS);
	struct ice_aqc_recipe_data_elem *tmp;
	struct ice_aqc_recipe_data_elem *buf;
	struct ice_recp_grp_entry *entry;
	u16 free_res_idx;
	u16 recipe_count;
	u8 chain_idx;
	u8 recps = 0;
	int status;

	/* When more than one recipe are required, another recipe is needed to
	 * chain them together. Matching a tunnel metadata ID takes up one of
	 * the match fields in the chaining recipe reducing the number of
	 * chained recipes by one.
	 */
	 /* check number of free result indices */
	bitmap_zero(result_idx_bm, ICE_MAX_FV_WORDS);
	free_res_idx = ice_find_free_recp_res_idx(hw, profiles, result_idx_bm);

	ice_debug(hw, ICE_DBG_SW, "Result idx slots: %d, need %d\n",
		  free_res_idx, rm->n_grp_count);

	if (rm->n_grp_count > 1) {
		if (rm->n_grp_count > free_res_idx)
			return -ENOSPC;

		rm->n_grp_count++;
	}

	if (rm->n_grp_count > ICE_MAX_CHAIN_RECIPE)
		return -ENOSPC;

	tmp = devm_kcalloc(ice_hw_to_dev(hw), ICE_MAX_NUM_RECIPES,
			   sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	buf = devm_kcalloc(ice_hw_to_dev(hw), rm->n_grp_count, sizeof(*buf),
			   GFP_KERNEL);
	if (!buf) {
		status = -ENOMEM;
		goto err_mem;
	}

	bitmap_zero(rm->r_bitmap, ICE_MAX_NUM_RECIPES);
	recipe_count = ICE_MAX_NUM_RECIPES;
	status = ice_aq_get_recipe(hw, tmp, &recipe_count, ICE_SW_LKUP_MAC,
				   NULL);
	if (status || recipe_count == 0)
		goto err_unroll;

	/* Allocate the recipe resources, and configure them according to the
	 * match fields from protocol headers and extracted field vectors.
	 */
	chain_idx = (u8)find_first_bit(result_idx_bm, ICE_MAX_FV_WORDS);
	list_for_each_entry(entry, &rm->rg_list, l_entry) {
		u8 i;

		status = ice_alloc_recipe(hw, &entry->rid);
		if (status)
			goto err_unroll;

		/* Clear the result index of the located recipe, as this will be
		 * updated, if needed, later in the recipe creation process.
		 */
		tmp[0].content.result_indx = 0;

		buf[recps] = tmp[0];
		buf[recps].recipe_indx = (u8)entry->rid;
		/* if the recipe is a non-root recipe RID should be programmed
		 * as 0 for the rules to be applied correctly.
		 */
		buf[recps].content.rid = 0;
		memset(&buf[recps].content.lkup_indx, 0,
		       sizeof(buf[recps].content.lkup_indx));

		/* All recipes use look-up index 0 to match switch ID. */
		buf[recps].content.lkup_indx[0] = ICE_AQ_SW_ID_LKUP_IDX;
		buf[recps].content.mask[0] =
			cpu_to_le16(ICE_AQ_SW_ID_LKUP_MASK);
		/* Setup lkup_indx 1..4 to INVALID/ignore and set the mask
		 * to be 0
		 */
		for (i = 1; i <= ICE_NUM_WORDS_RECIPE; i++) {
			buf[recps].content.lkup_indx[i] = 0x80;
			buf[recps].content.mask[i] = 0;
		}

		for (i = 0; i < entry->r_group.n_val_pairs; i++) {
			buf[recps].content.lkup_indx[i + 1] =
				(u8)entry->fv_idx[i];
			buf[recps].content.mask[i + 1] =
				cpu_to_le16(entry->fv_mask[i]);
		}

		if (rm->n_grp_count > 1) {
			/* Checks to see if there really is a valid result index
			 * that can be used.
			 */
			if (chain_idx >= ICE_MAX_FV_WORDS) {
				ice_debug(hw, ICE_DBG_SW, "No chain index available\n");
				status = -ENOSPC;
				goto err_unroll;
			}

			entry->chain_idx = chain_idx;
			buf[recps].content.result_indx =
				ICE_AQ_RECIPE_RESULT_EN |
				((chain_idx << ICE_AQ_RECIPE_RESULT_DATA_S) &
				 ICE_AQ_RECIPE_RESULT_DATA_M);
			clear_bit(chain_idx, result_idx_bm);
			chain_idx = (u8)find_first_bit(result_idx_bm,
						       ICE_MAX_FV_WORDS);
		}

		/* fill recipe dependencies */
		memset(buf[recps].recipe_bitmap, 0,
		       sizeof(buf[recps].recipe_bitmap));
		ice_set_recipe_index(buf[recps].recipe_indx,
				     buf[recps].recipe_bitmap);
		buf[recps].content.act_ctrl_fwd_priority = rm->priority;
		recps++;
	}

	if (rm->n_grp_count == 1) {
		rm->root_rid = buf[0].recipe_indx;
		set_bit(buf[0].recipe_indx, rm->r_bitmap);
		buf[0].content.rid = rm->root_rid | ICE_AQ_RECIPE_ID_IS_ROOT;
		if (sizeof(buf[0].recipe_bitmap) >= sizeof(rm->r_bitmap)) {
			memcpy(buf[0].recipe_bitmap, rm->r_bitmap,
			       sizeof(buf[0].recipe_bitmap));
		} else {
			status = -EINVAL;
			goto err_unroll;
		}
		/* Applicable only for ROOT_RECIPE, set the fwd_priority for
		 * the recipe which is getting created if specified
		 * by user. Usually any advanced switch filter, which results
		 * into new extraction sequence, ended up creating a new recipe
		 * of type ROOT and usually recipes are associated with profiles
		 * Switch rule referreing newly created recipe, needs to have
		 * either/or 'fwd' or 'join' priority, otherwise switch rule
		 * evaluation will not happen correctly. In other words, if
		 * switch rule to be evaluated on priority basis, then recipe
		 * needs to have priority, otherwise it will be evaluated last.
		 */
		buf[0].content.act_ctrl_fwd_priority = rm->priority;
	} else {
		struct ice_recp_grp_entry *last_chain_entry;
		u16 rid, i;

		/* Allocate the last recipe that will chain the outcomes of the
		 * other recipes together
		 */
		status = ice_alloc_recipe(hw, &rid);
		if (status)
			goto err_unroll;

		buf[recps].recipe_indx = (u8)rid;
		buf[recps].content.rid = (u8)rid;
		buf[recps].content.rid |= ICE_AQ_RECIPE_ID_IS_ROOT;
		/* the new entry created should also be part of rg_list to
		 * make sure we have complete recipe
		 */
		last_chain_entry = devm_kzalloc(ice_hw_to_dev(hw),
						sizeof(*last_chain_entry),
						GFP_KERNEL);
		if (!last_chain_entry) {
			status = -ENOMEM;
			goto err_unroll;
		}
		last_chain_entry->rid = rid;
		memset(&buf[recps].content.lkup_indx, 0,
		       sizeof(buf[recps].content.lkup_indx));
		/* All recipes use look-up index 0 to match switch ID. */
		buf[recps].content.lkup_indx[0] = ICE_AQ_SW_ID_LKUP_IDX;
		buf[recps].content.mask[0] =
			cpu_to_le16(ICE_AQ_SW_ID_LKUP_MASK);
		for (i = 1; i <= ICE_NUM_WORDS_RECIPE; i++) {
			buf[recps].content.lkup_indx[i] =
				ICE_AQ_RECIPE_LKUP_IGNORE;
			buf[recps].content.mask[i] = 0;
		}

		i = 1;
		/* update r_bitmap with the recp that is used for chaining */
		set_bit(rid, rm->r_bitmap);
		/* this is the recipe that chains all the other recipes so it
		 * should not have a chaining ID to indicate the same
		 */
		last_chain_entry->chain_idx = ICE_INVAL_CHAIN_IND;
		list_for_each_entry(entry, &rm->rg_list, l_entry) {
			buf[recps].content.lkup_indx[i] = entry->chain_idx;
			buf[recps].content.mask[i++] = cpu_to_le16(0xFFFF);
			set_bit(entry->rid, rm->r_bitmap);
		}
		list_add(&last_chain_entry->l_entry, &rm->rg_list);
		if (sizeof(buf[recps].recipe_bitmap) >=
		    sizeof(rm->r_bitmap)) {
			memcpy(buf[recps].recipe_bitmap, rm->r_bitmap,
			       sizeof(buf[recps].recipe_bitmap));
		} else {
			status = -EINVAL;
			goto err_unroll;
		}
		buf[recps].content.act_ctrl_fwd_priority = rm->priority;

		recps++;
		rm->root_rid = (u8)rid;
	}
	status = ice_acquire_change_lock(hw, ICE_RES_WRITE);
	if (status)
		goto err_unroll;

	status = ice_aq_add_recipe(hw, buf, rm->n_grp_count, NULL);
	ice_release_change_lock(hw);
	if (status)
		goto err_unroll;

	/* Every recipe that just got created add it to the recipe
	 * book keeping list
	 */
	list_for_each_entry(entry, &rm->rg_list, l_entry) {
		struct ice_switch_info *sw = hw->switch_info;
		bool is_root, idx_found = false;
		struct ice_sw_recipe *recp;
		u16 idx, buf_idx = 0;

		/* find buffer index for copying some data */
		for (idx = 0; idx < rm->n_grp_count; idx++)
			if (buf[idx].recipe_indx == entry->rid) {
				buf_idx = idx;
				idx_found = true;
			}

		if (!idx_found) {
			status = -EIO;
			goto err_unroll;
		}

		recp = &sw->recp_list[entry->rid];
		is_root = (rm->root_rid == entry->rid);
		recp->is_root = is_root;

		recp->root_rid = (u8)entry->rid;
		recp->big_recp = (is_root && rm->n_grp_count > 1);

		memcpy(&recp->ext_words, entry->r_group.pairs,
		       entry->r_group.n_val_pairs * sizeof(struct ice_fv_word));

		memcpy(recp->r_bitmap, buf[buf_idx].recipe_bitmap,
		       sizeof(recp->r_bitmap));

		/* Copy non-result fv index values and masks to recipe. This
		 * call will also update the result recipe bitmask.
		 */
		ice_collect_result_idx(&buf[buf_idx], recp);

		/* for non-root recipes, also copy to the root, this allows
		 * easier matching of a complete chained recipe
		 */
		if (!is_root)
			ice_collect_result_idx(&buf[buf_idx],
					       &sw->recp_list[rm->root_rid]);

		recp->n_ext_words = entry->r_group.n_val_pairs;
		recp->chain_idx = entry->chain_idx;
		recp->priority = buf[buf_idx].content.act_ctrl_fwd_priority;
		recp->n_grp_count = rm->n_grp_count;
		recp->tun_type = rm->tun_type;
		recp->recp_created = true;
	}
	rm->root_buf = buf;
	devm_kfree(ice_hw_to_dev(hw), tmp);
	return status;

err_unroll:
err_mem:
	devm_kfree(ice_hw_to_dev(hw), tmp);
	devm_kfree(ice_hw_to_dev(hw), buf);
	return status;
}

/**
 * ice_create_recipe_group - creates recipe group
 * @hw: pointer to hardware structure
 * @rm: recipe management list entry
 * @lkup_exts: lookup elements
 */
static int
ice_create_recipe_group(struct ice_hw *hw, struct ice_sw_recipe *rm,
			struct ice_prot_lkup_ext *lkup_exts)
{
	u8 recp_count = 0;
	int status;

	rm->n_grp_count = 0;

	/* Create recipes for words that are marked not done by packing them
	 * as best fit.
	 */
	status = ice_create_first_fit_recp_def(hw, lkup_exts,
					       &rm->rg_list, &recp_count);
	if (!status) {
		rm->n_grp_count += recp_count;
		rm->n_ext_words = lkup_exts->n_val_words;
		memcpy(&rm->ext_words, lkup_exts->fv_words,
		       sizeof(rm->ext_words));
		memcpy(rm->word_masks, lkup_exts->field_mask,
		       sizeof(rm->word_masks));
	}

	return status;
}

/**
 * ice_tun_type_match_word - determine if tun type needs a match mask
 * @rinfo: other information regarding the rule e.g. priority and action info
 * @off: offset of packet flag
 * @mask: mask to be used for the tunnel
 */
static bool
ice_tun_type_match_word(struct ice_adv_rule_info *rinfo, u16 *off, u16 *mask)
{
	switch (rinfo->tun_type) {
	case ICE_SW_TUN_VXLAN_GPE:
	case ICE_SW_TUN_GENEVE:
	case ICE_SW_TUN_VXLAN:
	case ICE_SW_TUN_NVGRE:
	case ICE_SW_TUN_UDP:
	case ICE_ALL_TUNNELS:
	case ICE_SW_TUN_GTPU:
	case ICE_SW_TUN_GTPC:
		*mask = ICE_TUN_FLAG_MASK;
		*off = ICE_TUN_FLAG_MDID_OFF(1);
		return true;

	case ICE_SW_TUN_AND_NON_TUN:
		if (rinfo->add_dir_lkup) {
			*mask = ICE_DIR_FLAG_MASK;
			*off = ICE_TUN_FLAG_MDID_OFF(0);
			return true;
		}
		*mask = 0;
		*off = 0;
		return false;

	case ICE_SW_TUN_GENEVE_VLAN:
	case ICE_SW_TUN_VXLAN_VLAN:
		*mask = ICE_TUN_FLAG_MASK & ~(ICE_TUN_FLAG_VLAN_MASK |
			ICE_TUN_FLAG_IN_VLAN_MASK);
		*off = ICE_TUN_FLAG_MDID_OFF(1);
		return true;

	default:
		*mask = 0;
		*off = 0;
		return false;
	}
}

/**
 * ice_add_special_words - Add words that are not protocols, such as metadata
 * @rinfo: other information regarding the rule e.g. priority and action info
 * @lkup_exts: lookup word structure
 * @dvm_ena: is double VLAN mode enabled
 */
static int
ice_add_special_words(struct ice_adv_rule_info *rinfo,
		      struct ice_prot_lkup_ext *lkup_exts, bool dvm_ena)
{
	u16 mask;
	u16 off;

	/* Always add direction flag */
	if (lkup_exts->n_val_words < ICE_MAX_CHAIN_WORDS) {
		u8 word = lkup_exts->n_val_words++;

		lkup_exts->fv_words[word].prot_id = ICE_META_DATA_ID_HW;
		lkup_exts->fv_words[word].off = ICE_TUN_FLAG_MDID_OFF(0);
		lkup_exts->field_mask[word] = ICE_FROM_NETWORK_FLAG_MASK;
	} else {
		return -ENOSPC;
	}

	/* If this is a tunneled packet, then add recipe index to match the
	 * tunnel bit in the packet metadata flags. If this is a tun_and_non_tun
	 * packet, then add recipe index to match the direction bit in the flag.
	 */
	if (ice_tun_type_match_word(rinfo, &off, &mask)) {
		if (lkup_exts->n_val_words < ICE_MAX_CHAIN_WORDS) {
			u8 word = lkup_exts->n_val_words++;

			lkup_exts->fv_words[word].prot_id = ICE_META_DATA_ID_HW;
			lkup_exts->fv_words[word].off = off;
			lkup_exts->field_mask[word] = mask;
		} else {
			return -ENOSPC;
		}
	}

	if (rinfo->vlan_type != 0 && dvm_ena) {
		if (lkup_exts->n_val_words < ICE_MAX_CHAIN_WORDS) {
			u8 word = lkup_exts->n_val_words++;

			lkup_exts->fv_words[word].prot_id = ICE_META_DATA_ID_HW;
			lkup_exts->fv_words[word].off = ICE_VLAN_FLAG_MDID_OFF;
			lkup_exts->field_mask[word] =
					ICE_PKT_FLAGS_0_TO_15_VLAN_FLAGS_MASK;
		} else {
			return -ENOSPC;
		}
	}

	return 0;
}

/* ice_get_compat_fv_bitmap - Get compatible field vector bitmap for rule
 * @hw: pointer to hardware structure
 * @rinfo: other information regarding the rule e.g. priority and action info
 * @bm: pointer to memory for returning the bitmap of field vectors
 */
static void
ice_get_compat_fv_bitmap(struct ice_hw *hw, struct ice_adv_rule_info *rinfo,
			 unsigned long *bm)
{
	enum ice_prof_type prof_type;

	bitmap_zero(bm, ICE_MAX_NUM_PROFILES);

	switch (rinfo->tun_type) {
	case ICE_NON_TUN:
		prof_type = ICE_PROF_NON_TUN;
		break;
	case ICE_ALL_TUNNELS:
		prof_type = ICE_PROF_TUN_ALL;
		break;
	case ICE_SW_TUN_VXLAN_GPE:
	case ICE_SW_TUN_GENEVE:
	case ICE_SW_TUN_GENEVE_VLAN:
	case ICE_SW_TUN_VXLAN:
	case ICE_SW_TUN_VXLAN_VLAN:
	case ICE_SW_TUN_UDP:
		prof_type = ICE_PROF_TUN_UDP;
		break;

	case ICE_SW_TUN_GTPU:
		prof_type = ICE_PROF_TUN_GTPU;
		break;
	case ICE_SW_TUN_GTPC:
		prof_type = ICE_PROF_TUN_GTPC;
		break;

	case ICE_SW_TUN_NVGRE:
		prof_type = ICE_PROF_TUN_GRE;
		break;
	case ICE_SW_IPV4_TCP:
		set_bit(ICE_PROFID_IPV4_TCP, bm);
		return;
	case ICE_SW_IPV4_UDP:
		set_bit(ICE_PROFID_IPV4_UDP, bm);
		return;
	case ICE_SW_IPV6_TCP:
		set_bit(ICE_PROFID_IPV6_TCP, bm);
		return;
	case ICE_SW_IPV6_UDP:
		set_bit(ICE_PROFID_IPV6_UDP, bm);
		return;
	case ICE_SW_TUN_AND_NON_TUN:
	default:
		prof_type = ICE_PROF_ALL;
		break;
	}

	ice_get_sw_fv_bitmap(hw, prof_type, bm);
}

/**
 * ice_add_adv_recipe - Add an advanced recipe that is not part of the default
 * @hw: pointer to hardware structure
 * @lkups: lookup elements or match criteria for the advanced recipe, one
 *  structure per protocol header
 * @lkups_cnt: number of protocols
 * @rinfo: other information regarding the rule e.g. priority and action info
 * @rid: return the recipe ID of the recipe created
 */
int
ice_add_adv_recipe(struct ice_hw *hw, struct ice_adv_lkup_elem *lkups,
		   u16 lkups_cnt, struct ice_adv_rule_info *rinfo, u16 *rid)
{
	DECLARE_BITMAP(fv_bitmap, ICE_MAX_NUM_PROFILES);
	DECLARE_BITMAP(profiles, ICE_MAX_NUM_PROFILES);
	struct ice_prot_lkup_ext *lkup_exts;
	struct ice_recp_grp_entry *r_entry;
	struct ice_sw_fv_list_entry *fvit;
	struct ice_recp_grp_entry *r_tmp;
	struct ice_sw_fv_list_entry *tmp;
	struct ice_sw_recipe *rm;
	int status = 0;
	u8 i;

	if (!lkups_cnt)
		return -EINVAL;

	lkup_exts = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*lkup_exts),
				 GFP_KERNEL);
	if (!lkup_exts)
		return -ENOMEM;

	/* Determine the number of words to be matched and if it exceeds a
	 * recipe's restrictions
	 */
	for (i = 0; i < lkups_cnt; i++) {
		u16 count;

		if (lkups[i].type >= ICE_PROTOCOL_LAST) {
			status = -EIO;
			goto err_free_lkup_exts;
		}

		count = ice_fill_valid_words(&lkups[i], lkup_exts);
		if (!count) {
			status = -EIO;
			goto err_free_lkup_exts;
		}
	}

	rm = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*rm), GFP_KERNEL);
	if (!rm) {
		status = -ENOMEM;
		goto err_free_lkup_exts;
	}

	/* Get field vectors that contain fields extracted from all the protocol
	 * headers being programmed.
	 */
	INIT_LIST_HEAD(&rm->fv_list);
	INIT_LIST_HEAD(&rm->rg_list);

	/* Get bitmap of field vectors (profiles) that are compatible with the
	 * rule request; only these will be searched in the subsequent call to
	 * ice_get_sw_fv_list.
	 */
	ice_get_compat_fv_bitmap(hw, rinfo, fv_bitmap);

	status = ice_get_sw_fv_list(hw, lkup_exts, fv_bitmap, &rm->fv_list);
	if (status)
		goto err_unroll;

	/* Create any special protocol/offset pairs, such as looking at tunnel
	 * bits by extracting metadata
	 */
	status = ice_add_special_words(rinfo, lkup_exts, ice_is_dvm_ena(hw));
	if (status)
		goto err_free_lkup_exts;

	/* Group match words into recipes using preferred recipe grouping
	 * criteria.
	 */
	status = ice_create_recipe_group(hw, rm, lkup_exts);
	if (status)
		goto err_unroll;

	/* set the recipe priority if specified */
	rm->priority = (u8)rinfo->priority;

	/* Find offsets from the field vector. Pick the first one for all the
	 * recipes.
	 */
	status = ice_fill_fv_word_index(hw, &rm->fv_list, &rm->rg_list);
	if (status)
		goto err_unroll;

	/* An empty FV list means to use all the profiles returned in the
	 * profile bitmap
	 */
	if (list_empty(&rm->fv_list)) {
		u16 j;

		for_each_set_bit(j, fv_bitmap, ICE_MAX_NUM_PROFILES) {
			struct ice_sw_fv_list_entry *fvl;

			fvl = devm_kzalloc(ice_hw_to_dev(hw), sizeof(*fvl),
					   GFP_KERNEL);
			if (!fvl)
				goto err_unroll;
			fvl->fv_ptr = NULL;
			fvl->profile_id = j;
			list_add(&fvl->list_entry, &rm->fv_list);
		}
	}

	/* get bitmap of all profiles the recipe will be associated with */
	bitmap_zero(profiles, ICE_MAX_NUM_PROFILES);
	list_for_each_entry(fvit, &rm->fv_list, list_entry) {
		ice_debug(hw, ICE_DBG_SW, "profile: %d\n", fvit->profile_id);
		set_bit((u16)fvit->profile_id, profiles);
	}

	/* Look for a recipe which matches our requested fv / mask list */
	*rid = ice_find_recp(hw, lkup_exts, rinfo->tun_type, rinfo->priority);
	if (*rid < ICE_MAX_NUM_RECIPES)
		/* Success if found a recipe that match the existing criteria */
		goto err_unroll;

	rm->tun_type = rinfo->tun_type;
	/* Recipe we need does not exist, add a recipe */
	status = ice_add_sw_recipe(hw, rm, profiles);
	if (status)
		goto err_unroll;

	/* Associate all the recipes created with all the profiles in the
	 * common field vector.
	 */
	list_for_each_entry(fvit, &rm->fv_list, list_entry) {
		DECLARE_BITMAP(r_bitmap, ICE_MAX_NUM_RECIPES);
		u16 j;

		status = ice_aq_get_recipe_to_profile(hw, fvit->profile_id,
						      (u8 *)r_bitmap, NULL);
		if (status)
			goto err_unroll;

		bitmap_or(r_bitmap, r_bitmap, rm->r_bitmap,
			  ICE_MAX_NUM_RECIPES);
		status = ice_acquire_change_lock(hw, ICE_RES_WRITE);
		if (status)
			goto err_unroll;

		status = ice_aq_map_recipe_to_profile(hw, fvit->profile_id,
						      (u8 *)r_bitmap,
						      NULL);
		ice_release_change_lock(hw);

		if (status)
			goto err_unroll;

		/* Update profile to recipe bitmap array */
		bitmap_copy(profile_to_recipe[fvit->profile_id], r_bitmap,
			    ICE_MAX_NUM_RECIPES);

		/* Update recipe to profile bitmap array */
		for_each_set_bit(j, rm->r_bitmap, ICE_MAX_NUM_RECIPES)
			set_bit((u16)fvit->profile_id, recipe_to_profile[j]);
	}

	*rid = rm->root_rid;
	memcpy(&hw->switch_info->recp_list[*rid].lkup_exts, lkup_exts,
	       sizeof(*lkup_exts));
err_unroll:
	list_for_each_entry_safe(r_entry, r_tmp, &rm->rg_list, l_entry) {
		list_del(&r_entry->l_entry);
		devm_kfree(ice_hw_to_dev(hw), r_entry);
	}

	list_for_each_entry_safe(fvit, tmp, &rm->fv_list, list_entry) {
		list_del(&fvit->list_entry);
		devm_kfree(ice_hw_to_dev(hw), fvit);
	}

	if (rm->root_buf)
		devm_kfree(ice_hw_to_dev(hw), rm->root_buf);

	devm_kfree(ice_hw_to_dev(hw), rm);

err_free_lkup_exts:
	devm_kfree(ice_hw_to_dev(hw), lkup_exts);

	return status;
}

/**
 * ice_find_dummy_packet - find dummy packet by tunnel type
 *
 * @lkups: lookup elements or match criteria for the advanced recipe, one
 *	   structure per protocol header
 * @lkups_cnt: number of protocols
 * @tun_type: tunnel type from the match criteria
 * @pkt: dummy packet to fill according to filter match criteria
 * @pkt_len: packet length of dummy packet
 * @offsets: pointer to receive the pointer to the offsets for the packet
 */
void
ice_find_dummy_packet(struct ice_adv_lkup_elem *lkups, u16 lkups_cnt,
		      enum ice_sw_tunnel_type tun_type, const u8 **pkt,
		      u16 *pkt_len,
		      const struct ice_dummy_pkt_offsets **offsets)
{
	bool tcp = false, udp = false, outer_ipv6 = false, vlan = false;
	bool inner_ipv6 = false, pppoe = false;
	bool gtp_no_pay = false, l2tpv3 = false;
	bool cvlan = false;
	u16 i;

	for (i = 0; i < lkups_cnt; i++) {
		if (lkups[i].type == ICE_UDP_ILOS)
			udp = true;
		else if (lkups[i].type == ICE_TCP_IL)
			tcp = true;
		else if (lkups[i].type == ICE_IPV6_OFOS)
			outer_ipv6 = true;
		else if (lkups[i].type == ICE_VLAN_OFOS ||
			 lkups[i].type == ICE_VLAN_EX)
			vlan = true;

		else if (lkups[i].type == ICE_VLAN_IN)
			cvlan = true;
		else if (lkups[i].type == ICE_ETYPE_OL &&
			 lkups[i].h_u.ethertype.ethtype_id ==
				cpu_to_be16(ICE_IPV6_ETHER_ID) &&
			 lkups[i].m_u.ethertype.ethtype_id ==
				cpu_to_be16(0xFFFF))
			outer_ipv6 = true;
		else if (lkups[i].type == ICE_ETYPE_IL &&
			 lkups[i].h_u.ethertype.ethtype_id ==
				cpu_to_be16(ICE_IPV6_ETHER_ID) &&
			 lkups[i].m_u.ethertype.ethtype_id ==
				cpu_to_be16(0xFFFF))
			inner_ipv6 = true;
		else if (lkups[i].type == ICE_PPPOE) {
			pppoe = true;
			if (lkups[i].h_u.pppoe_hdr.ppp_prot_id ==
				cpu_to_be16(ICE_PPP_IPV6_PROTO_ID) &&
			    lkups[i].m_u.pppoe_hdr.ppp_prot_id ==
				cpu_to_be16(0xFFFF))
				outer_ipv6 = true;
		}
		else if (lkups[i].type == ICE_IPV6_IL)
			inner_ipv6 = true;
		else if (lkups[i].type == ICE_GTP_NO_PAY)
			gtp_no_pay = true;
		else if (lkups[i].type == ICE_L2TPV3)
			l2tpv3 = true;
	}

	if (cvlan && vlan) {
		if (outer_ipv6) {
			if (tcp) {
				*pkt = dummy_qinq_ipv6_tcp_pkt;
				*pkt_len = sizeof(dummy_qinq_ipv6_tcp_pkt);
				*offsets = dummy_qinq_ipv6_tcp_packet_offsets;
				return;
			}

			if (udp) {
				*pkt = dummy_qinq_ipv6_udp_pkt;
				*pkt_len = sizeof(dummy_qinq_ipv6_udp_pkt);
				*offsets = dummy_qinq_ipv6_udp_packet_offsets;
				return;
			}

			*pkt = dummy_qinq_ipv6_pkt;
			*pkt_len = sizeof(dummy_qinq_ipv6_pkt);
			*offsets = dummy_qinq_ipv6_packet_offsets;
			return;
		} else  {
			if (tcp) {
				*pkt = dummy_qinq_ipv4_tcp_pkt;
				*pkt_len = sizeof(dummy_qinq_ipv4_tcp_pkt);
				*offsets = dummy_qinq_ipv4_tcp_packet_offsets;
				return;
			}

			if (udp) {
				*pkt = dummy_qinq_ipv4_udp_pkt;
				*pkt_len = sizeof(dummy_qinq_ipv4_udp_pkt);
				*offsets = dummy_qinq_ipv4_udp_packet_offsets;
				return;
			}

			*pkt = dummy_qinq_ipv4_pkt;
			*pkt_len = sizeof(dummy_qinq_ipv4_pkt);
			*offsets = dummy_qinq_ipv4_packet_offsets;
			return;
		}
	}

	if (tun_type == ICE_SW_IPV4_TCP) {
		*pkt = dummy_tcp_packet;
		*pkt_len = sizeof(dummy_tcp_packet);
		*offsets = dummy_tcp_packet_offsets;
		return;
	}

	if (tun_type == ICE_SW_IPV4_UDP) {
		*pkt = dummy_udp_packet;
		*pkt_len = sizeof(dummy_udp_packet);
		*offsets = dummy_udp_packet_offsets;
		return;
	}

	if (tun_type == ICE_SW_IPV6_TCP) {
		*pkt = dummy_tcp_ipv6_packet;
		*pkt_len = sizeof(dummy_tcp_ipv6_packet);
		*offsets = dummy_tcp_ipv6_packet_offsets;
		return;
	}

	if (tun_type == ICE_SW_IPV6_UDP) {
		*pkt = dummy_udp_ipv6_packet;
		*pkt_len = sizeof(dummy_udp_ipv6_packet);
		*offsets = dummy_udp_ipv6_packet_offsets;
		return;
	}

	if (tun_type == ICE_SW_TUN_GTPU) {
		if (outer_ipv6) {
			if (gtp_no_pay) {
				*pkt = dummy_ipv6_gtp_packet;
				*pkt_len = sizeof(dummy_ipv6_gtp_packet);
				*offsets = dummy_ipv6_gtp_no_pay_packet_offsets;
				return;
			}
			if (inner_ipv6 && udp) {
				*pkt = dummy_ipv6_gtpu_ipv6_udp_packet;
				*pkt_len =
					sizeof(dummy_ipv6_gtpu_ipv6_udp_packet);
				*offsets =
					dummy_ipv6_gtpu_ipv6_udp_packet_offsets;
				return;
			}
			if (inner_ipv6) {
				*pkt = dummy_ipv6_gtpu_ipv6_tcp_packet;
				*pkt_len =
					sizeof(dummy_ipv6_gtpu_ipv6_tcp_packet);
				*offsets =
					dummy_ipv6_gtpu_ipv6_tcp_packet_offsets;
				return;
			}
			if (udp) {
				*pkt = dummy_ipv6_gtpu_ipv4_udp_packet;
				*pkt_len =
					sizeof(dummy_ipv6_gtpu_ipv4_udp_packet);
				*offsets =
					dummy_ipv6_gtpu_ipv4_udp_packet_offsets;
				return;
			}
			*pkt = dummy_ipv6_gtpu_ipv4_tcp_packet;
			*pkt_len = sizeof(dummy_ipv6_gtpu_ipv4_tcp_packet);
			*offsets = dummy_ipv6_gtpu_ipv4_tcp_packet_offsets;
			return;
		}
		if (gtp_no_pay) {
			*pkt = dummy_ipv4_gtpu_ipv4_packet;
			*pkt_len = sizeof(dummy_ipv4_gtpu_ipv4_packet);
			*offsets = dummy_ipv4_gtp_no_pay_packet_offsets;
			return;
		}
		if (inner_ipv6 && udp) {
			*pkt = dummy_ipv4_gtpu_ipv6_udp_packet;
			*pkt_len = sizeof(dummy_ipv4_gtpu_ipv6_udp_packet);
			*offsets = dummy_ipv4_gtpu_ipv6_udp_packet_offsets;
			return;
		}
		if (inner_ipv6) {
			*pkt = dummy_ipv4_gtpu_ipv6_tcp_packet;
			*pkt_len = sizeof(dummy_ipv4_gtpu_ipv6_tcp_packet);
			*offsets = dummy_ipv4_gtpu_ipv6_tcp_packet_offsets;
			return;
		}
		if (udp) {
			*pkt = dummy_ipv4_gtpu_ipv4_udp_packet;
			*pkt_len = sizeof(dummy_ipv4_gtpu_ipv4_udp_packet);
			*offsets = dummy_ipv4_gtpu_ipv4_udp_packet_offsets;
			return;
		}
		*pkt = dummy_ipv4_gtpu_ipv4_tcp_packet;
		*pkt_len = sizeof(dummy_ipv4_gtpu_ipv4_tcp_packet);
		*offsets = dummy_ipv4_gtpu_ipv4_tcp_packet_offsets;
		return;
	}

	if (tun_type == ICE_SW_TUN_GTPC) {
		if (outer_ipv6) {
			*pkt = dummy_ipv6_gtp_packet;
			*pkt_len = sizeof(dummy_ipv6_gtp_packet);
			*offsets = dummy_ipv6_gtp_no_pay_packet_offsets;
			return;
		}
		*pkt = dummy_ipv4_gtpu_ipv4_packet;
		*pkt_len = sizeof(dummy_ipv4_gtpu_ipv4_packet);
		*offsets = dummy_ipv4_gtp_no_pay_packet_offsets;
		return;
	}

	if (tun_type == ICE_ALL_TUNNELS) {
		*pkt = dummy_gre_udp_packet;
		*pkt_len = sizeof(dummy_gre_udp_packet);
		*offsets = dummy_gre_udp_packet_offsets;
		return;
	}

	if (tun_type == ICE_SW_TUN_NVGRE) {
		if (tcp && inner_ipv6) {
			*pkt = dummy_gre_ipv6_tcp_packet;
			*pkt_len = sizeof(dummy_gre_ipv6_tcp_packet);
			*offsets = dummy_gre_ipv6_tcp_packet_offsets;
			return;
		}

		if (tcp) {
			*pkt = dummy_gre_tcp_packet;
			*pkt_len = sizeof(dummy_gre_tcp_packet);
			*offsets = dummy_gre_tcp_packet_offsets;
			return;
		}

		if (inner_ipv6) {
			*pkt = dummy_gre_ipv6_udp_packet;
			*pkt_len = sizeof(dummy_gre_ipv6_udp_packet);
			*offsets = dummy_gre_ipv6_udp_packet_offsets;
			return;
		}

		*pkt = dummy_gre_udp_packet;
		*pkt_len = sizeof(dummy_gre_udp_packet);
		*offsets = dummy_gre_udp_packet_offsets;
		return;
	}

	if (tun_type == ICE_SW_TUN_VXLAN || tun_type == ICE_SW_TUN_GENEVE ||
	    tun_type == ICE_SW_TUN_VXLAN_GPE || tun_type == ICE_SW_TUN_UDP ||
	    tun_type == ICE_SW_TUN_GENEVE_VLAN ||
	    tun_type == ICE_SW_TUN_VXLAN_VLAN) {
		if (tcp && inner_ipv6) {
			*pkt = dummy_udp_tun_ipv6_tcp_packet;
			*pkt_len = sizeof(dummy_udp_tun_ipv6_tcp_packet);
			*offsets = dummy_udp_tun_ipv6_tcp_packet_offsets;
			return;
		}

		if (tcp) {
			*pkt = dummy_udp_tun_tcp_packet;
			*pkt_len = sizeof(dummy_udp_tun_tcp_packet);
			*offsets = dummy_udp_tun_tcp_packet_offsets;
			return;
		}

		if (inner_ipv6) {
			*pkt = dummy_udp_tun_ipv6_udp_packet;
			*pkt_len = sizeof(dummy_udp_tun_ipv6_udp_packet);
			*offsets = dummy_udp_tun_ipv6_udp_packet_offsets;
			return;
		}

		*pkt = dummy_udp_tun_udp_packet;
		*pkt_len = sizeof(dummy_udp_tun_udp_packet);
		*offsets = dummy_udp_tun_udp_packet_offsets;
		return;
	}

	if (udp && !outer_ipv6) {
		if (vlan) {
			*pkt = dummy_vlan_udp_packet;
			*pkt_len = sizeof(dummy_vlan_udp_packet);
			*offsets = dummy_vlan_udp_packet_offsets;
			return;
		} else if (pppoe) {
			*pkt = dummy_pppoe_ipv4_udp_packet;
			*pkt_len = sizeof(dummy_pppoe_ipv4_udp_packet);
			*offsets = dummy_pppoe_ipv4_udp_packet_offsets;
			return;
		}
		*pkt = dummy_udp_packet;
		*pkt_len = sizeof(dummy_udp_packet);
		*offsets = dummy_udp_packet_offsets;
		return;
	} else if (udp && outer_ipv6) {
		if (vlan) {
			*pkt = dummy_vlan_udp_ipv6_packet;
			*pkt_len = sizeof(dummy_vlan_udp_ipv6_packet);
			*offsets = dummy_vlan_udp_ipv6_packet_offsets;
			return;
		} else if (pppoe) {
			*pkt = dummy_pppoe_ipv6_udp_packet;
			*pkt_len = sizeof(dummy_pppoe_ipv6_udp_packet);
			*offsets = dummy_pppoe_ipv6_udp_packet_offsets;
			return;
		}
		*pkt = dummy_udp_ipv6_packet;
		*pkt_len = sizeof(dummy_udp_ipv6_packet);
		*offsets = dummy_udp_ipv6_packet_offsets;
		return;
	} else if ((tcp && outer_ipv6) || outer_ipv6) {
		if (vlan) {
			*pkt = dummy_vlan_tcp_ipv6_packet;
			*pkt_len = sizeof(dummy_vlan_tcp_ipv6_packet);
			*offsets = dummy_vlan_tcp_ipv6_packet_offsets;
			return;
		} else if (pppoe) {
			*pkt = dummy_pppoe_ipv6_tcp_packet;
			*pkt_len = sizeof(dummy_pppoe_ipv6_tcp_packet);
			*offsets = dummy_pppoe_ipv6_tcp_packet_offsets;
			return;
		} else if (l2tpv3) {
			*pkt = dummy_ipv6_l2tpv3_pkt;
			*pkt_len = sizeof(dummy_ipv6_l2tpv3_pkt);
			*offsets = dummy_ipv6_l2tpv3_packet_offsets;
			return;
		}
		*pkt = dummy_tcp_ipv6_packet;
		*pkt_len = sizeof(dummy_tcp_ipv6_packet);
		*offsets = dummy_tcp_ipv6_packet_offsets;
		return;
	}

	if (vlan) {
		*pkt = dummy_vlan_tcp_packet;
		*pkt_len = sizeof(dummy_vlan_tcp_packet);
		*offsets = dummy_vlan_tcp_packet_offsets;
	} else if (pppoe) {
		*pkt = dummy_pppoe_ipv4_tcp_packet;
		*pkt_len = sizeof(dummy_pppoe_ipv4_tcp_packet);
		*offsets = dummy_pppoe_ipv4_tcp_packet_offsets;
		return;
	} else if (l2tpv3) {
		*pkt = dummy_ipv4_l2tpv3_pkt;
		*pkt_len = sizeof(dummy_ipv4_l2tpv3_pkt);
		*offsets = dummy_ipv4_l2tpv3_packet_offsets;
		return;
	} else {
		*pkt = dummy_tcp_packet;
		*pkt_len = sizeof(dummy_tcp_packet);
		*offsets = dummy_tcp_packet_offsets;
	}
}

/**
 * ice_fill_adv_dummy_packet - fill a dummy packet with given match criteria
 *
 * @lkups: lookup elements or match criteria for the advanced recipe, one
 *	   structure per protocol header
 * @lkups_cnt: number of protocols
 * @s_rule: stores rule information from the match criteria
 * @dummy_pkt: dummy packet to fill according to filter match criteria
 * @pkt_len: packet length of dummy packet
 * @offsets: offset info for the dummy packet
 */
int
ice_fill_adv_dummy_packet(struct ice_adv_lkup_elem *lkups, u16 lkups_cnt,
			  struct ice_sw_rule_lkup_rx_tx *s_rule,
			  const u8 *dummy_pkt, u16 pkt_len,
			  const struct ice_dummy_pkt_offsets *offsets)
{
	u8 *pkt;
	u16 i;

	/* Start with a packet with a pre-defined/dummy content. Then, fill
	 * in the header values to be looked up or matched.
	 */
	pkt = s_rule->hdr_data;

	memcpy(pkt, dummy_pkt, pkt_len);

	for (i = 0; i < lkups_cnt; i++) {
		enum ice_protocol_type type;
		u16 offset = 0, len = 0, j;
		bool found = false;

		/* find the start of this layer; it should be found since this
		 * was already checked when search for the dummy packet
		 */
		type = lkups[i].type;
		for (j = 0; offsets[j].type != ICE_PROTOCOL_LAST; j++) {
			if (type == offsets[j].type) {
				offset = offsets[j].offset;
				found = true;
				break;
			}
		}
		/* this should never happen in a correct calling sequence */
		if (!found)
			return -EINVAL;

		switch (lkups[i].type) {
		case ICE_MAC_OFOS:
		case ICE_MAC_IL:
			len = sizeof(struct ice_ether_hdr);
			break;
		case ICE_ETYPE_OL:
		case ICE_ETYPE_IL:
			len = sizeof(struct ice_ethtype_hdr);
			break;
		case ICE_VLAN_OFOS:
		case ICE_VLAN_EX:
		case ICE_VLAN_IN:
			len = sizeof(struct ice_vlan_hdr);
			break;
		case ICE_IPV4_OFOS:
		case ICE_IPV4_IL:
			len = sizeof(struct ice_ipv4_hdr);
			break;
		case ICE_IPV6_OFOS:
		case ICE_IPV6_IL:
			len = sizeof(struct ice_ipv6_hdr);
			break;
		case ICE_TCP_IL:
		case ICE_UDP_OF:
		case ICE_UDP_ILOS:
			len = sizeof(struct ice_l4_hdr);
			break;
		case ICE_SCTP_IL:
			len = sizeof(struct ice_sctp_hdr);
			break;
		case ICE_NVGRE:
			len = sizeof(struct ice_nvgre);
			break;
		case ICE_VXLAN:
		case ICE_GENEVE:
		case ICE_VXLAN_GPE:
			len = sizeof(struct ice_udp_tnl_hdr);
			break;

		case ICE_GTP_NO_PAY:
		case ICE_GTP:
			len = sizeof(struct ice_udp_gtp_hdr);
			break;
		case ICE_PPPOE:
			len = sizeof(struct ice_pppoe_hdr);
			break;
		case ICE_L2TPV3:
			len = sizeof(struct ice_l2tpv3_sess_hdr);
			break;
		default:
			return -EINVAL;
		}

		/* the length should be a word multiple */
		if (len % ICE_BYTES_PER_WORD)
			return -EIO;

		/* We have the offset to the header start, the length, the
		 * caller's header values and mask. Use this information to
		 * copy the data into the dummy packet appropriately based on
		 * the mask. Note that we need to only write the bits as
		 * indicated by the mask to make sure we don't improperly write
		 * over any significant packet data.
		 */
		for (j = 0; j < len / sizeof(u16); j++)
#ifdef __CHECKER__
			/* cppcheck-suppress objectIndex */
#endif /* __CHECKER__ */
			if (((u16 *)&lkups[i].m_u)[j])
				((u16 *)(pkt + offset))[j] =
					(((u16 *)(pkt + offset))[j] &
#ifdef __CHECKER__
					 /* cppcheck-suppress objectIndex */
#endif /* __CHECKER__ */
					 ~((u16 *)&lkups[i].m_u)[j]) |
#ifdef __CHECKER__
					/* cppcheck-suppress objectIndex */
#endif /* __CHECKER__ */
					(((u16 *)&lkups[i].h_u)[j] &
#ifdef __CHECKER__
					 /* cppcheck-suppress objectIndex */
#endif /* __CHECKER__ */
					 ((u16 *)&lkups[i].m_u)[j]);
	}

	s_rule->hdr_len = cpu_to_le16(pkt_len);

	return 0;
}

/**
 * ice_fill_adv_packet_tun - fill dummy packet with udp tunnel port
 * @hw: pointer to the hardware structure
 * @tun_type: tunnel type
 * @pkt: dummy packet to fill in
 * @offsets: offset info for the dummy packet
 */
static int
ice_fill_adv_packet_tun(struct ice_hw *hw, enum ice_sw_tunnel_type tun_type,
			u8 *pkt, const struct ice_dummy_pkt_offsets *offsets)
{
	u16 open_port, i;

	switch (tun_type) {
	case ICE_SW_TUN_AND_NON_TUN:
	case ICE_SW_TUN_VXLAN_GPE:
	case ICE_SW_TUN_VXLAN:
	case ICE_SW_TUN_VXLAN_VLAN:
	case ICE_SW_TUN_UDP:
		if (!ice_get_open_tunnel_port(hw, TNL_VXLAN, &open_port))
			return -EIO;
		break;
	case ICE_SW_TUN_GENEVE:
	case ICE_SW_TUN_GENEVE_VLAN:
		if (!ice_get_open_tunnel_port(hw, TNL_GENEVE, &open_port))
			return -EIO;
		break;
	default:
		/* Nothing needs to be done for this tunnel type */
		return 0;
	}

	/* Find the outer UDP protocol header and insert the port number */
	for (i = 0; offsets[i].type != ICE_PROTOCOL_LAST; i++) {
		if (offsets[i].type == ICE_UDP_OF) {
			struct ice_l4_hdr *hdr;
			u16 offset;

			offset = offsets[i].offset;
			hdr = (struct ice_l4_hdr *)&pkt[offset];
			hdr->dst_port = cpu_to_be16(open_port);

			return 0;
		}
	}

	return -EIO;
}

/**
 * ice_fill_adv_packet_vlan - fill dummy packet with VLAN tag type
 * @vlan_type: VLAN tag type
 * @pkt: dummy packet to fill in
 * @offsets: offset info for the dummy packet
 */
static int
ice_fill_adv_packet_vlan(u16 vlan_type, u8 *pkt,
			 const struct ice_dummy_pkt_offsets *offsets)
{
	u16 i;

	/* Find VLAN header and insert VLAN TPID */
	for (i = 0; offsets[i].type != ICE_PROTOCOL_LAST; i++) {
		if (offsets[i].type == ICE_VLAN_OFOS ||
		    offsets[i].type == ICE_VLAN_EX) {
			struct ice_vlan_hdr *hdr;
			u16 offset;

			offset = offsets[i].offset;
			hdr = (struct ice_vlan_hdr *)&pkt[offset];
			hdr->type = cpu_to_be16(vlan_type);

			return 0;
		}
	}

	return -EIO;
}

/**
 * ice_find_adv_rule_entry - Search a rule entry
 * @hw: pointer to the hardware structure
 * @lkups: lookup elements or match criteria for the advanced recipe, one
 *	   structure per protocol header
 * @lkups_cnt: number of protocols
 * @recp_id: recipe ID for which we are finding the rule
 * @rinfo: other information regarding the rule e.g. priority and action info
 *
 * Helper function to search for a given advance rule entry
 * Returns pointer to entry storing the rule if found
 */
struct ice_adv_fltr_mgmt_list_entry *
ice_find_adv_rule_entry(struct ice_hw *hw, struct ice_adv_lkup_elem *lkups,
			u16 lkups_cnt, u16 recp_id,
			struct ice_adv_rule_info *rinfo)
{
	struct ice_adv_fltr_mgmt_list_entry *list_itr;
	struct ice_switch_info *sw = hw->switch_info;
	int i;

	list_for_each_entry(list_itr, &sw->recp_list[recp_id].filt_rules,
			    list_entry) {
		bool lkups_matched = true;

		if (lkups_cnt != list_itr->lkups_cnt)
			continue;
		for (i = 0; i < list_itr->lkups_cnt; i++)
			if (memcmp(&list_itr->lkups[i], &lkups[i],
				   sizeof(*lkups))) {
				lkups_matched = false;
				break;
			}
		if (rinfo->sw_act.flag == list_itr->rule_info.sw_act.flag &&
		    rinfo->tun_type == list_itr->rule_info.tun_type &&
		    rinfo->vlan_type == list_itr->rule_info.vlan_type &&
		    lkups_matched)
			return list_itr;
	}
	return NULL;
}

/**
 * ice_adv_add_update_vsi_list
 * @hw: pointer to the hardware structure
 * @m_entry: pointer to current adv filter management list entry
 * @cur_fltr: filter information from the book keeping entry
 * @new_fltr: filter information with the new VSI to be added
 *
 * Call AQ command to add or update previously created VSI list with new VSI.
 *
 * Helper function to do book keeping associated with adding filter information
 * The algorithm to do the booking keeping is described below :
 * When a VSI needs to subscribe to a given advanced filter
 *	if only one VSI has been added till now
 *		Allocate a new VSI list and add two VSIs
 *		to this list using switch rule command
 *		Update the previously created switch rule with the
 *		newly created VSI list ID
 *	if a VSI list was previously created
 *		Add the new VSI to the previously created VSI list set
 *		using the update switch rule command
 */
int
ice_adv_add_update_vsi_list(struct ice_hw *hw,
			    struct ice_adv_fltr_mgmt_list_entry *m_entry,
			    struct ice_adv_rule_info *cur_fltr,
			    struct ice_adv_rule_info *new_fltr)
{
	u16 vsi_list_id = 0;
	int status;

	if (cur_fltr->sw_act.fltr_act == ICE_FWD_TO_Q ||
	    cur_fltr->sw_act.fltr_act == ICE_FWD_TO_QGRP ||
	    cur_fltr->sw_act.fltr_act == ICE_DROP_PACKET)
		return -EOPNOTSUPP;

	if ((new_fltr->sw_act.fltr_act == ICE_FWD_TO_Q ||
	     new_fltr->sw_act.fltr_act == ICE_FWD_TO_QGRP) &&
	    (cur_fltr->sw_act.fltr_act == ICE_FWD_TO_VSI ||
	     cur_fltr->sw_act.fltr_act == ICE_FWD_TO_VSI_LIST))
		return -EOPNOTSUPP;

	if (m_entry->vsi_count < 2 && !m_entry->vsi_list_info) {
		 /* Only one entry existed in the mapping and it was not already
		  * a part of a VSI list. So, create a VSI list with the old and
		  * new VSIs.
		  */
		struct ice_fltr_info tmp_fltr;
		u16 vsi_handle_arr[2];

		/* A rule already exists with the new VSI being added */
		if (cur_fltr->sw_act.fwd_id.hw_vsi_id ==
		    new_fltr->sw_act.fwd_id.hw_vsi_id)
			return -EEXIST;

		vsi_handle_arr[0] = cur_fltr->sw_act.vsi_handle;
		vsi_handle_arr[1] = new_fltr->sw_act.vsi_handle;
		status = ice_create_vsi_list_rule(hw, &vsi_handle_arr[0], 2,
						  &vsi_list_id,
						  ICE_SW_LKUP_LAST);
		if (status)
			return status;

		memset(&tmp_fltr, 0, sizeof(tmp_fltr));
		tmp_fltr.flag = m_entry->rule_info.sw_act.flag;
		tmp_fltr.fltr_rule_id = cur_fltr->fltr_rule_id;
		tmp_fltr.fltr_act = ICE_FWD_TO_VSI_LIST;
		tmp_fltr.fwd_id.vsi_list_id = vsi_list_id;
		tmp_fltr.lkup_type = ICE_SW_LKUP_LAST;

		/* Update the previous switch rule of "forward to VSI" to
		 * "fwd to VSI list"
		 */
		status = ice_update_pkt_fwd_rule(hw, &tmp_fltr);
		if (status)
			return status;

		cur_fltr->sw_act.fwd_id.vsi_list_id = vsi_list_id;
		cur_fltr->sw_act.fltr_act = ICE_FWD_TO_VSI_LIST;
		m_entry->vsi_list_info =
			ice_create_vsi_list_map(hw, &vsi_handle_arr[0], 2,
						vsi_list_id);
	} else {
		u16 vsi_handle = new_fltr->sw_act.vsi_handle;

		if (!m_entry->vsi_list_info)
			return -EIO;

		/* A rule already exists with the new VSI being added */
		if (test_bit(vsi_handle, m_entry->vsi_list_info->vsi_map))
			return -EEXIST;

		/* Update the previously created VSI list set with
		 * the new VSI ID passed in
		 */
		vsi_list_id = cur_fltr->sw_act.fwd_id.vsi_list_id;

		status = ice_update_vsi_list_rule(hw, &vsi_handle, 1,
						  vsi_list_id, false,
						  ice_aqc_opc_update_sw_rules,
						  ICE_SW_LKUP_LAST);
		/* update VSI list mapping info with new VSI ID */
		if (!status)
			set_bit(vsi_handle, m_entry->vsi_list_info->vsi_map);
	}
	if (!status)
		m_entry->vsi_count++;
	return status;
}

/**
 * ice_add_adv_rule - helper function to create an advanced switch rule
 * @hw: pointer to the hardware structure
 * @lkups: information on the words that needs to be looked up. All words
 * together makes one recipe
 * @lkups_cnt: num of entries in the lkups array
 * @rinfo: other information related to the rule that needs to be programmed
 * @added_entry: this will return recipe_id, rule_id and vsi_handle. should be
 *               ignored is case of error.
 *
 * This function can program only 1 rule at a time. The lkups is used to
 * describe the all the words that forms the "lookup" portion of the recipe.
 * These words can span multiple protocols. Callers to this function need to
 * pass in a list of protocol headers with lookup information along and mask
 * that determines which words are valid from the given protocol header.
 * rinfo describes other information related to this rule such as forwarding
 * IDs, priority of this rule, etc.
 */
int
ice_add_adv_rule(struct ice_hw *hw, struct ice_adv_lkup_elem *lkups,
		 u16 lkups_cnt, struct ice_adv_rule_info *rinfo,
		 struct ice_rule_query_data *added_entry)
{
	struct ice_adv_fltr_mgmt_list_entry *m_entry, *adv_fltr = NULL;
	u16 rid = 0, i, pkt_len, rule_buf_sz, vsi_handle;
	const struct ice_dummy_pkt_offsets *pkt_offsets;
	struct ice_sw_rule_lkup_rx_tx *s_rule = NULL;
	struct ice_sw_rule_lkup_rx_tx *rx_tx;
	struct list_head *rule_head;
	struct ice_switch_info *sw;
	const u8 *pkt = NULL;
	u16 num_rules = 1;
	u16 word_cnt;
	u32 act = 0;
	int status;
	u8 q_rgn;

	/* Initialize profile to result index bitmap */
	if (!hw->switch_info->prof_res_bm_init) {
		hw->switch_info->prof_res_bm_init = 1;
		ice_init_prof_result_bm(hw);
	}

	if (!lkups_cnt)
		return -EINVAL;

	/* get # of words we need to match */
	word_cnt = 0;
	for (i = 0; i < lkups_cnt; i++) {
		u16 j, *ptr;

		ptr = (u16 *)&lkups[i].m_u;
		for (j = 0; j < sizeof(lkups->m_u) / sizeof(u16); j++)
#ifdef __CHECKER__
			/* cppcheck-suppress objectIndex */
#endif /* __CHECKER__ */
			if (ptr[j] != 0)
				word_cnt++;
	}

	if (!word_cnt)
		return -EINVAL;

	if (word_cnt > ICE_MAX_CHAIN_WORDS)
		return -ENOSPC;

	/* make sure that we can locate a dummy packet */
	ice_find_dummy_packet(lkups, lkups_cnt, rinfo->tun_type, &pkt, &pkt_len,
			      &pkt_offsets);
	if (!pkt) {
		status = -EINVAL;
		goto err_ice_add_adv_rule;
	}

	if (!(rinfo->sw_act.fltr_act == ICE_FWD_TO_VSI ||
	      rinfo->sw_act.fltr_act == ICE_FWD_TO_Q ||
	      rinfo->sw_act.fltr_act == ICE_FWD_TO_QGRP ||
	      rinfo->sw_act.fltr_act == ICE_DROP_PACKET))
		return -EIO;

	vsi_handle = rinfo->sw_act.vsi_handle;
	if (!ice_is_vsi_valid(hw, vsi_handle))
		return -EINVAL;

	if (rinfo->sw_act.fltr_act == ICE_FWD_TO_VSI)
		rinfo->sw_act.fwd_id.hw_vsi_id =
			ice_get_hw_vsi_num(hw, vsi_handle);
	if (rinfo->sw_act.flag & ICE_FLTR_TX)
		rinfo->sw_act.src = ice_get_hw_vsi_num(hw, vsi_handle);

	status = ice_add_adv_recipe(hw, lkups, lkups_cnt, rinfo, &rid);
	if (status)
		return status;
	m_entry = ice_find_adv_rule_entry(hw, lkups, lkups_cnt, rid, rinfo);
	if (m_entry) {
		/* we have to add VSI to VSI_LIST and increment vsi_count.
		 * Also Update VSI list so that we can change forwarding rule
		 * if the rule already exists, we will check if it exists with
		 * same vsi_id, if not then add it to the VSI list if it already
		 * exists if not then create a VSI list and add the existing VSI
		 * ID and the new VSI ID to the list
		 * We will add that VSI to the list
		 */
		status = ice_adv_add_update_vsi_list(hw, m_entry,
						     &m_entry->rule_info,
						     rinfo);
		if (added_entry) {
			added_entry->rid = rid;
			added_entry->rule_id = m_entry->rule_info.fltr_rule_id;
			added_entry->vsi_handle = rinfo->sw_act.vsi_handle;
		}
		return status;
	}
	rule_buf_sz = struct_size(s_rule, hdr_data, 0) + pkt_len;
	s_rule = devm_kzalloc(ice_hw_to_dev(hw), rule_buf_sz, GFP_KERNEL);
	if (!s_rule)
		return -ENOMEM;
	if (!rinfo->flags_info.act_valid)
		act |= ICE_SINGLE_ACT_LAN_ENABLE;
	else
		act |= rinfo->flags_info.act & (ICE_SINGLE_ACT_LAN_ENABLE |
						ICE_SINGLE_ACT_LB_ENABLE);

	switch (rinfo->sw_act.fltr_act) {
	case ICE_FWD_TO_VSI:
		act |= (rinfo->sw_act.fwd_id.hw_vsi_id <<
			ICE_SINGLE_ACT_VSI_ID_S) & ICE_SINGLE_ACT_VSI_ID_M;
		act |= ICE_SINGLE_ACT_VSI_FORWARDING | ICE_SINGLE_ACT_VALID_BIT;
		break;
	case ICE_FWD_TO_Q:
		act |= ICE_SINGLE_ACT_TO_Q;
		act |= (rinfo->sw_act.fwd_id.q_id << ICE_SINGLE_ACT_Q_INDEX_S) &
		       ICE_SINGLE_ACT_Q_INDEX_M;
		break;
	case ICE_FWD_TO_QGRP:
		q_rgn = rinfo->sw_act.qgrp_size > 0 ?
			(u8)ilog2(rinfo->sw_act.qgrp_size) : 0;
		act |= ICE_SINGLE_ACT_TO_Q;
		act |= (rinfo->sw_act.fwd_id.q_id << ICE_SINGLE_ACT_Q_INDEX_S) &
		       ICE_SINGLE_ACT_Q_INDEX_M;
		act |= (q_rgn << ICE_SINGLE_ACT_Q_REGION_S) &
		       ICE_SINGLE_ACT_Q_REGION_M;
		break;
	case ICE_DROP_PACKET:
		act |= ICE_SINGLE_ACT_VSI_FORWARDING | ICE_SINGLE_ACT_DROP |
		       ICE_SINGLE_ACT_VALID_BIT;
		break;
	default:
		status = -EIO;
		goto err_ice_add_adv_rule;
	}

	/* Set the rule LOOKUP type based on caller specified 'Rx'
	 * instead of hardcoding it to be either LOOKUP_TX/RX
	 *
	 * for 'Rx' set the source to be the port number
	 * for 'Tx' set the source to be the source HW VSI number (determined
	 * by caller)
	 */
	if (rinfo->rx) {
		s_rule->hdr.type = cpu_to_le16(ICE_AQC_SW_RULES_T_LKUP_RX);
		s_rule->src = cpu_to_le16(hw->port_info->lport);
	} else {
		s_rule->hdr.type = cpu_to_le16(ICE_AQC_SW_RULES_T_LKUP_TX);
		s_rule->src = cpu_to_le16(rinfo->sw_act.src);
	}

	s_rule->recipe_id = cpu_to_le16(rid);
	s_rule->act = cpu_to_le32(act);

	status = ice_fill_adv_dummy_packet(lkups, lkups_cnt, s_rule, pkt,
					   pkt_len, pkt_offsets);
	if (status)
		goto err_ice_add_adv_rule;

	if (rinfo->tun_type != ICE_NON_TUN &&
	    rinfo->tun_type != ICE_SW_TUN_AND_NON_TUN) {
		status = ice_fill_adv_packet_tun(hw, rinfo->tun_type,
						 s_rule->hdr_data,
						 pkt_offsets);
		if (status)
			goto err_ice_add_adv_rule;
	}

	if (rinfo->vlan_type != 0 && ice_is_dvm_ena(hw)) {
		status = ice_fill_adv_packet_vlan(rinfo->vlan_type,
						  s_rule->hdr_data,
						  pkt_offsets);
		if (status)
			goto err_ice_add_adv_rule;
	}

	rx_tx = s_rule;

	status = ice_aq_sw_rules(hw, (struct ice_aqc_sw_rules *)s_rule,
				 rule_buf_sz, num_rules,
				 ice_aqc_opc_add_sw_rules, NULL);
	if (status)
		goto err_ice_add_adv_rule;
	adv_fltr = devm_kzalloc(ice_hw_to_dev(hw),
				sizeof(struct ice_adv_fltr_mgmt_list_entry),
				GFP_KERNEL);
	if (!adv_fltr) {
		status = -ENOMEM;
		goto err_ice_add_adv_rule;
	}

	adv_fltr->lkups = devm_kmemdup(ice_hw_to_dev(hw), lkups,
				       lkups_cnt * sizeof(*lkups), GFP_KERNEL);
	if (!adv_fltr->lkups) {
		status = -ENOMEM;
		goto err_ice_add_adv_rule;
	}

	adv_fltr->lkups_cnt = lkups_cnt;
	adv_fltr->rule_info = *rinfo;
	adv_fltr->rule_info.fltr_rule_id =
		le16_to_cpu(rx_tx->index);
	sw = hw->switch_info;
	sw->recp_list[rid].adv_rule = true;
	rule_head = &sw->recp_list[rid].filt_rules;

	if (rinfo->sw_act.fltr_act == ICE_FWD_TO_VSI)
		adv_fltr->vsi_count = 1;

	/* Add rule entry to book keeping list */
	list_add(&adv_fltr->list_entry, rule_head);
	if (added_entry) {
		added_entry->rid = rid;
		added_entry->rule_id = adv_fltr->rule_info.fltr_rule_id;
		added_entry->vsi_handle = rinfo->sw_act.vsi_handle;
	}
err_ice_add_adv_rule:
	if (status && adv_fltr) {
		devm_kfree(ice_hw_to_dev(hw), adv_fltr->lkups);
		devm_kfree(ice_hw_to_dev(hw), adv_fltr);
	}

	devm_kfree(ice_hw_to_dev(hw), s_rule);

	return status;
}

/**
 * ice_adv_rem_update_vsi_list
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle of the VSI to remove
 * @fm_list: filter management entry for which the VSI list management needs to
 *	     be done
 */
static int
ice_adv_rem_update_vsi_list(struct ice_hw *hw, u16 vsi_handle,
			    struct ice_adv_fltr_mgmt_list_entry *fm_list)
{
	struct ice_vsi_list_map_info *vsi_list_info;
	enum ice_sw_lkup_type lkup_type;
	u16 vsi_list_id;
	int status;

	if (fm_list->rule_info.sw_act.fltr_act != ICE_FWD_TO_VSI_LIST ||
	    fm_list->vsi_count == 0)
		return -EINVAL;

	/* A rule with the VSI being removed does not exist */
	if (!test_bit(vsi_handle, fm_list->vsi_list_info->vsi_map))
		return -ENOENT;

	lkup_type = ICE_SW_LKUP_LAST;
	vsi_list_id = fm_list->rule_info.sw_act.fwd_id.vsi_list_id;
	status = ice_update_vsi_list_rule(hw, &vsi_handle, 1, vsi_list_id, true,
					  ice_aqc_opc_update_sw_rules,
					  lkup_type);
	if (status)
		return status;

	fm_list->vsi_count--;
	clear_bit(vsi_handle, fm_list->vsi_list_info->vsi_map);
	vsi_list_info = fm_list->vsi_list_info;
	if (fm_list->vsi_count == 1) {
		struct ice_fltr_info tmp_fltr;
		u16 rem_vsi_handle;

		rem_vsi_handle = find_first_bit(vsi_list_info->vsi_map,
						ICE_MAX_VSI);
		if (!ice_is_vsi_valid(hw, rem_vsi_handle))
			return -EIO;

		/* Make sure VSI list is empty before removing it below */
		status = ice_update_vsi_list_rule(hw, &rem_vsi_handle, 1,
						  vsi_list_id, true,
						  ice_aqc_opc_update_sw_rules,
						  lkup_type);
		if (status)
			return status;

		memset(&tmp_fltr, 0, sizeof(tmp_fltr));
		tmp_fltr.flag = fm_list->rule_info.sw_act.flag;
		tmp_fltr.fltr_rule_id = fm_list->rule_info.fltr_rule_id;
		fm_list->rule_info.sw_act.fltr_act = ICE_FWD_TO_VSI;
		tmp_fltr.fltr_act = ICE_FWD_TO_VSI;
		tmp_fltr.fwd_id.hw_vsi_id =
			ice_get_hw_vsi_num(hw, rem_vsi_handle);
		fm_list->rule_info.sw_act.fwd_id.hw_vsi_id =
			ice_get_hw_vsi_num(hw, rem_vsi_handle);
		fm_list->rule_info.sw_act.vsi_handle = rem_vsi_handle;

		/* Update the previous switch rule of "MAC forward to VSI" to
		 * "MAC fwd to VSI list"
		 */
		status = ice_update_pkt_fwd_rule(hw, &tmp_fltr);
		if (status) {
			ice_debug(hw, ICE_DBG_SW, "Failed to update pkt fwd rule to FWD_TO_VSI on HW VSI %d, error %d\n",
				  tmp_fltr.fwd_id.hw_vsi_id, status);
			return status;
		}
		fm_list->vsi_list_info->ref_cnt--;

		/* Remove the VSI list since it is no longer used */
		status = ice_remove_vsi_list_rule(hw, vsi_list_id, lkup_type);
		if (status) {
			ice_debug(hw, ICE_DBG_SW, "Failed to remove VSI list %d, error %d\n",
				  vsi_list_id, status);
			return status;
		}

		list_del(&vsi_list_info->list_entry);
		devm_kfree(ice_hw_to_dev(hw), vsi_list_info);
		fm_list->vsi_list_info = NULL;
	}

	return status;
}

/**
 * ice_rem_adv_rule - removes existing advanced switch rule
 * @hw: pointer to the hardware structure
 * @lkups: information on the words that needs to be looked up. All words
 *         together makes one recipe
 * @lkups_cnt: num of entries in the lkups array
 * @rinfo: Its the pointer to the rule information for the rule
 *
 * This function can be used to remove 1 rule at a time. The lkups is
 * used to describe all the words that forms the "lookup" portion of the
 * rule. These words can span multiple protocols. Callers to this function
 * need to pass in a list of protocol headers with lookup information along
 * and mask that determines which words are valid from the given protocol
 * header. rinfo describes other information related to this rule such as
 * forwarding IDs, priority of this rule, etc.
 */
int
ice_rem_adv_rule(struct ice_hw *hw, struct ice_adv_lkup_elem *lkups,
		 u16 lkups_cnt, struct ice_adv_rule_info *rinfo)
{
	struct ice_adv_fltr_mgmt_list_entry *list_elem;
	struct ice_prot_lkup_ext lkup_exts;
	bool remove_rule = false;
	struct mutex *rule_lock; /* Lock to protect filter rule list */
	u16 i, rid, vsi_handle;
	int status = 0;

	memset(&lkup_exts, 0, sizeof(lkup_exts));
	for (i = 0; i < lkups_cnt; i++) {
		u16 count;

		if (lkups[i].type >= ICE_PROTOCOL_LAST)
			return -EIO;

		count = ice_fill_valid_words(&lkups[i], &lkup_exts);
		if (!count)
			return -EIO;
	}

	/* Create any special protocol/offset pairs, such as looking at tunnel
	 * bits by extracting metadata
	 */
	status = ice_add_special_words(rinfo, &lkup_exts, ice_is_dvm_ena(hw));
	if (status)
		return status;

	rid = ice_find_recp(hw, &lkup_exts, rinfo->tun_type, rinfo->priority);
	/* If did not find a recipe that match the existing criteria */
	if (rid == ICE_MAX_NUM_RECIPES)
		return -EINVAL;

	rule_lock = &hw->switch_info->recp_list[rid].filt_rule_lock;
	list_elem = ice_find_adv_rule_entry(hw, lkups, lkups_cnt, rid, rinfo);
	/* the rule is already removed */
	if (!list_elem)
		return 0;
	mutex_lock(rule_lock);
	if (list_elem->rule_info.sw_act.fltr_act != ICE_FWD_TO_VSI_LIST) {
		remove_rule = true;
	} else if (list_elem->vsi_count > 1) {
		remove_rule = false;
		vsi_handle = rinfo->sw_act.vsi_handle;
		status = ice_adv_rem_update_vsi_list(hw, vsi_handle, list_elem);
	} else {
		vsi_handle = rinfo->sw_act.vsi_handle;
		status = ice_adv_rem_update_vsi_list(hw, vsi_handle, list_elem);
		if (status) {
			mutex_unlock(rule_lock);
			return status;
		}
		if (list_elem->vsi_count == 0)
			remove_rule = true;
	}
	mutex_unlock(rule_lock);
	if (remove_rule) {
		struct ice_sw_rule_lkup_rx_tx *s_rule;
		u16 rule_buf_sz;

		rule_buf_sz = struct_size(s_rule, hdr_data, 0);
		s_rule = devm_kzalloc(ice_hw_to_dev(hw), rule_buf_sz,
				      GFP_KERNEL);
		if (!s_rule)
			return -ENOMEM;
		s_rule->act = 0;
		s_rule->index = cpu_to_le16(list_elem->rule_info.fltr_rule_id);
		s_rule->hdr_len = 0;
		status = ice_aq_sw_rules(hw, s_rule, rule_buf_sz, 1,
					 ice_aqc_opc_remove_sw_rules, NULL);
		if (!status || status == -ENOENT) {
			struct ice_switch_info *sw = hw->switch_info;

			mutex_lock(rule_lock);
			list_del(&list_elem->list_entry);
			devm_kfree(ice_hw_to_dev(hw), list_elem->lkups);
			devm_kfree(ice_hw_to_dev(hw), list_elem);
			mutex_unlock(rule_lock);
			if (list_empty(&sw->recp_list[rid].filt_rules))
				sw->recp_list[rid].adv_rule = false;
		}
		devm_kfree(ice_hw_to_dev(hw), s_rule);
	}
	return status;
}

/**
 * ice_rem_adv_rule_by_id - removes existing advanced switch rule by ID
 * @hw: pointer to the hardware structure
 * @remove_entry: data struct which holds rule_id, VSI handle and recipe ID
 *
 * This function is used to remove 1 rule at a time. The removal is based on
 * the remove_entry parameter. This function will remove rule for a given
 * vsi_handle with a given rule_id which is passed as parameter in remove_entry
 */
int
ice_rem_adv_rule_by_id(struct ice_hw *hw,
		       struct ice_rule_query_data *remove_entry)
{
	struct ice_adv_fltr_mgmt_list_entry *list_itr;
	struct list_head *list_head;
	struct ice_adv_rule_info rinfo;
	struct ice_switch_info *sw;

	sw = hw->switch_info;
	if (!sw->recp_list[remove_entry->rid].recp_created)
		return -EINVAL;
	list_head = &sw->recp_list[remove_entry->rid].filt_rules;
	list_for_each_entry(list_itr, list_head, list_entry) {
		if (list_itr->rule_info.fltr_rule_id ==
		    remove_entry->rule_id) {
			rinfo = list_itr->rule_info;
			rinfo.sw_act.vsi_handle = remove_entry->vsi_handle;
			return ice_rem_adv_rule(hw, list_itr->lkups,
						list_itr->lkups_cnt, &rinfo);
		}
	}
	/* either list is empty or unable to find rule */
	return -ENOENT;
}

/**
 * ice_rem_adv_rule_for_vsi - removes existing advanced switch rules for a
 *                            given VSI handle
 * @hw: pointer to the hardware structure
 * @vsi_handle: VSI handle for which we are supposed to remove all the rules.
 *
 * This function is used to remove all the rules for a given VSI and as soon
 * as removing a rule fails, it will return immediately with the error code,
 * else it will return success.
 */
int ice_rem_adv_rule_for_vsi(struct ice_hw *hw, u16 vsi_handle)
{
	struct ice_adv_fltr_mgmt_list_entry *list_itr, *tmp_entry;
	struct ice_vsi_list_map_info *map_info;
	struct ice_adv_rule_info rinfo;
	struct list_head *list_head;
	struct ice_switch_info *sw;
	int status;
	u8 rid;

	sw = hw->switch_info;
	for (rid = 0; rid < ICE_MAX_NUM_RECIPES; rid++) {
		if (!sw->recp_list[rid].recp_created)
			continue;
		if (!sw->recp_list[rid].adv_rule)
			continue;

		list_head = &sw->recp_list[rid].filt_rules;
		list_for_each_entry_safe(list_itr, tmp_entry, list_head,
					 list_entry) {
			rinfo = list_itr->rule_info;

			if (rinfo.sw_act.fltr_act == ICE_FWD_TO_VSI_LIST) {
				map_info = list_itr->vsi_list_info;
				if (!map_info)
					continue;

				if (!test_bit(vsi_handle, map_info->vsi_map))
					continue;
			} else if (rinfo.sw_act.vsi_handle != vsi_handle) {
				continue;
			}

			rinfo.sw_act.vsi_handle = vsi_handle;
			status = ice_rem_adv_rule(hw, list_itr->lkups,
						  list_itr->lkups_cnt, &rinfo);
			if (status)
				return status;
		}
	}
	return 0;
}

/**
 * ice_replay_vsi_fltr - Replay filters for requested VSI
 * @hw: pointer to the hardware structure
 * @pi: pointer to port information structure
 * @sw: pointer to switch info struct for which function replays filters
 * @vsi_handle: driver VSI handle
 * @recp_id: Recipe ID for which rules need to be replayed
 * @list_head: list for which filters need to be replayed
 *
 * Replays the filter of recipe recp_id for a VSI represented via vsi_handle.
 * It is required to pass valid VSI handle.
 */
static int
ice_replay_vsi_fltr(struct ice_hw *hw, struct ice_port_info *pi,
		    struct ice_switch_info *sw, u16 vsi_handle, u8 recp_id,
		    struct list_head *list_head)
{
	struct ice_fltr_mgmt_list_entry *itr;
	struct ice_sw_recipe *recp_list;
	int status = 0;
	u16 hw_vsi_id;

	if (list_empty(list_head))
		return status;
	recp_list = &sw->recp_list[recp_id];
	hw_vsi_id = ice_get_hw_vsi_num(hw, vsi_handle);

	list_for_each_entry(itr, list_head, list_entry) {
		struct ice_fltr_list_entry f_entry;

		f_entry.fltr_info = itr->fltr_info;
		if (itr->vsi_count < 2 && recp_id != ICE_SW_LKUP_VLAN &&
		    itr->fltr_info.vsi_handle == vsi_handle) {
			/* update the src in case it is VSI num */
			if (f_entry.fltr_info.src_id == ICE_SRC_ID_VSI)
				f_entry.fltr_info.src = hw_vsi_id;
			status = ice_add_rule_internal(hw, recp_list,
						       pi->lport,
						       &f_entry);
			if (status)
				goto end;
			continue;
		}
		if (!itr->vsi_list_info ||
		    !test_bit(vsi_handle, itr->vsi_list_info->vsi_map))
			continue;
		/* Clearing it so that the logic can add it back */
		clear_bit(vsi_handle, itr->vsi_list_info->vsi_map);
		f_entry.fltr_info.vsi_handle = vsi_handle;
		f_entry.fltr_info.fltr_act = ICE_FWD_TO_VSI;
		/* update the src in case it is VSI num */
		if (f_entry.fltr_info.src_id == ICE_SRC_ID_VSI)
			f_entry.fltr_info.src = hw_vsi_id;
		if (recp_id == ICE_SW_LKUP_VLAN)
			status = ice_add_vlan_internal(hw, recp_list, &f_entry);
		else
			status = ice_add_rule_internal(hw, recp_list,
						       pi->lport,
						       &f_entry);
		if (status)
			goto end;
	}
end:
	return status;
}

/**
 * ice_replay_vsi_adv_rule - Replay advanced rule for requested VSI
 * @hw: pointer to the hardware structure
 * @vsi_handle: driver VSI handle
 * @list_head: list for which filters need to be replayed
 *
 * Replay the advanced rule for the given VSI.
 */
static int
ice_replay_vsi_adv_rule(struct ice_hw *hw, u16 vsi_handle,
			struct list_head *list_head)
{
	struct ice_rule_query_data added_entry = { 0 };
	struct ice_adv_fltr_mgmt_list_entry *adv_fltr;
	int status = 0;

	if (list_empty(list_head))
		return status;
	list_for_each_entry(adv_fltr, list_head, list_entry) {
		struct ice_adv_rule_info *rinfo = &adv_fltr->rule_info;
		u16 lk_cnt = adv_fltr->lkups_cnt;

		if (vsi_handle != rinfo->sw_act.vsi_handle)
			continue;
		status = ice_add_adv_rule(hw, adv_fltr->lkups, lk_cnt, rinfo,
					  &added_entry);
		if (status)
			break;
	}
	return status;
}

/**
 * ice_replay_vsi_all_fltr - replay all filters stored in bookkeeping lists
 * @hw: pointer to the hardware structure
 * @pi: pointer to port information structure
 * @vsi_handle: driver VSI handle
 *
 * Replays filters for requested VSI via vsi_handle.
 */
int
ice_replay_vsi_all_fltr(struct ice_hw *hw, struct ice_port_info *pi,
			u16 vsi_handle)
{
	struct ice_switch_info *sw = NULL;
	int status;
	u8 i;

	sw = hw->switch_info;

	/* Update the recipes that were created */
	for (i = 0; i < ICE_MAX_NUM_RECIPES; i++) {
		struct list_head *head;

		head = &sw->recp_list[i].filt_replay_rules;
		if (!sw->recp_list[i].adv_rule)
			status = ice_replay_vsi_fltr(hw, pi, sw, vsi_handle, i,
						     head);
		else
			status = ice_replay_vsi_adv_rule(hw, vsi_handle, head);
		if (status)
			return status;
	}

	return 0;
}

/**
 * ice_rm_sw_replay_rule_info - helper function to delete filter replay rules
 * @hw: pointer to the HW struct
 * @sw: pointer to switch info struct for which function removes filters
 *
 * Deletes the filter replay rules for given switch
 */
void ice_rm_sw_replay_rule_info(struct ice_hw *hw, struct ice_switch_info *sw)
{
	u8 i;

	if (!sw)
		return;

	for (i = 0; i < ICE_MAX_NUM_RECIPES; i++) {
		if (!list_empty(&sw->recp_list[i].filt_replay_rules)) {
			struct list_head *l_head;

			l_head = &sw->recp_list[i].filt_replay_rules;
			if (!sw->recp_list[i].adv_rule)
				ice_rem_sw_rule_info(hw, l_head);
			else
				ice_rem_adv_rule_info(hw, l_head);
		}
	}
}

/**
 * ice_rm_all_sw_replay_rule_info - deletes filter replay rules
 * @hw: pointer to the HW struct
 *
 * Deletes the filter replay rules.
 */
void ice_rm_all_sw_replay_rule_info(struct ice_hw *hw)
{
	ice_rm_sw_replay_rule_info(hw, hw->switch_info);
}

