/*
 *
 * (C) 2017-18 - ntop.org
 *
 *  http://www.ntop.org/
 *
 * This code is proprietary code subject to the terms and conditions
 * defined in LICENSE file which is part of this source code package.
 *
 */

#ifndef RRC_LIB
#define RRC_LIB

/**                                                                                                          
 * @file rrc.h                                                                                               
 *                                                                                                           
 * @brief      RRC library header file (low-level API to configure the switch).                              
 */ 

//#define DEBUG

#include "nbpf.h"

#define MAX_NUM_PORTS  10
#define MAX_NUM_RULES  0x7FFFFFFF
#define MAX_NUM_USER_RULES (MAX_NUM_RULES-2)

#define DEFAULT_RULE_ID    (MAX_NUM_RULES-2)
#define INIT_RULE_ID       (MAX_NUM_RULES-1)

/* 
 * RRC switch port numbers are 1,2,3,4
 * 
 *       (host)
 *
 *      3       4   PEP (internal) ports
 *   ___|_______|___
 *  |               |
 *  |               |
 *  |      RRC      |
 *  |     Switch    |
 *  |               |
 *  |___ _______ ___|
 *      |       |
 *      1       2   EPL (external) Ethernet ports
 *
 *      (network)
 */

#define RRC_INIT_FLAG_PORTMASK (0 << 1) /* Set destination port mask (this is not compatible with redirection rules) */

typedef enum {
  PERMIT = 0, /* EGRESS_TRAFFIC only */
  DENY,       /* INGRESS_TRAFFIC (recommended) or EGRESS_TRAFFIC */
  REDIRECT    /* INGRESS_TRAFFIC only */
} rrc_policy_t;

typedef enum {
  EGRESS_TRAFFIC = 0, /* filter traffic leaving the port */
  INGRESS_TRAFFIC      /* steer traffic entering the port to another port */
} rrc_filter_type_t;

/* backward compatibility */
#define EGRESS_TRAFFIC_FILTERING EGRESS_TRAFFIC
#define INGRESS_TRAFFIC_STEERING INGRESS_TRAFFIC

typedef struct {
  u_int64_t packets;
  u_int64_t bytes;
} __attribute__((packed))
rrc_stats_t;

/* NOTE: all the fields of the structs reported here are in network byte order */

typedef union {
  u_int8_t   u6_addr8[16];
  u_int16_t  u6_addr16[8];
  u_int32_t  u6_addr32[4];
} __attribute__((packed))
rrc_in6_addr_t;

typedef union {
  rrc_in6_addr_t v6;           /* an IPv6 address */
  u_int32_t v4;                   /* an IPv4 address */
} __attribute__((packed))
rrc_ip_addr_t;

typedef struct {
  rrc_ip_addr_t host;          /* The network address part */
  rrc_ip_addr_t mask;          /* The network mask */
  u_int8_t ip_version;            /* the IP address version, 4 or 6 */
} __attribute__((packed))
rrc_network_t;

typedef struct {
  u_int16_t low;                  /* the low port number of a port range */
  u_int16_t high;                 /* the high port number of a port range, if suported */
} __attribute__((packed))
rrc_port_range_t;

typedef struct {
  u_int8_t smac[6];               /* source MAC */
  u_int8_t dmac[6];               /* destination MAC */
  u_int8_t proto;                 /* L3 protocol */
  u_int8_t __padding;
  u_int16_t vlan_id;              /* VLAN id */
  rrc_network_t shost;         /* source host or network, Ipv4 or Ipv6 */
  rrc_network_t dhost;         /* destination host or network, Ipv4 or Ipv6 */
  rrc_port_range_t sport;      /* L3 source port */
  rrc_port_range_t dport;      /* L3 destination port */
} __attribute__((packed))
rrc_match_t;

typedef struct rrc_port rrc_port_t;

/**
 * Initialise the card switch
 * @param flags See RRC_INIT_FLAG_* defines
 * @return 0 on success, -1 otherwise
 */
int rrc_init(u_int32_t flags);

/**
 * Get the port handle
 * @param portNumber The port number (usually 1 or 2 in case of INGRESS_TRAFFIC, 3 or 4 in case of EGRESS_TRAFFIC) 
 * @return           The port handler on success, NULL otherwise
 */
rrc_port_t *rrc_port_get(int portNumber);

/**
 * Sets the default policy
 * @param port               The port handler
 * @param type               The rule type: EGRESS_TRAFFIC or INGRESS_TRAFFIC
 * @param action             The action in case of match (PERMIT/DENY for EGRESS_TRAFFIC, REDIRECT for INGRESS_TRAFFIC)
 * @param redirectPortNumber The destination port in case of action = REDIRECT
 * @return                   0 on success, -1 otherwise
 */
int rrc_add_default_rule(rrc_port_t *port, rrc_filter_type_t type, rrc_policy_t action, int redirectPortNumber);

/**
 * Add a rule. Fields are in network byte order.
 * Please note a rule is identified by <port, ruleNumber, type>.
 * @param port               The port handler
 * @param ruleNumber         The rule number (0..2147483645), -1 for auto
 * @param type               The rule type: EGRESS_TRAFFIC or INGRESS_TRAFFIC
 * @param rule               The RRC rule
 * @param action             The action in case of match
 * @param redirectPortNumber The destination port in case of action = REDIRECT
 * @return                   The rule number on success, -1 otherwise
 */
int rrc_add_rule(rrc_port_t *port, int ruleNumber, rrc_filter_type_t type, rrc_match_t *rule, rrc_policy_t action, int redirectPortNumber);

/**
 * Converts a nBPF rule into a RRC rule. nBPF fields are in network byte order.
 * Please note a rule is identified by <port, ruleNumber, type>.
 * @param port               The port handler
 * @param ruleNumber         The rule number (0..2147483645), -1 for auto
 * @param type               The rule type: EGRESS_TRAFFIC or INGRESS_TRAFFIC
 * @param nBPFRule           The nBPF rule to convert
 * @param action             The action in case of match
 * @param redirectPortNumber The destination port in case of action = REDIRECT
 * @return                   The rule number on success, -1 otherwise
 */
int rrc_add_nbpf_rule(rrc_port_t *port, int ruleNumber, rrc_filter_type_t type, nbpf_rule_core_fields_t *nBPFRule, rrc_policy_t action, int redirectPortNumber);

/**
 * Removes a rule.
 * Please note a rule is identified by <port, ruleNumber, type>.
 * @param port       The port handler
 * @param ruleNumber The rule number
 * @param type       The rule type: EGRESS_TRAFFIC or INGRESS_TRAFFIC
 * @return           0 on success, -1 otherwise
 */
int rrc_remove_rule(rrc_port_t *port, int ruleNumber, rrc_filter_type_t type);

/**
 * Removes all rules for a <port, type>, including the default rule.
 * @param port       The port handler
 * @param type       The rule type: EGRESS_TRAFFIC or INGRESS_TRAFFIC
 * @return           0 on success, -1 otherwise
 */
int rrc_remove_all_rules(rrc_port_t *port, rrc_filter_type_t type);

/**
 * Read rule stats (packets matched).
 * Please note a rule is identified by <port, ruleNumber, type>.
 * Please note rules with type EGRESS_TRAFFIC do not support match counters, a good practice is 
 * to use DENY rules on INGRESS_TRAFFIC rather then EGRESS_TRAFFIC.
 * @param port       The port handler
 * @param ruleNumber The rule number
 * @param type       The rule type: INGRESS_TRAFFIC only (EGRESS_TRAFFIC does not support rule stats)
 * @param stats      The rule stats (out). 
 * @return           0 on success, -1 otherwise
 */
int rrc_read_rule_stats(rrc_port_t *port, int ruleNumber, rrc_filter_type_t type, rrc_stats_t *stats);

/**
 * Egress port stats (packets dropped by ACLs).
 * @param port       The port handler
 * @param stats      The port stats (out). 
 * @return           0 on success, -1 otherwise
 */
int rrc_read_port_stats(rrc_port_t *port, rrc_stats_t *stats);

/**
 * Applies all changes to a port
 * @return 0 on success, -1 otherwise
 */
int rrc_port_apply(rrc_port_t *port, rrc_filter_type_t type);

/**
 * Applies all changes
 * @return 0 on success, -1 otherwise
 */
int rrc_apply();

/**
 * Creates a mirror sending traffic from in_port to out_port.
 * Setting two mirrors with the same source port does not work
 * Setting two mirrors with the same destination port is not supported
 * @param in_port  The source port
 * @param out_port The destination port
 * @param rule     The RRC rule to match (optional)
 * @return 0 on success, -1 otherwise
 */
int rrc_add_mirror(rrc_port_t *in_port, rrc_port_t *out_port, rrc_match_t *rule);

/**
 * Removes mirror specifying the out_port.
 * @return 0 on success, -1 otherwise
 */
int rrc_remove_mirror(rrc_port_t *out_port);

/**
 * Sets a load balancer, for traffic matching the specified rule, with the specified destination ports.
 * @param out_ports     The destination ports
 * @param num_out_ports The number of destination ports
 * @param rule          The RRC rule to match
 * @return 0 on success, -1 otherwise
 */
int rrc_set_load_balancer(rrc_port_t *out_ports, int num_out_ports, rrc_match_t *r);

/**
 * Returns the physical PEP port number bound to the interface
 * @param ifname The interface name
 * @return       The port number on success, -1 otherwise
 */
int rrc_ifname_to_phys_port(const char *ifname);

/**
 * Returns the physical EPL port bound to the provided PEP port
 * @param internal_phys_port The physical PEP port number
 * @return                   The EPL port number on success, -1 otherwise
 */
int rrc_get_external_phys_port(int internal_phys_port);

/**
 * Returns the physical PEP port bound to the provided EPL port
 * @param external_phys_port The physical EPL port number
 * @return                   The PEP port number on success, -1 otherwise
 */
int rrc_get_internal_phys_port(int external_phys_port);

/**
 * Prints all the rules on a <port, type> (only for debugging)
 */
void rrc_dump_rules(rrc_port_t *port, rrc_filter_type_t type);

/**
 * Sets the verbosity level for logs
 */
void rrc_set_log_level(u_int8_t l);

/**
 * Sets the output file for logs (default is stdout)
 */
void rrc_set_log_file(FILE *f);

#endif /* RRC_LIB */

