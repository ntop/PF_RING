/*
 *  Copyright (C) 2016 ntop.org
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
#include <string.h>
#include <dirent.h>
#include <arpa/inet.h>

#include "fast_bpf.h"
#include "fast_bpf_mod_rdif.h"
#ifdef HAVE_REDIRECTOR_F

//#define DEBUG

#define MAX_NUM_RULES 512

typedef struct {
  unsigned int port1;
  unsigned int port2;
  unsigned int group_rules;
} rdif_interface_t;

static rdif_interface_t interface[MAX_INTERFACE] =
  {
    {
      1,  // port1
      3,  // port2
      1,  // group_rules
    },
    {
      2,  // port1
      4,  // port2
      2   // group_rules
    }
  };

/* Static functions */
static int __fast_bpf_rdif_set_port_inline(int unit, int port1, int port2);
static int __fast_bpf_rdif_interface_set_port_inline(fast_bpf_rdif_handle_t *handle);

static int __fast_bpf_rdif_init(fast_bpf_rdif_handle_t *handle);
static int __fast_bpf_rdif_init_for_rule(fast_bpf_rdif_handle_t *handle);
static int __fast_bpf_rdif_interface_set_ipv4_address(fast_bpf_rdif_handle_t *handle, unsigned int ipAddress, unsigned int isSrc);
static int __fast_bpf_rdif_interface_set_ipv6_address(fast_bpf_rdif_handle_t *handle, unsigned char* ipv6_addr, unsigned int isSrc);
static int __fast_bpf_rdif_interface_set_port(fast_bpf_rdif_handle_t *handle, unsigned int port, unsigned int isSrc);
static int __fast_bpf_rdif_interface_set_protocol(fast_bpf_rdif_handle_t *handle, unsigned int protocol);

static int __fast_bpf_rdif_interface_set_drop_action(fast_bpf_rdif_handle_t *handle);
static int __fast_bpf_rdif_interface_set_permit_action(fast_bpf_rdif_handle_t *handle);

static int __fast_bpf_rdif_add_rule(fast_bpf_rdif_handle_t *handle);
static int __fast_bpf_rdif_interface_set_drop_all(fast_bpf_rdif_handle_t *handle);

static int __fast_bpf_rdif_check_rules_constraints(fast_bpf_rdif_handle_t *handle, fast_bpf_tree_t *tree);
static void __fast_bpf_rdif_check_node_specific_constrains(fast_bpf_rdif_handle_t *handle, fast_bpf_node_t *n);
static int __fast_bpf_rdif_check_specific_constrains(fast_bpf_rdif_handle_t *handle, fast_bpf_tree_t *tree);
static int __fast_bpf_rdif_create_and_set_rules(fast_bpf_rdif_handle_t *handle, fast_bpf_rule_block_list_item_t *blockPun);
static int __fast_bpf_rdif_set_single_rule(fast_bpf_rdif_handle_t *handle, fast_bpf_rule_list_item_t *rule);
static int __fast_bpf_rdif_interface_clear(fast_bpf_rdif_handle_t *handle);

#ifdef DEBUG
static void __fast_bpf_rdif_call_print_tree(fast_bpf_tree_t *tree);
static void __fast_bpf_rdif_print_tree(fast_bpf_node_t *n);
#endif

/* ********************************************************************** */

static /* inline */ int is_empty_ipv6(unsigned char ipv6[16]);

static unsigned char  __empty_ipv6[16] = { 0 };

static /* inline */ int is_empty_ipv6(unsigned char ipv6[16]) {
  return memcmp(ipv6, __empty_ipv6, 16) == 0;
}

/* -------------------------------------------------- */

static int __fast_bpf_rdif_is_supported(char *interface) {
  char path[256];
  char line[512];
  FILE *fd;
  int rc = 0;

  sprintf(path, "/sys/class/net/%s/device/device", interface);

  fd = fopen(path, "r");

  if(fd == NULL)
    return 0;

  if(fgets(line, sizeof(line) - 1, fd)) {
    if(strncmp(line, "0x15a4", 6) == 0)
      rc = 1;
  }

  fclose(fd);
  return rc;
}

/* -------------------------------------------------- */

static int __fast_bpf_rdif_get_bus_id(char *interface) {
  const char *pci_slot_name_str = "PCI_SLOT_NAME=";
  char path[256];
  char line[512];
  FILE *fd;
  char *bus_id_ptr;
  short unsigned int bus_id = 0;

  sprintf(path, "/sys/class/net/%s/device/uevent", interface);

  fd = fopen(path, "r");

  if(fd == NULL)
    return -1;

  while(fgets(line, sizeof(line) - 1, fd)) {
    if(strncmp(line, pci_slot_name_str, strlen(pci_slot_name_str)) != 0)
      continue;

    /* PCI_SLOT_NAME=0000:04:00.0 */

    bus_id_ptr = &line[strlen(pci_slot_name_str) + 5];
    bus_id_ptr[2] = '\0';
    sscanf(bus_id_ptr, "%hX", &bus_id);

    break;
  }

  fclose(fd);

  return bus_id;
}

/* -------------------------------------------------- */

int __fast_bpf_rdif_get_interface_id(char *interface) {
  struct dirent **pent;
  int pnum, i, id = -1;
  int bus_id;

  if(!__fast_bpf_rdif_is_supported(interface))
    return -1;

  bus_id = __fast_bpf_rdif_get_bus_id(interface);

  if(bus_id < 0)
    return -1;

  pnum = scandir("/sys/class/net/", &pent, NULL, NULL);

  if(pnum <= 0)
    return -1;

  for (i = 0; i < pnum; i++) {
    if(id == -1) {
      if(!(pent[i]->d_name[0] == '.' ||
	   strcmp(pent[i]->d_name, "lo") == 0)) {
        if(__fast_bpf_rdif_is_supported(pent[i]->d_name)) {
          int other_bus_id = __fast_bpf_rdif_get_bus_id(interface);
          if(other_bus_id != -1) {
            if(other_bus_id > bus_id) id = 0;
            else id = 1;
          }
        }
      }
    }
    free(pent[i]);
  }
  free(pent);

  return id;
}

/* -------------------------------------------------- */
/*
 * This function sets the switch ports in inline mode (just for one direction).
 * Input parameter:
 *     - "unit" -> intel NIC card indentifier [range from 0 to (MAX_INTEL_DEV - 1)]
 *     - "intf" -> interface identifier [range from INTERFACE_1 to (MAX_INTERFACE - 1)]
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */

static int __fast_bpf_rdif_set_port_inline(int unit, int port1, int port2) {
  int j, pos;
  rdi_mask_t mask;

  if(unit >= MAX_INTEL_DEV) return 0;

  /* Prepare parameters for rdi_set_mask library call function */
  memset(&mask, 0, sizeof(rdi_mask_t));
  j = port1 / 8;
  pos = port1 % 8;
  if(j < 16)
    mask.ingress[j] |= (1 << pos);
  j = port2 / 8;
  pos = port2 % 8;
  if(j < 16)
    mask.egress[j] |= (1 << pos);
  /* Set the ports in inline mode (just one direction) by library call function */
  if((rdi_set_mask(unit, &mask, RDI_FLCM_DEV)) < 0)
    return (0);
  return (1);
}

/* -------------------------------------------------- */
/*
 * This function sets the switch ports for a interface in inline mode
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */

static int __fast_bpf_rdif_interface_set_port_inline(fast_bpf_rdif_handle_t *handle) {
  if(handle == NULL) return (0);

  /* Set interface in inline mode (normal direction) */
  if(!__fast_bpf_rdif_set_port_inline(handle->unit, interface[handle->intf].port1, interface[handle->intf].port2))
    return (0);
  /* Set interface in inline mode (reverse direction) */
  if(!__fast_bpf_rdif_set_port_inline(handle->unit, interface[handle->intf].port2, interface[handle->intf].port1))
    return (0);
  return (1);
}

/* -------------------------------------------------- */
/*
 * This function is used to prepare a drop rules
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */

static int __fast_bpf_rdif_interface_set_drop_action(fast_bpf_rdif_handle_t *handle) {
  if(handle == NULL) return (0);

  /* Set drop action */
  handle->rules_parameters.action  = 0;
  handle->rules_parameters.action |= 1<<RDI_ACT_DROP;

  return (1);
}

/* -------------------------------------------------- */
/*
 * This function is used to prepare a permit rules
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */

static int __fast_bpf_rdif_interface_set_permit_action(fast_bpf_rdif_handle_t *handle) {
  if(handle == NULL) return (0);

  /* Set permit action */
  handle->rules_parameters.action  = 0;
  handle->rules_parameters.action |= 1<<RDI_ACT_PERMIT;

  return (1);
}

/* -------------------------------------------------- */
/*
 * This function adds a rule for an interface .
 * Use this as a first called function before to prepare and set a rule.
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */

static int __fast_bpf_rdif_add_rule(fast_bpf_rdif_handle_t *handle) {
  if(handle == NULL) return (0);

#ifdef DEBUG
  printf("Print Rule:\n");
  printf("rule id: %d\n", handle->rules_parameters.rdi_mem.rule_id);
  printf("group: %d\n", handle->rules_parameters.rdi_mem.group);
  printf("port: %d\n", handle->rules_parameters.rdi_mem.port);
  printf("src_ip: %02X\n", handle->rules_parameters.rdi_mem.src_ip);
  printf("dst_ip: %02X\n", handle->rules_parameters.rdi_mem.dst_ip);
  printf("src_port: %d\n", handle->rules_parameters.rdi_mem.src_port);
  printf("dst_port: %d\n", handle->rules_parameters.rdi_mem.dst_port);
  printf("proto: %d\n\n", handle->rules_parameters.rdi_mem.ip_protocol);
#endif

  /* Set group id rule associated to interface */
  handle->rules_parameters.rdi_mem.group = ((MAX_INTERFACE * handle->unit) + interface[handle->intf].group_rules);
  /* Set switch ingress port */
  handle->rules_parameters.rdi_mem.port = interface[handle->intf].port1;

  /* Add rule to card for a specific switch ingress port */
  if(rdi_add_rule(handle->unit, &handle->rules_parameters.rdi_mem, handle->rules_parameters.action, RDI_FLCM_DEV) < 0)
    return (0);

  return (1);
}

/* -------------------------------------------------- */
/*
 * This function sets a rule that drops all the traffic for an interface.
 * Use this as the last set rule. The rules added below will be ignored.
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
static int __fast_bpf_rdif_interface_set_drop_all(fast_bpf_rdif_handle_t *handle) {
  if(handle == NULL) return (0);

  bzero(&handle->rules_parameters.rdi_mem, sizeof(rdi_mem_t));
  /* Set drop action */
  __fast_bpf_rdif_interface_set_drop_action(handle);
  /* Set rule identifier, switch ingress port and group identifier */
  handle->rules_parameters.rdi_mem.rule_id = handle->current_rule_id++;
  handle->rules_parameters.rdi_mem.port = interface[handle->intf].port1;
  handle->rules_parameters.rdi_mem.group = ((MAX_INTERFACE * handle->unit) + interface[handle->intf].group_rules);
  /* Add rule in order to dropp all the traffic for a specific interface */
  return __fast_bpf_rdif_add_rule(handle);
}

/* -------------------------------------------------- */
/*
 * This function initializes the local variabiles used in order to set a rule.
 * Use this as the first called function before to prepare and set a rule.
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
static int __fast_bpf_rdif_init_for_rule(fast_bpf_rdif_handle_t *handle) {
  if(handle == NULL) return (0);

  bzero(&handle->rules_parameters.rdi_mem, sizeof(rdi_mem_t));

  /* set rules group for a specific interface */
  handle->rules_parameters.rdi_mem.group = ((MAX_INTERFACE * handle->unit) + interface[handle->intf].group_rules);
  /* set ingress port of the swicth*/
  handle->rules_parameters.rdi_mem.port = interface[handle->intf].port1;
  /* set rule id*/
  handle->rules_parameters.rdi_mem.rule_id = handle->current_rule_id++;

  return (1);
}

/* -------------------------------------------------- */
/*
 * This function sets the source or destination ip v4 address in a rule
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 *     - "ipAddress" -> ip address
 *     - "isSrc"-> 1 for a source ip address or 0 for a destination ip address
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
static int __fast_bpf_rdif_interface_set_ipv4_address(fast_bpf_rdif_handle_t *handle, unsigned int ipAddress, unsigned int isSrc) {
  if(handle == NULL) return (0);

  if(isSrc) {
    /* Set ipv4 source address */
    handle->rules_parameters.rdi_mem.src_ip = ipAddress;
    /* Set ipv4 mode */
    handle->rules_parameters.rdi_mem.src_ip6.flag=0;
  } else {
    /* Set ipv4 destination address */
    handle->rules_parameters.rdi_mem.dst_ip = ipAddress;
    /* Set ipv4 mode */
    handle->rules_parameters.rdi_mem.dst_ip6.flag=0;
  }


  return (1);
}

/* -------------------------------------------------- */
/*
 * This function sets the source or destination ip v4 address in a rule
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 *     - "ipAddress" -> ip address
 *     - "isSrc"-> 1 for a source ip address or 0 for a destination ip address
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
static int __fast_bpf_rdif_interface_set_ipv6_address(fast_bpf_rdif_handle_t *handle, unsigned char* ipv6_addr, unsigned int isSrc) {
  if(handle == NULL) return (0);
  if(ipv6_addr == NULL) return (0);

  if(isSrc) {
    /* Set ipv4 source address */
    memcpy(handle->rules_parameters.rdi_mem.src_ip6.ip, ipv6_addr, 16);
    /* Set ipv4 mode */
    handle->rules_parameters.rdi_mem.src_ip6.flag=1;
  } else {
    /* Set ipv4 destination address */
    memcpy(handle->rules_parameters.rdi_mem.dst_ip6.ip, ipv6_addr, 16);
    /* Set ipv4 mode */
    handle->rules_parameters.rdi_mem.dst_ip6.flag=1;
  }

  return (1);
}

/* -------------------------------------------------- */
/*
 * This function sets the source or destination port in a rule
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 *     - "port" -> port number (host format)
 *     - "isSrc"-> 1 for a source port or 0 for a destination port
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
static int __fast_bpf_rdif_interface_set_port(fast_bpf_rdif_handle_t *handle, unsigned int port, unsigned int isSrc) {
  if(handle == NULL) return (0);

  if(isSrc) {
    /* Set ipv4 source port (you have also to set the mask port) */
    handle->rules_parameters.rdi_mem.src_port = port;
    handle->rules_parameters.rdi_mem.src_port_mask = 0xFFFFFFFF;
  } else {
    /* Set ipv4 destination port (you have also to set the mask port) */
    handle->rules_parameters.rdi_mem.dst_port = port;
    handle->rules_parameters.rdi_mem.dst_port_mask = 0xFFFFFFFF;
  }

  return (1);
}

/* -------------------------------------------------- */
/*
 * This function sets the protocol type in a rule
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 *     - "protocol" -> protocol
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
static int __fast_bpf_rdif_interface_set_protocol(fast_bpf_rdif_handle_t *handle, unsigned int protocol) {
  if(handle == NULL) return (0);

  /* Set protocol */
  handle->rules_parameters.rdi_mem.ip_protocol = protocol;

  return (1);
}

/* -------------------------------------------------- */
/*
 * This function checks before for a general relus constraints and after for the
 * intel NIC card specifies constrains
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 *     - "tree"   -> tree pointer
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
static int __fast_bpf_rdif_check_rules_constraints(fast_bpf_rdif_handle_t *handle, fast_bpf_tree_t *tree) {
  if(handle == NULL) return (0);

  /* check the general rules of the fast bpf */
  if(!fast_bpf_check_rules_constraints(tree, 0))
    return (0);

  /* check the intel specific rules of the fast bpf */
  if(!__fast_bpf_rdif_check_specific_constrains(handle, tree))
    return (0);

  return (1);
}

/* -------------------------------------------------- */
/*
 * This function loops through the tree and checks the constrains for the specific node.
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 *     - "n" -> pointer to a node in the tree
 */
/* -------------------------------------------------- */
static void __fast_bpf_rdif_check_node_specific_constrains(fast_bpf_rdif_handle_t *handle, fast_bpf_node_t *n) {

  if(handle == NULL) return;
  if(n == NULL) return;
  if(n->not_rule) return;

  switch(n->type) {
  case N_PRIMITIVE:
    if(n->qualifiers.address == Q_HOST) {
      if(n->qualifiers.direction == Q_SRC) {
	/* This counts how many time the src host ip is used in a bpf filter */
	handle->constraint_parameters.src_host++;
      } else if(n->qualifiers.direction == Q_DST) {
	/* This counts how many time the dst host ip is used */
	handle->constraint_parameters.dst_host++;
      } else {
	//handle->constraint_parameters.src_host++;
	//handle->constraint_parameters.dst_host++;
	/* At the moment you cannot use bidirectional ip address (for example: "host 192.168.0.1") */
	handle->constraint_parameters.not_managed++;
      }
    } else if(n->qualifiers.address == Q_PORT) {
      if(n->qualifiers.direction == Q_SRC) {
	/* This counts how many time the src port is used in a bpf filter */
	handle->constraint_parameters.src_port++;
      } else if(n->qualifiers.direction == Q_DST) {
	/* This counts how many time the dst port is used in a bpf filter */
	handle->constraint_parameters.dst_port++;
      } else {
	//handle->constraint_parameters.src_port++;
	//handle->constraint_parameters.dst_port++;
	/* At the moment you cannot use bidirectional ip address (for example: "port 3000") */
	handle->constraint_parameters.not_managed++;
      }
    } else if(n->qualifiers.address == Q_PROTO) {
      /* This counts how many time the protocol is used in a bpf filter */
      handle->constraint_parameters.proto++;
    } else {
      /* The other cases aren't managed */
      handle->constraint_parameters.not_managed++;
    }
    break;
  case N_AND:
    /* If you enter here, you have a bpf filter with just "and" operators */
    handle->constraint_parameters.is_and++;
    __fast_bpf_rdif_check_node_specific_constrains(handle, n->l);
    __fast_bpf_rdif_check_node_specific_constrains(handle, n->r);
    break;
  case N_OR:
    /* If you enter here, you have a bpf filter with just "or" operators */
    __fast_bpf_rdif_check_node_specific_constrains(handle, n->l);
    __fast_bpf_rdif_check_node_specific_constrains(handle, n->r);
    break;
  default:
    break;
  }
  return;
}

/* -------------------------------------------------- */
/*
 * This function checks specifies constraints for the intel NIC card
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 *     - "tree" -> tree that rappresents the bpf filter
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
static int __fast_bpf_rdif_check_specific_constrains(fast_bpf_rdif_handle_t *handle, fast_bpf_tree_t *tree) {

  if(handle == NULL) return (0);
  if(tree == NULL) return (0);

  /* reset structure for check constrains */
  memset( &handle->constraint_parameters, 0, sizeof(check_constraint_t));
  __fast_bpf_rdif_check_node_specific_constrains(handle, tree->root);

  /* If you have element not managed, return failure */
  if(handle->constraint_parameters.not_managed != 0)
    return (0);

  if(handle->constraint_parameters.is_and != 0) {
    /* If you have a bpf filter with just "and" operator, you cannot have more than one element in the filter.
     * For example if you have src_host>1 that means you have a bpf filter that uses more than one src host:
     * "src host 192.168.0.1 and src host 10.0.0.1"
     * But a such filter doesn't make sense so you have violated a constraint (return failure).
     */
    if(
       (handle->constraint_parameters.src_host > 1) ||
       (handle->constraint_parameters.dst_host > 1) ||
       (handle->constraint_parameters.src_port > 1) ||
       (handle->constraint_parameters.dst_port > 1) ||
       (handle->constraint_parameters.proto > 1)
       )
      return (0);
  }
  return (1);
}

/* -------------------------------------------------- */
/*
 * This function creates and set all the rules on the card for an interface
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 *     - "blockPun" -> block pointer that contains the rules list
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
static int __fast_bpf_rdif_create_and_set_rules(fast_bpf_rdif_handle_t *handle, fast_bpf_rule_block_list_item_t *blockPun) {
  fast_bpf_rule_block_list_item_t *currPun;
  fast_bpf_rule_list_item_t * pun;

  if(handle == NULL)
    return (0);

  if(blockPun == NULL)
    return (0);

  /* Clear and initialize the environment */
  if(!__fast_bpf_rdif_init(handle))
    return (0);

  /* Scan the list and set the single rule */
  currPun = blockPun;
  while(currPun != NULL) {
    pun = currPun->rule_list_head;

    while(pun != NULL) {
      if(!__fast_bpf_rdif_set_single_rule(handle, pun)) {
        __fast_bpf_rdif_init(handle);
        return (0);
      }

      pun = pun->next;
    }

    currPun = currPun->next;
  }

  /* The last rule drop all the traffic */
  if(!__fast_bpf_rdif_interface_set_drop_all(handle)) {
    __fast_bpf_rdif_init(handle);
    return (0);
  }

  return (1);
}

/* -------------------------------------------------- */
/*
 * This function adds a rule for an interface
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 *     - "rule" -> rule rappresentation element
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
static int __fast_bpf_rdif_set_single_rule(fast_bpf_rdif_handle_t *handle, fast_bpf_rule_list_item_t *rule) {

  if(handle == NULL) return (0);
  if(rule == NULL) return (0);

  /* Init the variables in order to set a rule */
  if(!__fast_bpf_rdif_init_for_rule(handle))
    return (0);
  /*Set permit action*/
  if(!__fast_bpf_rdif_interface_set_permit_action(handle))
    return (0);

  if(rule->fields.ip_version == 4 && rule->fields.shost.v4 != 0) {
    /* Set ipv4 src address */
    if(!__fast_bpf_rdif_interface_set_ipv4_address(handle, rule->fields.shost.v4, 1))
      return (0);
  }
  if(rule->fields.ip_version == 4 && rule->fields.dhost.v4 != 0) {
    /* Set ipv4 dst address */
    if(!__fast_bpf_rdif_interface_set_ipv4_address(handle, rule->fields.dhost.v4, 0))
      return (0);
  }
  if( (rule->fields.ip_version == 6) && (! is_empty_ipv6(rule->fields.shost.v6.u6_addr.u6_addr8) ) ) {
    /* Set ipv6 src address */
    if(!__fast_bpf_rdif_interface_set_ipv6_address(handle, rule->fields.shost.v6.u6_addr.u6_addr8, 1))
      return (0);
  }
  if( (rule->fields.ip_version == 6) && (! is_empty_ipv6(rule->fields.dhost.v6.u6_addr.u6_addr8) ) ) {
    /* Set ipv6 dst address */
    if(!__fast_bpf_rdif_interface_set_ipv6_address(handle, rule->fields.dhost.v6.u6_addr.u6_addr8, 0))
      return (0);
  }
  if(rule->fields.sport_low != 0) {
    /* Set src port */
    if(!__fast_bpf_rdif_interface_set_port(handle, ntohs(rule->fields.sport_low), 1))
      return (0);
  }
  if(rule->fields.dport_low != 0) {
    /* Set dst port */
    if(!__fast_bpf_rdif_interface_set_port(handle, ntohs(rule->fields.dport_low), 0))
      return (0);
  }
  if(rule->fields.proto != 0) {
    /* Set protocol */
    if(!__fast_bpf_rdif_interface_set_protocol(handle, rule->fields.proto))
      return (0);
  }
  if(!__fast_bpf_rdif_add_rule(handle))
    return (0);

  return (1);
}

/* -------------------------------------------------- */
/*
 * This function clears all the rules for an interface
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
static int __fast_bpf_rdif_interface_clear(fast_bpf_rdif_handle_t *handle) {
  rdi_query_list_t rdi_query_list;
  unsigned int group_rules;
  int m;

  if(handle == NULL) return (0);

  memset(&rdi_query_list, 0, sizeof(rdi_query_list_t));

  group_rules = ((MAX_INTERFACE * handle->unit) + interface[handle->intf].group_rules);
  /* Get the rule identifiers list set */
  if((rdi_entry_query_list(handle->unit, group_rules, &rdi_query_list, RDI_FLCM_DEV))<0)
    return (0);
  else {
    if(rdi_query_list.rdi_id_list.rule_num) {
      if(rdi_query_list.rdi_id_list.rule_num<=MAX_NUM_RULES) {
        for (m=0; m<rdi_query_list.rdi_id_list.rule_num;m++) {
          /* through the list and removes the single rule */
          if((rdi_entry_remove(handle->unit, rdi_query_list.rdi_id_list.id_list[m], group_rules, RDI_FLCM_DEV))<0) {
            return (0);
          }
        }
      }
    }
  }
  /* reset rules id counter */
  handle->current_rule_id = 1;

  return 1;
}

#endif /* HAVE_REDIRECTOR_F */

/* Global Functions Definitions */

/* -------------------------------------------------- */
/*
 * This global function is the main function and tries
 * to set a bfp filter on a NIC card interface
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 *     - "bpf" -> bpf filter
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
int fast_bpf_rdif_set_filter(fast_bpf_rdif_handle_t *handle, char *bpf) {
#ifdef HAVE_REDIRECTOR_F
  fast_bpf_tree_t *tree;
  fast_bpf_rule_block_list_item_t *punBlock;

  if(handle == NULL)
    return (0);
  if(bpf == NULL)
    return (0);

  /* Parses the bpf filters and builds the rules tree */
  if((tree = fast_bpf_parse(bpf, NULL)) == NULL) {
#ifdef DEBUG
    printf("Error on parsing the bpf filter.");
#endif
    return (0);
  }

  /* checks if the constrains are respected (both fast bpf and specific intel fast bpf) */
  if(!__fast_bpf_rdif_check_rules_constraints(handle, tree)) {
#ifdef DEBUG
    printf("Error on checking constrains for a bpf filter.\n");
#endif
    fast_bpf_free(tree);
    return (0);
  }

  /* Generates a optimized rules list */
  if((punBlock = fast_bpf_generate_optimized_rules(tree)) == NULL ) {
#ifdef DEBUG
    printf("Error on generating optimized rules.");
#endif
    fast_bpf_free(tree);
    return (0);
  }

  /* Creates and set the rules on the nic */
  if(!__fast_bpf_rdif_create_and_set_rules(handle, punBlock)) {
#ifdef DEBUG
    printf("Error on creating and setting the rules list on the NIC card.");
#endif
    fast_bpf_rule_block_list_free(punBlock);
    fast_bpf_free(tree);
    return (0);
  }

  fast_bpf_rule_block_list_free(punBlock);
  fast_bpf_free(tree);
  return (1);
#else  /* HAVE_REDIRECTOR_F */
  return (0);
#endif /* HAVE_REDIRECTOR_F */
}

/* -------------------------------------------------- */

#ifdef HAVE_REDIRECTOR_F

static int __fast_bpf_rdif_init(fast_bpf_rdif_handle_t *handle) {

  /* Clear all rules for the interface */
  if(!__fast_bpf_rdif_interface_clear(handle)) {
#ifdef DEBUG
    printf("Error on cleaning the rules in initialization phase.");
#endif
    return 0;
  }

  /* Set all interfaces inline mode */
  if(!__fast_bpf_rdif_interface_set_port_inline(handle)) {
#ifdef DEBUG
    printf("Error on setting interface in inline mode.");
#endif
    return 0;
  }

  return 1;
}
#endif /* HAVE_REDIRECTOR_F */

/* -------------------------------------------------- */
/*
 * This function initializes the switch in order to put the port in inline mode:
 * port 1 with port 3 for interface 0
 * port 2 with port 4 for interface 1
 * Input parameter:
 *     - "ifname" -> Interface name (for example "eth0", "ens9"....)
 * Return value:
 *     - NULL on failure
 *     - handle pointer on success
 */
fast_bpf_rdif_handle_t *fast_bpf_rdif_init(char *ifname) {
#ifdef HAVE_REDIRECTOR_F
  fast_bpf_rdif_handle_t *handle;
  int intf, unit;

  unit = 0; //TODO
  intf = __fast_bpf_rdif_get_interface_id(ifname);

  if(intf < 0)
    return NULL;

  if(unit >= MAX_INTEL_DEV ||
     intf >= MAX_INTERFACE)
    return NULL;

  handle = calloc(1, sizeof(fast_bpf_rdif_handle_t));
  if(handle == NULL)
    return NULL;

  handle->unit = unit;
  handle->intf = intf;

  if(!__fast_bpf_rdif_init(handle)) {
    if(handle) free(handle);
    return NULL;
  }

  return handle;
#else /* HAVE_REDIRECTOR_F */
  return NULL;
#endif /* HAVE_REDIRECTOR_F */
}

/* -------------------------------------------------- */
/*
 * This global function reset a NIC card. Make attention if you use this function
 * and you have already set some rule for some interfaces, it will clean everything.
 * Suggestion: use this function just once (in initialize phase of the NIC card).
 * Input parameter:
 *     - "unit" -> intel NIC card indentifier [range from 0 to (MAX_INTEL_DEV - 1)]
 * Return value:
 *     - 0 on failure
 *     - 1 on success
 */
/* -------------------------------------------------- */
int fast_bpf_rdif_reset(int unit) {
#ifdef HAVE_REDIRECTOR_F
  if(unit >= MAX_INTEL_DEV) return (0);

  /* Set MON2 configuration (value 5). No traffic in egress */
  if(rdi_set_cfg(unit, 5, RDI_FLCM_DEV) < 0)
    return (0);
  return (1);
#else
  return(0);
#endif /* HAVE_REDIRECTOR_F */
}

/* -------------------------------------------------- */
/*
 * This function frees the handle memory area.
 * Input parameter:
 *     - "handle" -> data structure that contains the bpf rdif data
 */
/* -------------------------------------------------- */
void fast_bpf_rdif_destroy(fast_bpf_rdif_handle_t *handle) {
#ifdef HAVE_REDIRECTOR_F
  /* Clear and initialize the environment */
  __fast_bpf_rdif_init(handle);
#endif
  /* free handle */
  if(handle != NULL)
    free(handle);
}

/* -------------------------------------------------- */
/* -------------------------------------------------- */

#ifdef DEBUG

void __fast_bpf_rdif_print_tree(fast_bpf_node_t *n) {

  if(n == NULL) return; /* empty and/or operators not allowed */
  if(n->not_rule) return;

  switch(n->type) {
  case N_PRIMITIVE:
    printf("Type: %d\n", n->type);
    printf("Qualifiers address: %d\n", n->qualifiers.address);
    printf("Qualifiers direction: %d\n", n->qualifiers.direction);
    printf("Qualifiers protocol: %d\n\n", n->qualifiers.protocol);
    break;
  case N_AND:
  case N_OR:
    __fast_bpf_rdif_print_tree(n->l);
    __fast_bpf_rdif_print_tree(n->r);
    break;
  default:
    break;
  }
  return;
}

/* -------------------------------------------------- */
void __fast_bpf_rdif_call_print_tree(fast_bpf_tree_t *tree) {
  __fast_bpf_rdif_print_tree(tree->root);
}
#endif
