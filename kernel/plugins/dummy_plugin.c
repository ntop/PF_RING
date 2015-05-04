/* ***************************************************************
 *
 * (C) 2007-11 - Luca Deri <deri@ntop.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

/*

  IMPORTANT

  See userland/examples/pfcount_dummy_plugin.c for
  learning how to use plugins from userspace

*/

#include <linux/version.h>
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33))
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif
#else
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/init.h>
#include <linux/filter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/textsearch.h>
#include <net/xfrm.h>
#include <net/sock.h>
#include <asm/io.h>   /* needed for virt_to_phys() */
#ifdef CONFIG_INET
#include <net/inet_common.h>
#endif
#include <net/ip.h>

/* Enable plugin PF_RING functions */
#define PF_RING_PLUGIN
#include "../linux/pf_ring.h"

#include "dummy_plugin.h"

static struct pfring_plugin_registration reg;

/* #define DEBUG */

/* ************************************ */

static int dummy_plugin_handle_skb(struct pf_ring_socket *pfr,
				   sw_filtering_rule_element *rule,
				   sw_filtering_hash_bucket *hash_rule,
				   struct pfring_pkthdr *hdr,
				   struct sk_buff *skb, int displ,
				   u_int16_t filter_plugin_id,
				   struct parse_buffer **filter_rule_memory_storage,
				   rule_action_behaviour *behaviour)
{

  if(rule != NULL) {
    if(rule->plugin_data_ptr == NULL) {
      rule->plugin_data_ptr = (struct simple_stats*)kmalloc(sizeof(struct simple_stats), GFP_ATOMIC);
      if(rule->plugin_data_ptr != NULL)
	memset(rule->plugin_data_ptr, 0, sizeof(struct simple_stats));
    }

    if(rule->plugin_data_ptr != NULL) {
      struct simple_stats *stats = (struct simple_stats*)rule->plugin_data_ptr;
      stats->num_pkts++, stats->num_bytes += hdr->len;

#ifdef DEBUG
      printk("-> dummy_plugin_handle_skb [pkts=%u][bytes=%u]\n",
	     (unsigned int)stats->num_pkts,
	     (unsigned int)stats->num_bytes);
#endif
    }
  }

  return(1);
}

/* ************************************ */

static int dummy_plugin_get_stats(struct pf_ring_socket *pfr,
				  sw_filtering_rule_element *rule,
				  sw_filtering_hash_bucket  *hash_bucket,
				  u_char* stats_buffer,
				  u_int stats_buffer_len)
{
#ifdef DEBUG
  printk("-> dummy_plugin_get_stats(len=%d)\n", stats_buffer_len);
#endif

  if(stats_buffer_len >= sizeof(struct simple_stats)) {
    if(rule->plugin_data_ptr == NULL)
      memset(stats_buffer, 0, sizeof(struct simple_stats));
    else
      memcpy(stats_buffer, rule->plugin_data_ptr, sizeof(struct simple_stats));

    return(sizeof(struct simple_stats));
  } else
    return(0);
}

/* ************************************ */

static int dummy_plugin_filter(struct pf_ring_socket *the_ring,
			       sw_filtering_rule_element *rule,
			       struct pfring_pkthdr *hdr,
			       struct sk_buff *skb, int displ,
			       struct parse_buffer **parse_memory)
{
  struct dummy_filter *rule_filter = (struct dummy_filter*)rule->rule.extended_fields.filter_plugin_data;

  if(rule_filter) {
#ifdef DEBUG
    printk("->l3_proto=%d / protocol=%d\n", hdr->extended_hdr.parsed_pkt.l3_proto, rule_filter->protocol);
#endif

    if(hdr->extended_hdr.parsed_pkt.l3_proto != rule_filter->protocol)
      return(0); /* no match */
  }

  return(1); /* Ok */
}

/* ************************************ */

static void dummy_plugin_register(u_int8_t register_plugin) {
  if(register_plugin)
    try_module_get(THIS_MODULE); /* Increment usage count */
  else
    module_put(THIS_MODULE);	 /* Decrement usage count */
}

/* ************************************ */

static int __init dummy_plugin_init(void)
{
  printk("Welcome to dummy plugin for PF_RING\n");

  memset(&reg, 0, sizeof(reg));

  reg.plugin_id                = DUMMY_PLUGIN_ID;
  reg.pfring_plugin_handle_skb = dummy_plugin_handle_skb;
  reg.pfring_plugin_get_stats  = dummy_plugin_get_stats;
  reg.pfring_plugin_filter_skb = dummy_plugin_filter;
  reg.pfring_plugin_register   = dummy_plugin_register;

  snprintf(reg.name, sizeof(reg.name)-1, "dummy");
  snprintf(reg.description, sizeof(reg.description)-1, "This is a dummy plugin");

  register_plugin(&reg);

  /* Make sure that PF_RING is loaded when this plugin is loaded */
  pf_ring_add_module_dependency();

  printk("Dummy plugin started [id=%d]\n", DUMMY_PLUGIN_ID);
  return(0);
}

/* ************************************ */

static void __exit dummy_plugin_exit(void)
{
  printk("Thanks for having used dummy plugin for PF_RING\n");
  unregister_plugin(DUMMY_PLUGIN_ID);
}

/* ************************************ */

module_init(dummy_plugin_init);
module_exit(dummy_plugin_exit);
MODULE_LICENSE("GPL");

