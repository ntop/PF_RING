 /* ***************************************************************
 *
 * (C) 2004-12 - Luca Deri <deri@ntop.org>
 *
 * This code includes contributions courtesy of
 * - Amit D. Chaudhary <amit_ml@rajgad.com>
 * - Andrew Gallatin <gallatyn@myri.com>
 * - Brad Doctor <brad@stillsecure.com>
 * - Felipe Huici <felipe.huici@nw.neclab.eu>
 * - Francesco Fusco <fusco@ntop.org> (IP defrag)
 * - Helmut Manck <helmut.manck@secunet.com>
 * - Hitoshi Irino <irino@sfc.wide.ad.jp> (IPv6 support)
 * - Jakov Haron <jyh@cabel.net>
 * - Jeff Randall <jrandall@nexvu.com>
 * - Kevin Wormington <kworm@sofnet.com>
 * - Mahdi Dashtbozorgi <rdfm2000@gmail.com>
 * - Marketakis Yannis <marketak@ics.forth.gr>
 * - Matthew J. Roth <mroth@imminc.com>
 * - Michael Stiller <ms@2scale.net> (VM memory support)
 * - Noam Dev <noamdev@gmail.com>
 * - Siva Kollipara <siva@cs.arizona.edu>
 * - Vincent Carrier <vicarrier@wanadoo.fr>
 * - Eugene Bogush <b_eugene@ukr.net>
 * - Samir Chang <coobyhb@gmail.com>
 * - Ury Stankevich <urykhy@gmail.com>
 * - Raja Mukerji <raja@mukerji.com>
 * - Davide Viti <zinosat@tiscali.it>
 * - Will Metcalf <william.metcalf@gmail.com>
 * - Godbach <nylzhaowei@gmail.com>
 * - Nicola Bonelli <bonelli@antifork.org>
 * - Jan Alsenz
 * - valxdater@seznam.cz
 * - Vito Piserchia <vpiserchia@metatype.it>
 * - Guo Chen <johncg1983@gmail.com>
 * - Dan Kruchinin <dkruchinin@acm.org>
 * - Andreas Tsopelas <tsopelas@kth.se>
 * - Alfredo Cardigliano <cardigliano@ntop.org>
 * - Alex Aronson <alexa@silicom.co.il>
 * - Piotr Romanus <promanus@crossbeamsys.com>
 * - Lior Okman <lior.okman@insightix.com>
 * - Fedor Sakharov <fedor.sakharov@gmail.com>
 * - Daniel Christopher <Chris.Daniel@visualnetworksystems.com>
 * - Martin Holste <mcholste@gmail.com>
 * - Eric Leblond <eric@regit.org>
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

#include <linux/version.h>

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))
#error **********************************************************************
#error * PF_RING works on kernel 2.6.18 or newer. Please update your kernel *
#error **********************************************************************
#endif

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
#include <linux/vmalloc.h>
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
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/if_arp.h>
#include <net/xfrm.h>
#include <net/sock.h>
#include <asm/io.h>		/* needed for virt_to_phys() */
#ifdef CONFIG_INET
#include <net/inet_common.h>
#endif
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/pci.h>

#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30))
#include <linux/eventfd.h>
#define VPFRING_SUPPORT
#endif

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
#define I82599_HW_FILTERING_SUPPORT
#endif

#include <linux/pf_ring.h>

#ifndef SVN_REV
#define SVN_REV ""
#endif

/* ************************************************* */

#define TH_FIN_MULTIPLIER	0x01
#define TH_SYN_MULTIPLIER	0x02
#define TH_RST_MULTIPLIER	0x04
#define TH_PUSH_MULTIPLIER	0x08
#define TH_ACK_MULTIPLIER	0x10
#define TH_URG_MULTIPLIER	0x20

/* ************************************************* */

#define PROC_INFO               "info"
#define PROC_DEV                "dev"
#define PROC_RULES              "rules"
#define PROC_PLUGINS_INFO       "plugins_info"

/* ************************************************* */

const static ip_addr ip_zero = { IN6ADDR_ANY_INIT };

static u_int8_t pfring_enabled = 0;

/* Dummy 'any' device */
static ring_device_element any_device_element, none_device_element;

/* List of all ring sockets. */
static struct list_head ring_table;
static u_int ring_table_size;

/* Protocol hook */
static struct packet_type prot_hook;

/*
  For each device, pf_ring keeps a list of the number of
  available ring socket slots. So that a caller knows in advance whether
  there are slots available (for rings bound to such device)
  that can potentially host the packet
*/
static struct list_head device_ring_list[MAX_NUM_DEVICES];

/* List of virtual filtering devices */
static struct list_head virtual_filtering_devices_list;
static rwlock_t virtual_filtering_lock =
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39))
  RW_LOCK_UNLOCKED
#else
  __RW_LOCK_UNLOCKED(virtual_filtering_lock)
#endif
;

/* List of all clusters */
static struct list_head ring_cluster_list;

/* List of all devices on which PF_RING has been registered */
static struct list_head ring_aware_device_list; /* List of ring_device_element */

/* Keep track of number of rings per device (plus any) */
static u_int8_t num_rings_per_device[MAX_NUM_IFIDX] = { 0 };
static struct pf_ring_socket* device_rings[MAX_NUM_IFIDX][MAX_NUM_RX_CHANNELS] = { { NULL } };
static u_int8_t num_any_rings = 0;

/* List of all DNA (direct nic access) devices */
static struct list_head ring_dna_devices_list;
static u_int dna_devices_list_size = 0;

/* List of all plugins */
static u_int plugin_registration_size = 0;
static struct pfring_plugin_registration *plugin_registration[MAX_PLUGIN_ID] = { NULL };
static u_short max_registered_plugin_id = 0;

/* List of userspace rings */
static struct list_head userspace_ring_list;
static rwlock_t userspace_ring_lock =
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39))
  RW_LOCK_UNLOCKED
#else
  __RW_LOCK_UNLOCKED(userspace_ring_lock)
#endif
;

/* Dumy buffer used for loopback_test */
u_int32_t loobpack_test_buffer_len = 4*1024*1024;
u_char *loobpack_test_buffer = NULL;

/* ********************************** */

/* /proc entry for ring module */
struct proc_dir_entry *ring_proc_dir = NULL, *ring_proc_dev_dir = NULL;
struct proc_dir_entry *ring_proc = NULL;
struct proc_dir_entry *ring_proc_plugins_info = NULL;

static int ring_proc_get_info(char *, char **, off_t, int, int *, void *);
static int ring_proc_get_plugin_info(char *, char **, off_t, int, int *,
				     void *);
static void ring_proc_add(struct pf_ring_socket *pfr);
static void ring_proc_remove(struct pf_ring_socket *pfr);
static void ring_proc_init(void);
static void ring_proc_term(void);

static int reflect_packet(struct sk_buff *skb,
			  struct pf_ring_socket *pfr,
			  struct net_device *reflector_dev,
			  int displ, rule_action_behaviour behaviour);

/* ********************************** */

static rwlock_t ring_mgmt_lock;

inline void init_ring_readers(void)      {
  ring_mgmt_lock =
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39))
    RW_LOCK_UNLOCKED
#else
    __RW_LOCK_UNLOCKED(ring_mgmt_lock)
#endif
    ;
}
inline void ring_write_lock(void)        { write_lock_bh(&ring_mgmt_lock);    }
inline void ring_write_unlock(void)      { write_unlock_bh(&ring_mgmt_lock);  }
/* use ring_read_lock/ring_read_unlock in process context (a bottom half may use write_lock) */
inline void ring_read_lock(void)         { read_lock_bh(&ring_mgmt_lock);     }
inline void ring_read_unlock(void)       { read_unlock_bh(&ring_mgmt_lock);   }
/* use ring_read_lock_inbh/ring_read_unlock_inbh in bottom half contex */
inline void ring_read_lock_inbh(void)    { read_lock(&ring_mgmt_lock);        }
inline void ring_read_unlock_inbh(void)  { read_unlock(&ring_mgmt_lock);      }

/* ********************************** */

/*
  Caveat
  [http://lists.metaprl.org/pipermail/cs134-labs/2002-October/000025.html]

  GFP_ATOMIC means roughly "make the allocation operation atomic".  This
  means that the kernel will try to find the memory using a pile of free
  memory set aside for urgent allocation.  If that pile doesn't have
  enough free pages, the operation will fail.  This flag is useful for
  allocation within interrupt handlers.

  GFP_KERNEL will try a little harder to find memory.  There's a
  possibility that the call to kmalloc() will sleep while the kernel is
  trying to find memory (thus making it unsuitable for interrupt
  handlers).  It's much more rare for an allocation with GFP_KERNEL to
  fail than with GFP_ATOMIC.

  In all cases, kmalloc() should only be used allocating small amounts of
  memory (a few kb).  vmalloc() is better for larger amounts.

  Also note that in lab 1 and lab 2, it would have been arguably better to
  use GFP_KERNEL instead of GFP_ATOMIC.  GFP_ATOMIC should be saved for
  those instances in which a sleep would be totally unacceptable.
*/
/* ********************************** */

/* Forward */
static struct proto_ops ring_ops;

#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11))
static struct proto ring_proto;
#endif

static int skb_ring_handler(struct sk_buff *skb, u_char recv_packet,
			    u_char real_skb,
			    u_int32_t channel_id, u_int32_t num_rx_channels);
static int buffer_ring_handler(struct net_device *dev, char *data, int len);
static int remove_from_cluster(struct sock *sock, struct pf_ring_socket *pfr);
static int ring_map_dna_device(struct pf_ring_socket *pfr,
			       dna_device_mapping * mapping);

/* Extern */
extern
#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23))
struct sk_buff *
#else
int
#endif
ip_defrag(struct sk_buff *skb, u32 user);

/* ********************************** */

/* Defaults */
static unsigned int min_num_slots = 4096;
static unsigned int enable_tx_capture = 1;
static unsigned int enable_ip_defrag = 0;
static unsigned int quick_mode = 0;
static unsigned int enable_debug = 0;
static unsigned int transparent_mode = standard_linux_path;
static u_int32_t ring_id_serial = 0;

#if defined(RHEL_RELEASE_CODE)
#if(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(4,8))
#define REDHAT_PATCHED_KERNEL
#endif
#endif

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)) || defined(REDHAT_PATCHED_KERNEL)
module_param(min_num_slots, uint, 0644);
module_param(transparent_mode, uint, 0644);
module_param(enable_debug, uint, 0644);
module_param(enable_tx_capture, uint, 0644);
module_param(enable_ip_defrag, uint, 0644);
module_param(quick_mode, uint, 0644);
#else
MODULE_PARM(min_num_slots, "i");
MODULE_PARM(transparent_mode, "i");
MODULE_PARM(enable_debug, "i");
MODULE_PARM(enable_tx_capture, "i");
MODULE_PARM(enable_ip_defrag, "i");
MODULE_PARM(quick_mode, "i");
#endif

MODULE_PARM_DESC(min_num_slots, "Min number of ring slots");
MODULE_PARM_DESC(transparent_mode,
		 "0=standard Linux, 1=direct2pfring+transparent, 2=direct2pfring+non transparent"
		 "For 1 and 2 you need to use a PF_RING aware driver");
MODULE_PARM_DESC(enable_debug, "Set to 1 to enable PF_RING debug tracing into the syslog");
MODULE_PARM_DESC(enable_tx_capture, "Set to 1 to capture outgoing packets");
MODULE_PARM_DESC(enable_ip_defrag,
		 "Set to 1 to enable IP defragmentation"
		 "(only rx traffic is defragmentead)");
MODULE_PARM_DESC(quick_mode,
		 "Set to 1 to run at full speed but with up"
		 "to one socket per interface");

/* ********************************** */

#define MIN_QUEUED_PKTS      64
#define MAX_QUEUE_LOOPS      64

#define ring_sk_datatype(__sk) ((struct pf_ring_socket *)__sk)
#define ring_sk(__sk) ((__sk)->sk_protinfo)

#define _rdtsc() ({ uint64_t x; asm volatile("rdtsc" : "=A" (x)); x; })

/* ***************** Legacy code ************************ */

u_int get_num_rx_queues(struct net_device *dev) {
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
  return(1);
#else
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)) && defined(CONFIG_RPS)
  return(dev->real_num_rx_queues);
#else
  return(dev->real_num_tx_queues);
  // return(1);
#endif
#endif
}

#if defined(RHEL_MAJOR) && (RHEL_MAJOR == 5) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18))
/* Redhat backports these functions to 2.6.18 so do nothing */
#else

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
static inline void skb_reset_network_header(struct sk_buff *skb) {
  /* skb->network_header = skb->data - skb->head; */
}

static inline void skb_reset_transport_header(struct sk_buff *skb) {
  /* skb->transport_header = skb->data - skb->head; */
}

static inline void skb_set_network_header(struct sk_buff *skb, const int offset) {
  skb_reset_network_header(skb);
  /* skb->network_header += offset; */
}

#endif /* KERNEL_VERSION */
#endif /* RH_MAJOR */

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)) || (defined(RHEL_MAJOR) && (RHEL_MAJOR == 5) && (RHEL_MINOR < 2))
static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
  return(struct iphdr *)skb->nh.iph;
}

#if(!defined(REDHAT_PATCHED_KERNEL)) || ((RHEL_MAJOR == 5) && (RHEL_MINOR < 2))
static inline void skb_set_network_header(struct sk_buff *skb, const int offset)
{
  skb->nh.iph = (struct iphdr *)skb->data + offset;
}

static inline void skb_reset_network_header(struct sk_buff *skb)
{
  ;
}

static inline void skb_reset_transport_header(struct sk_buff *skb)
{
  ;
}
#endif
#endif

/* ************************************************** */

static inline char* get_slot(struct pf_ring_socket *pfr, u_int32_t off) { return(&(pfr->ring_slots[off])); }

/* ********************************** */

/* ********************************** */

static inline int get_next_slot_offset(struct pf_ring_socket *pfr, u_int32_t off, 
				       u_int32_t caplen, u_int32_t parsed_header_len)
{
  u_int32_t real_slot_size = pfr->slot_header_len + caplen + parsed_header_len;

  if((off + real_slot_size + pfr->slots_info->slot_len) > (pfr->slots_info->tot_mem - sizeof(FlowSlotInfo))) {
    return 0;
  }

  return (off + real_slot_size);
}

/* ********************************** */

static inline u_int32_t num_queued_pkts(struct pf_ring_socket *pfr)
{
  // smp_rmb();

  if(pfr->ring_slots != NULL) {
    u_int32_t tot_insert = atomic_read(&pfr->slots_info->tot_insert), tot_read = pfr->slots_info->tot_read;

    if(tot_insert >= tot_read) {
      return(tot_insert - tot_read);
    } else {
      return(((u_int32_t) - 1) + tot_insert - tot_read);
    }

    if(unlikely(enable_debug)) {
      printk("[PF_RING] -> [tot_insert=%d][tot_read=%d]\n",
	     tot_insert, tot_read);
    }
  } else
    return(0);
}

/* ************************************* */

inline u_int get_num_ring_free_slots(struct pf_ring_socket * pfr)
{
  u_int32_t nqpkts = num_queued_pkts(pfr);

  if(nqpkts < (pfr->slots_info->min_num_slots))
    return(pfr->slots_info->min_num_slots - nqpkts);
  else
    return(0);
}

/* ********************************** */

static inline int check_free_slot(struct pf_ring_socket *pfr, int off)
{
  // smp_rmb();

  if(atomic_read(&pfr->slots_info->insert_off) == pfr->slots_info->remove_off) {
    /*
      Both insert and remove offset are set on the same slot.
      We need to find out whether the memory is full or empty
    */

    if(num_queued_pkts(pfr) >= min_num_slots)
      return(0); /* Memory is full */
  } else {
    /* There are packets in the ring. We have to check whether we have enough to accommodate a new packet */

    if(atomic_read(&pfr->slots_info->insert_off) < pfr->slots_info->remove_off) {

      /* Zero-copy recv: this prevents from overwriting packets while apps are processing them */
      if((pfr->slots_info->remove_off - atomic_read(&pfr->slots_info->insert_off)) < (2 * pfr->slots_info->slot_len))
	return(0);
    } else {
      /* We have enough room for the incoming packet as after we insert a packet, the insert_off
	 offset is wrapped to the beginning in case the space remaining is less than slot_len
	 (i.e. the memory needed to accommodate a packet)
      */

      /* Zero-copy recv: this prevents from overwriting packets while apps are processing them */
      if((pfr->slots_info->tot_mem - sizeof(FlowSlotInfo) - atomic_read(&pfr->slots_info->insert_off)) < (2 * pfr->slots_info->slot_len) &&
	 pfr->slots_info->remove_off == 0)
	return(0);
    }
  }

  return(1);
}

/* ********************************** */

#define IP_DEFRAG_RING 1234

/* Returns new sk_buff, or NULL  */
static struct sk_buff *ring_gather_frags(struct sk_buff *skb)
{
#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23))
  skb
#else
  int status
#endif
  = ip_defrag(skb, IP_DEFRAG_RING);

  if(
#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23))
  skb == NULL
#else
  status
#endif
  )
    skb = NULL;
  else
    ip_send_check(ip_hdr(skb));

  return(skb);
}

/* ********************************** */

static void ring_sock_destruct(struct sock *sk)
{
  struct pf_ring_socket *pfr;

  skb_queue_purge(&sk->sk_receive_queue);

  if(!sock_flag(sk, SOCK_DEAD)) {
    if(unlikely(enable_debug)) {
      printk("[PF_RING] Attempt to release alive ring socket: %p\n", sk);
    }
    return;
  }

  pfr = ring_sk(sk);

  if(pfr)
    kfree(pfr);
}

/* ********************************** */

static void ring_proc_add(struct pf_ring_socket *pfr)
{
  if((ring_proc_dir != NULL)
     && (pfr->sock_proc_name[0] == '\0')) {
    snprintf(pfr->sock_proc_name, sizeof(pfr->sock_proc_name),
	     "%d-%s.%d", pfr->ring_pid,
	     pfr->ring_netdev->dev->name, pfr->ring_id);

    create_proc_read_entry(pfr->sock_proc_name, 0 /* read-only */,
			   ring_proc_dir,
			   ring_proc_get_info, pfr);

    if(unlikely(enable_debug))
      printk("[PF_RING] Added /proc/net/pf_ring/%s\n", pfr->sock_proc_name);

    ring_table_size++;
  }
}

/* ********************************** */

static void ring_proc_remove(struct pf_ring_socket *pfr)
{
  if((ring_proc_dir != NULL)
     && (pfr->sock_proc_name[0] != '\0')) {
    if(unlikely(enable_debug))
      printk("[PF_RING] Removing /proc/net/pf_ring/%s\n", pfr->sock_proc_name);

    remove_proc_entry(pfr->sock_proc_name, ring_proc_dir);

    if(unlikely(enable_debug))
      printk("[PF_RING] Removed /proc/net/pf_ring/%s\n", pfr->sock_proc_name);

    pfr->sock_proc_name[0] = '\0';
    ring_table_size--;
  }
}

/* ********************************** */

static int ring_proc_dev_get_info(char *buf, char **start, off_t offset,
				  int len, int *unused, void *data)
{
  int rlen = 0;

  if(data != NULL) {
    ring_device_element *dev_ptr = (ring_device_element*)data;
    struct net_device *dev = dev_ptr->dev;
    char dev_buf[16] = { 0 }, *dev_family = "???";

    if(dev_ptr->is_dna_device) {
      switch(dev_ptr->dna_device_model) {
      case intel_e1000e:
	dev_family = "Intel e1000e"; break;
      case intel_igb:
	dev_family = "Intel igb"; break;
	break;
      case intel_igb_82580:
	dev_family = "Intel igb 82580"; break;
	break;
      case intel_ixgbe:
	dev_family = "Intel ixgbe"; break;
	break;
      case intel_ixgbe_82598:
	dev_family = "Intel ixgbe 82598"; break;
	break;
      case intel_ixgbe_82599:
	dev_family = "Intel ixgbe 82599"; break;
	break;
      }
    } else {
      switch(dev_ptr->device_type) {
      case standard_nic_family: dev_family = "Standard NIC"; break;
      case intel_82599_family:  dev_family = "Intel 82599"; break;
      }
    }

    rlen =  sprintf(buf,      "Name:              %s\n", dev->name);
    rlen += sprintf(buf+rlen, "Index:             %d\n", dev->ifindex);
    rlen += sprintf(buf+rlen, "Address:           %02X:%02X:%02X:%02X:%02X:%02X\n",
		    dev->perm_addr[0], dev->perm_addr[1], dev->perm_addr[2],
		    dev->perm_addr[3], dev->perm_addr[4], dev->perm_addr[5]);

    rlen += sprintf(buf+rlen, "Polling Mode:      %s\n", dev_ptr->is_dna_device ? "DNA" : "NAPI/TNAPI");

    switch(dev->type) {
    case 1:   strcpy(dev_buf, "Ethernet"); break;
    case 772: strcpy(dev_buf, "Loopback"); break;
    default: sprintf(dev_buf, "%d", dev->type); break;
    }

    rlen += sprintf(buf+rlen, "Type:              %s\n", dev_buf);
    rlen += sprintf(buf+rlen, "Family:            %s\n", dev_family);

    if(!dev_ptr->is_dna_device) {
      if(dev->ifindex < MAX_NUM_IFIDX) {
	rlen += sprintf(buf+rlen, "# Bound Sockets:   %d\n",
			num_rings_per_device[dev->ifindex]);
      }
    }

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
    rlen += sprintf(buf+rlen, "Max # TX Queues:   %d\n", dev->num_tx_queues);
#endif

    rlen += sprintf(buf+rlen, "# Used RX Queues:  %d\n",
		    dev_ptr->is_dna_device ? dev_ptr->num_dna_rx_queues : get_num_rx_queues(dev));
  }

  return rlen;
}

/* **************** 82599 ****************** */

static int i82599_generic_handler(struct pf_ring_socket *pfr,
				  hw_filtering_rule *rule, hw_filtering_rule_command request) {
  int rc = -1;

#ifdef I82599_HW_FILTERING_SUPPORT
  struct net_device *dev = pfr->ring_netdev->dev;
  intel_82599_five_tuple_filter_hw_rule *ftfq_rule;
  intel_82599_perfect_filter_hw_rule *perfect_rule;
  struct ethtool_rxnfc cmd;
  struct ethtool_rx_flow_spec *fsp = (struct ethtool_rx_flow_spec *) &cmd.fs;

  if(dev == NULL) return(-1);

  if((dev->ethtool_ops == NULL) || (dev->ethtool_ops->set_rxnfc == NULL)) return(-1);

  if(unlikely(enable_debug))
    printk("[PF_RING] hw_filtering_rule[%s][request=%d][%p]\n",
	   dev->name, request, dev->ethtool_ops->set_rxnfc);

  memset(&cmd, 0, sizeof(struct ethtool_rxnfc));

  switch (rule->rule_family_type) {
    case intel_82599_five_tuple_rule:
      ftfq_rule = &rule->rule_family.five_tuple_rule;

      fsp->h_u.tcp_ip4_spec.ip4src = ftfq_rule->s_addr;
      fsp->h_u.tcp_ip4_spec.psrc   = ftfq_rule->s_port;
      fsp->h_u.tcp_ip4_spec.ip4dst = ftfq_rule->d_addr;
      fsp->h_u.tcp_ip4_spec.pdst   = ftfq_rule->d_port;
      fsp->flow_type   = ftfq_rule->proto;
      fsp->ring_cookie = ftfq_rule->queue_id;
      fsp->location    = rule->rule_id;

      cmd.cmd = (request == add_hw_rule ? ETHTOOL_PFRING_SRXFTRLINS : ETHTOOL_PFRING_SRXFTRLDEL);

      break;

    case intel_82599_perfect_filter_rule:
      perfect_rule = &rule->rule_family.perfect_rule;

      fsp->ring_cookie = perfect_rule->queue_id;
      fsp->location    = rule->rule_id;

      if (perfect_rule->s_addr) {
        fsp->h_u.tcp_ip4_spec.ip4src = htonl(perfect_rule->s_addr);
        fsp->m_u.tcp_ip4_spec.ip4src = 0xFFFFFFFF;
      }

      if (perfect_rule->d_addr) {
        fsp->h_u.tcp_ip4_spec.ip4dst = htonl(perfect_rule->d_addr);
        fsp->m_u.tcp_ip4_spec.ip4dst = 0xFFFFFFFF;
      }

      if (perfect_rule->s_port) {
        fsp->h_u.tcp_ip4_spec.psrc = htons(perfect_rule->s_port);
        fsp->m_u.tcp_ip4_spec.psrc = 0xFFFF;
      }

      if (perfect_rule->d_port) {
        fsp->h_u.tcp_ip4_spec.pdst = htons(perfect_rule->d_port);
        fsp->m_u.tcp_ip4_spec.pdst = 0xFFFF;
      }

      if (perfect_rule->vlan_id) {
        fsp->h_ext.vlan_tci = perfect_rule->vlan_id;
	fsp->m_ext.vlan_tci = 0xFFF; // VLANID meaningful, VLAN priority ignored
	/* fsp->h_ext.vlan_etype
	 * fsp->m_ext.vlan_etype */
	fsp->flow_type |= FLOW_EXT;
      }

      switch (perfect_rule->proto) {
	case 6:   /* TCP */
          fsp->flow_type = TCP_V4_FLOW;
	  break;
	case 132: /* SCTP */
	  fsp->flow_type = SCTP_V4_FLOW;
	  break;
	case 17:  /* UDP */
	  fsp->flow_type = UDP_V4_FLOW;
	  break;
	default: /* * */
	  fsp->flow_type = IP_USER_FLOW;
	  break;
      }

      cmd.cmd = (request == add_hw_rule ? ETHTOOL_SRXCLSRLINS : ETHTOOL_SRXCLSRLDEL);

      break;

    default:
      break;
  }

  if (cmd.cmd) {

    rc = dev->ethtool_ops->set_rxnfc(dev, &cmd);

    if (unlikely(enable_debug)
     && rule->rule_family_type == intel_82599_perfect_filter_rule
     && rc < 0) {
      intel_82599_perfect_filter_hw_rule *perfect_rule = &rule->rule_family.perfect_rule;
      printk("[DNA][DEBUG] %s() ixgbe_set_rxnfc(%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d) returned %d\n",
    	     __FUNCTION__,
             perfect_rule->s_addr >> 24 & 0xFF, perfect_rule->s_addr >> 16 & 0xFF,
             perfect_rule->s_addr >>  8 & 0xFF, perfect_rule->s_addr >>  0 & 0xFF,
             perfect_rule->s_port & 0xFFFF,
             perfect_rule->d_addr >> 24 & 0xFF, perfect_rule->d_addr >> 16 & 0xFF,
             perfect_rule->d_addr >>  8 & 0xFF, perfect_rule->d_addr >>  0 & 0xFF,
             perfect_rule->d_port & 0xFFFF,
	     rc);
    }
  }
#endif
  return(rc);
}

/* ************************************* */

static int handle_hw_filtering_rule(struct pf_ring_socket *pfr,
				    hw_filtering_rule *rule,
				    hw_filtering_rule_command command) {

  if(unlikely(enable_debug))
    printk("[PF_RING] --> handle_hw_filtering_rule(command=%d)\n", command);

  switch(rule->rule_family_type) {
  case intel_82599_five_tuple_rule:
    if(pfr->ring_netdev->hw_filters.filter_handlers.five_tuple_handler == NULL)
      return(-EINVAL);
    else
      return(i82599_generic_handler(pfr, rule, command));
    break;

  case intel_82599_perfect_filter_rule:
    if(pfr->ring_netdev->hw_filters.filter_handlers.perfect_filter_handler == NULL)
      return(-EINVAL);
    else
      return(i82599_generic_handler(pfr, rule, command));
    break;

  case silicom_redirector_rule:
    return(-EINVAL); /* handled in userland */
    break;
  }

  return(-EINVAL);
}

/* ***************************************** */

#ifdef ENABLE_PROC_WRITE_RULE
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
static int ring_proc_dev_rule_read(char *buf, char **start, off_t offset,
				   int len, int *unused, void *data)
{
  int rlen = 0;

  if(data != NULL) {
    ring_device_element *dev_ptr = (ring_device_element*)data;
    struct net_device *dev = dev_ptr->dev;

    rlen =  sprintf(buf,      "Name:              %s\n", dev->name);
    rlen += sprintf(buf+rlen, "# Filters:         %d\n", dev_ptr->hw_filters.num_filters);
    rlen += sprintf(buf+rlen, "\nFiltering Rules:\n"
		    "[perfect rule]  +|-(rule_id,queue_id,vlan,tcp|udp,src_ip/mask,src_port,dst_ip/mask,dst_port)\n"
		    "Example:\t+(1,-1,0,tcp,192.168.0.10/32,25,10.6.0.0/16,0) (queue_id = -1 => drop)\n\n"
		    "[5 tuple rule]  +|-(rule_id,queue_id,tcp|udp,src_ip,src_port,dst_ip,dst_port)\n"
		    "Example:\t+(1,-1,tcp,192.168.0.10,25,0.0.0.0,0)\n\n"
		    "Note:\n\t- queue_id = -1 => drop\n\t- 0 = ignore value\n");
  }

  return rlen;
}
#endif

/* ********************************** */

#ifdef ENABLE_PROC_WRITE_RULE
static void init_intel_82599_five_tuple_filter_hw_rule(u_int8_t queue_id, u_int8_t proto,
						       u_int32_t s_addr, u_int32_t d_addr,
						       u_int16_t s_port, u_int16_t d_port,
						       intel_82599_five_tuple_filter_hw_rule *rule) {

  /* printk("init_intel_82599_five_tuple_filter_hw_rule()\n"); */

  memset(rule, 0, sizeof(intel_82599_five_tuple_filter_hw_rule));

  rule->queue_id = queue_id, rule->proto = proto;
  rule->s_addr = s_addr, rule->d_addr = d_addr;
  rule->s_port = s_port, rule->d_port = d_port;
}

/* ********************************** */

static void init_intel_82599_perfect_filter_hw_rule(u_int8_t queue_id,
						    u_int8_t proto, u_int16_t vlan,
						    u_int32_t s_addr, u_int8_t s_mask,
						    u_int32_t d_addr, u_int8_t d_mask,
						    u_int16_t s_port, u_int16_t d_port,
						    intel_82599_perfect_filter_hw_rule *rule) {
  u_int32_t netmask;

  /* printk("init_intel_82599_perfect_filter_hw_rule()\n"); */

  memset(rule, 0, sizeof(intel_82599_perfect_filter_hw_rule));

  rule->queue_id = queue_id, rule->vlan_id = vlan, rule->proto = proto;

  rule->s_addr = s_addr;
  if(s_mask == 32) netmask = 0xFFFFFFFF; else netmask = ~(0xFFFFFFFF >> s_mask);
  rule->s_addr &= netmask;

  rule->d_addr = d_addr;
  if(d_mask == 32) netmask = 0xFFFFFFFF; else netmask = ~(0xFFFFFFFF >> d_mask);
  rule->d_addr &= netmask;

  rule->s_port = s_port, rule->d_port = d_port;
}

#endif /* ENABLE_PROC_WRITE_RULE */

/* ********************************** */

#ifdef ENABLE_PROC_WRITE_RULE
static int ring_proc_dev_rule_write(struct file *file,
				    const char __user *buffer,
				    unsigned long count, void *data)
{
  char buf[128], add, proto[4] = { 0 };
  ring_device_element *dev_ptr = (ring_device_element*)data;
  int num, queue_id, vlan, rc, rule_id, protocol;
  int s_a, s_b, s_c, s_d, s_mask, s_port;
  int d_a, d_b, d_c, d_d, d_mask, d_port;
  hw_filtering_rule_request rule;
  u_int8_t found = 0;
  int debug = 0;

  if(data == NULL) return(0);

  if(count > (sizeof(buf)-1))             count = sizeof(buf) - 1;
  if(copy_from_user(buf, buffer, count))  return(-EFAULT);
  buf[sizeof(buf)-1] = '\0', buf[count] = '\0';

  if(unlikely(enable_debug)) printk("[PF_RING] ring_proc_dev_rule_write(%s)\n", buf);

  num = sscanf(buf, "%c(%d,%d,%d,%c%c%c,%d.%d.%d.%d/%d,%d,%d.%d.%d.%d/%d,%d)",
	       &add, &rule_id, &queue_id, &vlan,
	       &proto[0], &proto[1], &proto[2],
	       &s_a, &s_b, &s_c, &s_d, &s_mask, &s_port,
	       &d_a, &d_b, &d_c, &d_d, &d_mask, &d_port);

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_proc_dev_rule_write(%s): num=%d (1)\n", buf, num);

  if(num == 19) {
    if(proto[0] == 't')
      protocol = 6; /* TCP */
    else /* if(proto[0] == 'u') */
      protocol = 17; /* UDP */

    rule.rule.rule_id = rule_id;
    init_intel_82599_perfect_filter_hw_rule(queue_id, protocol, vlan,
					    ((s_a & 0xff) << 24) + ((s_b & 0xff) << 16) + ((s_c & 0xff) << 8) + (s_d & 0xff), s_mask,
					    ((d_a & 0xff) << 24) + ((d_b & 0xff) << 16) + ((d_c & 0xff) << 8) + (d_d & 0xff), d_mask,
					    s_port, d_port, &rule.rule.rule_family.perfect_rule);
    rule.rule.rule_family_type = intel_82599_perfect_filter_rule;
    found = 1;
  }

  if(!found) {
    num = sscanf(buf, "%c(%d,%d,%c%c%c,%d.%d.%d.%d,%d,%d.%d.%d.%d,%d)",
		 &add, &rule_id, &queue_id,
		 &proto[0], &proto[1], &proto[2],
		 &s_a, &s_b, &s_c, &s_d, &s_port,
		 &d_a, &d_b, &d_c, &d_d, &d_port);

    if(unlikely(enable_debug))
      printk("[PF_RING] ring_proc_dev_rule_write(%s): num=%d (2)\n", buf, num);

    if(num == 16) {
      if(proto[0] == 't')
	protocol = 6; /* TCP */
      else if(proto[0] == 'u')
	protocol = 17; /* UDP */
      else
	protocol = 0; /* any */

      rule.rule.rule_id = rule_id;
      init_intel_82599_five_tuple_filter_hw_rule(queue_id, protocol,
						 ((s_a & 0xff) << 24) + ((s_b & 0xff) << 16) + ((s_c & 0xff) << 8) + (s_d & 0xff),
						 ((d_a & 0xff) << 24) + ((d_b & 0xff) << 16) + ((d_c & 0xff) << 8) + (d_d & 0xff),
						 s_port, d_port, &rule.rule.rule_family.five_tuple_rule);
      rule.rule.rule_family_type = intel_82599_five_tuple_rule;
      found = 1;
    }
  }

  if(!found)
    return(-1);

  rule.command = (add == '+') ? add_hw_rule : remove_hw_rule;
  rc = handle_hw_filtering_rule(dev_ptr->dev, &rule);

  if(rc != -1) {
    /* Rule programmed successfully */

    if(add == '+')
      dev_ptr->hw_filters.num_filters++, pfr->num_hw_filtering_rules++;
    else {
      if(dev_ptr->hw_filters.num_filters > 0)
	dev_ptr->hw_filters.num_filters--;

      pfr->num_hw_filtering_rules--;
    }
  }

  return((int)count);
}
#endif

#endif

/* ********************************** */

static char* direction2string(packet_direction d) {
  switch(d) {
  case rx_and_tx_direction: return("RX+TX");
  case rx_only_direction:   return("RX only");
  case tx_only_direction:   return("TX only");
  }

  return("???");
}

/* ********************************** */

static int ring_proc_get_info(char *buf, char **start, off_t offset,
			      int len, int *unused, void *data)
{
  int rlen = 0;
  struct pf_ring_socket *pfr;
  FlowSlotInfo *fsi;

  if(data == NULL) {
    /* /proc/net/pf_ring/info */
    rlen = sprintf(buf, "PF_RING Version     : %s ($Revision: %s$)\n", RING_VERSION, SVN_REV);
    rlen += sprintf(buf + rlen, "Ring slots          : %d\n", min_num_slots);
    rlen += sprintf(buf + rlen, "Slot version        : %d\n", RING_FLOWSLOT_VERSION);
    rlen += sprintf(buf + rlen, "Capture TX          : %s\n", enable_tx_capture ? "Yes [RX+TX]" : "No [RX only]");
    rlen += sprintf(buf + rlen, "IP Defragment       : %s\n", enable_ip_defrag ? "Yes" : "No");
    rlen += sprintf(buf + rlen, "Socket Mode         : %s\n", quick_mode ? "Quick" : "Standard");
    rlen += sprintf(buf + rlen, "Transparent mode    : %s\n",
		    (transparent_mode == standard_linux_path ? "Yes (mode 0)" :
		     (transparent_mode == driver2pf_ring_transparent ? "Yes (mode 1)" : "No (mode 2)")));
    rlen += sprintf(buf + rlen, "Total rings         : %d\n", ring_table_size);
    rlen += sprintf(buf + rlen, "Total plugins       : %d\n", plugin_registration_size);
  } else {
    /* detailed statistics about a PF_RING */
    pfr = (struct pf_ring_socket *)data;

    if(data) {
      fsi = pfr->slots_info;

      if(fsi) {
	int num = 0;
	struct list_head *ptr, *tmp_ptr;
	
	rlen = sprintf(buf,         "Bound Device(s)    : ");

	list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
	  ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);
	  
	  if(test_bit(dev_ptr->dev->ifindex, pfr->netdev_mask)) {
	    rlen += sprintf(buf + rlen, "%s%s", (num > 0) ? "," : "", dev_ptr->dev->name);
	    num++;
	  }
	}

	rlen += sprintf(buf + rlen, "\n");

	rlen += sprintf(buf + rlen, "Slot Version       : %d [%s]\n", fsi->version, RING_VERSION);
	rlen += sprintf(buf + rlen, "Active             : %d\n", pfr->ring_active);
	rlen += sprintf(buf + rlen, "Breed              : %s\n", (pfr->dna_device_entry != NULL) ? "DNA" : "Non-DNA");
	rlen += sprintf(buf + rlen, "Sampling Rate      : %d\n", pfr->sample_rate);
	rlen += sprintf(buf + rlen, "Capture Direction  : %s\n", direction2string(pfr->direction));
	rlen += sprintf(buf + rlen, "Appl. Name         : %s\n", pfr->appl_name ? pfr->appl_name : "<unknown>");
	rlen += sprintf(buf + rlen, "IP Defragment      : %s\n", enable_ip_defrag ? "Yes" : "No");
	rlen += sprintf(buf + rlen, "BPF Filtering      : %s\n", pfr->bpfFilter ? "Enabled" : "Disabled");
	rlen += sprintf(buf + rlen, "# Sw Filt. Rules   : %d\n", pfr->num_sw_filtering_rules);
	rlen += sprintf(buf + rlen, "# Hw Filt. Rules   : %d\n", pfr->num_hw_filtering_rules);
	rlen += sprintf(buf + rlen, "Poll Pkt Watermark : %d\n", pfr->poll_num_pkts_watermark);
	rlen += sprintf(buf + rlen, "Num Poll Calls     : %u\n", pfr->num_poll_calls);

	if(pfr->dna_device_entry != NULL) {
	  /* DNA */
	  rlen += sprintf(buf + rlen, "Channel Id         : %d\n", pfr->dna_device_entry->dev.channel_id);
          rlen += sprintf(buf + rlen, "Num RX Slots       : %d\n", pfr->dna_device_entry->dev.mem_info.rx.packet_memory_num_slots);
	  rlen += sprintf(buf + rlen, "Num TX Slots       : %d\n", pfr->dna_device_entry->dev.mem_info.tx.packet_memory_num_slots);
	  rlen += sprintf(buf + rlen, "Tot Memory         : %u bytes\n",
			  ( pfr->dna_device_entry->dev.mem_info.rx.packet_memory_num_chunks *
			    pfr->dna_device_entry->dev.mem_info.rx.packet_memory_chunk_len   )
			  +(pfr->dna_device_entry->dev.mem_info.tx.packet_memory_num_chunks *
			    pfr->dna_device_entry->dev.mem_info.tx.packet_memory_chunk_len   )
			  + pfr->dna_device_entry->dev.mem_info.rx.descr_packet_memory_tot_len
			  + pfr->dna_device_entry->dev.mem_info.tx.descr_packet_memory_tot_len);
	} else {
	  rlen += sprintf(buf + rlen, "Channel Id         : %d\n", pfr->channel_id);
	  rlen += sprintf(buf + rlen, "Cluster Id         : %d\n", pfr->cluster_id);
	  rlen += sprintf(buf + rlen, "Min Num Slots      : %d\n", fsi->min_num_slots);
	  rlen += sprintf(buf + rlen, "Bucket Len         : %d\n", fsi->data_len);
	  rlen += sprintf(buf + rlen, "Slot Len           : %d [bucket+header]\n", fsi->slot_len);
	  rlen += sprintf(buf + rlen, "Tot Memory         : %d\n", fsi->tot_mem);
	  rlen += sprintf(buf + rlen, "Tot Packets        : %lu\n", (unsigned long)atomic_read(&fsi->tot_pkts));
	  rlen += sprintf(buf + rlen, "Tot Pkt Lost       : %lu\n", (unsigned long)atomic_read(&fsi->tot_lost));
	  rlen += sprintf(buf + rlen, "Tot Insert         : %lu\n", (unsigned long)atomic_read(&fsi->tot_insert));
	  rlen += sprintf(buf + rlen, "Tot Read           : %lu\n", (unsigned long)fsi->tot_read);
	  rlen += sprintf(buf + rlen, "Insert Offset      : %lu\n", (unsigned long)atomic_read(&fsi->insert_off));
	  rlen += sprintf(buf + rlen, "Remove Offset      : %lu\n", (unsigned long)fsi->remove_off);
	  rlen += sprintf(buf + rlen, "Tot Fwd Ok         : %lu\n", (unsigned long)fsi->tot_fwd_ok);
	  rlen += sprintf(buf + rlen, "Tot Fwd Errors     : %lu\n", (unsigned long)fsi->tot_fwd_notok);
	  rlen += sprintf(buf + rlen, "Num Free Slots     : %u\n",  get_num_ring_free_slots(pfr));
	}

      } else {
	rlen = sprintf(buf, "WARNING ring not active (fsi == NULL)\n");
      }
    } else
      rlen = sprintf(buf, "WARNING data == NULL\n");
  }

  return rlen;
}

/* ********************************** */

static int ring_proc_get_plugin_info(char *buf, char **start, off_t offset,
				     int len, int *unused, void *data)
{
  int rlen = 0, i = 0;
  struct pfring_plugin_registration *tmp = NULL;

  /* FIXME: I should now the number of plugins registered */
  if(!plugin_registration_size)
    return rlen;

  /* plugins_info */

  rlen += sprintf(buf + rlen, "ID\tPlugin\n");

  for(i = 0; i < MAX_PLUGIN_ID; i++) {
    tmp = plugin_registration[i];
    if(tmp) {
      rlen += sprintf(buf + rlen, "%d\t%s [%s]\n",
		      tmp->plugin_id, tmp->name,
		      tmp->description);
    }
  }

  return rlen;
}

/* ********************************** */

static void ring_proc_init(void)
{
  ring_proc_dir = proc_mkdir("pf_ring",
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
			     init_net.
#endif
			     proc_net);

  if(ring_proc_dir) {
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
    ring_proc_dir->owner = THIS_MODULE;
#endif

    ring_proc_dev_dir = proc_mkdir(PROC_DEV, ring_proc_dir);

    ring_proc = create_proc_read_entry(PROC_INFO, 0 /* read-only */,
				       ring_proc_dir,
				       ring_proc_get_info, NULL);
    ring_proc_plugins_info =
      create_proc_read_entry(PROC_PLUGINS_INFO, 0 /* read-only */,
			     ring_proc_dir,
			     ring_proc_get_plugin_info, NULL);
    if(!ring_proc || !ring_proc_plugins_info)
      printk("[PF_RING] unable to register proc file\n");
    else {
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30))
      ring_proc->owner = THIS_MODULE;
      ring_proc_plugins_info->owner = THIS_MODULE;
#endif
      printk("[PF_RING] registered /proc/net/pf_ring/\n");
    }
  } else
    printk("[PF_RING] unable to create /proc/net/pf_ring\n");
}

/* ********************************** */

static void ring_proc_term(void)
{
  if(ring_proc != NULL) {
    remove_proc_entry(PROC_INFO, ring_proc_dir);
    if(unlikely(enable_debug))  printk("[PF_RING] removed /proc/net/pf_ring/%s\n", PROC_INFO);

    remove_proc_entry(PROC_PLUGINS_INFO, ring_proc_dir);
    if(unlikely(enable_debug)) printk("[PF_RING] removed /proc/net/pf_ring/%s\n", PROC_PLUGINS_INFO);

    remove_proc_entry(PROC_DEV, ring_proc_dir);

    if(ring_proc_dir != NULL) {
      remove_proc_entry("pf_ring",
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
			init_net.
#endif
			proc_net);
      if(unlikely(enable_debug)) printk("[PF_RING] deregistered /proc/net/pf_ring\n");
    }
  }
}

/* ********************************** */

/*
 * Allocate ring memory used later on for
 * mapping it to userland
 */
static int ring_alloc_mem(struct sock *sk)
{
  u_int the_slot_len;
  u_int32_t tot_mem;
  struct pf_ring_socket *pfr = ring_sk(sk);

  /* UserSPace RING
   * - producer attaching to a ring
   * - or consumer re-opening an old ring already attachred */
  if(pfr->userspace_ring != NULL
      && (pfr->userspace_ring_type == userspace_ring_producer
          || (pfr->userspace_ring_type == userspace_ring_consumer
	      && pfr->userspace_ring->ring_memory != NULL))) {

    if(pfr->userspace_ring->ring_memory == NULL)
      return (-1); /* Consumr ring memory has not yet been allocated */

    pfr->slot_header_len = pfr->userspace_ring->slot_header_len;
    pfr->bucket_len      = pfr->userspace_ring->bucket_len;

    pfr->ring_memory     = pfr->userspace_ring->ring_memory;
    pfr->slots_info      = (FlowSlotInfo *) pfr->ring_memory;
    pfr->ring_slots      = (char *) (pfr->ring_memory + sizeof(FlowSlotInfo));

    pfr->insert_page_id = 1, pfr->insert_slot_id = 0;
    pfr->sw_filtering_rules_default_accept_policy = 1;
    pfr->num_sw_filtering_rules = pfr->num_hw_filtering_rules = 0;
  }

  /* Check if the memory has been already allocated */
  if(pfr->ring_memory != NULL) return(0);

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_alloc_mem(bucket_len=%d)\n", pfr->bucket_len);

  /* **********************************************

   * *************************************
   * *                                   *
   * *        FlowSlotInfo               *
   * *                                   *
   * ************************************* <-+
   * *        FlowSlot                   *   |
   * *************************************   |
   * *        FlowSlot                   *   |
   * *************************************   +- >= min_num_slots
   * *        FlowSlot                   *   |
   * *************************************   |
   * *        FlowSlot                   *   |
   * ************************************* <-+
   *
   * ********************************************** */

  if(quick_mode)
    pfr->slot_header_len = sizeof(struct timeval) + sizeof(u_int32_t) + sizeof(u_int32_t) + sizeof(u_int64_t) /* ts+caplen+len+timestamp_ns */;
  else
    pfr->slot_header_len = sizeof(struct pfring_pkthdr);

  the_slot_len = pfr->slot_header_len + pfr->bucket_len;

  tot_mem = PAGE_ALIGN(sizeof(FlowSlotInfo) + min_num_slots * the_slot_len);

  /* Alignment necessary on ARM platforms */
  tot_mem += SHMLBA - (tot_mem % SHMLBA);

  /* rounding size to the next power of 2 (needed by vPFRing) */
  tot_mem--;
  tot_mem |= tot_mem >> 1;
  tot_mem |= tot_mem >> 2;
  tot_mem |= tot_mem >> 4;
  tot_mem |= tot_mem >> 8;
  tot_mem |= tot_mem >> 16;
  tot_mem++;

  /* Memory is already zeroed */
  pfr->ring_memory = vmalloc_user(tot_mem);

  if(pfr->ring_memory != NULL) {
    if(unlikely(enable_debug))
      printk("[PF_RING] successfully allocated %lu bytes at 0x%08lx\n",
	     (unsigned long)tot_mem, (unsigned long)pfr->ring_memory);
  } else {
    printk("[PF_RING] ERROR: not enough memory for ring\n");
    return(-1);
  }

  pfr->slots_info = (FlowSlotInfo *) pfr->ring_memory;
  pfr->ring_slots = (char *)(pfr->ring_memory + sizeof(FlowSlotInfo));

  pfr->slots_info->version = RING_FLOWSLOT_VERSION;
  pfr->slots_info->slot_len = the_slot_len;
  pfr->slots_info->data_len = pfr->bucket_len;
  pfr->slots_info->min_num_slots = (tot_mem - sizeof(FlowSlotInfo)) / the_slot_len;
  pfr->slots_info->tot_mem = tot_mem;
  pfr->slots_info->sample_rate = 1;

  if(unlikely(enable_debug))
    printk("[PF_RING] allocated %d slots [slot_len=%d][tot_mem=%u]\n",
	   pfr->slots_info->min_num_slots, pfr->slots_info->slot_len,
	   pfr->slots_info->tot_mem);

  pfr->insert_page_id = 1, pfr->insert_slot_id = 0;
  pfr->sw_filtering_rules_default_accept_policy = 1;
  pfr->num_sw_filtering_rules = pfr->num_hw_filtering_rules = 0;

  /* UserSPace RING
   * - consumer creating a new ring */
  if(pfr->userspace_ring != NULL && pfr->userspace_ring_type == userspace_ring_consumer) {
    pfr->userspace_ring->slot_header_len = pfr->slot_header_len;
    pfr->userspace_ring->bucket_len      = pfr->bucket_len;
    pfr->userspace_ring->tot_mem         = pfr->slots_info->tot_mem;
    pfr->userspace_ring->ring_memory     = pfr->ring_memory;
  }

  return(0);
}

/* ********************************** */

/*
 * ring_insert()
 *
 * store the sk in a new element and add it
 * to the head of the list.
 */
static inline void ring_insert(struct sock *sk)
{
  struct ring_element *next;
  struct pf_ring_socket *pfr;

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_insert()\n");

  next = kmalloc(sizeof(struct ring_element), GFP_ATOMIC);
  if(next != NULL) {
    next->sk = sk;
    ring_write_lock();
    list_add(&next->list, &ring_table);
    ring_write_unlock();
  } else {
    if(net_ratelimit())
      printk("[PF_RING] net_ratelimit() failure\n");
  }

  pfr = (struct pf_ring_socket *)ring_sk(sk);
  pfr->ring_pid = current->pid;
  bitmap_zero(pfr->netdev_mask, MAX_NUM_DEVICES_ID), pfr->num_bound_devices = 0;
}

/* ********************************** */

/*
 * ring_remove()
 *
 * For each of the elements in the list:
 *  - check if this is the element we want to delete
 *  - if it is, remove it from the list, and free it.
 *
 * stop when we find the one we're looking for(break),
 * or when we reach the end of the list.
 */
static inline void ring_remove(struct sock *sk)
{
  struct list_head *ptr, *tmp_ptr;
  struct ring_element *entry, *to_delete = NULL;
  struct pf_ring_socket *pfr_to_delete = ring_sk(sk);
  u_int8_t master_found = 0, socket_found = 0;

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_remove()\n");

  list_for_each_safe(ptr, tmp_ptr, &ring_table) {
    struct pf_ring_socket *pfr;

    entry = list_entry(ptr, struct ring_element, list);
    pfr = ring_sk(entry->sk);

    if(pfr->master_ring == pfr_to_delete) {
      if(unlikely(enable_debug))
	printk("[PF_RING] Removing master ring\n");

      pfr->master_ring = NULL, master_found = 1;
    } else if(entry->sk == sk) {
      if(unlikely(enable_debug))
	printk("[PF_RING] Found socket to remove\n");

      list_del(ptr);
      to_delete = entry;
      socket_found = 1;
    }

    if(master_found && socket_found) break;
  }

  if(to_delete) kfree(to_delete);

  if(unlikely(enable_debug))
    printk("[PF_RING] leaving ring_remove()\n");
}

/* ********************************** */

inline u_int32_t hash_pkt(u_int16_t vlan_id, u_int8_t proto,
			  ip_addr host_peer_a, ip_addr host_peer_b,
			  u_int16_t port_peer_a, u_int16_t port_peer_b)
{
  return(vlan_id+proto+
	 host_peer_a.v6.s6_addr32[0]+host_peer_a.v6.s6_addr32[1]+
	 host_peer_a.v6.s6_addr32[2]+host_peer_a.v6.s6_addr32[3]+
	 host_peer_b.v6.s6_addr32[0]+host_peer_b.v6.s6_addr32[1]+
	 host_peer_b.v6.s6_addr32[2]+host_peer_b.v6.s6_addr32[3]+
	 port_peer_a+port_peer_b);
}

/* ********************************** */

inline u_int32_t hash_pkt_header(struct pfring_pkthdr * hdr, u_char mask_src, u_char mask_dst,
				 u_char mask_port, u_char mask_proto, u_char mask_vlan)
{
  if(hdr->extended_hdr.pkt_hash == 0)
    hdr->extended_hdr.pkt_hash = hash_pkt(mask_vlan  ? 0 : hdr->extended_hdr.parsed_pkt.vlan_id,
					  mask_proto ? 0 : hdr->extended_hdr.parsed_pkt.l3_proto,
					  mask_src ? ip_zero : hdr->extended_hdr.parsed_pkt.ip_src,
					  mask_dst ? ip_zero : hdr->extended_hdr.parsed_pkt.ip_dst,
					  (mask_src || mask_port) ? 0 : hdr->extended_hdr.parsed_pkt.l4_src_port,
					  (mask_dst || mask_port) ? 0 : hdr->extended_hdr.parsed_pkt.l4_dst_port);

  return(hdr->extended_hdr.pkt_hash);
}

/* ******************************************************* */

static int parse_raw_pkt(char *data, u_int data_len,
			 struct pfring_pkthdr *hdr, u_int8_t reset_all)
{
  struct ethhdr *eh = (struct ethhdr *)data;
  u_int16_t displ, ip_len;

  if(reset_all)
    memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(hdr->extended_hdr.parsed_pkt));
  else
    memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(hdr->extended_hdr.parsed_pkt)-sizeof(packet_user_detail) /* Preserve user data */);

  if(data_len < sizeof(struct ethhdr)) return(0);

  /* MAC address */
  memcpy(&hdr->extended_hdr.parsed_pkt.dmac, eh->h_dest, sizeof(eh->h_dest));
  memcpy(&hdr->extended_hdr.parsed_pkt.smac, eh->h_source, sizeof(eh->h_source));

  hdr->extended_hdr.parsed_pkt.eth_type = ntohs(eh->h_proto);
  hdr->extended_hdr.parsed_pkt.offset.eth_offset = 0;

  if(hdr->extended_hdr.parsed_pkt.eth_type == ETH_P_8021Q /* 802.1q (VLAN) */) {
    hdr->extended_hdr.parsed_pkt.offset.vlan_offset =
      hdr->extended_hdr.parsed_pkt.offset.eth_offset + sizeof(struct ethhdr);

    hdr->extended_hdr.parsed_pkt.vlan_id =
      (data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset] & 15) * 256 +
      data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset + 1];
    hdr->extended_hdr.parsed_pkt.eth_type =
      (data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset + 2]) * 256 +
      data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset + 3];
    displ = 4;
  } else {
    displ = 0;
    hdr->extended_hdr.parsed_pkt.vlan_id = 0; /* Any VLAN */
  }

  if(unlikely(enable_debug))
    printk("[PF_RING] [eth_type=%04X]\n", hdr->extended_hdr.parsed_pkt.eth_type);

  if(hdr->extended_hdr.parsed_pkt.eth_type == ETH_P_IP /* IPv4 */ ) {
    struct iphdr *ip;

    hdr->extended_hdr.parsed_pkt.offset.l3_offset = hdr->extended_hdr.parsed_pkt.offset.eth_offset + displ + sizeof(struct ethhdr);

    if(data_len < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct iphdr)) return(0);

    ip = (struct iphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);

    hdr->extended_hdr.parsed_pkt.ipv4_src = ntohl(ip->saddr);
    hdr->extended_hdr.parsed_pkt.ipv4_dst = ntohl(ip->daddr);
    hdr->extended_hdr.parsed_pkt.l3_proto = ip->protocol;
    hdr->extended_hdr.parsed_pkt.ipv4_tos = ip->tos;
    hdr->extended_hdr.parsed_pkt.ip_version = 4;
    ip_len  = ip->ihl*4;
  } else if(hdr->extended_hdr.parsed_pkt.eth_type == ETH_P_IPV6 /* IPv6 */) {
    struct ipv6hdr *ipv6;

    hdr->extended_hdr.parsed_pkt.ip_version = 6;
    ip_len = 40;

    hdr->extended_hdr.parsed_pkt.offset.l3_offset = hdr->extended_hdr.parsed_pkt.offset.eth_offset+displ+sizeof(struct ethhdr);

    if(data_len < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct ipv6hdr)) return(0);

    ipv6 = (struct ipv6hdr*)(&data[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);

    /* Values of IPv6 addresses are stored as network byte order */
    hdr->extended_hdr.parsed_pkt.ipv6_src = ipv6->saddr;
    hdr->extended_hdr.parsed_pkt.ipv6_dst = ipv6->daddr;

    hdr->extended_hdr.parsed_pkt.l3_proto = ipv6->nexthdr;
    hdr->extended_hdr.parsed_pkt.ipv6_tos = ipv6->priority; /* IPv6 class of service */

    /*
      RFC2460 4.1  Extension Header Order
      IPv6 header
      Hop-by-Hop Options header
      Destination Options header
      Routing header
      Fragment header
      Authentication header
      Encapsulating Security Payload header
      Destination Options header
      upper-layer header
    */

    while(hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_HOP	   ||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_DEST	   ||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ROUTING ||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_AUTH	   ||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ESP	   ||
	  hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_FRAGMENT) {
	struct ipv6_opt_hdr *ipv6_opt;
	ipv6_opt = (struct ipv6_opt_hdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l3_offset+ip_len]);
	ip_len += 8;
	if(hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_AUTH)
	  /*
	    RFC4302 2.2. Payload Length: This 8-bit field specifies the
	    length of AH in 32-bit words (4-byte units), minus "2".
	  */
	  ip_len += ipv6_opt->hdrlen * 4;
	else if(hdr->extended_hdr.parsed_pkt.l3_proto != NEXTHDR_FRAGMENT)
	  ip_len += ipv6_opt->hdrlen;

	hdr->extended_hdr.parsed_pkt.l3_proto = ipv6_opt->nexthdr;
      }
  } else {
    hdr->extended_hdr.parsed_pkt.l3_proto = 0;
    return(0); /* No IP */
  }

  if(unlikely(enable_debug))
    printk("[PF_RING] [l3_proto=%d]\n", hdr->extended_hdr.parsed_pkt.l3_proto);

  if((hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP) || (hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP)) {
    hdr->extended_hdr.parsed_pkt.offset.l4_offset = hdr->extended_hdr.parsed_pkt.offset.l3_offset+ip_len;

    if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP) {
      struct tcphdr *tcp;

      if(data_len < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct tcphdr)) return(0);

      tcp = (struct tcphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

      hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(tcp->source), hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(tcp->dest);
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + (tcp->doff * 4);
      hdr->extended_hdr.parsed_pkt.tcp.seq_num = ntohl(tcp->seq), hdr->extended_hdr.parsed_pkt.tcp.ack_num = ntohl(tcp->ack_seq);
      hdr->extended_hdr.parsed_pkt.tcp.flags = (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) +
	(tcp->rst * TH_RST_MULTIPLIER) + (tcp->psh * TH_PUSH_MULTIPLIER) +
	(tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);
    } else if(hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP) {
      struct udphdr *udp;

      if(data_len < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr)) return(0);

      udp = (struct udphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

      hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(udp->source), hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(udp->dest);
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr);
    } else
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;

    if(unlikely(enable_debug))
      printk("[PF_RING] [l4_offset=%d][l4_src_port/l4_dst_port=%d/%d]\n",
	     hdr->extended_hdr.parsed_pkt.offset.l4_offset,
	     hdr->extended_hdr.parsed_pkt.l4_src_port,
	     hdr->extended_hdr.parsed_pkt.l4_dst_port);
  } else
    hdr->extended_hdr.parsed_pkt.l4_src_port = hdr->extended_hdr.parsed_pkt.l4_dst_port = 0;

  hash_pkt_header(hdr, 0, 0, 0, 0, 0);

  return(1); /* IP */
}

/* ********************************** */

static int parse_pkt(struct sk_buff *skb,
		     u_int8_t real_skb,
		     u_int16_t skb_displ,
		     struct pfring_pkthdr *hdr,
		     u_int8_t reset_all)
{
  int rc;

  rc = parse_raw_pkt(&skb->data[real_skb ? -skb_displ : 0], (skb->len + skb_displ), hdr, reset_all);
  hdr->extended_hdr.parsed_pkt.offset.eth_offset = -skb_displ;

  return(rc);
}

/* ********************************** */

static int hash_bucket_match(sw_filtering_hash_bucket * hash_bucket,
			     struct pfring_pkthdr *hdr,
			     u_char mask_src, u_char mask_dst)
{
#if 0
    printk("[PF_RING] hash_bucket_match() (%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u) "
	   "(%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u)\n",
	   hash_bucket->rule.vlan_id, hash_bucket->rule.proto,
	   ((hash_bucket->rule.host4_peer_a >> 24) & 0xff),
	   ((hash_bucket->rule.host4_peer_a >> 16) & 0xff),
	   ((hash_bucket->rule.host4_peer_a >> 8) & 0xff),
	   ((hash_bucket->rule.host4_peer_a >> 0) & 0xff),
	   hash_bucket->rule.port_peer_a,
	   ((hash_bucket->rule.host4_peer_b >> 24) & 0xff),
	   ((hash_bucket->rule.host4_peer_b >> 16) & 0xff),
	   ((hash_bucket->rule.host4_peer_b >> 8) & 0xff),
	   ((hash_bucket->rule.host4_peer_b >> 0) & 0xff),
	   hash_bucket->rule.port_peer_b,

	   hdr->extended_hdr.parsed_pkt.vlan_id,
	   hdr->extended_hdr.parsed_pkt.l3_proto,
	   ((hdr->extended_hdr.parsed_pkt.ipv4_src >> 24) & 0xff),
	   ((hdr->extended_hdr.parsed_pkt.ipv4_src >> 16) & 0xff),
	   ((hdr->extended_hdr.parsed_pkt.ipv4_src >> 8) & 0xff),
	   ((hdr->extended_hdr.parsed_pkt.ipv4_src >> 0) & 0xff),
	   hdr->extended_hdr.parsed_pkt.l4_src_port,
	   ((hdr->extended_hdr.parsed_pkt.ipv4_dst >> 24) & 0xff),
	   ((hdr->extended_hdr.parsed_pkt.ipv4_dst >> 16) & 0xff),
	   ((hdr->extended_hdr.parsed_pkt.ipv4_dst >> 8) & 0xff),
	   ((hdr->extended_hdr.parsed_pkt.ipv4_dst >> 0) & 0xff),
	   hdr->extended_hdr.parsed_pkt.l4_dst_port);
#endif

  /*
    When protocol of host_peer is IPv4, s6_addr32[0] contains IPv4
    address and the value of other elements of s6_addr32 are 0.
  */
  if((hash_bucket->rule.proto == hdr->extended_hdr.parsed_pkt.l3_proto)
     && (hash_bucket->rule.vlan_id == hdr->extended_hdr.parsed_pkt.vlan_id)
     && (((hash_bucket->rule.host4_peer_a == (mask_src ? 0 : hdr->extended_hdr.parsed_pkt.ipv4_src))
	  && (hash_bucket->rule.host4_peer_b == (mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.ipv4_dst))
	  && (hash_bucket->rule.port_peer_a == (mask_src ? 0 : hdr->extended_hdr.parsed_pkt.l4_src_port))
	  && (hash_bucket->rule.port_peer_b == (mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.l4_dst_port)))
	 ||
	 ((hash_bucket->rule.host4_peer_a == (mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.ipv4_dst))
	  && (hash_bucket->rule.host4_peer_b == (mask_src ? 0 : hdr->extended_hdr.parsed_pkt.ipv4_src))
	  && (hash_bucket->rule.port_peer_a == (mask_dst ? 0 : hdr->extended_hdr.parsed_pkt.l4_dst_port))
	  && (hash_bucket->rule.port_peer_b == (mask_src ? 0 : hdr->extended_hdr.parsed_pkt.l4_src_port)))))
    {
      if(hdr->extended_hdr.parsed_pkt.ip_version == 6) {
	if(((memcmp(&hash_bucket->rule.host6_peer_a,
		    (mask_src ? &ip_zero.v6 : &hdr->extended_hdr.parsed_pkt.ipv6_src),
		    sizeof(ip_addr) == 0))
	    && (memcmp(&hash_bucket->rule.host6_peer_b,
		       (mask_dst ? &ip_zero.v6 : &hdr->extended_hdr.parsed_pkt.ipv6_dst),
		       sizeof(ip_addr) == 0)))
	   ||
	   ((memcmp(&hash_bucket->rule.host6_peer_a,
		    (mask_src ? &ip_zero.v6 : &hdr->extended_hdr.parsed_pkt.ipv6_dst),
		    sizeof(ip_addr) == 0))
	    && (memcmp(&hash_bucket->rule.host6_peer_b,
		       (mask_dst ? &ip_zero.v6 : &hdr->extended_hdr.parsed_pkt.ipv6_src),
		       sizeof(ip_addr) == 0)))) {
	  return(1);
	} else {
	  return(0);
	}
      } else {
	return(1);
      }
    } else {
    return(0);
  }
}

/* ********************************** */

inline int hash_bucket_match_rule(sw_filtering_hash_bucket * hash_bucket,
				  hash_filtering_rule * rule)
{
  if(unlikely(enable_debug))
    printk("[PF_RING] (%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u) "
	   "(%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u)\n",
	   hash_bucket->rule.vlan_id, hash_bucket->rule.proto,
	   ((hash_bucket->rule.host4_peer_a >> 24) & 0xff),
	   ((hash_bucket->rule.host4_peer_a >> 16) & 0xff),
	   ((hash_bucket->rule.host4_peer_a >> 8) & 0xff),
	   ((hash_bucket->rule.host4_peer_a >> 0) & 0xff),
	   hash_bucket->rule.port_peer_a,
	   ((hash_bucket->rule.host4_peer_b >> 24) & 0xff),
	   ((hash_bucket->rule.host4_peer_b >> 16) & 0xff),
	   ((hash_bucket->rule.host4_peer_b >> 8) & 0xff),
	   ((hash_bucket->rule.host4_peer_b >> 0) & 0xff),
	   hash_bucket->rule.port_peer_b,
	   rule->vlan_id, rule->proto,
	   ((rule->host4_peer_a >> 24) & 0xff),
	   ((rule->host4_peer_a >> 16) & 0xff),
	   ((rule->host4_peer_a >> 8) & 0xff),
	   ((rule->host4_peer_a >> 0) & 0xff),
	   rule->port_peer_a,
	   ((rule->host4_peer_b >> 24) & 0xff),
	   ((rule->host4_peer_b >> 16) & 0xff),
	   ((rule->host4_peer_b >> 8) & 0xff),
	   ((rule->host4_peer_b >> 0) & 0xff), rule->port_peer_b);

  if((hash_bucket->rule.proto == rule->proto)
     && (hash_bucket->rule.vlan_id == rule->vlan_id)
     && (((hash_bucket->rule.host4_peer_a == rule->host4_peer_a)
	  && (hash_bucket->rule.host4_peer_b == rule->host4_peer_b)
	  && (hash_bucket->rule.port_peer_a == rule->port_peer_a)
	  && (hash_bucket->rule.port_peer_b == rule->port_peer_b))
	 || ((hash_bucket->rule.host4_peer_a == rule->host4_peer_b)
	     && (hash_bucket->rule.host4_peer_b == rule->host4_peer_a)
	     && (hash_bucket->rule.port_peer_a == rule->port_peer_b)
	     && (hash_bucket->rule.port_peer_b == rule->port_peer_a)))) {
    hash_bucket->rule.internals.jiffies_last_match = jiffies;
    return(1);
  } else
    return(0);
}

/* ********************************** */

inline int hash_filtering_rule_match(hash_filtering_rule * a,
				     hash_filtering_rule * b)
{
  if(unlikely(enable_debug))
    printk("[PF_RING] (%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u) "
	   "(%u,%d,%d.%d.%d.%d:%u,%d.%d.%d.%d:%u)\n",
	   a->vlan_id, a->proto,
	   ((a->host4_peer_a >> 24) & 0xff),
	   ((a->host4_peer_a >> 16) & 0xff),
	   ((a->host4_peer_a >> 8) & 0xff),
	   ((a->host4_peer_a >> 0) & 0xff),
	   a->port_peer_a,
	   ((a->host4_peer_b >> 24) & 0xff),
	   ((a->host4_peer_b >> 16) & 0xff),
	   ((a->host4_peer_b >> 8) & 0xff),
	   ((a->host4_peer_b >> 0) & 0xff),
	   a->port_peer_b,
	   b->vlan_id, b->proto,
	   ((b->host4_peer_a >> 24) & 0xff),
	   ((b->host4_peer_a >> 16) & 0xff),
	   ((b->host4_peer_a >> 8) & 0xff),
	   ((b->host4_peer_a >> 0) & 0xff),
	   b->port_peer_a,
	   ((b->host4_peer_b >> 24) & 0xff),
	   ((b->host4_peer_b >> 16) & 0xff),
	   ((b->host4_peer_b >> 8) & 0xff),
	   ((b->host4_peer_b >> 0) & 0xff), b->port_peer_b);

  if((a->proto == b->proto)
     && (a->vlan_id == b->vlan_id)
     && (((a->host4_peer_a == b->host4_peer_a)
	  && (a->host4_peer_b == b->host4_peer_b)
	  && (a->port_peer_a == b->port_peer_a)
	  && (a->port_peer_b == b->port_peer_b))
	 || ((a->host4_peer_a == b->host4_peer_b)
	     && (a->host4_peer_b == b->host4_peer_a)
	     && (a->port_peer_a == b->port_peer_b)
	     && (a->port_peer_b == b->port_peer_a)))) {
    return(1);
  } else
    return(0);
}

/* ********************************** */

inline int match_ipv6(ip_addr *addr, ip_addr *rule_addr, ip_addr *rule_mask) {
  int i;
  if(rule_mask->v6.s6_addr32[0] != 0)
    for(i=0; i<4; i++)
      if((addr->v6.s6_addr32[i] & rule_mask->v6.s6_addr32[i]) != rule_addr->v6.s6_addr32[i])
        return(0);
  return(1);
}

/* ********************************** */

/* 0 = no match, 1 = match */
static int match_filtering_rule(struct pf_ring_socket *pfr,
				sw_filtering_rule_element * rule,
				struct pfring_pkthdr *hdr,
				struct sk_buff *skb,
				int displ,
				struct parse_buffer *parse_memory_buffer[],
				u_int8_t *free_parse_mem,
				u_int *last_matched_plugin,
				rule_action_behaviour *behaviour)
{
  u_int8_t empty_mac[ETH_ALEN] = { 0 }; /* NULL MAC address */

  if(unlikely(enable_debug)) printk("[PF_RING] %s()\n", __FUNCTION__);

  *behaviour = forward_packet_and_stop_rule_evaluation;	/* Default */

  if((rule->rule.core_fields.vlan_id > 0)
     && (hdr->extended_hdr.parsed_pkt.vlan_id != rule->rule.core_fields.vlan_id))
    return(0);

  if((rule->rule.core_fields.proto > 0)
     && (hdr->extended_hdr.parsed_pkt.l3_proto != rule->rule.core_fields.proto))
    return(0);

  if((memcmp(rule->rule.core_fields.dmac, empty_mac, ETH_ALEN) != 0)
     && (memcmp(hdr->extended_hdr.parsed_pkt.dmac, rule->rule.core_fields.dmac, ETH_ALEN) != 0))
    goto swap_direction;

  if((memcmp(rule->rule.core_fields.smac, empty_mac, ETH_ALEN) != 0)
     && (memcmp(hdr->extended_hdr.parsed_pkt.smac, rule->rule.core_fields.smac, ETH_ALEN) != 0))
    goto swap_direction;

  if(hdr->extended_hdr.parsed_pkt.ip_version == 6){
    /* IPv6 */
    if(!match_ipv6(&hdr->extended_hdr.parsed_pkt.ip_src, &rule->rule.core_fields.shost_mask, &rule->rule.core_fields.shost)
       || !match_ipv6(&hdr->extended_hdr.parsed_pkt.ip_dst, &rule->rule.core_fields.dhost_mask, &rule->rule.core_fields.dhost))
        goto swap_direction;
  } else {
    /* IPv4 */
    if((hdr->extended_hdr.parsed_pkt.ip_src.v4 & rule->rule.core_fields.shost_mask.v4) != rule->rule.core_fields.shost.v4
       || (hdr->extended_hdr.parsed_pkt.ip_dst.v4 & rule->rule.core_fields.dhost_mask.v4) != rule->rule.core_fields.dhost.v4)
        goto swap_direction;
  }

  if((rule->rule.core_fields.sport_high != 0)
    && ((hdr->extended_hdr.parsed_pkt.l4_src_port < rule->rule.core_fields.sport_low)
	|| (hdr->extended_hdr.parsed_pkt.l4_src_port > rule->rule.core_fields.sport_high)))
    goto swap_direction;

  if((rule->rule.core_fields.dport_high != 0)
     && ((hdr->extended_hdr.parsed_pkt.l4_dst_port < rule->rule.core_fields.dport_low)
	 || (hdr->extended_hdr.parsed_pkt.l4_dst_port > rule->rule.core_fields.dport_high)))
    goto swap_direction;

  goto success;

swap_direction:

  if(!rule->rule.bidirectional)
    return(0);

  if((memcmp(rule->rule.core_fields.dmac, empty_mac, ETH_ALEN) != 0)
     && (memcmp(hdr->extended_hdr.parsed_pkt.smac, rule->rule.core_fields.dmac, ETH_ALEN) != 0))
    return(0);

  if((memcmp(rule->rule.core_fields.smac, empty_mac, ETH_ALEN) != 0)
     && (memcmp(hdr->extended_hdr.parsed_pkt.dmac, rule->rule.core_fields.smac, ETH_ALEN) != 0))
    return(0);

  if(hdr->extended_hdr.parsed_pkt.ip_version == 6) {
    /* IPv6 */
    if(!match_ipv6(&hdr->extended_hdr.parsed_pkt.ip_src, &rule->rule.core_fields.dhost_mask, &rule->rule.core_fields.dhost)
       || !match_ipv6(&hdr->extended_hdr.parsed_pkt.ip_dst, &rule->rule.core_fields.shost_mask, &rule->rule.core_fields.shost))
      return(0);
  } else {
    /* IPv4 */
    if((hdr->extended_hdr.parsed_pkt.ip_src.v4 & rule->rule.core_fields.dhost_mask.v4) != rule->rule.core_fields.dhost.v4
       || (hdr->extended_hdr.parsed_pkt.ip_dst.v4 & rule->rule.core_fields.shost_mask.v4) != rule->rule.core_fields.shost.v4)
      return(0);
  }

  if((rule->rule.core_fields.sport_high != 0)
    && ((hdr->extended_hdr.parsed_pkt.l4_dst_port < rule->rule.core_fields.sport_low)
	|| (hdr->extended_hdr.parsed_pkt.l4_dst_port > rule->rule.core_fields.sport_high)))
    return(0);

  if((rule->rule.core_fields.dport_high != 0)
     && ((hdr->extended_hdr.parsed_pkt.l4_src_port < rule->rule.core_fields.dport_low)
	 || (hdr->extended_hdr.parsed_pkt.l4_src_port > rule->rule.core_fields.dport_high)))
    return(0);

success:

  if(rule->rule.balance_pool > 0) {
    u_int32_t balance_hash = hash_pkt_header(hdr, 0, 0, 0, 0, 0) % rule->rule.balance_pool;

    if(balance_hash != rule->rule.balance_id)
      return(0);
  }

#ifdef CONFIG_TEXTSEARCH
  if(rule->pattern[0] != NULL) {
    if(unlikely(enable_debug))
      printk("[PF_RING] pattern\n");

    if((hdr->extended_hdr.parsed_pkt.offset.payload_offset > 0)
       && (hdr->caplen > hdr->extended_hdr.parsed_pkt.offset.payload_offset)) {
      char *payload = (char *)&(skb->data[hdr->extended_hdr.parsed_pkt.offset.payload_offset /* -displ */ ]);
      int rc = 0, payload_len =
	hdr->caplen - hdr->extended_hdr.parsed_pkt.offset.payload_offset - displ;

      if(payload_len > 0) {
	int i;
	struct ts_state state;

	if(unlikely(enable_debug)) {
	  printk("[PF_RING] Trying to match pattern [caplen=%d][len=%d][displ=%d][payload_offset=%d][",
		 hdr->caplen, payload_len, displ,
		 hdr->extended_hdr.parsed_pkt.offset.payload_offset);

	  for(i = 0; i < payload_len; i++)
	    printk("[%d/%c]", i, payload[i] & 0xFF);
	  printk("]\n");
	}

	payload[payload_len] = '\0';

	if(unlikely(enable_debug))
	  printk("[PF_RING] Attempt to match [%s]\n", payload);

	for(i = 0; (i < MAX_NUM_PATTERN) && (rule->pattern[i] != NULL); i++) {
	  if(unlikely(enable_debug))
	    printk("[PF_RING] Attempt to match pattern %d\n", i);
	  rc = (textsearch_find_continuous
		(rule->pattern[i], &state,
		 payload, payload_len) != UINT_MAX) ? 1 : 0;
	  if(rc == 1)
	    break;
	}

	if(unlikely(enable_debug))
	  printk("[PF_RING] Match returned: %d [payload_len=%d][%s]\n",
		 rc, payload_len, payload);

	if(rc == 0)
	  return(0);	/* No match */
      } else
	return(0);	/* No payload data */
    } else
      return(0);	/* No payload data */
  }
#endif

  /* Step 1 - Filter (optional) */
  if((rule->rule.extended_fields.filter_plugin_id > 0)
     && (rule->rule.extended_fields.filter_plugin_id < MAX_PLUGIN_ID)
     && (plugin_registration[rule->rule.extended_fields.filter_plugin_id] != NULL)
     && (plugin_registration[rule->rule.extended_fields.filter_plugin_id]->pfring_plugin_filter_skb != NULL)
     ) {
    int rc;

    if(unlikely(enable_debug))
      printk("[PF_RING] rule->plugin_id [rule_id=%d]"
	     "[filter_plugin_id=%d][plugin_action=%d][ptr=%p]\n",
	     rule->rule.rule_id,
	     rule->rule.extended_fields.filter_plugin_id,
	     rule->rule.plugin_action.plugin_id,
	     plugin_registration[rule->rule.plugin_action.plugin_id]);

    rc = plugin_registration[rule->rule.extended_fields.filter_plugin_id]->pfring_plugin_filter_skb
      (pfr, rule, hdr, skb, displ, &parse_memory_buffer[rule->rule.extended_fields.filter_plugin_id]);

    if(parse_memory_buffer[rule->rule.extended_fields.filter_plugin_id])
      *free_parse_mem = 1;

    if(rc <= 0) {
      return(0); /* No match */
    } else {
      *last_matched_plugin = rule->rule.extended_fields.filter_plugin_id;
      hdr->extended_hdr.parsed_pkt.last_matched_plugin_id =
	rule->rule.extended_fields.filter_plugin_id;

      if(unlikely(enable_debug))
	printk("[PF_RING] [last_matched_plugin = %d][buffer=%p][len=%d]\n",
	       *last_matched_plugin,
	       parse_memory_buffer[rule->rule.extended_fields.filter_plugin_id],
	       parse_memory_buffer[rule->rule.extended_fields.filter_plugin_id] ?
	       parse_memory_buffer[rule->rule.extended_fields.filter_plugin_id]->mem_len : 0);
    }
  }

  /* Step 2 - Handle skb */
  /* Action to be performed in case of match */
  if((rule->rule.plugin_action.plugin_id != NO_PLUGIN_ID)
     && (rule->rule.plugin_action.plugin_id < MAX_PLUGIN_ID)
     && (plugin_registration[rule->rule.plugin_action.plugin_id] != NULL)
     && (plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_handle_skb != NULL)
     ) {
    int rc;

    if(unlikely(enable_debug))
      printk("[PF_RING] Calling pfring_plugin_handle_skb(pluginId=%d)\n",
	     rule->rule.plugin_action.plugin_id);

    rc = plugin_registration[rule->rule.plugin_action.plugin_id]
      ->pfring_plugin_handle_skb(pfr, rule, NULL, hdr, skb, displ,
				 rule->rule.extended_fields.filter_plugin_id,
				 &parse_memory_buffer[rule->rule.plugin_action.plugin_id],
				 behaviour);
    if(rc <= 0)
      return(0); /* No match */

    if(*last_matched_plugin == 0)
      *last_matched_plugin = rule->rule.plugin_action.plugin_id;

    if(parse_memory_buffer[rule->rule.plugin_action.plugin_id])
      *free_parse_mem = 1;
  } else {
    if(unlikely(enable_debug))
      printk("[PF_RING] Skipping pfring_plugin_handle_skb(plugin_action=%d)\n",
	     rule->rule.plugin_action.plugin_id);
    *behaviour = rule->rule.rule_action;

    if(unlikely(enable_debug))
      printk("[PF_RING] Rule %d behaviour: %d\n",
	     rule->rule.rule_id, rule->rule.rule_action);
  }

  if(unlikely(enable_debug)) {
    printk("[PF_RING] MATCH: %s(vlan=%u, proto=%u, sip=%u, sport=%u, dip=%u, dport=%u)\n"
           "          [rule(vlan=%u, proto=%u, ip=%u:%u, port=%u:%u-%u:%u)(behaviour=%d)]\n",
    	   __FUNCTION__,
	   hdr->extended_hdr.parsed_pkt.vlan_id, hdr->extended_hdr.parsed_pkt.l3_proto,
	   hdr->extended_hdr.parsed_pkt.ipv4_src, hdr->extended_hdr.parsed_pkt.l4_src_port,
	   hdr->extended_hdr.parsed_pkt.ipv4_dst, hdr->extended_hdr.parsed_pkt.l4_dst_port,
	   rule->rule.core_fields.vlan_id,
	   rule->rule.core_fields.proto,
	   rule->rule.core_fields.shost.v4,
	   rule->rule.core_fields.dhost.v4,
	   rule->rule.core_fields.sport_low, rule->rule.core_fields.sport_high,
	   rule->rule.core_fields.dport_low, rule->rule.core_fields.dport_high,
	   *behaviour);
  }

  rule->rule.internals.jiffies_last_match = jiffies;

  return(1); /* match */
}

/* ********************************** */

static inline void set_skb_time(struct sk_buff *skb, struct pfring_pkthdr *hdr) {
  /* BD - API changed for time keeping */
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
  if(skb->stamp.tv_sec == 0)
    do_gettimeofday(&skb->stamp);  /* If timestamp is missing add it */
  hdr->ts.tv_sec = skb->stamp.tv_sec, hdr->ts.tv_usec = skb->stamp.tv_usec;
  hdr->extended_hdr.timestamp_ns = 0; /* No nsec for old kernels */
#elif(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
  if(skb->tstamp.off_sec == 0)
    __net_timestamp(skb); /* If timestamp is missing add it */
  hdr->ts.tv_sec = skb->tstamp.off_sec, hdr->ts.tv_usec = skb->tstamp.off_usec;
  hdr->extended_hdr.timestamp_ns = 0; /* No nsec for old kernels */
#else /* 2.6.22 and above */
  if(skb->tstamp.tv64 == 0)
    __net_timestamp(skb); /* If timestamp is missing add it */

  hdr->ts = ktime_to_timeval(skb->tstamp);

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30))
  {
    /* Use hardware timestamps when present. If not, just use software timestamps */
    hdr->extended_hdr.timestamp_ns = ktime_to_ns(skb_hwtstamps(skb)->hwtstamp);

    if(unlikely(enable_debug))
      printk("[PF_RING] hwts=%llu/dev=%s\n",
	     hdr->extended_hdr.timestamp_ns,
	     skb->dev ? skb->dev->name : "???");
  }
#endif
  if(hdr->extended_hdr.timestamp_ns == 0)
    hdr->extended_hdr.timestamp_ns = ktime_to_ns(skb->tstamp);
#endif
}

/* ********************************** */

/*
  Generic function for copying either a skb or a raw
  memory block to the ring buffer

  Return:
  - 0 = packet was not copied (e.g. slot was full)
  - 1 = the packet was copied (i.e. there was room for it)
*/
inline int copy_data_to_ring(struct sk_buff *skb,
			     struct pf_ring_socket *pfr,
			     struct pfring_pkthdr *hdr,
			     int displ, int offset, void *plugin_mem,
			     void *raw_data, uint raw_data_len) {
  char *ring_bucket;
  // u_short do_lock = ((pfr->num_bound_devices > 1) || (pfr->num_channels_per_ring > 1)) ? 1 : 0;
  volatile u_int32_t off, next_offset;

  if(skb == NULL) {
    raw_data_len = min_val(raw_data_len, pfr->bucket_len); /* Avoid overruns */
    hdr->len = hdr->caplen = raw_data_len;
  }

 try_again:
  if(pfr->ring_slots == NULL) return(0);
  
  // smp_rmb();
  
  off = atomic_read(&pfr->slots_info->shadow_insert_off);
  
  if(!check_free_slot(pfr, off)) /* Full */ {
    /* No room left */
    atomic_inc((atomic_t *)&pfr->slots_info->tot_lost);
    
    if(unlikely(enable_debug))
      printk("[PF_RING] ==> slot(off=%d) is full [shadow_insert_off=%u][insert_off=%u][remove_off=%u][slot_len=%u][num_queued_pkts=%u]\n",
	     off, (unsigned int)atomic_read(&pfr->slots_info->shadow_insert_off), atomic_read(&pfr->slots_info->insert_off), 
	     pfr->slots_info->remove_off, pfr->slots_info->slot_len, num_queued_pkts(pfr));
    
    return(0);
  }
  
  /* Compute next offset */
  next_offset = get_next_slot_offset(pfr, off, hdr->caplen, hdr->extended_hdr.parsed_header_len);
  
  /*
  if(!do_lock)
    atomic_set(&pfr->slots_info->shadow_insert_off, next_offset);
    else */ {
    if(atomic_cmpxchg(&pfr->slots_info->shadow_insert_off, off /* old value */, next_offset /* new value */) != off)
      goto try_again;
  }

  if(unlikely(enable_debug))
    printk("[PF_RING] ==> slot(off=%d) [shadow_insert_off=%u][insert_off=%u][remove_off=%u][slot_len=%u][num_queued_pkts=%u]\n",
	   off, (unsigned int)atomic_read(&pfr->slots_info->shadow_insert_off), atomic_read(&pfr->slots_info->insert_off), 
	   pfr->slots_info->remove_off, pfr->slots_info->slot_len, num_queued_pkts(pfr));
  
  atomic_inc((atomic_t *)&pfr->slots_info->tot_pkts);
  ring_bucket = get_slot(pfr, off);

  if(skb != NULL) {
    /* skb copy mode */

    if(hdr->ts.tv_sec == 0)
      set_skb_time(skb, hdr);

    if((plugin_mem != NULL) && (offset > 0))
      memcpy(&ring_bucket[pfr->slot_header_len], plugin_mem, offset);

    if(hdr->caplen > 0) {
      if(unlikely(enable_debug))
	printk("[PF_RING] --> [caplen=%d][len=%d][displ=%d][extended_hdr.parsed_header_len=%d][bucket_len=%d][sizeof=%d]\n",
	       hdr->caplen, hdr->len, displ, hdr->extended_hdr.parsed_header_len, pfr->bucket_len,
	       pfr->slot_header_len);

      /* Copy packet payload */
      skb_copy_bits(skb, -displ, &ring_bucket[pfr->slot_header_len + offset], hdr->caplen);
    } else {
      if(hdr->extended_hdr.parsed_header_len >= pfr->bucket_len) {
	static u_char print_once = 0;

	if(!print_once) {
	  printk("[PF_RING] WARNING: the bucket len is [%d] shorter than the plugin parsed header [%d]\n",
		 pfr->bucket_len, hdr->extended_hdr.parsed_header_len);
	  print_once = 1;
	}
      }
    }
  } else {
    /* Raw data copy mode */
    memcpy(&ring_bucket[pfr->slot_header_len], raw_data, raw_data_len); /* Copy raw data if present */
    hdr->extended_hdr.if_index = FAKE_PACKET;
    /* printk("[PF_RING] Copied raw data at slot with offset %d [len=%d]\n", off, raw_data_len); */
  }

  // hdr->extended_hdr.reserved = 0; /* Packet not yet consumed (just to be safe) */
  memcpy(ring_bucket, hdr, pfr->slot_header_len); /* Copy extended packet header */

  /* 
     Wait until the value of atomic_read(&pfr->slots_info->insert_off) is the same
     as the pfr->slots_info->shadow_insert_off value that we have seen
     at the beginning of this function
  */
  while(atomic_read(&pfr->slots_info->insert_off) != off) {
    u_int num_loops = 0;
    
    if(unlikely(enable_debug))
      printk("[PF_RING] pfr->slots_info->insert_off != off (%u/%u) [loops: %u]\n",
	     atomic_read(&pfr->slots_info->insert_off), off, ++num_loops);
  }

  /* We now update the insert_off */
  atomic_set(&pfr->slots_info->insert_off, next_offset);

  if(unlikely(enable_debug))
    printk("[PF_RING] ==> insert_off=%d\n", atomic_read(&pfr->slots_info->insert_off));

  /*
    NOTE: smp_* barriers are _compiler_ barriers on UP, mandatory barriers on SMP
    a consumer _must_ see the new value of tot_insert only after the buffer update completes
  */
  smp_mb();
  //wmb();

  atomic_inc((atomic_t *)&pfr->slots_info->tot_insert);

  if(num_queued_pkts(pfr) >= pfr->poll_num_pkts_watermark)
    wake_up_interruptible(&pfr->ring_slots_waitqueue);
 
#ifdef VPFRING_SUPPORT
  if(pfr->vpfring_host_eventfd_ctx && !(pfr->slots_info->vpfring_guest_flags & VPFRING_GUEST_NO_INTERRUPT))
    eventfd_signal(pfr->vpfring_host_eventfd_ctx, 1);
#endif //VPFRING_SUPPORT
 
  return(1);
}

/* ********************************** */

inline int copy_raw_data_to_ring(struct pf_ring_socket *pfr,
				 struct pfring_pkthdr *dummy_hdr,
				 void *raw_data, uint raw_data_len) {
  return(copy_data_to_ring(NULL, pfr, dummy_hdr, 0, 0, NULL, raw_data, raw_data_len));
}

/* ********************************** */

inline int add_pkt_to_ring(struct sk_buff *skb,
			   u_int8_t real_skb,
			   struct pf_ring_socket *_pfr,
			   struct pfring_pkthdr *hdr,
			   int displ, u_int32_t channel_id,
			   int offset, void *plugin_mem)
{
  struct pf_ring_socket *pfr = (_pfr->master_ring != NULL) ? _pfr->master_ring : _pfr;
  u_int32_t the_bit = 1 << channel_id;

  if(unlikely(enable_debug))
    printk("[PF_RING] --> add_pkt_to_ring(len=%d) [pfr->channel_id=%d][channel_id=%d][real_skb=%u]\n",
	   hdr->len, pfr->channel_id, channel_id, real_skb);

  if((!pfr->ring_active) || (!skb))
    return(0);

  if((pfr->channel_id != RING_ANY_CHANNEL)
     && (channel_id != RING_ANY_CHANNEL)
     && ((pfr->channel_id & the_bit) != the_bit))
    return(0); /* Wrong channel */

  hdr->caplen = min_val(pfr->bucket_len - offset, hdr->caplen);

  if(pfr->kernel_consumer_plugin_id
     && plugin_registration[pfr->kernel_consumer_plugin_id]->pfring_packet_reader) {
    write_lock(&pfr->ring_index_lock); /* Serialize */
    plugin_registration[pfr->kernel_consumer_plugin_id]->pfring_packet_reader(pfr, skb, channel_id, hdr, displ);
    atomic_inc(&pfr->slots_info->tot_pkts);
    write_unlock(&pfr->ring_index_lock);
    return(0);
  }

  if(real_skb)
    return(copy_data_to_ring(skb, pfr, hdr, displ, offset, plugin_mem, NULL, 0));
  else
    return(copy_raw_data_to_ring(pfr, hdr, skb->data, hdr->len));
}

/* ********************************** */

static int add_packet_to_ring(struct pf_ring_socket *pfr,
			      u_int8_t real_skb,
			      struct pfring_pkthdr *hdr,
			      struct sk_buff *skb,
			      int displ, u_int8_t parse_pkt_first)
{
  if(parse_pkt_first)
    parse_pkt(skb, real_skb, displ, hdr, 0 /* Do not reset user-specified fields */);

  ring_read_lock();
  add_pkt_to_ring(skb, real_skb, pfr, hdr, 0, RING_ANY_CHANNEL, displ, NULL);
  ring_read_unlock();
  return(0);
}

/* ********************************** */

static int add_raw_packet_to_ring(struct pf_ring_socket *pfr, struct pfring_pkthdr *hdr,
				  char *data, u_int data_len,
				  u_int8_t parse_pkt_first)
{
  if(parse_pkt_first)
    parse_raw_pkt(data, data_len, hdr, 0 /* Do not reset user-specified fields */);

  ring_read_lock();
  copy_raw_data_to_ring(pfr, hdr, data, data_len);
  ring_read_unlock();
  return(0);
}

/* ********************************** */

static int add_hdr_to_ring(struct pf_ring_socket *pfr,
			   u_int8_t real_skb,
			   struct pfring_pkthdr *hdr)
{
  return(add_packet_to_ring(pfr, real_skb, hdr, NULL, 0, 0));
}

/* ********************************** */

/* Free filtering placeholders */
static void free_parse_memory(struct parse_buffer *parse_memory_buffer[])
{
  int i;

  for(i = 1; i <= max_registered_plugin_id; i++)
    if(parse_memory_buffer[i]) {
      if(parse_memory_buffer[i]->mem != NULL) {
	kfree(parse_memory_buffer[i]->mem);
      }

      kfree(parse_memory_buffer[i]);
    }
}

/* ************************************* */

static void free_filtering_rule(sw_filtering_rule_element * entry, u_int8_t freeing_ring)
{
#ifdef CONFIG_TEXTSEARCH
  int i;
#endif

  if(entry->rule.plugin_action.plugin_id > 0
     && plugin_registration[entry->rule.plugin_action.plugin_id]
     && plugin_registration[entry->rule.plugin_action.plugin_id]->pfring_plugin_free_rule_mem) {
    /* "Freeing rule" callback.
     * Note: if you are freeing rule->plugin_data_ptr within this callback, please set it to NULL. */
    plugin_registration[entry->rule.plugin_action.plugin_id]->pfring_plugin_free_rule_mem(entry);
  }

  if(freeing_ring){ /* tell the plugin to free global data structures */
    if(entry->rule.plugin_action.plugin_id > 0
       && plugin_registration[entry->rule.plugin_action.plugin_id]
       && plugin_registration[entry->rule.plugin_action.plugin_id]->pfring_plugin_free_ring_mem) {
      /* "Freeing ring" callback.
       * Note: if you are freeing rule->plugin_data_ptr within this callback, please set it to NULL. */
      plugin_registration[entry->rule.plugin_action.plugin_id]->pfring_plugin_free_ring_mem(entry);
    }
  }

#ifdef CONFIG_TEXTSEARCH
  for(i = 0; (i < MAX_NUM_PATTERN) && (entry->pattern[i] != NULL); i++)
    textsearch_destroy(entry->pattern[i]);
#endif

  if(entry->plugin_data_ptr != NULL) {
    kfree(entry->plugin_data_ptr);
    entry->plugin_data_ptr = NULL;
  }

  if(entry->rule.internals.reflector_dev != NULL)
    dev_put(entry->rule.internals.reflector_dev);	/* Release device */

  if(entry->rule.extended_fields.filter_plugin_id > 0) {
    if(plugin_registration[entry->rule.extended_fields.filter_plugin_id]->pfring_plugin_register)
      plugin_registration[entry->rule.extended_fields.filter_plugin_id]->pfring_plugin_register(0);
  }

  if(entry->rule.plugin_action.plugin_id > 0) {
    if(plugin_registration[entry->rule.plugin_action.plugin_id]->pfring_plugin_register)
      plugin_registration[entry->rule.plugin_action.plugin_id]->pfring_plugin_register(0);
  }
}

/* ************************************* */

static void free_sw_filtering_hash_bucket(sw_filtering_hash_bucket * bucket)
{
  if(bucket->plugin_data_ptr != NULL) {
    kfree(bucket->plugin_data_ptr);
    bucket->plugin_data_ptr = NULL;
  }

  if(bucket->rule.internals.reflector_dev != NULL)
    dev_put(bucket->rule.internals.reflector_dev);	/* Release device */

  if(bucket->rule.plugin_action.plugin_id > 0) {
    if(plugin_registration[bucket->rule.plugin_action.plugin_id]->pfring_plugin_register)
      plugin_registration[bucket->rule.plugin_action.plugin_id]->pfring_plugin_register(0);
  }
}

/*
  NOTE

  I jeopardize the get_coalesce/set_eeprom fields for my purpose
  until hw filtering support is part of the kernel

*/

/* ************************************* */

static int handle_sw_filtering_hash_bucket(struct pf_ring_socket *pfr,
					   sw_filtering_hash_bucket * rule,
					   u_char add_rule)
{
  int rc = -1;
  u_int32_t hash_value = hash_pkt(rule->rule.vlan_id, rule->rule.proto,
				  rule->rule.host_peer_a, rule->rule.host_peer_b,
				  rule->rule.port_peer_a, rule->rule.port_peer_b)
    % DEFAULT_RING_HASH_SIZE;

  if(unlikely(enable_debug))
    printk("[PF_RING] %s(vlan=%u, proto=%u, "
	   "sip=%d.%d.%d.%d, sport=%u, dip=%d.%d.%d.%d, dport=%u, "
	   "hash_value=%u, add_rule=%d) called\n",
	   __FUNCTION__,
	   rule->rule.vlan_id,
	   rule->rule.proto, ((rule->rule.host4_peer_a >> 24) & 0xff),
	   ((rule->rule.host4_peer_a >> 16) & 0xff),
	   ((rule->rule.host4_peer_a >> 8) & 0xff),
	   ((rule->rule.host4_peer_a >> 0) & 0xff),
	   rule->rule.port_peer_a,
	   ((rule->rule.host4_peer_b >> 24) & 0xff),
	   ((rule->rule.host4_peer_b >> 16) & 0xff),
	   ((rule->rule.host4_peer_b >> 8) & 0xff),
	   ((rule->rule.host4_peer_b >> 0) & 0xff),
	   rule->rule.port_peer_b, hash_value, add_rule);

  if(add_rule) {
    /* Checking plugins */
    if(rule->rule.plugin_action.plugin_id != NO_PLUGIN_ID) {
      int ret = 0;

      if(rule->rule.plugin_action.plugin_id >= MAX_PLUGIN_ID)
        ret = -EFAULT;
      else if(plugin_registration[rule->rule.plugin_action.plugin_id] == NULL)
        ret = -EFAULT;

      if(ret != 0) {
        if(unlikely(enable_debug))
	  printk("[PF_RING] Invalid action plugin [id=%d]\n",
	         rule->rule.plugin_action.plugin_id);
        return(ret);
      }
    }

    /* Checking reflector device */
    if(rule->rule.reflector_device_name[0] != '\0') {
      if((pfr->ring_netdev->dev != NULL)
         && (strcmp(rule->rule.reflector_device_name, pfr->ring_netdev->dev->name) == 0)) {
	if(unlikely(enable_debug))
	  printk("[PF_RING] You cannot use as reflection device the same device on "
	       "which this ring is bound\n");
        return(-EFAULT);
      }

      rule->rule.internals.reflector_dev = dev_get_by_name(
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
							   &init_net,
#endif
							   rule->rule.reflector_device_name);

      if(rule->rule.internals.reflector_dev == NULL) {
        printk("[PF_RING] Unable to find device %s\n",
	       rule->rule.reflector_device_name);
        return(-EFAULT);
      }
    } else
      rule->rule.internals.reflector_dev = NULL;

    /* initialiting hash table */
    if(pfr->sw_filtering_hash == NULL){
      pfr->sw_filtering_hash = (sw_filtering_hash_bucket **)
	kcalloc(DEFAULT_RING_HASH_SIZE, sizeof(sw_filtering_hash_bucket *), GFP_ATOMIC);

      if(pfr->sw_filtering_hash == NULL) {
        if(unlikely(enable_debug))
	  printk("[PF_RING] %s() returned %d [0]\n", __FUNCTION__, -EFAULT);
        return(-EFAULT);
      }

      if(unlikely(enable_debug))
        printk("[PF_RING] %s() allocated memory\n", __FUNCTION__);
    }
  }

  if(pfr->sw_filtering_hash == NULL) {
    /* We're trying to delete a hash rule from an empty hash */
    return(-EFAULT);
  }

  if(pfr->sw_filtering_hash[hash_value] == NULL) {
    if(add_rule) {
      rule->next = NULL;
      pfr->sw_filtering_hash[hash_value] = rule;
      rc = 0;
    } else {
      if(unlikely(enable_debug))
	printk("[PF_RING] %s() returned %d [1]\n", __FUNCTION__, -1);
      return(-1);	/* Unable to find the specified rule */
    }
  } else {
    sw_filtering_hash_bucket *prev = NULL, *bucket = pfr->sw_filtering_hash[hash_value];

    while(bucket != NULL) {
      if(hash_filtering_rule_match(&bucket->rule, &rule->rule)) {
	if(add_rule) {
	  if(unlikely(enable_debug))
	    printk("[PF_RING] Duplicate found while adding rule: discarded\n");
	  return(-EEXIST);
	} else {
	  /* We've found the bucket to delete */

	  if(unlikely(enable_debug))
	    printk("[PF_RING] %s() found a bucket to delete: removing it\n", __FUNCTION__);
	  if(prev == NULL)
	    pfr->sw_filtering_hash[hash_value] = bucket->next;
	  else
	    prev->next = bucket->next;

	  free_sw_filtering_hash_bucket(bucket);
	  kfree(bucket);
	  pfr->num_sw_filtering_rules--;
	  if(unlikely(enable_debug))
	    printk("[PF_RING] %s() returned %d [2]\n", __FUNCTION__, 0);
	  return(0);
	}
      } else {
	prev = bucket;
	bucket = bucket->next;
      }
    }

    if(add_rule) {
      /* If the flow arrived until here, then this rule is unique */
      if(unlikely(enable_debug))
	printk("[PF_RING] %s() no duplicate rule found: adding the rule\n", __FUNCTION__);

      rule->next = pfr->sw_filtering_hash[hash_value];
      pfr->sw_filtering_hash[hash_value] = rule;
      rc = 0;
    } else {
      /* The rule we searched for has not been found */
      rc = -1;
    }
  }

  if(add_rule && rc == 0){
    pfr->num_sw_filtering_rules++;

    /* Avoid immediate rule purging */
    rule->rule.internals.jiffies_last_match = jiffies;

    if(rule->rule.plugin_action.plugin_id > 0) {
      if(plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_register)
        plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_register(1);
    }
  }

  if(unlikely(enable_debug))
    printk("[PF_RING] %s() returned %d [3]\n", __FUNCTION__, rc);

  return(rc);
}

/* ************************************* */

static int add_sw_filtering_rule_element(struct pf_ring_socket *pfr, sw_filtering_rule_element *rule)
{
  struct list_head *ptr;
  int idx = 0;
  sw_filtering_rule_element *entry;
  struct list_head *prev = NULL;

  /* Implement an ordered add looking backwards (probably we have incremental ids) */
  prev = &pfr->sw_filtering_rules;
  list_for_each_prev(ptr, &pfr->sw_filtering_rules) {
    entry = list_entry(ptr, sw_filtering_rule_element, list);

    if(entry->rule.rule_id == rule->rule.rule_id)
      return(-EEXIST);

    if(entry->rule.rule_id < rule->rule.rule_id)
      break;

    prev = ptr; /* position where to insert the new entry after checks */
  }

  /* Rule checks */
  if(rule->rule.extended_fields.filter_plugin_id != NO_PLUGIN_ID) {
    if(rule->rule.extended_fields.filter_plugin_id >= MAX_PLUGIN_ID
       || plugin_registration[rule->rule.extended_fields.filter_plugin_id] == NULL) {
      if(unlikely(enable_debug))
	printk("[PF_RING] Invalid filtering plugin [id=%d]\n",
	       rule->rule.extended_fields.filter_plugin_id);
      return(-EFAULT);
    }
  }

  if(rule->rule.plugin_action.plugin_id != NO_PLUGIN_ID) {
    if(rule->rule.plugin_action.plugin_id >= MAX_PLUGIN_ID
       || plugin_registration[rule->rule.plugin_action.plugin_id] == NULL) {
      if(unlikely(enable_debug))
	printk("[PF_RING] Invalid action plugin [id=%d]\n",
	       rule->rule.plugin_action.plugin_id);
      return(-EFAULT);
    }
  }

  if(rule->rule.reflector_device_name[0] != '\0') {
    if((pfr->ring_netdev->dev != NULL)
       && (strcmp(rule->rule.reflector_device_name, pfr->ring_netdev->dev->name) == 0)) {
      if(unlikely(enable_debug))
	printk("[PF_RING] You cannot use as reflection device the same device on which this ring is bound\n");
      return(-EFAULT);
    }

    rule->rule.internals.reflector_dev = dev_get_by_name(
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
							 &init_net,
#endif
							 rule->rule.reflector_device_name);

    if(rule->rule.internals.reflector_dev == NULL) {
      printk("[PF_RING] Unable to find device %s\n", rule->rule.reflector_device_name);
      return(-EFAULT);
    }
  } else
    rule->rule.internals.reflector_dev = NULL;

  if(unlikely(enable_debug))
    printk("[PF_RING] SO_ADD_FILTERING_RULE: About to add rule %d\n",
	   rule->rule.rule_id);

  /* Compile pattern if present */
  if(strlen(rule->rule.extended_fields.payload_pattern) > 0) {
    char *pattern = rule->rule.extended_fields.payload_pattern;

    printk("[PF_RING] About to compile pattern '%s'\n", pattern);

    while(pattern && (idx < MAX_NUM_PATTERN)) {
      char *pipe = strchr(pattern, '|');

      if(pipe)
	pipe[0] = '\0';

#ifdef CONFIG_TEXTSEARCH
      rule->pattern[idx] = textsearch_prepare("bm"	/* Boyer-Moore */
					      /* "kmp" = Knuth-Morris-Pratt */
					      , pattern, strlen(pattern),
					      GFP_KERNEL,
					      TS_AUTOLOAD
#ifdef TS_IGNORECASE
					      | TS_IGNORECASE
#endif
					      );
      if(rule->pattern[idx])
	printk("[PF_RING] Compiled pattern '%s' [idx=%d]\n", pattern, idx);
#endif
      if(pipe)
	pattern = &pipe[1], idx++;
      else
	break;
    }
  } else {
#ifdef CONFIG_TEXTSEARCH
    rule->pattern[0] = NULL;
#endif
  }

  list_add_tail(&rule->list, prev);
  pfr->num_sw_filtering_rules++;
  rule->rule.internals.jiffies_last_match = jiffies; /* Avoid immediate rule purging */

  if(rule->rule.extended_fields.filter_plugin_id > 0) {
    if(plugin_registration[rule->rule.extended_fields.filter_plugin_id]->pfring_plugin_register)
      plugin_registration[rule->rule.extended_fields.filter_plugin_id]->pfring_plugin_register(1);
  }

  if(rule->rule.plugin_action.plugin_id > 0) {
    if(plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_register)
      plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_register(1);
  }

  return(0);
}

/* ************************************* */

static int remove_sw_filtering_rule_element(struct pf_ring_socket *pfr, u_int16_t rule_id)
{
  int rule_found = 0;
  struct list_head *ptr, *tmp_ptr;

  list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
    sw_filtering_rule_element *entry;
    entry = list_entry(ptr, sw_filtering_rule_element, list);

    if(entry->rule.rule_id == rule_id) {
      list_del(ptr);
      free_filtering_rule(entry, 0);
      kfree(entry);

      pfr->num_sw_filtering_rules--;

      if(unlikely(enable_debug))
	printk("[PF_RING] SO_REMOVE_FILTERING_RULE: rule %d has been removed\n", rule_id);
      rule_found = 1;
      break;
    }
  }	/* for */

  return(rule_found);
}

/* ********************************** */

static int reflect_packet(struct sk_buff *skb,
			  struct pf_ring_socket *pfr,
			  struct net_device *reflector_dev,
			  int displ,
			  rule_action_behaviour behaviour)
{
  if(unlikely(enable_debug))
    printk("[PF_RING] reflect_packet called\n");

  if((reflector_dev != NULL)
     && (reflector_dev->flags & IFF_UP) /* Interface is up */ ) {
    int ret;

    skb->pkt_type = PACKET_OUTGOING, skb->dev = reflector_dev;
    /*
      Avoid others to free the skb and crash
      this because dev_queue_xmit (if successfull) is gonna
      call kfree_skb that will free the skb if users (see below)
      has not been incremented
    */
    atomic_inc(&skb->users);
    if(displ > 0) skb->data -= displ, skb->len += displ;

    if(behaviour == bounce_packet_and_stop_rule_evaluation) {
      char dst_mac[6];

      /* Swap mac addresses */
      memcpy(dst_mac, skb->data, 6);
      memcpy(skb->data, &skb->data[6], 6);
      memcpy(&skb->data[6], dst_mac, 6);
    }

    /*
      NOTE
      dev_queue_xmit() must be called with interrupts enabled
      which means it can't be called with spinlocks held.
    */
    ret = dev_queue_xmit(skb);
    if(displ > 0) skb->data += displ, skb->len -= displ;
    atomic_set(&pfr->num_ring_users, 0);	/* Done */
    /* printk("[PF_RING] --> ret=%d\n", ret); */

    if(ret == NETDEV_TX_OK)
      pfr->slots_info->tot_fwd_ok++;
    else {
      pfr->slots_info->tot_fwd_notok++;
      /*
	Do not put the statement below in case of success
	as dev_queue_xmit has already decremented users
      */
      atomic_dec(&skb->users);
    }

    /* yield(); */
    return(ret == NETDEV_TX_OK ? 0 : -ENETDOWN);
  } else
    pfr->slots_info->tot_fwd_notok++;

  return(-ENETDOWN);
}

/* ********************************** */

int check_perfect_rules(struct sk_buff *skb,
			struct pf_ring_socket *pfr,
			struct pfring_pkthdr *hdr,
			int *fwd_pkt,
			u_int8_t *free_parse_mem,
			struct parse_buffer *parse_memory_buffer[MAX_PLUGIN_ID],
			int displ, u_int *last_matched_plugin)
{
  u_int hash_idx;
  sw_filtering_hash_bucket *hash_bucket;
  u_int8_t hash_found = 0;

  hash_idx = hash_pkt_header(hdr, 0, 0, 0, 0, 0) % DEFAULT_RING_HASH_SIZE;
  hash_bucket = pfr->sw_filtering_hash[hash_idx];

  while(hash_bucket != NULL) {
    if(hash_bucket_match(hash_bucket, hdr, 0, 0)) {
      hash_found = 1;
      break;
    } else
      hash_bucket = hash_bucket->next;
  } /* while */

  if(hash_found) {
    rule_action_behaviour behaviour = forward_packet_and_stop_rule_evaluation;

    if((hash_bucket->rule.plugin_action.plugin_id != NO_PLUGIN_ID)
       && (hash_bucket->rule.plugin_action.plugin_id < MAX_PLUGIN_ID)
       && (plugin_registration[hash_bucket->rule.plugin_action.plugin_id] != NULL)
       && (plugin_registration[hash_bucket->rule.plugin_action.plugin_id]->
	   pfring_plugin_handle_skb != NULL)
       ) {
      plugin_registration[hash_bucket->rule.plugin_action.plugin_id]
	->pfring_plugin_handle_skb(pfr, NULL, hash_bucket, hdr, skb, displ, 0, /* no plugin */
				   &parse_memory_buffer[hash_bucket->rule.plugin_action.plugin_id],
				   &behaviour);

      if(parse_memory_buffer[hash_bucket->rule.plugin_action.plugin_id])
	*free_parse_mem = 1;
      *last_matched_plugin = hash_bucket->rule.plugin_action.plugin_id;
      hdr->extended_hdr.parsed_pkt.last_matched_plugin_id = hash_bucket->rule.plugin_action.plugin_id;
    } else
      behaviour = hash_bucket->rule.rule_action;

    switch(behaviour) {
    case forward_packet_and_stop_rule_evaluation:
      *fwd_pkt = 1;
      break;
    case dont_forward_packet_and_stop_rule_evaluation:
      *fwd_pkt = 0;
      break;
    case execute_action_and_stop_rule_evaluation:
      *fwd_pkt = 0;
      break;
    case execute_action_and_continue_rule_evaluation:
      *fwd_pkt = 0;
      hash_found = 0;	/* This way we also evaluate the list of rules */
      break;
    case forward_packet_add_rule_and_stop_rule_evaluation:
      *fwd_pkt = 1;
      break;
    case forward_packet_del_rule_and_stop_rule_evaluation:
      *fwd_pkt = 1;
      break;
    case reflect_packet_and_stop_rule_evaluation:
    case bounce_packet_and_stop_rule_evaluation:
      *fwd_pkt = 0;
      reflect_packet(skb, pfr, hash_bucket->rule.internals.reflector_dev, displ, behaviour);
      break;
    case reflect_packet_and_continue_rule_evaluation:
    case bounce_packet_and_continue_rule_evaluation:
      *fwd_pkt = 0;
      reflect_packet(skb, pfr, hash_bucket->rule.internals.reflector_dev, displ, behaviour);
      hash_found = 0;	/* This way we also evaluate the list of rules */
      break;
    }
  } else {
    /* printk("[PF_RING] Packet not found\n"); */
  }

  return(hash_found);
}

/* ********************************** */

int check_wildcard_rules(struct sk_buff *skb,
			 struct pf_ring_socket *pfr,
			 struct pfring_pkthdr *hdr,
			 int *fwd_pkt,
			 u_int8_t *free_parse_mem,
			 struct parse_buffer *parse_memory_buffer[MAX_PLUGIN_ID],
			 int displ, u_int *last_matched_plugin)
{
  struct list_head *ptr, *tmp_ptr;

  if(unlikely(enable_debug))
    printk("[PF_RING] Entered check_wildcard_rules()\n");

  read_lock(&pfr->ring_rules_lock);

  list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
    sw_filtering_rule_element *entry;
    rule_action_behaviour behaviour = forward_packet_and_stop_rule_evaluation;

    entry = list_entry(ptr, sw_filtering_rule_element, list);

    if(match_filtering_rule(pfr, entry, hdr, skb, displ,
			    parse_memory_buffer, free_parse_mem,
			    last_matched_plugin, &behaviour)) {
      if(unlikely(enable_debug))
	printk("[PF_RING] Packet MATCH\n");

      if(unlikely(enable_debug))
	printk("[PF_RING] behaviour=%d\n", behaviour);

      hdr->extended_hdr.parsed_pkt.last_matched_rule_id = entry->rule.rule_id;

      if(behaviour == forward_packet_and_stop_rule_evaluation) {
	*fwd_pkt = 1;
	break;
      } else if(behaviour == forward_packet_add_rule_and_stop_rule_evaluation) {
        sw_filtering_rule_element *rule_element = NULL;
	sw_filtering_hash_bucket  *hash_bucket  = NULL;
	u_int16_t free_rule_element_id;
	int rc = 0;
	*fwd_pkt = 1;

	/* we have done with rule evaluation,
	 * now we need a write_lock to add rules */
	read_unlock(&pfr->ring_rules_lock);

	if(*last_matched_plugin
	   && plugin_registration[*last_matched_plugin] != NULL
	   && plugin_registration[*last_matched_plugin]->pfring_plugin_add_rule != NULL) {

          write_lock(&pfr->ring_rules_lock);

	  /* retrieving the first free rule id (rules are ordered).
	   * (we can reuse entry, ptr, tmp_ptr because we will stop rule evaluation) */
	  free_rule_element_id = 0;
          list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
            entry = list_entry(ptr, sw_filtering_rule_element, list);
            if(entry->rule.rule_id == free_rule_element_id)
	      free_rule_element_id = entry->rule.rule_id + 1;
	    else break; /* we found an hole */
	  }

	  /* safety check to make sure nothing is changed since the read_unlock() */
          if(plugin_registration[*last_matched_plugin] != NULL
	     && plugin_registration[*last_matched_plugin]->pfring_plugin_add_rule != NULL) {

	    rc = plugin_registration[*last_matched_plugin]->pfring_plugin_add_rule(
	           entry, hdr, free_rule_element_id, &rule_element, &hash_bucket,
	           *last_matched_plugin, &parse_memory_buffer[*last_matched_plugin]);

	    if(unlikely(enable_debug))
	      printk("pfring_plugin_add_rule() returned %d\n", rc);

	    if(rc == 0) {

	      if(hash_bucket != NULL) {
	        rc = handle_sw_filtering_hash_bucket(pfr, hash_bucket, 1 /* add_rule_from_plugin */);

	        if(rc != 0){
	          kfree(hash_bucket);
	          hash_bucket = NULL;
	        }
              }

	      if(rule_element != NULL) {
	        rc = add_sw_filtering_rule_element(pfr, rule_element);

	        if(rc != 0){
	          kfree(rule_element);
	          rule_element = NULL;
	        }
	      }
            }
          }

	  write_unlock(&pfr->ring_rules_lock);

	} else { /* No plugin defined, creating an hash rule from packet headers */
	  hash_bucket = (sw_filtering_hash_bucket *)kcalloc(1, sizeof(sw_filtering_hash_bucket), GFP_ATOMIC);

	  if(hash_bucket != NULL) {
	    hash_bucket->rule.vlan_id = hdr->extended_hdr.parsed_pkt.vlan_id;
	    hash_bucket->rule.proto = hdr->extended_hdr.parsed_pkt.l3_proto;
	    hash_bucket->rule.host4_peer_a = hdr->extended_hdr.parsed_pkt.ipv4_src;
	    hash_bucket->rule.host4_peer_b = hdr->extended_hdr.parsed_pkt.ipv4_dst;
	    hash_bucket->rule.port_peer_a = hdr->extended_hdr.parsed_pkt.l4_src_port;
	    hash_bucket->rule.port_peer_b = hdr->extended_hdr.parsed_pkt.l4_dst_port;
	    hash_bucket->rule.rule_action = forward_packet_and_stop_rule_evaluation;
	    hash_bucket->rule.reflector_device_name[0] = '\0';
	    hash_bucket->rule.internals.reflector_dev = NULL;
	    hash_bucket->rule.plugin_action.plugin_id = NO_PLUGIN_ID;

            write_lock(&pfr->ring_rules_lock);
	    rc = handle_sw_filtering_hash_bucket(pfr, hash_bucket, 1 /* add_rule_from_plugin */);
	    write_unlock(&pfr->ring_rules_lock);

	    if(rc != 0){
	      kfree(hash_bucket);
	      hash_bucket = NULL;
	    } else {
	      if(unlikely(enable_debug))
	        printk("[PF_RING] Added rule: [%d.%d.%d.%d:%d <-> %d.%d.%d.%d:%d][tot_rules=%d]\n",
		       ((hash_bucket->rule.host4_peer_a >> 24) & 0xff), ((hash_bucket->rule.host4_peer_a >> 16) & 0xff),
		       ((hash_bucket->rule.host4_peer_a >> 8) & 0xff), ((hash_bucket->rule.host4_peer_a >> 0) & 0xff),
		       hash_bucket->rule.port_peer_a, ((hash_bucket->rule.host4_peer_b >> 24) & 0xff),
		       ((hash_bucket->rule.host4_peer_b >> 16) & 0xff), ((hash_bucket->rule.host4_peer_b >> 8) & 0xff),
		       ((hash_bucket->rule.host4_peer_b >> 0) & 0xff), hash_bucket->rule.port_peer_b, pfr->num_sw_filtering_rules);
	    }
	  }
	}

        /* Negative return values are not handled by the caller, it is better to return always 0.
	 * Note: be careful with unlock code when moving this */
        return(0);

	break;
      } else if(behaviour == forward_packet_del_rule_and_stop_rule_evaluation) {
        u_int16_t rule_element_id;
	sw_filtering_hash_bucket hash_bucket;
	int rc = 0;
	*fwd_pkt = 1;

	if(*last_matched_plugin
	   && plugin_registration[*last_matched_plugin] != NULL
	   && plugin_registration[*last_matched_plugin]->pfring_plugin_del_rule != NULL) {

	  rc = plugin_registration[*last_matched_plugin]->pfring_plugin_del_rule(
	         entry, hdr, &rule_element_id, &hash_bucket,
	         *last_matched_plugin, &parse_memory_buffer[*last_matched_plugin]);

	  if(unlikely(enable_debug))
	    printk("pfring_plugin_del_rule() returned %d\n", rc);


          if(rc > 0) {
	    /* we have done with rule evaluation,
	     * now we need a write_lock to del rules */
	    read_unlock(&pfr->ring_rules_lock);

	    if(rc | 1) {
	      write_lock(&pfr->ring_rules_lock);
	      handle_sw_filtering_hash_bucket(pfr, &hash_bucket, 0 /* del */);
	      write_unlock(&pfr->ring_rules_lock);
            }

	    if(rc | 2) {
	      write_lock(&pfr->ring_rules_lock);
	      remove_sw_filtering_rule_element(pfr, rule_element_id);
	      write_unlock(&pfr->ring_rules_lock);
	    }

	    /* Note: be careful with unlock code when moving this */
            return(0);
	  }
	}
	break;
      } else if(behaviour == dont_forward_packet_and_stop_rule_evaluation) {
	*fwd_pkt = 0;
	break;
      }

      if(entry->rule.rule_action == forward_packet_and_stop_rule_evaluation) {
	*fwd_pkt = 1;
	break;
      } else if(entry->rule.rule_action == dont_forward_packet_and_stop_rule_evaluation) {
	*fwd_pkt = 0;
	break;
      } else if(entry->rule.rule_action == execute_action_and_stop_rule_evaluation) {
	printk("[PF_RING] *** execute_action_and_stop_rule_evaluation\n");
	break;
      } else if(entry->rule.rule_action == execute_action_and_continue_rule_evaluation) {
	/* The action has already been performed inside match_filtering_rule()
	   hence instead of stopping rule evaluation, the next rule
	   will be evaluated */
      } else if((entry->rule.rule_action == reflect_packet_and_stop_rule_evaluation)
		|| (entry->rule.rule_action == bounce_packet_and_stop_rule_evaluation)) {
	*fwd_pkt = 0;
	reflect_packet(skb, pfr, entry->rule.internals.reflector_dev, displ, entry->rule.rule_action);
	break;
      } else if((entry->rule.rule_action == reflect_packet_and_continue_rule_evaluation)
		|| (entry->rule.rule_action == bounce_packet_and_continue_rule_evaluation)) {
	*fwd_pkt = 1;
	reflect_packet(skb, pfr, entry->rule.internals.reflector_dev, displ, entry->rule.rule_action);
      }
    } else {
      if(unlikely(enable_debug))
	printk("[PF_RING] Packet not matched\n");
    }
  }  /* for */

  read_unlock(&pfr->ring_rules_lock);

  return(0);
}

/* ********************************** */

/*
  This code has been partially copied from af_packet.c

  Return code
  1: pass the filter
  0: this packet has to be dropped
 */
int bpf_filter_skb(struct sk_buff *skb,
		   struct pf_ring_socket *pfr,
		   int displ) {
  if(pfr->bpfFilter != NULL) {
    unsigned res = 1, len;
    u8 *skb_head = skb->data;
    int skb_len = skb->len;

    len = skb->len - skb->data_len;

    if(displ > 0) {
      /*
	Move off the offset (we modify the packet for the sake of filtering)
	thus we need to restore it later on

	NOTE: displ = 0 | skb_network_offset(skb)
      */
      skb_push(skb, displ);
    }

    rcu_read_lock_bh();
    res = sk_run_filter(skb, pfr->bpfFilter->insns
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38))
			, pfr->bpfFilter->len
#endif
			);
    rcu_read_unlock_bh();

    /* Restore */
    if(displ > 0)
      skb->data = skb_head, skb->len = skb_len;

    if(res == 0) {
      /* Filter failed */
      if(unlikely(enable_debug))
	printk("[PF_RING] add_skb_to_ring(skb): Filter failed [len=%d][tot=%llu]"
	       "[insert_off=%d][pkt_type=%d][cloned=%d]\n",
	       (int)skb->len, (long long unsigned int)atomic_read(&pfr->slots_info->tot_pkts),
	       (int)atomic_read(&pfr->slots_info->insert_off), skb->pkt_type,
	       skb->cloned);

      return(0);
    }
  }

  return(1);
}

/* ********************************** */

/*
 * add_skb_to_ring()
 *
 * Add the specified skb to the ring so that userland apps/plugins
 * can use the packet.
 *
 * Return code:
 *  0 packet successully processed but no room in the ring
 *  1 packet successully processed and available room in the ring
 * -1  processing error (e.g. the packet has been discarded by
 *                       filter, ring not active...)
 *
 */
static int add_skb_to_ring(struct sk_buff *skb,
			   u_int8_t real_skb,
			   struct pf_ring_socket *pfr,
			   struct pfring_pkthdr *hdr,
			   int is_ip_pkt, int displ,
			   u_int8_t channel_id,
			   u_int8_t num_rx_channels)
{
  int fwd_pkt = 0, rc = 0;
  struct parse_buffer *parse_memory_buffer[MAX_PLUGIN_ID] = { NULL };
  u_int8_t free_parse_mem = 0;
  u_int last_matched_plugin = 0;
  u_int8_t hash_found = 0;

  if(pfr && pfr->rehash_rss && skb->dev)
    channel_id = hash_pkt_header(hdr, 0, 0, 0, 0, 0) % get_num_rx_queues(skb->dev);

  /* This is a memory holder for storing parsed packet information
     that will then be freed when the packet has been handled
  */

  if(unlikely(enable_debug))
    printk("[PF_RING] --> add_skb_to_ring(len=%d) [channel_id=%d/%d][active=%d][%s]\n",
	   hdr->len, channel_id, num_rx_channels,
	   pfr->ring_active, pfr->ring_netdev->dev->name);

  if((!pfring_enabled) || ((!pfr->ring_active) && (pfr->master_ring == NULL)))
    return(-1);

  pfr->num_rx_channels = num_rx_channels; /* Constantly updated */
  hdr->extended_hdr.parsed_pkt.last_matched_rule_id = (u_int16_t)-1;

  atomic_set(&pfr->num_ring_users, 1);

  /* [1] BPF Filtering */
  if(pfr->bpfFilter != NULL) {
    if(bpf_filter_skb(skb, pfr, displ) == 0) {
      atomic_set(&pfr->num_ring_users, 0);
      return(-1);
    }
  }

  if(unlikely(enable_debug)) {
    printk("[PF_RING] add_skb_to_ring: [%s][displ=%d][len=%d][caplen=%d]"
	   "[is_ip_pkt=%d][%d -> %d][%p/%p]\n",
	   (skb->dev->name != NULL) ? skb->dev->name : "<NULL>",
	   displ, hdr->len, hdr->caplen,
	   is_ip_pkt, hdr->extended_hdr.parsed_pkt.l4_src_port,
	   hdr->extended_hdr.parsed_pkt.l4_dst_port, skb->dev,
	   pfr->ring_netdev);
  }

  /* Extensions */
  fwd_pkt = pfr->sw_filtering_rules_default_accept_policy;

  /* printk("[PF_RING] rules_default_accept_policy: [fwd_pkt=%d]\n", fwd_pkt); */

  /* ************************** */

  /* [2] Filter packet according to rules */

  /* [2.1] Search the hash */
  if(pfr->sw_filtering_hash != NULL)
    hash_found = check_perfect_rules(skb, pfr, hdr, &fwd_pkt, &free_parse_mem,
				     parse_memory_buffer, displ, &last_matched_plugin);

  if(unlikely(enable_debug))
    printk("[PF_RING] check_perfect_rules() returned %d\n", hash_found);

  /* [2.2] Search rules list */
  if((!hash_found) && (pfr->num_sw_filtering_rules > 0)) {
    if(check_wildcard_rules(skb, pfr, hdr, &fwd_pkt, &free_parse_mem,
			    parse_memory_buffer, displ, &last_matched_plugin) != 0)
      fwd_pkt = 0;

    if(unlikely(enable_debug))
      printk("[PF_RING] check_wildcard_rules() completed: fwd_pkt=%d\n", fwd_pkt);
  }

  if(fwd_pkt) {
    /* We accept the packet: it needs to be queued */
    if(unlikely(enable_debug))
      printk("[PF_RING] Forwarding packet to userland\n");

    /* [3] Packet sampling */
    if(pfr->sample_rate > 1) {
      write_lock(&pfr->ring_index_lock);
      atomic_inc(&pfr->slots_info->tot_pkts);

      if(pfr->pktToSample <= 1) {
	pfr->pktToSample = pfr->sample_rate;
      } else {
	pfr->pktToSample--;

	if(unlikely(enable_debug))
	  printk("[PF_RING] add_skb_to_ring(skb): sampled packet [len=%d]"
		 "[tot=%llu][insert_off=%d][pkt_type=%d][cloned=%d]\n",
		 (int)skb->len, (long long unsigned int)atomic_read(&pfr->slots_info->tot_pkts),
		 (int)atomic_read(&pfr->slots_info->insert_off), skb->pkt_type,
		 skb->cloned);

	write_unlock(&pfr->ring_index_lock);

	if(free_parse_mem)
	  free_parse_memory(parse_memory_buffer);

	atomic_set(&pfr->num_ring_users, 0);
	return(-1);
      }

      write_unlock(&pfr->ring_index_lock);
    }

    if(hdr->caplen > 0) {
      /* Copy the packet into the bucket */
      int offset;
      void *mem;

      if((last_matched_plugin > 0)
	 && (parse_memory_buffer[last_matched_plugin] != NULL)) {
	offset = hdr->extended_hdr.parsed_header_len = parse_memory_buffer[last_matched_plugin]->mem_len;

	hdr->extended_hdr.parsed_pkt.last_matched_plugin_id = last_matched_plugin;

	if(unlikely(enable_debug))
	  printk("[PF_RING] --> [last_matched_plugin = %d][extended_hdr.parsed_header_len=%d]\n",
		 last_matched_plugin, hdr->extended_hdr.parsed_header_len);

	if(offset > pfr->bucket_len)
	  offset = hdr->extended_hdr.parsed_header_len = pfr->bucket_len;

	mem = parse_memory_buffer[last_matched_plugin]->mem;
      } else
	offset = 0, hdr->extended_hdr.parsed_header_len = 0, mem = NULL;

      rc = add_pkt_to_ring(skb, real_skb, pfr, hdr, displ, channel_id, offset, mem);
    }
  }

  if(unlikely(enable_debug))
    printk("[PF_RING] [pfr->slots_info->insert_off=%d]\n",
	   atomic_read(&pfr->slots_info->insert_off));

  if(free_parse_mem)
    free_parse_memory(parse_memory_buffer);

  atomic_set(&pfr->num_ring_users, 0);

  return(rc);
}

/* ********************************** */

static u_int hash_pkt_cluster(ring_cluster_element * cluster_ptr,
			      struct pfring_pkthdr *hdr)
{
  u_int idx;

  switch(cluster_ptr->cluster.hashing_mode) {
    case cluster_round_robin:
      idx = cluster_ptr->cluster.hashing_id++;
      break;
    case cluster_per_flow_2_tuple:
      idx = hash_pkt_header(hdr, 0, 0, 1, 1, 1);
      break;
    case cluster_per_flow_4_tuple:
      idx = hash_pkt_header(hdr, 0, 0, 0, 1, 1);
      break;
    case cluster_per_flow_5_tuple:
      idx = hash_pkt_header(hdr, 0, 0, 0, 0, 1);
      break;
    case cluster_per_flow:
    default:
      idx = hash_pkt_header(hdr, 0, 0, 0, 0, 0);
      break;
  }

  return(idx % cluster_ptr->cluster.num_cluster_elements);
}

/* ********************************** */

static int register_plugin(struct pfring_plugin_registration *reg)
{
  if(reg == NULL)
    return(-1);

  if(unlikely(enable_debug))
    printk("[PF_RING] --> register_plugin(%d)\n", reg->plugin_id);

  if((reg->plugin_id >= MAX_PLUGIN_ID) || (reg->plugin_id == 0))
    return(-EINVAL);

  if(plugin_registration[reg->plugin_id] != NULL)
    return(-EINVAL);	/* plugin already registered */

  if(reg->pfring_plugin_register == NULL)
    printk("[PF_RING] WARNING: plugin %d does not implement handle pfring_plugin_register: please fix it\n",
	   reg->plugin_id);

  plugin_registration[reg->plugin_id] = reg;
  plugin_registration_size++;

  max_registered_plugin_id = max_val(max_registered_plugin_id, reg->plugin_id);

  printk("[PF_RING] registered plugin [id=%d][max=%d][%p]\n",
	 reg->plugin_id, max_registered_plugin_id,
	 plugin_registration[reg->plugin_id]);
  try_module_get(THIS_MODULE);	/* Increment usage count */
  return(0);
}

/* ********************************** */

int unregister_plugin(u_int16_t pfring_plugin_id)
{
  int i;

  if(pfring_plugin_id >= MAX_PLUGIN_ID)
    return(-EINVAL);

  if(plugin_registration[pfring_plugin_id] == NULL)
    return(-EINVAL);	/* plugin not registered */
  else {
    struct list_head *ptr, *tmp_ptr, *ring_ptr, *ring_tmp_ptr;

    plugin_registration[pfring_plugin_id] = NULL;
    plugin_registration_size--;

    ring_read_lock();
    list_for_each_safe(ring_ptr, ring_tmp_ptr, &ring_table) {
      struct ring_element *entry =
	list_entry(ring_ptr, struct ring_element, list);
      struct pf_ring_socket *pfr = ring_sk(entry->sk);

      list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
	sw_filtering_rule_element *rule;

	rule = list_entry(ptr, sw_filtering_rule_element, list);

	if(rule->rule.plugin_action.plugin_id == pfring_plugin_id) {
	  rule->rule.plugin_action.plugin_id = NO_PLUGIN_ID;

	  if(plugin_registration[pfring_plugin_id]
	     && plugin_registration[pfring_plugin_id]->pfring_plugin_free_ring_mem) {
	    /* Custom free function */
	    plugin_registration[pfring_plugin_id]->pfring_plugin_free_ring_mem(rule);
	  }

	  if(rule->plugin_data_ptr !=  NULL) {
	    kfree(rule->plugin_data_ptr);
	    rule->plugin_data_ptr = NULL;
	  }
	}
      }
    }
    ring_read_unlock();

    for(i = MAX_PLUGIN_ID - 1; i > 0; i--) {
      if(plugin_registration[i] != NULL) {
	max_registered_plugin_id = i;
	break;
      }
    }

    printk("[PF_RING] unregistered plugin [id=%d][max=%d]\n",
	   pfring_plugin_id, max_registered_plugin_id);
    module_put(THIS_MODULE);	/* Decrement usage count */
    return(0);
  }
}

/* ********************************** */

inline int is_valid_skb_direction(packet_direction direction, u_char recv_packet) {
  switch(direction) {
  case rx_and_tx_direction:
    return(1);
  case rx_only_direction:
    if(recv_packet) return(1);
    break;
  case tx_only_direction:
    if(!recv_packet) return(1);
    break;
  }

  return(0);
}

/* ********************************** */

static struct sk_buff* defrag_skb(struct sk_buff *skb,
				  u_int16_t displ,
				  struct pfring_pkthdr *hdr,
				  int *defragmented_skb) {
  struct sk_buff *cloned = NULL;
  struct iphdr *iphdr = NULL;
  struct sk_buff *skk = NULL;

  skb_set_network_header(skb, hdr->extended_hdr.parsed_pkt.offset.l3_offset - displ);
  skb_reset_transport_header(skb);

  iphdr = ip_hdr(skb);

  if(iphdr && (iphdr->version == 4)) {
    if(unlikely(enable_debug))
      printk("[PF_RING] [version=%d] %X -> %X\n",
	     iphdr->version, iphdr->saddr, iphdr->daddr);

    if(iphdr->frag_off & htons(IP_MF | IP_OFFSET)) {
      if((cloned = skb_clone(skb, GFP_ATOMIC)) != NULL) {
        int vlan_offset = 0;

        if(displ && (hdr->extended_hdr.parsed_pkt.offset.l3_offset - displ) /*VLAN*/){
	  vlan_offset = 4;
          skb_pull(cloned, vlan_offset);
          displ += vlan_offset;
	}

	skb_set_network_header(cloned, hdr->extended_hdr.parsed_pkt.offset.l3_offset - displ);
	skb_reset_transport_header(cloned);
        iphdr = ip_hdr(cloned);

	if(unlikely(enable_debug)) {
	  int ihl, end;
	  int offset = ntohs(iphdr->frag_off);
	  offset &= IP_OFFSET;
	  offset <<= 3;
	  ihl = iphdr->ihl * 4;
          end = offset + cloned->len - ihl;

	  printk("[PF_RING] There is a fragment to handle [proto=%d][frag_off=%u]"
		 "[ip_id=%u][ip_hdr_len=%d][end=%d][network_header=%d][displ=%d]\n",
		 iphdr->protocol, offset,
		 ntohs(iphdr->id),
		 ihl, end,
		 hdr->extended_hdr.parsed_pkt.offset.l3_offset - displ, displ);
	}
	skk = ring_gather_frags(cloned);

	if(skk != NULL) {
	  if(unlikely(enable_debug)) {
	    unsigned char *c;
	    printk("[PF_RING] IP reasm on new skb [skb_len=%d]"
		   "[head_len=%d][nr_frags=%d][frag_list=%p]\n",
		   (int)skk->len,
		   skb_headlen(skk),
		   skb_shinfo(skk)->nr_frags,
		   skb_shinfo(skk)->frag_list);
	    c = skb_network_header(skk);
	    printk("[PF_RING] IP header "
	           "%X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X\n",
		   c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9],
		   c[10], c[11], c[12], c[13], c[14], c[15], c[16], c[17], c[18], c[19]);
	    c -= displ;
	    printk("[PF_RING] L2 header "
	           "%X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X %X\n",
		   c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9],
		   c[10], c[11], c[12], c[13], c[14], c[15], c[16], c[17]);
          }

	  if(vlan_offset > 0){
	    skb_push(skk, vlan_offset);
	    displ -= vlan_offset;
	  }

	  skb = skk;
	  *defragmented_skb = 1;
	  hdr->len = hdr->caplen = skb->len + displ;
	  parse_pkt(skb, 1, displ, hdr, 1);
	} else {
	  //printk("[PF_RING] Fragment queued \n");
	  return(NULL);	/* mask rcvd fragments */
	}
      }
    } else {
      if(unlikely(enable_debug))
	printk("[PF_RING] Do not seems to be a fragmented ip_pkt[iphdr=%p]\n",
	       iphdr);
    }
  } else if(iphdr && iphdr->version == 6) {
    /* Re-assembling fragmented IPv6 packets has not been
       implemented. Probability of observing fragmented IPv6
       packets is extremely low. */
    if(unlikely(enable_debug))
      printk("[PF_RING] Re-assembling fragmented IPv6 packet hs not been implemented\n");
  }

  return(skb);
}

/* ********************************** */

/*
  PF_RING main entry point

  Return code
  0 - Packet not handled
  1 - Packet handled successfully
  2 - Packet handled successfully but unable to copy it into
      the ring due to lack of available space
*/

static int skb_ring_handler(struct sk_buff *skb,
			    u_int8_t recv_packet,
			    u_int8_t real_skb /* 1=real skb, 0=faked skb */ ,
			    u_int32_t channel_id,
			    u_int32_t num_rx_channels)
{
  struct sock *skElement;
  int rc = 0, is_ip_pkt = 0, room_available = 0;
  struct list_head *ptr, *tmp_ptr;
  struct pfring_pkthdr hdr;
  int displ;
  int defragmented_skb = 0;
  struct sk_buff *skk = NULL;
  struct sk_buff *orig_skb = skb;

  /* Check if there's at least one PF_RING ring defined that
     could receive the packet: if none just stop here */

  if(ring_table_size == 0)
    return(rc);

  if(recv_packet) {
    /* Hack for identifying a packet received by the e1000 */
    if(real_skb)
      displ = SKB_DISPLACEMENT;
    else
      displ = 0; /* Received by the e1000 wrapper */
  } else
    displ = 0;

  if(unlikely(enable_debug)) {
    if(skb->dev && (skb->dev->ifindex < MAX_NUM_IFIDX))
      printk("[PF_RING] --> skb_ring_handler(%s): %d rings [num_any_rings=%d]\n",
	     skb->dev->name, num_rings_per_device[skb->dev->ifindex], num_any_rings);
  }

  if((num_any_rings == 0)
     && (skb->dev
	 && (skb->dev->ifindex < MAX_NUM_IFIDX)
	 && (num_rings_per_device[skb->dev->ifindex] == 0)))
    return(rc);

#ifdef PROFILING
  uint64_t rdt = _rdtsc(), rdt1, rdt2;
#endif

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30))
  if(channel_id == UNKNOWN_RX_CHANNEL)
    channel_id = skb_get_rx_queue(skb);
#endif

  if(channel_id > MAX_NUM_RX_CHANNELS) channel_id = 0 /* MAX_NUM_RX_CHANNELS */;

  if((!skb) /* Invalid skb */ ||((!enable_tx_capture) && (!recv_packet))) {
    /*
      An outgoing packet is about to be sent out
      but we decided not to handle transmitted
      packets.
    */
    return(0);
  }

  if(unlikely(enable_debug)) {
    struct timeval tv;

    skb_get_timestamp(skb, &tv);
    printk("[PF_RING] skb_ring_handler() [skb=%p][%u.%u][len=%d][dev=%s][csum=%u]\n",
	   skb, (unsigned int)tv.tv_sec, (unsigned int)tv.tv_usec,
	   skb->len, skb->dev == NULL ? "<NULL>" : skb->dev->name,
	   skb->csum);
  }

#ifdef PROFILING
  rdt1 = _rdtsc();
#endif

  memset(&hdr, 0, sizeof(hdr));

  hdr.ts.tv_sec = 0;
  /*
     The min() below is not really necessary but we have observed that sometimes
     skb->len > MTU thus it's better to be on the safe side
  */
  hdr.len = hdr.caplen = min(skb->len + displ,
			     skb->dev->mtu /* 1500 */
			     + skb->dev->hard_header_len /* 14 */
			     + 4 /* VLAN header */);

  if(quick_mode) {
    struct pf_ring_socket *pfr = device_rings[skb->dev->ifindex][channel_id];

    hdr.extended_hdr.parsed_header_len = 0;

    if(pfr && pfr->rehash_rss && skb->dev) {
      parse_pkt(skb, real_skb, displ, &hdr, 1);

      channel_id = hash_pkt_header(&hdr, 0, 0, 0, 0, 0) % get_num_rx_queues(skb->dev);
    }

    if(unlikely(enable_debug)) printk("[PF_RING] Expecting channel %d [%p]\n", channel_id, pfr);

    if((pfr != NULL) && is_valid_skb_direction(pfr->direction, recv_packet)) {
      /* printk("==>>> [%d][%d]\n", skb->dev->ifindex, channel_id); */

      rc = 1, hdr.caplen = min_val(hdr.caplen, pfr->bucket_len);
      room_available |= copy_data_to_ring(real_skb ? skb : NULL, pfr, &hdr, displ, 0, NULL, NULL, 0);
    }
  } else {
    is_ip_pkt = parse_pkt(skb, real_skb, displ, &hdr, 1);

    if(enable_ip_defrag) {
      if(real_skb
	 && is_ip_pkt
	 && recv_packet) {
	skb = skk = defrag_skb(skb, displ, &hdr, &defragmented_skb);

	if(skb == NULL)
	  return(0);
      }
    }

    if(skb->dev)
      hdr.extended_hdr.if_index = skb->dev->ifindex;
    else
      hdr.extended_hdr.if_index = UNKNOWN_INTERFACE;

    hdr.extended_hdr.rx_direction = recv_packet;

    /* Avoid the ring to be manipulated while playing with it */
    ring_read_lock();

    /* [1] Check unclustered sockets */
    list_for_each_safe(ptr, tmp_ptr, &ring_table) {
      struct pf_ring_socket *pfr;
      struct ring_element *entry;

      entry = list_entry(ptr, struct ring_element, list);

      skElement = entry->sk;
      pfr = ring_sk(skElement);

      if((pfr != NULL)
	 && (
	     test_bit(skb->dev->ifindex, pfr->netdev_mask)
	     || (pfr->ring_netdev == &any_device_element) /* Socket bound to 'any' */
	     || ((skb->dev->flags & IFF_SLAVE) && (pfr->ring_netdev->dev == skb->dev->master)))
	 && (pfr->ring_netdev != &none_device_element) /* Not a dummy socket bound to "none" */
	 && (pfr->cluster_id == 0 /* No cluster */ )
	 && (pfr->ring_slots != NULL)
	 && is_valid_skb_direction(pfr->direction, recv_packet)
	 ) {
	/* We've found the ring where the packet can be stored */
	int old_caplen = hdr.caplen;  /* Keep old lenght */

	hdr.caplen = min_val(hdr.caplen, pfr->bucket_len);
	room_available |= add_skb_to_ring(skb, real_skb, pfr, &hdr, is_ip_pkt,
					  displ, channel_id, num_rx_channels);
	hdr.caplen = old_caplen;
	rc = 1;	/* Ring found: we've done our job */
      }
    }

    /* [2] Check socket clusters */
    list_for_each(ptr, &ring_cluster_list) {
      ring_cluster_element *cluster_ptr;
      struct pf_ring_socket *pfr;

      cluster_ptr = list_entry(ptr, ring_cluster_element, list);

      if(cluster_ptr->cluster.num_cluster_elements > 0) {
	u_int skb_hash = hash_pkt_cluster(cluster_ptr, &hdr);
	u_short num_iterations;

	/*
	  We try to add the packet to the right cluster
	  element, but if we're working in round-robin and this
	  element is full, we try to add this to the next available
	  element. If none with at least a free slot can be found
	  then we give up :-(
	*/

	for(num_iterations = 0;
	    num_iterations < cluster_ptr->cluster.num_cluster_elements;
	    num_iterations++) {

	  skElement = cluster_ptr->cluster.sk[skb_hash];

	  if(skElement != NULL) {
	    pfr = ring_sk(skElement);

	    if((pfr != NULL)
	       && (pfr->ring_slots != NULL)
	       && (test_bit(skb->dev->ifindex, pfr->netdev_mask)
		   || ((skb->dev->flags & IFF_SLAVE)
		       && (pfr->ring_netdev->dev == skb->dev->master)))
	       && is_valid_skb_direction(pfr->direction, recv_packet)
	       ) {
	      if(check_free_slot(pfr, atomic_read(&pfr->slots_info->insert_off)) /* Not full */) {
		/* We've found the ring where the packet can be stored */
		room_available |= add_skb_to_ring(skb, real_skb, pfr, &hdr, is_ip_pkt,
						  displ, channel_id, num_rx_channels);
		rc = 1; /* Ring found: we've done our job */
		break;

	      } else if((cluster_ptr->cluster.hashing_mode != cluster_round_robin)
			/* We're the last element of the cluster so no further cluster element to check */
			|| ((num_iterations + 1) > cluster_ptr->cluster.num_cluster_elements)) {
		atomic_inc(&pfr->slots_info->tot_pkts), atomic_inc(&pfr->slots_info->tot_lost);
	      }
	    }
	  }

	  if(cluster_ptr->cluster.hashing_mode != cluster_round_robin)
	    break;
	  else
	    skb_hash = (skb_hash + 1) % cluster_ptr->cluster.num_cluster_elements;
	}
      }
    } /* Clustering */

    ring_read_unlock();

#ifdef PROFILING
    rdt1 = _rdtsc() - rdt1;
    rdt2 = _rdtsc();
#endif

    /* Fragment handling */
    if(skk != NULL && defragmented_skb)
      kfree_skb(skk);
  }

  if(rc == 1) {
    if(transparent_mode != driver2pf_ring_non_transparent /* 2 */)
      rc = 0;
    else {
      if(recv_packet && real_skb) {
	if(unlikely(enable_debug))
	  printk("[PF_RING] kfree_skb()\n");

	kfree_skb(orig_skb); /* Free memory */
      }
    }
  }

#ifdef PROFILING
  rdt2 = _rdtsc() - rdt2;
  rdt = _rdtsc() - rdt;

  if(unlikely(enable_debug))
    printk("[PF_RING] # cycles: %d [lock costed %d %d%%][free costed %d %d%%]\n",
	   (int)rdt, rdt - rdt1,
	   (int)((float)((rdt - rdt1) * 100) / (float)rdt), rdt2,
	   (int)((float)(rdt2 * 100) / (float)rdt));
#endif

  //printk("[PF_RING] Returned %d\n", rc);

  if((rc == 1) && (room_available == 0))
    rc = 2;

  return(rc); /*  0 = packet not handled */
}

/* ********************************** */

struct sk_buff skb;

static int buffer_ring_handler(struct net_device *dev, char *data, int len)
{
  if(unlikely(enable_debug))
    printk("[PF_RING] buffer_ring_handler: [dev=%s][len=%d]\n",
	   dev->name == NULL ? "<NULL>" : dev->name, len);

  skb.dev = dev, skb.len = len, skb.data = data, skb.data_len = len;

  /* BD - API changed for time keeping */
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14))
  skb.stamp.tv_sec = 0;
#elif(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
  skb.tstamp.off_sec = 0;
#else
  skb.tstamp.tv64 = 0;
#endif

  return(skb_ring_handler(&skb, 1, 0 /* fake skb */ ,
			  UNKNOWN_RX_CHANNEL,
			  UNKNOWN_NUM_RX_CHANNELS));
}

/* ********************************** */

static int packet_rcv(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16))
		      , struct net_device *orig_dev
#endif
		      )
{
  int rc;

  if(skb->pkt_type != PACKET_LOOPBACK) {
    rc = skb_ring_handler(skb,
			  (skb->pkt_type == PACKET_OUTGOING) ? 0 : 1,
			  1, UNKNOWN_RX_CHANNEL, UNKNOWN_NUM_RX_CHANNELS);

  } else
    rc = 0;

  /*
    This packet has been received by Linux through its standard
    mechanisms (no PF_RING transparent/TNAPI)
  */
  kfree_skb(skb);
  return(rc);
}

/* ********************************** */

void register_device_handler(void) {
  if(transparent_mode != standard_linux_path) return;

  prot_hook.func = packet_rcv;
  prot_hook.type = htons(ETH_P_ALL);
  dev_add_pack(&prot_hook);
}

/* ********************************** */

void unregister_device_handler(void) {
  if(transparent_mode != standard_linux_path) return;
  dev_remove_pack(&prot_hook); /* Remove protocol hook */
}

/* ********************************** */

static int ring_create(
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
		       struct net *net,
#endif
		       struct socket *sock, int protocol
#if((LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)) || ((LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)) && defined(REDHAT_PATCHED_KERNEL)))
		       , int kern
#endif
		       )
{
  struct sock *sk;
  struct pf_ring_socket *pfr;
  int err = -ENOMEM;

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_create()\n");

  /* Are you root, superuser or so ? */
  if(!capable(CAP_NET_ADMIN))
    return -EPERM;

  if(sock->type != SOCK_RAW)
    return -ESOCKTNOSUPPORT;

  if(protocol != htons(ETH_P_ALL))
    return -EPROTONOSUPPORT;

#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,11))
  sk = sk_alloc(PF_RING, GFP_KERNEL, 1, NULL);
#else
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
  // BD: API changed in 2.6.12, ref:
  // http://svn.clkao.org/svnweb/linux/revision/?rev=28201
  sk = sk_alloc(PF_RING, GFP_ATOMIC, &ring_proto, 1);
#else
  sk = sk_alloc(net, PF_INET, GFP_KERNEL, &ring_proto);
#endif
#endif

  if(sk == NULL)
    goto out;

  sock->ops = &ring_ops;
  sock_init_data(sock, sk);
#if(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,11))
  sk_set_owner(sk, THIS_MODULE);
#endif

  ring_sk(sk) = ring_sk_datatype(kmalloc(sizeof(*pfr), GFP_KERNEL));

  if(!(pfr = ring_sk(sk))) {
    sk_free(sk);
    goto out;
  }

  memset(pfr, 0, sizeof(*pfr));
  pfr->ring_shutdown = 0;
  pfr->ring_active = 0;	/* We activate as soon as somebody waits for packets */
  pfr->num_rx_channels = UNKNOWN_NUM_RX_CHANNELS;
  pfr->channel_id = RING_ANY_CHANNEL;
  pfr->bucket_len = DEFAULT_BUCKET_LEN;
  pfr->poll_num_pkts_watermark = DEFAULT_MIN_PKT_QUEUED;
  pfr->add_packet_to_ring = add_packet_to_ring;
  pfr->add_raw_packet_to_ring = add_raw_packet_to_ring;
  init_waitqueue_head(&pfr->ring_slots_waitqueue);
  rwlock_init(&pfr->ring_index_lock);
  rwlock_init(&pfr->ring_rules_lock);
  atomic_set(&pfr->num_ring_users, 0);
  INIT_LIST_HEAD(&pfr->sw_filtering_rules);
  INIT_LIST_HEAD(&pfr->hw_filtering_rules);
  sk->sk_family = PF_RING;
  sk->sk_destruct = ring_sock_destruct;

  ring_insert(sk);

  pfr->master_ring = NULL;
  pfr->ring_netdev = &none_device_element; /* Unbound socket */
  pfr->sample_rate = 1;	/* No sampling */
  pfr->ring_id = ring_id_serial++;

  ring_proc_add(pfr);

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_create(): created\n");

  return(0);
 out:
  return err;
}

/* ************************************* */

static int ring_proc_virtual_filtering_dev_get_info(char *buf, char **start, off_t offset,
						    int len, int *unused, void *data)
{
  int rlen = 0;

  if(data != NULL) {
    virtual_filtering_device_info *info = (virtual_filtering_device_info*)data;
    char *dev_family = "???";

    switch(info->device_type) {
    case standard_nic_family: dev_family = "Standard NIC"; break;
    case intel_82599_family:  dev_family = "Intel 82599"; break;
    }

    rlen =  sprintf(buf,      "Name:              %s\n", info->device_name);
    rlen += sprintf(buf+rlen, "Family:            %s\n", dev_family);
  }

  return rlen;
}

/* ************************************* */

static virtual_filtering_device_element* add_virtual_filtering_device(struct sock *sock,
								      virtual_filtering_device_info *info)
{
  virtual_filtering_device_element *elem;
  struct list_head *ptr, *tmp_ptr;

  if(unlikely(enable_debug))
    printk("[PF_RING] --> add_virtual_filtering_device(%s)\n", info->device_name);

  if(info == NULL)
    return(NULL);

  /* Check if the same entry is already present */
  write_lock(&virtual_filtering_lock);
  list_for_each_safe(ptr, tmp_ptr, &virtual_filtering_devices_list) {
    virtual_filtering_device_element *filtering_ptr = list_entry(ptr, virtual_filtering_device_element, list);

    if(strcmp(filtering_ptr->info.device_name, info->device_name) == 0) {
      write_unlock(&virtual_filtering_lock);
      return(NULL); /* Entry alredy present */
    }
  }

  elem = kmalloc(sizeof(virtual_filtering_device_element), GFP_KERNEL);

  if(elem == NULL)
    return(NULL);
  else {
    memcpy(&elem->info, info, sizeof(virtual_filtering_device_info));
    INIT_LIST_HEAD(&elem->list);
  }

  list_add(&elem->list, &virtual_filtering_devices_list);  /* Add as first entry */
  write_unlock(&virtual_filtering_lock);

  /* Add /proc entry */
  elem->info.proc_entry = proc_mkdir(elem->info.device_name, ring_proc_dev_dir);
  create_proc_read_entry(PROC_INFO, 0 /* read-only */,
			 elem->info.proc_entry,
			 ring_proc_virtual_filtering_dev_get_info /* read */,
			 (void*)&elem->info);

  return(elem);
}

/* ************************************* */

static int remove_virtual_filtering_device(struct sock *sock, char *device_name)
{
  struct list_head *ptr, *tmp_ptr;

  if(unlikely(enable_debug))
    printk("[PF_RING] --> remove_virtual_filtering_device(%s)\n", device_name);

  write_lock(&virtual_filtering_lock);
  list_for_each_safe(ptr, tmp_ptr, &virtual_filtering_devices_list) {
    virtual_filtering_device_element *filtering_ptr;

    filtering_ptr = list_entry(ptr, virtual_filtering_device_element, list);

    if(strcmp(filtering_ptr->info.device_name, device_name) == 0) {
      /* Remove /proc entry */
      remove_proc_entry(PROC_INFO, filtering_ptr->info.proc_entry);
      remove_proc_entry(filtering_ptr->info.device_name, ring_proc_dev_dir);

      list_del(ptr);
      write_unlock(&virtual_filtering_lock);
      kfree(filtering_ptr);
      return(0);
    }
  }

  write_unlock(&virtual_filtering_lock);

  return(-EINVAL);	/* Not found */
}

/* ********************************** */

static struct pf_userspace_ring* userspace_ring_create(char *u_dev_name, userspace_ring_client_type type,
                                                       wait_queue_head_t *consumer_ring_slots_waitqueue) {
  char *c_p;
  long id;
  struct list_head *ptr, *tmp_ptr;
  struct pf_userspace_ring *entry;
  struct pf_userspace_ring *usr = NULL;

  if(strncmp(u_dev_name, "usr", 3) != 0)
    return NULL;

  id = simple_strtol(&u_dev_name[3], &c_p, 10);

  write_lock(&userspace_ring_lock);

  /* checking if the userspace ring already exists */
  list_for_each_safe(ptr, tmp_ptr, &userspace_ring_list) {
    entry = list_entry(ptr, struct pf_userspace_ring, list);
    if(entry->id == id) {

      if(atomic_read(&entry->users[type]) > 0)
        goto unlock;

      usr = entry;
      break;
    }
  }

  /* creating a new userspace ring */
  if(usr == NULL) {
    /* Note: a userspace ring can be created by a consumer only,
     * (however a producer can keep it if the consumer dies) */
    if(type == userspace_ring_producer)
      goto unlock;

    usr = kmalloc(sizeof(struct pf_userspace_ring), GFP_ATOMIC);

    if(usr == NULL)
      goto unlock;

    memset(usr, 0, sizeof(struct pf_userspace_ring));

    usr->id = id;
    atomic_set(&usr->users[userspace_ring_consumer], 0);
    atomic_set(&usr->users[userspace_ring_producer], 0);

    list_add(&usr->list, &userspace_ring_list);
  }

  atomic_inc(&usr->users[type]);

  if(type == userspace_ring_consumer)
    usr->consumer_ring_slots_waitqueue = consumer_ring_slots_waitqueue;

unlock:
  write_unlock(&userspace_ring_lock);

  if(unlikely(enable_debug))
    if(usr != NULL)
      printk("[PF_RING] userspace_ring_create() Userspace ring found or created.\n");

  return usr;
}

/* ********************************** */

static int userspace_ring_remove(struct pf_userspace_ring *usr,
                                        userspace_ring_client_type type) {
  struct list_head *ptr, *tmp_ptr;
  struct pf_userspace_ring *entry;
  int ret = 0;

  write_lock(&userspace_ring_lock);

  list_for_each_safe(ptr, tmp_ptr, &userspace_ring_list) {
    entry = list_entry(ptr, struct pf_userspace_ring, list);

    if(entry == usr) {
      if(atomic_read(&usr->users[type]) > 0)
        atomic_dec(&usr->users[type]);

      if(type == userspace_ring_consumer)
        usr->consumer_ring_slots_waitqueue = NULL;

      if(atomic_read(&usr->users[userspace_ring_consumer]) == 0
       && atomic_read(&usr->users[userspace_ring_producer]) == 0) {
        ret = 1; /* ring memory can be freed */
        list_del(ptr);
        kfree(entry);
      }

      break;
    }
  }

  write_unlock(&userspace_ring_lock);

  if(unlikely(enable_debug))
    if(ret == 1)
      printk("[PF_RING] userspace_ring_remove() Ring can be freed.\n");

  return ret;
}

/* ************************************* */

void reserve_memory(unsigned long base, unsigned long mem_len) {
  struct page *page, *page_end;

  page_end = virt_to_page(base + mem_len - 1);
  for(page = virt_to_page(base); page <= page_end; page++)
    SetPageReserved(page);
}

void unreserve_memory(unsigned long base, unsigned long mem_len) {
  struct page *page, *page_end;

  page_end = virt_to_page(base + mem_len - 1);
  for(page = virt_to_page(base); page <= page_end; page++)
    ClearPageReserved(page);
}

static void free_contiguous_memory(unsigned long mem, u_int mem_len) {
  if(mem != 0) {
    unreserve_memory(mem, mem_len);
    free_pages(mem, get_order(mem_len));
  }
}

static unsigned long alloc_contiguous_memory(u_int mem_len) {
  unsigned long mem = 0;

  mem = __get_free_pages(GFP_KERNEL, get_order(mem_len));

  if(mem)
    reserve_memory(mem, mem_len);
  else
    if(unlikely(enable_debug)) 
      printk("[PF_RING] %s() Failure (len=%d, order=%d)\n", __FUNCTION__, mem_len, get_order(mem_len));

  return(mem);
}

static int allocate_extra_dma_memory(struct pf_ring_socket *pfr, struct device *hwdev, 
                                     u_int32_t num_slots, u_int32_t slot_len, u_int32_t chunk_len)
{
  u_int i, num_slots_per_chunk;

  pfr->extra_dma_memory_chunk_len = chunk_len;
  pfr->extra_dma_memory_num_slots = num_slots;
  pfr->extra_dma_memory_slot_len = slot_len;
  pfr->extra_dma_memory_hwdev = hwdev;
  num_slots_per_chunk = pfr->extra_dma_memory_chunk_len / pfr->extra_dma_memory_slot_len;
  pfr->extra_dma_memory_num_chunks = pfr->extra_dma_memory_num_slots / num_slots_per_chunk;

  if(pfr->extra_dma_memory || pfr->extra_dma_memory_addr) /* already called */
    return -EINVAL;

  if((pfr->extra_dma_memory = kcalloc(1, sizeof(unsigned long) * pfr->extra_dma_memory_num_chunks, GFP_KERNEL)) == NULL)
    return -ENOMEM;

  if ((pfr->extra_dma_memory_addr = kcalloc(1, sizeof(u_int64_t) * pfr->extra_dma_memory_num_slots, GFP_KERNEL)) == NULL) {
    kfree(pfr->extra_dma_memory);
    pfr->extra_dma_memory = NULL;
    return -ENOMEM;
  }

  if(unlikely(enable_debug)) 
    printk("[PF_RING] %s() Allocating %d chunks of %d bytes [slots per chunk=%d]\n", 
           __FUNCTION__, pfr->extra_dma_memory_num_chunks, pfr->extra_dma_memory_chunk_len, num_slots_per_chunk);

  /* Allocating memory chunks */
  for(i=0; i < pfr->extra_dma_memory_num_chunks; i++) {
    pfr->extra_dma_memory[i] = alloc_contiguous_memory(pfr->extra_dma_memory_chunk_len);

    if(!pfr->extra_dma_memory[i]) {
      printk("[PF_RING] %s() Warning: no more free memory available! Allocated %d of %d chunks.\n", 
	     __FUNCTION__, i + 1, pfr->extra_dma_memory_num_chunks);

      pfr->extra_dma_memory_num_chunks = i;
      break;
    }
  }

  /* Mapping DMA slots */
  for(i=0; i < pfr->extra_dma_memory_num_slots; i++) {
    u_int chunk_id = i / num_slots_per_chunk;
    u_int offset = (i % num_slots_per_chunk) * pfr->extra_dma_memory_slot_len;
    char *slot;

    if(!pfr->extra_dma_memory[chunk_id])
      break;

    slot = (char *) (pfr->extra_dma_memory[chunk_id] + offset);

    if(unlikely(enable_debug))
      printk("[PF_RING] %s() Mapping DMA slot %d of %d [slot addr=%p][offset=%u]\n",
             __FUNCTION__, i + 1, pfr->extra_dma_memory_num_slots, slot, offset);

      pfr->extra_dma_memory_addr[i] = cpu_to_le64(
        pci_map_single(to_pci_dev(pfr->extra_dma_memory_hwdev), slot,
                       pfr->extra_dma_memory_slot_len,
                       PCI_DMA_BIDIRECTIONAL));

      if(dma_mapping_error(
#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,26))
                           pfr->extra_dma_memory_hwdev, 
#endif
			   pfr->extra_dma_memory_addr[i])) {
        printk("[PF_RING] %s() Error mapping DMA slot %d of %d \n", __FUNCTION__, i + 1, pfr->extra_dma_memory_num_slots);
	pfr->extra_dma_memory_addr[i] = 0;
        break;
      }
  }

  return 0;
}

static void free_extra_dma_memory(struct pf_ring_socket *pfr) {
  u_int i;

  if(!pfr->extra_dma_memory)
    return;
  
  /* Unmapping DMA addresses */
  if(pfr->extra_dma_memory_addr) {
    for(i=0; i < pfr->extra_dma_memory_num_slots; i++) {
      if(pfr->extra_dma_memory_addr[i]) {
        dma_unmap_single(pfr->extra_dma_memory_hwdev, pfr->extra_dma_memory_addr[i], 
	                 pfr->extra_dma_memory_slot_len, 
	                 PCI_DMA_BIDIRECTIONAL);
	pfr->extra_dma_memory_addr[i] = 0;
      }
    }
    kfree(pfr->extra_dma_memory_addr);
    pfr->extra_dma_memory_addr = NULL;
  }

  /* Freeing memory */
  for(i=0; i < pfr->extra_dma_memory_num_chunks; i++) {
    if(pfr->extra_dma_memory[i]) {
      if(unlikely(enable_debug)) 
        printk("[PF_RING] %s() Freeing chunk %d of %d\n", __FUNCTION__, i, pfr->extra_dma_memory_num_chunks);

      free_contiguous_memory(pfr->extra_dma_memory[i], pfr->extra_dma_memory_chunk_len); 
      pfr->extra_dma_memory[i] = 0;
    }
  }

  pfr->extra_dma_memory_num_chunks = 0;
  kfree(pfr->extra_dma_memory);
  pfr->extra_dma_memory = NULL;
}

/* *********************************************** */

static int ring_release(struct socket *sock)
{
  struct sock *sk = sock->sk;
  struct pf_ring_socket *pfr = ring_sk(sk);
  struct list_head *ptr, *tmp_ptr;
  void *ring_memory_ptr;
  int free_ring_memory = 1;

  if(!sk)
    return 0;
  else
    pfr->ring_active = 0;

  /* Notify the consumer that we're shutting down */
  if(pfr->kernel_consumer_plugin_id
     && plugin_registration[pfr->kernel_consumer_plugin_id]->pfring_packet_term) {
    plugin_registration[pfr->kernel_consumer_plugin_id]->pfring_packet_term(pfr);
  }

  /* Wait until the ring is being used... */
  while(atomic_read(&pfr->num_ring_users) > 0) {
    schedule();
  }

  if(unlikely(enable_debug))
    printk("[PF_RING] called ring_release(%s)\n", pfr->ring_netdev->dev->name);

  if(pfr->kernel_consumer_options) kfree(pfr->kernel_consumer_options);

  /*
    The calls below must be placed outside the
    write_lock...write_unlock block.
  */
  sock_orphan(sk);
  ring_proc_remove(pfr);
  ring_write_lock();

  if(pfr->ring_netdev->dev && pfr->ring_netdev == &any_device_element)
    num_any_rings--;
  else {
    if(pfr->ring_netdev
       && (pfr->ring_netdev->dev->ifindex < MAX_NUM_IFIDX)) {
      int i;

      if(num_rings_per_device[pfr->ring_netdev->dev->ifindex] > 0)
	num_rings_per_device[pfr->ring_netdev->dev->ifindex]--;

      for(i=0; i<MAX_NUM_RX_CHANNELS; i++) {
	u_int32_t the_bit = 1 << i;
	
	if((pfr->channel_id & the_bit) == the_bit) {
	  if(device_rings[pfr->ring_netdev->dev->ifindex][i] == pfr) {
	    /*
	      We must make sure that this is really us and not that by some chance
	      (e.g. bind failed) another ring
	    */
	    device_rings[pfr->ring_netdev->dev->ifindex][i] = NULL;	  
	  }
	}
      }
    }
  }

  if(pfr->ring_netdev != &none_device_element) {
    if(pfr->cluster_id != 0)
      remove_from_cluster(sk, pfr);
  }

  ring_remove(sk);

  sock->sk = NULL;

  /* Free rules */
  if(pfr->ring_netdev != &none_device_element) {
    list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
      sw_filtering_rule_element *rule;
      rule = list_entry(ptr, sw_filtering_rule_element, list);

      list_del(ptr);
      free_filtering_rule(rule, 1);
      kfree(rule);
    }

    /* Filtering hash rules */
    if(pfr->sw_filtering_hash) {
      int i;

      for(i = 0; i < DEFAULT_RING_HASH_SIZE; i++) {
	if(pfr->sw_filtering_hash[i] != NULL) {
	  sw_filtering_hash_bucket *scan = pfr->sw_filtering_hash[i], *next;

	  while(scan != NULL) {
	    next = scan->next;

	    free_sw_filtering_hash_bucket(scan);
	    kfree(scan);
	    scan = next;
	  }
	}
      }

      kfree(pfr->sw_filtering_hash);
    }

    /* printk("[PF_RING] --> num_hw_filtering_rules=%d\n", pfr->num_hw_filtering_rules); */

    /* Free Hw Filtering Rules */
    if(pfr->num_hw_filtering_rules > 0) {
      list_for_each_safe(ptr, tmp_ptr, &pfr->hw_filtering_rules) {
	hw_filtering_rule_element *hw_rule = list_entry(ptr, hw_filtering_rule_element, list);

	/* Remove hw rule */
	handle_hw_filtering_rule(pfr, &hw_rule->rule, remove_hw_rule);

	list_del(ptr);
	kfree(hw_rule);
      }
    }
  }

  if(pfr->v_filtering_dev != NULL) {
    remove_virtual_filtering_device(sk, pfr->v_filtering_dev->info.device_name);
    pfr->v_filtering_dev = NULL;
    /* pfr->v_filtering_dev has been freed by remove_virtual_filtering_device() */
  }

  /* Free the ring buffer later, vfree needs interrupts enabled */
  ring_memory_ptr = pfr->ring_memory;
  ring_sk(sk) = NULL;
  skb_queue_purge(&sk->sk_write_queue);

  sock_put(sk);
  ring_write_unlock();

#ifdef VPFRING_SUPPORT
  if(pfr->vpfring_host_eventfd_ctx)
    eventfd_ctx_put(pfr->vpfring_host_eventfd_ctx);
#endif //VPFRING_SUPPORT

  if(pfr->appl_name != NULL)
    kfree(pfr->appl_name);

  /* Removing userspace ring if there are no other consumer/producer */
  if(pfr->userspace_ring != NULL)
    free_ring_memory = userspace_ring_remove(pfr->userspace_ring, pfr->userspace_ring_type);

  if(ring_memory_ptr != NULL && free_ring_memory)
    vfree(ring_memory_ptr);
    
  if(pfr->dna_device_entry != NULL) {
    dna_device_mapping mapping;

    mapping.operation = remove_device_mapping;
    snprintf(mapping.device_name, sizeof(mapping.device_name), "%s",  pfr->dna_device_entry->dev.netdev->name);
    mapping.channel_id = pfr->dna_device_entry->dev.channel_id;
    ring_map_dna_device(pfr, &mapping);
  }

  if(pfr->extra_dma_memory)
    free_extra_dma_memory(pfr);

  kfree(pfr);

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_release: done\n");

  return 0;
}

/* ********************************** */

/*
 * We create a ring for this socket and bind it to the specified device
 */
static int packet_ring_bind(struct sock *sk, char *dev_name)
{
  struct pf_ring_socket *pfr = ring_sk(sk);
  struct list_head *ptr, *tmp_ptr;
  ring_device_element *dev = NULL;

  if(dev_name == NULL)
    return(-EINVAL);

  /* UserSpace RING.
   * Note: with userspace rings we expect that mmap() follow (only one) bind() */

  if(pfr->userspace_ring != NULL)
    return(-EINVAL); /* TODO bind() already called on a userspace ring */

  if(strncmp(dev_name, "usr", 3) == 0) {
    if(pfr->ring_memory != NULL)
      return(-EINVAL); /* TODO mmap() already called */

    pfr->userspace_ring = userspace_ring_create(dev_name, userspace_ring_consumer,
                                                &pfr->ring_slots_waitqueue);

    if(pfr->userspace_ring == NULL)
      return -EINVAL;

    pfr->userspace_ring_type = userspace_ring_consumer;
    dev = &none_device_element;
  } else {
    list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
      ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);

      if(strcmp(dev_ptr->dev->name, dev_name) == 0) {
        dev = dev_ptr;
        break;
      }
    }
  }

  if((dev == NULL) || (dev->dev->type != ARPHRD_ETHER))
    return(-EINVAL);

  if(dev->dev->ifindex >= MAX_NUM_IFIDX)
    return(-EINVAL);

  if(!(dev->dev->flags & IFF_UP))
    return(-ENETDOWN);

  if(unlikely(enable_debug))
    printk("[PF_RING] packet_ring_bind(%s, bucket_len=%d) called\n",
	   dev->dev->name, pfr->bucket_len);

  /* Set for all devices */
  set_bit(dev->dev->ifindex, pfr->netdev_mask), pfr->num_bound_devices++;

  /* We set the master device only when we have not yet set a device */
  if(pfr->ring_netdev == &none_device_element) {
    /* Remove old binding (by default binding to none)
       BEFORE binding to a new device
    */
    ring_proc_remove(pfr);

    /*
      IMPORTANT
      Leave this statement here as last one. In fact when
      the ring_netdev != &none_device_element the socket is ready to be used.
    */
    pfr->ring_netdev = dev, pfr->channel_id = RING_ANY_CHANNEL;

    /* Time to rebind to a new device */
    ring_proc_add(pfr);
  }

  /*
    As the 'struct net_device' does not contain the number
    of RX queues, we can guess that its number is the same as the number
    of TX queues. After the first packet has been received by the adapter
    the num of RX queues is updated with the real value
  */
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
  pfr->num_rx_channels = pfr->ring_netdev->dev->real_num_tx_queues;
#else
  pfr->num_rx_channels = 1;
#endif

  if((dev == &any_device_element) && (!quick_mode)) {
    num_any_rings++;
  } else {
    if(dev->dev->ifindex < MAX_NUM_IFIDX) {
      num_rings_per_device[dev->dev->ifindex]++;
    } else
      printk("[PF_RING] INTERNAL ERROR: ifindex %d for %s is > than MAX_NUM_IFIDX\n",
	     dev->dev->ifindex, dev->dev->name);
  }

  return(0);
}

/* ************************************* */

/* Bind to a device */
static int ring_bind(struct socket *sock, struct sockaddr *sa, int addr_len)
{
  struct sock *sk = sock->sk;

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_bind() called\n");

  /*
   * Check legality
   */
  if(addr_len != sizeof(struct sockaddr))
    return -EINVAL;
  if(sa->sa_family != PF_RING)
    return -EINVAL;
  if(sa->sa_data == NULL)
    return -EINVAL;

  /* Safety check: add trailing zero if missing */
  sa->sa_data[sizeof(sa->sa_data) - 1] = '\0';

  if(unlikely(enable_debug))
    printk("[PF_RING] searching device %s\n", sa->sa_data);

#if 0
  if(strcmp(sa->sa_data, "any") == 0)
    dev = &any_dev;
  else {
    if((dev = __dev_get_by_name(
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24))
				&init_net,
#endif
				sa->sa_data)) == NULL) {

      if(unlikely(enable_debug))
	printk("[PF_RING] search failed\n");
      return(-EINVAL);
    }
  }
#endif

  return(packet_ring_bind(sk, sa->sa_data));
}

/* ************************************* */

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11))
/*
 * rvmalloc / rvfree / kvirt_to_pa copied from usbvideo.c
 */
unsigned long kvirt_to_pa(unsigned long adr)
{
  unsigned long kva, ret;

  kva = (unsigned long)page_address(vmalloc_to_page((void *)adr));
  kva |= adr & (PAGE_SIZE - 1);	/* restore the offset */
  ret = __pa(kva);
  return ret;
}
#endif

/* ************************************* */

static int do_memory_mmap(struct vm_area_struct *vma,
			  unsigned long size, char *ptr, u_int flags, int mode)
{
  unsigned long start;

  /* we do not want to have this area swapped out, lock it */
  vma->vm_flags |= flags;

  start = vma->vm_start;

  if(unlikely(enable_debug))
    printk("[PF_RING] do_memory_mmap(mode=%d, size=%lu, ptr=%p)\n", mode, size, ptr);

  while(size > 0) {
    int rc;

    if(mode == 0) {
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11))
      rc = remap_vmalloc_range(vma, ptr, 0);
      break; /* Do not iterate */
#else
      rc = remap_pfn_range(vma, start, kvirt_to_pa((unsigned long)ptr), PAGE_SIZE, PAGE_SHARED);
#endif
    } else if(mode == 1) {
      rc = remap_pfn_range(vma, start, __pa(ptr) >> PAGE_SHIFT, PAGE_SIZE, PAGE_SHARED);
    } else {
      rc = remap_pfn_range(vma, start, ((unsigned long)ptr) >> PAGE_SHIFT, PAGE_SIZE, PAGE_SHARED);
    }

    if(rc) {
      if(unlikely(enable_debug))
	printk("[PF_RING] remap_pfn_range() failed\n");

      return(-EAGAIN);
    }

    start += PAGE_SIZE;
    ptr += PAGE_SIZE;
    if(size > PAGE_SIZE) {
      size -= PAGE_SIZE;
    } else {
      size = 0;
    }
  }

  return(0);
}

/* ************************************* */

static int ring_mmap(struct file *file,
		     struct socket *sock, struct vm_area_struct *vma)
{
  struct sock *sk = sock->sk;
  struct pf_ring_socket *pfr = ring_sk(sk);
  int rc;
  unsigned long mem_id = 0;
  unsigned long size = (unsigned long)(vma->vm_end - vma->vm_start);

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_mmap() called\n");

  if(ring_alloc_mem(sk) != 0) {
    printk("[PF_RING] ring_mmap(): unable to allocate memory\n");
    return(-EINVAL);
  }

  if(size % PAGE_SIZE) {
    if(unlikely(enable_debug))
      printk("[PF_RING] ring_mmap() failed: len is not multiple of PAGE_SIZE\n");

    return(-EINVAL);
  }

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_mmap() called, size: %ld bytes [bucket_len=%d]\n",
	   size, pfr->bucket_len);

  /* using vm_pgoff as memory id */
  mem_id = vma->vm_pgoff;

  if( (mem_id == 0 && pfr->ring_memory == NULL) ||
      (mem_id  > 0 && pfr->dna_device  == NULL)) {

    if(unlikely(enable_debug))
      printk("[PF_RING] ring_mmap() failed: "
	     "mapping area to an unbound socket\n");

    return -EINVAL;
  }

  /* Tricks for DNA */
  if(mem_id >= 100){
    mem_id -= 100;

    if(mem_id < pfr->dna_device->mem_info.rx.packet_memory_num_chunks) {
      /* DNA; RX packet memory */

      if((rc = do_memory_mmap(vma, size, (void *)pfr->dna_device->rx_packet_memory[mem_id], VM_LOCKED, 1)) < 0)
        return(rc);
    } else if(mem_id < pfr->dna_device->mem_info.rx.packet_memory_num_chunks + pfr->dna_device->mem_info.tx.packet_memory_num_chunks) {
      /* DNA: TX packet memory */

      mem_id -= pfr->dna_device->mem_info.rx.packet_memory_num_chunks;

      if(mem_id >= pfr->dna_device->mem_info.tx.packet_memory_num_chunks)
        return -EINVAL;

      if((rc = do_memory_mmap(vma, size, (void *)pfr->dna_device->tx_packet_memory[mem_id], VM_LOCKED, 1)) < 0)
        return(rc);
    } else {
      /* Extra DMA memory */

      mem_id -= pfr->dna_device->mem_info.rx.packet_memory_num_chunks;
      mem_id -= pfr->dna_device->mem_info.tx.packet_memory_num_chunks;

      if(mem_id >= pfr->extra_dma_memory_num_chunks)
        return -EINVAL;

      if(pfr->extra_dma_memory == NULL)
        return -EINVAL;
      
      if((rc = do_memory_mmap(vma, size, (void *)pfr->extra_dma_memory[mem_id], VM_LOCKED, 1)) < 0)
        return(rc); 
    }

    return(0);
  }

  switch(mem_id) {
    /* RING */
    case 0:
      /* If userspace tries to mmap beyond end of our buffer, then fail */
      if(size > pfr->slots_info->tot_mem) {
        if(unlikely(enable_debug))
	  printk("[PF_RING] ring_mmap() failed: "
	         "area too large [%ld > %d]\n",
	         size, pfr->slots_info->tot_mem);
        return(-EINVAL);
      }

      if(unlikely(enable_debug))
        printk("[PF_RING] mmap [slot_len=%d]"
	       "[tot_slots=%d] for ring on device %s\n",
	       pfr->slots_info->slot_len, pfr->slots_info->min_num_slots,
	       pfr->ring_netdev->dev->name);

      if((rc = do_memory_mmap(vma, size, pfr->ring_memory, VM_LOCKED, 0)) < 0)
        return(rc);
      break;

    case 1:
      /* DNA: RX packet descriptors */

      if((rc = do_memory_mmap(vma, size, (void *)pfr->dna_device->rx_descr_packet_memory, VM_LOCKED, 1)) < 0)
	return(rc);
      break;

    case 2:
      /* DNA: Physical card memory */

      if((rc = do_memory_mmap(vma, size, (void *)pfr->dna_device->phys_card_memory, (VM_RESERVED | VM_IO), 2)) < 0)
	return(rc);
      break;

    case 3:
      /* DNA: TX packet descriptors */

      if((rc = do_memory_mmap(vma, size, (void *)pfr->dna_device->tx_descr_packet_memory, VM_LOCKED, 1)) < 0)
	return(rc);
      break;

    default:
      return(-EAGAIN);
  }

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_mmap succeeded\n");

  return 0;
}

/* ************************************* */

static int ring_recvmsg(struct kiocb *iocb, struct socket *sock,
			struct msghdr *msg, size_t len, int flags)
{
  struct pf_ring_socket *pfr = ring_sk(sock->sk);
  u_int32_t queued_pkts, num_loops = 0;

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_recvmsg called\n");

  pfr->ring_active = 1;

  while((queued_pkts = num_queued_pkts(pfr)) < MIN_QUEUED_PKTS) {
    wait_event_interruptible(pfr->ring_slots_waitqueue, 1);

    if(unlikely(enable_debug))
      printk("[PF_RING] -> ring_recvmsg "
	     "[queued_pkts=%d][num_loops=%d]\n",
	     queued_pkts, num_loops);

    if(queued_pkts > 0) {
      if(num_loops++ > MAX_QUEUE_LOOPS)
	break;
    }
  }

  return(queued_pkts);
}

/* ************************************* */

/* This code is mostly coming from af_packet.c */
static int ring_sendmsg(struct kiocb *iocb, struct socket *sock,
			struct msghdr *msg, size_t len)
{
  struct pf_ring_socket *pfr = ring_sk(sock->sk);
  struct sockaddr_pkt *saddr;
  struct sk_buff *skb;
  __be16 proto=0;
  int err = 0;

  /* Userspace RING: Waking up the ring consumer */
  if(pfr->userspace_ring != NULL){
    if(pfr->userspace_ring->consumer_ring_slots_waitqueue != NULL
        && !(pfr->slots_info->userspace_ring_flags & USERSPACE_RING_NO_INTERRUPT)) {
        pfr->slots_info->userspace_ring_flags |= USERSPACE_RING_NO_INTERRUPT;
        wake_up_interruptible(pfr->userspace_ring->consumer_ring_slots_waitqueue);
    }
    return (len);
  }

  /*
   *	Get and verify the address.
   */
  saddr=(struct sockaddr_pkt *)msg->msg_name;
  if(saddr)
    {
      if(saddr == NULL) proto = htons(ETH_P_ALL);

      if(msg->msg_namelen < sizeof(struct sockaddr))
	return(-EINVAL);
      if(msg->msg_namelen == sizeof(struct sockaddr_pkt))
	proto = saddr->spkt_protocol;
    }
  else
    return(-ENOTCONN);	/* SOCK_PACKET must be sent giving an address */

  /*
   *	Find the device first to size check it
   */
  if(pfr->ring_netdev->dev == NULL)
    goto out_unlock;

  err = -ENETDOWN;
  if(!(pfr->ring_netdev->dev->flags & IFF_UP))
    goto out_unlock;

  /*
   *	You may not queue a frame bigger than the mtu. This is the lowest level
   *	raw protocol and you must do your own fragmentation at this level.
   */
  err = -EMSGSIZE;
  if(len > pfr->ring_netdev->dev->mtu + pfr->ring_netdev->dev->hard_header_len)
    goto out_unlock;

  err = -ENOBUFS;
  skb = sock_wmalloc(sock->sk, len + LL_RESERVED_SPACE(pfr->ring_netdev->dev), 0, GFP_KERNEL);

  /*
   *	If the write buffer is full, then tough. At this level the user gets to
   *	deal with the problem - do your own algorithmic backoffs. That's far
   *	more flexible.
   */

  if(skb == NULL)
    goto out_unlock;

  /*
   *	Fill it in
   */

  /* FIXME: Save some space for broken drivers that write a
   * hard header at transmission time by themselves. PPP is the
   * notable one here. This should really be fixed at the driver level.
   */
  skb_reserve(skb, LL_RESERVED_SPACE(pfr->ring_netdev->dev));
  skb_reset_network_header(skb);

  /* Try to align data part correctly */
#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
  if(pfr->ring_netdev->dev->header_ops) {
    skb->data -= pfr->ring_netdev->dev->hard_header_len;
    skb->tail -= pfr->ring_netdev->dev->hard_header_len;
    if(len < pfr->ring_netdev->dev->hard_header_len)
      skb_reset_network_header(skb);
  }
#else
  if(pfr->ring_netdev->dev->hard_header) {
    skb->data -= pfr->ring_netdev->dev->hard_header_len;
    skb->tail -= pfr->ring_netdev->dev->hard_header_len;
    if(len < pfr->ring_netdev->dev->hard_header_len) {
#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18))
      skb_reset_network_header(skb);
#else
      skb->nh.raw = skb->data;
#endif
    }
  }
#endif

  /* Returns -EFAULT on error */
  err = memcpy_fromiovec(skb_put(skb,len), msg->msg_iov, len);
  skb->protocol = proto;
  skb->dev = pfr->ring_netdev->dev;
  skb->priority = sock->sk->sk_priority;
  if(err)
    goto out_free;

  /*
   *	Now send it
   */

  dev_queue_xmit(skb);
  //dev_put(pfr->ring_netdev->dev);
  return(len);

 out_free:
  kfree_skb(skb);

 out_unlock:
  //if(pfr->ring_netdev)
  //  dev_put(pfr->ring_netdev->dev);

  return err;
}

/* ************************************* */

unsigned int ring_poll(struct file *file,
		       struct socket *sock, poll_table * wait)
{
  struct pf_ring_socket *pfr = ring_sk(sock->sk);
  int rc, mask = 0;

  if(unlikely(enable_debug))
    printk("[PF_RING] -- poll called\n");

  pfr->num_poll_calls++;

  if(unlikely(pfr->ring_shutdown))
    return(mask);

  if(pfr->dna_device == NULL) {
    /* PF_RING mode (No DNA) */

    if(unlikely(enable_debug))
      printk("[PF_RING] poll called (non DNA device)\n");

    pfr->ring_active = 1;
    // smp_rmb();

    if(num_queued_pkts(pfr) < pfr->poll_num_pkts_watermark) {
      poll_wait(file, &pfr->ring_slots_waitqueue, wait);
      // smp_mb();
    }

    if(num_queued_pkts(pfr) >= pfr->poll_num_pkts_watermark)
      mask |= POLLIN | POLLRDNORM;

    return(mask);
  } else {
    /* DNA mode */
    /* enable_debug = 1;  */

    if(unlikely(enable_debug))
      printk("[PF_RING] poll called on DNA device [%d]\n",
	     *pfr->dna_device->interrupt_received);

    if(pfr->dna_device->wait_packet_function_ptr == NULL) {
      if(unlikely(enable_debug))
	printk("[PF_RING] wait_packet_function_ptr is NULL: returning to caller\n");

      return(0);
    }

    rc = pfr->dna_device->wait_packet_function_ptr(pfr->dna_device->adapter_ptr, 1);

    if(unlikely(enable_debug))
      printk("[PF_RING] wait_packet_function_ptr(1) returned %d\n", rc);

    if(rc == 0) {
      if(unlikely(enable_debug))
	printk("[PF_RING] calling poll_wait()\n");

      /* No packet arrived yet */
      poll_wait(file, pfr->dna_device->packet_waitqueue, wait);

      if(unlikely(enable_debug))
	printk("[PF_RING] poll_wait() just returned\n");
    } else
      rc = pfr->dna_device->wait_packet_function_ptr(pfr->dna_device->adapter_ptr, 0);

    if(unlikely(enable_debug))
      printk("[PF_RING] wait_packet_function_ptr(0) returned %d\n", rc);

    if(unlikely(enable_debug))
      printk("[PF_RING] poll %s return [%d]\n",
	     pfr->ring_netdev->dev->name,
	     *pfr->dna_device->interrupt_received);

    if(*pfr->dna_device->interrupt_received) {
      return(POLLIN | POLLRDNORM);
    } else {
      return(0);
    }
  }
}

/* ************************************* */

int add_sock_to_cluster_list(ring_cluster_element * el, struct sock *sock)
{
  if(el->cluster.num_cluster_elements == CLUSTER_LEN)
    return(-1);	/* Cluster full */

  ring_sk_datatype(ring_sk(sock))->cluster_id = el->cluster.cluster_id;
  el->cluster.sk[el->cluster.num_cluster_elements] = sock;
  el->cluster.num_cluster_elements++;
  return(0);
}

/* ************************************* */

int remove_from_cluster_list(struct ring_cluster *el, struct sock *sock)
{
  int i, j;

  for(i = 0; i < CLUSTER_LEN; i++)
    if(el->sk[i] == sock) {
      el->num_cluster_elements--;

      if(el->num_cluster_elements > 0) {
	/* The cluster contains other elements */
	for(j = i; j < CLUSTER_LEN - 1; j++)
	  el->sk[j] = el->sk[j + 1];

	el->sk[CLUSTER_LEN - 1] = NULL;
      } else {
	/* Empty cluster */
	memset(el->sk, 0, sizeof(el->sk));
      }

      return(0);
    }

  return(-1); /* Not found */
}

/* ************************************* */

static int remove_from_cluster(struct sock *sock, struct pf_ring_socket *pfr)
{
  struct list_head *ptr, *tmp_ptr;

  if(unlikely(enable_debug))
    printk("[PF_RING] --> remove_from_cluster(%d)\n", pfr->cluster_id);

  if(pfr->cluster_id == 0 /* 0 = No Cluster */ )
    return(0);	/* Noting to do */

  list_for_each_safe(ptr, tmp_ptr, &ring_cluster_list) {
    ring_cluster_element *cluster_ptr;

    cluster_ptr = list_entry(ptr, ring_cluster_element, list);

    if(cluster_ptr->cluster.cluster_id == pfr->cluster_id) {
      int ret = remove_from_cluster_list(&cluster_ptr->cluster, sock);

      if (cluster_ptr->cluster.num_cluster_elements == 0) {
	list_del(ptr);
	kfree(cluster_ptr);
      }
      return ret;
    }
  }

  return(-EINVAL);	/* Not found */
}

/* ************************************* */

static int set_master_ring(struct sock *sock,
			   struct pf_ring_socket *pfr,
			   u_int32_t master_socket_id)
{
  int rc = -1;
  struct list_head *ptr, *tmp_ptr;

  if(unlikely(enable_debug))
    printk("[PF_RING] set_master_ring(%s=%d)\n",
	   pfr->ring_netdev->dev ? pfr->ring_netdev->dev->name : "none",
	   master_socket_id);

  /* Avoid the ring to be manipulated while playing with it */
  ring_read_lock();

  list_for_each_safe(ptr, tmp_ptr, &ring_table) {
    struct pf_ring_socket *sk_pfr;
    struct ring_element *entry;
    struct sock *skElement;

    entry = list_entry(ptr, struct ring_element, list);

    skElement = entry->sk;
    sk_pfr = ring_sk(skElement);

    if((sk_pfr != NULL) && (sk_pfr->ring_id == master_socket_id)) {
      pfr->master_ring = sk_pfr;

      if(unlikely(enable_debug))
	printk("[PF_RING] Found set_master_ring(%s) -> %s\n",
	       sk_pfr->ring_netdev->dev ? sk_pfr->ring_netdev->dev->name : "none",
	       pfr->master_ring->ring_netdev->dev->name);

      rc = 0;
      break;
    } else {
      if(unlikely(enable_debug))
	printk("[PF_RING] Skipping socket(%s)=%d\n",
	       sk_pfr->ring_netdev->dev ? sk_pfr->ring_netdev->dev->name : "none",
	       sk_pfr->ring_id);
    }
  }

  ring_read_unlock();

  if(unlikely(enable_debug))
    printk("[PF_RING] set_master_ring(%s, socket_id=%d) = %d\n",
	   pfr->ring_netdev->dev ? pfr->ring_netdev->dev->name : "none",
	   master_socket_id, rc);

  return(rc);
}

/* ************************************* */

static int add_sock_to_cluster(struct sock *sock,
			       struct pf_ring_socket *pfr,
			       struct add_to_cluster *cluster)
{
  struct list_head *ptr, *tmp_ptr;
  ring_cluster_element *cluster_ptr;

  if(unlikely(enable_debug))
    printk("[PF_RING] --> add_sock_to_cluster(%d)\n", cluster->clusterId);

  if(cluster->clusterId == 0 /* 0 = No Cluster */ )
    return(-EINVAL);

  if(pfr->cluster_id != 0)
    remove_from_cluster(sock, pfr);

  list_for_each_safe(ptr, tmp_ptr, &ring_cluster_list) {
    cluster_ptr = list_entry(ptr, ring_cluster_element, list);

    if(cluster_ptr->cluster.cluster_id == cluster->clusterId) {
      return(add_sock_to_cluster_list(cluster_ptr, sock));
    }
  }

  /* There's no existing cluster. We need to create one */
  if((cluster_ptr = kmalloc(sizeof(ring_cluster_element), GFP_KERNEL)) == NULL)
    return(-ENOMEM);

  INIT_LIST_HEAD(&cluster_ptr->list);

  cluster_ptr->cluster.cluster_id = cluster->clusterId;
  cluster_ptr->cluster.num_cluster_elements = 1;
  cluster_ptr->cluster.hashing_mode = cluster->the_type; /* Default */
  cluster_ptr->cluster.hashing_id = 0;

  memset(cluster_ptr->cluster.sk, 0, sizeof(cluster_ptr->cluster.sk));
  cluster_ptr->cluster.sk[0] = sock;
  pfr->cluster_id = cluster->clusterId;
  list_add(&cluster_ptr->list, &ring_cluster_list); /* Add as first entry */

  return(0); /* 0 = OK */
}

/* ************************************* */

static int ring_map_dna_device(struct pf_ring_socket *pfr,
			       dna_device_mapping *mapping)
{
  struct list_head *ptr, *tmp_ptr;

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_map_dna_device(%s@%d): %s\n",
	   mapping->device_name,
	   mapping->channel_id,
	   (mapping->operation == remove_device_mapping) ? "remove" : "add");

  if(mapping->operation == remove_device_mapping) {
    /* Unlock driver */
    u8 found = 0;

    list_for_each_safe(ptr, tmp_ptr, &ring_dna_devices_list) {
      dna_device_list *entry = list_entry(ptr, dna_device_list, list);

      if((!strcmp(entry->dev.netdev->name, mapping->device_name))
	 && (entry->dev.channel_id == mapping->channel_id)
	 && entry->num_bound_sockets) {
	int i;

	for(i=0; i<MAX_NUM_DNA_BOUND_SOCKETS; i++)
	  if(entry->bound_sockets[i] == pfr) {
	    entry->bound_sockets[i] = NULL;
	    found = 1;
	    break;
	  }

	if(!found) {
	  if(unlikely(enable_debug))
	    printk("[PF_RING] ring_map_dna_device(remove_device_mapping, %s, %u): something got wrong\n",
		   mapping->device_name, mapping->channel_id);
	  return(-1); /* Something got wrong */
	}

	entry->num_bound_sockets--;

	if(pfr->dna_device != NULL) {
	  if(unlikely(enable_debug))
	    printk("[PF_RING] ring_map_dna_device(%s): removed mapping [num_bound_sockets=%u]\n",
		   mapping->device_name, entry->num_bound_sockets);
	  pfr->dna_device->usage_notification(pfr->dna_device->adapter_ptr, 0 /* unlock */);
	  // pfr->dna_device = NULL;
	}
	/* Continue for all devices: no break */
      }
    }

    if(unlikely(enable_debug))
      printk("[PF_RING] ring_map_dna_device(%s): removed mapping\n", mapping->device_name);

    return(0);
  } else {
    ring_proc_remove(pfr);

    list_for_each_safe(ptr, tmp_ptr, &ring_dna_devices_list) {
      dna_device_list *entry = list_entry(ptr, dna_device_list, list);

      if((!strcmp(entry->dev.netdev->name, mapping->device_name))
	 && (entry->dev.channel_id == mapping->channel_id)) {
	int i, found = 0;

	if(unlikely(enable_debug))
	  printk("[PF_RING] ==>> %s@%d [num_bound_sockets=%d][%p]\n",
		 entry->dev.netdev->name, mapping->channel_id,
		 entry->num_bound_sockets, entry);

	for(i=0; i<MAX_NUM_DNA_BOUND_SOCKETS; i++)
	  if(entry->bound_sockets[i] == NULL) {
	    entry->bound_sockets[i] = pfr;
	    found = 1;
	    break;
	  }

	if(!found) {
	  if(unlikely(enable_debug))
	    printk("[PF_RING] ring_map_dna_device(add_device_mapping, %s, %u, %s): "
		   "something got wrong (too many DNA devices open)\n",
		   mapping->device_name, mapping->channel_id, direction2string(pfr->direction));

	  return(-1); /* Something got wrong: too many mappings */
	}

	entry->num_bound_sockets++, pfr->dna_device_entry = entry;

	pfr->dna_device = &entry->dev, pfr->ring_netdev->dev = entry->dev.netdev /* Default */;

	if(unlikely(enable_debug))
	  printk("[PF_RING] ring_map_dna_device(%s, %u): added mapping\n",
		 mapping->device_name, mapping->channel_id);

	/* Now let's set the read ring_netdev device */
	list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
	  ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);

	  if(!strcmp(dev_ptr->dev->name, mapping->device_name)) {
	    if(unlikely(enable_debug))
	      printk("[PF_RING] ==>> %s [%p]\n", dev_ptr->dev->name, dev_ptr);
	    pfr->ring_netdev = dev_ptr;
	    break;
	  }
	}

	/* Lock driver */
	if(unlikely(enable_debug))
	  printk("[PF_RING] ===> ring_map_dna_device(%s): added mapping [num_bound_sockets=%u]\n",
		 mapping->device_name, entry->num_bound_sockets);
	pfr->dna_device->usage_notification(pfr->dna_device->adapter_ptr, 1 /* lock */);

	ring_proc_add(pfr);
	return(0);
      }
    }
  }

  if(unlikely(enable_debug))
    printk("[PF_RING] ring_map_dna_device(%s, %u): mapping failed or not a dna device\n",
	   mapping->device_name, mapping->channel_id);

  return(-1);
}

/* ************************************* */

static void purge_idle_hash_rules(struct pf_ring_socket *pfr,
				  uint16_t rule_inactivity)
{
  int i, num_purged_rules = 0;
  unsigned long expire_jiffies =
    jiffies - msecs_to_jiffies(1000 * rule_inactivity);

  if(unlikely(enable_debug))
    printk("[PF_RING] purge_idle_hash_rules(rule_inactivity=%d)\n",
	   rule_inactivity);

  /* Free filtering hash rules inactive for more than rule_inactivity seconds */
  if(pfr->sw_filtering_hash != NULL) {
    for(i = 0; i < DEFAULT_RING_HASH_SIZE; i++) {
      if(pfr->sw_filtering_hash[i] != NULL) {
	sw_filtering_hash_bucket *scan = pfr->sw_filtering_hash[i], *next, *prev = NULL;

	while(scan != NULL) {
	  int rc = 0;
	  next = scan->next;

          if(scan->rule.plugin_action.plugin_id > 0
             && plugin_registration[scan->rule.plugin_action.plugin_id]
             && plugin_registration[scan->rule.plugin_action.plugin_id]->pfring_plugin_purge_idle)
            rc = plugin_registration[scan->rule.plugin_action.plugin_id]->
	           pfring_plugin_purge_idle(pfr, NULL, scan, rule_inactivity);

	  if(scan->rule.internals.jiffies_last_match < expire_jiffies || rc > 0) {
	    /* Expired rule: free it */

	    if(unlikely(enable_debug))
	      printk ("[PF_RING] Purging hash rule "
		      /* "[last_match=%u][expire_jiffies=%u]" */
		      "[%d.%d.%d.%d:%d <-> %d.%d.%d.%d:%d][purged=%d][tot_rules=%d]\n",
		      /*
			(unsigned int)scan->rule.internals.jiffies_last_match,
			(unsigned int)expire_jiffies,
		      */
		      ((scan->rule.host4_peer_a >> 24) & 0xff),
		      ((scan->rule.host4_peer_a >> 16) & 0xff),
		      ((scan->rule.host4_peer_a >> 8)  & 0xff),
		      ((scan->rule.host4_peer_a >> 0)  & 0xff),
		      scan->rule.port_peer_a,
		      ((scan->rule.host4_peer_b >> 24) & 0xff),
		      ((scan->rule.host4_peer_b >> 16) & 0xff),
		      ((scan->rule.host4_peer_b >> 8)  & 0xff),
		      ((scan->rule.host4_peer_b >> 0) & 0xff),
		      scan->rule.port_peer_b,
		      num_purged_rules,
		      pfr->num_sw_filtering_rules);

	    free_sw_filtering_hash_bucket(scan);
	    kfree(scan);

	    if(prev == NULL)
	      pfr->sw_filtering_hash[i] = next;
	    else
	      prev->next = next;

	    pfr->num_sw_filtering_rules--;
	    num_purged_rules++;
	  } else
	    prev = scan;

	  scan = next;
	}
      }
    }
  }

  if(unlikely(enable_debug))
    printk("[PF_RING] Purged %d hash rules [tot_rules=%d]\n",
	   num_purged_rules, pfr->num_sw_filtering_rules);
}

/* ************************************* */

static void purge_idle_rules(struct pf_ring_socket *pfr,
			     uint16_t rule_inactivity)
{
  struct list_head *ptr, *tmp_ptr;
  int num_purged_rules = 0;
  unsigned long expire_jiffies =
    jiffies - msecs_to_jiffies(1000 * rule_inactivity);

  if(unlikely(enable_debug))
    printk("[PF_RING] %s(rule_inactivity=%d) [num_sw_filtering_rules=%d]\n",
	   __FUNCTION__, rule_inactivity, pfr->num_sw_filtering_rules);

  /* Free filtering rules inactive for more than rule_inactivity seconds */
  if(pfr->num_sw_filtering_rules > 0) {
    list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
      int rc = 0;
      sw_filtering_rule_element *entry;
      entry = list_entry(ptr, sw_filtering_rule_element, list);

      /* Plugin callback is evaluated even if the rule has the "locked" field set. */
      if(entry->rule.plugin_action.plugin_id > 0
         && plugin_registration[entry->rule.plugin_action.plugin_id]
         && plugin_registration[entry->rule.plugin_action.plugin_id]->pfring_plugin_purge_idle)
        rc = plugin_registration[entry->rule.plugin_action.plugin_id]->
               pfring_plugin_purge_idle(pfr, entry, NULL, rule_inactivity);

      if((!entry->rule.locked && entry->rule.internals.jiffies_last_match < expire_jiffies) || rc > 0) {
        /* Expired rule: free it */

	if(unlikely(enable_debug))
	  printk ("[PF_RING] Purging rule "
		  // "[last_match=%u][expire_jiffies=%u]"
		  "[%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d][purged=%d][tot_rules=%d]\n",
		  //(unsigned int) entry->rule.internals.jiffies_last_match,
		  //(unsigned int) expire_jiffies,
		  ((entry->rule.core_fields.shost.v4 >> 24) & 0xff),
		  ((entry->rule.core_fields.shost.v4 >> 16) & 0xff),
		  ((entry->rule.core_fields.shost.v4 >> 8)  & 0xff),
		  ((entry->rule.core_fields.shost.v4 >> 0)  & 0xff),
		    entry->rule.core_fields.sport_low,
		  ((entry->rule.core_fields.dhost.v4 >> 24) & 0xff),
		  ((entry->rule.core_fields.dhost.v4 >> 16) & 0xff),
		  ((entry->rule.core_fields.dhost.v4 >> 8)  & 0xff),
		  ((entry->rule.core_fields.dhost.v4 >> 0) & 0xff),
		    entry->rule.core_fields.dport_low,
		  num_purged_rules,
		  pfr->num_sw_filtering_rules);

        list_del(ptr);
        free_filtering_rule(entry, 0);
        kfree(entry);

        pfr->num_sw_filtering_rules--;
        num_purged_rules++;
      }
    }
  }

  if(unlikely(enable_debug))
    printk("[PF_RING] Purged %d rules [tot_rules=%d]\n",
	   num_purged_rules, pfr->num_sw_filtering_rules);
}

/* ************************************* */

/* Code taken/inspired from core/sock.c */
static int ring_setsockopt(struct socket *sock,
			   int level, int optname,
			   char __user * optval,
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
			   unsigned
#endif
			   int optlen)
{
  struct pf_ring_socket *pfr = ring_sk(sock->sk);
  int val, found, ret = 0 /* OK */, i;
  u_int32_t ring_id;
  struct add_to_cluster cluster;
  u_int32_t channel_id;
  char applName[32 + 1] = { 0 };
  u_int16_t rule_id, rule_inactivity;
  packet_direction direction;
  hw_filtering_rule hw_rule;
  struct list_head *ptr, *tmp_ptr;
#ifdef VPFRING_SUPPORT
  struct vpfring_eventfd_info eventfd_i;
  struct file *eventfp;
#endif //VPFRING_SUPPORT

  if(pfr == NULL)
    return(-EINVAL);

  if(get_user(val, (int *)optval))
    return -EFAULT;

  found = 1;

  switch(optname) {
  case SO_ATTACH_FILTER:
    ret = -EINVAL;

    if(unlikely(enable_debug))
      printk("[PF_RING] BPF filter (%d)\n", 0);

    if(optlen == sizeof(struct sock_fprog)) {
      unsigned int fsize;
      struct sock_fprog fprog;
      struct sk_filter *filter, *old_filter;

      ret = -EFAULT;

      if(unlikely(enable_debug))
	printk("[PF_RING] BPF filter (%d)\n", 1);

      /*
	NOTE

	Do not call copy_from_user within a held
	splinlock (e.g. ring_mgmt_lock) as this caused
	problems when certain debugging was enabled under
	2.6.5 -- including hard lockups of the machine.
      */
      if(copy_from_user(&fprog, optval, sizeof(fprog)))
	break;

      /* Fix below courtesy of Noam Dev <noamdev@gmail.com> */
      fsize  = sizeof(struct sock_filter) * fprog.len;
      filter = kmalloc(fsize + sizeof(struct sk_filter), GFP_KERNEL);

      if(filter == NULL) {
	ret = -ENOMEM;
	break;
      }

      if(copy_from_user(filter->insns, fprog.filter, fsize)){
	kfree(filter);
        break;
      }

      filter->len = fprog.len;

      if(sk_chk_filter(filter->insns, filter->len) != 0) {
	/* Bad filter specified */
	kfree(filter);
	break;
      }

      old_filter = pfr->bpfFilter;

      /* get the lock, set the filter, release the lock */
      write_lock_bh(&pfr->ring_rules_lock);
      pfr->bpfFilter = filter;
      write_unlock_bh(&pfr->ring_rules_lock);

      if(old_filter != NULL)
        kfree(old_filter);

      ret = 0;

      if(unlikely(enable_debug))
	printk("[PF_RING] BPF filter attached successfully [len=%d]\n",
	       filter->len);
    }
    break;

  case SO_DETACH_FILTER:
    write_lock_bh(&pfr->ring_rules_lock);
    found = 1;
    if(pfr->bpfFilter != NULL) {
      kfree(pfr->bpfFilter);
      pfr->bpfFilter = NULL;
    } else
      ret = -ENONET;
    write_unlock_bh(&pfr->ring_rules_lock);
    break;

  case SO_ADD_TO_CLUSTER:
    if(optlen != sizeof(cluster))
      return -EINVAL;

    if(copy_from_user(&cluster, optval, sizeof(cluster)))
      return -EFAULT;

    write_lock_bh(&pfr->ring_rules_lock);
    ret = add_sock_to_cluster(sock->sk, pfr, &cluster);
    write_unlock_bh(&pfr->ring_rules_lock);
    break;

  case SO_REMOVE_FROM_CLUSTER:
    write_lock_bh(&pfr->ring_rules_lock);
    ret = remove_from_cluster(sock->sk, pfr);
    write_unlock_bh(&pfr->ring_rules_lock);
    break;

  case SO_SET_CHANNEL_ID:
    if(optlen != sizeof(channel_id))
      return -EINVAL;

    if(copy_from_user(&channel_id, optval, sizeof(channel_id)))
      return -EFAULT;

    /*
      We need to set the device_rings[] for all channels set
      in channel_id
    */
    pfr->num_channels_per_ring = 0;

    for(i=0; i<pfr->num_rx_channels; i++) {
      u_int32_t the_bit = 1 << i;

      if((channel_id & the_bit) == the_bit) {
	if(device_rings[pfr->ring_netdev->dev->ifindex][i] != NULL)
	  return(-EINVAL); /* Socket already bound on this device */
      }
    }

    /* Everything seems to work thus let's set the values */

    for(i=0; i<pfr->num_rx_channels; i++) {
      u_int32_t the_bit = 1 << i;

      if((channel_id & the_bit) == the_bit) {
	if(unlikely(enable_debug)) printk("[PF_RING] Setting channel %d\n", i);

	device_rings[pfr->ring_netdev->dev->ifindex][i] = pfr;
	pfr->num_channels_per_ring++;
      }
    }
    

    pfr->channel_id = channel_id;
    if(unlikely(enable_debug))
      printk("[PF_RING] [pfr->channel_id=%d][channel_id=%d]\n",
	     pfr->channel_id, channel_id);

    ret = 0;
    break;

  case SO_SET_APPL_NAME:
    if(optlen >
       sizeof(applName) /* Names should not be too long */ )
      return -EINVAL;

    if(copy_from_user(&applName, optval, optlen))
      return -EFAULT;

    if(pfr->appl_name != NULL)
      kfree(pfr->appl_name);
    pfr->appl_name = (char *)kmalloc(optlen + 1, GFP_ATOMIC);
    if(pfr->appl_name != NULL) {
      memcpy(pfr->appl_name, applName, optlen);
      pfr->appl_name[optlen] = '\0';
    }

    ret = 0;
    break;

  case SO_SET_PACKET_DIRECTION:
    if(optlen != sizeof(direction))
      return -EINVAL;

    if(copy_from_user(&direction, optval, sizeof(direction)))
      return -EFAULT;

    pfr->direction = direction;
    if(unlikely(enable_debug))
      printk("[PF_RING] SO_SET_PACKET_DIRECTION [pfr->direction=%s][direction=%s]\n",
	     direction2string(pfr->direction), direction2string(direction));

    ret = 0;
    break;

  case SO_PURGE_IDLE_HASH_RULES:
    if(optlen != sizeof(rule_inactivity))
      return -EINVAL;

    if(copy_from_user(&rule_inactivity, optval, sizeof(rule_inactivity)))
      return -EFAULT;
    else {
      if(rule_inactivity > 0) {
	write_lock_bh(&pfr->ring_rules_lock);
	purge_idle_hash_rules(pfr, rule_inactivity);
	write_unlock_bh(&pfr->ring_rules_lock);
      }
      ret = 0;
    }
    break;

  case SO_PURGE_IDLE_RULES:
    if(optlen != sizeof(rule_inactivity))
      return -EINVAL;

    if(copy_from_user(&rule_inactivity, optval, sizeof(rule_inactivity)))
      return -EFAULT;
    else {
      if(rule_inactivity > 0) {
	write_lock_bh(&pfr->ring_rules_lock);
	purge_idle_rules(pfr, rule_inactivity);
	write_unlock_bh(&pfr->ring_rules_lock);
      }
      ret = 0;
    }
    break;

  case SO_TOGGLE_FILTER_POLICY:
    if(optlen != sizeof(u_int8_t))
      return -EINVAL;
    else {
      u_int8_t new_policy;

      if(copy_from_user(&new_policy, optval, optlen))
	return -EFAULT;

      write_lock_bh(&pfr->ring_rules_lock);
      pfr->sw_filtering_rules_default_accept_policy = new_policy;
      write_unlock_bh(&pfr->ring_rules_lock);
      /*
	if(unlikely(enable_debug))
	printk("[PF_RING] SO_TOGGLE_FILTER_POLICY: default policy is %s\n",
	pfr->sw_filtering_rules_default_accept_policy ? "accept" : "drop");
      */
    }
    break;

  case SO_ADD_FILTERING_RULE:
    if(unlikely(enable_debug))
      printk("[PF_RING] +++ SO_ADD_FILTERING_RULE(len=%d)(len=%u)\n",
	     optlen, (unsigned int)sizeof(ip_addr));

    if(pfr->ring_netdev == &none_device_element)
      return -EFAULT;

    if(optlen == sizeof(filtering_rule)) {
      int ret;
      sw_filtering_rule_element *rule;

      if(unlikely(enable_debug))
	printk("[PF_RING] Allocating memory [filtering_rule]\n");

      rule =(sw_filtering_rule_element *)
	kcalloc(1, sizeof(sw_filtering_rule_element), GFP_KERNEL);

      if(rule == NULL)
	return -EFAULT;

      if(copy_from_user(&rule->rule, optval, optlen))
	return -EFAULT;

      INIT_LIST_HEAD(&rule->list);

      write_lock_bh(&pfr->ring_rules_lock);
      ret = add_sw_filtering_rule_element(pfr, rule);
      write_unlock_bh(&pfr->ring_rules_lock);

      if(ret != 0) { /* even if rc == -EEXIST */
        kfree(rule);
        return(ret);
      }
    } else if(optlen == sizeof(hash_filtering_rule)) {
      /* This is a hash rule */
      int ret;
      sw_filtering_hash_bucket *rule;

      rule = (sw_filtering_hash_bucket *)
        kcalloc(1, sizeof(sw_filtering_hash_bucket), GFP_KERNEL);

      if(rule == NULL)
	return -EFAULT;

      if(copy_from_user(&rule->rule, optval, optlen))
	return -EFAULT;

      write_lock_bh(&pfr->ring_rules_lock);
      ret = handle_sw_filtering_hash_bucket(pfr, rule, 1 /* add */);
      write_unlock_bh(&pfr->ring_rules_lock);

      if(ret != 0) { /* even if rc == -EEXIST */
        kfree(rule);
        return(ret);
      }
    } else {
      printk("[PF_RING] Bad rule length (%d): discarded\n", optlen);
      return -EFAULT;
    }
    break;

  case SO_REMOVE_FILTERING_RULE:
    if(pfr->ring_netdev == &none_device_element) return -EFAULT;

    if(optlen == sizeof(u_int16_t /* rule_id */ )) {
      /* This is a list rule */
      int rc;

      if(copy_from_user(&rule_id, optval, optlen))
	return -EFAULT;

      write_lock_bh(&pfr->ring_rules_lock);
      rc = remove_sw_filtering_rule_element(pfr, rule_id);
      write_unlock_bh(&pfr->ring_rules_lock);

      if (rc == 0) {
	if(unlikely(enable_debug))
	  printk("[PF_RING] SO_REMOVE_FILTERING_RULE: rule %d does not exist\n", rule_id);
	return -EFAULT;	/* Rule not found */
      }
    } else if(optlen == sizeof(hash_filtering_rule)) {
      /* This is a hash rule */
      sw_filtering_hash_bucket rule;
      int rc;

      if(copy_from_user(&rule.rule, optval, optlen))
	return -EFAULT;

      write_lock_bh(&pfr->ring_rules_lock);
      rc = handle_sw_filtering_hash_bucket(pfr, &rule, 0 /* delete */ );
      write_unlock_bh(&pfr->ring_rules_lock);

      if(rc != 0)
	return(rc);
    } else
      return -EFAULT;
    break;

  case SO_SET_SAMPLING_RATE:
    if(optlen != sizeof(pfr->sample_rate))
      return -EINVAL;

    if(copy_from_user(&pfr->sample_rate, optval, sizeof(pfr->sample_rate)))
      return -EFAULT;
    break;

  case SO_ACTIVATE_RING:
    if(unlikely(enable_debug))
      printk("[PF_RING] * SO_ACTIVATE_RING *\n");

    if(pfr->dna_device_entry != NULL) {
      int i;

      for(i=0; i<MAX_NUM_DNA_BOUND_SOCKETS; i++) {
	if((pfr->dna_device_entry->bound_sockets[i] != NULL)
	   && pfr->dna_device_entry->bound_sockets[i]->ring_active) {
	  if(   pfr->dna_device_entry->bound_sockets[i]->direction == pfr->direction
		|| pfr->dna_device_entry->bound_sockets[i]->direction == rx_and_tx_direction
		|| pfr->direction == rx_and_tx_direction) {
	    printk("[PF_RING] Unable to activate two or more DNA sockets on the same interface %s/direction\n",
		   pfr->ring_netdev->dev->name);

	    return -EFAULT; /* No way: we can't have two sockets that are doing the same thing with DNA */
	  }
	} /* if */
      } /* for */
    }

    found = 1, pfr->ring_active = 1;
    break;

  case SO_DEACTIVATE_RING:
    if(unlikely(enable_debug))
      printk("[PF_RING] * SO_DEACTIVATE_RING *\n");
    found = 1, pfr->ring_active = 0;
    break;

  case SO_SET_POLL_WATERMARK:
    if(optlen != sizeof(u_int16_t))
      return -EINVAL;
    else {
      u_int16_t threshold =  pfr->slots_info->min_num_slots/2;

      if(copy_from_user(&pfr->poll_num_pkts_watermark, optval, optlen))
	return -EFAULT;

      if(pfr->poll_num_pkts_watermark > threshold)
	pfr->poll_num_pkts_watermark = threshold;

      if(pfr->poll_num_pkts_watermark == 0)
	pfr->poll_num_pkts_watermark = 1;

      if(unlikely(enable_debug))
	printk("[PF_RING] --> SO_SET_POLL_WATERMARK=%d\n", pfr->poll_num_pkts_watermark);
    }
    break;

  case SO_RING_BUCKET_LEN:
    if(optlen != sizeof(u_int32_t))
      return -EINVAL;
    else {
      if(copy_from_user(&pfr->bucket_len, optval, optlen))
	return -EFAULT;

      if(unlikely(enable_debug))
	printk("[PF_RING] --> SO_RING_BUCKET_LEN=%d\n", pfr->bucket_len);
    }
    break;

  case SO_MAP_DNA_DEVICE:
    if(optlen != sizeof(dna_device_mapping))
      return -EINVAL;
    else {
      dna_device_mapping mapping;

      if(copy_from_user(&mapping, optval, optlen))
	return -EFAULT;
      else
	ret = ring_map_dna_device(pfr, &mapping), found = 1;
    }
    break;

  case SO_SET_MASTER_RING:
    /* Avoid using master sockets with bound rings */
    if(pfr->ring_netdev == &none_device_element)
      return -EFAULT;

    if(optlen != sizeof(ring_id))
      return -EINVAL;

    if(copy_from_user(&ring_id, optval, sizeof(ring_id)))
      return -EFAULT;

    write_lock_bh(&pfr->ring_rules_lock);
    ret = set_master_ring(sock->sk, pfr, ring_id);
    write_unlock_bh(&pfr->ring_rules_lock);
    break;

  case SO_ADD_HW_FILTERING_RULE:
    if(optlen != sizeof(hw_filtering_rule))
      return -EINVAL;

    if(copy_from_user(&hw_rule, optval, sizeof(hw_rule)))
      return -EFAULT;

    /* Check if a rule with the same id exists */
    list_for_each_safe(ptr, tmp_ptr, &pfr->hw_filtering_rules) {
      hw_filtering_rule_element *rule = list_entry(ptr, hw_filtering_rule_element, list);

      if(rule->rule.rule_id == hw_rule.rule_id) {
	/* There's already a rule with the same id: failure */
	printk("[PF_RING] Warning: duplicated hw rule id %d\n", hw_rule.rule_id);
	return -EINVAL;
      }
    }

    ret = handle_hw_filtering_rule(pfr, &hw_rule, add_hw_rule);

    if(ret != -1) {
      hw_filtering_rule_element *rule;

      if(unlikely(enable_debug))
        printk("[PF_RING] New hw filtering rule [id=%d]\n", hw_rule.rule_id);

      /* Add the hw rule to the socket hw rule list */
      rule = kmalloc(sizeof(hw_filtering_rule_element), GFP_ATOMIC);
      if(rule != NULL) {
	INIT_LIST_HEAD(&rule->list);
	memcpy(&rule->rule, &hw_rule, sizeof(hw_rule));
	list_add(&rule->list, &pfr->hw_filtering_rules); /* Add as first entry */
	pfr->num_hw_filtering_rules++;
      } else
	printk("[PF_RING] Out of memory\n");

      /* Increase the number of device hw rules */
      list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
        ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);

        if(dev_ptr->dev == pfr->ring_netdev->dev) {
	  dev_ptr->hw_filters.num_filters++;
          break;
        }
      }
    }

    found = 1;
    break;

  case SO_DEL_HW_FILTERING_RULE:
    if(optlen != sizeof(u_int16_t))
      return -EINVAL;

    if(copy_from_user(&rule_id, optval, sizeof(u_int16_t)))
      return -EFAULT;

    /* Check if the rule we want to remove exists */
    found = 0;
    list_for_each_safe(ptr, tmp_ptr, &pfr->hw_filtering_rules) {
      hw_filtering_rule_element *rule = list_entry(ptr, hw_filtering_rule_element, list);

      if(rule->rule.rule_id == rule_id) {
	/* There's already a rule with the same id: good */
	memcpy(&hw_rule, &rule->rule, sizeof(hw_filtering_rule));
	list_del(ptr);
        kfree(rule);
	found = 1;
	break;
      }
    }

    if(!found) return -EINVAL;

    ret = handle_hw_filtering_rule(pfr, &hw_rule, remove_hw_rule);

    if(ret != -1) {
      struct list_head *ptr, *tmp_ptr;

      pfr->num_hw_filtering_rules--;

      list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
        ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);

        if(dev_ptr->dev == pfr->ring_netdev->dev) {
	  if(dev_ptr->hw_filters.num_filters > 0)
	    dev_ptr->hw_filters.num_filters--;
          break;
        }
      }
    }
    break;

  case SO_SET_PACKET_CONSUMER_MODE:
    {
      u_int diff = optlen-sizeof(pfr->kernel_consumer_plugin_id);

      /* Copy the pluginId */
      if(copy_from_user(&pfr->kernel_consumer_plugin_id, optval,
			sizeof(pfr->kernel_consumer_plugin_id)))
	return -EFAULT;

#if 0
      printk("[PF_RING] SO_SET_PACKET_CONSUMER_MODE=%d [diff=%d]\n",
	     pfr->kernel_consumer_plugin_id, diff);
#endif

      if(diff > 0) {
	pfr->kernel_consumer_options = kmalloc(diff, GFP_KERNEL);

	if(pfr->kernel_consumer_options != NULL) {
	  if(copy_from_user(pfr->kernel_consumer_options,
			    &optval[sizeof(pfr->kernel_consumer_plugin_id)], diff))
	    return -EFAULT;
	} else
	  return -EFAULT;
      }

      /* Notify the consumer that we're ready to start */
      if(pfr->kernel_consumer_plugin_id
	 && (plugin_registration[pfr->kernel_consumer_plugin_id] == NULL)) {
	if(unlikely(enable_debug))
	  printk("[PF_RING] Plugin %d is unknown\n", pfr->kernel_consumer_plugin_id);

	pfr->kernel_consumer_plugin_id = 0;
	if(pfr->kernel_consumer_options != NULL) {
	  kfree(pfr->kernel_consumer_options);
	  pfr->kernel_consumer_options = NULL;
	}

	return -EFAULT;
      } else {
	if(plugin_registration[pfr->kernel_consumer_plugin_id]->pfring_packet_start
	   && (!pfr->ring_active)) {
	  plugin_registration[pfr->kernel_consumer_plugin_id]->
	    pfring_packet_start(pfr, copy_raw_data_to_ring);
	}
      }
    }
    break;

  case SO_SET_VIRTUAL_FILTERING_DEVICE:
    {
      virtual_filtering_device_info elem;

      if(optlen != sizeof(elem))
	return -EINVAL;

      if(copy_from_user(&elem, optval, sizeof(elem)))
	return -EFAULT;

      if((pfr->v_filtering_dev = add_virtual_filtering_device(sock->sk, &elem)) == NULL)
	return -EFAULT;
    }
    break;

  case SO_REHASH_RSS_PACKET:
    if(unlikely(enable_debug))
      printk("[PF_RING] * SO_REHASH_RSS_PACKET *\n");

    found = 1, pfr->rehash_rss = 1;
    break;

#ifdef VPFRING_SUPPORT
  case SO_SET_VPFRING_HOST_EVENTFD:
    if(optlen != sizeof(eventfd_i))
      return -EINVAL;

    if(copy_from_user(&eventfd_i, optval, sizeof(eventfd_i)))
      return -EFAULT;

    if(IS_ERR(eventfp = eventfd_fget(eventfd_i.fd)))
      return -EFAULT;

    /* We don't need to check the id (we have only one event)
     * eventfd_i.id == VPFRING_HOST_EVENT_RX_INT */

    pfr->vpfring_host_eventfd_ctx = eventfd_ctx_fileget(eventfp);
    break;

  case SO_SET_VPFRING_GUEST_EVENTFD:
    return -EINVAL; /* (unused) */
    break;

  case SO_SET_VPFRING_CLEAN_EVENTFDS:
    if(pfr->vpfring_host_eventfd_ctx)
      eventfd_ctx_put(pfr->vpfring_host_eventfd_ctx);
    pfr->vpfring_host_eventfd_ctx = NULL;
    break;
#endif //VPFRING_SUPPORT

  case SO_ATTACH_USERSPACE_RING:
    {
      char u_dev_name[32+1];

      if(copy_from_user(u_dev_name, optval, sizeof(u_dev_name) - 1))
	return -EFAULT;

      u_dev_name[sizeof(u_dev_name) - 1] = '\0';

      if(pfr->ring_memory != NULL)
        return -EINVAL; /* TODO mmap() already called */

      /* Checks if the userspace ring exists */
      pfr->userspace_ring = userspace_ring_create(u_dev_name, userspace_ring_producer, NULL);

      if(pfr->userspace_ring == NULL)
        return -EINVAL;

      pfr->userspace_ring_type = userspace_ring_producer;

      if(unlikely(enable_debug))
        printk("[PF_RING] SO_ATTACH_USERSPACE_RING done.\n");
    }
    found = 1;
    break;

  case SO_SHUTDOWN_RING:
    found = 1, pfr->ring_active = 0, pfr->ring_shutdown = 1;
    wake_up_interruptible(&pfr->ring_slots_waitqueue);
    break;

  default:
    found = 0;
    break;
  }

  if(found)
    return(ret);
  else
    return(sock_setsockopt(sock, level, optname, optval, optlen));
}

/* ************************************* */

static int ring_getsockopt(struct socket *sock,
			   int level, int optname,
			   char __user *optval,
			   int __user *optlen)
{
  int len;
  struct pf_ring_socket *pfr = ring_sk(sock->sk);

  if(pfr == NULL)
    return(-EINVAL);

  if(get_user(len, optlen))
    return -EFAULT;

  if(len < 0)
    return -EINVAL;

  if(unlikely(enable_debug))
    printk("[PF_RING] --> getsockopt(%d)\n", optname);

  switch (optname) {
  case SO_GET_RING_VERSION:
    {
      u_int32_t version = RING_VERSION_NUM;

      if(len < sizeof(u_int32_t))
	return -EINVAL;
      else if(copy_to_user(optval, &version, sizeof(version)))
	return -EFAULT;
    }
    break;

  case PACKET_STATISTICS:
    {
      struct tpacket_stats st;

      if(len < sizeof(struct tpacket_stats))
	return -EINVAL;

      st.tp_packets = atomic_read(&pfr->slots_info->tot_insert);
      st.tp_drops = atomic_read(&pfr->slots_info->tot_lost);

      if(copy_to_user(optval, &st, len))
	return -EFAULT;
      break;
    }

  case SO_GET_HASH_FILTERING_RULE_STATS:
    {
      int rc = -EFAULT;

      if(len >= sizeof(hash_filtering_rule)) {
	hash_filtering_rule rule;
	u_int hash_idx;

	if(pfr->sw_filtering_hash == NULL) {
	  printk("[PF_RING] so_get_hash_filtering_rule_stats(): no hash failure\n");
	  return -EFAULT;
	}

	if(copy_from_user(&rule, optval, sizeof(rule))) {
	  printk("[PF_RING] so_get_hash_filtering_rule_stats: copy_from_user() failure\n");
	  return -EFAULT;
	}

	if(unlikely(enable_debug))
	  printk("[PF_RING] so_get_hash_filtering_rule_stats"
		 "(vlan=%u, proto=%u, sip=%u, sport=%u, dip=%u, dport=%u)\n",
		 rule.vlan_id, rule.proto,
		 rule.host4_peer_a, rule.port_peer_a,
		 rule.host4_peer_b,
		 rule.port_peer_b);

	hash_idx = hash_pkt(rule.vlan_id, rule.proto,
			    rule.host_peer_a, rule.host_peer_b,
			    rule.port_peer_a, rule.port_peer_b) % DEFAULT_RING_HASH_SIZE;

	if(pfr->sw_filtering_hash[hash_idx] != NULL) {
	  sw_filtering_hash_bucket *bucket;

	  read_lock_bh(&pfr->ring_rules_lock);
	  bucket = pfr->sw_filtering_hash[hash_idx];

	  if(unlikely(enable_debug))
	    printk("[PF_RING] so_get_hash_filtering_rule_stats(): bucket=%p\n",
		   bucket);

	  while(bucket != NULL) {
	    if(hash_bucket_match_rule(bucket, &rule)) {
	      char *buffer = kmalloc(len, GFP_ATOMIC);

	      if(buffer == NULL) {
		printk("[PF_RING] so_get_hash_filtering_rule_stats() no memory failure\n");
		rc = -EFAULT;
	      } else {
		if((plugin_registration[rule.plugin_action.plugin_id] == NULL)
		   ||
		   (plugin_registration[rule.plugin_action.plugin_id]->pfring_plugin_get_stats == NULL)) {
		  printk("[PF_RING] Found rule but pluginId %d is not registered\n",
			 rule.plugin_action.plugin_id);
		  rc = -EFAULT;
		} else
		  rc = plugin_registration[rule.plugin_action.plugin_id]->
		    pfring_plugin_get_stats(pfr, NULL, bucket, buffer, len);

		if(rc > 0) {
		  if(copy_to_user(optval, buffer, rc)) {
		    printk("[PF_RING] copy_to_user() failure\n");
		    rc = -EFAULT;
		  }
		}
	      }
	      break;
	    } else
	      bucket = bucket->next;
	  }	/* while */

	  read_unlock_bh(&pfr->ring_rules_lock);
	} else {
	  if(unlikely(enable_debug))
	    printk("[PF_RING] so_get_hash_filtering_rule_stats(): entry not found [hash_idx=%d]\n",
		   hash_idx);
	}
      }

      return(rc);
      break;
    }

  case SO_GET_FILTERING_RULE_STATS:
    {
      char *buffer = NULL;
      int rc = -EFAULT;
      struct list_head *ptr, *tmp_ptr;
      u_int16_t rule_id;

      if(len < sizeof(rule_id))
	return -EINVAL;

      if(copy_from_user(&rule_id, optval, sizeof(rule_id)))
	return -EFAULT;

      if(unlikely(enable_debug))
	printk("[PF_RING] SO_GET_FILTERING_RULE_STATS: rule_id=%d\n",
	       rule_id);

      read_lock_bh(&pfr->ring_rules_lock);
      list_for_each_safe(ptr, tmp_ptr, &pfr->sw_filtering_rules) {
	sw_filtering_rule_element *rule;

	rule = list_entry(ptr, sw_filtering_rule_element, list);

	if(rule->rule.rule_id == rule_id) {
	  buffer = kmalloc(len, GFP_ATOMIC);

	  if(buffer == NULL)
	    rc = -EFAULT;
	  else {
	    if((plugin_registration[rule->rule.plugin_action.plugin_id] == NULL)
	       ||
	       (plugin_registration[rule->rule.plugin_action.plugin_id]->pfring_plugin_get_stats == NULL)) {
	      printk("[PF_RING] Found rule %d but pluginId %d is not registered\n",
		     rule_id, rule->rule.plugin_action.plugin_id);
	      rc = -EFAULT;
	    } else
	      rc = plugin_registration[rule->rule.plugin_action.plugin_id]->
		pfring_plugin_get_stats(pfr, rule, NULL, buffer, len);

	    if(rc > 0) {
	      if(copy_to_user(optval, buffer, rc)) {
		rc = -EFAULT;
	      }
	    }
	  }
	  break;
	}
      }

      read_unlock_bh(&pfr->ring_rules_lock);
      if(buffer != NULL)
	kfree(buffer);

      /* printk("[PF_RING] SO_GET_FILTERING_RULE_STATS *END*\n"); */
      return(rc);
      break;
    }

  case SO_GET_MAPPED_DNA_DEVICE:
    {
      if((pfr->dna_device == NULL) || (len < sizeof(dna_memory_slots)))
	return -EFAULT;

      if(copy_to_user(optval, &pfr->dna_device->mem_info, sizeof(dna_memory_slots)))
	return -EFAULT;

      break;
    }

  case SO_GET_EXTRA_DMA_MEMORY:
    {
      u_int64_t num_slots;

      if(pfr->dna_device == NULL || pfr->dna_device->hwdev == NULL)
        return -EINVAL;

      if(len < sizeof(u_int64_t))
        return -EINVAL;

      if(copy_from_user(&num_slots, optval, sizeof(num_slots)))
        return -EFAULT;

      if(num_slots > MAX_EXTRA_DMA_SLOTS)
        num_slots = MAX_EXTRA_DMA_SLOTS;

      if(len < (sizeof(u_int64_t) * num_slots))
        return -EINVAL;

      if(allocate_extra_dma_memory(pfr, pfr->dna_device->hwdev, num_slots, 
                                   pfr->dna_device->mem_info.rx.packet_memory_slot_len, 
                                   pfr->dna_device->mem_info.rx.packet_memory_chunk_len) < 0)
        return -EFAULT;
	
      if(copy_to_user(optval, pfr->extra_dma_memory_addr, (sizeof(u_int64_t) * num_slots))) {
        free_extra_dma_memory(pfr);
        return -EFAULT;
      }

      break;
    }

  case SO_GET_NUM_RX_CHANNELS:
    {
      u_int8_t num_rx_channels;

      if(pfr->ring_netdev == &none_device_element) {
	/* Device not yet bound */
	num_rx_channels = UNKNOWN_NUM_RX_CHANNELS;
      } else {
	if(pfr->ring_netdev->is_dna_device)
	  num_rx_channels = pfr->ring_netdev->num_dna_rx_queues;
	else
	  num_rx_channels = max_val(pfr->num_rx_channels, get_num_rx_queues(pfr->ring_netdev->dev));
      }

      if(unlikely(enable_debug))
	printk("[PF_RING] --> SO_GET_NUM_RX_CHANNELS[%s]=%d [dna=%d/dns_rx_channels=%d][%p]\n",
	       pfr->ring_netdev->dev->name, num_rx_channels,
	       pfr->ring_netdev->is_dna_device,
	       pfr->ring_netdev->num_dna_rx_queues,
	       pfr->ring_netdev);

      if(copy_to_user(optval, &num_rx_channels, sizeof(num_rx_channels)))
	return -EFAULT;
    }
    break;

  case SO_GET_RING_ID:
    if(len < sizeof(pfr->ring_id))
      return -EINVAL;

    if(unlikely(enable_debug))
      printk("[PF_RING] --> SO_GET_RING_ID=%d\n", pfr->ring_id);

    if(copy_to_user(optval, &pfr->ring_id, sizeof(pfr->ring_id)))
      return -EFAULT;
    break;

  case SO_GET_PACKET_CONSUMER_MODE:
    if(len < sizeof(pfr->kernel_consumer_plugin_id))
      return -EINVAL;

    if(unlikely(enable_debug))
      printk("[PF_RING] --> SO_GET_PACKET_CONSUMER_MODE=%d\n",
	     pfr->kernel_consumer_plugin_id);

    if(copy_to_user(optval, &pfr->kernel_consumer_plugin_id,
		    sizeof(pfr->kernel_consumer_plugin_id)))
      return -EFAULT;
    break;

  case SO_GET_BOUND_DEVICE_ADDRESS:
    if(len < ETH_ALEN) return -EINVAL;

    if(pfr->dna_device != NULL) {
      if(copy_to_user(optval, pfr->dna_device->device_address, 6))
	return -EFAULT;
    } else if((pfr->ring_netdev != NULL)
	      && (pfr->ring_netdev->dev != NULL)) {
      char lowest_if_mac[ETH_ALEN] = { 0 };
      char magic_if_mac[ETH_ALEN];
      memset(magic_if_mac, RING_MAGIC_VALUE, sizeof(magic_if_mac));

      /* Read input buffer */
      if(copy_from_user(&lowest_if_mac, optval, ETH_ALEN))
	return -EFAULT;

      if(!memcmp(lowest_if_mac, magic_if_mac, ETH_ALEN)) {
	struct list_head *ptr, *tmp_ptr;
	long lowest_id = -1;

	/* Return the MAC address of the lowest X of ethX */

	list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
	  ring_device_element *entry = list_entry(ptr, ring_device_element, device_list);
	  char *eptr;
	  long id = simple_strtol(&entry->dev->name[3], &eptr, 10);

	  if((lowest_id == -1) || (id < lowest_id)) {
	    lowest_id = id, memcpy(lowest_if_mac, entry->dev->perm_addr, ETH_ALEN);
	  }
	}

	if(copy_to_user(optval, lowest_if_mac, ETH_ALEN))
	  return -EFAULT;
      } else {
	if(copy_to_user(optval, pfr->ring_netdev->dev->dev_addr, ETH_ALEN))
	  return -EFAULT;
      }
    } else
      return -EFAULT;
    break;

  case SO_GET_NUM_QUEUED_PKTS:
    {
      u_int32_t num_queued = num_queued_pkts(pfr);

      if(len < sizeof(num_queued))
	return -EINVAL;

      if(copy_to_user(optval, &num_queued, sizeof(num_queued)))
	return -EFAULT;
    }
    break;

  case SO_GET_PKT_HEADER_LEN:
    if(len < sizeof(pfr->slot_header_len))
      return -EINVAL;

    if(copy_to_user(optval, &pfr->slot_header_len, sizeof(pfr->slot_header_len)))
      return -EFAULT;
    break;

  case SO_GET_BUCKET_LEN:
    if(len < sizeof(pfr->bucket_len))
      return -EINVAL;

    if(copy_to_user(optval, &pfr->bucket_len, sizeof(pfr->bucket_len)))
      return -EFAULT;
    break;

  case SO_GET_LOOPBACK_TEST:
    /* Used for testing purposes only */
    {
      /* printk("SO_GET_LOOPBACK_TEST (len=%d)\n", len); */

      if(len > 0) {
	if(len > loobpack_test_buffer_len) return(-EFAULT);

	if(loobpack_test_buffer == NULL) {
	  loobpack_test_buffer = kmalloc(loobpack_test_buffer_len, GFP_ATOMIC);

	  if(loobpack_test_buffer == NULL)
	    return(-EFAULT); /* Not enough memory */
	}

	{
	  u_int i;

	  for(i=0; i<len; i++) loobpack_test_buffer[i] = i;
	}

	if(copy_to_user(optval, loobpack_test_buffer, len))
	  return -EFAULT;
      }
    }
    break;

  case SO_GET_DEVICE_TYPE:
    if(len < sizeof(pfring_device_type))
      return -EINVAL;

    if (pfr->ring_netdev == NULL)
      return -EFAULT;

    if(copy_to_user(optval, &pfr->ring_netdev->device_type, sizeof(pfring_device_type)))
      return -EFAULT;
    break;

  default:
    return -ENOPROTOOPT;
  }

  if(put_user(len, optlen))
    return -EFAULT;
  else
    return(0);
}

/* ************************************* */

void dna_device_handler(dna_device_operation operation,
			dna_version version,
			mem_ring_info *rx_info,
			mem_ring_info *tx_info,
			unsigned long  rx_packet_memory[DNA_MAX_NUM_CHUNKS],
			void          *rx_descr_packet_memory,
			unsigned long  tx_packet_memory[DNA_MAX_NUM_CHUNKS],
			void          *tx_descr_packet_memory,
			void          *phys_card_memory,
			u_int          phys_card_memory_len,
			u_int channel_id,
			struct net_device *netdev,
			struct device *hwdev,
			dna_device_model device_model,
			u_char *device_address,
			wait_queue_head_t *packet_waitqueue,
			u_int8_t *interrupt_received,
			void *adapter_ptr,
			dna_wait_packet wait_packet_function_ptr,
			dna_device_notify dev_notify_function_ptr)
{
  if(unlikely(enable_debug)) {
    printk("[PF_RING] dna_device_handler(%s@%u [operation=%s])\n",
	   netdev->name, channel_id,
	   operation == add_device_mapping ? "add_device_mapping" : "remove_device_mapping");
    printk("[PF_RING] RX=%u/TX=%u\n", rx_info->packet_memory_num_chunks, tx_info->packet_memory_num_chunks);
  }

  if(operation == add_device_mapping) {
    dna_device_list *next;

    next = kmalloc(sizeof(dna_device_list), GFP_ATOMIC);
    if(next != NULL) {
      memset(next, 0, sizeof(dna_device_list));

      next->num_bound_sockets = 0, next->dev.mem_info.version = version;

      //printk("[PF_RING] [rx_slots=%u/num_rx_pages=%u/memory_tot_len=%u]][tx_slots=%u/num_tx_pages=%u]\n",
      //       packet_memory_num_slots, num_rx_pages, packet_memory_tot_len,
      //       num_tx_slots, num_tx_pages);

      /* RX */
      if(rx_info != NULL)
        memcpy(&next->dev.mem_info.rx, rx_info, sizeof(next->dev.mem_info.rx));
      if(rx_packet_memory != NULL)
        memcpy(&next->dev.rx_packet_memory, rx_packet_memory, sizeof(next->dev.rx_packet_memory));
      next->dev.rx_descr_packet_memory = rx_descr_packet_memory;

      /* TX */
      if(tx_info != NULL)
        memcpy(&next->dev.mem_info.tx, tx_info, sizeof(next->dev.mem_info.tx));
      if(tx_packet_memory != NULL)
	memcpy(&next->dev.tx_packet_memory, tx_packet_memory, sizeof(next->dev.tx_packet_memory));
      next->dev.tx_descr_packet_memory = tx_descr_packet_memory;

      /* PHYS */
      next->dev.phys_card_memory = phys_card_memory;
      next->dev.mem_info.phys_card_memory_len = phys_card_memory_len;

      next->dev.channel_id = channel_id;
      next->dev.netdev = netdev;
      next->dev.hwdev = hwdev;
      next->dev.mem_info.device_model = device_model;
      memcpy(next->dev.device_address, device_address, 6);
      next->dev.packet_waitqueue = packet_waitqueue;
      next->dev.interrupt_received = interrupt_received;
      next->dev.adapter_ptr = adapter_ptr;
      next->dev.wait_packet_function_ptr = wait_packet_function_ptr;
      next->dev.usage_notification = dev_notify_function_ptr;
      list_add(&next->list, &ring_dna_devices_list);
      dna_devices_list_size++;
      /* Increment usage count to avoid unloading it while DNA modules are in use */
      try_module_get(THIS_MODULE);

      /* We now have to update the device list */
      {
	struct list_head *ptr, *tmp_ptr;

	list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
	  ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);

	  if(strcmp(dev_ptr->dev->name, netdev->name) == 0) {
	    dev_ptr->num_dna_rx_queues = max_val(dev_ptr->num_dna_rx_queues, channel_id+1);
	    dev_ptr->is_dna_device = 1, dev_ptr->dna_device_model = device_model;

	    if(unlikely(enable_debug))
	      printk("[PF_RING] ==>> Updating DNA %s [num_dna_rx_queues=%d][%p]\n",
		     dev_ptr->dev->name, dev_ptr->num_dna_rx_queues, dev_ptr);
	    break;
	  }
	}
      }
    } else {
      printk("[PF_RING] Could not kmalloc slot!!\n");
    }
  } else {
    struct list_head *ptr, *tmp_ptr;
    dna_device_list *entry;

    list_for_each_safe(ptr, tmp_ptr, &ring_dna_devices_list) {
      entry = list_entry(ptr, dna_device_list, list);

      if((entry->dev.netdev == netdev)
	 && (entry->dev.channel_id == channel_id)) {
	list_del(ptr);
	kfree(entry);
	dna_devices_list_size--;
	/* Decrement usage count for DNA devices */
	module_put(THIS_MODULE);
	break;
      }
    }
  }

  if(unlikely(enable_debug))
    printk("[PF_RING] dna_device_handler(%s): [dna_devices_list_size=%d]\n",
	   netdev->name, dna_devices_list_size);
}

/* ************************************* */

static int ring_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
  switch (cmd) {
#ifdef CONFIG_INET
  case SIOCGIFFLAGS:
  case SIOCSIFFLAGS:
  case SIOCGIFCONF:
  case SIOCGIFMETRIC:
  case SIOCSIFMETRIC:
  case SIOCGIFMEM:
  case SIOCSIFMEM:
  case SIOCGIFMTU:
  case SIOCSIFMTU:
  case SIOCSIFLINK:
  case SIOCGIFHWADDR:
  case SIOCSIFHWADDR:
  case SIOCSIFMAP:
  case SIOCGIFMAP:
  case SIOCSIFSLAVE:
  case SIOCGIFSLAVE:
  case SIOCGIFINDEX:
  case SIOCGIFNAME:
  case SIOCGIFCOUNT:
  case SIOCSIFHWBROADCAST:
    return(inet_dgram_ops.ioctl(sock, cmd, arg));
#endif

  default:
    return -ENOIOCTLCMD;
  }

  return 0;
}

/* ************************************* */

static struct proto_ops ring_ops = {
  .family = PF_RING,
  .owner = THIS_MODULE,

  /* Operations that make no sense on ring sockets. */
  .connect = sock_no_connect,
  .socketpair = sock_no_socketpair,
  .accept = sock_no_accept,
  .getname = sock_no_getname,
  .listen = sock_no_listen,
  .shutdown = sock_no_shutdown,
  .sendpage = sock_no_sendpage,

  /* Now the operations that really occur. */
  .release = ring_release,
  .bind = ring_bind,
  .mmap = ring_mmap,
  .poll = ring_poll,
  .setsockopt = ring_setsockopt,
  .getsockopt = ring_getsockopt,
  .ioctl = ring_ioctl,
  .recvmsg = ring_recvmsg,
  .sendmsg = ring_sendmsg,
};

/* ************************************ */

static struct net_proto_family ring_family_ops = {
  .family = PF_RING,
  .create = ring_create,
  .owner = THIS_MODULE,
};

// BD: API changed in 2.6.12, ref:
// http://svn.clkao.org/svnweb/linux/revision/?rev=28201
#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11))
static struct proto ring_proto = {
  .name = "PF_RING",
  .owner = THIS_MODULE,
  .obj_size = sizeof(struct ring_sock),
};
#endif

/* ************************************ */

static struct pfring_hooks ring_hooks = {
  .magic = PF_RING,
  .transparent_mode = &transparent_mode,
  .ring_handler = skb_ring_handler,
  .buffer_ring_handler = buffer_ring_handler,
  .buffer_add_hdr_to_ring = add_hdr_to_ring,
  .pfring_registration = register_plugin,
  .pfring_unregistration = unregister_plugin,
  .ring_dna_device_handler = dna_device_handler,
};

/* ************************************ */

void remove_device_from_ring_list(struct net_device *dev) {
  struct list_head *ptr, *tmp_ptr;

  list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
    ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);

    if(dev_ptr->dev == dev) {
      struct list_head *ring_ptr, *ring_tmp_ptr;

      if(dev_ptr->proc_entry) {
#ifdef ENABLE_PROC_WRITE_RULE
	if(dev_ptr->device_type != standard_nic_family)
	  remove_proc_entry(PROC_RULES, dev_ptr->proc_entry);
#endif

	remove_proc_entry(PROC_INFO, dev_ptr->proc_entry);
	remove_proc_entry(dev_ptr->dev->name, ring_proc_dev_dir);
      }

      /* We now have to "un-bind" existing sockets */
      list_for_each_safe(ring_ptr, ring_tmp_ptr, &ring_table) {
	struct ring_element   *entry = list_entry(ring_ptr, struct ring_element, list);
	struct pf_ring_socket *pfr = ring_sk(entry->sk);

	if(pfr->ring_netdev == dev_ptr)
	  pfr->ring_netdev = &none_device_element; /* Unbinding socket */
      }

      list_del(ptr);
      kfree(dev_ptr);
      break;
    }
  }
}

/* ************************************ */

int add_device_to_ring_list(struct net_device *dev) {
  ring_device_element *dev_ptr;

  if((dev_ptr = kmalloc(sizeof(ring_device_element), GFP_KERNEL)) == NULL)
    return(-ENOMEM);

  memset(dev_ptr, 0, sizeof(ring_device_element));
  INIT_LIST_HEAD(&dev_ptr->device_list);
  dev_ptr->dev = dev;
  dev_ptr->proc_entry = proc_mkdir(dev_ptr->dev->name, ring_proc_dev_dir);
  dev_ptr->device_type = standard_nic_family; /* Default */

  create_proc_read_entry(PROC_INFO, 0 /* read-only */,
			 dev_ptr->proc_entry,
			 ring_proc_dev_get_info /* read */,
			 dev_ptr);

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
  /* Dirty trick to fix at some point used to discover Intel 82599 interfaces: FIXME */
  if((dev_ptr->dev->ethtool_ops != NULL) && (dev_ptr->dev->ethtool_ops->set_rxnfc != NULL)) {
    struct ethtool_rxnfc cmd;
    int rc;

    cmd.cmd = ETHTOOL_PFRING_SRXFTCHECK /* check */;

    rc = dev_ptr->dev->ethtool_ops->set_rxnfc(dev_ptr->dev, &cmd);

    if(unlikely(enable_debug))
      printk("[PF_RING] set_rxnfc returned %d\n", rc);

    if(rc == RING_MAGIC_VALUE) {
      /* This device supports hardware filtering */
      dev_ptr->device_type = intel_82599_family;

      /* Setup handlers */
      dev_ptr->hw_filters.filter_handlers.five_tuple_handler = i82599_generic_handler;
      dev_ptr->hw_filters.filter_handlers.perfect_filter_handler = i82599_generic_handler;

#ifdef ENABLE_PROC_WRITE_RULE
      entry = create_proc_read_entry(PROC_RULES, 0666 /* rw */,
				     dev_ptr->proc_entry,
				     ring_proc_dev_rule_read, dev_ptr);
      if(entry) {
	entry->write_proc = ring_proc_dev_rule_write;
	if(unlikely(enable_debug)) printk("[PF_RING] Device %s (Intel 82599) DOES support hardware packet filtering\n", dev->name);
      } else {
	if(unlikely(enable_debug)) printk("[PF_RING] Error while creating /proc entry 'rules' for device %s\n", dev->name);
      }
#endif
    } else {
      if(unlikely(enable_debug)) printk("[PF_RING] Device %s does NOT support hardware packet filtering [1]\n", dev->name);
    }
  } else {
    if(unlikely(enable_debug)) printk("[PF_RING] Device %s does NOT support hardware packet filtering [2]\n", dev->name);
  }
#endif

  list_add(&dev_ptr->device_list, &ring_aware_device_list);

  return(0);
}

/* ************************************ */

void pf_ring_add_module_dependency(void) {
  /* Don't actually do anything */
}
EXPORT_SYMBOL(pf_ring_add_module_dependency);

/* ************************************ */

static int ring_notifier(struct notifier_block *this, unsigned long msg, void *data)
{
  struct net_device *dev = data;
  struct pfring_hooks *hook;

  if(dev != NULL) {
    if(unlikely(enable_debug))
      printk("[PF_RING] packet_notifier(%lu) [%s][%d]\n", msg, dev->name, dev->type);

    /* Skip non ethernet interfaces */
    if(
       (dev->type != ARPHRD_ETHER) /* Ethernet */
       /* Wifi */
       && (dev->type != ARPHRD_IEEE80211)
       && (dev->type != ARPHRD_IEEE80211_PRISM)
       && (dev->type != ARPHRD_IEEE80211_RADIOTAP)
       && strncmp(dev->name, "bond", 4)) {
      if(unlikely(enable_debug)) printk("[PF_RING] packet_notifier(%s): skipping non ethernet device\n", dev->name);
      return NOTIFY_DONE;
    }

    if(dev->ifindex >= MAX_NUM_IFIDX) {
      if(unlikely(enable_debug))
	printk("[PF_RING] packet_notifier(%s): interface index %d > max index %d\n",
	       dev->name, dev->ifindex, MAX_NUM_IFIDX);
      return NOTIFY_DONE;
    }

    switch(msg) {
    case NETDEV_PRE_UP:
    case NETDEV_UP:
    case NETDEV_DOWN:
      break;
    case NETDEV_REGISTER:
      if(unlikely(enable_debug))
	printk("[PF_RING] packet_notifier(%s) [REGISTER][pfring_ptr=%p][hook=%p]\n",
	       dev->name, dev->pfring_ptr, &ring_hooks);

      if(dev->pfring_ptr == NULL) {
	dev->pfring_ptr = &ring_hooks;
	if(add_device_to_ring_list(dev) != 0) {
	  printk("[PF_RING] Error in add_device_to_ring_list(%s)\n", dev->name);
	}
      }
      break;

    case NETDEV_UNREGISTER:
      if(unlikely(enable_debug))
	printk("[PF_RING] packet_notifier(%s) [UNREGISTER][pfring_ptr=%p]\n",
	       dev->name, dev->pfring_ptr);

      hook = (struct pfring_hooks*)dev->pfring_ptr;
      if(hook && (hook->magic == PF_RING)) {
	remove_device_from_ring_list(dev);
	dev->pfring_ptr = NULL;
      }
      /* We don't have to worry updating rules that might have used this
	 device (just removed) as reflection device. This because whenever
	 we set a rule with reflection, we do dev_put() so such device is
	 busy until we remove the rule
      */
      break;

    case NETDEV_CHANGE:     /* Interface state change */
    case NETDEV_CHANGEADDR: /* Interface address changed (e.g. during device probing) */
      break;
    case NETDEV_CHANGENAME: /* Rename interface ethX -> ethY */
      {
	struct list_head *ptr, *tmp_ptr;

	if(unlikely(enable_debug)) printk("[PF_RING] Device change name %s\n", dev->name);

	list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
	  ring_device_element *dev_ptr = list_entry(ptr, ring_device_element, device_list);

	  if(dev_ptr->dev == dev) {
	    if(unlikely(enable_debug))
	      printk("[PF_RING] ==>> FOUND device change name %s -> %s\n",
		     dev_ptr->proc_entry->name, dev->name);

	    /* Remove old entry */
#ifdef ENABLE_PROC_WRITE_RULE
	    if(dev_ptr->device_type != standard_nic_family)
	      remove_proc_entry(PROC_RULES, dev_ptr->proc_entry);
#endif

	    remove_proc_entry(PROC_INFO, dev_ptr->proc_entry);
	    remove_proc_entry(dev_ptr->proc_entry->name, ring_proc_dev_dir);
	    /* Add new entry */
	    dev_ptr->proc_entry = proc_mkdir(dev_ptr->dev->name, ring_proc_dev_dir);
	    create_proc_read_entry(PROC_INFO, 0 /* read-only */,
				   dev_ptr->proc_entry,
				   ring_proc_dev_get_info /* read */,
				   dev_ptr);

#ifdef ENABLE_PROC_WRITE_RULE
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31))
	    if(dev_ptr->device_type != standard_nic_family) {
	      struct proc_dir_entry *entry;

	      entry= create_proc_read_entry(PROC_RULES, 0666 /* rw */,
					    dev_ptr->proc_entry,
					    ring_proc_dev_rule_read,
					    dev_ptr);
	      if(entry)
		entry->write_proc = ring_proc_dev_rule_write;
	    }
#endif
#endif

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0))
	    strncpy(dev_ptr->proc_entry->name, dev->name, dev_ptr->proc_entry->namelen);
	    dev_ptr->proc_entry->name[dev_ptr->proc_entry->namelen /* size is namelen+1 */] = '\0';
#else
	    dev_ptr->proc_entry->name = dev->name;
#endif
	    break;
	  }
	}
      }
      break;

    default:
      if(unlikely(enable_debug))
	printk("[PF_RING] packet_notifier(%s): unhandled message [msg=%lu][pfring_ptr=%p]\n",
	       dev->name, msg, dev->pfring_ptr);
      break;
    }
  }

  return NOTIFY_DONE;
}

/* ************************************ */

static struct notifier_block ring_netdev_notifier = {
  .notifier_call = ring_notifier,
};

/* ************************************ */

static void __exit ring_exit(void)
{
  struct list_head *ptr, *tmp_ptr;
  struct ring_element *entry;
  struct pfring_hooks *hook;

  pfring_enabled = 0;

  unregister_device_handler();

  list_for_each_safe(ptr, tmp_ptr, &ring_table) {
    entry = list_entry(ptr, struct ring_element, list);
    list_del(ptr);
    kfree(entry);
  }

  list_del(&any_device_element.device_list);
  list_for_each_safe(ptr, tmp_ptr, &ring_aware_device_list) {
    ring_device_element *dev_ptr;

    dev_ptr = list_entry(ptr, ring_device_element, device_list);
    hook = (struct pfring_hooks*)dev_ptr->dev->pfring_ptr;

#ifdef ENABLE_PROC_WRITE_RULE
    /* Remove /proc entry for the selected device */
    if(dev_ptr->device_type != standard_nic_family)
      remove_proc_entry(PROC_RULES, dev_ptr->proc_entry);
#endif

    remove_proc_entry(PROC_INFO, dev_ptr->proc_entry);
    remove_proc_entry(dev_ptr->dev->name, ring_proc_dev_dir);

    if(hook->magic == PF_RING) {
      if(unlikely(enable_debug)) printk("[PF_RING] Unregister hook for %s\n", dev_ptr->dev->name);
      dev_ptr->dev->pfring_ptr = NULL; /* Unhook PF_RING */
    }

    list_del(ptr);
    kfree(dev_ptr);
  }

  list_for_each_safe(ptr, tmp_ptr, &ring_cluster_list) {
    ring_cluster_element *cluster_ptr;

    cluster_ptr = list_entry(ptr, ring_cluster_element, list);

    list_del(ptr);
    kfree(cluster_ptr);
  }

  list_for_each_safe(ptr, tmp_ptr, &ring_dna_devices_list) {
    dna_device_list *elem;

    elem = list_entry(ptr, dna_device_list, list);

    list_del(ptr);
    kfree(elem);
  }

  sock_unregister(PF_RING);
#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11))
  proto_unregister(&ring_proto);
#endif
  unregister_netdevice_notifier(&ring_netdev_notifier);
  ring_proc_term();

  if(loobpack_test_buffer != NULL)
    kfree(loobpack_test_buffer);

  printk("[PF_RING] Module unloaded\n");
}

/* ************************************ */

static int __init ring_init(void)
{
  static struct net_device any_dev, none_dev;
  int i;
#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11))
  int rc;
#endif

  printk("[PF_RING] Welcome to PF_RING %s ($Revision: %s$)\n"
	 "(C) 2004-11 L.Deri <deri@ntop.org>\n",
	 RING_VERSION, SVN_REV);

#if(LINUX_VERSION_CODE > KERNEL_VERSION(2,6,11))
  if((rc = proto_register(&ring_proto, 0)) != 0)
    return(rc);
#endif

  INIT_LIST_HEAD(&ring_table);
  INIT_LIST_HEAD(&virtual_filtering_devices_list);
  INIT_LIST_HEAD(&ring_cluster_list);
  INIT_LIST_HEAD(&ring_aware_device_list);
  INIT_LIST_HEAD(&ring_dna_devices_list);
  INIT_LIST_HEAD(&userspace_ring_list);

  for(i = 0; i < MAX_NUM_DEVICES; i++)
    INIT_LIST_HEAD(&device_ring_list[i]);

  init_ring_readers();

  memset(&any_dev, 0, sizeof(any_dev));
  strcpy(any_dev.name, "any");
  any_dev.ifindex = MAX_NUM_IFIDX-1, any_dev.type = ARPHRD_ETHER;
  memset(&any_device_element, 0, sizeof(any_device_element));
  any_device_element.dev = &any_dev, any_device_element.device_type = standard_nic_family;

  INIT_LIST_HEAD(&any_device_element.device_list);
  list_add(&any_device_element.device_list, &ring_aware_device_list);

  memset(&none_dev, 0, sizeof(none_dev));
  strcpy(none_dev.name, "none");
  none_dev.ifindex = MAX_NUM_IFIDX-2, none_dev.type = ARPHRD_ETHER;
  memset(&none_device_element, 0, sizeof(none_device_element));
  none_device_element.dev = &none_dev, none_device_element.device_type = standard_nic_family;

  ring_proc_init();
  sock_register(&ring_family_ops);
  register_netdevice_notifier(&ring_netdev_notifier);

  /* Sanity check */
  if(transparent_mode > driver2pf_ring_non_transparent)
    transparent_mode = standard_linux_path;

  printk("[PF_RING] Min # ring slots %d\n", min_num_slots);
  printk("[PF_RING] Slot version     %d\n",
	 RING_FLOWSLOT_VERSION);
  printk("[PF_RING] Capture TX       %s\n",
	 enable_tx_capture ? "Yes [RX+TX]" : "No [RX only]");
  printk("[PF_RING] Transparent Mode %d\n",
	 transparent_mode);
  printk("[PF_RING] IP Defragment    %s\n",
	 enable_ip_defrag ? "Yes" : "No");
  printk("[PF_RING] Initialized correctly\n");

  register_device_handler();

  pfring_enabled = 1;
  return 0;
}

module_init(ring_init);
module_exit(ring_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luca Deri <deri@ntop.org>");
MODULE_DESCRIPTION("Packet capture acceleration and analysis");

MODULE_ALIAS_NETPROTO(PF_RING);
