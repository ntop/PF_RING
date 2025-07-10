/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "kcompat.h"

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) )
#ifdef CONFIG_PCI_IOV
int __kc_pci_vfs_assigned(struct pci_dev __maybe_unused *dev)
{
	unsigned int vfs_assigned = 0;
#ifdef HAVE_PCI_DEV_FLAGS_ASSIGNED
	int pos;
	struct pci_dev *vfdev;
	unsigned short dev_id;

	/* only search if we are a PF */
	if (!dev->is_physfn)
		return 0;

	/* find SR-IOV capability */
	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return 0;

	/*
	 * determine the device ID for the VFs, the vendor ID will be the
	 * same as the PF so there is no need to check for that one
	 */
	pci_read_config_word(dev, pos + PCI_SRIOV_VF_DID, &dev_id);

	/* loop through all the VFs to see if we own any that are assigned */
	vfdev = pci_get_device(dev->vendor, dev_id, NULL);
	while (vfdev) {
		/*
		 * It is considered assigned if it is a virtual function with
		 * our dev as the physical function and the assigned bit is set
		 */
		if (vfdev->is_virtfn && (vfdev->physfn == dev) &&
		    (vfdev->dev_flags & PCI_DEV_FLAGS_ASSIGNED))
			vfs_assigned++;

		vfdev = pci_get_device(dev->vendor, dev_id, vfdev);
	}

#endif /* HAVE_PCI_DEV_FLAGS_ASSIGNED */
	return vfs_assigned;
}

#endif /* CONFIG_PCI_IOV */
#endif /* 3.10.0 */

static const unsigned char __maybe_unused pcie_link_speed[] = {
	PCI_SPEED_UNKNOWN,      /* 0 */
	PCIE_SPEED_2_5GT,       /* 1 */
	PCIE_SPEED_5_0GT,       /* 2 */
	PCIE_SPEED_8_0GT,       /* 3 */
	PCIE_SPEED_16_0GT,      /* 4 */
	PCI_SPEED_UNKNOWN,      /* 5 */
	PCI_SPEED_UNKNOWN,      /* 6 */
	PCI_SPEED_UNKNOWN,      /* 7 */
	PCI_SPEED_UNKNOWN,      /* 8 */
	PCI_SPEED_UNKNOWN,      /* 9 */
	PCI_SPEED_UNKNOWN,      /* A */
	PCI_SPEED_UNKNOWN,      /* B */
	PCI_SPEED_UNKNOWN,      /* C */
	PCI_SPEED_UNKNOWN,      /* D */
	PCI_SPEED_UNKNOWN,      /* E */
	PCI_SPEED_UNKNOWN       /* F */
};

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0) )
int __kc_pcie_get_minimum_link(struct pci_dev *dev, enum pci_bus_speed *speed,
			       enum pcie_link_width *width)
{

	*speed = PCI_SPEED_UNKNOWN;
	*width = PCIE_LNK_WIDTH_UNKNOWN;

	while (dev) {
		u16 lnksta;
		enum pci_bus_speed next_speed;
		enum pcie_link_width next_width;
		int ret = pcie_capability_read_word(dev, PCI_EXP_LNKSTA, &lnksta);

		if (ret)
			return ret;

		next_speed = pcie_link_speed[lnksta & PCI_EXP_LNKSTA_CLS];
		next_width = (lnksta & PCI_EXP_LNKSTA_NLW) >>
			PCI_EXP_LNKSTA_NLW_SHIFT;

		if (next_speed < *speed)
			*speed = next_speed;

		if (next_width < *width)
			*width = next_width;

		dev = dev->bus->self;
	}

	return 0;
}

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
int _kc_pci_wait_for_pending_transaction(struct pci_dev *dev)
{
	int i;
	u16 status;

	/* Wait for Transaction Pending bit clean */
	for (i = 0; i < 4; i++) {
		if (i)
			msleep((1 << (i - 1)) * 100);

		pcie_capability_read_word(dev, PCI_EXP_DEVSTA, &status);
		if (!(status & PCI_EXP_DEVSTA_TRPND))
			return 1;
	}

	return 0;
}
#endif /* <RHEL6.7 */

#endif /* <3.12 */

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) )
int __kc_dma_set_mask_and_coherent(struct device *dev, u64 mask)
{
	int err = dma_set_mask(dev, mask);

	if (!err)
		/* coherent mask for the same size will always succeed if
		 * dma_set_mask does. However we store the error anyways, due
		 * to some kernels which use gcc's warn_unused_result on their
		 * definition of dma_set_coherent_mask.
		 */
		err = dma_set_coherent_mask(dev, mask);
	return err;
}

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
static bool _kc_pci_bus_read_dev_vendor_id(struct pci_bus *bus, int devfn,
					   u32 *l, int crs_timeout)
{
	int delay = 1;

	if (pci_bus_read_config_dword(bus, devfn, PCI_VENDOR_ID, l))
		return false;

	/* some broken boards return 0 or ~0 if a slot is empty: */
	if (*l == 0xffffffff || *l == 0x00000000 ||
	    *l == 0x0000ffff || *l == 0xffff0000)
		return false;

	/* Configuration request Retry Status */
	while (*l == 0xffff0001) {
		if (!crs_timeout)
			return false;

		msleep(delay);
		delay *= 2;
		if (pci_bus_read_config_dword(bus, devfn, PCI_VENDOR_ID, l))
			return false;
		/* Card hasn't responded in 60 seconds?  Must be stuck. */
		if (delay > crs_timeout) {
			printk(KERN_WARNING "pci %04x:%02x:%02x.%d: not "
			       "responding\n", pci_domain_nr(bus),
			       bus->number, PCI_SLOT(devfn),
			       PCI_FUNC(devfn));
			return false;
		}
	}

	return true;
}

bool _kc_pci_device_is_present(struct pci_dev *pdev)
{
	u32 v;

	return _kc_pci_bus_read_dev_vendor_id(pdev->bus, pdev->devfn, &v, 0);
}
#endif /* <RHEL7.0 */
#endif /* 3.13.0 */

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0) )
/******************************************************************************
 * ripped from linux/net/ipv6/exthdrs_core.c, GPL2, no direct copyright,
 * inferred copyright from kernel
 */
int __kc_ipv6_find_hdr(const struct sk_buff *skb, unsigned int *offset,
		       int target, unsigned short *fragoff, int *flags)
{
	unsigned int start = skb_network_offset(skb) + sizeof(struct ipv6hdr);
	u8 nexthdr = ipv6_hdr(skb)->nexthdr;
	bool found;

#define __KC_IP6_FH_F_FRAG	BIT(0)
#define __KC_IP6_FH_F_AUTH	BIT(1)
#define __KC_IP6_FH_F_SKIP_RH	BIT(2)

	if (fragoff)
		*fragoff = 0;

	if (*offset) {
		struct ipv6hdr _ip6, *ip6;

		ip6 = skb_header_pointer(skb, *offset, sizeof(_ip6), &_ip6);
		if (!ip6 || (ip6->version != 6)) {
			printk(KERN_ERR "IPv6 header not found\n");
			return -EBADMSG;
		}
		start = *offset + sizeof(struct ipv6hdr);
		nexthdr = ip6->nexthdr;
	}

	do {
		struct ipv6_opt_hdr _hdr, *hp;
		unsigned int hdrlen;
		found = (nexthdr == target);

		if ((!ipv6_ext_hdr(nexthdr)) || nexthdr == NEXTHDR_NONE) {
			if (target < 0 || found)
				break;
			return -ENOENT;
		}

		hp = skb_header_pointer(skb, start, sizeof(_hdr), &_hdr);
		if (!hp)
			return -EBADMSG;

		if (nexthdr == NEXTHDR_ROUTING) {
			struct ipv6_rt_hdr _rh, *rh;

			rh = skb_header_pointer(skb, start, sizeof(_rh),
						&_rh);
			if (!rh)
				return -EBADMSG;

			if (flags && (*flags & __KC_IP6_FH_F_SKIP_RH) &&
			    rh->segments_left == 0)
				found = false;
		}

		if (nexthdr == NEXTHDR_FRAGMENT) {
			unsigned short _frag_off;
			__be16 *fp;

			if (flags)	/* Indicate that this is a fragment */
				*flags |= __KC_IP6_FH_F_FRAG;
			fp = skb_header_pointer(skb,
						start+offsetof(struct frag_hdr,
							       frag_off),
						sizeof(_frag_off),
						&_frag_off);
			if (!fp)
				return -EBADMSG;

			_frag_off = ntohs(*fp) & ~0x7;
			if (_frag_off) {
				if (target < 0 &&
				    ((!ipv6_ext_hdr(hp->nexthdr)) ||
				     hp->nexthdr == NEXTHDR_NONE)) {
					if (fragoff)
						*fragoff = _frag_off;
					return hp->nexthdr;
				}
				return -ENOENT;
			}
			hdrlen = 8;
		} else if (nexthdr == NEXTHDR_AUTH) {
			if (flags && (*flags & __KC_IP6_FH_F_AUTH) && (target < 0))
				break;
			hdrlen = (hp->hdrlen + 2) << 2;
		} else
			hdrlen = ipv6_optlen(hp);

		if (!found) {
			nexthdr = hp->nexthdr;
			start += hdrlen;
		}
	} while (!found);

	*offset = start;
	return nexthdr;
}

int __kc_pci_enable_msix_range(struct pci_dev *dev, struct msix_entry *entries,
			       int minvec, int maxvec)
{
        int nvec = maxvec;
        int rc;

        if (maxvec < minvec)
                return -ERANGE;

        do {
                rc = pci_enable_msix(dev, entries, nvec);
                if (rc < 0) {
                        return rc;
                } else if (rc > 0) {
                        if (rc < minvec)
                                return -ENOSPC;
                        nvec = rc;
                }
        } while (rc);

        return nvec;
}
#endif /* 3.14.0 */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0))
char *_kc_devm_kstrdup(struct device *dev, const char *s, gfp_t gfp)
{
	size_t size;
	char *buf;

	if (!s)
		return NULL;

	size = strlen(s) + 1;
	buf = devm_kzalloc(dev, size, gfp);
	if (buf)
		memcpy(buf, s, size);
	return buf;
}

void __kc_netdev_rss_key_fill(void *buffer, size_t len)
{
	/* Set of random keys generated using kernel random number generator */
	static const u8 seed[NETDEV_RSS_KEY_LEN] = {0xE6, 0xFA, 0x35, 0x62,
				0x95, 0x12, 0x3E, 0xA3, 0xFB, 0x46, 0xC1, 0x5F,
				0xB1, 0x43, 0x82, 0x5B, 0x6A, 0x49, 0x50, 0x95,
				0xCD, 0xAB, 0xD8, 0x11, 0x8F, 0xC5, 0xBD, 0xBC,
				0x6A, 0x4A, 0xB2, 0xD4, 0x1F, 0xFE, 0xBC, 0x41,
				0xBF, 0xAC, 0xB2, 0x9A, 0x8F, 0x70, 0xE9, 0x2A,
				0xD7, 0xB2, 0x80, 0xB6, 0x5B, 0xAA, 0x9D, 0x20};

	BUG_ON(len > NETDEV_RSS_KEY_LEN);
	memcpy(buffer, seed, len);
}
#endif /* 3.15.0 */

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) )
#ifdef HAVE_SET_RX_MODE
#ifdef NETDEV_HW_ADDR_T_UNICAST
int __kc_hw_addr_sync_dev(struct netdev_hw_addr_list *list,
		struct net_device *dev,
		int (*sync)(struct net_device *, const unsigned char *),
		int (*unsync)(struct net_device *, const unsigned char *))
{
	struct netdev_hw_addr *ha, *tmp;
	int err;

	/* first go through and flush out any stale entries */
	list_for_each_entry_safe(ha, tmp, &list->list, list) {
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) )
		if (!ha->synced || ha->refcount != 1)
#else
		if (!ha->sync_cnt || ha->refcount != 1)
#endif
			continue;

		if (unsync && unsync(dev, ha->addr))
			continue;

		list_del_rcu(&ha->list);
		kfree_rcu(ha, rcu_head);
		list->count--;
	}

	/* go through and sync new entries to the list */
	list_for_each_entry_safe(ha, tmp, &list->list, list) {
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) )
		if (ha->synced)
#else
		if (ha->sync_cnt)
#endif
			continue;

		err = sync(dev, ha->addr);
		if (err)
			return err;
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) )
		ha->synced = true;
#else
		ha->sync_cnt++;
#endif
		ha->refcount++;
	}

	return 0;
}

void __kc_hw_addr_unsync_dev(struct netdev_hw_addr_list *list,
		struct net_device *dev,
		int (*unsync)(struct net_device *, const unsigned char *))
{
	struct netdev_hw_addr *ha, *tmp;

	list_for_each_entry_safe(ha, tmp, &list->list, list) {
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) )
		if (!ha->synced)
#else
		if (!ha->sync_cnt)
#endif
			continue;

		if (unsync && unsync(dev, ha->addr))
			continue;

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) )
		ha->synced = false;
#else
		ha->sync_cnt--;
#endif
		if (--ha->refcount)
			continue;

		list_del_rcu(&ha->list);
		kfree_rcu(ha, rcu_head);
		list->count--;
	}
}

#endif /* NETDEV_HW_ADDR_T_UNICAST  */
#ifndef NETDEV_HW_ADDR_T_MULTICAST
int __kc_dev_addr_sync_dev(struct dev_addr_list **list, int *count,
		struct net_device *dev,
		int (*sync)(struct net_device *, const unsigned char *),
		int (*unsync)(struct net_device *, const unsigned char *))
{
	struct dev_addr_list *da, **next = list;
	int err;

	/* first go through and flush out any stale entries */
	while ((da = *next) != NULL) {
		if (da->da_synced && da->da_users == 1) {
			if (!unsync || !unsync(dev, da->da_addr)) {
				*next = da->next;
				kfree(da);
				(*count)--;
				continue;
			}
		}
		next = &da->next;
	}

	/* go through and sync new entries to the list */
	for (da = *list; da != NULL; da = da->next) {
		if (da->da_synced)
			continue;

		err = sync(dev, da->da_addr);
		if (err)
			return err;

		da->da_synced++;
		da->da_users++;
	}

	return 0;
}

void __kc_dev_addr_unsync_dev(struct dev_addr_list **list, int *count,
		struct net_device *dev,
		int (*unsync)(struct net_device *, const unsigned char *))
{
	struct dev_addr_list *da;

	while ((da = *list) != NULL) {
		if (da->da_synced) {
			if (!unsync || !unsync(dev, da->da_addr)) {
				da->da_synced--;
				if (--da->da_users == 0) {
					*list = da->next;
					kfree(da);
					(*count)--;
					continue;
				}
			}
		}
		list = &da->next;
	}
}
#endif /* NETDEV_HW_ADDR_T_MULTICAST  */
#endif /* HAVE_SET_RX_MODE */
void *__kc_devm_kmemdup(struct device *dev, const void *src, size_t len,
			gfp_t gfp)
{
	void *p;

	p = devm_kzalloc(dev, len, gfp);
	if (p)
		memcpy(p, src, len);

	return p;
}
#endif /* 3.16.0 */

/******************************************************************************/
#if ((LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)) && \
     (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5)))
int _kc_param_set_ullong(const char *val, const struct kernel_param *kp)
{
	return kstrtoull(val, 0, (unsigned long long *)kp->arg);
}
int _kc_param_get_ullong(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%llu",
			 *((unsigned long long *)kp->arg));
}
const struct kernel_param_ops _kc_param_ops_ullong = {
	.set = _kc_param_set_ullong,
	.get = _kc_param_get_ullong,
};
#endif /* <3.17.0 && RHEL_RELEASE_CODE < RHEL7.5 */

/******************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0) )
static void __kc_sock_efree(struct sk_buff *skb)
{
	sock_put(skb->sk);
}

struct sk_buff *__kc_skb_clone_sk(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct sk_buff *clone;

	if (!sk || !atomic_inc_not_zero(&sk->sk_refcnt))
		return NULL;

	clone = skb_clone(skb, GFP_ATOMIC);
	if (!clone) {
		sock_put(sk);
		return NULL;
	}

	clone->sk = sk;
	clone->destructor = __kc_sock_efree;

	return clone;
}

void __kc_skb_complete_tx_timestamp(struct sk_buff *skb,
				    struct skb_shared_hwtstamps *hwtstamps)
{
	struct sock_exterr_skb *serr;
	struct sock *sk = skb->sk;
	int err;

	sock_hold(sk);

	*skb_hwtstamps(skb) = *hwtstamps;

	serr = SKB_EXT_ERR(skb);
	memset(serr, 0, sizeof(*serr));
	serr->ee.ee_errno = ENOMSG;
	serr->ee.ee_origin = SO_EE_ORIGIN_TIMESTAMPING;

	err = sock_queue_err_skb(sk, skb);
	if (err)
		kfree_skb(skb);

	sock_put(sk);
}
#endif /* < 3.18.0 */

/******************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0) )
#ifdef HAVE_NET_GET_RANDOM_ONCE
static u8 __kc_netdev_rss_key[NETDEV_RSS_KEY_LEN];

void __kc_netdev_rss_key_fill(void *buffer, size_t len)
{
	BUG_ON(len > sizeof(__kc_netdev_rss_key));
	net_get_random_once(__kc_netdev_rss_key, sizeof(__kc_netdev_rss_key));
	memcpy(buffer, __kc_netdev_rss_key, len);
}
#endif

int _kc_bitmap_print_to_pagebuf(bool list, char *buf,
				const unsigned long *maskp,
				int nmaskbits)
{
	ptrdiff_t len = PTR_ALIGN(buf + PAGE_SIZE - 1, PAGE_SIZE) - buf - 2;
	int n = 0;

	if (len > 1) {
		n = list ? bitmap_scnlistprintf(buf, len, maskp, nmaskbits) :
			   bitmap_scnprintf(buf, len, maskp, nmaskbits);
		buf[n++] = '\n';
		buf[n] = '\0';
	}
	return n;
}
#endif

/******************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0) )
#if !((RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,8) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)) && \
      (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2)) && \
      (SLE_VERSION_CODE > SLE_VERSION(12,1,0)))
unsigned int _kc_cpumask_local_spread(unsigned int i, int node)
{
	int cpu;

	/* Wrap: we always want a cpu. */
	i %= num_online_cpus();

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28) )
	/* Kernels prior to 2.6.28 do not have for_each_cpu or
	 * cpumask_of_node, so just use for_each_online_cpu()
	 */
	for_each_online_cpu(cpu)
		if (i-- == 0)
			return cpu;

	return 0;
#else
	if (node == -1) {
		for_each_cpu(cpu, cpu_online_mask)
			if (i-- == 0)
				return cpu;
	} else {
		/* NUMA first. */
		for_each_cpu_and(cpu, cpumask_of_node(node), cpu_online_mask)
			if (i-- == 0)
				return cpu;

		for_each_cpu(cpu, cpu_online_mask) {
			/* Skip NUMA nodes, done above. */
			if (cpumask_test_cpu(cpu, cpumask_of_node(node)))
				continue;

			if (i-- == 0)
				return cpu;
		}
	}
#endif /* KERNEL_VERSION >= 2.6.28 */
	BUG();
}
#endif
#endif

/******************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0))
#if (!(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4)) && \
     !(SLE_VERSION_CODE >= SLE_VERSION(12,2,0)))
/**
 * _kc_skb_flow_dissect_flow_keys - parse SKB to fill _kc_flow_keys
 * @skb: SKB used to fille _kc_flow_keys
 * @flow: _kc_flow_keys to set with SKB fields
 * @flags: currently unused flags
 *
 * The purpose of using kcompat for this function is so the caller doesn't have
 * to care about which kernel version they are on, which prevents a larger than
 * normal #ifdef mess created by using a HAVE_* flag for this case. This is also
 * done for 4.2 kernels to simplify calling skb_flow_dissect_flow_keys()
 * because in 4.2 kernels skb_flow_dissect_flow_keys() exists, but only has 2
 * arguments. Recent kernels have skb_flow_dissect_flow_keys() that has 3
 * arguments.
 *
 * The caller needs to understand that this function was only implemented as a
 * bare-minimum replacement for recent versions of skb_flow_dissect_flow_keys()
 * and this function is in no way similar to skb_flow_dissect_flow_keys(). An
 * example use can be found in the ice driver, specifically ice_arfs.c.
 *
 * This function is treated as a allowlist of supported fields the SKB can
 * parse. If new functionality is added make sure to keep this format (i.e. only
 * check for fields that are explicity wanted).
 *
 * Current allowlist:
 *
 * TCPv4, TCPv6, UDPv4, UDPv6
 *
 * If any unexpected protocol or other field is found this function memsets the
 * flow passed in back to 0 and returns false. Otherwise the flow is populated
 * and returns true.
 */
bool
_kc_skb_flow_dissect_flow_keys(const struct sk_buff *skb,
			       struct _kc_flow_keys *flow,
			       unsigned int __always_unused flags)
{
	memset(flow, 0, sizeof(*flow));

	flow->basic.n_proto = skb->protocol;
	switch (flow->basic.n_proto) {
	case htons(ETH_P_IP):
		flow->basic.ip_proto = ip_hdr(skb)->protocol;
		flow->addrs.v4addrs.src = ip_hdr(skb)->saddr;
		flow->addrs.v4addrs.dst = ip_hdr(skb)->daddr;
		break;
	case htons(ETH_P_IPV6):
		flow->basic.ip_proto = ipv6_hdr(skb)->nexthdr;
		memcpy(&flow->addrs.v6addrs.src, &ipv6_hdr(skb)->saddr,
		       sizeof(struct in6_addr));
		memcpy(&flow->addrs.v6addrs.dst, &ipv6_hdr(skb)->daddr,
		       sizeof(struct in6_addr));
		break;
	default:
		netdev_dbg(skb->dev, "%s: Unsupported/unimplemented layer 3 protocol %04x\n", __func__, htons(flow->basic.n_proto));
		goto unsupported;
	}

	switch (flow->basic.ip_proto) {
	case IPPROTO_TCP:
	{
		struct tcphdr *tcph;

		tcph = tcp_hdr(skb);
		flow->ports.src = tcph->source;
		flow->ports.dst = tcph->dest;
		break;
	}
	case IPPROTO_UDP:
	{
		struct udphdr *udph;

		udph = udp_hdr(skb);
		flow->ports.src = udph->source;
		flow->ports.dst = udph->dest;
		break;
	}
	default:
		netdev_dbg(skb->dev, "%s: Unsupported/unimplemented layer 4 protocol %02x\n", __func__, flow->basic.ip_proto);
		return false;
	}

	return true;

unsupported:
	memset(flow, 0, sizeof(*flow));
	return false;
}
#endif /* ! >= RHEL7.4 && ! >= SLES12.2 */
#endif /* 4.3.0 */

/******************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0) )
#if (!(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3)))
#ifdef CONFIG_SPARC
#include <asm/idprom.h>
#include <asm/prom.h>
#endif
int _kc_eth_platform_get_mac_address(struct device *dev __maybe_unused,
				     u8 *mac_addr __maybe_unused)
{
#if (((LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)) && defined(CONFIG_OF) && \
      !defined(HAVE_STRUCT_DEVICE_OF_NODE) || !defined(CONFIG_OF)) && \
     !defined(CONFIG_SPARC))
	return -ENODEV;
#else
	const unsigned char *addr;
	struct device_node *dp;

	if (dev_is_pci(dev))
		dp = pci_device_to_OF_node(to_pci_dev(dev));
	else
#if defined(HAVE_STRUCT_DEVICE_OF_NODE) && defined(CONFIG_OF)
		dp = dev->of_node;
#else
		dp = NULL;
#endif

	addr = NULL;
	if (dp)
		addr = of_get_mac_address(dp);
#ifdef CONFIG_SPARC
	/* Kernel hasn't implemented arch_get_platform_mac_address, but we
	 * should handle the SPARC case here since it was supported
	 * originally. This is replaced by arch_get_platform_mac_address()
	 * upstream.
	 */
	if (!addr)
		addr = idprom->id_ethaddr;
#endif
	if (!addr)
		return -ENODEV;

	ether_addr_copy(mac_addr, addr);
	return 0;
#endif
}
#endif /* !(RHEL_RELEASE >= 7.3) */
#endif /* < 4.5.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0))
int _kc_kstrtobool(const char *s, bool *res)
{
	if (!s)
		return -EINVAL;

	switch (s[0]) {
	case 'y':
	case 'Y':
	case '1':
		*res = true;
		return 0;
	case 'n':
	case 'N':
	case '0':
		*res = false;
		return 0;
	case 'o':
	case 'O':
		switch (s[1]) {
		case 'n':
		case 'N':
			*res = true;
			return 0;
		case 'f':
		case 'F':
			*res = false;
			return 0;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return -EINVAL;
}
#endif /* < 4.6.0 */

/*****************************************************************************/
#if ((LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)) || \
     (SLE_VERSION_CODE && (SLE_VERSION_CODE <= SLE_VERSION(12,3,0))) || \
     (RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7,5))))
const char *_kc_phy_speed_to_str(int speed)
{
	switch (speed) {
	case SPEED_10:
		return "10Mbps";
	case SPEED_100:
		return "100Mbps";
	case SPEED_1000:
		return "1Gbps";
	case SPEED_2500:
		return "2.5Gbps";
	case SPEED_5000:
		return "5Gbps";
	case SPEED_10000:
		return "10Gbps";
	case SPEED_14000:
		return "14Gbps";
	case SPEED_20000:
		return "20Gbps";
	case SPEED_25000:
		return "25Gbps";
	case SPEED_40000:
		return "40Gbps";
	case SPEED_50000:
		return "50Gbps";
	case SPEED_56000:
		return "56Gbps";
#ifdef SPEED_100000
	case SPEED_100000:
		return "100Gbps";
#endif
#ifdef SPEED_200000
	case SPEED_200000:
		return "200Gbps";
#endif
	case SPEED_UNKNOWN:
		return "Unknown";
	default:
		return "Unsupported (update phy-core.c)";
	}
}
#endif /* (LINUX < 4.14.0) || (SLES <= 12.3.0) || (RHEL <= 7.5) */

/******************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0) )
void _kc_ethtool_intersect_link_masks(struct ethtool_link_ksettings *dst,
				      struct ethtool_link_ksettings *src)
{
	unsigned int size = BITS_TO_LONGS(__ETHTOOL_LINK_MODE_MASK_NBITS);
	unsigned int idx = 0;

	for (; idx < size; idx++) {
		dst->link_modes.supported[idx] &=
			src->link_modes.supported[idx];
		dst->link_modes.advertising[idx] &=
			src->link_modes.advertising[idx];
	}
}
#endif /* 4.15.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0))
/* PCIe link information */
#define PCIE_SPEED2STR(speed) \
	((speed) == PCIE_SPEED_16_0GT ? "16 GT/s" : \
	 (speed) == PCIE_SPEED_8_0GT ? "8 GT/s" : \
	 (speed) == PCIE_SPEED_5_0GT ? "5 GT/s" : \
	 (speed) == PCIE_SPEED_2_5GT ? "2.5 GT/s" : \
	 "Unknown speed")

/* PCIe speed to Mb/s reduced by encoding overhead */
#define PCIE_SPEED2MBS_ENC(speed) \
	((speed) == PCIE_SPEED_16_0GT ? 16000*128/130 : \
	 (speed) == PCIE_SPEED_8_0GT  ?  8000*128/130 : \
	 (speed) == PCIE_SPEED_5_0GT  ?  5000*8/10 : \
	 (speed) == PCIE_SPEED_2_5GT  ?  2500*8/10 : \
	 0)

static u32
_kc_pcie_bandwidth_available(struct pci_dev *dev,
			     struct pci_dev **limiting_dev,
			     enum pci_bus_speed *speed,
			     enum pcie_link_width *width)
{
	u16 lnksta;
	enum pci_bus_speed next_speed;
	enum pcie_link_width next_width;
	u32 bw, next_bw;

	if (speed)
		*speed = PCI_SPEED_UNKNOWN;
	if (width)
		*width = PCIE_LNK_WIDTH_UNKNOWN;

	bw = 0;

	while (dev) {
		pcie_capability_read_word(dev, PCI_EXP_LNKSTA, &lnksta);

		next_speed = pcie_link_speed[lnksta & PCI_EXP_LNKSTA_CLS];
		next_width = (lnksta & PCI_EXP_LNKSTA_NLW) >>
			PCI_EXP_LNKSTA_NLW_SHIFT;

		next_bw = next_width * PCIE_SPEED2MBS_ENC(next_speed);

		/* Check if current device limits the total bandwidth */
		if (!bw || next_bw <= bw) {
			bw = next_bw;

			if (limiting_dev)
				*limiting_dev = dev;
			if (speed)
				*speed = next_speed;
			if (width)
				*width = next_width;
		}

		dev = pci_upstream_bridge(dev);
	}

	return bw;
}

static enum pci_bus_speed _kc_pcie_get_speed_cap(struct pci_dev *dev)
{
	u32 lnkcap2, lnkcap;

	/*
	 * PCIe r4.0 sec 7.5.3.18 recommends using the Supported Link
	 * Speeds Vector in Link Capabilities 2 when supported, falling
	 * back to Max Link Speed in Link Capabilities otherwise.
	 */
	pcie_capability_read_dword(dev, PCI_EXP_LNKCAP2, &lnkcap2);
	if (lnkcap2) { /* PCIe r3.0-compliant */
		if (lnkcap2 & PCI_EXP_LNKCAP2_SLS_16_0GB)
			return PCIE_SPEED_16_0GT;
		else if (lnkcap2 & PCI_EXP_LNKCAP2_SLS_8_0GB)
			return PCIE_SPEED_8_0GT;
		else if (lnkcap2 & PCI_EXP_LNKCAP2_SLS_5_0GB)
			return PCIE_SPEED_5_0GT;
		else if (lnkcap2 & PCI_EXP_LNKCAP2_SLS_2_5GB)
			return PCIE_SPEED_2_5GT;
		return PCI_SPEED_UNKNOWN;
	}

	pcie_capability_read_dword(dev, PCI_EXP_LNKCAP, &lnkcap);
	if (lnkcap) {
		if (lnkcap & PCI_EXP_LNKCAP_SLS_16_0GB)
			return PCIE_SPEED_16_0GT;
		else if (lnkcap & PCI_EXP_LNKCAP_SLS_8_0GB)
			return PCIE_SPEED_8_0GT;
		else if (lnkcap & PCI_EXP_LNKCAP_SLS_5_0GB)
			return PCIE_SPEED_5_0GT;
		else if (lnkcap & PCI_EXP_LNKCAP_SLS_2_5GB)
			return PCIE_SPEED_2_5GT;
	}

	return PCI_SPEED_UNKNOWN;
}

static enum pcie_link_width _kc_pcie_get_width_cap(struct pci_dev *dev)
{
	u32 lnkcap;

	pcie_capability_read_dword(dev, PCI_EXP_LNKCAP, &lnkcap);
	if (lnkcap)
		return (lnkcap & PCI_EXP_LNKCAP_MLW) >> 4;

	return PCIE_LNK_WIDTH_UNKNOWN;
}

static u32
_kc_pcie_bandwidth_capable(struct pci_dev *dev, enum pci_bus_speed *speed,
			   enum pcie_link_width *width)
{
	*speed = _kc_pcie_get_speed_cap(dev);
	*width = _kc_pcie_get_width_cap(dev);

	if (*speed == PCI_SPEED_UNKNOWN || *width == PCIE_LNK_WIDTH_UNKNOWN)
		return 0;

	return *width * PCIE_SPEED2MBS_ENC(*speed);
}

void _kc_pcie_print_link_status(struct pci_dev *dev) {
	enum pcie_link_width width, width_cap;
	enum pci_bus_speed speed, speed_cap;
	struct pci_dev *limiting_dev = NULL;
	u32 bw_avail, bw_cap;

	bw_cap = _kc_pcie_bandwidth_capable(dev, &speed_cap, &width_cap);
	bw_avail = _kc_pcie_bandwidth_available(dev, &limiting_dev, &speed,
						&width);

	if (bw_avail >= bw_cap)
		pci_info(dev, "%u.%03u Gb/s available PCIe bandwidth (%s x%d link)\n",
			 bw_cap / 1000, bw_cap % 1000,
			 PCIE_SPEED2STR(speed_cap), width_cap);
	else
		pci_info(dev, "%u.%03u Gb/s available PCIe bandwidth, limited by %s x%d link at %s (capable of %u.%03u Gb/s with %s x%d link)\n",
			 bw_avail / 1000, bw_avail % 1000,
			 PCIE_SPEED2STR(speed), width,
			 limiting_dev ? pci_name(limiting_dev) : "<unknown>",
			 bw_cap / 1000, bw_cap % 1000,
			 PCIE_SPEED2STR(speed_cap), width_cap);
}
#endif /* 4.17.0 */

#ifdef NEED_FLOW_BLOCK_CB_SETUP_SIMPLE
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
int _kc_flow_block_cb_setup_simple(struct flow_block_offload *f,
				   struct list_head __always_unused *driver_list,
				   tc_setup_cb_t *cb,
				   void *cb_ident, void *cb_priv,
				   bool ingress_only)
{
	if (ingress_only &&
	    f->binder_type != TCF_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	/* Note: Upstream has driver_block_list, but older kernels do not */
	switch (f->command) {
	case TC_BLOCK_BIND:
#ifdef HAVE_TCF_BLOCK_CB_REGISTER_EXTACK
		return tcf_block_cb_register(f->block, cb, cb_ident, cb_priv,
					     f->extack);
#else
		return tcf_block_cb_register(f->block, cb, cb_ident, cb_priv);
#endif
	case TC_BLOCK_UNBIND:
		tcf_block_cb_unregister(f->block, cb, cb_ident);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
#endif /* NEED_FLOW_BLOCK_CB_SETUP_SIMPLE */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0))
u64 _kc_pci_get_dsn(struct pci_dev *dev)
{
	u32 dword;
	u64 dsn;
	int pos;

	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_DSN);
	if (!pos)
		return 0;

	/*
	 * The Device Serial Number is two dwords offset 4 bytes from the
	 * capability position. The specification says that the first dword is
	 * the lower half, and the second dword is the upper half.
	 */
	pos += 4;
	pci_read_config_dword(dev, pos, &dword);
	dsn = (u64)dword;
	pci_read_config_dword(dev, pos + 4, &dword);
	dsn |= ((u64)dword) << 32;

	return dsn;
}
#endif /* 5.7.0 */

#ifdef NEED_DEVM_KVASPRINTF
char *devm_kvasprintf(struct device *dev, gfp_t gfp, const char *fmt,
		      va_list ap)
{
	unsigned int len;
	char *p;
	va_list aq;

	va_copy(aq, ap);
	len = vsnprintf(NULL, 0, fmt, aq);
	va_end(aq);

	p = devm_kmalloc(dev, len + 1, gfp);
	if (!p)
		return NULL;

	vsnprintf(p, len + 1, fmt, ap);

	return p;
}
#endif /* NEED_DEVM_KVASPRINTF */

#ifdef NEED_DEVM_KASPRINTF
char *devm_kasprintf(struct device *dev, gfp_t gfp, const char *fmt, ...)
{
	va_list ap;
	char *p;

	va_start(ap, fmt);
	p = devm_kvasprintf(dev, gfp, fmt, ap);
	va_end(ap);

	return p;
}
#endif /* NEED_DEVM_KASPRINTF */

#ifdef NEED_PCI_IOV_VF_ID
#ifdef CONFIG_PCI_IOV
/*
 * Below function needs to access pci_sriov offset and stride. Since
 * pci_sriov structure is defined in drivers/pci/pci.h which can not
 * be included as linux kernel header file, the structure definition
 * is not globally visible.
 * As a result, one copy of structure definition is added. Since the
 * definition is a copy, you need to make sure the kernel you want
 * to backport must have exactly the same pci_sriov definition as the
 * copy, otherwise you'll access wrong field offset and value.
 */

/* Single Root I/O Virtualization */
struct pci_sriov {
	int             pos;            /* Capability position */
	int             nres;           /* Number of resources */
	u32             cap;            /* SR-IOV Capabilities */
	u16             ctrl;           /* SR-IOV Control */
	u16             total_VFs;      /* Total VFs associated with the PF */
	u16             initial_VFs;    /* Initial VFs associated with the PF */
	u16             num_VFs;        /* Number of VFs available */
	u16             offset;         /* First VF Routing ID offset */
	u16             stride;         /* Following VF stride */
	u16             vf_device;      /* VF device ID */
	u32             pgsz;           /* Page size for BAR alignment */
	u8              link;           /* Function Dependency Link */
	u8              max_VF_buses;   /* Max buses consumed by VFs */
	u16             driver_max_VFs; /* Max num VFs driver supports */
	struct pci_dev  *dev;           /* Lowest numbered PF */
	struct pci_dev  *self;          /* This PF */
	u32             cfg_size;       /* VF config space size */
	u32             class;          /* VF device */
	u8              hdr_type;       /* VF header type */
	u16             subsystem_vendor; /* VF subsystem vendor */
	u16             subsystem_device; /* VF subsystem device */
	resource_size_t barsz[PCI_SRIOV_NUM_BARS];      /* VF BAR size */
	bool            drivers_autoprobe; /* Auto probing of VFs by driver */
};

int _kc_pci_iov_vf_id(struct pci_dev *dev)
{
	struct pci_dev *pf;

	if (!dev->is_virtfn)
		return -EINVAL;

	pf = pci_physfn(dev);
	return (((dev->bus->number << 8) + dev->devfn) -
		((pf->bus->number << 8) + pf->devfn + pf->sriov->offset)) /
	       pf->sriov->stride;
}
#endif /* CONFIG_PCI_IOV */
#endif /* NEED_PCI_IOV_VF_ID */

#ifdef NEED_MUL_U64_U64_DIV_U64
u64 mul_u64_u64_div_u64(u64 a, u64 b, u64 c)
{
	u64 res = 0, div, rem;
	int shift;

	/* can a * b overflow ? */
	if (ilog2(a) + ilog2(b) > 62) {
		/*
		 * (b * a) / c is equal to
		 *
		 *      (b / c) * a +
		 *      (b % c) * a / c
		 *
		 * if nothing overflows. Can the 1st multiplication
		 * overflow? Yes, but we do not care: this can only
		 * happen if the end result can't fit in u64 anyway.
		 *
		 * So the code below does
		 *
		 *      res = (b / c) * a;
		 *      b = b % c;
		 */
		div = div64_u64_rem(b, c, &rem);
		res = div * a;
		b = rem;

		shift = ilog2(a) + ilog2(b) - 62;
		if (shift > 0) {
			/* drop precision */
			b >>= shift;
			c >>= shift;
			if (!c)
				return res;
		}
	}

	return res + div64_u64(a * b, c);
}
#endif /* NEED_MUL_U64_U64_DIV_U64 */

#ifdef NEED_ETHTOOL_SPRINTF
void ethtool_sprintf(u8 **data, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(*data, ETH_GSTRING_LEN, fmt, args);
	va_end(args);

	*data += ETH_GSTRING_LEN;
}
#endif /* NEED_ETHTOOL_SPRINTF */

#ifdef NEED_SYSFS_EMIT
int sysfs_emit(char *buf, const char *fmt, ...)
{
	va_list args;
	int len;

	if (WARN(!buf || offset_in_page(buf),
		 "invalid %s: buf:%p\n", __func__, buf))
		return 0;

	va_start(args, fmt);
	len = vscnprintf(buf, PAGE_SIZE, fmt, args);
	va_end(args);

	return len;
}
#endif /* NEED_SYSFS_EMIT */

#ifndef HAVE_ETHTOOL_KEEE
void ethtool_convert_legacy_u32_to_link_mode(unsigned long *dst,
					     u32 legacy_u32)
{
	bitmap_zero(dst, __ETHTOOL_LINK_MODE_MASK_NBITS);
	dst[0] = legacy_u32;
}

bool ethtool_convert_link_mode_to_legacy_u32(u32 *legacy_u32,
					     const unsigned long *src)
{
	*legacy_u32 = src[0];
	return find_next_bit(src, __ETHTOOL_LINK_MODE_MASK_NBITS, 32) ==
		__ETHTOOL_LINK_MODE_MASK_NBITS;
}

void eee_to_keee(struct ethtool_keee *keee,
		 const struct ethtool_eee *eee)
{
	memset(keee, 0, sizeof(*keee));

	keee->eee_enabled = eee->eee_enabled;
	keee->tx_lpi_enabled = eee->tx_lpi_enabled;
	keee->tx_lpi_timer = eee->tx_lpi_timer;

	ethtool_convert_legacy_u32_to_link_mode(keee->supported,
						eee->supported);
	ethtool_convert_legacy_u32_to_link_mode(keee->advertised,
						eee->advertised);
	ethtool_convert_legacy_u32_to_link_mode(keee->lp_advertised,
						eee->lp_advertised);
}

bool ethtool_eee_use_linkmodes(const struct ethtool_keee *eee)
{
#if (RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8,0)))
	return !linkmode_empty(eee->supported);
#else
	return false;
#endif /* RH7.9 */
}

void keee_to_eee(struct ethtool_eee *eee,
		 const struct ethtool_keee *keee)
{
	bool overflow;

	memset(eee, 0, sizeof(*eee));

	eee->eee_active = keee->eee_active;
	eee->eee_enabled = keee->eee_enabled;
	eee->tx_lpi_enabled = keee->tx_lpi_enabled;
	eee->tx_lpi_timer = keee->tx_lpi_timer;

	overflow = !ethtool_convert_link_mode_to_legacy_u32(&eee->supported,
							    keee->supported);
	ethtool_convert_link_mode_to_legacy_u32(&eee->advertised,
						keee->advertised);
	ethtool_convert_link_mode_to_legacy_u32(&eee->lp_advertised,
						keee->lp_advertised);
	if (overflow)
		pr_warn("Ethtool ioctl interface doesn't support passing EEE linkmodes beyond bit 32\n");
}
#endif /* !HAVE_ETHTOOL_KEEE */

#ifdef NEED_PCI_DISABLE_PTM
#if defined(HAVE_STRUCT_PCI_DEV_PTM_ENABLED) && defined(CONFIG_PCIE_PTM)
static void __pci_disable_ptm(struct pci_dev *dev)
{
#if defined(HAVE_STRUCT_PCI_DEV_PTM_CAP)
	u16 ptm = dev->ptm_cap;
	u32 ctrl;

	if (!ptm)
		return;

	pci_read_config_dword(dev, ptm + PCI_PTM_CTRL, &ctrl);
	ctrl &= ~(PCI_PTM_CTRL_ENABLE | PCI_PTM_CTRL_ROOT);
	pci_write_config_dword(dev, ptm + PCI_PTM_CTRL, ctrl);
#else
	return;
#endif /* HAVE_STRUCT_PCI_DEV_PTM_CAP */
}
#endif /* HAVE_STRUCT_PCI_DEV_PTM_ENABLED && CONFIG_PCIE_PTM */

/**
 * pci_disable_ptm() - Disable Precision Time Measurement
 * @dev: PCI device
 *
 * Disable Precision Time Measurement for @dev.
 */
void pci_disable_ptm(struct pci_dev *dev)
{
#if defined(HAVE_STRUCT_PCI_DEV_PTM_ENABLED) && defined(CONFIG_PCIE_PTM)
	if (dev->ptm_enabled) {
		__pci_disable_ptm(dev);
		dev->ptm_enabled = 0;
	}
#else
	return;
#endif /* HAVE_STRUCT_PCI_DEV_PTM_ENABLED && CONFIG_PCIE_PTM */
}
#endif /* NEED_PCI_DISABLE_PTM */
