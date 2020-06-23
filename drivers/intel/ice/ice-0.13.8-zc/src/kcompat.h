/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/if_link.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/mii.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/vmalloc.h>

#ifdef HAVE_PF_RING

#define PCI_DEVICE_CACHE_LINE_SIZE		0x0C
#define PCI_DEVICE_CACHE_LINE_SIZE_BYTES	8
#define ICE_MAX_NIC				64

#ifdef HAVE_XDP_SUPPORT
#undef HAVE_XDP_SUPPORT
#endif

#ifdef CONFIG_DCB
#undef CONFIG_DCB
#endif

#ifdef CONFIG_FCOE
#undef CONFIG_FCOE
#endif

#ifdef CONFIG_FCOE_MODULE
#undef CONFIG_FCOE_MODULE
#endif

#ifdef ADQ_PERF
#undef ADQ_PERF
#endif

#ifdef ADQ_PERF_COUNTERS
#undef ADQ_PERF_COUNTERS
#endif

#endif

#ifndef GCC_VERSION
#define GCC_VERSION (__GNUC__ * 10000		\
		     + __GNUC_MINOR__ * 100	\
		     + __GNUC_PATCHLEVEL__)
#endif /* GCC_VERSION */

/* Backport macros for controlling GCC diagnostics */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0) )

/* Compilers before gcc-4.6 do not understand "#pragma GCC diagnostic push" */
#if GCC_VERSION >= 40600
#define __diag_str1(s)		#s
#define __diag_str(s)		__diag_str1(s)
#define __diag(s)		_Pragma(__diag_str(GCC diagnostic s))
#else
#define __diag(s)
#endif /* GCC_VERSION >= 4.6 */
#define __diag_push()	__diag(push)
#define __diag_pop()	__diag(pop)
#endif /* LINUX_VERSION < 4.18.0 */

#ifndef NSEC_PER_MSEC
#define NSEC_PER_MSEC 1000000L
#endif
#include <net/ipv6.h>
/* UTS_RELEASE is in a different header starting in kernel 2.6.18 */
#ifndef UTS_RELEASE
/* utsrelease.h changed locations in 2.6.33 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33) )
#include <linux/utsrelease.h>
#else
#include <generated/utsrelease.h>
#endif
#endif


#define adapter_struct ice_pf
#define adapter_q_vector ice_q_vector


/* Dynamic LTR and deeper C-State support disable/enable */

/* packet split disable/enable */
#ifdef DISABLE_PACKET_SPLIT
#endif /* DISABLE_PACKET_SPLIT */

/* MSI compatibility code for all kernels and drivers */
#ifdef DISABLE_PCI_MSI
#undef CONFIG_PCI_MSI
#endif
#ifndef CONFIG_PCI_MSI
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8) )
struct msix_entry {
	u16 vector; /* kernel uses to write allocated vector */
	u16 entry;  /* driver uses to specify entry, OS writes */
};
#endif
#undef pci_enable_msi
#define pci_enable_msi(a) -ENOTSUPP
#undef pci_disable_msi
#define pci_disable_msi(a) do {} while (0)
#undef pci_enable_msix
#define pci_enable_msix(a, b, c) -ENOTSUPP
#undef pci_disable_msix
#define pci_disable_msix(a) do {} while (0)
#define msi_remove_pci_irq_vectors(a) do {} while (0)
#endif /* CONFIG_PCI_MSI */
#ifdef DISABLE_PM
#undef CONFIG_PM
#endif

#ifdef DISABLE_NET_POLL_CONTROLLER
#undef CONFIG_NET_POLL_CONTROLLER
#endif

#ifndef PMSG_SUSPEND
#define PMSG_SUSPEND 3
#endif

/* generic boolean compatibility */
#undef TRUE
#undef FALSE
#define TRUE true
#define FALSE false
#ifdef GCC_VERSION
#if ( GCC_VERSION < 3000 )
#define _Bool char
#endif
#else
#define _Bool char
#endif


#undef __always_unused
#define __always_unused __attribute__((__unused__))

#undef __maybe_unused
#define __maybe_unused __attribute__((__unused__))

/* kernels less than 2.4.14 don't have this */
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef module_param
#define module_param(v,t,p) MODULE_PARM(v, "i");
#endif

#ifndef DMA_64BIT_MASK
#define DMA_64BIT_MASK  0xffffffffffffffffULL
#endif

#ifndef DMA_32BIT_MASK
#define DMA_32BIT_MASK  0x00000000ffffffffULL
#endif

#ifndef PCI_CAP_ID_EXP
#define PCI_CAP_ID_EXP 0x10
#endif

#ifndef uninitialized_var
#define uninitialized_var(x) x = x
#endif

#ifndef PCIE_LINK_STATE_L0S
#define PCIE_LINK_STATE_L0S 1
#endif
#ifndef PCIE_LINK_STATE_L1
#define PCIE_LINK_STATE_L1 2
#endif

#ifndef SET_NETDEV_DEV
#define SET_NETDEV_DEV(net, pdev)
#endif

#if !defined(HAVE_FREE_NETDEV) && ( LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0) )
#define free_netdev(x)	kfree(x)
#endif

#ifdef HAVE_POLL_CONTROLLER
#define CONFIG_NET_POLL_CONTROLLER
#endif

#ifndef SKB_DATAREF_SHIFT
/* if we do not have the infrastructure to detect if skb_header is cloned
   just return false in all cases */
#define skb_header_cloned(x) 0
#endif

#ifndef NETIF_F_GSO
#define gso_size tso_size
#define gso_segs tso_segs
#endif

#ifndef NETIF_F_GRO
#define vlan_gro_receive(_napi, _vlgrp, _vlan, _skb) \
		vlan_hwaccel_receive_skb(_skb, _vlgrp, _vlan)
#define napi_gro_receive(_napi, _skb) netif_receive_skb(_skb)
#endif

#ifndef NETIF_F_SCTP_CSUM
#define NETIF_F_SCTP_CSUM 0
#endif

#ifndef NETIF_F_LRO
#define NETIF_F_LRO BIT(15)
#endif

#ifndef NETIF_F_NTUPLE
#define NETIF_F_NTUPLE BIT(27)
#endif

#ifndef NETIF_F_ALL_FCOE
#define NETIF_F_ALL_FCOE	(NETIF_F_FCOE_CRC | NETIF_F_FCOE_MTU | \
				 NETIF_F_FSO)
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE 136
#endif

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif

#ifndef __read_mostly
#define __read_mostly
#endif

#ifndef MII_RESV1
#define MII_RESV1		0x17		/* Reserved...		*/
#endif

#ifndef unlikely
#define unlikely(_x) _x
#define likely(_x) _x
#endif

#ifndef WARN_ON
#define WARN_ON(x)
#endif

#ifndef PCI_DEVICE
#define PCI_DEVICE(vend,dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#endif

#ifndef node_online
#define node_online(node) ((node) == 0)
#endif

#ifndef cpu_online
#define cpu_online(cpuid) test_bit((cpuid), &cpu_online_map)
#endif

#ifndef _LINUX_RANDOM_H
#include <linux/random.h>
#endif

#ifndef BITS_PER_TYPE
#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#endif

#ifndef BITS_TO_LONGS
#define BITS_TO_LONGS(bits) (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#endif

#ifndef DECLARE_BITMAP
#define DECLARE_BITMAP(name,bits) long name[BITS_TO_LONGS(bits)]
#endif

#ifndef VLAN_HLEN
#define VLAN_HLEN 4
#endif

#ifndef VLAN_ETH_HLEN
#define VLAN_ETH_HLEN 18
#endif

#ifndef VLAN_ETH_FRAME_LEN
#define VLAN_ETH_FRAME_LEN 1518
#endif

#ifndef DCA_GET_TAG_TWO_ARGS
#define dca3_get_tag(a,b) dca_get_tag(b)
#endif

#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#if defined(__i386__) || defined(__x86_64__)
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#endif
#endif

/* taken from 2.6.24 definition in linux/kernel.h */
#ifndef IS_ALIGNED
#define IS_ALIGNED(x,a)         (((x) % ((typeof(x))(a))) == 0)
#endif

#ifdef IS_ENABLED
#undef IS_ENABLED
#undef __ARG_PLACEHOLDER_1
#undef config_enabled
#undef _config_enabled
#undef __config_enabled
#undef ___config_enabled
#endif

#define __ARG_PLACEHOLDER_1 0,
#define config_enabled(cfg) _config_enabled(cfg)
#define _config_enabled(value) __config_enabled(__ARG_PLACEHOLDER_##value)
#define __config_enabled(arg1_or_junk) ___config_enabled(arg1_or_junk 1, 0)
#define ___config_enabled(__ignored, val, ...) val

#define IS_ENABLED(option) \
	(config_enabled(option) || config_enabled(option##_MODULE))

#if !defined(NETIF_F_HW_VLAN_TX) && !defined(NETIF_F_HW_VLAN_CTAG_TX)
struct _kc_vlan_ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__be16		h_vlan_proto;
	__be16		h_vlan_TCI;
	__be16		h_vlan_encapsulated_proto;
};
#define vlan_ethhdr _kc_vlan_ethhdr
struct _kc_vlan_hdr {
	__be16		h_vlan_TCI;
	__be16		h_vlan_encapsulated_proto;
};
#define vlan_hdr _kc_vlan_hdr
#define vlan_tx_tag_present(_skb) 0
#define vlan_tx_tag_get(_skb) 0
#endif /* NETIF_F_HW_VLAN_TX && NETIF_F_HW_VLAN_CTAG_TX */

#ifndef VLAN_PRIO_SHIFT
#define VLAN_PRIO_SHIFT 13
#endif

#ifndef PCI_EXP_LNKSTA_CLS_2_5GB
#define PCI_EXP_LNKSTA_CLS_2_5GB 0x0001
#endif

#ifndef PCI_EXP_LNKSTA_CLS_5_0GB
#define PCI_EXP_LNKSTA_CLS_5_0GB 0x0002
#endif

#ifndef PCI_EXP_LNKSTA_CLS_8_0GB
#define PCI_EXP_LNKSTA_CLS_8_0GB 0x0003
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X1
#define PCI_EXP_LNKSTA_NLW_X1 0x0010
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X2
#define PCI_EXP_LNKSTA_NLW_X2 0x0020
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X4
#define PCI_EXP_LNKSTA_NLW_X4 0x0040
#endif

#ifndef PCI_EXP_LNKSTA_NLW_X8
#define PCI_EXP_LNKSTA_NLW_X8 0x0080
#endif


#ifndef __GFP_COLD
#define __GFP_COLD 0
#endif

#ifndef __GFP_COMP
#define __GFP_COMP 0
#endif

#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF /* "Fragment Offset" part */
#endif

/*****************************************************************************/
/* Installations with ethtool version without eeprom, adapter id, or statistics
 * support */

#ifndef ETH_GSTRING_LEN
#define ETH_GSTRING_LEN 32
#endif

#ifndef ETHTOOL_GSTATS
#define ETHTOOL_GSTATS 0x1d
#undef ethtool_drvinfo
#define ethtool_drvinfo k_ethtool_drvinfo
struct k_ethtool_drvinfo {
	u32 cmd;
	char driver[32];
	char version[32];
	char fw_version[32];
	char bus_info[32];
	char reserved1[32];
	char reserved2[16];
	u32 n_stats;
	u32 testinfo_len;
	u32 eedump_len;
	u32 regdump_len;
};

struct ethtool_stats {
	u32 cmd;
	u32 n_stats;
	u64 data[0];
};
#endif /* ETHTOOL_GSTATS */

#ifndef ETHTOOL_PHYS_ID
#define ETHTOOL_PHYS_ID 0x1c
#endif /* ETHTOOL_PHYS_ID */

#ifndef ETHTOOL_GSTRINGS
#define ETHTOOL_GSTRINGS 0x1b
enum ethtool_stringset {
	ETH_SS_TEST             = 0,
	ETH_SS_STATS,
};
struct ethtool_gstrings {
	u32 cmd;            /* ETHTOOL_GSTRINGS */
	u32 string_set;     /* string set id e.c. ETH_SS_TEST, etc*/
	u32 len;            /* number of strings in the string set */
	u8 data[0];
};
#endif /* ETHTOOL_GSTRINGS */

#ifndef ETHTOOL_TEST
#define ETHTOOL_TEST 0x1a
enum ethtool_test_flags {
	ETH_TEST_FL_OFFLINE	= BIT(0),
	ETH_TEST_FL_FAILED	= BIT(1),
};
struct ethtool_test {
	u32 cmd;
	u32 flags;
	u32 reserved;
	u32 len;
	u64 data[0];
};
#endif /* ETHTOOL_TEST */

#ifndef ETHTOOL_GEEPROM
#define ETHTOOL_GEEPROM 0xb
#undef ETHTOOL_GREGS
struct ethtool_eeprom {
	u32 cmd;
	u32 magic;
	u32 offset;
	u32 len;
	u8 data[0];
};

struct ethtool_value {
	u32 cmd;
	u32 data;
};
#endif /* ETHTOOL_GEEPROM */

#ifndef ETHTOOL_GLINK
#define ETHTOOL_GLINK 0xa
#endif /* ETHTOOL_GLINK */

#ifndef ETHTOOL_GWOL
#define ETHTOOL_GWOL 0x5
#define ETHTOOL_SWOL 0x6
#define SOPASS_MAX      6
struct ethtool_wolinfo {
	u32 cmd;
	u32 supported;
	u32 wolopts;
	u8 sopass[SOPASS_MAX]; /* SecureOn(tm) password */
};
#endif /* ETHTOOL_GWOL */

#ifndef ETHTOOL_GREGS
#define ETHTOOL_GREGS		0x00000004 /* Get NIC registers */
#define ethtool_regs _kc_ethtool_regs
/* for passing big chunks of data */
struct _kc_ethtool_regs {
	u32 cmd;
	u32 version; /* driver-specific, indicates different chips/revs */
	u32 len; /* bytes */
	u8 data[0];
};
#endif /* ETHTOOL_GREGS */

#ifndef ETHTOOL_GMSGLVL
#define ETHTOOL_GMSGLVL		0x00000007 /* Get driver message level */
#endif
#ifndef ETHTOOL_SMSGLVL
#define ETHTOOL_SMSGLVL		0x00000008 /* Set driver msg level, priv. */
#endif
#ifndef ETHTOOL_NWAY_RST
#define ETHTOOL_NWAY_RST	0x00000009 /* Restart autonegotiation, priv */
#endif
#ifndef ETHTOOL_GLINK
#define ETHTOOL_GLINK		0x0000000a /* Get link status */
#endif
#ifndef ETHTOOL_GEEPROM
#define ETHTOOL_GEEPROM		0x0000000b /* Get EEPROM data */
#endif
#ifndef ETHTOOL_SEEPROM
#define ETHTOOL_SEEPROM		0x0000000c /* Set EEPROM data */
#endif
#ifndef ETHTOOL_GCOALESCE
#define ETHTOOL_GCOALESCE	0x0000000e /* Get coalesce config */
/* for configuring coalescing parameters of chip */
#define ethtool_coalesce _kc_ethtool_coalesce
struct _kc_ethtool_coalesce {
	u32	cmd;	/* ETHTOOL_{G,S}COALESCE */

	/* How many usecs to delay an RX interrupt after
	 * a packet arrives.  If 0, only rx_max_coalesced_frames
	 * is used.
	 */
	u32	rx_coalesce_usecs;

	/* How many packets to delay an RX interrupt after
	 * a packet arrives.  If 0, only rx_coalesce_usecs is
	 * used.  It is illegal to set both usecs and max frames
	 * to zero as this would cause RX interrupts to never be
	 * generated.
	 */
	u32	rx_max_coalesced_frames;

	/* Same as above two parameters, except that these values
	 * apply while an IRQ is being serviced by the host.  Not
	 * all cards support this feature and the values are ignored
	 * in that case.
	 */
	u32	rx_coalesce_usecs_irq;
	u32	rx_max_coalesced_frames_irq;

	/* How many usecs to delay a TX interrupt after
	 * a packet is sent.  If 0, only tx_max_coalesced_frames
	 * is used.
	 */
	u32	tx_coalesce_usecs;

	/* How many packets to delay a TX interrupt after
	 * a packet is sent.  If 0, only tx_coalesce_usecs is
	 * used.  It is illegal to set both usecs and max frames
	 * to zero as this would cause TX interrupts to never be
	 * generated.
	 */
	u32	tx_max_coalesced_frames;

	/* Same as above two parameters, except that these values
	 * apply while an IRQ is being serviced by the host.  Not
	 * all cards support this feature and the values are ignored
	 * in that case.
	 */
	u32	tx_coalesce_usecs_irq;
	u32	tx_max_coalesced_frames_irq;

	/* How many usecs to delay in-memory statistics
	 * block updates.  Some drivers do not have an in-memory
	 * statistic block, and in such cases this value is ignored.
	 * This value must not be zero.
	 */
	u32	stats_block_coalesce_usecs;

	/* Adaptive RX/TX coalescing is an algorithm implemented by
	 * some drivers to improve latency under low packet rates and
	 * improve throughput under high packet rates.  Some drivers
	 * only implement one of RX or TX adaptive coalescing.  Anything
	 * not implemented by the driver causes these values to be
	 * silently ignored.
	 */
	u32	use_adaptive_rx_coalesce;
	u32	use_adaptive_tx_coalesce;

	/* When the packet rate (measured in packets per second)
	 * is below pkt_rate_low, the {rx,tx}_*_low parameters are
	 * used.
	 */
	u32	pkt_rate_low;
	u32	rx_coalesce_usecs_low;
	u32	rx_max_coalesced_frames_low;
	u32	tx_coalesce_usecs_low;
	u32	tx_max_coalesced_frames_low;

	/* When the packet rate is below pkt_rate_high but above
	 * pkt_rate_low (both measured in packets per second) the
	 * normal {rx,tx}_* coalescing parameters are used.
	 */

	/* When the packet rate is (measured in packets per second)
	 * is above pkt_rate_high, the {rx,tx}_*_high parameters are
	 * used.
	 */
	u32	pkt_rate_high;
	u32	rx_coalesce_usecs_high;
	u32	rx_max_coalesced_frames_high;
	u32	tx_coalesce_usecs_high;
	u32	tx_max_coalesced_frames_high;

	/* How often to do adaptive coalescing packet rate sampling,
	 * measured in seconds.  Must not be zero.
	 */
	u32	rate_sample_interval;
};
#endif /* ETHTOOL_GCOALESCE */

#ifndef ETHTOOL_SCOALESCE
#define ETHTOOL_SCOALESCE	0x0000000f /* Set coalesce config. */
#endif
#ifndef ETHTOOL_GRINGPARAM
#define ETHTOOL_GRINGPARAM	0x00000010 /* Get ring parameters */
/* for configuring RX/TX ring parameters */
#define ethtool_ringparam _kc_ethtool_ringparam
struct _kc_ethtool_ringparam {
	u32	cmd;	/* ETHTOOL_{G,S}RINGPARAM */

	/* Read only attributes.  These indicate the maximum number
	 * of pending RX/TX ring entries the driver will allow the
	 * user to set.
	 */
	u32	rx_max_pending;
	u32	rx_mini_max_pending;
	u32	rx_jumbo_max_pending;
	u32	tx_max_pending;

	/* Values changeable by the user.  The valid values are
	 * in the range 1 to the "*_max_pending" counterpart above.
	 */
	u32	rx_pending;
	u32	rx_mini_pending;
	u32	rx_jumbo_pending;
	u32	tx_pending;
};
#endif /* ETHTOOL_GRINGPARAM */

#ifndef ETHTOOL_SRINGPARAM
#define ETHTOOL_SRINGPARAM	0x00000011 /* Set ring parameters, priv. */
#endif
#ifndef ETHTOOL_GPAUSEPARAM
#define ETHTOOL_GPAUSEPARAM	0x00000012 /* Get pause parameters */
/* for configuring link flow control parameters */
#define ethtool_pauseparam _kc_ethtool_pauseparam
struct _kc_ethtool_pauseparam {
	u32	cmd;	/* ETHTOOL_{G,S}PAUSEPARAM */

	/* If the link is being auto-negotiated (via ethtool_cmd.autoneg
	 * being true) the user may set 'autoneg' here non-zero to have the
	 * pause parameters be auto-negotiated too.  In such a case, the
	 * {rx,tx}_pause values below determine what capabilities are
	 * advertised.
	 *
	 * If 'autoneg' is zero or the link is not being auto-negotiated,
	 * then {rx,tx}_pause force the driver to use/not-use pause
	 * flow control.
	 */
	u32	autoneg;
	u32	rx_pause;
	u32	tx_pause;
};
#endif /* ETHTOOL_GPAUSEPARAM */

#ifndef ETHTOOL_SPAUSEPARAM
#define ETHTOOL_SPAUSEPARAM	0x00000013 /* Set pause parameters. */
#endif
#ifndef ETHTOOL_GRXCSUM
#define ETHTOOL_GRXCSUM		0x00000014 /* Get RX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_SRXCSUM
#define ETHTOOL_SRXCSUM		0x00000015 /* Set RX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_GTXCSUM
#define ETHTOOL_GTXCSUM		0x00000016 /* Get TX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_STXCSUM
#define ETHTOOL_STXCSUM		0x00000017 /* Set TX hw csum enable (ethtool_value) */
#endif
#ifndef ETHTOOL_GSG
#define ETHTOOL_GSG		0x00000018 /* Get scatter-gather enable
					    * (ethtool_value) */
#endif
#ifndef ETHTOOL_SSG
#define ETHTOOL_SSG		0x00000019 /* Set scatter-gather enable
					    * (ethtool_value). */
#endif
#ifndef ETHTOOL_TEST
#define ETHTOOL_TEST		0x0000001a /* execute NIC self-test, priv. */
#endif
#ifndef ETHTOOL_GSTRINGS
#define ETHTOOL_GSTRINGS	0x0000001b /* get specified string set */
#endif
#ifndef ETHTOOL_PHYS_ID
#define ETHTOOL_PHYS_ID		0x0000001c /* identify the NIC */
#endif
#ifndef ETHTOOL_GSTATS
#define ETHTOOL_GSTATS		0x0000001d /* get NIC-specific statistics */
#endif
#ifndef ETHTOOL_GTSO
#define ETHTOOL_GTSO		0x0000001e /* Get TSO enable (ethtool_value) */
#endif
#ifndef ETHTOOL_STSO
#define ETHTOOL_STSO		0x0000001f /* Set TSO enable (ethtool_value) */
#endif

#ifndef ETHTOOL_BUSINFO_LEN
#define ETHTOOL_BUSINFO_LEN	32
#endif

#ifndef WAKE_FILTER
#define WAKE_FILTER	BIT(7)
#endif

#ifndef SPEED_2500
#define SPEED_2500 2500
#endif
#ifndef SPEED_5000
#define SPEED_5000 5000
#endif
#ifndef SPEED_14000
#define SPEED_14000 14000
#endif
#ifndef SPEED_25000
#define SPEED_25000 25000
#endif
#ifndef SPEED_50000
#define SPEED_50000 50000
#endif
#ifndef SPEED_56000
#define SPEED_56000 56000
#endif
#ifndef SPEED_100000
#define SPEED_100000 100000
#endif

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a,b) (((a) << 8) + (b))
#endif
#ifndef AX_RELEASE_VERSION
#define AX_RELEASE_VERSION(a,b) (((a) << 8) + (b))
#endif

#ifndef AX_RELEASE_CODE
#define AX_RELEASE_CODE 0
#endif

#if (AX_RELEASE_CODE && AX_RELEASE_CODE == AX_RELEASE_VERSION(3,0))
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(5,0)
#elif (AX_RELEASE_CODE && AX_RELEASE_CODE == AX_RELEASE_VERSION(3,1))
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(5,1)
#elif (AX_RELEASE_CODE && AX_RELEASE_CODE == AX_RELEASE_VERSION(3,2))
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(5,3)
#endif

#ifndef RHEL_RELEASE_CODE
/* NOTE: RHEL_RELEASE_* introduced in RHEL4.5 */
#define RHEL_RELEASE_CODE 0
#endif

/* RHEL 7 didn't backport the parameter change in
 * create_singlethread_workqueue.
 * If/when RH corrects this we will want to tighten up the version check.
 */
#if (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,0))
#undef create_singlethread_workqueue
#define create_singlethread_workqueue(name)	\
	alloc_ordered_workqueue("%s", WQ_MEM_RECLAIM, name)
#endif

/* Ubuntu Release ABI is the 4th digit of their kernel version. You can find
 * it in /usr/src/linux/$(uname -r)/include/generated/utsrelease.h for new
 * enough versions of Ubuntu. Otherwise you can simply see it in the output of
 * uname as the 4th digit of the kernel. The UTS_UBUNTU_RELEASE_ABI is not in
 * the linux-source package, but in the linux-headers package. It begins to
 * appear in later releases of 14.04 and 14.10.
 *
 * Ex:
 * <Ubuntu 14.04.1>
 *  $uname -r
 *  3.13.0-45-generic
 * ABI is 45
 *
 * <Ubuntu 14.10>
 *  $uname -r
 *  3.16.0-23-generic
 * ABI is 23
 */
#ifndef UTS_UBUNTU_RELEASE_ABI
#define UTS_UBUNTU_RELEASE_ABI 0
#define UBUNTU_VERSION_CODE 0
#else
/* Ubuntu does not provide actual release version macro, so we use the kernel
 * version plus the ABI to generate a unique version code specific to Ubuntu.
 * In addition, we mask the lower 8 bits of LINUX_VERSION_CODE in order to
 * ignore differences in sublevel which are not important since we have the
 * ABI value. Otherwise, it becomes impossible to correlate ABI to version for
 * ordering checks.
 */
#define UBUNTU_VERSION_CODE (((~0xFF & LINUX_VERSION_CODE) << 8) + \
			     UTS_UBUNTU_RELEASE_ABI)

#if UTS_UBUNTU_RELEASE_ABI > 255
#error UTS_UBUNTU_RELEASE_ABI is too large...
#endif /* UTS_UBUNTU_RELEASE_ABI > 255 */

#if ( LINUX_VERSION_CODE <= KERNEL_VERSION(3,0,0) )
/* Our version code scheme does not make sense for non 3.x or newer kernels,
 * and we have no support in kcompat for this scenario. Thus, treat this as a
 * non-Ubuntu kernel. Possibly might be better to error here.
 */
#define UTS_UBUNTU_RELEASE_ABI 0
#define UBUNTU_VERSION_CODE 0
#endif

#endif

/* Note that the 3rd digit is always zero, and will be ignored. This is
 * because Ubuntu kernels are based on x.y.0-ABI values, and while their linux
 * version codes are 3 digit, this 3rd digit is superseded by the ABI value.
 */
#define UBUNTU_VERSION(a,b,c,d) ((KERNEL_VERSION(a,b,0) << 8) + (d))

/* SuSE version macros are the same as Linux kernel version macro */
#ifndef SLE_VERSION
#define SLE_VERSION(a,b,c)	KERNEL_VERSION(a,b,c)
#endif
#define SLE_LOCALVERSION(a,b,c)	KERNEL_VERSION(a,b,c)
#ifdef CONFIG_SUSE_KERNEL
#if ( LINUX_VERSION_CODE == KERNEL_VERSION(2,6,27) )
/* SLES11 GA is 2.6.27 based */
#define SLE_VERSION_CODE SLE_VERSION(11,0,0)
#elif ( LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32) )
/* SLES11 SP1 is 2.6.32 based */
#define SLE_VERSION_CODE SLE_VERSION(11,1,0)
#elif ( LINUX_VERSION_CODE == KERNEL_VERSION(3,0,13) )
/* SLES11 SP2 GA is 3.0.13-0.27 */
#define SLE_VERSION_CODE SLE_VERSION(11,2,0)
#elif ((LINUX_VERSION_CODE == KERNEL_VERSION(3,0,76)))
/* SLES11 SP3 GA is 3.0.76-0.11 */
#define SLE_VERSION_CODE SLE_VERSION(11,3,0)
#elif (LINUX_VERSION_CODE == KERNEL_VERSION(3,0,101))
  #if (SLE_LOCALVERSION_CODE < SLE_LOCALVERSION(0,8,0))
  /* some SLES11sp2 update kernels up to 3.0.101-0.7.x */
  #define SLE_VERSION_CODE SLE_VERSION(11,2,0)
  #elif (SLE_LOCALVERSION_CODE < SLE_LOCALVERSION(63,0,0))
  /* most SLES11sp3 update kernels */
  #define SLE_VERSION_CODE SLE_VERSION(11,3,0)
  #else
  /* SLES11 SP4 GA (3.0.101-63) and update kernels 3.0.101-63+ */
  #define SLE_VERSION_CODE SLE_VERSION(11,4,0)
  #endif
#elif (LINUX_VERSION_CODE == KERNEL_VERSION(3,12,28))
/* SLES12 GA is 3.12.28-4
 * kernel updates 3.12.xx-<33 through 52>[.yy] */
#define SLE_VERSION_CODE SLE_VERSION(12,0,0)
#elif (LINUX_VERSION_CODE == KERNEL_VERSION(3,12,49))
/* SLES12 SP1 GA is 3.12.49-11
 * updates 3.12.xx-60.yy where xx={51..} */
#define SLE_VERSION_CODE SLE_VERSION(12,1,0)
#elif ((LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,21) && \
       (LINUX_VERSION_CODE <= KERNEL_VERSION(4,4,59))) || \
       (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,74) && \
        LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0) && \
        SLE_LOCALVERSION_CODE >= KERNEL_VERSION(92,0,0) && \
        SLE_LOCALVERSION_CODE <  KERNEL_VERSION(93,0,0)))
/* SLES12 SP2 GA is 4.4.21-69.
 * SLES12 SP2 updates before SLES12 SP3 are: 4.4.{21,38,49,59}
 * SLES12 SP2 updates after SLES12 SP3 are: 4.4.{74,90,103,114,120}
 * but they all use a SLE_LOCALVERSION_CODE matching 92.nn.y */
#define SLE_VERSION_CODE SLE_VERSION(12,2,0)
#elif ((LINUX_VERSION_CODE == KERNEL_VERSION(4,4,73) || \
        LINUX_VERSION_CODE == KERNEL_VERSION(4,4,82) || \
        LINUX_VERSION_CODE == KERNEL_VERSION(4,4,92)) || \
       (LINUX_VERSION_CODE == KERNEL_VERSION(4,4,103) && \
       (SLE_LOCALVERSION_CODE == KERNEL_VERSION(6,33,0) || \
        SLE_LOCALVERSION_CODE == KERNEL_VERSION(6,38,0))) || \
       (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,114) && \
        LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0) && \
        SLE_LOCALVERSION_CODE >= KERNEL_VERSION(94,0,0) && \
        SLE_LOCALVERSION_CODE <  KERNEL_VERSION(95,0,0)) )
/* SLES12 SP3 GM is 4.4.73-5 and update kernels are 4.4.82-6.3.
 * SLES12 SP3 updates not conflicting with SP2 are: 4.4.{82,92}
 * SLES12 SP3 updates conflicting with SP2 are:
 *   - 4.4.103-6.33.1, 4.4.103-6.38.1
 *   - 4.4.{114,120}-94.nn.y */
#define SLE_VERSION_CODE SLE_VERSION(12,3,0)
#elif (LINUX_VERSION_CODE == KERNEL_VERSION(4,12,14) && \
       (SLE_LOCALVERSION_CODE == KERNEL_VERSION(94,41,0) || \
       (SLE_LOCALVERSION_CODE >= KERNEL_VERSION(95,0,0) && \
        SLE_LOCALVERSION_CODE < KERNEL_VERSION(96,0,0))))
/* SLES12 SP4 GM is 4.12.14-94.41 and update kernel is 4.12.14-95.x. */
#define SLE_VERSION_CODE SLE_VERSION(12,4,0)
#elif (LINUX_VERSION_CODE == KERNEL_VERSION(4,12,14) && \
       (SLE_LOCALVERSION_CODE == KERNEL_VERSION(23,0,0) || \
        SLE_LOCALVERSION_CODE == KERNEL_VERSION(2,0,0) || \
        SLE_LOCALVERSION_CODE == KERNEL_VERSION(136,0,0) || \
        (SLE_LOCALVERSION_CODE >= KERNEL_VERSION(25,0,0) && \
	 SLE_LOCALVERSION_CODE < KERNEL_VERSION(26,0,0)) || \
	(SLE_LOCALVERSION_CODE >= KERNEL_VERSION(150,0,0) && \
	 SLE_LOCALVERSION_CODE < KERNEL_VERSION(151,0,0))))
/* SLES15 Beta1 is 4.12.14-2
 * SLES15 GM is 4.12.14-23 and update kernel is 4.12.14-{25,136},
 * and 4.12.14-150.14.
 */
#define SLE_VERSION_CODE SLE_VERSION(15,0,0)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,14) && \
       SLE_LOCALVERSION_CODE >= KERNEL_VERSION(25,23,0))
/* SLES15 SP1 Beta1 is 4.12.14-25.23 */
#define SLE_VERSION_CODE SLE_VERSION(15,1,0)
/* new SLES kernels must be added here with >= based on kernel
 * the idea is to order from newest to oldest and just catch all
 * of them using the >=
 */
#endif /* LINUX_VERSION_CODE == KERNEL_VERSION(x,y,z) */
#endif /* CONFIG_SUSE_KERNEL */
#ifndef SLE_VERSION_CODE
#define SLE_VERSION_CODE 0
#endif /* SLE_VERSION_CODE */
#ifndef SLE_LOCALVERSION_CODE
#define SLE_LOCALVERSION_CODE 0
#endif /* SLE_LOCALVERSION_CODE */

/*
 * ADQ depends on __TC_MQPRIO_MODE_MAX and related kernel code
 * added around 4.15. Some distributions (e.g. Oracle Linux 7.7)
 * have done a partial back-port of that to their kernels based
 * on older mainline kernels that did not include all the necessary
 * kernel enablement to support ADQ.
 * Undefine __TC_MQPRIO_MODE_MAX for all OSV distributions with
 * kernels based on mainline kernels older than 4.15 except for
 * RHEL, SLES and Ubuntu which are known to have good back-ports.
 */
#if (!RHEL_RELEASE_CODE && !SLE_VERSION_CODE && !UBUNTU_VERSION_CODE)
  #if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
  #undef __TC_MQPRIO_MODE_MAX
  #endif /*  LINUX_VERSION_CODE == KERNEL_VERSION(4,15,0) */
#endif /* if (NOT RHEL && NOT SLES && NOT UBUNTU) */

#ifdef __KLOCWORK__
/* The following are not compiled into the binary driver; they are here
 * only to tune Klocwork scans to workaround false-positive issues.
 */
#ifdef ARRAY_SIZE
#undef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define memcpy(dest, src, len)	memcpy_s(dest, len, src, len)
#define memset(dest, ch, len)	memset_s(dest, len, ch, len)

static inline int _kc_test_and_clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;
	unsigned long flags = 0;

	_atomic_spin_lock_irqsave(p, flags);
	old = *p;
	*p = old & ~mask;
	_atomic_spin_unlock_irqrestore(p, flags);

	return (old & mask) != 0;
}
#define test_and_clear_bit(nr, addr) _kc_test_and_clear_bit(nr, addr)

static inline int _kc_test_and_set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;
	unsigned long flags = 0;

	_atomic_spin_lock_irqsave(p, flags);
	old = *p;
	*p = old | mask;
	_atomic_spin_unlock_irqrestore(p, flags);

	return (old & mask) != 0;
}
#define test_and_set_bit(nr, addr) _kc_test_and_set_bit(nr, addr)

#ifdef CONFIG_DYNAMIC_DEBUG
#undef dev_dbg
#define dev_dbg(dev, format, arg...) dev_printk(KERN_DEBUG, dev, format, ##arg)
#undef pr_debug
#define pr_debug(format, arg...) printk(KERN_DEBUG format, ##arg)
#endif /* CONFIG_DYNAMIC_DEBUG */


#undef hlist_for_each_entry_safe
#define hlist_for_each_entry_safe(pos, n, head, member)			     \
	for (n = NULL, pos = hlist_entry_safe((head)->first, typeof(*(pos)), \
					      member);			     \
	     pos;							     \
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#ifdef uninitialized_var
#undef uninitialized_var
#define uninitialized_var(x) x = *(&(x))
#endif
#endif /* __KLOCWORK__ */


/* Older versions of GCC will trigger -Wformat-nonliteral warnings for const
 * char * strings. Unfortunately, the implementation of do_trace_printk does
 * this, in order to add a storage attribute to the memory. This was fixed in
 * GCC 5.1, but we still use older distributions built with GCC 4.x.
 *
 * The string pointer is only passed as a const char * to the __trace_bprintk
 * function. Since that function has the __printf attribute, it will trigger
 * the warnings. We can't remove the attribute, so instead we'll use the
 * __diag macro to disable -Wformat-nonliteral around the call to
 * __trace_bprintk.
 */
#if GCC_VERSION < 50100
#define __trace_bprintk(ip, fmt, args...) ({		\
	int err;					\
	__diag_push();					\
	__diag(ignored "-Wformat-nonliteral");		\
	err = __trace_bprintk(ip, fmt, ##args);		\
	__diag_pop();					\
	err;						\
})
#endif /* GCC_VERSION < 5.1.0 */

/* Newer kernels removed <linux/pci-aspm.h> */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0) )
#define HAVE_PCI_ASPM_H
#endif

#include <linux/aer.h>
#include <linux/pci_hotplug.h>
#include <linux/of_net.h>
#include <linux/of.h>
#define HAVE_SET_RX_MODE
#define HAVE_STRUCT_DEVICE_OF_NODE
#define HAVE_BRIDGE_FILTER

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) )
#ifndef NAPI_POLL_WEIGHT
#define NAPI_POLL_WEIGHT 64
#endif
#ifdef CONFIG_PCI_IOV
int __kc_pci_vfs_assigned(struct pci_dev *dev);
#else
static inline int __kc_pci_vfs_assigned(struct pci_dev __always_unused *dev)
{
	return 0;
}
#endif
#define pci_vfs_assigned(dev) __kc_pci_vfs_assigned(dev)

#ifndef list_first_entry_or_null
#define list_first_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)
#endif

#ifndef VLAN_TX_COOKIE_MAGIC
static inline struct sk_buff *__kc__vlan_hwaccel_put_tag(struct sk_buff *skb,
							 u16 vlan_tci)
{
#ifdef VLAN_TAG_PRESENT
	vlan_tci |= VLAN_TAG_PRESENT;
#endif
	skb->vlan_tci = vlan_tci;
        return skb;
}
#define __vlan_hwaccel_put_tag(skb, vlan_proto, vlan_tci) \
	__kc__vlan_hwaccel_put_tag(skb, vlan_tci)
#endif

#ifdef HAVE_FDB_OPS
#if defined(HAVE_NDO_FDB_ADD_NLATTR)
int __kc_ndo_dflt_fdb_add(struct ndmsg *ndm, struct nlattr *tb[],
			  struct net_device *dev,
			  const unsigned char *addr, u16 flags);
#elif defined(USE_CONST_DEV_UC_CHAR)
int __kc_ndo_dflt_fdb_add(struct ndmsg *ndm, struct net_device *dev,
			  const unsigned char *addr, u16 flags);
#else
int __kc_ndo_dflt_fdb_add(struct ndmsg *ndm, struct net_device *dev,
			  unsigned char *addr, u16 flags);
#endif /* HAVE_NDO_FDB_ADD_NLATTR */
#if defined(HAVE_FDB_DEL_NLATTR)
int __kc_ndo_dflt_fdb_del(struct ndmsg *ndm, struct nlattr *tb[],
			  struct net_device *dev,
			  const unsigned char *addr);
#elif defined(USE_CONST_DEV_UC_CHAR)
int __kc_ndo_dflt_fdb_del(struct ndmsg *ndm, struct net_device *dev,
			  const unsigned char *addr);
#else
int __kc_ndo_dflt_fdb_del(struct ndmsg *ndm, struct net_device *dev,
			  unsigned char *addr);
#endif /* HAVE_FDB_DEL_NLATTR */
#define ndo_dflt_fdb_add __kc_ndo_dflt_fdb_add
#define ndo_dflt_fdb_del __kc_ndo_dflt_fdb_del
#endif /* HAVE_FDB_OPS */

#ifndef PCI_DEVID
#define PCI_DEVID(bus, devfn)  ((((u16)(bus)) << 8) | (devfn))
#endif

/* The definitions for these functions when CONFIG_OF_NET is defined are
 * pulled in from <linux/of_net.h>. For kernels older than 3.5 we already have
 * backports for when CONFIG_OF_NET is true. These are separated and
 * duplicated in order to cover all cases so that all kernels get either the
 * real definitions (when CONFIG_OF_NET is defined) or the stub definitions
 * (when CONFIG_OF_NET is not defined, or the kernel is too old to have real
 * definitions).
 */
#ifndef CONFIG_OF_NET
static inline int of_get_phy_mode(struct device_node __always_unused *np)
{
	return -ENODEV;
}

static inline const void *
of_get_mac_address(struct device_node __always_unused *np)
{
	return NULL;
}
#endif

#else /* >= 3.10.0 */
#define HAVE_ENCAP_TSO_OFFLOAD
#define USE_DEFAULT_FDB_DEL_DUMP
#define HAVE_SKB_INNER_NETWORK_HEADER

#if (RHEL_RELEASE_CODE && \
     (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,0)) && \
     (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8,0)))
#define HAVE_RHEL7_PCI_DRIVER_RH
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,2))
#define HAVE_RHEL7_PCI_RESET_NOTIFY
#endif /* RHEL >= 7.2 */
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3))
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5))
#define HAVE_GENEVE_RX_OFFLOAD
#endif /* RHEL >=7.3 && RHEL < 7.5 */
#define HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC
#define HAVE_RHEL7_NET_DEVICE_OPS_EXT
#if !defined(HAVE_UDP_ENC_TUNNEL) && IS_ENABLED(CONFIG_GENEVE)
#define HAVE_UDP_ENC_TUNNEL
#endif
#endif /* RHEL >= 7.3 */

/* new hooks added to net_device_ops_extended in RHEL7.4 */
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4))
#define HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SET_VF_VLAN
#define HAVE_RHEL7_NETDEV_OPS_EXT_NDO_UDP_TUNNEL
#define HAVE_UDP_ENC_RX_OFFLOAD
#endif /* RHEL >= 7.4 */
#endif /* RHEL >= 7.0 && RHEL < 8.0 */

#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8,0))
#define HAVE_TCF_BLOCK_CB_REGISTER_EXTACK
#define NO_NETDEV_BPF_PROG_ATTACHED
#endif /* RHEL >= 8.0 */
#endif /* >= 3.10.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0) )
#define netdev_notifier_info_to_dev(ptr) ptr
#ifndef time_in_range64
#define time_in_range64(a, b, c) \
	(time_after_eq64(a, b) && \
	 time_before_eq64(a, c))
#endif /* time_in_range64 */
#if ((RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,6)) ||\
     (SLE_VERSION_CODE && SLE_VERSION_CODE >= SLE_VERSION(11,4,0)))
#define HAVE_NDO_SET_VF_LINK_STATE
#endif
#if RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2))
#define HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK
#endif
#else /* >= 3.11.0 */
#define HAVE_NDO_SET_VF_LINK_STATE
#define HAVE_SKB_INNER_PROTOCOL
#define HAVE_MPLS_FEATURES
#endif /* >= 3.11.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0) )
int __kc_pcie_get_minimum_link(struct pci_dev *dev, enum pci_bus_speed *speed,
			       enum pcie_link_width *width);
#ifndef pcie_get_minimum_link
#define pcie_get_minimum_link(_p, _s, _w) __kc_pcie_get_minimum_link(_p, _s, _w)
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(6,7))
int _kc_pci_wait_for_pending_transaction(struct pci_dev *dev);
#define pci_wait_for_pending_transaction _kc_pci_wait_for_pending_transaction
#endif /* <RHEL6.7 */

#else /* >= 3.12.0 */
#if ( SLE_VERSION_CODE && SLE_VERSION_CODE >= SLE_VERSION(12,0,0))
#define HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK
#endif
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0) )
#define HAVE_VXLAN_RX_OFFLOAD
#if !defined(HAVE_UDP_ENC_TUNNEL) && IS_ENABLED(CONFIG_VXLAN)
#define HAVE_UDP_ENC_TUNNEL
#endif
#endif /* < 4.8.0 */
#define HAVE_NDO_GET_PHYS_PORT_ID
#define HAVE_NETIF_SET_XPS_QUEUE_CONST_MASK
#endif /* >= 3.12.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0) )
#define dma_set_mask_and_coherent(_p, _m) __kc_dma_set_mask_and_coherent(_p, _m)
int __kc_dma_set_mask_and_coherent(struct device *dev, u64 mask);
#ifndef u64_stats_init
#define u64_stats_init(a) do { } while(0)
#endif
#undef BIT_ULL
#define BIT_ULL(n) (1ULL << (n))

#if (!(SLE_VERSION_CODE && SLE_VERSION_CODE >= SLE_VERSION(12,0,0)) && \
     !(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,0)))
static inline struct pci_dev *pci_upstream_bridge(struct pci_dev *dev)
{
	dev = pci_physfn(dev);
	if (pci_is_root_bus(dev->bus))
		return NULL;

	return dev->bus->self;
}
#endif

#if (SLE_VERSION_CODE && SLE_VERSION_CODE >= SLE_VERSION(12,1,0))
#undef HAVE_STRUCT_PAGE_PFMEMALLOC
#define HAVE_DCBNL_OPS_SETAPP_RETURN_INT
#endif
#ifndef list_next_entry
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)
#endif
#ifndef list_prev_entry
#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)
#endif

#if ( LINUX_VERSION_CODE > KERNEL_VERSION(2,6,20) )
#define devm_kcalloc(dev, cnt, size, flags) \
	devm_kzalloc(dev, cnt * size, flags)
#endif /* > 2.6.20 */

#if (!(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,2)))
#define list_last_entry(ptr, type, member) list_entry((ptr)->prev, type, member)
#endif

#else /* >= 3.13.0 */
#define HAVE_VXLAN_CHECKS
#if (UBUNTU_VERSION_CODE && UBUNTU_VERSION_CODE >= UBUNTU_VERSION(3,13,0,24))
#define HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK
#else
#define HAVE_NDO_SELECT_QUEUE_ACCEL
#endif
#define HAVE_HWMON_DEVICE_REGISTER_WITH_GROUPS
#endif

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0) )

#ifndef U16_MAX
#define U16_MAX ((u16)~0U)
#endif

#ifndef U32_MAX
#define U32_MAX ((u32)~0U)
#endif

#if (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,2)))
#define dev_consume_skb_any(x) dev_kfree_skb_any(x)
#define dev_consume_skb_irq(x) dev_kfree_skb_irq(x)
#endif

#if (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,0)) && \
     !(SLE_VERSION_CODE && SLE_VERSION_CODE >= SLE_VERSION(12,0,0)))

/* it isn't expected that this would be a #define unless we made it so */
#ifndef skb_set_hash

#define PKT_HASH_TYPE_NONE	0
#define PKT_HASH_TYPE_L2	1
#define PKT_HASH_TYPE_L3	2
#define PKT_HASH_TYPE_L4	3

enum _kc_pkt_hash_types {
	_KC_PKT_HASH_TYPE_NONE = PKT_HASH_TYPE_NONE,
	_KC_PKT_HASH_TYPE_L2 = PKT_HASH_TYPE_L2,
	_KC_PKT_HASH_TYPE_L3 = PKT_HASH_TYPE_L3,
	_KC_PKT_HASH_TYPE_L4 = PKT_HASH_TYPE_L4,
};
#define pkt_hash_types         _kc_pkt_hash_types

#define skb_set_hash __kc_skb_set_hash
static inline void __kc_skb_set_hash(struct sk_buff __maybe_unused *skb,
				     u32 __maybe_unused hash,
				     int __maybe_unused type)
{
#ifdef HAVE_SKB_L4_RXHASH
	skb->l4_rxhash = (type == PKT_HASH_TYPE_L4);
#endif
#ifdef NETIF_F_RXHASH
	skb->rxhash = hash;
#endif
}
#endif /* !skb_set_hash */

#else	/* RHEL_RELEASE_CODE >= 7.0 || SLE_VERSION_CODE >= 12.0 */

#if (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,5)))
#ifndef HAVE_VXLAN_RX_OFFLOAD
#define HAVE_VXLAN_RX_OFFLOAD
#endif /* HAVE_VXLAN_RX_OFFLOAD */
#endif

#if !defined(HAVE_UDP_ENC_TUNNEL) && IS_ENABLED(CONFIG_VXLAN)
#define HAVE_UDP_ENC_TUNNEL
#endif

#ifndef HAVE_VXLAN_CHECKS
#define HAVE_VXLAN_CHECKS
#endif /* HAVE_VXLAN_CHECKS */
#endif /* !(RHEL_RELEASE_CODE >= 7.0 && SLE_VERSION_CODE >= 12.0) */

#if ((RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3)) ||\
     (SLE_VERSION_CODE && SLE_VERSION_CODE >= SLE_VERSION(12,0,0)))
#define HAVE_NDO_DFWD_OPS
#endif

#ifndef pci_enable_msix_range
int __kc_pci_enable_msix_range(struct pci_dev *dev, struct msix_entry *entries,
			       int minvec, int maxvec);
#define pci_enable_msix_range __kc_pci_enable_msix_range
#endif

#ifndef ether_addr_copy
#define ether_addr_copy __kc_ether_addr_copy
static inline void __kc_ether_addr_copy(u8 *dst, const u8 *src)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	*(u32 *)dst = *(const u32 *)src;
	*(u16 *)(dst + 4) = *(const u16 *)(src + 4);
#else
	u16 *a = (u16 *)dst;
	const u16 *b = (const u16 *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
#endif
}
#endif /* ether_addr_copy */
int __kc_ipv6_find_hdr(const struct sk_buff *skb, unsigned int *offset,
		       int target, unsigned short *fragoff, int *flags);
#define ipv6_find_hdr(a, b, c, d, e) __kc_ipv6_find_hdr((a), (b), (c), (d), (e))

#ifndef OPTIMIZE_HIDE_VAR
#ifdef __GNUC__
#define OPTIMIZER_HIDE_VAR(var) __asm__ ("" : "=r" (var) : "0" (var))
#else
#include <linux/barrier.h>
#define OPTIMIZE_HIDE_VAR(var)	barrier()
#endif
#endif

#if (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,0)) && \
     !(SLE_VERSION_CODE && SLE_VERSION_CODE >= SLE_VERSION(10,4,0)))
static inline __u32 skb_get_hash_raw(const struct sk_buff *skb)
{
#ifdef NETIF_F_RXHASH
	return skb->rxhash;
#else
	return 0;
#endif /* NETIF_F_RXHASH */
}
#endif /* !RHEL > 5.9 && !SLES >= 10.4 */

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5))
#define request_firmware_direct	request_firmware
#endif /* !RHEL || RHEL < 7.5 */

#else /* >= 3.14.0 */

/* for ndo_dfwd_ ops add_station, del_station and _start_xmit */
#ifndef HAVE_NDO_DFWD_OPS
#define HAVE_NDO_DFWD_OPS
#endif
#define HAVE_NDO_SELECT_QUEUE_ACCEL_FALLBACK
#endif /* 3.14.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0) )
#if (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,1)) && \
     !(UBUNTU_VERSION_CODE && UBUNTU_VERSION_CODE >= UBUNTU_VERSION(3,13,0,30)))
#define u64_stats_fetch_begin_irq u64_stats_fetch_begin_bh
#define u64_stats_fetch_retry_irq u64_stats_fetch_retry_bh
#endif

char *_kc_devm_kstrdup(struct device *dev, const char *s, gfp_t gfp);
#define devm_kstrdup(dev, s, gfp) _kc_devm_kstrdup(dev, s, gfp)

#else
#define HAVE_NET_GET_RANDOM_ONCE
#define HAVE_PTP_1588_CLOCK_PINS
#define HAVE_NETDEV_PORT
#endif /* 3.15.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0) )
#ifndef smp_mb__before_atomic
#define smp_mb__before_atomic() smp_mb()
#define smp_mb__after_atomic()  smp_mb()
#endif
#ifndef __dev_uc_sync
#ifdef HAVE_SET_RX_MODE
#ifdef NETDEV_HW_ADDR_T_UNICAST
int __kc_hw_addr_sync_dev(struct netdev_hw_addr_list *list,
		struct net_device *dev,
		int (*sync)(struct net_device *, const unsigned char *),
		int (*unsync)(struct net_device *, const unsigned char *));
void __kc_hw_addr_unsync_dev(struct netdev_hw_addr_list *list,
		struct net_device *dev,
		int (*unsync)(struct net_device *, const unsigned char *));
#endif
#ifndef NETDEV_HW_ADDR_T_MULTICAST
int __kc_dev_addr_sync_dev(struct dev_addr_list **list, int *count,
		struct net_device *dev,
		int (*sync)(struct net_device *, const unsigned char *),
		int (*unsync)(struct net_device *, const unsigned char *));
void __kc_dev_addr_unsync_dev(struct dev_addr_list **list, int *count,
		struct net_device *dev,
		int (*unsync)(struct net_device *, const unsigned char *));
#endif
#endif /* HAVE_SET_RX_MODE */

static inline int __kc_dev_uc_sync(struct net_device __maybe_unused *dev,
				   int __maybe_unused (*sync)(struct net_device *, const unsigned char *),
				   int __maybe_unused (*unsync)(struct net_device *, const unsigned char *))
{
#ifdef NETDEV_HW_ADDR_T_UNICAST
	return __kc_hw_addr_sync_dev(&dev->uc, dev, sync, unsync);
#elif defined(HAVE_SET_RX_MODE)
	return __kc_dev_addr_sync_dev(&dev->uc_list, &dev->uc_count,
				      dev, sync, unsync);
#else
	return 0;
#endif
}
#define __dev_uc_sync __kc_dev_uc_sync

static inline void __kc_dev_uc_unsync(struct net_device __maybe_unused *dev,
				      int __maybe_unused (*unsync)(struct net_device *, const unsigned char *))
{
#ifdef HAVE_SET_RX_MODE
#ifdef NETDEV_HW_ADDR_T_UNICAST
	__kc_hw_addr_unsync_dev(&dev->uc, dev, unsync);
#else /* NETDEV_HW_ADDR_T_MULTICAST */
	__kc_dev_addr_unsync_dev(&dev->uc_list, &dev->uc_count, dev, unsync);
#endif /* NETDEV_HW_ADDR_T_UNICAST */
#endif /* HAVE_SET_RX_MODE */
}
#define __dev_uc_unsync __kc_dev_uc_unsync

static inline int __kc_dev_mc_sync(struct net_device __maybe_unused *dev,
				   int __maybe_unused (*sync)(struct net_device *, const unsigned char *),
				   int __maybe_unused (*unsync)(struct net_device *, const unsigned char *))
{
#ifdef NETDEV_HW_ADDR_T_MULTICAST
	return __kc_hw_addr_sync_dev(&dev->mc, dev, sync, unsync);
#elif defined(HAVE_SET_RX_MODE)
	return __kc_dev_addr_sync_dev(&dev->mc_list, &dev->mc_count,
				      dev, sync, unsync);
#else
	return 0;
#endif

}
#define __dev_mc_sync __kc_dev_mc_sync

static inline void __kc_dev_mc_unsync(struct net_device __maybe_unused *dev,
				      int __maybe_unused (*unsync)(struct net_device *, const unsigned char *))
{
#ifdef HAVE_SET_RX_MODE
#ifdef NETDEV_HW_ADDR_T_MULTICAST
	__kc_hw_addr_unsync_dev(&dev->mc, dev, unsync);
#else /* NETDEV_HW_ADDR_T_MULTICAST */
	__kc_dev_addr_unsync_dev(&dev->mc_list, &dev->mc_count, dev, unsync);
#endif /* NETDEV_HW_ADDR_T_MULTICAST */
#endif /* HAVE_SET_RX_MODE */
}
#define __dev_mc_unsync __kc_dev_mc_unsync
#endif /* __dev_uc_sync */

#if RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,1))
#define HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
#endif

#ifndef NETIF_F_GSO_UDP_TUNNEL_CSUM
/* if someone backports this, hopefully they backport as a #define.
 * declare it as zero on older kernels so that if it get's or'd in
 * it won't effect anything, therefore preventing core driver changes
 */
#define NETIF_F_GSO_UDP_TUNNEL_CSUM 0
#define SKB_GSO_UDP_TUNNEL_CSUM 0
#endif
void *__kc_devm_kmemdup(struct device *dev, const void *src, size_t len,
			gfp_t gfp);
#define devm_kmemdup __kc_devm_kmemdup

#else
#if ( ( LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0) ) && \
      ! ( SLE_VERSION_CODE && ( SLE_VERSION_CODE >= SLE_VERSION(12,4,0)) ) )
#define HAVE_PCI_ERROR_HANDLER_RESET_NOTIFY
#endif /* >= 3.16.0 && < 4.13.0 && !(SLES >= 12sp4) */
#define HAVE_NDO_SET_VF_MIN_MAX_TX_RATE
#endif /* 3.16.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0) )
#if !(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,8) && \
      RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)) && \
    !(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,2))
#ifndef timespec64
#define timespec64 timespec
static inline struct timespec64 timespec_to_timespec64(const struct timespec ts)
{
	return ts;
}
static inline struct timespec timespec64_to_timespec(const struct timespec64 ts64)
{
	return ts64;
}
#define timespec64_equal timespec_equal
#define timespec64_compare timespec_compare
#define set_normalized_timespec64 set_normalized_timespec
#define timespec64_add_safe timespec_add_safe
#define timespec64_add timespec_add
#define timespec64_sub timespec_sub
#define timespec64_valid timespec_valid
#define timespec64_valid_strict timespec_valid_strict
#define timespec64_to_ns timespec_to_ns
#define ns_to_timespec64 ns_to_timespec
#define ktime_to_timespec64 ktime_to_timespec
#define ktime_get_ts64 ktime_get_ts
#define ktime_get_real_ts64 ktime_get_real_ts
#define timespec64_add_ns timespec_add_ns
#endif /* timespec64 */
#endif /* !(RHEL6.8<RHEL7.0) && !RHEL7.2+ */

#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,8) && \
     RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0))
static inline void ktime_get_real_ts64(struct timespec64 *ts)
{
	*ts = ktime_to_timespec64(ktime_get_real());
}

static inline void ktime_get_ts64(struct timespec64 *ts)
{
	*ts = ktime_to_timespec64(ktime_get());
}
#endif

#if !(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4))
#define hlist_add_behind(_a, _b) hlist_add_after(_b, _a)
#endif

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5))
#define param_ops_ullong _kc_param_ops_ullong
extern const struct kernel_param_ops _kc_param_ops_ullong;
#define param_set_ullong _kc_param_set_ullong
int _kc_param_set_ullong(const char *val, const struct kernel_param *kp);
#define param_get_ullong _kc_param_get_ullong
int _kc_param_get_ullong(char *buffer, const struct kernel_param *kp);
#define param_check_ullong(name, p) __param_check(name, p, unsigned long long)
#endif /* RHEL_RELEASE_CODE < RHEL7.5 */

#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,3))
static inline u64 ktime_get_ns(void)
{
	return ktime_to_ns(ktime_get());
}

static inline u64 ktime_get_real_ns(void)
{
	return ktime_to_ns(ktime_get_real());
}

static inline u64 ktime_get_boot_ns(void)
{
	return ktime_to_ns(ktime_get_boottime());
}
#endif /* RHEL < 7.3 */

#else
#define HAVE_DCBNL_OPS_SETAPP_RETURN_INT
#include <linux/time64.h>
#endif /* 3.17.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0) )
u32 __kc_eth_get_headlen(const struct net_device *dev, unsigned char *data,
			 unsigned int max_len);
#define eth_get_headlen __kc_eth_get_headlen
#ifndef ETH_P_XDSA
#define ETH_P_XDSA 0x00F8
#endif
/* RHEL 7.1 backported csum_level, but SLES 12 and 12-SP1 did not */
#if RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,1))
#define HAVE_SKBUFF_CSUM_LEVEL
#endif /* >= RH 7.1 */

/* RHEL 7.3 backported xmit_more */
#if (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3))
#define HAVE_SKB_XMIT_MORE
#endif /* >= RH 7.3 */

#undef GENMASK
#define GENMASK(h, l) \
	(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#undef GENMASK_ULL
#define GENMASK_ULL(h, l) \
	(((~0ULL) << (l)) & (~0ULL >> (BITS_PER_LONG_LONG - 1 - (h))))

#else /*  3.18.0 */
#define HAVE_SKBUFF_CSUM_LEVEL
#define HAVE_SKB_XMIT_MORE
#define HAVE_SKB_INNER_PROTOCOL_TYPE
#endif /* 3.18.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,18,4) )
#else
#define HAVE_NDO_FEATURES_CHECK
#endif /* 3.18.4 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,18,13) )
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val) ({ ACCESS_ONCE(x) = (val); })
#endif
#endif /* 3.18.13 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0) )
/* netdev_phys_port_id renamed to netdev_phys_item_id */
#define netdev_phys_item_id netdev_phys_port_id

static inline void _kc_napi_complete_done(struct napi_struct *napi,
					  int __always_unused work_done) {
	napi_complete(napi);
}
/* don't use our backport if the distro kernels already have it */
#if (SLE_VERSION_CODE && (SLE_VERSION_CODE < SLE_VERSION(12,3,0))) || \
    (RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5)))
#define napi_complete_done _kc_napi_complete_done
#endif

int _kc_bitmap_print_to_pagebuf(bool list, char *buf,
				const unsigned long *maskp, int nmaskbits);
#define bitmap_print_to_pagebuf _kc_bitmap_print_to_pagebuf

#ifndef NETDEV_RSS_KEY_LEN
#define NETDEV_RSS_KEY_LEN (13 * 4)
#endif
#if (!(RHEL_RELEASE_CODE && \
      ((RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,7) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)) || \
       (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,2)))))
#define netdev_rss_key_fill(buffer, len) __kc_netdev_rss_key_fill(buffer, len)
#endif /* RHEL_RELEASE_CODE */
void __kc_netdev_rss_key_fill(void *buffer, size_t len);
#define SPEED_20000 20000
#define SPEED_40000 40000
#ifndef dma_rmb
#define dma_rmb() rmb()
#endif
#ifndef dev_alloc_pages
#ifndef NUMA_NO_NODE
#define NUMA_NO_NODE -1
#endif
#define dev_alloc_pages(_order) alloc_pages_node(NUMA_NO_NODE, (GFP_ATOMIC | __GFP_COLD | __GFP_COMP | __GFP_MEMALLOC), (_order))
#endif
#ifndef dev_alloc_page
#define dev_alloc_page() dev_alloc_pages(0)
#endif
#if !defined(eth_skb_pad) && !defined(skb_put_padto)
/**
 *     __kc_skb_put_padto - increase size and pad an skbuff up to a minimal size
 *     @skb: buffer to pad
 *     @len: minimal length
 *
 *     Pads up a buffer to ensure the trailing bytes exist and are
 *     blanked. If the buffer already contains sufficient data it
 *     is untouched. Otherwise it is extended. Returns zero on
 *     success. The skb is freed on error.
 */
static inline int __kc_skb_put_padto(struct sk_buff *skb, unsigned int len)
{
	unsigned int size = skb->len;

	if (unlikely(size < len)) {
		len -= size;
		if (skb_pad(skb, len))
			return -ENOMEM;
		__skb_put(skb, len);
	}
	return 0;
}
#define skb_put_padto(skb, len) __kc_skb_put_padto(skb, len)

static inline int __kc_eth_skb_pad(struct sk_buff *skb)
{
	return __kc_skb_put_padto(skb, ETH_ZLEN);
}
#define eth_skb_pad(skb) __kc_eth_skb_pad(skb)
#endif /* eth_skb_pad && skb_put_padto */

#ifndef SKB_ALLOC_NAPI
/* RHEL 7.2 backported napi_alloc_skb and friends */
static inline struct sk_buff *__kc_napi_alloc_skb(struct napi_struct *napi, unsigned int length)
{
	return netdev_alloc_skb_ip_align(napi->dev, length);
}
#define napi_alloc_skb(napi,len) __kc_napi_alloc_skb(napi,len)
#define __napi_alloc_skb(napi,len,mask) __kc_napi_alloc_skb(napi,len)
#endif /* SKB_ALLOC_NAPI */
#define HAVE_CONFIG_PM_RUNTIME
#if (RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,7)) && \
     (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)))
#define HAVE_RXFH_HASHFUNC
#endif /* 6.7 < RHEL < 7.0 */
#if RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,1))
#define HAVE_RXFH_HASHFUNC
#define NDO_DFLT_BRIDGE_GETLINK_HAS_BRFLAGS
#endif /* RHEL > 7.1 */
#ifndef napi_schedule_irqoff
#define napi_schedule_irqoff	napi_schedule
#endif
#ifndef READ_ONCE
#define READ_ONCE(_x) ACCESS_ONCE(_x)
#endif
#if RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2))
#define HAVE_NDO_FDB_ADD_VID
#endif
#ifndef ETH_MODULE_SFF_8636
#define ETH_MODULE_SFF_8636		0x3
#endif
#ifndef ETH_MODULE_SFF_8636_LEN
#define ETH_MODULE_SFF_8636_LEN		256
#endif
#ifndef ETH_MODULE_SFF_8436
#define ETH_MODULE_SFF_8436		0x4
#endif
#ifndef ETH_MODULE_SFF_8436_LEN
#define ETH_MODULE_SFF_8436_LEN		256
#endif
#ifndef writel_relaxed
#define writel_relaxed	writel
#endif
#else /* 3.19.0 */
#define HAVE_NDO_FDB_ADD_VID
#define HAVE_RXFH_HASHFUNC
#define NDO_DFLT_BRIDGE_GETLINK_HAS_BRFLAGS
#endif /* 3.19.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(3,20,0) )
/* vlan_tx_xx functions got renamed to skb_vlan */
#ifndef skb_vlan_tag_get
#define skb_vlan_tag_get vlan_tx_tag_get
#endif
#ifndef skb_vlan_tag_present
#define skb_vlan_tag_present vlan_tx_tag_present
#endif
#if RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,1))
#define HAVE_INCLUDE_LINUX_TIMECOUNTER_H
#endif
#if RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2))
#define HAVE_NDO_BRIDGE_SET_DEL_LINK_FLAGS
#endif
#else
#define HAVE_INCLUDE_LINUX_TIMECOUNTER_H
#define HAVE_NDO_BRIDGE_SET_DEL_LINK_FLAGS
#endif /* 3.20.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0) )
/* Definition for CONFIG_OF was introduced earlier */
#if !defined(CONFIG_OF) && \
    !(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2))
static inline struct device_node *
pci_device_to_OF_node(const struct pci_dev __always_unused *pdev) { return NULL; }
#else /* !CONFIG_OF && RHEL < 7.3 */
#define HAVE_DDP_PROFILE_UPLOAD_SUPPORT
#endif /* !CONFIG_OF && RHEL < 7.3 */
#else /* < 4.0 */
#define HAVE_DDP_PROFILE_UPLOAD_SUPPORT
#endif /* < 4.0 */

/*****************************************************************************/
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0) )
#if ((RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,2))) || \
     (SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(12,2,0))))
#define HAVE_NDO_SET_VF_RSS_QUERY_EN
#endif
#if RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2))
#define HAVE_NDO_BRIDGE_GETLINK_NLFLAGS
#endif
#if !((RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(6,8) && RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)) && \
      (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2)) && \
      (SLE_VERSION_CODE > SLE_VERSION(12,1,0)))
unsigned int _kc_cpumask_local_spread(unsigned int i, int node);
#define cpumask_local_spread _kc_cpumask_local_spread
#endif
#else /* >= 4,1,0 */
#define HAVE_PTP_CLOCK_INFO_GETTIME64
#define HAVE_NDO_BRIDGE_GETLINK_NLFLAGS
#define HAVE_PASSTHRU_FEATURES_CHECK
#define HAVE_NDO_SET_VF_RSS_QUERY_EN
#define HAVE_NDO_SET_TX_MAXRATE
#endif /* 4,1,0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,1,9))
#if (!(RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2)) && \
     !((SLE_VERSION_CODE == SLE_VERSION(11,3,0)) && \
       (SLE_LOCALVERSION_CODE >= SLE_LOCALVERSION(0,47,71))) && \
     !((SLE_VERSION_CODE == SLE_VERSION(11,4,0)) && \
       (SLE_LOCALVERSION_CODE >= SLE_LOCALVERSION(65,0,0))) && \
     !(SLE_VERSION_CODE >= SLE_VERSION(12,1,0)))
static inline bool page_is_pfmemalloc(struct page __maybe_unused *page)
{
#ifdef HAVE_STRUCT_PAGE_PFMEMALLOC
	return page->pfmemalloc;
#else
	return false;
#endif
}
#endif /* !RHEL7.2+ && !SLES11sp3(3.0.101-0.47.71+ update) && !SLES11sp4(3.0.101-65+ update) & !SLES12sp1+ */
#else
#undef HAVE_STRUCT_PAGE_PFMEMALLOC
#endif /* 4.1.9 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0))
#if (!(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,2)) && \
     !(SLE_VERSION_CODE >= SLE_VERSION(12,1,0)))
#define ETHTOOL_RX_FLOW_SPEC_RING	0x00000000FFFFFFFFULL
#define ETHTOOL_RX_FLOW_SPEC_RING_VF	0x000000FF00000000ULL
#define ETHTOOL_RX_FLOW_SPEC_RING_VF_OFF 32
static inline __u64 ethtool_get_flow_spec_ring(__u64 ring_cookie)
{
	return ETHTOOL_RX_FLOW_SPEC_RING & ring_cookie;
};

static inline __u64 ethtool_get_flow_spec_ring_vf(__u64 ring_cookie)
{
	return (ETHTOOL_RX_FLOW_SPEC_RING_VF & ring_cookie) >>
				ETHTOOL_RX_FLOW_SPEC_RING_VF_OFF;
};
#endif /* ! RHEL >= 7.2 && ! SLES >= 12.1 */
#if (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4))
#define HAVE_NDO_DFLT_BRIDGE_GETLINK_VLAN_SUPPORT
#endif

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,27))
#if (!((RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,8) && \
	RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)) || \
       RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,2)))
static inline bool pci_ari_enabled(struct pci_bus *bus)
{
	return bus->self && bus->self->ari_enabled;
}
#endif /* !(RHEL6.8+ || RHEL7.2+) */
#else
static inline bool pci_ari_enabled(struct pci_bus *bus)
{
	return false;
}
#endif /* 2.6.27 */
#else
#define HAVE_NDO_DFLT_BRIDGE_GETLINK_VLAN_SUPPORT
#define HAVE_VF_STATS
#endif /* 4.2.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0))
#if (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3))
#define HAVE_NDO_SET_VF_TRUST
#endif /* (RHEL_RELEASE >= 7.3) */
#ifndef CONFIG_64BIT
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0))
#include <asm-generic/io-64-nonatomic-lo-hi.h>	/* 32-bit readq/writeq */
#else /* 3.3.0 => 4.3.x */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26))
#include <asm-generic/int-ll64.h>
#endif /* 2.6.26 => 3.3.0 */
#ifndef readq
static inline __u64 readq(const volatile void __iomem *addr)
{
	const volatile u32 __iomem *p = addr;
	u32 low, high;

	low = readl(p);
	high = readl(p + 1);

	return low + ((u64)high << 32);
}
#define readq readq
#endif

#ifndef writeq
static inline void writeq(__u64 val, volatile void __iomem *addr)
{
	writel(val, addr);
	writel(val >> 32, addr + 4);
}
#define writeq writeq
#endif
#endif /* < 3.3.0 */
#endif /* !CONFIG_64BIT */
#else /* < 4.4.0 */
#define HAVE_NDO_SET_VF_TRUST

#ifndef CONFIG_64BIT
#include <linux/io-64-nonatomic-lo-hi.h>	/* 32-bit readq/writeq */
#endif /* !CONFIG_64BIT */
#endif /* 4.4.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0))
/* protect against a likely backport */
#ifndef NETIF_F_CSUM_MASK
#define NETIF_F_CSUM_MASK NETIF_F_ALL_CSUM
#endif /* NETIF_F_CSUM_MASK */
#ifndef NETIF_F_SCTP_CRC
#define NETIF_F_SCTP_CRC NETIF_F_SCTP_CSUM
#endif /* NETIF_F_SCTP_CRC */
#if (!(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3)))
#define eth_platform_get_mac_address _kc_eth_platform_get_mac_address
int _kc_eth_platform_get_mac_address(struct device *dev __maybe_unused,
				     u8 *mac_addr __maybe_unused);
#endif /* !(RHEL_RELEASE >= 7.3) */
#else /* 4.5.0 */
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0) )
#define HAVE_GENEVE_RX_OFFLOAD
#if !defined(HAVE_UDP_ENC_TUNNEL) && IS_ENABLED(CONFIG_GENEVE)
#define HAVE_UDP_ENC_TUNNEL
#endif
#endif /* < 4.8.0 */
#define HAVE_NETIF_NAPI_ADD_CALLS_NAPI_HASH_ADD
#endif /* 4.5.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0))
#if !(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,3))
static inline unsigned char *skb_checksum_start(const struct sk_buff *skb)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22))
	return skb->head + skb->csum_start;
#else /* < 2.6.22 */
	return skb_transport_header(skb);
#endif
}
#endif

#if !(UBUNTU_VERSION_CODE && \
		UBUNTU_VERSION_CODE >= UBUNTU_VERSION(4,4,0,21)) && \
	!(RHEL_RELEASE_CODE && \
		(RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2))) && \
	!(SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(12,3,0)))
static inline void napi_consume_skb(struct sk_buff *skb,
				    int __always_unused budget)
{
	dev_consume_skb_any(skb);
}

#endif /* UBUNTU 4,4,0,21, RHEL 7.2, SLES12 SP3 */
#if !(SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(12,3,0))) && \
	!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4))
static inline void csum_replace_by_diff(__sum16 *sum, __wsum diff)
{
	* sum = csum_fold(csum_add(diff, ~csum_unfold(*sum)));
}
#endif
#if !(RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7,2))) && \
	!(SLE_VERSION_CODE && (SLE_VERSION_CODE > SLE_VERSION(12,3,0)))
static inline void page_ref_inc(struct page *page)
{
	get_page(page);
}
#else
#define HAVE_PAGE_COUNT_BULK_UPDATE
#endif
#ifndef IPV4_USER_FLOW
#define	IPV4_USER_FLOW	0x0d	/* spec only (usr_ip4_spec) */
#endif

#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4))
#define HAVE_TC_SETUP_CLSFLOWER
#define HAVE_TC_FLOWER_ENC
#endif

#if ((RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,7)) || \
     (SLE_VERSION_CODE >= SLE_VERSION(12,2,0)))
#define HAVE_TC_SETUP_CLSU32
#endif

#if (SLE_VERSION_CODE >= SLE_VERSION(12,2,0))
#define HAVE_TC_SETUP_CLSFLOWER
#endif

#else /* >= 4.6.0 */
#define HAVE_PAGE_COUNT_BULK_UPDATE
#define HAVE_ETHTOOL_FLOW_UNION_IP6_SPEC
#define HAVE_PTP_CROSSTIMESTAMP
#define HAVE_TC_SETUP_CLSFLOWER
#define HAVE_TC_SETUP_CLSU32
#endif /* 4.6.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0))
#if ((SLE_VERSION_CODE >= SLE_VERSION(12,3,0)) ||\
     (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4)))
#define HAVE_NETIF_TRANS_UPDATE
#endif /* SLES12sp3+ || RHEL7.4+ */
#if ((UBUNTU_VERSION_CODE >= UBUNTU_VERSION(4,4,0,21)) || \
     (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4)) || \
     (SLE_VERSION_CODE >= SLE_VERSION(12,3,0)))
#define HAVE_DEVLINK_SUPPORT
#endif /* UBUNTU 4,4,0,21, RHEL 7.4, SLES12 SP3 */
#if ((RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3)) ||\
     (SLE_VERSION_CODE >= SLE_VERSION(12,3,0)))
#define HAVE_ETHTOOL_25G_BITS
#define HAVE_ETHTOOL_50G_BITS
#define HAVE_ETHTOOL_100G_BITS
#endif /* RHEL7.3+ || SLES12sp3+ */
#else /* 4.7.0 */
#define HAVE_DEVLINK_SUPPORT
#define HAVE_NETIF_TRANS_UPDATE
#define HAVE_ETHTOOL_CONVERT_U32_AND_LINK_MODE
#define HAVE_ETHTOOL_25G_BITS
#define HAVE_ETHTOOL_50G_BITS
#define HAVE_ETHTOOL_100G_BITS
#define HAVE_TCF_MIRRED_REDIRECT
#endif /* 4.7.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0))
#if !(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4))
enum udp_parsable_tunnel_type {
	UDP_TUNNEL_TYPE_VXLAN,
	UDP_TUNNEL_TYPE_GENEVE,
};
struct udp_tunnel_info {
	unsigned short type;
	sa_family_t sa_family;
	__be16 port;
};
#endif

#if (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,5))
#define HAVE_TCF_EXTS_TO_LIST
#endif

#if (UBUNTU_VERSION_CODE && UBUNTU_VERSION_CODE < UBUNTU_VERSION(4,8,0,0))
#define tc_no_actions(_exts) true
#define tc_for_each_action(_a, _exts) while (0)
#endif
#if !(SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(12,3,0))) &&\
	!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4))
static inline int
#ifdef HAVE_NON_CONST_PCI_DRIVER_NAME
pci_request_io_regions(struct pci_dev *pdev, char *name)
#else
pci_request_io_regions(struct pci_dev *pdev, const char *name)
#endif
{
	return pci_request_selected_regions(pdev,
			    pci_select_bars(pdev, IORESOURCE_IO), name);
}

static inline void
pci_release_io_regions(struct pci_dev *pdev)
{
	return pci_release_selected_regions(pdev,
			    pci_select_bars(pdev, IORESOURCE_IO));
}

static inline int
#ifdef HAVE_NON_CONST_PCI_DRIVER_NAME
pci_request_mem_regions(struct pci_dev *pdev, char *name)
#else
pci_request_mem_regions(struct pci_dev *pdev, const char *name)
#endif
{
	return pci_request_selected_regions(pdev,
			    pci_select_bars(pdev, IORESOURCE_MEM), name);
}

static inline void
pci_release_mem_regions(struct pci_dev *pdev)
{
	return pci_release_selected_regions(pdev,
			    pci_select_bars(pdev, IORESOURCE_MEM));
}
#endif /* !SLE_VERSION(12,3,0) */
#if ((RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4)) ||\
     (SLE_VERSION_CODE >= SLE_VERSION(12,3,0)))
#define HAVE_ETHTOOL_NEW_50G_BITS
#endif /* RHEL7.4+ || SLES12sp3+ */
#else
#define HAVE_UDP_ENC_RX_OFFLOAD
#define HAVE_TCF_EXTS_TO_LIST
#define HAVE_ETHTOOL_NEW_50G_BITS
#endif /* 4.8.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0))
#ifdef HAVE_TC_SETUP_CLSFLOWER
#if (!(RHEL_RELEASE_CODE) && !(SLE_VERSION_CODE) || \
    (SLE_VERSION_CODE && (SLE_VERSION_CODE < SLE_VERSION(12,3,0))))
#define HAVE_TC_FLOWER_VLAN_IN_TAGS
#endif /* !RHEL_RELEASE_CODE && !SLE_VERSION_CODE || <SLE_VERSION(12,3,0) */
#endif /* HAVE_TC_SETUP_CLSFLOWER */
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4))
#define HAVE_ETHTOOL_NEW_1G_BITS
#define HAVE_ETHTOOL_NEW_10G_BITS
#endif /* RHEL7.4+ */
#if (!(SLE_VERSION_CODE) && !(RHEL_RELEASE_CODE)) || \
     SLE_VERSION_CODE && (SLE_VERSION_CODE <= SLE_VERSION(12,3,0)) || \
     RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7,5))
#define time_is_before_jiffies64(a)	time_after64(get_jiffies_64(), a)
#endif /* !SLE_VERSION_CODE && !RHEL_RELEASE_CODE || (SLES <= 12.3.0) || (RHEL <= 7.5) */
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,4))
static inline void bitmap_from_u64(unsigned long *dst, u64 mask)
{
	dst[0] = mask & ULONG_MAX;

	if (sizeof(mask) > sizeof(unsigned long))
		dst[1] = mask >> 32;
}
#endif /* <RHEL7.4 */
#else /* >=4.9 */
#define HAVE_FLOW_DISSECTOR_KEY_VLAN_PRIO
#define HAVE_ETHTOOL_NEW_1G_BITS
#define HAVE_ETHTOOL_NEW_10G_BITS
#endif /* KERNEL_VERSION(4.9.0) */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0))
/* SLES 12.3 and RHEL 7.5 backported this interface */
#if (!SLE_VERSION_CODE && !RHEL_RELEASE_CODE) || \
    (SLE_VERSION_CODE && (SLE_VERSION_CODE < SLE_VERSION(12,3,0))) || \
    (RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5)))
static inline bool _kc_napi_complete_done2(struct napi_struct *napi,
					   int __always_unused work_done)
{
	/* it was really hard to get napi_complete_done to be safe to call
	 * recursively without running into our own kcompat, so just use
	 * napi_complete
	 */
	napi_complete(napi);

	/* true means that the stack is telling the driver to go-ahead and
	 * re-enable interrupts
	 */
	return true;
}

#ifdef napi_complete_done
#undef napi_complete_done
#endif
#define napi_complete_done _kc_napi_complete_done2
#endif /* sles and rhel exclusion for < 4.10 */
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,4))
#define HAVE_DEV_WALK_API
#define HAVE_ETHTOOL_NEW_2500MB_BITS
#define HAVE_ETHTOOL_5G_BITS
#endif /* RHEL7.4+ */
#if (SLE_VERSION_CODE && (SLE_VERSION_CODE == SLE_VERSION(12,3,0)))
#define HAVE_STRUCT_DMA_ATTRS
#endif /* (SLES == 12.3.0) */
#if (SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(12,3,0)))
#define HAVE_NETDEVICE_MIN_MAX_MTU
#endif /* (SLES >= 12.3.0) */
#if (RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,5)))
#define HAVE_STRUCT_DMA_ATTRS
#define HAVE_RHEL7_EXTENDED_MIN_MAX_MTU
#define HAVE_NETDEVICE_MIN_MAX_MTU
#endif
#if (!(SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(12,3,0))) && \
     !(RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,5))))
#ifndef dma_map_page_attrs
#define dma_map_page_attrs __kc_dma_map_page_attrs
static inline dma_addr_t __kc_dma_map_page_attrs(struct device *dev,
						 struct page *page,
						 size_t offset, size_t size,
						 enum dma_data_direction dir,
						 unsigned long __always_unused attrs)
{
	return dma_map_page(dev, page, offset, size, dir);
}
#endif

#ifndef dma_unmap_page_attrs
#define dma_unmap_page_attrs __kc_dma_unmap_page_attrs
static inline void __kc_dma_unmap_page_attrs(struct device *dev,
					     dma_addr_t addr, size_t size,
					     enum dma_data_direction dir,
					     unsigned long __always_unused attrs)
{
	dma_unmap_page(dev, addr, size, dir);
}
#endif

static inline void __page_frag_cache_drain(struct page *page,
					   unsigned int count)
{
#ifdef HAVE_PAGE_COUNT_BULK_UPDATE
	if (!page_ref_sub_and_test(page, count))
		return;

	init_page_count(page);
#else
	BUG_ON(count > 1);
	if (!count)
		return;
#endif
	__free_pages(page, compound_order(page));
}
#endif /* !SLE_VERSION(12,3,0) && !RHEL_VERSION(7,5) */
#if ((SLE_VERSION_CODE && (SLE_VERSION_CODE > SLE_VERSION(12,3,0))) ||\
     (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,5)))
#define HAVE_SWIOTLB_SKIP_CPU_SYNC
#endif

#if ((SLE_VERSION_CODE && (SLE_VERSION_CODE < SLE_VERSION(15,0,0))) ||\
     (RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7,4))))
#define page_frag_free __free_page_frag
#endif
#ifndef ETH_MIN_MTU
#define ETH_MIN_MTU 68
#endif /* ETH_MIN_MTU */
#else /* >= 4.10 */
#define HAVE_TC_FLOWER_ENC
#define HAVE_NETDEVICE_MIN_MAX_MTU
#define HAVE_SWIOTLB_SKIP_CPU_SYNC
#define HAVE_NETDEV_TC_RESETS_XPS
#define HAVE_XPS_QOS_SUPPORT
#define HAVE_DEV_WALK_API
#define HAVE_ETHTOOL_NEW_2500MB_BITS
#define HAVE_ETHTOOL_5G_BITS
/* kernel 4.10 onwards, as part of busy_poll rewrite, new state were added
 * which is part of NAPI:state. If NAPI:state=NAPI_STATE_IN_BUSY_POLL,
 * it means napi_poll is invoked in busy_poll context
 */
#define HAVE_NAPI_STATE_IN_BUSY_POLL
#define HAVE_TCF_MIRRED_EGRESS_REDIRECT
#endif /* 4.10.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0))
#ifdef CONFIG_NET_RX_BUSY_POLL
#define HAVE_NDO_BUSY_POLL
#endif /* CONFIG_NET_RX_BUSY_POLL */
#if ((SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(12,3,0))) || \
     (RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,5))))
#define HAVE_VOID_NDO_GET_STATS64
#endif /* (SLES >= 12.3.0) && (RHEL >= 7.5) */

static inline void _kc_dev_kfree_skb_irq(struct sk_buff *skb)
{
	if (!skb)
		return;
	dev_kfree_skb_irq(skb);
}

#undef dev_kfree_skb_irq
#define dev_kfree_skb_irq _kc_dev_kfree_skb_irq

static inline void _kc_dev_consume_skb_irq(struct sk_buff *skb)
{
	if (!skb)
		return;
	dev_consume_skb_irq(skb);
}

#undef dev_consume_skb_irq
#define dev_consume_skb_irq _kc_dev_consume_skb_irq

static inline void _kc_dev_kfree_skb_any(struct sk_buff *skb)
{
	if (!skb)
		return;
	dev_kfree_skb_any(skb);
}

#undef dev_kfree_skb_any
#define dev_kfree_skb_any _kc_dev_kfree_skb_any

static inline void _kc_dev_consume_skb_any(struct sk_buff *skb)
{
	if (!skb)
		return;
	dev_consume_skb_any(skb);
}

#undef dev_consume_skb_any
#define dev_consume_skb_any _kc_dev_consume_skb_any

#else /* > 4.11 */
#define HAVE_VOID_NDO_GET_STATS64
#define HAVE_VM_OPS_FAULT_NO_VMA
#endif /* 4.11.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0))
#ifndef NL_SET_ERR_MSG_MOD
#define NL_SET_ERR_MSG_MOD(extack, msg) pr_err(KBUILD_MODNAME ": " msg)
#endif /* !NL_SET_ERR_MSG_MOD */
#endif /* 4.12 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0))
#if ((SLE_VERSION_CODE && (SLE_VERSION_CODE > SLE_VERSION(12,3,0))) || \
     (RHEL_RELEASE_CODE && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,5)))
#define HAVE_TCF_EXTS_HAS_ACTION
#endif
#define  PCI_EXP_LNKCAP_SLS_8_0GB 0x00000003 /* LNKCAP2 SLS Vector bit 2 */
#if (SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(12,4,0)))
#define HAVE_PCI_ERROR_HANDLER_RESET_PREPARE
#endif /* SLES >= 12sp4 */
#else /* > 4.13 */
#define HAVE_HWTSTAMP_FILTER_NTP_ALL
#define HAVE_NDO_SETUP_TC_CHAIN_INDEX
#define HAVE_PCI_ERROR_HANDLER_RESET_PREPARE
#define HAVE_PTP_CLOCK_DO_AUX_WORK
#endif /* 4.13.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0))
#ifdef ETHTOOL_GLINKSETTINGS
#ifndef ethtool_link_ksettings_del_link_mode
#define ethtool_link_ksettings_del_link_mode(ptr, name, mode)		\
	__clear_bit(ETHTOOL_LINK_MODE_ ## mode ## _BIT, (ptr)->link_modes.name)
#endif
#endif /* ETHTOOL_GLINKSETTINGS */
#if (SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(12,4,0)))
#define HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
#endif

#if (RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,5)))
#define HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
#define HAVE_RHEL7_NETDEV_OPS_EXT_NDO_SETUP_TC
#endif

#define TIMER_DATA_TYPE		unsigned long
#define TIMER_FUNC_TYPE		void (*)(TIMER_DATA_TYPE)

#define timer_setup(timer, callback, flags)				\
	__setup_timer((timer), (TIMER_FUNC_TYPE)(callback),		\
		      (TIMER_DATA_TYPE)(timer), (flags))

#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)

#ifndef xdp_do_flush_map
#define xdp_do_flush_map() do {} while (0)
#endif
struct _kc_xdp_buff {
	void *data;
	void *data_end;
	void *data_hard_start;
};
#define xdp_buff _kc_xdp_buff
struct _kc_bpf_prog {
};
#define bpf_prog _kc_bpf_prog
#ifndef DIV_ROUND_DOWN_ULL
#define DIV_ROUND_DOWN_ULL(ll, d) \
	({ unsigned long long _tmp = (ll); do_div(_tmp, d); _tmp; })
#endif /* DIV_ROUND_DOWN_ULL */
#else /* > 4.14 */
#define HAVE_XDP_SUPPORT
#define HAVE_NDO_SETUP_TC_REMOVE_TC_TO_NETDEV
#define HAVE_TCF_EXTS_HAS_ACTION
#endif /* 4.14.0 */

/*****************************************************************************/
#ifndef ETHTOOL_GLINKSETTINGS

#define __ETHTOOL_LINK_MODE_MASK_NBITS 32
#define ETHTOOL_LINK_MASK_SIZE BITS_TO_LONGS(__ETHTOOL_LINK_MODE_MASK_NBITS)

/**
 * struct ethtool_link_ksettings
 * @link_modes: supported and advertising, single item arrays
 * @link_modes.supported: bitmask of supported link speeds
 * @link_modes.advertising: bitmask of currently advertised speeds
 * @base: base link details
 * @base.speed: current link speed
 * @base.port: current port type
 * @base.duplex: current duplex mode
 * @base.autoneg: current autonegotiation settings
 *
 * This struct and the following macros provide a way to support the old
 * ethtool get/set_settings API on older kernels, but in the style of the new
 * GLINKSETTINGS API.  In this way, the same code can be used to support both
 * APIs as seemlessly as possible.
 *
 * It should be noted the old API only has support up to the first 32 bits.
 */
struct ethtool_link_ksettings {
	struct {
		u32 speed;
		u8 port;
		u8 duplex;
		u8 autoneg;
	} base;
	struct {
		unsigned long supported[ETHTOOL_LINK_MASK_SIZE];
		unsigned long advertising[ETHTOOL_LINK_MASK_SIZE];
	} link_modes;
};

#define ETHTOOL_LINK_NAME_advertising(mode) ADVERTISED_ ## mode
#define ETHTOOL_LINK_NAME_supported(mode) SUPPORTED_ ## mode
#define ETHTOOL_LINK_NAME(name) ETHTOOL_LINK_NAME_ ## name
#define ETHTOOL_LINK_CONVERT(name, mode) ETHTOOL_LINK_NAME(name)(mode)

/**
 * ethtool_link_ksettings_zero_link_mode
 * @ptr: ptr to ksettings struct
 * @name: supported or advertising
 */
#define ethtool_link_ksettings_zero_link_mode(ptr, name)\
	(*((ptr)->link_modes.name) = 0x0)

/**
 * ethtool_link_ksettings_add_link_mode
 * @ptr: ptr to ksettings struct
 * @name: supported or advertising
 * @mode: link mode to add
 */
#define ethtool_link_ksettings_add_link_mode(ptr, name, mode)\
	(*((ptr)->link_modes.name) |= (typeof(*((ptr)->link_modes.name)))ETHTOOL_LINK_CONVERT(name, mode))

/**
 * ethtool_link_ksettings_del_link_mode
 * @ptr: ptr to ksettings struct
 * @name: supported or advertising
 * @mode: link mode to delete
 */
#define ethtool_link_ksettings_del_link_mode(ptr, name, mode)\
	(*((ptr)->link_modes.name) &= ~(typeof(*((ptr)->link_modes.name)))ETHTOOL_LINK_CONVERT(name, mode))

/**
 * ethtool_link_ksettings_test_link_mode
 * @ptr: ptr to ksettings struct
 * @name: supported or advertising
 * @mode: link mode to add
 */
#define ethtool_link_ksettings_test_link_mode(ptr, name, mode)\
	(!!(*((ptr)->link_modes.name) & ETHTOOL_LINK_CONVERT(name, mode)))

/**
 * _kc_ethtool_ksettings_to_cmd - Convert ethtool_link_ksettings to ethtool_cmd
 * @ks: ethtool_link_ksettings struct
 * @cmd: ethtool_cmd struct
 *
 * Convert an ethtool_link_ksettings structure into the older ethtool_cmd
 * structure. We provide this in kcompat.h so that drivers can easily
 * implement the older .{get|set}_settings as wrappers around the new api.
 * Hence, we keep it prefixed with _kc_ to make it clear this isn't actually
 * a real function in the kernel.
 */
static inline void
_kc_ethtool_ksettings_to_cmd(struct ethtool_link_ksettings *ks,
			     struct ethtool_cmd *cmd)
{
	cmd->supported = (u32)ks->link_modes.supported[0];
	cmd->advertising = (u32)ks->link_modes.advertising[0];
	ethtool_cmd_speed_set(cmd, ks->base.speed);
	cmd->duplex = ks->base.duplex;
	cmd->autoneg = ks->base.autoneg;
	cmd->port = ks->base.port;
}

#endif /* !ETHTOOL_GLINKSETTINGS */

/*****************************************************************************/
#if ((LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)) || \
     (SLE_VERSION_CODE && (SLE_VERSION_CODE <= SLE_VERSION(12,3,0))) || \
     (RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7,5))))
#define phy_speed_to_str _kc_phy_speed_to_str
const char *_kc_phy_speed_to_str(int speed);
#else /* (LINUX >= 4.14.0) || (SLES > 12.3.0) || (RHEL > 7.5) */
#include <linux/phy.h>
#endif /* (LINUX < 4.14.0) || (SLES <= 12.3.0) || (RHEL <= 7.5) */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
#if ((RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,6))) || \
     (SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(15,1,0))))
#define HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
#define HAVE_TCF_BLOCK
#else /* RHEL >= 7.6 || SLES >= 15.1 */
#define TC_SETUP_QDISC_MQPRIO TC_SETUP_MQPRIO
#endif /* !(RHEL >= 7.6) && !(SLES >= 15.1) */
void _kc_ethtool_intersect_link_masks(struct ethtool_link_ksettings *dst,
				      struct ethtool_link_ksettings *src);
#define ethtool_intersect_link_masks _kc_ethtool_intersect_link_masks
#else /* >= 4.15 */
#define HAVE_NDO_BPF
#define HAVE_XDP_BUFF_DATA_META
#define HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
#define HAVE_TCF_BLOCK
#endif /* 4.15.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,16,0))
#if (!(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,7)) && \
     !(SLE_VERSION_CODE >= SLE_VERSION(12,4,0) && \
       SLE_VERSION_CODE < SLE_VERSION(15,0,0)) && \
     !(SLE_VERSION_CODE >= SLE_VERSION(15,1,0)))
/* The return value of the strscpy() and strlcpy() functions is different.
 * This could be potentially hazard for the future.
 * To avoid this the void result is forced.
 * So it is not possible use this function with the return value.
 * Return value is required in kernel 4.3 through 4.15
 */
#define strscpy(...) (void)(strlcpy(__VA_ARGS__))
#endif /* !RHEL >= 7.7 && !SLES12sp4+ && !SLES15sp1+ */

#define pci_printk(level, pdev, fmt, arg...) \
	dev_printk(level, &(pdev)->dev, fmt, ##arg)
#define pci_emerg(pdev, fmt, arg...)	dev_emerg(&(pdev)->dev, fmt, ##arg)
#define pci_alert(pdev, fmt, arg...)	dev_alert(&(pdev)->dev, fmt, ##arg)
#define pci_crit(pdev, fmt, arg...)	dev_crit(&(pdev)->dev, fmt, ##arg)
#define pci_err(pdev, fmt, arg...)	dev_err(&(pdev)->dev, fmt, ##arg)
#define pci_warn(pdev, fmt, arg...)	dev_warn(&(pdev)->dev, fmt, ##arg)
#define pci_notice(pdev, fmt, arg...)	dev_notice(&(pdev)->dev, fmt, ##arg)
#define pci_info(pdev, fmt, arg...)	dev_info(&(pdev)->dev, fmt, ##arg)
#define pci_dbg(pdev, fmt, arg...)	dev_dbg(&(pdev)->dev, fmt, ##arg)

#ifndef array_index_nospec
static inline unsigned long _kc_array_index_mask_nospec(unsigned long index,
							unsigned long size)
{
	/*
	 * Always calculate and emit the mask even if the compiler
	 * thinks the mask is not needed. The compiler does not take
	 * into account the value of @index under speculation.
	 */
	OPTIMIZER_HIDE_VAR(index);
	return ~(long)(index | (size - 1UL - index)) >> (BITS_PER_LONG - 1);
}

#define array_index_nospec(index, size)					\
({									\
	typeof(index) _i = (index);					\
	typeof(size) _s = (size);					\
	unsigned long _mask = _kc_array_index_mask_nospec(_i, _s);	\
									\
	BUILD_BUG_ON(sizeof(_i) > sizeof(long));			\
	BUILD_BUG_ON(sizeof(_s) > sizeof(long));			\
									\
	(typeof(_i)) (_i & _mask);					\
})
#endif /* array_index_nospec */
#if (!(RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,6))) && \
     !(SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(15,1,0))))
#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
#include <net/pkt_cls.h>
static inline bool
tc_cls_can_offload_and_chain0(const struct net_device *dev,
			      struct tc_cls_common_offload *common)
{
	if (!tc_can_offload(dev))
		return false;
	if (common->chain_index)
		return false;

	return true;
}
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
#endif /* !(RHEL >= 7.6) && !(SLES >= 15.1) */
#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) (sizeof((((TYPE *)0)->MEMBER)))
#endif /* sizeof_field */
#else /* >= 4.16 */
#include <linux/nospec.h>
#define HAVE_XDP_BUFF_RXQ
#define HAVE_TC_FLOWER_OFFLOAD_COMMON_EXTACK
#define HAVE_TCF_MIRRED_DEV
#define HAVE_VF_STATS_DROPPED
#endif /* 4.16.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0))
#include <linux/pci_regs.h>
#include <linux/pci.h>
#define PCIE_SPEED_16_0GT 0x17
#define PCI_EXP_LNKCAP_SLS_16_0GB 0x00000004 /* LNKCAP2 SLS Vector bit 3 */
#define PCI_EXP_LNKSTA_CLS_16_0GB 0x0004 /* Current Link Speed 16.0GT/s */
#define PCI_EXP_LNKCAP2_SLS_16_0GB 0x00000010 /* Supported Speed 16GT/s */
void _kc_pcie_print_link_status(struct pci_dev *dev);
#define pcie_print_link_status _kc_pcie_print_link_status
#else /* >= 4.17.0 */
#define HAVE_XDP_BUFF_IN_XDP_H
#endif /* 4.17.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0))
#ifdef NETIF_F_HW_L2FW_DOFFLOAD
#include <linux/if_macvlan.h>
#ifndef macvlan_supports_dest_filter
#define macvlan_supports_dest_filter _kc_macvlan_supports_dest_filter
static inline bool _kc_macvlan_supports_dest_filter(struct net_device *dev)
{
	struct macvlan_dev *macvlan = netdev_priv(dev);

	return macvlan->mode == MACVLAN_MODE_PRIVATE ||
	       macvlan->mode == MACVLAN_MODE_VEPA ||
	       macvlan->mode == MACVLAN_MODE_BRIDGE;
}
#endif

#if (!SLE_VERSION_CODE || (SLE_VERSION_CODE < SLE_VERSION(15,1,0)))
#ifndef macvlan_accel_priv
#define macvlan_accel_priv _kc_macvlan_accel_priv
static inline void *_kc_macvlan_accel_priv(struct net_device *dev)
{
	struct macvlan_dev *macvlan = netdev_priv(dev);

	return macvlan->fwd_priv;
}
#endif

#ifndef macvlan_release_l2fw_offload
#define macvlan_release_l2fw_offload _kc_macvlan_release_l2fw_offload
static inline int _kc_macvlan_release_l2fw_offload(struct net_device *dev)
{
	struct macvlan_dev *macvlan = netdev_priv(dev);

	macvlan->fwd_priv = NULL;
	return dev_uc_add(macvlan->lowerdev, dev->dev_addr);
}
#endif
#endif /* !SLES || SLES < 15.1 */
#endif /* NETIF_F_HW_L2FW_DOFFLOAD */

#if (SLE_VERSION_CODE < SLE_VERSION(15,1,0))
#define firmware_request_nowarn	request_firmware_direct
#endif /* !SLES || SLES < 15.1 */

#else
#include <net/xdp_sock.h>
#define HAVE_XDP_FRAME_STRUCT
#define HAVE_XDP_SOCK
#define HAVE_NDO_XDP_XMIT_BULK_AND_FLAGS
#define NO_NDO_XDP_FLUSH
#define HAVE_AF_XDP_SUPPORT
#ifndef xdp_umem_get_data
static inline char *__kc_xdp_umem_get_data(struct xdp_umem *umem, u64 addr)
{
	return umem->pages[addr >> PAGE_SHIFT].addr + (addr & (PAGE_SIZE - 1));
}

#define xdp_umem_get_data __kc_xdp_umem_get_data
#endif /* !xdp_umem_get_data */
#ifndef xdp_umem_get_dma
static inline dma_addr_t __kc_xdp_umem_get_dma(struct xdp_umem *umem, u64 addr)
{
	return umem->pages[addr >> PAGE_SHIFT].dma + (addr & (PAGE_SIZE - 1));
}

#define xdp_umem_get_dma __kc_xdp_umem_get_dma
#endif /* !xdp_umem_get_dma */
#endif /* 4.18.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0))
#define bitmap_alloc(nbits, flags) \
	kmalloc_array(BITS_TO_LONGS(nbits), sizeof(unsigned long), flags)
#define bitmap_zalloc(nbits, flags) bitmap_alloc(nbits, ((flags) | __GFP_ZERO))
#define bitmap_free(bitmap) kfree(bitmap)
#ifdef ETHTOOL_GLINKSETTINGS
#define ethtool_ks_clear(ptr, name) \
	ethtool_link_ksettings_zero_link_mode(ptr, name)
#define ethtool_ks_add_mode(ptr, name, mode) \
	ethtool_link_ksettings_add_link_mode(ptr, name, mode)
#define ethtool_ks_del_mode(ptr, name, mode) \
	ethtool_link_ksettings_del_link_mode(ptr, name, mode)
#define ethtool_ks_test(ptr, name, mode) \
	ethtool_link_ksettings_test_link_mode(ptr, name, mode)
#endif /* ETHTOOL_GLINKSETTINGS */
#define HAVE_NETPOLL_CONTROLLER
#define REQUIRE_PCI_CLEANUP_AER_ERROR_STATUS
#if (SLE_VERSION_CODE && (SLE_VERSION_CODE >= SLE_VERSION(15,1,0)))
#define HAVE_TCF_MIRRED_DEV
#define HAVE_NDO_SELECT_QUEUE_SB_DEV
#define HAVE_TCF_BLOCK_CB_REGISTER_EXTACK
#endif
#if ((RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8,0)) ||\
     (SLE_VERSION_CODE >= SLE_VERSION(15,1,0)))
#define HAVE_TCF_EXTS_FOR_EACH_ACTION
#undef HAVE_TCF_EXTS_TO_LIST
#endif /* RHEL8.0+ */
#else /* >= 4.19.0 */
#define HAVE_TCF_BLOCK_CB_REGISTER_EXTACK
#define NO_NETDEV_BPF_PROG_ATTACHED
#define HAVE_NDO_SELECT_QUEUE_SB_DEV
#define HAVE_NETDEV_SB_DEV
#undef HAVE_TCF_EXTS_TO_LIST
#define HAVE_TCF_EXTS_FOR_EACH_ACTION
#define HAVE_TCF_VLAN_TPID
#endif /* 4.19.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,20,0))
#define HAVE_XDP_UMEM_PROPS
#ifdef HAVE_AF_XDP_SUPPORT
#ifndef napi_if_scheduled_mark_missed
static inline bool __kc_napi_if_scheduled_mark_missed(struct napi_struct *n)
{
	unsigned long val, new;

	do {
		val = READ_ONCE(n->state);
		if (val & NAPIF_STATE_DISABLE)
			return true;

		if (!(val & NAPIF_STATE_SCHED))
			return false;

		new = val | NAPIF_STATE_MISSED;
	} while (cmpxchg(&n->state, val, new) != val);

	return true;
}

#define napi_if_scheduled_mark_missed __kc_napi_if_scheduled_mark_missed
#endif /* !napi_if_scheduled_mark_missed */
#endif /* HAVE_AF_XDP_SUPPORT */
#else /* >= 4.20.0 */
#define HAVE_AF_XDP_ZC_SUPPORT
#define HAVE_VXLAN_TYPE
#endif /* 4.20.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0))
#if (!(RHEL_RELEASE_CODE && RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(8,0)))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0))
#define NETLINK_MAX_COOKIE_LEN	20
struct netlink_ext_ack {
	const char *_msg;
	const struct nlattr *bad_attr;
	u8 cookie[NETLINK_MAX_COOKIE_LEN];
	u8 cookie_len;
};

#endif /* < 4.12 */
static inline int _kc_dev_open(struct net_device *netdev,
			       struct netlink_ext_ack __always_unused *extack)
{
	return dev_open(netdev);
}

#define dev_open _kc_dev_open
#endif /* !(RHEL_RELEASE_CODE && RHEL > RHEL(8,0)) */
#if (RHEL_RELEASE_CODE && \
     (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,7) && \
      RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8,0)) || \
     (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8,1)))
#define HAVE_PTP_SYS_OFFSET_EXTENDED_IOCTL
#else /* RHEL >= 7.7 && RHEL < 8.0 || RHEL >= 8.1 */
struct ptp_system_timestamp {
	struct timespec64 pre_ts;
	struct timespec64 post_ts;
};

static inline void
ptp_read_system_prets(struct ptp_system_timestamp __always_unused *sts)
{
	;
}

static inline void
ptp_read_system_postts(struct ptp_system_timestamp __always_unused *sts)
{
	;
}
#endif /* !(RHEL >= 7.7 && RHEL != 8.0) */
#if (RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8,1)))
#define HAVE_NDO_BRIDGE_SETLINK_EXTACK
#endif /* RHEL 8.1 */
#else /* >= 5.0.0 */
#define HAVE_PTP_SYS_OFFSET_EXTENDED_IOCTL
#define HAVE_NDO_BRIDGE_SETLINK_EXTACK
#define HAVE_DMA_ALLOC_COHERENT_ZEROES_MEM
#define HAVE_GENEVE_TYPE
#define HAVE_TC_INDIR_BLOCK
#endif /* 5.0.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,1,0))
#if (RHEL_RELEASE_CODE && (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8,1)))
#define HAVE_TC_FLOW_RULE_INFRASTRUCTURE
#define HAVE_NDO_FDB_ADD_EXTACK
#else /* RHEL < 8.1 */
#ifdef HAVE_TC_SETUP_CLSFLOWER
#include <net/pkt_cls.h>

struct flow_match {
	struct flow_dissector	*dissector;
	void			*mask;
	void			*key;
};

struct flow_match_basic {
	struct flow_dissector_key_basic *key, *mask;
};

struct flow_match_control {
	struct flow_dissector_key_control *key, *mask;
};

struct flow_match_eth_addrs {
	struct flow_dissector_key_eth_addrs *key, *mask;
};

#ifdef HAVE_TC_FLOWER_ENC
struct flow_match_enc_keyid {
	struct flow_dissector_key_keyid *key, *mask;
};
#endif

#ifndef HAVE_TC_FLOWER_VLAN_IN_TAGS
struct flow_match_vlan {
	struct flow_dissector_key_vlan *key, *mask;
};
#endif

struct flow_match_ipv4_addrs {
	struct flow_dissector_key_ipv4_addrs *key, *mask;
};

struct flow_match_ipv6_addrs {
	struct flow_dissector_key_ipv6_addrs *key, *mask;
};

struct flow_match_ports {
	struct flow_dissector_key_ports *key, *mask;
};

struct flow_rule {
	struct flow_match	match;
};

void flow_rule_match_basic(const struct flow_rule *rule,
			   struct flow_match_basic *out);
void flow_rule_match_control(const struct flow_rule *rule,
			     struct flow_match_control *out);
void flow_rule_match_eth_addrs(const struct flow_rule *rule,
			       struct flow_match_eth_addrs *out);
#ifndef HAVE_TC_FLOWER_VLAN_IN_TAGS
void flow_rule_match_vlan(const struct flow_rule *rule,
			  struct flow_match_vlan *out);
#endif
void flow_rule_match_ipv4_addrs(const struct flow_rule *rule,
				struct flow_match_ipv4_addrs *out);
void flow_rule_match_ipv6_addrs(const struct flow_rule *rule,
				struct flow_match_ipv6_addrs *out);
void flow_rule_match_ports(const struct flow_rule *rule,
			   struct flow_match_ports *out);
#ifdef HAVE_TC_FLOWER_ENC
void flow_rule_match_enc_ports(const struct flow_rule *rule,
			       struct flow_match_ports *out);
void flow_rule_match_enc_control(const struct flow_rule *rule,
				 struct flow_match_control *out);
void flow_rule_match_enc_ipv4_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv4_addrs *out);
void flow_rule_match_enc_ipv6_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv6_addrs *out);
void flow_rule_match_enc_keyid(const struct flow_rule *rule,
			       struct flow_match_enc_keyid *out);
#endif

static inline struct flow_rule *
tc_cls_flower_offload_flow_rule(struct tc_cls_flower_offload *tc_flow_cmd)
{
	return (struct flow_rule *)&tc_flow_cmd->dissector;
}

static inline bool flow_rule_match_key(const struct flow_rule *rule,
				       enum flow_dissector_key_id key)
{
	return dissector_uses_key(rule->match.dissector, key);
}
#endif /* HAVE_TC_SETUP_CLSFLOWER */

#endif /* RHEL < 8.1 */
#else /* >= 5.1.0 */
#define HAVE_NDO_FDB_ADD_EXTACK
#define NO_XDP_QUERY_XSK_UMEM
#define HAVE_TC_FLOW_RULE_INFRASTRUCTURE
#define HAVE_TC_FLOWER_ENC_IP
#endif /* 5.1.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0))
#ifdef HAVE_SKB_XMIT_MORE
#define netdev_xmit_more()	(skb->xmit_more)
#else
#define netdev_xmit_more()	(0)
#endif

#ifndef eth_get_headlen
static inline u32
__kc_eth_get_headlen(const struct net_device __always_unused *dev, void *data,
		     unsigned int len)
{
	return eth_get_headlen(data, len);
}

#define eth_get_headlen(dev, data, len) __kc_eth_get_headlen(dev, data, len)
#endif /* !eth_get_headlen */

#ifndef mmiowb
#ifdef CONFIG_IA64
#define mmiowb() asm volatile ("mf.a" ::: "memory")
#else
#define mmiowb()
#endif
#endif /* mmiowb */

#else /* >= 5.2.0 */
#define HAVE_NDO_SELECT_QUEUE_FALLBACK_REMOVED
#define SPIN_UNLOCK_IMPLIES_MMIOWB
#endif /* 5.2.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0))
#define flow_block_offload tc_block_offload
#define flow_block_command tc_block_command
#define flow_block_binder_type tcf_block_binder_type
#define flow_cls_offload tc_cls_flower_offload
#define flow_cls_common_offload tc_cls_common_offload
#define flow_cls_offload_flow_rule tc_cls_flower_offload_flow_rule
#define FLOW_CLS_REPLACE TC_CLSFLOWER_REPLACE
#define FLOW_CLS_DESTROY TC_CLSFLOWER_DESTROY
#define FLOW_CLS_STATS TC_CLSFLOWER_STATS
#define FLOW_CLS_TMPLT_CREATE TC_CLSFLOWER_TMPLT_CREATE
#define FLOW_CLS_TMPLT_DESTROY TC_CLSFLOWER_TMPLT_DESTROY
#define FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS \
		TCF_BLOCK_BINDER_TYPE_CLSACT_INGRESS
#define FLOW_BLOCK_BIND TC_BLOCK_BIND
#define FLOW_BLOCK_UNBIND TC_BLOCK_UNBIND

#ifdef HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO
#include <net/pkt_cls.h>

int _kc_flow_block_cb_setup_simple(struct flow_block_offload *f,
				   struct list_head *driver_list,
				   tc_setup_cb_t *cb,
				   void *cb_ident, void *cb_priv,
				   bool ingress_only);

#define flow_block_cb_setup_simple(f, driver_list, cb, cb_ident, cb_priv, \
				   ingress_only) \
	_kc_flow_block_cb_setup_simple(f, driver_list, cb, cb_ident, cb_priv, \
				       ingress_only)
#endif /* HAVE_TC_CB_AND_SETUP_QDISC_MQPRIO */
#else /* >= 5.3.0 */
#define XSK_UMEM_RETURNS_XDP_DESC
#define HAVE_FLOW_BLOCK_API
#endif /* 5.3.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0))
static inline unsigned int skb_frag_off(const skb_frag_t *frag)
{
	return frag->page_offset;
}

static inline void skb_frag_off_add(skb_frag_t *frag, int delta)
{
	frag->page_offset += delta;
}

#define __flow_indr_block_cb_register __tc_indr_block_cb_register
#define __flow_indr_block_cb_unregister __tc_indr_block_cb_unregister
#else /* >= 5.4.0 */
#define HAVE_NDO_XSK_WAKEUP
#endif /* 5.4.0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0))
#ifdef HAVE_AF_XDP_SUPPORT
#define xsk_umem_release_addr		xsk_umem_discard_addr
#define xsk_umem_release_addr_rq	xsk_umem_discard_addr_rq
#endif /* HAVE_AF_XDP_SUPPORT */
#else /* >= 5.6.0 */
#define HAVE_TX_TIMEOUT_TXQUEUE
#endif /* 5.6.0 */

#endif /* _KCOMPAT_H_ */
