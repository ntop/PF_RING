/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _KCOMPAT_RHEL_DEFS_H_
#define _KCOMPAT_RHEL_DEFS_H_

/* This is the RedHat Enterprise Linux distribution specific definitions file.
 * It defines what features need backports for a given version of the RHEL
 * kernel.
 *
 * It checks the RHEL_RELEASE_CODE and RHEL_RELEASE_VERSION macros to decide
 * what support the target kernel has.
 *
 * It assumes that kcompat_std_defs.h has already been processed, and will
 * #define or #undef any flags that have changed based on backports done by
 * RHEL.
 */

#if !RHEL_RELEASE_CODE
#error "RHEL_RELEASE_CODE is 0 or undefined"
#endif

#ifndef RHEL_RELEASE_VERSION
#error "RHEL_RELEASE_VERSION is undefined"
#endif

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,3))
#define NEED_NETDEV_TXQ_BQL_PREFETCH
#else /* >= 7.3 */
#endif /* 7.3 */

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,4))
#define NEED_BUILD_BUG_ON
#else /* >= 7.4 */
#define HAVE_RHEL7_EXTENDED_OFFLOAD_STATS
#endif /* 7.4 */

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,5))
#else /* >= 7.5 */
#define HAVE_FLOW_DISSECTOR_KEY_IP
#endif /* 7.5 */

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,6))
#undef HAVE_XDP_BUFF_RXQ
#undef HAVE_XDP_RXQ_INFO_REG_3_PARAMS
#else /* >= 7.6 */
#undef NEED_JIFFIES_64_TIME_IS_MACROS
#undef NEED_TC_CLS_CAN_OFFLOAD_AND_CHAIN0
#undef NEED_TC_SETUP_QDISC_MQPRIO
#endif /* 7.6 */

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,7))
#else /* >= 7.7 */
#define HAVE_DEVLINK_PORT_ATTRS_SET_PORT_FLAVOUR
#define HAVE_ETHTOOL_NEW_100G_BITS
#undef NEED_IN_TASK
#define HAVE_FLOW_DISSECTOR_KEY_ENC_IP
#endif /* 7.7 */

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8,0))
#else /* >= 8.0 */
#undef HAVE_ETHTOOL_NEW_100G_BITS
#define HAVE_NDO_OFFLOAD_STATS
#undef HAVE_RHEL7_EXTENDED_OFFLOAD_STATS
#endif /* 8.0 */

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8,1))
#define NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
#else /* >= 8.1 */
#define HAVE_ETHTOOL_NEW_100G_BITS
#undef NEED_IDA_ALLOC_MIN_MAX_RANGE_FREE
#undef NEED_INDIRECT_CALL_WRAPPER_MACROS
#define HAVE_INDIRECT_CALL_WRAPPER_HEADER
#endif /* 8.1 */

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8,2))
#else /* >= 8.2 */
#undef NEED_FLOW_INDR_BLOCK_CB_REGISTER
#define HAVE_FLOW_INDR_BLOCK_LOCK
#define HAVE_DEVLINK_PORT_ATTRS_SET_SWITCH_ID
#define HAVE_NETDEV_SB_DEV
#endif /* 8.2 */

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8,3))
#else /* >= 8.3 */
#undef NEED_CPU_LATENCY_QOS_RENAME
#define HAVE_RT_IRQ_SCHED_FIX
#endif /* 8.3 */

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8,4))
#else /* >= 8.4 */
#undef NEED_DEVLINK_PORT_ATTRS_SET_STRUCT
#undef HAVE_XDP_QUERY_PROG
#define HAVE_AF_XDP_ZC_SUPPORT
#define HAVE_MEM_TYPE_XSK_BUFF_POOL
#define HAVE_NDO_XSK_WAKEUP
#define XSK_UMEM_RETURNS_XDP_DESC
#undef NEED_XSK_UMEM_GET_RX_FRAME_SIZE
#define HAVE_ETHTOOL_COALESCE_PARAMS_SUPPORT
#endif /* 8.4 */

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8,5))
#else /* >= 8.5 */
#undef HAVE_NAPI_BUSY_LOOP
#undef HAVE_XDP_RXQ_INFO_REG_3_PARAMS
#define NO_XDP_QUERY_XSK_UMEM
#undef NEED_XSK_BUFF_POOL_RENAME
#define HAVE_NETDEV_BPF_XSK_POOL
#define HAVE_AF_XDP_NETDEV_UMEM
#define HAVE_DEVLINK_OPS_CREATE_DEL
#endif /* 8.5 */

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8,7))
#else /* >= 8.7 */
#undef NEED_DEVLINK_ALLOC_SETS_DEV
#define HAVE_DEVLINK_SET_STATE_3_PARAM
#endif /* 8.7 */

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(9,0))
#else /* >= 9.0 */
#define HAVE_XDP_BUFF_RXQ
#endif /* 9.0 */

/*****************************************************************************/
#endif /* _KCOMPAT_RHEL_DEFS_H_ */
