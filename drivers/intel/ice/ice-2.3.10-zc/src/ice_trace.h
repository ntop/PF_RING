/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#if !IS_ENABLED(CONFIG_TRACEPOINTS) || defined(__CHECKER__)
#if !defined(_ICE_TRACE_H_)
#define _ICE_TRACE_H_
/* If the Linux kernel tracepoints are not available then the ice_trace*
 * macros become nops.
 */

#define ice_trace(trace_name, args...)
#define ice_trace_enabled(trace_name) (0)
#endif /* !defined(_ICE_TRACE_H_) */
#else /* CONFIG_TRACEPOINTS */
/*
 * Modeled on trace-events-sample.h
 */

/*
 * The trace subsystem name for ice will be "ice".
 *
 * This file is named ice_trace.h.
 *
 * Since this include file's name is different from the trace
 * subsystem name, we'll have to define TRACE_INCLUDE_FILE at the end
 * of this file.
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ice

/*
 * See trace-events-sample.h for a detailed description of why this
 * guard clause is different from most normal include files.
 */
#if !defined(_ICE_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _ICE_TRACE_H_

#include "ice_txrx.h"
#include "ice_ptp.h"
#include <linux/ptp_classify.h>
#include <linux/tracepoint.h>

/*
 * ice_trace() enables trace points
 * like:
 *
 * trace_ice_example(args...)
 *
 * ... as:
 *
 * ice_trace(example, args...)
 *
 * ... to resolve to the PF version of the tracepoint without
 * ifdefs, and to allow tracepoints to be disabled entirely at build
 * time.
 *
 * Trace point should always be referred to in the driver via this
 * macro.
 *
 * Similarly, ice_trace_enabled(trace_name) wraps references to
 * trace_ice_<trace_name>_enabled() functions.
 * @trace_name: name of tracepoint
 */
#define _ICE_TRACE_NAME(trace_name) (trace_##ice##_##trace_name)
#define ICE_TRACE_NAME(trace_name) _ICE_TRACE_NAME(trace_name)

#define ice_trace(trace_name, args...) ICE_TRACE_NAME(trace_name)(args)

#ifdef HAVE_TRACE_ENABLED_SUPPORT
#define ice_trace_enabled(trace_name) ICE_TRACE_NAME(trace_name##_enabled)()
#else /* HAVE_TRACE_ENABLED_SUPPORT */
#define ice_trace_enabled(trace_name) true
#endif /* HAVE_TRACE_ENABLED_SUPPORT */

/*
 * This is for events common to PF. Corresponding versions will be named
 * trace_ice_*. The ice_trace() macro above will select the right trace point
 * name for the driver.
 */

/* Begin tracepoints */

/* Global tracepoints */
DECLARE_EVENT_CLASS(ice_print_msg,
		    TP_PROTO(char *msg),

		    TP_ARGS(msg),

		    TP_STRUCT__entry(__string(msg, msg)),

#ifdef HAVE_ASSIGN_STR_2_PARAMS
		    TP_fast_assign(__assign_str(msg, msg);),
#else
		    TP_fast_assign(__assign_str(msg);),
#endif /* HAVE_ASSIGN_STR_2_PARAMS */

		    TP_printk("%s", __get_str(msg)));

#define DEFINE_PRINT_MSG_EVENT(name) \
DEFINE_EVENT(ice_print_msg, name, \
	     TP_PROTO(char *msg), \
	     TP_ARGS(msg))

DEFINE_PRINT_MSG_EVENT(ice_print_err);
DEFINE_PRINT_MSG_EVENT(ice_print_warn);
DEFINE_PRINT_MSG_EVENT(ice_print_adminq_msg);
DEFINE_PRINT_MSG_EVENT(ice_print_adminq_desc);
DEFINE_PRINT_MSG_EVENT(ice_print_netdev_err);
DEFINE_PRINT_MSG_EVENT(ice_print_netdev_warn);
DEFINE_PRINT_MSG_EVENT(ice_print_netdev_info);
DEFINE_PRINT_MSG_EVENT(ice_print_peer_err);

/* Events related to DIM, q_vectors and ring containers */
DECLARE_EVENT_CLASS(ice_rx_dim_template,
		    TP_PROTO(struct ice_q_vector *q_vector, struct dim *dim),
		    TP_ARGS(q_vector, dim),
		    TP_STRUCT__entry(__field(struct ice_q_vector *, q_vector)
				     __field(struct dim *, dim)
				     __string(devname, q_vector->rx.rx_ring->netdev->name)),

		    TP_fast_assign(__entry->q_vector = q_vector;
				   __entry->dim = dim;
#ifdef HAVE_ASSIGN_STR_2_PARAMS
				   __assign_str(devname, q_vector->rx.rx_ring->netdev->name);),
#else
				   __assign_str(devname);),
#endif /* HAVE_ASSIGN_STR_2_PARAMS */

		    TP_printk("netdev: %s Rx-Q: %d dim-state: %d dim-profile: %d dim-tune: %d dim-st-right: %d dim-st-left: %d dim-tired: %d",
			      __get_str(devname),
			      __entry->q_vector->rx.rx_ring->q_index,
			      __entry->dim->state,
			      __entry->dim->profile_ix,
			      __entry->dim->tune_state,
			      __entry->dim->steps_right,
			      __entry->dim->steps_left,
			      __entry->dim->tired));

DEFINE_EVENT(ice_rx_dim_template, ice_rx_dim_work,
	     TP_PROTO(struct ice_q_vector *q_vector, struct dim *dim),
	     TP_ARGS(q_vector, dim));

DECLARE_EVENT_CLASS(ice_tx_dim_template,
		    TP_PROTO(struct ice_q_vector *q_vector, struct dim *dim),
		    TP_ARGS(q_vector, dim),
		    TP_STRUCT__entry(__field(struct ice_q_vector *, q_vector)
				     __field(struct dim *, dim)
				     __string(devname, q_vector->tx.tx_ring->netdev->name)),

		    TP_fast_assign(__entry->q_vector = q_vector;
				   __entry->dim = dim;
#ifdef HAVE_ASSIGN_STR_2_PARAMS
				   __assign_str(devname, q_vector->tx.tx_ring->netdev->name);),
#else
				   __assign_str(devname);),
#endif /* HAVE_ASSIGN_STR_2_PARAMS */

		    TP_printk("netdev: %s Tx-Q: %d dim-state: %d dim-profile: %d dim-tune: %d dim-st-right: %d dim-st-left: %d dim-tired: %d",
			      __get_str(devname),
			      __entry->q_vector->rx.rx_ring->q_index,
			      __entry->dim->state,
			      __entry->dim->profile_ix,
			      __entry->dim->tune_state,
			      __entry->dim->steps_right,
			      __entry->dim->steps_left,
			      __entry->dim->tired));

DEFINE_EVENT(ice_tx_dim_template, ice_tx_dim_work,
	     TP_PROTO(struct ice_q_vector *q_vector, struct dim *dim),
	     TP_ARGS(q_vector, dim));

/* Events related to a vsi & ring */
DECLARE_EVENT_CLASS(ice_tx_template,
		    TP_PROTO(struct ice_tx_ring *ring, struct ice_tx_desc *desc,
			     struct ice_tx_buf *buf),

		    TP_ARGS(ring, desc, buf),
		    TP_STRUCT__entry(__field(void *, ring)
				     __field(void *, desc)
				     __field(void *, buf)
				     __string(devname, ring->netdev->name)),

		    TP_fast_assign(__entry->ring = ring;
				   __entry->desc = desc;
				   __entry->buf = buf;
#ifdef HAVE_ASSIGN_STR_2_PARAMS
				   __assign_str(devname, ring->netdev->name);),
#else
				   __assign_str(devname);),
#endif /* HAVE_ASSIGN_STR_2_PARAMS */

		    TP_printk("netdev: %s ring: %p desc: %p buf %p", __get_str(devname),
			      __entry->ring, __entry->desc, __entry->buf));

#define DEFINE_TX_TEMPLATE_OP_EVENT(name) \
DEFINE_EVENT(ice_tx_template, name, \
	     TP_PROTO(struct ice_tx_ring *ring, \
		      struct ice_tx_desc *desc, \
		      struct ice_tx_buf *buf), \
	     TP_ARGS(ring, desc, buf))

DEFINE_TX_TEMPLATE_OP_EVENT(ice_clean_tx_irq);
DEFINE_TX_TEMPLATE_OP_EVENT(ice_clean_tx_irq_unmap);
DEFINE_TX_TEMPLATE_OP_EVENT(ice_clean_tx_irq_unmap_eop);

DECLARE_EVENT_CLASS(ice_rx_template,
		    TP_PROTO(struct ice_rx_ring *ring, union ice_32b_rx_flex_desc *desc),

		    TP_ARGS(ring, desc),

		    TP_STRUCT__entry(__field(void *, ring)
				     __field(void *, desc)
				     __string(devname, ring->netdev->name)),

		    TP_fast_assign(__entry->ring = ring;
				   __entry->desc = desc;
#ifdef HAVE_ASSIGN_STR_2_PARAMS
				   __assign_str(devname, ring->netdev->name);),
#else
				   __assign_str(devname);),
#endif /* HAVE_ASSIGN_STR_2_PARAMS */

		    TP_printk("netdev: %s ring: %p desc: %p", __get_str(devname),
			      __entry->ring, __entry->desc));
DEFINE_EVENT(ice_rx_template, ice_clean_rx_irq,
	     TP_PROTO(struct ice_rx_ring *ring, union ice_32b_rx_flex_desc *desc),
	     TP_ARGS(ring, desc));

DECLARE_EVENT_CLASS(ice_rx_indicate_template,
		    TP_PROTO(struct ice_rx_ring *ring, union ice_32b_rx_flex_desc *desc,
			     struct sk_buff *skb),

		    TP_ARGS(ring, desc, skb),

		    TP_STRUCT__entry(__field(void *, ring)
				     __field(void *, desc)
				     __field(void *, skb)
				     __string(devname, ring->netdev->name)),

		    TP_fast_assign(__entry->ring = ring;
				   __entry->desc = desc;
				   __entry->skb = skb;
#ifdef HAVE_ASSIGN_STR_2_PARAMS
				   __assign_str(devname, ring->netdev->name);),
#else
				   __assign_str(devname);),
#endif /* HAVE_ASSIGN_STR_2_PARAMS */

		    TP_printk("netdev: %s ring: %p desc: %p skb %p", __get_str(devname),
			      __entry->ring, __entry->desc, __entry->skb));

DEFINE_EVENT(ice_rx_indicate_template, ice_clean_rx_irq_indicate,
	     TP_PROTO(struct ice_rx_ring *ring, union ice_32b_rx_flex_desc *desc,
		      struct sk_buff *skb),
	     TP_ARGS(ring, desc, skb));

DECLARE_EVENT_CLASS(ice_xmit_template,
		    TP_PROTO(struct ice_tx_ring *ring, struct sk_buff *skb),

		    TP_ARGS(ring, skb),

		    TP_STRUCT__entry(__field(void *, ring)
				     __field(void *, skb)
				     __string(devname, ring->netdev->name)),

		    TP_fast_assign(__entry->ring = ring;
				   __entry->skb = skb;
#ifdef HAVE_ASSIGN_STR_2_PARAMS
				   __assign_str(devname, ring->netdev->name);),
#else
				   __assign_str(devname);),
#endif /* HAVE_ASSIGN_STR_2_PARAMS */

		    TP_printk("netdev: %s skb: %p ring: %p", __get_str(devname),
			      __entry->skb, __entry->ring));

#define DEFINE_XMIT_TEMPLATE_OP_EVENT(name) \
DEFINE_EVENT(ice_xmit_template, name, \
	     TP_PROTO(struct ice_tx_ring *ring, struct sk_buff *skb), \
	     TP_ARGS(ring, skb))

DEFINE_XMIT_TEMPLATE_OP_EVENT(ice_xmit_frame_ring);
DEFINE_XMIT_TEMPLATE_OP_EVENT(ice_xmit_frame_ring_drop);

DECLARE_EVENT_CLASS(ice_tx_tstamp_template,
		    TP_PROTO(struct device *dev, struct ice_ptp_tx *tx,
			     struct sk_buff *skb, int idx),

		    TP_ARGS(dev, tx, skb, idx),

		    TP_STRUCT__entry(__string(dev_name, dev_name(dev))
				     __string(netdev_name,
					      netdev_name(skb->dev))
				     __field(void *, skb)
				     __field(int, seq)
				     __field(int, idx)
				     __field(int, block)
				     __field(int, offset)
				     __field(int, len)
				     __field(int, in_use)
				     __field(u8, init)
				     __field(u8, calibrating)),

		    TP_fast_assign(lockdep_assert_held(&tx->lock);
#ifdef HAVE_ASSIGN_STR_2_PARAMS
				   __assign_str(dev_name, dev_name(dev));
				   __assign_str(netdev_name,
						netdev_name(skb->dev));
#else
				   __assign_str(dev_name);
				   __assign_str(netdev_name);
#endif /* HAVE_ASSIGN_STR_2_PARAMS */
				   __entry->skb = skb;
				   __entry->seq = ice_ptp_get_seq_id(skb);
				   __entry->idx = idx;
				   __entry->block = tx->block;
				   __entry->offset = tx->offset;
				   __entry->len = tx->len;
				   __entry->in_use = bitmap_weight(tx->in_use,
								   tx->len);
				   __entry->init = tx->init;
				   __entry->calibrating = tx->calibrating;),

		    TP_printk("dev=%s netdev=%s skb=%pK sequence_id=%d block=%d offset=%d len=%d in_use=%d init=%d calibrating=%d idx=%d",
			      __get_str(dev_name), __get_str(netdev_name),
			      __entry->skb, __entry->seq,
			      __entry->block, __entry->offset, __entry->len,
			      __entry->in_use, __entry->init,
			      __entry->calibrating, __entry->idx));
#define DEFINE_TX_TSTAMP_OP_EVENT(name) \
DEFINE_EVENT(ice_tx_tstamp_template, name, \
	     TP_PROTO(struct device *dev, struct ice_ptp_tx *tx, \
		      struct sk_buff *skb, int tracker_idx), \
	     TP_ARGS(dev, tx, skb, tracker_idx))

DEFINE_TX_TSTAMP_OP_EVENT(ice_tx_tstamp_request);
DEFINE_TX_TSTAMP_OP_EVENT(ice_tx_tstamp_tracker_down);
DEFINE_TX_TSTAMP_OP_EVENT(ice_tx_tstamp_idx_full);
DEFINE_TX_TSTAMP_OP_EVENT(ice_tx_tstamp_complete);
DEFINE_TX_TSTAMP_OP_EVENT(ice_tx_tstamp_fw_req);
DEFINE_TX_TSTAMP_OP_EVENT(ice_tx_tstamp_fw_done);
DEFINE_TX_TSTAMP_OP_EVENT(ice_tx_tstamp_timeout);
DEFINE_TX_TSTAMP_OP_EVENT(ice_tx_tstamp_invalid);
DEFINE_TX_TSTAMP_OP_EVENT(ice_tx_tstamp_stale);
DEFINE_TX_TSTAMP_OP_EVENT(ice_tx_tstamp_dropped);

DECLARE_EVENT_CLASS(ice_switch_stats_template,
		    TP_PROTO(struct ice_switch_info *sw_info,
			     struct ice_bus_info *bus),
		    TP_ARGS(sw_info, bus),
		    TP_STRUCT__entry(__field(u16, rule_cnt)
				     __field(u8, recp_cnt)
				     __field(u16, domain_num)
				     __field(u16, device)
				     __field(u8, func)
				     __field(u8, bus_num)),
		    TP_fast_assign(__entry->rule_cnt = sw_info->rule_cnt;
				   __entry->recp_cnt = sw_info->recp_cnt;
				   __entry->domain_num = bus->domain_num;
				   __entry->device = bus->device;
				   __entry->func = bus->func;
				   __entry->bus_num = bus->bus_num;),
		    TP_printk("%04x:%02x:%02x.%d: rules=%u recipes=%u",
			      __entry->domain_num,
			      __entry->bus_num,
			      __entry->device,
			      __entry->func,
			      __entry->rule_cnt,
			      __entry->recp_cnt));

DEFINE_EVENT(ice_switch_stats_template,
	     ice_aq_sw_rules,
	     TP_PROTO(struct ice_switch_info *sw_info,
		      struct ice_bus_info *bus),
	     TP_ARGS(sw_info, bus));

DEFINE_EVENT(ice_switch_stats_template,
	     ice_alloc_recipe,
	     TP_PROTO(struct ice_switch_info *sw_info,
		      struct ice_bus_info *bus),
	     TP_ARGS(sw_info, bus));

DEFINE_EVENT(ice_switch_stats_template,
	     ice_free_recipe_res,
	     TP_PROTO(struct ice_switch_info *sw_info,
		      struct ice_bus_info *bus),
	     TP_ARGS(sw_info, bus));

/* End tracepoints */

#endif /* _ICE_TRACE_H_ */
/* This must be outside ifdef _ICE_TRACE_H */

/* This trace include file is not located in the .../include/trace
 * with the kernel tracepoint definitions, because we're a loadable
 * module.
 */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE ice_trace
#include <trace/define_trace.h>
#endif /* CONFIG_TRACEPOINTS */
