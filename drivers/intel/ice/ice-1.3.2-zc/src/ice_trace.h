/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

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
#include <linux/tracepoint.h>

/**
 * ice_trace() macro enables shared code to refer to trace points
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

#define ice_trace_enabled(trace_name) ICE_TRACE_NAME(trace_name##_enabled)()

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

		    TP_fast_assign(__assign_str(msg, msg);),

		    TP_printk("%s", __get_str(msg))
);

#define DEFINE_PRINT_MSG_EVENT(name) \
DEFINE_EVENT(ice_print_msg, name, \
	     TP_PROTO(char *msg), \
	     TP_ARGS(msg))

DEFINE_PRINT_MSG_EVENT(ice_print_err);
DEFINE_PRINT_MSG_EVENT(ice_print_warn);

/* Events related to a vsi & ring */
DECLARE_EVENT_CLASS(ice_tx_template,
		    TP_PROTO(struct ice_ring *ring, struct ice_tx_desc *desc,
			     struct ice_tx_buf *buf),

		    TP_ARGS(ring, desc, buf),
		    TP_STRUCT__entry(__field(void *, ring)
				     __field(void *, desc)
				     __field(void *, buf)
				     __string(devname, ring->netdev->name)),

		    TP_fast_assign(__entry->ring = ring;
				   __entry->desc = desc;
				   __entry->buf = buf;
				   __assign_str(devname, ring->netdev->name);),

		    TP_printk("netdev: %s ring: %pK desc: %pK buf %pK", __get_str(devname),
			      __entry->ring, __entry->desc, __entry->buf)
);

#define DEFINE_TX_TEMPLATE_OP_EVENT(name) \
DEFINE_EVENT(ice_tx_template, name, \
	     TP_PROTO(struct ice_ring *ring, \
		      struct ice_tx_desc *desc, \
		      struct ice_tx_buf *buf), \
	     TP_ARGS(ring, desc, buf))

DEFINE_TX_TEMPLATE_OP_EVENT(ice_clean_tx_irq);
DEFINE_TX_TEMPLATE_OP_EVENT(ice_clean_tx_irq_unmap);
DEFINE_TX_TEMPLATE_OP_EVENT(ice_clean_tx_irq_unmap_eop);

DECLARE_EVENT_CLASS(ice_rx_template,
		    TP_PROTO(struct ice_ring *ring, union ice_32b_rx_flex_desc *desc),

		    TP_ARGS(ring, desc),

		    TP_STRUCT__entry(__field(void *, ring)
				     __field(void *, desc)
				     __string(devname, ring->netdev->name)),

		    TP_fast_assign(__entry->ring = ring;
				   __entry->desc = desc;
				   __assign_str(devname, ring->netdev->name);),

		    TP_printk("netdev: %s ring: %pK desc: %pK", __get_str(devname),
			      __entry->ring, __entry->desc)
);
DEFINE_EVENT(ice_rx_template, ice_clean_rx_irq,
	     TP_PROTO(struct ice_ring *ring, union ice_32b_rx_flex_desc *desc),
	     TP_ARGS(ring, desc)
);

DECLARE_EVENT_CLASS(ice_rx_indicate_template,
		    TP_PROTO(struct ice_ring *ring, union ice_32b_rx_flex_desc *desc,
			     struct sk_buff *skb),

		    TP_ARGS(ring, desc, skb),

		    TP_STRUCT__entry(__field(void *, ring)
				     __field(void *, desc)
				     __field(void *, skb)
				     __string(devname, ring->netdev->name)),

		    TP_fast_assign(__entry->ring = ring;
				   __entry->desc = desc;
				   __entry->skb = skb;
				   __assign_str(devname, ring->netdev->name);),

		    TP_printk("netdev: %s ring: %pK desc: %pK skb %pK", __get_str(devname),
			      __entry->ring, __entry->desc, __entry->skb)
);

DEFINE_EVENT(ice_rx_indicate_template, ice_clean_rx_irq_indicate,
	     TP_PROTO(struct ice_ring *ring, union ice_32b_rx_flex_desc *desc,
		      struct sk_buff *skb),
	     TP_ARGS(ring, desc, skb)
);

DECLARE_EVENT_CLASS(ice_xmit_template,
		    TP_PROTO(struct ice_ring *ring, struct sk_buff *skb),

		    TP_ARGS(ring, skb),

		    TP_STRUCT__entry(__field(void *, ring)
				     __field(void *, skb)
				     __string(devname, ring->netdev->name)),

		    TP_fast_assign(__entry->ring = ring;
				   __entry->skb = skb;
				   __assign_str(devname, ring->netdev->name);),

		    TP_printk("netdev: %s skb: %pK ring: %pK", __get_str(devname),
			      __entry->skb, __entry->ring)
);

#define DEFINE_XMIT_TEMPLATE_OP_EVENT(name) \
DEFINE_EVENT(ice_xmit_template, name, \
	     TP_PROTO(struct ice_ring *ring, struct sk_buff *skb), \
	     TP_ARGS(ring, skb))

DEFINE_XMIT_TEMPLATE_OP_EVENT(ice_xmit_frame_ring);
DEFINE_XMIT_TEMPLATE_OP_EVENT(ice_xmit_frame_ring_drop);

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
