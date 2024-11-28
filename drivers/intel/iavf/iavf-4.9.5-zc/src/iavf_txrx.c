/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2013-2023 Intel Corporation */

#include <linux/prefetch.h>

#include "iavf.h"
#include "iavf_trace.h"
#include "iavf_prototype.h"
#ifdef HAVE_XDP_DO_FLUSH
#include <linux/filter.h>
#endif

#ifdef HAVE_PF_RING
extern int enable_debug;
extern int kernel_only_adapter[IAVF_MAX_NIC];

int wake_up_pfring_zc_socket(struct iavf_ring *rx_ring); /* iavf_main.c */
#endif

static inline __le64 build_ctob(u32 td_cmd, u32 td_offset, unsigned int size,
				u32 td_tag)
{
	return cpu_to_le64(IAVF_TX_DESC_DTYPE_DATA |
			   ((u64)td_cmd  << IAVF_TXD_QW1_CMD_SHIFT) |
			   ((u64)td_offset << IAVF_TXD_QW1_OFFSET_SHIFT) |
			   ((u64)size  << IAVF_TXD_QW1_TX_BUF_SZ_SHIFT) |
			   ((u64)td_tag  << IAVF_TXD_QW1_L2TAG1_SHIFT));
}

#define IAVF_TXD_CMD (IAVF_TX_DESC_CMD_EOP | IAVF_TX_DESC_CMD_RS)

/**
 * iavf_unmap_and_free_tx_resource - Release a Tx buffer
 * @ring:      the ring that owns the buffer
 * @tx_buffer: the buffer to free
 **/
static void iavf_unmap_and_free_tx_resource(struct iavf_ring *ring,
					    struct iavf_tx_buffer *tx_buffer)
{
	if (tx_buffer->skb) {
		if (tx_buffer->tx_flags & IAVF_TX_FLAGS_FD_SB)
			kfree(tx_buffer->raw_buf);
		else
			dev_kfree_skb_any(tx_buffer->skb);
		if (dma_unmap_len(tx_buffer, len))
			dma_unmap_single(ring->dev,
					 dma_unmap_addr(tx_buffer, dma),
					 dma_unmap_len(tx_buffer, len),
					 DMA_TO_DEVICE);
	} else if (dma_unmap_len(tx_buffer, len)) {
		dma_unmap_page(ring->dev,
			       dma_unmap_addr(tx_buffer, dma),
			       dma_unmap_len(tx_buffer, len),
			       DMA_TO_DEVICE);
	}

	tx_buffer->next_to_watch = NULL;
	tx_buffer->skb = NULL;
	dma_unmap_len_set(tx_buffer, len, 0);
	/* tx_buffer must be completely set up in the transmit path */
}

/**
 * iavf_clean_tx_ring - Free any empty Tx buffers
 * @tx_ring: ring to be cleaned
 **/
void iavf_clean_tx_ring(struct iavf_ring *tx_ring)
{
	unsigned long bi_size;
	u16 i;

	/* ring already cleared, nothing to do */
	if (!tx_ring->tx_bi)
		return;

	/* Free all the Tx ring sk_buffs */
	for (i = 0; i < tx_ring->count; i++)
		iavf_unmap_and_free_tx_resource(tx_ring, &tx_ring->tx_bi[i]);

	bi_size = sizeof(struct iavf_tx_buffer) * tx_ring->count;
	memset(tx_ring->tx_bi, 0, bi_size);

	/* Zero out the descriptor ring */
	memset(tx_ring->desc, 0, tx_ring->size);

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	if (!tx_ring->netdev)
		return;

	/* cleanup Tx queue statistics */
	netdev_tx_reset_queue(txring_txq(tx_ring));
}

/**
 * iavf_free_tx_resources - Free Tx resources per queue
 * @tx_ring: Tx descriptor ring for a specific queue
 *
 * Free all transmit software resources
 **/
void iavf_free_tx_resources(struct iavf_ring *tx_ring)
{
	iavf_clean_tx_ring(tx_ring);
	kfree(tx_ring->tx_bi);
	tx_ring->tx_bi = NULL;

	if (tx_ring->desc) {
		dma_free_coherent(tx_ring->dev, tx_ring->size,
				  tx_ring->desc, tx_ring->dma);
		tx_ring->desc = NULL;
	}
}

/**
 * iavf_get_tx_pending - how many Tx descriptors not processed
 * @ring: the ring of descriptors
 * @in_sw: is tx_pending being checked in SW or HW
 *
 * Since there is no access to the ring head register
 * in XL710, we need to use our local copies
 **/
u32 iavf_get_tx_pending(struct iavf_ring *ring, bool in_sw)
{
	u32 head, tail;

	/* underlying hardware might not allow access and/or always return
	 * 0 for the head/tail registers so just use the cached values
	 */
	head = ring->next_to_clean;
	tail = ring->next_to_use;

	if (head != tail)
		return (head < tail) ?
			tail - head : (tail + ring->count - head);

	return 0;
}

/**
 * iavf_chnl_detect_recover - logic to revive ADQ enabled vectors
 * @vsi: ptr to VSI
 *
 * This function implements "jiffy" based logic to revive ADQ enabled
 * vectors by triggering software interrupt. It is invoked from
 * "service_task" which typically runs once every second.
 **/
void iavf_chnl_detect_recover(struct iavf_vsi *vsi)
{
	struct iavf_ring *tx_ring = NULL;
	struct net_device *netdev;
	unsigned long end;
	unsigned int i;

	if (!vsi)
		return;

	if (test_bit(__IAVF_VSI_DOWN, vsi->state))
		return;

	netdev = vsi->netdev;
	if (!netdev)
		return;

	if (!netif_carrier_ok(netdev))
		return;

	for (i = 0; i < vsi->back->num_active_queues; i++) {
		u8 qv_state_flags;

		tx_ring = &vsi->back->tx_rings[i];
		if (!(tx_ring && tx_ring->desc))
			continue;
		if (!tx_ring->q_vector)
			continue;
		if (!vector_ch_ena(tx_ring->q_vector) ||
		    !vector_ch_perf_ena(tx_ring->q_vector))
			continue;

		end = tx_ring->q_vector->jiffies;
		if (!end)
			continue;

		qv_state_flags = tx_ring->q_vector->state_flags;

		/* trigger software interrupt (to revive queue processing) if
		 * vector is channel enabled and only if current jiffies is at
		 * least 1 sec (worth of jiffies, hence multiplying by HZ) more
		 * than old_jiffies
		 */
#define IAVF_CH_JIFFY_DELTA_IN_SEC	(1 * HZ)
		end += IAVF_CH_JIFFY_DELTA_IN_SEC;
		if (time_is_before_jiffies(end) &&
		    (qv_state_flags & IAVF_VECTOR_STATE_ONCE_IN_BP)) {
			iavf_inc_serv_task_sw_intr_counter(tx_ring->q_vector);
			iavf_force_wb(vsi, tx_ring->q_vector);
		}
	}
}

/**
 * iavf_detect_recover_hung - Function to detect and recover hung_queues
 * @vsi:  pointer to vsi struct with tx queues
 *
 * VSI has netdev and netdev has TX queues. This function is to check each of
 * those TX queues if they are hung, trigger recovery by issuing SW interrupt.
 **/
void iavf_detect_recover_hung(struct iavf_vsi *vsi)
{
	struct net_device *netdev;
	unsigned int i;
	int packets;

	if (!vsi)
		return;

	if (test_bit(__IAVF_VSI_DOWN, vsi->state))
		return;

	netdev = vsi->netdev;
	if (!netdev)
		return;

	if (!netif_carrier_ok(netdev))
		return;

	for (i = 0; i < vsi->back->num_active_queues; i++) {
		struct iavf_ring *tx_ring = &vsi->back->tx_rings[i];

		if (!tx_ring || !tx_ring->q_vector)
			continue;
		if (vector_ch_ena(tx_ring->q_vector))
			continue;
		if (tx_ring->desc) {
			/* If packet counter has not changed the queue is
			 * likely stalled, so force an interrupt for this
			 * queue.
			 *
			 * prev_pkt_ctr would be negative if there was no
			 * pending work.
			 */
			packets = tx_ring->stats.packets & INT_MAX;
			if (tx_ring->tx_stats.prev_pkt_ctr == packets) {
				iavf_force_wb(vsi, tx_ring->q_vector);
				continue;
			}

			/* Memory barrier between read of packet count and call
			 * to iavf_get_tx_pending()
			 */
			smp_rmb();
			tx_ring->tx_stats.prev_pkt_ctr =
			  iavf_get_tx_pending(tx_ring, true) ? packets : -1;
		}
	}
}

static void iavf_chnl_queue_stats(struct iavf_ring *ring, u64 pkts)
{
	u64_stats_update_begin(&ring->syncp);
	/* separate accounting of packets (either from busy_poll or
	 * napi_poll depending upon state of vector specific
	 * flag 'in_bp', 'prev_in_bp'
	 */
	if (ring->q_vector->state_flags & IAVF_VECTOR_STATE_IN_BP) {
		ring->ch_q_stats.poll.pkt_busy_poll += pkts;
	} else {
		if (ring->q_vector->state_flags & IAVF_VECTOR_STATE_PREV_IN_BP)
			ring->ch_q_stats.poll.pkt_busy_poll += pkts;
		else
			ring->ch_q_stats.poll.pkt_not_busy_poll += pkts;
	}
	u64_stats_update_end(&ring->syncp);
}
#define WB_STRIDE 4

/**
 * iavf_clean_tx_irq - Reclaim resources after transmit completes
 * @vsi: the VSI we care about
 * @tx_ring: Tx ring to clean
 * @napi_budget: Used to determine if we are in netpoll
 *
 * Returns true if there's any budget left (e.g. the clean is finished)
 **/
static bool iavf_clean_tx_irq(struct iavf_vsi *vsi,
			      struct iavf_ring *tx_ring, int napi_budget)
{
	int i = tx_ring->next_to_clean;
	struct iavf_tx_buffer *tx_buf;
	struct iavf_tx_desc *tx_desc;
	unsigned int total_bytes = 0, total_packets = 0;
	unsigned int budget = IAVF_DEFAULT_IRQ_WORK;
#ifdef HAVE_PF_RING
	struct iavf_adapter *adapter = netdev_priv(tx_ring->netdev);

	/*
	if (unlikely(enable_debug))
		printk("[PF_RING-ZC] %s(%s) called [usage_counter=%u]\n", 
	        	__FUNCTION__, tx_ring->netdev->name,
	        	atomic_read(&adapter->pfring_zc.usage_counter));
	*/

	if (atomic_read(&adapter->pfring_zc.usage_counter) > 0)
		return true;
#endif

	tx_buf = &tx_ring->tx_bi[i];
	tx_desc = IAVF_TX_DESC(tx_ring, i);
	i -= tx_ring->count;

	do {
		struct iavf_tx_desc *eop_desc = tx_buf->next_to_watch;

		/* if next_to_watch is not set then there is no work pending */
		if (!eop_desc)
			break;

		/* prevent any other reads prior to eop_desc */
		smp_rmb();

		iavf_trace(clean_tx_irq, tx_ring, tx_desc, tx_buf);
		/* if the descriptor isn't done, no work yet to do */
		if (!(eop_desc->cmd_type_offset_bsz &
		      cpu_to_le64(IAVF_TX_DESC_DTYPE_DESC_DONE)))
			break;

		/* clear next_to_watch to prevent false hangs */
		tx_buf->next_to_watch = NULL;

		/* update the statistics for this packet */
		total_bytes += tx_buf->bytecount;
		total_packets += tx_buf->gso_segs;

		/* free the skb */
		napi_consume_skb(tx_buf->skb, napi_budget);

		/* unmap skb header data */
		dma_unmap_single(tx_ring->dev,
				 dma_unmap_addr(tx_buf, dma),
				 dma_unmap_len(tx_buf, len),
				 DMA_TO_DEVICE);

		/* clear tx_buffer data */
		tx_buf->skb = NULL;
		dma_unmap_len_set(tx_buf, len, 0);

		/* unmap remaining buffers */
		while (tx_desc != eop_desc) {
			iavf_trace(clean_tx_irq_unmap,
				   tx_ring, tx_desc, tx_buf);

			tx_buf++;
			tx_desc++;
			i++;
			if (unlikely(!i)) {
				i -= tx_ring->count;
				tx_buf = tx_ring->tx_bi;
				tx_desc = IAVF_TX_DESC(tx_ring, 0);
			}

			/* unmap any remaining paged data */
			if (dma_unmap_len(tx_buf, len)) {
				dma_unmap_page(tx_ring->dev,
					       dma_unmap_addr(tx_buf, dma),
					       dma_unmap_len(tx_buf, len),
					       DMA_TO_DEVICE);
				dma_unmap_len_set(tx_buf, len, 0);
			}
		}

		/* move us one more past the eop_desc for start of next pkt */
		tx_buf++;
		tx_desc++;
		i++;
		if (unlikely(!i)) {
			i -= tx_ring->count;
			tx_buf = tx_ring->tx_bi;
			tx_desc = IAVF_TX_DESC(tx_ring, 0);
		}

		prefetch(tx_desc);

		/* update budget accounting */
		budget--;
	} while (likely(budget));

	i += tx_ring->count;
	tx_ring->next_to_clean = i;
	u64_stats_update_begin(&tx_ring->syncp);
	tx_ring->stats.bytes += total_bytes;
	tx_ring->stats.packets += total_packets;
	u64_stats_update_end(&tx_ring->syncp);
	tx_ring->q_vector->tx.total_bytes += total_bytes;
	tx_ring->q_vector->tx.total_packets += total_packets;
	iavf_chnl_queue_stats(tx_ring, total_packets);

	if (tx_ring->flags & IAVF_TXR_FLAGS_WB_ON_ITR) {
		/* check to see if there are < 4 descriptors
		 * waiting to be written back, then kick the hardware to force
		 * them to be written back in case we stay in NAPI.
		 * In this mode on X722 we do not enable Interrupt.
		 */
		unsigned int j = iavf_get_tx_pending(tx_ring, false);

		if (budget &&
		    ((j / WB_STRIDE) == 0) && (j > 0) &&
		    !test_bit(__IAVF_VSI_DOWN, vsi->state) &&
		    (IAVF_DESC_UNUSED(tx_ring) != tx_ring->count))
			tx_ring->arm_wb = true;
	}

	if (ring_is_xdp(tx_ring))
		return !!budget;

	/* notify netdev of completed buffers */
	netdev_tx_completed_queue(txring_txq(tx_ring),
				  total_packets, total_bytes);

#define TX_WAKE_THRESHOLD ((s16)(DESC_NEEDED * 2))
	if (unlikely(total_packets && netif_carrier_ok(tx_ring->netdev) &&
		     (IAVF_DESC_UNUSED(tx_ring) >= TX_WAKE_THRESHOLD))) {
		/* Make sure that anybody stopping the queue after this
		 * sees the new next_to_clean.
		 */
		smp_mb();
		if (__netif_subqueue_stopped(tx_ring->netdev,
					     tx_ring->queue_index) &&
		   !test_bit(__IAVF_VSI_DOWN, vsi->state)) {
			netif_wake_subqueue(tx_ring->netdev,
					    tx_ring->queue_index);
			++tx_ring->tx_stats.restart_queue;
		}
	}

	return !!budget;
}

/**
 * iavf_enable_wb_on_itr - Arm hardware to do a wb, interrupts are not enabled
 * @vsi: the VSI we care about
 * @q_vector: the vector on which to enable writeback
 *
 **/
static void iavf_enable_wb_on_itr(struct iavf_vsi *vsi,
				  struct iavf_q_vector *q_vector)
{
	u16 flags = q_vector->tx.ring[0].flags;
	u32 val;

	if (!(flags & IAVF_TXR_FLAGS_WB_ON_ITR))
		return;

	if (q_vector->arm_wb_state)
		return;

	val = IAVF_VFINT_DYN_CTLN1_WB_ON_ITR_MASK |
	      IAVF_VFINT_DYN_CTLN1_ITR_INDX_MASK; /* set noitr */

	wr32(&vsi->back->hw,
	     INT_DYN_CTL(&vsi->back->hw, q_vector->reg_idx), val);
	q_vector->arm_wb_state = true;
}

static inline bool iavf_container_is_rx(struct iavf_q_vector *q_vector,
					struct iavf_ring_container *rc)
{
	return &q_vector->rx == rc;
}

#define IAVF_AIM_MULTIPLIER_100G	2560
#define IAVF_AIM_MULTIPLIER_50G		1280
#define IAVF_AIM_MULTIPLIER_40G		1024
#define IAVF_AIM_MULTIPLIER_20G		512
#define IAVF_AIM_MULTIPLIER_10G		256
#define IAVF_AIM_MULTIPLIER_1G		32

static unsigned int iavf_mbps_itr_multiplier(u32 speed_mbps)
{
	switch (speed_mbps) {
	case SPEED_100000:
		return IAVF_AIM_MULTIPLIER_100G;
	case SPEED_50000:
		return IAVF_AIM_MULTIPLIER_50G;
	case SPEED_40000:
		return IAVF_AIM_MULTIPLIER_40G;
	case SPEED_25000:
	case SPEED_20000:
		return IAVF_AIM_MULTIPLIER_20G;
	case SPEED_10000:
	default:
		return IAVF_AIM_MULTIPLIER_10G;
	case SPEED_1000:
	case SPEED_100:
		return IAVF_AIM_MULTIPLIER_1G;
	}
}

static unsigned int
iavf_virtchnl_itr_multiplier(enum virtchnl_link_speed speed_virtchnl)
{
	switch (speed_virtchnl) {
	case VIRTCHNL_LINK_SPEED_40GB:
		return IAVF_AIM_MULTIPLIER_40G;
	case VIRTCHNL_LINK_SPEED_25GB:
	case VIRTCHNL_LINK_SPEED_20GB:
		return IAVF_AIM_MULTIPLIER_20G;
	case VIRTCHNL_LINK_SPEED_10GB:
	default:
		return IAVF_AIM_MULTIPLIER_10G;
	case VIRTCHNL_LINK_SPEED_1GB:
	case VIRTCHNL_LINK_SPEED_100MB:
		return IAVF_AIM_MULTIPLIER_1G;
	}
}

static unsigned int iavf_itr_divisor(struct iavf_adapter *adapter)
{
	if (ADV_LINK_SUPPORT(adapter))
		return IAVF_ITR_ADAPTIVE_MIN_INC *
			iavf_mbps_itr_multiplier(adapter->link_speed_mbps);
	else
		return IAVF_ITR_ADAPTIVE_MIN_INC *
			iavf_virtchnl_itr_multiplier(adapter->link_speed);
}

/**
 * iavf_update_itr - update the dynamic ITR value based on statistics
 * @q_vector: structure containing interrupt and ring information
 * @rc: structure containing ring performance data
 *
 * Stores a new ITR value based on packets and byte
 * counts during the last interrupt.  The advantage of per interrupt
 * computation is faster updates and more accurate ITR for the current
 * traffic pattern.  Constants in this function were computed
 * based on theoretical maximum wire speed and thresholds were set based
 * on testing data as well as attempting to minimize response time
 * while increasing bulk throughput.
 **/
static void iavf_update_itr(struct iavf_q_vector *q_vector,
			    struct iavf_ring_container *rc)
{
	unsigned int avg_wire_size, packets, bytes, itr;
	unsigned long next_update = jiffies;

	/* If we don't have any rings just leave ourselves set for maximum
	 * possible latency so we take ourselves out of the equation.
	 */
	if (!rc->ring || !ITR_IS_DYNAMIC(rc->ring->itr_setting))
		return;

	/* For Rx we want to push the delay up and default to low latency.
	 * for Tx we want to pull the delay down and default to high latency.
	 */
	itr = iavf_container_is_rx(q_vector, rc) ?
	      IAVF_ITR_ADAPTIVE_MIN_USECS | IAVF_ITR_ADAPTIVE_LATENCY :
	      IAVF_ITR_ADAPTIVE_MAX_USECS | IAVF_ITR_ADAPTIVE_LATENCY;

	/* If we didn't update within up to 1 - 2 jiffies we can assume
	 * that either packets are coming in so slow there hasn't been
	 * any work, or that there is so much work that NAPI is dealing
	 * with interrupt moderation and we don't need to do anything.
	 */
	if (time_after(next_update, rc->next_update))
		goto clear_counts;

	/* If itr_countdown is set it means we programmed an ITR within
	 * the last 4 interrupt cycles. This has a side effect of us
	 * potentially firing an early interrupt. In order to work around
	 * this we need to throw out any data received for a few
	 * interrupts following the update.
	 */
	if (q_vector->itr_countdown) {
		itr = rc->target_itr;
		goto clear_counts;
	}

	packets = rc->total_packets;
	bytes = rc->total_bytes;

	if (iavf_container_is_rx(q_vector, rc)) {
		/* If Rx there are 1 to 4 packets and bytes are less than
		 * 9000 assume insufficient data to use bulk rate limiting
		 * approach unless Tx is already in bulk rate limiting. We
		 * are likely latency driven.
		 */
		if (packets && packets < 4 && bytes < 9000 &&
		    (q_vector->tx.target_itr & IAVF_ITR_ADAPTIVE_LATENCY)) {
			itr = IAVF_ITR_ADAPTIVE_LATENCY;
			goto adjust_by_size;
		}
	} else if (packets < 4) {
		/* If we have Tx and Rx ITR maxed and Tx ITR is running in
		 * bulk mode and we are receiving 4 or fewer packets just
		 * reset the ITR_ADAPTIVE_LATENCY bit for latency mode so
		 * that the Rx can relax.
		 */
		if (rc->target_itr == IAVF_ITR_ADAPTIVE_MAX_USECS &&
		    (q_vector->rx.target_itr & IAVF_ITR_MASK) ==
		     IAVF_ITR_ADAPTIVE_MAX_USECS)
			goto clear_counts;
	} else if (packets > 32) {
		/* If we have processed over 32 packets in a single interrupt
		 * for Tx assume we need to switch over to "bulk" mode.
		 */
		rc->target_itr &= ~IAVF_ITR_ADAPTIVE_LATENCY;
	}

	/* We have no packets to actually measure against. This means
	 * either one of the other queues on this vector is active or
	 * we are a Tx queue doing TSO with too high of an interrupt rate.
	 *
	 * Between 4 and 56 we can assume that our current interrupt delay
	 * is only slightly too low. As such we should increase it by a small
	 * fixed amount.
	 */
	if (packets < 56) {
		itr = rc->target_itr + IAVF_ITR_ADAPTIVE_MIN_INC;
		if ((itr & IAVF_ITR_MASK) > IAVF_ITR_ADAPTIVE_MAX_USECS) {
			itr &= IAVF_ITR_ADAPTIVE_LATENCY;
			itr += IAVF_ITR_ADAPTIVE_MAX_USECS;
		}
		goto clear_counts;
	}

	if (packets <= 256) {
		itr = min(q_vector->tx.current_itr, q_vector->rx.current_itr);
		itr &= IAVF_ITR_MASK;

		/* Between 56 and 112 is our "goldilocks" zone where we are
		 * working out "just right". Just report that our current
		 * ITR is good for us.
		 */
		if (packets <= 112)
			goto clear_counts;

		/* If packet count is 128 or greater we are likely looking
		 * at a slight overrun of the delay we want. Try halving
		 * our delay to see if that will cut the number of packets
		 * in half per interrupt.
		 */
		itr /= 2;
		itr &= IAVF_ITR_MASK;
		if (itr < IAVF_ITR_ADAPTIVE_MIN_USECS)
			itr = IAVF_ITR_ADAPTIVE_MIN_USECS;

		goto clear_counts;
	}

	/* The paths below assume we are dealing with a bulk ITR since
	 * number of packets is greater than 256. We are just going to have
	 * to compute a value and try to bring the count under control,
	 * though for smaller packet sizes there isn't much we can do as
	 * NAPI polling will likely be kicking in sooner rather than later.
	 */
	itr = IAVF_ITR_ADAPTIVE_BULK;

adjust_by_size:
	/* If packet counts are 256 or greater we can assume we have a gross
	 * overestimation of what the rate should be. Instead of trying to fine
	 * tune it just use the formula below to try and dial in an exact value
	 * give the current packet size of the frame.
	 */
	avg_wire_size = bytes / packets;

	/* The following is a crude approximation of:
	 *  wmem_default / (size + overhead) = desired_pkts_per_int
	 *  rate / bits_per_byte / (size + ethernet overhead) = pkt_rate
	 *  (desired_pkt_rate / pkt_rate) * usecs_per_sec = ITR value
	 *
	 * Assuming wmem_default is 212992 and overhead is 640 bytes per
	 * packet, (256 skb, 64 headroom, 320 shared info), we can reduce the
	 * formula down to
	 *
	 *  (170 * (size + 24)) / (size + 640) = ITR
	 *
	 * We first do some math on the packet size and then finally bitshift
	 * by 8 after rounding up. We also have to account for PCIe link speed
	 * difference as ITR scales based on this.
	 */
	if (avg_wire_size <= 60) {
		/* Start at 250k ints/sec */
		avg_wire_size = 4096;
	} else if (avg_wire_size <= 380) {
		/* 250K ints/sec to 60K ints/sec */
		avg_wire_size *= 40;
		avg_wire_size += 1696;
	} else if (avg_wire_size <= 1084) {
		/* 60K ints/sec to 36K ints/sec */
		avg_wire_size *= 15;
		avg_wire_size += 11452;
	} else if (avg_wire_size <= 1980) {
		/* 36K ints/sec to 30K ints/sec */
		avg_wire_size *= 5;
		avg_wire_size += 22420;
	} else {
		/* plateau at a limit of 30K ints/sec */
		avg_wire_size = 32256;
	}

	/* If we are in low latency mode halve our delay which doubles the
	 * rate to somewhere between 100K to 16K ints/sec
	 */
	if (itr & IAVF_ITR_ADAPTIVE_LATENCY)
		avg_wire_size /= 2;

	/* Resultant value is 256 times larger than it needs to be. This
	 * gives us room to adjust the value as needed to either increase
	 * or decrease the value based on link speeds of 10G, 2.5G, 1G, etc.
	 *
	 * Use addition as we have already recorded the new latency flag
	 * for the ITR value.
	 */
	itr += DIV_ROUND_UP(avg_wire_size,
			    iavf_itr_divisor(q_vector->adapter)) *
		IAVF_ITR_ADAPTIVE_MIN_INC;

	if ((itr & IAVF_ITR_MASK) > IAVF_ITR_ADAPTIVE_MAX_USECS) {
		itr &= IAVF_ITR_ADAPTIVE_LATENCY;
		itr += IAVF_ITR_ADAPTIVE_MAX_USECS;
	}

clear_counts:
	/* write back value */
	rc->target_itr = itr;

	/* next update should occur within next jiffy */
	rc->next_update = next_update + 1;

	rc->total_bytes = 0;
	rc->total_packets = 0;
}

/**
 * iavf_setup_tx_descriptors - Allocate the Tx descriptors
 * @tx_ring: the tx ring to set up
 *
 * Return 0 on success, negative on error
 **/
int iavf_setup_tx_descriptors(struct iavf_ring *tx_ring)
{
	struct device *dev = tx_ring->dev;
	int bi_size;

	if (!dev)
		return -ENOMEM;

	/* warn if we are about to overwrite the pointer */
	WARN_ON(tx_ring->tx_bi);
	bi_size = sizeof(struct iavf_tx_buffer) * tx_ring->count;
	tx_ring->tx_bi = kzalloc(bi_size, GFP_KERNEL);
	if (!tx_ring->tx_bi)
		goto err;

	/* round up to nearest 4K */
	tx_ring->size = tx_ring->count * sizeof(struct iavf_tx_desc);
	tx_ring->size = ALIGN(tx_ring->size, 4096);
	tx_ring->desc = dma_alloc_coherent(dev, tx_ring->size,
					   &tx_ring->dma, GFP_KERNEL);
	if (!tx_ring->desc) {
		dev_info(dev, "Unable to allocate memory for the Tx descriptor ring, size=%d\n",
			 tx_ring->size);
		goto err;
	}

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;
	tx_ring->tx_stats.prev_pkt_ctr = -1;
	return 0;

err:
	kfree(tx_ring->tx_bi);
	tx_ring->tx_bi = NULL;
	return -ENOMEM;
}

/**
 * iavf_clean_rx_ring - Free Rx buffers
 * @rx_ring: ring to be cleaned
 **/
void iavf_clean_rx_ring(struct iavf_ring *rx_ring)
{
	unsigned long bi_size;
	u16 i;

	/* ring already cleared, nothing to do */
	if (!rx_ring->rx_bi)
		return;

	if (rx_ring->skb) {
		dev_kfree_skb(rx_ring->skb);
		rx_ring->skb = NULL;
	}

	/* Free all the Rx ring sk_buffs */
	for (i = 0; i < rx_ring->count; i++) {
		struct iavf_rx_buffer *rx_bi = &rx_ring->rx_bi[i];

		if (!rx_bi->page)
			continue;

		/* Invalidate cache lines that may have been written to by
		 * device so that we avoid corrupting memory.
		 */
		dma_sync_single_range_for_cpu(rx_ring->dev,
					      rx_bi->dma,
					      rx_bi->page_offset,
					      rx_ring->rx_buf_len,
					      DMA_FROM_DEVICE);

		/* free resources associated with mapping */
		dma_unmap_page_attrs(rx_ring->dev, rx_bi->dma,
				     iavf_rx_pg_size(rx_ring),
				     DMA_FROM_DEVICE,
				     IAVF_RX_DMA_ATTR);

		__page_frag_cache_drain(rx_bi->page, rx_bi->pagecnt_bias);

		rx_bi->page = NULL;
		rx_bi->page_offset = 0;
	}

	bi_size = sizeof(struct iavf_rx_buffer) * rx_ring->count;
	memset(rx_ring->rx_bi, 0, bi_size);

	/* Zero out the descriptor ring */
	memset(rx_ring->desc, 0, rx_ring->size);

	rx_ring->next_to_alloc = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
}

/**
 * iavf_free_rx_resources - Free Rx resources
 * @rx_ring: ring to clean the resources from
 *
 * Free all receive software resources
 **/
void iavf_free_rx_resources(struct iavf_ring *rx_ring)
{
	iavf_clean_rx_ring(rx_ring);
	rx_ring->xdp_prog = NULL;
	kfree(rx_ring->rx_bi);
	rx_ring->rx_bi = NULL;

	if (rx_ring->desc) {
#ifdef HAVE_PF_RING
		//if (unlikely(enable_debug))
			printk("[PF_RING-ZC] %s:%d Deallocating descriptors\n", __FUNCTION__, __LINE__);
#endif

		dma_free_coherent(rx_ring->dev, rx_ring->size,
				  rx_ring->desc, rx_ring->dma);
		rx_ring->desc = NULL;
	}
}

/**
 * iavf_setup_rx_descriptors - Allocate Rx descriptors
 * @rx_ring: Rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 **/
int iavf_setup_rx_descriptors(struct iavf_ring *rx_ring)
{
	struct device *dev = rx_ring->dev;
	int err = -ENOMEM;
	int bi_size;

	/* warn if we are about to overwrite the pointer */
	WARN_ON(rx_ring->rx_bi);
	bi_size = sizeof(struct iavf_rx_buffer) * rx_ring->count;
	rx_ring->rx_bi = kzalloc(bi_size, GFP_KERNEL);
	if (!rx_ring->rx_bi)
		goto err;

#ifdef HAVE_PF_RING
	if (unlikely(enable_debug))
		printk("[PF_RING-ZC] %s:%d allocating %u %lu bytes descriptors\n", 
        	       __FUNCTION__, __LINE__, rx_ring->count, sizeof(union iavf_rx_desc));
#endif

#ifdef HAVE_NDO_GET_STATS64

	u64_stats_init(&rx_ring->syncp);
#endif /* HAVE_NDO_GET_STATS64 */

	/* Round up to nearest 4K */
	rx_ring->size = rx_ring->count * sizeof(union iavf_rx_desc);
	rx_ring->size = ALIGN(rx_ring->size, 4096);
	rx_ring->desc = dma_alloc_coherent(dev, rx_ring->size,
					   &rx_ring->dma, GFP_KERNEL);

	if (!rx_ring->desc) {
		dev_info(dev, "Unable to allocate memory for the Rx descriptor ring, size=%d\n",
			 rx_ring->size);
		goto err;
	}

	rx_ring->next_to_alloc = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
	return 0;
err:
	kfree(rx_ring->rx_bi);
	rx_ring->rx_bi = NULL;
	return err;
}

/**
 * iavf_release_rx_desc - Store the new tail and head values
 * @rx_ring: ring to bump
 * @val: new head index
 **/
static void iavf_release_rx_desc(struct iavf_ring *rx_ring, u32 val)
{
	rx_ring->next_to_use = val;

	/* update next to alloc since we have filled the ring */
	rx_ring->next_to_alloc = val;

	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.  (Only
	 * applicable for weak-ordered memory model archs,
	 * such as IA-64).
	 */
	wmb();
	writel(val, rx_ring->tail);
}

/**
 * iavf_rx_offset - Return expected offset into page to access data
 * @rx_ring: Ring we are requesting offset of
 *
 * Returns the offset value for ring into the data buffer.
 */
static unsigned int iavf_rx_offset(struct iavf_ring *rx_ring)
{
	return ring_uses_build_skb(rx_ring) ? IAVF_SKB_PAD : 0;
}

/**
 * iavf_alloc_mapped_page - recycle or make a new page
 * @rx_ring: ring to use
 * @bi: rx_buffer struct to modify
 *
 * Returns true if the page was successfully allocated or
 * reused.
 **/
static bool iavf_alloc_mapped_page(struct iavf_ring *rx_ring,
				   struct iavf_rx_buffer *bi)
{
	struct page *page = bi->page;
	dma_addr_t dma;

	/* since we are recycling buffers we should seldom need to alloc */
	if (likely(page)) {
		rx_ring->rx_stats.page_reuse_count++;
		return true;
	}

	/* alloc new page for storage */
	page = dev_alloc_pages(iavf_rx_pg_order(rx_ring));
	if (unlikely(!page)) {
		rx_ring->rx_stats.alloc_page_failed++;
		return false;
	}

	/* map page for use */
	dma = dma_map_page_attrs(rx_ring->dev, page, 0,
				 iavf_rx_pg_size(rx_ring),
				 DMA_FROM_DEVICE,
				 IAVF_RX_DMA_ATTR);

	/* if mapping failed free memory back to system since
	 * there isn't much point in holding memory we can't use
	 */
	if (dma_mapping_error(rx_ring->dev, dma)) {
		__free_pages(page, iavf_rx_pg_order(rx_ring));
		rx_ring->rx_stats.alloc_page_failed++;
		return false;
	}

	bi->dma = dma;
	bi->page = page;
	bi->page_offset = iavf_rx_offset(rx_ring);

	/* initialize pagecnt_bias to 1 representing we fully own page */
	bi->pagecnt_bias = 1;

	return true;
}

/**
 * iavf_receive_skb - Send a completed packet up the stack
 * @rx_ring:  rx ring in play
 * @skb: packet to send up
 * @vlan_tag: vlan tag for packet
 **/
static void iavf_receive_skb(struct iavf_ring *rx_ring,
			     struct sk_buff *skb, u16 vlan_tag)
{
	struct iavf_q_vector *q_vector = rx_ring->q_vector;
#ifdef HAVE_VLAN_RX_REGISTER
	struct iavf_vsi *vsi = rx_ring->vsi;
#endif

#ifdef HAVE_VLAN_RX_REGISTER
	if (vlan_tag & VLAN_VID_MASK) {
		if (!vsi->vlgrp)
			dev_kfree_skb_any(skb);
		else
			vlan_gro_receive(&q_vector->napi, vsi->vlgrp,
					 vlan_tag, skb);
	}
#else /* HAVE_VLAN_RX_REGISTER */
	if (vlan_tag & VLAN_VID_MASK) {
		if (rx_ring->netdev->features & IAVF_NETIF_F_HW_VLAN_CTAG_RX) {
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       vlan_tag);
#ifdef IAVF_ADD_PROBES
			rx_ring->vsi->back->rx_vlano++;
#endif /* IAVF_ADD_PROBES */
#ifdef NETIF_F_HW_VLAN_STAG_RX
		} else if (rx_ring->netdev->features & NETIF_F_HW_VLAN_STAG_RX) {
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD),
					       vlan_tag);
#ifdef IAVF_ADD_PROBES
			rx_ring->vsi->back->rx_ad_vlano++;
#endif /* IAVF_ADD_PROBES */
#endif /* NETIF_F_HW_VLAN_STAG_RX */
		}
	}

	napi_gro_receive(&q_vector->napi, skb);
#endif /* HAVE_VLAN_RX_REGISTER */
}

/**
 * iavf_alloc_rx_buffers - Replace used receive buffers
 * @rx_ring: ring to place buffers on
 * @cleaned_count: number of buffers to replace
 *
 * Returns false if all allocations were successful, true if any fail
 **/
bool iavf_alloc_rx_buffers(struct iavf_ring *rx_ring, u16 cleaned_count)
{
	u16 ntu = rx_ring->next_to_use;
	union iavf_rx_desc *rx_desc;
	struct iavf_rx_buffer *bi;
#ifdef HAVE_PF_RING
#ifdef HAVE_PF_RING_ONLY
	struct iavf_adapter *adapter = netdev_priv(rx_ring->netdev); 
#endif
#endif

	/* do nothing if no valid netdev defined */
	if (!rx_ring->netdev || !cleaned_count)
		return false;

#ifdef HAVE_PF_RING
#ifdef HAVE_PF_RING_ONLY
	if (!kernel_only_adapter[adapter->instance]) {
		iavf_release_rx_desc(rx_ring, 0 /* set tail to 0 */);
		return true;
	}
#endif
	if (unlikely(enable_debug))
		printk("[PF_RING-ZC] %s(%s) prefilling rx ring with %u/%u skbuff\n",
			__FUNCTION__, rx_ring->netdev->name,
			cleaned_count, rx_ring->count);
#endif

	rx_desc = IAVF_RX_DESC(rx_ring, ntu);
	bi = &rx_ring->rx_bi[ntu];

	do {
		if (!iavf_alloc_mapped_page(rx_ring, bi))
			goto no_buffers;

		/* sync the buffer for use by the device */
		dma_sync_single_range_for_device(rx_ring->dev, bi->dma,
						 bi->page_offset,
						 rx_ring->rx_buf_len,
						 DMA_FROM_DEVICE);

		/* Refresh the desc even if buffer_addrs didn't change
		 * because each write-back erases this info.
		 */
		rx_desc->read.pkt_addr = cpu_to_le64(bi->dma + bi->page_offset);

		rx_desc++;
		bi++;
		ntu++;
		if (unlikely(ntu == rx_ring->count)) {
			rx_desc = IAVF_RX_DESC(rx_ring, 0);
			bi = rx_ring->rx_bi;
			ntu = 0;
		}

		/* clear the status bits for the next_to_use descriptor */
		rx_desc->wb.qword1.status_error_len = 0;

		cleaned_count--;
	} while (cleaned_count);

	if (rx_ring->next_to_use != ntu)
		iavf_release_rx_desc(rx_ring, ntu);

	return false;

no_buffers:
	if (rx_ring->next_to_use != ntu)
		iavf_release_rx_desc(rx_ring, ntu);

	/* make sure to come back via polling to try again after
	 * allocation failure
	 */
	return true;
}

/*
 * iavf_rx_csum_decoded
 *
 * Checksum offload bits decoded from the receive descriptor.
 */
struct iavf_rx_csum_decoded {
	u8 l3l4p : 1;
	u8 ipe : 1;
	u8 eipe : 1;
	u8 eudpe : 1;
	u8 ipv6exadd : 1;
	u8 l4e : 1;
	u8 pprs : 1;
	u8 nat : 1;
};

#ifdef IAVF_ADD_PROBES
static void iavf_rx_extra_counters(struct iavf_vsi *vsi,
				   struct iavf_rx_csum_decoded *csum_bits,
				   struct iavf_rx_ptype_decoded *decoded)
{
	bool ipv4;

	ipv4 = (decoded->outer_ip == IAVF_RX_PTYPE_OUTER_IP) &&
	       (decoded->outer_ip_ver == IAVF_RX_PTYPE_OUTER_IPV4);

	if (ipv4 && (csum_bits->ipe | csum_bits->eipe))
		vsi->back->rx_ip4_cso_err++;

	if (csum_bits->l4e) {
		if (decoded->inner_prot == IAVF_RX_PTYPE_INNER_PROT_TCP)
			vsi->back->rx_tcp_cso_err++;
		else if (decoded->inner_prot == IAVF_RX_PTYPE_INNER_PROT_UDP)
			vsi->back->rx_udp_cso_err++;
		else if (decoded->inner_prot == IAVF_RX_PTYPE_INNER_PROT_SCTP)
			vsi->back->rx_sctp_cso_err++;
	}

	if (decoded->outer_ip == IAVF_RX_PTYPE_OUTER_IP &&
	    decoded->outer_ip_ver == IAVF_RX_PTYPE_OUTER_IPV4)
		vsi->back->rx_ip4_cso++;
	if (decoded->inner_prot == IAVF_RX_PTYPE_INNER_PROT_TCP)
		vsi->back->rx_tcp_cso++;
	else if (decoded->inner_prot == IAVF_RX_PTYPE_INNER_PROT_UDP)
		vsi->back->rx_udp_cso++;
	else if (decoded->inner_prot == IAVF_RX_PTYPE_INNER_PROT_SCTP)
		vsi->back->rx_sctp_cso++;
}

#endif /* IAVF_ADD_PROBES */
#if defined(HAVE_VXLAN_RX_OFFLOAD) || defined(HAVE_GENEVE_RX_OFFLOAD) || defined(HAVE_UDP_ENC_RX_OFFLOAD)
#define IAVF_TUNNEL_SUPPORT
#endif

/**
 * iavf_rx_csum - Indicate in skb if hw indicated a good cksum
 * @vsi: the VSI we care about
 * @skb: skb currently being received and modified
 * @ptype: decoded ptype information
 * @csum_bits: decoded Rx descriptor information
 **/
static void
iavf_rx_csum(struct iavf_vsi *vsi, struct sk_buff *skb,
	     struct iavf_rx_ptype_decoded *ptype,
	     struct iavf_rx_csum_decoded *csum_bits)
{
	bool ipv4, ipv6;

	skb->ip_summed = CHECKSUM_NONE;
	skb_checksum_none_assert(skb);

	/* Rx csum enabled and ip headers found? */
#ifdef HAVE_NDO_SET_FEATURES
	if (!(vsi->netdev->features & NETIF_F_RXCSUM))
		return;
#else
	if (!(vsi->back->flags & IAVF_FLAG_RX_CSUM_ENABLED))
		return;
#endif

	/* did the hardware decode the packet and checksum? */
	if (!csum_bits->l3l4p)
		return;

	/* both known and outer_ip must be set for the below code to work */
	if (!(ptype->known && ptype->outer_ip))
		return;
#ifdef IAVF_ADD_PROBES
	vsi->back->hw_csum_rx_outer++;
#endif

	ipv4 = (ptype->outer_ip == IAVF_RX_PTYPE_OUTER_IP) &&
	       (ptype->outer_ip_ver == IAVF_RX_PTYPE_OUTER_IPV4);
	ipv6 = (ptype->outer_ip == IAVF_RX_PTYPE_OUTER_IP) &&
	       (ptype->outer_ip_ver == IAVF_RX_PTYPE_OUTER_IPV6);

#ifdef IAVF_ADD_PROBES
	iavf_rx_extra_counters(vsi, csum_bits, ptype);
#endif /* IAVF_ADD_PROBES */
	if (ipv4 && (csum_bits->ipe || csum_bits->eipe))
		goto checksum_fail;

	/* likely incorrect csum if alternate IP extension headers found */
	if (ipv6 && csum_bits->ipv6exadd)
		/* don't increment checksum err here, non-fatal err */
		return;

	/* there was some L4 error, count error and punt packet to the stack */
	if (csum_bits->l4e)
		goto checksum_fail;

	if (csum_bits->nat && csum_bits->eudpe)
		goto checksum_fail;

	/* handle packets that were not able to be checksummed due
	 * to arrival speed, in this case the stack can compute
	 * the csum.
	 */
	if (csum_bits->pprs)
		return;

	/* If there is an outer header present that might contain a checksum
	 * we need to bump the checksum level by 1 to reflect the fact that
	 * we are indicating we validated the inner checksum.
	 */
	if (ptype->tunnel_type >= IAVF_RX_PTYPE_TUNNEL_IP_GRENAT)
#ifdef HAVE_SKBUFF_CSUM_LEVEL
		skb->csum_level = 1;
#else
		skb->encapsulation = 1;
#endif

	/* Only report checksum unnecessary for TCP, UDP, or SCTP */
	switch (ptype->inner_prot) {
	case IAVF_RX_PTYPE_INNER_PROT_TCP:
	case IAVF_RX_PTYPE_INNER_PROT_UDP:
	case IAVF_RX_PTYPE_INNER_PROT_SCTP:
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		fallthrough;
	default:
		break;
	}
	return;

checksum_fail:
	vsi->back->hw_csum_rx_error++;
}

/**
 * iavf_legacy_rx_csum - Indicate in skb if hw indicated a good cksum
 * @vsi: the VSI we care about
 * @skb: skb currently being received and modified
 * @rx_desc: the receive descriptor
 *
 * This function only operates on the VIRTCHNL_RXDID_1_32B_BASE legacy 32byte
 * descriptor writeback format.
 **/
static void
iavf_legacy_rx_csum(struct iavf_vsi *vsi, struct sk_buff *skb, union iavf_rx_desc *rx_desc)
{
	struct iavf_rx_csum_decoded csum_bits;
	struct iavf_rx_ptype_decoded decoded;
	u32 rx_error, rx_status;
	u64 qword;
	u16 ptype;

	qword = le64_to_cpu(rx_desc->wb.qword1.status_error_len);
	ptype = (qword & IAVF_RXD_QW1_PTYPE_MASK) >> IAVF_RXD_QW1_PTYPE_SHIFT;
	rx_error = (qword & IAVF_RXD_QW1_ERROR_MASK) >>
		   IAVF_RXD_QW1_ERROR_SHIFT;
	rx_status = (qword & IAVF_RXD_QW1_STATUS_MASK) >>
		    IAVF_RXD_QW1_STATUS_SHIFT;
	decoded = decode_rx_desc_ptype(ptype);

	csum_bits.ipe = !!(rx_error & BIT(IAVF_RX_DESC_ERROR_IPE_SHIFT));
	csum_bits.eipe = !!(rx_error & BIT(IAVF_RX_DESC_ERROR_EIPE_SHIFT));
	csum_bits.l4e = !!(rx_error & BIT(IAVF_RX_DESC_ERROR_L4E_SHIFT));
	csum_bits.pprs = !!(rx_error & BIT(IAVF_RX_DESC_ERROR_PPRS_SHIFT));
	csum_bits.l3l4p = !!(rx_status & BIT(IAVF_RX_DESC_STATUS_L3L4P_SHIFT));
	csum_bits.ipv6exadd = !!(rx_status & BIT(IAVF_RX_DESC_STATUS_IPV6EXADD_SHIFT));
	csum_bits.nat = 0;
	csum_bits.eudpe = 0;

	iavf_rx_csum(vsi, skb, &decoded, &csum_bits);
}

/**
 * iavf_flex_rx_csum - Indicate in skb if hw indicated a good cksum
 * @vsi: the VSI we care about
 * @skb: skb currently being received and modified
 * @rx_desc: the receive descriptor
 *
 * This function only operates on the VIRTCHNL_RXDID_2_FLEX_SQ_NIC flexible
 * descriptor writeback format.
 **/
static void
iavf_flex_rx_csum(struct iavf_vsi *vsi, struct sk_buff *skb, union iavf_rx_desc *rx_desc)
{
	struct iavf_rx_csum_decoded csum_bits;
	struct iavf_rx_ptype_decoded decoded;
	u16 rx_status0, rx_status1, ptype;

	rx_status0 = le16_to_cpu(rx_desc->flex_wb.status_error0);
	rx_status1 = le16_to_cpu(rx_desc->flex_wb.status_error1);
	ptype = le16_to_cpu(rx_desc->flex_wb.ptype_flexi_flags0) &
		IAVF_RX_FLEX_DESC_PTYPE_M;
	decoded = decode_rx_desc_ptype(ptype);

	csum_bits.ipe = !!(rx_status0 & BIT(IAVF_RX_FLEX_DESC_STATUS0_XSUM_IPE_S));
	csum_bits.eipe = !!(rx_status0 & BIT(IAVF_RX_FLEX_DESC_STATUS0_XSUM_EIPE_S));
	csum_bits.l4e = !!(rx_status0 & BIT(IAVF_RX_FLEX_DESC_STATUS0_XSUM_L4E_S));
	csum_bits.eudpe = !!(rx_status0 & BIT(IAVF_RX_FLEX_DESC_STATUS0_XSUM_EUDPE_S));
	csum_bits.pprs = 0;
	csum_bits.l3l4p = !!(rx_status0 & BIT(IAVF_RX_FLEX_DESC_STATUS0_L3L4P_S));
	csum_bits.ipv6exadd = !!(rx_status0 & BIT(IAVF_RX_FLEX_DESC_STATUS0_IPV6EXADD_S));
	csum_bits.nat = !!(rx_status1 & BIT(IAVF_RX_FLEX_DESC_STATUS1_NAT_S));

	iavf_rx_csum(vsi, skb, &decoded, &csum_bits);
}

/**
 * iavf_ptype_to_htype - get a hash type
 * @ptype: the ptype value from the descriptor
 *
 * Returns a hash type to be used by skb_set_hash
 **/
static enum pkt_hash_types iavf_ptype_to_htype(u16 ptype)
{
	struct iavf_rx_ptype_decoded decoded = decode_rx_desc_ptype(ptype);

	if (!decoded.known)
		return PKT_HASH_TYPE_NONE;

	if (decoded.outer_ip == IAVF_RX_PTYPE_OUTER_IP &&
	    decoded.payload_layer == IAVF_RX_PTYPE_PAYLOAD_LAYER_PAY4)
		return PKT_HASH_TYPE_L4;
	else if (decoded.outer_ip == IAVF_RX_PTYPE_OUTER_IP &&
		 decoded.payload_layer == IAVF_RX_PTYPE_PAYLOAD_LAYER_PAY3)
		return PKT_HASH_TYPE_L3;
	else
		return PKT_HASH_TYPE_L2;
}

/**
 * iavf_legacy_rx_hash - set the hash value in the skb
 * @ring: descriptor ring
 * @rx_desc: specific descriptor
 * @skb: skb currently being received and modified
 * @rx_ptype: Rx packet type
 *
 * This function only operates on the VIRTCHNL_RXDID_1_32B_BASE legacy 32byte
 * descriptor writeback format.
 **/
static void
iavf_legacy_rx_hash(struct iavf_ring *ring, union iavf_rx_desc *rx_desc, struct sk_buff *skb,
		    u16 rx_ptype)
{
#ifdef NETIF_F_RXHASH
	u32 hash;
	const __le64 rss_mask =
		cpu_to_le64((u64)IAVF_RX_DESC_FLTSTAT_RSS_HASH <<
			    IAVF_RX_DESC_STATUS_FLTSTAT_SHIFT);

	if (!(ring->netdev->features & NETIF_F_RXHASH))
		return;

	if ((rx_desc->wb.qword1.status_error_len & rss_mask) == rss_mask) {
		hash = le32_to_cpu(rx_desc->wb.qword0.hi_dword.rss);
		skb_set_hash(skb, hash, iavf_ptype_to_htype(rx_ptype));
	}
#endif /* NETIF_F_RXHASH */
}

/**
 * iavf_flex_rx_hash - set the hash value in the skb
 * @ring: descriptor ring
 * @rx_desc: specific descriptor
 * @skb: skb currently being received and modified
 * @rx_ptype: Rx packet type
 *
 * This function only operates on the VIRTCHNL_RXDID_2_FLEX_SQ_NIC flexible
 * descriptor writeback format.
 **/
static void
iavf_flex_rx_hash(struct iavf_ring *ring, union iavf_rx_desc *rx_desc, struct sk_buff *skb,
		  u16 rx_ptype)
{
#ifdef NETIF_F_RXHASH
	__le16 status0;

	if (!(ring->netdev->features & NETIF_F_RXHASH))
		return;

	status0 = rx_desc->flex_wb.status_error0;
	if (status0 & cpu_to_le16(BIT(IAVF_RX_FLEX_DESC_STATUS0_RSS_VALID_S))) {
		u32 hash = le32_to_cpu(rx_desc->flex_wb.rss_hash);

		skb_set_hash(skb, hash, iavf_ptype_to_htype(rx_ptype));
	}
#endif /* NETIF_F_RXHASH */
}

/**
 * iavf_flex_rx_tstamp - Capture Rx timestamp from the descriptor
 * @rx_ring: descriptor ring
 * @rx_desc: specific descriptor
 * @skb: skb currently being received
 *
 * Read the Rx timestamp value from the descriptor and pass it to the stack.
 *
 * This function only operates on the VIRTCHNL_RXDID_2_FLEX_SQ_NIC flexible
 * descriptor writeback format.
 */
static void
iavf_flex_rx_tstamp(struct iavf_ring *rx_ring, union iavf_rx_desc *rx_desc, struct sk_buff *skb)
{
	struct skb_shared_hwtstamps *skb_tstamps;
	struct iavf_adapter *adapter;
	u32 tstamp;
	u64 ns;

	/* Skip processing if timestamps aren't enabled */
	if (!(rx_ring->flags & IAVF_TXRX_FLAGS_HW_TSTAMP))
		return;

	/* Check if this Rx descriptor has a valid timestamp */
	if (!(rx_desc->flex_wb.ts_low & IAVF_PTP_40B_TSTAMP_VALID))
		return;

	adapter = netdev_priv(rx_ring->netdev);

	/* the ts_low field only contains the valid bit and sub-nanosecond
	 * precision, so we don't need to extract it.
	 */
	tstamp = le32_to_cpu(rx_desc->flex_wb.flex_ts.ts_high);
	ns = iavf_ptp_extend_32b_timestamp(adapter->ptp.cached_phc_time, tstamp);

	skb_tstamps = skb_hwtstamps(skb);
	memset(skb_tstamps, 0, sizeof(*skb_tstamps));
	skb_tstamps->hwtstamp = ns_to_ktime(ns);
}

/**
 * iavf_process_skb_fields - Populate skb header fields from Rx descriptor
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @rx_desc: pointer to the EOP Rx descriptor
 * @skb: pointer to current skb being populated
 * @rx_ptype: the packet type decoded by hardware
 *
 * This function checks the ring, descriptor, and packet information in
 * order to populate the hash, checksum, VLAN, protocol, and
 * other fields within the skb.
 **/
static void
iavf_process_skb_fields(struct iavf_ring *rx_ring, union iavf_rx_desc *rx_desc,
			struct sk_buff *skb, u16 rx_ptype)
{
	if (rx_ring->rxdid == VIRTCHNL_RXDID_1_32B_BASE) {
		iavf_legacy_rx_hash(rx_ring, rx_desc, skb, rx_ptype);

		iavf_legacy_rx_csum(rx_ring->vsi, skb, rx_desc);
	} else {
		iavf_flex_rx_hash(rx_ring, rx_desc, skb, rx_ptype);

		iavf_flex_rx_csum(rx_ring->vsi, skb, rx_desc);

		iavf_flex_rx_tstamp(rx_ring, rx_desc, skb);
	}

	skb_record_rx_queue(skb, rx_ring->queue_index);

	/* modifies the skb - consumes the enet header */
	skb->protocol = eth_type_trans(skb, rx_ring->netdev);
}

/**
 * iavf_cleanup_headers - Correct empty headers
 * @rx_ring: rx descriptor ring packet is being transacted on
 * @skb: pointer to current skb being fixed
 * @rx_desc: pointer to the EOP Rx descriptor
 *
 * Also address the case where we are pulling data in on pages only
 * and as such no data is present in the skb header.
 *
 * In addition if skb is not at least 60 bytes we need to pad it so that
 * it is large enough to qualify as a valid Ethernet frame.
 *
 * Returns true if an error was encountered and skb was freed.
 **/
static bool iavf_cleanup_headers(struct iavf_ring *rx_ring, struct sk_buff *skb,
				 union iavf_rx_desc *rx_desc)
{
	/* XDP packets use error pointer so abort at this point */
	if (IS_ERR(skb))
		return true;

	/* ERR_MASK will only have valid bits if EOP set, and
	 * what we are doing here is actually checking
	 * IAVF_RX_DESC_ERROR_RXE_SHIFT, since it is the zeroth bit in
	 * the error field
	 */
	if (unlikely(iavf_test_staterr(rx_desc,
				       BIT(IAVF_RXD_QW1_ERROR_SHIFT)))) {
		dev_kfree_skb_any(skb);
		return true;
	}

	/* if eth_skb_pad returns an error the skb was freed */
	if (eth_skb_pad(skb))
		return true;

	return false;
}

/**
 * iavf_page_is_reusable - check if any reuse is possible
 * @page: page struct to check
 *
 * A page is not reusable if it was allocated under low memory
 * conditions, or it's not in the same NUMA node as this CPU.
 */
static bool iavf_page_is_reusable(struct page *page)
{
	return (page_to_nid(page) == numa_mem_id()) &&
		!page_is_pfmemalloc(page);
}

/**
 * iavf_reuse_rx_page - page flip buffer and store it back on the ring
 * @rx_ring: rx descriptor ring to store buffers on
 * @old_buff: donor buffer to have page reused
 *
 * Synchronizes page for reuse by the adapter
 **/
static void iavf_reuse_rx_page(struct iavf_ring *rx_ring,
			       struct iavf_rx_buffer *old_buff)
{
	struct iavf_rx_buffer *new_buff;
	u16 nta = rx_ring->next_to_alloc;

	new_buff = &rx_ring->rx_bi[nta];

	/* update, and store next to alloc */
	nta++;
	rx_ring->next_to_alloc = (nta < rx_ring->count) ? nta : 0;

	/* transfer page from old buffer to new buffer */
	new_buff->dma		= old_buff->dma;
	new_buff->page		= old_buff->page;
	new_buff->page_offset	= old_buff->page_offset;
	new_buff->pagecnt_bias	= old_buff->pagecnt_bias;
}

/**
 * iavf_can_reuse_rx_page - Determine if this page can be reused by
 * the adapter for another receive
 *
 * @rx_buffer: buffer containing the page
 *
 * If page is reusable, rx_buffer->page_offset is adjusted to point to
 * an unused region in the page.
 *
 * For small pages, @truesize will be a constant value, half the size
 * of the memory at page.  We'll attempt to alternate between high and
 * low halves of the page, with one half ready for use by the hardware
 * and the other half being consumed by the stack.  We use the page
 * ref count to determine whether the stack has finished consuming the
 * portion of this page that was passed up with a previous packet.  If
 * the page ref count is >1, we'll assume the "other" half page is
 * still busy, and this page cannot be reused.
 *
 * For larger pages, @truesize will be the actual space used by the
 * received packet (adjusted upward to an even multiple of the cache
 * line size).  This will advance through the page by the amount
 * actually consumed by the received packets while there is still
 * space for a buffer.  Each region of larger pages will be used at
 * most once, after which the page will not be reused.
 *
 * In either case, if the page is reusable its refcount is increased.
 **/
static bool iavf_can_reuse_rx_page(struct iavf_rx_buffer *rx_buffer)
{
	unsigned int pagecnt_bias = rx_buffer->pagecnt_bias;
	struct page *page = rx_buffer->page;

	/* Is any reuse possible? */
	if (unlikely(!iavf_page_is_reusable(page)))
		return false;

#if (PAGE_SIZE < 8192)
	/* if we are only owner of page we can reuse it */
	if (unlikely((page_count(page) - pagecnt_bias) > 1))
		return false;
#else
#define IAVF_LAST_OFFSET \
	(SKB_WITH_OVERHEAD(PAGE_SIZE) - IAVF_RXBUFFER_2048)
	if (rx_buffer->page_offset > IAVF_LAST_OFFSET)
		return false;
#endif

	/* If we have drained the page fragment pool we need to update
	 * the pagecnt_bias and page count so that we fully restock the
	 * number of references the driver holds.
	 */
#ifdef HAVE_PAGE_COUNT_BULK_UPDATE
	if (unlikely(!pagecnt_bias)) {
		page_ref_add(page, USHRT_MAX);
		rx_buffer->pagecnt_bias = USHRT_MAX;
	}
#else
	if (likely(!pagecnt_bias)) {
		get_page(page);
		rx_buffer->pagecnt_bias = 1;
	}
#endif

	return true;
}

/**
 * iavf_add_rx_frag - Add contents of Rx buffer to sk_buff
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: buffer containing page to add
 * @skb: sk_buff to place the data into
 * @size: packet length from rx_desc
 *
 * This function will add the data contained in rx_buffer->page to the skb.
 * It will just attach the page as a frag to the skb.
 *
 * The function will then update the page offset.
 **/
static void iavf_add_rx_frag(struct iavf_ring *rx_ring,
			     struct iavf_rx_buffer *rx_buffer,
			     struct sk_buff *skb,
			     unsigned int size)
{
#if (PAGE_SIZE < 8192)
	unsigned int truesize = iavf_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = SKB_DATA_ALIGN(size + iavf_rx_offset(rx_ring));
#endif

	if (!size)
		return;

	skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, rx_buffer->page,
			rx_buffer->page_offset, size, truesize);

	/* page is being used so we must update the page offset */
#if (PAGE_SIZE < 8192)
	rx_buffer->page_offset ^= truesize;
#else
	rx_buffer->page_offset += truesize;
#endif
}

/**
 * iavf_get_rx_buffer - Fetch Rx buffer and synchronize data for use
 * @rx_ring: rx descriptor ring to transact packets on
 * @size: size of buffer to add to skb
 *
 * This function will pull an Rx buffer from the ring and synchronize it
 * for use by the CPU.
 */
static struct iavf_rx_buffer *iavf_get_rx_buffer(struct iavf_ring *rx_ring,
						 const unsigned int size)
{
	struct iavf_rx_buffer *rx_buffer;

	rx_buffer = &rx_ring->rx_bi[rx_ring->next_to_clean];
	prefetchw(rx_buffer->page);
	if (!size)
		return rx_buffer;

	/* we are reusing so sync this buffer for CPU use */
	dma_sync_single_range_for_cpu(rx_ring->dev,
				      rx_buffer->dma,
				      rx_buffer->page_offset,
				      size,
				      DMA_FROM_DEVICE);

	/* We have pulled a buffer for use, so decrement pagecnt_bias */
	rx_buffer->pagecnt_bias--;

	return rx_buffer;
}

/**
 * iavf_construct_skb - Allocate skb and populate it
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: rx buffer to pull data from
 * @xdp: xdp_buff pointing to the data
 *
 * This function allocates an skb.  It then populates it with the page
 * data from the current receive descriptor, taking care to set up the
 * skb correctly.
 */
static struct sk_buff *iavf_construct_skb(struct iavf_ring *rx_ring,
					  struct iavf_rx_buffer *rx_buffer,
					  struct xdp_buff *xdp)
{
	unsigned int size = (u8 *)xdp->data_end - (u8 *)xdp->data;

#if (PAGE_SIZE < 8192)
	unsigned int truesize = iavf_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) +
				SKB_DATA_ALIGN(IAVF_SKB_PAD + size);
#endif
	unsigned int headlen;
	struct sk_buff *skb;

	if (!rx_buffer)
		return NULL;
	/* prefetch first cache line of first page */
	prefetch(xdp->data);
#if L1_CACHE_BYTES < 128
	prefetch((void *)((u8 *)xdp->data + L1_CACHE_BYTES));
#endif

	/* allocate a skb to store the frags */
#if 1
	skb = napi_alloc_skb(&rx_ring->q_vector->napi,
			       IAVF_RX_HDR_SIZE);
#else
	skb = __napi_alloc_skb(&rx_ring->q_vector->napi,
			       IAVF_RX_HDR_SIZE,
			       GFP_ATOMIC | __GFP_NOWARN);
#endif
	if (unlikely(!skb))
		return NULL;

	/* Determine available headroom for copy */
	headlen = size;
	if (headlen > IAVF_RX_HDR_SIZE)
		headlen = eth_get_headlen(skb->dev, xdp->data,
					  IAVF_RX_HDR_SIZE);

	/* align pull length to size of long to optimize memcpy performance */
	memcpy(__skb_put(skb, headlen), xdp->data,
	       ALIGN(headlen, sizeof(long)));

	/* update all of the pointers */
	size -= headlen;
	if (size) {
		skb_add_rx_frag(skb, 0, rx_buffer->page,
				rx_buffer->page_offset + headlen,
				size, truesize);

		/* buffer is used by skb, update page_offset */
#if (PAGE_SIZE < 8192)
		rx_buffer->page_offset ^= truesize;
#else
		rx_buffer->page_offset += truesize;
#endif
	} else {
		/* buffer is unused, reset bias back to rx_buffer */
		rx_buffer->pagecnt_bias++;
	}

	return skb;
}

#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
/**
 * iavf_build_skb - Build skb around an existing buffer
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: rx buffer to pull data from
 * @xdp: xdp_buff pointing to the data
 *
 * This function builds an skb around an existing Rx buffer, taking care
 * to set up the skb correctly and avoid any memcpy overhead.
 */
static struct sk_buff *iavf_build_skb(struct iavf_ring *rx_ring,
				      struct iavf_rx_buffer *rx_buffer,
				      struct xdp_buff *xdp)
{
	unsigned int size = (u8 *)xdp->data_end - (u8 *)xdp->data;

#if (PAGE_SIZE < 8192)
	unsigned int truesize = iavf_rx_pg_size(rx_ring) / 2;
#else
	unsigned int truesize = SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) +
				SKB_DATA_ALIGN(xdp->data_end -
					       xdp->data_hard_start);
#endif
	struct sk_buff *skb;

	if (!rx_buffer)
		return NULL;

	/* prefetch first cache line of first page */
	prefetch(xdp->data);
#if L1_CACHE_BYTES < 128
	prefetch(xdp->data + L1_CACHE_BYTES);
#endif
	/* build an skb around the page buffer */
	skb = build_skb(xdp->data_hard_start, truesize);
	if (unlikely(!skb))
		return NULL;

	/* update pointers within the skb to store the data */
	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	__skb_put(skb, size);

	/* buffer is used by skb, update page_offset */
#if (PAGE_SIZE < 8192)
	rx_buffer->page_offset ^= truesize;
#else
	rx_buffer->page_offset += truesize;
#endif

	return skb;
}

#endif /* HAVE_SWIOTLB_SKIP_CPU_SYNC */
/**
 * iavf_put_rx_buffer - Clean up used buffer and either recycle or free
 * @rx_ring: rx descriptor ring to transact packets on
 * @rx_buffer: rx buffer to pull data from
 *
 * This function will clean up the contents of the rx_buffer.  It will
 * either recycle the buffer or unmap it and free the associated resources.
 */
static void iavf_put_rx_buffer(struct iavf_ring *rx_ring,
			       struct iavf_rx_buffer *rx_buffer)
{
	if (!rx_buffer)
		return;

	if (iavf_can_reuse_rx_page(rx_buffer)) {
		/* hand second half of page back to the ring */
		iavf_reuse_rx_page(rx_ring, rx_buffer);
		rx_ring->rx_stats.page_reuse_count++;
	} else {
		/* we are not reusing the buffer so unmap it */
		dma_unmap_page_attrs(rx_ring->dev, rx_buffer->dma,
				     iavf_rx_pg_size(rx_ring),
				     DMA_FROM_DEVICE, IAVF_RX_DMA_ATTR);
		__page_frag_cache_drain(rx_buffer->page,
					rx_buffer->pagecnt_bias);
	}

	/* clear contents of buffer_info */
	rx_buffer->page = NULL;
}

/**
 * iavf_is_non_eop - process handling of non-EOP buffers
 * @rx_ring: Rx ring being processed
 * @rx_desc: Rx descriptor for current buffer
 * @skb: Current socket buffer containing buffer in progress
 *
 * This function updates next to clean.  If the buffer is an EOP buffer
 * this function exits returning false, otherwise it will place the
 * sk_buff in the next buffer to be chained and return true indicating
 * that this is in fact a non-EOP buffer.
 **/
static bool iavf_is_non_eop(struct iavf_ring *rx_ring,
			    union iavf_rx_desc *rx_desc,
			    struct sk_buff *skb)
{
	u32 ntc = rx_ring->next_to_clean + 1;

	/* fetch, update, and store next to clean */
	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;

	prefetch(IAVF_RX_DESC(rx_ring, ntc));

	/* if we are the last buffer then there is nothing else to do */
#define IAVF_RXD_EOF BIT(IAVF_RX_DESC_STATUS_EOF_SHIFT)
	if (likely(iavf_test_staterr(rx_desc, IAVF_RXD_EOF)))
		return false;

	rx_ring->rx_stats.non_eop_descs++;

	return true;
}

#define IAVF_XDP_PASS          0
#define IAVF_XDP_CONSUMED      BIT(0)
#define IAVF_XDP_TX            BIT(1)
#define IAVF_XDP_REDIR         BIT(2)

/**
 * iavf_run_xdp - run an XDP program
 * @rx_ring: Rx ring being processed
 * @xdp: XDP buffer containing the frame
 **/
static struct sk_buff *iavf_run_xdp(struct iavf_ring *rx_ring,
				    struct xdp_buff *xdp)
{
	int result = IAVF_XDP_PASS;
	return (struct sk_buff *)ERR_PTR(-result);
}

/**
 * iavf_rx_buffer_flip - adjusted rx_buffer to point to an unused region
 * @rx_ring: Rx ring
 * @rx_buffer: Rx buffer to adjust
 * @size: Size of adjustment
 **/
static void iavf_rx_buffer_flip(struct iavf_ring *rx_ring,
				struct iavf_rx_buffer *rx_buffer,
				unsigned int size)
{
#if (PAGE_SIZE < 8192)
	unsigned int truesize = iavf_rx_pg_size(rx_ring) / 2;

	if (!rx_buffer)
		return;
	rx_buffer->page_offset ^= truesize;
#else
	unsigned int truesize = SKB_DATA_ALIGN(iavf_rx_offset(rx_ring) + size);

	if (!rx_buffer)
		return;
	rx_buffer->page_offset += truesize;
#endif
}

static void iavf_xdp_ring_update_tail(struct iavf_ring *xdp_ring)
{
	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.
	 */
	wmb();
	writel_relaxed(xdp_ring->next_to_use, xdp_ring->tail);
}

/**
 * iavf_is_ctrl_pkt - check if packet is a TCP control packet or data packet
 * @skb: receive buffer
 * @rx_ring: ptr to Rx ring
 *
 * Returns true for all unsupported protocol/configuration. Supported protocol
 * is TCP/IPv4[6].  For TCP/IPv6, this function returns true if packet contains
 * nested header.
 * Logic to determine control packet:
 * - packets is control packet if it contains flags like SYN, SYN+ACK, FIN, RST
 *
 * Returns true if packet is classified as control packet and for all unhandled
 * condition otherwise false if packet is classified as data packet
 */
static bool iavf_is_ctrl_pkt(struct sk_buff *skb, struct iavf_ring *rx_ring)

{
	union {
		unsigned char *network;
		struct ipv6hdr *ipv6;
		struct iphdr *ipv4;
	} hdr;
	struct tcphdr *th;

	/* at this point, skb->data points to network header since
	 * ethernet_header was pulled inline due to eth_type_trans
	 */
	hdr.network = skb->data;

	/* only support IPv4/IPv6, all other protocol being treated like
	 * control packets
	 */
	if (skb->protocol == htons(ETH_P_IP)) {
		unsigned int hlen;

		/* access ihl as u8 to avoid unaligned access on ia64 */
		hlen = (hdr.network[0] & 0x0F) << 2;

		/* for now, assume all non TCP packets are ctrl packets, so that
		 * they don't get counted to evaluate the likelihood of being
		 * called back for polling
		 */
		if (hdr.ipv4->protocol != IPPROTO_TCP)
			return true;

		th = (struct tcphdr *)(hdr.network + hlen);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		/* for now, if next_hdr is not TCP, means it contains nested
		 * header. IPv6 packets which contains nested header:
		 * treat them like control packet, so that interrupts gets
		 * enabled normally, otherwise driver need to duplicate the
		 * code to parse nested IPv6 header.
		 */
		if (hdr.ipv6->nexthdr != IPPROTO_TCP)
			return true;

		th = (struct tcphdr *)(hdr.network + sizeof(struct ipv6hdr));
	} else {
		return true; /* if any other than IPv4[6], ctrl packet */
	}

	/* definition of control packet is, if packet is TCP/IPv4[6] and
	 * TCP flags are either SYN | FIN | RST.
	 * If neither of those flags (SYN|FIN|RST) are set, then it is
	 * data packet
	 */
	if (!th->fin && !th->rst && !th->syn)
		return false; /* data packet */

	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->ch_q_stats.rx.tcp_ctrl_pkts++;
	if (th->fin)
		rx_ring->ch_q_stats.rx.tcp_fin_recv++;
	else if (th->rst)
		rx_ring->ch_q_stats.rx.tcp_rst_recv++;
	else if (th->syn)
		rx_ring->ch_q_stats.rx.tcp_syn_recv++;
	u64_stats_update_end(&rx_ring->syncp);

	/* at this point based on L4 header (if it is TCP/IPv4[6]:flags,
	 * packet is detected as control packets
	 */
	return true;
}

static void iavf_chnl_rx_stats(struct iavf_ring *rx_ring, u64 pkts)
{
	iavf_chnl_queue_stats(rx_ring, pkts);

	/* if vector is transitioning from BP->INT (due to busy_poll_stop()) and
	 * we find no packets, in that case: to avoid entering into INTR mode
	 * (which happens from napi_poll - enabling interrupt if
	 * unlikely_comeback_to_bp getting set), make "prev_data_pkt_recv" to be
	 * non-zero, so that interrupts won't be enabled. This is to address the
	 * issue where num_force_wb on some queues is 2 to 3 times higher than
	 * other queues and those queues also sees lot of interrupts
	 */
	if (vector_ch_ena(rx_ring->q_vector) &&
	    vector_ch_perf_ena(rx_ring->q_vector) &&
	    vector_busypoll_intr(rx_ring->q_vector)) {
		if (!pkts)
			rx_ring->q_vector->state_flags |=
					IAVF_VECTOR_STATE_PREV_DATA_PKT_RECV;
	} else if (vector_ch_ena(rx_ring->q_vector)) {
		struct iavf_q_vector *q_vector = rx_ring->q_vector;
		u8 qv_flags = q_vector->state_flags;

		u64_stats_update_begin(&rx_ring->syncp);
		if (pkts &&
		    !(qv_flags & IAVF_VECTOR_STATE_PREV_DATA_PKT_RECV))
			rx_ring->ch_q_stats.rx.only_ctrl_pkts++;
		if (qv_flags & IAVF_VECTOR_STATE_IN_BP &&
		    !(qv_flags & IAVF_VECTOR_STATE_PREV_DATA_PKT_RECV))
			rx_ring->ch_q_stats.rx.bp_no_data_pkt++;
		u64_stats_update_end(&rx_ring->syncp);
	}
}

struct iavf_rx_extracted {
	unsigned int size;
	u16 vlan_tag;
	u16 rx_ptype;
};

/**
 * iavf_extract_legacy_rx_fields - Extract fields from the Rx descriptor
 * @rx_ring: rx descriptor ring
 * @rx_desc: the descriptor to process
 * @fields: storage for extracted values
 *
 * Decode the Rx descriptor and extract relevant information including the
 * size, VLAN tag, and Rx packet type.
 *
 * This function only operates on the VIRTCHNL_RXDID_1_32B_BASE legacy 32byte
 * descriptor writeback format.
 */
static void
iavf_extract_legacy_rx_fields(struct iavf_ring *rx_ring, union iavf_rx_desc *rx_desc,
			      struct iavf_rx_extracted *fields)
{
	u64 qword = le64_to_cpu(rx_desc->wb.qword1.status_error_len);

	fields->size = (qword & IAVF_RXD_QW1_LENGTH_PBUF_MASK) >> IAVF_RXD_QW1_LENGTH_PBUF_SHIFT;
	fields->rx_ptype = (qword & IAVF_RXD_QW1_PTYPE_MASK) >> IAVF_RXD_QW1_PTYPE_SHIFT;

	if (qword & BIT(IAVF_RX_DESC_STATUS_L2TAG1P_SHIFT) &&
	    rx_ring->flags & IAVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1)
		fields->vlan_tag = le16_to_cpu(rx_desc->wb.qword0.lo_dword.l2tag1);

	if (rx_desc->wb.qword2.ext_status &
	    cpu_to_le16(BIT(IAVF_RX_DESC_EXT_STATUS_L2TAG2P_SHIFT)) &&
	    rx_ring->flags & IAVF_RXR_FLAGS_VLAN_TAG_LOC_L2TAG2_2)
		fields->vlan_tag = le16_to_cpu(rx_desc->wb.qword2.l2tag2_2);
}

/**
 * iavf_extract_flex_rx_fields - Extract fields from the Rx descriptor
 * @rx_ring: rx descriptor ring
 * @rx_desc: the descriptor to process
 * @fields: storage for extracted values
 *
 * Decode the Rx descriptor and extract relevant information including the
 * size, VLAN tag, and Rx packet type.
 *
 * This function only operates on the VIRTCHNL_RXDID_2_FLEX_SQ_NIC flexible
 * descriptor writeback format.
 */
static void
iavf_extract_flex_rx_fields(struct iavf_ring *rx_ring, union iavf_rx_desc *rx_desc,
			    struct iavf_rx_extracted *fields)
{
	__le16 status0, status1;

	fields->size = le16_to_cpu(rx_desc->flex_wb.pkt_len) & IAVF_RX_FLEX_DESC_PKT_LEN_M;
	fields->rx_ptype = le16_to_cpu(rx_desc->flex_wb.ptype_flexi_flags0) &
		IAVF_RX_FLEX_DESC_PTYPE_M;

	status0 = rx_desc->flex_wb.status_error0;
	if (status0 & cpu_to_le16(BIT(IAVF_RX_FLEX_DESC_STATUS0_L2TAG1P_S)) &&
	    rx_ring->flags & IAVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1)
		fields->vlan_tag = le16_to_cpu(rx_desc->flex_wb.l2tag1);

	status1 = rx_desc->flex_wb.status_error1;
	if (status1 & cpu_to_le16(BIT(IAVF_RX_FLEX_DESC_STATUS1_L2TAG2P_S)) &&
	    rx_ring->flags & IAVF_RXR_FLAGS_VLAN_TAG_LOC_L2TAG2_2)
		fields->vlan_tag = le16_to_cpu(rx_desc->flex_wb.l2tag2_2nd);
}

static void
iavf_extract_rx_fields(struct iavf_ring *rx_ring, union iavf_rx_desc *rx_desc,
		       struct iavf_rx_extracted *fields)
{
	if (rx_ring->rxdid == VIRTCHNL_RXDID_1_32B_BASE)
		iavf_extract_legacy_rx_fields(rx_ring, rx_desc, fields);
	else
		iavf_extract_flex_rx_fields(rx_ring, rx_desc, fields);
}

/**
 * iavf_clean_rx_irq - Clean completed descriptors from Rx ring - bounce buf
 * @rx_ring: rx descriptor ring to transact packets on
 * @budget: Total limit on number of packets to process
 *
 * This function provides a "bounce buffer" approach to Rx interrupt
 * processing.  The advantage to this is that on systems that have
 * expensive overhead for IOMMU access this provides a means of avoiding
 * it by maintaining the mapping of the page to the system.
 *
 * Returns amount of work completed
 **/
static int iavf_clean_rx_irq(struct iavf_ring *rx_ring, int budget)
{
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;
	struct sk_buff *skb = rx_ring->skb;
	u16 cleaned_count = IAVF_DESC_UNUSED(rx_ring);
	unsigned int xdp_xmit = 0;
	struct xdp_buff xdp = {};
	bool failure = false;
#ifdef HAVE_PF_RING
#ifdef HAVE_PF_RING_ONLY
	struct iavf_adapter *adapter = netdev_priv(rx_ring->netdev); 

	if (!kernel_only_adapter[adapter->instance])
		return budget-1;
#else
	struct iavf_adapter *adapter = netdev_priv(rx_ring->netdev);

	if (atomic_read(&adapter->pfring_zc.usage_counter) > 0) {
		wake_up_pfring_zc_socket(rx_ring);
		/* Note: returning budget napi will call us again (keeping interrupts disabled),
		 * returning budget-1 will tell napi that we are done (this usually also reenable interrupts, not with ZC) */
		return budget-1;
	}
#endif
#endif

#ifdef HAVE_XDP_BUFF_RXQ
	xdp.rxq = &rx_ring->xdp_rxq;
#endif

	while (likely(total_rx_packets < (unsigned int)budget)) {
		struct iavf_rx_extracted fields = {};
		struct iavf_rx_buffer *rx_buffer;
		union iavf_rx_desc *rx_desc;

		/* return some buffers to hardware, one at a time is too slow */
		if (cleaned_count >= IAVF_RX_BUFFER_WRITE) {
			failure = failure ||
				  iavf_alloc_rx_buffers(rx_ring, cleaned_count);
			cleaned_count = 0;
		}

		rx_desc = IAVF_RX_DESC(rx_ring, rx_ring->next_to_clean);

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we have
		 * verified the descriptor has been written back.
		 */
		dma_rmb();
#define IAVF_RXD_DD BIT(IAVF_RX_DESC_STATUS_DD_SHIFT)
		if (!iavf_test_staterr(rx_desc, IAVF_RXD_DD))
			break;

		iavf_extract_rx_fields(rx_ring, rx_desc, &fields);

		iavf_trace(clean_rx_irq, rx_ring, rx_desc, skb);
		rx_buffer = iavf_get_rx_buffer(rx_ring, fields.size);

		/* retrieve a buffer from the ring */
		if (!skb) {
			if (rx_buffer) {
				xdp.data = page_address(rx_buffer->page) +
					   rx_buffer->page_offset;
				xdp.data_hard_start = (void *)((u8 *)xdp.data -
						      iavf_rx_offset(rx_ring));
				xdp.data_end = (void *)((u8 *)xdp.data + fields.size);
				skb = iavf_run_xdp(rx_ring, &xdp);
			} else {
				break;
			}
		}

		if (IS_ERR(skb)) {
			unsigned int xdp_res = -PTR_ERR(skb);

			if (xdp_res & (IAVF_XDP_TX | IAVF_XDP_REDIR)) {
				xdp_xmit |= xdp_res;
				iavf_rx_buffer_flip(rx_ring, rx_buffer, fields.size);
			} else {
				if (rx_buffer)
					rx_buffer->pagecnt_bias++;
			}
			total_rx_bytes += fields.size;
			total_rx_packets++;
		} else if (skb) {
			iavf_add_rx_frag(rx_ring, rx_buffer, skb, fields.size);
#ifdef HAVE_SWIOTLB_SKIP_CPU_SYNC
		} else if (ring_uses_build_skb(rx_ring)) {
			skb = iavf_build_skb(rx_ring, rx_buffer, &xdp);
#endif
		} else {
			skb = iavf_construct_skb(rx_ring, rx_buffer, &xdp);
		}

		/* exit if we failed to retrieve a buffer */
		if (!skb) {
			rx_ring->rx_stats.alloc_buff_failed++;
			if (rx_buffer)
				rx_buffer->pagecnt_bias++;
			break;
		}

		iavf_put_rx_buffer(rx_ring, rx_buffer);
		cleaned_count++;

		if (iavf_is_non_eop(rx_ring, rx_desc, skb))
			continue;

		if (iavf_cleanup_headers(rx_ring, skb, rx_desc)) {
			skb = NULL;
			continue;
		}

		/* probably a little skewed due to removing CRC */
		total_rx_bytes += skb->len;

		/* populate checksum, VLAN, and protocol */
		iavf_process_skb_fields(rx_ring, rx_desc, skb, fields.rx_ptype);

		if (vector_ch_ena(rx_ring->q_vector) &&
		    vector_ch_perf_ena(rx_ring->q_vector)) {
			if (!iavf_is_ctrl_pkt(skb, rx_ring))
				rx_ring->q_vector->state_flags |=
					IAVF_VECTOR_STATE_PREV_DATA_PKT_RECV;
		}

		iavf_trace(clean_rx_irq_rx, rx_ring, rx_desc, skb);
		iavf_receive_skb(rx_ring, skb, fields.vlan_tag);
		skb = NULL;

		/* update budget accounting */
		total_rx_packets++;
	}

	if (xdp_xmit & IAVF_XDP_REDIR)
#ifdef HAVE_XDP_DO_FLUSH_MAP
		xdp_do_flush_map();
#else
		xdp_do_flush();
#endif

	if (xdp_xmit & IAVF_XDP_TX) {
		struct iavf_ring *xdp_ring =
			rx_ring->vsi->xdp_rings[rx_ring->queue_index];

		iavf_xdp_ring_update_tail(xdp_ring);
	}
	rx_ring->skb = skb;

	u64_stats_update_begin(&rx_ring->syncp);
	rx_ring->stats.packets += total_rx_packets;
	rx_ring->stats.bytes += total_rx_bytes;
	u64_stats_update_end(&rx_ring->syncp);
	iavf_chnl_rx_stats(rx_ring, total_rx_packets);
	rx_ring->q_vector->rx.total_packets += total_rx_packets;
	rx_ring->q_vector->rx.total_bytes += total_rx_bytes;

	/* guarantee a trip back through this routine if there was a failure */
	return failure ? budget : (int)total_rx_packets;
}

static inline u32 iavf_buildreg_itr(const int type, u16 itr)
{
	u32 val;

	/* We don't bother with setting the CLEARPBA bit as the data sheet
	 * points out doing so is "meaningless since it was already
	 * auto-cleared". The auto-clearing happens when the interrupt is
	 * asserted.
	 *
	 * Hardware errata 28 for also indicates that writing to a
	 * xxINT_DYN_CTLx CSR with INTENA_MSK (bit 31) set to 0 will clear
	 * an event in the PBA anyway so we need to rely on the automask
	 * to hold pending events for us until the interrupt is re-enabled
	 *
	 * The itr value is reported in microseconds, and the register
	 * value is recorded in 2 microsecond units. For this reason we
	 * only need to shift by the interval shift - 1 instead of the
	 * full value.
	 */
	itr &= IAVF_ITR_MASK;

	val = IAVF_VFINT_DYN_CTLN1_INTENA_MASK |
	      (type << IAVF_VFINT_DYN_CTLN1_ITR_INDX_SHIFT) |
	      (itr << (IAVF_VFINT_DYN_CTLN1_INTERVAL_SHIFT - 1));

	return val;
}

/* The act of updating the ITR will cause it to immediately trigger. In order
 * to prevent this from throwing off adaptive update statistics we defer the
 * update so that it can only happen so often. So after either Tx or Rx are
 * updated we make the adaptive scheme wait until either the ITR completely
 * expires via the next_update expiration or we have been through at least
 * 3 interrupts.
 */
#define ITR_COUNTDOWN_START 3

/**
 * iavf_update_enable_itr - Update itr and re-enable MSIX interrupt
 * @vsi: the VSI we care about
 * @q_vector: q_vector for which itr is being updated and interrupt enabled
 *
 **/
#ifndef HAVE_PF_RING
static
#endif
inline void iavf_update_enable_itr(struct iavf_vsi *vsi,
					  struct iavf_q_vector *q_vector)
{
	struct iavf_hw *hw = &vsi->back->hw;
	u32 intval;

	/* if vector is channel enabled, it doesn't use ITR countdown
	 * or pseudo-lazy update for ITR update
	 */
	if (vector_ch_ena(q_vector) &&
	    vector_ch_perf_ena(q_vector)) {
		/* No ITR update */
		intval = iavf_buildreg_itr(IAVF_ITR_NONE, 0);
		goto do_write;
	}

	/* These will do nothing if dynamic updates are not enabled */
	iavf_update_itr(q_vector, &q_vector->tx);
	iavf_update_itr(q_vector, &q_vector->rx);

	/* This block of logic allows us to get away with only updating
	 * one ITR value with each interrupt. The idea is to perform a
	 * pseudo-lazy update with the following criteria.
	 *
	 * 1. Rx is given higher priority than Tx if both are in same state
	 * 2. If we must reduce an ITR that is given highest priority.
	 * 3. We then give priority to increasing ITR based on amount.
	 */
	if (q_vector->rx.target_itr < q_vector->rx.current_itr) {
		/* Rx ITR needs to be reduced, this is highest priority */
		intval = iavf_buildreg_itr(IAVF_RX_ITR,
					   q_vector->rx.target_itr);
		q_vector->rx.current_itr = q_vector->rx.target_itr;
		q_vector->itr_countdown = ITR_COUNTDOWN_START;
	} else if ((q_vector->tx.target_itr < q_vector->tx.current_itr) ||
		   ((q_vector->rx.target_itr - q_vector->rx.current_itr) <
		    (q_vector->tx.target_itr - q_vector->tx.current_itr))) {
		/* Tx ITR needs to be reduced, this is second priority
		 * Tx ITR needs to be increased more than Rx, fourth priority
		 */
		intval = iavf_buildreg_itr(IAVF_TX_ITR,
					   q_vector->tx.target_itr);
		q_vector->tx.current_itr = q_vector->tx.target_itr;
		q_vector->itr_countdown = ITR_COUNTDOWN_START;
	} else if (q_vector->rx.current_itr != q_vector->rx.target_itr) {
		/* Rx ITR needs to be increased, third priority */
		intval = iavf_buildreg_itr(IAVF_RX_ITR,
					   q_vector->rx.target_itr);
		q_vector->rx.current_itr = q_vector->rx.target_itr;
		q_vector->itr_countdown = ITR_COUNTDOWN_START;
	} else {
		/* No ITR update, lowest priority */
		intval = iavf_buildreg_itr(IAVF_ITR_NONE, 0);
		if (q_vector->itr_countdown)
			q_vector->itr_countdown--;
	}

do_write:
	if (!test_bit(__IAVF_VSI_DOWN, vsi->state))
		wr32(hw, INT_DYN_CTL(hw, q_vector->reg_idx), intval);
}

/**
 * iavf_refresh_bp_state - refresh state machine
 * @napi: ptr to NAPI struct
 *
 * Update ADQ state machine, and depending on whether this was called from
 * busy poll, enable interrupts and update ITR
 */
static void iavf_refresh_bp_state(struct napi_struct *napi)
{
	struct iavf_q_vector *q_vector =
			container_of(napi, struct iavf_q_vector, napi);

	/* cache previous state of vector */
	if (q_vector->state_flags & IAVF_VECTOR_STATE_IN_BP)
		q_vector->state_flags |= IAVF_VECTOR_STATE_PREV_IN_BP;
	else
		q_vector->state_flags &= ~IAVF_VECTOR_STATE_PREV_IN_BP;

#ifdef HAVE_NAPI_STATE_IN_BUSY_POLL
	/* update current state of vector */
	if (test_bit(NAPI_STATE_IN_BUSY_POLL, &napi->state))
		q_vector->state_flags |= IAVF_VECTOR_STATE_IN_BP;
	else
		q_vector->state_flags &= ~IAVF_VECTOR_STATE_IN_BP;
#endif /* HAVE_STATE_IN_BUSY_POLL */

	if (q_vector->state_flags & IAVF_VECTOR_STATE_IN_BP) {
		q_vector->jiffies = jiffies;
		/* trigger force_wb by setting WB_ON_ITR only when
		 * - vector is transitioning from INTR->BUSY_POLL
		 * - once_in_bp is false, this is to prevent from doing it
		 * every time whenever vector state is changing from
		 * INTR->BUSY_POLL because that could be due to legit
		 * busy_poll stop
		 */
		if (!(q_vector->state_flags & IAVF_VECTOR_STATE_ONCE_IN_BP) &&
		    vector_intr_busypoll(q_vector))
			iavf_set_wb_on_itr(&q_vector->vsi->back->hw, q_vector);

		q_vector->state_flags |= IAVF_VECTOR_STATE_ONCE_IN_BP;
		q_vector->ch_stats.in_bp++;
		/* state transition : INTERRUPT --> BUSY_POLL */
		if (!(q_vector->state_flags & IAVF_VECTOR_STATE_PREV_IN_BP))
			q_vector->ch_stats.intr_to_bp++;
		else
			q_vector->ch_stats.bp_to_bp++;
	} else {
		q_vector->ch_stats.in_intr++;
		/* state transition : BUSY_POLL --> INTERRUPT */
		if (q_vector->state_flags & IAVF_VECTOR_STATE_PREV_IN_BP)
			q_vector->ch_stats.bp_to_intr++;
		else
			q_vector->ch_stats.intr_to_intr++;
	}
}

/*
 * iavf_handle_chnl_vector - handle channel enabled vector
 * @vsi: ptr to VSI
 * @q_vector: ptr to q_vector
 * @unlikely_cb_bp: will comeback to busy_poll or not
 *
 * This function eithers triggers software interrupt (when unlikely_cb_bp is
 * true) or enable interrupt normally. unlikely_cb_bp gets determined based
 * on state machine and packet parsing logic.
 */
static void
iavf_handle_chnl_vector(struct iavf_vsi *vsi, struct iavf_q_vector *q_vector,
			bool unlikely_cb_bp)
{
	struct iavf_q_vector_ch_stats *stats = &q_vector->ch_stats;

	/* caller of this function deteremines next occurrence/execution context
	 * of napi_poll (means next time whether napi_poll will be invoked from
	 * busy_poll or SOFT IRQ context). Please refer to the caller of this
	 * function to see logic for "unlikely_cb_bp" (aka, re-occurrence to
	 * busy_poll or not).
	 * If logic determines that, next occurrence of napi_poll will not be
	 * from busy_poll context, trigger software initiated interrupt on
	 * channel enabled vector to revive queue(s) processing, otherwise if
	 * in true interrupt state - just enable interrupt.
	 */
	if (unlikely_cb_bp) {
		stats->unlikely_cb_to_bp++;
		/* if once_in_bp is set and pkt inspection based optimization
		 * is off, do not trigger SW interrupt (simply bailout).
		 * No change in logic from service_task based software
		 * triggred interrupt - to revive the queue based on jiffy logic
		 */
		if (q_vector->state_flags & IAVF_VECTOR_STATE_ONCE_IN_BP) {
			stats->ucb_once_in_bp_true++;
			if (!vector_pkt_inspect_opt_ena(q_vector)) {
				stats->no_sw_intr_opt_off++;
				return;
			}
		}

		/* Since this real BP -> INT transition, reset jiffy snapshot */
		q_vector->jiffies = 0;

		/* Likewise for real BP -> INT, trigger
		 * SW interrupt, so that vector is put back
		 * in sane state, trigger sw interrupt to revive the queue
		 */
		iavf_inc_napi_sw_intr_counter(q_vector);
		iavf_force_wb(vsi, q_vector);
	} else if (!(q_vector->state_flags & IAVF_VECTOR_STATE_ONCE_IN_BP)) {
		stats->intr_once_bp_false++;
		iavf_update_enable_itr(vsi, q_vector);
	}
}

/**
 * iavf_napi_poll - NAPI polling Rx/Tx cleanup routine
 * @napi: napi struct with our devices info in it
 * @budget: amount of work driver is allowed to do this pass, in packets
 *
 * This function will clean all queues associated with a q_vector.
 *
 * Returns the amount of work done
 **/
int iavf_napi_poll(struct napi_struct *napi, int budget)
{
	struct iavf_q_vector *q_vector =
			       container_of(napi, struct iavf_q_vector, napi);
	struct iavf_vsi *vsi = q_vector->vsi;
	bool cleaned_any_data_pkt = false;
	u64 flags = vsi->back->flags;
	bool unlikely_cb_bp = false;
	bool clean_complete = true;
	bool ch_enabled = false;
	bool wb_on_itr_enabled;
	struct iavf_ring *ring;
	bool arm_wb = false;
	int budget_per_ring;
	int work_done = 0;
#ifdef HAVE_PF_RING
	struct iavf_adapter *adapter = netdev_priv(vsi->netdev);

	adapter->pfring_zc.interrupts_required = 0;
#endif

	if (test_bit(__IAVF_VSI_DOWN, vsi->state)) {
		napi_complete(napi);
		return 0;
	}

	/* determine if WB_ON_ITR is enabled on not, if not - not need to
	 * apply any  performance optimization
	 */
	wb_on_itr_enabled = true;
	iavf_for_each_ring(ring, q_vector->tx) {
		if (!(ring->flags & IAVF_TXR_FLAGS_WB_ON_ITR)) {
			wb_on_itr_enabled &= false;
			break;
		}
	}

	/* determine once if vector needs to be processed differently */
	ch_enabled = wb_on_itr_enabled && vector_ch_ena(q_vector) &&
		     vector_ch_perf_ena(q_vector);
	if (ch_enabled) {
		u8 qv_flags;

		/* Refresh state machine */
		iavf_refresh_bp_state(napi);

		/* check during previous run of napi_poll whether at least one
		 * data packets is processed or not. If processed at least one
		 * data packet, set the local flag 'cleaned_any_data_pkt'
		 * which is used later in this function to determine if
		 * interrupt should be enabled or deferred (this is applicable
		 * only in case when busy_poll stop is invoked, means previous
		 * state of vector is in busy_poll and current state is not
		 * (aka BUSY_POLL -> INTR))
		 */
		qv_flags = q_vector->state_flags;
		if (qv_flags & IAVF_VECTOR_STATE_PREV_DATA_PKT_RECV) {
			q_vector->state_flags &=
					~IAVF_VECTOR_STATE_PREV_DATA_PKT_RECV;
			/* It is important to check and cache correct\
			 * information (cleaned any data packets or not) in
			 * local variable before napi_complete_done is finished.
			 * Once napi_complete_done is returned, napi_poll
			 * can get invoked again (means re-entrant) which can
			 * potentially results to incorrect decision making
			 * w.r.t. whether interrupt should be enabled or
			 * deferred)
			 */
			if (vector_busypoll_intr(q_vector)) {
				cleaned_any_data_pkt = true;
				q_vector->ch_stats.cleaned_any_data_pkt++;
			}
		}
	}

	/* Since the actual Tx work is minimal, we can give the Tx a larger
	 * budget and be more aggressive about cleaning up the Tx descriptors.
	 */
	iavf_for_each_ring(ring, q_vector->tx) {
		if (!iavf_clean_tx_irq(vsi, ring, budget)) {
			clean_complete = false;
			continue;
		}
		arm_wb |= ring->arm_wb;
		ring->arm_wb = false;
	}

	/* Handle case where we are called by netpoll with a budget of 0 */
	if (budget <= 0)
		goto tx_only;

	/* state transitioning from BUSY_POLL --> INTERRUPT. This can happen
	 * due to several reason when stack calls busy_poll_stop
	 *    1. during last execution of napi_poll returned non-zero packets
	 *    2. busy_loop ended
	 *    3. need re-sched set
	 * driver keeps track of packets were cleaned during last run and if
	 * that is zero, means most likely napi_poll won't be invoked from
	 * busy_poll context; in that situation bypass processing of Rx queues
	 * and enable interrupt and let subsequent run of napi_poll from
	 * interrupt path handle cleanup of Rx queues
	 */
	if (ch_enabled && vector_busypoll_intr(q_vector))
		goto bypass;

	/* We attempt to distribute budget to each Rx queue fairly, but don't
	 * allow the budget to go below 1 because that would exit polling early.
	 */
	budget_per_ring = max(budget/q_vector->num_ringpairs, 1);

	iavf_for_each_ring(ring, q_vector->rx) {
		int cleaned = iavf_clean_rx_irq(ring, budget_per_ring);

		work_done += cleaned;
		/* if we clean as many as budgeted, we must not be done */
		if (cleaned >= budget_per_ring)
			clean_complete = false;
	}

#ifndef HAVE_NETDEV_NAPI_LIST
	/* if netdev is disabled we need to stop polling */
	if (!netif_running(vsi->netdev))
		clean_complete = true;

#endif
	/* if this vector ever was/is in BUSY_POLL, skip processing  */
	if (ch_enabled && vector_ever_in_busypoll(q_vector))
		goto bypass;

	/* If work not completed, return budget and polling will return */
	if (!clean_complete) {
#ifdef HAVE_IRQ_AFFINITY_NOTIFY
		int cpu_id = smp_processor_id();

		/* It is possible that the interrupt affinity has changed but,
		 * if the cpu is pegged at 100%, polling will never exit while
		 * traffic continues and the interrupt will be stuck on this
		 * cpu.  We check to make sure affinity is correct before we
		 * continue to poll, otherwise we must stop polling so the
		 * interrupt can move to the correct cpu.
		 */
		if (!cpumask_test_cpu(cpu_id, &q_vector->affinity_mask)) {
			/* Tell napi that we are done polling */
			napi_complete_done(napi, work_done);
			q_vector->ch_stats.intr_en_not_clean_complete++;

			/* Force an interrupt */
			iavf_force_wb(vsi, q_vector);

			/* Return budget-1 so that polling stops */
			return budget - 1;
		}
#endif /* HAVE_IRQ_AFFINITY_NOTIFY */
tx_only:
		if (arm_wb) {
			q_vector->tx.ring[0].tx_stats.tx_force_wb++;
			iavf_enable_wb_on_itr(vsi, q_vector);
		}
		return budget;
	}

	if (flags & IAVF_TXR_FLAGS_WB_ON_ITR)
		q_vector->arm_wb_state = false;

bypass:
	/* Following block is only for stats, hence guarded by "debug_mask" */
	if (ch_enabled && vector_busypoll_intr(q_vector)) {
		struct iavf_q_vector_ch_stats *stats;

		stats = &q_vector->ch_stats;
		if (unlikely(need_resched())) {
			stats->bp_stop_need_resched++;
			if (!cleaned_any_data_pkt)
				stats->need_resched_no_data_pkt++;
		} else {
			/* here , means actually because of 2 reason
			 * - busy_poll timeout expired
			 * - last time, cleaned data packets, hence
			 *  stack asked to stop busy_poll so that packet
			 *  can be processed by consumer
			 */
			stats->bp_stop_timeout++;
			if (!cleaned_any_data_pkt)
				stats->timeout_no_data_pkt++;
		}
	}
	/* if state transition from busy_poll to interrupt and during
	 * last run: did not cleanup TCP data packets -
	 *      then application unlikely to comeback to busy_poll
	 */
	if (ch_enabled && vector_busypoll_intr(q_vector) &&
	    !cleaned_any_data_pkt) {
		/* for now, if need_resched is true (it can be either
		 * due to voluntary/in-voluntary context switches),
		 * do not trigger SW interrupt.
		 * if need_resched is not set, safely assuming, it is due
		 * to possible timeout and unlikely that application/context
		 * will return to busy_poll, hence set 'unlikely_cb_bp' to
		 * true which will cause software triggered interrupt
		 * to reviev the queue/vector
		 */
		if (unlikely(need_resched()))
			unlikely_cb_bp = false;
		else
			unlikely_cb_bp = true;
	}

	/* Work is done so exit the polling mode and re-enable the interrupt */
	if (likely(napi_complete_done(napi, work_done))) {
		/* napi_ret : false (means vector is still in POLLING mode
		 *            true (means out of POLLING)
		 * NOTE: Generally if napi_ret is TRUE, enable device interrupt
		 * but there are condition/optimization, where it can be
		 * optimized. Bascially, if napi_complete_done returns true buti
		 * last time Rx packets were cleaned, then most likely, consumer
		 * thread will come back to do busy_polling where cleaning of
		 * Tx/Rx queue will happen normally. Hence no reason to arm the
		 * interrupt.
		 *
		 * If for some reason, consumer thread/context doesn't comeback
		 * to busy_poll:napi_poll, there is bail-out mechanism to kick
		 * start the state machine thru' SW triggered interrupt from
		 * service task.
		 */

#ifdef HAVE_PF_RING
		/* We should not enable interrupts here, as wait_packet_function_ptr should 
		 * do it when needed, however since on some i40e adapters, when interrupts are 
		 * disabled, packets are not delivered if #queued < 4, we should always enable
		 * interrupts to avoid race conditions in case of multiple sockets (RSS) 
		 * if (atomic_read(&netdev_priv(vsi->netdev)->pfring_zc.usage_counter) == 0 || 
	         *    adapter->pfring_zc.interrupts_required) */
#endif

		if (ch_enabled) {
			/* current state of NAPI is INTERRUPT */
			iavf_handle_chnl_vector(vsi, q_vector, unlikely_cb_bp);
		} else {
			iavf_update_enable_itr(vsi, q_vector);
		}
	} else {
		/* if code makes it here, means busy_poll is still ON.
		 * if vector is channel enabled, setting WB_ON_ITR is handled
		 * from iavf_refresh_bp_state function.
		 * otherwise set WB_ON_ITR (if supported)
		 */

#ifdef HAVE_PF_RING
		/* We should not enable interrupts here, as wait_packet_function_ptr should 
		 * do it when needed, however since on some i40e adapters, when interrupts are 
		 * disabled, packets are not delivered if #queued < 4, we should always enable
		 * interrupts to avoid race conditions in case of multiple sockets (RSS) 
		 * if (atomic_read(&netdev_priv(vsi->netdev)->pfring_zc.usage_counter) == 0 || 
	         *    adapter->pfring_zc.interrupts_required) */
#endif

		if (!ch_enabled) {
			if (wb_on_itr_enabled)
				iavf_enable_wb_on_itr(vsi, q_vector);
			else
				iavf_update_enable_itr(vsi, q_vector);
		}
	}

	return min_t(int, work_done, budget - 1);
}

/**
 * iavf_tx_prepare_vlan_flags - prepare generic TX VLAN tagging flags for HW
 * @skb:     send buffer
 * @tx_ring: ring to send buffer on
 * @flags:   the tx flags to be set
 *
 * Checks the skb and set up correspondingly several generic transmit flags
 * related to VLAN tagging for the HW, such as VLAN, DCB, etc.
 *
 * Returns error code indicate the frame should be dropped upon error and the
 * otherwise  returns 0 to indicate the flags has been set properly.
 **/
static void iavf_tx_prepare_vlan_flags(struct sk_buff *skb,
				       struct iavf_ring *tx_ring, u32 *flags)
{
	u32  tx_flags = 0;

	/* stack will only request hardware VLAN insertion offload for protocols
	 * that the driver supports and has enabled
	 */
	if (!skb_vlan_tag_present(skb))
		return;

	tx_flags |= skb_vlan_tag_get(skb) << IAVF_TX_FLAGS_VLAN_SHIFT;
	if (tx_ring->flags & IAVF_TXR_FLAGS_VLAN_TAG_LOC_L2TAG2) {
		tx_flags |= IAVF_TX_FLAGS_HW_OUTER_SINGLE_VLAN;
	} else if (tx_ring->flags & IAVF_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1) {
		tx_flags |= IAVF_TX_FLAGS_HW_VLAN;
	} else {
		dev_dbg(tx_ring->dev, "Unsupported Tx VLAN tag location requested\n");
		return;
	}
#ifdef IAVF_ADD_PROBES
	if (tx_ring->netdev->features & IAVF_NETIF_F_HW_VLAN_CTAG_TX)
		tx_ring->vsi->back->tx_vlano++;
	else
		tx_ring->vsi->back->tx_ad_vlano++;
#endif

	*flags = tx_flags;
}

#ifdef IAVF_ADD_PROBES
/**
 * iavf_update_gso_counter - update TSO/USO counter
 * @tx_buffer: Tx buffer with necessary data to update counter
 */
static void iavf_update_gso_counter(struct iavf_tx_buffer *tx_buffer)
{
	struct sk_buff *skb = tx_buffer->skb;
	struct iavf_adapter *adapter =
		netdev_priv(skb->dev);

	if (skb->csum_offset == offsetof(struct tcphdr, check))
		adapter->tcp_segs += tx_buffer->gso_segs;
	else
		adapter->udp_segs += tx_buffer->gso_segs;
}
#endif

#ifndef HAVE_ENCAP_TSO_OFFLOAD
#define inner_ip_hdr(skb) 0
#define inner_tcp_hdr(skb) 0
#define inner_ipv6_hdr(skb) 0
#define inner_tcp_hdrlen(skb) 0
#define inner_tcp_hdrlen(skb) 0
#define skb_inner_transport_header(skb) ((skb)->data)
#endif /* HAVE_ENCAP_TSO_OFFLOAD */
/**
 * iavf_tso - set up the tso context descriptor
 * @first:    pointer to first Tx buffer for xmit
 * @hdr_len:  ptr to the size of the packet header
 * @cd_type_cmd_tso_mss: Quad Word 1
 *
 * Returns 0 if no TSO can happen, 1 if tso is going, or error
 **/
static int iavf_tso(struct iavf_tx_buffer *first, u8 *hdr_len,
		    u64 *cd_type_cmd_tso_mss)
{
	struct sk_buff *skb = first->skb;
	u64 cd_cmd, cd_tso_len, cd_mss;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		unsigned char *hdr;
	} l4;
	u32 paylen, l4_offset;
	u16 gso_segs, gso_size;
	int err;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (!skb_is_gso(skb))
		return 0;

	err = skb_cow_head(skb, 0);
	if (err < 0)
		return err;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	/* initialize outer IP header fields */
	if (ip.v4->version == 4) {
		ip.v4->tot_len = 0;
		ip.v4->check = 0;
	} else {
		ip.v6->payload_len = 0;
	}

#ifdef HAVE_ENCAP_TSO_OFFLOAD
	if (skb_shinfo(skb)->gso_type & (SKB_GSO_GRE |
#ifdef NETIF_F_GSO_PARTIAL
					 SKB_GSO_GRE_CSUM |
#endif
#ifdef NETIF_F_GSO_IPXIP4
					 SKB_GSO_IPXIP4 |
#ifdef NETIF_F_GSO_IPXIP6
					 SKB_GSO_IPXIP6 |
#endif
#else
#ifdef NETIF_F_GSO_IPIP
					 SKB_GSO_IPIP |
#endif
#ifdef NETIF_F_GSO_SIT
					 SKB_GSO_SIT |
#endif
#endif
					 SKB_GSO_UDP_TUNNEL |
					 SKB_GSO_UDP_TUNNEL_CSUM)) {
#ifndef NETIF_F_GSO_PARTIAL
		if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM) {
#else
		if (!(skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL) &&
		    (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM)) {
#endif
			l4.udp->len = 0;

			/* determine offset of outer transport header */
			l4_offset = l4.hdr - skb->data;

			/* remove payload length from outer checksum */
			paylen = skb->len - l4_offset;
			csum_replace_by_diff(&l4.udp->check,
					     (__force __wsum)htonl(paylen));
		}

		/* reset pointers to inner headers */
		ip.hdr = skb_inner_network_header(skb);
		l4.hdr = skb_inner_transport_header(skb);

		/* initialize inner IP header fields */
		if (ip.v4->version == 4) {
			ip.v4->tot_len = 0;
			ip.v4->check = 0;
		} else {
			ip.v6->payload_len = 0;
		}
	}

#endif /* HAVE_ENCAP_TSO_OFFLOAD */
	/* determine offset of inner transport header */
	l4_offset = l4.hdr - skb->data;
	/* remove payload length from inner checksum */
	paylen = skb->len - l4_offset;

#ifdef NETIF_F_GSO_UDP_L4
	if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4) {
		csum_replace_by_diff(&l4.udp->check,
				     (__force __wsum)htonl(paylen));
		/* compute length of UDP segmentation header */
		*hdr_len = (u8)sizeof(l4.udp) + l4_offset;
	} else {
		csum_replace_by_diff(&l4.tcp->check,
				     (__force __wsum)htonl(paylen));
		/* compute length of TCP segmentation header */
		*hdr_len = (u8)((l4.tcp->doff * 4) + l4_offset);
	}
#else
	csum_replace_by_diff(&l4.tcp->check, (__force __wsum)htonl(paylen));
	*hdr_len = (u8)((l4.tcp->doff * 4) + l4_offset);
#endif /* NETIF_F_GSO_UDP_L4 */

	/* pull values out of skb_shinfo */
	gso_size = skb_shinfo(skb)->gso_size;
	gso_segs = skb_shinfo(skb)->gso_segs;

#ifndef HAVE_NDO_FEATURES_CHECK
	/* too small a TSO segment size causes problems */
	if (gso_size < 64) {
		gso_size = 64;
		gso_segs = DIV_ROUND_UP(skb->len - *hdr_len, 64);
	}
#endif
	/* update GSO size and bytecount with header size */
	first->gso_segs = gso_segs;
	first->bytecount += (first->gso_segs - 1) * *hdr_len;

	/* find the field values */
	cd_cmd = IAVF_TX_CTX_DESC_TSO;
	cd_tso_len = skb->len - *hdr_len;
	cd_mss = gso_size;
	*cd_type_cmd_tso_mss |= (cd_cmd << IAVF_TXD_CTX_QW1_CMD_SHIFT) |
				(cd_tso_len << IAVF_TXD_CTX_QW1_TSO_LEN_SHIFT) |
				(cd_mss << IAVF_TXD_CTX_QW1_MSS_SHIFT);
#ifdef IAVF_ADD_PROBES
	iavf_update_gso_counter(first);
#endif
	return 1;
}

/**
 * iavf_tx_enable_csum - Enable Tx checksum offloads
 * @skb: send buffer
 * @tx_flags: pointer to Tx flags currently set
 * @td_cmd: Tx descriptor command bits to set
 * @td_offset: Tx descriptor header offsets to set
 * @tx_ring: Tx descriptor ring
 * @cd_tunneling: ptr to context desc bits
 **/
static int iavf_tx_enable_csum(struct sk_buff *skb, u32 *tx_flags,
			       u32 *td_cmd, u32 *td_offset,
			       struct iavf_ring *tx_ring,
			       u32 *cd_tunneling)
{
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} ip;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		unsigned char *hdr;
	} l4;
	unsigned char *exthdr;
	u32 offset, cmd = 0;
	__be16 frag_off;
	u8 l4_proto = 0;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	ip.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	/* compute outer L2 header size */
	offset = ((ip.hdr - skb->data) / 2) << IAVF_TX_DESC_LENGTH_MACLEN_SHIFT;

#ifdef HAVE_ENCAP_CSUM_OFFLOAD
	if (skb->encapsulation) {
		u32 tunnel = 0;
		/* define outer network header type */
		if (*tx_flags & IAVF_TX_FLAGS_IPV4) {
			tunnel |= (*tx_flags & IAVF_TX_FLAGS_TSO) ?
				  IAVF_TX_CTX_EXT_IP_IPV4 :
				  IAVF_TX_CTX_EXT_IP_IPV4_NO_CSUM;

			l4_proto = ip.v4->protocol;
		} else if (*tx_flags & IAVF_TX_FLAGS_IPV6) {
			tunnel |= IAVF_TX_CTX_EXT_IP_IPV6;

			exthdr = ip.hdr + sizeof(*ip.v6);
			l4_proto = ip.v6->nexthdr;
			if (l4.hdr != exthdr)
				ipv6_skip_exthdr(skb, exthdr - skb->data,
						 &l4_proto, &frag_off);
		}

		/* define outer transport */
		switch (l4_proto) {
		case IPPROTO_UDP:
			tunnel |= IAVF_TXD_CTX_UDP_TUNNELING;
			*tx_flags |= IAVF_TX_FLAGS_TUNNEL;
			break;
#ifdef HAVE_GRE_ENCAP_OFFLOAD
		case IPPROTO_GRE:
			tunnel |= IAVF_TXD_CTX_GRE_TUNNELING;
			*tx_flags |= IAVF_TX_FLAGS_TUNNEL;
			/* There was a long-standing issue in GRE where GSO
			 * was not setting the outer transport header unless
			 * a GRE checksum was requested. This was fixed in
			 * the 4.6 version of the kernel.  In the 4.7 kernel
			 * support for GRE over IPv6 was added to GSO.  So we
			 * can assume this workaround for all IPv4 headers
			 * without impacting later versions of the GRE.
			 */
			if (ip.v4->version == 4)
				l4.hdr = ip.hdr + (ip.v4->ihl * 4);
			break;
		case IPPROTO_IPIP:
		case IPPROTO_IPV6:
			*tx_flags |= IAVF_TX_FLAGS_TUNNEL;
			l4.hdr = skb_inner_network_header(skb);
			break;
#endif
		default:
			if (*tx_flags & IAVF_TX_FLAGS_TSO)
				return -1;

			skb_checksum_help(skb);
			return 0;
		}

#ifdef IAVF_ADD_PROBES
		if (*tx_flags & IAVF_TX_FLAGS_IPV4)
			if (*tx_flags & IAVF_TX_FLAGS_TSO)
				tx_ring->vsi->back->tx_ip4_cso++;
#endif
		/* compute outer L3 header size */
		tunnel |= ((l4.hdr - ip.hdr) / 4) <<
			  IAVF_TXD_CTX_QW0_EXT_IPLEN_SHIFT;

		/* switch IP header pointer from outer to inner header */
		ip.hdr = skb_inner_network_header(skb);

		/* compute tunnel header size */
		tunnel |= ((ip.hdr - l4.hdr) / 2) <<
			  IAVF_TXD_CTX_QW0_NATLEN_SHIFT;

		/* indicate if we need to offload outer UDP header */
		if ((*tx_flags & IAVF_TX_FLAGS_TSO) &&
#ifdef NETIF_F_GSO_PARTIAL
		    !(skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL) &&
#endif
		    (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM))
			tunnel |= IAVF_TXD_CTX_QW0_L4T_CS_MASK;

		/* record tunnel offload values */
		*cd_tunneling |= tunnel;

		/* switch L4 header pointer from outer to inner */
		l4.hdr = skb_inner_transport_header(skb);
		l4_proto = 0;

		/* reset type as we transition from outer to inner headers */
		*tx_flags &= ~(IAVF_TX_FLAGS_IPV4 | IAVF_TX_FLAGS_IPV6);
		if (ip.v4->version == 4)
			*tx_flags |= IAVF_TX_FLAGS_IPV4;
		if (ip.v6->version == 6)
			*tx_flags |= IAVF_TX_FLAGS_IPV6;
	}
#endif /* HAVE_ENCAP_CSUM_OFFLOAD */

	/* Enable IP checksum offloads */
	if (*tx_flags & IAVF_TX_FLAGS_IPV4) {
		l4_proto = ip.v4->protocol;
#ifdef IAVF_ADD_PROBES
		tx_ring->vsi->back->tx_ip4_cso++;
#endif
		/* the stack computes the IP header already, the only time we
		 * need the hardware to recompute it is in the case of TSO.
		 */
		cmd |= (*tx_flags & IAVF_TX_FLAGS_TSO) ?
		       IAVF_TX_DESC_CMD_IIPT_IPV4_CSUM :
		       IAVF_TX_DESC_CMD_IIPT_IPV4;
#ifdef NETIF_F_IPV6_CSUM
	} else if (*tx_flags & IAVF_TX_FLAGS_IPV6) {
		cmd |= IAVF_TX_DESC_CMD_IIPT_IPV6;

		exthdr = ip.hdr + sizeof(*ip.v6);
		l4_proto = ip.v6->nexthdr;
		if (l4.hdr != exthdr)
			ipv6_skip_exthdr(skb, exthdr - skb->data,
					 &l4_proto, &frag_off);
#endif
	}

	/* compute inner L3 header size */
	offset |= ((l4.hdr - ip.hdr) / 4) << IAVF_TX_DESC_LENGTH_IPLEN_SHIFT;

	/* Enable L4 checksum offloads */
	switch (l4_proto) {
	case IPPROTO_TCP:
		/* enable checksum offloads */
		cmd |= IAVF_TX_DESC_CMD_L4T_EOFT_TCP;
		offset |= l4.tcp->doff << IAVF_TX_DESC_LENGTH_L4_FC_LEN_SHIFT;
#ifdef IAVF_ADD_PROBES
		tx_ring->vsi->back->tx_tcp_cso++;
#endif
		break;
	case IPPROTO_SCTP:
		/* enable SCTP checksum offload */
#ifdef HAVE_SCTP
		cmd |= IAVF_TX_DESC_CMD_L4T_EOFT_SCTP;
		offset |= (sizeof(struct sctphdr) >> 2) <<
			  IAVF_TX_DESC_LENGTH_L4_FC_LEN_SHIFT;
#ifdef IAVF_ADD_PROBES
		tx_ring->vsi->back->tx_sctp_cso++;
#endif
#endif /* HAVE_SCTP */
		break;
	case IPPROTO_UDP:
		/* enable UDP checksum offload */
		cmd |= IAVF_TX_DESC_CMD_L4T_EOFT_UDP;
		offset |= (sizeof(struct udphdr) >> 2) <<
			  IAVF_TX_DESC_LENGTH_L4_FC_LEN_SHIFT;
#ifdef IAVF_ADD_PROBES
		tx_ring->vsi->back->tx_udp_cso++;
#endif
		break;
	default:
		if (*tx_flags & IAVF_TX_FLAGS_TSO)
			return -1;
		skb_checksum_help(skb);
		return 0;
	}

	*td_cmd |= cmd;
	*td_offset |= offset;

	return 1;
}

/**
 * iavf_tstamp - setup context descriptor for timestamping
 * @tx_ring: ring to send buffer on
 * @skb: send buffer
 * @tx_flags: collected send information
 * @cd_type_cmd_tso_mss: Quad Word 1
 *
 * Setup timestamp request for an outbound packet. The request will only be
 * made if the user has requested it, and if we're not already waiting for
 * timestamp completion of a previous packet.
 *
 * Return 1 if a Tx timestamp will happen, 0 otherwise.
 */
static int
iavf_tstamp(struct iavf_ring *tx_ring, struct sk_buff *skb, u32 tx_flags, u64 *cd_type_cmd_tso_mss)
{
	struct iavf_adapter *adapter;
	struct iavf_ptp *ptp;
	u64 ts_idx;

	/* Timestamping is not enabled */
	if (!(tx_ring->flags & IAVF_TXRX_FLAGS_HW_TSTAMP))
		return 0;

	if (likely(!(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)))
		return 0;

	/* Hardware cannot sample a timestamp when doing TSO */
	if (tx_flags & IAVF_TX_FLAGS_TSO)
		return 0;

	adapter = netdev_priv(tx_ring->netdev);
	ptp = &adapter->ptp;

	if (test_and_set_bit_lock(__IAVF_TX_TSTAMP_IN_PROGRESS, &adapter->crit_section)) {
		ptp->tx_hwtstamp_skipped++;
		return 0;
	}

	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
	ptp->tx_start = jiffies;
	ptp->tx_skb = skb_get(skb);

	ts_idx = ptp->hw_caps.tx_tstamp_idx;
	*cd_type_cmd_tso_mss |= (IAVF_TX_CTX_DESC_TSYN << IAVF_TXD_CTX_QW1_CMD_SHIFT) |
				(ts_idx << IAVF_TXD_CTX_QW1_TSO_LEN_SHIFT);

	return 1;
}

/**
 * iavf_create_tx_ctx - Build the Tx context descriptor
 * @tx_ring:  ring to create the descriptor on
 * @cd_type_cmd_tso_mss: Quad Word 1
 * @cd_tunneling: Quad Word 0 - bits 0-31
 * @cd_l2tag2: Quad Word 0 - bits 32-63
 **/
static void iavf_create_tx_ctx(struct iavf_ring *tx_ring,
			       const u64 cd_type_cmd_tso_mss,
			       const u32 cd_tunneling, const u32 cd_l2tag2)
{
	struct iavf_tx_context_desc *context_desc;
	int i = tx_ring->next_to_use;

	if ((cd_type_cmd_tso_mss == IAVF_TX_DESC_DTYPE_CONTEXT) &&
	    !cd_tunneling && !cd_l2tag2)
		return;

	/* grab the next descriptor */
	context_desc = IAVF_TX_CTXTDESC(tx_ring, i);

	i++;
	tx_ring->next_to_use = (i < tx_ring->count) ? i : 0;

	/* cpu_to_le32 and assign to struct fields */
	context_desc->tunneling_params = cpu_to_le32(cd_tunneling);
	context_desc->l2tag2 = cpu_to_le16(cd_l2tag2);
	context_desc->rsvd = cpu_to_le16(0);
	context_desc->type_cmd_tso_mss = cpu_to_le64(cd_type_cmd_tso_mss);
}

/**
 * __iavf_chk_linearize - Check if there are more than 8 buffers per packet
 * @skb:      send buffer
 *
 * Note: Our HW can't DMA more than 8 buffers to build a packet on the wire
 * and so we need to figure out the cases where we need to linearize the skb.
 *
 * For TSO we need to count the TSO header and segment payload separately.
 * As such we need to check cases where we have 7 fragments or more as we
 * can potentially require 9 DMA transactions, 1 for the TSO header, 1 for
 * the segment payload in the first descriptor, and another 7 for the
 * fragments.
 **/
bool __iavf_chk_linearize(struct sk_buff *skb)
{
	const skb_frag_t *frag, *stale;
	int nr_frags, sum;

	/* no need to check if number of frags is less than 7 */
	nr_frags = skb_shinfo(skb)->nr_frags;
	if (nr_frags < (IAVF_MAX_BUFFER_TXD - 1))
		return false;

	/* We need to walk through the list and validate that each group
	 * of 6 fragments totals at least gso_size.
	 */
	nr_frags -= IAVF_MAX_BUFFER_TXD - 2;
	frag = &skb_shinfo(skb)->frags[0];

	/* Initialize size to the negative value of gso_size minus 1.  We
	 * use this as the worst case scenerio in which the frag ahead
	 * of us only provides one byte which is why we are limited to 6
	 * descriptors for a single transmit as the header and previous
	 * fragment are already consuming 2 descriptors.
	 */
	sum = 1 - skb_shinfo(skb)->gso_size;

	/* Add size of frags 0 through 4 to create our initial sum */
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);
	sum += skb_frag_size(frag++);

	/* Walk through fragments adding latest fragment, testing it, and
	 * then removing stale fragments from the sum.
	 */
	for (stale = &skb_shinfo(skb)->frags[0];; stale++) {
		int stale_size = skb_frag_size(stale);

		sum += skb_frag_size(frag++);

		/* The stale fragment may present us with a smaller
		 * descriptor than the actual fragment size. To account
		 * for that we need to remove all the data on the front and
		 * figure out what the remainder would be in the last
		 * descriptor associated with the fragment.
		 */
		if (stale_size > IAVF_MAX_DATA_PER_TXD) {
			int align_pad = -(skb_frag_off(stale)) &
					(IAVF_MAX_READ_REQ_SIZE - 1);

			sum -= align_pad;
			stale_size -= align_pad;

			do {
				sum -= IAVF_MAX_DATA_PER_TXD_ALIGNED;
				stale_size -= IAVF_MAX_DATA_PER_TXD_ALIGNED;
			} while (stale_size > IAVF_MAX_DATA_PER_TXD);
		}

		/* if sum is negative we failed to make sufficient progress */
		if (sum < 0)
			return true;

		if (!nr_frags--)
			break;

		sum -= stale_size;
	}

	return false;
}

/**
 * __iavf_maybe_stop_tx - 2nd level check for tx stop conditions
 * @tx_ring: the ring to be checked
 * @size:    the size buffer we want to assure is available
 *
 * Returns -EBUSY if a stop is needed, else 0
 **/
int __iavf_maybe_stop_tx(struct iavf_ring *tx_ring, int size)
{
	netif_stop_subqueue(tx_ring->netdev, tx_ring->queue_index);
	/* Memory barrier before checking head and tail */
	smp_mb();

	/* Check again in a case another CPU has just made room available. */
	if (likely(IAVF_DESC_UNUSED(tx_ring) < size))
		return -EBUSY;

	/* A reprieve! - use start_queue because it doesn't call schedule */
	netif_start_subqueue(tx_ring->netdev, tx_ring->queue_index);
	++tx_ring->tx_stats.restart_queue;
	return 0;
}

/**
 * iavf_tx_map - Build the Tx descriptor
 * @tx_ring:  ring to send buffer on
 * @skb:      send buffer
 * @first:    first buffer info buffer to use
 * @tx_flags: collected send information
 * @hdr_len:  size of the packet header
 * @td_cmd:   the command field in the descriptor
 * @td_offset: offset for checksum or crc
 *
 * Returns 0 on success, negative error code on DMA failure.
 **/
static int iavf_tx_map(struct iavf_ring *tx_ring, struct sk_buff *skb,
		       struct iavf_tx_buffer *first, u32 tx_flags,
		       const u8 hdr_len, u32 td_cmd, u32 td_offset)
{
	unsigned int data_len = skb->data_len;
	unsigned int size = skb_headlen(skb);
	skb_frag_t *frag;
	struct iavf_tx_buffer *tx_bi;
	struct iavf_tx_desc *tx_desc;
	u16 i = tx_ring->next_to_use;
	u32 td_tag = 0;
	dma_addr_t dma;

	if (tx_flags & IAVF_TX_FLAGS_HW_VLAN) {
		td_cmd |= IAVF_TX_DESC_CMD_IL2TAG1;
		td_tag = (tx_flags & IAVF_TX_FLAGS_VLAN_MASK) >>
			 IAVF_TX_FLAGS_VLAN_SHIFT;
	}

	first->tx_flags = tx_flags;

	dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);

	tx_desc = IAVF_TX_DESC(tx_ring, i);
	tx_bi = first;

	for (frag = &skb_shinfo(skb)->frags[0];; frag++) {
		unsigned int max_data = IAVF_MAX_DATA_PER_TXD_ALIGNED;

		if (dma_mapping_error(tx_ring->dev, dma))
			goto dma_error;

		/* record length, and DMA address */
		dma_unmap_len_set(tx_bi, len, size);
		dma_unmap_addr_set(tx_bi, dma, dma);

		/* align size to end of page */
		max_data += -dma & (IAVF_MAX_READ_REQ_SIZE - 1);
		tx_desc->buffer_addr = cpu_to_le64(dma);

		while (unlikely(size > IAVF_MAX_DATA_PER_TXD)) {
			tx_desc->cmd_type_offset_bsz =
				build_ctob(td_cmd, td_offset,
					   max_data, td_tag);

			tx_desc++;
			i++;

			if (i == tx_ring->count) {
				tx_desc = IAVF_TX_DESC(tx_ring, 0);
				i = 0;
			}

			dma += max_data;
			size -= max_data;

			max_data = IAVF_MAX_DATA_PER_TXD_ALIGNED;
			tx_desc->buffer_addr = cpu_to_le64(dma);
		}

		if (likely(!data_len))
			break;

		tx_desc->cmd_type_offset_bsz = build_ctob(td_cmd, td_offset,
							  size, td_tag);

		tx_desc++;
		i++;

		if (i == tx_ring->count) {
			tx_desc = IAVF_TX_DESC(tx_ring, 0);
			i = 0;
		}

		size = skb_frag_size(frag);
		data_len -= size;

		dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size,
				       DMA_TO_DEVICE);

		tx_bi = &tx_ring->tx_bi[i];
	}

	netdev_tx_sent_queue(txring_txq(tx_ring), first->bytecount);

	i++;
	if (i == tx_ring->count)
		i = 0;

	tx_ring->next_to_use = i;

	iavf_maybe_stop_tx(tx_ring, DESC_NEEDED);

	/* write last descriptor with RS and EOP bits */
	td_cmd |= IAVF_TXD_CMD;
	tx_desc->cmd_type_offset_bsz =
			build_ctob(td_cmd, td_offset, size, td_tag);

	/* timestamp the skb as late as possible, just prior to notifying
	 * the MAC that it should transmit this packet
	 */
	skb_tx_timestamp(skb);

	/* Force memory writes to complete before letting h/w know there
	 * are new descriptors to fetch.
	 *
	 * We also use this memory barrier to make certain all of the
	 * status bits have been updated before next_to_watch is written.
	 */
	wmb();

	/* set next_to_watch value indicating a packet is present */
	first->next_to_watch = tx_desc;

	/* notify HW of packet */
#ifdef HAVE_SKB_XMIT_MORE
	if (netif_xmit_stopped(txring_txq(tx_ring)) || !netdev_xmit_more()) {
		writel(i, tx_ring->tail);
#ifndef SPIN_UNLOCK_IMPLIES_MMIOWB
		/* We need this mmiowb on IA64/Altix systems where wmb() isn't
		 * guaranteed to synchronize I/O.
		 *
		 * Note that mmiowb() only provides a guarantee about ordering
		 * when in conjunction with a spin_unlock(). This barrier is
		 * used to guarantee the I/O ordering with respect to a spin
		 * lock in the networking core code.
		 */
		mmiowb();
#endif /* SPIN_UNLOCK_IMPLIES_MMIOWB */
	}
#else
	writel(i, tx_ring->tail);

#ifndef SPIN_UNLOCK_IMPLIES_MMIOWB
	/* We need this mmiowb on IA64/Altix systems where wmb() isn't
	 * guaranteed to synchronize I/O.
	 *
	 * Note that mmiowb() only provides a guarantee about ordering when in
	 * conjunction with a spin_unlock(). This barrier is used to guarantee
	 * the I/O ordering with respect to a spin lock in the networking core
	 * code.
	 */
	mmiowb();
#endif /* SPIN_UNLOCK_IMPLIES_MMIOWB */
#endif /* HAVE_XMIT_MORE */

	return 0;

dma_error:
	dev_info(tx_ring->dev, "TX DMA map failed\n");

	/* clear dma mappings for failed tx_bi map */
	for (;;) {
		tx_bi = &tx_ring->tx_bi[i];
		iavf_unmap_and_free_tx_resource(tx_ring, tx_bi);
		if (tx_bi == first)
			break;
		if (i == 0)
			i = tx_ring->count;
		i--;
	}

	tx_ring->next_to_use = i;

	return -EIO;
}

/**
 * iavf_xmit_frame_ring - Sends buffer on Tx ring
 * @skb:     send buffer
 * @tx_ring: ring to send buffer on
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 **/
static netdev_tx_t iavf_xmit_frame_ring(struct sk_buff *skb,
					struct iavf_ring *tx_ring)
{
	u64 cd_type_cmd_tso_mss = IAVF_TX_DESC_DTYPE_CONTEXT;
	u32 cd_tunneling = 0, cd_l2tag2 = 0;
	struct iavf_tx_buffer *first;
	u32 td_offset = 0;
	u32 tx_flags = 0;
	__be16 protocol;
	u32 td_cmd = 0;
	u8 hdr_len = 0;
	int tso, count;
	int tstamp;

	/* prefetch the data, we'll need it later */
	prefetch(skb->data);

	iavf_trace(xmit_frame_ring, skb, tx_ring);

	count = iavf_xmit_descriptor_count(skb);
	if (iavf_chk_linearize(skb, count)) {
		if (__skb_linearize(skb)) {
			dev_kfree_skb_any(skb);
			return NETDEV_TX_OK;
		}
		count = iavf_txd_use_count(skb->len);
		tx_ring->tx_stats.tx_linearize++;
	}

	/* need: 1 descriptor per page * PAGE_SIZE/IAVF_MAX_DATA_PER_TXD,
	 *       + 1 desc for skb_head_len/IAVF_MAX_DATA_PER_TXD,
	 *       + 4 desc gap to avoid the cache line where head is,
	 *       + 1 desc for context descriptor,
	 * otherwise try next time
	 */
	if (iavf_maybe_stop_tx(tx_ring, count + 4 + 1)) {
		tx_ring->tx_stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	/* record the location of the first descriptor for this packet */
	first = &tx_ring->tx_bi[tx_ring->next_to_use];
	first->skb = skb;
	first->bytecount = skb->len;
	first->gso_segs = 1;

	/* prepare the xmit flags */
	iavf_tx_prepare_vlan_flags(skb, tx_ring, &tx_flags);
	if (tx_flags & IAVF_TX_FLAGS_HW_OUTER_SINGLE_VLAN) {
		cd_type_cmd_tso_mss |= IAVF_TX_CTX_DESC_IL2TAG2 <<
			IAVF_TXD_CTX_QW1_CMD_SHIFT;
		cd_l2tag2 = (tx_flags & IAVF_TX_FLAGS_VLAN_MASK) >>
			IAVF_TX_FLAGS_VLAN_SHIFT;
	}

	/* obtain protocol of skb */
	protocol = vlan_get_protocol(skb);

	/* setup IPv4/IPv6 offloads */
	if (protocol == htons(ETH_P_IP))
		tx_flags |= IAVF_TX_FLAGS_IPV4;
	else if (protocol == htons(ETH_P_IPV6))
		tx_flags |= IAVF_TX_FLAGS_IPV6;
	else if (protocol == htons(ETH_P_LLDP))
		cd_type_cmd_tso_mss |= IAVF_TX_CTX_DESC_SWTCH_UPLINK <<
			IAVF_TXD_CTX_QW1_CMD_SHIFT;

	tso = iavf_tso(first, &hdr_len, &cd_type_cmd_tso_mss);

	if (tso < 0)
		goto out_drop;
	else if (tso)
		tx_flags |= IAVF_TX_FLAGS_TSO;

	/* Always offload the checksum, since it's in the data descriptor */
	tso = iavf_tx_enable_csum(skb, &tx_flags, &td_cmd, &td_offset,
				  tx_ring, &cd_tunneling);
	if (tso < 0)
		goto out_drop;

	tstamp = iavf_tstamp(tx_ring, skb, tx_flags, &cd_type_cmd_tso_mss);
	if (tstamp)
		tx_flags |= IAVF_TX_FLAGS_TSTAMP;

	/* always enable CRC insertion offload */
	td_cmd |= IAVF_TX_DESC_CMD_ICRC;

	iavf_create_tx_ctx(tx_ring, cd_type_cmd_tso_mss,
			   cd_tunneling, cd_l2tag2);

	if (iavf_tx_map(tx_ring, skb, first, tx_flags, hdr_len,
			td_cmd, td_offset))
		goto cleanup_ret;

#ifndef HAVE_TRANS_START_IN_QUEUE
	tx_ring->netdev->trans_start = jiffies;
#endif
	return NETDEV_TX_OK;

out_drop:
	iavf_trace(xmit_frame_ring_drop, first->skb, tx_ring);
	dev_kfree_skb_any(first->skb);
	first->skb = NULL;
cleanup_ret:
	if (unlikely(tx_flags & IAVF_TX_FLAGS_TSTAMP)) {
		struct iavf_adapter *adapter = netdev_priv(tx_ring->netdev);

		dev_kfree_skb_any(adapter->ptp.tx_skb);
		adapter->ptp.tx_skb = NULL;
		clear_bit_unlock(__IAVF_TX_TSTAMP_IN_PROGRESS, &adapter->crit_section);
	}

	return NETDEV_TX_OK;
}

/**
 * iavf_xmit_frame - Selects the correct VSI and Tx queue to send buffer
 * @skb:    send buffer
 * @netdev: network interface device structure
 *
 * Returns NETDEV_TX_OK if sent, else an error code
 **/
netdev_tx_t iavf_xmit_frame(struct sk_buff *skb, struct net_device *netdev)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	struct iavf_ring *tx_ring = &adapter->tx_rings[skb->queue_mapping];

#ifdef HAVE_PF_RING
#ifdef HAVE_PF_RING_ONLY
	if (!kernel_only_adapter[adapter->instance])
#else
	/* We don't allow legacy send when in zc mode */
	if (atomic_read(&adapter->pfring_zc.usage_counter) > 0)
#endif
	{

		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}
#endif

	/* hardware can't handle really short frames, hardware padding works
	 * beyond this point
	 */
	if (skb_put_padto(skb, IAVF_MIN_TX_LEN))
		return NETDEV_TX_OK;

	return iavf_xmit_frame_ring(skb, tx_ring);
}
