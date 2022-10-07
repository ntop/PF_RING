/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2013, Intel Corporation. */

/* ethtool statistics helpers */

/**
 * struct iavf_stats - definition for an ethtool statistic
 * @stat_string: statistic name to display in ethtool -S output
 * @sizeof_stat: the sizeof() the stat, must be no greater than sizeof(u64)
 * @stat_offset: offsetof() the stat from a base pointer
 *
 * This structure defines a statistic to be added to the ethtool stats buffer.
 * It defines a statistic as offset from a common base pointer. Stats should
 * be defined in constant arrays using the IAVF_STAT macro, with every element
 * of the array using the same _type for calculating the sizeof_stat and
 * stat_offset.
 *
 * The @sizeof_stat is expected to be sizeof(u8), sizeof(u16), sizeof(u32) or
 * sizeof(u64). Other sizes are not expected and will produce a WARN_ONCE from
 * the iavf_add_ethtool_stat() helper function.
 *
 * The @stat_string is interpreted as a format string, allowing formatted
 * values to be inserted while looping over multiple structures for a given
 * statistics array. Thus, every statistic string in an array should have the
 * same type and number of format specifiers, to be formatted by variadic
 * arguments to the iavf_add_stat_string() helper function.
 **/
struct iavf_stats {
	char stat_string[ETH_GSTRING_LEN];
	int sizeof_stat;
	int stat_offset;
};

/* Helper macro to define an iavf_stat structure with proper size and type.
 * Use this when defining constant statistics arrays. Note that @_type expects
 * only a type name and is used multiple times.
 */
#define IAVF_STAT(_type, _name, _stat) { \
	.stat_string = _name, \
	.sizeof_stat = sizeof_field(_type, _stat), \
	.stat_offset = offsetof(_type, _stat) \
}


/* Helper macro for defining some statistics related to queues */
#define IAVF_QUEUE_STAT(_name, _stat) \
	IAVF_STAT(struct iavf_ring, _name, _stat)

/* Stats associated with a Tx or Rx ring */
static const struct iavf_stats iavf_gstrings_queue_stats[] = {
	IAVF_QUEUE_STAT("%s-%u.packets", stats.packets),
	IAVF_QUEUE_STAT("%s-%u.bytes", stats.bytes),
};

#define IAVF_VECTOR_STAT(_name, _stat) \
	IAVF_STAT(struct iavf_q_vector, _name, _stat)

/* Stats associated with a Tx or Rx ring */
static struct iavf_stats iavf_gstrings_queue_stats_poll[] = {
	IAVF_QUEUE_STAT("%s-%u.pkt_busy_poll", ch_q_stats.poll.pkt_busy_poll),
	IAVF_QUEUE_STAT("%s-%u.pkt_not_busy_poll",
			ch_q_stats.poll.pkt_not_busy_poll),
};

static struct iavf_stats iavf_gstrings_queue_stats_tx[] = {
};

static struct iavf_stats iavf_gstrings_queue_stats_rx[] = {
	IAVF_QUEUE_STAT("%s-%u.tcp_ctrl_pkts", ch_q_stats.rx.tcp_ctrl_pkts),
	IAVF_QUEUE_STAT("%s-%u.only_ctrl_pkts", ch_q_stats.rx.only_ctrl_pkts),
	IAVF_QUEUE_STAT("%s-%u.tcp_fin_recv", ch_q_stats.rx.tcp_fin_recv),
	IAVF_QUEUE_STAT("%s-%u.tcp_rst_recv", ch_q_stats.rx.tcp_rst_recv),
	IAVF_QUEUE_STAT("%s-%u.tcp_syn_recv", ch_q_stats.rx.tcp_syn_recv),
	IAVF_QUEUE_STAT("%s-%u.bp_no_data_pkt", ch_q_stats.rx.bp_no_data_pkt),
};

static struct iavf_stats iavf_gstrings_queue_stats_vector[] = {
	/* tracking BP, INT, BP->INT, INT->BP */
	IAVF_VECTOR_STAT("%s-%u.in_bp", ch_stats.in_bp),
	IAVF_VECTOR_STAT("%s-%u.intr_to_bp", ch_stats.intr_to_bp),
	IAVF_VECTOR_STAT("%s-%u.bp_to_bp", ch_stats.bp_to_bp),
	IAVF_VECTOR_STAT("%s-%u.in_intr", ch_stats.in_intr),
	IAVF_VECTOR_STAT("%s-%u.bp_to_intr", ch_stats.bp_to_intr),
	IAVF_VECTOR_STAT("%s-%u.intr_to_intr", ch_stats.intr_to_intr),

	/* unlikely comeback to busy_poll */
	IAVF_VECTOR_STAT("%s-%u.unlikely_cb_to_bp", ch_stats.unlikely_cb_to_bp),
	/* unlikely comeback to busy_poll and once_in_bp is true */
	IAVF_VECTOR_STAT("%s-%u.ucb_once_in_bp_true",
			 ch_stats.ucb_once_in_bp_true),
	/* once_in_bp is false */
	IAVF_VECTOR_STAT("%s-%u.intr_once_in_bp_false",
			 ch_stats.intr_once_bp_false),
	/* busy_poll stop due to need_resched() */
	IAVF_VECTOR_STAT("%s-%u.bp_stop_need_resched",
			 ch_stats.bp_stop_need_resched),
	/* busy_poll stop due to possible due to timeout */
	IAVF_VECTOR_STAT("%s-%u.bp_stop_timeout", ch_stats.bp_stop_timeout),
	/* Transition: BP->INT: previously cleaned data packets */
	IAVF_VECTOR_STAT("%s-%u.cleaned_any_data_pkt",
			 ch_stats.cleaned_any_data_pkt),
	/* need_resched(), but didn't clean any data packets */
	IAVF_VECTOR_STAT("%s-%u.need_resched_no_data_pkt",
			 ch_stats.need_resched_no_data_pkt),
	/* possible timeout(), but didn't clean any data packets */
	IAVF_VECTOR_STAT("%s-%u.timeout_no_data_pkt",
			 ch_stats.timeout_no_data_pkt),
	/* number of SW triggered interrupt from napi_poll due to
	 * possible timeout detected
	 */
	IAVF_VECTOR_STAT("%s-%u.sw_intr_timeout", ch_stats.sw_intr_timeout),
	/* number of SW triggered interrupt from service_task */
	IAVF_VECTOR_STAT("%s-%u.sw_intr_service_task",
			 ch_stats.sw_intr_serv_task),
	/* number of times, SW triggered interrupt is not triggered from
	 * napi_poll even when unlikely_cb_to_bp is set, once_in_bp is set
	 * but ethtool private featute flag is off (for interrupt optimization
	 * strategy
	 */
	IAVF_VECTOR_STAT("%s-%u.no_sw_intr_opt_off",
			 ch_stats.no_sw_intr_opt_off),
	/* number of times WB_ON_ITR is set */
	IAVF_VECTOR_STAT("%s-%u.wb_on_itr_set", ch_stats.wb_on_itr_set),

	/* enable SW triggered interrupt due to not_clean_complete */
	IAVF_VECTOR_STAT("%s-%u.sw_intr_not_cc",
			 ch_stats.intr_en_not_clean_complete),
};

/**
 * iavf_add_one_ethtool_stat - copy the stat into the supplied buffer
 * @data: location to store the stat value
 * @pointer: basis for where to copy from
 * @stat: the stat definition
 *
 * Copies the stat data defined by the pointer and stat structure pair into
 * the memory supplied as data. Used to implement iavf_add_ethtool_stats and
 * iavf_add_queue_stats. If the pointer is null, data will be zero'd.
 */
static void
iavf_add_one_ethtool_stat(u64 *data, void *pointer,
			  const struct iavf_stats *stat)
{
	char *p;

	if (!pointer) {
		/* ensure that the ethtool data buffer is zero'd for any stats
		 * which don't have a valid pointer.
		 */
		*data = 0;
		return;
	}

	p = (char *)pointer + stat->stat_offset;
	switch (stat->sizeof_stat) {
	case sizeof(u64):
		*data = *((u64 *)p);
		break;
	case sizeof(u32):
		*data = *((u32 *)p);
		break;
	case sizeof(u16):
		*data = *((u16 *)p);
		break;
	case sizeof(u8):
		*data = *((u8 *)p);
		break;
	default:
		WARN_ONCE(1, "unexpected stat size for %s",
			  stat->stat_string);
		*data = 0;
	}
}

/**
 * __iavf_add_ethtool_stats - copy stats into the ethtool supplied buffer
 * @data: ethtool stats buffer
 * @pointer: location to copy stats from
 * @stats: array of stats to copy
 * @size: the size of the stats definition
 *
 * Copy the stats defined by the stats array using the pointer as a base into
 * the data buffer supplied by ethtool. Updates the data pointer to point to
 * the next empty location for successive calls to __iavf_add_ethtool_stats.
 * If pointer is null, set the data values to zero and update the pointer to
 * skip these stats.
 **/
static void
__iavf_add_ethtool_stats(u64 **data, void *pointer,
			 const struct iavf_stats stats[],
			 const unsigned int size)
{
	unsigned int i;

	for (i = 0; i < size; i++)
		iavf_add_one_ethtool_stat((*data)++, pointer, &stats[i]);
}

/**
 * iavf_add_ethtool_stats - copy stats into ethtool supplied buffer
 * @data: ethtool stats buffer
 * @pointer: location where stats are stored
 * @stats: static const array of stat definitions
 *
 * Macro to ease the use of __iavf_add_ethtool_stats by taking a static
 * constant stats array and passing the ARRAY_SIZE(). This avoids typos by
 * ensuring that we pass the size associated with the given stats array.
 *
 * The parameter @stats is evaluated twice, so parameters with side effects
 * should be avoided.
 **/
#define iavf_add_ethtool_stats(data, pointer, stats) \
	__iavf_add_ethtool_stats(data, pointer, stats, ARRAY_SIZE(stats))

enum iavf_chnl_stat_type {
	IAVF_CHNL_STAT_INVALID,
	IAVF_CHNL_STAT_POLL,
	IAVF_CHNL_STAT_TX,
	IAVF_CHNL_STAT_RX,
	IAVF_CHNL_STAT_VECTOR,
	IAVF_CHNL_STAT_LAST, /* This must be last */_
};

/**
 * iavf_add_queue_stats_chnl - copy channel specific queue stats
 * @data: ethtool stats buffer
 * @ring: the ring to copy
 * @stat_type: stat_type could be TX/TX/VECTOR
 *
 * Queue statistics must be copied while protected by
 * u64_stats_fetch_begin_irq, so we can't directly use iavf_add_ethtool_stats.
 * Assumes that queue stats are defined in iavf_gstrings_queue_stats. If the
 * ring pointer is null, zero out the queue stat values and update the data
 * pointer. Otherwise safely copy the stats from the ring into the supplied
 * buffer and update the data pointer when finished.
 *
 * This function expects to be called while under rcu_read_lock().
 **/
static void
iavf_add_queue_stats_chnl(u64 **data, struct iavf_ring *ring,
			  enum iavf_chnl_stat_type stat_type)
{
	struct iavf_stats *stats = NULL;
#ifdef HAVE_NDO_GET_STATS64
	unsigned int start;
#endif
	unsigned int size;
	unsigned int i;

	switch (stat_type) {
	case IAVF_CHNL_STAT_POLL:
		size = ARRAY_SIZE(iavf_gstrings_queue_stats_poll);
		stats = iavf_gstrings_queue_stats_poll;
		break;
	case IAVF_CHNL_STAT_TX:
		size = ARRAY_SIZE(iavf_gstrings_queue_stats_tx);
		stats = iavf_gstrings_queue_stats_tx;
		break;
	case IAVF_CHNL_STAT_RX:
		size = ARRAY_SIZE(iavf_gstrings_queue_stats_rx);
		stats = iavf_gstrings_queue_stats_rx;
		break;
	case IAVF_CHNL_STAT_VECTOR:
		size = ARRAY_SIZE(iavf_gstrings_queue_stats_vector);
		stats = iavf_gstrings_queue_stats_vector;
		break;
	default:
		break; /* unsupported stat type */
	}

	if (!stats)
		return;

	/* To avoid invalid statistics values, ensure that we keep retrying
	 * the copy until we get a consistent value according to
	 * u64_stats_fetch_retry_irq. But first, make sure our ring is
	 * non-null before attempting to access its syncp.
	 */
#ifdef HAVE_NDO_GET_STATS64
	do {
		start = !ring ? 0 : u64_stats_fetch_begin_irq(&ring->syncp);
#endif
		for (i = 0; i < size; i++) {
			void *ptr = ring;

			if (stat_type == IAVF_CHNL_STAT_VECTOR)
				ptr = ring ? ring->q_vector : NULL;
			iavf_add_one_ethtool_stat(&(*data)[i], ptr,
						  &stats[i]);
		}
#ifdef HAVE_NDO_GET_STATS64
	} while (ring && u64_stats_fetch_retry_irq(&ring->syncp, start));
#endif

	/* Once we successfully copy the stats in, update the data pointer */
	*data += size;
}

/**
 * iavf_add_queue_stats - copy queue statistics into supplied buffer
 * @data: ethtool stats buffer
 * @ring: the ring to copy
 *
 * Queue statistics must be copied while protected by
 * u64_stats_fetch_begin_irq, so we can't directly use iavf_add_ethtool_stats.
 * Assumes that queue stats are defined in iavf_gstrings_queue_stats. If the
 * ring pointer is null, zero out the queue stat values and update the data
 * pointer. Otherwise safely copy the stats from the ring into the supplied
 * buffer and update the data pointer when finished.
 *
 * This function expects to be called while under rcu_read_lock().
 **/
static void
iavf_add_queue_stats(u64 **data, struct iavf_ring *ring)
{
	const unsigned int size = ARRAY_SIZE(iavf_gstrings_queue_stats);
	const struct iavf_stats *stats = iavf_gstrings_queue_stats;
#ifdef HAVE_NDO_GET_STATS64
	unsigned int start;
#endif
	unsigned int i;

	/* To avoid invalid statistics values, ensure that we keep retrying
	 * the copy until we get a consistent value according to
	 * u64_stats_fetch_retry_irq. But first, make sure our ring is
	 * non-null before attempting to access its syncp.
	 */
#ifdef HAVE_NDO_GET_STATS64
	do {
		start = !ring ? 0 : u64_stats_fetch_begin_irq(&ring->syncp);
#endif
		for (i = 0; i < size; i++) {
			iavf_add_one_ethtool_stat(&(*data)[i], ring,
						  &stats[i]);
		}
#ifdef HAVE_NDO_GET_STATS64
	} while (ring && u64_stats_fetch_retry_irq(&ring->syncp, start));
#endif

	/* Once we successfully copy the stats in, update the data pointer */
	*data += size;
}


/**
 * __iavf_add_stat_strings - copy stat strings into ethtool buffer
 * @p: ethtool supplied buffer
 * @stats: stat definitions array
 * @size: size of the stats array
 *
 * Format and copy the strings described by stats into the buffer pointed at
 * by p.
 **/
static void __iavf_add_stat_strings(u8 **p, const struct iavf_stats *stats,
				    const unsigned int size, ...)
{
	unsigned int i;

	for (i = 0; i < size; i++) {
		va_list args;

		va_start(args, size);
		vsnprintf(*p, ETH_GSTRING_LEN, stats[i].stat_string, args);
		*p += ETH_GSTRING_LEN;
		va_end(args);
	}
}

/**
 * iavf_add_stat_strings - copy stat strings into ethtool buffer
 * @p: ethtool supplied buffer
 * @stats: stat definitions array
 *
 * Format and copy the strings described by the const static stats value into
 * the buffer pointed at by p.
 *
 * The parameter @stats is evaluated twice, so parameters with side effects
 * should be avoided. Additionally, stats must be an array such that
 * ARRAY_SIZE can be called on it.
 **/
#define iavf_add_stat_strings(p, stats, ...) \
	__iavf_add_stat_strings(p, stats, ARRAY_SIZE(stats), ## __VA_ARGS__)
