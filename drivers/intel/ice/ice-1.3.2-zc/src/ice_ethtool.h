/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2019, Intel Corporation. */

#ifndef _ICE_ETHTOOL_H_
#define _ICE_ETHTOOL_H_

struct ice_stats {
	char stat_string[ETH_GSTRING_LEN];
	int sizeof_stat;
	int stat_offset;
};

#define ICE_STAT(_type, _name, _stat) { \
	.stat_string = _name, \
	.sizeof_stat = sizeof_field(_type, _stat), \
	.stat_offset = offsetof(_type, _stat) \
}

#define ICE_VSI_STAT(_name, _stat) \
		ICE_STAT(struct ice_vsi, _name, _stat)
#define ICE_PF_STAT(_name, _stat) \
		ICE_STAT(struct ice_pf, _name, _stat)

#ifdef UNIFIED_STATS
#define PICK(legacy_stat, unified_stat) unified_stat
#else
#define PICK(legacy_stat, unified_stat) legacy_stat
#endif

/* VSI stats */
#define ICE_RX_UNICAST			"rx_unicast"
#define ICE_TX_UNICAST			"tx_unicast"
#define ICE_RX_MULTICAST		"rx_multicast"
#define ICE_TX_MULTICAST		"tx_multicast"
#define ICE_RX_BROADCAST		"rx_broadcast"
#define ICE_TX_BROADCAST		"tx_broadcast"
#define ICE_RX_BYTES			"rx_bytes"
#define ICE_TX_BYTES			"tx_bytes"
#define ICE_RX_DROPPED			PICK("rx_dropped", "rx-dropped_pkts")
#define ICE_RX_UNKNOWN_PROTO		PICK("rx_unknown_protocol", "rx-unknown-protocol_pkts")
#define ICE_RX_ALLOC_FAIL		PICK("rx_alloc_fail", "rx-buf-alloc-fail_events")
#define ICE_RX_PAGE_ALLOC_FAIL		PICK("rx_pg_alloc_fail", "rx-page-alloc-fail_events")
#define ICE_RX_GRO_DROPPED		"rx_gro_dropped"
#define ICE_TX_ERRORS			"tx_errors"
#define ICE_TX_LINEARIZE		PICK("tx_linearized", "tx-linearized_pkts")
#define ICE_TX_BUSY			PICK("tx_busy", "tx-busy_events")
#define ICE_TX_RESTART			"tx_restart"
#ifdef ICE_ADD_PROBES
#define ICE_RX_PAGE_REUSE		"rx_page_reuse"
#endif
#ifdef ADQ_PERF_COUNTERS
#endif /* ADQ_PERF_COUNTERS */

/* port stats */
#define ICE_PORT_RX_BYTES		PICK("rx_bytes.nic", "port-rx_bytes")
#define ICE_PORT_TX_BYTES		PICK("tx_bytes.nic", "port-tx_bytes")
#define ICE_PORT_RX_UNICAST		PICK("rx_unicast.nic", "port-rx-unicast_pkts")
#define ICE_PORT_TX_UNICAST		PICK("tx_unicast.nic", "port-tx-unicast_pkts")
#define ICE_PORT_RX_MULTICAST		PICK("rx_multicast.nic", "port-rx-multicast_pkts")
#define ICE_PORT_TX_MULTICAST		PICK("tx_multicast.nic", "port-tx-multicast_pkts")
#define ICE_PORT_RX_BROADCAST		PICK("rx_broadcast.nic", "port-rx-broadcast_pkts")
#define ICE_PORT_TX_BROADCAST		PICK("tx_broadcast.nic", "port-tx-broadcast_pkts")
#define ICE_PORT_TX_ERRORS		PICK("tx_errors.nic", "port-tx_errors")
#define ICE_PORT_TX_TIMEOUT		PICK("tx_timeout.nic", "port-tx-timeout_events")
#define ICE_PORT_RX_SIZE_64		PICK("rx_size_64.nic", "port-rx_size-64_pkts")
#define ICE_PORT_TX_SIZE_64		PICK("tx_size_64.nic", "port-tx_size-64_pkts")
#define ICE_PORT_RX_SIZE_127		PICK("rx_size_127.nic", "port-rx_size-127_pkts")
#define ICE_PORT_TX_SIZE_127		PICK("tx_size_127.nic", "port-tx_size-127_pkts")
#define ICE_PORT_RX_SIZE_255		PICK("rx_size_255.nic", "port-rx_size-255_pkts")
#define ICE_PORT_TX_SIZE_255		PICK("tx_size_255.nic", "port-tx_size-255_pkts")
#define ICE_PORT_RX_SIZE_511		PICK("rx_size_511.nic", "port-rx_size-511_pkts")
#define ICE_PORT_TX_SIZE_511		PICK("tx_size_511.nic", "port-tx_size-511_pkts")
#define ICE_PORT_RX_SIZE_1023		PICK("rx_size_1023.nic", "port-rx_size-1023_pkts")
#define ICE_PORT_TX_SIZE_1023		PICK("tx_size_1023.nic", "port-tx_size-1023_pkts")
#define ICE_PORT_RX_SIZE_1522		PICK("rx_size_1522.nic", "port-rx_size-1522_pkts")
#define ICE_PORT_TX_SIZE_1522		PICK("tx_size_1522.nic", "port-tx_size-1522_pkts")
#define ICE_PORT_RX_SIZE_JUMBO		PICK("rx_size_big.nic", "port-rx_size-jumbo_pkts")
#define ICE_PORT_TX_SIZE_JUMBO		PICK("tx_size_big.nic", "port-tx_size-jumbo_pkts")
#define ICE_PORT_RX_LINK_XON		PICK("link_xon_rx.nic", "port-rx-xon_events")
#define ICE_PORT_TX_LINK_XON		PICK("link_xon_tx.nic", "port-tx-xon_events")
#define ICE_PORT_RX_LINK_XOFF		PICK("link_xoff_rx.nic", "port-rx-xoff_events")
#define ICE_PORT_TX_LINK_XOFF		PICK("link_xoff_tx.nic", "port-tx-xoff_events")
#define ICE_PORT_TX_DROP_LINK_DOWN	PICK("tx_dropped_link_down.nic", "port-tx-dropped_link-down_pkts")
#define ICE_PORT_RX_UNDERSIZE		PICK("rx_undersize.nic", "port-rx-undersized_pkts")
#define ICE_PORT_RX_FRAGMENTS		PICK("rx_fragments.nic", "port-rx-fragmented_pkts")
#define ICE_PORT_RX_OVERSIZE		PICK("rx_oversize.nic", "port-rx-oversized_pkts")
#define ICE_PORT_RX_JABBER		PICK("rx_jabber.nic", "port-rx-jabber_pkts")
#define ICE_PORT_RX_CSUM_BAD		PICK("rx_csum_bad.nic", "port-rx-csum_errors")
#define ICE_PORT_RX_LEN_ERRORS		PICK("rx_length_errors.nic", "port-rx-length_errors")
#define ICE_PORT_RX_DROPPED		PICK("rx_dropped.nic", "port-rx-dropped_pkts")
#define ICE_PORT_RX_CRC_ERRORS		PICK("rx_crc_errors.nic", "port-rx-crc_errors")
#define ICE_PORT_ILLEGAL_BYTES		PICK("illegal_bytes.nic", "port-rx-illegal_bytes")
#define ICE_PORT_MAC_LOCAL_FAULTS	PICK("mac_local_faults.nic", "port-mac-local_faults")
#define ICE_PORT_MAC_REMOTE_FAULTS	PICK("mac_remote_faults.nic", "port-mac-remote_faults")
#ifdef ICE_ADD_PROBES
#define ICE_PORT_TX_TCP_SEGMENTS	PICK("tx_tcp_segments.nic", "port-tx-tcp-segments_count")
#define ICE_PORT_TX_UDP_SEGMENTS	PICK("tx_udp_segments.nic", "port-tx-udp-segments_count")
#define ICE_PORT_RX_TCP_CSO		PICK("rx_tcp_cso.nic", "port-rx-tcp-csum-offload_count")
#define ICE_PORT_TX_TCP_CSO		PICK("tx_tcp_cso.nic", "port-tx-tcp-csum-offload_count")
#define ICE_PORT_RX_UDP_CSO		PICK("rx_udp_cso.nic", "port-rx-udp-csum-offload_count")
#define ICE_PORT_TX_UDP_CSO		PICK("tx_udp_cso.nic", "port-tx-udp-csum-offload_count")
#define ICE_PORT_RX_SCTP_CSO		PICK("rx_sctp_cso.nic", "port-rx-sctp-csum-offload_count")
#define ICE_PORT_TX_SCTP_CSO		PICK("tx_sctp_cso.nic", "port-tx-sctp-csum-offload_count")
#define ICE_PORT_RX_IP4_CSO		PICK("rx_ip4_cso.nic", "port-rx-ipv4-csum-offload_count")
#define ICE_PORT_TX_IP4_CSO		PICK("tx_ip4_cso.nic", "port-tx-ipv4-csum-offload_count")
#define ICE_PORT_RX_IP4_CSO_ERROR	PICK("rx_ip4_cso_error.nic", "port-rx-ipv4-csum_errors")
#define ICE_PORT_RX_TCP_CSO_ERROR	PICK("rx_tcp_cso_error.nic", "port-rx-tcp-csum_errors")
#define ICE_PORT_RX_UDP_CSO_ERROR	PICK("rx_udp_cso_error.nic", "port-rx-udp-csum_errors")
#define ICE_PORT_RX_SCTP_CSO_ERROR	PICK("rx_sctp_cso_error.nic", "port-rx-sctp-csum_errors")
#define ICE_PORT_TX_L3_CSO_ERROR	PICK("tx_l3_cso_err.nic", "port-tx-layer-3-csum_errors")
#define ICE_PORT_TX_L4_CSO_ERROR	PICK("tx_l4_cso_err.nic", "port-tx-layer-4-csum_errors")
#define ICE_PORT_RX_VLANO		PICK("rx_vlano.nic", "port-rx-vlan-offload_count")
#define ICE_PORT_TX_VLANO		PICK("tx_vlano.nic", "port-tx-vlan-offload_count")
#endif /* ICE_ADD_PROBES */
	/* LPI stats */
#define ICE_PORT_RX_LPI_STATUS		PICK("rx_lpi_status.nic", "port-rx-lpi_status")
#define ICE_PORT_TX_LPI_STATUS		PICK("tx_lpi_status.nic", "port-tx-lpi_status")
#define ICE_PORT_RX_LPI_COUNT		PICK("rx_lpi_count.nic", "port-rx-lpi_count")
#define ICE_PORT_TX_LPI_COUNT		PICK("tx_lpi_count.nic", "port-tx-lpi_count")
#define ICE_PORT_FDIR_SB_MATCH		PICK("fdir_sb_match.nic", "port-rx-fdir-sideband")
#define ICE_PORT_FDIR_SB_STATUS		PICK("fdir_sb_status.nic", "port-rx-fdir-sideband-status")
#ifdef ICE_ADD_PROBES
#define ICE_PORT_ARFS_TCPV4_MATCH	PICK("arfs_tcpv4_match.nic", "port-rx-arfs-tcpv4-pkts")
#define ICE_PORT_ARFS_TCPV6_MATCH	PICK("arfs_tcpv6_match.nic", "port-rx-arfs-tcpv6-pkts")
#define ICE_PORT_ARFS_UDP4_MATCH	PICK("arfs_udpv4_match.nic", "port-rx-arfs-udpv4-pkts")
#define ICE_PORT_ARFS_UDP6_MATCH	PICK("arfs_udpv6_match.nic", "port-rx-arfs-udpv6-pkts")
#endif /* ICE_ADD_PROBES */
#define PORT_TX_PRIO_XON		PICK("tx_priority_%u_xon.nic", "port-tx-xon_prio-%u_events")
#define PORT_TX_PRIO_XOFF		PICK("tx_priority_%u_xoff.nic", "port-tx-xoff_prio-%u_events")
#define PORT_RX_PRIO_XON		PICK("rx_priority_%u_xon.nic", "port-rx-xon_prio-%u_events")
#define PORT_RX_PRIO_XOFF		PICK("rx_priority_%u_xoff.nic", "port-rx-xoff_prio-%u_events")

/* per-queue stats */
#define ICE_TXQ_PACKETS			PICK("tx_queue_%u_packets", "tx_q-%u_pkts")
#define ICE_TXQ_BYTES			PICK("tx_queue_%u_bytes", "tx_q-%u_bytes")
#define ICE_RXQ_PACKETS			PICK("rx_queue_%u_packets", "rx_q-%u_pkts")
#define ICE_RXQ_BYTES			PICK("rx_queue_%u_bytes", "rx_q-%u_bytes")
#ifdef ICE_ADD_PROBES
#define ICE_TXQ_NAPI_POLL		PICK("tx_queue_%u_napi_poll_cnt", "tx_q-%u_napi_poll_count")
#define ICE_RXQ_NAPI_POLL		PICK("rx_queue_%u_napi_poll_cnt", "rx_q-%u_napi_poll_count")
#endif /* ICE_ADD_PROBES */

#ifdef HAVE_NETDEV_SB_DEV
#ifdef ICE_ADD_PROBES
/* macvlan stats */
#define L2_FWD_TX_PKTS1			PICK("l2-fwd-%s-tx_pkts", "tx-l2-forward_q-%s_pkts")
#define L2_FWD_TX_BYTES1		PICK("l2-fwd-%s-tx_bytes", "tx-l2-forward_q-%s_bytes")
#define L2_FWD_TX_PKTS2			PICK("l2-fwd-%i-tx_pkts", "tx-l2-forward_q-%i_pkts")
#define L2_FWD_TX_BYTES2		PICK("l2-fwd-%i-tx_bytes", "tx-l2-forward_q-%i_bytes")
#define L2_FWD_RX_PKTS1			PICK("l2-fwd-%s-rx_pkts", "rx-l2-forward_q-%s_pkts")
#define L2_FWD_RX_BYTES1		PICK("l2-fwd-%s-rx_bytes", "rx-l2-forward_q-%s_bytes")
#define L2_FWD_RX_PKTS2			PICK("l2-fwd-%i-rx_pkts", "rx-l2-forward_q-%i_pkts")
#define L2_FWD_RX_BYTES2		PICK("l2-fwd-%i-rx_bytes", "rx-l2-forward_q-%i_bytes")
#endif /* ICE_ADD_PROBES */
#endif /* HAVE_NETDEV_SB_DEV */

#ifdef ADQ_PERF_COUNTERS
/* ADQ stats */
#define ICE_TXQ_BUSY_POLL		PICK("tx_%u.pkt_busy_poll", "tx_q-%u_pkt_busy_poll")
#define ICE_TXQ_NOT_BUSY_POLL		PICK("tx_%u.pkt_not_busy_poll", "tx_q-%u_pkt_not_busy_poll")
#define ICE_TXQ_ATR_SETUP		PICK("tx_%u.atr_setup", "tx_q-%u_atr_setup")
#define ICE_TXQ_ATR_TEARDOWN		PICK("tx_%u.atr_teardown", "tx_q-%u_atr_teardown")
#define ICE_TXQ_ATR_BAIL		PICK("tx_%u.atr_bailouts", "tx_q-%u_atr_bailouts")
#define ICE_RXQ_BUSY_POLL		PICK("rx_%u.pkt_busy_poll", "rx_q-%u_pkt_busy_poll")
#define ICE_RXQ_NOT_BUSY_POLL		PICK("rx_%u.pkt_not_busy_poll", "rx_q-%u_pkt_not_busy_poll")
#define ICE_RXQ_SET			PICK("rx_%u.queue_set", "rx_q-%u_queue_set")
#define ICE_RXQ_BAIL			PICK("rx_%u.queue_bailouts", "rx_q-%u_queue_bailouts")
#define ICE_RXQ_TCP_CTRL_PKTS		PICK("rx_%u.tcp_ctrl_pkts", "rx_q-%u_tcp_ctrl_pkts")
#define ICE_RXQ_ONLY_CTRL_PKTS		PICK("rx_%u.only_ctrl_pkts", "rx_q-%u_only_ctrl_pkts")
#define ICE_RXQ_TCP_FIN_RECV		PICK("rx_%u.tcp_fin_recv", "rx_q-%u_tcp_fin_recv")
#define ICE_RXQ_TCP_RST_RECV		PICK("rx_%u.tcp_rst_recv", "rx_q-%u_tcp_rst_recv")
#define ICE_RXQ_TCP_SYN_RECV		PICK("rx_%u.tcp_syn_recv", "rx_q-%u_tcp_syn_recv")
#define ICE_RXQ_BP_NO_DATA_PKT		PICK("rx_%u.bp_no_data_pkt", "rx_q-%u_bp_no_data_pkt")
#define ICE_RXQ_IN_BP			PICK("rx_%u.in_bp", "rx_q-%u_in_bp")
#define ICE_RXQ_INTR_TO_BP		PICK("rx_%u.intr_to_bp", "rx_q-%u_intr_to_bp")
#define ICE_RXQ_BP_TO_BP		PICK("rx_%u.bp_to_bp", "rx_q-%u_bp_to_bp")
#define ICE_RXQ_IN_INTR			PICK("rx_%u.in_intr", "rx_q-%u_in_intr")
#define ICE_RXQ_BP_TO_INTR		PICK("rx_%u.bp_to_intr", "rx_q-%u_bp_to_intr")
#define ICE_RXQ_INTR_TO_INTR		PICK("rx_%u.intr_to_intr", "rx_q-%u_intr_to_intr")
#define ICE_RXQ_UNLIKELY_CB_TO_BP	PICK("rx_%u.unlikely_cb_to_bp", "rx_q-%u_unlikely_cb_to_bp")
#define ICE_RXQ_UCB_ONCE_IN_BP		PICK("rx_%u.ucb_once_in_bp", "rx_q-%u_ucb_once_in_bp")
#define ICE_RXQ_INTR_ONCE_IN_BP_FALSE	PICK("rx_%u.intr_once_in_bp_false", "rx_q-%u_intr_once_in_bp_false")
#define ICE_RXQ_BP_STOP_NEED_RESCHED	PICK("rx_%u.bp_stop_need_resched", "rx_q-%u_bp_stop_need_resched")
#define ICE_RXQ_BP_STOP_TIMEOUT		PICK("rx_%u.bp_stop_timeout", "rx_q-%u_bp_stop_timeout")
#define ICE_RXQ_CLEANED_ANY_DATA_PKT	PICK("rx_%u.cleaned_any_data_pkt", "rx_q-%u_cleaned_any_data_pkt")
#define ICE_RXQ_NEED_RESCHED_NO_DATA	PICK("rx_%u.need_resched_no_data", "rx_q-%u_need_resched_no_data")
#define ICE_RXQ_TIMEOUT_NO_DATA		PICK("rx_%u.timeout_no_data", "rx_q-%u_timeout_no_data")
#define ICE_RXQ_SW_INTR_TIMEOUT		PICK("rx_%u.sw_intr_timeout", "rx_q-%u_sw_intr_timeout")
#define ICE_RXQ_SW_INTR_SERV_TASK	PICK("rx_%u.sw_intr_service_task", "rx_q-%u_sw_intr_service_task")
#define ICE_RXQ_NO_SW_INTR_OPT_OFF	PICK("rx_%u.no_sw_intr_opt_off", "rx_q-%u_no_sw_intr_opt_off")
#define ICE_RXQ_WB_ON_ITR_SET		PICK("rx_%u.wb_on_itr_set", "rx_q-%u_wb_on_itr_set")
#define ICE_RXQ_PKTS_BP_STOP_BUDGET8	PICK("rx_%u.pkts_bp_stop_budget8", "rx_q-%u_pkts_bp_stop_budget8")
#define ICE_RXQ_PKTS_BP_STOP_BUDGET64	PICK("rx_%u.pkts_bp_stop_budget64", "rx_q-%u_pkts_bp_stop_budget64")
#define ICE_RXQ_BP_WD_EQUAL_BUDGET8	PICK("rx_%u.bp_wd_equal_budget8", "rx_q-%u_bp_wd_equal_budget8")
#define ICE_RXQ_BP_WD_EQUAL_BUDGET64	PICK("rx_%u.bp_wd_equal_budget64", "rx_q-%u_bp_wd_equal_b")
#define ICE_RXQ_KEEP_STATE_BP_BUDGET8	PICK("rx_%u.keep_state_bp_budget8", "rx_q-%u_keep_state_bp_budget8")
#define ICE_RXQ_KEEP_STATE_BP_BUDGET64	PICK("rx_%u.keep_state_bp_budget64", "rx_q-%u_keep_state_bp_budget64")
#endif /* ADQ_PERF_COUNTERS */
#endif /* !_ICE_ETHTOOL_H_ */
