/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2023 Intel Corporation */

#ifndef _ICE_LIB_H_
#define _ICE_LIB_H_

#include "ice.h"

/* Flags used for VSI configuration and rebuild */
#define ICE_VSI_FLAG_NO_INIT	0
#define ICE_VSI_FLAG_INIT	BIT(0)
#define ICE_VSI_FLAG_RELOAD	BIT(1) /* devlink reload action */

/**
 * struct ice_vsi_cfg_params - VSI configuration parameters
 * @pi: pointer to the port_info instance for the VSI
 * @ch: pointer to the channel structure for the VSI, may be NULL
 * @tc: traffic class number
 * @vf: pointer to the VF associated with this VSI, may be NULL
 * @type: the type of VSI to configure
 * @flags: VSI flags used for rebuild and configuration
 *
 * Parameter structure used when configuring a new VSI.
 */
struct ice_vsi_cfg_params {
	struct ice_port_info *pi;
	struct ice_vf *vf;
	u32 flags;
	enum ice_vsi_type type;
	struct ice_channel *ch;
	u8 tc;
};

/**
 * ice_vsi_to_params - Get parameters for an existing VSI
 * @vsi: the VSI to get parameters for
 *
 * Fill a parameter structure for reconfiguring a VSI with its current
 * parameters, such as during a rebuild operation.
 */
static inline struct ice_vsi_cfg_params ice_vsi_to_params(struct ice_vsi *vsi)
{
	struct ice_vsi_cfg_params params;

	params.pi = vsi->port_info;
	params.ch = vsi->ch;
	params.tc = 0;
	params.vf = vsi->vf;
	params.type = vsi->type;
	params.flags = 0;

	return params;
}

const char *ice_vsi_type_str(enum ice_vsi_type vsi_type);

bool ice_pf_state_is_nominal(struct ice_pf *pf);

void ice_update_eth_stats(struct ice_vsi *vsi);

int ice_vsi_cfg_single_rxq(struct ice_vsi *vsi, u16 q_idx);

int ice_vsi_cfg_single_txq(struct ice_vsi *vsi, struct ice_tx_ring **tx_rings, u16 q_idx);

int ice_vsi_cfg_rxqs(struct ice_vsi *vsi);

int ice_vsi_cfg_lan_txqs(struct ice_vsi *vsi);

void ice_vsi_cfg_msix(struct ice_vsi *vsi);

int ice_vsi_start_all_rx_rings(struct ice_vsi *vsi);

int ice_vsi_stop_all_rx_rings(struct ice_vsi *vsi);

int
ice_vsi_stop_lan_tx_rings(struct ice_vsi *vsi, enum ice_disq_rst_src rst_src,
			  u16 rel_vmvf_num);
#ifdef HAVE_XDP_SUPPORT

int ice_vsi_cfg_xdp_txqs(struct ice_vsi *vsi);

int ice_vsi_stop_xdp_tx_rings(struct ice_vsi *vsi);

#endif /* HAVE_XDP_SUPPORT */

bool ice_vsi_is_vlan_pruning_ena(struct ice_vsi *vsi);

void ice_cfg_sw_lldp(struct ice_vsi *vsi, bool tx, bool create);

int ice_set_link(struct ice_vsi *vsi, bool ena);

void ice_vsi_delete_from_hw(struct ice_vsi *vsi);
int ice_vsi_free(struct ice_vsi *vsi);
void ice_vsi_put_qs(struct ice_vsi *vsi);

void ice_vsi_cfg_netdev_tc(struct ice_vsi *vsi, u8 ena_tc);

int ice_vsi_cfg_tc(struct ice_vsi *vsi, u8 ena_tc);

int ice_vsi_cfg_rss_lut_key(struct ice_vsi *vsi);

int ice_get_valid_rss_size(struct ice_hw *hw, int new_size);
int ice_vsi_set_dflt_rss_lut(struct ice_vsi *vsi, int req_rss_size);

struct ice_vsi *
ice_vsi_setup(struct ice_pf *pf, struct ice_vsi_cfg_params *params);

void ice_napi_del(struct ice_vsi *vsi);

int ice_vsi_release(struct ice_vsi *vsi);

void ice_vsi_close(struct ice_vsi *vsi);

int ice_vsi_cfg(struct ice_vsi *vsi, struct ice_vsi_cfg_params *params);

int ice_ena_vsi(struct ice_vsi *vsi, bool locked);

void ice_vsi_decfg(struct ice_vsi *vsi);

void ice_dis_vsi(struct ice_vsi *vsi, bool locked);

struct ice_res_tracker *ice_alloc_res_tracker(u16 size);

int ice_free_res(struct ice_res_tracker *res, u16 index, u16 id);

u16 ice_get_free_res_count(struct ice_res_tracker *res);

u16 ice_get_valid_res_count(struct ice_res_tracker *res);

int
ice_get_res(struct ice_pf *pf, struct ice_res_tracker *res, u16 needed, u16 id);

int ice_vsi_rebuild(struct ice_vsi *vsi, u32 flags);

bool ice_is_reset_in_progress(unsigned long *state);
int ice_wait_for_reset(struct ice_pf *pf, unsigned long timeout);

void ice_vsi_dis_irq(struct ice_vsi *vsi);

void ice_vsi_free_irq(struct ice_vsi *vsi);

void ice_vsi_free_rx_rings(struct ice_vsi *vsi);

void ice_vsi_free_tx_rings(struct ice_vsi *vsi);

void ice_vsi_manage_rss_lut(struct ice_vsi *vsi, bool ena);

void ice_vsi_cfg_crc_strip(struct ice_vsi *vsi, bool disable);

void ice_update_tx_ring_stats(struct ice_tx_ring *ring, u64 pkts, u64 bytes);

void ice_update_rx_ring_stats(struct ice_rx_ring *ring, u64 pkts, u64 bytes);

void ice_vsi_cfg_frame_size(struct ice_vsi *vsi);

void
ice_write_qrxflxp_cntxt(struct ice_hw *hw, u16 pf_q, u32 rxdid, u32 prio,
			bool __maybe_unused ena_ts);

#ifdef HAVE_NETPOLL_CONTROLLER
irqreturn_t ice_msix_clean_rings(int __always_unused irq, void *data);
#endif /* HAVE_NETPOLL_CONTROLLER */

void ice_write_intrl(struct ice_q_vector *q_vector, u8 intrl);
void ice_write_itr(struct ice_ring_container *rc, u16 itr);
void ice_set_q_vector_intrl(struct ice_q_vector *q_vector);
void ice_vsi_get_q_vector_q_base(struct ice_vsi *vsi, u16 vector_id, u16 *txq,
				 u16 *rxq);

int ice_vsi_cfg_mac_fltr(struct ice_vsi *vsi, const u8 *macaddr, bool set);
bool ice_is_safe_mode(struct ice_pf *pf);
bool ice_is_aux_ena(struct ice_pf *pf);
bool ice_is_vsi_dflt_vsi(struct ice_vsi *vsi);
int ice_set_dflt_vsi(struct ice_vsi *vsi);
int ice_clear_dflt_vsi(struct ice_vsi *vsi);
int ice_set_min_bw_limit(struct ice_vsi *vsi, u64 min_tx_rate);
int ice_set_max_bw_limit(struct ice_vsi *vsi, u64 max_tx_rate);
int ice_get_link_speed_kbps(struct ice_vsi *vsi);
int ice_get_link_speed_mbps(struct ice_vsi *vsi);
int ice_vsi_update_security(struct ice_vsi *vsi,
			    void (*fill)(struct ice_vsi_ctx *));
#ifdef HAVE_METADATA_PORT_INFO
void ice_vsi_ctx_set_antispoof(struct ice_vsi_ctx *ctx);
void ice_vsi_ctx_clear_antispoof(struct ice_vsi_ctx *ctx);
#endif /* HAVE_METADATA_PORT_INFO */
void ice_vsi_ctx_set_allow_override(struct ice_vsi_ctx *ctx);
void ice_vsi_ctx_clear_allow_override(struct ice_vsi_ctx *ctx);
int ice_check_mtu_valid(struct net_device *netdev, int new_mtu);
int ice_vsi_add_vlan_zero(struct ice_vsi *vsi);
int ice_vsi_del_vlan_zero(struct ice_vsi *vsi);
bool ice_vsi_has_non_zero_vlans(struct ice_vsi *vsi);
u16 ice_vsi_num_non_zero_vlans(struct ice_vsi *vsi);
bool ice_is_feature_supported(struct ice_pf *pf, enum ice_feature f);
void ice_set_feature_support(struct ice_pf *pf, enum ice_feature f);
void ice_clear_feature_support(struct ice_pf *pf, enum ice_feature f);
void ice_init_feature_support(struct ice_pf *pf);
int ice_normalize_cpu_count(int num_cpus);
bool ice_vsi_is_rx_queue_active(struct ice_vsi *vsi);
void ice_vsi_free_rss_global_lut(struct ice_vsi *vsi);
int ice_vsi_alloc_rss_global_lut(struct ice_vsi *vsi);
ssize_t
ice_vsi_alloc_rss_lut(struct ice_hw *hw, struct device *dev,
		      struct ice_vsi *vsi, const char *buf, size_t count);
#endif /* !_ICE_LIB_H_ */
