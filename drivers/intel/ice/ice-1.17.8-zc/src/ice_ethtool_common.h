/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _ICE_ETHTOOL_COMMON_H_
#define _ICE_ETHTOOL_COMMON_H_

void ice_get_strings(struct net_device *netdev, u32 stringset, u8 *data);
int ice_get_sset_count(struct net_device *netdev, int sset);
void ice_get_ethtool_stats(struct net_device *netdev,
			   struct ethtool_stats __always_unused *stats,
			   u64 *data);

#endif /* _ICE_ETHTOOL_COMMON_H_ */
