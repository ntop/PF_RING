/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2023 Intel Corporation */
#ifndef IRDMA_WS_H
#define IRDMA_WS_H

#include "osdep.h"

enum irdma_ws_node_type {
	WS_NODE_TYPE_PARENT,
	WS_NODE_TYPE_LEAF,
};

enum irdma_ws_match_type {
	WS_MATCH_TYPE_VSI,
	WS_MATCH_TYPE_TC,
};

struct irdma_ws_node {
	struct list_head siblings;
	struct list_head child_list_head;
	struct irdma_ws_node *parent;
	u32 l2_sched_node_id;
	u16 index;
	u16 qs_handle;
	u16 vsi_index;
	u8 traffic_class;
	u8 user_pri;
	u8 rel_bw;
	u8 abstraction_layer; /* used for splitting a TC */
	u8 prio_type;
	u8 failing_port;
	u8 active_port;
	bool assign_to_active_port:1;
	bool type_leaf:1;
	bool enable:1;
};

struct irdma_sc_vsi;
int irdma_ws_add(struct irdma_sc_vsi *vsi, u8 user_pri);
void irdma_ws_remove(struct irdma_sc_vsi *vsi, u8 user_pri);
void irdma_ws_reset(struct irdma_sc_vsi *vsi);
void irdma_ws_failover_cmd(struct irdma_sc_vsi *vsi, u8 cmd, u8 failing_port, u8 active_port);
void irdma_ws_move_cmd(struct irdma_sc_vsi *vsi);

#endif /* IRDMA_WS_H */
