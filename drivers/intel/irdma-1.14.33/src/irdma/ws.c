// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2017 - 2023 Intel Corporation */
#include "osdep.h"
#include "hmc.h"
#include "defs.h"
#include "type.h"
#include "protos.h"
#include "virtchnl.h"

#include "ws.h"

#include "iidc.h"

/**
 * irdma_alloc_node - Allocate a WS node and init
 * @vsi: vsi pointer
 * @user_pri: user priority
 * @node_type: Type of node, leaf or parent
 * @parent: parent node pointer
 */
static struct irdma_ws_node *irdma_alloc_node(struct irdma_sc_vsi *vsi,
					      u8 user_pri,
					      enum irdma_ws_node_type node_type,
					      struct irdma_ws_node *parent)
{
	struct irdma_virt_mem ws_mem;
	struct irdma_ws_node *node;
	u16 node_index = 0;

	ws_mem.size = sizeof(*node);
	ws_mem.va = kzalloc(ws_mem.size, GFP_KERNEL);
	if (!ws_mem.va)
		return NULL;

	if (parent || vsi->vm_vf_type == IRDMA_VF_TYPE) {
		node_index = irdma_alloc_ws_node_id(vsi->dev);
		if (node_index == IRDMA_WS_NODE_INVALID) {
			kfree(ws_mem.va);
			return NULL;
		}
	}

	node = ws_mem.va;
	node->index = node_index;
	node->vsi_index = vsi->vsi_idx;
	INIT_LIST_HEAD(&node->child_list_head);
	if (node_type == WS_NODE_TYPE_LEAF) {
		node->type_leaf = true;
		node->traffic_class = vsi->qos[user_pri].traffic_class;
		node->user_pri = user_pri;
		node->rel_bw = vsi->qos[user_pri].rel_bw;
		if (!node->rel_bw)
			node->rel_bw = 1;

		node->prio_type = IRDMA_PRIO_WEIGHTED_RR;
	} else {
		node->rel_bw = 1;
		node->prio_type = IRDMA_PRIO_WEIGHTED_RR;
		node->enable = true;
	}

	node->parent = parent;

	return node;
}

/**
 * irdma_free_node - Free a WS node
 * @vsi: VSI stricture of device
 * @node: Pointer to node to free
 */
static void irdma_free_node(struct irdma_sc_vsi *vsi,
			    struct irdma_ws_node *node)
{
	struct irdma_virt_mem ws_mem;

	if (node->index)
		irdma_free_ws_node_id(vsi->dev, node->index);

	ws_mem.va = node;
	ws_mem.size = sizeof(*node);
	kfree(ws_mem.va);
}

/**
 * irdma_ws_cqp_cmd - Post CQP work scheduler node cmd
 * @vsi: vsi pointer
 * @node: pointer to node
 * @cmd: add, remove or modify
 * @qs_handle: Pointer to store the qs_handle for a leaf node
 */
static int irdma_ws_cqp_cmd(struct irdma_sc_vsi *vsi,
			    struct irdma_ws_node *node, u8 cmd, u16 *qs_handle)
{
	struct irdma_ws_node_info node_info = {};

	node_info.id = node->index;
	node_info.vsi = node->vsi_index;
	if (node->parent)
		node_info.parent_id = node->parent->index;
	else
		node_info.parent_id = node_info.id;

	node_info.weight = node->rel_bw;
	node_info.tc = node->traffic_class;
	node_info.prio_type = node->prio_type;
	node_info.type_leaf = node->type_leaf;
	node_info.failing_port = node->failing_port;
	node_info.active_port = node->active_port;
	node_info.assign_to_active_port = node->assign_to_active_port;
	node_info.enable = node->enable;
	if (irdma_cqp_ws_node_cmd(vsi->dev, cmd, &node_info)) {
		ibdev_dbg(to_ibdev(vsi->dev), "WS: CQP WS CMD failed\n");
		return -ENOMEM;
	}

	if (node->type_leaf && cmd == IRDMA_OP_WS_ADD_NODE && qs_handle)
		*qs_handle = node_info.qs_handle;

	return 0;
}

/**
 * ws_find_node - Find SC WS node based on VSI id or TC
 * @parent: parent node of First VSI or TC node
 * @match_val: value to match
 * @type: match type VSI/TC
 */
static struct irdma_ws_node *ws_find_node(struct irdma_ws_node *parent,
					  u16 match_val,
					  enum irdma_ws_match_type type)
{
	struct irdma_ws_node *node;

	switch (type) {
	case WS_MATCH_TYPE_VSI:
		list_for_each_entry(node, &parent->child_list_head, siblings) {
			if (node->vsi_index == match_val)
				return node;
		}
		break;
	case WS_MATCH_TYPE_TC:
		list_for_each_entry(node, &parent->child_list_head, siblings) {
			if (node->traffic_class == match_val)
				return node;
		}
		break;
	default:
		break;
	}

	return NULL;
}

/**
 * irdma_ws_in_use - Checks to see if a leaf node is in use
 * @vsi: vsi pointer
 * @user_pri: user priority
 */
static bool irdma_ws_in_use(struct irdma_sc_vsi *vsi, u8 user_pri)
{
	int i;

	mutex_lock(&vsi->qos[user_pri].qos_mutex);
	if (!list_empty(&vsi->qos[user_pri].qplist)) {
		mutex_unlock(&vsi->qos[user_pri].qos_mutex);
		return true;
	}

	/* Check if the qs handle associated with the given user priority
	 * is in use by any other user priority. If so, nothing left to do
	 */
	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; i++) {
		if (vsi->qos[i].qs_handle[0] == vsi->qos[user_pri].qs_handle[0] &&
		    !list_empty(&vsi->qos[i].qplist)) {
			mutex_unlock(&vsi->qos[user_pri].qos_mutex);
			return true;
		}
	}
	mutex_unlock(&vsi->qos[user_pri].qos_mutex);

	return false;
}

static void irdma_lag_setup_tc_node(struct irdma_sc_vsi *vsi,
				    struct irdma_ws_node *tc_node,
				    bool first_node)
{
	tc_node->assign_to_active_port = true;
	if (first_node) {
		/* Default first TC node to primary port unless only secondary port is up */
		if ((vsi->lag_port_bitmap & IIDC_RDMA_BOTH_PORT) ==
		    IIDC_RDMA_SECONDARY_PORT) {
			tc_node->active_port =
				vsi->lag_ports[IRDMA_LAG_SECONDARY_IDX];
			if (tc_node->active_port == IIDC_RDMA_INVALID_PORT)
				tc_node->active_port =
				vsi->lag_ports[IRDMA_LAG_PRIMARY_IDX];
			vsi->primary_port_migrated = true;
		} else {
			tc_node->active_port =
				vsi->lag_ports[IRDMA_LAG_PRIMARY_IDX];
			if (tc_node->active_port == IIDC_RDMA_INVALID_PORT)
				tc_node->active_port =
				vsi->lag_ports[IRDMA_LAG_SECONDARY_IDX];
			vsi->primary_port_migrated = false;
		}
	} else {
		/* If secondary port is not active default to primary if it's active */
		if ((vsi->lag_port_bitmap & IIDC_RDMA_BOTH_PORT) ==
		    IIDC_RDMA_SECONDARY_PORT) {
			tc_node->active_port =
				vsi->lag_ports[IRDMA_LAG_PRIMARY_IDX];
			if (tc_node->active_port == IIDC_RDMA_INVALID_PORT)
				tc_node->active_port =
				vsi->lag_ports[IRDMA_LAG_SECONDARY_IDX];
			vsi->secondary_port_migrated = true;
		} else {
			tc_node->active_port =
				vsi->lag_ports[IRDMA_LAG_SECONDARY_IDX];
			if (tc_node->active_port == IIDC_RDMA_INVALID_PORT)
				tc_node->active_port =
				vsi->lag_ports[IRDMA_LAG_PRIMARY_IDX];
			vsi->secondary_port_migrated = false;
		}
	}
}

static void irdma_add_node_id(u16 *node_ids, u16 idx)
{
	int i;

	/* Save the node ID in an available slot indicated by 0 */
	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; i++) {
		if (!node_ids[i]) {
			node_ids[i] = idx;
			return;
		}
	}
}

static void irdma_remove_node_id(u16 *node_ids, u16 idx)
{
	int i;

	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; i++) {
		if (node_ids[i] == idx) {
			node_ids[i] = 0;
			return;
		}
	}
}

/**
 * irdma_remove_leaf - Remove leaf node unconditionally
 * @vsi: vsi pointer
 * @user_pri: user priority
 */
static void irdma_remove_leaf(struct irdma_sc_vsi *vsi, u8 user_pri)
{
	struct irdma_ws_node *ws_tree_root, *vsi_node, *tc_node;
	struct irdma_ws_node *tc_node2 = NULL;
	u16 qs_handle;
	int i;

	qs_handle = vsi->qos[user_pri].qs_handle[0];
	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; i++) {
		if (vsi->qos[i].qs_handle[0] == qs_handle)
			vsi->qos[i].valid = false;
	}

	if (!vsi->dev->privileged) {
		int ret;

		ret = irdma_vchnl_req_manage_ws_node(vsi->dev, false, user_pri,
						     NULL);
		if (ret)
			ibdev_dbg(to_ibdev(vsi->dev),
				  "VIRT: Send message failed ret = %d \n",
				  ret);

		return;
	}

	ws_tree_root = vsi->dev->ws_tree_root;
	if (!ws_tree_root)
		return;

	vsi_node = ws_find_node(ws_tree_root, vsi->vsi_idx,
				WS_MATCH_TYPE_VSI);
	if (!vsi_node)
		return;

	tc_node = ws_find_node(vsi_node,
			       vsi->qos[user_pri].traffic_class,
			       WS_MATCH_TYPE_TC);
	if (!tc_node)
		return;

	list_del(&tc_node->siblings);
	if (vsi->lag_aa) {
		tc_node2 = ws_find_node(vsi_node,
					vsi->qos[user_pri].traffic_class,
					WS_MATCH_TYPE_TC);
		if (!tc_node2)
			return;
		pr_info("%s: Second TC node found. Removing.\n", __func__);
		list_del(&tc_node2->siblings);
		irdma_ws_cqp_cmd(vsi, tc_node2, IRDMA_OP_WS_DELETE_NODE, NULL);

		irdma_remove_node_id(vsi->primary_port_node_ids, tc_node->index);
		irdma_remove_node_id(vsi->secondary_port_node_ids, tc_node2->index);
	}
	irdma_ws_cqp_cmd(vsi, tc_node, IRDMA_OP_WS_DELETE_NODE, NULL);

	vsi->unregister_qset(vsi, tc_node2, tc_node);
	irdma_free_node(vsi, tc_node);
	if (tc_node2)
		irdma_free_node(vsi, tc_node2);
	/* Check if VSI node can be freed */
	if (list_empty(&vsi_node->child_list_head)) {
		irdma_ws_cqp_cmd(vsi, vsi_node, IRDMA_OP_WS_DELETE_NODE, NULL);
		list_del(&vsi_node->siblings);
		irdma_free_node(vsi, vsi_node);
		/* Free head node there are no remaining VSI nodes */
		if (list_empty(&ws_tree_root->child_list_head)) {
			irdma_ws_cqp_cmd(vsi, ws_tree_root,
					 IRDMA_OP_WS_DELETE_NODE, NULL);
			irdma_free_node(vsi, ws_tree_root);
			vsi->dev->ws_tree_root = NULL;
		}
	}
}

static int irdma_enable_leaves(struct irdma_sc_vsi *vsi,
			       struct irdma_ws_node *tc_node1,
			       struct irdma_ws_node *tc_node2)
{
	int ret;

	ret = vsi->register_qset(vsi, tc_node1, tc_node2);
	if (ret)
		return ret;

	tc_node1->enable = true;
	ret = irdma_ws_cqp_cmd(vsi, tc_node1, IRDMA_OP_WS_MODIFY_NODE, NULL);
	if (ret)
		goto enable_err;
	if (tc_node2) {
		tc_node2->enable = true;
		ret = irdma_ws_cqp_cmd(vsi, tc_node2, IRDMA_OP_WS_MODIFY_NODE, NULL);
		if (ret)
			goto enable_err;
	}
	return 0;

enable_err:
	vsi->unregister_qset(vsi, tc_node1, tc_node2);

	return ret;
}

static struct irdma_ws_node *irdma_add_leaf_node(struct irdma_sc_vsi *vsi,
						 struct irdma_ws_node *vsi_node,
						 u8 user_pri, u16 traffic_class)
{
	struct irdma_ws_node *tc_node =
		irdma_alloc_node(vsi, user_pri, WS_NODE_TYPE_LEAF, vsi_node);
	struct irdma_ws_node *tc_node2 = NULL;
	int i, ret = 0;

	if (!tc_node)
		return NULL;
	if (vsi->lag_aa)
		irdma_lag_setup_tc_node(vsi, tc_node, true);
	ret = irdma_ws_cqp_cmd(vsi, tc_node, IRDMA_OP_WS_ADD_NODE, &tc_node->qs_handle);
	if (ret) {
		irdma_free_node(vsi, tc_node);
		return NULL;
	}
	vsi->qos[tc_node->user_pri].qs_handle[0] = tc_node->qs_handle;

	list_add(&tc_node->siblings, &vsi_node->child_list_head);

	if (vsi->lag_aa) {
		irdma_add_node_id(vsi->primary_port_node_ids, tc_node->index);
		pr_info("%s: First TC node ID=%d, using active_port = %d\n",
			__func__, tc_node->index, tc_node->active_port);
		tc_node2 = irdma_alloc_node(vsi, user_pri, WS_NODE_TYPE_LEAF,
					   vsi_node);
		if (!tc_node2) {
			irdma_remove_node_id(vsi->primary_port_node_ids, tc_node->index);
			goto reg_err;
		}
		irdma_lag_setup_tc_node(vsi, tc_node2, false);
		ret = irdma_ws_cqp_cmd(vsi, tc_node2, IRDMA_OP_WS_ADD_NODE,
				       &tc_node2->qs_handle);
		if (ret) {
			irdma_remove_node_id(vsi->primary_port_node_ids,
					     tc_node->index);
			irdma_free_node(vsi, tc_node2);
			tc_node2 = NULL;
			goto reg_err;
		}
		vsi->qos[tc_node2->user_pri].qs_handle[1] = tc_node2->qs_handle;
		irdma_add_node_id(vsi->secondary_port_node_ids, tc_node2->index);
		pr_info("%s: Second TC node ID=%d, using active_port = %d\n",
			__func__, tc_node2->index, tc_node2->active_port);

		list_add(&tc_node2->siblings, &vsi_node->child_list_head);
	}

	ret = irdma_enable_leaves(vsi, tc_node, tc_node2);
	if (ret) {
		irdma_remove_node_id(vsi->primary_port_node_ids, tc_node->index);
		if (tc_node2)
			irdma_remove_node_id(vsi->secondary_port_node_ids,
					     tc_node2->index);
		goto reg_err;
	}

	/*
	 * Iterate through other UPs and update the QS handle if they have
	 * a matching traffic class.
	 */
	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; i++) {
		if (vsi->qos[i].traffic_class == traffic_class) {
			vsi->qos[i].qs_handle[0] = tc_node->qs_handle;
			vsi->qos[i].l2_sched_node_id[0] =
				tc_node->l2_sched_node_id;
			if (tc_node2) {
				vsi->qos[i].qs_handle[1] = tc_node2->qs_handle;
				vsi->qos[i].l2_sched_node_id[1] =
					tc_node2->l2_sched_node_id;
			}
			vsi->qos[i].valid = true;
		}
	}
	return tc_node;

reg_err:
	if (tc_node2) {
		irdma_ws_cqp_cmd(vsi, tc_node2, IRDMA_OP_WS_DELETE_NODE, NULL);
		list_del(&tc_node2->siblings);
		irdma_free_node(vsi, tc_node2);
	}
	irdma_ws_cqp_cmd(vsi, tc_node, IRDMA_OP_WS_DELETE_NODE, NULL);
	list_del(&tc_node->siblings);
	irdma_free_node(vsi, tc_node);

	return NULL;
}

/**
 * irdma_ws_add - Build work scheduler tree, set RDMA qs_handle
 * @vsi: vsi pointer
 * @user_pri: user priority
 */
int irdma_ws_add(struct irdma_sc_vsi *vsi, u8 user_pri)
{
	struct irdma_ws_node *ws_tree_root;
	struct irdma_ws_node *vsi_node;
	struct irdma_ws_node *tc_node;
	u16 traffic_class;
	int ret = 0;

	mutex_lock(&vsi->dev->ws_mutex);
	if (vsi->tc_change_pending) {
		ret = -EBUSY;
		goto exit;
	}

	if (vsi->qos[user_pri].valid)
		goto exit;

	if (!vsi->dev->privileged) {
		u16 vf_qs_handle;

		ret = irdma_vchnl_req_manage_ws_node(vsi->dev, true, user_pri,
						     &vf_qs_handle);
		if (ret) {
			ibdev_dbg(to_ibdev(vsi->dev),
				  "VIRT: Send message failed ret = %d\n", ret);
			goto exit;
		}

		vsi->qos[user_pri].qs_handle[0] = vf_qs_handle;
		vsi->qos[user_pri].valid = true;
		goto exit;
	}

	ws_tree_root = vsi->dev->ws_tree_root;
	if (!ws_tree_root) {
		ws_tree_root = irdma_alloc_node(vsi, user_pri,
						WS_NODE_TYPE_PARENT, NULL);
		if (!ws_tree_root) {
			ret = -ENOMEM;
			goto exit;
		}
		ibdev_dbg(to_ibdev(vsi->dev), "WS: Creating root node = %d\n",
			  ws_tree_root->index);

		ret = irdma_ws_cqp_cmd(vsi, ws_tree_root, IRDMA_OP_WS_ADD_NODE,
				       NULL);
		if (ret) {
			irdma_free_node(vsi, ws_tree_root);
			goto exit;
		}

		vsi->dev->ws_tree_root = ws_tree_root;
	}

	/* Find a second tier node that matches the VSI */
	vsi_node = ws_find_node(ws_tree_root, vsi->vsi_idx,
				WS_MATCH_TYPE_VSI);

	/* If VSI node doesn't exist, add one */
	if (!vsi_node) {
		ibdev_dbg(to_ibdev(vsi->dev),
			  "WS: Node not found matching VSI %d\n",
			  vsi->vsi_idx);
		vsi_node = irdma_alloc_node(vsi, user_pri, WS_NODE_TYPE_PARENT,
					    ws_tree_root);
		if (!vsi_node) {
			ret = -ENOMEM;
			goto vsi_add_err;
		}

		ret = irdma_ws_cqp_cmd(vsi, vsi_node, IRDMA_OP_WS_ADD_NODE,
				       NULL);
		if (ret) {
			irdma_free_node(vsi, vsi_node);
			goto vsi_add_err;
		}

		list_add(&vsi_node->siblings, &ws_tree_root->child_list_head);
	}

	ibdev_dbg(to_ibdev(vsi->dev),
		  "WS: Using node %d which represents VSI %d\n",
		  vsi_node->index, vsi->vsi_idx);
	traffic_class = vsi->qos[user_pri].traffic_class;
	tc_node = ws_find_node(vsi_node, traffic_class,
			       WS_MATCH_TYPE_TC);
	if (!tc_node) {
		/* Add leaf node */
		ibdev_dbg(to_ibdev(vsi->dev),
			  "WS: Node not found matching VSI %d and TC %d\n",
			  vsi->vsi_idx, traffic_class);
		tc_node = irdma_add_leaf_node(vsi, vsi_node, user_pri,
					      traffic_class);
		if (!tc_node) {
			ret = -ENOMEM;
			goto leaf_add_err;
		}
	}
	ibdev_dbg(to_ibdev(vsi->dev),
		  "WS: Using node %d which represents VSI %d TC %d\n",
		  tc_node->index, vsi->vsi_idx, traffic_class);
	goto exit;

leaf_add_err:
	if (list_empty(&vsi_node->child_list_head)) {
		if (irdma_ws_cqp_cmd(vsi, vsi_node, IRDMA_OP_WS_DELETE_NODE,
				     NULL))
			goto exit;
		list_del(&vsi_node->siblings);
		irdma_free_node(vsi, vsi_node);
	}

vsi_add_err:
	/* Free head node there are no remaining VSI nodes */
	if (list_empty(&ws_tree_root->child_list_head)) {
		irdma_ws_cqp_cmd(vsi, ws_tree_root, IRDMA_OP_WS_DELETE_NODE,
				 NULL);
		vsi->dev->ws_tree_root = NULL;
		irdma_free_node(vsi, ws_tree_root);
	}

exit:
	mutex_unlock(&vsi->dev->ws_mutex);
	return ret;
}

/**
 * irdma_ws_remove - Free WS scheduler node, update WS tree
 * @vsi: vsi pointer
 * @user_pri: user priority
 */
void irdma_ws_remove(struct irdma_sc_vsi *vsi, u8 user_pri)
{
	mutex_lock(&vsi->dev->ws_mutex);
	if (irdma_ws_in_use(vsi, user_pri))
		goto exit;
	irdma_remove_leaf(vsi, user_pri);
exit:
	mutex_unlock(&vsi->dev->ws_mutex);
}

/**
 * irdma_ws_reset - Reset entire WS tree
 * @vsi: vsi pointer
 */
void irdma_ws_reset(struct irdma_sc_vsi *vsi)
{
	u8 i;

	mutex_lock(&vsi->dev->ws_mutex);
	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; ++i)
		irdma_remove_leaf(vsi, i);
	mutex_unlock(&vsi->dev->ws_mutex);
}

static u8 irdma_move_nodes(u16 *dest_nodes, u16 *src_nodes)
{
	int i;
	u8 num_nodes = 0;

	for (i = 0; i < IRDMA_MAX_USER_PRIORITY; ++i) {
		if (src_nodes[i])
			dest_nodes[num_nodes++] = src_nodes[i];
	}
	return num_nodes;
}

/**
 * irdma_ws_move_cmd - Perform Scheduler Move CQP command
 * @vsi: vsi pointer
 */
void irdma_ws_move_cmd(struct irdma_sc_vsi *vsi)
{
	struct irdma_ws_move_node_info move_ws_node = {};
	int i;

	mutex_lock(&vsi->dev->ws_mutex);
	if ((vsi->lag_port_bitmap & IIDC_RDMA_BOTH_PORT) ==
	    IIDC_RDMA_BOTH_PORT) { /* if both ports are active */
		if (vsi->primary_port_migrated) { /* if primary port was in failed state */
			vsi->primary_port_migrated = false;
			/* move all primary port nodes back to the primary port */
			move_ws_node.target_port =
				vsi->lag_ports[IRDMA_LAG_PRIMARY_IDX];
			move_ws_node.num_nodes =
				irdma_move_nodes(move_ws_node.node_id,
						 vsi->primary_port_node_ids);
			pr_info("%s: both ports active. move primary port node_ids back to target_port=%d, num_nodes = %d, nodes:\n",
				__func__, move_ws_node.target_port,
				move_ws_node.num_nodes);
		} else if (vsi->secondary_port_migrated) { /* secondary port was in failed state */
			vsi->secondary_port_migrated = false;
			/* move all secondary port nodes back to the secondary port */
			move_ws_node.target_port =
				vsi->lag_ports[IRDMA_LAG_SECONDARY_IDX];
			move_ws_node.num_nodes =
				irdma_move_nodes(move_ws_node.node_id,
						 vsi->secondary_port_node_ids);
			pr_info("%s: both ports active. move secondary port node_ids back to target_port=%d, num_nodes = %d, nodes:\n",
				__func__, move_ws_node.target_port,
				move_ws_node.num_nodes);

		}
		for (i = 0; i < move_ws_node.num_nodes; ++i)
			pr_info("%d\n",  move_ws_node.node_id[i]);
		move_ws_node.resume_traffic = true;
		if (irdma_cqp_ws_move_cmd(vsi->dev, &move_ws_node))
			ibdev_dbg(to_ibdev(vsi->dev),
				  "WS: CQP WS MOVE CMD failed, both ports up case\n");
	} else { /* if only one or none are active */
		if (vsi->lag_port_bitmap == IIDC_RDMA_SECONDARY_PORT) {	/* if only secodary port is active */
			move_ws_node.target_port =
				vsi->lag_ports[IRDMA_LAG_SECONDARY_IDX];
			vsi->secondary_port_migrated = false;
			vsi->primary_port_migrated = true;
			/* move all primary port nodes to secondary */
			move_ws_node.num_nodes =
				irdma_move_nodes(move_ws_node.node_id,
						 vsi->primary_port_node_ids);
			/* move all secodary port nodes back to secodary port */
			move_ws_node.num_nodes =
				irdma_move_nodes(move_ws_node.node_id,
						 vsi->secondary_port_node_ids);
			pr_info("%s: only secondary port is active. move all node_ids to target_port=%d, num_nodes = %d, nodes:\n",
				__func__, move_ws_node.target_port,
				move_ws_node.num_nodes);
		} else { /* only primary port is active or none are active, move everything to primary port */
			move_ws_node.target_port =
				vsi->lag_ports[IRDMA_LAG_PRIMARY_IDX];
			vsi->secondary_port_migrated = true;
			vsi->primary_port_migrated = false;
			/* move all primary port nodes back to primary port */
			move_ws_node.num_nodes =
				irdma_move_nodes(move_ws_node.node_id,
						 vsi->primary_port_node_ids);
			/* move all secondary port nodes to primary port */
			move_ws_node.num_nodes =
				irdma_move_nodes(move_ws_node.node_id,
						 vsi->secondary_port_node_ids);
			pr_info("%s: only primary port is active. move all node_ids to target_port=%d, num_nodes = %d, nodes:\n",
				__func__, move_ws_node.target_port,
				move_ws_node.num_nodes);
		}
		move_ws_node.resume_traffic = true;
		for (i = 0; i < move_ws_node.num_nodes; ++i)
			pr_info("%d\n", move_ws_node.node_id[i]);

		if (irdma_cqp_ws_move_cmd(vsi->dev, &move_ws_node))
			ibdev_dbg(to_ibdev(vsi->dev),
				  "WS: CQP WS MOVE CMD failed\n");
	}

	mutex_unlock(&vsi->dev->ws_mutex);
}

/**
 * irdma_ws_failover_cmd - Perform failover CQP command
 * @vsi: vsi pointer
 * @cmd: Failover Start or Complete cmd
 * @failing_port: Port number that is failing
 * @active_port: Port number to become active
 */
void irdma_ws_failover_cmd(struct irdma_sc_vsi *vsi, u8 cmd, u8 failing_port,
			   u8 active_port)
{
	struct irdma_ws_node ws_node;

	mutex_lock(&vsi->dev->ws_mutex);
	if (WARN_ON_ONCE(!vsi->dev->ws_tree_root)) {
		mutex_unlock(&vsi->dev->ws_mutex);
		return;
	}
	ws_node  = *vsi->dev->ws_tree_root;

	ws_node.failing_port = failing_port;
	ws_node.active_port = active_port;
	irdma_ws_cqp_cmd(vsi, &ws_node, cmd, NULL);
	mutex_unlock(&vsi->dev->ws_mutex);
}
