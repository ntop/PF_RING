/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/random.h>
#include "ice.h"
#include "ice_lib.h"
#include "ice_fltr.h"

#define ICE_FW_DUMP_BLK_MAX	0xFFFF
#define ICE_FW_DUMP_DATA_SIZE	4096
#define ICE_FW_DUMP_HDR_SIZE	24
/* dump blk = Cluster header + dump data */
#define ICE_FW_DUMP_BLK_SIZE	(ICE_FW_DUMP_DATA_SIZE + ICE_FW_DUMP_HDR_SIZE)
#define ICE_FW_DUMP_FILENAME	"debug_dump"
#define ICE_FW_DUMP_LAST_IDX	0xFFFFFFFF
#define ICE_FW_DUMP_LAST_ID	0xFF
#define ICE_FW_DUMP_LAST_ID2	0xFFFF

static struct dentry *ice_debugfs_root;

/* create a define that has an extra module that doesn't really exist. this
 * is so we can add a module 'all' to easily enable/disable all the modules
 */
#define ICE_NR_FW_LOG_MODULES (ICE_AQC_FW_LOG_ID_MAX + 1)

/* the ordering in this array is important. it matches the ordering of the
 * values in the FW so the index is the same value as in ice_aqc_fw_logging_mod
 */
static const char * const ice_fwlog_module_string[] = {
	"general",
	"ctrl",
	"link",
	"link_topo",
	"dnl",
	"i2c",
	"sdp",
	"mdio",
	"adminq",
	"hdma",
	"lldp",
	"dcbx",
	"dcb",
	"xlr",
	"nvm",
	"auth",
	"vpd",
	"iosf",
	"parser",
	"sw",
	"scheduler",
	"txq",
	"rsvd",
	"post",
	"watchdog",
	"task_dispatch",
	"mng",
	"synce",
	"health",
	"tsdrv",
	"pfreg",
	"mdlver",
	"all",
};

/* the ordering in this array is important. it matches the ordering of the
 * values in the FW so the index is the same value as in ice_fwlog_level
 */
static const char * const ice_fwlog_level_string[] = {
	"none",
	"error",
	"warning",
	"normal",
	"verbose",
};

/* the order in this array is important. it matches the ordering of the
 * values in the FW so the index is the same value as in ice_fwlog_level
 */
static const char * const ice_fwlog_log_size[] = {
	"128K",
	"256K",
	"512K",
	"1M",
	"2M",
};

/* The ice_cluster_header structure needs to be added to each table dump
 * the header is contains 6 words each of 4byte(32 bits) in size
 * The structe contains following fields
 *
 * Cluster ID - The cluster ID of the tables
 * Table ID - The table ID of the data dump
 * Table Length - Size of the table
 * Current Offset - This value represents the total offset of bytes into
 *		the Table Length defined by Table ID. For the very
 *		first buffer returned for any table, the offset shall be 0.
 * Two (2) Reserved words for future use.
 */
struct ice_cluster_header {
	u32 cluster_id;
	u32 table_id;
	u32 table_len;
	u32 table_offset;
	u32 reserved[2];
};

/**
 * ice_get_last_table_id - get a value that should be used as End of Table
 * @pf: pointer to pf struct
 *
 * Different versions of FW may indicate End Of Table by different value. Read
 * FW capabilities and decide what value to use as End of Table.
 */
static u16 ice_get_last_table_id(struct ice_pf *pf)
{
	if (pf->hw.func_caps.common_cap.next_cluster_id_support ||
	    pf->hw.dev_caps.common_cap.next_cluster_id_support)
		return ICE_FW_DUMP_LAST_ID2;
	else
		return ICE_FW_DUMP_LAST_ID;
}

/**
 * ice_debugfs_fw_dump - send request to FW to dump cluster and save to file
 * @pf: pointer to pf struct
 * @cluster_id: number or FW cluster to be dumped
 * @desc_blob: pointer to already allocated debugfs_blob_wrapper
 * @read_all_clusters: if true dump all clusters
 *
 * Create FW configuration binary snapshot. Repeatedly send AQ requests to dump
 * FW cluster, FW responds in 4KB blocks and sets new values for tbl_id
 * and blk_idx. Repeat until all tables in given cluster were read.
 */
static void
ice_debugfs_fw_dump(struct ice_pf *pf, u16 cluster_id,
		    struct debugfs_blob_wrapper *desc_blob,
		    bool read_all_clusters)
{
	u16 buf_len, next_tbl_id, next_cluster_id, last_tbl_id, tbl_id = 0;
	u32 next_blk_idx, blk_idx = 0, ntw = 0, ctw = 0, offset = 0;
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_cluster_header header = {};
	u8 *vblk = desc_blob->data;
	int i;

	last_tbl_id = ice_get_last_table_id(pf);

	for (i = 0; i < ICE_FW_DUMP_BLK_MAX; i++) {
		int res;

		/* Skip the header bytes */
		ntw += sizeof(struct ice_cluster_header);

		res = ice_aq_get_internal_data(&pf->hw, cluster_id,
					       tbl_id, blk_idx, vblk + ntw,
					       ICE_FW_DUMP_DATA_SIZE,
					       &buf_len, &next_cluster_id,
					       &next_tbl_id, &next_blk_idx,
					       NULL);
		if (res) {
			dev_err(dev, "Internal FW error %d while dumping cluster %d\n",
				res, cluster_id);
			ntw = 0;
			break;
		}
		ntw += buf_len;

		header.cluster_id = cluster_id;
		header.table_id = tbl_id;
		header.table_len = buf_len;
		header.table_offset = offset;

		memcpy(vblk + ctw, &header, sizeof(header));
		ctw = ntw;
		memset(&header, 0, sizeof(header));

		offset += buf_len;

		if (blk_idx == next_blk_idx)
			blk_idx = ICE_FW_DUMP_LAST_IDX;
		else
			blk_idx = next_blk_idx;

		if (blk_idx != ICE_FW_DUMP_LAST_IDX)
			continue;

		blk_idx = 0;
		offset = 0;

		if (next_cluster_id == ICE_FW_DUMP_LAST_ID2)
			break;

		if (next_tbl_id != last_tbl_id)
			tbl_id = next_tbl_id;

		/* End of cluster */
		if (cluster_id != next_cluster_id) {
			if (read_all_clusters) {
				dev_info(dev, "All FW clusters dump - cluster %d appended",
					 cluster_id);
				cluster_id = next_cluster_id;
				tbl_id = 0;
			} else {
				break;
			}
		}
	}
	desc_blob->size = (unsigned long)ntw;

	if (read_all_clusters)
		dev_info(dev, "Created FW dump of all available clusters in file %s\n",
			 ICE_FW_DUMP_FILENAME);
	else
		dev_info(dev, "Created FW dump of cluster %d in file %s\n",
			 cluster_id, ICE_FW_DUMP_FILENAME);
}

/**
 * dump_cluster_id_read - show currently set FW cluster id to dump
 * @file: kernel file struct
 * @buf: user space buffer to fill with correct data
 * @len: buf's length
 * @offset: current position in buf
 */
static ssize_t dump_cluster_id_read(struct file *file, char __user *buf,
				    size_t len, loff_t *offset)
{
	struct ice_pf *pf = file->private_data;
	char temp_buf[11];
	int ret;

	ret = snprintf(temp_buf, sizeof(temp_buf), "%u\n",
		       pf->fw_dump_cluster_id);

	return simple_read_from_buffer(buf, len, offset, temp_buf, ret);
}

/**
 * dump_cluster_id_write - set FW cluster id to dump
 * @file: kernel file struct
 * @buf: user space buffer containing data to read
 * @len: buf's length
 * @offset: current position in buf
 */
static ssize_t dump_cluster_id_write(struct file *file, const char __user *buf,
				     size_t len, loff_t *offset)
{
	static struct debugfs_blob_wrapper *desc_blob;
	struct ice_pf *pf = file->private_data;
	bool read_all_clusters = false;
	const struct dentry *pfile;
	char kbuf[11] = { 0 };
	int bytes_read;
	u16 cluster_id;

	bytes_read = simple_write_to_buffer(kbuf, sizeof(kbuf), offset, buf,
					    len);
	if (bytes_read < 0)
		return -EINVAL;

	if (bytes_read == 1 && kbuf[0] == '\n') {
		cluster_id = 0;
		read_all_clusters = true;
	} else {
		int err = kstrtou16(kbuf, 10, &cluster_id);
		if (err)
			return err;
	}

	if (!pf->ice_fw_dump_blob) {
		desc_blob = kzalloc(sizeof(*desc_blob), GFP_KERNEL);
		if (!desc_blob)
			return -ENOMEM;

		desc_blob->data = vmalloc(ICE_FW_DUMP_BLK_MAX *
					  ICE_FW_DUMP_BLK_SIZE);
		if (!desc_blob->data) {
			kfree(desc_blob);
			return -ENOMEM;
		}

		pf->ice_fw_dump_blob = desc_blob;
	}

	ice_debugfs_fw_dump(pf, cluster_id, desc_blob, read_all_clusters);

	debugfs_lookup_and_remove(ICE_FW_DUMP_FILENAME, pf->ice_debugfs_fw);
	pfile = debugfs_create_blob(ICE_FW_DUMP_FILENAME, 0400,
				    pf->ice_debugfs_fw, desc_blob);
	if (!pfile)
		return -ENODEV;

	pf->fw_dump_cluster_id = cluster_id;

	return bytes_read;
}

static const struct file_operations dump_cluster_id_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = dump_cluster_id_read,
	.write = dump_cluster_id_write,
};

static void ice_dump_pf(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);

	dev_info(dev, "pf struct:\n");
	dev_info(dev, "\tmax_pf_txqs = %d\n", pf->max_pf_txqs);
	dev_info(dev, "\tmax_pf_rxqs = %d\n", pf->max_pf_rxqs);
	dev_info(dev, "\tnum_alloc_vsi = %d\n", pf->num_alloc_vsi);
	dev_info(dev, "\tnum_lan_tx = %d\n", pf->num_lan_tx);
	dev_info(dev, "\tnum_lan_rx = %d\n", pf->num_lan_rx);
	dev_info(dev, "\tnum_avail_tx = %d\n", ice_get_avail_txq_count(pf));
	dev_info(dev, "\tnum_avail_rx = %d\n", ice_get_avail_rxq_count(pf));
	dev_info(dev, "\tmsix total = %d\n",
		 pf->msix.eth + pf->msix.rdma + pf->msix.misc + pf->msix.vf);
	dev_info(dev, "\tmsix.eth = %d\n", pf->msix.eth);
	dev_info(dev, "\tmsix.misc = %d\n", pf->msix.misc);
#ifdef HAVE_DEVLINK_RELOAD_ACTION_AND_LIMIT
	dev_info(dev, "\tmsix.vf occ = %lld\n", ice_sriov_get_vf_used_msix(pf));
	dev_info(dev, "\tmsix.vf free = %lld\n",
		 pf->msix.vf - ice_sriov_get_vf_used_msix(pf));
#endif
	dev_info(dev, "\tmsix.rdma = %d\n", pf->msix.rdma);
	dev_info(dev, "\trdma_base_vector = %d\n", pf->rdma_base_vector);
#ifdef HAVE_NDO_DFWD_OPS
	dev_info(dev, "\tnum_macvlan = %d\n", pf->num_macvlan);
	dev_info(dev, "\tmax_num_macvlan = %d\n", pf->max_num_macvlan);
#endif /* HAVE_NDO_DFWD_OPS */
#ifdef HAVE_PCI_MSIX_ALLOC_IRQ_AT
	dev_info(dev, "\tirq_tracker.num_entries = %d\n",
		 pf->irq_tracker.num_entries);
#else
	dev_info(dev, "\tirq_tracker->num_entries = %d\n",
		 pf->irq_tracker->num_entries);
	dev_info(dev, "\tirq_tracker->end = %d\n", pf->irq_tracker->end);
	dev_info(dev, "\tirq_tracker valid count = %d\n",
		 ice_get_valid_res_count(pf->irq_tracker));
#endif /* HAVE_PCI_MSIX_ALLOC_IRQ_AT */
	dev_info(dev, "\tsriov_base_vector = %d\n", pf->sriov_base_vector);
	dev_info(dev, "\tnum_alloc_vfs = %d\n", ice_get_num_vfs(pf));
	dev_info(dev, "\tnum_qps_per_vf = %d\n", pf->vfs.num_qps_per);
	dev_info(dev, "\tnum_msix_per_vf = %d\n", pf->vfs.num_msix_per);
}

static void ice_dump_pf_vsi_list(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	u16 i;

	ice_for_each_vsi(pf, i) {
		struct ice_vsi *vsi = pf->vsi[i];

		if (!vsi)
			continue;

		dev_info(dev, "vsi[%d]:\n", i);
		dev_info(dev, "\tvsi = %p\n", vsi);
		dev_info(dev, "\tvsi_num = %d\n", vsi->vsi_num);
		dev_info(dev, "\ttype = %s\n", ice_vsi_type_str(vsi->type));
		if (vsi->type == ICE_VSI_VF)
			dev_info(dev, "\tvf_id = %d\n", vsi->vf->vf_id);
		dev_info(dev, "\tback = %p\n", vsi->back);
		dev_info(dev, "\tnetdev = %p\n", vsi->netdev);
		dev_info(dev, "\tmax_frame = %d\n", vsi->max_frame);
		dev_info(dev, "\trx_buf_len = %d\n", vsi->rx_buf_len);
		dev_info(dev, "\tnum_txq = %d\n", vsi->num_txq);
		dev_info(dev, "\tnum_rxq = %d\n", vsi->num_rxq);
		dev_info(dev, "\treq_txq = %d\n", vsi->req_txq);
		dev_info(dev, "\treq_rxq = %d\n", vsi->req_rxq);
		dev_info(dev, "\talloc_txq = %d\n", vsi->alloc_txq);
		dev_info(dev, "\talloc_rxq = %d\n", vsi->alloc_rxq);
		dev_info(dev, "\tnum_rx_desc = %d\n", vsi->num_rx_desc);
		dev_info(dev, "\tnum_tx_desc = %d\n", vsi->num_tx_desc);
		dev_info(dev, "\tnum_vlan = %d\n", vsi->num_vlan);
	}
}

/**
 * ice_dump_pf_fdir - output Flow Director stats to dmesg log
 * @pf: pointer to PF to get Flow Director HW stats for.
 */
static void ice_dump_pf_fdir(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	u16 pf_guar_pool = 0;
	u32 dev_fltr_size;
	u32 dev_fltr_cnt;
	u32 pf_fltr_cnt;
	u16 i;

	pf_fltr_cnt = rd32(hw, PFQF_FD_CNT);
	dev_fltr_cnt = rd32(hw, GLQF_FD_CNT);
	dev_fltr_size = rd32(hw, GLQF_FD_SIZE);

	ice_for_each_vsi(pf, i) {
		struct ice_vsi *vsi = pf->vsi[i];

		if (!vsi)
			continue;

		pf_guar_pool += vsi->num_gfltr;
	}

	dev_info(dev, "Flow Director filter usage:\n");
	dev_info(dev, "\tPF guaranteed used = %ld\n",
		 (pf_fltr_cnt & PFQF_FD_CNT_FD_GCNT_M_BY_MAC(hw)) >>
		 PFQF_FD_CNT_FD_GCNT_S);
	dev_info(dev, "\tPF best_effort used = %ld\n",
		 (pf_fltr_cnt & PFQF_FD_CNT_FD_BCNT_M_BY_MAC(hw)) >>
		 PFQF_FD_CNT_FD_BCNT_S);
	dev_info(dev, "\tdevice guaranteed used = %ld\n",
		 (dev_fltr_cnt & GLQF_FD_CNT_FD_GCNT_M_BY_MAC(hw)) >>
		 GLQF_FD_CNT_FD_GCNT_S);
	dev_info(dev, "\tdevice best_effort used = %ld\n",
		 (dev_fltr_cnt & GLQF_FD_CNT_FD_BCNT_M_BY_MAC(hw)) >>
		 GLQF_FD_CNT_FD_BCNT_S);
	dev_info(dev, "\tPF guaranteed pool = %d\n", pf_guar_pool);
	dev_info(dev, "\tdevice guaranteed pool = %ld\n",
		 (dev_fltr_size & GLQF_FD_SIZE_FD_GSIZE_M_BY_MAC(hw)) >>
		 GLQF_FD_SIZE_FD_GSIZE_S);
	dev_info(dev, "\tdevice best_effort pool = %d\n",
		 hw->func_caps.fd_fltr_best_effort);
}

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
/**
 * ice_dump_rclk_status - print the PHY recovered clock status
 * @pf: pointer to PF
 *
 * Print the PHY's recovered clock pin status.
 */
static void ice_dump_rclk_status(struct ice_pf *pf)
{
	struct device *dev = ice_pf_to_dev(pf);
	u8 phy, phy_pin, pin;
	int phy_pins;

	if (pf->hw.mac_type == ICE_MAC_E810)
		phy_pins = ICE_E810_RCLK_PINS_NUM;
	else
		/* E822-based devices have only one RCLK pin */
		phy_pins = E82X_CGU_RCLK_PHY_PINS_NUM;

	for (phy_pin = 0; phy_pin < phy_pins; phy_pin++) {
		const char *pin_name, *pin_state;
		u8 flags;

		if (ice_aq_get_phy_rec_clk_out(&pf->hw, phy_pin, NULL,
					       &flags, NULL))
			return;

		if (pf->hw.mac_type == ICE_MAC_E810) {
			int status = ice_get_pf_c827_idx(&pf->hw, &phy);

			if (status) {
				dev_err(dev,
					"Could not find PF C827 PHY, status=%d\n",
					status);
				return;
			}

			pin = E810T_CGU_INPUT_C827(phy, phy_pin);
			pin_name = ice_cgu_get_pin_name(&pf->hw, pin, true);
		} else {
			/* e822-based devices for now have only one phy
			 * available (from Rimmon) and only one DPLL RCLK input
			 * pin
			 */
			pin_name = E82X_CGU_RCLK_PIN_NAME;
		}
		pin_state =
			flags & ICE_AQC_SET_PHY_REC_CLK_OUT_OUT_EN ?
			"Enabled" : "Disabled";

		dev_info(dev, "State for pin %s: %s\n", pin_name, pin_state);
	}
}

#endif /* CONFIG_PTP_1588_CLOCK */
/**
 * ice_vsi_dump_ctxt - print the passed in VSI context structure
 * @dev: Device used for dev_info prints
 * @ctxt: VSI context structure to print
 */
static void ice_vsi_dump_ctxt(struct device *dev, struct ice_vsi_ctx *ctxt)
{
	struct ice_aqc_vsi_props *info;

	if (!ctxt)
		return;

	info = &ctxt->info;
	dev_info(dev, "Get VSI Parameters:\n");
	dev_info(dev, "\tVSI Number: %d Valid sections: 0x%04x\n",
		 ctxt->vsi_num, le16_to_cpu(info->valid_sections));

	dev_info(dev, "========================\n");
	dev_info(dev, "| Category - Switching |");
	dev_info(dev, "========================\n");
	dev_info(dev, "\tSwitch ID: %u\n", info->sw_id);
	dev_info(dev, "\tAllow Loopback: %s\n", (info->sw_flags &
		 ICE_AQ_VSI_SW_FLAG_ALLOW_LB) ? "enabled" : "disabled");
	dev_info(dev, "\tAllow Local Loopback: %s\n", (info->sw_flags &
		 ICE_AQ_VSI_SW_FLAG_LOCAL_LB) ? "enabled" : "disabled");
	dev_info(dev, "\tApply source VSI pruning: %s\n", (info->sw_flags &
		 ICE_AQ_VSI_SW_FLAG_SRC_PRUNE) ? "enabled" : "disabled");
	dev_info(dev, "\tEgress (Rx VLAN) pruning: %s\n",
		 (info->sw_flags2 & ICE_AQ_VSI_SW_FLAG_RX_PRUNE_EN_M) ?
		 "enabled" : "disabled");
	dev_info(dev, "\tLAN enable: %s\n", (info->sw_flags2 &
		 ICE_AQ_VSI_SW_FLAG_LAN_ENA) ? "enabled" : "disabled");
	dev_info(dev, "\tVEB statistic block ID: %u\n", info->veb_stat_id &
		 ICE_AQ_VSI_SW_VEB_STAT_ID_M);
	dev_info(dev, "\tVEB statistic block ID valid: %d\n",
		 (info->veb_stat_id & ICE_AQ_VSI_SW_VEB_STAT_ID_VALID) ? 1 : 0);

	dev_info(dev, "=======================\n");
	dev_info(dev, "| Category - Security |\n");
	dev_info(dev, "=======================\n");
	dev_info(dev, "\tAllow destination override: %s\n", (info->sec_flags &
		 ICE_AQ_VSI_SEC_FLAG_ALLOW_DEST_OVRD) ? "enabled" : "disabled");
	dev_info(dev, "\tEnable MAC anti-spoof: %s\n", (info->sec_flags &
		 ICE_AQ_VSI_SEC_FLAG_ENA_MAC_ANTI_SPOOF) ? "enabled" : "disabled");
	dev_info(dev, "\tIngress (Tx VLAN) pruning enables: %s\n",
		 (info->sec_flags & ICE_AQ_VSI_SEC_TX_PRUNE_ENA_M) ?
		 "enabled" : "disabled");

	dev_info(dev, "=================================\n");
	dev_info(dev, "| Category: Inner VLAN Handling |\n");
	dev_info(dev, "=================================\n");
	dev_info(dev, "\tPort Based Inner VLAN Insertion: PVLAN ID: %d PRIO: %d\n",
		 le16_get_bits(info->port_based_inner_vlan, VLAN_VID_MASK),
		 le16_get_bits(info->port_based_inner_vlan, VLAN_PRIO_MASK));
	dev_info(dev, "\tInner VLAN TX Mode: 0x%02x\n",
		 FIELD_GET(ICE_AQ_VSI_INNER_VLAN_TX_MODE_M, info->inner_vlan_flags));
	dev_info(dev, "\tInsert PVID: %s\n", (info->inner_vlan_flags &
		 ICE_AQ_VSI_INNER_VLAN_INSERT_PVID) ? "enabled" : "disabled");
	dev_info(dev, "\tInner VLAN and UP expose mode (RX): 0x%02x\n",
		 FIELD_GET(ICE_AQ_VSI_INNER_VLAN_EMODE_M, info->inner_vlan_flags));
	dev_info(dev, "\tBlock Inner VLAN from TX Descriptor: %s\n",
		 (info->inner_vlan_flags & ICE_AQ_VSI_INNER_VLAN_BLOCK_TX_DESC) ?
		 "enabled" : "disabled");

	dev_info(dev, "=================================\n");
	dev_info(dev, "| Category: Outer VLAN Handling |\n");
	dev_info(dev, "=================================\n");
	dev_info(dev, "\tPort Based Outer VLAN Insertion: PVID: %d PRIO: %d\n",
		 le16_get_bits(info->port_based_outer_vlan, VLAN_VID_MASK),
		 le16_get_bits(info->port_based_outer_vlan, VLAN_PRIO_MASK));
	dev_info(dev, "\tOuter VLAN and UP expose mode (RX): 0x%02x\n",
		 FIELD_GET(ICE_AQ_VSI_OUTER_VLAN_EMODE_M, info->outer_vlan_flags));
	dev_info(dev, "\tOuter Tag type (Tx and Rx): 0x%02x\n",
		 FIELD_GET(ICE_AQ_VSI_OUTER_TAG_TYPE_M, info->outer_vlan_flags));
	dev_info(dev, "\tPort Based Outer VLAN Insert Enable: %s\n",
		 (info->outer_vlan_flags &
		 ICE_AQ_VSI_OUTER_VLAN_PORT_BASED_INSERT) ?
		 "enabled" : "disabled");
	dev_info(dev, "\tOuter VLAN TX Mode: 0x%02x\n",
		 FIELD_GET(ICE_AQ_VSI_OUTER_VLAN_TX_MODE_M, info->outer_vlan_flags));
	dev_info(dev, "\tBlock Outer VLAN from TX Descriptor: %s\n",
		 (info->outer_vlan_flags & ICE_AQ_VSI_OUTER_VLAN_BLOCK_TX_DESC) ?
		 "enabled" : "disabled");
}

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
#define ICE_E810T_NEVER_USE_PIN 0xff
#define ZL_VER_MAJOR_SHIFT	24
#define ZL_VER_MAJOR_MASK	ICE_M(0xff, ZL_VER_MAJOR_SHIFT)
#define ZL_VER_MINOR_SHIFT	16
#define ZL_VER_MINOR_MASK	ICE_M(0xff, ZL_VER_MINOR_SHIFT)
#define ZL_VER_REV_SHIFT	8
#define ZL_VER_REV_MASK		ICE_M(0xff, ZL_VER_REV_SHIFT)
#define ZL_VER_BF_SHIFT		0
#define ZL_VER_BF_MASK		ICE_M(0xff, ZL_VER_BF_SHIFT)

/**
 * ice_get_dpll_status - get the detailed state of the clock generator
 * @pf: pointer to PF
 * @buff: buffer for the state to be printed
 * @buff_size: size of the buffer
 *
 * This function reads current status of the ZL CGU and prints it to the buffer
 * buff_size will be updated to reflect the number of bytes written to the
 * buffer
 *
 * Return: 0 on success, error code otherwise
 */
static int
ice_get_dpll_status(struct ice_pf *pf, char *buff, size_t *buff_size)
{
	u8 pin, synce_prio, ptp_prio, ver_major, ver_minor, rev, bugfix;
	struct ice_aqc_get_cgu_abilities abilities = {0};
	struct ice_aqc_get_cgu_input_config cfg = {0};
	struct device *dev = ice_pf_to_dev(pf);
	u32 cgu_id, cgu_cfg_ver, cgu_fw_ver;
	size_t bytes_left = *buff_size;
	struct ice_hw *hw = &pf->hw;
	char pin_name[MAX_PIN_NAME];
	int cnt = 0;
	int status;

	if (!ice_is_cgu_in_netlist(hw)) {
		dev_err(dev, "CGU not present\n");
		return -ENODEV;
	}

	memset(&abilities, 0, sizeof(struct ice_aqc_get_cgu_abilities));
	status = ice_aq_get_cgu_abilities(hw, &abilities);
	if (status) {
		dev_err(dev,
			"Failed to read CGU caps, status: %d, Error: 0x%02X\n",
			status, hw->adminq.sq_last_status);
		abilities.num_inputs = 7;
		abilities.pps_dpll_idx = 1;
		abilities.eec_dpll_idx = 0;
	}

	status = ice_aq_get_cgu_info(hw, &cgu_id, &cgu_cfg_ver, &cgu_fw_ver);
	if (status)
		return status;

	if (abilities.cgu_part_num ==
	    ICE_AQC_GET_LINK_TOPO_NODE_NR_ZL30632_80032) {
		cnt = snprintf(buff, bytes_left, "Found ZL80032 CGU\n");

		/* Read DPLL config version from AQ */
		ver_major = FIELD_GET(ZL_VER_MAJOR_MASK, cgu_cfg_ver);
		ver_minor = FIELD_GET(ZL_VER_MINOR_MASK, cgu_cfg_ver);
		rev = FIELD_GET(ZL_VER_REV_MASK, cgu_cfg_ver);
		bugfix = FIELD_GET(ZL_VER_BF_MASK, cgu_cfg_ver);

		cnt += snprintf(&buff[cnt], bytes_left - cnt,
				"DPLL Config ver: %d.%d.%d.%d\n", ver_major,
				ver_minor, rev, bugfix);
		cnt += snprintf(&buff[cnt], bytes_left - cnt,
				"DPLL FW ver: %i\n", cgu_fw_ver);
	} else if (abilities.cgu_part_num ==
		   ICE_AQC_GET_LINK_TOPO_NODE_NR_SI5383_5384) {
		cnt = snprintf(buff, bytes_left, "Found SI5383/5384 CGU\n");
	}

	cnt += snprintf(&buff[cnt], bytes_left - cnt, "\nCGU Input status:\n");
	cnt += snprintf(&buff[cnt], bytes_left - cnt,
			"                   |            |      priority     |            |\n"
			"      input (idx)  |    state   | EEC (%d) | PPS (%d) | ESync fail |\n",
			abilities.eec_dpll_idx, abilities.pps_dpll_idx);
	cnt += snprintf(&buff[cnt], bytes_left - cnt,
			"  ----------------------------------------------------------------\n");

	for (pin = 0; pin < abilities.num_inputs; pin++) {
		u8 esync_fail = 0;
		u8 esync_en = 0;
		char *pin_state;
		u8 data;

		status = ice_aq_get_input_pin_cfg(hw, pin, &cfg.status, NULL,
						  NULL, &cfg.flags2, NULL,
						  NULL);
		if (status)
			data = ICE_CGU_IN_PIN_FAIL_FLAGS;
		else
			data = (cfg.status & ICE_CGU_IN_PIN_FAIL_FLAGS);

		/* get either e810t pin names or generic ones */
		ice_dpll_pin_idx_to_name(pf, pin, pin_name);

		/* get pin priorities */
		if (ice_aq_get_cgu_ref_prio(hw, abilities.eec_dpll_idx, pin,
					    &synce_prio))
			synce_prio = ICE_E810T_NEVER_USE_PIN;
		if (ice_aq_get_cgu_ref_prio(hw, abilities.pps_dpll_idx, pin,
					    &ptp_prio))
			ptp_prio = ICE_E810T_NEVER_USE_PIN;

		/* if all flags are set, the pin is invalid */
		if (data == ICE_CGU_IN_PIN_FAIL_FLAGS) {
			pin_state = ICE_DPLL_PIN_STATE_INVALID;
		/* if some flags are set, the pin is validating */
		} else if (data) {
			pin_state = ICE_DPLL_PIN_STATE_VALIDATING;
		/* if all flags are cleared, the pin is valid */
		} else {
			pin_state = ICE_DPLL_PIN_STATE_VALID;
			esync_en = (cfg.flags2 &
			    ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_REFSYNC_EN) ==
			   (ICE_AQC_GET_CGU_IN_CFG_ESYNC_EN <<
			    ICE_AQC_GET_CGU_IN_CFG_FLG2_ESYNC_REFSYNC_EN_SHIFT);
			esync_fail = !!(cfg.status &
			    ICE_AQC_GET_CGU_IN_CFG_STATUS_ESYNC_FAIL);
		}

		cnt += snprintf(&buff[cnt], bytes_left - cnt,
				"  %12s (%d) | %10s |     %3d |     %3d |    %4s    |\n",
				pin_name, pin, pin_state, synce_prio, ptp_prio,
				esync_en ? esync_fail ?
				"true" : "false" : "N/A");
	}

	if (!test_bit(ICE_FLAG_DPLL_MONITOR, pf->flags)) {
		cnt += snprintf(&buff[cnt], bytes_left - cnt,
				"\nDPLL Monitoring disabled\n");
	} else {
		/* SYNCE DPLL status */
		ice_dpll_pin_idx_to_name(pf, pf->synce_ref_pin, pin_name);
		cnt += snprintf(&buff[cnt], bytes_left - cnt, "\nEEC DPLL:\n");
		cnt += snprintf(&buff[cnt], bytes_left - cnt,
				"\tCurrent reference:\t%s\n", pin_name);

		cnt += snprintf(&buff[cnt], bytes_left - cnt,
				"\tStatus:\t\t\t%s\n",
				ice_cgu_state_to_name(pf->synce_dpll_state));

		ice_dpll_pin_idx_to_name(pf, pf->ptp_ref_pin, pin_name);
		cnt += snprintf(&buff[cnt], bytes_left - cnt, "\nPPS DPLL:\n");
		cnt += snprintf(&buff[cnt], bytes_left - cnt,
				"\tCurrent reference:\t%s\n", pin_name);
		cnt += snprintf(&buff[cnt], bytes_left - cnt,
				"\tStatus:\t\t\t%s\n",
				ice_cgu_state_to_name(pf->ptp_dpll_state));

		if (pf->ptp_dpll_state != 0)
			cnt += snprintf(&buff[cnt], bytes_left - cnt,
					"\tPhase offset [ps]:\t\t\t%lld\n",
					pf->ptp_dpll_phase_offset);
	}

	*buff_size = cnt;
	return 0;
}

/**
 * ice_debugfs_cgu_read - debugfs interface for reading DPLL status
 * @file: the opened file
 * @user_buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 *
 * Return: number of bytes read
 */
static ssize_t ice_debugfs_cgu_read(struct file *file, char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	struct ice_pf *pf = file->private_data;
	size_t buffer_size = PAGE_SIZE;
	char *kbuff;
	int err;

	if (*ppos != 0)
		return 0;

	kbuff = (char *)get_zeroed_page(GFP_KERNEL);
	if (!kbuff)
		return -ENOMEM;

	err = ice_get_dpll_status(pf, kbuff, &buffer_size);

	if (err) {
		err = -EIO;
		goto err;
	}

	err = simple_read_from_buffer(user_buf, count, ppos, kbuff,
				      buffer_size);

err:
	free_page((unsigned long)kbuff);
	return err;
}

static const struct file_operations ice_debugfs_cgu_fops = {
	.owner = THIS_MODULE,
	.llseek = default_llseek,
	.open  = simple_open,
	.read  = ice_debugfs_cgu_read,
};
#endif /* SYNCE_SUPPORT */

/**
 * ice_fwlog_print_module_cfg - print current FW logging module configuration
 * @hw: pointer to the HW structure
 * @module: module to print
 * @s: the seq file to put data into
 */
static void
ice_fwlog_print_module_cfg(const struct ice_hw *hw, int module,
			   struct seq_file *s)
{
	const struct ice_fwlog_cfg *cfg = &hw->fwlog_cfg;
	const struct ice_fwlog_module_entry *entry;

	if (module != ICE_AQC_FW_LOG_ID_MAX) {
		entry =	&cfg->module_entries[module];

		seq_printf(s, "\tModule: %s, Log Level: %s\n",
			   ice_fwlog_module_string[entry->module_id],
			   ice_fwlog_level_string[entry->log_level]);
	} else {
		int i;

		for (i = 0; i < ICE_AQC_FW_LOG_ID_MAX; i++) {
			entry =	&cfg->module_entries[i];

			seq_printf(s, "\tModule: %s, Log Level: %s\n",
				   ice_fwlog_module_string[entry->module_id],
				   ice_fwlog_level_string[entry->log_level]);
		}
	}
}

static int
ice_find_module_by_dentry(const struct ice_pf *pf, const struct dentry *d)
{
	int i, module;

	module = -1;
	/* find the module based on the dentry */
	for (i = 0; i < ICE_NR_FW_LOG_MODULES; i++) {
		if (d == pf->ice_debugfs_pf_fwlog_modules[i]) {
			module = i;
			break;
		}
	}

	return module;
}

/**
 * ice_debugfs_module_show - read from 'module' file
 * @s: the opened file
 * @v: pointer to the offset
 */
static int ice_debugfs_module_show(struct seq_file *s, void *v)
{
#ifdef HAVE_FILE_IN_SEQ_FILE
	const struct file *file = s->file;
	const struct dentry *dentry;
	const struct ice_pf *pf;
	int module;

	dentry = file_dentry(file);
	pf = s->private;

	module = ice_find_module_by_dentry(pf, dentry);
	if (module < 0) {
		dev_info(ice_pf_to_dev(pf), "unknown module\n");
		return -EINVAL;
	}
#else
	/* print all modules instead of requested one */
	const struct ice_pf *pf = s->private;
	int module = ICE_AQC_FW_LOG_ID_MAX;
#endif /* HAVE_FILE_IN_SEQ_FILE */

	ice_fwlog_print_module_cfg(&pf->hw, module, s);

	return 0;
}

static int ice_debugfs_module_open(struct inode *inode, struct file *file)
{
	return single_open(file, ice_debugfs_module_show, inode->i_private);
}

/**
 * ice_debugfs_module_write - write into 'module' file
 * @file: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t
ice_debugfs_module_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	struct ice_pf *pf = file_inode(file)->i_private;
	const struct dentry *dentry = file_dentry(file);
	struct device *dev = ice_pf_to_dev(pf);
	char user_val[16], *cmd_buf;
	int module, log_level, cnt;

	/* don't allow partial writes or invalid input */
	if (*ppos != 0 || count > 8)
		return -EINVAL;

	cmd_buf = memdup_user(buf, count);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);

	module = ice_find_module_by_dentry(pf, dentry);
	if (module < 0) {
		dev_info(dev, "unknown module\n");
		return -EINVAL;
	}

	cnt = sscanf(cmd_buf, "%8s", user_val);
	if (cnt != 1)
		return -EINVAL;

	log_level = sysfs_match_string(ice_fwlog_level_string, user_val);
	if (log_level < 0) {
		dev_info(dev, "unknown log level '%s'\n", user_val);
		return -EINVAL;
	}

	if (module != ICE_AQC_FW_LOG_ID_MAX) {
		ice_pf_fwlog_update_module(pf, log_level, module);
	} else {
		/* the module 'all' is a shortcut so that we can set
		 * all of the modules to the same level quickly
		 */
		int i;

		for (i = 0; i < ICE_AQC_FW_LOG_ID_MAX; i++)
			ice_pf_fwlog_update_module(pf, log_level, i);
	}

	return count;
}

static const struct file_operations ice_debugfs_module_fops = {
	.owner = THIS_MODULE,
	.open  = ice_debugfs_module_open,
	.read = seq_read,
	.release = single_release,
	.write = ice_debugfs_module_write,
};

/**
 * ice_debugfs_nr_messages_read - read from 'nr_messages' file
 * @file: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 */
static ssize_t ice_debugfs_nr_messages_read(struct file *file,
					    char __user *buffer, size_t count,
					    loff_t *ppos)
{
	struct ice_pf *pf = file->private_data;
	struct ice_hw *hw = &pf->hw;
	char buff[32] = {};
	int status;

	snprintf(buff, sizeof(buff), "%d\n",
		 hw->fwlog_cfg.log_resolution);

	status = simple_read_from_buffer(buffer, count, ppos, buff,
					 strlen(buff));

	return status;
}

/**
 * ice_debugfs_nr_messages_write - write into 'nr_messages' file
 * @file: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t
ice_debugfs_nr_messages_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct ice_pf *pf = file->private_data;
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	char user_val[8], *cmd_buf;
	s16 nr_messages;
	ssize_t ret;

	/* don't allow partial writes or invalid input */
	if (*ppos != 0 || count > 4)
		return -EINVAL;

	cmd_buf = memdup_user(buf, count);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);

	ret = sscanf(cmd_buf, "%4s", user_val);
	if (ret != 1)
		return -EINVAL;

	ret = kstrtos16(user_val, 0, &nr_messages);
	if (ret)
		return ret;

	if (nr_messages < ICE_AQC_FW_LOG_MIN_RESOLUTION ||
	    nr_messages > ICE_AQC_FW_LOG_MAX_RESOLUTION) {
		dev_err(dev, "Invalid FW log number of messages %d, value must be between %d - %d\n",
			nr_messages, ICE_AQC_FW_LOG_MIN_RESOLUTION,
			ICE_AQC_FW_LOG_MAX_RESOLUTION);
		return -EINVAL;
	}

	hw->fwlog_cfg.log_resolution = nr_messages;

	return count;
}

static const struct file_operations ice_debugfs_nr_messages_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = ice_debugfs_nr_messages_read,
	.write = ice_debugfs_nr_messages_write,
};

/**
 * ice_debugfs_enable_read - read from 'enable' file
 * @file: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 */
static ssize_t ice_debugfs_enable_read(struct file *file,
				       char __user *buffer, size_t count,
				       loff_t *ppos)
{
	struct ice_pf *pf = file->private_data;
	struct ice_hw *hw = &pf->hw;
	char buff[32] = {};

	snprintf(buff, sizeof(buff), "%u\n",
		 (u16)(hw->fwlog_cfg.options &
		 ICE_FWLOG_OPTION_IS_REGISTERED) >> 3);

	return simple_read_from_buffer(buffer, count, ppos, buff, strlen(buff));
}

/**
 * ice_debugfs_enable_write - write into 'enable' file
 * @file: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t
ice_debugfs_enable_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	struct ice_pf *pf = file->private_data;
	struct ice_hw *hw = &pf->hw;
	char user_val[8], *cmd_buf;
	bool enable;
	ssize_t ret;

	/* don't allow partial writes or invalid input */
	if (*ppos != 0 || count > 2)
		return -EINVAL;

	cmd_buf = memdup_user(buf, count);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);

	ret = sscanf(cmd_buf, "%2s", user_val);
	if (ret != 1)
		return -EINVAL;

	ret = kstrtobool(user_val, &enable);
	if (ret)
		goto enable_write_error;

	if (enable)
		hw->fwlog_cfg.options |= ICE_FWLOG_OPTION_ARQ_ENA;
	else
		hw->fwlog_cfg.options &= ~ICE_FWLOG_OPTION_ARQ_ENA;

	ret = ice_fwlog_set(hw, &hw->fwlog_cfg);
	if (ret)
		goto enable_write_error;

	if (enable)
		ret = ice_fwlog_register(hw);
	else
		ret = ice_fwlog_unregister(hw);

	if (ret)
		goto enable_write_error;

	dev_info(ice_pf_to_dev(pf), "Firmware logging %s\n",
		 enable ? "enabled" : "disabled");

	/* if we get here, nothing went wrong; return count since we didn't
	 * really write anything
	 */
	ret = (ssize_t)count;

enable_write_error:
	/* This function always consumes all of the written input, or produces
	 * an error. Check and enforce this. Otherwise, the write operation
	 * won't complete properly.
	 */
	if (WARN_ON(ret != (ssize_t)count && ret >= 0))
		ret = -EIO;

	return ret;
}

static const struct file_operations ice_debugfs_enable_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = ice_debugfs_enable_read,
	.write = ice_debugfs_enable_write,
};

/**
 * ice_debugfs_log_size_read - read from 'log_size' file
 * @file: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 */
static ssize_t ice_debugfs_log_size_read(struct file *file,
					 char __user *buffer, size_t count,
					 loff_t *ppos)
{
	struct ice_pf *pf = file->private_data;
	struct ice_hw *hw = &pf->hw;
	char buff[32] = {};
	int index;

	index = hw->fwlog_ring.index;
	snprintf(buff, sizeof(buff), "%s\n", ice_fwlog_log_size[index]);

	return simple_read_from_buffer(buffer, count, ppos, buff, strlen(buff));
}

/**
 * ice_debugfs_log_size_write - write into 'log_size' file
 * @file: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t
ice_debugfs_log_size_write(struct file *file, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	struct ice_pf *pf = file->private_data;
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	char user_val[8], *cmd_buf;
	ssize_t ret;
	int index;

	/* don't allow partial writes */
	if (*ppos != 0)
		return -EINVAL;

	cmd_buf = memdup_user(buf, count);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);

	ret = sscanf(cmd_buf, "%5s", user_val);
	if (ret != 1)
		return -EINVAL;

	index = sysfs_match_string(ice_fwlog_log_size, user_val);
	if (index < 0) {
		dev_info(dev, "Invalid log size '%s'. The value must be one of 128K, 256K, 512K, 1M, 2M\n",
			 user_val);
		ret = -EINVAL;
		goto log_size_write_error;
	} else if (hw->fwlog_cfg.options & ICE_FWLOG_OPTION_IS_REGISTERED) {
		dev_info(dev, "FW logging is currently running. Please disable FW logging to change log_size\n");
		ret = -EINVAL;
		goto log_size_write_error;
	}

	/* free all the buffers and the tracking info and resize */
	ice_fwlog_realloc_rings(hw, index);

	/* if we get here, nothing went wrong; return count since we didn't
	 * really write anything
	 */
	ret = (ssize_t)count;

log_size_write_error:
	/* This function always consumes all of the written input, or produces
	 * an error. Check and enforce this. Otherwise, the write operation
	 * won't complete properly.
	 */
	if (WARN_ON(ret != (ssize_t)count && ret >= 0))
		ret = -EIO;

	return ret;
}

static const struct file_operations ice_debugfs_log_size_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = ice_debugfs_log_size_read,
	.write = ice_debugfs_log_size_write,
};

/**
 * ice_debugfs_data_read - read from 'data' file
 * @file: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 */
static ssize_t ice_debugfs_data_read(struct file *file, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	struct ice_pf *pf = file->private_data;
	struct ice_hw *hw = &pf->hw;
	int data_copied = 0;
	bool done = false;

	if (ice_fwlog_ring_empty(&hw->fwlog_ring))
		return 0;

	while (!ice_fwlog_ring_empty(&hw->fwlog_ring) && !done) {
		struct ice_fwlog_data *log;
		u16 cur_buf_len;

		log = &hw->fwlog_ring.rings[hw->fwlog_ring.head];
		cur_buf_len = log->data_size;
		if (cur_buf_len >= count) {
			done = true;
			continue;
		}

		if (copy_to_user(buffer, log->data, cur_buf_len)) {
			/* if there is an error then bail and return whatever
			 * the driver has copied so far
			 */
			done = true;
			continue;
		}

		data_copied += cur_buf_len;
		buffer += cur_buf_len;
		count -= cur_buf_len;
		*ppos += cur_buf_len;
		ice_fwlog_ring_increment(&hw->fwlog_ring.head,
					 hw->fwlog_ring.size);
	}

	return data_copied;
}

/**
 * ice_debugfs_data_write - write into 'data' file
 * @file: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t
ice_debugfs_data_write(struct file *file, const char __user *buf, size_t count,
		       loff_t *ppos)
{
	struct ice_pf *pf = file->private_data;
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	ssize_t ret;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;

	/* any value is allowed to clear the buffer so no need to even look at
	 * what the value is
	 */
	if (!(hw->fwlog_cfg.options & ICE_FWLOG_OPTION_IS_REGISTERED)) {
		hw->fwlog_ring.head = 0;
		hw->fwlog_ring.tail = 0;
	} else {
		dev_info(dev, "Can't clear FW log data while FW log running\n");
		ret = -EINVAL;
		goto nr_buffs_write_error;
	}

	/* if we get here, nothing went wrong; return count since we didn't
	 * really write anything
	 */
	ret = (ssize_t)count;

nr_buffs_write_error:
	/* This function always consumes all of the written input, or produces
	 * an error. Check and enforce this. Otherwise, the write operation
	 * won't complete properly.
	 */
	if (WARN_ON(ret != (ssize_t)count && ret >= 0))
		ret = -EIO;

	return ret;
}

static const struct file_operations ice_debugfs_data_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read = ice_debugfs_data_read,
	.write = ice_debugfs_data_write,
};

/**
 * ice_debugfs_fwlog_init - setup the debugfs directory
 * @pf: the ice that is starting up
 */
void ice_debugfs_fwlog_init(struct ice_pf *pf)
{
	struct dentry *fw_modules_dir;
	struct dentry **fw_modules;
	int i;

	/* only support fw log commands on PF 0 */
	if (pf->hw.bus.func)
		return;

	/* allocate space for this first because if it fails then we don't
	 * need to unwind
	 */
	fw_modules = kcalloc(ICE_NR_FW_LOG_MODULES, sizeof(*fw_modules),
			     GFP_KERNEL);
	if (!fw_modules)
		return;

	pf->ice_debugfs_pf_fwlog = debugfs_create_dir("fwlog",
						      pf->ice_debugfs_pf);
	if (IS_ERR(pf->ice_debugfs_pf))
		goto err_create_module_files;

	fw_modules_dir = debugfs_create_dir("modules",
					    pf->ice_debugfs_pf_fwlog);
	if (IS_ERR(fw_modules_dir))
		goto err_create_module_files;

	for (i = 0; i < ICE_NR_FW_LOG_MODULES; i++) {
		fw_modules[i] = debugfs_create_file(ice_fwlog_module_string[i],
						    0600, fw_modules_dir, pf,
						    &ice_debugfs_module_fops);

		if (IS_ERR(fw_modules[i]))
			goto err_create_module_files;
	}

	debugfs_create_file("nr_messages", 0600,
			    pf->ice_debugfs_pf_fwlog, pf,
			    &ice_debugfs_nr_messages_fops);

	pf->ice_debugfs_pf_fwlog_modules = fw_modules;

	debugfs_create_file("enable", 0600, pf->ice_debugfs_pf_fwlog,
			    pf, &ice_debugfs_enable_fops);

	debugfs_create_file("log_size", 0600, pf->ice_debugfs_pf_fwlog,
			    pf, &ice_debugfs_log_size_fops);

	debugfs_create_file("data", 0600, pf->ice_debugfs_pf_fwlog,
			    pf, &ice_debugfs_data_fops);

	return;

err_create_module_files:
	debugfs_remove_recursive(pf->ice_debugfs_pf_fwlog);
	kfree(fw_modules);
}

/**
 * ice_debugfs_command_write - write into command datum
 * @file: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t
ice_debugfs_command_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct ice_pf *pf = file->private_data;
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret;
	char **argv;
	int argc;

	/* don't allow partial writes and writes when reset is in progress*/
	if (*ppos != 0 || ice_is_reset_in_progress(pf->state))
		return 0;

	cmd_buf = memdup_user(buf, count + 1);
	if (IS_ERR(cmd_buf))
		return PTR_ERR(cmd_buf);
	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = (size_t)cmd_buf_tmp - (size_t)cmd_buf + 1;
	}

	argv = argv_split(GFP_KERNEL, cmd_buf, &argc);
	if (!argv) {
		ret = -ENOMEM;
		goto err_copy_from_user;
	}

	if (argc > 1 && !strncmp(argv[1], "vsi", 3)) {
		if (argc == 3 && !strncmp(argv[0], "get", 3)) {
			struct ice_vsi_ctx *vsi_ctx;

			vsi_ctx = devm_kzalloc(dev, sizeof(*vsi_ctx),
					       GFP_KERNEL);
			if (!vsi_ctx) {
				ret = -ENOMEM;
				goto command_write_error;
			}
			ret = kstrtou16(argv[2], 0, &vsi_ctx->vsi_num);
			if (ret) {
				devm_kfree(dev, vsi_ctx);
				goto command_help;
			}
			ret = ice_aq_get_vsi_params(hw, vsi_ctx, NULL);
			if (ret) {
				devm_kfree(dev, vsi_ctx);
				goto command_help;
			}

			ice_vsi_dump_ctxt(dev, vsi_ctx);
			devm_kfree(dev, vsi_ctx);
		} else {
			goto command_help;
		}
	} else if (argc == 2 && !strncmp(argv[0], "dump", 4) &&
		   !strncmp(argv[1], "switch", 6)) {
		ret = ice_dump_sw_cfg(hw);
		if (ret) {
			ret = -EINVAL;
			dev_err(dev, "dump switch failed\n");
			goto command_write_error;
		}
	} else if (argc == 2 && !strncmp(argv[0], "dump", 4) &&
		   !strncmp(argv[1], "capabilities", 11)) {
		ice_dump_caps(hw);
	} else if (argc == 4 && !strncmp(argv[0], "dump", 4) &&
		   !strncmp(argv[1], "ptp", 3) &&
		   !strncmp(argv[2], "func", 4) &&
		   !strncmp(argv[3], "capabilities", 11)) {
		ice_dump_ptp_func_caps(hw);
	} else if (argc == 4 && !strncmp(argv[0], "dump", 4) &&
		   !strncmp(argv[1], "ptp", 3) &&
		   !strncmp(argv[2], "dev", 3) &&
		   !strncmp(argv[3], "capabilities", 11)) {
		ice_dump_ptp_dev_caps(hw);
	} else if (argc == 2 && !strncmp(argv[0], "dump", 4) &&
		   !strncmp(argv[1], "ports", 5)) {
		dev_info(dev, "port_info:\n");
		ice_dump_port_info(hw->port_info);
#ifdef ICE_ADD_PROBES
	} else if (argc == 2 && !strncmp(argv[0], "dump", 4) &&
		   !strncmp(argv[1], "arfs_stats", 10)) {
		struct ice_vsi *vsi = ice_get_main_vsi(pf);

		if (!vsi) {
			dev_err(dev, "Failed to find PF VSI\n");
		} else if (vsi->netdev->features & NETIF_F_NTUPLE) {
			struct ice_arfs_active_fltr_cntrs *fltr_cntrs;

			fltr_cntrs = vsi->arfs_fltr_cntrs;

			/* active counters can be updated by multiple CPUs */
			smp_mb__before_atomic();
			dev_info(dev, "arfs_active_tcpv4_filters: %d\n",
				 atomic_read(&fltr_cntrs->active_tcpv4_cnt));
			dev_info(dev, "arfs_active_tcpv6_filters: %d\n",
				 atomic_read(&fltr_cntrs->active_tcpv6_cnt));
			dev_info(dev, "arfs_active_udpv4_filters: %d\n",
				 atomic_read(&fltr_cntrs->active_udpv4_cnt));
			dev_info(dev, "arfs_active_udpv6_filters: %d\n",
				 atomic_read(&fltr_cntrs->active_udpv6_cnt));
		}
#endif /* ICE_ADD_PROBES */
	} else if (argc == 2 && !strncmp(argv[0], "dump", 4)) {
		if (!strncmp(argv[1], "mmcast", 6)) {
			ice_dump_sw_rules(hw, ICE_SW_LKUP_MAC);
		} else if (!strncmp(argv[1], "vlan", 4)) {
			ice_dump_sw_rules(hw, ICE_SW_LKUP_VLAN);
		} else if (!strncmp(argv[1], "eth", 3)) {
			ice_dump_sw_rules(hw, ICE_SW_LKUP_ETHERTYPE);
		} else if (!strncmp(argv[1], "pf_vsi", 6)) {
			ice_dump_pf_vsi_list(pf);
		} else if (!strncmp(argv[1], "pf_port_num", 11)) {
			dev_info(dev, "pf_id = %d, port_num = %d\n",
				 hw->pf_id, hw->port_info->lport);
		} else if (!strncmp(argv[1], "pf", 2)) {
			ice_dump_pf(pf);
		} else if (!strncmp(argv[1], "vfs", 3)) {
			ice_dump_all_vfs(pf);
		} else if (!strncmp(argv[1], "fdir_stats", 10)) {
			ice_dump_pf_fdir(pf);
		} else if (!strncmp(argv[1], "reset_stats", 11)) {
			dev_info(dev, "core reset count: %d\n",
				 pf->corer_count);
			dev_info(dev, "global reset count: %d\n",
				 pf->globr_count);
			dev_info(dev, "emp reset count: %d\n", pf->empr_count);
			dev_info(dev, "pf reset count: %d\n", pf->pfr_count);
#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
		} else if ((!strncmp(argv[1], "rclk_status", 11))) {
			if (ice_is_feature_supported(pf, ICE_F_PHY_RCLK))
				ice_dump_rclk_status(pf);
#endif /* CONFIG_PTP_1588_CLOCK */
		}

#ifdef CONFIG_DCB
	} else if (argc == 3 && !strncmp(argv[0], "lldp", 4) &&
				!strncmp(argv[1], "get", 3)) {
		u8 mibtype;
		u16 llen, rlen;
		u8 *buff;

		if (!strncmp(argv[2], "local", 5))
			mibtype = ICE_AQ_LLDP_MIB_LOCAL;
		else if (!strncmp(argv[2], "remote", 6))
			mibtype = ICE_AQ_LLDP_MIB_REMOTE;
		else
			goto command_help;

		buff = devm_kzalloc(dev, ICE_LLDPDU_SIZE, GFP_KERNEL);
		if (!buff) {
			ret = -ENOMEM;
			goto command_write_error;
		}

		ret = ice_aq_get_lldp_mib(hw,
					  ICE_AQ_LLDP_BRID_TYPE_NEAREST_BRID,
					  mibtype, (void *)buff,
					  ICE_LLDPDU_SIZE,
					  &llen, &rlen, NULL);

		if (!ret) {
			if (mibtype == ICE_AQ_LLDP_MIB_LOCAL) {
				dev_info(dev, "LLDP MIB (local)\n");
				print_hex_dump(KERN_INFO, "LLDP MIB (local): ",
					       DUMP_PREFIX_OFFSET, 16, 1,
					       buff, llen, true);
			} else if (mibtype == ICE_AQ_LLDP_MIB_REMOTE) {
				dev_info(dev, "LLDP MIB (remote)\n");
				print_hex_dump(KERN_INFO, "LLDP MIB (remote): ",
					       DUMP_PREFIX_OFFSET, 16, 1,
					       buff, rlen, true);
			}
		} else {
			dev_err(dev, "GET LLDP MIB failed. Status: %ld\n", ret);
		}
		devm_kfree(dev, buff);
#endif /* CONFIG_DCB */
	} else if ((argc > 1) && !strncmp(argv[1], "scheduling", 10)) {
		if (argc == 4 && !strncmp(argv[0], "get", 3) &&
		    !strncmp(argv[2], "tree", 4) &&
		    !strncmp(argv[3], "topology", 8)) {
			ice_dump_port_topo(hw->port_info);
		}
	} else {
command_help:
		dev_info(dev, "unknown or invalid command '%s'\n", cmd_buf);
		dev_info(dev, "available commands\n");
		dev_info(dev, "\t get vsi <vsinum>\n");
		dev_info(dev, "\t dump switch\n");
		dev_info(dev, "\t dump ports\n");
		dev_info(dev, "\t dump capabilities\n");
		dev_info(dev, "\t dump ptp func capabilities\n");
		dev_info(dev, "\t dump ptp dev capabilities\n");
		dev_info(dev, "\t dump mmcast\n");
		dev_info(dev, "\t dump vlan\n");
		dev_info(dev, "\t dump eth\n");
		dev_info(dev, "\t dump pf_vsi\n");
		dev_info(dev, "\t dump pf\n");
		dev_info(dev, "\t dump pf_port_num\n");
		dev_info(dev, "\t dump vfs\n");
		dev_info(dev, "\t dump reset_stats\n");
		dev_info(dev, "\t dump fdir_stats\n");
		dev_info(dev, "\t get scheduling tree topology\n");
		dev_info(dev, "\t get scheduling tree topology portnum <port>\n");
#ifdef CONFIG_DCB
		dev_info(dev, "\t lldp get local\n");
		dev_info(dev, "\t lldp get remote\n");
#endif /* CONFIG_DCB */
#ifdef ICE_ADD_PROBES
		dev_info(dev, "\t dump arfs_stats\n");
#endif /* ICE_ADD_PROBES */
		if (ice_is_feature_supported(pf, ICE_F_PHY_RCLK))
			dev_info(dev, "\t dump rclk_status\n");
		ret = -EINVAL;
		goto command_write_error;
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_error:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);

	/* This function always consumes all of the written input, or produces
	 * an error. Check and enforce this. Otherwise, the write operation
	 * won't complete properly.
	 */
	if (WARN_ON(ret != (ssize_t)count && ret >= 0))
		ret = -EIO;

	return ret;
}

static const struct file_operations ice_debugfs_command_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.write = ice_debugfs_command_write,
};

/**
 * ice_debugfs_pf_init - setup the debugfs directory
 * @pf: the ice that is starting up
 */
void ice_debugfs_pf_init(struct ice_pf *pf)
{
	const char *name = pci_name(pf->pdev);

	pf->ice_debugfs_pf = debugfs_create_dir(name, ice_debugfs_root);
	if (IS_ERR(pf->ice_debugfs_pf))
		return;

	pf->ice_debugfs_fw = debugfs_create_dir("fw", pf->ice_debugfs_pf);
	if (IS_ERR(pf->ice_debugfs_fw))
		return;

	if (!debugfs_create_file("command", 0600, pf->ice_debugfs_pf,
				 pf, &ice_debugfs_command_fops))
		goto create_failed;

	if (!debugfs_create_file("dump_cluster_id", 0600, pf->ice_debugfs_fw,
				 pf, &dump_cluster_id_fops))
		goto create_failed;

#if IS_ENABLED(CONFIG_PTP_1588_CLOCK)
	/* Expose external CGU debugfs interface if CGU available*/
	if (ice_is_feature_supported(pf, ICE_F_CGU)) {
		if (!debugfs_create_file("cgu", 0400, pf->ice_debugfs_pf, pf,
					 &ice_debugfs_cgu_fops))
			goto create_failed;
	}
#endif /* CONFIG_PTP_1588_CLOCK */

	ice_fwlog_init(&pf->hw);

	return;

create_failed:
	dev_err(ice_pf_to_dev(pf), "debugfs dir/file for %s failed\n", name);
	debugfs_remove_recursive(pf->ice_debugfs_pf);
}

/**
 * ice_debugfs_pf_exit - clear out the ices debugfs entries
 * @pf: the ice that is stopping
 */
void ice_debugfs_pf_exit(struct ice_pf *pf)
{
	struct debugfs_blob_wrapper *desc_blob = pf->ice_fw_dump_blob;

	debugfs_remove_recursive(pf->ice_debugfs_pf);

	ice_fwlog_deinit(&pf->hw);

	if (desc_blob) {
		vfree(desc_blob->data);
		kfree(desc_blob);
	}
	pf->ice_fw_dump_blob = NULL;

	pf->ice_debugfs_fw = NULL;
	pf->ice_debugfs_pf = NULL;
}

/**
 * ice_debugfs_init - create root directory for debugfs entries
 */
void ice_debugfs_init(void)
{
	ice_debugfs_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (IS_ERR(ice_debugfs_root))
		pr_info("init of debugfs failed\n");
}

/**
 * ice_debugfs_exit - remove debugfs entries
 */
void ice_debugfs_exit(void)
{
	debugfs_remove_recursive(ice_debugfs_root);
	ice_debugfs_root = NULL;
}
