// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2018-2019, Intel Corporation. */

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/random.h>
#include "ice.h"
#include "ice_lib.h"
#include "ice_fltr.h"


static struct dentry *ice_debugfs_root;


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
	dev_info(dev, "\tnum_lan_msix = %d\n", pf->num_lan_msix);
	dev_info(dev, "\tnum_rdma_msix = %d\n", pf->num_rdma_msix);
	dev_info(dev, "\trdma_base_vector = %d\n", pf->rdma_base_vector);
#ifdef HAVE_NETDEV_SB_DEV
	dev_info(dev, "\tnum_macvlan = %d\n", pf->num_macvlan);
	dev_info(dev, "\tmax_num_macvlan = %d\n", pf->max_num_macvlan);
#endif /* HAVE_NETDEV_SB_DEV */
	dev_info(dev, "\tirq_tracker->num_entries = %d\n",
		 pf->irq_tracker->num_entries);
	dev_info(dev, "\tirq_tracker->end = %d\n", pf->irq_tracker->end);
	dev_info(dev, "\tirq_tracker valid count = %d\n",
		 ice_get_valid_res_count(pf->irq_tracker));
	dev_info(dev, "\tnum_avail_sw_msix = %d\n", pf->num_avail_sw_msix);
	dev_info(dev, "\tsriov_base_vector = %d\n", pf->sriov_base_vector);
	dev_info(dev, "\tnum_alloc_vfs = %d\n", pf->num_alloc_vfs);
	dev_info(dev, "\tnum_qps_per_vf = %d\n", pf->num_qps_per_vf);
	dev_info(dev, "\tnum_msix_per_vf = %d\n", pf->num_msix_per_vf);
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
		dev_info(dev, "\tvsi = %pK\n", vsi);
		dev_info(dev, "\tvsi_num = %d\n", vsi->vsi_num);
		dev_info(dev, "\ttype = %s\n", ice_vsi_type_str(vsi->type));
		if (vsi->type == ICE_VSI_VF)
			dev_info(dev, "\tvf_id = %d\n", vsi->vf_id);
		dev_info(dev, "\tback = %pK\n", vsi->back);
		dev_info(dev, "\tnetdev = %pK\n", vsi->netdev);
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
	dev_info(dev, "\tPF guaranteed used = %d\n",
		 (pf_fltr_cnt & PFQF_FD_CNT_FD_GCNT_M) >>
		 PFQF_FD_CNT_FD_GCNT_S);
	dev_info(dev, "\tPF best_effort used = %d\n",
		 (pf_fltr_cnt & PFQF_FD_CNT_FD_BCNT_M) >>
		 PFQF_FD_CNT_FD_BCNT_S);
	dev_info(dev, "\tdevice guaranteed used = %d\n",
		 (dev_fltr_cnt & GLQF_FD_CNT_FD_GCNT_M) >>
		 GLQF_FD_CNT_FD_GCNT_S);
	dev_info(dev, "\tdevice best_effort used = %d\n",
		 (dev_fltr_cnt & GLQF_FD_CNT_FD_BCNT_M) >>
		 GLQF_FD_CNT_FD_BCNT_S);
	dev_info(dev, "\tPF guaranteed pool = %d\n", pf_guar_pool);
	dev_info(dev, "\tdevice guaranteed pool = %d\n",
		 (dev_fltr_size & GLQF_FD_SIZE_FD_GSIZE_M) >>
		 GLQF_FD_SIZE_FD_GSIZE_S);
	dev_info(dev, "\tdevice best_effort pool = %d\n",
		 hw->func_caps.fd_fltr_best_effort);
}

/**
 * ice_debugfs_command_write - write into command datum
 * @filp: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t
ice_debugfs_command_write(struct file *filp, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct ice_pf *pf = filp->private_data;
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	char *cmd_buf, *cmd_buf_tmp;
	ssize_t ret = 0;
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
				goto command_write_done;
			}
			ret = kstrtou16(argv[2], 0, &vsi_ctx->vsi_num);
			if (ret) {
				devm_kfree(dev, vsi_ctx);
				goto command_help;
			}
			ret = ice_aq_get_vsi_params(hw, vsi_ctx, NULL);
			if (ret) {
				ret = -EINVAL;
				devm_kfree(dev, vsi_ctx);
				goto command_help;
			}
			dev_info(dev, "Get VSI params\n");
			dev_info(dev, "VSI Number: %d Context.valid_section : 0x%04x sw_id: %u sw_flags: 0x%02x security_flags: 0x%04x rx_prune_enabled: %u veb_stat_id : %u\n",
				 vsi_ctx->vsi_num,
				 le16_to_cpu(vsi_ctx->info.valid_sections),
				 vsi_ctx->info.sw_id, vsi_ctx->info.sw_flags,
				 vsi_ctx->info.sec_flags,
				 (vsi_ctx->info.sec_flags) >>
					ICE_AQ_VSI_SEC_TX_PRUNE_ENA_S,
				 vsi_ctx->info.veb_stat_id);
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
			goto command_write_done;
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
		if (!buff)
			goto command_write_done;

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
	} else if (argc == 4 && !strncmp(argv[0], "set_ts_pll", 10)) {
		u8 time_ref_freq;
		u8 time_ref_sel;
		u8 mstr_tmr_mode;

		ret = kstrtou8(argv[1], 0, &time_ref_freq);
		if (ret)
			goto command_help;
		ret = kstrtou8(argv[2], 0, &time_ref_sel);
		if (ret)
			goto command_help;
		ret = kstrtou8(argv[3], 0, &mstr_tmr_mode);
		if (ret)
			goto command_help;

		ice_cgu_cfg_ts_pll(pf, false, (enum ice_time_ref_freq)time_ref_freq,
				   (enum ice_cgu_time_ref_sel)time_ref_sel,
				   (enum ice_mstr_tmr_mode)mstr_tmr_mode);
		ice_cgu_cfg_ts_pll(pf, true, (enum ice_time_ref_freq)time_ref_freq,
				   (enum ice_cgu_time_ref_sel)time_ref_sel,
				   (enum ice_mstr_tmr_mode)mstr_tmr_mode);
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
		if (ret >= 0)
			ret = -EINVAL;
		goto command_write_done;
	}

	/* if we get here, nothing went wrong; return bytes copied */
	ret = (ssize_t)count;

command_write_done:
	argv_free(argv);
err_copy_from_user:
	kfree(cmd_buf);
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
	struct dentry *pfile;

	pf->ice_debugfs_pf = debugfs_create_dir(name, ice_debugfs_root);
	if (IS_ERR(pf->ice_debugfs_pf))
		return;

	pfile = debugfs_create_file("command", 0600, pf->ice_debugfs_pf, pf,
				    &ice_debugfs_command_fops);
	if (!pfile)
		goto create_failed;

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
	debugfs_remove_recursive(pf->ice_debugfs_pf);
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
