// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2022 Intel Corporation */
#include "main.h"
#include "i40iw_hw.h"
#include "i40e_client.h"

static struct i40e_client i40iw_client;

/**
 * i40iw_l2param_change - handle mss change
 * @cdev_info: parent lan device information structure with data/ops
 * @client: client for parameter change
 * @params: new parameters from L2
 */
static void i40iw_l2param_change(struct i40e_info *cdev_info,
				 struct i40e_client *client,
				 struct i40e_params *params)
{
	struct irdma_l2params l2params = {};
	struct irdma_device *iwdev;
	struct ib_device *ibdev;

	ibdev = ib_device_get_by_netdev(cdev_info->netdev, RDMA_DRIVER_IRDMA);
	if (!ibdev)
		return;

	iwdev = to_iwdev(ibdev);

	if (iwdev->vsi.mtu != params->mtu) {
		l2params.mtu_changed = true;
		l2params.mtu = params->mtu;
	}
	irdma_change_l2params(&iwdev->vsi, &l2params);
	ib_device_put(ibdev);
}

/**
 * i40iw_close - client interface operation close for iwarp/uda device
 * @cdev_info: parent lan device information structure with data/ops
 * @client: client to close
 * @reset: flag to indicate close on reset
 *
 * Called by the lan driver during the processing of client unregister
 * Destroy and clean up the driver resources
 */
static void i40iw_close(struct i40e_info *cdev_info, struct i40e_client *client,
			bool reset)
{
	struct irdma_device *iwdev;
	struct ib_device *ibdev;

	ibdev = ib_device_get_by_netdev(cdev_info->netdev, RDMA_DRIVER_IRDMA);
	if (WARN_ON(!ibdev))
		return;

	iwdev = to_iwdev(ibdev);
	if (reset)
		iwdev->rf->reset = true;

	irdma_unregister_notifiers(iwdev);
	ib_device_put(&iwdev->ibdev);
	irdma_ib_unregister_device(iwdev);
#ifndef IB_DEALLOC_DRIVER_SUPPORT
	/* In newer kernels core issues callback irdma_ib_dealloc_device to cleanup
	 * Older kernels require cleanup here and explicilty need to call ib_dealloc_device
	 */
	irdma_deinit_device(iwdev);
	ib_dealloc_device(&iwdev->ibdev);
#endif /* IB_DEALLOC_DRIVER_SUPPORT */
	pr_debug("INIT: Gen1 PF[%d] close complete\n", PCI_FUNC(cdev_info->pcidev->devfn));
}

static void i40iw_request_reset(struct irdma_pci_f *rf)
{
	struct i40e_info *cdev_info = rf->cdev;

	cdev_info->ops->request_reset(cdev_info, &i40iw_client, 1);
}

static void i40iw_fill_device_info(struct irdma_device *iwdev, struct i40e_info *cdev_info)
{
	struct irdma_pci_f *rf = iwdev->rf;

	rf->rdma_ver = IRDMA_GEN_1;
	rf->sc_dev.hw = &rf->hw;
	rf->sc_dev.hw_attrs.uk_attrs.hw_rev = IRDMA_GEN_1;
	rf->sc_dev.privileged = true;
	rf->gen_ops.request_reset = i40iw_request_reset;
	rf->hw.hw_addr = cdev_info->hw_addr;
	rf->pcidev = cdev_info->pcidev;
	rf->hw.device = &rf->pcidev->dev;
	rf->ftype = cdev_info->ftype;
	rf->pf_id = cdev_info->fid;
	rf->cdev = cdev_info;
	rf->msix_count = cdev_info->msix_count;
	rf->msix_entries = cdev_info->msix_entries;
	irdma_set_rf_user_cfg_params(rf);
	rf->protocol_used = IRDMA_IWARP_PROTOCOL_ONLY;
	rf->iwdev = iwdev;

	iwdev->init_state = INITIAL_STATE;
	iwdev->rcv_wnd = IRDMA_CM_DEFAULT_RCV_WND_SCALED;
	iwdev->rcv_wscale = IRDMA_CM_DEFAULT_RCV_WND_SCALE;
	iwdev->netdev = cdev_info->netdev;
	iwdev->aux_dev = cdev_info->aux_dev;
	iwdev->vsi_num = 0;
}

/**
 * i40iw_open - client interface operation open for iwarp/uda device
 * @cdev_info: parent lan device information structure with data/ops
 * @client: iwarp client information, provided during registration
 *
 * Called by the lan driver during the processing of client register
 * Create device resources, set up queues, pble and hmc objects and
 * register the device with the ib verbs interface
 * Return 0 if successful, otherwise return error
 */
static int i40iw_open(struct i40e_info *cdev_info, struct i40e_client *client)
{
	struct irdma_l2params l2params = {};
	struct irdma_device *iwdev;
	struct irdma_pci_f *rf;
	int err = -EIO;
	int i;
	u16 qset;
	u16 last_qset = IRDMA_NO_QSET;
	struct irdma_handler *hdl;

	iwdev = ib_alloc_device(irdma_device, ibdev);
	if (!iwdev)
		return -ENOMEM;

	iwdev->rf = kzalloc(sizeof(*rf), GFP_KERNEL);
	if (!iwdev->rf) {
		ib_dealloc_device(&iwdev->ibdev);
		return -ENOMEM;
	}

	i40iw_fill_device_info(iwdev, cdev_info);
	rf = iwdev->rf;

	hdl = kzalloc(sizeof(*hdl), GFP_KERNEL);
	if (!hdl) {
		err = -ENOMEM;
		goto err_hdl;
	}

	hdl->iwdev = iwdev;
	iwdev->hdl = hdl;
	if (irdma_ctrl_init_hw(rf)) {
		err = -EIO;
		goto err_ctrl_init;
	}

	l2params.mtu = (cdev_info->params.mtu) ? cdev_info->params.mtu : IRDMA_DEFAULT_MTU;
	for (i = 0; i < I40E_CLIENT_MAX_USER_PRIORITY; i++) {
		qset = cdev_info->params.qos.prio_qos[i].qs_handle;
		l2params.up2tc[i] = cdev_info->params.qos.prio_qos[i].tc;
		l2params.qs_handle_list[i] = qset;
		if (last_qset == IRDMA_NO_QSET)
			last_qset = qset;
		else if ((qset != last_qset) && (qset != IRDMA_NO_QSET))
			iwdev->dcb_vlan_mode = true;
	}

	if (irdma_rt_init_hw(iwdev, &l2params)) {
		err = -EIO;
		goto err_rt_init;
	}

	err = irdma_ib_register_device(iwdev);
	if (err)
		goto err_ibreg;

	err = irdma_register_notifiers(iwdev);
	if (err)
		goto err_notifier_reg;

	irdma_add_handler(hdl);
#ifdef CONFIG_DEBUG_FS
	irdma_dbg_pf_init(hdl);
#endif
	ibdev_dbg(&iwdev->ibdev, "INIT: Gen1 PF[%d] open success\n",
		  PCI_FUNC(rf->pcidev->devfn));

	return 0;

err_notifier_reg:
	irdma_ib_unregister_device(iwdev);
err_ibreg:
	irdma_rt_deinit_hw(iwdev);
err_rt_init:
	irdma_ctrl_deinit_hw(rf);
err_ctrl_init:
	kfree(hdl);
err_hdl:
	kfree(iwdev->rf);
	ib_dealloc_device(&iwdev->ibdev);

	return err;
}

/* client interface functions */
static const struct i40e_client_ops i40e_ops = {
	.open = i40iw_open,
	.close = i40iw_close,
	.l2_param_change = i40iw_l2param_change
};

static struct i40e_client i40iw_client = {
	.ops = &i40e_ops,
	.version.major = I40E_CLIENT_VERSION_MAJOR,
	.version.minor = I40E_CLIENT_VERSION_MINOR,
	.version.build = I40E_CLIENT_VERSION_BUILD,
	.type = I40E_CLIENT_IWARP,
};

static int i40iw_probe(struct auxiliary_device *aux_dev, const struct auxiliary_device_id *id)
{
	struct i40e_auxiliary_device *i40e_adev = container_of(aux_dev,
							       struct i40e_auxiliary_device,
							       aux_dev);
	struct i40e_info *cdev_info = i40e_adev->ldev;

	if (cdev_info->version.major != I40E_CLIENT_VERSION_MAJOR ||
	    cdev_info->version.minor != I40E_CLIENT_VERSION_MINOR) {
		pr_err("version mismatch:\n");
		pr_err("expected major ver %d, caller specified major ver %d\n",
		       I40E_CLIENT_VERSION_MAJOR, cdev_info->version.major);
		pr_err("expected minor ver %d, caller specified minor ver %d\n",
		       I40E_CLIENT_VERSION_MINOR, cdev_info->version.minor);
		return -EINVAL;
	}

	strncpy(i40iw_client.name, "irdma", I40E_CLIENT_STR_LENGTH);
	cdev_info->client = &i40iw_client;

	return cdev_info->ops->client_device_register(cdev_info);
}

#ifdef HAVE_AUXILIARY_DRIVER_INT_REMOVE
static int i40iw_remove(struct auxiliary_device *aux_dev)
#else
static void i40iw_remove(struct auxiliary_device *aux_dev)
#endif
{
	struct i40e_auxiliary_device *i40e_adev = container_of(aux_dev,
							       struct i40e_auxiliary_device,
							       aux_dev);
	struct i40e_info *cdev_info = i40e_adev->ldev;

	cdev_info->ops->client_device_unregister(cdev_info);
#ifdef HAVE_AUXILIARY_DRIVER_INT_REMOVE
	return 0;
#endif /* HAVE_AUXILIARY_DRIVER_INT_REMOVE */
}

static const struct auxiliary_device_id i40iw_auxiliary_id_table[] = {
	{.name = "i40e.iwarp", },
	{},
};

MODULE_DEVICE_TABLE(auxiliary, i40iw_auxiliary_id_table);

struct auxiliary_driver i40iw_auxiliary_drv = {
	.name = "gen_1",
	.id_table = i40iw_auxiliary_id_table,
	.probe = i40iw_probe,
	.remove = i40iw_remove,
};
