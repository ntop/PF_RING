/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2013-2023 Intel Corporation */

#include <linux/idr.h>
#include "iavf.h"
#include "iavf_idc.h"

static DEFINE_IDA(iavf_idc_ida);

/**
 * iavf_idc_is_adapter_ready - is the adapter is ready to process IDC requests
 * @adapter: driver specific private data
 *
 * If the adapter is currently in reset this means that the adapter is not ready
 * to process IDC requests as virtchnl is not ready.
 *
 * If the adapter is currently being removed this means that the adapter is
 * being torn down and virtchnl processing has already been disabled.
 *
 * This function needs to be checked before any IDC processing happens. Returns
 * true if IDC processing is allowed and false if it should be
 * rejected/prevented.
 */
static bool iavf_idc_is_adapter_ready(struct iavf_adapter *adapter)
{
	if (iavf_is_reset_in_progress(adapter)) {
		dev_dbg(&adapter->pdev->dev, "Adapter is in reset, preventing IDC communication\n");
		return false;
	}

	if (iavf_is_remove_in_progress(adapter)) {
		dev_dbg(&adapter->pdev->dev, "Adapter is being removed, preventing IDC communication\n");
		return false;
	}

	return true;
}

/**
 * iavf_get_auxiliary_drv - retrieve iidc_auxiliary_drv structure
 * @cdev_info: pointer to iidc_core_dev_info struct
 *
 * This function has to be called with a device_lock on the
 * cdev_info->adev.dev to avoid race conditions.
 */
static struct iidc_auxiliary_drv *
iavf_get_auxiliary_drv(struct iidc_core_dev_info *cdev_info)
{
	struct auxiliary_device *adev;

	if (!cdev_info)
		return NULL;

	adev = cdev_info->adev;
	if (!adev || !adev->dev.driver)
		return NULL;

	return container_of(adev->dev.driver, struct iidc_auxiliary_drv,
			    adrv.driver);
}

/**
 * iavf_idc_vc_receive - Used to pass the received msg over IDC
 * @adapter: driver specific private data
 * @msg: payload received on mailbox
 * @msg_size: size of the payload
 *
 * This function is used by the Auxiliary Device to pass the receive mailbox
 * message an Auxiliary Driver cell
 */
void iavf_idc_vc_receive(struct iavf_adapter *adapter, u8 *msg, u16 msg_size)
{
	struct iavf_rdma *rdma = &adapter->rdma;
	struct iidc_core_dev_info *cdev_info;
	struct iidc_auxiliary_drv *iadrv;
	int err = 0;

	if (!iavf_idc_is_adapter_ready(adapter))
		return;

	if (!rdma->cdev_info || !rdma->cdev_info->adev)
		return;

	cdev_info = rdma->cdev_info;

	device_lock(&cdev_info->adev->dev);
	iadrv = iavf_get_auxiliary_drv(cdev_info);
	if (iadrv && iadrv->vc_receive)
		iadrv->vc_receive(cdev_info, 0, msg, msg_size);
	device_unlock(&cdev_info->adev->dev);
	if (err)
		pr_err("Failed to pass receive idc msg, err %d\n", err);
}

/**
 * iavf_idc_request_reset - Called by an Auxiliary Driver
 * @cdev_info: IIDC device specific pointer
 * @reset_type: function, core or other
 *
 * This callback function is accessed by an Auxiliary Driver to request a reset
 * on the Auxiliary Device
 */
static int
iavf_idc_request_reset(struct iidc_core_dev_info *cdev_info,
		       enum iidc_reset_type __always_unused reset_type)
{
	struct iavf_adapter *adapter =
		netdev_priv(pci_get_drvdata(cdev_info->pdev));

	if (!iavf_idc_is_adapter_ready(adapter))
		return -ENODEV;

	iavf_schedule_reset(adapter);

	return 0;
}

/**
 * iavf_idc_vc_send - Called by an Auxiliary Driver
 * @cdev_info: IIDC device specific pointer
 * @vf_id: always unused
 * @msg: payload to be sent
 * @msg_size: size of the payload
 *
 * This callback function is accessed by an Auxiliary Driver to request a send
 * on the mailbox queue
 */
static int
iavf_idc_vc_send(struct iidc_core_dev_info *cdev_info,
		 u32 __always_unused vf_id, u8 *msg, u16 msg_size)
{
	struct iavf_adapter *adapter;
	struct iavf_vc_msg *vc_msg;

	if (cdev_info->cdev_info_id != IIDC_RDMA_ID)
		return -EINVAL;

	adapter = iavf_pdev_to_adapter(cdev_info->pdev);
	if (!iavf_idc_is_adapter_ready(adapter))
		return -ENODEV;

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_RDMA, msg_size);
	if (!vc_msg)
		return -ENOMEM;

	memcpy(vc_msg->msg, msg, msg_size);


	iavf_queue_vc_msg(adapter, vc_msg);

	return 0;
}

/**
 * iavf_idc_wait_for_rdma_vc_event - wait for RDMA virtchnl event or timeout
 * @adapter: pointer to the private adapter structure
 *
 * After sending a RDMA message over virtchnl to the PF, the driver can use this
 * to wait for a response.
 *
 * The caller is expected to set the vc_op_state to IAVF_RDMA_VC_OP_PENDING
 * before calling this function and set the vc_op_state to
 * IAVF_RDMA_VC_OP_NO_WORK after it returns.
 *
 * If the vc_op_state doesn't change to IAVF_RDMA_VC_OP_FAILED or
 * IAVF_RDMA_VC_OP_COMPLETE before the timeout time, then return -ETIMEDOUT.
 *
 * Otherwise set the return value based on the result of the virtchnl response.
 */
static int iavf_idc_wait_for_rdma_vc_event(struct iavf_adapter *adapter)
{
	enum iavf_rdma_vc_op_state vc_op_state;
	int err;

	err = wait_event_interruptible_timeout(adapter->rdma.vc_op_waitqueue,
					       adapter->rdma.vc_op_state >
					       IAVF_RDMA_VC_OP_PENDING,
					       HZ * 2);

	vc_op_state = adapter->rdma.vc_op_state;

	switch (vc_op_state) {
	case IAVF_RDMA_VC_OP_PENDING:
		return err < 0 ? err : -ETIMEDOUT;
	case IAVF_RDMA_VC_OP_FAILED:
		return err < 0 ? err : -EAGAIN;
	case IAVF_RDMA_VC_OP_COMPLETE:
		return err < 0 ? err : 0;
	default:
		WARN(1, "Unexpected RDMA op state %u", vc_op_state);
		return -EINVAL;
	}
}

/**
 * iavf_idc_vc_send_sync - syncrhonous version of vc_send
 * @cdev_info: core device info pointer
 * @send_msg: message to send to PF
 * @msg_size: size of message to send to PF
 * @recv_msg: message to populate on reception of response from PF
 * @recv_len: length of message copied into recv_msg or 0 on error
 */
static int
iavf_idc_vc_send_sync(struct iidc_core_dev_info *cdev_info, u8 *send_msg,
		      u16 msg_size, u8 *recv_msg, u16 *recv_len)
{
	struct iavf_adapter *adapter = iavf_pdev_to_adapter(cdev_info->pdev);
	int err;

	if (!recv_msg || !recv_len || *recv_len > IAVF_MAX_AQ_BUF_SIZE)
		return -EINVAL;

	adapter->rdma.vc_op_state = IAVF_RDMA_VC_OP_PENDING;
	err = iavf_idc_vc_send(cdev_info, 0, send_msg, msg_size);
	if (err) {
		if (err != -ENODEV)
			dev_err(&adapter->pdev->dev, "Failed to send VIRTCHNL_OP_RDMA message, err %d\n",
				err);
		else
			dev_dbg(&adapter->pdev->dev, "Adapter is not ready to send virtchnl requests, err %d\n",
				err);
	} else {
		err = iavf_idc_wait_for_rdma_vc_event(adapter);
		if (!err) {
			u16 size = min_t(u16, *recv_len,
					 adapter->rdma.recv_sync_msg_size);

			memcpy(recv_msg, adapter->rdma.recv_sync_msg, size);
			*recv_len = size;
		}
	}

	/* clear value for all failure cases */
	if (err)
		*recv_len = 0;

	adapter->rdma.vc_op_state = IAVF_RDMA_VC_OP_NO_WORK;
	adapter->rdma.recv_sync_msg_size = 0;
	memset(adapter->rdma.recv_sync_msg, 0, IAVF_MAX_AQ_BUF_SIZE);

	return err;
}

/**
 * iavf_vc_rdma_qv_map - queue message to configure RDMA IRQ map
 * @adapter: private adapter structure
 * @qvl_info: queue to vector mapping information used for configuration
 */
static int
iavf_vc_rdma_qv_map(struct iavf_adapter *adapter,
		    struct iidc_qvlist_info *qvl_info)
{
	struct virtchnl_rdma_qvlist_info *vc_qvl_info;
	struct iavf_vc_msg *vc_msg;
	int size;
	u32 i;

	if (!qvl_info || !qvl_info->num_vectors ||
	    qvl_info->num_vectors > adapter->rdma.num_msix) {
		dev_err(&adapter->pdev->dev, "Invalid MSIX vector information from IDC driver\n");
		return -EINVAL;
	}

	size = sizeof(struct virtchnl_rdma_qvlist_info) +
		(sizeof(struct virtchnl_rdma_qv_info) *
		 (qvl_info->num_vectors - 1));

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP, size);
	if (!vc_msg)
		return -ENOMEM;

	vc_qvl_info = (typeof(vc_qvl_info))vc_msg->msg;
	vc_qvl_info->num_vectors = qvl_info->num_vectors;

	for (i = 0; i < vc_qvl_info->num_vectors; i++) {
		struct iidc_qv_info *iidc_qv_info = &qvl_info->qv_info[i];
		struct virtchnl_rdma_qv_info *vc_qv_info =
			&vc_qvl_info->qv_info[i];

		if (iidc_qv_info->v_idx >=
		    (adapter->rdma.num_msix + adapter->num_msix_vectors)) {
			dev_err(&adapter->pdev->dev, "Invalid MSIX index from IDC driver %d\n",
				iidc_qv_info->v_idx);
			kfree(vc_msg);
			return -EINVAL;
		}

		vc_qv_info->v_idx = iidc_qv_info->v_idx;
		vc_qv_info->ceq_idx = iidc_qv_info->ceq_idx;
		vc_qv_info->aeq_idx = iidc_qv_info->aeq_idx;
		vc_qv_info->itr_idx = iidc_qv_info->itr_idx;
	}

	iavf_queue_vc_msg(adapter, vc_msg);

	return 0;
}

/**
 * iavf_vc_rdma_qv_unmap - queue message to release RDMA IRQ map
 * @adapter: private adapter structure
 */
static int iavf_vc_rdma_qv_unmap(struct iavf_adapter *adapter)
{
	struct iavf_vc_msg *vc_msg;

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP, 0);
	if (!vc_msg)
		return -ENOMEM;

	iavf_queue_vc_msg(adapter, vc_msg);

	return 0;
}

/**
 * iavf_idc_vc_qv_map_unmap - Called by an Auxiliary Driver
 * @cdev_info: IIDC device specific pointer
 * @qvl_info: payload to be sent on mailbox
 * @map: map or unmap
 *
 * This callback function is called by an Auxiliary Driver to request a map or
 * unmap of queues to vectors on mailbox queue
 */
static int
iavf_idc_vc_qv_map_unmap(struct iidc_core_dev_info *cdev_info,
			 struct iidc_qvlist_info *qvl_info, bool map)
{
	struct iavf_adapter *adapter = iavf_pdev_to_adapter(cdev_info->pdev);
	int err;

	if (!iavf_idc_is_adapter_ready(adapter)) {
		dev_dbg(&adapter->pdev->dev, "Adapter is not ready to map/unmap RDMA queue vector over virtchnl\n");
		return -ENODEV;
	}

	adapter->rdma.vc_op_state = IAVF_RDMA_VC_OP_PENDING;

	if (map)
		err = iavf_vc_rdma_qv_map(adapter, qvl_info);
	else
		err = iavf_vc_rdma_qv_unmap(adapter);
	if (err)
		dev_err(&adapter->pdev->dev, "Failed to send RDMA queue vector map/unmap message, err %d\n",
			err);
	else
		err = iavf_idc_wait_for_rdma_vc_event(adapter);

	adapter->rdma.vc_op_state = IAVF_RDMA_VC_OP_NO_WORK;

	return err;
}

/* Implemented by the Auxiliary Device and called by the Auxiliary Driver */
static const struct iidc_core_ops idc_ops = {
	.request_reset                  = iavf_idc_request_reset,
	.vc_send                        = iavf_idc_vc_send,
	.vc_send_sync			= iavf_idc_vc_send_sync,
	.vc_queue_vec_map_unmap         = iavf_idc_vc_qv_map_unmap,
};

/**
 * iavf_adev_release - function to be mapped to aux dev's release op
 * @dev: pointer to device to free
 */
static void iavf_adev_release(struct device *dev)
{
	struct iidc_auxiliary_dev *iadev;

	iadev = container_of(dev, struct iidc_auxiliary_dev, adev.dev);
	kfree(iadev);
	iadev = NULL;
}

/* iavf_plug_aux_dev - allocate and register an Auxiliary device
 * @pf: pointer to pf struct
 *
 * This function must not be called while the __IAVF_IN_CRITICAL_TASK bit is
 * held because this will synchronously call irdma_probe() if the irdma driver
 * is loaded, which may rely on sending/receiving virtchnl messages. Currently,
 * sending/receiving virtchnl messages relies on holding the
 * __IAVF_IN_CRITICAL_TASK bit. Without taking this precaution there could be a
 * deadlock.
 */
static int iavf_plug_aux_dev(struct iavf_rdma *rdma)
{
	struct iidc_core_dev_info *cdev_info;
	struct iidc_auxiliary_dev *iadev;
	struct auxiliary_device *adev;
	int err;

	cdev_info = rdma->cdev_info;
	if (!cdev_info)
		return -ENODEV;

	rdma->aux_idx = ida_alloc(&iavf_idc_ida, GFP_KERNEL);
	if (rdma->aux_idx < 0) {
		pr_err("failed to allocate unique device ID for Auxiliary driver\n");
		return -ENOMEM;
	}

	iadev = kzalloc(sizeof(*iadev), GFP_KERNEL);
	if (!iadev) {
		err = -ENOMEM;
		goto err_iadev_alloc;
	}

	adev = &iadev->adev;
	cdev_info->adev = adev;
	iadev->cdev_info = cdev_info;

	if (cdev_info->rdma_protocol == IIDC_RDMA_PROTOCOL_IWARP)
		adev->name = IIDC_RDMA_IWARP_NAME;
	else
		adev->name = IIDC_RDMA_ROCE_NAME;

	adev->id = rdma->aux_idx;
	adev->dev.release = iavf_adev_release;
	adev->dev.parent = &cdev_info->pdev->dev;

	err = auxiliary_device_init(adev);
	if (err)
		goto err_aux_dev_init;

	err = auxiliary_device_add(adev);
	if (err)
		goto err_aux_dev_add;

	return 0;

err_aux_dev_add:
	cdev_info->adev = NULL;
	auxiliary_device_uninit(adev);
err_aux_dev_init:
	kfree(iadev);
err_iadev_alloc:
	ida_free(&iavf_idc_ida, rdma->aux_idx);

	return err;
}

/* iavf_unplug_aux_dev - unregister and free an Auxiliary device
 * @pf: pointer to pf struct
 *
 * This function must not be called while the __IAVF_IN_CRITICAL_TASK bit is
 * held because this will synchronously call irdma_remove() if the irdma driver
 * is loaded, which may rely on sending/receiving virtchnl messages. Currently,
 * sending/receiving virtchnl messages relies on holding the
 * __IAVF_IN_CRITICAL_TASK bit. Without taking this precaution there could be a
 * deadlock.
 */
static void iavf_unplug_aux_dev(struct iavf_rdma *rdma)
{
	struct auxiliary_device *adev;

	if (!rdma->cdev_info)
		return;

	adev = rdma->cdev_info->adev;
	auxiliary_device_delete(adev);
	auxiliary_device_uninit(adev);
	adev = NULL;

	ida_free(&iavf_idc_ida, rdma->aux_idx);
}

/**
 * iavf_idc_init_msix_data - initialize MSIX data for the cdev_info structure
 * @adapter: driver private data structure
 */
static void
iavf_idc_init_msix_data(struct iavf_adapter *adapter)
{
	struct iidc_core_dev_info *cdev_info;
	struct iavf_rdma *rdma;
	int idc_vector_start;

	if (!adapter->msix_entries)
		return;

	rdma = &adapter->rdma;
	cdev_info = rdma->cdev_info;

	cdev_info->msix_count = rdma->num_msix;
	/* don't give pointer to msix_entries if there are no MSIX  */
	if (rdma->num_msix) {
		idc_vector_start = adapter->num_msix_vectors;
		cdev_info->msix_entries =
			&adapter->msix_entries[idc_vector_start];
	}
}

/**
 * iavf_idc_init_qos_info - initialialize default QoS information
 * @qos_info: QoS information structure to populate
 */
static void
iavf_idc_init_qos_info(struct iidc_qos_params *qos_info)
{
	int i;

	qos_info->num_apps = 0;
	qos_info->num_tc = 1;

	for (i = 0; i < IIDC_MAX_USER_PRIORITY; i++)
		qos_info->up2tc[i] = 0;

	qos_info->tc_info[0].rel_bw = 100;
	for (i = 1; i < IEEE_8021QAZ_MAX_TCS; i++)
		qos_info->tc_info[i].rel_bw = 0;
}

/**
 * iavf_idc_clear_rdma_info - clear RDMA info that may be updated on reset/init
 * @rdma: Pointer to the RDMA specific information
 *
 * This function will be called if creating the auxiliary device for RDMA fails
 * or when tearing down the auxiliary device for RDMA.
 */
static void iavf_idc_clear_rdma_info(struct iavf_rdma *rdma)
{
	kfree(rdma->cdev_info);
	rdma->cdev_info = NULL;
	rdma->aux_idx = -1;
	rdma->recv_sync_msg_size = 0;
	memset(rdma->recv_sync_msg, 0, IAVF_MAX_AQ_BUF_SIZE);
	rdma->vc_op_state = IAVF_RDMA_VC_OP_NO_WORK;
}

/**
 * iavf_idc_init_aux_device - initialize Auxiliary Device
 * @adapter: driver private data structure
 */
static int
iavf_idc_init_aux_device(struct iavf_adapter *adapter)
{
	struct iavf_rdma *rdma = &adapter->rdma;
	struct iidc_core_dev_info *cdev_info;
	int err;

	/* structure layout needed for container_of's looks like:
	 * iidc_auxiliary_dev (container_of super-struct for adev)
	 * |--> auxiliary_device
	 * |--> *iidc_core_dev_info (pointer from cdev_info struct)
	 *
	 * The iidc_auxiliary_device has a lifespan as long as it
	 * is on the bus.  Once removed it will be freed and a new
	 * one allocated if needed to re-add.
	 */
	rdma->cdev_info = kzalloc(sizeof(struct iidc_core_dev_info),
				  GFP_KERNEL);
	if (!rdma->cdev_info) {
		err = -ENOMEM;
		goto err_out;
	}

	cdev_info = rdma->cdev_info;
	cdev_info->hw_addr = (typeof(cdev_info->hw_addr))adapter->hw.hw_addr;
	cdev_info->ver.major = IIDC_MAJOR_VER;
	cdev_info->ver.minor = IIDC_MINOR_VER;
	cdev_info->ftype = IIDC_FUNCTION_TYPE_VF;
	cdev_info->vport_id = adapter->vsi_res->vsi_id;
	cdev_info->netdev = adapter->netdev;
	cdev_info->pdev = adapter->pdev;
	cdev_info->ops = &idc_ops;
	cdev_info->rdma_protocol = IIDC_RDMA_PROTOCOL_IWARP;
	cdev_info->cdev_info_id = IIDC_RDMA_ID;

	iavf_idc_init_qos_info(&cdev_info->qos_info);
	iavf_idc_init_msix_data(adapter);

	err = iavf_plug_aux_dev(rdma);
	if (err)
		goto err_out;

	return 0;

err_out:
	iavf_idc_clear_rdma_info(rdma);

	return err;
}

/**
 * iavf_idc_deinit_aux_device - de-initialize Auxiliary Device
 * @adapter: driver private data structure
 */
static void iavf_idc_deinit_aux_device(struct iavf_adapter *adapter)
{
	struct iavf_rdma *rdma = &adapter->rdma;

	iavf_unplug_aux_dev(rdma);
	iavf_idc_clear_rdma_info(rdma);
}

/**
 * iavf_idc_init_task - delayed worker to setup IDC/Auxiliary for RDMA
 * @work: pointer to work_struct
 *
 * Since rdma_probe() may depend on sending/receiving virtchnl messages, the
 * driver doesn't want to call this while the __IAVF_IN_CRITICAL_TASK bit is
 * set. To prevent deadlock, perform IDC/Auxiliary initialization from a delayed
 * work task.
 */
void iavf_idc_init_task(struct work_struct *work)
{
	struct iavf_rdma *rdma = container_of(work, struct iavf_rdma,
					      init_task.work);
	struct iavf_adapter *adapter = rdma->back;
	int err;

	err = iavf_idc_init_aux_device(adapter);
	if (err)
		dev_err(&adapter->pdev->dev, "failed to initialize IDC: %d\n",
			err);
}

/**
 * iavf_idc_init - Called to initialize IDC
 * @adapter: driver private data structure
 */
void iavf_idc_init(struct iavf_adapter *adapter)
{
	if (!RDMA_ALLOWED(adapter))
		return;

	queue_delayed_work(iavf_wq, &adapter->rdma.init_task,
			   msecs_to_jiffies(5));
}

/**
 * iavf_rdma_op_match - used to check if virtchnl message is an RDMA message
 * @pending_op: virtchnl opcode that's pending on the virtchnl message queue
 */
static bool iavf_rdma_op_match(enum virtchnl_ops pending_op)
{
	if (pending_op == VIRTCHNL_OP_RDMA ||
	    pending_op == VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP ||
	    pending_op == VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP)
		return true;

	return false;
}

/**
 * iavf_idc_deinit - Called to de-initialize IDC
 * @adapter: driver private data structure
 */
void iavf_idc_deinit(struct iavf_adapter *adapter)
{
	/* make sure any init work is done before deinit */
	cancel_delayed_work_sync(&adapter->rdma.init_task);

	/* don't leave pending opeartions on deinit */
	iavf_flush_vc_msg_queue(adapter, iavf_rdma_op_match);

	iavf_idc_deinit_aux_device(adapter);
}
