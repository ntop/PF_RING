/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2013-2023 Intel Corporation */

#include "iavf.h"

/**
 * iavf_virtchnl_gnss_read_i2c - Respond to opcode
 * VIRTCHNL_OP_GNSS_READ_I2C
 * @adapter: private adapter structure
 * @data: the message from the PF
 * @len: length of the message from the PF
 *
 * Handle the VIRTCHNL_OP_GNSS_READ_I2C message from the PF.
 * This message is sent by the PF in response to the same op as a request
 * from the VF.
 * Extract the message from the data store it in read_i2c_resp.
 * Then, notify any thread that is waiting for the update via the wait queue.
 */
void iavf_virtchnl_gnss_read_i2c(struct iavf_adapter *adapter,
				 void *data, u16 len)
{
	struct device *dev = &adapter->pdev->dev;
	struct iavf_gnss *gnss = &adapter->gnss;
	struct virtchnl_gnss_read_i2c_resp *msg;

	if (len == sizeof(*msg)) {
		msg = data;
	} else {
		dev_err_once(dev,
			     "Invalid gnss i2c read got size %u, expected %lu\n",
			     len, sizeof(*msg));
		return;
	}

	memcpy(&gnss->read_i2c_resp, msg, len);
	dev_dbg(dev, "%s: data %u: len %u\n", __func__, msg->i2c_data[0], len);
	gnss->i2c_read_ready = true;
	wake_up(&gnss->i2c_read_waitqueue);
}

/**
 * iavf_virtchnl_gnss_write_i2c - Respond to opcode
 * VIRTCHNL_OP_GNSS_WRITE_I2C
 * @adapter: private adapter structure
 *
 * Handle the VIRTCHNL_OP_GNSS_WRITE_I2C message from the PF.
 * This message is sent by the PF in response to the same op as a request
 * from the VF.
 */
void iavf_virtchnl_gnss_write_i2c(struct iavf_adapter *adapter)
{
	struct iavf_gnss *gnss = &adapter->gnss;

	gnss->i2c_write_ready = true;
	wake_up(&gnss->i2c_write_waitqueue);
}

/**
 * iavf_gnss_read_i2c
 * @adapter: pointer to iavf adapter
 * @topo_addr: topology address for a device to communicate with
 * @bus_addr: 7-bit I2C bus address
 * @addr: I2C memory address (I2C offset) with up to 16 bits
 * @params: I2C parameters: bit [7] - Repeated start, bits [6:5] data offset size,
 *			    bit [4] - I2C address type, bits [3:0] - data size to read (0-16 bytes)
 * @data: pointer to data (0 to 16 bytes) to be read from the I2C device
 *
 * Read I2C (0x06E2)
 */
static int
iavf_gnss_read_i2c(struct iavf_adapter *adapter,
		   struct virtchnl_link_topo_addr topo_addr, u16 bus_addr,
		   u16 addr, u8 params, u8 *data)
{
	struct device *dev = &adapter->pdev->dev;
	struct iavf_gnss *gnss = &adapter->gnss;
	struct virtchnl_gnss_i2c *cmd;
	struct iavf_vc_msg *vc_msg;
	u8 data_size;
	int status;

	if (!data)
		return IAVF_ERR_PARAM;


	data_size = (params & VIRTCHNL_I2C_DATA_SIZE_M)
		     >> VIRTCHNL_I2C_DATA_SIZE_S;

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_GNSS_READ_I2C, sizeof(*cmd));
	if (!vc_msg)
		return -ENOMEM;

	cmd = (typeof(cmd))vc_msg->msg;
	cmd->i2c_bus_addr = bus_addr;
	cmd->topo_addr = topo_addr;
	cmd->i2c_params = params;
	cmd->i2c_addr = addr;

	iavf_queue_vc_msg(adapter, vc_msg);

	/* Handle the response from PF */
	gnss->i2c_read_ready = false;
	status = wait_event_interruptible_timeout(gnss->i2c_read_waitqueue,
						  gnss->i2c_read_ready,
						  HZ);
	if (status < 0)
		return status;
	else if (!status)
		return -EBUSY;

	memcpy(data, gnss->read_i2c_resp.i2c_data, data_size);

	dev_dbg(dev,
		"%s: bus_addr: %04x addr: %04x Data Bytes Read: %u B0: %x B1: %x\n",
		__func__, bus_addr, addr, data_size, data[0], data[1]);

	return 0;
}

/**
 * iavf_gnss_write_i2c
 * @adapter: pointer to the iavf_adapter struct
 * @topo_addr: topology address for a device to communicate with
 * @bus_addr: 7-bit I2C bus address
 * @addr: I2C memory address (I2C offset) with up to 16 bits
 * @params: I2C parameters: bit [4] - I2C address type, bits [3:0] - data size to write (0-7 bytes)
 * @data: pointer to data (0 to 4 bytes) to be written to the I2C device
 *
 * Write I2C (0x06E3)
 */
static int
iavf_gnss_write_i2c(struct iavf_adapter *adapter,
		    struct virtchnl_link_topo_addr topo_addr,
		    u16 bus_addr, u16 addr, u8 params, u8 *data)
{
	struct device *dev = &adapter->pdev->dev;
	struct iavf_gnss *gnss = &adapter->gnss;
	struct virtchnl_gnss_i2c *cmd;
	struct iavf_vc_msg *vc_msg;
	u8 data_size;
	int status;

	if (!data)
		return IAVF_ERR_PARAM;

	dev_dbg(dev,
		"%s: lport_num %u: lport_num_valid %u: node_type_ctx %u: index: %u: handle %u\n",
		__func__, topo_addr.topo_params.lport_num,
		topo_addr.topo_params.lport_num_valid,
		topo_addr.topo_params.node_type_ctx,
		topo_addr.topo_params.index, topo_addr.handle);
	dev_dbg(dev, "%s: bus_addr: %u addr: %u params: %u\n",
		__func__, bus_addr, addr, params);

	vc_msg = iavf_alloc_vc_msg(VIRTCHNL_OP_GNSS_WRITE_I2C, sizeof(*cmd));
	if (!vc_msg)
		return -ENOMEM;

	data_size = (params & VIRTCHNL_I2C_DATA_SIZE_M)
		     >> VIRTCHNL_I2C_DATA_SIZE_S;

	/* data_size limited to IAVF_MAX_I2C_WRITE_BYTES */
	if (data_size > IAVF_MAX_I2C_WRITE_BYTES) {
		kfree(vc_msg);
		return IAVF_ERR_PARAM;
	}

	cmd = (typeof(cmd))vc_msg->msg;
	cmd->i2c_bus_addr = bus_addr;
	cmd->topo_addr = topo_addr;
	cmd->i2c_params = params;
	cmd->i2c_addr = addr;
	memcpy(cmd->i2c_data, data, data_size);

	iavf_queue_vc_msg(adapter, vc_msg);

	/* Handle the response from PF */
	gnss->i2c_write_ready = false;
	status = wait_event_interruptible_timeout(gnss->i2c_write_waitqueue,
						  gnss->i2c_write_ready,
						  HZ);
	if (status < 0)
		return status;
	else if (!status)
		return -EBUSY;

	return 0;
}

/**
 * iavf_gnss_do_write - Write data to internal GNSS
 * @adapter: board private structure
 * @buf: command buffer
 * @size: command buffer size
 *
 * Write UBX command data to the GNSS receiver
 */
static unsigned int
iavf_gnss_do_write(struct iavf_adapter *adapter, unsigned char *buf,
		   unsigned int size)
{
	struct virtchnl_link_topo_addr link_topo;
	struct device *dev = &adapter->pdev->dev;
	unsigned int offset = 0;
	int err;

	memset(&link_topo, 0, sizeof(struct virtchnl_link_topo_addr));
	link_topo.topo_params.index = IAVF_E810T_GNSS_I2C_BUS;
	link_topo.topo_params.node_type_ctx |=
		VIRTCHNL_LINK_TOPO_NODE_CTX_OVERRIDE <<
		VIRTCHNL_LINK_TOPO_NODE_CTX_S;

	/* It's not possible to write a single byte to u-blox.
	 * Write all bytes in a loop until there are 6 or less bytes left. If
	 * there are exactly 6 bytes left, the last write would be only a byte.
	 * In this case, do 4+2 bytes writes instead of 5+1. Otherwise, do the
	 * last 2 to 5 bytes write.
	 */
	while (size - offset > IAVF_GNSS_UBX_WRITE_BYTES + 1) {
		err = iavf_gnss_write_i2c(adapter, link_topo,
					  IAVF_GNSS_UBX_I2C_BUS_ADDR,
					  buf[offset],
					  IAVF_MAX_I2C_WRITE_BYTES,
					  &buf[offset + 1]);
		if (err)
			goto exit;

		offset += IAVF_GNSS_UBX_WRITE_BYTES;
	}

	/* Single byte would be written. Write 4 bytes instead of 5. */
	if (size - offset == IAVF_GNSS_UBX_WRITE_BYTES + 1) {
		err = iavf_gnss_write_i2c(adapter, link_topo,
					  IAVF_GNSS_UBX_I2C_BUS_ADDR,
					  buf[offset],
					  IAVF_MAX_I2C_WRITE_BYTES - 1,
					  &buf[offset + 1]);
		if (err)
			goto exit;

		offset += IAVF_GNSS_UBX_WRITE_BYTES - 1;
	}

	/* Do the last write, 2 to 5 bytes. */
	err = iavf_gnss_write_i2c(adapter, link_topo,
				  IAVF_GNSS_UBX_I2C_BUS_ADDR,
				  buf[offset], size - offset - 1,
				  &buf[offset + 1]);
	if (!err)
		offset = size;

exit:
	if (err)
		dev_err(dev,
			"GNSS failed to write, offset=%u, size=%u, status=%d\n",
			offset, size, err);

	return offset;
}

/**
 * iavf_gnss_write_pending - Write all pending data to internal GNSS
 * @work: GNSS write work structure
 */
static void iavf_gnss_write_pending(struct kthread_work *work)
{
	struct iavf_gnss_serial *gnss_serial;
	struct iavf_adapter *adapter;
	struct device *dev;

	gnss_serial = container_of(work,
				   struct iavf_gnss_serial,
				   write_work);

	adapter = gnss_serial->back;
	if (!adapter)
		return;

	dev = &adapter->pdev->dev;

	while (!list_empty(&gnss_serial->queue)) {
		struct iavf_gnss_write_buf *write_buf = NULL;
		unsigned int bytes;

		write_buf = list_first_entry(&gnss_serial->queue,
					     struct iavf_gnss_write_buf,
					     queue);

		bytes = iavf_gnss_do_write(adapter, write_buf->buf,
					   write_buf->size);
		dev_dbg(dev, "%u bytes written to GNSS\n", bytes);

		list_del(&write_buf->queue);
		kfree(write_buf->buf);
		kfree(write_buf);
	}
}

/**
 * iavf_gnss_read - Read data from internal GNSS module
 * @work: GNSS read work structure
 *
 * Read the data from internal GNSS receiver, number of bytes read will be
 * returned in *read_data parameter.
 */
static void iavf_gnss_read(struct kthread_work *work)
{
	struct virtchnl_link_topo_addr link_topo;
	struct iavf_gnss_serial *gnss_serial;
	unsigned int i, bytes_read, data_len;
	struct iavf_adapter *adapter;
	struct tty_port *port;
	struct device *dev;
	u8 data_len_b[2];
	u8 *buf = NULL;
	u8 i2c_params;
	int err = 0;

	gnss_serial = container_of(work,
				   struct iavf_gnss_serial,
				   read_work.work);
	adapter = gnss_serial->back;
	if (!adapter || !gnss_serial->tty || !gnss_serial->tty->port)
		return;

	dev = &adapter->pdev->dev;
	port = gnss_serial->tty->port;

	buf = (u8 *)get_zeroed_page(GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto exit;
	}

	memset(&link_topo, 0, sizeof(struct virtchnl_link_topo_addr));
	link_topo.topo_params.index = IAVF_E810T_GNSS_I2C_BUS;
	link_topo.topo_params.node_type_ctx |=
		VIRTCHNL_LINK_TOPO_NODE_CTX_OVERRIDE <<
		VIRTCHNL_LINK_TOPO_NODE_CTX_S;

	i2c_params = IAVF_GNSS_UBX_DATA_LEN_WIDTH |
		     VIRTCHNL_I2C_USE_REPEATED_START;

	/* Read data length in a loop, when it's not 0 the data is ready */
	for (i = 0; i < IAVF_MAX_UBX_READ_TRIES; i++) {
		err = iavf_gnss_read_i2c(adapter, link_topo,
					 IAVF_GNSS_UBX_I2C_BUS_ADDR,
					 IAVF_GNSS_UBX_DATA_LEN_H,
					 i2c_params, data_len_b);
		if (err)
			goto exit_buf;

		data_len = data_len_b[0]*256 + data_len_b[1];
		if (data_len != 0 && data_len != U16_MAX) {
			/* Get The Data Length of UBLOX Available Data @ UBLOX Module
			 * TRACE: UBLOX Link Topology, I2C Bus Address, Data Length
			 * Register Address,
			 * I2C Parameter (Data Length of 2 Bytes, Repeated Start)
			 * Data got back from UBLOX is Big-Endian, so be16_to_cpu as
			 * PF passes it as byte arrary
			 */
			dev_dbg(dev,
				"%s: lport_num: %u lport_num_valid: %u node_type_ctx: %u index: %u handle: %u\n",
				__func__, link_topo.topo_params.lport_num,
				link_topo.topo_params.lport_num_valid,
				link_topo.topo_params.node_type_ctx,
				link_topo.topo_params.index, link_topo.handle);
			dev_dbg(dev, "%s: bus_addr: %04x addr: %04x params: %x Date Size %u\n",
				__func__, IAVF_GNSS_UBX_I2C_BUS_ADDR, IAVF_GNSS_UBX_DATA_LEN_H,
				i2c_params, data_len);
			break;
		}

		msleep(20);
	}

	/* In case no data available, just schedule another read */
	if (i == IAVF_MAX_UBX_READ_TRIES)
		goto exit_buf;

	/* Data size can not be more than 4K for one read due to tty limit
	 * and Buffer size.
	 * Multiple page upload required if so
	 */
	data_len = min_t(typeof(data_len), data_len, PAGE_SIZE);
	data_len = tty_buffer_request_room(port, data_len);
	if (!data_len) {
		err = -ENOMEM;
		goto exit_buf;
	}

	/* Read received data */
	for (i = 0; i < data_len; i += bytes_read) {
		unsigned int bytes_left = data_len - i;

		bytes_read = min_t(typeof(bytes_left), bytes_left,
				   IAVF_MAX_I2C_DATA_SIZE);

		/* Get Available Data @ UBLOX Module in chunks
		 * TRACE: UBLOX Link Topology, I2C Bus Address, Empty Data Register Address,
		 * I2C Parameter (Number of Bytes to Read)
		 * Data got back from UBLOX
		 */
		if (i == 0 || bytes_read < IAVF_MAX_I2C_DATA_SIZE ||
		    ((bytes_read == IAVF_MAX_I2C_DATA_SIZE) &&
		    (i == data_len - IAVF_MAX_I2C_DATA_SIZE)))
			dev_dbg(dev,
				"%s: bus_addr: %04x addr: %04x Bytes to be read: %u\n",
				__func__, IAVF_GNSS_UBX_I2C_BUS_ADDR,
				IAVF_GNSS_UBX_EMPTY_DATA, bytes_read);

		err = iavf_gnss_read_i2c(adapter, link_topo,
					 IAVF_GNSS_UBX_I2C_BUS_ADDR,
					 IAVF_GNSS_UBX_EMPTY_DATA,
					 bytes_read, &buf[i]);
		if (err)
			goto exit_buf;
	}

	/* Send the data to the tty layer for users to read. This doesn't
	 * actually push the data through unless tty->low_latency is set.
	 */
	tty_insert_flip_string(port, (char *)buf, i);
	tty_flip_buffer_push(port);

exit_buf:
	free_page((unsigned long)buf);
	kthread_queue_delayed_work(gnss_serial->kworker,
				   &gnss_serial->read_work,
				   IAVF_GNSS_TIMER_DELAY_TIME);
exit:
	if (err)
		dev_dbg(dev, "GNSS failed to read err=%d\n", err);
}

/**
 * iavf_gnss_struct_init - Initialize GNSS structure for the TTY
 * @adapter: Board private structure
 * @index: TTY device index
 */
static struct iavf_gnss_serial *
iavf_gnss_struct_init(struct iavf_adapter *adapter, int index)
{
	struct device *dev = &adapter->pdev->dev;
	struct iavf_gnss_serial *gnss_serial;
	struct kthread_worker *kworker;

	gnss_serial = kzalloc(sizeof(*gnss_serial), GFP_KERNEL);
	if (!gnss_serial)
		return NULL;

	mutex_init(&gnss_serial->gnss_mutex);
	gnss_serial->open_count = 0;
	gnss_serial->back = adapter;
	adapter->gnss.serial = gnss_serial;

	kthread_init_delayed_work(&gnss_serial->read_work, iavf_gnss_read);
	INIT_LIST_HEAD(&gnss_serial->queue);
	kthread_init_work(&gnss_serial->write_work, iavf_gnss_write_pending);
	/* Allocate a kworker for handling work required for the GNSS TTY
	 * writes.
	 */
	kworker = kthread_create_worker(0, "iavf-gnss-%s", dev_name(dev));
	if (IS_ERR(kworker)) {
		kfree(gnss_serial);
		return NULL;
	}

	gnss_serial->kworker = kworker;

	return gnss_serial;
}

/**
 * iavf_gnss_tty_open - Initialize GNSS structures on TTY device open
 * @tty: pointer to the tty_struct
 * @filp: pointer to the file
 *
 * This routine is mandatory. If this routine is not filled in, the attempted
 * open will fail with ENODEV.
 */
static int iavf_gnss_tty_open(struct tty_struct *tty, struct file *filp)
{
	struct iavf_gnss_serial *gnss_serial;
	struct iavf_adapter *adapter;

	adapter = (struct iavf_adapter *)tty->driver->driver_state;
	if (!adapter)
		return -EFAULT;

	/* Clear the pointer in case something fails */
	tty->driver_data = NULL;
	gnss_serial = adapter->gnss.serial;

	if (!gnss_serial) {
		/* Initialize GNSS struct on the first device open */
		gnss_serial = iavf_gnss_struct_init(adapter, tty->index);
		if (!gnss_serial)
			return -ENOMEM;
	}

	mutex_lock(&gnss_serial->gnss_mutex);

	/* Save our structure within the tty structure */
	tty->driver_data = gnss_serial;
	gnss_serial->tty = tty;
	gnss_serial->open_count++;
	kthread_queue_delayed_work(gnss_serial->kworker,
				   &gnss_serial->read_work, 0);

	mutex_unlock(&gnss_serial->gnss_mutex);

	return 0;
}

/**
 * iavf_gnss_tty_close - Cleanup GNSS structures on tty device close
 * @tty: pointer to the tty_struct
 * @filp: pointer to the file
 */
static void iavf_gnss_tty_close(struct tty_struct *tty, struct file *filp)
{
	struct iavf_gnss_serial *gnss_serial;
	struct iavf_adapter *adapter;

	gnss_serial = (struct iavf_gnss_serial *)tty->driver_data;
	if (!gnss_serial)
		return;

	adapter = (struct iavf_adapter *)tty->driver->driver_state;
	if (!adapter)
		return;

	mutex_lock(&gnss_serial->gnss_mutex);

	if (!gnss_serial->open_count) {
		/* Port was never opened */
		dev_err(&adapter->pdev->dev, "GNSS port not opened\n");
		goto exit;
	}

	gnss_serial->open_count--;
	if (gnss_serial->open_count <= 0) {
		/* Port is in shutdown state */
		kthread_cancel_delayed_work_sync(&gnss_serial->read_work);
	}
exit:
	mutex_unlock(&gnss_serial->gnss_mutex);
}

/**
 * iavf_gnss_tty_write - Write GNSS data
 * @tty: pointer to the tty_struct
 * @buf: pointer to the user data
 * @count: the number of characters that was able to be sent to the hardware (or
 *         queued to be sent at a later time)
 *
 * The write function call is called by the user when there is data to be sent
 * to the hardware. First the tty core receives the call, and then it passes the
 * data on to the tty driver's write function. The tty core also tells the tty
 * driver the size of the data being sent.
 * If any errors happen during the write call, a negative error value should be
 * returned instead of the number of characters that were written.
 */
static int
iavf_gnss_tty_write(struct tty_struct *tty,
		    const unsigned char *buf, int count)
{
	struct iavf_gnss_write_buf *write_buf;
	struct iavf_gnss_serial *gnss_serial;
	struct iavf_adapter *adapter;
	unsigned char *cmd_buf;
	int err = count;

	/* We cannot write a single byte using our I2C implementation. */
	if (count <= 1 || count > IAVF_GNSS_TTY_WRITE_BUF)
		return -EINVAL;

	gnss_serial = (struct iavf_gnss_serial *)tty->driver_data;
	if (!gnss_serial)
		return -EFAULT;

	adapter = (struct iavf_adapter *)tty->driver->driver_state;
	if (!adapter)
		return -EFAULT;

	mutex_lock(&gnss_serial->gnss_mutex);

	if (!gnss_serial->open_count) {
		err = -EINVAL;
		goto exit;
	}

	cmd_buf = kcalloc(count, sizeof(*buf), GFP_KERNEL);
	if (!cmd_buf) {
		err = -ENOMEM;
		goto exit;
	}

	memcpy(cmd_buf, buf, count);

	/* Send the data out to a hardware port */
	write_buf = kzalloc(sizeof(*write_buf), GFP_KERNEL);
	if (!write_buf) {
		err = -ENOMEM;
		goto exit;
	}

	write_buf->buf = cmd_buf;
	write_buf->size = count;
	INIT_LIST_HEAD(&write_buf->queue);
	list_add_tail(&write_buf->queue, &gnss_serial->queue);
	kthread_queue_work(gnss_serial->kworker, &gnss_serial->write_work);
exit:
	mutex_unlock(&gnss_serial->gnss_mutex);

	return err;
}

/**
 * iavf_gnss_tty_write_room - Returns the numbers of characters to be written.
 * @tty: pointer to the tty_struct
 *
 * This routine returns the numbers of characters the tty driver will accept
 * for queuing to be written. This number is subject to change as output buffers
 * get emptied, or if the output flow control is acted.
 */
#ifdef HAVE_TTY_WRITE_ROOM_UINT
static unsigned int iavf_gnss_tty_write_room(struct tty_struct *tty)
#else
static int iavf_gnss_tty_write_room(struct tty_struct *tty)
#endif /* !HAVE_TTY_WRITE_ROOM_UINT */
{
	struct iavf_gnss_serial *gnss_serial;

	gnss_serial = (struct iavf_gnss_serial *)tty->driver_data;
	if (!gnss_serial)
#ifndef HAVE_TTY_WRITE_ROOM_UINT
		return 0;
#else
		return -EFAULT;
#endif /* !HAVE_TTY_WRITE_ROOM_UINT */

	mutex_lock(&gnss_serial->gnss_mutex);

	if (!gnss_serial->open_count) {
		mutex_unlock(&gnss_serial->gnss_mutex);
#ifndef HAVE_TTY_WRITE_ROOM_UINT
		return 0;
#else
		return -EFAULT;
#endif /* !HAVE_TTY_WRITE_ROOM_UINT */
	}

	mutex_unlock(&gnss_serial->gnss_mutex);

	return IAVF_GNSS_TTY_WRITE_BUF;
}

static const struct tty_operations tty_gps_ops = {
	.open =		iavf_gnss_tty_open,
	.close =	iavf_gnss_tty_close,
	.write =	iavf_gnss_tty_write,
	.write_room =	iavf_gnss_tty_write_room,
};

/**
 * iavf_gnss_create_tty_driver - Create a TTY driver for GNSS
 * @adapter: Board private structure
 */
static struct tty_driver *
iavf_gnss_create_tty_driver(struct iavf_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;
	const int IAVF_TTYDRV_NAME_MAX = 13;
	struct tty_driver *tty_driver;
	char *ttydrv_name;
	int err;

	tty_driver = tty_alloc_driver(1, TTY_DRIVER_REAL_RAW |
					 TTY_DRIVER_UNNUMBERED_NODE);
	if (IS_ERR(tty_driver)) {
		dev_err(dev, "Failed to allocate memory for GNSS TTY\n");
		return NULL;
	}

	ttydrv_name = kzalloc(IAVF_TTYDRV_NAME_MAX, GFP_KERNEL);
	if (!ttydrv_name) {
		tty_driver_kref_put(tty_driver);
		return NULL;
	}

	snprintf(ttydrv_name, IAVF_TTYDRV_NAME_MAX, "ttyGNSS_%02x%02x",
		 (u8)adapter->pdev->bus->number,
		 (u8)adapter->pdev->devfn);

	/* Initialize the tty driver*/
	tty_driver->owner = THIS_MODULE;
	tty_driver->driver_name = dev_driver_string(dev);
	tty_driver->name = (const char *)ttydrv_name;
	tty_driver->type = TTY_DRIVER_TYPE_SERIAL;
	tty_driver->subtype = SERIAL_TYPE_NORMAL;
	tty_driver->init_termios = tty_std_termios;
	tty_driver->init_termios.c_iflag &= ~INLCR;
	tty_driver->init_termios.c_iflag |= IGNCR;
	tty_driver->init_termios.c_oflag &= ~OPOST;
	tty_driver->init_termios.c_lflag &= ~ICANON;
	tty_driver->init_termios.c_cflag &= ~(CSIZE | CBAUD | CBAUDEX);
	tty_driver->init_termios.c_cflag |= CS8;
	/* baud rate 9600 */
	tty_termios_encode_baud_rate(&tty_driver->init_termios, 9600, 9600);
	tty_driver->driver_state = adapter;
	tty_set_operations(tty_driver, &tty_gps_ops);

	adapter->gnss.tty_port =
		kzalloc(sizeof(*adapter->gnss.tty_port), GFP_KERNEL);
	adapter->gnss.serial = NULL;

	tty_port_init(adapter->gnss.tty_port);
	tty_port_link_device(adapter->gnss.tty_port, tty_driver, 0);

	err = tty_register_driver(tty_driver);
	if (err) {
		dev_err(dev, "Failed to register TTY driver err=%d\n", err);

		tty_port_destroy(adapter->gnss.tty_port);
		kfree(adapter->gnss.tty_port);
		kfree(ttydrv_name);
		tty_driver_kref_put(tty_driver);

		return NULL;
	}

	dev_info(dev, "%s registered\n", ttydrv_name);
	return tty_driver;
}

/**
 * iavf_gnss_init - Initialize GNSS TTY support
 * @adapter: Board private structure
 */
void iavf_gnss_init(struct iavf_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;
	struct tty_driver *tty_driver;

	if (!iavf_ptp_cap_supported(adapter, VIRTCHNL_1588_PTP_CAP_GNSS)) {
		dev_info(dev, "GNSS Capability Not Supported\n");
		return;
	}

	if (WARN_ON(adapter->gnss.initialized)) {
		dev_err(dev, "GNSS functionality was already initialized!\n");
		return;
	}

	init_waitqueue_head(&adapter->gnss.i2c_read_waitqueue);
	init_waitqueue_head(&adapter->gnss.i2c_write_waitqueue);

	tty_driver = iavf_gnss_create_tty_driver(adapter);
	if (!tty_driver) {
		dev_err(dev, "GNSS TTY Driver Can not be instantiated!\n");
		return;
	}

	adapter->gnss.tty_driver = tty_driver;
	adapter->gnss.initialized = true;
	dev_info(dev, "GNSS Module init successful\n");
}

/**
 * iavf_gnss_op_match - Check if any pending iavf gnss virtchnl opcodes
 * @pending_op: virtchnl opcode
 *
 * Return true if pending opcode is one of iavf synce virtchnl opcodes
 * otherwise return false
 */
static bool iavf_gnss_op_match(enum virtchnl_ops pending_op)
{
	if (pending_op == VIRTCHNL_OP_GNSS_READ_I2C ||
	    pending_op == VIRTCHNL_OP_GNSS_WRITE_I2C)
		return true;

	return false;
}

/**
 * iavf_gnss_exit - Disable GNSS Module support
 * @adapter: pointer to the iavf_adapter struct
 */
void iavf_gnss_exit(struct iavf_adapter *adapter)
{
	if (!adapter->gnss.initialized || !adapter->gnss.tty_driver)
		return;

	iavf_flush_vc_msg_queue(adapter, iavf_gnss_op_match);

	if (adapter->gnss.tty_port) {
		tty_port_destroy(adapter->gnss.tty_port);
		kfree(adapter->gnss.tty_port);
	}

	if (adapter->gnss.serial) {
		struct iavf_gnss_serial *gnss_serial = adapter->gnss.serial;

		kthread_cancel_work_sync(&gnss_serial->write_work);
		kthread_cancel_delayed_work_sync(&gnss_serial->read_work);
		kthread_destroy_worker(gnss_serial->kworker);
		gnss_serial->kworker = NULL;
		kfree(gnss_serial);
		adapter->gnss.serial = NULL;
	}

	tty_unregister_driver(adapter->gnss.tty_driver);
	kfree((void *)(adapter->gnss.tty_driver->name));
	tty_driver_kref_put(adapter->gnss.tty_driver);
	adapter->gnss.tty_driver = NULL;
}
