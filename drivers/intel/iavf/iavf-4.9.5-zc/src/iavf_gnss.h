/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2013-2023 Intel Corporation */

#ifndef _IAVF_GNSS_H_
#define _IAVF_GNSS_H_

#include "kcompat_kthread.h"
#include <linux/tty.h>
#include <linux/tty_flip.h>

#define IAVF_E810T_GNSS_I2C_BUS			0x2
#define IAVF_GNSS_TIMER_DELAY_TIME		(HZ / 10) /* 0.1 second per message */
#define IAVF_GNSS_TTY_WRITE_BUF			250
#define IAVF_MAX_I2C_DATA_SIZE			(VIRTCHNL_I2C_DATA_SIZE_M >> \
						 VIRTCHNL_I2C_DATA_SIZE_S)
#define IAVF_MAX_I2C_WRITE_BYTES		4

/* ublox specific deifinitions */
#define IAVF_GNSS_UBX_I2C_BUS_ADDR		0x42
/* Data length register is big endian */
#define IAVF_GNSS_UBX_DATA_LEN_H		0xFD
#define IAVF_GNSS_UBX_DATA_LEN_WIDTH		2
#define IAVF_GNSS_UBX_EMPTY_DATA		0xFF
/* For ublox writes are performed without address so the first byte to write is
 * passed as I2C addr parameter.
 */
#define IAVF_GNSS_UBX_WRITE_BYTES		(IAVF_MAX_I2C_WRITE_BYTES + 1)
#define IAVF_MAX_UBX_READ_TRIES			255
#define IAVF_MAX_UBX_ACK_READ_TRIES		4095

/**
 * struct iavf_gnss_write_buf - gnss write buffer
 * @queue: gnss write queue
 * @size: buffer size
 * @buf: buffer data
 */
struct iavf_gnss_write_buf {
	struct list_head queue;
	unsigned int size;
	unsigned char *buf;
};

/**
 * struct iavf_gnss_serial - data used to initialize GNSS TTY port
 * @back: back pointer to iavf adapter
 * @tty: pointer to the tty for this device
 * @open_count: number of times this port has been opened
 * @gnss_mutex: gnss_mutex used to protect GNSS serial operations
 * @kworker: kwork thread for handling periodic work
 * @read_work: read_work function for handling GNSS reads
 * @write_work: write_work function for handling GNSS writes
 * @queue: write buffers queue
 * @buf: write buffer for a single u8, negative if empty
 */
struct iavf_gnss_serial {
	struct iavf_adapter *back;
	struct tty_struct *tty;
	int open_count;
	struct mutex gnss_mutex; /* protects GNSS serial structure */
	struct kthread_worker *kworker;
	struct kthread_delayed_work read_work;
	struct kthread_work write_work;
	struct list_head queue;
};

/**
 * struct iavf_gnss - data used to initialize GNSS module
 * @tty_driver: gnss tty driver
 * @tty_port: gnss tty port
 * @serial: gnss serial structure
 * @gnss_read_i2c_waitqueue: gnss i2c read waitqueue
 * @i2c_read_ready: gnss i2c read ready
 * @read_i2c_resp: gnss i2c read respons
 * @initialized: gnss module initialization state
 */
struct iavf_gnss {
	struct tty_driver *tty_driver;
	struct tty_port *tty_port;
	struct iavf_gnss_serial *serial;
	wait_queue_head_t i2c_read_waitqueue;
	wait_queue_head_t i2c_write_waitqueue;
	bool i2c_read_ready;
	bool i2c_write_ready;
	struct virtchnl_gnss_read_i2c_resp read_i2c_resp;
	bool initialized;
};

void iavf_gnss_init(struct iavf_adapter *adapter);
void iavf_gnss_exit(struct iavf_adapter *adapter);
void iavf_virtchnl_gnss_read_i2c(struct iavf_adapter *adapter, void *data,
				 u16 len);
void iavf_virtchnl_gnss_write_i2c(struct iavf_adapter *adapter);
#endif /* _IAVF_GNSS_H_ */
