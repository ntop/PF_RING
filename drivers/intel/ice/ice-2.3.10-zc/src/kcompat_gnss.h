/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Intel Corporation. */

/* This is taken from upstream <include/linux/gnss.h> commit 625239d */

#ifndef _KCOMPAT_GNSS_H_
#define _KCOMPAT_GNSS_H_

#ifdef _GNSS_H_
#error "Do not include both kcompat_gnss.h and <include/linux/gnss.h>"
#endif

#if IS_ENABLED(CONFIG_GNSS) && !defined(CONFIG_SUSE_KERNEL)
#error "CONFIG_GNSS is enabled, use <include/linux/gnss.h>"
#endif

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kfifo.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/types.h>
#include <linux/wait.h>

struct gnss_device;

enum gnss_type {
	GNSS_TYPE_NMEA = 0,
	GNSS_TYPE_SIRF,
	GNSS_TYPE_UBX,
	GNSS_TYPE_MTK,

	GNSS_TYPE_COUNT
};

struct gnss_operations {
	int (*open)(struct gnss_device *gdev);
	void (*close)(struct gnss_device *gdev);
	int (*write_raw)(struct gnss_device *gdev, const unsigned char *buf,
			 size_t count);
};

struct gnss_device {
	struct device dev;
	struct cdev cdev;
	int id;

	enum gnss_type type;
	unsigned long flags;

	struct rw_semaphore rwsem;
	const struct gnss_operations *ops;
	unsigned int count;
	unsigned int disconnected:1;

	struct mutex read_mutex; /* GNSS read lock */
	struct kfifo read_fifo;
	wait_queue_head_t read_queue;

	struct mutex write_mutex; /* GNSS write lock */
	char *write_buf;
};

struct gnss_device *gnss_allocate_device(struct device *parent);
void gnss_put_device(struct gnss_device *gdev);
int gnss_register_device(struct gnss_device *gdev);
void gnss_deregister_device(struct gnss_device *gdev);

int gnss_insert_raw(struct gnss_device *gdev, const unsigned char *buf,
		    size_t count);

static inline void gnss_set_drvdata(struct gnss_device *gdev, void *data)
{
	dev_set_drvdata(&gdev->dev, data);
}

static inline void *gnss_get_drvdata(struct gnss_device *gdev)
{
	return dev_get_drvdata(&gdev->dev);
}

int gnss_module_init(void);
void gnss_module_exit(void);

#endif /* _KCOMPAT_GNSS_H_ */
