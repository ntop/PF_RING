/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _AUXILIARY_BUS_H_
#define _AUXILIARY_BUS_H_

/* The CRC of the exported symbols which depend on 'struct device' can change
 * if the definition of 'struct dev_pm_qos' is not included in this file, i.e.
 * if we don't include this file.
 */
#include <linux/pm_qos.h>
#include <linux/device.h>
#include <linux/mod_devicetable.h>
#include "auxiliary_compat.h"

#ifndef HAVE_AUXILIARY_DEVICE_ID
/* For some kernel, auxiliary is not mature enough so that part code is
 * included, but no driver uses it. HAVE_AUXILIARY_DEVICE_ID will be
 * generated only when CONFIG_AUXILIARY_BUS is not defined. If
 * HAVE_AUXILIARY_DEVICE_ID is defined, it means struct
 * auxiliary_device_id and AUXILIARY_NAME_SIZE, AXUILIARY_MODULE_PREFIX
 * in <linux/mod_devicetable.h> is used. Otherwise need definition here.
 */
#define AUXILIARY_NAME_SIZE 32
#define AUXILIARY_MODULE_PREFIX "intel_auxiliary:"
struct auxiliary_device_id {
	char name[AUXILIARY_NAME_SIZE];
	kernel_ulong_t driver_data;
};
#endif

#define AUX_PREFIX(func) intel_ ## func

#define auxiliary_device_init AUX_PREFIX(auxiliary_device_init)
#define __auxiliary_device_add AUX_PREFIX(__auxiliary_device_add)
#define auxiliary_find_device AUX_PREFIX(auxiliary_find_device)
#define __auxiliary_driver_register AUX_PREFIX(__auxiliary_driver_register)
#define auxiliary_driver_unregister AUX_PREFIX(auxiliary_driver_unregister)

struct auxiliary_device {
	struct device dev;
	const char *name;
	u32 id;
};

struct auxiliary_driver {
	int (*probe)(struct auxiliary_device *auxdev, const struct auxiliary_device_id *id);
	void (*remove)(struct auxiliary_device *auxdev);
	void (*shutdown)(struct auxiliary_device *auxdev);
	int (*suspend)(struct auxiliary_device *auxdev, pm_message_t state);
	int (*resume)(struct auxiliary_device *auxdev);
	const char *name;
	struct device_driver driver;
	const struct auxiliary_device_id *id_table;
};

static inline struct auxiliary_device *to_auxiliary_dev(struct device *dev)
{
	return container_of(dev, struct auxiliary_device, dev);
}

static inline struct auxiliary_driver *to_auxiliary_drv(struct device_driver *drv)
{
	return container_of(drv, struct auxiliary_driver, driver);
}

int auxiliary_device_init(struct auxiliary_device *auxdev);
int __auxiliary_device_add(struct auxiliary_device *auxdev, const char *modname);
#define auxiliary_device_add(auxdev) __auxiliary_device_add(auxdev, KBUILD_MODNAME)

static inline void auxiliary_device_uninit(struct auxiliary_device *auxdev)
{
	put_device(&auxdev->dev);
}

static inline void auxiliary_device_delete(struct auxiliary_device *auxdev)
{
	device_del(&auxdev->dev);
}

int __auxiliary_driver_register(struct auxiliary_driver *auxdrv, struct module *owner,
				const char *modname);
#define auxiliary_driver_register(auxdrv) \
	__auxiliary_driver_register(auxdrv, THIS_MODULE, KBUILD_MODNAME)

void auxiliary_driver_unregister(struct auxiliary_driver *auxdrv);

/**
 * module_auxiliary_driver() - Helper macro for registering an auxiliary driver
 * @__auxiliary_driver: auxiliary driver struct
 *
 * Helper macro for auxiliary drivers which do not do anything special in
 * module init/exit. This eliminates a lot of boilerplate. Each module may only
 * use this macro once, and calling it replaces module_init() and module_exit()
 */
#define module_auxiliary_driver(__auxiliary_driver) \
	module_driver(__auxiliary_driver, auxiliary_driver_register, auxiliary_driver_unregister)

struct auxiliary_device *auxiliary_find_device(struct device *start,
					       const void *data,
					       int (*match)(struct device *dev, const void *data));

#endif /* _AUXILIARY_BUS_H_ */
