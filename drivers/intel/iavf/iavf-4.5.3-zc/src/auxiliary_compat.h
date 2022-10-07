/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2013, Intel Corporation. */

#ifndef _AUXILIARY_COMPAT_H_
#define _AUXILIARY_COMPAT_H_

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#ifndef LINUX_VERSION_CODE
#error "LINUX_VERSION_CODE is undefined"
#endif

#ifndef KERNEL_VERSION
#error "KERNEL_VERSION is undefined"
#endif

/* This file contains only the minimal set of kernel compatibility backports
 * required by auxiliary.c to build. It is similar to the kcompat.h file, but
 * reduced to an absolute minimum in order to reduce the risk of generating
 * different kernel symbol CRC values at build time.
 *
 * For a detailed discussion of kernel symbol CRCs, please read:
 *
 *    Documentation/kernel-symbol-crc.rst
 *
 * Include only the minimum required kernel compatibility implementations from
 * kcompat_std_defs.h and kcompat_impl.h. If a new fix is required, please
 * first implement it as part of the kcompat project before porting it to this
 * file.
 *
 * The current list of required implementations is:
 *
 *  NEED_BUS_FIND_DEVICE_CONST_DATA
 *  NEED_DEV_PM_DOMAIN_ATTACH_DETACH
 *
 * Note that kernels since v5.11 support auxiliary as a built-in config
 * option. Using this is always preferred to using an out-of-tree module when
 * available.
 */

/************************
 * Standard definitions *
 ************************/

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0))
#define NEED_DEV_PM_DOMAIN_ATTACH_DETACH
#else /* >= 3,18,0 */
#endif /* 3,18,0 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0))
#define NEED_BUS_FIND_DEVICE_CONST_DATA
#else /* >= 5.3.0 */
#endif /* 5.3.0 */

#ifdef RHEL_RELEASE_CODE
/********************
 * RHEL definitions *
 ********************/

#ifndef RHEL_RELEASE_VERSION
#error "RHEL_RELEASE_VERSION is undefined"
#endif

/*****************************************************************************/
#if (RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8,2))
#else /* >= 8.2 */
#undef NEED_BUS_FIND_DEVICE_CONST_DATA
#endif /* 8.2 */

#endif /* RHEL_RELEASE_CODE */

#ifdef CONFIG_SUSE_KERNEL
/********************
 * SLES definitions *
 ********************/

#if !SLE_KERNEL_REVISION
#error "SLE_KERNEL_REVISION is 0 or undefined"
#endif

#if SLE_KERNEL_REVISION > 65535
#error "SLE_KERNEL_REVISION is unexpectedly large"
#endif

/* SLE kernel versions are a combination of the LINUX_VERSION_CODE along with
 * an extra digit that indicates the SUSE specific revision of that kernel.
 * This value is found in the CONFIG_LOCALVERSION of the SUSE kernel, which is
 * extracted by common.mk and placed into SLE_KERNEL_REVISION_CODE.
 *
 * We combine the value of SLE_KERNEL_REVISION along with the LINUX_VERSION code
 * to generate the useful value that determines what specific kernel we're
 * dealing with.
 *
 * Just in case the SLE_KERNEL_REVISION ever goes above 255, we reserve 16 bits
 * instead of 8 for this value.
 */
#define SLE_KERNEL_CODE ((LINUX_VERSION_CODE << 16) + SLE_KERNEL_REVISION)
#define SLE_KERNEL_VERSION(a,b,c,d) ((KERNEL_VERSION(a,b,c) << 16) + (d))

/* Unlike RHEL, SUSE kernels are not always tied to a single service pack. For
 * example, 4.12.14 was used as the base for SLE 15 SP1, SLE 12 SP4, and SLE 12
 * SP5.
 *
 * You can find the patches that SUSE applied to the kernel tree at
 * https://github.com/SUSE/kernel-source.
 *
 * You can find the correct kernel version for a check by using steps similar
 * to the following
 *
 * 1) download the kernel-source repo
 * 2) checkout the relevant branch, i.e SLE15-SP3
 * 3) find the relevant backport you're interested in the patches.suse
 *    directory
 * 4) git log <patch file> to locate the commit that introduced the backport
 * 5) git describe --contains to find the relevant tag that includes that
 *    commit, i.e. rpm-5.3.18-37
 * 6) those digits represent the SLE kernel that introduced that backport.
 *
 * Try to keep the checks in SLE_KERNEL_CODE order and condense where
 * possible.
 */

/*****************************************************************************/
#if (SLE_KERNEL_CODE > SLE_KERNEL_VERSION(4,12,14,23) && \
     SLE_KERNEL_CODE < SLE_KERNEL_VERSION(4,12,14,94))
/*
 * 4.12.14 is used as the base for SLE 12 SP4, SLE 12 SP5, SLE 15, and SLE 15
 * SP1. Unfortunately the revision codes do not line up cleanly. SLE 15
 * launched with 4.12.14-23. It appears that SLE 12 SP4 and SLE 15 SP1 both
 * diverged from this point, with SLE 12 SP4 kernels starting around
 * 4.12.14-94. A few backports for SLE 15 SP1 landed in some alpha and beta
 * kernels tagged between 4.12.14-25 up to 4.12.14-32. These changes did not
 * make it into SLE 12 SP4. This was cleaned up with SLE 12 SP5 by an apparent
 * merge in 4.12.14-111. The official launch of SLE 15 SP1 ended up with
 * version 4.12.14-195.
 *
 * Because of this inconsistency and because all of these kernels appear to be
 * alpha or beta kernel releases for SLE 15 SP1, we do not rely on version
 * checks between this range. Issue a warning to indicate that we do not
 * support these.
 */
#warning "SLE kernel versions between 4.12.14-23 and 4.12.14-94 are not supported"
#endif

/*****************************************************************************/
#if (SLE_KERNEL_CODE < SLE_KERNEL_VERSION(5,3,8,2))
#else /* >= 5.3.8-2 */
#undef NEED_BUS_FIND_DEVICE_CONST_DATA
#endif /* 5.3.8-2 */

#endif /* CONFIG_SUSE_KERNEL */

/****************************
 * Backport implementations *
 ****************************/

#ifdef NEED_BUS_FIND_DEVICE_CONST_DATA
/* NEED_BUS_FIND_DEVICE_CONST_DATA
 *
 * bus_find_device() was updated in upstream commit 418e3ea157ef
 * ("bus_find_device: Unify the match callback with class_find_device")
 * to take a const void *data parameter and also have the match() function
 * passed in take a const void *data parameter.
 *
 * all of the kcompat below makes it so the caller can always just call
 * bus_find_device() according to the upstream kernel without having to worry
 * about const vs. non-const arguments.
 */
struct _kc_bus_find_device_custom_data {
	const void *real_data;
	int (*real_match)(struct device *dev, const void *data);
};

static inline int _kc_bus_find_device_wrapped_match(struct device *dev, void *data)
{
	struct _kc_bus_find_device_custom_data *custom_data = data;

	return custom_data->real_match(dev, custom_data->real_data);
}

static inline struct device *
_kc_bus_find_device(struct bus_type *type, struct device *start,
		    const void *data,
		    int (*match)(struct device *dev, const void *data))
{
	struct _kc_bus_find_device_custom_data custom_data = {};

	custom_data.real_data = data;
	custom_data.real_match = match;

	return bus_find_device(type, start, &custom_data,
			       _kc_bus_find_device_wrapped_match);
}

/* force callers of bus_find_device() to call _kc_bus_find_device() on kernels
 * where NEED_BUS_FIND_DEVICE_CONST_DATA is defined
 */
#define bus_find_device(type, start, data, match) \
	_kc_bus_find_device(type, start, data, match)
#endif /* NEED_BUS_FIND_DEVICE_CONST_DATA */

#ifdef NEED_DEV_PM_DOMAIN_ATTACH_DETACH
#include <linux/acpi.h>
/* NEED_DEV_PM_DOMAIN_ATTACH_DETACH
 *
 * dev_pm_domain_attach() and dev_pm_domain_detach() were added in upstream
 * commit 46420dd73b80 ("PM / Domains: Add APIs to attach/detach a PM domain for
 * a device"). To support older kernels and OSVs that don't have these API, just
 * implement how older versions worked by directly calling acpi_dev_pm_attach()
 * and acpi_dev_pm_detach().
 */
static inline int dev_pm_domain_attach(struct device *dev, bool power_on)
{
	if (dev->pm_domain)
		return 0;

	if (ACPI_HANDLE(dev))
		return acpi_dev_pm_attach(dev, true);

	return 0;
}

static inline void dev_pm_domain_detach(struct device *dev, bool power_off)
{
	if (ACPI_HANDLE(dev))
		acpi_dev_pm_detach(dev, true);
}
#endif /* NEED_DEV_PM_DOMAIN_ATTACH_DETACH */

#endif /* _AUXILIARY_COMPAT_H_ */
