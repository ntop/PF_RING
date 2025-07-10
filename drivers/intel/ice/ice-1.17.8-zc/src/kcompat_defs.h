/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#ifndef _KCOMPAT_DEFS_H_
#define _KCOMPAT_DEFS_H_

#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#else
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif
#endif /* LINUX_VERSION_CODE */

#ifndef UTS_RELEASE
#include <generated/utsrelease.h>
#endif

/*
 * Include the definitions file for HAVE/NEED flags for the standard upstream
 * kernels.
 *
 * Then, based on the distribution we detect, load the distribution specific
 * definitions file that customizes the definitions for the target
 * distribution.
 */
#include "kcompat_std_defs.h"

#ifdef CONFIG_SUSE_KERNEL
#include "kcompat_sles_defs.h"
#elif UBUNTU_VERSION_CODE
#include "kcompat_ubuntu_defs.h"
#elif RHEL_RELEASE_CODE
#include "kcompat_rhel_defs.h"
#endif

#include "kcompat_generated_defs.h"

#endif /* _KCOMPAT_DEFS_H_ */
