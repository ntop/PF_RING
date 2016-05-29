/* Intel(R) Ethernet Switch Host Interface Driver
 * Copyright(c) 2013 - 2016 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 */

#include <linux/types.h>
#include <linux/module.h>

#include "fm10k.h"

/* This is the only thing that needs to be changed to adjust the
 * maximum number of ports that the driver can manage.
 */

#define FM10K_MAX_INTFC	32

#define OPTION_UNSET	-1
#define OPTION_DISABLED	0
#define OPTION_ENABLED	1

#define STRINGIFY(foo)	#foo /* magic for getting defines into strings */
#define XSTRINGIFY(bar)	STRINGIFY(bar)

#define FM10K_PARAM_INIT { [0 ... FM10K_MAX_INTFC] = OPTION_UNSET }
/* Module Parameters are always initialized to -1, so that the driver
 * can tell the difference between no user specified value or the
 * user asking for the default value.
 * The true default values are loaded in when fm10k_check_options is called.
 *
 * This is a GCC extension to ANSI C.
 * See the item "Labeled Elements in Initializers" in the section
 * "Extensions to the C Language Family" of the GCC documentation.
 */

#ifdef HAVE_CONFIG_HOTPLUG
#define FM10K_PARAM(X, desc) \
	static int X[FM10K_MAX_INTFC + 1] __devinitdata = FM10K_PARAM_INIT; \
	static unsigned int num_##X; \
	module_param_array_named(X, X, int, &num_##X, 0); \
	MODULE_PARM_DESC(X, desc)
#else
#define FM10K_PARAM(X, desc) \
	static int X[FM10K_MAX_INTFC + 1] = FM10K_PARAM_INIT; \
	static unsigned int num_##X; \
	module_param_array_named(X, X, int, &num_##X, 0); \
	MODULE_PARM_DESC(X, desc)
#endif

static int ifc;

/* FTAG - Initialize interface as IES interface instead of Ethernet
 *
 * Valid Range: 0-1
 *  - 0 - Ethernet interface for passing Ethernet traffic
 *  - 1 - IES interface for passing switch traffic with outer FTAG and timestamp
 *
 * Default Value: 0
 */

FM10K_PARAM(FTAG,
	    "FTAG Interface Enable: 0 = Ethernet Interface (default), 1 = IES Interface");

/* max_vfs - SR I/O Virtualization
 *
 * Valid Range: 0-64
 *  - 0 Disables SR-IOV
 *  - 1-64 - enables SR-IOV and sets the number of VFs enabled
 *
 * Default Value: 0
 */

#define MAX_SRIOV_VFS 64

FM10K_PARAM(max_vfs, "Number of Virtual Functions: 0 = disable (default), 1-"
	    XSTRINGIFY(MAX_SRIOV_VFS) " = enable this many VFs");

/* RSS - Receive-Side Scaling (RSS) Descriptor Queues
 *
 * Valid Range: 0-128
 *  - 0 - enables RSS and sets the Desc. Q's to min(16, num_online_cpus()).
 *  - 1-128 - enables RSS and sets the Desc. Q's to the specified value.
 *
 * Default Value: 0
 */

FM10K_PARAM(RSS,
	    "Number of Receive-Side Scaling Descriptor Queues: 0 = number of cpus (default), 1-128 = number of queues");

struct fm10k_option {
	enum { enable_option, range_option, list_option } type;
	const char *name;
	const char *err;
	int def;
	union {
		struct { /* range_option info */
			int min;
			int max;
		} r;
		struct { /* list_option info */
			int nr;
			const struct fm10k_opt_list {
				int i;
				char *str;
			} *p;
		} l;
	} arg;
};

#ifdef HAVE_CONFIG_HOTPLUG
static int __devinit fm10k_validate_option(unsigned int *value,
					   struct fm10k_option *opt)
#else
static int fm10k_validate_option(unsigned int *value,
				 struct fm10k_option *opt)
#endif
{
	if (*value == OPTION_UNSET) {
		*value = opt->def;
		return 0;
	}

	switch (opt->type) {
	case enable_option:
		switch (*value) {
		case OPTION_ENABLED:
			pr_info("fm10k: %s Enabled\n", opt->name);
			return 0;
		case OPTION_DISABLED:
			pr_info("fm10k: %s Disabled\n", opt->name);
			return 0;
		}
		break;
	case range_option:
		if (*value >= opt->arg.r.min && *value <= opt->arg.r.max) {
			pr_info("fm10k: %s set to %d\n", opt->name, *value);
			return 0;
		}
		break;
	case list_option: {
		int i;
		const struct fm10k_opt_list *ent;

		for (i = 0; i < opt->arg.l.nr; i++) {
			ent = &opt->arg.l.p[i];
			if (*value == ent->i) {
				if (ent->str[0] != '\0')
					pr_info("%s\n", ent->str);
				return 0;
			}
		}
	}
		break;
	default:
		break;
	}

	pr_err("fm10k: Invalid %s (type=%d) specified (%d),  %s\n",
	       opt->name, opt->type, *value, opt->err);
	*value = opt->def;
	return -1;
}

/**
 * fm10k_check_options - Range Checking for Command Line Parameters
 * @interface: board private structure
 *
 * This routine checks all command line parameters for valid user
 * input.  If an invalid value is given, or if no user specified
 * value exists, a default value is used.  The final value is stored
 * in a variable in the interface structure.
 **/
#ifdef HAVE_CONFIG_HOTPLUG
int __devinit fm10k_check_options(struct fm10k_intfc *interface)
#else
int fm10k_check_options(struct fm10k_intfc *interface)
#endif
{
	struct fm10k_ring_feature *feature = interface->ring_feature;

	{ /* Single Root I/O Virtualization (SR-IOV) */
		struct fm10k_option opt = {
			.type = range_option,
			.name = "I/O Virtualization (IOV)",
			.err  = "defaulting to Disabled",
			.def  = OPTION_DISABLED,
			.arg  = { .r = { .min = OPTION_DISABLED,
					 .max = MAX_SRIOV_VFS} }
		};
		unsigned int vfs = opt.def;

		/* block enabling SR-IOV if we cannot support it */
		if (!interface->hw.iov.ops.assign_resources)
			opt.arg.r.max = OPTION_DISABLED;

		if (num_max_vfs > ifc) {
			vfs = max_vfs[ifc];
			if (fm10k_validate_option(&vfs, &opt))
				return -EINVAL;
		}

		interface->init_vfs = vfs;
	}
	{ /* Receive-Side Scaling (RSS) */
		struct fm10k_option opt = {
			.type = range_option,
			.name = "Receive-Side Scaling (RSS)",
			.err  = "using default.",
			.def  = 0,
			.arg  = { .r = { .min = 0,
					 .max = FM10K_MAX_RSS_INDICES} }
		};
		unsigned int rss = opt.def;

		if (num_RSS > ifc) {
			rss = RSS[ifc];
			if (fm10k_validate_option(&rss, &opt))
				return -EINVAL;
		}

		/* base it off num_online_cpus() with hardware limit */
		if (!rss)
			rss = min_t(int, opt.arg.r.max,
				    num_online_cpus());

		feature[RING_F_RSS].limit = rss;
	}
	{ /* IES Interface Enable */
		struct fm10k_option opt = {
			.type = enable_option,
			.name = "IES Interface",
			.err  = "defaulting to Disabled",
			.def  = OPTION_DISABLED,
		};
		unsigned int ies = opt.def;

		if (num_FTAG > ifc) {
			ies = FTAG[ifc];

			/* VLAN is always IES disabled */
			if (interface->hw.mac.type == fm10k_mac_vf)
				ies = OPTION_DISABLED;

			if (fm10k_validate_option(&ies, &opt))
				return -EINVAL;
		}

		if (ies)
			interface->flags |= FM10K_FLAG_IES_MODE;
	}

	ifc++;

	return 0;
}
