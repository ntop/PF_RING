/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018-2021, Intel Corporation. */

/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _KCOMPAT_KTHREAD_H_
#define _KCOMPAT_KTHREAD_H_

/* Kernels since 4.9 have supported delayed work items for kthreads. In order
 * to allow seamless transition from old to new kernels, this header defines
 * a set of macros to switch out kthread usage with a work queue on the older
 * kernels that do not have support for kthread_delayed_work.
 */
#ifdef HAVE_KTHREAD_DELAYED_API
#include <linux/kthread.h>
#else /* HAVE_KTHREAD_DELAYED_API */
#include <linux/workqueue.h>
#undef kthread_work
#define kthread_work work_struct
#undef kthread_delayed_work
#define kthread_delayed_work delayed_work
#undef kthread_worker
#define kthread_worker workqueue_struct
#undef kthread_queue_work
#define kthread_queue_work(worker, work) queue_work(worker, work)
#undef kthread_queue_delayed_work
#define kthread_queue_delayed_work(worker, dwork, delay) \
	queue_delayed_work(worker, dwork, delay)
#undef kthread_init_work
#define kthread_init_work(work, fn) INIT_WORK(work, fn)
#undef kthread_init_delayed_work
#define kthread_init_delayed_work(dwork, fn) \
	INIT_DELAYED_WORK(dwork, fn)
#undef kthread_flush_worker
#define kthread_flush_worker(worker) flush_workqueue(worker)
#undef kthread_cancel_work_sync
#define kthread_cancel_work_sync(work) cancel_work_sync(work)
#undef kthread_cancel_delayed_work_sync
#define kthread_cancel_delayed_work_sync(dwork) \
	cancel_delayed_work_sync(dwork)
#undef kthread_create_worker
#define kthread_create_worker(flags, namefmt, ...) \
	alloc_workqueue(namefmt, 0, 0, ##__VA_ARGS__)
#undef kthread_destroy_worker
#define kthread_destroy_worker(worker) destroy_workqueue(worker)
#endif /* !HAVE_KTHREAD_DELAYED_API */

#endif /* _KCOMPAT_KTHREAD_H_ */
