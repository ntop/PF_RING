/*
 *
 * (C) 2023 - ntop
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 */

#ifdef HAVE_DL_REDIS
#ifndef _PFRING_RUNTIME_MANAGER_H_
#define _PFRING_RUNTIME_MANAGER_H_

/* ********************************* */

void pfring_run_runtime_manager(pfring *ring);
void pfring_stop_runtime_manager(pfring *ring);

/* ********************************* */

#endif /* _PFRING_RUNTIME_MANAGER_H_ */
#endif /* HAVE_DL_REDIS */
