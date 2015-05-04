/*
 *
 * (C) 2005-11 - Luca Deri <deri@ntop.org>
 *               Alfredo Cardigliano <cardigliano@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef _PFRING_MOD_MULTI_H_
#define _PFRING_MOD_MULTI_H_

int  pfring_mod_multi_open (pfring *ring);

void pfring_mod_multi_close(pfring *ring);
int  pfring_mod_multi_stats(pfring *ring, pfring_stat *stats);
int  pfring_mod_multi_add_hw_rule(pfring *ring, hw_filtering_rule *rule);
int  pfring_mod_multi_remove_hw_rule(pfring *ring, u_int16_t rule_id);
int  pfring_mod_multi_bind(pfring *ring, char *device_name);
int  pfring_mod_multi_set_sampling_rate(pfring *ring, u_int32_t rate);
int  pfring_mod_multi_set_direction(pfring *ring, packet_direction direction);
int  pfring_mod_multi_enable_rss_rehash(pfring *ring);

#endif /* _PFRING_MOD_MULTI_H_ */
