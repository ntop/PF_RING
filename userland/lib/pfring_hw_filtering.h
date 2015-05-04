/*
 *
 * (C) 2011-14 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 */

#ifndef _PFRING_HW_FT_H_
#define _PFRING_HW_FT_H_

void pfring_hw_ft_init(pfring *ring);
int pfring_hw_ft_set_traffic_policy(pfring *ring, u_int8_t rules_default_accept_policy);
int pfring_hw_ft_add_hw_rule(pfring *ring, hw_filtering_rule *rule);
int pfring_hw_ft_remove_hw_rule(pfring *ring, u_int16_t rule_id);
int pfring_hw_ft_handle_hash_filtering_rule(pfring *ring, hash_filtering_rule* rule_to_add, u_char add_rule);
int pfring_hw_ft_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add);
int pfring_hw_ft_remove_filtering_rule(pfring *ring, u_int16_t rule_id);


#endif /* _PFRING_HW_FT_H_ */
