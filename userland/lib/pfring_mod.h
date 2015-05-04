/*
 *
 * (C) 2005-14 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 *
 */

#ifndef _PFRING_MOD_H_
#define _PFRING_MOD_H_

int pfring_mod_open_setup(pfring *ring);
int pfring_mod_open(pfring *ring);
void pfring_mod_close(pfring *ring);
int pfring_mod_stats(pfring *ring, pfring_stat *stats);
int pfring_mod_is_pkt_available(pfring *ring);
int pfring_mod_next_pkt_time(pfring *ring, struct timespec *ts);
int pfring_mod_recv(pfring *ring, u_char** buffer, u_int buffer_len, 
			  struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet);
int pfring_mod_set_poll_watermark(pfring *ring, u_int16_t watermark);
int pfring_mod_set_poll_duration(pfring *ring, u_int duration);
int pfring_mod_add_hw_rule(pfring *ring, hw_filtering_rule *rule);
int pfring_mod_remove_hw_rule(pfring *ring, u_int16_t rule_id);
int pfring_mod_set_channel_id(pfring *ring, u_int32_t channel_id);
int pfring_mod_set_channel_mask(pfring *ring, u_int64_t channel_mask);
int pfring_mod_set_application_name(pfring *ring, char *name);
int pfring_mod_set_application_stats(pfring *ring, char *stats);
char* pfring_mod_get_appl_stats_file_name(pfring *ring, char *path, u_int path_len);
int pfring_mod_bind(pfring *ring, char *device_name);
int pfring_mod_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet);
u_int8_t pfring_mod_get_num_rx_channels(pfring *ring);
int pfring_mod_set_sampling_rate(pfring *ring, u_int32_t rate);
int pfring_mod_get_selectable_fd(pfring *ring);
int pfring_mod_set_direction(pfring *ring, packet_direction direction);
int pfring_mod_set_socket_mode(pfring *ring, socket_mode mode);
int pfring_mod_set_cluster(pfring *ring, u_int clusterId, cluster_type the_type);
int pfring_mod_remove_from_cluster(pfring *ring);
int pfring_mod_set_master_id(pfring *ring, u_int32_t master_id);
int pfring_mod_set_master(pfring *ring, pfring *master);
u_int16_t pfring_mod_get_ring_id(pfring *ring);
u_int32_t pfring_mod_get_num_queued_pkts(pfring *ring);
u_int8_t pfring_mod_get_packet_consumer_mode(pfring *ring);
int pfring_mod_set_packet_consumer_mode(pfring *ring, u_int8_t plugin_id,
				        char *plugin_data, u_int plugin_data_len);
int pfring_mod_get_hash_filtering_rule_stats(pfring *ring,
					     hash_filtering_rule* rule,
					     char* stats, u_int *stats_len);
int pfring_mod_handle_hash_filtering_rule(pfring *ring,
					  hash_filtering_rule* rule_to_add,
					  u_char add_rule);
int pfring_mod_purge_idle_hash_rules(pfring *ring, u_int16_t inactivity_sec); 
int pfring_mod_purge_idle_rules(pfring *ring, u_int16_t inactivity_sec);
int pfring_mod_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add);
int pfring_mod_remove_filtering_rule(pfring *ring, u_int16_t rule_id);
int pfring_mod_get_filtering_rule_stats(pfring *ring, u_int16_t rule_id,
					char* stats, u_int *stats_len);
int pfring_mod_toggle_filtering_policy(pfring *ring, u_int8_t rules_default_accept_policy);
int pfring_mod_enable_rss_rehash(pfring *ring);
int pfring_mod_poll(pfring *ring, u_int wait_duration);
int pfring_mod_version(pfring *ring, u_int32_t *version);
int pfring_mod_get_bound_device_address(pfring *ring, u_char mac_address[6]);
int pfring_mod_get_bound_device_ifindex(pfring *ring, int *if_index);
int pfring_mod_get_device_ifindex(pfring *ring, char *device_name, int *if_index);
int pfring_mod_get_link_status(pfring *ring);
u_int16_t pfring_mod_get_slot_header_len(pfring *ring);
int pfring_mod_set_virtual_device(pfring *ring, virtual_filtering_device_info *info);
int pfring_mod_loopback_test(pfring *ring, char *buffer, u_int buffer_len, u_int test_len);
int pfring_mod_enable_ring(pfring *ring);
int pfring_mod_disable_ring(pfring *ring);
int pfring_mod_set_bpf_filter(pfring *ring, char *filter_buffer);
int pfring_mod_remove_bpf_filter(pfring *ring);
int pfring_mod_send_last_rx_packet(pfring *ring, int tx_interface_id);
void pfring_mod_shutdown(pfring *ring);
int pfring_mod_set_bound_dev_name(pfring *ring, char *custom_dev_name);

#endif /* _PFRING_MOD_H_ */
