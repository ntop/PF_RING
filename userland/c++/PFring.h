/*
 *
 * (C) 2007-17 - Luca Deri <deri@ntop.org>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef PFRING_H
#define PFRING_H

extern "C" {
#define HAVE_PF_RING
#include "pcap-int.h"
#define HAVE_PCAP
#include "pfring.h"
}

class PFring {
 private:
  pfring *ring;
  u_int snaplen;
  char *device_name;

 public:
  PFring(char *device, u_int snaplen, u_int flags = 0);
  ~PFring();

  /* Cluster */
  inline int set_cluster(u_int clusterId)
  { return pfring_set_cluster(ring, clusterId, cluster_round_robin); };
  inline int remove_from_cluster()               
  { return pfring_remove_from_cluster(ring); };

  /* Channel */
  inline int set_channel_id(short channelId)
  { return pfring_set_channel_id(ring, channelId); };

  /* Read Packets */
  bool wait_for_packets(int msec = -1 /* -1 == infinite */);
  int get_next_packet(struct pfring_pkthdr *hdr, const u_char *pkt, u_int pkt_len);
  int get_next_packet_zc(struct pfring_pkthdr *hdr, const u_char **pkt);

  /* Filtering */
  int add_bpf_filter(char *the_filter);
  inline int add_filtering_rule(filtering_rule* the_rule) 
    { return pfring_add_filtering_rule(ring, the_rule);   };
  inline int remove_filtering_rule(u_int16_t rule_id)     
    { return pfring_remove_filtering_rule(ring, rule_id); };
  inline int toggle_filtering_policy(bool rules_default_accept_policy)
    { return pfring_toggle_filtering_policy(ring, rules_default_accept_policy ? 1 : 0); };
  inline int add_hash_filtering_rule(hash_filtering_rule *rule)
    { return pfring_handle_hash_filtering_rule(ring, rule, 1); };
  inline int remove_hash_filtering_rule(hash_filtering_rule *rule)
    { return pfring_handle_hash_filtering_rule(ring, rule, 0); };

  /* Stats */
  inline int get_stats(pfring_stat *stats)
    { return pfring_stats(ring, stats); };
  inline int get_filtering_rule_stats(u_int16_t rule_id, char *stats, u_int *stats_len)
    { return pfring_get_filtering_rule_stats(ring, rule_id, stats, stats_len); };
  inline int get_hash_filtering_rule_stats(hash_filtering_rule* rule, char *stats, u_int *stats_len)
    { return pfring_get_hash_filtering_rule_stats(ring, rule, stats, stats_len); };

  /* Utils */
  inline char* get_device_name() { return device_name; };
  inline int enable_ring()       { return pfring_enable_ring(ring); };
  inline int set_sampling_rate(u_int32_t rate /* 1 = no sampling */)
    { return pfring_set_sampling_rate(ring, rate); };
  inline int set_sw_filtering_sampling_rate(u_int32_t rate /* 0 = no sampling */)
    { return pfring_set_sw_filtering_sampling_rate(ring, rate); };
  inline int get_version(u_int32_t *version) 
    { return pfring_version(ring, version); };
  inline int get_socket_id()  { return ring->fd; };
};

#endif /* PFRING_H */


