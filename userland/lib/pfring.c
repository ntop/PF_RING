/*
 *
 * (C) 2005-2018 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 *
 */

#define __USE_XOPEN2K
#include <sys/types.h>
#include <pthread.h>

#ifndef _NETINET_IF_ETHER_H
#define _NETINET_IF_ETHER_H /* fixes compilation with musl library */
#endif

#include "pfring.h"
#include <net/ethernet.h>

// #define RING_DEBUG

#define EXTRA_SAFE 1

/* ********************************* */

#include "pfring_mod.h"
#include "pfring_mod_stack.h"
#include "pfring_mod_sysdig.h"

#ifdef HAVE_NT
/* Napatech */
#include "pfring_mod_nt.h"
#endif

#ifdef HAVE_DAG
/* Endace DAG */
#include "pfring_mod_dag.h"
#endif

#ifdef HAVE_FIBERBLAZE
/* Fiberblaze */
#include "pfring_mod_fiberblaze.h"
#endif

#ifdef HAVE_MELLANOX
/* Mellanox */
#include "pfring_mod_mlx.h"
#endif

#ifdef HAVE_ACCOLADE
/* Accolade */
#include "pfring_mod_accolade.h"
#endif

#ifdef HAVE_MYRICOM
/* Myricom */
#include "pfring_mod_myricom.h"
#endif

#ifdef HAVE_INVEATECH
/* InveaTech */
#include "pfring_mod_invea.h"
#endif

#ifdef HAVE_NETCOPE
/* Netcope */
#include "pfring_mod_netcope.h"
#endif

#ifdef HAVE_EXABLAZE
/* Exablaze */
#include "pfring_mod_exablaze.h"
#endif

#ifdef HAVE_NPCAP
/* n2disk timeline */
#include "pfring_mod_timeline.h"
#endif

#ifdef HAVE_PF_RING_ZC
extern int pfring_zc_open(pfring *ring);
#endif

static pfring_module_info pfring_module_list[] = {
  { /* usually you don't need to specify this */
    .name = "default",
    .open = pfring_mod_open,
    .findalldevs = pfring_mod_findalldevs
  },
  {
    .name = "stack",
    .open = pfring_mod_stack_open,
    .findalldevs = NULL
  },
  {
    .name = "sysdig",
    .open = pfring_mod_sysdig_open,
    .findalldevs = NULL
  },
#ifdef HAVE_DAG
  {
    .name = "dag",
    .open = pfring_dag_open,
    .findalldevs = pfring_dag_findalldevs
  },
#endif

#ifdef HAVE_FIBERBLAZE
  {
    .name = "fbcard",
    .open = pfring_fb_open,
    .findalldevs = pfring_fb_findalldevs
  },
#endif

#ifdef HAVE_NT
  {
    .name = "nt",
    .open = pfring_nt_open,
    .findalldevs = pfring_nt_findalldevs
  },
#endif

#ifdef HAVE_MELLANOX
  {
    .name = "mlx",
    .open = pfring_mlx_open,
    .findalldevs = NULL
  },
#endif

#ifdef HAVE_ACCOLADE
  {
    .name = "anic",
    .open = pfring_anic_open,
    .findalldevs = NULL
  },
#endif

#ifdef HAVE_MYRICOM
  {
    .name = "myri",
    .open = pfring_myri_open,
    .findalldevs = pfring_myri_findalldevs
  },
#endif

#ifdef HAVE_INVEATECH
  {
    .name = "invea",
    .open = pfring_invea_open,
    .findalldevs = NULL
  },
#endif

#ifdef HAVE_NETCOPE
  {
    .name = "nsf",
    .open = pfring_netcope_open,
    .findalldevs = NULL
  },
#endif

#ifdef HAVE_EXABLAZE
  {
    .name = "exanic",
    .open = pfring_exablaze_open,
    .findalldevs = NULL
  },
#endif

#ifdef HAVE_PF_RING_ZC
  {
    .name = "zc",
    .open = pfring_zc_open,
    .findalldevs = NULL
  },
#endif

#ifdef HAVE_NPCAP
  {
    .name = "timeline",
    .open = pfring_timeline_open,
    .findalldevs = NULL
  },
#endif

  {0}
};

/* **************************************************** */

pfring *pfring_open(const char *device_name, u_int32_t caplen, u_int32_t flags) {
  int i = -1;
  int mod_found = 0;
  int ret;
  char prefix[32];
  pfring *ring;

  if (device_name == NULL)
    return NULL;

#ifdef RING_DEBUG
  printf("[PF_RING] Attempting to pfring_open(%s)\n", device_name);
#endif

  ring = (pfring *) malloc(sizeof(pfring));

  if (ring == NULL) {
    errno = ENOMEM;
    return NULL;
  }

  if (caplen > MAX_CAPLEN) caplen = MAX_CAPLEN;

  memset(ring, 0, sizeof(pfring));

  ring->caplen              = caplen;
  ring->direction           = rx_and_tx_direction;
  ring->mode                = send_and_recv_mode;
  ring->ft_mode             = software_only;
  ring->flags               = flags;

  ring->promisc             = !!(flags & PF_RING_PROMISC);
  ring->reentrant           = !!(flags & PF_RING_REENTRANT);
  ring->long_header         = !!(flags & PF_RING_LONG_HEADER);
  ring->rss_mode            = (flags & PF_RING_ZC_NOT_REPROGRAM_RSS) ? PF_RING_ZC_NOT_REPROGRAM_RSS : (
                              (flags & PF_RING_ZC_SYMMETRIC_RSS) ? PF_RING_ZC_SYMMETRIC_RSS : (
                              (flags & PF_RING_ZC_FIXED_RSS_Q_0) ? PF_RING_ZC_FIXED_RSS_Q_0 : 0));
  if (flags & PF_RING_ZC_IPONLY_RSS) ring->rss_mode |= PF_RING_ZC_IPONLY_RSS;
  ring->force_timestamp     = !!(flags & PF_RING_TIMESTAMP);
  ring->strip_hw_timestamp  = !!(flags & PF_RING_STRIP_HW_TIMESTAMP);
  ring->hw_ts.enable_hw_timestamp = !!(flags & PF_RING_HW_TIMESTAMP);
  ring->tx.enabled_rx_packet_send = !!(flags & PF_RING_RX_PACKET_BOUNCE);
  ring->disable_parsing     = !!(flags & PF_RING_DO_NOT_PARSE);
  ring->disable_timestamp   = !!(flags & PF_RING_DO_NOT_TIMESTAMP);
  ring->chunk_mode_enabled  = !!(flags & PF_RING_CHUNK_MODE);
  ring->ixia_timestamp_enabled = !!(flags & PF_RING_IXIA_TIMESTAMP);
  ring->vss_apcon_timestamp_enabled = !!(flags & PF_RING_VSS_APCON_TIMESTAMP);
  ring->force_userspace_bpf = !!(flags & PF_RING_USERSPACE_BPF);

#ifdef RING_DEBUG
  printf("[PF_RING] pfring_open: device_name=%s\n", device_name);
#endif
  /* modules */

  ret = -1;
  ring->device_name = NULL;

  while (pfring_module_list[++i].name) {
    sprintf(prefix, "%s:", pfring_module_list[i].name);
    if(strncmp(device_name, prefix, strlen(prefix)) != 0) continue;
    if(!pfring_module_list[i].open)                       continue;
    mod_found = 1;
#ifdef RING_DEBUG
    printf("[PF_RING] pfring_open: found module %s\n", pfring_module_list[i].name);
#endif

    ring->device_name = strdup(&device_name[strlen(prefix)]);
    if (ring->device_name == NULL) {
      errno = ENOMEM;
      free(ring);
      return NULL;
    }
    ret = pfring_module_list[i].open(ring);
    break;
  }

  /* default */
  if(!mod_found) {
    ring->device_name = strdup(device_name ? device_name : "any");
    if (ring->device_name == NULL) {
      errno = ENOMEM;
      free(ring);
      return NULL;
    }
    ret = pfring_mod_open(ring);
  }

  if(ret < 0) {
    errno = ENODEV;
    if (ring->device_name != NULL) free(ring->device_name);
    free(ring);
    return NULL;
  }

  if(unlikely(ring->reentrant)) {
    if (pfring_rwlock_init(&ring->rx_lock, PTHREAD_PROCESS_PRIVATE) != 0 || 
        pfring_rwlock_init(&ring->tx_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
      free(ring);
      return NULL;
    }
  }

  ring->socket_default_accept_policy = 1; /* Accept (default) */

  ring->rdi.device_id = ring->rdi.port_id = -1; /* Default */

  ring->mtu = pfring_get_mtu_size(ring);
  if(ring->mtu == 0) ring->mtu =  9000 /* Jumbo MTU */;

  pfring_get_bound_device_ifindex(ring, &ring->device_id);
  ring->initialized = 1;

#ifdef RING_DEBUG
  printf("[PF_RING] Successfully open pfring_open(%s)\n", device_name);
#endif

  return ring;
}

/* **************************************************** */

u_int8_t pfring_open_multichannel(const char *device_name, u_int32_t caplen,
				  u_int32_t flags,
				  pfring *ring[MAX_NUM_RX_CHANNELS]) {
  u_int8_t num_channels, i, num = 0;
  char *at;
  char base_device_name[32];

  snprintf(base_device_name, sizeof(base_device_name), "%s", device_name);
  at = strchr(base_device_name, '@');
  if(at != NULL)
    at[0] = '\0';

  /* Count how many RX channel the specified device supports */
  ring[0] = pfring_open(base_device_name, caplen, flags);

  if(ring[0] == NULL)
    return(0);
  else
    num_channels = pfring_get_num_rx_channels(ring[0]);

  pfring_close(ring[0]);

  if(num_channels > MAX_NUM_RX_CHANNELS)
    num_channels = MAX_NUM_RX_CHANNELS;

  /* Now do the real job */
  for(i=0; i<num_channels; i++) {
    char dev[32];

    snprintf(dev, sizeof(dev), "%s@%d", base_device_name, i);
    ring[i] = pfring_open(dev, caplen, flags);

    if(ring[i] == NULL)
      return(num);
    else
      num++;
  }

  return(num);
}

/* **************************************************** */

void pfring_close(pfring *ring) {
  if(!ring)
    return;

  if(ring->one_copy_rx_pfring)
    pfring_close(ring->one_copy_rx_pfring);

  pfring_shutdown(ring);

  pfring_sync_indexes_with_kernel(ring);

  if(ring->close)
    ring->close(ring);

  if(unlikely(ring->reentrant)) {
    pfring_rwlock_destroy(&ring->rx_lock);
    pfring_rwlock_destroy(&ring->tx_lock);
  }

  free(ring->device_name);
  free(ring);
}

/* **************************************************** */

void pfring_shutdown(pfring *ring) {
  if (!ring)
    return;

  ring->is_shutting_down = ring->break_recv_loop = 1;

  if(ring->shutdown)
    ring->shutdown(ring);
}

/* **************************************************** */

void pfring_config(u_short cpu_percentage) {
  static u_int pfring_initialized = 0;

  if(!pfring_initialized) {
    struct sched_param schedparam;

    /*if(cpu_percentage >= 50) mlockall(MCL_CURRENT|MCL_FUTURE); */

    pfring_initialized = 1;
    schedparam.sched_priority = cpu_percentage;
    if(sched_setscheduler(0, SCHED_FIFO, &schedparam) == -1) {
      printf("error while setting the scheduler, errno=%i\n", errno);
      exit(1);
    }
  }
}

/* **************************************************** */

int pfring_set_reflector_device(pfring *ring, char *device_name) {
  if((device_name == NULL) || ring->reflector_socket)
    return(-1);

  ring->reflector_socket = pfring_open(device_name, ring->caplen, PF_RING_PROMISC);

  if(ring->reflector_socket != NULL) {
    pfring_set_socket_mode(ring->reflector_socket, send_only_mode);
    pfring_enable_ring(ring->reflector_socket);
    return(0);
  } else
    return(-1);
}

/* **************************************************** */

int pfring_loop(pfring *ring, pfringProcesssPacket looper,
		const u_char *user_bytes, u_int8_t wait_for_packet) {
  struct pfring_pkthdr hdr;
  u_char *buffer = NULL;
  int rc = 0;

  memset(&hdr, 0, sizeof(hdr));
  ring->break_recv_loop = 0;

  if((! ring)
     || ring->is_shutting_down
     || (! ring->recv)
     || ring->mode == send_only_mode)
    return -1;

  while(!ring->break_recv_loop) {
    rc = ring->recv(ring, &buffer, 0, &hdr, wait_for_packet);

    if(rc < 0)
      break;
    else if(rc > 0) {
      hdr.caplen = min_val(hdr.caplen, ring->caplen);

#ifdef ENABLE_BPF
      if (unlikely(ring->userspace_bpf && bpf_filter(ring->userspace_bpf_filter.bf_insns, buffer, hdr.caplen, hdr.len) == 0))
        continue; /* rejected */
#endif
      if(unlikely(ring->ixia_timestamp_enabled))
        pfring_handle_ixia_hw_timestamp(buffer, &hdr);
      else if(unlikely(ring->vss_apcon_timestamp_enabled))
        pfring_handle_vss_apcon_hw_timestamp(buffer, &hdr);

      looper(&hdr, buffer, user_bytes);
    } else {
      /* if(!wait_for_packet) usleep(1); */
    }
  }

  return(rc);
}

/* **************************************************** */

void pfring_breakloop(pfring *ring) {
  if(!ring)
    return;

  ring->break_recv_loop = 1;

  if(ring->one_copy_rx_pfring != NULL)
    ring->one_copy_rx_pfring->break_recv_loop = 1;
}

/* **************************************************** */
/*                Module-specific functions             */
/* **************************************************** */

int pfring_stats(pfring *ring, pfring_stat *stats) {
  if(ring && ring->stats) {
    if(ring->enabled)
      return(ring->stats(ring, stats));
    else {
      memset(stats, 0, sizeof(pfring_stat));
      return(0);
    }
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_recv(pfring *ring, u_char** buffer, u_int buffer_len,
		struct pfring_pkthdr *hdr,
		u_int8_t wait_for_incoming_packet) {
  if (likely(ring
	     && ring->enabled
	     && ring->recv
	     && ring->mode != send_only_mode)) {
    int rc;

    /* Reentrancy is not compatible with zero copy */
    if (unlikely(buffer_len == 0 && ring->reentrant))
      return PF_RING_ERROR_INVALID_ARGUMENT;

    ring->break_recv_loop = 0;

#ifdef ENABLE_BPF
recv_next:
#endif

    rc = ring->recv(ring, buffer, buffer_len, hdr, wait_for_incoming_packet);

    if(unlikely(ring->ixia_timestamp_enabled))
      pfring_handle_ixia_hw_timestamp(*buffer, hdr);
    else if(unlikely(ring->vss_apcon_timestamp_enabled))
      pfring_handle_vss_apcon_hw_timestamp(*buffer, hdr);

#ifdef ENABLE_BPF
    if (unlikely(rc > 0 && ring->userspace_bpf && bpf_filter(ring->userspace_bpf_filter.bf_insns, *buffer, hdr->caplen, hdr->len) == 0))
      goto recv_next; /* rejected */
#endif

    if (unlikely(rc > 0 && ring->reflector_socket != NULL))
        pfring_send(ring->reflector_socket, (char *) *buffer, hdr->caplen, 0 /* flush */);

    return rc;
  }

  if (!ring->enabled)
    return PF_RING_ERROR_RING_NOT_ENABLED;

  return PF_RING_ERROR_NOT_SUPPORTED;
}

/* **************************************************** */

int pfring_recv_parsed(pfring *ring, u_char** buffer, u_int buffer_len,
		       struct pfring_pkthdr *hdr, u_int8_t wait_for_incoming_packet,
		       u_int8_t level /* 1..4 */, u_int8_t add_timestamp, u_int8_t add_hash) {
  int rc = pfring_recv(ring, buffer, buffer_len, hdr, wait_for_incoming_packet);

  if(rc > 0)
    rc = pfring_parse_pkt(*buffer, hdr, level, add_timestamp, add_hash);

  return rc;
}

/* **************************************************** */

int pfring_get_metadata(pfring *ring, u_char **metadata, u_int32_t *metadata_len) {
  if(ring && ring->get_metadata)
    return ring->get_metadata(ring, metadata, metadata_len);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_poll_watermark(pfring *ring, u_int16_t watermark) {
  if(ring && ring->set_poll_watermark)
    return ring->set_poll_watermark(ring, watermark);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_poll_duration(pfring *ring, u_int duration) {
  if(ring && ring->set_poll_duration)
    return ring->set_poll_duration(ring, duration);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_tx_watermark(pfring *ring, u_int16_t watermark) {
  if(ring && ring->set_tx_watermark)
    return ring->set_tx_watermark(ring, watermark);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_add_hw_rule(pfring *ring, hw_filtering_rule *rule) {
  if(ring && ring->add_hw_rule)
    return ring->add_hw_rule(ring, rule);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_remove_hw_rule(pfring *ring, u_int16_t rule_id) {
  if(ring && ring->remove_hw_rule)
    return ring->remove_hw_rule(ring, rule_id);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_channel_id(pfring *ring, u_int32_t channel_id) {
  if(ring && ring->set_channel_id)
    return ring->set_channel_id(ring, channel_id);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_channel_mask(pfring *ring, u_int64_t channel_mask) {
  if(ring && ring->set_channel_mask)
    return ring->set_channel_mask(ring, channel_mask);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_application_name(pfring *ring, char *name) {
  if(ring && ring->set_application_name)
    return ring->set_application_name(ring, name);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_application_stats(pfring *ring, char *stats) {
  if(ring && ring->set_application_stats)
    return ring->set_application_stats(ring, stats);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

char* pfring_get_appl_stats_file_name(pfring *ring, char *path, u_int path_len) {
  if(ring && ring->get_appl_stats_file_name)
    return ring->get_appl_stats_file_name(ring, path, path_len);

  return(NULL);
}

/* **************************************************** */

int pfring_set_vlan_id(pfring *ring, u_int16_t vlan_id) {
  if(ring && ring->set_vlan_id)
    return ring->set_vlan_id(ring, vlan_id & 0x0FFF);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_bind(pfring *ring, char *device_name) {
  if(ring && ring->bind)
    return ring->bind(ring, device_name);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet) {
  int rc;

  if(unlikely(pkt_len > ring->mtu + sizeof(struct ether_header) + sizeof(struct eth_vlan_hdr))) {
    errno = EMSGSIZE;
    return(PF_RING_ERROR_INVALID_ARGUMENT); /* Packet too long */
  }

  if(likely(ring
	    && ring->enabled
	    && (!ring->is_shutting_down)
	    && ring->send
	    && (ring->mode != recv_only_mode))) {

    if(unlikely(ring->reentrant))
      pfring_rwlock_wrlock(&ring->tx_lock);

    rc =  ring->send(ring, pkt, pkt_len, flush_packet);

    if(unlikely(ring->reentrant))
      pfring_rwlock_unlock(&ring->tx_lock);

    return rc;
  }

  if(!ring->enabled)
    return(PF_RING_ERROR_RING_NOT_ENABLED);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_send_get_time(pfring *ring, char *pkt, u_int pkt_len, struct timespec *ts) {
  int rc;

  if(likely(ring
	    && ring->enabled
	    && (!ring->is_shutting_down)
	    && ring->send_get_time
	    && (ring->mode != recv_only_mode))) {

    if(unlikely(ring->reentrant))
      pfring_rwlock_wrlock(&ring->tx_lock);

    rc =  ring->send_get_time(ring, pkt, pkt_len, ts);

    if(unlikely(ring->reentrant))
      pfring_rwlock_unlock(&ring->tx_lock);

    return rc;
  }

  if(!ring->enabled)
    return(PF_RING_ERROR_RING_NOT_ENABLED);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

u_int8_t pfring_get_num_rx_channels(pfring *ring) {
  if(ring && ring->get_num_rx_channels)
    return ring->get_num_rx_channels(ring);

  return 1;
}

/* **************************************************** */

int pfring_get_card_settings(pfring *ring, pfring_card_settings *settings) {
  if(ring && ring->get_card_settings)
    return ring->get_card_settings(ring, settings);

  settings->max_packet_size = ring->mtu + sizeof(struct ether_header) + sizeof(struct eth_vlan_hdr);
  settings->rx_ring_slots = 0;
  settings->tx_ring_slots = 0;

  return 0;
}

/* **************************************************** */

int pfring_set_sampling_rate(pfring *ring, u_int32_t rate /* 1 = no sampling */) {
  if(ring && ring->set_sampling_rate) {
    int rc;

    rc = ring->set_sampling_rate(ring, rate);

    if (rc == 0)
      ring->sampling_rate = rate;

    return(rc);
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_sw_filtering_sampling_rate(pfring *ring, u_int32_t rate /* 0 = no sampling */) {
  if(ring && ring->set_sw_filtering_sampling_rate) {
    int rc;

    rc = ring->set_sw_filtering_sampling_rate(ring, rate);

    if (rc == 0)
      ring->sw_filtering_sampling_rate = rate;

    return(rc);
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_packet_slicing(pfring *ring, packet_slicing_level level, u_int32_t additional_bytes) {
  if (ring && ring->set_packet_slicing) {
    int rc;

    rc = ring->set_packet_slicing(ring, level, additional_bytes);

    if (rc == 0) {
      ring->slicing_level = level;
      ring->slicing_additional_bytes = additional_bytes;
    }

    return rc;
  }

  return PF_RING_ERROR_NOT_SUPPORTED;
}

/* **************************************************** */

int pfring_get_selectable_fd(pfring *ring) {
  if(ring && ring->get_selectable_fd)
    return ring->get_selectable_fd(ring);

  return(-1);
}

/* **************************************************** */

int pfring_set_direction(pfring *ring, packet_direction direction) {
  if(ring && ring->set_direction) {
    int rc;

    /*
      In theory you should enable the direction *before* you
      enable the ring. However doing it from libpcap is not
      possible due to the way the library works. Thus although
      it is a good practice to do so, we removed the check below
      so that libpcap-based apps can work.
     */
#if 0
    if(ring->enabled)
      return -1; /* direction must be set before pfring_enable() */
#endif

    rc = ring->set_direction(ring, direction);

    if(rc == 0)
      ring->direction = direction;

    return(rc);
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_socket_mode(pfring *ring, socket_mode mode) {
  if(ring && ring->set_socket_mode) {
    int rc;

    if(ring->enabled)
      return -1; /* direction must be set before pfring_enable() */

    rc = ring->set_socket_mode(ring, mode);

    if(rc == 0)
      ring->mode = mode;

    return(rc);
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_cluster(pfring *ring, u_int clusterId, cluster_type the_type) {
  if(ring && ring->set_cluster)
    return ring->set_cluster(ring, clusterId, the_type);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_remove_from_cluster(pfring *ring) {
  if(ring && ring->remove_from_cluster)
    return ring->remove_from_cluster(ring);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_master_id(pfring *ring, u_int32_t master_id) {
  if(ring && ring->set_master_id)
    return ring->set_master_id(ring, master_id);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_master(pfring *ring, pfring *master) {
  if(ring && ring->set_master)
    return ring->set_master(ring, master);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

u_int32_t pfring_get_ring_id(pfring *ring) {
  if(ring && ring->get_ring_id)
    return ring->get_ring_id(ring);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

u_int32_t pfring_get_num_queued_pkts(pfring *ring) {
  if(ring && ring->get_num_queued_pkts)
    return ring->get_num_queued_pkts(ring);

  return 0;
}

/* **************************************************** */

int pfring_get_hash_filtering_rule_stats(pfring *ring, hash_filtering_rule* rule,
					 char* stats, u_int *stats_len) {
  if(ring && ring->get_hash_filtering_rule_stats)
    return ring->get_hash_filtering_rule_stats(ring, rule, stats, stats_len);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_handle_hash_filtering_rule(pfring *ring, hash_filtering_rule* rule_to_add,
				      u_char add_rule) {
  if(ring && ring->handle_hash_filtering_rule)
    return ring->handle_hash_filtering_rule(ring, rule_to_add, add_rule);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_purge_idle_hash_rules(pfring *ring, u_int16_t inactivity_sec) {
  if(ring && ring->purge_idle_hash_rules)
    return ring->purge_idle_hash_rules(ring, inactivity_sec);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_purge_idle_rules(pfring *ring, u_int16_t inactivity_sec) {
  if(ring && ring->purge_idle_rules)
    return ring->purge_idle_rules(ring, inactivity_sec);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_add_filtering_rule(pfring *ring, filtering_rule* rule_to_add) {
  if(ring && ring->add_filtering_rule)
    return ring->add_filtering_rule(ring, rule_to_add);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_remove_filtering_rule(pfring *ring, u_int16_t rule_id) {
  if(ring && ring->remove_filtering_rule)
    return ring->remove_filtering_rule(ring, rule_id);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_get_filtering_rule_stats(pfring *ring, u_int16_t rule_id,
				    char* stats, u_int *stats_len) {
  if(ring && ring->get_filtering_rule_stats)
    return ring->get_filtering_rule_stats(ring, rule_id, stats, stats_len);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_toggle_filtering_policy(pfring *ring, u_int8_t rules_default_accept_policy) {
  if (ring && ring->toggle_filtering_policy)
    return ring->toggle_filtering_policy(ring, rules_default_accept_policy);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_enable_rss_rehash(pfring *ring) {
  if(ring && ring->enable_rss_rehash)
    return ring->enable_rss_rehash(ring);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_poll(pfring *ring, u_int wait_duration) {
  if(likely((ring && ring->poll)))
    return ring->poll(ring, wait_duration);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

void pfring_version_noring(u_int32_t *version) {
  *version = RING_VERSION_NUM; 
}

/* **************************************************** */

int pfring_version(pfring *ring, u_int32_t *version) {
  if(ring && ring->version)
    return ring->version(ring, version);

  pfring_version_noring(version);
  return 0;
}

/* **************************************************** */

int pfring_get_bound_device_address(pfring *ring, u_char mac_address[6]) {
  if(ring && ring->get_bound_device_address)
    return ring->get_bound_device_address(ring, mac_address);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

/* TODO: Optimize the call below as ring->device_id initializes the id */

int pfring_get_bound_device_ifindex(pfring *ring, int *if_index) {
  if(ring && ring->get_bound_device_ifindex)
    return ring->get_bound_device_ifindex(ring, if_index);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_get_device_ifindex(pfring *ring, char *device_name, int *if_index) {
  if(ring && ring->get_device_ifindex)
    return ring->get_device_ifindex(ring, device_name, if_index);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_get_link_status(pfring *ring) {
  return(pfring_mod_get_link_status(ring));
}

/* **************************************************** */

u_int16_t pfring_get_slot_header_len(pfring *ring) {
  if(ring && ring->get_slot_header_len)
    return ring->get_slot_header_len(ring);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_virtual_device(pfring *ring, virtual_filtering_device_info *info) {
  if(ring && ring->set_virtual_device)
    return ring->set_virtual_device(ring, info);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_loopback_test(pfring *ring, char *buffer, u_int buffer_len, u_int test_len) {
  if(ring && ring->loopback_test)
    return ring->loopback_test(ring, buffer, buffer_len, test_len);

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_enable_ring(pfring *ring) {
  if(ring && ring->enable_ring) {
    int rc;

    if(ring->enabled) return(0);

    rc = ring->enable_ring(ring);
    if(rc == 0) ring->enabled = 1;

    return rc;
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_disable_ring(pfring *ring) {
  if(ring && ring->disable_ring) {
    int rc;

    if(!ring->enabled) return(0);

    rc = ring->disable_ring(ring);
    if(rc == 0) ring->enabled = 0;

    return rc;
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_is_pkt_available(pfring *ring) {
  if(ring && ring->is_pkt_available) {
    return ring->is_pkt_available(ring);
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_next_pkt_time(pfring *ring, struct timespec *ts) {
  if(ring && ring->next_pkt_time) {
    return ring->next_pkt_time(ring, ts);
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_next_pkt_raw_timestamp(pfring *ring, u_int64_t *ts) {
  if(ring && ring->next_pkt_raw_timestamp) {
    return ring->next_pkt_raw_timestamp(ring, ts);
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_bpf_filter(pfring *ring, char *filter_buffer) {
  int rc = PF_RING_ERROR_NOT_SUPPORTED;

  if (!ring)
    return -1;

  if (!ring->force_userspace_bpf && ring->set_bpf_filter) {
    rc = ring->set_bpf_filter(ring, filter_buffer);
    if (rc == 0 || rc < -1 /* force returning error if != -1 */)
      return rc;
  }

  /* no in-kernel or module-dependent bpf support, setting up userspace bpf */

  if (unlikely(ring->reentrant))
    pfring_rwlock_wrlock(&ring->rx_lock);

  rc = pfring_parse_bpf_filter(filter_buffer, ring->caplen, &ring->userspace_bpf_filter);

#ifdef DEBUG
#ifdef ENABLE_BPF
  if (rc == 0)
    bpf_dump(&ring->userspace_bpf_filter, 1);
#endif
#endif

  if(unlikely(ring->reentrant))
    pfring_rwlock_unlock(&ring->rx_lock);

  if (rc == 0)
    ring->userspace_bpf = 1;

  return rc;
}

/* **************************************************** */

int pfring_remove_bpf_filter(pfring *ring) {
  if(!ring)
    return -1;

  if (!ring->force_userspace_bpf && ring->remove_bpf_filter)
    return ring->remove_bpf_filter(ring);

  if (ring->userspace_bpf) {
    pfring_free_bpf_filter(&ring->userspace_bpf_filter); 
    ring->userspace_bpf = 0;
    return 0;
  }

  return PF_RING_ERROR_NOT_SUPPORTED;
}

/* **************************************************** */

void pfring_sync_indexes_with_kernel(pfring *ring) {
  if(ring && ring->sync_indexes_with_kernel)
    ring->sync_indexes_with_kernel(ring);
}

/* **************************************************** */

int pfring_send_last_rx_packet(pfring *ring, int tx_interface_id) {
  /*
    We can't send the last packet with multithread as the concept of "last"
    does not apply here having threads that compete for packets
  */
  if(unlikely(ring->reentrant || (!ring->long_header)))
    return(PF_RING_ERROR_NOT_SUPPORTED);

  if(ring && ring->send_last_rx_packet)
    return(ring->send_last_rx_packet(ring, tx_interface_id));

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_filtering_mode(pfring *ring, filtering_mode mode) {
  if(!ring)
    return -1;

  ring->ft_mode = mode;
  return 0;
}

/* **************************************************** */

int pfring_get_device_clock(pfring *ring, struct timespec *ts) {
  if(ring && ring->get_device_clock) {
    return ring->get_device_clock(ring, ts);
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_device_clock(pfring *ring, struct timespec *ts) {
  if(ring && ring->set_device_clock) {
    return ring->set_device_clock(ring, ts);
  }

  return PF_RING_ERROR_NOT_SUPPORTED;
}

/* **************************************************** */

int pfring_adjust_device_clock(pfring *ring, struct timespec *offset, int8_t sign) {
  if(ring && ring->adjust_device_clock) {
    return ring->adjust_device_clock(ring, offset, sign);
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_flush_tx_packets(pfring *ring) {
  if(ring && ring->flush_tx_packets) {
    ring->flush_tx_packets(ring);
    return(0);
  }

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_search_payload(pfring *ring, char *string_to_search) {
  if (!ring)
    return(-1);

  return(-2);
}

/* **************************************************** */

int pfring_recv_chunk(pfring *ring, void **chunk, pfring_chunk_info *chunk_info, u_int8_t wait_for_incoming_chunk) {
  if(ring && ring->recv_chunk)
    return(ring->recv_chunk(ring, chunk, chunk_info, wait_for_incoming_chunk));

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

int pfring_set_bound_dev_name(pfring *ring, char *custom_dev_name) {
  if(ring && ring->set_bound_dev_name)
    return(ring->set_bound_dev_name(ring, custom_dev_name));

  return(PF_RING_ERROR_NOT_SUPPORTED);
}

/* **************************************************** */

u_int32_t pfring_get_interface_speed(pfring *ring) {
  if (!ring)
    return 0;

  if (ring->get_interface_speed)
    return ring->get_interface_speed(ring);

  return pfring_mod_get_interface_speed(ring);
}

/* **************************************************** */

pfring_if_t *pfring_findalldevs() {
  pfring_if_t *list = NULL, *last = NULL, *mod_list;
  int i = -1;

  while (pfring_module_list[++i].name) {
    if (pfring_module_list[i].findalldevs == NULL) continue;
    mod_list = pfring_module_list[i].findalldevs();
    if (mod_list == NULL) continue;
    if (last == NULL) { last = mod_list; list = mod_list; }
    else last->next = mod_list;
    while (last->next != NULL)
      last = last->next;
  }

  return list; 
}

/* **************************************************** */

void pfring_freealldevs(pfring_if_t *list) {
  pfring_if_t *tmp = list;
  while (tmp) {
    list = list->next;
    if (tmp->name)        free(tmp->name);
    if (tmp->system_name) free(tmp->system_name);
    if (tmp->module)      free(tmp->module);
    if (tmp->sn)          free(tmp->sn);
    free(tmp);
    tmp = list;
  }
}

/* **************************************************** */
