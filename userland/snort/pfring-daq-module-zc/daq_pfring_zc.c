/*
** Copyright (C) 2012-14 - ntop.org
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sysinfo.h> /* get_nprocs(void) */
#include <unistd.h>
#include <signal.h>
#include <numa.h>
#include <ctype.h>

#include "pfring.h"
#include "pfring_zc.h"
#include "sfbpf.h"
#include "daq_api.h"

//#define SIG_RELOAD
#define ENABLE_BPF
#define DAQ_PF_RING_BEST_EFFORT_BOOST

#ifdef ENABLE_BPF
#include <pcap/pcap.h>
#include <pcap/bpf.h>
#endif

#define DAQ_PF_RING_ZC_VERSION 10

#define DAQ_PF_RING_MAX_NUM_DEVICES 16
#define DAQ_PF_RING_PASSIVE_DEV_IDX  0

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
#define QUEUE_LEN 8192
#endif

typedef struct _pfring_context
{
  DAQ_Mode mode;

  int num_devices;
  char *devices[DAQ_PF_RING_MAX_NUM_DEVICES];
  char *tx_devices[DAQ_PF_RING_MAX_NUM_DEVICES];
  int ifindexes[DAQ_PF_RING_MAX_NUM_DEVICES];
  pfring *qs[DAQ_PF_RING_MAX_NUM_DEVICES];
  pfring_zc_queue* rx_queues[DAQ_PF_RING_MAX_NUM_DEVICES];
  pfring_zc_queue* tx_queues[DAQ_PF_RING_MAX_NUM_DEVICES];

  int ipc_queues[DAQ_PF_RING_MAX_NUM_DEVICES];
  pfring_zc_buffer_pool *ipc_pool;
  int ipc_attach;

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  pfring_zc_queue *q;
  pfring_zc_queue *mq_queues[DAQ_PF_RING_MAX_NUM_DEVICES + 1];
  pfring_zc_multi_queue *mq;
#endif

#ifdef ENABLE_BPF
  int bpf_filter;
  struct bpf_program filter;
#endif

  char errbuf[1024];

  pfring_zc_pkt_buff *buffer;
  pfring_zc_pkt_buff *buffer_inject;

  volatile u_int breakloop;

  int max_buffer_len;
  int snaplen;
  int promisc_flag;
  int timeout;
  DAQ_Analysis_Func_t analysis_func;
  uint32_t netmask;
  DAQ_Stats_t stats;
  int ids_bridge;
  u_int bindcpu;

  uint64_t base_recv[DAQ_PF_RING_MAX_NUM_DEVICES];
  uint64_t base_drop[DAQ_PF_RING_MAX_NUM_DEVICES];

  DAQ_State state;

  pfring_zc_cluster *cluster;
  int cluster_id;

} Pfring_Context_t;

static void pfring_zc_daq_reset_stats(void *handle);
static int pfring_zc_daq_set_filter(void *handle, const char *filter);

static int max_packet_len(Pfring_Context_t *context, char *device, int id, int *card_buffers) {
  int max_len = 1536, num_slots = 32768 /* max */;
  pfring *ring;

  ring = pfring_open(device, 1536, PF_RING_PROMISC);

  if (ring == NULL)
    goto error;

  pfring_get_bound_device_ifindex(ring, &context->ifindexes[id]);

  if (ring->zc_device) {
    pfring_card_settings settings;
    pfring_get_card_settings(ring, &settings);
    max_len = settings.max_packet_size;
    num_slots = settings.rx_ring_slots;
  } else {
    max_len = pfring_get_mtu_size(ring);
    if (max_len == 0) max_len = 9000;
    max_len += 14 + 4;
    num_slots = 0;
  }

  pfring_close(ring);

error:
  *card_buffers = num_slots;
  return max_len;
}

static int is_a_queue(char *device, int *cluster_id, int *queue_id) {
  char *tmp;
  char c_id[32], q_id[32];
  int i;

  /* Syntax <number>@<number> or zc:<number>@<number> */

  tmp = strstr(device, "zc:");
  if (tmp != NULL) tmp = &tmp[3];
  else tmp = device;

  i = 0;
  if (tmp[0] == '\0' || tmp[0] == '@') return 0;
  while (tmp[0] != '@' && tmp[0] != '\0') {
    if (!isdigit(tmp[0])) return 0;
    c_id[i++] = tmp[0];
    tmp++;
  }
  c_id[i] = '\0';

  i = 0;
  if (tmp[0] == '@') tmp++;
  if (tmp[0] == '\0') return 0;
  while (tmp[0] != '\0') {
    if (!isdigit(tmp[0])) return 0;
    q_id[i++] = tmp[0];
    tmp++;
  }
  q_id[i] = '\0';

  *cluster_id = atoi(c_id);
  *queue_id = atoi(q_id);

  return 1;
}

static int pfring_zc_daq_open(Pfring_Context_t *context, int id, char *errbuf, size_t len) {
  uint32_t default_net = 0xFFFFFF00;
  char *device = context->devices[id], *tx_device = context->tx_devices[id];
  pfring_zc_queue *q = NULL;

  if (device == NULL) {
    snprintf(errbuf, len, "pfring_zc_open_device(): device #%d name not found", id);
    return -1;
  }
 
  if (context->mode == DAQ_MODE_INLINE || (context->mode == DAQ_MODE_PASSIVE && context->ids_bridge)) {
    q = pfring_zc_open_device(context->cluster,
                              tx_device,
                              tx_only,
                              (context->promisc_flag ? PF_RING_PROMISC : 0));

    if (q == NULL) {
      snprintf(errbuf, len, "pfring_zc_open_device(): unable to open device '%s' (TX)", tx_device);
      return -1;
    }

    context->tx_queues[id] = q;
#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
    context->mq_queues[id] = q;
#endif
  }

  if (!context->ipc_attach) {

    q = pfring_zc_open_device(context->cluster,
                              device,
                              rx_only,
                              (context->promisc_flag ? PF_RING_PROMISC : 0) | PF_RING_ZC_DEVICE_SW_TIMESTAMP);

    if (q == NULL) {
      snprintf(errbuf, len, "pfring_zc_open_device(): unable to open device '%s' (RX)", device);
      return -1;
    }

  } else {

    q = pfring_zc_ipc_attach_queue(context->cluster_id, context->ipc_queues[id], rx_only);

    if (q == NULL) {
      snprintf(errbuf, len, "pfring_zc_ipc_attach_queue(): unable to open queue %d from cluster %d (RX)", 
        context->ipc_queues[id], context->cluster_id);
      return -1;
    }

  }

  context->rx_queues[id] = q;

  context->netmask = htonl(default_net);

  return 0;
}

static int update_hw_stats(Pfring_Context_t *context) {
  pfring_zc_stat ps;
  int i;

  for (i = 0; i < context->num_devices; i++)
    if (context->rx_queues[i] == NULL)
      /* daq stopped - using last available stats */
      return DAQ_SUCCESS;

  context->stats.hw_packets_received = 0;
  context->stats.hw_packets_dropped = 0;

  for (i = 0; i < context->num_devices; i++) {
    memset(&ps, 0, sizeof(pfring_zc_stat));

    if (pfring_zc_stats(context->rx_queues[i], &ps) < 0) {
      DPE(context->errbuf, "%s: pfring_stats error [ring_idx = %d]", __FUNCTION__, i);
      return DAQ_ERROR;
    }

    context->stats.hw_packets_received += (ps.recv - context->base_recv[i]);
    context->stats.hw_packets_dropped  += (ps.drop - context->base_drop[i]);
  }

  return DAQ_SUCCESS;
}

#ifdef SIG_RELOAD
static sighandler_t default_sig_reload_handler = NULL;
static u_int8_t pfring_zc_daq_reload_requested = 0;

static void pfring_zc_daq_sig_reload(int sig) {
  if (default_sig_reload_handler != NULL)
    default_sig_reload_handler(sig);

  pfring_zc_daq_reload_requested = 1;
}

static void pfring_zc_daq_reload(Pfring_Context_t *context) {
  pfring_zc_daq_reload_requested = 0;

  /* Reload actions (e.g. purge filtering rules) */
}
#endif

static int pfring_zc_daq_initialize(const DAQ_Config_t *config,
				 void **ctxt_ptr, char *errbuf, size_t len) {
  Pfring_Context_t *context;
  DAQ_Dict* entry;
  u_int numCPU = get_nprocs();
  int i, max_buffer_len = 0, card_buffers;
  int num_buffers;
  int ipc_cluster_id;

  context = calloc(1, sizeof(Pfring_Context_t));

  if (context == NULL) {
    snprintf(errbuf, len, "%s: Couldn't allocate memory for context!", __FUNCTION__);
    return DAQ_ERROR_NOMEM;
  }

  context->mode = config->mode;
  context->snaplen = config->snaplen;
  context->promisc_flag =(config->flags & DAQ_CFG_PROMISC);
  context->timeout = (config->timeout > 0) ? (int) config->timeout : -1;
  context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX] = strdup(config->name);
  context->num_devices = 1;
  context->ids_bridge = 0;
  context->cluster_id = -1;
  context->max_buffer_len = 0;
  context->bindcpu = 0;
  context->ipc_attach = 0;

  if (!context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX]) {
    snprintf(errbuf, len, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
    free(context);
    return DAQ_ERROR_NOMEM;
  }

  for (entry = config->values; entry; entry = entry->next) {
    if (!entry->value || !*entry->value) {
      snprintf(errbuf, len, "%s: variable needs value(%s)\n", __FUNCTION__, entry->key);
      return DAQ_ERROR;
    } else if (!strcmp(entry->key, "bindcpu")) {
      char *end = entry->value;
      context->bindcpu = (int) strtol(entry->value, &end, 0);
      if(*end
	 || (context->bindcpu >= numCPU)) {
	snprintf(errbuf, len, "%s: bad bindcpu(%s)\n", __FUNCTION__, entry->value);
	return DAQ_ERROR;
      } else {
	cpu_set_t mask;

	CPU_ZERO(&mask);
	CPU_SET((int)context->bindcpu, &mask);
	if (sched_setaffinity(0, sizeof(mask), &mask) < 0) {
	  snprintf(errbuf, len, "%s:failed to set bindcpu(%u) on pid %i\n", __FUNCTION__, context->bindcpu, getpid());
	  return DAQ_ERROR;
	}
      }
    } else if (!strcmp(entry->key, "timeout")) {
      char *end = entry->value;
      context->timeout = (int) strtol(entry->value, &end, 0);
      if (*end || (context->timeout < 0)) {
	snprintf(errbuf, len, "%s: bad timeout(%s)\n", __FUNCTION__, entry->value);
	return DAQ_ERROR;
      }
    } else if (!strcmp(entry->key, "idsbridge")) {
      if (context->mode == DAQ_MODE_PASSIVE) {
        char* end = entry->value;
        context->ids_bridge = (int) strtol(entry->value, &end, 0);
	if (*end || (context->ids_bridge < 0) || (context->ids_bridge > 2)) {
	  snprintf(errbuf, len, "%s: bad ids bridge mode(%s)\n", __FUNCTION__, entry->value);
	  return DAQ_ERROR;
	}
      } else {
        snprintf(errbuf, len, "%s: idsbridge is for passive mode only\n", __FUNCTION__);
        return DAQ_ERROR;
      }
    } else if (!strcmp(entry->key, "clusterid")) {
      char *end = entry->value;
      context->cluster_id = (int) strtol(entry->value, &end, 0);
      if (*end || (context->cluster_id < 0)) {
        snprintf(errbuf, len, "%s: bad clusterid(%s)\n", __FUNCTION__, entry->value);
        return DAQ_ERROR;
      }
    } else {
      snprintf(errbuf, len, "%s: unsupported variable(%s=%s)\n", __FUNCTION__, entry->key, entry->value);
      return DAQ_ERROR;
    }
  }

  if (context->mode == DAQ_MODE_READ_FILE) {
    snprintf(errbuf, len, "%s: function not supported on PF_RING", __FUNCTION__);
    free(context);
    return DAQ_ERROR;
  } else if (context->mode == DAQ_MODE_INLINE || (context->mode == DAQ_MODE_PASSIVE && context->ids_bridge)) {
    /* zc:ethX+zc:ethY,zc:ethZ+zc:ethJ */
    char *twins, *twins_pos = NULL;
    context->num_devices = 0;

    twins = strtok_r(context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX], ",", &twins_pos);
    while(twins != NULL) {
      char *dev, *dev_pos = NULL, *tx_dev;
      int last_twin = 0;

      dev = strtok_r(twins, "+", &dev_pos);
      while (dev != NULL) {

        if (context->num_devices >= DAQ_PF_RING_MAX_NUM_DEVICES) {
          snprintf(errbuf, len, "%s: Maximum num of devices reached (%d), you should increase "
	    "DAQ_PF_RING_MAX_NUM_DEVICES.\n", __FUNCTION__, DAQ_PF_RING_MAX_NUM_DEVICES);
          free(context);
          return DAQ_ERROR;
        }

        last_twin = context->num_devices;

	context->devices[context->num_devices] = dev;

        tx_dev = strchr(dev, '-');
        if (tx_dev != NULL) { /* use the specified device for tx */
          tx_dev[0] = '\0';
          tx_dev++;
	  context->tx_devices[context->num_devices] = tx_dev;
        } else {
	  context->tx_devices[context->num_devices] = dev;
        }

        context->num_devices++;

        dev = strtok_r(NULL, "+", &dev_pos);
      }

      if (context->num_devices & 0x1) {
        snprintf(errbuf, len, "%s: Wrong format: %s requires pairs of devices",
	         __FUNCTION__, context->mode == DAQ_MODE_INLINE ? "inline mode" : "ids bridge");
        free(context);
        return DAQ_ERROR;
      }

      if (last_twin > 0) /* new dev pair */
        printf("%s <-> %s\n", context->devices[last_twin - 1], context->devices[last_twin]);

      twins = strtok_r(NULL, ",", &twins_pos);
    }
  } else if(context->mode == DAQ_MODE_PASSIVE) {
    /* zc:ethX,zc:ethY */
    char *dev, *dev_pos = NULL;
    context->num_devices = 0;
    context->ipc_attach = 1; /* IPC queue attach supported in pure IDS only at the moment */

    dev = strtok_r(context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX], ",", &dev_pos);
    while (dev != NULL) {

      /* checking for IPC Queue */
      if (!is_a_queue(dev, &ipc_cluster_id, &context->ipc_queues[context->num_devices])) {
        context->ipc_attach = 0;
      } else {
        if (context->cluster_id == -1)
          context->cluster_id = ipc_cluster_id;
        else if (ipc_cluster_id != context->cluster_id)
          context->ipc_attach = 0;
      }

      context->devices[context->num_devices++] = dev;
      dev = strtok_r(NULL, ",", &dev_pos);
    }
  }

#ifdef SIG_RELOAD
  /* catching the SIGRELOAD signal, replacing the default snort handler */
  if ((default_sig_reload_handler = signal(SIGHUP, pfring_zc_daq_sig_reload)) == SIG_ERR)
    default_sig_reload_handler = NULL;
#endif

  if (!context->ipc_attach) {

    num_buffers = 2 /* buffer, buffer_inject */;

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
    if (context->mode == DAQ_MODE_PASSIVE && context->ids_bridge == 2)
      num_buffers += QUEUE_LEN;
#endif

    for (i = 0; i < context->num_devices; i++) {
      max_buffer_len = max_packet_len(context, context->devices[i], i, &card_buffers);
      if (max_buffer_len > context->max_buffer_len) context->max_buffer_len = max_buffer_len;
      if (strstr(context->devices[i], "zc:") != NULL) num_buffers += card_buffers;
      if (context->tx_devices[i] != NULL) {
        max_buffer_len = max_packet_len(context, context->tx_devices[i], i, &card_buffers);
        if (max_buffer_len > context->max_buffer_len) context->max_buffer_len = max_buffer_len;
        if (strstr(context->tx_devices[i], "zc:") != NULL) num_buffers += card_buffers;
      }
    }

    context->cluster = pfring_zc_create_cluster(context->cluster_id, context->max_buffer_len, 0, num_buffers,
                                              context->bindcpu == 0 ? -1 : numa_node_of_cpu(context->bindcpu), NULL);

    if (context->cluster == NULL) {
      snprintf(errbuf, len, "%s: Cluster failed: %s (error %d)", __FUNCTION__, strerror(errno), errno);
      return DAQ_ERROR;
    }

    context->buffer = pfring_zc_get_packet_handle(context->cluster);

    if (context->buffer == NULL) {
      snprintf(errbuf, len, "%s: Buffer allocation failed: %s(%d)", __FUNCTION__, strerror(errno), errno);
      return DAQ_ERROR;
    }

    context->buffer_inject = pfring_zc_get_packet_handle(context->cluster);

    if (context->buffer_inject == NULL) {
      snprintf(errbuf, len, "%s: Buffer allocation failed: %s(%d)", __FUNCTION__, strerror(errno), errno);
      return DAQ_ERROR;
    }

  } else {

    context->ipc_pool = pfring_zc_ipc_attach_buffer_pool(context->cluster_id, context->ipc_queues[0]);

    if(context->ipc_pool == NULL) {
      snprintf(errbuf, len, "%s: pfring_zc_ipc_attach_buffer_pool error %s(%d), please check that cluster %d is running\n",
          __FUNCTION__, strerror(errno), errno, context->cluster_id);
      return -1;
    }

    context->buffer = pfring_zc_get_packet_handle_from_pool(context->ipc_pool);

    if (context->buffer == NULL) {
      snprintf(errbuf, len, "%s: Buffer allocation failed: %s(%d)", __FUNCTION__, strerror(errno), errno);
      return DAQ_ERROR;
    }

  }

  for (i = 0; i < context->num_devices; i++) {
    if (pfring_zc_daq_open(context, i, errbuf, len) == -1)
      return DAQ_ERROR;
  }

  if (!context->ipc_attach) {
#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
    if (context->mode == DAQ_MODE_PASSIVE && context->ids_bridge == 2) {
      context->q = pfring_zc_create_queue(context->cluster, QUEUE_LEN);

      if (context->q == NULL) {
        snprintf(errbuf, len, "%s: Couldn't create queue: '%s'", __FUNCTION__, strerror(errno));
        return DAQ_ERROR_NOMEM;
      }

      context->mq_queues[context->num_devices] = context->q;
      context->mq = pfring_zc_create_multi_queue(context->mq_queues, context->num_devices + 1);
    }
#endif
  }

  context->state = DAQ_STATE_INITIALIZED;

  *ctxt_ptr = context;
  return DAQ_SUCCESS;
}

static int pfring_zc_daq_set_filter(void *handle, const char *filter) {
  Pfring_Context_t *context = (Pfring_Context_t *) handle;

#ifdef ENABLE_BPF
  if (pcap_compile_nopcap(context->snaplen, /* snaplen_arg */
                          DLT_EN10MB,       /* linktype_arg */
                          &context->filter, /* program */
                          filter,           /* const char *buf */
                          0,                /* optimize */
                          0                 /* mask */
                          ) == -1) {
    goto bpf_error;
  }

  if (context->filter.bf_insns == NULL)
    goto bpf_error;

  context->bpf_filter = 1;

  return DAQ_SUCCESS;

bpf_error:
  DPE(context->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__); 
#else
  DPE(context->errbuf, "%s: BPF filters not supported!", __FUNCTION__);
#endif
  return DAQ_ERROR;
}

static int pfring_zc_daq_start(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  pfring_zc_daq_reset_stats(context);
  context->state = DAQ_STATE_STARTED;

  return DAQ_SUCCESS;
}

static int pfring_zc_daq_send_packet(Pfring_Context_t *context, pfring_zc_queue *txq, u_int pkt_len) {
  int rc;

  if (txq == NULL)
    return DAQ_ERROR;

  rc = pfring_zc_send_pkt(txq, &context->buffer, 1 /* flush packet */);

  if (rc < 0) {
    DPE(context->errbuf, "%s", "pfring_zc_send_pkt() error");
    return DAQ_ERROR;
  }

  context->stats.packets_injected++;

  return DAQ_SUCCESS;
}

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST

static inline void pfring_zc_daq_process(Pfring_Context_t *context, pfring_zc_pkt_buff *buffer, void *user) {
  DAQ_PktHdr_t hdr;
  DAQ_Verdict verdict;
  u_char *pkt_buffer;

  hdr.pktlen = hdr.caplen = buffer->len;
  hdr.ts.tv_sec = buffer->ts.tv_sec;
  hdr.ts.tv_usec = buffer->ts.tv_nsec/1000;
#if (DAQ_API_VERSION >= 0x00010002)
  hdr.ingress_index = buffer->hash;
  hdr.egress_index = -1;
  hdr.ingress_group = -1;
  hdr.egress_group = -1;
#else
  hdr.device_index = buffer->hash;
#endif
  hdr.flags = 0;

  pkt_buffer = pfring_zc_pkt_buff_data(buffer, context->q);

  verdict = context->analysis_func(user, &hdr, pkt_buffer);

  if(verdict >= MAX_DAQ_VERDICT)
    verdict = DAQ_VERDICT_PASS;

  switch(verdict) {
    case DAQ_VERDICT_BLACKLIST: /* Block the packet and block all future packets in the same flow systemwide. */
      /* TODO handle hw filters */
      break;
    case DAQ_VERDICT_WHITELIST: /* Pass the packet and fastpath all future packets in the same flow systemwide. */
    case DAQ_VERDICT_IGNORE:    /* Pass the packet and fastpath all future packets in the same flow for this application. */
    case DAQ_VERDICT_PASS:      /* Pass the packet */
    case DAQ_VERDICT_REPLACE:   /* Pass a packet that has been modified in-place.(No resizing allowed!) */
    case DAQ_VERDICT_BLOCK:     /* Block the packet. */
      /* Nothing to do really */
      break;
    case MAX_DAQ_VERDICT:
      /* No way we can reach this point */
      break;
  }

  context->stats.packets_received++;
  context->stats.verdicts[verdict]++;
}

static inline int pfring_zc_daq_in_packets(Pfring_Context_t *context, u_int32_t *rx_ring_idx) {
  int i;
  
  for (i = 0; i < context->num_devices; i++) {
    *rx_ring_idx = ((*rx_ring_idx) + 1) % context->num_devices;
    if (!pfring_zc_queue_is_empty(context->rx_queues[*rx_ring_idx])) 
      return 1;
  }

  return 0;
}

static int pfring_zc_daq_acquire_best_effort(void *handle, int cnt, DAQ_Analysis_Func_t callback,
#if (DAQ_API_VERSION >= 0x00010002)
                              DAQ_Meta_Func_t metaback,
#endif
			      void *user) {
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int ret = 0, c = 0;
  u_int32_t rx_ring_idx = context->num_devices - 1, rx_ring_idx_clone;
  u_int32_t mask = 0;
  u_char *pkt_buffer;

  context->analysis_func = callback;
  context->breakloop = 0;

  while (!context->breakloop && (cnt <= 0 || c < cnt)) {

#ifdef SIG_RELOAD
    if (pfring_zc_daq_reload_requested)
      pfring_zc_daq_reload(context);
#endif

    while (pfring_zc_daq_in_packets(context, &rx_ring_idx) && !context->breakloop) {

      pfring_zc_recv_pkt(context->rx_queues[rx_ring_idx], &context->buffer, 0);

      context->buffer->hash = context->ifindexes[rx_ring_idx];

      pkt_buffer = pfring_zc_pkt_buff_data(context->buffer, context->rx_queues[rx_ring_idx]);

#ifdef ENABLE_BPF
      if (!context->bpf_filter || bpf_filter(context->filter.bf_insns, pkt_buffer, context->buffer->len /* caplen */, context->buffer->len) != 0) { /* accept */
#endif
        /* enqueueing pkt (and don't care of no room available) */
        mask = 1 << (context->num_devices); 
#ifdef ENABLE_BPF
      } else {
        context->stats.packets_received++;
        context->stats.verdicts[DAQ_VERDICT_PASS]++;
      }
#endif
      mask |= 1 << (rx_ring_idx ^ 0x1);
      pfring_zc_send_pkt_multi(context->mq, &context->buffer, mask, 0);
    }

    rx_ring_idx_clone = rx_ring_idx;
    while (!(ret = pfring_zc_daq_in_packets(context, &rx_ring_idx_clone)) && !pfring_zc_queue_is_empty(context->q) && !context->breakloop) {
      ret = pfring_zc_recv_pkt(context->q, &context->buffer, 0);
      pfring_zc_daq_process(context, context->buffer, user);
      c++;
    }

    if (!ret) {
      if (usleep(1) == -1)
        if (errno == EINTR)
          break;
    }
  }

  return 0;
}

#endif

static int pfring_zc_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback,
#if (DAQ_API_VERSION >= 0x00010002)
                              DAQ_Meta_Func_t metaback,
#endif
			      void *user) {
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int ret = 0, i = 0, rx_ring_idx = context->num_devices - 1, c = 0;
  DAQ_PktHdr_t hdr;
  DAQ_Verdict verdict;
  u_char *pkt_buffer;

#ifdef DAQ_PF_RING_BEST_EFFORT_BOOST
  if (context->mode == DAQ_MODE_PASSIVE && context->ids_bridge == 2)
    return pfring_zc_daq_acquire_best_effort(handle, cnt, callback, 
#if (DAQ_API_VERSION >= 0x00010002)
      metaback,
#endif 
      user);
#endif

  context->analysis_func = callback;
  context->breakloop = 0;

  while (!context->breakloop && (cnt <= 0 || c < cnt)) {

#ifdef SIG_RELOAD
    if (pfring_zc_daq_reload_requested)
      pfring_zc_daq_reload(context);
#endif

    for (i = 0; i < context->num_devices; i++) {
      rx_ring_idx = (rx_ring_idx + 1) % context->num_devices;

      ret = pfring_zc_recv_pkt(context->rx_queues[rx_ring_idx], &context->buffer, 0 /* Dont't wait */);

      if (ret > 0)
        break;
    }

    if (ret <= 0) {
      if (usleep(1) == -1)
        if (errno == EINTR)
          break;
      continue;
    }

    hdr.pktlen = hdr.caplen = context->buffer->len;
    hdr.ts.tv_sec = context->buffer->ts.tv_sec;
    hdr.ts.tv_usec = context->buffer->ts.tv_nsec/1000;
#if (DAQ_API_VERSION >= 0x00010002)
    hdr.ingress_index = context->ifindexes[rx_ring_idx];
    hdr.egress_index = -1;
    hdr.ingress_group = -1;
    hdr.egress_group = -1;
#else
    hdr.device_index = context->ifindexes[rx_ring_idx];
#endif
    hdr.flags = 0;

    pkt_buffer = pfring_zc_pkt_buff_data(context->buffer, context->rx_queues[rx_ring_idx]);

#ifdef ENABLE_BPF
    if (!context->bpf_filter || bpf_filter(context->filter.bf_insns, pkt_buffer, hdr.caplen, hdr.pktlen) != 0) { /* analyse */
#endif
      verdict = context->analysis_func(user, &hdr, pkt_buffer);
#ifdef ENABLE_BPF
    } else
      verdict = DAQ_VERDICT_PASS;
#endif

    if (verdict >= MAX_DAQ_VERDICT)
      verdict = DAQ_VERDICT_PASS;

    if (context->mode == DAQ_MODE_PASSIVE && context->ids_bridge) { /* always forward the packet */

      pfring_zc_daq_send_packet(context, context->tx_queues[rx_ring_idx ^ 0x1], hdr.caplen);

    } else if (context->mode == DAQ_MODE_INLINE && verdict != DAQ_VERDICT_PASS /* optimisation */ ) {
      /* parsing eth_type to forward ARP */
      struct ethhdr *eh = (struct ethhdr *) pkt_buffer;
      u_int16_t eth_type = ntohs(eh->h_proto);
      u_int16_t vlan_offset = 0;
      if (eth_type == 0x8100 /* 802.1q (VLAN) */) {
        struct eth_vlan_hdr *vh;
        vlan_offset = sizeof(struct ethhdr) - sizeof(struct eth_vlan_hdr);
        while (eth_type == 0x8100 /* 802.1q (VLAN) */ ) {
          vlan_offset += sizeof(struct eth_vlan_hdr);
          vh = (struct eth_vlan_hdr *) &pkt_buffer[vlan_offset];
          eth_type = ntohs(vh->h_proto);
        }
      }

      if (eth_type == 0x0806 /* ARP */ )
        verdict = DAQ_VERDICT_PASS;
    }

    switch(verdict) {
      case DAQ_VERDICT_BLACKLIST: /* Block the packet and block all future packets in the same flow systemwide. */
        /* TODO handle hw filters */
	break;
      case DAQ_VERDICT_WHITELIST: /* Pass the packet and fastpath all future packets in the same flow systemwide. */
      case DAQ_VERDICT_IGNORE:    /* Pass the packet and fastpath all future packets in the same flow for this application. */
      case DAQ_VERDICT_PASS:      /* Pass the packet */
      case DAQ_VERDICT_REPLACE:   /* Pass a packet that has been modified in-place.(No resizing allowed!) */
        if (context->mode == DAQ_MODE_INLINE)
	  pfring_zc_daq_send_packet(context, context->tx_queues[rx_ring_idx ^ 0x1], hdr.caplen);
	break;
      case DAQ_VERDICT_BLOCK:     /* Block the packet. */
	/* Nothing to do really */
	break;
      case MAX_DAQ_VERDICT:
	/* No way we can reach this point */
	break;
    }

    context->stats.packets_received++;
    context->stats.verdicts[verdict]++;
    c++;
  }

  return 0;
}

static int pfring_zc_daq_inject(void *handle, const DAQ_PktHdr_t *hdr,
			     const uint8_t *packet_data, uint32_t len, int reverse) {
  Pfring_Context_t *context = (Pfring_Context_t *) handle;
  int i, tx_ring_idx = DAQ_PF_RING_PASSIVE_DEV_IDX;

  if (!(context->mode == DAQ_MODE_INLINE || (context->mode == DAQ_MODE_PASSIVE && context->ids_bridge)))
    return DAQ_ERROR;

  for (i = 0; i < context->num_devices; i++) {
    if (context->ifindexes[i] == 
#if (DAQ_API_VERSION >= 0x00010002)
        hdr->ingress_index
#else
        hdr->device_index
#endif
       ) {
      tx_ring_idx = i ^ 0x1; /* TODO Check this (do we have to send to i or i ^ 0x1?) */
      break;
    }
  }

  memcpy(
    pfring_zc_pkt_buff_data(context->buffer_inject, context->rx_queues[tx_ring_idx]), 
    packet_data, 
    len
  );

  if(pfring_zc_send_pkt(context->tx_queues[tx_ring_idx],
		        &context->buffer_inject, 1 /* flush packet */) < 0) {
    DPE(context->errbuf, "%s", "pfring_zc_send_pkt() error");
    return DAQ_ERROR;
  }

  context->stats.packets_injected++;
  return DAQ_SUCCESS;
}

static int pfring_zc_daq_breakloop(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if (!context->rx_queues[DAQ_PF_RING_PASSIVE_DEV_IDX])
    return DAQ_ERROR;

  context->breakloop = 1;

  return DAQ_SUCCESS;
}

static int pfring_zc_daq_stop(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  update_hw_stats(context);

  context->state = DAQ_STATE_STOPPED;

  return DAQ_SUCCESS;
}

static void pfring_zc_daq_shutdown(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if (context->cluster)
    pfring_zc_destroy_cluster(context->cluster);

  if (context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX])
    free(context->devices[DAQ_PF_RING_PASSIVE_DEV_IDX]);

  free(context);
}

static DAQ_State pfring_zc_daq_check_status(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  return context->state;
}

static int pfring_zc_daq_get_stats(void *handle, DAQ_Stats_t *stats) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  update_hw_stats(context);

  memcpy(stats, &context->stats, sizeof(DAQ_Stats_t));

  return DAQ_SUCCESS;
}

static void pfring_zc_daq_reset_stats(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;
  pfring_zc_stat ps;
  int i;

  memset(&context->stats, 0, sizeof(DAQ_Stats_t));
  memset(&ps, 0, sizeof(pfring_zc_stat));

  for (i = 0; i < context->num_devices; i++) {
    if (context->rx_queues[i] && pfring_zc_stats(context->rx_queues[i], &ps) == 0) {
      context->base_recv[i] = ps.recv;
      context->base_drop[i] = ps.drop;
    }
  }
}

static int pfring_zc_daq_get_snaplen(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if (!context->rx_queues[DAQ_PF_RING_PASSIVE_DEV_IDX])
    return DAQ_ERROR;

  return context->snaplen;
}

static uint32_t pfring_zc_daq_get_capabilities(void *handle) {
  return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
    DAQ_CAPA_INJECT_RAW | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BPF;
}

static int pfring_zc_daq_get_datalink_type(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if (!context)
    return DAQ_ERROR;

  return DLT_EN10MB;
}

static const char *pfring_zc_daq_get_errbuf(void *handle) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  return context->errbuf;
}

static void pfring_zc_daq_set_errbuf(void *handle, const char *string) {
  Pfring_Context_t *context =(Pfring_Context_t *) handle;

  if (!string)
    return;

  DPE(context->errbuf, "%s", string);
}

static int pfring_zc_daq_get_device_index(void *handle, const char *device) {
  return DAQ_ERROR_NOTSUP;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
  const DAQ_Module_t pfring_zc_daq_module_data =
#endif
  {
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_PF_RING_ZC_VERSION,
    .name = "pfring_zc",
    .type = DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    .initialize = pfring_zc_daq_initialize,
    .set_filter = pfring_zc_daq_set_filter,
    .start = pfring_zc_daq_start,
    .acquire = pfring_zc_daq_acquire,
    .inject = pfring_zc_daq_inject,
    .breakloop = pfring_zc_daq_breakloop,
    .stop = pfring_zc_daq_stop,
    .shutdown = pfring_zc_daq_shutdown,
    .check_status = pfring_zc_daq_check_status,
    .get_stats = pfring_zc_daq_get_stats,
    .reset_stats = pfring_zc_daq_reset_stats,
    .get_snaplen = pfring_zc_daq_get_snaplen,
    .get_capabilities = pfring_zc_daq_get_capabilities,
    .get_datalink_type = pfring_zc_daq_get_datalink_type,
    .get_errbuf = pfring_zc_daq_get_errbuf,
    .set_errbuf = pfring_zc_daq_set_errbuf,
    .get_device_index = pfring_zc_daq_get_device_index
  };
