/*
 *
 * (C) 2015 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 */

#include "pfring_mod_mlx.h"
#include "pfring_mod.h" /* to print stats under /proc */

#include <limits.h>

/* **************************************************** */

static struct ibv_qp *mlx_create_qp(struct mlx_ring *ring, int nent) {
  struct ibv_exp_qp_init_attr attr;
  struct ibv_qp* qp = NULL;

  memset(&attr, 0, sizeof(struct ibv_exp_qp_init_attr));

  attr.pd = ring->pd;
  attr.send_cq = ring->cq;
  attr.recv_cq = ring->cq;
  attr.cap.max_recv_wr = nent;
  attr.cap.max_send_wr = nent;
  attr.cap.max_recv_sge = MAX_SGE;
  attr.cap.max_send_sge = MAX_SGE;
  attr.qp_type = IBV_QPT_RAW_PACKET;
  attr.cap.max_inline_data = MAX_INLINE;
  attr.comp_mask = IBV_EXP_QP_INIT_ATTR_PD;
  qp = ibv_exp_create_qp(ring->context, &attr);

  return qp;
}

/* **************************************************** */

static int mlx_qp_to_ready(struct ibv_qp *qp, int port) {
  struct ibv_qp_attr attr;

  memset(&attr, 0, sizeof(struct ibv_qp_attr));

  attr.qp_state = IBV_QPS_INIT;
  attr.port_num = port;

  if(ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_PORT))
    return(-1);

  attr.qp_state = IBV_QPS_RTR;
  if(ibv_modify_qp(qp, &attr, IBV_QP_STATE))
    return(-1);

  attr.qp_state = IBV_QPS_RTS;
  if(ibv_modify_qp(qp, &attr, IBV_QP_STATE))
    return(-1);

  return(0);
}

/* **************************************************** */

static int mlx_configure_qp(struct mlx_ring *ring, u_int mtu_len, u_int num_entries, u_int port_num) {
  int buf_size = num_entries * mtu_len;

  if((ring->buf = (uint8_t*)memalign(sysconf(_SC_PAGESIZE),sizeof(uint8_t)*buf_size)) == NULL)
    goto err_mr;
  else
    memset(ring->buf, 0, buf_size);

  if((ring->sg = (struct ibv_sge*)malloc(sizeof(struct ibv_sge)*num_entries)) == NULL)
    goto err_mr;

  if((ring->wc = (struct ibv_wc*)malloc(sizeof(struct ibv_wc)*WC_POLL_FETCH)) == NULL)
    goto err_mr;

  ring->mr = ibv_reg_mr(ring->pd, ring->buf, buf_size, IBV_ACCESS_LOCAL_WRITE);
  if(!ring->mr) {
    printf("Failure allocating MR\n");
    goto err_mr;
  }

  ring->cq = ibv_create_cq(ring->context, num_entries, NULL, NULL, 0);
  if(!ring->cq) {
    printf("Failure allocating CQ\n");
    goto err_cq;
  }

  ring->qp = mlx_create_qp(ring, num_entries);
  if(!ring->qp) {
    printf("Cannot allocate QP\n");
    goto err_qp;
  }

  if(mlx_qp_to_ready(ring->qp, port_num)) {
    printf("Error moving RAW QP to ready\n");
    goto err_qp_ready;
  }

  return(0);

 err_qp_ready:
  ibv_destroy_qp(ring->qp);

 err_qp:
  ibv_destroy_cq(ring->cq);

 err_cq:
  ibv_dereg_mr(ring->mr);

 err_mr:
  free(ring->buf);
  free(ring->sg);

  return(-1);
}

/* **************************************************** */

int pfring_mlx_open(pfring *ring) {
  pfring_mlx *mlx;
  int i, num_of_device;
  struct ibv_device **dev_list;
  struct ibv_device *ib_dev = NULL;

  ring->close              = pfring_mlx_close;
  ring->stats              = pfring_mlx_stats;
  ring->recv               = pfring_mlx_recv;
  ring->send               = pfring_mlx_send;
  ring->set_poll_watermark = pfring_mlx_set_poll_watermark;
  ring->set_poll_duration  = pfring_mlx_set_poll_duration;
  ring->poll               = pfring_mlx_poll;
  ring->set_direction      = pfring_mlx_set_direction;
  ring->enable_ring        = pfring_mlx_enable_ring;
  ring->get_bound_device_ifindex = pfring_mlx_get_bound_device_ifindex;
  ring->get_interface_speed = pfring_mlx_get_interface_speed;

  /* Inherited from pfring_mod.c */
  ring->set_socket_mode    = pfring_mod_set_socket_mode;
  ring->set_bound_dev_name = pfring_mod_set_bound_dev_name;
  ring->set_application_name = pfring_mod_set_application_name;
  ring->set_application_stats = pfring_mod_set_application_stats;
  ring->get_appl_stats_file_name = pfring_mod_get_appl_stats_file_name;

  ring->fd = socket(PF_RING, SOCK_RAW, htons(ETH_P_ALL)); /* opening PF_RING socket to primlx stats under /proc */

  if(ring->fd < 0)
    return -1;

  ring->priv_data = calloc(1, sizeof(pfring_mlx));

  if(ring->priv_data == NULL)
    goto error;

  mlx = (pfring_mlx*)ring->priv_data;

  /* Device Name: mlx:mlx4_0 */
  dev_list = ibv_get_device_list(&num_of_device);

  if(num_of_device <= 0) {
    printf("No device found: is the mellanox driver loaded in the kernel?\n");
    goto error;
  }

  for(ib_dev = NULL, i = 0; i < num_of_device; i++) {
    if(!strcmp(ibv_get_device_name(dev_list[i]), ring->device_name)) {
      ib_dev = dev_list[i];
      break;
    }
  }

  if(ib_dev == NULL) {
    printf("Unable to find the specified device %s\n", ring->device_name);
    printf("Available devices:\n");
    for(ib_dev = NULL, i = 0; i < num_of_device; i++) {
      printf("%u. %s\n", i+1, ibv_get_device_name(dev_list[i]));
    }

    goto free_private;
  }

  mlx->ring.context = ibv_open_device(ib_dev);
  if(!mlx->ring.context) {
    printf("Failure getting context for device %s\n", ring->device_name);
    goto free_private;
  }

  ring->poll_duration = DEFAULT_POLL_DURATION;

  return 0;

 free_private:
  free(ring->priv_data);

 error:
  return(-1);
}

/* **************************************************** */

static void mlx_release_resources(struct mlx_ring *ring) {
  if(ibv_destroy_qp(ring->qp))
    printf("failed to destroy QP\n");

  if(ibv_destroy_cq(ring->cq))
    printf("failed to destroy CQ\n");

  if(ibv_dereg_mr(ring->mr))
    printf("failed to dereg MR\n");

  if(ibv_dealloc_pd(ring->pd))
    printf("failed to deallocate PD\n");

  if(ibv_close_device(ring->context))
    printf("failed to close device context\n");

  free(ring->buf);
  free(ring->sg);
  free(ring->wc);
}

/* **************************************************** */

void pfring_mlx_close(pfring *ring) {
  pfring_mlx *mlx = (pfring_mlx *) ring->priv_data;

  if(mlx->uc_flow && ibv_exp_destroy_flow(mlx->uc_flow))
    printf("Couldn't Destory UC flow\n");

  if(mlx->flow && ibv_exp_destroy_flow(mlx->flow))
    printf("Couldn't Destory promisc flow\n");

  free(mlx->wr);
  mlx_release_resources(&mlx->ring);

  free(ring->priv_data);

  close(ring->fd);
}

/* **************************************************** */

int pfring_mlx_recv(pfring *ring, u_char** buffer,
		    u_int buffer_len,
		    struct pfring_pkthdr *hdr,
		    u_int8_t wait_for_incoming_packet) {
  pfring_mlx *mlx = (pfring_mlx *) ring->priv_data;
  int retval = 0;
  int i;
  int ne;
  struct ibv_wc *wc = NULL;
  struct ibv_recv_wr *bad_wr_recv = NULL;
  struct mlx_stats *stats = &mlx->ring.stats;

  if(ring->break_recv_loop)
    goto exit; /* retval = 0 */

  if(mlx->num_rx_queued_packets == 0) {
    wait_incoming_packet:
      ne = ibv_poll_cq(mlx->ring.cq, mlx->rx_watermark, mlx->ring.wc);
      
      if(ne < 0) {
	retval = -1;
	goto exit;
      } else {
	if((ne == 0) && wait_for_incoming_packet) {
	  usleep(1);
	  goto wait_incoming_packet;
	}
	
	retval = ne, mlx->num_rx_queued_packets = ne, mlx->last_processed_queued_packet = 0;
      }
  }

  for(i = mlx->last_processed_queued_packet; i < mlx->num_rx_queued_packets; i++) {
    wc = &mlx->ring.wc[i];

    if(wc->status != IBV_WC_SUCCESS) {
      retval = -1;
      goto exit;
    } else
      mlx->last_processed_queued_packet++;    

    stats->total_packets++, stats->total_bytes += (wc->byte_len + HW_CRC_ADDITION);

    if(ibv_post_recv(mlx->ring.qp, &mlx->wr[wc->wr_id], &bad_wr_recv)) {
      printf("Couldn't post recv\n");
      return(-1);
    }

    *buffer = (u_char*)mlx->wr[wc->wr_id].sg_list[0].addr;
    hdr->len = wc->byte_len;
    hdr->caplen = min_val(hdr->len, ring->caplen);

    if(0) {
      char *p = (char*)mlx->wr[wc->wr_id].sg_list[0].addr;

      printf("[%u] ", wc->byte_len);
      for(i = 0; i < wc->byte_len; i++) printf("%02X ", p[i] & 0xFF);
      printf("\n");
    }

    break; /* One packet at time */
  }

  if(mlx->last_processed_queued_packet == mlx->num_rx_queued_packets)
    mlx->num_rx_queued_packets = 0;

  retval = 1;

 exit:
  return retval;
}

/* **************************************************** */

int pfring_mlx_set_poll_watermark(pfring *ring, u_int16_t watermark) {
  pfring_mlx *mlx = (pfring_mlx *) ring->priv_data;

  mlx->rx_watermark = min_val(mlx->num_entries, watermark);

  return 0;
}

/* **************************************************** */

int pfring_mlx_set_poll_duration(pfring *ring, u_int duration) {
  ring->poll_duration = duration;

  return 0;
}

/* **************************************************** */

int pfring_mlx_send(pfring *ring, char *pkt, u_int pkt_len, u_int8_t flush_packet) {
#if 0
  pfring_mlx *mlx = (pfring_mlx *) ring->priv_data;
  struct ibv_send_wr *bw = NULL;

  if(ibv_post_send(mlx->qp, &xmit_ring.wr[i * POST_LIST_SIZE], &bw)) {
    fprintf(stderr, "Couldn't post send WQE=%d\n", (int)wc->wr_id);
    return failure;
  }
#endif

  return(0); // TODO
}

/* **************************************************** */

int pfring_mlx_stats(pfring *ring, pfring_stat *stats) {
  pfring_mlx *mlx = (pfring_mlx *) ring->priv_data;

  stats->recv = mlx->ring.stats.total_packets, stats->drop = 0;
  return(0);
}

/* **************************************************** */

int pfring_mlx_set_direction(pfring *ring, packet_direction direction) {
  if(direction == rx_only_direction || direction == rx_and_tx_direction) {
    return(setsockopt(ring->fd, 0, SO_SET_PACKET_DIRECTION, &direction, sizeof(direction)));
  }

  return(-1);
}

/* **************************************************** */

static int mlx_recv_set_promisc(pfring_mlx *ring, int port) {
  struct ibv_exp_flow_attr attr;

  memset(&attr, 0, sizeof(struct ibv_exp_flow_attr));

  attr.type = IBV_EXP_FLOW_ATTR_ALL_DEFAULT;
  attr.port = port;

  ring->flow = ibv_exp_create_flow(ring->ring.qp, &attr);

  if(!ring->flow) {
    printf("Cannot attach promisc rule to QP\n");
    return(-1);
  }

  return(0);
}

/* **************************************************** */

static void mac_from_gid(uint8_t *mac, uint8_t *gid, uint32_t port) {
  memcpy(mac, gid + 8, 3);
  memcpy(mac + 3, gid + 13, 3);

  if(port == 1)
    mac[0] ^= 2;
}

/* **************************************************** */

static int mlx_recv_set_unicast(pfring_mlx *ring, int port) {
  void *buff = NULL;
  union ibv_gid gid;
  struct ibv_exp_flow_attr *attr = NULL;
  struct ibv_exp_flow_spec *spec = NULL;
  int buff_size = sizeof(struct ibv_exp_flow_attr) +
    sizeof(struct ibv_exp_flow_spec_eth);

  if((buff = (uint8_t*)calloc(sizeof(uint8_t), buff_size)) == NULL)
    return(-1);

  attr = (struct ibv_exp_flow_attr*)buff;
  attr->type = IBV_EXP_FLOW_ATTR_NORMAL;
  attr->size = buff_size;
  attr->num_of_specs = 1;
  attr->port = port;
  spec = (struct ibv_exp_flow_spec*)(buff + sizeof(struct ibv_exp_flow_attr));
  spec->eth.type = IBV_EXP_FLOW_SPEC_ETH;
  spec->eth.size = sizeof(struct ibv_exp_flow_spec_eth);

  if(ibv_query_gid(ring->ring.context, port, 0, &gid)) {
    printf("Cannot query GUID 0\n");
    free(buff);
    return(-1);
  }

  mac_from_gid(spec->eth.val.dst_mac, gid.raw, port);
  memset(spec->eth.mask.dst_mac, 0xFF, sizeof(spec->eth.mask.dst_mac));

  ring->uc_flow = ibv_exp_create_flow(ring->ring.qp, attr);
  if(!ring->uc_flow) {
    printf("Cannot attach Unicast rule to RSS\n");
    free(buff);
    return(-2);
  }

  free(buff);
  return(0);
}

/* **************************************************** */

static int mlx_recv_post_wqes(pfring_mlx *ring, u_int mtu_len) {
  int i;
  struct ibv_sge *sg = NULL;
  struct ibv_recv_wr *wr = NULL;
  struct ibv_recv_wr *bad_wr_recv;

  if((ring->wr = (struct ibv_recv_wr*)calloc(sizeof(struct ibv_recv_wr),
					     ring->num_entries)) == NULL)
    return(-1);

  for (i = 0; i < ring->num_entries; i++) {
    sg = &ring->ring.sg[i];
    wr = &ring->wr[i];

    sg->addr   = (uintptr_t)ring->ring.buf + (i * mtu_len);
    sg->length = mtu_len;
    sg->lkey   = ring->ring.mr->lkey;

    wr->sg_list = sg;
    wr->wr_id   = i;
    wr->num_sge = MAX_SGE;

    if(ibv_post_recv(ring->ring.qp, wr, &bad_wr_recv)) {
      printf("Couldn't post recv index=%d\n", i);
      free(ring->wr);
      return(-1);
    }
  }

  return(0);
}

/* **************************************************** */

int pfring_mlx_enable_ring(pfring *ring) {
  pfring_mlx *mlx = (pfring_mlx *) ring->priv_data;

  mlx->ring.pd = ibv_alloc_pd(mlx->ring.context);
  if(!mlx->ring.pd) {
    printf("Failure allocating PD for device %s\n", ring->device_name);
    goto err_pd;
  }

  if(ring->mtu_len == 0) ring->mtu_len = 1536;

  mlx->rx_watermark = 16, mlx->num_entries = 512 /* FIX */, mlx->port_num = 1 /* FIX */;
  if(mlx_configure_qp(&mlx->ring, ring->mtu_len, mlx->num_entries, mlx->port_num)) {
    printf("Error in QP configuration\n");
    goto err_config;
  }

  if(mlx_recv_set_promisc(mlx, mlx->port_num))
    goto err_promisc;

  if(mlx_recv_set_unicast(mlx, mlx->port_num))
    goto err_unicast;

  if(mlx_recv_post_wqes(mlx, ring->mtu_len))
    goto err_post_wqe;

  return(0);

 err_post_wqe:
  ibv_exp_destroy_flow(mlx->uc_flow);

 err_unicast:
  ibv_exp_destroy_flow(mlx->flow);

 err_promisc:
  mlx_release_resources(&mlx->ring);
  return(-2);

 err_config:
  ibv_dealloc_pd(mlx->ring.pd);

 err_pd:
  ibv_close_device(mlx->ring.context);

  return(-1);
}

/* **************************************************** */

int pfring_mlx_poll(pfring *ring, u_int wait_duration) {
  /* TODO */
  return 1;
}

/* **************************************************** */

int pfring_mlx_get_bound_device_ifindex(pfring *ring, int *if_index) {
  //pfring_mlx *mlx = (pfring_mlx *) ring->priv_data;

  *if_index = 0; /* FIX */
  return 0;
}

/* **************************************************** */

u_int32_t pfring_mlx_get_interface_speed(pfring *ring) {
  //pfring_mlx *mlx = (pfring_mlx *) ring->priv_data;

  /* TODO */

  return 0;
}

/* **************************************************** */

