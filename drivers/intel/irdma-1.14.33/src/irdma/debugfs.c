// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2015 - 2023 Intel Corporation */
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/list.h>

#include "main.h"

#ifdef CONFIG_DEBUG_FS
static const char irdma_driver_name[] = "irdma";
static struct dentry *irdma_dbg_root;
static char cmd_buf[64];

/* QP subcommand */
#define QP_ACTIVE               1
#define QP_INFO                 2
#define QP_Q2                   3
#define QP_HOST_CTX             4
#define QP_CHIP_CTX             5
#define QP_CHIP_RAW             6
#define QP_CHIP_REG             7

#define DUMP_HMC_INFO           1
#define DUMP_HMC_INDEXES        2
#define DUMP_HMC_OBJ_INFO       4
#define DUMP_HMC_SD             8
#define DUMP_HMC_ALL            0xf

#define OFFSET_MASK_4K          0x0000000000000fffl

static char *irdma_dbg_dump_buf;
static size_t irdma_dbg_dump_data_len;
static size_t irdma_dbg_dump_buf_len;
static u32 cmdnew;
static u32 cmddone;
#define BUF_ADDR_SIZE 17	/* address plus space */
#define BUF_DATA_ASCII_SIZE (32 * 3 + 2 + 32 + 1)	/* data plus ASCII */
#define IRDMA_DUMP_BUF_SIZE             16384
#define IRDMA_DUMP_BUF_HALF_FULL        (IRDMA_DUMP_BUF_SIZE / 2)

struct hmc_find {
	dma_addr_t paddr;
	bool fnd;
	dma_addr_t bp_pa;
	bool in_vf;
	u32 vf_id;
	int sd_indx;
	bool paged;
	bool in_pd_itself;
	int pd_indx;
	u64 hmc_addr;
	bool obj_info_fnd;
	enum irdma_hmc_rsrc_type obj_type;
	int obj_indx;
};

/**
 * dbg_vsnprintf -
 * @fmt: print formatting string
 */
static void dbg_vsnprintf(char *fmt, ...) __attribute__ ((format(gnu_printf, 1, 2)));
static void dbg_vsnprintf(char *fmt, ...)
{
	int cnt;
	va_list argp;

	va_start(argp, fmt);
	cnt = vsnprintf(irdma_dbg_dump_buf + irdma_dbg_dump_data_len,
			irdma_dbg_dump_buf_len - irdma_dbg_dump_data_len,
			fmt, argp);
	va_end(argp);

	irdma_dbg_dump_data_len += cnt;
}

/**
 * dump_help -
 */
static void dump_help(void)
{
	dbg_vsnprintf("Dump commands:\n");
	dbg_vsnprintf(" sw-stats\n");
	dbg_vsnprintf(" hw-stats\n");
	dbg_vsnprintf(" qp <n> chip_ctx\n");
	dbg_vsnprintf(" qp <n> chip_raw\n");
	dbg_vsnprintf(" qp <n> active           <n> is a qp number or 'all'\n");
	dbg_vsnprintf(" qp <n> info\n");
	dbg_vsnprintf(" cq <n>                  <n> is a cq number or 'all'\n");
	cmddone = true;
}

/**
 * irdma_dbg_save_ucontext -
 * @iwdev: device
 * @ucontext: user context
 */
void irdma_dbg_save_ucontext(struct irdma_device *iwdev,
			     struct irdma_ucontext *ucontext)
{
	struct irdma_handler *hdl;
	unsigned long flags;

	hdl = iwdev->hdl;

	spin_lock_irqsave(&hdl->uctx_list_lock, flags);
	list_add_tail(&ucontext->uctx_list, &hdl->ucontext_list);
	spin_unlock_irqrestore(&hdl->uctx_list_lock, flags);
}

/**
 * irdma_dbg_free_ucontext -
 * @ucontext: user context
 */
void irdma_dbg_free_ucontext(struct irdma_ucontext *ucontext)
{
	struct irdma_handler *hdl;
	unsigned long flags;

	hdl = ucontext->iwdev->hdl;

	spin_lock_irqsave(&hdl->uctx_list_lock, flags);
	list_del(&ucontext->uctx_list);
	spin_unlock_irqrestore(&hdl->uctx_list_lock, flags);
}

/**
 * find_next_rsrc - Find next free resource ID
 * @rf: RDMA PCI function
 * @rsrc_array: resource array
 * @max_rsrc: max num resources
 * @next: next id to search
 */
static int find_next_rsrc(struct irdma_pci_f *rf,
			      unsigned long *rsrc_array,
			      u32 max_rsrc,
			      u32 next)
{
	u32 rsrc_num;
	unsigned long flags;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	rsrc_num = find_next_bit(rsrc_array, max_rsrc, next);
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);
	return (rsrc_num < max_rsrc) ? rsrc_num : -2;
}

/**
 * find_next_qp_num -
 * @rf: RDMA PCI function
 * @qp_id: QP ID
 */
static int find_next_qp_num(struct irdma_pci_f *rf, int qp_id)
{
	do {
		++qp_id;
		if ((qp_id == 0) || (qp_id == 1))
			qp_id = 2;
		qp_id = find_next_rsrc(rf, rf->allocated_qps,
					   rf->max_qp, qp_id);
		if (qp_id < 0)
			break;
	} while (!rf->qp_table[qp_id]);

	return qp_id;
}

/**
 * find_next_cq_num -
 * @rf: RDMA PCI function
 * @cq_id: CQ ID
 */
static long find_next_cq_num(struct irdma_pci_f *rf, long cq_id)
{
	do {
		++cq_id;
		if (cq_id < 3 ||
		    cq_id >= rf->cqp.sc_cqp.dev->hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].max_cnt)
			cq_id = 3;
		cq_id = find_next_rsrc(rf, rf->allocated_cqs,
				       rf->max_cq, cq_id);
		if (cq_id < 0)
			break;

	} while (!rf->cq_table[cq_id]);

	return cq_id;
}

/**
 * dump_qp_shared -
 * @qp: QP pointer
 */
static void dump_qp_shared(struct irdma_qp *qp)
{
	struct irdma_sc_qp *qpsh = &qp->sc_qp;
	struct irdma_qp_uk *qpuk = &qpsh->qp_uk;

	dbg_vsnprintf("      sq_ring.head: 0x%x tail: 0x%x size: 0x%x\n",
		      qpuk->sq_ring.head, qpuk->sq_ring.tail,
		      qpuk->sq_ring.size);
	dbg_vsnprintf("      rq_ring.head: 0x%x tail: 0x%x size: 0x%x\n",
		      qpuk->rq_ring.head, qpuk->rq_ring.tail,
		      qpuk->rq_ring.size);
	dbg_vsnprintf("      qp_id: 0x%x\n", qpuk->qp_id);
	dbg_vsnprintf("      sq_size: 0x%x\n", qpuk->sq_size);
	dbg_vsnprintf("      rq_size: 0x%x\n", qpuk->rq_size);
	dbg_vsnprintf("      swqe_polarity: 0x%x\n", qpuk->swqe_polarity);
	dbg_vsnprintf("      rwqe_polarity: 0x%x\n", qpuk->rwqe_polarity);
	dbg_vsnprintf("      rq_wqe_size: 0x%x\n", qpuk->rq_wqe_size);
	dbg_vsnprintf("      rq_wqe_size_multiplier: 0x%x\n",
		      qpuk->rq_wqe_size_multiplier);
	dbg_vsnprintf("      max_sq_frag_cnt: 0x%x\n", qpuk->max_sq_frag_cnt);
	dbg_vsnprintf("      max_rq_frag_cnt: 0x%x\n", qpuk->max_rq_frag_cnt);

	dbg_vsnprintf("    qs_handle: 0x%x\n", qpsh->qs_handle);
	dbg_vsnprintf("    exception_lan_q: 0x%x\n",
		      qp->iwdev->vsi.exception_lan_q);
	dbg_vsnprintf("    sq_tph_val: 0x%x\n", qpsh->sq_tph_val);
	dbg_vsnprintf("    rq_tph_val: 0x%x\n", qpsh->rq_tph_val);
	dbg_vsnprintf("    sq_tph_en: 0x%x\n", qpsh->sq_tph_en);
	dbg_vsnprintf("    rq_tph_en: 0x%x\n", qpsh->rq_tph_en);
	dbg_vsnprintf("    rcv_tph_en: 0x%x\n", qpsh->rcv_tph_en);
	dbg_vsnprintf("    xmit_tph_en: 0x%x\n", qpsh->xmit_tph_en);

	dbg_vsnprintf("    virtual_map: 0x%x\n", qpsh->virtual_map);
	dbg_vsnprintf("    flush_sq: 0x%x\n", qpsh->flush_sq);
	dbg_vsnprintf("    flush_rq: 0x%x\n", qpsh->flush_rq);
	dbg_vsnprintf("    qp_type: 0x%x\n", qpsh->qp_uk.qp_type);
	dbg_vsnprintf("    hw_sq_size: 0x%x\n", qpsh->hw_sq_size);
	dbg_vsnprintf("    hw_rq_size: 0x%x\n", qpsh->hw_rq_size);
}

/**
 * dump_qp_info -
 * @qp: QP pointer
 */
static void dump_qp_info(struct irdma_qp *qp)
{
	dbg_vsnprintf("struct irdma_qp\n");

	dump_qp_shared(qp);

	dbg_vsnprintf("  refcount: 0x%x\n", refcount_read(&qp->refcnt));
	dbg_vsnprintf("  ibqp_state: 0x%x\n", qp->ibqp_state);
	dbg_vsnprintf("  iwarp_state: 0x%x\n", qp->iwarp_state);
	dbg_vsnprintf("  qp_mem_size: 0x%x\n", qp->qp_mem_size);
	dbg_vsnprintf("  last_aeq: 0x%x\n", qp->last_aeq);
	dbg_vsnprintf("  close_timer_started: 0x%x\n",
		      qp->close_timer_started.counter);
	dbg_vsnprintf("  qp_mem_size: 0x%x\n", qp->qp_mem_size);
	dbg_vsnprintf("  active_conn: %d\n", qp->active_conn);
	dbg_vsnprintf("  user_mode: %d\n", qp->user_mode);
	dbg_vsnprintf("  hte_added: %d\n", qp->hte_added);
	dbg_vsnprintf("  flush_issued: %d\n", qp->flush_issued);
	dbg_vsnprintf("  destroy_pending: %d\n", qp->sc_qp.qp_uk.destroy_pending);
	dbg_vsnprintf("  sig_all: %d\n", qp->sig_all);
	dbg_vsnprintf("  pau_mode: %d\n", qp->pau_mode);
	dbg_vsnprintf("  term_sq_flush_code: 0x%x\n", qp->term_sq_flush_code);
	dbg_vsnprintf("  term_rq_flush_code: 0x%x\n", qp->term_rq_flush_code);
	dbg_vsnprintf("  hw_iwarp_state: %d\n", qp->hw_iwarp_state);
	dbg_vsnprintf("  hw_tcp_state: %d\n", qp->hw_tcp_state);
}

#if 0
/**
 * dump_qp_ctx -
 * @qp: QP pointer
 */
static void dump_qp_ctx(struct irdma_qp *qp)
{
	u64 *hwctx = qp->sc_qp.hw_host_ctx;
	size_t lendumped = 0;
	u32 val;
	u64 val64;
	u8 qp_type = qp->sc_qp.qp_type;

	dump_to_buf((char *)qp->sc_qp.hw_host_ctx, 256, 0, 32, 8,
			     false, &lendumped);

	dbg_vsnprintf("host_context 0x%p\n", qp->sc_qp.hw_host_ctx);
	if (qp_type == IRDMA_CQ_TYPE_IWARP)
		dbg_vsnprintf("  iwarp_rdmap_ver: 0x%llx\n", RS_64(hwctx[0], IRDMAQPC_RDMAP_VER));
	else
		dbg_vsnprintf("  roce_tver_ver: 0x%llx\n", RS_64(hwctx[0], IRDMAQPC_ROCE_TVER));
	dbg_vsnprintf("  push_mode_ena: 0x%llx\n",
		      RS_64(hwctx[0], IRDMAQPC_PMENA));
	dbg_vsnprintf("  push_page_index:  0x%llx\n",
		      RS_64(hwctx[0], IRDMAQPC_PPIDX));
	dbg_vsnprintf("  SQ_THP_en:  0x%llx\n",
		      RS_64(hwctx[0], IRDMAQPC_SQTPHEN));
	dbg_vsnprintf("  RQ_THP_en:  0x%llx\n",
		      RS_64(hwctx[0], IRDMAQPC_RQTPHEN));
	if (qp_type == IRDMA_CQ_TYPE_IWARP) {
		dbg_vsnprintf("  XMIT_THP_en:  0x%llx\n",
			      RS_64(hwctx[0], IRDMAQPC_XMITTPHEN));
		dbg_vsnprintf("  RCV_THP_en:  0x%llx\n",
			      RS_64(hwctx[0], IRDMAQPC_RCVTPHEN));
		dbg_vsnprintf("  dupack_thresh:  0x%llx\n",
			      RS_64(hwctx[0], IRDMAQPC_DUPACK_THRESH));
		dbg_vsnprintf("  drop_out_of_order_seg: 0x%llx\n",
			      RS_64(hwctx[0], IRDMAQPC_DROPOOOSEG));
		dbg_vsnprintf("  ECN_ena: no constants defined\n");
		dbg_vsnprintf("  limit: 0x%llx\n", RS_64(hwctx[0], IRDMAQPC_LIMIT));
	}
	dbg_vsnprintf("  RQ_WQE_Size: 0x%llx\n",
		      RS_64(hwctx[0], IRDMAQPC_RQWQESIZE));
	dbg_vsnprintf("  timestamp: 0x%llx\n",
		      RS_64(hwctx[0], IRDMAQPC_TIMESTAMP));
	dbg_vsnprintf("  use_srq: 0x%llx\n", RS_64(hwctx[0], IRDMAQPC_USESRQ));
	dbg_vsnprintf("  Insert VLAN Tag: 0x%llx\n",
		      RS_64(hwctx[0], IRDMAQPC_INSERTVLANTAG));
	if (qp_type == IRDMA_CQ_TYPE_IWARP) {
		dbg_vsnprintf("  NoNagle: 0x%llx\n", RS_64(hwctx[0], IRDMAQPC_NONAGLE));
		dbg_vsnprintf("  iwarp_ddp_ver: 0x%llx\n",
			      RS_64(hwctx[0], IRDMAQPC_DDP_VER));
	}
	dbg_vsnprintf("  IPv4: 0x%llx\n", RS_64(hwctx[0], IRDMAQPC_IPV4));

	/* Offset 8 */
	dbg_vsnprintf("  SQ_Address: 0x%llx\n",
		      RS_64(hwctx[1], IRDMAQPC_SQADDR));

	/* Offset 16 */
	dbg_vsnprintf("  RQ_Address: 0x%llx\n",
		      RS_64(hwctx[2], IRDMAQPC_RQADDR));

	/* Offset 24 */
	dbg_vsnprintf("  Dest Port Number: 0x%llx (%lld)\n",
		      RS_64(hwctx[3], IRDMAQPC_DESTPORTNUM),
		      RS_64(hwctx[3], IRDMAQPC_DESTPORTNUM));
	dbg_vsnprintf("  Source Port Number: 0x%llx (%lld)\n",
		      RS_64(hwctx[3], IRDMAQPC_SRCPORTNUM),
		      RS_64(hwctx[3], IRDMAQPC_SRCPORTNUM));
	dbg_vsnprintf("  Traffic Class or TOS: 0x%llx\n",
		      RS_64(hwctx[3], IRDMAQPC_TOS));
	dbg_vsnprintf("  avoid_stretch_ack: 0x%llx\n",
		      RS_64(hwctx[3], IRDMAQPC_AVOIDSTRETCHACK));
	dbg_vsnprintf("  SQ Size: 0x%llx\n", RS_64(hwctx[3], IRDMAQPC_SQSIZE));
	dbg_vsnprintf("  RQ Size: 0x%llx\n", RS_64(hwctx[3], IRDMAQPC_RQSIZE));
	dbg_vsnprintf("  Hop Limit or TTL: 0x%llx\n",
		      RS_64(hwctx[3], IRDMAQPC_TTL));

	/* Offset 32 */
	val = be32_to_cpu(RS_64(hwctx[4], IRDMAQPC_DESTIPADDR2));
	dbg_vsnprintf("  Dest_IP_Address_2: %pI4\n", &val);

	val = be32_to_cpu(RS_64(hwctx[4], IRDMAQPC_DESTIPADDR3));
	dbg_vsnprintf("  Dest_IP_Address_3: %pI4\n", &val);

	/* Offset 40 */
	val = be32_to_cpu(RS_64(hwctx[5], IRDMAQPC_DESTIPADDR0));
	dbg_vsnprintf("  Dest_IP_Address_0: %pI4\n", &val);

	val = be32_to_cpu(RS_64(hwctx[5], IRDMAQPC_DESTIPADDR1));
	dbg_vsnprintf("  Dest_IP_Address_1: %pI4\n", &val);

	/* Offset 48 */
	dbg_vsnprintf("  ARP Index: 0x%llx\n",
		      RS_64(hwctx[6], IRDMAQPC_ARPIDX));
	dbg_vsnprintf("  VLAN Tag: 0x%llx\n",
		      RS_64(hwctx[6], IRDMAQPC_VLANTAG));
	dbg_vsnprintf("  snd_mss: 0x%llx\n", RS_64(hwctx[6], IRDMAQPC_SNDMSS));

	/* Offset 56 */
	dbg_vsnprintf("  pd_index: 0x%llx\n",
		      RS_64(hwctx[7], IRDMAQPC_PDIDX) | RS_64(hwctx[0],
			    IRDMAQPC_PDIDXHI));

	if (qp_type == IRDMA_CQ_TYPE_IWARP) {
		dbg_vsnprintf("  Snd_wscale: 0x%llx\n",
			      RS_64(hwctx[7], IRDMAQPC_SNDSCALE));
		dbg_vsnprintf("  Rcv_wscale: 0x%llx\n",
			      RS_64(hwctx[7], IRDMAQPC_RCVSCALE));
		dbg_vsnprintf("  TCP_state: 0x%llx\n",
			      RS_64(hwctx[7], IRDMAQPC_TCPSTATE));
		dbg_vsnprintf("  ignore_tcp_uns_options: 0x%llx\n",
			      RS_64(hwctx[7], IRDMAQPC_IGNORE_TCP_UNS_OPT));
		dbg_vsnprintf("  ignore_tcp_options: 0x%llx\n",
			      RS_64(hwctx[7], IRDMAQPC_IGNORE_TCP_OPT));
		dbg_vsnprintf("  Flow Label: 0x%llx\n",
			      RS_64(hwctx[7], IRDMAQPC_FLOWLABEL));

		/* Offset 72 */
		dbg_vsnprintf("  timestamp_age: 0x%llx\n",
			      RS_64(hwctx[9], IRDMAQPC_TIMESTAMP_AGE));
		dbg_vsnprintf("  timestamp_recent: 0x%llx\n",
			      RS_64(hwctx[9], IRDMAQPC_TIMESTAMP_RECENT));

		/* Offset 80 */
		dbg_vsnprintf("  snd_wnd: 0x%llx\n", RS_64(hwctx[10], IRDMAQPC_SNDWND));
		dbg_vsnprintf("  snd_nxt: 0x%llx\n", RS_64(hwctx[10], IRDMAQPC_SNDNXT));

		/* Offset 88 */
		dbg_vsnprintf("  rcv_wnd: 0x%llx\n", RS_64(hwctx[11], IRDMAQPC_RCVWND));
		dbg_vsnprintf("  rcv_nxt: 0x%llx\n", RS_64(hwctx[11], IRDMAQPC_RCVNXT));

		/* Offset 96 */
		dbg_vsnprintf("  snd_una: 0x%llx\n", RS_64(hwctx[12], IRDMAQPC_SNDUNA));
		dbg_vsnprintf("  snd_max: 0x%llx\n", RS_64(hwctx[12], IRDMAQPC_SNDMAX));

		/* Offset 104 */
		dbg_vsnprintf("  rtt_var: 0x%llx\n", RS_64(hwctx[13], IRDMAQPC_RTTVAR));
		dbg_vsnprintf("  srtt: 0x%llx\n", RS_64(hwctx[13], IRDMAQPC_SRTT));
	} else {
		dbg_vsnprintf("  pkey: 0x%llx\n", RS_64(hwctx[7], IRDMAQPC_PKEY));
		dbg_vsnprintf("  ack_credits: 0x%llx\n", RS_64(hwctx[7], IRDMAQPC_ACKCREDITS));
		dbg_vsnprintf("  qkey: 0x%llx\n", RS_64(hwctx[8], IRDMAQPC_QKEY));
		dbg_vsnprintf("  Dest_QPN: 0x%llx\n", RS_64(hwctx[8], IRDMAQPC_DESTQP));
		dbg_vsnprintf("  Isn: 0x%llx\n", RS_64(hwctx[10], IRDMAQPC_ISN));
		dbg_vsnprintf("  psn_nxt: 0x%llx\n", RS_64(hwctx[10], IRDMAQPC_QKEY));
		dbg_vsnprintf("  epsn: 0x%llx\n", RS_64(hwctx[11], IRDMAQPC_EPSN));
		dbg_vsnprintf("  psn_una: 0x%llx\n", RS_64(hwctx[12], IRDMAQPC_PSNUNA));
		dbg_vsnprintf("  psn_max: 0x%llx\n", RS_64(hwctx[12], IRDMAQPC_PSNMAX));
		dbg_vsnprintf("  ss_thresh: 0x%llx\n", RS_64(hwctx[14], IRDMAQPC_SSTHRESH));
	}
	/* Offset 112 */
	dbg_vsnprintf("  cwnd: 0x%llx\n", RS_64(hwctx[14], IRDMAQPC_CWND));

	if (qp_type == IRDMA_CQ_TYPE_IWARP) {
		/* Offset 120 */
		dbg_vsnprintf("  snd_wl2: 0x%llx\n", RS_64(hwctx[15], IRDMAQPC_SNDWL2));
		dbg_vsnprintf("  snd_wl1: 0x%llx\n", RS_64(hwctx[15], IRDMAQPC_SNDWL1));

		/* Offset 128 */
		dbg_vsnprintf("  rexmit_thresh: 0x%llx\n",
			      RS_64(hwctx[16], IRDMAQPC_REXMIT_THRESH));
		dbg_vsnprintf("  max_snd_window: 0x%llx\n",
			      RS_64(hwctx[16], IRDMAQPC_MAXSNDWND));
	}
	/* Offset 136 */
	dbg_vsnprintf("  RxCmpQueueNum: 0x%llx\n",
		      RS_64(hwctx[17], IRDMAQPC_RXCQNUM));
	dbg_vsnprintf("  TxCmpQueueNum: 0x%llx\n",
		      RS_64(hwctx[17], IRDMAQPC_TXCQNUM));

	/* Offset 144 */
	if (qp_type == IRDMA_CQ_TYPE_IWARP)
		dbg_vsnprintf("  Q2_Address: 0x%llx\n", RS_64(hwctx[18], IRDMAQPC_Q2ADDR);
	dbg_vsnprintf("  Stats_instance_Index: 0x%llx\n", RS_64(hwctx[18], IRDMAQPC_STAT_INDEX));

	/* Offset 152 */
	dbg_vsnprintf("  L2TAG2: no constants defined\n");
	dbg_vsnprintf("  last_byte_sent: 0x%llx\n", RS_64(hwctx[19], IRDMAQPC_LASTBYTESENT));
	val64 = RS_64(hwctx[19], IRDMAQPC_MACADDRESS);
	dbg_vsnprintf("  src_MAC_Address: 0x%pM\n", &val64);

	if (qp_type == IRDMA_CQ_TYPE_IWARP) {
		/* Offset 160 */
		dbg_vsnprintf("  snd_mrk_offset: 0x%llx\n",
			      RS_64(hwctx[20], IRDMAQPC_SNDMARKOFFSET));
		dbg_vsnprintf("  rcv_mrk_offset: 0x%llx\n",
			      RS_64(hwctx[20], IRDMAQPC_RCVMARKOFFSET));

		dbg_vsnprintf("  rcv_no_mpa_crc: 0x%llx\n",
			      RS_64(hwctx[20], IRDMAQPC_RCVNOMPACRC));
		dbg_vsnprintf("  assume_aligned_hdrs: 0x%llx\n",
			      RS_64(hwctx[20], IRDMAQPC_ALIGNHDRS));
		dbg_vsnprintf("  Receive Markers: 0x%llx\n",
			      RS_64(hwctx[20], IRDMAQPC_RCVMARKERS));
		dbg_vsnprintf("  iWARP Mode: 0x%llx\n",
			      RS_64(hwctx[20], IRDMAQPC_IWARPMODE));
	}
	dbg_vsnprintf("  AdjustForLSMM: 0x%llx\n",
		      RS_64(hwctx[20], IRDMAQPC_ADJUSTFORLSMM));
	dbg_vsnprintf("  PrivilegedEnable: 0x%llx\n",
		      RS_64(hwctx[20], IRDMAQPC_PRIVEN));
	dbg_vsnprintf("  FastRegisterEnable: 0x%llx\n",
		      RS_64(hwctx[20], IRDMAQPC_FASTREGEN));
	dbg_vsnprintf("  BindEnable: 0x%llx\n",
		      RS_64(hwctx[20], IRDMAQPC_BINDEN));
	dbg_vsnprintf("  Send Markers: 0x%llx\n",
		      RS_64(hwctx[20], IRDMAQPC_SNDMARKERS));
	dbg_vsnprintf("  rdmard_ok: 0x%llx\n", RS_64(hwctx[20], IRDMAQPC_RDOK));
	dbg_vsnprintf("  rdmawr_rdresp_ok: 0x%llx\n",
		      RS_64(hwctx[20], IRDMAQPC_WRRDRSPOK));
	dbg_vsnprintf("  IRD_Size: 0x%llx\n",
		      RS_64(hwctx[20], IRDMAQPC_IRDSIZE));
	dbg_vsnprintf("  ORD_Size: 0x%llx\n",
		      RS_64(hwctx[20], IRDMAQPC_ORDSIZE));

	/* Offset 168 */
	dbg_vsnprintf("  Queue Pair Completion Context: 0x%llx\n",
		      RS_64(hwctx[21], IRDMAQPC_QPCOMPCTX));

	/* Offset 176 */
	if (qp_type == IRDMA_CQ_TYPE_IWARP)
		dbg_vsnprintf("  Exception_LAN_Queue: 0x%llx\n", RS_64(hwctx[22], IRDMAQPC_EXCEPTION_LAN_QUEUE));
	dbg_vsnprintf("  QS_Handle: 0x%llx\n",
		      RS_64(hwctx[22], IRDMAQPC_QSHANDLE));
	dbg_vsnprintf("  RQ_TPH_val: 0x%llx\n",
		      RS_64(hwctx[22], IRDMAQPC_RQTPHVAL));
	dbg_vsnprintf("  SQ_TPH_val: 0x%llx\n",
		      RS_64(hwctx[22], IRDMAQPC_SQTPHVAL));

	/* Offset 184 */
	val = be32_to_cpu(RS_64(hwctx[23], IRDMAQPC_LOCAL_IPADDR2));
	dbg_vsnprintf("  Local_IP_Address_2: %pI4\n", &val);

	val = be32_to_cpu(RS_64(hwctx[23], IRDMAQPC_LOCAL_IPADDR3));
	dbg_vsnprintf("  Local_IP_Address_3: %pI4\n", &val);

	/* Offset 192 */
	val = be32_to_cpu(RS_64(hwctx[24], IRDMAQPC_LOCAL_IPADDR0));
	dbg_vsnprintf("  Local_IP_Address_0: %pI4\n", &val);

	val = be32_to_cpu(RS_64(hwctx[24], IRDMAQPC_LOCAL_IPADDR1));
	dbg_vsnprintf("  Local_IP_Address_1: %pI4\n", &val);
}
#endif

/**
 * dump_qp -
 * @rf: RDMA PCI function
 * @qp_id: QP ID
 * @subtype: QP info type
 */
static void dump_qp(struct irdma_pci_f *rf, u32 qp_id, u32 subtype)
{
	struct irdma_qp *iwqp = NULL;

	if ((qp_id >= 2) && (qp_id < rf->max_qp))
		iwqp = rf->qp_table[qp_id];

	if (!iwqp) {
		dbg_vsnprintf("QP %d is not valid\n", qp_id);
		return;
	}

	dbg_vsnprintf("QP %d ibqp_state=0x%x warp_state=0x%x\n", qp_id,
		      iwqp->ibqp_state, iwqp->iwarp_state);

	switch (subtype) {
	case QP_INFO:
		dump_qp_info(iwqp);
		break;
	case QP_CHIP_CTX:
		dbg_vsnprintf
		    ("QP %d context will be dumped to /var/log/messages\n",
		     qp_id);
		irdma_upload_qp_context(iwqp, 0, 0);
		break;
	case QP_CHIP_RAW:
		dbg_vsnprintf
		    ("QP %d context will be dumped using regs (no CQP ops) to /var/log/messages\n",
		     qp_id);
		irdma_upload_qp_context(iwqp, 0, 1);
		break;
	case QP_ACTIVE:
		if (!iwqp->user_mode) {
			unsigned long flags;

			spin_lock_irqsave(&iwqp->lock, flags);
			irdma_print_sq_wqes(&iwqp->sc_qp.qp_uk);
			spin_unlock_irqrestore(&iwqp->lock, flags);
		}
		break;
	}
}

/**
 * dump_qp_cmd -
 * @rf: RDMA PCI function
 * @cbuf: character buffer to dump to
 */
static void dump_qp_cmd(struct irdma_pci_f *rf, char *cbuf)
{
	static int qp_id;
	static u32 all;
	static u32 subtype = QP_ACTIVE;
	char stype[9];
	char qpstr[11];
	int offset;
	int rc;

	if (cmdnew) {
		if (sscanf(cbuf, "%10s%n", qpstr, &offset) == 0)
			return;

		if (strncasecmp(qpstr, "all", 3) == 0) {
			all = true;
			qp_id = find_next_qp_num(rf, -1);
		} else {
			all = false;
			rc = kstrtoul(qpstr, 10, (long *)&qp_id);
			if (rc)
				return;

			if ((qp_id == 0) || (qp_id == 1))
				qp_id = -1;
		}

		if (sscanf(cbuf + offset, "%8s", stype) == 1) {
			if (strncasecmp(stype, "active", 6) == 0)
				subtype = QP_ACTIVE;
			if (strncasecmp(stype, "info", 5) == 0)
				subtype = QP_INFO;
			else if (strncasecmp(stype, "q2", 2) == 0)
				subtype = QP_Q2;
			else if (strncasecmp(stype, "chip_ctx", 8) == 0)
				subtype = QP_CHIP_CTX;
			else if (strncasecmp(stype, "chip_raw", 8) == 0)
				subtype = QP_CHIP_RAW;
			else if (strncasecmp(stype, "chip_reg", 8) == 0)
				subtype = QP_CHIP_REG;
		}
	} else {
		if (!all)
			return;

		qp_id = find_next_qp_num(rf, qp_id);
	}

	if (qp_id >= 0)
		dump_qp(rf, qp_id, subtype);
	else
		cmddone = true;
}

/**
 * dump_cq_cmd -
 * @rf: RDMA PCI function
 * @cbuf: character buffer to read the cmd from
 */
static void dump_cq_cmd(struct irdma_pci_f *rf, const char *cbuf)
{
	static long cq_id;
	static bool all;
	char cqstr[11];
	int offset;
	int rc;

	if (cmdnew) {
		if (sscanf(cbuf, "%10s%n", cqstr, &offset) == 0)
			return;

		if (strncasecmp(cqstr, "all", 3) == 0) {
			all = true;
			cq_id = find_next_cq_num(rf, 1);
		} else {
			all = false;
			rc = kstrtoul(cqstr, 0, &cq_id);
			if (rc)
				return;

			if (cq_id < 3 ||
			    cq_id >= rf->cqp.sc_cqp.dev->hmc_info->hmc_obj[IRDMA_HMC_IW_CQ].max_cnt) {
				dbg_vsnprintf("CQ %ld is not valid\n", cq_id);
				return;
			}
		}
	} else {
		if (!all)
			return;

		cq_id = find_next_cq_num(rf, cq_id);
	}

	if (cq_id > 2) {
		struct irdma_cq *iwcq = rf->cq_table[cq_id];

		if (iwcq && !iwcq->user_mode) {
			unsigned long flags;

			spin_lock_irqsave(&iwcq->lock, flags);
			irdma_print_cqes(&iwcq->sc_cq.cq_uk);
			spin_unlock_irqrestore(&iwcq->lock, flags);
		}
	} else {
		cmddone = true;
	}
}

/**
 * dump_stats_cmd - Dump statistics
 * @iwdev: device
 */
static void dump_stats_cmd(struct irdma_device *iwdev)
{
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
	struct irdma_cm_core *cm_core = &iwdev->cm_core;
	struct irdma_hmc_pble_rsrc *pble = iwdev->rf->pble_rsrc;
	struct irdma_puda_rsrc *ilq = iwdev->vsi.ilq;
	struct irdma_puda_rsrc *ieq = iwdev->vsi.ieq;

	dbg_vsnprintf("cm nodes created                 %lld\n",
		      cm_core->stats_nodes_created);
	dbg_vsnprintf("cm nodes destroyed               %lld\n",
		      cm_core->stats_nodes_destroyed);
	dbg_vsnprintf("cm listen called                 %lld\n",
		      cm_core->stats_listen_created);
	dbg_vsnprintf("cm listen removed                %lld\n",
		      cm_core->stats_listen_destroyed);
	dbg_vsnprintf("cm listen nodes created          %lld\n",
		      cm_core->stats_listen_nodes_created);
	dbg_vsnprintf("cm listen nodes destroyed        %lld\n",
		      cm_core->stats_listen_nodes_destroyed);
	dbg_vsnprintf("cm accepts                       %lld\n",
		      cm_core->stats_accepts);
	dbg_vsnprintf("cm rejects                       %lld\n",
		      cm_core->stats_rejects);
	dbg_vsnprintf("cm loopbacks                     %lld\n",
		      cm_core->stats_lpbs);
	dbg_vsnprintf("cm connect errors                %lld\n",
		      cm_core->stats_connect_errs);
	dbg_vsnprintf("cm passive errors                %lld\n",
		      cm_core->stats_passive_errs);
	dbg_vsnprintf("cm pkts retrans                  %lld\n",
		      cm_core->stats_pkt_retrans);
	dbg_vsnprintf("cm backlog drops                 %lld\n",
		      cm_core->stats_backlog_drops);

	dbg_vsnprintf("pble direct sds                  %d\n",
		      pble->stats_direct_sds);
	dbg_vsnprintf("pble paged sds                   %d\n",
		      pble->stats_paged_sds);
	dbg_vsnprintf("pble alloc ok                    %lld\n",
		      pble->stats_alloc_ok);
	dbg_vsnprintf("pble alloc fail                  %lld\n",
		      pble->stats_alloc_fail);
	dbg_vsnprintf("pble alloc freed                 %lld\n",
		      pble->stats_alloc_freed);
	dbg_vsnprintf("pble lvl1 alloc                  %lld\n",
		      pble->stats_lvl1);
	dbg_vsnprintf("pble lvl2 alloc                  %lld\n",
		      pble->stats_lvl2);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
	dbg_vsnprintf("hugepages registered             %d\n",
		       iwdev->hugepgcnt);
#endif
	if (ilq) {
		dbg_vsnprintf("ilq packet sent                  %lld\n",
			      ilq->stats_pkt_sent);
		dbg_vsnprintf("ilq avail buffs                  %d\n",
			      ilq->avail_buf_count);
		dbg_vsnprintf("ilq alloc buffs                  %d\n",
			      ilq->alloc_buf_count);
		dbg_vsnprintf("ilq buf alloc fail               %lld\n",
			      ilq->stats_buf_alloc_fail);
		dbg_vsnprintf("ilq packet rcvd                  %lld\n",
			      ilq->stats_pkt_rcvd);
		dbg_vsnprintf("ilq packet rcv error             %lld\n",
			      ilq->stats_rcvd_pkt_err);
	}

	if (ieq) {
		dbg_vsnprintf("ieq fpdu_processed               %lld\n",
			      ieq->fpdu_processed);
		dbg_vsnprintf("ieq bad_seq_num                  %lld\n",
			      ieq->bad_seq_num);
		dbg_vsnprintf("ieq crc_err                      %lld\n",
			      ieq->crc_err);
		dbg_vsnprintf("ieq pmode_count                  %lld\n",
			      ieq->pmode_count);
		dbg_vsnprintf("ieq bad_qp_id(or RoCE pkts)      %lld\n\n",
			      ieq->stats_bad_qp_id);
	}

	dbg_vsnprintf("cqp requested ops                %llu\n",
		      dev->cqp->requested_ops);
	dbg_vsnprintf("cqp completed ops                %llu\n\n",
		      (u64)atomic64_read(&dev->cqp->completed_ops));

	/* sorted by cqp op type */
	dbg_vsnprintf("cqp OP_CEQ_DESTROY               %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_CEQ_DESTROY]);
	dbg_vsnprintf("cqp OP_AEQ_DESTROY               %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_AEQ_DESTROY]);
	dbg_vsnprintf("cqp OP_DELETE_ARP_CACHE_ENTRY    %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_DELETE_ARP_CACHE_ENTRY]);
	dbg_vsnprintf("cqp OP_MANAGE_APBVT_ENTRY        %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_MANAGE_APBVT_ENTRY]);
	dbg_vsnprintf("cqp OP_CEQ_CREATE                %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_CEQ_CREATE]);
	dbg_vsnprintf("cqp OP_AEQ_CREATE                %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_AEQ_CREATE]);
	dbg_vsnprintf("cqp OP_MANAGE_QHASH_TABLE_ENTRY  %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_MANAGE_QHASH_TABLE_ENTRY]);
	dbg_vsnprintf("cqp OP_QP_MODIFY                 %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_QP_MODIFY]);
	dbg_vsnprintf("cqp OP_QP_UPLOAD_CONTEXT         %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_QP_UPLOAD_CONTEXT]);
	dbg_vsnprintf("cqp OP_CQ_CREATE                 %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_CQ_CREATE]);
	dbg_vsnprintf("cqp OP_CQ_DESTROY                %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_CQ_DESTROY]);
	dbg_vsnprintf("cqp OP_QP_CREATE                 %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_QP_CREATE]);
	dbg_vsnprintf("cqp OP_QP_DESTROY                %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_QP_DESTROY]);
	dbg_vsnprintf("cqp OP_ALLOC_STAG                %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_ALLOC_STAG]);
	dbg_vsnprintf("cqp OP_MR_REG_NON_SHARED         %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_MR_REG_NON_SHARED]);
	dbg_vsnprintf("cqp OP_DEALLOC_STAG              %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_DEALLOC_STAG]);
	dbg_vsnprintf("cqp OP_MW_ALLOC                  %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_MW_ALLOC]);
	dbg_vsnprintf("cqp OP_QP_FLUSH_WQES             %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_QP_FLUSH_WQES]);
	dbg_vsnprintf("cqp OP_ADD_ARP_CACHE_ENTRY       %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_ADD_ARP_CACHE_ENTRY]);
	dbg_vsnprintf("cqp OP_MANAGE_PUSH_PAGE          %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_MANAGE_PUSH_PAGE]);
	dbg_vsnprintf("cqp OP_UPDATE_PE_SDS             %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_UPDATE_PE_SDS]);
	dbg_vsnprintf("cqp OP_MANAGE_HMC_PM_FUNC_TABLE  %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_MANAGE_HMC_PM_FUNC_TABLE]);
	dbg_vsnprintf("cqp OP_SUSPEND                   %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_SUSPEND]);
	dbg_vsnprintf("cqp OP_RESUME                    %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_RESUME]);
	dbg_vsnprintf("cqp OP_MANAGE_PBLE_BP		%lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_MANAGE_PBLE_BP]);
	dbg_vsnprintf("cqp OP_QUERY_FPM_VAL             %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_QUERY_FPM_VAL]);
	dbg_vsnprintf("cqp OP_COMMIT_FPM_VAL            %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_COMMIT_FPM_VAL]);
	dbg_vsnprintf("cqp OP_AH_CREATE                 %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_AH_CREATE]);
	dbg_vsnprintf("cqp OP_AH_MODIFY                 %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_AH_MODIFY]);
	dbg_vsnprintf("cqp OP_AH_DESTROY                %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_AH_DESTROY]);
	dbg_vsnprintf("cqp OP_MC_CREATE                 %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_MC_CREATE]);
	dbg_vsnprintf("cqp OP_MC_DESTROY                %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_MC_DESTROY]);
	dbg_vsnprintf("cqp OP_MC_MODIFY                 %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_MC_MODIFY]);
	dbg_vsnprintf("cqp OP_STATS_ALLOCATE            %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_STATS_ALLOCATE]);
	dbg_vsnprintf("cqp OP_STATS_FREE                %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_STATS_FREE]);
	dbg_vsnprintf("cqp OP_STATS_GATHER              %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_STATS_GATHER]);
	dbg_vsnprintf("cqp OP_WS_ADD_NODE               %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_WS_ADD_NODE]);
	dbg_vsnprintf("cqp OP_WS_MODIFY_NODE            %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_WS_MODIFY_NODE]);
	dbg_vsnprintf("cqp OP_WS_DELETE_NODE            %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_WS_DELETE_NODE]);
	dbg_vsnprintf("cqp OP_WS_FAILOVER_START         %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_WS_FAILOVER_START]);
	dbg_vsnprintf("cqp OP_WS_FAILOVER_COMPLETE      %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_WS_FAILOVER_COMPLETE]);
	dbg_vsnprintf("cqp OP_SET_UP_MAP                %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_SET_UP_MAP]);
	dbg_vsnprintf("cqp OP_GEN_AE                    %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_GEN_AE]);
	dbg_vsnprintf("cqp OP_QUERY_RDMA_FEATURES       %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_QUERY_RDMA_FEATURES]);
	dbg_vsnprintf("cqp OP_ALLOC_LOCAL_MAC_ENTRY     %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_ALLOC_LOCAL_MAC_ENTRY]);
	dbg_vsnprintf("cqp OP_ADD_LOCAL_MAC_ENTRY       %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_ADD_LOCAL_MAC_ENTRY]);
	dbg_vsnprintf("cqp OP_DELETE_LOCAL_MAC_ENTRY    %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_DELETE_LOCAL_MAC_ENTRY]);
	dbg_vsnprintf("cqp OP_CQ_MODIFY                 %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_CQ_MODIFY]);
	dbg_vsnprintf("cqp OP_SRQ_CREATE                %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_SRQ_CREATE]);
	dbg_vsnprintf("cqp OP_SRQ_MODIFY                %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_SRQ_MODIFY]);
	dbg_vsnprintf("cqp OP_SRQ_DESTROY               %lld\n",
		      dev->cqp_cmd_stats[IRDMA_OP_SRQ_DESTROY]);

	dbg_vsnprintf("AH Reused Count                  %lld\n",
		      iwdev->ah_reused);
	dbg_vsnprintf("AH Current List Count            %d\n",
		      iwdev->ah_list_cnt);
	dbg_vsnprintf("AH list cnt HWM                  %d\n",
		      iwdev->ah_list_hwm);

#if IS_ENABLED(CONFIG_CONFIGFS_FS)
	if  (iwdev->roce_mode) {
		dbg_vsnprintf("roce rtomin  = %d\n", iwdev->roce_rtomin);
		dbg_vsnprintf("roce cwnd    = %d\n", iwdev->roce_cwnd);
	} else {
		dbg_vsnprintf("iwarp rtomin = %d\n", iwdev->iwarp_rtomin);
		dbg_vsnprintf("iwarp rcvwnd = %d\n", iwdev->rcv_wnd);
	}
#endif /* CONFIG_CONFIGFS_FS */
#if 0
	irdma_dump_cm_nodes(iwdev);
#endif
	cmddone = true;
}

/**
 * dump_hw_stats_cmd -
 * @iwdev: iwarp device
 */
static void dump_hw_stats_cmd(struct irdma_device *iwdev)
{
	struct irdma_sc_dev *dev = &iwdev->rf->sc_dev;
	struct irdma_vsi_pestat *devstat = iwdev->vsi.pestat;
	struct irdma_dev_hw_stats *hw_stats = &devstat->hw_stats;

	if (iwdev->rf->rdma_ver >= IRDMA_GEN_2)
		irdma_cqp_gather_stats_cmd(dev, devstat, true);
	else
		irdma_cqp_gather_stats_gen1(dev, devstat);

	dbg_vsnprintf("IPV4 octs recvd                      %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4RXOCTS]);
	dbg_vsnprintf("IPV6 octs recvd                      %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6RXOCTS]);
	dbg_vsnprintf("IPV4 pkts recvd                      %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4RXPKTS]);
	dbg_vsnprintf("IPV6 pkts recvd                      %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6RXPKTS]);
	dbg_vsnprintf("IPV4 frag recvd                      %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4RXFRAGS]);
	dbg_vsnprintf("IPV6 frag recvd                      %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6RXFRAGS]);

	if (iwdev->rf->rdma_ver >= IRDMA_GEN_2) {
		dbg_vsnprintf("IPV4 multicast pkts recvd            %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4RXMCPKTS]);
		dbg_vsnprintf("IPV6 multicast pkts recvd            %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6RXMCPKTS]);
		dbg_vsnprintf("IPV4 multicast octs recvd            %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4RXMCOCTS]);
		dbg_vsnprintf("IPV6 multicast octs recvd            %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6RXMCOCTS]);
	}

	dbg_vsnprintf("IPV4 octs trans                      %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4TXOCTS]);
	dbg_vsnprintf("IPV6 octs trans                      %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6TXOCTS]);
	dbg_vsnprintf("IPV4 pkts trans                      %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4TXPKTS]);
	dbg_vsnprintf("IPV6 pkts trans                      %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6TXPKTS]);
	dbg_vsnprintf("IPV4 frag trans                      %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4TXFRAGS]);
	dbg_vsnprintf("IPV6 frag trans                      %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6TXFRAGS]);
	dbg_vsnprintf("IPV4 multicast pkts trans            %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4TXMCPKTS]);
	dbg_vsnprintf("IPV6 multicast pkts trans            %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6TXMCPKTS]);
	dbg_vsnprintf("IPV4 multicast octs trans            %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4TXMCOCTS]);
	dbg_vsnprintf("IPV6 multicast octs trans            %llu\n",
	       hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6TXMCOCTS]);
	dbg_vsnprintf("IPV4 pkts recvd & discarded          %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4RXDISCARD]);
	dbg_vsnprintf("IPV6 pkts recvd & discarded          %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6RXDISCARD]);
	dbg_vsnprintf("IPV4 pkts recvd & truncated          %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4RXTRUNC]);
	dbg_vsnprintf("IPV6 pkts recvd & truncated          %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6RXTRUNC]);
	dbg_vsnprintf("IPV4 dtgms discarded (no ARP hit)    %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP4TXNOROUTE]);
	dbg_vsnprintf("IPV6 dtgms discarded (no ARP hit)    %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_IP6TXNOROUTE]);
	dbg_vsnprintf("Rx VLAN err                          %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RXVLANERR]);

	dbg_vsnprintf("TCP sgmnts recvd                     %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_TCPRXSEGS]);
	dbg_vsnprintf("TCP sgmnts trans                     %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_TCPTXSEG]);
	dbg_vsnprintf("TCP sgmnts retrans                   %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_TCPRTXSEG]);
	dbg_vsnprintf("TCP sgmnts recvd w/ err              %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_TCPRXOPTERR]);
	dbg_vsnprintf("TCP sgmnts recvd w/ protocol-err     %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_TCPRXPROTOERR]);

	if (iwdev->rf->rdma_ver >= IRDMA_GEN_2) {
		dbg_vsnprintf("Rx CNP HANDLED                       %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RXRPCNPHANDLED]);
		dbg_vsnprintf("Rx CNP IGNORED                       %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RXRPCNPIGNORED]);
		dbg_vsnprintf("Tx CNP SENT                          %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_TXNPCNPSENT]);
	}

	dbg_vsnprintf("RDMA read-req msgs recvd             %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RDMARXRDS]);
	dbg_vsnprintf("RDMA send-type msgs recvd            %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RDMARXSNDS]);
	dbg_vsnprintf("RDMA write msgs recvd                %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RDMARXWRS]);
	dbg_vsnprintf("RDMA read-req msgs sent              %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RDMATXRDS]);
	dbg_vsnprintf("RDMA send-type msgs sent             %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RDMATXSNDS]);
	dbg_vsnprintf("RDMA write msgs sent                 %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RDMATXWRS]);
	dbg_vsnprintf("RDMA verb-bind ops                   %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RDMAVBND]);
	dbg_vsnprintf("RDMA verb-inv ops                    %llu\n",
		      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RDMAVINV]);

	if (iwdev->rf->rdma_ver >= IRDMA_GEN_2) {
		dbg_vsnprintf("UDP recvd                            %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_UDPRXPKTS]);
		dbg_vsnprintf("UDP trans                            %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_UDPTXPKTS]);
	}

	if (iwdev->rf->rdma_ver >= IRDMA_GEN_2 && iwdev->roce_mode) {
		dbg_vsnprintf("RX ECN MARKED PKTS           %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RXNPECNMARKEDPKTS]);
	}

	if (iwdev->rf->rdma_ver >= IRDMA_GEN_3) {
		dbg_vsnprintf("RNR sent                     %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RNR_SENT]);
		dbg_vsnprintf("RNR received                 %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RNR_RCVD]);
		dbg_vsnprintf("ord limit count              %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RDMAORDLMTCNT]);
		dbg_vsnprintf("ird limit count              %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RDMAIRDLMTCNT]);
		dbg_vsnprintf("Rx ATS                       %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RDMARXATS]);
		dbg_vsnprintf("Tx ATS                       %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RDMATXATS]);
		dbg_vsnprintf("Nak Sequence Error           %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_NAKSEQERR]);
		dbg_vsnprintf("Nak Sequence Error Implied   %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_NAKSEQERR_IMPLIED]);
		dbg_vsnprintf("RTO                          %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RTO]);
		dbg_vsnprintf("Rcvd Out of order packets    %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_RXOOOPKTS]);
		dbg_vsnprintf("CRC errors                   %llu\n",
			      hw_stats->stats_val[IRDMA_HW_STAT_INDEX_ICRCERR]);
	}

	cmddone = true;
}

#if 0
/**
 * dump_mem_cmd -
 * @rf: RDMA PCI function
 * @cbuf: character buffer
 */
static void dump_mem_cmd(struct irdma_pci_f *rf, char *cbuf)
{
	static char *addr;
	static int offset;
	static int groupsize;
	static size_t dumpsize;
	static size_t lendumped;
	static int ascii;
	int delta = 0;
	int ret;

	if (cmdnew) {
		if (sscanf(cbuf, "%llx%n", (u64 *)&addr, &delta) == 0)
			return;

		cbuf += delta;
		if (sscanf(cbuf, "%zu%n", &dumpsize, &delta) == 0)
			return;

		cbuf += delta;
		ret = kstrtoint(cbuf, 10, &groupsize);
		if (ret < 0)
			groupsize = 4;

		if (dumpsize == 0 || (dumpsize & 0x80000000))
			dumpsize = 32;

		switch (groupsize) {
		case 1:
			ascii = true;
			break;
		case 8:
			break;
		default:
			groupsize = 4;
		}
		offset = 0;
	}

	dump_to_buf(addr, dumpsize, offset, 16, groupsize, ascii,
		       &lendumped);

	addr += lendumped;
	offset += lendumped;
	dumpsize -= lendumped;
	if (dumpsize == 0)
		cmddone = true;
}

/**
 * dump_pmem_cmd -
 * @rf: RDMA PCI function
 * @cbuf: char buffer
 */
static void dump_pmem_cmd(struct irdma_pci_f *rf, char *cbuf)
{
	static ulong paddr;
	static char *addr;
	static int offset;
	static int groupsize;
	static size_t dumpsize;
	static size_t lendumped;
	static int ascii;
	int delta = 0;
	int ret;

	if (cmdnew) {
		if (sscanf(cbuf, "%llx%n", (u64 *)&paddr, &delta) == 0)
			return;

		cbuf += delta;
		if (sscanf(cbuf, "%zu%n", &dumpsize, &delta) == 0)
			return;

		cbuf += delta;
		ret = kstrtoint(cbuf, 10, &groupsize);
		if (ret < 0)
			groupsize = 4;

		if (dumpsize == 0 || (dumpsize & 0x80000000))
			dumpsize = 32;

		switch (grpsize) {
		case 1:
			ascii = true;
			break;
		case 8:
			break;
		default:
			groupsize = 4;
		}
		offset = 0;
	}

	addr = ioremap(paddr, dumpsize);
	if (addr) {
		dump_to_buf(addr, dumpsize, offset, 16, groupsize, ascii,
			       &lendumped);
		iounmap(addr);
	}

	paddr += lendumped;
	offset += lendumped;
	dumpsize -= lendumped;
	if (dumpsize == 0)
		cmddone = true;
}

#endif
/**
 * irdma_dbg_dump_read - read the dump data
 * @filp: the opened file
 * @buf: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 *
 * When a read happens, the file system will keep calling this routine
 * until it returns with no data.  This is because the buffers may be too
 * small to contain all the data at once.  Some of the cmds count on being
 * able to return the results in pieces.
 */
static ssize_t irdma_dbg_dump_read(struct file *filp,
				   char __user *buf,
				   size_t count,
				   loff_t *ppos)
{
	struct irdma_handler *hdl = filp->private_data;
	struct irdma_device *iwdev = hdl->iwdev;
	struct irdma_pci_f *rf;
	int bytes_not_copied;
	int len;

	rf = iwdev->rf;
	if (cmddone) {
		cmdnew = true;
		cmddone = false;
	} else {
		if (cmdnew)
			dbg_vsnprintf("cmd: %s", cmd_buf);

		if (strncasecmp(cmd_buf, "qp ", 3) == 0)
			dump_qp_cmd(rf, &cmd_buf[3]);
		else if (strncasecmp(cmd_buf, "cq ", 3) == 0)
			dump_cq_cmd(rf, &cmd_buf[3]);
		else if (strncasecmp(cmd_buf, "sw-stats", 8) == 0)
			dump_stats_cmd(iwdev);
		else if (strncasecmp(cmd_buf, "hw-stats", 8) == 0)
			dump_hw_stats_cmd(iwdev);
		else
			dump_help();
		cmdnew = false;
	}

	len = min_t(int, count, (irdma_dbg_dump_data_len - *ppos));
	if (len == 0) {
		*ppos = 0;
		irdma_dbg_dump_data_len = 0;
		return 0;
	}

	bytes_not_copied =
	    copy_to_user(buf, &irdma_dbg_dump_buf[*ppos], len);
	if (bytes_not_copied) {
		dev_warn(iwdev->ibdev.dma_device,
			 "copy_to_user returned 0x%x\n", bytes_not_copied);
	}

	*ppos += len;
	if (*ppos >= irdma_dbg_dump_data_len) {
		*ppos = 0;
		irdma_dbg_dump_data_len = 0;
	}

	return len;
}

/**
 * irdma_dbg_dump_write - trigger a datadump snapshot
 * @filp: the opened file
 * @buf: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t irdma_dbg_dump_write(struct file *filp,
				    const char __user *buf,
				    size_t count,
				    loff_t *ppos)
{
	int bytes_not_copied;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(cmd_buf))
		return -ENOSPC;

	bytes_not_copied = copy_from_user(cmd_buf, buf, count);
	if (bytes_not_copied < 0)
		return bytes_not_copied;
	if (bytes_not_copied > 0)
		count -= bytes_not_copied;

	cmd_buf[count] = '\0';
	cmdnew = true;
	cmddone = false;
	*ppos = 0;
	irdma_dbg_dump_data_len = 0;
	return count;
}

/**
 * irdma_dbg_prep_dump_buf
 * @hdl: the iWARP handler we're working with
 * @buflen: the desired buffer length
 *
 * Return positive if success, 0 if failed
 */
static int irdma_dbg_prep_dump_buf(struct irdma_handler *hdl, int buflen)
{
	if (irdma_dbg_dump_buf_len && irdma_dbg_dump_buf_len < buflen) {
		kfree(irdma_dbg_dump_buf);
		irdma_dbg_dump_buf_len = 0;
		irdma_dbg_dump_buf = NULL;
	}

	if (!irdma_dbg_dump_buf) {
		irdma_dbg_dump_buf = kzalloc(buflen, GFP_KERNEL);
		if (!irdma_dbg_dump_buf) {
			irdma_dbg_dump_buf_len = 0;
			pr_err("%s: memory alloc for snapshot failed\n",
			       __func__);
		} else {
			irdma_dbg_dump_buf_len = buflen;
			pr_err("%s: irdma_dbg_dump_buf_len = %d\n",
			       __func__, (int)irdma_dbg_dump_buf_len);
		}
	}

	return irdma_dbg_dump_buf_len;
}

static const struct file_operations irdma_dbg_dump_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = irdma_dbg_dump_read,
	.write = irdma_dbg_dump_write,
};

/**
 * irdma_dbg_pf_init - setup the debugfs directory for the pf
 * @hdl: the iWARP handler that is starting up
 */
void irdma_dbg_pf_init(struct irdma_handler *hdl)
{
	const char *name = pci_name(hdl->iwdev->rf->pcidev);
	struct dentry *pfile __attribute__ ((unused));

	spin_lock_init(&hdl->uctx_list_lock);
	INIT_LIST_HEAD(&hdl->ucontext_list);
	if (irdma_dbg_prep_dump_buf(hdl, IRDMA_DUMP_BUF_SIZE) == 0) {
		pr_err("irdma_dbg_pf_init: unable to allocate debugfs dump buffer\n");
		return;
	}

	hdl->irdma_dbg_dentry = debugfs_create_dir(name, irdma_dbg_root);
	if (hdl->irdma_dbg_dentry)
		pfile =
		    debugfs_create_file("dump", 0600, hdl->irdma_dbg_dentry,
					hdl, &irdma_dbg_dump_fops);
	else
		pr_err("%s: debugfs entry for %s failed\n", __func__, name);
}

/**
 * irdma_dbg_pf_exit - clear out the pf's debugfs entries
 * @hdl: the iWARP handler that is stopping
 */
void irdma_dbg_pf_exit(struct irdma_handler *hdl)
{
	if (hdl) {
		pr_err("%s: removing debugfs entries\n", __func__);
		debugfs_remove_recursive(hdl->irdma_dbg_dentry);
		hdl->irdma_dbg_dentry = NULL;
	}
}

/**
 * irdma_dbg_init - start up debugfs for the driver
 */
void irdma_dbg_init(void)
{
	irdma_dbg_root = debugfs_create_dir(irdma_driver_name, NULL);
	if (!irdma_dbg_root)
		pr_err("%s: init of debugfs failed\n", __func__);
}

/**
 * irdma_dbg_exit - clean out the driver's debugfs entries
 */
void irdma_dbg_exit(void)
{
	kfree(irdma_dbg_dump_buf);
	irdma_dbg_dump_buf_len = 0;
	irdma_dbg_dump_buf = NULL;
	debugfs_remove_recursive(irdma_dbg_root);
}

#endif /* CONFIG_DEBUG_FS */
