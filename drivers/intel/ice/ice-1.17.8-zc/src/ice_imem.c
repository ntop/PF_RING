/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2018-2025 Intel Corporation */

#include "ice_common.h"
#include "ice_parser_util.h"

#define ICE_IMEM_TABLE_SIZE 192

static void _imem_bst_bm_dump(struct ice_hw *hw, struct ice_bst_main *bm)
{
	dev_info(ice_hw_to_dev(hw), "boost main:\n");
	dev_info(ice_hw_to_dev(hw), "\tal0 = %d\n", bm->al0);
	dev_info(ice_hw_to_dev(hw), "\tal1 = %d\n", bm->al1);
	dev_info(ice_hw_to_dev(hw), "\tal2 = %d\n", bm->al2);
	dev_info(ice_hw_to_dev(hw), "\tpg = %d\n", bm->pg);
}

static void _imem_bst_kb_dump(struct ice_hw *hw, struct ice_bst_keybuilder *kb)
{
	dev_info(ice_hw_to_dev(hw), "boost key builder:\n");
	dev_info(ice_hw_to_dev(hw), "\tpriority = %d\n", kb->priority);
	dev_info(ice_hw_to_dev(hw), "\ttsr_ctrl = %d\n", kb->tsr_ctrl);
}

static void _imem_np_kb_dump(struct ice_hw *hw, struct ice_np_keybuilder *kb)
{
	dev_info(ice_hw_to_dev(hw), "next proto key builder:\n");
	dev_info(ice_hw_to_dev(hw), "\tops = %d\n", kb->ops);
	dev_info(ice_hw_to_dev(hw), "\tstart_or_reg0 = %d\n",
		 kb->start_or_reg0);
	dev_info(ice_hw_to_dev(hw), "\tlen_or_reg1 = %d\n", kb->len_or_reg1);
}

static void _imem_pg_kb_dump(struct ice_hw *hw, struct ice_pg_keybuilder *kb)
{
	dev_info(ice_hw_to_dev(hw), "parse graph key builder:\n");
	dev_info(ice_hw_to_dev(hw), "\tflag0_ena = %d\n", kb->flag0_ena);
	dev_info(ice_hw_to_dev(hw), "\tflag1_ena = %d\n", kb->flag1_ena);
	dev_info(ice_hw_to_dev(hw), "\tflag2_ena = %d\n", kb->flag2_ena);
	dev_info(ice_hw_to_dev(hw), "\tflag3_ena = %d\n", kb->flag3_ena);
	dev_info(ice_hw_to_dev(hw), "\tflag0_idx = %d\n", kb->flag0_idx);
	dev_info(ice_hw_to_dev(hw), "\tflag1_idx = %d\n", kb->flag1_idx);
	dev_info(ice_hw_to_dev(hw), "\tflag2_idx = %d\n", kb->flag2_idx);
	dev_info(ice_hw_to_dev(hw), "\tflag3_idx = %d\n", kb->flag3_idx);
	dev_info(ice_hw_to_dev(hw), "\talu_reg_idx = %d\n", kb->alu_reg_idx);
}

static void _imem_alu_dump(struct ice_hw *hw, struct ice_alu *alu, int index)
{
	dev_info(ice_hw_to_dev(hw), "alu%d:\n", index);
	dev_info(ice_hw_to_dev(hw), "\topc = %d\n", alu->opc);
	dev_info(ice_hw_to_dev(hw), "\tsrc_start = %d\n", alu->src_start);
	dev_info(ice_hw_to_dev(hw), "\tsrc_len = %d\n", alu->src_len);
	dev_info(ice_hw_to_dev(hw), "\tshift_xlate_select = %d\n",
		 alu->shift_xlate_select);
	dev_info(ice_hw_to_dev(hw), "\tshift_xlate_key = %d\n",
		 alu->shift_xlate_key);
	dev_info(ice_hw_to_dev(hw), "\tsrc_reg_id = %d\n", alu->src_reg_id);
	dev_info(ice_hw_to_dev(hw), "\tdst_reg_id = %d\n", alu->dst_reg_id);
	dev_info(ice_hw_to_dev(hw), "\tinc0 = %d\n", alu->inc0);
	dev_info(ice_hw_to_dev(hw), "\tinc1 = %d\n", alu->inc1);
	dev_info(ice_hw_to_dev(hw), "\tproto_offset_opc = %d\n",
		 alu->proto_offset_opc);
	dev_info(ice_hw_to_dev(hw), "\tproto_offset = %d\n",
		 alu->proto_offset);
	dev_info(ice_hw_to_dev(hw), "\tbranch_addr = %d\n", alu->branch_addr);
	dev_info(ice_hw_to_dev(hw), "\timm = %d\n", alu->imm);
	dev_info(ice_hw_to_dev(hw), "\tdst_start = %d\n", alu->dst_start);
	dev_info(ice_hw_to_dev(hw), "\tdst_len = %d\n", alu->dst_len);
	dev_info(ice_hw_to_dev(hw), "\tflags_extr_imm = %d\n",
		 alu->flags_extr_imm);
	dev_info(ice_hw_to_dev(hw), "\tflags_start_imm= %d\n",
		 alu->flags_start_imm);
}

/**
 * ice_imem_dump - dump an imem item info
 * @hw: pointer to the hardware structure
 * @item: imem item to dump
 */
void ice_imem_dump(struct ice_hw *hw, struct ice_imem_item *item)
{
	dev_info(ice_hw_to_dev(hw), "index = %d\n", item->idx);
	_imem_bst_bm_dump(hw, &item->b_m);
	_imem_bst_kb_dump(hw, &item->b_kb);
	dev_info(ice_hw_to_dev(hw), "pg priority = %d\n", item->pg);
	_imem_np_kb_dump(hw, &item->np_kb);
	_imem_pg_kb_dump(hw, &item->pg_kb);
	_imem_alu_dump(hw, &item->alu0, 0);
	_imem_alu_dump(hw, &item->alu1, 1);
	_imem_alu_dump(hw, &item->alu2, 2);
}

/** The function parses a 4 bits Boost Main with below format:
 *  BIT 0: ALU 0 (bm->alu0)
 *  BIT 1: ALU 1 (bm->alu1)
 *  BIT 2: ALU 2 (bm->alu2)
 *  BIT 3: Parge Graph (bm->pg)
 */
static void _imem_bm_init(struct ice_bst_main *bm, u8 data)
{
	bm->al0 = (data & 0x1) != 0;
	bm->al1 = (data & 0x2) != 0;
	bm->al2 = (data & 0x4) != 0;
	bm->pg = (data & 0x8) != 0;
}

/** The function parses a 10 bits Boost Main Build with below format:
 *  BIT 0-7:	Priority (bkb->priority)
 *  BIT 8:	TSR Control (bkb->tsr_ctrl)
 *  BIT 9:	Reserved
 */
static void _imem_bkb_init(struct ice_bst_keybuilder *bkb, u16 data)
{
	bkb->priority = (u8)(data & 0xff);
	bkb->tsr_ctrl = (data & 0x100) != 0;
}

/** The function parses a 18 bits Next Protocol Key Build with below format:
 *  BIT 0-1:	Opcode kb->ops
 *  BIT 2-9:	Start / Reg 0 (kb->start_or_reg0)
 *  BIT 10-17:	Length / Reg 1 (kb->len_or_reg1)
 */
static void _imem_npkb_init(struct ice_np_keybuilder *kb, u32 data)
{
	kb->ops = (u8)(data & 0x3);
	kb->start_or_reg0 = (u8)((data >> 2) & 0xff);
	kb->len_or_reg1 = (u8)((data >> 10) & 0xff);
}

/** The function parses a 35 bits Parse Graph Key Build with below format:
 *  BIT 0:	Flag 0 Enable (kb->flag0_ena)
 *  BIT 1-6:	Flag 0 Index (kb->flag0_idx)
 *  BIT 7:	Flag 1 Enable (kb->flag1_ena)
 *  BIT 8-13:	Flag 1 Index (kb->flag1_idx)
 *  BIT 14:	Flag 2 Enable (kb->flag2_ena)
 *  BIT 15-20:	Flag 2 Index (kb->flag2_idx)
 *  BIT 21:	Flag 3 Enable (kb->flag3_ena)
 *  BIT 22-27:	Flag 3 Index (kb->flag3_idx)
 *  BIT 28-34:	ALU Register Index (kb->alu_reg_idx)
 */
static void _imem_pgkb_init(struct ice_pg_keybuilder *kb, u64 data)
{
	kb->flag0_ena = (data & 0x1) != 0;
	kb->flag0_idx = (u8)((data >> 1) & 0x3f);
	kb->flag1_ena = ((data >> 7) & 0x1) != 0;
	kb->flag1_idx = (u8)((data >> 8) & 0x3f);
	kb->flag2_ena = ((data >> 14) & 0x1) != 0;
	kb->flag2_idx = (u8)((data >> 15) & 0x3f);
	kb->flag3_ena = ((data >> 21) & 0x1) != 0;
	kb->flag3_idx = (u8)((data >> 22) & 0x3f);
	kb->alu_reg_idx = (u8)((data >> 28) & 0x7f);
}

/** The function parses a 96 bits ALU entry with below format:
 *  BIT 0-5:	Opcode (alu->opc)
 *  BIT 6-13:	Source Start (alu->src_start)
 *  BIT 14-18:	Source Length (alu->src_len)
 *  BIT 19:	Shift/Xlate Select (alu->shift_xlate_select)
 *  BIT 20-23:	Shift/Xlate Key (alu->shift_xlate_key)
 *  BIT 24-30:	Source Register ID (alu->src_reg_id)
 *  BIT 31-37:	Dest. Register ID (alu->dst_reg_id)
 *  BIT 38:	Inc0 (alu->inc0)
 *  BIT 39:	Inc1:(alu->inc1)
 *  BIT 40:41	Protocol Offset Opcode (alu->proto_offset_opc)
 *  BIT 42:49	Protocol Offset (alu->proto_offset)
 *  BIT 50:57	Branch Address (alu->branch_addr)
 *  BIT 58:73	Immediate (alu->imm)
 *  BIT 74	Dedicated Flags Enable (alu->dedicate_flags_ena)
 *  BIT 75:80	Dest. Start (alu->dst_start)
 *  BIT 81:86	Dest. Length (alu->dst_len)
 *  BIT 87	Flags Extract Imm. (alu->flags_extr_imm)
 *  BIT 88:95	Flags Start/Immediate (alu->flags_start_imm)
 *
 *  NOTE: the first 5 bits are skipped as the start bit is not
 *  byte aligned.
 */
static void _imem_alu_init(struct ice_alu *alu, u8 *data)
{
	u64 d64 = *(u64 *)data >> 5;

	alu->opc = (enum ice_alu_opcode)(d64 & 0x3f);
	alu->src_start = (u8)((d64 >> 6) & 0xff);
	alu->src_len = (u8)((d64 >> 14) & 0x1f);
	alu->shift_xlate_select = ((d64 >> 19) & 0x1) != 0;
	alu->shift_xlate_key = (u8)((d64 >> 20) & 0xf);
	alu->src_reg_id = (u8)((d64 >> 24) & 0x7f);
	alu->dst_reg_id = (u8)((d64 >> 31) & 0x7f);
	alu->inc0 = ((d64 >> 38) & 0x1) != 0;
	alu->inc1 = ((d64 >> 39) & 0x1) != 0;
	alu->proto_offset_opc = (u8)((d64 >> 40) & 0x3);
	alu->proto_offset = (u8)((d64 >> 42) & 0xff);
	alu->branch_addr = (u8)((d64 >> 50) & 0xff);

	d64 = *(u64 *)(&data[7]) >> 7;

	alu->imm = (u16)(d64 & 0xffff);
	alu->dedicate_flags_ena = ((d64 >> 16) & 0x1) != 0;
	alu->dst_start = (u8)((d64 >> 17) & 0x3f);
	alu->dst_len = (u8)((d64 >> 23) & 0x3f);
	alu->flags_extr_imm = ((d64 >> 29) & 0x1) != 0;
	alu->flags_start_imm = (u8)((d64 >> 30) & 0xff);
}

/** The function parses a 384 bits IMEM entry with below format:
 *  BIT 0-3:	Boost Main (ii->b_m)
 *  BIT 4-13:	Boost Key Build (ii->b_kb)
 *  BIT 14-15:	PG Priority (ii->pg)
 *  BIT 16-33:	Next Proto Key Build (ii->np_kb)
 *  BIT 34-68:	PG Key Build (ii->pg_kb)
 *  BIT 69-164:	ALU0 (ii->alu0)
 *  BIT 165-260:ALU1 (ii->alu1)
 *  BIT 261-356:ALU2 (ii->alu2)
 *  BIT 357-383:Reserved
 */
static void _imem_parse_item(struct ice_hw *hw, u16 idx, void *item,
			     void *data, int size)
{
	struct ice_imem_item *ii = item;
	u8 *buf = data;

	ii->idx = idx;

	_imem_bm_init(&ii->b_m, buf[0]);
	_imem_bkb_init(&ii->b_kb, *((u16 *)(&buf[0])) >> 4);

	ii->pg = FIELD_GET(0xc0, buf[1]);
	_imem_npkb_init(&ii->np_kb, *((u32 *)(&buf[2])));
	_imem_pgkb_init(&ii->pg_kb, *((u64 *)(&buf[2])) >> 18);
	_imem_alu_init(&ii->alu0, &buf[8]);
	_imem_alu_init(&ii->alu1, &buf[20]);
	_imem_alu_init(&ii->alu2, &buf[32]);

	if (hw->debug_mask & ICE_DBG_PARSER)
		ice_imem_dump(hw, ii);
}

/**
 * ice_imem_table_get - create an imem table
 * @hw: pointer to the hardware structure
 */
struct ice_imem_item *ice_imem_table_get(struct ice_hw *hw)
{
	return (struct ice_imem_item *)
		ice_parser_create_table(hw, ICE_SID_RXPARSER_IMEM,
					sizeof(struct ice_imem_item),
					ICE_IMEM_TABLE_SIZE,
					ice_parser_sect_item_get,
					_imem_parse_item, false);
}
