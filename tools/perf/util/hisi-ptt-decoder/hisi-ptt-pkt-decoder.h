/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HiSilicon PCIe Trace and Tuning (PTT) support
 * Copyright (c) 2022 HiSilicon Technologies Co., Ltd.
 */

#ifndef INCLUDE__HISI_PTT_PKT_DECODER_H__
#define INCLUDE__HISI_PTT_PKT_DECODER_H__

#include <stddef.h>
#include <stdint.h>

#define HISI_PTT_PKT_DESC_MAX		256
#define HISI_PTT_NEED_MORE_BYTES	-1
#define HISI_PTT_8DW_CHECK_MASK		GENMASK(31, 11)
#define HISI_PTT_IS_8DW_PKT		GENMASK(31, 11)
#define HISI_PTT_8DW_PKT_SIZE		32
#define HISI_PTT_4DW_PKT_SIZE		16
#define HISI_PTT_MAX_SPACE_LEN		10

enum hisi_ptt_pkt_type {
	HISI_PTT_4DW_PKT,
	HISI_PTT_8DW_PKT,
};

int hisi_ptt_pkt_desc(const unsigned char *buf, int pos, enum hisi_ptt_pkt_type type);

#endif
