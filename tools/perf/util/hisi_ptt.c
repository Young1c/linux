// SPDX-License-Identifier: GPL-2.0
/*
 * HiSilicon PCIe Trace and Tuning (PTT) support
 * Copyright (c) 2022 HiSilicon Technologies Co., Ltd.
 */

#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/types.h>
#include <linux/zalloc.h>
#include <stdlib.h>
#include <unistd.h>

#include "auxtrace.h"
#include "color.h"
#include "debug.h"
#include "evlist.h"
#include "evsel.h"
#include "hisi_ptt.h"
#include "hisi-ptt-decoder/hisi-ptt-pkt-decoder.h"
#include "machine.h"
#include "session.h"
#include "symbol.h"
#include "tool.h"
#include "util/synthetic-events.h"

struct hisi_ptt {
	struct auxtrace auxtrace;
	struct auxtrace_queues queues;
	u32 auxtrace_type;
	struct perf_session *session;
	struct machine *machine;
	u32 pmu_type;
};

struct hisi_ptt_queue {
	struct hisi_ptt *ptt;
	struct auxtrace_buffer *buffer;
};

static enum hisi_ptt_pkt_type hisi_ptt_check_packet_type(unsigned char *buf)
{
	uint32_t head = *(uint32_t *)buf;

	if ((HISI_PTT_8DW_CHECK_MASK & head) == HISI_PTT_IS_8DW_PKT)
		return HISI_PTT_8DW_PKT;

	return HISI_PTT_4DW_PKT;
}

static void hisi_ptt_dump(struct hisi_ptt *ptt __maybe_unused,
			  unsigned char *buf, size_t len)
{
	const char *color = PERF_COLOR_BLUE;
	enum hisi_ptt_pkt_type type;
	size_t pos = 0;
	int pkt_len;

	color_fprintf(stdout, color, ". ... HISI PTT data: size %zu bytes\n",
		      len);

	type = hisi_ptt_check_packet_type(buf);
	while (len) {
		pkt_len = hisi_ptt_pkt_desc(buf, pos, type);
		if (!pkt_len)
			color_fprintf(stdout, color, " Bad packet!\n");

		pos += pkt_len;
		buf += pkt_len;
		len -= pkt_len;
	}
}

static void hisi_ptt_dump_event(struct hisi_ptt *ptt, unsigned char *buf,
				size_t len)
{
	printf(".\n");

	hisi_ptt_dump(ptt, buf, len);
}

static int hisi_ptt_process_event(struct perf_session *session __maybe_unused,
				  union perf_event *event __maybe_unused,
				  struct perf_sample *sample __maybe_unused,
				  struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static int hisi_ptt_process_auxtrace_event(struct perf_session *session,
					   union perf_event *event,
					   struct perf_tool *tool __maybe_unused)
{
	struct hisi_ptt *ptt = container_of(session->auxtrace, struct hisi_ptt,
					    auxtrace);
	struct auxtrace_buffer *buffer;
	off_t data_offset;
	int fd = perf_data__fd(session->data);
	int err;

	if (perf_data__is_pipe(session->data)) {
		data_offset = 0;
	} else {
		data_offset = lseek(fd, 0, SEEK_CUR);
		if (data_offset == -1)
			return -errno;
	}

	err = auxtrace_queues__add_event(&ptt->queues, session, event,
					 data_offset, &buffer);
	if (err)
		return err;

	if (dump_trace) {
		if (auxtrace_buffer__get_data(buffer, fd)) {
			hisi_ptt_dump_event(ptt, buffer->data, buffer->size);
			auxtrace_buffer__put_data(buffer);
		}
	}

	return 0;
}

static int hisi_ptt_flush(struct perf_session *session __maybe_unused,
			  struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static void hisi_ptt_free_events(struct perf_session *session)
{
	struct hisi_ptt *ptt = container_of(session->auxtrace, struct hisi_ptt,
					    auxtrace);
	struct auxtrace_queues *queues = &ptt->queues;
	unsigned int i;

	for (i = 0; i < queues->nr_queues; i++) {
		free(queues->queue_array[i].priv);
		queues->queue_array[i].priv = NULL;
	}
	auxtrace_queues__free(queues);
}

static void hisi_ptt_free(struct perf_session *session)
{
	struct hisi_ptt *ptt = container_of(session->auxtrace, struct hisi_ptt,
					    auxtrace);

	hisi_ptt_free_events(session);
	session->auxtrace = NULL;
	free(ptt);
}

static bool hisi_ptt_evsel_is_auxtrace(struct perf_session *session,
				       struct evsel *evsel)
{
	struct hisi_ptt *ptt = container_of(session->auxtrace, struct hisi_ptt, auxtrace);

	return evsel->core.attr.type == ptt->pmu_type;
}

static const char * const hisi_ptt_info_fmts[] = {
	[HISI_PTT_PMU_TYPE]		= "  PMU Type           %" PRId64 "\n",
};

static void hisi_ptt_print_info(__u64 *arr)
{
	if (!dump_trace)
		return;

	fprintf(stdout, hisi_ptt_info_fmts[HISI_PTT_PMU_TYPE], arr[HISI_PTT_PMU_TYPE]);
}

int hisi_ptt_process_auxtrace_info(union perf_event *event,
				   struct perf_session *session)
{
	struct perf_record_auxtrace_info *auxtrace_info = &event->auxtrace_info;
	struct hisi_ptt *ptt;
	int err;

	if (auxtrace_info->header.size < HISI_PTT_AUXTRACE_PRIV_SIZE +
				sizeof(struct perf_record_auxtrace_info))
		return -EINVAL;

	ptt = zalloc(sizeof(struct hisi_ptt));
	if (!ptt)
		return -ENOMEM;

	err = auxtrace_queues__init(&ptt->queues);
	if (err)
		goto err_free;

	ptt->session = session;
	ptt->machine = &session->machines.host; /* No kvm support */
	ptt->auxtrace_type = auxtrace_info->type;
	ptt->pmu_type = auxtrace_info->priv[HISI_PTT_PMU_TYPE];

	ptt->auxtrace.process_event = hisi_ptt_process_event;
	ptt->auxtrace.process_auxtrace_event = hisi_ptt_process_auxtrace_event;
	ptt->auxtrace.flush_events = hisi_ptt_flush;
	ptt->auxtrace.free_events = hisi_ptt_free_events;
	ptt->auxtrace.free = hisi_ptt_free;
	ptt->auxtrace.evsel_is_auxtrace = hisi_ptt_evsel_is_auxtrace;
	session->auxtrace = &ptt->auxtrace;

	hisi_ptt_print_info(&auxtrace_info->priv[0]);

	return 0;

err_free:
	free(ptt);
	return err;
}
