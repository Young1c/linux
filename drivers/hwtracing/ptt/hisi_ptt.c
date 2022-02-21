// SPDX-License-Identifier: GPL-2.0
/*
 * Driver for HiSilicon PCIe tune and trace device
 *
 * Copyright (c) 2022 HiSilicon Technologies Co., Ltd.
 * Author: Yicong Yang <yangyicong@hisilicon.com>
 */

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/vmalloc.h>

#include "hisi_ptt.h"

static int hisi_ptt_wait_tuning_finish(struct hisi_ptt *hisi_ptt)
{
	u32 val;

	return readl_poll_timeout(hisi_ptt->iobase + HISI_PTT_TUNING_INT_STAT,
				  val, !(val & HISI_PTT_TUNING_INT_STAT_MASK),
				  HISI_PTT_WAIT_POLL_INTERVAL_US,
				  HISI_PTT_WAIT_TIMEOUT_US);
}

static int hisi_ptt_tune_data_get(struct hisi_ptt *hisi_ptt,
				  u32 event, u16 *data)
{
	u32 reg;

	reg = readl(hisi_ptt->iobase + HISI_PTT_TUNING_CTRL);
	reg &= ~(HISI_PTT_TUNING_CTRL_CODE | HISI_PTT_TUNING_CTRL_SUB);
	reg |= FIELD_PREP(HISI_PTT_TUNING_CTRL_CODE | HISI_PTT_TUNING_CTRL_SUB,
			  event);
	writel(reg, hisi_ptt->iobase + HISI_PTT_TUNING_CTRL);

	/* Write all 1 to indicates it's the read process */
	writel(~0UL, hisi_ptt->iobase + HISI_PTT_TUNING_DATA);

	if (hisi_ptt_wait_tuning_finish(hisi_ptt))
		return -ETIMEDOUT;

	reg = readl(hisi_ptt->iobase + HISI_PTT_TUNING_DATA);
	reg &= HISI_PTT_TUNING_DATA_VAL_MASK;
	*data = FIELD_GET(HISI_PTT_TUNING_DATA_VAL_MASK, reg);

	return 0;
}

static int hisi_ptt_tune_data_set(struct hisi_ptt *hisi_ptt,
				  u32 event, u16 data)
{
	u32 reg;

	reg = readl(hisi_ptt->iobase + HISI_PTT_TUNING_CTRL);
	reg &= ~(HISI_PTT_TUNING_CTRL_CODE | HISI_PTT_TUNING_CTRL_SUB);
	reg |= FIELD_PREP(HISI_PTT_TUNING_CTRL_CODE | HISI_PTT_TUNING_CTRL_SUB,
			  event);
	writel(reg, hisi_ptt->iobase + HISI_PTT_TUNING_CTRL);

	writel(FIELD_PREP(HISI_PTT_TUNING_DATA_VAL_MASK, data),
	       hisi_ptt->iobase + HISI_PTT_TUNING_DATA);

	if (hisi_ptt_wait_tuning_finish(hisi_ptt))
		return -ETIMEDOUT;

	return 0;
}

static ssize_t hisi_ptt_tune_attr_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct hisi_ptt *hisi_ptt = to_hisi_ptt(dev_get_drvdata(dev));
	struct dev_ext_attribute *ext_attr;
	struct hisi_ptt_tune_desc *desc;
	int ret;
	u16 val;

	ext_attr = container_of(attr, struct dev_ext_attribute, attr);
	desc = ext_attr->var;

	if (!mutex_trylock(&hisi_ptt->mutex))
		return -EBUSY;

	ret = hisi_ptt_tune_data_get(hisi_ptt, desc->event_code, &val);

	mutex_unlock(&hisi_ptt->mutex);
	return ret ? ret : sysfs_emit(buf, "%u\n", val);
}

static ssize_t hisi_ptt_tune_attr_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct hisi_ptt *hisi_ptt = to_hisi_ptt(dev_get_drvdata(dev));
	struct dev_ext_attribute *ext_attr;
	struct hisi_ptt_tune_desc *desc;
	int ret;
	u16 val;

	ext_attr = container_of(attr, struct dev_ext_attribute, attr);
	desc = ext_attr->var;

	if (kstrtou16(buf, 10, &val))
		return -EINVAL;

	if (!mutex_trylock(&hisi_ptt->mutex))
		return -EBUSY;

	ret = hisi_ptt_tune_data_set(hisi_ptt, desc->event_code, val);

	mutex_unlock(&hisi_ptt->mutex);
	return ret ? ret : count;
}

#define HISI_PTT_TUNE_ATTR(_name, _val, _show, _store)			\
	static struct hisi_ptt_tune_desc _name##_desc = {		\
		.name = #_name,						\
		.event_code = _val,					\
	};								\
	static struct dev_ext_attribute hisi_ptt_##_name##_attr = {	\
		.attr	= __ATTR(_name, 0600, _show, _store),		\
		.var	= &_name##_desc,				\
	}

#define HISI_PTT_TUNE_ATTR_COMMON(_name, _val)		\
	HISI_PTT_TUNE_ATTR(_name, _val,			\
			   hisi_ptt_tune_attr_show,	\
			   hisi_ptt_tune_attr_store)

/*
 * The value of the tuning event are composed of two parts: main event code in bit[0,15] and
 * subevent code in bit[16,23]. For example, qox_tx_cpl is a subevent of 'Tx path QoS control'
 * which for tuning the weight of Tx completion TLPs. See hisi_ptt.rst documentation for
 * more information.
 */
#define HISI_PTT_TUNE_QOS_TX_CPL				(0x4 | (3 << 16))
#define HISI_PTT_TUNE_QOS_TX_NP					(0x4 | (4 << 16))
#define HISI_PTT_TUNE_QOS_TX_P					(0x4 | (5 << 16))
#define HISI_PTT_TUNE_TX_PATH_IOB_RX_REQ_ALLOC_BUF_LEVEL	(0x5 | (6 << 16))
#define HISI_PTT_TUNE_TX_PATH_TX_REQ_ALLOC_BUF_LEVEL		(0x5 | (7 << 16))

HISI_PTT_TUNE_ATTR_COMMON(qos_tx_cpl,
			  HISI_PTT_TUNE_QOS_TX_CPL);
HISI_PTT_TUNE_ATTR_COMMON(qos_tx_np,
			  HISI_PTT_TUNE_QOS_TX_NP);
HISI_PTT_TUNE_ATTR_COMMON(qos_tx_p,
			  HISI_PTT_TUNE_QOS_TX_P);
HISI_PTT_TUNE_ATTR_COMMON(tx_path_iob_rx_req_alloc_buf_level,
			  HISI_PTT_TUNE_TX_PATH_IOB_RX_REQ_ALLOC_BUF_LEVEL);
HISI_PTT_TUNE_ATTR_COMMON(tx_path_tx_req_alloc_buf_level,
			  HISI_PTT_TUNE_TX_PATH_TX_REQ_ALLOC_BUF_LEVEL);

static struct attribute *hisi_ptt_tune_attrs[] = {
	&hisi_ptt_qos_tx_cpl_attr.attr.attr,
	&hisi_ptt_qos_tx_np_attr.attr.attr,
	&hisi_ptt_qos_tx_p_attr.attr.attr,
	&hisi_ptt_tx_path_iob_rx_req_alloc_buf_level_attr.attr.attr,
	&hisi_ptt_tx_path_tx_req_alloc_buf_level_attr.attr.attr,
	NULL,
};

static struct attribute_group hisi_ptt_tune_group = {
	.attrs	= hisi_ptt_tune_attrs,
	.name	= "tune",
};

static u16 hisi_ptt_get_filter_val(struct pci_dev *pdev)
{
	if (pci_pcie_type(pdev) == PCI_EXP_TYPE_ROOT_PORT)
		return BIT(HISI_PCIE_CORE_PORT_ID(PCI_SLOT(pdev->devfn)));

	return PCI_DEVID(pdev->bus->number, pdev->devfn);
}

static bool hisi_ptt_wait_trace_hw_idle(struct hisi_ptt *hisi_ptt)
{
	u32 val;

	return !readl_poll_timeout_atomic(hisi_ptt->iobase + HISI_PTT_TRACE_STS,
					  val, val & HISI_PTT_TRACE_IDLE,
					  HISI_PTT_WAIT_POLL_INTERVAL_US,
					  HISI_PTT_WAIT_TIMEOUT_US);
}

static bool hisi_ptt_wait_dma_reset_done(struct hisi_ptt *hisi_ptt)
{
	u32 val;

	return !readl_poll_timeout_atomic(hisi_ptt->iobase + HISI_PTT_TRACE_WR_STS,
					  val, !val, HISI_PTT_RESET_POLL_INTERVAL_US,
					  HISI_PTT_RESET_TIMEOUT_US);
}

static void hisi_ptt_free_trace_buf(struct hisi_ptt *hisi_ptt)
{
	struct hisi_ptt_trace_ctrl *ctrl = &hisi_ptt->trace_ctrl;
	struct device *dev = &hisi_ptt->pdev->dev;
	int i;

	if (!ctrl->trace_buf)
		return;

	for (i = 0; i < HISI_PTT_TRACE_BUF_CNT; i++) {
		if (ctrl->trace_buf[i].addr)
			dmam_free_coherent(dev, HISI_PTT_TRACE_BUF_SIZE,
					   ctrl->trace_buf[i].addr,
					   ctrl->trace_buf[i].dma);
	}

	devm_kfree(dev, ctrl->trace_buf);
	ctrl->trace_buf = NULL;
}

static int hisi_ptt_alloc_trace_buf(struct hisi_ptt *hisi_ptt)
{
	struct hisi_ptt_trace_ctrl *ctrl = &hisi_ptt->trace_ctrl;
	struct device *dev = &hisi_ptt->pdev->dev;
	int i;

	hisi_ptt->trace_ctrl.buf_index = 0;

	/* If the trace buffer has already been allocated, zero it. */
	if (ctrl->trace_buf) {
		for (i = 0; i < HISI_PTT_TRACE_BUF_CNT; i++)
			memset(ctrl->trace_buf[i].addr, 0, HISI_PTT_TRACE_BUF_SIZE);
		return 0;
	}

	ctrl->trace_buf = devm_kcalloc(dev, HISI_PTT_TRACE_BUF_CNT,
				       sizeof(struct hisi_ptt_dma_buffer), GFP_KERNEL);
	if (!ctrl->trace_buf)
		return -ENOMEM;

	for (i = 0; i < HISI_PTT_TRACE_BUF_CNT; ++i) {
		ctrl->trace_buf[i].addr = dmam_alloc_coherent(dev, HISI_PTT_TRACE_BUF_SIZE,
							     &ctrl->trace_buf[i].dma,
							     GFP_KERNEL);
		if (!ctrl->trace_buf[i].addr) {
			hisi_ptt_free_trace_buf(hisi_ptt);
			return -ENOMEM;
		}
	}

	return 0;
}

static void hisi_ptt_trace_end(struct hisi_ptt *hisi_ptt)
{
	writel(0, hisi_ptt->iobase + HISI_PTT_TRACE_CTRL);
	hisi_ptt->trace_ctrl.status = HISI_PTT_TRACE_STATUS_OFF;
}

static int hisi_ptt_trace_start(struct hisi_ptt *hisi_ptt)
{
	struct hisi_ptt_trace_ctrl *ctrl = &hisi_ptt->trace_ctrl;
	u32 val;
	int i;

	/* Check device idle before start trace */
	if (!hisi_ptt_wait_trace_hw_idle(hisi_ptt)) {
		pci_err(hisi_ptt->pdev, "Failed to start trace, the device is still busy.\n");
		return -EBUSY;
	}

	/* Reset the DMA before start tracing */
	val = readl(hisi_ptt->iobase + HISI_PTT_TRACE_CTRL);
	val |= HISI_PTT_TRACE_CTRL_RST;
	writel(val, hisi_ptt->iobase + HISI_PTT_TRACE_CTRL);

	hisi_ptt_wait_dma_reset_done(hisi_ptt);

	val = readl(hisi_ptt->iobase + HISI_PTT_TRACE_CTRL);
	val &= ~HISI_PTT_TRACE_CTRL_RST;
	writel(val, hisi_ptt->iobase + HISI_PTT_TRACE_CTRL);

	/* Clear the interrupt status */
	writel(HISI_PTT_TRACE_INT_STAT_MASK, hisi_ptt->iobase + HISI_PTT_TRACE_INT_STAT);
	writel(0, hisi_ptt->iobase + HISI_PTT_TRACE_INT_MASK);

	/* Configure the trace DMA buffer */
	for (i = 0; i < HISI_PTT_TRACE_BUF_CNT; i++) {
		writel(lower_32_bits(ctrl->trace_buf[i].dma),
		       hisi_ptt->iobase + HISI_PTT_TRACE_ADDR_BASE_LO_0 +
		       i * HISI_PTT_TRACE_ADDR_STRIDE);
		writel(upper_32_bits(ctrl->trace_buf[i].dma),
		       hisi_ptt->iobase + HISI_PTT_TRACE_ADDR_BASE_HI_0 +
		       i * HISI_PTT_TRACE_ADDR_STRIDE);
	}
	writel(HISI_PTT_TRACE_BUF_SIZE, hisi_ptt->iobase + HISI_PTT_TRACE_ADDR_SIZE);

	/* Set the trace control register */
	val = FIELD_PREP(HISI_PTT_TRACE_CTRL_TYPE_SEL, ctrl->type);
	val |= FIELD_PREP(HISI_PTT_TRACE_CTRL_RXTX_SEL, ctrl->direction);
	val |= FIELD_PREP(HISI_PTT_TRACE_CTRL_DATA_FORMAT, ctrl->format);
	val |= FIELD_PREP(HISI_PTT_TRACE_CTRL_TARGET_SEL, hisi_ptt->trace_ctrl.filter);
	if (!hisi_ptt->trace_ctrl.is_port)
		val |= HISI_PTT_TRACE_CTRL_FILTER_MODE;

	/* Start the Trace */
	val |= HISI_PTT_TRACE_CTRL_EN;
	writel(val, hisi_ptt->iobase + HISI_PTT_TRACE_CTRL);

	ctrl->status = HISI_PTT_TRACE_STATUS_ON;

	return 0;
}

static int hisi_ptt_update_aux(struct hisi_ptt *hisi_ptt, int index, bool stop)
{
	struct hisi_ptt_trace_ctrl *ctrl = &hisi_ptt->trace_ctrl;
	struct perf_output_handle *handle = &ctrl->handle;
	struct perf_event *event = handle->event;
	struct hisi_ptt_pmu_buf *buf;
	void *addr;

	buf = perf_get_aux(handle);
	if (!buf || !handle->size)
		return -EINVAL;

	addr = ctrl->trace_buf[ctrl->buf_index].addr;

	memcpy(buf->base + buf->pos, addr, HISI_PTT_TRACE_BUF_SIZE);
	memset(addr, 0, HISI_PTT_TRACE_BUF_SIZE);
	buf->pos += HISI_PTT_TRACE_BUF_SIZE;

	if (stop) {
		perf_aux_output_end(handle, buf->pos);
	} else if (buf->length - buf->pos < HISI_PTT_TRACE_BUF_SIZE) {
		perf_aux_output_skip(handle, buf->length - buf->pos);
		perf_aux_output_end(handle, buf->pos);

		buf = perf_aux_output_begin(handle, event);
		if (!buf)
			return -EINVAL;

		buf->pos = handle->head % buf->length;
		if (buf->length - buf->pos < HISI_PTT_TRACE_BUF_SIZE) {
			perf_aux_output_end(handle, 0);
			return -EINVAL;
		}
	}

	return 0;
}

static irqreturn_t hisi_ptt_isr(int irq, void *context)
{
	struct hisi_ptt *hisi_ptt = context;
	u32 status, buf_idx;

	status = readl(hisi_ptt->iobase + HISI_PTT_TRACE_INT_STAT);
	buf_idx = ffs(status) - 1;

	/* Clear the interrupt status of buffer @buf_idx */
	writel(status, hisi_ptt->iobase + HISI_PTT_TRACE_INT_STAT);

	/*
	 * Update the AUX buffer and cache the current buffer index,
	 * as we need to know this and save the data when the trace
	 * is ended out of the interrupt handler. End the trace
	 * if the updating fails.
	 */
	if (hisi_ptt_update_aux(hisi_ptt, buf_idx, false))
		hisi_ptt_trace_end(hisi_ptt);
	else
		hisi_ptt->trace_ctrl.buf_index = (buf_idx + 1) % HISI_PTT_TRACE_BUF_CNT;

	return IRQ_HANDLED;
}

static irqreturn_t hisi_ptt_irq(int irq, void *context)
{
	struct hisi_ptt *hisi_ptt = context;
	u32 status;

	status = readl(hisi_ptt->iobase + HISI_PTT_TRACE_INT_STAT);
	if (!(status & HISI_PTT_TRACE_INT_STAT_MASK))
		return IRQ_NONE;

	return IRQ_WAKE_THREAD;
}

static void hisi_ptt_irq_free_vectors(void *pdev)
{
	pci_free_irq_vectors(pdev);
}

static int hisi_ptt_register_irq(struct hisi_ptt *hisi_ptt)
{
	struct pci_dev *pdev = hisi_ptt->pdev;
	int ret;

	ret = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSI);
	if (ret < 0) {
		pci_err(pdev, "failed to allocate irq vector, ret = %d.\n", ret);
		return ret;
	}

	ret = devm_add_action_or_reset(&pdev->dev, hisi_ptt_irq_free_vectors, pdev);
	if (ret < 0)
		return ret;

	ret = devm_request_threaded_irq(&pdev->dev,
					pci_irq_vector(pdev, HISI_PTT_TRACE_DMA_IRQ),
					hisi_ptt_irq, hisi_ptt_isr, 0,
					DRV_NAME, hisi_ptt);
	if (ret) {
		pci_err(pdev, "failed to request irq %d, ret = %d.\n",
			pci_irq_vector(pdev, HISI_PTT_TRACE_DMA_IRQ), ret);
		return ret;
	}

	return 0;
}

static void hisi_ptt_update_filters(struct work_struct *work)
{
	struct delayed_work *delayed_work = to_delayed_work(work);
	struct hisi_ptt_filter_update_info info;
	struct hisi_ptt_filter_desc *filter;
	struct list_head *target_list;
	struct hisi_ptt *hisi_ptt;

	hisi_ptt = container_of(delayed_work, struct hisi_ptt, work);

	if (!mutex_trylock(&hisi_ptt->mutex)) {
		schedule_delayed_work(&hisi_ptt->work, HISI_PTT_WORK_DELAY_MS);
		return;
	}

	while (kfifo_get(&hisi_ptt->filter_update_kfifo, &info)) {
		bool is_port = pci_pcie_type(info.pdev) == PCI_EXP_TYPE_ROOT_PORT;
		u16 val = hisi_ptt_get_filter_val(info.pdev);

		target_list = is_port ? &hisi_ptt->port_filters : &hisi_ptt->req_filters;

		if (info.is_add) {
			filter = kzalloc(sizeof(*filter), GFP_KERNEL);
			if (!filter)
				continue;

			filter->pdev = info.pdev;
			list_add_tail(&filter->list, target_list);
		} else {
			list_for_each_entry(filter, target_list, list)
				if (hisi_ptt_get_filter_val(filter->pdev) == val) {
					list_del(&filter->list);
					kfree(filter);
					break;
				}
		}

		/* Update the available port mask */
		if (!is_port)
			continue;

		if (info.is_add)
			hisi_ptt->port_mask |= val;
		else
			hisi_ptt->port_mask &= ~val;
	}

	mutex_unlock(&hisi_ptt->mutex);
}

static void hisi_ptt_update_fifo_in(struct hisi_ptt *hisi_ptt,
				    struct hisi_ptt_filter_update_info *info)
{
	struct pci_dev *root_port = pcie_find_root_port(info->pdev);
	u32 port_devid;

	if (!root_port)
		return;

	port_devid = PCI_DEVID(root_port->bus->number, root_port->devfn);
	if (port_devid < hisi_ptt->lower ||
	    port_devid > hisi_ptt->upper)
		return;

	if (kfifo_in_spinlocked(&hisi_ptt->filter_update_kfifo, info, 1,
				&hisi_ptt->filter_update_lock))
		schedule_delayed_work(&hisi_ptt->work, 0);
	else
		pci_warn(hisi_ptt->pdev,
			 "filter update fifo overflow for target %s\n",
			 pci_name(info->pdev));
}

/*
 * A PCI bus notifier is used here for dynamically updating the filter
 * list.
 */
static int hisi_ptt_notifier_call(struct notifier_block *nb, unsigned long action,
				  void *data)
{
	struct hisi_ptt *hisi_ptt = container_of(nb, struct hisi_ptt, hisi_ptt_nb);
	struct hisi_ptt_filter_update_info info;
	struct device *dev = data;
	struct pci_dev *pdev = to_pci_dev(dev);

	info.pdev = pdev;

	switch (action) {
	case BUS_NOTIFY_ADD_DEVICE:
		info.is_add = true;
		break;
	case BUS_NOTIFY_DEL_DEVICE:
		info.is_add = false;
		break;
	default:
		return 0;
	}

	hisi_ptt_update_fifo_in(hisi_ptt, &info);

	return 0;
}

static int hisi_ptt_init_filters(struct pci_dev *pdev, void *data)
{
	struct hisi_ptt_filter_update_info info = {
		.pdev = pdev,
		.is_add = true,
	};
	struct hisi_ptt *hisi_ptt = data;

	hisi_ptt_update_fifo_in(hisi_ptt, &info);

	return 0;
}

static void hisi_ptt_release_filters(struct hisi_ptt *hisi_ptt)
{
	struct hisi_ptt_filter_desc *filter, *tfilter;

	list_for_each_entry_safe(filter, tfilter, &hisi_ptt->req_filters, list) {
		list_del(&filter->list);
		kfree(filter);
	}

	list_for_each_entry_safe(filter, tfilter, &hisi_ptt->port_filters, list) {
		list_del(&filter->list);
		kfree(filter);
	}
}

static void hisi_ptt_init_ctrls(struct hisi_ptt *hisi_ptt)
{
	struct pci_dev *pdev = hisi_ptt->pdev;
	struct pci_bus *bus;
	u32 reg;

	INIT_DELAYED_WORK(&hisi_ptt->work, hisi_ptt_update_filters);
	spin_lock_init(&hisi_ptt->filter_update_lock);
	INIT_KFIFO(hisi_ptt->filter_update_kfifo);
	INIT_LIST_HEAD(&hisi_ptt->port_filters);
	INIT_LIST_HEAD(&hisi_ptt->req_filters);

	/*
	 * The device range register provides the information about the
	 * root ports which the RCiEP can control and trace. The RCiEP
	 * and the root ports it support are on the same PCIe core, with
	 * same domain number but maybe different bus number. The device
	 * range register will tell us which root ports we can support,
	 * Bit[31:16] indicates the upper BDF numbers of the root port,
	 * while Bit[15:0] indicates the lower.
	 */
	reg = readl(hisi_ptt->iobase + HISI_PTT_DEVICE_RANGE);
	hisi_ptt->upper = FIELD_GET(HISI_PTT_DEVICE_RANGE_UPPER, reg);
	hisi_ptt->lower = FIELD_GET(HISI_PTT_DEVICE_RANGE_LOWER, reg);

	/*
	 * No need to fail if the bus is NULL here as the device
	 * maybe hotplugged after the PTT driver probe, in which
	 * case we can detect the event and update the list as
	 * we register a bus notifier for dynamically updating
	 * the filter list.
	 */
	bus = pci_find_bus(pci_domain_nr(pdev->bus), PCI_BUS_NUM(hisi_ptt->upper));
	if (bus)
		pci_walk_bus(bus, hisi_ptt_init_filters, hisi_ptt);

	hisi_ptt->trace_ctrl.default_cpu = cpumask_first(cpumask_of_node(dev_to_node(&pdev->dev)));
}

#define HISI_PTT_PMU_FILTER_IS_PORT	BIT(19)
#define HISI_PTT_PMU_FILTER_VAL_MASK	GENMASK(15, 0)
#define HISI_PTT_PMU_DIRECTION_MASK	GENMASK(23, 20)
#define HISI_PTT_PMU_TYPE_MASK		GENMASK(31, 24)
#define HISI_PTT_PMU_FORMAT_MASK	GENMASK(35, 32)

static ssize_t available_root_port_filters_show(struct device *dev,
						struct device_attribute *attr,
						char *buf)
{
	struct hisi_ptt *hisi_ptt = to_hisi_ptt(dev_get_drvdata(dev));
	struct hisi_ptt_filter_desc *filter;
	int pos = 0;

	mutex_lock(&hisi_ptt->mutex);
	if (list_empty(&hisi_ptt->port_filters)) {
		pos = sysfs_emit(buf, "\n");
		goto out;
	}

	list_for_each_entry(filter, &hisi_ptt->port_filters, list)
		pos += sysfs_emit_at(buf, pos, "%s	0x%05lx\n",
				     pci_name(filter->pdev),
				     hisi_ptt_get_filter_val(filter->pdev) |
				     HISI_PTT_PMU_FILTER_IS_PORT);

out:
	mutex_unlock(&hisi_ptt->mutex);
	return pos;
}
static DEVICE_ATTR_ADMIN_RO(available_root_port_filters);

static ssize_t available_requester_filters_show(struct device *dev,
						struct device_attribute *attr,
						char *buf)
{
	struct hisi_ptt *hisi_ptt = to_hisi_ptt(dev_get_drvdata(dev));
	struct hisi_ptt_filter_desc *filter;
	int pos = 0;

	mutex_lock(&hisi_ptt->mutex);
	if (list_empty(&hisi_ptt->req_filters)) {
		pos = sysfs_emit(buf, "\n");
		goto out;
	}

	list_for_each_entry(filter, &hisi_ptt->req_filters, list)
		pos += sysfs_emit_at(buf, pos, "%s	0x%05x\n",
				     pci_name(filter->pdev),
				     hisi_ptt_get_filter_val(filter->pdev));

out:
	mutex_unlock(&hisi_ptt->mutex);
	return pos;
}
static DEVICE_ATTR_ADMIN_RO(available_requester_filters);

PMU_FORMAT_ATTR(filter,		"config:0-19");
PMU_FORMAT_ATTR(direction,	"config:20-23");
PMU_FORMAT_ATTR(type,		"config:24-31");
PMU_FORMAT_ATTR(format,		"config:32-35");

static struct attribute *hisi_ptt_pmu_format_attrs[] = {
	&format_attr_filter.attr,
	&format_attr_direction.attr,
	&format_attr_type.attr,
	&format_attr_format.attr,
	NULL
};

static struct attribute_group hisi_ptt_pmu_format_group = {
	.name = "format",
	.attrs = hisi_ptt_pmu_format_attrs,
};

static struct attribute *hisi_ptt_pmu_filter_attrs[] = {
	&dev_attr_available_root_port_filters.attr,
	&dev_attr_available_requester_filters.attr,
	NULL
};

static struct attribute_group hisi_ptt_pmu_filter_group = {
	.attrs = hisi_ptt_pmu_filter_attrs,
};

static const struct attribute_group *hisi_ptt_pmu_groups[] = {
	&hisi_ptt_pmu_format_group,
	&hisi_ptt_pmu_filter_group,
	&hisi_ptt_tune_group,
	NULL
};

/*
 * Check whether the config is valid or not. Some configs are multi-selectable
 * and can be set simultaneously, while some are single selectable (onehot).
 * Use this function to check the non-onehot configs while
 * hisi_ptt_trace_valid_config_onehot() for the onehot ones.
 */
static int hisi_ptt_trace_valid_config(u32 val, const u32 *available_list, u32 list_size)
{
	int i;

	/* The non-onehot configs cannot be 0. */
	if (!val)
		return -EINVAL;

	/*
	 * Walk the available list and clear the valid bits of
	 * the config. If there is any resident bit after the
	 * walk then the config is invalid.
	 */
	for (i = 0; i < list_size; i++)
		val &= ~available_list[i];

	return val ? -EINVAL : 0;
}

static int hisi_ptt_trace_valid_config_onehot(u32 val, const u32 *available_list, u32 list_size)
{
	int i;

	for (i = 0; i < list_size; i++)
		if (val == available_list[i])
			return 0;

	return -EINVAL;
}

static int hisi_ptt_trace_init_filter(struct hisi_ptt *hisi_ptt, u64 config)
{
	unsigned long val, port_mask = hisi_ptt->port_mask;
	struct hisi_ptt_filter_desc *filter;
	int ret = -EINVAL;

	hisi_ptt->trace_ctrl.is_port = FIELD_GET(HISI_PTT_PMU_FILTER_IS_PORT, config);
	val = FIELD_GET(HISI_PTT_PMU_FILTER_VAL_MASK, config);

	/*
	 * Port filters are defined as bit mask. For port filters, check
	 * the bits in the @val are within the range of hisi_ptt->port_mask
	 * and whether it's empty or not, otherwise user has specified
	 * some unsupported root ports.
	 *
	 * For Requester ID filters, walk the available filter list to see
	 * whether we have one matched.
	 */
	if (!hisi_ptt->trace_ctrl.is_port) {
		list_for_each_entry(filter, &hisi_ptt->req_filters, list)
			if (val == hisi_ptt_get_filter_val(filter->pdev)) {
				ret = 0;
				break;
			}
	} else if (bitmap_subset(&val, &port_mask, BITS_PER_LONG)) {
		ret = 0;
	}

	if (ret)
		return ret;

	hisi_ptt->trace_ctrl.filter = val;
	return 0;
}

static int hisi_ptt_pmu_event_init(struct perf_event *event)
{
	/*
	 * The supported value of the direction parameter. See hisi_ptt.rst
	 * documentation for more details.
	 */
	static const u32 hisi_ptt_trace_available_direction[] = {
		0,
		1,
		2,
		3,
	};
	/* Different types can be set simultaneously */
	static const u32 hisi_ptt_trace_available_type[] = {
		1,	/* posted_request */
		2,	/* non-posted_request */
		4,	/* completion */
	};
	static const u32 hisi_ptt_trace_availble_format[] = {
		0,	/* 4DW */
		1,	/* 8DW */
	};
	struct hisi_ptt *hisi_ptt = to_hisi_ptt(event->pmu);
	struct hisi_ptt_trace_ctrl *ctrl = &hisi_ptt->trace_ctrl;
	int ret;
	u32 val;

	if (event->attr.type != hisi_ptt->hisi_ptt_pmu.type)
		return -ENOENT;

	mutex_lock(&hisi_ptt->mutex);

	ret = hisi_ptt_trace_init_filter(hisi_ptt, event->attr.config);
	if (ret < 0)
		goto out;

	val = FIELD_GET(HISI_PTT_PMU_DIRECTION_MASK, event->attr.config);
	ret = hisi_ptt_trace_valid_config_onehot(val, hisi_ptt_trace_available_direction,
						 ARRAY_SIZE(hisi_ptt_trace_available_direction));
	if (ret < 0)
		goto out;
	ctrl->direction = val;

	val = FIELD_GET(HISI_PTT_PMU_TYPE_MASK, event->attr.config);
	ret = hisi_ptt_trace_valid_config(val, hisi_ptt_trace_available_type,
					  ARRAY_SIZE(hisi_ptt_trace_available_type));
	if (ret < 0)
		goto out;
	ctrl->type = val;

	val = FIELD_GET(HISI_PTT_PMU_FORMAT_MASK, event->attr.config);
	ret = hisi_ptt_trace_valid_config_onehot(val, hisi_ptt_trace_availble_format,
						 ARRAY_SIZE(hisi_ptt_trace_availble_format));
	if (ret < 0)
		goto out;
	ctrl->format = val;

out:
	mutex_unlock(&hisi_ptt->mutex);
	return ret;
}

static void *hisi_ptt_pmu_setup_aux(struct perf_event *event, void **pages,
				    int nr_pages, bool overwrite)
{
	struct hisi_ptt_pmu_buf *buf;
	struct page **pagelist;
	int i;

	if (overwrite) {
		dev_warn(event->pmu->dev, "Overwrite mode is not supported\n");
		return NULL;
	}

	/* If the pages size less than buffers, we cannot start trace */
	if (nr_pages < HISI_PTT_TRACE_TOTAL_BUF_SIZE / PAGE_SIZE)
		return NULL;

	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return NULL;

	pagelist = kcalloc(nr_pages, sizeof(*pagelist), GFP_KERNEL);
	if (!pagelist) {
		kfree(buf);
		return NULL;
	}

	for (i = 0; i < nr_pages; i++)
		pagelist[i] = virt_to_page(pages[i]);

	buf->base = vmap(pagelist, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!buf->base) {
		kfree(pagelist);
		kfree(buf);
		return NULL;
	}

	buf->nr_pages = nr_pages;
	buf->length = nr_pages * PAGE_SIZE;
	buf->pos = 0;

	kfree(pagelist);
	return buf;
}

static void hisi_ptt_pmu_free_aux(void *aux)
{
	struct hisi_ptt_pmu_buf *buf = aux;

	vunmap(buf->base);
	kfree(buf);
}

static void hisi_ptt_pmu_start(struct perf_event *event, int flags)
{
	struct hisi_ptt *hisi_ptt = to_hisi_ptt(event->pmu);
	struct perf_output_handle *handle = &hisi_ptt->trace_ctrl.handle;
	struct hw_perf_event *hwc = &event->hw;
	struct hisi_ptt_pmu_buf *buf;
	int cpu = event->cpu;
	int ret;

	hwc->state = 0;
	mutex_lock(&hisi_ptt->mutex);
	if (hisi_ptt->trace_ctrl.status == HISI_PTT_TRACE_STATUS_ON) {
		pci_dbg(hisi_ptt->pdev, "trace has already started\n");
		goto stop;
	}

	if (cpu == -1)
		cpu = hisi_ptt->trace_ctrl.default_cpu;

	/*
	 * Handle the interrupt on the same cpu which starts the trace to avoid
	 * context mismatch. Otherwise we'll trigger the WARN from the perf
	 * core in event_function_local().
	 */
	WARN_ON(irq_set_affinity(pci_irq_vector(hisi_ptt->pdev, HISI_PTT_TRACE_DMA_IRQ),
				 cpumask_of(cpu)));

	ret = hisi_ptt_alloc_trace_buf(hisi_ptt);
	if (ret) {
		pci_dbg(hisi_ptt->pdev, "alloc trace buf failed, ret = %d\n", ret);
		goto stop;
	}

	buf = perf_aux_output_begin(handle, event);
	if (!buf) {
		pci_dbg(hisi_ptt->pdev, "aux output begin failed\n");
		goto stop;
	}

	buf->pos = handle->head % buf->length;

	ret = hisi_ptt_trace_start(hisi_ptt);
	if (ret) {
		pci_dbg(hisi_ptt->pdev, "trace start failed, ret = %d\n", ret);
		perf_aux_output_end(handle, 0);
		goto stop;
	}

	mutex_unlock(&hisi_ptt->mutex);
	return;
stop:
	event->hw.state |= PERF_HES_STOPPED;
	mutex_unlock(&hisi_ptt->mutex);
}

static void hisi_ptt_pmu_stop(struct perf_event *event, int flags)
{
	struct hisi_ptt *hisi_ptt = to_hisi_ptt(event->pmu);
	struct hw_perf_event *hwc = &event->hw;

	if (hwc->state & PERF_HES_STOPPED)
		return;

	mutex_lock(&hisi_ptt->mutex);
	if (hisi_ptt->trace_ctrl.status == HISI_PTT_TRACE_STATUS_ON) {
		hisi_ptt_trace_end(hisi_ptt);
		WARN(!hisi_ptt_wait_trace_hw_idle(hisi_ptt), "Device is still busy");
		hisi_ptt_update_aux(hisi_ptt, hisi_ptt->trace_ctrl.buf_index, true);
	}
	mutex_unlock(&hisi_ptt->mutex);

	hwc->state |= PERF_HES_STOPPED;
	perf_event_update_userpage(event);
	hwc->state |= PERF_HES_UPTODATE;
}

static int hisi_ptt_pmu_add(struct perf_event *event, int flags)
{
	struct hisi_ptt *hisi_ptt = to_hisi_ptt(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int cpu = event->cpu;

	/*
	 * Only allow the default cpu to add the event if user doesn't specify
	 * the cpus.
	 */
	if (cpu == -1 && smp_processor_id() != hisi_ptt->trace_ctrl.default_cpu)
		return 0;

	hwc->state = PERF_HES_STOPPED | PERF_HES_UPTODATE;

	if (flags & PERF_EF_START) {
		hisi_ptt_pmu_start(event, PERF_EF_RELOAD);
		if (hwc->state & PERF_HES_STOPPED)
			return -EINVAL;
	}

	return 0;
}

static void hisi_ptt_pmu_del(struct perf_event *event, int flags)
{
	hisi_ptt_pmu_stop(event, PERF_EF_UPDATE);
}

static int hisi_ptt_register_pmu(struct hisi_ptt *hisi_ptt)
{
	u16 core_id, sicl_id;
	char *pmu_name;
	u32 reg;

	hisi_ptt->hisi_ptt_pmu = (struct pmu) {
		.module		= THIS_MODULE,
		.capabilities	= PERF_PMU_CAP_EXCLUSIVE | PERF_PMU_CAP_ITRACE,
		.task_ctx_nr	= perf_sw_context,
		.attr_groups	= hisi_ptt_pmu_groups,
		.event_init	= hisi_ptt_pmu_event_init,
		.setup_aux	= hisi_ptt_pmu_setup_aux,
		.free_aux	= hisi_ptt_pmu_free_aux,
		.start		= hisi_ptt_pmu_start,
		.stop		= hisi_ptt_pmu_stop,
		.add		= hisi_ptt_pmu_add,
		.del		= hisi_ptt_pmu_del,
	};

	reg = readl(hisi_ptt->iobase + HISI_PTT_LOCATION);
	core_id = FIELD_GET(HISI_PTT_CORE_ID, reg);
	sicl_id = FIELD_GET(HISI_PTT_SICL_ID, reg);

	pmu_name = devm_kasprintf(&hisi_ptt->pdev->dev, GFP_KERNEL, "hisi_ptt%u_%u",
				  sicl_id, core_id);
	if (!pmu_name)
		return -ENOMEM;

	return perf_pmu_register(&hisi_ptt->hisi_ptt_pmu, pmu_name, -1);
}

static void hisi_ptt_unregister_filter_update_notifier(void *data)
{
	struct hisi_ptt *hisi_ptt = data;

	bus_unregister_notifier(&pci_bus_type, &hisi_ptt->hisi_ptt_nb);

	/* Cancel any work that has been queued */
	cancel_delayed_work_sync(&hisi_ptt->work);
}

/* Register the bus notifier for dynamically updating the filter list */
static int hisi_ptt_register_filter_update_notifier(struct hisi_ptt *hisi_ptt)
{
	int ret;

	hisi_ptt->hisi_ptt_nb.notifier_call = hisi_ptt_notifier_call;
	ret = bus_register_notifier(&pci_bus_type, &hisi_ptt->hisi_ptt_nb);
	if (ret)
		return ret;

	return devm_add_action_or_reset(&hisi_ptt->pdev->dev,
					hisi_ptt_unregister_filter_update_notifier,
					hisi_ptt);
}

/*
 * The DMA of PTT trace can only use direct mapping, due to some
 * hardware restriction. Check whether there is an IOMMU or the
 * policy of the IOMMU domain is passthrough, otherwise the trace
 * cannot work.
 *
 * The PTT device is supposed to behind the ARM SMMUv3, which
 * should have passthrough the device by a quirk.
 */
static int hisi_ptt_check_iommu_mapping(struct pci_dev *pdev)
{
	struct iommu_domain *iommu_domain;

	iommu_domain = iommu_get_domain_for_dev(&pdev->dev);
	if (!iommu_domain || iommu_domain->type == IOMMU_DOMAIN_IDENTITY)
		return 0;

	return -EOPNOTSUPP;
}

static int hisi_ptt_probe(struct pci_dev *pdev,
			  const struct pci_device_id *id)
{
	struct hisi_ptt *hisi_ptt;
	int ret;

	ret = hisi_ptt_check_iommu_mapping(pdev);
	if (ret) {
		pci_err(pdev, "cannot work with non-direct DMA mapping.\n");
		return ret;
	}

	hisi_ptt = devm_kzalloc(&pdev->dev, sizeof(*hisi_ptt), GFP_KERNEL);
	if (!hisi_ptt)
		return -ENOMEM;

	mutex_init(&hisi_ptt->mutex);
	hisi_ptt->pdev = pdev;
	pci_set_drvdata(pdev, hisi_ptt);

	ret = pcim_enable_device(pdev);
	if (ret) {
		pci_err(pdev, "failed to enable device, ret = %d.\n", ret);
		return ret;
	}

	ret = pcim_iomap_regions(pdev, BIT(2), DRV_NAME);
	if (ret) {
		pci_err(pdev, "failed to remap io memory, ret = %d.\n", ret);
		return ret;
	}

	hisi_ptt->iobase = pcim_iomap_table(pdev)[2];

	ret = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		pci_err(pdev, "failed to set 64 bit dma mask, ret = %d.\n", ret);
		return ret;
	}
	pci_set_master(pdev);

	ret = hisi_ptt_register_irq(hisi_ptt);
	if (ret)
		return ret;

	hisi_ptt_init_ctrls(hisi_ptt);

	ret = hisi_ptt_register_filter_update_notifier(hisi_ptt);
	if (ret)
		pci_warn(pdev, "failed to register filter update notifier, ret = %d", ret);

	ret = hisi_ptt_register_pmu(hisi_ptt);
	if (ret) {
		pci_err(pdev, "failed to register pmu device, ret = %d", ret);
		return ret;
	}

	return 0;
}

void hisi_ptt_remove(struct pci_dev *pdev)
{
	struct hisi_ptt *hisi_ptt = pci_get_drvdata(pdev);

	perf_pmu_unregister(&hisi_ptt->hisi_ptt_pmu);
	hisi_ptt_release_filters(hisi_ptt);
}

static const struct pci_device_id hisi_ptt_id_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, 0xa12e) },
	{ }
};
MODULE_DEVICE_TABLE(pci, hisi_ptt_id_tbl);

static struct pci_driver hisi_ptt_driver = {
	.name = DRV_NAME,
	.id_table = hisi_ptt_id_tbl,
	.probe = hisi_ptt_probe,
	.remove = hisi_ptt_remove,
};
module_pci_driver(hisi_ptt_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Yicong Yang <yangyicong@hisilicon.com>");
MODULE_DESCRIPTION("Driver for HiSilicon PCIe tune and trace device");
