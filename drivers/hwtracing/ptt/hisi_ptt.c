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

#include "hisi_ptt.h"

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

static int hisi_ptt_init_filters(struct pci_dev *pdev, void *data)
{
	struct hisi_ptt_filter_desc *filter;
	struct hisi_ptt *hisi_ptt = data;
	struct list_head *target_list;

	target_list = pci_pcie_type(pdev) == PCI_EXP_TYPE_ROOT_PORT ?
		      &hisi_ptt->port_filters : &hisi_ptt->req_filters;

	filter = kzalloc(sizeof(*filter), GFP_KERNEL);
	if (!filter)
		return -ENOMEM;

	filter->pdev = pdev;
	list_add_tail(&filter->list, target_list);

	/* Update the available port mask */
	if (pci_pcie_type(pdev) == PCI_EXP_TYPE_ROOT_PORT)
		hisi_ptt->port_mask |= hisi_ptt_get_filter_val(pdev);

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

	bus = pci_find_bus(pci_domain_nr(pdev->bus), PCI_BUS_NUM(hisi_ptt->upper));
	if (bus)
		pci_walk_bus(bus, hisi_ptt_init_filters, hisi_ptt);

	hisi_ptt->trace_ctrl.default_cpu = cpumask_first(cpumask_of_node(dev_to_node(&pdev->dev)));
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

	hisi_ptt_init_ctrls(hisi_ptt);

	return 0;
}

void hisi_ptt_remove(struct pci_dev *pdev)
{
	struct hisi_ptt *hisi_ptt = pci_get_drvdata(pdev);

	if (hisi_ptt->trace_ctrl.status == HISI_PTT_TRACE_STATUS_ON)
		hisi_ptt_trace_end(hisi_ptt);

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
