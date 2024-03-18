/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#include "al_common.h"

#include <linux/clk.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/firmware.h>
#include <linux/of_reserved_mem.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "al_buf.h"
#include "al_codec_msg.h"

#define AL_BOOT_HEADER_OFFSET                           0
/* version format is in 12.12.8 for major.minor.patch */
#define AL_BOOT_VERSION(major, minor, patch)              (((major) << 20) | \
							   ((minor) << 12) | \
							   ((patch) << 0))

#define AL_CODEC_UID                                    0x0000
#define AL_CODEC_UID_ID                                 0x30AB6E51

#define AL_CODEC_RESET                                  0x0010
#define AL_CODEC_RESET_CMD                              BIT(0)

#define AL_CODEC_IRQ_MASK                               0x0014

#define AL_CODEC_IRQ_STATUS_CLEAR                       0x0018
#define AL_CODEC_IRQ_MCU_2_CPU                          BIT(30)

#define AL_CODEC_MCU_CLK                                0x0400
#define AL_CODEC_MCU_CLK_ENABLE                         BIT(0)
#define AL_CODEC_MCU_CLK_DISABLE                        0

#define AL_CODEC_MCU_RST                                0x0404
#define AL_CODEC_MCU_RST_ENABLE                         BIT(0)
#define AL_CODEC_MCU_RST_DISABLE                        0

#define AL_CODEC_MCU_IRQ                                0x040C
#define AL_CODEC_MCU_BOOT_ADDR_MSB                      0x0410
#define AL_CODEC_MCU_BOOT_ADDR_LSB                      0x0414
#define AL_CODEC_MCU_START_APB_MSB                      0x0418
#define AL_CODEC_MCU_START_APB_LSB                      0x041C
#define AL_CODEC_MCU_END_APB_MSB                        0x0420
#define AL_CODEC_MCU_END_APB_LSB                        0x0424
#define AL_CODEC_MCU_PERIPHERAL_ADDR_MSB                0x0428
#define AL_CODEC_MCU_PERIPHERAL_ADDR_LSB                0x042C
#define AL_CODEC_MCU_IP_INTERRUPT_MASK                  0x0440

#define AL_CODEC_INSTRUCTION_OFFSET_MSB                 0x0450
#define AL_CODEC_INSTRUCTION_OFFSET_LSB                 0x0454
#define AL_CODEC_DATA_OFFSET_MSB                        0x0458
#define AL_CODEC_DATA_OFFSET_LSB                        0x045C

#define MACHINE_ID_1                                    1
#define MACHINE_ID_2                                    2
#define MACHINE_ID_2_IP_OFFSET                          0x06000000
#define MACHINE_ID_2_APB_MASK                           0x07ffffff

#define common_dbg(__dev, fmt, ...) \
	dev_dbg(&__dev->pdev->dev, fmt, ## __VA_ARGS__)
#define common_info(__dev, fmt, ...) \
	dev_info(&__dev->pdev->dev, fmt, ## __VA_ARGS__)
#define common_warn(__dev, fmt, ...) \
	dev_warn(&__dev->pdev->dev, fmt, ## __VA_ARGS__)
#define common_err(__dev, fmt, ...) \
	dev_err(&__dev->pdev->dev, fmt, ## __VA_ARGS__)

struct mb_header {
	uint64_t start;
	uint64_t end;
} __attribute__((__packed__));

struct boot_header {
	/* info used by driver */
	uint32_t bh_version;
	uint32_t fw_version;
	char model[16];
	uint64_t vaddr_start;
	uint64_t vaddr_end;
	uint64_t boot_addr;
	struct mb_header h2m;
	struct mb_header m2h;
	uint64_t machine_id;
	/* fill by driver before fw boot */
	uint64_t ip_start;
	uint64_t ip_end;
	uint64_t mcu_clk_rate;
} __attribute__((__packed__));

static bool common_mem_check_machine_id_1(struct al_common_dev *dev,
					  dma_addr_t dma_handle,
					  size_t size)
{
	/* Full 64 bits memory space is available */

	return true;
}

static bool common_mem_check_machine_id_2(struct al_common_dev *dev,
					  dma_addr_t dma_handle,
					  size_t size)
{
	const uint64_t max_addr = 0x7f80000000ull;

	/* Check memory is inside [0:2^39 - 2G[ range */
	if (dma_handle > max_addr ||
	    dma_handle + size > max_addr)
		return false;

	return true;
}

static void *common_dma_alloc_coherent(struct al_common_dev *dev, size_t size,
				       dma_addr_t *dma_handle, gfp_t gfp)
{
	void *cpu_mem;

	BUG_ON(!dev->mem_check);
	cpu_mem = dma_alloc_coherent(&dev->pdev->dev, size, dma_handle, gfp);
	if (!cpu_mem || dev->mem_check(dev, *dma_handle, size))
		return cpu_mem;

	common_dbg(dev, "mem check failed for %pad of size %zu\n", dma_handle,
		   size);
	dma_free_coherent(&dev->pdev->dev, size, cpu_mem, *dma_handle);

	return NULL;
}

static inline u32 common_readl(struct al_common_dev *dev, int addr)
{
	return readl(dev->regs + addr);
}

static inline void common_writel(struct al_common_dev *dev, int addr, u32 d)
{
	writel(d, dev->regs + addr);
}

static void common_trigger_mcu_irq(void *arg)
{
	struct al_common_dev *dev = arg;

	common_writel(dev, AL_CODEC_MCU_IRQ, 1);
}

static void common_reset(struct al_common_dev *dev)
{
	/* reset ip */
	common_writel(dev, AL_CODEC_RESET, AL_CODEC_RESET_CMD);

	/* reset and stop mcu */
	common_writel(dev, AL_CODEC_MCU_RST, AL_CODEC_MCU_RST_ENABLE);
	common_writel(dev, AL_CODEC_MCU_CLK, AL_CODEC_MCU_CLK_DISABLE);
	common_writel(dev, AL_CODEC_MCU_IRQ, 0);
	common_writel(dev, AL_CODEC_MCU_IP_INTERRUPT_MASK, 0);
	msleep(10);
	common_writel(dev, AL_CODEC_MCU_RST, AL_CODEC_MCU_RST_DISABLE);
}

static int common_probe_check_and_setup_hw(struct al_common_dev *dev,
					   struct resource *res)
{
	unsigned int id;

	id = common_readl(dev, AL_CODEC_UID);
	if (id != AL_CODEC_UID_ID) {
		common_err(dev, "bad device id, expected 0x%08x, got 0x%08x\n",
			   AL_CODEC_UID_ID, id);
		return -ENODEV;
	}

	common_reset(dev);
	common_writel(dev, AL_CODEC_IRQ_MASK, AL_CODEC_IRQ_MCU_2_CPU);
	common_writel(dev, AL_CODEC_MCU_START_APB_MSB,
		      upper_32_bits(res->start));
	common_writel(dev, AL_CODEC_MCU_START_APB_LSB,
		      lower_32_bits(res->start));
	common_writel(dev, AL_CODEC_MCU_END_APB_MSB,
		      upper_32_bits(res->start + resource_size(res)));
	common_writel(dev, AL_CODEC_MCU_END_APB_LSB,
		      lower_32_bits(res->start + resource_size(res)));

	dev->regs_info = *res;

	return 0;
}

static void common_dma_buf_insert(struct al_common_dev *dev,
				  struct codec_dma_buf *buf)
{
	buf_insert(&dev->dma_lock, &dev->dma_buffers, buf);
}

static void common_dma_buf_remove(struct al_common_dev *dev,
				  struct codec_dma_buf *buf)
{
	buf_remove(&dev->dma_lock, buf);
}

static struct codec_dma_buf *common_dma_buf_lookup(struct al_common_dev *dev,
						   dma_addr_t dma_handle, bool remove)
{
	return buf_lookup(&dev->dma_lock, &dev->dma_buffers, dma_handle, remove);
}

static void common_dma_buf_cleanup(struct al_common_dev *dev)
{
	buf_cleanup_list(&dev->dma_lock, &dev->dma_buffers, &dev->pdev->dev);
}

static void handle_get_cma_req(struct al_common_dev *dev,
			       struct msg_itf_header *hdr)
{
	struct msg_itf_get_cma_reply_full reply;
	struct msg_itf_get_cma_req req;
	struct codec_dma_buf *buf;
	int ret;

	reply.reply.phyAddr = 0;
	ret = al_common_get_data(dev, (char *)&req, hdr->payload_len);
	if (ret) {
		common_err(dev, "Unable to get cma req\n");
		return;
	}

	buf = kmalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf)
		goto send_reply;

	buf->size = req.uSize;
	/* We don't need kernel side mapping */
	buf->is_kernel_mapped = dev->map_in_kernel;
	buf->cpu_mem = common_dma_alloc(dev, req.uSize, &buf->dma_handle,
					GFP_KERNEL);
	if (!buf->cpu_mem)
		goto send_reply;
	reply.reply.phyAddr = (uint64_t)buf->dma_handle;

	common_dma_buf_insert(dev, buf);

send_reply:
	reply.hdr.type = MSG_ITF_TYPE_GET_CMA_REPLY;
	/* both fields embed info need to finish request */
	reply.hdr.drv_client_hdl = hdr->drv_client_hdl;
	reply.hdr.drv_cmd_hdl = hdr->drv_cmd_hdl;
	reply.hdr.payload_len = sizeof(reply.reply);

	ret = al_common_send(dev, &reply.hdr);
	if (ret) {
		common_err(dev, "Unable to reply to cma alloc\n");
		common_dma_buf_remove(dev, buf);
	}
}

static void handle_put_cma_req(struct al_common_dev *dev,
			       struct msg_itf_header *hdr)
{
	struct msg_itf_put_cma_reply_full reply;
	struct msg_itf_put_cma_req req;
	struct codec_dma_buf *buf;
	int ret;

	reply.reply.ret = -1;
	ret = al_common_get_data(dev, (char *)&req, hdr->payload_len);
	if (ret) {
		common_err(dev, "Unable to put cma req\n");
		return;
	}

	buf = common_dma_buf_lookup(dev, req.phyAddr, true);
	common_dbg(dev, "req.phyAddr = %p => %p\n",
		   (void *)(long)req.phyAddr, buf);
	if (!buf) {
		common_err(dev, "Unable to get dma handle for %p\n",
			   (void *)(long)req.phyAddr);
		reply.reply.ret = -EINVAL;
		goto send_reply;
	}

	dma_free_coherent(&dev->pdev->dev, buf->size, buf->cpu_mem,
			  buf->dma_handle);
	reply.reply.ret = 0;

send_reply:
	reply.hdr.type = MSG_ITF_TYPE_PUT_CMA_REPLY;
	/* both fields embbed info need to hinish request */
	reply.hdr.drv_client_hdl = hdr->drv_client_hdl;
	reply.hdr.drv_cmd_hdl = hdr->drv_cmd_hdl;
	reply.hdr.payload_len = sizeof(reply.reply);

	ret = al_common_send(dev, &reply.hdr);
	if (ret)
		common_err(dev, "Unable to reply to cma free\n");
}

static void handle_write_req(struct al_common_dev *dev,
			     struct msg_itf_header *hdr)
{
	struct msg_itf_write_req *req;
	int ret;

	/* one more byte to be sure to have a zero terminated string */
	req = kzalloc(hdr->payload_len + 1, GFP_KERNEL);
	if (!req) {
		codec_msg_get_data(&dev->mb_m2h, NULL, hdr->payload_len);
		common_err(dev, "Unable to alloc memory\n");
		return;
	}

	ret = codec_msg_get_data(&dev->mb_m2h, (char *)req, hdr->payload_len);
	if (ret) {
		common_err(dev, "Unable to get request\n");
		kfree(req);
		return;
	}

	pr_cont("%s", (char *)(req + 1));

	if (req)
		kfree(req);
}

static void process_one_message(struct al_common_dev *dev,
				struct msg_itf_header *hdr)
{
	if (hdr->type == MSG_ITF_TYPE_GET_CMA_REQ)
		handle_get_cma_req(dev, hdr);
	else if (hdr->type == MSG_ITF_TYPE_PUT_CMA_REQ)
		handle_put_cma_req(dev, hdr);
	else if (hdr->type == MSG_ITF_TYPE_WRITE_REQ)
		handle_write_req(dev, hdr);
	else if (hdr->type == MSG_ITF_TYPE_FW_READY)
		complete(&dev->done);
	else
		dev->process_msg_cb(dev->cb_arg, hdr);
}

static void common_reply_handle(struct al_common_dev *dev)
{
	struct msg_itf_header hdr;
	int ret;

	while (1) {
		ret = codec_msg_get_header(&dev->mb_m2h, &hdr);
		if (ret)
			break;

		process_one_message(dev, &hdr);
	}
}

static irqreturn_t common_irq_handler(int irq, void *data)
{
	struct al_common_dev *dev = data;

	/* poll all messages */
	common_reply_handle(dev);

	return IRQ_HANDLED;
}

static irqreturn_t common_hardirq_handler(int irq, void *data)
{
	struct al_common_dev *dev = data;

	u32 irq_status = common_readl(dev, AL_CODEC_IRQ_STATUS_CLEAR);

	if (!irq_status)
		return IRQ_NONE;

	common_writel(dev, AL_CODEC_IRQ_STATUS_CLEAR, AL_CODEC_IRQ_MCU_2_CPU);

	return IRQ_WAKE_THREAD;
}

static uint64_t get_machine_boot_addr(struct al_common_dev *dev,
				      struct boot_header *bh)
{
	switch (bh->machine_id) {
	case MACHINE_ID_1:
		return bh->boot_addr;
	case MACHINE_ID_2:
		return bh->boot_addr - bh->vaddr_start + dev->fw_phys_addr;
	default:
		BUG();
	}
}

static int common_start_fw(struct al_common_dev *dev, struct boot_header *bh)
{
	uint64_t boot_addr = get_machine_boot_addr(dev, bh);

	common_writel(dev, AL_CODEC_MCU_BOOT_ADDR_MSB, upper_32_bits(boot_addr));
	common_writel(dev, AL_CODEC_MCU_BOOT_ADDR_LSB, lower_32_bits(boot_addr));
	common_dbg(dev, "boot_addr = %pad\n", &boot_addr);

	/* let's go */
	common_writel(dev, AL_CODEC_MCU_CLK, AL_CODEC_MCU_CLK_ENABLE);

	return !wait_for_completion_timeout(&dev->done, HZ);
}

static uint64_t get_machine_offset(struct al_common_dev *dev,
				   struct boot_header *bh)
{
	switch (bh->machine_id) {
	case MACHINE_ID_1:
		return dev->fw_phys_addr - bh->vaddr_start;
	case MACHINE_ID_2:
		return 0;
	default:
		BUG();
	}
}

static uint64_t common_get_perih_addr(struct al_common_dev *dev)
{
	struct resource *res;

	res = platform_get_resource_byname(dev->pdev, IORESOURCE_MEM, "apb");
	if (!res) {
		common_err(dev, "Unable fo find apb start address\n");
		return 0;
	}

	if (res->start & MACHINE_ID_2_APB_MASK) {
		common_err(dev, "apb start address is invalid\n");
		return 0;
	}

	return res->start;
}

static int common_alloc_and_setup_fw_memory(struct al_common_dev *dev,
					    struct boot_header *bh)
{
	uint64_t offset;

	dev->fw_cpu_mem = common_dma_alloc_coherent(dev, dev->fw_size,
						    &dev->fw_phys_addr,
						    GFP_KERNEL);
	if (!dev->fw_cpu_mem)
		return -ENOMEM;

	common_dbg(dev, "fw phys_addr = %pad\n", &dev->fw_phys_addr);
	common_dbg(dev, "fw virt_addr = 0x%p\n", dev->fw_cpu_mem);

	offset = get_machine_offset(dev, bh);
	common_dbg(dev, "offset       = 0x%016llx\n", offset);

	common_writel(dev, AL_CODEC_INSTRUCTION_OFFSET_LSB, lower_32_bits(offset));
	common_writel(dev, AL_CODEC_INSTRUCTION_OFFSET_MSB, upper_32_bits(offset));
	common_writel(dev, AL_CODEC_DATA_OFFSET_LSB, lower_32_bits(offset));
	common_writel(dev, AL_CODEC_DATA_OFFSET_MSB, upper_32_bits(offset));

	if (bh->machine_id == MACHINE_ID_2) {
		uint64_t periph_addr = common_get_perih_addr(dev);

		common_dbg(dev, "periph_addr = %pad\n", &periph_addr);
		common_writel(dev, AL_CODEC_MCU_PERIPHERAL_ADDR_MSB,
			      upper_32_bits(periph_addr));
		common_writel(dev, AL_CODEC_MCU_PERIPHERAL_ADDR_LSB,
			      lower_32_bits(periph_addr));
	}

	return 0;
}

static void common_fw_callback(const struct firmware *fw, void *context)
{
	struct al_common_dev *dev = context;
	struct boot_header bh;
	struct boot_header *bhw;
	int ret;

	if (!fw) {
		common_info(dev, "No fw :(\n");
		return;
	}

	memcpy(&bh, fw->data + AL_BOOT_HEADER_OFFSET, sizeof(bh));
	common_dbg(dev, "bh version 0x%08x\n", bh.bh_version);
	common_info(dev, "fw version 0x%08x\n", bh.fw_version);
	common_dbg(dev, "fw model = %s\n", bh.model);
	common_dbg(dev, "vaddress start = 0x%016llx\n", bh.vaddr_start);
	common_dbg(dev, "vaddress end   = 0x%016llx\n", bh.vaddr_end);
	common_dbg(dev, "boot address   = 0x%016llx\n", bh.boot_addr);
	common_info(dev, "machineid     = %lld\n", bh.machine_id);
	dev->fw_size = bh.vaddr_end - bh.vaddr_start;

	common_dbg(dev, "check header\n");
	if (bh.bh_version < AL_BOOT_VERSION(2, 0, 0) ||
	    bh.bh_version >= AL_BOOT_VERSION(3, 0, 0)) {
		common_err(dev, "bad boot header version\n");
		goto error_release;
	}

	switch (bh.machine_id) {
	case MACHINE_ID_1:
		dev->mem_check = common_mem_check_machine_id_1;
		break;
	case MACHINE_ID_2:
		dev->mem_check = common_mem_check_machine_id_2;
		if (!common_get_perih_addr(dev)) {
			common_err(dev, "machine_id_2 must define periph addr\n");
			goto error_release;
		}
		break;
	default:
		common_err(dev, "unsupported machine id %lld\n", bh.machine_id);
		goto error_release;
	}

	ret = common_alloc_and_setup_fw_memory(dev, &bh);
	if (ret) {
		common_err(dev, "out of memory %d\n", ret);
		goto error_release;
	}

	codec_mb_init(&dev->mb_h2m,
		      dev->fw_cpu_mem + bh.h2m.start - bh.vaddr_start,
		      MB_IFT_MAGIC_H2M, bh.h2m.end - bh.h2m.start);
	codec_mb_init(&dev->mb_m2h,
		      dev->fw_cpu_mem + bh.m2h.start - bh.vaddr_start,
		      MB_IFT_MAGIC_M2H, bh.m2h.end - bh.m2h.start);

	common_info(dev, "Copy %zu bytes of fw\n", fw->size);
	memcpy(dev->fw_cpu_mem, fw->data, fw->size);
	/* give fw information about registers location */
	bhw = dev->fw_cpu_mem + AL_BOOT_HEADER_OFFSET;
	if (bh.machine_id == MACHINE_ID_1)
		bhw->ip_start = dev->regs_info.start;
	else if (bh.machine_id == MACHINE_ID_2)
		bhw->ip_start = common_get_perih_addr(dev) + MACHINE_ID_2_IP_OFFSET;
	bhw->ip_end = bhw->ip_start + resource_size(&dev->regs_info);
	common_dbg(dev, "ip_start = 0x%016llx\n", bhw->ip_start);
	common_dbg(dev, "ip_end =   0x%016llx\n", bhw->ip_end);
	/* give fw information about mcu clock */
	if (dev->mcu_clk_rate)
		bhw->mcu_clk_rate = dev->mcu_clk_rate;
	common_info(dev, "mcu clock rate is %llu\n", bhw->mcu_clk_rate);
	release_firmware(fw);

	ret = common_start_fw(dev, &bh);
	if (ret) {
		common_err(dev, "fw start has failed\n");
		return;
	}
	common_info(dev, "mcu has boot successfully\n");

	dev->fw_ready_cb(dev->cb_arg);

	return;

error_release:
	release_firmware(fw);
}

static int common_firmware_request_nowait(struct al_common_dev *dev,
					  const char *fw_name)
{
	common_info(dev, "request fw %s\n", fw_name);

	return request_firmware_nowait(THIS_MODULE, true, fw_name,
				       &dev->pdev->dev, GFP_KERNEL, dev,
				       common_fw_callback);
}

static int common_setup_dma(struct al_common_dev *dev)
{
	int ret;

	/* setup dma memory mask */
	ret = dma_set_mask_and_coherent(&dev->pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		common_err(dev, "failed to set dma\n");
		return -EINVAL;
	}

	/* Try to use reserved memory if we got one */
	ret = of_reserved_mem_device_init(&dev->pdev->dev);
	if (ret && of_parse_phandle(dev->pdev->dev.of_node, "memory-region", 0))
		common_warn(dev, "Unable to got reserved memory, using cma\n");

	return 0;
}

int al_common_probe(struct platform_device *pdev, struct al_common_dev *dev,
		    const char *fw_name, bool map_in_kernel)
{
	struct resource *res;
	struct clk *clk;
	int irq;
	int ret;

	dev->pdev = pdev;
	dev->map_in_kernel = map_in_kernel;
	dev->mcu_clk_rate = 0;
	mutex_init(&dev->dma_lock);
	INIT_LIST_HEAD(&dev->dma_buffers);
	init_completion(&dev->done);

	clk = devm_clk_get(&pdev->dev, "mcu");
	if (IS_ERR(clk))
		common_warn(dev, "Unable to get mcu clock, will keep default value\n");
	else if (clk_prepare_enable(clk))
		common_warn(dev, "Unable to enable mcu clock, will keep default value\n");

	else
		dev->mcu_clk_rate = clk_get_rate(clk);

	/* setup dma memory */
	ret = common_setup_dma(dev);
	if (ret)
		return ret;

	/* Hw registers */
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "regs");
	if (!res) {
		common_err(dev, "regs resource missing from device tree\n");
		return -EINVAL;
	}
	dev->regs = devm_ioremap(&pdev->dev, res->start, resource_size(res));
	if (!dev->regs) {
		common_err(dev, "failed to map registers\n");
		return -ENOMEM;
	}

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		common_err(dev, "Failed to get IRQ\n");
		return -EINVAL;
	}

	ret = devm_request_threaded_irq(&pdev->dev, irq,
					common_hardirq_handler,
					common_irq_handler,
					IRQF_SHARED,
					dev_name(&pdev->dev), dev);
	if (ret) {
		common_err(dev, "Unable to register irq handler\n");
		return ret;
	}

	ret = common_probe_check_and_setup_hw(dev, res);
	if (ret) {
		common_err(dev, "Unable to setup hw\n");
		return ret;
	}

	/* ok so request the fw */
	ret = common_firmware_request_nowait(dev, fw_name);
	if (ret) {
		common_err(dev, "failed to request firmware\n");
		return ret;
	}

	return 0;
}

int al_common_remove(struct al_common_dev *dev)
{
	common_dma_buf_cleanup(dev);
	if (dev->fw_cpu_mem)
		dma_free_coherent(&dev->pdev->dev, dev->fw_size,
				  dev->fw_cpu_mem, dev->fw_phys_addr);

	/* reset device */
	common_reset(dev);

	return 0;
}

int al_common_get_header(struct al_common_dev *dev, struct msg_itf_header *hdr)
{
	return codec_msg_get_header(&dev->mb_m2h, hdr);
}

int al_common_get_data(struct al_common_dev *dev, char *data, int len)
{
	return codec_msg_get_data(&dev->mb_m2h, data, len);
}

int al_common_send(struct al_common_dev *dev, struct msg_itf_header *hdr)
{
	return codec_msg_send(&dev->mb_h2m, hdr, common_trigger_mcu_irq,
			      dev);
}

void *common_dma_alloc_noncoherent(struct al_common_dev *dev, size_t size,
		       dma_addr_t *dma_handle, gfp_t flag)
{
	void *cpu_mem;

	BUG_ON(!dev->mem_check);
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 10, 0)
	cpu_mem = dma_alloc_noncoherent(&dev->pdev->dev, size, dma_handle, DMA_BIDIRECTIONAL, flag);
#else
	cpu_mem = dma_alloc_attrs(&dev->pdev->dev, size, dma_handle, flag, DMA_ATTR_NON_CONSISTENT);
#endif
	if (!cpu_mem || dev->mem_check(dev, *dma_handle, size))
		return cpu_mem;

	common_dbg(dev, "mem check failed for %pad of size %zu\n", dma_handle,
		   size);
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 10, 0)
	dma_free_noncoherent(&dev->pdev->dev, size, cpu_mem, *dma_handle, DMA_BIDIRECTIONAL);
#else
	dma_free_attrs(&dev->pdev->dev, size, cpu_mem, *dma_handle, DMA_ATTR_NON_CONSISTENT);
#endif

	return NULL;
}

void *common_dma_alloc(struct al_common_dev *dev, size_t size,
		       dma_addr_t *dma_handle, gfp_t flag)
{
	void *cpu_mem;

	BUG_ON(!dev->mem_check);
	cpu_mem = dma_alloc_attrs(&dev->pdev->dev, size, dma_handle, flag,
				  dev->map_in_kernel ? 0 : DMA_ATTR_NO_KERNEL_MAPPING);
	if (!cpu_mem || dev->mem_check(dev, *dma_handle, size))
		return cpu_mem;

	common_dbg(dev, "mem check failed for %pad of size %zu\n", dma_handle,
		   size);
	dma_free_coherent(&dev->pdev->dev, size, cpu_mem, *dma_handle);

	return NULL;
}

int al_common_dma_buf_free(struct al_common_dev *dev, uint64_t phy_addr)
{
	struct codec_dma_buf *buf;

	buf = common_dma_buf_lookup(dev, phy_addr, true);
	if (!buf)
		return -EINVAL;

	dma_free_coherent(&dev->pdev->dev, buf->size, buf->cpu_mem,
			  buf->dma_handle);


	return 0;
}

int al_common_dma_buf_map(struct al_common_dev *dev, struct vm_area_struct *vma)
{
	return buf_map(&dev->dma_lock, &dev->dma_buffers, vma,
		       &dev->pdev->dev);
}
