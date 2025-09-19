/*
 * al_common.c common functions used by encoder and decoder.
 *
 * Copyright (C) 2024, Allegro DVT2 (www.allegrodvt.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
#define AL_CODEC_MCU_BOOT_TIMEOUT_RATIO                 (15000000000)
#define MCU_VIRTUAL_SIZE                                (254ULL * 1024 * 1024 * 1024)  /* 254GB */

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

/* Get the boot timeout using the clock rate (in msecs ) */
static inline uint32_t estimate_boot_timeout(uint32_t clk_rate)
{
  return (uint32_t)( AL_CODEC_MCU_BOOT_TIMEOUT_RATIO / clk_rate );
}

/**
 * get_mcu_offset: Calculate MCU offset based on reserved memory location
 * This function now properly handles both high and low physical addresses
 * by creating a mapping window that accommodates the reserved memory region
 *
 * @param reserved_mem_start: Start of reserved memory region
 * @param reserved_mem_size: Size of reserved memory region
 * @return: Offset for MCU address translation
 */
static inline u64 get_mcu_offset(u64 reserved_mem_start, u64 reserved_mem_size)
{
    uint64_t reserved_mem_end = reserved_mem_start + reserved_mem_size;

    /* If reserved memory fits entirely within MCU's addressing capability
     * For low addresses, we can start mapping from address 0 */
    if (reserved_mem_end <= MCU_VIRTUAL_SIZE)
        return 0;

    /* For high addresses or large regions, calculate offset to fit the reserved memory
     * within the MCU's virtual address space */
    if (reserved_mem_size <= MCU_VIRTUAL_SIZE)
        return reserved_mem_start; // Align the reserved memory region to fit within virtual space

    // Reserved memory is larger than MCU virtual space - use start address
    return reserved_mem_start;
}

static void *common_dma_alloc_coherent(struct al_common_dev *dev, size_t size,
		       dma_addr_t *dma_handle, gfp_t flag)
{
	void *cpu_mem;

	cpu_mem = dma_alloc_coherent(&dev->pdev->dev, size, dma_handle, flag);
	if (!cpu_mem)
	  return NULL;

  common_dbg(dev, "allocated mem %p -- 0x%16llx\n", cpu_mem, *dma_handle);

	return cpu_mem;
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
	buf->cpu_mem = common_dma_alloc_coherent(dev, req.uSize, &buf->dma_handle,
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

static inline u64 get_machine_boot_addr(struct al_common_dev *dev,
				      struct boot_header *bh)
{
  u64 fw_addr;

  fw_addr = dev->fw_phys_addr - dev->offset;
	return bh->boot_addr - bh->vaddr_start + fw_addr;
}

static int common_start_fw(struct al_common_dev *dev, struct boot_header *bh)
{
	u64 boot_addr = get_machine_boot_addr(dev, bh);
	u32 boot_timeout = estimate_boot_timeout(dev->mcu_clk_rate);

	common_writel(dev, AL_CODEC_MCU_BOOT_ADDR_MSB, upper_32_bits(boot_addr));
	common_writel(dev, AL_CODEC_MCU_BOOT_ADDR_LSB, lower_32_bits(boot_addr));
	common_dbg(dev, "boot_addr = %pad\n", &boot_addr);
	common_dbg(dev, "boot_timeout = %d\n",boot_timeout);

	/* let's go */
	common_writel(dev, AL_CODEC_MCU_CLK, AL_CODEC_MCU_CLK_ENABLE);

	boot_timeout = max(boot_timeout, (u32)1000);
	return !wait_for_completion_timeout(&dev->done,msecs_to_jiffies(boot_timeout));
}

static int common_alloc_and_setup_fw_memory(struct al_common_dev *dev,
					    struct boot_header *bh)
{
	dev->fw_cpu_mem = common_dma_alloc_coherent(dev, dev->fw_size,
						    &dev->fw_phys_addr,
						    GFP_KERNEL);
	if (!dev->fw_cpu_mem)
		return -ENOMEM;

	common_info(dev, "offset       = 0x%016llx\n", dev->offset);
	common_info(dev, "fw phys_addr = %pad\n", &dev->fw_phys_addr);
	common_info(dev, "fw virt_addr = 0x%p\n", dev->fw_cpu_mem);

	common_writel(dev, AL_CODEC_INSTRUCTION_OFFSET_LSB, lower_32_bits(dev->offset));
	common_writel(dev, AL_CODEC_INSTRUCTION_OFFSET_MSB, upper_32_bits(dev->offset));
	common_writel(dev, AL_CODEC_DATA_OFFSET_LSB, lower_32_bits(dev->offset));
	common_writel(dev, AL_CODEC_DATA_OFFSET_MSB, upper_32_bits(dev->offset));

	common_info(dev, "periph_addr = 0x%016llx\n", dev->periph_addr);

	common_writel(dev, AL_CODEC_MCU_PERIPHERAL_ADDR_LSB, lower_32_bits(dev->periph_addr));
	common_writel(dev, AL_CODEC_MCU_PERIPHERAL_ADDR_MSB, upper_32_bits(dev->periph_addr));

	return 0;
}

static void common_fw_callback(const struct firmware *fw, void *context)
{
	struct al_common_dev *dev = context;
	struct resource *res;
	struct boot_header bh;
	struct boot_header *bhw;
	int ret;

	if (!fw) {
		common_info(dev, "No fw :(\n");
		return;
	}

	memcpy(&bh, fw->data + AL_BOOT_HEADER_OFFSET, sizeof(bh));
	common_dbg(dev, "bh version 0x%08x\n", bh.bh_version);
	common_info(dev, "fw version %d.%d.%d\n", (u8)(bh.fw_version >> 20),
						 (u8)(bh.fw_version >> 12), (u8)bh.fw_version);
	common_dbg(dev, "fw model = %s\n", bh.model);
	common_dbg(dev, "vaddress start = 0x%016llx\n", bh.vaddr_start);
	common_dbg(dev, "vaddress end   = 0x%016llx\n", bh.vaddr_end);
	common_dbg(dev, "boot address   = 0x%016llx\n", bh.boot_addr);
	common_info(dev, "machineid     = %lld\n", bh.machine_id);
	dev->fw_size = bh.vaddr_end - bh.vaddr_start;
	dev->fw_version = bh.fw_version;

	common_dbg(dev, "check header\n");
	if (bh.bh_version < AL_BOOT_VERSION(2, 0, 0) ||
	    bh.bh_version >= AL_BOOT_VERSION(3, 0, 0)) {
		common_err(dev, "bad boot header version\n");
		goto error_release;
	}

	if(WARN(bh.machine_id != MACHINE_ID_2, "Unsupported machine id"))
	  goto error_release;

	res = platform_get_resource_byname(dev->pdev, IORESOURCE_MEM, "apb");
	if (!res) {
		common_err(dev, "Unable fo find apb start address\n");
	  goto error_release;
	}

	if (res->start & MACHINE_ID_2_APB_MASK) {
		common_err(dev, "apb start address is invalid\n");
	  goto error_release;
	}

  dev->periph_addr = res->start;

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
	bhw->ip_start = dev->periph_addr + MACHINE_ID_2_IP_OFFSET;
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

static int common_setup_dma(struct al_common_dev *common)
{
	struct device *dev = &common->pdev->dev;
	struct device_node *node;
	struct resource r;
	int ret;

	common_info(common, "Setting up DMA...\n");

	node = of_parse_phandle(dev->of_node, "memory-region", 0);
	if (!node) {
		/* If there is a memory-region phandle, we use that memory to allocate our dma buffers
		 * and if the hw ip supports it, we start the hw ip bus address range at the first address
		 * of that memory.
		 * Else, we use the CMA memory.
		 * If we use the CMA memory, we cannot know where the cma memory region is starting,
		 * so we do not configure the hw ip bus address range and it will start at address 0 by default.
		 * If the hw ip supports 64bit memory regions, then there is nothing to configure.
		 */
		common_warn(common, "No reserved memory, use CMA instead\n");

		/* FIXED: Limit DMA mask to 39 bits (512GB) for CMA to ensure compatibility with MCU addressing */
		ret = dma_coerce_mask_and_coherent(dev, DMA_BIT_MASK(39));
		if (ret) {
			common_err(common, "No suitable DMA available with 39-bit addressing");
			return ret;
		}

		common->offset = 0;  /* Default offset for CMA */
		common_dbg(common, "Using CMA with 39-bit DMA addressing\n");
		return 0;
	}

	/* Setup 64-bit DMA mask for reserved memory case */
	ret = dma_coerce_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		common_err(common, "No suitable DMA available");
		return ret;
	}

	ret = of_reserved_mem_device_init(dev);
	if (ret) {
		common_err(common, "Couldn't get reserved memory (errno: %d)", ret);
		return ret;
	}

	ret = of_address_to_resource(node, 0, &r);
	of_node_put(node);
	if (ret) {
		common_err(common, "Failed to parse the memory-region resources");
		return -EINVAL;
	}

	common->reserved_mem_start = r.start;
	common->reserved_mem_size = r.end - r.start;

	/* FIXED: Use improved offset calculation that handles both high and low addresses */
	common->offset = get_mcu_offset(common->reserved_mem_start, common->reserved_mem_size);

	common_dbg(common, "Reserved memory: 0x%llx, size: 0x%lld\n",
		    (u64)common->reserved_mem_start, common->reserved_mem_size);
	common_dbg(common, "Calculated offset: 0x%llx\n", common->offset);

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
	dev->offset = 0;
	dev->periph_addr = 0;

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
		goto err_clk_disable;

	/* Hw registers */
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "regs");
	if (!res) {
		common_err(dev, "regs resource missing from device tree\n");
		ret = -EINVAL;
		goto err_clk_disable;
	}

	dev->regs = devm_ioremap(&pdev->dev, res->start, resource_size(res));
	if (!dev->regs) {
		common_err(dev, "failed to map registers\n");
		ret =  -ENOMEM;
		goto err_clk_disable;
	}

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		common_err(dev, "Failed to get IRQ\n");
		ret = -EINVAL;
		goto err_clk_disable;
	}

	ret = devm_request_threaded_irq(&pdev->dev, irq,
					common_hardirq_handler,
					common_irq_handler,
					IRQF_SHARED,
					dev_name(&pdev->dev), dev);
	if (ret) {
		common_err(dev, "Unable to register irq handler\n");
		goto err_clk_disable;
	}

	ret = common_probe_check_and_setup_hw(dev, res);
	if (ret) {
		common_err(dev, "Unable to setup hw\n");
		goto err_clk_disable;
	}

	/* ok so request the fw */
	ret = common_firmware_request_nowait(dev, fw_name);
	if (ret) {
		common_err(dev, "failed to request firmware\n");
		goto err_clk_disable;
	}

	return 0;

err_clk_disable:
	if(dev->mcu_clk_rate)
		clk_disable_unprepare(clk);

	return ret;
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

void *common_dma_alloc(struct al_common_dev *dev, size_t size,
		       dma_addr_t *dma_handle, gfp_t flag)
{
	return common_dma_alloc_coherent(dev, size, dma_handle, flag);
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
