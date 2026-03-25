/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#include <asm/byteorder.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>
#include <linux/slab.h>

#include "al_common.h"
#include "al_buf.h"
#include "al_codec_msg.h"

#define AL_BOOT_HEADER_OFFSET 0

/* Version format is 12.12.8 for major.minor.patch */
#define AL_BOOT_VERSION(major, minor, patch) \
	(((major) << 20) | ((minor) << 12) | ((patch) << 0))

/* IP Registers */
#define AL_CODEC_UID 0x0000
#define AL_CODEC_UID_ID 0x30AB6E51
#define AL_CODEC_RESET 0x0010
#define AL_CODEC_IRQ_MASK 0x0014
#define AL_CODEC_IRQ_STATUS_CLEAR 0x0018

/* MCU Registers (relative to MCU base) */
#define AL_CODEC_MCU_CLK 0x0400
#define AL_CODEC_MCU_RST 0x0404
#define AL_CODEC_MCU_IRQ 0x040C
#define AL_CODEC_MCU_BOOT_ADDR_MSB 0x0410
#define AL_CODEC_MCU_BOOT_ADDR_LSB 0x0414

/* NOTE: Registers 0x418, 0x41C, 0x420, 0x424 are used by mailbox */
#define AL_CODEC_MCU_PERIPHERAL_ADDR_MSB 0x0428
#define AL_CODEC_MCU_PERIPHERAL_ADDR_LSB 0x042C
#define AL_CODEC_MCU_IP_INTERRUPT_MASK 0x0440
#define AL_CODEC_INSTRUCTION_OFFSET_MSB 0x0450
#define AL_CODEC_INSTRUCTION_OFFSET_LSB 0x0454
#define AL_CODEC_DATA_OFFSET_MSB 0x0458
#define AL_CODEC_DATA_OFFSET_LSB 0x045C

/* Register configuration */
#define AL_CODEC_IRQ_MCU_2_CPU BIT(30)
#define AL_CODEC_REG_ENABLE BIT(0)
#define AL_CODEC_REG_DISABLE 0

/* Machine IDs */
#define MACHINE_ID_1 1
#define MACHINE_ID_2 2
#define MACHINE_ID_2_IP_OFFSET 0x06000000
#define MACHINE_ID_2_APB_MASK 0x07ffffff

/* Mailbox interface */
#define MAILBOX_IFT_VERSION 0x00010000
#define MAILBOX_IFT_MAGIC_H2M 0xabcd1230
#define MAILBOX_IFT_MAGIC_M2H 0xabcd1231

/* For inter-comm mailboxes */
#define IMAILBOX_SIZE 4096 /* 4KB size */

/* Debug macros */
#define common_dbg(__dev, fmt, ...) \
	dev_dbg(&__dev->pdev->dev, fmt, ##__VA_ARGS__)
#define common_info(__dev, fmt, ...) \
	dev_info(&__dev->pdev->dev, fmt, ##__VA_ARGS__)
#define common_warn(__dev, fmt, ...) \
	dev_warn(&__dev->pdev->dev, fmt, ##__VA_ARGS__)
#define common_err(__dev, fmt, ...) \
	dev_err(&__dev->pdev->dev, fmt, ##__VA_ARGS__)

/* Mailbox header in firmware */
struct mb_header {
	uint32_t magic;
	uint64_t start;
	uint64_t end;
} __packed;

/* Boot header extension for inter-MCU mailboxes */
struct imb_boot {
	uint64_t imailbox_addrs[AL_MAX_MCUS]; /* Physical addresses */
	uint32_t num_mcus;
	uint32_t reserved;
} __packed;

/* Boot header structure in firmware */
struct boot_header {
	/* Info used by driver */
	uint32_t bh_version;
	uint32_t fw_version;
	char model[16];
	uint64_t vaddr_start;
	uint64_t vaddr_end;
	uint64_t boot_addr;
	struct mb_header h2m;
	struct mb_header m2h;
	uint64_t machine_id;

	/* Filled by driver before fw boot */
	uint64_t ip_start;
	uint64_t ip_end;
	uint64_t mcu_clk_rate;

	uint32_t mb_version;
	uint8_t mcu_id;
	struct imb_boot imb_info;
} __packed;

/*******************************************************************************
 * HELPER FUNCTIONS
 ******************************************************************************/
static bool process_mcu_messages(struct al_mcu_instance *mcu);

/* Read/Write operations for MCU registers */
static inline u32 common_readl(struct al_mcu_instance *mcu, u32 offset)
{
	return readl(mcu->regs + offset);
}

static inline void common_writel(struct al_mcu_instance *mcu, u32 offset,
				 u32 val)
{
	writel(val, mcu->regs + offset);
}

/* Read/Write operations for device-level registers */
static inline u32 dev_readl(struct al_common_dev *dev, u32 offset)
{
	return readl(dev->regs + offset);
}

static inline void dev_writel(struct al_common_dev *dev, u32 offset, u32 val)
{
	writel(val, dev->regs + offset);
}

/* Trigger MCU interrupt */
static void common_trigger_mcu_irq(void *arg)
{
	struct al_mcu_instance *mcu = arg;
	common_writel(mcu, AL_CODEC_MCU_IRQ, AL_CODEC_REG_ENABLE);
}

/**
 * al_common_get_header - Get message header from master MCU
 * @dev: Device structure
 * @hdr: Message header output
 *
 * Returns: 0 on success, negative error code on failure
 */
int al_common_get_header(struct al_common_dev *dev, struct msg_itf_header *hdr)
{
	struct al_mcu_instance *mcu = &dev->mcus[0];
	return codec_msg_get_header(&mcu->mb_m2h, hdr);
}
/**
 * al_mcu_get_data - Get message data from specific MCU
 * @mcu: the MCU to get data from
 * @data: Data buffer
 * @len: Length to read
 *
 * Returns: 0 on success, negative error code on failure
 */
static inline int al_mcu_get_data(struct al_mcu_instance *mcu, char *data,
				  int len)
{
	return codec_msg_get_data(&mcu->mb_m2h, data, len);
}

/**
 * al_mcu_msg_send - Send message to specific MCU
 * @mcu: MCU to send data to
 * @hdr: Message header
 *
 * Returns: 0 on success, negative error code on failure
 */
static inline int al_mcu_msg_send(struct al_mcu_instance *mcu,
				  struct msg_itf_header *hdr)
{
	return codec_msg_send(&mcu->mb_h2m, hdr, common_trigger_mcu_irq, mcu);
}

/**
 * al_common_get_data - Get message data from master MCU
 * @dev: Device structure
 * @data: Data buffer
 * @len: Length to read
 *
 * Returns: 0 on success, negative error code on failure
 */
int al_common_get_data(struct al_common_dev *dev, char *data, int len)
{
	return al_mcu_get_data(&dev->mcus[0], data, len);
}

/**
 * al_common_send - Send message to active MCU
 * @dev: Device structure
 * @hdr: Message header
 *
 * Returns: 0 on success, negative error code on failure
 */
int al_common_send(struct al_common_dev *dev, struct msg_itf_header *hdr)
{
	return al_mcu_msg_send(&dev->mcus[0], hdr);
}

/* DMA allocation wrapper */
static void *common_dma_alloc_coherent(struct al_common_dev *dev, size_t size,
				       dma_addr_t *dma_handle, gfp_t gfp)
{
	void *cpu_mem;

	cpu_mem = dma_alloc_coherent(&dev->pdev->dev, size, dma_handle, gfp);
	if (!cpu_mem) {
		common_err(dev, "Failed to allocate %zu bytes of DMA memory\n",
			   size);
		return ERR_PTR(-ENOMEM);
	}

	common_dbg(dev,
		   "Allocated DMA: cpu_mem=%p, dma_handle=%pad, size=%zu\n",
		   cpu_mem, dma_handle, size);
	return cpu_mem;
}

/* Reset a single MCU */
static void common_reset_mcu(struct al_mcu_instance *mcu)
{
	/* Reset the IP */
	common_writel(mcu, AL_CODEC_RESET, AL_CODEC_REG_ENABLE);

	common_writel(mcu, AL_CODEC_MCU_RST, AL_CODEC_REG_ENABLE);
	common_writel(mcu, AL_CODEC_MCU_CLK, AL_CODEC_REG_DISABLE);
	common_writel(mcu, AL_CODEC_MCU_IRQ, AL_CODEC_REG_DISABLE);
	common_writel(mcu, AL_CODEC_MCU_IP_INTERRUPT_MASK,
		      AL_CODEC_REG_DISABLE);
	msleep(10);
	common_writel(mcu, AL_CODEC_MCU_RST, AL_CODEC_REG_DISABLE);
}

/* Reset device and all MCUs */
static inline void common_reset(struct al_common_dev *dev)
{
	int i;

	/* Reset all MCUs */
	for (i = 0; i < dev->num_mcus; i++)
		common_reset_mcu(&dev->mcus[i]);
}

/*******************************************************************************
 * FIRMWARE VALIDATION AND COPY FUNCTIONS
 ******************************************************************************/

/**
 * validate_firmware - Validate firmware before loading
 * @dev: Device structure
 * @fw: Firmware data
 * @bh: Output boot header structure
 *
 * This function parses the boot header from the firmware and validates it
 * by checking the machine_id and version fields.
 *
 * Returns: true if firmware is valid, false otherwise
 */
static bool validate_firmware(struct al_common_dev *dev,
			      const struct firmware *fw, struct boot_header *bh)
{
	const struct boot_header *fw_bh;

	if (!fw || !fw->data || fw->size < sizeof(struct boot_header)) {
		common_err(dev, "Firmware too small: %zu bytes\n", fw->size);
		return false;
	}

	/* Parse boot header from firmware */
	fw_bh = (const struct boot_header *)(fw->data + AL_BOOT_HEADER_OFFSET);

	/* Copy boot header with proper endianness conversion */
	bh->bh_version = le32_to_cpu(fw_bh->bh_version);
	bh->fw_version = le32_to_cpu(fw_bh->fw_version);
	bh->mb_version = le32_to_cpu(fw_bh->mb_version);
	memcpy(bh->model, fw_bh->model, sizeof(bh->model));
	bh->vaddr_start = le64_to_cpu(fw_bh->vaddr_start);
	bh->vaddr_end = le64_to_cpu(fw_bh->vaddr_end);
	bh->boot_addr = le64_to_cpu(fw_bh->boot_addr);

	/* Mailbox headers */
	bh->h2m.magic = le32_to_cpu(fw_bh->h2m.magic);
	bh->h2m.start = le64_to_cpu(fw_bh->h2m.start);
	bh->h2m.end = le64_to_cpu(fw_bh->h2m.end);
	bh->m2h.magic = le32_to_cpu(fw_bh->m2h.magic);
	bh->m2h.start = le64_to_cpu(fw_bh->m2h.start);
	bh->m2h.end = le64_to_cpu(fw_bh->m2h.end);

	bh->machine_id = le64_to_cpu(fw_bh->machine_id);

	/* Validate machine ID */
	if (bh->machine_id != MACHINE_ID_1 && bh->machine_id != MACHINE_ID_2) {
		common_err(dev, "Invalid machine_id: %llu\n", bh->machine_id);
		return false;
	}

	/* Validate mailbox magic numbers */
	if (bh->h2m.magic != MAILBOX_IFT_MAGIC_H2M) {
		common_err(dev, "Invalid H2M mailbox magic: 0x%08x\n",
			   bh->h2m.magic);
		return false;
	}

	if (bh->m2h.magic != MAILBOX_IFT_MAGIC_M2H) {
		common_err(dev, "Invalid M2H mailbox magic: 0x%08x\n",
			   bh->m2h.magic);
		return false;
	}

	common_dbg(
		dev,
		"Firmware validated: model=%s, version=0x%08x, machine_id=%llu\n",
		bh->model, bh->fw_version, bh->machine_id);

	return true;
}

/**
 * copy_firmware_to_mcu - Copy firmware to MCU DMA memory
 * @dev: Device structure
 * @mcu: MCU instance
 * @fw: Firmware data
 * @bh: Boot header (will be updated with runtime data)
 *
 * This function copies the firmware to the allocated DMA memory for the MCU,
 * using proper endianness conversion (le32_to_cpu) and filling in the
 * boot header with runtime information.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int copy_firmware_to_mcu(struct al_common_dev *dev,
				struct al_mcu_instance *mcu,
				const struct firmware *fw,
				struct boot_header *bh)
{
	const u32 *src;
	u32 *dst;
	size_t i, num_words;
	struct boot_header *bh_dst;
	u64 periph_addr;

	if (!mcu->fw_cpu_mem) {
		common_err(dev, "MCU %d: No DMA memory allocated\n",
			   mcu->mcu_id);
		return -ENOMEM;
	}

	/* Copy firmware data word by word with endianness conversion */
	src = (const u32 *)fw->data;
	dst = (u32 *)mcu->fw_cpu_mem;
	num_words = fw->size / sizeof(u32);

	for (i = 0; i < num_words; i++)
		dst[i] = le32_to_cpu(src[i]);

	/* Handle remaining bytes if firmware size is not word-aligned */
	if (fw->size % sizeof(u32)) {
		size_t remaining = fw->size % sizeof(u32);
		u8 *dst_byte = (u8 *)&dst[num_words];
		const u8 *src_byte = (const u8 *)&src[num_words];

		for (i = 0; i < remaining; i++)
			dst_byte[i] = src_byte[i];
	}

	/* Update boot header in firmware copy with runtime data */
	bh_dst = (struct boot_header *)((u8 *)mcu->fw_cpu_mem +
					AL_BOOT_HEADER_OFFSET);

	/* Calculate peripheral address based on machine ID */
	if (bh->machine_id == MACHINE_ID_2) {
		periph_addr = (mcu->apb_addr) + MACHINE_ID_2_IP_OFFSET;
	} else {
		periph_addr = dev->regs_info.start;
	}

	/* Fill the mcu index */
	bh_dst->mcu_id = mcu->mcu_id;
	bh_dst->imb_info.num_mcus = dev->num_mcus;

	/* Fill runtime data in boot header */
	bh_dst->ip_start = cpu_to_le64(periph_addr);
	bh_dst->ip_end =
		cpu_to_le64(periph_addr + resource_size(&dev->regs_info));
	bh_dst->mcu_clk_rate = cpu_to_le64(mcu->mcu_clk_rate);

	if (dev->num_mcus > 1) {
		for (i = 0; i < dev->num_mcus; i++)
			bh_dst->imb_info.imailbox_addrs[i] =
				dev->mcus[i].imb.phys;
	}

	/* Ensure data is written to memory */
	wmb();

	common_dbg(
		dev,
		"MCU %d: Firmware copied, ip_start=0x%llx, ip_end=0x%llx, clk_rate=%lu\n",
		mcu->mcu_id, bh_dst->ip_start, bh_dst->ip_end,
		mcu->mcu_clk_rate);

	/* Store firmware version */
	mcu->fw_version = bh->fw_version;
	dev->fw_version = bh->fw_version;

	return 0;
}

/*******************************************************************************
 * MCU INITIALIZATION AND STARTUP
 ******************************************************************************/

/**
 * init_mcu_mailbox - Initialize mailbox for an MCU
 * @dev: Device structure
 * @mcu: MCU instance
 * @bh: Boot header with mailbox configuration
 *
 * Returns: 0 on success, negative error code on failure
 */
static int init_mcu_mailbox(struct al_common_dev *dev,
			    struct al_mcu_instance *mcu,
			    const struct boot_header *bh)
{
	char *mb_h2m_addr;
	char *mb_m2h_addr;
	size_t mb_h2m_size;
	size_t mb_m2h_size;

	/* Calculate mailbox addresses and sizes */
	mb_h2m_addr =
		(char *)mcu->fw_cpu_mem + (bh->h2m.start - bh->vaddr_start);
	mb_h2m_size = bh->h2m.end - bh->h2m.start;

	mb_m2h_addr =
		(char *)mcu->fw_cpu_mem + (bh->m2h.start - bh->vaddr_start);
	mb_m2h_size = bh->m2h.end - bh->m2h.start;

	/* Initialize mailboxes */
	codec_mb_init(mcu->regs, &mcu->mb_h2m, mb_h2m_addr, mb_h2m_size,
		      MAILBOX_H2M);
	codec_mb_init(mcu->regs, &mcu->mb_m2h, mb_m2h_addr, mb_m2h_size,
		      MAILBOX_M2H);

	common_dbg(
		dev,
		"MCU %d: Mailbox initialized - H2M: %p (size=%zu), M2H: %p (size=%zu)\n",
		mcu->mcu_id, mb_h2m_addr, mb_h2m_size, mb_m2h_addr,
		mb_m2h_size);

	return 0;
}

/**
 * start_mcu - Start an MCU with loaded firmware
 * @dev: Device structure
 * @mcu: MCU instance
 * @bh: Boot header with boot configuration
 *
 * Returns: 0 on success, negative error code on failure
 */
static int start_mcu(struct al_common_dev *dev, struct al_mcu_instance *mcu,
		     const struct boot_header *bh)
{
	u64 boot_addr_phys;
	u64 periph_addr;
	u64 instr_offset;
	u64 data_offset;

	/* Calculate physical boot address */
	boot_addr_phys = mcu->fw_phys_addr + (bh->boot_addr - bh->vaddr_start);

	/* Calculate peripheral address */
	if (bh->machine_id == MACHINE_ID_2) {
		periph_addr = mcu->apb_addr;
	} else {
		periph_addr = mcu->apb_addr;
	}

	/* Calculate offsets */
	/* instr_offset = mcu->fw_phys_addr - bh->vaddr_start; */
	/* data_offset = instr_offset; */
	instr_offset = 0;
	data_offset = instr_offset;

	/* Configure MCU boot address */
	common_writel(mcu, AL_CODEC_MCU_BOOT_ADDR_MSB,
		      upper_32_bits(boot_addr_phys));
	common_writel(mcu, AL_CODEC_MCU_BOOT_ADDR_LSB,
		      lower_32_bits(boot_addr_phys));

	/* Configure MCU peripheral address */
	common_writel(mcu, AL_CODEC_MCU_PERIPHERAL_ADDR_MSB,
		      upper_32_bits(periph_addr));
	common_writel(mcu, AL_CODEC_MCU_PERIPHERAL_ADDR_LSB,
		      lower_32_bits(periph_addr));

	/* Configure instruction and data offsets */
	common_writel(mcu, AL_CODEC_INSTRUCTION_OFFSET_MSB,
		      upper_32_bits(instr_offset));
	common_writel(mcu, AL_CODEC_INSTRUCTION_OFFSET_LSB,
		      lower_32_bits(instr_offset));
	common_writel(mcu, AL_CODEC_DATA_OFFSET_MSB,
		      upper_32_bits(data_offset));
	common_writel(mcu, AL_CODEC_DATA_OFFSET_LSB,
		      lower_32_bits(data_offset));

	/* Start MCU clock and release reset */
	common_writel(mcu, AL_CODEC_MCU_CLK, AL_CODEC_REG_ENABLE);

	/* This should be set, or the irq handler will disable the irq*/
	mcu->active = true;

	if (wait_for_completion_timeout(&mcu->done, 5 * HZ) <= 0) {
		mcu->active = false;
		return -ETIMEDOUT;
	}

	common_dbg(
		dev,
		"MCU %d (%s): Started - boot_addr=0x%llx, periph_addr=0x%llx\n",
		mcu->mcu_id, mcu->name, boot_addr_phys, periph_addr);

	return 0;
}

/**
 * load_firmware_to_mcus - Load and start firmware on all MCUs
 * @dev: Device structure
 * @fw: Firmware data
 *
 * This function validates the firmware once, then copies it to each MCU
 * and starts them all.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int load_firmware_to_mcus(struct al_common_dev *dev,
				 const struct firmware *fw)
{
	struct boot_header bh;
	struct al_mcu_instance *mcu;
	u32 i;
	int ret;

	/* Validate firmware once before copying to any MCU */
	if (!validate_firmware(dev, fw, &bh)) {
		common_err(dev, "Firmware validation failed\n");
		return -EINVAL;
	}

	/* Allocate DMA memory and copy firmware for each MCU */
	for (i = 0; i < dev->num_mcus; i++) {
		mcu = &dev->mcus[i];

		mcu->fw_size = bh.vaddr_end - bh.vaddr_start;
		mcu->fw_cpu_mem = common_dma_alloc_coherent(
			dev, mcu->fw_size, &mcu->fw_phys_addr, GFP_KERNEL);
		if (IS_ERR(mcu->fw_cpu_mem)) {
			common_err(
				dev,
				"MCU %d: Failed to allocate firmware memory\n",
				i);
			ret = -ENOMEM;
			goto error_cleanup;
		}

		/* Allocate buffer for the inter-comm mailboxes */
		if (dev->num_mcus > 1) {
			mcu->imb.virt = common_dma_alloc_coherent(
				dev, IMAILBOX_SIZE, &mcu->imb.phys, GFP_KERNEL);
			if (IS_ERR(mcu->imb.virt)) {
				common_err(
					dev,
					"Failed to allocate inter-comm buffers \n");
				ret = -ENOMEM;
				goto error_cleanup;
			}

			mcu->imb.size = IMAILBOX_SIZE;
		}
	}

	for (i = 0; i < dev->num_mcus; i++) {
		mcu = &dev->mcus[i];

		/* Copy firmware to MCU memory */
		ret = copy_firmware_to_mcu(dev, mcu, fw, &bh);
		if (ret) {
			common_err(dev, "MCU %d: Failed to copy firmware\n", i);
			goto error_cleanup;
		}

		/* Initialize mailbox */
		ret = init_mcu_mailbox(dev, mcu, &bh);
		if (ret) {
			common_err(dev,
				   "MCU %d: Failed to initialize mailbox\n", i);
			goto error_cleanup;
		}

		/* Start all MCUs */
		ret = start_mcu(dev, mcu, &bh);
		if (ret) {
			common_err(dev, "MCU %d: Failed to start\n", i);
			goto error_cleanup;
		}
	}

	common_info(dev, "All %d MCUs loaded and started successfully\n",
		    dev->num_mcus);
	return 0;

error_cleanup:
	/* Cleanup: Free any allocated DMA memory */
	for (i = 0; i < dev->num_mcus; i++) {
		if (dev->mcus[i].fw_cpu_mem) {
			dma_free_coherent(&dev->pdev->dev, dev->mcus[i].fw_size,
					  dev->mcus[i].fw_cpu_mem,
					  dev->mcus[i].fw_phys_addr);

			dev->mcus[i].fw_cpu_mem = NULL;
		}

		if (dev->mcus[i].imb.virt) {
			dma_free_coherent(&dev->pdev->dev,
					  dev->mcus[i].imb.size,
					  dev->mcus[i].imb.virt,
					  dev->mcus[i].imb.phys);

			dev->mcus[i].imb.virt = NULL;
		}
	}
	return ret;
}

/**
 * common_fw_callback - Firmware loading callback
 * @fw: Firmware data
 * @context: Device structure
 *
 * This callback is called when request_firmware_nowait completes.
 */
static void common_fw_callback(const struct firmware *fw, void *context)
{
	struct al_common_dev *dev = context;
	int ret;

	if (!fw) {
		common_err(dev, "Firmware loading failed\n");
		return;
	}

	common_dbg(dev, "Firmware loaded: size=%zu bytes\n", fw->size);

	/* Load firmware to all MCUs */
	ret = load_firmware_to_mcus(dev, fw);
	if (ret) {
		common_err(dev, "Failed to load firmware to MCUs\n");
		release_firmware(fw);
		return;
	}

	/* Release firmware data (we've copied it) */
	release_firmware(fw);

	/* Notify client that firmware is ready */
	if (dev->fw_ready_cb) {
		dev->fw_ready_cb(dev->cb_arg);
	}

	common_dbg(dev, "Firmware initialization complete\n");
}

/**
 * common_firmware_request_nowait - Request firmware asynchronously
 * @dev: Device structure
 * @fw_name: Firmware filename
 *
 * Returns: 0 on success, negative error code on failure
 */
static int common_firmware_request_nowait(struct al_common_dev *dev,
					  const char *fw_name)
{
	common_info(dev, "Requesting firmware: %s\n", fw_name);

	return request_firmware_nowait(THIS_MODULE, true, fw_name,
				       &dev->pdev->dev, GFP_KERNEL, dev,
				       common_fw_callback);
}

/*******************************************************************************
 * INTERRUPT HANDLING WITH WORKQUEUE
 ******************************************************************************/

/**
* mcu_irq_work_handler - Workqueue handler for MCU interrupts
* @work: Work structure
*
* This function runs in workqueue context and processes messages from
* the MCU mailbox.
*/
static void mcu_irq_work_handler(struct work_struct *work)
{
	struct al_mcu_instance *mcu =
		container_of(work, struct al_mcu_instance, irq_work);

	if (!mcu->active)
		return;

	/* Process messages from this MCU */
	process_mcu_messages(mcu);
}

/**
 * common_hardirq_handler - Hard IRQ handler (top half)
 * @irq: IRQ number
 * @arg: Device structure
 *
 * This is the fast interrupt handler that checks if an interrupt is pending
 * and signals the threaded handler to process it.
 *
 * Returns: IRQ_WAKE_THREAD if interrupt needs processing, IRQ_NONE otherwise
 */
static irqreturn_t common_hardirq_handler(int irq, void *arg)
{
	struct al_common_dev *dev = arg;
	bool irq_pending = false;
	u32 irq_status;
	int i;

	/* Check if this MCU has an interrupt pending */
	for (i = 0; i < dev->num_mcus; i++) {
		struct al_mcu_instance *mcu = &dev->mcus[i];

		if (!mcu->active)
			continue;

		irq_status = common_readl(mcu, AL_CODEC_IRQ_STATUS_CLEAR);
		if (irq_status) {
			common_writel(mcu, AL_CODEC_IRQ_STATUS_CLEAR,
				      irq_status);

			/* Queue work - workqueue was created at probe */
			queue_work(dev->irq_wq, &mcu->irq_work);

			irq_pending = true;
			break;
		}
	}

	return irq_pending ? IRQ_HANDLED : IRQ_NONE;
}

/*******************************************************************************
 * DEVICE TREE PARSING
 ******************************************************************************/

/**
 * parse_mcu_clock - Parse and enable clock for an MCU
 * @dev: Device structure
 * @mcu: MCU instance
 * @mcu_node: Device tree node for this MCU
 *
 * Returns: 0 on success, negative error code on failure
 */
static int parse_mcu_clock(struct al_common_dev *dev,
			   struct al_mcu_instance *mcu,
			   struct device_node *mcu_node)
{
	struct clk *clk;
	int ret;

	clk = of_clk_get(mcu_node, 0);
	if (IS_ERR(clk)) {
		common_warn(dev, "MCU %d: No clock specified, using default\n",
			    mcu->mcu_id);
		mcu->mcu_clk_rate = 0;
		return 0;
	}

	ret = clk_prepare_enable(clk);
	if (ret) {
		common_err(dev, "MCU %d: Failed to enable clock\n",
			   mcu->mcu_id);
		clk_put(clk);
		return ret;
	}

	mcu->clk = clk;
	mcu->mcu_clk_rate = clk_get_rate(clk);

	common_info(dev, "MCU %d: Clock enabled, rate=%lu Hz\n", mcu->mcu_id,
		    mcu->mcu_clk_rate);

	return 0;
}

/**
 * parse_mcu_subnode - Parse a single MCU child node from device tree
 * @dev: Device structure
 * @mcu_node: Device tree node for this MCU
 * @mcu_id: MCU index
 *
 * Returns: 0 on success, negative error code on failure
 */
static int parse_mcu_subnode(struct al_common_dev *dev,
			     struct device_node *mcu_node, u32 mcu_id)
{
	struct al_mcu_instance *mcu = &dev->mcus[mcu_id];
	u32 mcu_offset;
	const char *name;
	u64 apb_addr;
	int ret;

	/* Initialize MCU structure */
	mcu->mcu_id = mcu_id;
	mcu->is_master = (mcu_id == 0); /* First MCU is master */
	mcu->active = false;
	init_completion(&mcu->done);

	ret = of_property_read_u32(mcu_node, "mcu-offset", &mcu_offset);
	if (ret) {
		common_err(dev, "MCU%d: Missing mcu-offset for MCU node\n",
			   mcu_id);
		return ret;
	}

	/* Check the offset is exceed the device size */
	if (mcu_offset > resource_size(&dev->regs_info)) {
		common_err(dev, "MCU%d: Missing mcu-offset for MCU node\n",
			   mcu_id);
		return -EINVAL;
	}

	mcu->regs = dev->regs + mcu_offset;

	/* Parse APB address (64-bit property) */
	/* TODO: Add the check of the apb_address */
	ret = of_property_read_u64(mcu_node, "apb-address", &apb_addr);
	if (ret) {
		common_warn(dev, "MCU %d: No apb-address specified\n", mcu_id);
		apb_addr = 0;
	}
	mcu->apb_addr = apb_addr;

	/* TODO: Calculate offset (for 39-bit physical address limitation) */
	mcu->offset = 0;

	/* Parse optional MCU name */
	ret = of_property_read_string(mcu_node, "mcu-name", &name);
	if (ret == 0) {
		strncpy(mcu->name, name, sizeof(mcu->name) - 1);
		mcu->name[sizeof(mcu->name) - 1] = '\0';
	} else {
		snprintf(mcu->name, sizeof(mcu->name), "MCU%d", mcu_id);
	}

	/* Parse and enable clock */
	ret = parse_mcu_clock(dev, mcu, mcu_node);
	if (ret)
		return ret;

	common_dbg(dev, "MCU %d (%s): Parsed - regs=0x%llx, apb=0x%llx\n",
		   mcu_id, mcu->name, (u64)dev->regs_info.start + mcu_offset,
		   apb_addr);

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
/* of_node_name_prefix - Device-tree helper,
 * used to check if a device node's name starts with a specified prefix
 */
bool of_node_name_prefix(const struct device_node *np, const char *prefix)
{
	if (!np)
		return false;

	return strncmp(kbasename(np->full_name), prefix, strlen(prefix)) == 0;
}
#endif

/**
 * parse_multi_mcu_dt - Parse multi-MCU configuration from device tree
 * @dev: Device structure
 *
 * This function parses child nodes with the "mcu" prefix to configure
 * multiple MCU instances.
 *
 * Returns: 0 on success, -ENOENT if no MCU nodes found, other negative on error
 */
static int parse_multi_mcu_dt(struct al_common_dev *dev)
{
	struct device_node *np = dev->pdev->dev.of_node;
	struct device_node *mcu_node;
	u32 num_mcus = 0;
	u32 mcu_id;
	int ret;

	/* Count MCU child nodes */
	for_each_child_of_node(np, mcu_node) {
		if (of_node_name_prefix(mcu_node, "mcu") ||
		    of_node_name_prefix(mcu_node, "codec-mcu"))
			num_mcus++;
	}

	if (num_mcus == 0) {
		common_dbg(dev, "No MCU child nodes found\n");
		return -ENOENT;
	}

	if (num_mcus > AL_MAX_MCUS) {
		common_err(dev, "Too many MCU nodes: %d (max %d)\n", num_mcus,
			   AL_MAX_MCUS);
		return -EINVAL;
	}

	/* Allocate MCU array */
	dev->num_mcus = num_mcus;
	dev->mcus = devm_kcalloc(&dev->pdev->dev, num_mcus,
				 sizeof(struct al_mcu_instance), GFP_KERNEL);
	if (!dev->mcus)
		return -ENOMEM;

	/* Parse each MCU node */
	mcu_id = 0;

	for_each_child_of_node(np, mcu_node) {
		if (!of_node_name_prefix(mcu_node, "mcu") &&
		    !of_node_name_prefix(mcu_node, "codec-mcu"))
			continue;

		ret = parse_mcu_subnode(dev, mcu_node, mcu_id);
		if (ret) {
			of_node_put(mcu_node);
			common_err(dev, "Failed to parse MCU %d node\n",
				   mcu_id);
			return ret;
		}

		mcu_id++;
	}

	common_info(dev, "Multi-MCU mode: %d MCUs configured\n", num_mcus);
	return 0;
}

/**
 * parse_single_mcu_dt - Parse single MCU (legacy) configuration
 * @dev: Device structure
 *
 * This function parses the legacy single-MCU device tree format where
 * the MCU registers and APB are specified at the device level.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int parse_single_mcu_dt(struct al_common_dev *dev)
{
	struct al_mcu_instance *mcu;
	struct resource *res;
	struct clk *clk;
	int ret;

	/* Allocate single MCU */
	dev->num_mcus = 1;
	dev->mcus = devm_kzalloc(&dev->pdev->dev,
				 sizeof(struct al_mcu_instance), GFP_KERNEL);
	if (!dev->mcus)
		return -ENOMEM;

	mcu = &dev->mcus[0];
	mcu->mcu_id = 0;
	mcu->is_master = true;
	mcu->active = false;
	init_completion(&mcu->done);
	strncpy(mcu->name, "MCU0", sizeof(mcu->name));

	mcu->regs = devm_ioremap_resource(&dev->pdev->dev, &dev->regs_info);
	if (IS_ERR(mcu->regs)) {
		common_err(dev, "Single MCU: failed to map registers\n");
		return PTR_ERR(mcu->regs);
	}

	/* Parse APB address */
	res = platform_get_resource_byname(dev->pdev, IORESOURCE_MEM, "apb");
	if (res) {
		mcu->apb_addr = res->start;
	} else {
		common_warn(dev, "Single MCU: No APB resource\n");
		mcu->apb_addr = 0;
	}

	mcu->offset = 0;

	/* Parse clock from device level */
	clk = devm_clk_get(&dev->pdev->dev, "mcu");
	if (!IS_ERR(clk)) {
		ret = clk_prepare_enable(clk);
		if (ret == 0) {
			mcu->clk = clk;
			mcu->mcu_clk_rate = clk_get_rate(clk);
		} else {
			common_warn(dev,
				    "Single MCU: Failed to enable clock\n");
			mcu->mcu_clk_rate = 0;
		}
	} else {
		common_warn(dev, "Single MCU: No clock specified\n");
		mcu->mcu_clk_rate = 0;
	}

	common_dbg(dev, "Single MCU: regs=0x%llx, apb=0x%llx, clk_rate=%lu\n",
		   (u64)mcu->regs_info->start, mcu->apb_addr,
		   mcu->mcu_clk_rate);

	return 0;
}

/**
 * parse_dt_architecture - Parse device tree for MCU configuration
 * @dev: Device structure
 *
 * This function tries to parse multi-MCU configuration first, then falls
 * back to single-MCU (legacy) mode if no child nodes are found.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int parse_dt_architecture(struct al_common_dev *dev)
{
	int ret;

	/* Try multi-MCU mode first */
	ret = parse_multi_mcu_dt(dev);
	if (ret == 0) {
		return 0;
	} else if (ret == -ENOENT) {
		/* No child nodes, try single MCU (legacy) */
		return parse_single_mcu_dt(dev);
	}

	return ret;
}

/*******************************************************************************
 * DMA BUFFER MANAGEMENT (From original code)
 ******************************************************************************/

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
						   dma_addr_t dma_handle,
						   bool remove)
{
	return buf_lookup(&dev->dma_lock, &dev->dma_buffers, dma_handle,
			  remove);
}

static void common_dma_buf_cleanup(struct al_common_dev *dev)
{
	buf_cleanup_list(&dev->dma_lock, &dev->dma_buffers, &dev->pdev->dev);
}

static void handle_get_cma_req(struct al_mcu_instance *mcu,
			       struct msg_itf_header *hdr)
{
	struct al_common_dev *dev = mcu->dev;
	struct msg_itf_get_cma_reply_full reply = { 0 };
	struct msg_itf_get_cma_req req = { 0 };
	struct codec_dma_buf *buf = NULL;
	int ret;

	reply.reply.phyAddr = 0;

	// Always read aligned payload
	size_t aligned_len = ALIGN(hdr->payload_len, 64);
	ret = al_mcu_get_data(mcu, (char *)&req, aligned_len);
	if (ret) {
		common_err(dev, "Unable to get cma req\n");
		goto send_reply;
	}

	buf = kzalloc(sizeof(*buf), GFP_KERNEL); // Zeroed, safer
	if (!buf)
		goto send_reply;

	buf->size = req.uSize;
	buf->is_kernel_mapped = dev->map_in_kernel;
	buf->cpu_mem = common_dma_alloc_coherent(dev, req.uSize,
						 &buf->dma_handle, GFP_KERNEL);
	if (IS_ERR(buf->cpu_mem))
		goto send_reply;

	reply.reply.phyAddr = (uint64_t)buf->dma_handle;

	// Ensure the buffer is cache-line aligned
	if (!IS_ALIGNED((uintptr_t)buf->cpu_mem, 64))
		common_warn(dev, "Allocated CMA buffer not 64B aligned!\n");

	common_dma_buf_insert(dev, buf);

send_reply:
	reply.hdr.type = MSG_ITF_TYPE_GET_CMA_REPLY;
	reply.hdr.driver_client_handle = hdr->driver_client_handle;
	reply.hdr.driver_command_handle = hdr->driver_command_handle;
	reply.hdr.payload_len = sizeof(reply.reply);

	ret = al_mcu_msg_send(mcu, &reply.hdr);
	if (ret) {
		common_err(dev, "Unable to reply to cma alloc\n");
		if (buf)
			common_dma_buf_remove(dev, buf);
	}
}

static void handle_put_cma_req(struct al_mcu_instance *mcu,
			       struct msg_itf_header *hdr)
{
	struct al_common_dev *dev = mcu->dev;
	struct msg_itf_put_cma_reply_full reply = { 0 };
	struct msg_itf_put_cma_req req = { 0 };
	struct codec_dma_buf *buf = NULL;
	int ret;

	reply.reply.ret = -1;
	size_t aligned_len = ALIGN(hdr->payload_len, 64);
	ret = al_mcu_get_data(mcu, (char *)&req, aligned_len);
	if (ret) {
		common_err(dev, "Unable to put cma req\n");
		goto send_reply;
	}

	buf = common_dma_buf_lookup(dev, req.phyAddr, true);
	if (!buf) {
		common_err(dev, "Unable to get dma handle for %llx\n",
			   req.phyAddr);
		reply.reply.ret = -EINVAL;
		goto send_reply;
	}

	dma_free_coherent(&dev->pdev->dev, buf->size, buf->cpu_mem,
			  buf->dma_handle);
	reply.reply.ret = 0;

send_reply:
	reply.hdr.type = MSG_ITF_TYPE_PUT_CMA_REPLY;
	reply.hdr.driver_client_handle = hdr->driver_client_handle;
	reply.hdr.driver_command_handle = hdr->driver_command_handle;
	reply.hdr.payload_len = sizeof(reply.reply);

	ret = al_mcu_msg_send(mcu, &reply.hdr);
	if (ret)
		common_err(dev, "Unable to reply to cma free\n");
}

static void handle_write_req(struct al_mcu_instance *mcu,
			     struct msg_itf_header *hdr)
{
	struct al_common_dev *dev = mcu->dev;
	struct msg_itf_write_req *req = NULL;
	size_t aligned_size = ALIGN(hdr->payload_len, 64);
	int ret;

	// +1 for zero-terminated string safety
	req = kzalloc(aligned_size + 1, GFP_KERNEL);
	if (!req) {
		al_mcu_get_data(
			mcu, NULL,
			aligned_size); // Discard in mailbox for alignment
		common_err(dev, "Unable to alloc memory\n");
		return;
	}

	ret = al_mcu_get_data(mcu, (char *)req, aligned_size);
	if (ret) {
		common_err(dev, "%s Unable to get request\n", __func__);
		kfree(req);
		return;
	}

	pr_cont("%s: %s", mcu->name,
		(char *)(req +
			 1)); // Assuming payload starts after struct for legacy API
	kfree(req);
}

/**
 * process_mcu_messages - Process messages from an MCU
 * @dev: Device structure
 * @mcu: MCU instance
 *
 * Returns: true if messages were processed, false otherwise
 */
static bool process_mcu_messages(struct al_mcu_instance *mcu)
{
	struct al_common_dev *dev = mcu->dev;
	struct msg_itf_header hdr;
	bool processed = false;

	/* Check if there are messages in the mailbox */
	while (codec_msg_get_header(&mcu->mb_m2h, &hdr) == 0) {
		switch (hdr.type) {
		case MSG_ITF_TYPE_GET_CMA_REQ:
			handle_get_cma_req(mcu, &hdr);
			break;
		case MSG_ITF_TYPE_PUT_CMA_REQ:
			handle_put_cma_req(mcu, &hdr);
			break;
		case MSG_ITF_TYPE_WRITE_REQ:
			handle_write_req(mcu, &hdr);
			break;
		case MSG_ITF_TYPE_FW_READY:
			complete(&mcu->done);
			break;

		default:
			/* Process message through callback */
			if (dev->process_msg_cb)
				dev->process_msg_cb(dev->cb_arg, &hdr);
		}

		processed = true;
	}

	return processed;
}

/*******************************************************************************
 * DEVICE SETUP AND INITIALIZATION
 ******************************************************************************/

/**
 * common_probe_check_and_setup_hw - Check and setup hardware
 * @dev: Device structure
 * @res: Resource for device registers
 *
 * Returns: 0 on success, negative error code on failure
 */
static int common_probe_check_and_setup_hw(struct al_common_dev *dev,
					   struct resource *res)
{
	unsigned int id;
	int i;

	/* Verify device ID */
	id = dev_readl(dev, AL_CODEC_UID);
	if (id != AL_CODEC_UID_ID) {
		common_err(dev,
			   "Invalid device ID: expected 0x%08x, got 0x%08x\n",
			   AL_CODEC_UID_ID, id);
		return -ENODEV;
	}

	for (i = 0; i < dev->num_mcus; i++) {
		/* Reset device and all MCUs */
		common_reset_mcu(&dev->mcus[i]);
		/* Configure the IRQ mask */
		common_writel(&dev->mcus[i], AL_CODEC_IRQ_MASK,
			      AL_CODEC_IRQ_MCU_2_CPU);
	}

	dev->regs_info = *res;

	common_info(dev, "Hardware initialized successfully\n");
	return 0;
}

/**
 * common_setup_dma - Setup DMA configuration
 * @dev: Device structure
 *
 * Returns: 0 on success, negative error code on failure
 */

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
			common_err(
				common,
				"No suitable DMA available with 39-bit addressing");
			return ret;
		}

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
		common_err(common, "Couldn't get reserved memory (errno: %d)",
			   ret);
		return ret;
	}

	ret = of_address_to_resource(node, 0, &r);
	of_node_put(node);
	if (ret) {
		common_err(common,
			   "Failed to parse the memory-region resources");
		return -EINVAL;
	}

	common->reserved_mem_start = r.start;
	common->reserved_mem_size = r.end - r.start;

	common_dbg(common, "Reserved memory: 0x%llx, size: 0x%lld\n",
		   (u64)common->reserved_mem_start, common->reserved_mem_size);

	return 0;
}

/*******************************************************************************
 * PUBLIC API FUNCTIONS
 ******************************************************************************/

/**
 * al_common_probe - Main probe function
 * @pdev: Platform device
 * @dev: Device structure (must be allocated by caller)
 * @fw_name: Firmware filename
 * @map_in_kernel: Whether to map DMA buffers in kernel
 *
 * Returns: 0 on success, negative error code on failure
 */
int al_common_probe(struct platform_device *pdev, struct al_common_dev *dev,
		    const char *fw_name, bool map_in_kernel)
{
	struct resource *res;
	int ret;
	int i;

	dev->pdev = pdev;
	dev->map_in_kernel = map_in_kernel;

	/* Initialize locks and lists */
	mutex_init(&dev->dma_lock);
	INIT_LIST_HEAD(&dev->dma_buffers);

	/* Setup DMA */
	ret = common_setup_dma(dev);
	if (ret)
		return ret;

	/* Map device-level registers */
	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "regs");
	if (!res) {
		common_err(dev, "regs resource missing from device tree\n");
		return -EINVAL;
	}

	dev->regs_info = *res;

	dev->regs = devm_ioremap(&pdev->dev, res->start, resource_size(res));
	if (!dev->regs) {
		common_err(dev, "Failed to map device registers\n");
		return -ENOMEM;
	}

	/* Parse device tree for MCU configuration */
	ret = parse_dt_architecture(dev);
	if (ret) {
		common_err(dev, "Failed to parse device tree\n");
		return ret;
	}

	/* Create high-priority workqueue ONCE */
	dev->irq_wq = create_singlethread_workqueue("al_codec_irq");
	if (!dev->irq_wq) {
		common_err(dev, "Failed to create IRQ workqueue\n");
		return -ENOMEM;
	}

	/* Initialize work structure for each MCU */
	for (i = 0; i < dev->num_mcus; i++) {
		struct al_mcu_instance *mcu = &dev->mcus[i];
		mcu->dev = dev; /* Backpointer to device */
		INIT_WORK(&mcu->irq_work, mcu_irq_work_handler);
	}

	/* Get IRQ */
	dev->irq = platform_get_irq(pdev, 0);
	if (dev->irq < 0) {
		common_err(dev, "Failed to get IRQ\n");
		return -EINVAL;
	}

	/* Register threaded IRQ handler */
	ret = devm_request_irq(&pdev->dev, dev->irq, common_hardirq_handler,
			       IRQF_SHARED, dev_name(&pdev->dev), dev);
	if (ret) {
		common_err(dev, "Failed to register IRQ handler\n");
		return ret;
	}

	/* Check and setup hardware */
	ret = common_probe_check_and_setup_hw(dev, res);
	if (ret) {
		common_err(dev, "Hardware setup failed\n");
		return ret;
	}

	/* Request firmware asynchronously */
	ret = common_firmware_request_nowait(dev, fw_name);
	if (ret) {
		common_err(dev, "Failed to request firmware\n");
		return ret;
	}

	common_info(dev, "Probe completed successfully\n");
	return 0;
}
EXPORT_SYMBOL(al_common_probe);

/**
 * al_common_remove - Remove function
 * @dev: Device structure
 *
 * Returns: 0 on older kernels, void on newer kernels
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
void al_common_remove(struct al_common_dev *dev)
#else
int al_common_remove(struct al_common_dev *dev)
#endif
{
	u32 i;

	/* Cleanup DMA buffers */
	common_dma_buf_cleanup(dev);

	/* Free firmware memory for each MCU */
	for (i = 0; i < dev->num_mcus; i++) {
		struct al_mcu_instance *mcu = &dev->mcus[i];

		/* Free the firmware memory */
		if (mcu->fw_cpu_mem)
			dma_free_coherent(&dev->pdev->dev, mcu->fw_size,
					  mcu->fw_cpu_mem, mcu->fw_phys_addr);

		/* Free the inter-comm mb */
		if (mcu->imb.virt)
			dma_free_coherent(&dev->pdev->dev, mcu->imb.size,
					  mcu->imb.virt, mcu->imb.phys);

		/* Disable and put clock */
		if (!IS_ERR(mcu->clk))
			clk_disable_unprepare(mcu->clk);

		/* Cancel all pending work for each MCU */
		cancel_work_sync(&mcu->irq_work);
	}

	/* Reset device */
	common_reset(dev);

	/* Flush and destroy workqueue */
	flush_workqueue(dev->irq_wq);
	destroy_workqueue(dev->irq_wq);
	dev->irq_wq = NULL;

	common_info(dev, "Device removed\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 11, 0)
	return 0;
#endif
}
EXPORT_SYMBOL(al_common_remove);

/**
 * common_dma_alloc - Allocate DMA memory
 * @dev: Device structure
 * @size: Size to allocate
 * @dma_handle: DMA handle output
 * @flag: GFP flags
 *
 * Returns: CPU address on success, NULL on failure
 */
void *common_dma_alloc(struct al_common_dev *dev, size_t size,
		       dma_addr_t *dma_handle, gfp_t flag)
{
	return common_dma_alloc_coherent(dev, size, dma_handle, flag);
}
EXPORT_SYMBOL(common_dma_alloc);

/**
 * al_common_dma_buf_free - Free DMA buffer
 * @dev: Device structure
 * @phy_addr: Physical address
 *
 * Returns: 0 on success, negative error code on failure
 */
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
EXPORT_SYMBOL(al_common_dma_buf_free);

/**
 * al_common_dma_buf_map - Map DMA buffer to userspace
 * @dev: Device structure
 * @vma: VM area struct
 *
 * Returns: 0 on success, negative error code on failure
 */
int al_common_dma_buf_map(struct al_common_dev *dev, struct vm_area_struct *vma)
{
	return buf_map(&dev->dma_lock, &dev->dma_buffers, vma, &dev->pdev->dev);
}
EXPORT_SYMBOL(al_common_dma_buf_map);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yassine OUAISSA");
MODULE_DESCRIPTION("Multi-MCU Codec Driver");
