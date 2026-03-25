/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#ifndef __AL_CODEC__
#define __AL_CODEC__ 1

#include <linux/types.h>
#include <linux/platform_device.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/clk.h>
#include "al_codec_mb.h"
#include "msg_common_itf.h"

/* Maximum number of MCUs supported */
#define AL_MAX_MCUS 8

struct al_dma_mem {
	dma_addr_t phys; /* Memory physical address */
	void *virt; /* Memory virtual address */
	size_t size; /* Size of the allocated memory */
};

struct al_common_dev {
	struct platform_device *pdev;
	void __iomem *regs; /* Device base registers */
	struct resource regs_info;
	u32 fw_version;

	/* Multi-MCU support */
	struct al_mcu_instance *mcus;
	u32 num_mcus; /* Number of MCU instances */

	bool map_in_kernel;
	struct mutex dma_lock;
	struct list_head dma_buffers;

	/* Callbacks set by client before common_probe */
	void *cb_arg;
	void (*process_msg_cb)(void *cb_arg, struct msg_itf_header *hdr);
	void (*fw_ready_cb)(void *cb_arg);

	/* Reserved memory */
	u64 reserved_mem_start;
	u64 reserved_mem_size;

	/* Firmware loading */
	const struct firmware *fw; /* Firmware data (shared by all MCUs) */
	struct workqueue_struct *irq_wq;
	int irq;
};

/* MCU Instance */
struct al_mcu_instance {
	struct al_common_dev *dev;
	void __iomem *regs; /* MCU registers (device reg + mcu offset) */
	struct resource *regs_info;
	u32 mcu_id;
	u64 apb_addr; /* APB peripheral address */
	u64 offset; /* Physical address offset (MCU supports only 39-bit) */
	bool active;
	bool is_master; /* First MCU is always the master */
	struct completion done;
	struct clk *clk; /* Clock for this MCU */
	unsigned long mcu_clk_rate; /* Clock rate from device tree or firmware */
	struct work_struct irq_work;

	/* Firmware memory for this MCU */
	void *fw_cpu_mem;
	dma_addr_t fw_phys_addr;
	size_t fw_size;
	u32 fw_version;

	/* Mailbox handlers for this MCU */
	struct codec_mb mb_h2m; /* Host to MCU mailbox */
	struct codec_mb mb_m2h; /* MCU to Host mailbox */

	/* Inter-comm mailbox shared buffer */
	struct al_dma_mem imb;

	/* Name for debugging */
	char name[32];
};

/* Probe and Remove */
int al_common_probe(struct platform_device *pdev, struct al_common_dev *dev,
		    const char *fw_name, bool map_in_kernel);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
void al_common_remove(struct al_common_dev *dev);
#else
int al_common_remove(struct al_common_dev *dev);
#endif

/* Message interface */
int al_common_get_header(struct al_common_dev *dev, struct msg_itf_header *hdr);
int al_common_get_data(struct al_common_dev *dev, char *data, int len);
int al_common_send(struct al_common_dev *dev, struct msg_itf_header *hdr);

/* DMA buffer management */
void *common_dma_alloc(struct al_common_dev *dev, size_t size,
		       dma_addr_t *dma_handle, gfp_t flag);
int al_common_dma_buf_free(struct al_common_dev *dev, uint64_t phy_addr);
int al_common_dma_buf_map(struct al_common_dev *dev,
			  struct vm_area_struct *vma);

#endif /* __AL_CODEC__ */
