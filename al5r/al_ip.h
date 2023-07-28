/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#pragma once

#include <linux/cdev.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

#include "al_ioctl.h"
#include "al_alloc.h"

#define AL5R_NR_DEVS 4

#define AXI_ADDR_OFFSET_IP(codec) ((codec)->regs_min_addr + 0x1208)
#define AL5_INTERRUPT_MASK(codec) ((codec)->regs_min_addr + 0x14)
#define AL5_INTERRUPT(codec) ((codec)->regs_min_addr + 0x18)

#define al5_writel(val, reg) iowrite32(val, codec->regs + reg)
#define al5_readl(reg) ioread32(codec->regs + reg)

#define al5_dbg(format, ...) \
	dev_dbg(codec->device, format, ## __VA_ARGS__)

#define al5_info(format, ...) \
	dev_info(codec->device, format, ## __VA_ARGS__)

#define al5_err(format, ...) \
	dev_err(codec->device, format, ## __VA_ARGS__)

struct al5r_codec_desc;
struct dma_buf_info {
	struct al5_dma_buffer *buffer;
	struct al5r_codec_desc *codec;
};

struct r_irq {
	struct list_head list;
	u32 bitfield;
};

struct al5r_codec_desc {
	struct device *device;
	void __iomem *regs;             /* base addr of the ip hw registers */
	unsigned long regs_size;
	u32 regs_min_addr;              /* first regs that can be addressed in the mmio.*/
	dma_addr_t dma_offset;          /* hw ip adds this offset to the dma address it is given */
	struct cdev cdev;
	/* one for one mapping in the no mcu case */
	struct al5r_codec_chan *chan;
	struct list_head irq_masks;
	spinlock_t i_lock;
	struct kmem_cache *cache;
	int minor;
};

struct al5_dma_buf_mmap {
	struct list_head list;
	struct al5_dma_buffer *buf;
	int buf_id;
};

struct al5r_codec_chan {
	wait_queue_head_t irq_queue;
	int unblock;
	spinlock_t lock;
	struct list_head mem;
	int num_bufs;
	struct al5r_codec_desc *codec;
};

int al5r_codec_bind_channel(struct al5r_codec_chan *chan,
			    struct inode *inode);
void al5r_codec_unbind_channel(struct al5r_codec_chan *chan);
int al5r_codec_read_register(struct al5r_codec_chan *chan,
			     struct al5_reg *reg);
void al5r_codec_write_register(struct al5r_codec_chan *chan,
			       struct al5_reg *reg);
irqreturn_t al5r_irq_handler(int irq, void *data);
irqreturn_t al5r_hardirq_handler(int irq, void *data);
