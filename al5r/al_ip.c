/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/firmware.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "al_ip.h"

int al5r_codec_bind_channel(struct al5r_codec_chan *chan,
			    struct inode *inode)
{
	struct al5r_codec_desc *codec;
	unsigned long flags;
	struct list_head *pos, *n;
	struct r_irq *tmp;
	int ret = 0;

	codec = container_of(inode->i_cdev, struct al5r_codec_desc, cdev);

	spin_lock_irqsave(&codec->i_lock, flags);

	chan->codec = codec;
	/* No mcu, there is a one for one mapping */
	if (codec->chan != NULL) {
		ret = -ENODEV;
		goto unlock;
	}

	list_for_each_safe(pos, n, &codec->irq_masks) {
		tmp = list_entry(pos, struct r_irq, list);
		al5_err("Previous channel lost irq:%x\n", tmp->bitfield);
		list_del(pos);
		kmem_cache_free(codec->cache, tmp);
	}

	codec->chan = chan;

unlock:
	spin_unlock_irqrestore(&codec->i_lock, flags);
	return ret;

}

void al5r_codec_unbind_channel(struct al5r_codec_chan *chan)
{
	struct al5r_codec_desc *codec;
	unsigned long flags;

	codec = chan->codec;
	spin_lock_irqsave(&codec->i_lock, flags);

	codec->chan = NULL;

	spin_unlock_irqrestore(&codec->i_lock, flags);
}

int al5r_codec_read_register(struct al5r_codec_chan *chan,
			     struct al5_reg *reg)
{
	struct al5r_codec_desc *codec = chan->codec;

	if (!chan->codec->regs) {
		al5_err("Registers not mapped\n");
		return -EINVAL;
	}
	reg->value = ioread32(chan->codec->regs + reg->id);

	return 0;
}

void al5r_codec_write_register(struct al5r_codec_chan *chan,
			       struct al5_reg *reg)
{
	struct al5r_codec_desc *codec = chan->codec;

	if (!chan->codec->regs) {
		al5_err("Registers not mapped\n");
		return;
	}
	iowrite32(reg->value, chan->codec->regs + reg->id);

}

irqreturn_t al5r_hardirq_handler(int irq, void *data)
{
	struct al5r_codec_desc *codec = (struct al5r_codec_desc *)data;
	u32 unmasked_irq_bitfield, irq_bitfield;
	u32 mask;
	unsigned long flags;
	struct r_irq *i_callback;
	int callback_nb;
	int i = 0;
	int al5_interrupt_nb = 27;

	mask = ioread32(codec->regs + AL5_INTERRUPT_MASK(codec));
	unmasked_irq_bitfield = ioread32(codec->regs + AL5_INTERRUPT(codec));
	irq_bitfield = unmasked_irq_bitfield & mask;
	if (irq_bitfield == 0) {
		al5_dbg("bitfield is 0\n");
		return IRQ_NONE;
	}
	iowrite32(unmasked_irq_bitfield, codec->regs + AL5_INTERRUPT(codec));
	ioread32(codec->regs + AL5_INTERRUPT(codec));

	al5_dbg("got irq. bitfield:%x, mask:%x", unmasked_irq_bitfield, mask);

	for (i = 0; i < al5_interrupt_nb; ++i) {
		callback_nb = 1U << i;
		if (irq_bitfield & callback_nb) {
			i_callback = kmem_cache_alloc(codec->cache, GFP_ATOMIC);
			if (!i_callback) {
				al5_dbg("ENOMEM: Missed interrupt\n");
				return IRQ_NONE;
			}
			i_callback->bitfield = i;
			spin_lock_irqsave(&codec->i_lock, flags);
			list_add_tail(&i_callback->list, &codec->irq_masks);
			spin_unlock_irqrestore(&codec->i_lock, flags);
		}
	}

	spin_lock_irqsave(&codec->i_lock, flags);
	if (codec->chan)
		wake_up_interruptible(&codec->chan->irq_queue);
	spin_unlock_irqrestore(&codec->i_lock, flags);

	return IRQ_HANDLED;
}
