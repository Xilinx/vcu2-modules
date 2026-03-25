/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#include <linux/kernel.h>
#include <linux/string.h>

#include "al_codec_mb.h"

/* Mailbox heads and tails */
#define AL_CODEC_MCU_MAILBOX_H2M_HEAD 0x0418
#define AL_CODEC_MCU_MAILBOX_H2M_TAIL 0x041C
#define AL_CODEC_MCU_MAILBOX_M2H_HEAD 0x0420
#define AL_CODEC_MCU_MAILBOX_M2H_TAIL 0x0424

static inline int get_used_space(struct codec_mb *mb)
{
	u32 head = readl(mb->hw);
	u32 tail = readl(mb->hw + 0x4);

	return head >= tail ? head - tail : mb->size - (tail - head);
}

static inline int get_free_space(struct codec_mb *mb)
{
	return mb->size - get_used_space(mb) - 1;
}

static inline int has_enough_space(struct codec_mb *mb, size_t len)
{
	return get_free_space(mb) >= len;
}

static void copy_to_mb(struct codec_mb *mb, char *data, size_t len)
{
	u32 head = readl(mb->hw);
	int bytes_to_end = mb->size - head;
	int first_copy_len = min(bytes_to_end, (int)len);

	if (WARN(!IS_ALIGNED(head, 64), "MB head is not aligned"))
		return;

	memcpy(&mb->data[head], data, first_copy_len);
	if (len > first_copy_len)
		memcpy(&mb->data[0], &data[first_copy_len],
		       len - first_copy_len);

	/* Make sure that the data is seen by the mcu */
	dma_wmb();

	head = (head + ALIGN(len, 64)) % mb->size;
	writel(head, mb->hw);
}

static inline void copy_from_mb(struct codec_mb *mb, char *data, size_t len)
{
	u32 tail = readl(mb->hw + 0x4);
	int bytes_to_end = mb->size - tail;
	int first_copy_len = min(bytes_to_end, (int)len);

	if (WARN(!IS_ALIGNED(tail, 64), "MB tail is not aligned"))
		return;

	if (!data)
		goto update_tail;

	dma_rmb();

	/* tail+= padding; */
	memcpy(data, &mb->data[tail], first_copy_len);
	if (len > first_copy_len)
		memcpy(&data[first_copy_len], &mb->data[0],
		       len - first_copy_len);

update_tail:
	tail = (tail + ALIGN(len, 64)) % mb->size;
	writel(tail, mb->hw + 0x4);
}

void codec_mb_init(void __iomem *base_reg, struct codec_mb *mb, char *addr,
		   size_t size, mailbox_direction_t direction)
{
	/* Check is the addr and size are aligned 64*/
	if (WARN_ON(!IS_ALIGNED((uintptr_t)addr, 64) || !IS_ALIGNED(size, 64)))
		return;

	if (direction == MAILBOX_H2M)
		mb->hw = base_reg + AL_CODEC_MCU_MAILBOX_H2M_HEAD;
	else
		mb->hw = base_reg + AL_CODEC_MCU_MAILBOX_M2H_HEAD;

	mb->data = addr;
	mb->size = size;

	writeq(0, mb->hw);
	mutex_init(&mb->lock);
}

int codec_mb_send(struct codec_mb *mb, char *data, size_t len)
{
	mutex_lock(&mb->lock);
	if (!has_enough_space(mb, len)) {
		mutex_unlock(&mb->lock);
		return -ENOMEM;
	}

	copy_to_mb(mb, data, len);
	mutex_unlock(&mb->lock);

	return 0;
}

int codec_mb_receive(struct codec_mb *mb, char *data, size_t len)
{
	mutex_lock(&mb->lock);
	if (get_used_space(mb) < len) {
		mutex_unlock(&mb->lock);
		return -ENOMEM;
	}

	copy_from_mb(mb, data, len);
	mutex_unlock(&mb->lock);

	return 0;
}
