/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#ifndef __AL_CODEC_MB__
#define __AL_CODEC_MB__ 1

#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/clk.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/firmware.h>
#include <linux/of_reserved_mem.h>
#include <linux/slab.h>
#include <linux/version.h>

#define DCACHE_LINE_SIZE 64

/*
 * struct codec_mb - Mbox header struct
 *
 * @data: transmitted/received data
 * @size: size of data in bytes
 * @hw : pointer to the hardware head register
 * @lock:  protect the msg
 */
struct codec_mb {
	char *data;
	size_t size;
	void __iomem *hw;
	struct mutex lock;
} __attribute__((aligned(DCACHE_LINE_SIZE)));

/* Mailbox direction enumeration */
typedef enum {
	MAILBOX_H2M = 0, /* Host to MCU */
	MAILBOX_M2H = 1 /* MCU to Host */
} mailbox_direction_t;

void codec_mb_init(void __iomem *base_reg, struct codec_mb *mb, char *addr,
		   size_t size, mailbox_direction_t direction);
int codec_mb_send(struct codec_mb *mb, char *data, size_t len);
int codec_mb_receive(struct codec_mb *mb, char *data, size_t len);

#endif
