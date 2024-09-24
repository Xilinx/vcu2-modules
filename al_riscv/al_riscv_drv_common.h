/*
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

#ifndef __AL_RISCV_DRV__
#define __AL_RISCV_DRV__

#include <linux/dma-mapping.h>
#include <linux/platform_device.h>

#include "al_buf.h"

typedef struct {
	const char *fw_name;
	const char *default_device_name;
} al_riscv_device_data;

struct codec_client {
	struct kref refcount;
	struct list_head list;
	struct codec_dev *dev;
	struct file *file;

	struct mutex event_lock;
	struct list_head events;

	struct mutex client_lock;
	struct list_head cmds;

	wait_queue_head_t event_queue;

	struct mutex dma_lock;
	struct list_head dma_buffers;
};

void client_dma_buf_insert(struct codec_client *client,
				  struct codec_dma_buf *buf);

struct codec_dma_buf *client_dma_buf_lookup(struct codec_client *client,
						   dma_addr_t dma_handle, bool remove);

void client_dma_buf_remove(struct codec_client *client, struct codec_dma_buf *buf);

int al_riscv_codec_probe(struct platform_device *pdev);
int al_riscv_codec_remove(struct platform_device *pdev);

#endif
