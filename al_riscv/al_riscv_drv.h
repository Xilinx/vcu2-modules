/******************************************************************************
*
* Copyright (C) 2026 Allegro DVT.  All rights reserved.
*
******************************************************************************/

#ifndef __AL_RISCV_DRV__
#define __AL_RISCV_DRV__

#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/version.h>

#include "al_common.h"

#define MAX_MISC_NAME 32

struct al_riscv_match_data {
	const char *fw_name;
	const char *default_device_name;
};

struct codec_dev {
	struct al_common_dev common;

	struct miscdevice misc;
	char misc_name[MAX_MISC_NAME];
	int is_misc_init_done;

	struct mutex client_lock;
	struct list_head clients;
};

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

void client_dma_buf_insert(struct codec_client *ctx, struct al_dma_buf *buf);

void client_dma_buf_remove(struct codec_client *ctx, struct al_dma_buf *buf);

void codec_client_get(struct codec_client *client);

void codec_client_put(struct codec_client *client);

int codec_probe(struct platform_device *pdev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
void codec_remove(struct platform_device *pdev);
#else
int codec_remove(struct platform_device *pdev);
#endif

#endif
