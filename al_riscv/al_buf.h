/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#ifndef __AL_BUF__
#define __AL_BUF__ 1

#include <linux/dma-mapping.h>

struct codec_dma_buf {
	struct list_head list;
	dma_addr_t dma_handle;
	void *cpu_mem;
	uint32_t size;
	int is_kernel_mapped;
	bool is_coherent;
	struct dma_buf* dmabuf_handle;
};

void buf_insert(struct mutex *lock, struct list_head *head,
		struct codec_dma_buf *buf);

void buf_remove(struct mutex *lock, struct codec_dma_buf *buf);

struct codec_dma_buf *buf_lookup(struct mutex *lock, struct list_head *head,
				 dma_addr_t dma_handle, bool remove);


void buf_free_dma_coherent(struct device *dev, struct codec_dma_buf *buf);
void buf_cleanup_list(struct mutex *lock, struct list_head *head,
		      struct device *dev);
int buf_map(struct mutex *lock, struct list_head *head,
	    struct vm_area_struct *vma, struct device *dev);

#endif
