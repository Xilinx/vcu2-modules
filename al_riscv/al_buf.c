/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#include "al_buf.h"

#include <linux/dma-buf.h>
#include <linux/slab.h>
#include <linux/version.h>

static int buf_access(struct vm_area_struct *vma, unsigned long addr,
		      void *buf, int len, int write)
{
	struct codec_dma_buf *buffer = vma->vm_private_data;
	unsigned long offset = addr - vma->vm_start;
	unsigned long vm_size = vma->vm_end - vma->vm_start;

	if (!buffer->is_kernel_mapped)
		return -EINVAL;

	if (offset + len > vm_size)
		return -EINVAL;

	if (write)
		memcpy(buffer->cpu_mem + offset, buf, len);
	else
		memcpy(buf, buffer->cpu_mem + offset, len);

	return len;
}

static const struct vm_operations_struct buf_vm_ops = {
	.access = buf_access,
};

void buf_insert(struct mutex *lock, struct list_head *head,
		struct codec_dma_buf *buf)
{
	mutex_lock(lock);
	list_add(&buf->list, head);
	mutex_unlock(lock);
}

void buf_remove(struct mutex *lock, struct codec_dma_buf *buf)
{
	mutex_lock(lock);
	list_del(&buf->list);
	mutex_unlock(lock);
}

struct codec_dma_buf *buf_lookup(struct mutex *lock,
				 struct list_head *head,
				 dma_addr_t dma_handle, bool remove)
{
	struct codec_dma_buf *res = NULL;
	struct codec_dma_buf *buf;

	mutex_lock(lock);
	list_for_each_entry(buf, head, list) {
		if (buf->dma_handle != dma_handle)
			continue;
		res = buf;
		break;
	}

	if(res != NULL && remove)
		list_del(&res->list);

	mutex_unlock(lock);

	return res;
}

inline void buf_free_dma_coherent(struct device *dev, struct codec_dma_buf *buf)
{
	dma_free_coherent(dev, buf->size, buf->cpu_mem,
						buf->dma_handle);
}

void buf_cleanup_list(struct mutex *lock, struct list_head *head,
		      struct device *dev)
{
	struct codec_dma_buf *buf;
	struct codec_dma_buf *next;

	mutex_lock(lock);
	list_for_each_entry_safe(buf, next, head, list) {
			dma_free_coherent(dev, buf->size, buf->cpu_mem,buf->dma_handle);
			list_del(&buf->list);
			kfree(buf);
	}
	mutex_unlock(lock);
}

int buf_map(struct mutex *lock, struct list_head *head,
	    struct vm_area_struct *vma, struct device *dev)
{
	unsigned long vsize = vma->vm_end - vma->vm_start;
	struct codec_dma_buf *buf;
	dma_addr_t key;
	int ret;

	key = vma->vm_pgoff << PAGE_SHIFT;
	buf = buf_lookup(lock, head, key, false);
	dev_dbg(dev, "buf lookup into driver -> %p", buf);
	if (!buf)
		return -EINVAL;

	vma->vm_pgoff = 0;
	ret = dma_mmap_coherent(dev, vma, buf->cpu_mem,
				buf->dma_handle, vsize);

	if (ret < 0)
		return ret;

	vma->vm_ops = &buf_vm_ops;
	vma->vm_private_data = buf;

	return 0;
}
