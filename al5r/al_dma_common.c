/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/version.h>

#include "al_dma_common.h"

static int al5_access(struct vm_area_struct *vma, unsigned long addr,
		      void *buf, int len, int write)
{
	struct al5_dma_buffer *buffer = vma->vm_private_data;
	unsigned long offset = addr - vma->vm_start;
	unsigned long vm_size = vma->vm_end - vma->vm_start;

	if (!buffer->is_kernel_mapped)
		return -EINVAL;

	if (offset + len > vm_size)
		return -EINVAL;

	if (write)
		memcpy(buffer->cpu_handle + offset, buf, len);
	else
		memcpy(buf, buffer->cpu_handle + offset, len);

	return len;
}

static const struct vm_operations_struct al5_vm_ops = {
	.access = al5_access,
};

int al5_dma_common_mmap(struct device *dev, struct vm_area_struct *vma,
			struct al5_dma_buffer *buf)
{
	int ret;
	unsigned long start = vma->vm_start;
	unsigned long vsize = vma->vm_end - start;

	vma->vm_pgoff = 0;

	ret = dma_mmap_coherent(dev, vma, buf->cpu_handle,
				buf->dma_handle, vsize);
	if (ret < 0) {
		pr_err("Remapping memory failed, error: %d\n", ret);
		return ret;
	}

	vma->vm_private_data = buf;
	vma->vm_ops = &al5_vm_ops;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
#else
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
#endif
	return 0;
}



