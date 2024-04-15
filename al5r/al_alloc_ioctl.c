/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#include "al_alloc_ioctl.h"
#include "al_alloc.h"

#include <linux/uaccess.h>
#include "al_dmabuf.h"

int al5_ioctl_get_dma_fd(struct device *dev, dma_addr_t dma_offset, unsigned long arg)
{
	struct al5_dma32_info info;
	int err;
	dma_addr_t bus_addr;

	if (copy_from_user(&info, (struct al5_dma32_info *)arg, sizeof(info)))
		return -EFAULT;

	err = al5_allocate_dmabuf(dev, info.size, &info.fd);
	if (err)
		return err;

	err = al5_dmabuf_get_address(dev, info.fd, &bus_addr);
	if (err)
		return err;

	info.phy_addr = bus_addr - dma_offset;

	if (copy_to_user((void *)arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

int al5_ioctl_get_dma64_fd(struct device *dev, dma_addr_t dma_offset, unsigned long arg)
{
	struct al5_dma64_info info;
	int err;
	dma_addr_t bus_addr;

	if (copy_from_user(&info, (struct al5_dma64_info *)arg, sizeof(info)))
		return -EFAULT;

	err = al5_allocate_dmabuf(dev, info.size, &info.fd);
	if (err)
		return err;

	err = al5_dmabuf_get_address(dev, info.fd, &bus_addr);
	if (err)
		return err;

	info.phy_addr = bus_addr;

	if (copy_to_user((void *)arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

int add_buffer_to_list(struct al5r_codec_chan *chan, struct al5_dma_buffer *buf)
{
	struct al5_dma_buf_mmap *buf_mmap = kmalloc(sizeof(*buf_mmap), GFP_KERNEL);

	if (!buf_mmap)
		return -1;
	buf_mmap->buf = buf;
	spin_lock(&chan->lock);
	list_add_tail(&buf_mmap->list, &chan->mem);
	buf_mmap->buf_id = chan->num_bufs++;
	spin_unlock(&chan->lock);
	return buf_mmap->buf_id;
}

int al5_ioctl_get_dma_mmap(struct device *dev, struct al5r_codec_chan *chan,
			   unsigned long arg)
{
	struct al5_dma32_info info;
	struct al5_dma_buffer *buf = NULL;
	dma_addr_t dma_offset = chan->codec->dma_offset;

	if (copy_from_user(&info, (struct al5_dma32_info *)arg, sizeof(info)))
		return -EFAULT;

	buf = al5_alloc_dma(dev, info.size);

	if (!buf) {
		dev_err(dev, "Can't alloc DMA buffer\n");
		return -ENOMEM;
	}

	info.fd = add_buffer_to_list(chan, buf);
	if (info.fd == -1)
		return -ENOMEM;
	/* offset for mmap needs to be a multiple of page size */
	info.fd = info.fd << PAGE_SHIFT;

	info.phy_addr = (__u32)(buf->dma_handle - dma_offset);

	pr_info("allocated buffer cpu: %p, phy:%d, offset:%d\n", buf->cpu_handle,
		info.phy_addr, info.fd);

	if (copy_to_user((void *)arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

int al5_ioctl_get_dma64_mmap(struct device *dev, struct al5r_codec_chan *chan,
			     unsigned long arg)
{
	struct al5_dma64_info info;
	struct al5_dma_buffer *buf = NULL;

	if (copy_from_user(&info, (struct al5_dma64_info *)arg, sizeof(info)))
		return -EFAULT;

	buf = al5_alloc_dma(dev, info.size);

	if (!buf) {
		dev_err(dev, "Can't alloc DMA buffer\n");
		return -ENOMEM;
	}

	info.fd = add_buffer_to_list(chan, buf);
	if (info.fd == -1)
		return -ENOMEM;
	/* offset for mmap needs to be a multiple of page size */
	info.fd = info.fd << PAGE_SHIFT;

	info.phy_addr = buf->dma_handle;

	pr_info("allocated buffer cpu: %p, phy:%llu, offset:%d\n", buf->cpu_handle,
		info.phy_addr, info.fd);

	if (copy_to_user((void *)arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

int al5_ioctl_get_dmabuf_dma_addr(struct device *dev, dma_addr_t dma_offset,
				  unsigned long arg)
{
	struct al5_dma32_info info;
	int err;
	dma_addr_t bus_addr;

	if (copy_from_user(&info, (struct al5_dma32_info *)arg, sizeof(info)))
		return -EFAULT;

	err = al5_dmabuf_get_address(dev, info.fd, &bus_addr);
	if (err)
		return err;

	info.phy_addr = bus_addr - dma_offset;

	if (copy_to_user((void *)arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}

int al5_ioctl_get_dmabuf_dma64_addr(struct device *dev, dma_addr_t dma_offset,
				    unsigned long arg)
{
	struct al5_dma64_info info;
	int err;
	dma_addr_t bus_addr;

	if (copy_from_user(&info, (struct al5_dma64_info *)arg, sizeof(info)))
		return -EFAULT;

	err = al5_dmabuf_get_address(dev, info.fd, &bus_addr);
	if (err)
		return err;

	info.phy_addr = bus_addr;

	if (copy_to_user((void *)arg, &info, sizeof(info)))
		return -EFAULT;

	return 0;
}
