/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#include <linux/device.h>
#include "al_ip.h"

int al5_ioctl_get_dma_fd(struct device *dev, dma_addr_t dma_offset, unsigned long arg);
int al5_ioctl_get_dma64_fd(struct device *dev, dma_addr_t dma_offset, unsigned long arg);
int al5_ioctl_get_dmabuf_dma_addr(struct device *dev, dma_addr_t dma_offset,
				  unsigned long arg);
int al5_ioctl_get_dmabuf_dma64_addr(struct device *dev, dma_addr_t dma_offset,
				    unsigned long arg);
int al5_ioctl_get_dma_mmap(struct device *dev, struct al5r_codec_chan *chan,
			   unsigned long arg);
int al5_ioctl_get_dma64_mmap(struct device *dev, struct al5r_codec_chan *chan,
			     unsigned long arg);
