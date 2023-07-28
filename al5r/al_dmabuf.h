/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#include <linux/device.h>
#include "al_alloc.h"

struct al5_buffer_info {
	u32 bus_address;
	u32 size;
};

int al5_create_dmabuf_fd(struct device *dev, size_t size, struct al5_dma_buffer *buffer);
int al5_allocate_dmabuf(struct device *dev, size_t size, u32 *fd);
int al5_dmabuf_get_address(struct device *dev, u32 fd, dma_addr_t *bus_address);

