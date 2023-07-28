/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#ifndef _AL_DMA_COMMON_H_
#define _AL_DMA_COMMON_H_

#include <linux/device.h>
#include <linux/mm_types.h>
#include "al_alloc.h"

int al5_dma_common_mmap(struct device *dev, struct vm_area_struct *vma,
			struct al5_dma_buffer *buf);

#endif /* _AL_DMA_COMMON_H_ */