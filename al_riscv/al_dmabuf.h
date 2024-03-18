/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#ifndef __AL_DMABUF__
#define __AL_DMABUF__ 1

#include <linux/dma-mapping.h>
#include "al_buf.h"
#include "al_riscv_drv.h"

struct dma_buf *codec_dmabuf_wrap(struct device *dev, size_t size,
								struct codec_dma_buf *buffer,
								struct codec_client *client);

#endif