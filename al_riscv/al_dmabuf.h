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

#ifndef __AL_DMABUF__
#define __AL_DMABUF__ 1

#include <linux/dma-mapping.h>
#include "al_buf.h"
#include "al_riscv_drv_common.h"

struct dma_buf *codec_dmabuf_wrap(struct device *dev, size_t size,
								struct codec_dma_buf *buffer,
								struct codec_client *client);

#endif
