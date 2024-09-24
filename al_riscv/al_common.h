/* 
 * al_common.h Common functions used by encoder and decoder.
 *
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

#ifndef __AL_CODEC__
#define __AL_CODEC__ 1

#include <linux/delay.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>

#include "al_codec_mb.h"
#include "msg_common_itf.h"

struct al_common_dev {
	struct platform_device *pdev;
	void __iomem *regs;
	struct resource regs_info;
	void *fw_cpu_mem;
	dma_addr_t fw_phys_addr;
	size_t fw_size;
	uint32_t fw_version;
	unsigned long mcu_clk_rate;

	struct codec_mb mb_h2m;
	struct codec_mb mb_m2h;
	struct completion done;

	bool map_in_kernel;
	struct mutex dma_lock;
	struct list_head dma_buffers;

	bool (*mem_check)(struct al_common_dev *, dma_addr_t, size_t);

	/* callbacks set by client before common_probe */
	void *cb_arg;
	void (*process_msg_cb)(void *cb_arg, struct msg_itf_header *hdr);
	void (*fw_ready_cb)(void *cb_arg);
};

int al_common_probe(struct platform_device *pdev, struct al_common_dev *dev,
		    const char *fw_name, bool map_in_kernel);
int al_common_remove(struct al_common_dev *dev);
int al_common_get_header(struct al_common_dev *dev, struct msg_itf_header *hdr);
int al_common_get_data(struct al_common_dev *dev, char *data, int len);
int al_common_send(struct al_common_dev *dev, struct msg_itf_header *hdr);
void *common_dma_alloc(struct al_common_dev *dev, size_t size,
		       dma_addr_t *dma_handle, gfp_t flag);
int al_common_dma_buf_free(struct al_common_dev *dev, uint64_t phy_addr);
int al_common_dma_buf_map(struct al_common_dev *dev,
			  struct vm_area_struct *vma);

#endif
