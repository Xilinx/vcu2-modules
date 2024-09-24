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

#ifndef __ENC_UAPI__
#define __ENC_UAPI__ 1

struct codec_cmd_reply {
	uint16_t req_size;
	uint16_t reply_size;
	void *req;
	void *reply;
};

struct codec_dma_info {
	uint64_t phy_addr;
	uint64_t offset;
	uint32_t size;
	int32_t fd;
};

struct codec_event {
	uint32_t type;
	void *event;
};

struct codec_fw_info {
	uint32_t version;
};

#define CODEC_FW_CMD_REPLY      _IOWR('c', 1, struct codec_cmd_reply)
#define CODEC_DMA_ALLOC         _IOWR('c', 2, struct codec_dma_info)
#define CODEC_DMA_FREE          _IOWR('c', 3, struct codec_dma_info)
#define CODEC_GET_EVENT         _IOWR('c', 4, struct codec_event)
#define CODEC_DMA_FREE_MCU      _IOWR('c', 5, struct codec_dma_info)
#define CODEC_DMA_ALLOC_WITH_FD _IOWR('c', 6, struct codec_dma_info)
#define CODEC_DMA_GET_PHY       _IOWR('c', 7, struct codec_dma_info)
#define CODEC_GET_FW_INFO       _IOR('c', 8, struct codec_fw_info)

#endif
