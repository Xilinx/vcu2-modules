/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

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
};

struct codec_event {
	uint32_t type;
	void *event;
};

#define CODEC_FW_CMD_REPLY      _IOWR('c', 1, struct codec_cmd_reply)
#define CODEC_DMA_ALLOC         _IOWR('c', 2, struct codec_dma_info)
#define CODEC_DMA_FREE          _IOWR('c', 3, struct codec_dma_info)
#define CODEC_GET_EVENT         _IOWR('c', 4, struct codec_event)
#define CODEC_DMA_FREE_MCU      _IOWR('c', 5, struct codec_dma_info)

#endif
