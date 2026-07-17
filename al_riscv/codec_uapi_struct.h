/******************************************************************************
*
* Copyright (C) 2026 Allegro DVT.  All rights reserved.
*
******************************************************************************/

#ifndef __CODEC_UAPI_STRUCTS__
#define __CODEC_UAPI_STRUCTS__ 1

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

#endif /* __CODEC_UAPI_STRUCTS__ */
