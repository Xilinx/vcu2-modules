/******************************************************************************
*
* Copyright (C) 2026 Allegro DVT.  All rights reserved.
*
******************************************************************************/

#ifndef __CODEC_UAPI_IOCTL__
#define __CODEC_UAPI_IOCTL__ 1

#include <linux/types.h>
#include <linux/ioctl.h>
#include "codec_uapi_struct.h"

#define CODEC_FW_CMD_REPLY _IOWR('c', 1, struct codec_cmd_reply)
#define CODEC_DMA_ALLOC _IOWR('c', 2, struct codec_dma_info)
#define CODEC_DMA_FREE _IOWR('c', 3, struct codec_dma_info)
#define CODEC_GET_EVENT _IOWR('c', 4, struct codec_event)
#define CODEC_DMA_FREE_MCU _IOWR('c', 5, struct codec_dma_info)
#define CODEC_DMA_ALLOC_WITH_FD _IOWR('c', 6, struct codec_dma_info)
#define CODEC_DMA_GET_PHY _IOWR('c', 7, struct codec_dma_info)

/* FW Information */
#define CODEC_GET_FW_INFO _IOR('c', 8, struct codec_fw_info)

#endif /* __CODEC_UAPI_IOCTL__ */
