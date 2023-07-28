/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#ifndef __AL_CODEC_MSG__
#define __AL_CODEC_MSG__ 1

#include <linux/types.h>
#include "msg_common_itf.h"
#include "al_codec_mb.h"

int codec_msg_get_header(struct codec_mb *mb, struct msg_itf_header *hdr);
int codec_msg_get_data(struct codec_mb *mb, char *data, int len);
int codec_msg_send(struct codec_mb *mb, struct msg_itf_header *hdr,
		   void (*trigger)(void *), void *trigger_arg);

#endif
