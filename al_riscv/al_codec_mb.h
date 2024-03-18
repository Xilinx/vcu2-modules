/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#ifndef __AL_CODEC_MB__
#define __AL_CODEC_MB__ 1

#include <linux/mutex.h>
#include <linux/types.h>

#include "mb_itf.h"

struct codec_mb {
	struct mb_itf *hdr;
	char *data;
	int size;
	struct mutex lock;
};

void codec_mb_init(struct codec_mb *mb, char *addr, uint32_t magic, int size);
int codec_mb_send(struct codec_mb *mb, char *data, int len);
int codec_mb_receive(struct codec_mb *mb, char *data, int len);

#endif
