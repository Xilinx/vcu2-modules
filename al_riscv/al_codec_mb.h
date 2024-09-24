/* 
 * al_codec_mb.h mailbox mechanisms. r/w messages to/from the mcu
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
