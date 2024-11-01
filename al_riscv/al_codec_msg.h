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
