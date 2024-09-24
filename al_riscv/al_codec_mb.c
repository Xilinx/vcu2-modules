/* 
 * al_codec_mb.c mailbox mechanisms. r/w messages to/from the mcu
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

#include "al_codec_mb.h"

#include <linux/kernel.h>
#include <linux/string.h>

static int get_used_space(struct codec_mb *mb)
{
	uint32_t head = mb->hdr->head;
	uint32_t tail = mb->hdr->tail;

	return head >= tail ? head - tail : mb->size - (tail - head);
}

static int get_free_space(struct codec_mb *mb)
{
	return mb->size - get_used_space(mb) - 1;
}

static int has_enought_space(struct codec_mb *mb, int len)
{
	return get_free_space(mb) >= len;
}

static void copy_to_mb(struct codec_mb *mb, char *data, int len)
{
	uint32_t head = mb->hdr->head;
	int copy_len = min(mb->size - head, (unsigned int)len);
	int copied_len = len;

	memcpy(&mb->data[head], data, copy_len);
	len -= copy_len;
	if (len)
		memcpy(&mb->data[0], &data[copy_len], len);

	/* Be sure we wrote all message before updating head */
	dma_wmb();
	mb->hdr->head = (head + copied_len) % mb->size;
	/* Be sure we update head before going on */
	dma_wmb();
}

static void copy_from_mb(struct codec_mb *mb, char *data, int len)
{
	uint32_t tail = mb->hdr->tail;
	int copy_len = min(mb->size - tail, (unsigned int)len);
	int copied_len = len;

	if (!data)
		goto update_tail;

	memcpy(data, &mb->data[tail], copy_len);
	len -= copy_len;
	if (len)
		memcpy(&data[copy_len], &mb->data[0], len);

update_tail:
	mb->hdr->tail = (tail + copied_len) % mb->size;
	/* Be sure we update tail before going on */
	dma_wmb();
}

void codec_mb_init(struct codec_mb *mb, char *addr, uint32_t magic, int size)
{
	mb->hdr = (struct mb_itf *)addr;
	mb->hdr->magic = magic;
	mb->hdr->version = MB_IFT_VERSION;
	mb->hdr->head = 0;
	mb->hdr->tail = 0;
	mb->data = addr + sizeof(struct mb_itf);
	mb->size = size - sizeof(struct mb_itf);
	mutex_init(&mb->lock);
}

int codec_mb_send(struct codec_mb *mb, char *data, int len)
{
	if (!has_enought_space(mb, len))
		return -1;

	copy_to_mb(mb, data, len);

	return 0;
}

int codec_mb_receive(struct codec_mb *mb, char *data, int len)
{
	if (get_used_space(mb) < len)
		return -1;

	copy_from_mb(mb, data, len);

	return 0;
}
