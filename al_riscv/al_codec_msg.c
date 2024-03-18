/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#include "al_codec_msg.h"

#include <linux/errno.h>
#include <linux/jiffies.h>

/* add locks */

int codec_msg_get_header(struct codec_mb *mb, struct msg_itf_header *hdr)
{
	return codec_mb_receive(mb, (char *)hdr, sizeof(*hdr));
}

int codec_msg_get_data(struct codec_mb *mb, char *data, int len)
{
	return codec_mb_receive(mb, data, len);
}

int codec_msg_send(struct codec_mb *mb, struct msg_itf_header *hdr,
		   void (*trigger)(void *), void *trigger_arg)
{
	unsigned long timeout;
	int ret;

	mutex_lock(&mb->lock);
	timeout = jiffies + HZ;
	do {
		if (time_after(jiffies, timeout))
			return -ETIMEDOUT;
		ret = codec_mb_send(mb, (char *)hdr, hdr->payload_len +
				    sizeof(struct msg_itf_header));
	} while (ret);
	mutex_unlock(&mb->lock);

	trigger(trigger_arg);

	return 0;
}
