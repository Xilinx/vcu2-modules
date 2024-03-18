/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/


#define MB_IFT_MAGIC_H2M      0xabcd1230
#define MB_IFT_MAGIC_M2H      0xabcd1231

#define MB_IFT_VERSION        0x00010000

struct mb_itf {
	uint32_t magic;
	uint32_t version;
	uint32_t head;
	uint32_t tail;
};
