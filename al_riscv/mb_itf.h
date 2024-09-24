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


#define MB_IFT_MAGIC_H2M      0xabcd1230
#define MB_IFT_MAGIC_M2H      0xabcd1231

#define MB_IFT_VERSION        0x00010000

struct mb_itf {
	uint32_t magic;
	uint32_t version;
	uint32_t head;
	uint32_t tail;
};
