/*
 * al_riscv_wrap_dec.c userspace wrapper for the decoder driver. 
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

#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/module.h>

#include "al_riscv_drv_common.h"

static const al_riscv_device_data ald3xx_data = {
	.fw_name		= "ald3xx.fw",
	.default_device_name	= "al_d3xx",
};

static const struct of_device_id al_riscv_dec_dt_match[] = {
	{
		.compatible = "al,ald3xx",
		.data = &ald3xx_data
	},
	{}
};
MODULE_DEVICE_TABLE(of, al_riscv_dec_dt_match);

static struct platform_driver al_riscv_dec_driver = {
	.driver			= {
		.name		= "ald3_riscv",
		.of_match_table = of_match_ptr(al_riscv_dec_dt_match),
	},
	.probe			= al_riscv_codec_probe,
	.remove			= al_riscv_codec_remove,
};

module_platform_driver(al_riscv_dec_driver);

MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:ald3_riscv");
MODULE_AUTHOR("Mickael Guene <mickael.guene@allegrodvt.com>");
MODULE_DESCRIPTION("Allegro DVT RiscV decoder driver");
