/******************************************************************************
*
* Copyright (C) 2026 Allegro DVT.  All rights reserved.
*
******************************************************************************/

/*
 * al_riscv_wrap_dec.c userspace wrapper for the decoder driver.
 */

#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/module.h>

#include "al_riscv_drv.h"

static const struct al_riscv_match_data ald3xx_data = {
	.fw_name = "ald3xx.fw",
	.default_device_name = "al_d3xx",
};

static const struct of_device_id al_riscv_dec_dt_match[] = {
	{ .compatible = "al,ald3xx", .data = &ald3xx_data },
	{}
};
MODULE_DEVICE_TABLE(of, al_riscv_dec_dt_match);

static struct platform_driver al_riscv_dec_driver = {
	.driver			= {
		.name		= "ald3_riscv",
		.of_match_table = of_match_ptr(al_riscv_dec_dt_match),
	},
	.probe			= codec_probe,
	.remove			= codec_remove,
};

module_platform_driver(al_riscv_dec_driver);

MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:ald3_riscv");
MODULE_AUTHOR("Mickael Guene <mickael.guene@allegrodvt.com>");
MODULE_DESCRIPTION("Allegro DVT RiscV decoder driver");
