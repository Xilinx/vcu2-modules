/******************************************************************************
*
* Copyright (C) 2026 Allegro DVT.  All rights reserved.
*
******************************************************************************/

/*
 * al_riscv_wrap_enc.c userspace wrapper for the encoder driver.
 */

#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/module.h>

#include "al_riscv_drv.h"

static const struct al_riscv_match_data ale2xx_data = {
	.fw_name = "ale2xx.fw",
	.default_device_name = "al_e2xx",
};

static const struct of_device_id al_riscv_enc_dt_match[] = {
	{ .compatible = "al,ale2xx", .data = &ale2xx_data },
	{}
};
MODULE_DEVICE_TABLE(of, al_riscv_enc_dt_match);

static struct platform_driver al_riscv_enc_driver = {
	.driver			= {
		.name		= "ale2_riscv",
		.of_match_table = of_match_ptr(al_riscv_enc_dt_match),
	},
	.probe			= codec_probe,
	.remove			= codec_remove,
};

module_platform_driver(al_riscv_enc_driver);

MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:ale2_riscv");
MODULE_AUTHOR("Mickael Guene <mickael.guene@allegrodvt.com>");
MODULE_DESCRIPTION("Allegro DVT RiscV encoder driver");
