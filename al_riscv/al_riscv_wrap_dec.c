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

MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:ald3_riscv");
MODULE_AUTHOR("Mickael Guene <mickael.guene@allegrodvt.com>");
MODULE_DESCRIPTION("Allegro DVT RiscV decoder driver");
