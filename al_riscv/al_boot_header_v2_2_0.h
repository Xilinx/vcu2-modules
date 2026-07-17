/******************************************************************************
*
* Copyright (C) 2026 Allegro DVT.  All rights reserved.
*
******************************************************************************/


/* Boot header structure in firmware */
struct tBootHeader_v2_2_0 {
	/* Info used by driver */
	uint32_t bh_version;
	uint32_t fw_version;
	char model[16];
	uint64_t vaddr_start;
	uint64_t vaddr_end;
	uint64_t boot_addr;
	struct mb_header h2m;
	struct mb_header m2h;
	uint64_t machine_id;

	/* Filled by driver before fw boot */
	uint64_t ip_start;
	uint64_t ip_end;
	uint64_t mcu_clk_rate;

	uint32_t mb_version;
	uint8_t mcu_id;
	struct imb_boot imb_info;
} __packed;

/******************************************************************************
 * BOOT_HEADER ACCESSORS
 *****************************************************************************/
static uint32_t get_boot_header_v2_2_0_fw_version(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->fw_version;
}
static inline char *get_boot_header_v2_2_0_model(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->model;
}
static uint64_t get_boot_header_v2_2_0_vaddr_start(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->vaddr_start;
}
static uint64_t get_boot_header_v2_2_0_vaddr_end(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->vaddr_end;
}
static uint64_t get_boot_header_v2_2_0_boot_addr(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->boot_addr;
}
static struct mb_header get_boot_header_v2_2_0_h2m(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->h2m;
}
static struct mb_header get_boot_header_v2_2_0_m2h(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->m2h;
}
static uint64_t get_boot_header_v2_2_0_machine_id(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->machine_id;
}
static uint64_t get_boot_header_v2_2_0_ip_start(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->ip_start;
}
static uint64_t get_boot_header_v2_2_0_ip_end(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->ip_end;
}
static uint64_t get_boot_header_v2_2_0_mcu_clk_rate(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->mcu_clk_rate;
}
static uint32_t get_boot_header_v2_2_0_mb_version(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->mb_version;
}
static uint8_t get_boot_header_v2_2_0_mcu_id(const union boot_header *bh)
{
	return ((struct tBootHeader_v2_2_0 *)bh)->mcu_id;
}
static struct imb_boot *
get_boot_header_v2_2_0_imb_info(const union boot_header *bh)
{
	return &((struct tBootHeader_v2_2_0 *)bh)->imb_info;
}
static void set_boot_header_v2_2_0_mcu_id(const union boot_header *bh,
					  uint8_t mcu_id)
{
	((struct tBootHeader_v2_2_0 *)bh)->mcu_id = mcu_id;
}
static void set_boot_header_v2_2_0_ip_start(const union boot_header *bh,
					    uint64_t ip_start)
{
	((struct tBootHeader_v2_2_0 *)bh)->ip_start = ip_start;
}
static void set_boot_header_v2_2_0_ip_end(const union boot_header *bh,
					  uint64_t ip_end)
{
	((struct tBootHeader_v2_2_0 *)bh)->ip_end = ip_end;
}
static void set_boot_header_v2_2_0_mcu_clk_rate(const union boot_header *bh,
						uint64_t mcu_clk_rate)
{
	((struct tBootHeader_v2_2_0 *)bh)->mcu_clk_rate = mcu_clk_rate;
}
static uint32_t get_boot_header_v2_2_0_size(void)
{
	return sizeof(struct tBootHeader_v2_2_0);
}

void set_v2_2_0_boot_header(struct boot_header_vtable *vbh)
{
	vbh->get_boot_header_fw_version = get_boot_header_v2_2_0_fw_version;
	vbh->get_boot_header_model = get_boot_header_v2_2_0_model;
	vbh->get_boot_header_vaddr_start = get_boot_header_v2_2_0_vaddr_start;
	vbh->get_boot_header_vaddr_end = get_boot_header_v2_2_0_vaddr_end;
	vbh->get_boot_header_boot_addr = get_boot_header_v2_2_0_boot_addr;
	vbh->get_boot_header_h2m = get_boot_header_v2_2_0_h2m;
	vbh->get_boot_header_m2h = get_boot_header_v2_2_0_m2h;
	vbh->get_boot_header_machine_id = get_boot_header_v2_2_0_machine_id;
	vbh->get_boot_header_ip_start = get_boot_header_v2_2_0_ip_start;
	vbh->get_boot_header_ip_end = get_boot_header_v2_2_0_ip_end;
	vbh->get_boot_header_mcu_clk_rate = get_boot_header_v2_2_0_mcu_clk_rate;
	vbh->get_boot_header_mb_version = get_boot_header_v2_2_0_mb_version;
	vbh->get_boot_header_mcu_id = get_boot_header_v2_2_0_mcu_id;
	vbh->get_boot_header_imb_info = get_boot_header_v2_2_0_imb_info;
	vbh->set_boot_header_mcu_id = set_boot_header_v2_2_0_mcu_id;
	vbh->set_boot_header_ip_start = set_boot_header_v2_2_0_ip_start;
	vbh->set_boot_header_ip_end = set_boot_header_v2_2_0_ip_end;
	vbh->set_boot_header_mcu_clk_rate = set_boot_header_v2_2_0_mcu_clk_rate;
	vbh->get_boot_header_size = get_boot_header_v2_2_0_size;
}
