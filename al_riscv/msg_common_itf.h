/******************************************************************************
*
* Copyright (C) 2019 Allegro DVT2.  All rights reserved.
*
******************************************************************************/

#ifndef __MSG_COMMON_ITF__
#define __MSG_COMMON_ITF__ 1

#define DECLARE_FULL_REQ(s) \
	struct s ## _full { \
		struct msg_itf_header hdr; \
		struct s req; \
	}

#define DECLARE_FULL_REPLY(s) \
	struct s ## _full { \
		struct msg_itf_header hdr; \
		struct s reply; \
	}

#define DECLARE_FULL_EVENT(s) \
	struct s ## _full { \
		struct msg_itf_header hdr; \
		struct s event; \
	}

enum {
	MSG_ITF_TYPE_FW_READY = 0,
	MSG_ITF_TYPE_CLIENT_LEAVE,
	MSG_ITF_TYPE_WRITE_REQ,
	MSG_ITF_TYPE_NEXT,
	MSG_ITF_TYPE_FIRST_REQ = 1024,
	MSG_ITF_TYPE_PERF_INFO_REQ = MSG_ITF_TYPE_FIRST_REQ,
	MSG_ITF_TYPE_NEXT_REQ,
	MSG_ITF_TYPE_FIRST_REPLY = 2048,
	MSG_ITF_TYPE_PERF_INFO_REPLY = MSG_ITF_TYPE_FIRST_REPLY,
	MSG_ITF_TYPE_NEXT_REPLY,
	MSG_ITF_TYPE_GET_CMA_REQ = 3072,
	MSG_ITF_TYPE_PUT_CMA_REQ,
	MSG_ITF_TYPE_GET_CMA_REPLY = 4096,
	MSG_ITF_TYPE_PUT_CMA_REPLY,
	MSG_ITF_TYPE_FIRST_EVT = 5120,
	MSG_ITF_TYPE_NEXT_EVT = MSG_ITF_TYPE_FIRST_EVT
};

/* padding is important here since it insure that sizeof(struct msg_itf_header)
 * as same value as get_size_struct_msg_itf_header(). This assertion is assumed
 * in driver and fw code.
 * Note that we want to avoid packed structure since riscv compiler will access
 * those struct byte per byte.
 */
struct msg_itf_header {
	uint64_t drv_client_hdl;
	uint64_t drv_cmd_hdl;
	uint16_t type;
	uint16_t payload_len;
	uint16_t padding[2];
};

struct msg_itf_get_cma_req {
	uint64_t uSize;
};
DECLARE_FULL_REQ(msg_itf_get_cma_req);

struct msg_itf_get_cma_reply {
	uint64_t phyAddr;
};
DECLARE_FULL_REPLY(msg_itf_get_cma_reply);

struct msg_itf_put_cma_req {
	uint64_t phyAddr;
};
DECLARE_FULL_REQ(msg_itf_put_cma_req);

struct msg_itf_put_cma_reply {
	int64_t ret;
};
DECLARE_FULL_REPLY(msg_itf_put_cma_reply);

struct msg_itf_perf_info_req {
	uint8_t isProfile;
};
DECLARE_FULL_REQ(msg_itf_perf_info_req);

struct msg_itf_perf_info_reply {
	uint64_t offset;
	uint32_t size;
};
DECLARE_FULL_REPLY(msg_itf_perf_info_reply);

struct msg_itf_write_req {
	int32_t fd;
	int32_t len;
	/* payload follow */
};
DECLARE_FULL_REQ(msg_itf_write_req);

#endif
