ispace - Coding Assessment
===
<p align="right">Jonathan Liang<br/>2024-Dec-06</p>

Repo Structure
---
```
.
├── test
│   ├── component_test_cpp
│   ├── unit_test.cpp
├── CMakeLists.txt
├── README.md
├── spp_parser.c
└── spp.h
```
* [https://github.com/jonathanyhliang/spp](https://github.com/jonathanyhliang/spp)
* `README.md`: 
  * This file.
* `spp_parser.c`: 
  * Implememtation of Protocol Data Unit (PDU) parser of Space Packet Protocal (SPP). Possible APIDs are configured statically as singly linked list nodes which each node is linked when calling spp_init().
* `spp.h`: 
  * Macros/helpers for parsing PDU, PDU data structure, APID configuration data structure, SPP parser context data structure, error messages/codes.
* `CMakeLists.txt`:
  * CMake scripts that fetch googletest framework and link test executables/libraries.
* `test/unit_test.cpp`: 
  * Unit-level test cases.
* `test/component_test.cpp`:
  * Component-level test cases.

spp_parser.c
---
```c
#include <errno.h>
#include "spp.h"

int spp_apid_data_parser(const struct spp_pdu *pdu);
static struct spp_apid_cfg apid_0_cfg =   { .apid = 0, .sec_hdr_flag = 1,
										    .data_parser = spp_apid_data_parser,
											.next = NULL };
static struct spp_apid_cfg apid_1_cfg =   { .apid = 1, .sec_hdr_flag = 1,
										    .data_parser = spp_apid_data_parser,
											.next = NULL };
static struct spp_apid_cfg apid_2_cfg =   { .apid = 2, .sec_hdr_flag = 1,
										    .data_parser = spp_apid_data_parser,
											.next = NULL };
static struct spp_apid_cfg apid_256_cfg = { .apid = 256, .sec_hdr_flag = 1,
										    .data_parser = spp_apid_data_parser,
											.next = NULL };
static struct spp_apid_cfg apid_257_cfg = { .apid = 257, .sec_hdr_flag = 1,
										    .data_parser = spp_apid_data_parser,
											.next = NULL };
static struct spp_apid_cfg apid_258_cfg = { .apid = 258, .sec_hdr_flag = 1,
										    .data_parser = spp_apid_data_parser,
											.next = NULL };
static struct spp_apid_cfg apid_512_cfg = { .apid = 512, .sec_hdr_flag = 1,
										    .data_parser = spp_apid_data_parser,
											.next = NULL };
static struct spp_apid_cfg apid_513_cfg = { .apid = 513, .sec_hdr_flag = 1,
										    .data_parser = spp_apid_data_parser,
											.next = NULL };
static struct spp_apid_cfg apid_514_cfg = { .apid = 514, .sec_hdr_flag = 1,
										    .data_parser = spp_apid_data_parser,
											.next = NULL };

static inline uint16_t sys_get_be16(const uint8_t src[2])
{
	return ((uint16_t)src[0] << 8) | src[1];
}

int spp_append_apid_cfg(struct spp_apid_cfg *tail, struct spp_apid_cfg *new_node)
{
	if (tail == NULL) {
		printf("error: spp_append_apid_cfg_node: invalid argument(tail)\n");
		return -EINVAL;
	}

	if (new_node == NULL) {
		printf("error: spp_append_apid_cfg_node: invalid argument(new_node)\n");
		return -EINVAL;
	}

	tail->next = new_node;

	return 0;
}

struct spp_apid_cfg *spp_get_apid_cfg(const struct spp_ctx *ctx)
{
	struct spp_apid_cfg *cfg;

	if (ctx == NULL) {
		printf("error: spp_get_apid_cfg: invalid argument(ctx)\n");
		return NULL;
	}
	
	cfg = ctx->apid_cfg_list;
	while (cfg != NULL) {
		if (ctx->pdu.apid == cfg->apid) {
			return cfg;
		}
		cfg = cfg->next;
	}

	return NULL;
}

int spp_apid_data_parser(const struct spp_pdu *pdu)
{
	uint16_t sec_hdr;
	int ret = 0;

	if (pdu == NULL) {
		printf("error: spp_apid_data_parser: invalid argument\n");
		return -EINVAL;
	}
	
	sec_hdr = sys_get_be16(pdu->data);
	switch (sec_hdr) {
	case 0:
		if (pdu->data_len != 1) {
			printf("error: spp_apid_data_parser: %s %d [%d]\n",
				ERR_MSG_SPP_PKT_DATA_LEN,
				pdu->data_len,
				-ERR_CODE_SPP_PKT_DATA_LEN);
			ret = -ERR_CODE_SPP_PKT_DATA_LEN;
			break;
		}
		printf("the payload %d receives NOOP.\n", pdu->apid);
		ret = 0;
		break;
	
	case 256:
		if (pdu->data_len != 2) {
			printf("error: spp_apid_data_parser: %s %d [%d]\n",
				ERR_MSG_SPP_PKT_DATA_LEN,
				pdu->data_len,
				-ERR_CODE_SPP_PKT_DATA_LEN);
			ret = -ERR_CODE_SPP_PKT_DATA_LEN;
			break;
		}

		if (pdu->data[2] > 15U) {
			printf("error: spp_apid_data_parser: %s %d [%d]\n",
				ERR_MSG_USR_REG_ID,
				pdu->data[2],
				-ERR_CODE_USR_REG_ID);
			ret = -ERR_CODE_USR_REG_ID;
			break;
		}

		printf("the register %d of the payload %d is read.\n", pdu->data[2],
		       pdu->apid);
		ret = 0;
		break;

	case 257:
		if (pdu->data_len != 3) {
			printf("error: spp_apid_data_parser: %s %d [%d]\n",
				ERR_MSG_SPP_PKT_DATA_LEN,
				pdu->data_len,
				-ERR_CODE_SPP_PKT_DATA_LEN);
			ret = -ERR_CODE_SPP_PKT_DATA_LEN;
			break;
		}

		if (pdu->data[2] > 15U) {
			printf("error: spp_apid_data_parser: %s %d [%d]\n",
				ERR_MSG_USR_REG_ID,
				pdu->data[2],
				-ERR_CODE_USR_REG_ID);
			ret = -ERR_CODE_USR_REG_ID;
			break;
		}

		printf("the register %d of the payload %d is set to %d.\n", pdu->data[2],
		       pdu->apid, pdu->data[3]);
		ret = 0;
		break;

	default:
		printf("error: spp_apid_data_parser: %s %d [%d]\n",
				ERR_MSG_USR_SEC_HDR,
				sec_hdr,
				-ERR_CODE_USR_SEC_HDR);
		ret = -ERR_CODE_USR_SEC_HDR;
		break;
	}

	return ret;
}

int spp_pdu_parser(struct spp_ctx *ctx, const uint8_t *buf, const int buf_len)
{
	uint16_t temp;
	struct spp_apid_cfg *apid_cfg;
	int ret;

	if (ctx == NULL) {
		printf("error: spp_pdu_parser: invalid argument(ctx)\n");
		return -EINVAL;
	}

	if (buf == NULL) {
		printf("error: spp_pdu_parser: invalid argument(buf)\n");
		return -EINVAL;
	}
	
	if (buf_len < SPP_PACKET_MIN_LENGTH) {
		printf("error: spp_pdu_parser: %s [%d]\n",
				ERR_MSG_SPP_PKT_LEN,
				-ERR_CODE_SPP_PKT_LEN);
		return -ERR_CODE_SPP_PKT_LEN;
	}
	
	temp = sys_get_be16(buf);
	ctx->pdu.ver = SPP_GET_PACKET_VER(temp);
	ctx->pdu.type = SPP_GET_PACKET_TYPE(temp);
	ctx->pdu.sec_hdr_flag = SPP_GET_PACKET_SEC_FLAG(temp);
	ctx->pdu.apid = SPP_GET_PACKET_APID(temp);

	temp = sys_get_be16(buf + 2);
	ctx->pdu.seq_flags = SPP_GET_PACKET_SEQ_FLAGS(temp);
	ctx->pdu.seq_id = SPP_GET_PACKET_SEQ_ID(temp);
	ctx->pdu.data_len = (int)sys_get_be16(buf + 4);
	ctx->pdu.data = (buf + 6);

	if (ctx->pdu.ver != SPP_PACKET_VER) {
		printf("error: spp_pdu_parser: %s [%d]\n",
				ERR_MSG_SPP_PKT_VER,
				-ERR_CODE_SPP_PKT_VER);
		return -ERR_CODE_SPP_PKT_VER;
	}

	if (ctx->pdu.data_len != (buf_len - SPP_PACKET_MIN_LENGTH)) {
		printf("error: spp_pdu_parser: %s [%d]\n",
				ERR_MSG_SPP_PKT_DATA_LEN,
				-ERR_CODE_SPP_PKT_DATA_LEN);
		return -ERR_CODE_SPP_PKT_DATA_LEN;
	}

	apid_cfg = spp_get_apid_cfg(ctx);
	if (apid_cfg == NULL) {
		printf("error: spp_pdu_parser: %s: %d [%d]\n",
				ERR_MSG_SPP_APID,
				ctx->pdu.apid,
				-ERR_CODE_SPP_APID);
		return -ERR_CODE_SPP_APID; 
	}

	if (ctx->pdu.sec_hdr_flag != apid_cfg->sec_hdr_flag) {
		printf("error: spp_pdu_parser: %s %d [%d]\n",
				ERR_MSG_SPP_SEC_HDR_FLAG,
				ctx->pdu.apid,
				-ERR_CODE_SPP_SEC_HDR_FLAG);
		return -ERR_CODE_SPP_SEC_HDR_FLAG; 
	}

	if (apid_cfg->data_parser != NULL) {
		ret = apid_cfg->data_parser(&ctx->pdu);
		if (ret < 0) {
			return ret;
		}
	}
	
	return 0;
}

struct spp_ctx *spp_init(void)
{
	static struct spp_ctx ctx;
	spp_append_apid_cfg(&apid_0_cfg, &apid_1_cfg);
	spp_append_apid_cfg(&apid_1_cfg, &apid_2_cfg);
	spp_append_apid_cfg(&apid_2_cfg, &apid_256_cfg);
	spp_append_apid_cfg(&apid_256_cfg, &apid_257_cfg);
	spp_append_apid_cfg(&apid_257_cfg, &apid_258_cfg);
	spp_append_apid_cfg(&apid_258_cfg, &apid_512_cfg);
	spp_append_apid_cfg(&apid_512_cfg, &apid_513_cfg);
	spp_append_apid_cfg(&apid_513_cfg, &apid_514_cfg);
	ctx.apid_cfg_list = &apid_0_cfg;
	return &ctx;
}

```

spp.h
---
```c
#ifndef _SPP_H_
#define _SPP_H_

#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#ifndef BSWAP_16
#define BSWAP_16(x) ((uint16_t) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))
#endif
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define sys_le16_to_cpu(val) (val)
#define sys_cpu_to_le16(val) (val)
#define sys_be16_to_cpu(val) BSWAP_16(val)
#define sys_cpu_to_be16(val) BSWAP_16(val)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define sys_le16_to_cpu(val) BSWAP_16(val)
#define sys_cpu_to_le16(val) BSWAP_16(val)
#define sys_be16_to_cpu(val) (val)
#define sys_cpu_to_be16(val) (val)
#elif
#error "__BYTE_ORDER__ is not defined and cannot be automatically resolved"
#endif

#ifndef BIT
#define BIT(n) (1UL << (n))
#endif

#ifndef BIT_MASK
#define BIT_MASK(n) (BIT(n) - 1UL)
#endif

/* 4.1.3.2 Packet Version Number
4.1.3.2.1 Bits 0–2 of the Packet Primary Header shall contain the (binary encoded) Packet
Version Number (PVN).
4.1.3.2.2 This 3-bit field shall identify the data unit as a Space Packet defined by this
Recommended Standard; it shall be set to ‘000’ */
#define SPP_PACKET_VER            (0b000)
#define SPP_PACKET_VER_MASK_SHIFT (13)
#define SPP_PACKET_VER_MASK       (BIT_MASK(3) << SPP_PACKET_VER_MASK_SHIFT)
#define SPP_GET_PACKET_VER(val)   ((val & SPP_PACKET_VER_MASK) >> SPP_PACKET_VER_MASK_SHIFT)

#define SPP_PACKET_TYPE_MASK_SHIFT (12)
#define SPP_PACKET_TYPE_MASK       (BIT_MASK(1) << SPP_PACKET_TYPE_MASK_SHIFT)
#define SPP_GET_PACKET_TYPE(val)   ((val & SPP_PACKET_TYPE_MASK) >> SPP_PACKET_TYPE_MASK_SHIFT)

#define SPP_PACKET_SEC_FLAG_MASK_SHIFT 	(11)
#define SPP_PACKET_SEC_FLAG_MASK       	(BIT_MASK(1) << SPP_PACKET_SEC_FLAG_MASK_SHIFT)
#define SPP_GET_PACKET_SEC_FLAG(val) 	((val & SPP_PACKET_SEC_FLAG_MASK) >> SPP_PACKET_SEC_FLAG_MASK_SHIFT)

#define SPP_PACKET_APID_MASK_SHIFT (0)
#define SPP_PACKET_APID_MASK       (BIT_MASK(11) << SPP_PACKET_APID_MASK_SHIFT)
#define SPP_GET_PACKET_APID(val)   ((val & SPP_PACKET_APID_MASK) >> SPP_PACKET_APID_MASK_SHIFT)

#define SPP_PACKET_SEQ_FLAG_MASK_SHIFT (14)
#define SPP_PACKET_SEQ_FLAG_MASK       (BIT_MASK(2) << SPP_PACKET_SEQ_FLAG_MASK_SHIFT)
#define SPP_GET_PACKET_SEQ_FLAGS(val)   ((val & SPP_PACKET_SEQ_FLAG_MASK) >> SPP_PACKET_SEQ_FLAG_MASK_SHIFT)

#define SPP_PACKET_SEQ_ID_MASK_SHIFT (0)
#define SPP_PACKET_SEQ_ID_MASK       (BIT_MASK(14) << SPP_PACKET_SEQ_ID_MASK_SHIFT)
#define SPP_GET_PACKET_SEQ_ID(val)   ((val & SPP_PACKET_SEQ_ID_MASK) >> SPP_PACKET_SEQ_ID_MASK_SHIFT)

#ifndef __ELASTERROR
#define __ELASTERROR 2000       /* Users can add values starting here */
#endif

/* 4.1.2.1 A Space Packet shall include the defined fields, positioned contiguously, in the
following sequence:
a) Packet Primary Header (6 octets, mandatory);
b) Packet Data Field (from 1 to 65536 octets, mandatory).
4.1.2.2 A Space Packet shall consist of at least 7 and at most 65542 octets. */
#define SPP_PACKET_MIN_LENGTH		(7)
#define ERR_MSG_SPP_PKT_LEN			"invalid packet length"
#define ERR_CODE_SPP_PKT_LEN		(__ELASTERROR + 1)

#define ERR_MSG_SPP_PKT_VER			"invalid packet version"
#define ERR_CODE_SPP_PKT_VER		(__ELASTERROR + 2)

#define ERR_MSG_SPP_APID			"unexpected packet apid"
#define ERR_CODE_SPP_APID			(__ELASTERROR + 3)

#define ERR_MSG_SPP_SEC_HDR_FLAG	"incompatible secondary header flag"
#define ERR_CODE_SPP_SEC_HDR_FLAG	(__ELASTERROR + 4)

#define ERR_MSG_USR_SEC_HDR			"unsupported secondary header"
#define ERR_CODE_USR_SEC_HDR		(__ELASTERROR + 5)

#define ERR_MSG_SPP_PKT_DATA_LEN	"invalid packet data length"
#define ERR_CODE_SPP_PKT_DATA_LEN	(__ELASTERROR + 6)

#define ERR_MSG_USR_REG_ID			"invalid register id"
#define ERR_CODE_USR_REG_ID			(__ELASTERROR + 7)

struct spp_pdu {
	uint8_t ver;
	uint8_t type;
	uint8_t sec_hdr_flag;
	uint16_t apid;
	uint8_t seq_flags;
	uint16_t seq_id;
	int data_len;
	const uint8_t *data;
};

typedef int (*packet_data_parser_t)(const struct spp_pdu *pdu);

struct spp_apid_cfg {
	const uint16_t apid;
	/* 4.1.3.3.3.3 The Secondary Header Flag shall be static with respect to
    the APID and managed data path throughout a Mission Phase.*/
	const uint8_t sec_hdr_flag;
	packet_data_parser_t data_parser;
	struct spp_apid_cfg *next;
};

struct spp_ctx {
	struct spp_apid_cfg *apid_cfg_list;
	struct spp_pdu pdu;
};

int spp_append_apid_cfg(struct spp_apid_cfg *tail, struct spp_apid_cfg *new_node);
struct spp_apid_cfg *spp_get_apid_cfg(const struct spp_ctx *ctx);
int spp_apid_data_parser(const struct spp_pdu *pdu);
int spp_pdu_parser(struct spp_ctx *ctx, const uint8_t *buf, const int buf_len);
struct spp_ctx *spp_init(void);

#endif /* _SPP_H_ */
```

unit_test.cpp
---
```c
#include <gtest/gtest.h>
extern "C" {
    #include "spp.h"
}

TEST(spp_unit_test, invalid_arg)
{
    struct spp_apid_cfg cfg = { };
    struct spp_ctx ctx;
    uint8_t header[7];
    EXPECT_EQ(spp_append_apid_cfg(NULL, &cfg), -EINVAL);
    EXPECT_EQ(spp_append_apid_cfg(&cfg, NULL), -EINVAL);
    EXPECT_EQ(spp_get_apid_cfg(NULL), NULL);
    EXPECT_EQ(spp_apid_data_parser(NULL), -EINVAL);
    EXPECT_EQ(spp_pdu_parser(NULL, header, 0), -EINVAL);
    EXPECT_EQ(spp_pdu_parser(&ctx, NULL, 0), -EINVAL);
}

TEST(spp_unit_test, append_apid_cfg)
{
    struct spp_apid_cfg apid_123 = { .apid = 123, .sec_hdr_flag = 1, .next = NULL };
    struct spp_apid_cfg apid_456 = { .apid = 456, .sec_hdr_flag = 1, .next = NULL };
    struct spp_ctx ctx;
    EXPECT_EQ(spp_append_apid_cfg(&apid_123, &apid_456), 0);
    ctx.apid_cfg_list = &apid_123;
    EXPECT_EQ(ctx.apid_cfg_list->apid, 123);
    EXPECT_EQ(ctx.apid_cfg_list->next->apid, 456);
}

TEST(spp_unit_test, apid_data_parser_pass)
{
    // command code = 0 (NOOP)
    const uint8_t a[2] = {0x00, 0x00};
    struct spp_pdu pdu_a = { .apid = 256, .data_len = 1, .data = a };
    EXPECT_EQ(spp_apid_data_parser(&pdu_a), 0);

    // command code = 256 (READ REGISTER), reg id = 15
    const uint8_t b[3] = {0x01, 0x00, 15};
    struct spp_pdu pdu_b = { .apid = 2, .data_len = 2, .data = b };
    EXPECT_EQ(spp_apid_data_parser(&pdu_b), 0);

    // command code = 257 (WRITE REGISTER), reg id = 7, reg val = 250
    const uint8_t c[4] = {0x01, 0x01, 7, 250};
    struct spp_pdu pdu_c = { .apid = 1, .data_len = 3, .data = c };
    EXPECT_EQ(spp_apid_data_parser(&pdu_c), 0);
}

TEST(spp_unit_test, apid_data_parser_unsupported)
{
    // command code = 1 (unsupported)
    const uint8_t a[2] = {0x00, 0x01};
    struct spp_pdu pdu_a = { .apid = 256, .data_len = 1, .data = a };
    EXPECT_EQ(spp_apid_data_parser(&pdu_a), -ERR_CODE_USR_SEC_HDR);
}

TEST(spp_unit_test, apid_data_parser_insufficient_data)
{
    // command code = 0 (NOOP)
    const uint8_t a[1] = {0x00};
    struct spp_pdu pdu_a = { .apid = 256, .data_len = 0, .data = a };
    EXPECT_EQ(spp_apid_data_parser(&pdu_a), -ERR_CODE_USR_SEC_HDR);

    // command code = 256 (READ REGISTER)
    const uint8_t b[2] = {0x01, 0x00};
    struct spp_pdu pdu_b = { .apid = 2, .data_len = 1, .data = b };
    EXPECT_EQ(spp_apid_data_parser(&pdu_b), -ERR_CODE_SPP_PKT_DATA_LEN);

    // command code = 257 (WRITE REGISTER), reg id = 7
    const uint8_t c[3] = {0x01, 0x01, 7};
    struct spp_pdu pdu_c = { .apid = 1, .data_len = 2, .data = c };
    EXPECT_EQ(spp_apid_data_parser(&pdu_c), -ERR_CODE_SPP_PKT_DATA_LEN);
}

TEST(spp_unit_test, apid_data_parser_excessive_data)
{
    // command code = 0 (NOOP)
    const uint8_t a[3] = {0x00, 0x00, 0x00};
    struct spp_pdu pdu_a = { .apid = 256, .data_len = 2, .data = a };
    EXPECT_EQ(spp_apid_data_parser(&pdu_a), -ERR_CODE_SPP_PKT_DATA_LEN);

    // command code = 256 (READ REGISTER), reg id = 15
    const uint8_t b[4] = {0x01, 0x00, 15, 0x00};
    struct spp_pdu pdu_b = { .apid = 2, .data_len = 3, .data = b };
    EXPECT_EQ(spp_apid_data_parser(&pdu_b), -ERR_CODE_SPP_PKT_DATA_LEN);

    // command code = 257 (WRITE REGISTER), reg id = 7, reg val = 250
    const uint8_t c[5] = {0x01, 0x01, 7, 250, 0x00};
    struct spp_pdu pdu_c = { .apid = 1, .data_len = 4, .data = c };
    EXPECT_EQ(spp_apid_data_parser(&pdu_c), -ERR_CODE_SPP_PKT_DATA_LEN);
}

TEST(spp_unit_test, apid_data_parser_out_of_range)
{
    // command code = 256 (READ REGISTER), reg id = 16
    const uint8_t b[3] = {0x01, 0x00, 16};
    struct spp_pdu pdu_b = { .apid = 2, .data_len = 2, .data = b };
    EXPECT_EQ(spp_apid_data_parser(&pdu_b), -ERR_CODE_USR_REG_ID);

    // command code = 257 (WRITE REGISTER), reg id = 16, reg val = 250
    const uint8_t c[4] = {0x01, 0x01, 16, 250};
    struct spp_pdu pdu_c = { .apid = 1, .data_len = 3, .data = c };
    EXPECT_EQ(spp_apid_data_parser(&pdu_c), -ERR_CODE_USR_REG_ID);
}

TEST(spp_unit_test, spp_pdu_parser_prim_hdr)
{
    struct spp_ctx ctx;
    // packet version = 0b101
    // packet type = 0b1
    // secondary header flag = 0b1
    // apid = 512
    // sequence flag = 0b10
    // sequence id = 256
    // data length = 1
    // data[3] = {0x2, 0x3}
    const uint8_t buf[9] = { 0b10111010, 0b00000000, 0b10000001, 0b00000000,
                                0x0, 0x1, 0x2, 0x3 };
    spp_pdu_parser(&ctx, buf, sizeof(buf) / sizeof(buf[0]));
    EXPECT_EQ(ctx.pdu.ver, 0b101);
    EXPECT_EQ(ctx.pdu.type, 0b1);
    EXPECT_EQ(ctx.pdu.sec_hdr_flag, 0b1);
    EXPECT_EQ(ctx.pdu.apid, 512);
    EXPECT_EQ(ctx.pdu.seq_flags, 0b10);
    EXPECT_EQ(ctx.pdu.seq_id, 256);
    EXPECT_EQ(ctx.pdu.data_len, 1);
    EXPECT_EQ(ctx.pdu.data[0], 2);
    EXPECT_EQ(ctx.pdu.data[1], 3);
}

class spp_unit_test_f : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ctx = spp_init();
    }

    struct spp_ctx *ctx;
};

TEST_F(spp_unit_test_f, get_apid_cfg_pass)
{
    struct spp_apid_cfg *cfg;
    ctx->pdu.sec_hdr_flag = 1;

    ctx->pdu.apid = 0;
    cfg = spp_get_apid_cfg(ctx);
    EXPECT_NE(cfg, NULL);
    EXPECT_EQ(ctx->pdu.apid, cfg->apid);

    ctx->pdu.apid = 1;
    cfg = spp_get_apid_cfg(ctx);
    EXPECT_NE(cfg, NULL);
    EXPECT_EQ(ctx->pdu.apid, cfg->apid);
    
    ctx->pdu.apid = 2;
    cfg = spp_get_apid_cfg(ctx);
    EXPECT_NE(cfg, NULL);
    EXPECT_EQ(ctx->pdu.apid, cfg->apid);
    
    ctx->pdu.apid = 256;
    cfg = spp_get_apid_cfg(ctx);
    EXPECT_NE(cfg, NULL);
    EXPECT_EQ(ctx->pdu.apid, cfg->apid);
    
    ctx->pdu.apid = 257;
    cfg = spp_get_apid_cfg(ctx);
    EXPECT_NE(cfg, NULL);
    EXPECT_EQ(ctx->pdu.apid, cfg->apid);
    
    ctx->pdu.apid = 258;
    cfg = spp_get_apid_cfg(ctx);
    EXPECT_NE(cfg, NULL);
    EXPECT_EQ(ctx->pdu.apid, cfg->apid);
    
    ctx->pdu.apid = 512;
    cfg = spp_get_apid_cfg(ctx);
    EXPECT_NE(cfg, NULL);
    EXPECT_EQ(ctx->pdu.apid, cfg->apid);
    
    ctx->pdu.apid = 513;
    cfg = spp_get_apid_cfg(ctx);
    EXPECT_NE(cfg, NULL);
    EXPECT_EQ(ctx->pdu.apid, cfg->apid);
    
    ctx->pdu.apid = 514;
    cfg = spp_get_apid_cfg(ctx);
    EXPECT_NE(cfg, NULL);
    EXPECT_EQ(ctx->pdu.apid, cfg->apid);
}

TEST_F(spp_unit_test_f, get_apid_cfg_fail)
{
    struct spp_apid_cfg *cfg;
    ctx->pdu.sec_hdr_flag = 1;
    ctx->pdu.apid = 1024;
    cfg = spp_get_apid_cfg(ctx);
    EXPECT_EQ(cfg, NULL);
}

TEST_F(spp_unit_test_f, spp_pdu_parser_invalid_pkt_ver)
{
    // packet version = 0b001 (invalid)
    // packet type = 0b0
    // secondary header flag = 0b1
    // apid = 512
    // sequence flag = 0b00
    // sequence count = 0
    // data length = 2
    // data[3] = {0x1, 0x0, 0x7}
    const uint8_t buf[9] = { 0b00101010, 0b00000000, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 0x7 };
    EXPECT_EQ(spp_pdu_parser(ctx, buf, sizeof(buf) / sizeof(buf[0])),
                                -ERR_CODE_SPP_PKT_VER);
}

TEST_F(spp_unit_test_f, spp_pdu_parser_insufficient_length)
{
    const uint8_t buf[6] = { 0b00001010, 0b00000000, 0x0, 0x0, 0x0, 0x0};
    EXPECT_EQ(spp_pdu_parser(ctx, buf, sizeof(buf) / sizeof(buf[0])),
                                -ERR_CODE_SPP_PKT_LEN);
}

TEST_F(spp_unit_test_f, spp_pdu_parser_invalid_length)
{
    // packet version = 0b000
    // packet type = 0b0
    // secondary header flag = 0b1
    // apid = 512
    // sequence flag = 0b00
    // sequence count = 0
    // data length = 1 (invalid)
    // data[3] = {0x1, 0x0, 0x7}
    const uint8_t buf[9] = { 0b00001010, 0b00000000, 0x0, 0x0, 0x0, 0x1,
                                0x1, 0x0, 0x7 };
    EXPECT_EQ(spp_pdu_parser(ctx, buf, sizeof(buf) / sizeof(buf[0])),
                                -ERR_CODE_SPP_PKT_DATA_LEN);
}

TEST_F(spp_unit_test_f, spp_pdu_parser_unexpected_apid)
{
    // packet version = 0b000
    // packet type = 0b0
    // secondary header flag = 0b1
    // apid = 1024 (unexpected)
    // sequence flag = 0b00
    // sequence count = 0
    // data length = 2
    // data[3] = {0x1, 0x0, 0x7}
    const uint8_t buf[9] = { 0b00001100, 0b00000000, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 0x7 };
    EXPECT_EQ(spp_pdu_parser(ctx, buf, sizeof(buf) / sizeof(buf[0])),
                                -ERR_CODE_SPP_APID);
}

TEST_F(spp_unit_test_f, spp_pdu_parser_incompatable_sec_flag)
{
    // packet version = 0b000
    // packet type = 0b0
    // secondary header flag = 0b0 (incompatable)
    // apid = 512
    // sequence flag = 0b00
    // sequence count = 0
    // data length = 2
    // data[3] = {0x1, 0x0, 0x7}
    const uint8_t buf[9] = { 0b00000010, 0b00000000, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 0x7 };
    EXPECT_EQ(spp_pdu_parser(ctx, buf, sizeof(buf) / sizeof(buf[0])),
                                -ERR_CODE_SPP_SEC_HDR_FLAG);
}
```

component_test.cpp
---
```c
#include <gtest/gtest.h>
extern "C" {
    #include "spp.h"
}

class spp_component_test_f : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ctx = spp_init();
    }

    struct spp_ctx *ctx;
};

TEST_F(spp_component_test_f, spp_pdu_parser_noop)
{
    // sec_hdr_flag = 0b1, apid = 0, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_0[8] = { 0b00001000, 0b00000000, 0x0, 0x0, 0x0, 0x1,
                                0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_0, 8), 0);

    // sec_hdr_flag = 0b1, apid = 1, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_1[8] = { 0b00001000, 0b00000001, 0x0, 0x0, 0x0, 0x1,
                                0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_1, 8), 0);

    // sec_hdr_flag = 0b1, apid = 2, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_2[8] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x1,
                                0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_2, 8), 0);

    // sec_hdr_flag = 0b1, apid = 256, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_3[8] = { 0b00001001, 0b00000000, 0x0, 0x0, 0x0, 0x1,
                                0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_3, 8), 0);

    // sec_hdr_flag = 0b1, apid = 257, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_4[8] = { 0b00001001, 0b00000001, 0x0, 0x0, 0x0, 0x1,
                                0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_4, 8), 0);

    // sec_hdr_flag = 0b1, apid = 258, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_5[8] = { 0b00001001, 0b00000010, 0x0, 0x0, 0x0, 0x1,
                                0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_5, 8), 0);

    // sec_hdr_flag = 0b1, apid = 512, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_6[8] = { 0b00001010, 0b00000000, 0x0, 0x0, 0x0, 0x1,
                                0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_6, 8), 0);

    // sec_hdr_flag = 0b1, apid = 513, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_7[8] = { 0b00001010, 0b00000001, 0x0, 0x0, 0x0, 0x1,
                                0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_7, 8), 0);

    // sec_hdr_flag = 0b1, apid = 514, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_8[8] = { 0b00001010, 0b00000010, 0x0, 0x0, 0x0, 0x1,
                                0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_8, 8), 0);
}

TEST_F(spp_component_test_f, spp_pdu_parser_read)
{
    // sec_hdr_flag = 0b1, apid = 0, data_len = 2, cmd code = 256 (READ),
    // reg id = 0
    const uint8_t pdu_0[9] = { 0b00001000, 0b00000000, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_0, 9), 0);

    // sec_hdr_flag = 0b1, apid = 1, data_len = 2, cmd code = 256 (READ),
    // reg id = 1
    const uint8_t pdu_1[9] = { 0b00001000, 0b00000001, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 1 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_1, 9), 0);

    // sec_hdr_flag = 0b1, apid = 2, data_len = 2, cmd code = 256 (READ),
    // reg id = 2
    const uint8_t pdu_2[9] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 2 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_2, 9), 0);

    // sec_hdr_flag = 0b1, apid = 256, data_len = 2, cmd code = 256 (READ),
    // reg id = 8
    const uint8_t pdu_3[9] = { 0b00001001, 0b00000000, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 8 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_3, 9), 0);

    // sec_hdr_flag = 0b1, apid = 257, data_len = 2, cmd code = 256 (READ),
    // reg id = 9
    const uint8_t pdu_4[9] = { 0b00001001, 0b00000001, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 9 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_4, 9), 0);

    // sec_hdr_flag = 0b1, apid = 258, data_len = 2, cmd code = 256 (READ),
    // reg id = 10
    const uint8_t pdu_5[9] = { 0b00001001, 0b00000010, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 10 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_5, 9), 0);

    // sec_hdr_flag = 0b1, apid = 512, data_len = 2, cmd code = 256 (READ),
    // reg id = 13
    const uint8_t pdu_6[9] = { 0b00001010, 0b00000000, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 13 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_6, 9), 0);

    // sec_hdr_flag = 0b1, apid = 513, data_len = 2, cmd code = 256 (READ),
    // reg id = 14
    const uint8_t pdu_7[9] = { 0b00001010, 0b00000001, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 14 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_7, 9), 0);

    // sec_hdr_flag = 0b1, apid = 514, data_len = 2, cmd code = 256 (READ),
    // reg id = 15
    const uint8_t pdu_8[9] = { 0b00001010, 0b00000010, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 15 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_8, 9), 0);
}

TEST_F(spp_component_test_f, spp_pdu_parser_write)
{
    // sec_hdr_flag = 0b1, apid = 0, data_len = 3, cmd code = 257 (WRITE),
    // reg id = 0, reg val = 10
    const uint8_t pdu_0[10] = { 0b00001000, 0b00000000, 0x0, 0x0, 0x0, 0x3,
                                0x1, 0x1, 0, 10 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_0, 10), 0);

    // sec_hdr_flag = 0b1, apid = 1, data_len = 3, cmd code = 257 (WRITE),
    // reg id = 1, reg val = 20
    const uint8_t pdu_1[10] = { 0b00001000, 0b00000001, 0x0, 0x0, 0x0, 0x3,
                                0x1, 0x1, 1, 20 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_1, 10), 0);

    // sec_hdr_flag = 0b1, apid = 2, data_len = 3, cmd code = 257 (WRITE),
    // reg id = 2, reg val = 30
    const uint8_t pdu_2[10] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x3,
                                0x1, 0x1, 2, 30 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_2, 10), 0);

    // sec_hdr_flag = 0b1, apid = 256, data_len = 3, cmd code = 257 (WRITE),
    // reg id = 8, reg val = 40
    const uint8_t pdu_3[10] = { 0b00001001, 0b00000000, 0x0, 0x0, 0x0, 0x3,
                                0x1, 0x1, 8, 40 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_3, 10), 0);

    // sec_hdr_flag = 0b1, apid = 257, data_len = 3, cmd code = 257 (WRITE),
    // reg id = 9, reg val = 50
    const uint8_t pdu_4[10] = { 0b00001001, 0b00000001, 0x0, 0x0, 0x0, 0x3,
                                0x1, 0x1, 9, 50 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_4, 10), 0);

    // sec_hdr_flag = 0b1, apid = 258, data_len = 3, cmd code = 257 (WRITE),
    // reg id = 10, reg val = 60
    const uint8_t pdu_5[10] = { 0b00001001, 0b00000010, 0x0, 0x0, 0x0, 0x3,
                                0x1, 0x1, 10, 60 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_5, 10), 0);

    // sec_hdr_flag = 0b1, apid = 512, data_len = 3, cmd code = 257 (WRITE),
    // reg id = 13, reg val = 70
    const uint8_t pdu_6[10] = { 0b00001010, 0b00000000, 0x0, 0x0, 0x0, 0x3,
                                0x1, 0x1, 13, 70 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_6, 10), 0);

    // sec_hdr_flag = 0b1, apid = 513, data_len = 3, cmd code = 257 (WRITE),
    // reg id = 14, reg val = 80
    const uint8_t pdu_7[10] = { 0b00001010, 0b00000001, 0x0, 0x0, 0x0, 0x3,
                                0x1, 0x1, 14, 80 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_7, 10), 0);

    // sec_hdr_flag = 0b1, apid = 514, data_len = 3, cmd code = 257 (WRITE),
    // reg id = 15, reg val = 90
    const uint8_t pdu_8[10] = { 0b00001010, 0b00000010, 0x0, 0x0, 0x0, 0x3,
                                0x1, 0x1, 15, 90 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_8, 10), 0);
}

TEST_F(spp_component_test_f, spp_pdu_parser_insufficient_data)
{
    // sec_hdr_flag = 0b1, apid = 256, data_len = 0, cmd code = 0 (NOOP)
    const uint8_t pdu_a[7] = { 0b00001001, 0b00000000, 0x0, 0x0, 0x0, 0x0,
                                0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_a, 7), -ERR_CODE_SPP_PKT_DATA_LEN);

    // sec_hdr_flag = 0b1, apid = 2, data_len = 1, cmd code = 256 (READ)
    const uint8_t pdu_b[8] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x1,
                                0x1, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_b, 8), -ERR_CODE_SPP_PKT_DATA_LEN);

    // sec_hdr_flag = 0b1, apid = 257, data_len = 2, cmd code = 257 (WRITE),
    // reg id = 7
    const uint8_t pdu_c[9] = { 0b00001001, 0b00000001, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x1, 7 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_c, 9), -ERR_CODE_SPP_PKT_DATA_LEN);
}

TEST_F(spp_component_test_f, spp_pdu_parser_excessive_data)
{
    // sec_hdr_flag = 0b1, apid = 256, data_len = 2, cmd code = 0 (NOOP)
    const uint8_t pdu_a[9] = { 0b00001001, 0b00000000, 0x0, 0x0, 0x0, 0x2,
                                0x0, 0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_a, 9), -ERR_CODE_SPP_PKT_DATA_LEN);

    // sec_hdr_flag = 0b1, apid = 2, data_len = 3, cmd code = 256 (READ),
    // reg id = 15
    const uint8_t pdu_b[10] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x3,
                                0x1, 0x0, 15, 0x0};
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_b, 10), -ERR_CODE_SPP_PKT_DATA_LEN);

    // sec_hdr_flag = 0b1, apid = 257, data_len = 4, cmd code = 257 (WRITE),
    // reg id = 7, reg val = 250
    const uint8_t pdu_c[11] = { 0b00001001, 0b00000001, 0x0, 0x0, 0x0, 0x4,
                                0x1, 0x1, 7, 250, 0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_c, 11), -ERR_CODE_SPP_PKT_DATA_LEN);
}

TEST_F(spp_component_test_f, spp_pdu_parser_out_of_range)
{
    // sec_hdr_flag = 0b1, apid = 2, data_len = 2, cmd code = 256 (READ),
    // reg id = 15
    const uint8_t pdu_b[9] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x2,
                                0x1, 0x0, 16};
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_b, 9), -ERR_CODE_USR_REG_ID);

    // sec_hdr_flag = 0b1, apid = 257, data_len = 3, cmd code = 257 (WRITE),
    // reg id = 16, reg val = 250
    const uint8_t pdu_c[10] = { 0b00001001, 0b00000001, 0x0, 0x0, 0x0, 0x3,
                                0x1, 0x1, 16, 250 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_c, 10), -ERR_CODE_USR_REG_ID);
}
```
Test Log
---
```js
Start testing: Dec 06 03:20 UTC
----------------------------------------------------------
1/2 Testing: spp_unit_test
1/2 Test: spp_unit_test
Command: "/workdir/test/build/test_spp_unit"
Directory: /workdir/test/build
"spp_unit_test" start time: Dec 06 03:20 UTC
Output:
----------------------------------------------------------
Running main() from /workdir/test/build/_deps/googletest-src/googletest/src/gtest_main.cc
[==========] Running 15 tests from 2 test suites.
[----------] Global test environment set-up.
[----------] 8 tests from spp_unit_test
[ RUN      ] spp_unit_test.invalid_arg
error: spp_append_apid_cfg_node: invalid argument(tail)
error: spp_append_apid_cfg_node: invalid argument(new_node)
error: spp_get_apid_cfg: invalid argument(ctx)
error: spp_apid_data_parser: invalid argument
error: spp_pdu_parser: invalid argument(ctx)
error: spp_pdu_parser: invalid argument(buf)
[       OK ] spp_unit_test.invalid_arg (0 ms)
[ RUN      ] spp_unit_test.append_apid_cfg
[       OK ] spp_unit_test.append_apid_cfg (0 ms)
[ RUN      ] spp_unit_test.apid_data_parser_pass
the payload 256 receives NOOP.
the register 15 of the payload 2 is read.
the register 7 of the payload 1 is set to 250.
[       OK ] spp_unit_test.apid_data_parser_pass (0 ms)
[ RUN      ] spp_unit_test.apid_data_parser_unsupported
error: spp_apid_data_parser: unsupported secondary header 1 [-2005]
[       OK ] spp_unit_test.apid_data_parser_unsupported (0 ms)
[ RUN      ] spp_unit_test.apid_data_parser_insufficient_data
error: spp_apid_data_parser: unsupported secondary header 148 [-2005]
error: spp_apid_data_parser: invalid packet data length 1 [-2006]
error: spp_apid_data_parser: invalid packet data length 2 [-2006]
[       OK ] spp_unit_test.apid_data_parser_insufficient_data (0 ms)
[ RUN      ] spp_unit_test.apid_data_parser_excessive_data
error: spp_apid_data_parser: invalid packet data length 2 [-2006]
error: spp_apid_data_parser: invalid packet data length 3 [-2006]
error: spp_apid_data_parser: invalid packet data length 4 [-2006]
[       OK ] spp_unit_test.apid_data_parser_excessive_data (0 ms)
[ RUN      ] spp_unit_test.apid_data_parser_out_of_range
error: spp_apid_data_parser: invalid register id 16 [-2007]
error: spp_apid_data_parser: invalid register id 16 [-2007]
[       OK ] spp_unit_test.apid_data_parser_out_of_range (0 ms)
[ RUN      ] spp_unit_test.spp_pdu_parser_prim_hdr
error: spp_pdu_parser: invalid packet version [-2002]
[       OK ] spp_unit_test.spp_pdu_parser_prim_hdr (0 ms)
[----------] 8 tests from spp_unit_test (0 ms total)

[----------] 7 tests from spp_unit_test_f
[ RUN      ] spp_unit_test_f.get_apid_cfg_pass
[       OK ] spp_unit_test_f.get_apid_cfg_pass (0 ms)
[ RUN      ] spp_unit_test_f.get_apid_cfg_fail
[       OK ] spp_unit_test_f.get_apid_cfg_fail (0 ms)
[ RUN      ] spp_unit_test_f.spp_pdu_parser_invalid_pkt_ver
error: spp_pdu_parser: invalid packet version [-2002]
[       OK ] spp_unit_test_f.spp_pdu_parser_invalid_pkt_ver (0 ms)
[ RUN      ] spp_unit_test_f.spp_pdu_parser_insufficient_length
error: spp_pdu_parser: invalid packet length [-2001]
[       OK ] spp_unit_test_f.spp_pdu_parser_insufficient_length (0 ms)
[ RUN      ] spp_unit_test_f.spp_pdu_parser_invalid_length
error: spp_pdu_parser: invalid packet data length [-2006]
[       OK ] spp_unit_test_f.spp_pdu_parser_invalid_length (0 ms)
[ RUN      ] spp_unit_test_f.spp_pdu_parser_unexpected_apid
error: spp_pdu_parser: unexpected packet apid: 1024 [-2003]
[       OK ] spp_unit_test_f.spp_pdu_parser_unexpected_apid (0 ms)
[ RUN      ] spp_unit_test_f.spp_pdu_parser_incompatable_sec_flag
error: spp_pdu_parser: incompatible secondary header flag 512 [-2004]
[       OK ] spp_unit_test_f.spp_pdu_parser_incompatable_sec_flag (0 ms)
[----------] 7 tests from spp_unit_test_f (0 ms total)

[----------] Global test environment tear-down
[==========] 15 tests from 2 test suites ran. (0 ms total)
[  PASSED  ] 15 tests.
<end of output>
Test time =   0.04 sec
----------------------------------------------------------
Test Passed.
"spp_unit_test" end time: Dec 06 03:20 UTC
"spp_unit_test" time elapsed: 00:00:00
----------------------------------------------------------

2/2 Testing: spp_component_test
2/2 Test: spp_component_test
Command: "/workdir/test/build/test_spp_component"
Directory: /workdir/test/build
"spp_component_test" start time: Dec 06 03:20 UTC
Output:
----------------------------------------------------------
Running main() from /workdir/test/build/_deps/googletest-src/googletest/src/gtest_main.cc
[==========] Running 6 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 6 tests from spp_component_test_f
[ RUN      ] spp_component_test_f.spp_pdu_parser_noop
the payload 0 receives NOOP.
the payload 1 receives NOOP.
the payload 2 receives NOOP.
the payload 256 receives NOOP.
the payload 257 receives NOOP.
the payload 258 receives NOOP.
the payload 512 receives NOOP.
the payload 513 receives NOOP.
the payload 514 receives NOOP.
[       OK ] spp_component_test_f.spp_pdu_parser_noop (0 ms)
[ RUN      ] spp_component_test_f.spp_pdu_parser_read
the register 0 of the payload 0 is read.
the register 1 of the payload 1 is read.
the register 2 of the payload 2 is read.
the register 8 of the payload 256 is read.
the register 9 of the payload 257 is read.
the register 10 of the payload 258 is read.
the register 13 of the payload 512 is read.
the register 14 of the payload 513 is read.
the register 15 of the payload 514 is read.
[       OK ] spp_component_test_f.spp_pdu_parser_read (0 ms)
[ RUN      ] spp_component_test_f.spp_pdu_parser_write
the register 0 of the payload 0 is set to 10.
the register 1 of the payload 1 is set to 20.
the register 2 of the payload 2 is set to 30.
the register 8 of the payload 256 is set to 40.
the register 9 of the payload 257 is set to 50.
the register 10 of the payload 258 is set to 60.
the register 13 of the payload 512 is set to 70.
the register 14 of the payload 513 is set to 80.
the register 15 of the payload 514 is set to 90.
[       OK ] spp_component_test_f.spp_pdu_parser_write (0 ms)
[ RUN      ] spp_component_test_f.spp_pdu_parser_insufficient_data
error: spp_apid_data_parser: invalid packet data length 0 [-2006]
error: spp_apid_data_parser: invalid packet data length 1 [-2006]
error: spp_apid_data_parser: invalid packet data length 2 [-2006]
[       OK ] spp_component_test_f.spp_pdu_parser_insufficient_data (0 ms)
[ RUN      ] spp_component_test_f.spp_pdu_parser_excessive_data
error: spp_apid_data_parser: invalid packet data length 2 [-2006]
error: spp_apid_data_parser: invalid packet data length 3 [-2006]
error: spp_apid_data_parser: invalid packet data length 4 [-2006]
[       OK ] spp_component_test_f.spp_pdu_parser_excessive_data (0 ms)
[ RUN      ] spp_component_test_f.spp_pdu_parser_out_of_range
error: spp_apid_data_parser: invalid register id 16 [-2007]
error: spp_apid_data_parser: invalid register id 16 [-2007]
[       OK ] spp_component_test_f.spp_pdu_parser_out_of_range (0 ms)
[----------] 6 tests from spp_component_test_f (0 ms total)

[----------] Global test environment tear-down
[==========] 6 tests from 1 test suite ran. (0 ms total)
[  PASSED  ] 6 tests.
<end of output>
Test time =   0.04 sec
----------------------------------------------------------
Test Passed.
"spp_component_test" end time: Dec 06 03:20 UTC
"spp_component_test" time elapsed: 00:00:00
----------------------------------------------------------

End testing: Dec 06 03:20 UTC
```

QEMU Emulation
---
```c
#include <stdio.h>
#include "spp.h"

int main(void)
{
	struct spp_ctx *ctx = spp_init();
	const uint8_t pdu_1[10] = { 0b00001000, 0b00000001, 0x0, 0x0, 0x0, 0x3,
                                0x01, 0x01, 7, 250 };
	const uint8_t pdu_2[9] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x2,
                                0x01, 0x00, 15 };
	const uint8_t pdu_256[8] = { 0b00001001, 0b00000000, 0x0, 0x0, 0x0, 0x1,
                                0x00, 0x00 };

	printf("Target: %s\n\n", CONFIG_BOARD_TARGET);

	spp_pdu_parser(ctx, pdu_1, sizeof(pdu_1) / sizeof(pdu_1[0]));
	spp_pdu_parser(ctx, pdu_2, sizeof(pdu_2) / sizeof(pdu_2[0]));
	spp_pdu_parser(ctx, pdu_256, sizeof(pdu_256) / sizeof(pdu_256[0]));

    printf("\n");
	
	return 0;
}
```

- **Code Base**: Zephyr OS build 4.0.0-rc3
- **SDK**: docker.io/zephyrprojectrtos/zephyr-build:latest
- **Emulator**: qemu-system-mipsel
- **Target**: MIPS Malta little endian
```sh
-- west build: running target run
[0/1] To exit from QEMU enter: 'CTRL+a, x'[QEMU] CPU: 24Kc
*** Booting Zephyr OS build 4.0.0-rc3 ***
Target: qemu_malta/qemu_malta

the register 7 of the payload 1 is set to 250.
the register 15 of the payload 2 is read.
the payload 256 receives NOOP.

qemu-system-mipsel: terminating on signal 2
ninja: build stopped: interrupted by user.
```

- **Code Base**: Zephyr OS build 4.0.0-rc3
- **SDK**: docker.io/zephyrprojectrtos/zephyr-build:latest
- **Emulator**: qemu-system-mips
- **Target**: MIPS Malta big endian
```sh
-- west build: running target run
[0/1] To exit from QEMU enter: 'CTRL+a, x'[QEMU] CPU: 24Kc
*** Booting Zephyr OS build 4.0.0-rc3 ***
Target: qemu_malta/qemu_malta/be

the register 7 of the payload 1 is set to 250.
the register 15 of the payload 2 is read.
the payload 256 receives NOOP.

qemu-system-mips: terminating on signal 2
ninja: build stopped: interrupted by user.
```

