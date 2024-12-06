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
	/* 4.1.3.3.3.3 The Secondary Header Flag shall be static with respect to the APID and
	managed data path throughout a Mission Phase.*/
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
