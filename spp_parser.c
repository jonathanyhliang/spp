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
