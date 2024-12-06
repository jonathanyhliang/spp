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
    const uint8_t buf[9] = { 0b10111010, 0b00000000, 0b10000001, 0b00000000, 0x0, 0x1, 0x2, 0x3 };
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
    const uint8_t buf[9] = { 0b00101010, 0b00000000, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x7 };
    EXPECT_EQ(spp_pdu_parser(ctx, buf, sizeof(buf) / sizeof(buf[0])), -ERR_CODE_SPP_PKT_VER);
}

TEST_F(spp_unit_test_f, spp_pdu_parser_insufficient_length)
{
    const uint8_t buf[6] = { 0b00001010, 0b00000000, 0x0, 0x0, 0x0, 0x0};
    EXPECT_EQ(spp_pdu_parser(ctx, buf, sizeof(buf) / sizeof(buf[0])), -ERR_CODE_SPP_PKT_LEN);
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
    const uint8_t buf[9] = { 0b00001010, 0b00000000, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x7 };
    EXPECT_EQ(spp_pdu_parser(ctx, buf, sizeof(buf) / sizeof(buf[0])), -ERR_CODE_SPP_PKT_DATA_LEN);
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
    const uint8_t buf[9] = { 0b00001100, 0b00000000, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x7 };
    EXPECT_EQ(spp_pdu_parser(ctx, buf, sizeof(buf) / sizeof(buf[0])), -ERR_CODE_SPP_APID);
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
    const uint8_t buf[9] = { 0b00000010, 0b00000000, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0x7 };
    EXPECT_EQ(spp_pdu_parser(ctx, buf, sizeof(buf) / sizeof(buf[0])), -ERR_CODE_SPP_SEC_HDR_FLAG);
}
