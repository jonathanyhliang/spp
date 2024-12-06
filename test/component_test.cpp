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
    const uint8_t pdu_0[8] = { 0b00001000, 0b00000000, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_0, 8), 0);

    // sec_hdr_flag = 0b1, apid = 1, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_1[8] = { 0b00001000, 0b00000001, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_1, 8), 0);

    // sec_hdr_flag = 0b1, apid = 2, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_2[8] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_2, 8), 0);

    // sec_hdr_flag = 0b1, apid = 256, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_3[8] = { 0b00001001, 0b00000000, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_3, 8), 0);

    // sec_hdr_flag = 0b1, apid = 257, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_4[8] = { 0b00001001, 0b00000001, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_4, 8), 0);

    // sec_hdr_flag = 0b1, apid = 258, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_5[8] = { 0b00001001, 0b00000010, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_5, 8), 0);

    // sec_hdr_flag = 0b1, apid = 512, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_6[8] = { 0b00001010, 0b00000000, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_6, 8), 0);

    // sec_hdr_flag = 0b1, apid = 513, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_7[8] = { 0b00001010, 0b00000001, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_7, 8), 0);

    // sec_hdr_flag = 0b1, apid = 514, data_len = 1, cmd code = 0 (NOOP)
    const uint8_t pdu_8[8] = { 0b00001010, 0b00000010, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_8, 8), 0);
}

TEST_F(spp_component_test_f, spp_pdu_parser_read)
{
    // sec_hdr_flag = 0b1, apid = 0, data_len = 2, cmd code = 256 (READ), reg id = 0
    const uint8_t pdu_0[9] = { 0b00001000, 0b00000000, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_0, 9), 0);

    // sec_hdr_flag = 0b1, apid = 1, data_len = 2, cmd code = 256 (READ), reg id = 1
    const uint8_t pdu_1[9] = { 0b00001000, 0b00000001, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 1 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_1, 9), 0);

    // sec_hdr_flag = 0b1, apid = 2, data_len = 2, cmd code = 256 (READ), reg id = 2
    const uint8_t pdu_2[9] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 2 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_2, 9), 0);

    // sec_hdr_flag = 0b1, apid = 256, data_len = 2, cmd code = 256 (READ), reg id = 8
    const uint8_t pdu_3[9] = { 0b00001001, 0b00000000, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 8 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_3, 9), 0);

    // sec_hdr_flag = 0b1, apid = 257, data_len = 2, cmd code = 256 (READ), reg id = 9
    const uint8_t pdu_4[9] = { 0b00001001, 0b00000001, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 9 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_4, 9), 0);

    // sec_hdr_flag = 0b1, apid = 258, data_len = 2, cmd code = 256 (READ), reg id = 10
    const uint8_t pdu_5[9] = { 0b00001001, 0b00000010, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 10 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_5, 9), 0);

    // sec_hdr_flag = 0b1, apid = 512, data_len = 2, cmd code = 256 (READ), reg id = 13
    const uint8_t pdu_6[9] = { 0b00001010, 0b00000000, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 13 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_6, 9), 0);

    // sec_hdr_flag = 0b1, apid = 513, data_len = 2, cmd code = 256 (READ), reg id = 14
    const uint8_t pdu_7[9] = { 0b00001010, 0b00000001, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 14 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_7, 9), 0);

    // sec_hdr_flag = 0b1, apid = 514, data_len = 2, cmd code = 256 (READ), reg id = 15
    const uint8_t pdu_8[9] = { 0b00001010, 0b00000010, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 15 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_8, 9), 0);
}

TEST_F(spp_component_test_f, spp_pdu_parser_write)
{
    // sec_hdr_flag = 0b1, apid = 0, data_len = 3, cmd code = 257 (WRITE), reg id = 0, reg val = 10
    const uint8_t pdu_0[10] = { 0b00001000, 0b00000000, 0x0, 0x0, 0x0, 0x3, 0x1, 0x1, 0, 10 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_0, 10), 0);

    // sec_hdr_flag = 0b1, apid = 1, data_len = 3, cmd code = 257 (WRITE), reg id = 1, reg val = 20
    const uint8_t pdu_1[10] = { 0b00001000, 0b00000001, 0x0, 0x0, 0x0, 0x3, 0x1, 0x1, 1, 20 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_1, 10), 0);

    // sec_hdr_flag = 0b1, apid = 2, data_len = 3, cmd code = 257 (WRITE), reg id = 2, reg val = 30
    const uint8_t pdu_2[10] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x3, 0x1, 0x1, 2, 30 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_2, 10), 0);

    // sec_hdr_flag = 0b1, apid = 256, data_len = 3, cmd code = 257 (WRITE), reg id = 8, reg val = 40
    const uint8_t pdu_3[10] = { 0b00001001, 0b00000000, 0x0, 0x0, 0x0, 0x3, 0x1, 0x1, 8, 40 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_3, 10), 0);

    // sec_hdr_flag = 0b1, apid = 257, data_len = 3, cmd code = 257 (WRITE), reg id = 9, reg val = 50
    const uint8_t pdu_4[10] = { 0b00001001, 0b00000001, 0x0, 0x0, 0x0, 0x3, 0x1, 0x1, 9, 50 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_4, 10), 0);

    // sec_hdr_flag = 0b1, apid = 258, data_len = 3, cmd code = 257 (WRITE), reg id = 10, reg val = 60
    const uint8_t pdu_5[10] = { 0b00001001, 0b00000010, 0x0, 0x0, 0x0, 0x3, 0x1, 0x1, 10, 60 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_5, 10), 0);

    // sec_hdr_flag = 0b1, apid = 512, data_len = 3, cmd code = 257 (WRITE), reg id = 13, reg val = 70
    const uint8_t pdu_6[10] = { 0b00001010, 0b00000000, 0x0, 0x0, 0x0, 0x3, 0x1, 0x1, 13, 70 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_6, 10), 0);

    // sec_hdr_flag = 0b1, apid = 513, data_len = 3, cmd code = 257 (WRITE), reg id = 14, reg val = 80
    const uint8_t pdu_7[10] = { 0b00001010, 0b00000001, 0x0, 0x0, 0x0, 0x3, 0x1, 0x1, 14, 80 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_7, 10), 0);

    // sec_hdr_flag = 0b1, apid = 514, data_len = 3, cmd code = 257 (WRITE), reg id = 15, reg val = 90
    const uint8_t pdu_8[10] = { 0b00001010, 0b00000010, 0x0, 0x0, 0x0, 0x3, 0x1, 0x1, 15, 90 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_8, 10), 0);
}

TEST_F(spp_component_test_f, spp_pdu_parser_insufficient_data)
{
    // sec_hdr_flag = 0b1, apid = 256, data_len = 0, cmd code = 0 (NOOP)
    const uint8_t pdu_a[7] = { 0b00001001, 0b00000000, 0x0, 0x0, 0x0, 0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_a, 7), -ERR_CODE_SPP_PKT_DATA_LEN);

    // sec_hdr_flag = 0b1, apid = 2, data_len = 1, cmd code = 256 (READ)
    const uint8_t pdu_b[8] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x1, 0x1, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_b, 8), -ERR_CODE_SPP_PKT_DATA_LEN);

    // sec_hdr_flag = 0b1, apid = 257, data_len = 2, cmd code = 257 (WRITE), reg id = 7
    const uint8_t pdu_c[9] = { 0b00001001, 0b00000001, 0x0, 0x0, 0x0, 0x2, 0x1, 0x1, 7 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_c, 9), -ERR_CODE_SPP_PKT_DATA_LEN);
}

TEST_F(spp_component_test_f, spp_pdu_parser_excessive_data)
{
    // sec_hdr_flag = 0b1, apid = 256, data_len = 2, cmd code = 0 (NOOP)
    const uint8_t pdu_a[9] = { 0b00001001, 0b00000000, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_a, 9), -ERR_CODE_SPP_PKT_DATA_LEN);

    // sec_hdr_flag = 0b1, apid = 2, data_len = 3, cmd code = 256 (READ), reg id = 15
    const uint8_t pdu_b[10] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x3, 0x1, 0x0, 15, 0x0};
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_b, 10), -ERR_CODE_SPP_PKT_DATA_LEN);

    // sec_hdr_flag = 0b1, apid = 257, data_len = 4, cmd code = 257 (WRITE), reg id = 7, reg val = 250
    const uint8_t pdu_c[11] = { 0b00001001, 0b00000001, 0x0, 0x0, 0x0, 0x4, 0x1, 0x1, 7, 250, 0 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_c, 11), -ERR_CODE_SPP_PKT_DATA_LEN);
}

TEST_F(spp_component_test_f, spp_pdu_parser_out_of_range)
{
    // sec_hdr_flag = 0b1, apid = 2, data_len = 2, cmd code = 256 (READ), reg id = 15
    const uint8_t pdu_b[9] = { 0b00001000, 0b00000010, 0x0, 0x0, 0x0, 0x2, 0x1, 0x0, 16};
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_b, 9), -ERR_CODE_USR_REG_ID);

    // sec_hdr_flag = 0b1, apid = 257, data_len = 3, cmd code = 257 (WRITE), reg id = 16, reg val = 250
    const uint8_t pdu_c[10] = { 0b00001001, 0b00000001, 0x0, 0x0, 0x0, 0x3, 0x1, 0x1, 16, 250 };
    EXPECT_EQ(spp_pdu_parser(ctx, pdu_c, 10), -ERR_CODE_USR_REG_ID);
}
