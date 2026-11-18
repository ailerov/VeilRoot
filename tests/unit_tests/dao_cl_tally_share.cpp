// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_tally.h"
#include "governance/dao_tally_share.h"

#include <cstring>
#include <vector>

namespace cryptonote {
namespace dao {
namespace {

TEST(DaoClPartialSet, roundtrip)
{
    dao_partial_set s;
    s.member_indices = {1u, 3u, 5u};
    s.cl_partials = {
        std::vector<uint8_t>(128, 0x11),
        std::vector<uint8_t>(200, 0x22),
        std::vector<uint8_t>(64, 0x33),
    };

    std::vector<uint8_t> wire;
    ASSERT_TRUE(s.serialize(wire));
    ASSERT_GE(wire.size(), 1u);
    EXPECT_EQ(wire[0], dao_partial_set::CL_FORMAT_TAG);

    dao_partial_set s2;
    ASSERT_TRUE(s2.deserialize(wire));
    EXPECT_EQ(s2.member_indices, s.member_indices);
    EXPECT_EQ(s2.cl_partials, s.cl_partials);
}

TEST(DaoClPartialSet, rejects_empty_partial)
{
    dao_partial_set s;
    s.member_indices = {1u};
    s.cl_partials = { std::vector<uint8_t>() };
    std::vector<uint8_t> wire;
    EXPECT_FALSE(s.serialize(wire));
}

TEST(DaoClPartialSet, rejects_oversize_partial)
{
    dao_partial_set s;
    s.member_indices = {1u};
    s.cl_partials = {
        std::vector<uint8_t>(dao_partial_set::CL_PARTIAL_MAX_BYTES + 1, 0xAA)
    };
    std::vector<uint8_t> wire;
    EXPECT_FALSE(s.serialize(wire));
}

TEST(DaoClPartialSet, rejects_wrong_format_tag)
{
    dao_partial_set s;
    s.member_indices = {1u};
    s.cl_partials = { std::vector<uint8_t>(32, 0x55) };
    std::vector<uint8_t> wire;
    ASSERT_TRUE(s.serialize(wire));
    wire[0] = 0x00;
    dao_partial_set s2;
    EXPECT_FALSE(s2.deserialize(wire));
}

TEST(DaoClPartialSet, rejects_trailing_bytes)
{
    dao_partial_set s;
    s.member_indices = {1u};
    s.cl_partials = { std::vector<uint8_t>(32, 0x55) };
    std::vector<uint8_t> wire;
    ASSERT_TRUE(s.serialize(wire));
    wire.push_back(0);
    dao_partial_set s2;
    EXPECT_FALSE(s2.deserialize(wire));
}

TEST(DaoClTallyShare, roundtrip)
{
    dao_v2_tally_share s;
    s.proposal_id = crypto::null_hash;
    std::memset(s.proposal_id.data, 0xAA, 32);
    s.vote_end_height = 4242;
    s.tally_key_id.assign(32, 0xCC);
    s.aggregate_ciphertext_hash = crypto::null_hash;
    std::memset(s.aggregate_ciphertext_hash.data, 0xDD, 32);
    s.member_index = 7;
    s.cl_partial_W = std::vector<uint8_t>(80, 0x01);
    s.cl_partial_S = std::vector<uint8_t>(120, 0x02);
    s.cl_partial_B = std::vector<uint8_t>(64, 0x03);

    std::vector<uint8_t> wire;
    ASSERT_TRUE(s.serialize(wire));
    EXPECT_EQ(wire[0], dao_v2_tally_share::WIRE_VERSION);

    dao_v2_tally_share s2;
    ASSERT_TRUE(s2.deserialize(wire));
    EXPECT_EQ(s2.version, dao_v2_tally_share::WIRE_VERSION);
    EXPECT_EQ(s2.proposal_id, s.proposal_id);
    EXPECT_EQ(s2.vote_end_height, s.vote_end_height);
    EXPECT_EQ(s2.tally_key_id, s.tally_key_id);
    EXPECT_EQ(s2.aggregate_ciphertext_hash, s.aggregate_ciphertext_hash);
    EXPECT_EQ(s2.member_index, s.member_index);
    EXPECT_EQ(s2.cl_partial_W, s.cl_partial_W);
    EXPECT_EQ(s2.cl_partial_S, s.cl_partial_S);
    EXPECT_EQ(s2.cl_partial_B, s.cl_partial_B);
}

TEST(DaoClTallyShare, rejects_empty_cl_field)
{
    dao_v2_tally_share s;
    s.tally_key_id.assign(32, 0xCC);
    s.cl_partial_W.clear();
    s.cl_partial_S = std::vector<uint8_t>(64, 0x02);
    s.cl_partial_B = std::vector<uint8_t>(64, 0x03);
    std::vector<uint8_t> wire;
    EXPECT_FALSE(s.serialize(wire));
}

TEST(DaoClTallyShare, rejects_bad_key_id_size)
{
    dao_v2_tally_share s;
    s.tally_key_id.assign(31, 0xCC);
    s.cl_partial_W = std::vector<uint8_t>(64, 0x01);
    s.cl_partial_S = std::vector<uint8_t>(64, 0x02);
    s.cl_partial_B = std::vector<uint8_t>(64, 0x03);
    std::vector<uint8_t> wire;
    EXPECT_FALSE(s.serialize(wire));
}

TEST(DaoClTallyShare, rejects_wrong_wire_version)
{
    dao_v2_tally_share s;
    s.tally_key_id.assign(32, 0xCC);
    s.cl_partial_W = std::vector<uint8_t>(64, 0x01);
    s.cl_partial_S = std::vector<uint8_t>(64, 0x02);
    s.cl_partial_B = std::vector<uint8_t>(64, 0x03);
    std::vector<uint8_t> wire;
    ASSERT_TRUE(s.serialize(wire));
    wire[0] = 2;  // Paillier-era tag, must be rejected
    dao_v2_tally_share s2;
    EXPECT_FALSE(s2.deserialize(wire));
}

} // namespace
} // namespace dao
} // namespace cryptonote
