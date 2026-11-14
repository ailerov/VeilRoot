// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_dkg.h"

#include <vector>

namespace cryptonote {
namespace dao {
namespace {

static dao_share_set_record make_paillier_v2()
{
    dao_share_set_record r;
    r.version            = 2;
    r.share_set_id       = 1;
    r.height             = 100;
    r.threshold          = 2;
    r.key_id.assign(32, 0x11);
    r.committee_id_hash.assign(32, 0x22);
    r.committee_members.assign(3, std::vector<uint8_t>(32, 0x33));
    r.VK_i.assign(3, std::vector<uint8_t>(PAILLIER_CT_BYTES, 0x44));
    return r;
}

static dao_share_set_record make_cl_v3()
{
    dao_share_set_record r;
    r.version            = 3;
    r.share_set_id       = 5;
    r.height             = 200;
    r.threshold          = 2;
    r.key_id.assign(32, 0x55);
    r.committee_id_hash.assign(32, 0x66);
    r.committee_members.assign(3, std::vector<uint8_t>(32, 0x77));
    r.cl_gammas_serialized = std::vector<uint8_t>(64, 0x88);
    r.qualified_ids = {0u, 1u, 2u};
    return r;
}

TEST(DaoShareSetRecordV3, paillier_v2_roundtrip)
{
    auto r = make_paillier_v2();
    std::vector<uint8_t> wire;
    ASSERT_TRUE(r.serialize(wire));
    // v2 first word
    ASSERT_GE(wire.size(), 4u);
    EXPECT_EQ(wire[0], 2u);

    dao_share_set_record r2;
    ASSERT_TRUE(r2.deserialize(wire));
    EXPECT_EQ(r2.version, 2u);
    EXPECT_EQ(r2.share_set_id, r.share_set_id);
    EXPECT_EQ(r2.threshold, r.threshold);
    EXPECT_EQ(r2.key_id, r.key_id);
    EXPECT_EQ(r2.committee_members, r.committee_members);
    EXPECT_EQ(r2.VK_i, r.VK_i);
    EXPECT_TRUE(r2.cl_gammas_serialized.empty());
    EXPECT_TRUE(r2.qualified_ids.empty());
}

TEST(DaoShareSetRecordV3, cl_v3_roundtrip)
{
    auto r = make_cl_v3();
    std::vector<uint8_t> wire;
    ASSERT_TRUE(r.serialize(wire));
    ASSERT_GE(wire.size(), 4u);
    EXPECT_EQ(wire[0], 3u);

    dao_share_set_record r2;
    ASSERT_TRUE(r2.deserialize(wire));
    EXPECT_EQ(r2.version, 3u);
    EXPECT_EQ(r2.share_set_id, r.share_set_id);
    EXPECT_EQ(r2.threshold, r.threshold);
    EXPECT_EQ(r2.key_id, r.key_id);
    EXPECT_EQ(r2.committee_members, r.committee_members);
    EXPECT_EQ(r2.cl_gammas_serialized, r.cl_gammas_serialized);
    EXPECT_EQ(r2.qualified_ids, r.qualified_ids);
    EXPECT_TRUE(r2.VK_i.empty());
    EXPECT_TRUE(r2.contributions.empty());
}

TEST(DaoShareSetRecordV3, cl_v3_rejects_unsorted_qualified_ids)
{
    auto r = make_cl_v3();
    r.qualified_ids = {2u, 1u, 0u};
    std::vector<uint8_t> wire;
    EXPECT_FALSE(r.serialize(wire));
}

TEST(DaoShareSetRecordV3, cl_v3_rejects_out_of_range_qualified_id)
{
    auto r = make_cl_v3();
    r.qualified_ids = {0u, 1u, 5u};
    std::vector<uint8_t> wire;
    EXPECT_FALSE(r.serialize(wire));
}

TEST(DaoShareSetRecordV3, cl_v3_rejects_empty_gammas)
{
    auto r = make_cl_v3();
    r.cl_gammas_serialized.clear();
    std::vector<uint8_t> wire;
    EXPECT_FALSE(r.serialize(wire));
}

TEST(DaoShareSetRecordV3, cl_v3_rejects_trailing_bytes)
{
    auto r = make_cl_v3();
    std::vector<uint8_t> wire;
    ASSERT_TRUE(r.serialize(wire));
    wire.push_back(0);
    dao_share_set_record r2;
    EXPECT_FALSE(r2.deserialize(wire));
}

} // namespace
} // namespace dao
} // namespace cryptonote
