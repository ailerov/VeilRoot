// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_dkg.h"

#include <vector>

namespace cryptonote {
namespace dao {
namespace {

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

TEST(DaoShareSetRecordV3, is_reshared_false_for_base)
{
    auto r = make_cl_v3();
    r.base_share_set_id = 0;
    EXPECT_FALSE(dao_share_set_is_reshared(r));
}

TEST(DaoShareSetRecordV3, is_reshared_true_for_reshare)
{
    auto r = make_cl_v3();
    r.base_share_set_id = 12345;
    EXPECT_TRUE(dao_share_set_is_reshared(r));
}

TEST(DaoShareSetRecordV3, is_reshared_false_for_v1)
{
    dao_share_set_record r;
    r.version = 1;
    r.base_share_set_id = 12345;
    r.cl_gammas_serialized = {0x01};
    EXPECT_FALSE(dao_share_set_is_reshared(r));
}

TEST(DaoShareSetRecordV3, is_reshared_false_when_gammas_missing)
{
    auto r = make_cl_v3();
    r.base_share_set_id = 12345;
    r.cl_gammas_serialized.clear();
    EXPECT_FALSE(dao_share_set_is_reshared(r));
}

TEST(DaoShareSetRecordV3, cl_v3_rejects_zero_threshold)
{
    auto r = make_cl_v3();
    r.threshold = 0;
    std::vector<uint8_t> wire;
    EXPECT_FALSE(r.serialize(wire));
}

TEST(DaoShareSetRecordV3, cl_v3_rejects_threshold_above_members)
{
    auto r = make_cl_v3();
    r.threshold = 4;
    std::vector<uint8_t> wire;
    EXPECT_FALSE(r.serialize(wire));
}

TEST(DaoShareSetRecordV3, cl_v3_rejects_empty_committee)
{
    auto r = make_cl_v3();
    r.committee_members.clear();
    std::vector<uint8_t> wire;
    EXPECT_FALSE(r.serialize(wire));
}

TEST(DaoShareSetRecordV3, cl_v3_rejects_bad_key_id_size)
{
    auto r = make_cl_v3();
    r.key_id.resize(31);
    std::vector<uint8_t> wire;
    EXPECT_FALSE(r.serialize(wire));
}

TEST(DaoShareSetRecordV3, cl_v3_rejects_bad_committee_member_size)
{
    auto r = make_cl_v3();
    r.committee_members[0].resize(31);
    std::vector<uint8_t> wire;
    EXPECT_FALSE(r.serialize(wire));
}

TEST(DaoShareSetRecordV3, cl_v3_rejects_truncated)
{
    auto r = make_cl_v3();
    std::vector<uint8_t> wire;
    ASSERT_TRUE(r.serialize(wire));
    wire.resize(wire.size() - 1);
    dao_share_set_record r2;
    EXPECT_FALSE(r2.deserialize(wire));
}

} // namespace
} // namespace dao
} // namespace cryptonote
