// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_dkg.h"
#include "governance/dao_paillier.h"
#include "crypto/crypto.h"

#include <openssl/bn.h>

#include <cstring>
#include <vector>

namespace {

using namespace cryptonote;
using namespace cryptonote::dao;

dao_share_set_record make_record()
{
    dao_share_set_record r;
    r.version = 1;
    r.share_set_id = 42;
    r.height = 98765;
    r.threshold = 2;
    r.key_id.assign(32, 0xAA);
    r.committee_id_hash.assign(32, 0xBB);
    for (int i = 0; i < 3; ++i) {
        std::vector<uint8_t> m(32, 0);
        m[0] = static_cast<uint8_t>(i + 1);
        r.committee_members.push_back(m);
        std::vector<uint8_t> vk(PAILLIER_CT_BYTES, 0);
        vk[0] = static_cast<uint8_t>(0x10 + i);
        r.VK_i.push_back(vk);
    }
    return r;
}

} // namespace

TEST(DaoShareSetRecord, RoundTrip)
{
    auto r = make_record();
    std::vector<uint8_t> blob;
    ASSERT_TRUE(r.serialize(blob));

    dao_share_set_record back;
    ASSERT_TRUE(back.deserialize(blob));

    EXPECT_EQ(back.version, r.version);
    EXPECT_EQ(back.share_set_id, r.share_set_id);
    EXPECT_EQ(back.height, r.height);
    EXPECT_EQ(back.threshold, r.threshold);
    EXPECT_EQ(back.key_id, r.key_id);
    EXPECT_EQ(back.committee_id_hash, r.committee_id_hash);
    EXPECT_EQ(back.committee_members, r.committee_members);
    EXPECT_EQ(back.VK_i, r.VK_i);
}

TEST(DaoShareSetRecord, RejectsZeroThreshold)
{
    auto r = make_record();
    r.threshold = 0;
    std::vector<uint8_t> blob;
    EXPECT_FALSE(r.serialize(blob));
}

TEST(DaoShareSetRecord, RejectsThresholdAboveMembers)
{
    auto r = make_record();
    r.threshold = 4;
    std::vector<uint8_t> blob;
    EXPECT_FALSE(r.serialize(blob));
}

TEST(DaoShareSetRecord, RejectsTruncated)
{
    auto r = make_record();
    std::vector<uint8_t> blob;
    ASSERT_TRUE(r.serialize(blob));
    blob.resize(blob.size() - 1);
    dao_share_set_record back;
    EXPECT_FALSE(back.deserialize(blob));
}

TEST(DaoShareSetRecord, RejectsWrongVkSize)
{
    auto r = make_record();
    r.VK_i[1].resize(PAILLIER_CT_BYTES - 1);
    std::vector<uint8_t> blob;
    EXPECT_FALSE(r.serialize(blob));
}

// ------------------------------------------------------------------
// B3c-2a: dao_share_set_record v2 with reshare evidence round-trips.
// ------------------------------------------------------------------
TEST(DaoShareSetRecordV2, EvidenceRoundTrip)
{
    using namespace cryptonote::dao;

    dao_share_set_record r{};
    r.version           = 2;
    r.share_set_id      = 42;
    r.height            = 1000;
    r.threshold         = 2;
    r.key_id.assign(32, 0xA1);
    r.committee_id_hash.assign(32, 0xA2);
    r.committee_members.resize(3);
    r.VK_i.resize(3);
    for (int i = 0; i < 3; ++i) {
        r.committee_members[i].assign(32, static_cast<uint8_t>(0xB0 + i));
        r.VK_i[i].assign(PAILLIER_CT_BYTES, static_cast<uint8_t>(0xC0 + i));
    }

    r.base_share_set_id = 7;
    r.contributions.resize(2);
    r.contributions[0].assign(100, 0xD0);
    r.contributions[1].assign(100, 0xD1);
    r.contributor_indices = { 1, 3 };
    r.contributor_vk.resize(2);
    r.contributor_vk[0].assign(PAILLIER_CT_BYTES, 0xE0);
    r.contributor_vk[1].assign(PAILLIER_CT_BYTES, 0xE1);

    std::vector<uint8_t> blob;
    ASSERT_TRUE(r.serialize(blob));
    ASSERT_FALSE(blob.empty());

    dao_share_set_record back{};
    ASSERT_TRUE(back.deserialize(blob));
    EXPECT_EQ(back.version, r.version);
    EXPECT_EQ(back.share_set_id, r.share_set_id);
    EXPECT_EQ(back.height, r.height);
    EXPECT_EQ(back.threshold, r.threshold);
    EXPECT_EQ(back.key_id, r.key_id);
    EXPECT_EQ(back.committee_members, r.committee_members);
    EXPECT_EQ(back.VK_i, r.VK_i);
    EXPECT_EQ(back.base_share_set_id, r.base_share_set_id);
    EXPECT_EQ(back.contributions, r.contributions);
    EXPECT_EQ(back.contributor_indices, r.contributor_indices);
    EXPECT_EQ(back.contributor_vk, r.contributor_vk);
}

// ------------------------------------------------------------------
// B3c-2a: v1 (legacy) deserialization still works with empty evidence.
// ------------------------------------------------------------------
TEST(DaoShareSetRecordV2, V1DeserializesWithEmptyEvidence)
{
    using namespace cryptonote::dao;

    // Simulate a v1 blob: same as v2 minus the evidence tail.
    dao_share_set_record r{};
    r.version           = 1;
    r.share_set_id      = 1;
    r.height            = 1;
    r.threshold         = 2;
    r.key_id.assign(32, 0x11);
    r.committee_id_hash.assign(32, 0x22);
    r.committee_members.resize(3);
    r.VK_i.resize(3);
    for (int i = 0; i < 3; ++i) {
        r.committee_members[i].assign(32, static_cast<uint8_t>(0x30 + i));
        r.VK_i[i].assign(PAILLIER_CT_BYTES, static_cast<uint8_t>(0x40 + i));
    }

    // Hand-build a v1 blob: no evidence tail.
    std::vector<uint8_t> v1;
    auto push_u32 = [](std::vector<uint8_t>& v, uint32_t x) {
        for (int i = 0; i < 4; ++i) v.push_back((x >> (8*i)) & 0xff);
    };
    auto push_u64 = [](std::vector<uint8_t>& v, uint64_t x) {
        for (int i = 0; i < 8; ++i) v.push_back((x >> (8*i)) & 0xff);
    };
    auto push_bytes = [&](std::vector<uint8_t>& v, const std::vector<uint8_t>& b) {
        push_u32(v, static_cast<uint32_t>(b.size()));
        v.insert(v.end(), b.begin(), b.end());
    };
    push_u32(v1, 1);           // version
    push_u64(v1, r.share_set_id);
    push_u64(v1, r.height);
    push_u32(v1, r.threshold);
    push_bytes(v1, r.key_id);
    push_bytes(v1, r.committee_id_hash);
    push_u32(v1, 3);
    for (const auto& m : r.committee_members) push_bytes(v1, m);
    for (const auto& vk : r.VK_i) push_bytes(v1, vk);

    dao_share_set_record back{};
    ASSERT_TRUE(back.deserialize(v1));
    EXPECT_EQ(back.version, 1);
    EXPECT_EQ(back.committee_members, r.committee_members);
    EXPECT_EQ(back.VK_i, r.VK_i);
    EXPECT_EQ(back.base_share_set_id, 0u);
    EXPECT_TRUE(back.contributions.empty());
    EXPECT_TRUE(back.contributor_indices.empty());
    EXPECT_TRUE(back.contributor_vk.empty());
}

