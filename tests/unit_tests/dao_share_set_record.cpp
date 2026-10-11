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
