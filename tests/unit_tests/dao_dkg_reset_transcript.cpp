// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstdint>
#include <cstring>
#include <vector>

#include "gtest/gtest.h"
#include "governance/dao_dkg_reset_transcript.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

dao_dkg_reset_config make_cfg()
{
    dao_dkg_reset_config cfg;
    cfg.old_epoch = 1;
    cfg.new_epoch = 60000;
    cfg.old_threshold = 3;
    cfg.new_threshold = 3;
    cfg.old_members.resize(4);
    cfg.new_members.resize(5);
    cfg.reset_participant_ids = {1, 2, 4};
    for (size_t i = 0; i < cfg.key_id.data + 32 - cfg.key_id.data; ++i)
        cfg.key_id.data[i] = static_cast<uint8_t>(i);
    return cfg;
}

dao_dkg_reset_config make_cfg_b()
{
    dao_dkg_reset_config cfg = make_cfg();
    cfg.reset_participant_ids = {1, 3, 4};
    return cfg;
}

dkg_msg make_public(uint32_t sender, uint32_t seq, uint8_t type_byte)
{
    dkg_msg m;
    m.hdr.version = 1;
    m.hdr.epoch = 60000;
    m.hdr.sender_id = sender;
    m.hdr.recipient_id = 0;
    m.hdr.sequence = seq;
    m.hdr.type = static_cast<dkg_msg_type>(type_byte);
    m.bytes_a = {0x01, 0x02, 0x03};
    m.tag32 = sender * 100 + seq;
    return m;
}

dkg_msg make_private(uint32_t sender, uint32_t recipient, uint32_t seq)
{
    dkg_msg m;
    m.hdr.version = 1;
    m.hdr.epoch = 60000;
    m.hdr.sender_id = sender;
    m.hdr.recipient_id = recipient;
    m.hdr.sequence = seq;
    m.hdr.type = dkg_msg_type::reshare_share;
    m.bytes_a = {0xAA, 0xBB, 0xCC, 0xDD, static_cast<uint8_t>(seq)};
    return m;
}

crypto::hash pid()
{
    crypto::hash h{};
    std::memset(h.data, 0x42, 32);
    return h;
}

} // namespace

TEST(dao_dkg_reset_transcript, order_independent)
{
    dao_dkg_reset_transcript a, b;
    auto m1 = make_public(1, 10, 0x74);
    auto m2 = make_public(2, 11, 0x74);
    auto m3 = make_public(3, 12, 0x74);
    a.append_public(m1); a.append_public(m2); a.append_public(m3);
    b.append_public(m3); b.append_public(m1); b.append_public(m2);

    auto cfg = make_cfg();
    std::vector<uint8_t> ha, hb;
    a.hash(cfg, pid(), ha);
    b.hash(cfg, pid(), hb);
    EXPECT_EQ(ha, hb);
}

TEST(dao_dkg_reset_transcript, public_tamper_changes_hash)
{
    dao_dkg_reset_transcript a, b;
    auto m1 = make_public(1, 10, 0x74);
    auto m1b = m1;
    m1b.bytes_a = {0x01, 0x02, 0x04};
    a.append_public(m1);
    b.append_public(m1b);

    auto cfg = make_cfg();
    std::vector<uint8_t> ha, hb;
    a.hash(cfg, pid(), ha);
    b.hash(cfg, pid(), hb);
    EXPECT_NE(ha, hb);
}

TEST(dao_dkg_reset_transcript, private_tamper_changes_hash)
{
    dao_dkg_reset_transcript a, b;
    auto p1 = make_private(1, 2, 20);
    auto p1b = p1;
    p1b.bytes_a.back() ^= 0x01;
    a.append_private(p1);
    b.append_private(p1b);

    auto cfg = make_cfg();
    std::vector<uint8_t> ha, hb;
    a.hash(cfg, pid(), ha);
    b.hash(cfg, pid(), hb);
    EXPECT_NE(ha, hb);
}

TEST(dao_dkg_reset_transcript, manifest_change_changes_hash)
{
    dao_dkg_reset_transcript a, b;
    a.append_public(make_public(1, 10, 0x74));
    b.append_public(make_public(1, 10, 0x74));

    std::vector<uint8_t> ha, hb;
    a.hash(make_cfg(), pid(), ha);
    b.hash(make_cfg_b(), pid(), hb);
    EXPECT_NE(ha, hb);
}

TEST(dao_dkg_reset_transcript, private_leaf_differs_from_public)
{
    // A public append of the same encrypted msg and a private append
    // of it must produce different hashes, because private records a
    // domain-separated digest of the envelope.
    auto m = make_private(1, 2, 30);
    dao_dkg_reset_transcript a, b;
    a.append_public(m);
    b.append_private(m);
    std::vector<uint8_t> ha, hb;
    a.hash(make_cfg(), pid(), ha);
    b.hash(make_cfg(), pid(), hb);
    EXPECT_NE(ha, hb);
}
