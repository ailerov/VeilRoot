// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_dkg.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/tx_pool.h"

#include <cstring>
#include <limits>
#include <vector>

namespace cryptonote {
namespace dao {
namespace {

static dao_tally_key_record make_key_rec()
{
    dao_tally_key_record r;
    r.version            = 2;
    r.committee_size     = 3;
    r.threshold          = 2;
    r.t                  = 1;
    r.committee_id_hash.assign(32, 0x22);
    r.committee_members.assign(3, std::vector<uint8_t>(32, 0x33));
    r.key_id.assign(32, 0x55);
    r.dkg_transcript_hash.assign(32, 0x99);
    r.cl_modulus.assign(48, 0xAA);
    return r;
}

static dao_share_set_record make_cl_share_set()
{
    dao_share_set_record r;
    r.version            = 3;
    r.share_set_id       = 1;
    r.height             = 100;
    r.threshold          = 2;
    r.key_id.assign(32, 0x55);
    r.committee_id_hash.assign(32, 0x22);
    r.committee_members.assign(3, std::vector<uint8_t>(32, 0x33));
    r.cl_gammas_serialized = std::vector<uint8_t>(64, 0x88);
    r.qualified_ids = {0u, 1u, 2u};
    return r;
}

TEST(DaoDkgProposalEligibility, rejects_terminal_and_already_keyed_proposals)
{
    cryptonote::proposal_record rec{};
    rec.tally_key_id = crypto::null_hash;

    rec.status = cryptonote::PROPOSAL_STATUS_ACTIVE;
    EXPECT_TRUE(cryptonote::dao_v2_dkg_proposal_eligible(rec));

    rec.status = cryptonote::PROPOSAL_STATUS_REJECTED;
    EXPECT_FALSE(cryptonote::dao_v2_dkg_proposal_eligible(rec));

    rec.status = cryptonote::PROPOSAL_STATUS_EXPIRED;
    EXPECT_FALSE(cryptonote::dao_v2_dkg_proposal_eligible(rec));

    rec.status = cryptonote::PROPOSAL_STATUS_PASSED;
    EXPECT_FALSE(cryptonote::dao_v2_dkg_proposal_eligible(rec));

    rec.status = cryptonote::PROPOSAL_STATUS_EXECUTED;
    EXPECT_FALSE(cryptonote::dao_v2_dkg_proposal_eligible(rec));

    rec.status = cryptonote::PROPOSAL_STATUS_FAILED_EXECUTION;
    EXPECT_FALSE(cryptonote::dao_v2_dkg_proposal_eligible(rec));

    rec.status = cryptonote::PROPOSAL_STATUS_ACTIVE;
    rec.tally_key_id.data[0] = 1;
    EXPECT_FALSE(cryptonote::dao_v2_dkg_proposal_eligible(rec));
}

TEST(DaoDkgKeyActivationV3, v2_roundtrip_without_share_set)
{
    dao_dkg_key_activation a;
    a.version          = 2;
    a.selection_height = 50;
    a.proposal_id      = crypto::null_hash;
    std::memset(a.proposal_id.data, 0x01, 32);
    a.record           = make_key_rec();
    for (uint32_t i = 1; i <= 3; ++i) {
        dao_dkg_key_attestation att;
        att.member_index = i;
        att.signature.assign(sizeof(crypto::signature), 0xCC);
        a.attestations.push_back(att);
    }

    std::vector<uint8_t> wire;
    ASSERT_TRUE(a.serialize(wire));
    EXPECT_EQ(wire[0], 2u);

    dao_dkg_key_activation a2;
    ASSERT_TRUE(a2.deserialize(wire));
    EXPECT_EQ(a2.version, 2u);
    EXPECT_EQ(a2.selection_height, a.selection_height);
    EXPECT_EQ(a2.proposal_id, a.proposal_id);
    EXPECT_EQ(a2.attestations.size(), a.attestations.size());
    // v2 deserialize leaves initial_share_set default-constructed
    EXPECT_TRUE(a2.initial_share_set.committee_members.empty());
}

TEST(DaoDkgKeyActivationV3, v3_roundtrip_with_share_set)
{
    dao_dkg_key_activation a;
    a.version          = 3;
    a.selection_height = 50;
    std::memset(a.proposal_id.data, 0x01, 32);
    a.record           = make_key_rec();
    a.initial_share_set = make_cl_share_set();
    for (uint32_t i = 1; i <= 3; ++i) {
        dao_dkg_key_attestation att;
        att.member_index = i;
        att.signature.assign(sizeof(crypto::signature), 0xCC);
        a.attestations.push_back(att);
    }

    std::vector<uint8_t> wire;
    ASSERT_TRUE(a.serialize(wire));
    EXPECT_EQ(wire[0], 3u);

    dao_dkg_key_activation a2;
    ASSERT_TRUE(a2.deserialize(wire));
    EXPECT_EQ(a2.version, 3u);
    EXPECT_EQ(a2.record.key_id, a.record.key_id);
    EXPECT_EQ(a2.initial_share_set.share_set_id,
              a.initial_share_set.share_set_id);
    EXPECT_EQ(a2.initial_share_set.cl_gammas_serialized,
              a.initial_share_set.cl_gammas_serialized);
    EXPECT_EQ(a2.initial_share_set.qualified_ids,
              a.initial_share_set.qualified_ids);
}

TEST(DaoDkgKeyActivationV3, digest_v3_binds_share_set)
{
    crypto::hash genesis{};
    std::memset(genesis.data, 0xA5, 32);
    crypto::hash prop{};
    std::memset(prop.data, 0x11, 32);

    auto rec = make_key_rec();
    auto ss = make_cl_share_set();

    auto d1 = dao_dkg_activation_digest_v3(genesis, 50, rec, ss, prop);
    EXPECT_NE(d1, crypto::null_hash);

    // Different share set => different digest
    auto ss2 = ss;
    ss2.cl_gammas_serialized[0] ^= 0x01;
    auto d2 = dao_dkg_activation_digest_v3(genesis, 50, rec, ss2, prop);
    EXPECT_NE(d1, d2);

    // Different selection height => different digest
    auto d3 = dao_dkg_activation_digest_v3(genesis, 51, rec, ss, prop);
    EXPECT_NE(d1, d3);

    // Deterministic
    auto d4 = dao_dkg_activation_digest_v3(genesis, 50, rec, ss, prop);
    EXPECT_EQ(d1, d4);
}

TEST(DaoDkgKeyActivationV3, rejects_unsorted_attestations)
{
    dao_dkg_key_activation a;
    a.version = 3;
    a.record = make_key_rec();
    a.initial_share_set = make_cl_share_set();
    for (uint32_t i : {2u, 1u, 3u}) {
        dao_dkg_key_attestation att;
        att.member_index = i;
        att.signature.assign(sizeof(crypto::signature), 0xCC);
        a.attestations.push_back(att);
    }
    std::vector<uint8_t> wire;
    EXPECT_FALSE(a.serialize(wire));
}

TEST(DaoDkgKeyActivationV3, rejects_trailing_bytes)
{
    dao_dkg_key_activation a;
    a.version = 3;
    a.record = make_key_rec();
    a.initial_share_set = make_cl_share_set();
    dao_dkg_key_attestation att;
    att.member_index = 1;
    att.signature.assign(sizeof(crypto::signature), 0xCC);
    a.attestations.push_back(att);
    std::vector<uint8_t> wire;
    ASSERT_TRUE(a.serialize(wire));
    wire.push_back(0);
    dao_dkg_key_activation a2;
    EXPECT_FALSE(a2.deserialize(wire));
}

TEST(DaoDkgActivationRelay, only_consensus_valid_zero_fee_dao_tx_bypasses_fee_gate)
{
    txpool_tx_meta_t meta{};

    EXPECT_FALSE(tx_memory_pool::is_relayable_transaction(meta, false));
    EXPECT_TRUE(tx_memory_pool::is_relayable_transaction(meta, true));

    // Ordinary fee-paying transactions remain relayable without the DAO
    // exception, while the existing metadata filters remain authoritative.
    meta.fee = 1;
    EXPECT_TRUE(tx_memory_pool::is_relayable_transaction(meta, false));

    meta.fee = 0;
    meta.pruned = 1;
    EXPECT_FALSE(tx_memory_pool::is_relayable_transaction(meta, true));

    meta.pruned = 0;
    meta.do_not_relay = 1;
    EXPECT_FALSE(tx_memory_pool::is_relayable_transaction(meta, true));
}

TEST(DaoDkgActivationRelay, unset_last_relay_timestamp_allows_first_broadcast)
{
    txpool_tx_meta_t meta{};
    meta.receive_time = 1000;
    meta.last_relayed_time = std::numeric_limits<uint64_t>::max();
    EXPECT_TRUE(tx_memory_pool::is_relay_delay_elapsed(meta, 1001));

    // After the first relay, the ordinary minimum relay delay applies.
    meta.last_relayed_time = 1000;
    EXPECT_FALSE(tx_memory_pool::is_relay_delay_elapsed(meta, 1001));
    EXPECT_TRUE(tx_memory_pool::is_relay_delay_elapsed(meta, 1301));

    // Future timestamps are not treated as elapsed.
    meta.last_relayed_time = 1400;
    EXPECT_FALSE(tx_memory_pool::is_relay_delay_elapsed(meta, 1301));
}

} // namespace
} // namespace dao
} // namespace cryptonote
