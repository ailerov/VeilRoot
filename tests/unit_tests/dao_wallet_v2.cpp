// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Tests for build_dao_v2_vote() (dao_wallet_v2). Constructs real
// sources with synthetic ring data, builds a vote, and feeds it
// through the consensus verifier. The only way to know the module is
// correct is that the verifier accepts its output.

#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "gtest/gtest.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "blockchain_db/testdb.h"
#include "crypto/crypto.h"
#include "governance/dao_dkg.h"
#include "governance/dao_paillier.h"
#include "governance/dao_wallet_v2.h"
#include "governance/governance_payload.h"
#include "governance/vote_proof_verifier.h"
#include "ringct/rctOps.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

class WalletV2TestDB : public BaseTestDB
{
public:
    uint64_t proposal_submission_height = 0;
    uint64_t proposal_voting_end_height = 0;
    uint32_t proposal_tally_key_epoch   = 0;

    dao::dao_tally_key_record tally_key_record;
    std::unordered_set<crypto::hash> persistent_nullifiers;
    std::unordered_map<uint64_t, output_data_t> outputs;

    void add_output(uint64_t gi, const rct::key& P, const rct::key& C,
                    uint64_t height)
    {
        output_data_t od{};
        od.height = height;
        std::memcpy(od.pubkey.data, P.bytes, 32);
        od.commitment = C;
        outputs[gi] = od;
    }

    bool get_proposal_record(const crypto::hash&, proposal_record& rec) const override
    {
        std::memset(&rec, 0, sizeof(rec));
        rec.status            = PROPOSAL_STATUS_ACTIVE;
        rec.submission_height = proposal_submission_height;
        rec.voting_end_height = proposal_voting_end_height;
        rec.tally_key_epoch   = proposal_tally_key_epoch;
        return true;
    }

    bool get_dao_tally_key(uint32_t, dao::dao_tally_key_record& rec) const override
    {
        rec = tally_key_record;
        return true;
    }

    bool has_vote_nullifier(const crypto::hash&, const crypto::hash& nf) const override
    {
        return persistent_nullifiers.count(nf) > 0;
    }

    tx_out_index get_output_tx_and_index_from_global(const uint64_t& idx) const override
    {
        if (outputs.count(idx) == 0)
            throw std::runtime_error("output not found");
        return tx_out_index{};
    }

    output_data_t get_output_key_from_global(const uint64_t& idx) const override
    {
        auto it = outputs.find(idx);
        if (it == outputs.end())
            throw std::runtime_error("output not found");
        return it->second;
    }
};

struct synthetic_source
{
    dao_v2_vote_source src;
    std::vector<rct::key> P_j;
    std::vector<rct::key> C_j;
    std::vector<uint64_t> abs;
    std::vector<uint64_t> heights;
};

// Build one synthetic source with a ring of 4 members, real at index 2.
synthetic_source make_source(uint64_t base_abs, uint64_t amount,
                             const rct::key& real_mask, uint8_t seed)
{
    synthetic_source out;
    out.abs     = { base_abs, base_abs + 1, base_abs + 2, base_abs + 3 };
    out.heights = { 40000, 30000, 20000, 10000 };
    // Real member index 2 with height 20000 → age factor 5 at vote_height 51000.

    std::vector<rct::key> xs;
    std::vector<rct::key> masks;
    std::vector<uint64_t> amts = { 10, 11, 12, 13 };
    for (size_t j = 0; j < 4; ++j) {
        rct::key x = rct::zero();
        x.bytes[0] = static_cast<uint8_t>(seed * 8 + j + 1);
        xs.push_back(x);
        rct::key m = rct::zero();
        m.bytes[0] = static_cast<uint8_t>(seed * 8 + j + 100);
        masks.push_back(m);
    }

    for (size_t j = 0; j < 4; ++j) {
        rct::key P{}, C{};
        rct::scalarmultBase(P, xs[j]);
        rct::key amtH{}, mG{};
        rct::key amt = rct::zero();
        for (int i = 0; i < 8; ++i) amt.bytes[i] = (amts[j] >> (8*i)) & 0xff;
        rct::scalarmultKey(amtH, rct::H, amt);
        rct::scalarmultBase(mG, masks[j]);
        rct::addKeys(C, amtH, mG);
        out.P_j.push_back(P);
        out.C_j.push_back(C);
    }

    // Real member's secret, mask and amount.
    out.src.real_index = 2;
    std::memcpy(out.src.real_spend_secret.data, xs[2].bytes, 32);
    out.src.real_mask   = real_mask;
    out.src.real_amount = amount;

    // Overwrite C[real_index] to match the real amount and mask.
    rct::key amtH{}, mG{};
    rct::key amt = rct::zero();
    for (int i = 0; i < 8; ++i) amt.bytes[i] = (amount >> (8*i)) & 0xff;
    rct::scalarmultKey(amtH, rct::H, amt);
    rct::scalarmultBase(mG, real_mask);
    rct::addKeys(out.C_j[2], amtH, mG);

    out.src.P = out.P_j;
    out.src.C = out.C_j;
    out.src.output_indices = out.abs;
    out.src.output_heights = out.heights;
    out.src.key_offsets = { base_abs, 1, 1, 1 };
    return out;
}

} // namespace

TEST(dao_wallet_v2, builds_valid_vote_one_input_yes)
{
    dao::PaillierPrivateKey psk;
    ASSERT_TRUE(psk.generate_for_testing(1024));
    PaillierPublicKey ppk = psk.public_key();

    std::vector<uint8_t> modulus;
    ASSERT_TRUE(ppk.serialize_modulus(modulus));
    ASSERT_EQ(modulus.size(), 256u);

    crypto::hash proposal_id{};
    proposal_id.data[0] = 0x33;
    crypto::hash tally_key_id{};
    tally_key_id.data[0] = 0x77;

    rct::key real_mask = rct::zero();
    real_mask.bytes[0] = 0x55;

    auto s = make_source(10000, 5000, real_mask, 1);

    std::vector<dao_v2_vote_source> sources = { s.src };

    vote_proof_v2 proof;
    ASSERT_TRUE(build_dao_v2_vote(
        proposal_id,
        /*submission=*/50000,
        /*vote_height=*/51000,
        /*tally_key_epoch=*/1,
        tally_key_id,
        modulus,
        /*direction=*/0,
        sources,
        proof));

    // Feed the ring members into the verifier DB.
    WalletV2TestDB db;
    db.proposal_submission_height = 50000;
    db.proposal_voting_end_height = 60000;
    db.proposal_tally_key_epoch   = 1;
    db.tally_key_record.key_id.assign(32, 0);
    std::memcpy(db.tally_key_record.key_id.data(), tally_key_id.data, 32);
    db.tally_key_record.N = modulus;
    for (size_t j = 0; j < s.P_j.size(); ++j)
        db.add_output(s.abs[j], s.P_j[j], s.C_j[j], s.heights[j]);

    std::unordered_set<crypto::hash> block_nfs;
    auto r = VoteProofVerifier::verify(proof, db, 51000, block_nfs);
    EXPECT_TRUE(r.success) << "reason: " << r.reason;
}

TEST(dao_wallet_v2, builds_valid_vote_two_inputs_no)
{
    dao::PaillierPrivateKey psk;
    ASSERT_TRUE(psk.generate_for_testing(1024));
    PaillierPublicKey ppk = psk.public_key();

    std::vector<uint8_t> modulus;
    ASSERT_TRUE(ppk.serialize_modulus(modulus));

    crypto::hash proposal_id{};
    proposal_id.data[0] = 0x44;
    crypto::hash tally_key_id{};
    tally_key_id.data[0] = 0x88;

    rct::key mask_a = rct::zero();
    mask_a.bytes[0] = 0x66;
    rct::key mask_b = rct::zero();
    mask_b.bytes[0] = 0x67;

    auto s_a = make_source(20000, 5000, mask_a, 2);
    auto s_b = make_source(30000, 7000, mask_b, 3);

    std::vector<dao_v2_vote_source> sources = { s_a.src, s_b.src };

    vote_proof_v2 proof;
    ASSERT_TRUE(build_dao_v2_vote(
        proposal_id,
        50000, 51000, 1, tally_key_id, modulus,
        /*direction=*/1, sources, proof));

    WalletV2TestDB db;
    db.proposal_submission_height = 50000;
    db.proposal_voting_end_height = 60000;
    db.proposal_tally_key_epoch   = 1;
    db.tally_key_record.key_id.assign(32, 0);
    std::memcpy(db.tally_key_record.key_id.data(), tally_key_id.data, 32);
    db.tally_key_record.N = modulus;
    for (size_t j = 0; j < s_a.P_j.size(); ++j)
        db.add_output(s_a.abs[j], s_a.P_j[j], s_a.C_j[j], s_a.heights[j]);
    for (size_t j = 0; j < s_b.P_j.size(); ++j)
        db.add_output(s_b.abs[j], s_b.P_j[j], s_b.C_j[j], s_b.heights[j]);

    std::unordered_set<crypto::hash> block_nfs;
    auto r = VoteProofVerifier::verify(proof, db, 51000, block_nfs);
    EXPECT_TRUE(r.success) << "reason: " << r.reason;
    EXPECT_EQ(proof.inputs.size(), 2u);
    EXPECT_EQ(proof.nullifiers.size(), 2u);
}


TEST(dao_wallet_v2, yes_vote_tampered_to_no_cs_fails)
{
    dao::PaillierPrivateKey psk;
    ASSERT_TRUE(psk.generate_for_testing(1024));
    PaillierPublicKey ppk = psk.public_key();

    std::vector<uint8_t> modulus;
    ASSERT_TRUE(ppk.serialize_modulus(modulus));

    crypto::hash proposal_id{};  proposal_id.data[0] = 0x11;
    crypto::hash tally_key_id{}; tally_key_id.data[0] = 0x22;

    rct::key real_mask = rct::zero();
    real_mask.bytes[0] = 0x33;
    auto s = make_source(40000, 5000, real_mask, 5);

    std::vector<dao_v2_vote_source> sources = { s.src };

    vote_proof_v2 proof;
    ASSERT_TRUE(build_dao_v2_vote(proposal_id, 50000, 51000, 1,
        tally_key_id, modulus, /*yes*/0, sources, proof));

    // Replace C_S with the identity. That breaks the OR proof and the
    // consistency proof simultaneously; the verifier must reject.
    proof.C_S = rct::identity();

    WalletV2TestDB db;
    db.proposal_submission_height = 50000;
    db.proposal_voting_end_height = 60000;
    db.proposal_tally_key_epoch   = 1;
    db.tally_key_record.key_id.assign(32, 0);
    std::memcpy(db.tally_key_record.key_id.data(), tally_key_id.data, 32);
    db.tally_key_record.N = modulus;
    for (size_t j = 0; j < s.P_j.size(); ++j)
        db.add_output(s.abs[j], s.P_j[j], s.C_j[j], s.heights[j]);

    std::unordered_set<crypto::hash> block_nfs;
    auto r = VoteProofVerifier::verify(proof, db, 51000, block_nfs);
    EXPECT_FALSE(r.success);
}

TEST(dao_wallet_v2, no_vote_tampered_direction_fails)
{
    dao::PaillierPrivateKey psk;
    ASSERT_TRUE(psk.generate_for_testing(1024));
    PaillierPublicKey ppk = psk.public_key();

    std::vector<uint8_t> modulus;
    ASSERT_TRUE(ppk.serialize_modulus(modulus));

    crypto::hash proposal_id{};  proposal_id.data[0] = 0x66;
    crypto::hash tally_key_id{}; tally_key_id.data[0] = 0x77;

    rct::key real_mask = rct::zero();
    real_mask.bytes[0] = 0x88;
    auto s = make_source(50000, 5000, real_mask, 7);

    std::vector<dao_v2_vote_source> sources = { s.src };

    vote_proof_v2 proof;
    ASSERT_TRUE(build_dao_v2_vote(proposal_id, 50000, 51000, 1,
        tally_key_id, modulus, /*no*/1, sources, proof));

    // Flip a byte in the OR proof so the challenge no longer closes.
    proof.direction_proof.c_yes.bytes[0] ^= 0x01;

    WalletV2TestDB db;
    db.proposal_submission_height = 50000;
    db.proposal_voting_end_height = 60000;
    db.proposal_tally_key_epoch   = 1;
    db.tally_key_record.key_id.assign(32, 0);
    std::memcpy(db.tally_key_record.key_id.data(), tally_key_id.data, 32);
    db.tally_key_record.N = modulus;
    for (size_t j = 0; j < s.P_j.size(); ++j)
        db.add_output(s.abs[j], s.P_j[j], s.C_j[j], s.heights[j]);

    std::unordered_set<crypto::hash> block_nfs;
    auto r = VoteProofVerifier::verify(proof, db, 51000, block_nfs);
    EXPECT_FALSE(r.success);
}
