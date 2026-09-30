// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "gtest/gtest.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "ringct/rctOps.h"
#include "blockchain_db/testdb.h"
#include "governance/dao_clsag.h"
#include "governance/dao_consistency.h"
#include "governance/dao_dkg.h"
#include "governance/dao_paillier.h"
#include "governance/dao_vote_or_proof.h"
#include "governance/vote_proof_verifier.h"
#include "governance/governance_payload.h"
#include "serialization/binary_archive.h"
#include "governance/vote_proof_v2.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

// Minimal BaseTestDB subclass. Only the accessors used by steps 1-9
// are overridden; everything else inherits BaseTestDB's no-op stubs.
class VerifierTestDB : public BaseTestDB
{
public:
    bool have_proposal = false;
    bool have_tally_key = false;
    uint64_t proposal_submission_height = 0;
    uint64_t proposal_voting_end_height = 0;
    uint64_t proposal_tally_key_epoch   = 0;
    uint8_t  proposal_status            = PROPOSAL_STATUS_ACTIVE;

    dao::dao_tally_key_record tally_key_record;
    std::unordered_set<crypto::hash> persistent_nullifiers;

    std::unordered_map<uint64_t, output_data_t> outputs;

    void add_output(uint64_t gi, uint64_t height = 0)
    {
        output_data_t od{};
        od.height = height;

        // Fill pubkey and commitment with a valid compressed Ed25519
        // point. The all-zero default is not a curve point and
        // ge_frombytes_vartime rejects it inside dao_clsag_verify.
        rct::key id = rct::identity();
        std::memcpy(od.pubkey.data, id.bytes, 32);
        od.commitment = id;

        outputs[gi] = od;
    }

    bool get_proposal_record(const crypto::hash&, proposal_record& rec) const override
    {
        if (!have_proposal) return false;
        std::memset(&rec, 0, sizeof(rec));
        rec.status              = proposal_status;
        rec.submission_height   = proposal_submission_height;
        rec.voting_end_height   = proposal_voting_end_height;
        rec.tally_key_epoch     = proposal_tally_key_epoch;
        return true;
    }

    bool get_dao_tally_key(uint32_t, dao::dao_tally_key_record& rec) const override
    {
        if (!have_tally_key) return false;
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

vote_input_v2 make_ring_input(size_t ring_size)
{
    // Relative offsets [0, 1, 1, 1, ...] expand cumulatively to absolute
    // indices [0, 1, 2, ..., ring_size - 1]. Tests insert those globals
    // into the fake DB for step 9 to succeed.
    vote_input_v2 in;
    for (size_t i = 0; i < ring_size; ++i)
        in.key_offsets.push_back(i == 0 ? 0 : 1);
    in.signature.s.resize(ring_size);

    // sig.I and sig.D must be valid compressed curve points; the
    // all-zero default fails ge_frombytes_vartime inside
    // dao_clsag_verify before the structural checks run.
    rct::key id = rct::identity();
    in.signature.I = id;
    in.signature.D = id;
    return in;
}

vote_proof_v2 make_valid_until_step8()
{
    vote_proof_v2 p;
    p.version = vote_proof_v2::VERSION;
    p.vote_height = 100;
    p.tally_key_epoch = 1;
    p.inputs.push_back(make_ring_input(16));
    { crypto::hash n; n.data[0] = 0x03; p.nullifiers.push_back(n); }
    return p;
}

} // namespace

TEST(vote_proof_verifier, step1_nullifier_count_mismatch)
{
    VerifierTestDB db;
    vote_proof_v2 p = make_valid_until_step8();
    p.nullifiers.clear(); // mismatch: 1 input, 0 nullifiers

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step1"), std::string::npos);
}

TEST(vote_proof_verifier, step2_wrong_version)
{
    VerifierTestDB db;
    vote_proof_v2 p = make_valid_until_step8();
    p.version = 1;

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step2"), std::string::npos);
}

TEST(vote_proof_verifier, step3_proposal_not_found)
{
    VerifierTestDB db; // have_proposal = false
    vote_proof_v2 p = make_valid_until_step8();

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step3"), std::string::npos);
}

TEST(vote_proof_verifier, step4_voting_period_closed)
{
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 90;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;

    vote_proof_v2 p = make_valid_until_step8();
    p.vote_height = 100;

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step4"), std::string::npos);
}

TEST(vote_proof_verifier, step5_vote_height_mismatch)
{
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;

    vote_proof_v2 p = make_valid_until_step8();
    p.vote_height = 99; // != block_height 100

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step5"), std::string::npos);
}

TEST(vote_proof_verifier, step6_epoch_mismatch)
{
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.proposal_tally_key_epoch = 7;
    db.have_tally_key = true;

    vote_proof_v2 p = make_valid_until_step8();
    p.tally_key_epoch = 1;

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step6"), std::string::npos);
}

TEST(vote_proof_verifier, step7_no_inputs)
{
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;

    vote_proof_v2 p = make_valid_until_step8();
    p.inputs.clear();
    p.nullifiers.clear();

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step7"), std::string::npos);
}

TEST(vote_proof_verifier, step8_empty_ring)
{
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;

    vote_proof_v2 p;
    p.version = vote_proof_v2::VERSION;
    p.vote_height = 100;
    p.tally_key_epoch = 1;
    vote_input_v2 in;
    // key_offsets left empty
    p.inputs.push_back(in);
    p.nullifiers.push_back(crypto::hash{});

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step8"), std::string::npos);
}

TEST(vote_proof_verifier, step8_clsag_size_mismatch)
{
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;

    vote_proof_v2 p;
    p.version = vote_proof_v2::VERSION;
    p.vote_height = 100;
    p.tally_key_epoch = 1;
    vote_input_v2 in = make_ring_input(5);
    in.signature.s.resize(4); // mismatch
    p.inputs.push_back(in);
    p.nullifiers.push_back(crypto::hash{});

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step8"), std::string::npos);
}

TEST(vote_proof_verifier, step8_duplicate_absolute_index)
{
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;

    vote_proof_v2 p;
    p.version = vote_proof_v2::VERSION;
    p.vote_height = 100;
    p.tally_key_epoch = 1;
    vote_input_v2 in;
    in.key_offsets = { 0, 1, 0 }; // abs = {0, 1, 1}: duplicate
    in.signature.s.resize(3);
    p.inputs.push_back(in);
    p.nullifiers.push_back(crypto::hash{});

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step8"), std::string::npos);
}

TEST(vote_proof_verifier, step8_variable_ring_accepted)
{
    // No frozen DAO ring-size constant: any non-empty ring with matching
    // CLSAG dimensions is structurally valid. Use ring size 3 to make the
    // point that the verifier is not pinned to 16.
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;
    for (uint64_t i = 0; i < 3; ++i)
        db.add_output(i);

    vote_proof_v2 p;
    p.version = vote_proof_v2::VERSION;
    p.vote_height = 100;
    p.tally_key_epoch = 1;
    p.inputs.push_back(make_ring_input(3));
    { crypto::hash n; n.data[0] = 0x01; p.nullifiers.push_back(n); }

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    // Structural checks passed; failure is downstream in the not-yet-
    // implemented pipeline, not at step 8.
    EXPECT_EQ(r.reason.find("step8"), std::string::npos);
    EXPECT_NE(r.reason.find("step15"), std::string::npos);
}

TEST(vote_proof_verifier, spent_ring_member_accepted_by_design)
{
    // Spec amendment: DAO voting is non-consuming. A ring member that is
    // already spent on chain is not rejected by consensus. The stub
    // cannot express "spent", but this test documents that no spent-status
    // check exists between steps 8 and 9 and the vote proceeds past them.
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;
    for (uint64_t i = 0; i < 5; ++i)
        db.add_output(i);

    vote_proof_v2 p;
    p.version = vote_proof_v2::VERSION;
    p.vote_height = 100;
    p.tally_key_epoch = 1;
    p.inputs.push_back(make_ring_input(5));
    { crypto::hash n; n.data[0] = 0x02; p.nullifiers.push_back(n); }

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    // Not rejected at step 8 or 9; fails only because steps 11+ are not
    // implemented yet.
    EXPECT_FALSE(r.success);
    EXPECT_EQ(r.reason.find("step8"),  std::string::npos);
    EXPECT_EQ(r.reason.find("step9"),  std::string::npos);
    EXPECT_EQ(r.reason.find("step13"), std::string::npos);
    EXPECT_EQ(r.reason.find("step14"), std::string::npos);
    EXPECT_NE(r.reason.find("step15"), std::string::npos);
}

TEST(vote_proof_verifier, step9_output_missing)
{
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;
    // existing_global_indices is empty; any lookup throws.

    vote_proof_v2 p = make_valid_until_step8();

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step9"), std::string::npos);
}

TEST(vote_proof_verifier, step15_clsag_fails_first)
{
    // A structurally valid vote with an empty CLSAG (identity s vector,
    // zero c1) reaches step 15 and is rejected there.
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;
    for (uint64_t i = 0; i < 16; ++i)
        db.add_output(i);

    vote_proof_v2 p = make_valid_until_step8();

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step15"), std::string::npos);
}

TEST(vote_proof_verifier, step13_zero_nullifier)
{
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;
    for (uint64_t i = 0; i < 16; ++i)
        db.add_output(i);

    vote_proof_v2 p = make_valid_until_step8();
    p.nullifiers[0] = crypto::hash{}; // zero

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step13"), std::string::npos);
}

TEST(vote_proof_verifier, step13_duplicate_nullifier_within_vote)
{
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;
    for (uint64_t i = 0; i < 32; ++i)
        db.add_output(i);

    vote_proof_v2 p;
    p.version = vote_proof_v2::VERSION;
    p.vote_height = 100;
    p.tally_key_epoch = 1;
    p.inputs.push_back(make_ring_input(16));
    p.inputs.push_back(make_ring_input(16));
    crypto::hash n; n.data[0] = 0xAA;
    p.nullifiers.push_back(n);
    p.nullifiers.push_back(n); // duplicate

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step13"), std::string::npos);
}

TEST(vote_proof_verifier, step14_output_height_exceeds_vote_height)
{
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;
    for (uint64_t i = 0; i < 16; ++i)
        db.add_output(i, 200); // height 200 > vote_height 100

    vote_proof_v2 p = make_valid_until_step8();
    crypto::hash n; n.data[0] = 0x77;
    p.nullifiers[0] = n;

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step14"), std::string::npos);
}


// ---- End-to-end: a fully valid vote passes steps 1-24 ----

namespace {

rct::key mk_s(uint8_t v)
{
    rct::key k{};
    k.bytes[0] = v;
    return k;
}

rct::key small_scalar(uint64_t v)
{
    rct::key k{};
    for (int i = 0; i < 8; ++i) k.bytes[i] = (v >> (8 * i)) & 0xff;
    return k;
}

crypto::hash h32(uint8_t seed)
{
    crypto::hash h{};
    std::memset(h.data, seed, 32);
    return h;
}

} // namespace

TEST(vote_proof_verifier, valid_vote_passes_all_24_steps)
{
    // 1. Build a fully valid vote and the DB state that verifies it.
    constexpr uint64_t VOTE_HEIGHT    = 51000;
    constexpr uint64_t PROPOSAL_SUB   = 50000;
    constexpr uint64_t PROPOSAL_END   = 60000;
    constexpr uint32_t TALLY_EPOCH    = 1;
    const size_t N = 4;
    const size_t L = 2;

    crypto::hash proposal_id = h32(0x33);

    uint64_t heights[N]    = {40000, 30000, 20000, 10000};
    uint8_t  exp_f[N]      = {4, 4, 5, 5};
    uint64_t amt[N]        = {10, 11, 12, 13};

    rct::key x_s[N], mask[N], P[N], C[N], f_s[N], Q[N];
    for (size_t i = 0; i < N; ++i) {
        x_s[i]  = mk_s(0x10 + (uint8_t)i);
        mask[i] = mk_s(0x20 + (uint8_t)i);
        rct::scalarmultBase(P[i], x_s[i]);

        rct::key aH, mG;
        rct::scalarmultKey(aH, rct::H, small_scalar(amt[i]));
        rct::scalarmultBase(mG, mask[i]);
        rct::addKeys(C[i], aH, mG);

        f_s[i] = small_scalar(exp_f[i]);
        rct::scalarmultKey(Q[i], C[i], f_s[i]);
    }

    rct::key rho_l = mk_s(0x40);
    rct::key rhoG;
    rct::scalarmultBase(rhoG, rho_l);
    rct::key V;
    rct::addKeys(V, Q[L], rhoG);

    // R_W = f[L]*mask[L] + rho_l
    rct::key R_W;
    sc_muladd(R_W.bytes, f_s[L].bytes, mask[L].bytes, rho_l.bytes);

    // W = f[L] * amt[L]
    uint64_t W_val = (uint64_t)exp_f[L] * amt[L];

    // S must satisfy S == +W (YES) or S == -W (NO); the OR proof only
    // has a valid discrete-log branch when one of these holds.
    rct::key S_s = small_scalar(W_val);
    rct::key R_S = mk_s(0x55);
    rct::key SH, RSG, C_S;
    rct::scalarmultKey(SH, rct::H, S_s);
    rct::scalarmultBase(RSG, R_S);
    rct::addKeys(C_S, SH, RSG);

    // 2. Paillier keypair and ciphertexts.
    PaillierPrivateKey psk;
    ASSERT_TRUE(psk.generate_for_testing(1024));
    PaillierPublicKey ppk = psk.public_key();

    BIGNUM* W_bn = BN_new(); BN_set_word(W_bn, W_val);
    BIGNUM* S_bn = BN_new(); BN_set_word(S_bn, W_val);
    BIGNUM* r_W  = BN_new(); BN_set_word(r_W, 3);
    BIGNUM* r_S  = BN_new(); BN_set_word(r_S, 5);

    std::vector<uint8_t> E_W_raw, E_S_raw;
    ASSERT_TRUE(ppk.encrypt(W_bn, r_W, E_W_raw));
    ASSERT_TRUE(ppk.encrypt(S_bn, r_S, E_S_raw));

    // 3. Tally key record (matching N).
    dao::dao_tally_key_record key_rec;
    key_rec.epoch = TALLY_EPOCH;
    key_rec.N.assign(256, 0);
    BN_bn2binpad(ppk.N(), key_rec.N.data(), 256);
    key_rec.key_id.assign(32, 0x11);

    // 4. Transcript digest.
    crypto::hash nullifier = h32(0xAA);

    dao::dao_vote_transcript_input ti;
    ti.version = 2;
    ti.proposal_id = proposal_id;
    ti.proposal_submission_height = PROPOSAL_SUB;
    ti.vote_height = VOTE_HEIGHT;
    ti.tally_key_epoch = TALLY_EPOCH;
    std::memcpy(ti.tally_key_id.data, key_rec.key_id.data(), 32);

    std::vector<uint64_t> rel_offsets = { 1000, 1000, 1000, 1000 };
    std::vector<uint64_t> abs_indices = { 1000, 2000, 3000, 4000 };
    std::vector<rct::key> Pv(P, P + N), Cv(C, C + N);
    std::vector<uint64_t> hv(heights, heights + N);
    std::vector<uint8_t>  fv(exp_f, exp_f + N);

    ti.key_offsets.push_back(rel_offsets);
    ti.absolute_indices.push_back(abs_indices);
    ti.P.push_back(Pv);
    ti.C.push_back(Cv);
    ti.output_heights.push_back(hv);
    ti.age_factors.push_back(fv);
    ti.nullifiers.push_back(nullifier);
    ti.C_W = V;
    ti.C_S = C_S;
    ti.E_W = E_W_raw;
    ti.E_S = E_S_raw;

    std::vector<uint8_t> digest = dao::dao_vote_input_transcript(ti);
    ASSERT_EQ(digest.size(), 32u);

    // 5. Consistency proofs.
    dao::dao_consistency_context cctx;
    cctx.domain = "C_W-Enc(W)";
    cctx.version = 2;
    cctx.proposal_id = proposal_id;
    cctx.vote_height = VOTE_HEIGHT;
    cctx.tally_key_epoch = TALLY_EPOCH;
    cctx.vote_input_transcript = digest;

    dao::dao_consistency_proof pW;
    ASSERT_TRUE(dao::dao_consistency_prove(cctx, ppk.N(), E_W_raw, V,
                                           W_bn, r_W, R_W, pW));

    dao::dao_consistency_context cctx_s = cctx;
    cctx_s.domain = "C_S-Enc(S)";
    dao::dao_consistency_proof pS;
    ASSERT_TRUE(dao::dao_consistency_prove(cctx_s, ppk.N(), E_S_raw, C_S,
                                           S_bn, r_S, R_S, pS));

    // 6. OR proof.
    dao_or_context octx;
    octx.version = 2;
    octx.proposal_id = proposal_id;
    octx.vote_height = VOTE_HEIGHT;
    {
        rct::key nfk{};
        std::memcpy(nfk.bytes, nullifier.data, 32);
        octx.nullifiers.push_back(nfk);
    }
    octx.key_offsets = rel_offsets;
    octx.extra_binding = dao::dao_extra_binding(E_W_raw, E_S_raw, pW, pS);
    octx.C_W = V;
    octx.C_S = C_S;

    dao_vote_or_proof orp;
    ASSERT_TRUE(dao_or_prove(octx, true, R_S, R_W, orp));

    // 7. CLSAG.
    dao_clsag_context cctx_clsag;
    cctx_clsag.proposal_id                = proposal_id;
    cctx_clsag.proposal_submission_height = PROPOSAL_SUB;
    cctx_clsag.vote_height                = VOTE_HEIGHT;
    cctx_clsag.tally_key_epoch            = TALLY_EPOCH;
    cctx_clsag.P = Pv;
    cctx_clsag.C = Cv;
    cctx_clsag.output_indices = abs_indices;
    cctx_clsag.output_heights = hv;
    cctx_clsag.age_factors    = fv;
    cctx_clsag.V              = V;

    rct::clsag sig;
    crypto::secret_key sk;
    std::memcpy(sk.data, x_s[L].bytes, 32);
    ASSERT_TRUE(dao_clsag_generate(cctx_clsag, L, sk, rho_l, sig));

    // 8. Wire assembly.
    vote_proof_v2 p;
    p.version         = vote_proof_v2::VERSION;
    p.proposal_id     = proposal_id;
    p.vote_height     = VOTE_HEIGHT;
    p.tally_key_epoch = TALLY_EPOCH;

    vote_input_v2 in;
    in.key_offsets = rel_offsets;
    in.weight_commitment = V;
    in.signature = sig;
    p.inputs.push_back(in);
    p.nullifiers.push_back(nullifier);

    p.C_W = V;
    p.C_S = C_S;
    std::memcpy(p.E_W.data.data(), E_W_raw.data(), 512);
    std::memcpy(p.E_S.data.data(), E_S_raw.data(), 512);
    p.proof_W = pW;
    p.proof_S = pS;
    p.direction_proof = orp;
    std::memcpy(p.transcript_hash.data, digest.data(), 32);

    // 9. DB state.
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = PROPOSAL_SUB;
    db.proposal_voting_end_height = PROPOSAL_END;
    db.proposal_tally_key_epoch   = TALLY_EPOCH;
    db.have_tally_key = true;
    db.tally_key_record = key_rec;

    for (size_t i = 0; i < N; ++i) {
        output_data_t od{};
        std::memcpy(od.pubkey.data, P[i].bytes, 32);
        od.commitment = C[i];
        od.height = heights[i];
        db.outputs[abs_indices[i]] = od;
    }

    // 10. Verify.
    std::unordered_set<crypto::hash> block_nfs;
    auto r = VoteProofVerifier::verify(p, db, VOTE_HEIGHT, block_nfs);
    EXPECT_TRUE(r.success) << "reason: " << r.reason;

    // 11. Step 23 rejection.
    db.persistent_nullifiers.insert(nullifier);
    auto r23 = VoteProofVerifier::verify(p, db, VOTE_HEIGHT, block_nfs);
    EXPECT_FALSE(r23.success);
    EXPECT_NE(r23.reason.find("step23"), std::string::npos);
    db.persistent_nullifiers.clear();

    // 12. Step 24 rejection.
    block_nfs.insert(nullifier);
    auto r24 = VoteProofVerifier::verify(p, db, VOTE_HEIGHT, block_nfs);
    EXPECT_FALSE(r24.success);
    EXPECT_NE(r24.reason.find("step24"), std::string::npos);

    BN_free(W_bn); BN_free(S_bn); BN_free(r_W); BN_free(r_S);
}

// ---- V2 carrier roundtrip ----

namespace {

void append_varint(std::vector<uint8_t>& v, uint64_t n)
{
    while (n >= 0x80) {
        v.push_back(static_cast<uint8_t>((n & 0x7f) | 0x80));
        n >>= 7;
    }
    v.push_back(static_cast<uint8_t>(n & 0x7f));
}

bool read_varint(const std::vector<uint8_t>& v, size_t& off, uint64_t& out)
{
    out = 0;
    int shift = 0;
    while (off < v.size()) {
        const uint8_t b = v[off++];
        out |= static_cast<uint64_t>(b & 0x7f) << shift;
        if ((b & 0x80) == 0) return true;
        shift += 7;
        if (shift > 63) return false;
    }
    return false;
}

} // namespace

TEST(vote_proof_verifier, v2_payload_roundtrip_via_governance_object)
{
    vote_proof_v2 p;
    p.version         = vote_proof_v2::VERSION;
    p.vote_height     = 51000;
    p.tally_key_epoch = 1;
    p.C_W = rct::identity();
    p.C_S = rct::identity();

    // Object-level serialization (BEGIN_SERIALIZE_OBJECT path).
    blobdata body;
    ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(p, body));

    // Manually wrap in the canonical governance_payload wire form:
    //   varint(governance_object::vote_v2) || varint(len) || body
    std::vector<uint8_t> wire;
    append_varint(wire, static_cast<uint64_t>(governance_object::vote_v2));
    append_varint(wire, body.size());
    wire.insert(wire.end(), body.begin(), body.end());

    // Unwrap.
    size_t off = 0;
    uint64_t tag = 0, len = 0;
    ASSERT_TRUE(read_varint(wire, off, tag));
    ASSERT_EQ(tag, 3u); // vote_v2
    ASSERT_TRUE(read_varint(wire, off, len));
    ASSERT_EQ(len, body.size());
    ASSERT_LE(off + len, wire.size());

    vote_proof_v2 p2;
    blobdata body2(wire.begin() + off, wire.begin() + off + len);
    ASSERT_TRUE(cryptonote::t_serializable_object_from_blob(p2, body2));
    EXPECT_EQ(p2.version, vote_proof_v2::VERSION);
    EXPECT_EQ(p2.vote_height, 51000u);
    EXPECT_EQ(p2.tally_key_epoch, 1u);
}
