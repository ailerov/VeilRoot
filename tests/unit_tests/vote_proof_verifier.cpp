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

#include "v2_vote_builder.h"

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
    in.weight_signature.s.resize(ring_size);
    in.balance_signature.s.resize(ring_size);

    // sig.I and sig.D must be valid compressed curve points; the
    // all-zero default fails ge_frombytes_vartime inside
    // dao_clsag_verify before the structural checks run.
    rct::key id = rct::identity();
    in.weight_signature.I = id;
    in.weight_signature.D = id;
    in.balance_signature.I = id;
    in.balance_signature.D = id;
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
    in.weight_signature.s.resize(4); // mismatch
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
    in.weight_signature.s.resize(3);
    in.balance_signature.s.resize(3);
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
    // Build a fully-valid rev3 vote (weight, signed, participation-
    // balance channels) using the shared helper, install the matching
    // DB state, and drive the whole verifier.

    constexpr uint64_t VOTE_HEIGHT  = 51000;
    constexpr uint64_t PROPOSAL_SUB = 50000;
    constexpr uint64_t PROPOSAL_END = 60000;
    constexpr uint32_t TALLY_EPOCH  = 1;

    PaillierPrivateKey psk;
    ASSERT_TRUE(psk.generate_for_testing(1024));
    PaillierPublicKey ppk = psk.public_key();

    crypto::hash proposal_id = v2test::hash_from_byte(0x33);
    crypto::hash nullifier   = v2test::hash_from_byte(0xAA);

    v2test::ValidVote fx;
    ASSERT_TRUE(v2test::build_valid_vote(fx, ppk,
        proposal_id, nullifier,
        TALLY_EPOCH, VOTE_HEIGHT, PROPOSAL_SUB, PROPOSAL_END));

    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = PROPOSAL_SUB;
    db.proposal_voting_end_height = PROPOSAL_END;
    db.proposal_tally_key_epoch   = TALLY_EPOCH;
    db.have_tally_key = true;
    db.tally_key_record = fx.key_rec;

    for (const auto& kv : fx.outputs)
        db.outputs[kv.first] = kv.second;

    std::unordered_set<crypto::hash> block_nfs;
    auto r = VoteProofVerifier::verify(fx.proof, db, VOTE_HEIGHT, block_nfs);
    EXPECT_TRUE(r.success) << "reason: " << r.reason;

    // Prior-chain nullifier lookup rejects.
    db.persistent_nullifiers.insert(nullifier);
    auto r23 = VoteProofVerifier::verify(fx.proof, db, VOTE_HEIGHT, block_nfs);
    EXPECT_FALSE(r23.success);
    EXPECT_NE(r23.reason.find("step27"), std::string::npos);
    db.persistent_nullifiers.clear();

    // Same-block nullifier set rejects.
    block_nfs.insert(nullifier);
    auto r24 = VoteProofVerifier::verify(fx.proof, db, VOTE_HEIGHT, block_nfs);
    EXPECT_FALSE(r24.success);
    EXPECT_NE(r24.reason.find("step28"), std::string::npos);
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
