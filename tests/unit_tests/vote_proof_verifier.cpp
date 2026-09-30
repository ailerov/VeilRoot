// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstring>
#include <unordered_set>
#include <vector>

#include "gtest/gtest.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "blockchain_db/testdb.h"
#include "governance/vote_proof_verifier.h"
#include "governance/vote_proof_v2.h"

using namespace cryptonote;

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

    std::unordered_set<uint64_t> existing_global_indices;

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

    bool get_dao_tally_key(uint32_t, dao::dao_tally_key_record&) const override
    {
        return have_tally_key;
    }

    tx_out_index get_output_tx_and_index_from_global(const uint64_t& idx) const override
    {
        if (existing_global_indices.count(idx) == 0)
            throw std::runtime_error("output not found");
        return tx_out_index{};
    }
};

vote_input_v2 make_ring_input(size_t ring_size)
{
    // All-zero relative offsets expand cumulatively to global index 0 for
    // every ring member. Tests that want to reach step 10 insert index 0
    // into the fake DB.
    vote_input_v2 in;
    for (size_t i = 0; i < ring_size; ++i)
        in.key_offsets.push_back(0);
    in.signature.s.resize(ring_size);
    return in;
}

vote_proof_v2 make_valid_until_step8()
{
    vote_proof_v2 p;
    p.version = vote_proof_v2::VERSION;
    p.vote_height = 100;
    p.tally_key_epoch = 1;
    p.inputs.push_back(make_ring_input(16));
    p.nullifiers.push_back(crypto::hash{});
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

TEST(vote_proof_verifier, step8_ring_size_not_16)
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
    p.inputs.push_back(make_ring_input(11)); // wrong
    p.nullifiers.push_back(crypto::hash{});

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step8"), std::string::npos);
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

TEST(vote_proof_verifier, step10_not_implemented)
{
    VerifierTestDB db;
    db.have_proposal = true;
    db.proposal_submission_height = 50;
    db.proposal_voting_end_height = 200;
    db.have_tally_key = true;
    db.proposal_tally_key_epoch = 1;
    db.existing_global_indices.insert(0);

    vote_proof_v2 p = make_valid_until_step8();

    std::unordered_set<crypto::hash> bn;
    auto r = VoteProofVerifier::verify(p, db, 100, bn);
    EXPECT_FALSE(r.success);
    EXPECT_NE(r.reason.find("step10"), std::string::npos);
}
