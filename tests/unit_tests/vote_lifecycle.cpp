// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

// Regression tests for the vote nullifier ordering fix in
// VoteManager::process_vote(). Before the fix, add_nullifier() was called
// before the last validation that could reject a vote, so an invalid vote
// would leave a permanent entry in the nullifier table even though it was
// never counted. This test proves both directions:
//
//   1. invalid vote  -> outcome unchanged, nullifier NOT persisted
//   2. valid vote    -> outcome updated,   nullifier persisted

#include "gtest/gtest.h"

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/blockchain.h"
#include "governance/governance_db.h"
#include "governance/governance_params.h"
#include "governance/governance_payload.h"
#include "governance/vote_manager.h"
#include "governance/vote_proof.h"
#include "serialization/string.h"

#include <boost/filesystem.hpp>
#include <cstring>
#include <memory>
#include <string>

using namespace cryptonote;

namespace {

// Build a deterministic hash from a single byte value, used only to give
// each test a distinguishable proposal_id / nullifier.
crypto::hash make_hash(uint8_t seed)
{
    crypto::hash h;
    std::memset(h.data, 0, sizeof(h.data));
    h.data[0] = seed;
    h.data[31] = seed;
    return h;
}


// Construct a vns_vote transaction carrying a governance_payload with the
// given vote_proof. VoteManager trusts the totals declared by the wallet
// and does not verify CLSAG inside process_vote(), so no signature is
// produced here.
transaction make_vote_tx(
    const crypto::hash& proposal_id,
    bool direction_yes,
    uint64_t participation_balance,
    uint64_t voting_weight,
    const crypto::hash& nullifier)
{
    vote_proof vp{};
    vp.version = 1;
    vp.proposal_id = proposal_id;
    vp.direction_yes = direction_yes;
    vp.snapshot_height = 1;
    vp.participation_balance = participation_balance;
    vp.voting_weight = voting_weight;
    vp.voting_nullifiers.push_back(nullifier);
    vp.output_heights.push_back(1); // must match voting_nullifiers size
    vp.balance_commitment = rct::identity();
    vp.weight_commitment = rct::identity();
    vp.aggregate_proof.clear();

    governance_payload gp;
    gp.type = governance_object::vote;
    std::string vp_blob = t_serializable_object_to_blob(vp);
    gp.data.assign(vp_blob.begin(), vp_blob.end());

    tx_extra_governance_payload tx_gp{gp};
    tx_extra_field extra_field = tx_gp;
    std::string extra_blob = t_serializable_object_to_blob(extra_field);

    transaction tx;
    tx.version = 2;
    tx.unlock_time = 0;
    tx.extra.assign(extra_blob.begin(), extra_blob.end());

    txin_vns_vote vote_in{};
    vote_in.amount = 1000000000;
    vote_in.key_offsets = {0, 0};
    tx.vin.push_back(vote_in);

    tx.rct_signatures = rct::rctSig{};
    tx.rct_signatures.type = rct::RCTTypeNull;
    return tx;
}

class VoteFixture : public ::testing::Test
{
protected:
    std::string m_dir;
    BlockchainDB* m_db = nullptr;

    void SetUp() override
    {
        boost::filesystem::path tmp =
            boost::filesystem::temp_directory_path() /
            boost::filesystem::unique_path("vr_vote_test_%%%%-%%%%-%%%%-%%%%");
        m_dir = tmp.string();
        boost::filesystem::create_directories(m_dir);

        m_db = new BlockchainLMDB();
        m_db->open(m_dir);
    }

    void TearDown() override
    {
        if (m_db)
        {
            try { m_db->close(); } catch (...) {}
            delete m_db;
            m_db = nullptr;
        }
        boost::filesystem::remove_all(m_dir);
    }

    void store_proposal(GovernanceDB& gov,
                        const crypto::hash& pid,
                        uint64_t submission_height,
                        uint64_t voting_end_height)
    {
        proposal_record rec;
        std::memset(&rec, 0, sizeof(rec));
        rec.proposal_id = pid;
        rec.type = 0;
        rec.amount = 0;
        rec.voting_period_days = 7;
        rec.submission_height = submission_height;
        rec.voting_end_height = voting_end_height;
        rec.submission_tx_hash = pid;
        rec.status = 0;

        db_wtxn_guard guard(m_db);
        gov.store_proposal(rec);
    }
};

TEST_F(VoteFixture, InvalidVoteDoesNotPoisonNullifier)
{
    GovernanceDB gov(*m_db, MAINNET);
    governance_params params = governance_params::default_params();
    VoteManager vm(gov, params);

    const crypto::hash pid       = make_hash(0xaa);
    const crypto::hash nullifier = make_hash(0xbb);
    const uint64_t height = 10;

    store_proposal(gov, pid, /*submit=*/1, /*end=*/100);

    // Invalid vote: participation_balance == 0. VoteManager::process_vote
    // must reject with invalid_format BEFORE writing the nullifier.
    transaction tx = make_vote_tx(pid, /*yes=*/true,
                                  /*balance=*/0,
                                  /*weight=*/100,
                                  nullifier);

    vote_result r;
    {
        db_wtxn_guard guard(m_db);
        r = vm.process_vote(tx, height, false);
    }
    EXPECT_EQ(r, vote_result::invalid_format);

    // (a) The nullifier must NOT be persisted.
    EXPECT_FALSE(gov.has_nullifier(pid, nullifier));

    // (b) The outcome must remain unchanged (either not present, or all zeros).
    uint64_t yw = 0, nw = 0, yb = 0, nb = 0;
    const bool has_outcome = gov.get_outcome(pid, yw, nw, yb, nb);
    EXPECT_FALSE(has_outcome && (yw + nw + yb + nb > 0));
}

TEST_F(VoteFixture, ValidVotePersistsNullifierAndOutcome)
{
    GovernanceDB gov(*m_db, MAINNET);
    governance_params params = governance_params::default_params();
    VoteManager vm(gov, params);

    const crypto::hash pid       = make_hash(0xcc);
    const crypto::hash nullifier = make_hash(0xdd);
    const uint64_t height = 1000;

    store_proposal(gov, pid, /*submit=*/1, /*end=*/2000);

    transaction tx = make_vote_tx(pid, /*yes=*/true,
                                  /*balance=*/5000,
                                  /*weight=*/7000,
                                  nullifier);

    vote_result r;
    {
        db_wtxn_guard guard(m_db);
        r = vm.process_vote(tx, height, false);
    }
    EXPECT_EQ(r, vote_result::success);

    EXPECT_TRUE(gov.has_nullifier(pid, nullifier));

    // Current V1 semantics: total_balance = participation_balance;
    // total_weight = balance * f_i where f_i is derived from output
    // height, not the wallet-supplied voting_weight field.
    uint64_t yw = 0, nw = 0, yb = 0, nb = 0;
    EXPECT_TRUE(gov.get_outcome(pid, yw, nw, yb, nb));
    EXPECT_EQ(yw, 5000u);
    EXPECT_EQ(yb, 5000u);
    EXPECT_EQ(nw, 0u);
    EXPECT_EQ(nb, 0u);
}

TEST_F(VoteFixture, DuplicateVoteIsRejectedWithoutSecondCount)
{
    GovernanceDB gov(*m_db, MAINNET);
    governance_params params = governance_params::default_params();
    VoteManager vm(gov, params);

    const crypto::hash pid       = make_hash(0xee);
    const crypto::hash nullifier = make_hash(0xff);
    const uint64_t height = 1000;

    store_proposal(gov, pid, /*submit=*/1, /*end=*/2000);

    transaction tx = make_vote_tx(pid, /*yes=*/true,
                                  /*balance=*/5000,
                                  /*weight=*/7000,
                                  nullifier);

    vote_result r1, r2;
    {
        db_wtxn_guard guard(m_db);
        r1 = vm.process_vote(tx, height, false);
    }
    EXPECT_EQ(r1, vote_result::success);

    {
        db_wtxn_guard guard(m_db);
        r2 = vm.process_vote(tx, height, false);
    }
    EXPECT_EQ(r2, vote_result::already_voted);

    // The tally must reflect only the first vote.
    uint64_t yw = 0, nw = 0, yb = 0, nb = 0;
    EXPECT_TRUE(gov.get_outcome(pid, yw, nw, yb, nb));
    EXPECT_EQ(yw, 5000u);
    EXPECT_EQ(yb, 5000u);
}

} // namespace
