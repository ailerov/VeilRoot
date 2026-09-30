// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Consensus-level tests for V2 DAO vote apply and rollback:
//   - apply_dao_vote updates aggregate bytes, nullifier table,
//     and the per-vote record.
//   - rollback_block inverts the aggregate contribution byte-for-byte.

#include <cstring>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "gtest/gtest.h"

#include <boost/filesystem.hpp>

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
#include "governance/vote_proof_v2.h"
#include "serialization/string.h"

#include "v2_vote_builder.h"

using namespace cryptonote;
using namespace cryptonote::v2test;

namespace {

transaction make_v2_tx(const vote_proof_v2& proof)
{
    governance_payload gp;
    gp.type = governance_object::vote_v2;
    std::string blob = t_serializable_object_to_blob(proof);
    gp.data.assign(blob.begin(), blob.end());

    tx_extra_governance_payload tgp{gp};
    tx_extra_field ef = tgp;
    std::string extra = t_serializable_object_to_blob(ef);

    transaction tx;
    tx.version = 2;
    tx.extra.assign(extra.begin(), extra.end());
    tx.rct_signatures.type = rct::RCTTypeNull;
    return tx;
}

block make_block(const std::vector<transaction>& txs)
{
    block blk;
    for (const auto& tx : txs)
        blk.tx_hashes.push_back(cryptonote::get_transaction_hash(tx));
    return blk;
}

class ConsensusFixture : public ::testing::Test
{
protected:
    std::string m_dir;
    BlockchainLMDB* m_db = nullptr;

    void SetUp() override
    {
        boost::filesystem::path tmp =
            boost::filesystem::temp_directory_path() /
            boost::filesystem::unique_path("vr_v2_cons_%%%%-%%%%-%%%%");
        m_dir = tmp.string();
        boost::filesystem::create_directories(m_dir);
        m_db = new BlockchainLMDB();
        m_db->open(m_dir);
    }

    void TearDown() override
    {
        if (m_db) { try { m_db->close(); } catch (...) {} delete m_db; }
        boost::filesystem::remove_all(m_dir);
    }

    void install(const ValidVote& fx)
    {
        // Proposal record.
        proposal_record rec;
        std::memset(&rec, 0, sizeof(rec));
        rec.proposal_id           = fx.proposal_id;
        rec.voting_period_days    = 7;
        rec.submission_height     = fx.proposal_submission_height;
        rec.voting_end_height     = fx.proposal_voting_end_height;
        rec.submission_tx_hash    = fx.proposal_id;
        rec.status                = 0;
        rec.tally_key_epoch       = fx.tally_epoch;

        db_wtxn_guard g(m_db);
        m_db->add_proposal_record(fx.proposal_id, rec);
        m_db->add_dao_tally_key(fx.tally_epoch, fx.key_rec);
        m_db->set_current_dao_tally_key_epoch(fx.tally_epoch);
    }

    bool apply(const ValidVote& fx)
    {
        GovernanceDB gov(*m_db, MAINNET);
        governance_params params = governance_params::default_params();
        VoteManager vm(gov, params);
        db_wtxn_guard g(m_db);
        return vm.apply_dao_vote(fx.proof,
            cryptonote::get_transaction_hash(make_v2_tx(fx.proof)));
    }
};

} // namespace

TEST_F(ConsensusFixture, apply_writes_aggregate_nullifier_and_record)
{
    ValidVote fx;
    ASSERT_TRUE(build_valid_vote(fx,
        hash_from_byte(0x33), hash_from_byte(0xAA),
        /*tally_epoch=*/1, /*vote_height=*/51000,
        /*submission=*/50000, /*end=*/60000));
    install(fx);
    ASSERT_TRUE(apply(fx));

    dao_proposal_aggregate agg;
    ASSERT_TRUE(m_db->get_dao_proposal_aggregate(fx.proposal_id, agg));
    EXPECT_EQ(agg.aggregate_E_W, fx.E_W());
    EXPECT_EQ(agg.aggregate_E_S, fx.E_S());
    EXPECT_EQ(std::memcmp(agg.aggregate_C_W.bytes, fx.proof.C_W.bytes, 32), 0);
    EXPECT_EQ(std::memcmp(agg.aggregate_C_S.bytes, fx.proof.C_S.bytes, 32), 0);

    EXPECT_TRUE(m_db->has_vote_nullifier(fx.proposal_id, fx.nullifier));

    const crypto::hash tx_hash =
        cryptonote::get_transaction_hash(make_v2_tx(fx.proof));
    dao_vote_record_v2 rec;
    EXPECT_TRUE(m_db->get_dao_vote_record_v2(tx_hash, rec));
    EXPECT_EQ(rec.proposal_id, fx.proposal_id);
    ASSERT_EQ(rec.nullifiers.size(), 1u);
    EXPECT_EQ(rec.nullifiers[0], fx.nullifier);
}


TEST_F(ConsensusFixture, rollback_restores_aggregate_byte_for_byte)
{
    ValidVote fx;
    ASSERT_TRUE(build_valid_vote(fx,
        hash_from_byte(0x33), hash_from_byte(0xAA),
        /*tally_epoch=*/1, /*vote_height=*/51000,
        /*submission=*/50000, /*end=*/60000));
    install(fx);

    // Pre-apply state: no aggregate, no nullifier, no vote record.
    const crypto::hash tx_hash =
        cryptonote::get_transaction_hash(make_v2_tx(fx.proof));
    {
        dao_proposal_aggregate agg;
        EXPECT_FALSE(m_db->get_dao_proposal_aggregate(fx.proposal_id, agg));
        EXPECT_FALSE(m_db->has_vote_nullifier(fx.proposal_id, fx.nullifier));
        dao_vote_record_v2 rec;
        EXPECT_FALSE(m_db->get_dao_vote_record_v2(tx_hash, rec));
    }

    // Apply.
    ASSERT_TRUE(apply(fx));
    {
        dao_proposal_aggregate agg;
        ASSERT_TRUE(m_db->get_dao_proposal_aggregate(fx.proposal_id, agg));
        EXPECT_EQ(agg.aggregate_E_W, fx.E_W());
        EXPECT_TRUE(m_db->has_vote_nullifier(fx.proposal_id, fx.nullifier));
    }

    // Rollback via VoteManager::rollback_block.
    GovernanceDB gov(*m_db, MAINNET);
    governance_params params = governance_params::default_params();
    VoteManager vm(gov, params);

    block blk = make_block({ make_v2_tx(fx.proof) });
    std::vector<transaction> txs = { make_v2_tx(fx.proof) };
    {
        db_wtxn_guard g(m_db);
        ASSERT_TRUE(vm.rollback_block(blk, txs, fx.vote_height));
    }

    // Post-rollback state matches pre-apply byte-for-byte: the
    // aggregate row is removed, the nullifier is gone, and the vote
    // record is removed.
    {
        dao_proposal_aggregate agg;
        EXPECT_FALSE(m_db->get_dao_proposal_aggregate(fx.proposal_id, agg));
        EXPECT_FALSE(m_db->has_vote_nullifier(fx.proposal_id, fx.nullifier));
        dao_vote_record_v2 rec;
        EXPECT_FALSE(m_db->get_dao_vote_record_v2(tx_hash, rec));
    }
}

TEST_F(ConsensusFixture, duplicate_nullifier_in_two_txs_of_one_block_is_invalid)
{
    ValidVote fx;
    ASSERT_TRUE(build_valid_vote(fx,
        hash_from_byte(0x33), hash_from_byte(0xAA),
        /*tally_epoch=*/1, /*vote_height=*/51000,
        /*submission=*/50000, /*end=*/60000));
    install(fx);

    // Two transactions with the same proof => same nullifier.
    transaction tx_a = make_v2_tx(fx.proof);
    transaction tx_b = make_v2_tx(fx.proof);

    GovernanceDB gov(*m_db, MAINNET);
    governance_params params = governance_params::default_params();
    VoteManager vm(gov, params);

    block blk = make_block({ tx_a, tx_b });
    db_wtxn_guard g(m_db);
    EXPECT_FALSE(vm.process_block(blk, fx.vote_height));
}
