// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

// V2 vote dispatcher tests: classification, activation guard, and
// malformed-payload rejection. These exercise VoteManager's dispatch
// logic without building a full cryptographic V2 vote.

#include "gtest/gtest.h"

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/blockchain.h"
#include "governance/dao_dkg.h"
#include "governance/governance_db.h"
#include "governance/governance_params.h"
#include "governance/governance_payload.h"
#include "governance/vote_manager.h"
#include "governance/vote_proof.h"
#include "governance/vote_proof_v2.h"
#include "serialization/string.h"

#include <boost/filesystem.hpp>
#include <cstring>
#include <memory>
#include <string>

using namespace cryptonote;

namespace {

crypto::hash h(uint8_t seed)
{
    crypto::hash x;
    std::memset(x.data, 0, sizeof(x.data));
    x.data[0] = seed;
    x.data[31] = seed;
    return x;
}

transaction make_v1_vote_tx(const crypto::hash& pid,
                            const crypto::hash& nullifier)
{
    vote_proof vp{};
    vp.version = 1;
    vp.proposal_id = pid;
    vp.direction_yes = true;
    vp.snapshot_height = 1;
    vp.participation_balance = 100;
    vp.voting_weight = 100;
    vp.voting_nullifiers.push_back(nullifier);
    vp.output_heights.push_back(1); // must match voting_nullifiers size
    vp.balance_commitment = rct::identity();
    vp.weight_commitment = rct::identity();

    governance_payload gp;
    gp.type = governance_object::vote;
    std::string blob = t_serializable_object_to_blob(vp);
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

transaction make_v2_vote_tx(const crypto::hash& pid,
                            uint64_t epoch,
                            uint64_t height,
                            size_t n_inputs = 0)
{
    vote_proof_v2 vp{};
    vp.version = vote_proof_v2::VERSION;
    vp.proposal_id = pid;
    vp.vote_height = height;
    vp.tally_key_epoch = epoch;
    vp.C_W = rct::identity();
    vp.C_S = rct::identity();
    for (size_t i = 0; i < n_inputs; ++i) {
        vote_input_v2 in;
        in.key_offsets = {0, 1, 1, 1};
        in.weight_signature.s.resize(4);
        in.weight_signature.I = rct::identity();
        in.weight_signature.D = rct::identity();
        in.balance_signature.s.resize(4);
        in.balance_signature.I = rct::identity();
        in.balance_signature.D = rct::identity();
        vp.inputs.push_back(in);
        crypto::hash nf{};
        nf.data[0] = static_cast<uint8_t>(0x10 + i);
        vp.nullifiers.push_back(nf);
    }

    governance_payload gp;
    gp.type = governance_object::vote_v2;
    std::string blob = t_serializable_object_to_blob(vp);
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

transaction make_malformed_governance_tx()
{
    governance_payload gp;
    gp.type = static_cast<governance_object>(0x7F);
    gp.data = {0x01, 0x02};

    tx_extra_governance_payload tgp{gp};
    tx_extra_field ef = tgp;
    std::string extra = t_serializable_object_to_blob(ef);

    transaction tx;
    tx.version = 2;
    tx.extra.assign(extra.begin(), extra.end());
    tx.rct_signatures.type = rct::RCTTypeNull;
    return tx;
}

transaction make_two_vote_objects_tx(const crypto::hash& pid,
                                     const crypto::hash& nullifier)
{
    vote_proof v1{};
    v1.version = 1;
    v1.proposal_id = pid;
    v1.voting_nullifiers.push_back(nullifier);

    governance_payload gp1;
    gp1.type = governance_object::vote;
    std::string b1 = t_serializable_object_to_blob(v1);
    gp1.data.assign(b1.begin(), b1.end());

    tx_extra_governance_payload tgp1{gp1};
    tx_extra_field ef1 = tgp1;
    std::string e1 = t_serializable_object_to_blob(ef1);

    governance_payload gp2;
    gp2.type = governance_object::vote_v2;
    vote_proof_v2 v2{};
    v2.version = vote_proof_v2::VERSION;
    v2.proposal_id = pid;
    std::string b2 = t_serializable_object_to_blob(v2);
    gp2.data.assign(b2.begin(), b2.end());
    tx_extra_governance_payload tgp2{gp2};
    tx_extra_field ef2 = tgp2;
    std::string e2 = t_serializable_object_to_blob(ef2);

    transaction tx;
    tx.version = 2;
    tx.extra.assign(e1.begin(), e1.end());
    tx.extra.insert(tx.extra.end(), e2.begin(), e2.end());
    tx.rct_signatures.type = rct::RCTTypeNull;
    return tx;
}

class DispatchFixture : public ::testing::Test
{
protected:
    std::string m_dir;
    BlockchainDB* m_db = nullptr;

    void SetUp() override
    {
        boost::filesystem::path tmp =
            boost::filesystem::temp_directory_path() /
            boost::filesystem::unique_path("vr_v2_dispatch_%%%%-%%%%-%%%%");
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

    void store_proposal(GovernanceDB& gov, const crypto::hash& pid,
                        uint64_t sub, uint64_t end,
                        uint64_t tally_key_epoch = 0)
    {
        proposal_record rec;
        std::memset(&rec, 0, sizeof(rec));
        rec.proposal_id = pid;
        rec.voting_period_days = 7;
        rec.submission_height = sub;
        rec.voting_end_height = end;
        rec.submission_tx_hash = pid;
        rec.status = 0;
        rec.tally_key_epoch = tally_key_epoch;
        db_wtxn_guard g(m_db);
        gov.store_proposal(rec);
    }

    void store_tally_key(uint32_t epoch, uint64_t activation_height)
    {
        dao::dao_tally_key_record rec;
        rec.version = 1;
        rec.epoch = epoch;
        rec.committee_size = 16;
        rec.threshold = 8;
        rec.t = 7;
        rec.committee_id_hash.assign(32, 0);
        rec.delta.assign(32, 0);
        rec.N.assign(256, 0);
        rec.G.assign(256, 0);
        rec.theta.assign(256, 0);
        rec.V.assign(512, 0);
        rec.V_K_i.assign(16, std::vector<uint8_t>(512, 0));
        rec.vss_P.assign(64, 0);
        rec.vss_P_prime.assign(64, 0);
        rec.vss_g.assign(1, 4);
        rec.vss_h.assign(64, 0);
        rec.activation_height = activation_height;
        rec.dkg_transcript_hash.assign(32, 0);
        rec.key_id.assign(32, 0);
        db_wtxn_guard g(m_db);
        m_db->add_dao_tally_key(epoch, rec);
        m_db->set_current_dao_tally_key_epoch(epoch);
    }
};

TEST_F(DispatchFixture, NoGovernanceObjectIsMissingTag)
{
    GovernanceDB gov(*m_db, MAINNET);
    governance_params params = governance_params::default_params();
    VoteManager vm(gov, params);

    transaction tx;
    tx.version = 2;
    tx.rct_signatures.type = rct::RCTTypeNull;

    EXPECT_EQ(vm.process_vote(tx, 10, false), vote_result::missing_vote_tag);
}

TEST_F(DispatchFixture, MalformedGovernanceObjectRejected)
{
    GovernanceDB gov(*m_db, MAINNET);
    governance_params params = governance_params::default_params();
    VoteManager vm(gov, params);

    transaction tx = make_malformed_governance_tx();
    EXPECT_EQ(vm.process_vote(tx, 10, false), vote_result::invalid_format);
}

TEST_F(DispatchFixture, TwoVoteObjectsRejected)
{
    GovernanceDB gov(*m_db, MAINNET);
    governance_params params = governance_params::default_params();
    VoteManager vm(gov, params);

    crypto::hash pid = h(0xAA);
    crypto::hash nf  = h(0xBB);
    transaction tx = make_two_vote_objects_tx(pid, nf);
    EXPECT_EQ(vm.process_vote(tx, 10, false), vote_result::invalid_format);
}

TEST_F(DispatchFixture, V1AcceptedBeforeActivation)
{
    GovernanceDB gov(*m_db, MAINNET);
    governance_params params = governance_params::default_params();
    VoteManager vm(gov, params);

    crypto::hash pid = h(0xAA);
    crypto::hash nf  = h(0xBB);
    store_proposal(gov, pid, 1, 2000, /*epoch=*/0);

    transaction tx = make_v1_vote_tx(pid, nf);
    vote_result r;
    { db_wtxn_guard g(m_db); r = vm.process_vote(tx, 1000, false); }
    EXPECT_EQ(r, vote_result::success);
    EXPECT_TRUE(gov.has_nullifier(pid, nf));
}

TEST_F(DispatchFixture, V1RejectedAfterActivation)
{
    GovernanceDB gov(*m_db, MAINNET);
    governance_params params = governance_params::default_params();
    VoteManager vm(gov, params);

    crypto::hash pid = h(0xAA);
    crypto::hash nf  = h(0xBB);
    store_proposal(gov, pid, 1, 2000, /*epoch=*/1);
    store_tally_key(1, /*activation=*/5);

    transaction tx = make_v1_vote_tx(pid, nf);
    vote_result r;
    { db_wtxn_guard g(m_db); r = vm.process_vote(tx, 1000, false); }
    EXPECT_EQ(r, vote_result::invalid_format);
    EXPECT_FALSE(gov.has_nullifier(pid, nf));
}

TEST_F(DispatchFixture, V2RejectedBeforeActivation)
{
    GovernanceDB gov(*m_db, MAINNET);
    governance_params params = governance_params::default_params();
    VoteManager vm(gov, params);

    crypto::hash pid = h(0xAA);
    store_proposal(gov, pid, 1, 100, /*epoch=*/1);
    store_tally_key(1, /*activation=*/50);

    transaction tx = make_v2_vote_tx(pid, /*epoch=*/1, /*height=*/10);
    EXPECT_EQ(vm.process_vote(tx, 10, false), vote_result::voting_period_closed);
}

TEST_F(DispatchFixture, V2AfterActivationReachesVerifier)
{
    GovernanceDB gov(*m_db, MAINNET);
    governance_params params = governance_params::default_params();
    VoteManager vm(gov, params);

    crypto::hash pid = h(0xAA);
    store_proposal(gov, pid, 1, 100, /*epoch=*/1);
    store_tally_key(1, /*activation=*/1);

    transaction tx = make_v2_vote_tx(pid, /*epoch=*/1, /*height=*/10,
                                    /*n_inputs=*/0);
    vote_result r;
    { db_wtxn_guard g(m_db); r = vm.process_vote(tx, 10, false); }
    // Empty inputs -> verifier fails at step 7.
    EXPECT_EQ(r, vote_result::invalid_signature);
}

} // namespace
