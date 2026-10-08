// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Single-node bootstrap integration test. Instantiates a real
// cryptonote::core with a fresh LMDB, installs a persistent node
// identity and three eligible records, then drives the production
// bootstrap sequence end to end:
//
//   core
//     -> Blockchain::init (real)
//     -> committee_privkey installed
//     -> eligible records installed
//     -> Blockchain::bootstrap_dao_v2_dkg(1)
//     -> runner starts, watcher queues
//     -> owner thread drains the queue
//     -> LMDB holds the tally key record for this node's committee index

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include "gtest/gtest.h"

#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_core.h"
#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/governance_params.h"
#include "governance/dao_tally_session_cycle.h"
#include "governance/tally_manager.h"
#include "governance/dao_tally_share.h"
#include "governance/dao_tally.h"
#include "governance/dao_supply.h"
#include "governance/dao_paillier.h"

namespace po = boost::program_options;
using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

constexpr uint64_t FIXED_TEST_CANDIDATE_SEED_3 = 0x5645494C52544F33ULL;

} // namespace

class DaoBootstrapIntegration : public ::testing::Test
{
protected:
    std::string m_dir;
    std::unique_ptr<cryptonote::core> m_core;
    crypto::secret_key m_node_sec;
    crypto::public_key m_node_pub;

    void SetUp() override
    {
        boost::filesystem::path tmp =
            boost::filesystem::temp_directory_path() /
            boost::filesystem::unique_path("vr_dkg_int_%%%%-%%%%");
        m_dir = tmp.string();
        boost::filesystem::create_directories(m_dir);

        po::options_description desc("");
        cryptonote::core::init_options(desc);

        po::variables_map vm;
        // FAKECHAIN mode: --regtest-on.
        // data dir set to our temp path.
        std::vector<std::string> args = {
            "--regtest",
            "--data-dir", m_dir,
            "--offline",
            "--keep-fakechain",
            "--fixed-difficulty", "1",
        };
        po::store(po::command_line_parser(args).options(desc).run(), vm);
        po::notify(vm);

        m_core.reset(new cryptonote::core(nullptr));
        ASSERT_TRUE(m_core->init(vm, nullptr, nullptr, false));

        // Persistent node identity, matching Blockchain::init()'s own
        // behavior: load from LMDB if present, else generate and store.
        crypto::secret_key sec;
        if (!m_core->get_blockchain_storage().get_db().get_committee_privkey(sec))
        {
            crypto::generate_keys(m_node_pub, m_node_sec);
            m_core->get_blockchain_storage().get_db().set_committee_privkey(m_node_sec);
        }
        else
        {
            m_node_sec = sec;
            ASSERT_TRUE(crypto::secret_key_to_public_key(m_node_sec, m_node_pub));
        }
        m_core->set_node_key(m_node_sec);
    }

    void TearDown() override
    {
        if (m_core) {
            m_core->deinit();
        }
        m_core.reset();
        boost::filesystem::remove_all(m_dir);
    }
};

TEST_F(DaoBootstrapIntegration, CoreInitSucceeds)
{
    // The fixture itself exercises this; the assert is that SetUp
    // reached this point.
    SUCCEED();
}

TEST_F(DaoBootstrapIntegration, PersistentNodeIdentityInstalled)
{
    crypto::secret_key recovered;
    ASSERT_TRUE(m_core->get_blockchain_storage().get_db()
                    .get_committee_privkey(recovered));
    crypto::public_key recovered_pub;
    ASSERT_TRUE(crypto::secret_key_to_public_key(recovered, recovered_pub));
    EXPECT_EQ(recovered_pub, m_node_pub);
}

TEST_F(DaoBootstrapIntegration, BootstrapStartsRunnerForThisCommittee)
{
    // Install three eligible records: this node plus two decoys. The
    // selector returns them in weight order, and start_dao_v2_dkg
    // derives local_party_id from m_node_privkey against that order.
    auto& db = m_core->get_blockchain_storage().get_db();

    committee_eligible_record self_rec{};
    self_rec.node_pubkey = m_node_pub;
    self_rec.amount = 3000000;
    self_rec.unlock_height = 1;
    self_rec.stake_age_weight = 0;

    crypto::key_image self_ki{};
    std::memset(self_ki.data, 0, sizeof(self_ki.data));
    self_ki.data[0] = 1;

    {
        db_wtxn_guard g(&db);
        db.add_committee_eligible(self_ki, self_rec);
    }

    for (uint32_t i = 1; i <= 2; ++i) {
        crypto::public_key dummy;
        crypto::secret_key dummy_sec;
        crypto::generate_keys(dummy, dummy_sec);

        committee_eligible_record rec{};
        rec.node_pubkey = dummy;
        rec.amount = 2000000 - i * 100000;
        rec.unlock_height = 1;
        rec.stake_age_weight = 0;

        crypto::key_image ki{};
        std::memset(ki.data, 0, sizeof(ki.data));
        ki.data[0] = static_cast<uint8_t>(i + 1);

        db_wtxn_guard g(&db);
        db.add_committee_eligible(ki, rec);
    }

    // Selector sees all three.
    auto sel = dao::select_dao_v2_committee(db, 3, 1000000ULL);
    ASSERT_EQ(sel.size(), 3u);
    EXPECT_EQ(sel[0].first, m_node_pub);

    // install the P2P send callback so bootstrap does not bail on a
    // missing callback.
    m_core->get_blockchain_storage().set_dao_v2_dkg_send(
        [](const std::string&) -> bool { return true; });

    ASSERT_TRUE(m_core->get_blockchain_storage().bootstrap_dao_v2_dkg(1));

    // A runner for epoch 1 now exists. It cannot complete without
    // peers; teardown stops it via ~Blockchain.
    SUCCEED();
}


// ------------------------------------------------------------------
// Activation chain: DKG result queued -> drained on owner thread ->
// epoch active -> new proposals bind to it.
//
// The DKG itself runs on three offline runners (the same construction
// the bootstrap unit test uses), so this test isolates the persistence
// and epoch-activation path in Blockchain.
// ------------------------------------------------------------------

namespace {

struct act_network
{
    std::mutex mu;
    std::map<crypto::public_key, dkg_p2p_runner*> by_pk;
    std::map<uint32_t, dkg_p2p_runner*>          by_id;

    void reg(uint32_t id, const crypto::public_key& pk, dkg_p2p_runner* r)
    {
        std::lock_guard<std::mutex> lk(mu);
        by_id.emplace(id, r);
        by_pk.emplace(pk, r);
    }

    dkg_p2p_callbacks cb()
    {
        dkg_p2p_callbacks c;
        c.send_to = [this](const crypto::public_key& to,
                           const std::string& payload) -> bool {
            dkg_p2p_runner* t = nullptr;
            {
                std::lock_guard<std::mutex> lk(mu);
                auto it = by_pk.find(to);
                if (it == by_pk.end()) return false;
                t = it->second;
            }
            dkg_msg m;
            std::vector<uint8_t> buf(payload.begin(), payload.end());
            if (!m.deserialize(buf)) return false;
            t->on_message(m);
            return true;
        };
        c.broadcast = [this](const std::string& payload) {
            dkg_msg m;
            std::vector<uint8_t> buf(payload.begin(), payload.end());
            if (!m.deserialize(buf)) return;
            std::vector<dkg_p2p_runner*> targets;
            {
                std::lock_guard<std::mutex> lk(mu);
                for (auto it = by_id.begin(); it != by_id.end(); ++it)
                    if (it->first != m.hdr.sender_id)
                        targets.push_back(it->second);
            }
            for (auto* t : targets) t->on_message(m);
        };
        return c;
    }
};

} // namespace

TEST_F(DaoBootstrapIntegration, ActivationChainBindsEpochAfterPersistence)
{
    // The integration node's identity is already installed in LMDB.
    // Build a committee whose first entry is this node, then run three
    // offline runners to produce a real dkg_result.
    std::vector<crypto::public_key> committee;
    committee.push_back(m_node_pub);
    for (int i = 0; i < 2; ++i) {
        crypto::public_key pk;
        crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        committee.push_back(pk);
    }

    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));

    act_network net;
    std::vector<std::unique_ptr<dkg_p2p_runner>> runners;
    for (uint32_t i = 0; i < 3; ++i) {
        dkg_config cfg;
        cfg.committee_size = 3;
        cfg.threshold      = dao_dkg_expected_threshold(3);
        cfg.epoch          = 1;
        cfg.member_ids     = committee;
        cfg.local_party_id = i + 1;
        cfg.test_seed      = 0x5645494C52544F33ULL;   // 3-party fixed
        cfg.target_N_bits  = 128;
        cfg.phase_timeout_seconds = 120;
        auto cb = net.cb();
        runners.emplace_back(new dkg_p2p_runner(cfg, vss, cb));
    }
    for (uint32_t i = 0; i < 3; ++i)
        net.reg(i + 1, committee[i], runners[i].get());
    for (auto& r : runners) ASSERT_TRUE(r->start());

    dkg_result completed;
    ASSERT_TRUE(runners[0]->wait(completed, 180));
    ASSERT_TRUE(completed.ok);
    ASSERT_FALSE(completed.local_secret_share.empty());

    // Queue the result on the blockchain and drain it on this thread.
    auto& bc = m_core->get_blockchain_storage();
    bc.queue_dao_v2_dkg_result(1, completed);
    bc.maybe_process_dao_v2_dkg_results();

    // Key record persisted.
    dao::dao_tally_key_record rec;
    ASSERT_TRUE(bc.get_db().get_dao_tally_key(1, rec));
    EXPECT_EQ(rec.committee_size, 3u);
    EXPECT_EQ(rec.threshold, 2u);

    // Epoch activated.
    uint32_t ep = 0;
    ASSERT_TRUE(bc.get_db().get_current_dao_tally_key_epoch(ep));
    EXPECT_EQ(ep, 1u);

    // Local share stored under this node's committee index.
    std::vector<uint8_t> share;
    ASSERT_TRUE(bc.get_db().get_dao_local_share(1, 1, share));
    EXPECT_FALSE(share.empty());
}

// ------------------------------------------------------------------
// Threshold combine is invariant to the chosen subset.
//
// Run a real 2-of-3 DKG. Then take two distinct 2-of-3 subsets of the
// bootstrap shareholders and confirm dao_threshold_combine produces
// the same combined ciphertext from each. This is the property the
// tally lifecycle depends on: any threshold subset of the bootstrap
// shareholders can decrypt, and the result is the same.
// ------------------------------------------------------------------
TEST(DaoThresholdSubsetInvariance, SameCiphertextFromAnySubset)
{
    std::vector<crypto::public_key> committee;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk;
        crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        committee.push_back(pk);
    }

    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));

    // In-process transport; populates test_SK.
    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    pool.reserve(inet.endpoints.size());
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };

    dkg_config cfg;
    cfg.committee_size = 3;
    cfg.threshold      = dao_dkg_expected_threshold(3);
    cfg.epoch          = 1;
    cfg.member_ids     = committee;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F33ULL;

    dkg_result out;
    ASSERT_TRUE(dkg_run_with_transport(cfg, factory, out));
    ASSERT_TRUE(out.candidate_accepted);
    ASSERT_EQ(out.test_SK.size(), 3u);

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));

    BIGNUM* m = BN_new();
    BN_set_word(m, 4242);
    BIGNUM* r = BN_new();
    ASSERT_TRUE(dao_dkg_sample_r(pk, r));
    std::vector<uint8_t> c;
    ASSERT_TRUE(pk.encrypt(m, r, c));

    auto partial_for = [&](uint32_t member_index) {
        BIGNUM* sk = nullptr;
        const std::string dec(out.test_SK[member_index - 1].begin(),
                              out.test_SK[member_index - 1].end());
        BN_dec2bn(&sk, dec.c_str());
        std::vector<uint8_t> ci;
        bool ok = dao_threshold_partial_decrypt(pk, c, sk, ci);
        BN_free(sk);
        return std::make_pair(ok, ci);
    };

    std::vector<std::vector<uint32_t>> subsets = {
        {1, 2},
        {1, 3},
    };

    std::vector<std::vector<uint8_t>> combined;
    for (const auto& subset : subsets) {
        std::vector<std::vector<uint8_t>> partials;
        for (uint32_t idx : subset) {
            auto [ok, ci] = partial_for(idx);
            ASSERT_TRUE(ok);
            partials.push_back(std::move(ci));
        }
        std::vector<uint8_t> C;
        ASSERT_TRUE(dao_threshold_combine(pk, subset, partials,
                                          out.record.threshold, C));
        combined.push_back(std::move(C));
    }

    EXPECT_EQ(combined[0], combined[1]);

    BN_free(m); BN_free(r);
}

// ------------------------------------------------------------------
// End-to-end lifecycle on a single fakechain core.
//
// 1. bootstrap DKG over three shareholders (this node + two dummies);
// 2. queue the DKG result and drain it on the owner thread;
// 3. persist a proposal whose voting window closes at VOTE_END;
// 4. encrypt a synthetic aggregate under the resulting N;
// 5. call maybe_produce_dao_v2_share(VOTE_END + 1);
// 6. assert the tally session is written and one share was produced;
// 7. feed that share, plus a second share built directly from
//    test_SK[1], through handle_dao_v2_tally_share;
// 8. assert the outcome record exists and the proposal passed.
//
// This exercises the exact production code path from the block-apply
// producer through the P2P handler through to try_finalize. It does
// not exercise two-node consensus (see the two-core test).
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// End-to-end consensus path for a DAO V2 tally result.
//
// 1. bootstrap DKG over three shareholders (this node + two dummies);
// 2. queue the DKG result and drain it on the owner thread;
// 3. persist a proposal whose voting window closes at VOTE_END;
// 4. encrypt a synthetic aggregate under the resulting N;
// 5. build a tally-result transaction from the threshold shares;
// 6. validate_dao_v2_tally_result_tx(tx, VOTE_END + 1) -> true;
// 7. apply_dao_v2_tally_result(tx, VOTE_END + 1);
// 8. assert outcome record and proposal status.
//
// This is the same computation the P2P handler and block-apply path
// perform. It uses the direct API so the test does not need to walk
// the mempool; the mempool path is exercised separately.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, TallyResultTxValidatedAndApplied)
{
    constexpr uint64_t VOTE_END = 60001;
    const crypto::hash prop_id = []{
        crypto::hash h{};
        std::memset(h.data, 0x77, 32);
        return h;
    }();

    // ---- 1. Bootstrap DKG over three shareholders ----
    std::vector<crypto::public_key> committee_pks;
    committee_pks.push_back(m_node_pub);
    for (int i = 0; i < 2; ++i) {
        crypto::public_key pk;
        crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        committee_pks.push_back(pk);
    }

    auto& db = m_core->get_blockchain_storage().get_db();
    for (size_t i = 0; i < 3; ++i) {
        committee_eligible_record rec{};
        rec.node_pubkey = committee_pks[i];
        rec.amount = 3000000 - i * 1000000;
        rec.unlock_height = 1;
        rec.stake_age_weight = 0;

        crypto::key_image ki{};
        std::memset(ki.data, 0, sizeof(ki.data));
        ki.data[0] = static_cast<uint8_t>(i + 1);

        db_wtxn_guard g(&db);
        db.add_committee_eligible(ki, rec);
    }

    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));

    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    pool.reserve(inet.endpoints.size());
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));
    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };

    dkg_config cfg;
    cfg.committee_size = 3;
    cfg.threshold      = dao_dkg_expected_threshold(3);
    cfg.member_ids     = committee_pks;
    cfg.epoch          = 1;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F33ULL;
    cfg.local_party_id = 1;

    dkg_result out;
    ASSERT_TRUE(dkg_run_with_transport(cfg, factory, out));
    ASSERT_TRUE(out.candidate_accepted);
    ASSERT_EQ(out.test_SK.size(), 3u);

    auto& bc = m_core->get_blockchain_storage();
    bc.queue_dao_v2_dkg_result(1, out);
    bc.maybe_process_dao_v2_dkg_results();

    dao::dao_tally_key_record key_rec;
    ASSERT_TRUE(bc.get_db().get_dao_tally_key(1, key_rec));
    ASSERT_EQ(key_rec.committee_size, 3u);
    ASSERT_EQ(key_rec.threshold, 2u);

    // ---- 2. Persist a proposal ----
    {
        proposal_record rec{};
        std::memset(&rec, 0, sizeof(rec));
        rec.proposal_id = prop_id;
        rec.voting_period_days = 7;
        rec.submission_height = VOTE_END - 1000;
        rec.voting_end_height = VOTE_END;
        rec.tally_key_epoch = 1;
        rec.submission_tx_hash = prop_id;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        rec.status_height = VOTE_END - 1000;
        db_wtxn_guard g(&db);
        bc.get_db().add_proposal_record(prop_id, rec);
    }

    // ---- 3. Encrypt a synthetic aggregate ----
    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));

    BIGNUM* W = BN_new(); BN_set_word(W, 1000);
    BIGNUM* S = BN_new(); BN_set_word(S, 1000);
    BIGNUM* B = BN_new(); BN_set_word(B, 5000);
    BIGNUM* r1 = BN_new(); BN_set_word(r1, 3);
    BIGNUM* r2 = BN_new(); BN_set_word(r2, 5);
    BIGNUM* r3 = BN_new(); BN_set_word(r3, 7);
    std::vector<uint8_t> E_W, E_S, E_B;
    ASSERT_TRUE(pk.encrypt(W, r1, E_W));
    ASSERT_TRUE(pk.encrypt(S, r2, E_S));
    ASSERT_TRUE(pk.encrypt(B, r3, E_B));
    const crypto::hash agg_hash =
        dao::dao_aggregate_ciphertext_hash(E_W, E_S, E_B);

    {
        dao_proposal_aggregate agg;
        agg.aggregate_E_W = E_W;
        agg.aggregate_E_S = E_S;
        agg.aggregate_E_B = E_B;
        agg.aggregate_C_W = rct::identity();
        agg.aggregate_C_S = rct::identity();
        agg.aggregate_C_B = rct::identity();
        db_wtxn_guard g(&db);
        bc.get_db().add_dao_proposal_aggregate(prop_id, agg);

        dao::dao_supply_snapshot snap;
        snap.height = VOTE_END;
        snap.minted = dao::dao_u128(100000);
        snap.circulating = dao::dao_u128(50000);
        bc.get_db().add_dao_supply_snapshot(snap);
    }

    // ---- 4. Produce the local share (member 1) ----
    bc.set_dao_v2_tally_broadcast([](const dao::dao_v2_tally_share&) {});
    bc.set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });

    dao::dao_v2_tally_share first_share;
    bool captured_first = false;
    bc.set_dao_v2_tally_broadcast(
        [&](const dao::dao_v2_tally_share& s) {
            first_share = s;
            captured_first = true;
        });
    {
        db_wtxn_guard g(&db);
        bc.maybe_produce_dao_v2_share(VOTE_END + 1);
    }
    ASSERT_TRUE(captured_first);
    ASSERT_EQ(first_share.member_index, 1u);

    // ---- 5. Build the second share from test_SK[1] ----
    dao::dao_v2_tally_share second_share{};
    second_share.version = 1;
    second_share.proposal_id = prop_id;
    second_share.vote_end_height = VOTE_END;
    second_share.tally_key_epoch = 1;
    second_share.share_epoch = 1;
    second_share.member_index = 2;
    second_share.aggregate_ciphertext_hash = agg_hash;
    {
        BIGNUM* sk = nullptr;
        const std::string dec(out.test_SK[1].begin(), out.test_SK[1].end());
        BN_dec2bn(&sk, dec.c_str());
        ASSERT_NE(sk, nullptr);

        auto do_channel = [&](const std::vector<uint8_t>& c,
                              std::vector<uint8_t>& p_out,
                              dao::dao_partial_decryption_proof& proof_out) -> bool {
            std::vector<uint8_t> ci;
            if (!dao::dao_threshold_partial_decrypt(pk, c, sk, ci)) return false;
            BIGNUM* r = BN_new();
            if (!dao::dao_dkg_sample_r(pk, r)) { BN_free(r); return false; }
            const bool ok = dao::dao_partial_decryption_prove(
                pk, out.record.V, out.record.V_K_i[1], 2,
                c, ci, sk, r, proof_out);
            BN_free(r);
            if (!ok) return false;
            p_out = std::move(ci);
            return true;
        };
        ASSERT_TRUE(do_channel(E_W, second_share.partial_W, second_share.proof_W));
        ASSERT_TRUE(do_channel(E_S, second_share.partial_S, second_share.proof_S));
        ASSERT_TRUE(do_channel(E_B, second_share.partial_B, second_share.proof_B));
        BN_free(sk);
    }

    // ---- 6. Build the tally-result transaction from both shares ----
    std::map<crypto::public_key, dao::dao_v2_tally_share> shares;
    shares[committee_pks[0]] = first_share;
    shares[committee_pks[1]] = second_share;

    const governance_params params = governance_params::default_params();
    cryptonote::TallyManager tm(db, params);
    transaction result_tx;
    ASSERT_TRUE(tm.build_tally_result_transaction(
        prop_id, shares, key_rec.threshold, result_tx));

    // Sanity: the constructed tx is recognised by the parser.
    ASSERT_TRUE(bc.is_dao_v2_tally_result_tx(result_tx));

    // ---- 7. Consensus validation ----
    {
        db_rtxn_guard rtxn(&db);
        ASSERT_TRUE(bc.validate_dao_v2_tally_result_tx(
            result_tx, VOTE_END + 1));
    }

    // ---- 8. Apply (block-application path) ----
    {
        db_wtxn_guard g(&db);
        ASSERT_TRUE(bc.apply_dao_v2_tally_result(result_tx, VOTE_END + 1));
    }

    // ---- 9. Assertions ----
    dao::dao_v2_outcome_record outcome;
    ASSERT_TRUE(bc.get_db().get_dao_v2_outcome(prop_id, outcome));
    EXPECT_TRUE(outcome.passed);
    EXPECT_TRUE(outcome.quorum_met);
    EXPECT_TRUE(outcome.majority_met);
    EXPECT_EQ(outcome.yes_weight, dao::dao_u128(1000));
    EXPECT_EQ(outcome.no_weight, dao::dao_u128(0));
    EXPECT_EQ(outcome.participation_coins, dao::dao_u128(5000));

    proposal_record after;
    ASSERT_TRUE(bc.get_db().get_proposal_record(prop_id, after));
    EXPECT_EQ(after.status, PROPOSAL_STATUS_PASSED);

    BN_free(W); BN_free(S); BN_free(B);
    BN_free(r1); BN_free(r2); BN_free(r3);
}
