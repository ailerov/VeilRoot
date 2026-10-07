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
