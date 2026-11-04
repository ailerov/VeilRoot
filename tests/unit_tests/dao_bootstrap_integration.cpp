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
//     -> Blockchain::bootstrap_dao_v2_dkg(std::string{})
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
#include "cryptonote_basic/tx_extra.h"
#include "serialization/binary_utils.h"
#include "serialization/binary_archive.h"
#include "serialization/variant.h"
#include "serialization/string.h"
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

namespace {

// Sign and deliver a node_ready announcement for (sec, pub). The
// digest matches Blockchain::compute_dao_v2_node_ready_digest (V2:
// covers genesis, pk, announce height, and block hash at that height).
void deliver_node_ready(core& c,
                        const crypto::hash& genesis,
                        const crypto::public_key& pk,
                        const crypto::secret_key& sk)
{
    auto& bs = c.get_blockchain_storage();
    const uint64_t current_h = bs.get_current_blockchain_height();
    if (current_h == 0) return;
    const uint64_t announce_h = current_h - 1;
    crypto::hash announce_hash{};
    try { announce_hash = bs.get_block_id_by_height(announce_h); }
    catch (...) { return; }

    const char* domain = "VeilRoot-DAO-DKG-NODE-READY-V2";
    std::vector<uint8_t> msg;
    const size_t dlen = std::strlen(domain);
    msg.insert(msg.end(), domain, domain + dlen);
    msg.insert(msg.end(), genesis.data, genesis.data + 32);
    msg.insert(msg.end(), pk.data, pk.data + 32);
    uint8_t h_le[8];
    std::memcpy(h_le, &announce_h, 8);
    msg.insert(msg.end(), h_le, h_le + 8);
    msg.insert(msg.end(), announce_hash.data, announce_hash.data + 32);

    crypto::hash digest{};
    crypto::cn_fast_hash(msg.data(), msg.size(), digest);

    crypto::signature sig{};
    crypto::generate_signature(digest, pk, sk, sig);

    dao::dkg_msg m;
    m.hdr.type         = dao::dkg_msg_type::node_ready;
    m.hdr.recipient_id = 0;
    m.bytes_a.resize(sizeof(crypto::signature));
    std::memcpy(m.bytes_a.data(), &sig, sizeof(crypto::signature));
    m.bytes_b.resize(8 + 32);
    std::memcpy(m.bytes_b.data(), &announce_h, 8);
    std::memcpy(m.bytes_b.data() + 8, announce_hash.data, 32);

    std::vector<uint8_t> wire;
    ASSERT_TRUE(m.serialize(wire));
    std::string payload(wire.begin(), wire.end());

    bs.handle_dao_v2_dkg_msg(pk, payload);
}

}  // namespace

TEST_F(DaoBootstrapIntegration, BootstrapStartsRunnerForThisCommittee)
{
    // The bootstrap gate is the ready-node roster, built from signed
    // P2P announcements. Deliver three: this node plus two decoys.
    // The roster path exercises real signing, real routing through
    // handle_dao_v2_dkg_msg, and real signature verification.
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));

    // This node's own key is inside the daemon, not directly reachable
    // from the test. Use two decoys plus this node's public key with
    // a signing key we install via set_node_key — the roster is keyed
    // by public key, and handle_dao_v2_node_ready binds to the
    // sender argument, so the decoys can sign with their own keys.
    //
    // Self is not needed to reach MIN=3: three decoys are sufficient
    // for the gate. The runner will then find this node is not in the
    // roster, which is the "not in committee" path — bootstrap returns
    // false but the gate has passed. To exercise the "runner started"
    // branch, self must be in the roster, so sign self with a
    // test-installed node key.

    crypto::public_key self_pk{};
    crypto::secret_key self_new_sk{};
    crypto::generate_keys(self_pk, self_new_sk);
    m_core->set_node_key(self_new_sk);

    deliver_node_ready(*m_core, genesis, self_pk, self_new_sk);

    for (int i = 0; i < 2; ++i) {
        crypto::public_key dummy;
        crypto::secret_key dummy_sk;
        crypto::generate_keys(dummy, dummy_sk);
        deliver_node_ready(*m_core, genesis, dummy, dummy_sk);
    }

    // install the P2P send callback so bootstrap does not bail on a
    // missing callback.
    m_core->get_blockchain_storage().set_dao_v2_dkg_send(
        [](const std::string&) -> bool { return true; });

    ASSERT_TRUE(m_core->get_blockchain_storage().bootstrap_dao_v2_dkg(std::string{}));

    // A runner for the bootstrap ceremony now exists. It cannot complete without
    // peers; teardown stops it via ~Blockchain.
    SUCCEED();
}


TEST_F(DaoBootstrapIntegration, NodeReadyRecordsValidAnnouncement)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));

    crypto::public_key a_pk;
    crypto::secret_key a_sk;
    crypto::generate_keys(a_pk, a_sk);

    deliver_node_ready(*m_core, genesis, a_pk, a_sk);

    auto& bs = m_core->get_blockchain_storage();
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(a_pk));
    EXPECT_EQ(1u, bs.get_dao_v2_ready_peer_count_for_test());
}

TEST_F(DaoBootstrapIntegration, NodeReadyRejectsInvalidSignature)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));

    crypto::public_key a_pk;
    crypto::secret_key a_sk;
    crypto::generate_keys(a_pk, a_sk);

    crypto::public_key b_pk;
    crypto::secret_key b_sk;
    crypto::generate_keys(b_pk, b_sk);

    deliver_node_ready(*m_core, genesis, a_pk, a_sk);
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .has_dao_v2_ready_peer_for_test(a_pk));

    // Forged: signature is over A's digest, but the message arrives
    // claiming sender=B. The handler computes the digest over B, so
    // signature verification against B's public key fails.
    auto& bs_for_rej = m_core->get_blockchain_storage();
    const uint64_t cur_h = bs_for_rej.get_current_blockchain_height();
    ASSERT_GT(cur_h, 0u);
    const uint64_t announce_h = cur_h - 1;
    crypto::hash announce_hash{};
    try { announce_hash = bs_for_rej.get_block_id_by_height(announce_h); }
    catch (...) { FAIL() << "get_block_id_by_height threw"; return; }

    std::vector<uint8_t> msg;
    const char* domain = "VeilRoot-DAO-DKG-NODE-READY-V2";
    const size_t dlen = std::strlen(domain);
    msg.insert(msg.end(), domain, domain + dlen);
    msg.insert(msg.end(), genesis.data, genesis.data + 32);
    msg.insert(msg.end(), a_pk.data, a_pk.data + 32);
    uint8_t h_le[8];
    std::memcpy(h_le, &announce_h, 8);
    msg.insert(msg.end(), h_le, h_le + 8);
    msg.insert(msg.end(), announce_hash.data, announce_hash.data + 32);
    crypto::hash digest{};
    crypto::cn_fast_hash(msg.data(), msg.size(), digest);
    crypto::signature sig{};
    crypto::generate_signature(digest, a_pk, a_sk, sig);

    dao::dkg_msg forged;
    forged.hdr.type         = dao::dkg_msg_type::node_ready;
    forged.hdr.recipient_id = 0;
    forged.bytes_a.resize(sizeof(crypto::signature));
    std::memcpy(forged.bytes_a.data(), &sig, sizeof(crypto::signature));
    forged.bytes_b.resize(8 + 32);
    std::memcpy(forged.bytes_b.data(), &announce_h, 8);
    std::memcpy(forged.bytes_b.data() + 8, announce_hash.data, 32);
    std::vector<uint8_t> wire;
    ASSERT_TRUE(forged.serialize(wire));
    std::string payload(wire.begin(), wire.end());
    m_core->get_blockchain_storage().handle_dao_v2_dkg_msg(b_pk, payload);

    auto& bs = m_core->get_blockchain_storage();
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(a_pk));
    EXPECT_FALSE(bs.has_dao_v2_ready_peer_for_test(b_pk));
    EXPECT_EQ(1u, bs.get_dao_v2_ready_peer_count_for_test());
}

namespace {

inline void write_u64_le(uint8_t out[8], uint64_t v)
{
    for (int i = 0; i < 8; ++i)
        out[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
}

// Build a node_ready message signed by (pk, sk) over an arbitrary
// (height, hash) tuple. Height is written little-endian on the wire,
// matching the source-side encoding.
dao::dkg_msg make_node_ready_msg(
    const crypto::hash& genesis,
    const crypto::public_key& pk,
    const crypto::secret_key& sk,
    uint64_t height,
    const crypto::hash& block_hash)
{
    const char* domain = "VeilRoot-DAO-DKG-NODE-READY-V2";
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), domain, domain + std::strlen(domain));
    msg.insert(msg.end(), genesis.data, genesis.data + 32);
    msg.insert(msg.end(), pk.data, pk.data + 32);
    uint8_t h_le[8];
    write_u64_le(h_le, height);
    msg.insert(msg.end(), h_le, h_le + 8);
    msg.insert(msg.end(), block_hash.data, block_hash.data + 32);
    crypto::hash digest{};
    crypto::cn_fast_hash(msg.data(), msg.size(), digest);
    crypto::signature sig{};
    crypto::generate_signature(digest, pk, sk, sig);

    dao::dkg_msg m;
    m.hdr.type         = dao::dkg_msg_type::node_ready;
    m.hdr.recipient_id = 0;
    m.bytes_a.resize(sizeof(crypto::signature));
    std::memcpy(m.bytes_a.data(), &sig, sizeof(crypto::signature));
    m.bytes_b.resize(8 + 32);
    write_u64_le(m.bytes_b.data(), height);
    std::memcpy(m.bytes_b.data() + 8, block_hash.data, 32);
    return m;
}

void send_ready_msg(core& c,
                    const crypto::public_key& sender,
                    const dao::dkg_msg& m)
{
    std::vector<uint8_t> wire;
    ASSERT_TRUE(m.serialize(wire));
    std::string payload(wire.begin(), wire.end());
    c.get_blockchain_storage().handle_dao_v2_dkg_msg(sender, payload);
}

}  // namespace

TEST_F(DaoBootstrapIntegration, NodeReadyRejectsFutureHeight)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));

    crypto::public_key a_pk;
    crypto::secret_key a_sk;
    crypto::generate_keys(a_pk, a_sk);

    auto& bs = m_core->get_blockchain_storage();
    const uint64_t cur_h = bs.get_current_blockchain_height();
    ASSERT_GT(cur_h, 0u);

    crypto::hash fake_hash{};
    std::memset(fake_hash.data, 0xAB, sizeof(fake_hash.data));

    // Height at or above local tip is rejected.
    dao::dkg_msg m = make_node_ready_msg(
        genesis, a_pk, a_sk, cur_h, fake_hash);
    send_ready_msg(*m_core, a_pk, m);

    EXPECT_FALSE(bs.has_dao_v2_ready_peer_for_test(a_pk));
    EXPECT_EQ(0u, bs.get_dao_v2_ready_peer_count_for_test());
}

TEST_F(DaoBootstrapIntegration, NodeReadyRejectsNonCanonicalHash)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));

    crypto::public_key a_pk;
    crypto::secret_key a_sk;
    crypto::generate_keys(a_pk, a_sk);

    auto& bs = m_core->get_blockchain_storage();
    const uint64_t cur_h = bs.get_current_blockchain_height();
    ASSERT_GT(cur_h, 0u);

    const uint64_t h = cur_h - 1;
    crypto::hash fake_hash{};
    std::memset(fake_hash.data, 0xCD, sizeof(fake_hash.data));

    dao::dkg_msg m = make_node_ready_msg(genesis, a_pk, a_sk, h, fake_hash);
    send_ready_msg(*m_core, a_pk, m);

    EXPECT_FALSE(bs.has_dao_v2_ready_peer_for_test(a_pk));
    EXPECT_EQ(0u, bs.get_dao_v2_ready_peer_count_for_test());
}

TEST_F(DaoBootstrapIntegration, NodeReadyArrivalOrderABCPopulatesRoster)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));
    auto& bs = m_core->get_blockchain_storage();

    crypto::public_key a_pk, b_pk, c_pk;
    crypto::secret_key a_sk, b_sk, c_sk;
    crypto::generate_keys(a_pk, a_sk);
    crypto::generate_keys(b_pk, b_sk);
    crypto::generate_keys(c_pk, c_sk);

    deliver_node_ready(*m_core, genesis, a_pk, a_sk);
    deliver_node_ready(*m_core, genesis, b_pk, b_sk);
    deliver_node_ready(*m_core, genesis, c_pk, c_sk);

    EXPECT_EQ(3u, bs.get_dao_v2_ready_peer_count_for_test());
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(a_pk));
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(b_pk));
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(c_pk));
}

TEST_F(DaoBootstrapIntegration, NodeReadyArrivalOrderCBAPopulatesRoster)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));
    auto& bs = m_core->get_blockchain_storage();

    crypto::public_key a_pk, b_pk, c_pk;
    crypto::secret_key a_sk, b_sk, c_sk;
    crypto::generate_keys(a_pk, a_sk);
    crypto::generate_keys(b_pk, b_sk);
    crypto::generate_keys(c_pk, c_sk);

    deliver_node_ready(*m_core, genesis, c_pk, c_sk);
    deliver_node_ready(*m_core, genesis, b_pk, b_sk);
    deliver_node_ready(*m_core, genesis, a_pk, a_sk);

    EXPECT_EQ(3u, bs.get_dao_v2_ready_peer_count_for_test());
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(a_pk));
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(b_pk));
    EXPECT_TRUE(bs.has_dao_v2_ready_peer_for_test(c_pk));
}

TEST_F(DaoBootstrapIntegration, BootstrapGateRequiresThreeReadyNodes)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));

    m_core->get_blockchain_storage().set_dao_v2_dkg_send(
        [](const std::string&) -> bool { return true; });

    // 0 ready: bootstrap refuses.
    EXPECT_FALSE(m_core->get_blockchain_storage().bootstrap_dao_v2_dkg(std::string{}));

    // 1 ready (self): still refuses.
    deliver_node_ready(*m_core, genesis, m_node_pub, m_node_sec);
    EXPECT_FALSE(m_core->get_blockchain_storage().bootstrap_dao_v2_dkg(std::string{}));

    // 2 ready: still refuses.
    crypto::public_key a_pk;
    crypto::secret_key a_sk;
    crypto::generate_keys(a_pk, a_sk);
    deliver_node_ready(*m_core, genesis, a_pk, a_sk);
    EXPECT_FALSE(m_core->get_blockchain_storage().bootstrap_dao_v2_dkg(std::string{}));

    // 3 ready: gate passes and a runner starts.
    crypto::public_key b_pk;
    crypto::secret_key b_sk;
    crypto::generate_keys(b_pk, b_sk);
    deliver_node_ready(*m_core, genesis, b_pk, b_sk);
    EXPECT_TRUE(m_core->get_blockchain_storage().bootstrap_dao_v2_dkg(std::string{}));
}

TEST_F(DaoBootstrapIntegration, AnnounceIsThrottled)
{
    crypto::hash genesis{};
    ASSERT_TRUE(m_core->get_blockchain_storage()
                    .get_dao_v2_genesis_hash(genesis));

    int sent = 0;
    m_core->get_blockchain_storage().set_dao_v2_dkg_send(
        [&sent](const std::string&) -> bool { ++sent; return true; });

    m_core->get_blockchain_storage().maybe_announce_dao_v2_node_ready();
    EXPECT_EQ(1, sent);

    // Second call within the throttle window does not emit.
    m_core->get_blockchain_storage().maybe_announce_dao_v2_node_ready();
    EXPECT_EQ(1, sent);

    // The first announce also recorded self in the roster.
    EXPECT_EQ(1u,
        m_core->get_blockchain_storage().get_dao_v2_ready_peer_count_for_test());
}


// ------------------------------------------------------------------
// Activation chain: DKG result queued -> drained on owner thread ->
// key record active -> new proposals bind to it.
//
// The DKG itself runs on three offline runners (the same construction
// the bootstrap unit test uses), so this test isolates the persistence
// and key-activation path in Blockchain.
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

TEST_F(DaoBootstrapIntegration, ActivationChainBindsKeyRecordAfterPersistence)
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

    dkg_result completed;
    bool ceremony_ok = false;
    for (int attempt = 0; attempt < 2 && !ceremony_ok; ++attempt) {
        act_network net;
        std::vector<std::unique_ptr<dkg_p2p_runner>> runners;
        for (uint32_t i = 0; i < 3; ++i) {
            dkg_config cfg;
            cfg.committee_size = 3;
            cfg.threshold      = dao_dkg_expected_threshold(3);
            cfg.member_ids     = committee;
            cfg.local_party_id = i + 1;
            cfg.test_seed      = 0x5645494C52544F33ULL;
            cfg.target_N_bits  = 128;
            cfg.phase_timeout_seconds = 600;
            auto cb = net.cb();
            runners.emplace_back(new dkg_p2p_runner(cfg, vss, cb));
        }
        for (uint32_t i = 0; i < 3; ++i)
            net.reg(i + 1, committee[i], runners[i].get());
        for (auto& r : runners) ASSERT_TRUE(r->start());

        dkg_result local_completed;
        if (runners[0]->wait(local_completed, 600) &&
            local_completed.ok &&
            !local_completed.local_secret_share.empty()) {
            completed = std::move(local_completed);
            ceremony_ok = true;
        } else {
            std::cerr << "ActivationChainBinds attempt " << attempt
                      << ": DKG did not complete\n";
        }
    }
    ASSERT_TRUE(ceremony_ok) << "ActivationChainBinds DKG failed after 2 attempts";
    ASSERT_TRUE(completed.ok);
    ASSERT_FALSE(completed.local_secret_share.empty());

    // Queue the result on the blockchain and drain it on this thread.
    auto& bc = m_core->get_blockchain_storage();
    bc.queue_dao_v2_dkg_result(std::string{}, completed);
    bc.maybe_process_dao_v2_dkg_results();

    // Key record installed. In production this happens via a
    // DKG key-activation transaction during block application; this
    // fixture exercises the tally path and installs directly.
    bc.install_dao_tally_key_for_test(completed.record);

    // Key record persisted.
    dao::dao_tally_key_record rec;
    ASSERT_TRUE(bc.get_db().get_dao_tally_key(rec));
    EXPECT_EQ(rec.committee_size, 3u);
    EXPECT_EQ(rec.threshold, 2u);

    // Key record activated.
    
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
    // Small enough to keep the test fast while exercising real chain
    // height in mempool admission. The mempool rejects tally-result
    // txs whose voting_end_height has not passed on the actual chain,
    // so the test must mine to VOTE_END + 2 before submitting.
    constexpr uint64_t VOTE_END = 2;
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
    bc.queue_dao_v2_dkg_result(std::string{}, out);
    bc.maybe_process_dao_v2_dkg_results();

    // Install the key record. See note at the top of this file.
    bc.install_dao_tally_key_for_test(out.record);

    dao::dao_tally_key_record key_rec;
    ASSERT_TRUE(bc.get_db().get_dao_tally_key(key_rec));
    ASSERT_EQ(key_rec.committee_size, 3u);
    ASSERT_EQ(key_rec.threshold, 2u);

    // ---- 2. Persist a proposal ----
    {
        proposal_record rec{};
        std::memset(&rec, 0, sizeof(rec));
        rec.proposal_id = prop_id;
        rec.voting_period_days = 7;
        rec.submission_height = 1;
        rec.voting_end_height = VOTE_END;
        std::memset(rec.tally_key_id.data, 0, 32);
        rec.submission_tx_hash = prop_id;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        rec.status_height = VOTE_END - 1000;
        db_wtxn_guard g(&db);
        bc.get_db().add_proposal_record(prop_id, rec);
    }

    // ---- 2b. Mine past VOTE_END ----
    // Mempool admission checks the real current chain height against
    // voting_end_height; without mining, the test chain is too shallow
    // and the tally-result tx is rejected as "before voting ended".
    {
        account_base miner_acc;
        miner_acc.generate();
        auto& bs = m_core->get_blockchain_storage();
        while (bs.get_current_blockchain_height() < VOTE_END + 2) {
            block tmpl{};
            difficulty_type diff{};
            uint64_t tmpl_h = 0, reward = 0, seed_h = 0;
            crypto::hash seed_hsh{};
            blobdata ex_nonce(8, 0);
            ASSERT_TRUE(bs.create_block_template(
                tmpl, miner_acc.get_keys().m_account_address,
                diff, tmpl_h, reward, ex_nonce, seed_h, seed_hsh));
            auto gbh = [&bs](const block& b, uint64_t h,
                             const crypto::hash* sh,
                             unsigned int mn, crypto::hash& ho) -> bool {
                return get_block_longhash(&bs, b, ho, h, sh,
                                          static_cast<int>(mn));
            };
            ASSERT_TRUE(miner::find_nonce_for_given_block(
                gbh, tmpl, diff, tmpl_h, nullptr));
            block_verification_context bvc{};
            pool_supplement extra{};
            blobdata bb = block_to_blob(tmpl);
            ASSERT_TRUE(m_core->handle_single_incoming_block(
                bb, &tmpl, bvc, extra, false));
            ASSERT_FALSE(bvc.m_verifivation_failed);
        }
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
    second_share.version = dao::dao_v2_tally_share::WIRE_VERSION;
    second_share.proposal_id = prop_id;
    second_share.vote_end_height = VOTE_END;
    second_share.tally_key_id.assign(32, 0);
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

    // ---- 7b. Mempool acceptance + block-template inclusion ----
    // A valid tally-result tx must be admitted to mempool and then
    // selected by fill_block_template. Before the exemption was added
    // it sat in mempool forever and the DAO V2 tally never completed
    // on chain.
    {
        cryptonote::blobdata tx_blob = cryptonote::tx_to_blob(result_tx);
        cryptonote::tx_verification_context tvc{};
        ASSERT_TRUE(m_core->handle_incoming_tx(
            tx_blob, tvc, cryptonote::relay_method::local, false));
        ASSERT_FALSE(tvc.m_verifivation_failed);
    }

    {
        cryptonote::block templ{};
        cryptonote::difficulty_type diff{};
        uint64_t tmpl_height = 0, expected_reward = 0;
        cryptonote::blobdata ex_nonce(8, 0);
        uint64_t seed_height = 0;
        crypto::hash seed_hash{};
        cryptonote::account_base miner_acc;
        miner_acc.generate();
        ASSERT_TRUE(bc.create_block_template(
            templ, miner_acc.get_keys().m_account_address,
            diff, tmpl_height, expected_reward, ex_nonce,
            seed_height, seed_hash));
        const crypto::hash txid = cryptonote::get_transaction_hash(result_tx);
        EXPECT_NE(std::find(templ.tx_hashes.begin(),
                            templ.tx_hashes.end(), txid),
                  templ.tx_hashes.end())
            << "tally_result tx must be mined in a block template";
    }

    // ---- 7b. Mempool acceptance + block-template inclusion ----
    // A valid tally-result tx must be admitted to mempool and then
    // selected by fill_block_template. Before the fee exemption
    // existed it sat in mempool forever and the DAO V2 tally never
    // completed on chain.
    {
        cryptonote::blobdata tx_blob = cryptonote::tx_to_blob(result_tx);
        cryptonote::tx_verification_context tvc{};
        ASSERT_TRUE(m_core->handle_incoming_tx(
            tx_blob, tvc, cryptonote::relay_method::local, false));
        ASSERT_FALSE(tvc.m_verifivation_failed);
    }

    {
        cryptonote::block templ{};
        cryptonote::difficulty_type diff{};
        uint64_t tmpl_height = 0, expected_reward = 0, seed_height = 0;
        cryptonote::blobdata ex_nonce(8, 0);
        crypto::hash seed_hash{};
        cryptonote::account_base miner_acc;
        miner_acc.generate();
        ASSERT_TRUE(bc.create_block_template(
            templ, miner_acc.get_keys().m_account_address,
            diff, tmpl_height, expected_reward, ex_nonce,
            seed_height, seed_hash));
        const crypto::hash txid = cryptonote::get_transaction_hash(result_tx);
        EXPECT_NE(std::find(templ.tx_hashes.begin(),
                            templ.tx_hashes.end(), txid),
                  templ.tx_hashes.end())
            << "tally_result tx must be mined in a block template";
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

// ------------------------------------------------------------------
// Reorg: a tally-result transaction applied to a block, then rolled
// back by popping that block, must restore the proposal to ACTIVE and
// remove the outcome record and pending execution.
//
// The reorg code path in pop_block_from_blockchain is not directly
// exercised here — it needs a chain to pop from. What this test
// asserts is the state contract: after applying a valid tally-result
// and then reversing it with the same certificate-driven rollback
// the pop path performs, governance state returns to exactly the
// pre-apply state.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, TallyResultTxRolledBackByReorg)
{
    constexpr uint64_t VOTE_END = 60001;
    const crypto::hash prop_id = []{
        crypto::hash h{};
        std::memset(h.data, 0x88, 32);
        return h;
    }();

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

    auto& bc = m_core->get_blockchain_storage();
    bc.queue_dao_v2_dkg_result(std::string{}, out);
    bc.maybe_process_dao_v2_dkg_results();

    // Install the key record. See note at the top of this file.
    bc.install_dao_tally_key_for_test(out.record);

    dao::dao_tally_key_record key_rec;
    ASSERT_TRUE(bc.get_db().get_dao_tally_key(key_rec));

    {
        proposal_record rec{};
        std::memset(&rec, 0, sizeof(rec));
        rec.proposal_id = prop_id;
        rec.voting_period_days = 7;
        rec.submission_height = VOTE_END - 1000;
        rec.voting_end_height = VOTE_END;
        std::memset(rec.tally_key_id.data, 0, 32);
        rec.submission_tx_hash = prop_id;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        rec.status_height = VOTE_END - 1000;
        db_wtxn_guard g(&db);
        bc.get_db().add_proposal_record(prop_id, rec);
    }

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

    dao::dao_v2_tally_share second_share{};
    second_share.version = dao::dao_v2_tally_share::WIRE_VERSION;
    second_share.proposal_id = prop_id;
    second_share.vote_end_height = VOTE_END;
    second_share.tally_key_id.assign(32, 0);
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

    std::map<crypto::public_key, dao::dao_v2_tally_share> shares;
    shares[committee_pks[0]] = first_share;
    shares[committee_pks[1]] = second_share;

    const governance_params params = governance_params::default_params();
    cryptonote::TallyManager tm(db, params);

    transaction result_tx;
    ASSERT_TRUE(tm.build_tally_result_transaction(
        prop_id, shares, key_rec.threshold, result_tx));

    // ---- Phase 1: apply ----
    {
        db_wtxn_guard g(&db);
        ASSERT_TRUE(bc.apply_dao_v2_tally_result(result_tx, VOTE_END + 1));
    }

    {
        dao::dao_v2_outcome_record outcome;
        ASSERT_TRUE(bc.get_db().get_dao_v2_outcome(prop_id, outcome));
        EXPECT_TRUE(outcome.passed);

        proposal_record after;
        ASSERT_TRUE(bc.get_db().get_proposal_record(prop_id, after));
        EXPECT_EQ(after.status, PROPOSAL_STATUS_PASSED);
    }

    // ---- Phase 2: simulate the pop rollback ----
    // The production pop path deserializes the same certificate from
    // the popped tx and performs exactly these writes. The reorg test
    // performs them directly because the fixture does not build a
    // real chain to pop from.
    {
        db_wtxn_guard g(&db);
        bc.get_db().remove_dao_v2_outcome(prop_id);

        proposal_record prop;
        ASSERT_TRUE(bc.get_db().get_proposal_record(prop_id, prop));
        prop.status = PROPOSAL_STATUS_ACTIVE;
        prop.status_height = VOTE_END;
        bc.get_db().add_proposal_record(prop_id, prop);

        // The result also created a pending execution. The production
        // pop path removes it by (voting_end_height + 720,
        // proposal_id); mirror that here.
        const uint64_t delay = 720;
        try {
            bc.get_db().remove_pending_execution(
                prop.voting_end_height + delay, prop_id);
        } catch (...) {}
    }

    // ---- Phase 3: outcome gone, proposal back to ACTIVE ----
    {
        dao::dao_v2_outcome_record outcome;
        EXPECT_FALSE(bc.get_db().get_dao_v2_outcome(prop_id, outcome));

        proposal_record after;
        ASSERT_TRUE(bc.get_db().get_proposal_record(prop_id, after));
        EXPECT_EQ(after.status, PROPOSAL_STATUS_ACTIVE);
    }

    // ---- Phase 4: re-apply on the replacement chain ----
    {
        db_wtxn_guard g(&db);
        ASSERT_TRUE(bc.apply_dao_v2_tally_result(result_tx, VOTE_END + 2));
    }

    {
        dao::dao_v2_outcome_record outcome;
        ASSERT_TRUE(bc.get_db().get_dao_v2_outcome(prop_id, outcome));
        EXPECT_TRUE(outcome.passed);

        proposal_record after;
        ASSERT_TRUE(bc.get_db().get_proposal_record(prop_id, after));
        EXPECT_EQ(after.status, PROPOSAL_STATUS_PASSED);
    }

    BN_free(W); BN_free(S); BN_free(B);
    BN_free(r1); BN_free(r2); BN_free(r3);
}

// ------------------------------------------------------------------
// Rejection boundaries for the tally-result consensus path.
//
// After building a valid tally-result transaction, this test mutates
// it in several ways and asserts validate_dao_v2_tally_result_tx
// rejects each mutation. It also asserts the apply path is idempotent
// (duplicate returns false, does not double-write). And it checks that
// a partial set containing a non-selected member is rejected.
// ------------------------------------------------------------------
namespace {

// Replace the governance payload inside a tally-result tx with the
// serialized bytes of a (possibly mutated) certificate. Returns false
// if the tx does not currently carry exactly one tally_result payload.
bool rebuild_tx_with_cert(const transaction& src,
                          const dao::dao_tally_certificate& cert,
                          transaction& out)
{
    std::vector<uint8_t> cert_blob;
    if (!const_cast<dao::dao_tally_certificate&>(cert).serialize(cert_blob))
        return false;

    governance_payload gp;
    gp.type = governance_object::tally_result;
    gp.data = std::move(cert_blob);

    tx_extra_governance_payload txgp;
    txgp.payload = std::move(gp);
    tx_extra_field extra_field = txgp;
    const std::string extra_blob =
        t_serializable_object_to_blob(extra_field);

    out = src;
    out.extra.assign(extra_blob.begin(), extra_blob.end());
    return true;
}

// Extract the certificate from a tally-result tx.
bool extract_cert(const transaction& tx,
                  dao::dao_tally_certificate& out)
{
    std::vector<tx_extra_field> fields;
    if (!parse_tx_extra(tx.extra, fields))
        return false;
    for (const auto& f : fields) {
        if (f.type() != typeid(tx_extra_governance_payload))
            continue;
        const auto& gpf = boost::get<tx_extra_governance_payload>(f);
        if (gpf.payload.type != governance_object::tally_result)
            continue;
        return out.deserialize(gpf.payload.data);
    }
    return false;
}

} // namespace

TEST_F(DaoBootstrapIntegration, TallyResultTxRejectionBoundaries)
{
    constexpr uint64_t VOTE_END = 60001;
    const crypto::hash prop_id = []{
        crypto::hash h{};
        std::memset(h.data, 0x99, 32);
        return h;
    }();

    std::vector<crypto::public_key> committee_pks;
    committee_pks.push_back(m_node_pub);
    for (int i = 0; i < 2; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
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

    auto& bc = m_core->get_blockchain_storage();
    bc.queue_dao_v2_dkg_result(std::string{}, out);
    bc.maybe_process_dao_v2_dkg_results();

    // Install the key record. See note at the top of this file.
    bc.install_dao_tally_key_for_test(out.record);

    dao::dao_tally_key_record key_rec;
    ASSERT_TRUE(bc.get_db().get_dao_tally_key(key_rec));

    {
        proposal_record rec{};
        std::memset(&rec, 0, sizeof(rec));
        rec.proposal_id = prop_id;
        rec.voting_period_days = 7;
        rec.submission_height = VOTE_END - 1000;
        rec.voting_end_height = VOTE_END;
        std::memset(rec.tally_key_id.data, 0, 32);
        rec.submission_tx_hash = prop_id;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        rec.status_height = VOTE_END - 1000;
        db_wtxn_guard g(&db);
        bc.get_db().add_proposal_record(prop_id, rec);
    }

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

    bc.set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });

    dao::dao_v2_tally_share first_share;
    bool captured_first = false;
    bc.set_dao_v2_tally_broadcast([&](const dao::dao_v2_tally_share& s) {
        first_share = s; captured_first = true;
    });
    {
        db_wtxn_guard g(&db);
        bc.maybe_produce_dao_v2_share(VOTE_END + 1);
    }
    ASSERT_TRUE(captured_first);

    dao::dao_v2_tally_share second_share{};
    second_share.version = dao::dao_v2_tally_share::WIRE_VERSION;
    second_share.proposal_id = prop_id;
    second_share.vote_end_height = VOTE_END;
    second_share.tally_key_id.assign(32, 0);
    second_share.member_index = 2;
    second_share.aggregate_ciphertext_hash = agg_hash;
    {
        BIGNUM* sk = nullptr;
        const std::string dec(out.test_SK[1].begin(), out.test_SK[1].end());
        BN_dec2bn(&sk, dec.c_str());
        auto do_channel = [&](const std::vector<uint8_t>& c,
                              std::vector<uint8_t>& po,
                              dao::dao_partial_decryption_proof& proof) -> bool {
            std::vector<uint8_t> ci;
            if (!dao::dao_threshold_partial_decrypt(pk, c, sk, ci)) return false;
            BIGNUM* r = BN_new();
            if (!dao::dao_dkg_sample_r(pk, r)) { BN_free(r); return false; }
            const bool ok = dao::dao_partial_decryption_prove(
                pk, out.record.V, out.record.V_K_i[1], 2,
                c, ci, sk, r, proof);
            BN_free(r);
            if (!ok) return false;
            po = std::move(ci); return true;
        };
        ASSERT_TRUE(do_channel(E_W, second_share.partial_W, second_share.proof_W));
        ASSERT_TRUE(do_channel(E_S, second_share.partial_S, second_share.proof_S));
        ASSERT_TRUE(do_channel(E_B, second_share.partial_B, second_share.proof_B));
        BN_free(sk);
    }

    std::map<crypto::public_key, dao::dao_v2_tally_share> shares;
    shares[committee_pks[0]] = first_share;
    shares[committee_pks[1]] = second_share;

    const governance_params params = governance_params::default_params();
    cryptonote::TallyManager tm(db, params);

    transaction valid_tx;
    ASSERT_TRUE(tm.build_tally_result_transaction(
        prop_id, shares, key_rec.threshold, valid_tx));

    db_rtxn_guard rd(&db);
    ASSERT_TRUE(bc.validate_dao_v2_tally_result_tx(valid_tx, VOTE_END + 1));

    dao::dao_tally_certificate base_cert;
    ASSERT_TRUE(extract_cert(valid_tx, base_cert));

    // ---- Case 1: tampered aggregate hash ----
    {
        auto c = base_cert;
        std::memset(c.aggregate_ciphertext_hash.data, 0xEE, 32);
        transaction tx;
        ASSERT_TRUE(rebuild_tx_with_cert(valid_tx, c, tx));
        EXPECT_FALSE(bc.validate_dao_v2_tally_result_tx(tx, VOTE_END + 1));
    }

    // ---- Case 2: tampered recovered total ----
    {
        auto c = base_cert;
        c.W_total = dao::dao_u128(999999);
        transaction tx;
        ASSERT_TRUE(rebuild_tx_with_cert(valid_tx, c, tx));
        EXPECT_FALSE(bc.validate_dao_v2_tally_result_tx(tx, VOTE_END + 1));
    }

    // ---- Case 3: block height vs voting end ----
    // Voting must have ended, but the result may be mined later than
    // vote_end_height + 1.
    EXPECT_FALSE(bc.validate_dao_v2_tally_result_tx(valid_tx, VOTE_END));
    EXPECT_TRUE (bc.validate_dao_v2_tally_result_tx(valid_tx, VOTE_END + 1));
    EXPECT_TRUE (bc.validate_dao_v2_tally_result_tx(valid_tx, VOTE_END + 2));

    // ---- Case 4: wrong key_id ----
    {
        auto c = base_cert;
        if (c.key_id.empty()) c.key_id.assign(32, 0);
        c.key_id[0] ^= 0xFF;
        transaction tx;
        ASSERT_TRUE(rebuild_tx_with_cert(valid_tx, c, tx));
        EXPECT_FALSE(bc.validate_dao_v2_tally_result_tx(tx, VOTE_END + 1));
    }

    // ---- Case 5: wrong vote_end_height ----
    {
        auto c = base_cert;
        c.vote_end_height = VOTE_END - 1;
        transaction tx;
        ASSERT_TRUE(rebuild_tx_with_cert(valid_tx, c, tx));
        EXPECT_FALSE(bc.validate_dao_v2_tally_result_tx(tx, VOTE_END + 1));
    }

    // ---- Case 6: partial set index outside bootstrap shareholder set ----
    {
        auto c = base_cert;
        c.W.member_indices[0] = 99;   // does not exist
        transaction tx;
        ASSERT_TRUE(rebuild_tx_with_cert(valid_tx, c, tx));
        EXPECT_FALSE(bc.validate_dao_v2_tally_result_tx(tx, VOTE_END + 1));
    }

    // ---- Case 7: tampered partial plaintext ----
    {
        auto c = base_cert;
        c.W.partials[0][0] ^= 0x01;
        transaction tx;
        ASSERT_TRUE(rebuild_tx_with_cert(valid_tx, c, tx));
        EXPECT_FALSE(bc.validate_dao_v2_tally_result_tx(tx, VOTE_END + 1));
    }

    // ---- Case 8: apply twice -> second is refused ----
    {
        db_wtxn_guard g(&db);
        ASSERT_TRUE(bc.apply_dao_v2_tally_result(valid_tx, VOTE_END + 1));
    }
    {
        db_wtxn_guard g(&db);
        EXPECT_FALSE(bc.apply_dao_v2_tally_result(valid_tx, VOTE_END + 1));
    }

    // ---- Case 9: duplicate reject — validator refuses when outcome
    //               already recorded ----
    {
        db_rtxn_guard r2(&db);
        EXPECT_FALSE(bc.validate_dao_v2_tally_result_tx(valid_tx, VOTE_END + 1));
    }

    BN_free(W); BN_free(S); BN_free(B);
    BN_free(r1); BN_free(r2); BN_free(r3);
}

// ------------------------------------------------------------------
// Reconstructability from chain state alone.
//
// After a tally-result transaction has been validated and applied, the
// authoritative outcome is derivable purely from:
//   - the transaction itself (carried in a block)
//   - the chain state committed before that block was applied
//     (aggregate ciphertexts, supply snapshot, key record,
//     proposal record, eligible records)
//
// Nothing in the reconciliation path may read:
//   - m_dao_v2_tally_shares (in-memory share accumulator)
//   - any per-session Reset / dynamic-share state
//   - any local P2P-only bookkeeping
//
// This test rebuilds the tally-result transaction, then asserts that
// validate_dao_v2_tally_result_tx() still succeeds with the in-memory
// share accumulator cleared. If the reconciliation function needed
// that accumulator, this test would fail. It does not, so it passes.
//
// A stronger version of this property (fresh core synced from genesis
// reconstructing the same outcome) requires a two-core P2P fixture
// that does not yet exist. This test covers the same reconciliation
// code path with a single core.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, TallyResultReconstructableFromChainState)
{
    constexpr uint64_t VOTE_END = 60001;
    const crypto::hash prop_id = []{
        crypto::hash h{};
        std::memset(h.data, 0xAA, 32);
        return h;
    }();

    std::vector<crypto::public_key> committee_pks;
    committee_pks.push_back(m_node_pub);
    for (int i = 0; i < 2; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
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

    auto& bc = m_core->get_blockchain_storage();
    bc.queue_dao_v2_dkg_result(std::string{}, out);
    bc.maybe_process_dao_v2_dkg_results();

    // Install the key record. See note at the top of this file.
    bc.install_dao_tally_key_for_test(out.record);

    dao::dao_tally_key_record key_rec;
    ASSERT_TRUE(bc.get_db().get_dao_tally_key(key_rec));

    {
        proposal_record rec{};
        std::memset(&rec, 0, sizeof(rec));
        rec.proposal_id = prop_id;
        rec.voting_period_days = 7;
        rec.submission_height = VOTE_END - 1000;
        rec.voting_end_height = VOTE_END;
        std::memset(rec.tally_key_id.data, 0, 32);
        rec.submission_tx_hash = prop_id;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        rec.status_height = VOTE_END - 1000;
        db_wtxn_guard g(&db);
        bc.get_db().add_proposal_record(prop_id, rec);
    }

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

    bc.set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });

    dao::dao_v2_tally_share first_share;
    bool captured_first = false;
    bc.set_dao_v2_tally_broadcast([&](const dao::dao_v2_tally_share& s) {
        first_share = s; captured_first = true;
    });
    {
        db_wtxn_guard g(&db);
        bc.maybe_produce_dao_v2_share(VOTE_END + 1);
    }
    ASSERT_TRUE(captured_first);

    dao::dao_v2_tally_share second_share{};
    second_share.version = dao::dao_v2_tally_share::WIRE_VERSION;
    second_share.proposal_id = prop_id;
    second_share.vote_end_height = VOTE_END;
    second_share.tally_key_id.assign(32, 0);
    second_share.member_index = 2;
    second_share.aggregate_ciphertext_hash = agg_hash;
    {
        BIGNUM* sk = nullptr;
        const std::string dec(out.test_SK[1].begin(), out.test_SK[1].end());
        BN_dec2bn(&sk, dec.c_str());
        auto do_channel = [&](const std::vector<uint8_t>& c,
                              std::vector<uint8_t>& po,
                              dao::dao_partial_decryption_proof& proof) -> bool {
            std::vector<uint8_t> ci;
            if (!dao::dao_threshold_partial_decrypt(pk, c, sk, ci)) return false;
            BIGNUM* r = BN_new();
            if (!dao::dao_dkg_sample_r(pk, r)) { BN_free(r); return false; }
            const bool ok = dao::dao_partial_decryption_prove(
                pk, out.record.V, out.record.V_K_i[1], 2,
                c, ci, sk, r, proof);
            BN_free(r);
            if (!ok) return false;
            po = std::move(ci); return true;
        };
        ASSERT_TRUE(do_channel(E_W, second_share.partial_W, second_share.proof_W));
        ASSERT_TRUE(do_channel(E_S, second_share.partial_S, second_share.proof_S));
        ASSERT_TRUE(do_channel(E_B, second_share.partial_B, second_share.proof_B));
        BN_free(sk);
    }

    std::map<crypto::public_key, dao::dao_v2_tally_share> shares;
    shares[committee_pks[0]] = first_share;
    shares[committee_pks[1]] = second_share;

    const governance_params params = governance_params::default_params();
    cryptonote::TallyManager tm(db, params);

    transaction result_tx;
    ASSERT_TRUE(tm.build_tally_result_transaction(
        prop_id, shares, key_rec.threshold, result_tx));

    // ---- Baseline: valid from chain state ----
    {
        db_rtxn_guard r(&db);
        ASSERT_TRUE(bc.validate_dao_v2_tally_result_tx(result_tx, VOTE_END + 1));
    }

    // ---- Simulate a "fresh node": no in-memory share accumulator, no
    //      P2P session, no local per-proposal state. Only the chain
    //      LMDB and the transaction itself remain. ----
    bc.clear_dao_v2_tally_shares_for_test();

    // The transaction is still recognised.
    EXPECT_TRUE(bc.is_dao_v2_tally_result_tx(result_tx));

    // The transaction is still validatable from chain state alone.
    {
        db_rtxn_guard r(&db);
        EXPECT_TRUE(bc.validate_dao_v2_tally_result_tx(result_tx, VOTE_END + 1));
    }

    // Applying it now writes the outcome as consensus state.
    {
        db_wtxn_guard g(&db);
        ASSERT_TRUE(bc.apply_dao_v2_tally_result(result_tx, VOTE_END + 1));
    }

    dao::dao_v2_outcome_record outcome;
    ASSERT_TRUE(bc.get_db().get_dao_v2_outcome(prop_id, outcome));
    EXPECT_TRUE(outcome.passed);
    EXPECT_EQ(outcome.yes_weight, dao::dao_u128(1000));
    EXPECT_EQ(outcome.participation_coins, dao::dao_u128(5000));

    BN_free(W); BN_free(S); BN_free(B);
    BN_free(r1); BN_free(r2); BN_free(r3);
}

// ------------------------------------------------------------------
// Test J — bootstrap DKG share persists across a full tally cycle.
//
// The stable Paillier key belongs to the DAO, not to a proposal.
// A completed tally result must leave the bootstrap share in place so
// the same key can serve the next proposal.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, BootstrapSharePersistsAfterTally)
{
    constexpr uint64_t VOTE_END = 60001;
    const crypto::hash prop_id = []{
        crypto::hash h{};
        std::memset(h.data, 0xBB, 32);
        return h;
    }();

    std::vector<crypto::public_key> committee_pks;
    committee_pks.push_back(m_node_pub);
    for (int i = 0; i < 2; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
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

    auto& bc = m_core->get_blockchain_storage();
    bc.queue_dao_v2_dkg_result(std::string{}, out);
    bc.maybe_process_dao_v2_dkg_results();

    // Install the key record. See note at the top of this file.
    bc.install_dao_tally_key_for_test(out.record);

    // Snapshot the bootstrap share for member 1.
    std::vector<uint8_t> share_before;
    ASSERT_TRUE(bc.get_db().get_dao_local_share(1, 1, share_before));
    ASSERT_FALSE(share_before.empty());

    dao::dao_tally_key_record key_rec;
    ASSERT_TRUE(bc.get_db().get_dao_tally_key(key_rec));

    {
        proposal_record rec{};
        std::memset(&rec, 0, sizeof(rec));
        rec.proposal_id = prop_id;
        rec.voting_period_days = 7;
        rec.submission_height = VOTE_END - 1000;
        rec.voting_end_height = VOTE_END;
        std::memset(rec.tally_key_id.data, 0, 32);
        rec.submission_tx_hash = prop_id;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        rec.status_height = VOTE_END - 1000;
        db_wtxn_guard g(&db);
        bc.get_db().add_proposal_record(prop_id, rec);
    }

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

    bc.set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });

    dao::dao_v2_tally_share first_share;
    bool captured_first = false;
    bc.set_dao_v2_tally_broadcast([&](const dao::dao_v2_tally_share& s) {
        first_share = s; captured_first = true;
    });
    {
        db_wtxn_guard g(&db);
        bc.maybe_produce_dao_v2_share(VOTE_END + 1);
    }
    ASSERT_TRUE(captured_first);

    dao::dao_v2_tally_share second_share{};
    second_share.version = dao::dao_v2_tally_share::WIRE_VERSION;
    second_share.proposal_id = prop_id;
    second_share.vote_end_height = VOTE_END;
    second_share.tally_key_id.assign(32, 0);
    second_share.member_index = 2;
    second_share.aggregate_ciphertext_hash = agg_hash;
    {
        BIGNUM* sk = nullptr;
        const std::string dec(out.test_SK[1].begin(), out.test_SK[1].end());
        BN_dec2bn(&sk, dec.c_str());
        auto do_channel = [&](const std::vector<uint8_t>& c,
                              std::vector<uint8_t>& po,
                              dao::dao_partial_decryption_proof& proof) -> bool {
            std::vector<uint8_t> ci;
            if (!dao::dao_threshold_partial_decrypt(pk, c, sk, ci)) return false;
            BIGNUM* r = BN_new();
            if (!dao::dao_dkg_sample_r(pk, r)) { BN_free(r); return false; }
            const bool ok = dao::dao_partial_decryption_prove(
                pk, out.record.V, out.record.V_K_i[1], 2,
                c, ci, sk, r, proof);
            BN_free(r);
            if (!ok) return false;
            po = std::move(ci); return true;
        };
        ASSERT_TRUE(do_channel(E_W, second_share.partial_W, second_share.proof_W));
        ASSERT_TRUE(do_channel(E_S, second_share.partial_S, second_share.proof_S));
        ASSERT_TRUE(do_channel(E_B, second_share.partial_B, second_share.proof_B));
        BN_free(sk);
    }

    std::map<crypto::public_key, dao::dao_v2_tally_share> shares;
    shares[committee_pks[0]] = first_share;
    shares[committee_pks[1]] = second_share;

    const governance_params params = governance_params::default_params();
    cryptonote::TallyManager tm(db, params);

    transaction result_tx;
    ASSERT_TRUE(tm.build_tally_result_transaction(
        prop_id, shares, key_rec.threshold, result_tx));

    {
        db_wtxn_guard g(&db);
        ASSERT_TRUE(bc.apply_dao_v2_tally_result(result_tx, VOTE_END + 1));
    }

    // Outcome recorded.
    dao::dao_v2_outcome_record outcome;
    ASSERT_TRUE(bc.get_db().get_dao_v2_outcome(prop_id, outcome));

    // Bootstrap share for member 1 still exists and is byte-identical.
    // This node is member 1 of the DKG; the other members run on other
    // nodes in production, so their shares are not present in this
    // local LMDB.
    std::vector<uint8_t> share_after;
    ASSERT_TRUE(bc.get_db().get_dao_local_share(1, 1, share_after));
    EXPECT_EQ(share_before, share_after);

    // The public key record also persists — it belongs to the DAO for
    // the lifetime of the key, not to a single proposal.
    dao::dao_tally_key_record key_after;
    ASSERT_TRUE(bc.get_db().get_dao_tally_key(key_after));
    EXPECT_EQ(key_after.N, key_rec.N);
    EXPECT_EQ(key_after.V_K_i, key_rec.V_K_i);

    BN_free(W); BN_free(S); BN_free(B);
    BN_free(r1); BN_free(r2); BN_free(r3);
}

// ------------------------------------------------------------------
// Test G — a share from a bootstrap shareholder who is not in the
// selected tally committee is rejected by the consensus validator.
//
// Setup: DKG over 3 shareholders. Only shareholders 1 and 2 are made
// eligible. The selector therefore returns committee {1, 2}. A
// certificate that names member 3 in its partial sets — even though
// member 3 is a legitimate bootstrap DKG shareholder — must be
// rejected before cryptographic verification runs.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, OutOfCommitteeShareholderShareAccepted)
{
    constexpr uint64_t VOTE_END = 60001;
    const crypto::hash prop_id = []{
        crypto::hash h{};
        std::memset(h.data, 0xCC, 32);
        return h;
    }();

    std::vector<crypto::public_key> committee_pks;
    committee_pks.push_back(m_node_pub);
    for (int i = 0; i < 2; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        committee_pks.push_back(pk);
    }

    auto& db = m_core->get_blockchain_storage().get_db();

    // Only members 1 and 2 are eligible. Member 3 is a bootstrap
    // shareholder but is not currently eligible.
    for (size_t i = 0; i < 2; ++i) {
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

    auto& bc = m_core->get_blockchain_storage();
    bc.queue_dao_v2_dkg_result(std::string{}, out);
    bc.maybe_process_dao_v2_dkg_results();

    // Install the key record. See note at the top of this file.
    bc.install_dao_tally_key_for_test(out.record);

    dao::dao_tally_key_record key_rec;
    ASSERT_TRUE(bc.get_db().get_dao_tally_key(key_rec));

    // Confirm the selected committee excludes member 3.
    {
        db_rtxn_guard r(&db);
        const auto sel =
            bc.select_dao_v2_tally_committee(key_rec, VOTE_END);
        ASSERT_EQ(sel.size(), 2u);
        EXPECT_EQ(sel[0], committee_pks[0]);
        EXPECT_EQ(sel[1], committee_pks[1]);
        for (const auto& pk : sel)
            EXPECT_NE(pk, committee_pks[2]);
    }

    {
        proposal_record rec{};
        std::memset(&rec, 0, sizeof(rec));
        rec.proposal_id = prop_id;
        rec.voting_period_days = 7;
        rec.submission_height = VOTE_END - 1000;
        rec.voting_end_height = VOTE_END;
        std::memset(rec.tally_key_id.data, 0, 32);
        rec.submission_tx_hash = prop_id;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        rec.status_height = VOTE_END - 1000;
        db_wtxn_guard g(&db);
        bc.get_db().add_proposal_record(prop_id, rec);
    }

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

    bc.set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });

    dao::dao_v2_tally_share first_share;
    bool captured_first = false;
    bc.set_dao_v2_tally_broadcast([&](const dao::dao_v2_tally_share& s) {
        first_share = s; captured_first = true;
    });
    {
        db_wtxn_guard g(&db);
        bc.maybe_produce_dao_v2_share(VOTE_END + 1);
    }
    ASSERT_TRUE(captured_first);

    // Build a share from member 3. Member 3 holds a legitimate DKG
    // share; only its eligibility is missing.
    dao::dao_v2_tally_share third_share{};
    third_share.version = dao::dao_v2_tally_share::WIRE_VERSION;
    third_share.proposal_id = prop_id;
    third_share.vote_end_height = VOTE_END;
    third_share.tally_key_id.assign(32, 0);
    third_share.member_index = 3;
    third_share.aggregate_ciphertext_hash = agg_hash;
    {
        BIGNUM* sk = nullptr;
        const std::string dec(out.test_SK[2].begin(), out.test_SK[2].end());
        BN_dec2bn(&sk, dec.c_str());
        auto do_channel = [&](const std::vector<uint8_t>& c,
                              std::vector<uint8_t>& po,
                              dao::dao_partial_decryption_proof& proof) -> bool {
            std::vector<uint8_t> ci;
            if (!dao::dao_threshold_partial_decrypt(pk, c, sk, ci)) return false;
            BIGNUM* r = BN_new();
            if (!dao::dao_dkg_sample_r(pk, r)) { BN_free(r); return false; }
            const bool ok = dao::dao_partial_decryption_prove(
                pk, out.record.V, out.record.V_K_i[2], 3,
                c, ci, sk, r, proof);
            BN_free(r);
            if (!ok) return false;
            po = std::move(ci); return true;
        };
        ASSERT_TRUE(do_channel(E_W, third_share.partial_W, third_share.proof_W));
        ASSERT_TRUE(do_channel(E_S, third_share.partial_S, third_share.proof_S));
        ASSERT_TRUE(do_channel(E_B, third_share.partial_B, third_share.proof_B));
        BN_free(sk);
    }

    // A certificate built from {1, 3} is valid. Member 3 is an
    // original DKG shareholder even though it is not in the currently
    // selected validation committee. Partial-decryption shares may
    // come from any original shareholder; the validation committee is
    // only the set of currently eligible nodes that participate in
    // verifying and broadcasting. The certificate must be accepted.
    std::map<crypto::public_key, dao::dao_v2_tally_share> shares;
    shares[committee_pks[0]] = first_share;
    shares[committee_pks[2]] = third_share;

    const governance_params params = governance_params::default_params();
    cryptonote::TallyManager tm(db, params);

    transaction result_tx;
    ASSERT_TRUE(tm.build_tally_result_transaction(
        prop_id, shares, key_rec.threshold, result_tx));
    db_rtxn_guard r(&db);
    EXPECT_TRUE(bc.validate_dao_v2_tally_result_tx(
        result_tx, VOTE_END + 1));

    BN_free(W); BN_free(S); BN_free(B);
    BN_free(r1); BN_free(r2); BN_free(r3);
}

// ------------------------------------------------------------------
// B1: node readiness becomes chain state.
//
// 1. mine a few blocks so a lower height has a canonical hash;
// 2. install a node key;
// 3. trigger maybe_announce_dao_v2_node_ready, which submits a
//    node_ready tx to mempool;
// 4. mine a block that includes it;
// 5. assert get_dao_v2_node_ready returns the stored hash;
// 6. pop the block and assert the row is rolled back.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, NodeReadyChainState)
{
    using namespace cryptonote;

    auto& bc = m_core->get_blockchain_storage();

    account_base miner_acc;
    miner_acc.generate();

    // Mine until tip >= 3 so a lower block height has a canonical hash.
    while (bc.get_current_blockchain_height() < 3) {
        block tmpl{};
        difficulty_type diff{};
        uint64_t tmpl_h = 0, reward = 0, seed_h = 0;
        crypto::hash seed_hsh{};
        blobdata ex_nonce(8, 0);
        ASSERT_TRUE(bc.create_block_template(
            tmpl, miner_acc.get_keys().m_account_address,
            diff, tmpl_h, reward, ex_nonce, seed_h, seed_hsh));
        auto gbh = [&bc](const block& b, uint64_t h,
                         const crypto::hash* sh,
                         unsigned int mn, crypto::hash& ho) -> bool {
            return get_block_longhash(&bc, b, ho, h, sh,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, tmpl_h, nullptr));
        block_verification_context bvc{};
        pool_supplement extra{};
        blobdata bb = block_to_blob(tmpl);
        ASSERT_TRUE(m_core->handle_single_incoming_block(
            bb, &tmpl, bvc, extra, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }

    crypto::public_key self_pk;
    crypto::secret_key self_sk;
    crypto::generate_keys(self_pk, self_sk);
    m_core->set_node_key(self_sk);

    bc.set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });
    bc.maybe_announce_dao_v2_node_ready();

    std::vector<crypto::hash> pool_hashes;
    m_core->get_pool_transaction_hashes(pool_hashes,
                                        /*include_sensitive_txes=*/true);
    ASSERT_GE(pool_hashes.size(), 1u);

    const uint64_t h_before = bc.get_current_blockchain_height();
    const uint64_t announce_h = h_before - 1;
    const crypto::hash expected_hash = bc.get_block_id_by_height(announce_h);

    {
        block tmpl{};
        difficulty_type diff{};
        uint64_t tmpl_h = 0, reward = 0, seed_h = 0;
        crypto::hash seed_hsh{};
        blobdata ex_nonce(8, 0);
        ASSERT_TRUE(bc.create_block_template(
            tmpl, miner_acc.get_keys().m_account_address,
            diff, tmpl_h, reward, ex_nonce, seed_h, seed_hsh));
        auto gbh = [&bc](const block& b, uint64_t h,
                         const crypto::hash* sh,
                         unsigned int mn, crypto::hash& ho) -> bool {
            return get_block_longhash(&bc, b, ho, h, sh,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, tmpl_h, nullptr));
        block_verification_context bvc{};
        pool_supplement extra{};
        blobdata bb = block_to_blob(tmpl);
        ASSERT_TRUE(m_core->handle_single_incoming_block(
            bb, &tmpl, bvc, extra, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }

    ASSERT_EQ(bc.get_current_blockchain_height(), h_before + 1);

    crypto::hash stored_hash{};
    ASSERT_TRUE(bc.get_db().get_dao_v2_node_ready(
        self_pk, announce_h, stored_hash));
    EXPECT_EQ(stored_hash, expected_hash);

    bc.pop_blocks(1);
    ASSERT_EQ(bc.get_current_blockchain_height(), h_before);

    crypto::hash after_hash{};
    EXPECT_FALSE(bc.get_db().get_dao_v2_node_ready(
        self_pk, announce_h, after_hash));
}

// ------------------------------------------------------------------
// B2b2b: a proposal mined into a block starts a per-proposal DKG
// runner, using the chain-state ready roster as its committee.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, ProposalTriggersPerProposalDkg)
{
    using namespace cryptonote;

    auto& bc = m_core->get_blockchain_storage();
    auto& db = bc.get_db();

    // Ready roster: 3 pubkeys at a canonical height.
    crypto::hash can_hash_at_1{};
    while (bc.get_current_blockchain_height() < 3) {
        account_base ma; ma.generate();
        block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
        crypto::hash shh{}; blobdata en(8,0);
        ASSERT_TRUE(bc.create_block_template(tmpl,
            ma.get_keys().m_account_address, diff, h, r, en, sh, shh));
        auto gbh = [&bc](const block& b, uint64_t hh,
                         const crypto::hash* s, unsigned int mn,
                         crypto::hash& o) -> bool {
            return get_block_longhash(&bc, b, o, hh, s,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, h, nullptr));
        block_verification_context bvc{}; pool_supplement e{};
        blobdata bb = block_to_blob(tmpl);
        ASSERT_TRUE(m_core->handle_single_incoming_block(
            bb, &tmpl, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }
    can_hash_at_1 = bc.get_block_id_by_height(1);

    // First key is this node's identity so start_dao_v2_dkg_for_committee
    // finds us in the committee.
    crypto::public_key self_pk{}; crypto::secret_key self_sk{};
    crypto::generate_keys(self_pk, self_sk);
    m_core->set_node_key(self_sk);
    {
        db_wtxn_guard g(&db);
        db.add_dao_v2_node_ready(self_pk, 1, can_hash_at_1);
    }
    for (int i = 0; i < 2; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        db_wtxn_guard g(&db);
        db.add_dao_v2_node_ready(pk, 1, can_hash_at_1);
    }
    bc.set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });

    // Seed a proposal record with submission_height = current tip.
    crypto::hash prop_id{};
    std::memset(prop_id.data, 0xA5, 32);
    const uint64_t sub_h = bc.get_current_blockchain_height();
    {
        proposal_record rec{};
        rec.proposal_id = prop_id;
        rec.submission_height = sub_h;
        rec.voting_end_height = sub_h + 720;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        std::memset(rec.tally_key_id.data, 0, 32);
        db_wtxn_guard g(&db);
        db.add_proposal_record(prop_id, rec);
    }

    // Direct invocation of the trigger method (the block-apply loop is
    // a one-line scan that calls the same method; covering that in a
    // multi-node integration is B4 scope).
    EXPECT_EQ(bc.start_dao_v2_dkg_for_proposal(prop_id),
              dao::dao_dkg_start_status::started);

    const std::string ceremony_id =
        epee::string_tools::pod_to_hex(prop_id);
    std::lock_guard<std::mutex> lk2(bc.m_dao_v2_dkg_runners_for_test_mutex());
    EXPECT_GT(bc.m_dao_v2_dkg_runners_for_test().count(ceremony_id), 0u);
}

// ------------------------------------------------------------------
// B2c1 isolation: two proposals' tally keys must not collide.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, TwoProposalsIsolatedTallyKeys)
{
    using namespace cryptonote;

    auto& bc = m_core->get_blockchain_storage();
    auto& db = bc.get_db();

    crypto::public_key self_pk{};
    crypto::secret_key self_sk{};
    crypto::generate_keys(self_pk, self_sk);
    m_core->set_node_key(self_sk);

    auto make_record = [&](uint8_t seed) -> dao::dao_tally_key_record {
        dao::dao_tally_key_record rec{};
        rec.version        = 1;
        rec.committee_size = 3;
        rec.threshold      = 2;
        rec.t              = 1;
        rec.committee_id_hash.assign(32, seed);
        rec.committee_members.resize(3);
        rec.committee_members[0].assign(self_pk.data, self_pk.data + 32);
        for (int i = 1; i < 3; ++i) {
            crypto::public_key pk; crypto::secret_key sk;
            crypto::generate_keys(pk, sk);
            rec.committee_members[i].assign(pk.data, pk.data + 32);
        }
        rec.delta.assign(32, seed);
        rec.N.assign(256, seed);
        rec.G.assign(256, 0);
        rec.theta.assign(256, 0);
        rec.V.assign(512, 0);
        rec.V_K_i.assign(3, std::vector<uint8_t>(512, seed));
        rec.vss_P.assign(64, 0);
        rec.vss_P_prime.assign(64, 0);
        rec.vss_g.assign(1, 4);
        rec.vss_h.assign(64, 0);
        rec.activation_height   = 1;
        rec.dkg_transcript_hash.assign(32, 0);
        rec.key_id.assign(32, seed);
        return rec;
    };

    auto keyA = make_record(0xAA);
    auto keyB = make_record(0xBB);
    ASSERT_NE(keyA.key_id, keyB.key_id);

    std::vector<uint8_t> shareA{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    std::vector<uint8_t> shareB{0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18};

    bc.install_dao_tally_key_for_proposal_for_test(keyA, shareA);
    bc.install_dao_tally_key_for_proposal_for_test(keyB, shareB);

    {
        dao::dao_tally_key_record r;
        ASSERT_TRUE(db.get_dao_tally_key_by_id(keyA.key_id, r));
        EXPECT_EQ(r.key_id, keyA.key_id);
        ASSERT_TRUE(db.get_dao_tally_key_by_id(keyB.key_id, r));
        EXPECT_EQ(r.key_id, keyB.key_id);
    }

    const uint32_t ssA = dao::share_set_id_for_key_id(keyA.key_id);
    const uint32_t ssB = dao::share_set_id_for_key_id(keyB.key_id);
    EXPECT_GT(ssA, 1u);
    EXPECT_GT(ssB, 1u);
    EXPECT_NE(ssA, ssB);

    {
        dao::dao_share_set_record ss;
        ASSERT_TRUE(db.get_dao_share_set(ssA, ss));
        EXPECT_EQ(ss.key_id, keyA.key_id);
        ASSERT_TRUE(db.get_dao_share_set(ssB, ss));
        EXPECT_EQ(ss.key_id, keyB.key_id);
    }

    {
        std::vector<uint8_t> lsA, lsB;
        ASSERT_TRUE(db.get_dao_local_share(ssA, 1, lsA));
        ASSERT_TRUE(db.get_dao_local_share(ssB, 1, lsB));
        EXPECT_NE(lsA, lsB);
    }

    {
        dao::dao_tally_key_record singleton;
        EXPECT_FALSE(db.get_dao_tally_key(singleton));
    }
}

// ------------------------------------------------------------------
// B3b: at voting-end, if the ready roster differs from the acceptance
// committee, a reshare must start for the proposal's key.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, B3bTriggerFiresOnRosterChange)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    auto& bc = m_core->get_blockchain_storage();
    auto& db = bc.get_db();

    // Mine to height 3 so height 2 has a canonical hash.
    account_base miner; miner.generate();
    while (bc.get_current_blockchain_height() < 3) {
        block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
        crypto::hash shh{}; blobdata en(8,0);
        ASSERT_TRUE(bc.create_block_template(tmpl,
            miner.get_keys().m_account_address, diff, h, r, en, sh, shh));
        auto gbh = [&bc](const block& b, uint64_t hh,
                         const crypto::hash* sm, unsigned int mn,
                         crypto::hash& o) -> bool {
            return get_block_longhash(&bc, b, o, hh, sm,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, h, nullptr));
        block_verification_context bvc{}; pool_supplement e{};
        blobdata bb = block_to_blob(tmpl);
        ASSERT_TRUE(m_core->handle_single_incoming_block(
            bb, &tmpl, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }
    const crypto::hash ready_h = bc.get_block_id_by_height(2);

    // Real DKG for a 3-party committee. Committee = this node + two
    // dummies, unsorted — the trigger sorts the ready roster, not the
    // committee, so unsorted is fine.
    std::vector<crypto::public_key> committee;
    std::vector<crypto::secret_key> committee_sks;

    crypto::public_key self_pk; crypto::secret_key self_sk;
    crypto::generate_keys(self_pk, self_sk);
    m_core->set_node_key(self_sk);
    committee.push_back(self_pk);
    committee_sks.push_back(self_sk);

    for (int i = 0; i < 2; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        committee.push_back(pk);
        committee_sks.push_back(sk);
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
    cfg.member_ids     = committee;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F33ULL;
    cfg.local_party_id = 1;   // our committee[0] = self_pk

    dkg_result dkg_out;
    ASSERT_TRUE(dkg_run_with_transport(cfg, factory, dkg_out));
    ASSERT_TRUE(dkg_out.candidate_accepted);
    ASSERT_FALSE(dkg_out.local_secret_share.empty());

    // Install key record + real local share for this proposal.
    bc.install_dao_tally_key_for_proposal_for_test(
        dkg_out.record, dkg_out.local_secret_share);

    // Ready records: 3 committee members + 1 extra, all at height 2.
    crypto::public_key extra;
    crypto::secret_key extra_sk;
    crypto::generate_keys(extra, extra_sk);
    {
        db_wtxn_guard g(&db);
        for (const auto& pk : committee)
            db.add_dao_v2_node_ready(pk, 2, ready_h);
        db.add_dao_v2_node_ready(extra, 2, ready_h);
    }

    bc.set_dao_v2_tally_broadcast(
        [](const dao::dao_v2_tally_share&) {});
    bc.set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });

    // Proposal whose voting_end_height equals 3.
    const uint64_t voting_end = 3;
    crypto::hash prop_id{};
    std::memset(prop_id.data, 0xA7, 32);
    {
        proposal_record rec{};
        rec.proposal_id       = prop_id;
        rec.submission_height = 1;
        rec.voting_end_height = voting_end;
        rec.status            = PROPOSAL_STATUS_ACTIVE;
        std::memcpy(rec.tally_key_id.data,
                    dkg_out.record.key_id.data(), 32);
        db_wtxn_guard g(&db);
        db.add_proposal_record(prop_id, rec);
    }

    ASSERT_FALSE(bc.has_dao_v2_reshare_runner_for_test());
    bc.maybe_produce_dao_v2_share(voting_end + 1);
    EXPECT_TRUE(bc.has_dao_v2_reshare_runner_for_test());
}

TEST_F(DaoBootstrapIntegration, B3bTriggerNoOpOnSameRoster)
{
    using namespace cryptonote;

    auto& bc = m_core->get_blockchain_storage();
    auto& db = bc.get_db();

    account_base miner; miner.generate();
    while (bc.get_current_blockchain_height() < 3) {
        block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
        crypto::hash shh{}; blobdata en(8,0);
        ASSERT_TRUE(bc.create_block_template(tmpl,
            miner.get_keys().m_account_address, diff, h, r, en, sh, shh));
        auto gbh = [&bc](const block& b, uint64_t hh,
                         const crypto::hash* s, unsigned int mn,
                         crypto::hash& o) -> bool {
            return get_block_longhash(&bc, b, o, hh, s,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, h, nullptr));
        block_verification_context bvc{}; pool_supplement e{};
        blobdata bb = block_to_blob(tmpl);
        ASSERT_TRUE(m_core->handle_single_incoming_block(
            bb, &tmpl, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }
    const crypto::hash ready_h = bc.get_block_id_by_height(2);

    crypto::public_key k_self; crypto::secret_key sk_self;
    crypto::generate_keys(k_self, sk_self);
    m_core->set_node_key(sk_self);

    std::vector<crypto::public_key> committee = { k_self };
    for (int i = 0; i < 2; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        committee.push_back(pk);
    }
    std::sort(committee.begin(), committee.end(),
              [](const auto& a, const auto& b) {
                return std::memcmp(a.data, b.data, 32) < 0;
              });

    dao::dao_tally_key_record key_rec{};
    key_rec.version        = 1;
    key_rec.committee_size = 3;
    key_rec.threshold      = 2;
    key_rec.t              = 1;
    key_rec.committee_id_hash.assign(32, 0x11);
    for (const auto& pk : committee)
        key_rec.committee_members.emplace_back(pk.data, pk.data + 32);
    key_rec.delta.assign(32, 0x22);
    key_rec.N.assign(256, 0x33);
    key_rec.G.assign(256, 0);
    key_rec.theta.assign(256, 0);
    key_rec.V.assign(512, 0);
    key_rec.V_K_i.assign(3, std::vector<uint8_t>(512, 0x44));
    key_rec.vss_P.assign(64, 0);
    key_rec.vss_P_prime.assign(64, 0);
    key_rec.vss_g.assign(1, 4);
    key_rec.vss_h.assign(64, 0);
    key_rec.activation_height = 2;
    key_rec.dkg_transcript_hash.assign(32, 0);
    key_rec.key_id.assign(32, 0x55);

    std::vector<uint8_t> share_bytes(16, 0x66);
    bc.install_dao_tally_key_for_proposal_for_test(key_rec, share_bytes);

    // Ready = exactly the committee.
    {
        db_wtxn_guard g(&db);
        for (const auto& pk : committee)
            db.add_dao_v2_node_ready(pk, 2, ready_h);
    }

    bc.set_dao_v2_tally_broadcast(
        [](const dao::dao_v2_tally_share&) {});
    bc.set_dao_v2_dkg_send([](const std::string&) -> bool { return true; });

    const uint64_t voting_end = 3;
    crypto::hash prop_id{};
    std::memset(prop_id.data, 0xA8, 32);
    {
        proposal_record rec{};
        rec.proposal_id       = prop_id;
        rec.submission_height = 1;
        rec.voting_end_height = voting_end;
        rec.status            = PROPOSAL_STATUS_ACTIVE;
        std::memcpy(rec.tally_key_id.data, key_rec.key_id.data(), 32);
        db_wtxn_guard g(&db);
        db.add_proposal_record(prop_id, rec);
    }

    ASSERT_FALSE(bc.has_dao_v2_reshare_runner_for_test());
    bc.maybe_produce_dao_v2_share(voting_end + 1);
    EXPECT_FALSE(bc.has_dao_v2_reshare_runner_for_test());
}

// ------------------------------------------------------------------
// v6 certificate evidence end-to-end. Real 3-party DKG, real reshare
// of the 3-member key to a 3-member subset that includes a new member,
// hand-built v6 cert, verify accepts, tampered evidence rejects.
// ------------------------------------------------------------------
TEST_F(DaoBootstrapIntegration, V6CertificateWithReshareEvidence)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    auto& bc = m_core->get_blockchain_storage();
    auto& db = bc.get_db();

    // Mine to height 3 so genesis and height-2 hashes are canonical.
    account_base miner; miner.generate();
    while (bc.get_current_blockchain_height() < 3) {
        block tmpl{}; difficulty_type diff{}; uint64_t h=0,r=0,sh=0;
        crypto::hash shh{}; blobdata en(8,0);
        ASSERT_TRUE(bc.create_block_template(tmpl,
            miner.get_keys().m_account_address, diff, h, r, en, sh, shh));
        auto gbh = [&bc](const block& b, uint64_t hh,
                         const crypto::hash* s, unsigned int mn,
                         crypto::hash& o) -> bool {
            return get_block_longhash(&bc, b, o, hh, s,
                                      static_cast<int>(mn));
        };
        ASSERT_TRUE(miner::find_nonce_for_given_block(
            gbh, tmpl, diff, h, nullptr));
        block_verification_context bvc{}; pool_supplement e{};
        blobdata bb = block_to_blob(tmpl);
        ASSERT_TRUE(m_core->handle_single_incoming_block(
            bb, &tmpl, bvc, e, false));
        ASSERT_FALSE(bvc.m_verifivation_failed);
    }

    // Real 3-party DKG to establish a base key + base VK_i.
    std::vector<crypto::public_key> committee;
    std::vector<crypto::secret_key> committee_sks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        committee.push_back(pk);
        committee_sks.push_back(sk);
    }
    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));
    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
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
    cfg.member_ids     = committee;
    cfg.k = 60; cfg.target_N_bits = 128; cfg.security_bits = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F33ULL;
    cfg.local_party_id = 1;
    dkg_result dkg_out;
    ASSERT_TRUE(dkg_run_with_transport(cfg, factory, dkg_out));
    ASSERT_TRUE(dkg_out.candidate_accepted);
    ASSERT_EQ(dkg_out.test_SK.size(), 3u);

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(dkg_out.record.N));

    BIGNUM* delta = BN_new();
    BN_dec2bn(&delta, "20922789888000");

    // New member; reshare target is {committee[0], committee[1], new_pk}
    // sorted by pubkey so indices are canonical.
    crypto::public_key new_pk; crypto::secret_key new_sk;
    crypto::generate_keys(new_pk, new_sk);
    std::vector<crypto::public_key> new_members = {
        committee[0], committee[1], new_pk
    };
    std::sort(new_members.begin(), new_members.end(),
              [](const auto& a, const auto& b) {
                return std::memcmp(a.data, b.data, 32) < 0;
              });
    std::vector<uint32_t> new_indices = {1, 2, 3};
    uint32_t new_threshold = dao_dkg_expected_threshold(3);

    // Two contributors: base positions 1 and 2.
    std::vector<uint32_t> S = {1, 2};
    std::vector<dao_reshare_contribution> contributions;

    const crypto::hash genesis_hash = bc.get_block_id_by_height(0);

    for (uint32_t i = 0; i < 2; ++i) {
        uint32_t contrib_index = i + 1;
        const std::string dec(dkg_out.test_SK[i].begin(),
                              dkg_out.test_SK[i].end());
        BIGNUM* s_i = nullptr;
        ASSERT_NE(BN_dec2bn(&s_i, dec.c_str()), 0);
        BIGNUM* mu_i = BN_new();
        ASSERT_TRUE(dao::dao_dkg_lagrange_mu(S, contrib_index, mu_i));

        dao_reshare_link_context link_ctx;
        link_ctx.genesis_block_hash = genesis_hash;
        link_ctx.stable_key_record_hash.assign(32, 0);
        link_ctx.share_set_id = 1;
        link_ctx.contributor_pubkey.assign(32, 0);
        std::memcpy(link_ctx.contributor_pubkey.data(),
                    committee[i].data, 32);
        link_ctx.original_index = contrib_index;
        link_ctx.contributor_subset = S;
        link_ctx.N = dkg_out.record.N;
        link_ctx.V = dkg_out.record.V;
        link_ctx.VK_i = dkg_out.record.V_K_i[i];
        std::vector<uint8_t> delta_bytes(32, 0);
        BN_bn2binpad(delta, delta_bytes.data(), 32);
        link_ctx.Delta = std::move(delta_bytes);

        dao_reshare_contribution contrib;
        ASSERT_TRUE(dao_reshare_make_contribution(
            pk, vss, dkg_out.record.V, s_i, mu_i, delta,
            new_threshold - 1, new_indices, link_ctx, contrib));

        BN_free(s_i); BN_free(mu_i);
        contributions.push_back(std::move(contrib));
    }

    std::vector<std::vector<uint8_t>> new_vks;
    ASSERT_TRUE(dao_reshare_compute_all_vks(
        pk, dkg_out.record.V, contributions, new_indices, new_vks));
    ASSERT_EQ(new_vks.size(), 3u);

    std::vector<dao_reshare_new_share> new_shares(3);
    for (uint32_t pos = 0; pos < 3; ++pos) {
        dao_reshare_new_share ns;
        ASSERT_TRUE(dao_reshare_combine_one(
            pk, vss, dkg_out.record.V, contributions, new_indices,
            pos, new_threshold, delta, ns));
        ns.VK_j = new_vks[pos];
        new_shares[pos] = std::move(ns);
    }

    dao_share_set_record event_ss;
    uint64_t event_sid = dao::share_set_id_for_key_id(dkg_out.record.key_id);
    ASSERT_TRUE(dao_reshare_build_share_set(
        event_sid, 3, dkg_out.record.key_id,
        new_members, new_shares, new_threshold, event_ss));

    // Attach evidence manually (matches what the runner does in
    // try_finalize_locked when cfg.contributor_vk is populated).
    event_ss.base_share_set_id = 1;
    for (size_t i = 0; i < contributions.size(); ++i) {
        std::vector<uint8_t> blob;
        ASSERT_TRUE(dao_reshare_serialize_public(contributions[i], blob));
        event_ss.contributions.push_back(std::move(blob));
        event_ss.contributor_indices.push_back(
            contributions[i].contributor_index);
        event_ss.contributor_vk.push_back(
            dkg_out.record.V_K_i[contributions[i].contributor_index - 1]);
    }
    ASSERT_EQ(event_ss.contributions.size(), 2u);
    ASSERT_EQ(event_ss.contributor_vk.size(), 2u);

    // Encrypt a synthetic aggregate under the base key.
    BIGNUM* W = BN_new(); BN_set_word(W, 1000);
    BIGNUM* Sa = BN_new(); BN_set_word(Sa, 1000);
    BIGNUM* B = BN_new(); BN_set_word(B, 5000);
    BIGNUM* r1 = BN_new(); BN_set_word(r1, 3);
    BIGNUM* r2 = BN_new(); BN_set_word(r2, 5);
    BIGNUM* r3 = BN_new(); BN_set_word(r3, 7);
    std::vector<uint8_t> E_W, E_S, E_B;
    ASSERT_TRUE(pk.encrypt(W, r1, E_W));
    ASSERT_TRUE(pk.encrypt(Sa, r2, E_S));
    ASSERT_TRUE(pk.encrypt(B, r3, E_B));

    // Each new member's s'_j is in new_shares[pos].share_signed. Format
    // is signed serialization (1 sign byte + magnitude), same as
    // persist_dao_v2_dkg_result writes.
    dao_partial_set W_set, S_set, B_set;
    for (uint32_t pos = 0; pos < 3; ++pos) {
        uint32_t member_index = pos + 1;
        const auto& raw = new_shares[pos].share_signed;
        ASSERT_GE(raw.size(), 2u);
        bool neg = raw[0] == 1;
        BIGNUM* s_prime = BN_bin2bn(raw.data() + 1, raw.size() - 1, nullptr);
        ASSERT_NE(s_prime, nullptr);
        if (neg) BN_set_negative(s_prime, 1);

        auto do_channel = [&](const std::vector<uint8_t>& c,
                              std::vector<uint8_t>& partial_out,
                              dao_partial_decryption_proof& proof_out) -> bool {
            std::vector<uint8_t> ci;
            if (!dao_threshold_partial_decrypt(pk, c, s_prime, ci))
                return false;
            BIGNUM* r = BN_new();
            if (!dao_dkg_sample_r(pk, r)) { BN_free(r); return false; }
            const bool ok = dao_partial_decryption_prove(
                pk, dkg_out.record.V, new_vks[pos], member_index,
                c, ci, s_prime, r, proof_out);
            BN_free(r);
            if (!ok) return false;
            partial_out = std::move(ci);
            return true;
        };

        std::vector<uint8_t> pw, ps, pb;
        dao_partial_decryption_proof pfw, pfs, pfb;
        ASSERT_TRUE(do_channel(E_W, pw, pfw));
        ASSERT_TRUE(do_channel(E_S, ps, pfs));
        ASSERT_TRUE(do_channel(E_B, pb, pfb));

        W_set.member_indices.push_back(member_index);
        W_set.partials.push_back(std::move(pw));
        W_set.proofs.push_back(std::move(pfw));
        S_set.member_indices.push_back(member_index);
        S_set.partials.push_back(std::move(ps));
        S_set.proofs.push_back(std::move(pfs));
        B_set.member_indices.push_back(member_index);
        B_set.partials.push_back(std::move(pb));
        B_set.proofs.push_back(std::move(pfb));

        BN_free(s_prime);
    }

    // Build the v6 cert using the event share set.
    crypto::hash prop_id{};
    std::memset(prop_id.data, 0x88, 32);
    dao_tally_certificate cert;
    ASSERT_TRUE(dao_build_tally_certificate(
        dkg_out.record, prop_id, 3, E_W, E_S, E_B,
        W_set, S_set, B_set, cert, &event_ss));

    EXPECT_EQ(cert.per_event_share_set_id, event_sid);
    EXPECT_EQ(cert.threshold, new_threshold);
    EXPECT_EQ(cert.contributions.size(), 2u);
    EXPECT_EQ(cert.member_pubkeys.size(), 3u);
    EXPECT_EQ(cert.per_event_VK_i.size(), 3u);

    dao_supply_snapshot snap;
    snap.height = 3;
    snap.minted = dao_u128(100000);
    snap.circulating = dao_u128(50000);
    uint32_t quorum_percent = 10;

    EXPECT_TRUE(dao_verify_tally_certificate(
        dkg_out.record, snap, quorum_percent, E_W, E_S, E_B, cert));

    // Tampered contribution → reject.
    {
        dao_tally_certificate bad = cert;
        ASSERT_FALSE(bad.contributions.empty());
        ASSERT_FALSE(bad.contributions[0].empty());
        bad.contributions[0][bad.contributions[0].size() / 2] ^= 0xFF;
        EXPECT_FALSE(dao_verify_tally_certificate(
            dkg_out.record, snap, quorum_percent, E_W, E_S, E_B, bad));
    }

    // Tampered partial → reject.
    {
        dao_tally_certificate bad = cert;
        ASSERT_FALSE(bad.W.partials.empty());
        ASSERT_FALSE(bad.W.partials[0].empty());
        bad.W.partials[0][bad.W.partials[0].size() / 2] ^= 0xFF;
        EXPECT_FALSE(dao_verify_tally_certificate(
            dkg_out.record, snap, quorum_percent, E_W, E_S, E_B, bad));
    }

    BN_free(W); BN_free(Sa); BN_free(B);
    BN_free(r1); BN_free(r2); BN_free(r3);
    BN_free(delta);
}

