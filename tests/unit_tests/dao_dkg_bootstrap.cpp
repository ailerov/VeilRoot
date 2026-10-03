// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Bootstrap composition test. Exercises the production pieces that sit
// between the eligible-records table and the persisted tally-key
// record, without constructing a full Blockchain:
//
//   BlockchainDB eligible records
//     -> select_dao_v2_committee (real production selector)
//     -> real node identities and committee indices
//     -> real dkg_p2p_runner over an in-process test transport
//     -> persist_dao_v2_dkg_result (real persistence)
//
// Asserts identical public key records across all three nodes and
// distinct local secret shares under the correct member indices.

#include <boost/filesystem.hpp>

#include "gtest/gtest.h"

#include <array>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "crypto/crypto.h"
#include "cryptonote_core/blockchain.h"
#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

// In-process routing network. Broadcasts go from sender to every other
// registered runner; the sender's own copy is provided by the runner's
// own_queue in the transport, not here.
struct routed_network
{
    std::mutex mu;
    std::map<crypto::public_key, dkg_p2p_runner*> runners_by_pk;
    std::map<uint32_t, dkg_p2p_runner*>          runners_by_id;

    void register_runner(uint32_t id,
                         const crypto::public_key& pk,
                         dkg_p2p_runner* r)
    {
        std::lock_guard<std::mutex> lk(mu);
        runners_by_id.emplace(id, r);
        runners_by_pk.emplace(pk, r);
    }

    dkg_p2p_callbacks callbacks_for_self()
    {
        dkg_p2p_callbacks cb;
        cb.send_to = [this](const crypto::public_key& to,
                            const std::string& payload) -> bool {
            dkg_p2p_runner* target = nullptr;
            {
                std::lock_guard<std::mutex> lk(mu);
                auto it = runners_by_pk.find(to);
                if (it == runners_by_pk.end()) return false;
                target = it->second;
            }
            dkg_msg m;
            std::vector<uint8_t> buf(payload.begin(), payload.end());
            if (!m.deserialize(buf)) return false;
            target->on_message(m);
            return true;
        };
        cb.broadcast = [this](const std::string& payload) {
            dkg_msg m;
            std::vector<uint8_t> buf(payload.begin(), payload.end());
            if (!m.deserialize(buf)) return;

            std::vector<dkg_p2p_runner*> targets;
            {
                std::lock_guard<std::mutex> lk(mu);
                for (const auto& [id, runner] : runners_by_id)
                    if (id != m.hdr.sender_id)
                        targets.push_back(runner);
            }
            for (auto* t : targets) t->on_message(m);
        };
        return cb;
    }
};

constexpr uint64_t FIXED_TEST_CANDIDATE_SEED_3 = 0x5645494C52544F33ULL;

void install_eligible(BlockchainDB& db,
                      const crypto::public_key& pk,
                      uint64_t weight,
                      uint8_t kidx)
{
    committee_eligible_record rec{};
    rec.node_pubkey = pk;
    rec.amount = 1000000;
    rec.unlock_height = 1;
    rec.stake_age_weight = weight;

    crypto::key_image ki{};
    std::memset(ki.data, 0, sizeof(ki.data));
    ki.data[0] = kidx;

    db_wtxn_guard g(&db);
    db.add_committee_eligible(ki, rec);
}

} // namespace

class DaoV2Bootstrap : public ::testing::Test
{
protected:
    std::vector<std::string>                 m_dirs;
    std::vector<std::unique_ptr<BlockchainLMDB>> m_dbs;
    std::vector<crypto::secret_key>          m_priv;
    std::vector<crypto::public_key>          m_pub;

    void SetUp() override
    {
        for (int i = 0; i < 3; ++i) {
            boost::filesystem::path tmp =
                boost::filesystem::temp_directory_path() /
                boost::filesystem::unique_path("vr_dkg_boot_%%%%-%%%%");
            m_dirs.push_back(tmp.string());
            boost::filesystem::create_directories(tmp);

            auto db = std::make_unique<BlockchainLMDB>();
            db->open(tmp.string());
            m_dbs.push_back(std::move(db));

            crypto::public_key pub;
            crypto::secret_key sec;
            crypto::generate_keys(pub, sec);
            m_pub.push_back(pub);
            m_priv.push_back(sec);
        }
    }

    void TearDown() override
    {
        for (auto& db : m_dbs) {
            try { db->close(); } catch (...) {}
        }
        m_dbs.clear();
        for (const auto& d : m_dirs)
            boost::filesystem::remove_all(d);
    }
};

TEST_F(DaoV2Bootstrap, ThreeEligibleNodesSelectAndComplete2of3DKG)
{
    // Same three eligible records in every DB, distinct weights so
    // committee order is unambiguous even without the tie-break.
    for (auto& db : m_dbs) {
        install_eligible(*db, m_pub[0], 3000000, 1);
        install_eligible(*db, m_pub[1], 2000000, 2);
        install_eligible(*db, m_pub[2], 1000000, 3);
    }

    // Real selector: same ordered committee from every DB.
    std::vector<crypto::public_key> expected;
    for (size_t i = 0; i < 3; ++i) {
        auto sel = dao::select_dao_v2_committee(*m_dbs[i], 3);
        ASSERT_EQ(sel.size(), 3u);
        std::vector<crypto::public_key> committee;
        for (const auto& [pk, w] : sel) committee.push_back(pk);
        if (i == 0) expected = committee;
        else        EXPECT_EQ(committee, expected);
    }
    EXPECT_EQ(expected[0], m_pub[0]);
    EXPECT_EQ(expected[1], m_pub[1]);
    EXPECT_EQ(expected[2], m_pub[2]);

    // Committee indices match node identity order.
    for (size_t i = 0; i < 3; ++i)
        EXPECT_EQ(dao::dao_dkg_party_index_for(expected, m_pub[i]),
                  static_cast<uint32_t>(i + 1));

    // VSS group: production derivation, shared by every node.
    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));

    routed_network net;

    std::vector<std::unique_ptr<dkg_p2p_runner>> runners;
    for (uint32_t i = 0; i < 3; ++i) {
        dkg_config cfg;
        cfg.committee_size = 3;
        cfg.threshold      = dao_dkg_expected_threshold(3);
        cfg.epoch          = 1;
        cfg.member_ids     = expected;
        cfg.local_party_id = i + 1;
        cfg.test_seed      = FIXED_TEST_CANDIDATE_SEED_3;
        cfg.target_N_bits  = 128;
        cfg.phase_timeout_seconds = 30;

        auto cb = net.callbacks_for_self();
        runners.emplace_back(new dkg_p2p_runner(cfg, vss, cb));
    }
    for (uint32_t i = 0; i < 3; ++i)
        net.register_runner(i + 1, expected[i], runners[i].get());

    for (auto& r : runners) ASSERT_TRUE(r->start());

    std::vector<dkg_result> results(3);
    for (uint32_t i = 0; i < 3; ++i) {
        ASSERT_TRUE(runners[i]->wait(results[i], 60));
        ASSERT_TRUE(results[i].ok);
    }

    // Persist via the production helper. Caller owns the write
    // transaction, mirroring the owner-thread discipline.
    for (uint32_t i = 0; i < 3; ++i) {
        db_wtxn_guard wtxn(m_dbs[i].get());
        ASSERT_TRUE(dao::persist_dao_v2_dkg_result(
            *m_dbs[i], 1, results[i], i + 1));
    }

    // Compare public key records across DBs.
    std::vector<dao_tally_key_record> recs(3);
    for (uint32_t i = 0; i < 3; ++i)
        ASSERT_TRUE(m_dbs[i]->get_dao_tally_key(1, recs[i]));

    for (uint32_t i = 1; i < 3; ++i) {
        EXPECT_EQ(recs[0].committee_id_hash, recs[i].committee_id_hash);
        EXPECT_EQ(recs[0].committee_members, recs[i].committee_members);
        EXPECT_EQ(recs[0].N,     recs[i].N);
        EXPECT_EQ(recs[0].G,     recs[i].G);
        EXPECT_EQ(recs[0].theta, recs[i].theta);
        EXPECT_EQ(recs[0].delta, recs[i].delta);
        EXPECT_EQ(recs[0].V,     recs[i].V);
        EXPECT_EQ(recs[0].V_K_i, recs[i].V_K_i);
        EXPECT_EQ(recs[0].vss_P,       recs[i].vss_P);
        EXPECT_EQ(recs[0].vss_P_prime, recs[i].vss_P_prime);
        EXPECT_EQ(recs[0].vss_g,       recs[i].vss_g);
        EXPECT_EQ(recs[0].vss_h,       recs[i].vss_h);
        EXPECT_EQ(recs[0].dkg_transcript_hash, recs[i].dkg_transcript_hash);
        EXPECT_EQ(recs[0].key_id, recs[i].key_id);
    }

    for (uint32_t i = 0; i < 3; ++i) {
        EXPECT_EQ(recs[i].committee_size, 3u);
        EXPECT_EQ(recs[i].threshold, 2u);
        EXPECT_EQ(recs[i].t, 1u);
        EXPECT_EQ(recs[i].committee_members.size(), 3u);
    }

    // Local shares: distinct, correct index.
    std::vector<std::vector<uint8_t>> shares(3);
    for (uint32_t i = 0; i < 3; ++i)
        ASSERT_TRUE(m_dbs[i]->get_dao_local_share(1, i + 1, shares[i]));

    EXPECT_NE(shares[0], shares[1]);
    EXPECT_NE(shares[1], shares[2]);
    EXPECT_NE(shares[0], shares[2]);

    // Serializer round-trip on the persisted bytes.
    for (const auto& rec : recs) {
        std::vector<uint8_t> enc;
        ASSERT_TRUE(rec.serialize(enc));
        dao_tally_key_record decoded;
        ASSERT_TRUE(decoded.deserialize(enc));
        std::vector<uint8_t> enc2;
        ASSERT_TRUE(decoded.serialize(enc2));
        EXPECT_EQ(enc, enc2);
    }
}

TEST_F(DaoV2Bootstrap, RepeatedWaitReturnsSameResult)
{
    for (auto& db : m_dbs) {
        install_eligible(*db, m_pub[0], 3000000, 1);
        install_eligible(*db, m_pub[1], 2000000, 2);
        install_eligible(*db, m_pub[2], 1000000, 3);
    }

    auto sel = dao::select_dao_v2_committee(*m_dbs[0], 3);
    std::vector<crypto::public_key> committee;
    for (const auto& [pk, w] : sel) committee.push_back(pk);

    dao_vss_group vss;
    ASSERT_TRUE(dao_vss_group_generate(vss,
        dao_dkg_required_vss_bits(60, 128, 32)));

    routed_network net;
    std::vector<std::unique_ptr<dkg_p2p_runner>> runners;
    for (uint32_t i = 0; i < 3; ++i) {
        dkg_config cfg;
        cfg.committee_size = 3;
        cfg.threshold      = dao_dkg_expected_threshold(3);
        cfg.epoch          = 1;
        cfg.member_ids     = committee;
        cfg.local_party_id = i + 1;
        cfg.test_seed      = FIXED_TEST_CANDIDATE_SEED_3;
        cfg.target_N_bits  = 128;
        cfg.phase_timeout_seconds = 30;
        auto cb = net.callbacks_for_self();
        runners.emplace_back(new dkg_p2p_runner(cfg, vss, cb));
    }
    for (uint32_t i = 0; i < 3; ++i)
        net.register_runner(i + 1, committee[i], runners[i].get());
    for (auto& r : runners) ASSERT_TRUE(r->start());

    for (auto& r : runners) {
        dkg_result first;
        ASSERT_TRUE(r->wait(first, 60));
        ASSERT_TRUE(first.ok);

        dkg_result second;
        ASSERT_TRUE(r->wait(second, 0));
        ASSERT_TRUE(second.ok);

        EXPECT_EQ(first.N, second.N);
        EXPECT_EQ(first.theta, second.theta);
        EXPECT_EQ(first.V, second.V);
        EXPECT_EQ(first.V_K_i, second.V_K_i);
        EXPECT_EQ(first.record.V_K_i, second.record.V_K_i);
        EXPECT_EQ(first.record.key_id, second.record.key_id);
        EXPECT_EQ(first.local_secret_share, second.local_secret_share);
    }
}

TEST_F(DaoV2Bootstrap, PersistentCommitteeIdentitySurvivesRestart)
{
    for (uint32_t i = 0; i < 3; ++i)
        m_dbs[i]->set_committee_privkey(m_priv[i]);

    // Close and reopen.
    for (auto& db : m_dbs) { db->close(); }

    for (uint32_t i = 0; i < 3; ++i) {
        m_dbs[i]->open(m_dirs[i]);
        crypto::secret_key recovered_sec;
        ASSERT_TRUE(m_dbs[i]->get_committee_privkey(recovered_sec));
        crypto::public_key recovered_pub;
        ASSERT_TRUE(crypto::secret_key_to_public_key(recovered_sec,
                                                     recovered_pub));
        EXPECT_EQ(recovered_pub, m_pub[i]);
    }
}

TEST_F(DaoV2Bootstrap, CommitteeSelectionIsDeterministicOnEqualWeights)
{
    // All three records have the same weight. The tie-break on the
    // public key must still produce the same committee order on every
    // DB.
    for (auto& db : m_dbs) {
        install_eligible(*db, m_pub[0], 1000000, 1);
        install_eligible(*db, m_pub[1], 1000000, 2);
        install_eligible(*db, m_pub[2], 1000000, 3);
    }

    std::vector<std::vector<crypto::public_key>> committees;
    for (auto& db : m_dbs) {
        auto sel = dao::select_dao_v2_committee(*db, 3);
        ASSERT_EQ(sel.size(), 3u);
        std::vector<crypto::public_key> c;
        for (const auto& [pk, w] : sel) c.push_back(pk);
        committees.push_back(std::move(c));
    }

    EXPECT_EQ(committees[0], committees[1]);
    EXPECT_EQ(committees[1], committees[2]);

    // And the order is by public key ascending.
    EXPECT_TRUE(std::memcmp(committees[0][0].data, committees[0][1].data,
                            sizeof(committees[0][0].data)) < 0);
    EXPECT_TRUE(std::memcmp(committees[0][1].data, committees[0][2].data,
                            sizeof(committees[0][1].data)) < 0);
}
