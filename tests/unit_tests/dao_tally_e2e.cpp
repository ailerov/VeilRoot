// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Full V2 tally pipeline at the live 3-node committee size.
//   3-party DKG (2-of-3) -> encrypt W/S/B -> per-member partial
//   decryption + proof -> certificate build -> independent verify.
//
// Also proves that participation coins (B) and voting weight (W/S)
// decide different conditions and are never substituted for one
// another, using real ciphertexts.

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include <openssl/bn.h>
#include <openssl/rand.h>

#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_paillier.h"
#include "governance/dao_supply.h"
#include "governance/dao_tally.h"
#include "governance/dao_tally_session_cycle.h"
#include "governance/tally_manager.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "blockchain_db/blockchain_db.h"
#include "governance/governance_db.h"
#include "cryptonote_core/blockchain.h"
#include <boost/filesystem.hpp>

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

std::vector<crypto::public_key> e2e_member_ids(uint32_t n)
{
    std::vector<crypto::public_key> ids;
    ids.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        crypto::public_key pk{};
        for (int k = 0; k < 32; ++k)
            pk.data[k] = static_cast<uint8_t>((i + 1) * 17 + k);
        ids.push_back(pk);
    }
    return ids;
}

// Run the 3-party DKG and return its result.
bool run_three_party_dkg(dkg_result& out)
{
    constexpr uint64_t FIXED_SEED_3 = 0x5645494C52544F33ULL;

    dkg_config cfg;
    cfg.committee_size = 3;
    cfg.threshold      = 2;
    cfg.member_ids     = e2e_member_ids(3);
    cfg.epoch          = 1;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = 32;
    cfg.max_attempts   = 1;
    cfg.test_seed      = FIXED_SEED_3;

    auto net = dkg_make_inproc_network(cfg.committee_size, nullptr);

    std::vector<std::unique_ptr<dkg_transport>> pool;
    for (auto& e : net.endpoints) pool.push_back(std::move(e));

    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };

    dkg_run_with_transport(cfg, factory, out);
    return out.ok && out.candidate_accepted;
}

// Build a partial set for one aggregate with all committee members.
dao_partial_set build_partial_set(
    const PaillierPublicKey& pk,
    const dao_tally_key_record& key_rec,
    const std::vector<BIGNUM*>& sk_all,
    const std::vector<uint8_t>& c)
{
    dao_partial_set s;
    for (uint32_t m = 1; m <= key_rec.committee_size; ++m) {
        std::vector<uint8_t> ci;
        if (!dao_threshold_partial_decrypt(pk, c, sk_all[m - 1], ci))
            return {};

        BIGNUM* r = BN_new();
        if (!dao_dkg_sample_r(pk, r)) { BN_free(r); return {}; }

        dao_partial_decryption_proof proof;
        if (!dao_partial_decryption_prove(pk, key_rec.V, key_rec.V_K_i[m - 1],
                                          m, c, ci, sk_all[m - 1], r, proof)) {
            BN_free(r);
            return {};
        }
        BN_free(r);

        s.member_indices.push_back(m);
        s.partials.push_back(std::move(ci));
        s.proofs.push_back(std::move(proof));
    }
    return s;
}

} // namespace

TEST(dao_tally_e2e, three_party_quorum_and_majority)
{
    dkg_result out;
    ASSERT_TRUE(run_three_party_dkg(out));
    ASSERT_EQ(out.record.committee_size, 3u);
    ASSERT_EQ(out.record.threshold, 2u);
    ASSERT_EQ(out.record.V_K_i.size(), 3u);
    ASSERT_EQ(out.test_SK.size(), 3u);

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));

    // Parse shares.
    std::vector<BIGNUM*> sk_all(3, nullptr);
    for (size_t j = 0; j < 3; ++j) {
        const std::string dec(out.test_SK[j].begin(), out.test_SK[j].end());
        ASSERT_EQ(BN_dec2bn(&sk_all[j], dec.c_str()),
                  static_cast<int>(dec.size()));
        ASSERT_NE(sk_all[j], nullptr);
    }

    // Encrypt W=1000, S=1000, B=5000.
    BIGNUM* W_bn = BN_new(); BN_set_word(W_bn, 1000);
    BIGNUM* S_bn = BN_new(); BN_set_word(S_bn, 1000);
    BIGNUM* B_bn = BN_new(); BN_set_word(B_bn, 5000);
    BIGNUM* r_W  = BN_new(); BN_set_word(r_W, 3);
    BIGNUM* r_S  = BN_new(); BN_set_word(r_S, 5);
    BIGNUM* r_B  = BN_new(); BN_set_word(r_B, 7);

    std::vector<uint8_t> E_W, E_S, E_B;
    ASSERT_TRUE(pk.encrypt(W_bn, r_W, E_W));
    ASSERT_TRUE(pk.encrypt(S_bn, r_S, E_S));
    ASSERT_TRUE(pk.encrypt(B_bn, r_B, E_B));

    dao_partial_set W_set = build_partial_set(pk, out.record, sk_all, E_W);
    dao_partial_set S_set = build_partial_set(pk, out.record, sk_all, E_S);
    dao_partial_set B_set = build_partial_set(pk, out.record, sk_all, E_B);

    ASSERT_EQ(W_set.member_indices.size(), 3u);
    ASSERT_EQ(S_set.member_indices.size(), 3u);
    ASSERT_EQ(B_set.member_indices.size(), 3u);

    crypto::hash prop_id{};
    std::memset(prop_id.data, 0x33, 32);
    constexpr uint64_t VOTE_END_HEIGHT = 60000;

    dao_tally_certificate cert;
    ASSERT_TRUE(dao_build_tally_certificate(
        out.record, prop_id, VOTE_END_HEIGHT,
        E_W, E_S, E_B, W_set, S_set, B_set, cert));

    EXPECT_EQ(cert.W_total, dao_u128(1000));
    EXPECT_FALSE(cert.s_negative);
    EXPECT_EQ(cert.S_abs, dao_u128(1000));
    EXPECT_EQ(cert.B_total, dao_u128(5000));

    // Fabricated historical supply snapshot.
    dao_supply_snapshot snap;
    snap.height      = VOTE_END_HEIGHT;
    snap.minted      = dao_u128(200000);
    snap.treasury    = dao_u128(50000);
    snap.burned      = dao_u128(50000);
    snap.circulating = dao_u128(100000);

    ASSERT_TRUE(dao_verify_tally_certificate(
        out.record, snap, 10, E_W, E_S, E_B, cert));

    // Threshold = 10000. B = 5000 -> quorum fails. YES=1000 > NO=0.
    EXPECT_EQ(cert.YES_weight, dao_u128(1000));
    EXPECT_EQ(cert.NO_weight,  dao_u128(0));
    EXPECT_EQ(cert.quorum_threshold, dao_u128(10000));
    EXPECT_FALSE(cert.quorum_met);
    EXPECT_TRUE(cert.majority_met);
    EXPECT_FALSE(cert.passed);

    // Tamper: change B plaintext (re-encrypt) -> certificate hash mismatch.
    {
        BIGNUM* B2 = BN_new(); BN_set_word(B2, 99999);
        BIGNUM* r2 = BN_new(); BN_set_word(r2, 11);
        std::vector<uint8_t> E_B_bad;
        ASSERT_TRUE(pk.encrypt(B2, r2, E_B_bad));
        EXPECT_FALSE(dao_verify_tally_certificate(
            out.record, snap, 10, E_W, E_S, E_B_bad, cert));
        BN_free(B2); BN_free(r2);
    }

    for (auto* x : sk_all) if (x) BN_free(x);
    BN_free(W_bn); BN_free(S_bn); BN_free(B_bn);
    BN_free(r_W);  BN_free(r_S);  BN_free(r_B);
}

TEST(dao_tally_e2e, large_W_small_B_passes_majority_fails_quorum)
{
    dkg_result out;
    ASSERT_TRUE(run_three_party_dkg(out));

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));

    std::vector<BIGNUM*> sk_all(3, nullptr);
    for (size_t j = 0; j < 3; ++j) {
        const std::string dec(out.test_SK[j].begin(), out.test_SK[j].end());
        ASSERT_EQ(BN_dec2bn(&sk_all[j], dec.c_str()),
                  static_cast<int>(dec.size()));
    }

    // W=100000, S=100000 (YES=100000, NO=0), B=100 (well under 10% of 100000).
    BIGNUM* W_bn = BN_new(); BN_set_word(W_bn, 100000);
    BIGNUM* S_bn = BN_new(); BN_set_word(S_bn, 100000);
    BIGNUM* B_bn = BN_new(); BN_set_word(B_bn, 100);
    BIGNUM* r1   = BN_new(); BN_set_word(r1, 3);
    BIGNUM* r2   = BN_new(); BN_set_word(r2, 5);
    BIGNUM* r3   = BN_new(); BN_set_word(r3, 7);

    std::vector<uint8_t> E_W, E_S, E_B;
    ASSERT_TRUE(pk.encrypt(W_bn, r1, E_W));
    ASSERT_TRUE(pk.encrypt(S_bn, r2, E_S));
    ASSERT_TRUE(pk.encrypt(B_bn, r3, E_B));

    dao_partial_set W_set = build_partial_set(pk, out.record, sk_all, E_W);
    dao_partial_set S_set = build_partial_set(pk, out.record, sk_all, E_S);
    dao_partial_set B_set = build_partial_set(pk, out.record, sk_all, E_B);

    crypto::hash prop_id{}; std::memset(prop_id.data, 0x44, 32);
    dao_tally_certificate cert;
    ASSERT_TRUE(dao_build_tally_certificate(
        out.record, prop_id, 60000,
        E_W, E_S, E_B, W_set, S_set, B_set, cert));

    dao_supply_snapshot snap;
    snap.height      = 60000;
    snap.circulating = dao_u128(100000);

    ASSERT_TRUE(dao_verify_tally_certificate(
        out.record, snap, 10, E_W, E_S, E_B, cert));

    EXPECT_EQ(cert.quorum_threshold, dao_u128(10000));
    EXPECT_FALSE(cert.quorum_met);
    EXPECT_TRUE(cert.majority_met);
    EXPECT_FALSE(cert.passed);

    for (auto* x : sk_all) if (x) BN_free(x);
    BN_free(W_bn); BN_free(S_bn); BN_free(B_bn);
    BN_free(r1); BN_free(r2); BN_free(r3);
}

// ====================================================================
// TallyManager: the automatic-tally engine, driven by a single call.
//
// Proves the entire state machine end-to-end against a real LMDB:
//   - three committee members produce signed partial decryptions,
//   - TallyManager::try_finalize combines them,
//   - the outcome record and proposal status are written to consensus
//     state automatically, with no user action and no certificate
//     transaction.
// ====================================================================

TEST(dao_tally_e2e, tally_manager_finalizes_automatically)
{
    namespace fs = boost::filesystem;

    dkg_result out;
    ASSERT_TRUE(run_three_party_dkg(out));

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));
    ASSERT_EQ(out.record.committee_size, 3u);
    ASSERT_EQ(out.record.threshold, 2u);
    ASSERT_EQ(out.record.committee_members.size(), 3u);
    ASSERT_EQ(out.record.V_K_i.size(), 3u);
    ASSERT_EQ(out.test_SK.size(), 3u);

    // Aggregate ciphertexts: W = 1000, S = 1000 (all YES), B = 5000.
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
    const crypto::hash agg_hash = dao_aggregate_ciphertext_hash(E_W, E_S, E_B);

    crypto::hash prop_id{}; std::memset(prop_id.data, 0x55, 32);
    constexpr uint64_t VOTE_END = 60000;

    // Parse SK_i.
    std::vector<BIGNUM*> sk_all(3, nullptr);
    for (size_t j = 0; j < 3; ++j) {
        const std::string dec(out.test_SK[j].begin(), out.test_SK[j].end());
        ASSERT_EQ(BN_dec2bn(&sk_all[j], dec.c_str()),
                  static_cast<int>(dec.size()));
    }

    // Build shares for all three members.
    std::map<crypto::public_key, dao_v2_tally_share> shares;
    for (uint32_t m = 1; m <= 3; ++m) {
        dao_v2_tally_share sh;
        sh.version = 1;
        sh.proposal_id = prop_id;
        sh.vote_end_height = VOTE_END;
        sh.tally_key_epoch = 1;
        sh.share_epoch     = static_cast<uint32_t>(VOTE_END);
        std::memset(sh.reset_transcript_hash.data, 0xAB, 32);
        sh.member_index = m;
        sh.aggregate_ciphertext_hash = agg_hash;

        auto do_channel = [&](const std::vector<uint8_t>& c,
                              std::vector<uint8_t>& p_out,
                              dao_partial_decryption_proof& proof_out) -> bool {
            std::vector<uint8_t> ci;
            if (!dao_threshold_partial_decrypt(pk, c, sk_all[m-1], ci))
                return false;
            BIGNUM* r = BN_new();
            if (!dao_dkg_sample_r(pk, r)) { BN_free(r); return false; }
            const bool ok = dao_partial_decryption_prove(
                pk, out.record.V, out.record.V_K_i[m-1], m,
                c, ci, sk_all[m-1], r, proof_out);
            BN_free(r);
            if (!ok) return false;
            p_out = std::move(ci);
            return true;
        };
        ASSERT_TRUE(do_channel(E_W, sh.partial_W, sh.proof_W));
        ASSERT_TRUE(do_channel(E_S, sh.partial_S, sh.proof_S));
        ASSERT_TRUE(do_channel(E_B, sh.partial_B, sh.proof_B));

        crypto::public_key member;
        std::memcpy(member.data, out.record.committee_members[m-1].data(), 32);
        shares[member] = std::move(sh);
    }

    // Fresh LMDB for this test.
    fs::path tmp = fs::temp_directory_path() /
                   fs::unique_path("vr_tm_test_%%%%-%%%%-%%%%");
    fs::create_directories(tmp.string());
    BlockchainLMDB db;
    db.open(tmp.string());

    {
        db_wtxn_guard g(&db);
        proposal_record rec;
        std::memset(&rec, 0, sizeof(rec));
        rec.proposal_id = prop_id;
        rec.voting_period_days = 7;
        rec.submission_height = VOTE_END - 1000;
        rec.voting_end_height = VOTE_END;
        rec.submission_tx_hash = prop_id;
        rec.status = PROPOSAL_STATUS_ACTIVE;
        rec.tally_key_epoch = 1;
        db.add_proposal_record(prop_id, rec);

        db.add_dao_tally_key(1, out.record);

        // The tally pipeline is driven by the per-proposal session.
        // In this test the session committee is the bootstrap
        // committee (no Reset), so committee_V_K_i == out.record.V_K_i.
        // The reset is marked complete.
        dao_tally_session session;
        session.version              = 1;
        session.share_epoch          = static_cast<uint32_t>(VOTE_END);
        session.proposal_id          = prop_id;
        session.selection_height     = VOTE_END;
        session.vote_end_height      = VOTE_END;
        session.committee_size       = out.record.committee_size;
        session.threshold            = out.record.threshold;
        session.t                    = out.record.t;
        session.committee_V_K_i      = out.record.V_K_i;
        session.resharing_complete   = true;
        session.tally_complete       = false;
        std::memset(session.reset_transcript_hash.data, 0xAB, 32);
        for (const auto& m : out.record.committee_members) {
            crypto::public_key pk_m{};
            std::memcpy(pk_m.data, m.data(), 32);
            session.committee_members.push_back(pk_m);
        }
        db.add_dao_tally_session(prop_id, session);

        dao_proposal_aggregate agg;
        agg.aggregate_E_W = E_W;
        agg.aggregate_E_S = E_S;
        agg.aggregate_E_B = E_B;
        agg.aggregate_C_W = rct::identity();
        agg.aggregate_C_S = rct::identity();
        agg.aggregate_C_B = rct::identity();
        db.add_dao_proposal_aggregate(prop_id, agg);

        dao_supply_snapshot snap;
        snap.height = VOTE_END;
        snap.minted = dao_u128(100000);
        snap.circulating = dao_u128(10000);   // threshold = 1000
        db.add_dao_supply_snapshot(snap);
    }

    // Drive the engine.
    governance_params params = governance_params::default_params();
    TallyManager tm(db, params);

    // First with only two shares: threshold is 2, so this succeeds.
    std::map<crypto::public_key, dao_v2_tally_share> two;
    auto it = shares.begin();
    two[it->first] = it->second; ++it;
    two[it->first] = it->second;

    {
        db_wtxn_guard g(&db);
        ASSERT_TRUE(tm.try_finalize(prop_id, two, VOTE_END + 10));
    }

    // Outcome record written automatically.
    dao_v2_outcome_record outcome;
    ASSERT_TRUE(db.get_dao_v2_outcome(prop_id, outcome));
    EXPECT_TRUE(outcome.passed);
    EXPECT_TRUE(outcome.quorum_met);
    EXPECT_TRUE(outcome.majority_met);
    EXPECT_EQ(outcome.yes_weight, dao_u128(1000));
    EXPECT_EQ(outcome.no_weight, dao_u128(0));
    EXPECT_EQ(outcome.participation_coins, dao_u128(5000));
    EXPECT_EQ(outcome.quorum_threshold, dao_u128(1000));

    // Proposal status updated automatically.
    proposal_record prop_after;
    ASSERT_TRUE(db.get_proposal_record(prop_id, prop_after));
    EXPECT_EQ(prop_after.status, PROPOSAL_STATUS_PASSED);

    // Idempotent: second call is a no-op.
    {
        db_wtxn_guard g(&db);
        ASSERT_TRUE(tm.try_finalize(prop_id, shares, VOTE_END + 100));
    }

    // Cleanup.
    for (auto* x : sk_all) if (x) BN_free(x);
    BN_free(W); BN_free(S); BN_free(B);
    BN_free(r1); BN_free(r2); BN_free(r3);
    db.close();
    fs::remove_all(tmp);
}