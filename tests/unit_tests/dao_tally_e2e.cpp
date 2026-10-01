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
