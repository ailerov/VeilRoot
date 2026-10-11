// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Signed-integer VSS tests for DAO V2 resharing.
//
// Uses a real Paillier modulus from the DKG harness and verifies:
//   - evaluation verification accepts valid shares;
//   - tampered evaluation rejected;
//   - tampered commitment rejected;
//   - VK_j computed from commitments equals V^(Delta * s'_j) where
//     s'_j is the sum of contributions divided by Delta.

#include "gtest/gtest.h"

#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_paillier.h"
#include "governance/dao_reshare_proof.h"
#include "governance/dao_reshare_vss.h"
#include "crypto/crypto.h"

#include <openssl/bn.h>

#include <memory>
#include <string>
#include <vector>

namespace {

using namespace cryptonote;
using namespace cryptonote::dao;

struct BNFree {
    void operator()(BIGNUM* p) const { if (p) BN_free(p); }
};
using BN_ptr = std::unique_ptr<BIGNUM, BNFree>;

bool run_dkg_3(dkg_result& out)
{
    dao_vss_group vss;
    if (!dao_vss_group_generate(vss,
            dao_dkg_required_vss_bits(60, 128, 32)))
        return false;

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

    std::vector<crypto::public_key> pks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        pks.push_back(pk);
    }

    dkg_config cfg;
    cfg.committee_size = 3;
    cfg.threshold      = dao_dkg_expected_threshold(3);
    cfg.member_ids     = pks;
    cfg.epoch          = 1;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F33ULL;
    cfg.local_party_id = 1;

    return dkg_run_with_transport(cfg, factory, out);
}

BN_ptr bn_from_dec(const std::string& s)
{
    BIGNUM* b = nullptr;
    if (BN_dec2bn(&b, s.c_str()) == 0) {
        if (b) BN_free(b);
        return BN_ptr();
    }
    return BN_ptr(b);
}

bool modexp_signed(const BIGNUM* base, const BIGNUM* exp,
                   const BIGNUM* mod, BIGNUM* out, BN_CTX* ctx)
{
    if (!BN_is_negative(exp))
        return BN_mod_exp(out, base, exp, mod, ctx) == 1;
    BIGNUM* inv = BN_mod_inverse(nullptr, base, mod, ctx);
    if (!inv) return false;
    BIGNUM* pos = BN_dup(exp);
    if (!pos) { BN_free(inv); return false; }
    BN_set_negative(pos, 0);
    const bool ok = BN_mod_exp(out, inv, pos, mod, ctx) == 1;
    BN_free(inv); BN_free(pos);
    return ok;
}

} // namespace

TEST(DaoReshareVss, EvaluationAndVk)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));

    BIGNUM* delta_raw = BN_new();
    ASSERT_NE(delta_raw, nullptr);
    BN_dec2bn(&delta_raw, "20922789888000");
    BN_ptr delta(delta_raw);

    const std::vector<uint32_t> S = {1, 2};
    BN_ptr mu1(BN_new()), mu2(BN_new());
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 1, mu1.get()));
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 2, mu2.get()));

    BN_ptr s1 = bn_from_dec(std::string(out.test_SK[0].begin(),
                                         out.test_SK[0].end()));
    BN_ptr s2 = bn_from_dec(std::string(out.test_SK[1].begin(),
                                         out.test_SK[1].end()));
    ASSERT_NE(s1, nullptr);
    ASSERT_NE(s2, nullptr);

    // New committee has 3 members at indices 4, 5, 6. Use degree 1
    // (threshold 2).
    const uint32_t degree = 1;
    std::vector<uint32_t> new_indices = {4, 5, 6};

    dao_reshare_vss_commitments c1, c2;
    std::vector<dao_reshare_vss_share> sh1, sh2;
    ASSERT_TRUE(dao_reshare_vss_deal(pk, out.record.V, s1.get(),
                                      mu1.get(), delta.get(),
                                      degree, new_indices, 32,
                                      c1, sh1));
    ASSERT_TRUE(dao_reshare_vss_deal(pk, out.record.V, s2.get(),
                                      mu2.get(), delta.get(),
                                      degree, new_indices, 32,
                                      c2, sh2));
    ASSERT_EQ(sh1.size(), 3u);
    ASSERT_EQ(sh2.size(), 3u);

    for (size_t k = 0; k < new_indices.size(); ++k) {
        ASSERT_TRUE(dao_reshare_vss_verify(pk, out.record.V, c1,
                                            new_indices[k], sh1[k].q_i_j));
        ASSERT_TRUE(dao_reshare_vss_verify(pk, out.record.V, c2,
                                            new_indices[k], sh2[k].q_i_j));
    }

    // Compute VK_j from both contributions and compare to
    // V^(Delta * s'_j) where s'_j = (q_1(j) + q_2(j)) / Delta.
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_NE(ctx, nullptr);

    BIGNUM* V = BN_bin2bn(out.record.V.data(),
                           static_cast<int>(out.record.V.size()), nullptr);
    BIGNUM* N = BN_bin2bn(out.record.N.data(),
                           static_cast<int>(out.record.N.size()), nullptr);
    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N, ctx);
    ASSERT_NE(V, nullptr);

    std::vector<dao_reshare_vss_commitments> all = {c1, c2};
    for (uint32_t j : new_indices) {
        std::vector<uint8_t> vk_expected;
        ASSERT_TRUE(dao_reshare_vss_compute_vk(pk, out.record.V,
                                                all, j, vk_expected));

        BN_ptr q1(BN_new()), q2(BN_new());
        bool f1 = false, f2 = false;
        for (const auto& s : sh1) if (s.j == j) { f1 = dao_reshare_deserialize_signed(s.q_i_j, q1.get()); break; }
        for (const auto& s : sh2) if (s.j == j) { f2 = dao_reshare_deserialize_signed(s.q_i_j, q2.get()); break; }
        ASSERT_TRUE(f1);
        ASSERT_TRUE(f2);

        BIGNUM* sum = BN_new();
        BN_add(sum, q1.get(), q2.get());
        BIGNUM* sp = BN_new();
        BIGNUM* rem = BN_new();
        BN_div(sp, rem, sum, delta.get(), ctx);
        ASSERT_TRUE(BN_is_zero(rem));

        BIGNUM* exp = BN_new();
        BN_mul(exp, delta.get(), sp, ctx);
        BIGNUM* vk_calc = BN_new();
        ASSERT_TRUE(modexp_signed(V, exp, N2, vk_calc, ctx));

        std::vector<uint8_t> vk_calc_bytes(PAILLIER_CT_BYTES, 0);
        BN_bn2binpad(vk_calc, vk_calc_bytes.data(), PAILLIER_CT_BYTES);
        EXPECT_EQ(vk_expected, vk_calc_bytes);

        BN_free(sum); BN_free(sp); BN_free(rem); BN_free(exp); BN_free(vk_calc);
    }

    BN_free(V); BN_free(N); BN_free(N2);
    BN_CTX_free(ctx);
}

TEST(DaoReshareVss, RejectsTamperedEvaluation)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));

    BIGNUM* delta_raw = BN_new();
    BN_dec2bn(&delta_raw, "20922789888000");
    BN_ptr delta(delta_raw);

    const std::vector<uint32_t> S = {1, 2};
    BN_ptr mu1(BN_new());
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 1, mu1.get()));

    BN_ptr s1 = bn_from_dec(std::string(out.test_SK[0].begin(),
                                         out.test_SK[0].end()));
    ASSERT_NE(s1, nullptr);

    dao_reshare_vss_commitments c1;
    std::vector<dao_reshare_vss_share> sh1;
    ASSERT_TRUE(dao_reshare_vss_deal(pk, out.record.V, s1.get(),
                                      mu1.get(), delta.get(),
                                      1, {4, 5, 6}, 32,
                                      c1, sh1));

    auto bad = sh1[0].q_i_j;
    bad[2] ^= 0x01;
    EXPECT_FALSE(dao_reshare_vss_verify(pk, out.record.V, c1,
                                         sh1[0].j, bad));
}

TEST(DaoReshareVss, RejectsTamperedCommitment)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));

    BIGNUM* delta_raw = BN_new();
    BN_dec2bn(&delta_raw, "20922789888000");
    BN_ptr delta(delta_raw);

    const std::vector<uint32_t> S = {1, 2};
    BN_ptr mu1(BN_new());
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 1, mu1.get()));

    BN_ptr s1 = bn_from_dec(std::string(out.test_SK[0].begin(),
                                         out.test_SK[0].end()));
    ASSERT_NE(s1, nullptr);

    dao_reshare_vss_commitments c1;
    std::vector<dao_reshare_vss_share> sh1;
    ASSERT_TRUE(dao_reshare_vss_deal(pk, out.record.V, s1.get(),
                                      mu1.get(), delta.get(),
                                      1, {4, 5, 6}, 32,
                                      c1, sh1));

    auto bad_commits = c1;
    bad_commits.C_k[0][0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_vss_verify(pk, out.record.V, bad_commits,
                                         sh1[0].j, sh1[0].q_i_j));
}
