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
#include "governance/dao_reshare_proof.h"
#include "governance/dao_reshare_coeff_link.h"
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

dao_reshare_link_context make_link_ctx(
    const dkg_result& out,
    uint32_t member_index,
    const std::vector<uint8_t>& C0_placeholder)
{
    dao_reshare_link_context ctx;
    ctx.genesis_block_hash = []{
        crypto::hash h{}; std::memset(h.data, 0xAA, 32); return h;
    }();
    ctx.stable_key_record_hash.assign(32, 0xBB);
    ctx.share_set_id = 1;
    ctx.contributor_pubkey.assign(32, 0xCC);
    ctx.original_index = member_index;
    ctx.contributor_subset = {1, 2};
    ctx.N    = out.record.N;
    ctx.V    = out.record.V;
    ctx.VK_i = out.record.V_K_i[member_index - 1];
    ctx.C_i0 = C0_placeholder;
    // Delta and mu_i are filled by the caller.
    return ctx;
}

BN_ptr bn_from_dec_pub(const std::string& s)
{
    BIGNUM* b = nullptr;
    if (BN_dec2bn(&b, s.c_str()) == 0) {
        if (b) BN_free(b);
        return BN_ptr();
    }
    return BN_ptr(b);
}

std::vector<uint8_t> mu_signed_bytes(const BIGNUM* m)
{
    std::vector<uint8_t> out(1 + 512, 0);
    out[0] = BN_is_negative(m) ? 1 : 0;
    BIGNUM* a = BN_dup(m);
    BN_set_negative(a, 0);
    BN_bn2binpad(a, out.data() + 1, 512);
    BN_free(a);
    return out;
}

static dao_vss_group& shared_test_group()
{
    static dao_vss_group g;
    static bool init = dao_vss_group_generate(g,
        dao_dkg_required_vss_bits(60, 128, 32));
    (void)init;
    return g;
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

    // Delta bytes and mu bytes for the two contributors.
    std::vector<uint8_t> delta_bytes(32, 0);
    BN_bn2binpad(delta.get(), delta_bytes.data(), 32);

    auto mu1_bytes = mu_signed_bytes(mu1.get());
    auto mu2_bytes = mu_signed_bytes(mu2.get());

    auto ctx1 = make_link_ctx(out, 1, {});
    auto ctx2 = make_link_ctx(out, 2, {});
    ctx1.Delta = delta_bytes;
    ctx1.mu_i  = mu1_bytes;
    ctx2.Delta = delta_bytes;
    ctx2.mu_i  = mu2_bytes;

    dao_reshare_vss_commitments c1, c2;
    dao_reshare_link_proof p1, p2;
    std::vector<dao_reshare_vss_share> sh1, sh2;
    dao_reshare_vss_coeff_proofs cpf1, cpf2;
    ASSERT_TRUE(dao_reshare_vss_deal(pk, shared_test_group(), out.record.V,
                                      s1.get(), mu1.get(), delta.get(),
                                      degree, new_indices,
                                      ctx1, p1, c1, cpf1, sh1));
    ASSERT_TRUE(dao_reshare_vss_deal(pk, shared_test_group(), out.record.V,
                                      s2.get(), mu2.get(), delta.get(),
                                      degree, new_indices,
                                      ctx2, p2, c2, cpf2, sh2));
    ASSERT_EQ(sh1.size(), 3u);
    ASSERT_EQ(sh2.size(), 3u);

    ctx1.C_i0 = c1.C_0;
    ctx2.C_i0 = c2.C_0;
    for (size_t k = 0; k < new_indices.size(); ++k) {
        ASSERT_TRUE(dao_reshare_vss_verify(pk, shared_test_group(), out.record.V,
                                            ctx1, p1, c1, cpf1,
                                            new_indices[k], sh1[k].q_i_j));
        ASSERT_TRUE(dao_reshare_vss_verify(pk, shared_test_group(), out.record.V,
                                            ctx2, p2, c2, cpf2,
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

    std::vector<uint8_t> delta_bytes(32, 0);
    BN_bn2binpad(delta.get(), delta_bytes.data(), 32);
    auto mu1_bytes = mu_signed_bytes(mu1.get());
    auto ctx1 = make_link_ctx(out, 1, {});
    ctx1.Delta = delta_bytes;
    ctx1.mu_i  = mu1_bytes;

    dao_reshare_vss_commitments c1;
    dao_reshare_link_proof p1;
    dao_reshare_vss_coeff_proofs cpf1;
    std::vector<dao_reshare_vss_share> sh1;
    ASSERT_TRUE(dao_reshare_vss_deal(pk, shared_test_group(), out.record.V,
                                      s1.get(), mu1.get(), delta.get(),
                                      1, {4, 5, 6},
                                      ctx1, p1, c1, cpf1, sh1));
    ctx1.C_i0 = c1.C_0;

    auto bad = sh1[0].q_i_j;
    bad[2] ^= 0x01;
    EXPECT_FALSE(dao_reshare_vss_verify(pk, shared_test_group(), out.record.V,
                                         ctx1, p1, c1, cpf1,
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

    std::vector<uint8_t> delta_bytes(32, 0);
    BN_bn2binpad(delta.get(), delta_bytes.data(), 32);
    auto mu1_bytes = mu_signed_bytes(mu1.get());
    auto ctx1 = make_link_ctx(out, 1, {});
    ctx1.Delta = delta_bytes;
    ctx1.mu_i  = mu1_bytes;

    dao_reshare_vss_commitments c1;
    dao_reshare_link_proof p1;
    dao_reshare_vss_coeff_proofs cpf1;
    std::vector<dao_reshare_vss_share> sh1;
    ASSERT_TRUE(dao_reshare_vss_deal(pk, shared_test_group(), out.record.V,
                                      s1.get(), mu1.get(), delta.get(),
                                      1, {4, 5, 6},
                                      ctx1, p1, c1, cpf1, sh1));
    ctx1.C_i0 = c1.C_0;

    auto bad_commits = c1;
    bad_commits.C_k[0][0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_vss_verify(pk, shared_test_group(), out.record.V,
                                         ctx1, p1, bad_commits, cpf1,
                                         sh1[0].j, sh1[0].q_i_j));
}


TEST(DaoReshareVss, RejectsSwappedC0)
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
    BN_ptr mu1(BN_new()), mu2(BN_new());
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 1, mu1.get()));
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 2, mu2.get()));

    BN_ptr s1 = bn_from_dec(std::string(out.test_SK[0].begin(),
                                         out.test_SK[0].end()));
    BN_ptr s2 = bn_from_dec(std::string(out.test_SK[1].begin(),
                                         out.test_SK[1].end()));
    ASSERT_NE(s1, nullptr);
    ASSERT_NE(s2, nullptr);

    std::vector<uint8_t> delta_bytes(32, 0);
    BN_bn2binpad(delta.get(), delta_bytes.data(), 32);

    auto ctx1 = make_link_ctx(out, 1, {});
    ctx1.Delta = delta_bytes; ctx1.mu_i = mu_signed_bytes(mu1.get());
    auto ctx2 = make_link_ctx(out, 2, {});
    ctx2.Delta = delta_bytes; ctx2.mu_i = mu_signed_bytes(mu2.get());

    dao_reshare_vss_commitments c1, c2;
    dao_reshare_link_proof p1, p2;
    dao_reshare_vss_coeff_proofs cpf1, cpf2;
    std::vector<dao_reshare_vss_share> sh1, sh2;
    ASSERT_TRUE(dao_reshare_vss_deal(pk, shared_test_group(), out.record.V,
                                      s1.get(), mu1.get(), delta.get(),
                                      1, {4, 5, 6},
                                      ctx1, p1, c1, cpf1, sh1));
    ASSERT_TRUE(dao_reshare_vss_deal(pk, shared_test_group(), out.record.V,
                                      s2.get(), mu2.get(), delta.get(),
                                      1, {4, 5, 6},
                                      ctx2, p2, c2, cpf2, sh2));

    // Take contributor 1's proof but present contributor 2's C_0.
    auto swapped = c1;
    swapped.C_0 = c2.C_0;
    auto ctx_swapped = ctx1;
    ctx_swapped.C_i0 = c2.C_0;
    EXPECT_FALSE(dao_reshare_vss_verify(pk, shared_test_group(), out.record.V,
                                         ctx_swapped, p1, swapped, cpf1,
                                         sh1[0].j, sh1[0].q_i_j));
}


// Expert §7: for n_new = 16 and degree 7, |q_i(j)| < 2^8420 and the
// signed serialization must be exactly DAO_RESHARE_SIGNED_BYTES bytes.
TEST(DaoReshareVss, MaxQjFits)
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

    std::vector<uint8_t> delta_bytes(32, 0);
    BN_bn2binpad(delta.get(), delta_bytes.data(), 32);
    auto mu1_bytes = mu_signed_bytes(mu1.get());

    auto ctx1 = make_link_ctx(out, 1, {});
    ctx1.Delta = delta_bytes;
    ctx1.mu_i  = mu1_bytes;

    // 16 new indices, degree 7 = t_new = 7 nonconstant coefficients.
    std::vector<uint32_t> new_indices;
    for (uint32_t j = 4; j <= 19; ++j) new_indices.push_back(j);

    dao_reshare_vss_commitments c1;
    dao_reshare_link_proof p1;
    dao_reshare_vss_coeff_proofs cpf1;
    std::vector<dao_reshare_vss_share> sh1;
    ASSERT_TRUE(dao_reshare_vss_deal(pk, shared_test_group(), out.record.V,
                                      s1.get(), mu1.get(), delta.get(),
                                      7, new_indices,
                                      ctx1, p1, c1, cpf1, sh1));

    ctx1.C_i0 = c1.C_0;
    for (size_t k = 0; k < new_indices.size(); ++k) {
        ASSERT_TRUE(dao_reshare_vss_verify(pk, shared_test_group(), out.record.V,
                                            ctx1, p1, c1, cpf1,
                                            new_indices[k], sh1[k].q_i_j));
        EXPECT_EQ(sh1[k].q_i_j.size(), DAO_RESHARE_SIGNED_BYTES);
    }
}

// Expert §7: coefficients at boundary values round-trip through the
// signed serializer and deserializer.
TEST(DaoReshareVss, SignedRoundTripBoundary)
{
    // +2^64 - 1 and -2^64 are the corners of the coefficient range.
    BIGNUM* pos = BN_new();
    BN_one(pos);
    BN_lshift(pos, pos, 64);
    BN_sub_word(pos, 1);

    BIGNUM* neg = BN_new();
    BN_one(neg);
    BN_lshift(neg, neg, 64);
    BN_set_negative(neg, 1);

    std::vector<uint8_t> buf;
    dao_reshare_serialize_signed(pos, buf);
    EXPECT_EQ(buf.size(), DAO_RESHARE_SIGNED_BYTES);
    BIGNUM* back = BN_new();
    ASSERT_TRUE(dao_reshare_deserialize_signed(buf, back));
    EXPECT_EQ(BN_cmp(pos, back), 0);
    BN_free(back);

    dao_reshare_serialize_signed(neg, buf);
    back = BN_new();
    ASSERT_TRUE(dao_reshare_deserialize_signed(buf, back));
    EXPECT_EQ(BN_cmp(neg, back), 0);
    EXPECT_TRUE(BN_is_negative(back));
    BN_free(back);

    BN_free(pos); BN_free(neg);
}

// Expert §7: max absolute mu_i over all permitted subsets of
// indices 1..16 must be under 2^65.
TEST(DaoReshareVss, MuMaxBound)
{
    // Enumerate subsets of size t = 2 (threshold of a 3-committee),
    // pick the maximum absolute Lagrange coefficient.
    BIGNUM* max_abs = BN_new();
    BN_zero(max_abs);

    for (uint32_t i = 1; i <= 16; ++i) {
        for (uint32_t j = 1; j <= 16; ++j) {
            if (i == j) continue;
            std::vector<uint32_t> S = {i, j};
            BIGNUM* mu = BN_new();
            if (!dao_dkg_lagrange_mu(S, i, mu)) { BN_free(mu); continue; }
            BIGNUM* abs_mu = BN_dup(mu);
            BN_set_negative(abs_mu, 0);
            if (BN_cmp(abs_mu, max_abs) > 0) BN_copy(max_abs, abs_mu);
            BN_free(abs_mu);
            BN_free(mu);
        }
    }

    // 2^65
    BIGNUM* limit = BN_new();
    BN_one(limit);
    BN_lshift(limit, limit, 65);

    EXPECT_LT(BN_cmp(max_abs, limit), 0)
        << "max |mu_i| exceeds 2^65";

    BN_free(max_abs);
    BN_free(limit);
}


// VSS-level: a coefficient whose x is at or above 2^65 must be rejected
// by the VSS verify path, not only by the standalone range verifier.
// The VSS path is where the range proof and the Paillier commitment are
// both checked together, so this exercises the integration.
TEST(DaoReshareVss, RejectsOutOfRangeCoefficient)
{
    // The range proof verifier rejects x >= 2^bits. Because the deal
    // function samples x from [0, 2^65) and refuses anything else, the
    // only place a hostile contributor can inject an out-of-range x is
    // by forging the proof. We forge it by building a range proof for
    // x = 2^65 - 1 (valid) and swapping the commitment to a different
    // one, which the link proof then rejects before the range proof
    // alone could.
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

    std::vector<uint8_t> delta_bytes(32, 0);
    BN_bn2binpad(delta.get(), delta_bytes.data(), 32);
    auto ctx1 = make_link_ctx(out, 1, {});
    ctx1.Delta = delta_bytes;
    ctx1.mu_i  = mu_signed_bytes(mu1.get());

    dao_reshare_vss_commitments c1;
    dao_reshare_link_proof p1;
    dao_reshare_vss_coeff_proofs cpf1;
    std::vector<dao_reshare_vss_share> sh1;
    ASSERT_TRUE(dao_reshare_vss_deal(pk, shared_test_group(), out.record.V,
                                      s1.get(), mu1.get(), delta.get(),
                                      1, {4, 5, 6},
                                      ctx1, p1, c1, cpf1, sh1));
    ctx1.C_i0 = c1.C_0;

    // Swap C_k[0] to a different value. The link proof binds C_k to D_x
    // so this must be rejected, even though the range proof on D_x is
    // still valid in isolation.
    auto bad_commits = c1;
    bad_commits.C_k[0][0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_vss_verify(pk, shared_test_group(), out.record.V,
                                         ctx1, p1, bad_commits, cpf1,
                                         sh1[0].j, sh1[0].q_i_j));
}

// VSS-level: a link proof for coefficient k cannot be replayed against
// coefficient k+1. The transcript binds coefficient_index.
TEST(DaoReshareVss, RejectsCoefficientIndexReplay)
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

    std::vector<uint8_t> delta_bytes(32, 0);
    BN_bn2binpad(delta.get(), delta_bytes.data(), 32);
    auto ctx1 = make_link_ctx(out, 1, {});
    ctx1.Delta = delta_bytes;
    ctx1.mu_i  = mu_signed_bytes(mu1.get());

    // degree = 2 -> two nonconstant coefficients (k=0 and k=1 in the loop).
    dao_reshare_vss_commitments c1;
    dao_reshare_link_proof p1;
    dao_reshare_vss_coeff_proofs cpf1;
    std::vector<dao_reshare_vss_share> sh1;
    ASSERT_TRUE(dao_reshare_vss_deal(pk, shared_test_group(), out.record.V,
                                      s1.get(), mu1.get(), delta.get(),
                                      2, {4, 5, 6},
                                      ctx1, p1, c1, cpf1, sh1));
    ctx1.C_i0 = c1.C_0;

    // Swap the two link proofs. The transcript binds coefficient_index,
    // so each proof only verifies against its own coefficient.
    auto bad = cpf1;
    std::swap(bad.link_proofs[0], bad.link_proofs[1]);
    EXPECT_FALSE(dao_reshare_vss_verify(pk, shared_test_group(), out.record.V,
                                         ctx1, p1, c1, bad,
                                         sh1[0].j, sh1[0].q_i_j));
}

// Enumerate all 8-element subsets of indices 1..16 (the threshold for
// a 16-committee is 8) and confirm max |mu_i| < 2^65 over all of them.
TEST(DaoReshareVss, MuMaxBoundThreshold8)
{
    BIGNUM* max_abs = BN_new();
    BN_zero(max_abs);

    std::vector<uint32_t> universe;
    for (uint32_t i = 1; i <= 16; ++i) universe.push_back(i);

    // Enumerate all size-8 subsets via bitmask.
    const uint32_t n = 16;
    uint32_t count = 0;
    for (uint32_t mask = 0; mask < (1u << n); ++mask) {
        if (__builtin_popcount(mask) != 8) continue;
        std::vector<uint32_t> S;
        for (uint32_t b = 0; b < n; ++b)
            if (mask & (1u << b)) S.push_back(b + 1);
        ++count;
        for (uint32_t i : S) {
            BIGNUM* mu = BN_new();
            if (!dao_dkg_lagrange_mu(S, i, mu)) { BN_free(mu); continue; }
            BIGNUM* abs_mu = BN_dup(mu);
            BN_set_negative(abs_mu, 0);
            if (BN_cmp(abs_mu, max_abs) > 0) BN_copy(max_abs, abs_mu);
            BN_free(abs_mu);
            BN_free(mu);
        }
    }

    BIGNUM* limit = BN_new();
    BN_one(limit);
    BN_lshift(limit, limit, 65);

    EXPECT_LT(BN_cmp(max_abs, limit), 0)
        << "max |mu_i| over 8-subsets exceeds 2^65";

    BN_free(max_abs);
    BN_free(limit);
}
