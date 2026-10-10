// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Common-exponent proof (DAO V2 resharing link proof) tests.
//
// Uses a real Paillier modulus produced by the DKG test harness.
// Verifies the positive case and rejects altered public values,
// altered commitments, forged responses and stale context bindings.

#include "gtest/gtest.h"

#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_paillier.h"
#include "governance/dao_reshare_proof.h"
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

bool bn_fixed(const BIGNUM* b, size_t w, std::vector<uint8_t>& out)
{
    out.assign(w, 0);
    return BN_bn2binpad(b, out.data(), static_cast<int>(w)) ==
           static_cast<int>(w);
}

// Build a real (N, V, VK_i, C_i0, Delta, mu_i) tuple from a DKG run.
struct ProofFixture
{
    BIGNUM* N;
    std::vector<uint8_t> N_bytes;
    std::vector<uint8_t> V_bytes;
    std::vector<uint8_t> VK_bytes;
    std::vector<uint8_t> C0_bytes;
    std::vector<uint8_t> delta_bytes;
    std::vector<uint8_t> mu_bytes;
    BN_ptr s_i;
    dao_reshare_link_context ctx;
};

bool build_fixture(const dkg_result& out,
                   uint32_t member_index,
                   ProofFixture& fx)
{
    // Delta
    BIGNUM* delta = BN_new();
    BN_dec2bn(&delta, "20922789888000");
    fx.delta_bytes.assign(32, 0);
    BN_bn2binpad(delta, fx.delta_bytes.data(), 32);

    // mu_i = Delta * lambda_i(0) for subset {1, 2}
    std::vector<uint32_t> S = {1, 2};
    BIGNUM* mu = BN_new();
    if (!dao_dkg_lagrange_mu(S, member_index, mu)) return false;
    fx.mu_bytes.assign(64, 0);
    BIGNUM* abs_mu = BN_dup(mu);
    BN_set_negative(abs_mu, 0);
    BN_bn2binpad(abs_mu, fx.mu_bytes.data(), 64);
    BN_free(abs_mu);

    // N, V, VK
    if (out.record.N.size() != PAILLIER_MODULUS_BYTES) return false;
    if (out.record.V.size() != PAILLIER_CT_BYTES) return false;
    if (out.record.V_K_i.size() <= member_index - 1) return false;
    fx.N_bytes = out.record.N;
    fx.V_bytes = out.record.V;
    fx.VK_bytes = out.record.V_K_i[member_index - 1];

    // s_i
    if (out.test_SK.size() <= member_index - 1) return false;
    fx.s_i = bn_from_dec(std::string(out.test_SK[member_index - 1].begin(),
                                     out.test_SK[member_index - 1].end()));
    if (!fx.s_i) return false;

    // C_i0 = V^(mu_i * s_i) mod N^2
    BN_CTX* c = BN_CTX_new();
    BIGNUM* N = BN_bin2bn(fx.N_bytes.data(),
                          static_cast<int>(fx.N_bytes.size()), nullptr);
    BIGNUM* V = BN_bin2bn(fx.V_bytes.data(),
                          static_cast<int>(fx.V_bytes.size()), nullptr);
    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N, c);
    BIGNUM* exp = BN_new();
    BN_mul(exp, mu, fx.s_i.get(), c);
    BIGNUM* C0 = BN_new();
    BN_mod_exp(C0, V, exp, N2, c);
    fx.C0_bytes.assign(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(C0, fx.C0_bytes.data(), PAILLIER_CT_BYTES);

    fx.ctx.genesis_block_hash = []{
        crypto::hash h{}; std::memset(h.data, 0xAA, 32); return h;
    }();
    fx.ctx.stable_key_record_hash.assign(32, 0xBB);
    fx.ctx.share_set_id = 42;
    fx.ctx.contributor_pubkey.assign(32, 0xCC);
    fx.ctx.original_index = member_index;
    fx.ctx.contributor_subset = S;
    fx.ctx.N    = fx.N_bytes;
    fx.ctx.V    = fx.V_bytes;
    fx.ctx.VK_i = fx.VK_bytes;
    fx.ctx.C_i0 = fx.C0_bytes;
    fx.ctx.Delta = fx.delta_bytes;
    fx.ctx.mu_i  = fx.mu_bytes;

    BN_free(N); BN_free(V); BN_free(N2); BN_free(exp); BN_free(C0);
    BN_free(delta); BN_free(mu);
    BN_CTX_free(c);
    return true;
}

} // namespace

TEST(DaoReshareProof, RoundTrip)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    ProofFixture fx{};
    ASSERT_TRUE(build_fixture(out, 1, fx));

    dao_reshare_link_proof proof;
    ASSERT_TRUE(dao_reshare_link_prove(fx.ctx, fx.s_i.get(), proof));
    EXPECT_TRUE(dao_reshare_link_verify(fx.ctx, proof));

    std::vector<uint8_t> ser;
    ASSERT_TRUE(proof.serialize(ser));
    dao_reshare_link_proof back;
    ASSERT_TRUE(back.deserialize(ser));
    EXPECT_TRUE(dao_reshare_link_verify(fx.ctx, back));
}

TEST(DaoReshareProof, RejectsAlteredC_i0)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    ProofFixture fx{};
    ASSERT_TRUE(build_fixture(out, 1, fx));

    dao_reshare_link_proof proof;
    ASSERT_TRUE(dao_reshare_link_prove(fx.ctx, fx.s_i.get(), proof));

    auto bad_ctx = fx.ctx;
    bad_ctx.C_i0[0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_link_verify(bad_ctx, proof));
}

TEST(DaoReshareProof, RejectsAlteredVK)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    ProofFixture fx{};
    ASSERT_TRUE(build_fixture(out, 1, fx));

    dao_reshare_link_proof proof;
    ASSERT_TRUE(dao_reshare_link_prove(fx.ctx, fx.s_i.get(), proof));

    auto bad_ctx = fx.ctx;
    bad_ctx.VK_i[0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_link_verify(bad_ctx, proof));
}

TEST(DaoReshareProof, RejectsAlteredCommitment)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    ProofFixture fx{};
    ASSERT_TRUE(build_fixture(out, 1, fx));

    dao_reshare_link_proof proof;
    ASSERT_TRUE(dao_reshare_link_prove(fx.ctx, fx.s_i.get(), proof));

    auto bad = proof;
    bad.A[3][0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_link_verify(fx.ctx, bad));

    auto bad2 = proof;
    bad2.B[7][0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_link_verify(fx.ctx, bad2));

    auto bad3 = proof;
    bad3.Z[11][1] ^= 0x01;
    EXPECT_FALSE(dao_reshare_link_verify(fx.ctx, bad3));
}

TEST(DaoReshareProof, RejectsStaleShareSetId)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    ProofFixture fx{};
    ASSERT_TRUE(build_fixture(out, 1, fx));

    dao_reshare_link_proof proof;
    ASSERT_TRUE(dao_reshare_link_prove(fx.ctx, fx.s_i.get(), proof));

    auto bad_ctx = fx.ctx;
    bad_ctx.share_set_id = 43;
    EXPECT_FALSE(dao_reshare_link_verify(bad_ctx, proof));
}

TEST(DaoReshareProof, RejectsWrongWitness)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    ProofFixture fx{};
    ASSERT_TRUE(build_fixture(out, 1, fx));

    // Sign the correct relation but with the wrong witness: prove with
    // s_2 instead of s_1. The public values still match s_1, so the
    // resulting proof must not verify.
    dkg_result out2;
    ASSERT_TRUE(run_dkg_3(out2));
    ASSERT_TRUE(out2.candidate_accepted);

    BN_ptr wrong = bn_from_dec(
        std::string(out.test_SK[1].begin(), out.test_SK[1].end()));
    ASSERT_NE(wrong, nullptr);

    dao_reshare_link_proof proof;
    ASSERT_TRUE(dao_reshare_link_prove(fx.ctx, wrong.get(), proof));
    EXPECT_FALSE(dao_reshare_link_verify(fx.ctx, proof));
}
