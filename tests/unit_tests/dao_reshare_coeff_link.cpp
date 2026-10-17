// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_paillier.h"
#include "governance/dao_reshare_coeff_link.h"
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

struct Fixture
{
    BIGNUM* G = nullptr;
    BIGNUM* Y = nullptr;
    BIGNUM* x = nullptr;
    BIGNUM* rho = nullptr;
    BIGNUM* Dx = nullptr;
    dao_reshare_coeff_link_context ctx;
    dao_reshare_coeff_link_proof proof;
    size_t vss_bytes = 0;
};

void free_fixture(Fixture& f)
{
    if (f.G) BN_free(f.G);
    if (f.Y) BN_free(f.Y);
    if (f.x) BN_free(f.x);
    if (f.rho) BN_free(f.rho);
    if (f.Dx) BN_free(f.Dx);
}

bool build_fixture(const dkg_result& out, Fixture& fx)
{
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return false;

    PaillierPublicKey pk;
    if (!pk.deserialize_modulus(out.record.N)) { BN_CTX_free(ctx); return false; }

    dao_vss_group grp;
    if (!dao_vss_group_generate(grp,
            dao_dkg_required_vss_bits(60, 128, 32))) {
        BN_CTX_free(ctx);
        return false;
    }

    const BIGNUM* N2 = pk.N2();
    BIGNUM* V = BN_bin2bn(out.record.V.data(),
                           (int)out.record.V.size(), nullptr);

    // G = V^(Delta * 2^8281)
    BIGNUM* delta = BN_new();
    BN_dec2bn(&delta, "20922789888000");
    BIGNUM* scale = BN_new();
    BN_one(scale);
    BN_lshift(scale, scale, 8281);
    BIGNUM* exp = BN_new();
    BN_mul(exp, delta, scale, ctx);
    fx.G = BN_new();
    BN_mod_exp(fx.G, V, exp, N2, ctx);

    // x in [0, 2^65); b = x - 2^64; C_ik = G^b; Y = C_ik * G^(2^64) = G^x
    BIGNUM* lim = BN_new();
    BN_one(lim);
    BN_lshift(lim, lim, 65);
    fx.x = BN_new();
    BN_rand_range(fx.x, lim);
    BIGNUM* b = BN_new();
    BIGNUM* half = BN_new();
    BN_one(half);
    BN_lshift(half, half, 64);
    BN_sub(b, fx.x, half);

    BIGNUM* Cik = BN_new();
    BN_mod_exp(Cik, fx.G, b, N2, ctx);
    fx.Y = BN_new();
    BN_mod_exp(fx.Y, fx.G, fx.x, N2, ctx);

    // D_x = g^x * h^rho in VSS group
    fx.rho = BN_new();
    BN_rand_range(fx.rho, grp.P_prime);
    BIGNUM* g_x = BN_new();
    BIGNUM* h_r = BN_new();
    BN_mod_exp(g_x, grp.g, fx.x, grp.P, ctx);
    BN_mod_exp(h_r, grp.h, fx.rho, grp.P, ctx);
    fx.Dx = BN_new();
    BN_mod_mul(fx.Dx, g_x, h_r, grp.P, ctx);
    fx.vss_bytes = BN_num_bytes(grp.P);

    auto bytes_fixed = [](const BIGNUM* v, size_t w) {
        std::vector<uint8_t> o(w, 0);
        BN_bn2binpad(v, o.data(), (int)w);
        return o;
    };

    fx.ctx.genesis_block_hash = []{
        crypto::hash h{}; std::memset(h.data, 0xAA, 32); return h;
    }();
    fx.ctx.stable_key_record_hash.assign(32, 0xBB);
    fx.ctx.share_set_id = 7;
    fx.ctx.contributor_pubkey.assign(32, 0xCC);
    fx.ctx.contributor_index = 1;
    fx.ctx.coefficient_index = 3;
    fx.ctx.G    = bytes_fixed(fx.G, PAILLIER_CT_BYTES);
    fx.ctx.C_ik = bytes_fixed(Cik, PAILLIER_CT_BYTES);
    fx.ctx.Y    = bytes_fixed(fx.Y, PAILLIER_CT_BYTES);
    fx.ctx.D_x  = bytes_fixed(fx.Dx, fx.vss_bytes);
    fx.ctx.range_proof_hash.assign(32, 0xDD);

    BN_free(V); BN_free(delta); BN_free(scale); BN_free(exp);
    BN_free(lim); BN_free(b); BN_free(half); BN_free(Cik);
    BN_free(g_x); BN_free(h_r);
    BN_CTX_free(ctx);
    return true;
}

} // namespace

TEST(DaoReshareCoeffLink, RoundTrip)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));

    Fixture fx;
    ASSERT_TRUE(build_fixture(out, fx));

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp,
        dao_dkg_required_vss_bits(60, 128, 32)));

    ASSERT_TRUE(dao_reshare_coeff_link_prove(pk, grp, fx.ctx,
                                              fx.x, fx.rho, fx.proof));
    EXPECT_TRUE(dao_reshare_coeff_link_verify(pk, grp, fx.ctx, fx.proof));

    std::vector<uint8_t> ser;
    ASSERT_TRUE(fx.proof.serialize(ser, fx.vss_bytes));
    dao_reshare_coeff_link_proof back;
    ASSERT_TRUE(back.deserialize(ser, fx.vss_bytes));
    EXPECT_TRUE(dao_reshare_coeff_link_verify(pk, grp, fx.ctx, back));

    free_fixture(fx);
}

TEST(DaoReshareCoeffLink, RejectsAlteredCik)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));

    Fixture fx;
    ASSERT_TRUE(build_fixture(out, fx));

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp,
        dao_dkg_required_vss_bits(60, 128, 32)));

    ASSERT_TRUE(dao_reshare_coeff_link_prove(pk, grp, fx.ctx,
                                              fx.x, fx.rho, fx.proof));

    auto bad = fx.ctx;
    bad.C_ik[0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_coeff_link_verify(pk, grp, bad, fx.proof));

    free_fixture(fx);
}

TEST(DaoReshareCoeffLink, RejectsAlteredDx)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));

    Fixture fx;
    ASSERT_TRUE(build_fixture(out, fx));

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp,
        dao_dkg_required_vss_bits(60, 128, 32)));

    ASSERT_TRUE(dao_reshare_coeff_link_prove(pk, grp, fx.ctx,
                                              fx.x, fx.rho, fx.proof));

    auto bad = fx.ctx;
    bad.D_x[0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_coeff_link_verify(pk, grp, bad, fx.proof));

    free_fixture(fx);
}

TEST(DaoReshareCoeffLink, RejectsAlteredIndex)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));

    Fixture fx;
    ASSERT_TRUE(build_fixture(out, fx));

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp,
        dao_dkg_required_vss_bits(60, 128, 32)));

    ASSERT_TRUE(dao_reshare_coeff_link_prove(pk, grp, fx.ctx,
                                              fx.x, fx.rho, fx.proof));

    auto bad = fx.ctx;
    bad.coefficient_index += 1;
    EXPECT_FALSE(dao_reshare_coeff_link_verify(pk, grp, bad, fx.proof));

    auto bad2 = fx.ctx;
    bad2.share_set_id += 1;
    EXPECT_FALSE(dao_reshare_coeff_link_verify(pk, grp, bad2, fx.proof));

    free_fixture(fx);
}

TEST(DaoReshareCoeffLink, RejectsForgedResponse)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));

    Fixture fx;
    ASSERT_TRUE(build_fixture(out, fx));

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp,
        dao_dkg_required_vss_bits(60, 128, 32)));

    ASSERT_TRUE(dao_reshare_coeff_link_prove(pk, grp, fx.ctx,
                                              fx.x, fx.rho, fx.proof));

    auto bad = fx.proof;
    bad.Z_x[5][0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_coeff_link_verify(pk, grp, fx.ctx, bad));

    auto bad2 = fx.proof;
    bad2.Z_rho[11][0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_coeff_link_verify(pk, grp, fx.ctx, bad2));

    auto bad3 = fx.proof;
    bad3.A_paillier[3][0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_coeff_link_verify(pk, grp, fx.ctx, bad3));

    auto bad4 = fx.proof;
    bad4.A_vss[7][0] ^= 0x01;
    EXPECT_FALSE(dao_reshare_coeff_link_verify(pk, grp, fx.ctx, bad4));

    free_fixture(fx);
}
