// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#ifdef VEILROOT_ENABLE_CL

#include <cstring>

#include "gtest/gtest.h"

#include <openssl/bn.h>

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"

#include "crypto/crypto.h"
#include "governance/dao_cl_consistency.h"
#include "governance/dao_crypto_backend.h"
#include "ringct/rctOps.h"

using namespace cryptonote;
using namespace cryptonote::dao;
using namespace BICYCL;

namespace {

constexpr unsigned long SECLEVEL = 128;

struct Fixture
{
    Mpz q;
    RandGen randgen;
    SecLevel seclevel{SECLEVEL};
    std::unique_ptr<CL_HSMqk> CL;
    std::unique_ptr<CL_HSMqk::SecretKey> sk;
    std::unique_ptr<CL_HSMqk::PublicKey> pk;

    Fixture() = default;
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    bool init()
    {
        // Ed25519 subgroup order (rct::curveOrder).
        rct::key L = rct::curveOrder();
        std::array<uint8_t, 32> be{};
        for (size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
        q = Mpz(std::vector<unsigned char>(be.begin(), be.end()));

        std::random_device rd;
        randgen.set_seed(Mpz(static_cast<unsigned long>(rd())));

        CL = std::make_unique<CL_HSMqk>(q, 1, seclevel, randgen,
                                        CL_Params{SECLEVEL});
        sk = std::make_unique<CL_HSMqk::SecretKey>(*CL, randgen);
        pk = std::make_unique<CL_HSMqk::PublicKey>(*CL, *sk);
        return true;
    }
};

bool mpz_lt_u128(const Mpz& a, unsigned __int128 b)
{
    std::vector<uint8_t> be;
    uint64_t lo = static_cast<uint64_t>(b);
    uint64_t hi = static_cast<uint64_t>(b >> 64);
    for (int i = 7; i >= 0; --i) {
        uint8_t bt = (hi >> (8*i)) & 0xff;
        if (!be.empty() || bt != 0) be.push_back(bt);
    }
    for (int i = 7; i >= 0; --i) {
        uint8_t bt = (lo >> (8*i)) & 0xff;
        if (!be.empty() || bt != 0) be.push_back(bt);
    }
    Mpz bmpz = be.empty() ? Mpz(0UL) : Mpz(std::vector<unsigned char>(be.begin(), be.end()));
    return a <= bmpz;
}

bool build_case(Fixture& f, unsigned __int128 W_128,
                Mpz& W_mpz, Mpz& r_mpz,
                rct::key& rho, rct::key& C,
                std::vector<uint8_t>& c1_bytes,
                std::vector<uint8_t>& c2_bytes,
                CL_HSMqk::CipherText& ct)
{
    // W as Mpz.
    std::vector<uint8_t> be;
    uint64_t lo = static_cast<uint64_t>(W_128);
    uint64_t hi = static_cast<uint64_t>(W_128 >> 64);
    for (int i = 7; i >= 0; --i) {
        uint8_t bt = (hi >> (8*i)) & 0xff;
        if (!be.empty() || bt != 0) be.push_back(bt);
    }
    for (int i = 7; i >= 0; --i) {
        uint8_t bt = (lo >> (8*i)) & 0xff;
        if (!be.empty() || bt != 0) be.push_back(bt);
    }
    W_mpz = be.empty() ? Mpz(0UL) : Mpz(std::vector<unsigned char>(be.begin(), be.end()));

    // r.
    r_mpz = f.randgen.random_mpz(f.CL->encrypt_randomness_bound());

    // rho, C = W·H + rho·G.
    rho = rct::skGen();
    rct::key W_scalar;
    {
        std::vector<uint8_t> wbe = be;
        std::memset(W_scalar.bytes, 0, 32);
        const size_t n = wbe.size();
        for (size_t i = 0; i < n; ++i) W_scalar.bytes[i] = wbe[n - 1 - i];
    }
    rct::key WH, rhoG;
    WH = rct::scalarmultH(W_scalar);
    rct::scalarmultBase(rhoG, rho);
    rct::addKeys(C, WH, rhoG);

    // CL ciphertext.
    CL_HSMqk::ClearText mcl(*f.CL, W_mpz);
    ct = f.CL->encrypt(*f.pk, mcl, r_mpz);

    return true;
}

dao_consistency_context make_ctx(const std::string& domain)
{
    dao_consistency_context ctx;
    ctx.domain = domain;
    ctx.version = 2;
    ctx.proposal_id.data[0] = 0x11;
    ctx.vote_height = 1000;
    ctx.tally_key_id.data[0] = 0x22;
    ctx.vote_input_transcript = {1, 2, 3, 4};
    return ctx;
}

} // namespace

// ---- Honest path tests ----

TEST(dao_cl_consistency, prove_verify_zero)
{
    Fixture f; ASSERT_TRUE(f.init());
    Mpz W, r; rct::key rho, C;
    CL_HSMqk::CipherText ct;
    std::vector<uint8_t> c1b, c2b;
    ASSERT_TRUE(build_case(f, 0, W, r, rho, C, c1b, c2b, ct));
    auto ctx = make_ctx("C_W-Enc(W)");
    dao_cl_pedersen_proof p;
    ASSERT_TRUE(dao_cl_consistency_prove(*f.CL, *f.pk, ct, W, r, C, rho,
                                         ctx, f.randgen, p));
    EXPECT_TRUE(dao_cl_consistency_verify(*f.CL, *f.pk, ct, C, ctx, p));
}

TEST(dao_cl_consistency, prove_verify_one)
{
    Fixture f; ASSERT_TRUE(f.init());
    Mpz W, r; rct::key rho, C;
    CL_HSMqk::CipherText ct;
    std::vector<uint8_t> c1b, c2b;
    ASSERT_TRUE(build_case(f, 1, W, r, rho, C, c1b, c2b, ct));
    auto ctx = make_ctx("C_W-Enc(W)");
    dao_cl_pedersen_proof p;
    ASSERT_TRUE(dao_cl_consistency_prove(*f.CL, *f.pk, ct, W, r, C, rho,
                                         ctx, f.randgen, p));
    EXPECT_TRUE(dao_cl_consistency_verify(*f.CL, *f.pk, ct, C, ctx, p));
}

TEST(dao_cl_consistency, prove_verify_2p34_boundary)
{
    Fixture f; ASSERT_TRUE(f.init());
    Mpz W, r; rct::key rho, C;
    CL_HSMqk::CipherText ct;
    std::vector<uint8_t> c1b, c2b;
    ASSERT_TRUE(build_case(f, (unsigned __int128)1 << 34, W, r, rho, C, c1b, c2b, ct));
    auto ctx = make_ctx("C_W-Enc(W)");
    dao_cl_pedersen_proof p;
    ASSERT_TRUE(dao_cl_consistency_prove(*f.CL, *f.pk, ct, W, r, C, rho,
                                         ctx, f.randgen, p));
    EXPECT_TRUE(dao_cl_consistency_verify(*f.CL, *f.pk, ct, C, ctx, p));
}

TEST(dao_cl_consistency, prove_verify_at_w_max)
{
    Fixture f; ASSERT_TRUE(f.init());
    Mpz W, r; rct::key rho, C;
    CL_HSMqk::CipherText ct;
    std::vector<uint8_t> c1b, c2b;
    ASSERT_TRUE(build_case(f, DAO_WEIGHTED_MAX, W, r, rho, C, c1b, c2b, ct));
    auto ctx = make_ctx("C_W-Enc(W)");
    dao_cl_pedersen_proof p;
    ASSERT_TRUE(dao_cl_consistency_prove(*f.CL, *f.pk, ct, W, r, C, rho,
                                         ctx, f.randgen, p));
    EXPECT_TRUE(dao_cl_consistency_verify(*f.CL, *f.pk, ct, C, ctx, p));
}

// ---- Range rejection ----

TEST(dao_cl_consistency, prover_rejects_w_max_plus_one)
{
    Fixture f; ASSERT_TRUE(f.init());
    Mpz W, r; rct::key rho, C;
    CL_HSMqk::CipherText ct;
    std::vector<uint8_t> c1b, c2b;
    unsigned __int128 bad = DAO_WEIGHTED_MAX + 1;
    ASSERT_TRUE(build_case(f, bad, W, r, rho, C, c1b, c2b, ct));
    auto ctx = make_ctx("C_W-Enc(W)");
    dao_cl_pedersen_proof p;
    EXPECT_FALSE(dao_cl_consistency_prove(*f.CL, *f.pk, ct, W, r, C, rho,
                                          ctx, f.randgen, p));
}

TEST(dao_cl_consistency, prover_rejects_2p68_minus_one)
{
    Fixture f; ASSERT_TRUE(f.init());
    Mpz W, r; rct::key rho, C;
    CL_HSMqk::CipherText ct;
    std::vector<uint8_t> c1b, c2b;
    unsigned __int128 bad = (((unsigned __int128)1) << 68) - 1;
    ASSERT_TRUE(build_case(f, bad, W, r, rho, C, c1b, c2b, ct));
    auto ctx = make_ctx("C_W-Enc(W)");
    dao_cl_pedersen_proof p;
    EXPECT_FALSE(dao_cl_consistency_prove(*f.CL, *f.pk, ct, W, r, C, rho,
                                          ctx, f.randgen, p));
}

// ---- Tampering ----

TEST(dao_cl_consistency, tampered_c1_rejects)
{
    Fixture f; ASSERT_TRUE(f.init());
    Mpz W, r; rct::key rho, C;
    CL_HSMqk::CipherText ct;
    std::vector<uint8_t> c1b, c2b;
    ASSERT_TRUE(build_case(f, 42, W, r, rho, C, c1b, c2b, ct));
    auto ctx = make_ctx("C_W-Enc(W)");
    dao_cl_pedersen_proof p;
    ASSERT_TRUE(dao_cl_consistency_prove(*f.CL, *f.pk, ct, W, r, C, rho,
                                         ctx, f.randgen, p));

    // Re-encrypt a different plaintext.
    CL_HSMqk::ClearText bad_m(*f.CL, Mpz(43UL));
    CL_HSMqk::CipherText bad_ct = f.CL->encrypt(*f.pk, bad_m, r);
    EXPECT_FALSE(dao_cl_consistency_verify(*f.CL, *f.pk, bad_ct, C, ctx, p));
}

TEST(dao_cl_consistency, tampered_C_rejects)
{
    Fixture f; ASSERT_TRUE(f.init());
    Mpz W, r; rct::key rho, C;
    CL_HSMqk::CipherText ct;
    std::vector<uint8_t> c1b, c2b;
    ASSERT_TRUE(build_case(f, 42, W, r, rho, C, c1b, c2b, ct));
    auto ctx = make_ctx("C_W-Enc(W)");
    dao_cl_pedersen_proof p;
    ASSERT_TRUE(dao_cl_consistency_prove(*f.CL, *f.pk, ct, W, r, C, rho,
                                         ctx, f.randgen, p));

    rct::key bad_C;
    rct::scalarmultBase(bad_C, rct::skGen());
    EXPECT_FALSE(dao_cl_consistency_verify(*f.CL, *f.pk, ct, bad_C, ctx, p));
}

TEST(dao_cl_consistency, tampered_z_W_rejects)
{
    Fixture f; ASSERT_TRUE(f.init());
    Mpz W, r; rct::key rho, C;
    CL_HSMqk::CipherText ct;
    std::vector<uint8_t> c1b, c2b;
    ASSERT_TRUE(build_case(f, 42, W, r, rho, C, c1b, c2b, ct));
    auto ctx = make_ctx("C_W-Enc(W)");
    dao_cl_pedersen_proof p;
    ASSERT_TRUE(dao_cl_consistency_prove(*f.CL, *f.pk, ct, W, r, C, rho,
                                         ctx, f.randgen, p));

    p.z_W = rct::skGen();
    EXPECT_FALSE(dao_cl_consistency_verify(*f.CL, *f.pk, ct, C, ctx, p));
}

TEST(dao_cl_consistency, tampered_context_rejects)
{
    Fixture f; ASSERT_TRUE(f.init());
    Mpz W, r; rct::key rho, C;
    CL_HSMqk::CipherText ct;
    std::vector<uint8_t> c1b, c2b;
    ASSERT_TRUE(build_case(f, 42, W, r, rho, C, c1b, c2b, ct));
    auto ctx = make_ctx("C_W-Enc(W)");
    dao_cl_pedersen_proof p;
    ASSERT_TRUE(dao_cl_consistency_prove(*f.CL, *f.pk, ct, W, r, C, rho,
                                         ctx, f.randgen, p));

    auto ctx2 = ctx;
    ctx2.vote_height = 1001;
    EXPECT_FALSE(dao_cl_consistency_verify(*f.CL, *f.pk, ct, C, ctx2, p));
}

// ---- Response bound ----

TEST(dao_cl_consistency, oversized_z_r_rejects)
{
    Fixture f; ASSERT_TRUE(f.init());
    Mpz W, r; rct::key rho, C;
    CL_HSMqk::CipherText ct;
    std::vector<uint8_t> c1b, c2b;
    ASSERT_TRUE(build_case(f, 42, W, r, rho, C, c1b, c2b, ct));
    auto ctx = make_ctx("C_W-Enc(W)");
    dao_cl_pedersen_proof p;
    ASSERT_TRUE(dao_cl_consistency_prove(*f.CL, *f.pk, ct, W, r, C, rho,
                                         ctx, f.randgen, p));

    // Inflate z_r beyond the bound.
    Mpz huge(1UL);
    for (int i = 0; i < 800; ++i) Mpz::mulby2(huge, huge);
    Mpz::add(p.z_r, p.z_r, huge);
    EXPECT_FALSE(dao_cl_consistency_verify(*f.CL, *f.pk, ct, C, ctx, p));
}

#endif // VEILROOT_ENABLE_CL
