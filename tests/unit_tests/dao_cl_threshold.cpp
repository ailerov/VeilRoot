// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#ifdef VEILROOT_ENABLE_CL

#include <cstring>
#include <memory>

#include "gtest/gtest.h"

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/cl/CL_threshold.hpp"

#include "governance/dao_cl_threshold.h"
#include "governance/dao_crypto_backend.h"
#include "ringct/rctOps.h"

using namespace cryptonote;
using namespace cryptonote::dao;
using namespace BICYCL;

namespace {

constexpr unsigned long kSecLevel = 128;
constexpr unsigned long kSoundness = 16;  // bytes

std::shared_ptr<CL_HSMqk> make_cl(RandGen& randgen)
{
    rct::key L = rct::curveOrder();
    std::array<uint8_t, 32> be{};
    for (size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
    Mpz q(std::vector<unsigned char>(be.begin(), be.end()));
    std::random_device rd;
    randgen.set_seed(Mpz(static_cast<unsigned long>(rd())));
    SecLevel sl(static_cast<int>(kSecLevel));
    return std::make_shared<CL_HSMqk>(q, 1, sl, randgen, CL_Params{kSecLevel});
}

std::vector<uint8_t> mpz_to_bytes_be(const Mpz& v)
{
    if (v.is_zero()) return {};
    std::vector<unsigned char> vec =
        static_cast<std::vector<unsigned char>>(v);
    return std::vector<uint8_t>(vec.begin(), vec.end());
}

} // namespace

// ---- Keygen tests ----

TEST(dao_cl_threshold, keygen_3_of_3_produces_pk)
{
    RandGen rg;
    auto cl = make_cl(rg);
    CLCommittee committee(cl, 3, 1, kSoundness);
    ASSERT_TRUE(committee.run_keygen_inproc(rg));

    const auto& pk = committee.public_key();
    EXPECT_EQ(pk.elt().discriminant(), cl->Cl_G().discriminant());
    EXPECT_EQ(cl->genus(pk.elt()), CL_HSMqk::Genus({1, 1}));
}

TEST(dao_cl_threshold, keygen_5_of_3_produces_pk)
{
    RandGen rg;
    auto cl = make_cl(rg);
    CLCommittee committee(cl, 5, 2, kSoundness);
    ASSERT_TRUE(committee.run_keygen_inproc(rg));
    EXPECT_EQ(committee.n(), 5u);
    EXPECT_EQ(committee.t_plus_1(), 3u);
}

TEST(dao_cl_threshold, serialize_public_params_roundtrip)
{
    RandGen rg;
    auto cl = make_cl(rg);
    CLCommittee committee(cl, 3, 1, kSoundness);
    ASSERT_TRUE(committee.run_keygen_inproc(rg));

    std::vector<uint8_t> params;
    ASSERT_TRUE(committee.serialize_public_params(params));
    EXPECT_GT(params.size(), 0u);

    // Fresh backend from serialized params.
    auto backend = make_paillier_backend(params);
    // Should be nullptr - this is CL params not Paillier.
    EXPECT_EQ(backend, nullptr);

    auto cl_backend = make_cl_backend(128);
    (void)cl_backend;  // single-party constructor works
    auto fresh = make_cl_backend(128);
    ASSERT_NE(fresh, nullptr);
    ASSERT_TRUE(fresh->deserialize_modulus(params));

    // Fresh backend can encrypt.
    BIGNUM* m = BN_new(); BN_set_word(m, 12345);
    BIGNUM* r = BN_new();
    ASSERT_TRUE(fresh->sample_r(r));
    std::vector<uint8_t> ct;
    ASSERT_TRUE(fresh->encrypt(m, r, ct));
    EXPECT_GT(ct.size(), 0u);

    BN_free(m); BN_free(r);
}

// ---- Encryption + threshold decryption ----

TEST(dao_cl_threshold, ballot_encrypted_under_committee_pk_is_decryptable)
{
    RandGen rg;
    auto cl = make_cl(rg);
    CLCommittee committee(cl, 3, 1, kSoundness);
    ASSERT_TRUE(committee.run_keygen_inproc(rg));

    // Encrypt under the committee's shared pk.
    const auto& pk = committee.public_key();
    Mpz m_int(54321UL);
    CL_HSMqk::ClearText m(*cl, m_int);
    CL_HSMqk::CipherText ct = cl->encrypt(pk, m, rg);

    // Two players (0 and 1) partially decrypt.
    ASSERT_TRUE(committee.partial_decrypt(0, ct, rg));
    ASSERT_TRUE(committee.partial_decrypt(1, ct, rg));

    // Exchange partials.
    committee.add_partial_dec(0, 1, committee.partial_dec_for_test(1));
    committee.add_partial_dec(1, 0, committee.partial_dec_for_test(0));

    // Verify + combine at player 0.
    ASSERT_TRUE(committee.verify_partials(0, rg));
    CL_HSMqk::ClearText out(*cl, Mpz(0UL));
    ASSERT_TRUE(committee.combine(0, out, ct));

    // Recovered plaintext equals original.
    Mpz recovered = static_cast<Mpz>(out);
    EXPECT_EQ(recovered, m_int);

    // Same result via players 1 and 2.
    ASSERT_TRUE(committee.partial_decrypt(1, ct, rg));
    ASSERT_TRUE(committee.partial_decrypt(2, ct, rg));
    committee.add_partial_dec(1, 2, committee.partial_dec_for_test(2));
    committee.add_partial_dec(2, 1, committee.partial_dec_for_test(1));

    ASSERT_TRUE(committee.verify_partials(1, rg));
    CL_HSMqk::ClearText out2(*cl, Mpz(0UL));
    ASSERT_TRUE(committee.combine(1, out2, ct));
    EXPECT_EQ(static_cast<Mpz>(out2), m_int);
}

TEST(dao_cl_threshold, wire_ciphertext_roundtrip)
{
    RandGen rg;
    auto cl = make_cl(rg);
    CLCommittee committee(cl, 3, 1, kSoundness);
    ASSERT_TRUE(committee.run_keygen_inproc(rg));

    const auto& pk = committee.public_key();
    Mpz m_int(999UL);
    CL_HSMqk::ClearText m(*cl, m_int);
    CL_HSMqk::CipherText ct = cl->encrypt(pk, m, rg);

    std::vector<uint8_t> ct_bytes;
    ASSERT_TRUE(committee.ciphertext_to_bytes(ct, ct_bytes));
    EXPECT_GT(ct_bytes.size(), 0u);

    CL_HSMqk::CipherText parsed;  // placeholder, overwritten below
    ASSERT_TRUE(committee.ciphertext_from_bytes(ct_bytes, parsed));

    // Two-party threshold decryption of the parsed ciphertext.
    ASSERT_TRUE(committee.partial_decrypt(0, parsed, rg));
    ASSERT_TRUE(committee.partial_decrypt(2, parsed, rg));
    committee.add_partial_dec(0, 2, committee.partial_dec_for_test(2));
    committee.add_partial_dec(2, 0, committee.partial_dec_for_test(0));

    ASSERT_TRUE(committee.verify_partials(0, rg));
    CL_HSMqk::ClearText out(*cl, Mpz(0UL));
    ASSERT_TRUE(committee.combine(0, out, parsed));
    EXPECT_EQ(static_cast<Mpz>(out), m_int);
}

#endif // VEILROOT_ENABLE_CL
