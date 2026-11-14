// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_cl_ballot.h"
#include "governance/dao_crypto_backend.h"

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl.hpp"
#include "ringct/rctOps.h"

#include <array>
#include <memory>

using namespace cryptonote::dao;

namespace {

TEST(DaoClBallot, signed_plaintext_roundtrip)
{
    std::array<uint8_t, 32> be{};
    const auto L = rct::curveOrder();
    for (size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
    BICYCL::Mpz q(std::vector<uint8_t>(be.begin(), be.end()));

    for (long long v : {0LL, 1LL, 1000LL, -1LL, -1000LL}) {
        BICYCL::Mpz s(static_cast<unsigned long>(std::llabs(v)));
        if (v < 0) s.neg();
        BICYCL::Mpz canon;
        ASSERT_TRUE(dao_cl_encode_signed_plaintext(s, q, canon));
        ASSERT_GE(canon.sgn(), 0);
        ASSERT_TRUE(canon < q);

        BICYCL::Mpz back;
        ASSERT_TRUE(dao_cl_decode_signed_plaintext(canon, q, back));
        EXPECT_EQ(back, s) << "v=" << v;
    }
}

TEST(DaoClBallot, rejects_out_of_range_signed_plaintext)
{
    BICYCL::Mpz q(1000UL);
    BICYCL::Mpz s(1000UL);
    BICYCL::Mpz out;
    EXPECT_FALSE(dao_cl_encode_signed_plaintext(s, q, out));
    s = BICYCL::Mpz(1000UL); s.neg();
    EXPECT_FALSE(dao_cl_encode_signed_plaintext(s, q, out));
}

TEST(DaoClBallot, signed_scalar_matches_canonical_residue)
{
    std::array<uint8_t, 32> be{};
    const auto L = rct::curveOrder();
    for (size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
    BICYCL::Mpz q(std::vector<uint8_t>(be.begin(), be.end()));

    BICYCL::Mpz s(42UL); s.neg();
    rct::key scalar;
    ASSERT_TRUE(dao_cl_signed_scalar(s, q, scalar));

    BICYCL::Mpz canon;
    ASSERT_TRUE(dao_cl_encode_signed_plaintext(s, q, canon));
    auto canon_be = static_cast<std::vector<unsigned char>>(canon);
    EXPECT_LE(canon_be.size(), 32u);
    for (size_t i = 0; i < canon_be.size(); ++i)
        EXPECT_EQ(scalar.bytes[i], canon_be[canon_be.size() - 1 - i]);
}

} // namespace

#endif // VEILROOT_ENABLE_CL
