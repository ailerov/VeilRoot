// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_tally_wire.h"

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "ringct/rctOps.h"

#include <array>
#include <memory>

using namespace cryptonote::dao;

namespace {

static std::shared_ptr<BICYCL::CL_HSMqk>
make_cl(BICYCL::RandGen& rng, uint64_t seed)
{
    rng.set_seed(BICYCL::Mpz(static_cast<unsigned long>(seed)));
    std::array<uint8_t, 32> be{};
    const auto L = rct::curveOrder();
    for (size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
    BICYCL::Mpz q(std::vector<uint8_t>(be.begin(), be.end()));
    BICYCL::SecLevel sl(128);
    return std::make_shared<BICYCL::CL_HSMqk>(
        q, 1, sl, rng, BICYCL::CL_Params(static_cast<size_t>(128)));
}

static BICYCL::CL_HSMqk_DlogEq_AoK
make_proof(const BICYCL::CL_HSMqk& cl, BICYCL::RandGen& rng,
           const BICYCL::Mpz& x, const BICYCL::QFI& f1, const BICYCL::QFI& f2)
{
    BICYCL::QFI q1, q2;
    cl.Cl_G().nupow(q1, f1, x);
    cl.Cl_G().nupow(q2, f2, x);
    return BICYCL::CL_HSMqk_DlogEq_AoK(cl, 16, rng, x, f1, f2, q1, q2);
}

TEST(dao_cl_tally_wire, partial_decryption_roundtrip)
{
    BICYCL::RandGen rng;
    auto cl = make_cl(rng, 111UL);
    ASSERT_TRUE(cl);

    BICYCL::Mpz x(54321UL);
    BICYCL::QFI f1 = cl->h();
    BICYCL::QFI f2;
    cl->Cl_G().nupow(f2, f1, BICYCL::Mpz(2UL));
    auto proof = make_proof(*cl, rng, x, f1, f2);

    BICYCL::QFI w = f1;

    std::vector<uint8_t> wire;
    ASSERT_TRUE(dao_cl_partial_decryption_serialize(w, proof, wire));
    ASSERT_FALSE(wire.empty());
    ASSERT_LE(wire.size(), DAO_CL_PARTIAL_DECRYPTION_MAX_BYTES);

    BICYCL::QFI w_out, R1_out, R2_out;
    BICYCL::Mpz u_out;
    ASSERT_TRUE(dao_cl_partial_decryption_deserialize(
        wire, cl->Cl_G().discriminant(), w_out, u_out, R1_out, R2_out));

    EXPECT_EQ(w_out, w);
    EXPECT_EQ(u_out, proof.u());
    EXPECT_EQ(R1_out, proof.R1());
    EXPECT_EQ(R2_out, proof.R2());
}

TEST(dao_cl_tally_wire, partial_decryption_rejects_wrong_discriminant)
{
    BICYCL::RandGen rng1;
    auto cl_a = make_cl(rng1, 222UL);
    BICYCL::RandGen rng2;
    auto cl_b = make_cl(rng2, 333UL);
    ASSERT_TRUE(cl_a);
    ASSERT_TRUE(cl_b);
    ASSERT_NE(cl_a->Cl_G().discriminant(), cl_b->Cl_G().discriminant());

    BICYCL::Mpz x(99UL);
    BICYCL::QFI f1 = cl_a->h();
    BICYCL::QFI f2;
    cl_a->Cl_G().nupow(f2, f1, BICYCL::Mpz(2UL));
    auto proof = make_proof(*cl_a, rng1, x, f1, f2);
    BICYCL::QFI w = f1;

    std::vector<uint8_t> wire;
    ASSERT_TRUE(dao_cl_partial_decryption_serialize(w, proof, wire));

    BICYCL::QFI w_out, R1_out, R2_out;
    BICYCL::Mpz u_out;
    EXPECT_FALSE(dao_cl_partial_decryption_deserialize(
        wire, cl_b->Cl_G().discriminant(), w_out, u_out, R1_out, R2_out));
}

TEST(dao_cl_tally_wire, partial_decryption_rejects_truncated_and_trailing)
{
    BICYCL::RandGen rng;
    auto cl = make_cl(rng, 444UL);
    ASSERT_TRUE(cl);

    BICYCL::Mpz x(12345UL);
    BICYCL::QFI f1 = cl->h();
    BICYCL::QFI f2;
    cl->Cl_G().nupow(f2, f1, BICYCL::Mpz(2UL));
    auto proof = make_proof(*cl, rng, x, f1, f2);
    BICYCL::QFI w = f1;

    std::vector<uint8_t> wire;
    ASSERT_TRUE(dao_cl_partial_decryption_serialize(w, proof, wire));

    BICYCL::QFI w_out, R1_out, R2_out;
    BICYCL::Mpz u_out;

    // Truncated
    for (size_t cut = 1; cut < wire.size(); cut += 7) {
        std::vector<uint8_t> t(wire.begin(), wire.begin() + (wire.size() - cut));
        EXPECT_FALSE(dao_cl_partial_decryption_deserialize(
            t, cl->Cl_G().discriminant(), w_out, u_out, R1_out, R2_out))
            << "cut=" << cut;
    }

    // Trailing byte
    std::vector<uint8_t> t = wire;
    t.push_back(0);
    EXPECT_FALSE(dao_cl_partial_decryption_deserialize(
        t, cl->Cl_G().discriminant(), w_out, u_out, R1_out, R2_out));

    // Empty and oversized
    std::vector<uint8_t> empty;
    EXPECT_FALSE(dao_cl_partial_decryption_deserialize(
        empty, cl->Cl_G().discriminant(), w_out, u_out, R1_out, R2_out));
    std::vector<uint8_t> big(DAO_CL_PARTIAL_DECRYPTION_MAX_BYTES + 1, 0);
    EXPECT_FALSE(dao_cl_partial_decryption_deserialize(
        big, cl->Cl_G().discriminant(), w_out, u_out, R1_out, R2_out));
}

} // namespace

#endif // VEILROOT_ENABLE_CL
