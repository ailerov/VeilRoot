// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#ifdef VEILROOT_ENABLE_CL

#include <array>
#include <cstdint>
#include <vector>

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/arith/qfi.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"

#include "crypto/crypto.h"
#include "governance/dao_consistency.h"
#include "ringct/rctTypes.h"

namespace cryptonote {
namespace dao {

// Range proof that a Pedersen commitment opens to an integer in
// [0, DAO_WEIGHTED_MAX]. Uses one aggregated 8-output Bulletproof+
// proof over two 34-bit limbs of W, two 34-bit limbs of the
// complement D = DAO_WEIGHTED_MAX - W, and four complementary values.
struct dao_cl_range_proof
{
    rct::BulletproofPlus bp;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

// Proof that a CL ciphertext binds the same integer that a RingCT
// Pedersen commitment contains, with that integer in the DAO range.
// Statement: c1 = h^r, c2 = f^W * pk^r, C = W*H + rho*G,
//            0 <= W <= DAO_WEIGHTED_MAX.
struct dao_cl_pedersen_proof
{
    BICYCL::QFI          A1;    // CL.Cl_G()
    BICYCL::QFI          A2;    // CL.Delta()
    rct::key             A3;    // RingCT first-message commitment
    std::array<uint8_t, 32> e;  // Fiat-Shamir challenge (big-endian)
    BICYCL::Mpz          z_r;   // positive integer response
    rct::key             z_W;   // shared plaintext response (mod q)
    rct::key             z_rho; // Pedersen blinding response (mod q)
    dao_cl_range_proof   range;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

bool dao_cl_consistency_prove(
    const BICYCL::CL_HSMqk& CL,
    const BICYCL::CL_HSMqk::PublicKey& pk,
    const BICYCL::CL_HSMqk::CipherText& ct,
    const BICYCL::Mpz& W,
    const BICYCL::Mpz& r,
    const rct::key& C,
    const rct::key& rho,
    const dao_consistency_context& ctx,
    BICYCL::RandGen& randgen,
    dao_cl_pedersen_proof& proof);

bool dao_cl_consistency_verify(
    const BICYCL::CL_HSMqk& CL,
    const BICYCL::CL_HSMqk::PublicKey& pk,
    const BICYCL::CL_HSMqk::CipherText& ct,
    const rct::key& C,
    const dao_consistency_context& ctx,
    const dao_cl_pedersen_proof& proof);

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
