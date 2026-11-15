// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

// Some system headers in this translation unit define a
// setbit(a,i) macro that collides with the bicycl function of
// the same name. Neutralize it here, before bicycl headers are
// pulled in by any include below.
#ifdef setbit
#undef setbit
#endif


#ifdef VEILROOT_ENABLE_CL

#include <array>
#include <cstdint>
#include <vector>

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/arith/qfi.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"

#include "crypto/crypto.h"
#include "governance/dao_consistency_context.h"
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

// DLogEq-only CL consistency proof. Same DLogEq statement as the full
// proof above, without the range proof. Used only for the S channel;
// the direction OR proof combined with the W range proof bounds S to
// +W or -W under the mandatory invariant
//   CL.q() == rct::curveOrder()
//   and 2 * DAO_WEIGHTED_MAX < CL.q()
// which the verifier enforces before evaluating this proof.
struct dao_cl_pedersen_proof_no_range
{
    BICYCL::QFI          A1;
    BICYCL::QFI          A2;
    rct::key             A3;
    std::array<uint8_t, 32> e;
    BICYCL::Mpz          z_r;
    rct::key             z_W;
    rct::key             z_rho;

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

bool dao_cl_consistency_prove_no_range(
    const BICYCL::CL_HSMqk& CL,
    const BICYCL::CL_HSMqk::PublicKey& pk,
    const BICYCL::CL_HSMqk::CipherText& ct,
    const BICYCL::Mpz& plaintext,
    const BICYCL::Mpz& r,
    const rct::key& C,
    const rct::key& rho,
    const dao_consistency_context& ctx,
    BICYCL::RandGen& randgen,
    dao_cl_pedersen_proof_no_range& proof);

bool dao_cl_consistency_verify_no_range(
    const BICYCL::CL_HSMqk& CL,
    const BICYCL::CL_HSMqk::PublicKey& pk,
    const BICYCL::CL_HSMqk::CipherText& ct,
    const rct::key& C,
    const dao_consistency_context& ctx,
    const dao_cl_pedersen_proof_no_range& proof);

// Mandatory modulus invariant, checked by both verifier entry points.
// Returns false unless:
//   CL.q() == rct::curveOrder()   (same plaintext field as Pedersen)
//   and 2 * DAO_WEIGHTED_MAX <  CL.q()   (signed total fits centred)
bool dao_cl_consistency_check_modulus(const BICYCL::CL_HSMqk& CL);

// Direction OR proof extra binding for the CL path. Binds the two
// ciphertext wires and the two serialized proofs so that substituting
// either invalidates the OR challenge. Domain-separated from the
// Paillier binding.
std::vector<uint8_t> dao_cl_extra_binding(
    const std::vector<uint8_t>& E_W,
    const std::vector<uint8_t>& E_S,
    const std::vector<uint8_t>& proof_W_bytes,
    const std::vector<uint8_t>& proof_S_bytes);

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
