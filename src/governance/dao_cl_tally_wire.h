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


#include <cstddef>
#include <cstdint>
#include <vector>

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/arith/qfi.hpp"
#include "bicycl/bicycl/proofs/CL_HSMqk_DlogEq_AoK.hpp"

namespace cryptonote {
namespace dao {

// One CL partial decryption. Wire layout is:
//   QFI_wire(w) || SCALAR(u) || QFI_wire(R1) || QFI_wire(R2)
// where QFI_wire(x) = SCALAR(x.a) || SCALAR(x.b) || SCALAR(x.c) and
// SCALAR is the sign-magnitude encoding shared with the DKG payload
// codec. Deserialization validates every QFI against the expected
// class-group discriminant, bounds the total payload, and rejects
// trailing bytes.

constexpr std::size_t DAO_CL_PARTIAL_DECRYPTION_MAX_BYTES = 16384;

bool dao_cl_partial_decryption_serialize(
    const BICYCL::QFI& w,
    const BICYCL::CL_HSMqk_DlogEq_AoK& proof,
    std::vector<uint8_t>& out);

bool dao_cl_partial_decryption_deserialize(
    const std::vector<uint8_t>& in,
    const BICYCL::Mpz& expected_disc,
    BICYCL::QFI& w,
    BICYCL::Mpz& proof_u,
    BICYCL::QFI& proof_R1,
    BICYCL::QFI& proof_R2);

// Canonical CL ciphertext wire: QFI(c1) || QFI(c2).
bool dao_cl_ciphertext_to_wire(const BICYCL::CL_HSMqk::CipherText& ct,
                               std::vector<uint8_t>& out);

bool dao_cl_ciphertext_from_wire(const BICYCL::CL_HSMqk& cl,
                                 const std::vector<uint8_t>& in,
                                 BICYCL::CL_HSMqk::CipherText& out);

// Negate a ciphertext homomorphically (multiply by -1).
bool dao_cl_ciphertext_inverse(const BICYCL::CL_HSMqk& cl,
                               const BICYCL::CL_HSMqk::PublicKey& pk,
                               const BICYCL::CL_HSMqk::CipherText& ct,
                               BICYCL::RandGen& rng,
                               BICYCL::CL_HSMqk::CipherText& out);

// Homomorphically add two ciphertexts.
bool dao_cl_ciphertext_add(const BICYCL::CL_HSMqk& cl,
                           const BICYCL::CL_HSMqk::PublicKey& pk,
                           const BICYCL::CL_HSMqk::CipherText& a,
                           const BICYCL::CL_HSMqk::CipherText& b,
                           BICYCL::RandGen& rng,
                           BICYCL::CL_HSMqk::CipherText& out);

// True iff the given wire encodes the CL ciphertext Enc(0, r=1), i.e.
// the neutral element for additive aggregation. Used to decide whether
// a rollback reduced the aggregate to empty.
bool dao_cl_ciphertext_is_zero_wire(const BICYCL::CL_HSMqk& cl,
                                    const BICYCL::CL_HSMqk::PublicKey& pk,
                                    const std::vector<uint8_t>& wire);

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
