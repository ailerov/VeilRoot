// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

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

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
