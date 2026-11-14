// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_cl_tally_wire.h"

#ifdef VEILROOT_ENABLE_CL

#include "governance/dao_cl_dkg_payload.h"

namespace cryptonote {
namespace dao {

bool dao_cl_partial_decryption_serialize(
    const BICYCL::QFI& w,
    const BICYCL::CL_HSMqk_DlogEq_AoK& proof,
    std::vector<uint8_t>& out)
{
    out.clear();
    if (!cl_dkg_qfi_to_bytes(out, w)) return false;
    if (!cl_dkg_mpz_to_bytes_signed(out, proof.u())) return false;
    if (!cl_dkg_qfi_to_bytes(out, proof.R1())) return false;
    if (!cl_dkg_qfi_to_bytes(out, proof.R2())) return false;
    if (out.size() > DAO_CL_PARTIAL_DECRYPTION_MAX_BYTES) {
        out.clear();
        return false;
    }
    return true;
}

bool dao_cl_partial_decryption_deserialize(
    const std::vector<uint8_t>& in,
    const BICYCL::Mpz& expected_disc,
    BICYCL::QFI& w,
    BICYCL::Mpz& proof_u,
    BICYCL::QFI& proof_R1,
    BICYCL::QFI& proof_R2)
{
    if (in.empty() || in.size() > DAO_CL_PARTIAL_DECRYPTION_MAX_BYTES)
        return false;
    std::size_t off = 0;
    if (!cl_dkg_qfi_from_bytes(in, off, w, expected_disc)) return false;
    if (!cl_dkg_mpz_from_bytes_signed(in, off, proof_u, true)) return false;
    if (!cl_dkg_qfi_from_bytes(in, off, proof_R1, expected_disc)) return false;
    if (!cl_dkg_qfi_from_bytes(in, off, proof_R2, expected_disc)) return false;
    return off == in.size();
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
