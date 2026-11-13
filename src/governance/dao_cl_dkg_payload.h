// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/arith/qfi.hpp"
#include "bicycl/bicycl/proofs/CL_HSMqk_Batch_Dlog_AoK.hpp"

namespace cryptonote {
namespace dao {

// Reconstructs a peer's batch Dlog AoK from its public (u, R) parts.
// The base class keeps this constructor protected so that only the
// verifier path can rebuild a proof object without the prover's
// secret inputs.
class CLBatchDlogAoKExposed : public BICYCL::CL_HSMqk_Batch_Dlog_AoK
{
public:
    CLBatchDlogAoKExposed(const BICYCL::Mpz& u, const BICYCL::QFI& R)
        : BICYCL::CL_HSMqk_Batch_Dlog_AoK(u, R) {}
};

// Subtype of one CL DKG message. Every subtype shares the outer
// dkg_msg_type::cl_dkg_envelope; the outer header carries the routing
// fields (sender, recipient, proposal, committee) unchanged.
enum class cl_dkg_subtype : uint8_t
{
    keygen_commitments   = 0x01,
    keygen_batch_proof   = 0x02,
    keygen_private_share = 0x03,
    keygen_complaint     = 0x04,
    keygen_complete      = 0x05,
};

// One canonical CL DKG payload. The body is subtype-specific; the
// envelope prepends a fixed domain, version, subtype, and length.
struct cl_dkg_payload
{
    cl_dkg_subtype        subtype = cl_dkg_subtype::keygen_complete;
    std::vector<uint8_t>  body;

    bool serialize(std::vector<uint8_t>& out) const;
    static bool deserialize(const std::vector<uint8_t>& in, cl_dkg_payload& out);
};

bool cl_dkg_encode_commitments(const std::vector<BICYCL::QFI>& C,
                               cl_dkg_payload& out);
bool cl_dkg_decode_commitments(const cl_dkg_payload& in,
                               std::vector<BICYCL::QFI>& out,
                               const BICYCL::Mpz& expected_disc,
                               std::size_t max_count);

bool cl_dkg_encode_batch_proof(const BICYCL::Mpz& u,
                               const BICYCL::QFI& R,
                               cl_dkg_payload& out);
bool cl_dkg_decode_batch_proof(const cl_dkg_payload& in,
                               BICYCL::Mpz& u_out,
                               BICYCL::QFI& R_out,
                               const BICYCL::Mpz& expected_disc);

bool cl_dkg_encode_private_share(const BICYCL::Mpz& y,
                                 cl_dkg_payload& out);
bool cl_dkg_decode_private_share(const cl_dkg_payload& in,
                                 BICYCL::Mpz& y_out);

bool cl_dkg_encode_complete(cl_dkg_payload& out);
bool cl_dkg_decode_complete(const cl_dkg_payload& in);

bool cl_dkg_encode_complaint(uint32_t against_sender_id,
                             uint32_t reason,
                             cl_dkg_payload& out);
bool cl_dkg_decode_complaint(const cl_dkg_payload& in,
                             uint32_t& against_sender_id,
                             uint32_t& reason);

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
