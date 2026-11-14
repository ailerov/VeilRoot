// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/cl/CL_threshold.hpp"
#include "bicycl/bicycl/arith/qfi.hpp"
#include "bicycl/bicycl/proofs/CL_HSMqk_Batch_Dlog_AoK.hpp"
#include "bicycl/bicycl/proofs/CL_HSMqk_DlogEq_AoK.hpp"

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

// Reconstructs a peer's DLog-Eq AoK from its public (u, R1, R2) parts.
// The base class keeps the (u, R1, R2) constructor protected so that
// only the verifier path can rebuild a proof without the prover's
// witness.
class CLDlogEqAoKExposed : public BICYCL::CL_HSMqk_DlogEq_AoK
{
public:
    CLDlogEqAoKExposed(const BICYCL::Mpz& u,
                       const BICYCL::QFI& R1,
                       const BICYCL::QFI& R2)
        : BICYCL::CL_HSMqk_DlogEq_AoK(u, R1, R2) {}
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

    reshare_prestate        = 0x10,
    reshare_contribution    = 0x11,
    reshare_private_share   = 0x12,
    reshare_complete        = 0x13,
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

// One reshare contribution as it travels on the wire. This is the
// public part only; each recipient's private share arrives on a
// separate unicast message.
struct cl_reshare_contribution_wire
{
    uint32_t                 dealer_id = 0;
    BICYCL::Mpz              c_i;
    BICYCL::Mpz              q_i;
    BICYCL::Mpz              r_i;
    BICYCL::Mpz              L_i;
    std::vector<BICYCL::QFI> commitments;
    BICYCL::Mpz              batch_u;
    BICYCL::QFI              batch_R;
    BICYCL::Mpz              link_u;
    BICYCL::QFI              link_R1;
    BICYCL::QFI              link_R2;
};

bool cl_dkg_encode_reshare_prestate(uint32_t dealer_id,
                                    const BICYCL::Mpz& q_i,
                                    const BICYCL::Mpz& r_i,
                                    const BICYCL::Mpz& L_i,
                                    cl_dkg_payload& out);
bool cl_dkg_decode_reshare_prestate(const cl_dkg_payload& in,
                                    uint32_t& dealer_id,
                                    BICYCL::Mpz& q_i,
                                    BICYCL::Mpz& r_i,
                                    BICYCL::Mpz& L_i);

bool cl_dkg_encode_reshare_contribution(
    const cl_reshare_contribution_wire& in, cl_dkg_payload& out);
bool cl_dkg_decode_reshare_contribution(
    const cl_dkg_payload& in,
    const BICYCL::Mpz& expected_disc,
    std::size_t max_commitments,
    cl_reshare_contribution_wire& out);

bool cl_dkg_encode_reshare_private_share(const BICYCL::Mpz& share,
                                         cl_dkg_payload& out);
bool cl_dkg_decode_reshare_private_share(const cl_dkg_payload& in,
                                         BICYCL::Mpz& out);

bool cl_dkg_encode_reshare_complete(cl_dkg_payload& out);
bool cl_dkg_decode_reshare_complete(const cl_dkg_payload& in);

// DERIVE q FROM Ed25519 SUBGROUP ORDER (matches CL encryption backend).
// CONSTRUCTS AN HSMqk INSTANCE WITH q = CURVE ORDER, k = 1, AND THE
// GIVEN SECURITY LEVEL. callers must supply a RandGen seeded from
// their own entropy source.
std::shared_ptr<BICYCL::CL_HSMqk> cl_dkg_make_hsmq(
    std::size_t seclevel_bits, BICYCL::RandGen& randgen);

// CANONICAL WIRE HELPERS USED BY THE RUNNER AND ANY CONSENSUS-SIDE
// DECODER.
void cl_dkg_mpz_to_bytes_be(std::vector<uint8_t>& out, const BICYCL::Mpz& v);
bool cl_dkg_mpz_to_bytes_signed(std::vector<uint8_t>& out, const BICYCL::Mpz& v);
bool cl_dkg_qfi_to_bytes(std::vector<uint8_t>& out, const BICYCL::QFI& f);
bool cl_dkg_qfi_from_bytes(const std::vector<uint8_t>& in, std::size_t& off,
                           BICYCL::QFI& out, const BICYCL::Mpz& expected_disc);
bool cl_dkg_mpz_from_bytes_signed(const std::vector<uint8_t>& in,
                                  std::size_t& off, BICYCL::Mpz& out,
                                  bool allow_negative = true);

// Canonical gamma-map codec. Entries are sorted by player id so
// the output is byte-identical regardless of the source map's
// iteration order.
bool cl_dkg_serialize_gammas(
    const BICYCL::CL_Threshold_Static::ParticipantsValueMap<BICYCL::QFI>& g,
    std::vector<uint8_t>& out);
bool cl_dkg_deserialize_gammas(
    const std::vector<uint8_t>& in,
    const BICYCL::Mpz& expected_disc,
    BICYCL::CL_Threshold_Static::ParticipantsValueMap<BICYCL::QFI>& out);

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
