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


#include <cstdint>
#include <memory>
#include <vector>

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"

#include "ringct/rctTypes.h"

namespace cryptonote {
namespace dao {

// Proposal key, reconstructed from the canonical cl_key_context wire
// (domain || version || len_q || q || k || p || pk_qfi || D).
struct dao_cl_proposal_key
{
    std::shared_ptr<BICYCL::CL_HSMqk> cl;
    std::shared_ptr<BICYCL::CL_HSMqk::PublicKey> pk;
    BICYCL::Mpz q;
    BICYCL::Mpz D;
};

bool dao_cl_load_proposal_key(const std::vector<uint8_t>& cl_key_context_wire,
                              dao_cl_proposal_key& out,
                              uint64_t seclevel_bits = 128);

// Encrypt m under pk with randomness r. Output is canonical ciphertext
// wire: QFI(c1) || QFI(c2).
bool dao_cl_encrypt_at_pk(const BICYCL::CL_HSMqk& cl,
                          const BICYCL::CL_HSMqk::PublicKey& pk,
                          const BICYCL::Mpz& m,
                          const BICYCL::Mpz& r,
                          std::vector<uint8_t>& ct_wire_out);

// Sample valid CL randomness (strictly less than encrypt_randomness_bound).
BICYCL::Mpz dao_cl_sample_randomness(const BICYCL::CL_HSMqk& cl,
                                     BICYCL::RandGen& rng);

// Encode a signed value S as its canonical residue in Z_q:
//   S >= 0  ->  S
//   S <  0  ->  q - |S|
// Rejects |S| >= q.
bool dao_cl_encode_signed_plaintext(const BICYCL::Mpz& s,
                                    const BICYCL::Mpz& q,
                                    BICYCL::Mpz& out);

// Encode a signed value as an rct::key (LE) representing its canonical
// Z_q residue, i.e. the scalar (S mod q). Matches the Pedersen
// commitment exponent used by the CL consistency proof.
bool dao_cl_signed_scalar(const BICYCL::Mpz& s,
                          const BICYCL::Mpz& q,
                          rct::key& out);

// Centred decode of a post-decryption residue in Z_q:
//   m <= q/2  ->  S = m
//   m >  q/2  ->  S = m - q
bool dao_cl_decode_signed_plaintext(const BICYCL::Mpz& m,
                                    const BICYCL::Mpz& q,
                                    BICYCL::Mpz& out);

// Mandatory invariant, checked by wallet and verifier before producing
// or accepting a ballot:
//   q == rct::curveOrder()          (CL plaintext field == Pedersen)
//   2 * DAO_WEIGHTED_MAX  <  q      (centred decode unambiguous)
bool dao_cl_check_ballot_modulus(const BICYCL::CL_HSMqk& cl);

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
