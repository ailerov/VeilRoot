// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Signed-integer VSS for DAO V2 resharing. Distinct from the bootstrap
// VSS in dao_dkg.{h,cpp}: this one commits over the Paillier group
// Z*_{N^2} with base V, and permits signed coefficients.
//
// Construction (expert §2):
//   q_i(x)  = mu_i * s_i + Delta * sum_{k=1..t_new-1} b_{i,k} x^k
//   C_i,0   = V^(mu_i * s_i)          mod N^2
//   C_i,k   = V^(Delta * b_{i,k})     mod N^2     k >= 1
//   V^q_i(j) == C_i,0 * prod_k C_i,k^(j^k)  mod N^2
//   VK'_j   = prod_i ( C_i,0 * prod_k C_i,k^(j^k) )  mod N^2
//   VK'_j   = V^(Delta * s'_j)        mod N^2
//
// The common-exponent proof for C_i,0 is in dao_reshare_proof.{h,cpp}.
// The integer range for b_{i,k} is a parameter of the deal function;
// the source-derived bound is established separately before production
// integration.

#ifndef VEILROOT_DAO_RESHARE_VSS_H
#define VEILROOT_DAO_RESHARE_VSS_H

#include <cstdint>
#include <vector>

#include <openssl/bn.h>

#include "crypto/crypto.h"
#include "governance/dao_paillier.h"

namespace cryptonote {
namespace dao {

// Signed serialization: 1 sign byte (0 = nonneg, 1 = negative) then
// 512 bytes of big-endian magnitude.
constexpr size_t DAO_RESHARE_SIGNED_BYTES = 1 + 1024;

void dao_reshare_serialize_signed(const BIGNUM* x, std::vector<uint8_t>& out);
bool dao_reshare_deserialize_signed(const std::vector<uint8_t>& in,
                                     BIGNUM* out);

struct dao_reshare_vss_commitments
{
    uint32_t t_new = 0;                      // new threshold - 1 (degree)
    std::vector<uint8_t> C_0;                // PAILLIER_CT_BYTES
    std::vector<std::vector<uint8_t>> C_k;   // PAILLIER_CT_BYTES each

    bool serialize(std::vector<uint8_t>& out) const;
    bool deserialize(const std::vector<uint8_t>& in);
};

struct dao_reshare_vss_share
{
    uint32_t j = 0;
    std::vector<uint8_t> q_i_j;   // signed serialization
};

bool dao_reshare_vss_deal(
    const PaillierPublicKey& pk,
    const std::vector<uint8_t>& V_bytes,
    const BIGNUM* s_i,
    const BIGNUM* mu_i,
    const BIGNUM* delta,
    uint32_t t_new,
    const std::vector<uint32_t>& new_indices,
    uint32_t range_bits,
    dao_reshare_vss_commitments& commits_out,
    std::vector<dao_reshare_vss_share>& shares_out);

bool dao_reshare_vss_verify(
    const PaillierPublicKey& pk,
    const std::vector<uint8_t>& V_bytes,
    const dao_reshare_vss_commitments& commits,
    uint32_t j,
    const std::vector<uint8_t>& q_i_j);

bool dao_reshare_vss_compute_vk(
    const PaillierPublicKey& pk,
    const std::vector<uint8_t>& V_bytes,
    const std::vector<dao_reshare_vss_commitments>& all_commits,
    uint32_t j,
    std::vector<uint8_t>& VK_j_out);

} // namespace dao
} // namespace cryptonote

#endif
