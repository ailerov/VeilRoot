// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Scheme-neutral DAO consistency transcript context and vote-input
// transcript. Split out of dao_consistency.h so CL code does not
// depend on other equality-proof implementations.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "crypto/hash.h"
#include "ringct/rctTypes.h"

namespace cryptonote {
namespace dao {

// Transcript context bound into the Fiat-Shamir challenge.
struct dao_consistency_context
{
    // Domain separator, e.g. "C_W-Enc(W)" or "C_S-Enc(S)". Different
    // domains make the two proofs independent even when other fields
    // match.
    std::string          domain;
    uint8_t              version = 2;
    crypto::hash         proposal_id;
    uint64_t             vote_height = 0;
    crypto::hash         tally_key_id{};
    std::vector<uint8_t> vote_input_transcript;
};

// Canonical vote-input transcript (spec section 11). Built by the wallet and
// reconstructed identically by the verifier from chain state. Its
// 32-byte SHA-256 digest is bound by proof_W, proof_S, and the
// top-level transcript_hash. The OR proof's extra_binding is a
// separate object and does not call this function.
struct dao_vote_transcript_input
{
    uint8_t              version = 2;
    crypto::hash         proposal_id;
    uint64_t             proposal_submission_height = 0;
    uint64_t             vote_height                = 0;
    crypto::hash         tally_key_id{};

    std::vector<std::vector<uint64_t>> key_offsets;
    std::vector<std::vector<uint64_t>> absolute_indices;
    std::vector<std::vector<rct::key>> P;
    std::vector<std::vector<rct::key>> C;
    std::vector<std::vector<uint64_t>> output_heights;
    std::vector<std::vector<uint8_t>>  age_factors;
    std::vector<crypto::hash>          nullifiers;
    std::vector<rct::key>              balance_commitments;

    rct::key             C_W;
    rct::key             C_S;
    rct::key             C_B;
    std::vector<uint8_t> E_W;
    std::vector<uint8_t> E_S;
    std::vector<uint8_t> E_B;
};

// Returns SHA-256(canonical_encoding). Exactly 32 bytes. Returns empty
// on any structural violation.
std::vector<uint8_t> dao_vote_input_transcript(
    const dao_vote_transcript_input& in);

} // namespace dao
} // namespace cryptonote
