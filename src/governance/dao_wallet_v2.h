// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// DAO V2 vote construction, shared by the wallet and by tests. No
// wallet dependencies: the caller provides real ring data and the
// module returns a fully-formed vote_proof_v2.
//
// This mirrors tests/unit_tests/v2_vote_builder.h but on real chain
// data. The verifier in vote_proof_verifier.cpp is the reference for
// every field and every proof context.

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "governance/vote_proof_v2.h"

namespace cryptonote {
namespace dao {

// One owned eligible output and its ring.
struct dao_v2_vote_source
{
    // Ring. All vectors must have the same length, and it must equal
    // the ring size the caller intends to use.
    std::vector<rct::key> P;                // ring one-time output keys
    std::vector<rct::key> C;                // ring amount commitments
    std::vector<uint64_t> output_indices;   // absolute output indices
    std::vector<uint64_t> output_heights;   // chain heights
    std::vector<uint64_t> key_offsets;      // relative offsets (same order)
    size_t                real_index = 0;

    // Real output.
    crypto::secret_key    real_spend_secret{};   // x_l
    rct::key              real_mask{};           // Pedersen mask of C_l
    uint64_t              real_amount = 0;       // atomic units
};

// Build a fully-valid vote_proof_v2.
//
// direction: 0 = YES, 1 = NO.
//
// paillier_modulus: 256-byte big-endian Paillier N of the epoch.
//
// Returns false if the input set is empty or malformed.
bool build_dao_v2_vote(
    const crypto::hash& proposal_id,
    uint64_t proposal_submission_height,
    uint64_t vote_height,
    uint32_t tally_key_epoch,
    const crypto::hash& tally_key_id,
    const std::vector<uint8_t>& paillier_modulus,
    uint8_t direction,
    const std::vector<dao_v2_vote_source>& sources,
    vote_proof_v2& out);

} // namespace dao
} // namespace cryptonote
