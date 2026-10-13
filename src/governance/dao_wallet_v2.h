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
#include "cryptonote_basic/cryptonote_basic.h"
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
    const crypto::hash& tally_key_id,
    const std::vector<uint8_t>& paillier_modulus,
    uint8_t direction,
    const std::vector<dao_v2_vote_source>& sources,
    vote_proof_v2& out);

// ---------------------------------------------------------------------
// Shared V2 vote transaction construction
//
// These two helpers contain the source-preparation, proof-building and
// transaction-wrapping logic that is otherwise duplicated between
// wallet2::create_vote_v2_tx() and its tests. They are wallet-free: the
// caller supplies the ring data and the real output's spend material,
// and the helper returns a fully-formed TX_VERSION_DAO_VOTE
// transaction with the vote_v2 payload.
// ---------------------------------------------------------------------

// One ring member, as selected by the caller.
struct dao_v2_ring_member_data
{
    rct::key P{};
    rct::key C{};
    uint64_t global_index = 0;
    uint64_t height       = 0;
};

// One owned eligible output plus its ring. `ring` includes the real
// output at position `real_index`.
struct dao_v2_vote_output
{
    std::vector<dao_v2_ring_member_data> ring;
    size_t             real_index = 0;

    crypto::secret_key output_secret{};   // x_l
    rct::key           mask{};            // Pedersen mask of C_l
    uint64_t           amount = 0;        // atomic units
};

// Convert one owned output into the wire-form source struct.
bool prepare_dao_v2_vote_source(const dao_v2_vote_output& in,
                                dao_v2_vote_source& out);

// Prepare every output, build the proof, and wrap it in a
// TX_VERSION_DAO_VOTE transaction (zero vin, zero vout, RCTTypeNull,
// one governance_object::vote_v2 payload).
bool build_dao_v2_vote_tx(
    const crypto::hash& proposal_id,
    uint64_t proposal_submission_height,
    uint64_t vote_height,
    const crypto::hash& tally_key_id,
    const std::vector<uint8_t>& paillier_modulus,
    uint8_t direction,
    const std::vector<dao_v2_vote_output>& outputs,
    transaction& tx_out);

} // namespace dao
} // namespace cryptonote
