// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"

namespace cryptonote {

// Per-input context for a DAO V2 weighted CLSAG.
// Every value supplied here must be derived from the blockchain by the
// caller, never from the transaction being validated (spec §32).
struct dao_clsag_context
{
    crypto::hash proposal_id;
    uint64_t     proposal_submission_height = 0;
    uint64_t     vote_height                = 0;
    uint64_t     tally_key_epoch            = 0;

    std::vector<rct::key> P;              // ring one-time output keys
    std::vector<rct::key> C;              // ring RingCT amount commitments
    std::vector<uint64_t> output_indices; // absolute output indices
    std::vector<uint64_t> output_heights; // blockchain output heights
    std::vector<uint8_t>  age_factors;    // f_i per ring member

    rct::key V;                           // per-input weight commitment
};

// H_vote(P, proposal_id) per spec §14, using the Monero hash-to-curve
// pipeline with a domain-separated input.
rct::key dao_hash_to_point(const rct::key& P, const crypto::hash& proposal_id);

// Canonical CLSAG message transcript for a DAO V2 vote input, per spec §12.
rct::key dao_clsag_message(const dao_clsag_context& ctx,
                           const rct::key& N,
                           const rct::key& V);

// Generate a DAO V2 weighted CLSAG for one hidden ring member.
// output_secret is x_l; weight_blinding is rho_l.
bool dao_clsag_generate(const dao_clsag_context& ctx,
                        size_t real_index,
                        const crypto::secret_key& output_secret,
                        const rct::key& weight_blinding,
                        rct::clsag& sig);

// Verify a DAO V2 weighted CLSAG.
bool dao_clsag_verify(const dao_clsag_context& ctx,
                      const rct::clsag& sig);

} // namespace cryptonote