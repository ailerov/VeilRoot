// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>

#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "governance/voting_weight.h"

namespace cryptonote {

// Per-output weighted Pedersen commitment, spec §16-§18.
//
//   Q_i = f_i * C_i
//   V_i = Q_i + rho_i * G
//
// Expanding Q_i = f_i * (mask_i*G + amount_i*H):
//
//   V_i = (f_i*mask_i + rho_i) * G  +  (f_i*amount_i) * H
//       = total_blinding_i * G + W_i * H
//
// where:
//   W_i            = amount_i * f_i
//   total_blinding = f_i*mask_i + rho_i
//
// The CLSAG binds V_i to the hidden output via C_offset = V_i and
// z = -rho_i. The aggregate commitment C_W = Σ V_i therefore has
// blinding Σ total_blinding_i, not Σ rho_i.
//
// Spec §19 writes "R_W = Σ rho_i" without including the f_i*mask_i
// term that §17's expansion produces. The implementation uses the
// mathematically correct total_blinding; the notation mismatch is
// documented in the commit that introduced the aggregate.
struct dao_output_weight
{
    rct::key            commitment;      // V_i
    rct::key            rho_i;           // CLSAG blinding (z = -rho_i)
    rct::key            total_blinding;  // f_i*mask_i + rho_i
    governance_weight_t weight;          // W_i = amount_i * f_i
};

// Aggregate commitment for one logical wallet vote, spec §19-§20.
//
//   C_W      = Σ V_i                            (on wire)
//   W_total  = Σ W_i                            (wallet-private)
//   R_W      = Σ total_blinding_i               (wallet-private)
//   C_S      = +W_total * H + R_S * G  for YES  (on wire)
//   C_S      = -W_total * H + R_S * G  for NO
struct dao_vote_aggregate
{
    rct::key            C_W;
    rct::key            C_S;
    rct::key            R_S;
    rct::key            R_W;
    governance_weight_t W_total;
    bool                direction_yes = true;
    size_t              num_inputs    = 0;
};

// Build V_i and total_blinding from the wallet's private inputs.
//
//   amount      - output amount in atomic units
//   age_factor  - f_i, from calculate_voting_weight
//   C_i         - RingCT Pedersen amount commitment for this output
//   mask_i      - wallet-private mask of this output
//   rho_i       - fresh random scalar (CLSAG blinding)
bool dao_commit_output_weight(uint64_t amount,
                              uint8_t  age_factor,
                              const rct::key& C_i,
                              const rct::key& mask_i,
                              const rct::key& rho_i,
                              dao_output_weight& out);

void dao_aggregate_init(dao_vote_aggregate& agg);

bool dao_accumulate_output(dao_vote_aggregate& agg,
                           const dao_output_weight& ow);

bool dao_finalize_aggregate(dao_vote_aggregate& agg,
                            bool yes,
                            const rct::key& R_S);

bool dao_verify_aggregate(const dao_vote_aggregate& agg);

void dao_weight_to_scalar(const governance_weight_t& w, rct::key& out);

} // namespace cryptonote