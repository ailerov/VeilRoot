// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"

namespace cryptonote {

// Transcript for the hidden-direction OR proof, spec §21.
// Everything the challenge binds goes here.
struct dao_or_context
{
    uint8_t       version     = 2;
    crypto::hash  proposal_id;
    uint64_t      vote_height = 0;

    std::vector<rct::key> nullifiers;    // one per vote input
    std::vector<uint64_t> key_offsets;   // concatenated, per input in order

    // Reserved for the threshold ciphertexts introduced in a later commit.
    // Empty until then. Bound as-is so the challenge does not change when
    // the ciphertexts start being produced.
    std::vector<uint8_t>  extra_binding;

    rct::key C_W;
    rct::key C_S;
};

// 2-branch Schnorr OR proof (Chaum-Pedersen), Fiat-Shamir.
//
//   branch 0 (YES): D_yes = C_S - C_W, dlog = R_S - R_W
//   branch 1 (NO):  D_no  = C_S + C_W, dlog = R_S + R_W
//
// Prover knows exactly one discrete log. Verifier learns neither.
struct dao_vote_or_proof
{
    rct::key c_yes;
    rct::key s_yes;
    rct::key c_no;
    rct::key s_no;
};

// Prove direction. `direction_yes` selects which branch the prover knows.
// R_S, R_W are the aggregate blinding scalars (wallet-private).
bool dao_or_prove(const dao_or_context& ctx,
                  bool direction_yes,
                  const rct::key& R_S,
                  const rct::key& R_W,
                  dao_vote_or_proof& proof);

// Verify. Returns true iff one branch was proven and the challenge closes.
bool dao_or_verify(const dao_or_context& ctx,
                   const dao_vote_or_proof& proof);

} // namespace cryptonote