// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "vote_proof_verifier.h"

namespace cryptonote {

verification_result VoteProofVerifier::verify(
    const vote_proof& proof,
    const aggregate_vote_proof& agg_proof,
    BlockchainDB& db,
    const Blockchain& blockchain,
    uint64_t current_height)
{
    // stub – always success
    return {true, "Stub verification passed"};
}

} // namespace cryptonote