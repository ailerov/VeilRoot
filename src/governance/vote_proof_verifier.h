// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <string>
#include <unordered_set>

#include "governance/vote_proof_v2.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_core/blockchain.h"  // for proposal_record

namespace cryptonote {

struct verification_result
{
    bool success;
    std::string reason;
};

class VoteProofVerifier
{
public:
    // Read-only with respect to DAO consensus state. Block-processing
    // performs the state mutation (spec section 20 step 25) after this
    // returns success. `block_nullifiers` carries the DAO nullifiers of
    // the other DAO V2 votes already accepted in this block.
    static verification_result verify(
        const vote_proof_v2& proof,
        BlockchainDB& db,
        const Blockchain& blockchain,
        uint64_t block_height,
        const std::unordered_set<crypto::hash>& block_nullifiers);
};

} // namespace cryptonote