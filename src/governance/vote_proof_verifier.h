// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "vote_proof.h"
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
    static verification_result verify(
        const vote_proof& proof,
        const aggregate_vote_proof& agg_proof,
        BlockchainDB& db,
        const Blockchain& blockchain,
        uint64_t current_height
    );
};

} // namespace cryptonote