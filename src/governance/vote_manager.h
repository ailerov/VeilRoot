// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <unordered_set>

#include "governance_db.h"
#include "governance_params.h"
#include "vote_proof.h"
#include "vote_proof_v2.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "vote_result.h"

namespace cryptonote {

// Classification of a transaction with respect to DAO vote objects.
enum class vote_kind
{
    none,      // no governance vote object
    v1,        // one governance_object::vote
    v2,        // one governance_object::vote_v2
    malformed, // unparseable or unknown governance object type
    multiple   // more than one vote object of any kind
};

class VoteManager {
public:
    VoteManager(GovernanceDB& db, const governance_params& params);

    bool process_block(const block& blk, uint64_t height);
    bool rollback_block(const block& blk, uint64_t height);

    // BEGIN_VNS_PROCESS_VOTE
    vote_result process_vote(const transaction& tx, uint64_t height, bool dry_run);
    // END_VNS_PROCESS_VOTE

    bool vote_exists(const crypto::hash& proposal_id, const crypto::hash& nullifier) const;

private:
    bool validate_vote(const vote_proof& vp, uint64_t height) const;
    bool is_vote_tx(const transaction& tx) const;
    bool extract_vote(const transaction& tx, vote_proof& vp) const;
    bool extract_vote_v2(const transaction& tx, vote_proof_v2& vp) const;

    vote_kind classify_vote_tx(const transaction& tx) const;

    vote_result process_v1_vote(const transaction& tx, uint64_t height, bool dry_run);
    vote_result process_v2_vote(const transaction& tx,
                                const crypto::hash& tx_hash,
                                uint64_t height,
                                std::unordered_set<crypto::hash>& block_nullifiers,
                                bool dry_run);

    bool apply_dao_vote(const vote_proof_v2& proof, const crypto::hash& tx_hash);

    GovernanceDB& m_db;
    const governance_params& m_params;
};

} // namespace cryptonote