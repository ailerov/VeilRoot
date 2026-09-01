// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "governance_db.h"
#include "governance_params.h"
#include "vote_proof.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "vote_result.h"

namespace cryptonote {

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

    GovernanceDB& m_db;
    const governance_params& m_params;
};

} // namespace cryptonote