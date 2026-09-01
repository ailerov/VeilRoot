// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "governance_db.h"
#include "governance_params.h"
#include "cryptonote_basic/cryptonote_basic.h"

namespace cryptonote {

class LifecycleManager {
public:
    LifecycleManager(GovernanceDB& db, const governance_params& params);

    bool process_block(uint64_t height);
    bool rollback_block(uint64_t height);

private:
    bool evaluate_proposal(const crypto::hash& proposal_id, uint64_t height);
    bool is_quorum_met(uint64_t yes_b, uint64_t no_b, uint64_t voting_end_height) const;
    bool is_majority_met(uint64_t yes_w, uint64_t no_w) const;

    GovernanceDB& m_db;
    const governance_params& m_params;
};

} // namespace cryptonote