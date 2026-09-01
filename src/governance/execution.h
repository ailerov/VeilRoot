// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "governance_db.h"
#include "treasury.h"
#include "proposal.h"

namespace cryptonote {

class ExecutionManager
{
public:
    ExecutionManager(GovernanceDB& db, TreasuryManager& treasury, ProposalManager& proposals);

    void execute_due(uint64_t current_height);
    void rollback(const crypto::hash& proposal_id);

private:
    GovernanceDB& m_db;
    TreasuryManager& m_treasury;
    ProposalManager& m_proposals;
};

} // namespace cryptonote