// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "governance_db.h"
#include "proposal.h"
#include "execution.h"
#include "treasury.h"
#include "vote_proof_verifier.h"
#include "governance_params.h"
#include "vote_manager.h"
#include "lifecycle_manager.h"
#include "parameter_manager.h"

namespace cryptonote {

class GovernanceManager
{
public:
    GovernanceManager(BlockchainDB& db, const governance_params& params, network_type nettype);

    bool process_block(const block& blk, uint64_t height);
    void rollback_block(const block& blk, const std::vector<transaction>& txs, uint64_t height);

    bool record_vote(const vote_proof& proof, uint64_t current_height);
    // BEGIN_VNS_PROCESS_VOTE
    vote_result process_vote(const transaction& tx, uint64_t height, bool dry_run);
    // END_VNS_PROCESS_VOTE
    bool is_proposal_passed(uint64_t yes_weight, uint64_t no_weight,
                            uint64_t yes_balance, uint64_t no_balance,
                            uint64_t voting_end_height) const;

    GovernanceDB& db() { return m_db; }

    TreasuryManager& treasury() { return m_treasury; }
    const TreasuryManager& treasury() const { return m_treasury; }
    std::vector<proposal_record> get_ready_executions(uint64_t current_height) const;
    uint64_t get_governance_parameter(governance_parameter param, uint64_t height) const;
    void recover_overdue_executions(uint64_t current_height);

private:
    GovernanceDB m_db;
    governance_params m_params;
    ProposalManager m_proposals;
    TreasuryManager m_treasury;
    ExecutionManager m_execution;
    VoteManager m_votes;
    LifecycleManager m_lifecycle;
    ParameterManager m_parameters;
};

} // namespace cryptonote