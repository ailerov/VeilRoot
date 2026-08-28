// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance_engine.h"
#include "governance.h"

namespace cryptonote {

GovernanceEngine::GovernanceEngine() = default;
GovernanceEngine::~GovernanceEngine() = default;

bool GovernanceEngine::initialize(BlockchainDB& db, const governance_params& params, network_type nettype)
{
    m_impl = std::make_unique<GovernanceManager>(db, params, nettype);
    return true;
}

bool GovernanceEngine::process_block(const block& blk, uint64_t height)
{
    return m_impl->process_block(blk, height);
}

void GovernanceEngine::rollback_block(const block& blk, const std::vector<transaction>& txs, uint64_t height)
{
    m_impl->rollback_block(blk, txs, height);
}

bool GovernanceEngine::is_proposal_passed(uint64_t yes_weight, uint64_t no_weight,
                                          uint64_t yes_balance, uint64_t no_balance,
                                          uint64_t voting_end_height) const
{
    return m_impl->is_proposal_passed(yes_weight, no_weight, yes_balance, no_balance, voting_end_height);
}

TreasuryManager& GovernanceEngine::treasury() {
    return m_impl->treasury();
}
const TreasuryManager& GovernanceEngine::treasury() const {
    return m_impl->treasury();
}

std::vector<proposal_record> GovernanceEngine::get_ready_executions(uint64_t current_height) const
{
    return m_impl->get_ready_executions(current_height);
}

uint64_t GovernanceEngine::get_governance_parameter(governance_parameter param, uint64_t height) const
{
    if (!m_impl)
    {
        MERROR("GovernanceEngine::get_governance_parameter called with null m_impl – initialization order bug?");
        // Defaults matching ParameterManager::get_parameter fallbacks.
        switch (param)
        {
            case governance_parameter::proposal_submission_fee: return 10000000ULL;
            case governance_parameter::voting_quorum_percent:   return 10;
            case governance_parameter::treasury_ratio:          return 18;
            case governance_parameter::execution_delay:         return 720;
            case governance_parameter::voting_period_days:      return 14;
            default: return 0;
        }
    }
    return m_impl->get_governance_parameter(param, height);
}

// BEGIN_VNS_PROCESS_VOTE
vote_result GovernanceEngine::process_vote(const transaction& tx, uint64_t height, bool dry_run)
{
    return m_impl->process_vote(tx, height, dry_run);
}
// END_VNS_PROCESS_VOTE

// BEGIN_VNS_RECOVER_OVERDUE
void GovernanceEngine::recover_overdue_executions(uint64_t current_height)
{
    m_impl->recover_overdue_executions(current_height);
}
// END_VNS_RECOVER_OVERDUE

} // namespace cryptonote