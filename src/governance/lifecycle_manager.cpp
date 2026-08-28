// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "lifecycle_manager.h"
#include "cryptonote_core/blockchain.h"   // for proposal_record, proposal_status (if any)
#include "cryptonote_config.h"
#include "misc_log_ex.h"

namespace cryptonote {

LifecycleManager::LifecycleManager(GovernanceDB& db, const governance_params& params)
    : m_db(db), m_params(params) {}

bool LifecycleManager::process_block(uint64_t height)
{
    std::vector<crypto::hash> due_proposals;
    m_db.get_voting_end_entries(height, due_proposals);

    if (due_proposals.empty())
        return true;

    // BEGIN_VNS_LIFECYCLE_TXN
    try { m_db.block_wtxn_start(); }
    catch (const std::exception& e) {
        MERROR("Lifecycle: failed to start write txn: " << e.what());
        return false;
    }

    try {
        for (const auto& pid : due_proposals)
        {
            proposal_record rec;
            if (!m_db.get_proposal(pid, rec))
                continue;
            if (rec.executed)
                continue;
            if (!evaluate_proposal(pid, height))
            {
                throw std::runtime_error("evaluate_proposal failed for " + epee::string_tools::pod_to_hex(pid));
            }
            m_db.remove_voting_end_entry(height, pid);
        }

        m_db.block_wtxn_stop();
        return true;
    }
    catch (const std::exception& e) {
        m_db.block_wtxn_abort();
        MERROR("Lifecycle process_block failed: " << e.what());
        return false;
    }
    // END_VNS_LIFECYCLE_TXN
}

bool LifecycleManager::rollback_block(uint64_t height)
{
    // Rollback is handled by GovernanceManager using the block disconnection.
    // We don't need to do anything here – the proposal statuses will be reverted
    // by removing the block that changed them.
    return true;
}

bool LifecycleManager::evaluate_proposal(const crypto::hash& proposal_id, uint64_t height)
{
    proposal_record rec;
    if (!m_db.get_proposal(proposal_id, rec)) {
        MERROR("Proposal " << proposal_id << " not found");
        return false;
    }

    if (rec.status != PROPOSAL_STATUS_ACTIVE)
        return true;

    uint64_t yes_w, no_w, yes_b, no_b;
    if (!m_db.get_outcome(proposal_id, yes_w, no_w, yes_b, no_b)) {
        MERROR("No outcome record for proposal " << proposal_id);
        return false;
    }

    bool quorum_met = is_quorum_met(yes_b, no_b, rec.voting_end_height);
    bool majority_met = is_majority_met(yes_w, no_w);

    if (quorum_met && majority_met) {
        rec.status = PROPOSAL_STATUS_PASSED;
        // BEGIN_VNS_PENDING_EXECUTION
        uint64_t execution_delay = 0;
        if (!m_db.get_parameter(governance_parameter::execution_delay, height, execution_delay) || execution_delay == 0)
            execution_delay = 720; // fallback
        uint64_t execution_height = rec.voting_end_height + execution_delay;
        m_db.add_pending_execution(execution_height, proposal_id);
        // END_VNS_PENDING_EXECUTION
        MINFO("Proposal " << proposal_id << " PASSED. Execution scheduled at height " << execution_height);
    } else {
        rec.status = PROPOSAL_STATUS_REJECTED;
        MINFO("Proposal " << proposal_id << " REJECTED. Quorum: " << (quorum_met ? "met" : "not met") << ", Majority: " << (majority_met ? "yes" : "no"));

        // Unlock an exact-domain policy target when the proposal is rejected.
        pending_domain_policy_record pending;
        if (m_db.get_pending_domain_policy_by_proposal(proposal_id, pending))
            m_db.remove_pending_domain_policy_by_domain(std::string(pending.domain,
                strnlen(pending.domain, sizeof(pending.domain))));
    }
    rec.status_height = height;

    m_db.store_proposal(rec);
    return true;
}

bool LifecycleManager::is_quorum_met(uint64_t yes_b, uint64_t no_b, uint64_t voting_end_height) const
{
    uint64_t participating = yes_b + no_b;
    // Cap height to current DB height to avoid out-of-range exceptions
    uint64_t effective_height = std::min(voting_end_height, m_db.height());
    uint64_t minted = m_db.get_block_already_generated_coins(effective_height);
    uint64_t treasury = m_db.get_treasury_balance();
    uint64_t burned = m_db.get_total_burned_fees();
    uint64_t circulating = (minted > treasury + burned) ? (minted - treasury - burned) : 0;
    uint64_t quorum = circulating * m_params.voting_quorum_percent / 100;
    return participating >= quorum;
}

bool LifecycleManager::is_majority_met(uint64_t yes_w, uint64_t no_w) const
{
    return yes_w > no_w;
}

} // namespace cryptonote