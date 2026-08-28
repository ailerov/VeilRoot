// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "execution.h"

namespace cryptonote {

ExecutionManager::ExecutionManager(GovernanceDB& db, TreasuryManager& treasury, ProposalManager& proposals)
    : m_db(db), m_treasury(treasury), m_proposals(proposals) {}

void ExecutionManager::execute_due(uint64_t current_height) {
    std::vector<std::pair<uint64_t, crypto::hash>> due_entries;
    m_db.get_pending_executions(current_height, due_entries);

    for (const auto& [exec_height, pid] : due_entries) {
        proposal_record rec;
        if (!m_db.get_proposal(pid, rec)) {
            MERROR("Pending execution proposal not found: " << pid);
            m_db.remove_pending_execution(exec_height, pid);
            continue;
        }
        if (rec.status != PROPOSAL_STATUS_PASSED) {
            if (rec.executed || rec.status == PROPOSAL_STATUS_EXECUTED) {
                MDEBUG("Proposal " << pid << " already executed; removing stale pending execution entry");
            } else if (rec.status == PROPOSAL_STATUS_REJECTED) {
                MDEBUG("Proposal " << pid << " was rejected; removing pending execution entry");
            } else {
                MWARNING("Proposal " << pid << " in pending queue but not in PASSED state, skipping");
            }
            m_db.remove_pending_execution(exec_height, pid);
            continue;
        }
        // Execution handled by block-connection path; no treasury mutation here
    }
}

void ExecutionManager::rollback(const crypto::hash& proposal_id) {
    proposal_record rec;
    if (m_db.get_proposal(proposal_id, rec)) {
        if (rec.status == PROPOSAL_STATUS_EXECUTED || rec.status == PROPOSAL_STATUS_FAILED_EXECUTION) {
            // Capture the execution record before removing it.
            proposal_execution_record exec_record;
            bool have_exec_record = m_db.get_execution_record(proposal_id, exec_record);

            uint64_t previous_status_height = rec.status_height;
            if (have_exec_record && exec_record.pre_execution_status_height != 0)
                previous_status_height = exec_record.pre_execution_status_height;

            rec.status = PROPOSAL_STATUS_PASSED;
            rec.executed = false;
            rec.status_height = previous_status_height;

            m_db.store_proposal(rec);

            if (have_exec_record)
                m_db.remove_execution_record(proposal_id);

            MINFO("Rolled back execution of proposal " << proposal_id);
        }
    }
}

} // namespace cryptonote