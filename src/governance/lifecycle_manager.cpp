// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "lifecycle_manager.h"
#include "cryptonote_core/blockchain.h"   // for proposal_record, proposal_status (if any)
#include "cryptonote_config.h"
#include "misc_log_ex.h"
#include <algorithm>
#include <utility>

namespace cryptonote {

namespace {

bool has_pending_dao_v2_tally(
    const GovernanceDB& db, const proposal_record& rec)
{
    if (rec.tally_key_id == crypto::null_hash)
        return false;

    dao_proposal_aggregate aggregate;
    if (!db.get_underlying_db().get_dao_proposal_aggregate(
            rec.proposal_id, aggregate))
        return false;

    return !aggregate.aggregate_E_W.empty() &&
           !aggregate.aggregate_E_S.empty() &&
           !aggregate.aggregate_E_B.empty();
}

} // namespace

LifecycleManager::LifecycleManager(GovernanceDB& db, const governance_params& params)
    : m_db(db), m_params(params) {}

bool LifecycleManager::process_block(uint64_t height)
{    std::vector<crypto::hash> due_proposals;
    m_db.get_voting_end_entries(height, due_proposals);

    // The LMDB voting-end index is queried by exact height. If an older
    // event was missed (for example during an upgrade), it will never be
    // returned by a later exact-height lookup. Catch up ACTIVE proposals
    // whose voting windows have already closed.
    std::vector<std::pair<crypto::hash, proposal_record>> expired_active;
    m_db.for_all_proposals(
        [&](const crypto::hash& proposal_id,
            const proposal_record& rec) -> bool {
            if (!rec.executed && rec.status == PROPOSAL_STATUS_ACTIVE &&
                rec.voting_end_height < height)
                expired_active.emplace_back(proposal_id, rec);
            return true;
        });

    for (const auto& item : expired_active)
    {
        // A complete encrypted DAO V2 aggregate still needs committee
        // decryption and a canonical tally-result transaction. Do not turn
        // that legitimate pending tally into a zero-vote rejection.
        if (has_pending_dao_v2_tally(m_db, item.second))
            continue;
        if (std::find(due_proposals.begin(), due_proposals.end(), item.first) ==
            due_proposals.end())
            due_proposals.push_back(item.first);
    }

    // Filter due queue entries with a real encrypted DAO V2 tally before
    // opening the write transaction. Their queue records can be removed,
    // but their proposal status must remain ACTIVE until the tally-result
    // transaction is committed.
    std::vector<crypto::hash> pending_tally_due;
    std::vector<crypto::hash> proposals_to_evaluate;
    for (const auto& pid : due_proposals)
    {
        proposal_record rec;
        if (m_db.get_proposal(pid, rec) &&
            rec.status == PROPOSAL_STATUS_ACTIVE &&
            has_pending_dao_v2_tally(m_db, rec))
            pending_tally_due.push_back(pid);
        else
            proposals_to_evaluate.push_back(pid);
    }
    due_proposals.swap(proposals_to_evaluate);

    if (due_proposals.empty() && pending_tally_due.empty())
        return true;
// BEGIN_VNS_LIFECYCLE_TXN
    try { m_db.block_wtxn_start(); }
    catch (const std::exception& e) {
        MERROR("Lifecycle: failed to start write txn: " << e.what());
        return false;
    }

    try {
        for (const auto& pid : pending_tally_due)
        {
            proposal_record rec;
            if (m_db.get_proposal(pid, rec))
                m_db.remove_voting_end_entry(rec.voting_end_height + 1, pid);
        }
        for (const auto& pid : due_proposals)
        {
            proposal_record rec;
            if (!m_db.get_proposal(pid, rec))
                continue;
            if (!rec.executed && rec.status == PROPOSAL_STATUS_ACTIVE &&
                !evaluate_proposal(pid, height))
            {
                throw std::runtime_error("evaluate_proposal failed for " + epee::string_tools::pod_to_hex(pid));
            }
            // Remove the original scheduled key, not the catch-up height.
            m_db.remove_voting_end_entry(rec.voting_end_height + 1, pid);
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
    }    if (rec.status != PROPOSAL_STATUS_ACTIVE)
        return true;

    // Missing legacy outcome means there were no ordinary V1 votes. Proposals
    // with a complete encrypted DAO V2 aggregate were filtered before this
    // write transaction; the remaining no-outcome case is zero participation.
    uint64_t yes_w = 0, no_w = 0, yes_b = 0, no_b = 0;
    if (!m_db.get_outcome(proposal_id, yes_w, no_w, yes_b, no_b)) {
        MINFO("Lifecycle: no vote outcome for proposal " << proposal_id
              << "; treating participation as zero");
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
    vns_supply_t minted = m_db.get_block_already_generated_coins(effective_height);
    uint64_t treasury = m_db.get_treasury_balance();
    uint64_t burned = m_db.get_total_burned_fees();
    vns_supply_t circulating = (minted > treasury + burned) ? (minted - treasury - burned) : 0;
    vns_supply_t quorum = circulating * m_params.voting_quorum_percent / 100;
    return participating >= quorum;
}

bool LifecycleManager::is_majority_met(uint64_t yes_w, uint64_t no_w) const
{
    return yes_w > no_w;
}

} // namespace cryptonote