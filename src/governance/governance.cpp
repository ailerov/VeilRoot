// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance.h"
#include <unordered_set>
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "serialization/binary_archive.h"
#include "span.h"
#include "governance/parameter_update.h"

namespace cryptonote {

GovernanceManager::GovernanceManager(BlockchainDB& db, const governance_params& params, network_type nettype)
    : m_db(db, nettype), m_params(params), m_proposals(m_db, m_params), m_votes(m_db, m_params), m_treasury(m_db), m_execution(m_db, m_treasury, m_proposals), m_lifecycle(m_db, m_params), m_parameters(m_db)
{
}

bool GovernanceManager::process_block(const block& blk, uint64_t height)
{
    if (!m_proposals.process_block(blk, height)) {
        return false;
    }
    if (!m_votes.process_block(blk, height)) {
        return false;
    }
    if (!m_lifecycle.process_block(height)) {
        return false;
    }
    m_execution.execute_due(height);
    if (!m_parameters.process_block(height)) {
        return false;
    }
    return true;
}

void GovernanceManager::rollback_block(const block& blk, const std::vector<transaction>& txs, uint64_t height)
{
    // 1. Execution rollback – must run before proposal removal
    for (const auto& tx : txs)
    {
        for (const auto& in : tx.vin)
        {
            if (in.type() == typeid(txin_treasury))
            {
                const auto& treas_in = boost::get<txin_treasury>(in);
                m_execution.rollback(treas_in.proposal_id);
            }
        }
    }

    // BEGIN_VNS_PARAMETER_EXECUTION_ROLLBACK
    for (const auto& tx : txs)
    {
        std::vector<tx_extra_field> extra_fields;
        if (!parse_tx_extra(tx.extra, extra_fields))
            continue;

        for (const auto& field : extra_fields)
        {
            if (field.type() == typeid(tx_extra_governance_payload))
            {
                const auto& gp_field = boost::get<tx_extra_governance_payload>(field);
                if (gp_field.payload.type == governance_object::execution)
                {
                    parameter_execution_payload payload;
                    epee::span<const uint8_t> span(gp_field.payload.data.data(), gp_field.payload.data.size());
                    binary_archive<false> ar(span);
                    if (::serialization::serialize(ar, payload))
                        m_execution.rollback(payload.proposal_id);
                }
            }
        }
    }
    // END_VNS_PARAMETER_EXECUTION_ROLLBACK

    // 2. Vote rollback – nullifier removal + tally reversal + vote-record removal
    m_votes.rollback_block(blk, height);

    // 3. Lifecycle rollback – currently a no‑op
    m_lifecycle.rollback_block(height);

    // 4. Proposal & parameters – must run last
    m_proposals.rollback_block(blk, txs, height);
    m_parameters.rollback_block(height);
}

bool GovernanceManager::record_vote(const vote_proof& proof, uint64_t current_height) {
    return true; // stub
}

// BEGIN_VNS_PROPOSAL_PASSING
bool GovernanceManager::is_proposal_passed(uint64_t yes_weight, uint64_t no_weight,
                                           uint64_t yes_balance, uint64_t no_balance,
                                           uint64_t voting_end_height) const
{
    // Cap the height to the current DB height to avoid future-block errors
    uint64_t effective_height = std::min(voting_end_height, m_db.height());

    uint64_t minted = m_db.get_block_already_generated_coins(effective_height);
    uint64_t treasury = m_db.get_treasury_balance();
    uint64_t burned = m_db.get_total_burned_fees();
    uint64_t circulating = (minted > treasury + burned) ? (minted - treasury - burned) : 0;

    governance_params gp;
    if (!m_db.get_governance_params(gp))
        gp = governance_params::default_params();
    uint64_t required_quorum = circulating * gp.voting_quorum_percent / 100;

    bool quorum_met = (yes_balance + no_balance) >= required_quorum;
    bool majority_met = (yes_weight > no_weight);

    return quorum_met && majority_met;
}
// END_VNS_PROPOSAL_PASSING

std::vector<proposal_record> GovernanceManager::get_ready_executions(uint64_t current_height) const
{
    std::vector<proposal_record> ready;

    // BEGIN_VNS_DETERMINISTIC_EXECUTION
    // Execution eligibility is deterministically derived from chain state.
    // The pending_executions table is a cache, not a consensus requirement.
    uint64_t exec_delay = 0;
    if (!m_db.get_parameter(governance_parameter::execution_delay, current_height, exec_delay))
        exec_delay = 720;   // fallback default

    m_db.for_all_proposals([&](const crypto::hash& pid, const proposal_record& rec) -> bool
    {
        if (rec.executed || rec.status != PROPOSAL_STATUS_PASSED)
            return true;   // continue

        uint64_t exec_height = rec.voting_end_height + exec_delay;
        if (current_height >= exec_height)
            ready.push_back(rec);

        return true;
    });
    // END_VNS_DETERMINISTIC_EXECUTION

    return ready;
}

// BEGIN_VNS_RECOVER_OVERDUE
void GovernanceManager::recover_overdue_executions(uint64_t current_height)
{
    uint64_t exec_delay = 0;
    m_db.get_parameter(governance_parameter::execution_delay, current_height, exec_delay);
    if (exec_delay == 0) exec_delay = 720;

    // Build set of already pending proposal IDs to avoid duplicates
    std::vector<std::pair<uint64_t, crypto::hash>> pending_entries;
    m_db.get_pending_executions(current_height, pending_entries);
    std::unordered_set<crypto::hash> already_pending;
    for (const auto& [h, pid] : pending_entries)
        already_pending.insert(pid);

    // Collect proposals that need a pending execution entry
    struct overdue {
        crypto::hash id;
        uint64_t exec_height;
        bool needs_status_fix;  // true if status must be updated to PASSED
    };
    std::vector<overdue> to_recover;

    m_db.for_all_proposals([&](const crypto::hash& pid, const proposal_record& rec) -> bool {
        if (rec.executed)
            return true;
        uint64_t scheduled = rec.voting_end_height + exec_delay;
        if (scheduled > current_height)
            return true;

        bool should_execute = (rec.status == PROPOSAL_STATUS_PASSED);
        bool needs_fix = false;
        if (!should_execute && rec.status == PROPOSAL_STATUS_ACTIVE)
        {
            // Status update may have been lost; check outcome for majority
            uint64_t yes_w = 0, no_w = 0, yes_b = 0, no_b = 0;
            if (m_db.get_outcome(pid, yes_w, no_w, yes_b, no_b))
            {
                if (yes_w > no_w)
                {
                    should_execute = true;
                    needs_fix = true;
                }
            }
        }
        if (!should_execute)
            return true;

        if (already_pending.count(pid) == 0)
        {
            to_recover.push_back({pid, scheduled, needs_fix});
        }
        else if (needs_fix)
        {
            // Already pending but status still wrong; we need to update status
            to_recover.push_back({pid, scheduled, true});  // will be skipped for pending addition but status fixed
        }
        return true;
    });

    // Now write pending entries and fix statuses outside the read transaction
    if (!to_recover.empty())
    {
        try { m_db.block_wtxn_start(); }
        catch (const std::exception& e) {
            MERROR("Recovery: failed to start write txn: " << e.what());
            return;
        }

        try {
            for (const auto& item : to_recover)
            {
                // Fix status if needed
                if (item.needs_status_fix)
                {
                    proposal_record rec;
                    if (m_db.get_proposal(item.id, rec))
                    {
                        if (rec.status == PROPOSAL_STATUS_ACTIVE && !rec.executed)
                        {
                            rec.status = PROPOSAL_STATUS_PASSED;
                            rec.status_height = current_height;
                            m_db.store_proposal(rec);
                        }
                    }
                }

                // Add pending execution if not already present
                if (already_pending.count(item.id) == 0)
                {
                    m_db.add_pending_execution(item.exec_height, item.id);
                }
            }
            m_db.block_wtxn_stop();
        }
        catch (const std::exception& e) {
            m_db.block_wtxn_abort();
            MERROR("Recovery: write failed: " << e.what());
        }
    }
}
// END_VNS_RECOVER_OVERDUE

uint64_t GovernanceManager::get_governance_parameter(governance_parameter param, uint64_t height) const
{
    return m_parameters.get_parameter(param, height);
}

vote_result GovernanceManager::process_vote(const transaction& tx, uint64_t height, bool dry_run)
{
    return m_votes.process_vote(tx, height, dry_run);
}

} // namespace cryptonote