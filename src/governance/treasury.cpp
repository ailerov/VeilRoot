// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "treasury.h"
#include "misc_log_ex.h"
#include "cryptonote_core/blockchain.h"   // for proposal_execution_record

namespace cryptonote {

TreasuryManager::TreasuryManager(GovernanceDB& db) : m_db(db) {}

uint64_t TreasuryManager::get_balance() const {
    return m_db.get_treasury_balance();
}

void TreasuryManager::credit_emission(uint64_t amount) {
    if (amount == 0) return;
    uint64_t balance = m_db.get_treasury_balance();
    // Check overflow (shouldn't happen with sane emission)
    if (balance > std::numeric_limits<uint64_t>::max() - amount) {
        MERROR("Treasury balance overflow when crediting " << amount);
        return;
    }
    m_db.set_treasury_balance(balance + amount);
    MINFO("Treasury credited with " << amount << ", new balance: " << (balance + amount));
}

bool TreasuryManager::execute_grant(const crypto::hash& proposal_id, uint64_t amount) {
    if (amount == 0) {
        MERROR("Grant amount is zero for proposal " << proposal_id);
        return false;
    }

    uint64_t balance = m_db.get_treasury_balance();
    if (balance < amount) {
        MERROR("Insufficient treasury balance (" << balance << ") for grant of " << amount << " (proposal " << proposal_id << ")");
        return false;
    }

    uint64_t new_balance = balance - amount;
    m_db.set_treasury_balance(new_balance);

    // Store execution record (amount is already in proposal_record, but we store it here for audit)
    proposal_execution_record rec;
    rec.proposal_id = proposal_id;
    rec.execution_height = 0; // will be set by caller (ExecutionManager)
    // We don't have execution_tx_hash yet – we can set it to null for now.
    rec.execution_tx_hash = crypto::null_hash;
    m_db.add_execution_record(rec);

    MINFO("Executed grant of " << amount << " from treasury for proposal " << proposal_id << ", new balance: " << new_balance);
    return true;
}

void TreasuryManager::rollback_grant(const crypto::hash& proposal_id, uint64_t amount) {
    if (amount == 0) return;
    uint64_t balance = m_db.get_treasury_balance();
    // Check overflow (shouldn't happen if rollback is correct)
    if (balance > std::numeric_limits<uint64_t>::max() - amount) {
        MERROR("Treasury balance overflow when rolling back grant of " << amount << " for proposal " << proposal_id);
        return;
    }
    m_db.set_treasury_balance(balance + amount);
    m_db.remove_execution_record(proposal_id);
    MINFO("Rolled back grant of " << amount << " for proposal " << proposal_id << ", new balance: " << (balance + amount));
}

uint64_t TreasuryManager::get_burned_fees() const {
    return m_db.get_burned_fees();
}

void TreasuryManager::add_burned_fees(uint64_t amount) {
    if (amount == 0) return;
    m_db.add_burned_fees(amount);
    MINFO("Burned fees increased by " << amount << ", total burned: " << m_db.get_burned_fees());
}

} // namespace cryptonote