// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "parameter_manager.h"
#include "misc_log_ex.h"

namespace cryptonote {

ParameterManager::ParameterManager(GovernanceDB& db) : m_db(db) {}

bool ParameterManager::process_block(uint64_t height)
{
    std::vector<parameter_record> records;
    m_db.get_parameters_ready(height, records);
    for (const auto& rec : records)
    {
        MINFO("Parameter " << (int)rec.parameter << " set to " << rec.value << " at height " << height);
    }
    return true;
}

bool ParameterManager::rollback_block(uint64_t height)
{
    m_db.remove_parameter_records_by_height_in_txn(height);
    m_db.remove_extension_policy_records_by_height_in_txn(height);
    m_db.remove_premium_label_policy_records_by_height_in_txn(height);
    m_db.remove_banned_label_policy_records_by_height_in_txn(height);
    m_db.remove_banned_extension_policy_records_by_height_in_txn(height);
    m_db.remove_exact_domain_ban_policy_records_by_height_in_txn(height);
    m_db.remove_exact_domain_tier_policy_records_by_height_in_txn(height);
    return true;
}

uint64_t ParameterManager::get_parameter(governance_parameter param, uint64_t height) const
{
    uint64_t value = 0;
    if (m_db.get_parameter(param, height, value))
        return value;

    switch (param)
    {
        case governance_parameter::proposal_submission_fee: return 10000000ULL;
        case governance_parameter::voting_quorum_percent:  return 10;
        case governance_parameter::treasury_ratio:          return 18;
        case governance_parameter::execution_delay:         return 720;
        case governance_parameter::voting_period_days:      return 14;
        case governance_parameter::domain_tier_fee_0:       return 100000000000ULL;
        case governance_parameter::domain_tier_fee_1:       return 1000000000000ULL;
        case governance_parameter::domain_tier_fee_2:       return 10000000000000ULL;
        case governance_parameter::domain_tier_fee_3:       return 100000000000000ULL;
        case governance_parameter::domain_tier_fee_4:       return 1000000000000000ULL;
        case governance_parameter::domain_tier_fee_5:       return 10000000000000000ULL;
        default: return 0;
    }
}

void ParameterManager::add_parameter_record(const parameter_record& rec)
{
    m_db.add_parameter_record(rec);
}

} // namespace cryptonote