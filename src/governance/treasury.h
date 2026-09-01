// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "governance_db.h"

namespace cryptonote {

class TreasuryManager
{
public:
    TreasuryManager(GovernanceDB& db);

    uint64_t get_balance() const;
    void credit_emission(uint64_t amount);
    bool execute_grant(const crypto::hash& proposal_id, uint64_t amount);
    void rollback_grant(const crypto::hash& proposal_id, uint64_t amount);
    uint64_t get_burned_fees() const;
    void add_burned_fees(uint64_t amount);

private:
    GovernanceDB& m_db;
};

} // namespace cryptonote