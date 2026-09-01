// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <memory>
#include "governance_params.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "treasury.h"
#include "vote_result.h"

namespace cryptonote {

class BlockchainDB;
class GovernanceManager;

class GovernanceEngine
{
public:
    GovernanceEngine();
    ~GovernanceEngine();

    bool initialize(BlockchainDB& db, const governance_params& params, network_type nettype);

    // BEGIN_VNS_PROCESS_VOTE
    vote_result process_vote(const transaction& tx, uint64_t height, bool dry_run);
    // END_VNS_PROCESS_VOTE

    bool process_block(const block& blk, uint64_t height);
    void rollback_block(const block& blk, const std::vector<transaction>& txs, uint64_t height);

    bool is_proposal_passed(uint64_t yes_weight, uint64_t no_weight,
                            uint64_t yes_balance, uint64_t no_balance,
                            uint64_t voting_end_height) const;

    TreasuryManager& treasury();
    const TreasuryManager& treasury() const;
    // BEGIN_VNS_TREASURY_EXECUTION
    std::vector<proposal_record> get_ready_executions(uint64_t current_height) const;
    uint64_t get_governance_parameter(governance_parameter param, uint64_t height) const;
    // END_VNS_TREASURY_EXECUTION

    void recover_overdue_executions(uint64_t current_height);

private:
    std::unique_ptr<GovernanceManager> m_impl;
};

} // namespace cryptonote