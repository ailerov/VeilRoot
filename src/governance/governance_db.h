// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <crypto/hash.h>
#include <cryptonote_basic/cryptonote_basic.h>
#include <blockchain_db/blockchain_db.h>

namespace cryptonote {

class GovernanceDB
{
public:
    explicit GovernanceDB(BlockchainDB& db, network_type nettype);

    bool get_proposal(const crypto::hash& id, proposal_record& rec) const;
    void store_proposal(const proposal_record& rec);
    bool for_all_proposals(std::function<bool(const crypto::hash&, const proposal_record&)> f) const;

    void add_pending_execution(uint64_t execution_height, const crypto::hash& proposal_id);
    void get_pending_executions(uint64_t max_height, std::vector<std::pair<uint64_t, crypto::hash>>& entries) const;
    void remove_pending_execution(uint64_t execution_height, const crypto::hash& proposal_id);

    void add_voting_end_entry(uint64_t voting_end_height, const crypto::hash& proposal_id);
    void get_voting_end_entries(uint64_t height, std::vector<crypto::hash>& proposal_ids) const;
    void remove_voting_end_entry(uint64_t voting_end_height, const crypto::hash& proposal_id);

    void add_parameter_record(const parameter_record& rec);
    void get_parameters_ready(uint64_t height, std::vector<parameter_record>& records) const;
    void remove_parameter_records_by_height(uint64_t height);

    // BEGIN_VNS_BATCH_PARAMETER_ROLLBACK
    void add_parameter_record_in_txn(const parameter_record& rec);
    void remove_parameter_records_by_height_in_txn(uint64_t height);
    // END_VNS_BATCH_PARAMETER_ROLLBACK

    // BEGIN_VNS_EXTENSION_POLICY_DB_WRAPPERS
    void add_extension_policy_record_in_txn(const extension_policy_record& rec);
    void remove_extension_policy_records_by_height_in_txn(uint64_t height);
    bool for_all_extension_policy_records(std::function<bool(const extension_policy_record&)> f) const;
    // END_VNS_EXTENSION_POLICY_DB_WRAPPERS

    // BEGIN_VNS_PREMIUM_LABEL_POLICY_DB_WRAPPERS
    void add_premium_label_policy_record_in_txn(const premium_label_policy_record& rec);
    void remove_premium_label_policy_records_by_height_in_txn(uint64_t height);
    bool get_premium_label_policy(const std::string& label, uint64_t height, premium_label_policy_record& rec) const;
    bool for_all_premium_label_policy_records(std::function<bool(const premium_label_policy_record&)> f) const;
    // END_VNS_PREMIUM_LABEL_POLICY_DB_WRAPPERS

    // BEGIN_VNS_BANNED_LABEL_POLICY_DB_WRAPPERS
    void add_banned_label_policy_record_in_txn(const banned_label_policy_record& rec);
    void remove_banned_label_policy_records_by_height_in_txn(uint64_t height);
    bool get_banned_label_policy(const std::string& term, uint64_t height, banned_label_policy_record& rec) const;
    bool for_all_banned_label_policy_records(std::function<bool(const banned_label_policy_record&)> f) const;
    // END_VNS_BANNED_LABEL_POLICY_DB_WRAPPERS

    // BEGIN_VNS_BANNED_EXTENSION_POLICY_DB_WRAPPERS
    void add_banned_extension_policy_record_in_txn(const banned_extension_policy_record& rec);
    void remove_banned_extension_policy_records_by_height_in_txn(uint64_t height);
    bool get_banned_extension_policy(const std::string& extension, uint64_t height, banned_extension_policy_record& rec) const;
    bool for_all_banned_extension_policy_records(std::function<bool(const banned_extension_policy_record&)> f) const;
    // END_VNS_BANNED_EXTENSION_POLICY_DB_WRAPPERS

    // BEGIN_VNS_EXACT_DOMAIN_BAN_POLICY_DB_WRAPPERS
    void add_exact_domain_ban_policy_record_in_txn(const exact_domain_ban_policy_record& rec);
    void remove_exact_domain_ban_policy_records_by_height_in_txn(uint64_t height);
    void remove_exact_domain_ban_policy_records_by_domain_in_txn(const std::string& domain);
    bool get_exact_domain_ban_policy(const std::string& domain, uint64_t height, exact_domain_ban_policy_record& rec) const;
    bool for_all_exact_domain_ban_policy_records(std::function<bool(const exact_domain_ban_policy_record&)> f) const;
    // END_VNS_EXACT_DOMAIN_BAN_POLICY_DB_WRAPPERS

    // BEGIN_VNS_EXACT_DOMAIN_TIER_POLICY_DB_WRAPPERS
    void add_exact_domain_tier_policy_record_in_txn(const exact_domain_tier_policy_record& rec);
    void remove_exact_domain_tier_policy_records_by_height_in_txn(uint64_t height);
    void remove_exact_domain_tier_policy_records_by_domain_in_txn(const std::string& domain);
    bool get_exact_domain_tier_policy(const std::string& domain, uint64_t height, exact_domain_tier_policy_record& rec) const;
    bool for_all_exact_domain_tier_policy_records(std::function<bool(const exact_domain_tier_policy_record&)> f) const;
    // END_VNS_EXACT_DOMAIN_TIER_POLICY_DB_WRAPPERS

    // BEGIN_VNS_PENDING_DOMAIN_POLICY_DB_WRAPPERS
    void add_pending_domain_policy_record(const pending_domain_policy_record& rec);
    bool get_pending_domain_policy(const std::string& domain, pending_domain_policy_record& rec) const;
    bool get_pending_domain_policy_by_proposal(const crypto::hash& proposal_id, pending_domain_policy_record& rec) const;
    void remove_pending_domain_policy_by_domain(const std::string& domain);
    void remove_pending_domain_policy_by_proposal(const crypto::hash& proposal_id);
    bool for_all_pending_domain_policy_records(std::function<bool(const pending_domain_policy_record&)> f) const;
    // END_VNS_PENDING_DOMAIN_POLICY_DB_WRAPPERS

    bool get_parameter(governance_parameter param, uint64_t height, uint64_t& value) const;

    // BEGIN_VNS_PROPOSAL_DATA
    void set_proposal_data(const crypto::hash& proposal_id, const std::string& data_blob);
    bool get_proposal_data(const crypto::hash& proposal_id, std::string& data_blob) const;
    // END_VNS_PROPOSAL_DATA

    bool get_outcome(const crypto::hash& pid, uint64_t& yes_w, uint64_t& no_w, uint64_t& yes_b, uint64_t& no_b) const;
    void set_outcome(const crypto::hash& pid, uint64_t yes_w, uint64_t no_w, uint64_t yes_b, uint64_t no_b);
    void remove_outcome(const crypto::hash& pid);

    bool get_execution_record(const crypto::hash& pid, proposal_execution_record& rec) const;
    void add_execution_record(const proposal_execution_record& rec);
    void remove_execution_record(const crypto::hash& pid);

    void add_nullifier(const crypto::hash& pid, const crypto::hash& nullifier);
    bool has_nullifier(const crypto::hash& pid, const crypto::hash& nullifier) const;
    void remove_nullifier(const crypto::hash& pid, const crypto::hash& nullifier);
    void remove_vote_record(const crypto::hash& pid, const crypto::key_image& ki);
    void remove_all_nullifiers(const crypto::hash& pid);

    uint64_t get_treasury_balance() const;
    void set_treasury_balance(uint64_t amount);

    // BEGIN_VNS_PROPOSAL_PASSING
    uint64_t height() const;
    uint64_t get_block_already_generated_coins(uint64_t height) const;
    uint64_t get_total_burned_fees() const;
    // END_VNS_PROPOSAL_PASSING

    uint64_t get_burned_fees() const;
    void add_burned_fees(uint64_t amount);

    bool get_governance_params(governance_params& gp) const;
    void set_governance_params(const governance_params& gp);

    BlockchainDB& get_underlying_db() { return m_db; }
    const BlockchainDB& get_underlying_db() const { return m_db; }
    network_type nettype() const { return m_nettype; }

    void remove_proposal(const crypto::hash& proposal_id);
    void remove_vote(const crypto::hash& proposal_id, const crypto::key_image& ki);

    bool get_transaction(const crypto::hash& tx_hash, transaction& tx) const;

    // BEGIN_VNS_TXN_WRAPPERS
    void block_wtxn_start();
    void block_wtxn_stop();
    void block_wtxn_abort();
    // END_VNS_TXN_WRAPPERS

private:
    BlockchainDB& m_db;
    network_type m_nettype;
};

} // namespace cryptonote