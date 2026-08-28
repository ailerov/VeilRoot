// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance_db.h"
#include "cryptonote_core/blockchain.h"      // for proposal_record definition
#include "governance/governance_params.h"    // for governance_params definition
#include "cryptonote_basic/cryptonote_format_utils.h"

namespace cryptonote {

GovernanceDB::GovernanceDB(BlockchainDB& db, network_type nettype) : m_db(db), m_nettype(nettype) {}

bool GovernanceDB::get_proposal(const crypto::hash& id, proposal_record& rec) const {
    return m_db.get_proposal_record(id, rec);
}
void GovernanceDB::store_proposal(const proposal_record& rec) {
    m_db.add_proposal_record(rec.proposal_id, rec);
}
bool GovernanceDB::for_all_proposals(std::function<bool(const crypto::hash&, const proposal_record&)> f) const {
    return m_db.for_all_proposal_records(f);
}

// BEGIN_VNS_PENDING_EXECUTION
void GovernanceDB::add_pending_execution(uint64_t execution_height, const crypto::hash& proposal_id)
{
    m_db.add_pending_execution(execution_height, proposal_id);
}

void GovernanceDB::get_pending_executions(uint64_t max_height, std::vector<std::pair<uint64_t, crypto::hash>>& entries) const
{
    m_db.get_pending_executions(max_height, entries);
}

void GovernanceDB::remove_pending_execution(uint64_t execution_height, const crypto::hash& proposal_id)
{
    m_db.remove_pending_execution(execution_height, proposal_id);
}
// END_VNS_PENDING_EXECUTION

// BEGIN_VNS_VOTING_END_QUEUE
void GovernanceDB::add_voting_end_entry(uint64_t voting_end_height, const crypto::hash& proposal_id)
{
    m_db.add_voting_end_entry(voting_end_height, proposal_id);
}

void GovernanceDB::get_voting_end_entries(uint64_t height, std::vector<crypto::hash>& proposal_ids) const
{
    m_db.get_voting_end_entries(height, proposal_ids);
}

void GovernanceDB::remove_voting_end_entry(uint64_t voting_end_height, const crypto::hash& proposal_id)
{
    m_db.remove_voting_end_entry(voting_end_height, proposal_id);
}
// END_VNS_VOTING_END_QUEUE

// BEGIN_VNS_PARAMETER_MANAGER
void GovernanceDB::add_parameter_record(const parameter_record& rec)
{
    m_db.add_parameter_record(rec);
}

void GovernanceDB::get_parameters_ready(uint64_t height, std::vector<parameter_record>& records) const
{
    m_db.get_parameters_ready(height, records);
}

void GovernanceDB::remove_parameter_records_by_height(uint64_t height)
{
    m_db.remove_parameter_records_by_height(height);
}

// BEGIN_VNS_BATCH_PARAMETER_ROLLBACK
void GovernanceDB::add_parameter_record_in_txn(const parameter_record& rec)
{
    m_db.add_parameter_record_in_txn(rec);
}

void GovernanceDB::remove_parameter_records_by_height_in_txn(uint64_t height)
{
    m_db.remove_parameter_records_by_height_in_txn(height);
}
// END_VNS_BATCH_PARAMETER_ROLLBACK

// BEGIN_VNS_EXTENSION_POLICY_DB_WRAPPERS
void GovernanceDB::add_extension_policy_record_in_txn(const extension_policy_record& rec)
{
    m_db.add_extension_policy_record_in_txn(rec);
}

void GovernanceDB::remove_extension_policy_records_by_height_in_txn(uint64_t height)
{
    m_db.remove_extension_policy_records_by_height_in_txn(height);
}

bool GovernanceDB::for_all_extension_policy_records(std::function<bool(const extension_policy_record&)> f) const
{
    return m_db.for_all_extension_policy_records(f);
}
// END_VNS_EXTENSION_POLICY_DB_WRAPPERS

// BEGIN_VNS_PREMIUM_LABEL_POLICY_DB_WRAPPERS
void GovernanceDB::add_premium_label_policy_record_in_txn(const premium_label_policy_record& rec)
{
    m_db.add_premium_label_policy_record_in_txn(rec);
}

void GovernanceDB::remove_premium_label_policy_records_by_height_in_txn(uint64_t height)
{
    m_db.remove_premium_label_policy_records_by_height_in_txn(height);
}

bool GovernanceDB::get_premium_label_policy(const std::string& label, uint64_t height, premium_label_policy_record& rec) const
{
    return m_db.get_premium_label_policy(label, height, rec);
}

bool GovernanceDB::for_all_premium_label_policy_records(std::function<bool(const premium_label_policy_record&)> f) const
{
    return m_db.for_all_premium_label_policy_records(f);
}
// END_VNS_PREMIUM_LABEL_POLICY_DB_WRAPPERS

// BEGIN_VNS_BANNED_LABEL_POLICY_DB_WRAPPERS
void GovernanceDB::add_banned_label_policy_record_in_txn(const banned_label_policy_record& rec)
{
    m_db.add_banned_label_policy_record_in_txn(rec);
}

void GovernanceDB::remove_banned_label_policy_records_by_height_in_txn(uint64_t height)
{
    m_db.remove_banned_label_policy_records_by_height_in_txn(height);
}

bool GovernanceDB::get_banned_label_policy(const std::string& term, uint64_t height, banned_label_policy_record& rec) const
{
    return m_db.get_banned_label_policy(term, height, rec);
}

bool GovernanceDB::for_all_banned_label_policy_records(std::function<bool(const banned_label_policy_record&)> f) const
{
    return m_db.for_all_banned_label_policy_records(f);
}
// END_VNS_BANNED_LABEL_POLICY_DB_WRAPPERS

// BEGIN_VNS_BANNED_EXTENSION_POLICY_DB_WRAPPERS
void GovernanceDB::add_banned_extension_policy_record_in_txn(const banned_extension_policy_record& rec)
{
    m_db.add_banned_extension_policy_record_in_txn(rec);
}

void GovernanceDB::remove_banned_extension_policy_records_by_height_in_txn(uint64_t height)
{
    m_db.remove_banned_extension_policy_records_by_height_in_txn(height);
}

bool GovernanceDB::get_banned_extension_policy(const std::string& extension, uint64_t height, banned_extension_policy_record& rec) const
{
    return m_db.get_banned_extension_policy(extension, height, rec);
}

bool GovernanceDB::for_all_banned_extension_policy_records(std::function<bool(const banned_extension_policy_record&)> f) const
{
    return m_db.for_all_banned_extension_policy_records(f);
}
// END_VNS_BANNED_EXTENSION_POLICY_DB_WRAPPERS

// BEGIN_VNS_EXACT_DOMAIN_BAN_POLICY_DB_WRAPPERS
void GovernanceDB::add_exact_domain_ban_policy_record_in_txn(const exact_domain_ban_policy_record& rec)
{
    m_db.add_exact_domain_ban_policy_record_in_txn(rec);
}

void GovernanceDB::remove_exact_domain_ban_policy_records_by_height_in_txn(uint64_t height)
{
    m_db.remove_exact_domain_ban_policy_records_by_height_in_txn(height);
}

void GovernanceDB::remove_exact_domain_ban_policy_records_by_domain_in_txn(const std::string& domain)
{
    m_db.remove_exact_domain_ban_policy_records_by_domain_in_txn(domain);
}

bool GovernanceDB::get_exact_domain_ban_policy(const std::string& domain, uint64_t height, exact_domain_ban_policy_record& rec) const
{
    return m_db.get_exact_domain_ban_policy(domain, height, rec);
}

bool GovernanceDB::for_all_exact_domain_ban_policy_records(std::function<bool(const exact_domain_ban_policy_record&)> f) const
{
    return m_db.for_all_exact_domain_ban_policy_records(f);
}
// END_VNS_EXACT_DOMAIN_BAN_POLICY_DB_WRAPPERS

// BEGIN_VNS_EXACT_DOMAIN_TIER_POLICY_DB_WRAPPERS
void GovernanceDB::add_exact_domain_tier_policy_record_in_txn(const exact_domain_tier_policy_record& rec)
{
    m_db.add_exact_domain_tier_policy_record_in_txn(rec);
}

void GovernanceDB::remove_exact_domain_tier_policy_records_by_height_in_txn(uint64_t height)
{
    m_db.remove_exact_domain_tier_policy_records_by_height_in_txn(height);
}

void GovernanceDB::remove_exact_domain_tier_policy_records_by_domain_in_txn(const std::string& domain)
{
    m_db.remove_exact_domain_tier_policy_records_by_domain_in_txn(domain);
}

bool GovernanceDB::get_exact_domain_tier_policy(const std::string& domain, uint64_t height, exact_domain_tier_policy_record& rec) const
{
    return m_db.get_exact_domain_tier_policy(domain, height, rec);
}

bool GovernanceDB::for_all_exact_domain_tier_policy_records(std::function<bool(const exact_domain_tier_policy_record&)> f) const
{
    return m_db.for_all_exact_domain_tier_policy_records(f);
}
// END_VNS_EXACT_DOMAIN_TIER_POLICY_DB_WRAPPERS

// BEGIN_VNS_PENDING_DOMAIN_POLICY_DB_WRAPPERS
void GovernanceDB::add_pending_domain_policy_record(const pending_domain_policy_record& rec)
{
    m_db.add_pending_domain_policy_record(rec);
}

bool GovernanceDB::get_pending_domain_policy(const std::string& domain, pending_domain_policy_record& rec) const
{
    return m_db.get_pending_domain_policy(domain, rec);
}

bool GovernanceDB::get_pending_domain_policy_by_proposal(const crypto::hash& proposal_id, pending_domain_policy_record& rec) const
{
    return m_db.get_pending_domain_policy_by_proposal(proposal_id, rec);
}

void GovernanceDB::remove_pending_domain_policy_by_domain(const std::string& domain)
{
    m_db.remove_pending_domain_policy_by_domain(domain);
}

void GovernanceDB::remove_pending_domain_policy_by_proposal(const crypto::hash& proposal_id)
{
    m_db.remove_pending_domain_policy_by_proposal(proposal_id);
}

bool GovernanceDB::for_all_pending_domain_policy_records(std::function<bool(const pending_domain_policy_record&)> f) const
{
    return m_db.for_all_pending_domain_policy_records(f);
}
// END_VNS_PENDING_DOMAIN_POLICY_DB_WRAPPERS

bool GovernanceDB::get_parameter(governance_parameter param, uint64_t height, uint64_t& value) const
{
    return m_db.get_parameter(param, height, value);
}
// END_VNS_PARAMETER_MANAGER

// BEGIN_VNS_PROPOSAL_DATA
void GovernanceDB::set_proposal_data(const crypto::hash& proposal_id, const std::string& data_blob)
{
    m_db.set_proposal_data(proposal_id, data_blob);
}

bool GovernanceDB::get_proposal_data(const crypto::hash& proposal_id, std::string& data_blob) const
{
    return m_db.get_proposal_data(proposal_id, data_blob);
}
// END_VNS_PROPOSAL_DATA

bool GovernanceDB::get_outcome(const crypto::hash& pid, uint64_t& yes_w, uint64_t& no_w, uint64_t& yes_b, uint64_t& no_b) const {
    return m_db.get_proposal_outcome(pid, yes_w, no_w, yes_b, no_b);
}
void GovernanceDB::set_outcome(const crypto::hash& pid, uint64_t yes_w, uint64_t no_w, uint64_t yes_b, uint64_t no_b) {
    m_db.set_proposal_outcome(pid, yes_w, no_w, yes_b, no_b);
}
void GovernanceDB::remove_outcome(const crypto::hash& pid) {
    m_db.remove_proposal_outcome(pid);
}

bool GovernanceDB::get_execution_record(const crypto::hash& pid, proposal_execution_record& rec) const {
    return m_db.get_proposal_execution_record(pid, rec);
}
void GovernanceDB::add_execution_record(const proposal_execution_record& rec) {
    m_db.add_proposal_execution_record(rec);
}
void GovernanceDB::remove_execution_record(const crypto::hash& pid) {
    m_db.remove_proposal_execution_record(pid);
}

void GovernanceDB::add_nullifier(const crypto::hash& pid, const crypto::hash& nullifier) {
    m_db.add_vote_nullifier(pid, nullifier);
}
bool GovernanceDB::has_nullifier(const crypto::hash& pid, const crypto::hash& nullifier) const {
    return m_db.has_vote_nullifier(pid, nullifier);
}
void GovernanceDB::remove_nullifier(const crypto::hash& pid, const crypto::hash& nullifier) {
    m_db.remove_vote_nullifier(pid, nullifier);
}
void GovernanceDB::remove_vote_record(const crypto::hash& pid, const crypto::key_image& ki) {
    m_db.remove_vote_record(pid, ki);
}
void GovernanceDB::remove_all_nullifiers(const crypto::hash& pid) {
    m_db.remove_all_vote_nullifiers(pid);
}

uint64_t GovernanceDB::get_treasury_balance() const {
    return m_db.get_treasury_balance();
}
void GovernanceDB::set_treasury_balance(uint64_t amount) {
    m_db.set_treasury_balance(amount);
}

// BEGIN_VNS_PROPOSAL_PASSING
uint64_t GovernanceDB::height() const
{
    return m_db.height();
}

uint64_t GovernanceDB::get_block_already_generated_coins(uint64_t h) const
{
    return m_db.get_block_already_generated_coins(h);
}

uint64_t GovernanceDB::get_total_burned_fees() const
{
    return m_db.get_total_burned_fees();
}
// END_VNS_PROPOSAL_PASSING

// BEGIN_VNS_BURNED_FEES
uint64_t GovernanceDB::get_burned_fees() const {
    return m_db.get_total_burned_fees();
}
void GovernanceDB::add_burned_fees(uint64_t amount) {
    m_db.add_burned_fees(amount);
}
// END_VNS_BURNED_FEES

bool GovernanceDB::get_governance_params(governance_params& gp) const {
    std::string blob;
    if (!m_db.get_governance_params(blob)) return false;
    return governance_params::deserialize(blob, gp);
}
void GovernanceDB::set_governance_params(const governance_params& gp) {
    m_db.set_governance_params(gp.serialize());
}

// BEGIN_VNS_REMOVE_PROPOSAL
void GovernanceDB::remove_proposal(const crypto::hash& proposal_id)
{
    m_db.remove_proposal_record(proposal_id);
}
// END_VNS_REMOVE_PROPOSAL

bool GovernanceDB::get_transaction(const crypto::hash& tx_hash, transaction& tx) const
{
    std::string blob;
    if (!m_db.get_tx_blob(tx_hash, blob))
        return false;
    return parse_and_validate_tx_from_blob(blob, tx);
}

// BEGIN_VNS_TXN_WRAPPERS
void GovernanceDB::block_wtxn_start()  { m_db.block_wtxn_start(); }
void GovernanceDB::block_wtxn_stop()   { m_db.block_wtxn_stop(); }
void GovernanceDB::block_wtxn_abort()  { m_db.block_wtxn_abort(); }
// END_VNS_TXN_WRAPPERS

} // namespace cryptonote