// Copyright (c) 2014-2022, The Monero Project
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#pragma once

#include <atomic>

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/blobdatatype.h" // for type blobdata
#include "ringct/rctTypes.h"
#include "crypto/threshold_elgamal.h"
#include <boost/thread/tss.hpp>

#include <lmdb.h>

#define ENABLE_AUTO_RESIZE
#define LMDB_TREASURY_OUTPUTS "treasury_outputs"

namespace cryptonote
{

typedef struct txindex {
    crypto::hash key;
    tx_data_t data;
} txindex;

typedef struct mdb_txn_cursors
{
  MDB_cursor *m_txc_blocks;
  MDB_cursor *m_txc_block_heights;
  MDB_cursor *m_txc_block_info;

  MDB_cursor *m_txc_output_txs;
  MDB_cursor *m_txc_output_amounts;

  MDB_cursor *m_txc_txs;
  MDB_cursor *m_txc_txs_pruned;
  MDB_cursor *m_txc_txs_prunable;
  MDB_cursor *m_txc_txs_prunable_hash;
  MDB_cursor *m_txc_txs_prunable_tip;
  MDB_cursor *m_txc_tx_indices;
  MDB_cursor *m_txc_tx_outputs;

  MDB_cursor *m_txc_spent_keys;

  MDB_cursor *m_txc_txpool_meta;
  MDB_cursor *m_txc_txpool_blob;

  MDB_cursor *m_txc_alt_blocks;
  MDB_cursor *m_txc_vns_domains;
  MDB_cursor *m_txc_vns_domain_heartbeat_events;
  MDB_cursor *m_txc_proposals;
  MDB_cursor *m_txc_vns_heartbeat_proofs;
  MDB_cursor *m_txc_votes;
  MDB_cursor *m_txc_voting_end_queue;
  MDB_cursor *m_txc_vote_ciphertexts;
  MDB_cursor *m_txc_committee_eligible;
  MDB_cursor *m_txc_proposal_executions;
  MDB_cursor *m_txc_dkg_shares;
  MDB_cursor *m_txc_committee_key;
  MDB_cursor *m_txc_proposal_outcomes;
  MDB_cursor *m_txc_proposal_data;
  MDB_cursor *m_txc_vote_nullifiers;
  MDB_cursor *m_txc_pending_executions;
  MDB_cursor *m_txc_governance_parameters;
  MDB_cursor *m_txc_extension_policy;
  MDB_cursor *m_txc_premium_label_policy;
  MDB_cursor *m_txc_banned_label_policy;
  MDB_cursor *m_txc_banned_extension_policy;
  MDB_cursor *m_txc_exact_domain_ban_policy;
  MDB_cursor *m_txc_exact_domain_tier_policy;
  MDB_cursor *m_txc_pending_domain_policy;

  MDB_cursor *m_txc_hf_versions;

  MDB_cursor *m_txc_properties;
} mdb_txn_cursors;

#define m_cur_blocks	m_cursors->m_txc_blocks
#define m_cur_block_heights	m_cursors->m_txc_block_heights
#define m_cur_block_info	m_cursors->m_txc_block_info
#define m_cur_output_txs	m_cursors->m_txc_output_txs
#define m_cur_output_amounts	m_cursors->m_txc_output_amounts
#define m_cur_txs	m_cursors->m_txc_txs
#define m_cur_txs_pruned	m_cursors->m_txc_txs_pruned
#define m_cur_txs_prunable	m_cursors->m_txc_txs_prunable
#define m_cur_txs_prunable_hash	m_cursors->m_txc_txs_prunable_hash
#define m_cur_txs_prunable_tip	m_cursors->m_txc_txs_prunable_tip
#define m_cur_tx_indices	m_cursors->m_txc_tx_indices
#define m_cur_tx_outputs	m_cursors->m_txc_tx_outputs
#define m_cur_spent_keys	m_cursors->m_txc_spent_keys
#define m_cur_txpool_meta	m_cursors->m_txc_txpool_meta
#define m_cur_txpool_blob	m_cursors->m_txc_txpool_blob
#define m_cur_alt_blocks	m_cursors->m_txc_alt_blocks
#define m_cur_hf_versions	m_cursors->m_txc_hf_versions
#define m_cur_properties	m_cursors->m_txc_properties
#define m_cur_vns_domains   m_cursors->m_txc_vns_domains
#define m_cur_vns_domain_heartbeat_events m_cursors->m_txc_vns_domain_heartbeat_events
#define m_cur_proposals     m_cursors->m_txc_proposals
#define m_cur_vns_heartbeat_proofs    m_cursors->m_txc_vns_heartbeat_proofs
#define m_cur_votes         m_cursors->m_txc_votes
#define m_cur_voting_end_queue     m_cursors->m_txc_voting_end_queue
#define m_cur_vote_ciphertexts m_cursors->m_txc_vote_ciphertexts
#define m_cur_committee_eligible   m_cursors->m_txc_committee_eligible
#define m_cur_proposal_executions   m_cursors->m_txc_proposal_executions
#define m_cur_dkg_shares           m_cursors->m_txc_dkg_shares
#define m_cur_committee_key        m_cursors->m_txc_committee_key
#define m_cur_proposal_outcomes    m_cursors->m_txc_proposal_outcomes
#define m_cur_proposal_data        m_cursors->m_txc_proposal_data
#define m_cur_pending_executions   m_cursors->m_txc_pending_executions
#define m_cur_governance_parameters  m_cursors->m_txc_governance_parameters
#define m_cur_extension_policy       m_cursors->m_txc_extension_policy
#define m_cur_premium_label_policy   m_cursors->m_txc_premium_label_policy
#define m_cur_banned_label_policy    m_cursors->m_txc_banned_label_policy
#define m_cur_banned_extension_policy m_cursors->m_txc_banned_extension_policy
#define m_cur_exact_domain_ban_policy m_cursors->m_txc_exact_domain_ban_policy
#define m_cur_exact_domain_tier_policy m_cursors->m_txc_exact_domain_tier_policy
#define m_cur_pending_domain_policy m_cursors->m_txc_pending_domain_policy

typedef struct mdb_rflags
{
  bool m_rf_txn;
  bool m_rf_blocks;
  bool m_rf_block_heights;
  bool m_rf_block_info;
  bool m_rf_output_txs;
  bool m_rf_output_amounts;
  bool m_rf_txs;
  bool m_rf_txs_pruned;
  bool m_rf_txs_prunable;
  bool m_rf_txs_prunable_hash;
  bool m_rf_txs_prunable_tip;
  bool m_rf_tx_indices;
  bool m_rf_tx_outputs;
  bool m_rf_spent_keys;
  bool m_rf_txpool_meta;
  bool m_rf_txpool_blob;
  bool m_rf_alt_blocks;
  bool m_rf_hf_versions;
  bool m_rf_properties;
  bool m_rf_vns_domains;
  bool m_rf_vns_domain_heartbeat_events;
  bool m_rf_vns_heartbeat_proofs;
  bool m_rf_proposals;
  bool m_rf_votes;
  bool m_rf_voting_end_queue;
  bool m_rf_vote_ciphertexts;
  bool m_rf_committee_eligible;
  bool m_rf_proposal_executions;
  bool m_rf_pending_executions;
  bool m_rf_governance_parameters;
  bool m_rf_extension_policy;
  bool m_rf_premium_label_policy;
  bool m_rf_banned_label_policy;
  bool m_rf_banned_extension_policy;
  bool m_rf_exact_domain_ban_policy;
  bool m_rf_exact_domain_tier_policy;
  bool m_rf_pending_domain_policy;
  bool m_rf_dkg_shares;
  bool m_rf_committee_key;
  bool m_rf_proposal_outcomes;
  bool m_rf_proposal_data;
} mdb_rflags;

typedef struct mdb_threadinfo
{
  MDB_txn *m_ti_rtxn;	// per-thread read txn
  mdb_txn_cursors m_ti_rcursors;	// per-thread read cursors
  mdb_rflags m_ti_rflags;	// per-thread read state

  ~mdb_threadinfo();
} mdb_threadinfo;

struct mdb_txn_safe
{
  mdb_txn_safe(const bool check=true);
  ~mdb_txn_safe();

  void commit(std::string message = "");

  // This should only be needed for batch transaction which must be ensured to
  // be aborted before mdb_env_close, not after. So we can't rely on
  // BlockchainLMDB destructor to call mdb_txn_safe destructor, as that's too late
  // to properly abort, since mdb_env_close would have been called earlier.
  void abort();
  void uncheck();

  operator MDB_txn*()
  {
    return m_txn;
  }

  operator MDB_txn**()
  {
    return &m_txn;
  }

  uint64_t num_active_tx() const;

  static void prevent_new_txns();
  static void wait_no_active_txns();
  static void allow_new_txns();
  static void increment_txns(int);

  mdb_threadinfo* m_tinfo;
  MDB_txn* m_txn;
  bool m_batch_txn = false;
  bool m_check;
  static std::atomic<uint64_t> num_active_txns;

  // could use a mutex here, but this should be sufficient.
  static std::atomic_flag creation_gate;
};


// If m_batch_active is set, a batch transaction exists beyond this class, such
// as a batch import with verification enabled, or possibly (later) a batch
// network sync.
//
// For some of the lookup methods, such as get_block_timestamp(), tx_exists(),
// and get_tx(), when m_batch_active is set, the lookup uses the batch
// transaction. This isn't only because the transaction is available, but it's
// necessary so that lookups include the database updates only present in the
// current batch write.
//
// A regular network sync without batch writes is expected to open a new read
// transaction, as those lookups are part of the validation done prior to the
// write for block and tx data, so no write transaction is open at the time.
class BlockchainLMDB : public BlockchainDB
{
public:
  BlockchainLMDB(bool batch_transactions=true);
  ~BlockchainLMDB();

  virtual void open(const std::string& filename, const int mdb_flags=0);

  virtual void close();

  virtual void sync();

  virtual void safesyncmode(const bool onoff);

  virtual void reset();

  virtual std::vector<std::string> get_filenames() const;

  virtual bool remove_data_file(const std::string& folder) const;

  virtual std::string get_db_name() const;

  virtual bool lock();

  virtual void unlock();

  virtual bool block_exists(const crypto::hash& h, uint64_t *height = NULL) const;

  virtual uint64_t get_block_height(const crypto::hash& h) const;

  virtual block_header get_block_header(const crypto::hash& h) const;

  virtual cryptonote::blobdata get_block_blob(const crypto::hash& h) const;

  virtual cryptonote::blobdata get_block_blob_from_height(const uint64_t& height) const;

  virtual std::vector<uint64_t> get_block_cumulative_rct_outputs(const std::vector<uint64_t> &heights) const;

  virtual uint64_t get_block_timestamp(const uint64_t& height) const;

  virtual uint64_t get_top_block_timestamp() const;

  virtual size_t get_block_weight(const uint64_t& height) const;

  virtual std::vector<uint64_t> get_block_weights(uint64_t start_height, size_t count) const;

  virtual difficulty_type get_block_cumulative_difficulty(const uint64_t& height) const;

  virtual difficulty_type get_block_difficulty(const uint64_t& height) const;

  virtual void correct_block_cumulative_difficulties(const uint64_t& start_height, const std::vector<difficulty_type>& new_cumulative_difficulties);

  virtual uint64_t get_block_already_generated_coins(const uint64_t& height) const;

  virtual uint64_t get_block_long_term_weight(const uint64_t& height) const;

  virtual std::vector<uint64_t> get_long_term_block_weights(uint64_t start_height, size_t count) const;

  virtual crypto::hash get_block_hash_from_height(const uint64_t& height) const;
  bool get_block_hash_from_height_in_txn(uint64_t height, crypto::hash& hash);

  virtual std::vector<block> get_blocks_range(const uint64_t& h1, const uint64_t& h2) const;

  virtual std::vector<crypto::hash> get_hashes_range(const uint64_t& h1, const uint64_t& h2) const;

  virtual crypto::hash top_block_hash(uint64_t *block_height = NULL) const;

  virtual block get_top_block() const;

  virtual uint64_t height() const;

  virtual bool tx_exists(const crypto::hash& h) const;
  virtual bool tx_exists(const crypto::hash& h, uint64_t& tx_index) const;

  virtual uint64_t get_tx_unlock_time(const crypto::hash& h) const;

  virtual bool get_tx_blob(const crypto::hash& h, cryptonote::blobdata &tx) const;
  virtual bool get_pruned_tx_blob(const crypto::hash& h, cryptonote::blobdata &tx) const;
  virtual bool get_pruned_tx_blobs_from(const crypto::hash& h, size_t count, std::vector<cryptonote::blobdata> &bd) const;
  virtual bool get_blocks_from(uint64_t start_height, size_t min_block_count, size_t max_block_count, size_t max_tx_count, size_t max_size, std::vector<std::pair<std::pair<cryptonote::blobdata, crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::blobdata>>>>& blocks, bool pruned, bool skip_coinbase, bool get_miner_tx_hash) const;
  virtual bool get_prunable_tx_blob(const crypto::hash& h, cryptonote::blobdata &tx) const;
  virtual bool get_prunable_tx_hash(const crypto::hash& tx_hash, crypto::hash &prunable_hash) const;

  virtual uint64_t get_tx_count() const;

  virtual std::vector<transaction> get_tx_list(const std::vector<crypto::hash>& hlist) const;

  virtual uint64_t get_tx_block_height(const crypto::hash& h) const;

  virtual uint64_t get_num_outputs(const uint64_t& amount) const;

  virtual output_data_t get_output_key(const uint64_t& amount, const uint64_t& index, bool include_commitmemt) const;
  virtual void get_output_key(const epee::span<const uint64_t> &amounts, const std::vector<uint64_t> &offsets, std::vector<output_data_t> &outputs, bool allow_partial = false) const;

  virtual tx_out_index get_output_tx_and_index_from_global(const uint64_t& index) const;
  virtual void get_output_tx_and_index_from_global(const std::vector<uint64_t> &global_indices,
      std::vector<tx_out_index> &tx_out_indices) const;

  virtual tx_out_index get_output_tx_and_index(const uint64_t& amount, const uint64_t& index) const;
  virtual void get_output_tx_and_index(const uint64_t& amount, const std::vector<uint64_t> &offsets, std::vector<tx_out_index> &indices) const;

  virtual std::vector<std::vector<uint64_t>> get_tx_amount_output_indices(const uint64_t tx_id, size_t n_txes) const;

  virtual bool has_key_image(const crypto::key_image& img) const;

  virtual void add_txpool_tx(const crypto::hash &txid, const cryptonote::blobdata_ref &blob, const txpool_tx_meta_t& meta);
  virtual void update_txpool_tx(const crypto::hash &txid, const txpool_tx_meta_t& meta);
  virtual uint64_t get_txpool_tx_count(relay_category category = relay_category::broadcasted) const;
  virtual bool txpool_has_tx(const crypto::hash &txid, relay_category tx_category) const;
  virtual void remove_txpool_tx(const crypto::hash& txid);
  virtual bool get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t &meta) const;
  virtual bool get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata& bd, relay_category tx_category) const;
  virtual cryptonote::blobdata get_txpool_tx_blob(const crypto::hash& txid, relay_category tx_category) const;
  virtual uint32_t get_blockchain_pruning_seed() const;
  virtual bool prune_blockchain(uint32_t pruning_seed = 0);
  virtual bool update_pruning();
  virtual bool check_pruning();

  virtual void add_alt_block(const crypto::hash &blkid, const cryptonote::alt_block_data_t &data, const cryptonote::blobdata_ref &blob);
  virtual bool get_alt_block(const crypto::hash &blkid, alt_block_data_t *data, cryptonote::blobdata *blob);
  virtual void remove_alt_block(const crypto::hash &blkid);
  virtual uint64_t get_alt_block_count();
  virtual void drop_alt_blocks();

  virtual bool for_all_txpool_txes(std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const cryptonote::blobdata_ref*)> f, bool include_blob = false, relay_category category = relay_category::broadcasted) const;

  virtual bool for_all_key_images(std::function<bool(const crypto::key_image&)>) const;
  virtual bool for_blocks_range(const uint64_t& h1, const uint64_t& h2, std::function<bool(uint64_t, const crypto::hash&, const cryptonote::block&)>) const;
  virtual bool for_all_transactions(std::function<bool(const crypto::hash&, const cryptonote::transaction&)>, bool pruned) const;
  virtual bool for_all_outputs(std::function<bool(uint64_t amount, const crypto::hash &tx_hash, uint64_t height, size_t tx_idx)> f) const;
  virtual bool for_all_outputs(uint64_t amount, const std::function<bool(uint64_t height)> &f) const;
  virtual bool for_all_alt_blocks(std::function<bool(const crypto::hash &blkid, const alt_block_data_t &data, const cryptonote::blobdata_ref *blob)> f, bool include_blob = false) const;

  virtual uint64_t add_block( const std::pair<block, blobdata>& blk
                            , size_t block_weight
                            , uint64_t long_term_block_weight
                            , const difficulty_type& cumulative_difficulty
                            , const uint64_t& coins_generated
                            , const std::vector<std::pair<transaction, blobdata>>& txs
                            , const std::vector<proposal_execution_record>& execution_records = {}
                            , uint64_t fee_summary = 0
                            ) override;

  virtual void set_batch_transactions(bool batch_transactions);
  virtual bool batch_start(uint64_t batch_num_blocks=0, uint64_t batch_bytes=0);
  virtual void batch_commit();
  virtual void batch_stop();
  virtual void batch_abort();

  virtual void block_wtxn_start();
  virtual void block_wtxn_stop();
  virtual void block_wtxn_abort();
  // BEGIN_VNS_DOMAIN_EXPIRY_GUARD
  virtual bool is_batch_active() const override { return m_batch_active; }
  virtual bool has_active_write_txn() const override { return m_write_txn != nullptr; }
  // END_VNS_DOMAIN_EXPIRY_GUARD
  virtual bool block_rtxn_start() const;
  virtual void block_rtxn_stop() const;
  virtual void block_rtxn_abort() const;

  // VNS domain record persistence
  virtual void add_vns_domain_record(const std::string& domain_name, const vns_domain_record& record) override;
  virtual bool get_vns_domain_record(const std::string& domain_name, vns_domain_record& record) const override;
  virtual void remove_vns_domain_record(const std::string& domain_name) override;
  virtual bool for_all_vns_domain_records(std::function<bool(const std::string&, const vns_domain_record&)> f) const override;
  virtual bool get_vns_heartbeat_proof(const std::string& domain_name, crypto::hash& proof) const override;
  virtual void set_vns_heartbeat_proof(const std::string& domain_name, const crypto::hash& proof) override;
  virtual void remove_vns_heartbeat_proof(const std::string& domain_name) override;

  // BEGIN_VNS_DOMAIN_HEARTBEAT_EVENT_DB_OVERRIDES
  virtual void add_vns_domain_heartbeat_event(const vns_domain_heartbeat_event_record& rec) override;
  virtual bool get_vns_domain_heartbeat_events_by_height(
      uint64_t height,
      std::vector<vns_domain_heartbeat_event_record>& events) const override;
  virtual void remove_vns_domain_heartbeat_events_by_height(uint64_t height) override;
  virtual void remove_vns_domain_heartbeat_events_by_domain(const std::string& domain_name) override;
  // END_VNS_DOMAIN_HEARTBEAT_EVENT_DB_OVERRIDES

  virtual uint64_t get_treasury_balance() const override;
    // BEGIN_VNS_TXN_SAFE_GETTERS
    uint64_t get_treasury_balance_in_txn() const;
    // END_VNS_TXN_SAFE_GETTERS
  virtual uint64_t get_total_burned_fees() const override;
  virtual void add_burned_fees(uint64_t amount) override;
  virtual void set_treasury_balance(uint64_t amount) override;
    // BEGIN_VNS_TXN_SAFE_GETTERS
    void set_treasury_balance_in_txn(uint64_t amount);
    // END_VNS_TXN_SAFE_GETTERS
  virtual void set_governance_params(const std::string& blob) override;
  virtual bool get_governance_params(std::string& blob) const override;
  virtual void add_proposal_record(const crypto::hash& proposal_id, const proposal_record& record) override;
  virtual void remove_proposal_record(const crypto::hash& proposal_id) override;
  virtual bool get_proposal_record(const crypto::hash& proposal_id, proposal_record& record) const override;
  bool get_proposal_amount_in_txn(const crypto::hash& proposal_id, uint64_t& amount);
  bool get_proposal_record_in_txn(const crypto::hash& proposal_id, proposal_record& rec);
  virtual bool for_all_proposal_records(std::function<bool(const crypto::hash&, const proposal_record&)> f) const override;
  virtual void add_vote_record(const crypto::hash& proposal_id, const crypto::key_image& ki, const vote_record& record) override;
  virtual bool get_vote_record(const crypto::hash& proposal_id, const crypto::key_image& ki, vote_record& record) const override;
  virtual void remove_vote_record(const crypto::hash& proposal_id, const crypto::key_image& ki) override;
  virtual bool for_all_vote_records(std::function<bool(const crypto::hash&, const crypto::key_image&, const vote_record&)> f) const override;
  virtual void add_vote_ciphertext_record(const crypto::hash& proposal_id, const crypto::key_image& ki, const crypto::elgamal_ciphertext& ct) override;
  virtual bool get_vote_ciphertext_record(const crypto::hash& proposal_id, const crypto::key_image& ki, crypto::elgamal_ciphertext& ct) const override;
  virtual void remove_vote_ciphertext_record(const crypto::hash& proposal_id, const crypto::key_image& ki) override;
  virtual bool for_all_vote_ciphertext_records(std::function<bool(const crypto::hash&, const crypto::key_image&, const crypto::elgamal_ciphertext&)> f) const override;
  // BEGIN_VNS_ELIGIBLE
  virtual void add_committee_eligible(const crypto::key_image& ki, const committee_eligible_record& rec) override;
  virtual bool get_committee_eligible(const crypto::key_image& ki, committee_eligible_record& rec) const override;
  virtual void remove_committee_eligible(const crypto::key_image& ki) override;
  virtual bool for_all_committee_eligible(std::function<bool(const crypto::key_image&, const committee_eligible_record&)> f) const override;

  // BEGIN_VNS_PROPOSAL_EXECUTION_RECORD
  virtual void add_proposal_execution_record(const proposal_execution_record& rec) override;
  virtual bool get_proposal_execution_record(const crypto::hash& proposal_id, proposal_execution_record& rec) const override;
    // BEGIN_VNS_TXN_SAFE_GETTERS
    bool get_proposal_execution_record_in_txn(const crypto::hash& proposal_id, proposal_execution_record& rec);
    // END_VNS_TXN_SAFE_GETTERS
  virtual void remove_proposal_execution_record(const crypto::hash& proposal_id) override;

  void add_pending_execution(
    uint64_t execution_height,
    const crypto::hash& proposal_id) override;

  void get_pending_executions(
      uint64_t max_height,
      std::vector<std::pair<uint64_t, crypto::hash>>& entries) const override;

  void remove_pending_execution(
    uint64_t execution_height,
    const crypto::hash& proposal_id) override;

  virtual void add_voting_end_entry(uint64_t voting_end_height, const crypto::hash& proposal_id) override;
  virtual void get_voting_end_entries(uint64_t height, std::vector<crypto::hash>& proposal_ids) const override;
  virtual void remove_voting_end_entry(uint64_t voting_end_height, const crypto::hash& proposal_id) override;

  virtual void add_parameter_record(const parameter_record& rec) override;
  virtual void get_parameters_ready(uint64_t height, std::vector<parameter_record>& records) const override;
  virtual void remove_parameter_records_by_height(uint64_t height) override;
  virtual bool get_parameter(governance_parameter param, uint64_t height, uint64_t& value) const override;
  // BEGIN_VNS_PARAMETER_RECORD_LOOKUP
  virtual bool get_parameter_record(governance_parameter param, uint64_t height, parameter_record& rec) const override;
  // END_VNS_PARAMETER_RECORD_LOOKUP
  virtual void add_parameter_record_in_txn(const parameter_record& rec) override;
  virtual void remove_parameter_records_by_height_in_txn(uint64_t height) override;

  // BEGIN_VNS_EXTENSION_POLICY_DB_OVERRIDES
  virtual void add_extension_policy_record(const extension_policy_record& rec) override;
  virtual void get_extension_policies_ready(uint64_t height, std::vector<extension_policy_record>& records) const override;
  virtual void remove_extension_policy_records_by_height(uint64_t height) override;
  virtual bool get_extension_policy(const std::string& extension, uint64_t height, extension_policy_record& rec) const override;
  virtual void add_extension_policy_record_in_txn(const extension_policy_record& rec) override;
  virtual void remove_extension_policy_records_by_height_in_txn(uint64_t height) override;
  virtual bool for_all_extension_policy_records(std::function<bool(const extension_policy_record&)> f) const override;
  // END_VNS_EXTENSION_POLICY_DB_OVERRIDES

  // BEGIN_VNS_PREMIUM_LABEL_POLICY_DB_OVERRIDES
  virtual void add_premium_label_policy_record(const premium_label_policy_record& rec) override;
  virtual bool get_premium_label_policy(const std::string& label, uint64_t height, premium_label_policy_record& rec) const override;
  virtual void add_premium_label_policy_record_in_txn(const premium_label_policy_record& rec) override;
  virtual void remove_premium_label_policy_records_by_height_in_txn(uint64_t height) override;
  virtual bool for_all_premium_label_policy_records(std::function<bool(const premium_label_policy_record&)> f) const override;
  // END_VNS_PREMIUM_LABEL_POLICY_DB_OVERRIDES

  // BEGIN_VNS_BANNED_LABEL_POLICY_DB_OVERRIDES
  virtual void add_banned_label_policy_record(const banned_label_policy_record& rec) override;
  virtual bool get_banned_label_policy(const std::string& term, uint64_t height, banned_label_policy_record& rec) const override;
  virtual void add_banned_label_policy_record_in_txn(const banned_label_policy_record& rec) override;
  virtual void remove_banned_label_policy_records_by_height_in_txn(uint64_t height) override;
  virtual bool for_all_banned_label_policy_records(std::function<bool(const banned_label_policy_record&)> f) const override;
  // END_VNS_BANNED_LABEL_POLICY_DB_OVERRIDES

  // BEGIN_VNS_BANNED_EXTENSION_POLICY_DB_OVERRIDES
  virtual void add_banned_extension_policy_record(const banned_extension_policy_record& rec) override;
  virtual bool get_banned_extension_policy(const std::string& extension, uint64_t height, banned_extension_policy_record& rec) const override;
  virtual void add_banned_extension_policy_record_in_txn(const banned_extension_policy_record& rec) override;
  virtual void remove_banned_extension_policy_records_by_height_in_txn(uint64_t height) override;
  virtual bool for_all_banned_extension_policy_records(std::function<bool(const banned_extension_policy_record&)> f) const override;
  // END_VNS_BANNED_EXTENSION_POLICY_DB_OVERRIDES

  // BEGIN_VNS_EXACT_DOMAIN_BAN_POLICY_DB_OVERRIDES
  virtual void add_exact_domain_ban_policy_record(const exact_domain_ban_policy_record& rec) override;
  virtual bool get_exact_domain_ban_policy(const std::string& domain, uint64_t height, exact_domain_ban_policy_record& rec) const override;
  virtual void add_exact_domain_ban_policy_record_in_txn(const exact_domain_ban_policy_record& rec) override;
  virtual void remove_exact_domain_ban_policy_records_by_height_in_txn(uint64_t height) override;
  virtual void remove_exact_domain_ban_policy_records_by_domain_in_txn(const std::string& domain) override;
  virtual bool for_all_exact_domain_ban_policy_records(std::function<bool(const exact_domain_ban_policy_record&)> f) const override;
  // END_VNS_EXACT_DOMAIN_BAN_POLICY_DB_OVERRIDES

  // BEGIN_VNS_EXACT_DOMAIN_TIER_POLICY_DB_OVERRIDES
  virtual void add_exact_domain_tier_policy_record(const exact_domain_tier_policy_record& rec) override;
  virtual bool get_exact_domain_tier_policy(const std::string& domain, uint64_t height, exact_domain_tier_policy_record& rec) const override;
  virtual void add_exact_domain_tier_policy_record_in_txn(const exact_domain_tier_policy_record& rec) override;
  virtual void remove_exact_domain_tier_policy_records_by_height_in_txn(uint64_t height) override;
  virtual void remove_exact_domain_tier_policy_records_by_domain_in_txn(const std::string& domain) override;
  virtual bool for_all_exact_domain_tier_policy_records(std::function<bool(const exact_domain_tier_policy_record&)> f) const override;
  // END_VNS_EXACT_DOMAIN_TIER_POLICY_DB_OVERRIDES

  // BEGIN_VNS_PENDING_DOMAIN_POLICY_DB_OVERRIDES
  virtual void add_pending_domain_policy_record(const pending_domain_policy_record& rec) override;
  virtual bool get_pending_domain_policy(const std::string& domain, pending_domain_policy_record& rec) const override;
  virtual bool get_pending_domain_policy_by_proposal(const crypto::hash& proposal_id, pending_domain_policy_record& rec) const override;
  virtual void remove_pending_domain_policy_by_domain(const std::string& domain) override;
  virtual void remove_pending_domain_policy_by_proposal(const crypto::hash& proposal_id) override;
  virtual bool for_all_pending_domain_policy_records(std::function<bool(const pending_domain_policy_record&)> f) const override;
  // END_VNS_PENDING_DOMAIN_POLICY_DB_OVERRIDES

  virtual bool for_all_proposal_execution_records(std::function<bool(const crypto::hash&, const proposal_execution_record&)> f) const override;
  // END_VNS_PROPOSAL_EXECUTION_RECORD

  virtual void store_dkg_share(const crypto::public_key& member, const rct::key& share) override;
  virtual bool get_dkg_share(const crypto::public_key& member, rct::key& share) const override;
  virtual bool for_all_dkg_shares(std::function<bool(const crypto::public_key&, const rct::key&)> f) const override;
  virtual void set_committee_privkey(const crypto::secret_key& key) override;
  virtual bool get_committee_privkey(crypto::secret_key& key) const override;
  // BEGIN_VNS_PARTICIPATION_BALANCE
  virtual void set_proposal_outcome(const crypto::hash& proposal_id, uint64_t yes_weight, uint64_t no_weight, uint64_t yes_balance, uint64_t no_balance) override;
  virtual bool get_proposal_outcome(const crypto::hash& proposal_id, uint64_t& yes_weight, uint64_t& no_weight, uint64_t& yes_balance, uint64_t& no_balance) const override;
  // END_VNS_PARTICIPATION_BALANCE
  virtual void remove_proposal_outcome(const crypto::hash& proposal_id) override;
  virtual void set_proposal_data(const crypto::hash& proposal_id, const std::string& data_blob) override;
  virtual bool get_proposal_data(const crypto::hash& proposal_id, std::string& data_blob) const override;
  // BEGIN_VNS_DAO_VOTE
  virtual void add_vote_nullifier(const crypto::hash& proposal_id, const crypto::hash& nullifier) override;
  virtual bool has_vote_nullifier(const crypto::hash& proposal_id, const crypto::hash& nullifier) const override;
  virtual void remove_vote_nullifier(const crypto::hash& proposal_id, const crypto::hash& nullifier) override;
  virtual void remove_all_vote_nullifiers(const crypto::hash& proposal_id) override;
  // END_VNS_DAO_VOTE

  // BEGIN_VNS_TREASURY_LMDB_OVERRIDE
  virtual uint64_t add_treasury_output(uint64_t amount, uint64_t height) override;
  virtual bool get_treasury_output(uint64_t output_id, treasury_output& out) const override;
  virtual void remove_treasury_output(uint64_t output_id) override;
  virtual void remove_treasury_outputs_by_height(uint64_t height) override;
  virtual void mark_treasury_output_spent(uint64_t output_id, bool spent) override;
  virtual std::vector<treasury_output> get_unspent_treasury_outputs() const override;
  // END_VNS_TREASURY_LMDB_OVERRIDE

  bool block_rtxn_start(MDB_txn **mtxn, mdb_txn_cursors **mcur) const;

  virtual void pop_block(block& blk, std::vector<transaction>& txs);

  virtual bool can_thread_bulk_indices() const { return true; }

  /**
   * @brief return a histogram of outputs on the blockchain
   *
   * @param amounts optional set of amounts to lookup
   * @param unlocked whether to restrict count to unlocked outputs
   * @param recent_cutoff timestamp to determine which outputs are recent
   * @param min_count return only amounts with at least that many instances
   *
   * @return a set of amount/instances
   */
  std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> get_output_histogram(const std::vector<uint64_t> &amounts, bool unlocked, uint64_t recent_cutoff, uint64_t min_count) const;

  bool get_output_distribution(uint64_t amount, uint64_t from_height, uint64_t to_height, std::vector<uint64_t> &distribution, uint64_t &base) const;

  // helper functions
  static int compare_uint64(const MDB_val *a, const MDB_val *b);
  static int compare_hash32(const MDB_val *a, const MDB_val *b);
  static int compare_hash64(const MDB_val* a, const MDB_val* b);
  static int compare_string(const MDB_val *a, const MDB_val *b);

private:
  void do_resize(uint64_t size_increase=0);

  bool need_resize(uint64_t threshold_size=0) const;
  void check_and_resize_for_batch(uint64_t batch_num_blocks, uint64_t batch_bytes);
  uint64_t get_estimated_batch_size(uint64_t batch_num_blocks, uint64_t batch_bytes) const;

  virtual void add_block( const block& blk
                , size_t block_weight
                , uint64_t long_term_block_weight
                , const difficulty_type& cumulative_difficulty
                , const uint64_t& coins_generated
                , uint64_t num_rct_outs
                , const crypto::hash& block_hash
                );

  virtual void remove_block();

  virtual uint64_t add_transaction_data(const crypto::hash& blk_hash, const std::pair<transaction, blobdata_ref>& tx, const crypto::hash& tx_hash, const crypto::hash& tx_prunable_hash);

  virtual void remove_transaction_data(const crypto::hash& tx_hash, const transaction& tx);

  virtual uint64_t add_output(const crypto::hash& tx_hash,
      const tx_out& tx_output,
      const uint64_t& local_index,
      const uint64_t unlock_time,
      const rct::key *commitment
      );

  virtual void add_tx_amount_output_indices(const uint64_t tx_id,
      const std::vector<uint64_t>& amount_output_indices
      );

  void remove_tx_outputs(const uint64_t tx_id, const transaction& tx);

  void remove_output(const uint64_t amount, const uint64_t& out_index);

  virtual void prune_outputs(uint64_t amount);

  virtual void add_spent_key(const crypto::key_image& k_image);

  virtual void remove_spent_key(const crypto::key_image& k_image);

  uint64_t num_outputs() const;

  // Hard fork
  virtual void set_hard_fork_version(uint64_t height, uint8_t version);
  virtual uint8_t get_hard_fork_version(uint64_t height) const;
  virtual void check_hard_fork_info();
  virtual void drop_hard_fork_info();

  inline void check_open() const;

  bool prune_worker(int mode, uint32_t pruning_seed);

  virtual bool is_read_only() const;

  virtual uint64_t get_database_size() const;

  std::vector<uint64_t> get_block_info_64bit_fields(uint64_t start_height, size_t count, off_t offset) const;

  uint64_t get_max_block_size();
  void add_max_block_size(uint64_t sz);

  // fix up anything that may be wrong due to past bugs
  virtual void fixup();

  // migrate from older DB version to current
  void migrate(const uint32_t oldversion);

  // migrate from DB version 0 to 1
  void migrate_0_1();

  // migrate from DB version 1 to 2
  void migrate_1_2();

  // migrate from DB version 2 to 3
  void migrate_2_3();

  // migrate from DB version 3 to 4
  void migrate_3_4();

  // migrate from DB version 4 to 5
  void migrate_4_5();

  void cleanup_batch();

private:
  MDB_env* m_env;

  MDB_dbi m_blocks;
  MDB_dbi m_block_heights;
  MDB_dbi m_block_info;

  MDB_dbi m_txs;
  MDB_dbi m_txs_pruned;
  MDB_dbi m_txs_prunable;
  MDB_dbi m_txs_prunable_hash;
  MDB_dbi m_txs_prunable_tip;
  MDB_dbi m_tx_indices;
  MDB_dbi m_tx_outputs;

  MDB_dbi m_output_txs;
  MDB_dbi m_output_amounts;

  MDB_dbi m_spent_keys;

  MDB_dbi m_txpool_meta;
  MDB_dbi m_txpool_blob;

  MDB_dbi m_alt_blocks;

  MDB_dbi m_hf_starting_heights;
  MDB_dbi m_hf_versions;

  MDB_dbi m_properties;
  MDB_dbi m_vns_domains;
  MDB_dbi m_vns_domain_heartbeat_events;
  MDB_dbi m_vns_heartbeat_proofs;
  MDB_dbi m_proposals;
  MDB_dbi m_votes;
  MDB_dbi m_vote_ciphertexts;
  MDB_dbi m_committee_eligible;
  MDB_dbi m_proposal_executions;
  MDB_dbi m_dkg_shares;
  MDB_dbi m_committee_key;
  MDB_dbi m_proposal_outcomes;
  MDB_dbi m_proposal_data;
  MDB_dbi m_pending_executions;
  MDB_dbi m_voting_end_queue;
  MDB_dbi m_governance_parameters;
  MDB_dbi m_extension_policy;
  MDB_dbi m_premium_label_policy;
  MDB_dbi m_banned_label_policy;
  MDB_dbi m_banned_extension_policy;
  MDB_dbi m_exact_domain_ban_policy;
  MDB_dbi m_exact_domain_tier_policy;
  MDB_dbi m_pending_domain_policy;
  MDB_dbi m_vote_nullifiers;
  MDB_dbi m_treasury_outputs;

  mutable uint64_t m_cum_size;	// used in batch size estimation
  mutable unsigned int m_cum_count;
  std::string m_folder;
  mdb_txn_safe* m_write_txn; // may point to either a short-lived txn or a batch txn
  mdb_txn_safe* m_write_batch_txn; // persist batch txn outside of BlockchainLMDB
  boost::thread::id m_writer;

  bool m_batch_transactions; // support for batch transactions
  bool m_batch_active; // whether batch transaction is in progress

  mdb_txn_cursors m_wcursors;
  mutable boost::thread_specific_ptr<mdb_threadinfo> m_tinfo;

#if defined(__arm__)
  // force a value so it can compile with 32-bit ARM
  constexpr static uint64_t DEFAULT_MAPSIZE = 1LL << 31;
#else
#if defined(ENABLE_AUTO_RESIZE)
  constexpr static uint64_t DEFAULT_MAPSIZE = 1LL << 30;
#else
  constexpr static uint64_t DEFAULT_MAPSIZE = 1LL << 33;
#endif
#endif

  constexpr static float RESIZE_PERCENT = 0.9f;
};

}  // namespace cryptonote
