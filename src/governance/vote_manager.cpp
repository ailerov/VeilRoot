// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "vote_manager.h"
#include "cryptonote_core/blockchain.h"   // for vote_record, vote_tally
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_config.h"
#include "serialization/binary_archive.h"
#include "span.h"
#include "crypto/crypto.h"
#include "misc_log_ex.h"
#include "serialization/string.h"
#include "governance_payload.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "voting_weight.h"
#include "vote_proof_verifier.h"
#include "dao_consistency.h"
#include "dao_dkg.h"
#include "dao_paillier.h"
#include "ringct/rctOps.h"
#include <limits>
#include <unordered_set>

namespace cryptonote {

VoteManager::VoteManager(GovernanceDB& db, const governance_params& params)
    : m_db(db), m_params(params) {}

bool VoteManager::process_block(const block& blk, uint64_t height)
{
    std::unordered_set<crypto::hash> block_nullifiers;

    for (const auto& tx_hash : blk.tx_hashes) {
        transaction tx;
        if (!m_db.get_transaction(tx_hash, tx)) {
            MERROR("Failed to get transaction " << tx_hash);
            return false;
        }

        const vote_kind kind = classify_vote_tx(tx);
        switch (kind) {
            case vote_kind::none:
                continue;

            case vote_kind::malformed:
                MERROR("Malformed governance object in tx " << tx_hash);
                return false;

            case vote_kind::multiple:
                MERROR("Multiple vote objects in tx " << tx_hash);
                return false;

            case vote_kind::v1: {
                const vote_result r = process_v1_vote(tx, height, false);
                if (r == vote_result::missing_vote_tag) continue;
                if (r != vote_result::success) {
                    MERROR("V1 vote processing failed for tx " << tx_hash
                           << " result " << (int)r);
                    return false;
                }
                break;
            }

            case vote_kind::v2: {
                const vote_result r = process_v2_vote(tx, tx_hash, height,
                                                      block_nullifiers, false);
                if (r != vote_result::success) {
                    MERROR("V2 vote processing failed for tx " << tx_hash
                           << " result " << (int)r);
                    return false;
                }
                break;
            }
        }
    }
    return true;
}

bool VoteManager::rollback_block(const block& blk,
                                 const std::vector<transaction>& txs,
                                 uint64_t height)
{
    // Build a tx-hash -> transaction map from the popped set; the LMDB
    // store may already have dropped or be in the process of dropping
    // these, so use the caller-supplied vector as the authoritative
    // source for V2 proof recovery.
    std::unordered_map<crypto::hash, const transaction*> by_hash;
    for (const auto& tx : txs) {
        by_hash[cryptonote::get_transaction_hash(tx)] = &tx;
    }

    for (const auto& tx_hash : blk.tx_hashes) {
        transaction tx_storage;
        const transaction* txp = nullptr;
        auto it = by_hash.find(tx_hash);
        if (it != by_hash.end()) {
            txp = it->second;
        } else {
            if (!m_db.get_transaction(tx_hash, tx_storage))
                continue;
            txp = &tx_storage;
        }
        const transaction& tx = *txp;

        const vote_kind kind = classify_vote_tx(tx);

        if (kind == vote_kind::v1) {
            vote_proof vp;
            if (!extract_vote(tx, vp))
                continue;

            // BEGIN_VNS_VOTE_RECORD_ROLLBACK
            if (tx.vin.size() == 1 && tx.vin[0].type() == typeid(txin_vns_vote))
            {
                const auto& vote_in = boost::get<txin_vns_vote>(tx.vin[0]);
                m_db.remove_vote_record(vp.proposal_id, vote_in.k_image);
            }
            // END_VNS_VOTE_RECORD_ROLLBACK

            crypto::hash nullifier = vp.voting_nullifiers.empty()
                ? crypto::null_hash : vp.voting_nullifiers[0];
            if (nullifier == crypto::null_hash)
                continue;

            m_db.remove_nullifier(vp.proposal_id, nullifier);

            uint64_t yes_w, no_w, yes_b, no_b;
            if (m_db.get_outcome(vp.proposal_id, yes_w, no_w, yes_b, no_b)) {
                if (vp.direction_yes) {
                    yes_w -= (yes_w >= vp.voting_weight ? vp.voting_weight : yes_w);
                    yes_b -= (yes_b >= vp.participation_balance ? vp.participation_balance : yes_b);
                } else {
                    no_w -= (no_w >= vp.voting_weight ? vp.voting_weight : no_w);
                    no_b -= (no_b >= vp.participation_balance ? vp.participation_balance : no_b);
                }
                m_db.set_outcome(vp.proposal_id, yes_w, no_w, yes_b, no_b);
            }

            MINFO("Rolled back V1 vote for proposal " << vp.proposal_id);
            continue;
        }

        if (kind != vote_kind::v2)
            continue;

        vote_proof_v2 proof;
        if (!extract_vote_v2(tx, proof))
            continue;

        BlockchainDB& bdb = m_db.get_underlying_db();

        dao::dao_tally_key_record key_rec;
        if (!bdb.get_dao_tally_key(
                static_cast<uint32_t>(proof.tally_key_epoch), key_rec))
            continue;
        dao::PaillierPublicKey pk;
        if (!pk.deserialize_modulus(key_rec.N))
            continue;

        // Reverse the aggregate contribution.
        dao_proposal_aggregate agg;
        if (bdb.get_dao_proposal_aggregate(proof.proposal_id, agg)) {
            std::vector<uint8_t> E_W_in(proof.E_W.data.begin(),
                                        proof.E_W.data.end());
            std::vector<uint8_t> E_S_in(proof.E_S.data.begin(),
                                        proof.E_S.data.end());
            std::vector<uint8_t> inv, tmp;
            bool ok = true;
            if (!agg.aggregate_E_W.empty()) {
                ok = ok && pk.inverse(E_W_in, inv) &&
                     pk.add(agg.aggregate_E_W, inv, tmp);
                if (ok) agg.aggregate_E_W = tmp;
            }
            if (ok && !agg.aggregate_E_S.empty()) {
                ok = ok && pk.inverse(E_S_in, inv) &&
                     pk.add(agg.aggregate_E_S, inv, tmp);
                if (ok) agg.aggregate_E_S = tmp;
            }
            if (ok) {
                // Spec section 25: commitment rollback uses point
                // subtraction.
                rct::key new_C_W;
                rct::subKeys(new_C_W, agg.aggregate_C_W, proof.C_W);
                agg.aggregate_C_W = new_C_W;

                rct::key new_C_S;
                rct::subKeys(new_C_S, agg.aggregate_C_S, proof.C_S);
                agg.aggregate_C_S = new_C_S;

                bdb.add_dao_proposal_aggregate(proof.proposal_id, agg);
            }
        }

        bdb.remove_dao_vote_record_v2(tx_hash);

        for (const auto& nf : proof.nullifiers)
            bdb.remove_vote_nullifier(proof.proposal_id, nf);

        MINFO("Rolled back V2 vote for proposal " << proof.proposal_id);
    }
    return true;
}

bool VoteManager::vote_exists(const crypto::hash& proposal_id, const crypto::hash& nullifier) const
{
    return m_db.has_nullifier(proposal_id, nullifier);
}

bool VoteManager::validate_vote(const vote_proof& vp, uint64_t height) const
{
    // Version
    if (vp.version != 1) {
        MERROR("Unsupported vote version " << (int)vp.version);
        return false;
    }

    // Check proposal exists
    proposal_record rec;
    if (!m_db.get_proposal(vp.proposal_id, rec)) {
        MERROR("Proposal not found: " << vp.proposal_id);
        return false;
    }

    // Check voting window
    if (height < rec.submission_height || height > rec.voting_end_height) {
        MERROR("Voting period not active for proposal " << vp.proposal_id);
        return false;
    }

    return true;
}

bool VoteManager::is_vote_tx(const transaction& tx) const
{
    for (size_t i = 0; i < tx.extra.size(); ++i) {
        if (tx.extra[i] == TX_EXTRA_GOVERNANCE) {
            epee::span<const uint8_t> data_span(tx.extra.data() + i + 1, tx.extra.size() - i - 1);
            binary_archive<false> ar(data_span);
            governance_payload gp;
            if (!::serialization::serialize(ar, gp))
                return false;
            return gp.type == governance_object::vote;
        }
    }
    return false;
}

bool VoteManager::extract_vote(const transaction& tx, vote_proof& vp) const
{
    std::vector<tx_extra_field> extra_fields;
    if (!parse_tx_extra(tx.extra, extra_fields))
        return false;

    for (const auto& field : extra_fields)
    {
        if (field.type() == typeid(tx_extra_governance_payload))
        {
            const auto& gp_field = boost::get<tx_extra_governance_payload>(field);
            const governance_payload& gp = gp_field.payload;
            if (gp.type != governance_object::vote)
                return false;

            epee::span<const uint8_t> data_span(gp.data.data(), gp.data.size());
            binary_archive<false> data_ar(data_span);
            if (!::serialization::serialize(data_ar, vp))
            {
                MERROR("Failed to deserialize vote_proof from governance payload");
                return false;
            }
            return true;
        }
    }
    return false;
}

// Extract a V2 vote from a tx carrying governance_object::vote_v2.
// gp.data must contain exactly one canonical serialized vote_proof_v2;
// truncation or trailing bytes are rejected. Returns false if no V2
// vote object is present, or if the object is malformed.
bool VoteManager::extract_vote_v2(const transaction& tx, vote_proof_v2& vp) const
{
    std::vector<tx_extra_field> extra_fields;
    if (!parse_tx_extra(tx.extra, extra_fields))
        return false;

    for (const auto& field : extra_fields)
    {
        if (field.type() != typeid(tx_extra_governance_payload))
            continue;
        const auto& gp_field = boost::get<tx_extra_governance_payload>(field);
        const governance_payload& gp = gp_field.payload;
        if (gp.type != governance_object::vote_v2)
            continue;

        if (gp.data.empty())
            return false;

        epee::span<const uint8_t> data_span(gp.data.data(), gp.data.size());
        binary_archive<false> data_ar(data_span);
        if (!::serialization::serialize(data_ar, vp))
            return false;

        // Strict consumption: nothing may remain.
        if (data_ar.getpos() != data_span.size())
            return false;

        if (vp.version != vote_proof_v2::VERSION)
            return false;

        return true;
    }
    return false;
}

vote_kind VoteManager::classify_vote_tx(const transaction& tx) const
{
    std::vector<tx_extra_field> extra_fields;
    if (!parse_tx_extra(tx.extra, extra_fields))
        return vote_kind::malformed;

    int v1 = 0, v2 = 0;
    for (const auto& field : extra_fields) {
        if (field.type() != typeid(tx_extra_governance_payload))
            continue;
        const governance_payload& gp =
            boost::get<tx_extra_governance_payload>(field).payload;
        switch (gp.type) {
            case governance_object::proposal:
            case governance_object::execution:
                break;
            case governance_object::vote:
                ++v1;
                break;
            case governance_object::vote_v2:
                ++v2;
                break;
            default:
                return vote_kind::malformed;
        }
    }

    if (v1 + v2 == 0) return vote_kind::none;
    if (v1 + v2 > 1)  return vote_kind::multiple;
    return (v2 == 1) ? vote_kind::v2 : vote_kind::v1;
}

// BEGIN_VNS_PROCESS_VOTE
vote_result VoteManager::process_vote(const transaction& tx, uint64_t height, bool dry_run)
{
    switch (classify_vote_tx(tx)) {
        case vote_kind::none:     return vote_result::missing_vote_tag;
        case vote_kind::malformed:
        case vote_kind::multiple: return vote_result::invalid_format;
        case vote_kind::v1:       return process_v1_vote(tx, height, dry_run);
        case vote_kind::v2: {
            std::unordered_set<crypto::hash> bn;
            const crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);
            return process_v2_vote(tx, tx_hash, height, bn, dry_run);
        }
    }
    return vote_result::invalid_format;
}

vote_result VoteManager::process_v1_vote(const transaction& tx, uint64_t height, bool dry_run)
{
    if (!is_vote_tx(tx))
        return vote_result::missing_vote_tag;

    vote_proof vp;
    if (!extract_vote(tx, vp))
    {
        MERROR("Failed to extract vote from transaction");
        return vote_result::invalid_format;
    }

    // Basic metadata validation
    if (vp.version != 1)
    {
        MERROR("Unsupported vote version " << (int)vp.version);
        return vote_result::invalid_format;
    }

    proposal_record rec;
    if (!m_db.get_proposal(vp.proposal_id, rec))
    {
        MERROR("Proposal not found: " << vp.proposal_id);
        return vote_result::invalid_proposal_id;
    }

    // V1 is forbidden after the proposal's tally-key epoch activates.
    {
        dao::dao_tally_key_record key_rec;
        if (m_db.get_underlying_db().get_dao_tally_key(
                static_cast<uint32_t>(rec.tally_key_epoch), key_rec))
        {
            if (height >= key_rec.activation_height) {
                MERROR("V1 vote rejected: DAO V2 active for this proposal");
                return vote_result::invalid_format;
            }
        }
    }

    if (height > rec.voting_end_height || height < rec.submission_height)
    {
        MERROR("Voting period not active");
        return vote_result::voting_period_closed;
    }

    if (dry_run)
        return vote_result::success;

    // Nullifier duplicate check - using proposal-scoped nullifiers
    crypto::hash nullifier = vp.voting_nullifiers.empty() ? crypto::null_hash : vp.voting_nullifiers[0];
    if (nullifier == crypto::null_hash)
    {
        MERROR("Vote has no nullifier");
        return vote_result::invalid_format;
    }

    // Check for duplicate voting - reject if nullifier already exists
    if (m_db.has_nullifier(vp.proposal_id, nullifier))
    {
        MWARNING("Duplicate nullifier detected: " << nullifier);
        return vote_result::already_voted;
    }

    // Calculate deterministic voting weights from blockchain state
    uint64_t total_balance = vp.participation_balance;

    // V2 helper returns exact 128-bit weight. The V1 tally storage is still
    // 64-bit; the V2 tally rewrite will replace this boundary. Until then,
    // accumulate wide and narrow once with an explicit range check.
    governance_weight_t wide_total_weight = 0;

    // V2 requires output heights for deterministic weight calculation
    if (!vp.output_heights.empty() && vp.output_heights.size() == vp.voting_nullifiers.size())
    {
        // Calculate weight for each output - must succeed or reject vote
        for (size_t i = 0; i < vp.output_heights.size(); ++i)
        {
            governance_weight_t output_weight;
            if (!calculate_voting_weight(
                vp.participation_balance / vp.voting_nullifiers.size(),
                vp.output_heights[i],
                height,
                output_weight))
            {
                MERROR("Voting weight calculation invalid - rejecting vote");
                return vote_result::invalid_format;
            }
            wide_total_weight += output_weight;
        }
    }
    else
    {
        // V2: Reject votes without proper height information (no fallback to wallet values)
        MERROR("Vote missing required output heights for deterministic weight calculation");
        return vote_result::invalid_format;
    }

    if (wide_total_weight > governance_weight_t(std::numeric_limits<uint64_t>::max()))
    {
        MERROR("Aggregate voting weight exceeds V1 tally range - rejecting vote");
        return vote_result::invalid_format;
    }
    uint64_t total_weight = wide_total_weight.convert_to<uint64_t>();

    if (total_balance == 0 || total_weight == 0)
    {
        MERROR("Vote balance or weight is zero");
        return vote_result::invalid_format;
    }

    // Update tally with deterministic weights
    uint64_t yes_w, no_w, yes_b, no_b;
    if (!m_db.get_outcome(vp.proposal_id, yes_w, no_w, yes_b, no_b))
        yes_w = no_w = yes_b = no_b = 0;

    if (vp.direction_yes)
    {
        yes_w += total_weight;
        yes_b += total_balance;
    }
    else
    {
        no_w += total_weight;
        no_b += total_balance;
    }

    // Only persist the nullifier once all validation has passed and the
    // vote is actually being counted. Writing it earlier would poison the
    // nullifier table if a later validation rejected the vote.
    m_db.add_nullifier(vp.proposal_id, nullifier);
    m_db.set_outcome(vp.proposal_id, yes_w, no_w, yes_b, no_b);

    MINFO("Stored vote for proposal " << vp.proposal_id << " (direction="
          << (vp.direction_yes ? "yes" : "no") << ") at height " << height
          << " total_balance=" << total_balance << " total_weight=" << total_weight
          << " using deterministic weights");

    MINFO("Stored vote for proposal " << vp.proposal_id << " (direction="
          << (vp.direction_yes ? "yes" : "no") << ") at height " << height
          << " total_balance=" << total_balance << " total_weight=" << total_weight);
    return vote_result::success;
}
// END_VNS_PROCESS_VOTE

vote_result VoteManager::process_v2_vote(
    const transaction& tx,
    const crypto::hash& tx_hash,
    uint64_t height,
    std::unordered_set<crypto::hash>& block_nullifiers,
    bool dry_run)
{
    vote_proof_v2 proof;
    if (!extract_vote_v2(tx, proof)) {
        MERROR("Failed to extract V2 vote");
        return vote_result::invalid_format;
    }

    proposal_record prop;
    if (!m_db.get_proposal(proof.proposal_id, prop)) {
        MERROR("V2 vote: proposal not found");
        return vote_result::invalid_proposal_id;
    }

    // Activation: tally-key epoch for this proposal must be active.
    dao::dao_tally_key_record key_rec;
    if (!m_db.get_underlying_db().get_dao_tally_key(
            static_cast<uint32_t>(proof.tally_key_epoch), key_rec))
    {
        MERROR("V2 vote: tally key not found for epoch "
               << proof.tally_key_epoch);
        return vote_result::invalid_proposal_id;
    }
    if (height < key_rec.activation_height) {
        MERROR("V2 vote: tally key not yet active");
        return vote_result::voting_period_closed;
    }

    BlockchainDB& bdb = m_db.get_underlying_db();
    const auto vr = VoteProofVerifier::verify(proof, bdb, height, block_nullifiers);
    if (!vr.success) {
        MERROR("V2 vote verification failed: " << vr.reason);
        return vote_result::invalid_signature;
    }

    if (dry_run)
        return vote_result::success;

    if (!apply_dao_vote(proof, tx_hash)) {
        MERROR("V2 vote: apply_dao_vote failed");
        return vote_result::invalid_format;
    }

    for (const auto& nf : proof.nullifiers)
        block_nullifiers.insert(nf);

    MINFO("Stored V2 vote for proposal " << proof.proposal_id
          << " epoch=" << proof.tally_key_epoch
          << " height=" << height);
    return vote_result::success;
}

bool VoteManager::apply_dao_vote(const vote_proof_v2& proof,
                                 const crypto::hash& tx_hash)
{
    BlockchainDB& bdb = m_db.get_underlying_db();

    dao::dao_tally_key_record key_rec;
    if (!bdb.get_dao_tally_key(static_cast<uint32_t>(proof.tally_key_epoch),
                               key_rec))
        return false;

    dao::PaillierPublicKey pk;
    if (!pk.deserialize_modulus(key_rec.N))
        return false;

    dao_proposal_aggregate agg;
    const bool have_agg = bdb.get_dao_proposal_aggregate(proof.proposal_id, agg);
    if (!have_agg) {
        agg.aggregate_C_W = rct::identity();
        agg.aggregate_C_S = rct::identity();
    }

    std::vector<uint8_t> E_W_in(proof.E_W.data.begin(), proof.E_W.data.end());
    std::vector<uint8_t> E_S_in(proof.E_S.data.begin(), proof.E_S.data.end());

    if (have_agg && !agg.aggregate_E_W.empty() && !agg.aggregate_E_S.empty()) {
        std::vector<uint8_t> tmp;
        if (!pk.add(agg.aggregate_E_W, E_W_in, tmp)) return false;
        agg.aggregate_E_W = tmp;
        if (!pk.add(agg.aggregate_E_S, E_S_in, tmp)) return false;
        agg.aggregate_E_S = tmp;
    } else {
        agg.aggregate_E_W = E_W_in;
        agg.aggregate_E_S = E_S_in;
    }

    rct::key tmp_k;
    rct::addKeys(tmp_k, agg.aggregate_C_W, proof.C_W);
    agg.aggregate_C_W = tmp_k;
    rct::addKeys(tmp_k, agg.aggregate_C_S, proof.C_S);
    agg.aggregate_C_S = tmp_k;

    bdb.add_dao_proposal_aggregate(proof.proposal_id, agg);

    dao_vote_record_v2 rec;
    rec.proposal_id = proof.proposal_id;
    rec.vote_height = proof.vote_height;
    rec.tx_hash     = tx_hash;
    rec.nullifiers  = proof.nullifiers;
    bdb.add_dao_vote_record_v2(tx_hash, rec);

    for (const auto& nf : proof.nullifiers)
        bdb.add_vote_nullifier(proof.proposal_id, nf);

    return true;
}

} // namespace cryptonote