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

namespace cryptonote {

VoteManager::VoteManager(GovernanceDB& db, const governance_params& params)
    : m_db(db), m_params(params) {}

bool VoteManager::process_block(const block& blk, uint64_t height)
{
    for (const auto& tx_hash : blk.tx_hashes) {
        transaction tx;
        if (!m_db.get_transaction(tx_hash, tx)) {
            MERROR("Failed to get transaction " << tx_hash);
            return false;
        }

        vote_result res = process_vote(tx, height, false);
        if (res == vote_result::already_voted) {
            // Duplicate votes are allowed – just skip
            MWARNING("Duplicate vote in tx " << tx_hash << " – skipped");
            continue;
        }
        if (res != vote_result::success && res != vote_result::missing_vote_tag) {
            MERROR("Vote processing failed for tx " << tx_hash << " with result " << (int)res);
            return false;
        }
    }
    return true;
}

bool VoteManager::rollback_block(const block& blk, uint64_t height)
{
    for (const auto& tx_hash : blk.tx_hashes) {
        transaction tx;
        if (!m_db.get_transaction(tx_hash, tx))
            continue;
        if (!is_vote_tx(tx))
            continue;

        vote_proof vp;
        if (!extract_vote(tx, vp))
            continue;

        // BEGIN_VNS_VOTE_RECORD_ROLLBACK
        // Remove the vote record (key_image) from the DB
        if (tx.vin.size() == 1 && tx.vin[0].type() == typeid(txin_vns_vote))
        {
            const auto& vote_in = boost::get<txin_vns_vote>(tx.vin[0]);
            m_db.remove_vote_record(vp.proposal_id, vote_in.k_image);
        }
        // END_VNS_VOTE_RECORD_ROLLBACK

        crypto::hash nullifier = vp.voting_nullifiers.empty() ? crypto::null_hash : vp.voting_nullifiers[0];
        if (nullifier == crypto::null_hash)
            continue;

        // Remove nullifier
        m_db.remove_nullifier(vp.proposal_id, nullifier);

        // Subtract from tally
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

        MINFO("Rolled back vote for proposal " << vp.proposal_id);
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

// BEGIN_VNS_PROCESS_VOTE
vote_result VoteManager::process_vote(const transaction& tx, uint64_t height, bool dry_run)
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

    if (height > rec.voting_end_height || height < rec.submission_height)
    {
        MERROR("Voting period not active");
        return vote_result::voting_period_closed;
    }

    if (dry_run)
        return vote_result::success;

    // Nullifier duplicate check (single representative nullifier)
    crypto::hash nullifier = vp.voting_nullifiers.empty() ? crypto::null_hash : vp.voting_nullifiers[0];
    if (nullifier == crypto::null_hash)
    {
        MERROR("Vote has no nullifier");
        return vote_result::invalid_format;
    }

    if (m_db.has_nullifier(vp.proposal_id, nullifier))
    {
        MWARNING("Duplicate nullifier: " << nullifier);
        return vote_result::already_voted;
    }

    m_db.add_nullifier(vp.proposal_id, nullifier);

    // Use the totals declared by the wallet (placeholder proof trust)
    uint64_t total_balance = vp.participation_balance;
    uint64_t total_weight  = vp.voting_weight;

    if (total_balance == 0 || total_weight == 0)
    {
        MERROR("Vote balance or weight is zero");
        return vote_result::invalid_format;
    }

    // Update tally
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
    m_db.set_outcome(vp.proposal_id, yes_w, no_w, yes_b, no_b);

    MINFO("Stored vote for proposal " << vp.proposal_id << " (direction="
          << (vp.direction_yes ? "yes" : "no") << ") at height " << height
          << " total_balance=" << total_balance << " total_weight=" << total_weight);
    return vote_result::success;
}
// END_VNS_PROCESS_VOTE

} // namespace cryptonote