// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "proposal.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_config.h"
#include "serialization/binary_archive.h"
#include "span.h"   // epee span header
#include "crypto/crypto.h"   // for crypto::null_pkey
#include "misc_log_ex.h"     // for MERROR, MINFO
#include "cryptonote_basic/cryptonote_format_utils.h"   // for parse_and_validate_tx_from_blob
#include <cstring>           // for memset
#include "governance_payload.h"
#include "parameter_update.h"
#include "common/domain_utils.h"

namespace cryptonote {

ProposalManager::ProposalManager(GovernanceDB& db, const governance_params& params)
    : m_db(db), m_params(params) {}

bool ProposalManager::process_block(const block& blk, uint64_t height)
{
    for (const auto& tx_hash : blk.tx_hashes) {
        transaction tx;
        if (!m_db.get_transaction(tx_hash, tx)) {
            MERROR("Failed to get transaction " << tx_hash);
            return false;
        }

        if (!is_proposal_tx(tx))
            continue;

        if (!index_proposal(tx, tx_hash, height))
            return false;
    }
    return true;
}

// BEGIN_VNS_INDEX_PROPOSAL
bool ProposalManager::index_proposal(const transaction& tx, const crypto::hash& tx_hash, uint64_t height)
{
    if (!is_proposal_tx(tx))
        return true;

    proposal p;
    std::vector<uint8_t> data_blob;
    if (!extract_proposal(tx, p, data_blob))
    {
        MERROR("Failed to extract proposal from transaction " << tx_hash);
        return false;
    }

    if (!validate_proposal(p, height, data_blob))
    {
        MERROR("Invalid proposal in transaction " << tx_hash);
        return false;
    }

    uint64_t start_height = (p.voting_start_height == 0) ? height + 1 : p.voting_start_height;
    uint64_t end_height = p.voting_end_height;
    if (end_height == 0)
    {
        uint64_t blocks_per_day = 720;
        end_height = start_height + p.voting_period_days * blocks_per_day;
    }

    proposal_record rec;
    rec.proposal_id = tx_hash;
    rec.type = static_cast<uint8_t>(p.action);
    rec.amount = p.amount;
    rec.voting_end_height = end_height;
    rec.submission_height = height;
    rec.submission_tx_hash = tx_hash;
    rec.executed = false;
    rec.status = PROPOSAL_STATUS_ACTIVE;
    rec.status_height = height;
    rec.is_subaddress = p.is_subaddress;   // preserve subaddress flag for execution derivation
    rec.recipient_view_public_key = p.recipient_view_public_key;
    rec.voting_period_days = p.voting_period_days;

    {
        std::string t(p.title.begin(), p.title.end());
        std::string d(p.description.begin(), p.description.end());
        strncpy(rec.title, t.c_str(), sizeof(rec.title) - 1);
        rec.title[sizeof(rec.title) - 1] = '\0';
        strncpy(rec.description, d.c_str(), sizeof(rec.description) - 1);
        rec.description[sizeof(rec.description) - 1] = '\0';
    }

    rec.recipient[0] = '\0';
    if (p.action == proposal_action::treasury_payment)
    {
        std::string addr_str = cryptonote::get_account_address_as_str(m_db.nettype(), p.is_subaddress, p.destination);
        strncpy(rec.recipient, addr_str.c_str(), sizeof(rec.recipient) - 1);
        rec.recipient[sizeof(rec.recipient) - 1] = '\0';
    }

    // BEGIN_VNS_PENDING_DOMAIN_POLICY_INDEX
    if (p.action == proposal_action::parameter_change && !data_blob.empty())
    {
        const uint8_t pv = static_cast<uint8_t>(data_blob[0]);
        if (pv == 6 || pv == 7)
        {
            std::string normalized_domain;
            uint8_t action = 0;
            bool enable = false;
            uint8_t tier = 0;

            if (pv == 6)
            {
                exact_domain_tier_update_payload payload;
                epee::span<const uint8_t> span(
                    reinterpret_cast<const uint8_t*>(data_blob.data()), data_blob.size());
                binary_archive<false> ar(span);
                if (!::serialization::serialize(ar, payload))
                {
                    MERROR("Failed to deserialize exact-domain tier payload");
                    return false;
                }
                normalized_domain = domain_utils::normalize_vns_domain(payload.domain);
                if (normalized_domain.empty())
                {
                    MERROR("Invalid exact-domain tier policy domain");
                    return false;
                }
                action = 0;
                enable = payload.enable;
                tier = payload.tier;
            }
            else
            {
                exact_domain_ban_update_payload payload;
                epee::span<const uint8_t> span(
                    reinterpret_cast<const uint8_t*>(data_blob.data()), data_blob.size());
                binary_archive<false> ar(span);
                if (!::serialization::serialize(ar, payload))
                {
                    MERROR("Failed to deserialize exact-domain ban payload");
                    return false;
                }
                normalized_domain = domain_utils::normalize_vns_domain(payload.domain);
                if (normalized_domain.empty())
                {
                    MERROR("Invalid exact-domain ban policy domain");
                    return false;
                }
                action = 1;
                enable = payload.enable;
            }

            pending_domain_policy_record existing;
            if (m_db.get_pending_domain_policy(normalized_domain, existing))
            {
                MERROR("A pending domain policy already exists for " << normalized_domain);
                return false;
            }

            pending_domain_policy_record pending;
            memset(&pending, 0, sizeof(pending));
            strncpy(pending.domain, normalized_domain.c_str(), sizeof(pending.domain) - 1);
            pending.proposal_id = tx_hash;
            pending.voting_end_height = rec.voting_end_height;
            pending.action = action;
            pending.enable = enable;
            pending.tier = tier;
            pending.submission_height = height;
            m_db.add_pending_domain_policy_record(pending);
        }
    }
    // END_VNS_PENDING_DOMAIN_POLICY_INDEX

    m_db.store_proposal(rec);
    // BEGIN_VNS_STORE_PROPOSAL_DATA
    if (p.action == proposal_action::parameter_change)
        m_db.set_proposal_data(tx_hash, std::string(data_blob.begin(), data_blob.end()));
    // END_VNS_STORE_PROPOSAL_DATA
    m_db.add_voting_end_entry(rec.voting_end_height + 1, tx_hash);
    MINFO("Stored proposal " << rec.proposal_id << " at height " << height);
    return true;
}
// END_VNS_INDEX_PROPOSAL

// BEGIN_VNS_REINDEX
void ProposalManager::reindex_governance(uint64_t start_height, uint64_t end_height)
{
    for (uint64_t h = start_height; h <= end_height; ++h)
    {
        block blk;
        crypto::hash block_hash = m_db.get_underlying_db().get_block_hash_from_height(h);
        if (block_hash == crypto::null_hash)
        {
            MWARNING("Reindex: no block hash at height " << h << ", skipping");
            continue;
        }
        blk = m_db.get_underlying_db().get_block(block_hash);
        {
            MWARNING("Reindex: block not found at height " << h << ", skipping");
            continue;
        }

        try { m_db.block_wtxn_start(); }
        catch (const std::exception& e) {
            MERROR("Reindex: failed to start write txn at height " << h << ": " << e.what());
            continue;
        }

        try
        {
            for (const auto& tx_hash : blk.tx_hashes)
            {
                // Skip if proposal record already exists
                proposal_record existing;
                if (m_db.get_proposal(tx_hash, existing))
                    continue;

                transaction tx;
                if (!m_db.get_transaction(tx_hash, tx))
                {
                    MWARNING("Reindex: cannot get transaction " << tx_hash << " at height " << h);
                    continue;
                }

                if (!index_proposal(tx, tx_hash, h))
                {
                    MWARNING("Reindex: failed to index proposal " << tx_hash << " at height " << h);
                }
            }
            m_db.block_wtxn_stop();
        }
        catch (const std::exception& e)
        {
            m_db.block_wtxn_abort();
            MERROR("Reindex: exception at height " << h << ": " << e.what());
        }
    }
}
// END_VNS_REINDEX

bool ProposalManager::rollback_block(const block& blk, const std::vector<transaction>& txs, uint64_t height)
{
    for (const auto& tx : txs)
    {
        if (!is_proposal_tx(tx))
            continue;

        crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);

        // Remove pending exact-domain lock, if any
        m_db.remove_pending_domain_policy_by_proposal(tx_hash);

        // Remove voting‑end entry
        proposal_record rec;
        if (m_db.get_proposal(tx_hash, rec))
        {
            m_db.remove_voting_end_entry(rec.voting_end_height + 1, tx_hash);
        }

        // Remove proposal record
        m_db.remove_proposal(tx_hash);
        MINFO("Rolled back proposal " << tx_hash);
    }
    return true;
}

bool ProposalManager::proposal_exists(const crypto::hash& proposal_id) const
{
    proposal_record rec;
    return m_db.get_proposal(proposal_id, rec);
}

bool ProposalManager::get_proposal_record(const crypto::hash& proposal_id, proposal_record& rec) const
{
    return m_db.get_proposal(proposal_id, rec);
}

bool ProposalManager::validate_proposal(const proposal& p, uint64_t height, const std::vector<uint8_t>& data_blob) const
{
    if (p.version != 1) {
        MERROR("Unsupported proposal version " << (int)p.version);
        return false;
    }

    if (p.voting_period_days < 1 || p.voting_period_days > 30) {
        MERROR("voting_period_days must be between 1 and 30, got " << (int)p.voting_period_days);
        return false;
    }

    uint64_t start_height = (p.voting_start_height == 0) ? height + 1 : p.voting_start_height;
    if (start_height <= height) {
        MERROR("voting_start_height must be greater than current height");
        return false;
    }
    if (p.voting_end_height != 0 && p.voting_end_height <= start_height) {
        MERROR("voting_end_height must be after voting_start_height");
        return false;
    }
    if (p.action == proposal_action::treasury_payment && p.amount == 0) {
        MERROR("Treasury payment amount must be > 0");
        return false;
    }
    if (p.action == proposal_action::treasury_payment) {
        if (p.destination.m_view_public_key == crypto::null_pkey ||
            p.destination.m_spend_public_key == crypto::null_pkey) {
            MERROR("Invalid destination address");
            return false;
        }
    }
    if (p.metadata_hash == crypto::null_hash) {
        MERROR("metadata_hash cannot be zero");
        return false;
    }

    // BEGIN_VNS_PARAMETER_UPDATE_VALIDATION
    if (p.action == proposal_action::parameter_change)
    {
        if (data_blob.empty())
        {
            MERROR("parameter_change proposal requires a governance update payload");
            return false;
        }

        const uint8_t payload_version = data_blob[0];

        if (payload_version == 1)
        {
            parameter_update_payload payload;
            epee::span<const uint8_t> payload_span(data_blob.data(), data_blob.size());
            binary_archive<false> payload_ar(payload_span);
            if (!::serialization::serialize(payload_ar, payload))
            {
                MERROR("Failed to deserialize parameter_update_payload");
                return false;
            }

            if (payload.entries.size() != 6)
            {
                MERROR("parameter_update_payload must contain exactly 6 fee entries");
                return false;
            }

            for (size_t i = 0; i < payload.entries.size(); ++i)
            {
                const governance_parameter expected = static_cast<governance_parameter>(
                    static_cast<uint8_t>(governance_parameter::domain_tier_fee_0) + i);
                const auto& entry = payload.entries[i];
                if (entry.parameter != expected)
                {
                    MERROR("Invalid parameter order at index " << i);
                    return false;
                }
                if (entry.value < MIN_DOMAIN_TIER_FEE || entry.value > MAX_DOMAIN_TIER_FEE)
                {
                    MERROR("Fee out of bounds at index " << i << ": " << entry.value);
                    return false;
                }
            }
        }
        else if (payload_version == 2)
        {
            extension_update_payload payload;
            epee::span<const uint8_t> payload_span(data_blob.data(), data_blob.size());
            binary_archive<false> payload_ar(payload_span);
            if (!::serialization::serialize(payload_ar, payload))
            {
                MERROR("Failed to deserialize extension_update_payload");
                return false;
            }

            const std::string normalized_extension = domain_utils::normalize_vns_extension(payload.extension);
            if (normalized_extension.empty())
            {
                MERROR("Invalid extension in extension_update_payload: " << payload.extension);
                return false;
            }

            if (payload.tier > 5)
            {
                MERROR("Extension tier must be 0..5");
                return false;
            }
        }
        else if (payload_version == 3 || payload_version == 4 || payload_version == 5)
        {
            label_policy_update_payload payload;
            epee::span<const uint8_t> payload_span(data_blob.data(), data_blob.size());
            binary_archive<false> payload_ar(payload_span);
            if (!::serialization::serialize(payload_ar, payload))
            {
                MERROR("Failed to deserialize label_policy_update_payload");
                return false;
            }

            if (payload.version != payload_version)
            {
                MERROR("Label policy payload version mismatch");
                return false;
            }

            std::string normalized_term;
            if (payload_version == 5)
                normalized_term = domain_utils::normalize_vns_extension(payload.term);
            else
                normalized_term = domain_utils::normalize_vns_label(payload.term);

            if (normalized_term.empty())
            {
                MERROR("Invalid policy term in label_policy_update_payload: " << payload.term);
                return false;
            }
        }
        else if (payload_version == 6)
        {
            exact_domain_tier_update_payload payload;
            epee::span<const uint8_t> payload_span(data_blob.data(), data_blob.size());
            binary_archive<false> payload_ar(payload_span);
            if (!::serialization::serialize(payload_ar, payload))
            {
                MERROR("Failed to deserialize exact_domain_tier_update_payload");
                return false;
            }

            if (payload.version != 6)
                return false;

            const std::string normalized = domain_utils::normalize_vns_domain(payload.domain);
            if (normalized.empty())
            {
                MERROR("Invalid exact domain: " << payload.domain);
                return false;
            }

            if (payload.tier > 5)
            {
                MERROR("Exact domain tier must be 0..5");
                return false;
            }
        }
        else if (payload_version == 7)
        {
            exact_domain_ban_update_payload payload;
            epee::span<const uint8_t> payload_span(data_blob.data(), data_blob.size());
            binary_archive<false> payload_ar(payload_span);
            if (!::serialization::serialize(payload_ar, payload))
            {
                MERROR("Failed to deserialize exact_domain_ban_update_payload");
                return false;
            }

            if (payload.version != 7)
                return false;

            const std::string normalized = domain_utils::normalize_vns_domain(payload.domain);
            if (normalized.empty())
            {
                MERROR("Invalid exact domain: " << payload.domain);
                return false;
            }

            vns_domain_record existing_domain;
            if (m_db.get_underlying_db().get_vns_domain_record(normalized, existing_domain))
            {
                MERROR("Exact-domain ban proposal targets an already registered domain: " << normalized);
                return false;
            }
        }
        else
        {
            MERROR("Unsupported governance update payload version " << (int)payload_version);
            return false;
        }
    }
    // END_VNS_PARAMETER_UPDATE_VALIDATION

    return true;
}

bool ProposalManager::is_proposal_tx(const transaction& tx) const
{
    std::vector<tx_extra_field> extra_fields;
    if (!parse_tx_extra(tx.extra, extra_fields))
        return false;

    for (const auto& field : extra_fields)
    {
        if (field.type() == typeid(tx_extra_governance_payload))
        {
            const auto& gp_field = boost::get<tx_extra_governance_payload>(field);
            return gp_field.payload.type == governance_object::proposal;
        }
    }

    return false;
}

bool ProposalManager::extract_proposal(const transaction& tx, proposal& p, std::vector<uint8_t>& data_blob) const
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
            if (gp.type != governance_object::proposal)
                return false;

            epee::span<const uint8_t> data_span(gp.data.data(), gp.data.size());
            binary_archive<false> data_ar(data_span);
            if (!::serialization::serialize_noeof(data_ar, p))
            {
                MERROR("Failed to deserialize proposal from governance payload");
                return false;
            }

            // BEGIN_VNS_PROPOSAL_TRAILING_DATA
            const size_t consumed = data_ar.getpos();
            if (consumed <= gp.data.size())
                data_blob.assign(gp.data.begin() + consumed, gp.data.end());
            else
                data_blob.clear();
            // END_VNS_PROPOSAL_TRAILING_DATA

            return true;
        }
    }
    return false;
}

} // namespace cryptonote