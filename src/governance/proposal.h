// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include "crypto/hash.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/blockchain.h"   // for proposal_record, proposal_status
#include "governance_db.h"                // for GovernanceDB
#include "governance_params.h"            // for governance_params
#include "serialization/serialization.h"
#include "parameter_update.h"

namespace cryptonote {

// Canonical proposal action types
enum class proposal_action : uint8_t {
    treasury_payment = 0,
    parameter_change = 1,
    text = 2,
    protocol_upgrade = 3
};

// Canonical proposal structure – consensus-critical
struct proposal {
    uint8_t version = 1;
    crypto::hash metadata_hash;
    proposal_action action;
    uint64_t amount;
    account_public_address destination;
    uint64_t voting_start_height;
    crypto::public_key recipient_view_public_key;   // main account view public key for ECDH
    bool is_subaddress = false;   // whether destination was provided as a subaddress
    uint64_t voting_end_height;
    uint8_t voting_period_days;
    // BEGIN_VNS_PROPOSAL_METADATA_ONCHAIN
    std::vector<uint8_t> title;
    std::vector<uint8_t> description;
    // END_VNS_PROPOSAL_METADATA_ONCHAIN

    BEGIN_SERIALIZE()
        FIELD(version)
        FIELD(metadata_hash)
        VARINT_FIELD(action)
        VARINT_FIELD(amount)
        FIELD(destination)
        FIELD(recipient_view_public_key)
        FIELD(is_subaddress)
        VARINT_FIELD(voting_start_height)
        VARINT_FIELD(voting_end_height)
        VARINT_FIELD(voting_period_days)
        // BEGIN_VNS_PROPOSAL_METADATA_ONCHAIN
        FIELD(title)
        FIELD(description)
        // END_VNS_PROPOSAL_METADATA_ONCHAIN
    END_SERIALIZE()
};

// Manager class
class ProposalManager {
public:
    ProposalManager(GovernanceDB& db, const governance_params& params);

    bool process_block(const block& blk, uint64_t height);
    bool rollback_block(const block& blk, const std::vector<transaction>& txs, uint64_t height);
    bool index_proposal(const transaction& tx, const crypto::hash& tx_hash, uint64_t height);
    void reindex_governance(uint64_t start_height, uint64_t end_height);
    bool proposal_exists(const crypto::hash& proposal_id) const;
    bool get_proposal_record(const crypto::hash& proposal_id, proposal_record& rec) const;

private:
    bool validate_proposal(const proposal& p, uint64_t height, const std::vector<uint8_t>& data_blob = {}) const;
    bool is_proposal_tx(const transaction& tx) const;
    bool extract_proposal(const transaction& tx, proposal& p, std::vector<uint8_t>& data_blob) const;

    GovernanceDB& m_db;
    const governance_params& m_params;
};

} // namespace cryptonote