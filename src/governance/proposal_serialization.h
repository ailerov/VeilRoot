// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef PROPOSAL_SERIALIZATION_H
#define PROPOSAL_SERIALIZATION_H

#include <cstdint>
#include <string>
#include <vector>
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"

namespace cryptonote {
namespace governance {

struct ProposalData {
    // Unique identifier for the proposal
    crypto::hash proposal_id;

    // Proposal title
    std::string title;

    // Proposal description
    std::string description;

    // Proposal type (e.g., governance, technical, marketing)
    std::string type;

    // Voting start time (Unix timestamp)
    uint64_t voting_start_time;

    // Voting end time (Unix timestamp)
    uint64_t voting_end_time;

    // Proposal author's public key
    crypto::public_key author_key;

    // Signature of the proposal data
    crypto::signature signature;

    // Constructor
    ProposalData() : voting_start_time(0), voting_end_time(0) {}
};

// Serialization functions
bool serialize_proposal_data(const ProposalData& proposal, std::string& buffer);
bool deserialize_proposal_data(const std::string& buffer, ProposalData& proposal);
bool serialize_proposal_data(const ProposalData& proposal, std::vector<uint8_t>& buffer);
bool deserialize_proposal_data(const std::vector<uint8_t>& buffer, ProposalData& proposal);

// Helper functions for signing and verification
bool sign_proposal(ProposalData& proposal, const crypto::secret_key& private_key);
bool verify_proposal_signature(const ProposalData& proposal);

} // namespace governance
} // namespace cryptonote

#endif // PROPOSAL_SERIALIZATION_H