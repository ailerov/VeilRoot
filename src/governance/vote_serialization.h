// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef VOTE_SERIALIZATION_H
#define VOTE_SERIALIZATION_H

#include <cstdint>
#include <string>
#include <vector>
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"

namespace cryptonote {
namespace governance {

enum class VoteChoice : uint8_t {
    YES = 0,
    NO = 1,
    ABSTAIN = 2
};

struct VoteData {
    // Unique identifier for the proposal being voted on
    crypto::hash proposal_id;

    // The vote choice
    VoteChoice choice;

    // Timestamp of when vote was cast
    uint64_t timestamp;

    // Voter's public key
    crypto::public_key voter_key;

    // Weight of the vote (calculated from voting weight function)
    uint64_t weight;

    // Signature of the vote data
    crypto::signature signature;

    // Constructor
    VoteData() : choice(VoteChoice::ABSTAIN), timestamp(0), weight(0) {}

    // Constructor with parameters
    VoteData(const crypto::hash& proposal_id_, VoteChoice choice_, uint64_t timestamp_,
             const crypto::public_key& voter_key_, uint64_t weight_)
        : proposal_id(proposal_id_), choice(choice_), timestamp(timestamp_),
          voter_key(voter_key_), weight(weight_) {}
};

// Serialization functions
bool serialize_vote_data(const VoteData& vote, std::string& buffer);
bool deserialize_vote_data(const std::string& buffer, VoteData& vote);
bool serialize_vote_data(const VoteData& vote, std::vector<uint8_t>& buffer);
bool deserialize_vote_data(const std::vector<uint8_t>& buffer, VoteData& vote);

// Helper functions for signing and verification
bool sign_vote(VoteData& vote, const crypto::secret_key& private_key);
bool verify_vote_signature(const VoteData& vote);

} // namespace governance
} // namespace cryptonote

#endif // VOTE_SERIALIZATION_H