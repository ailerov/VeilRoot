// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "vote_serialization.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include <cstring>

namespace cryptonote {
namespace governance {

// Helper function to serialize a hash
void serialize_hash(const crypto::hash& hash, std::string& buffer) {
    buffer.append(reinterpret_cast<const char*>(hash.data), sizeof(hash.data));
}

// Helper function to deserialize a hash
bool deserialize_hash(const std::string& buffer, size_t& offset, crypto::hash& hash) {
    if (offset + sizeof(hash.data) > buffer.size()) {
        return false;
    }
    memcpy(hash.data, buffer.data() + offset, sizeof(hash.data));
    offset += sizeof(hash.data);
    return true;
}

// Serialize VoteData to string
bool serialize_vote_data(const VoteData& vote, std::string& buffer) {
    buffer.clear();

    // Serialize proposal_id (32 bytes)
    serialize_hash(vote.proposal_id, buffer);

    // Serialize choice (1 byte)
    buffer.append(1, static_cast<char>(vote.choice));

    // Serialize timestamp (8 bytes)
    buffer.append(reinterpret_cast<const char*>(&vote.timestamp), sizeof(vote.timestamp));

    // Serialize voter_key (32 bytes)
    buffer.append(reinterpret_cast<const char*>(vote.voter_key.data), sizeof(vote.voter_key.data));

    // Serialize weight (8 bytes)
    buffer.append(reinterpret_cast<const char*>(&vote.weight), sizeof(vote.weight));

    return true;
}

// Serialize VoteData to vector
bool serialize_vote_data(const VoteData& vote, std::vector<uint8_t>& buffer) {
    buffer.clear();

    // Reserve space for all data
    buffer.reserve(32 + 1 + 8 + 32 + 8); // proposal_id + choice + timestamp + voter_key + weight

    // Serialize proposal_id (32 bytes)
    buffer.insert(buffer.end(), vote.proposal_id.data, vote.proposal_id.data + 32);

    // Serialize choice (1 byte)
    buffer.push_back(static_cast<uint8_t>(vote.choice));

    // Serialize timestamp (8 bytes)
    uint64_t timestamp = vote.timestamp;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&timestamp),
                 reinterpret_cast<uint8_t*>(&timestamp) + 8);

    // Serialize voter_key (32 bytes)
    buffer.insert(buffer.end(), vote.voter_key.data, vote.voter_key.data + 32);

    // Serialize weight (8 bytes)
    uint64_t weight = vote.weight;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&weight),
                 reinterpret_cast<uint8_t*>(&weight) + 8);

    return true;
}

// Deserialize VoteData from string
bool deserialize_vote_data(const std::string& buffer, VoteData& vote) {
    size_t offset = 0;

    // Deserialize proposal_id (32 bytes)
    if (!deserialize_hash(buffer, offset, vote.proposal_id)) {
        return false;
    }

    // Deserialize choice (1 byte)
    if (offset + 1 > buffer.size()) {
        return false;
    }
    vote.choice = static_cast<VoteChoice>(static_cast<uint8_t>(buffer[offset]));
    offset += 1;

    // Deserialize timestamp (8 bytes)
    if (offset + 8 > buffer.size()) {
        return false;
    }
    memcpy(&vote.timestamp, buffer.data() + offset, sizeof(vote.timestamp));
    offset += 8;

    // Deserialize voter_key (32 bytes)
    if (offset + 32 > buffer.size()) {
        return false;
    }
    memcpy(vote.voter_key.data, buffer.data() + offset, sizeof(vote.voter_key.data));
    offset += 32;

    // Deserialize weight (8 bytes)
    if (offset + 8 > buffer.size()) {
        return false;
    }
    memcpy(&vote.weight, buffer.data() + offset, sizeof(vote.weight));

    return true;
}

// Deserialize VoteData from vector
bool deserialize_vote_data(const std::vector<uint8_t>& buffer, VoteData& vote) {
    size_t offset = 0;

    // Deserialize proposal_id (32 bytes)
    if (offset + 32 > buffer.size()) {
        return false;
    }
    memcpy(vote.proposal_id.data, buffer.data() + offset, sizeof(vote.proposal_id.data));
    offset += 32;

    // Deserialize choice (1 byte)
    if (offset + 1 > buffer.size()) {
        return false;
    }
    vote.choice = static_cast<VoteChoice>(buffer[offset]);
    offset += 1;

    // Deserialize timestamp (8 bytes)
    if (offset + 8 > buffer.size()) {
        return false;
    }
    memcpy(&vote.timestamp, buffer.data() + offset, sizeof(vote.timestamp));
    offset += 8;

    // Deserialize voter_key (32 bytes)
    if (offset + 32 > buffer.size()) {
        return false;
    }
    memcpy(vote.voter_key.data, buffer.data() + offset, sizeof(vote.voter_key.data));
    offset += 32;

    // Deserialize weight (8 bytes)
    if (offset + 8 > buffer.size()) {
        return false;
    }
    memcpy(&vote.weight, buffer.data() + offset, sizeof(vote.weight));

    return true;
}

// Sign a vote
bool sign_vote(VoteData& vote, const crypto::secret_key& private_key) {
    std::string data_to_sign;
    if (!serialize_vote_data(vote, data_to_sign)) {
        return false;
    }

    // Create hash of the serialized data
    crypto::hash hash;
    crypto::cn_fast_hash(data_to_sign.data(), data_to_sign.size(), hash);

    // Sign the hash
    crypto::generate_signature(hash, vote.voter_key, private_key, vote.signature);
    return true;
}

// Verify vote signature
bool verify_vote_signature(const VoteData& vote) {
    std::string data_to_verify;
    if (!serialize_vote_data(vote, data_to_verify)) {
        return false;
    }

    // Create hash of the serialized data
    crypto::hash hash;
    crypto::cn_fast_hash(data_to_verify.data(), data_to_verify.size(), hash);

    // Verify the signature
    return crypto::check_signature(hash, vote.voter_key, vote.signature);
}

} // namespace governance
} // namespace cryptonote