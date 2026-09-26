// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "proposal_serialization.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include <cstring>

namespace cryptonote {
namespace governance {

// Serialize ProposalData to string
bool serialize_proposal_data(const ProposalData& proposal, std::string& buffer) {
    buffer.clear();

    // Serialize proposal_id (32 bytes)
    buffer.append(reinterpret_cast<const char*>(proposal.proposal_id.data), sizeof(proposal.proposal_id.data));

    // Serialize title length and data
    uint32_t title_length = static_cast<uint32_t>(proposal.title.size());
    buffer.append(reinterpret_cast<const char*>(&title_length), sizeof(title_length));
    buffer.append(proposal.title);

    // Serialize description length and data
    uint32_t description_length = static_cast<uint32_t>(proposal.description.size());
    buffer.append(reinterpret_cast<const char*>(&description_length), sizeof(description_length));
    buffer.append(proposal.description);

    // Serialize type length and data
    uint32_t type_length = static_cast<uint32_t>(proposal.type.size());
    buffer.append(reinterpret_cast<const char*>(&type_length), sizeof(type_length));
    buffer.append(proposal.type);

    // Serialize voting_start_time (8 bytes)
    buffer.append(reinterpret_cast<const char*>(&proposal.voting_start_time), sizeof(proposal.voting_start_time));

    // Serialize voting_end_time (8 bytes)
    buffer.append(reinterpret_cast<const char*>(&proposal.voting_end_time), sizeof(proposal.voting_end_time));

    // Serialize author_key (32 bytes)
    buffer.append(reinterpret_cast<const char*>(proposal.author_key.data), sizeof(proposal.author_key.data));

    return true;
}

// Serialize ProposalData to vector
bool serialize_proposal_data(const ProposalData& proposal, std::vector<uint8_t>& buffer) {
    buffer.clear();

    // Reserve space for all data
    size_t estimated_size = 32 + 4 + proposal.title.size() + 4 + proposal.description.size() + 4 +
                           proposal.type.size() + 8 + 8 + 32;
    buffer.reserve(estimated_size);

    // Serialize proposal_id (32 bytes)
    buffer.insert(buffer.end(), proposal.proposal_id.data, proposal.proposal_id.data + 32);

    // Serialize title length and data
    uint32_t title_length = static_cast<uint32_t>(proposal.title.size());
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&title_length),
                 reinterpret_cast<const uint8_t*>(&title_length) + sizeof(title_length));
    buffer.insert(buffer.end(), proposal.title.begin(), proposal.title.end());

    // Serialize description length and data
    uint32_t description_length = static_cast<uint32_t>(proposal.description.size());
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&description_length),
                 reinterpret_cast<const uint8_t*>(&description_length) + sizeof(description_length));
    buffer.insert(buffer.end(), proposal.description.begin(), proposal.description.end());

    // Serialize type length and data
    uint32_t type_length = static_cast<uint32_t>(proposal.type.size());
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&type_length),
                 reinterpret_cast<const uint8_t*>(&type_length) + sizeof(type_length));
    buffer.insert(buffer.end(), proposal.type.begin(), proposal.type.end());

    // Serialize voting_start_time (8 bytes)
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&proposal.voting_start_time),
                 reinterpret_cast<const uint8_t*>(&proposal.voting_start_time) + sizeof(proposal.voting_start_time));

    // Serialize voting_end_time (8 bytes)
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&proposal.voting_end_time),
                 reinterpret_cast<const uint8_t*>(&proposal.voting_end_time) + sizeof(proposal.voting_end_time));

    // Serialize author_key (32 bytes)
    buffer.insert(buffer.end(), proposal.author_key.data, proposal.author_key.data + 32);

    return true;
}

// Deserialize ProposalData from string
bool deserialize_proposal_data(const std::string& buffer, ProposalData& proposal) {
    size_t offset = 0;

    // Deserialize proposal_id (32 bytes)
    if (offset + 32 > buffer.size()) {
        return false;
    }
    memcpy(proposal.proposal_id.data, buffer.data() + offset, sizeof(proposal.proposal_id.data));
    offset += 32;

    // Deserialize title
    if (offset + sizeof(uint32_t) > buffer.size()) {
        return false;
    }
    uint32_t title_length;
    memcpy(&title_length, buffer.data() + offset, sizeof(title_length));
    offset += sizeof(title_length);

    if (offset + title_length > buffer.size()) {
        return false;
    }
    proposal.title.assign(buffer.data() + offset, title_length);
    offset += title_length;

    // Deserialize description
    if (offset + sizeof(uint32_t) > buffer.size()) {
        return false;
    }
    uint32_t description_length;
    memcpy(&description_length, buffer.data() + offset, sizeof(description_length));
    offset += sizeof(description_length);

    if (offset + description_length > buffer.size()) {
        return false;
    }
    proposal.description.assign(buffer.data() + offset, description_length);
    offset += description_length;

    // Deserialize type
    if (offset + sizeof(uint32_t) > buffer.size()) {
        return false;
    }
    uint32_t type_length;
    memcpy(&type_length, buffer.data() + offset, sizeof(type_length));
    offset += sizeof(type_length);

    if (offset + type_length > buffer.size()) {
        return false;
    }
    proposal.type.assign(buffer.data() + offset, type_length);
    offset += type_length;

    // Deserialize voting_start_time (8 bytes)
    if (offset + 8 > buffer.size()) {
        return false;
    }
    memcpy(&proposal.voting_start_time, buffer.data() + offset, sizeof(proposal.voting_start_time));
    offset += 8;

    // Deserialize voting_end_time (8 bytes)
    if (offset + 8 > buffer.size()) {
        return false;
    }
    memcpy(&proposal.voting_end_time, buffer.data() + offset, sizeof(proposal.voting_end_time));
    offset += 8;

    // Deserialize author_key (32 bytes)
    if (offset + 32 > buffer.size()) {
        return false;
    }
    memcpy(proposal.author_key.data, buffer.data() + offset, sizeof(proposal.author_key.data));
    offset += 32;

    return true;
}

// Deserialize ProposalData from vector
bool deserialize_proposal_data(const std::vector<uint8_t>& buffer, ProposalData& proposal) {
    size_t offset = 0;

    // Deserialize proposal_id (32 bytes)
    if (offset + 32 > buffer.size()) {
        return false;
    }
    memcpy(proposal.proposal_id.data, buffer.data() + offset, sizeof(proposal.proposal_id.data));
    offset += 32;

    // Deserialize title
    if (offset + sizeof(uint32_t) > buffer.size()) {
        return false;
    }
    uint32_t title_length;
    memcpy(&title_length, buffer.data() + offset, sizeof(title_length));
    offset += sizeof(title_length);

    if (offset + title_length > buffer.size()) {
        return false;
    }
    proposal.title.assign(reinterpret_cast<const char*>(buffer.data() + offset), title_length);
    offset += title_length;

    // Deserialize description
    if (offset + sizeof(uint32_t) > buffer.size()) {
        return false;
    }
    uint32_t description_length;
    memcpy(&description_length, buffer.data() + offset, sizeof(description_length));
    offset += sizeof(description_length);

    if (offset + description_length > buffer.size()) {
        return false;
    }
    proposal.description.assign(reinterpret_cast<const char*>(buffer.data() + offset), description_length);
    offset += description_length;

    // Deserialize type
    if (offset + sizeof(uint32_t) > buffer.size()) {
        return false;
    }
    uint32_t type_length;
    memcpy(&type_length, buffer.data() + offset, sizeof(type_length));
    offset += sizeof(type_length);

    if (offset + type_length > buffer.size()) {
        return false;
    }
    proposal.type.assign(reinterpret_cast<const char*>(buffer.data() + offset), type_length);
    offset += type_length;

    // Deserialize voting_start_time (8 bytes)
    if (offset + 8 > buffer.size()) {
        return false;
    }
    memcpy(&proposal.voting_start_time, buffer.data() + offset, sizeof(proposal.voting_start_time));
    offset += 8;

    // Deserialize voting_end_time (8 bytes)
    if (offset + 8 > buffer.size()) {
        return false;
    }
    memcpy(&proposal.voting_end_time, buffer.data() + offset, sizeof(proposal.voting_end_time));
    offset += 8;

    // Deserialize author_key (32 bytes)
    if (offset + 32 > buffer.size()) {
        return false;
    }
    memcpy(proposal.author_key.data, buffer.data() + offset, sizeof(proposal.author_key.data));
    offset += 32;

    return true;
}

// Sign a proposal
bool sign_proposal(ProposalData& proposal, const crypto::secret_key& private_key) {
    std::string data_to_sign;
    if (!serialize_proposal_data(proposal, data_to_sign)) {
        return false;
    }

    // Create hash of the serialized data
    crypto::hash hash;
    crypto::cn_fast_hash(data_to_sign.data(), data_to_sign.size(), hash);

    // Sign the hash
    crypto::generate_signature(hash, proposal.author_key, private_key, proposal.signature);
    return true;
}

// Verify proposal signature
bool verify_proposal_signature(const ProposalData& proposal) {
    std::string data_to_verify;
    if (!serialize_proposal_data(proposal, data_to_verify)) {
        return false;
    }

    // Create hash of the serialized data
    crypto::hash hash;
    crypto::cn_fast_hash(data_to_verify.data(), data_to_verify.size(), hash);

    // Verify the signature
    return crypto::check_signature(hash, proposal.author_key, proposal.signature);
}

} // namespace governance
} // namespace cryptonote