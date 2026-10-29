// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <vector>
#include "serialization/serialization.h"

namespace cryptonote {

enum class governance_object : uint8_t
{
    proposal = 0,
    vote = 1,        // frozen V1 / historical
    execution = 2,
    vote_v2 = 3,            // DAO V2 vote, carries vote_proof_v2 in data
    tally_result = 4,       // DAO V2 tally certificate (consensus object)
    dkg_key_activation = 5, // DAO V2 DKG public key record (consensus object)
    node_ready = 6          // DAO V2 node readiness announcement (B1)
};

struct node_ready_payload
{
    uint8_t              version = 1;
    std::vector<uint8_t> sender_pubkey;  // 32 bytes
    uint64_t             height = 0;
    std::vector<uint8_t> block_hash;     // 32 bytes
    std::vector<uint8_t> signature;      // 64 bytes

    BEGIN_SERIALIZE()
        FIELD(version)
        FIELD(sender_pubkey)
        VARINT_FIELD(height)
        FIELD(block_hash)
        FIELD(signature)
    END_SERIALIZE()
};

struct governance_payload
{
    governance_object type;
    std::vector<uint8_t> data;

    BEGIN_SERIALIZE()
        VARINT_FIELD(type)
        FIELD(data)
    END_SERIALIZE()
};

} // namespace cryptonote