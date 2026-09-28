// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"
#include "serialization/serialization.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"

namespace cryptonote {

// V2 DAO vote wire format. Outer structure frozen by spec §11 and §28.
// Cryptographic sub-objects are introduced by their dedicated commits;
// their slots here are length-prefixed opaque payloads during scaffolding.
// No V1 field survives: no direction_yes, no participation_balance,
// no voting_weight, no voting_nullifiers.

struct dao_clsag {
    std::vector<uint8_t> payload;
    BEGIN_SERIALIZE_OBJECT()
        FIELD(payload)
    END_SERIALIZE()
};

struct threshold_ciphertext {
    std::vector<uint8_t> payload;
    BEGIN_SERIALIZE_OBJECT()
        FIELD(payload)
    END_SERIALIZE()
};

struct dao_vote_or_proof {
    std::vector<uint8_t> payload;
    BEGIN_SERIALIZE_OBJECT()
        FIELD(payload)
    END_SERIALIZE()
};

struct dao_vote_consistency_proof {
    std::vector<uint8_t> payload;
    BEGIN_SERIALIZE_OBJECT()
        FIELD(payload)
    END_SERIALIZE()
};

struct vote_input_v2
{
    std::vector<uint64_t> key_offsets;
    crypto::key_image      dao_nullifier;
    rct::key               weight_commitment;
    dao_clsag              signature;

    BEGIN_SERIALIZE_OBJECT()
        FIELD(key_offsets)
        FIELD(dao_nullifier)
        FIELD(weight_commitment)
        FIELD(signature)
    END_SERIALIZE()
};

struct vote_proof_v2
{
    enum : uint8_t { VERSION = 2 };

    uint8_t      version     = VERSION;
    crypto::hash proposal_id;
    uint64_t     vote_height = 0;

    rct::key total_weight_commitment;
    rct::key signed_weight_commitment;

    threshold_ciphertext encrypted_weight;
    threshold_ciphertext encrypted_signed_weight;
    threshold_ciphertext encrypted_weight_blinding;
    threshold_ciphertext encrypted_signed_blinding;

    rct::BulletproofPlus       weight_range_proof;
    dao_vote_or_proof          direction_proof;
    dao_vote_consistency_proof consistency_proof;

    std::vector<vote_input_v2> inputs;

    BEGIN_SERIALIZE_OBJECT()
        FIELD(version)
        FIELD(proposal_id)
        VARINT_FIELD(vote_height)
        FIELD(total_weight_commitment)
        FIELD(signed_weight_commitment)
        FIELD(encrypted_weight)
        FIELD(encrypted_signed_weight)
        FIELD(encrypted_weight_blinding)
        FIELD(encrypted_signed_blinding)
        FIELD(weight_range_proof)
        FIELD(direction_proof)
        FIELD(consistency_proof)
        FIELD(inputs)
    END_SERIALIZE()
};

} // namespace cryptonote