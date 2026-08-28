// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <vector>
#include <string>
#include "crypto/hash.h"
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "serialization/serialization.h"

namespace cryptonote {

// Proposal-scoped voting nullifier (alias for hash)
struct voting_nullifier
{
    crypto::hash nullifier;

    BEGIN_SERIALIZE()
        FIELD(nullifier)
    END_SERIALIZE()
};

// Canonical VoteProof per spec
struct vote_proof
{
    uint8_t version;                         // must be 1 for this spec
    crypto::hash proposal_id;
    bool direction_yes;                      // true = YES, false = NO
    uint64_t snapshot_height;
    uint64_t participation_balance;          // X (atomic units)
    uint64_t voting_weight;                  // Y (weighted units, fixed point)
    std::vector<crypto::hash> voting_nullifiers; // one per eligible output

    // Pedersen commitments
    rct::key balance_commitment;
    rct::key weight_commitment;

    // Aggregate proof blob (CLSAGs + Bulletproofs + binding signature)
    std::string aggregate_proof;             // blobdata

    BEGIN_SERIALIZE()
        FIELD(version)
        FIELD(proposal_id)
        FIELD(direction_yes)
        VARINT_FIELD(snapshot_height)
        VARINT_FIELD(participation_balance)
        VARINT_FIELD(voting_weight)
        FIELD(voting_nullifiers)
        FIELD(balance_commitment)
        FIELD(weight_commitment)
        FIELD(aggregate_proof)
    END_SERIALIZE()
};

// BEGIN_VNS_AGGREGATE_PROOF
struct vote_input
{
    uint64_t amount;
    uint64_t weight;
    std::vector<uint64_t> key_offsets;
    rct::clsag signature;
    crypto::key_image key_image;

    BEGIN_SERIALIZE()
        VARINT_FIELD(amount)
        VARINT_FIELD(weight)
        FIELD(key_offsets)
        FIELD(signature)
        FIELD(key_image)
    END_SERIALIZE()
};

struct aggregate_vote_proof
{
    std::vector<vote_input> inputs;
    rct::BulletproofPlus balance_proof;
    rct::BulletproofPlus weight_proof;
    crypto::public_key binding_public_key;
    crypto::signature binding_signature;

    BEGIN_SERIALIZE()
        FIELD(inputs)
        FIELD(balance_proof)
        FIELD(weight_proof)
        FIELD(binding_public_key)
        FIELD(binding_signature)
    END_SERIALIZE()
};
// END_VNS_AGGREGATE_PROOF

} // namespace cryptonote