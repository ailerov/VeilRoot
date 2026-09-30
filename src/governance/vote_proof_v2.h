// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"
#include "serialization/serialization.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"

#include "governance/dao_consistency.h"
#include "governance/dao_vote_or_proof.h"

namespace cryptonote {

// Fixed 512-byte Paillier ciphertext. Serialized raw (no length prefix).
struct fixed_512_byte
{
    std::array<uint8_t, 512> data{{}};
};

} // namespace cryptonote

BLOB_SERIALIZER(cryptonote::fixed_512_byte);

namespace cryptonote {

// One ring input of a DAO V2 vote. The typed weighted CLSAG lives
// inside the input. weight_commitment is V_i = Q_i + rho_i*G.
struct vote_input_v2
{
    std::vector<uint64_t> key_offsets;
    rct::key              weight_commitment;
    rct::clsag            signature;

    BEGIN_SERIALIZE_OBJECT()
        FIELD(key_offsets)
        FIELD(weight_commitment)
        FIELD(signature)
    END_SERIALIZE()
};

// V2 DAO vote wire format. Frozen by spec section 18.
struct vote_proof_v2
{
    enum : uint8_t { VERSION = 2 };

    uint8_t      version         = VERSION;
    crypto::hash proposal_id;
    uint64_t     vote_height     = 0;
    uint64_t     tally_key_epoch = 0;

    std::vector<vote_input_v2>  inputs;
    std::vector<crypto::hash>   nullifiers;

    rct::key C_W;
    rct::key C_S;

    fixed_512_byte E_W;
    fixed_512_byte E_S;

    dao::dao_consistency_proof proof_W;
    dao::dao_consistency_proof proof_S;

    dao_vote_or_proof direction_proof;

    crypto::hash transcript_hash;

    BEGIN_SERIALIZE_OBJECT()
        FIELD(version)
        FIELD(proposal_id)
        VARINT_FIELD(vote_height)
        VARINT_FIELD(tally_key_epoch)
        FIELD(inputs)
        FIELD(nullifiers)
        FIELD(C_W)
        FIELD(C_S)
        FIELD(E_W)
        FIELD(E_S)
        FIELD(proof_W)
        FIELD(proof_S)
        FIELD(direction_proof)
        FIELD(transcript_hash)
    END_SERIALIZE()
};

} // namespace cryptonote
