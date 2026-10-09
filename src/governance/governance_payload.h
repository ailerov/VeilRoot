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
    dkg_key_activation = 5  // DAO V2 DKG public key record (consensus object)
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