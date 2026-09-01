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
    vote = 1,
    execution = 2
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