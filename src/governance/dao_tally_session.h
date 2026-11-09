// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Dynamic tally committee record.
//
// A committee is selected deterministically at a proposal's voting end
// from the eligible-node state. Its secret shares are derived from the
// stable Paillier key (see dao_tally_key.h) by dynamic threshold
// resharing; the secret itself is never reconstructed. The committee
// disbands after tally.
//
// This record is public. It carries no private share material.

#pragma once

#include <cstdint>
#include <vector>

#include "crypto/hash.h"
#include "governance/dao_paillier.h"

namespace cryptonote {
namespace dao {
} // namespace dao
} // namespace cryptonote
