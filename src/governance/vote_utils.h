// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <vector>
#include <crypto/hash.h>
#include <cryptonote_basic/cryptonote_basic.h>

namespace cryptonote {

// Check if a transaction is a DAO vote transaction
bool is_vote_tx(const transaction& tx);

// Check if a transaction is an eligibility transaction
bool is_eligible_tx(const transaction& tx);

// Check if a transaction is a non‑consuming governance transaction
bool is_non_consuming_tx(const transaction& tx);

// Parse the DAO vote metadata from tx_extra
bool parse_vote_extra(const std::vector<uint8_t>& extra,
                      crypto::hash& proposal_id,
                      uint8_t& direction,
                      uint64_t& weight,
                      uint64_t& amount);

} // namespace cryptonote