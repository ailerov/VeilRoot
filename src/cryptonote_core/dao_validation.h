// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of the VeilRoot project.

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "cryptonote_basic/cryptonote_format_utils.h"

namespace cryptonote
{
  struct proposal_record;  // full definition in blockchain.h

  // BEGIN_VNS_GRANT_VALIDATION
  struct grant_validation_result
  {
    bool success;
    uint64_t total_grants;
    std::string message;
  };

  grant_validation_result validate_grant_payouts(
      const transaction& miner_tx,
      const std::vector<grant_payout_info>& expected_payouts,
      uint64_t base_reward);
  // END_VNS_GRANT_VALIDATION

  // BEGIN_VNS_GRANT_PAYOUT_COMPUTATION
  std::vector<grant_payout_info> compute_pending_grant_payouts(
      const std::vector<proposal_record>& executable,
      network_type nettype);
  // END_VNS_GRANT_PAYOUT_COMPUTATION
}