// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This file is part of the VeilRoot project.

#include "dao_validation.h"
#include <algorithm>
#include <set>
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "common/error.h"
#include "blockchain.h"
#include "cryptonote_config.h"

namespace cryptonote
{
  // BEGIN_VNS_GRANT_VALIDATION
  grant_validation_result validate_grant_payouts(
      const transaction& miner_tx,
      const std::vector<grant_payout_info>& expected_payouts,
      uint64_t base_reward)
  {
    grant_validation_result result = {true, 0, ""};

    // Parse tx_extra and find tx_extra_grant_payouts
    std::vector<tx_extra_field> tx_extra_fields;
    if (!parse_tx_extra(miner_tx.extra, tx_extra_fields))
    {
      result.success = false;
      result.message = "Failed to parse miner tx extra";
      return result;
    }

    const tx_extra_grant_payouts* extra_payouts = nullptr;
    for (const auto& f : tx_extra_fields)
    {
      if (f.type() == typeid(tx_extra_grant_payouts))
      {
        if (extra_payouts)
        {
          result.success = false;
          result.message = "Duplicate tx_extra_grant_payouts field";
          return result;
        }
        extra_payouts = &boost::get<tx_extra_grant_payouts>(f);
      }
    }

    // Reject missing extra when grants expected, or extra present when none expected
    if (expected_payouts.empty() && extra_payouts)
    {
      result.success = false;
      result.message = "tx_extra_grant_payouts present but no grants expected";
      return result;
    }
    if (!expected_payouts.empty() && !extra_payouts)
    {
      result.success = false;
      result.message = "Missing tx_extra_grant_payouts";
      return result;
    }

    if (extra_payouts)
    {
      const auto& payouts = extra_payouts->payouts;

      // Compare parsed objects
      if (payouts.size() != expected_payouts.size())
      {
        result.success = false;
        result.message = "tx_extra payout count mismatch";
        return result;
      }

      for (size_t i = 0; i < payouts.size(); ++i)
      {
        const auto& a = payouts[i];
        const auto& b = expected_payouts[i];
        if (a.proposal_id != b.proposal_id)
        {
          result.success = false;
          result.message = "proposal_id mismatch at index " + std::to_string(i);
          return result;
        }
        if (a.recipient.m_spend_public_key != b.recipient.m_spend_public_key ||
            a.recipient.m_view_public_key != b.recipient.m_view_public_key)
        {
          result.success = false;
          result.message = "recipient mismatch at index " + std::to_string(i);
          return result;
        }
        if (a.amount != b.amount)
        {
          result.success = false;
          result.message = "amount mismatch at index " + std::to_string(i);
          return result;
        }
        if (a.amount == 0)
        {
          result.success = false;
          result.message = "zero amount at index " + std::to_string(i);
          return result;
        }
      }

      // Duplicate proposal IDs
      std::set<crypto::hash> seen_ids;
      for (const auto& p : payouts)
      {
        if (!seen_ids.insert(p.proposal_id).second)
        {
          result.success = false;
          result.message = "duplicate proposal_id";
          return result;
        }
      }

      // Verify grant outputs in the coinbase
      size_t miner_outs = 0, treasury_outs = 0, other_outs = 0;
      for (const auto& o : miner_tx.vout)
      {
        if (o.target.type() == typeid(txout_treasury))
          ++treasury_outs;
        else if (o.amount == base_reward)
          ++miner_outs;
        else
          ++other_outs;
      }

      if (miner_outs != 1)
      {
        result.success = false;
        result.message = "Expected exactly 1 miner output";
        return result;
      }
      if (treasury_outs > 1)
      {
        result.success = false;
        result.message = "At most 1 treasury output expected";
        return result;
      }
      if (other_outs != expected_payouts.size())
      {
        result.success = false;
        result.message = "Grant output count mismatch";
        return result;
      }

      // Build amount vectors for comparison
      std::vector<uint64_t> actual_amounts;
      for (const auto& o : miner_tx.vout)
      {
        if (o.target.type() == typeid(txout_treasury))
          continue;
        if (o.amount == base_reward)
          continue;
        actual_amounts.push_back(o.amount);
      }

      std::vector<uint64_t> expected_amounts;
      for (const auto& p : expected_payouts)
        expected_amounts.push_back(p.amount);

      std::sort(expected_amounts.begin(), expected_amounts.end());
      std::sort(actual_amounts.begin(), actual_amounts.end());

      if (actual_amounts.size() != expected_amounts.size())
      {
        result.success = false;
        result.message = "Grant output count mismatch after sorting";
        return result;
      }
      for (size_t i = 0; i < actual_amounts.size(); ++i)
      {
        if (actual_amounts[i] != expected_amounts[i])
        {
          result.success = false;
          result.message = "Grant output amount mismatch";
          return result;
        }
      }

      // Explicit sum check
      uint64_t sum_actual = 0, sum_expected = 0;
      for (auto amt : actual_amounts) sum_actual += amt;
      for (auto amt : expected_amounts) sum_expected += amt;
      if (sum_actual != sum_expected)
      {
        result.success = false;
        result.message = "Sum of grant amounts mismatch";
        return result;
      }

      result.total_grants = sum_expected;
    }
    else
    {
      result.total_grants = 0;
    }

    return result;
  }
  // END_VNS_GRANT_VALIDATION

  // BEGIN_VNS_GRANT_PAYOUT_COMPUTATION
  std::vector<grant_payout_info> compute_pending_grant_payouts(
      const std::vector<proposal_record>& executable,
      cryptonote::network_type nettype)
  {
    std::vector<grant_payout_info> payouts;

    for (const auto& rec : executable)
    {
      if (rec.type != 0)  // GRANT
        continue;

      grant_payout_info info;
      info.proposal_id = rec.proposal_id;
      info.amount = rec.amount;

      cryptonote::address_parse_info addr_info;
      CHECK_AND_ASSERT_THROW_MES(
          cryptonote::get_account_address_from_str(addr_info, nettype, rec.recipient),
          "Invalid grant recipient address");
      info.recipient = addr_info.address;

      payouts.push_back(info);
    }

    // Sort deterministically by proposal_id (crypto::hash is comparable)
    std::sort(payouts.begin(), payouts.end(),
        [](const grant_payout_info& a, const grant_payout_info& b)
        {
          return a.proposal_id < b.proposal_id;
        });

    return payouts;
  }
  // END_VNS_GRANT_PAYOUT_COMPUTATION
}