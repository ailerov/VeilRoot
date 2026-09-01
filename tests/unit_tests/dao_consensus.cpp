// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"
#include "cryptonote_core/dao_validation.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"
#include "crypto/crypto.h"

using namespace cryptonote;

namespace
{
  // Helper: build a minimal valid miner transaction with grants
  transaction make_miner_tx_with_grants(
      const std::vector<grant_payout_info>& payouts,
      uint64_t base_reward)
  {
    transaction tx;
    tx.version = 2;
    tx.vin.push_back(txin_gen{});
    // miner output
    {
      tx_out out;
      out.amount = base_reward;
      out.target = txout_to_key{};
      tx.vout.push_back(out);
    }
    // treasury output (optional)
    {
      tx_out out;
      out.amount = 0;
      out.target = txout_treasury{};
      tx.vout.push_back(out);
    }
    // grant outputs
    for (const auto& p : payouts)
    {
      tx_out out;
      out.amount = p.amount;
      out.target = txout_to_key{};
      tx.vout.push_back(out);
    }
    // embed tx_extra_grant_payouts
    if (!payouts.empty())
    {
      add_grant_payouts_to_extra(tx.extra, payouts);
    }
    return tx;
  }

  // Helper: create a grant_payout_info with a given id and amount
  grant_payout_info make_payout(crypto::hash proposal_id, uint64_t amount)
  {
    grant_payout_info g;
    g.proposal_id = proposal_id;
    g.recipient = account_public_address{};  // zero-initialised keys
    g.amount = amount;
    return g;
  }

  // Some fixed proposal IDs
  const crypto::hash ID1 = crypto::hash{1};
  const crypto::hash ID2 = crypto::hash{2};
  const crypto::hash ID3 = crypto::hash{3};
}

// ---------- Valid cases ----------
TEST(dao_grant_validation, no_grants_pass)
{
  transaction tx = make_miner_tx_with_grants({}, 1000);
  grant_validation_result r = validate_grant_payouts(tx, {}, 1000);
  ASSERT_TRUE(r.success) << r.message;
  ASSERT_EQ(r.total_grants, 0);
}

TEST(dao_grant_validation, single_grant_pass)
{
  auto payouts = std::vector{grant_payout_info{ID1, account_public_address{}, 500}};
  transaction tx = make_miner_tx_with_grants(payouts, 1000);
  grant_validation_result r = validate_grant_payouts(tx, payouts, 1000);
  ASSERT_TRUE(r.success) << r.message;
  ASSERT_EQ(r.total_grants, 500);
}

TEST(dao_grant_validation, multiple_grants_pass)
{
  std::vector<grant_payout_info> payouts = {
      grant_payout_info{ID1, account_public_address{}, 100},
      grant_payout_info{ID2, account_public_address{}, 200}
  };
  transaction tx = make_miner_tx_with_grants(payouts, 1000);
  grant_validation_result r = validate_grant_payouts(tx, payouts, 1000);
  ASSERT_TRUE(r.success) << r.message;
  ASSERT_EQ(r.total_grants, 300);
}

// ---------- Missing/extra tx_extra ----------
TEST(dao_grant_validation, missing_extra_reject)
{
  auto payouts = std::vector{grant_payout_info{ID1, account_public_address{}, 500}};
  transaction tx = make_miner_tx_with_grants(payouts, 1000);
  tx.extra.clear(); // remove extra
  grant_validation_result r = validate_grant_payouts(tx, payouts, 1000);
  ASSERT_FALSE(r.success);
}

TEST(dao_grant_validation, extra_without_grants_reject)
{
  transaction tx;
  tx.version = 2;
  tx.vin.push_back(txin_gen{});
  tx_out out;
  out.amount = 1000;
  out.target = txout_to_key{};
  tx.vout.push_back(out);
  // embed extra even though expected empty
  add_grant_payouts_to_extra(tx.extra, {});
  grant_validation_result r = validate_grant_payouts(tx, {}, 1000);
  ASSERT_FALSE(r.success);
}

// ---------- Mismatched entries ----------
TEST(dao_grant_validation, extra_entry_missing_reject)
{
  auto payouts = std::vector{grant_payout_info{ID1, account_public_address{}, 500}};
  transaction tx = make_miner_tx_with_grants(payouts, 1000);
  std::vector<grant_payout_info> expected = {
      grant_payout_info{ID1, account_public_address{}, 500},
      grant_payout_info{ID2, account_public_address{}, 100}
  };
  grant_validation_result r = validate_grant_payouts(tx, expected, 1000);
  ASSERT_FALSE(r.success);
}

TEST(dao_grant_validation, extra_entry_extra_reject)
{
  std::vector<grant_payout_info> payouts = {
      grant_payout_info{ID1, account_public_address{}, 500},
      grant_payout_info{ID2, account_public_address{}, 100}
  };
  transaction tx = make_miner_tx_with_grants(payouts, 1000);
  std::vector<grant_payout_info> expected = {
      grant_payout_info{ID1, account_public_address{}, 500}
  };
  grant_validation_result r = validate_grant_payouts(tx, expected, 1000);
  ASSERT_FALSE(r.success);
}

// ---------- Amount mismatch ----------
TEST(dao_grant_validation, wrong_amount_reject)
{
  auto payouts = std::vector{grant_payout_info{ID1, account_public_address{}, 500}};
  transaction tx = make_miner_tx_with_grants(payouts, 1000);
  std::vector<grant_payout_info> bad = {
      grant_payout_info{ID1, account_public_address{}, 501}
  };
  grant_validation_result r = validate_grant_payouts(tx, bad, 1000);
  ASSERT_FALSE(r.success);
}

// ---------- Duplicate proposal ID ----------
TEST(dao_grant_validation, duplicate_proposal_id_reject)
{
  std::vector<grant_payout_info> payouts = {
      grant_payout_info{ID1, account_public_address{}, 100},
      grant_payout_info{ID1, account_public_address{}, 200}
  };
  transaction tx = make_miner_tx_with_grants(payouts, 1000);
  grant_validation_result r = validate_grant_payouts(tx, payouts, 1000);
  ASSERT_FALSE(r.success);
}

// ---------- Zero amount ----------
TEST(dao_grant_validation, zero_amount_reject)
{
  auto payouts = std::vector{grant_payout_info{ID1, account_public_address{}, 0}};
  transaction tx = make_miner_tx_with_grants(payouts, 1000);
  grant_validation_result r = validate_grant_payouts(tx, payouts, 1000);
  ASSERT_FALSE(r.success);
}

// ---------- Output count mismatch ----------
TEST(dao_grant_validation, missing_output_reject)
{
  auto payouts = std::vector{grant_payout_info{ID1, account_public_address{}, 500}};
  transaction tx = make_miner_tx_with_grants(payouts, 1000);
  tx.vout.pop_back(); // remove the grant output
  grant_validation_result r = validate_grant_payouts(tx, payouts, 1000);
  ASSERT_FALSE(r.success);
}

TEST(dao_grant_validation, extra_output_reject)
{
  auto payouts = std::vector{grant_payout_info{ID1, account_public_address{}, 500}};
  transaction tx = make_miner_tx_with_grants(payouts, 1000);
  // add an extra output
  tx_out extra;
  extra.amount = 50;
  extra.target = txout_to_key{};
  tx.vout.push_back(extra);
  grant_validation_result r = validate_grant_payouts(tx, payouts, 1000);
  ASSERT_FALSE(r.success);
}