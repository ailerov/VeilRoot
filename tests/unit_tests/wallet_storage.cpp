// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Wallet file storage tests.
//
// Every source wallet is generated in-test from a fixed seed and stored
// with a known password, so these tests depend only on VeilRoot's own
// genesis and serialization. No wallet fixture built on another chain
// is loaded, and the genesis guard in wallet2::load is exercised rather
// than bypassed.

#include "unit_tests_utils.h"
#include "gtest/gtest.h"

#include <boost/filesystem.hpp>

#include "file_io_utils.h"
#include "wallet/wallet2.h"
#include "common/util.h"

using namespace boost::filesystem;
using namespace epee::file_io_utils;

namespace {

// Fixed seed so a stored wallet's address is reproducible across runs.
crypto::secret_key fixed_seed()
{
  crypto::secret_key k{};
  for (size_t i = 0; i < sizeof(k.data); ++i)
    k.data[i] = static_cast<uint8_t>(0x10 + i);
  return k;
}

// Remove a wallet file and its .keys companion.
void remove_wallet(const path& p)
{
  if (is_file_exist(p.string()))
    remove(p);
  if (is_file_exist(p.string() + ".keys"))
    remove(p.string() + ".keys");
}

}  // namespace

TEST(wallet_storage, store_to_file2file)
{
  const path source_wallet_file = unit_test::data_dir / "wallet_gen_file2file";
  const path interm_wallet_file = unit_test::data_dir / "wallet_gen_copy_file2file";
  const path target_wallet_file = unit_test::data_dir / "wallet_gen_new_file2file";

  remove_wallet(source_wallet_file);
  remove_wallet(interm_wallet_file);
  remove_wallet(target_wallet_file);

  epee::wipeable_string password("beepbeep");

  std::string source_address;
  {
    tools::wallet2 w(cryptonote::TESTNET);
    w.generate("", password, fixed_seed(), /*recover=*/true);
    source_address = w.get_address_as_str();
    w.store_to(source_wallet_file.string(), password);
  }

  ASSERT_TRUE(is_file_exist(source_wallet_file.string()));
  ASSERT_TRUE(is_file_exist(source_wallet_file.string() + ".keys"));

  tools::copy_file(source_wallet_file.string(), interm_wallet_file.string());
  tools::copy_file(source_wallet_file.string() + ".keys", interm_wallet_file.string() + ".keys");

  ASSERT_TRUE(is_file_exist(interm_wallet_file.string()));
  ASSERT_TRUE(is_file_exist(interm_wallet_file.string() + ".keys"));

  const auto files_are_expected = [&]()
  {
      EXPECT_FALSE(is_file_exist(interm_wallet_file.string()));
      EXPECT_FALSE(is_file_exist(interm_wallet_file.string() + ".keys"));
      EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
      EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));
  };

  {
      tools::wallet2 w(cryptonote::TESTNET);
      w.load(interm_wallet_file.string(), password);
      const std::string primary_address = w.get_address_as_str();
      EXPECT_EQ(source_address, primary_address);
      w.store_to(target_wallet_file.string(), password);
      files_are_expected();
  }

  files_are_expected();

  {
      tools::wallet2 w(cryptonote::TESTNET);
      w.load(target_wallet_file.string(), password);
      const std::string primary_address = w.get_address_as_str();
      EXPECT_EQ(source_address, primary_address);
      w.store_to("", "");
      files_are_expected();
  }

  files_are_expected();
}

TEST(wallet_storage, store_to_mem2file)
{
    const path target_wallet_file = unit_test::data_dir / "wallet_mem2file";

    remove_wallet(target_wallet_file);

    epee::wipeable_string password("beepbeep2");

    {
        tools::wallet2 w(cryptonote::TESTNET);
        w.generate("", password);
        w.store_to(target_wallet_file.string(), password);

        EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
        EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));
    }

    EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));

    {
        tools::wallet2 w(cryptonote::TESTNET);
        w.load(target_wallet_file.string(), password);

        EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
        EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));
    }

    EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));
}

TEST(wallet_storage, change_password_same_file)
{
    const path source_wallet_file = unit_test::data_dir / "wallet_gen_change_password_same";
    const path interm_wallet_file = unit_test::data_dir / "wallet_gen_copy_change_password_same";

    remove_wallet(source_wallet_file);
    remove_wallet(interm_wallet_file);

    epee::wipeable_string old_password("beepbeep");
    epee::wipeable_string new_password("meepmeep");

    std::string source_address;
    {
        tools::wallet2 w(cryptonote::TESTNET);
        w.generate("", old_password, fixed_seed(), /*recover=*/true);
        source_address = w.get_address_as_str();
        w.store_to(source_wallet_file.string(), old_password);
    }

    ASSERT_TRUE(is_file_exist(source_wallet_file.string()));
    ASSERT_TRUE(is_file_exist(source_wallet_file.string() + ".keys"));

    tools::copy_file(source_wallet_file.string(), interm_wallet_file.string());
    tools::copy_file(source_wallet_file.string() + ".keys", interm_wallet_file.string() + ".keys");

    ASSERT_TRUE(is_file_exist(interm_wallet_file.string()));
    ASSERT_TRUE(is_file_exist(interm_wallet_file.string() + ".keys"));

    {
        tools::wallet2 w(cryptonote::TESTNET);
        w.load(interm_wallet_file.string(), old_password);
        const std::string primary_address = w.get_address_as_str();
        EXPECT_EQ(source_address, primary_address);
        w.change_password(w.get_wallet_file(), old_password, new_password);
    }

    {
        tools::wallet2 w(cryptonote::TESTNET);
        w.load(interm_wallet_file.string(), new_password);
        const std::string primary_address = w.get_address_as_str();
        EXPECT_EQ(source_address, primary_address);
    }

    {
        tools::wallet2 w(cryptonote::TESTNET);
        EXPECT_THROW(w.load(interm_wallet_file.string(), old_password), tools::error::invalid_password);
    }
}

TEST(wallet_storage, change_password_different_file)
{
    const path source_wallet_file = unit_test::data_dir / "wallet_gen_change_password_diff";
    const path interm_wallet_file = unit_test::data_dir / "wallet_gen_copy_change_password_diff";
    const path target_wallet_file = unit_test::data_dir / "wallet_gen_new_change_password_diff";

    remove_wallet(source_wallet_file);
    remove_wallet(interm_wallet_file);
    remove_wallet(target_wallet_file);

    epee::wipeable_string old_password("beepbeep");
    epee::wipeable_string new_password("meepmeep");

    std::string source_address;
    {
        tools::wallet2 w(cryptonote::TESTNET);
        w.generate("", old_password, fixed_seed(), /*recover=*/true);
        source_address = w.get_address_as_str();
        w.store_to(source_wallet_file.string(), old_password);
    }

    ASSERT_TRUE(is_file_exist(source_wallet_file.string()));
    ASSERT_TRUE(is_file_exist(source_wallet_file.string() + ".keys"));

    tools::copy_file(source_wallet_file.string(), interm_wallet_file.string());
    tools::copy_file(source_wallet_file.string() + ".keys", interm_wallet_file.string() + ".keys");

    ASSERT_TRUE(is_file_exist(interm_wallet_file.string()));
    ASSERT_TRUE(is_file_exist(interm_wallet_file.string() + ".keys"));

    {
        tools::wallet2 w(cryptonote::TESTNET);
        w.load(interm_wallet_file.string(), old_password);
        const std::string primary_address = w.get_address_as_str();
        EXPECT_EQ(source_address, primary_address);
        w.change_password(target_wallet_file.string(), old_password, new_password);
    }

    EXPECT_FALSE(is_file_exist(interm_wallet_file.string()));
    EXPECT_FALSE(is_file_exist(interm_wallet_file.string() + ".keys"));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));

    {
        tools::wallet2 w(cryptonote::TESTNET);
        w.load(target_wallet_file.string(), new_password);
        const std::string primary_address = w.get_address_as_str();
        EXPECT_EQ(source_address, primary_address);
    }
}

TEST(wallet_storage, change_password_in_memory)
{
    const epee::wipeable_string password1("veilroot");
    const epee::wipeable_string password2("keeps keys private");
    const epee::wipeable_string password_wrong("wrong password");

    tools::wallet2 w(cryptonote::TESTNET);
    w.generate("", password1);
    const std::string primary_address_1 = w.get_address_as_str();
    w.change_password("", password1, password2);
    const std::string primary_address_2 = w.get_address_as_str();
    EXPECT_EQ(primary_address_1, primary_address_2);

    EXPECT_THROW(w.change_password("", password_wrong, password1), tools::error::invalid_password);
}

TEST(wallet_storage, change_password_mem2file)
{
    const path target_wallet_file = unit_test::data_dir / "wallet_change_password_mem2file";

    remove_wallet(target_wallet_file);

    const epee::wipeable_string password1("first password");
    const epee::wipeable_string password2("second password");

    std::string primary_address_1, primary_address_2;
    {
        tools::wallet2 w(cryptonote::TESTNET);
        w.generate("", password1);
        primary_address_1 = w.get_address_as_str();
        w.change_password(target_wallet_file.string(), password1, password2);
    }

    EXPECT_TRUE(is_file_exist(target_wallet_file.string()));
    EXPECT_TRUE(is_file_exist(target_wallet_file.string() + ".keys"));

    {
        tools::wallet2 w(cryptonote::TESTNET);
        w.load(target_wallet_file.string(), password2);
        primary_address_2 = w.get_address_as_str();
    }

    EXPECT_EQ(primary_address_1, primary_address_2);
}
