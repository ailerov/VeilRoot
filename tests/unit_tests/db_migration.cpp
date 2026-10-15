// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// LMDB schema migration tests.
//
// The cumulative generated-supply field was widened to a 128-bit value
// in schema version 6. This test builds a database in the version-5
// on-disk layout by rewriting the block_info record with raw LMDB,
// reopens it with the current binary, and asserts that the migration
// preserves the low 64 bits of supply, zeroes the new high limb, and
// drops the transient alt_blocks table.

#include <boost/filesystem.hpp>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

#include <gtest/gtest.h>

#include <lmdb.h>

#include "blockchain_db/lmdb/db_lmdb.h"
#include "crypto/crypto.h"

using namespace cryptonote;

namespace {

int compare_uint64_lmdb(const MDB_val *a, const MDB_val *b)
{
  const uint64_t va = *reinterpret_cast<const uint64_t*>(a->mv_data);
  const uint64_t vb = *reinterpret_cast<const uint64_t*>(b->mv_data);
  return (va < vb) ? -1 : (va > vb) ? 1 : 0;
}

// On-disk layout produced by schema version 5.
struct block_info_v4
{
  uint64_t bi_height;
  uint64_t bi_timestamp;
  uint64_t bi_coins;
  uint64_t bi_weight;
  uint64_t bi_diff_lo;
  uint64_t bi_diff_hi;
  crypto::hash bi_hash;
  uint64_t bi_cum_rct;
  uint64_t bi_long_term_block_weight;
};

// On-disk layout produced by schema version 4 (pre-supply-limb).
struct block_info_v3
{
  uint64_t bi_height;
  uint64_t bi_timestamp;
  uint64_t bi_coins;
  uint64_t bi_weight;
  uint64_t bi_diff;
  crypto::hash bi_hash;
  uint64_t bi_cum_rct;
};

}  // namespace

TEST(DbMigration, V5ToV6PreservesSupplyAndDropsAltBlocks)
{
  namespace fs = boost::filesystem;

  const fs::path tempPath =
      fs::temp_directory_path() /
      fs::unique_path("vr_db_migration_%%%%-%%%%");
  const std::string dir = tempPath.string();
  fs::create_directories(tempPath);

  constexpr uint64_t legacy_coins = 123456789012345ULL;

  // ------------------------------------------------------------------
  // 1. Create a database with the current binary so every table
  //    exists, then close it.
  // ------------------------------------------------------------------
  {
    BlockchainLMDB db;
    db.open(dir);
    ASSERT_TRUE(db.is_open());
    db.close();
  }

  // ------------------------------------------------------------------
  // 2. Rewrite the database into the version-5 layout: replace the
  //    block_info record with the v4 shape, insert a transient
  //    alt_blocks entry, and set properties.version = 5.
  // ------------------------------------------------------------------
  {
    MDB_env *env = nullptr;
    ASSERT_EQ(0, mdb_env_create(&env));
    ASSERT_EQ(0, mdb_env_set_maxdbs(env, 128));
    ASSERT_EQ(0, mdb_env_open(env, dir.c_str(), 0, 0644));

    MDB_txn *txn = nullptr;
    ASSERT_EQ(0, mdb_txn_begin(env, nullptr, 0, &txn));

    // block_info: drop whatever the current binary wrote, and write a
    // single v4-format record.
    {
      MDB_dbi dbi = 0;
      ASSERT_EQ(0, mdb_dbi_open(txn, "block_info",
          MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED, &dbi));
      mdb_set_dupsort(txn, dbi, compare_uint64_lmdb);

      // Clear existing entries.
      MDB_cursor *cur = nullptr;
      ASSERT_EQ(0, mdb_cursor_open(txn, dbi, &cur));
      MDB_val k, v;
      int rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST);
      while (rc == 0) {
        ASSERT_EQ(0, mdb_cursor_del(cur, 0));
        rc = mdb_cursor_get(cur, &k, &v, MDB_FIRST);
      }
      mdb_cursor_close(cur);

      block_info_v4 rec{};
      rec.bi_height = 0;
      rec.bi_timestamp = 100;
      rec.bi_coins = legacy_coins;
      rec.bi_weight = 128;
      rec.bi_diff_lo = 10;
      rec.bi_diff_hi = 0;
      std::memset(rec.bi_hash.data, 0, sizeof(rec.bi_hash.data));
      rec.bi_cum_rct = 0;
      rec.bi_long_term_block_weight = 128;

      const uint64_t zero = 0;
      MDB_val zkey{sizeof(zero), const_cast<uint64_t*>(&zero)};
      MDB_val rval{sizeof(rec), &rec};
      ASSERT_EQ(0, mdb_put(txn, dbi, &zkey, &rval, 0));
    }

    // alt_blocks: one transient entry.
    {
      MDB_dbi dbi = 0;
      ASSERT_EQ(0, mdb_dbi_open(txn, "alt_blocks", 0, &dbi));

      struct alt_blob {
        uint64_t height;
        uint64_t cumulative_weight;
        uint64_t cumulative_difficulty_low;
        uint64_t cumulative_difficulty_high;
        uint64_t already_generated_coins;
        uint64_t already_generated_coins_hi;
      } blob{};

      crypto::hash fake{};
      std::memset(fake.data, 0xAB, sizeof(fake.data));
      MDB_val akey{sizeof(fake), &fake};
      MDB_val aval{sizeof(blob), &blob};
      ASSERT_EQ(0, mdb_put(txn, dbi, &akey, &aval, 0));
    }

    // properties: version = 5.
    {
      MDB_dbi dbi = 0;
      ASSERT_EQ(0, mdb_dbi_open(txn, "properties", 0, &dbi));

      const uint32_t v5 = 5;
      // MDB_val_str in db_lmdb.cpp uses strlen + 1, i.e. the key
      // includes the terminating NUL.
      const char version_key[] = "version";
      MDB_val vkey{sizeof(version_key), const_cast<char*>(version_key)};
      MDB_val vval{sizeof(v5), const_cast<uint32_t*>(&v5)};
      ASSERT_EQ(0, mdb_put(txn, dbi, &vkey, &vval, 0));
    }

    ASSERT_EQ(0, mdb_txn_commit(txn));
    mdb_env_close(env);
  }

  // ------------------------------------------------------------------
  // 3. Reopen with the current binary. migrate_5_6() runs on open.
  // ------------------------------------------------------------------
  {
    BlockchainLMDB db;
    db.open(dir);
    ASSERT_TRUE(db.is_open());

    // The migrated record preserves the low 64 bits of supply; the
    // high limb is zero because every v5 record was produced by code
    // that accumulated supply in a uint64_t.
    const vns_supply_t got = db.get_block_already_generated_coins(0);
    EXPECT_EQ(got, static_cast<vns_supply_t>(legacy_coins));

    // alt_blocks was dropped rather than reinterpreted.
    EXPECT_EQ(0u, db.get_alt_block_count());

    db.close();
  }

  // ------------------------------------------------------------------
  // 4. Reopen again. Version is now 6; migration must not run again.
  // ------------------------------------------------------------------
  {
    BlockchainLMDB db;
    db.open(dir);
    ASSERT_TRUE(db.is_open());
    const vns_supply_t got = db.get_block_already_generated_coins(0);
    EXPECT_EQ(got, static_cast<vns_supply_t>(legacy_coins));
    db.close();
  }



  fs::remove_all(tempPath);
}

TEST(DbMigration, ReadOnlyOpenRefusesPendingMigration)
{
  namespace fs = boost::filesystem;

  const fs::path tempPath =
      fs::temp_directory_path() /
      fs::unique_path("vr_db_migration_ro_%%%%-%%%%");
  const std::string dir = tempPath.string();
  fs::create_directories(tempPath);

  // Build a v6 DB with the current binary, then rewrite properties
  // so the on-disk version is 5.
  {
    BlockchainLMDB db;
    db.open(dir);
    ASSERT_TRUE(db.is_open());
    db.close();
  }
  {
    MDB_env *env = nullptr;
    ASSERT_EQ(0, mdb_env_create(&env));
    ASSERT_EQ(0, mdb_env_set_maxdbs(env, 128));
    ASSERT_EQ(0, mdb_env_open(env, dir.c_str(), 0, 0644));

    MDB_txn *txn = nullptr;
    ASSERT_EQ(0, mdb_txn_begin(env, nullptr, 0, &txn));

    MDB_dbi dbi = 0;
    ASSERT_EQ(0, mdb_dbi_open(txn, "properties", 0, &dbi));
    const uint32_t v5 = 5;
    const char version_key[] = "version";
    MDB_val vkey{sizeof(version_key), const_cast<char*>(version_key)};
    MDB_val vval{sizeof(v5), const_cast<uint32_t*>(&v5)};
    ASSERT_EQ(0, mdb_put(txn, dbi, &vkey, &vval, 0));

    ASSERT_EQ(0, mdb_txn_commit(txn));
    mdb_env_close(env);
  }

  // A read-only open must refuse to open a database that needs
  // conversion: it cannot migrate, and silently reading the old
  // layout would misinterpret records.
  {
    BlockchainLMDB db;
    db.open(dir, DBF_RDONLY);
    EXPECT_FALSE(db.is_open());
  }

  // The database is left untouched and still usable read-write.
  {
    BlockchainLMDB db;
    db.open(dir);
    ASSERT_TRUE(db.is_open());
    db.close();
  }

  fs::remove_all(tempPath);
}
