// Copyright (c) 2014-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "serialization/difficulty_type.h"


namespace cryptonote
{
  namespace bootstrap
  {

    struct file_info
    {
      uint8_t  major_version;
      uint8_t  minor_version;
      uint32_t header_size;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(major_version);
        FIELD(minor_version);
        VARINT_FIELD(header_size);
      END_SERIALIZE()
    };

    struct blocks_info
    {
      // block heights of file's first and last blocks, zero-based indexes
      uint64_t block_first;
      uint64_t block_last;

      // file position, for directly reading last block
      uint64_t block_last_pos;

      BEGIN_SERIALIZE_OBJECT()
        VARINT_FIELD(block_first);
        VARINT_FIELD(block_last);
        VARINT_FIELD(block_last_pos);
      END_SERIALIZE()
    };

    struct block_package_1
    {
      cryptonote::block block;
      std::vector<transaction> txs;
      size_t block_weight;
      uint64_t cumulative_difficulty;
      uint64_t coins_generated;

      BEGIN_SERIALIZE()
        FIELD(block)
        FIELD(txs)
        VARINT_FIELD(block_weight)
        VARINT_FIELD(cumulative_difficulty)
        VARINT_FIELD(coins_generated)
      END_SERIALIZE()
    };

    // Version 1 bootstrap layout. Keep this byte-compatible with
    // bootstrap files whose file_info.major_version is 1.
    struct block_package_v1
    {
      cryptonote::block block;
      std::vector<transaction> txs;
      size_t block_weight;
      difficulty_type cumulative_difficulty;
      uint64_t coins_generated;

      BEGIN_SERIALIZE()
        FIELD(block)
        FIELD(txs)
        VARINT_FIELD(block_weight)
        FIELD(cumulative_difficulty)
        VARINT_FIELD(coins_generated)
      END_SERIALIZE()
    };

    // Version 2 stores cumulative generated supply using two uint64
    // varints: high limb first, then low limb. This preserves the full
    // vns_supply_t range on platforms without native __int128.
    struct block_package
    {
      cryptonote::block block;
      std::vector<transaction> txs;
      size_t block_weight;
      difficulty_type cumulative_difficulty;
      vns_supply_t coins_generated;

      BEGIN_SERIALIZE()
        FIELD(block)
        FIELD(txs)
        VARINT_FIELD(block_weight)
        FIELD(cumulative_difficulty)

        uint64_t generated_hi = 0;
        uint64_t generated_lo = 0;

        if (W)
        {
          generated_hi = static_cast<uint64_t>(coins_generated >> 64);
          generated_lo = static_cast<uint64_t>(coins_generated);
        }

        ar.serialize_varint(generated_hi);
        if (!ar.good()) return false;

        ar.serialize_varint(generated_lo);
        if (!ar.good()) return false;

        if (!W)
        {
          coins_generated = generated_hi;
          coins_generated <<= 64;
          coins_generated |= generated_lo;
        }
      END_SERIALIZE()
    };

  }

}
