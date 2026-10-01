// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Historical circulating-supply snapshot. Written once per canonical
// block height by the block-apply path. Quorum lookups read the
// snapshot at the proposal's voting-end height, not current DB state.

#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include <boost/multiprecision/cpp_int.hpp>

namespace cryptonote {
namespace dao {

using dao_u128 = boost::multiprecision::uint128_t;

struct dao_supply_snapshot
{
    uint64_t  height    = 0;
    dao_u128  minted    = 0;
    dao_u128  treasury  = 0;
    dao_u128  burned    = 0;
    dao_u128  circulating = 0;

    bool serialize(std::vector<uint8_t>& out) const
    {
        out.clear();
        for (int i = 0; i < 8; ++i)
            out.push_back(static_cast<uint8_t>((height >> (8 * i)) & 0xff));
        if (!put_u128(out, minted)) return false;
        if (!put_u128(out, treasury)) return false;
        if (!put_u128(out, burned)) return false;
        if (!put_u128(out, circulating)) return false;
        return true;
    }

    bool deserialize(const std::vector<uint8_t>& in)
    {
        const size_t want = 8 + 4 * 16;
        if (in.size() != want) return false;
        size_t off = 0;
        height = 0;
        for (int i = 0; i < 8; ++i)
            height |= static_cast<uint64_t>(in[off + i]) << (8 * i);
        off += 8;
        if (!take_u128(in, off, minted)) return false;
        if (!take_u128(in, off, treasury)) return false;
        if (!take_u128(in, off, burned)) return false;
        if (!take_u128(in, off, circulating)) return false;
        return true;
    }

    // Compute circulating from minted/treasury/burned. Returns false on
    // underflow; caller must reject rather than wrap.
    static bool compute_circulating(dao_u128 minted,
                                    dao_u128 treasury,
                                    dao_u128 burned,
                                    dao_u128& out)
    {
        if (treasury > minted) return false;
        dao_u128 m1 = minted - treasury;
        if (burned > m1) return false;
        out = m1 - burned;
        return true;
    }

private:
    static bool put_u128(std::vector<uint8_t>& out, const dao_u128& v)
    {
        for (int i = 15; i >= 0; --i)
            out.push_back(static_cast<uint8_t>(
                (v >> (8 * i)) & static_cast<unsigned>(0xff)));
        return true;
    }

    static bool take_u128(const std::vector<uint8_t>& in,
                          size_t& off, dao_u128& out)
    {
        if (off + 16 > in.size()) return false;
        out = 0;
        for (int i = 0; i < 16; ++i)
            out = (out << 8) | static_cast<unsigned>(in[off + i]);
        off += 16;
        return true;
    }
};

} // namespace dao
} // namespace cryptonote
