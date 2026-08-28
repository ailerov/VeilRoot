// Copyright (c) 2017 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bech32 and Bech32m encoding/decoding (BIP-173 and BIP-350)
// Modified for VeilRoot Name System (VNS) – removed Bitcoin-specific checks.

#ifndef VNS_BECH32_H
#define VNS_BECH32_H

#include <stdint.h>
#include <string>
#include <vector>
#include <tuple>   // ADD THIS

namespace bech32
{
    enum class Encoding {
        BECH32,     // Original Bech32 (used by Nostr npub/nsec)
        BECH32M,    // Bech32m (not needed for Nostr, but included for completeness)
        INVALID
    };

    /** Decode a Bech32 or Bech32m string. Returns (encoding, hrp, data).
     *  If decoding fails, encoding = INVALID.
     */
    std::tuple<Encoding, std::string, std::vector<uint8_t>> Decode(const std::string& str);

    /** Encode a Bech32 or Bech32m string. hrp must be lowercase.
     *  data must be a vector of 5-bit values (0-31). */
    std::string Encode(Encoding enc, const std::string& hrp, const std::vector<uint8_t>& data);
}

#endif // VNS_BECH32_H