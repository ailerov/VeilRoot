// Copyright (c) 2017 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bech32 and Bech32m encoding/decoding (BIP-173 and BIP-350)
// Modified for VeilRoot Name System (VNS)

#include "bech32.h"
#include <stdexcept>
#include <algorithm>
#include <array>
#include <tuple>   // ADD THIS

namespace
{
    /** The Bech32 character set for encoding. */
    const std::string CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    /** The Bech32 character set for decoding. */
    const int8_t CHARSET_REV[128] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
    };

    /** Concatenate two vectors. */
    std::vector<uint8_t> Cat(const std::vector<uint8_t>& x, const std::vector<uint8_t>& y)
    {
        std::vector<uint8_t> ret = x;
        ret.insert(ret.end(), y.begin(), y.end());
        return ret;
    }

    /** Expand the HRP into a vector for checksum computation. */
    std::vector<uint8_t> ExpandHrp(const std::string& hrp)
    {
        std::vector<uint8_t> ret;
        ret.reserve(hrp.size() * 2 + 1);
        for (char c : hrp) {
            ret.push_back(static_cast<uint8_t>(c) >> 5);
        }
        ret.push_back(0);
        for (char c : hrp) {
            ret.push_back(static_cast<uint8_t>(c) & 31);
        }
        return ret;
    }

    /** Polymod function for checksum verification. */
    uint32_t Polymod(const std::vector<uint8_t>& values)
    {
        uint32_t chk = 1;
        for (uint8_t v : values) {
            uint32_t top = chk >> 25;
            chk = (chk & 0x1ffffff) << 5 ^ v;
            if (top & 1)  chk ^= 0x3b6a57b2;
            if (top & 2)  chk ^= 0x26508e6d;
            if (top & 4)  chk ^= 0x1ea119fa;
            if (top & 8)  chk ^= 0x3d4233dd;
            if (top & 16) chk ^= 0x2a1462b3;
        }
        return chk;
    }

    /** Verify a checksum given HRP and data (including checksum). Returns true if valid. */
    bool VerifyChecksum(bech32::Encoding enc, const std::string& hrp, const std::vector<uint8_t>& data)
    {
        std::vector<uint8_t> expanded = ExpandHrp(hrp);
        std::vector<uint8_t> values = Cat(expanded, data);
        uint32_t checksum = Polymod(values);
        if (enc == bech32::Encoding::BECH32) return checksum == 1;
        if (enc == bech32::Encoding::BECH32M) return checksum == 0x2bc830a3;
        return false;
    }

    /** Create a checksum for a given HRP and data (without checksum). */
    std::vector<uint8_t> CreateChecksum(bech32::Encoding enc, const std::string& hrp, const std::vector<uint8_t>& data)
    {
        std::vector<uint8_t> expanded = ExpandHrp(hrp);
        std::vector<uint8_t> values = Cat(expanded, data);
        // Pad with 6 zeros
        values.resize(values.size() + 6, 0);
        uint32_t mod = Polymod(values);
        uint32_t target;
        if (enc == bech32::Encoding::BECH32) target = 1;
        else target = 0x2bc830a3;
        uint32_t chk = mod ^ target;
        std::vector<uint8_t> ret(6);
        for (int i = 0; i < 6; ++i) {
            ret[i] = (chk >> (5 * (5 - i))) & 31;
        }
        return ret;
    }
} // namespace

namespace bech32
{
    std::tuple<Encoding, std::string, std::vector<uint8_t>> Decode(const std::string& str)
    {
        // Check for mixed case
        bool lower = false, upper = false;
        for (char c : str) {
            if (c >= 'a' && c <= 'z') lower = true;
            else if (c >= 'A' && c <= 'Z') upper = true;
            if (lower && upper) return {Encoding::INVALID, "", {}};
        }
        // Find the last '1' separator
        size_t pos = str.rfind('1');
        if (pos == std::string::npos || pos == 0 || pos + 7 > str.size()) return {Encoding::INVALID, "", {}};
        std::string hrp = str.substr(0, pos);
        std::string data_str = str.substr(pos + 1);
        // Convert characters to 5-bit values
        std::vector<uint8_t> data;
        data.reserve(data_str.size());
        for (char c : data_str) {
            // Cast to unsigned char to avoid signed comparison warnings
            unsigned char uc = static_cast<unsigned char>(c);
            if (uc >= 128) return {Encoding::INVALID, "", {}};
            int8_t v = CHARSET_REV[uc];
            if (v == -1) return {Encoding::INVALID, "", {}};
            data.push_back(static_cast<uint8_t>(v));
        }
        // Try Bech32
        if (VerifyChecksum(Encoding::BECH32, hrp, data)) {
            // Remove checksum
            data.resize(data.size() - 6);
            return {Encoding::BECH32, hrp, data};
        }
        // Try Bech32m
        if (VerifyChecksum(Encoding::BECH32M, hrp, data)) {
            data.resize(data.size() - 6);
            return {Encoding::BECH32M, hrp, data};
        }
        return {Encoding::INVALID, "", {}};
    }

    std::string Encode(Encoding enc, const std::string& hrp, const std::vector<uint8_t>& data)
    {
        if (enc != Encoding::BECH32 && enc != Encoding::BECH32M) return "";
        if (hrp.empty() || hrp.size() > 83) return "";
        // Lowercase HRP
        std::string hrp_lower = hrp;
        std::transform(hrp_lower.begin(), hrp_lower.end(), hrp_lower.begin(), ::tolower);
        std::vector<uint8_t> checksum = CreateChecksum(enc, hrp_lower, data);
        std::vector<uint8_t> combined = Cat(data, checksum);
        std::string ret = hrp_lower + '1';
        for (uint8_t v : combined) {
            if (v >= CHARSET.size()) return "";
            ret += CHARSET[v];
        }
        return ret;
    }
}