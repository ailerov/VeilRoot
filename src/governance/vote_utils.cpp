// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "vote_utils.h"
#include <cstring>
#include "cryptonote_basic/cryptonote_format_utils.h"

namespace cryptonote {

bool is_vote_tx(const transaction& tx) {
    return !tx.vin.empty() && tx.vin[0].type() == typeid(txin_vns_vote);
}

bool is_eligible_tx(const transaction& tx) {
    return !tx.vin.empty() && tx.vin[0].type() == typeid(txin_vns_eligible);
}

bool is_non_consuming_tx(const transaction& tx) {
    return is_vote_tx(tx) || is_eligible_tx(tx);
}

bool parse_vote_extra(const std::vector<uint8_t>& extra,
                      crypto::hash& proposal_id,
                      uint8_t& direction,
                      uint64_t& weight,
                      uint64_t& amount)
{
    static const char VOTE_MAGIC[] = "DAO_VOTE";
    proposal_id = crypto::null_hash;
    direction = 0;
    weight = 0;
    amount = 0;

    for (size_t i = 0; i < extra.size(); ) {
        uint8_t tag = extra[i];
        if (tag == 0x01) { i += 1 + 32; continue; }
        if (tag == 0x02) {
            size_t len = 0;
            size_t varint_bytes = 0;
            for (size_t vi = i + 1; vi < i + 10 && vi < extra.size(); ++vi) {
                len |= ((size_t)(extra[vi] & 0x7F)) << (7 * varint_bytes);
                ++varint_bytes;
                if (!(extra[vi] & 0x80)) break;
            }
            if (varint_bytes == 0 || varint_bytes > 9) { i += 2; continue; }
            size_t len_header_size = varint_bytes;
            size_t magic_size = sizeof(VOTE_MAGIC) - 1;
            if (len < magic_size || i + 1 + len_header_size + len > extra.size()) {
                i += 1 + len_header_size + len;
                continue;
            }
            if (memcmp(&extra[i + 1 + len_header_size], VOTE_MAGIC, magic_size) == 0) {
                size_t pos = i + 1 + len_header_size + magic_size;
                size_t payload_end = i + 1 + len_header_size + len;
                while (pos < payload_end) {
                    if (pos >= extra.size()) return false;
                    uint8_t type = extra[pos++];
                    if (type == 0x00) return true; // terminator, success
                    if (pos >= extra.size()) return false;
                    uint8_t length = extra[pos++];
                    if (pos + length > extra.size() || pos + length > payload_end)
                        return false;
                    switch (type) {
                        case 0x10: // proposal_id
                            if (length != 32) return false;
                            memcpy(proposal_id.data, &extra[pos], 32);
                            break;
                        case 0x11: // direction
                            if (length != 1) return false;
                            direction = extra[pos];
                            break;
                        case 0x12: // weight (uint64 LE)
                            if (length > 8) return false;
                            weight = 0;
                            for (uint8_t j = 0; j < length; ++j)
                                weight |= ((uint64_t)extra[pos + j]) << (j * 8);
                            break;
                        case 0x13: // raw amount (uint64 LE)
                            if (length > 8) return false;
                            amount = 0;
                            for (uint8_t j = 0; j < length; ++j)
                                amount |= ((uint64_t)extra[pos + j]) << (j * 8);
                            break;
                        default: break;
                    }
                    pos += length;
                }
                return true;
            }
            i += 1 + len_header_size + len;
            continue;
        }
        else i++;
    }
    return false;
}

} // namespace cryptonote