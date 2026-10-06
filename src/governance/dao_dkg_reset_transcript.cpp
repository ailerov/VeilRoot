// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_dkg_reset_transcript.h"

#include <algorithm>
#include <cstring>

#include <openssl/sha.h>

namespace cryptonote {
namespace dao {

namespace {

void push_u32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xff);
}

void push_u64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back((x >> (8 * i)) & 0xff);
}

void push_blob(std::vector<uint8_t>& v, const std::vector<uint8_t>& b)
{
    push_u32(v, static_cast<uint32_t>(b.size()));
    v.insert(v.end(), b.begin(), b.end());
}

} // anonymous namespace

void dao_dkg_reset_transcript::append_public(const dkg_msg& msg)
{
    entry e;
    e.sender_id    = msg.hdr.sender_id;
    e.recipient_id = msg.hdr.recipient_id;
    e.type         = static_cast<uint8_t>(msg.hdr.type);
    e.sequence     = msg.hdr.sequence;
    e.private_leaf = false;
    msg.serialize(e.canonical);
    entries_.push_back(std::move(e));
}

void dao_dkg_reset_transcript::append_private(const dkg_msg& encrypted_msg)
{
    entry e;
    e.sender_id    = encrypted_msg.hdr.sender_id;
    e.recipient_id = encrypted_msg.hdr.recipient_id;
    e.type         = static_cast<uint8_t>(encrypted_msg.hdr.type);
    e.sequence     = encrypted_msg.hdr.sequence;
    e.private_leaf = true;

    std::vector<uint8_t> canonical;
    encrypted_msg.serialize(canonical);

    const char* dom = "VeilRoot-DAO-DKG-RESET-PRIVATE-LEAF-V1";
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), dom, dom + std::strlen(dom));
    buf.insert(buf.end(), canonical.begin(), canonical.end());

    e.canonical.assign(32, 0);
    SHA256(buf.data(), buf.size(), e.canonical.data());

    entries_.push_back(std::move(e));
}

void dao_dkg_reset_transcript::hash(
    const dao_dkg_reset_config& cfg,
    const crypto::hash& proposal_id,
    std::vector<uint8_t>& out) const
{
    std::vector<uint8_t> material;
    const char* dom = "VeilRoot-DAO-DKG-RESET-TRANSCRIPT-V1";
    material.insert(material.end(), dom, dom + std::strlen(dom));
    material.insert(material.end(), cfg.key_id.data, cfg.key_id.data + 32);
    material.insert(material.end(), proposal_id.data, proposal_id.data + 32);
    push_u32(material, cfg.old_epoch);
    push_u32(material, cfg.new_epoch);
    material.insert(material.end(), cfg.old_committee_id.data,
                    cfg.old_committee_id.data + 32);
    material.insert(material.end(), cfg.new_committee_id.data,
                    cfg.new_committee_id.data + 32);
    for (uint32_t id : cfg.reset_participant_ids) push_u32(material, id);

    std::vector<entry> sorted = entries_;
    std::sort(sorted.begin(), sorted.end(),
        [](const entry& a, const entry& b) {
            if (a.sender_id != b.sender_id) return a.sender_id < b.sender_id;
            if (a.recipient_id != b.recipient_id) return a.recipient_id < b.recipient_id;
            if (a.type != b.type) return a.type < b.type;
            if (a.sequence != b.sequence) return a.sequence < b.sequence;
            if (a.private_leaf != b.private_leaf) return a.private_leaf < b.private_leaf;
            return a.canonical < b.canonical;
        });

    for (const auto& e : sorted) {
        push_u32(material, e.sender_id);
        push_u32(material, e.recipient_id);
        material.push_back(e.type);
        push_u64(material, e.sequence);
        material.push_back(e.private_leaf ? 1 : 0);
        push_blob(material, e.canonical);
    }

    out.assign(32, 0);
    SHA256(material.data(), material.size(), out.data());
}

} // namespace dao
} // namespace cryptonote
