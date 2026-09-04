// Copyright (c) 2026, The VeilRoot Project
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <array>
#include <string>
#include <vector>
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"

namespace cryptonote {

class nostr_client
 {
public:
    struct heartbeat_event
    {
        std::string domain;
        crypto::hash proof;
        crypto::hash fingerprint;
        crypto::hash block_hash;
        uint64_t leaf_index = 0;
        std::vector<crypto::hash> sibling_hashes;
        uint64_t created_at;   // Unix timestamp
        uint64_t heartbeat_height = 0;
        uint64_t heartbeat_count = 0;
        crypto::hash event_id;
    };

    // Fetches the most recent kind:30001 event for a domain from a relay.
    // Returns true and fills out_event on success.
    bool fetch_heartbeat(const std::string& relay_url,
                         const std::string& domain_name,
                         const std::array<unsigned char, 33>& registrant_pubkey,
                         heartbeat_event& out_event,
                         int timeout_seconds = 10);

    // --- New for kind 30003 (service descriptor) ---
    struct service_descriptor_event
    {
        std::string content;
        std::string fingerprint_hex;          // hex string from tag
        crypto::hash block_hash;
        uint64_t leaf_index;
        std::vector<crypto::hash> sibling_hashes;
        uint64_t created_at;
        uint64_t version = 0;                 // monotonic descriptor version
        crypto::hash event_id = crypto::null_hash;
        std::string pubkey_hex;
    };

    // Fetches the most recent kind:30003 event for a domain.
    bool fetch_service_descriptor(const std::string& relay_url,
                                  const std::string& domain_name,
                                  const std::array<unsigned char, 33>& registrant_pubkey,
                                  service_descriptor_event& out_event,
                                  int timeout_seconds = 10);

    // Publishes a signed event (any kind) to a relay.
    // event_json must be a complete Nostr event JSON (with id, pubkey, sig, etc.).
    // Returns true if the relay acknowledged with an "OK" message and success.
    bool publish_event(const std::string& relay_url,
                       const std::string& event_json,
                       int timeout_seconds = 10);

    // Verify a raw Nostr event object using the domain's legacy 33-byte registrant key.
    static bool verify_nostr_event_signature(
        const std::string& event_json,
        const std::array<unsigned char, 33>& registrant_pubkey);

    // Test-only wrappers around internal Nostr validation/parsing helpers.
    static bool verify_nostr_signature_for_test(
        const std::string& full_message_json,
        const std::array<unsigned char, 33>& registrant_pubkey);

    static bool parse_service_descriptor_event_for_test(
        const std::string& json_line,
        const std::string& expected_domain,
        service_descriptor_event& out_event);

    static bool parse_heartbeat_event_for_test(
        const std::string& json_line,
        const std::string& expected_domain,
        heartbeat_event& out_event);
 };

 } // namespace cryptonote