// Copyright (c) 2026, The VeilRoot Project
// SPDX-License-Identifier: BSD-3-Clause

#include "gtest/gtest.h"

#include "cryptonote_core/nostr_client.h"
#include "common/bip340.h"
#include "crypto/crypto.h"
#include "string_tools.h"
#include "misc_language.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <openssl/evp.h>
#include <secp256k1.h>
#include <sstream>
#include <string>
#include <vector>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

namespace
{
    std::string to_hex(const unsigned char* data, size_t len)
    {
        return epee::string_tools::buff_to_hex_nodelimer(
            std::string(reinterpret_cast<const char*>(data), len));
    }

    std::string hash_to_hex(const crypto::hash& h)
    {
        return epee::string_tools::pod_to_hex(h);
    }

    std::string canonical_event_id_hex(
        const std::string& pubkey_hex,
        uint64_t created_at,
        int kind,
        const std::string& content,
        const std::vector<std::pair<std::string, std::string>>& tags)
    {
        using namespace rapidjson;

        Document canon;
        canon.SetArray();
        Document::AllocatorType& alloc = canon.GetAllocator();

        canon.PushBack(0, alloc);
        canon.PushBack(Value(pubkey_hex.c_str(), alloc).Move(), alloc);
        canon.PushBack(created_at, alloc);
        canon.PushBack(kind, alloc);

        Value tags_arr(kArrayType);
        for (const auto& tag : tags)
        {
            Value tag_arr(kArrayType);
            tag_arr.PushBack(Value(tag.first.c_str(), alloc).Move(), alloc);
            tag_arr.PushBack(Value(tag.second.c_str(), alloc).Move(), alloc);
            tags_arr.PushBack(tag_arr, alloc);
        }
        canon.PushBack(tags_arr, alloc);

        canon.PushBack(Value(content.c_str(), alloc).Move(), alloc);

        StringBuffer buffer;
        Writer<StringBuffer> writer(buffer);
        canon.Accept(writer);

        crypto::hash id;
        crypto::cn_fast_hash(buffer.GetString(), buffer.GetSize(), id);
        return hash_to_hex(id);
    }

    struct secp_keypair
    {
        crypto::secret_key secret;
        std::string pubkey_hex;                       // x-only hex, 64 chars
        std::array<unsigned char, 33> compressed_key; // compressed secp256k1 pubkey
    };

    secp_keypair make_secp_keypair(uint8_t seed_byte = 0)
    {
        secp_keypair out;

        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        EXPECT_NE(ctx, nullptr);

        unsigned char seed[32];
        for (size_t i = 0; i < sizeof(seed); ++i)
            seed[i] = static_cast<unsigned char>(i * 7 + 13 + seed_byte);

        secp256k1_pubkey pub;
        int ret = secp256k1_ec_pubkey_create(ctx, &pub, seed);
        EXPECT_EQ(ret, 1);

        unsigned char compressed[33];
        size_t compressed_len = sizeof(compressed);
        ret = secp256k1_ec_pubkey_serialize(ctx, compressed, &compressed_len, &pub, SECP256K1_EC_COMPRESSED);
        EXPECT_EQ(ret, 1);

        memcpy(out.secret.data, seed, 32);
        out.pubkey_hex = to_hex(compressed + 1, 32);
        std::copy(compressed, compressed + sizeof(compressed), out.compressed_key.begin());

        secp256k1_context_destroy(ctx);
        return out;
    }

    std::string sign_event_id_hex(
        const crypto::secret_key& secret,
        const std::string& event_id_hex)
    {
        crypto::hash id;
        EXPECT_TRUE(epee::string_tools::hex_to_pod(event_id_hex, id));

        unsigned char sig[64];
        bool ok = bip340::sign(
            reinterpret_cast<const unsigned char*>(&secret),
            reinterpret_cast<const unsigned char*>(&id),
            sig);
        EXPECT_TRUE(ok);

        return to_hex(sig, sizeof(sig));
    }

    std::string make_event_json(
        const std::string& id_hex,
        const std::string& pubkey_hex,
        uint64_t created_at,
        int kind,
        const std::vector<std::pair<std::string, std::string>>& tags,
        const std::string& content,
        const std::string& sig_hex)
    {
        std::ostringstream oss;
        oss << "[\"EVENT\",\"sub\",{"
            << "\"id\":\"" << id_hex << "\","
            << "\"pubkey\":\"" << pubkey_hex << "\","
            << "\"created_at\":" << created_at << ","
            << "\"kind\":" << kind << ","
            << "\"tags\":[";

        for (size_t i = 0; i < tags.size(); ++i)
        {
            if (i) oss << ",";
            oss << "[\"" << tags[i].first << "\",\"" << tags[i].second << "\"]";
        }

        oss << "],"
            << "\"content\":\"" << content << "\","
            << "\"sig\":\"" << sig_hex << "\""
            << "}]";

        return oss.str();
    }

    const uint64_t NOW = 1700000000;
    const std::string DOMAIN = "final..net";
    const std::string CONTENT = "https://example.com";
}

TEST(VnsNostr, ValidServiceDescriptorAccepted)
{
    const auto kp = make_secp_keypair();

    std::vector<std::pair<std::string, std::string>> tags = {
        {"d", DOMAIN},
        {"fingerprint", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        {"block_hash", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        {"leaf_index", "1"},
        {"sibling_path", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
        {"version", "5"}
    };

    const std::string id_hex = canonical_event_id_hex(kp.pubkey_hex, NOW, 30003, CONTENT, tags);
    const std::string sig_hex = sign_event_id_hex(kp.secret, id_hex);
    const std::string json = make_event_json(id_hex, kp.pubkey_hex, NOW, 30003, tags, CONTENT, sig_hex);

    cryptonote::nostr_client::service_descriptor_event ev;
    EXPECT_TRUE(cryptonote::nostr_client::parse_service_descriptor_event_for_test(json, DOMAIN, ev));
    EXPECT_EQ(ev.version, 5u);
    EXPECT_EQ(ev.content, CONTENT);

    std::array<unsigned char, 33> registrant_key = kp.compressed_key;

    EXPECT_TRUE(cryptonote::nostr_client::verify_nostr_signature_for_test(json, registrant_key));
}

TEST(VnsNostr, WrongRegistrantKeyRejected)
{
    const auto kp = make_secp_keypair(1);
    const auto attacker = make_secp_keypair(2);

    std::vector<std::pair<std::string, std::string>> tags = {
        {"d", DOMAIN},
        {"fingerprint", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        {"block_hash", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        {"leaf_index", "1"},
        {"sibling_path", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
        {"version", "5"}
    };

    const std::string id_hex = canonical_event_id_hex(attacker.pubkey_hex, NOW, 30003, CONTENT, tags);
    const std::string sig_hex = sign_event_id_hex(attacker.secret, id_hex);
    const std::string json = make_event_json(id_hex, attacker.pubkey_hex, NOW, 30003, tags, CONTENT, sig_hex);

    // Validate against the legitimate registrant key, not attacker key.
    std::array<unsigned char, 33> legit_key = kp.compressed_key;

    EXPECT_FALSE(cryptonote::nostr_client::verify_nostr_signature_for_test(json, legit_key));
}

TEST(VnsNostr, FakeIdRejected)
{
    const auto kp = make_secp_keypair();

    std::vector<std::pair<std::string, std::string>> tags = {
        {"d", DOMAIN},
        {"fingerprint", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        {"block_hash", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        {"leaf_index", "1"},
        {"sibling_path", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
        {"version", "5"}
    };

    const std::string real_id = canonical_event_id_hex(kp.pubkey_hex, NOW, 30003, CONTENT, tags);
    const std::string fake_id = std::string(64, 'f');
    const std::string sig_hex = sign_event_id_hex(kp.secret, fake_id);
    const std::string json = make_event_json(fake_id, kp.pubkey_hex, NOW, 30003, tags, CONTENT, sig_hex);

    std::array<unsigned char, 33> registrant_key = kp.compressed_key;

    EXPECT_FALSE(cryptonote::nostr_client::verify_nostr_signature_for_test(json, registrant_key));
}

TEST(VnsNostr, MissingVersionRejected)
{
    const auto kp = make_secp_keypair();

    std::vector<std::pair<std::string, std::string>> tags = {
        {"d", DOMAIN},
        {"fingerprint", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        {"block_hash", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        {"leaf_index", "1"},
        {"sibling_path", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
    };

    const std::string id_hex = canonical_event_id_hex(kp.pubkey_hex, NOW, 30003, CONTENT, tags);
    const std::string sig_hex = sign_event_id_hex(kp.secret, id_hex);
    const std::string json = make_event_json(id_hex, kp.pubkey_hex, NOW, 30003, tags, CONTENT, sig_hex);

    cryptonote::nostr_client::service_descriptor_event ev;
    EXPECT_FALSE(cryptonote::nostr_client::parse_service_descriptor_event_for_test(json, DOMAIN, ev));
}

TEST(VnsNostr, WrongKindRejected)
{
    const auto kp = make_secp_keypair();

    std::vector<std::pair<std::string, std::string>> tags = {
        {"d", DOMAIN}
    };

    const std::string id_hex = canonical_event_id_hex(kp.pubkey_hex, NOW, 30001, CONTENT, tags);
    const std::string sig_hex = sign_event_id_hex(kp.secret, id_hex);
    const std::string json = make_event_json(id_hex, kp.pubkey_hex, NOW, 30001, tags, CONTENT, sig_hex);

    cryptonote::nostr_client::service_descriptor_event ev;
    EXPECT_FALSE(cryptonote::nostr_client::parse_service_descriptor_event_for_test(json, DOMAIN, ev));
}

TEST(VnsNostr, WrongDomainRejected)
{
    const auto kp = make_secp_keypair();

    std::vector<std::pair<std::string, std::string>> tags = {
        {"d", "other..net"},
        {"version", "5"}
    };

    const std::string id_hex = canonical_event_id_hex(kp.pubkey_hex, NOW, 30003, CONTENT, tags);
    const std::string sig_hex = sign_event_id_hex(kp.secret, id_hex);
    const std::string json = make_event_json(id_hex, kp.pubkey_hex, NOW, 30003, tags, CONTENT, sig_hex);

    cryptonote::nostr_client::service_descriptor_event ev;
    EXPECT_FALSE(cryptonote::nostr_client::parse_service_descriptor_event_for_test(json, DOMAIN, ev));
}