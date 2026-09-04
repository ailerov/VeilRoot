// Copyright (c) 2026, The VeilRoot Project
// SPDX-License-Identifier: BSD-3-Clause

#include "nostr_client.h"
#include "ixwebsocket/IXWebSocket.h"
#include "ixwebsocket/IXNetSystem.h"
#include <thread>
#include <chrono>
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "misc_log_ex.h"
#include "string_tools.h"
#include "crypto/crypto.h"
#include "common/bip340.h"
#include <openssl/evp.h>

static std::string ensure_websocket_scheme(const std::string& url)
{
if (url.find("ws://") == 0 || url.find("wss://") == 0)
return url;
return "ws://" + url;
}

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "nostr"

namespace cryptonote {

static bool hex_to_hash(const std::string& hex, crypto::hash& h)
{
    if (hex.size() != 2 * sizeof(crypto::hash))
        return false;
    return epee::string_tools::hex_to_pod(hex, h);
}

// secp256k1 signature verification

static bool recompute_nostr_event_id(const rapidjson::Value& ev, crypto::hash& out_id)
{
    using namespace rapidjson;
    if (!ev.IsObject())
        return false;

    if (!ev.HasMember("pubkey") || !ev["pubkey"].IsString())
        return false;
    if (!ev.HasMember("created_at") || !ev["created_at"].IsInt64())
        return false;
    if (!ev.HasMember("kind") || !ev["kind"].IsInt())
        return false;
    if (!ev.HasMember("tags") || !ev["tags"].IsArray())
        return false;
    if (!ev.HasMember("content") || !ev["content"].IsString())
        return false;

    Document canon;
    canon.SetArray();
    Document::AllocatorType& alloc = canon.GetAllocator();

    canon.PushBack(0, alloc);
    canon.PushBack(Value(ev["pubkey"].GetString(), alloc).Move(), alloc);
    canon.PushBack(Value(ev["created_at"].GetInt64()).Move(), alloc);
    canon.PushBack(Value(ev["kind"].GetInt()).Move(), alloc);

    Value tags_copy;
    tags_copy.CopyFrom(ev["tags"], alloc);
    canon.PushBack(tags_copy, alloc);

    canon.PushBack(Value(ev["content"].GetString(), alloc).Move(), alloc);

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    canon.Accept(writer);

    unsigned int out_len = sizeof(out_id);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return false;

    const bool ok =
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(mdctx, buffer.GetString(), buffer.GetSize()) == 1 &&
        EVP_DigestFinal_ex(mdctx, reinterpret_cast<unsigned char*>(out_id.data), &out_len) == 1;

    EVP_MD_CTX_free(mdctx);
    return ok;
    return true;
}

static bool verify_nostr_signature(const std::string& full_message_json,
                                   const std::array<unsigned char, 33>& registrant_pubkey)
{
    using namespace rapidjson;

    Document doc;
    if (doc.Parse(full_message_json.c_str()).HasParseError())
    {
        MERROR("Nostr: JSON parse error");
        return false;
    }

    if (!doc.IsArray() || doc.Size() < 3)
    {
        MERROR("Nostr: invalid EVENT message");
        return false;
    }

    if (!doc[0].IsString() || std::strcmp(doc[0].GetString(), "EVENT") != 0)
    {
        MERROR("Nostr: message is not an EVENT");
        return false;
    }

    const Value& ev = doc[2];
    if (!ev.IsObject())
    {
        MERROR("Nostr: event object missing");
        return false;
    }

    if (!ev.HasMember("id") || !ev["id"].IsString())
    {
        MERROR("Nostr: event id missing");
        return false;
    }

    if (!ev.HasMember("pubkey") || !ev["pubkey"].IsString())
    {
        MERROR("Nostr: event pubkey missing");
        return false;
    }

    if (!ev.HasMember("sig") || !ev["sig"].IsString())
    {
        MERROR("Nostr: event signature missing");
        return false;
    }

    // Nostr uses a 32-byte x-only public key encoded as 64 hex characters.
    const std::string event_pubkey_hex = ev["pubkey"].GetString();
    if (event_pubkey_hex.size() != 64)
    {
        MERROR("Nostr: invalid event pubkey length");
        return false;
    }

    std::array<unsigned char, 32> event_pubkey;
    if (!epee::string_tools::hex_to_pod(event_pubkey_hex, event_pubkey))
    {
        MERROR("Nostr: invalid event pubkey hex");
        return false;
    }

    // The legacy VNS registrant key is a 33-byte compressed secp256k1 key.
    // Its x-coordinate is the last 32 bytes and is the Nostr/BIP340 key.
    if (memcmp(event_pubkey.data(), registrant_pubkey.data() + 1, 32) != 0)
    {
        MERROR("Nostr: event pubkey does not match domain registrant key");
        return false;
    }

    crypto::hash supplied_id;
    const std::string id_hex = ev["id"].GetString();

    if (id_hex.size() != 2 * sizeof(crypto::hash))
    {
        MERROR("Nostr: invalid event id length");
        return false;
    }

    if (!epee::string_tools::hex_to_pod(id_hex, supplied_id))
    {
        MERROR("Nostr: invalid event id hex");
        return false;
    }

    // Reconstruct the exact NIP-01 serialized event and hash it with SHA-256.
    crypto::hash computed_id;
    if (!recompute_nostr_event_id(ev, computed_id))
    {
        MERROR("Nostr: failed to recompute event id");
        return false;
    }

    if (computed_id != supplied_id)
    {
        MERROR("Nostr: event id mismatch");
        return false;
    }

    const std::string sig_hex = ev["sig"].GetString();
    if (sig_hex.size() != 128)
    {
        MERROR("Nostr: invalid signature length");
        return false;
    }

    std::array<unsigned char, 64> signature{};
    for (size_t i = 0; i < signature.size(); ++i)
    {
        const std::string byte_str = sig_hex.substr(i * 2, 2);
        try
        {
            signature[i] = static_cast<unsigned char>(
                std::stoul(byte_str, nullptr, 16));
        }
        catch (...)
        {
            MERROR("Nostr: invalid signature hex");
            return false;
        }
    }

    if (!bip340::verify(
            registrant_pubkey.data(),
            reinterpret_cast<const unsigned char*>(&computed_id),
            signature.data()))
    {
        MERROR("Nostr: BIP340 signature verification failed");
        return false;
    }

    return true;
}

static bool parse_event(const std::string& json_line,
                        const std::string& expected_domain,
                        nostr_client::heartbeat_event& out_event)
 {
    using namespace rapidjson;
    Document doc;
    if (doc.Parse(json_line.c_str()).HasParseError())
        return false;
    if (!doc.IsArray()) return false;
    if (doc.Size() < 3) return false;          // [ "EVENT", sub_id, event ]
    std::string type = doc[0].GetString();
    if (type != "EVENT") return false;

    const Value& ev = doc[2];                  // event object is at index 2
    if (!ev.IsObject()) return false;

    if (!ev.HasMember("kind") || !ev["kind"].IsInt()) return false;
    int kind = ev["kind"].GetInt();
    if (kind != 30001) return false;

    if (!ev.HasMember("tags") || !ev["tags"].IsArray()) return false;
    const Value& tags = ev["tags"];
    std::string domain_found;
    crypto::hash proof_hash = crypto::null_hash;
    crypto::hash fingerprint_hash = crypto::null_hash;
    crypto::hash block_hash = crypto::null_hash;
    uint64_t leaf_index = 0;
    std::vector<crypto::hash> sibling_hashes;
    for (const auto& tag : tags.GetArray())
    {
        if (!tag.IsArray() || tag.Size() < 2) continue;
        std::string tagname = tag[0].GetString();
        if (tagname == "d" && tag[1].IsString())
        {
            domain_found = tag[1].GetString();
        }
        else if (tagname == "proof" && tag[1].IsString())
        {
            if (!hex_to_hash(tag[1].GetString(), proof_hash))
                return false;
        }
        else if (tagname == "block_hash" && tag[1].IsString())
        {
            if (!hex_to_hash(tag[1].GetString(), block_hash))
                return false;

            // Legacy proof field is the registration proof block hash.
            proof_hash = block_hash;
        }
        else if (tagname == "leaf_index" && tag[1].IsString())
        {
            try
            {
                leaf_index = std::stoull(tag[1].GetString());
            }
            catch (...)
            {
                return false;
            }
        }
        else if (tagname == "sibling_path" && tag[1].IsString())
        {
            std::stringstream ss(tag[1].GetString());
            std::string item;
            while (std::getline(ss, item, ','))
            {
                crypto::hash h;
                if (!hex_to_hash(item, h))
                    return false;
                sibling_hashes.push_back(h);
            }
        }
        else if (tagname == "fingerprint" && tag[1].IsString())
        {
            if (!hex_to_hash(tag[1].GetString(), fingerprint_hash))
                return false;
        }
        else if (tagname == "heartbeat_height" && tag[1].IsString())
        {
            out_event.heartbeat_height = std::stoull(tag[1].GetString());
        }
        else if (tagname == "heartbeat_count" && tag[1].IsString())
        {
            out_event.heartbeat_count = std::stoull(tag[1].GetString());
        }
    }

    if (domain_found != expected_domain)
    {
        MERROR("parse_event: domain mismatch");
        return false;
    }

    if (proof_hash == crypto::null_hash)
    {
        MERROR("parse_event: proof_hash is null");
        return false;
    }

    if (fingerprint_hash == crypto::null_hash)
    {
        MERROR("parse_event: fingerprint_hash is null");
        return false;
    }

    if (block_hash == crypto::null_hash)
    {
        MERROR("parse_event: block_hash is null");
        return false;
    }

    if (sibling_hashes.empty())
    {
        MERROR("parse_event: sibling_path is empty");
        return false;
    }

    if (!ev.HasMember("created_at") || !ev["created_at"].IsInt64())
    {
        MERROR("parse_event: missing created_at");
        return false;
    }
    uint64_t created_at = ev["created_at"].GetInt64();

    // Extract event ID from the event object
    crypto::hash event_id = crypto::null_hash;
    if (ev.HasMember("id") && ev["id"].IsString())
    {
        std::string id_hex = ev["id"].GetString();
        if (id_hex.size() == 2 * sizeof(crypto::hash))
            epee::string_tools::hex_to_pod(id_hex, event_id);
    }
    out_event.domain = domain_found;
    out_event.event_id = event_id;
    out_event.proof = proof_hash;
    out_event.fingerprint = fingerprint_hash;
    out_event.block_hash = block_hash;
    out_event.leaf_index = leaf_index;
    out_event.sibling_hashes = sibling_hashes;
    out_event.created_at = created_at;
    return true;
}

// --- New helper: generate REQ message for a given kind ---
static std::string make_req_message_generic(const std::string& subscription_id,
                                            const std::string& domain_name,
                                            int kind)
{
    using namespace rapidjson;
    Document doc;
    doc.SetArray();
    doc.PushBack("REQ", doc.GetAllocator());
    doc.PushBack(Value(subscription_id.c_str(), doc.GetAllocator()), doc.GetAllocator());
    Value filter(kObjectType);
    Value kinds(kArrayType);
    kinds.PushBack(kind, doc.GetAllocator());
    filter.AddMember("kinds", kinds, doc.GetAllocator());
    Value d_tag(kArrayType);
    d_tag.PushBack(Value(domain_name.c_str(), doc.GetAllocator()), doc.GetAllocator());
    filter.AddMember("#d", d_tag, doc.GetAllocator());
    filter.AddMember("limit", 1, doc.GetAllocator());
    doc.PushBack(filter, doc.GetAllocator());

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    doc.Accept(writer);
    return buffer.GetString();
}

// --- New parser for service descriptor (kind 30003) ---
static bool parse_service_descriptor_event(const std::string& json_line,
                                           const std::string& expected_domain,
                                           nostr_client::service_descriptor_event& out_event)
 {
    using namespace rapidjson;
    Document doc;
    if (doc.Parse(json_line.c_str()).HasParseError()) {
        MINFO("parse_service_descriptor_event: JSON parse error");
        return false;
    }
    if (!doc.IsArray()) {
        MINFO("parse_service_descriptor_event: not an array");
        return false;
    }
    if (doc.Size() < 3) {                     // [ "EVENT", sub_id, event ]
        MINFO("parse_service_descriptor_event: array too small (need 3 elements)");
        return false;
    }
    std::string type = doc[0].GetString();
    if (type != "EVENT") {
        MINFO("parse_service_descriptor_event: not an EVENT message");
        return false;
    }

    const Value& ev = doc[2];                  // event object is at index 2
    if (!ev.IsObject()) {
        MINFO("parse_service_descriptor_event: second element not an object");
        return false;
    }

    if (!ev.HasMember("kind") || !ev["kind"].IsInt()) {
        MINFO("parse_service_descriptor_event: missing or invalid kind");
        return false;
    }
    int kind = ev["kind"].GetInt();
    if (kind != 30003) {
        MINFO("parse_service_descriptor_event: kind is " << kind << ", expected 30003");
        return false;
    }

    if (!ev.HasMember("tags") || !ev["tags"].IsArray()) {
        MINFO("parse_service_descriptor_event: missing or invalid tags");
        return false;
    }
    const Value& tags = ev["tags"];
    std::string domain_found;
    std::string fingerprint_hex;
    std::string block_hash_hex;
    std::string leaf_index_str;
    std::string sibling_path_str;

    for (const auto& tag : tags.GetArray())
    {
        if (!tag.IsArray() || tag.Size() < 2) continue;
        std::string tagname = tag[0].GetString();
        if (tagname == "d" && tag[1].IsString())
        {
            domain_found = tag[1].GetString();
            MINFO("parse_service_descriptor_event: found d tag = " << domain_found);
        }
        else if (tagname == "fingerprint" && tag[1].IsString())
        {
            fingerprint_hex = tag[1].GetString();
            MINFO("parse_service_descriptor_event: found fingerprint tag = " << fingerprint_hex);
        }
        else if (tagname == "block_hash" && tag[1].IsString())
        {
            block_hash_hex = tag[1].GetString();
            MINFO("parse_service_descriptor_event: found block_hash tag = " << block_hash_hex);
        }
        else if (tagname == "leaf_index" && tag[1].IsString())
        {
            leaf_index_str = tag[1].GetString();
            MINFO("parse_service_descriptor_event: found leaf_index tag = " << leaf_index_str);
        }
        else if (tagname == "sibling_path")
        {
            // tag may have multiple values; collect all after the first
            for (rapidjson::SizeType i = 1; i < tag.Size(); ++i)
            {
                if (tag[i].IsString())
                {
                    if (!sibling_path_str.empty()) sibling_path_str += ",";
                    sibling_path_str += tag[i].GetString();
                }
            }
            MINFO("parse_service_descriptor_event: found sibling_path tag = " << sibling_path_str);
        }
        else if (tagname == "version" && tag[1].IsString())
        {
            const std::string version_str = tag[1].GetString();
            try
            {
                out_event.version = std::stoull(version_str);
                MINFO("parse_service_descriptor_event: found version tag = " << version_str);
            }
            catch (...)
            {
                MINFO("parse_service_descriptor_event: invalid version tag = " << version_str);
                out_event.version = 0;
            }
        }
    }
    if (domain_found != expected_domain) {
        MINFO("parse_service_descriptor_event: domain mismatch: found '" << domain_found << "', expected '" << expected_domain << "'");
        return false;
    }
    if (fingerprint_hex.empty()) {
        MINFO("parse_service_descriptor_event: fingerprint tag missing or empty");
        return false;
    }
    if (block_hash_hex.empty()) {
        MINFO("parse_service_descriptor_event: block_hash tag missing or empty");
        return false;
    }
    if (leaf_index_str.empty()) {
        MINFO("parse_service_descriptor_event: leaf_index tag missing or empty");
        return false;
    }
    if (sibling_path_str.empty()) {
        MINFO("parse_service_descriptor_event: sibling_path tag missing or empty");
        return false;
    }

    // Parse block_hash
    if (!hex_to_hash(block_hash_hex, out_event.block_hash)) {
        MINFO("parse_service_descriptor_event: failed to parse block_hash hex: " << block_hash_hex);
        return false;
    }

    // Parse leaf_index
    try { out_event.leaf_index = std::stoull(leaf_index_str); }
    catch (...) {
        MINFO("parse_service_descriptor_event: failed to parse leaf_index: " << leaf_index_str);
        return false;
    }

    // Parse sibling_path (comma-separated hex)
    out_event.sibling_hashes.clear();
    std::stringstream ss(sibling_path_str);
    std::string item;
    while (std::getline(ss, item, ','))
    {
        crypto::hash h;
        if (!hex_to_hash(item, h)) {
            MINFO("parse_service_descriptor_event: failed to parse sibling hash: " << item);
            return false;
        }
        out_event.sibling_hashes.push_back(h);
    }
    if (out_event.sibling_hashes.empty()) {
        MINFO("parse_service_descriptor_event: no sibling hashes after parsing");
        return false;
    }

    out_event.fingerprint_hex = fingerprint_hex;

    if (!ev.HasMember("content") || !ev["content"].IsString()) {
        MINFO("parse_service_descriptor_event: missing or invalid content");
        return false;
    }
    out_event.content = ev["content"].GetString();

    if (!ev.HasMember("created_at") || !ev["created_at"].IsInt64()) {
        MINFO("parse_service_descriptor_event: missing or invalid created_at");
        return false;
    }
    out_event.created_at = ev["created_at"].GetInt64();

    if (ev.HasMember("id") && ev["id"].IsString())
    {
        const std::string id_hex = ev["id"].GetString();
        if (id_hex.size() == 2 * sizeof(crypto::hash))
            epee::string_tools::hex_to_pod(id_hex, out_event.event_id);
    }

    if (ev.HasMember("pubkey") && ev["pubkey"].IsString())
        out_event.pubkey_hex = ev["pubkey"].GetString();

    if (out_event.version == 0)
    {
        MINFO("parse_service_descriptor_event: missing or invalid version");
        return false;
    }

    MINFO("parse_service_descriptor_event: parsing successful for domain " << expected_domain
          << " version=" << out_event.version);
    return true;
}

// ---------- VNS NOSTR FETCHER START ----------

bool nostr_client::fetch_heartbeat(const std::string& relay_url,
                                   const std::string& domain_name,
                                   const std::array<unsigned char, 33>& registrant_pubkey,
                                   heartbeat_event& out_event,
                                   int timeout_seconds)
{
    ix::initNetSystem();
    ix::WebSocket ws;
    std::string url = ensure_websocket_scheme(relay_url);

    ws.setUrl(url);
    ws.setHandshakeTimeout(timeout_seconds);
    ws.setPingInterval(30);

    std::vector<heartbeat_event> events;
    bool done = false;

    ws.setOnMessageCallback([&](const ix::WebSocketMessagePtr& msg) {
    if (msg->type == ix::WebSocketMessageType::Open) {
        MINFO("Nostr: connected to " << relay_url);
        std::string req_msg = make_req_message_generic("vns_heartbeat", domain_name, 30001);
        MINFO("Nostr: sending REQ: " << req_msg);
        ws.sendText(req_msg);
    }
    else if (msg->type == ix::WebSocketMessageType::Message)
{
    MINFO("Nostr received: " << msg->str);

    heartbeat_event ev;

    bool parsed = parse_event(msg->str, domain_name, ev);
    MINFO("Heartbeat parse result: " << parsed);

    if (parsed)
    {
        bool verified =
            verify_nostr_signature(msg->str, registrant_pubkey);


        if (verified)
        {
            events.push_back(ev);
            MINFO("Heartbeat event accepted");
        }
    }
}
});

    ws.start();
    auto start_time = std::chrono::steady_clock::now();
    while (!done && events.empty())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (std::chrono::steady_clock::now() - start_time > std::chrono::seconds(timeout_seconds))
        {
            MERROR("Nostr: timeout waiting for events from " << relay_url);
            ws.stop();
            return false;
        }
    }
    ws.stop();

    if (events.empty())
        return false;

    out_event = events.front();
    return true;
}

bool nostr_client::fetch_service_descriptor(const std::string& relay_url,
                                            const std::string& domain_name,
                                            const std::array<unsigned char, 33>& registrant_pubkey,
                                            service_descriptor_event& out_event,
                                            int timeout_seconds)
{
    ix::initNetSystem();
    ix::WebSocket ws;
    std::string url = ensure_websocket_scheme(relay_url);

    ws.setUrl(url);
    ws.setHandshakeTimeout(timeout_seconds);
    ws.setPingInterval(30);

    std::vector<service_descriptor_event> events;
    bool done = false;

    ws.setOnMessageCallback([&](const ix::WebSocketMessagePtr& msg) {
    if (msg->type == ix::WebSocketMessageType::Open) {
        MINFO("Nostr: connected to " << relay_url);
        std::string req_msg = make_req_message_generic("vns_service_desc", domain_name, 30003);
        MINFO("Nostr: sending REQ: " << req_msg);
        ws.sendText(req_msg);
    }
    else if (msg->type == ix::WebSocketMessageType::Message) {
    MINFO("Nostr received: " << msg->str);
    service_descriptor_event ev;
    if (parse_service_descriptor_event(msg->str, domain_name, ev))
    {
        const bool verified = verify_nostr_signature(msg->str, registrant_pubkey);
        if (verified)
        {
            events.push_back(ev);
            MINFO("Nostr: service descriptor event accepted, events size: " << events.size());
        }
        else
        {
            MERROR("Nostr: service descriptor signature verification failed for domain " << domain_name);
        }
    }
    else
    {
        MDEBUG("Nostr: failed to parse service descriptor event: " << msg->str);
        // Promote to INFO temporarily for debugging
        MINFO("Nostr: failed to parse service descriptor event (see previous logs)");
    }
 }
    else if (msg->type == ix::WebSocketMessageType::Close) {
        MINFO("Nostr: connection closed to " << relay_url);
        done = true;
    }
    else if (msg->type == ix::WebSocketMessageType::Error) {
        MERROR("Nostr: error " << msg->errorInfo.reason);
        done = true;
    }
});

    ws.start();
    auto start_time = std::chrono::steady_clock::now();
    while (!done && events.empty())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (std::chrono::steady_clock::now() - start_time > std::chrono::seconds(timeout_seconds))
        {
            MERROR("Nostr: timeout waiting for service descriptor events from " << relay_url);
            ws.stop();
            return false;
        }
    }
    ws.stop();

    if (events.empty())
        return false;

    out_event = events.front();
    return true;
}

bool nostr_client::publish_event(const std::string& relay_url,
                                 const std::string& event_json,
                                 int timeout_seconds)
{
    ix::initNetSystem();
    ix::WebSocket ws;
    std::string url = ensure_websocket_scheme(relay_url);

    ws.setUrl(url);
    ws.setHandshakeTimeout(timeout_seconds);
    ws.setPingInterval(30);

    bool published = false;
    bool done = false;

    ws.setOnMessageCallback([&](const ix::WebSocketMessagePtr& msg) {
        if (msg->type == ix::WebSocketMessageType::Open) {
            MINFO("Nostr: connected to " << relay_url << " for publishing");
            // Send EVENT message
            using namespace rapidjson;
            Document doc;
            doc.SetArray();
            auto& alloc = doc.GetAllocator();
            doc.PushBack("EVENT", alloc);
            Document event_doc;
            if (event_doc.Parse(event_json.c_str()).HasParseError())
            {
                MERROR("Invalid event JSON");
                ws.stop();
                done = true;
                return;
            }
            doc.PushBack(event_doc, alloc);

            StringBuffer buffer;
            Writer<StringBuffer> writer(buffer);
            doc.Accept(writer);
            std::string msg_str = buffer.GetString();
            MINFO("Nostr publish message: " << msg_str);
            ws.sendText(msg_str);
        }
        else if (msg->type == ix::WebSocketMessageType::Message) {
            // Check for OK message
            using namespace rapidjson;
            Document doc;
            if (doc.Parse(msg->str.c_str()).HasParseError())
                return;
            if (!doc.IsArray() || doc.Size() < 3)
                return;
            if (doc[0].GetString() != std::string("OK"))
                return;
            if (doc[2].IsBool() && doc[2].GetBool())
            {
                published = true;
            }
            else
            {
                MERROR("Nostr: relay rejected event: " << msg->str);
            }
            done = true;
        }
        else if (msg->type == ix::WebSocketMessageType::Close) {
            MINFO("Nostr: connection closed after publishing");
            done = true;
        }
        else if (msg->type == ix::WebSocketMessageType::Error) {
            MERROR("Nostr: error during publish: " << msg->errorInfo.reason);
            done = true;
        }
    });

    ws.start();
    auto start_time = std::chrono::steady_clock::now();
    while (!done)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (std::chrono::steady_clock::now() - start_time > std::chrono::seconds(timeout_seconds))
        {
            MERROR("Nostr: timeout waiting for OK from " << relay_url);
            ws.stop();
            return false;
        }
    }
    ws.stop();

    return published;
}

bool nostr_client::verify_nostr_event_signature(
    const std::string& event_json,
    const std::array<unsigned char, 33>& registrant_pubkey)
{
    // The internal verifier operates on the standard Nostr relay EVENT envelope.
    const std::string full_message =
        "[\"EVENT\",\"vns_verify\"," + event_json + "]";

    return verify_nostr_signature(full_message, registrant_pubkey);
}

bool nostr_client::verify_nostr_signature_for_test(
    const std::string& full_message_json,
    const std::array<unsigned char, 33>& registrant_pubkey)
{
    return verify_nostr_signature(full_message_json, registrant_pubkey);
}

bool nostr_client::parse_service_descriptor_event_for_test(
    const std::string& json_line,
    const std::string& expected_domain,
    service_descriptor_event& out_event)
{
    return parse_service_descriptor_event(json_line, expected_domain, out_event);
}

bool nostr_client::parse_heartbeat_event_for_test(
    const std::string& json_line,
    const std::string& expected_domain,
    heartbeat_event& out_event)
{
    return parse_event(json_line, expected_domain, out_event);
}

} // namespace cryptonote