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

static bool verify_nostr_signature(const std::string& full_message_json,
                                   const std::array<unsigned char, 33>& registrant_pubkey)
{
    using namespace rapidjson;
    Document doc;
    if (doc.Parse(full_message_json.c_str()).HasParseError())
    {
        MERROR("DEBUG: JSON parse error");
        return false;
    }
    if (!doc.IsArray() || doc.Size() < 3)
    {
        MERROR("DEBUG: Not array or size<2, size=" << (doc.IsArray() ? "n/a" : "not array"));
        return false;
    }
    if (!doc[0].IsString() || doc[0].GetString() != std::string("EVENT"))
    {
        MERROR("DEBUG: doc[0] not EVENT string");
        return false;
    }
    const Value& ev = doc[2];
    if (!ev.IsObject())
    {
        MERROR("DEBUG: ev not object");
        return false;
    }
    if (!ev.HasMember("id") || !ev["id"].IsString())
    {
        MERROR("DEBUG: id missing or not string");
        return false;
    }
    if (!ev.HasMember("sig") || !ev["sig"].IsString())
    {
        MERROR("DEBUG: sig missing or not string");
        return false;
    }

    // Parse event ID (32 bytes)
    crypto::hash event_id;
    std::string id_hex = ev["id"].GetString();
    if (id_hex.size() != 2 * sizeof(crypto::hash))
    {
        MERROR("DEBUG: id_hex size mismatch: " << id_hex.size() << " vs " << (2*sizeof(crypto::hash)));
        return false;
    }
    if (!epee::string_tools::hex_to_pod(id_hex, event_id))
    {
        MERROR("DEBUG: hex_to_pod failed for id_hex: " << id_hex);
        return false;
    }

    // Parse BIP340 signature (64 bytes)
    std::string sig_hex = ev["sig"].GetString();
    if (sig_hex.size() != 128) // 64 bytes * 2
    {
        MERROR("DEBUG: sig_hex size mismatch: " << sig_hex.size() << " vs 128");
        return false;
    }
    std::array<unsigned char, 64> sig;
    for (size_t i = 0; i < 64; ++i) {
        std::string byte_str = sig_hex.substr(i*2, 2);
        sig[i] = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
    }

    // Debug: log the values being verified
    std::string pubkey_hex = epee::string_tools::buff_to_hex_nodelimer(std::string((const char*)registrant_pubkey.data(), 33));
    std::string id_hex_log = epee::string_tools::pod_to_hex(event_id);
    std::string sig_hex_log = epee::string_tools::buff_to_hex_nodelimer(std::string((const char*)sig.data(), 64));
    bool result = bip340::verify(registrant_pubkey.data(), (const unsigned char*)&event_id, sig.data());
    return result;
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
    for (const auto& tag : tags.GetArray())
    {
        if (!tag.IsArray() || tag.Size() < 2) continue;
        std::string tagname = tag[0].GetString();
        if (tagname == "d" && tag[1].IsString())
        {
            domain_found = tag[1].GetString();
        }
        else if ((tagname == "proof" || tagname == "block_hash") && tag[1].IsString())
        {
            if (!hex_to_hash(tag[1].GetString(), proof_hash))
                return false;
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

    MINFO("parse_service_descriptor_event: parsing successful for domain " << expected_domain);
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
                                            const crypto::public_key& registrant_pubkey,
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
        // Optionally verify signature (skipped for now, as in heartbeat)
        // We could call verify_nostr_signature with the full event JSON
        events.push_back(ev);
        MINFO("Nostr: service descriptor event pushed, events size: " << events.size());
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

} // namespace cryptonote