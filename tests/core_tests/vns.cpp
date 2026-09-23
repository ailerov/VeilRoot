// Copyright (c) 2026, The VeilRoot Project
// SPDX-License-Identifier: BSD-3-Clause

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "chaingen.h"
#include "chaingen_tests_list.h"
#include "common/domain_utils.h"
#include "common/bip340.h"
#include "crypto/crypto.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "string_tools.h"

#include <secp256k1.h>

using namespace cryptonote;

namespace
{
    // Produce a real compressed secp256k1 public key from a deterministic
    // seed. prefix_override lets the caller force 0x00/0x04 etc. for the
    // negative test cases; for prefix 0x02/0x03 the bytes are a valid point.
    std::array<unsigned char, 33> make_key(uint8_t prefix, uint8_t seed)
    {
        std::array<unsigned char, 33> k{};
        // derive real key
        std::array<unsigned char, 32> sec{};
        for (size_t i = 0; i < 32; ++i)
            sec[i] = static_cast<unsigned char>((seed * 37 + i * 11 + 1) & 0xff);
        sec[0] |= 0x01;
        sec[31] |= 0x80;

        secp256k1_context* ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        secp256k1_pubkey pk;
        if (secp256k1_ec_pubkey_create(ctx, &pk, sec.data()))
        {
            size_t out_len = 33;
            secp256k1_ec_pubkey_serialize(ctx, k.data(), &out_len, &pk, SECP256K1_EC_COMPRESSED);
        }
        secp256k1_context_destroy(ctx);

        // force the requested prefix for negative tests
        if (k[0] != prefix)
            k[0] = prefix;

        return k;
    }

    struct kp_t
    {
        std::array<unsigned char, 32> secret{};
        std::array<unsigned char, 32> xonly{};
        std::array<unsigned char, 33> compressed{};
    };

    kp_t make_keypair(uint8_t seed)
    {
        kp_t kp;
        for (size_t i = 0; i < 32; ++i)
            kp.secret[i] = static_cast<unsigned char>((seed * 37 + i * 11 + 1) & 0xff);
        kp.secret[0] |= 0x01;
        kp.secret[31] |= 0x80;

        secp256k1_context* ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        secp256k1_pubkey pk;
        if (!secp256k1_ec_pubkey_create(ctx, &pk, kp.secret.data()))
        {
            secp256k1_context_destroy(ctx);
            return kp;
        }
        size_t out_len = 33;
        secp256k1_ec_pubkey_serialize(ctx, kp.compressed.data(), &out_len, &pk,
                                      SECP256K1_EC_COMPRESSED);
        memcpy(kp.xonly.data(), kp.compressed.data() + 1, 32);
        secp256k1_context_destroy(ctx);
        return kp;
    }

    std::vector<uint8_t> wrap_extra(const std::vector<uint8_t>& payload)
    {
        std::vector<uint8_t> extra;
        extra.push_back(0x02);
        if (payload.size() < 0x80)
        {
            extra.push_back(static_cast<uint8_t>(payload.size()));
        }
        else
        {
            extra.push_back(static_cast<uint8_t>(payload.size() | 0x80));
            extra.push_back(static_cast<uint8_t>(payload.size() >> 7));
        }
        extra.insert(extra.end(), payload.begin(), payload.end());
        return extra;
    }

    void tlv(std::vector<uint8_t>& out, uint8_t t, const void* d, size_t n)
    {
        out.push_back(t);
        out.push_back(static_cast<uint8_t>(n));
        const uint8_t* p = static_cast<const uint8_t*>(d);
        out.insert(out.end(), p, p + n);
    }

    std::vector<uint8_t> build_reg_extra_raw(
        const std::string& domain,
        uint8_t fee_tier,
        const std::vector<unsigned char>& key_bytes,
        const crypto::hash& fingerprint,
        const std::vector<std::pair<uint8_t, std::string>>& relays)
    {
        std::vector<uint8_t> payload;
        const char MAGIC[] = "DOMAIN_REG";
        payload.insert(payload.end(), MAGIC, MAGIC + 10);

        tlv(payload, 0x01, domain.data(), domain.size());
        tlv(payload, 0x02, &fee_tier, 1);
        tlv(payload, 0x03, key_bytes.data(), key_bytes.size());
        tlv(payload, 0x04, fingerprint.data, sizeof(fingerprint));
        for (const auto& r : relays)
            tlv(payload, r.first, r.second.data(), r.second.size());
        payload.push_back(0x00);
        return wrap_extra(payload);
    }

    std::vector<uint8_t> build_xfer_extra_raw(
        const std::string& domain,
        const std::vector<unsigned char>& xonly,
        const std::vector<unsigned char>& sig)
    {
        std::vector<uint8_t> payload;
        const char MAGIC[] = "DOMAIN_XFER";
        payload.insert(payload.end(), MAGIC, MAGIC + 11);

        tlv(payload, 0x01, domain.data(), domain.size());
        tlv(payload, 0x05, xonly.data(), xonly.size());
        tlv(payload, 0x04, sig.data(), sig.size());
        payload.push_back(0x00);
        return wrap_extra(payload);
    }

    // Parse the wire envelope: [0x02][varint len][payload][0x00]
    // Then walk the payload TLVs and record (tag -> bytes) pairs.
    bool parse_extra_tlvs(const std::vector<uint8_t>& extra,
                          const std::string& expected_magic,
                          std::vector<std::pair<uint8_t, std::vector<uint8_t>>>& out,
                          std::string& err)
    {
        if (extra.size() < 3 || extra[0] != 0x02) { err = "missing 0x02 envelope tag"; return false; }
        size_t len_pos = 1;
        size_t payload_len = 0;
        if (extra[len_pos] < 0x80) {
            payload_len = extra[len_pos];
            len_pos += 1;
        } else {
            payload_len = (size_t)(extra[len_pos] & 0x7f) | ((size_t)extra[len_pos+1] << 7);
            len_pos += 2;
        }
        if (len_pos + payload_len > extra.size()) { err = "payload length exceeds extra"; return false; }
        const uint8_t* p = extra.data() + len_pos;
        if (payload_len < expected_magic.size() ||
            memcmp(p, expected_magic.data(), expected_magic.size()) != 0) {
            err = "wrong magic"; return false;
        }
        size_t pos = expected_magic.size();
        while (pos < payload_len) {
            uint8_t tag = p[pos++];
            if (tag == 0x00) break;
            if (pos >= payload_len) { err = "truncated TLV"; return false; }
            uint8_t len = p[pos++];
            if (pos + len > payload_len) { err = "TLV length overflow"; return false; }
            out.emplace_back(tag, std::vector<uint8_t>(p + pos, p + pos + len));
            pos += len;
        }
        return true;
    }

    cryptonote::transaction make_tx(const std::vector<uint8_t>& extra)
    {
        cryptonote::transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1;
        tx.extra = extra;
        return tx;
    }

    cryptonote::transaction make_reg_tx(
        const std::string& domain,
        uint8_t fee_tier,
        const std::array<unsigned char, 33>& key,
        const crypto::hash& fp,
        const std::vector<std::string>& relays)
    {
        std::array<std::string, 3> relay_arr{};
        for (size_t i = 0; i < std::min<size_t>(3, relays.size()); ++i)
            relay_arr[i] = relays[i];
        cryptonote::transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.version = 1;
        tx.extra = domain_utils::build_registration_extra(
            domain, fee_tier, key, fp, relay_arr);
        return tx;
    }
}

vns_protocol_tests::vns_protocol_tests()
{
    REGISTER_CALLBACK_METHOD(vns_protocol_tests, run_all);
}

bool vns_protocol_tests::generate(std::vector<test_event_entry>& events) const
{
    uint64_t ts_start = 1338224400;
    MAKE_GENESIS_BLOCK(events, blk_0, m_miner_account, ts_start);
    MAKE_ACCOUNT(events, m_miner_account);
    DO_CALLBACK(events, "run_all");
    return true;
}

bool vns_protocol_tests::run_all(cryptonote::core& c, size_t /*ev_index*/,
                                 const std::vector<test_event_entry>& /*events*/)
{
    DEFINE_TESTS_ERROR_CONTEXT("vns_protocol_tests::run_all");
    Blockchain& bc = c.get_blockchain_storage();

    // process_domain_registration(..., dry_run=false) writes through m_db,
    // and BlockchainLMDB::add_vns_domain_record requires an active write
    // transaction. Wrap every non-dry-run call in a db_wtxn_guard so the
    // production persistence path has a transaction to write into.
    auto reg = [&bc](const cryptonote::transaction& tx, uint64_t h) {
        cryptonote::db_wtxn_guard g(
            const_cast<cryptonote::BlockchainDB*>(&bc.get_db()));
        return bc.process_domain_registration(tx, h, false);
    };

    const uint64_t H = 1000;
    const uint8_t T_GENERIC = 0;

    // ---- Test 1: 33-byte key 0x02 -> ACCEPT
    {
        auto key = make_key(0x02, 1);
        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint("vt01..com", key, T_GENERIC);
        auto tx = make_reg_tx("vt01..com", T_GENERIC, key, fp, {"ws://a1.example"});
        auto r = reg(tx, H);
        CHECK_TEST_CONDITION(r == domain_registration_result::success);
        auto rec = bc.get_domain_record("vt01..com");
        CHECK_TEST_CONDITION(rec.registrant_key == key);
        CHECK_TEST_CONDITION(rec.registered_height == H);
        CHECK_TEST_CONDITION(rec.last_heartbeat_block == H);
        CHECK_TEST_CONDITION(rec.status == 0);
        CHECK_TEST_CONDITION(rec.fee_tier == T_GENERIC);
        CHECK_TEST_CONDITION(rec.genesis_fingerprint == fp);
        CHECK_TEST_CONDITION(std::string(rec.relays[0].url) == "ws://a1.example");
    }

    // ---- Test 2: 33-byte key 0x03 -> ACCEPT
    {
        auto key = make_key(0x03, 2);
        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint("vt02..com", key, T_GENERIC);
        auto tx = make_reg_tx("vt02..com", T_GENERIC, key, fp, {"ws://a2.example"});
        auto r = reg(tx, H);
        CHECK_TEST_CONDITION(r == domain_registration_result::success);
    }

    // ---- Test 3: 32-byte key -> REJECT
    {
        std::vector<unsigned char> key32(32, 0xAA);
        crypto::hash fp = crypto::null_hash;
        fp.data[0] = 1;
        auto extra = build_reg_extra_raw("vt03..com", T_GENERIC, key32, fp, {{0x06, "ws://a3.example"}});
        auto r = reg(make_tx(extra), H);
        CHECK_TEST_CONDITION(r == domain_registration_result::invalid_key);
    }

    // ---- Test 4: 33-byte key with prefix 0x04 -> REJECT
    {
        auto key = make_key(0x04, 4);
        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint("vt04..com", key, T_GENERIC);
        auto tx = make_reg_tx("vt04..com", T_GENERIC, key, fp, {"ws://a4.example"});
        auto r = reg(tx, H);
        CHECK_TEST_CONDITION(r == domain_registration_result::invalid_key);
    }

    // ---- Test 5: 33-byte key with prefix 0x00 -> REJECT
    {
        auto key = make_key(0x00, 5);
        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint("vt05..com", key, T_GENERIC);
        auto tx = make_reg_tx("vt05..com", T_GENERIC, key, fp, {"ws://a5.example"});
        auto r = reg(tx, H);
        CHECK_TEST_CONDITION(r == domain_registration_result::invalid_key);
    }

    // ---- Test 6: 1 relay -> ACCEPT
    {
        auto key = make_key(0x02, 6);
        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint("vt06..com", key, T_GENERIC);
        auto tx = make_reg_tx("vt06..com", T_GENERIC, key, fp, {"ws://a6.example"});
        auto r = reg(tx, H);
        CHECK_TEST_CONDITION(r == domain_registration_result::success);
    }

    // ---- Test 7: 3 relays -> ACCEPT
    {
        auto key = make_key(0x02, 7);
        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint("vt07..com", key, T_GENERIC);
        auto tx = make_reg_tx("vt07..com", T_GENERIC, key, fp,
                              {"ws://a7.example", "ws://b7.example", "wss://c7.example"});
        auto r = reg(tx, H);
        CHECK_TEST_CONDITION(r == domain_registration_result::success);
        auto rec = bc.get_domain_record("vt07..com");
        CHECK_TEST_CONDITION(std::string(rec.relays[0].url) == "ws://a7.example");
        CHECK_TEST_CONDITION(std::string(rec.relays[1].url) == "ws://b7.example");
        CHECK_TEST_CONDITION(std::string(rec.relays[2].url) == "wss://c7.example");
    }

    // ---- Test 8: 4th relay tag 0x09 -> REJECT (unsupported wire tag)
    {
        auto key = make_key(0x02, 8);
        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint("vt08..com", key, T_GENERIC);
        std::vector<unsigned char> key_bytes(key.begin(), key.end());
        auto extra = build_reg_extra_raw("vt08..com", T_GENERIC, key_bytes, fp,
            {{0x06, "ws://a8.example"}, {0x07, "ws://b8.example"},
             {0x08, "ws://c8.example"}, {0x09, "ws://d8.example"}});
        auto r = reg(make_tx(extra), H);
        CHECK_TEST_CONDITION(r == domain_registration_result::invalid_format);
    }

    // ---- Test 9: active duplicate -> REJECT
    {
        auto key = make_key(0x02, 9);
        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint("vt09..com", key, T_GENERIC);
        auto tx = make_reg_tx("vt09..com", T_GENERIC, key, fp, {"ws://a9.example"});
        CHECK_TEST_CONDITION(reg(tx, H) ==
                             domain_registration_result::success);
        auto tx2 = make_reg_tx("vt09..com", T_GENERIC, key, fp, {"ws://a9.example"});
        CHECK_TEST_CONDITION(reg(tx2, H + 10) ==
                             domain_registration_result::already_registered);
    }

    // ---- Test 10: expiry/reclaim boundaries
    {
        auto key = make_key(0x02, 10);
        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint("vt10..com", key, T_GENERIC);
        auto tx = make_reg_tx("vt10..com", T_GENERIC, key, fp, {"ws://a10.example"});
        CHECK_TEST_CONDITION(reg(tx, H) ==
                             domain_registration_result::success);

        bc.check_domain_expiry(H + 21600);
        CHECK_TEST_CONDITION(bc.get_domain_record("vt10..com").status == 1); // GRACE

        bc.check_domain_expiry(H + 21601);
        CHECK_TEST_CONDITION(bc.get_domain_record("vt10..com").status == 2); // EXPIRED

        // H + 21601: expired but NOT reclaimable
        auto tx2 = make_reg_tx("vt10..com", T_GENERIC, key, fp, {"ws://a10b.example"});
        CHECK_TEST_CONDITION(reg(tx2, H + 21601) ==
                             domain_registration_result::already_registered);

        // H + 43200: expired but NOT reclaimable
        bc.check_domain_expiry(H + 43200);
        CHECK_TEST_CONDITION(bc.get_domain_record("vt10..com").status == 2);
        auto tx3 = make_reg_tx("vt10..com", T_GENERIC, key, fp, {"ws://a10c.example"});
        CHECK_TEST_CONDITION(reg(tx3, H + 43200) ==
                             domain_registration_result::already_registered);

        // H + 43201: first reclaimable height
        bc.check_domain_expiry(H + 43201);
        CHECK_TEST_CONDITION(bc.get_domain_record("vt10..com").status == 2);
        auto key2 = make_key(0x02, 11);
        crypto::hash fp2 = domain_utils::compute_vns_registration_fingerprint("vt10..com", key2, T_GENERIC);
        auto tx4 = make_reg_tx("vt10..com", T_GENERIC, key2, fp2, {"ws://a10d.example"});
        CHECK_TEST_CONDITION(reg(tx4, H + 43201) ==
                             domain_registration_result::success);

        auto rec = bc.get_domain_record("vt10..com");
        CHECK_TEST_CONDITION(rec.registrant_key == key2);
        CHECK_TEST_CONDITION(rec.registered_height == H + 43201);
        CHECK_TEST_CONDITION(rec.genesis_fingerprint == fp2);
        CHECK_TEST_CONDITION(std::string(rec.relays[0].url) == "ws://a10d.example");
    }

    // ---- Test 11: transfer with valid owner signature -> ACCEPT
    {
        auto owner = make_keypair(20);
        auto newowner = make_keypair(21);

        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint(
            "vt11..com", owner.compressed, T_GENERIC);
        auto reg_tx = make_reg_tx("vt11..com", T_GENERIC, owner.compressed, fp, {"ws://a11.example"});
        CHECK_TEST_CONDITION(reg(reg_tx, H) ==
                             domain_registration_result::success);

        std::array<unsigned char, 32> xonly_dest{};
        memcpy(xonly_dest.data(), newowner.xonly.data(), 32);
        crypto::hash msg = domain_utils::compute_vns_transfer_message_hash("vt11..com", xonly_dest);
        unsigned char sig64[64];
        CHECK_TEST_CONDITION(bip340::sign(owner.secret.data(),
                                          reinterpret_cast<const unsigned char*>(&msg), sig64));

        std::vector<unsigned char> xonly_vec(xonly_dest.begin(), xonly_dest.end());
        std::vector<unsigned char> sig_vec(sig64, sig64 + 64);
        auto xfer_tx = make_tx(build_xfer_extra_raw("vt11..com", xonly_vec, sig_vec));
        CHECK_TEST_CONDITION(reg(xfer_tx, H + 1) ==
                             domain_registration_result::success);

        auto rec = bc.get_domain_record("vt11..com");
        CHECK_TEST_CONDITION(rec.registrant_key[0] == 0x02);
        CHECK_TEST_CONDITION(memcmp(rec.registrant_key.data() + 1, newowner.xonly.data(), 32) == 0);
    }

    // ---- Test 12: transfer with garbage signature -> REJECT
    {
        auto owner = make_keypair(30);
        auto newowner = make_keypair(31);

        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint(
            "vt12..com", owner.compressed, T_GENERIC);
        auto reg_tx = make_reg_tx("vt12..com", T_GENERIC, owner.compressed, fp, {"ws://a12.example"});
        CHECK_TEST_CONDITION(reg(reg_tx, H) ==
                             domain_registration_result::success);

        std::vector<unsigned char> xonly_vec(newowner.xonly.begin(), newowner.xonly.end());
        std::vector<unsigned char> sig_vec(64, 0x42);
        auto xfer_tx = make_tx(build_xfer_extra_raw("vt12..com", xonly_vec, sig_vec));
        CHECK_TEST_CONDITION(reg(xfer_tx, H + 1) ==
                             domain_registration_result::signature_invalid);
    }

    // ---- Test 13: transfer signed by non-owner -> REJECT
    {
        auto owner = make_keypair(40);
        auto attacker = make_keypair(41);
        auto newowner = make_keypair(42);

        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint(
            "vt13..com", owner.compressed, T_GENERIC);
        auto reg_tx = make_reg_tx("vt13..com", T_GENERIC, owner.compressed, fp, {"ws://a13.example"});
        CHECK_TEST_CONDITION(reg(reg_tx, H) ==
                             domain_registration_result::success);

        std::array<unsigned char, 32> xonly_dest{};
        memcpy(xonly_dest.data(), newowner.xonly.data(), 32);
        crypto::hash msg = domain_utils::compute_vns_transfer_message_hash("vt13..com", xonly_dest);
        unsigned char sig64[64];
        CHECK_TEST_CONDITION(bip340::sign(attacker.secret.data(),
                                          reinterpret_cast<const unsigned char*>(&msg), sig64));

        std::vector<unsigned char> xonly_vec(xonly_dest.begin(), xonly_dest.end());
        std::vector<unsigned char> sig_vec(sig64, sig64 + 64);
        auto xfer_tx = make_tx(build_xfer_extra_raw("vt13..com", xonly_vec, sig_vec));
        CHECK_TEST_CONDITION(reg(xfer_tx, H + 1) ==
                             domain_registration_result::signature_invalid);
    }

    // ---- Test 14: signed for K2a, submitted with K2b -> REJECT
    {
        auto owner = make_keypair(50);
        auto newowner_a = make_keypair(51);
        auto newowner_b = make_keypair(52);

        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint(
            "vt14..com", owner.compressed, T_GENERIC);
        auto reg_tx = make_reg_tx("vt14..com", T_GENERIC, owner.compressed, fp, {"ws://a14.example"});
        CHECK_TEST_CONDITION(reg(reg_tx, H) ==
                             domain_registration_result::success);

        std::array<unsigned char, 32> xonly_a{};
        memcpy(xonly_a.data(), newowner_a.xonly.data(), 32);
        crypto::hash msg = domain_utils::compute_vns_transfer_message_hash("vt14..com", xonly_a);
        unsigned char sig64[64];
        CHECK_TEST_CONDITION(bip340::sign(owner.secret.data(),
                                          reinterpret_cast<const unsigned char*>(&msg), sig64));

        // Submit with newowner_b's xonly key instead
        std::vector<unsigned char> xonly_b_vec(newowner_b.xonly.begin(), newowner_b.xonly.end());
        std::vector<unsigned char> sig_vec(sig64, sig64 + 64);
        auto xfer_tx = make_tx(build_xfer_extra_raw("vt14..com", xonly_b_vec, sig_vec));
        CHECK_TEST_CONDITION(reg(xfer_tx, H + 1) ==
                             domain_registration_result::signature_invalid);
    }

    // ---- Test 15: malformed new-owner key length -> REJECT
    {
        auto owner = make_keypair(60);

        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint(
            "vt15..com", owner.compressed, T_GENERIC);
        auto reg_tx = make_reg_tx("vt15..com", T_GENERIC, owner.compressed, fp, {"ws://a15.example"});
        CHECK_TEST_CONDITION(reg(reg_tx, H) ==
                             domain_registration_result::success);

        std::vector<unsigned char> short_key(31, 0xAA);
        std::vector<unsigned char> sig_vec(64, 0x42);
        auto xfer_tx = make_tx(build_xfer_extra_raw("vt15..com", short_key, sig_vec));
        CHECK_TEST_CONDITION(reg(xfer_tx, H + 1) ==
                             domain_registration_result::invalid_key);
    }

    // ---- Test 16: DOMAIN_REG built by the production wallet-rpc builder ----
    {
        auto owner = make_keypair(70);
        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint(
            "vt16..com", owner.compressed, T_GENERIC);

        // This is the exact call site wallet_rpc_server::on_register_domain uses.
        std::array<std::string, 3> relays = {"ws://a16.example", "", ""};
        std::vector<uint8_t> extra = domain_utils::build_registration_extra(
            "vt16..com", T_GENERIC, owner.compressed, fp, relays);
        CHECK_TEST_CONDITION(!extra.empty());

        std::vector<std::pair<uint8_t, std::vector<uint8_t>>> tlvs;
        std::string err;
        CHECK_TEST_CONDITION(parse_extra_tlvs(extra, "DOMAIN_REG", tlvs, err));
        // Required tags: 0x01 domain, 0x02 tier, 0x03 key, 0x04 fingerprint, 0x06..0x08 relays
        bool have_domain = false, have_tier = false, have_key = false,
             have_fp = false, have_relay0 = false;
        for (const auto& kv : tlvs) {
            if (kv.first == 0x01) { have_domain = (std::string(kv.second.begin(), kv.second.end()) == "vt16..com"); }
            if (kv.first == 0x02) { have_tier = (kv.second.size() == 1 && kv.second[0] == T_GENERIC); }
            if (kv.first == 0x03) { have_key = (kv.second.size() == 33); }
            if (kv.first == 0x04) { have_fp = (kv.second.size() == 32); }
            if (kv.first == 0x06) { have_relay0 = (std::string(kv.second.begin(), kv.second.end()) == "ws://a16.example"); }
        }
        CHECK_TEST_CONDITION(have_domain);
        CHECK_TEST_CONDITION(have_tier);
        CHECK_TEST_CONDITION(have_key);
        CHECK_TEST_CONDITION(have_fp);
        CHECK_TEST_CONDITION(have_relay0);

        cryptonote::transaction tx = make_tx(extra);
        CHECK_TEST_CONDITION(reg(tx, H) == domain_registration_result::success);
    }

    // ---- Test 17: DOMAIN_XFER built by the production wallet-rpc builder ----
    {
        auto owner = make_keypair(80);
        auto newowner = make_keypair(81);

        crypto::hash fp = domain_utils::compute_vns_registration_fingerprint(
            "vt17..com", owner.compressed, T_GENERIC);
        {
            cryptonote::transaction reg_tx = make_reg_tx(
                "vt17..com", T_GENERIC, owner.compressed, fp, {"ws://a17.example"});
            CHECK_TEST_CONDITION(reg(reg_tx, H) == domain_registration_result::success);
        }

        // Sign the ownership message exactly as the browser wallet service would.
        std::array<unsigned char, 32> xonly_dest{};
        memcpy(xonly_dest.data(), newowner.xonly.data(), 32);
        crypto::hash msg = domain_utils::compute_vns_transfer_message_hash("vt17..com", xonly_dest);
        unsigned char sig64[64];
        CHECK_TEST_CONDITION(bip340::sign(owner.secret.data(),
                                          reinterpret_cast<const unsigned char*>(&msg), sig64));
        std::array<unsigned char, 64> sig_array;
        std::copy(sig64, sig64 + 64, sig_array.begin());

        crypto::public_key new_owner_pub{};
        memcpy(new_owner_pub.data, xonly_dest.data(), 32);

        // This is the exact call site wallet_rpc_server::on_transfer_domain uses.
        std::vector<uint8_t> extra = domain_utils::build_transfer_extra(
            "vt17..com", new_owner_pub, sig_array);
        CHECK_TEST_CONDITION(!extra.empty());

        std::vector<std::pair<uint8_t, std::vector<uint8_t>>> tlvs;
        std::string err;
        CHECK_TEST_CONDITION(parse_extra_tlvs(extra, "DOMAIN_XFER", tlvs, err));
        bool have_domain = false, have_key = false, have_sig = false;
        size_t tag_count = 0;
        for (const auto& kv : tlvs) {
            ++tag_count;
            if (kv.first == 0x01) { have_domain = (std::string(kv.second.begin(), kv.second.end()) == "vt17..com"); }
            if (kv.first == 0x05) { have_key = (kv.second.size() == 32); }
            if (kv.first == 0x04) { have_sig = (kv.second.size() == 64); }
        }
        CHECK_TEST_CONDITION(tag_count == 3);   // exactly domain, key, sig — nothing else
        CHECK_TEST_CONDITION(have_domain);
        CHECK_TEST_CONDITION(have_key);
        CHECK_TEST_CONDITION(have_sig);

        cryptonote::transaction xfer_tx = make_tx(extra);
        CHECK_TEST_CONDITION(reg(xfer_tx, H + 1) == domain_registration_result::success);

        // Tamper: flip one byte of the new-owner x-only key. Signature no longer matches.
        {
            std::vector<uint8_t> tampered = extra;
            // Find the 0x05 TLV inside the payload and flip its last data byte.
            // Payload layout: envelope(0x02, len), "DOMAIN_XFER"(11), then TLVs.
            size_t pos = 2 + 11;   // skip envelope tag + 1-byte len, then magic
            while (pos < tampered.size()) {
                uint8_t tag = tampered[pos];
                if (tag == 0x00) break;
                uint8_t len = tampered[pos + 1];
                if (tag == 0x05) { tampered[pos + 1 + len - 1] ^= 0x01; break; }
                pos += 2 + len;
            }
            cryptonote::transaction t_tx = make_tx(tampered);
            CHECK_TEST_CONDITION(reg(t_tx, H + 2) == domain_registration_result::signature_invalid);
        }
    }

    return true;
}