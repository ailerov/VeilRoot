// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// P2P Reset ceremony: three in-process runner instances, 3 old -> 5 new.
// Same message flow as production, different transport (local dispatch).

#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/rand.h>

#include "gtest/gtest.h"
#include "governance/dao_dkg.h"
#include "governance/dao_dkg_reset.h"
#include "governance/dao_threshold.h"

using namespace cryptonote;
using namespace cryptonote::dao;

namespace {

struct ReshareHub
{
    std::map<std::string, dkg_p2p_reshare_runner*> by_pk;

    dkg_p2p_reshare_callbacks callbacks_for(
        const crypto::public_key& self_pk)
    {
        dkg_p2p_reshare_callbacks cb;
        cb.send_to = [this, self_pk](
            const crypto::public_key& to, const std::string& payload) -> bool
        {
            std::string key(reinterpret_cast<const char*>(to.data), 32);
            auto it = by_pk.find(key);
            if (it == by_pk.end()) return false;
            dkg_msg m;
            if (!m.deserialize(std::vector<uint8_t>(payload.begin(), payload.end())))
                return false;
            it->second->on_message(m);
            return true;
        };
        cb.broadcast = [this, self_pk](const std::string& payload) {
            dkg_msg m;
            if (!m.deserialize(std::vector<uint8_t>(payload.begin(), payload.end())))
                return;
            for (auto& kv : by_pk) {
                if (kv.first == std::string(reinterpret_cast<const char*>(self_pk.data), 32))
                    continue;
                kv.second->on_message(m);
            }
        };
        return cb;
    }
};

std::vector<crypto::public_key> reset_member_ids(uint32_t n)
{
    std::vector<crypto::public_key> ids;
    for (uint32_t i = 0; i < n; ++i) {
        crypto::public_key pk{};
        for (int k = 0; k < 32; ++k)
            pk.data[k] = static_cast<uint8_t>((i + 1) * 31 + k);
        ids.push_back(pk);
    }
    return ids;
}

void make_signed_share(int64_t x, std::vector<uint8_t>& v)
{
    BIGNUM* b = BN_new();
    BN_set_word(b, (BN_ULONG)(x >= 0 ? x : -x));
    v.assign(1 + BN_num_bytes(b), 0);
    v[0] = (x < 0) ? 1 : 0;
    BN_bn2bin(b, v.data() + 1);
    BN_free(b);
}

void decode_vss(const dao_tally_key_record& rec, dao_vss_group& grp)
{
    grp.P       = BN_bin2bn(rec.vss_P.data(), (int)rec.vss_P.size(), nullptr);
    grp.P_prime = BN_bin2bn(rec.vss_P_prime.data(), (int)rec.vss_P_prime.size(), nullptr);
    grp.g       = BN_bin2bn(rec.vss_g.data(), (int)rec.vss_g.size(), nullptr);
    grp.h       = BN_bin2bn(rec.vss_h.data(), (int)rec.vss_h.size(), nullptr);
}

} // namespace

TEST(dao_dkg_reset_p2p, three_to_five_ceremony)
{
    // ---- Public key record with a small VSS group. ----
    dao_tally_key_record krec{};
    {
        BIGNUM* P  = BN_new(); BN_set_word(P, 47);
        BIGNUM* Pp = BN_new(); BN_set_word(Pp, 23);
        BIGNUM* g  = BN_new(); BN_set_word(g, 4);
        BIGNUM* h  = BN_new(); BN_set_word(h, 16);

        auto vec = [](const BIGNUM* b) {
            std::vector<uint8_t> v(BN_num_bytes(b));
            BN_bn2bin(b, v.data());
            return v;
        };
        krec.vss_P = vec(P);
        krec.vss_P_prime = vec(Pp);
        krec.vss_g = vec(g);
        krec.vss_h = vec(h);
        BN_free(P); BN_free(Pp); BN_free(g); BN_free(h);
    }

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* N  = BN_new(); BN_set_bit(N, 127); BN_set_bit(N, 0); BN_set_bit(N, 63);
    BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
    BIGNUM* V_K = BN_new(); BN_set_word(V_K, 12345);
    {
        std::vector<uint8_t> v(512, 0);
        BN_bn2binpad(V_K, v.data(), 512);
        krec.V = v;
    }

    // Old committee: 3 members, secret 42, shares f(1..3) = 142,242,342.
    // V_K_i = V_K^(Delta*SK_i) mod N^2 for each.
    std::vector<int64_t> SKs = {142, 242, 342};
    std::vector<std::vector<uint8_t>> old_shares(3);
    krec.V_K_i.assign(3, {});
    for (int i = 0; i < 3; ++i) {
        make_signed_share(SKs[i], old_shares[i]);
        BIGNUM* e = BN_new(); BN_set_word(e, (BN_ULONG)SKs[i]);
        BN_mul(e, e, dao_dkg_delta(), ctx);
        BIGNUM* r = BN_new(); BN_mod_exp(r, V_K, e, N2, ctx);
        krec.V_K_i[i].assign(512, 0);
        BN_bn2binpad(r, krec.V_K_i[i].data(), 512);
        BN_free(e); BN_free(r);
    }

    auto old_ids = reset_member_ids(3);
    auto new_ids = reset_member_ids(5);
    krec.committee_members.clear();
    for (auto& pk : old_ids)
        krec.committee_members.push_back(std::vector<uint8_t>(pk.data, pk.data + 32));

    dao_vss_group vss; decode_vss(krec, vss);

    dao_dkg_reset_config cfg{};
    cfg.old_threshold = 3;
    cfg.new_threshold = 3;
    cfg.old_members = old_ids;
    cfg.new_members = new_ids;
    cfg.reset_participant_ids = {1, 2, 3};
    for (size_t i = 0; i < sizeof(cfg.key_id.data); ++i) cfg.key_id.data[i] = (uint8_t)i;

    // Each old member and new member needs a distinct keypair. Old and
    // new committees overlap here in the test, so generate unique
    // keypairs for all 8 slots.
    std::vector<crypto::public_key> pks(8);
    std::vector<crypto::secret_key> sks(8);
    for (int i = 0; i < 8; ++i) crypto::generate_keys(pks[i], sks[i]);

    // Old committee (uses pks[0..2]) drives the Reset. New committee
    // (pks[3..7]) collects. They are separate runners.
    // However cfg.old_members must contain the OLD identities so the
    // new members can find the sender's public key by index; and
    // cfg.new_members must contain the NEW identities.
    for (int i = 0; i < 3; ++i) cfg.old_members[i] = pks[i];
    for (int i = 0; i < 5; ++i) cfg.new_members[i] = pks[3 + i];

    ReshareHub hub;

    std::vector<std::unique_ptr<dkg_p2p_reshare_runner>> old_runners;
    std::vector<std::unique_ptr<dkg_p2p_reshare_runner>> new_runners;

    for (int i = 0; i < 3; ++i) {
        // old member i runs with its own identity
        auto cb = hub.callbacks_for(pks[i]);
        auto r = std::make_unique<dkg_p2p_reshare_runner>(
            cfg, [&]() -> dao_tally_public_key_record {
                dao_tally_public_key_record p{};
                p.V = krec.V;
                p.vss_P = krec.vss_P;
                p.vss_P_prime = krec.vss_P_prime;
                p.vss_g = krec.vss_g;
                p.vss_h = krec.vss_h;
                return p;
            }(),
            vss, N2, pks[i], sks[i], old_shares[i], krec.V_K_i, cb);
        hub.by_pk.emplace(std::string(reinterpret_cast<const char*>(pks[i].data), 32),
                          r.get());
        old_runners.push_back(std::move(r));
    }

    for (int i = 0; i < 5; ++i) {
        auto cb = hub.callbacks_for(pks[3 + i]);
        std::vector<uint8_t> no_old_share;
        auto r = std::make_unique<dkg_p2p_reshare_runner>(
            cfg, [&]() -> dao_tally_public_key_record {
                dao_tally_public_key_record p{};
                p.V = krec.V;
                p.vss_P = krec.vss_P;
                p.vss_P_prime = krec.vss_P_prime;
                p.vss_g = krec.vss_g;
                p.vss_h = krec.vss_h;
                return p;
            }(),
            vss, N2, pks[3 + i], sks[3 + i], no_old_share, krec.V_K_i, cb);
        hub.by_pk.emplace(std::string(reinterpret_cast<const char*>(pks[3 + i].data), 32),
                          r.get());
        new_runners.push_back(std::move(r));
    }

    for (auto& r : old_runners) r->start();
    for (auto& r : new_runners) r->start();

    // Give the broadcast + private sends a moment. on_message is called
    // synchronously by the hub, so ordering is deterministic: each
    // old runner broadcasts its commit before sending subshares, and
    // it iterates new_members in order. Handle order is therefore
    // fine. Old members finish first; then we wait on new members.
    std::vector<dao_dkg_reset_result> old_res(3);
    for (int i = 0; i < 3; ++i)
        ASSERT_TRUE(old_runners[i]->wait(old_res[i], 30));

    std::vector<dao_dkg_reset_result> new_res(5);
    for (int i = 0; i < 5; ++i)
        ASSERT_TRUE(new_runners[i]->wait(new_res[i], 30))
            << "new shareholder " << i << " did not complete";

    // Reconstruct SK(0) from 3 new shares via integer Lagrange.
    std::vector<BIGNUM*> new_bns(3);
    for (int i = 0; i < 3; ++i) {
        const auto& v = new_res[i].local_share;
        ASSERT_FALSE(v.empty());
        BIGNUM* b = BN_bin2bn(v.data() + 1, (int)(v.size() - 1), nullptr);
        if (v[0]) BN_set_negative(b, 1);
        new_bns[i] = b;
    }
    BIGNUM* acc = BN_new(); BN_zero(acc);
    std::vector<uint32_t> sub = {1, 2, 3};
    for (uint32_t i = 1; i <= 3; ++i) {
        BIGNUM* mu = BN_new();
        ASSERT_TRUE(dao_dkg_lagrange_mu(sub, i, mu));
        BIGNUM* t = BN_new(); BN_mul(t, mu, new_bns[i-1], ctx);
        BN_add(acc, acc, t);
        BN_free(t); BN_free(mu);
    }
    BIGNUM* rem = BN_new(); BIGNUM* q = BN_new();
    ASSERT_TRUE(BN_div(q, rem, acc, dao_dkg_delta(), ctx) == 1);
    ASSERT_TRUE(BN_is_zero(rem)) << "not divisible by Delta";
    EXPECT_EQ(BN_get_word(q), 42u);

    for (auto* b : new_bns) BN_free(b);
    BN_free(rem); BN_free(q); BN_free(acc);
    BN_free(V_K); BN_free(N2); BN_free(N);
    BN_CTX_free(ctx);
}

// -------------------------------------------------------------------
// Partial old availability: 3 old shareholders, threshold 2, only
// members {1, 2} run. Member 3 is offline. The manifest selects {1,2}
// and the ceremony completes.
// -------------------------------------------------------------------
TEST(dao_dkg_reset_p2p, partial_old_availability)
{
    dao_tally_key_record krec{};
    {
        BIGNUM* P  = BN_new(); BN_set_word(P, 47);
        BIGNUM* Pp = BN_new(); BN_set_word(Pp, 23);
        BIGNUM* g  = BN_new(); BN_set_word(g, 4);
        BIGNUM* h  = BN_new(); BN_set_word(h, 16);
        auto vec = [](const BIGNUM* b) {
            std::vector<uint8_t> v(BN_num_bytes(b));
            BN_bn2bin(b, v.data());
            return v;
        };
        krec.vss_P = vec(P);
        krec.vss_P_prime = vec(Pp);
        krec.vss_g = vec(g);
        krec.vss_h = vec(h);
        BN_free(P); BN_free(Pp); BN_free(g); BN_free(h);
    }

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* N  = BN_new(); BN_set_bit(N, 127); BN_set_bit(N, 0); BN_set_bit(N, 63);
    BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
    BIGNUM* V_K = BN_new(); BN_set_word(V_K, 12345);
    {
        std::vector<uint8_t> v(512, 0);
        BN_bn2binpad(V_K, v.data(), 512);
        krec.V = v;
    }

    std::vector<int64_t> SKs = {142, 242, 342};
    std::vector<std::vector<uint8_t>> old_shares(3);
    krec.V_K_i.assign(3, {});
    for (int i = 0; i < 3; ++i) {
        make_signed_share(SKs[i], old_shares[i]);
        BIGNUM* e = BN_new(); BN_set_word(e, (BN_ULONG)SKs[i]);
        BN_mul(e, e, dao_dkg_delta(), ctx);
        BIGNUM* r = BN_new(); BN_mod_exp(r, V_K, e, N2, ctx);
        krec.V_K_i[i].assign(512, 0);
        BN_bn2binpad(r, krec.V_K_i[i].data(), 512);
        BN_free(e); BN_free(r);
    }

    auto old_ids = reset_member_ids(3);
    auto new_ids = reset_member_ids(5);

    dao_vss_group vss; decode_vss(krec, vss);

    dao_dkg_reset_config cfg{};
    cfg.old_threshold = 2;
    cfg.new_threshold = 3;
    cfg.old_members = old_ids;
    cfg.new_members = new_ids;

    std::vector<crypto::public_key> pks(8);
    std::vector<crypto::secret_key> sks(8);
    for (int i = 0; i < 8; ++i) crypto::generate_keys(pks[i], sks[i]);
    for (int i = 0; i < 3; ++i) cfg.old_members[i] = pks[i];
    for (int i = 0; i < 5; ++i) cfg.new_members[i] = pks[3 + i];

    ReshareHub hub;
    std::vector<std::unique_ptr<dkg_p2p_reshare_runner>> old_runners;
    std::vector<std::unique_ptr<dkg_p2p_reshare_runner>> new_runners;

    // Start members 1 and 2 only. Member 3 is offline (no runner).
    for (int i = 0; i < 2; ++i) {
        auto cb = hub.callbacks_for(pks[i]);
        auto pk_rec = [&]() {
            dao_tally_public_key_record p{};
            p.V = krec.V;
            p.vss_P = krec.vss_P;
            p.vss_P_prime = krec.vss_P_prime;
            p.vss_g = krec.vss_g;
            p.vss_h = krec.vss_h;
            return p;
        }();
        auto r = std::make_unique<dkg_p2p_reshare_runner>(
            cfg, pk_rec, vss, N2, pks[i], sks[i], old_shares[i],
            krec.V_K_i, cb);
        hub.by_pk.emplace(std::string(reinterpret_cast<const char*>(pks[i].data), 32),
                          r.get());
        old_runners.push_back(std::move(r));
    }

    for (int i = 0; i < 5; ++i) {
        auto cb = hub.callbacks_for(pks[3 + i]);
        std::vector<uint8_t> no_old_share;
        auto pk_rec = [&]() {
            dao_tally_public_key_record p{};
            p.V = krec.V;
            p.vss_P = krec.vss_P;
            p.vss_P_prime = krec.vss_P_prime;
            p.vss_g = krec.vss_g;
            p.vss_h = krec.vss_h;
            return p;
        }();
        auto r = std::make_unique<dkg_p2p_reshare_runner>(
            cfg, pk_rec, vss, N2, pks[3 + i], sks[3 + i], no_old_share,
            krec.V_K_i, cb);
        hub.by_pk.emplace(std::string(reinterpret_cast<const char*>(pks[3 + i].data), 32),
                          r.get());
        new_runners.push_back(std::move(r));
    }

    for (auto& r : old_runners) r->start();
    for (auto& r : new_runners) r->start();

    std::vector<dao_dkg_reset_result> old_res(2);
    for (int i = 0; i < 2; ++i)
        ASSERT_TRUE(old_runners[i]->wait(old_res[i], 30));

    std::vector<dao_dkg_reset_result> new_res(5);
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(new_runners[i]->wait(new_res[i], 30))
            << "new shareholder " << i << " did not complete";
        ASSERT_EQ(new_res[i].reset_participant_ids.size(), 2u);
    }
    for (auto& r : new_runners) r->stop();
    for (auto& r : old_runners) r->stop();

    // Reconstruct SK(0) from 3 new shares.
    std::vector<BIGNUM*> new_bns(3);
    for (int i = 0; i < 3; ++i) {
        const auto& v = new_res[i].local_share;
        ASSERT_FALSE(v.empty());
        BIGNUM* b = BN_bin2bn(v.data() + 1, (int)(v.size() - 1), nullptr);
        if (v[0]) BN_set_negative(b, 1);
        new_bns[i] = b;
    }
    BIGNUM* acc = BN_new(); BN_zero(acc);
    std::vector<uint32_t> sub = {1, 2, 3};
    for (uint32_t i = 1; i <= 3; ++i) {
        BIGNUM* mu = BN_new();
        ASSERT_TRUE(dao_dkg_lagrange_mu(sub, i, mu));
        BIGNUM* tt = BN_new(); BN_mul(tt, mu, new_bns[i-1], ctx);
        BN_add(acc, acc, tt);
        BN_free(tt); BN_free(mu);
    }
    BIGNUM* rem = BN_new(); BIGNUM* q = BN_new();
    ASSERT_TRUE(BN_div(q, rem, acc, dao_dkg_delta(), ctx) == 1);
    ASSERT_TRUE(BN_is_zero(rem));
    EXPECT_EQ(BN_get_word(q), 42u);

    for (auto* b : new_bns) BN_free(b);
    BN_free(rem); BN_free(q); BN_free(acc);
    BN_free(V_K); BN_free(N2); BN_free(N);
    BN_CTX_free(ctx);
}
