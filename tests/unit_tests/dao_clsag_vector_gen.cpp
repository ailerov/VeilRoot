// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reference generator for the DAO V2 weighted CLSAG fixed vector.
//
// This file implements the DAO V2 CLSAG equations by hand, using only
// the primitive operations exposed by rct:: and crypto-ops. It does NOT
// call CLSAG_Gen and it does NOT call into dao_clsag.cpp. Its output is
// meant to be captured once and hard-coded into the DAO CLSAG unit test.
//
// The test is prefixed DISABLED_ so it does not run in the default suite.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctOps.h"      // pulls rctTypes.h, which includes crypto-ops.h inside extern "C"
#include "ringct/rctTypes.h"
#include "cryptonote_config.h"

using namespace rct;

namespace {

constexpr const char* DAO_HASH_DOMAIN = "VeilRoot-DAO-VOTE-V2";     // 20 bytes
constexpr const char* MSG_DOMAIN      = "VeilRoot-DAO-CLSAG-V2-MSG"; // 25 bytes

std::string hex(const unsigned char* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(H[p[i] >> 4]);
        s.push_back(H[p[i] & 0xf]);
    }
    return s;
}

std::string K(const rct::key& k) { return hex(k.bytes, 32); }

rct::key mk_scalar(uint8_t s) {
    rct::key k;
    std::memset(k.bytes, 0, 32);
    k.bytes[0]  = s;
    k.bytes[31] = static_cast<uint8_t>(s ^ 0xA5);
    sc_reduce32(k.bytes);
    return k;
}

rct::key mk_point(uint8_t s) {
    rct::key k;
    scalarmultBase(k, mk_scalar(s));
    return k;
}

// H_vote(P, proposal_id) per spec §14, matching the Monero
// hash_to_p3 pipeline: cn_fast_hash -> ge_fromfe_frombytes_vartime
// -> ge_mul8 -> compress.
void dao_hash_to_p3(ge_p3& out, const rct::key& P, const rct::key& proposal_id) {
    unsigned char buf[20 + 32 + 32];
    std::memcpy(buf,     DAO_HASH_DOMAIN, 20);
    std::memcpy(buf + 20, proposal_id.bytes, 32);
    std::memcpy(buf + 52, P.bytes, 32);
    rct::key h;
    cn_fast_hash(h, buf, sizeof(buf));
    ge_p2 p2;
    ge_fromfe_frombytes_vartime(&p2, h.bytes);
    ge_p1p1 p1p1;
    ge_mul8(&p1p1, &p2);
    ge_p1p1_to_p3(&out, &p1p1);
}

rct::key dao_hash_key(const rct::key& P, const rct::key& proposal_id) {
    ge_p3 p3;
    dao_hash_to_p3(p3, P, proposal_id);
    rct::key out;
    ge_p3_tobytes(out.bytes, &p3);
    return out;
}

uint64_t floor_log2_u64(uint64_t n) {
    uint64_t r = 0;
    while (n > 1) { n >>= 1; ++r; }
    return r;
}

uint8_t age_factor(uint64_t output_height, uint64_t vote_height) {
    if (vote_height < output_height) return 0;
    uint64_t age_days = (vote_height - output_height) / 720;
    if (age_days > 7300) age_days = 7300;
    return static_cast<uint8_t>(floor_log2_u64(age_days + 1));
}

rct::key build_message(
    const rct::key& proposal_id,
    uint64_t proposal_submission_height,
    uint64_t vote_height,
    uint64_t tally_key_epoch,
    const std::vector<uint64_t>& out_idx,
    const std::vector<uint64_t>& out_h,
    const std::vector<rct::key>& P,
    const std::vector<rct::key>& C,
    const std::vector<uint8_t>& f,
    const rct::key& N,
    const rct::key& V)
{
    std::vector<uint8_t> ring;
    uint32_t n = static_cast<uint32_t>(P.size());
    for (int i = 0; i < 4; ++i) ring.push_back((n >> (8*i)) & 0xff);
    for (size_t i = 0; i < P.size(); ++i) {
        for (int j = 0; j < 8; ++j) ring.push_back((out_idx[i] >> (8*j)) & 0xff);
        for (int j = 0; j < 8; ++j) ring.push_back((out_h[i]   >> (8*j)) & 0xff);
        ring.insert(ring.end(), P[i].bytes, P[i].bytes + 32);
        ring.insert(ring.end(), C[i].bytes, C[i].bytes + 32);
        ring.push_back(f[i]);
    }
    rct::key ring_digest;
    cn_fast_hash(ring_digest, ring.data(), ring.size());

    std::vector<uint8_t> m;
    m.insert(m.end(), MSG_DOMAIN, MSG_DOMAIN + 25);
    m.push_back(2);
    m.insert(m.end(), proposal_id.bytes, proposal_id.bytes + 32);
    for (int j = 0; j < 8; ++j) m.push_back((proposal_submission_height >> (8*j)) & 0xff);
    for (int j = 0; j < 8; ++j) m.push_back((vote_height >> (8*j)) & 0xff);
    for (int j = 0; j < 8; ++j) m.push_back((tally_key_epoch >> (8*j)) & 0xff);
    m.insert(m.end(), ring_digest.bytes, ring_digest.bytes + 32);
    m.insert(m.end(), N.bytes, N.bytes + 32);
    m.insert(m.end(), V.bytes, V.bytes + 32);

    rct::key out;
    cn_fast_hash(out, m.data(), m.size());
    return out;
}

// ---------------------------------------------------------------------------

TEST(dao_clsag_vector_gen, DISABLED_print_reference_vector)
{
    const size_t n = 4;
    const size_t l = 2;

    const uint64_t proposal_submission_height = 50000;
    const uint64_t vote_height                = 51000;
    const uint64_t tally_key_epoch            = 1;

    rct::key proposal_id;
    std::memset(proposal_id.bytes, 0x33, 32);

    std::vector<uint64_t> out_idx = {1000, 2000, 3000, 4000};
    std::vector<uint64_t> out_h   = {40000, 30000, 20000, 10000};

    std::vector<rct::key> P(n), mask(n), amount(n), C(n), Q(n);
    std::vector<uint8_t>  f(n);

    for (size_t i = 0; i < n; ++i) {
        P[i]      = mk_point(0x10 + static_cast<uint8_t>(i));
        mask[i]   = mk_scalar(0x20 + static_cast<uint8_t>(i));
        amount[i] = mk_scalar(0x30 + static_cast<uint8_t>(i));
        rct::key aH, mG;
        scalarmultKey(aH, rct::H, amount[i]);
        scalarmultBase(mG, mask[i]);
        addKeys(C[i], aH, mG);
        f[i] = age_factor(out_h[i], vote_height);
    }

    for (size_t i = 0; i < n; ++i) {
        if (f[i] == 0) {
            identity(Q[i]);
        } else {
            rct::key s_f;
            std::memset(s_f.bytes, 0, 32);
            s_f.bytes[0] = f[i];
            sc_reduce32(s_f.bytes);
            scalarmultKey(Q[i], C[i], s_f);
        }
    }

    rct::key x_l   = mk_scalar(0x10 + static_cast<uint8_t>(l));
    rct::key rho_l = mk_scalar(0x40);
    rct::key a_    = mk_scalar(0x50);

    rct::key rho_G;
    scalarmultBase(rho_G, rho_l);
    rct::key V;
    addKeys(V, Q[l], rho_G);

    std::vector<rct::key> C_prime(n);
    for (size_t i = 0; i < n; ++i)
        subKeys(C_prime[i], Q[i], V);

    rct::key z;
    sc_0(z.bytes);
    sc_sub(z.bytes, z.bytes, rho_l.bytes);

    rct::key H_l = dao_hash_key(P[l], proposal_id);

    rct::key N;
    scalarmultKey(N, H_l, x_l);

    rct::key D_full;
    scalarmultKey(D_full, H_l, z);

    rct::key D_stored;
    scalarmultKey(D_stored, D_full, INV_EIGHT);

    rct::key m = build_message(
        proposal_id, proposal_submission_height, vote_height,
        tally_key_epoch, out_idx, out_h, P, C, f, N, V);

    std::vector<rct::key> mu_P_to_hash(2*n + 4);
    std::vector<rct::key> mu_C_to_hash(2*n + 4);
    sc_0(mu_P_to_hash[0].bytes);
    std::memcpy(mu_P_to_hash[0].bytes, config::HASH_KEY_CLSAG_AGG_0,
                sizeof(config::HASH_KEY_CLSAG_AGG_0) - 1);
    sc_0(mu_C_to_hash[0].bytes);
    std::memcpy(mu_C_to_hash[0].bytes, config::HASH_KEY_CLSAG_AGG_1,
                sizeof(config::HASH_KEY_CLSAG_AGG_1) - 1);
    for (size_t i = 0; i < n; ++i) {
        mu_P_to_hash[i + 1]     = P[i];
        mu_C_to_hash[i + 1]     = P[i];
        mu_P_to_hash[i + n + 1] = Q[i];
        mu_C_to_hash[i + n + 1] = Q[i];
    }
    mu_P_to_hash[2*n + 1] = N;
    mu_P_to_hash[2*n + 2] = D_stored;
    mu_P_to_hash[2*n + 3] = V;
    mu_C_to_hash[2*n + 1] = N;
    mu_C_to_hash[2*n + 2] = D_stored;
    mu_C_to_hash[2*n + 3] = V;

    rct::key mu_P = hash_to_scalar(mu_P_to_hash);
    rct::key mu_C = hash_to_scalar(mu_C_to_hash);

    rct::key aG, aH;
    scalarmultBase(aG, a_);
    scalarmultKey(aH, H_l, a_);

    std::vector<rct::key> c_to_hash(2*n + 5);
    sc_0(c_to_hash[0].bytes);
    std::memcpy(c_to_hash[0].bytes, config::HASH_KEY_CLSAG_ROUND,
                sizeof(config::HASH_KEY_CLSAG_ROUND) - 1);
    for (size_t i = 0; i < n; ++i) {
        c_to_hash[i + 1]     = P[i];
        c_to_hash[i + n + 1] = Q[i];
    }
    c_to_hash[2*n + 1] = V;
    c_to_hash[2*n + 2] = m;
    c_to_hash[2*n + 3] = aG;
    c_to_hash[2*n + 4] = aH;

    rct::key c = hash_to_scalar(c_to_hash);

    std::vector<rct::key> s(n);
    rct::key c1;
    sc_0(c1.bytes);

    size_t i = (l + 1) % n;
    if (i == 0) c1 = c;

    while (i != l) {
        s[i] = mk_scalar(0x60 + static_cast<uint8_t>(i));

        rct::key c_p, c_c;
        sc_mul(c_p.bytes, mu_P.bytes, c.bytes);
        sc_mul(c_c.bytes, mu_C.bytes, c.bytes);

        geDsmp P_pre, C_pre;
        precomp(P_pre.k, P[i]);
        precomp(C_pre.k, C_prime[i]);
        rct::key L;
        addKeys_aGbBcC(L, s[i], c_p, P_pre.k, c_c, C_pre.k);

        ge_p3 H_i_p3;
        dao_hash_to_p3(H_i_p3, P[i], proposal_id);
        geDsmp H_pre, I_pre, D_pre;
        ge_dsm_precomp(H_pre.k, &H_i_p3);
        precomp(I_pre.k, N);
        precomp(D_pre.k, D_full);
        rct::key R;
        addKeys_aAbBcC(R, s[i], H_pre.k, c_p, I_pre.k, c_c, D_pre.k);

        c_to_hash[2*n + 3] = L;
        c_to_hash[2*n + 4] = R;
        c = hash_to_scalar(c_to_hash);

        i = (i + 1) % n;
        if (i == 0) c1 = c;
    }

    rct::key s_l;
    {
        rct::key mu_P_x, sum;
        sc_mul(mu_P_x.bytes, mu_P.bytes, x_l.bytes);
        sc_muladd(sum.bytes, mu_C.bytes, z.bytes, mu_P_x.bytes);
        sc_mulsub(s_l.bytes, c.bytes, sum.bytes, a_.bytes);
    }
    s[l] = s_l;

    // Print the vector.
    std::cout << "\n=== DAO_CLSAG_VECTOR BEGIN ===\n";
    std::cout << "proposal_id                  = " << K(proposal_id) << "\n";
    std::cout << "proposal_submission_height   = " << proposal_submission_height << "\n";
    std::cout << "vote_height                  = " << vote_height << "\n";
    std::cout << "tally_key_epoch              = " << tally_key_epoch << "\n";
    std::cout << "n                            = " << n << "\n";
    std::cout << "l                            = " << l << "\n";
    for (size_t k = 0; k < n; ++k)
        std::cout << "output_index[" << k << "]            = " << out_idx[k] << "\n";
    for (size_t k = 0; k < n; ++k)
        std::cout << "output_height[" << k << "]           = " << out_h[k] << "\n";
    for (size_t k = 0; k < n; ++k)
        std::cout << "age_factor[" << k << "]              = "
                  << static_cast<int>(f[k]) << "\n";
    for (size_t k = 0; k < n; ++k)
        std::cout << "P[" << k << "]                        = " << K(P[k]) << "\n";
    for (size_t k = 0; k < n; ++k)
        std::cout << "C[" << k << "]                        = " << K(C[k]) << "\n";
    for (size_t k = 0; k < n; ++k)
        std::cout << "Q[" << k << "]                        = " << K(Q[k]) << "\n";
    std::cout << "x_l                          = " << K(x_l)   << "\n";
    std::cout << "rho_l                        = " << K(rho_l) << "\n";
    std::cout << "V                            = " << K(V)     << "\n";
    std::cout << "N                            = " << K(N)     << "\n";
    std::cout << "D_stored                     = " << K(D_stored) << "\n";
    std::cout << "mu_P                         = " << K(mu_P)  << "\n";
    std::cout << "mu_C                         = " << K(mu_C)  << "\n";
    std::cout << "m                            = " << K(m)     << "\n";
    std::cout << "c1                           = " << K(c1)    << "\n";
    for (size_t k = 0; k < n; ++k)
        std::cout << "s[" << k << "]                        = " << K(s[k]) << "\n";
    std::cout << "=== DAO_CLSAG_VECTOR END ===\n\n";

    // Self-verify by walking the ring with the produced signature.
    {
        rct::key cwalk = c1;
        for (size_t k = 0; k < n; ++k) {
            rct::key cp, cc;
            sc_mul(cp.bytes, mu_P.bytes, cwalk.bytes);
            sc_mul(cc.bytes, mu_C.bytes, cwalk.bytes);

            geDsmp P_pre, C_pre;
            precomp(P_pre.k, P[k]);
            precomp(C_pre.k, C_prime[k]);
            rct::key L;
            addKeys_aGbBcC(L, s[k], cp, P_pre.k, cc, C_pre.k);

            ge_p3 H_k_p3;
            dao_hash_to_p3(H_k_p3, P[k], proposal_id);
            geDsmp H_pre, I_pre, D_pre;
            ge_dsm_precomp(H_pre.k, &H_k_p3);
            precomp(I_pre.k, N);
            precomp(D_pre.k, D_full);
            rct::key R;
            addKeys_aAbBcC(R, s[k], H_pre.k, cp, I_pre.k, cc, D_pre.k);

            c_to_hash[2*n + 3] = L;
            c_to_hash[2*n + 4] = R;
            cwalk = hash_to_scalar(c_to_hash);
        }
        std::cout << "[self-verify] closing c matches c1: "
                  << (cwalk == c1 ? "YES" : "NO") << "\n";
    }
}

} // namespace