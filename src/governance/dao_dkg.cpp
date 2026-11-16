// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_dkg.h"
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <deque>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>

#include "governance/dao_dkg_transport.h"

#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "ringct/rctOps.h"

namespace cryptonote {
namespace dao {

// ====================================================================
// Internal helpers
// ====================================================================

uint32_t dao_dkg_required_vss_bits(uint32_t /*k_bits*/,
                                   uint32_t target_N_bits,
                                   uint32_t security_bits)
{
    // Conservative bound from §30:
    //   theta_max = 2 * n * Delta * K * (1 + K) * N_max^2
    // with K = 2^security_bits, N_max = 2^target_N_bits, Delta = 16!.
    //
    // log2(theta_max) ≈ 1 + log2(n) + log2(Delta) + 2*security_bits
    //                 + 2*target_N_bits
    //
    // n = 16 → log2(n) = 4
    // Delta = 16! → log2(Delta) ≈ 44.2
    //
    // P' > 2 * theta_max, so add 1 bit and 16 bits of margin.
    const uint64_t bits = 1ULL
                        + 4ULL
                        + 45ULL
                        + 2ULL * security_bits
                        + 2ULL * target_N_bits
                        + 1ULL
                        + 16ULL;
    return static_cast<uint32_t>(bits);
}

namespace {

struct CtxGuard {
    BN_CTX* ctx;
    CtxGuard() : ctx(BN_CTX_new()) {}
    ~CtxGuard() { if (ctx) BN_CTX_free(ctx); }
    CtxGuard(const CtxGuard&) = delete;
    CtxGuard& operator=(const CtxGuard&) = delete;
    bool ok() const { return ctx != nullptr; }
};

void push_u32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xff);
}

void push_u64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back((x >> (8 * i)) & 0xff);
}

bool pull_u32(const std::vector<uint8_t>& v, size_t& off, uint32_t& out)
{
    if (off + 4 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) out |= uint32_t(v[off++]) << (8 * i);
    return true;
}

bool pull_u64(const std::vector<uint8_t>& v, size_t& off, uint64_t& out)
{
    if (off + 8 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) out |= uint64_t(v[off++]) << (8 * i);
    return true;
}

bool push_bytes(std::vector<uint8_t>& v, const std::vector<uint8_t>& b)
{
    push_u32(v, static_cast<uint32_t>(b.size()));
    v.insert(v.end(), b.begin(), b.end());
    return true;
}

bool pull_bytes(const std::vector<uint8_t>& v, size_t& off, std::vector<uint8_t>& out)
{
    uint32_t n = 0;
    if (!pull_u32(v, off, n)) return false;
    if (off + n > v.size()) return false;
    out.assign(v.begin() + off, v.begin() + off + n);
    off += n;
    return true;
}

// Modular exponentiation with support for a signed exponent.
bool modexp_signed(const BIGNUM* base, const BIGNUM* exp, const BIGNUM* mod,
                   BIGNUM* out, BN_CTX* ctx)
{
    if (!BN_is_negative(exp)) {
        return BN_mod_exp(out, base, exp, mod, ctx) == 1;
    }
    BIGNUM* inv = BN_mod_inverse(nullptr, base, mod, ctx);
    if (!inv) return false;
    BIGNUM* pos = BN_dup(exp);
    if (!pos) { BN_free(inv); return false; }
    BN_set_negative(pos, 0);
    const bool ok = BN_mod_exp(out, inv, pos, mod, ctx) == 1;
    BN_free(inv);
    BN_free(pos);
    return ok;
}

// SHA-256 over four byte strings. Challenge for the Q_i proof.
bool challenge_hash(const std::vector<uint8_t>& a,
                    const std::vector<uint8_t>& b,
                    const std::vector<uint8_t>& c4,
                    const std::vector<uint8_t>& ci2,
                    BIGNUM* E_out)
{
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) return false;
    if (!a.empty())   SHA256_Update(&ctx, a.data(), a.size());
    if (!b.empty())   SHA256_Update(&ctx, b.data(), b.size());
    if (!c4.empty())  SHA256_Update(&ctx, c4.data(), c4.size());
    if (!ci2.empty()) SHA256_Update(&ctx, ci2.data(), ci2.size());
    unsigned char digest[32];
    if (!SHA256_Final(digest, &ctx)) return false;
    BN_bin2bn(digest, 32, E_out);
    return true;
}

// Canonical 32-byte big-endian encoding of a challenge scalar.
void E_to_bytes(const BIGNUM* E, std::vector<uint8_t>& out)
{
    out.assign(32, 0);
    BN_bn2binpad(E, out.data(), 32);
}

// Canonical V-commitment hash used both by the committer and by the
// driver's reveal verification. Binds party id and the big-endian
// bytes of r_i.
void compute_v_commit(uint32_t party_id,
                      const std::vector<uint8_t>& r_bytes,
                      std::vector<uint8_t>& digest_out)
{
    std::vector<uint8_t> buf;
    const char* dom = "DAO_DKG_V1";
    buf.insert(buf.end(), dom, dom + 10);
    for (int i = 0; i < 4; ++i) buf.push_back((party_id >> (8*i)) & 0xff);
    buf.insert(buf.end(), r_bytes.begin(), r_bytes.end());
    digest_out.assign(32, 0);
    SHA256(buf.data(), buf.size(), digest_out.data());
}

// Signed BIGNUM serialization: sign byte (0 = non-negative, 1 = negative)
// followed by big-endian magnitude. BN_bn2bin alone discards the sign,
// which silently corrupts any wire value that can be negative.
void bn_to_signed(const BIGNUM* b, std::vector<uint8_t>& out)
{
    out.clear();
    out.push_back(BN_is_negative(b) ? 1 : 0);
    const int n = BN_num_bytes(b);
    if (n > 0) {
        const size_t off = out.size();
        out.resize(off + n);
        BN_bn2bin(b, out.data() + off);
    }
}

BIGNUM* bn_from_signed(const std::vector<uint8_t>& in)
{
    if (in.empty()) return nullptr;
    const bool neg = in[0] != 0;
    BIGNUM* v = BN_bin2bn(in.data() + 1,
                          static_cast<int>(in.size() - 1), nullptr);
    if (!v) return nullptr;
    if (neg) BN_set_negative(v, 1);
    return v;
}

// Return (P-1)/2 for the VSS group. Caller owns the returned BIGNUM.
BIGNUM* vss_group_order(const dao_vss_group& g)
{
    BIGNUM* q = BN_new();
    BIGNUM* one = BN_new();
    BN_one(one);
    BN_sub(q, g.P, one);
    BN_rshift1(q, q);
    BN_free(one);
    return q;
}

// Verify that the loaded VSS group's subgroup order meets or exceeds
// the required bit count.
static bool dao_vss_group_meets_requirement(const dao_vss_group& grp,
                                            uint32_t required_order_bits)
{
    if (!grp.valid()) return false;

    BIGNUM* q = vss_group_order(grp);
    if (!q) return false;

    const bool ok =
        BN_num_bits(q) >= static_cast<int>(required_order_bits);

    BN_free(q);
    return ok;
}

// Serialize and deserialize a Q_i proof.
void push_u8(std::vector<uint8_t>& v, uint8_t b) { v.push_back(b); }

bool pull_u8(const std::vector<uint8_t>& v, size_t& off, uint8_t& b)
{
    if (off + 1 > v.size()) return false;
    b = v[off++];
    return true;
}

bool serialize_Q_proof(const dao_Q_proof& p, std::vector<uint8_t>& out)
{
    out.clear();
    push_u32(out, p.member_index);
    push_u32(out, static_cast<uint32_t>(p.reps.size()));
    for (const auto& r : p.reps) {
        push_bytes(out, r.A);
        push_bytes(out, r.B);
        push_u8(out, r.c);
        push_bytes(out, r.zx);
        push_bytes(out, r.zy);
    }
    return true;
}

bool deserialize_Q_proof(const std::vector<uint8_t>& in, dao_Q_proof& out)
{
    size_t off = 0;
    if (!pull_u32(in, off, out.member_index)) return false;
    uint32_t n = 0;
    if (!pull_u32(in, off, n)) return false;
    if (n > 1024) return false;
    out.reps.assign(n, {});
    for (uint32_t i = 0; i < n; ++i) {
        if (!pull_bytes(in, off, out.reps[i].A)) return false;
        if (!pull_bytes(in, off, out.reps[i].B)) return false;
        if (!pull_u8(in, off, out.reps[i].c)) return false;
        if (!pull_bytes(in, off, out.reps[i].zx)) return false;
        if (!pull_bytes(in, off, out.reps[i].zy)) return false;
    }
    if (off != in.size()) return false;
    return true;
}

} // anonymous namespace

// ====================================================================
// Message serialization
// ====================================================================

bool dkg_msg::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    out.push_back(hdr.version);
    push_u32(out, hdr.candidate_id);
    out.insert(out.end(),
               std::begin(hdr.committee_id_hash),
               std::end(hdr.committee_id_hash));
    out.insert(out.end(),
               hdr.proposal_id.data,
               hdr.proposal_id.data + 32);
    push_u32(out, hdr.sender_id);
    push_u32(out, hdr.recipient_id);
    push_u32(out, hdr.phase);
    push_u32(out, hdr.round);
    push_u64(out, hdr.sequence);
    out.push_back(static_cast<uint8_t>(hdr.type));
    push_u32(out, tag32);
    push_bytes(out, bytes_a);
    push_bytes(out, bytes_b);
    push_bytes(out, bytes_c);
    push_bytes(out, bytes_d);
    push_u32(out, static_cast<uint32_t>(vec_a.size()));
    for (const auto& e : vec_a) push_bytes(out, e);
    return true;
}

bool dkg_msg::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    if (in.size() < 4) return false;
    hdr.version = in[off++];
    if (hdr.version != 2) return false;
    if (!pull_u32(in, off, hdr.candidate_id)) return false;
    if (off + 32 > in.size()) return false;
    std::memcpy(hdr.committee_id_hash, in.data() + off, 32);
    off += 32;
    if (off + 32 > in.size()) return false;
    std::memcpy(hdr.proposal_id.data, in.data() + off, 32);
    off += 32;
    if (!pull_u32(in, off, hdr.sender_id)) return false;
    if (!pull_u32(in, off, hdr.recipient_id)) return false;
    if (!pull_u32(in, off, hdr.phase)) return false;
    if (!pull_u32(in, off, hdr.round)) return false;
    if (!pull_u64(in, off, hdr.sequence)) return false;
    if (off >= in.size()) return false;
    hdr.type = static_cast<dkg_msg_type>(in[off++]);
    if (!pull_u32(in, off, tag32)) return false;
    if (!pull_bytes(in, off, bytes_a)) return false;
    if (!pull_bytes(in, off, bytes_b)) return false;
    if (!pull_bytes(in, off, bytes_c)) return false;
    if (!pull_bytes(in, off, bytes_d)) return false;
    uint32_t n = 0;
    if (!pull_u32(in, off, n)) return false;
    if (n > 4096) return false;
    vec_a.assign(n, {});
    for (uint32_t i = 0; i < n; ++i)
        if (!pull_bytes(in, off, vec_a[i])) return false;
    if (off != in.size()) return false;
    return true;
}

// ====================================================================
// VSS
// ====================================================================

dao_vss_group::~dao_vss_group()
{
    if (P)       BN_free(P);
    if (P_prime) BN_free(P_prime);
    if (g)       BN_free(g);
    if (h)       BN_free(h);
}

// ====================================================================
// Named FFDHE group selection and deterministic h derivation
// ====================================================================

static int dao_vss_select_named_group(unsigned int required_order_bits)
{
    // required_order_bits refers to the subgroup order P' = (P-1)/2.
    // ffdhe2048 -> P' is 2047 bits.
    if (required_order_bits <= 2047) return NID_ffdhe2048;
    // ffdhe6144 -> P' is 6143 bits.
    if (required_order_bits <= 6143) return NID_ffdhe6144;
    // ffdhe8192 -> P' is 8191 bits.
    if (required_order_bits <= 8191) return NID_ffdhe8192;
    return NID_undef;
}

// Append x as a fixed-width big-endian byte string to out.
static bool dao_bn_append_fixed(std::vector<uint8_t>& out,
                                const BIGNUM* x,
                                size_t width)
{
    if (!x) return false;
    std::vector<uint8_t> tmp(width);
    if (BN_bn2binpad(x, tmp.data(), static_cast<int>(width)) !=
        static_cast<int>(width)) {
        return false;
    }
    out.insert(out.end(), tmp.begin(), tmp.end());
    return true;
}

// Deterministic derivation of h from the complete group parameter set.
// The hash input binds domain, group name, P, P', and g, plus a counter.
// The result is a member of the quadratic-residue subgroup of order P'.
static bool dao_vss_derive_h(const BIGNUM* P,
                             const BIGNUM* P_prime,
                             const BIGNUM* g,
                             const char* group_name,
                             BIGNUM* h_out,
                             BN_CTX* ctx)
{
    if (!P || !P_prime || !g || !group_name || !h_out || !ctx) return false;

    const size_t p_bytes = static_cast<size_t>(BN_num_bytes(P));

    for (uint32_t counter = 0; counter < 256; ++counter) {
        std::vector<uint8_t> input;
        static const char DOMAIN[] = "VeilRoot-DAO-VSS-H-V2";
        input.insert(input.end(), DOMAIN, DOMAIN + sizeof(DOMAIN) - 1);
        input.push_back(0);
        input.insert(input.end(), group_name,
                     group_name + std::strlen(group_name));
        input.push_back(0);

        if (!dao_bn_append_fixed(input, P, p_bytes))       return false;
        if (!dao_bn_append_fixed(input, P_prime, p_bytes)) return false;
        if (!dao_bn_append_fixed(input, g, p_bytes))       return false;

        input.push_back(static_cast<uint8_t>(counter & 0xff));
        input.push_back(static_cast<uint8_t>((counter >> 8) & 0xff));
        input.push_back(static_cast<uint8_t>((counter >> 16) & 0xff));
        input.push_back(static_cast<uint8_t>((counter >> 24) & 0xff));

        EVP_MD_CTX* md = EVP_MD_CTX_new();
        if (!md) return false;

        bool ok = true;
        ok = ok && EVP_DigestInit_ex(md, EVP_shake256(), nullptr) == 1;
        ok = ok && EVP_DigestUpdate(md, input.data(), input.size()) == 1;

        std::vector<uint8_t> digest(p_bytes);
        ok = ok && EVP_DigestFinalXOF(md, digest.data(), digest.size()) == 1;
        EVP_MD_CTX_free(md);
        if (!ok) return false;

        BIGNUM* x = BN_bin2bn(digest.data(),
                              static_cast<int>(digest.size()), nullptr);
        if (!x) return false;

        if (!BN_nnmod(x, x, P, ctx)) { BN_free(x); return false; }
        if (BN_is_zero(x)) { BN_free(x); continue; }

        // Squaring maps into the quadratic-residue subgroup of order P'.
        if (!BN_mod_sqr(h_out, x, P, ctx)) { BN_free(x); return false; }
        BN_free(x);

        if (BN_is_one(h_out)) continue;

        // Verify h is in the subgroup of order P'.
        BIGNUM* h_check = BN_new();
        if (!h_check) return false;
        const bool ok_h =
            BN_mod_exp(h_check, h_out, P_prime, P, ctx) == 1 &&
            BN_is_one(h_check);
        BN_free(h_check);
        if (!ok_h) continue;

        return true;
    }
    return false;
}

bool dao_vss_group_generate(dao_vss_group& out, unsigned int required_order_bits)
{
    CtxGuard guard;
    if (!guard.ok()) return false;

#ifdef VEILROOT_DAO_DKG_TESTING
    // Test-only fixed 512-bit safe-prime group. P' is 511 bits, which
    // exceeds the ~387-bit required_order_bits for the current
    // test configuration (k=60, target_N=128, security_bits=32).
    //
    // This fixture uses g=4, which is a generator of the same
    // prime-order quadratic-residue subgroup for this safe-prime P.
    // It intentionally does not exercise the production FFDHE g=2
    // path; that path is tested separately by ffdhe2048_parameters
    // and ffdhe6144_parameters.
    //
    // Using a fixed, verified group here keeps ordinary DKG tests
    // fast. The production path below is unchanged.
    if (required_order_bits <= 512)
    {
        static const char TEST_P_HEX[] =
            "ef8b1e5b265783daa07523036b73c9c4b7c1e4a049e5047b4f04c56a8892ac18"
            "ed0c704da6fdda1c600be037c03b1fcde18030c98fdc501b39ec683bfc24f4b7";

        static const char TEST_H_HEX[] =
            "5d43788a19cfc5da5ce1fbaeb1dbd552a1b375307d3c601f8580ad6ee9de5a19"
            "2d1f25a9a48fc59b40b2f7e30de1027c8253ea64b40365c75820109deb79f258";

        BIGNUM* P = nullptr;
        BIGNUM* h = nullptr;
        BIGNUM* g = BN_new();
        BIGNUM* q = BN_new();
        BIGNUM* check = BN_new();

        if (!g || !q || !check ||
            BN_hex2bn(&P, TEST_P_HEX) == 0 ||
            BN_hex2bn(&h, TEST_H_HEX) == 0 ||
            !BN_set_word(g, 4)) {
            BN_free(P);
            BN_free(h);
            BN_free(g);
            BN_free(q);
            BN_free(check);
            return false;
        }

        bool ok =
            BN_sub(q, P, BN_value_one()) == 1 &&
            BN_rshift1(q, q) == 1 &&
            BN_num_bits(q) >= 511 &&
            BN_mod_exp(check, g, q, P, guard.ctx) == 1 &&
            BN_is_one(check) &&
            BN_mod_exp(check, h, q, P, guard.ctx) == 1 &&
            BN_is_one(check) &&
            !BN_is_one(g) &&
            !BN_is_one(h);

        if (ok)
            ok = BN_is_prime_ex(P, 64, guard.ctx, nullptr) == 1;

        if (ok)
            ok = BN_is_prime_ex(q, 64, guard.ctx, nullptr) == 1;

        if (!ok) {
            BN_free(P);
            BN_free(h);
            BN_free(g);
            BN_free(q);
            BN_free(check);
            return false;
        }

        if (out.P)       BN_free(out.P);
        if (out.P_prime) BN_free(out.P_prime);
        if (out.g)       BN_free(out.g);
        if (out.h)       BN_free(out.h);

        out.P       = P;
        out.P_prime = q;
        out.g       = g;
        out.h       = h;

        BN_free(check);
        return true;
    }
#endif

    const int nid = dao_vss_select_named_group(required_order_bits);
    if (nid == NID_undef) return false;

    DH* dh = DH_new_by_nid(nid);
    if (!dh) return false;

    const BIGNUM* P = nullptr;
    const BIGNUM* Q = nullptr;
    const BIGNUM* G = nullptr;
    DH_get0_pqg(dh, &P, &Q, &G);

    if (!P || !G) {
        DH_free(dh);
        return false;
    }

    // OpenSSL 1.1.1 may return FFDHE named-group parameters without Q.
    // Derive Q = (P - 1) / 2 ourselves, and validate Q when supplied.
    BIGNUM* expected_Q = BN_new();
    if (!expected_Q) { DH_free(dh); return false; }

    if (!BN_sub(expected_Q, P, BN_value_one()) ||
        !BN_rshift1(expected_Q, expected_Q)) {
        BN_free(expected_Q);
        DH_free(dh);
        return false;
    }

    if (Q && BN_cmp(expected_Q, Q) != 0) {
        BN_free(expected_Q);
        DH_free(dh);
        return false;
    }

    const BIGNUM* subgroup_order = Q ? Q : expected_Q;

    if (BN_num_bits(subgroup_order) <
        static_cast<int>(required_order_bits)) {
        BN_free(expected_Q);
        DH_free(dh);
        return false;
    }

    // The published generators of the FFDHE groups are 2.
    if (!BN_is_word(G, 2)) {
        BN_free(expected_Q);
        DH_free(dh);
        return false;
    }

    // Explicit subgroup check for G: G^P' == 1 mod P and G != 1.
    // For safe-prime P, QR(P) has prime order P'; this makes the
    // assumption enforced rather than implicit.
    {
        BIGNUM* g_check = BN_new();
        if (!g_check) {
            BN_free(expected_Q);
            DH_free(dh);
            return false;
        }
        const bool g_ok =
            BN_mod_exp(g_check, G, subgroup_order, P, guard.ctx) == 1 &&
            BN_is_one(g_check) &&
            !BN_is_one(G);
        BN_free(g_check);
        if (!g_ok) {
            BN_free(expected_Q);
            DH_free(dh);
            return false;
        }
    }

    BIGNUM* h_val = BN_new();
    if (!h_val) {
        BN_free(expected_Q);
        DH_free(dh);
        return false;
    }

    const char* group_name = nullptr;
    switch (nid) {
        case NID_ffdhe2048: group_name = "ffdhe2048"; break;
        case NID_ffdhe6144: group_name = "ffdhe6144"; break;
        case NID_ffdhe8192: group_name = "ffdhe8192"; break;
        default:
            BN_free(h_val);
            BN_free(expected_Q);
            DH_free(dh);
            return false;
    }

    if (!dao_vss_derive_h(P, subgroup_order, G, group_name, h_val, guard.ctx)) {
        BN_free(h_val);
        BN_free(expected_Q);
        DH_free(dh);
        return false;
    }

    // Atomic replacement of the group.
    if (out.P)       BN_free(out.P);
    if (out.P_prime) BN_free(out.P_prime);
    if (out.g)       BN_free(out.g);
    if (out.h)       BN_free(out.h);

    out.P       = BN_dup(P);
    out.P_prime = BN_dup(subgroup_order);
    out.g       = BN_dup(G);
    out.h       = h_val;

    const bool ok =
        out.P != nullptr &&
        out.P_prime != nullptr &&
        out.g != nullptr &&
        out.h != nullptr;

    if (!ok) {
        if (out.P)       { BN_free(out.P);       out.P       = nullptr; }
        if (out.P_prime) { BN_free(out.P_prime); out.P_prime = nullptr; }
        if (out.g)       { BN_free(out.g);       out.g       = nullptr; }
        if (out.h)       { BN_free(out.h);       out.h       = nullptr; }
    }

    BN_free(expected_Q);
    DH_free(dh);
    return ok;
}

bool dao_vss_deal(const dao_vss_group& grp,
                  const BIGNUM* secret,
                  uint32_t n,
                  uint32_t degree,
                  dao_vss_commitments& commitments_out,
                  std::vector<BIGNUM*>& shares_out,
                  std::vector<BIGNUM*>& blindings_out,
                  BIGNUM** constant_blinding_out)
{
    if (!grp.valid() || !secret) return false;
    if (n < degree + 1) return false;
    if (BN_is_negative(secret)) return false;
    if (BN_cmp(secret, grp.P_prime) >= 0) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    const uint32_t t = degree;

    // Integer VSS bound. For every evaluation point i in [1, n]:
    //   secret + SUM_{k=1..t} a_k * i^k < P_prime
    //   SUM_{k=0..t} b_k * i^k           < P_prime
    //
    // Coefficient values are sampled in [0, a_limit] and [0, b_limit]
    // with a_limit and b_limit derived from the sum-of-powers upper
    // bounds at i = n.

    BIGNUM* n_bn       = BN_new();
    BIGNUM* sum_pow    = BN_new();   // sum_{k=1..t} n^k
    BIGNUM* pow        = BN_new();
    BIGNUM* a_limit    = BN_new();
    BIGNUM* b_limit    = BN_new();
    BIGNUM* remaining  = BN_new();

    if (!n_bn || !sum_pow || !pow || !a_limit || !b_limit || !remaining) {
        BN_free(n_bn); BN_free(sum_pow); BN_free(pow);
        BN_free(a_limit); BN_free(b_limit); BN_free(remaining);
        return false;
    }

    BN_set_word(n_bn, static_cast<BN_ULONG>(n));
    BN_zero(sum_pow);
    BN_one(pow);

    for (uint32_t k = 1; k <= t; ++k) {
        if (!BN_mul(pow, pow, n_bn, ctx.ctx)) {
            BN_free(n_bn); BN_free(sum_pow); BN_free(pow);
            BN_free(a_limit); BN_free(b_limit); BN_free(remaining);
            return false;
        }
        if (!BN_add(sum_pow, sum_pow, pow)) {
            BN_free(n_bn); BN_free(sum_pow); BN_free(pow);
            BN_free(a_limit); BN_free(b_limit); BN_free(remaining);
            return false;
        }
    }

    // a_limit = (P_prime - 1 - secret) / sum_pow  (or 0 if t == 0)
    if (t == 0 || BN_is_zero(sum_pow)) {
        BN_zero(a_limit);
    } else {
        BN_copy(remaining, grp.P_prime);
        BN_sub_word(remaining, 1);
        BN_sub(remaining, remaining, secret);
        BN_div(a_limit, nullptr, remaining, sum_pow, ctx.ctx);
    }

    // b_limit = (P_prime - 1) / (sum_pow + 1)
    {
        BIGNUM* denom = BN_new();
        if (!denom) {
            BN_free(n_bn); BN_free(sum_pow); BN_free(pow);
            BN_free(a_limit); BN_free(b_limit); BN_free(remaining);
            return false;
        }
        BN_add(denom, sum_pow, BN_value_one());
        BN_copy(remaining, grp.P_prime);
        BN_sub_word(remaining, 1);
        BN_div(b_limit, nullptr, remaining, denom, ctx.ctx);
        BN_free(denom);
    }

    BN_free(n_bn); BN_free(sum_pow); BN_free(pow); BN_free(remaining);

    std::vector<BIGNUM*> a(t + 1, nullptr);
    std::vector<BIGNUM*> b(t + 1, nullptr);
    a[0] = BN_dup(secret);
    if (!a[0]) { BN_free(a_limit); BN_free(b_limit); return false; }
    for (uint32_t k = 1; k <= t; ++k) a[k] = BN_new();
    for (uint32_t k = 0; k <= t; ++k) b[k] = BN_new();

    // Sample in [0, limit]. Add one to make BN_rand_range produce the
    // inclusive upper bound.
    BIGNUM* a_range = BN_new();
    BIGNUM* b_range = BN_new();
    if (!a_range || !b_range) {
        BN_free(a_limit); BN_free(b_limit);
        for (auto* x : a) if (x) BN_free(x);
        for (auto* x : b) if (x) BN_free(x);
        return false;
    }
    BN_copy(a_range, a_limit);
    BN_add_word(a_range, 1);
    BN_copy(b_range, b_limit);
    BN_add_word(b_range, 1);

    for (uint32_t k = 1; k <= t; ++k)
        if (!BN_rand_range(a[k], a_range)) {
            BN_free(a_range); BN_free(b_range); BN_free(a_limit); BN_free(b_limit);
            for (auto* x : a) if (x) BN_free(x);
            for (auto* x : b) if (x) BN_free(x);
            return false;
        }
    for (uint32_t k = 0; k <= t; ++k)
        if (!BN_rand_range(b[k], b_range)) {
            BN_free(a_range); BN_free(b_range); BN_free(a_limit); BN_free(b_limit);
            for (auto* x : a) if (x) BN_free(x);
            for (auto* x : b) if (x) BN_free(x);
            return false;
        }
    BN_free(a_range); BN_free(b_range); BN_free(a_limit); BN_free(b_limit);

    commitments_out.C.assign(t + 1, {});
    const size_t P_bytes = static_cast<size_t>(BN_num_bytes(grp.P));
    for (uint32_t k = 0; k <= t; ++k) {
        BIGNUM* ga = BN_new();
        BIGNUM* hb = BN_new();
        BIGNUM* C  = BN_new();
        if (!ga || !hb || !C) return false;
        // Secret polynomial coefficients: use constant-time modular
        // exponentiation where OpenSSL supports it.
        if (!BN_mod_exp_mont_consttime(ga, grp.g, a[k], grp.P, ctx.ctx, nullptr))
            return false;
        if (!BN_mod_exp_mont_consttime(hb, grp.h, b[k], grp.P, ctx.ctx, nullptr))
            return false;
        if (!BN_mod_mul(C, ga, hb, grp.P, ctx.ctx)) return false;
        commitments_out.C[k].assign(P_bytes, 0);
        BN_bn2binpad(C, commitments_out.C[k].data(),
                     static_cast<int>(P_bytes));
        BN_free(ga); BN_free(hb); BN_free(C);
    }

    // Integer evaluations. The coefficient bound guarantees s < P' and
    // ti < P' for every i in [1, n]. The check below is defensive.
    shares_out.assign(n, nullptr);
    blindings_out.assign(n, nullptr);
    for (uint32_t i = 1; i <= n; ++i) {
        BIGNUM* s   = BN_new();
        BIGNUM* ti  = BN_new();
        BIGNUM* pw  = BN_new();
        if (!s || !ti || !pw) return false;
        BN_zero(s); BN_zero(ti); BN_one(pw);
        for (uint32_t k = 0; k <= t; ++k) {
            BIGNUM* term_s = BN_new();
            BIGNUM* term_t = BN_new();
            if (!term_s || !term_t) return false;
            if (!BN_mul(term_s, a[k], pw, ctx.ctx)) return false;
            if (!BN_mul(term_t, b[k], pw, ctx.ctx)) return false;
            if (!BN_add(s, s, term_s)) return false;
            if (!BN_add(ti, ti, term_t)) return false;
            BN_free(term_s); BN_free(term_t);
            if (k < t) BN_mul_word(pw, i);
        }
        if (BN_cmp(s, grp.P_prime) >= 0 || BN_cmp(ti, grp.P_prime) >= 0) {
            BN_free(s); BN_free(ti); BN_free(pw);
            for (auto* x : a) if (x) BN_free(x);
            for (auto* x : b) if (x) BN_free(x);
            return false;
        }
        shares_out[i - 1]    = s;
        blindings_out[i - 1] = ti;
        BN_free(pw);
    }

    if (constant_blinding_out) {
        *constant_blinding_out = BN_dup(b[0]);
        if (!*constant_blinding_out) {
            for (auto* x : a) if (x) BN_free(x);
            for (auto* x : b) if (x) BN_free(x);
            return false;
        }
    }

    // BEGIN_VNS_DKG_SELFCHECK
    for (uint32_t i = 1; i <= n; ++i) {
        if (!dao_vss_verify_share(grp, commitments_out, n, i,
                                  shares_out[i - 1], blindings_out[i - 1])) {
            for (auto* x : a) if (x) BN_free(x);
            for (auto* x : b) if (x) BN_free(x);
            return false;
        }
    }
    // END_VNS_DKG_SELFCHECK

    for (auto* x : a) if (x) BN_free(x);
    for (auto* x : b) if (x) BN_free(x);
    return true;
}

bool dao_vss_verify_share(const dao_vss_group& grp,
                          const dao_vss_commitments& commitments,
                          uint32_t n,
                          uint32_t i,
                          const BIGNUM* share,
                          const BIGNUM* blinding)
{
    if (!grp.valid() || !share || !blinding) return false;
    if (i == 0 || i > n) return false;
    if (commitments.C.empty()) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    // LHS: g^share * h^blinding mod P. BN_mod_exp reduces the
    // exponent modulo the group order P_prime automatically.
    BIGNUM* lhs_a = BN_new();
    BIGNUM* lhs_b = BN_new();
    BIGNUM* lhs   = BN_new();
    if (!lhs_a || !lhs_b || !lhs) return false;
    if (!BN_mod_exp(lhs_a, grp.g, share, grp.P, ctx.ctx)) return false;
    if (!BN_mod_exp(lhs_b, grp.h, blinding, grp.P, ctx.ctx)) return false;
    if (!BN_mod_mul(lhs, lhs_a, lhs_b, grp.P, ctx.ctx)) return false;

    // RHS: prod_k C_k^(i^k) mod P. The exponent i^k is maintained
    // modulo P_prime.
    BIGNUM* rhs = BN_new();
    BN_one(rhs);
    BIGNUM* pow = BN_new();
    BN_one(pow);
    const uint32_t t = static_cast<uint32_t>(commitments.C.size()) - 1;
    for (uint32_t k = 0; k <= t; ++k) {
        BIGNUM* C_k = BN_bin2bn(commitments.C[k].data(),
                                static_cast<int>(commitments.C[k].size()),
                                nullptr);
        BIGNUM* term = BN_new();
        if (!C_k || !term) { BN_free(C_k); BN_free(term); return false; }
        if (!BN_mod_exp(term, C_k, pow, grp.P, ctx.ctx)) return false;
        if (!BN_mod_mul(rhs, rhs, term, grp.P, ctx.ctx)) return false;
        BN_free(C_k); BN_free(term);
        if (k < t) {
            BN_mul_word(pow, i);
            BN_mod(pow, pow, grp.P_prime, ctx.ctx);
        }
    }

    const bool ok = (BN_cmp(lhs, rhs) == 0);
    BN_free(lhs_a); BN_free(lhs_b); BN_free(lhs);
    BN_free(rhs); BN_free(pow);
    return ok;
}

// ====================================================================
// Gap 1 — beta/R range proof (bit decomposition + link)
// ====================================================================

namespace {

std::vector<uint8_t> bn_to_bytes_fixed(const BIGNUM* x, size_t width)
{
    std::vector<uint8_t> out(width, 0);
    if (x) BN_bn2binpad(x, out.data(), static_cast<int>(width));
    return out;
}

BIGNUM* bytes_to_bn(const std::vector<uint8_t>& b)
{
    if (b.empty()) return nullptr;
    return BN_bin2bn(b.data(), static_cast<int>(b.size()), nullptr);
}

void append_u32be(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 3; i >= 0; --i) v.push_back((x >> (8*i)) & 0xff);
}

void append_bn_fixed(std::vector<uint8_t>& v, const BIGNUM* x, size_t width)
{
    std::vector<uint8_t> tmp(width, 0);
    if (x) BN_bn2binpad(x, tmp.data(), static_cast<int>(width));
    v.insert(v.end(), tmp.begin(), tmp.end());
}

bool fs_challenge_bn(const std::vector<uint8_t>& input,
                     const BIGNUM* modulus,
                     BIGNUM* out,
                     BN_CTX* ctx)
{
    unsigned char digest[32];
    SHA256(input.data(), input.size(), digest);
    if (!BN_bin2bn(digest, 32, out)) return false;
    return BN_mod(out, out, modulus, ctx) == 1;
}

bool mod_pow_ct(BIGNUM* r, const BIGNUM* a, const BIGNUM* e,
                const BIGNUM* m, BN_CTX* ctx)
{
    return BN_mod_exp_mont_consttime(r, a, e, m, ctx, nullptr) == 1;
}

} // namespace

bool dao_range_proof::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    push_u32(out, bits);
    push_u32(out, static_cast<uint32_t>(bit_commitments.size()));
    for (const auto& b : bit_commitments) push_bytes(out, b);
    push_u32(out, static_cast<uint32_t>(bit_proofs.size()));
    for (const auto& p : bit_proofs) {
        push_bytes(out, p.A_0);
        push_bytes(out, p.A_1);
        push_bytes(out, p.c_0);
        push_bytes(out, p.c_1);
        push_bytes(out, p.z_0);
        push_bytes(out, p.z_1);
    }
    push_bytes(out, link_a);
    push_bytes(out, link_z);
    return true;
}

bool dao_range_proof::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    uint32_t b = 0;
    if (!pull_u32(in, off, b)) return false;
    if (b == 0 || b > 4096) return false;
    bits = b;

    uint32_t nc = 0;
    if (!pull_u32(in, off, nc)) return false;
    if (nc != bits) return false;
    bit_commitments.assign(nc, {});
    for (uint32_t i = 0; i < nc; ++i)
        if (!pull_bytes(in, off, bit_commitments[i])) return false;

    uint32_t np = 0;
    if (!pull_u32(in, off, np)) return false;
    if (np != bits) return false;
    bit_proofs.assign(np, {});
    for (uint32_t i = 0; i < np; ++i) {
        auto& p = bit_proofs[i];
        if (!pull_bytes(in, off, p.A_0)) return false;
        if (!pull_bytes(in, off, p.A_1)) return false;
        if (!pull_bytes(in, off, p.c_0)) return false;
        if (!pull_bytes(in, off, p.c_1)) return false;
        if (!pull_bytes(in, off, p.z_0)) return false;
        if (!pull_bytes(in, off, p.z_1)) return false;
    }
    if (!pull_bytes(in, off, link_a)) return false;
    if (!pull_bytes(in, off, link_z)) return false;
    return off == in.size();
}

bool dao_range_prove(const dao_vss_group& grp,
                     uint32_t party_id,
                     uint32_t value_tag,
                     const BIGNUM* x,
                     const BIGNUM* rho_x,
                     const BIGNUM* C_x,
                     uint32_t bits,
                     dao_range_proof& proof_out)
{
    if (!grp.valid() || !x || !rho_x || !C_x) return false;
    if (bits == 0 || bits > 4096) return false;
    if (BN_is_negative(x) || BN_is_negative(rho_x)) return false;
    if (BN_num_bits(x) > static_cast<int>(bits)) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    const size_t P_bytes  = static_cast<size_t>(BN_num_bytes(grp.P));
    const size_t Pp_bytes = static_cast<size_t>(BN_num_bytes(grp.P_prime));

    std::vector<BIGNUM*> rho_j(bits, nullptr);
    std::vector<BIGNUM*> B_j(bits, nullptr);
    std::vector<uint32_t> bit_values(bits, 0);

    for (uint32_t j = 0; j < bits; ++j)
        bit_values[j] = BN_is_bit_set(x, j) ? 1 : 0;

    for (uint32_t j = 0; j < bits; ++j) {
        rho_j[j] = BN_new();
        B_j[j]   = BN_new();
        if (!rho_j[j] || !B_j[j]) return false;
        if (!BN_rand_range(rho_j[j], grp.P_prime)) return false;

        BIGNUM* gb = BN_new();
        BIGNUM* hr = BN_new();
        if (!gb || !hr) return false;

        if (bit_values[j] == 1) BN_copy(gb, grp.g);
        else                     BN_one(gb);

        if (!mod_pow_ct(hr, grp.h, rho_j[j], grp.P, ctx.ctx)) return false;
        if (!BN_mod_mul(B_j[j], gb, hr, grp.P, ctx.ctx)) return false;
        BN_free(gb); BN_free(hr);
    }

    // D = C_x / prod_j B_j^{2^j}
    BIGNUM* prod = BN_new();
    BN_one(prod);
    for (uint32_t j = 0; j < bits; ++j) {
        BIGNUM* exp = BN_new();
        BN_one(exp);
        BN_lshift(exp, exp, j);
        BIGNUM* term = BN_new();
        if (!BN_mod_exp(term, B_j[j], exp, grp.P, ctx.ctx)) return false;
        if (!BN_mod_mul(prod, prod, term, grp.P, ctx.ctx)) return false;
        BN_free(exp); BN_free(term);
    }
    BIGNUM* prod_inv = BN_mod_inverse(nullptr, prod, grp.P, ctx.ctx);
    if (!prod_inv) return false;
    BIGNUM* D = BN_new();
    BN_mod_mul(D, C_x, prod_inv, grp.P, ctx.ctx);
    BN_free(prod); BN_free(prod_inv);

    // delta = rho_x - sum_j rho_j 2^j mod P'
    BIGNUM* delta = BN_dup(rho_x);
    for (uint32_t j = 0; j < bits; ++j) {
        BIGNUM* exp = BN_new();
        BN_one(exp);
        BN_lshift(exp, exp, j);
        BIGNUM* term = BN_new();
        BN_mod_mul(term, rho_j[j], exp, grp.P_prime, ctx.ctx);
        BN_mod_sub(delta, delta, term, grp.P_prime, ctx.ctx);
        BN_free(exp); BN_free(term);
    }

    proof_out.bits = bits;
    proof_out.bit_commitments.clear();
    proof_out.bit_proofs.clear();

    for (uint32_t j = 0; j < bits; ++j) {
        proof_out.bit_commitments.push_back(bn_to_bytes_fixed(B_j[j], P_bytes));

        BIGNUM* X0 = BN_dup(B_j[j]);
        BIGNUM* g_inv = BN_mod_inverse(nullptr, grp.g, grp.P, ctx.ctx);
        BIGNUM* X1 = BN_new();
        BN_mod_mul(X1, B_j[j], g_inv, grp.P, ctx.ctx);
        BN_free(g_inv);

        const int real_branch = static_cast<int>(bit_values[j]);

        BIGNUM* a = BN_new();
        BN_rand_range(a, grp.P_prime);
        BIGNUM* A_real = BN_new();
        if (!mod_pow_ct(A_real, grp.h, a, grp.P, ctx.ctx)) return false;

        BIGNUM* c_false = BN_new();
        BIGNUM* z_false = BN_new();
        BN_rand_range(c_false, grp.P_prime);
        BN_rand_range(z_false, grp.P_prime);

        const BIGNUM* X_false = (real_branch == 0) ? X1 : X0;

        BIGNUM* hz = BN_new();
        mod_pow_ct(hz, grp.h, z_false, grp.P, ctx.ctx);

        BIGNUM* Xf_c = BN_new();
        BN_mod_exp(Xf_c, X_false, c_false, grp.P, ctx.ctx);
        BIGNUM* Xf_c_inv = BN_mod_inverse(nullptr, Xf_c, grp.P, ctx.ctx);

        BIGNUM* A_false = BN_new();
        BN_mod_mul(A_false, hz, Xf_c_inv, grp.P, ctx.ctx);

        BIGNUM* A0; BIGNUM* A1;
        if (real_branch == 0) { A0 = A_real; A1 = A_false; }
        else                  { A0 = A_false; A1 = A_real; }

        std::vector<uint8_t> input;
        static const char DOM_BIT[] = "VeilRoot-DAO-DKG-RANGE-BIT-V1";
        input.insert(input.end(), DOM_BIT, DOM_BIT + sizeof(DOM_BIT) - 1);
        append_u32be(input, party_id);
        append_u32be(input, value_tag);
        append_bn_fixed(input, C_x, P_bytes);
        append_u32be(input, j);
        append_bn_fixed(input, B_j[j], P_bytes);
        append_bn_fixed(input, A0, P_bytes);
        append_bn_fixed(input, A1, P_bytes);

        BIGNUM* e = BN_new();
        fs_challenge_bn(input, grp.P_prime, e, ctx.ctx);

        BIGNUM* c_real = BN_new();
        BN_mod_sub(c_real, e, c_false, grp.P_prime, ctx.ctx);

        BIGNUM* z_real = BN_new();
        BIGNUM* cr = BN_new();
        BN_mod_mul(cr, c_real, rho_j[j], grp.P_prime, ctx.ctx);
        BN_mod_add(z_real, a, cr, grp.P_prime, ctx.ctx);

        BIGNUM* c0; BIGNUM* c1; BIGNUM* z0; BIGNUM* z1;
        if (real_branch == 0) {
            c0 = c_real; c1 = c_false;
            z0 = z_real; z1 = z_false;
        } else {
            c0 = c_false; c1 = c_real;
            z0 = z_false; z1 = z_real;
        }

        dao_bit_or_proof bp;
        bp.A_0 = bn_to_bytes_fixed(A0, P_bytes);
        bp.A_1 = bn_to_bytes_fixed(A1, P_bytes);
        bp.c_0 = bn_to_bytes_fixed(c0, Pp_bytes);
        bp.c_1 = bn_to_bytes_fixed(c1, Pp_bytes);
        bp.z_0 = bn_to_bytes_fixed(z0, Pp_bytes);
        bp.z_1 = bn_to_bytes_fixed(z1, Pp_bytes);
        proof_out.bit_proofs.push_back(std::move(bp));

        BN_free(a); BN_free(A_real);
        BN_free(c_false); BN_free(z_false);
        BN_free(hz); BN_free(Xf_c); BN_free(Xf_c_inv); BN_free(A_false);
        BN_free(e); BN_free(c_real); BN_free(z_real); BN_free(cr);
        BN_free(X0); BN_free(X1);
    }

    // Link proof: D = h^delta
    BIGNUM* u = BN_new();
    BN_rand_range(u, grp.P_prime);
    BIGNUM* A_link = BN_new();
    mod_pow_ct(A_link, grp.h, u, grp.P, ctx.ctx);

    std::vector<uint8_t> link_input;
    static const char DOM_LINK[] = "VeilRoot-DAO-DKG-RANGE-LINK-V1";
    link_input.insert(link_input.end(), DOM_LINK, DOM_LINK + sizeof(DOM_LINK) - 1);
    append_u32be(link_input, party_id);
    append_u32be(link_input, value_tag);
    append_bn_fixed(link_input, C_x, P_bytes);
    for (uint32_t j = 0; j < bits; ++j)
        append_bn_fixed(link_input, B_j[j], P_bytes);
    append_bn_fixed(link_input, D, P_bytes);
    append_bn_fixed(link_input, A_link, P_bytes);

    BIGNUM* e_link = BN_new();
    fs_challenge_bn(link_input, grp.P_prime, e_link, ctx.ctx);

    BIGNUM* z_link = BN_new();
    BIGNUM* ed = BN_new();
    BN_mod_mul(ed, e_link, delta, grp.P_prime, ctx.ctx);
    BN_mod_add(z_link, u, ed, grp.P_prime, ctx.ctx);

    proof_out.link_a = bn_to_bytes_fixed(A_link, P_bytes);
    proof_out.link_z = bn_to_bytes_fixed(z_link, Pp_bytes);

    for (auto* v : rho_j) if (v) BN_free(v);
    for (auto* v : B_j)   if (v) BN_free(v);
    BN_free(D); BN_free(delta);
    BN_free(u); BN_free(A_link); BN_free(e_link); BN_free(z_link); BN_free(ed);
    return true;
}

bool dao_range_verify(const dao_vss_group& grp,
                      uint32_t party_id,
                      uint32_t value_tag,
                      const BIGNUM* C_x,
                      const dao_range_proof& proof)
{
    if (!grp.valid() || !C_x) return false;
    if (proof.bits == 0 || proof.bits > 4096) return false;
    if (proof.bit_commitments.size() != proof.bits) return false;
    if (proof.bit_proofs.size() != proof.bits) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    const size_t P_bytes  = static_cast<size_t>(BN_num_bytes(grp.P));

    std::vector<BIGNUM*> B_j(proof.bits, nullptr);
    for (uint32_t j = 0; j < proof.bits; ++j) {
        B_j[j] = bytes_to_bn(proof.bit_commitments[j]);
        if (!B_j[j]) return false;
    }

    for (uint32_t j = 0; j < proof.bits; ++j) {
        const auto& bp = proof.bit_proofs[j];
        BIGNUM* A0 = bytes_to_bn(bp.A_0);
        BIGNUM* A1 = bytes_to_bn(bp.A_1);
        BIGNUM* c0 = bytes_to_bn(bp.c_0);
        BIGNUM* c1 = bytes_to_bn(bp.c_1);
        BIGNUM* z0 = bytes_to_bn(bp.z_0);
        BIGNUM* z1 = bytes_to_bn(bp.z_1);
        if (!A0 || !A1 || !c0 || !c1 || !z0 || !z1) return false;

        BIGNUM* X0 = BN_dup(B_j[j]);
        BIGNUM* g_inv = BN_mod_inverse(nullptr, grp.g, grp.P, ctx.ctx);
        BIGNUM* X1 = BN_new();
        BN_mod_mul(X1, B_j[j], g_inv, grp.P, ctx.ctx);
        BN_free(g_inv);

        std::vector<uint8_t> input;
        static const char DOM_BIT[] = "VeilRoot-DAO-DKG-RANGE-BIT-V1";
        input.insert(input.end(), DOM_BIT, DOM_BIT + sizeof(DOM_BIT) - 1);
        append_u32be(input, party_id);
        append_u32be(input, value_tag);
        append_bn_fixed(input, C_x, P_bytes);
        append_u32be(input, j);
        append_bn_fixed(input, B_j[j], P_bytes);
        append_bn_fixed(input, A0, P_bytes);
        append_bn_fixed(input, A1, P_bytes);

        BIGNUM* e = BN_new();
        fs_challenge_bn(input, grp.P_prime, e, ctx.ctx);

        BIGNUM* csum = BN_new();
        BN_mod_add(csum, c0, c1, grp.P_prime, ctx.ctx);
        const bool ok_c = (BN_cmp(csum, e) == 0);

        bool ok_eq = true;
        for (int k = 0; k < 2 && ok_eq; ++k) {
            const BIGNUM* zk = (k == 0) ? z0 : z1;
            const BIGNUM* ck = (k == 0) ? c0 : c1;
            const BIGNUM* Ak = (k == 0) ? A0 : A1;
            const BIGNUM* Xk = (k == 0) ? X0 : X1;

            BIGNUM* hz = BN_new();
            BN_mod_exp(hz, grp.h, zk, grp.P, ctx.ctx);
            BIGNUM* Xk_c = BN_new();
            BN_mod_exp(Xk_c, Xk, ck, grp.P, ctx.ctx);
            BIGNUM* rhs = BN_new();
            BN_mod_mul(rhs, Ak, Xk_c, grp.P, ctx.ctx);
            if (BN_cmp(hz, rhs) != 0) ok_eq = false;
            BN_free(hz); BN_free(Xk_c); BN_free(rhs);
        }

        BN_free(X0); BN_free(X1);
        BN_free(A0); BN_free(A1); BN_free(c0); BN_free(c1);
        BN_free(z0); BN_free(z1); BN_free(e); BN_free(csum);

        if (!ok_c || !ok_eq) {
            for (auto* v : B_j) if (v) BN_free(v);
            return false;
        }
    }

    // D = C_x / prod B_j^{2^j}
    BIGNUM* prod = BN_new();
    BN_one(prod);
    for (uint32_t j = 0; j < proof.bits; ++j) {
        BIGNUM* exp = BN_new();
        BN_one(exp);
        BN_lshift(exp, exp, j);
        BIGNUM* term = BN_new();
        BN_mod_exp(term, B_j[j], exp, grp.P, ctx.ctx);
        BN_mod_mul(prod, prod, term, grp.P, ctx.ctx);
        BN_free(exp); BN_free(term);
    }
    BIGNUM* prod_inv = BN_mod_inverse(nullptr, prod, grp.P, ctx.ctx);
    if (!prod_inv) return false;
    BIGNUM* D = BN_new();
    BN_mod_mul(D, C_x, prod_inv, grp.P, ctx.ctx);

    BIGNUM* A_link = bytes_to_bn(proof.link_a);
    BIGNUM* z_link = bytes_to_bn(proof.link_z);
    if (!A_link || !z_link) return false;

    std::vector<uint8_t> link_input;
    static const char DOM_LINK[] = "VeilRoot-DAO-DKG-RANGE-LINK-V1";
    link_input.insert(link_input.end(), DOM_LINK, DOM_LINK + sizeof(DOM_LINK) - 1);
    append_u32be(link_input, party_id);
    append_u32be(link_input, value_tag);
    append_bn_fixed(link_input, C_x, P_bytes);
    for (uint32_t j = 0; j < proof.bits; ++j)
        append_bn_fixed(link_input, B_j[j], P_bytes);
    append_bn_fixed(link_input, D, P_bytes);
    append_bn_fixed(link_input, A_link, P_bytes);

    BIGNUM* e_link = BN_new();
    fs_challenge_bn(link_input, grp.P_prime, e_link, ctx.ctx);

    BIGNUM* hz = BN_new();
    BN_mod_exp(hz, grp.h, z_link, grp.P, ctx.ctx);
    BIGNUM* De = BN_new();
    BN_mod_exp(De, D, e_link, grp.P, ctx.ctx);
    BIGNUM* rhs = BN_new();
    BN_mod_mul(rhs, A_link, De, grp.P, ctx.ctx);
    const bool ok_link = (BN_cmp(hz, rhs) == 0);

    for (auto* v : B_j) if (v) BN_free(v);
    BN_free(prod); BN_free(prod_inv); BN_free(D);
    BN_free(A_link); BN_free(z_link); BN_free(e_link);
    BN_free(hz); BN_free(De); BN_free(rhs);

    return ok_link;
}

// ====================================================================
// Verification keys
// ====================================================================

bool dao_choose_verification_base(const PaillierPublicKey& pk,
                                  std::vector<uint8_t>& V_K_out)
{
    if (!pk.valid()) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* v = BN_new();
    if (!BN_rand_range(v, pk.N2())) { BN_free(v); return false; }
    BIGNUM* gcd = BN_new();
    BN_gcd(gcd, v, pk.N2(), ctx.ctx);
    if (!BN_is_one(gcd)) { BN_free(v); BN_free(gcd); return false; }
    BN_free(gcd);

    BIGNUM* VK = BN_new();
    BN_mod_mul(VK, v, v, pk.N2(), ctx.ctx);

    V_K_out.assign(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(VK, V_K_out.data(), PAILLIER_CT_BYTES);

    BN_free(v); BN_free(VK);
    return true;
}

bool dao_derive_verification_key(const PaillierPublicKey& pk,
                                 const std::vector<uint8_t>& V_K,
                                 const BIGNUM* share,
                                 std::vector<uint8_t>& V_K_i_out)
{
    if (!pk.valid() || !share) return false;
    if (V_K.size() != PAILLIER_CT_BYTES) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* vk = BN_bin2bn(V_K.data(), static_cast<int>(V_K.size()), nullptr);
    if (!vk) return false;

    BIGNUM* exp = BN_new();
    if (!BN_mul(exp, dao_dkg_delta(), share, ctx.ctx)) return false;

    BIGNUM* VKi = BN_new();
    if (!BN_mod_exp(VKi, vk, exp, pk.N2(), ctx.ctx)) return false;

    V_K_i_out.assign(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(VKi, V_K_i_out.data(), PAILLIER_CT_BYTES);

    BN_free(vk); BN_free(exp); BN_free(VKi);
    return true;
}

// ====================================================================
// Partial-decryption ZK proof (Appendix C)
// ====================================================================

bool dao_dkg_sample_r(const PaillierPublicKey& pk, BIGNUM* r_out)
{
    if (!pk.valid() || !r_out) return false;
    return BN_rand_range(r_out, pk.N()) == 1;
}

bool dao_partial_decryption_prove(const PaillierPublicKey& pk,
                                  const std::vector<uint8_t>& V_K,
                                  const std::vector<uint8_t>& V_K_i,
                                  uint32_t member_index,
                                  const std::vector<uint8_t>& c_bytes,
                                  const std::vector<uint8_t>& c_i_bytes,
                                  const BIGNUM* share,
                                  const BIGNUM* randomness,
                                  dao_partial_decryption_proof& proof_out)
{
    if (!pk.valid() || !share || !randomness) return false;
    if (c_bytes.size() != PAILLIER_CT_BYTES) return false;
    if (c_i_bytes.size() != PAILLIER_CT_BYTES) return false;
    if (V_K.size() != PAILLIER_CT_BYTES) return false;
    if (V_K_i.size() != PAILLIER_CT_BYTES) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* c   = BN_bin2bn(c_bytes.data(),   static_cast<int>(c_bytes.size()),   nullptr);
    BIGNUM* ci  = BN_bin2bn(c_i_bytes.data(), static_cast<int>(c_i_bytes.size()), nullptr);
    BIGNUM* vk  = BN_bin2bn(V_K.data(),       static_cast<int>(V_K.size()),       nullptr);
    if (!c || !ci || !vk) return false;

    const BIGNUM* N2 = pk.N2();

    BIGNUM* c4 = BN_new();
    BIGNUM* four = BN_new();
    BN_set_word(four, 4);
    if (!BN_mod_exp(c4, c, four, N2, ctx.ctx)) return false;

    BIGNUM* ci2 = BN_new();
    if (!BN_mod_mul(ci2, ci, ci, N2, ctx.ctx)) return false;

    BIGNUM* a = BN_new();
    BIGNUM* b = BN_new();
    if (!BN_mod_exp(a, c4, randomness, N2, ctx.ctx)) return false;
    if (!BN_mod_exp(b, vk, randomness, N2, ctx.ctx)) return false;

    std::vector<uint8_t> a_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> b_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> c4_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> ci2_bytes(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(a,   a_bytes.data(),   PAILLIER_CT_BYTES);
    BN_bn2binpad(b,   b_bytes.data(),   PAILLIER_CT_BYTES);
    BN_bn2binpad(c4,  c4_bytes.data(),  PAILLIER_CT_BYTES);
    BN_bn2binpad(ci2, ci2_bytes.data(), PAILLIER_CT_BYTES);

    BIGNUM* E = BN_new();
    if (!challenge_hash(a_bytes, b_bytes, c4_bytes, ci2_bytes, E)) return false;

    BIGNUM* Z = BN_new();
    BIGNUM* ed = BN_new();
    if (!BN_mul(ed, E, dao_dkg_delta(), ctx.ctx)) return false;
    if (!BN_mul(ed, ed, share, ctx.ctx)) return false;
    if (!BN_add(Z, randomness, ed)) return false;

    // Response width. Fixed at DAO_DKG_PARTIAL_PROOF_Z_BYTES so a
    // reshared share (magnitude ~2^8389) fits. Hard-fail on overflow;
    // do not silently truncate.
    proof_out.member_index = member_index;
    E_to_bytes(E, proof_out.E);

    if (static_cast<uint32_t>(BN_num_bytes(Z)) >
        DAO_DKG_PARTIAL_PROOF_Z_BYTES) {
        BN_free(c); BN_free(ci); BN_free(vk);
        BN_free(c4); BN_free(four); BN_free(ci2);
        BN_free(a); BN_free(b); BN_free(E); BN_free(Z); BN_free(ed);
        proof_out.E.clear();
        proof_out.Z.clear();
        return false;
    }
    // Signed encoding: 1 sign byte (0 = nonneg, 1 = negative) then
    // (DAO_DKG_PARTIAL_PROOF_Z_BYTES - 1) magnitude bytes.
    proof_out.Z.assign(DAO_DKG_PARTIAL_PROOF_Z_BYTES, 0);
    proof_out.Z[0] = BN_is_negative(Z) ? 1 : 0;
    {
        BIGNUM* abs_Z = BN_dup(Z);
        BN_set_negative(abs_Z, 0);
        const size_t mag = DAO_DKG_PARTIAL_PROOF_Z_BYTES - 1;
        if (static_cast<size_t>(BN_num_bytes(abs_Z)) > mag) {
            BN_free(abs_Z);
            BN_free(c); BN_free(ci); BN_free(vk);
            BN_free(c4); BN_free(four); BN_free(ci2);
            BN_free(a); BN_free(b); BN_free(E); BN_free(Z); BN_free(ed);
            proof_out.E.clear();
            proof_out.Z.clear();
            return false;
        }
        const int n = BN_bn2binpad(abs_Z,
                                   proof_out.Z.data() + 1,
                                   static_cast<int>(mag));
        BN_free(abs_Z);
        if (n != static_cast<int>(mag)) {
            BN_free(c); BN_free(ci); BN_free(vk);
            BN_free(c4); BN_free(four); BN_free(ci2);
            BN_free(a); BN_free(b); BN_free(E); BN_free(Z); BN_free(ed);
            proof_out.E.clear();
            proof_out.Z.clear();
            return false;
        }
    }
    BN_free(c); BN_free(ci); BN_free(vk);
    BN_free(c4); BN_free(four); BN_free(ci2);
    BN_free(a); BN_free(b); BN_free(E); BN_free(Z); BN_free(ed);
    return true;
}

bool dao_partial_decryption_verify(const PaillierPublicKey& pk,
                                   const std::vector<uint8_t>& V_K,
                                   const std::vector<uint8_t>& V_K_i,
                                   uint32_t member_index,
                                   const std::vector<uint8_t>& c_bytes,
                                   const std::vector<uint8_t>& c_i_bytes,
                                   const dao_partial_decryption_proof& proof)
{
    if (!pk.valid()) return false;
    if (proof.member_index != member_index) return false;
    if (proof.E.size() != 32) return false;
    if (proof.Z.size() != DAO_DKG_PARTIAL_PROOF_Z_BYTES) return false;
    if (V_K.size() != PAILLIER_CT_BYTES) return false;
    if (V_K_i.size() != PAILLIER_CT_BYTES) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    if (proof.Z[0] != 0 && proof.Z[0] != 1) return false;
    BIGNUM* c   = BN_bin2bn(c_bytes.data(),   static_cast<int>(c_bytes.size()),   nullptr);
    BIGNUM* ci  = BN_bin2bn(c_i_bytes.data(), static_cast<int>(c_i_bytes.size()), nullptr);
    BIGNUM* vk  = BN_bin2bn(V_K.data(),       static_cast<int>(V_K.size()),       nullptr);
    BIGNUM* vki = BN_bin2bn(V_K_i.data(),     static_cast<int>(V_K_i.size()),     nullptr);
    BIGNUM* E   = BN_bin2bn(proof.E.data(),   static_cast<int>(proof.E.size()),   nullptr);
    BIGNUM* Z   = BN_bin2bn(proof.Z.data() + 1,
                            static_cast<int>(proof.Z.size() - 1), nullptr);
    if (!c || !ci || !vk || !vki || !E || !Z) return false;
    if (proof.Z[0] == 1) BN_set_negative(Z, 1);

    const BIGNUM* N2 = pk.N2();

    BIGNUM* c4 = BN_new();
    BIGNUM* four = BN_new();
    BN_set_word(four, 4);
    if (!BN_mod_exp(c4, c, four, N2, ctx.ctx)) return false;

    BIGNUM* ci2 = BN_new();
    if (!BN_mod_mul(ci2, ci, ci, N2, ctx.ctx)) return false;

    BIGNUM* negE = BN_new();
    BN_copy(negE, E);
    BN_set_negative(negE, 1);

    BIGNUM* a1 = BN_new();
    BIGNUM* a2 = BN_new();
    if (!modexp_signed(c4, Z, N2, a1, ctx.ctx)) return false;
    if (!modexp_signed(ci2, negE, N2, a2, ctx.ctx)) return false;
    BIGNUM* a = BN_new();
    BN_mod_mul(a, a1, a2, N2, ctx.ctx);

    BIGNUM* b1 = BN_new();
    BIGNUM* b2 = BN_new();
    if (!modexp_signed(vk, Z, N2, b1, ctx.ctx)) return false;
    if (!modexp_signed(vki, negE, N2, b2, ctx.ctx)) return false;
    BIGNUM* b = BN_new();
    BN_mod_mul(b, b1, b2, N2, ctx.ctx);

    std::vector<uint8_t> a_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> b_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> c4_bytes(PAILLIER_CT_BYTES, 0);
    std::vector<uint8_t> ci2_bytes(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(a,   a_bytes.data(),   PAILLIER_CT_BYTES);
    BN_bn2binpad(b,   b_bytes.data(),   PAILLIER_CT_BYTES);
    BN_bn2binpad(c4,  c4_bytes.data(),  PAILLIER_CT_BYTES);
    BN_bn2binpad(ci2, ci2_bytes.data(), PAILLIER_CT_BYTES);

    BIGNUM* E_check = BN_new();
    if (!challenge_hash(a_bytes, b_bytes, c4_bytes, ci2_bytes, E_check)) return false;

    const bool ok = (BN_cmp(E, E_check) == 0);

    BN_free(c); BN_free(ci); BN_free(vk); BN_free(vki); BN_free(E); BN_free(Z);
    BN_free(c4); BN_free(four); BN_free(ci2);
    BN_free(negE);
    BN_free(a1); BN_free(a2); BN_free(a);
    BN_free(b1); BN_free(b2); BN_free(b);
    BN_free(E_check);
    return ok;
}

// ====================================================================
// Key record serialization
// ====================================================================

bool dao_share_set_record::serialize(std::vector<uint8_t>& out) const
{
    if (key_id.size() != 32) return false;
    if (committee_id_hash.size() != 32) return false;
    if (committee_members.size() == 0) return false;
    if (threshold == 0 || threshold > committee_members.size()) return false;
    for (const auto& m : committee_members)
        if (m.size() != 32) return false;

    // CL share-set wire format v3. Emitted only when the record
    // carries CL material; Paillier-only records stay on v2 so that
    // existing on-disk state and historical decoding are unchanged.
    const bool is_cl =
        !cl_gammas_serialized.empty() || !qualified_ids.empty();
    if (is_cl) {
        if (cl_gammas_serialized.empty()) return false;
        for (uint32_t q : qualified_ids)
            if (q >= committee_members.size()) return false;
        for (size_t i = 1; i < qualified_ids.size(); ++i)
            if (qualified_ids[i] <= qualified_ids[i - 1]) return false;

        out.clear();
        push_u32(out, 3);
        push_u64(out, share_set_id);
        push_u64(out, height);
        push_u32(out, threshold);
        push_bytes(out, key_id);
        push_bytes(out, committee_id_hash);
        push_u32(out, static_cast<uint32_t>(committee_members.size()));
        for (const auto& m : committee_members) push_bytes(out, m);
        push_u64(out, base_share_set_id);
        push_bytes(out, cl_gammas_serialized);
        push_u32(out, static_cast<uint32_t>(qualified_ids.size()));
        for (uint32_t q : qualified_ids) push_u32(out, q);
        return true;
    }

    if (committee_members.size() != VK_i.size()) return false;
    for (const auto& vk : VK_i)
        if (vk.size() != PAILLIER_CT_BYTES) return false;

    out.clear();
    push_u32(out, 2);   // always serialize as v2; evidence may be empty
    push_u64(out, share_set_id);
    push_u64(out, height);
    push_u32(out, threshold);
    push_bytes(out, key_id);
    push_bytes(out, committee_id_hash);
    push_u32(out, static_cast<uint32_t>(committee_members.size()));
    for (const auto& m : committee_members) push_bytes(out, m);
    for (const auto& vk : VK_i) push_bytes(out, vk);

    // v2 evidence
    push_u64(out, base_share_set_id);
    push_u32(out, static_cast<uint32_t>(contributions.size()));
    for (const auto& c : contributions) push_bytes(out, c);
    push_u32(out, static_cast<uint32_t>(contributor_indices.size()));
    for (uint32_t i : contributor_indices) push_u32(out, i);
    push_u32(out, static_cast<uint32_t>(contributor_vk.size()));
    for (const auto& v : contributor_vk) push_bytes(out, v);
    return true;
}

bool dao_share_set_record::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    uint32_t v = 0;
    if (!pull_u32(in, off, v)) return false;
    if (v != 1 && v != 2 && v != 3) return false;
    version = v;

    if (v == 3) {
        // v3 CL layout.
        cl_gammas_serialized.clear();
        qualified_ids.clear();
        VK_i.clear();
        contributions.clear();
        contributor_indices.clear();
        contributor_vk.clear();
        if (!pull_u64(in, off, share_set_id)) return false;
        if (!pull_u64(in, off, height)) return false;
        if (!pull_u32(in, off, threshold)) return false;
        if (!pull_bytes(in, off, key_id)) return false;
        if (key_id.size() != 32) return false;
        if (!pull_bytes(in, off, committee_id_hash)) return false;
        if (committee_id_hash.size() != 32) return false;
        uint32_t n = 0;
        if (!pull_u32(in, off, n)) return false;
        if (n == 0 || n > 64) return false;
        committee_members.assign(n, {});
        for (uint32_t i = 0; i < n; ++i) {
            if (!pull_bytes(in, off, committee_members[i])) return false;
            if (committee_members[i].size() != 32) return false;
        }
        if (!pull_u64(in, off, base_share_set_id)) return false;
        if (!pull_bytes(in, off, cl_gammas_serialized)) return false;
        if (cl_gammas_serialized.empty()) return false;
        uint32_t nq = 0;
        if (!pull_u32(in, off, nq)) return false;
        if (nq == 0 || nq > 64) return false;
        qualified_ids.assign(nq, 0);
        for (uint32_t i = 0; i < nq; ++i) {
            if (!pull_u32(in, off, qualified_ids[i])) return false;
            if (qualified_ids[i] >= committee_members.size()) return false;
            if (i > 0 && qualified_ids[i] <= qualified_ids[i - 1]) return false;
        }
        if (threshold == 0 || threshold > committee_members.size())
            return false;
        return off == in.size();
    }
    if (!pull_u64(in, off, share_set_id)) return false;
    if (!pull_u64(in, off, height)) return false;
    if (!pull_u32(in, off, threshold)) return false;
    if (!pull_bytes(in, off, key_id)) return false;
    if (key_id.size() != 32) return false;
    if (!pull_bytes(in, off, committee_id_hash)) return false;
    if (committee_id_hash.size() != 32) return false;
    uint32_t n = 0;
    if (!pull_u32(in, off, n)) return false;
    if (n == 0 || n > DAO_DKG_MAX_COMMITTEE_SIZE) return false;
    if (threshold == 0 || threshold > n) return false;
    committee_members.assign(n, {});
    for (uint32_t i = 0; i < n; ++i) {
        if (!pull_bytes(in, off, committee_members[i])) return false;
        if (committee_members[i].size() != 32) return false;
    }
    VK_i.assign(n, {});
    for (uint32_t i = 0; i < n; ++i) {
        if (!pull_bytes(in, off, VK_i[i])) return false;
        if (VK_i[i].size() != PAILLIER_CT_BYTES) return false;
    }

    base_share_set_id = 0;
    contributions.clear();
    contributor_indices.clear();
    contributor_vk.clear();

    if (version == 2) {
        if (!pull_u64(in, off, base_share_set_id)) return false;

        uint32_t nc = 0;
        if (!pull_u32(in, off, nc)) return false;
        if (nc > DAO_DKG_MAX_COMMITTEE_SIZE) return false;
        contributions.assign(nc, {});
        for (uint32_t i = 0; i < nc; ++i)
            if (!pull_bytes(in, off, contributions[i])) return false;

        uint32_t ni = 0;
        if (!pull_u32(in, off, ni)) return false;
        if (ni > DAO_DKG_MAX_COMMITTEE_SIZE) return false;
        contributor_indices.assign(ni, 0);
        for (uint32_t i = 0; i < ni; ++i)
            if (!pull_u32(in, off, contributor_indices[i])) return false;

        uint32_t nk = 0;
        if (!pull_u32(in, off, nk)) return false;
        if (nk > DAO_DKG_MAX_COMMITTEE_SIZE) return false;
        contributor_vk.assign(nk, {});
        for (uint32_t i = 0; i < nk; ++i)
            if (!pull_bytes(in, off, contributor_vk[i])) return false;
    }

    if (off != in.size()) return false;
    return true;
}

bool dao_tally_key_record::serialize(std::vector<uint8_t>& out) const
{
    // A record that carries CL parameters goes on the wire in the
    // CL-only form; it must not carry Paillier placeholders.
    if (!cl_modulus.empty()) return serialize_cl(out);

    // Strict canonical layout. Every field is length-prefixed or
    // fixed-width, in a single well-defined order.
    if (committee_id_hash.size() != 32) return false;
    if (committee_members.size() != committee_size) return false;
    for (const auto& m : committee_members)
        if (m.size() != 32) return false;
    if (delta.size() != 32) return false;
    if (N.size() != PAILLIER_MODULUS_BYTES) return false;
    if (G.size() != PAILLIER_MODULUS_BYTES) return false;
    if (theta.size() != PAILLIER_MODULUS_BYTES) return false;
    if (V.size() != PAILLIER_CT_BYTES) return false;
    if (V_K_i.size() != committee_size) return false;
    for (const auto& vk : V_K_i)
        if (vk.size() != PAILLIER_CT_BYTES) return false;
    if (dkg_transcript_hash.size() != 32) return false;
    if (key_id.size() != 32) return false;

    out.clear();
    push_u32(out, version);
    push_u32(out, committee_size);
    push_u32(out, threshold);
    push_u32(out, t);
    out.insert(out.end(), committee_id_hash.begin(), committee_id_hash.end());
    for (const auto& m : committee_members)
        out.insert(out.end(), m.begin(), m.end());
    out.insert(out.end(), delta.begin(), delta.end());
    out.insert(out.end(), N.begin(), N.end());
    out.insert(out.end(), G.begin(), G.end());
    out.insert(out.end(), theta.begin(), theta.end());
    out.insert(out.end(), V.begin(), V.end());
    for (const auto& vk : V_K_i)
        out.insert(out.end(), vk.begin(), vk.end());
    push_bytes(out, vss_P);
    push_bytes(out, vss_P_prime);
    push_bytes(out, vss_g);
    push_bytes(out, vss_h);
    push_u64(out, activation_height);
    out.insert(out.end(), dkg_transcript_hash.begin(), dkg_transcript_hash.end());
    out.insert(out.end(), key_id.begin(), key_id.end());

    // Trailing field: CL public parameters. Empty is accepted for
    // legacy records only.
    push_bytes(out, cl_modulus);
    return true;
}

bool dao_tally_key_record::serialize_cl(std::vector<uint8_t>& out) const
{
    if (cl_modulus.empty()) return false;
    if (key_id.size() != 32) return false;
    if (committee_id_hash.size() != 32) return false;
    if (dkg_transcript_hash.size() != 32) return false;
    if (committee_members.size() != committee_size) return false;
    for (const auto& m : committee_members)
        if (m.size() != 32) return false;
    if (threshold == 0 || threshold > committee_size) return false;
    if (cl_modulus.size() >= 65536u) return false;

    out.clear();
    push_u32(out, CL_WIRE_VERSION);
    push_u32(out, committee_size);
    push_u32(out, threshold);
    push_u32(out, t);
    out.insert(out.end(), committee_id_hash.begin(), committee_id_hash.end());
    push_u32(out, static_cast<uint32_t>(committee_members.size()));
    for (const auto& m : committee_members)
        out.insert(out.end(), m.begin(), m.end());
    push_bytes(out, cl_modulus);
    push_u64(out, activation_height);
    out.insert(out.end(), dkg_transcript_hash.begin(), dkg_transcript_hash.end());
    out.insert(out.end(), key_id.begin(), key_id.end());
    return true;
}

bool dao_tally_key_record::deserialize_cl(const std::vector<uint8_t>& in)
{
    // CL-only reader. The caller must be certain the record is CL
    // (either by inspecting the first u32, or from context).
    size_t off = 0;
    uint32_t v = 0, cs = 0, th = 0, tt = 0, nc = 0;
    if (!pull_u32(in, off, v)) return false;
    if (v != CL_WIRE_VERSION) return false;
    if (!pull_u32(in, off, cs)) return false;
    if (cs == 0 || cs > 64) return false;
    if (!pull_u32(in, off, th)) return false;
    if (!pull_u32(in, off, tt)) return false;
    if (off + 32 > in.size()) return false;
    committee_id_hash.assign(in.begin() + off, in.begin() + off + 32);
    off += 32;
    if (!pull_u32(in, off, nc)) return false;
    if (nc != cs) return false;
    committee_members.assign(cs, {});
    for (uint32_t i = 0; i < cs; ++i) {
        if (off + 32 > in.size()) return false;
        committee_members[i].assign(in.begin() + off,
                                    in.begin() + off + 32);
        off += 32;
    }
    if (!pull_bytes(in, off, cl_modulus)) return false;
    if (cl_modulus.empty()) return false;
    if (!pull_u64(in, off, activation_height)) return false;
    if (off + 32 > in.size()) return false;
    dkg_transcript_hash.assign(in.begin() + off, in.begin() + off + 32);
    off += 32;
    if (off + 32 > in.size()) return false;
    key_id.assign(in.begin() + off, in.begin() + off + 32);
    off += 32;
    if (off != in.size()) return false;

    version        = CL_WIRE_VERSION;
    committee_size = cs;
    threshold      = th;
    t              = tt;
    // Clear Paillier fields on a CL record.
    delta.clear();
    N.clear();
    G.clear();
    theta.clear();
    V.clear();
    V_K_i.clear();
    vss_P.clear();
    vss_P_prime.clear();
    vss_g.clear();
    vss_h.clear();
    return true;
}

bool dao_tally_key_record::deserialize(const std::vector<uint8_t>& in)
{
    if (in.size() >= 4) {
        uint32_t peek = static_cast<uint32_t>(in[0])
                      | (static_cast<uint32_t>(in[1]) << 8)
                      | (static_cast<uint32_t>(in[2]) << 16)
                      | (static_cast<uint32_t>(in[3]) << 24);
        if (peek == CL_WIRE_VERSION) return deserialize_cl(in);
    }

    size_t off = 0;
    uint32_t v = 0, cs = 0, th = 0, tt = 0;
    if (!pull_u32(in, off, v)) return false;
    if (!pull_u32(in, off, cs)) return false;
    if (!pull_u32(in, off, th)) return false;
    if (!pull_u32(in, off, tt)) return false;
    if (cs == 0 || cs > 64) return false;

    auto pull_fixed = [&](size_t n, std::vector<uint8_t>& dest) -> bool {
        if (off + n > in.size()) return false;
        dest.assign(in.begin() + off, in.begin() + off + n);
        off += n;
        return true;
    };

    if (!pull_fixed(32, committee_id_hash)) return false;
    committee_members.assign(cs, {});
    for (uint32_t i = 0; i < cs; ++i)
        if (!pull_fixed(32, committee_members[i])) return false;
    if (!pull_fixed(32, delta)) return false;
    if (!pull_fixed(PAILLIER_MODULUS_BYTES, N)) return false;
    if (!pull_fixed(PAILLIER_MODULUS_BYTES, G)) return false;
    if (!pull_fixed(PAILLIER_MODULUS_BYTES, theta)) return false;
    if (!pull_fixed(PAILLIER_CT_BYTES, V)) return false;
    V_K_i.assign(cs, {});
    for (uint32_t i = 0; i < cs; ++i)
        if (!pull_fixed(PAILLIER_CT_BYTES, V_K_i[i])) return false;

    if (!pull_bytes(in, off, vss_P)) return false;
    if (!pull_bytes(in, off, vss_P_prime)) return false;
    if (!pull_bytes(in, off, vss_g)) return false;
    if (!pull_bytes(in, off, vss_h)) return false;
    if (!pull_u64(in, off, activation_height)) return false;
    if (!pull_fixed(32, dkg_transcript_hash)) return false;
    if (!pull_fixed(32, key_id)) return false;

    // Trailing field: CL public parameters. Absent is accepted for
    // legacy records only.
    if (off < in.size()) {
        if (!pull_bytes(in, off, cl_modulus)) return false;
    } else {
        cl_modulus.clear();
    }
    if (off != in.size()) return false;

    version = v;
    committee_size = cs;
    threshold = th;
    t = tt;
    return true;
}

// ====================================================================
// Local share envelope
// ====================================================================

std::vector<uint8_t> dao_pack_local_share(
    const std::vector<uint8_t>& key_id,
    const std::vector<uint8_t>& raw_share)
{
    if (key_id.size() != 32) return {};
    if (raw_share.empty()) return {};
    std::vector<uint8_t> out;
    out.reserve(1 + 32 + raw_share.size());
    out.push_back(DAO_LOCAL_SHARE_ENVELOPE_VERSION);
    out.insert(out.end(), key_id.begin(), key_id.end());
    out.insert(out.end(), raw_share.begin(), raw_share.end());
    return out;
}

bool dao_unpack_local_share(
    const std::vector<uint8_t>& packed,
    const std::vector<uint8_t>& expected_key_id,
    std::vector<uint8_t>& raw_out)
{
    if (expected_key_id.size() != 32) return false;
    if (packed.size() < 1 + 32) return false;
    if (packed[0] != DAO_LOCAL_SHARE_ENVELOPE_VERSION) return false;
    if (std::memcmp(packed.data() + 1, expected_key_id.data(), 32) != 0)
        return false;
    raw_out.assign(packed.begin() + 1 + 32, packed.end());
    return !raw_out.empty();
}

// ====================================================================
// Activation digest
// ====================================================================

crypto::hash dao_dkg_activation_digest(
    const crypto::hash& genesis_block_hash,
    uint64_t selection_height,
    const dao_tally_key_record& record,
    const crypto::hash& proposal_id)
{
    std::vector<uint8_t> body;
    const char* dom = "VeilRoot-DAO-DKG-KEY-ACTIVATION-V2";
    body.insert(body.end(), dom, dom + std::strlen(dom));
    body.insert(body.end(), genesis_block_hash.data,
                genesis_block_hash.data + sizeof(genesis_block_hash.data));
    for (int i = 0; i < 8; ++i)
        body.push_back((selection_height >> (8 * i)) & 0xff);
    body.insert(body.end(), proposal_id.data, proposal_id.data + 32);

    std::vector<uint8_t> rec_blob;
    if (!record.serialize(rec_blob))
        return crypto::null_hash;
    body.insert(body.end(), rec_blob.begin(), rec_blob.end());

    crypto::hash h{};
    crypto::cn_fast_hash(body.data(), body.size(), h);
    return h;
}

crypto::hash dao_dkg_activation_digest_v3(
    const crypto::hash& genesis_block_hash,
    uint64_t selection_height,
    const dao_tally_key_record& record,
    const dao_share_set_record& initial_share_set,
    const crypto::hash& proposal_id)
{
    std::vector<uint8_t> body;
    const char* dom = "VeilRoot-DAO-DKG-KEY-ACTIVATION-V3";
    body.insert(body.end(), dom, dom + std::strlen(dom));
    body.insert(body.end(), genesis_block_hash.data,
                genesis_block_hash.data + sizeof(genesis_block_hash.data));
    for (int i = 0; i < 8; ++i)
        body.push_back((selection_height >> (8 * i)) & 0xff);
    body.insert(body.end(), proposal_id.data, proposal_id.data + 32);

    std::vector<uint8_t> rec_blob;
    if (!record.serialize(rec_blob))
        return crypto::null_hash;
    body.insert(body.end(), rec_blob.begin(), rec_blob.end());

    std::vector<uint8_t> ss_blob;
    if (!initial_share_set.serialize(ss_blob))
        return crypto::null_hash;
    body.insert(body.end(), ss_blob.begin(), ss_blob.end());

    crypto::hash h{};
    crypto::cn_fast_hash(body.data(), body.size(), h);
    return h;
}

// ====================================================================
// dao_dkg_key_attestation
// ====================================================================

bool dao_dkg_key_attestation::serialize(std::vector<uint8_t>& out) const
{
    if (signature.size() != sizeof(crypto::signature)) return false;
    out.clear();
    push_u32(out, member_index);
    push_bytes(out, signature);
    return true;
}

bool dao_dkg_key_attestation::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    uint32_t mi = 0;
    if (!pull_u32(in, off, mi)) return false;
    if (!pull_bytes(in, off, signature)) return false;
    if (signature.size() != sizeof(crypto::signature)) return false;
    if (off != in.size()) return false;
    member_index = mi;
    return true;
}

// ====================================================================
// dao_dkg_key_activation
// ====================================================================

bool dao_dkg_key_activation::serialize(std::vector<uint8_t>& out) const
{
    out.clear();

    if (version != 2 && version != 3) return false;
    if (attestations.size() > 64) return false;

    // Validate attestation ordering before writing.
    uint32_t prev = 0;
    for (const auto& a : attestations) {
        if (a.member_index == 0) return false;
        if (a.member_index <= prev) return false;   // strictly ascending
        if (a.signature.size() != sizeof(crypto::signature)) return false;
        prev = a.member_index;
    }

    std::vector<uint8_t> rec_blob;
    if (!record.serialize(rec_blob)) return false;

    push_u32(out, version);
    push_u64(out, selection_height);
    out.insert(out.end(), proposal_id.data, proposal_id.data + 32);
    push_bytes(out, rec_blob);

    if (version == 3) {
        std::vector<uint8_t> ss_blob;
        if (!initial_share_set.serialize(ss_blob)) return false;
        push_bytes(out, ss_blob);
    }

    push_u32(out, static_cast<uint32_t>(attestations.size()));
    for (const auto& a : attestations) {
        push_u32(out, a.member_index);
        push_bytes(out, a.signature);
    }
    return true;
}

bool dao_dkg_key_activation::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    uint32_t v = 0;
    if (!pull_u32(in, off, v)) return false;
    if (v != 2 && v != 3) return false;
    version = v;
    initial_share_set = dao_share_set_record{};
    if (!pull_u64(in, off, selection_height)) return false;
    if (off + 32 > in.size()) return false;
    std::memcpy(proposal_id.data, in.data() + off, 32);
    off += 32;

    std::vector<uint8_t> rec_blob;
    if (!pull_bytes(in, off, rec_blob)) return false;
    if (!record.deserialize(rec_blob)) return false;

    if (v == 3) {
        std::vector<uint8_t> ss_blob;
        if (!pull_bytes(in, off, ss_blob)) return false;
        if (!initial_share_set.deserialize(ss_blob)) return false;
    }

    uint32_t n = 0;
    if (!pull_u32(in, off, n)) return false;
    if (n > 64) return false;

    attestations.clear();
    attestations.reserve(n);

    uint32_t prev = 0;
    for (uint32_t i = 0; i < n; ++i) {
        dao_dkg_key_attestation a;
        uint32_t mi = 0;
        if (!pull_u32(in, off, mi)) return false;
        if (mi == 0) return false;
        if (mi <= prev) return false;   // strictly ascending, unique
        if (mi > record.committee_size) return false;
        if (!pull_bytes(in, off, a.signature)) return false;
        if (a.signature.size() != sizeof(crypto::signature)) return false;
        a.member_index = mi;
        prev = mi;
        attestations.push_back(std::move(a));
    }

    if (off != in.size()) return false;
    version = v;
    return true;
}

bool dkg_result::to_record(std::vector<uint8_t>& out) const
{
    if (!ok) return false;
    return record.serialize(out);
}

// ====================================================================
// Party state machine
// ====================================================================

;

// -------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------

namespace {

constexpr const char* DAO_DKG_TRANSCRIPT_LEAF_DOMAIN =
    "VeilRoot-DAO-DKG-TRANSCRIPT-LEAF-V1";

inline void transcript_push_u32(std::vector<uint8_t>& b, uint32_t v)
{
    for (int i = 0; i < 4; ++i) b.push_back((v >> (8*i)) & 0xff);
}

inline void transcript_push_u64(std::vector<uint8_t>& b, uint64_t v)
{
    for (int i = 0; i < 8; ++i) b.push_back((v >> (8*i)) & 0xff);
}


} // namespace


// -------------------------------------------------------------------
// Phase A: generate polynomial commitments + distribute shares
// -------------------------------------------------------------------


// -------------------------------------------------------------------
// Phase B: form N_i = (sum_j p_j_i)(sum_j q_j_i) + (sum_j h_j_i)
// -------------------------------------------------------------------


// -------------------------------------------------------------------
// Phase C: publish Q_i (biprimality)
// -------------------------------------------------------------------


// -------------------------------------------------------------------
// Compute the party's share of p and q from received VSS shares.
// -------------------------------------------------------------------


// -------------------------------------------------------------------
// §4.1 trial division. Fresh VSS of the per-party randomizers.
// `r` selects which small prime this phase is testing. r == 0 uses
// share_p_; r == 1 uses share_q_.
// -------------------------------------------------------------------


// -------------------------------------------------------------------
// start_phase / handle_message
// -------------------------------------------------------------------


// ====================================================================
// §5 threshold key derivation
// ====================================================================


// ====================================================================
// Driver
// ====================================================================

namespace {

// Interpolate N from the party shares N_i via Lagrange at zero over
// the integers. The shares are values of the degree-2t polynomial
// alpha(x), and we want alpha(0).


} // anonymous namespace

// ====================================================================
// Test-only accessors used by the in-process driver
//
// These exist because the driver runs all parties in one process and
// must coordinate the phases. They do NOT expose secret material:
// only the values the protocol itself broadcasts or aggregates.
// ====================================================================

namespace {

// Extract the N_i value a party computed in phase 2.

// Extract the Q_i value a party computed in phase 4.

// Extract the lambda share from phase 6.

} // anonymous namespace

// ====================================================================
// Public entry points
// ====================================================================


// -------------------------------------------------------------------
// Gap 4: canonical DKG transcript
// -------------------------------------------------------------------

bool dao_theta_mul_proof::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    if (!push_bytes(out, T1)) return false;
    if (!push_bytes(out, T2)) return false;
    if (!push_bytes(out, z_b)) return false;
    if (!push_bytes(out, z_rho)) return false;
    if (!push_bytes(out, z_k)) return false;
    return true;
}

bool dao_theta_mul_proof::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    if (!pull_bytes(in, off, T1)) return false;
    if (!pull_bytes(in, off, T2)) return false;
    if (!pull_bytes(in, off, z_b)) return false;
    if (!pull_bytes(in, off, z_rho)) return false;
    if (!pull_bytes(in, off, z_k)) return false;
    return off == in.size();
}

bool dao_theta_open_proof::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    if (!push_bytes(out, T)) return false;
    if (!push_bytes(out, z_theta)) return false;
    if (!push_bytes(out, z_r)) return false;
    return true;
}

bool dao_theta_open_proof::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    if (!pull_bytes(in, off, T)) return false;
    if (!pull_bytes(in, off, z_theta)) return false;
    if (!pull_bytes(in, off, z_r)) return false;
    return off == in.size();
}

// Aggregate the per-sender commitment vector, then evaluate at point i:
//   out = prod_j prod_k (C_j_k)^(i^k)  mod P
// Assumes every per_party[j].C has the same length (same VSS degree).
static bool aggregate_eval_at(
    const std::vector<dao_vss_commitments>& per_party,
    const dao_vss_group& grp,
    uint32_t i,
    BIGNUM* out)
{
    if (!out) return false;
    if (!grp.valid()) return false;
    if (per_party.size() < 2) return false;
    if (per_party[1].C.empty()) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    const uint32_t t = static_cast<uint32_t>(per_party[1].C.size()) - 1;

    BIGNUM* acc = BN_new();
    BIGNUM* pow_bn = BN_new();
    if (!acc || !pow_bn) { BN_free(acc); BN_free(pow_bn); return false; }
    BN_one(acc);
    BN_one(pow_bn);

    for (uint32_t k = 0; k <= t; ++k) {
        BIGNUM* coeff = BN_new();
        BN_one(coeff);
        for (size_t j = 1; j < per_party.size(); ++j) {
            if (k >= per_party[j].C.size()) {
                BN_free(coeff); BN_free(acc); BN_free(pow_bn);
                return false;
            }
            BIGNUM* Ck = BN_bin2bn(per_party[j].C[k].data(),
                                   static_cast<int>(per_party[j].C[k].size()),
                                   nullptr);
            if (!Ck || !BN_mod_mul(coeff, coeff, Ck, grp.P, ctx.ctx)) {
                BN_free(Ck); BN_free(coeff);
                BN_free(acc); BN_free(pow_bn);
                return false;
            }
            BN_free(Ck);
        }
        BIGNUM* term = BN_new();
        if (!term || !BN_mod_exp(term, coeff, pow_bn, grp.P, ctx.ctx)) {
            BN_free(term); BN_free(coeff);
            BN_free(acc); BN_free(pow_bn);
            return false;
        }
        if (!BN_mod_mul(acc, acc, term, grp.P, ctx.ctx)) {
            BN_free(term); BN_free(coeff);
            BN_free(acc); BN_free(pow_bn);
            return false;
        }
        BN_free(term); BN_free(coeff);
        if (k < t) {
            BN_mul_word(pow_bn, i);
            BN_mod(pow_bn, pow_bn, grp.P_prime, ctx.ctx);
        }
    }

    BN_copy(out, acc);
    BN_free(acc); BN_free(pow_bn);
    return true;
}


// ---------------------------------------------------------------
// Gap 3: Theta(i) correctness proofs
// ---------------------------------------------------------------

static void fs_append_u32be(std::vector<uint8_t>& v, uint32_t x)
{
    v.push_back(static_cast<uint8_t>((x >> 24) & 0xff));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xff));
    v.push_back(static_cast<uint8_t>((x >>  8) & 0xff));
    v.push_back(static_cast<uint8_t>((x      ) & 0xff));
}

static void fs_append_bn_len_pref(std::vector<uint8_t>& v, const BIGNUM* x)
{
    const int n = x ? BN_num_bytes(x) : 0;
    fs_append_u32be(v, static_cast<uint32_t>(n));
    if (n > 0) {
        const size_t off = v.size();
        v.resize(off + n);
        BN_bn2bin(x, v.data() + off);
    }
}

static void fs_sha256_to_bn(const std::vector<uint8_t>& buf, BIGNUM* out)
{
    uint8_t h[32];
    SHA256(buf.data(), buf.size(), h);
    BN_bin2bn(h, 32, out);
}

bool dao_theta_mul_prove(
    const dao_vss_group& grp,
    uint32_t candidate_id,
    uint32_t party_id,
    const BIGNUM* N,
    const BIGNUM* C_phi_i,
    const BIGNUM* C_beta_i,
    const BIGNUM* beta_i,
    const BIGNUM* r_beta_i,
    const BIGNUM* k,
    const BIGNUM* C_prod,
    dao_theta_mul_proof& proof)
{
    if (!grp.valid() || !N || !C_phi_i || !C_beta_i ||
        !beta_i || !r_beta_i || !k || !C_prod) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* a_b   = BN_new();
    BIGNUM* a_rho = BN_new();
    BIGNUM* a_k   = BN_new();
    if (!a_b || !a_rho || !a_k) {
        BN_free(a_b); BN_free(a_rho); BN_free(a_k); return false;
    }
    BN_rand_range(a_b,   grp.P_prime);
    BN_rand_range(a_rho, grp.P_prime);
    BN_rand_range(a_k,   grp.P_prime);

    BIGNUM* T1 = BN_new();
    BIGNUM* T2 = BN_new();
    {
        BIGNUM* t1a = BN_new(); BIGNUM* t1b = BN_new();
        BIGNUM* t2a = BN_new(); BIGNUM* t2b = BN_new();
        bool ok = t1a && t1b && t2a && t2b;
        ok = ok && BN_mod_exp(t1a, grp.g,   a_b,   grp.P, ctx.ctx);
        ok = ok && BN_mod_exp(t1b, grp.h,   a_rho, grp.P, ctx.ctx);
        ok = ok && BN_mod_mul(T1,  t1a,     t1b,   grp.P, ctx.ctx);
        ok = ok && BN_mod_exp(t2a, C_phi_i, a_b,   grp.P, ctx.ctx);
        ok = ok && BN_mod_exp(t2b, grp.h,   a_k,   grp.P, ctx.ctx);
        ok = ok && BN_mod_mul(T2,  t2a,     t2b,   grp.P, ctx.ctx);
        BN_free(t1a); BN_free(t1b); BN_free(t2a); BN_free(t2b);
        if (!ok) {
            BN_free(a_b); BN_free(a_rho); BN_free(a_k);
            BN_free(T1);  BN_free(T2);
            return false;
        }
    }

    std::vector<uint8_t> buf;
    const char* dom = "VeilRoot-DAO-DKG-THETA-MUL-V1";
    buf.insert(buf.end(), dom, dom + std::strlen(dom));
    fs_append_u32be(buf, candidate_id);
    fs_append_u32be(buf, party_id);
    fs_append_bn_len_pref(buf, N);
    fs_append_bn_len_pref(buf, grp.P);
    fs_append_bn_len_pref(buf, grp.P_prime);
    fs_append_bn_len_pref(buf, grp.g);
    fs_append_bn_len_pref(buf, grp.h);
    fs_append_bn_len_pref(buf, C_phi_i);
    fs_append_bn_len_pref(buf, C_beta_i);
    fs_append_bn_len_pref(buf, C_prod);
    fs_append_bn_len_pref(buf, T1);
    fs_append_bn_len_pref(buf, T2);

    BIGNUM* e = BN_new();
    if (!e) {
        BN_free(a_b); BN_free(a_rho); BN_free(a_k);
        BN_free(T1);  BN_free(T2); return false;
    }
    fs_sha256_to_bn(buf, e);

    BIGNUM* z_b   = BN_new();
    BIGNUM* z_rho = BN_new();
    BIGNUM* z_k   = BN_new();
    if (!z_b || !z_rho || !z_k) {
        BN_free(a_b); BN_free(a_rho); BN_free(a_k);
        BN_free(T1);  BN_free(T2);    BN_free(e);
        BN_free(z_b); BN_free(z_rho); BN_free(z_k);
        return false;
    }
    BN_mod_mul(z_b,   e, beta_i,   grp.P_prime, ctx.ctx);
    BN_mod_add(z_b,   z_b, a_b,    grp.P_prime, ctx.ctx);
    BN_mod_mul(z_rho, e, r_beta_i, grp.P_prime, ctx.ctx);
    BN_mod_add(z_rho, z_rho, a_rho, grp.P_prime, ctx.ctx);
    BN_mod_mul(z_k,   e, k,        grp.P_prime, ctx.ctx);
    BN_mod_add(z_k,   z_k, a_k,    grp.P_prime, ctx.ctx);

    auto bn_to_vec = [](const BIGNUM* x, std::vector<uint8_t>& out) {
        const int nb = BN_num_bytes(x);
        out.assign(nb, 0);
        BN_bn2bin(x, out.data());
    };
    bn_to_vec(T1, proof.T1);
    bn_to_vec(T2, proof.T2);
    bn_to_vec(z_b,   proof.z_b);
    bn_to_vec(z_rho, proof.z_rho);
    bn_to_vec(z_k,   proof.z_k);

    BN_free(a_b); BN_free(a_rho); BN_free(a_k);
    BN_free(T1);  BN_free(T2);    BN_free(e);
    BN_free(z_b); BN_free(z_rho); BN_free(z_k);
    return true;
}

bool dao_theta_mul_verify(
    const dao_vss_group& grp,
    uint32_t candidate_id,
    uint32_t party_id,
    const BIGNUM* N,
    const BIGNUM* C_phi_i,
    const BIGNUM* C_beta_i,
    const BIGNUM* C_prod,
    const dao_theta_mul_proof& proof)
{
    if (!grp.valid() || !N || !C_phi_i || !C_beta_i || !C_prod)
        return false;
    if (proof.T1.empty() || proof.T2.empty() ||
        proof.z_b.empty() || proof.z_rho.empty() || proof.z_k.empty())
        return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* T1    = BN_bin2bn(proof.T1.data(),
                              static_cast<int>(proof.T1.size()), nullptr);
    BIGNUM* T2    = BN_bin2bn(proof.T2.data(),
                              static_cast<int>(proof.T2.size()), nullptr);
    BIGNUM* z_b   = BN_bin2bn(proof.z_b.data(),
                              static_cast<int>(proof.z_b.size()), nullptr);
    BIGNUM* z_rho = BN_bin2bn(proof.z_rho.data(),
                              static_cast<int>(proof.z_rho.size()), nullptr);
    BIGNUM* z_k   = BN_bin2bn(proof.z_k.data(),
                              static_cast<int>(proof.z_k.size()), nullptr);
    if (!T1 || !T2 || !z_b || !z_rho || !z_k) {
        BN_free(T1); BN_free(T2);
        BN_free(z_b); BN_free(z_rho); BN_free(z_k);
        return false;
    }

    std::vector<uint8_t> buf;
    const char* dom = "VeilRoot-DAO-DKG-THETA-MUL-V1";
    buf.insert(buf.end(), dom, dom + std::strlen(dom));
    fs_append_u32be(buf, candidate_id);
    fs_append_u32be(buf, party_id);
    fs_append_bn_len_pref(buf, N);
    fs_append_bn_len_pref(buf, grp.P);
    fs_append_bn_len_pref(buf, grp.P_prime);
    fs_append_bn_len_pref(buf, grp.g);
    fs_append_bn_len_pref(buf, grp.h);
    fs_append_bn_len_pref(buf, C_phi_i);
    fs_append_bn_len_pref(buf, C_beta_i);
    fs_append_bn_len_pref(buf, C_prod);
    fs_append_bn_len_pref(buf, T1);
    fs_append_bn_len_pref(buf, T2);

    BIGNUM* e = BN_new();
    if (!e) {
        BN_free(T1); BN_free(T2);
        BN_free(z_b); BN_free(z_rho); BN_free(z_k);
        return false;
    }
    fs_sha256_to_bn(buf, e);

    bool ok = true;
    // Eq 1: g^z_b * h^z_rho == T1 * C_beta_i^e
    {
        BIGNUM* lhs_a = BN_new(); BIGNUM* lhs_b = BN_new();
        BIGNUM* lhs   = BN_new();
        BIGNUM* rhs_b = BN_new(); BIGNUM* rhs   = BN_new();
        ok = lhs_a && lhs_b && lhs && rhs_b && rhs;
        ok = ok && BN_mod_exp(lhs_a, grp.g,   z_b,   grp.P, ctx.ctx);
        ok = ok && BN_mod_exp(lhs_b, grp.h,   z_rho, grp.P, ctx.ctx);
        ok = ok && BN_mod_mul(lhs,   lhs_a,   lhs_b, grp.P, ctx.ctx);
        ok = ok && BN_mod_exp(rhs_b, C_beta_i, e,    grp.P, ctx.ctx);
        ok = ok && BN_mod_mul(rhs,   T1,      rhs_b, grp.P, ctx.ctx);
        if (ok) ok = (BN_cmp(lhs, rhs) == 0);
        BN_free(lhs_a); BN_free(lhs_b); BN_free(lhs);
        BN_free(rhs_b); BN_free(rhs);
    }
    // Eq 2: C_phi_i^z_b * h^z_k == T2 * C_prod^e
    if (ok) {
        BIGNUM* lhs_a = BN_new(); BIGNUM* lhs_b = BN_new();
        BIGNUM* lhs   = BN_new();
        BIGNUM* rhs_b = BN_new(); BIGNUM* rhs   = BN_new();
        ok = lhs_a && lhs_b && lhs && rhs_b && rhs;
        ok = ok && BN_mod_exp(lhs_a, C_phi_i, z_b, grp.P, ctx.ctx);
        ok = ok && BN_mod_exp(lhs_b, grp.h,   z_k, grp.P, ctx.ctx);
        ok = ok && BN_mod_mul(lhs,   lhs_a,   lhs_b, grp.P, ctx.ctx);
        ok = ok && BN_mod_exp(rhs_b, C_prod,  e, grp.P, ctx.ctx);
        ok = ok && BN_mod_mul(rhs,   T2,      rhs_b, grp.P, ctx.ctx);
        if (ok) ok = (BN_cmp(lhs, rhs) == 0);
        BN_free(lhs_a); BN_free(lhs_b); BN_free(lhs);
        BN_free(rhs_b); BN_free(rhs);
    }

    BN_free(T1); BN_free(T2); BN_free(e);
    BN_free(z_b); BN_free(z_rho); BN_free(z_k);
    return ok;
}

bool dao_theta_open_prove(
    const dao_vss_group& grp,
    uint32_t candidate_id,
    uint32_t party_id,
    const BIGNUM* C_theta_i,
    const BIGNUM* theta_i,
    const BIGNUM* r_theta_i,
    dao_theta_open_proof& proof)
{
    if (!grp.valid() || !C_theta_i || !theta_i || !r_theta_i) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* a_theta = BN_new();
    BIGNUM* a_r     = BN_new();
    if (!a_theta || !a_r) {
        BN_free(a_theta); BN_free(a_r); return false;
    }
    BN_rand_range(a_theta, grp.P_prime);
    BN_rand_range(a_r,     grp.P_prime);

    BIGNUM* T = BN_new();
    {
        BIGNUM* ta = BN_new(); BIGNUM* tb = BN_new();
        bool ok = ta && tb;
        ok = ok && BN_mod_exp(ta, grp.g, a_theta, grp.P, ctx.ctx);
        ok = ok && BN_mod_exp(tb, grp.h, a_r,     grp.P, ctx.ctx);
        ok = ok && BN_mod_mul(T,  ta,    tb,      grp.P, ctx.ctx);
        BN_free(ta); BN_free(tb);
        if (!ok) {
            BN_free(a_theta); BN_free(a_r); BN_free(T);
            return false;
        }
    }

    std::vector<uint8_t> buf;
    const char* dom = "VeilRoot-DAO-DKG-THETA-OPEN-V1";
    buf.insert(buf.end(), dom, dom + std::strlen(dom));
    fs_append_u32be(buf, candidate_id);
    fs_append_u32be(buf, party_id);
    fs_append_bn_len_pref(buf, grp.P);
    fs_append_bn_len_pref(buf, grp.P_prime);
    fs_append_bn_len_pref(buf, grp.g);
    fs_append_bn_len_pref(buf, grp.h);
    fs_append_bn_len_pref(buf, C_theta_i);
    fs_append_bn_len_pref(buf, theta_i);
    fs_append_bn_len_pref(buf, T);

    BIGNUM* e = BN_new();
    if (!e) {
        BN_free(a_theta); BN_free(a_r); BN_free(T);
        return false;
    }
    fs_sha256_to_bn(buf, e);

    BIGNUM* z_theta = BN_new();
    BIGNUM* z_r     = BN_new();
    if (!z_theta || !z_r) {
        BN_free(a_theta); BN_free(a_r); BN_free(T); BN_free(e);
        BN_free(z_theta); BN_free(z_r);
        return false;
    }
    BN_mod_mul(z_theta, e, theta_i,   grp.P_prime, ctx.ctx);
    BN_mod_add(z_theta, z_theta, a_theta, grp.P_prime, ctx.ctx);
    BN_mod_mul(z_r,     e, r_theta_i, grp.P_prime, ctx.ctx);
    BN_mod_add(z_r,     z_r, a_r,     grp.P_prime, ctx.ctx);

    auto bn_to_vec = [](const BIGNUM* x, std::vector<uint8_t>& out) {
        const int nb = BN_num_bytes(x);
        out.assign(nb, 0);
        BN_bn2bin(x, out.data());
    };
    bn_to_vec(T,       proof.T);
    bn_to_vec(z_theta, proof.z_theta);
    bn_to_vec(z_r,     proof.z_r);

    BN_free(a_theta); BN_free(a_r); BN_free(T); BN_free(e);
    BN_free(z_theta); BN_free(z_r);
    return true;
}

bool dao_theta_open_verify(
    const dao_vss_group& grp,
    uint32_t candidate_id,
    uint32_t party_id,
    const BIGNUM* C_theta_i,
    const BIGNUM* theta_i,
    const dao_theta_open_proof& proof)
{
    if (!grp.valid() || !C_theta_i || !theta_i) return false;
    if (proof.T.empty() || proof.z_theta.empty() || proof.z_r.empty())
        return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* T = BN_bin2bn(proof.T.data(),
                          static_cast<int>(proof.T.size()), nullptr);
    BIGNUM* z_theta = BN_bin2bn(proof.z_theta.data(),
                                static_cast<int>(proof.z_theta.size()), nullptr);
    BIGNUM* z_r = BN_bin2bn(proof.z_r.data(),
                            static_cast<int>(proof.z_r.size()), nullptr);
    if (!T || !z_theta || !z_r) {
        BN_free(T); BN_free(z_theta); BN_free(z_r);
        return false;
    }

    std::vector<uint8_t> buf;
    const char* dom = "VeilRoot-DAO-DKG-THETA-OPEN-V1";
    buf.insert(buf.end(), dom, dom + std::strlen(dom));
    fs_append_u32be(buf, candidate_id);
    fs_append_u32be(buf, party_id);
    fs_append_bn_len_pref(buf, grp.P);
    fs_append_bn_len_pref(buf, grp.P_prime);
    fs_append_bn_len_pref(buf, grp.g);
    fs_append_bn_len_pref(buf, grp.h);
    fs_append_bn_len_pref(buf, C_theta_i);
    fs_append_bn_len_pref(buf, theta_i);
    fs_append_bn_len_pref(buf, T);

    BIGNUM* e = BN_new();
    if (!e) { BN_free(T); BN_free(z_theta); BN_free(z_r); return false; }
    fs_sha256_to_bn(buf, e);

    // g^z_theta * h^z_r == T * C_theta_i^e
    bool ok = true;
    BIGNUM* lhs_a = BN_new(); BIGNUM* lhs_b = BN_new();
    BIGNUM* lhs   = BN_new();
    BIGNUM* rhs_b = BN_new(); BIGNUM* rhs   = BN_new();
    ok = lhs_a && lhs_b && lhs && rhs_b && rhs;
    ok = ok && BN_mod_exp(lhs_a, grp.g,   z_theta, grp.P, ctx.ctx);
    ok = ok && BN_mod_exp(lhs_b, grp.h,   z_r,     grp.P, ctx.ctx);
    ok = ok && BN_mod_mul(lhs,   lhs_a,   lhs_b,   grp.P, ctx.ctx);
    ok = ok && BN_mod_exp(rhs_b, C_theta_i, e,     grp.P, ctx.ctx);
    ok = ok && BN_mod_mul(rhs,   T,       rhs_b,   grp.P, ctx.ctx);
    if (ok) ok = (BN_cmp(lhs, rhs) == 0);
    BN_free(lhs_a); BN_free(lhs_b); BN_free(lhs);
    BN_free(rhs_b); BN_free(rhs);

    BN_free(T); BN_free(z_theta); BN_free(z_r); BN_free(e);
    return ok;
}


namespace {

// Drain every transport until no more messages are pending. Every
// drained message is recorded in the canonical transcript.


// Route collected messages to all parties whose id matches the
// recipient (or to all if recipient is 0).


// Reconstruct N from the N_i values via Lagrange interpolation over
// the integers at x=0. Uses any (2t+1) = 15 of the 16 shares.


// Perform one candidate attempt: phases 1-2 and reconstruction of N.
// Returns true if a candidate N was reconstructed.


// Choose g_bar with Jacobi(g_bar, N) = +1.
bool choose_g_bar(const BIGNUM* N, BIGNUM* out)
{
    CtxGuard ctx;
    if (!ctx.ok()) return false;

    for (int tries = 0; tries < 128; ++tries) {
        if (!BN_rand_range(out, N)) return false;
        if (BN_is_zero(out)) continue;
        if (BN_is_one(out)) continue;
        BIGNUM* gcd = BN_new();
        BN_gcd(gcd, out, N, ctx.ctx);
        const bool coprime = BN_is_one(gcd);
        BN_free(gcd);
        if (!coprime) continue;
        const int jac = BN_kronecker(out, N, ctx.ctx);
        if (jac == 1) return true;
    }
    return false;
}

// Deterministic g_bar derivation. Every committee node computes the
// same value from (N, committee_id_hash), which is required for
// the distributed ceremony: g_bar is public data, so no party needs to
// broadcast it and no party can force a different value.
bool choose_g_bar_deterministic(const BIGNUM* N,
                                const uint8_t committee_id_hash[32],
                                BIGNUM* out)
{
    CtxGuard ctx;
    if (!ctx.ok()) return false;

    const char* dom = "VeilRoot-DAO-DKG-GBAR-V1";

    for (uint32_t counter = 0; counter < 65536; ++counter) {
        std::vector<uint8_t> buf;
        buf.insert(buf.end(), dom, dom + std::strlen(dom));
        buf.insert(buf.end(), committee_id_hash, committee_id_hash + 32);

        std::vector<uint8_t> nb(BN_num_bytes(N));
        BN_bn2bin(N, nb.data());
        buf.insert(buf.end(), nb.begin(), nb.end());

        for (int i = 0; i < 4; ++i) buf.push_back((counter >> (8*i)) & 0xff);

        uint8_t h[64];
        SHA512(buf.data(), buf.size(), h);

        BIGNUM* candidate = BN_bin2bn(h, 64, nullptr);
        if (!candidate) return false;
        BIGNUM* reduced = BN_new();
        BN_mod(reduced, candidate, N, ctx.ctx);
        BN_free(candidate);
        if (BN_is_zero(reduced) || BN_is_one(reduced)) {
            BN_free(reduced);
            continue;
        }

        BIGNUM* gcd = BN_new();
        BN_gcd(gcd, reduced, N, ctx.ctx);
        const bool coprime = BN_is_one(gcd);
        BN_free(gcd);
        if (!coprime) { BN_free(reduced); continue; }

        const int jac = BN_kronecker(reduced, N, ctx.ctx);
        if (jac == 1) {
            BN_copy(out, reduced);
            BN_free(reduced);
            return true;
        }
        BN_free(reduced);
    }
    return false;
}

// Biprimality acceptance: R = Q_1 / prod_{i>=2} Q_i mod N, accept iff
// R == 1 or R == -1. Returns 1 if accepted, 0 if rejected, -1 on error.
int biprimality_check(const std::vector<const BIGNUM*>& Q,
                      const BIGNUM* N)
{
    // Q is indexed 1..n (Q[0] unused). Accept iff
    //     Q[1] / (Q[2] * Q[3] * ... * Q[n]) == +1 or -1 mod N.
    if (Q.size() < 2 || !N) return -1;
    CtxGuard ctx;
    if (!ctx.ok()) return -1;

    // Product of Q[2] .. Q[n], excluding the numerator Q[1].
    BIGNUM* prod = BN_new();
    BN_one(prod);

    for (size_t i = 2; i < Q.size(); ++i) {
        if (!Q[i]) { BN_free(prod); return -1; }
        if (!BN_mod_mul(prod, prod, Q[i], N, ctx.ctx)) {
            BN_free(prod); return -1;
        }
    }

    BIGNUM* inv = BN_mod_inverse(nullptr, prod, N, ctx.ctx);
    if (!inv) { BN_free(prod); return -1; }

    // R = Q[1] * inv mod N
    BIGNUM* R = BN_new();
    if (!BN_mod_mul(R, Q[1], inv, N, ctx.ctx)) {
        BN_free(prod); BN_free(inv); BN_free(R);
        return -1;
    }

    int rc = 0;
    if (BN_is_one(R)) {
        rc = 1;
    } else {
        BIGNUM* Nm1 = BN_new();
        BN_sub(Nm1, N, BN_value_one());
        if (BN_cmp(R, Nm1) == 0) rc = 1;
        BN_free(Nm1);
    }

    BN_free(prod); BN_free(inv); BN_free(R);
    return rc;
}

// §4.1 trial division on one hidden factor. factor_selector: 0 = p,
// 1 = q. The function:
//   1. runs the VSS prolog for Ra/Rb in every party,
//   2. exchanges shares,
//   3. computes the gamma share per party,
//   4. collects gamma shares and reconstructs gamma at x=0,
//   5. checks gcd(gamma, r) == 1.
// Any failure at any repetition for any small prime rejects the
// candidate.
// Unique wire identity for a trial-division iteration. Phase 5
// repeats a (small_prime, repetition) grid, and rep alone is not
// unique across primes: every prime restarts at rep 0. Encode
// prime_index * REPS + rep so every protocol iteration has a distinct
// (phase, round) pair.
static uint32_t trial_division_wire_round(uint32_t selector,
                                          size_t prime_index,
                                          uint32_t rep)
{
    // Factor 0 (p) and factor 1 (q) must use disjoint wire_round
    // ranges. Without the selector offset, both factors emit traffic
    // with identical (phase=5, round) pairs, and a party that has
    // moved to factor 1 can have its factor-1 messages filtered out
    // by another party still collecting factor 0 at the same round.
    const uint64_t span =
        static_cast<uint64_t>(DAO_DKG_SMALL_PRIME_COUNT) *
        static_cast<uint64_t>(DAO_DKG_TRIAL_DIVISION_REPS);
    const uint64_t value =
        static_cast<uint64_t>(selector) * span +
        static_cast<uint64_t>(prime_index) *
            static_cast<uint64_t>(DAO_DKG_TRIAL_DIVISION_REPS) +
        static_cast<uint64_t>(rep);
    if (value > UINT32_MAX) return UINT32_MAX;
    return static_cast<uint32_t>(value);
}


} // anonymous namespace

// ====================================================================
// dkg_run_with_transport
// ====================================================================


// ====================================================================
// Distributed (P2P) DKG runner
//
// One committee node runs one dkg_p2p_runner. The runner owns a single
// dkg_party, a dkg_p2p_transport_local, and a worker thread. All
// committee members run the same code in parallel; no coordinator
// exists. Driver-level decisions (choose_g_bar, biprimality_check,
// lagrange_interpolate_zero, theta_tilde mod N, gcd(theta,N)==1,
// V derivation) are recomputed locally on every node from the same
// broadcast message set.
// ====================================================================

namespace {

constexpr char DAO_DKG_PRIVATE_MAGIC[4] = {'V','D','K','E'};
constexpr uint8_t DAO_DKG_PRIVATE_VERSION = 1;
constexpr const char* DAO_DKG_PRIVATE_DOMAIN =
    "VeilRoot-DAO-DKG-PRIVATE-V1";

constexpr size_t DAO_DKG_PRIVATE_NONCE_SIZE = 12;
constexpr size_t DAO_DKG_PRIVATE_TAG_SIZE = 16;

inline void dkg_private_push_u32(std::string& out, uint32_t v)
{
    out.push_back(static_cast<char>(v & 0xff));
    out.push_back(static_cast<char>((v >> 8) & 0xff));
    out.push_back(static_cast<char>((v >> 16) & 0xff));
    out.push_back(static_cast<char>((v >> 24) & 0xff));
}

inline bool dkg_private_pull_u32(const std::string& in, size_t& off, uint32_t& v)
{
    if (off + 4 > in.size()) return false;
    const auto b = [&](size_t n) -> uint32_t {
        return static_cast<uint8_t>(in[off + n]);
    };
    v = b(0) | (b(1) << 8) | (b(2) << 16) | (b(3) << 24);
    off += 4;
    return true;
}

inline bool dkg_private_magic_ok(const std::string& payload)
{
    return payload.size() >= 5 &&
           std::memcmp(payload.data(), DAO_DKG_PRIVATE_MAGIC, 4) == 0 &&
           static_cast<uint8_t>(payload[4]) == DAO_DKG_PRIVATE_VERSION;
}

void dkg_private_make_aad(const crypto::public_key& sender_pub,
                          const crypto::public_key& recipient_pub,
                          const crypto::public_key& ephemeral_pub,
                          std::string& aad)
{
    aad.clear();
    aad.append(DAO_DKG_PRIVATE_MAGIC, sizeof(DAO_DKG_PRIVATE_MAGIC));
    aad.push_back(static_cast<char>(DAO_DKG_PRIVATE_VERSION));
    aad.append(reinterpret_cast<const char*>(sender_pub.data),
               sizeof(sender_pub.data));
    aad.append(reinterpret_cast<const char*>(recipient_pub.data),
               sizeof(recipient_pub.data));
    aad.append(reinterpret_cast<const char*>(ephemeral_pub.data),
               sizeof(ephemeral_pub.data));
}

void dkg_private_derive_material(
    const crypto::key_derivation& derivation,
    const crypto::public_key& recipient_pub,
    const crypto::public_key& ephemeral_pub,
    std::vector<uint8_t>& material)
{
    material.clear();
    const char* dom = DAO_DKG_PRIVATE_DOMAIN;
    material.insert(material.end(), dom, dom + std::strlen(dom));
    material.push_back(0);
    material.insert(material.end(),
                    reinterpret_cast<const uint8_t*>(&derivation),
                    reinterpret_cast<const uint8_t*>(&derivation) +
                        sizeof(derivation));
    material.insert(material.end(),
                    reinterpret_cast<const uint8_t*>(recipient_pub.data),
                    reinterpret_cast<const uint8_t*>(recipient_pub.data) +
                        sizeof(recipient_pub.data));
    material.insert(material.end(),
                    reinterpret_cast<const uint8_t*>(ephemeral_pub.data),
                    reinterpret_cast<const uint8_t*>(ephemeral_pub.data) +
                        sizeof(ephemeral_pub.data));
}

bool dkg_private_aes_gcm_encrypt(
    const std::string& plaintext,
    const crypto::hash& key_hash,
    const std::string& aad,
    const uint8_t* nonce,
    std::string& ciphertext,
    std::array<uint8_t, DAO_DKG_PRIVATE_TAG_SIZE>& tag)
{
    if (plaintext.size() >
        static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                               nullptr, nullptr, nullptr) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                DAO_DKG_PRIVATE_NONCE_SIZE, nullptr) != 1)
            break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                               reinterpret_cast<const unsigned char*>(&key_hash),
                               nonce) != 1)
            break;

        int len = 0;
        if (!aad.empty() &&
            EVP_EncryptUpdate(ctx, nullptr, &len,
                reinterpret_cast<const unsigned char*>(aad.data()),
                static_cast<int>(aad.size())) != 1)
            break;

        ciphertext.resize(plaintext.size() + 16);
        int out_len = 0;
        if (!plaintext.empty() &&
            EVP_EncryptUpdate(ctx,
                reinterpret_cast<unsigned char*>(&ciphertext[0]),
                &len,
                reinterpret_cast<const unsigned char*>(plaintext.data()),
                static_cast<int>(plaintext.size())) != 1)
            break;

        out_len = len;
        if (EVP_EncryptFinal_ex(ctx,
                reinterpret_cast<unsigned char*>(&ciphertext[0]) + out_len,
                &len) != 1)
            break;
        out_len += len;
        ciphertext.resize(static_cast<size_t>(out_len));

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                DAO_DKG_PRIVATE_TAG_SIZE, tag.data()) != 1)
            break;
        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool dkg_private_aes_gcm_decrypt(
    const std::string& ciphertext,
    const crypto::hash& key_hash,
    const std::string& aad,
    const uint8_t* nonce,
    const uint8_t* tag,
    std::string& plaintext)
{
    if (ciphertext.size() >
        static_cast<size_t>(std::numeric_limits<int>::max()))
        return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                               nullptr, nullptr, nullptr) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                DAO_DKG_PRIVATE_NONCE_SIZE, nullptr) != 1)
            break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                               reinterpret_cast<const unsigned char*>(&key_hash),
                               nonce) != 1)
            break;

        int len = 0;
        if (!aad.empty() &&
            EVP_DecryptUpdate(ctx, nullptr, &len,
                reinterpret_cast<const unsigned char*>(aad.data()),
                static_cast<int>(aad.size())) != 1)
            break;

        plaintext.resize(ciphertext.size() + 16);
        int out_len = 0;
        if (!ciphertext.empty() &&
            EVP_DecryptUpdate(ctx,
                reinterpret_cast<unsigned char*>(&plaintext[0]),
                &len,
                reinterpret_cast<const unsigned char*>(ciphertext.data()),
                static_cast<int>(ciphertext.size())) != 1)
            break;

        out_len = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                DAO_DKG_PRIVATE_TAG_SIZE,
                                const_cast<uint8_t*>(tag)) != 1)
            break;

        if (EVP_DecryptFinal_ex(ctx,
                reinterpret_cast<unsigned char*>(&plaintext[0]) + out_len,
                &len) != 1) {
            plaintext.clear();
            break;
        }

        out_len += len;
        plaintext.resize(static_cast<size_t>(out_len));
        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

} // anonymous namespace

bool encrypt_dkg_private_payload(
    const std::string& plaintext,
    const crypto::public_key& sender_pub,
    const crypto::public_key& recipient_pub,
    std::string& envelope)
{
    crypto::public_key ephemeral_pub;
    crypto::secret_key ephemeral_priv;
    crypto::generate_keys(ephemeral_pub, ephemeral_priv);

    crypto::key_derivation derivation;
    if (!crypto::generate_key_derivation(recipient_pub,
                                         ephemeral_priv,
                                         derivation))
        return false;

    std::vector<uint8_t> material;
    dkg_private_derive_material(derivation, recipient_pub,
                                ephemeral_pub, material);

    crypto::hash key_hash;
    crypto::cn_fast_hash(material.data(), material.size(), key_hash);

    std::array<uint8_t, DAO_DKG_PRIVATE_NONCE_SIZE> nonce{};
    crypto::generate_random_bytes_thread_safe(nonce.size(), nonce.data());

    std::string aad;
    dkg_private_make_aad(sender_pub, recipient_pub, ephemeral_pub, aad);

    std::string ciphertext;
    std::array<uint8_t, DAO_DKG_PRIVATE_TAG_SIZE> tag{};

    if (!dkg_private_aes_gcm_encrypt(plaintext, key_hash, aad,
                                     nonce.data(), ciphertext, tag))
        return false;

    if (ciphertext.size() > std::numeric_limits<uint32_t>::max())
        return false;

    envelope.clear();
    envelope.reserve(4 + 1 +
                     sizeof(recipient_pub.data) +
                     sizeof(ephemeral_pub.data) +
                     DAO_DKG_PRIVATE_NONCE_SIZE +
                     4 + ciphertext.size() +
                     DAO_DKG_PRIVATE_TAG_SIZE);

    envelope.append(DAO_DKG_PRIVATE_MAGIC, sizeof(DAO_DKG_PRIVATE_MAGIC));
    envelope.push_back(static_cast<char>(DAO_DKG_PRIVATE_VERSION));
    envelope.append(reinterpret_cast<const char*>(recipient_pub.data),
                    sizeof(recipient_pub.data));
    envelope.append(reinterpret_cast<const char*>(ephemeral_pub.data),
                    sizeof(ephemeral_pub.data));
    envelope.append(reinterpret_cast<const char*>(nonce.data()),
                    nonce.size());
    dkg_private_push_u32(envelope,
        static_cast<uint32_t>(ciphertext.size()));
    envelope += ciphertext;
    envelope.append(reinterpret_cast<const char*>(tag.data()),
                    tag.size());
    return true;
}

bool is_dkg_private_payload(const std::string& payload)
{
    return dkg_private_magic_ok(payload);
}

bool get_dkg_private_payload_recipient(
    const std::string& envelope,
    crypto::public_key& recipient)
{
    recipient = {};

    if (!dkg_private_magic_ok(envelope))
        return false;

    constexpr size_t recipient_offset = 4 + 1;
    if (envelope.size() <
        recipient_offset + sizeof(recipient.data))
        return false;

    std::memcpy(recipient.data,
                envelope.data() + recipient_offset,
                sizeof(recipient.data));

    return crypto::check_key(recipient);
}

bool decrypt_dkg_private_payload(
    const std::string& envelope,
    const crypto::public_key& sender_pub,
    const crypto::secret_key& recipient_priv,
    std::string& plaintext)
{
    plaintext.clear();

    if (!dkg_private_magic_ok(envelope))
        return false;

    const size_t min_size =
        4 + 1 +
        sizeof(crypto::public_key::data) +
        sizeof(crypto::public_key::data) +
        DAO_DKG_PRIVATE_NONCE_SIZE +
        4 +
        DAO_DKG_PRIVATE_TAG_SIZE;

    if (envelope.size() < min_size)
        return false;

    size_t off = 0;
    if (std::memcmp(envelope.data(), DAO_DKG_PRIVATE_MAGIC, 4) != 0)
        return false;
    off += 4;
    if (static_cast<uint8_t>(envelope[off++]) != DAO_DKG_PRIVATE_VERSION)
        return false;

    crypto::public_key recipient_pub{};
    std::memcpy(recipient_pub.data, envelope.data() + off,
                sizeof(recipient_pub.data));
    off += sizeof(recipient_pub.data);

    crypto::public_key self_pub{};
    if (!crypto::secret_key_to_public_key(recipient_priv, self_pub))
        return false;
    if (std::memcmp(self_pub.data, recipient_pub.data,
                    sizeof(self_pub.data)) != 0)
        return false;

    crypto::public_key ephemeral_pub{};
    std::memcpy(ephemeral_pub.data, envelope.data() + off,
                sizeof(ephemeral_pub.data));
    off += sizeof(ephemeral_pub.data);

    if (!crypto::check_key(ephemeral_pub))
        return false;

    if (off + DAO_DKG_PRIVATE_NONCE_SIZE > envelope.size())
        return false;
    const uint8_t* nonce =
        reinterpret_cast<const uint8_t*>(envelope.data() + off);
    off += DAO_DKG_PRIVATE_NONCE_SIZE;

    uint32_t ciphertext_size = 0;
    if (!dkg_private_pull_u32(envelope, off, ciphertext_size))
        return false;

    const size_t needed = static_cast<size_t>(ciphertext_size) +
                          DAO_DKG_PRIVATE_TAG_SIZE;
    if (off + needed != envelope.size())
        return false;

    const std::string ciphertext = envelope.substr(off, ciphertext_size);
    off += ciphertext_size;
    const uint8_t* tag =
        reinterpret_cast<const uint8_t*>(envelope.data() + off);

    crypto::key_derivation derivation;
    if (!crypto::generate_key_derivation(ephemeral_pub, recipient_priv,
                                         derivation))
        return false;

    std::vector<uint8_t> material;
    dkg_private_derive_material(derivation, recipient_pub,
                                ephemeral_pub, material);

    crypto::hash key_hash;
    crypto::cn_fast_hash(material.data(), material.size(), key_hash);

    std::string aad;
    dkg_private_make_aad(sender_pub, recipient_pub, ephemeral_pub, aad);

    return dkg_private_aes_gcm_decrypt(ciphertext, key_hash, aad,
                                       nonce, tag, plaintext);
}

namespace {

;

} // anonymous namespace

;

// --------------------------------------------------------------------
// Phases 1-2: modulus shares and reconstruction
// --------------------------------------------------------------------


// --------------------------------------------------------------------
// Phase 3-4: biprimality
// --------------------------------------------------------------------


// --------------------------------------------------------------------
// Phase 5: trial division (one factor_selector)
// --------------------------------------------------------------------


// --------------------------------------------------------------------
// Top-level worker
// --------------------------------------------------------------------


// --------------------------------------------------------------------
// Lifecycle
// --------------------------------------------------------------------


// --------------------------------------------------------------------
// Phases 6-13: threshold key derivation
// --------------------------------------------------------------------


uint32_t dao_dkg_party_index_for(
    const std::vector<crypto::public_key>& member_ids,
    const crypto::public_key& self_pk)
{
    for (size_t i = 0; i < member_ids.size(); ++i) {
        if (std::memcmp(member_ids[i].data, self_pk.data,
                        sizeof(self_pk.data)) == 0)
            return static_cast<uint32_t>(i) + 1;
    }
    return 0;
}


// ====================================================================
// §3.3 Q_i proof
// ====================================================================

namespace {

void bn_to_bytes(const BIGNUM* v, size_t width, std::vector<uint8_t>& out)
{
    out.assign(width, 0);
    BN_bn2binpad(v, out.data(), static_cast<int>(width));
}

} // anonymous namespace

bool dao_Q_prove(const dao_vss_group& grp,
                 const BIGNUM* N,
                 const BIGNUM* g4,
                 const BIGNUM* h,
                 const BIGNUM* g_bar,
                 const BIGNUM* C0,
                 const BIGNUM* Q,
                 const BIGNUM* x,
                 const BIGNUM* y,
                 uint32_t member_index,
                 uint32_t rounds,
                 dao_Q_proof& proof_out)
{
    if (!grp.valid() || !N || !g4 || !h || !g_bar || !C0 || !Q || !x || !y)
        return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    const size_t P_bytes = static_cast<size_t>(BN_num_bytes(grp.P));
    const size_t N_bytes = static_cast<size_t>(BN_num_bytes(N));

    proof_out.member_index = member_index;
    proof_out.reps.clear();

    // Response-domain bound. For the Appendix-B integer equality
    // proof, responses zx = a + c*x and zy = b + c*y must lie in a
    // fixed public interval larger than the witnesses x and y. We use
    // 2^(bitlen(P') + 1), which is above 2*max(|x|, |y|).
    BIGNUM* resp_bound = BN_new();
    BN_lshift(resp_bound, BN_value_one(), BN_num_bits(grp.P) + 1);

    for (uint32_t i = 0; i < rounds; ++i) {
        BIGNUM* a = BN_new();
        BIGNUM* b = BN_new();
        BN_rand_range(a, resp_bound);
        BN_rand_range(b, resp_bound);

        // A = (g^4)^a * h^b mod P'
        BIGNUM* Aa = BN_new();
        BIGNUM* Ab = BN_new();
        BIGNUM* A  = BN_new();
        BN_mod_exp(Aa, g4, a, grp.P, ctx.ctx);
        BN_mod_exp(Ab, h,  b, grp.P, ctx.ctx);
        BN_mod_mul(A, Aa, Ab, grp.P, ctx.ctx);

        // B = g_bar^a mod N
        BIGNUM* B = BN_new();
        BN_mod_exp(B, g_bar, a, N, ctx.ctx);

        // Fiat-Shamir challenge bit. Bind transcript: N, member, C0, Q,
        // A, B, and the round index.
        SHA256_CTX sha;
        SHA256_Init(&sha);
        std::vector<uint8_t> nb(N_bytes, 0);
        if (BN_bn2binpad(N, nb.data(), static_cast<int>(N_bytes))
            != static_cast<int>(N_bytes)) return false;
        SHA256_Update(&sha, nb.data(), nb.size());
        uint8_t mi_le[4];
        for (int q2 = 0; q2 < 4; ++q2) mi_le[q2] = (member_index >> (8*q2)) & 0xff;
        SHA256_Update(&sha, mi_le, 4);
        std::vector<uint8_t> c0b(P_bytes, 0);
        std::vector<uint8_t> qb(N_bytes, 0);
        std::vector<uint8_t> ab(P_bytes, 0);
        std::vector<uint8_t> bb(N_bytes, 0);
        BN_bn2binpad(C0, c0b.data(), static_cast<int>(P_bytes));
        BN_bn2binpad(Q,  qb.data(),  static_cast<int>(N_bytes));
        BN_bn2binpad(A,  ab.data(),  static_cast<int>(P_bytes));
        BN_bn2binpad(B,  bb.data(),  static_cast<int>(N_bytes));
        SHA256_Update(&sha, c0b.data(), c0b.size());
        SHA256_Update(&sha, qb.data(), qb.size());
        SHA256_Update(&sha, ab.data(), ab.size());
        SHA256_Update(&sha, bb.data(), bb.size());
        SHA256_Update(&sha, &i, sizeof(i));
        unsigned char dig[32];
        SHA256_Final(dig, &sha);
        const uint8_t c = dig[0] & 1;

        // zx = a + c*x, zy = b + c*y
        BIGNUM* zx = BN_new();
        BIGNUM* zy = BN_new();
        if (c) {
            BN_add(zx, a, x);
            BN_add(zy, b, y);
        } else {
            BN_copy(zx, a);
            BN_copy(zy, b);
        }

        dao_Q_proof_repetition rep;
        bn_to_bytes(A, P_bytes, rep.A);
        bn_to_bytes(B, N_bytes, rep.B);
        rep.c = c;
        rep.zx.assign(BN_num_bytes(zx), 0);
        BN_bn2bin(zx, rep.zx.data());
        rep.zy.assign(BN_num_bytes(zy), 0);
        BN_bn2bin(zy, rep.zy.data());
        proof_out.reps.push_back(std::move(rep));

        BN_free(a); BN_free(b);
        BN_free(Aa); BN_free(Ab); BN_free(A); BN_free(B);
        BN_free(zx); BN_free(zy);
    }

    BN_free(resp_bound);
    return true;
}

bool dao_Q_verify(const dao_vss_group& grp,
                  const BIGNUM* N,
                  const BIGNUM* g4,
                  const BIGNUM* h,
                  const BIGNUM* g_bar,
                  const BIGNUM* C0,
                  const BIGNUM* Q,
                  const dao_Q_proof& proof)
{
    if (!grp.valid() || !N || !g4 || !h || !g_bar || !C0 || !Q) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    const size_t P_bytes = static_cast<size_t>(BN_num_bytes(grp.P));
    const size_t N_bytes = static_cast<size_t>(BN_num_bytes(N));

    for (uint32_t i = 0; i < proof.reps.size(); ++i) {
        const auto& rep = proof.reps[i];
        if (rep.A.size() != P_bytes) return false;
        if (rep.B.size() != N_bytes) return false;

        BIGNUM* A = BN_bin2bn(rep.A.data(), static_cast<int>(rep.A.size()), nullptr);
        BIGNUM* B = BN_bin2bn(rep.B.data(), static_cast<int>(rep.B.size()), nullptr);
        BIGNUM* zx = BN_bin2bn(rep.zx.data(), static_cast<int>(rep.zx.size()), nullptr);
        BIGNUM* zy = BN_bin2bn(rep.zy.data(), static_cast<int>(rep.zy.size()), nullptr);
        if (!A || !B || !zx || !zy) return false;

        // Recompute challenge.
        SHA256_CTX sha;
        SHA256_Init(&sha);
        std::vector<uint8_t> nb(N_bytes, 0);
        if (BN_bn2binpad(N, nb.data(), static_cast<int>(N_bytes))
            != static_cast<int>(N_bytes)) return false;
        SHA256_Update(&sha, nb.data(), nb.size());
        uint8_t mi_le[4];
        for (int q2 = 0; q2 < 4; ++q2) mi_le[q2] = (proof.member_index >> (8*q2)) & 0xff;
        SHA256_Update(&sha, mi_le, 4);
        std::vector<uint8_t> c0b(P_bytes, 0), qb(N_bytes, 0);
        std::vector<uint8_t> ab(P_bytes, 0), bb(N_bytes, 0);
        BN_bn2binpad(C0, c0b.data(), static_cast<int>(P_bytes));
        BN_bn2binpad(Q,  qb.data(),  static_cast<int>(N_bytes));
        BN_bn2binpad(A,  ab.data(),  static_cast<int>(P_bytes));
        BN_bn2binpad(B,  bb.data(),  static_cast<int>(N_bytes));
        SHA256_Update(&sha, c0b.data(), c0b.size());
        SHA256_Update(&sha, qb.data(), qb.size());
        SHA256_Update(&sha, ab.data(), ab.size());
        SHA256_Update(&sha, bb.data(), bb.size());
        SHA256_Update(&sha, &i, sizeof(i));
        unsigned char dig[32];
        SHA256_Final(dig, &sha);
        const uint8_t c = dig[0] & 1;
        if (c != rep.c) return false;

        // Check: (g^4)^zx * h^zy == A * C0^c mod P'
        BIGNUM* lhs_a = BN_new();
        BIGNUM* lhs_b = BN_new();
        BIGNUM* lhs = BN_new();
        BN_mod_exp(lhs_a, g4, zx, grp.P, ctx.ctx);
        BN_mod_exp(lhs_b, h, zy, grp.P, ctx.ctx);
        BN_mod_mul(lhs, lhs_a, lhs_b, grp.P, ctx.ctx);

        BIGNUM* rhs_a = BN_new();
        BIGNUM* rhs = BN_new();
        if (c) {
            BN_mod_mul(rhs_a, A, C0, grp.P, ctx.ctx);
            BN_copy(rhs, rhs_a);
        } else {
            BN_copy(rhs, A);
        }

        if (BN_cmp(lhs, rhs) != 0) return false;

        // Check: g_bar^zx == B * Q^c mod N
        BIGNUM* lhs2 = BN_new();
        BN_mod_exp(lhs2, g_bar, zx, N, ctx.ctx);

        BIGNUM* rhs2 = BN_new();
        if (c) {
            BIGNUM* qc = BN_new();
            BN_mod_mul(qc, B, Q, N, ctx.ctx);
            BN_copy(rhs2, qc);
            BN_free(qc);
        } else {
            BN_copy(rhs2, B);
        }

        const bool ok = (BN_cmp(lhs2, rhs2) == 0);

        BN_free(A); BN_free(B); BN_free(zx); BN_free(zy);
        BN_free(lhs_a); BN_free(lhs_b); BN_free(lhs);
        BN_free(rhs_a); BN_free(rhs); BN_free(lhs2); BN_free(rhs2);

        if (!ok) return false;
    }
    return true;
}
} // namespace dao
} // namespace cryptonote
