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

} // anonymous namespace

// ====================================================================
// Message serialization
// ====================================================================

bool dkg_msg::serialize(std::vector<uint8_t>& out) const
{
    if (hdr.version != 2 && hdr.version != 3) return false;
    if (hdr.version == 3 && hdr.attempt_id == crypto::null_hash)
        return false;
    out.clear();
    out.push_back(hdr.version);
    push_u32(out, hdr.candidate_id);
    out.insert(out.end(),
               std::begin(hdr.committee_id_hash),
               std::end(hdr.committee_id_hash));
    out.insert(out.end(),
               hdr.proposal_id.data,
               hdr.proposal_id.data + 32);
    if (hdr.version == 3)
        out.insert(out.end(), hdr.attempt_id.data, hdr.attempt_id.data + 32);
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
    if (hdr.version != 2 && hdr.version != 3) return false;
    hdr.attempt_id = crypto::null_hash;
    if (!pull_u32(in, off, hdr.candidate_id)) return false;
    if (off + 32 > in.size()) return false;
    std::memcpy(hdr.committee_id_hash, in.data() + off, 32);
    off += 32;
    if (off + 32 > in.size()) return false;
    std::memcpy(hdr.proposal_id.data, in.data() + off, 32);
    off += 32;
    if (hdr.version == 3) {
        if (off + 32 > in.size()) return false;
        std::memcpy(hdr.attempt_id.data, in.data() + off, 32);
        off += 32;
        if (hdr.attempt_id == crypto::null_hash) return false;
    }
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

} // namespace

// ====================================================================
// Verification keys
// ====================================================================

// ====================================================================
// Partial-decryption ZK proof (Appendix C)
// ====================================================================

// ====================================================================
// Key record serialization
// ====================================================================

bool dao_share_set_record::serialize(std::vector<uint8_t>& out) const
{
    if (key_id.size() != 32) return false;
    if (committee_id_hash.size() != 32) return false;
    if (committee_members.empty()) return false;
    if (threshold == 0 || threshold > committee_members.size()) return false;
    for (const auto& m : committee_members)
        if (m.size() != 32) return false;

    if (cl_gammas_serialized.empty()) return false;
    if (qualified_ids.empty()) return false;
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

bool dao_share_set_record::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    uint32_t v = 0;
    if (!pull_u32(in, off, v)) return false;
    if (v != 3) return false;
    version = v;

    cl_gammas_serialized.clear();
    qualified_ids.clear();

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

bool dao_tally_key_record::serialize(std::vector<uint8_t>& out) const
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

bool dao_tally_key_record::deserialize(const std::vector<uint8_t>& in)
{
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

crypto::hash dao_dkg_attempt_id(
    const crypto::hash& proposal_id,
    const crypto::hash& retry_block_hash,
    const crypto::hash& committee_id_hash)
{
    if (retry_block_hash == crypto::null_hash ||
        committee_id_hash == crypto::null_hash)
        return crypto::null_hash;
    std::vector<uint8_t> body;
    const char* dom = "VeilRoot-DAO-DKG-ATTEMPT-V1";
    body.insert(body.end(), dom, dom + std::strlen(dom));
    body.insert(body.end(), proposal_id.data, proposal_id.data + 32);
    body.insert(body.end(), retry_block_hash.data, retry_block_hash.data + 32);
    body.insert(body.end(), committee_id_hash.data, committee_id_hash.data + 32);
    crypto::hash h{};
    crypto::cn_fast_hash(body.data(), body.size(), h);
    return h;
}

crypto::hash dao_dkg_activation_digest_v4(
    const crypto::hash& genesis_block_hash,
    uint64_t selection_height,
    const dao_tally_key_record& record,
    const dao_share_set_record& initial_share_set,
    const crypto::hash& proposal_id,
    const crypto::hash& attempt_id)
{
    if (attempt_id == crypto::null_hash) return crypto::null_hash;
    std::vector<uint8_t> body;
    const char* dom = "VeilRoot-DAO-DKG-KEY-ACTIVATION-V4";
    body.insert(body.end(), dom, dom + std::strlen(dom));
    body.insert(body.end(), genesis_block_hash.data,
                genesis_block_hash.data + sizeof(genesis_block_hash.data));
    for (int i = 0; i < 8; ++i)
        body.push_back((selection_height >> (8 * i)) & 0xff);
    body.insert(body.end(), proposal_id.data, proposal_id.data + 32);
    body.insert(body.end(), attempt_id.data, attempt_id.data + 32);
    std::vector<uint8_t> rec_blob;
    if (!record.serialize(rec_blob)) return crypto::null_hash;
    body.insert(body.end(), rec_blob.begin(), rec_blob.end());
    std::vector<uint8_t> ss_blob;
    if (!initial_share_set.serialize(ss_blob)) return crypto::null_hash;
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

    if (version != 2 && version != 3 && version != 4) return false;
    if (version == 4 && attempt_id == crypto::null_hash) return false;
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
    if (version == 4)
        out.insert(out.end(), attempt_id.data, attempt_id.data + 32);
    push_bytes(out, rec_blob);

    if (version >= 3) {
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
    if (v != 2 && v != 3 && v != 4) return false;
    version = v;
    attempt_id = crypto::null_hash;
    initial_share_set = dao_share_set_record{};
    if (!pull_u64(in, off, selection_height)) return false;
    if (off + 32 > in.size()) return false;
    std::memcpy(proposal_id.data, in.data() + off, 32);
    off += 32;
    if (v == 4) {
        if (off + 32 > in.size()) return false;
        std::memcpy(attempt_id.data, in.data() + off, 32);
        off += 32;
        if (attempt_id == crypto::null_hash) return false;
    }
    std::vector<uint8_t> rec_blob;
    if (!pull_bytes(in, off, rec_blob)) return false;
    if (!record.deserialize(rec_blob)) return false;

    if (v >= 3) {
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

// Aggregate the per-sender commitment vector, then evaluate at point i:
//   out = prod_j prod_k (C_j_k)^(i^k)  mod P
// Assumes every per_party[j].C has the same length (same VSS degree).

// ---------------------------------------------------------------
// Gap 3: Theta(i) correctness proofs
// ---------------------------------------------------------------


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

} // namespace dao
} // namespace cryptonote
