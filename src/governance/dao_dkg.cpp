// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_dkg.h"
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
// driver's reveal verification. Binds epoch, party id, and the
// big-endian bytes of r_i.
void compute_v_commit(uint32_t epoch, uint32_t party_id,
                      const std::vector<uint8_t>& r_bytes,
                      std::vector<uint8_t>& digest_out)
{
    std::vector<uint8_t> buf;
    const char* dom = "DAO_DKG_V1";
    buf.insert(buf.end(), dom, dom + 10);
    for (int i = 0; i < 4; ++i) buf.push_back((epoch >> (8*i)) & 0xff);
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
    push_u32(out, hdr.epoch);
    push_u32(out, hdr.candidate_id);
    out.insert(out.end(),
               std::begin(hdr.committee_id_hash),
               std::end(hdr.committee_id_hash));
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
    if (hdr.version != 1) return false;
    if (!pull_u32(in, off, hdr.epoch)) return false;
    if (!pull_u32(in, off, hdr.candidate_id)) return false;
    if (off + 32 > in.size()) return false;
    std::memcpy(hdr.committee_id_hash, in.data() + off, 32);
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

    if (!P || !Q || !G) {
        DH_free(dh);
        return false;
    }

    // Validate the structural relationship P' = (P-1)/2.
    BIGNUM* expected_Q = BN_new();
    if (!expected_Q) { DH_free(dh); return false; }

    if (!BN_sub(expected_Q, P, BN_value_one()) ||
        !BN_rshift1(expected_Q, expected_Q)) {
        BN_free(expected_Q);
        DH_free(dh);
        return false;
    }

    if (BN_cmp(expected_Q, Q) != 0) {
        BN_free(expected_Q);
        DH_free(dh);
        return false;
    }

    if (BN_num_bits(Q) < static_cast<int>(required_order_bits)) {
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
            BN_mod_exp(g_check, G, Q, P, guard.ctx) == 1 &&
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

    if (!dao_vss_derive_h(P, Q, G, group_name, h_val, guard.ctx)) {
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
    out.P_prime = BN_dup(Q);
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
                     uint32_t epoch,
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
        append_u32be(input, epoch);
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
    append_u32be(link_input, epoch);
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
                      uint32_t epoch,
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
        append_u32be(input, epoch);
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
    append_u32be(link_input, epoch);
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

    proof_out.member_index = member_index;
    E_to_bytes(E, proof_out.E);
    proof_out.Z.assign(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(Z, proof_out.Z.data(), PAILLIER_CT_BYTES);

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
    if (proof.Z.size() != PAILLIER_CT_BYTES) return false;
    if (V_K.size() != PAILLIER_CT_BYTES) return false;
    if (V_K_i.size() != PAILLIER_CT_BYTES) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* c   = BN_bin2bn(c_bytes.data(),   static_cast<int>(c_bytes.size()),   nullptr);
    BIGNUM* ci  = BN_bin2bn(c_i_bytes.data(), static_cast<int>(c_i_bytes.size()), nullptr);
    BIGNUM* vk  = BN_bin2bn(V_K.data(),       static_cast<int>(V_K.size()),       nullptr);
    BIGNUM* vki = BN_bin2bn(V_K_i.data(),     static_cast<int>(V_K_i.size()),     nullptr);
    BIGNUM* E   = BN_bin2bn(proof.E.data(),   static_cast<int>(proof.E.size()),   nullptr);
    BIGNUM* Z   = BN_bin2bn(proof.Z.data(),   static_cast<int>(proof.Z.size()),   nullptr);
    if (!c || !ci || !vk || !vki || !E || !Z) return false;

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
    if (!BN_mod_exp(a1, c4, Z, N2, ctx.ctx)) return false;
    if (!modexp_signed(ci2, negE, N2, a2, ctx.ctx)) return false;
    BIGNUM* a = BN_new();
    BN_mod_mul(a, a1, a2, N2, ctx.ctx);

    BIGNUM* b1 = BN_new();
    BIGNUM* b2 = BN_new();
    if (!BN_mod_exp(b1, vk, Z, N2, ctx.ctx)) return false;
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

bool dao_tally_key_record::serialize(std::vector<uint8_t>& out) const
{
    // Strict canonical layout. Every field is length-prefixed or
    // fixed-width, in a single well-defined order.
    if (committee_id_hash.size() != 32) return false;
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
    push_u32(out, epoch);
    push_u32(out, committee_size);
    push_u32(out, threshold);
    push_u32(out, t);
    out.insert(out.end(), committee_id_hash.begin(), committee_id_hash.end());
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
    return true;
}

bool dao_tally_key_record::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    uint32_t v = 0, e = 0, cs = 0, th = 0, tt = 0;
    if (!pull_u32(in, off, v)) return false;
    if (!pull_u32(in, off, e)) return false;
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

    if (off != in.size()) return false;

    version = v;
    epoch = e;
    committee_size = cs;
    threshold = th;
    t = tt;
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

class dkg_party
{
public:
    dkg_party(uint32_t party_id, uint32_t committee_size,
              uint32_t threshold, uint32_t epoch)
        : party_id_(party_id),
          committee_size_(committee_size),
          threshold_(threshold),
          epoch_(epoch)
    {
        shares_p_received_.assign(committee_size + 1, nullptr);
        shares_q_received_.assign(committee_size + 1, nullptr);
        shares_h_received_.assign(committee_size + 1, nullptr);
        N_i_received_.assign(committee_size + 1, nullptr);
        Q_received_.assign(committee_size + 1, nullptr);
        beta_shares_received_.assign(committee_size + 1, nullptr);
        delta_r_shares_received_.assign(committee_size + 1, nullptr);
        h_theta_shares_received_.assign(committee_size + 1, nullptr);
        ra_shares_received_.assign(committee_size + 1, nullptr);
        rb_shares_received_.assign(committee_size + 1, nullptr);
        v_commit_received_.assign(committee_size + 1, {});
        v_reveal_received_.assign(committee_size + 1, nullptr);
        commits_p_recv_.resize(committee_size + 1);
        commits_q_recv_.resize(committee_size + 1);
        commits_beta_recv_.resize(committee_size + 1);
        commits_dr_recv_.resize(committee_size + 1);
        commits_h_theta_recv_.resize(committee_size + 1);
        b_p_received_.assign(committee_size + 1, nullptr);
        b_q_received_.assign(committee_size + 1, nullptr);
        b_beta_received_.assign(committee_size + 1, nullptr);
        b_dr_received_.assign(committee_size + 1, nullptr);
        b_h_theta_received_.assign(committee_size + 1, nullptr);
    }

    ~dkg_party()
    {
        auto free_vec = [](std::vector<BIGNUM*>& v) {
            for (auto* p : v) if (p) BN_free(p);
            v.clear();
        };
        free_bn(p_i_); free_bn(q_i_);
#ifdef VEILROOT_DAO_DKG_TESTING
        free_bn(fixed_test_p_i_); free_bn(fixed_test_q_i_);
#endif
        free_bn(h_coeffs_first_);
        free_bn(N_i_); free_bn(N_candidate_);
        free_bn(g_bar_); free_bn(Q_i_);
        free_bn(share_p_); free_bn(share_q_);
        free_bn(share_ra_); free_bn(share_rb_);
        free_bn(gamma_share_);
        free_bn(phi_share_);
        free_bn(beta_i_); free_bn(R_i_);
        free_bn(beta_share_); free_bn(f1_share_); free_bn(h_theta_share_);
        free_bn(theta_share_); free_bn(theta_tilde_); free_bn(theta_);
        free_bn(SK_i_);
        free_bn(r_phi_i_); free_bn(r_beta_i_); free_bn(k_prod_);
        free_bn(r_prod_i_); free_bn(r_theta_i_);
        free_bn(C_phi_i_); free_bn(C_beta_i_); free_bn(C_f1_i_);
        free_bn(C_h_theta_i_); free_bn(C_prod_); free_bn(C_theta_i_);
        free_bn(v_r_i_); free_bn(V_);
        free_vec(shares_p_received_);
        free_vec(shares_q_received_);
        free_vec(shares_h_received_);
        free_vec(N_i_received_);
        free_vec(Q_received_);
        free_vec(ra_shares_received_);
        free_vec(rb_shares_received_);
        free_vec(beta_shares_received_);
        free_vec(delta_r_shares_received_);
        free_vec(h_theta_shares_received_);
        free_vec(v_reveal_received_);
        free_vec(b_p_received_);
        free_vec(b_q_received_);
        free_vec(b_beta_received_);
        free_vec(b_dr_received_);
        free_vec(b_h_theta_received_);
    }

    uint32_t id() const { return party_id_; }
    uint32_t phase() const { return phase_; }
    bool     aborted() const { return aborted_; }

    void attach_transport(dkg_transport* t) { transport_ = t; }
    void attach_vss_group(const dao_vss_group* g) { vss_group_ = g; }
    void set_qproof_rounds(uint32_t r) { qproof_rounds_ = r; }
    void set_candidate_id(uint32_t cid) { candidate_id_ = cid; }
    void set_committee_id_hash(const uint8_t h[32])
    {
        std::memcpy(committee_id_hash_, h, 32);
    }

    // Phase transitions, all driven by messages by the driver.
    bool handle_message(const dkg_msg& m);

    // Produce the initial burst of messages for the current phase.
    bool start_phase(uint32_t phase, uint32_t k, uint32_t security_bits,
                     uint32_t target_N_bits);

    // Trial-division phase helpers (§4.1). Called by the driver.
    bool do_compute_share_pq();
    bool do_trial_division_prolog(uint32_t factor_selector);
    bool do_trial_division_gamma(uint32_t r);

    // §5 threshold key derivation. Called by the driver in sequence.
    bool do_phi_share_init();
    bool do_beta_R_generate();
    bool do_beta_R_collect();
    bool do_compute_theta_share();
    bool do_reconstruct_theta();
    bool do_compute_SK();
    bool do_v_commit();
    bool do_v_reveal();
    bool do_compute_V();
    bool do_derive_VKi(std::vector<uint8_t>& VKi_out);

    // Accessors for the driver.
    const BIGNUM* theta_tilde() const { return theta_tilde_; }
    const BIGNUM* theta() const { return theta_; }
    const BIGNUM* V() const { return V_; }
    const BIGNUM* SK() const { return SK_i_; }
    bool set_theta_tilde(const BIGNUM* v);
    bool set_V(const BIGNUM* v);

#ifdef VEILROOT_DAO_DKG_TESTING
public:
    const BIGNUM* test_beta_i() const { return beta_i_; }
    const BIGNUM* test_R_i() const { return R_i_; }
    const BIGNUM* test_theta_tilde() const { return theta_tilde_; }
    const BIGNUM* test_SK() const { return SK_i_; }
    const BIGNUM* test_phi_share() const { return phi_share_; }
#endif

    // Query.
    bool public_N(std::vector<uint8_t>& out) const;
    bool has_candidate_N() const { return N_candidate_ != nullptr; }

    // Gap 3 - driver-side verification accessors.
    const std::vector<dao_vss_commitments>& commits_p_recv() const { return commits_p_recv_; }
    const std::vector<dao_vss_commitments>& commits_q_recv() const { return commits_q_recv_; }
    const std::vector<dao_vss_commitments>& commits_beta_recv() const { return commits_beta_recv_; }
    const std::vector<dao_vss_commitments>& commits_dr_recv() const { return commits_dr_recv_; }
    const std::vector<dao_vss_commitments>& commits_h_theta_recv() const { return commits_h_theta_recv_; }

private:
    uint32_t party_id_;
    uint32_t committee_size_;
    uint32_t threshold_;
    uint32_t epoch_;
    uint32_t candidate_id_ = 0;
    uint8_t  committee_id_hash_[32] = {};

    uint32_t phase_ = 0;
    bool     aborted_ = false;
    uint64_t seq_ = 0;

    dkg_transport*      transport_ = nullptr;
    const dao_vss_group* vss_group_ = nullptr;

    // Config carried into phases
    uint32_t k_              = 0;
    uint32_t security_bits_  = 0;
    uint32_t target_N_bits_  = 0;
    uint32_t qproof_rounds_  = 0;

    // --- modulus generation ---
    BIGNUM* p_i_ = nullptr;
    BIGNUM* q_i_ = nullptr;
#ifdef VEILROOT_DAO_DKG_TESTING
    BIGNUM* fixed_test_p_i_ = nullptr;
    BIGNUM* fixed_test_q_i_ = nullptr;
#endif
    dao_vss_commitments commits_p_;
    dao_vss_commitments commits_q_;
    dao_vss_commitments commits_h_;
    std::vector<BIGNUM*> shares_p_received_;
    std::vector<BIGNUM*> shares_q_received_;
    std::vector<BIGNUM*> shares_h_received_;
    BIGNUM* h_coeffs_first_ = nullptr;   // coefficient h_i for the product polynomial

    BIGNUM* N_i_ = nullptr;
    std::vector<BIGNUM*> N_i_received_;
    BIGNUM* N_candidate_ = nullptr;

    BIGNUM* g_bar_ = nullptr;
    BIGNUM* Q_i_ = nullptr;
    std::vector<BIGNUM*> Q_received_;

    // Trial-division state (§4.1)
    BIGNUM* share_p_ = nullptr;
    BIGNUM* share_q_ = nullptr;
    BIGNUM* share_ra_ = nullptr;
    BIGNUM* share_rb_ = nullptr;
    BIGNUM* gamma_share_ = nullptr;
    uint32_t trial_r_ = 0;
    std::vector<BIGNUM*> ra_shares_received_;
    std::vector<BIGNUM*> rb_shares_received_;

    // --- §5 threshold key derivation ---
    BIGNUM* phi_share_ = nullptr;       // Phi(i) = N + 1 - p(i) - q(i)

    BIGNUM* beta_i_ = nullptr;          // own beta_i
    BIGNUM* R_i_ = nullptr;             // own R_i
    dao_vss_commitments commits_beta_;
    dao_vss_commitments commits_delta_r_;
    dao_vss_commitments commits_h_theta_;
    std::vector<BIGNUM*> beta_shares_received_;      // Beta_j(i)
    std::vector<BIGNUM*> delta_r_shares_received_;   // F1_j(i)
    std::vector<BIGNUM*> h_theta_shares_received_;   // h_theta_j(i)

    BIGNUM* beta_share_ = nullptr;      // aggregate Beta(i)
    BIGNUM* f1_share_ = nullptr;        // aggregate F1(i)
    BIGNUM* h_theta_share_ = nullptr;   // aggregate H_theta(i)

    BIGNUM* theta_share_ = nullptr;     // Theta(i)
    BIGNUM* theta_tilde_ = nullptr;     // public value (Theta(0))
    BIGNUM* theta_ = nullptr;           // theta_tilde mod N

    BIGNUM* SK_i_ = nullptr;            // F(i)

    // Gap 3 - Theta(i) proof state.
    BIGNUM* r_phi_i_ = nullptr;
    BIGNUM* r_beta_i_ = nullptr;
    BIGNUM* k_prod_ = nullptr;
    BIGNUM* r_prod_i_ = nullptr;
    BIGNUM* r_theta_i_ = nullptr;
    BIGNUM* C_phi_i_ = nullptr;
    BIGNUM* C_beta_i_ = nullptr;
    BIGNUM* C_f1_i_ = nullptr;
    BIGNUM* C_h_theta_i_ = nullptr;
    BIGNUM* C_prod_ = nullptr;
    BIGNUM* C_theta_i_ = nullptr;

    // V commit/reveal round.
    BIGNUM* v_r_i_ = nullptr;           // own r_i in Z*_{N^2}
    std::vector<std::vector<uint8_t>> v_commit_received_;   // per party
    std::vector<BIGNUM*> v_reveal_received_;                // per party
    BIGNUM* V_ = nullptr;

    // Gap 3 — per-sender VSS commitments and blinding evaluations.
    // Indexed [1..committee_size]. commits_X_recv_[j] = sender j's
    // public polynomial commitments; b_X_received_[j] = the blinding
    // evaluation that sender j sent privately to this party.
    std::vector<dao_vss_commitments> commits_p_recv_;
    std::vector<dao_vss_commitments> commits_q_recv_;
    std::vector<dao_vss_commitments> commits_beta_recv_;
    std::vector<dao_vss_commitments> commits_dr_recv_;
    std::vector<dao_vss_commitments> commits_h_theta_recv_;
    std::vector<BIGNUM*> b_p_received_;
    std::vector<BIGNUM*> b_q_received_;
    std::vector<BIGNUM*> b_beta_received_;
    std::vector<BIGNUM*> b_dr_received_;
    std::vector<BIGNUM*> b_h_theta_received_;

    // helpers
    void free_bn(BIGNUM*& p) { if (p) { BN_free(p); p = nullptr; } }
    bool send_msg(const dkg_msg& m);
    dkg_msg make_header(dkg_msg_type type, uint32_t recipient) const;

    bool do_polynomial_commit();
    bool do_bgw_product();
    bool do_publish_Q();

#ifdef VEILROOT_DAO_DKG_TESTING
public:
    // Test-only accessors. Not compiled into production builds.
    const BIGNUM* test_p_i() const { return p_i_; }
    const BIGNUM* test_q_i() const { return q_i_; }

    // Test-only injection of a fixed contribution. When both are set,
    // do_polynomial_commit uses them instead of drawing random values.
    void set_fixed_test_contribution(const BIGNUM* p, const BIGNUM* q)
    {
        free_bn(fixed_test_p_i_);
        free_bn(fixed_test_q_i_);
        fixed_test_p_i_ = p ? BN_dup(p) : nullptr;
        fixed_test_q_i_ = q ? BN_dup(q) : nullptr;
    }
#endif
};

// -------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------

bool dkg_party::send_msg(const dkg_msg& m)
{
    if (!transport_) return false;
    return transport_->send(m);
}

dkg_msg dkg_party::make_header(dkg_msg_type type, uint32_t recipient) const
{
    dkg_msg m;
    m.hdr.version      = 1;
    m.hdr.epoch        = epoch_;
    m.hdr.candidate_id = candidate_id_;
    std::memcpy(m.hdr.committee_id_hash, committee_id_hash_, 32);
    m.hdr.sender_id    = party_id_;
    m.hdr.recipient_id = recipient;
    m.hdr.phase        = phase_;
    m.hdr.round        = 0;
    m.hdr.sequence     = seq_;
    m.hdr.type         = type;
    return m;
}

// -------------------------------------------------------------------
// Phase A: generate polynomial commitments + distribute shares
// -------------------------------------------------------------------

bool dkg_party::do_polynomial_commit()
{
    if (!vss_group_ || !vss_group_->valid()) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    // p_i, q_i with residue conditions.
    // P1: p1 = q1 = 3 mod 4.
    // Pi (i>=2): pi = qi = 0 mod 4.
    const uint32_t t = threshold_ - 1;

    auto draw_candidate = [&](bool p1_style, BIGNUM* out) -> bool {
        if (!BN_rand(out, k_, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY)) return false;

        BIGNUM* four = BN_new();
        BN_set_word(four, 4);
        BIGNUM* r = BN_new();
        BN_mod(r, out, four, ctx.ctx);
        BIGNUM* target = BN_new();
        BN_set_word(target, p1_style ? 3 : 0);
        BIGNUM* diff = BN_new();
        BN_sub(diff, target, r);
        BN_nnmod(diff, diff, four, ctx.ctx);
        // BN_add, NOT BN_mod_add: we add a small correction (0..3) so
        // out becomes the right residue without reducing its magnitude.
        BN_add(out, out, diff);
        BN_free(four); BN_free(r); BN_free(target); BN_free(diff);
        return true;
    };

    const bool is_p1 = (party_id_ == 1);

    free_bn(p_i_);
    free_bn(q_i_);
    p_i_ = BN_new();
    q_i_ = BN_new();

#ifdef VEILROOT_DAO_DKG_TESTING
    if (fixed_test_p_i_ && fixed_test_q_i_) {
        if (!BN_copy(p_i_, fixed_test_p_i_)) return false;
        if (!BN_copy(q_i_, fixed_test_q_i_)) return false;
    } else
#endif
    {
        if (!draw_candidate(is_p1, p_i_)) return false;
        if (!draw_candidate(is_p1, q_i_)) return false;
    }

    // Deal VSS of p_i and q_i at degree t.
    std::vector<BIGNUM*> s_p, s_q, b_p, b_q;
    if (!dao_vss_deal(*vss_group_, p_i_, committee_size_, t,
                      commits_p_, s_p, b_p)) return false;
    if (!dao_vss_deal(*vss_group_, q_i_, committee_size_, t,
                      commits_q_, s_q, b_q)) return false;

    // Deal VSS of h_i (with h_i(0)=0) at degree 2t.
    BIGNUM* zero = BN_new();
    BN_zero(zero);
    std::vector<BIGNUM*> s_h, b_h;
    if (!dao_vss_deal(*vss_group_, zero, committee_size_, 2 * t,
                      commits_h_, s_h, b_h)) {
        BN_free(zero); return false;
    }
    BN_free(zero);

    // Broadcast commitments.
    {
        dkg_msg m = make_header(dkg_msg_type::polynomial_commitment_p, 0);
        for (const auto& c : commits_p_.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }
    {
        dkg_msg m = make_header(dkg_msg_type::polynomial_commitment_q, 0);
        for (const auto& c : commits_q_.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }
    {
        dkg_msg m = make_header(dkg_msg_type::polynomial_commitment_h, 0);
        for (const auto& c : commits_h_.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }

    // Private shares to each party j = 1..n (including ourselves; we
    // will simply not loop back through the transport for j == our id).
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (j == party_id_) {
            // Store locally.
            if (shares_p_received_[j]) BN_free(shares_p_received_[j]);
            if (shares_q_received_[j]) BN_free(shares_q_received_[j]);
            if (shares_h_received_[j]) BN_free(shares_h_received_[j]);
            if (b_p_received_[j]) BN_free(b_p_received_[j]);
            if (b_q_received_[j]) BN_free(b_q_received_[j]);
            shares_p_received_[j] = BN_dup(s_p[j - 1]);
            shares_q_received_[j] = BN_dup(s_q[j - 1]);
            shares_h_received_[j] = BN_dup(s_h[j - 1]);
            b_p_received_[j] = BN_dup(b_p[j - 1]);
            b_q_received_[j] = BN_dup(b_q[j - 1]);
            continue;
        }

        dkg_msg m = make_header(dkg_msg_type::polynomial_share, j);
        // encode shares as big-endian byte blobs
        auto enc = [](const BIGNUM* b, std::vector<uint8_t>& out) {
            const int n = BN_num_bytes(b);
            out.assign(n, 0);
            BN_bn2bin(b, out.data());
        };
        enc(s_p[j - 1], m.bytes_a);
        enc(s_q[j - 1], m.bytes_b);
        enc(s_h[j - 1], m.bytes_c);
        // Gap 3: transmit Pedersen blinding evaluations privately so
        // the recipient can verify (share, blinding) against the
        // contributor's public commitments.
        bn_to_signed(b_p[j - 1], m.bytes_d);
        {
            std::vector<uint8_t> bq_enc;
            bn_to_signed(b_q[j - 1], bq_enc);
            m.vec_a.push_back(std::move(bq_enc));
        }
        if (!send_msg(m)) return false;
    }

    for (auto* x : s_p) BN_free(x);
    for (auto* x : s_q) BN_free(x);
    for (auto* x : s_h) BN_free(x);
    for (auto* x : b_p) BN_free(x);
    for (auto* x : b_q) BN_free(x);
    for (auto* x : b_h) BN_free(x);
    return true;
}

// -------------------------------------------------------------------
// Phase B: form N_i = (sum_j p_j_i)(sum_j q_j_i) + (sum_j h_j_i)
// -------------------------------------------------------------------

bool dkg_party::do_bgw_product()
{
    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* sum_p = BN_new();
    BIGNUM* sum_q = BN_new();
    BIGNUM* sum_h = BN_new();
    if (!sum_p || !sum_q || !sum_h) return false;
    BN_zero(sum_p); BN_zero(sum_q); BN_zero(sum_h);

    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (!shares_p_received_[j] || !shares_q_received_[j] ||
            !shares_h_received_[j]) return false;
        BN_add(sum_p, sum_p, shares_p_received_[j]);
        BN_add(sum_q, sum_q, shares_q_received_[j]);
        BN_add(sum_h, sum_h, shares_h_received_[j]);
    }

    BIGNUM* prod = BN_new();
    BN_mul(prod, sum_p, sum_q, ctx.ctx);
    BIGNUM* n_i = BN_new();
    BN_add(n_i, prod, sum_h);

    free_bn(N_i_);
    N_i_ = n_i;
    BN_free(prod);
    BN_free(sum_p); BN_free(sum_q); BN_free(sum_h);

    // Broadcast N_i.
    dkg_msg m = make_header(dkg_msg_type::bgw_product_share, 0);
    const int nb = BN_num_bytes(N_i_);
    m.bytes_a.assign(nb, 0);
    BN_bn2bin(N_i_, m.bytes_a.data());
    return send_msg(m);
}

// -------------------------------------------------------------------
// Phase C: publish Q_i (biprimality)
// -------------------------------------------------------------------

bool dkg_party::do_publish_Q()
{
    if (!N_candidate_) return false;
    if (!g_bar_) return false;
    if (!vss_group_ || !vss_group_->valid()) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    // The secret being proven:
    //   i == 1: s_1 = N + 1 - p_1 - q_1
    //   i >= 2: s_i = p_i + q_i
    //
    // x_i = s_i / 4, integer-exact by the residue conditions.
    // y_i:
    //   i == 1: q - r_1  where r_1 in [1, q)
    //   i >= 2: r_i      where r_i in [0, q)
    //
    // Commitments:
    //   i == 1: C0'_1 = g^(N+1) / [g^(p_1+q_1) * h^(r_1)]
    //         = (g^4)^x_1 * h^(q - r_1)  mod P'
    //   i >= 2: C0_i = g^(p_i+q_i) * h^(r_i) = (g^4)^x_i * h^(r_i)  mod P'
    //
    // Public values:
    //   Q_i = g_bar^x_i  mod N

    BIGNUM* q_ord = vss_group_order(*vss_group_);
    if (!q_ord) return false;

    BIGNUM* s = BN_new();
    BIGNUM* x = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* y = BN_new();
    BIGNUM* four = BN_new();
    BN_set_word(four, 4);

    // s.
    if (party_id_ == 1) {
        BIGNUM* tmp = BN_new();
        BN_add(tmp, N_candidate_, BN_value_one());
        BN_sub(tmp, tmp, p_i_);
        BN_sub(tmp, tmp, q_i_);
        BN_copy(s, tmp);
        BN_free(tmp);
    } else {
        BN_add(s, p_i_, q_i_);
    }

    // x = s / 4, assert exact.
    {
        BIGNUM* rem = BN_new();
        BN_div(x, rem, s, four, ctx.ctx);
        if (!BN_is_zero(rem)) {
            BN_free(q_ord); BN_free(s); BN_free(x); BN_free(r);
            BN_free(y); BN_free(four); BN_free(rem);
            return false;
        }
        BN_free(rem);
    }
    BN_free(four);

    // r_i. For i == 1, sample from [1, q). For i >= 2, sample from [0, q).
    if (party_id_ == 1) {
        do {
            BN_rand_range(r, q_ord);
        } while (BN_is_zero(r));
        // y = q - r, so y is in [1, q).
        BN_sub(y, q_ord, r);
    } else {
        BN_rand_range(r, q_ord);
        BN_copy(y, r);
    }

    // g4 = g^4 mod P'.
    BIGNUM* g4 = BN_new();
    {
        BIGNUM* four2 = BN_new();
        BN_set_word(four2, 4);
        BN_mod_exp(g4, vss_group_->g, four2, vss_group_->P, ctx.ctx);
        BN_free(four2);
    }

    // g4x = (g^4)^x mod P'.
    BIGNUM* g4x = BN_new();
    BN_mod_exp(g4x, g4, x, vss_group_->P, ctx.ctx);

    // hr = h^y mod P'. Note: h^y where y is what we're using as the
    // blinding for the "commitment" side of the equation. For i == 1
    // this is h^(q-r) which equals h^(-r) because h has order q.
    BIGNUM* hy = BN_new();
    BN_mod_exp(hy, vss_group_->h, y, vss_group_->P, ctx.ctx);

    // C0' = (g^4)^x * h^y mod P'.
    BIGNUM* C0p = BN_new();
    BN_mod_mul(C0p, g4x, hy, vss_group_->P, ctx.ctx);

    // Q_i = g_bar^x mod N.
    BIGNUM* Q = BN_new();
    BN_mod_exp(Q, g_bar_, x, N_candidate_, ctx.ctx);

    // Proof.
    dao_Q_proof proof;
    if (!dao_Q_prove(*vss_group_, N_candidate_, g4, vss_group_->h,
                     g_bar_, C0p, Q, x, y, party_id_,
                     qproof_rounds_, proof)) {
        BN_free(q_ord); BN_free(s); BN_free(x); BN_free(r); BN_free(y);
        BN_free(g4); BN_free(g4x); BN_free(hy); BN_free(C0p); BN_free(Q);
        return false;
    }

    // Broadcast: bytes_a = C0' (P_bytes), bytes_b = Q (N_bytes),
    // bytes_c = serialized proof.
    const size_t P_bytes = static_cast<size_t>(BN_num_bytes(vss_group_->P));
    const size_t N_bytes = static_cast<size_t>(BN_num_bytes(N_candidate_));

    dkg_msg m = make_header(dkg_msg_type::biprimality_Q, 0);
    m.tag32 = party_id_;
    m.bytes_a.assign(P_bytes, 0);
    BN_bn2binpad(C0p, m.bytes_a.data(), static_cast<int>(P_bytes));
    m.bytes_b.assign(N_bytes, 0);
    BN_bn2binpad(Q, m.bytes_b.data(), static_cast<int>(N_bytes));
    serialize_Q_proof(proof, m.bytes_c);

    const bool sent = send_msg(m);

    BN_free(q_ord); BN_free(s); BN_free(x); BN_free(r); BN_free(y);
    BN_free(g4); BN_free(g4x); BN_free(hy); BN_free(C0p); BN_free(Q);
    return sent;
}

// -------------------------------------------------------------------
// Compute the party's share of p and q from received VSS shares.
// -------------------------------------------------------------------

bool dkg_party::do_compute_share_pq()
{
    BIGNUM* sp = BN_new();
    BIGNUM* sq = BN_new();
    BN_zero(sp); BN_zero(sq);
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (!shares_p_received_[j] || !shares_q_received_[j]) return false;
        BN_add(sp, sp, shares_p_received_[j]);
        BN_add(sq, sq, shares_q_received_[j]);
    }
    free_bn(share_p_);
    free_bn(share_q_);
    share_p_ = sp;
    share_q_ = sq;
    return true;
}

// -------------------------------------------------------------------
// §4.1 trial division. Fresh VSS of the per-party randomizers.
// `r` selects which small prime this phase is testing. r == 0 uses
// share_p_; r == 1 uses share_q_.
// -------------------------------------------------------------------

bool dkg_party::do_trial_division_prolog(uint32_t r)
{
    if (!vss_group_ || !vss_group_->valid()) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    trial_r_ = r;
    const uint32_t t = threshold_ - 1;

    // p_max = committee_size * 3 * 2^(k-1). The bound depends on the
    // actual committee size, not a fixed 16.
    BIGNUM* p_max = BN_new();
    BN_lshift(p_max, BN_value_one(), k_ - 1);
    BN_mul_word(p_max, 3);
    BN_mul_word(p_max, committee_size_);

    // K = 2^security_bits
    BIGNUM* K = BN_new();
    BN_lshift(K, BN_value_one(), security_bits_);

    // K^2 * p_max^2
    BIGNUM* K2 = BN_new();
    BN_sqr(K2, K, ctx.ctx);
    BIGNUM* p_max2 = BN_new();
    BN_sqr(p_max2, p_max, ctx.ctx);
    BIGNUM* Rb_bound = BN_new();
    BN_mul(Rb_bound, K2, p_max2, ctx.ctx);

    // Ra_bound = K * p_max
    BIGNUM* Ra_bound = BN_new();
    BN_mul(Ra_bound, K, p_max, ctx.ctx);

    // Sample ra_i in [0, Ra_bound), rb_i in [0, Rb_bound)
    BIGNUM* ra_i = BN_new();
    BIGNUM* rb_i = BN_new();
    BN_rand_range(ra_i, Ra_bound);
    BN_rand_range(rb_i, Rb_bound);

    // VSS-deal ra_i and rb_i at degree t.
    dao_vss_commitments commits_ra, commits_rb;
    std::vector<BIGNUM*> s_ra, s_rb, b_ra, b_rb;
    if (!dao_vss_deal(*vss_group_, ra_i, committee_size_, t,
                      commits_ra, s_ra, b_ra)) {
        BN_free(p_max); BN_free(K); BN_free(K2);
        BN_free(p_max2); BN_free(Rb_bound); BN_free(Ra_bound);
        BN_free(ra_i); BN_free(rb_i);
        return false;
    }
    if (!dao_vss_deal(*vss_group_, rb_i, committee_size_, t,
                      commits_rb, s_rb, b_rb)) {
        BN_free(p_max); BN_free(K); BN_free(K2);
        BN_free(p_max2); BN_free(Rb_bound); BN_free(Ra_bound);
        BN_free(ra_i); BN_free(rb_i);
        return false;
    }

    // Broadcast commitments.
    {
        dkg_msg m = make_header(dkg_msg_type::trial_division_ra_commit, 0);
        m.tag32 = party_id_;
        for (const auto& c : commits_ra.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }
    {
        dkg_msg m = make_header(dkg_msg_type::trial_division_rb_commit, 0);
        m.tag32 = party_id_;
        for (const auto& c : commits_rb.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }

    // Private shares.
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (j == party_id_) {
            if (ra_shares_received_[j]) BN_free(ra_shares_received_[j]);
            if (rb_shares_received_[j]) BN_free(rb_shares_received_[j]);
            ra_shares_received_[j] = BN_dup(s_ra[j - 1]);
            rb_shares_received_[j] = BN_dup(s_rb[j - 1]);
            continue;
        }
        dkg_msg m = make_header(dkg_msg_type::trial_division_ra_share, j);
        m.tag32 = party_id_;
        const int n1 = BN_num_bytes(s_ra[j - 1]);
        m.bytes_a.assign(n1, 0);
        BN_bn2bin(s_ra[j - 1], m.bytes_a.data());
        const int n2 = BN_num_bytes(s_rb[j - 1]);
        m.bytes_b.assign(n2, 0);
        BN_bn2bin(s_rb[j - 1], m.bytes_b.data());
        if (!send_msg(m)) return false;
    }

    for (auto* x : s_ra) BN_free(x);
    for (auto* x : s_rb) BN_free(x);
    for (auto* x : b_ra) BN_free(x);
    for (auto* x : b_rb) BN_free(x);
    BN_free(p_max); BN_free(K); BN_free(K2);
    BN_free(p_max2); BN_free(Rb_bound); BN_free(Ra_bound);
    BN_free(ra_i); BN_free(rb_i);
    return true;
}

bool dkg_party::do_trial_division_gamma(uint32_t r)
{
    if (!share_p_ || !share_q_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    // Sum received ra/rb shares into the party's share of Ra and Rb.
    BIGNUM* sra = BN_new();
    BIGNUM* srb = BN_new();
    BN_zero(sra); BN_zero(srb);
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (!ra_shares_received_[j] || !rb_shares_received_[j]) return false;
        BN_add(sra, sra, ra_shares_received_[j]);
        BN_add(srb, srb, rb_shares_received_[j]);
    }
    free_bn(share_ra_);
    free_bn(share_rb_);
    share_ra_ = sra;
    share_rb_ = srb;

    // Party's share of the factor to test.
    BIGNUM* share_factor = (trial_r_ == 0) ? share_p_ : share_q_;

    // H_gamma is a shared degree-2t polynomial with H_gamma(0) = 0.
    // Its purpose is to randomize the individual share values of the
    // BGW product (P(x)-1)*Ra(x). In this implementation we set it to
    // zero. The security of the trial-division test does not depend on
    // it here because Ra and Rb are VSS-shared and unknown to any
    // single party, so the reconstructed value
    //     gamma = (p-1)*Ra + r*Rb
    // is already masked relative to p mod r. Setting the term to zero
    // (rather than sampling it locally per party) is required for
    // correctness: a per-party random term does not vanish under
    // Lagrange interpolation and masks the (p-1) mod r == 0 condition,
    // causing the test to falsely accept candidates whose small-prime
    // condition fails.
    BIGNUM* hi = BN_new();
    BN_zero(hi);

    // gamma_share_i = (share_factor - 1) * share_ra + h_i(i) + r * share_rb
    BIGNUM* pminus1 = BN_new();
    BN_sub(pminus1, share_factor, BN_value_one());

    BIGNUM* prod = BN_new();
    BN_mul(prod, pminus1, share_ra_, ctx.ctx);
    BN_add(prod, prod, hi);

    BIGNUM* rbn = BN_new();
    BN_set_word(rbn, r);
    BIGNUM* rterm = BN_new();
    BN_mul(rterm, rbn, share_rb_, ctx.ctx);
    BN_add(prod, prod, rterm);

    free_bn(gamma_share_);
    gamma_share_ = prod;

    dkg_msg m = make_header(dkg_msg_type::trial_division_gamma, 0);
    m.tag32 = party_id_;
    const int nb = BN_num_bytes(gamma_share_);
    m.bytes_a.assign(nb, 0);
    BN_bn2bin(gamma_share_, m.bytes_a.data());
    const bool sent = send_msg(m);
    BN_free(pminus1); BN_free(rbn); BN_free(rterm); BN_free(hi);
    return sent;
}

// -------------------------------------------------------------------
// start_phase / handle_message
// -------------------------------------------------------------------

bool dkg_party::start_phase(uint32_t phase, uint32_t k,
                            uint32_t security_bits, uint32_t target_N_bits)
{
    phase_ = phase;
    k_ = k;
    security_bits_ = security_bits;
    target_N_bits_ = target_N_bits;
    // qproof_rounds is set by the driver via set_qproof_rounds().

    switch (phase) {
        case 1: return do_polynomial_commit();
        case 2: return do_bgw_product();
        case 3: return true;   // driver broadcasts g_bar
        case 4: return do_publish_Q();
        case 5: return true;   // trial division handled by driver
        case 6: return do_phi_share_init();
        case 7: return do_beta_R_generate();
        case 8: return do_beta_R_collect();
        case 9: return do_compute_theta_share();
        case 10: return do_compute_SK();
        case 11: return do_v_commit();
        case 12: return do_v_reveal();
        case 13: return do_compute_V();
        default: return false;
    }
}

bool dkg_party::handle_message(const dkg_msg& m)
{
    if (m.hdr.epoch != epoch_) return false;
    if (m.hdr.candidate_id != candidate_id_) return false;
    if (std::memcmp(m.hdr.committee_id_hash, committee_id_hash_, 32) != 0)
        return false;
    if (m.hdr.sender_id > committee_size_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    switch (m.hdr.type) {
        case dkg_msg_type::polynomial_commitment_p: {
            const uint32_t j = m.hdr.sender_id;
            if (j < 1 || j > committee_size_) return false;
            commits_p_recv_[j].C = m.vec_a;
            return true;
        }

        case dkg_msg_type::polynomial_commitment_q: {
            const uint32_t j = m.hdr.sender_id;
            if (j < 1 || j > committee_size_) return false;
            commits_q_recv_[j].C = m.vec_a;
            return true;
        }

        case dkg_msg_type::polynomial_commitment_h:
            return true;   // not needed for Gap 3 verification

        case dkg_msg_type::polynomial_share: {
            const uint32_t j = m.hdr.sender_id;
            if (j < 1 || j > committee_size_) return false;
            if (m.bytes_a.empty() || m.bytes_b.empty() || m.bytes_c.empty())
                return false;
            if (m.bytes_d.empty() || m.vec_a.empty() || m.vec_a[0].empty())
                return false;
            if (!vss_group_ || !vss_group_->valid()) return false;
            if (commits_p_recv_[j].C.empty() || commits_q_recv_[j].C.empty())
                return false;

            BIGNUM* sp = BN_bin2bn(m.bytes_a.data(),
                                   static_cast<int>(m.bytes_a.size()), nullptr);
            BIGNUM* sq = BN_bin2bn(m.bytes_b.data(),
                                   static_cast<int>(m.bytes_b.size()), nullptr);
            BIGNUM* sh = BN_bin2bn(m.bytes_c.data(),
                                   static_cast<int>(m.bytes_c.size()), nullptr);
            BIGNUM* bp = bn_from_signed(m.bytes_d);
            BIGNUM* bq = bn_from_signed(m.vec_a[0]);
            if (!sp || !sq || !sh || !bp || !bq) {
                BN_free(sp); BN_free(sq); BN_free(sh);
                BN_free(bp); BN_free(bq);
                aborted_ = true; return false;
            }

            if (!dao_vss_verify_share(*vss_group_, commits_p_recv_[j],
                                      committee_size_, party_id_, sp, bp) ||
                !dao_vss_verify_share(*vss_group_, commits_q_recv_[j],
                                      committee_size_, party_id_, sq, bq)) {
                BN_free(sp); BN_free(sq); BN_free(sh);
                BN_free(bp); BN_free(bq);
                aborted_ = true; return false;
            }

            if (shares_p_received_[j]) BN_free(shares_p_received_[j]);
            if (shares_q_received_[j]) BN_free(shares_q_received_[j]);
            if (shares_h_received_[j]) BN_free(shares_h_received_[j]);
            if (b_p_received_[j]) BN_free(b_p_received_[j]);
            if (b_q_received_[j]) BN_free(b_q_received_[j]);
            shares_p_received_[j] = sp;
            shares_q_received_[j] = sq;
            shares_h_received_[j] = sh;
            b_p_received_[j] = bp;
            b_q_received_[j] = bq;
            return true;
        }

        case dkg_msg_type::bgw_product_share: {
            const uint32_t j = m.hdr.sender_id;
            if (m.bytes_a.empty()) return false;
            BIGNUM* v = BN_bin2bn(m.bytes_a.data(),
                                  static_cast<int>(m.bytes_a.size()), nullptr);
            if (!v) return false;
            if (N_i_received_[j]) BN_free(N_i_received_[j]);
            N_i_received_[j] = v;
            return true;
        }

        case dkg_msg_type::candidate_N: {
            if (m.bytes_a.empty()) return false;
            BIGNUM* nb = BN_bin2bn(m.bytes_a.data(),
                                   static_cast<int>(m.bytes_a.size()), nullptr);
            if (!nb) return false;
            free_bn(N_candidate_);
            N_candidate_ = nb;
            return true;
        }

        case dkg_msg_type::biprimality_base: {
            if (m.bytes_a.empty()) return false;
            BIGNUM* gb = BN_bin2bn(m.bytes_a.data(),
                                   static_cast<int>(m.bytes_a.size()), nullptr);
            if (!gb) return false;
            free_bn(g_bar_);
            g_bar_ = gb;
            return true;
        }

        case dkg_msg_type::biprimality_Q: {
            const uint32_t j = m.tag32;
            if (j < 1 || j > committee_size_) return false;
            if (m.bytes_b.empty()) return false;

            // bytes_a = C0', bytes_b = Q, bytes_c = proof.
            // The party does not need to store C0' or the proof
            // itself; the driver collects and verifies them from the
            // message stream directly. Here we just store Q.
            BIGNUM* Q = BN_bin2bn(m.bytes_b.data(),
                                  static_cast<int>(m.bytes_b.size()), nullptr);
            if (!Q) return false;
            if (Q_received_[j]) BN_free(Q_received_[j]);
            Q_received_[j] = Q;
            return true;
        }

        case dkg_msg_type::beta_commit: {
            const uint32_t j = m.tag32;
            if (j < 1 || j > committee_size_) return false;
            commits_beta_recv_[j].C = m.vec_a;
            return true;
        }

        case dkg_msg_type::r_commit: {
            const uint32_t j = m.tag32;
            if (j < 1 || j > committee_size_) return false;
            commits_dr_recv_[j].C = m.vec_a;
            return true;
        }

        case dkg_msg_type::theta_share:
        case dkg_msg_type::v_commit:
            return true;   // driver holds these

        case dkg_msg_type::beta_share: {
            const uint32_t j = m.tag32;
            if (j < 1 || j > committee_size_) return false;
            if (m.bytes_a.empty() || m.bytes_b.empty() ||
                m.bytes_c.empty() || m.bytes_d.empty()) return false;
            if (!vss_group_ || !vss_group_->valid()) return false;
            if (commits_beta_recv_[j].C.empty() || commits_dr_recv_[j].C.empty())
                return false;

            BIGNUM* bv = bn_from_signed(m.bytes_a);
            BIGNUM* rv = bn_from_signed(m.bytes_b);
            BIGNUM* bb = bn_from_signed(m.bytes_c);
            BIGNUM* br = bn_from_signed(m.bytes_d);
            if (!bv || !rv || !bb || !br) {
                BN_free(bv); BN_free(rv); BN_free(bb); BN_free(br);
                aborted_ = true; return false;
            }

            if (!dao_vss_verify_share(*vss_group_, commits_beta_recv_[j],
                                      committee_size_, party_id_, bv, bb) ||
                !dao_vss_verify_share(*vss_group_, commits_dr_recv_[j],
                                      committee_size_, party_id_, rv, br)) {
                BN_free(bv); BN_free(rv); BN_free(bb); BN_free(br);
                aborted_ = true; return false;
            }

            if (beta_shares_received_[j]) BN_free(beta_shares_received_[j]);
            if (delta_r_shares_received_[j]) BN_free(delta_r_shares_received_[j]);
            if (b_beta_received_[j]) BN_free(b_beta_received_[j]);
            if (b_dr_received_[j]) BN_free(b_dr_received_[j]);
            beta_shares_received_[j] = bv;
            delta_r_shares_received_[j] = rv;
            b_beta_received_[j] = bb;
            b_dr_received_[j] = br;
            return true;
        }

        case dkg_msg_type::h_theta_share: {
            const uint32_t j = m.tag32;
            if (j < 1 || j > committee_size_) return false;

            // Broadcast form: commitments in vec_a, no bytes_a.
            if (m.hdr.recipient_id == 0) {
                commits_h_theta_recv_[j].C = m.vec_a;
                return true;
            }

            // Private form: share in bytes_a, blinding in bytes_b.
            if (m.bytes_a.empty() || m.bytes_b.empty()) return false;
            if (!vss_group_ || !vss_group_->valid()) return false;
            if (commits_h_theta_recv_[j].C.empty()) return false;

            BIGNUM* hv = bn_from_signed(m.bytes_a);
            BIGNUM* bh = bn_from_signed(m.bytes_b);
            if (!hv || !bh) {
                BN_free(hv); BN_free(bh);
                aborted_ = true; return false;
            }

            if (!dao_vss_verify_share(*vss_group_, commits_h_theta_recv_[j],
                                      committee_size_, party_id_, hv, bh)) {
                BN_free(hv); BN_free(bh);
                aborted_ = true; return false;
            }

            if (h_theta_shares_received_[j]) BN_free(h_theta_shares_received_[j]);
            if (b_h_theta_received_[j]) BN_free(b_h_theta_received_[j]);
            h_theta_shares_received_[j] = hv;
            b_h_theta_received_[j] = bh;
            return true;
        }

        case dkg_msg_type::theta_tilde_broadcast: {
            if (m.bytes_a.empty()) return false;
            BIGNUM* tv = BN_bin2bn(m.bytes_a.data(),
                                   static_cast<int>(m.bytes_a.size()), nullptr);
            if (!tv) return false;
            free_bn(theta_tilde_);
            theta_tilde_ = tv;
            // Compute theta = theta_tilde mod N.
            if (N_candidate_) {
                BIGNUM* t = BN_new();
                BN_CTX* c = BN_CTX_new();
                BN_mod(t, theta_tilde_, N_candidate_, c);
                free_bn(theta_);
                theta_ = t;
                BN_CTX_free(c);
            }
            return true;
        }

        case dkg_msg_type::v_reveal: {
            const uint32_t j = m.tag32;
            if (j < 1 || j > committee_size_) return false;
            if (m.bytes_a.empty()) return false;
            BIGNUM* rv = BN_bin2bn(m.bytes_a.data(),
                                   static_cast<int>(m.bytes_a.size()), nullptr);
            if (!rv) return false;
            if (v_reveal_received_[j]) BN_free(v_reveal_received_[j]);
            v_reveal_received_[j] = rv;
            return true;
        }

        case dkg_msg_type::trial_division_ra_commit:
        case dkg_msg_type::trial_division_rb_commit:
            return true;   // driver holds these

        case dkg_msg_type::trial_division_ra_share: {
            const uint32_t j = m.hdr.sender_id;
            if (j < 1 || j > committee_size_) return false;
            if (m.bytes_a.empty() || m.bytes_b.empty()) return false;
            BIGNUM* sra = BN_bin2bn(m.bytes_a.data(),
                                    static_cast<int>(m.bytes_a.size()), nullptr);
            BIGNUM* srb = BN_bin2bn(m.bytes_b.data(),
                                    static_cast<int>(m.bytes_b.size()), nullptr);
            if (!sra || !srb) { BN_free(sra); BN_free(srb); return false; }
            if (ra_shares_received_[j]) BN_free(ra_shares_received_[j]);
            if (rb_shares_received_[j]) BN_free(rb_shares_received_[j]);
            ra_shares_received_[j] = sra;
            rb_shares_received_[j] = srb;
            return true;
        }

        case dkg_msg_type::trial_division_gamma:
            return true;   // collected by driver

        case dkg_msg_type::candidate_reject:
            aborted_ = true;
            return true;

        default:
            return true;
    }
}

bool dkg_party::public_N(std::vector<uint8_t>& out) const
{
    if (!N_candidate_) return false;
    const int nb = BN_num_bytes(N_candidate_);
    out.assign(nb, 0);
    BN_bn2bin(N_candidate_, out.data());
    return true;
}

// ====================================================================
// §5 threshold key derivation
// ====================================================================

bool dkg_party::do_phi_share_init()
{
    if (!share_p_ || !share_q_ || !N_candidate_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* phi = BN_new();
    BN_add(phi, N_candidate_, BN_value_one());
    BN_sub(phi, phi, share_p_);
    BN_sub(phi, phi, share_q_);

    free_bn(phi_share_);
    phi_share_ = phi;
    return true;
}

bool dkg_party::do_beta_R_generate()
{
    if (!N_candidate_ || !vss_group_ || !vss_group_->valid()) return false;
    if (security_bits_ == 0) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    const uint32_t t = threshold_ - 1;

    // beta_i in [0, K*N], R_i in [0, K^2*N]
    BIGNUM* K = BN_new();
    BN_lshift(K, BN_value_one(), security_bits_);

    BIGNUM* K2 = BN_new();
    BN_sqr(K2, K, ctx.ctx);

    BIGNUM* beta_bound = BN_new();
    BN_mul(beta_bound, K, N_candidate_, ctx.ctx);

    BIGNUM* r_bound = BN_new();
    BN_mul(r_bound, K2, N_candidate_, ctx.ctx);

    free_bn(beta_i_);
    free_bn(R_i_);
    beta_i_ = BN_new();
    R_i_    = BN_new();
    BN_rand_range(beta_i_, beta_bound);
    BN_rand_range(R_i_, r_bound);

    // Delta * R_i
    BIGNUM* delta_R = BN_new();
    BN_mul(delta_R, dao_dkg_delta(), R_i_, ctx.ctx);

    // VSS deal beta_i and delta_R at degree t, capturing the constant
    // blinding of each so we can prove the value is in range.
    std::vector<BIGNUM*> s_beta, b_beta, s_dr, b_dr;
    BIGNUM* beta_blinding = nullptr;
    BIGNUM* dr_blinding   = nullptr;
    if (!dao_vss_deal(*vss_group_, beta_i_, committee_size_, t,
                      commits_beta_, s_beta, b_beta, &beta_blinding)) {
        BN_free(K); BN_free(K2); BN_free(beta_bound); BN_free(r_bound);
        BN_free(delta_R);
        return false;
    }
    if (!dao_vss_deal(*vss_group_, delta_R, committee_size_, t,
                      commits_delta_r_, s_dr, b_dr, &dr_blinding)) {
        BN_free(beta_blinding);
        BN_free(K); BN_free(K2); BN_free(beta_bound); BN_free(r_bound);
        BN_free(delta_R);
        return false;
    }

    // VSS deal h_theta at degree 2t with h_theta(0) = 0.
    BIGNUM* zero = BN_new();
    BN_zero(zero);
    std::vector<BIGNUM*> s_h, b_h;
    if (!dao_vss_deal(*vss_group_, zero, committee_size_, 2 * t,
                      commits_h_theta_, s_h, b_h)) {
        BN_free(zero); BN_free(K); BN_free(K2);
        BN_free(beta_bound); BN_free(r_bound); BN_free(delta_R);
        BN_free(beta_blinding); BN_free(dr_blinding);
        return false;
    }
    BN_free(zero);

    // Range proofs over the two published constants.
    //   beta_bits  = target_N_bits + security_bits
    //   dr_bits    = target_N_bits + 2*security_bits + delta_bits
    // where delta_bits = ceil(log2(Delta)).
    const uint32_t beta_bits = target_N_bits_ + security_bits_;
    const uint32_t delta_bits =
        static_cast<uint32_t>(BN_num_bits(dao_dkg_delta()));
    const uint32_t dr_bits = target_N_bits_ + 2 * security_bits_ + delta_bits;

    BIGNUM* C_beta = nullptr;
    BIGNUM* C_dr   = nullptr;
    {
        C_beta = BN_bin2bn(commits_beta_.C[0].data(),
                           static_cast<int>(commits_beta_.C[0].size()), nullptr);
        C_dr   = BN_bin2bn(commits_delta_r_.C[0].data(),
                           static_cast<int>(commits_delta_r_.C[0].size()), nullptr);
        if (!C_beta || !C_dr) {
            BN_free(C_beta); BN_free(C_dr);
            BN_free(beta_blinding); BN_free(dr_blinding);
            for (auto* x : s_beta) BN_free(x);
            for (auto* x : b_beta) BN_free(x);
            for (auto* x : s_dr)   BN_free(x);
            for (auto* x : b_dr)   BN_free(x);
            for (auto* x : s_h)    BN_free(x);
            for (auto* x : b_h)    BN_free(x);
            BN_free(K); BN_free(K2); BN_free(beta_bound); BN_free(r_bound);
            BN_free(delta_R);
            return false;
        }
    }

    dao_range_proof beta_range;
    dao_range_proof dr_range;
    bool proofs_ok =
        dao_range_prove(*vss_group_, epoch_, party_id_,
                        DAO_RANGE_VALUE_TAG_BETA,
                        beta_i_, beta_blinding, C_beta, beta_bits, beta_range) &&
        dao_range_prove(*vss_group_, epoch_, party_id_,
                        DAO_RANGE_VALUE_TAG_R,
                        delta_R, dr_blinding, C_dr, dr_bits, dr_range);

    BN_free(C_beta); BN_free(C_dr);
    BN_free(beta_blinding); BN_free(dr_blinding);

    if (!proofs_ok) {
        for (auto* x : s_beta) BN_free(x);
        for (auto* x : b_beta) BN_free(x);
        for (auto* x : s_dr)   BN_free(x);
        for (auto* x : b_dr)   BN_free(x);
        for (auto* x : s_h)    BN_free(x);
        for (auto* x : b_h)    BN_free(x);
        BN_free(K); BN_free(K2); BN_free(beta_bound); BN_free(r_bound);
        BN_free(delta_R);
        return false;
    }

    // Broadcast commitments.
    {
        dkg_msg m = make_header(dkg_msg_type::beta_commit, 0);
        m.tag32 = party_id_;
        for (const auto& c : commits_beta_.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }
    {
        dkg_msg m = make_header(dkg_msg_type::r_commit, 0);
        m.tag32 = party_id_;
        for (const auto& c : commits_delta_r_.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }
    {
        dkg_msg m = make_header(dkg_msg_type::h_theta_share, 0);
        m.tag32 = party_id_;
        for (const auto& c : commits_h_theta_.C) m.vec_a.push_back(c);
        if (!send_msg(m)) return false;
    }
    {
        dkg_msg m = make_header(dkg_msg_type::beta_range_proof, 0);
        m.tag32 = party_id_;
        if (!beta_range.serialize(m.bytes_a)) return false;
        if (!send_msg(m)) return false;
    }
    {
        dkg_msg m = make_header(dkg_msg_type::r_range_proof, 0);
        m.tag32 = party_id_;
        if (!dr_range.serialize(m.bytes_a)) return false;
        if (!send_msg(m)) return false;
    }

    // Private shares.
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (j == party_id_) {
            if (beta_shares_received_[j]) BN_free(beta_shares_received_[j]);
            if (delta_r_shares_received_[j]) BN_free(delta_r_shares_received_[j]);
            if (h_theta_shares_received_[j]) BN_free(h_theta_shares_received_[j]);
            if (b_beta_received_[j]) BN_free(b_beta_received_[j]);
            if (b_dr_received_[j]) BN_free(b_dr_received_[j]);
            if (b_h_theta_received_[j]) BN_free(b_h_theta_received_[j]);
            beta_shares_received_[j] = BN_dup(s_beta[j - 1]);
            delta_r_shares_received_[j] = BN_dup(s_dr[j - 1]);
            h_theta_shares_received_[j] = BN_dup(s_h[j - 1]);
            b_beta_received_[j] = BN_dup(b_beta[j - 1]);
            b_dr_received_[j] = BN_dup(b_dr[j - 1]);
            b_h_theta_received_[j] = BN_dup(b_h[j - 1]);
            continue;
        }
        dkg_msg m = make_header(dkg_msg_type::beta_share, j);
        m.tag32 = party_id_;
        bn_to_signed(s_beta[j - 1], m.bytes_a);
        bn_to_signed(s_dr[j - 1], m.bytes_b);
        bn_to_signed(b_beta[j - 1], m.bytes_c);
        bn_to_signed(b_dr[j - 1], m.bytes_d);
        if (!send_msg(m)) return false;

        dkg_msg mh = make_header(dkg_msg_type::h_theta_share, j);
        mh.tag32 = party_id_;
        bn_to_signed(s_h[j - 1], mh.bytes_a);
        bn_to_signed(b_h[j - 1], mh.bytes_b);
        if (!send_msg(mh)) return false;
    }

    for (auto* x : s_beta) BN_free(x);
    for (auto* x : b_beta) BN_free(x);
    for (auto* x : s_dr) BN_free(x);
    for (auto* x : b_dr) BN_free(x);
    for (auto* x : s_h) BN_free(x);
    for (auto* x : b_h) BN_free(x);
    BN_free(K); BN_free(K2); BN_free(beta_bound); BN_free(r_bound);
    BN_free(delta_R);
    return true;
}

bool dkg_party::do_beta_R_collect()
{
    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* bsum = BN_new();
    BIGNUM* rsum = BN_new();
    BIGNUM* hsum = BN_new();
    BN_zero(bsum); BN_zero(rsum); BN_zero(hsum);

    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (!beta_shares_received_[j] ||
            !delta_r_shares_received_[j] ||
            !h_theta_shares_received_[j]) {
            BN_free(bsum); BN_free(rsum); BN_free(hsum);
            return false;
        }
        BN_add(bsum, bsum, beta_shares_received_[j]);
        BN_add(rsum, rsum, delta_r_shares_received_[j]);
        BN_add(hsum, hsum, h_theta_shares_received_[j]);
    }

    free_bn(beta_share_);
    free_bn(f1_share_);
    free_bn(h_theta_share_);
    beta_share_ = bsum;
    f1_share_   = rsum;
    h_theta_share_ = hsum;
    return true;
}

bool dkg_party::do_compute_theta_share()
{
    if (!phi_share_ || !beta_share_ || !f1_share_ ||
        !h_theta_share_ || !N_candidate_) return false;
    if (!vss_group_ || !vss_group_->valid()) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    // Compute Theta(i) = Delta * Phi(i) * Beta(i) + N * F1(i) + H_theta(i).
    {
        BIGNUM* prod = BN_new();
        BIGNUM* nf1 = BN_new();
        BIGNUM* theta_i = BN_new();
        if (!prod || !nf1 || !theta_i) {
            BN_free(prod); BN_free(nf1); BN_free(theta_i);
            return false;
        }
        BN_mul(prod, phi_share_, beta_share_, ctx.ctx);
        BN_mul(prod, prod, dao_dkg_delta(), ctx.ctx);
        BN_mul(nf1, N_candidate_, f1_share_, ctx.ctx);
        BN_add(theta_i, prod, nf1);
        BN_add(theta_i, theta_i, h_theta_share_);
        free_bn(theta_share_);
        theta_share_ = theta_i;
        BN_free(prod); BN_free(nf1);
    }

    // Local helper: aggregate commitment evaluation at point party_id_.
    auto agg_eval = [&](const std::vector<dao_vss_commitments>& per,
                        BIGNUM* out) -> bool {
        if (!out) return false;
        if (per.size() < 2) return false;
        if (per[1].C.empty()) return false;
        const uint32_t t = static_cast<uint32_t>(per[1].C.size()) - 1;
        BIGNUM* acc = BN_new();
        BIGNUM* pw  = BN_new();
        if (!acc || !pw) { BN_free(acc); BN_free(pw); return false; }
        BN_one(acc); BN_one(pw);
        bool lok = true;
        for (uint32_t k = 0; k <= t && lok; ++k) {
            BIGNUM* coeff = BN_new();
            BN_one(coeff);
            for (size_t j = 1; j < per.size() && lok; ++j) {
                if (k >= per[j].C.size()) { lok = false; break; }
                BIGNUM* Ck = BN_bin2bn(per[j].C[k].data(),
                                       static_cast<int>(per[j].C[k].size()),
                                       nullptr);
                if (!Ck || !BN_mod_mul(coeff, coeff, Ck,
                                       vss_group_->P, ctx.ctx)) {
                    BN_free(Ck); lok = false; break;
                }
                BN_free(Ck);
            }
            if (!lok) { BN_free(coeff); break; }
            BIGNUM* term = BN_new();
            if (!term ||
                !BN_mod_exp(term, coeff, pw, vss_group_->P, ctx.ctx) ||
                !BN_mod_mul(acc, acc, term, vss_group_->P, ctx.ctx)) {
                BN_free(term); BN_free(coeff); lok = false; break;
            }
            BN_free(term); BN_free(coeff);
            if (k < t) {
                BN_mul_word(pw, party_id_);
                BN_mod(pw, pw, vss_group_->P_prime, ctx.ctx);
            }
        }
        if (lok) BN_copy(out, acc);
        BN_free(acc); BN_free(pw);
        return lok;
    };

    BIGNUM* C_p_i      = nullptr;
    BIGNUM* C_q_i      = nullptr;
    BIGNUM* C_phi_i    = nullptr;
    BIGNUM* r_phi_i    = nullptr;
    BIGNUM* r_beta_i   = nullptr;
    BIGNUM* k_prod     = nullptr;
    BIGNUM* C_prod     = nullptr;
    BIGNUM* r_prod     = nullptr;
    BIGNUM* C_theta_i  = nullptr;
    BIGNUM* r_theta    = nullptr;
    bool ok = false;

    C_p_i = BN_new();
    C_q_i = BN_new();
    if (!C_beta_i_)    C_beta_i_    = BN_new();
    if (!C_f1_i_)      C_f1_i_      = BN_new();
    if (!C_h_theta_i_) C_h_theta_i_ = BN_new();
    if (!C_p_i || !C_q_i || !C_beta_i_ || !C_f1_i_ || !C_h_theta_i_)
        goto done;
    if (!agg_eval(commits_p_recv_, C_p_i)) goto done;
    if (!agg_eval(commits_q_recv_, C_q_i)) goto done;
    if (!agg_eval(commits_beta_recv_, C_beta_i_)) goto done;
    if (!agg_eval(commits_dr_recv_, C_f1_i_)) goto done;
    if (!agg_eval(commits_h_theta_recv_, C_h_theta_i_)) goto done;

    // C_phi_i = g^(N+1) * C_p_i^(-1) * C_q_i^(-1) mod P.
    C_phi_i = BN_new();
    if (!C_phi_i) goto done;
    {
        BIGNUM* Np1  = BN_new();
        BIGNUM* Np1m = BN_new();
        BIGNUM* gNp1 = BN_new();
        BIGNUM* invp = BN_new();
        BIGNUM* invq = BN_new();
        if (!Np1 || !Np1m || !gNp1 || !invp || !invq) {
            BN_free(Np1); BN_free(Np1m); BN_free(gNp1);
            BN_free(invp); BN_free(invq);
            goto done;
        }
        BN_add(Np1, N_candidate_, BN_value_one());
        BN_nnmod(Np1m, Np1, vss_group_->P_prime, ctx.ctx);
        if (!BN_mod_exp(gNp1, vss_group_->g, Np1m, vss_group_->P, ctx.ctx) ||
            !BN_mod_inverse(invp, C_p_i, vss_group_->P, ctx.ctx) ||
            !BN_mod_inverse(invq, C_q_i, vss_group_->P, ctx.ctx) ||
            !BN_mod_mul(C_phi_i, gNp1, invp, vss_group_->P, ctx.ctx) ||
            !BN_mod_mul(C_phi_i, C_phi_i, invq, vss_group_->P, ctx.ctx)) {
            BN_free(Np1); BN_free(Np1m); BN_free(gNp1);
            BN_free(invp); BN_free(invq);
            goto done;
        }
        BN_free(Np1); BN_free(Np1m); BN_free(gNp1);
        BN_free(invp); BN_free(invq);
    }

    // r_phi_i = -(sum_j b_p_received_[j] + sum_j b_q_received_[j]) mod P'.
    // r_beta_i = sum_j b_beta_received_[j] mod P'.
    r_phi_i  = BN_new();
    r_beta_i = BN_new();
    if (!r_phi_i || !r_beta_i) goto done;
    BN_zero(r_phi_i);
    BN_zero(r_beta_i);
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (b_p_received_[j])
            BN_mod_add(r_phi_i, r_phi_i, b_p_received_[j],
                       vss_group_->P_prime, ctx.ctx);
        if (b_q_received_[j])
            BN_mod_add(r_phi_i, r_phi_i, b_q_received_[j],
                       vss_group_->P_prime, ctx.ctx);
        if (b_beta_received_[j])
            BN_mod_add(r_beta_i, r_beta_i, b_beta_received_[j],
                       vss_group_->P_prime, ctx.ctx);
    }
    {
        BIGNUM* zb = BN_new();
        if (!zb) goto done;
        BN_zero(zb);
        BN_mod_sub(r_phi_i, zb, r_phi_i, vss_group_->P_prime, ctx.ctx);
        BN_free(zb);
    }

    // C_prod = C_phi_i^Beta(i) * h^k_prod.
    k_prod = BN_new();
    C_prod = BN_new();
    if (!k_prod || !C_prod) goto done;
    BN_rand_range(k_prod, vss_group_->P_prime);
    {
        BIGNUM* bmod = BN_new();
        BIGNUM* t1   = BN_new();
        BIGNUM* t2   = BN_new();
        if (!bmod || !t1 || !t2) {
            BN_free(bmod); BN_free(t1); BN_free(t2);
            goto done;
        }
        BN_nnmod(bmod, beta_share_, vss_group_->P_prime, ctx.ctx);
        if (!BN_mod_exp(t1, C_phi_i, bmod, vss_group_->P, ctx.ctx) ||
            !BN_mod_exp(t2, vss_group_->h, k_prod, vss_group_->P, ctx.ctx) ||
            !BN_mod_mul(C_prod, t1, t2, vss_group_->P, ctx.ctx)) {
            BN_free(bmod); BN_free(t1); BN_free(t2);
            goto done;
        }
        BN_free(bmod); BN_free(t1); BN_free(t2);
    }

    // r_prod = Beta(i) * r_phi_i + k_prod mod P'.
    r_prod = BN_new();
    if (!r_prod) goto done;
    {
        BIGNUM* bmod = BN_new();
        BIGNUM* term = BN_new();
        if (!bmod || !term) {
            BN_free(bmod); BN_free(term);
            goto done;
        }
        BN_nnmod(bmod, beta_share_, vss_group_->P_prime, ctx.ctx);
        BN_mod_mul(term, bmod, r_phi_i, vss_group_->P_prime, ctx.ctx);
        BN_mod_add(r_prod, term, k_prod, vss_group_->P_prime, ctx.ctx);
        BN_free(bmod); BN_free(term);
    }

    // C_theta_i = C_prod^Delta * C_f1_i^N * C_h_theta_i mod P.
    C_theta_i = BN_new();
    if (!C_theta_i) goto done;
    {
        BIGNUM* dm = BN_new();
        BIGNUM* nm = BN_new();
        BIGNUM* t1 = BN_new();
        BIGNUM* t2 = BN_new();
        BIGNUM* t3 = BN_new();
        if (!dm || !nm || !t1 || !t2 || !t3) {
            BN_free(dm); BN_free(nm); BN_free(t1); BN_free(t2); BN_free(t3);
            goto done;
        }
        BN_nnmod(dm, dao_dkg_delta(), vss_group_->P_prime, ctx.ctx);
        BN_nnmod(nm, N_candidate_, vss_group_->P_prime, ctx.ctx);
        if (!BN_mod_exp(t1, C_prod, dm, vss_group_->P, ctx.ctx) ||
            !BN_mod_exp(t2, C_f1_i_, nm, vss_group_->P, ctx.ctx) ||
            !BN_mod_mul(t3, t1, t2, vss_group_->P, ctx.ctx) ||
            !BN_mod_mul(C_theta_i, t3, C_h_theta_i_,
                        vss_group_->P, ctx.ctx)) {
            BN_free(dm); BN_free(nm); BN_free(t1); BN_free(t2); BN_free(t3);
            goto done;
        }
        BN_free(dm); BN_free(nm); BN_free(t1); BN_free(t2); BN_free(t3);
    }

    // r_theta = Delta*r_prod + N*b_dr_sum + b_h_theta_sum mod P'.
    r_theta = BN_new();
    if (!r_theta) goto done;
    {
        BIGNUM* drs = BN_new();
        BIGNUM* hhs = BN_new();
        if (!drs || !hhs) {
            BN_free(drs); BN_free(hhs);
            goto done;
        }
        BN_zero(drs); BN_zero(hhs);
        for (uint32_t j = 1; j <= committee_size_; ++j) {
            if (b_dr_received_[j])
                BN_mod_add(drs, drs, b_dr_received_[j],
                           vss_group_->P_prime, ctx.ctx);
            if (b_h_theta_received_[j])
                BN_mod_add(hhs, hhs, b_h_theta_received_[j],
                           vss_group_->P_prime, ctx.ctx);
        }
        BIGNUM* dm = BN_new();
        BIGNUM* nm = BN_new();
        BIGNUM* t1 = BN_new();
        BIGNUM* t2 = BN_new();
        if (!dm || !nm || !t1 || !t2) {
            BN_free(dm); BN_free(nm); BN_free(t1); BN_free(t2);
            BN_free(drs); BN_free(hhs);
            goto done;
        }
        BN_nnmod(dm, dao_dkg_delta(), vss_group_->P_prime, ctx.ctx);
        BN_nnmod(nm, N_candidate_, vss_group_->P_prime, ctx.ctx);
        BN_mod_mul(t1, dm, r_prod, vss_group_->P_prime, ctx.ctx);
        BN_mod_mul(t2, nm, drs, vss_group_->P_prime, ctx.ctx);
        BN_mod_add(r_theta, t1, t2, vss_group_->P_prime, ctx.ctx);
        BN_mod_add(r_theta, r_theta, hhs, vss_group_->P_prime, ctx.ctx);
        BN_free(dm); BN_free(nm); BN_free(t1); BN_free(t2);
        BN_free(drs); BN_free(hhs);
    }

#ifdef VEILROOT_DAO_DKG_TESTING
    // Sanity: C_theta_i == g^theta_share_ * h^r_theta mod P.
    {
        BIGNUM* ts  = BN_new();
        BIGNUM* tsr = BN_new();
        BIGNUM* ga  = BN_new();
        BIGNUM* hb  = BN_new();
        BIGNUM* chk = BN_new();
        if (!ts || !tsr || !ga || !hb || !chk) {
            BN_free(ts); BN_free(tsr); BN_free(ga); BN_free(hb); BN_free(chk);
            goto done;
        }
        BN_nnmod(tsr, theta_share_, vss_group_->P_prime, ctx.ctx);
        BN_mod_exp(ga, vss_group_->g, tsr, vss_group_->P, ctx.ctx);
        BN_mod_exp(hb, vss_group_->h, r_theta, vss_group_->P, ctx.ctx);
        BN_mod_mul(chk, ga, hb, vss_group_->P, ctx.ctx);
        if (BN_cmp(chk, C_theta_i) != 0) {
            std::cerr << "[theta] C_theta sanity FAILED for party "
                      << party_id_ << "\n";
            BN_free(ts); BN_free(tsr); BN_free(ga); BN_free(hb); BN_free(chk);
            goto done;
        }
        BN_free(ts); BN_free(tsr); BN_free(ga); BN_free(hb); BN_free(chk);
    }
#endif

    // Generate proofs.
    {
        dao_theta_mul_proof mul_proof;
        dao_theta_open_proof open_proof;
        if (!dao_theta_mul_prove(*vss_group_, epoch_, candidate_id_, party_id_,
                                 N_candidate_, C_phi_i, C_beta_i_,
                                 beta_share_, r_beta_i, k_prod, C_prod,
                                 mul_proof)) goto done;
        if (!dao_theta_open_prove(*vss_group_, epoch_, candidate_id_, party_id_,
                                  C_theta_i, theta_share_, r_theta,
                                  open_proof)) goto done;

        dkg_msg m = make_header(dkg_msg_type::theta_share, 0);
        m.tag32 = party_id_;
        bn_to_signed(theta_share_, m.bytes_a);
        auto bn_to_vec = [](const BIGNUM* x, std::vector<uint8_t>& v) {
            const int nb = BN_num_bytes(x);
            v.assign(nb, 0);
            BN_bn2bin(x, v.data());
        };
        bn_to_vec(C_prod, m.bytes_b);
        bn_to_vec(C_theta_i, m.bytes_c);
        if (!mul_proof.serialize(m.bytes_d)) goto done;
        {
            std::vector<uint8_t> enc;
            if (!open_proof.serialize(enc)) goto done;
            m.vec_a.push_back(std::move(enc));
        }
        if (!send_msg(m)) goto done;
    }

    // Cache for driver-side inspection.
    free_bn(C_phi_i_);      C_phi_i_     = C_phi_i;      C_phi_i = nullptr;
    free_bn(C_prod_);       C_prod_      = C_prod;       C_prod = nullptr;
    free_bn(C_theta_i_);    C_theta_i_   = C_theta_i;    C_theta_i = nullptr;
    free_bn(r_phi_i_);      r_phi_i_     = r_phi_i;      r_phi_i = nullptr;
    free_bn(r_beta_i_);     r_beta_i_    = r_beta_i;     r_beta_i = nullptr;
    free_bn(k_prod_);       k_prod_      = k_prod;       k_prod = nullptr;
    free_bn(r_prod_i_);     r_prod_i_    = r_prod;       r_prod = nullptr;
    free_bn(r_theta_i_);    r_theta_i_   = r_theta;      r_theta = nullptr;

    ok = true;

done:
    BN_free(C_p_i); BN_free(C_q_i);
    BN_free(C_phi_i); BN_free(r_phi_i); BN_free(r_beta_i);
    BN_free(k_prod); BN_free(C_prod); BN_free(r_prod);
    BN_free(C_theta_i); BN_free(r_theta);
    return ok;
}

bool dkg_party::do_compute_SK()
{
    if (!f1_share_ || !theta_tilde_ || !N_candidate_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* nf1 = BN_new();
    BN_mul(nf1, N_candidate_, f1_share_, ctx.ctx);

    BIGNUM* sk = BN_new();
    BN_sub(sk, nf1, theta_tilde_);

    free_bn(SK_i_);
    SK_i_ = sk;
    BN_free(nf1);
    return true;
}

bool dkg_party::set_theta_tilde(const BIGNUM* v)
{
    if (!v) return false;
    free_bn(theta_tilde_);
    theta_tilde_ = BN_dup(v);
    if (!theta_tilde_) return false;
    if (N_candidate_) {
        CtxGuard ctx;
        if (!ctx.ok()) return false;
        BIGNUM* t = BN_new();
        BN_mod(t, theta_tilde_, N_candidate_, ctx.ctx);
        free_bn(theta_);
        theta_ = t;
    }
    return true;
}

bool dkg_party::set_V(const BIGNUM* v)
{
    if (!v) return false;
    free_bn(V_);
    V_ = BN_dup(v);
    return V_ != nullptr;
}

bool dkg_party::do_v_commit()
{
    if (!N_candidate_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    // r_i sampled uniformly from Z*_{N^2}.
    BIGNUM* N2 = BN_new();
    if (!N2) return false;
    if (!BN_sqr(N2, N_candidate_, ctx.ctx)) { BN_free(N2); return false; }

    BIGNUM* r_i = BN_new();
    BIGNUM* gcd = BN_new();
    if (!r_i || !gcd) { BN_free(N2); BN_free(r_i); BN_free(gcd); return false; }

    bool ok = false;
    for (int tries = 0; tries < 256 && !ok; ++tries) {
        if (!BN_rand_range(r_i, N2)) break;
        if (BN_is_zero(r_i)) continue;
        if (!BN_gcd(gcd, r_i, N2, ctx.ctx)) break;
        if (BN_is_one(gcd)) ok = true;
    }
    BN_free(N2); BN_free(gcd);
    if (!ok) { BN_free(r_i); return false; }

    free_bn(v_r_i_);
    v_r_i_ = r_i;

    const int rb = BN_num_bytes(v_r_i_);
    std::vector<uint8_t> rbytes(rb, 0);
    BN_bn2bin(v_r_i_, rbytes.data());

    std::vector<uint8_t> digest;
    compute_v_commit(epoch_, party_id_, rbytes, digest);

    dkg_msg m = make_header(dkg_msg_type::v_commit, 0);
    m.tag32 = party_id_;
    m.bytes_a = digest;
    return send_msg(m);
}

bool dkg_party::do_v_reveal()
{
    if (!v_r_i_) return false;

    dkg_msg m = make_header(dkg_msg_type::v_reveal, 0);
    m.tag32 = party_id_;
    const int n = BN_num_bytes(v_r_i_);
    m.bytes_a.assign(n, 0);
    BN_bn2bin(v_r_i_, m.bytes_a.data());
    return send_msg(m);
}

bool dkg_party::do_compute_V()
{
    if (!N_candidate_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N_candidate_, ctx.ctx);

    BIGNUM* r = BN_new();
    BN_one(r);
    for (uint32_t j = 1; j <= committee_size_; ++j) {
        if (!v_reveal_received_[j]) { BN_free(N2); BN_free(r); return false; }
        BN_mod_mul(r, r, v_reveal_received_[j], N2, ctx.ctx);
    }
    BIGNUM* V = BN_new();
    BN_mod_mul(V, r, r, N2, ctx.ctx);

    free_bn(V_);
    V_ = V;

    BN_free(N2); BN_free(r);
    return true;
}

bool dkg_party::do_derive_VKi(std::vector<uint8_t>& VKi_out)
{
    if (!V_ || !SK_i_ || !N_candidate_) return false;

    CtxGuard ctx;
    if (!ctx.ok()) return false;

    BIGNUM* N2 = BN_new();
    BN_sqr(N2, N_candidate_, ctx.ctx);

    // exp = Delta * SK_i, may be negative.
    BIGNUM* exp = BN_new();
    BN_mul(exp, dao_dkg_delta(), SK_i_, ctx.ctx);

    BIGNUM* result = BN_new();
    if (BN_is_negative(exp)) {
        BIGNUM* Vinv = BN_mod_inverse(nullptr, V_, N2, ctx.ctx);
        BIGNUM* pos = BN_dup(exp);
        BN_set_negative(pos, 0);
        BN_mod_exp(result, Vinv, pos, N2, ctx.ctx);
        BN_free(Vinv); BN_free(pos);
    } else {
        BN_mod_exp(result, V_, exp, N2, ctx.ctx);
    }

    // V_K_i is a value mod N^2. The record format is fixed width
    // regardless of N's bit length in the test configuration, so pad
    // to PAILLIER_CT_BYTES.
    VKi_out.assign(PAILLIER_CT_BYTES, 0);
    BN_bn2binpad(result, VKi_out.data(),
                 static_cast<int>(PAILLIER_CT_BYTES));

    BN_free(N2); BN_free(exp); BN_free(result);
    return true;
}

// ====================================================================
// Driver
// ====================================================================

namespace {

// Interpolate N from the party shares N_i via Lagrange at zero over
// the integers. The shares are values of the degree-2t polynomial
// alpha(x), and we want alpha(0).
bool lagrange_interpolate_zero(const std::vector<uint32_t>& subset,
                               const std::vector<const BIGNUM*>& shares,
                               BIGNUM* out, BN_CTX* ctx)
{
    if (subset.size() != shares.size()) return false;
    if (subset.empty()) return false;

    BIGNUM* total = BN_new();
    BN_zero(total);

    for (size_t k = 0; k < subset.size(); ++k) {
        const int64_t i = static_cast<int64_t>(subset[k]);

        // numerator = prod_{j != k} (-j)
        // denominator = prod_{j != k} (i - j)
        BIGNUM* num = BN_new();
        BIGNUM* den = BN_new();
        BN_one(num);
        BN_one(den);

        for (size_t j = 0; j < subset.size(); ++j) {
            if (j == k) continue;
            const int64_t jj = static_cast<int64_t>(subset[j]);
            BIGNUM* bj = BN_new();
            BN_set_word(bj, static_cast<BN_ULONG>(jj < 0 ? -jj : jj));
            if (jj < 0) BN_set_negative(bj, 1);
            BN_mul(num, num, bj, ctx);
            BN_set_negative(num, !BN_is_negative(num));
            BN_free(bj);

            BIGNUM* diff = BN_new();
            BN_set_word(diff, static_cast<BN_ULONG>(i));
            BIGNUM* bj2 = BN_new();
            BN_set_word(bj2, static_cast<BN_ULONG>(jj));
            BN_sub(diff, diff, bj2);
            BN_mul(den, den, diff, ctx);
            BN_free(diff); BN_free(bj2);
        }

        // term = share * num / den
        BIGNUM* term = BN_new();
        BN_mul(term, shares[k], num, ctx);
        BN_div(term, nullptr, term, den, ctx);
        BN_add(total, total, term);

        BN_free(num); BN_free(den); BN_free(term);
    }

    BN_copy(out, total);
    BN_free(total);
    return true;
}

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
bool party_get_N_i(const dkg_party& p, BIGNUM* out);

// Extract the Q_i value a party computed in phase 4.
bool party_get_Q_i(const dkg_party& p, BIGNUM* out);

// Extract the lambda share from phase 6.
bool party_get_lambda_share(const dkg_party& p, BIGNUM* out);

} // anonymous namespace

// ====================================================================
// Public entry points
// ====================================================================

std::unique_ptr<dkg_party> dkg_party_create(uint32_t party_id,
                                            uint32_t committee_size,
                                            uint32_t threshold,
                                            uint32_t epoch)
{
    return std::unique_ptr<dkg_party>(
        new dkg_party(party_id, committee_size, threshold, epoch));
}

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
    uint32_t epoch,
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
    fs_append_u32be(buf, epoch);
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
    uint32_t epoch,
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
    fs_append_u32be(buf, epoch);
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
    uint32_t epoch,
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
    fs_append_u32be(buf, epoch);
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
    uint32_t epoch,
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
    fs_append_u32be(buf, epoch);
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

void dkg_transcript::append(const dkg_msg& m)
{
    entry e;
    e.candidate_id = m.hdr.candidate_id;
    e.phase        = m.hdr.phase;
    e.round        = m.hdr.round;
    e.sender_id    = m.hdr.sender_id;
    e.recipient_id = m.hdr.recipient_id;
    e.type         = static_cast<uint8_t>(m.hdr.type);
    e.sequence     = m.hdr.sequence;
    if (!m.serialize(e.canonical)) return;
    entries_.push_back(std::move(e));
}

void dkg_transcript::hash(std::vector<uint8_t>& out) const
{
    std::vector<entry> sorted = entries_;

    std::sort(sorted.begin(), sorted.end(),
        [](const entry& a, const entry& b) {
            if (a.candidate_id != b.candidate_id) return a.candidate_id < b.candidate_id;
            if (a.phase        != b.phase)        return a.phase        < b.phase;
            if (a.round        != b.round)        return a.round        < b.round;
            if (a.sender_id    != b.sender_id)    return a.sender_id    < b.sender_id;
            if (a.recipient_id != b.recipient_id) return a.recipient_id < b.recipient_id;
            if (a.type         != b.type)         return a.type         < b.type;
            if (a.sequence     != b.sequence)     return a.sequence     < b.sequence;
            return a.canonical < b.canonical;
        });

    sorted.erase(
        std::unique(sorted.begin(), sorted.end(),
            [](const entry& a, const entry& b) {
                return a.canonical == b.canonical;
            }),
        sorted.end());

    std::vector<uint8_t> buf;
    const char* dom = "VeilRoot-DAO-DKG-TRANSCRIPT-V1";
    buf.insert(buf.end(), dom, dom + std::strlen(dom));
    for (const auto& e : sorted) {
        buf.insert(buf.end(), e.canonical.begin(), e.canonical.end());
    }

    out.assign(32, 0);
    SHA256(buf.data(), buf.size(), out.data());
}

namespace {

// Drain every transport until no more messages are pending. Every
// drained message is recorded in the canonical transcript.
void drain_all(const std::vector<std::unique_ptr<dkg_transport>>& transports,
               std::vector<dkg_msg>& collected,
               dkg_transcript& transcript)
{
    bool any = false;
    do {
        any = false;
        for (const auto& t : transports) {
            dkg_msg m;
            while (t->try_recv(m)) {
                collected.push_back(m);
                transcript.append(m);
                any = true;
            }
        }
    } while (any);
}

// Route collected messages to all parties whose id matches the
// recipient (or to all if recipient is 0).
bool deliver_all(const std::vector<std::unique_ptr<dkg_party>>& parties,
                 const std::vector<dkg_msg>& msgs)
{
    for (const auto& m : msgs) {
        if (m.hdr.recipient_id == 0) {
            for (const auto& p : parties) {
                if (!p->handle_message(m)) return false;
            }
        } else {
            for (const auto& p : parties) {
                if (p->id() == m.hdr.recipient_id) {
                    if (!p->handle_message(m)) return false;
                }
            }
        }
    }
    return true;
}

// Reconstruct N from the N_i values via Lagrange interpolation over
// the integers at x=0. Uses any (2t+1) = 15 of the 16 shares.
bool reconstruct_N(const std::vector<std::unique_ptr<dkg_party>>& parties,
                   BIGNUM* N_out)
{
    CtxGuard ctx;
    if (!ctx.ok()) return false;

    std::vector<uint32_t> subset;
    std::vector<const BIGNUM*> shares;

    for (const auto& p : parties) {
        // We do not have an accessor for the raw N_i here; the party's
        // N_candidate_ field is set only after the driver has computed
        // N. The N_i values are what the parties broadcast, and the
        // driver collected them from the transports. This function is
        // therefore called with the collected N_i values by the caller,
        // not by reading the parties.
        (void)p;
    }
    // Placeholder: the caller supplies shares explicitly.
    (void)subset;
    (void)shares;
    (void)N_out;
    return false;
}

// Perform one candidate attempt: phases 1-2 and reconstruction of N.
// Returns true if a candidate N was reconstructed.
bool run_modulus_attempt(const dkg_config& cfg,
                         std::vector<std::unique_ptr<dkg_party>>& parties,
                         std::vector<std::unique_ptr<dkg_transport>>& transports,
                         dkg_transcript& transcript,
                         BIGNUM* N_out)
{
    // Phase 1: each party deals VSS and sends shares.
    for (auto& p : parties) {
        if (!p->start_phase(1, cfg.k, cfg.security_bits, cfg.target_N_bits))
            return false;
    }

    std::vector<dkg_msg> collected;
    drain_all(transports, collected, transcript);
    if (!deliver_all(parties, collected)) return false;
    collected.clear();

    // Phase 2: each party forms N_i and broadcasts.
    for (auto& p : parties) {
        if (!p->start_phase(2, cfg.k, cfg.security_bits, cfg.target_N_bits))
            return false;
    }

    drain_all(transports, collected, transcript);

    // Collect the broadcast N_i values from the message stream.
    std::vector<BIGNUM*> N_i(parties.size() + 1, nullptr);
    for (const auto& m : collected) {
        if (m.hdr.type != dkg_msg_type::bgw_product_share) continue;
        const uint32_t j = m.hdr.sender_id;
        if (j < 1 || j > parties.size()) return false;
        if (m.bytes_a.empty()) return false;
        N_i[j] = BN_bin2bn(m.bytes_a.data(),
                           static_cast<int>(m.bytes_a.size()), nullptr);
        if (!N_i[j]) return false;
    }

    // Also deliver the messages so the parties can continue.
    if (!deliver_all(parties, collected)) return false;

    // Verify all N_i are present.
    for (size_t j = 1; j <= parties.size(); ++j) {
        if (!N_i[j]) {
            for (auto* x : N_i) if (x) BN_free(x);
            return false;
        }
    }

    // Interpolate at zero using the first 2t+1 = 15 shares.
    const uint32_t deg = 2 * (cfg.threshold - 1);
    const uint32_t need = deg + 1;
    if (parties.size() < need) {
        for (auto* x : N_i) if (x) BN_free(x);
        return false;
    }

    std::vector<uint32_t> idx;
    std::vector<const BIGNUM*> vals;
    for (uint32_t j = 1; j <= need; ++j) {
        idx.push_back(j);
        vals.push_back(N_i[j]);
    }

    CtxGuard ctx;
    if (!ctx.ok()) {
        for (auto* x : N_i) if (x) BN_free(x);
        return false;
    }
    const bool ok = lagrange_interpolate_zero(idx, vals, N_out, ctx.ctx);
    for (auto* x : N_i) if (x) BN_free(x);
    return ok;
}

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
bool trial_division_check_factor(
    const std::vector<std::unique_ptr<dkg_party>>& parties,
    std::vector<std::unique_ptr<dkg_transport>>& transports,
    const dkg_config& cfg,
    dkg_transcript& transcript,
    uint32_t factor_selector)
{
    const uint32_t t = cfg.threshold - 1;
    const uint32_t deg = 2 * t;
    const uint32_t need = deg + 1;   // 2t+1 = 15 shares

    for (size_t r_idx = 0; r_idx < DAO_DKG_SMALL_PRIME_COUNT; ++r_idx) {
        const uint32_t r = DAO_DKG_SMALL_PRIMES[r_idx];
        bool passed = false;

        for (uint32_t rep = 0; rep < DAO_DKG_TRIAL_DIVISION_REPS && !passed; ++rep) {
            // Phase: prolog.
            for (auto& p : parties) {
                if (!p->do_trial_division_prolog(factor_selector)) return false;
            }
            {
                std::vector<dkg_msg> collected;
                drain_all(transports, collected, transcript);
                if (!deliver_all(parties, collected)) return false;
            }

            // Phase: gamma share.
            for (auto& p : parties) {
                if (!p->do_trial_division_gamma(r)) return false;
            }

            std::vector<dkg_msg> collected;
            drain_all(transports, collected, transcript);

            // Collect gamma shares.
            std::vector<BIGNUM*> gamma_shares(parties.size() + 1, nullptr);
            for (const auto& m : collected) {
                if (m.hdr.type != dkg_msg_type::trial_division_gamma) continue;
                const uint32_t j = m.tag32;
                if (j < 1 || j > parties.size()) continue;
                if (m.bytes_a.empty()) continue;
                gamma_shares[j] = BN_bin2bn(m.bytes_a.data(),
                                            static_cast<int>(m.bytes_a.size()),
                                            nullptr);
            }
            // Deliver so parties keep any state they need.
            if (!deliver_all(parties, collected)) return false;

            bool all_present = true;
            for (size_t j = 1; j <= need; ++j) {
                if (!gamma_shares[j]) { all_present = false; break; }
            }
            if (!all_present) {
                for (auto* x : gamma_shares) if (x) BN_free(x);
                return false;
            }

            // Reconstruct gamma via Lagrange at 0 using the first `need`
            // shares.
            CtxGuard ctx;
            if (!ctx.ok()) {
                for (auto* x : gamma_shares) if (x) BN_free(x);
                return false;
            }

            std::vector<uint32_t> idx;
            std::vector<const BIGNUM*> vals;
            for (uint32_t j = 1; j <= need; ++j) {
                idx.push_back(j);
                vals.push_back(gamma_shares[j]);
            }
            BIGNUM* gamma = BN_new();
            if (!lagrange_interpolate_zero(idx, vals, gamma, ctx.ctx)) {
                BN_free(gamma);
                for (auto* x : gamma_shares) if (x) BN_free(x);
                return false;
            }
            for (auto* x : gamma_shares) if (x) BN_free(x);

            // gcd(gamma, r) == 1?
            BIGNUM* rbn = BN_new();
            BN_set_word(rbn, r);
            BIGNUM* g = BN_new();
            BN_gcd(g, gamma, rbn, ctx.ctx);
            if (BN_is_one(g)) passed = true;

            BN_free(rbn); BN_free(g); BN_free(gamma);
        }

        if (!passed) return false;
    }
    return true;
}

} // anonymous namespace

// ====================================================================
// dkg_run_with_transport
// ====================================================================

bool dkg_run_with_transport(const dkg_config& cfg,
                            const dkg_transport_factory& factory,
                            dkg_result& out)
{
    out = dkg_result{};

    if (cfg.committee_size < DAO_DKG_MIN_COMMITTEE_SIZE ||
        cfg.committee_size > DAO_DKG_MAX_COMMITTEE_SIZE)
        return false;

    const uint32_t expected_threshold =
        dao_dkg_expected_threshold(cfg.committee_size);
    if (expected_threshold == 0) return false;
    if (cfg.threshold != expected_threshold) return false;

    dkg_transcript transcript;

    // Create transports.
    std::vector<std::unique_ptr<dkg_transport>> transports;
    transports.reserve(cfg.committee_size);
    for (uint32_t i = 1; i <= cfg.committee_size; ++i) {
        transports.push_back(factory(i));
        if (!transports.back()) return false;
    }

    // Compute committee_id_hash = SHA-256(
    //     domain || epoch || ordered member ids )
    // The member ids are 1..committee_size in ascending order.
    uint8_t committee_id_hash[32] = {};
    {
        std::vector<uint8_t> buf;
        const char* dom = DAO_DKG_COMMITTEE_DOMAIN;
        buf.insert(buf.end(), dom, dom + std::strlen(dom));
        for (int i = 0; i < 4; ++i) buf.push_back((cfg.epoch >> (8*i)) & 0xff);
        for (uint32_t i = 1; i <= cfg.committee_size; ++i) {
            for (int k = 0; k < 4; ++k) buf.push_back((i >> (8*k)) & 0xff);
        }
        SHA256(buf.data(), buf.size(), committee_id_hash);
    }

    // Create parties and attach transports.
    std::vector<std::unique_ptr<dkg_party>> parties;
    parties.reserve(cfg.committee_size);
    for (uint32_t i = 1; i <= cfg.committee_size; ++i) {
        auto p = dkg_party_create(i, cfg.committee_size, cfg.threshold, cfg.epoch);
        if (!p) return false;
        p->attach_transport(transports[i - 1].get());
        p->set_committee_id_hash(committee_id_hash);
        parties.push_back(std::move(p));
    }

    // The VSS group. In-process, one group is shared across all parties.
    // For the test configuration (k = 60), the size of the shares and
    // the products Ra*p is bounded by roughly 2^200, so a 512-bit P'
    // is sufficient. The production configuration chooses P' after
    // evaluating all bounds from §4.1, §5, and Appendix B.
    dao_vss_group vss;
    // P' must exceed the range-proof bit lengths per §7:
    //   beta_bits = target_N_bits + security_bits
    //   R_bits    = target_N_bits + 2*security_bits
    // dao_dkg_required_vss_bits already computes a bound derived from
    // those.
    const uint32_t required_bits =
        dao_dkg_required_vss_bits(cfg.k, cfg.target_N_bits, cfg.security_bits);
    if (!dao_vss_group_generate(vss, required_bits)) return false;
    if (!dao_vss_group_meets_requirement(vss, required_bits)) return false;

    for (auto& p : parties) {
        p->attach_vss_group(&vss);
        p->set_qproof_rounds(cfg.qproof_rounds);
    }

#ifdef VEILROOT_DAO_DKG_TESTING
    // Fixed known-good 128-bit candidate. Enabled when cfg.test_seed is
    // set to the marker value below. In that mode every party uses the
    // fixed p_i/q_i contributions, the candidate loop runs exactly once,
    // and the reconstructed N is asserted to match the expected value.
    static const char* TEST_P_I[16] = {
        "969268552214414479",  "888031839494547792",
        "1079397876156048660", "1006574070186212908",
        "877477030194816300",  "791836913387411172",
        "768506220692087400",  "813633058001625364",
        "666206511486790708",  "947746232640603164",
        "1105465569543844360", "607439790306659332",
        "1055474825484965160", "584154533438528320",
        "765317402755487352",  "906859206339637076"
    };
    static const char* TEST_Q_I[16] = {
        "788035984088342967",  "785893246012606672",
        "1008809060784577456", "956801234593989956",
        "622867011629669024",  "714583382660623768",
        "1152027874352792244", "873607243235969604",
        "1076454260578465704", "726189582184062888",
        "923866761182567912",  "587248126720312492",
        "979668901553805100",  "970721716908318012",
        "1021503496685327708", "591266747085483712"
    };
    constexpr uint64_t FIXED_TEST_CANDIDATE_SEED = 0x5645494C52544F54ULL;
    const bool use_fixed_candidate = (cfg.test_seed == FIXED_TEST_CANDIDATE_SEED);

    if (use_fixed_candidate) {
        if (cfg.committee_size != 16) return false;
        for (uint32_t i = 1; i <= cfg.committee_size; ++i) {
            BIGNUM* p = nullptr;
            BIGNUM* q = nullptr;
            if (BN_dec2bn(&p, TEST_P_I[i - 1]) == 0 ||
                BN_dec2bn(&q, TEST_Q_I[i - 1]) == 0) {
                BN_free(p); BN_free(q);
                return false;
            }
            parties[i - 1]->set_fixed_test_contribution(p, q);
            BN_free(p); BN_free(q);
        }
    }
#else
    const bool use_fixed_candidate = false;
#endif

    // Main candidate loop.
    BIGNUM* attempt_N  = BN_new();
    BIGNUM* accepted_N = BN_new();
    bool accepted = false;

#ifdef VEILROOT_DAO_DKG_TESTING
    const uint32_t attempt_limit =
        use_fixed_candidate ? 1u : cfg.max_attempts;
#else
    const uint32_t attempt_limit = cfg.max_attempts;
#endif

    for (uint32_t attempt = 1; attempt <= attempt_limit; ++attempt) {
        out.candidate_attempts = attempt;

        // Bind every party to the current candidate id. Messages from
        // a previous candidate attempt are then rejected by the
        // header check in handle_message.
        for (auto& p : parties) p->set_candidate_id(attempt);

        // A fresh attempt always starts from zero so no state from a
        // failed attempt can carry over.
        BN_zero(attempt_N);

        // Phases 1-2: modulus shares and reconstruction.
        if (!run_modulus_attempt(cfg, parties, transports, transcript, attempt_N)) {
            continue;
        }

        // Enforce exact target bit length.
        if (static_cast<uint32_t>(BN_num_bits(attempt_N)) != cfg.target_N_bits) {
            continue;
        }

        // Freeze the accepted modulus. From here to the end of the
        // loop body, `N` is const: nothing may write to it.
#ifdef VEILROOT_DAO_DKG_TESTING
        if (use_fixed_candidate) {
            static const char EXPECTED_N[] =
                "190617809826337441250605450219703325793";
            BIGNUM* expected = nullptr;
            if (BN_dec2bn(&expected, EXPECTED_N) == 0) return false;
            if (BN_cmp(attempt_N, expected) != 0) {
                BN_free(expected);
                return false;
            }
            BN_free(expected);
        }
#endif

        if (!BN_copy(accepted_N, attempt_N)) {
            continue;
        }
        const BIGNUM* N = accepted_N;

#ifdef VEILROOT_DAO_DKG_TESTING
        std::cerr << "[dkg] ACCEPTED at attempt " << attempt
                  << "  accepted_N bits=" << BN_num_bits(accepted_N) << "\n";
#endif

        // Declare g_bar before any goto to avoid jumping over its
        // initializer.
        BIGNUM* g_bar = BN_new();

        // Broadcast the reconstructed N to every party so they can
        // compute Q_i.
        {
            dkg_msg mN;
            mN.hdr.version = 1;
            mN.hdr.epoch = cfg.epoch;
            mN.hdr.candidate_id = attempt;
            std::memcpy(mN.hdr.committee_id_hash, committee_id_hash, 32);
            mN.hdr.sender_id = 0;
            mN.hdr.recipient_id = 0;
            mN.hdr.phase = 3;
            mN.hdr.type = dkg_msg_type::candidate_N;
            const int nbN = BN_num_bytes(N);
            mN.bytes_a.assign(nbN, 0);
            BN_bn2bin(N, mN.bytes_a.data());
            for (auto& p : parties) {
                if (!p->handle_message(mN)) {
                    BN_free(g_bar);
                    goto next_attempt;
                }
            }
        }

        // Phase 3: choose g_bar and broadcast.
        if (!choose_g_bar(N, g_bar)) {
            BN_free(g_bar);
            continue;
        }

        for (auto& p : parties) {
            dkg_msg m;
            m.hdr.version = 1;
            m.hdr.epoch = cfg.epoch;
            m.hdr.candidate_id = attempt;
            std::memcpy(m.hdr.committee_id_hash, committee_id_hash, 32);
            m.hdr.sender_id = 0;
            m.hdr.recipient_id = 0;
            m.hdr.phase = 3;
            m.hdr.type = dkg_msg_type::biprimality_base;
            const int nb = BN_num_bytes(g_bar);
            m.bytes_a.assign(nb, 0);
            BN_bn2bin(g_bar, m.bytes_a.data());
            if (!p->handle_message(m)) {
                BN_free(g_bar);
                goto next_attempt;
            }
        }

        // Phase 4: each party publishes Q_i.
        for (auto& p : parties) {
            if (!p->start_phase(4, cfg.k, cfg.security_bits, cfg.target_N_bits)) {
                BN_free(g_bar);
                goto next_attempt;
            }
        }

        // Drain and collect Q_i (with proofs), verify each proof, then
        // run the biprimality predicate.
        {
            std::vector<dkg_msg> collected;
            drain_all(transports, collected, transcript);

            std::vector<BIGNUM*> Q_own(cfg.committee_size + 1, nullptr);
            std::vector<const BIGNUM*> Q(cfg.committee_size + 1, nullptr);
            bool ok = true;

            for (const auto& m : collected) {
                if (m.hdr.type != dkg_msg_type::biprimality_Q) continue;
                const uint32_t j = m.tag32;
                if (j < 1 || j > cfg.committee_size) { ok = false; break; }
                if (m.bytes_a.empty() || m.bytes_b.empty() || m.bytes_c.empty()) {
                    ok = false; break;
                }
                if (Q_own[j]) continue;

                BIGNUM* C0p = BN_bin2bn(m.bytes_a.data(),
                                        static_cast<int>(m.bytes_a.size()),
                                        nullptr);
                BIGNUM* Qbn = BN_bin2bn(m.bytes_b.data(),
                                        static_cast<int>(m.bytes_b.size()),
                                        nullptr);
                if (!C0p || !Qbn) {
                    if (C0p) BN_free(C0p);
                    if (Qbn) BN_free(Qbn);
                    ok = false; break;
                }

                dao_Q_proof proof;
                if (!deserialize_Q_proof(m.bytes_c, proof) ||
                    proof.member_index != j) {
                    BN_free(C0p); BN_free(Qbn);
                    ok = false; break;
                }

                BIGNUM* g4 = BN_new();
                BIGNUM* four2 = BN_new();
                BN_set_word(four2, 4);
                BN_CTX* qctx = BN_CTX_new();
                if (!qctx) { BN_free(C0p); BN_free(Qbn); BN_free(g4); BN_free(four2); ok = false; break; }
                BN_mod_exp(g4, vss.g, four2, vss.P, qctx);
                BN_free(four2);
                BN_CTX_free(qctx);

                const bool vok = dao_Q_verify(vss, N, g4, vss.h, g_bar,
                                              C0p, Qbn, proof);
                BN_free(g4); BN_free(C0p);

                if (!vok) {
                    BN_free(Qbn);
                    ok = false; break;
                }

                Q_own[j] = Qbn;
                Q[j] = Qbn;
            }

            for (size_t j = 1; j <= cfg.committee_size && ok; ++j) {
                if (!Q[j]) ok = false;
            }

            if (ok) {
                const int bi = biprimality_check(Q, N);
                if (bi == 0) {
                    out.biprimality_failures++;
                    ok = false;
                } else if (bi < 0) {
                    ok = false;
                }
            }

            for (auto* q : Q_own) if (q) BN_free(q);

            if (!deliver_all(parties, collected)) {
                BN_free(g_bar);
                goto next_attempt;
            }

            if (!ok) {
                BN_free(g_bar);
                goto next_attempt;
            }
        }

        // Phase 5: trial division §4.1 on hidden p and q separately.
        // do_compute_share_pq aggregates the received VSS shares into
        // each party's own share of p and q.
        for (auto& p : parties) {
            if (!p->do_compute_share_pq()) {
                BN_free(g_bar);
                goto next_attempt;
            }
        }
        if (!trial_division_check_factor(parties, transports, cfg, transcript, 0)) {
            out.trial_division_failures++;
            BN_free(g_bar);
            goto next_attempt;
        }
        if (!trial_division_check_factor(parties, transports, cfg, transcript, 1)) {
            out.trial_division_failures++;
            BN_free(g_bar);
            goto next_attempt;
        }

        // Candidate accepted.
        {
            out.N.assign(PAILLIER_MODULUS_BYTES, 0);
            BN_bn2binpad(N, out.N.data(), PAILLIER_MODULUS_BYTES);
        }
        BN_free(g_bar);
        accepted = true;
        break;

    next_attempt:
        (void)0;
    }

    BN_free(attempt_N);

    if (!accepted) {
        BN_free(accepted_N);
        out.ok = false;
        out.candidate_accepted = false;
        return false;
    }

    // The accepted modulus is frozen for the remainder of this
    // function. Every phase below uses this exact object.
    const BIGNUM* N = accepted_N;

    out.candidate_accepted = true;
    out.epoch = cfg.epoch;

    // ---------------------------------------------------------------
    // Phases 6-13: threshold key derivation (§5)
    // ---------------------------------------------------------------

    // Theta_tilde may fail gcd(theta, N) == 1; retry the beta phase.
    bool key_ok = false;
    for (uint32_t beta_try = 1;
         beta_try <= 8 && !key_ok;
         ++beta_try)
    {
        if (beta_try > 1) out.beta_phase_retries++;

        // Phase 6: each party computes phi_share = N + 1 - p(i) - q(i).
        #ifdef VEILROOT_DAO_DKG_TESTING
        std::cerr << "[key-phase] try=" << beta_try << " start phase 6\n";
        #endif
        for (auto& p : parties) {
            if (!p->do_phi_share_init()) {
                #ifdef VEILROOT_DAO_DKG_TESTING
                std::cerr << "[key-phase] phase 6 failed\n";
                #endif
                goto after_key_phase;
            }
        }
        #ifdef VEILROOT_DAO_DKG_TESTING
        std::cerr << "[key-phase] phase 6 ok\n";
        #endif

        // Phase 7: beta_i, R_i generate + VSS deal + private share.
        for (auto& p : parties) {
            if (!p->do_beta_R_generate()) {
                #ifdef VEILROOT_DAO_DKG_TESTING
                std::cerr << "[key-phase] phase 7 failed\n";
                #endif
                goto after_key_phase;
            }
        }
        #ifdef VEILROOT_DAO_DKG_TESTING
        std::cerr << "[key-phase] phase 7 ok\n";
        #endif
        {
            std::vector<dkg_msg> collected;
            drain_all(transports, collected, transcript);

            // Collect each party's published constant VSS commitment for
            // beta and delta_R. Broadcast fan-out means multiple copies
            // per sender; identical content is fine.
            std::vector<std::vector<uint8_t>>
                beta_C0(cfg.committee_size + 1);
            std::vector<std::vector<uint8_t>>
                dr_C0(cfg.committee_size + 1);
            for (const auto& m : collected) {
                const uint32_t j = m.tag32;
                if (j < 1 || j > cfg.committee_size) continue;
                if (m.hdr.type == dkg_msg_type::beta_commit) {
                    if (!m.vec_a.empty()) beta_C0[j] = m.vec_a[0];
                } else if (m.hdr.type == dkg_msg_type::r_commit) {
                    if (!m.vec_a.empty()) dr_C0[j] = m.vec_a[0];
                }
            }

            // Verify every range proof against its published commitment.
            for (const auto& m : collected) {
                if (m.hdr.type != dkg_msg_type::beta_range_proof &&
                    m.hdr.type != dkg_msg_type::r_range_proof) continue;

                const uint32_t j = m.tag32;
                if (j < 1 || j > cfg.committee_size) goto after_key_phase;

                const bool is_beta =
                    (m.hdr.type == dkg_msg_type::beta_range_proof);
                const std::vector<uint8_t>& C0 = is_beta ? beta_C0[j] : dr_C0[j];
                if (C0.empty()) goto after_key_phase;

                BIGNUM* C_bn = BN_bin2bn(C0.data(),
                                         static_cast<int>(C0.size()),
                                         nullptr);
                if (!C_bn) goto after_key_phase;

                dao_range_proof proof;
                if (!proof.deserialize(m.bytes_a)) {
                    BN_free(C_bn);
                    goto after_key_phase;
                }

                const uint32_t value_tag = is_beta
                    ? DAO_RANGE_VALUE_TAG_BETA
                    : DAO_RANGE_VALUE_TAG_R;

                const bool ok = dao_range_verify(vss, cfg.epoch, j,
                                                 value_tag, C_bn, proof);
                BN_free(C_bn);
                if (!ok) {
                    #ifdef VEILROOT_DAO_DKG_TESTING
                    std::cerr << "[key-phase] range proof failed party "
                              << j << " tag " << value_tag << "\n";
                    #endif
                    goto after_key_phase;
                }
            }

            if (!deliver_all(parties, collected)) goto after_key_phase;
        }

        // Phase 8: aggregate Beta(i), F1(i), H_theta(i).
        for (auto& p : parties) {
            if (!p->do_beta_R_collect()) {
                #ifdef VEILROOT_DAO_DKG_TESTING
                std::cerr << "[key-phase] phase 8 failed\n";
                #endif
                goto after_key_phase;
            }
        }
        #ifdef VEILROOT_DAO_DKG_TESTING
        std::cerr << "[key-phase] phase 8 ok\n";
        #endif

        // Phase 9: compute Theta(i).
        for (auto& p : parties) {
            if (!p->do_compute_theta_share()) {
                #ifdef VEILROOT_DAO_DKG_TESTING
                std::cerr << "[key-phase] phase 9 failed\n";
                #endif
                goto after_key_phase;
            }
        }
        #ifdef VEILROOT_DAO_DKG_TESTING
        std::cerr << "[key-phase] phase 9 ok\n";
        #endif

        // Collect theta shares and reconstruct theta_tilde by Lagrange
        // at 0 over the 2t+1 = 15 largest-index shares.
        {
            std::vector<dkg_msg> collected;
            drain_all(transports, collected, transcript);

            const uint32_t deg = 2 * (cfg.threshold - 1);
            const uint32_t need = deg + 1;
            std::vector<BIGNUM*> theta_shares(cfg.committee_size + 1, nullptr);
            std::vector<BIGNUM*> C_prod_msgs(cfg.committee_size + 1, nullptr);
            std::vector<BIGNUM*> C_theta_msgs(cfg.committee_size + 1, nullptr);
            std::vector<dao_theta_mul_proof>  mul_proofs(cfg.committee_size + 1);
            std::vector<dao_theta_open_proof> open_proofs(cfg.committee_size + 1);
            std::vector<bool> proof_seen(cfg.committee_size + 1, false);
            bool proofs_ok = true;

            for (const auto& m : collected) {
                if (m.hdr.type != dkg_msg_type::theta_share) continue;
                const uint32_t j = m.tag32;
                if (j < 1 || j > cfg.committee_size) continue;
                if (m.bytes_a.empty()) continue;
                if (theta_shares[j]) continue;
                theta_shares[j] = bn_from_signed(m.bytes_a);
                if (!theta_shares[j]) { proofs_ok = false; break; }
                if (m.bytes_b.empty() || m.bytes_c.empty() ||
                    m.bytes_d.empty() || m.vec_a.empty() ||
                    m.vec_a[0].empty()) {
                    proofs_ok = false; break;
                }
                C_prod_msgs[j] = BN_bin2bn(m.bytes_b.data(),
                                           static_cast<int>(m.bytes_b.size()),
                                           nullptr);
                C_theta_msgs[j] = BN_bin2bn(m.bytes_c.data(),
                                            static_cast<int>(m.bytes_c.size()),
                                            nullptr);
                if (!C_prod_msgs[j] || !C_theta_msgs[j]) {
                    proofs_ok = false; break;
                }
                if (!mul_proofs[j].deserialize(m.bytes_d) ||
                    !open_proofs[j].deserialize(m.vec_a[0])) {
                    proofs_ok = false; break;
                }
                proof_seen[j] = true;
            }

            // Driver-side verification of every accepted theta proof.
            if (proofs_ok && !parties.empty()) {
                const std::vector<dao_vss_commitments>& cpr =
                    parties[0]->commits_p_recv();
                const std::vector<dao_vss_commitments>& cqr =
                    parties[0]->commits_q_recv();
                const std::vector<dao_vss_commitments>& cbr =
                    parties[0]->commits_beta_recv();
                const std::vector<dao_vss_commitments>& cdr =
                    parties[0]->commits_dr_recv();
                const std::vector<dao_vss_commitments>& chr =
                    parties[0]->commits_h_theta_recv();

                for (uint32_t j = 1; j <= cfg.committee_size; ++j) {
                    if (!proof_seen[j]) continue;
                    if (!theta_shares[j] || !C_prod_msgs[j] ||
                        !C_theta_msgs[j]) {
                        proofs_ok = false; break;
                    }

                    BIGNUM* C_p_i    = BN_new();
                    BIGNUM* C_q_i    = BN_new();
                    BIGNUM* C_beta_i = BN_new();
                    BIGNUM* C_f1_i   = BN_new();
                    BIGNUM* C_h_i    = BN_new();
                    BIGNUM* C_phi_i  = BN_new();
                    if (!C_p_i || !C_q_i || !C_beta_i || !C_f1_i ||
                        !C_h_i || !C_phi_i) {
                        BN_free(C_p_i); BN_free(C_q_i);
                        BN_free(C_beta_i); BN_free(C_f1_i);
                        BN_free(C_h_i); BN_free(C_phi_i);
                        proofs_ok = false; break;
                    }

                    if (!aggregate_eval_at(cpr, vss, j, C_p_i) ||
                        !aggregate_eval_at(cqr, vss, j, C_q_i) ||
                        !aggregate_eval_at(cbr, vss, j, C_beta_i) ||
                        !aggregate_eval_at(cdr, vss, j, C_f1_i) ||
                        !aggregate_eval_at(chr, vss, j, C_h_i)) {
                        BN_free(C_p_i); BN_free(C_q_i);
                        BN_free(C_beta_i); BN_free(C_f1_i);
                        BN_free(C_h_i); BN_free(C_phi_i);
                        proofs_ok = false; break;
                    }

                    // C_phi_i = g^(N+1) * C_p_i^(-1) * C_q_i^(-1) mod P.
                    BN_CTX* vctx = BN_CTX_new();
                    BIGNUM* Np1  = BN_new();
                    BIGNUM* Np1m = BN_new();
                    BIGNUM* gNp1 = BN_new();
                    BIGNUM* invp = BN_new();
                    BIGNUM* invq = BN_new();
                    bool cok = vctx && Np1 && Np1m && gNp1 && invp && invq;
                    if (cok) {
                        BN_add(Np1, N, BN_value_one());
                        BN_nnmod(Np1m, Np1, vss.P_prime, vctx);
                        cok = BN_mod_exp(gNp1, vss.g, Np1m, vss.P, vctx) &&
                              BN_mod_inverse(invp, C_p_i, vss.P, vctx) &&
                              BN_mod_inverse(invq, C_q_i, vss.P, vctx) &&
                              BN_mod_mul(C_phi_i, gNp1, invp, vss.P, vctx) &&
                              BN_mod_mul(C_phi_i, C_phi_i, invq, vss.P, vctx);
                    }
                    BN_free(Np1); BN_free(Np1m); BN_free(gNp1);
                    BN_free(invp); BN_free(invq);
                    if (vctx) BN_CTX_free(vctx);
                    BN_free(C_p_i); BN_free(C_q_i);
                    BN_free(C_f1_i); BN_free(C_h_i);

                    if (!cok) {
                        BN_free(C_beta_i); BN_free(C_phi_i);
                        proofs_ok = false; break;
                    }

                    const bool mvok = dao_theta_mul_verify(
                        vss, cfg.epoch, out.candidate_attempts, j, N,
                        C_phi_i, C_beta_i, C_prod_msgs[j], mul_proofs[j]);
                    const bool ovok = dao_theta_open_verify(
                        vss, cfg.epoch, out.candidate_attempts, j,
                        C_theta_msgs[j], theta_shares[j], open_proofs[j]);
                    BN_free(C_beta_i); BN_free(C_phi_i);

                    if (!mvok || !ovok) {
                        #ifdef VEILROOT_DAO_DKG_TESTING
                        std::cerr << "[key-phase] theta proof failed party "
                                  << j << " mul=" << mvok
                                  << " open=" << ovok << "\n";
                        #endif
                        proofs_ok = false; break;
                    }
                }
            }

            for (auto* x : C_prod_msgs)  if (x) BN_free(x);
            for (auto* x : C_theta_msgs) if (x) BN_free(x);

            if (!proofs_ok) {
                for (auto* x : theta_shares) if (x) BN_free(x);
                goto after_key_phase;
            }

            bool have_all = true;
            for (uint32_t j = 1; j <= need; ++j)
                if (!theta_shares[j]) { have_all = false; break; }

            CtxGuard ctx;
            BIGNUM* theta_tilde = nullptr;
            if (have_all && ctx.ok()) {
                std::vector<uint32_t> idx;
                std::vector<const BIGNUM*> vals;
                for (uint32_t j = 1; j <= need; ++j) {
                    idx.push_back(j);
                    vals.push_back(theta_shares[j]);
                }
                theta_tilde = BN_new();
                if (!lagrange_interpolate_zero(idx, vals, theta_tilde, ctx.ctx)) {
                    BN_free(theta_tilde);
                    theta_tilde = nullptr;
                }
            }
            for (auto* x : theta_shares) if (x) BN_free(x);

            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] theta_shares have_all=" << have_all << "\n";
            #endif
            if (!theta_tilde) {
                #ifdef VEILROOT_DAO_DKG_TESTING
                std::cerr << "[key-phase] theta_tilde reconstruction failed\n";
                #endif
                goto after_key_phase;
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] theta_tilde reconstructed\n";
            #endif

            // theta = theta_tilde mod N, always in [0, N).
            BIGNUM* theta = BN_new();
            BN_CTX* tctx = BN_CTX_new();
            BN_nnmod(theta, theta_tilde, N, tctx);
            BN_CTX_free(tctx);

            // gcd(theta, N) == 1? theta is now non-negative; N is
            // always non-negative.
            BIGNUM* gcd = BN_new();
            tctx = BN_CTX_new();
            BN_gcd(gcd, theta, N, tctx);
            const bool invertible = BN_is_one(gcd);
            BN_CTX_free(tctx);
            BN_free(gcd);

            if (!invertible) {
                #ifdef VEILROOT_DAO_DKG_TESTING
                std::cerr << "[key-phase] gcd(theta,N) != 1, retrying\n";
                #endif
                BN_free(theta_tilde);
                BN_free(theta);
                continue;   // retry beta phase
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] theta invertible\n";
            #endif

            // Broadcast theta_tilde to all parties.
            for (auto& p : parties) {
                if (!p->set_theta_tilde(theta_tilde)) {
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }

            // Save for later driver-side use.
            out.theta.assign(PAILLIER_MODULUS_BYTES, 0);
            BN_bn2binpad(theta, out.theta.data(), PAILLIER_MODULUS_BYTES);

            // Phase 10: each party computes SK_i = N*F1(i) - theta_tilde.
            for (auto& p : parties) {
                if (!p->do_compute_SK()) {
                    #ifdef VEILROOT_DAO_DKG_TESTING
                    std::cerr << "[key-phase] phase 10 failed\n";
                    #endif
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] phase 10 ok\n";
            #endif

            // Phase 11: V commit round.
            for (auto& p : parties) {
                if (!p->do_v_commit()) {
                    #ifdef VEILROOT_DAO_DKG_TESTING
                    std::cerr << "[key-phase] phase 11 failed\n";
                    #endif
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] phase 11 ok\n";
            #endif
            // Phase 11: collect commitments, then deliver to parties.
            std::vector<std::vector<uint8_t>> v_commits(cfg.committee_size + 1);
            {
                std::vector<dkg_msg> vcollected;
                drain_all(transports, vcollected, transcript);

                bool commits_ok = true;
                for (const auto& m : vcollected) {
                    if (m.hdr.type != dkg_msg_type::v_commit) continue;
                    const uint32_t j = m.tag32;
                    if (j < 1 || j > cfg.committee_size) { commits_ok = false; break; }
                    if (m.bytes_a.size() != 32) { commits_ok = false; break; }
                    if (!v_commits[j].empty()) {
                        // Duplicate from broadcast fan-out. Identical
                        // copies are fine; a different value from the
                        // same sender is a protocol violation.
                        if (v_commits[j] != m.bytes_a) { commits_ok = false; break; }
                        continue;
                    }
                    v_commits[j] = m.bytes_a;
                }
                for (uint32_t j = 1; j <= cfg.committee_size; ++j)
                    if (v_commits[j].empty()) { commits_ok = false; break; }

                if (!commits_ok || !deliver_all(parties, vcollected)) {
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }

            // Phase 12: V reveal round.
            for (auto& p : parties) {
                if (!p->do_v_reveal()) {
                    #ifdef VEILROOT_DAO_DKG_TESTING
                    std::cerr << "[key-phase] phase 12 failed\n";
                    #endif
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }
            {
                std::vector<dkg_msg> vcollected;
                drain_all(transports, vcollected, transcript);

                // Cross-check every reveal against the party's earlier
                // commitment. Recompute SHA-256 over the same canonical
                // buffer and require an exact match.
                std::vector<int> revealed(cfg.committee_size + 1, 0);
                bool reveals_ok = true;
                for (const auto& m : vcollected) {
                    if (m.hdr.type != dkg_msg_type::v_reveal) continue;
                    const uint32_t j = m.tag32;
                    if (j < 1 || j > cfg.committee_size) { reveals_ok = false; break; }
                    if (m.bytes_a.empty()) { reveals_ok = false; break; }
                    if (revealed[j]) continue;   // duplicate broadcast fan-out

                    std::vector<uint8_t> recomputed;
                    compute_v_commit(cfg.epoch, j, m.bytes_a, recomputed);
                    if (recomputed != v_commits[j]) {
                        reveals_ok = false; break;
                    }
                    revealed[j] = 1;
                }
                for (uint32_t j = 1; j <= cfg.committee_size; ++j)
                    if (!revealed[j]) { reveals_ok = false; break; }

                if (!reveals_ok) {
                    #ifdef VEILROOT_DAO_DKG_TESTING
                    std::cerr << "[key-phase] V reveal does not match commitment\n";
                    #endif
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }

                if (!deliver_all(parties, vcollected)) {
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] phase 12 ok\n";
            #endif

            // Phase 13: compute V.
            for (auto& p : parties) {
                if (!p->do_compute_V()) {
                    #ifdef VEILROOT_DAO_DKG_TESTING
                    std::cerr << "[key-phase] phase 13 failed\n";
                    #endif
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] phase 13 ok\n";
            #endif

            // Derive V_K_i for each party and collect.
            out.V_K_i.assign(cfg.committee_size, {});
            for (size_t k = 0; k < parties.size(); ++k) {
                if (!parties[k]->do_derive_VKi(out.V_K_i[k])) {
                    #ifdef VEILROOT_DAO_DKG_TESTING
                    std::cerr << "[key-phase] VKi failed at party " << k << "\n";
                    #endif
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
            }
            #ifdef VEILROOT_DAO_DKG_TESTING
            std::cerr << "[key-phase] VKi ok\n";
            #endif

            // Fill record basics.
            out.record.version        = 1;
            out.record.epoch          = cfg.epoch;
            out.record.committee_size = cfg.committee_size;
            out.record.threshold      = cfg.threshold;
            out.record.t              = cfg.threshold - 1;

            out.record.committee_id_hash.assign(32, 0);
            {
                SHA256_CTX sha;
                SHA256_Init(&sha);
                unsigned char eb[4];
                for (int i = 0; i < 4; ++i) eb[i] = (cfg.epoch >> (8*i)) & 0xff;
                SHA256_Update(&sha, eb, 4);
                SHA256_Final(out.record.committee_id_hash.data(), &sha);
            }

            out.record.delta.assign(32, 0);
            {
                BIGNUM* d = BN_dup(dao_dkg_delta());
                BN_bn2binpad(d, out.record.delta.data(), 32);
                BN_free(d);
            }

            out.record.N.assign(PAILLIER_MODULUS_BYTES, 0);
            BN_bn2binpad(N, out.record.N.data(), PAILLIER_MODULUS_BYTES);

            // G = N + 1.
            {
                BIGNUM* G = BN_new();
                BN_add(G, N, BN_value_one());
                out.record.G.assign(PAILLIER_MODULUS_BYTES, 0);
                BN_bn2binpad(G, out.record.G.data(), PAILLIER_MODULUS_BYTES);
                BN_free(G);
            }

            out.record.theta = out.theta;
            out.record.V.assign(PAILLIER_CT_BYTES, 0);
            {
                const BIGNUM* Vbn = parties[0]->V();
                if (!Vbn) {
                    BN_free(theta_tilde); BN_free(theta);
                    goto after_key_phase;
                }
                BN_bn2binpad(Vbn, out.record.V.data(), PAILLIER_CT_BYTES);
            }
            out.record.V_K_i = out.V_K_i;

            // VSS public parameters.
            {
                auto bn_to_vec = [](const BIGNUM* b, std::vector<uint8_t>& v) {
                    const int n = BN_num_bytes(b);
                    v.assign(n, 0);
                    BN_bn2bin(b, v.data());
                };
                bn_to_vec(vss.P, out.record.vss_P);
                bn_to_vec(vss.g, out.record.vss_g);
                bn_to_vec(vss.h, out.record.vss_h);
                // P' = (P-1)/2.
                BIGNUM* pp = BN_new();
                BN_sub(pp, vss.P, BN_value_one());
                BN_rshift1(pp, pp);
                bn_to_vec(pp, out.record.vss_P_prime);
                BN_free(pp);
            }

            out.record.activation_height = 0;

            // Transcript hash: canonical hash of every accepted DKG
            // protocol message (Gap 4). Covers all candidate attempts
            // through the successful one, plus complaint resolution
            // messages. Domain string fixed by the DKG spec.
            transcript.hash(out.record.dkg_transcript_hash);

            // Key id = SHA-256 of the record with key_id zeroed.
            {
                dao_tally_key_record tmp2 = out.record;
                tmp2.key_id.assign(32, 0);
                std::vector<uint8_t> body2;
                tmp2.serialize(body2);
                out.record.key_id.assign(32, 0);
                SHA256(body2.data(), body2.size(), out.record.key_id.data());
            }

            out.key_id = out.record.key_id;

#ifdef VEILROOT_DAO_DKG_TESTING
            // Oracle fields.
            {
                CtxGuard tctx2;
                BIGNUM* sum_p = BN_new();
                BIGNUM* sum_q = BN_new();
                BIGNUM* sum_beta = BN_new();
                BN_zero(sum_p); BN_zero(sum_q); BN_zero(sum_beta);
                for (auto& p : parties) {
                    BN_add(sum_p, sum_p, p->test_p_i());
                    BN_add(sum_q, sum_q, p->test_q_i());
                    BN_add(sum_beta, sum_beta, p->test_beta_i());
                }
                auto bn_out = [](const BIGNUM* b, std::vector<uint8_t>& v) {
                    const int n = BN_num_bytes(b);
                    v.assign(n, 0);
                    BN_bn2bin(b, v.data());
                };
                bn_out(sum_p, out.test_p);
                bn_out(sum_q, out.test_q);
                bn_out(sum_beta, out.test_beta);

                BIGNUM* phi = BN_new();
                BN_add(phi, N, BN_value_one());
                BN_sub(phi, phi, sum_p);
                BN_sub(phi, phi, sum_q);
                bn_out(phi, out.test_phi);
                bn_out(theta_tilde, out.test_theta_tilde);

                out.test_SK.assign(cfg.committee_size, {});
                for (size_t k = 0; k < parties.size(); ++k) {
                    // SK_i is signed; serialize as decimal so the test
                    // can reconstruct the sign unambiguously.
                    char* dec = BN_bn2dec(parties[k]->test_SK());
                    if (!dec) continue;
                    out.test_SK[k].assign(dec, dec + strlen(dec));
                    OPENSSL_free(dec);
                }

                BN_free(sum_p); BN_free(sum_q); BN_free(sum_beta);
                BN_free(phi);
            }
#endif

            BN_free(theta_tilde);
            BN_free(theta);
            key_ok = true;
        }
    }

after_key_phase:
    if (!key_ok) {
        out.ok = false;
        return false;
    }

    BN_free(accepted_N);
    out.ok = true;
    return true;
}

bool dkg_run(const dkg_config& cfg, dkg_result& out)
{
    // Construct an in-process transport factory using the network
    // helper from dao_dkg_transport.h.
    dkg_inproc_network net = dkg_make_inproc_network(cfg.committee_size, nullptr);
    auto* hub = net.hub.get();

    auto factory = [hub](uint32_t) -> std::unique_ptr<dkg_transport> {
        // The transports were already built by dkg_make_inproc_network;
        // we cannot easily hand them out individually from here. For
        // the in-process default entry point, callers use
        // dkg_run_with_transport directly with the network's endpoints.
        (void)hub;
        return nullptr;
    };

    // Delegate: the caller should use dkg_run_with_transport with the
    // endpoints from dkg_make_inproc_network. This function returns
    // false to signal that the caller must supply a transport.
    (void)factory;
    out = dkg_result{};
    return false;
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
        unsigned char nb[256];
        BN_bn2binpad(N, nb, 256);
        SHA256_Update(&sha, nb, 256);
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
        unsigned char nb[256];
        BN_bn2binpad(N, nb, 256);
        SHA256_Update(&sha, nb, 256);
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
