// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_paillier.h"

#include <cstring>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/rand.h>

namespace cryptonote {
namespace dao {

namespace {

// RAII for BN_CTX.
struct CtxGuard {
    BN_CTX* ctx;
    CtxGuard() : ctx(BN_CTX_new()) {}
    ~CtxGuard() { if (ctx) BN_CTX_free(ctx); }
    CtxGuard(const CtxGuard&) = delete;
    CtxGuard& operator=(const CtxGuard&) = delete;
    bool ok() const { return ctx != nullptr; }
};

// Constant-time (best effort) random BIGNUM in [1, N-1] with gcd(x,N)=1.
bool random_unit_mod_N(const BIGNUM* N, BIGNUM* out)
{
    if (!N || !out) return false;
    if (BN_cmp(N, BN_value_one()) <= 0) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* candidate = BN_new();
    if (!candidate) return false;

    const int bits = BN_num_bits(N) - 1;
    bool ok = false;
    for (int tries = 0; tries < 64; ++tries) {
        if (!BN_rand(candidate, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) break;
        if (BN_cmp(candidate, N) >= 0) continue;
        BIGNUM* gcd = BN_new();
        if (!gcd) break;
        BN_CTX_start(g.ctx);
        BN_gcd(gcd, candidate, N, g.ctx);
        const bool coprime = BN_is_one(gcd);
        BN_CTX_end(g.ctx);
        BN_free(gcd);
        if (!coprime) continue;
        if (!BN_copy(out, candidate)) break;
        ok = true;
        break;
    }
    BN_clear_free(candidate);
    return ok;
}

// (1 + N)^m mod N^2 = 1 + m*N (mod N^2), and r^N mod N^2.
// Enc(m; r) = (1 + m*N) * r^N mod N^2.
bool encrypt_with(const BIGNUM* N, const BIGNUM* N2,
                  const BIGNUM* m, const BIGNUM* r,
                  BIGNUM* c_out)
{
    if (!N || !N2 || !m || !r || !c_out) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* mN     = BN_new();
    BIGNUM* one_mN = BN_new();
    BIGNUM* rN     = BN_new();
    BIGNUM* c      = BN_new();
    bool ok = false;
    do {
        if (!mN || !one_mN || !rN || !c) break;

        if (!BN_mod_mul(mN, m, N, N2, g.ctx)) break;
        if (!BN_add(one_mN, mN, BN_value_one())) break;
        if (BN_cmp(one_mN, N2) >= 0) {
            if (!BN_mod(one_mN, one_mN, N2, g.ctx)) break;
        }

        if (!BN_mod_exp(rN, r, N, N2, g.ctx)) break;
        if (!BN_mod_mul(c, one_mN, rN, N2, g.ctx)) break;

        if (!BN_copy(c_out, c)) break;
        ok = true;
    } while (false);

    BN_clear_free(mN);
    BN_clear_free(one_mN);
    BN_clear_free(rN);
    BN_clear_free(c);
    return ok;
}

} // anonymous namespace

// =========================== PaillierPublicKey ===========================

PaillierPublicKey::~PaillierPublicKey() { reset(); }

PaillierPublicKey::PaillierPublicKey(PaillierPublicKey&& o) noexcept
    : N_(o.N_), N2_(o.N2_) { o.N_ = nullptr; o.N2_ = nullptr; }

PaillierPublicKey& PaillierPublicKey::operator=(PaillierPublicKey&& o) noexcept
{
    if (this != &o) {
        reset();
        N_  = o.N_;  o.N_  = nullptr;
        N2_ = o.N2_; o.N2_ = nullptr;
    }
    return *this;
}

void PaillierPublicKey::reset()
{
    if (N_)  { BN_free(N_);  N_  = nullptr; }
    if (N2_) { BN_free(N2_); N2_ = nullptr; }
}

bool PaillierPublicKey::set_modulus(const BIGNUM* N)
{
    if (!N) return false;
    if (BN_is_negative(N)) return false;
    if (BN_is_zero(N)) return false;
    if (BN_is_one(N)) return false;

    BIGNUM* copy = BN_dup(N);
    if (!copy) return false;
    reset();
    N_ = copy;
    return ensure_N2();
}

bool PaillierPublicKey::deserialize_modulus(const std::vector<uint8_t>& in)
{
    if (in.size() != PAILLIER_MODULUS_BYTES) return false;
    BIGNUM* N = BN_bin2bn(in.data(), static_cast<int>(in.size()), nullptr);
    if (!N) return false;
    const bool ok = set_modulus(N);
    BN_free(N);
    return ok;
}

bool PaillierPublicKey::serialize_modulus(std::vector<uint8_t>& out) const
{
    if (!N_) return false;
    out.assign(PAILLIER_MODULUS_BYTES, 0);
    const int n = BN_bn2binpad(N_, out.data(),
                               static_cast<int>(PAILLIER_MODULUS_BYTES));
    if (n != static_cast<int>(PAILLIER_MODULUS_BYTES)) { out.clear(); return false; }
    return true;
}

bool PaillierPublicKey::ensure_N2()
{
    if (!N_) return false;
    if (N2_) return true;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* sq = BN_new();
    if (!sq) return false;
    if (!BN_sqr(sq, N_, g.ctx)) { BN_free(sq); return false; }
    N2_ = sq;
    return true;
}

bool PaillierPublicKey::encrypt(const BIGNUM* m, const BIGNUM* r,
                                std::vector<uint8_t>& ct_out) const
{
    if (!N_ || !N2_ || !m || !r) return false;
    if (BN_is_negative(m) || BN_is_negative(r)) return false;
    if (BN_cmp(m, N_) >= 0) return false;
    if (BN_is_zero(r)) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* gcd = BN_new();
    if (!gcd) return false;
    if (!BN_gcd(gcd, r, N_, g.ctx)) { BN_free(gcd); return false; }
    const bool coprime = BN_is_one(gcd);
    BN_free(gcd);
    if (!coprime) return false;

    BIGNUM* c = BN_new();
    if (!c) return false;
    const bool ok = encrypt_with(N_, N2_, m, r, c);
    if (ok) {
        ct_out.assign(PAILLIER_CT_BYTES, 0);
        const int n = BN_bn2binpad(c, ct_out.data(),
                                   static_cast<int>(PAILLIER_CT_BYTES));
        if (n != static_cast<int>(PAILLIER_CT_BYTES)) ct_out.clear();
        const bool good = (n == static_cast<int>(PAILLIER_CT_BYTES));
        BN_clear_free(c);
        return good;
    }
    BN_clear_free(c);
    return false;
}

bool PaillierPublicKey::is_valid_ciphertext(const std::vector<uint8_t>& c) const
{
    if (!N_ || !N2_) return false;
    if (c.size() != PAILLIER_CT_BYTES) return false;

    BIGNUM* bn = BN_bin2bn(c.data(), static_cast<int>(c.size()), nullptr);
    if (!bn) return false;

    CtxGuard g;
    if (!g.ok()) { BN_free(bn); return false; }

    bool ok = false;
    do {
        if (BN_cmp(bn, N2_) >= 0) break;
        if (BN_is_zero(bn)) break;
        BIGNUM* gcd = BN_new();
        if (!gcd) break;
        if (!BN_gcd(gcd, bn, N_, g.ctx)) { BN_free(gcd); break; }
        ok = BN_is_one(gcd);
        BN_free(gcd);
    } while (false);

    BN_free(bn);
    return ok;
}

bool PaillierPublicKey::add(const std::vector<uint8_t>& c1,
                            const std::vector<uint8_t>& c2,
                            std::vector<uint8_t>& out) const
{
    if (!N_ || !N2_) return false;
    if (!is_valid_ciphertext(c1) || !is_valid_ciphertext(c2)) return false;

    BIGNUM* a = BN_bin2bn(c1.data(), static_cast<int>(c1.size()), nullptr);
    BIGNUM* b = BN_bin2bn(c2.data(), static_cast<int>(c2.size()), nullptr);
    if (!a || !b) { BN_free(a); BN_free(b); return false; }

    CtxGuard g;
    if (!g.ok()) { BN_free(a); BN_free(b); return false; }

    BIGNUM* r = BN_new();
    bool ok = false;
    if (r && BN_mod_mul(r, a, b, N2_, g.ctx)) {
        out.assign(PAILLIER_CT_BYTES, 0);
        const int n = BN_bn2binpad(r, out.data(),
                                   static_cast<int>(PAILLIER_CT_BYTES));
        ok = (n == static_cast<int>(PAILLIER_CT_BYTES));
        if (!ok) out.clear();
    }
    BN_free(a); BN_free(b); BN_free(r);
    return ok;
}

bool PaillierPublicKey::inverse(const std::vector<uint8_t>& c,
                                std::vector<uint8_t>& out) const
{
    if (!N_ || !N2_) return false;
    if (!is_valid_ciphertext(c)) return false;

    BIGNUM* a = BN_bin2bn(c.data(), static_cast<int>(c.size()), nullptr);
    if (!a) return false;

    CtxGuard g;
    if (!g.ok()) { BN_free(a); return false; }

    BIGNUM* inv = BN_new();
    bool ok = false;
    if (inv && BN_mod_inverse(inv, a, N2_, g.ctx)) {
        out.assign(PAILLIER_CT_BYTES, 0);
        const int n = BN_bn2binpad(inv, out.data(),
                                   static_cast<int>(PAILLIER_CT_BYTES));
        ok = (n == static_cast<int>(PAILLIER_CT_BYTES));
        if (!ok) out.clear();
    }
    BN_free(a); BN_free(inv);
    return ok;
}

bool PaillierPublicKey::scalar_mul(const std::vector<uint8_t>& c,
                                   const BIGNUM* k,
                                   std::vector<uint8_t>& out) const
{
    if (!N_ || !N2_ || !k) return false;
    if (!is_valid_ciphertext(c)) return false;

    BIGNUM* a = BN_bin2bn(c.data(), static_cast<int>(c.size()), nullptr);
    if (!a) return false;

    CtxGuard g;
    if (!g.ok()) { BN_free(a); return false; }

    BIGNUM* r = BN_new();
    bool ok = false;
    if (r && BN_mod_exp(r, a, k, N2_, g.ctx)) {
        out.assign(PAILLIER_CT_BYTES, 0);
        const int n = BN_bn2binpad(r, out.data(),
                                   static_cast<int>(PAILLIER_CT_BYTES));
        ok = (n == static_cast<int>(PAILLIER_CT_BYTES));
        if (!ok) out.clear();
    }
    BN_free(a); BN_free(r);
    return ok;
}

// =========================== PaillierPrivateKey ===========================

PaillierPrivateKey::~PaillierPrivateKey() { reset(); }

PaillierPrivateKey::PaillierPrivateKey(PaillierPrivateKey&& o) noexcept
    : N_(o.N_), N2_(o.N2_), lambda_(o.lambda_), mu_(o.mu_),
      p_(o.p_), q_(o.q_)
{
    o.N_ = o.N2_ = o.lambda_ = o.mu_ = o.p_ = o.q_ = nullptr;
}

PaillierPrivateKey& PaillierPrivateKey::operator=(PaillierPrivateKey&& o) noexcept
{
    if (this != &o) {
        reset();
        N_ = o.N_; N2_ = o.N2_; lambda_ = o.lambda_; mu_ = o.mu_;
        p_ = o.p_; q_ = o.q_;
        o.N_ = o.N2_ = o.lambda_ = o.mu_ = o.p_ = o.q_ = nullptr;
    }
    return *this;
}

void PaillierPrivateKey::reset()
{
    if (N_)      { BN_free(N_); N_ = nullptr; }
    if (N2_)     { BN_free(N2_); N2_ = nullptr; }
    if (lambda_) { BN_clear_free(lambda_); lambda_ = nullptr; }
    if (mu_)     { BN_clear_free(mu_); mu_ = nullptr; }
    if (p_)      { BN_clear_free(p_); p_ = nullptr; }
    if (q_)      { BN_clear_free(q_); q_ = nullptr; }
}

bool PaillierPrivateKey::generate_for_testing(unsigned int bits)
{
    reset();

    CtxGuard g;
    if (!g.ok()) return false;

    const unsigned int half = bits / 2;

    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* N = BN_new();
    BIGNUM* N2 = BN_new();
    BIGNUM* p1 = BN_new();
    BIGNUM* q1 = BN_new();
    BIGNUM* g_ = BN_new();
    BIGNUM* lcm = BN_new();
    BIGNUM* lambda = BN_new();
    BIGNUM* gl = BN_new();      // g^lambda mod N^2
    BIGNUM* gl_minus1 = BN_new();
    BIGNUM* L = BN_new();
    BIGNUM* mu = BN_new();

    bool ok = false;
    do {
        if (!p || !q || !N || !N2 || !p1 || !q1 || !g_ || !lcm ||
            !lambda || !gl || !gl_minus1 || !L || !mu) break;

        // 2048-bit modulus = two 1024-bit safe primes.
        if (!BN_generate_prime_ex(p, half, 1, nullptr, nullptr, nullptr)) break;
        if (!BN_generate_prime_ex(q, half, 1, nullptr, nullptr, nullptr)) break;
        if (BN_cmp(p, q) == 0) break;

        if (!BN_mul(N, p, q, g.ctx)) break;
        if (!BN_sqr(N2, N, g.ctx)) break;

        if (!BN_sub(p1, p, BN_value_one())) break;
        if (!BN_sub(q1, q, BN_value_one())) break;

        // lambda = lcm(p-1, q-1) = (p-1)(q-1) / gcd(p-1, q-1)
        {
            BIGNUM* tmp = BN_new();
            BIGNUM* gcd = BN_new();
            if (!tmp || !gcd) { BN_free(tmp); BN_free(gcd); break; }
            if (!BN_mul(tmp, p1, q1, g.ctx)) { BN_free(tmp); BN_free(gcd); break; }
            if (!BN_gcd(gcd, p1, q1, g.ctx)) { BN_free(tmp); BN_free(gcd); break; }
            if (!BN_div(lambda, nullptr, tmp, gcd, g.ctx)) { BN_free(tmp); BN_free(gcd); break; }
            BN_free(tmp); BN_free(gcd);
        }

        // g = 1 + N
        if (!BN_add(g_, N, BN_value_one())) break;

        // gl = g^lambda mod N^2
        if (!BN_mod_exp(gl, g_, lambda, N2, g.ctx)) break;
        if (!BN_sub(gl_minus1, gl, BN_value_one())) break;

        // L = (gl - 1) / N
        if (!BN_div(L, nullptr, gl_minus1, N, g.ctx)) break;

        // mu = L^{-1} mod N
        if (!BN_mod_inverse(mu, L, N, g.ctx)) break;

        N_ = N;      N = nullptr;
        N2_ = N2;    N2 = nullptr;
        lambda_ = lambda; lambda = nullptr;
        mu_ = mu;    mu = nullptr;
        p_ = p;      p = nullptr;
        q_ = q;      q = nullptr;
        ok = true;
    } while (false);

    if (N)        BN_free(N);
    if (N2)       BN_free(N2);
    if (p)        BN_clear_free(p);
    if (q)        BN_clear_free(q);
    if (p1)       BN_clear_free(p1);
    if (q1)       BN_clear_free(q1);
    if (g_)       BN_free(g_);
    if (lcm)      BN_free(lcm);
    if (lambda)   BN_clear_free(lambda);
    if (gl)       BN_free(gl);
    if (gl_minus1) BN_clear_free(gl_minus1);
    if (L)        BN_clear_free(L);
    if (mu)       BN_clear_free(mu);

    return ok;
}

PaillierPublicKey PaillierPrivateKey::public_key() const
{
    PaillierPublicKey pk;
    if (N_) pk.set_modulus(N_);
    return pk;
}

bool PaillierPrivateKey::decrypt(const std::vector<uint8_t>& ct,
                                 BIGNUM* m_out) const
{
    if (!N_ || !N2_ || !lambda_ || !mu_ || !m_out) return false;
    if (ct.size() != PAILLIER_CT_BYTES) return false;

    BIGNUM* c = BN_bin2bn(ct.data(), static_cast<int>(ct.size()), nullptr);
    if (!c) return false;

    CtxGuard g;
    if (!g.ok()) { BN_free(c); return false; }

    // Reject invalid ciphertext (c >= N^2 or gcd(c, N) != 1).
    {
        BIGNUM* gcd = BN_new();
        const bool bad = (BN_cmp(c, N2_) >= 0) || !gcd ||
                         !BN_gcd(gcd, c, N_, g.ctx) || !BN_is_one(gcd);
        if (gcd) BN_free(gcd);
        if (bad) { BN_free(c); return false; }
    }

    BIGNUM* u         = BN_new();   // c^lambda mod N^2
    BIGNUM* u_minus1  = BN_new();
    BIGNUM* L         = BN_new();
    BIGNUM* m         = BN_new();
    bool ok = false;

    do {
        if (!u || !u_minus1 || !L || !m) break;
        if (!BN_mod_exp_mont_consttime(u, c, lambda_, N2_, g.ctx, nullptr)) break;
        if (!BN_sub(u_minus1, u, BN_value_one())) break;
        if (!BN_div(L, nullptr, u_minus1, N_, g.ctx)) break;
        if (!BN_mod_mul(m, L, mu_, N_, g.ctx)) break;
        if (!BN_copy(m_out, m)) break;
        ok = true;
    } while (false);

    BN_free(c);
    BN_clear_free(u);
    BN_clear_free(u_minus1);
    BN_clear_free(L);
    BN_clear_free(m);
    return ok;
}

// =========================== signed encoding ===========================

bool int128_to_bn(const boost::multiprecision::int128_t& v, BIGNUM* out)
{
    if (!out) return false;
    if (v < 0) return false;   // caller must handle sign explicitly
    std::vector<uint8_t> buf(16, 0);
    boost::multiprecision::uint128_t mag =
        static_cast<boost::multiprecision::uint128_t>(v);
    // BN_bin2bn reads big-endian; write big-endian.
    for (int i = 0; i < 16; ++i) {
        buf[i] = static_cast<uint8_t>((mag >> (8 * (15 - i))) & 0xff);
    }
    BIGNUM* tmp = BN_bin2bn(buf.data(), 16, nullptr);
    if (!tmp) return false;
    BN_copy(out, tmp);
    BN_free(tmp);
    return true;
}

bool bn_to_int128(const BIGNUM* v, boost::multiprecision::int128_t& out)
{
    if (!v) return false;
    if (BN_is_negative(v)) return false;
    if (BN_num_bits(v) > 127) return false;

    std::vector<uint8_t> buf(16, 0);
    if (BN_bn2binpad(v, buf.data(), 16) != 16) return false;

    // BN_bn2binpad writes big-endian; read big-endian.
    boost::multiprecision::uint128_t mag = 0;
    for (int i = 0; i < 16; ++i) {
        mag = (mag << 8) | buf[i];
    }
    out = static_cast<boost::multiprecision::int128_t>(mag);
    return true;
}

bool governance_weight_to_bn(const governance_weight_t& w, BIGNUM* out)
{
    if (!out) return false;
    std::vector<uint8_t> buf(16, 0);
    governance_weight_t t = w;
    // BN_bin2bn reads big-endian; write big-endian.
    for (int i = 0; i < 16; ++i) {
        buf[15 - i] = static_cast<uint8_t>((t & 0xff).convert_to<uint8_t>());
        t >>= 8;
    }
    BIGNUM* tmp = BN_bin2bn(buf.data(), 16, nullptr);
    if (!tmp) return false;
    BN_copy(out, tmp);
    BN_free(tmp);
    return true;
}

bool encode_unsigned_weight(const governance_weight_t& w,
                            const BIGNUM* N,
                            BIGNUM* m_out)
{
    if (!N || !m_out) return false;
    if (w > governance_w_max()) return false;

    BIGNUM* bn = BN_new();
    if (!bn) return false;
    if (!governance_weight_to_bn(w, bn)) { BN_free(bn); return false; }
    if (BN_cmp(bn, N) >= 0) { BN_free(bn); return false; }
    BN_copy(m_out, bn);
    BN_free(bn);
    return true;
}

bool encode_signed_value(const boost::multiprecision::int128_t& s,
                         const BIGNUM* N,
                         BIGNUM* m_out)
{
    if (!N || !m_out) return false;

    if (s >= 0) {
        BIGNUM* abs_bn = BN_new();
        if (!abs_bn) return false;
        if (!int128_to_bn(s, abs_bn)) { BN_free(abs_bn); return false; }
        const bool ok = (BN_cmp(abs_bn, N) < 0) && BN_copy(m_out, abs_bn);
        BN_free(abs_bn);
        return ok;
    }

    // m = (N - |s|) mod N
    BIGNUM* abs_bn = BN_new();
    if (!abs_bn) return false;
    boost::multiprecision::int128_t pos = -s;
    if (!int128_to_bn(pos, abs_bn)) { BN_free(abs_bn); return false; }
    if (BN_cmp(abs_bn, N) >= 0) { BN_free(abs_bn); return false; }

    CtxGuard g;
    if (!g.ok()) { BN_free(abs_bn); return false; }

    BIGNUM* m = BN_new();
    bool ok = false;
    if (m) {
        // m = N - |s|
        if (BN_sub(m, N, abs_bn)) {
            if (BN_copy(m_out, m)) ok = true;
        }
    }
    BN_free(abs_bn);
    BN_free(m);
    return ok;
}

bool decode_signed_value(const BIGNUM* m,
                         const BIGNUM* N,
                         boost::multiprecision::int128_t& out)
{
    if (!m || !N) return false;
    if (BN_is_negative(m) || BN_is_negative(N)) return false;
    if (BN_cmp(m, N) >= 0) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    BIGNUM* half = BN_new();
    if (!half) return false;
    if (!BN_rshift1(half, N)) { BN_free(half); return false; }

    bool ok = false;
    if (BN_cmp(m, half) <= 0) {
        // S = m, non-negative.
        ok = bn_to_int128(m, out);
    } else {
        // S = m - N = -(N - m). Compute N - m as a positive BIGNUM and
        // apply the sign in int128. Never construct a negative BIGNUM,
        // because not every OpenSSL build represents them.
        BIGNUM* mag = BN_new();
        if (mag && BN_sub(mag, N, m)) {
            boost::multiprecision::int128_t pos = 0;
            ok = bn_to_int128(mag, pos);
            if (ok) out = -pos;
        }
        if (mag) BN_free(mag);
    }
    BN_free(half);
    return ok;
}

} // namespace dao
} // namespace cryptonote