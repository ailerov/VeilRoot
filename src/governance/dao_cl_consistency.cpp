// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_cl_consistency.h"

#ifdef VEILROOT_ENABLE_CL

#include <cstring>
#include <stdexcept>

#include "crypto/crypto-ops.h"
#include "crypto/hash.h"
#include "governance/dao_crypto_backend.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctOps.h"
#include "serialization/binary_utils.h"

namespace cryptonote {
namespace dao {

namespace {

using namespace BICYCL;

// ---- Byte helpers ----

void u32_be_append(std::vector<uint8_t>& out, uint32_t v)
{
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >>  8));
    out.push_back(static_cast<uint8_t>(v      ));
}

bool u32_be_read(const std::vector<uint8_t>& in, size_t& off, uint32_t& v)
{
    if (off + 4 > in.size()) return false;
    v = (static_cast<uint32_t>(in[off    ]) << 24)
      | (static_cast<uint32_t>(in[off + 1]) << 16)
      | (static_cast<uint32_t>(in[off + 2]) <<  8)
      |  static_cast<uint32_t>(in[off + 3]);
    off += 4;
    return true;
}

std::vector<uint8_t> mpz_to_bytes_be(const Mpz& v)
{
    if (v.is_zero()) return {};
    std::vector<unsigned char> vec =
        static_cast<std::vector<unsigned char>>(v);
    return std::vector<uint8_t>(vec.begin(), vec.end());
}

Mpz mpz_from_bytes_be(const uint8_t* data, size_t n)
{
    if (n == 0) return Mpz();
    std::vector<unsigned char> vec(data, data + n);
    return Mpz(vec);
}

// BE magnitude with explicit sign byte.
void mpz_to_bytes_signed(std::vector<uint8_t>& out, const Mpz& v)
{
    bool neg = v.sgn() < 0;
    out.push_back(neg ? 1 : 0);
    Mpz abs_v;
    Mpz::abs(abs_v, v);
    auto bytes = mpz_to_bytes_be(abs_v);
    u32_be_append(out, static_cast<uint32_t>(bytes.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
}

bool mpz_from_bytes_signed(const std::vector<uint8_t>& in, size_t& off,
                           Mpz& out, bool allow_negative = true)
{
    if (off >= in.size()) return false;
    uint8_t sign_byte = in[off++];
    if (sign_byte > 1) return false;
    uint32_t len = 0;
    if (!u32_be_read(in, off, len)) return false;
    if (off + len > in.size()) return false;
    if (len == 0) {
        if (sign_byte != 0) return false;
        out = Mpz();
        return true;
    }
    if (in[off] == 0) return false;
    out = mpz_from_bytes_be(in.data() + off, len);
    off += len;
    if (sign_byte == 1) {
        if (!allow_negative) return false;
        out.neg();
    }
    return true;
}

void qfi_to_bytes(std::vector<uint8_t>& out, const QFI& f)
{
    mpz_to_bytes_signed(out, f.a());
    mpz_to_bytes_signed(out, f.b());
    mpz_to_bytes_signed(out, f.c());
}

bool qfi_from_bytes(const std::vector<uint8_t>& in, size_t& off, QFI& out,
                    const Mpz& expected_disc)
{
    Mpz a, b, c;
    if (!mpz_from_bytes_signed(in, off, a, false)) return false;
    if (!mpz_from_bytes_signed(in, off, b, true))  return false;
    if (!mpz_from_bytes_signed(in, off, c, false)) return false;
    try {
        out = QFI(a, b, c);
    } catch (...) {
        return false;
    }
    if (out.discriminant() != expected_disc) return false;
    return true;
}

// Mpz < q, encoded as 32-byte little-endian rct::key.
bool mpz_to_rct_scalar(const Mpz& v, const Mpz& q, rct::key& out)
{
    if (v.sgn() < 0) return false;
    if (v >= q) return false;
    auto be = mpz_to_bytes_be(v);
    std::memset(out.bytes, 0, 32);
    // be is big-endian, up to 32 bytes; reverse into out.
    const size_t n = be.size();
    for (size_t i = 0; i < n; ++i)
        out.bytes[i] = be[n - 1 - i];
    return true;
}

// Reverse direction: 32-byte LE rct::key -> Mpz.
Mpz rct_scalar_to_mpz(const rct::key& k)
{
    std::vector<uint8_t> be(32);
    for (size_t i = 0; i < 32; ++i)
        be[i] = k.bytes[31 - i];
    // Trim leading zeros (mpz_from_bytes_be handles n=0 → zero).
    size_t skip = 0;
    while (skip < 32 && be[skip] == 0) ++skip;
    return mpz_from_bytes_be(be.data() + skip, 32 - skip);
}

// unsigned __int128 → 32-byte LE rct::key (value must be < q).
rct::key u128_to_rct_scalar(unsigned __int128 v)
{
    rct::key out;
    std::memset(out.bytes, 0, 32);
    uint64_t lo = static_cast<uint64_t>(v);
    uint64_t hi = static_cast<uint64_t>(v >> 64);
    for (int i = 0; i < 8; ++i) out.bytes[i]     = (lo >> (8*i)) & 0xff;
    for (int i = 0; i < 8; ++i) out.bytes[8 + i] = (hi >> (8*i)) & 0xff;
    return out;
}

// Mpz < 2^64 limbs → uint64_t. nbits() checked by caller.
uint64_t mpz_to_u64_small(const Mpz& v)
{
    auto be = mpz_to_bytes_be(v);
    uint64_t r = 0;
    for (uint8_t b : be) r = (r << 8) | b;
    return r;
}

// ---- Transcript / challenge ----

bool hash_challenge(
    const CL_HSMqk& CL,
    const CL_HSMqk::PublicKey& pk,
    const CL_HSMqk::CipherText& ct,
    const QFI& A1,
    const QFI& A2,
    const rct::key& C,
    const rct::key& A3,
    const dao_consistency_context& ctx,
    Mpz& e_out,
    std::array<uint8_t, 32>& digest_out)
{
    std::vector<uint8_t> t;

    // Leading domain separator (wire identifier, versioned).
    static const char kDomain[] = "VeilRoot-CL-Pedersen-Ballot-v1";
    t.insert(t.end(), kDomain, kDomain + sizeof(kDomain) - 1);

    // CL public parameters.
    auto qb = mpz_to_bytes_be(CL.q());
    auto pb = mpz_to_bytes_be(CL.p());
    auto dkb = mpz_to_bytes_be(CL.DeltaK());
    auto db = mpz_to_bytes_be(CL.Delta());
    u32_be_append(t, static_cast<uint32_t>(qb.size()));
    t.insert(t.end(), qb.begin(), qb.end());
    u32_be_append(t, 1u);  // k (fixed 1 in this backend)
    u32_be_append(t, static_cast<uint32_t>(pb.size()));
    t.insert(t.end(), pb.begin(), pb.end());
    u32_be_append(t, static_cast<uint32_t>(dkb.size()));
    t.insert(t.end(), dkb.begin(), dkb.end());
    u32_be_append(t, static_cast<uint32_t>(db.size()));
    t.insert(t.end(), db.begin(), db.end());
    t.push_back(CL.compact_variant() ? 1 : 0);

    // Generators h, f (both as QFI-encoded).
    QFI h_qfi = CL.h();
    QFI f_qfi = CL.power_of_f(Mpz(1UL));
    std::vector<uint8_t> hbuf, fbuf;
    qfi_to_bytes(hbuf, h_qfi);
    qfi_to_bytes(fbuf, f_qfi);
    u32_be_append(t, static_cast<uint32_t>(hbuf.size()));
    t.insert(t.end(), hbuf.begin(), hbuf.end());
    u32_be_append(t, static_cast<uint32_t>(fbuf.size()));
    t.insert(t.end(), fbuf.begin(), fbuf.end());

    // Public key and ciphertext.
    std::vector<uint8_t> pkbuf, c1buf, c2buf;
    qfi_to_bytes(pkbuf, pk.elt());
    qfi_to_bytes(c1buf, ct.c1());
    qfi_to_bytes(c2buf, ct.c2());
    u32_be_append(t, static_cast<uint32_t>(pkbuf.size()));
    t.insert(t.end(), pkbuf.begin(), pkbuf.end());
    u32_be_append(t, static_cast<uint32_t>(c1buf.size()));
    t.insert(t.end(), c1buf.begin(), c1buf.end());
    u32_be_append(t, static_cast<uint32_t>(c2buf.size()));
    t.insert(t.end(), c2buf.begin(), c2buf.end());

    // First messages.
    std::vector<uint8_t> a1buf, a2buf;
    qfi_to_bytes(a1buf, A1);
    qfi_to_bytes(a2buf, A2);
    u32_be_append(t, static_cast<uint32_t>(a1buf.size()));
    t.insert(t.end(), a1buf.begin(), a1buf.end());
    u32_be_append(t, static_cast<uint32_t>(a2buf.size()));
    t.insert(t.end(), a2buf.begin(), a2buf.end());

    // Pedersen commitment and first-message.
    t.insert(t.end(), C.bytes,  C.bytes  + 32);
    t.insert(t.end(), A3.bytes, A3.bytes + 32);

    // RingCT bases G, H.
    t.insert(t.end(), rct::G.bytes, rct::G.bytes + 32);
    t.insert(t.end(), rct::H.bytes, rct::H.bytes + 32);

    // Vote context.
    u32_be_append(t, static_cast<uint32_t>(ctx.domain.size()));
    t.insert(t.end(), ctx.domain.begin(), ctx.domain.end());
    t.push_back(ctx.version);
    t.insert(t.end(), ctx.proposal_id.data, ctx.proposal_id.data + 32);
    for (int i = 7; i >= 0; --i)
        t.push_back(static_cast<uint8_t>((ctx.vote_height >> (8*i)) & 0xff));
    t.insert(t.end(), ctx.tally_key_id.data, ctx.tally_key_id.data + 32);
    u32_be_append(t, static_cast<uint32_t>(ctx.vote_input_transcript.size()));
    t.insert(t.end(), ctx.vote_input_transcript.begin(),
                    ctx.vote_input_transcript.end());

    // Hash.
    crypto::hash h{};
    crypto::cn_fast_hash(t.data(), t.size(), h);
    std::memcpy(digest_out.data(), h.data, 32);
    e_out = mpz_from_bytes_be(digest_out.data(), 32);
    return true;
}

// ---- Range proof (internal) ----

static const Mpz& range_B_mpz()
{
    static const Mpz B(static_cast<unsigned long>(1UL << 34) == 0 ?
                       Mpz(0UL) : Mpz(0UL));
    // Cannot use shift on unsigned long for 2^34 on 32-bit UL, so build
    // 2^34 = 4 * 2^32 = 4 * (2^16 * 2^16).
    static const Mpz Bv = []{
        Mpz t(1UL);
        for (int i = 0; i < 34; ++i) Mpz::mulby2(t, t);
        return t;
    }();
    return Bv;
}

static const rct::key& range_B_scalar()
{
    static const rct::key k = []{
        rct::key out;
        // 2^34 as LE 32-byte scalar: byte 4 = 0x04, rest zero.
        std::memset(out.bytes, 0, 32);
        out.bytes[4] = 0x04;
        return out;
    }();
    return k;
}

bool range_prove(uint64_t W_lo, uint64_t W_hi,
                 uint64_t D_lo, uint64_t D_hi,
                 const rct::key& rho,
                 const rct::key& gamma_Wlo,
                 const rct::key& gamma_Dlo,
                 const Mpz& q,
                 dao_cl_range_proof& out)
{
    // Compute gamma_Whi = (rho - gamma_Wlo) / B mod q
    rct::key B = range_B_scalar();
    // B_inv = B^(q-2) mod q via square-and-multiply in the scalar field.
    rct::key B_inv;
    {
        rct::key q_minus_2 = rct::curveOrder();
        q_minus_2.bytes[0] -= 2;  // low byte of q; no borrow
        rct::key result;
        std::memset(result.bytes, 0, 32);
        result.bytes[0] = 1;
        rct::key base = B;
        for (int i = 0; i < 256; ++i) {
            if (q_minus_2.bytes[i / 8] & (1 << (i % 8))) {
                rct::key tmp;
                sc_mul(tmp.bytes, result.bytes, base.bytes);
                result = tmp;
            }
            rct::key sq;
            sc_mul(sq.bytes, base.bytes, base.bytes);
            base = sq;
        }
        B_inv = result;
    }

    rct::key rho_minus_gammaWlo;
    sc_sub(rho_minus_gammaWlo.bytes, rho.bytes, gamma_Wlo.bytes);
    rct::key gamma_Whi;
    sc_mul(gamma_Whi.bytes, rho_minus_gammaWlo.bytes, B_inv.bytes);

    // Compute gamma_Dhi = (-rho - gamma_Dlo) / B mod q
    rct::key neg_rho;
    {
        rct::key zero = rct::zero();
        sc_sub(neg_rho.bytes, zero.bytes, rho.bytes);
    }
    rct::key neg_rho_minus_gammaDlo;
    sc_sub(neg_rho_minus_gammaDlo.bytes, neg_rho.bytes, gamma_Dlo.bytes);
    rct::key gamma_Dhi;
    sc_mul(gamma_Dhi.bytes, neg_rho_minus_gammaDlo.bytes, B_inv.bytes);

    // Eight range-proof values
    const uint64_t B64 = (uint64_t)1 << 34;
    const uint64_t Bm1 = B64 - 1;
    std::vector<uint64_t> values = {
        W_lo, W_hi, Bm1 - W_lo, Bm1 - W_hi,
        D_lo, D_hi, Bm1 - D_lo, Bm1 - D_hi
    };

    // Eight blinding factors
    rct::key neg_gamma_Wlo, neg_gamma_Whi, neg_gamma_Dlo, neg_gamma_Dhi;
    {
        rct::key zero = rct::zero();
        sc_sub(neg_gamma_Wlo.bytes, zero.bytes, gamma_Wlo.bytes);
        sc_sub(neg_gamma_Whi.bytes, zero.bytes, gamma_Whi.bytes);
        sc_sub(neg_gamma_Dlo.bytes, zero.bytes, gamma_Dlo.bytes);
        sc_sub(neg_gamma_Dhi.bytes, zero.bytes, gamma_Dhi.bytes);
    }
    rct::keyV gamma = {
        gamma_Wlo, gamma_Whi, neg_gamma_Wlo, neg_gamma_Whi,
        gamma_Dlo, gamma_Dhi, neg_gamma_Dlo, neg_gamma_Dhi
    };

    out.bp = rct::bulletproof_plus_PROVE(values, gamma);
    return out.bp.V.size() == 8;
}

bool range_verify(const rct::key& C, const dao_cl_range_proof& in)
{
    if (in.bp.V.size() != 8) return false;

    if (!rct::bulletproof_plus_VERIFY(in.bp)) return false;

    // Un-scale V (BP+ stores V scaled by 1/8)
    rct::key C_i[8];
    for (size_t i = 0; i < 8; ++i)
        C_i[i] = rct::scalarmult8(in.bp.V[i]);

    rct::key B = range_B_scalar();
    rct::key Bm1;
    {
        rct::key one = rct::identity();
        sc_sub(Bm1.bytes, B.bytes, one.bytes);
    }
    rct::key W_MAX_scalar = u128_to_rct_scalar(DAO_WEIGHTED_MAX);

    // Check 1: C_0 + C_2 == (B-1)*H
    {
        rct::key sum, expect;
        rct::addKeys(sum, C_i[0], C_i[2]);
        expect = rct::scalarmultH(Bm1);
        if (!(sum == expect)) return false;
    }
    // Check 2: C_1 + C_3 == (B-1)*H
    {
        rct::key sum, expect;
        rct::addKeys(sum, C_i[1], C_i[3]);
        expect = rct::scalarmultH(Bm1);
        if (!(sum == expect)) return false;
    }
    // Check 3: C_4 + C_6 == (B-1)*H
    {
        rct::key sum, expect;
        rct::addKeys(sum, C_i[4], C_i[6]);
        expect = rct::scalarmultH(Bm1);
        if (!(sum == expect)) return false;
    }
    // Check 4: C_5 + C_7 == (B-1)*H
    {
        rct::key sum, expect;
        rct::addKeys(sum, C_i[5], C_i[7]);
        expect = rct::scalarmultH(Bm1);
        if (!(sum == expect)) return false;
    }
    // Check 5: C == C_0 + B*C_1
    {
        rct::key Bc1;
        rct::scalarmultKey(Bc1, C_i[1], B);
        rct::key sum;
        rct::addKeys(sum, C_i[0], Bc1);
        if (!(sum == C)) return false;
    }
    // Check 6: C_D == C_4 + B*C_5
    rct::key C_D;
    {
        rct::key Bc5;
        rct::scalarmultKey(Bc5, C_i[5], B);
        rct::addKeys(C_D, C_i[4], Bc5);
    }
    // Check 7: C + C_D == W_MAX*H
    {
        rct::key sum, expect;
        rct::addKeys(sum, C, C_D);
        expect = rct::scalarmultH(W_MAX_scalar);
        if (!(sum == expect)) return false;
    }
    return true;
}

} // namespace

// ============================================================
// Public: prove
// ============================================================

bool dao_cl_consistency_prove(
    const CL_HSMqk& CL,
    const CL_HSMqk::PublicKey& pk,
    const CL_HSMqk::CipherText& ct,
    const Mpz& W,
    const Mpz& r,
    const rct::key& C,
    const rct::key& rho,
    const dao_consistency_context& ctx,
    RandGen& randgen,
    dao_cl_pedersen_proof& proof)
{
    // Range guard.
    Mpz w_max_mpz;
    {
        unsigned __int128 wmax = DAO_WEIGHTED_MAX;
        std::vector<uint8_t> be;
        uint64_t lo = static_cast<uint64_t>(wmax);
        uint64_t hi = static_cast<uint64_t>(wmax >> 64);
        // Build BE bytes: 8 bytes hi, 8 bytes lo.
        for (int i = 7; i >= 0; --i) {
            uint8_t b = (hi >> (8*i)) & 0xff;
            if (!be.empty() || b != 0) be.push_back(b);
        }
        for (int i = 7; i >= 0; --i) {
            uint8_t b = (lo >> (8*i)) & 0xff;
            if (!be.empty() || b != 0) be.push_back(b);
        }
        w_max_mpz = mpz_from_bytes_be(be.data(), be.size());
    }
    if (W.sgn() < 0) return false;
    if (W > w_max_mpz) return false;

    // Decompose W and D into limbs.
    const Mpz& B = range_B_mpz();
    Mpz W_lo_mpz, W_hi_mpz;
    Mpz::mod(W_lo_mpz, W, B);
    Mpz::fdiv_q(W_hi_mpz, W, B);

    Mpz D;
    Mpz::sub(D, w_max_mpz, W);
    Mpz D_lo_mpz, D_hi_mpz;
    Mpz::mod(D_lo_mpz, D, B);
    Mpz::fdiv_q(D_hi_mpz, D, B);

    if (W_lo_mpz.nbits() > 34 || W_hi_mpz.nbits() > 34) return false;
    if (D_lo_mpz.nbits() > 34 || D_hi_mpz.nbits() > 34) return false;

    uint64_t W_lo = mpz_to_u64_small(W_lo_mpz);
    uint64_t W_hi = mpz_to_u64_small(W_hi_mpz);
    uint64_t D_lo = mpz_to_u64_small(D_lo_mpz);
    uint64_t D_hi = mpz_to_u64_small(D_hi_mpz);

    // Sample nonces.
    Mpz R = CL.encrypt_randomness_bound();
    Mpz bound_r;
    Mpz::mulby2k(bound_r, R, 256u + CL.lambda_distance());
    Mpz a_r = randgen.random_mpz(bound_r);
    Mpz a_W = randgen.random_mpz(CL.M());
    rct::key a_rho = rct::skGen();

    // Construct A1 = h^a_r, A2 = f^a_W · pk^a_r via the CipherText ctor.
    CL_HSMqk::ClearText a_clear(CL, a_W);
    CL_HSMqk::CipherText A_ct(CL, pk, a_clear, a_r);
    proof.A1 = A_ct.c1();
    proof.A2 = A_ct.c2();

    // A3 = a_W·H + a_rho·G
    rct::key a_W_scalar;
    if (!mpz_to_rct_scalar(a_W, CL.M(), a_W_scalar)) return false;
    {
        rct::key aW_H, a_rho_G;
        aW_H = rct::scalarmultH(a_W_scalar);
        rct::scalarmultBase(a_rho_G, a_rho);
        rct::addKeys(proof.A3, aW_H, a_rho_G);
    }

    // Challenge.
    Mpz e_mpz;
    std::array<uint8_t, 32> digest;
    if (!hash_challenge(CL, pk, ct, proof.A1, proof.A2, C, proof.A3, ctx,
                        e_mpz, digest)) return false;
    proof.e = digest;

    Mpz e_mod_q;
    Mpz::mod(e_mod_q, e_mpz, CL.M());

    rct::key e_mod_q_scalar;
    if (!mpz_to_rct_scalar(e_mod_q, CL.M(), e_mod_q_scalar)) return false;

    // z_r = a_r + e·r (integer, no reduction)
    Mpz z_r_tmp;
    Mpz::mul(z_r_tmp, e_mpz, r);
    Mpz::add(proof.z_r, a_r, z_r_tmp);

    // z_W = (a_W + e·W) mod q
    {
        rct::key W_scalar;
        if (!mpz_to_rct_scalar(W, CL.M(), W_scalar)) return false;
        sc_muladd(proof.z_W.bytes, e_mod_q_scalar.bytes, W_scalar.bytes,
                                    a_W_scalar.bytes);
    }

    // z_rho = a_rho + (e mod q)·rho mod q
    sc_muladd(proof.z_rho.bytes, e_mod_q_scalar.bytes, rho.bytes,
                                 a_rho.bytes);

    // Range proof.
    rct::key gamma_Wlo = rct::skGen();
    rct::key gamma_Dlo = rct::skGen();
    if (!range_prove(W_lo, W_hi, D_lo, D_hi, rho,
                     gamma_Wlo, gamma_Dlo, CL.M(), proof.range))
        return false;

    return true;
}

// ============================================================
// Public: verify
// ============================================================

bool dao_cl_consistency_verify(
    const CL_HSMqk& CL,
    const CL_HSMqk::PublicKey& pk,
    const CL_HSMqk::CipherText& ct,
    const rct::key& C,
    const dao_consistency_context& ctx,
    const dao_cl_pedersen_proof& proof)
try {
    // Group membership.
    if (pk.elt().discriminant() != CL.Cl_G().discriminant()) return false;
    if (CL.genus(pk.elt()) != CL_HSMqk::Genus({1, 1})) return false;
    if (ct.c1().discriminant() != CL.Cl_G().discriminant()) return false;
    if (CL.genus(ct.c1()) != CL_HSMqk::Genus({1, 1})) return false;
    if (ct.c2().discriminant() != CL.Cl_Delta().discriminant()) return false;
    if (CL.genus(ct.c2()) != CL_HSMqk::Genus({1, 1})) return false;
    if (proof.A1.discriminant() != CL.Cl_G().discriminant()) return false;
    if (proof.A2.discriminant() != CL.Cl_Delta().discriminant()) return false;

    // Range check (exact DAO bound).
    if (!range_verify(C, proof.range)) return false;

    // Response bounds.
    {
        Mpz R = CL.encrypt_randomness_bound();
        Mpz z_max;
        // z_max = R * 2^(c+d) + R * 2^c
        Mpz Rc, Rd;
        Mpz::mulby2k(Rc, R, 256u);
        Mpz::mulby2k(Rd, Rc, CL.lambda_distance());
        Mpz::add(z_max, Rd, Rc);
        if (proof.z_r.sgn() < 0) return false;
        if (proof.z_r > z_max) return false;
    }

    // Challenge.
    Mpz e_mpz;
    std::array<uint8_t, 32> digest;
    if (!hash_challenge(CL, pk, ct, proof.A1, proof.A2, C, proof.A3, ctx,
                        e_mpz, digest)) return false;
    if (std::memcmp(digest.data(), proof.e.data(), 32) != 0) return false;

    Mpz e_mod_q;
    Mpz::mod(e_mod_q, e_mpz, CL.M());
    rct::key e_mod_q_scalar;
    if (!mpz_to_rct_scalar(e_mod_q, CL.M(), e_mod_q_scalar)) return false;

    // CL equation 1: h^z_r == A1 · c1^e (in Cl_G)
    {
        QFI lhs, rhs_part, rhs;
        CL.power_of_h(lhs, proof.z_r);
        CL.Cl_G().nupow(rhs_part, ct.c1(), e_mpz);
        CL.Cl_G().nucomp(rhs, proof.A1, rhs_part);
        if (!(lhs == rhs)) return false;
    }

    // CL equation 2: pk^z_r · f^z_W == A2 · c2^e (in Cl_Delta)
    {
        QFI pk_zr, pk_zr_delta;
        pk.exponentiation(CL, pk_zr, proof.z_r);
        if (CL.compact_variant())
            CL.from_Cl_DeltaK_to_Cl_Delta(pk_zr);
        pk_zr_delta = pk_zr;

        Mpz z_W_mpz = rct_scalar_to_mpz(proof.z_W);
        QFI f_zw = CL.power_of_f(z_W_mpz);

        QFI lhs;
        CL.Cl_Delta().nucomp(lhs, pk_zr_delta, f_zw);

        QFI rhs_part, rhs;
        CL.Cl_Delta().nupow(rhs_part, ct.c2(), e_mpz);
        CL.Cl_Delta().nucomp(rhs, proof.A2, rhs_part);

        if (!(lhs == rhs)) return false;
    }

    // Pedersen equation: z_W·H + z_rho·G == A3 + e·C
    {
        rct::key l1, l2, lhs;
        l1 = rct::scalarmultH(proof.z_W);
        rct::scalarmultBase(l2, proof.z_rho);
        rct::addKeys(lhs, l1, l2);

        rct::key eC, rhs;
        rct::scalarmultKey(eC, C, e_mod_q_scalar);
        rct::addKeys(rhs, proof.A3, eC);

        if (!(lhs == rhs)) return false;
    }

    return true;
}
catch (const std::exception&) {
    // A verifier that throws on adversarial input is a DoS surface.
    return false;
}
catch (...) {
    return false;
}

// ============================================================
// Serialization
// ============================================================

bool dao_cl_range_proof::serialize(std::vector<uint8_t>& out) const
{
    // Wire format (canonical):
    //   u8  n_outputs                 (must be 8)
    //   8 x 32-byte rct::key V
    //   32-byte A, A1, B
    //   32-byte r1, s1, d1
    //   u32 |L|, |L| x 32-byte L points
    //   u32 |R|, |R| x 32-byte R points
    out.clear();
    if (bp.V.size() != 8) return false;
    out.push_back(static_cast<uint8_t>(bp.V.size()));
    for (const auto& v : bp.V)
        out.insert(out.end(), v.bytes, v.bytes + 32);
    out.insert(out.end(), bp.A.bytes,  bp.A.bytes  + 32);
    out.insert(out.end(), bp.A1.bytes, bp.A1.bytes + 32);
    out.insert(out.end(), bp.B.bytes,  bp.B.bytes  + 32);
    out.insert(out.end(), bp.r1.bytes, bp.r1.bytes + 32);
    out.insert(out.end(), bp.s1.bytes, bp.s1.bytes + 32);
    out.insert(out.end(), bp.d1.bytes, bp.d1.bytes + 32);
    u32_be_append(out, static_cast<uint32_t>(bp.L.size()));
    for (const auto& p2 : bp.L)
        out.insert(out.end(), p2.bytes, p2.bytes + 32);
    u32_be_append(out, static_cast<uint32_t>(bp.R.size()));
    for (const auto& p2 : bp.R)
        out.insert(out.end(), p2.bytes, p2.bytes + 32);
    return true;
}

bool dao_cl_range_proof::deserialize(const std::vector<uint8_t>& in)
{
    bp = rct::BulletproofPlus{};
    if (in.empty()) return false;
    size_t off = 0;
    if (in[off++] != 8) return false;
    auto read_key = [&](rct::key& k) -> bool {
        if (off + 32 > in.size()) return false;
        std::memcpy(k.bytes, in.data() + off, 32);
        off += 32;
        return true;
    };
    bp.V.resize(8);
    for (size_t i = 0; i < 8; ++i)
        if (!read_key(bp.V[i])) return false;
    if (!read_key(bp.A))  return false;
    if (!read_key(bp.A1)) return false;
    if (!read_key(bp.B))  return false;
    if (!read_key(bp.r1)) return false;
    if (!read_key(bp.s1)) return false;
    if (!read_key(bp.d1)) return false;
    uint32_t lsz = 0;
    if (!u32_be_read(in, off, lsz)) return false;
    if (off + static_cast<size_t>(lsz) * 32 > in.size()) return false;
    bp.L.resize(lsz);
    for (uint32_t i = 0; i < lsz; ++i)
        if (!read_key(bp.L[i])) return false;
    uint32_t rsz = 0;
    if (!u32_be_read(in, off, rsz)) return false;
    if (rsz != lsz) return false;
    if (off + static_cast<size_t>(rsz) * 32 > in.size()) return false;
    bp.R.resize(rsz);
    for (uint32_t i = 0; i < rsz; ++i)
        if (!read_key(bp.R[i])) return false;
    return off == in.size();
}

bool dao_cl_pedersen_proof::serialize(std::vector<uint8_t>& out) const
{
    // Wire format (canonical):
    //   QFI  A1
    //   QFI  A2
    //   32-byte A3
    //   32-byte e
    //   u32 len, len-byte z_r (BE magnitude, no leading zero, non-negative)
    //   32-byte z_W
    //   32-byte z_rho
    //   range proof
    out.clear();
    qfi_to_bytes(out, A1);
    qfi_to_bytes(out, A2);
    out.insert(out.end(), A3.bytes, A3.bytes + 32);
    out.insert(out.end(), e.begin(), e.end());
    if (z_r.sgn() < 0) return false;
    auto zr_be = mpz_to_bytes_be(z_r);
    u32_be_append(out, static_cast<uint32_t>(zr_be.size()));
    out.insert(out.end(), zr_be.begin(), zr_be.end());
    out.insert(out.end(), z_W.bytes,   z_W.bytes   + 32);
    out.insert(out.end(), z_rho.bytes, z_rho.bytes + 32);
    std::vector<uint8_t> range_bytes;
    if (!range.serialize(range_bytes)) return false;
    u32_be_append(out, static_cast<uint32_t>(range_bytes.size()));
    out.insert(out.end(), range_bytes.begin(), range_bytes.end());
    return true;
}

bool dao_cl_pedersen_proof::deserialize(const std::vector<uint8_t>& in)
{
    // QFI deserialization needs the class-group discriminant. The
    // public entry point cannot know it without the CL context; this
    // raw form is treated as an opaque container and validated inside
    // dao_cl_consistency_verify against the caller-supplied CL. The
    // discriminant on each QFI is only meaningful in that context, so
    // here we decode structurally (any group) and let verify reject.
    size_t off = 0;
    QFI a1, a2;
    // Structural QFI decode: same as qfi_from_bytes but without disc check.
    auto qfi_read = [&](QFI& out_qfi) -> bool {
        Mpz a, b, c;
        if (!mpz_from_bytes_signed(in, off, a, false)) return false;
        if (!mpz_from_bytes_signed(in, off, b, true))  return false;
        if (!mpz_from_bytes_signed(in, off, c, false)) return false;
        try { out_qfi = QFI(a, b, c); } catch (...) { return false; }
        return true;
    };
    if (!qfi_read(A1)) return false;
    if (!qfi_read(A2)) return false;
    if (off + 32 > in.size()) return false;
    std::memcpy(A3.bytes, in.data() + off, 32); off += 32;
    if (off + 32 > in.size()) return false;
    std::memcpy(e.data(), in.data() + off, 32); off += 32;
    uint32_t zr_len = 0;
    if (!u32_be_read(in, off, zr_len)) return false;
    if (off + zr_len > in.size()) return false;
    if (zr_len > 0 && in[off] == 0) return false;
    z_r = mpz_from_bytes_be(in.data() + off, zr_len);
    off += zr_len;
    if (off + 32 > in.size()) return false;
    std::memcpy(z_W.bytes, in.data() + off, 32); off += 32;
    if (off + 32 > in.size()) return false;
    std::memcpy(z_rho.bytes, in.data() + off, 32); off += 32;
    uint32_t range_len = 0;
    if (!u32_be_read(in, off, range_len)) return false;
    if (off + range_len > in.size()) return false;
    std::vector<uint8_t> range_bytes(in.begin() + off,
                                     in.begin() + off + range_len);
    off += range_len;
    if (!range.deserialize(range_bytes)) return false;
    return off == in.size();
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
