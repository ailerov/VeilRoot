// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_cl_ballot.h"

#ifdef VEILROOT_ENABLE_CL

#include <array>
#include <cstring>

#include <openssl/sha.h>

#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_crypto_backend.h"

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/seclevel.hpp"
#include "ringct/rctOps.h"

namespace cryptonote {
namespace dao {

using namespace BICYCL;

namespace {

// cl_key_context_parse stores scalars as sign || magnitude.
bool parse_sign_magnitude(const std::vector<uint8_t>& in, Mpz& out)
{
    if (in.empty()) return false;
    if (in[0] > 1) return false;
    if (in.size() == 1) {
        if (in[0] != 0) return false;
        out = Mpz();
        return true;
    }
    if (in[1] == 0) return false;
    out = Mpz(std::vector<uint8_t>(in.begin() + 1, in.end()));
    if (in[0] == 1) out.neg();
    return true;
}

bool parse_cl_modulus_qp(const std::vector<uint8_t>& q_be,
                         const std::vector<uint8_t>& p_signed,
                         Mpz& q_out, Mpz& p_out)
{
    if (q_be.empty() || q_be[0] == 0) return false;
    q_out = Mpz(q_be);
    return parse_sign_magnitude(p_signed, p_out);
}

bool parse_pk_qfi(const std::vector<uint8_t>& pk_wire, QFI& out)
{
    std::size_t off = 0;
    // pk_qfi is a raw QFI SCALAR triple; parse structurally here,
    // discriminant is checked against CL after construction.
    Mpz a, b, c;
    auto mpz_read = [&](Mpz& m, bool allow_neg) -> bool {
        if (off >= pk_wire.size()) return false;
        uint8_t sign_byte = pk_wire[off++];
        if (sign_byte > 1) return false;
        uint32_t len = 0;
        if (off + 4 > pk_wire.size()) return false;
        len = (static_cast<uint32_t>(pk_wire[off]) << 24)
            | (static_cast<uint32_t>(pk_wire[off+1]) << 16)
            | (static_cast<uint32_t>(pk_wire[off+2]) <<  8)
            |  static_cast<uint32_t>(pk_wire[off+3]);
        off += 4;
        if (len > 4096u) return false;
        if (off + len > pk_wire.size()) return false;
        if (len == 0) {
            if (sign_byte != 0) return false;
            m = Mpz();
            return true;
        }
        if (pk_wire[off] == 0) return false;
        m = Mpz(std::vector<uint8_t>(pk_wire.begin() + off,
                                     pk_wire.begin() + off + len));
        off += len;
        if (sign_byte == 1) {
            if (!allow_neg) return false;
            m.neg();
        }
        return true;
    };
    if (!mpz_read(a, false)) return false;
    if (!mpz_read(b, true))  return false;
    if (!mpz_read(c, false)) return false;
    if (off != pk_wire.size()) return false;
    try {
        out = QFI(a, b, c);
    } catch (...) {
        return false;
    }
    return true;
}

} // namespace

bool dao_cl_load_proposal_key(const std::vector<uint8_t>& wire,
                              dao_cl_proposal_key& out,
                              uint64_t seclevel_bits)
{
    cl_key_context ctx;
    if (!dao_cl_key_context_parse(wire, ctx)) return false;
    if (ctx.k == 0) return false;

    Mpz q_mpz, p_mpz;
    if (!parse_cl_modulus_qp(ctx.q, ctx.p, q_mpz, p_mpz)) return false;

    try {
        SecLevel sl(static_cast<int>(seclevel_bits));
        auto cl = std::make_shared<CL_HSMqk>(
            q_mpz, static_cast<size_t>(ctx.k), p_mpz,
            CL_Params(static_cast<size_t>(seclevel_bits)));
        QFI pk_qfi;
        if (!parse_pk_qfi(ctx.pk_qfi, pk_qfi)) return false;
        if (pk_qfi.discriminant() != cl->Cl_G().discriminant()) return false;
        auto pk = std::make_shared<CL_HSMqk::PublicKey>(*cl, pk_qfi);
        out.cl = std::move(cl);
        out.pk = std::move(pk);
        out.q  = q_mpz;
        out.D  = Mpz();
        if (!parse_sign_magnitude(ctx.D, out.D)) return false;
        return true;
    } catch (...) {
        return false;
    }
}

std::shared_ptr<BICYCL::CL_HSMqk> dao_cl_make_hsmq_from_seed(
    const std::vector<uint8_t>& seed,
    uint64_t seclevel_bits)
{
    if (seed.empty()) return nullptr;

    // q = rct::curveOrder(), k = 1.
    std::array<uint8_t, 32> be{};
    const rct::key L = rct::curveOrder();
    for (size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
    Mpz q(std::vector<uint8_t>(be.begin(), be.end()));

    // Deterministically seed the RandGen. BICYCL derives p from
    // randgen.random_prime(DeltaK_nbits); identical seed produces
    // identical p across nodes.
    RandGen rng;
    {
        // Mix a domain tag with the seed so that unrelated uses of the
        // same seed do not collide.
        std::vector<uint8_t> buf;
        const char* dom = "VeilRoot-DAO-CL-CLASSGROUP-V1";
        buf.insert(buf.end(), dom, dom + std::strlen(dom));
        buf.insert(buf.end(), seed.begin(), seed.end());
        uint8_t h[32];
        SHA256(buf.data(), buf.size(), h);
        Mpz seed_mpz(std::vector<uint8_t>(h, h + sizeof(h)));
        rng.set_seed(seed_mpz);
    }

    try {
        SecLevel sl(static_cast<int>(seclevel_bits));
        return std::make_shared<CL_HSMqk>(
            q, static_cast<size_t>(1), sl, rng,
            CL_Params(static_cast<size_t>(seclevel_bits)));
    } catch (...) {
        return nullptr;
    }
}

bool dao_cl_encrypt_at_pk(const BICYCL::CL_HSMqk& cl,
                          const BICYCL::CL_HSMqk::PublicKey& pk,
                          const BICYCL::Mpz& m,
                          const BICYCL::Mpz& r,
                          std::vector<uint8_t>& ct_wire_out)
{
    try {
        CL_HSMqk::ClearText mct(cl, m);
        CL_HSMqk::CipherText ct = cl.encrypt(pk, mct, r);
        ct_wire_out.clear();
        if (!cl_dkg_qfi_to_bytes(ct_wire_out, ct.c1())) return false;
        if (!cl_dkg_qfi_to_bytes(ct_wire_out, ct.c2())) return false;
        return true;
    } catch (...) {
        return false;
    }
}

BICYCL::Mpz dao_cl_sample_randomness(const BICYCL::CL_HSMqk& cl,
                                     BICYCL::RandGen& rng)
{
    return rng.random_mpz(cl.encrypt_randomness_bound());
}

bool dao_cl_encode_signed_plaintext(const BICYCL::Mpz& s,
                                    const BICYCL::Mpz& q,
                                    BICYCL::Mpz& out)
{
    if (s.sgn() < 0) {
        Mpz abs_s;
        Mpz::abs(abs_s, s);
        if (!(abs_s < q)) return false;
        Mpz::sub(out, q, abs_s);
    } else {
        if (!(s < q)) return false;
        out = s;
    }
    return true;
}

bool dao_cl_signed_scalar(const BICYCL::Mpz& s,
                          const BICYCL::Mpz& q,
                          rct::key& out)
{
    Mpz canon;
    if (!dao_cl_encode_signed_plaintext(s, q, canon)) return false;
    auto be = static_cast<std::vector<unsigned char>>(canon);
    if (be.size() > 32) return false;
    out = rct::zero();
    for (size_t i = 0; i < be.size(); ++i)
        out.bytes[i] = be[be.size() - 1 - i];
    return true;
}

bool dao_cl_decode_signed_plaintext(const BICYCL::Mpz& m,
                                    const BICYCL::Mpz& q,
                                    BICYCL::Mpz& out)
{
    if (m.sgn() < 0) return false;
    if (!(m < q)) return false;
    Mpz two_m;
    Mpz::add(two_m, m, m);
    if (two_m <= q) {
        out = m;
    } else {
        Mpz::sub(out, m, q);
    }
    return true;
}

bool dao_cl_check_ballot_modulus(const BICYCL::CL_HSMqk& cl)
{
    // Invariant 1: q equals the RingCT scalar order.
    std::array<uint8_t, 32> be{};
    const rct::key L = rct::curveOrder();
    for (size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
    Mpz expect_q(std::vector<uint8_t>(be.begin(), be.end()));
    if (cl.q() != expect_q) return false;

    // Invariant 2: 2 * W_MAX < q.
    unsigned __int128 wmax = DAO_WEIGHTED_MAX;
    std::vector<uint8_t> wbe;
    uint64_t lo = static_cast<uint64_t>(wmax);
    uint64_t hi = static_cast<uint64_t>(wmax >> 64);
    for (int i = 7; i >= 0; --i) {
        uint8_t b = (hi >> (8*i)) & 0xff;
        if (!wbe.empty() || b != 0) wbe.push_back(b);
    }
    for (int i = 7; i >= 0; --i) {
        uint8_t b = (lo >> (8*i)) & 0xff;
        if (!wbe.empty() || b != 0) wbe.push_back(b);
    }
    if (wbe.empty()) return false;
    Mpz wmax_mpz = Mpz(wbe);
    Mpz two_wmax;
    Mpz::add(two_wmax, wmax_mpz, wmax_mpz);
    if (!(two_wmax < cl.q())) return false;
    return true;
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
