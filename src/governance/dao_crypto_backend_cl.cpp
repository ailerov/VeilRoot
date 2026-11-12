// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// CL-over-class-groups backend. RESEARCH CODE.
//
// BICYCL is not constant-time and is not production-ready. This file
// is compiled only when VEILROOT_ENABLE_CL is defined; shipped
// binaries leave that option off.
//
// Implements the full DaoEncryptionBackend contract.
// Constructor, encrypt, decrypt (test hook), ciphertext validity,
// sample_r, serialize_modulus, deserialize_modulus, add, inverse,
// scalar_mul.
//
// Wire formats:
//   ciphertext   = QFI(c1) || QFI(c2)
//   QFI(x)       = SCALAR(a) || SCALAR(b) || SCALAR(c)
//   SCALAR(v)    = sign_byte (0 or 1) || u32(len) || magnitude_be
//   public_params = u32(len_q) || q_be || u32(k) || SCALAR(p) ||
//                   QFI(pk.elt())
//   (sign-aware; mpz_export alone loses sign, which breaks b in
//   reduced binary quadratic forms that have negative middle
//   coefficient. p is required: the class group is Cl(-p*q^{2k+1});
//   omitting p would derive a fresh p and produce a semantically
//   different group.)

#include "governance/dao_crypto_backend.h"

#ifdef VEILROOT_ENABLE_CL

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/CL_HSMqk.hpp"
#include "bicycl/bicycl/gmp_extras.hpp"
#include "bicycl/bicycl/qfi.hpp"
#include "bicycl/bicycl/seclevel.hpp"
#include "ringct/rctOps.h"

#include <array>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace cryptonote {
namespace dao {

namespace {

using namespace BICYCL;

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
    if (mpz_sgn(v.mpz_) == 0) return {};
    std::vector<uint8_t> buf(mpz_sizeinbase(v.mpz_, 2) / 8 + 2);
    size_t count = 0;
    mpz_export(buf.data(), &count, 1, 1, 0, 0, v.mpz_);
    buf.resize(count);
    return buf;
}

Mpz mpz_from_bytes_be(const uint8_t* data, size_t n)
{
    Mpz out;
    if (n == 0) return out;
    mpz_import(out.mpz_, n, 1, 1, 0, 0, data);
    return out;
}

// Sign-aware Mpz wire encoding. mpz_export/mpz_import only handle
// magnitude; binary quadratic form components (especially b) can be
// negative in reduced form, so sign must be preserved explicitly.
void mpz_to_bytes_signed(std::vector<uint8_t>& out, const Mpz& v)
{
    bool neg = mpz_sgn(v.mpz_) < 0;
    out.push_back(neg ? 1 : 0);
    Mpz abs_v = v;
    if (neg) mpz_neg(abs_v.mpz_, abs_v.mpz_);
    auto bytes = mpz_to_bytes_be(abs_v);
    u32_be_append(out, static_cast<uint32_t>(bytes.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
}

bool mpz_from_bytes_signed(const std::vector<uint8_t>& in, size_t& off, Mpz& out)
{
    if (off >= in.size()) return false;
    bool neg = in[off++] != 0;
    uint32_t len = 0;
    if (!u32_be_read(in, off, len)) return false;
    if (off + len > in.size()) return false;
    out = mpz_from_bytes_be(in.data() + off, len);
    off += len;
    if (neg) mpz_neg(out.mpz_, out.mpz_);
    return true;
}

void qfi_to_bytes(std::vector<uint8_t>& out, const QFI& f)
{
    mpz_to_bytes_signed(out, f.a());
    mpz_to_bytes_signed(out, f.b());
    mpz_to_bytes_signed(out, f.c());
}

bool qfi_from_bytes(const std::vector<uint8_t>& in, size_t& off, QFI& out)
{
    Mpz a, b, c;
    if (!mpz_from_bytes_signed(in, off, a)) return false;
    if (!mpz_from_bytes_signed(in, off, b)) return false;
    if (!mpz_from_bytes_signed(in, off, c)) return false;
    try {
        out = QFI(a, b, c);
    } catch (...) {
        return false;
    }
    return true;
}

// Ed25519 subgroup order (q):
//   2^252 + 27742317777372353535851937790883648493
// This is what rct::curveOrder() returns in Monero's RingCT
// implementation.
Mpz make_q()
{
    // rct::curveOrder() returns LE bytes; Mpz ctor expects BE.
    std::array<uint8_t, 32> be{};
    const rct::key L = rct::curveOrder();
    for (size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
    return Mpz(std::vector<uint8_t>(be.begin(), be.end()));
}

} // namespace

class CLEncryptionBackend final : public DaoEncryptionBackend
{
public:
    explicit CLEncryptionBackend(size_t seclevel_bits)
        : seclevel_bits_(seclevel_bits)
    {
        Mpz q = make_q();
        // q must exceed the signed tally range (2*W_MAX + 1,
        // ~2^69) with margin. Ed25519 q has 252 bits; require
        // at least 200 bits so a future change to make_q()
        // cannot silently produce a q incompatible with the
        // tally range.
        if (mpz_sizeinbase(q.mpz_, 2) < 200)
        {
            throw std::runtime_error(
                "CL backend: q must be >= 200 bits for DAO "
                "signed-tally-range injectivity");
        }
        SecLevel sl(static_cast<int>(seclevel_bits));
        cl_ = std::make_unique<CL_HSMqk>(q, 1, sl, randgen_, /*compact=*/false);
        sk_ = std::make_unique<CL_HSMqk::SecretKey>(*cl_, randgen_);
        pk_ = std::make_unique<CL_HSMqk::PublicKey>(*cl_, *sk_);
    }

    std::string name() const override { return "cl_hsmqk"; }

    bool serialize_modulus(std::vector<uint8_t>& out) const override
    {
        // Wire: u32(len_q) || q_be || u32(k) || SCALAR(p) || QFI(pk.elt())
        // p (the odd prime whose negation is the fundamental
        // discriminant of K) is public and REQUIRED: reconstructing
        // CL_HSMqk without it derives a fresh p, hence a different
        // class group, hence semantically incompatible ciphertexts.
        out.clear();
        auto q_bytes = mpz_to_bytes_be(cl_->q());
        u32_be_append(out, static_cast<uint32_t>(q_bytes.size()));
        out.insert(out.end(), q_bytes.begin(), q_bytes.end());
        u32_be_append(out, static_cast<uint32_t>(cl_->k()));
        mpz_to_bytes_signed(out, cl_->p());
        qfi_to_bytes(out, pk_->elt());
        return true;
    }

    bool deserialize_modulus(const std::vector<uint8_t>& in) override
    {
        // Format mirrors serialize_modulus:
        //   u32(len_q) || q_be || u32(k) || SCALAR(p) || QFI(pk.elt())
        // After success, this backend is public-key-only: sk_ is
        // reset because the wire does not (and must not) carry
        // secret material. Callers that need decryption must
        // hold a backend with the original sk_.
        size_t off = 0;
        uint32_t lq = 0;
        if (!u32_be_read(in, off, lq)) return false;
        if (off + lq > in.size()) return false;
        Mpz q = mpz_from_bytes_be(in.data() + off, lq);
        off += lq;
        uint32_t k = 0;
        if (!u32_be_read(in, off, k)) return false;
        if (k == 0) return false;
        Mpz p;
        if (!mpz_from_bytes_signed(in, off, p)) return false;
        QFI pk_qfi;
        if (!qfi_from_bytes(in, off, pk_qfi)) return false;
        if (off != in.size()) return false;
        try {
            cl_ = std::make_unique<CL_HSMqk>(
                q, static_cast<size_t>(k), p, /*compact=*/false);
            pk_ = std::make_unique<CL_HSMqk::PublicKey>(*cl_, pk_qfi);
        } catch (...) {
            cl_.reset();
            pk_.reset();
            sk_.reset();
            return false;
        }
        sk_.reset();
        return true;
    }

    bool encrypt(const BIGNUM* m, const BIGNUM* r,
                 std::vector<uint8_t>& ct_out) const override
    {
        if (!pk_) return false;
        int mb = BN_num_bytes(m);
        std::vector<uint8_t> mbuf(mb);
        BN_bn2bin(m, mbuf.data());
        Mpz m_mpz = mpz_from_bytes_be(mbuf.data(), mbuf.size());

        int rb = BN_num_bytes(r);
        std::vector<uint8_t> rbuf(rb);
        BN_bn2bin(r, rbuf.data());
        Mpz r_mpz = mpz_from_bytes_be(rbuf.data(), rbuf.size());

        CL_HSMqk::ClearText mct(*cl_, m_mpz);
        CL_HSMqk::CipherText ct = cl_->encrypt(*pk_, mct, r_mpz);
        ct_out.clear();
        qfi_to_bytes(ct_out, ct.c1());
        qfi_to_bytes(ct_out, ct.c2());
        return true;
    }

    bool add(const std::vector<uint8_t>& c1,
             const std::vector<uint8_t>& c2,
             std::vector<uint8_t>& out) const override
    {
        if (!pk_) return false;
        size_t off1 = 0, off2 = 0;
        QFI a1, a2, b1, b2;
        if (!qfi_from_bytes(c1, off1, a1)) return false;
        if (!qfi_from_bytes(c1, off1, a2)) return false;
        if (!qfi_from_bytes(c2, off2, b1)) return false;
        if (!qfi_from_bytes(c2, off2, b2)) return false;
        CL_HSMqk::CipherText ca(*cl_, a1, a2);
        CL_HSMqk::CipherText cb(*cl_, b1, b2);
        Mpz r = randgen_.random_mpz(cl_->encrypt_randomness_bound());
        CL_HSMqk::CipherText sum = cl_->add_ciphertexts(*pk_, ca, cb, r);
        out.clear();
        qfi_to_bytes(out, sum.c1());
        qfi_to_bytes(out, sum.c2());
        return true;
    }

    bool inverse(const std::vector<uint8_t>& c,
                 std::vector<uint8_t>& out) const override
    {
        Mpz minus_one(-1L);
        return scalar_mul_impl(c, minus_one, out);
    }

    bool scalar_mul(const std::vector<uint8_t>& c,
                    const BIGNUM* k,
                    std::vector<uint8_t>& out) const override
    {
        int kb = BN_num_bytes(k);
        std::vector<uint8_t> kbuf(kb);
        BN_bn2bin(k, kbuf.data());
        Mpz k_mpz = mpz_from_bytes_be(kbuf.data(), kbuf.size());
        return scalar_mul_impl(c, k_mpz, out);
    }

    bool is_valid_ciphertext(const std::vector<uint8_t>& c) const override
    {
        size_t off = 0;
        QFI t;
        if (!qfi_from_bytes(c, off, t)) return false;
        if (!qfi_from_bytes(c, off, t)) return false;
        return off == c.size();
    }

    bool sample_r(BIGNUM* r_out) const override
    {
        Mpz r = randgen_.random_mpz(cl_->encrypt_randomness_bound());
        auto bytes = mpz_to_bytes_be(r);
        return BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()),
                         r_out) != nullptr;
    }

    size_t ciphertext_size_hint() const override { return 0; }

    bool decrypt_for_testing(const std::vector<uint8_t>& ct,
                             BIGNUM* m_out) const override
    {
        if (!sk_) return false;
        size_t off = 0;
        QFI c1, c2;
        if (!qfi_from_bytes(ct, off, c1)) return false;
        if (!qfi_from_bytes(ct, off, c2)) return false;
        CL_HSMqk::CipherText ct_cl(*cl_, c1, c2);
        CL_HSMqk::ClearText pt = cl_->decrypt(*sk_, ct_cl);
        auto bytes = mpz_to_bytes_be(pt);
        return BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()),
                         m_out) != nullptr;
    }

private:
    bool scalar_mul_impl(const std::vector<uint8_t>& c, const Mpz& s,
                         std::vector<uint8_t>& out) const
    {
        if (!pk_) return false;
        size_t off = 0;
        QFI c1, c2;
        if (!qfi_from_bytes(c, off, c1)) return false;
        if (!qfi_from_bytes(c, off, c2)) return false;
        CL_HSMqk::CipherText ct(*cl_, c1, c2);
        Mpz r = randgen_.random_mpz(cl_->encrypt_randomness_bound());
        CL_HSMqk::CipherText scaled = cl_->scal_ciphertexts(*pk_, ct, s, r);
        out.clear();
        qfi_to_bytes(out, scaled.c1());
        qfi_to_bytes(out, scaled.c2());
        return true;
    }

    size_t seclevel_bits_ = 128;
    mutable RandGen randgen_;
    std::unique_ptr<CL_HSMqk> cl_;
    std::unique_ptr<CL_HSMqk::SecretKey> sk_;
    std::unique_ptr<CL_HSMqk::PublicKey> pk_;
};

std::unique_ptr<DaoEncryptionBackend>
make_cl_backend(size_t seclevel_bits)
{
    try {
        return std::make_unique<CLEncryptionBackend>(seclevel_bits);
    } catch (const std::exception&) {
        // Constructor rejected its parameters. Return nullptr
        // rather than propagate, matching make_paillier_backend.
        return nullptr;
    }
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
