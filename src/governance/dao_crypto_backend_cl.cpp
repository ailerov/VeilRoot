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
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/arith/gmp_extras.hpp"
#include "bicycl/bicycl/arith/qfi.hpp"
#include "bicycl/bicycl/seclevel.hpp"
#include "ringct/rctOps.h"

#include <array>
#include <cstring>
#include <memory>
#include <random>
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

// Sign-aware Mpz wire encoding. mpz_export/mpz_import only handle
// magnitude; binary quadratic form components (especially b) can be
// negative in reduced form, so sign must be preserved explicitly.
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

// Canonical signed-magnitude decode:
//   SCALAR(v) = sign_byte (0 = non-negative, 1 = negative) || u32(len) || magnitude_be
// Rejects: sign_byte > 1, negative values when allow_negative=false,
// zero with sign_byte=1 (negative zero), zero with len>0 (all-zero
// magnitude), non-zero magnitudes with a leading zero byte.
bool mpz_from_bytes_signed(const std::vector<uint8_t>& in, size_t& off, Mpz& out,
                           bool allow_negative = true)
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

// In reduced binary quadratic forms 'a' and 'c' are positive; 'b'
// may be negative. Any form whose reconstructed discriminant differs
// from expected_disc is rejected — this binds a wire-encoded QFI to
// the class group it was created in, so a ciphertext from a different
// CL parameter set cannot be misinterpreted as valid here.
bool qfi_from_bytes(const std::vector<uint8_t>& in, size_t& off, QFI& out,
                    const Mpz& expected_disc)
{
    Mpz a, b, c;
    if (!mpz_from_bytes_signed(in, off, a, /*allow_negative=*/false)) return false;
    if (!mpz_from_bytes_signed(in, off, b, /*allow_negative=*/true))  return false;
    if (!mpz_from_bytes_signed(in, off, c, /*allow_negative=*/false)) return false;
    try {
        out = QFI(a, b, c);
    } catch (...) {
        return false;
    }
    if (out.discriminant() != expected_disc) return false;
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
        // RandGen's default constructor produces the same sequence
        // for every instance. Without an explicit seed, two backends
        // constructed with identical parameters would derive the
        // same p, hence the same class group, defeating
        // discriminant isolation. Seed from the OS before any
        // operation that consumes randomness (including random_p
        // during CL_HSMqk construction).
        {
            std::random_device rd;
            Mpz seed(static_cast<unsigned long>(rd()));
            randgen_.set_seed(seed);
        }
        Mpz q = make_q();
        // q must exceed the signed tally range (2*W_MAX + 1,
        // ~2^69) with margin. Ed25519 q has 252 bits; require
        // at least 200 bits so a future change to make_q()
        // cannot silently produce a q incompatible with the
        // tally range.
        if (q.nbits() < 200)
        {
            throw std::runtime_error(
                "CL backend: q must be >= 200 bits for DAO "
                "signed-tally-range injectivity");
        }
        SecLevel sl(static_cast<int>(seclevel_bits));
        cl_ = std::make_unique<CL_HSMqk>(
            q, 1, sl, randgen_, CL_Params{seclevel_bits});
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
        // The class group is constructed from (q, k, p) BEFORE parsing
        // pk so that pk's discriminant can be checked against the group
        // we just built. sk_ is not restored: the wire carries public
        // parameters only.
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
        if (!mpz_from_bytes_signed(in, off, p, /*allow_negative=*/false))
            return false;
        try {
            cl_ = std::make_unique<CL_HSMqk>(
                q, static_cast<size_t>(k), p,
                CL_Params{seclevel_bits_});
        } catch (...) {
            cl_.reset(); pk_.reset(); sk_.reset();
            return false;
        }
        QFI pk_qfi;
        if (!qfi_from_bytes(in, off, pk_qfi, cl_->Delta())) {
            cl_.reset(); pk_.reset(); sk_.reset();
            return false;
        }
        if (off != in.size()) {
            cl_.reset(); pk_.reset(); sk_.reset();
            return false;
        }
        try {
            pk_ = std::make_unique<CL_HSMqk::PublicKey>(*cl_, pk_qfi);
        } catch (...) {
            cl_.reset(); pk_.reset(); sk_.reset();
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
        if (!qfi_from_bytes(c1, off1, a1, cl_->Delta())) return false;
        if (!qfi_from_bytes(c1, off1, a2, cl_->Delta())) return false;
        if (!qfi_from_bytes(c2, off2, b1, cl_->Delta())) return false;
        if (!qfi_from_bytes(c2, off2, b2, cl_->Delta())) return false;
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
        if (!qfi_from_bytes(c, off, t, cl_->Delta())) return false;
        if (!qfi_from_bytes(c, off, t, cl_->Delta())) return false;
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
        if (!qfi_from_bytes(ct, off, c1, cl_->Delta())) return false;
        if (!qfi_from_bytes(ct, off, c2, cl_->Delta())) return false;
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
        if (!qfi_from_bytes(c, off, c1, cl_->Delta())) return false;
        if (!qfi_from_bytes(c, off, c2, cl_->Delta())) return false;
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
