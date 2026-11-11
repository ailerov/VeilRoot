// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later
//
// CL-over-class-groups backend. RESEARCH CODE.
//
// BICYCL is not constant-time and is not production-ready. This file
// is compiled only when VEILROOT_ENABLE_CL is defined, which is
// never the case in shipped binaries until Phase 5 hardening lands.
//
// Scope of this file (Phase 4.2b): constructor, encrypt, decrypt
// (test hook only), ciphertext validity check, sample_r, and
// serialize_modulus. add/inverse/scalar_mul/deserialize_modulus
// return false -- those land in 4.2c/4.2d/4.2e with their own tests.
//
// Wire format (frozen for 4.2b, revocable in 4.4):
//   ciphertext = QFI(c1) || QFI(c2)
//   QFI(x)     = u32(len_a) || a_be || u32(len_b) || b_be || u32(len_c) || c_be
//   (full (a,b,c) triple; no derivation, no bypass_check)

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

void qfi_to_bytes(std::vector<uint8_t>& out, const QFI& f)
{
    auto a = mpz_to_bytes_be(f.a());
    auto b = mpz_to_bytes_be(f.b());
    auto c = mpz_to_bytes_be(f.c());
    u32_be_append(out, static_cast<uint32_t>(a.size()));
    out.insert(out.end(), a.begin(), a.end());
    u32_be_append(out, static_cast<uint32_t>(b.size()));
    out.insert(out.end(), b.begin(), b.end());
    u32_be_append(out, static_cast<uint32_t>(c.size()));
    out.insert(out.end(), c.begin(), c.end());
}

bool qfi_from_bytes(const std::vector<uint8_t>& in, size_t& off, QFI& out)
{
    auto read_one = [&](Mpz& v) -> bool {
        uint32_t len = 0;
        if (!u32_be_read(in, off, len)) return false;
        if (off + len > in.size()) return false;
        v = mpz_from_bytes_be(in.data() + off, len);
        off += len;
        return true;
    };
    Mpz a, b, c;
    if (!read_one(a)) return false;
    if (!read_one(b)) return false;
    if (!read_one(c)) return false;
    try {
        out = QFI(a, b, c);
    } catch (...) {
        return false;
    }
    return true;
}

// secp256k1 scalar field order (q). Matches reference
// benchmark_qclpvss.cpp:18 (`Mpz Q(ec_group_.order())`).
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
    {
        Mpz q = make_q();
        SecLevel sl(static_cast<int>(seclevel_bits));
        cl_ = std::make_unique<CL_HSMqk>(q, 1, sl, randgen_, /*compact=*/false);
        sk_ = std::make_unique<CL_HSMqk::SecretKey>(*cl_, randgen_);
        pk_ = std::make_unique<CL_HSMqk::PublicKey>(*cl_, *sk_);
    }

    std::string name() const override { return "cl_hsmqk"; }

    bool serialize_modulus(std::vector<uint8_t>& out) const override
    {
        out.clear();
        auto q_bytes = mpz_to_bytes_be(cl_->q());
        u32_be_append(out, static_cast<uint32_t>(q_bytes.size()));
        out.insert(out.end(), q_bytes.begin(), q_bytes.end());
        u32_be_append(out, static_cast<uint32_t>(cl_->k()));
        qfi_to_bytes(out, pk_->elt());
        return true;
    }

    bool deserialize_modulus(const std::vector<uint8_t>& /*in*/) override
    {
        // 4.2e.
        return false;
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

    bool add(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
             std::vector<uint8_t>&) const override { return false; }

    bool inverse(const std::vector<uint8_t>&,
                 std::vector<uint8_t>&) const override { return false; }

    bool scalar_mul(const std::vector<uint8_t>&, const BIGNUM*,
                    std::vector<uint8_t>&) const override { return false; }

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
    mutable RandGen randgen_;
    std::unique_ptr<CL_HSMqk> cl_;
    std::unique_ptr<CL_HSMqk::SecretKey> sk_;
    std::unique_ptr<CL_HSMqk::PublicKey> pk_;
};

std::unique_ptr<DaoEncryptionBackend>
make_cl_backend(size_t seclevel_bits)
{
    return std::make_unique<CLEncryptionBackend>(seclevel_bits);
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
