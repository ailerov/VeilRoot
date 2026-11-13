// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_cl_threshold.h"

#ifdef VEILROOT_ENABLE_CL

#include <cstring>
#include <stdexcept>

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

} // namespace

CLCommittee::CLCommittee(std::shared_ptr<CL_HSMqk> cl,
                         unsigned int n,
                         unsigned int t,
                         size_t soundness_bits)
    : cl_(std::move(cl)),
      n_(n), t_(t),
      soundness_bits_(soundness_bits)
{
    if (!cl_) throw std::invalid_argument("CLCommittee: null CL_HSMqk");
    if (n < 2) throw std::invalid_argument("CLCommittee: n must be >= 2");
    if (t >= n) throw std::invalid_argument("CLCommittee: t must be < n");
    for (unsigned int i = 0; i < n_; ++i) {
        parties_.push_back(std::make_unique<CLCommitteeParty>(
            cl_, n_, t_, i, soundness_bits_));
    }
}

bool CLCommittee::run_keygen_inproc(RandGen& randgen)
{
    try {
        for (auto& p : parties_)
            if (!p->keygen_dealing(randgen)) return false;

        for (unsigned int i = 0; i < n_; ++i) {
            for (unsigned int j = 0; j < n_; ++j) {
                if (i == j) continue;
                if (!parties_[j]->keygen_add_commitments(
                        i, parties_[i]->keygen_commitments())) return false;
                if (!parties_[j]->keygen_add_proof(
                        i, parties_[i]->keygen_batch_proof())) return false;
            }
        }

        for (unsigned int i = 0; i < n_; ++i) {
            for (unsigned int j = 0; j < n_; ++j) {
                if (i == j) continue;
                if (!parties_[j]->keygen_add_share(
                        i, parties_[i]->keygen_y_k(j))) return false;
            }
        }

        for (auto& p : parties_)
            if (!p->keygen_check_verify_all()) return false;

        for (auto& p : parties_)
            if (!p->keygen_extract()) return false;

        keygen_done_ = true;
        return true;
    }
    catch (...) { return false; }
}

const CL_HSMqk::PublicKey& CLCommittee::public_key() const
{
    if (!keygen_done_)
        throw std::logic_error("CLCommittee: keygen not yet completed");
    return parties_.front()->public_key();
}

bool CLCommittee::serialize_public_params(std::vector<uint8_t>& out) const
{
    if (!keygen_done_) return false;
    try {
        out.clear();
        auto qb = mpz_to_bytes_be(cl_->q());
        u32_be_append(out, static_cast<uint32_t>(qb.size()));
        out.insert(out.end(), qb.begin(), qb.end());
        u32_be_append(out, 1u);
        mpz_to_bytes_signed(out, cl_->p());
        qfi_to_bytes(out, parties_.front()->public_key().elt());
        return true;
    }
    catch (...) { return false; }
}

bool CLCommittee::ciphertext_from_bytes(
    const std::vector<uint8_t>& in,
    CL_HSMqk::CipherText& out) const
{
    try {
        size_t off = 0;
        QFI c1, c2;
        if (!qfi_from_bytes(in, off, c1, cl_->Cl_G().discriminant()))
            return false;
        if (!qfi_from_bytes(in, off, c2, cl_->Cl_Delta().discriminant()))
            return false;
        if (off != in.size()) return false;
        out = CL_HSMqk::CipherText(*cl_, c1, c2);
        return true;
    }
    catch (...) { return false; }
}

bool CLCommittee::ciphertext_to_bytes(
    const CL_HSMqk::CipherText& in,
    std::vector<uint8_t>& out) const
{
    try {
        out.clear();
        qfi_to_bytes(out, in.c1());
        qfi_to_bytes(out, in.c2());
        return true;
    }
    catch (...) { return false; }
}

bool CLCommittee::partial_decrypt(unsigned int i,
                                  const CL_HSMqk::CipherText& ct,
                                  RandGen& randgen)
{
    if (!keygen_done_ || i >= n_) return false;
    return parties_[i]->partial_decrypt(ct, randgen);
}

const CL_Threshold_Static::PartialDecryption&
CLCommittee::partial_dec_for_test(unsigned int i) const
{
    return parties_[i]->partial();
}

void CLCommittee::add_partial_dec(
    unsigned int i, unsigned int j,
    const CL_Threshold_Static::PartialDecryption& pd)
{
    if (i >= n_ || j >= n_) return;
    parties_[i]->add_partial_dec(j, pd);
}

bool CLCommittee::verify_partials(unsigned int i, RandGen& randgen)
{
    if (!keygen_done_ || i >= n_) return false;
    return parties_[i]->verify_partials(randgen);
}

bool CLCommittee::combine(unsigned int i,
                          CL_HSMqk::ClearText& out,
                          const CL_HSMqk::CipherText& ct)
{
    if (!keygen_done_ || i >= n_) return false;
    return parties_[i]->combine(out, ct);
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
