// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_cl_dkg_payload.h"

#ifdef VEILROOT_ENABLE_CL

#include <array>
#include <cstring>
#include <memory>
#include <utility>

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/seclevel.hpp"
#include "ringct/rctOps.h"

namespace cryptonote {
namespace dao {

namespace {

using namespace BICYCL;

constexpr const char  kDomain[]         = "VeilRoot-DAO-CL-DKG-V1";
constexpr std::size_t kDomainLen        = sizeof(kDomain) - 1;
constexpr uint8_t     kPayloadVersion   = 1;
constexpr std::size_t kScalarMaxBytes   = 4096;

void u32_be_append(std::vector<uint8_t>& out, uint32_t v)
{
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >>  8));
    out.push_back(static_cast<uint8_t>(v      ));
}

bool u32_be_read(const std::vector<uint8_t>& in, std::size_t& off, uint32_t& v)
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

Mpz mpz_from_bytes_be(const uint8_t* data, std::size_t n)
{
    if (n == 0) return Mpz();
    std::vector<unsigned char> vec(data, data + n);
    return Mpz(vec);
}

bool mpz_to_bytes_signed(std::vector<uint8_t>& out, const Mpz& v)
{
    bool neg = v.sgn() < 0;
    out.push_back(neg ? 1 : 0);
    Mpz abs_v;
    Mpz::abs(abs_v, v);
    auto bytes = mpz_to_bytes_be(abs_v);
    if (bytes.size() > kScalarMaxBytes) return false;
    u32_be_append(out, static_cast<uint32_t>(bytes.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
    return true;
}

bool mpz_from_bytes_signed(const std::vector<uint8_t>& in, std::size_t& off,
                           Mpz& out, bool allow_negative = true)
{
    if (off >= in.size()) return false;
    uint8_t sign_byte = in[off++];
    if (sign_byte > 1) return false;
    uint32_t len = 0;
    if (!u32_be_read(in, off, len)) return false;
    if (len > kScalarMaxBytes) return false;
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

bool qfi_to_bytes(std::vector<uint8_t>& out, const QFI& f)
{
    return mpz_to_bytes_signed(out, f.a())
        && mpz_to_bytes_signed(out, f.b())
        && mpz_to_bytes_signed(out, f.c());
}

bool qfi_from_bytes(const std::vector<uint8_t>& in, std::size_t& off,
                    QFI& out, const Mpz& expected_disc)
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

bool cl_dkg_payload::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    out.reserve(4 + kDomainLen + 1 + 1 + 4 + body.size());
    u32_be_append(out, static_cast<uint32_t>(kDomainLen));
    out.insert(out.end(), kDomain, kDomain + kDomainLen);
    out.push_back(kPayloadVersion);
    out.push_back(static_cast<uint8_t>(subtype));
    u32_be_append(out, static_cast<uint32_t>(body.size()));
    out.insert(out.end(), body.begin(), body.end());
    return true;
}

bool cl_dkg_payload::deserialize(const std::vector<uint8_t>& in, cl_dkg_payload& out)
{
    std::size_t off = 0;
    uint32_t dlen = 0;
    if (!u32_be_read(in, off, dlen)) return false;
    if (dlen != kDomainLen) return false;
    if (off + dlen > in.size()) return false;
    if (std::memcmp(in.data() + off, kDomain, kDomainLen) != 0) return false;
    off += kDomainLen;
    if (off >= in.size()) return false;
    if (in[off++] != kPayloadVersion) return false;
    if (off >= in.size()) return false;
    uint8_t st = in[off++];
    uint32_t blen = 0;
    if (!u32_be_read(in, off, blen)) return false;
    if (off + blen != in.size()) return false;
    out.subtype = static_cast<cl_dkg_subtype>(st);
    out.body.assign(in.begin() + off, in.end());
    return true;
}

bool cl_dkg_encode_commitments(const std::vector<BICYCL::QFI>& C,
                               cl_dkg_payload& out)
{
    std::vector<uint8_t> body;
    u32_be_append(body, static_cast<uint32_t>(C.size()));
    for (const auto& f : C) {
        if (!qfi_to_bytes(body, f)) return false;
    }
    out.subtype = cl_dkg_subtype::keygen_commitments;
    out.body = std::move(body);
    return true;
}

bool cl_dkg_decode_commitments(const cl_dkg_payload& in,
                               std::vector<BICYCL::QFI>& out,
                               const BICYCL::Mpz& expected_disc,
                               std::size_t max_count)
{
    if (in.subtype != cl_dkg_subtype::keygen_commitments) return false;
    std::size_t off = 0;
    uint32_t cnt = 0;
    if (!u32_be_read(in.body, off, cnt)) return false;
    if (cnt == 0 || cnt > max_count) return false;
    out.clear();
    out.reserve(cnt);
    for (uint32_t i = 0; i < cnt; ++i) {
        QFI f;
        if (!qfi_from_bytes(in.body, off, f, expected_disc)) return false;
        out.push_back(std::move(f));
    }
    if (off != in.body.size()) return false;
    return true;
}

bool cl_dkg_encode_batch_proof(const BICYCL::Mpz& u,
                               const BICYCL::QFI& R,
                               cl_dkg_payload& out)
{
    std::vector<uint8_t> body;
    if (!mpz_to_bytes_signed(body, u)) return false;
    if (!qfi_to_bytes(body, R)) return false;
    out.subtype = cl_dkg_subtype::keygen_batch_proof;
    out.body = std::move(body);
    return true;
}

bool cl_dkg_decode_batch_proof(const cl_dkg_payload& in,
                               BICYCL::Mpz& u_out,
                               BICYCL::QFI& R_out,
                               const BICYCL::Mpz& expected_disc)
{
    if (in.subtype != cl_dkg_subtype::keygen_batch_proof) return false;
    std::size_t off = 0;
    if (!mpz_from_bytes_signed(in.body, off, u_out, true)) return false;
    if (!qfi_from_bytes(in.body, off, R_out, expected_disc)) return false;
    if (off != in.body.size()) return false;
    return true;
}

bool cl_dkg_encode_private_share(const BICYCL::Mpz& y,
                                 cl_dkg_payload& out)
{
    std::vector<uint8_t> body;
    if (!mpz_to_bytes_signed(body, y)) return false;
    out.subtype = cl_dkg_subtype::keygen_private_share;
    out.body = std::move(body);
    return true;
}

bool cl_dkg_decode_private_share(const cl_dkg_payload& in,
                                 BICYCL::Mpz& y_out)
{
    if (in.subtype != cl_dkg_subtype::keygen_private_share) return false;
    std::size_t off = 0;
    if (!mpz_from_bytes_signed(in.body, off, y_out, true)) return false;
    if (off != in.body.size()) return false;
    return true;
}

bool cl_dkg_encode_complete(cl_dkg_payload& out)
{
    out.subtype = cl_dkg_subtype::keygen_complete;
    out.body.clear();
    return true;
}

bool cl_dkg_decode_complete(const cl_dkg_payload& in)
{
    return in.subtype == cl_dkg_subtype::keygen_complete && in.body.empty();
}

bool cl_dkg_encode_complaint(uint32_t against_sender_id,
                             uint32_t reason,
                             cl_dkg_payload& out)
{
    std::vector<uint8_t> body;
    u32_be_append(body, against_sender_id);
    u32_be_append(body, reason);
    out.subtype = cl_dkg_subtype::keygen_complaint;
    out.body = std::move(body);
    return true;
}

bool cl_dkg_decode_complaint(const cl_dkg_payload& in,
                             uint32_t& against_sender_id,
                             uint32_t& reason)
{
    if (in.subtype != cl_dkg_subtype::keygen_complaint) return false;
    std::size_t off = 0;
    if (!u32_be_read(in.body, off, against_sender_id)) return false;
    if (!u32_be_read(in.body, off, reason)) return false;
    if (off != in.body.size()) return false;
    return true;
}

std::shared_ptr<BICYCL::CL_HSMqk> cl_dkg_make_hsmq(
    std::size_t seclevel_bits, BICYCL::RandGen& randgen)
{
    std::array<uint8_t, 32> be{};
    const auto L = rct::curveOrder();
    for (std::size_t i = 0; i < 32; ++i) be[i] = L.bytes[31 - i];
    Mpz q(std::vector<uint8_t>(be.begin(), be.end()));
    SecLevel sl(static_cast<int>(seclevel_bits));
    return std::make_shared<CL_HSMqk>(
        q, 1, sl, randgen, CL_Params{seclevel_bits});
}

void cl_dkg_mpz_to_bytes_be(std::vector<uint8_t>& out, const BICYCL::Mpz& v)
{
    auto be = mpz_to_bytes_be(v);
    out.insert(out.end(), be.begin(), be.end());
}

bool cl_dkg_mpz_to_bytes_signed(std::vector<uint8_t>& out, const BICYCL::Mpz& v)
{
    return mpz_to_bytes_signed(out, v);
}

bool cl_dkg_qfi_to_bytes(std::vector<uint8_t>& out, const BICYCL::QFI& f)
{
    return qfi_to_bytes(out, f);
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
