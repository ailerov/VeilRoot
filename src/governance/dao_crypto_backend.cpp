// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_crypto_backend.h"

#include "governance/dao_dkg.h"
#include "governance/dao_paillier.h"

namespace cryptonote {
namespace dao {

namespace {

class PaillierEncryptionBackend final : public DaoEncryptionBackend
{
public:
    PaillierEncryptionBackend() = default;
    explicit PaillierEncryptionBackend(PaillierPublicKey&& pk)
        : pk_(std::move(pk)) {}

    std::string name() const override { return "paillier"; }

    bool serialize_modulus(std::vector<uint8_t>& out) const override
    {
        return pk_.serialize_modulus(out);
    }
    bool deserialize_modulus(const std::vector<uint8_t>& in) override
    {
        return pk_.deserialize_modulus(in);
    }

    bool encrypt(const BIGNUM* m,
                 const BIGNUM* r,
                 std::vector<uint8_t>& ct_out) const override
    {
        return pk_.encrypt(m, r, ct_out);
    }
    bool add(const std::vector<uint8_t>& c1,
             const std::vector<uint8_t>& c2,
             std::vector<uint8_t>& out) const override
    {
        return pk_.add(c1, c2, out);
    }
    bool inverse(const std::vector<uint8_t>& c,
                 std::vector<uint8_t>& out) const override
    {
        return pk_.inverse(c, out);
    }
    bool scalar_mul(const std::vector<uint8_t>& c,
                    const BIGNUM* k,
                    std::vector<uint8_t>& out) const override
    {
        return pk_.scalar_mul(c, k, out);
    }
    bool is_valid_ciphertext(const std::vector<uint8_t>& c) const override
    {
        return pk_.is_valid_ciphertext(c);
    }
    bool sample_r(BIGNUM* r_out) const override
    {
        return dao_dkg_sample_r(pk_, r_out);
    }
    size_t ciphertext_size_hint() const override
    {
        // Matches the wire format assumed by every existing caller.
        // Paillier's ciphertext space is Z_{N^2}, encoded in
        // PAILLIER_CT_BYTES big-endian bytes.
        return PAILLIER_CT_BYTES;
    }

private:
    PaillierPublicKey pk_;
};

} // namespace

std::unique_ptr<DaoEncryptionBackend> make_paillier_backend()
{
    return std::make_unique<PaillierEncryptionBackend>();
}

namespace {

bool read_u32_be(const std::vector<uint8_t>& in, size_t& off, uint32_t& v)
{
    if (off + 4 > in.size()) return false;
    v = (static_cast<uint32_t>(in[off    ]) << 24)
      | (static_cast<uint32_t>(in[off + 1]) << 16)
      | (static_cast<uint32_t>(in[off + 2]) <<  8)
      |  static_cast<uint32_t>(in[off + 3]);
    off += 4;
    return true;
}

void write_u32_be(std::vector<uint8_t>& out, uint32_t v)
{
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >>  8));
    out.push_back(static_cast<uint8_t>(v      ));
}

bool read_scalar_be(const std::vector<uint8_t>& in, size_t& off,
                    bool require_positive,
                    std::vector<uint8_t>& payload_out)
{
    if (off >= in.size()) return false;
    uint8_t sign = in[off++];
    if (sign > 1) return false;
    if (require_positive && sign != 0) return false;
    uint32_t len = 0;
    if (!read_u32_be(in, off, len)) return false;
    if (len >= 4096) return false;
    if (off + len > in.size()) return false;
    if (len > 0 && in[off] == 0) return false;
    payload_out.clear();
    payload_out.reserve(1 + len);
    payload_out.push_back(sign);
    payload_out.insert(payload_out.end(),
                       in.begin() + off,
                       in.begin() + off + len);
    off += len;
    return true;
}

void write_scalar_be(std::vector<uint8_t>& out,
                     const std::vector<uint8_t>& sign_plus_payload)
{
    out.push_back(sign_plus_payload[0]);
    write_u32_be(out,
        static_cast<uint32_t>(sign_plus_payload.size() - 1u));
    out.insert(out.end(),
               sign_plus_payload.begin() + 1,
               sign_plus_payload.end());
}

bool read_qfi(const std::vector<uint8_t>& in, size_t& off,
              std::vector<uint8_t>& payload_out)
{
    std::vector<uint8_t> a, b, c;
    if (!read_scalar_be(in, off, false, a)) return false;
    if (!read_scalar_be(in, off, false, b)) return false;
    if (!read_scalar_be(in, off, false, c)) return false;
    payload_out.clear();
    write_scalar_be(payload_out, a);
    write_scalar_be(payload_out, b);
    write_scalar_be(payload_out, c);
    return true;
}

} // namespace

bool dao_cl_key_context_serialize(const cl_key_context& ctx,
                                  std::vector<uint8_t>& out)
{
    out.clear();
    static const char dom[] = "VeilRoot-DAO-CL-KeyCtx-V1";
    out.insert(out.end(), dom, dom + sizeof(dom));
    out.push_back(1);
    if (ctx.q.empty() || ctx.q[0] == 0) return false;
    if (ctx.q.size() >= 4096u) return false;
    write_u32_be(out, static_cast<uint32_t>(ctx.q.size()));
    out.insert(out.end(), ctx.q.begin(), ctx.q.end());
    if (ctx.k == 0u || ctx.k >= 1024u) return false;
    write_u32_be(out, ctx.k);
    if (ctx.p.size() < 1u) return false;
    write_scalar_be(out, ctx.p);
    out.insert(out.end(), ctx.pk_qfi.begin(), ctx.pk_qfi.end());
    if (ctx.D.size() < 1u) return false;
    write_scalar_be(out, ctx.D);
    return true;
}

bool dao_cl_key_context_parse(const std::vector<uint8_t>& in,
                              cl_key_context& out)
{
    static const char dom[] = "VeilRoot-DAO-CL-KeyCtx-V1";
    const size_t dom_len = sizeof(dom);
    if (in.size() < dom_len + 1u) return false;
    if (std::memcmp(in.data(), dom, dom_len) != 0) return false;
    size_t off = dom_len;
    if (in[off] != 1) return false;
    off += 1;
    uint32_t len_q = 0;
    if (!read_u32_be(in, off, len_q)) return false;
    if (len_q == 0u || len_q >= 4096u) return false;
    if (off + len_q > in.size()) return false;
    if (in[off] == 0) return false;
    out.q.assign(in.begin() + off, in.begin() + off + len_q);
    off += len_q;
    uint32_t k = 0;
    if (!read_u32_be(in, off, k)) return false;
    if (k == 0u || k >= 1024u) return false;
    out.k = k;
    if (!read_scalar_be(in, off, /*require_positive=*/false, out.p)) return false;
    if (!read_qfi(in, off, out.pk_qfi)) return false;
    if (!read_scalar_be(in, off, /*require_positive=*/true,  out.D)) return false;
    return off == in.size();
}

bool dao_cl_modulus_wire_valid(const std::vector<uint8_t>& in)
{
    cl_key_context tmp;
    return dao_cl_key_context_parse(in, tmp);
}


std::unique_ptr<DaoEncryptionBackend>
make_paillier_backend(const std::vector<uint8_t>& modulus)
{
    PaillierPublicKey pk;
    if (!pk.deserialize_modulus(modulus)) return nullptr;
    return std::make_unique<PaillierEncryptionBackend>(std::move(pk));
}

#ifndef VEILROOT_ENABLE_CL
// Stub: CL backend was not compiled. Return nullptr so callers get a
// clean failure instead of a link error.
std::unique_ptr<DaoEncryptionBackend>
make_cl_backend(size_t /*seclevel_bits*/)
{
    return nullptr;
}
#endif

} // namespace dao
} // namespace cryptonote
