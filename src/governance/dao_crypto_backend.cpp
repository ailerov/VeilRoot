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

bool read_scalar_be(const std::vector<uint8_t>& in, size_t& off)
{
    if (off >= in.size()) return false;
    uint8_t sign = in[off++];
    if (sign > 1) return false;
    uint32_t len = 0;
    if (!read_u32_be(in, off, len)) return false;
    if (len >= 4096) return false;
    if (off + len > in.size()) return false;
    if (len > 0 && in[off] == 0) return false;  // no leading zero
    off += len;
    return true;
}

bool read_qfi(const std::vector<uint8_t>& in, size_t& off)
{
    return read_scalar_be(in, off)
        && read_scalar_be(in, off)
        && read_scalar_be(in, off);
}

} // namespace

bool dao_cl_modulus_wire_valid(const std::vector<uint8_t>& in)
{
    if (in.empty()) return false;
    size_t off = 0;
    uint32_t len_q = 0;
    if (!read_u32_be(in, off, len_q)) return false;
    if (len_q == 0 || len_q >= 4096) return false;
    if (off + len_q > in.size()) return false;
    if (in[off] == 0) return false;  // no leading zero
    off += len_q;
    uint32_t k = 0;
    if (!read_u32_be(in, off, k)) return false;
    if (k == 0 || k >= 1024) return false;
    if (!read_scalar_be(in, off)) return false;  // p
    if (!read_qfi(in, off)) return false;        // pk
    return off == in.size();
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
