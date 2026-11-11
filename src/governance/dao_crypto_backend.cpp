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

std::unique_ptr<DaoEncryptionBackend>
make_paillier_backend(const std::vector<uint8_t>& modulus)
{
    PaillierPublicKey pk;
    if (!pk.deserialize_modulus(modulus)) return nullptr;
    return std::make_unique<PaillierEncryptionBackend>(std::move(pk));
}

} // namespace dao
} // namespace cryptonote
