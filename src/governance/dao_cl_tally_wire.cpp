// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_cl_tally_wire.h"

#ifdef VEILROOT_ENABLE_CL

#include "governance/dao_cl_dkg_payload.h"

#include "bicycl/bicycl/cl/CL_threshold.hpp"

#include <algorithm>
#include <random>

namespace cryptonote {
namespace dao {

bool dao_cl_partial_decryption_serialize(
    const BICYCL::QFI& w,
    const BICYCL::CL_HSMqk_DlogEq_AoK& proof,
    std::vector<uint8_t>& out)
{
    out.clear();
    if (!cl_dkg_qfi_to_bytes(out, w)) return false;
    if (!cl_dkg_mpz_to_bytes_signed(out, proof.u())) return false;
    if (!cl_dkg_qfi_to_bytes(out, proof.R1())) return false;
    if (!cl_dkg_qfi_to_bytes(out, proof.R2())) return false;
    if (out.size() > DAO_CL_PARTIAL_DECRYPTION_MAX_BYTES) {
        out.clear();
        return false;
    }
    return true;
}

bool dao_cl_partial_decryption_deserialize(
    const std::vector<uint8_t>& in,
    const BICYCL::Mpz& expected_disc,
    BICYCL::QFI& w,
    BICYCL::Mpz& proof_u,
    BICYCL::QFI& proof_R1,
    BICYCL::QFI& proof_R2)
{
    if (in.empty() || in.size() > DAO_CL_PARTIAL_DECRYPTION_MAX_BYTES)
        return false;
    std::size_t off = 0;
    if (!cl_dkg_qfi_from_bytes(in, off, w, expected_disc)) return false;
    if (!cl_dkg_mpz_from_bytes_signed(in, off, proof_u, true)) return false;
    if (!cl_dkg_qfi_from_bytes(in, off, proof_R1, expected_disc)) return false;
    if (!cl_dkg_qfi_from_bytes(in, off, proof_R2, expected_disc)) return false;
    return off == in.size();
}

bool dao_cl_ciphertext_to_wire(const BICYCL::CL_HSMqk::CipherText& ct,
                               std::vector<uint8_t>& out)
{
    out.clear();
    if (!cl_dkg_qfi_to_bytes(out, ct.c1())) return false;
    if (!cl_dkg_qfi_to_bytes(out, ct.c2())) return false;
    return true;
}

bool dao_cl_ciphertext_from_wire(const BICYCL::CL_HSMqk& cl,
                                 const std::vector<uint8_t>& in,
                                 BICYCL::CL_HSMqk::CipherText& out)
{
    std::size_t off = 0;
    BICYCL::QFI c1, c2;
    if (!cl_dkg_qfi_from_bytes(in, off, c1, cl.Cl_G().discriminant()))
        return false;
    if (!cl_dkg_qfi_from_bytes(in, off, c2, cl.Cl_Delta().discriminant()))
        return false;
    if (off != in.size()) return false;
    try {
        out = BICYCL::CL_HSMqk::CipherText(cl, c1, c2);
    } catch (...) {
        return false;
    }
    return true;
}

// Both helpers use the deterministic forms (explicit randomness r = 0
// or r = 1) so that re-applying the same operation on the same inputs
// reproduces byte-identical ciphertexts. Rerandomizing add/inverse
// breaks byte-level rollback equality, which the DAO consensus relies
// on when reverting a vote contribution.
// Both helpers use r = 0 so that no h^r / pk^r factor is introduced.
// That makes add and inverse pure, deterministic class-group operations:
//   inverse(ct) = (c1^-1, c2^-1)
//   add(a,b)    = (a.c1*b.c1, a.c2*b.c2)
// so that inverse+add restores the canonical (1, 1) identity when the
// aggregate is emptied. r != 0 would multiply by h^r and pk^r and make
// byte-for-byte rollback impossible.
bool dao_cl_ciphertext_inverse(const BICYCL::CL_HSMqk& cl,
                               const BICYCL::CL_HSMqk::PublicKey& pk,
                               const BICYCL::CL_HSMqk::CipherText& ct,
                               BICYCL::RandGen& rng,
                               BICYCL::CL_HSMqk::CipherText& out)
{
    (void)rng;
    try {
        BICYCL::Mpz minus_one(-1L);
        out = cl.scal_ciphertexts(pk, ct, minus_one, BICYCL::Mpz(0UL));
        return true;
    } catch (...) {
        return false;
    }
}

bool dao_cl_ciphertext_add(const BICYCL::CL_HSMqk& cl,
                           const BICYCL::CL_HSMqk::PublicKey& pk,
                           const BICYCL::CL_HSMqk::CipherText& a,
                           const BICYCL::CL_HSMqk::CipherText& b,
                           BICYCL::RandGen& rng,
                           BICYCL::CL_HSMqk::CipherText& out)
{
    (void)rng;
    try {
        out = cl.add_ciphertexts(pk, a, b, BICYCL::Mpz(0UL));
        return true;
    } catch (...) {
        return false;
    }
}

bool dao_cl_ciphertext_is_zero_wire(const BICYCL::CL_HSMqk& cl,
                                    const BICYCL::CL_HSMqk::PublicKey& pk,
                                    const std::vector<uint8_t>& wire)
{
    (void)pk;
    if (wire.empty()) return false;
    try {
        BICYCL::CL_HSMqk::CipherText parsed;
        if (!dao_cl_ciphertext_from_wire(cl, wire, parsed)) return false;
        // Canonical identity ciphertext: c1 == Cl_G().one(),
        // c2 == Cl_Delta().one().
        const BICYCL::QFI one_G     = cl.Cl_G().one();
        const BICYCL::QFI one_Delta = cl.Cl_Delta().one();
        return parsed.c1() == one_G && parsed.c2() == one_Delta;
    } catch (...) {
        return false;
    }
}

bool dao_cl_partial_decryption_verify(
    const BICYCL::CL_HSMqk& cl,
    const BICYCL::CL_HSMqk::CipherText& ct,
    const BICYCL::Mpz& D,
    const BICYCL::QFI& gamma_i,
    const std::vector<uint8_t>& partial_wire)
{
    try {
        BICYCL::QFI w, R1, R2;
        BICYCL::Mpz u;
        if (!dao_cl_partial_decryption_deserialize(
                partial_wire, cl.Cl_G().discriminant(), w, u, R1, R2))
            return false;

        CLDlogEqAoKExposed proof(u, R1, R2);

        BICYCL::Mpz delta2;
        BICYCL::Mpz::mul(delta2, D, D);

        BICYCL::QFI h_delta2;
        cl.power_of_h(h_delta2, delta2);

        BICYCL::QFI ct1_delta2;
        cl.Cl_G().nupow(ct1_delta2, ct.c1(), delta2);

        BICYCL::CL_Threshold_Static::PartialDecryption pd;
        pd.w() = w;
        pd.proof() = proof;
        return pd.verify(cl, /*soundness_bytes=*/32,
                         h_delta2, ct1_delta2, gamma_i);
    } catch (...) {
        return false;
    }
}

bool dao_cl_partial_decryption_combine(
    const BICYCL::CL_HSMqk& cl,
    const BICYCL::CL_HSMqk::PublicKey& pk,
    const BICYCL::CL_HSMqk::CipherText& ct,
    const BICYCL::Mpz& D,
    const std::vector<uint32_t>& member_ids,
    const std::vector<std::vector<uint8_t>>& cl_partials,
    const BICYCL::CL_Threshold_Static::ParticipantsValueMap<BICYCL::QFI>& gammas,
    const BICYCL::CL_Threshold_Static::ParticipantsSet& qualified_ids,
    BICYCL::Mpz& out_plaintext)
{
    if (member_ids.size() != cl_partials.size()) return false;
    if (member_ids.size() < 2) return false;

    unsigned int n = 1;
    for (uint32_t m : member_ids) n = std::max(n, m + 1u);
    for (uint32_t q : qualified_ids) n = std::max(n, q + 1u);
    if (n < 2) return false;

    unsigned int t = static_cast<unsigned int>(member_ids.size() - 1u);
    if (t >= n) t = n - 1u;

    // Pick a valid i_ not in member_ids; used only to satisfy the
    // constructor. The verified-install path does not depend on i_.
    unsigned int i_dummy = 0;
    while (i_dummy < n) {
        bool clash = false;
        for (uint32_t m : member_ids)
            if (m == i_dummy) { clash = true; break; }
        if (!clash) break;
        ++i_dummy;
    }
    if (i_dummy >= n) return false;

    try {
        BICYCL::CL_Threshold_Static player(cl, n, t, i_dummy, 32);
        player.install_public_state(cl, pk, gammas, qualified_ids);

        for (size_t k = 0; k < member_ids.size(); ++k) {
            BICYCL::QFI w, R1, R2;
            BICYCL::Mpz u;
            if (!dao_cl_partial_decryption_deserialize(
                    cl_partials[k], cl.Cl_G().discriminant(),
                    w, u, R1, R2))
                return false;
            BICYCL::CL_Threshold_Static::PartialDecryption pd;
            pd.w() = w;
            CLDlogEqAoKExposed proof(u, R1, R2);
            pd.proof() = proof;
            player.install_verified_partial_dec(member_ids[k], pd);
        }

        BICYCL::CL_HSMqk::ClearText m(cl, BICYCL::Mpz(0UL));
        player.decrypt_combine(m, cl, ct);
        out_plaintext = static_cast<BICYCL::Mpz>(m);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
