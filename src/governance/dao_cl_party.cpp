// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_cl_party.h"

#ifdef VEILROOT_ENABLE_CL

#include <stdexcept>

namespace cryptonote {
namespace dao {

using namespace BICYCL;

CLCommitteeParty::CLCommitteeParty(std::shared_ptr<CL_HSMqk> cl,
                                   unsigned int n,
                                   unsigned int t,
                                   unsigned int local_id,
                                   size_t soundness_bytes)
    : cl_(std::move(cl)),
      n_(n), t_(t), local_id_(local_id),
      soundness_bytes_(soundness_bytes)
{
    if (!cl_) throw std::invalid_argument("CLCommitteeParty: null CL_HSMqk");
    if (n < 2) throw std::invalid_argument("CLCommitteeParty: n must be >= 2");
    if (t >= n) throw std::invalid_argument("CLCommitteeParty: t must be < n");
    if (local_id >= n)
        throw std::invalid_argument("CLCommitteeParty: local_id must be < n");
    player_ = std::make_unique<CL_Threshold_Static>(
        *cl_, n_, t_, local_id_, soundness_bytes_);
}

CLCommitteeParty::CLCommitteeParty(std::shared_ptr<CL_HSMqk> cl,
                                   unsigned int n,
                                   unsigned int t,
                                   unsigned int local_id,
                                   size_t soundness_bytes,
                                   const Mpz& D)
    : cl_(std::move(cl)),
      n_(n), t_(t), local_id_(local_id),
      soundness_bytes_(soundness_bytes)
{
    if (!cl_) throw std::invalid_argument("CLCommitteeParty: null CL_HSMqk");
    if (n < 2) throw std::invalid_argument("CLCommitteeParty: n must be >= 2");
    if (t >= n) throw std::invalid_argument("CLCommitteeParty: t must be < n");
    if (local_id >= n)
        throw std::invalid_argument("CLCommitteeParty: local_id must be < n");
    player_ = std::make_unique<CL_Threshold_Static>(
        *cl_, n_, t_, local_id_, soundness_bytes_, D);
}

bool CLCommitteeParty::keygen_dealing(RandGen& randgen)
{
    try { player_->keygen_dealing(*cl_, randgen); return true; }
    catch (...) { return false; }
}

const std::vector<QFI>& CLCommitteeParty::keygen_commitments() const
{
    return player_->C();
}

const CL_HSMqk_Batch_Dlog_AoK& CLCommitteeParty::keygen_batch_proof() const
{
    return player_->batch_proof();
}

const Mpz& CLCommitteeParty::keygen_y_k(unsigned int recipient_id) const
{
    return player_->y_k(recipient_id);
}

bool CLCommitteeParty::keygen_add_commitments(
    unsigned int sender_id, const std::vector<QFI>& C)
{
    try { player_->keygen_add_commitments(sender_id, C); return true; }
    catch (...) { return false; }
}

bool CLCommitteeParty::keygen_add_proof(
    unsigned int sender_id, const CL_HSMqk_Batch_Dlog_AoK& proof)
{
    try { player_->keygen_add_proof(sender_id, proof); return true; }
    catch (...) { return false; }
}

bool CLCommitteeParty::keygen_add_share(unsigned int sender_id, const Mpz& y)
{
    try { player_->keygen_add_share(sender_id, y); return true; }
    catch (...) { return false; }
}

bool CLCommitteeParty::keygen_check_verify_all()
{
    try { return player_->keygen_check_verify_all_players(*cl_); }
    catch (...) { return false; }
}

bool CLCommitteeParty::keygen_extract()
{
    try { player_->keygen_extract(*cl_); keygen_done_ = true; return true; }
    catch (...) { return false; }
}

const CL_HSMqk::PublicKey& CLCommitteeParty::public_key() const
{
    if (!keygen_done_)
        throw std::logic_error("CLCommitteeParty: keygen not completed");
    return player_->pk();
}

bool CLCommitteeParty::partial_decrypt(const CL_HSMqk::CipherText& ct,
                                       RandGen& randgen)
{
    if (!keygen_done_) return false;
    try { player_->decrypt_partial(*cl_, randgen, ct); return true; }
    catch (...) { return false; }
}

const CL_Threshold_Static::PartialDecryption&
CLCommitteeParty::partial() const
{
    return player_->part_dec();
}

void CLCommitteeParty::add_partial_dec(
    unsigned int sender_id,
    const CL_Threshold_Static::PartialDecryption& pd)
{
    player_->decrypt_add_partial_dec(sender_id, pd);
}

bool CLCommitteeParty::verify_partials(RandGen& randgen)
{
    if (!keygen_done_) return false;
    try { return player_->decrypt_verify_batch(*cl_, randgen); }
    catch (...) { return false; }
}

bool CLCommitteeParty::combine(CL_HSMqk::ClearText& out,
                               const CL_HSMqk::CipherText& ct)
{
    if (!keygen_done_) return false;
    try { player_->decrypt_combine(out, *cl_, ct); return true; }
    catch (...) { return false; }
}

const BICYCL::Mpz& CLCommitteeParty::interpolation_scale() const
{
    return player_->interpolation_scale();
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
