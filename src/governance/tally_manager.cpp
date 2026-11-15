// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/tally_manager.h"
#include "serialization/binary_archive.h"
#include "serialization/binary_utils.h"
#include "serialization/variant.h"
#include "serialization/string.h"
#include "governance/governance_payload.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/tx_extra.h"

#include <cstring>
#include <unordered_set>

#include <openssl/bn.h>

#include "cryptonote_core/blockchain.h"   // for proposal_record, status enum
#include "governance/dao_paillier.h"
#include "governance/dao_supply.h"
#include "governance/dao_threshold.h"
#include "governance/dao_cl_ballot.h"
#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_tally_wire.h"
#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/cl/CL_threshold.hpp"
#include <memory>
#include <random>
#include "misc_log_ex.h"

namespace cryptonote {

using namespace cryptonote::dao;

namespace {

// Signed BIGNUM wire decoding; matches the DKG driver export format.
BIGNUM* bn_from_signed_share(const std::vector<uint8_t>& in)
{
    if (in.empty()) return nullptr;
    const bool neg = (in[0] != 0);
    BIGNUM* b = BN_bin2bn(in.data() + 1,
                          static_cast<int>(in.size() - 1), nullptr);
    if (!b) return nullptr;
    if (neg && !BN_is_zero(b)) BN_set_negative(b, 1);
    return b;
}

} // anonymous namespace

TallyManager::TallyManager(BlockchainDB& db, const governance_params& params)
    : m_db(db), m_params(params) {}


bool TallyManager::build_tally_result_transaction(
    const crypto::hash& proposal_id,
    const std::map<crypto::public_key, dao::dao_v2_tally_share>& shares,
    uint32_t threshold,
    transaction& tx_out)
{
    // Do not finalize if the outcome already exists as consensus state.
    {
        dao::dao_v2_outcome_record existing;
        if (m_db.get_dao_v2_outcome(proposal_id, existing))
            return false;
    }

    proposal_record prop;
    if (!m_db.get_proposal_record(proposal_id, prop))
        return false;
    if (prop.status != PROPOSAL_STATUS_ACTIVE)
        return false;

    dao::dao_tally_key_record key_rec;
    if (prop.tally_key_id == crypto::null_hash)
        return false;  // proposal has no per-proposal key bound
    {
        std::vector<uint8_t> kid(prop.tally_key_id.data,
                                 prop.tally_key_id.data + 32);
        if (!m_db.get_dao_tally_key_by_id(kid, key_rec))
            return false;
    }

    // Find the latest share set for this key. If its evidence is
    // populated, the cert will be emitted as v6 and partials will be
    // bound to the reshared VK_i. Otherwise the v5-compat path is used.
    dao::dao_share_set_record share_set;
    dao::dao_share_set_record* event_ss_ptr = nullptr;
    {
        uint64_t latest_sid = 0;
        m_db.for_all_dao_share_sets(
            [&](uint64_t sid, const dao::dao_share_set_record& rec) -> bool {
                if (rec.key_id.size() != 32) return true;
                if (std::memcmp(rec.key_id.data(), key_rec.key_id.data(),
                                32) != 0) return true;
                if (sid > latest_sid) latest_sid = sid;
                return true;
            });
        if (latest_sid != 0 && m_db.get_dao_share_set(latest_sid, share_set))
            event_ss_ptr = &share_set;
    }

    // Effective threshold for the "enough shares?" gate.
    uint32_t eff_threshold = key_rec.threshold;
    if (event_ss_ptr && !event_ss_ptr->contributions.empty())
        eff_threshold = event_ss_ptr->threshold;

    if (threshold < eff_threshold) return false;
    if (shares.size() < eff_threshold) return false;

    dao_proposal_aggregate agg;
    if (!m_db.get_dao_proposal_aggregate(proposal_id, agg))
        return false;
    if (agg.aggregate_E_W.empty() ||
        agg.aggregate_E_S.empty() ||
        agg.aggregate_E_B.empty())
        return false;

    const crypto::hash agg_hash =
        dao::dao_aggregate_ciphertext_hash(agg.aggregate_E_W,
                                           agg.aggregate_E_S,
                                           agg.aggregate_E_B);

    const bool cl_key = !key_rec.cl_modulus.empty();
    dao::dao_partial_set W_set, S_set, B_set;
    for (const auto& kv : shares) {
        if (W_set.member_indices.size() >= eff_threshold) break;
        const auto& s = kv.second;
        if (std::memcmp(s.aggregate_ciphertext_hash.data,
                        agg_hash.data, 32) != 0)
            continue;
        W_set.member_indices.push_back(s.member_index);
        S_set.member_indices.push_back(s.member_index);
        B_set.member_indices.push_back(s.member_index);
        if (cl_key) {
            W_set.cl_partials.push_back(s.cl_partial_W);
            S_set.cl_partials.push_back(s.cl_partial_S);
            B_set.cl_partials.push_back(s.cl_partial_B);
        } else {
            W_set.partials.push_back(s.partial_W);
            W_set.proofs.push_back(s.proof_W);
            S_set.partials.push_back(s.partial_S);
            S_set.proofs.push_back(s.proof_S);
            B_set.partials.push_back(s.partial_B);
            B_set.proofs.push_back(s.proof_B);
        }
    }
    if (W_set.member_indices.size() < eff_threshold)
        return false;

    dao::dao_supply_snapshot snap;
    if (!m_db.get_dao_supply_snapshot(prop.voting_end_height, snap))
        return false;

    dao::dao_tally_certificate cert;
    if (!key_rec.cl_modulus.empty()) {
        // CL key: require the active share set, build and verify on
        // the CL path. Partial sets are populated from the incoming
        // shares below; the Paillier branch fills the older fields.
        if (event_ss_ptr == nullptr) return false;
        if (event_ss_ptr->cl_gammas_serialized.empty()) return false;
    }

    if (cl_key) {
        if (!dao::dao_build_tally_certificate_cl(
                key_rec, *event_ss_ptr, proposal_id, prop.voting_end_height,
                agg.aggregate_E_W, agg.aggregate_E_S, agg.aggregate_E_B,
                W_set, S_set, B_set, cert))
            return false;
        if (!dao::dao_verify_tally_certificate_cl(
                key_rec, *event_ss_ptr, snap,
                m_params.voting_quorum_percent,
                agg.aggregate_E_W, agg.aggregate_E_S, agg.aggregate_E_B, cert))
            return false;
    } else {
        if (!dao::dao_build_tally_certificate(
                key_rec, proposal_id, prop.voting_end_height,
                agg.aggregate_E_W, agg.aggregate_E_S, agg.aggregate_E_B,
                W_set, S_set, B_set, cert, event_ss_ptr))
            return false;
        if (!dao::dao_verify_tally_certificate(
                key_rec, snap, m_params.voting_quorum_percent,
                agg.aggregate_E_W, agg.aggregate_E_S, agg.aggregate_E_B, cert))
            return false;
    }

    // Serialize the certificate and place it in a governance payload.
    std::vector<uint8_t> cert_blob;
    if (!cert.serialize(cert_blob))
        return false;

    governance_payload gp;
    gp.type = governance_object::tally_result;
    gp.data = std::move(cert_blob);

    tx_extra_governance_payload txgp;
    txgp.payload = std::move(gp);

    tx_extra_field extra_field = txgp;
    const std::string extra_blob =
        t_serializable_object_to_blob(extra_field);

    tx_out = transaction{};
    tx_out.version = 2;
    tx_out.unlock_time = 0;
    tx_out.vin.clear();
    tx_out.vout.clear();
    tx_out.extra.assign(extra_blob.begin(), extra_blob.end());
    tx_out.rct_signatures = rct::rctSig{};
    tx_out.rct_signatures.type = rct::RCTTypeNull;

    return true;
}

bool TallyManager::produce_local_share(
    const crypto::hash& proposal_id,
    const dao::dao_tally_key_record& key_rec,
    uint32_t key_record_position,
    dao::dao_v2_tally_share& share_out,
    const dao::dao_share_set_record* event_share_set)
{
    proposal_record prop;
    if (!m_db.get_proposal_record(proposal_id, prop)) return false;

    if (key_record_position < 1) return false;
    if (key_rec.key_id.size() != 32) return false;
    if (key_rec.cl_modulus.empty()) {
        if (key_rec.V_K_i.size() != key_rec.committee_members.size())
            return false;
    }

    // Resolve which share set (and thus which VK_i) this partial will
    // be bound to. When the caller passes a reshared event share set,
    // use it directly: position is in that set, VK_i is that set's.
    uint64_t share_set_id = 0;
    std::vector<uint8_t> proof_vk;
    if (event_share_set != nullptr) {
        share_set_id = event_share_set->share_set_id;
        if (key_record_position < 1 ||
            key_record_position > event_share_set->VK_i.size())
            return false;
        proof_vk = event_share_set->VK_i[key_record_position - 1];
    } else {
        share_set_id = static_cast<uint64_t>(
            dao::share_set_id_for_key_id(key_rec.key_id));
        if (key_record_position < 1 ||
            key_record_position > key_rec.V_K_i.size())
            return false;
        proof_vk = key_rec.V_K_i[key_record_position - 1];
    }
    if (share_set_id == 0) return false;
    std::vector<uint8_t> packed_blob;
    if (!m_db.get_dao_local_share(
            static_cast<uint32_t>(share_set_id),
            key_record_position, packed_blob))
        return false;
    std::vector<uint8_t> sk_blob;
    if (!dao::dao_unpack_local_share(packed_blob, key_rec.key_id, sk_blob)) {
        MERROR("V2 tally: local share does not match key_id");
        return false;
    }
    BIGNUM* sk = bn_from_signed_share(sk_blob);
    if (!sk) return false;

    dao_proposal_aggregate agg;
    if (!m_db.get_dao_proposal_aggregate(proposal_id, agg) ||
        agg.aggregate_E_W.empty() || agg.aggregate_E_S.empty() ||
        agg.aggregate_E_B.empty())
    {
        BN_free(sk);
        return false;
    }

    if (!key_rec.cl_modulus.empty()) {
        // CL produce path. Uses the active share set's Gamma map to
        // restore the local decryption state, then produces one
        // partial per channel on the aggregate ciphertext.
        if (event_share_set == nullptr) { BN_free(sk); return false; }
        dao::dao_cl_proposal_key cl_key;
        if (!dao::dao_cl_load_proposal_key(key_rec.cl_modulus, cl_key))
        { BN_free(sk); return false; }
        if (!dao::dao_cl_check_ballot_modulus(*cl_key.cl))
        { BN_free(sk); return false; }

        BICYCL::CL_Threshold_Static::ParticipantsValueMap<BICYCL::QFI>
            gammas;
        if (!dao::cl_dkg_deserialize_gammas(
                event_share_set->cl_gammas_serialized,
                cl_key.cl->Cl_G().discriminant(), gammas))
        { BN_free(sk); return false; }
        BICYCL::CL_Threshold_Static::ParticipantsSet qualified;
        for (uint32_t q : event_share_set->qualified_ids) qualified.insert(q);

        std::unique_ptr<BICYCL::CL_Threshold_Static> player;
        try {
            player = std::make_unique<BICYCL::CL_Threshold_Static>(
                *cl_key.cl,
                static_cast<unsigned int>(event_share_set->committee_members.size()),
                static_cast<unsigned int>(event_share_set->threshold - 1),
                static_cast<unsigned int>(key_record_position - 1),
                32);
        } catch (...) { BN_free(sk); return false; }

        BICYCL::Mpz share_mpz;
        {
            // sk_blob holds sign||magnitude.
            if (sk_blob.empty()) { BN_free(sk); return false; }
            const bool neg = sk_blob[0] != 0;
            BICYCL::Mpz mag;
            if (sk_blob.size() > 1)
                mag = BICYCL::Mpz(std::vector<uint8_t>(
                    sk_blob.begin() + 1, sk_blob.end()));
            share_mpz = mag;
            if (neg) share_mpz.neg();
        }
        if (!player->restore_decryption_state(
                *cl_key.cl, *cl_key.pk, gammas, qualified, share_mpz))
        { BN_free(sk); return false; }

        BICYCL::CL_HSMqk::CipherText ct_W, ct_S, ct_B;
        if (!dao::dao_cl_ciphertext_from_wire(*cl_key.cl,
                                              agg.aggregate_E_W, ct_W))
        { BN_free(sk); return false; }
        if (!dao::dao_cl_ciphertext_from_wire(*cl_key.cl,
                                              agg.aggregate_E_S, ct_S))
        { BN_free(sk); return false; }
        if (!dao::dao_cl_ciphertext_from_wire(*cl_key.cl,
                                              agg.aggregate_E_B, ct_B))
        { BN_free(sk); return false; }

        BICYCL::RandGen rng;
        {
            std::random_device rd;
            rng.set_seed(BICYCL::Mpz(static_cast<unsigned long>(rd())));
        }

        share_out = dao::dao_v2_tally_share{};
        share_out.version         = dao::dao_v2_tally_share::WIRE_VERSION_CL;
        share_out.proposal_id     = proposal_id;
        share_out.vote_end_height = prop.voting_end_height;
        share_out.tally_key_id    = key_rec.key_id;
        share_out.member_index    = key_record_position;
        share_out.aggregate_ciphertext_hash =
            dao::dao_aggregate_ciphertext_hash(agg.aggregate_E_W,
                                               agg.aggregate_E_S,
                                               agg.aggregate_E_B);

        auto emit = [&](const BICYCL::CL_HSMqk::CipherText& ct,
                        std::vector<uint8_t>& out_wire) -> bool {
            try {
                player->decrypt_partial(*cl_key.cl, rng, ct);
                const auto& pd = player->part_dec();
                const BICYCL::Mpz& u = pd.proof().u();
                const BICYCL::QFI& R1 = pd.proof().R1();
                const BICYCL::QFI& R2 = pd.proof().R2();
                out_wire.clear();
                const BICYCL::QFI& w = pd.w();
                std::vector<uint8_t> w_wire, u_wire, r1_wire, r2_wire;
                if (!dao::cl_dkg_qfi_to_bytes(w_wire, w)) return false;
                if (!dao::cl_dkg_mpz_to_bytes_signed(u_wire, u)) return false;
                if (!dao::cl_dkg_qfi_to_bytes(r1_wire, R1)) return false;
                if (!dao::cl_dkg_qfi_to_bytes(r2_wire, R2)) return false;
                out_wire = w_wire;
                out_wire.insert(out_wire.end(), u_wire.begin(), u_wire.end());
                out_wire.insert(out_wire.end(), r1_wire.begin(), r1_wire.end());
                out_wire.insert(out_wire.end(), r2_wire.begin(), r2_wire.end());
                return true;
            } catch (...) { return false; }
        };

        const bool ok =
            emit(ct_W, share_out.cl_partial_W) &&
            emit(ct_S, share_out.cl_partial_S) &&
            emit(ct_B, share_out.cl_partial_B);
        BN_free(sk);
        return ok;
    }

    PaillierPublicKey pk;
    if (!pk.deserialize_modulus(key_rec.N)) { BN_free(sk); return false; }

    share_out = dao::dao_v2_tally_share{};
    share_out.version         = 1;
    share_out.proposal_id     = proposal_id;
    share_out.vote_end_height = prop.voting_end_height;
    share_out.tally_key_id    = key_rec.key_id;
    share_out.member_index    = key_record_position;
    share_out.aggregate_ciphertext_hash =
        dao::dao_aggregate_ciphertext_hash(agg.aggregate_E_W,
                                           agg.aggregate_E_S,
                                           agg.aggregate_E_B);

    auto do_channel = [&](const std::vector<uint8_t>& c,
                          std::vector<uint8_t>& partial_out,
                          dao_partial_decryption_proof& proof_out) -> bool {
        std::vector<uint8_t> ci;
        if (!dao_threshold_partial_decrypt(pk, c, sk, ci)) return false;
        BIGNUM* r = BN_new();
        if (!dao_dkg_sample_r(pk, r)) { BN_free(r); return false; }
        // proof_vk is the correct VK for whichever share set is active
        // (reshared when event_share_set was provided).
        const bool ok = dao_partial_decryption_prove(
            pk, key_rec.V, proof_vk, key_record_position,
            c, ci, sk, r, proof_out);
        BN_free(r);
        if (!ok) return false;
        partial_out = std::move(ci);
        return true;
    };

    const bool ok =
        do_channel(agg.aggregate_E_W, share_out.partial_W, share_out.proof_W) &&
        do_channel(agg.aggregate_E_S, share_out.partial_S, share_out.proof_S) &&
        do_channel(agg.aggregate_E_B, share_out.partial_B, share_out.proof_B);

    BN_free(sk);
    return ok;
}

} // namespace cryptonote
