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
#include "governance/dao_tally_session_cycle.h"
#include "governance/dao_threshold.h"
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

bool TallyManager::try_finalize(
    const crypto::hash& proposal_id,
    const std::map<crypto::public_key, dao::dao_v2_tally_share>& shares,
    uint64_t current_height)
{
    // Already finalized.
    {
        dao::dao_v2_outcome_record existing;
        if (m_db.get_dao_v2_outcome(proposal_id, existing)) {
            return true;
        }
    }

    proposal_record prop;
    if (!m_db.get_proposal_record(proposal_id, prop)) {
    }

    // Temporary tally session: names the committee that must have
    // produced these shares. Bound to the proposal.
    dao::dao_tally_session session;
    if (!m_db.get_dao_tally_session(proposal_id, session)) return false;

    // Stable Paillier key epoch, unchanged from bootstrap.
    dao::dao_tally_key_record key_rec;
    if (!m_db.get_dao_tally_key(static_cast<uint32_t>(prop.tally_key_epoch),
                                key_rec))
        return false;

    if (shares.size() < session.threshold) return false;

    dao_proposal_aggregate agg;
    if (!m_db.get_dao_proposal_aggregate(proposal_id, agg)) return false;
    if (agg.aggregate_E_W.empty() || agg.aggregate_E_S.empty() ||
        agg.aggregate_E_B.empty())
        return false;

    const crypto::hash agg_hash =
        dao::dao_aggregate_ciphertext_hash(agg.aggregate_E_W,
                                           agg.aggregate_E_S,
                                           agg.aggregate_E_B);

    // Build partial sets from the in-memory store, taking the first
    // `threshold` distinct members. Every entry was validated at
    // receive time (identity, epoch, aggregate binding, ZK proof).
    dao::dao_partial_set W_set, S_set, B_set;
    for (const auto& kv : shares) {
        if (W_set.member_indices.size() >= session.threshold) break;
        const auto& s = kv.second;
        if (std::memcmp(s.aggregate_ciphertext_hash.data,
                        agg_hash.data, 32) != 0)
            continue;
        W_set.member_indices.push_back(s.member_index);
        W_set.partials.push_back(s.partial_W);
        W_set.proofs.push_back(s.proof_W);
        S_set.member_indices.push_back(s.member_index);
        S_set.partials.push_back(s.partial_S);
        S_set.proofs.push_back(s.proof_S);
        B_set.member_indices.push_back(s.member_index);
        B_set.partials.push_back(s.partial_B);
        B_set.proofs.push_back(s.proof_B);
    }
    if (W_set.member_indices.size() < session.threshold) return false;

    // Historical supply at the voting-end height.
    dao::dao_supply_snapshot snap;
    if (!m_db.get_dao_supply_snapshot(prop.voting_end_height, snap)) {
        MERROR("V2 tally: supply snapshot missing for height "
               << prop.voting_end_height);
        return false;
    }

    // Build a synthetic key record bound to the SESSION committee.
    // The public Paillier material (N, G, theta, delta, V) is
    // bootstrap; the committee material (threshold, t, V_K_i,
    // committee_size) is the temporary session. This is what the
    // frozen certificate builder consumes; its mathematics is
    // unchanged.
    // The certificate builder consumes a key record. The correct
    // threshold and t here are the BOOTSTRAP DKG values, because the
    // shares being combined are shares of the bootstrap polynomial.
    // Overriding with session.threshold would mis-parameterise the
    // combine whenever the committee is smaller than the bootstrap
    // shareholder set.
    dao::dao_tally_key_record cert_key_rec = key_rec;
    // cert_key_rec.threshold and cert_key_rec.t already hold the
    // bootstrap values. Leave them.

    // Recombine through the existing certificate pipeline, which also
    // re-verifies each partial's ZK proof before use.
    dao::dao_tally_certificate cert;
    if (!dao::dao_build_tally_certificate(
            cert_key_rec, proposal_id, prop.voting_end_height,
            agg.aggregate_E_W, agg.aggregate_E_S, agg.aggregate_E_B,
            W_set, S_set, B_set, cert))
    {
        MERROR("V2 tally: certificate build failed for " << proposal_id);
        return false;
    }
    if (!dao::dao_verify_tally_certificate(
            cert_key_rec, snap, m_params.voting_quorum_percent,
            agg.aggregate_E_W, agg.aggregate_E_S, agg.aggregate_E_B, cert))
    {
        MERROR("V2 tally: certificate verification failed for " << proposal_id);
        return false;
    }

    // Write the outcome record and update the proposal.
    dao::dao_v2_outcome_record out_rec;
    out_rec.proposal_id               = proposal_id;
    out_rec.vote_end_height           = prop.voting_end_height;
    out_rec.tally_key_epoch           = prop.tally_key_epoch;
    out_rec.aggregate_ciphertext_hash = agg_hash;
    out_rec.yes_weight                = cert.YES_weight;
    out_rec.no_weight                 = cert.NO_weight;
    out_rec.participation_coins       = cert.B_total;
    out_rec.quorum_threshold          = cert.quorum_threshold;
    out_rec.quorum_met                = cert.quorum_met;
    out_rec.majority_met              = cert.majority_met;
    out_rec.passed                    = cert.passed;

    try {
        m_db.add_dao_v2_outcome(out_rec);

        prop.status = cert.passed ? PROPOSAL_STATUS_PASSED
                                  : PROPOSAL_STATUS_REJECTED;
        prop.status_height = current_height;
        m_db.add_proposal_record(proposal_id, prop);

        if (cert.passed) {
            // Same execution-delay fallback as the V1 lifecycle manager.
            const uint64_t delay = 720;
            m_db.add_pending_execution(prop.voting_end_height + delay,
                                       proposal_id);
        }
    } catch (const std::exception& e) {
        MERROR("V2 tally: consensus write failed: " << e.what());
        return false;
    }

    MINFO("V2 tally finalized for " << proposal_id
          << " passed=" << cert.passed
          << " yes=" << cert.YES_weight
          << " no=" << cert.NO_weight
          << " B=" << cert.B_total);
    return true;
}

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
    if (!m_db.get_dao_tally_key(
            static_cast<uint32_t>(prop.tally_key_epoch), key_rec))
        return false;

    if (threshold < key_rec.threshold)
        return false;
    if (shares.size() < key_rec.threshold)
        return false;

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

    dao::dao_partial_set W_set, S_set, B_set;
    for (const auto& kv : shares) {
        if (W_set.member_indices.size() >= key_rec.threshold) break;
        const auto& s = kv.second;
        if (std::memcmp(s.aggregate_ciphertext_hash.data,
                        agg_hash.data, 32) != 0)
            continue;
        W_set.member_indices.push_back(s.member_index);
        W_set.partials.push_back(s.partial_W);
        W_set.proofs.push_back(s.proof_W);
        S_set.member_indices.push_back(s.member_index);
        S_set.partials.push_back(s.partial_S);
        S_set.proofs.push_back(s.proof_S);
        B_set.member_indices.push_back(s.member_index);
        B_set.partials.push_back(s.partial_B);
        B_set.proofs.push_back(s.proof_B);
    }
    if (W_set.member_indices.size() < key_rec.threshold)
        return false;

    dao::dao_supply_snapshot snap;
    if (!m_db.get_dao_supply_snapshot(prop.voting_end_height, snap))
        return false;

    dao::dao_tally_certificate cert;
    if (!dao::dao_build_tally_certificate(
            key_rec, proposal_id, prop.voting_end_height,
            agg.aggregate_E_W, agg.aggregate_E_S, agg.aggregate_E_B,
            W_set, S_set, B_set, cert))
        return false;
    if (!dao::dao_verify_tally_certificate(
            key_rec, snap, m_params.voting_quorum_percent,
            agg.aggregate_E_W, agg.aggregate_E_S, agg.aggregate_E_B, cert))
        return false;

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
    uint32_t global_member_index,
    dao::dao_v2_tally_share& share_out)
{
    proposal_record prop;
    if (!m_db.get_proposal_record(proposal_id, prop)) return false;

    if (global_member_index < 1 ||
        global_member_index > key_rec.committee_size)
        return false;

    // Local bootstrap DKG share for this member's global index. The
    // same share is used for every tally this node is selected for;
    // there is no per-proposal share transfer.
    std::vector<uint8_t> sk_blob;
    if (!m_db.get_dao_local_share(
            static_cast<uint32_t>(prop.tally_key_epoch),
            global_member_index, sk_blob))
        return false;
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

    PaillierPublicKey pk;
    if (!pk.deserialize_modulus(key_rec.N)) { BN_free(sk); return false; }

    share_out = dao::dao_v2_tally_share{};
    share_out.version         = 1;
    share_out.proposal_id     = proposal_id;
    share_out.vote_end_height = prop.voting_end_height;
    share_out.tally_key_epoch = prop.tally_key_epoch;
    share_out.share_epoch     = prop.tally_key_epoch;
    share_out.member_index    = global_member_index;
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
        // Bind the proof to the bootstrap key record's V_K_i for the
        // member's global index. The selected committee is a subset of
        // the bootstrap shareholder set, so the correct verification
        // key is the one recorded in the key epoch for that index.
        const std::vector<uint8_t>& vk =
            key_rec.V_K_i[global_member_index - 1];
        const bool ok = dao_partial_decryption_prove(
            pk, key_rec.V, vk, global_member_index,
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
