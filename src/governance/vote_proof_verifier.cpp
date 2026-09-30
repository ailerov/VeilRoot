#include "vote_proof_verifier.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <unordered_set>
#include <vector>

#include "governance/dao_clsag.h"
#include "governance/dao_consistency.h"
#include "governance/dao_dkg.h"
#include "governance/dao_paillier.h"
#include "governance/dao_vote_or_proof.h"
#include "ringct/rctOps.h"

namespace cryptonote {

namespace {

verification_result fail(const char* why)
{
    return {false, std::string(why)};
}

} // namespace

verification_result VoteProofVerifier::verify(
    const vote_proof_v2& proof,
    BlockchainDB& db,
    uint64_t block_height,
    const std::unordered_set<crypto::hash>& block_nullifiers)
{
    (void)block_nullifiers;

    // Step 1: strict deserialize is the caller's responsibility; here we
    // enforce the cross-field invariant.
    if (proof.nullifiers.size() != proof.inputs.size())
        return fail("step1: nullifier count != input count");

    // Step 2: version.
    if (proof.version != vote_proof_v2::VERSION)
        return fail("step2: wrong version");

    // Step 3: proposal exists.
    proposal_record prop;
    if (!db.get_proposal_record(proof.proposal_id, prop))
        return fail("step3: proposal not found");

    // Step 4: voting period active at block_height.
    if (prop.status != PROPOSAL_STATUS_ACTIVE)
        return fail("step4: proposal not active");
    if (block_height < prop.submission_height)
        return fail("step4: block before proposal submission");
    if (block_height > prop.voting_end_height)
        return fail("step4: voting period ended");

    // Step 5: vote_height == block height.
    if (proof.vote_height != block_height)
        return fail("step5: vote_height != block_height");

    // Step 6: tally-key epoch matches the proposal; historical record
    // for that epoch must exist.
    if (proof.tally_key_epoch != prop.tally_key_epoch)
        return fail("step6: tally_key_epoch mismatch");
    if (proof.tally_key_epoch > std::numeric_limits<uint32_t>::max())
        return fail("step6: tally_key_epoch out of range");
    dao::dao_tally_key_record key_rec;
    if (!db.get_dao_tally_key(static_cast<uint32_t>(proof.tally_key_epoch),
                              key_rec))
        return fail("step6: tally key not found");

    // Step 7: no invented DAO-specific numeric limit. Non-empty and
    // matching the nullifier count (step 1). Strict deserialization
    // bounds and the transaction size limit remain authoritative.
    if (proof.inputs.empty())
        return fail("step7: no inputs");

    // Step 8: variable-ring structural checks. No DAO ring-size constant
    // is frozen by the spec; the CLSAG context already enforces shape
    // consistency, and the verifier enforces the wire-side invariants.
    for (const auto& in : proof.inputs) {
        const size_t n = in.key_offsets.size();
        if (n == 0)
            return fail("step8: empty ring");
        if (in.signature.s.size() != n)
            return fail("step8: CLSAG response/ring size mismatch");

        // Expand relative offsets to absolute global indices; overflow-safe.
        std::vector<uint64_t> abs;
        abs.reserve(n);
        uint64_t acc = 0;
        for (uint64_t off : in.key_offsets) {
            if (acc > std::numeric_limits<uint64_t>::max() - off)
                return fail("step8: key_offset overflow");
            acc += off;
            abs.push_back(acc);
        }

        // Duplicate absolute indices within the ring are rejected.
        std::vector<uint64_t> sorted_abs = abs;
        std::sort(sorted_abs.begin(), sorted_abs.end());
        if (std::adjacent_find(sorted_abs.begin(), sorted_abs.end())
                != sorted_abs.end())
            return fail("step8: duplicate absolute index within ring");
    }

    // Step 9: every referenced global output exists and resolves to a
    // canonical RingCT output record.
    for (const auto& in : proof.inputs) {
        uint64_t acc = 0;
        for (uint64_t off : in.key_offsets) {
            acc += off; // overflow already checked in step 8
            try {
                (void)db.get_output_key_from_global(acc);
            } catch (...) {
                return fail("step9: output lookup failed");
            }
        }
    }

    // Step 13: nullifiers non-zero and unique within this vote.
    {
        std::unordered_set<crypto::hash> seen;
        for (const auto& nf : proof.nullifiers) {
            bool all_zero = true;
            for (size_t k = 0; k < sizeof(nf.data); ++k) {
                if (nf.data[k] != 0) { all_zero = false; break; }
            }
            if (all_zero)
                return fail("step13: zero nullifier");
            if (!seen.insert(nf).second)
                return fail("step13: duplicate nullifier within vote");
        }
    }

    // Step 14: recompute age factors from canonical chain heights and
    // build the per-input CLSAG context. Amounts are never taken from
    // the wire.
    std::vector<dao_clsag_context> clsag_ctxs(proof.inputs.size());
    for (size_t i = 0; i < proof.inputs.size(); ++i) {
        const vote_input_v2& in = proof.inputs[i];
        dao_clsag_context& rc = clsag_ctxs[i];

        rc.proposal_id                = proof.proposal_id;
        rc.proposal_submission_height = prop.submission_height;
        rc.vote_height                = proof.vote_height;
        rc.tally_key_epoch            = proof.tally_key_epoch;
        rc.V                          = in.weight_commitment;

        uint64_t acc = 0;
        for (uint64_t off : in.key_offsets) {
            acc += off;

            output_data_t od;
            try {
                od = db.get_output_key_from_global(acc);
            } catch (...) {
                return fail("step14: output lookup failed");
            }
            if (proof.vote_height < od.height)
                return fail("step14: output height exceeds vote height");

            rct::key P;
            std::memcpy(P.bytes, od.pubkey.data, sizeof(P.bytes));
            rc.P.push_back(P);
            rc.C.push_back(od.commitment);
            rc.output_indices.push_back(acc);
            rc.output_heights.push_back(od.height);

            uint64_t raw_age_days = (proof.vote_height - od.height) / 720;
            if (raw_age_days > 7300) raw_age_days = 7300;
            uint64_t f = 0;
            uint64_t n = raw_age_days + 1;
            while (n > 1) { n >>= 1; ++f; }
            if (f > 255)
                return fail("step14: age factor overflow");
            rc.age_factors.push_back(static_cast<uint8_t>(f));
        }
    }

    // Step 15: weighted DAO CLSAG per input.
    for (size_t i = 0; i < proof.inputs.size(); ++i) {
        if (!dao_clsag_verify(clsag_ctxs[i], proof.inputs[i].signature))
            return fail("step15: CLSAG verification failed");
    }

    // Step 16: C_W == sum of per-input V_i.
    {
        rct::key acc = rct::identity();
        for (const auto& in : proof.inputs) {
            rct::key tmp;
            rct::addKeys(tmp, acc, in.weight_commitment);
            acc = tmp;
        }
        if (!(acc == proof.C_W))
            return fail("step16: C_W does not match sum of V_i");
    }

    // Step 17: C_W and C_S are valid curve points in the main subgroup.
    if (!rct::isInMainSubgroup(proof.C_W))
        return fail("step17: C_W is not a valid curve point");
    if (!rct::isInMainSubgroup(proof.C_S))
        return fail("step17: C_S is not a valid curve point");

    // Step 18: E_W and E_S are canonical Paillier ciphertexts in Z*_{N^2}.
    BIGNUM* N = BN_bin2bn(key_rec.N.data(),
                          static_cast<int>(key_rec.N.size()), nullptr);
    if (!N)
        return fail("step18: cannot load N");
    auto bail_N = [&](const char* why) {
        BN_free(N);
        return fail(why);
    };

    if (proof.E_W.data.size() != dao::PAILLIER_CT_BYTES ||
        proof.E_S.data.size() != dao::PAILLIER_CT_BYTES)
        return bail_N("step18: ciphertext size");

    auto valid_ct = [&](const std::array<uint8_t, 512>& raw) -> bool {
        std::vector<uint8_t> v(raw.begin(), raw.end());
        BIGNUM* c = BN_bin2bn(v.data(), static_cast<int>(v.size()), nullptr);
        if (!c) return false;
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* N2 = BN_new(); BN_sqr(N2, N, ctx);
        bool ok = (BN_cmp(c, N2) < 0) && !BN_is_zero(c);
        // gcd(c, N2) == 1
        BIGNUM* g = BN_new();
        BN_gcd(g, c, N2, ctx);
        ok = ok && BN_is_one(g);
        BN_free(g); BN_free(N2); BN_CTX_free(ctx); BN_free(c);
        return ok;
    };
    if (!valid_ct(proof.E_W.data)) return bail_N("step18: E_W invalid");
    if (!valid_ct(proof.E_S.data)) return bail_N("step18: E_S invalid");

    // Build the consistency context. The transcript is exactly the
    // 32-byte digest produced by dao_vote_input_transcript.
    dao::dao_vote_transcript_input ti;
    ti.version                    = proof.version;
    ti.proposal_id                = proof.proposal_id;
    ti.proposal_submission_height = prop.submission_height;
    ti.vote_height                = proof.vote_height;
    ti.tally_key_epoch            = proof.tally_key_epoch;
    std::memcpy(ti.tally_key_id.data, key_rec.key_id.data(), 32);

    for (size_t i = 0; i < proof.inputs.size(); ++i) {
        const vote_input_v2& in  = proof.inputs[i];
        const dao_clsag_context& rc = clsag_ctxs[i];

        ti.key_offsets.push_back(in.key_offsets);
        ti.absolute_indices.push_back(rc.output_indices);
        ti.P.push_back(rc.P);
        ti.C.push_back(rc.C);
        ti.output_heights.push_back(rc.output_heights);
        ti.age_factors.push_back(rc.age_factors);
        ti.nullifiers.push_back(proof.nullifiers[i]);
    }
    ti.C_W = proof.C_W;
    ti.C_S = proof.C_S;
    ti.E_W.assign(proof.E_W.data.begin(), proof.E_W.data.end());
    ti.E_S.assign(proof.E_S.data.begin(), proof.E_S.data.end());

    std::vector<uint8_t> transcript_digest = dao::dao_vote_input_transcript(ti);
    if (transcript_digest.size() != 32)
        return bail_N("step22: transcript could not be computed");

    dao::dao_consistency_context cctx_w;
    cctx_w.domain                = "C_W-Enc(W)";
    cctx_w.version               = proof.version;
    cctx_w.proposal_id           = proof.proposal_id;
    cctx_w.vote_height           = proof.vote_height;
    cctx_w.tally_key_epoch       = proof.tally_key_epoch;
    cctx_w.vote_input_transcript = transcript_digest;

    dao::dao_consistency_context cctx_s = cctx_w;
    cctx_s.domain = "C_S-Enc(S)";

    std::vector<uint8_t> E_W_vec(proof.E_W.data.begin(), proof.E_W.data.end());
    std::vector<uint8_t> E_S_vec(proof.E_S.data.begin(), proof.E_S.data.end());

    // Step 19: proof_W.
    if (!dao::dao_consistency_verify(cctx_w, N, E_W_vec, proof.C_W,
                                     proof.proof_W))
        return bail_N("step19: consistency proof W failed");

    // Step 20: proof_S.
    if (!dao::dao_consistency_verify(cctx_s, N, E_S_vec, proof.C_S,
                                     proof.proof_S))
        return bail_N("step20: consistency proof S failed");

    // Step 21: hidden-direction OR proof. Context binds the transcript
    // digest and the pair of consistency proofs via extra_binding.
    dao_or_context octx;
    octx.version     = proof.version;
    octx.proposal_id = proof.proposal_id;
    octx.vote_height = proof.vote_height;
    octx.nullifiers.reserve(proof.nullifiers.size());
    for (const auto& nf : proof.nullifiers)
        octx.nullifiers.push_back(rct::key{}); // see below
    // dao_or_context uses std::vector<rct::key> nullifiers; convert.
    octx.nullifiers.clear();
    for (const auto& nf : proof.nullifiers) {
        rct::key k{};
        std::memcpy(k.bytes, nf.data, 32);
        octx.nullifiers.push_back(k);
    }
    octx.key_offsets.clear();
    for (const auto& in : proof.inputs)
        for (uint64_t off : in.key_offsets)
            octx.key_offsets.push_back(off);
    octx.extra_binding = dao::dao_extra_binding(E_W_vec, E_S_vec,
                                                proof.proof_W, proof.proof_S);
    octx.C_W = proof.C_W;
    octx.C_S = proof.C_S;

    if (!dao_or_verify(octx, proof.direction_proof))
        return bail_N("step21: direction OR proof failed");

    // Step 22: transcript hash equals proof.transcript_hash.
    {
        crypto::hash want{};
        std::memcpy(want.data, transcript_digest.data(), 32);
        if (!(want == proof.transcript_hash))
            return bail_N("step22: transcript hash mismatch");
    }

    BN_free(N);

    // Step 23+ not implemented (nullifier persistence and same-block
    // set live in the caller). Read-only verify() succeeds here.
    return fail("step23+: not yet implemented");
}

} // namespace cryptonote
