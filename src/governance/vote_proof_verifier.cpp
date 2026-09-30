#include "vote_proof_verifier.h"

#include <limits>

#include "governance/dao_dkg.h"

namespace cryptonote {

namespace {

// Frozen V2 DAO ring size. Post-CLSAG consensus value.
constexpr size_t DAO_V2_RING_SIZE = 16;

verification_result fail(const char* why)
{
    return {false, std::string(why)};
}

} // namespace

verification_result VoteProofVerifier::verify(
    const vote_proof_v2& proof,
    BlockchainDB& db,
    const Blockchain& blockchain,
    uint64_t block_height,
    const std::unordered_set<crypto::hash>& block_nullifiers)
{
    (void)blockchain;
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

    // Step 8: ring shape. Ring size is exactly the frozen V2 value;
    // CLSAG response vector matches ring size.
    for (const auto& in : proof.inputs) {
        if (in.key_offsets.empty())
            return fail("step8: empty ring");
        if (in.key_offsets.size() != DAO_V2_RING_SIZE)
            return fail("step8: ring size is not 16");
        if (in.signature.s.size() != in.key_offsets.size())
            return fail("step8: CLSAG response/ring size mismatch");
    }

    // Step 9: every referenced global output exists. Expand offsets
    // (Monero cumulative-relative rule, overflow-checked), then query
    // each global index.
    for (const auto& in : proof.inputs) {
        uint64_t acc = 0;
        for (uint64_t off : in.key_offsets) {
            if (acc > std::numeric_limits<uint64_t>::max() - off)
                return fail("step9: key_offset overflow");
            acc += off;
            try {
                (void)db.get_output_tx_and_index_from_global(acc);
            } catch (...) {
                return fail("step9: output lookup failed");
            }
        }
    }

    // Steps 10-24 not implemented. Returning success here would accept
    // votes that have not been fully verified; the caller treats any
    // non-success as vote-invalid.
    return fail("step10+: not yet implemented");
}

} // namespace cryptonote
