// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_reshare_pipeline.h"

#include <cstring>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/sha.h>

namespace cryptonote {
namespace dao {

namespace {

struct CtxGuard {
    BN_CTX* ctx;
    CtxGuard() : ctx(BN_CTX_new()) {}
    ~CtxGuard() { if (ctx) BN_CTX_free(ctx); }
    CtxGuard(const CtxGuard&) = delete;
    CtxGuard& operator=(const CtxGuard&) = delete;
    bool ok() const { return ctx != nullptr; }
};

bool modexp_signed(const BIGNUM* base, const BIGNUM* exp,
                   const BIGNUM* mod, BIGNUM* out, BN_CTX* ctx)
{
    if (!BN_is_negative(exp))
        return BN_mod_exp(out, base, exp, mod, ctx) == 1;
    BIGNUM* inv = BN_mod_inverse(nullptr, base, mod, ctx);
    if (!inv) return false;
    BIGNUM* pos = BN_dup(exp);
    if (!pos) { BN_free(inv); return false; }
    BN_set_negative(pos, 0);
    const bool ok = BN_mod_exp(out, inv, pos, mod, ctx) == 1;
    BN_free(inv); BN_free(pos);
    return ok;
}

} // namespace

bool dao_reshare_make_contribution(
    const PaillierPublicKey& pk,
    const dao_vss_group& grp,
    const std::vector<uint8_t>& V_bytes,
    const BIGNUM* s_i,
    const BIGNUM* mu_i,
    const BIGNUM* delta,
    uint32_t t_new,
    const std::vector<uint32_t>& new_indices,
    dao_reshare_link_context link_ctx,
    dao_reshare_contribution& out)
{
    if (!pk.valid() || !grp.valid() || !s_i || !mu_i || !delta) return false;
    if (new_indices.empty()) return false;

    out = dao_reshare_contribution{};
    out.contributor_index = link_ctx.original_index;
    out.contributor_pubkey = link_ctx.contributor_pubkey;

    dao_reshare_vss_commitments commits;
    dao_reshare_vss_coeff_proofs cps;
    std::vector<dao_reshare_vss_share> shares;
    dao_reshare_link_proof lp;

    if (!dao_reshare_vss_deal(pk, grp, V_bytes, s_i, mu_i, delta,
                              t_new, new_indices, link_ctx, lp,
                              commits, cps, shares))
        return false;

    // deal fills C_i0 inside its own copy of link_ctx. Store the
    // post-deal value so verifiers see the same C_i0 that C_0 carries.
    link_ctx.C_i0 = commits.C_0;
    out.link_ctx = std::move(link_ctx);
    out.link_proof = std::move(lp);
    out.commits = std::move(commits);
    out.coeff_proofs = std::move(cps);
    out.shares = std::move(shares);
    return true;
}

bool dao_reshare_combine(
    const PaillierPublicKey& pk,
    const dao_vss_group& grp,
    const std::vector<uint8_t>& V_bytes,
    const std::vector<dao_reshare_contribution>& contributions,
    const std::vector<uint32_t>& new_indices,
    uint32_t threshold,
    const BIGNUM* delta,
    std::vector<dao_reshare_new_share>& new_shares_out)
{
    if (!pk.valid() || !grp.valid() || !delta) return false;
    if (contributions.size() < threshold) return false;
    if (threshold == 0) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    // Verify each contribution is internally consistent. This
    // reconstructs what VSS verify does per recipient without needing
    // one recipient at a time: it runs the coeff-level proofs against
    // every contribution and checks each delivered evaluation.
    std::vector<dao_reshare_vss_commitments> all_commits;
    all_commits.reserve(contributions.size());
    for (const auto& c : contributions) {
        if (c.shares.size() != new_indices.size()) return false;
        all_commits.push_back(c.commits);
    }

    // Sum the per-recipient evaluations across contributions. Each
    // evaluation is V-verified against its contributor's commitments.
    new_shares_out.assign(new_indices.size(), {});
    for (size_t k = 0; k < new_indices.size(); ++k) {
        BIGNUM* s_prime = BN_new();
        if (!s_prime) return false;
        BN_zero(s_prime);

        for (size_t c = 0; c < contributions.size(); ++c) {
            const auto& contrib = contributions[c];
            if (contrib.shares[k].j != new_indices[k]) {
                BN_free(s_prime);
                return false;
            }
            // The contributor's VSS verify path checks all coefficient
            // proofs and the link proof against C_i0, and checks that
            // the delivered q_i(j) matches the commitments.
            if (!dao_reshare_vss_verify(pk, grp, V_bytes,
                                         contrib.link_ctx,
                                         contrib.link_proof,
                                         contrib.commits,
                                         contrib.coeff_proofs,
                                         new_indices[k],
                                         contrib.shares[k].q_i_j)) {
                BN_free(s_prime);
                return false;
            }
            BIGNUM* q = BN_new();
            if (!q || !dao_reshare_deserialize_signed(
                          contrib.shares[k].q_i_j, q)) {
                BN_free(q); BN_free(s_prime);
                return false;
            }
            BN_add(s_prime, s_prime, q);
            BN_free(q);
        }

        // s'_j = (sum_i q_i(j)) / Delta
        BIGNUM* rem = BN_new();
        BIGNUM* s_j = BN_new();
        if (!rem || !s_j ||
            !BN_div(s_j, rem, s_prime, delta, g.ctx) ||
            !BN_is_zero(rem)) {
            BN_free(rem); BN_free(s_j); BN_free(s_prime);
            return false;
        }
        BN_free(rem);
        BN_free(s_prime);

        // Compute VK_j = product_i (C_i0 * prod_k C_ik^(j^k))
        std::vector<uint8_t> VK_j;
        if (!dao_reshare_vss_compute_vk(pk, V_bytes, all_commits,
                                         new_indices[k], VK_j)) {
            BN_free(s_j);
            return false;
        }

        // Cross-check: V^s'_j * Delta must equal VK_j.
        {
            BIGNUM* V = BN_bin2bn(V_bytes.data(),
                                   (int)V_bytes.size(), nullptr);
            BIGNUM* exp = BN_new();
            BN_mul(exp, s_j, delta, g.ctx);
            BIGNUM* VK_calc = BN_new();
            if (!V || !exp || !VK_calc ||
                !modexp_signed(V, exp, pk.N2(), VK_calc, g.ctx)) {
                BN_free(V); BN_free(exp); BN_free(VK_calc); BN_free(s_j);
                return false;
            }
            std::vector<uint8_t> VK_calc_bytes(PAILLIER_CT_BYTES, 0);
            BN_bn2binpad(VK_calc, VK_calc_bytes.data(), PAILLIER_CT_BYTES);
            BN_free(V); BN_free(exp); BN_free(VK_calc);
            if (VK_calc_bytes != VK_j) {
                BN_free(s_j);
                return false;
            }
        }

        dao_reshare_new_share ns;
        ns.j = new_indices[k];
        dao_reshare_serialize_signed(s_j, ns.share_signed);
        ns.VK_j = std::move(VK_j);
        new_shares_out[k] = std::move(ns);
        BN_free(s_j);
    }

    return true;
}

bool dao_reshare_build_share_set(
    uint64_t share_set_id,
    uint64_t height,
    const std::vector<uint8_t>& key_id,
    const std::vector<crypto::public_key>& new_members,
    const std::vector<dao_reshare_new_share>& new_shares,
    uint32_t threshold,
    dao_share_set_record& record_out)
{
    if (key_id.size() != 32) return false;
    if (new_members.size() != new_shares.size()) return false;
    if (new_members.empty()) return false;
    if (threshold == 0 || threshold > new_members.size()) return false;

    record_out = dao_share_set_record{};
    record_out.version      = 1;
    record_out.share_set_id = share_set_id;
    record_out.height       = height;
    record_out.threshold    = threshold;
    record_out.key_id       = key_id;

    record_out.committee_members.reserve(new_members.size());
    record_out.VK_i.reserve(new_shares.size());
    for (size_t i = 0; i < new_members.size(); ++i) {
        std::vector<uint8_t> m(32, 0);
        std::memcpy(m.data(), new_members[i].data, 32);
        record_out.committee_members.push_back(std::move(m));
        record_out.VK_i.push_back(new_shares[i].VK_j);
    }

    // committee_id_hash = SHA256(domain || share_set_id || members)
    std::vector<uint8_t> buf;
    const char* dom = "VeilRoot-DAO-SHARE-SET-V1";
    buf.insert(buf.end(), dom, dom + std::strlen(dom));
    for (int i = 0; i < 8; ++i)
        buf.push_back((share_set_id >> (8*(7-i))) & 0xff);
    for (const auto& m : record_out.committee_members)
        buf.insert(buf.end(), m.begin(), m.end());
    record_out.committee_id_hash.assign(32, 0);
    SHA256(buf.data(), buf.size(), record_out.committee_id_hash.data());

    return true;
}

} // namespace dao
} // namespace cryptonote
