// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "dao_reshare_pipeline.h"

#include <cstring>
#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>

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

bool dao_reshare_combine_one(
    const PaillierPublicKey& pk,
    const dao_vss_group& grp,
    const std::vector<uint8_t>& V_bytes,
    const std::vector<dao_reshare_contribution>& contributions,
    const std::vector<uint32_t>& new_indices,
    uint32_t recipient_position,
    uint32_t threshold,
    const BIGNUM* delta,
    dao_reshare_new_share& new_share_out)
{
    if (!pk.valid() || !grp.valid() || !delta) return false;
    if (threshold == 0) return false;
    if (contributions.size() < threshold) return false;
    if (recipient_position >= new_indices.size()) return false;

    CtxGuard g;
    if (!g.ok()) return false;

    const uint32_t target_index = new_indices[recipient_position];

    std::vector<dao_reshare_vss_commitments> all_commits;
    all_commits.reserve(contributions.size());

    BIGNUM* s_prime = BN_new();
    if (!s_prime) return false;
    BN_zero(s_prime);

    size_t used = 0;
    for (const auto& c : contributions) {
        if (used >= threshold) break;
        if (c.shares.size() != 1) { BN_free(s_prime); return false; }
        const auto& sh = c.shares[0];
        if (sh.j != target_index) { BN_free(s_prime); return false; }

        if (!dao_reshare_vss_verify(pk, grp, V_bytes,
                                     c.link_ctx, c.link_proof,
                                     c.commits, c.coeff_proofs,
                                     sh.j, sh.q_i_j)) {
            BN_free(s_prime);
            return false;
        }
        BIGNUM* q = BN_new();
        if (!q || !dao_reshare_deserialize_signed(sh.q_i_j, q)) {
            BN_free(q); BN_free(s_prime);
            return false;
        }
        BN_add(s_prime, s_prime, q);
        BN_free(q);
        all_commits.push_back(c.commits);
        ++used;
    }
    if (used < threshold) { BN_free(s_prime); return false; }

    BIGNUM* rem = BN_new();
    BIGNUM* s_j = BN_new();
    if (!rem || !s_j ||
        !BN_div(s_j, rem, s_prime, delta, g.ctx) ||
        !BN_is_zero(rem)) {
        BN_free(rem); BN_free(s_j); BN_free(s_prime);
        return false;
    }
    BN_free(rem); BN_free(s_prime);

    std::vector<uint8_t> VK_j;
    if (!dao_reshare_vss_compute_vk(pk, V_bytes, all_commits,
                                     target_index, VK_j)) {
        BN_free(s_j);
        return false;
    }
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

    new_share_out = dao_reshare_new_share{};
    new_share_out.j = target_index;
    dao_reshare_serialize_signed(s_j, new_share_out.share_signed);
    new_share_out.VK_j = std::move(VK_j);
    BN_free(s_j);
    return true;
}

bool dao_reshare_compute_all_vks(
    const PaillierPublicKey& pk,
    const std::vector<uint8_t>& V_bytes,
    const std::vector<dao_reshare_contribution>& contributions,
    const std::vector<uint32_t>& new_indices,
    std::vector<std::vector<uint8_t>>& vks_out)
{
    if (!pk.valid() || contributions.empty()) return false;

    std::vector<dao_reshare_vss_commitments> all_commits;
    all_commits.reserve(contributions.size());
    for (const auto& c : contributions) all_commits.push_back(c.commits);

    vks_out.assign(new_indices.size(), {});
    for (size_t pos = 0; pos < new_indices.size(); ++pos) {
        if (!dao_reshare_vss_compute_vk(pk, V_bytes, all_commits,
                                         new_indices[pos], vks_out[pos]))
            return false;
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


namespace {

void rp_push_u32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back((x >> (8 * i)) & 0xff);
}
void rp_push_u64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back((x >> (8 * i)) & 0xff);
}
void rp_push_bytes(std::vector<uint8_t>& v, const std::vector<uint8_t>& b)
{
    rp_push_u32(v, static_cast<uint32_t>(b.size()));
    v.insert(v.end(), b.begin(), b.end());
}
bool rp_pull_u32(const std::vector<uint8_t>& v, size_t& off, uint32_t& out)
{
    if (off + 4 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 4; ++i) out |= uint32_t(v[off++]) << (8 * i);
    return true;
}
bool rp_pull_u64(const std::vector<uint8_t>& v, size_t& off, uint64_t& out)
{
    if (off + 8 > v.size()) return false;
    out = 0;
    for (int i = 0; i < 8; ++i) out |= uint64_t(v[off++]) << (8 * i);
    return true;
}
bool rp_pull_bytes(const std::vector<uint8_t>& v, size_t& off,
                   std::vector<uint8_t>& out)
{
    uint32_t n = 0;
    if (!rp_pull_u32(v, off, n)) return false;
    if (off + n > v.size()) return false;
    out.assign(v.begin() + off, v.begin() + off + n);
    off += n;
    return true;
}

} // namespace

bool dao_reshare_msg::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    rp_push_u32(out, version);
    rp_push_u64(out, old_share_set_id);
    rp_push_u64(out, new_share_set_id);
    rp_push_u32(out, sender_index);
    out.push_back(type);
    rp_push_bytes(out, public_blob);
    rp_push_u32(out, static_cast<uint32_t>(recipient_indices.size()));
    for (uint32_t i : recipient_indices) rp_push_u32(out, i);
    rp_push_u32(out, static_cast<uint32_t>(recipient_payloads.size()));
    for (const auto& p : recipient_payloads) rp_push_bytes(out, p);
    rp_push_bytes(out, record_blob);
    return true;
}

bool dao_reshare_msg::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    if (!rp_pull_u32(in, off, version)) return false;
    if (version != 1) return false;
    if (!rp_pull_u64(in, off, old_share_set_id)) return false;
    if (!rp_pull_u64(in, off, new_share_set_id)) return false;
    if (!rp_pull_u32(in, off, sender_index)) return false;
    if (off >= in.size()) return false;
    type = in[off++];
    if (type != 0 && type != 1) return false;
    if (!rp_pull_bytes(in, off, public_blob)) return false;
    uint32_t nr = 0;
    if (!rp_pull_u32(in, off, nr)) return false;
    if (nr > 1024) return false;
    recipient_indices.assign(nr, 0);
    for (uint32_t i = 0; i < nr; ++i)
        if (!rp_pull_u32(in, off, recipient_indices[i])) return false;
    uint32_t np = 0;
    if (!rp_pull_u32(in, off, np)) return false;
    if (np != nr) return false;
    recipient_payloads.assign(np, {});
    for (uint32_t i = 0; i < np; ++i)
        if (!rp_pull_bytes(in, off, recipient_payloads[i])) return false;
    if (!rp_pull_bytes(in, off, record_blob)) return false;
    return off == in.size();
}

bool dao_reshare_share_bundle::serialize(std::vector<uint8_t>& out) const
{
    out.clear();
    rp_push_u64(out, old_share_set_id);
    rp_push_u32(out, sender_index);
    rp_push_bytes(out, share_bytes);
    return true;
}

bool dao_reshare_share_bundle::deserialize(const std::vector<uint8_t>& in)
{
    size_t off = 0;
    if (!rp_pull_u64(in, off, old_share_set_id)) return false;
    if (!rp_pull_u32(in, off, sender_index)) return false;
    if (!rp_pull_bytes(in, off, share_bytes)) return false;
    return off == in.size();
}

bool dao_reshare_serialize_public(
    const dao_reshare_contribution& c, std::vector<uint8_t>& out)
{
    out.clear();
    rp_push_u32(out, c.contributor_index);
    rp_push_bytes(out, c.contributor_pubkey);

    const auto& ctx = c.link_ctx;
    out.insert(out.end(), ctx.genesis_block_hash.data,
               ctx.genesis_block_hash.data + 32);
    rp_push_bytes(out, ctx.stable_key_record_hash);
    rp_push_u64(out, ctx.share_set_id);
    rp_push_bytes(out, ctx.contributor_pubkey);
    rp_push_u32(out, ctx.original_index);
    rp_push_u32(out, static_cast<uint32_t>(ctx.contributor_subset.size()));
    for (uint32_t s : ctx.contributor_subset) rp_push_u32(out, s);
    rp_push_bytes(out, ctx.N);
    rp_push_bytes(out, ctx.V);
    rp_push_bytes(out, ctx.VK_i);
    rp_push_bytes(out, ctx.C_i0);
    rp_push_bytes(out, ctx.Delta);
    rp_push_bytes(out, ctx.mu_i);

    {
        std::vector<uint8_t> lp;
        if (!c.link_proof.serialize(lp)) return false;
        rp_push_bytes(out, lp);
    }
    {
        std::vector<uint8_t> cb;
        if (!c.commits.serialize(cb)) return false;
        rp_push_bytes(out, cb);
    }
    {
        const auto& cp = c.coeff_proofs;
        rp_push_u32(out, static_cast<uint32_t>(cp.range_commitments.size()));
        for (const auto& rc : cp.range_commitments) rp_push_bytes(out, rc);
        rp_push_u32(out, static_cast<uint32_t>(cp.range_proofs.size()));
        for (const auto& rpf : cp.range_proofs) rp_push_bytes(out, rpf);
        rp_push_u32(out, static_cast<uint32_t>(cp.link_proofs.size()));
        size_t veb = cp.range_commitments.empty()
                   ? 0 : cp.range_commitments[0].size();
        if (veb == 0) return false;
        for (const auto& lp : cp.link_proofs) {
            std::vector<uint8_t> lb;
            if (!lp.serialize(lb, veb)) return false;
            rp_push_bytes(out, lb);
        }
    }
    return true;
}

bool dao_reshare_deserialize_public(
    const std::vector<uint8_t>& in, dao_reshare_contribution& c_out)
{
    size_t off = 0;
    c_out = dao_reshare_contribution{};
    if (!rp_pull_u32(in, off, c_out.contributor_index)) return false;
    if (!rp_pull_bytes(in, off, c_out.contributor_pubkey)) return false;

    auto& ctx = c_out.link_ctx;
    if (off + 32 > in.size()) return false;
    std::memcpy(ctx.genesis_block_hash.data, in.data() + off, 32);
    off += 32;
    if (!rp_pull_bytes(in, off, ctx.stable_key_record_hash)) return false;
    if (!rp_pull_u64(in, off, ctx.share_set_id)) return false;
    if (!rp_pull_bytes(in, off, ctx.contributor_pubkey)) return false;
    if (!rp_pull_u32(in, off, ctx.original_index)) return false;
    uint32_t ns = 0;
    if (!rp_pull_u32(in, off, ns)) return false;
    if (ns > 32) return false;
    ctx.contributor_subset.assign(ns, 0);
    for (uint32_t i = 0; i < ns; ++i)
        if (!rp_pull_u32(in, off, ctx.contributor_subset[i])) return false;
    if (!rp_pull_bytes(in, off, ctx.N)) return false;
    if (!rp_pull_bytes(in, off, ctx.V)) return false;
    if (!rp_pull_bytes(in, off, ctx.VK_i)) return false;
    if (!rp_pull_bytes(in, off, ctx.C_i0)) return false;
    if (!rp_pull_bytes(in, off, ctx.Delta)) return false;
    if (!rp_pull_bytes(in, off, ctx.mu_i)) return false;

    {
        std::vector<uint8_t> lp;
        if (!rp_pull_bytes(in, off, lp)) return false;
        if (!c_out.link_proof.deserialize(lp)) return false;
    }
    {
        std::vector<uint8_t> cb;
        if (!rp_pull_bytes(in, off, cb)) return false;
        if (!c_out.commits.deserialize(cb)) return false;
    }
    {
        auto& cp = c_out.coeff_proofs;

        uint32_t nrc = 0;
        if (!rp_pull_u32(in, off, nrc)) return false;
        if (nrc == 0 || nrc > 256) return false;
        cp.range_commitments.assign(nrc, {});
        for (uint32_t i = 0; i < nrc; ++i)
            if (!rp_pull_bytes(in, off, cp.range_commitments[i])) return false;

        uint32_t nrp = 0;
        if (!rp_pull_u32(in, off, nrp)) return false;
        if (nrp != nrc) return false;
        cp.range_proofs.assign(nrp, {});
        for (uint32_t i = 0; i < nrp; ++i)
            if (!rp_pull_bytes(in, off, cp.range_proofs[i])) return false;

        uint32_t nlp = 0;
        if (!rp_pull_u32(in, off, nlp)) return false;
        if (nlp != nrc) return false;
        size_t veb = cp.range_commitments[0].size();
        if (veb == 0) return false;
        cp.link_proofs.assign(nlp, {});
        for (uint32_t i = 0; i < nlp; ++i) {
            std::vector<uint8_t> lb;
            if (!rp_pull_bytes(in, off, lb)) return false;
            if (!cp.link_proofs[i].deserialize(lb, veb)) return false;
        }
    }
    return off == in.size();
}

bool dao_reshare_serialize_share(
    const dao_reshare_vss_share& sh, std::vector<uint8_t>& out)
{
    out.clear();
    rp_push_u32(out, sh.j);
    rp_push_bytes(out, sh.q_i_j);
    return true;
}

bool dao_reshare_deserialize_share(
    const std::vector<uint8_t>& in, dao_reshare_vss_share& sh_out)
{
    size_t off = 0;
    if (!rp_pull_u32(in, off, sh_out.j)) return false;
    if (!rp_pull_bytes(in, off, sh_out.q_i_j)) return false;
    return off == in.size();
}


namespace {

std::vector<uint8_t> pk_to_bytes(const crypto::public_key& pk)
{
    std::vector<uint8_t> v(32, 0);
    std::memcpy(v.data(), pk.data, 32);
    return v;
}

} // namespace

struct dao_reshare_runner::impl
{
    // Copied by value. Config holds only pointers to caller-owned data
    // (pk, grp, delta, s_i, mu_i) that must outlive the runner.
    config cfg;
    dao_reshare_p2p_callbacks cb;

    mutable std::mutex mtx;
    std::condition_variable cv;

    bool stopped = false;

    std::map<uint32_t, dao_reshare_contribution> contributions;

    bool finalized = false;
    dao_share_set_record final_record;

    std::vector<uint8_t> local_share;
    bool have_local_share = false;

    impl(const config& c, const dao_reshare_p2p_callbacks& b)
        : cfg(c), cb(b) {}

    void try_finalize_locked()
    {
        if (finalized) return;
        if (cfg.local_new_index == 0) return;
        if (contributions.size() < cfg.threshold) return;

        std::vector<dao_reshare_contribution> ordered;
        for (uint32_t idx : cfg.contributor_indices) {
            auto it = contributions.find(idx);
            if (it != contributions.end()) ordered.push_back(it->second);
            if (ordered.size() >= cfg.threshold) break;
        }
        if (ordered.size() < cfg.threshold) return;

        // Every VK'_j is public and derived from the commitments alone.
        std::vector<std::vector<uint8_t>> vks;
        if (!dao_reshare_compute_all_vks(*cfg.pk, cfg.V_bytes,
                                          ordered, cfg.new_indices, vks))
            return;

        std::vector<dao_reshare_new_share> new_shares;
        new_shares.reserve(cfg.new_indices.size());
        for (size_t pos = 0; pos < cfg.new_indices.size(); ++pos) {
            dao_reshare_new_share ns;
            ns.j = cfg.new_indices[pos];
            ns.VK_j = vks[pos];
            new_shares.push_back(std::move(ns));
        }

        // If this node is one of the new members, derive its own share.
        if (cfg.local_new_index != 0 &&
            cfg.local_new_index <= cfg.new_indices.size()) {
            uint32_t pos = cfg.local_new_index - 1;
            dao_reshare_new_share mine;
            if (dao_reshare_combine_one(*cfg.pk, *cfg.grp, cfg.V_bytes,
                                         ordered, cfg.new_indices,
                                         pos, cfg.threshold, cfg.delta, mine)) {
                new_shares[pos].share_signed = std::move(mine.share_signed);
                local_share = new_shares[pos].share_signed;
                have_local_share = true;
            }
        }

        dao_share_set_record rec;
        if (!dao_reshare_build_share_set(cfg.new_share_set_id, cfg.height,
                                          cfg.key_id, cfg.new_members,
                                          new_shares, cfg.threshold, rec))
            return;

        final_record = rec;
        finalized = true;

        dao_reshare_msg cm;
        cm.old_share_set_id = cfg.old_share_set_id;
        cm.new_share_set_id = cfg.new_share_set_id;
        cm.sender_index     = cfg.local_party_index;
        cm.type             = 1;
        if (rec.serialize(cm.record_blob)) {
            std::vector<uint8_t> mb;
            cm.serialize(mb);
            std::string ms(mb.begin(), mb.end());
            cb.broadcast(ms);
        }
        cv.notify_all();
    }
};

dao_reshare_runner::dao_reshare_runner(
    const config& cfg, const dao_reshare_p2p_callbacks& cb)
    : p_(new impl(cfg, cb)) {}

dao_reshare_runner::~dao_reshare_runner() = default;

bool dao_reshare_runner::start()
{
    if (p_->cfg.local_party_index == 0) {
        // New member only; wait for deals.
        return true;
    }
    if (!p_->cfg.local_s_i || !p_->cfg.local_mu_i) return false;
    if (!p_->cfg.grp || !p_->cfg.delta) return false;

    dao_reshare_contribution contrib;
    dao_reshare_link_context ctx = p_->cfg.link_ctx_base;
    if (!dao_reshare_make_contribution(
            *p_->cfg.pk, *p_->cfg.grp, p_->cfg.V_bytes,
            p_->cfg.local_s_i, p_->cfg.local_mu_i, p_->cfg.delta,
            p_->cfg.t_new, p_->cfg.new_indices, ctx, contrib))
        return false;

    {
        std::lock_guard<std::mutex> lk(p_->mtx);
        p_->contributions[p_->cfg.local_party_index] = contrib;
    }

    // Build the deal message: our public part plus encrypted shares to
    // each new member.
    dao_reshare_msg m;
    m.old_share_set_id = p_->cfg.old_share_set_id;
    m.new_share_set_id = p_->cfg.new_share_set_id;
    m.sender_index     = p_->cfg.local_party_index;
    m.type             = 0;
    if (!dao_reshare_serialize_public(contrib, m.public_blob)) return false;

    for (size_t i = 0; i < p_->cfg.new_indices.size(); ++i) {
        std::vector<uint8_t> sh_bytes;
        if (!dao_reshare_serialize_share(contrib.shares[i], sh_bytes))
            return false;
        dao_reshare_share_bundle bundle;
        bundle.old_share_set_id = p_->cfg.old_share_set_id;
        bundle.sender_index     = p_->cfg.local_party_index;
        bundle.share_bytes      = std::move(sh_bytes);
        std::vector<uint8_t> bb;
        if (!bundle.serialize(bb)) return false;

        std::string bstr(bb.begin(), bb.end());
        std::string encrypted;
        if (!encrypt_dkg_private_payload(bstr, p_->cfg.local_pub,
                                          p_->cfg.new_members[i], encrypted))
            return false;
        m.recipient_indices.push_back(p_->cfg.new_indices[i]);
        m.recipient_payloads.push_back(
            std::vector<uint8_t>(encrypted.begin(), encrypted.end()));
    }

    std::vector<uint8_t> mb;
    m.serialize(mb);
    std::string ms(mb.begin(), mb.end());
    p_->cb.broadcast(ms);

    {
        std::lock_guard<std::mutex> lk(p_->mtx);
        p_->try_finalize_locked();
    }
    return true;
}

void dao_reshare_runner::stop()
{
    std::lock_guard<std::mutex> lk(p_->mtx);
    p_->stopped = true;
    p_->cv.notify_all();
}

void dao_reshare_runner::on_message(const crypto::public_key& from,
                                    const dao_reshare_msg& m)
{
    if (m.version != 1) return;
    if (m.old_share_set_id != p_->cfg.old_share_set_id) return;
    if (m.new_share_set_id != p_->cfg.new_share_set_id) return;

    if (m.type == 0) {
        // Deal.
        if (m.sender_index == 0 ||
            m.sender_index > p_->cfg.contributor_members.size())
            return;
        if (std::memcmp(p_->cfg.contributor_members[m.sender_index - 1].data,
                        from.data, 32) != 0)
            return;

        {
            std::lock_guard<std::mutex> lk(p_->mtx);
            if (p_->contributions.count(m.sender_index) > 0) return;
        }

        dao_reshare_contribution contrib;
        if (!dao_reshare_deserialize_public(m.public_blob, contrib))
            return;
        if (contrib.contributor_index != m.sender_index) return;
        if (contrib.contributor_pubkey != pk_to_bytes(from)) return;
        if (contrib.link_ctx.share_set_id != p_->cfg.old_share_set_id) return;
        if (contrib.link_ctx.original_index != m.sender_index) return;

        // Find our payload and decrypt if present.
        bool got_share = false;
        dao_reshare_vss_share my_share{};
        if (p_->cfg.local_new_index != 0 &&
            p_->cfg.local_new_index <= p_->cfg.new_indices.size()) {
            const uint32_t my_new_index =
                p_->cfg.new_indices[p_->cfg.local_new_index - 1];
            for (size_t i = 0; i < m.recipient_indices.size(); ++i) {
                if (m.recipient_indices[i] != my_new_index)
                    continue;
                std::string ciphertext(m.recipient_payloads[i].begin(),
                                       m.recipient_payloads[i].end());
                if (!is_dkg_private_payload(ciphertext)) continue;
                std::string plaintext;
                if (!decrypt_dkg_private_payload(
                        ciphertext, from, p_->cfg.local_priv, plaintext))
                    continue;
                std::vector<uint8_t> bb(plaintext.begin(), plaintext.end());
                dao_reshare_share_bundle bundle;
                if (!bundle.deserialize(bb)) continue;
                if (bundle.old_share_set_id != p_->cfg.old_share_set_id)
                    continue;
                if (bundle.sender_index != m.sender_index) continue;
                if (!dao_reshare_deserialize_share(bundle.share_bytes,
                                                    my_share))
                    continue;
                got_share = true;
                break;
            }
        }

        // If this is not our own contribution, we must have obtained a
        // share for ourselves to be able to use this contribution in
        // combine.
        if (m.sender_index != p_->cfg.local_party_index && !got_share)
            return;

        // Verify the delivered share against the contributor's public
        // commitments, and verify all coefficient proofs and the link
        // proof.
        if (got_share) {
            contrib.shares.clear();
            contrib.shares.push_back(my_share);
            if (!dao_reshare_vss_verify(*p_->cfg.pk, *p_->cfg.grp,
                                         p_->cfg.V_bytes,
                                         contrib.link_ctx, contrib.link_proof,
                                         contrib.commits, contrib.coeff_proofs,
                                         my_share.j, my_share.q_i_j))
                return;
        } else {
            // Our own contribution: shares vector already populated.
        }

        {
            std::lock_guard<std::mutex> lk(p_->mtx);
            if (p_->contributions.count(m.sender_index) > 0) return;
            p_->contributions[m.sender_index] = std::move(contrib);
            p_->try_finalize_locked();
        }
        return;
    }

    if (m.type == 1) {
        // Complete.
        dao_share_set_record rec;
        if (!rec.deserialize(m.record_blob)) return;
        if (rec.share_set_id != p_->cfg.new_share_set_id) return;
        if (rec.committee_members.size() != p_->cfg.new_members.size())
            return;
        for (size_t i = 0; i < rec.committee_members.size(); ++i) {
            if (rec.committee_members[i].size() != 32) return;
            if (std::memcmp(rec.committee_members[i].data(),
                            p_->cfg.new_members[i].data, 32) != 0)
                return;
        }

        std::lock_guard<std::mutex> lk(p_->mtx);
        if (p_->finalized) return;
        p_->final_record = std::move(rec);
        p_->finalized = true;
        p_->cv.notify_all();
    }
}

bool dao_reshare_runner::wait(dao_share_set_record& out, uint32_t timeout_s)
{
    std::unique_lock<std::mutex> lk(p_->mtx);
    if (timeout_s == 0) {
        p_->cv.wait(lk, [&] { return p_->finalized || p_->stopped; });
    } else {
        p_->cv.wait_for(lk, std::chrono::seconds(timeout_s),
                        [&] { return p_->finalized || p_->stopped; });
    }
    if (!p_->finalized) return false;
    out = p_->final_record;
    return true;
}

bool dao_reshare_runner::finished() const
{
    std::lock_guard<std::mutex> lk(p_->mtx);
    return p_->finalized;
}

bool dao_reshare_runner::get_local_share(
    std::vector<uint8_t>& share_out) const
{
    std::lock_guard<std::mutex> lk(p_->mtx);
    if (!p_->have_local_share) return false;
    share_out = p_->local_share;
    return true;
}

} // namespace dao
} // namespace cryptonote
