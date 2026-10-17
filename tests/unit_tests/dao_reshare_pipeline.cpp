// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "gtest/gtest.h"

#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_paillier.h"
#include "governance/dao_reshare_pipeline.h"
#include "crypto/crypto.h"

#include <openssl/bn.h>

#include <memory>
#include <string>
#include <vector>

namespace {

using namespace cryptonote;
using namespace cryptonote::dao;

struct BNFree {
    void operator()(BIGNUM* p) const { if (p) BN_free(p); }
};
using BN_ptr = std::unique_ptr<BIGNUM, BNFree>;

bool run_dkg_3(dkg_result& out)
{
    dao_vss_group vss;
    if (!dao_vss_group_generate(vss,
            dao_dkg_required_vss_bits(60, 128, 32)))
        return false;

    dkg_inproc_network inet = dkg_make_inproc_network(3, nullptr);
    std::vector<std::unique_ptr<dkg_transport>> pool;
    pool.reserve(inet.endpoints.size());
    for (auto& e : inet.endpoints) pool.push_back(std::move(e));

    size_t next = 0;
    dkg_transport_factory factory =
        [&pool, &next](uint32_t) -> std::unique_ptr<dkg_transport> {
            if (next >= pool.size()) return nullptr;
            return std::move(pool[next++]);
        };

    std::vector<crypto::public_key> pks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk; crypto::secret_key sk;
        crypto::generate_keys(pk, sk);
        pks.push_back(pk);
    }

    dkg_config cfg;
    cfg.committee_size = 3;
    cfg.threshold      = dao_dkg_expected_threshold(3);
    cfg.member_ids     = pks;
    cfg.k              = 60;
    cfg.target_N_bits  = 128;
    cfg.security_bits  = 32;
    cfg.qproof_rounds  = DAO_DKG_QPROOF_ROUNDS_TEST;
    cfg.max_attempts   = 1;
    cfg.test_seed      = 0x5645494C52544F33ULL;
    cfg.local_party_id = 1;

    return dkg_run_with_transport(cfg, factory, out);
}

BN_ptr bn_from_dec(const std::string& s)
{
    BIGNUM* b = nullptr;
    if (BN_dec2bn(&b, s.c_str()) == 0) {
        if (b) BN_free(b);
        return BN_ptr();
    }
    return BN_ptr(b);
}

std::vector<uint8_t> mu_signed(const BIGNUM* m)
{
    std::vector<uint8_t> out(1 + 512, 0);
    out[0] = BN_is_negative(m) ? 1 : 0;
    BIGNUM* a = BN_dup(m); BN_set_negative(a, 0);
    BN_bn2binpad(a, out.data() + 1, 512);
    BN_free(a);
    return out;
}

dao_reshare_link_context base_ctx(const dkg_result& out,
                                  uint32_t idx,
                                  const std::vector<uint8_t>& delta_bytes,
                                  const std::vector<uint8_t>& mu_bytes,
                                  const std::vector<crypto::public_key>& pks)
{
    dao_reshare_link_context ctx;
    ctx.genesis_block_hash = []{
        crypto::hash h{}; std::memset(h.data, 0xAA, 32); return h;
    }();
    ctx.stable_key_record_hash.assign(32, 0xBB);
    ctx.share_set_id = 1;
    std::vector<uint8_t> pk32(32, 0);
    std::memcpy(pk32.data(), pks[idx - 1].data, 32);
    ctx.contributor_pubkey = std::move(pk32);
    ctx.original_index = idx;
    ctx.contributor_subset = {1, 2};
    ctx.N = out.record.N;
    ctx.V = out.record.V;
    ctx.VK_i = out.record.V_K_i[idx - 1];
    ctx.C_i0.assign(PAILLIER_CT_BYTES, 0);
    ctx.Delta = delta_bytes;
    ctx.mu_i  = mu_bytes;
    return ctx;
}

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

TEST(DaoResharePipeline, EndToEndResharing)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));

    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp,
        dao_dkg_required_vss_bits(60, 128, 32)));

    BIGNUM* delta_raw = BN_new();
    BN_dec2bn(&delta_raw, "20922789888000");
    BN_ptr delta(delta_raw);

    std::vector<uint8_t> delta_bytes(32, 0);
    BN_bn2binpad(delta.get(), delta_bytes.data(), 32);

    const std::vector<uint32_t> S = {1, 2};
    BN_ptr mu1(BN_new()), mu2(BN_new());
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 1, mu1.get()));
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 2, mu2.get()));

    BN_ptr s1 = bn_from_dec(std::string(out.test_SK[0].begin(),
                                         out.test_SK[0].end()));
    BN_ptr s2 = bn_from_dec(std::string(out.test_SK[1].begin(),
                                         out.test_SK[1].end()));
    ASSERT_NE(s1, nullptr);
    ASSERT_NE(s2, nullptr);

    // Reconstruct committee public keys from VSS group (any 3 keys).
    std::vector<crypto::public_key> pks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key pk_i; crypto::secret_key sk_i;
        crypto::generate_keys(pk_i, sk_i);
        pks.push_back(pk_i);
    }

    auto ctx1 = base_ctx(out, 1, delta_bytes, mu_signed(mu1.get()), pks);
    auto ctx2 = base_ctx(out, 2, delta_bytes, mu_signed(mu2.get()), pks);

    // New committee: 3 members at indices 4, 5, 6, degree 1 (threshold 2).
    const uint32_t t_new = 1;
    std::vector<uint32_t> new_indices = {4, 5, 6};

    dao_reshare_contribution c1, c2;
    ASSERT_TRUE(dao_reshare_make_contribution(pk, grp, out.record.V,
                                               s1.get(), mu1.get(),
                                               delta.get(), t_new,
                                               new_indices, ctx1, c1));
    ASSERT_TRUE(dao_reshare_make_contribution(pk, grp, out.record.V,
                                               s2.get(), mu2.get(),
                                               delta.get(), t_new,
                                               new_indices, ctx2, c2));

    std::vector<dao_reshare_contribution> contribs = { c1, c2 };

    std::vector<dao_reshare_new_share> new_shares;
    ASSERT_TRUE(dao_reshare_combine(pk, grp, out.record.V,
                                     contribs, new_indices, 2,
                                     delta.get(), new_shares));
    ASSERT_EQ(new_shares.size(), 3u);

    // Each new share's VK_j equals V^(Delta * s'_j).
    for (size_t k = 0; k < new_shares.size(); ++k) {
        BN_ptr s_j(BN_new());
        ASSERT_TRUE(dao_reshare_deserialize_signed(
            new_shares[k].share_signed, s_j.get()));

        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* V = BN_bin2bn(out.record.V.data(),
                               (int)out.record.V.size(), nullptr);
        BIGNUM* exp = BN_new();
        BN_mul(exp, s_j.get(), delta.get(), ctx);
        BIGNUM* calc = BN_new();
        ASSERT_TRUE(modexp_signed(V, exp, pk.N2(), calc, ctx));
        std::vector<uint8_t> bytes(PAILLIER_CT_BYTES, 0);
        BN_bn2binpad(calc, bytes.data(), PAILLIER_CT_BYTES);
        EXPECT_EQ(bytes, new_shares[k].VK_j);
        BN_free(V); BN_free(exp); BN_free(calc);
        BN_CTX_free(ctx);
    }

    // Build the share-set record.
    std::vector<crypto::public_key> new_members;
    for (uint32_t j = 0; j < 3; ++j) {
        crypto::public_key m; crypto::secret_key msk;
        crypto::generate_keys(m, msk);
        new_members.push_back(m);
    }

    std::vector<uint8_t> key_id = out.record.key_id;
    dao_share_set_record rec;
    ASSERT_TRUE(dao_reshare_build_share_set(7, 12345, key_id,
                                             new_members, new_shares,
                                             2, rec));
    EXPECT_EQ(rec.share_set_id, 7u);
    EXPECT_EQ(rec.threshold, 2u);
    EXPECT_EQ(rec.committee_members.size(), 3u);
    EXPECT_EQ(rec.VK_i.size(), 3u);

    std::vector<uint8_t> blob;
    ASSERT_TRUE(rec.serialize(blob));
    dao_share_set_record back;
    ASSERT_TRUE(back.deserialize(blob));
    EXPECT_EQ(back.share_set_id, 7u);
    EXPECT_EQ(back.committee_id_hash, rec.committee_id_hash);
    EXPECT_EQ(back.VK_i, rec.VK_i);
}

TEST(DaoResharePipeline, RejectsForgedContribution)
{
    dkg_result out;
    ASSERT_TRUE(run_dkg_3(out));
    ASSERT_TRUE(out.candidate_accepted);

    PaillierPublicKey pk;
    ASSERT_TRUE(pk.deserialize_modulus(out.record.N));

    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp,
        dao_dkg_required_vss_bits(60, 128, 32)));

    BIGNUM* delta_raw = BN_new();
    BN_dec2bn(&delta_raw, "20922789888000");
    BN_ptr delta(delta_raw);
    std::vector<uint8_t> delta_bytes(32, 0);
    BN_bn2binpad(delta.get(), delta_bytes.data(), 32);

    const std::vector<uint32_t> S = {1, 2};
    BN_ptr mu1(BN_new());
    ASSERT_TRUE(dao_dkg_lagrange_mu(S, 1, mu1.get()));
    BN_ptr s1 = bn_from_dec(std::string(out.test_SK[0].begin(),
                                         out.test_SK[0].end()));
    ASSERT_NE(s1, nullptr);

    std::vector<crypto::public_key> pks;
    for (int i = 0; i < 3; ++i) {
        crypto::public_key p; crypto::secret_key s;
        crypto::generate_keys(p, s);
        pks.push_back(p);
    }
    auto ctx1 = base_ctx(out, 1, delta_bytes, mu_signed(mu1.get()), pks);

    std::vector<uint32_t> new_indices = {4, 5, 6};
    dao_reshare_contribution c1;
    ASSERT_TRUE(dao_reshare_make_contribution(pk, grp, out.record.V,
                                               s1.get(), mu1.get(),
                                               delta.get(), 1,
                                               new_indices, ctx1, c1));

    // Corrupt one of the delivered shares. The combine path must reject.
    auto bad = c1;
    bad.shares[0].q_i_j[2] ^= 0x01;
    std::vector<dao_reshare_contribution> contribs = { bad };
    std::vector<dao_reshare_new_share> out_shares;
    EXPECT_FALSE(dao_reshare_combine(pk, grp, out.record.V,
                                      contribs, new_indices, 1,
                                      delta.get(), out_shares));

    // Corrupt a link proof. Rejected.
    auto bad2 = c1;
    bad2.link_proof.Z[3][0] ^= 0x01;
    std::vector<dao_reshare_contribution> contribs2 = { bad2 };
    std::vector<dao_reshare_new_share> out_shares2;
    EXPECT_FALSE(dao_reshare_combine(pk, grp, out.record.V,
                                      contribs2, new_indices, 1,
                                      delta.get(), out_shares2));
}
