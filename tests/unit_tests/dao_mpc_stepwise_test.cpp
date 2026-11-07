#include "gtest/gtest.h"
#include <openssl/bn.h>
#include "governance/dao_dkg.h"
#include "governance/dao_mpc.h"

using namespace cryptonote::dao;

TEST(dao_mpc_stepwise, local_product_ok) {
    dao_mpc_field f; f.r = 1000003;
    BIGNUM* a = BN_new(); BN_set_word(a, 5);
    BIGNUM* b = BN_new(); BN_set_word(b, 7);
    uint32_t c = 0;
    ASSERT_TRUE(dao_mpc_mul::local_product(f, a, b, c));
    EXPECT_EQ(c, 35u);
    BN_free(a); BN_free(b);
}

TEST(dao_mpc_stepwise, three_parties_match_centralized) {
    dao_mpc_field f; f.r = 1000003;
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_TRUE(ctx);

    const uint32_t n = 3, t = 1;
    const uint32_t a = 5, b = 7;

    dao_vss_commitments ca, cb;
    std::vector<BIGNUM*> sa, sb, ba, bb;
    ASSERT_TRUE(dao_mpc_vss::deal(f, grp, a, n, t, ca, sa, ba, ctx));
    ASSERT_TRUE(dao_mpc_vss::deal(f, grp, b, n, t, cb, sb, bb, ctx));

    // Party-private state.
    std::vector<uint32_t> c(n);
    std::vector<dao_vss_commitments> deals(n);
    std::vector<std::vector<BIGNUM*>> all_shares(n);
    std::vector<std::vector<BIGNUM*>> all_blindings(n);
    for (uint32_t i = 0; i < n; ++i) {
        ASSERT_TRUE(dao_mpc_mul::local_product(f, sa[i], sb[i], c[i]));
        ASSERT_TRUE(dao_mpc_mul::deal_c(f, grp, c[i], n, t,
                                         deals[i], all_shares[i], all_blindings[i], ctx));
    }

    // Each party independently combines its received shares.
    std::vector<uint32_t> r(n);
    for (uint32_t i = 0; i < n; ++i) {
        std::vector<const BIGNUM*> my_shares(n);
        for (uint32_t d = 0; d < n; ++d) {
            ASSERT_TRUE(all_shares[d][i] != nullptr);
            my_shares[d] = all_shares[d][i];
        }
        ASSERT_TRUE(dao_mpc_mul::combine_c_shares(f, my_shares, n, t, r[i]));
    }

    // Reconstruct from any t+1 = 2 combined shares.
    std::vector<BIGNUM*> rbn(n);
    for (uint32_t i = 0; i < n; ++i) {
        rbn[i] = BN_new();
        BN_set_word(rbn[i], r[i]);
    }
    std::vector<const BIGNUM*> rec01 = {rbn[0], rbn[1]};
    std::vector<uint32_t> idx01 = {1, 2};
    uint32_t result01 = 0;
    ASSERT_TRUE(dao_mpc_vss::reconstruct(f, rec01, idx01, t, result01, ctx));
    EXPECT_EQ(result01, (a * b) % f.r);

    std::vector<const BIGNUM*> rec02 = {rbn[0], rbn[2]};
    std::vector<uint32_t> idx02 = {1, 3};
    uint32_t result02 = 0;
    ASSERT_TRUE(dao_mpc_vss::reconstruct(f, rec02, idx02, t, result02, ctx));
    EXPECT_EQ(result02, (a * b) % f.r);

    std::vector<const BIGNUM*> rec12 = {rbn[1], rbn[2]};
    std::vector<uint32_t> idx12 = {2, 3};
    uint32_t result12 = 0;
    ASSERT_TRUE(dao_mpc_vss::reconstruct(f, rec12, idx12, t, result12, ctx));
    EXPECT_EQ(result12, (a * b) % f.r);

    // Centralized API must agree with the stepwise decomposition.
    std::vector<const BIGNUM*> pa(sa.begin(), sa.end());
    std::vector<const BIGNUM*> pb(sb.begin(), sb.end());
    std::vector<BIGNUM*> centralized;
    ASSERT_TRUE(dao_mpc_mul::multiply(f, grp, n, t, pa, pb, centralized, ctx));
    std::vector<const BIGNUM*> rec_c = {centralized[0], centralized[1]};
    uint32_t result_c = 0;
    ASSERT_TRUE(dao_mpc_vss::reconstruct(f, rec_c, idx01, t, result_c, ctx));
    EXPECT_EQ(result_c, result01);

    for (auto* x : sa) BN_free(x);
    for (auto* x : sb) BN_free(x);
    for (auto* x : ba) BN_free(x);
    for (auto* x : bb) BN_free(x);
    for (auto& v : all_shares) for (auto* x : v) BN_free(x);
    for (auto& v : all_blindings) for (auto* x : v) BN_free(x);
    for (auto* x : centralized) BN_free(x);
    for (auto* x : rbn) BN_free(x);
    BN_CTX_free(ctx);
}
