#include "gtest/gtest.h"
#include <openssl/bn.h>
#include "governance/dao_dkg.h"
#include "governance/dao_mpc.h"

using namespace cryptonote::dao;

TEST(dao_mpc, FieldOps) {
    dao_mpc_field f; f.r = 1000003;
    EXPECT_EQ(f.add(1000002, 2), 1u);
    EXPECT_EQ(f.sub(0, 1), 1000002u);
    EXPECT_EQ(f.mul(2, 3), 6u);
    uint32_t inv = f.inv(7);
    EXPECT_EQ(f.mul(7, inv), 1u);
}

TEST(dao_mpc, MultiplyThreeParties) {
    dao_mpc_field f; f.r = 1000003;
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));

    const uint32_t n = 3, t = 1;
    const uint32_t a = 5, b = 7;

    BN_CTX* ctx = BN_CTX_new();
    ASSERT_TRUE(ctx);

    dao_vss_commitments ca, cb;
    std::vector<BIGNUM*> sa, sb, ba, bb;
    ASSERT_TRUE(dao_mpc_vss::deal(f, grp, a, n, t, ca, sa, ba, ctx));
    ASSERT_TRUE(dao_mpc_vss::deal(f, grp, b, n, t, cb, sb, bb, ctx));

    std::vector<const BIGNUM*> pa(sa.begin(), sa.end());
    std::vector<const BIGNUM*> pb(sb.begin(), sb.end());
    std::vector<BIGNUM*> out;
    ASSERT_TRUE(dao_mpc_mul::multiply(f, grp, n, t, pa, pb, out, ctx));
    ASSERT_EQ(out.size(), (size_t)n);

    {
        std::vector<const BIGNUM*> rec = {out[0], out[1]};
        std::vector<uint32_t> idx = {1, 2};
        uint32_t result = 0;
        ASSERT_TRUE(dao_mpc_vss::reconstruct(f, rec, idx, t, result, ctx));
        EXPECT_EQ(result, (a * b) % f.r);
    }
    {
        std::vector<const BIGNUM*> rec = {out[0], out[1], out[2]};
        std::vector<uint32_t> idx = {1, 2, 3};
        uint32_t result = 0;
        ASSERT_TRUE(dao_mpc_vss::reconstruct(f, rec, idx, t, result, ctx));
        EXPECT_EQ(result, (a * b) % f.r);
    }

    for (auto* x : sa) BN_free(x);
    for (auto* x : sb) BN_free(x);
    for (auto* x : ba) BN_free(x);
    for (auto* x : bb) BN_free(x);
    for (auto* x : out) BN_free(x);
    BN_CTX_free(ctx);
}

TEST(dao_mpc, MultiplyRejectBadShare) {
    dao_mpc_field f; f.r = 1000003;
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_TRUE(ctx);

    dao_vss_commitments c;
    std::vector<BIGNUM*> sh, bl;
    ASSERT_TRUE(dao_mpc_vss::deal(f, grp, 42, 3, 1, c, sh, bl, ctx));

    BIGNUM* bad = BN_new();
    BN_set_word(bad, 999);
    EXPECT_FALSE(dao_mpc_vss::verify(f, grp, c, 1, bad, bl[0], ctx));

    BN_free(bad);
    for (auto* x : sh) BN_free(x);
    for (auto* x : bl) BN_free(x);
    BN_CTX_free(ctx);
}
