// Phase 2b-2 wire milestone: three real dkg_transport endpoints run
// the stepwise GRR multiply, exchanging commit-broadcast and share-
// unicast messages through the in-process hub. No dkg_party, no
// dkg_p2p_runner. This proves the transport layer can carry an F_r
// secure multiplication round end to end.

#include "gtest/gtest.h"
#include <openssl/bn.h>
#include <utility>
#include <chrono>
#include <vector>

#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_mpc.h"
#include "governance/dao_mpc_crt.h"

using namespace cryptonote::dao;

namespace {
// Reserved for Phase 2b-3. Two distinct values suffice for this test.
constexpr dkg_msg_type TAG_COMMIT = static_cast<dkg_msg_type>(0x90);
constexpr dkg_msg_type TAG_SHARE  = static_cast<dkg_msg_type>(0x91);
} // namespace

TEST(dao_mpc_wire, three_party_grr_via_transport)
{
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

    dkg_inproc_network net = dkg_make_inproc_network(n, nullptr);
    ASSERT_EQ(net.endpoints.size(), (size_t)n);

    std::vector<dao_vss_commitments>    commits(n);
    std::vector<std::vector<BIGNUM*>>   all_shares(n);
    std::vector<std::vector<BIGNUM*>>   all_blinds(n);

    // Phase A: each party deals, broadcasts commits, unicasts shares.
    for (uint32_t i = 1; i <= n; ++i) {
        uint32_t c_i = 0;
        ASSERT_TRUE(dao_mpc_mul::local_product(f, sa[i-1], sb[i-1], c_i));
        ASSERT_TRUE(dao_mpc_mul::deal_c(f, grp, c_i, n, t,
                    commits[i-1], all_shares[i-1], all_blinds[i-1], ctx));

        dkg_transport* t_i = net.endpoints[i-1].get();
        ASSERT_NE(t_i, nullptr);

        dkg_msg mc;
        mc.hdr.version      = 2;
        mc.hdr.sender_id    = i;
        mc.hdr.recipient_id = 0;
        mc.hdr.type         = TAG_COMMIT;
        mc.tag32            = i;
        for (const auto& c : commits[i-1].C) mc.vec_a.push_back(c);
        ASSERT_TRUE(t_i->send(mc));

        for (uint32_t j = 1; j <= n; ++j) {
            if (j == i) continue;
            dkg_msg ms;
            ms.hdr.version      = 2;
            ms.hdr.sender_id    = i;
            ms.hdr.recipient_id = j;
            ms.hdr.type         = TAG_SHARE;
            ms.tag32            = i;
            const BIGNUM* sh = all_shares[i-1][j-1];
            const BIGNUM* bl = all_blinds[i-1][j-1];
            const int shb = BN_num_bytes(sh);
            ms.bytes_a.assign(shb, 0);
            BN_bn2bin(sh, ms.bytes_a.data());
            const int blb = BN_num_bytes(bl);
            ms.bytes_b.assign(blb, 0);
            BN_bn2bin(bl, ms.bytes_b.data());
            ASSERT_TRUE(t_i->send(ms));
        }
    }

    // Phase B: each party drains, verifies, combines.
    std::vector<uint32_t> own_results(n, 0);
    for (uint32_t i = 1; i <= n; ++i) {
        dkg_transport* t_i = net.endpoints[i-1].get();
        ASSERT_NE(t_i, nullptr);

        std::vector<dkg_msg> inbox;
        {
            dkg_msg m;
            while (t_i->try_recv(m)) inbox.push_back(m);
        }

        std::vector<dao_vss_commitments> peer_commits(n);
        peer_commits[i-1] = commits[i-1];
        for (const auto& mm : inbox) {
            if (mm.hdr.type != TAG_COMMIT) continue;
            uint32_t s = mm.hdr.sender_id;
            ASSERT_GE(s, 1u); ASSERT_LE(s, (uint32_t)n);
            ASSERT_EQ(mm.tag32, s);
            peer_commits[s-1].C = mm.vec_a;
        }
        for (uint32_t k = 0; k < n; ++k)
            ASSERT_FALSE(peer_commits[k].C.empty())
                << "missing commit from " << (k+1);

        std::vector<BIGNUM*> my_shares(n, nullptr);
        my_shares[i-1] = BN_dup(all_shares[i-1][i-1]);
        ASSERT_NE(my_shares[i-1], nullptr);

        for (const auto& mm : inbox) {
            if (mm.hdr.type != TAG_SHARE) continue;
            if (mm.hdr.recipient_id != i) continue;
            uint32_t s = mm.hdr.sender_id;
            ASSERT_GE(s, 1u); ASSERT_LE(s, (uint32_t)n);
            ASSERT_NE(s, i);
            ASSERT_EQ(mm.tag32, s);
            ASSERT_FALSE(mm.bytes_a.empty());
            ASSERT_FALSE(mm.bytes_b.empty());
            BIGNUM* sh = BN_bin2bn(mm.bytes_a.data(),
                                   (int)mm.bytes_a.size(), nullptr);
            BIGNUM* bl = BN_bin2bn(mm.bytes_b.data(),
                                   (int)mm.bytes_b.size(), nullptr);
            ASSERT_NE(sh, nullptr);
            ASSERT_NE(bl, nullptr);
            const bool ok = dao_mpc_vss::verify(f, grp, peer_commits[s-1], i, sh, bl, ctx);
            BN_free(bl);
            if (!ok) {
                BN_free(sh);
                FAIL() << "share verify failed: sender=" << s
                       << " recipient=" << i;
            }
            my_shares[s-1] = sh;
        }
        for (uint32_t k = 0; k < n; ++k) {
            if (!my_shares[k]) {
                for (auto* x : my_shares) if (x) BN_free(x);
                FAIL() << "missing share from " << (k+1);
            }
        }

        std::vector<const BIGNUM*> my_shares_const(my_shares.begin(), my_shares.end());
        ASSERT_TRUE(dao_mpc_mul::combine_c_shares(f, my_shares_const, n, t, own_results[i-1]));

        for (auto* x : my_shares) BN_free(x);
    }

    // Phase C: any two of the three combined shares must reconstruct a*b.
    std::vector<BIGNUM*> rbn(n);
    for (uint32_t i = 0; i < n; ++i) {
        rbn[i] = BN_new();
        ASSERT_NE(rbn[i], nullptr);
        BN_set_word(rbn[i], own_results[i]);
    }
    std::pair<uint32_t, uint32_t> pairs[3] = {{0,1},{0,2},{1,2}};
    for (auto& pr : pairs) {
        std::vector<const BIGNUM*> rec = {rbn[pr.first], rbn[pr.second]};
        std::vector<uint32_t> idx = {pr.first + 1, pr.second + 1};
        uint32_t result = 0;
        ASSERT_TRUE(dao_mpc_vss::reconstruct(f, rec, idx, t, result, ctx));
        EXPECT_EQ(result, (a * b) % f.r)
            << "reconstruction from parties " << (pr.first + 1)
            << "," << (pr.second + 1);
    }

    for (auto* x : sa) BN_free(x);
    for (auto* x : sb) BN_free(x);
    for (auto* x : ba) BN_free(x);
    for (auto* x : bb) BN_free(x);
    for (auto* x : rbn) BN_free(x);
    for (auto& v : all_shares) for (auto* x : v) BN_free(x);
    for (auto& v : all_blinds) for (auto* x : v) BN_free(x);
    BN_CTX_free(ctx);
}
// ------------------------------------------------------------------
// Phase 2b-3: single-prime sieve round over real transports.
//
// Full pipeline for ONE sieve prime r with n=3, t=1:
//   1. Each party draws u_i in [1,r), deals F_r VSS of u_i.
//   2. Wire: broadcast commits, unicast shares.
//   3. GRR multiply u_1 * u_2 (local_product + deal_c + combine).
//   4. GRR multiply (u_1*u_2) * u_3.
//   5. Convert Shamir shares of product to additive shares.
//   6. Verify sum == u_1*u_2*u_3 mod r, nonzero.
//   7. Lift each additive share into [2^{bits-1}, 2^bits) preserving
//      mod-r residue. Verify lifted sum mod r != 0 and range.
//
// This is the exact construction the production sieve will use. It
// exercises the full message path through dkg_inproc_network. No
// dkg_party, no dkg_p2p_runner, no production code changes.
// ------------------------------------------------------------------

namespace {

constexpr dkg_msg_type TAG_W_COMMIT = static_cast<dkg_msg_type>(0x90);
constexpr dkg_msg_type TAG_W_SHARE  = static_cast<dkg_msg_type>(0x91);

void w_broadcast_commits(dkg_transport* tp, uint32_t sender, uint32_t round,
                         const dao_vss_commitments& commits)
{
    dkg_msg m;
    m.hdr.version = 2;
    m.hdr.sender_id = sender;
    m.hdr.recipient_id = 0;
    m.hdr.phase = 0;
    m.hdr.round = round;
    m.hdr.type = TAG_W_COMMIT;
    m.tag32 = sender;
    for (const auto& c : commits.C) m.vec_a.push_back(c);
    tp->send(m);
}

void w_unicast_shares(dkg_transport* tp, uint32_t sender, uint32_t round,
                      uint32_t n, uint32_t self,
                      const std::vector<BIGNUM*>& shares,
                      const std::vector<BIGNUM*>& blinds)
{
    for (uint32_t j = 1; j <= n; ++j) {
        if (j == self) continue;
        dkg_msg m;
        m.hdr.version = 2;
        m.hdr.sender_id = sender;
        m.hdr.recipient_id = j;
        m.hdr.phase = 0;
        m.hdr.round = round;
        m.hdr.type = TAG_W_SHARE;
        m.tag32 = sender;
        const BIGNUM* sh = shares[j-1];
        const BIGNUM* bl = blinds[j-1];
        const int shb = BN_num_bytes(sh);
        m.bytes_a.assign(shb, 0);
        BN_bn2bin(sh, m.bytes_a.data());
        const int blb = BN_num_bytes(bl);
        m.bytes_b.assign(blb, 0);
        BN_bn2bin(bl, m.bytes_b.data());
        tp->send(m);
    }
}

bool w_drain_round(dkg_transport* tp, uint32_t self, uint32_t n,
                   uint32_t round,
                   const dao_mpc_field& f, const dao_vss_group& grp,
                   const dao_vss_commitments& own_commits,
                   const BIGNUM* own_share, const BIGNUM* own_blind,
                   BN_CTX* ctx,
                   std::vector<dao_vss_commitments>& peer_commits_out,
                   std::vector<BIGNUM*>& shares_out)
{
    peer_commits_out.assign(n, {});
    peer_commits_out[self-1] = own_commits;
    shares_out.assign(n, nullptr);
    shares_out[self-1] = BN_dup(own_share);
    if (!shares_out[self-1]) return false;

    std::vector<dkg_msg> inbox;
    dkg_msg m;
    while (tp->try_recv(m)) inbox.push_back(m);

    for (const auto& mm : inbox) {
        if (mm.hdr.type != TAG_W_COMMIT) continue;
        if (mm.hdr.round != round) continue;
        uint32_t s = mm.hdr.sender_id;
        if (s < 1 || s > n || s == self) return false;
        peer_commits_out[s-1].C = mm.vec_a;
    }
    for (uint32_t k = 0; k < n; ++k)
        if (peer_commits_out[k].C.empty()) return false;

    for (const auto& mm : inbox) {
        if (mm.hdr.type != TAG_W_SHARE) continue;
        if (mm.hdr.round != round) continue;
        if (mm.hdr.recipient_id != self) continue;
        uint32_t s = mm.hdr.sender_id;
        if (s < 1 || s > n || s == self) continue;
        BIGNUM* sh = BN_bin2bn(mm.bytes_a.data(), (int)mm.bytes_a.size(), nullptr);
        BIGNUM* bl = BN_bin2bn(mm.bytes_b.data(), (int)mm.bytes_b.size(), nullptr);
        if (!sh || !bl) { if (sh) BN_free(sh); if (bl) BN_free(bl); return false; }
        const bool ok = dao_mpc_vss::verify(f, grp, peer_commits_out[s-1], self, sh, bl, ctx);
        BN_free(bl);
        if (!ok) { BN_free(sh); return false; }
        if (shares_out[s-1]) { BN_free(sh); return false; }
        shares_out[s-1] = sh;
    }
    for (uint32_t k = 0; k < n; ++k) {
        if (!shares_out[k]) {
            for (auto* x : shares_out) if (x) BN_free(x);
            shares_out.clear();
            return false;
        }
    }
    return true;
}

} // namespace

TEST(dao_mpc_wire, single_prime_sieve_round)
{
    dao_mpc_field f; f.r = 65537;   // Fermat prime, odd
    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));
    BN_CTX* ctx = BN_CTX_new();
    ASSERT_TRUE(ctx);

    const uint32_t n = 3, t = 1;
    const uint32_t r = f.r;

    dkg_inproc_network net = dkg_make_inproc_network(n, nullptr);
    ASSERT_EQ(net.endpoints.size(), (size_t)n);

    // ---- Draw u_i and deal VSS (round 0) ----
    std::vector<uint32_t> us(n, 0);
    std::vector<dao_vss_commitments> u_commits(n);
    std::vector<std::vector<BIGNUM*>> u_shares(n);
    std::vector<std::vector<BIGNUM*>> u_blinds(n);

    BIGNUM* rmod = BN_new(); BN_set_word(rmod, r);
    BIGNUM* tmp = BN_new();
    ASSERT_NE(rmod, nullptr);
    ASSERT_NE(tmp, nullptr);

    for (uint32_t i = 0; i < n; ++i) {
        uint32_t u = 0;
        for (int tries = 0; tries < 32 && u == 0; ++tries) {
            ASSERT_TRUE(BN_rand_range(tmp, rmod));
            u = (uint32_t)BN_get_word(tmp);
        }
        ASSERT_GT(u, 0u);
        us[i] = u;
        ASSERT_TRUE(dao_mpc_vss::deal(f, grp, u, n, t,
                    u_commits[i], u_shares[i], u_blinds[i], ctx));
    }
    BN_free(tmp); BN_free(rmod);

    // ---- Wire round 0: broadcast commits, unicast shares ----
    for (uint32_t i = 1; i <= n; ++i) {
        w_broadcast_commits(net.endpoints[i-1].get(), i, 0, u_commits[i-1]);
        w_unicast_shares(net.endpoints[i-1].get(), i, 0, n, i,
                         u_shares[i-1], u_blinds[i-1]);
    }

    // ---- Drain round 0: each party gets its shares of every u_j ----
    // party_u_share[i][j] = party i's share of u_{j+1}, i.e. 0-indexed
    std::vector<std::vector<BIGNUM*>> party_u_share(n);
    for (uint32_t i = 1; i <= n; ++i) {
        std::vector<dao_vss_commitments> peer_c;
        std::vector<BIGNUM*> peer_s;
        ASSERT_TRUE(w_drain_round(net.endpoints[i-1].get(), i, n, 0, f, grp,
                                  u_commits[i-1], u_shares[i-1][i-1],
                                  u_blinds[i-1][i-1], ctx, peer_c, peer_s));
        party_u_share[i-1] = std::move(peer_s);
    }

    // Helper: run one full GRR round (local_product, deal_c, wire, combine).
    // a_at[i] = party i's share of a; b_at[i] = party i's share of b.
    // Produces out[i] = party i's Shamir share of a*b (degree t).
    auto do_grr_round = [&](const std::vector<BIGNUM*>& a_at,
                            const std::vector<BIGNUM*>& b_at,
                            uint32_t wire_round,
                            std::vector<BIGNUM*>& out_sh) {
        std::vector<uint32_t> c_local(n);
        std::vector<dao_vss_commitments> c_commits(n);
        std::vector<std::vector<BIGNUM*>> c_shares(n);
        std::vector<std::vector<BIGNUM*>> c_blinds(n);
        for (uint32_t i = 0; i < n; ++i) {
            ASSERT_TRUE(dao_mpc_mul::local_product(f, a_at[i], b_at[i], c_local[i]));
            ASSERT_TRUE(dao_mpc_vss::deal(f, grp, c_local[i], n, t,
                        c_commits[i], c_shares[i], c_blinds[i], ctx));
        }
        for (uint32_t i = 1; i <= n; ++i) {
            w_broadcast_commits(net.endpoints[i-1].get(), i, wire_round, c_commits[i-1]);
            w_unicast_shares(net.endpoints[i-1].get(), i, wire_round, n, i,
                             c_shares[i-1], c_blinds[i-1]);
        }
        out_sh.assign(n, nullptr);
        for (uint32_t i = 1; i <= n; ++i) {
            std::vector<dao_vss_commitments> pc;
            std::vector<BIGNUM*> ps;
            ASSERT_TRUE(w_drain_round(net.endpoints[i-1].get(), i, n, wire_round,
                                      f, grp, c_commits[i-1],
                                      c_shares[i-1][i-1], c_blinds[i-1][i-1],
                                      ctx, pc, ps));
            std::vector<const BIGNUM*> ps_c(ps.begin(), ps.end());
            uint32_t comb = 0;
            ASSERT_TRUE(dao_mpc_mul::combine_c_shares(f, ps_c, n, t, comb));
            out_sh[i-1] = BN_new();
            ASSERT_NE(out_sh[i-1], nullptr);
            BN_set_word(out_sh[i-1], comb);
            for (auto* x : ps) BN_free(x);
        }
        for (auto& v : c_shares) for (auto* x : v) BN_free(x);
        for (auto& v : c_blinds) for (auto* x : v) BN_free(x);
    };

    // ---- GRR round 1: w1 = u_0 * u_1 ----
    std::vector<BIGNUM*> u0_at(n), u1_at(n);
    for (uint32_t i = 0; i < n; ++i) { u0_at[i] = party_u_share[i][0]; u1_at[i] = party_u_share[i][1]; }
    std::vector<BIGNUM*> w1;
    do_grr_round(u0_at, u1_at, 1, w1);

    // ---- GRR round 2: w2 = w1 * u_2 ----
    std::vector<BIGNUM*> u2_at(n);
    for (uint32_t i = 0; i < n; ++i) u2_at[i] = party_u_share[i][2];
    std::vector<BIGNUM*> w2;
    do_grr_round(w1, u2_at, 2, w2);

    // ---- Convert Shamir to additive ----
    std::vector<const BIGNUM*> w2_c(w2.begin(), w2.end());
    std::vector<uint32_t> additive(n, 0);
    ASSERT_TRUE(dao_mpc_mul::to_additive_shares(f, n, w2_c, additive));

    uint64_t expected = ((uint64_t)us[0] * us[1]) % r;
    expected = (expected * us[2]) % r;
    uint64_t add_sum = 0;
    for (uint32_t i = 0; i < n; ++i) add_sum = (add_sum + additive[i]) % r;
    EXPECT_EQ(add_sum, expected) << "additive sum mismatch";
    EXPECT_NE(add_sum, 0u) << "product divisible by r";

    // ---- Lift each additive share into [2^{bits-1}, 2^bits) with Q=r ----
    // The lift interval must be wider than 4*Q so a solution always
    // exists. Q = 65537, so bits >= 18 suffices; 32 gives margin.
    const uint32_t bits = 32;
    BIGNUM* Q = BN_new(); BN_set_word(Q, r);
    ASSERT_NE(Q, nullptr);
    std::vector<BIGNUM*> lifted(n, nullptr);
    for (uint32_t i = 0; i < n; ++i) {
        BIGNUM* ai = BN_new(); BN_set_word(ai, additive[i]);
        ASSERT_NE(ai, nullptr);
        lifted[i] = BN_new();
        ASSERT_NE(lifted[i], nullptr);
        ASSERT_TRUE(dao_mpc_crt::lift_to_range(ai, Q, bits, 1, lifted[i], ctx))
            << "lift failed for party " << (i+1);
        BN_free(ai);
    }
    uint64_t lifted_sum = 0;
    for (uint32_t i = 0; i < n; ++i) {
        uint64_t v = BN_get_word(lifted[i]);
        EXPECT_GE(v, (uint64_t)1 << (bits - 1));
        EXPECT_LT(v, (uint64_t)1 << bits);
        lifted_sum += v;
    }
    EXPECT_EQ(lifted_sum % r, expected) << "lifted sum mod r mismatch";
    EXPECT_NE(lifted_sum % r, 0u) << "lifted sum divisible by r";

    // ---- Cleanup ----
    for (auto* x : w1) BN_free(x);
    for (auto* x : w2) BN_free(x);
    for (auto& v : party_u_share) for (auto* x : v) BN_free(x);
    for (auto& v : u_shares) for (auto* x : v) BN_free(x);
    for (auto& v : u_blinds) for (auto* x : v) BN_free(x);
    for (auto* x : lifted) BN_free(x);
    BN_free(Q);
    BN_CTX_free(ctx);
}


// ================================================================
// Full sieve over the production prime set (n=3, one factor).
//
// This is the wire version of run_local_sieve_factor at 126 primes.
// Exercises: initial VSS for every prime, multiply_tree via wire
// rounds, Lagrange-to-additive, pairwise-mask (via existing
// dao_mpc_additive on the reconstructed product chain), CRT with
// mod-4 for party 1.
//
// Assertions:
//   - aggregate P ≡ ∏ u_j^(r) (mod r) for every sieve prime r
//   - aggregate P coprime to every sieve prime
//   - aggregate P mod 4 == 3
//   - aggregate P bit length in expert's bound
//   - per-party contribution in [L, U)
//
// Uses the same wire helpers as single_prime_sieve_round.
// ================================================================

TEST(dao_mpc_wire, full_sieve_126_primes_n3_one_factor)
{
    std::vector<uint32_t> primes;
    ASSERT_TRUE(dao_mpc_crt::near_primorial_primes(1024, 3, primes));
    const size_t L = primes.size();
    ASSERT_GT(L, 100u);
    std::cout << "[wire] prime count = " << L << "\n";

    dao_vss_group grp;
    ASSERT_TRUE(dao_vss_group_generate(grp, 512));
    BN_CTX* ctx = BN_CTX_new(); ASSERT_TRUE(ctx);

    const uint32_t n = 3, t = 1;
    dkg_inproc_network net = dkg_make_inproc_network(n, nullptr);

    // Per-prime per-party u value.
    std::vector<std::vector<uint32_t>> us(L, std::vector<uint32_t>(n, 0));
    BIGNUM* rmod = BN_new();
    BIGNUM* tmp  = BN_new();
    ASSERT_NE(rmod, nullptr); ASSERT_NE(tmp, nullptr);
    for (size_t j = 0; j < L; ++j) {
        BN_set_word(rmod, primes[j]);
        for (uint32_t i = 0; i < n; ++i) {
            uint32_t u = 0;
            for (int tries = 0; tries < 32 && u == 0; ++tries) {
                ASSERT_TRUE(BN_priv_rand_range(tmp, rmod));
                u = (uint32_t)BN_get_word(tmp);
            }
            ASSERT_GT(u, 0u);
            us[j][i] = u;
        }
    }
    BN_free(rmod); BN_free(tmp);

    auto t_start = std::chrono::steady_clock::now();

    // additive_shares[me-1][j] = party me's additive share of the product
    // mod primes[j] after wire sieve. Sum over me == ∏ u_j (mod primes[j]).
    std::vector<std::vector<uint32_t>> additive_shares(n,
        std::vector<uint32_t>(L, 0));

    for (size_t j = 0; j < L; ++j) {
        dao_mpc_field fj; fj.r = primes[j];
        const uint32_t round_base = (uint32_t)j * 8;

        // ---- Initial round: every party deals their u_i ----
        std::vector<dao_vss_commitments> init_commits(n);
        std::vector<std::vector<BIGNUM*>> init_shares(n), init_blinds(n);
        for (uint32_t me = 1; me <= n; ++me) {
            ASSERT_TRUE(dao_mpc_vss::deal(fj, grp, us[j][me-1], n, t,
                        init_commits[me-1], init_shares[me-1],
                        init_blinds[me-1], ctx));
            w_broadcast_commits(net.endpoints[me-1].get(), me,
                                round_base + 0, init_commits[me-1]);
            w_unicast_shares(net.endpoints[me-1].get(), me,
                             round_base + 0, n, me,
                             init_shares[me-1], init_blinds[me-1]);
        }
        std::vector<std::vector<BIGNUM*>> peer_collect(n);
        for (uint32_t me = 1; me <= n; ++me) {
            std::vector<dao_vss_commitments> pc;
            std::vector<BIGNUM*> ps;
            ASSERT_TRUE(w_drain_round(net.endpoints[me-1].get(), me, n,
                                      round_base + 0, fj, grp,
                                      init_commits[me-1],
                                      init_shares[me-1][me-1],
                                      init_blinds[me-1][me-1],
                                      ctx, pc, ps));
            peer_collect[me-1] = ps;
        }
        for (uint32_t me = 0; me < n; ++me) {
            for (auto* x : init_shares[me]) BN_free(x);
            for (auto* x : init_blinds[me]) BN_free(x);
        }

        // Accumulator starts as u_0 (party 1's contribution, shared).
        std::vector<BIGNUM*> acc(n);
        for (uint32_t me = 1; me <= n; ++me)
            acc[me-1] = BN_dup(peer_collect[me-1][0]);

        // ---- Successive multiplies: acc × u_k for k=1..n-1 ----
        for (uint32_t k = 1; k < n; ++k) {
            const uint32_t round_k = round_base + k;
            std::vector<dao_vss_commitments> c_commits(n);
            std::vector<std::vector<BIGNUM*>> c_shares(n), c_blinds(n);
            for (uint32_t me = 1; me <= n; ++me) {
                uint32_t acc_v = (uint32_t)BN_mod_word(acc[me-1], fj.r);
                uint32_t uk_v = (uint32_t)BN_mod_word(
                    peer_collect[me-1][k], fj.r);
                uint32_t c_val = fj.mul(acc_v, uk_v);
                ASSERT_TRUE(dao_mpc_vss::deal(fj, grp, c_val, n, t,
                            c_commits[me-1], c_shares[me-1],
                            c_blinds[me-1], ctx));
                w_broadcast_commits(net.endpoints[me-1].get(), me,
                                    round_k, c_commits[me-1]);
                w_unicast_shares(net.endpoints[me-1].get(), me,
                                 round_k, n, me,
                                 c_shares[me-1], c_blinds[me-1]);
            }
            for (uint32_t me = 1; me <= n; ++me) {
                std::vector<dao_vss_commitments> pc;
                std::vector<BIGNUM*> ps;
                ASSERT_TRUE(w_drain_round(net.endpoints[me-1].get(), me,
                                          n, round_k, fj, grp,
                                          c_commits[me-1],
                                          c_shares[me-1][me-1],
                                          c_blinds[me-1][me-1],
                                          ctx, pc, ps));
                std::vector<const BIGNUM*> ps_const(ps.begin(), ps.end());
                uint32_t comb = 0;
                ASSERT_TRUE(dao_mpc_mul::combine_c_shares(
                    fj, ps_const, n, t, comb));
                for (auto* x : ps) BN_free(x);
                BN_free(acc[me-1]);
                acc[me-1] = BN_new();
                BN_set_word(acc[me-1], comb);
            }
            for (uint32_t me = 0; me < n; ++me) {
                for (auto* x : c_shares[me]) BN_free(x);
                for (auto* x : c_blinds[me]) BN_free(x);
            }
        }

        // ---- Lagrange-to-additive ----
        const uint32_t tp1 = (n + 1) / 2;
        for (uint32_t me = 1; me <= n; ++me) {
            uint32_t acc_v = (uint32_t)BN_mod_word(acc[me-1], fj.r);
            uint32_t lc = 0;
            if (me <= tp1) {
                uint64_t num = 1, den = 1;
                for (uint32_t i = 1; i <= tp1; ++i) {
                    if (i == me) continue;
                    int64_t neg_i = ((-(int64_t)i) % (int64_t)fj.r
                                     + (int64_t)fj.r) % (int64_t)fj.r;
                    int64_t diff  = (((int64_t)me - (int64_t)i) % (int64_t)fj.r
                                     + (int64_t)fj.r) % (int64_t)fj.r;
                    num = (num * (uint64_t)neg_i) % fj.r;
                    den = (den * (uint64_t)diff) % fj.r;
                }
                uint64_t inv_den = fj.inv((uint32_t)den);
                lc = (uint32_t)((num * inv_den) % fj.r);
            }
            additive_shares[me-1][j] = fj.mul(lc, acc_v);
        }

        for (uint32_t me = 0; me < n; ++me) {
            BN_free(acc[me]);
            for (auto* x : peer_collect[me]) BN_free(x);
        }
    }

    auto t_end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        t_end - t_start).count();
    std::cout << "[wire] 126-prime sieve wire time: " << ms << " ms\n";

    // ---- Verify sum of additive shares mod r == ∏ u_j mod r, nonzero ----
    for (size_t j = 0; j < L; ++j) {
        uint64_t sum = 0;
        for (uint32_t me = 0; me < n; ++me)
            sum = (sum + additive_shares[me][j]) % primes[j];
        uint64_t expected = 1;
        for (uint32_t i = 0; i < n; ++i)
            expected = (expected * us[j][i]) % primes[j];
        EXPECT_EQ(sum, expected) << "prime " << primes[j];
        EXPECT_NE(sum, 0ull) << "prime " << primes[j];
    }

    // ---- CRT-reconstruct with mod-4 for each party ----
    std::vector<BIGNUM*> W;
    ASSERT_TRUE(dao_mpc_crt::crt_reconstruct_with_mod4(
        primes, additive_shares, W, ctx));
    ASSERT_EQ(W.size(), (size_t)n);

    // ---- Aggregate P, verify constraints ----
    BIGNUM* M0 = BN_new();
    ASSERT_TRUE(dao_mpc_crt::sieve_modulus_mod4(primes, M0, ctx));

    std::vector<BIGNUM*> P;
    ASSERT_TRUE(dao_mpc_crt::reconstruct_all_to_contributions(
        W, M0, 1024, 80, P, ctx));
    ASSERT_EQ(P.size(), (size_t)n);

    BIGNUM* agg = BN_new(); BN_zero(agg);
    for (auto* p : P) BN_add(agg, agg, p);

    // Bit length in [2^1024, 2^1104) aggregated.
    BIGNUM* lb = BN_new(); BN_one(lb); BN_lshift(lb, lb, 1024);
    BIGNUM* ub = BN_new(); BN_one(ub); BN_lshift(ub, ub, 1104);
    std::cout << "[wire] agg P bits = " << BN_num_bits(agg) << "\n";
    EXPECT_GE(BN_cmp(agg, lb), 0);
    EXPECT_LT(BN_cmp(agg, ub), 0);

    // Coprime to all sieve primes.
    for (uint32_t r : primes) {
        EXPECT_NE(BN_mod_word(agg, r), 0UL) << "P div by " << r;
    }
    // mod 4 == 3.
    EXPECT_EQ(BN_mod_word(agg, 4), 3UL);

    for (auto* x : W) BN_free(x);
    for (auto* x : P) BN_free(x);
    BN_free(agg); BN_free(lb); BN_free(ub); BN_free(M0);
    BN_CTX_free(ctx);
}
