#include "dao_sieve_runner.h"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <thread>

namespace cryptonote { namespace dao {

namespace {

constexpr dkg_msg_type SIEVE_COMMIT = static_cast<dkg_msg_type>(0x90);
constexpr dkg_msg_type SIEVE_SHARE  = static_cast<dkg_msg_type>(0x91);
constexpr uint32_t SIEVE_BASE_PHASE = 100;

void fill_hdr(dkg_msg_header& h, uint8_t version, uint32_t candidate_id,
              const uint8_t cid[32], uint32_t sender, uint32_t recipient,
              uint32_t phase, uint32_t round, dkg_msg_type type)
{
    h.version = version;
    h.candidate_id = candidate_id;
    std::memcpy(h.committee_id_hash, cid, 32);
    h.proposal_id = {};
    h.sender_id = sender;
    h.recipient_id = recipient;
    h.phase = phase;
    h.round = round;
    h.sequence = 0;
    h.type = type;
}

bool bn_to_bytes(const BIGNUM* b, std::vector<uint8_t>& out) {
    const int nb = BN_num_bytes(b);
    if (nb <= 0) {
        // Zero value: emit single 0x00 so the wire message is never
        // empty. An empty bytes_a would be indistinguishable from a
        // protocol error and would be dropped by the receiver,
        // stalling the drain for that (prime, sender) pair.
        out.assign(1, 0);
    } else {
        out.assign(nb, 0);
        BN_bn2bin(b, out.data());
    }
    return true;
}

} // namespace

namespace {

// Internal: run one factor's sieve with a caller-owned pending deque
// and explicit phase base. Called by dkg_run_sieve_both_runner.
bool run_one_factor_impl(
    dkg_transport* transport,
    uint32_t n,
    uint32_t threshold,
    uint32_t local_party_id,
    const uint8_t committee_id_hash[32],
    uint32_t candidate_id,
    const std::vector<uint32_t>& primes,
    const dao_vss_group& vss_grp,
    uint8_t factor,
    uint32_t lambda,
    uint32_t sigma,
    uint32_t phase_timeout_s,
    BIGNUM* out_contribution,
    BN_CTX* ctx,
    std::deque<dkg_msg>& pending,
    const char** fail_stage_out)
{
    auto FAIL = [&](const char* stage) -> bool {
        if (fail_stage_out) *fail_stage_out = stage;
        std::fprintf(stderr, "[sieve f%u p%u] FAIL: %s\n",
                     (unsigned)factor, local_party_id, stage);
        // File-based log (defensive against test harness capturing stderr).
        if (FILE* f = std::fopen("sieve_debug.log", "a")) {
            std::fprintf(f, "[f%u p%u] FAIL: %s\n",
                         (unsigned)factor, local_party_id, stage);
            std::fclose(f);
        }
        return false;
    };

    // Diagnostic: log entry/exit for drain stages so we can identify where
    // the pipeline stalls. Writes to sieve_debug.log in cwd.
    auto dbg = [&](const char* tag) {
        if (FILE* f = std::fopen("sieve_debug.log", "a")) {
            std::fprintf(f, "[f%u p%u] %s\n",
                         (unsigned)factor, local_party_id, tag);
            std::fclose(f);
        }
    };

    // Factor-aware drain failure strings.
    static const char* DRAIN_FAIL_STR[2][5] = {
        {"drain_l0_f0","drain_l1_f0","drain_l2_f0","drain_l3_f0","drain_l4_f0"},
        {"drain_l0_f1","drain_l1_f1","drain_l2_f1","drain_l3_f1","drain_l4_f1"},
    };
    auto drain_fail = [&](uint32_t lvl) -> const char* {
        if (lvl > 4) return "drain_lx_f?";
        return DRAIN_FAIL_STR[factor][lvl];
    };

    if (!transport || !out_contribution || !ctx) return FAIL("precondition");
    if (n < 3 || threshold < 2 || factor > 1) return FAIL("precondition_n");
    if (local_party_id < 1 || local_party_id > n) return FAIL("precondition_pid");
    const uint32_t t = threshold - 1;
    const size_t L = primes.size();
    if (L == 0) return FAIL("precondition_primes");
    const uint32_t tp1 = (n + 1) / 2;

    const uint32_t base_phase = SIEVE_BASE_PHASE + factor;

    // ---- drain implementation ----
    // Filters by phase first (future factors are buffered here), then
    // by level. Both are needed because P-factor and Q-factor sieves
    // can overlap across peers.
    auto drain = [&](uint32_t level,
                     std::vector<std::vector<dao_vss_commitments>>& commits,
                     std::vector<std::vector<std::vector<BIGNUM*>>>& shares,
                     const std::vector<dao_vss_commitments>& my_commits,
                     const std::vector<std::vector<BIGNUM*>>& my_shares) -> bool
    {
        for (size_t j = 0; j < L; ++j) {
            commits[j][local_party_id - 1] = my_commits[j];
            shares[j][local_party_id - 1].assign(n, nullptr);
            for (uint32_t k = 0; k < n; ++k) {
                if (shares[j][local_party_id - 1][k])
                    BN_free(shares[j][local_party_id - 1][k]);
                shares[j][local_party_id - 1][k] = BN_dup(my_shares[j][k]);
            }
        }

        auto complete = [&]() -> bool {
            for (size_t j = 0; j < L; ++j) {
                for (uint32_t k = 1; k <= n; ++k) {
                    if (k == local_party_id) continue;
                    if (commits[j][k - 1].C.empty()) return false;
                    if (shares[j][k - 1].size() != n) return false;
                    if (!shares[j][k - 1][local_party_id - 1]) return false;
                }
            }
            return true;
        };

        auto apply = [&](dkg_msg& m) -> bool {
            if (m.hdr.candidate_id != candidate_id) return false;
            if (std::memcmp(m.hdr.committee_id_hash, committee_id_hash, 32) != 0)
                return false;
            const uint32_t j = m.hdr.round;
            if (j >= L) return false;
            const uint32_t s = m.hdr.sender_id;
            if (s < 1 || s > n || s == local_party_id) return false;
            if (m.hdr.type == SIEVE_COMMIT) {
                commits[j][s - 1].C = m.vec_a;
                return true;
            }
            if (m.hdr.type == SIEVE_SHARE) {
                if (m.hdr.recipient_id != local_party_id) return false;
                // Empty bytes_a means peer used an older bn_to_bytes that
                // emitted nothing for zero. Treat as zero share.
                BIGNUM* sh = nullptr;
                if (m.bytes_a.empty()) {
                    sh = BN_new();
                    if (sh) BN_zero(sh);
                } else {
                    sh = BN_bin2bn(m.bytes_a.data(),
                                   (int)m.bytes_a.size(), nullptr);
                }
                if (!sh) return false;
                if (shares[j][s - 1].size() != n)
                    shares[j][s - 1].assign(n, nullptr);
                if (shares[j][s - 1][local_party_id - 1])
                    BN_free(shares[j][s - 1][local_party_id - 1]);
                shares[j][s - 1][local_party_id - 1] = sh;
                return true;
            }
            return false;
        };

        // Process pending first. Filter by phase, then level.
        for (auto it = pending.begin(); it != pending.end();) {
            if (it->hdr.phase < base_phase) { it = pending.erase(it); continue; }
            if (it->hdr.phase > base_phase) { ++it; continue; }
            if (it->tag32 < level) { it = pending.erase(it); continue; }
            if (it->tag32 > level) { ++it; continue; }
            dkg_msg m = std::move(*it);
            it = pending.erase(it);
            apply(m);
        }

        auto dl = std::chrono::steady_clock::now()
                + std::chrono::seconds(phase_timeout_s);
        while (!complete()) {
            if (std::chrono::steady_clock::now() >= dl) return false;
            dkg_msg m;
            bool got = transport->try_recv(m);
            if (!got) got = transport->try_recv_own(m);
            if (!got) {
                std::this_thread::sleep_for(std::chrono::milliseconds(3));
                continue;
            }
            if (m.hdr.phase < base_phase) continue;              // stale factor
            if (m.hdr.phase > base_phase) {                      // future factor
                pending.push_back(std::move(m));
                continue;
            }
            if (m.tag32 < level) continue;                       // stale level
            if (m.tag32 > level) { pending.push_back(std::move(m)); continue; }
            apply(m);
        }
        return true;
    };

    // ---- Level 0 ----
    std::vector<std::vector<BIGNUM*>> my_u_shares(L);
    std::vector<std::vector<BIGNUM*>> my_u_blinds(L);
    std::vector<dao_vss_commitments> my_u_commits(L);
    BIGNUM* rmod = BN_new();
    BIGNUM* tmp  = BN_new();
    if (!rmod || !tmp) { BN_free(rmod); BN_free(tmp); return FAIL("rng_init"); }
    for (size_t j = 0; j < L; ++j) {
        dao_mpc_field fj; fj.r = primes[j];
        BN_set_word(rmod, primes[j]);
        uint32_t u = 0;
        for (int tries = 0; tries < 32 && u == 0; ++tries) {
            if (!BN_priv_rand_range(tmp, rmod)) {
                BN_free(rmod); BN_free(tmp);
                for (auto& v : my_u_shares) for (auto* x : v) BN_free(x);
                for (auto& v : my_u_blinds) for (auto* x : v) BN_free(x);
                return FAIL("rng_u");
            }
            u = (uint32_t)BN_get_word(tmp);
        }
        if (u == 0 ||
            !dao_mpc_vss::deal(fj, vss_grp, u, n, t,
                               my_u_commits[j], my_u_shares[j],
                               my_u_blinds[j], ctx)) {
            BN_free(rmod); BN_free(tmp);
            for (auto& v : my_u_shares) for (auto* x : v) BN_free(x);
            for (auto& v : my_u_blinds) for (auto* x : v) BN_free(x);
            return FAIL("vss_deal_u");
        }
    }
    BN_free(rmod); BN_free(tmp);

    // Send level 0.
    for (size_t j = 0; j < L; ++j) {
        dkg_msg cm;
        fill_hdr(cm.hdr, 2, candidate_id, committee_id_hash,
                 local_party_id, 0, base_phase, (uint32_t)j, SIEVE_COMMIT);
        cm.tag32 = 0;
        for (const auto& cc : my_u_commits[j].C) cm.vec_a.push_back(cc);
        if (!transport->send(cm)) {
            for (auto& v : my_u_shares) for (auto* x : v) BN_free(x);
            for (auto& v : my_u_blinds) for (auto* x : v) BN_free(x);
            return FAIL("send_l0_commit");
        }
        for (uint32_t k = 1; k <= n; ++k) {
            if (k == local_party_id) continue;
            dkg_msg sm;
            fill_hdr(sm.hdr, 2, candidate_id, committee_id_hash,
                     local_party_id, k, base_phase, (uint32_t)j, SIEVE_SHARE);
            sm.tag32 = 0;
            bn_to_bytes(my_u_shares[j][k - 1], sm.bytes_a);
            bn_to_bytes(my_u_blinds[j][k - 1], sm.bytes_b);
            if (!transport->send(sm)) {
                for (auto& v : my_u_shares) for (auto* x : v) BN_free(x);
                for (auto& v : my_u_blinds) for (auto* x : v) BN_free(x);
                return FAIL("send_l0_share");
            }
        }
    }

    // Drain level 0.
    std::vector<std::vector<dao_vss_commitments>> u_commits(
        L, std::vector<dao_vss_commitments>(n));
    std::vector<std::vector<std::vector<BIGNUM*>>> u_shares(
        L, std::vector<std::vector<BIGNUM*>>(n));
    dbg("drain_l0_enter");
    if (!drain(0, u_commits, u_shares, my_u_commits, my_u_shares)) {
        dbg("drain_l0_FAIL");
        for (auto& v : my_u_shares) for (auto* x : v) BN_free(x);
        for (auto& v : my_u_blinds) for (auto* x : v) BN_free(x);
        for (auto& v : u_shares) for (auto& vv : v) for (auto* x : vv) BN_free(x);
        return FAIL(drain_fail(0));
    }
    dbg("drain_l0_done");
    for (auto& v : my_u_shares) for (auto* x : v) BN_free(x);
    for (auto& v : my_u_blinds) for (auto* x : v) BN_free(x);

    // ---- Accumulator: single BIGNUM per prime (own share only) ----
    std::vector<BIGNUM*> acc(L, nullptr);
    for (size_t j = 0; j < L; ++j) {
        acc[j] = BN_dup(u_shares[j][0][local_party_id - 1]);
        if (!acc[j]) {
            for (auto* a : acc) if (a) BN_free(a);
            for (auto& v : u_shares) for (auto& vv : v) for (auto* x : vv) BN_free(x);
            return FAIL("acc_seed");
        }
    }

    // ---- Levels 1..n-1 ----
    for (uint32_t level = 1; level < n; ++level) {
        std::vector<std::vector<BIGNUM*>> c_shares(L);
        std::vector<std::vector<BIGNUM*>> c_blinds(L);
        std::vector<dao_vss_commitments> c_commits(L);
        for (size_t j = 0; j < L; ++j) {
            dao_mpc_field fj; fj.r = primes[j];
            const uint32_t acc_v = (uint32_t)BN_mod_word(acc[j], fj.r);
            const uint32_t u_v = (uint32_t)BN_mod_word(
                u_shares[j][level][local_party_id - 1], fj.r);
            const uint32_t c_val = fj.mul(acc_v, u_v);
            if (!dao_mpc_vss::deal(fj, vss_grp, c_val, n, t,
                                   c_commits[j], c_shares[j], c_blinds[j],
                                   ctx)) {
                for (auto& v : c_shares) for (auto* x : v) BN_free(x);
                for (auto& v : c_blinds) for (auto* x : v) BN_free(x);
                for (auto* a : acc) BN_free(a);
                for (auto& v : u_shares) for (auto& vv : v) for (auto* x : vv) BN_free(x);
                return FAIL("vss_deal_c");
            }
        }
        for (size_t j = 0; j < L; ++j) {
            dkg_msg cm;
            fill_hdr(cm.hdr, 2, candidate_id, committee_id_hash,
                     local_party_id, 0, base_phase, (uint32_t)j, SIEVE_COMMIT);
            cm.tag32 = level;
            for (const auto& cc : c_commits[j].C) cm.vec_a.push_back(cc);
            if (!transport->send(cm)) {
                for (auto& v : c_shares) for (auto* x : v) BN_free(x);
                for (auto& v : c_blinds) for (auto* x : v) BN_free(x);
                for (auto* a : acc) BN_free(a);
                for (auto& v : u_shares) for (auto& vv : v) for (auto* x : vv) BN_free(x);
                return FAIL("send_lN_commit");
            }
            for (uint32_t k = 1; k <= n; ++k) {
                if (k == local_party_id) continue;
                dkg_msg sm;
                fill_hdr(sm.hdr, 2, candidate_id, committee_id_hash,
                         local_party_id, k, base_phase, (uint32_t)j, SIEVE_SHARE);
                sm.tag32 = level;
                bn_to_bytes(c_shares[j][k - 1], sm.bytes_a);
                bn_to_bytes(c_blinds[j][k - 1], sm.bytes_b);
                if (!transport->send(sm)) {
                    for (auto& v : c_shares) for (auto* x : v) BN_free(x);
                    for (auto& v : c_blinds) for (auto* x : v) BN_free(x);
                    for (auto* a : acc) BN_free(a);
                    for (auto& v : u_shares) for (auto& vv : v) for (auto* x : vv) BN_free(x);
                    return FAIL("send_lN_share");
                }
            }
        }
        std::vector<std::vector<dao_vss_commitments>> c_commits_peer(
            L, std::vector<dao_vss_commitments>(n));
        std::vector<std::vector<std::vector<BIGNUM*>>> c_shares_peer(
            L, std::vector<std::vector<BIGNUM*>>(n));
        {
            char tag[32];
            std::snprintf(tag, sizeof(tag), "drain_l%u_enter", level);
            dbg(tag);
        }
        if (!drain(level, c_commits_peer, c_shares_peer, c_commits, c_shares)) {
            {
                char tag[32];
                std::snprintf(tag, sizeof(tag), "drain_l%u_FAIL", level);
                dbg(tag);
            }
            for (auto& v : c_shares) for (auto* x : v) BN_free(x);
            for (auto& v : c_blinds) for (auto* x : v) BN_free(x);
            for (auto& v : c_shares_peer) for (auto& vv : v) for (auto* x : vv) BN_free(x);
            for (auto* a : acc) BN_free(a);
            for (auto& v : u_shares) for (auto& vv : v) for (auto* x : vv) BN_free(x);
            return FAIL(drain_fail(level));
        }
        {
            char tag[32];
            std::snprintf(tag, sizeof(tag), "drain_l%u_done", level);
            dbg(tag);
        }
        for (auto& v : c_shares) for (auto* x : v) BN_free(x);
        for (auto& v : c_blinds) for (auto* x : v) BN_free(x);

        for (size_t j = 0; j < L; ++j) {
            dao_mpc_field fj; fj.r = primes[j];
            std::vector<const BIGNUM*> ps(n);
            for (uint32_t k = 0; k < n; ++k)
                ps[k] = c_shares_peer[j][k][local_party_id - 1];
            uint32_t comb = 0;
            if (!dao_mpc_mul::combine_c_shares(fj, ps, n, t, comb)) {
                for (auto& v : c_shares_peer) for (auto& vv : v) for (auto* x : vv) BN_free(x);
                for (auto* a : acc) BN_free(a);
                for (auto& v : u_shares) for (auto& vv : v) for (auto* x : vv) BN_free(x);
                return FAIL("combine_c");
            }
            BN_free(acc[j]);
            acc[j] = BN_new();
            BN_set_word(acc[j], comb);
        }
        for (auto& v : c_shares_peer) for (auto& vv : v) for (auto* x : vv) BN_free(x);
    }

    // ---- Party-local Lagrange-at-zero. ----
    // My share of the aggregate polynomial g has degree t; g(0)=∏u.
    // Each party computes L_local(0) * g(local) using the t+1 point set
    // {1..t+1}. Sum over parties = g(0).
    std::vector<std::vector<uint32_t>> additive(n, std::vector<uint32_t>(L, 0));
    for (size_t j = 0; j < L; ++j) {
        dao_mpc_field fj; fj.r = primes[j];
        const uint32_t my_share =
            (uint32_t)BN_mod_word(acc[j], fj.r);
        uint32_t L_local = 0;
        if (local_party_id <= tp1) {
            uint64_t num = 1, den = 1;
            for (uint32_t i = 1; i <= tp1; ++i) {
                if (i == local_party_id) continue;
                int64_t neg_i = ((-(int64_t)i) % (int64_t)fj.r
                                 + (int64_t)fj.r) % (int64_t)fj.r;
                int64_t diff  = (((int64_t)local_party_id - (int64_t)i)
                                 % (int64_t)fj.r + (int64_t)fj.r)
                                 % (int64_t)fj.r;
                num = (num * (uint64_t)neg_i) % fj.r;
                den = (den * (uint64_t)diff) % fj.r;
            }
            uint64_t inv_den = fj.inv((uint32_t)den);
            L_local = (uint32_t)((num * inv_den) % fj.r);
        }
        additive[local_party_id - 1][j] = fj.mul(L_local, my_share);
    }
    for (auto* a : acc) BN_free(a);
    for (auto& v : u_shares) for (auto& vv : v) for (auto* x : vv) BN_free(x);

    // ---- CRT, lift ----
    std::vector<BIGNUM*> W;
    if (!dao_mpc_crt::crt_reconstruct_with_mod4(primes, additive, W, ctx)) {
        return FAIL("crt_reconstruct");
    }
    BIGNUM* M0 = BN_new();
    if (!M0 || !dao_mpc_crt::sieve_modulus_mod4(primes, M0, ctx)) {
        for (auto* w : W) BN_free(w);
        if (M0) BN_free(M0);
        return FAIL("sieve_modulus");
    }
    bool r = dao_mpc_crt::reconstruct_to_contribution(
        W[local_party_id - 1], M0, lambda, sigma, n, out_contribution, ctx);
    for (auto* w : W) BN_free(w);
    BN_free(M0);
    if (!r) return FAIL("lift");
    return true;
}

} // anonymous namespace

bool dkg_run_sieve_both_runner(
    dkg_transport* transport,
    uint32_t n,
    uint32_t threshold,
    uint32_t local_party_id,
    const uint8_t committee_id_hash[32],
    uint32_t candidate_id,
    const std::vector<uint32_t>& primes,
    const dao_vss_group& vss_grp,
    uint32_t lambda,
    uint32_t sigma,
    uint32_t phase_timeout_s,
    BIGNUM* out_p,
    BIGNUM* out_q,
    BN_CTX* ctx,
    const char** fail_stage_out)
{
    if (fail_stage_out) *fail_stage_out = nullptr;
    if (!out_p || !out_q) {
        if (fail_stage_out) *fail_stage_out = "out_null";
        return false;
    }

    std::deque<dkg_msg> pending;

    if (!run_one_factor_impl(transport, n, threshold, local_party_id,
                             committee_id_hash, candidate_id, primes,
                             vss_grp, /*factor=*/0, lambda, sigma,
                             phase_timeout_s, out_p, ctx, pending,
                             fail_stage_out)) {
        return false;
    }
    if (!run_one_factor_impl(transport, n, threshold, local_party_id,
                             committee_id_hash, candidate_id, primes,
                             vss_grp, /*factor=*/1, lambda, sigma,
                             phase_timeout_s, out_q, ctx, pending,
                             fail_stage_out)) {
        return false;
    }
    return true;
}

}} // namespace
