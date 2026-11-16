// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_cl_reshare_runner.h"

#ifdef VEILROOT_ENABLE_CL

#include "governance/dao_cl_dkg_payload.h"

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/bicycl/cl/CL_threshold.hpp"

#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <thread>

#include <algorithm>
#include <atomic>
#include <openssl/sha.h>

namespace cryptonote {
namespace dao {

namespace {

using namespace BICYCL;

Mpz mpz_from_signed_wire(const std::vector<uint8_t>& in)
{
    if (in.size() < 5) return Mpz();
    uint32_t len = (static_cast<uint32_t>(in[1]) << 24)
                 | (static_cast<uint32_t>(in[2]) << 16)
                 | (static_cast<uint32_t>(in[3]) <<  8)
                 |  static_cast<uint32_t>(in[4]);
    if (in.size() != 5u + len) return Mpz();
    if (len == 0) return Mpz();
    std::vector<unsigned char> mag(in.begin() + 5, in.end());
    Mpz v(mag);
    if (in[0] == 1) v.neg();
    return v;
}

} // namespace

struct cl_reshare_p2p_runner::impl
{
    cl_reshare_config cfg;
    std::unique_ptr<dkg_transport> transport;

    std::unique_ptr<CL_Threshold_Static> old_party;
    std::unique_ptr<CL_Threshold_Static> new_party;

    CL_Threshold_Static::ParticipantsSet old_set;
    CL_Threshold_Static::ParticipantsValueMap<QFI> old_gammas;
    CL_HSMqk::PublicKey old_pk;
    Mpz D;

    RandGen randgen;

    // Broadcast buffer keyed by dealer id.
    std::map<uint32_t, CL_Threshold_Static::ResharePreState> prestates;
    std::map<uint32_t, cl_reshare_contribution_wire> public_contribs;
    std::map<uint32_t, Mpz> private_shares;

    // reshare_complete broadcasts from new members, keyed by the
    // sender's new-committee index (0-based). An old-only
    // contributor accepts the new Gamma map + qualified ids once
    // new_threshold senders agree on the same payload.
    std::map<uint32_t,
             std::pair<std::vector<uint8_t>, std::vector<uint32_t>>>
        complete_msgs;

    std::mutex mu;
    std::condition_variable cv;
    bool running   = false;
    bool finished  = false;
    bool shutdown  = false;
    cl_reshare_result result;
    std::thread worker;

    // Count of unique public-dealer contributions accepted. Updated
    // from the worker thread, read from contribution_count_for_test()
    // on the caller thread: atomic.
    std::atomic<size_t> accepted_public_count{0};

    uint32_t old_local_1based() const { return cfg.old_local_id + 1; }
    uint32_t new_local_1based() const { return cfg.new_local_id + 1; }

    void seed_randgen()
    {
        if (cfg.test_seed != 0) {
            randgen.set_seed(Mpz(static_cast<unsigned long>(cfg.test_seed)));
        } else {
            std::random_device rd;
            randgen.set_seed(Mpz(static_cast<unsigned long>(rd())));
        }
    }

    bool send_broadcast(const cl_dkg_payload& p)
    {
        dkg_msg m;
        m.hdr.version = 2;
        m.hdr.proposal_id = cfg.proposal_id;
        m.hdr.sender_id = old_local_1based();  // old-committee numbering
        m.hdr.recipient_id = 0;
        m.hdr.type = dkg_msg_type::cl_dkg_envelope;
        if (!p.serialize(m.bytes_a)) return false;
        return transport->send(m);
    }

    bool send_broadcast_as_new(const cl_dkg_payload& p)
    {
        dkg_msg m;
        m.hdr.version = 2;
        m.hdr.proposal_id = cfg.proposal_id;
        m.hdr.sender_id = new_local_1based();
        m.hdr.recipient_id = 0;
        m.hdr.type = dkg_msg_type::cl_dkg_envelope;
        if (!p.serialize(m.bytes_a)) return false;
        return transport->send(m);
    }

    bool send_unicast(uint32_t peer_1based, const cl_dkg_payload& p)
    {
        dkg_msg m;
        m.hdr.version = 2;
        m.hdr.proposal_id = cfg.proposal_id;
        m.hdr.sender_id = old_local_1based();
        m.hdr.recipient_id = peer_1based;
        m.hdr.type = dkg_msg_type::cl_dkg_envelope;
        if (!p.serialize(m.bytes_a)) return false;
        return transport->send(m);
    }

    void mark_finished(bool ok)
    {
        std::lock_guard<std::mutex> lk(mu);
        result.ok = ok;
        finished = true;
        running  = false;
        cv.notify_all();
    }

    bool should_stop()
    {
        std::lock_guard<std::mutex> lk(mu);
        return shutdown;
    }

    bool decode_config_state()
    {
        // D
        D = mpz_from_signed_wire(cfg.D_signed);
        if (D.is_zero()) return false;

        // Old pk
        QFI pk_qfi;
        {
            std::size_t off = 0;
            if (!cl_dkg_qfi_from_bytes(cfg.old_pk_qfi, off, pk_qfi,
                                       cfg.cl->Cl_G().discriminant()))
                return false;
            if (off != cfg.old_pk_qfi.size()) return false;
        }
        old_pk = CL_HSMqk::PublicKey(*cfg.cl, pk_qfi);

        // Old gammas
        if (!cl_dkg_deserialize_gammas(
                cfg.old_gammas_serialized,
                cfg.cl->Cl_G().discriminant(), old_gammas))
            return false;

        // Old set
        old_set.clear();
        for (uint32_t i : cfg.old_contributors) old_set.insert(i);

        return true;
    }

    bool prepare_old_party()
    {
        old_party = std::make_unique<CL_Threshold_Static>(
            *cfg.cl, cfg.old_n, cfg.old_t_internal, cfg.old_local_id,
            cfg.soundness_bytes, D);
        Mpz share = mpz_from_signed_wire(cfg.old_share_bytes);
        // Restore against the CL-qualified set, not all old committee
        // indices. A node's Gamma value may be absent for old members
        // that were not qualified in the DKG.
        CL_Threshold_Static::ParticipantsSet qualified;
        for (uint32_t q : cfg.old_qualified_ids) qualified.insert(q);
        if (!old_party->restore_decryption_state(
                *cfg.cl, old_pk, old_gammas, qualified, share))
            return false;
        return true;
    }

    // Structural preflight executed once in start(). Returns false on
    // any malformed or inconsistent config. Does not touch crypto
    // state; the protocol-decode checks in run() remain authoritative.
    bool validate_config()
    {
        if (!cfg.cl) return false;
        if (cfg.old_n == 0 || cfg.old_t_internal >= cfg.old_n) return false;
        if (cfg.new_n == 0 || cfg.new_t_internal >= cfg.new_n) return false;
        if (cfg.old_contributors.empty()) return false;
        if (cfg.old_contributors.size() <
                static_cast<size_t>(cfg.old_t_internal) + 1)
            return false;
        for (size_t i = 0; i < cfg.old_contributors.size(); ++i) {
            uint32_t v = cfg.old_contributors[i];
            if (v >= cfg.old_n) return false;
            if (i > 0 && v <= cfg.old_contributors[i - 1]) return false;
        }
        if (cfg.old_qualified_ids.empty()) return false;
        for (size_t i = 0; i < cfg.old_qualified_ids.size(); ++i) {
            uint32_t v = cfg.old_qualified_ids[i];
            if (v >= cfg.old_n) return false;
            if (i > 0 && v <= cfg.old_qualified_ids[i - 1]) return false;
        }
        for (uint32_t c : cfg.old_contributors) {
            if (std::find(cfg.old_qualified_ids.begin(),
                           cfg.old_qualified_ids.end(), c)
                == cfg.old_qualified_ids.end())
                return false;
        }
        if (cfg.D_signed.empty()) return false;
        if (cfg.old_pk_qfi.empty()) return false;
        if (cfg.old_gammas_serialized.empty()) return false;
        if (cfg.old_share_set_id == 0) return false;
        if (cfg.old_committee_id_hash.size() != 32) return false;
        if (cfg.new_committee_id_hash.size() != 32) return false;
        bool sid_nonzero = false;
        for (int i = 0; i < 32; ++i) if (cfg.session_id.data[i]) {
            sid_nonzero = true; break;
        }
        if (!sid_nonzero) return false;
        if (!cfg.is_old_contributor && !cfg.is_new_member) return false;
        if (cfg.is_old_contributor) {
            if (cfg.old_local_id >= cfg.old_n) return false;
            if (cfg.old_share_bytes.empty()) return false;
            if (std::find(cfg.old_contributors.begin(),
                           cfg.old_contributors.end(),
                           cfg.old_local_id)
                == cfg.old_contributors.end())
                return false;
        }
        if (cfg.is_new_member) {
            if (cfg.new_local_id >= cfg.new_n) return false;
        }
        // Qualified ids must exactly match the old Gamma map keys.
        CL_Threshold_Static::ParticipantsValueMap<QFI> gammas;
        if (!cl_dkg_deserialize_gammas(cfg.old_gammas_serialized,
                cfg.cl->Cl_G().discriminant(), gammas))
            return false;
        if (gammas.size() != cfg.old_qualified_ids.size()) return false;
        for (uint32_t q : cfg.old_qualified_ids)
            if (gammas.count(q) == 0) return false;
        return true;
    }

    void prepare_new_party()
    {
        new_party = std::make_unique<CL_Threshold_Static>(
            *cfg.cl, cfg.new_n, cfg.new_t_internal, cfg.new_local_id,
            cfg.soundness_bytes, D);
        new_party->begin_reshare(old_set, cfg.old_n, cfg.old_t_internal);
    }

    bool process_inbound(const dkg_msg& m)
    {
        if (m.hdr.type != dkg_msg_type::cl_dkg_envelope) return true;
        if (m.hdr.version != 2) return true;
        if (m.hdr.proposal_id != cfg.proposal_id) return true;
        if (m.hdr.sender_id == 0) return true;
        if (m.hdr.recipient_id != 0 && m.hdr.recipient_id != new_local_1based())
            return true;

        cl_dkg_payload p;
        if (!cl_dkg_payload::deserialize(m.bytes_a, p)) return true;

        switch (p.subtype) {
        case cl_dkg_subtype::reshare_prestate: {
            crypto::hash got_sid{};
            uint32_t dealer_id = 0;
            CL_Threshold_Static::ResharePreState pre;
            if (!cl_dkg_decode_reshare_prestate(
                    p, got_sid, dealer_id, pre.q_i, pre.r_i, pre.L_i))
                return false;
            if (got_sid != cfg.session_id) return true;   // stale: drop
            if (dealer_id != m.hdr.sender_id - 1) return true;
            if (old_set.count(dealer_id) == 0) return true;
            prestates[dealer_id] = std::move(pre);
            return true;
        }
        case cl_dkg_subtype::reshare_contribution: {
            crypto::hash got_sid{};
            cl_reshare_contribution_wire w;
            if (!cl_dkg_decode_reshare_contribution(
                    p, cfg.cl->Cl_G().discriminant(),
                    cfg.new_t_internal + 1u, got_sid, w))
                return false;
            if (got_sid != cfg.session_id) return true;   // stale: drop
            if (w.dealer_id != m.hdr.sender_id - 1) return true;
            if (old_set.count(w.dealer_id) == 0) return true;
            if (public_contribs.emplace(w.dealer_id, std::move(w)).second)
                accepted_public_count.fetch_add(1);
            return true;
        }
        case cl_dkg_subtype::reshare_private_share: {
            if (m.hdr.sender_id == 0) return true;
            if (m.hdr.recipient_id != new_local_1based()) return true;
            uint32_t dealer_id = m.hdr.sender_id - 1;
            if (old_set.count(dealer_id) == 0) return true;
            crypto::hash got_sid{};
            Mpz share;
            if (!cl_dkg_decode_reshare_private_share(p, got_sid, share))
                return false;
            if (got_sid != cfg.session_id) return true;   // stale: drop
            private_shares[dealer_id] = std::move(share);
            return true;
        }
        case cl_dkg_subtype::reshare_complete: {
            crypto::hash got_sid{};
            std::vector<uint8_t> gammas_wire;
            std::vector<uint32_t> qualified_ids;
            if (!cl_dkg_decode_reshare_complete(
                    p, got_sid, gammas_wire, qualified_ids))
                return false;
            if (got_sid != cfg.session_id) return true;   // stale: drop
            if (m.hdr.sender_id == 0) return true;
            if (m.hdr.sender_id > cfg.new_n) return true;
            if (gammas_wire.empty() || qualified_ids.empty()) return true;
            for (size_t i = 0; i < qualified_ids.size(); ++i) {
                if (qualified_ids[i] >= cfg.new_n) return true;
                if (i > 0 && qualified_ids[i] <= qualified_ids[i - 1])
                    return true;
            }
            complete_msgs[m.hdr.sender_id - 1] =
                {std::move(gammas_wire), std::move(qualified_ids)};
            return true;
        }
        default:
            return true;
        }
    }

    bool all_prestates_received() const
    {
        if (cfg.old_contributors.empty()) return false;
        if (prestates.size() < cfg.old_contributors.size()) return false;
        for (uint32_t d : cfg.old_contributors)
            if (prestates.count(d) == 0) return false;
        return true;
    }

    bool all_contribs_installed() const
    {
        if (!cfg.is_new_member) return true;
        if (public_contribs.size() < cfg.old_contributors.size()) return false;
        if (private_shares.size() < cfg.old_contributors.size()) return false;
        for (uint32_t d : cfg.old_contributors)
            if (public_contribs.count(d) == 0) return false;
        for (uint32_t d : cfg.old_contributors)
            if (private_shares.count(d) == 0) return false;
        return true;
    }

    bool install_new_contribution(uint32_t dealer_id)
    {
        const auto& w = public_contribs.at(dealer_id);
        const auto& sh = private_shares.at(dealer_id);

        CLBatchDlogAoKExposed batch(w.batch_u, w.batch_R);
        CLDlogEqAoKExposed link(w.link_u, w.link_R1, w.link_R2);

        try {
            new_party->add_reshare_contribution(
                *cfg.cl, dealer_id, sh,
                w.c_i, w.r_i, w.L_i,
                w.commitments, batch, link,
                old_gammas.at(dealer_id));
            return true;
        } catch (...) {
            return false;
        }
    }

    size_t complete_threshold_count() const
    {
        std::map<std::pair<std::vector<uint8_t>, std::vector<uint32_t>>,
                 size_t> tally;
        for (const auto& kv : complete_msgs) tally[kv.second]++;
        size_t best = 0;
        for (const auto& kv : tally) if (kv.second > best) best = kv.second;
        return best;
    }

    bool fill_result()
    {
        result.has_local_new_share = false;
        result.pk_qfi = cfg.old_pk_qfi;   // carry through unconditionally
        if (!cfg.is_new_member) {
            // Old-only contributor: no new local private share, but
            // the public Gamma map and qualified ids are required
            // for future validation. They are published by the new
            // committee via reshare_complete broadcasts and accepted
            // here once new_threshold senders agree.
            std::map<std::pair<std::vector<uint8_t>, std::vector<uint32_t>>,
                     size_t> tally;
            for (const auto& kv : complete_msgs) tally[kv.second]++;
            const uint32_t new_threshold = cfg.new_t_internal + 1;
            for (const auto& kv : tally) {
                if (kv.second < new_threshold) continue;
                result.new_gammas_serialized = kv.first.first;
                result.qualified_ids = kv.first.second;
                return true;
            }
            return false;
        }
        if (!new_party) return false;

        result.new_share_bytes.clear();
        if (!new_party->serialize_secret_share(result.new_share_bytes))
            return false;
        if (result.new_share_bytes.empty()) return false;

        result.new_gammas_serialized.clear();
        if (!cl_dkg_serialize_gammas(new_party->Gammas(),
                                     result.new_gammas_serialized))
            return false;
        if (result.new_gammas_serialized.empty()) return false;

        result.qualified_ids.clear();
        for (unsigned int id : new_party->QualifiedPlayerSet())
            result.qualified_ids.push_back(id);
        std::sort(result.qualified_ids.begin(), result.qualified_ids.end());
        if (result.qualified_ids.empty()) return false;
        for (size_t i = 1; i < result.qualified_ids.size(); ++i)
            if (result.qualified_ids[i] <= result.qualified_ids[i - 1])
                return false;
        for (uint32_t q : result.qualified_ids)
            if (q >= cfg.new_n) return false;

        result.pk_qfi.clear();
        if (!cl_dkg_qfi_to_bytes(result.pk_qfi, new_party->pk().elt()))
            return false;
        if (result.pk_qfi != cfg.old_pk_qfi) return false;

        result.has_local_new_share = true;
        return true;
    }

    void run()
    {
        if (!decode_config_state()) { mark_finished(false); return; }
        if (cfg.is_old_contributor && !prepare_old_party())
        { mark_finished(false); return; }
        if (cfg.is_new_member) prepare_new_party();

        const auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::seconds(cfg.phase_timeout_seconds);

        // --- Phase 1: exchange prestates ---
        if (cfg.is_old_contributor) {
            auto pre = old_party->compute_reshare_prestate(old_set);
            prestates[cfg.old_local_id] = pre;

            cl_dkg_payload out;
            if (!cl_dkg_encode_reshare_prestate(
                    cfg.session_id, cfg.old_local_id,
                    pre.q_i, pre.r_i, pre.L_i, out))
            { mark_finished(false); return; }
            if (!send_broadcast(out)) { mark_finished(false); return; }
        }
        while (!all_prestates_received()) {
            if (should_stop())       { mark_finished(false); return; }
            if (now_reached(deadline)){ mark_finished(false); return; }
            dkg_msg m;
            if (transport->try_recv(m)) {
                if (!process_inbound(m)) { mark_finished(false); return; }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }

        // --- Phase 2: correction R and c_i assignment ---
        Mpz D2;
        Mpz::mul(D2, D, D);
        Mpz r_sum(0UL);
        for (uint32_t d : cfg.old_contributors)
            Mpz::add(r_sum, r_sum, prestates.at(d).r_i);
        Mpz R, rem;
        Mpz::fdiv_qr(R, rem, r_sum, D2);
        if (!rem.is_zero()) { mark_finished(false); return; }

        uint32_t min_id = cfg.old_contributors.front();
        for (uint32_t d : cfg.old_contributors)
            if (d < min_id) min_id = d;
        Mpz c_for_me(0UL);
        if (cfg.is_old_contributor && cfg.old_local_id == min_id)
            c_for_me = R;

        // --- Phase 3: create + distribute contribution (old contributors) ---
        if (cfg.is_old_contributor) {
            CL_Threshold_Static::ReshareContribution c;
            try {
                c = old_party->create_reshare_contribution(
                    *cfg.cl, old_set, cfg.new_n, cfg.new_t_internal,
                    randgen, c_for_me);
            } catch (...) { mark_finished(false); return; }

            if (c.shares.size() != cfg.new_n) { mark_finished(false); return; }

            cl_reshare_contribution_wire w;
            w.dealer_id   = cfg.old_local_id;
            w.c_i         = c.c_i;
            w.q_i         = c.q_i;
            w.r_i         = c.r_i;
            w.L_i         = c.L_i;
            w.commitments = c.commitments;
            w.batch_u     = c.batch_proof->u();
            w.batch_R     = c.batch_proof->R();
            w.link_u      = c.old_share_link_proof->u();
            w.link_R1     = c.old_share_link_proof->R1();
            w.link_R2     = c.old_share_link_proof->R2();

            cl_dkg_payload pub;
            if (!cl_dkg_encode_reshare_contribution(cfg.session_id, w, pub))
            { mark_finished(false); return; }
            if (!send_broadcast(pub)) { mark_finished(false); return; }

            for (uint32_t peer = 0; peer < cfg.new_n; ++peer) {
                if (cfg.is_new_member && peer == cfg.new_local_id) continue;
                cl_dkg_payload ps;
                if (!cl_dkg_encode_reshare_private_share(
                        cfg.session_id, c.shares[peer], ps))
                { mark_finished(false); return; }
                if (!send_unicast(peer + 1, ps))
                { mark_finished(false); return; }
            }

            if (cfg.is_new_member) {
                public_contribs[cfg.old_local_id] = std::move(w);
                private_shares[cfg.old_local_id] =
                    c.shares[cfg.new_local_id];
            }
        }

        // --- Phase 4: collect + install (new members) ---
        if (cfg.is_new_member) {
            std::set<uint32_t> installed;
            // Install any fully-received contributions.
            for (uint32_t d : cfg.old_contributors) {
                if (public_contribs.count(d) == 0) continue;
                if (private_shares.count(d) == 0) continue;
                if (!install_new_contribution(d))
                { mark_finished(false); return; }
                installed.insert(d);
            }
            while (installed.size() < cfg.old_contributors.size()) {
                if (should_stop())       { mark_finished(false); return; }
                if (now_reached(deadline)){ mark_finished(false); return; }
                dkg_msg m;
                if (transport->try_recv(m)) {
                    if (!process_inbound(m)) { mark_finished(false); return; }
                    for (uint32_t d : cfg.old_contributors) {
                        if (installed.count(d) != 0) continue;
                        if (public_contribs.count(d) == 0) continue;
                        if (private_shares.count(d) == 0) continue;
                        if (!install_new_contribution(d))
                        { mark_finished(false); return; }
                        installed.insert(d);
                    }
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
            }

            try {
                new_party->finalize_reshare(*cfg.cl, old_pk);
            } catch (...) { mark_finished(false); return; }

            // Publish the new Gamma map + qualified ids for the
            // old-only contributors who cannot derive them locally.
            std::vector<uint8_t> gammas_wire;
            if (!cl_dkg_serialize_gammas(new_party->Gammas(), gammas_wire))
            { mark_finished(false); return; }
            std::vector<uint32_t> qual;
            for (unsigned int id : new_party->QualifiedPlayerSet())
                qual.push_back(id);
            std::sort(qual.begin(), qual.end());
            cl_dkg_payload pub;
            if (!cl_dkg_encode_reshare_complete(
                    cfg.session_id, gammas_wire, qual, pub))
            { mark_finished(false); return; }
            if (!send_broadcast_as_new(pub))
            { mark_finished(false); return; }
        }

        if (cfg.is_old_contributor && !cfg.is_new_member) {
            // Wait for new_threshold new members to agree on the new
            // public Gamma map.
            const uint32_t new_threshold = cfg.new_t_internal + 1;
            while (complete_threshold_count() < new_threshold) {
                if (should_stop())       { mark_finished(false); return; }
                if (now_reached(deadline)){ mark_finished(false); return; }
                dkg_msg m;
                if (transport->try_recv(m)) {
                    if (!process_inbound(m)) { mark_finished(false); return; }
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
            }
        }

        if (!fill_result()) { mark_finished(false); return; }
        mark_finished(true);
    }

    static bool now_reached(std::chrono::steady_clock::time_point t)
    {
        return std::chrono::steady_clock::now() >= t;
    }
};

cl_reshare_p2p_runner::cl_reshare_p2p_runner(
    const cl_reshare_config& cfg, std::unique_ptr<dkg_transport> transport)
    : p_(std::make_unique<impl>())
{
    p_->cfg = cfg;
    p_->transport = std::move(transport);
    p_->seed_randgen();
}

cl_reshare_p2p_runner::~cl_reshare_p2p_runner() { stop(); }

bool cl_reshare_p2p_runner::start()
{
    std::lock_guard<std::mutex> lk(p_->mu);
    if (p_->running)  return true;
    if (p_->finished) return false;
    if (!p_->transport) return false;
    if (!p_->validate_config()) return false;
    p_->running = true;
    p_->worker = std::thread([this] {
        try { p_->run(); }
        catch (...) { p_->mark_finished(false); }
    });
    return true;
}

crypto::hash cl_reshare_p2p_runner::session_id() const
{
    return p_->cfg.session_id;
}

const std::vector<crypto::public_key>&
cl_reshare_p2p_runner::new_member_pks() const
{
    return p_->cfg.new_member_pks;
}

void cl_reshare_p2p_runner::on_message(const dkg_msg& m)
{
    if (!p_->transport) return;
    if (m.hdr.type != dkg_msg_type::cl_dkg_envelope) return;
    if (m.hdr.version != 2) return;
    if (m.hdr.proposal_id != p_->cfg.proposal_id) return;
    if (m.hdr.sender_id == 0) return;
    const uint32_t max_allowed = std::max(p_->cfg.old_n, p_->cfg.new_n);
    if (m.hdr.sender_id > max_allowed) return;
    if (m.hdr.recipient_id != 0 &&
        m.hdr.recipient_id != p_->cfg.new_local_id + 1) return;
    p_->transport->deliver(m);
}

size_t cl_reshare_p2p_runner::contribution_count_for_test() const
{
    return p_->accepted_public_count.load();
}

void cl_reshare_p2p_runner::stop()
{
    {
        std::lock_guard<std::mutex> lk(p_->mu);
        p_->shutdown = true;
        p_->cv.notify_all();
    }
    if (p_->transport) p_->transport->shutdown();
    if (p_->worker.joinable()) p_->worker.join();
}

bool cl_reshare_p2p_runner::wait(cl_reshare_result& out, uint32_t timeout_s)
{
    std::unique_lock<std::mutex> lk(p_->mu);
    if (timeout_s == 0) {
        p_->cv.wait(lk, [this] { return p_->finished; });
    } else {
        if (!p_->cv.wait_for(lk, std::chrono::seconds(timeout_s),
                             [this] { return p_->finished; })) {
            return false;
        }
    }
    out = p_->result;
    return true;
}

void cl_reshare_p2p_runner::finish_failed_for_test()
{
    std::lock_guard<std::mutex> lk(p_->mu);
    p_->result = cl_reshare_result{};
    p_->result.ok = false;
    p_->finished = true;
    p_->running = false;
    p_->cv.notify_all();
}

void cl_reshare_p2p_runner::finish_ok_for_test(const cl_reshare_result& r)
{
    std::lock_guard<std::mutex> lk(p_->mu);
    p_->result = r;
    p_->finished = true;
    p_->running = false;
    p_->cv.notify_all();
}

bool cl_reshare_p2p_runner::running()  const { return p_->running; }
bool cl_reshare_p2p_runner::finished() const { return p_->finished; }


crypto::hash dao_cl_reshare_compute_session_id(
    const crypto::hash& proposal_id,
    uint64_t old_share_set_id,
    const std::vector<uint8_t>& old_committee_id_hash,
    const std::vector<uint8_t>& new_committee_id_hash,
    const std::vector<uint32_t>& sorted_old_contributors)
{
    crypto::hash h{};
    if (old_committee_id_hash.size() != 32) return h;
    if (new_committee_id_hash.size() != 32) return h;
    std::vector<uint8_t> buf;
    static const char dom[] = "VeilRoot-DAO-CL-RESHARE-SESSION-V1";
    buf.insert(buf.end(), dom, dom + sizeof(dom) - 1);
    buf.push_back(1);   // version
    buf.insert(buf.end(), proposal_id.data, proposal_id.data + 32);
    for (int i = 7; i >= 0; --i)
        buf.push_back(uint8_t((old_share_set_id >> (8 * i)) & 0xff));
    buf.insert(buf.end(), old_committee_id_hash.begin(),
                old_committee_id_hash.end());
    buf.insert(buf.end(), new_committee_id_hash.begin(),
                new_committee_id_hash.end());
    uint32_t n = static_cast<uint32_t>(sorted_old_contributors.size());
    for (int i = 3; i >= 0; --i)
        buf.push_back(uint8_t((n >> (8 * i)) & 0xff));
    for (uint32_t v : sorted_old_contributors)
        for (int i = 3; i >= 0; --i)
            buf.push_back(uint8_t((v >> (8 * i)) & 0xff));
    unsigned char digest[32];
    SHA256(buf.data(), buf.size(), digest);
    std::memcpy(h.data, digest, 32);
    return h;
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
