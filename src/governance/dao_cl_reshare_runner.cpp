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

    std::mutex mu;
    std::condition_variable cv;
    bool running   = false;
    bool finished  = false;
    bool shutdown  = false;
    cl_reshare_result result;
    std::thread worker;

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
        CL_Threshold_Static::ParticipantsSet all_old;
        for (uint32_t k = 0; k < cfg.old_n; ++k) all_old.insert(k);
        if (!old_party->restore_decryption_state(
                *cfg.cl, old_pk, old_gammas, all_old, share))
            return false;
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
            uint32_t dealer_id = 0;
            CL_Threshold_Static::ResharePreState pre;
            if (!cl_dkg_decode_reshare_prestate(
                    p, dealer_id, pre.q_i, pre.r_i, pre.L_i))
                return false;
            if (old_set.count(dealer_id) == 0) return true;
            prestates[dealer_id] = std::move(pre);
            return true;
        }
        case cl_dkg_subtype::reshare_contribution: {
            cl_reshare_contribution_wire w;
            if (!cl_dkg_decode_reshare_contribution(
                    p, cfg.cl->Cl_G().discriminant(),
                    cfg.new_t_internal + 1u, w))
                return false;
            if (old_set.count(w.dealer_id) == 0) return true;
            public_contribs[w.dealer_id] = std::move(w);
            return true;
        }
        case cl_dkg_subtype::reshare_private_share: {
            if (m.hdr.sender_id == 0) return true;
            uint32_t dealer_id = m.hdr.sender_id - 1;
            if (old_set.count(dealer_id) == 0) return true;
            Mpz share;
            if (!cl_dkg_decode_reshare_private_share(p, share)) return false;
            private_shares[dealer_id] = std::move(share);
            return true;
        }
        case cl_dkg_subtype::reshare_complete:
            return true;
        default:
            return true;
        }
    }

    bool all_prestates_received() const
    {
        if (cfg.old_contributors.empty()) return true;
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

    void fill_result()
    {
        // Serialize new share + gammas + pk + qualified set.
        if (!new_party->serialize_secret_share(result.new_share_bytes)) return;
        if (!cl_dkg_serialize_gammas(new_party->Gammas(),
                                     result.new_gammas_serialized))
            return;
        result.qualified_ids.clear();
        for (unsigned int id : new_party->QualifiedPlayerSet())
            result.qualified_ids.push_back(id);
        std::sort(result.qualified_ids.begin(), result.qualified_ids.end());
        result.pk_qfi.clear();
        if (!cl_dkg_qfi_to_bytes(result.pk_qfi,
                                 new_party->pk().elt()))
            return;
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
                    cfg.old_local_id, pre.q_i, pre.r_i, pre.L_i, out))
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
            if (!cl_dkg_encode_reshare_contribution(w, pub))
            { mark_finished(false); return; }
            if (!send_broadcast(pub)) { mark_finished(false); return; }

            for (uint32_t peer = 0; peer < cfg.new_n; ++peer) {
                if (cfg.is_new_member && peer == cfg.new_local_id) continue;
                cl_dkg_payload ps;
                if (!cl_dkg_encode_reshare_private_share(c.shares[peer], ps))
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

            fill_result();
        }

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
    p_->running = true;
    p_->worker = std::thread([this] {
        try { p_->run(); }
        catch (...) { p_->mark_finished(false); }
    });
    return true;
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
    return out.ok;
}

bool cl_reshare_p2p_runner::running()  const { return p_->running; }
bool cl_reshare_p2p_runner::finished() const { return p_->finished; }

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
