// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_cl_dkg_runner.h"

#ifdef VEILROOT_ENABLE_CL

#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_party.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <random>
#include <set>
#include <thread>

namespace cryptonote {
namespace dao {

namespace {

using namespace BICYCL;

} // namespace

struct cl_dkg_p2p_runner::impl
{
    cl_dkg_config cfg;
    std::unique_ptr<dkg_transport> transport;
    std::unique_ptr<CLCommitteeParty> party;
    RandGen randgen;

    std::mutex mu;
    std::condition_variable cv;
    bool running = false;
    bool finished = false;
    bool shutdown = false;
    cl_dkg_result result;
    std::thread worker;

    std::set<uint32_t> peer_commitments;
    std::set<uint32_t> peer_proofs;
    std::set<uint32_t> peer_shares;

    void seed_randgen()
    {
        if (cfg.test_seed != 0) {
            randgen.set_seed(Mpz(static_cast<unsigned long>(cfg.test_seed)));
        } else {
            std::random_device rd;
            randgen.set_seed(Mpz(static_cast<unsigned long>(rd())));
        }
    }

    bool broadcast(const cl_dkg_payload& p)
    {
        dkg_msg m;
        m.hdr.version = 2;
        m.hdr.proposal_id = cfg.proposal_id;
        m.hdr.sender_id = cfg.local_party_id;
        m.hdr.recipient_id = 0;
        m.hdr.type = dkg_msg_type::cl_dkg_envelope;
        if (!p.serialize(m.bytes_a)) return false;
        return transport->send(m);
    }

    bool unicast(uint32_t peer, const cl_dkg_payload& p)
    {
        dkg_msg m;
        m.hdr.version = 2;
        m.hdr.proposal_id = cfg.proposal_id;
        m.hdr.sender_id = cfg.local_party_id;
        m.hdr.recipient_id = peer;
        m.hdr.type = dkg_msg_type::cl_dkg_envelope;
        if (!p.serialize(m.bytes_a)) return false;
        return transport->send(m);
    }

    bool all_peer_inputs_received() const
    {
        return peer_commitments.size() == cfg.committee_size - 1
            && peer_proofs.size()      == cfg.committee_size - 1
            && peer_shares.size()      == cfg.committee_size - 1;
    }

    bool process_inbound(const dkg_msg& m)
    {
        if (m.hdr.type != dkg_msg_type::cl_dkg_envelope) return true;
        if (m.hdr.version != 2) return true;
        if (m.hdr.proposal_id != cfg.proposal_id) return true;
        if (m.hdr.sender_id == 0 || m.hdr.sender_id > cfg.committee_size)
            return true;
        if (m.hdr.recipient_id != 0 && m.hdr.recipient_id != cfg.local_party_id)
            return true;

        cl_dkg_payload p;
        if (!cl_dkg_payload::deserialize(m.bytes_a, p)) return true;
        const uint32_t s0 = m.hdr.sender_id - 1;

        switch (p.subtype) {
        case cl_dkg_subtype::keygen_commitments: {
            std::vector<QFI> C;
            if (!cl_dkg_decode_commitments(
                    p, C, cfg.cl->Cl_G().discriminant(),
                    cfg.committee_size)) return false;
            if (!party->keygen_add_commitments(s0, C)) return false;
            peer_commitments.insert(m.hdr.sender_id);
            return true;
        }
        case cl_dkg_subtype::keygen_batch_proof: {
            Mpz u; QFI R;
            if (!cl_dkg_decode_batch_proof(
                    p, u, R, cfg.cl->Cl_G().discriminant())) return false;
            CLBatchDlogAoKExposed proof(u, R);
            if (!party->keygen_add_proof(s0, proof)) return false;
            peer_proofs.insert(m.hdr.sender_id);
            return true;
        }
        case cl_dkg_subtype::keygen_private_share: {
            Mpz y;
            if (!cl_dkg_decode_private_share(p, y)) return false;
            if (!party->keygen_add_share(s0, y)) return false;
            peer_shares.insert(m.hdr.sender_id);
            return true;
        }
        case cl_dkg_subtype::keygen_complaint:
        case cl_dkg_subtype::keygen_complete:
            return true;
        }
        return true;
    }

    bool fill_result(cl_dkg_result& out) const
    {
        const auto& cl = *cfg.cl;
        out.ctx.q.clear();
        cl_dkg_mpz_to_bytes_be(out.ctx.q, cl.q());
        out.ctx.k = static_cast<uint32_t>(cl.k());
        out.ctx.p.clear();
        cl_dkg_mpz_to_bytes_signed(out.ctx.p, cl.p());
        out.ctx.pk_qfi.clear();
        cl_dkg_qfi_to_bytes(out.ctx.pk_qfi, party->public_key().elt());
        out.ctx.D.clear();
        cl_dkg_mpz_to_bytes_signed(out.ctx.D, party->interpolation_scale());

        out.local_secret_share.clear();
        if (!party->serialize_secret_share(out.local_secret_share)) return false;

        out.gammas_serialized.clear();
        if (!cl_dkg_serialize_gammas(party->gammas(), out.gammas_serialized))
            return false;

        out.qualified_ids.clear();
        for (unsigned int id : party->qualified_players())
            out.qualified_ids.push_back(id);
        std::sort(out.qualified_ids.begin(), out.qualified_ids.end());
        return true;
    }

    void mark_finished(bool ok)
    {
        std::lock_guard<std::mutex> lk(mu);
        result.ok = ok;
        finished = true;
        running = false;
        cv.notify_all();
    }

    bool should_stop()
    {
        std::lock_guard<std::mutex> lk(mu);
        return shutdown;
    }

    void run()
    {
        if (!party->keygen_dealing(randgen)) { mark_finished(false); return; }

        {
            cl_dkg_payload p;
            if (!cl_dkg_encode_commitments(party->keygen_commitments(), p))
            { mark_finished(false); return; }
            if (!broadcast(p)) { mark_finished(false); return; }
            if (!cl_dkg_encode_batch_proof(
                    party->keygen_batch_proof().u(),
                    party->keygen_batch_proof().R(), p))
            { mark_finished(false); return; }
            if (!broadcast(p)) { mark_finished(false); return; }
        }
        for (uint32_t peer = 1; peer <= cfg.committee_size; ++peer) {
            if (peer == cfg.local_party_id) continue;
            cl_dkg_payload p;
            if (!cl_dkg_encode_private_share(
                    party->keygen_y_k(peer - 1), p))
            { mark_finished(false); return; }
            if (!unicast(peer, p)) { mark_finished(false); return; }
        }

        const auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::seconds(cfg.phase_timeout_seconds);
        while (!all_peer_inputs_received()) {
            if (should_stop()) { mark_finished(false); return; }
            if (std::chrono::steady_clock::now() >= deadline)
            { mark_finished(false); return; }
            dkg_msg m;
            if (transport->try_recv(m)) {
                if (!process_inbound(m)) { mark_finished(false); return; }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }

        if (!party->keygen_check_verify_all()) { mark_finished(false); return; }
        if (!party->keygen_extract())           { mark_finished(false); return; }

        cl_dkg_payload comp;
        if (!cl_dkg_encode_complete(comp)) { mark_finished(false); return; }
        if (!broadcast(comp)) { mark_finished(false); return; }

        std::lock_guard<std::mutex> lk(mu);
        if (!fill_result(result)) { result.ok = false; finished = true; running = false; cv.notify_all(); return; }
        result.ok = true;
        finished = true;
        running = false;
        cv.notify_all();
    }
};

cl_dkg_p2p_runner::cl_dkg_p2p_runner(
    const cl_dkg_config& cfg, std::unique_ptr<dkg_transport> transport)
    : p_(std::make_unique<impl>())
{
    p_->cfg = cfg;
    p_->transport = std::move(transport);
    p_->seed_randgen();
    p_->party = std::make_unique<CLCommitteeParty>(
        cfg.cl, cfg.committee_size, cfg.threshold_internal,
        cfg.local_party_id - 1, cfg.soundness_bytes);
}

cl_dkg_p2p_runner::~cl_dkg_p2p_runner()
{
    stop();
}

bool cl_dkg_p2p_runner::start()
{
    std::lock_guard<std::mutex> lk(p_->mu);
    if (p_->running) return true;
    if (p_->finished) return false;
    if (!p_->transport) return false;
    p_->running = true;
    p_->worker = std::thread([this] { p_->run(); });
    return true;
}

void cl_dkg_p2p_runner::stop()
{
    {
        std::lock_guard<std::mutex> lk(p_->mu);
        p_->shutdown = true;
        p_->cv.notify_all();
    }
    if (p_->transport) p_->transport->shutdown();
    if (p_->worker.joinable()) p_->worker.join();
}

bool cl_dkg_p2p_runner::wait(cl_dkg_result& out, uint32_t timeout_s)
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

bool cl_dkg_p2p_runner::running()  const { return p_->running; }
bool cl_dkg_p2p_runner::finished() const { return p_->finished; }
uint32_t cl_dkg_p2p_runner::local_party_id() const
{
    return p_->cfg.local_party_id;
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
