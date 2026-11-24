// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_cl_dkg_runner.h"

#ifdef VEILROOT_ENABLE_CL

#include "governance/dao_cl_dkg_payload.h"
#include "crypto/hash.h"
#include "governance/dao_cl_party.h"

#include "misc_log_ex.h"

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
    std::shared_ptr<dkg_transport> transport;
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
    std::string inbound_failure_reason;

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
        m.hdr.version = 3;
        m.hdr.proposal_id = cfg.proposal_id;
        m.hdr.attempt_id = cfg.attempt_id;
        m.hdr.sender_id = cfg.local_party_id;
        m.hdr.recipient_id = 0;
        m.hdr.type = dkg_msg_type::cl_dkg_envelope;
        if (!p.serialize(m.bytes_a)) return false;
        return transport->send(m);
    }

    bool unicast(uint32_t peer, const cl_dkg_payload& p)
    {
        dkg_msg m;
        m.hdr.version = 3;
        m.hdr.proposal_id = cfg.proposal_id;
        m.hdr.attempt_id = cfg.attempt_id;
        m.hdr.sender_id = cfg.local_party_id;
        m.hdr.recipient_id = peer;
        m.hdr.type = dkg_msg_type::cl_dkg_envelope;
        if (!p.serialize(m.bytes_a)) return false;
        return transport->send(m);
    }

    size_t complete_peer_count() const
    {
        size_t complete = 0;
        for (uint32_t peer = 1; peer <= cfg.committee_size; ++peer) {
            if (peer == cfg.local_party_id) continue;
            if (peer_commitments.count(peer) && peer_proofs.count(peer) &&
                peer_shares.count(peer))
                ++complete;
        }
        return complete;
    }
    bool all_peer_inputs_received() const
    {
        // A participant is ready only when that same participant has
        // supplied commitments, proof, and its unicast share. Aggregate
        // per-message counts can otherwise combine contributions from
        // different peers and incorrectly advance verification.
        const size_t required_peers = cfg.committee_size > 0
            ? static_cast<size_t>(cfg.committee_size - 1) : 0;
        return complete_peer_count() == required_peers;
    }

    bool process_inbound(const dkg_msg& m, std::string& stage)
    {
        if (m.hdr.type != dkg_msg_type::cl_dkg_envelope) return true;
        if (m.hdr.version != 3) return true;
        if (m.hdr.proposal_id != cfg.proposal_id) return true;
        if (m.hdr.attempt_id != cfg.attempt_id) return true;
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
                    cfg.committee_size)) {
                stage = "decode_commitments"; return false;
            }
            if (!party->keygen_add_commitments(s0, C)) {
                stage = "add_commitments"; return false;
            }
            peer_commitments.insert(m.hdr.sender_id);
            MWARNING("CL DKG rx: id=" << m.hdr.sender_id
                     << " type=commitments"
                     << " c=" << peer_commitments.size()
                     << " p=" << peer_proofs.size()
                     << " s=" << peer_shares.size());
            return true;
        }
        case cl_dkg_subtype::keygen_batch_proof: {
            Mpz u; QFI R;
            if (!cl_dkg_decode_batch_proof(
                    p, u, R, cfg.cl->Cl_G().discriminant())) {
                stage = "decode_batch_proof"; return false;
            }
            CLBatchDlogAoKExposed proof(u, R);
            if (!party->keygen_add_proof(s0, proof)) {
                stage = "add_proof"; return false;
            }
            peer_proofs.insert(m.hdr.sender_id);
            MWARNING("CL DKG rx: id=" << m.hdr.sender_id
                     << " type=proof"
                     << " c=" << peer_commitments.size()
                     << " p=" << peer_proofs.size()
                     << " s=" << peer_shares.size());
            return true;
        }
        case cl_dkg_subtype::keygen_private_share: {
            Mpz y;
            if (!cl_dkg_decode_private_share(p, y)) {
                stage = "decode_private_share"; return false;
            }
            if (!party->keygen_add_share(s0, y)) {
                stage = "add_share"; return false;
            }
            peer_shares.insert(m.hdr.sender_id);
            MWARNING("CL DKG rx: id=" << m.hdr.sender_id
                     << " type=share"
                     << " c=" << peer_commitments.size()
                     << " p=" << peer_proofs.size()
                     << " s=" << peer_shares.size());
            return true;
        }
        case cl_dkg_subtype::keygen_complaint: {
            uint32_t against_sender_id = 0;
            uint32_t complaint_reason = 0;
            if (!cl_dkg_decode_complaint(
                    p, against_sender_id, complaint_reason) ||
                against_sender_id == 0 ||
                against_sender_id > cfg.committee_size) {
                stage = "keygen_complaint_decode";
                inbound_failure_reason = "malformed keygen complaint";
                return false;
            }
            stage = "keygen_complaint";
            inbound_failure_reason =
                "unresolved complaint from peer " +
                std::to_string(m.hdr.sender_id) + " against peer " +
                std::to_string(against_sender_id) + " (reason " +
                std::to_string(complaint_reason) + ")";
            // The exposed CL party API has no complaint-resolution
            // transition. Do not treat this as resolved and do not
            // locally disqualify either participant. Abort this attempt.
            return false;
        }
        case cl_dkg_subtype::keygen_complete:
            return true;
        case cl_dkg_subtype::reshare_prestate:
        case cl_dkg_subtype::reshare_contribution:
        case cl_dkg_subtype::reshare_private_share:
        case cl_dkg_subtype::reshare_complete:
            return true;
        }
        return true;
    }

    bool fill_result(cl_dkg_result& out) const
    {
        out.attempt_id = cfg.attempt_id;
        const auto& cl = *cfg.cl;
        // DKG scalar encoding is sign || u32(length) || magnitude.
        // cl_key_context stores sign || magnitude because its serializer
        // writes the length prefix itself.
        auto scalar_to_key_context_payload = [](
            std::vector<uint8_t>& dst,
            const BICYCL::Mpz& value,
            bool require_positive) -> bool
        {
            std::vector<uint8_t> wire;
            if (!cl_dkg_mpz_to_bytes_signed(wire, value) ||
                wire.size() < 5u || wire[0] > 1u)
                return false;

            const uint32_t len =
                (static_cast<uint32_t>(wire[1]) << 24)
              | (static_cast<uint32_t>(wire[2]) << 16)
              | (static_cast<uint32_t>(wire[3]) <<  8)
              |  static_cast<uint32_t>(wire[4]);

            if (len >= 4096u ||
                wire.size() != 5u + static_cast<size_t>(len) ||
                (len != 0u && wire[5] == 0u) ||
                (len == 0u && wire[0] != 0u) ||
                (require_positive && wire[0] != 0u))
                return false;

            dst.clear();
            dst.reserve(1u + static_cast<size_t>(len));
            dst.push_back(wire[0]);
            dst.insert(dst.end(), wire.begin() + 5, wire.end());
            return true;
        };

        out.ctx.q.clear();
        cl_dkg_mpz_to_bytes_be(out.ctx.q, cl.q());
        out.ctx.k = static_cast<uint32_t>(cl.k());
        if (!scalar_to_key_context_payload(out.ctx.p, cl.p(), false))
            return false;
        out.ctx.pk_qfi.clear();
        cl_dkg_qfi_to_bytes(out.ctx.pk_qfi, party->public_key().elt());
        if (!scalar_to_key_context_payload(
                out.ctx.D, party->interpolation_scale(), true))
            return false;

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

    void mark_finished(bool ok,
                       const std::string& stage = {},
                       const std::string& reason = {})
    {
        std::lock_guard<std::mutex> lk(mu);
        result.attempt_id = cfg.attempt_id;
        result.ok = ok;
        result.failure_stage = stage;
        result.failure_reason = reason;
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
        try { run_impl(); }
        catch (const std::exception& e) {
            mark_finished(false, "runner_exception", e.what());
        }
        catch (...) {
            mark_finished(false, "runner_exception", "unknown");
        }
    }

    void run_impl()
    {
        if (!party->keygen_dealing(randgen)) {
            mark_finished(false, "keygen_dealing", party->last_error());
            return;
        }

        {
            cl_dkg_payload p;
            if (!cl_dkg_encode_commitments(party->keygen_commitments(), p)) {
                mark_finished(false, "encode_commitments", "");
                return;
            }
            if (!broadcast(p)) {
                mark_finished(false, "broadcast_commitments",
                              "transport send failed");
                return;
            }
            if (!cl_dkg_encode_batch_proof(
                    party->keygen_batch_proof().u(),
                    party->keygen_batch_proof().R(), p)) {
                mark_finished(false, "encode_batch_proof", "");
                return;
            }
            if (!broadcast(p)) {
                mark_finished(false, "broadcast_batch_proof",
                              "transport send failed");
                return;
            }
        }
        for (uint32_t peer = 1; peer <= cfg.committee_size; ++peer) {
            if (peer == cfg.local_party_id) continue;
            cl_dkg_payload p;
            if (!cl_dkg_encode_private_share(
                    party->keygen_y_k(peer - 1), p)) {
                mark_finished(false, "encode_private_share", "");
                return;
            }
            if (!unicast(peer, p)) {
                mark_finished(false, "unicast_private_share",
                              "transport send failed to peer "
                              + std::to_string(peer));
                return;
            }
        }

        const auto deadline = std::chrono::steady_clock::now()
                            + std::chrono::seconds(cfg.phase_timeout_seconds);
        while (!all_peer_inputs_received()) {
            if (should_stop()) {
                mark_finished(false, "waiting_for_peer_inputs",
                              "shutdown");
                return;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                const size_t need = cfg.committee_size > 0
                    ? static_cast<size_t>(cfg.committee_size - 1) : 0;
                std::string reason =
                    "timeout after "
                    + std::to_string(cfg.phase_timeout_seconds) + "s"
                    + " complete_peers=" +
                    std::to_string(complete_peer_count()) + "/" +
                    std::to_string(need)
                    + " commitments=" + std::to_string(peer_commitments.size())
                    + " proofs=" + std::to_string(peer_proofs.size())
                    + " shares=" + std::to_string(peer_shares.size());
                mark_finished(false, "waiting_for_peer_inputs", reason);
                return;
            }
            dkg_msg m;
            if (transport->try_recv(m)) {
                std::string stage;
                if (!process_inbound(m, stage)) {
                    mark_finished(false, stage,
                                  inbound_failure_reason.empty()
                                      ? party->last_error()
                                      : inbound_failure_reason);
                    return;
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }

        // Drain messages already queued at the collection boundary. A
        // complaint or malformed contribution must not sit behind the
        // final share and be bypassed by verification.
        dkg_msg queued;
        while (transport->try_recv(queued)) {
            std::string stage;
            if (!process_inbound(queued, stage)) {
                mark_finished(false, stage,
                              inbound_failure_reason.empty()
                                  ? party->last_error()
                                  : inbound_failure_reason);
                return;
            }
        }
        {
            auto hex_pk = [](const crypto::public_key& pk) {
                static const char hx[] = "0123456789abcdef";
                std::string r; r.reserve(64);
                for (size_t i = 0; i < sizeof(pk.data); ++i) {
                    r.push_back(hx[(pk.data[i] >> 4) & 0xf]);
                    r.push_back(hx[pk.data[i] & 0xf]);
                }
                return r;
            };
            auto join_set = [](const std::set<uint32_t>& st) {
                std::string r;
                for (auto v : st) { if (!r.empty()) r += ","; r += std::to_string(v); }
                return r;
            };
            std::string memb;
            for (size_t i = 0; i < cfg.member_ids.size(); ++i) {
                if (i) memb += ",";
                memb += hex_pk(cfg.member_ids[i]);
            }
            auto hex8 = [](const crypto::hash& h) {
                static const char hx[] = "0123456789abcdef";
                std::string r; r.reserve(16);
                for (size_t i = 0; i < 8; ++i) {
                    r.push_back(hx[(h.data[i] >> 4) & 0xf]);
                    r.push_back(hx[h.data[i] & 0xf]);
                }
                return r;
            };
            std::vector<uint8_t> p_bytes, q_bytes, h_bytes;
            cl_dkg_mpz_to_bytes_be(p_bytes, cfg.cl->p());
            cl_dkg_mpz_to_bytes_be(q_bytes, cfg.cl->q());
            {
                QFI hq;
                cfg.cl->power_of_h(hq, Mpz(1UL));
                cl_dkg_qfi_to_bytes(h_bytes, hq);
            }
            crypto::hash p_h{}, q_h{}, h_h{};
            crypto::cn_fast_hash(p_bytes.data(), p_bytes.size(), p_h);
            crypto::cn_fast_hash(q_bytes.data(), q_bytes.size(), q_h);
            crypto::cn_fast_hash(h_bytes.data(), h_bytes.size(), h_h);
        }

        MWARNING("CL DKG pre-verify: qualified=" << party->qualified_players().size()
                 << "/" << cfg.committee_size << " complaints=" << party->complaints_count());

        MWARNING("CL DKG stage begin: keygen_check_verify_all");
        const auto verify_started = std::chrono::steady_clock::now();
        if (!party->keygen_check_verify_all()) {
            const auto verify_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - verify_started).count();
            const std::string reason = party->last_error();
            MWARNING("CL DKG stage FAILED: keygen_check_verify_all elapsed_ms="
                     << verify_ms << " reason=" << reason);
            mark_finished(false, "keygen_check_verify_all", reason);
            return;
        }
        const auto verify_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - verify_started).count();
        MWARNING("CL DKG stage OK: keygen_check_verify_all elapsed_ms="
                 << verify_ms);
        MWARNING("CL DKG stage begin: keygen_extract");
        const auto extract_started = std::chrono::steady_clock::now();
        if (!party->keygen_extract()) {
            const auto extract_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - extract_started).count();
            const std::string reason = party->last_error();
            MWARNING("CL DKG stage FAILED: keygen_extract elapsed_ms="
                     << extract_ms << " reason=" << reason);
            mark_finished(false, "keygen_extract", reason);
            return;
        }
        const auto extract_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - extract_started).count();
        MWARNING("CL DKG stage OK: keygen_extract elapsed_ms="
                 << extract_ms);

        cl_dkg_payload comp;
        if (!cl_dkg_encode_complete(comp)) {
            mark_finished(false, "encode_complete", "");
            return;
        }
        if (!broadcast(comp)) {
            mark_finished(false, "broadcast_complete",
                          "transport send failed");
            return;
        }

        cl_dkg_result local;
        MWARNING("CL DKG stage begin: fill_result");
        const auto fill_started = std::chrono::steady_clock::now();
        if (!fill_result(local)) {
            const auto fill_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - fill_started).count();
            MWARNING("CL DKG stage FAILED: fill_result elapsed_ms="
                     << fill_ms);
            mark_finished(false, "fill_result", "fill_result returned false");
            return;
        }
        const auto fill_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - fill_started).count();
        MWARNING("CL DKG stage OK: fill_result elapsed_ms="
                 << fill_ms);
        {
            std::lock_guard<std::mutex> lk(mu);
            result = std::move(local);
            result.ok = true;
            result.failure_stage.clear();
            result.failure_reason.clear();
            finished = true;
            running = false;
            cv.notify_all();
        }
    }
};

// ====================================================================
// cl_dkg_p2p_transport
// ====================================================================

cl_dkg_p2p_transport::cl_dkg_p2p_transport(
    std::vector<crypto::public_key> members,
    std::function<bool(const crypto::public_key&, const std::string&)> send_to,
    std::function<bool(const std::string&)> broadcast)
    : members_(std::move(members))
    , send_to_(std::move(send_to))
    , broadcast_(std::move(broadcast)) {}

bool cl_dkg_p2p_transport::send(const dkg_msg& m)
{
    std::vector<uint8_t> buf;
    if (!m.serialize(buf)) return false;
    std::string payload(buf.begin(), buf.end());

    if (m.hdr.recipient_id == 0) {
        if (!broadcast_) return false;
        return broadcast_(payload);
    }
    const uint32_t idx = m.hdr.recipient_id;
    if (idx < 1 || idx > members_.size()) return false;
    if (!send_to_) return false;
    return send_to_(members_[idx - 1], payload);
}

bool cl_dkg_p2p_transport::recv(dkg_msg& m)
{
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait(lk, [&] { return stopped_ || !queue_.empty(); });
    if (queue_.empty()) return false;
    m = std::move(queue_.front());
    queue_.pop();
    return true;
}

bool cl_dkg_p2p_transport::try_recv(dkg_msg& m)
{
    std::lock_guard<std::mutex> lk(mu_);
    if (queue_.empty()) return false;
    m = std::move(queue_.front());
    queue_.pop();
    return true;
}

void cl_dkg_p2p_transport::deliver(const dkg_msg& m)
{
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (stopped_) return;
        queue_.push(m);
    }
    cv_.notify_one();
}

void cl_dkg_p2p_transport::shutdown()
{
    {
        std::lock_guard<std::mutex> lk(mu_);
        stopped_ = true;
    }
    cv_.notify_all();
}

cl_dkg_p2p_runner::cl_dkg_p2p_runner(
    const cl_dkg_config& cfg, std::unique_ptr<dkg_transport> transport)
    : p_(std::make_unique<impl>())
{
    p_->cfg = cfg;
    p_->transport = std::shared_ptr<dkg_transport>(std::move(transport));
    p_->seed_randgen();
    p_->party = std::make_unique<CLCommitteeParty>(
        cfg.cl, cfg.committee_size, cfg.threshold_internal,
        cfg.local_party_id - 1, cfg.soundness_bytes);
}

cl_dkg_p2p_runner::cl_dkg_p2p_runner(
    const cl_dkg_config& cfg, std::shared_ptr<dkg_transport> transport)
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
    if (!p_->transport || p_->cfg.attempt_id == crypto::null_hash)
        return false;
    p_->running = true;
    try {
        p_->worker = std::thread([this] { p_->run(); });
    } catch (...) {
        p_->running = false;
        p_->finished = true;
        p_->result.attempt_id = p_->cfg.attempt_id;
        p_->result.ok = false;
        p_->result.failure_stage = "thread_start";
        p_->result.failure_reason = "worker thread creation failed";
        p_->cv.notify_all();
        return false;
    }
    return true;
}

void cl_dkg_p2p_runner::on_message(const dkg_msg& m)
{
    if (!p_->transport) return;
    p_->transport->deliver(m);
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
    return true;
}

bool cl_dkg_p2p_runner::running() const
{
    std::lock_guard<std::mutex> lk(p_->mu);
    return p_->running;
}
bool cl_dkg_p2p_runner::finished() const
{
    std::lock_guard<std::mutex> lk(p_->mu);
    return p_->finished;
}
uint32_t cl_dkg_p2p_runner::local_party_id() const
{
    return p_->cfg.local_party_id;
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
