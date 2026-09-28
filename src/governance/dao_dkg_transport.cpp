// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_dkg_transport.h"

namespace cryptonote {
namespace dao {

// ============================= hub =============================

dkg_inproc_hub::dkg_inproc_hub(uint32_t n) : n_(n)
{
    endpoints_.assign(n + 1, nullptr);   // 1-based indexing
}

dkg_inproc_hub::~dkg_inproc_hub() = default;

void dkg_inproc_hub::register_endpoint(uint32_t party_id, dkg_inproc_transport* t)
{
    if (party_id < 1 || party_id > n_) return;
    std::lock_guard<std::mutex> lk(mu_);
    endpoints_[party_id] = t;
}

void dkg_inproc_hub::deregister_endpoint(uint32_t party_id)
{
    if (party_id < 1 || party_id > n_) return;
    std::lock_guard<std::mutex> lk(mu_);
    endpoints_[party_id] = nullptr;
}

void dkg_inproc_hub::route(const dkg_msg& m)
{
    std::vector<dkg_inproc_transport*> targets;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (m.hdr.recipient_id == 0) {
            for (uint32_t i = 1; i <= n_; ++i) {
                if (i == m.hdr.sender_id) continue;
                if (endpoints_[i]) targets.push_back(endpoints_[i]);
            }
        } else if (m.hdr.recipient_id <= n_) {
            if (endpoints_[m.hdr.recipient_id])
                targets.push_back(endpoints_[m.hdr.recipient_id]);
        }
    }
    for (auto* t : targets) t->deliver(m);
}

void dkg_inproc_hub::shutdown_all()
{
    std::vector<dkg_inproc_transport*> eps;
    {
        std::lock_guard<std::mutex> lk(mu_);
        eps = endpoints_;
    }
    for (auto* t : eps) if (t) t->shutdown();
}

// ============================= endpoint =============================

dkg_inproc_transport::dkg_inproc_transport(uint32_t party_id,
                                           dkg_inproc_hub* hub,
                                           dkg_tamper_hook hook)
    : party_id_(party_id), hub_(hub), hook_(std::move(hook))
{
    if (hub_) hub_->register_endpoint(party_id_, this);
}

dkg_inproc_transport::~dkg_inproc_transport()
{
    shutdown();
    if (hub_) hub_->deregister_endpoint(party_id_);
}

void dkg_inproc_transport::deliver(const dkg_msg& m)
{
    dkg_msg copy = m;
    if (hook_) hook_(copy);
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (stopped_) return;
        queue_.push(std::move(copy));
    }
    cv_.notify_one();
}

bool dkg_inproc_transport::send(const dkg_msg& m)
{
    if (!hub_) return false;
    hub_->route(m);
    return true;
}

bool dkg_inproc_transport::recv(dkg_msg& m)
{
    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait(lk, [&] { return stopped_ || !queue_.empty(); });
    if (stopped_ && queue_.empty()) return false;
    m = std::move(queue_.front());
    queue_.pop();
    return true;
}

bool dkg_inproc_transport::try_recv(dkg_msg& m)
{
    std::lock_guard<std::mutex> lk(mu_);
    if (queue_.empty()) return false;
    m = std::move(queue_.front());
    queue_.pop();
    return true;
}

void dkg_inproc_transport::shutdown()
{
    {
        std::lock_guard<std::mutex> lk(mu_);
        stopped_ = true;
    }
    cv_.notify_all();
}

// ============================= network =============================

dkg_inproc_network::dkg_inproc_network() = default;

dkg_inproc_network::~dkg_inproc_network()
{
    // Destroy endpoints first so no shutdown races with hub.
    endpoints.clear();
    if (hub) hub->shutdown_all();
    hub.reset();
}

dkg_inproc_network::dkg_inproc_network(dkg_inproc_network&&) noexcept = default;

dkg_inproc_network&
dkg_inproc_network::operator=(dkg_inproc_network&&) noexcept = default;

dkg_inproc_network dkg_make_inproc_network(uint32_t n, dkg_tamper_hook hook)
{
    dkg_inproc_network net;
    net.hub = std::make_shared<dkg_inproc_hub>(n);
    net.endpoints.reserve(n);
    for (uint32_t i = 1; i <= n; ++i) {
        net.endpoints.emplace_back(
            new dkg_inproc_transport(i, net.hub.get(), hook));
    }
    return net;
}

} // namespace dao
} // namespace cryptonote