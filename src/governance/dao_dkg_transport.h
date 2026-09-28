// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>

#include "governance/dao_dkg.h"

namespace cryptonote {
namespace dao {

class dkg_inproc_hub;

// One in-process endpoint.
class dkg_inproc_transport final : public dkg_transport
{
public:
    dkg_inproc_transport(uint32_t party_id,
                         dkg_inproc_hub* hub,
                         dkg_tamper_hook hook);
    ~dkg_inproc_transport() override;

    bool send(const dkg_msg& m) override;
    bool recv(dkg_msg& m) override;
    bool try_recv(dkg_msg& m) override;
    void shutdown() override;

private:
    uint32_t         party_id_;
    dkg_inproc_hub*  hub_;
    dkg_tamper_hook  hook_;

    std::mutex               mu_;
    std::condition_variable  cv_;
    std::queue<dkg_msg>      queue_;
    bool                     stopped_ = false;

    friend class dkg_inproc_hub;
    void deliver(const dkg_msg& m);
};

// Shared routing hub.
class dkg_inproc_hub
{
public:
    explicit dkg_inproc_hub(uint32_t n);
    ~dkg_inproc_hub();

    void register_endpoint(uint32_t party_id, dkg_inproc_transport* t);
    void deregister_endpoint(uint32_t party_id);
    void route(const dkg_msg& m);
    void shutdown_all();

private:
    uint32_t n_;
    std::vector<dkg_inproc_transport*> endpoints_;
    std::mutex mu_;
};

// Ownership-bundled in-process network. Destructor tears down the
// endpoints first, then the hub. No dangling pointers.
struct dkg_inproc_network
{
    std::shared_ptr<dkg_inproc_hub>             hub;
    std::vector<std::unique_ptr<dkg_transport>> endpoints;

    ~dkg_inproc_network();
    dkg_inproc_network();
    dkg_inproc_network(dkg_inproc_network&&) noexcept;
    dkg_inproc_network& operator=(dkg_inproc_network&&) noexcept;
    dkg_inproc_network(const dkg_inproc_network&) = delete;
    dkg_inproc_network& operator=(const dkg_inproc_network&) = delete;
};

// dkg_make_inproc_network is declared in dao_dkg.h, which this header
// includes. Do not redeclare it here.

} // namespace dao
} // namespace cryptonote