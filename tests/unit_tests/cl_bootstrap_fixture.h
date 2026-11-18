// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#ifdef VEILROOT_ENABLE_CL

#include "governance/dao_cl_ballot.h"
#include "governance/dao_cl_dkg_payload.h"
#include "governance/dao_cl_dkg_runner.h"
#include "governance/dao_cl_party.h"
#include "governance/dao_dkg.h"
#include "governance/dao_dkg_transport.h"
#include "governance/dao_tally.h"

#include "bicycl/bicycl.hpp"
#include "bicycl/bicycl/cl/CL_HSMqk.hpp"
#include "ringct/rctOps.h"

#include <cstring>
#include <memory>

#include <openssl/sha.h>

namespace v2test {

struct CLBootstrapFixture {
    cryptonote::dao::dao_tally_key_record   record;
    cryptonote::dao::dao_share_set_record   share_set;
    std::vector<uint8_t>                    local_share;   // party 0 (compat)
    std::vector<std::vector<uint8_t>>       local_shares;  // one per party
    std::vector<crypto::public_key> committee_pubs;
    std::vector<crypto::secret_key> committee_sks;
};

inline std::vector<uint8_t> sign_magnitude(const BICYCL::Mpz& v)
{
    std::vector<uint8_t> out;
    out.push_back(v.sgn() < 0 ? 1u : 0u);
    BICYCL::Mpz abs_v;
    BICYCL::Mpz::abs(abs_v, v);
    if (!abs_v.is_zero()) {
        auto bv = static_cast<std::vector<unsigned char>>(abs_v);
        out.insert(out.end(), bv.begin(), bv.end());
    }
    return out;
}

inline bool make_cl_bootstrap_3party(CLBootstrapFixture& out, uint64_t seed)
{
    using namespace cryptonote;
    using namespace cryptonote::dao;

    BICYCL::RandGen rng;
    rng.set_seed(BICYCL::Mpz(static_cast<unsigned long>(seed)));
    auto cl = cl_dkg_make_hsmq(128, rng);
    if (!cl) return false;

    std::vector<crypto::public_key> committee_pubs(3);
    std::vector<crypto::secret_key> committee_sks(3);
    for (int i = 0; i < 3; ++i)
        crypto::generate_keys(committee_pubs[i], committee_sks[i]);

    auto net = dkg_make_inproc_network(3);
    std::vector<std::unique_ptr<cl_dkg_p2p_runner>> runners;
    for (uint32_t i = 0; i < 3; ++i) {
        cl_dkg_config cfg;
        cfg.cl = cl;
        cfg.committee_size = 3;
        cfg.threshold_internal = 1;
        cfg.member_ids = committee_pubs;
        cfg.local_party_id = i + 1;
        cfg.soundness_bytes = 32;
        cfg.test_seed = seed + i + 1;
        cfg.phase_timeout_seconds = 180;
        runners.push_back(std::make_unique<cl_dkg_p2p_runner>(
            cfg, std::move(net.endpoints[i])));
    }
    for (auto& r : runners) if (!r->start()) return false;

    std::vector<cl_dkg_result> results(3);
    for (size_t i = 0; i < 3; ++i) {
        if (!runners[i]->wait(results[i], 300)) return false;
        if (!results[i].ok) return false;
    }
    for (auto& r : runners) r->stop();

    // Assemble the CL key context wire.
    cl_key_context ctx;
    {
        auto qb = static_cast<std::vector<unsigned char>>(cl->q());
        ctx.q.assign(qb.begin(), qb.end());
        ctx.k = static_cast<uint32_t>(cl->k());
        ctx.p = sign_magnitude(cl->p());
        BICYCL::QFI pk_qfi;
        std::size_t off = 0;
        if (!cl_dkg_qfi_from_bytes(results[0].ctx.pk_qfi, off, pk_qfi,
                                   cl->Cl_G().discriminant()))
            return false;
        if (!cl_dkg_qfi_to_bytes(ctx.pk_qfi, pk_qfi)) return false;
        BICYCL::Mpz D;
        off = 0;
        if (!cl_dkg_mpz_from_bytes_signed(results[0].ctx.D, off, D, true))
            return false;
        ctx.D = sign_magnitude(D);
    }
    std::vector<uint8_t> ctx_wire;
    if (!dao_cl_key_context_serialize(ctx, ctx_wire)) return false;

    // Committee member bytes.
    std::vector<std::vector<uint8_t>> members(3);
    for (int i = 0; i < 3; ++i)
        members[i].assign(committee_pubs[i].data,
                          committee_pubs[i].data + 32);

    // Build the key record.
    out.record = dao_tally_key_record{};
    out.record.committee_size = 3;
    out.record.threshold      = 2;
    out.record.t              = 1;
    out.record.committee_members = members;
    {
        std::vector<uint8_t> buf;
        const char* dom = "VeilRoot-DAO-DKG-COMMITTEE-V1";
        buf.insert(buf.end(), dom, dom + std::strlen(dom));
        for (const auto& m : members) buf.insert(buf.end(), m.begin(), m.end());
        out.record.committee_id_hash.assign(32, 0);
        SHA256(buf.data(), buf.size(), out.record.committee_id_hash.data());
    }
    out.record.cl_modulus        = ctx_wire;
    out.record.activation_height = 1;
    out.record.dkg_transcript_hash.assign(32, 0);
    SHA256(ctx_wire.data(), ctx_wire.size(),
           out.record.dkg_transcript_hash.data());
    out.record.key_id.assign(32, 0);
    {
        std::vector<uint8_t> kb;
        if (!out.record.serialize(kb)) return false;
        SHA256(kb.data(), kb.size(), out.record.key_id.data());
    }

    // Build the share set.
    out.share_set = dao_share_set_record{};
    out.share_set.version        = 3;
    out.share_set.share_set_id   = static_cast<uint64_t>(
        share_set_id_for_key_id(out.record.key_id));
    out.share_set.height         = 1;
    out.share_set.threshold      = out.record.threshold;
    out.share_set.key_id         = out.record.key_id;
    out.share_set.committee_id_hash = out.record.committee_id_hash;
    out.share_set.committee_members = out.record.committee_members;
    out.share_set.cl_gammas_serialized = results[0].gammas_serialized;
    out.share_set.qualified_ids = results[0].qualified_ids;

    out.local_share = results[0].local_secret_share;
    out.local_shares.resize(3);
    for (int i = 0; i < 3; ++i)
        out.local_shares[i] = results[i].local_secret_share;
    out.committee_pubs = committee_pubs;
    out.committee_sks  = committee_sks;
    return true;
}

} // namespace v2test

#endif // VEILROOT_ENABLE_CL
