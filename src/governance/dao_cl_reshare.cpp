// Copyright (c) 2024-2026, The VeilRoot Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "governance/dao_cl_reshare.h"

#ifdef VEILROOT_ENABLE_CL

#include <stdexcept>

namespace cryptonote {
namespace dao {

bool dao_cl_reshare_inproc(
    const BICYCL::CL_HSMqk& CL,
    const std::vector<std::unique_ptr<BICYCL::CL_Threshold_Static>>& old_players,
    const std::vector<std::unique_ptr<BICYCL::CL_Threshold_Static>>& new_players,
    const dao_cl_reshare_params& params,
    BICYCL::RandGen& randgen,
    std::string* error_out)
{
    using namespace BICYCL;
    try {
        if (old_players.size() != params.n_old) return false;
        if (new_players.size() != params.n_new) return false;
        if (params.old_contributors.size() != params.t_old + 1u) return false;
        for (unsigned int i : params.old_contributors) {
            if (i >= params.n_old) return false;
        }

        const auto& old_pk = old_players[0]->pk();
        const auto& old_gammas = old_players[0]->Gammas();
        if (old_gammas.size() < params.n_old) return false;

        CL_Threshold_Static::ParticipantsSet old_set;
        for (unsigned int i : params.old_contributors)
            old_set.insert(i);

        // Phase 1: lightweight prestate from each contributor.
        std::vector<CL_Threshold_Static::ResharePreState> pres;
        pres.reserve(params.old_contributors.size());
        for (unsigned int i : params.old_contributors)
            pres.push_back(old_players[i]->compute_reshare_prestate(old_set));

        // Phase 2: R = sum(r_i) / D^2. Verify exact divisibility.
        const Mpz& D = old_players[params.old_contributors[0]]
                           ->interpolation_scale();
        Mpz D2;
        Mpz::mul(D2, D, D);
        Mpz r_sum(0UL);
        for (const auto& p : pres)
            Mpz::add(r_sum, r_sum, p.r_i);
        Mpz R, rem;
        Mpz::fdiv_qr(R, rem, r_sum, D2);
        if (!rem.is_zero()) return false;

        // Phase 3: c_i assignment. Lowest contributor ID gets R, rest zero.
        std::vector<Mpz> c_values(pres.size(), Mpz(0UL));
        size_t min_idx = 0;
        for (size_t k = 1; k < params.old_contributors.size(); ++k)
            if (params.old_contributors[k]
                < params.old_contributors[min_idx])
                min_idx = k;
        c_values[min_idx] = R;

        // Phase 4: full contributions with assigned c_i.
        std::vector<CL_Threshold_Static::ReshareContribution> contribs;
        contribs.reserve(params.old_contributors.size());
        for (size_t k = 0; k < params.old_contributors.size(); ++k) {
            unsigned int i = params.old_contributors[k];
            auto c = old_players[i]->create_reshare_contribution(
                CL, old_set, params.n_new, params.t_new, randgen,
                c_values[k]);
            if (c.shares.size() != params.n_new) return false;
            if (c.commitments.size() != params.t_new + 1u) return false;
            if (!c.batch_proof || !c.old_share_link_proof) return false;
            contribs.push_back(std::move(c));
        }

        // Phase 5: distribute to new players.
        for (auto& np : new_players)
            np->begin_reshare(old_set, params.n_old, params.t_old);

        for (unsigned int j = 0; j < params.n_new; ++j) {
            for (const auto& c : contribs) {
                new_players[j]->add_reshare_contribution(
                    CL,
                    c.old_dealer_id,
                    c.shares[j],
                    c.c_i,
                    c.r_i,
                    c.L_i,
                    c.commitments,
                    *c.batch_proof,
                    *c.old_share_link_proof,
                    old_gammas.at(c.old_dealer_id));
            }
        }

        // Phase 6: finalize. pk must equal old pk.
        for (auto& np : new_players)
            np->finalize_reshare(CL, old_pk);

        return true;
    }
    catch (const std::exception& e) {
        if (error_out) *error_out = e.what();
        return false;
    }
    catch (...) {
        if (error_out) *error_out = "unknown exception";
        return false;
    }
}

} // namespace dao
} // namespace cryptonote

#endif // VEILROOT_ENABLE_CL
