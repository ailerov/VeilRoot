/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2026  Cyril Bouvier <cyril.bouvier@lirmm.fr>
 *                     Guilhem Castagnos <guilhem.castagnos@math.u-bordeaux.fr>
 *                     Laurent Imbert <laurent.imbert@lirmm.fr>
 *                     Fabien Laguillaumie <fabien.laguillaumie@lirmm.fr>
 *                     Quentin Combal <quentin.combal@lirmm.fr>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef BICYCL_PROOFS_CL_HSMQK_BATCH_DLOG_AOK_INL
#define BICYCL_PROOFS_CL_HSMQK_BATCH_DLOG_AOK_INL

#include "bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/proofs/CL_HSMqk_Batch_Dlog_AoK.hpp"

namespace BICYCL
{
inline CL_HSMqk_Batch_Dlog_AoK::CL_HSMqk_Batch_Dlog_AoK(const Mpz & u, const QFI & R)
  : u_{u},
    R_{R}
{
}

inline CL_HSMqk_Batch_Dlog_AoK::CL_HSMqk_Batch_Dlog_AoK(const CL_HSMqk & CL,
                                            size_t soundness_bytes,
                                            RandGen & randgen,
                                            const size_t a_rand_bound,
                                            const size_t x_rand_bound,
                                            const unsigned int t,
                                            const Mpz & delta,
                                            const Mpz & a,
                                            const std::vector<Mpz> & xi,
                                            const std::vector<QFI> & Ci)
{
  if (xi.size() != t)
    throw std::invalid_argument("xi shall have exactly t elements");
  if (Ci.size() != t + 1)
    throw std::invalid_argument("Ci shall have exactly t+1 elements");

  // Sample r, random bound is :
  // 2^lambda_dist * 2^soundness * (2^size_a + t * delta * 2^size_x)
  Mpz r_bound{static_cast<unsigned long>(t)};
  Mpz::mul(r_bound, r_bound, delta);
  Mpz::mulby2k(r_bound, r_bound, x_rand_bound); // t * delta * 2^size_x
  Mpz temp{1UL};
  Mpz::mulby2k(temp, temp, a_rand_bound);
  Mpz::add(r_bound, r_bound, temp);             // + 2^size_a
  size_t shift = CL.lambda_distance() + soundness_bytes * 8u;
  Mpz::mulby2k(r_bound, r_bound, shift);        // * 2^lambda_dist * 2^soundness
  Mpz r(randgen.random_mpz(r_bound));

  // Compute R = h^r
  CL.power_of_h(R_, r);

  // Compute t+1 hash-challenges
  std::vector<Mpz> challenges;
  hash_for_challenge(challenges, soundness_bytes, CL, delta, Ci);

  // a = ai
  // x[i] = r[i]
  // Compute u = r + a*ch[0] + delta*(x[0]*ch[1] + ... + x[t-1]*ch[t])
  for (unsigned int k = 0u; k < t; k++)
  {
    Mpz::mul(temp, xi[k], challenges[k + 1]);
    Mpz::add(u_, u_, temp); // + x[k]*ch[k+1]
  }
  Mpz::mul(u_, u_, delta);  // * delta
  Mpz::mul(temp, a, challenges[0]);
  Mpz::add(u_, u_, temp);   // + a*ch[0]
  Mpz::add(u_, u_, r);      // + r
}

/* */
inline const Mpz & CL_HSMqk_Batch_Dlog_AoK::u() const
{
  return u_;
}

/* */
inline const QFI & CL_HSMqk_Batch_Dlog_AoK::R() const
{
  return R_;
}

/* */
inline bool CL_HSMqk_Batch_Dlog_AoK::verify(size_t soundness_bytes,
                                      const CL_HSMqk & CL,
                                      const Mpz & delta,
                                      size_t m,
                                      const std::vector<QFI> & Ci) const
{
  if (Ci.size() != m)
    throw std::invalid_argument("Ci shall have exactly m elements");

  // Compute h^u
  QFI hu;
  CL.power_of_h(hu, u_);

  // Compute t+1 hash-challenges
  std::vector<Mpz> challenges;
  hash_for_challenge(challenges, soundness_bytes, CL, delta, Ci);

  // Compute R * C[0]^ch[0] * C[1]^ch[1] * ... * C[t]^ch[t]
  QFI product;
  // WNAF multi-expo with w = 5
  CL.Cl_G().nupow(product, Ci, challenges, 5);
  CL.Cl_G().nucomp(product, product, R_);

  // Finally verify the product
  return (hu == product);
}

inline void
CL_HSMqk_Batch_Dlog_AoK::hash_for_challenge(std::vector<Mpz> & challenges,
                                      size_t soundness_bytes,
                                      const CL_HSMqk & CL,
                                      const Mpz & Delta,
                                      const std::vector<QFI> & Ci) const
{
  // ch = H(CL params, Delta, R, C0, ..., Cn-1)
  // Extended hash of the statement, get t+1 challenges of [soundness] bytes
  HashAlgo H((soundness_bytes <= 16) ? HashAlgo::SHAKE128 : HashAlgo::SHAKE256,
             soundness_bytes * Ci.size());
  HashAlgo::Digest hashed(H(CL, Delta, R_, Ci));

  // Split extended hash into t+1 challenges of [soundness] bytes
  challenges.reserve(Ci.size());
  for (unsigned int k = 0u; k < Ci.size(); ++k)
  {
    unsigned char * start = hashed.data() + k * soundness_bytes;
    std::vector<unsigned char> ch(start, start + soundness_bytes);
    challenges.emplace_back(ch);
  }
}

}


#endif /*BICYCL_PROOFS_CL_HSMQK_BATCH_DLOG_AOK_INL*/