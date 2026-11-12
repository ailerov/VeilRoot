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
#ifndef BICYCL_PROOFS_CL_HSMQK_DLOGEQ_AOK_INL
#define BICYCL_PROOFS_CL_HSMQK_DLOGEQ_AOK_INL

#include "CL_HSMqk_DlogEq_AoK.hpp"

namespace BICYCL
{
inline CL_HSMqk_DlogEq_AoK::CL_HSMqk_DlogEq_AoK(const CL_HSMqk & CL,
                                    size_t soundness_bytes,
                                    RandGen & randgen,
                                    const Mpz & x,
                                    const QFI & f1,
                                    const QFI & f2,
                                    const QFI & q1,
                                    const QFI & q2)
{
  // Sample r, random bound is :
  // 2^lambda_dist * 2^challenge_bits * 2^size_x
  Mpz r{randgen.random_mpz_2exp(x.nbits() + soundness_bytes * 8u
                                + CL.lambda_distance())};

  // Compute commitment R2 = f2^r
  CL.Cl_G().nupow(R2_, f2, r);

  // Compute commitment R1 = f1^r
  CL.Cl_G().nupow(R1_, f1, r);

  // Compute hash-challenge
  Mpz ch{hash_for_challenge(soundness_bytes, CL, f1, f2, q1, q2)};

  // Compute "response" u = r + ch*x
  Mpz::mul(u_, ch, x);
  Mpz::add(u_, u_, r);
}

#ifdef BICYCL_WITH_PTHREADS
/* Multi-threaded variant */
inline CL_HSMqk_DlogEq_AoK::CL_HSMqk_DlogEq_AoK(const CL_HSMqk & CL,
                                    size_t soundness_bytes,
                                    RandGen & randgen,
                                    const Mpz & x,
                                    const QFI & f1,
                                    const QFI & f2,
                                    const QFI & q1,
                                    const QFI & q2,
                                    std::thread & thread_q)
{
  // Sample r, random bound is :
  // 2^lambda_dist * 2^challenge_bits * 2^size_x
  Mpz r{randgen.random_mpz_2exp(x.nbits() + soundness_bytes * 8u
                                + CL.lambda_distance())};

  // Compute R2 = f2^r on a another thread
  void (ClassGroup::*nupow_ptr)(QFI &, const QFI &, const Mpz &) const
      = &ClassGroup::nupow;
  std::thread thread_R2{
      nupow_ptr, CL.Cl_G(), std::ref(R2_), std::cref(f2), std::cref(r)};

  // Compute commitment R1 = f1^r
  CL.Cl_G().nupow(R1_, f1, r);

  // Compute hash-challenge
  thread_q.join();  // q1 and q2 required
  thread_R2.join(); // R2 required
  Mpz ch{hash_for_challenge(soundness_bytes, CL, f1, f2, q1, q2)};

  // Compute "response" u = r + ch*x
  Mpz::mul(u_, ch, x);
  Mpz::add(u_, u_, r);
}
#endif

/* */
inline const Mpz & CL_HSMqk_DlogEq_AoK::u() const
{
  return u_;
}

/* */
inline const QFI & CL_HSMqk_DlogEq_AoK::R1() const
{
  return R1_;
}

/* */
inline const QFI & CL_HSMqk_DlogEq_AoK::R2() const
{
  return R2_;
}

/* */
inline bool CL_HSMqk_DlogEq_AoK::verify(const CL_HSMqk & CL,
                                  size_t soundness_bytes,
                                  const QFI & f1,
                                  const QFI & f2,
                                  const QFI & q1,
                                  const QFI & q2) const
{
  // Compute hash-challenge
  Mpz ch{hash_for_challenge(soundness_bytes, CL, f1, f2, q1, q2)};

  // check: perform generic check f^u = R*Q^ch
  auto check
      = [this, &CL, &ch] (
            bool & success, const QFI & f, const QFI & Q, const QFI & R) {
          QFI check_right, check_left;

          // f^u
          if (f == CL.h()) // Optimize the case where f = h
            CL.power_of_h(check_left, u_);
          else
            CL.Cl_G().nupow(check_left, f, u_);

          // R*Q^ch
          CL.Cl_G().nupow(check_right, Q, ch);
          CL.Cl_G().nucomp(check_right, check_right, R);

          // Compare
          success = (check_left == check_right);
        };

#ifdef BICYCL_WITH_PTHREADS
  // Check f1^u = R1*q1^ch on a second thread
  bool check1;
  std::thread thread_check1{
      check, std::ref(check1), std::cref(f1), std::cref(q1), std::cref(R1_)};

  // Check f2^u = R2*q2^ch
  bool check2;
  check(check2, f2, q2, R2_);

  thread_check1.join();
  return (check1 && check2);

#else
  bool success;
  check(success, f1, q1, R1_);   // Check f1^u = R1*q1^ch
  if (success == true)           // If first check passed
    check(success, f2, q2, R2_); // Check f2^u = R2*q2^ch

  return success;

#endif
}

/* */
inline Mpz CL_HSMqk_DlogEq_AoK::hash_for_challenge(size_t soundness_bytes,
                                             const CL_HSMqk & CL,
                                             const QFI & f1,
                                             const QFI & f2,
                                             const QFI & q1,
                                             const QFI & q2) const
{
  HashAlgo H((soundness_bytes <= 16) ? HashAlgo::SHAKE128 : HashAlgo::SHAKE256,
             soundness_bytes);
  return Mpz(H(CL, R1_, R2_, f1, f2, q1, q2));
}
}

#endif /*BICYCL_PROOFS_CL_HSMQK_DLOGEQ_AOK_INL*/