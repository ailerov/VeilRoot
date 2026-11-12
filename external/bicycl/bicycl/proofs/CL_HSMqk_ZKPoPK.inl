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

#ifndef BICYCL_PROOF_CL_HSMQK_ZKPOPK_INL
#define BICYCL_PROOF_CL_HSMQK_ZKPOPK_INL

#include "bicycl/proofs/CL_HSMqk_ZKPoPK.hpp"

namespace BICYCL {
  /* */
  inline
  CL_HSMqk_ZKPoPK::CL_HSMqk_ZKPoPK (const CL_HSMqk &CL,
                                            HashAlgo &H,
                                            const CL_HSMqk::PublicKey &pk,
                                            const CL_HSMqk::CipherText &c,
                                            const CL_HSMqk::ClearText &a,
                                            const Mpz &r, RandGen &randgen)
  {
    int soundness = H.digest_nbits();

    Mpz B (CL.encrypt_randomness_bound());
    Mpz::mulby2k (B, B, soundness);
    Mpz::mulby2k (B, B, CL.lambda_distance());

    Mpz r1 (randgen.random_mpz (B));
    Mpz r2 (randgen.random_mpz (CL.M()));
    CL_HSMqk::CipherText t (CL, pk, CL_HSMqk::ClearText (CL, r2), r1);

    /* k = hash(CL public params, pk, c, t1, t2)*/
    k_ = k_from_hash (H, CL, pk, c, t.c1(), t.c2());
    // TODO use variable length digest of size C

    Mpz::mul (u1_, k_, r);
    Mpz::add (u1_, u1_, r1);

    Mpz::mul (u2_, k_, a);
    Mpz::add (u2_, u2_, r2);
    Mpz::mod (u2_, u2_, CL.M());
  }

  inline
  CL_HSMqk_ZKPoPK::CL_HSMqk_ZKPoPK(const Mpz & u1,
                                           const Mpz & u2,
                                           const Mpz & k)
    : u1_(u1), u2_(u2), k_(k)
  {}


  /* */
  inline
  bool CL_HSMqk_ZKPoPK::verify (const CL_HSMqk &CL, HashAlgo &H,
                                    const CL_HSMqk::PublicKey &pk,
                                    const CL_HSMqk::CipherText &c) const
  {
    bool ret = true;

    /* Check that pk is a form in G */
    ret &= pk.elt().discriminant() == CL.Cl_G().discriminant();
    ret &= CL.genus (pk.elt()) == CL_HSMqk::Genus ({ 1, 1 });

    /* Check that c1 is a form in G */
    ret &= c.c1().discriminant() == CL.Cl_G().discriminant();
    ret &= CL.genus (c.c1()) == CL_HSMqk::Genus ({ 1, 1 });

    /* Check that c2 */
    ret &= c.c2().discriminant() == CL.Cl_Delta().discriminant();
    ret &= CL.genus (c.c2()) == CL_HSMqk::Genus ({ 1, 1 });

    /* Check u1 bound */
    Mpz B (1UL);
    Mpz::mulby2k (B, B, CL.lambda_distance());
    Mpz::add (B, B, 1UL);
    Mpz::mulby2k (B, B, H.digest_nbits());
    Mpz::mul (B, B, CL.encrypt_randomness_bound());
    ret &= (u1_.sgn() >= 0 && u1_ <= B);

    /* Check u2 bound */
    ret &= (u2_.sgn() >= 0 && u2_ < CL.M());

    /* cu = (gq^u1, pk^u1 f^u2) */
    // CL_HSMqk::CipherText cu (C, pk, CL_HSMqk::ClearText (C, u2_), u1_);
    QFI cu1, cu2;
    CL.power_of_h(cu1, u1_);
    pk.exponentiation(CL, cu2, u1_);
    if (CL.compact_variant())
      CL.from_Cl_DeltaK_to_Cl_Delta (cu2);
    QFI temp{CL.power_of_f(u2_)};
    CL.Cl_Delta().nucomp(cu2, cu2, temp);


    /* ck = (c1^k, c2^k) */
    // CL_HSMqk::CipherText ck (C.scal_ciphertexts (pk, c, k_, Mpz (0UL)));
    // Rewrite the operations of CL_HSMqk::CipherText without the task parallelism.
    // It's not wanted in this case because the current function can be executed
    // inside other threads, and we do not want these threads to create sub-threads.
    QFI c1k, c2k;
    CL.Cl_G().nupow(c1k, c.c1(), k_);
    CL.Cl_Delta().nupow(c2k, c.c2(), k_);

    QFI t1, t2;
    /* Using the equality gq^u1 == t1*c1^k to compute t1 */
    CL.Cl_G().nucompinv (t1, cu1, c1k);

    /* Using the equality pk^u1 f^u2 == t2*c2^k to compute t2 */
    CL.Cl_Delta().nucompinv (t2, cu2, c2k);

    /* Generate k using hash function and check that it matches */
    Mpz k (k_from_hash (H, CL, pk, c, t1, t2));
    ret &= (k == k_);

    return ret;
  }

  inline
  const Mpz & CL_HSMqk_ZKPoPK::u1() const
  {
    return u1_;
  }

  inline
  const Mpz & CL_HSMqk_ZKPoPK::u2() const
  {
    return u2_;
  }

  inline
  const Mpz & CL_HSMqk_ZKPoPK::k() const
  {
    return k_;
  }

  inline
  size_t CL_HSMqk_ZKPoPK::num_bytes() const
  {
    return u1_.num_bytes() + u2_.num_bytes() + k_.num_bytes();
  }

  /* */
  inline
  Mpz CL_HSMqk_ZKPoPK::k_from_hash (HashAlgo &H, const CL_HSMqk &CL,
                                        const CL_HSMqk::PublicKey &pk,
                                        const CL_HSMqk::CipherText &c,
                                        const QFI &t1, const QFI &t2) const
  {
    return Mpz (H (pk, CL, c, t1, t2));
  }

} /* BICYCL namespace */

#endif /* BICYCL_PROOF_CL_HSMQK_ZKPOPK_INL */
