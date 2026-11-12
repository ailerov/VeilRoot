/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2024  Cyril Bouvier <cyril.bouvier@lirmm.fr>
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
#ifndef BICYCL_PROOFS_CL_HSMQK_EC_DLOG_ZKPWPE_INL
#define BICYCL_PROOFS_CL_HSMQK_EC_DLOG_ZKPWPE_INL

#include "CL_HSMqk_EC_Dlog_ZKPwPE.hpp"

namespace BICYCL
{
  /**
   * CL_HSMqk_Dlog_HVZKPwPE contructor
   *
   **/
  inline
  CL_HSMqk_EC_Dlog_ZKPwPE::CL_HSMqk_EC_Dlog_ZKPwPE(const Mpz & u1,
                           const Mpz & u2,
                           const Mpz & chl)
    : u1_{u1},
      u2_{u2},
      chl_{chl}
  {
    // Nothing to do
  }

  /**
   * CL_HSMqk_Dlog_HVZKPwPE contructor
   *
   **/
  inline
  CL_HSMqk_EC_Dlog_ZKPwPE::CL_HSMqk_EC_Dlog_ZKPwPE(HashAlgo & H,
                           const ECGroup & E,
                           const SecretValue & x,
                           const ECPoint & Q,
                           const CL_HSMqk & CL,
                           const CL_HSMqk::PublicKey & pk,
                           const CL_HSMqk::CipherText & c,
                           const Mpz & r,
                           RandGen & randgen)
  {
    int soundness = H.digest_nbits();

    // Compute r1 randomness bound
    Mpz B(CL.encrypt_randomness_bound());     // B = S
    Mpz::mulby2k(B, B, soundness);            // B = S * 2^soundness
    Mpz::mulby2k(B, B, CL.lambda_distance()); // B = S * 2^soundness * 2^dist

    // Sample r1, r2
    Mpz r1(randgen.random_mpz(B));
    Mpz r2(randgen.random_mpz(CL.M()));
    // Compute t1, t2
    CL_HSMqk::CipherText t(CL, pk, CL_HSMqk::ClearText(CL, r2), r1);

    // Compute T
    ECPoint T{E};
    E.scal_mul_gen(T, BN(r2));

    // Challenge = H(public params, Q, pk, c, t1, t2, T)
    chl_ = hash_for_challenge(H, CL, E, Q, pk, c, t.c1(), t.c2(), T);

    // u1 = r1 + ch*r
    Mpz::mul(u1_, chl_, r);
    Mpz::add(u1_, u1_, r1);

    // u1 = r2 + ch*x mod q^k
    Mpz::mul(u2_, chl_, static_cast<Mpz>(x));
    Mpz::add(u2_, u2_, r2);
    Mpz::mod(u2_, u2_, CL.M());
  }

#ifdef BICYCL_WITH_PTHREADS
  /**
   * CL_HSMqk_Dlog_HVZKPwPE contructor
   *
   **/
  inline
  CL_HSMqk_EC_Dlog_ZKPwPE::CL_HSMqk_EC_Dlog_ZKPwPE(HashAlgo & H,
                           const ECGroup & E,
                           const SecretValue & x,
                           const ECPoint & Q,
                           const CL_HSMqk & CL,
                           const CL_HSMqk::PublicKey & pk,
                           const CL_HSMqk::CipherText & c,
                           const Mpz & r,
                           RandGen & randgen,
                           std::thread & thread_ckey)
  {
    int soundness = H.digest_nbits();

    // Compute r1 randomness bound
    Mpz B(CL.encrypt_randomness_bound());     // B = S
    Mpz::mulby2k(B, B, soundness);            // B = S * 2^soundness
    Mpz::mulby2k(B, B, CL.lambda_distance()); // B = S * 2^soundness * 2^dist

    // Sample r1, r2
    Mpz r1(randgen.random_mpz(B));
    Mpz r2(randgen.random_mpz(CL.M()));
    // Compute t1, t2
    CL_HSMqk::CipherText t(CL, pk, CL_HSMqk::ClearText(CL, r2), r1);

    // Compute T
    ECPoint T{E};
    E.scal_mul_gen(T, BN(r2));

    // Ensure Ckey computation is done
    thread_ckey.join();

    // Compute hash-challenge
    chl_ = hash_for_challenge(H, CL, E, Q, pk, c, t.c1(), t.c2(), T);

    // u1 = r1 + ch*r
    Mpz::mul(u1_, chl_, r);
    Mpz::add(u1_, u1_, r1);

    // u1 = r2 + ch*x mod q^k
    Mpz::mul(u2_, chl_, static_cast<Mpz>(x));
    Mpz::add(u2_, u2_, r2);
    Mpz::mod(u2_, u2_, CL.M());
  }
#endif

  /**
   * Getters
   */
  inline const Mpz & CL_HSMqk_EC_Dlog_ZKPwPE::u1() const
  {
    return u1_;
  }
  inline const Mpz & CL_HSMqk_EC_Dlog_ZKPwPE::u2() const
  {
    return u2_;
  }
  inline const Mpz & CL_HSMqk_EC_Dlog_ZKPwPE::chl() const
  {
    return chl_;
  }


  /**
   * Verify
   *
   **/
  inline
  bool CL_HSMqk_EC_Dlog_ZKPwPE::verify(HashAlgo & H,
                           const ECGroup & E,
                           const ECPoint & Q,
                           const CL_HSMqk & CL,
                           const CL_HSMqk::PublicKey & pk,
                           const CL_HSMqk::CipherText & c) const
  {
    bool ret = true;

    /* Check that Q belongs to E*/
    if (!E.is_in_group(Q))
      return false;

    int soundness = H.digest_nbits();

    /* Check that pk is a form in G */
    ret &= pk.elt().discriminant() == CL.Cl_G().discriminant();
    ret &= CL.genus(pk.elt()) == CL_HSMqk::Genus({1, 1});

    /* Check that c1 is a form in G */
    ret &= c.c1().discriminant() == CL.Cl_G().discriminant();
    ret &= CL.genus(c.c1()) == CL_HSMqk::Genus({1, 1});

    /* Check that c2 is a form in G */
    ret &= c.c2().discriminant() == CL.Cl_Delta().discriminant();
    ret &= CL.genus(c.c2()) == CL_HSMqk::Genus({1, 1});

    /* Check u1 bound */
    Mpz B(1UL);
    Mpz::mulby2k(B, B, CL.lambda_distance());
    Mpz::add(B, B, 1UL);
    Mpz::mulby2k(B, B, soundness);
    Mpz::mul(B, B, CL.encrypt_randomness_bound());
    ret &= (u1_.sgn() >= 0 && u1_ <= B);

    /* Check u2 bound */
    ret &= (u2_.sgn() >= 0 && u2_ < CL.M());

    /* cu = (gq^u1, pk^u1 f^u2) */

#ifdef BICYCL_WITH_PTHREADS
    // Compute cu in a separate tread

    auto compute_cu = [this, &CL, &pk] (CL_HSMqk::CipherText & cu) {
      cu = CL_HSMqk::CipherText(CL, pk, CL_HSMqk::ClearText(CL, u2_), u1_);
    };

    CL_HSMqk::CipherText cu;
    std::thread th(compute_cu, std::ref(cu));
#else
    CL_HSMqk::CipherText cu(CL, pk, CL_HSMqk::ClearText(CL, u2_), u1_);
#endif

    /* ck = (c1^k, c2^k) */
    CL_HSMqk::CipherText ck(CL.scal_ciphertexts(pk, c, chl_, Mpz(0UL)));

#ifdef BICYCL_WITH_PTHREADS
    // Wait until cu computation is done
    th.join();
#endif

    QFI t1, t2;

    /* Using the equality gq^u1 == t1*c1^k to compute t1 */
    CL.Cl_G().nucompinv(t1, cu.c1(), ck.c1());

    /* Using the equality pk^u1 f^u2 == t2*c2^k to compute t2 */
    CL.Cl_Delta().nucompinv(t2, cu.c2(), ck.c2());

    /* Using the equality u2.P = t2 + ch.Q to compute T */
    ECPoint T(E);
    BN chl_neg = BN(chl_); chl_neg.neg();
    E.scal_mul(T, BN(u2_), chl_neg, Q);

    /* Generate chl using hash function and check that it matches chl_ */
    Mpz chl{hash_for_challenge(H, CL, E, Q, pk, c, t1, t2, T)};
    ret &= (chl == chl_);

    return ret;
  }

  /**
   * Hash for challenge util
   *
   **/
  inline
  Mpz CL_HSMqk_EC_Dlog_ZKPwPE::hash_for_challenge(HashAlgo & H,
                                      const CL_HSMqk & CL,
                                      const ECGroup & E,
                                      const ECPoint & Q,
                                      const CL_HSMqk::PublicKey & pk,
                                      const CL_HSMqk::CipherText & c,
                                      const QFI & t1,
                                      const QFI & t2,
                                      const ECPoint & T) const
  {
    return Mpz(H(CL,
                 E,
                 ECPointGroupCRefPair(Q, E),
                 ECPointGroupCRefPair(T, E),
                 pk,
                 c,
                 t1,
                 t2));
  }

} /* namespace BICYCL */

#endif /* BICYCL_PROOFS_CL_HSMQK_EC_DLOG_ZKPWPE_INL */