/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2022  Cyril Bouvier <cyril.bouvier@lirmm.fr>
 *                     Guilhem Castagnos <guilhem.castagnos@math.u-bordeaux.fr>
 *                     Laurent Imbert <laurent.imbert@lirmm.fr>
 *                     Fabien Laguillaumie <fabien.laguillaumie@lirmm.fr>
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
#ifndef BICYCL_PROOFS_EC_PROOFS_INL
#define BICYCL_PROOFS_EC_PROOFS_INL

#include "EC_proofs.hpp"

namespace BICYCL
{
  /* */
  inline
  EC_Dlog_ZKPoK::EC_Dlog_ZKPoK (const ECGroup &E, HashAlgo &H, RandGen & randgen,
                            const SecretValue &s, const PublicValue &Q,
                            const Mpz & sid)
    : R_(E)
  {
    BN r (E.random_mod_order(randgen));
    E.scal_mul_gen (R_, r);

    BN c (hash_for_challenge (H, E, R_, Q, sid));

    E.mul_mod_order (z_, c, s);
    E.sub_mod_order (z_, r, z_); /* z = r - c*s  mod q */
  }

  /* */
  inline
  EC_Dlog_ZKPoK::EC_Dlog_ZKPoK (const ECGroup &E, HashAlgo &H, RandGen & randgen,
                            const SecretValue &s)
    : EC_Dlog_ZKPoK (E, H, randgen, s, compute_Q_from_secret (E, s))
  {
  }

  /* */
  inline EC_Dlog_ZKPoK::EC_Dlog_ZKPoK(const ECGroup & E,
                                  const ECPoint & R,
                                  const BN & z)
    : R_(E, R),
      z_(z)
  {
  }

  /* */
  inline EC_Dlog_ZKPoK::EC_Dlog_ZKPoK(const ECGroup & E,
                                  const BN & Rx,
                                  const BN & Ry,
                                  const BN & z)
    : R_(E, Rx, Ry),
      z_(z)
  {
  }

  /* */
  inline
  EC_Dlog_ZKPoK::EC_Dlog_ZKPoK (const ECGroup &E, const EC_Dlog_ZKPoK &p)
    : EC_Dlog_ZKPoK(E, p.R_, p.z_)
  {
  }

  /* */
  inline
  EC_Dlog_ZKPoK::EC_Dlog_ZKPoK (const ECGroup &E)
    : R_ (E)
  {
  }

  inline
  const ECPoint & EC_Dlog_ZKPoK::R() const
  {
    return R_;
  }

  inline
  const BN & EC_Dlog_ZKPoK::z() const
  {
    return z_;
  }

  /* */
  inline
  bool EC_Dlog_ZKPoK::verify (const ECGroup &E, HashAlgo &H,
                            const PublicValue &Q, const Mpz & sid) const
  {
    if (!E.is_in_group (Q))
      return false;

    BN c (hash_for_challenge (H, E, R_, Q, sid));

    ECPoint rhs (E);
    E.scal_mul (rhs, z_, c, Q); /* z*P + c*Q */

    return E.ec_point_eq (R_, rhs);
  }

  /* */
  inline
  size_t EC_Dlog_ZKPoK::num_bytes(ECGroup const & E) const
  {
    return R_.num_bytes(E) + z_.num_bytes();
  }

  /* */
  inline
  BN EC_Dlog_ZKPoK::hash_for_challenge (HashAlgo & H,
                                      const ECGroup &E,
                                      const ECPoint &R,
                                      const ECPoint &Q,
                                      const Mpz &sid)
  {
    return BN (H (E, ECPointGroupCRefPair (R, E),
                              ECPointGroupCRefPair (Q, E), sid));
  }

  /* */
  inline
  ECPoint EC_Dlog_ZKPoK::compute_Q_from_secret(const ECGroup & E,
                                             const SecretValue & s)
  {
    return ECPoint(E,s);
  }

  /******************************************************************************/
  /* */
  inline
  EC_3Dlog_ZKAoK::EC_3Dlog_ZKAoK (const ECGroup &E, HashAlgo &H, RandGen & randgen,
                        const ECPoint & R, const SecretValue &s,
                        const SecretValue &l, const SecretValue &rho,
                        const PublicValue &V, const PublicValue &A)
    : K_(E)
  {
    BN v (E.random_mod_order(randgen));
    BN u (E.random_mod_order(randgen));

    E.scal_mul (K_, v, u, R); /* K = u R + v P */

    /* c = Hash(E, R, V, A, K) */
    BN c (hash_for_challenge (H, E, R, V, A, K_));

    E.mul_mod_order (t1_, c, s);
    E.add_mod_order (t1_, t1_, u); /* t1 = u + c * s */

    E.mul_mod_order (t2_, c, l);
    E.mul_mod_order (u, c, c); /* use u as temp var */
    E.mul_mod_order (u, u, rho); /* use u as temp var */
    E.add_mod_order (t2_, t2_, u);
    E.add_mod_order (t2_, t2_, v); /* t2 = v + c*l + c^2 * rho */
  }

  /* */
  inline
  EC_3Dlog_ZKAoK::EC_3Dlog_ZKAoK (const ECGroup &E, const EC_3Dlog_ZKAoK &p)
    : K_ (E, p.K_), t1_(p.t1_), t2_(p.t2_)
  {
  }

  /* */
  inline
  EC_3Dlog_ZKAoK::EC_3Dlog_ZKAoK (const ECGroup &E, const ECPoint &H, const BN &t1, const BN &t2)
    : K_ (E, H), t1_(t1), t2_(t2)
  {
  }

  /* */
  inline
  bool EC_3Dlog_ZKAoK::verify (const ECGroup &E, HashAlgo &H,
                          const ECPoint & R, const PublicValue &V,
                          const PublicValue &A) const
  {
    /* c = Hash(E, R, V, A, K) */
    BN c (hash_for_challenge (H, E, R, V, A, K_));

    ECPoint lhs (E);
    ECPoint rhs (E);

    E.scal_mul (lhs, t2_, t1_, R); /* t1 R + t2 P */

    E.scal_mul (rhs, c, A);
    E.ec_add (rhs, V, rhs);
    E.scal_mul (rhs, c, rhs);
    E.ec_add (rhs, rhs, K_); /* c V + c^2 A + K */

    return E.ec_point_eq (lhs, rhs);
  }

  inline
  const ECPoint & EC_3Dlog_ZKAoK::H() const
  {
    return K_;
  }

  inline
  const BN & EC_3Dlog_ZKAoK::t1() const
  {
    return t1_;
  }

  inline
  const BN & EC_3Dlog_ZKAoK::t2() const
  {
    return t2_;
  }

  /* */
  inline
  size_t EC_3Dlog_ZKAoK::num_bytes(ECGroup const & E) const
  {
    return K_.num_bytes(E) + t1_.num_bytes() + t2_.num_bytes();
  }

  /* */
  inline
  BN EC_3Dlog_ZKAoK::hash_for_challenge (HashAlgo &Hash,
                                    const ECGroup &E,
                                    const ECPoint &R,
                                    const ECPoint &V,
                                    const ECPoint &A,
                                    const ECPoint &H)
  {
    return BN (Hash (E, ECPointGroupCRefPair (R, E),
                                ECPointGroupCRefPair (V, E),
                                ECPointGroupCRefPair (A, E),
                                ECPointGroupCRefPair (H, E)));
  }

}

#endif /* BICYCL_PROOFS_EC_PROOFS_INL */
