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
/**
 * @defgroup PROOFS Proofs
 */

#ifndef BICYCL_PROOFS_EC_PROOFS_HPP
#define BICYCL_PROOFS_EC_PROOFS_HPP

#include "bicycl/arith/openssl_wrapper.hpp"

namespace BICYCL
{
/**
   * @brief Proof of knowledge for the relation :
   *    \f$ R := \{Q;s|Q=sP\}\f$\n
   * @details
   *  - \f$s\f$ the secret value
   *  - \f$P\f$ the generator of the elliptic curve
   *  - \f$Q\f$ an EC point
   * @ingroup ECDSA_THRESHOLD ECDSA_TWOPARTY PROOFS
   */
class EC_Dlog_ZKPoK
{
  public:
    using SecretValue = BN;
    using PublicValue = ECPoint;

    EC_Dlog_ZKPoK(const ECGroup & E,
                  HashAlgo & H,
                  RandGen & randgen,
                  const SecretValue & s,
                  const PublicValue & Q,
                  const Mpz & sid = Mpz{0UL});
    EC_Dlog_ZKPoK(const ECGroup & E,
                  HashAlgo & H,
                  RandGen & randgen,
                  const SecretValue & s);
    EC_Dlog_ZKPoK(const ECGroup & E, const ECPoint & R, const BN & z);
    EC_Dlog_ZKPoK(const ECGroup & E,
                  const BN & Rx,
                  const BN & Ry,
                  const BN & z);
    EC_Dlog_ZKPoK(const ECGroup & E, const EC_Dlog_ZKPoK & p);
    explicit EC_Dlog_ZKPoK(const ECGroup & E);

    const ECPoint & R () const;
    const BN & z () const;

    bool verify (const ECGroup & E,
                 HashAlgo & H,
                 const PublicValue & Q,
                 const Mpz & sid = Mpz{0UL}) const;

    size_t num_bytes(ECGroup const & E) const;

  protected:
    static BN hash_for_challenge (HashAlgo & H,
                                  const ECGroup & E,
                                  const ECPoint & R,
                                  const ECPoint & Q,
                                  const Mpz & sid);
    static ECPoint compute_Q_from_secret (const ECGroup & E,
                                          const SecretValue & s);

  private:
    ECPoint R_;
    BN z_;
}; /* ECNIZKProof */

/*****/
/**
   * @ingroup ECDSA_THRESHOLD PROOFS
   */
/**
   * @brief Argument of knowledge for the relation
   *  \f$R := \{(V,A);(s,l,\rho)| V=s.R+l.P \land A=\rho.P\}\f$
   * @details
   * With :
   *  - \f$s,l,\rho\f$ the secret values
   *  - \f$P\f$ the generator of the elliptic curve
   *  - \f$R, A, V\f$ points on the elliptic curve
   * @ingroup ECDSA_THRESHOLD PROOFS
   */
class EC_3Dlog_ZKAoK
{
  public:
    using SecretValue = BN;
    using PublicValue = ECPoint;

    EC_3Dlog_ZKAoK(const ECGroup & E,
              HashAlgo & H,
              RandGen & randgen,
              const ECPoint & R,
              const SecretValue & x,
              const SecretValue & y,
              const SecretValue & rho,
              const PublicValue & V,
              const PublicValue & A);
    EC_3Dlog_ZKAoK(const ECGroup & E, const EC_3Dlog_ZKAoK & p);
    EC_3Dlog_ZKAoK(const ECGroup & E,
              const ECPoint & H,
              const BN & t1,
              const BN & t2);

    bool verify (const ECGroup & E,
                 HashAlgo & H,
                 const ECPoint & R,
                 const PublicValue & V,
                 const PublicValue & A) const;

    const ECPoint & H () const;
    const BN & t1 () const;
    const BN & t2 () const;

    size_t num_bytes(ECGroup const & E) const;

  protected:
    static BN hash_for_challenge (HashAlgo & Hash,
                                  const ECGroup & E,
                                  const ECPoint & R,
                                  const ECPoint & V,
                                  const ECPoint & A,
                                  const ECPoint & H);

  private:
    ECPoint K_;
    BN t1_;
    BN t2_;
}; /* ECNIZKAoK */

} /* Namespace BICYCL */

#include "EC_proofs.inl" // IWYU pragma: keep

#endif                   /* BICYCL_PROOFS_EC_PROOFS_HPP */
