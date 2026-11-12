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
#ifndef BICYCL_PROOFS_CL_HSMQK_EC_DLOG_ZKPWPE_HPP
#define BICYCL_PROOFS_CL_HSMQK_EC_DLOG_ZKPWPE_HPP

#include "bicycl/arith/openssl_wrapper.hpp"
#include "bicycl/cl/CL_HSMqk.hpp"

namespace BICYCL
{
/************************************************************************/
/**
   * @brief Zero knowledge proof with partial extractability for the relation :
   * \f$ R_{CL-DL} := \{(pk, (c_1,c_2), Q);(x, r) | c_1=h^r \land c_2={f^x}{pk}^r \land Q=xP\}\f$
   * @details
   * With :
   *  - \f$(h, f)\f$ the public parameters of \f$\CL_HSMqk\f$
   *  - \f$pk\f$ a public key in CL_HSMqk
   *  - \f$x \in \Z/q\Z\f$ the secret value
   *  - \f$r\f$ the randomness used in the encryption
   *  - \f$c = (c_1, c_2) = CL.Enc(r; (pk, x))\f$ the encrypted \f$x\f$
   *  - \f$P\f$ the generator of the elliptic curve
   *  - \f$Q\f$ an EC point
   *
   * @ingroup ECDSA_TWOPARTY PROOFS
   */
class CL_HSMqk_EC_Dlog_ZKPwPE
{
  public:
    using SecretValue = BN;

    /* Ctor */
    CL_HSMqk_EC_Dlog_ZKPwPE() = default;

    CL_HSMqk_EC_Dlog_ZKPwPE(const Mpz & u1, const Mpz & u2, const Mpz & chl);

    CL_HSMqk_EC_Dlog_ZKPwPE(HashAlgo & H,
                            const ECGroup & E,
                            const SecretValue & x,
                            const ECPoint & Q,
                            const CL_HSMqk & cryptosystem,
                            const CL_HSMqk::PublicKey & pk,
                            const CL_HSMqk::CipherText & c,
                            const Mpz & r,
                            RandGen & randgen);

#ifdef BICYCL_WITH_PTHREADS
    CL_HSMqk_EC_Dlog_ZKPwPE(HashAlgo & H,
                            const ECGroup & E,
                            const SecretValue & x,
                            const ECPoint & Q,
                            const CL_HSMqk & cryptosystem,
                            const CL_HSMqk::PublicKey & pk,
                            const CL_HSMqk::CipherText & c,
                            const Mpz & r,
                            RandGen & randgen,
                            std::thread & thread_ckey);
#endif

    /* Getters */
    const Mpz & u1 () const;
    const Mpz & u2 () const;
    const Mpz & chl () const;

    /* verify */
    bool verify (HashAlgo & H,
                 const ECGroup & E,
                 const ECPoint & Q,
                 const CL_HSMqk & C,
                 const CL_HSMqk::PublicKey & pk,
                 const CL_HSMqk::CipherText & c) const;


  private:
    /* util */
    Mpz hash_for_challenge (HashAlgo & H,
                            const CL_HSMqk & CL,
                            const ECGroup & E,
                            const ECPoint & Q,
                            const CL_HSMqk::PublicKey & pk,
                            const CL_HSMqk::CipherText & c,
                            const QFI & t1,
                            const QFI & t2,
                            const ECPoint & T) const;

    Mpz u1_;
    Mpz u2_;
    Mpz chl_;
}; /* CLDLZKProof */

} /* namespace BICYCL */

#include "CL_HSMqk_EC_Dlog_ZKPwPE.inl" // IWYU pragma: keep

#endif /* BICYCL_PROOFS_CL_HSMQK_EC_DLOG_ZKPWPE_HPP */