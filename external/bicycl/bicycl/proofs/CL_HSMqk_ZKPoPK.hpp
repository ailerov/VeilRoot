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

#ifndef BICYCL_PROOF_CL_HSMQK_ZKPOPK_HPP
#define BICYCL_PROOF_CL_HSMQK_ZKPOPK_HPP

#include "bicycl/cl/CL_HSMqk.hpp"

namespace BICYCL
{
  /**
   * @brief Zero knowledge proof of plaintext knowledge for the relation :
   * \f$ R_{Enc} := \{(pk, c_1,c_2);(a, r) | pk \in \hat{G} \land c_1=h^r \land c_2={pk^r}{f^a}\}\f$
   * @details
   * With :
   *  - \f$(h, f, \hat{G})\f$ the public parameters of \f$\CL_HSMqk\f$
   *  - \f$pk\f$ a public key in CL_HSMqk
   *  - \f$a \in \Z/q\Z\f$ the plaintext
   *  - \f$r\f$ the randomness used in the encryption
   *  - \f$c = (c_1, c_2) = CL.Enc(r; (pk, a))\f$ the encrypted \f$a\f$
   *
   * @ingroup ECDSA_THRESHOLD PROOFS
   */
class CL_HSMqk_ZKPoPK
  {
    public:
    /******************************************************
     * @name Constructors
     *@{
     *****************************************************/
    /**
     * @brief Compute a ZK proof of plaintext knowledge in CL
     *
     * @param[in] CL CL_HSMqk cryptosystem
     * @param[in] H hash Algorithm used
     * @param[in] pk CL public key used for encryption
     * @param[in] c ciphertext
     * @param[in] a secret cleartext
     * @param[in] r randomness used in the encryption
     * @param[in] randgen Randomness generator
     */
      CL_HSMqk_ZKPoPK (const CL_HSMqk &CL, HashAlgo &H,
                       const CL_HSMqk::PublicKey &pk,
                       const CL_HSMqk::CipherText &c,
                       const CL_HSMqk::ClearText &a,
                       const Mpz &r, RandGen &randgen);

      CL_HSMqk_ZKPoPK(const Mpz & u1, const Mpz & u2, const Mpz & k);
      /**@}*/

      /******************************************************
       * @name Verify
       *@{
       *****************************************************/
      /**
       * @brief Verify a ZK proof of plaintext knowledge in CL
       *
       * @param[in] CL CL_HSMqk cryptosystem
       * @param[in] H hash Algorithm used
       * @param[in] pk CL public key used for encryption
       * @param[in] c ciphertext
       *
       * @return true if proof was verified
       * @return false otherwise
       */
      bool verify (const CL_HSMqk &CL, HashAlgo &H,
                   const CL_HSMqk::PublicKey &pk,
                   const CL_HSMqk::CipherText &c) const;
      /**@}*/


      /******************************************************
      * @name Getters
      * Methods to retrieve the public parameters
      *@{
      *****************************************************/
      const Mpz & u1 () const;
      const Mpz & u2 () const;
      const Mpz & k () const;
      /**@}*/

      size_t num_bytes() const;

    private:
      Mpz k_from_hash (HashAlgo &H, const CL_HSMqk &CL,
                       const CL_HSMqk::PublicKey &pk,
                       const CL_HSMqk::CipherText &c,
                       const QFI &t1, const QFI &t2) const;

      Mpz u1_;
      Mpz u2_;
      Mpz k_;
  };

} /* BICYCL namespace */

#include "CL_HSMqk_ZKPoPK.inl" // IWYU pragma: keep

#endif /* BICYCL_PROOF_CL_HSMQK_ZKPOPK_HPP */
