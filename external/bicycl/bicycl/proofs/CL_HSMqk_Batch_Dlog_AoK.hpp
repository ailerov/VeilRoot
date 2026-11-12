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
#ifndef BICYCL_PROOFS_CL_HSMQK_BATCH_DLOG_AOK_HPP
#define BICYCL_PROOFS_CL_HSMQK_BATCH_DLOG_AOK_HPP

#include "bicycl/cl/CL_HSMqk.hpp"

namespace BICYCL
{
//WARNING proof is computed differently than in IACR 2024/717
/**
 * @brief Batched arguments of Dlog knowledge, for the relation:
 * \f${R_{Batch-DLog}} := \{(\Delta, C_0,...,C_t); {a, x_1, ..., x_t})|\{C_0,...,C_t\} \in \hat{G}^{t+1} \land C_0=h^a \land C_k=h^{\Delta.x_k}, k \in [1,t]\}\f$
 * @details
 * With :
 * - \f$a,x_k \in \Z/q\Z\f$ the secrets
 * - \f$C_0 \in \hat{G} \f$ the commitment to \f$a\f$
 * - \f$C_k \in \hat{G} \f$ the commitment to \f$x_k\f$, for \f$k \in [1,t]\f$
 * - \f$(h,\hat{G})\f$ public parameters of CL_HSMqk
 * - \f$t\f$ threshold setting from CL_Threshold_Static
 * - \f$\Delta=N!\f$ from CL_Threshold_Static
 *
 * @ingroup CL_THRESHOLD PROOFS
 * @nosubgrouping
 */
class CL_HSMqk_Batch_Dlog_AoK
{
  public:
    /******************************************************
     * @name Constructors
     *@{
     *****************************************************/
    /**
     * @brief Compute a Batch Dlog AoK for the CL_Threshold protocol
     * @details @warning proof is computed differently than in IACR 2024/717
     *
     * @param[in] CL The CL cryptosystem
     * @param[in] soundness_bytes soundness in bytes
     * @param[in] randgen Randomness generator
     * @param[in] a_rand_bound Random bound (in bit size) used to sample a
     * @param[in] x_rand_bound Random bound (in bit size) used to sample xi
     * @param[in] t Threshold of CL_Threshold_Static
     * @param[in] delta \f$\Delta=N!\f$ from CL_Threshold
     * @param[in] a Secret share (degree-0 coeff) to include in batch proof
     * @param[in] xi Secret polynom coefficients to batch proof, t elements
     * @param[in] Ci Commitments, t+1 elements.\n
     *            \f$Ci[0] = h^a\f$\n
     *            \f$Ci[k+1] = h^{\Delta.x[k]}\f$  for \f$k \in [0,t[\f$
     *
     * @throw std::invalid_argument Input vectors have the wrong size
     */
    CL_HSMqk_Batch_Dlog_AoK(const CL_HSMqk & CL,
                      size_t soundness_bytes,
                      RandGen & randgen,
                      const size_t a_rand_bound,
                      const size_t x_rand_bound,
                      const unsigned int t,
                      const Mpz & delta,
                      const Mpz & a,
                      const std::vector<Mpz> & xi,
                      const std::vector<QFI> & Ci);
    /**@}*/

    /******************************************************
     * @name Getters
     * Methods to retrieve the public parameters
     *@{
     *****************************************************/
    /**
     * @brief Get u, the "response" part of the proof, defined as:
     * \f$u = r + a*ch[0] + delta*(x[0]*ch[1] + ... + x[t-1]*ch[t])\f$
     * @return \f$u\f$, the "response" part of the proof
     */
    const Mpz & u () const;

    /**
     * @brief Get the commitment R, defined as: \f$R = h^r\f$
     * @return \f$R\f$, the commitment
     */
    const QFI & R () const;
    /**@}*/

    /******************************************************
     * @name Verify
     *@{
     *****************************************************/
    /**
     * @brief Verify a batch proof
     *
     * @param[in] soundness_bytes soundness in bytes
     * @param[in] CL The CL cryptosystem
     * @param[in] delta \f$\Delta=N!\f$ from CL_Threshold_Static
     * @param[in] m Number of elements to verify
     * @param[in] Ci Commitments to be verified, m elements
     *
     * @return true if proof was verified
     * @return false otherwise
     * @throw std::invalid_argument Input vector Ci has the wrong size
     */
    bool verify (size_t soundness_bytes,
                 const CL_HSMqk & CL,
                 const Mpz & delta,
                 size_t m,
                 const std::vector<QFI> & Ci) const;
    /**@}*/

  protected:
    /**
     * @brief Constructor used for tests to create a wrong proof.
     * It provides direct access to u and R, so can construct an invalid proof.
     * Use with care.
     *
     * @param[in] u
     * @param[in] R
     *
     */
    CL_HSMqk_Batch_Dlog_AoK(const Mpz & u, const QFI & R);

  private:
    /**
     * @brief Compute the hash-challenges used in the proof.
     *
     * @param[in] soundness_bytes soundness in bytes
     * @param[out] challenges Where to store the hash-challenges. Elements are
     * added at the back of the vector, previously existing elements are not
     * cleared.
     * @param[in] CL The CL cryptosystem
     * @param[in] Delta \f$\Delta=N!\f$ from CL_Threshold
     * @param[in] Ci Commitments used in proof. m elements
     *
     */
    void hash_for_challenge (std::vector<Mpz> & challenges,
                             size_t soundness_bytes,
                             const CL_HSMqk & CL,
                             const Mpz & Delta,
                             const std::vector<QFI> & Ci) const;

    /* Member */
    Mpz u_; /** u = r + a*k[0] + x[0]*k[1] + x[1]*k[2] + ... + x[t-1]*k[t] */
    QFI R_; /** R <- h^ */
};
}

#include "CL_HSMqk_Batch_Dlog_AoK.inl" // IWYU pragma: keep

#endif                           /*BICYCL_PROOFS_CL_HSMQK_BATCH_DLOG_AOK_HPP*/