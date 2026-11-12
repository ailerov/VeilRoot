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
#ifndef BICYCL_PROOFS_CL_HSMQK_DLOGEQ_AOK_HPP
#define BICYCL_PROOFS_CL_HSMQK_DLOGEQ_AOK_HPP

#include "bicycl/cl/CL_HSMqk.hpp"

namespace BICYCL
{
/**
 * @brief Argument of knowledge for the relation:
 * \f$R_{DLog-eq} := \{(f_1,f_2,q_1,q_2);x)|q_1={f_1}^x \land q_2={f_2}^x\}\f$
 * @details
 * With :
 * - \f$(f_1, f_2. q_1, q_2)\f$ elements of \f$\CL\f$
 * - \f$x_k \in \Z/q\Z\f$ the secret
 *
 * @ingroup CL_THRESHOLD PROOFS
 * @nosubgrouping
 */
class CL_HSMqk_DlogEq_AoK
{
  public:
    /******************************************************
     * @name Constructors
     *@{
     *****************************************************/
    /**
     * @brief Compute a Dlog-Eq AoK, general case
     *
     * @param[in] cl_hsmq The CL cryptosystem
     * @param[in] H Hash algo used for hash-challenges
     * @param[in] randgen Randomness generator
     * @param[in] x Discrete log
     * @param[in] f1 QFI
     * @param[in] f2 QFI
     * @param[in] q1 QFI such that \f$q_1 = {f_1}^x\f$
     * @param[in] q2 QFI such that \f$q_2 = {f_2}^x\f$
     */
    CL_HSMqk_DlogEq_AoK(const CL_HSMqk & cl_hsmq,
                  size_t soundness_bytes,
                  RandGen & randgen,
                  const Mpz & x,
                  const QFI & f1,
                  const QFI & f2,
                  const QFI & q1,
                  const QFI & q2);
#ifdef BICYCL_WITH_PTHREADS
    /**
     * @brief Compute a Dlog-Eq AoK, with the statement computed on another thread.
     * @details Same as the previous constructor, but takes a thread parameter
     * to allow the statement to be computed on a different thread.
     * The caller creates the thread beforehand, and tasks it to compute either
     * \f$q_1 = {f_1}^x\f$, \f$q_2 = {f_2}^x\f$, or both. Then, it calls this constructor
     * and passes a ref to the running thread as @p thread_q .
     * The contructor joins @p thread_q when q1 and q2 values are needed.
     *
     * @param[in] cl_hsmq The CL cryptosystem
     * @param[in] soundness_bytes soundness in bytes
     * @param[in] randgen Randomness generator
     * @param[in] x Discrete log
     * @param[in] f1 QFI
     * @param[in] f2 QFI
     * @param[in] q1 QFI such that \f$q_1 = {f_1}^x\f$
     * @param[in] q2 QFI such that \f$q_2 = {f_2}^x\f$
     * @param[in] thread_Q thread in which the statement is computed
     */
    // TODO defult arg for thread_Q when not used
    CL_HSMqk_DlogEq_AoK(const CL_HSMqk & cl_hsmq,
                  size_t soundness_bytes,
                  RandGen & randgen,
                  const Mpz & x,
                  const QFI & f1,
                  const QFI & f2,
                  const QFI & q1,
                  const QFI & q2,
                  std::thread & thread_Q);
#endif
    /**@}*/

    /******************************************************
     * @name Getters
     * Methods to retrieve the public parameters
     *@{
     *****************************************************/
    /**
     * @brief Get u, the "response" part of the proof, defined as:
     * \f$u = r + ch*x\f$
     * @return \f$u\f$, the "response" part of the proof
     */
    const Mpz & u () const;

    /**
     * @brief Get the first commitment R1, defined as: \f$R1 = f1^r\f$
     * @return \f$R1\f$, the first commitment
     */
    const QFI & R1 () const;

    /**
     * @brief Get the second commitment R2, defined as: \f$R2 = f2^r\f$
     * @return \f$R2\f$, the second commitment
     */
    const QFI & R2 () const;
    /**@}*/

    /******************************************************
     * @name Verify
     * @see CL_Threshold_Static::decrypt_verify_batch for a batch-verification variant
     *@{
     *****************************************************/
    /**
     * @brief Verify a Dlog-Eq Aok. Verify that \f$q_1 = {f_1}^x\f$ and \f$q_2 = {f_2}^x\f$
     *
     * @param[in] cl_hsmq The CL cryptosystem
     * @param[in] H Hash algo used for hash-challenges
     * @param[in] f1 QFI to verify
     * @param[in] f2 QFI to verify
     * @param[in] q1 QFI to verify
     * @param[in] q2 QFI to verify
     *
     * @return true if proof was successfully verified
     * @return false otherwise
     *
     * @see CL_Threshold_Static::decrypt_verify_batch for a batch-verification variant
     */
    bool verify (const CL_HSMqk & cl_hsmq,
                 size_t soundness_bytes,
                 const QFI & f1,
                 const QFI & f2,
                 const QFI & q1,
                 const QFI & q2) const;
    /**@}*/

  protected:
    /**
     * @brief Default CL_DlogEq_AoK constructor. Does not contruct a valid
     * proof, but is useful to make containers with this type.
     * Used in PartialDecryption.
     */
    CL_HSMqk_DlogEq_AoK() = default;

  private:
    /**
     * @brief Compute the hash-challenge used in the proof
     *
     * @param[in] H Hash algo used
     * @param[in] f1 QFI to verify
     * @param[in] f2 QFI to verify
     * @param[in] q1 QFI to verify
     * @param[in] q2 QFI to verify
     *
     * @return The hash-challenge
     */
    Mpz hash_for_challenge (size_t soundness_bytes,
                            const CL_HSMqk & CL,
                            const QFI & f1,
                            const QFI & f2,
                            const QFI & q1,
                            const QFI & q2) const;

    /* Member */
    Mpz u_;       /* u <- r + ch* */
    QFI R1_, R2_; /* R1 <- f1^r;  R2 <- f2^ */

    /* */
    friend class CL_Threshold_Static; // Needed to implement batch variant in
                                      // CL_Threshold_Static
};

}

#include "CL_HSMqk_DlogEq_AoK.inl" // IWYU pragma: keep

#endif                       /*BICYCL_PROOFS_CL_HSMQK_DLOGEQ_AOK_HPP*/