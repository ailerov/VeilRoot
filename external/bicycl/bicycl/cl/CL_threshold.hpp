/*
 * BICYCL Implements CryptographY in CLass groups
 * Copyright (C) 2025  Cyril Bouvier <cyril.bouvier@lirmm.fr>
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
 * @example CL_threshold_example.cpp
 * This file is an example of how to use the BICYCL::CL_Threshold_Static class.\n
 * It shows how to setup and use a 2-out-of-3 threshold decryption system.
 *
 * @defgroup CL_THRESHOLD Threshold decryption
 * @ingroup CL
 * T-out-of-N threshold decryption using class groups
 */

#ifndef BICYCL_CL_CL_THRESHOLD_HPP
#define BICYCL_CL_CL_THRESHOLD_HPP

#include <unordered_map>
#include <unordered_set>

#include "bicycl/arith/gmp_extras.hpp"
#include "bicycl/cl/CL_HSMqk.hpp"
#include "bicycl/proofs/CL_HSMqk_Batch_Dlog_AoK.hpp"
#include "bicycl/proofs/CL_HSMqk_DlogEq_AoK.hpp"

#include "bicycl/parallelism.hpp"

namespace BICYCL
{
/**
 * @brief A player within the CL threshold decryption static protocol
 *
 * This class implements the protocol defined in IACR 2024/717
 * (https://eprint.iacr.org/2024/717).\n
 * It assumes the players IDs are the integers [0, n-1], for n players.
 *
 * @ingroup CL_THRESHOLD
 * @nosubgrouping
 */
class CL_Threshold_Static
{
  public:
    using CipherText = CL_HSMqk::CipherText;
    using ClearText = CL_HSMqk::ClearText;
    using PublicKey = CL_HSMqk::PublicKey;
    using ParticipantsSet = std::unordered_set<unsigned int>;
    template <typename T> using ParticipantsValueMap
        = std::unordered_map<unsigned int, T>;

    /**
     * @brief Indicates an error in the usage of CL_Threshold_Static methods.
     * @details This exception usually means that the protocol steps were not
     * executed in the correct order. Note that it does not entirely prevent
     * the missuse of CL_Threshold_Static methods, but reduces its likelyhood.
     **/
    class ProtocolLogicError : public std::logic_error
    {
      public:
        using logic_error::logic_error;
    };

    /**
     * @brief Indicates the protocol cannot proceed and must be aborted.
     * @details This exception usually means that too many players were dishonest.
     *
     */
    class ProtocolAbortError : public std::runtime_error
    {
      public:
        using std::runtime_error::runtime_error;
    };

    /**
     * @brief An object representing a partial decryption w and its associated proof for the CL_Threshold protocol.
     * @details This is a utility class to bundle \f$\omega\f$ with its decryption proof.\n
     * - \f$\omega=ct_1^{\gamma_i {\Delta^2}}\f$\n
     * - \f$proof=\f$ CL_DlogEq_AoK\f$(h, ct_1, \Gamma_i\, \omega, \gamma_i {\Delta^2})\f$\n
     *
     */
    class PartialDecryption : public std::pair<QFI, CL_HSMqk_DlogEq_AoK>
    {
      public:
        /******************************************************
         * @name Constructors
         *@{
         *****************************************************/
        PartialDecryption();

        /*@}*/

        /******************************************************
         * @name Getters
         * More explicit accesors for pair elements.
         *@{
         *****************************************************/

        /** @brief Get \f$w\f$, the partially decrypted message */
        QFI & w ();
        /** @brief Get \f$w\f$, the partially decrypted message */
        const QFI & w () const;

        /** @brief Get the proof asociated with the partially decrypted message */
        CL_HSMqk_DlogEq_AoK & proof ();
        /** @brief Get the proof asociated with the partially decrypted message */
        const CL_HSMqk_DlogEq_AoK & proof () const;
        /**@}*/

        /******************************************************
         * @name Verification
         *@{
         *****************************************************/
        /**
         * @brief Shorthand for verifying the decryption proof
         *
         * @param[in] cl_hsmq The CL cryptosystem
         * @param[in] soundness_bytes soundness in bytes
         * @param[in] h_delta2 \f${h}^{\Delta^2}\f$.
         * @param[in] ct1_delta2 \f${ct_1}^{\Delta^2}\f$, with \f${ct_1}\f$ the first term of the cyphertext.
         * @param[in] Gamma Public value \f$\Gamma_i\f$
         * @return true if proof was verified
         * @return false otherwise
         */
        bool verify (const CL_HSMqk & cl_hsmq,
                     size_t soundness_bytes,
                     const QFI & h_delta2,
                     const QFI & ct1_delta2,
                     const QFI & Gamma) const;
    };

    /******************************************************
     * @name Constructors
     *@{
     *****************************************************/
    /**
     * @brief Construct a player within the t-out-of-n Threshold CL protocol.
     * @details This constructor:\n
     * - Initialzes the set of qualified players Q with integer IDs \f$[0, n-1]\f$.\n
     * - Computes \f$\Delta\f$, \f$\Delta^2\f$, and \f$\Delta^{-2}\mod{q}\f$
     * - Performs precomputations to optimise exponentiations with base \f$h^{\Delta}\f$.\n
     *
     * @param[in] cl_hsmq The CL cryptosystem
     * @param[in] n Number of players.
     * @param[in] t Threshold - 1. The threshold for decryption is t+1.
                      Must verify t < n.
     * @param[in] i ID to use for this player. Must verify i < n.
     *
     * @exception std::invalid_argument Input parameters (n , t, i) do not satisfy input requirements.
     */
    CL_Threshold_Static(const CL_HSMqk & cl_hsmq,
                        unsigned int n,
                        unsigned int t,
                        unsigned int i,
                        size_t soundness);
    /**@}*/

    /******************************************************
     * @name Getters
     * Methods to retrieve the public parameters
     *@{
     *****************************************************/

    /**
     * @brief Get this player's ID
     * @return This players ID.
     */
    unsigned int i () const;

    /**
     * @brief Get \f$y_k\f$, the Shamir share for player k
     * @details The returned value corresponds to \f$F(X)\f$ evaluated a \f$X=k+1\f$,
     * with \f$F(X) = \Delta*a_i + r[0]*X + r[1]*X^2 + ... + r[t-1]*X^t\f$.\n
     * In other words, it's the Shamir share of \f$\Delta*a_i\f$ for the player k.\n
     * Each \f$y_k\f$ must be sent to it's respective player k.\n
     *
     * @param[in] k ID of another player
     *
     * @return The Shamir share for player k.
     * @exception ProtocolLogicError The Shamir shares have not been computed yet.
     * Execute keygen_dealing() first.
     * @exception std::invalid_argument Player k does not exist
     *
     * @pre keygen_dealing() called at least once.
     */
    const Mpz & y_k (unsigned int k) const;

    /**
     * @brief Get this player's commitments for verifiable secret sharing.
     * @details C denotes the commitments of the player's polynom
     * coefficients.\n
     * \f$C_0=h^{a_i}\f$, \f$C_k = h^{\Delta r_{k-1}}\f$ for k in \f$[1, t]\f$\n
     * The commitments must be broadcasted to all other players.
     *
     * @return This player's t+1 commitments.
     * @exception ProtocolLogicError The commitments have not been computed yet.
     * Execute keygen_dealing() first.
     *
     * @pre keygen_dealing() called at least once.
     */
    const std::vector<QFI> & C () const;

    /**
     * @brief Get this player's batch proof for keygen phase
     * @details The proof must be broadcasted to all other players.
     * @see CL_Batch_Dlog_AoK for more info on the proof.
     *
     * @return This player's batch proof for the keygen phase
     * @exception ProtocolLogicError The batch proof has not been computed yet.
     * Execute keygen_dealing() first.
     *
     * @pre keygen_dealing() called at least once.
     */
    const CL_HSMqk_Batch_Dlog_AoK & batch_proof () const;

    /**
     * @brief Get the public key.
     * @details The public key is defined by all the players commitments.
     *
     * @return The public key.
     *
     * @pre keygen_extract() called at least once
     */
    const PublicKey & pk () const;

    /**
     * @brief Get the map of public verification value \f$Gamma\f$ per player.
     * @details Not needed for protocol execution, but useful for benchmarks
     *
     * @return A map of the public verifications values \f$Gamma\f$ per player.
     *
     * @pre keygen_extract() called at least once
     */
    const ParticipantsValueMap<QFI> & Gammas () const;

    /**
     * @brief Get most recent partial decryption done by this player.
     * @details Get the PartialDecryption object containing the partially
     * decrypted value w, and the associated proof.
     * Must be broadcasted to all other players.
     *
     * @return This player's most recent partial decryption
     * @exception ProtocolLogicError Partial decryption has not been performed yet.
     * Execute decrypt_partial first.
     *
     * @pre decrypt_partial() called at least once
     */
    const PartialDecryption & part_dec () const;

    /**
     * @brief Get the set of Qualified players.
     * @details Players maintain the set of qualified (trusted) players
     * defined during the keygen phase.
     * The set of players who this player trusts can be accessed using this
     * function.
     *
     * @return The set of Qualified Players.
     */
    const ParticipantsSet & QualifiedPlayerSet () const;

    /**
     * @brief Get the set of players with unresolved complaints.
     * @details After checking other players shares with eiher keygen_check_share or
     * keygen_check_verify_all_players, each player who does pass the check is
     * stored in the "complaints" set.
     * All complaints must then be resolved, either by checking again or disqualifying the players.
     * The set of players to complain to can be accesses with this function.
     *
     * @return The set of players with unresolved complaints.
     */
    const ParticipantsSet & ComplaintsSet () const;

    /**
     * @brief Get the set of players participating in the decryption phase.
     * @details Players maintain the subset of qualified players who provided
     * a verifiable partial decryption during the decrypt phase.
     * The set can be accessed using this function.\n
     * After calling decrypt_partial(), only this object's player is in the set.\n
     * After a player is verified by calling decrypt_verify_player_decryption(), it is added to the set.\n
     * After several players are verified by calling decrypt_verify_batch(), they are added to the set.\n
     *
     * @return The set of Qualified Players.
     */
    const ParticipantsSet & DecryptionPlayerSet () const;
    /**@}*/

    /******************************************************
     * @name Keygen
     * Methods to perform the keygen steps.
     *@{
     *****************************************************/
    /**
     * @brief Perform the Keygen Dealing phase.
     * @details Sample a secret then use verifiable secret sharing to split it
     * between players. \n
     * The secret is stored in a_i. \n
     * It is split using VSS for t+1 party reconstruction. \n
     * A proof is computed to prove the commitments are honest. The proof is accessed using batch_proof()\n
     * The polynom is evaluated at each player ID, with an offset of 1. \n
     *
     * @param[in] CL_Hsmq The CL cryptosystem
     * @param[in] hash Hash algorithm used in the proof
     * @param[in] randgen Randomness generator
     *
     * @post The getters y_k(), C(), and batch_proof() can be used. \n
     * y_k() returns the secret share for player k. \n
     * C() returns the commitments of polynom coefficients. \n
     * batch_proof() returns the proof for the commitments.
     */
    void keygen_dealing (const CL_HSMqk & CL_Hsmq,
                         RandGen randgen);

    /**
     * @brief Store the secret share yj sent by player j.
     * @details Can be called multiple times with the same j, and will
     * override the previously stored value if there was one.
     *
     * @param[in] j The ID of the player who sent the share
     * @param[in] yj The secret share
     *
     * @exception std::invalid_argument j is not a valid, different player
     */
    void keygen_add_share (unsigned int j, const Mpz & yj);

    /**
     * @brief Add the t+1 commitments from player j.
     * @details Can be called multiple times with the same j, and will
     * override the previously stored value if there was one.
     *
     * @param[in] j ID of the player who sent the commitment
     * @param[in] Cj Vector of size t+1 with the commitments of player j
     *
     * @exception std::invalid_argument
     * Either: \n
     *  - j is not a valid, different player \n
     *  - Cj does not contain t+1 elements
     *
     */
    void keygen_add_commitments (unsigned int j, const std::vector<QFI> & Cj);

    /**
     * @brief Add the batch proof from player j.
     * @details Can be called multiple times with the same j, and will
     * override the previously stored value if there was one.
     *
     * @param[in] j ID of the player who sent the proof
     * @param[in] proof the CL_Batch_Dlog_AoK sent by player j
     *
     * @exception std::invalid_argument j is not a valid, different player.
     */
    void keygen_add_proof (unsigned int j, const CL_HSMqk_Batch_Dlog_AoK & proof);

    /**
     * @brief Remove player j from the set of qualified players, and delete
     * all stored values about player j.
     *
     * @param[in] j ID of the player to disqualify
     *
     * @exception std::invalid_argument j is not a valid, different player
     *
     * @post Values stored for player j are deleted from this object. j is
     * removed from QualifiedPlayerSet.
     */
    void keygen_disqualify_player (unsigned int j);

    /**
     * @brief Check the validity of player j's shares using their commitments.
     * Part of Keygen Check phase.
     * @details If @p resolve_complaints is true, j is automatically added to or
     * removed from the complaints set, depending on check result.
     *
     * @param[in] CL_Hsmq The CL cryptosystem
     * @param[in] j ID of the player to check
     * @param[in] resolve_complaints Whether to automatically register and
     * resolve complaints based on check result. Defaults to true.
     *
     * @return true if j's share matches their commitments
     * @return false otherwise
     * @exception std::invalid_argument Player k does not exist
     * @exception ProtocolLogicError The share or commitments for player j is missing
     */
    bool keygen_check_player_shares (const CL_HSMqk & CL_Hsmq,
                                     unsigned int j,
                                     bool resolve_complaints = true);

    /**
     * @brief Verify the validity of player j's batch proof. Part of Keygen
     * Check phase.
     * If @p disqualify_on_fail is true, j is automatically removed from the
     * set of qualified players if verification fails.
     *
     * @param[in] CL_Hsmq The CL cryptosystem
     * @param[in] hash Hash algo used in the proof
     * @param[in] j ID of the player to verify
     * @param[in] disqualify_on_fail Whether to automatically disqualify players
     * for which verification fails. Defaults to true.
     *
     * @return true if proof was verified
     * @return false otherwise
     * @exception std::invalid_argument j is not a valid, different player
     * @exception ProtocolLogicError The proof for player j is missing
     */
    bool keygen_verify_player_proof (const CL_HSMqk & CL_Hsmq,
                                     unsigned int j,
                                     bool disqualify_on_fail = true);

    /**
     * @brief Check shares and verify proofs of every other player. Disqualify
     * players who do not pass the checks. Part of Keygen Check phase.
     * @details Call keygen_check_player_shares() and keygen_verify_player_proof()
     * on every player in QualifiedPlayersSet_ except this player.\n
     * If proof verification fails, disqualify the corresponding player.\n
     * If the former passes, but share check fails, add the corresponding players
     * to the complaints set.\n
     *
     * @param[in] CL_Hsmq The CL cryptosystem
     * @param[in] hash Hash algo used in the proof
     *
     * @return true if all checked players are honest
     * @return false if at least one player is dishonest, or some commitments
     * or proofs are missing
     *
     * @pre For each Qualified player, commitments and proof were provided
     * using keygen_add_commitments() and keygen_add_proof() respectively
     */
    bool keygen_check_verify_all_players (const CL_HSMqk & CL_Hsmq);

    /**
     * @brief Perform Keygen Extract phase.
     * @details From the values gathered from qualified players, compute: \n
     *   - The public key \f$pk_{CL}\f$ \n
     *   - The share of implicit secret key \f$\gamma_i\f$ \n
     *   - The public values \f$\Gamma\f$ for each qualified player \n
     *
     * @param[in] CL_Hsmq The CL cryptosystem
     *
     * @exception ProtocolLogicError Player shares or commitments are missing,
     * the keys cannot be computed
     *
     * @pre The Keygen "dealing" and "check" phases have been performed
     * @post The getter pk() can be called to get the public key. \n
     */
    void keygen_extract (const CL_HSMqk & CL_Hsmq);
    /**@}*/

    /******************************************************
     * @name Decryption
     * Methods to perform the decryption steps.
     *@{
     *****************************************************/

    /**
     * @brief Perform the Partial Decryption phase.
     * All previously computed or stored partial decryptions are cleared.
     * @details From the ciphertext @p ct, compute the partial decryption w and
     * its associated CL_DlogEq proof.
     *
     * @param[in] CL_Hsmq The CL cryptosystem
     * @param[in] hash Hash algo used in the proof
     * @param[in] randgen Randomness generator
     * @param[in] ct Cyphertext to decrypt
     *
     * @pre The keygen phase was executed correctly.
     * @post The getter part_dec() can be called to get this player's partial decryption.\n
     * Previous partial decryptions, as well as the set of players participating
     * in the decryption, are cleared.
     */
    void decrypt_partial (const CL_HSMqk & CL_Hsmq,
                          RandGen randgen,
                          const CipherText & ct);

    /**
     * @brief Add the partial decryption from player j.
     * @see PartialDecryption
     *
     * @param[in] j ID of the player who performed the partial decryption
     * @param[in] part_dec partial decryption \f$(\omega, proof)\f$ from player j
     *
     * @exception std::invalid_argument j is not a valid, different player
     */
    void decrypt_add_partial_dec (unsigned int j,
                                  const PartialDecryption & part_dec);

    /**
     * @brief Verify the partial decryption of player j.
     * Part of the Decrypt Verify phase.
     *
     * @param[in] CL_Hsmq The CL cryptosystem
     * @param[in] hash Hash algo used in the proof
     * @param[in] j ID of the player to check
     *
     * @return true Partial decryption is valid
     * @return false Otherwise
     * @exception std::invalid_argument j is not a valid, different player
     * @exception ProtocolLogicError The partial decryption for player j is missing
     */
    bool decrypt_verify_player_decryption (const CL_HSMqk & CL_Hsmq,
                                           unsigned int j);

    /**
     * @brief Decrypt Verify phase, verify received partial decryptions.
     * @details Performs a batch verification of the t+1 first received decryption proofs,
     * using the small exponent test.
     * This operation allows to verify multiple players at once, but does not
     * allow identification of dishonest players if it fails.
     *
     * @param[in] cl_hsmq The CL cryptosystem
     * @param[in] H Hash algo used in the proof
     * @param[in] randgen Randomness generator
     *
     * @return true if all partial decryptions are valid
     * @return false if at least one partial decryption is invalid
     * @exception ProtocolLogicError
     * Either: \n
     *  - The Keygen phase was not correctly executed \n
     *  - Not enough partial decryptions have been provided by other players
     *    (t+1 are needed)
     */
    bool decrypt_verify_batch (const CL_HSMqk & cl_hsmq,
                               RandGen & randgen);

    /**
     * @brief Perform the Decrypt Combine phase.
     * From t+1 partial decryptions, decrypt the ciphertext ct.
     *
     * @param[out] m Clear text, decryption of ct
     * @param[in] CL_Hsmq The CL cryptosystem
     * @param[in] ct Cyphertext to decrypt
     *
     * @exception ProtocolLogicError Not enough partial decryptions have been
     * provided by other players (t+1 are needed)
     * @exception ProtocolAbortError Decryption failed, DLog could not be computed.
     * This likely means that some partial decryptions were dishonest.
     */
    void decrypt_combine (ClearText & m,
                          const CL_HSMqk & CL_Hsmq,
                          const CipherText & ct);
    /**@}*/

  private:
    /**
     * @internal
     * @brief Compute the Lagrange coefficient for player j, evaluated at 0
     * @details The Lagrange coefficient for j is defined as: \n
     *   \f$Lj(X)=\Delta \prod{k, k!=j} (k - X)/(k - j)\f$ \n
     * Evaluated at zero, we get \n
     *   Lj(0) = delta * \prod{k, k!=j} k/(k - j) \n
     * Use Lj0 with player j's partial decryption to decrypt jointly
     *
     * @param[out] Lj0 Lagrange coefficient for j
     * @param[in] j ID of the player
     *
     * @pre j is in S, and player IDs in S verify ID < n_ \n
     */
    void lagrange_at_zero (Mpz & Lj0, unsigned int j) const;

    /**
     * @internal
     * @brief Get the bitsize from which to sample the random polynom coefficients.
     * In the protocol, it corresponds to l0 + sigma
     * @details Random bound for r[i] is 2^(l0 + sigma) with \n
     *  - sigma = statistic security level \n
     *  - l0 > secret_bound size + log2(delta) + 2*log2(t+1) + 2 \n
     * Take l0 = size(secret_bound) + size(delta) + size(t+1) + 3 \n
     *
     * @return Bitsize to sample r[i] from
     */
    size_t poly_coeff_bitsize_bound (const CL_HSMqk & CL_Hsmq) const;

    /**
     * @internal
     * @brief Get a HashAlgo using SHAKE-128/256 with soundness_bytes_ digest length
     */
    HashAlgo hash_algo() const;

    /** Security parameters */
    size_t soundness_bytes_;

    /** Number of participants */
    const unsigned int n_;

    /** Threshold. The number of honest participants needed to decrypt is t+1
     */
    const unsigned int t_;

    /**
     * The players ID.
     * In the protocol defined in the paper, the IDs range from 1 to N. \n
     * In the implementation, they are 0-based, from 0 to n-1. \n
     * In some operations, the IDs are offset by 1 to match protocol. \n
     */
    const unsigned int i_;

    /**
     * Precomputed values: \n
     * - Delta_      = n!\n
     * - Delta2_     = Delta_^2 \n
     * - Delta2_inv_ = Delta_^(-2) mod q \n
     */
    Mpz delta_, delta2_, delta2_inv_;

    /** Precomputed value h^delta */
    QFI h_delta_;

    /**
     * Precomputed values h_delta_e, h_delta_d, h_delta_de.
     * These values are used to optimize exponentiations (h^delta)^r[i], where
     * {r[0], ..., r[t-1]} are the random coefficients sampled during the
     * keygen_deal phase
     *
     * d = (r bitsize + 1) / 2
     * h_delta_e =  (h^delta)^(2^(d/2))
     * h_delta_d =  (h^delta)^(2^d)
     * h_delta_ed = (h^delta)^(2^(d+d/2))
     * @see nupow
     */
    QFIPrecomp h_delta_precomp_;

    /** Precomputed value h^(delta^2) */
    QFI h_delta2_;

    /** Secret value of this player */
    Mpz ai_;

    /**
     * Shares of secret ai_. There is 1 share for each honest party, so at
     * most n shares. To be distributed to the corresponding player. \n
     * Share of ai to distribute to player j --> y_self[j]
     */
    ParticipantsValueMap<Mpz> y_self_;

    /**
     * Polynom coeffs commitments, for each player. \n
     * Usage: \n
     *   Commitment of Player j for their coeff k --> C_[j][k] (QFI) \n
     *   Commitments of Player j --> C_[j] (vector<QFI> of size t_+1) \n
     * Thus: \n
     *  Commitments of this Player --> C_[i_] \n
     *  Commitments of other Players --> C_[j] (j != i_)
     */
    ParticipantsValueMap<std::vector<QFI>> C_;

    /** Batch proofs used during keygen, for each playe */
    ParticipantsValueMap<CL_HSMqk_Batch_Dlog_AoK> keygen_batch_proofs_;

    /**
     * Secret shares received from other players. \n
     * Share of Pj's secret for this player --> y_other_[j]
     */
    ParticipantsValueMap<Mpz> y_others_;

    /** Share of the implicit private key. Computed in keygen_extrac */
    Mpz sk_share_;

    /** Public key, computed from C_[j][0] for j in QualifiedPlayerSe */
    PublicKey pk_;

    /**
     * Public verification keys Gamma, 1 value per honest player \n
     * Computed from C_[j][k], for j in QualifiedPlayerSet and k in
     * {0, ... , t}. \n
     * Used in decryption proof.
     */
    ParticipantsValueMap<QFI> Gamma_;

    /** Set of qualified players. Defined during keygen phase */
    ParticipantsSet QualifiedPlayersSet_;

    /** Set of players to send a complaint to during the keygen phase */
    ParticipantsSet ComplaintsSet_;

    /**
     * QFI equal to ct1^(delta^2).
     * Computed in decrypt_partial and reused in decrypt_verify
     */
    QFI ct1_delta2_;

    /**
     * Partial decryptions with proofs, for each player. @see
     * CL_Threshold_Static::PartialDecryption
     */
    ParticipantsValueMap<PartialDecryption> part_dec_;

    /** Set of players participating in Decryption.
     *  Defined during decrypt verify phase.
     */
    ParticipantsSet DecryptionPlayersSet_;

  protected:
    /**
     * @brief Faster keygen_extract with Gamma already computed.
     * Used in benchmarks only, to speedup the keygen_extract process for non-benched players.
     */
    void keygen_extract_for_benchs (const CL_HSMqk & CL_Hsmq,
                                    const ParticipantsValueMap<QFI> & Gamma);
};
}

#include "CL_threshold.inl" // IWYU pragma: keep

#endif                      /* BICYCL_CL_CL_THRESHOLD_HP */