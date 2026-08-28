// Copyright (c) 2026, The VeilRoot Project
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <vector>
#include <utility>
#include "ringct/rctOps.h"

namespace crypto {

  // ElGamal ciphertext over the ed25519 curve
  struct elgamal_ciphertext {
    rct::key c1; // k*G
    rct::key c2; // w*G + k*T_pub

    bool operator==(const elgamal_ciphertext &other) const {
      return memcmp(c1.bytes, other.c1.bytes, 32) == 0 &&
             memcmp(c2.bytes, other.c2.bytes, 32) == 0;
    }
  };

  // Generate a new threshold keypair (t_priv, t_pub)
  bool generate_threshold_keypair(rct::key &t_priv, rct::key &t_pub);

  // Encrypt a 64‑bit weight w under threshold public key T_pub.
  // Returns the ciphertext. The random scalar k is discarded (not needed for
  // future ZK proofs in this version).
  elgamal_ciphertext encrypt_weight(uint64_t w, const rct::key &T_pub);

  // Shamir secret sharing over the scalar field (mod l).
  // Split a secret scalar into n shares, threshold k.
  // Each share is a pair (x_index, y_value), where x_index is 1‑based.
  void split_secret(const rct::key &secret, int k, int n,
                    std::vector<std::pair<int, rct::key>> &shares);

  // Reconstruct the secret from exactly threshold shares using Lagrange interpolation.
  rct::key reconstruct_secret(const std::vector<std::pair<int, rct::key>> &shares);

  // Compute a partial decryption share for the given ciphertext c1_sum.
  // The secret_share is the node's Shamir share scalar.
  rct::key compute_decryption_share(const rct::key &c1_sum, const rct::key &secret_share);

  // Combine at least threshold partial shares to recover w*G.
  // Each share is (x_index, point).
  rct::key combine_shares(const std::vector<std::pair<int, rct::key>> &shares);

  // Recover the integer weight from w*G by solving the 64‑bit DLP.
  uint64_t recover_weight_from_point(const rct::key &wG);

  // Helper: convert a uint64_t to a scalar (mod l)
  rct::key uint64_to_scalar(uint64_t value);

  // BEGIN_VNS_DKG_ENCRYPTION
  std::string encrypt_dkg_share(const rct::key &share, const public_key &recipient_pub, const secret_key &sender_priv);
  rct::key decrypt_dkg_share(const std::string &encrypted, const secret_key &recipient_priv, public_key &sender_pub);
  rct::key combine_partial_points(const std::vector<std::pair<int, rct::key>> &points, const std::vector<int> &indices, int threshold);
  // END_VNS_DKG_ENCRYPTION

} // namespace crypto