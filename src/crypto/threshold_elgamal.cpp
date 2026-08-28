#include "threshold_elgamal.h"
#include "crypto/crypto-ops.h"   // sc_add, sc_sub, sc_mul
#include "crypto/crypto.h"       // random_scalar, generate_keys
#include <cstring>
#include <unordered_map>

extern "C" {
  void sc_add(unsigned char *, const unsigned char *, const unsigned char *);
  void sc_sub(unsigned char *, const unsigned char *, const unsigned char *);
  void sc_mul(unsigned char *, const unsigned char *, const unsigned char *);
}

namespace crypto {

  // ------------------------------------------------------------
  // Scalar field helpers
  // ------------------------------------------------------------
  static const rct::key SCALAR_ZERO = rct::zero();
  static const rct::key SCALAR_ONE = []() {
    rct::key one;
    memset(&one, 0, sizeof(one));
    one.bytes[0] = 1; // 1 in little-endian
    return one;
  }();

  static void scalar_add(rct::key &res, const rct::key &a, const rct::key &b) {
    sc_add(res.bytes, a.bytes, b.bytes);
  }
  static void scalar_sub(rct::key &res, const rct::key &a, const rct::key &b) {
    sc_sub(res.bytes, a.bytes, b.bytes);
  }
  static void scalar_mul(rct::key &res, const rct::key &a, const rct::key &b) {
    sc_mul(res.bytes, a.bytes, b.bytes);
  }

  // Compute modular inverse via Fermat: a^(l-2) mod l
  static void scalar_invert(rct::key &res, const rct::key &a) {
    // The group order l is 2^252 + 27742317777372353535851937790883648493
    // l-2 in little‑endian bytes:
    static const unsigned char order_minus_2[32] = {
      0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
      0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    rct::key base = a;
    rct::key result = SCALAR_ONE;
    rct::key exponent;
    memcpy(exponent.bytes, order_minus_2, 32);
    // Square-and-multiply
    for (int i = 0; i < 256; ++i) {
      if (exponent.bytes[i / 8] & (1 << (i % 8))) {
        scalar_mul(result, result, base);
      }
      scalar_mul(base, base, base);
    }
    res = result;
  }

  rct::key uint64_to_scalar(uint64_t value) {
    rct::key s = rct::zero();
    for (int i = 0; i < 8; ++i) {
      s.bytes[i] = (value >> (i * 8)) & 0xff;
    }
    return s;
  }

  // ------------------------------------------------------------
  // generate_threshold_keypair
  // ------------------------------------------------------------
  bool generate_threshold_keypair(rct::key &t_priv, rct::key &t_pub) {
    // Use Monero's Ed25519 key generation
    public_key pub;
    secret_key sec = crypto::generate_keys(pub, sec);
    t_pub = rct::pk2rct(pub);
    t_priv = rct::sk2rct(sec);
    return true;
  }

  // ------------------------------------------------------------
  // encrypt_weight
  // ------------------------------------------------------------
  elgamal_ciphertext encrypt_weight(uint64_t w, const rct::key &T_pub) {
    elgamal_ciphertext ct;
    // Generate random scalar k
    rct::key k = crypto::rand<rct::key>();
    // c1 = k*G
    rct::scalarmultBase(ct.c1, k);
    // wG
    rct::key w_scalar = uint64_to_scalar(w);
    rct::key wG;
    rct::scalarmultBase(wG, w_scalar);
    // k*T_pub
    rct::key kT;
    rct::scalarmultKey(kT, T_pub, k);
    // c2 = wG + kT
    rct::addKeys(ct.c2, wG, kT);
    return ct;
  }

  // ------------------------------------------------------------
  // split_secret (Shamir)
  // ------------------------------------------------------------
  void split_secret(const rct::key &secret, int k, int n,
                    std::vector<std::pair<int, rct::key>> &shares) {
    shares.clear();
    // Generate random polynomial coefficients a[0] = secret, a[1..k-1] random
    std::vector<rct::key> coeff(k);
    coeff[0] = secret;
    for (int i = 1; i < k; ++i) {
      coeff[i] = crypto::rand<rct::key>();
    }
    // Evaluate at x = 1..n
    for (int x = 1; x <= n; ++x) {
      rct::key x_scalar = uint64_to_scalar(x);
      rct::key y = rct::zero();
      rct::key x_pow = SCALAR_ONE;
      for (int j = 0; j < k; ++j) {
        rct::key term;
        scalar_mul(term, coeff[j], x_pow);
        scalar_add(y, y, term);
        scalar_mul(x_pow, x_pow, x_scalar);
      }
      shares.push_back({x, y});
    }
  }

  // ------------------------------------------------------------
  // reconstruct_secret (Lagrange at x=0)
  // ------------------------------------------------------------
  rct::key reconstruct_secret(const std::vector<std::pair<int, rct::key>> &shares) {
    int k = shares.size();
    rct::key secret = rct::zero();
    for (int j = 0; j < k; ++j) {
      int xj = shares[j].first;
      rct::key yj = shares[j].second;
      // Compute λ_j(0)
      rct::key lambda = SCALAR_ONE;
      for (int m = 0; m < k; ++m) {
        if (m == j) continue;
        int xm = shares[m].first;
        // λ_j *= (0 - xm) / (xj - xm)
        rct::key num = uint64_to_scalar(xm);
        scalar_sub(num, rct::zero(), num); // num = -xm
        rct::key den = uint64_to_scalar(xj);
        scalar_sub(den, den, uint64_to_scalar(xm)); // den = xj - xm
        rct::key den_inv;
        scalar_invert(den_inv, den);
        rct::key factor;
        scalar_mul(factor, num, den_inv);
        scalar_mul(lambda, lambda, factor);
      }
      // secret += yj * lambda
      rct::key term;
      scalar_mul(term, yj, lambda);
      scalar_add(secret, secret, term);
    }
    return secret;
  }

  // ------------------------------------------------------------
  // compute_decryption_share
  // ------------------------------------------------------------
  rct::key compute_decryption_share(const rct::key &c1_sum, const rct::key &secret_share) {
    // share = secret_share * c1_sum
    rct::key share;
    rct::scalarmultKey(share, c1_sum, secret_share);
    return share;
  }

  // ------------------------------------------------------------
  // combine_shares
  // ------------------------------------------------------------
  rct::key combine_shares(const std::vector<std::pair<int, rct::key>> &shares) {
    int k = shares.size();
    rct::key wG = rct::identity(); // zero point
    for (int j = 0; j < k; ++j) {
      int xj = shares[j].first;
      rct::key point = shares[j].second;
      // Compute λ_j(0) scalar
      rct::key lambda = SCALAR_ONE;
      for (int m = 0; m < k; ++m) {
        if (m == j) continue;
        int xm = shares[m].first;
        rct::key num = uint64_to_scalar(xm);
        scalar_sub(num, rct::zero(), num); // -xm
        rct::key den = uint64_to_scalar(xj);
        scalar_sub(den, den, uint64_to_scalar(xm)); // xj - xm
        rct::key den_inv;
        scalar_invert(den_inv, den);
        rct::key factor;
        scalar_mul(factor, num, den_inv);
        scalar_mul(lambda, lambda, factor);
      }
      // Multiply point by lambda
      rct::key term;
      rct::scalarmultKey(term, point, lambda);
      // Add to wG
      rct::addKeys(wG, wG, term);
    }
    return wG;
  }

  // ------------------------------------------------------------
  // recover_weight_from_point (baby-step giant-step)
  // ------------------------------------------------------------
  uint64_t recover_weight_from_point(const rct::key &wG) {
    const uint64_t m = 1ULL << 32; // 2^32
    // Baby steps: j*G for j=0..m-1
    std::unordered_map<std::string, uint64_t> baby;
    rct::key cur = rct::identity();
    for (uint64_t j = 0; j < m; ++j) {
      std::string key(reinterpret_cast<const char*>(cur.bytes), 32);
      baby[key] = j;
      rct::addKeys(cur, cur, rct::G);
    }
    // Giant steps
    rct::key mG;
    rct::scalarmultBase(mG, uint64_to_scalar(m));
    rct::key giant = wG;
    for (uint64_t i = 0; i < m; ++i) {
      std::string key(reinterpret_cast<const char*>(giant.bytes), 32);
      auto it = baby.find(key);
      if (it != baby.end()) {
        return i * m + it->second;
      }
      rct::subKeys(giant, giant, mG);
    }
    return 0; // should never happen for valid votes
  }

  // BEGIN_VNS_DKG_ENCRYPTION
  std::string encrypt_dkg_share(const rct::key &share, const public_key &recipient_pub, const secret_key &sender_priv) {
    public_key eph_pub;
    secret_key eph_priv;
    crypto::generate_keys(eph_pub, eph_priv);
    crypto::key_derivation derivation;
    if (!crypto::generate_key_derivation(recipient_pub, eph_priv, derivation))
      return {};
    public_key derived_key;
    crypto::derive_public_key(derivation, 0, recipient_pub, derived_key);
    rct::key tmp_nonce = crypto::rand<rct::key>();
    unsigned char nonce[8];
    memcpy(nonce, tmp_nonce.bytes, sizeof(nonce));
    crypto::hash key_hash;
    crypto::cn_fast_hash(&derived_key, sizeof(derived_key), key_hash);
    std::string ciphertext(sizeof(share), 0);
    for (size_t i = 0; i < sizeof(share); ++i)
      ciphertext[i] = share.bytes[i] ^ key_hash.data[i % sizeof(key_hash)];
    std::string out;
    out.reserve(sizeof(eph_pub) + sizeof(nonce) + ciphertext.size());
    out.append(reinterpret_cast<const char*>(&eph_pub), sizeof(eph_pub));
    out.append(reinterpret_cast<const char*>(nonce), sizeof(nonce));
    out += ciphertext;
    return out;
  }

  rct::key decrypt_dkg_share(const std::string &encrypted, const secret_key &recipient_priv, public_key &sender_pub) {
    const size_t pub_sz = sizeof(public_key), nonce_sz = 8;
    if (encrypted.size() < pub_sz + nonce_sz + 1)
      return rct::zero();
    memcpy(&sender_pub, encrypted.data(), pub_sz);
    const char *ct = encrypted.data() + pub_sz + nonce_sz;
    size_t ct_len = encrypted.size() - pub_sz - nonce_sz;
    if (ct_len < sizeof(rct::key))
      return rct::zero();
    crypto::key_derivation derivation;
    if (!crypto::generate_key_derivation(sender_pub, recipient_priv, derivation))
      return rct::zero();
    public_key derived_key;
    crypto::derive_public_key(derivation, 0, sender_pub, derived_key);
    crypto::hash key_hash;
    crypto::cn_fast_hash(&derived_key, sizeof(derived_key), key_hash);
    rct::key share;
    for (size_t i = 0; i < sizeof(share); ++i)
      share.bytes[i] = ct[i] ^ key_hash.data[i % sizeof(key_hash)];
    return share;
  }

  rct::key combine_partial_points(const std::vector<std::pair<int, rct::key>> &points, const std::vector<int> &indices, int threshold) {
    rct::key result = rct::identity();
    for (size_t i = 0; i < indices.size(); ++i) {
      int xi = indices[i];
      rct::key lagrange_num = SCALAR_ONE, lagrange_den = SCALAR_ONE;
      for (size_t j = 0; j < indices.size(); ++j) {
        if (i == j) continue;
        int xj = indices[j];
        rct::key term_num = uint64_to_scalar(xj);
        rct::key term_den;
        rct::key xi_s = uint64_to_scalar(xi);
        rct::key xj_s = uint64_to_scalar(xj);
        scalar_sub(term_den, xi_s, xj_s);
        scalar_mul(lagrange_num, lagrange_num, term_num);
        scalar_mul(lagrange_den, lagrange_den, term_den);
      }
      rct::key coeff;
      scalar_invert(coeff, lagrange_den);
      scalar_mul(coeff, coeff, lagrange_num);
      rct::key term;
      rct::scalarmultKey(term, points[i].second, coeff);
      rct::addKeys(result, result, term);
    }
    return result;
  }
  // END_VNS_DKG_ENCRYPTION

} // namespace crypto