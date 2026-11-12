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
#ifndef BICYCL_TWOPARTY_ECDSA_INL
#define BICYCL_TWOPARTY_ECDSA_INL

#include "twoParty_ECDSA.hpp"

namespace BICYCL
{
//////////////////////////////////////////////////////////////////////////////
//      ___ ___ _____ _   _ ___
//     / __| __|_   _| | | | _ \.
//     \__ \ _|  | | | |_| |  _/
//     |___/___| |_|  \___/|_|
//
inline TwoPartyECDSA::Setup::Setup(SecLevel seclevel, RandGen & randgen)
  : seclevel_(seclevel),
    E_(seclevel)
{
  gen_rho_part(randgen);
}

/* */
inline const Mpz & TwoPartyECDSA::Setup::rho_part() const
{
  return rho_part_;
}

/* */
inline const Mpz & TwoPartyECDSA::Setup::rho() const
{
  return rho_;
}

/* */
inline const TwoPartyECDSA::Commitment &
TwoPartyECDSA::Setup::commitment() const
{
  return c_;
}

/* */
inline const TwoPartyECDSA::CommitmentSecret &
TwoPartyECDSA::Setup::commitment_secret() const
{
  return cs_;
}

inline
void TwoPartyECDSA::Setup::gen_rho_part(RandGen & randgen)
{
  // Generate rho_part
  rho_part_ = Mpz(E_.random_mod_order(randgen));
  // Commit using public parameters + a secret of seclevel bits
  cs_ = randgen.random_bytes(seclevel_.nbits() / 8);
  HashAlgo H{seclevel_};
  c_ = H(cs_, rho_part_, E_);
}

inline
void TwoPartyECDSA::Setup::compute_rho(
    const Mpz & rho_part_other,
    const TwoPartyECDSA::Commitment & c_other,
    const TwoPartyECDSA::CommitmentSecret & cs_other)
{
  HashAlgo H{seclevel_};

  // Open commitments and compute rho (xor of rho_parts)
  Commitment commit_check{H(cs_other, rho_part_other, E_)};
  if (commit_check != c_other)
    throw ProtocolAbortError("Setup: cannot verify commitment");

  Mpz::exor(rho_, rho_part_other, rho_part_);
}

/* */
inline CL_HSMqk TwoPartyECDSA::Setup::gen_CL() const
{
  RandGen randgen(rho_);
  return CL_HSMqk(
      E_.order(), 1, seclevel_, randgen, CL_Params{seclevel_.statistical()});
}

//////////////////////////////////////////////////////////////////////////////
//    ___ _      ___   _____ ___   _
//   | _ \ |    /_\ \ / / __| _ \ / |
//   |  _/ |__ / _ \ V /| _||   / | |
//   |_| |____/_/ \_\_| |___|_|_\ |_|
//
inline TwoPartyECDSA::Player1::Player1(const TwoPartyECDSA & ctx)
  : Q1_{ctx.E_},
    R1_{ctx.E_},
    public_key_{ctx.E_},
    proof_ckey_{},
    zk_com_proof_{ctx.E_}
{
  // Nothing to do
}

inline const ECPoint & TwoPartyECDSA::Player1::Q1() const
{
  return Q1_;
}

inline const ECPoint & TwoPartyECDSA::Player1::R1() const
{
  return R1_;
}

inline const ECPoint & TwoPartyECDSA::Player1::public_key() const
{
  return public_key_;
}

inline const TwoPartyECDSA::Commitment & TwoPartyECDSA::Player1::commit() const
{
  return commit_;
}

inline const TwoPartyECDSA::CommitmentSecret &
TwoPartyECDSA::Player1::commit_secret() const
{
  return commit_secret_;
}

inline const CL_HSMqk::PublicKey & TwoPartyECDSA::Player1::pkcl() const
{
  return pkcl_;
}

inline const CL_HSMqk::CipherText & TwoPartyECDSA::Player1::Ckey() const
{
  return Ckey_;
}

inline const EC_Dlog_ZKPoK & TwoPartyECDSA::Player1::zk_com_proof() const
{
  return zk_com_proof_;
}

inline const CL_HSMqk_EC_Dlog_ZKPwPE & TwoPartyECDSA::Player1::proof_ckey() const
{
  return proof_ckey_;
}

inline void TwoPartyECDSA::Player1::KeygenPart1(const TwoPartyECDSA & ctx,
                                                RandGen & randgen)
{
  // Sample x1 from [0, q[
  x1_ = ctx.E_.random_mod_order(randgen);
  // Compute Q1 <- [x1] P
  ctx.E_.scal_mul_gen(Q1_, x1_);

  // Compute proof of x1 knowledge
  zk_com_proof_ = EC_Dlog_ZKPoK(ctx.E_, ctx.H_, randgen, x1_, Q1_);

  // Compute commitment + commitment secret
  std::tie(commit_, commit_secret_) = ctx.commit(randgen, zk_com_proof_);
}

inline void TwoPartyECDSA::Player1::KeygenPart3(const TwoPartyECDSA & ctx,
                                                RandGen & randgen,
                                                const ECPoint & Q2,
                                                const EC_Dlog_ZKPoK & proof_x2)
{
  // Verify ZK proof
  if (false == proof_x2.verify(ctx.E_, ctx.H_, Q2))
  {
    throw ProtocolAbortError("could not verify ZK-proof of x2 knowledge");
  }

  // Generate CL_HSM keys
  skcl_ = ctx.CL_.keygen(randgen); // Secret key
  pkcl_ = ctx.CL_.keygen(skcl_);   // Public key from secret key

  // Encrypt x1 into Ckey
  Mpz random = ctx.CL_.encrypt_randomness_bound();
  CL_HSMqk::ClearText x1ClearText(ctx.CL_, Mpz(x1_));

#ifdef BICYCL_WITH_PTHREADS
  // Ckey computation is done in a separate thread
  auto compute_ckey
      = [this, &ctx, x1ClearText, random] (CL_HSMqk::CipherText & ckey) {
          ckey = CL_HSMqk::CipherText(ctx.CL_, pkcl_, x1ClearText, random);
        };
  std::thread th(compute_ckey, std::ref(Ckey_));

  // Compute proof of Ckey's plaintext knowledge
  // Provide thread reference to proof constructor, so that the thread can be
  // joined when Ckey value is needed
  proof_ckey_ = CL_HSMqk_EC_Dlog_ZKPwPE(
      ctx.H_, ctx.E_, x1_, Q1_, ctx.CL_, pkcl_, Ckey_, random, randgen, th);
#else
  Ckey_ = CL_HSMqk::CipherText(ctx.CL_, pkcl_, x1ClearText, random);

  // Compute proof of Ckey's plaintext knowledge
  proof_ckey_ = CL_HSMqk_EC_Dlog_ZKPwPE(
      ctx.H_, ctx.E_, x1_, Q1_, ctx.CL_, pkcl_, Ckey_, random, randgen);
#endif


  // Compute Q
  ctx.E_.scal_mul(public_key_, x1_, Q2);
}

inline void TwoPartyECDSA::Player1::SignPart1(const TwoPartyECDSA & ctx,
                                              RandGen & randgen,
                                              const Mpz & sid)
{
  // Sample k1 from [0, q[
  k1_ = ctx.E_.random_mod_order(randgen);
  // Compute R1 <- [k1] P
  ctx.E_.scal_mul_gen(R1_, k1_);

  // Compute proof of k1 knowledge
  Mpz sid1;
  Mpz::mulby2(sid1, sid);
  sid1.setbit(0);
  zk_com_proof_ = EC_Dlog_ZKPoK(ctx.E_, ctx.H_, randgen, k1_, R1_, sid1);

  // Compute commitment + commitment secret
  std::tie(commit_, commit_secret_) = ctx.commit(randgen, zk_com_proof_);
}

inline TwoPartyECDSA::Player1::PresignData
TwoPartyECDSA::Player1::SignPart3(const TwoPartyECDSA & ctx,
                                  const ECPoint & R2,
                                  const EC_Dlog_ZKPoK & proof_k2,
                                  const Mpz & sid)
{
  // Verify ZK proof
  Mpz sid2;
  Mpz::mulby2(sid2, sid);
  if (false == proof_k2.verify(ctx.E_, ctx.H_, R2, sid2))
  {
    throw ProtocolAbortError("could not verify ZK-proof of k2 knowledge");
  }

  // Compute R <- [k1] R2, and extract r
  ECPoint R(ctx.E_);

  ctx.E_.scal_mul(R, k1_, R2);
  ctx.E_.x_coord_of_point(r_, R); // r <- Rx

  return PresignData{k1_, r_};
}

inline ECSignature
TwoPartyECDSA::Player1::SignPart5(const TwoPartyECDSA & ctx,
                                  const HashAlgo::Digest & m,
                                  const CL_HSMqk::CipherText & C3)
{
  return SignPart5(ctx, m, C3, {k1_, r_});
}

inline ECSignature
TwoPartyECDSA::Player1::SignPart5(const TwoPartyECDSA & ctx,
                                  const HashAlgo::Digest & m,
                                  const CL_HSMqk::CipherText & C3,
                                  const PresignData & presign_data)
{
  const BN & k1 = presign_data[0];
  const BN & r = presign_data[1];

  // Decrypt C3 using secret key
  Mpz alpha = ctx.CL_.decrypt(skcl_, C3);

  // s <-- alpha * k1^-1 = Dec(skcl, C3) * k1^-1
  BN temp, s;
  ctx.E_.inverse_mod_order(temp, k1);
  ctx.E_.mul_mod_order(s, temp, BN(alpha));

  // s <-- min(s, q-s)
  ctx.E_.neg_mod_order(temp, s); // temp = q-s
  if (temp <= s)
  {
    s = temp;
  }
  ECSignature sig{r, s};

  if (not sig.verify(ctx.E_, public_key_, m))
    throw ProtocolAbortError("could not verify the output signature");

  return ECSignature(r, s);
}

////////////////////////////////////////////////////////////////////////////////
//     ___   __  __ _ _          ___            _
//    / _ \ / _|/ _| (_)_ _  ___| _ \_ _ ___ __(_)__ _ _ _
//   | (_) |  _|  _| | | ' \/ -_)  _/ '_/ -_|_-< / _` | ' \.
//    \___/|_| |_| |_|_|_||_\___|_| |_| \___/__/_\__, |_||_|
//                                               |___/
////////////////////////////////////////////////////////////////////////////////

inline TwoPartyECDSA::Player2::PresignData::PresignData(
    const TwoPartyECDSA & ctx,
    const CLPublicKey pkcl,
    const CLCipherText & ckey_x2,
    const Mpz & r,
    const Mpz k2,
    const Mpz t)
{
  const CL_HSMqk & CL = ctx.CL_;

  Mpz::mod_inverse(k2_inv_, k2, ctx.E_.order());
  Mpz exp;
  Mpz::mul(exp, k2_inv_, r);
  Mpz::mod(exp, exp, ctx.E_.order());

#ifdef BICYCL_WITH_PTHREADS
  // FIXME: This will use 4 threads no matter the value of Parallelism::max_threads
  QFI f1, f2, f3, f4;

  void (ClassGroup::*nupow_ptr)(QFI &, const QFI &, const Mpz &) const
      = &ClassGroup::nupow;
  /* f1 <-- {Ckey_1^{x_2}} ^ {k_2^{-1} * r} */
  std::thread th_f1{nupow_ptr,
                    std::cref(CL.Cl_G()),
                    std::ref(f1),
                    std::cref(ckey_x2.c1()),
                    std::cref(exp)};
  /* f2 <-- {Ckey_2^{x_2}} ^ {k_2^{-1} * r} */
  std::thread th_f2{nupow_ptr,
                    std::cref(CL.Cl_G()),
                    std::ref(f2),
                    std::cref(ckey_x2.c2()),
                    std::cref(exp)};

  /* f3 <-- gq^{t} */
  auto power_of_h_ptr = &CL_HSMqk::power_of_h;
  std::thread th_f3{power_of_h_ptr, std::cref(CL), std::ref(f3), std::cref(t)};

  /* f4 <-- pkcl^{t} */
  pkcl.exponentiation(CL, f4, t);

  /* C31 <-- f1 * f3 = Ckey_1^{x_2 * k_2^{-1} * r} * gq^{t} */
  th_f1.join();
  th_f3.join();
  CL.Cl_G().nucomp(C31_, f1, f3);

  /* C32p <-- f2 * f4 = Ckey_1^{x_2 * k_2^{-1} * r} * pkcl^{t} */
  th_f2.join();
  CL.Cl_G().nucomp(C32p_, f2, f4);

#else
  QFI f_temp;
  /* f_temp <-- {Ckey_1^{x_2}} ^ {k_2^{-1} * r} */
  CL.Cl_G().nupow(f_temp, ckey_x2.c1(), exp);
  /* C31 <-- f_temp * gq^{t} = Ckey_1^{x_2 * k_2^{-1} * r} * gq^{t} */
  CL.power_of_h(C31_, t);
  CL.Cl_G().nucomp(C31_, C31_, f_temp);

  /* f_temp <-- {Ckey_2^{x_2}} ^ {k_2^{-1} * r} */
  CL.Cl_G().nupow(f_temp, ckey_x2.c2(), exp);
  /* C32p <-- f_temp * pkcl^{t} = Ckey_1^{x_2 * k_2^{-1} * r} * pkcl^{t} */
  pkcl.exponentiation(CL, C32p_, t);
  CL.Cl_G().nucomp(C32p_, C32p_, f_temp);

#endif
}

inline TwoPartyECDSA::Player2::PresignData::PresignData(
    const TwoPartyECDSA & ctx,
    const CLPublicKey pkcl,
    const CLCipherText & ckey_x2,
    const Mpz & r,
    const Mpz k2,
    RandGen & randgen)
  : PresignData(ctx,
                pkcl,
                ckey_x2,
                r,
                k2,
                randgen.random_mpz(ctx.CL_.encrypt_randomness_bound()))
{
}

//////////////////////////////////////////////////////////////////////////////
//    ___ _      ___   _____ ___   ___
//   | _ \ |    /_\ \ / / __| _ \ |_  )
//   |  _/ |__ / _ \ V /| _||   /  / /
//   |_| |____/_/ \_\_| |___|_|_\ /___|
//
inline TwoPartyECDSA::Player2::Player2(const TwoPartyECDSA & ctx)
  : Q2_{ctx.E_},
    R2_{ctx.E_},
    public_key_{ctx.E_},
    zk_proof_{ctx.E_}
{
  // Nothing to do
}

inline const ECPoint & TwoPartyECDSA::Player2::Q2() const
{
  return Q2_;
}

inline const ECPoint & TwoPartyECDSA::Player2::R2() const
{
  return R2_;
}

inline const ECPoint & TwoPartyECDSA::Player2::public_key() const
{
  return public_key_;
}

inline const CL_HSMqk::PublicKey & TwoPartyECDSA::Player2::pkcl() const
{
  return pkcl_;
}

inline const CL_HSMqk::CipherText & TwoPartyECDSA::Player2::C3() const
{
  return C3_;
}

inline const EC_Dlog_ZKPoK & TwoPartyECDSA::Player2::zk_proof() const
{
  return zk_proof_;
}

inline void TwoPartyECDSA::Player2::KeygenPart2(const TwoPartyECDSA & ctx,
                                                RandGen & randgen,
                                                const Commitment & commit_Q1)
{
  // Sample x2 from [0, q[
  x2_ = ctx.E_.random_mod_order(randgen);
  // Compute Q2 <- [x1] P
  ctx.E_.scal_mul_gen(Q2_, x2_);

  // Store commitment
  commit_ = commit_Q1;

  // Compute proof of x2 knowledge
  zk_proof_ = EC_Dlog_ZKPoK(ctx.E_, ctx.H_, randgen, x2_, Q2_);
}

inline void TwoPartyECDSA::Player2::KeygenPart4(
    const TwoPartyECDSA & ctx,
    const ECPoint & Q1,
    const CL_HSMqk::CipherText & Ckey,
    const CL_HSMqk::PublicKey & pk,
    const TwoPartyECDSA::CommitmentSecret commit_secret,
    const EC_Dlog_ZKPoK & proof_x1,
    const CL_HSMqk_EC_Dlog_ZKPwPE & proof_ckey)
{
  // Check commitment of proof matches
  if (false == ctx.open(commit_, proof_x1, commit_secret))
  {
    throw ProtocolAbortError(
        "could not verify commited value of ZK-proof (in KeyGen)");
  }

  // Verify ZK proof
  if (false == proof_x1.verify(ctx.E_, ctx.H_, Q1))
  {
    throw ProtocolAbortError("could not verify ZK-proof of x1 knowledge");
  }

  // Verify ZK proof
  if (false == proof_ckey.verify(ctx.H_, ctx.E_, Q1, ctx.CL_, pk, Ckey))
  {
    throw ProtocolAbortError("could not verify CL-DL proof for Ckey");
  }

  // Compute Q <- [x2] Q1
  ctx.E_.scal_mul(public_key_, x2_, Q1);

  // Store CL public key
  pkcl_ = pk;

  // Precompute (Ckey_1^{x_2}, Ckey_2^{x_2})
  QFI ckey1_x2, ckey2_x2;
  Mpz x2{x2_};

#ifdef BICYCL_WITH_PTHREADS
  void (ClassGroup::*nupow_ptr)(QFI &, const QFI &, const Mpz &) const
      = &ClassGroup::nupow;
  std::thread th{nupow_ptr,
                 std::cref(ctx.CL_.Cl_G()),
                 std::ref(ckey1_x2),
                 std::cref(Ckey.c1()),
                 std::cref(x2)};

  ctx.CL_.Cl_G().nupow(ckey2_x2, Ckey.c2(), x2);
  th.join();
#else

  ctx.CL_.Cl_G().nupow(ckey1_x2, Ckey.c1(), x2);
  ctx.CL_.Cl_G().nupow(ckey2_x2, Ckey.c2(), x2);
#endif

  Ckey_x2_ = CL_HSMqk::CipherText(ctx.CL_, ckey1_x2, ckey2_x2);
}

inline void TwoPartyECDSA::Player2::SignPart2(const TwoPartyECDSA & ctx,
                                              RandGen & randgen,
                                              const Commitment & commit_R1,
                                              const Mpz & sid)
{
  // Sample k2 from [0, q[
  k2_ = ctx.E_.random_mod_order(randgen);

  // Compute R2 <- [k2] P
  ctx.E_.scal_mul_gen(R2_, k2_);

  // Store commitment
  commit_ = commit_R1;

  // Compute proof of k2 knowledge
  Mpz sid2;
  Mpz::mulby2(sid2, sid);
  zk_proof_ = EC_Dlog_ZKPoK(ctx.E_, ctx.H_, randgen, k2_, R2_, sid2);
}

inline TwoPartyECDSA::Player2::PresignData
TwoPartyECDSA::Player2::SignPart4_offline(
    const TwoPartyECDSA & ctx,
    RandGen & randgen,
    const ECPoint & R1,
    const TwoPartyECDSA::CommitmentSecret commit_secret,
    const EC_Dlog_ZKPoK & proof_k1,
    const Mpz & sid)
{
  // Check commitment of proof matches
  if (false == ctx.open(commit_, proof_k1, commit_secret))
  {
    throw ProtocolAbortError(
        "could not verify commited value of ZK-proof (in Sign)");
  }

  // Verify ZK proof
  Mpz sid1;
  Mpz::mulby2(sid1, sid);
  sid1.setbit(0);
  if (false == proof_k1.verify(ctx.E_, ctx.H_, R1, sid1))
  {
    throw ProtocolAbortError("could not verify ZK-proof of k1 knowledge");
  }

  // Compute R <- [k2] R1, and extract r
  ECPoint R(ctx.E_);
  ctx.E_.scal_mul(R, k2_, R1);
  BN r;
  ctx.E_.x_coord_of_point(r, R); // r <- Rx

  // Compute the presignature, a precomputation of C3
  return PresignData(ctx, pkcl_, Ckey_x2_, Mpz(r), Mpz(k2_), randgen);
}

/* */
inline void
TwoPartyECDSA::Player2::SignPart4_online(const TwoPartyECDSA & ctx,
                                         const HashAlgo::Digest & m,
                                         const PresignData & presign)
{
  const CL_HSMqk & CL = ctx.CL_;

  // Compute C3,2 = C3,2,p * f^{H(m) * k2^{-1}}
  Mpz exp{m};
  Mpz::mul(exp, exp, presign.k2_inv_); // exp = H(m) * k2^{-1}
  QFI C32;
  CL.Cl_G().nucomp(C32, presign.C32p_, CL.power_of_f(exp));

  C3_ = CLCipherText(CL, presign.C31_, C32);
}

inline void TwoPartyECDSA::Player2::SignPart4(
    const TwoPartyECDSA & ctx,
    RandGen & randgen,
    const HashAlgo::Digest & m,
    const ECPoint & R1,
    const TwoPartyECDSA::CommitmentSecret commit_secret,
    const EC_Dlog_ZKPoK & proof_k1,
    const Mpz & sid)
{
  PresignData presign{
      SignPart4_offline(ctx, randgen, R1, commit_secret, proof_k1, sid)};
  SignPart4_online(ctx, m, presign);
}

//////////////////////////////////////////////////////////////////////////////
//  _______      _____    ___  _   ___ _______   __  ___ ___ ___  ___   _
// |_   _\ \    / / _ \  | _ \/_\ | _ \_   _\ \ / / | __/ __|   \/ __| /_\.
//   | |  \ \/\/ / (_) | |  _/ _ \|   / | |  \ V /  | _| (__| |) \__ \/ _ \.
//   |_|   \_/\_/ \___/  |_|/_/ \_\_|_\ |_|   |_|   |___\___|___/|___/_/ \_\.
//
inline TwoPartyECDSA::TwoPartyECDSA(const SecLevel & seclevel,
                                    RandGen & randgen)
  : seclevel_{seclevel},
    E_{seclevel_},
    CL_{E_.order(), 1, seclevel_, randgen, CL_Params{seclevel.statistical()}},
    H_{seclevel_}
{
  // Nothing to do
}

inline TwoPartyECDSA::TwoPartyECDSA(const SecLevel & seclevel,
                                    const CL_HSMqk & CL)
  : seclevel_{seclevel},
    E_{seclevel_},
    CL_{CL},
    H_{seclevel_}
{
  if (E_.order() != CL.q())
    std::invalid_argument("TwoPartyECDSA: CL.q should be equal to Elliptic Curve order");
}

inline TwoPartyECDSA::TwoPartyECDSA(const SecLevel & seclevel,
                                    const Setup & isetup)
  : TwoPartyECDSA(seclevel, isetup.gen_CL())
{
  // Nothing to do
}


/**
   * Getters
   *
   **/
inline const ECGroup & TwoPartyECDSA::ec_group() const
{
  return E_;
}

inline const CL_HSMqk & TwoPartyECDSA::CL_HSMq() const
{
  return CL_;
}

inline HashAlgo & TwoPartyECDSA::H() const
{
  return H_;
}

inline HashAlgo::Digest
TwoPartyECDSA::hash(const std::vector<unsigned char> & m) const
{
  return H_(m);
}

inline std::tuple<TwoPartyECDSA::Commitment, TwoPartyECDSA::CommitmentSecret>
TwoPartyECDSA::commit(RandGen & randgen, const EC_Dlog_ZKPoK & proof) const
{
  size_t nbytes = seclevel_.nbits() >> 3; /* = seclevel/8 */
  TwoPartyECDSA::CommitmentSecret r(randgen.random_bytes(nbytes));
  // Commitment <- H(r, R, z)
  // Commitment secret <- r
  return std::make_tuple(H_(r, ECPointGroupCRefPair(proof.R(), E_), proof.z()),
                         r);
}

inline bool TwoPartyECDSA::open(const Commitment & c,
                                const EC_Dlog_ZKPoK & proof,
                                const TwoPartyECDSA::CommitmentSecret & r) const
{
  Commitment c2(H_(r, ECPointGroupCRefPair(proof.R(), E_), proof.z()));
  return c == c2;
}

inline bool TwoPartyECDSA::verify(const ECSignature & signature,
                                  const PublicKey & Q,
                                  const HashAlgo::Digest & m) const
{
  return signature.verify(E_, Q, m);
}

}

#endif /* BICYCL_TWOPARTY_ECDSA_INL */
