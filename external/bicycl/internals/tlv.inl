/*
 * Implementation of TECLA and THE CLASH for the NIST MPTC 2026 call
 * Copyright (C) 2026 Quentin Combal <quentin.combal@lirmm.fr>
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

#ifndef BICYCL_TLV_INL
#define BICYCL_TLV_INL

#include "tlv.hpp"
#include <sstream>

namespace BICYCL
{

/* */
inline TLV::TLV(const Bytes & data)
  : type_{TYPEID_BYTES},
    value_{data}
{
  ctor_set_length();
}

/* */
inline TLV::TLV(const Mpz & d)
  : type_(TYPEID_INT)
{
  /* First byte is the sign, then the absolute value */
  value_.push_back((d.sgn() < 0) ? 1 : 0);
  Bytes d_vec(d);
  value_.insert(value_.cend(), d_vec.cbegin(), d_vec.cend());

  ctor_set_length();
}

/* */
inline TLV::TLV(const QFI & f, bool compressed)
  : type_(compressed ? TYPEID_QFI_COMPR : TYPEID_QFI_STD)
{
  if (compressed)
  {
    QFICompressedRepresentation fzip = f.compressed_repr();
    /* First byte is the sign*/
    value_.push_back(fzip.is_neg ? 0x01 : 0x00);
    /* Then TLV sequence of ap, g ,tp, b0 */
    TLV tlv_mpz{fzip.ap};
    tlv_mpz.serialize(value_);
    tlv_mpz = TLV(fzip.g);
    tlv_mpz.serialize(value_);
    tlv_mpz = TLV(fzip.tp);
    tlv_mpz.serialize(value_);
    tlv_mpz = TLV(fzip.b0);
    tlv_mpz.serialize(value_);
  }
  else
  {
    /* TLV sequence of a,b,c */
    TLV tlv_mpz{f.a()};
    tlv_mpz.serialize(value_);
    tlv_mpz = TLV(f.b());
    tlv_mpz.serialize(value_);
    tlv_mpz = TLV(f.c());
    tlv_mpz.serialize(value_);
  }

  ctor_set_length();
}

/* */
inline TLV::TLV(const CLCipherText & ct, bool compressed)
  : type_(TYPEID_CIPHERTXT)
{
  TLV tlv_qfi{ct.c1(), compressed};
  tlv_qfi.serialize(value_);
  tlv_qfi = TLV(ct.c2(), compressed);
  tlv_qfi.serialize(value_);

  ctor_set_length();
}

/* */
inline TLV::TLV(const CL_HSMqk_ZKPoPK & proof)
  : type_(TYPEID_CLZKAOK)
{
  TLV tlv_mpz{proof.u1()};
  tlv_mpz.serialize(value_);
  tlv_mpz = TLV(proof.u2());
  tlv_mpz.serialize(value_);
  tlv_mpz = TLV(proof.k());
  tlv_mpz.serialize(value_);

  ctor_set_length();
}

/* */
inline TLV::TLV(const ECGroup & E, const ECPoint & P, bool compressed)
  : type_(compressed ? TYPEID_ECPOINT_COMPR : TYPEID_ECPOINT_AFFINE)
{
  if (compressed)
  {
    /* sign of y + coordinate x */
    BICYCL::BN x, y;
    E.coords_of_point(x, y, P);
    value_.push_back(y.is_odd() ? 1 : 0);
    TLV tlv_mpz{Mpz(x)};
    tlv_mpz.serialize(value_);
  }
  else
  {
    /* 2 coordinates (x,y) */
    BICYCL::BN x, y;
    E.coords_of_point(x, y, P);
    TLV tlv_mpz{Mpz(x)};
    tlv_mpz.serialize(value_);
    tlv_mpz = TLV(Mpz(y));
    tlv_mpz.serialize(value_);
  }

  ctor_set_length();
}

/* */
inline TLV::TLV(const ECGroup & E, const EC_Dlog_ZKPoK & proof)
  : type_(TYPEID_ECNIZKPOK)
{
  TLV tlv{E, proof.R()};
  tlv.serialize(value_);
  tlv = TLV(Mpz(proof.z()));
  tlv.serialize(value_);

  ctor_set_length();
}

/* */
inline TLV::TLV(const ECGroup & E, const EC_3Dlog_ZKAoK & proof)
  : type_(TYPEID_ECNIZKAOK)
{
  TLV tlv{E, proof.H()};
  tlv.serialize(value_);
  tlv = TLV(Mpz(proof.t1()));
  tlv.serialize(value_);
  tlv = TLV(Mpz(proof.t2()));
  tlv.serialize(value_);

  ctor_set_length();
}

/* */
inline TLV::TLV(const CL_HSMqk_EC_Dlog_ZKPwPE & proof)
  : type_(TYPEID_CLDLZKPOK)
{
  TLV tlv{proof.u1()};
  tlv.serialize(value_);
  tlv = TLV(Mpz(proof.u2()));
  tlv.serialize(value_);
  tlv = TLV(Mpz(proof.chl()));
  tlv.serialize(value_);

  ctor_set_length();
}

/* */
inline TLV::operator Mpz () const
{
  if (type_ != TYPEID_INT)
  {
    std::cerr << "type : " << (unsigned int)type_ << std::endl;
    throw ParsingError("TLV to Mpz: wrong type");
  }

  std::vector<uint8_t> absval;
  absval.insert(absval.cbegin(), std::next(value_.cbegin()), value_.cend());
  Mpz d{absval};
  if (value_.at(0) != 0x00) d.neg();

  return d;
}

/* */
inline TLV::operator BN () const
{
  Mpz d{*this};
  return BN(d);
}


/* */
inline TLV::operator CL_HSMqk_ZKPoPK () const
{
  if (type_ != TYPEID_CLZKAOK)
  {
    std::cerr << "type : " << (unsigned int)type_ << std::endl;
    throw ParsingError("TLV to CLHsmqk_ZK_AoK: wrong type");
  }
  std::vector<TLV> tlv_vec;
  parse(tlv_vec, value_);
  if (tlv_vec.size() < 3)
    throw ParsingError("TLV to CLHsmqk_ZK_AoK: invalid frame");

  return CL_HSMqk_ZKPoPK(Mpz(tlv_vec[0]), Mpz(tlv_vec[1]), Mpz(tlv_vec[2]));
}

inline TLV::operator CL_HSMqk_EC_Dlog_ZKPwPE() const
{
  if (type_ != TYPEID_CLDLZKPOK)
    throw ParsingError("TLV to CLDLZKProof: wrong type");

  std::vector<TLV> tlv_vec;
  parse(tlv_vec, value_);
  if (tlv_vec.size() < 3)
    throw ParsingError("TLV to CLDLZKProof: invalid frame");

  return CL_HSMqk_EC_Dlog_ZKPwPE(Mpz(tlv_vec[0]), Mpz(tlv_vec[1]), Mpz(tlv_vec[2]));
}


/* */
inline QFI TLV::to_QFI(const Mpz & disc) const
{
  QFI ret;
  std::vector<TLV> tlv_vec;
  if (type_ == TYPEID_QFI_STD)
  {
    /* Standard representation (a, b, c) */
    parse(tlv_vec, value_);
    if (tlv_vec.size() < 3) throw ParsingError("TLV to QFI: invalid frame");
    Mpz a{tlv_vec.at(0)};
    Mpz b{tlv_vec.at(1)};
    Mpz c{tlv_vec.at(2)};
    ret = QFI(a, b, c);
  }
  else if (type_ == TYPEID_QFI_COMPR)
  {
    /* Compressed representation (sign, ap, g, tp, b0) */
    bool is_neg = (value_.at(0) == 0x01);
    parse(tlv_vec, value_, 1);
    if (tlv_vec.size() < 4) throw ParsingError("TLV to QFI: invalid frame");
    Mpz ap{tlv_vec.at(0)};
    Mpz g{tlv_vec.at(1)};
    Mpz tp{tlv_vec.at(2)};
    Mpz b0{tlv_vec.at(3)};
    ret = QFI(QFICompressedRepresentation(ap, g, tp, b0, is_neg), disc);
  }
  else
  {
    throw ParsingError("TLV to QFI: wrong type");
  }

  return ret;
}

/* */
inline CL_HSMqk::CipherText TLV::to_Ciphertext(const CL_HSMqk & C) const
{
  if (type_ != TYPEID_CIPHERTXT)
    throw ParsingError("TLV to Ciphertext: wrong type");

  std::vector<TLV> tlv_vec;
  parse(tlv_vec, value_);
  if (tlv_vec.size() < 2)
    throw ParsingError("TLV to Ciphertext: invalid frame");

  const Mpz & c1_disc = C.Cl_G().discriminant();
  const Mpz & c2_disc = C.Delta();

  return CLCipherText{
      C, tlv_vec.at(0).to_QFI(c1_disc), tlv_vec.at(1).to_QFI(c2_disc)};
}

/* */
inline ECPoint TLV::to_ECPoint(const ECGroup & E) const
{
  ECPoint ret{E};
  std::vector<TLV> tlv_vec;
  if (type_ == TYPEID_ECPOINT_AFFINE)
  {
    /* 2 coordinates (x,y) */
    parse(tlv_vec, value_);
    if (tlv_vec.size() < 2) throw ParsingError("TLV to ECPoint: invalid frame");
    Mpz x{tlv_vec.at(0)};
    Mpz y{tlv_vec.at(1)};
    E.set_coords_of_point(ret, BN(x), BN(y));
  }
  else if (type_ == TYPEID_ECPOINT_COMPR)
  {
    /* sign of y + coordinate x */
    bool is_odd = (value_.at(0) == 0x01);
    parse(tlv_vec, value_, 1);
    if (tlv_vec.size() < 1) throw ParsingError("TLV to ECPoint: invalid frame");
    Mpz x{tlv_vec.at(0)};
    E.set_coords_of_point(ret, BN(x), is_odd);
  }
  else
  {
    throw ParsingError("TLV to EcPoint: wrong type");
  }

  return ret;
}

inline EC_Dlog_ZKPoK TLV::to_ECNIZKProof(const ECGroup & E) const
{
  if (type_ != TYPEID_ECNIZKPOK)
    throw ParsingError("TLV to ECNIZKProof: wrong type");

  std::vector<TLV> tlv_vec;
  parse(tlv_vec, value_);
  if (tlv_vec.size() < 2)
    throw ParsingError("TLV to ECNIZKProof: invalid frame");

  return EC_Dlog_ZKPoK(E, tlv_vec[0].to_ECPoint(E), BN(tlv_vec[1]));
}

inline EC_3Dlog_ZKAoK TLV::to_ECNIZKAoK(const ECGroup & E) const
{
  if (type_ != TYPEID_ECNIZKAOK)
    throw ParsingError("TLV to ECNIZKAoK: wrong type");

  std::vector<TLV> tlv_vec;
  parse(tlv_vec, value_);
  if (tlv_vec.size() < 3)
    throw ParsingError("TLV to ECNIZKAoK: invalid frame");

  return EC_3Dlog_ZKAoK(E, tlv_vec[0].to_ECPoint(E), BN(tlv_vec[1]), BN(tlv_vec[2]));
}


/* */
inline uint8_t TLV::type() const
{
  return type_;
}

/* */
inline uint16_t TLV::length() const
{
  return length_;
}

/* */
inline const TLV::Bytes & TLV::value() const
{
  return value_;
}

/* */
inline void TLV::serialize(Bytes & frame) const
{
  /* Add type */
  frame.push_back(type_);
  /* Add length */
  frame.push_back(length_ & 0xFF);
  frame.push_back(length_ >> 8u);
  /* Add data */
  frame.insert(frame.cend(), value_.cbegin(), value_.cend());
}

/* */
inline TLV TLV::parse_one(const Bytes & frame, BytesIt & it)
{
  long dist = std::distance(it, frame.cend());
  if (dist < 3u) throw ParsingError("TLV frame is too short");

  TLV tlv;
  /* Get type */
  tlv.type_ = *it;

  /* Get and check length */
  tlv.length_ = *++it;
  tlv.length_ = (*++it << 8) | tlv.length_;
  if (dist < (tlv.length_ + 3u))
  {
    std::stringstream err;
    err << "Wrong frame length, expected at least " << tlv.length_ + 3u
        << ", got " << dist;
    throw ParsingError(err.str());
  }

  /* Store value */
  ++it;
  tlv.value_.assign(it, std::next(it, tlv.length_));
  std::advance(it, tlv.length_);

  return tlv;
}

/* */
inline size_t
TLV::parse(std::vector<TLV> & tlv_vec, const Bytes & frame, unsigned int offset)
{
  if (offset >= frame.size()) throw ParsingError("Invalid iterator offset");
  auto it = frame.cbegin();
  std::advance(it, offset); // WARNING problem if offset > frame size
  while (it != frame.cend())
  {
    tlv_vec.push_back(parse_one(frame, it));
  }
  return tlv_vec.size();
}

/* */
inline std::ostream & operator<< (std::ostream & o, const TLV & tlv)
{
  auto flags_bak = o.flags();
  o << std::setw(2) << std::setfill('0');
  o << "Type: 0x" << std::hex << std::setw(2) << std::setfill('0')
    << (unsigned int)tlv.type_;
  o << "  Length: " << std::dec << (unsigned int)tlv.length_;
  o << "  Value: " << std::hex;

  for (auto b : tlv.value_)
  {
    o << std::setw(2) << std::setfill('0') << (unsigned int)b << ' ';
  }

  o.flags(flags_bak);
  return o;
}

/* */
inline void TLV::ctor_set_length()
{
  if (value_.size() > MAX_LENGTH)
    throw std::invalid_argument("TLV: data is too large");

  length_ = value_.size();
}
} /* namespace BICYCL */


#endif /* BICYCL_TLV_HPP */