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

#ifndef BICYCL_TLV_HPP
#define BICYCL_TLV_HPP

#include "bicycl.hpp"
#include <iomanip>

namespace BICYCL
{

class TLV
{
  public:
    /* Aliases */
    using Bytes = std::vector<uint8_t>;
    using BytesIt = Bytes::const_iterator;
    using CLCipherText = CL_HSMqk::CipherText;

    /* Parsing error */
    class ParsingError : public std::runtime_error
    {
      public:
        using runtime_error::runtime_error;
    };


    /* Ctors */
    TLV() = default;
    explicit TLV(const Bytes & data);
    explicit TLV(const Mpz & d);
    explicit TLV(const QFI & f, bool compressed = true);
    explicit TLV(const CLCipherText & f, bool compressed = true);
    explicit TLV(const CL_HSMqk_ZKPoPK & aok);
    explicit TLV(const CL_HSMqk_EC_Dlog_ZKPwPE & proof);
    TLV(const ECGroup & E, const ECPoint & P, bool compressed = true);
    TLV(const ECGroup & E, const EC_Dlog_ZKPoK & proof);
    TLV(const ECGroup & E, const EC_3Dlog_ZKAoK & aok);

    /* Conversion */
    explicit operator Mpz () const;
    explicit operator BN () const;
    explicit operator CL_HSMqk_ZKPoPK() const;
    explicit operator CL_HSMqk_EC_Dlog_ZKPwPE() const;
    QFI to_QFI (const Mpz & disc) const;
    CL_HSMqk::CipherText to_Ciphertext (const CL_HSMqk & C) const;
    ECPoint to_ECPoint (const ECGroup & E) const;
    EC_Dlog_ZKPoK to_ECNIZKProof(const ECGroup & E) const;
    EC_3Dlog_ZKAoK to_ECNIZKAoK(const ECGroup & E) const;


    /* getters */
    uint8_t type() const;
    uint16_t length() const;
    const Bytes & value() const;

    /* Serialize: TLV to frame */
    void serialize (Bytes & frame) const;

    /* Parse: frame to TLV */
    static TLV parse_one (const Bytes & frame, BytesIt & it);

    static size_t parse (std::vector<TLV> & tlv_vec,
                         const Bytes & frame,
                         unsigned int offset = 0u);

    friend std::ostream & operator<< (std::ostream & o, const TLV &);

  private:
    void ctor_set_length ();

    /* TLV type IDs */
    static const uint8_t TYPEID_BYTES           = 0x01;
    static const uint8_t TYPEID_INT             = 0x02;
    static const uint8_t TYPEID_QFI_STD         = 0x10;
    static const uint8_t TYPEID_QFI_COMPR       = 0x11;
    static const uint8_t TYPEID_CIPHERTXT       = 0x20;
    static const uint8_t TYPEID_ECPOINT_AFFINE  = 0x30;
    static const uint8_t TYPEID_ECPOINT_COMPR   = 0x31;
    static const uint8_t TYPEID_CLZKAOK         = 0x40;
    static const uint8_t TYPEID_ECNIZKPOK       = 0x41;
    static const uint8_t TYPEID_ECNIZKAOK       = 0x42;
    static const uint8_t TYPEID_CLDLZKPOK       = 0x43;

    /* Max length */
    static const uint16_t MAX_LENGTH = 0xFFFF - 3u;

    /* Member vars */
    uint8_t type_;
    Bytes value_; /* Has exactly length - 3 elements */
    uint16_t length_;
};

} /* namespace BICYCL */


#include "tlv.inl"

#endif /* BICYCL_TLV_HPP */