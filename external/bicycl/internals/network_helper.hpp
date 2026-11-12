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

#ifndef BICYCL_NETWORK_HELPER_HPP
#define BICYCL_NETWORK_HELPER_HPP

#include <cassert>
#include <map>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <chrono>

#include "bicycl.hpp"
#include "tlv.hpp"

#include "sockpp/tcp_connector.h"
#include "sockpp/tcp_acceptor.h"

namespace BICYCL
{

class NetworkError : public std::runtime_error
{
    using std::runtime_error::runtime_error;
};

class NetworkHelper
{
  public:
    using PeersMap = std::map<unsigned int, sockpp::tcp_socket>;
    using seconds = std::chrono::duration<long int>;

    std::vector<uint8_t> buffer_out;
    std::vector<uint8_t> buffer_in;
    PeersMap peers_map;

  private:
    static const size_t MAX_PACKET_SIZE = 65536;
    sockpp::tcp_acceptor acceptor_;

    class InvalidArgument : public std::invalid_argument
    {
        using std::invalid_argument::invalid_argument;
    };

  public:

    /* ctor */
    NetworkHelper()
    {
      sockpp::initialize();
    }

    NetworkHelper(uint32_t address, uint16_t port)
    : NetworkHelper()
    {
      /* Create tcp socket and bind it with the port */
      std::error_code ec;
      sockpp::inet_address addr(htonl(address), port);
      sockpp::tcp_acceptor acc{addr, 4, sockpp::tcp_acceptor::REUSE, ec};
      if (ec) {
        std::stringstream str;
        str << "Socket creation failed : " << ec.message();
        throw NetworkError(str.str());
      }

      acceptor_ = std::move(acc);
    }

    sockpp::tcp_socket tcp_connect2 (uint32_t address, uint16_t port=8080)
    {
      sockpp::inet_address addr(htonl(address), port);
      sockpp::tcp_connector conn;

      // Attempt to connect with a 5sec timeout.
      auto res = conn.connect(addr,seconds(5));
      if (!res) {
        std::cout << "timeout";
          std::stringstream str;
          str << "Error connecting to peer : " << res.error_message();
          throw NetworkError(str.str());
      }

      // Set a timeout for the responses
      res = conn.read_timeout(seconds(5));
      if (!res) {
        std::stringstream str;
        str << "Error setting timeout on TCP stream: " << res.error_message();
        throw NetworkError(str.str());
      }

      return conn;
    }

    sockpp::tcp_socket tcp_accept2 ()
    {
      sockpp::inet_address peer;
      auto res = acceptor_.accept(&peer);
      if (!res)
          throw NetworkError("Error accepting connection");

      return res.release();
    }

    /* prepare data frame */
    void prepare (const std::vector<uint8_t> vec)
    {
      BICYCL::TLV tlv(vec);
      tlv.serialize(buffer_out);
    }

    void prepare (const BICYCL::Mpz & d)
    {
      BICYCL::TLV tlv(d);
      tlv.serialize(buffer_out);
    }

    void prepare (const BICYCL::QFI & f, bool compressed = true)
    {
      BICYCL::TLV tlv(f, compressed);
      tlv.serialize(buffer_out);
    }

    void prepare (const BICYCL::CL_HSMqk::CipherText & ct,
                  bool compressed = true)
    {
      BICYCL::TLV tlv(ct, compressed);
      tlv.serialize(buffer_out);
    }


    void prepare (const BICYCL::CL_HSMqk_ZKPoPK & proof)
    {
      BICYCL::TLV tlv(proof);
      tlv.serialize(buffer_out);
    }

    void prepare (const BICYCL::CL_HSMqk_EC_Dlog_ZKPwPE & proof)
    {
      BICYCL::TLV tlv(proof);
      tlv.serialize(buffer_out);
    }

    void prepare (const BICYCL::BN & a)
    {
      prepare(BICYCL::Mpz(a));
    }

    void prepare (const BICYCL::ECGroup & E,
                  const BICYCL::ECPoint & P,
                  bool compressed = true)
    {
      BICYCL::TLV tlv(E, P, compressed);
      tlv.serialize(buffer_out);
    }


    void prepare (const BICYCL::ECGroup & E,
                  const std::vector<BICYCL::ECPoint> & P,
                  bool compressed = true)
    {
      for(const ECPoint & Pi : P)
        prepare(E, Pi, compressed);
    }

    void prepare (const BICYCL::ECGroup & E, const BICYCL::EC_Dlog_ZKPoK & proof)
    {
      BICYCL::TLV tlv(E, proof);
      tlv.serialize(buffer_out);
    }

    void prepare (const BICYCL::ECGroup & E, const BICYCL::EC_3Dlog_ZKAoK & proof)
    {
      BICYCL::TLV tlv(E, proof);
      tlv.serialize(buffer_out);
    }


    /* send data */
    size_t send (bool clear_after=true){
        return send_to(peers_map.cbegin()->first, clear_after);
    }

    size_t send_to (unsigned int j, bool clear_after=true)
    {
      if (buffer_out.size() > MAX_PACKET_SIZE)
        throw InvalidArgument("send: frame exceeds maximum packet size");

      auto res = peers_map.at(j).write(buffer_out.data(), buffer_out.size());
      if (res.is_error()) throw NetworkError("Failed to send frame");

      if (clear_after) buffer_out.clear();

      return res.value();
    }

    /* Receive data */
    size_t receive ()
    {
      return recv_from(peers_map.cbegin()->first);
    }

    size_t recv_from (unsigned int j)
    {
      uint8_t buffer[MAX_PACKET_SIZE];

      auto res = peers_map.at(j).read(buffer, MAX_PACKET_SIZE);
      if (res.is_error())
      {
        std::stringstream str;
        str << "Failed to receive frame : " << res.error_message();
        throw NetworkError(str.str());
      }

      buffer_in = std::vector<uint8_t>(buffer, buffer + res.value());

      return res.value();
    }

};

} /* namespace BICYCL */

#endif /* BICYCL_NETWORK_HELPER_HPP */
