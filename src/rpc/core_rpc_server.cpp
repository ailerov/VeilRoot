// Copyright (c) 2014-2022, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <boost/preprocessor/stringize.hpp>
#include <boost/uuid/nil_generator.hpp>
#include <boost/filesystem.hpp>
#include "include_base_utils.h"
#include "string_tools.h"
using namespace epee;

#include "core_rpc_server.h"
#include "common/command_line.h"
#include "common/updates.h"
#include "common/download.h"
#include "common/util.h"
#include "common/perf_timer.h"
#include "int-util.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/merge_mining.h"
#include "cryptonote_core/tx_sanity_check.h"
#include "misc_language.h"
#include "net/local_ip.h"
#include "net/parse.h"
#include "storages/http_abstract_invoke.h"
#include "crypto/hash.h"
#include "rpc/rpc_args.h"
#include "rpc/rpc_handler.h"
#include "rpc/rpc_payment_costs.h"
#include "rpc/rpc_payment_signature.h"
#include "core_rpc_server_error_codes.h"
#include "p2p/net_node.h"
#include "version.h"
#include "cryptonote_core/nostr_client.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "common/bip340.h"
#include "common/domain_utils.h"
#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <array>
#include <algorithm>
#include "governance/vote_proof.h"
#include "ringct/rctSigs.h"
#include "cryptonote_config.h"
#include "ringct/bulletproofs_plus.h"
#include "governance/vote_proof_verifier.h"
#include "governance/governance.h"
#include "governance/domain_policy.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon.rpc"

#define MAX_RESTRICTED_FAKE_OUTS_COUNT 40
#define MAX_RESTRICTED_GLOBAL_FAKE_OUTS_COUNT 5000

#define OUTPUT_HISTOGRAM_RECENT_CUTOFF_RESTRICTION (3 * 86400) // 3 days max, the wallet requests 1.8 days

#define DEFAULT_PAYMENT_DIFFICULTY 1000
#define DEFAULT_PAYMENT_CREDITS_PER_HASH 100

#define RESTRICTED_BLOCK_HEADER_RANGE 1000
#define RESTRICTED_TRANSACTIONS_COUNT 100
#define RESTRICTED_SPENT_KEY_IMAGES_COUNT 5000
#define RESTRICTED_BLOCK_COUNT 1000

#define RPC_TRACKER(rpc) \
  PERF_TIMER(rpc); \
  RPCTracker tracker(#rpc, PERF_TIMER_NAME(rpc))

namespace
{
  class RPCTracker
  {
  public:
    struct entry_t
    {
      uint64_t count;
      uint64_t time;
      uint64_t credits;
    };

    RPCTracker(const char *rpc, tools::LoggingPerformanceTimer &timer): rpc(rpc), timer(timer) {
    }
    ~RPCTracker() {
      try
      {
        boost::unique_lock<boost::mutex> lock(mutex);
        auto &e = tracker[rpc];
        ++e.count;
        e.time += timer.value();
      }
      catch (...) { /* ignore */ }
    }
    void pay(uint64_t amount) {
      boost::unique_lock<boost::mutex> lock(mutex);
      auto &e = tracker[rpc];
      e.credits += amount;
    }
    const std::string &rpc_name() const { return rpc; }
    static void clear() { boost::unique_lock<boost::mutex> lock(mutex); tracker.clear(); }
    static std::unordered_map<std::string, entry_t> data() { boost::unique_lock<boost::mutex> lock(mutex); return tracker; }
  private:
    std::string rpc;
    tools::LoggingPerformanceTimer &timer;
    static boost::mutex mutex;
    static std::unordered_map<std::string, entry_t> tracker;
  };
  boost::mutex RPCTracker::mutex;
  std::unordered_map<std::string, RPCTracker::entry_t> RPCTracker::tracker;

  void add_reason(std::string &reasons, const char *reason)
  {
    if (!reasons.empty())
      reasons += ", ";
    reasons += reason;
  }

 // Helper to check if a 33‑byte key is null (all zeros)
 static inline bool is_null_key(const std::array<unsigned char, 33>& key) {
     return std::all_of(key.begin(), key.end(), [](unsigned char c) { return c == 0; });
 }

  uint64_t round_up(uint64_t value, uint64_t quantum)
  {
    return (value + quantum - 1) / quantum * quantum;
  }

  void store_128(boost::multiprecision::uint128_t value, uint64_t &slow64, std::string &swide, uint64_t &stop64)
  {
    slow64 = (value & 0xffffffffffffffff).convert_to<uint64_t>();
    swide = cryptonote::hex(value);
    stop64 = ((value >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
  }

  void store_difficulty(cryptonote::difficulty_type difficulty, uint64_t &sdiff, std::string &swdiff, uint64_t &stop64)
  {
    store_128(difficulty, sdiff, swdiff, stop64);
  }
}

namespace cryptonote
{

  //-----------------------------------------------------------------------------------
  void core_rpc_server::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_rpc_bind_port);
    command_line::add_arg(desc, arg_rpc_restricted_bind_port);
    command_line::add_arg(desc, arg_restricted_rpc);
    command_line::add_arg(desc, arg_bootstrap_daemon_address);
    command_line::add_arg(desc, arg_bootstrap_daemon_login);
    command_line::add_arg(desc, arg_bootstrap_daemon_proxy);
    cryptonote::rpc_args::init_options(desc, true);
    command_line::add_arg(desc, arg_rpc_payment_address);
    command_line::add_arg(desc, arg_rpc_payment_difficulty);
    command_line::add_arg(desc, arg_rpc_payment_credits);
    command_line::add_arg(desc, arg_rpc_payment_allow_free_loopback);
    command_line::add_arg(desc, arg_rpc_max_connections_per_public_ip);
    command_line::add_arg(desc, arg_rpc_max_connections_per_private_ip);
    command_line::add_arg(desc, arg_rpc_max_connections);
    command_line::add_arg(desc, arg_rpc_response_soft_limit);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  core_rpc_server::core_rpc_server(
      core& cr
    , nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& p2p
    )
    : m_core(cr)
    , m_p2p(p2p)
    , m_was_bootstrap_ever_used(false)
    , disable_rpc_ban(false)
    , m_rpc_payment_allow_free_loopback(false)
  {}
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::set_bootstrap_daemon(
    const std::string &address,
    const std::string &username_password,
    const std::string &proxy)
  {
    boost::optional<epee::net_utils::http::login> credentials;
    const auto loc = username_password.find(':');
    if (loc != std::string::npos)
    {
      credentials = epee::net_utils::http::login(username_password.substr(0, loc), username_password.substr(loc + 1));
    }
    return set_bootstrap_daemon(address, credentials, proxy);
  }
  //------------------------------------------------------------------------------------------------------------------------------
  std::map<std::string, bool> core_rpc_server::get_public_nodes(uint32_t credits_per_hash_threshold/* = 0*/)
  {
    COMMAND_RPC_GET_PUBLIC_NODES::request request;
    COMMAND_RPC_GET_PUBLIC_NODES::response response;

    request.gray = true;
    request.white = true;
    request.include_blocked = false;
    if (!on_get_public_nodes(request, response) || response.status != CORE_RPC_STATUS_OK)
    {
      return {};
    }

    std::map<std::string, bool> result;

    const auto append = [&result, &credits_per_hash_threshold](const std::vector<public_node> &nodes, bool white) {
      for (const auto &node : nodes)
      {
        const bool rpc_payment_enabled = credits_per_hash_threshold > 0;
        const bool node_rpc_payment_enabled = node.rpc_credits_per_hash > 0;
        if (!node_rpc_payment_enabled ||
            (rpc_payment_enabled && node.rpc_credits_per_hash >= credits_per_hash_threshold))
        {
          result.insert(std::make_pair(node.host + ":" + std::to_string(node.rpc_port), white));
        }
      }
    };

    append(response.white, true);
    append(response.gray, false);

    return result;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::set_bootstrap_daemon(
    const std::string &address,
    const boost::optional<epee::net_utils::http::login> &credentials,
    const std::string &proxy)
  {
    boost::unique_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);

    constexpr const uint32_t credits_per_hash_threshold = 0;
    constexpr const bool rpc_payment_enabled = credits_per_hash_threshold != 0;

    if (address.empty())
    {
      m_bootstrap_daemon.reset(nullptr);
    }
    else if (address == "auto")
    {
      auto get_nodes = [this]() {
        return get_public_nodes(credits_per_hash_threshold);
      };
      m_bootstrap_daemon.reset(new bootstrap_daemon(std::move(get_nodes), rpc_payment_enabled, m_bootstrap_daemon_proxy.empty() ? proxy : m_bootstrap_daemon_proxy));
    }
    else
    {
      m_bootstrap_daemon.reset(new bootstrap_daemon(address, credentials, rpc_payment_enabled, m_bootstrap_daemon_proxy.empty() ? proxy : m_bootstrap_daemon_proxy));
    }

    m_should_use_bootstrap_daemon = m_bootstrap_daemon.get() != nullptr;

    return true;
  }
  core_rpc_server::~core_rpc_server()
  {
    if (m_rpc_payment)
      m_rpc_payment->store();
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::init(
      const boost::program_options::variables_map& vm
      , const bool restricted
      , const std::string& port
      , bool allow_rpc_payment
      , const std::string& proxy
    )
  {
    m_bootstrap_daemon_proxy = proxy;
    m_restricted = restricted;
    m_net_server.set_threads_prefix("RPC");
    m_net_server.set_connection_filter(&m_p2p);

    auto rpc_config = cryptonote::rpc_args::process(vm, true);
    if (!rpc_config)
      return false;

    std::string bind_ip_str = rpc_config->bind_ip;
    std::string bind_ipv6_str = rpc_config->bind_ipv6_address;
    if (restricted)
    {
      const auto restricted_rpc_port_arg = cryptonote::core_rpc_server::arg_rpc_restricted_bind_port;
      const bool has_restricted_rpc_port_arg = !command_line::is_arg_defaulted(vm, restricted_rpc_port_arg);
      if (has_restricted_rpc_port_arg && port == command_line::get_arg(vm, restricted_rpc_port_arg))
      {
        bind_ip_str = rpc_config->restricted_bind_ip;
        bind_ipv6_str = rpc_config->restricted_bind_ipv6_address;
      }
    }
    disable_rpc_ban = rpc_config->disable_rpc_ban;
    const std::string data_dir{command_line::get_arg(vm, cryptonote::arg_data_dir)};
    std::string address = command_line::get_arg(vm, arg_rpc_payment_address);
    if (!address.empty() && allow_rpc_payment)
    {
      if (!m_restricted && nettype() != FAKECHAIN)
      {
        MFATAL("RPC payment enabled, but server is not restricted, anyone can adjust their balance to bypass payment");
        return false;
      }
      cryptonote::address_parse_info info;
      if (!get_account_address_from_str(info, nettype(), address))
      {
        MFATAL("Invalid payment address: " << address);
        return false;
      }
      if (info.is_subaddress)
      {
        MFATAL("Payment address may not be a subaddress: " << address);
        return false;
      }
      uint64_t diff = command_line::get_arg(vm, arg_rpc_payment_difficulty);
      uint64_t credits = command_line::get_arg(vm, arg_rpc_payment_credits);
      if (diff == 0 || credits == 0)
      {
        MFATAL("Payments difficulty and/or payments credits are 0, but a payment address was given");
        return false;
      }
      m_rpc_payment_allow_free_loopback = command_line::get_arg(vm, arg_rpc_payment_allow_free_loopback);
      m_rpc_payment.reset(new rpc_payment(info.address, diff, credits));
      m_rpc_payment->load(data_dir);
      m_p2p.set_rpc_credits_per_hash(RPC_CREDITS_PER_HASH_SCALE * (credits / (float)diff));
    }

    if (!m_rpc_payment)
    {
      uint32_t bind_ip;
      bool ok = epee::string_tools::get_ip_int32_from_string(bind_ip, bind_ip_str);
      if (ok & !epee::net_utils::is_ip_loopback(bind_ip))
        MWARNING("The RPC server is accessible from the outside, but no RPC payment was setup. RPC access will be free for all.");
    }

    if (!set_bootstrap_daemon(
          command_line::get_arg(vm, arg_bootstrap_daemon_address),
          command_line::get_arg(vm, arg_bootstrap_daemon_login),
          command_line::get_arg(vm, arg_bootstrap_daemon_proxy)))
    {
      MFATAL("Failed to parse bootstrap daemon address");
      return false;
    }

    boost::optional<epee::net_utils::http::login> http_login{};

    if (rpc_config->login)
      http_login.emplace(std::move(rpc_config->login->username), std::move(rpc_config->login->password).password());

    if (m_rpc_payment)
      m_net_server.add_idle_handler([this](){ return m_rpc_payment->on_idle(); }, 60 * 1000);

    bool store_ssl_key = !restricted && rpc_config->ssl_options && rpc_config->ssl_options.auth.certificate_path.empty();
    const auto ssl_base_path = (boost::filesystem::path{data_dir} / "rpc_ssl").string();
    const bool ssl_cert_file_exists = boost::filesystem::exists(ssl_base_path + ".crt");
    const bool ssl_pkey_file_exists = boost::filesystem::exists(ssl_base_path + ".key");
    if (store_ssl_key)
    {
      // .key files are often given different read permissions as their corresponding .crt files.
      // Consequently, sometimes the .key file wont't get copied, while the .crt file will.
      if (ssl_cert_file_exists != ssl_pkey_file_exists)
      {
        MFATAL("Certificate (.crt) and private key (.key) files must both exist or both not exist at path: " << ssl_base_path);
        return false;
      }
      else if (ssl_cert_file_exists) { // and ssl_pkey_file_exists
        // load key from previous run, password prompted by OpenSSL
        store_ssl_key = false;
        rpc_config->ssl_options.auth =
          epee::net_utils::ssl_authentication_t{ssl_base_path + ".key", ssl_base_path + ".crt"};
      }
    }

    const auto max_connections_public = command_line::get_arg(vm, arg_rpc_max_connections_per_public_ip);
    const auto max_connections_private = command_line::get_arg(vm, arg_rpc_max_connections_per_private_ip);
    const auto max_connections = command_line::get_arg(vm, arg_rpc_max_connections);

    if (max_connections < max_connections_public)
    {
      MFATAL(arg_rpc_max_connections_per_public_ip.name << " is bigger than " << arg_rpc_max_connections.name);
      return false;
    }
    if (max_connections < max_connections_private)
    {
      MFATAL(arg_rpc_max_connections_per_private_ip.name << " is bigger than " << arg_rpc_max_connections.name);
      return false;
    }

    auto rng = [](size_t len, uint8_t *ptr){ return crypto::rand(len, ptr); };
    const bool inited = epee::http_server_impl_base<core_rpc_server, connection_context>::init(
      rng, std::move(port), std::move(bind_ip_str),
      std::move(bind_ipv6_str), std::move(rpc_config->use_ipv6), std::move(rpc_config->require_ipv4),
      std::move(rpc_config->access_control_origins), std::move(http_login), std::move(rpc_config->ssl_options),
      max_connections_public, max_connections_private, max_connections,
      command_line::get_arg(vm, arg_rpc_response_soft_limit)
    );

    m_net_server.get_config_object().m_max_content_length = MAX_RPC_CONTENT_LENGTH;

    if (store_ssl_key && inited)
    {
      // new keys were generated, store for next run
      const auto error = epee::net_utils::store_ssl_keys(m_net_server.get_ssl_context(), ssl_base_path);
      if (error)
        MFATAL("Failed to store HTTP SSL cert/key for " << (restricted ? "restricted " : "") << "RPC server: " << error.message());
      return !bool(error);
    }
    return inited;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::check_payment(const std::string &client_message, uint64_t payment, const std::string &rpc, bool same_ts, std::string &message, uint64_t &credits, std::string &top_hash)
  {
    if (m_rpc_payment == NULL)
    {
      credits = 0;
      return true;
    }
    uint64_t height;
    crypto::hash hash;
    m_core.get_blockchain_top(height, hash);
    top_hash = epee::string_tools::pod_to_hex(hash);
    crypto::public_key client;
    uint64_t ts;
#ifndef NDEBUG
    if (nettype() == TESTNET && client_message == "debug")
    {
      credits = 0;
      return true;
    }
#endif
    if (!cryptonote::verify_rpc_payment_signature(client_message, client, ts))
    {
      credits = 0;
      message = "Client signature does not verify for " + rpc;
      return false;
    }
    if (!m_rpc_payment->pay(client, ts, payment, rpc, same_ts, credits))
    {
      message = CORE_RPC_STATUS_PAYMENT_REQUIRED;
      return false;
    }
    return true;
  }
#define CHECK_PAYMENT_BASE(req, res, payment, same_ts) do { if (!ctx) break; uint64_t P = (uint64_t)payment; if (P > 0 && !check_payment(req.client, P, tracker.rpc_name(), same_ts, res.status, res.credits, res.top_hash)){return true;} tracker.pay(P); } while(0)
#define CHECK_PAYMENT(req, res, payment) CHECK_PAYMENT_BASE(req, res, payment, false)
#define CHECK_PAYMENT_SAME_TS(req, res, payment) CHECK_PAYMENT_BASE(req, res, payment, true)
#define CHECK_PAYMENT_MIN1(req, res, payment, same_ts) do { if (!ctx || (m_rpc_payment_allow_free_loopback && ctx->m_remote_address.is_loopback())) break; uint64_t P = (uint64_t)payment; if (P == 0) P = 1; if(!check_payment(req.client, P, tracker.rpc_name(), same_ts, res.status, res.credits, res.top_hash)){return true;} tracker.pay(P); } while(0)
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::check_core_ready()
  {
    if(!m_p2p.get_payload_object().is_synchronized())
    {
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::add_host_fail(const connection_context *ctx, unsigned int score)
  {
    if(!ctx || !ctx->m_remote_address.is_blockable() || disable_rpc_ban)
      return false;

    CRITICAL_REGION_LOCAL(m_host_fails_score_lock);
    uint64_t fails = m_host_fails_score[ctx->m_remote_address.host_str()] += score;
    MDEBUG("Host " << ctx->m_remote_address.host_str() << " fail score=" << fails);
    if(fails > RPC_IP_FAILS_BEFORE_BLOCK)
    {
      auto it = m_host_fails_score.find(ctx->m_remote_address.host_str());
      CHECK_AND_ASSERT_MES(it != m_host_fails_score.end(), false, "internal error");
      it->second = RPC_IP_FAILS_BEFORE_BLOCK/2;
      m_p2p.block_host(ctx->m_remote_address);
    }
    return true;
  }
#define CHECK_CORE_READY() do { if(!check_core_ready()){res.status =  CORE_RPC_STATUS_BUSY;return true;} } while(0)

  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_height(const COMMAND_RPC_GET_HEIGHT::request& req, COMMAND_RPC_GET_HEIGHT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_height);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_HEIGHT>(invoke_http_mode::JON, "/getheight", req, res, r))
      return r;

    crypto::hash hash;
    m_core.get_blockchain_top(res.height, hash);
    ++res.height; // block height to chain height
    res.hash = string_tools::pod_to_hex(hash);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_info(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_info);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_INFO>(invoke_http_mode::JON, "/getinfo", req, res, r))
    {
      {
        boost::shared_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
        if (m_bootstrap_daemon.get() != nullptr)
        {
          res.bootstrap_daemon_address = m_bootstrap_daemon->address();
        }
      }
      crypto::hash top_hash;
      m_core.get_blockchain_top(res.height_without_bootstrap, top_hash);
      ++res.height_without_bootstrap; // turn top block height into blockchain height
      res.was_bootstrap_ever_used = true;
      return r;
    }

    CHECK_PAYMENT_MIN1(req, res, COST_PER_GET_INFO, false);

    const bool restricted = m_restricted && ctx;

    crypto::hash top_hash;
    m_core.get_blockchain_top(res.height, top_hash);
    ++res.height; // turn top block height into blockchain height
    res.top_block_hash = string_tools::pod_to_hex(top_hash);
    res.target_height = m_p2p.get_payload_object().is_synchronized() ? 0 : m_core.get_target_blockchain_height();
    store_difficulty(m_core.get_blockchain_storage().get_difficulty_for_next_block(), res.difficulty, res.wide_difficulty, res.difficulty_top64);
    res.target = m_core.get_blockchain_storage().get_difficulty_target();
    res.tx_count = m_core.get_blockchain_storage().get_total_transactions() - res.height; //without coinbase
    res.tx_pool_size = m_core.get_pool_transactions_count(!restricted);
    res.alt_blocks_count = restricted ? 0 : m_core.get_blockchain_storage().get_alternative_blocks_count();
    res.outgoing_connections_count = restricted ? 0 : m_p2p.get_all_outgoing_connections_count();
    res.incoming_connections_count = restricted ? 0 : m_p2p.get_all_incoming_connections_count();
    res.rpc_connections_count = restricted ? 0 : get_connections_count();
    res.white_peerlist_size = restricted ? 0 : m_p2p.get_public_white_peers_count();
    res.grey_peerlist_size = restricted ? 0 : m_p2p.get_public_gray_peers_count();

    cryptonote::network_type net_type = nettype();
    res.mainnet = net_type == MAINNET;
    res.testnet = net_type == TESTNET;
    res.stagenet = net_type == STAGENET;
    res.nettype = net_type == MAINNET ? "mainnet" : net_type == TESTNET ? "testnet" : net_type == STAGENET ? "stagenet" : "fakechain";
    store_difficulty(m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(res.height - 1),
        res.cumulative_difficulty, res.wide_cumulative_difficulty, res.cumulative_difficulty_top64);
    res.block_size_limit = res.block_weight_limit = m_core.get_blockchain_storage().get_current_cumulative_block_weight_limit();
    res.block_size_median = res.block_weight_median = m_core.get_blockchain_storage().get_current_cumulative_block_weight_median();
    res.adjusted_time = m_core.get_blockchain_storage().get_adjusted_time(res.height);

    res.start_time = restricted ? 0 : (uint64_t)m_core.get_start_time();
    res.free_space = restricted ? std::numeric_limits<uint64_t>::max() : m_core.get_free_space();
    res.offline = m_core.offline();
    res.height_without_bootstrap = restricted ? 0 : res.height;
    if (restricted)
    {
      res.bootstrap_daemon_address = "";
      res.was_bootstrap_ever_used = false;
    }
    else
    {
      boost::shared_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
      if (m_bootstrap_daemon.get() != nullptr)
      {
        res.bootstrap_daemon_address = m_bootstrap_daemon->address();
      }
      res.was_bootstrap_ever_used = m_was_bootstrap_ever_used;
    }
    res.database_size = m_core.get_blockchain_storage().get_db().get_database_size();
    if (restricted)
      res.database_size = round_up(res.database_size, 5ull* 1024 * 1024 * 1024);
    res.update_available = restricted ? false : m_core.is_update_available();
    res.version = restricted ? "" : MONERO_VERSION_FULL;
    res.synchronized = check_core_ready();
    res.busy_syncing = m_p2p.get_payload_object().is_busy_syncing();
    res.restricted = restricted;

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_net_stats(const COMMAND_RPC_GET_NET_STATS::request& req, COMMAND_RPC_GET_NET_STATS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_net_stats);
    // No bootstrap daemon check: Only ever get stats about local server
    res.start_time = (uint64_t)m_core.get_start_time();
    {
      CRITICAL_REGION_LOCAL(epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_in);
      epee::net_utils::network_throttle_manager::get_global_throttle_in().get_stats(res.total_packets_in, res.total_bytes_in);
    }
    {
      CRITICAL_REGION_LOCAL(epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_out);
      epee::net_utils::network_throttle_manager::get_global_throttle_out().get_stats(res.total_packets_out, res.total_bytes_out);
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  class pruned_transaction {
    transaction& tx;
  public:
    pruned_transaction(transaction& tx) : tx(tx) {}
    BEGIN_SERIALIZE_OBJECT()
      bool r = tx.serialize_base(ar);
      if (!r) return false;
    END_SERIALIZE()
  };
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& req, COMMAND_RPC_GET_BLOCKS_FAST::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_blocks);

    bool use_bootstrap_daemon;
    {
      boost::shared_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
      use_bootstrap_daemon = m_should_use_bootstrap_daemon;
    }
    if (use_bootstrap_daemon)
    {
      bool r;
      return use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BLOCKS_FAST>(invoke_http_mode::BIN, "/getblocks.bin", req, res, r);
    }

    CHECK_PAYMENT(req, res, 1);

    res.daemon_time = (uint64_t)time(NULL);
    // Always set daemon time, and set it early rather than late, as delivering some incremental pool
    // info twice because of slightly overlapping time intervals is no problem, whereas producing gaps
    // and never delivering something is

    bool get_blocks = false;
    bool get_pool = false;
    switch (req.requested_info)
    {
      case COMMAND_RPC_GET_BLOCKS_FAST::BLOCKS_ONLY:
        // Compatibility value 0: Clients that do not set 'requested_info' want blocks, and only blocks
        get_blocks = true;
        break;
      case COMMAND_RPC_GET_BLOCKS_FAST::BLOCKS_AND_POOL:
        get_blocks = true;
        get_pool = true;
        break;
      case COMMAND_RPC_GET_BLOCKS_FAST::POOL_ONLY:
        get_pool = true;
        break;
      default:
        res.status = "Failed, wrong requested info";
        return true;
    }

    res.pool_info_extent = COMMAND_RPC_GET_BLOCKS_FAST::NONE;

    if (get_pool)
    {
      const bool restricted = m_restricted && ctx;
      const bool request_has_rpc_origin = ctx != NULL;
      const bool allow_sensitive = !request_has_rpc_origin || !restricted;
      const size_t max_tx_count = restricted ? RESTRICTED_TRANSACTIONS_COUNT : std::numeric_limits<size_t>::max();

      bool incremental;
      std::vector<std::pair<crypto::hash, tx_memory_pool::tx_details>> added_pool_txs;
      bool success = m_core.get_pool_info((time_t)req.pool_info_since, allow_sensitive, max_tx_count, added_pool_txs, res.remaining_added_pool_txids, res.removed_pool_txids, incremental);
      if (success)
      {
        res.added_pool_txs.clear();
        if (m_rpc_payment)
        {
          CHECK_PAYMENT_SAME_TS(req, res, added_pool_txs.size() * COST_PER_TX + (res.remaining_added_pool_txids.size() + res.removed_pool_txids.size()) * COST_PER_POOL_HASH);
        }
        for (const auto &added_pool_tx: added_pool_txs)
        {
          COMMAND_RPC_GET_BLOCKS_FAST::pool_tx_info info;
          info.tx_hash = added_pool_tx.first;
          std::stringstream oss;
          binary_archive<true> ar(oss);
          bool r = req.prune
            ? const_cast<cryptonote::transaction&>(added_pool_tx.second.tx).serialize_base(ar)
            : ::serialization::serialize(ar, const_cast<cryptonote::transaction&>(added_pool_tx.second.tx));
          if (!r)
          {
            res.status = "Failed to serialize transaction";
            return true;
          }
          info.tx_blob = oss.str();
          info.double_spend_seen = added_pool_tx.second.double_spend_seen;
          res.added_pool_txs.push_back(std::move(info));
        }
      }
      if (success)
      {
        res.pool_info_extent = incremental ? COMMAND_RPC_GET_BLOCKS_FAST::INCREMENTAL : COMMAND_RPC_GET_BLOCKS_FAST::FULL;
      }
      else
      {
        res.status = "Failed to get pool info";
        return true;
      }
    }

    if (get_blocks)
    {
      // quick check for noop
      if (!req.block_ids.empty())
      {
        uint64_t last_block_height;
        crypto::hash last_block_hash;
        m_core.get_blockchain_top(last_block_height, last_block_hash);
        if (last_block_hash == req.block_ids.front())
        {
          res.start_height = 0;
          res.current_height = last_block_height + 1;
          res.status = CORE_RPC_STATUS_OK;
          return true;
        }
      }

      size_t max_blocks = req.max_block_count > 0
        ? std::min(req.max_block_count, (uint64_t)COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT)
        : COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT;

      if (m_rpc_payment)
      {
        max_blocks = std::min((size_t)(res.credits / COST_PER_BLOCK), max_blocks);
        if (max_blocks == 0)
        {
          res.status = CORE_RPC_STATUS_PAYMENT_REQUIRED;
          return true;
        }
      }

      std::vector<std::pair<std::pair<cryptonote::blobdata, crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::blobdata> > > > bs;
      if(!m_core.find_blockchain_supplement(req.start_height, req.block_ids, bs, res.current_height, res.start_height, req.prune, !req.no_miner_tx, max_blocks, COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT))
      {
        res.status = "Failed";
        add_host_fail(ctx);
        return true;
      }

      CHECK_PAYMENT_SAME_TS(req, res, bs.size() * COST_PER_BLOCK);

      size_t size = 0, ntxes = 0;
      res.blocks.reserve(bs.size());
      res.output_indices.reserve(bs.size());
      for(auto& bd: bs)
      {
        res.blocks.resize(res.blocks.size()+1);
        res.blocks.back().pruned = req.prune;
        res.blocks.back().block = bd.first.first;
        size += bd.first.first.size();
        res.output_indices.push_back(COMMAND_RPC_GET_BLOCKS_FAST::block_output_indices());
        ntxes += bd.second.size();
        res.output_indices.back().indices.reserve(1 + bd.second.size());
        if (req.no_miner_tx)
          res.output_indices.back().indices.push_back(COMMAND_RPC_GET_BLOCKS_FAST::tx_output_indices());
        res.blocks.back().txs.reserve(bd.second.size());
        for (std::vector<std::pair<crypto::hash, cryptonote::blobdata>>::iterator i = bd.second.begin(); i != bd.second.end(); ++i)
        {
          res.blocks.back().txs.push_back({std::move(i->second), crypto::null_hash});
          i->second.clear();
          i->second.shrink_to_fit();
          size += res.blocks.back().txs.back().blob.size();
        }

        const size_t n_txes_to_lookup = bd.second.size() + (req.no_miner_tx ? 0 : 1);
        if (n_txes_to_lookup > 0)
        {
          std::vector<std::vector<uint64_t>> indices;
          bool r = m_core.get_tx_outputs_gindexs(req.no_miner_tx ? bd.second.front().first : bd.first.second, n_txes_to_lookup, indices);
          if (!r)
          {
            res.status = "Failed";
            return true;
          }
          if (indices.size() != n_txes_to_lookup || res.output_indices.back().indices.size() != (req.no_miner_tx ? 1 : 0))
          {
            res.status = "Failed";
            return true;
          }
          for (size_t i = 0; i < indices.size(); ++i)
            res.output_indices.back().indices.push_back({std::move(indices[i])});
        }
      }
      MDEBUG("on_get_blocks: " << bs.size() << " blocks, " << ntxes << " txes, size " << size);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
    bool core_rpc_server::on_get_alt_blocks_hashes(const COMMAND_RPC_GET_ALT_BLOCKS_HASHES::request& req, COMMAND_RPC_GET_ALT_BLOCKS_HASHES::response& res, const connection_context *ctx)
    {
      RPC_TRACKER(get_alt_blocks_hashes);
      bool r;
      if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_ALT_BLOCKS_HASHES>(invoke_http_mode::JON, "/get_alt_blocks_hashes", req, res, r))
        return r;

      std::vector<block> blks;

      if(!m_core.get_alternative_blocks(blks))
      {
          res.status = "Failed";
          return true;
      }

      res.blks_hashes.reserve(blks.size());

      for (auto const& blk: blks)
      {
          res.blks_hashes.push_back(epee::string_tools::pod_to_hex(get_block_hash(blk)));
      }

      MDEBUG("on_get_alt_blocks_hashes: " << blks.size() << " blocks " );
      res.status = CORE_RPC_STATUS_OK;
      return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_blocks_by_height(const COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_blocks_by_height);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BLOCKS_BY_HEIGHT>(invoke_http_mode::BIN, "/getblocks_by_height.bin", req, res, r))
      return r;

    const bool restricted = m_restricted && ctx;
    if (restricted && req.heights.size() > RESTRICTED_BLOCK_COUNT)
    {
      res.status = "Too many blocks requested in restricted mode";
      return true;
    }

    res.status = "Failed";
    res.blocks.clear();
    res.blocks.reserve(req.heights.size());
    CHECK_PAYMENT_MIN1(req, res, req.heights.size() * COST_PER_BLOCK, false);
    for (uint64_t height : req.heights)
    {
      block blk;
      try
      {
        blk = m_core.get_blockchain_storage().get_db().get_block_from_height(height);
      }
      catch (...)
      {
        res.status = "Error retrieving block at height " + std::to_string(height);
        return true;
      }
      std::vector<transaction> txs;
      std::vector<crypto::hash> missed_txs;
      m_core.get_transactions(blk.tx_hashes, txs, missed_txs);
      res.blocks.resize(res.blocks.size() + 1);
      res.blocks.back().block = block_to_blob(blk);
      for (auto& tx : txs)
        res.blocks.back().txs.push_back({tx_to_blob(tx), crypto::null_hash});
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_hashes(const COMMAND_RPC_GET_HASHES_FAST::request& req, COMMAND_RPC_GET_HASHES_FAST::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_hashes);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_HASHES_FAST>(invoke_http_mode::BIN, "/gethashes.bin", req, res, r))
      return r;

    CHECK_PAYMENT(req, res, 1);

    res.start_height = req.start_height;
    if(!m_core.get_blockchain_storage().find_blockchain_supplement(req.block_ids, res.m_block_ids, NULL, res.start_height, res.current_height, false))
    {
      res.status = "Failed";
      add_host_fail(ctx);
      return true;
    }

    CHECK_PAYMENT_SAME_TS(req, res, res.m_block_ids.size() * COST_PER_BLOCK_HASH);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_outs_bin(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_outs_bin);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_OUTPUTS_BIN>(invoke_http_mode::BIN, "/get_outs.bin", req, res, r))
      return r;

    CHECK_PAYMENT_MIN1(req, res, req.outputs.size() * COST_PER_OUT, false);

    res.status = "Failed";

    const bool restricted = m_restricted && ctx;
    if (restricted)
    {
      if (req.outputs.size() > MAX_RESTRICTED_GLOBAL_FAKE_OUTS_COUNT)
      {
        res.status = "Too many outs requested";
        return true;
      }
    }

    if(!m_core.get_outs(req, res))
    {
      return true;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_outs(const COMMAND_RPC_GET_OUTPUTS::request& req, COMMAND_RPC_GET_OUTPUTS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_outs);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_OUTPUTS>(invoke_http_mode::JON, "/get_outs", req, res, r))
      return r;

    CHECK_PAYMENT_MIN1(req, res, req.outputs.size() * COST_PER_OUT, false);

    res.status = "Failed";

    const bool restricted = m_restricted && ctx;
    if (restricted)
    {
      if (req.outputs.size() > MAX_RESTRICTED_GLOBAL_FAKE_OUTS_COUNT)
      {
        res.status = "Too many outs requested";
        return true;
      }
    }

    cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::request req_bin;
    req_bin.outputs = req.outputs;
    req_bin.get_txid = req.get_txid;
    cryptonote::COMMAND_RPC_GET_OUTPUTS_BIN::response res_bin;
    if(!m_core.get_outs(req_bin, res_bin))
    {
      return true;
    }

    // convert to text
    for (const auto &i: res_bin.outs)
    {
      res.outs.push_back(cryptonote::COMMAND_RPC_GET_OUTPUTS::outkey());
      cryptonote::COMMAND_RPC_GET_OUTPUTS::outkey &outkey = res.outs.back();
      outkey.key = epee::string_tools::pod_to_hex(i.key);
      outkey.mask = epee::string_tools::pod_to_hex(i.mask);
      outkey.unlocked = i.unlocked;
      outkey.height = i.height;
      if (req.get_txid)
        outkey.txid = epee::string_tools::pod_to_hex(i.txid);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& req, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_indexes);
    bool ok;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(invoke_http_mode::BIN, "/get_o_indexes.bin", req, res, ok))
      return ok;

    CHECK_PAYMENT_MIN1(req, res, COST_PER_OUTPUT_INDEXES, false);

    bool r = m_core.get_tx_outputs_gindexs(req.txid, res.o_indexes);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    LOG_PRINT_L2("COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES: [" << res.o_indexes.size() << "]");
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& req, COMMAND_RPC_GET_TRANSACTIONS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transactions);
    bool ok;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TRANSACTIONS>(invoke_http_mode::JON, "/gettransactions", req, res, ok))
      return ok;

    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;

    if (restricted && req.txs_hashes.size() > RESTRICTED_TRANSACTIONS_COUNT)
    {
      res.status = "Too many transactions requested in restricted mode";
      return true;
    }

    CHECK_PAYMENT_MIN1(req, res, req.txs_hashes.size() * COST_PER_TX, false);

    std::vector<crypto::hash> vh;
    for(const auto& tx_hex_str: req.txs_hashes)
    {
      blobdata b;
      if(!string_tools::parse_hexstr_to_binbuff(tx_hex_str, b))
      {
        res.status = "Failed to parse hex representation of transaction hash";
        return true;
      }
      if(b.size() != sizeof(crypto::hash))
      {
        res.status = "Failed, size of data mismatch";
        return true;
      }
      vh.push_back(*reinterpret_cast<const crypto::hash*>(b.data()));
    }
    std::vector<crypto::hash> missed_txs;
    std::vector<std::tuple<crypto::hash, cryptonote::blobdata, crypto::hash, cryptonote::blobdata>> txs;
    bool r = m_core.get_split_transactions_blobs(vh, txs, missed_txs);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    LOG_PRINT_L2("Found " << txs.size() << "/" << vh.size() << " transactions on the blockchain");

    // try the pool for any missing txes
    size_t found_in_pool = 0;
    std::unordered_set<crypto::hash> pool_tx_hashes;
    std::unordered_map<crypto::hash, tx_memory_pool::tx_details> per_tx_pool_tx_details;
    if (!missed_txs.empty())
    {
      std::vector<std::pair<crypto::hash, tx_memory_pool::tx_details>> pool_txs;
      bool r = m_core.get_pool_transactions_info(missed_txs, pool_txs, !request_has_rpc_origin || !restricted);
      if(r)
      {
        // sort to match original request
        std::vector<std::tuple<crypto::hash, cryptonote::blobdata, crypto::hash, cryptonote::blobdata>> sorted_txs;
        std::vector<std::pair<crypto::hash, tx_memory_pool::tx_details>>::const_iterator i;
        unsigned txs_processed = 0;
        for (const crypto::hash &h: vh)
        {
          if (std::find(missed_txs.begin(), missed_txs.end(), h) == missed_txs.end())
          {
            if (txs.size() == txs_processed)
            {
              res.status = "Failed: internal error - txs is empty";
              return true;
            }
            // core returns the ones it finds in the right order
            if (std::get<0>(txs[txs_processed]) != h)
            {
              res.status = "Failed: tx hash mismatch";
              return true;
            }
            sorted_txs.push_back(std::move(txs[txs_processed]));
            ++txs_processed;
          }
          else if ((i = std::find_if(pool_txs.begin(), pool_txs.end(), [h](const std::pair<crypto::hash, tx_memory_pool::tx_details> &pt) { return h == pt.first; })) != pool_txs.end())
          {
            const tx_memory_pool::tx_details &td = i->second;
            std::stringstream ss;
            binary_archive<true> ba(ss);
            bool r = const_cast<cryptonote::transaction&>(td.tx).serialize_base(ba);
            if (!r)
            {
              res.status = "Failed to serialize transaction base";
              return true;
            }
            const cryptonote::blobdata pruned = ss.str();
            const crypto::hash prunable_hash = td.tx.version == 1 ? crypto::null_hash : get_transaction_prunable_hash(td.tx);
            sorted_txs.push_back(std::make_tuple(h, pruned, prunable_hash, std::string(td.tx_blob, pruned.size())));
            missed_txs.erase(std::find(missed_txs.begin(), missed_txs.end(), h));
            pool_tx_hashes.insert(h);
            per_tx_pool_tx_details.insert(std::make_pair(h, td));
            ++found_in_pool;
          }
        }
        txs = sorted_txs;
      }
      LOG_PRINT_L2("Found " << found_in_pool << "/" << vh.size() << " transactions in the pool");
    }

    CHECK_AND_ASSERT_MES(txs.size() + missed_txs.size() == vh.size(), false, "mismatched number of txs");

    auto txhi = req.txs_hashes.cbegin();
    auto vhi = vh.cbegin();
    auto missedi = missed_txs.cbegin();

    for(auto& tx: txs)
    {
      res.txs.push_back(COMMAND_RPC_GET_TRANSACTIONS::entry());
      COMMAND_RPC_GET_TRANSACTIONS::entry &e = res.txs.back();

      while (missedi != missed_txs.end() && *missedi == *vhi)
      {
          ++vhi;
          ++txhi;
          ++missedi;
      }

      crypto::hash tx_hash = *vhi++;
      CHECK_AND_ASSERT_MES(tx_hash == std::get<0>(tx), false, "mismatched tx hash");
      e.tx_hash = *txhi++;
      e.prunable_hash = epee::string_tools::pod_to_hex(std::get<2>(tx));
      if (req.split || req.prune || std::get<3>(tx).empty())
      {
        // use splitted form with pruned and prunable (filled only when prune=false and the daemon has it), leaving as_hex as empty
        e.pruned_as_hex = string_tools::buff_to_hex_nodelimer(std::get<1>(tx));
        if (!req.prune)
          e.prunable_as_hex = string_tools::buff_to_hex_nodelimer(std::get<3>(tx));
        if (req.decode_as_json)
        {
          cryptonote::blobdata tx_data;
          cryptonote::transaction t;
          if (req.prune || std::get<3>(tx).empty())
          {
            // decode pruned tx to JSON
            tx_data = std::get<1>(tx);
            if (cryptonote::parse_and_validate_tx_base_from_blob(tx_data, t))
            {
              pruned_transaction pruned_tx{t};
              e.as_json = obj_to_json_str(pruned_tx);
            }
            else
            {
              res.status = "Failed to parse and validate pruned tx from blob";
              return true;
            }
          }
          else
          {
            // decode full tx to JSON
            tx_data = std::get<1>(tx) + std::get<3>(tx);
            if (cryptonote::parse_and_validate_tx_from_blob(tx_data, t))
            {
              e.as_json = obj_to_json_str(t);
            }
            else
            {
              res.status = "Failed to parse and validate tx from blob";
              return true;
            }
          }
        }
      }
      else
      {
        // use non-splitted form, leaving pruned_as_hex and prunable_as_hex as empty
        cryptonote::blobdata tx_data = std::get<1>(tx) + std::get<3>(tx);
        e.as_hex = string_tools::buff_to_hex_nodelimer(tx_data);
        if (req.decode_as_json)
        {
          cryptonote::transaction t;
          if (cryptonote::parse_and_validate_tx_from_blob(tx_data, t))
          {
            e.as_json = obj_to_json_str(t);
          }
          else
          {
            res.status = "Failed to parse and validate tx from blob";
            return true;
          }
        }
      }
      e.in_pool = pool_tx_hashes.find(tx_hash) != pool_tx_hashes.end();
      if (e.in_pool)
      {
        e.block_height = e.block_timestamp = std::numeric_limits<uint64_t>::max();
        e.confirmations = 0;
        auto it = per_tx_pool_tx_details.find(tx_hash);
        if (it != per_tx_pool_tx_details.end())
        {
          e.double_spend_seen = it->second.double_spend_seen;
          e.relayed = it->second.relayed;
          e.received_timestamp = it->second.receive_time;
        }
        else
        {
          MERROR("Failed to determine pool info for " << tx_hash);
          e.double_spend_seen = false;
          e.relayed = false;
          e.received_timestamp = 0;
        }
      }
      else
      {
        e.block_height = m_core.get_blockchain_storage().get_db().get_tx_block_height(tx_hash);
        e.confirmations = m_core.get_current_blockchain_height() - e.block_height;
        e.block_timestamp = m_core.get_blockchain_storage().get_db().get_block_timestamp(e.block_height);
        e.received_timestamp = 0;
        e.double_spend_seen = false;
        e.relayed = false;
      }

      // fill up old style responses too, in case an old wallet asks
      res.txs_as_hex.push_back(e.as_hex);
      if (req.decode_as_json)
        res.txs_as_json.push_back(e.as_json);

      // output indices too if not in pool
      if (pool_tx_hashes.find(tx_hash) == pool_tx_hashes.end())
      {
        bool r = m_core.get_tx_outputs_gindexs(tx_hash, e.output_indices);
        if (!r)
        {
          res.status = "Failed";
          return true;
        }
      }
    }

    for(const auto& miss_tx: missed_txs)
    {
      res.missed_tx.push_back(string_tools::pod_to_hex(miss_tx));
    }

    LOG_PRINT_L2(res.txs.size() << " transactions found, " << res.missed_tx.size() << " not found");
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_is_key_image_spent(const COMMAND_RPC_IS_KEY_IMAGE_SPENT::request& req, COMMAND_RPC_IS_KEY_IMAGE_SPENT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(is_key_image_spent);
    bool ok;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_IS_KEY_IMAGE_SPENT>(invoke_http_mode::JON, "/is_key_image_spent", req, res, ok))
      return ok;

    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;

    if (restricted && req.key_images.size() > RESTRICTED_SPENT_KEY_IMAGES_COUNT)
    {
      res.status = "Too many key images queried in restricted mode";
      return true;
    }

    CHECK_PAYMENT_MIN1(req, res, req.key_images.size() * COST_PER_KEY_IMAGE, false);

    std::vector<crypto::key_image> key_images;
    for(const auto& ki_hex_str: req.key_images)
    {
      blobdata b;
      if(!string_tools::parse_hexstr_to_binbuff(ki_hex_str, b))
      {
        res.status = "Failed to parse hex representation of key image";
        return true;
      }
      if(b.size() != sizeof(crypto::key_image))
      {
        res.status = "Failed, size of data mismatch";
        return true;
      }
      key_images.emplace_back();
      crypto::key_image &ki = key_images.back();
      memcpy(&ki, b.data(), sizeof(crypto::key_image));
    }
    std::vector<bool> spent_status;
    bool r = m_core.are_key_images_spent(key_images, spent_status);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    res.spent_status.clear();
    for (size_t n = 0; n < spent_status.size(); ++n)
      res.spent_status.push_back(spent_status[n] ? COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_BLOCKCHAIN : COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT);

    // check the pool too
    std::vector<cryptonote::tx_info> txs;
    std::vector<cryptonote::spent_key_image_info> ki;
    r = m_core.get_pool_transactions_and_spent_keys_info(txs, ki, !request_has_rpc_origin || !restricted);
    if(!r)
    {
      res.status = "Failed";
      return true;
    }
    for (std::vector<cryptonote::spent_key_image_info>::const_iterator i = ki.begin(); i != ki.end(); ++i)
    {
      crypto::hash hash;
      crypto::key_image spent_key_image;
      if (parse_hash256(i->id_hash, hash))
      {
        memcpy(&spent_key_image, &hash, sizeof(hash)); // a bit dodgy, should be other parse functions somewhere
        for (size_t n = 0; n < res.spent_status.size(); ++n)
        {
          if (res.spent_status[n] == COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT)
          {
            if (key_images[n] == spent_key_image)
            {
              res.spent_status[n] = COMMAND_RPC_IS_KEY_IMAGE_SPENT::SPENT_IN_POOL;
              break;
            }
          }
        }
      }
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  // BEGIN_VNS_ELIGIBLE
bool core_rpc_server::on_send_raw_tx_json(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
  return on_send_raw_tx(req, res, ctx);
}
// END_VNS_ELIGIBLE
  bool core_rpc_server::on_send_raw_tx(const COMMAND_RPC_SEND_RAW_TX::request& req, COMMAND_RPC_SEND_RAW_TX::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(send_raw_tx);

    {
      bool ok;
      use_bootstrap_daemon_if_necessary<COMMAND_RPC_SEND_RAW_TX>(invoke_http_mode::JON, "/sendrawtransaction", req, res, ok);
    }

    const bool restricted = m_restricted && ctx;

    bool skip_validation = false;
    if (!restricted)
    {
      boost::shared_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
      if (m_should_use_bootstrap_daemon)
      {
        skip_validation = !check_core_ready();
      }
      else
      {
        CHECK_CORE_READY();
      }
    }
    else
    {
      CHECK_CORE_READY();
    }

    CHECK_PAYMENT_MIN1(req, res, COST_PER_TX_RELAY, false);

    std::string tx_blob;
    if(!string_tools::parse_hexstr_to_binbuff(req.tx_as_hex, tx_blob))
    {
      LOG_PRINT_L0("[on_send_raw_tx]: Failed to parse tx from hexbuff: " << req.tx_as_hex);
      res.status = "Failed";
      return true;
    }

    if (req.do_sanity_checks && !cryptonote::tx_sanity_check(tx_blob, m_core.get_blockchain_storage().get_num_mature_outputs(0)))
    {
      res.status = "Failed";
      res.reason = "Sanity check failed";
      res.sanity_check_failed = true;
      return true;
    }
    res.sanity_check_failed = false;

    if (!skip_validation)
    {
      tx_verification_context tvc{};
      if(!m_core.handle_incoming_tx(tx_blob, tvc, (req.do_not_relay ? relay_method::none : relay_method::local), false) || tvc.m_verifivation_failed)
      {
        res.status = "Failed";
        std::string reason = "";
        if ((res.low_mixin = tvc.m_low_mixin))
          add_reason(reason, "bad ring size");
        if ((res.double_spend = tvc.m_double_spend))
          add_reason(reason, "double spend");
        if ((res.invalid_input = tvc.m_invalid_input))
          add_reason(reason, "invalid input");
        if ((res.invalid_output = tvc.m_invalid_output))
          add_reason(reason, "invalid output");
        if ((res.too_big = tvc.m_too_big))
          add_reason(reason, "too big");
        if ((res.overspend = tvc.m_overspend))
          add_reason(reason, "overspend");
        if ((res.fee_too_low = tvc.m_fee_too_low))
          add_reason(reason, "fee too low");
        if ((res.too_few_outputs = tvc.m_too_few_outputs))
          add_reason(reason, "too few outputs");
        if ((res.tx_extra_too_big = tvc.m_tx_extra_too_big))
          add_reason(reason, "tx-extra too big");
        if ((res.nonzero_unlock_time = tvc.m_nonzero_unlock_time))
          add_reason(reason, "tx unlock time is not zero");
        if ((res.domain_already_registered = tvc.m_domain_already_registered))
          add_reason(reason, "domain already registered");

        // BEGIN_VNS_FALLBACK_VOTE_PERIOD_CHECK
        if (reason.empty())
        {
            cryptonote::transaction tx;
            if (cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx))
            {
                uint64_t current_height = m_core.get_blockchain_storage().get_current_blockchain_height();
                cryptonote::vote_result vres = m_core.get_blockchain_storage().governance().process_vote(tx, current_height, true);
                if (vres == cryptonote::vote_result::voting_period_closed)
                {
                    reason = "voting period ended";
                    res.vote_period_ended = true;
                }
            }
        }
        // END_VNS_FALLBACK_VOTE_PERIOD_CHECK

        res.reason = reason;
          LOG_PRINT_L0("TX REJECTED: " << reason << " (flags: low_mixin=" << tvc.m_low_mixin
            << ", double_spend=" << tvc.m_double_spend
            << ", invalid_input=" << tvc.m_invalid_input
            << ", invalid_output=" << tvc.m_invalid_output
            << ", too_big=" << tvc.m_too_big
            << ", overspend=" << tvc.m_overspend
            << ", fee_too_low=" << tvc.m_fee_too_low
            << ", too_few_outputs=" << tvc.m_too_few_outputs
            << ", tx_extra_too_big=" << tvc.m_tx_extra_too_big
            << ", nonzero_unlock_time=" << tvc.m_nonzero_unlock_time
            << ", domain_already_registered=" << tvc.m_domain_already_registered
            << ", vote_period_ended=" << tvc.m_vote_period_ended << ")");
            // Print reason via MERROR to always show in console
        MERROR("TX rejected: " << (reason.empty() ? "unknown reason" : reason)
               << " (flags: low_mixin=" << tvc.m_low_mixin
               << ", double_spend=" << tvc.m_double_spend
               << ", invalid_input=" << tvc.m_invalid_input
               << ", invalid_output=" << tvc.m_invalid_output
               << ", too_big=" << tvc.m_too_big
               << ", overspend=" << tvc.m_overspend
               << ", fee_too_low=" << tvc.m_fee_too_low
               << ", too_few_outputs=" << tvc.m_too_few_outputs
               << ", tx_extra_too_big=" << tvc.m_tx_extra_too_big
               << ", nonzero_unlock_time=" << tvc.m_nonzero_unlock_time
               << ", domain_already_registered=" << tvc.m_domain_already_registered
               << ", vote_period_ended=" << tvc.m_vote_period_ended << ")");
        const std::string punctuation = reason.empty() ? "" : ": ";
        if (tvc.m_verifivation_failed)
        {
          LOG_PRINT_L0("[on_send_raw_tx]: tx verification failed" << punctuation << reason);
        }
        else
        {
          LOG_PRINT_L0("[on_send_raw_tx]: Failed to process tx" << punctuation << reason);
        }
        return true;
      }

      if(tvc.m_relay == relay_method::none)
      {
        LOG_PRINT_L0("[on_send_raw_tx]: tx accepted, but not relayed");
        res.reason = "Not relayed";
        res.not_relayed = true;
        res.status = CORE_RPC_STATUS_OK;
        return true;
      }
    }

    NOTIFY_NEW_TRANSACTIONS::request r;
    r.txs.push_back(std::move(tx_blob));
    m_core.get_protocol()->relay_transactions(r, boost::uuids::nil_uuid(), epee::net_utils::zone::invalid, relay_method::local);
    //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_start_mining(const COMMAND_RPC_START_MINING::request& req, COMMAND_RPC_START_MINING::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(start_mining);
    CHECK_CORE_READY();
    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, nettype(), req.miner_address))
    {
      res.status = "Failed, wrong address";
      LOG_PRINT_L0(res.status);
      return true;
    }
    if (info.is_subaddress)
    {
      res.status = "Mining to subaddress isn't supported yet";
      LOG_PRINT_L0(res.status);
      return true;
    }

    unsigned int concurrency_count = boost::thread::hardware_concurrency() * 4;

    // if we couldn't detect threads, set it to a ridiculously high number
    if(concurrency_count == 0)
    {
      concurrency_count = 257;
    }

    // if there are more threads requested than the hardware supports
    // then we fail and log that.
    if(req.threads_count > concurrency_count)
    {
      res.status = "Failed, too many threads relative to CPU cores.";
      LOG_PRINT_L0(res.status);
      return true;
    }

    cryptonote::miner &miner= m_core.get_miner();
    if (miner.is_mining())
    {
      res.status = "Already mining";
      return true;
    }
    if(!miner.start(info.address, static_cast<size_t>(req.threads_count), req.do_background_mining, req.ignore_battery))
    {
      res.status = "Failed, mining not started";
      LOG_PRINT_L0(res.status);
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_stop_mining(const COMMAND_RPC_STOP_MINING::request& req, COMMAND_RPC_STOP_MINING::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(stop_mining);
    cryptonote::miner &miner= m_core.get_miner();
    if(!miner.is_mining())
    {
      res.status = "Mining never started";
      LOG_PRINT_L0(res.status);
      return true;
    }
    if(!miner.stop())
    {
      res.status = "Failed, mining not stopped";
      LOG_PRINT_L0(res.status);
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_mining_status(const COMMAND_RPC_MINING_STATUS::request& req, COMMAND_RPC_MINING_STATUS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(mining_status);

    const miner& lMiner = m_core.get_miner();
    res.active = lMiner.is_mining();
    res.is_background_mining_enabled = lMiner.get_is_background_mining_enabled();
    store_difficulty(m_core.get_blockchain_storage().get_difficulty_for_next_block(), res.difficulty, res.wide_difficulty, res.difficulty_top64);
    
    res.block_target = m_core.get_blockchain_storage().get_current_hard_fork_version() < HF_VERSION_MIN_MIXIN_4 ? DIFFICULTY_TARGET_V1 : DIFFICULTY_TARGET_V2;
    if ( lMiner.is_mining() ) {
      res.speed = lMiner.get_speed();
      res.threads_count = lMiner.get_threads_count();
      res.block_reward = lMiner.get_block_reward();
    }
    const account_public_address& lMiningAdr = lMiner.get_mining_address();
    if (lMiner.is_mining() || lMiner.get_is_background_mining_enabled())
      res.address = get_account_address_as_str(nettype(), false, lMiningAdr);
    const uint8_t major_version = m_core.get_blockchain_storage().get_current_hard_fork_version();
    const unsigned variant = major_version >= 7 ? major_version - 6 : 0;
    switch (variant)
    {
      case 0: res.pow_algorithm = "Cryptonight"; break;
      case 1: res.pow_algorithm = "CNv1 (Cryptonight variant 1)"; break;
      case 2: case 3: res.pow_algorithm = "CNv2 (Cryptonight variant 2)"; break;
      case 4: case 5: res.pow_algorithm = "CNv4 (Cryptonight variant 4)"; break;
      case 6: case 7: case 8: case 9: res.pow_algorithm = "RandomX"; break;
      default: res.pow_algorithm = "RandomX"; break; // assumed
    }
    if (res.is_background_mining_enabled)
    {
      res.bg_idle_threshold = lMiner.get_idle_threshold();
      res.bg_min_idle_seconds = lMiner.get_min_idle_seconds();
      res.bg_ignore_battery = lMiner.get_ignore_battery();
      res.bg_target = lMiner.get_mining_target();
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_save_bc(const COMMAND_RPC_SAVE_BC::request& req, COMMAND_RPC_SAVE_BC::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(save_bc);
    if( !m_core.get_blockchain_storage().store_blockchain() )
    {
      res.status = "Error while storing blockchain";
      return true;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_peer_list(const COMMAND_RPC_GET_PEER_LIST::request& req, COMMAND_RPC_GET_PEER_LIST::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_peer_list);
    std::vector<nodetool::peerlist_entry> white_list;
    std::vector<nodetool::peerlist_entry> gray_list;

    if (req.public_only)
    {
      m_p2p.get_public_peerlist(gray_list, white_list);
    }
    else
    {
      m_p2p.get_peerlist(gray_list, white_list);
    }

    for (auto & entry : white_list)
    {
      if (!req.include_blocked && m_p2p.is_host_blocked(entry.adr, NULL))
        continue;
      if (entry.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
        res.white_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv4_network_address>().ip(),
            entry.adr.as<epee::net_utils::ipv4_network_address>().port(), entry.last_seen, entry.pruning_seed, entry.rpc_port, entry.rpc_credits_per_hash);
      else if (entry.adr.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
        res.white_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv6_network_address>().host_str(),
            entry.adr.as<epee::net_utils::ipv6_network_address>().port(), entry.last_seen, entry.pruning_seed, entry.rpc_port, entry.rpc_credits_per_hash);
      else
        res.white_list.emplace_back(entry.id, entry.adr.str(), entry.last_seen, entry.pruning_seed, entry.rpc_port, entry.rpc_credits_per_hash);
    }

    for (auto & entry : gray_list)
    {
      if (!req.include_blocked && m_p2p.is_host_blocked(entry.adr, NULL))
        continue;
      if (entry.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
        res.gray_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv4_network_address>().ip(),
            entry.adr.as<epee::net_utils::ipv4_network_address>().port(), entry.last_seen, entry.pruning_seed, entry.rpc_port, entry.rpc_credits_per_hash);
      else if (entry.adr.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id())
        res.gray_list.emplace_back(entry.id, entry.adr.as<epee::net_utils::ipv6_network_address>().host_str(),
            entry.adr.as<epee::net_utils::ipv6_network_address>().port(), entry.last_seen, entry.pruning_seed, entry.rpc_port, entry.rpc_credits_per_hash);
      else
        res.gray_list.emplace_back(entry.id, entry.adr.str(), entry.last_seen, entry.pruning_seed, entry.rpc_port, entry.rpc_credits_per_hash);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_public_nodes(const COMMAND_RPC_GET_PUBLIC_NODES::request& req, COMMAND_RPC_GET_PUBLIC_NODES::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_public_nodes);

    COMMAND_RPC_GET_PEER_LIST::request peer_list_req;
    COMMAND_RPC_GET_PEER_LIST::response peer_list_res;
    peer_list_req.include_blocked = req.include_blocked;
    const bool success = on_get_peer_list(peer_list_req, peer_list_res, ctx);
    res.status = peer_list_res.status;
    if (!success)
    {      
      res.status = "Failed to get peer list";
      return true;
    }
    if (res.status != CORE_RPC_STATUS_OK)
    {
      return true;
    }

    const auto collect = [](const std::vector<peer> &peer_list, std::vector<public_node> &public_nodes)
    {
      for (const auto &entry : peer_list)
      {
        if (entry.rpc_port != 0)
        {
          public_nodes.emplace_back(entry);
        }
      }
    };

    if (req.white)
    {
      collect(peer_list_res.white_list, res.white);
    }
    if (req.gray)
    {
      collect(peer_list_res.gray_list, res.gray);
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_hash_rate(const COMMAND_RPC_SET_LOG_HASH_RATE::request& req, COMMAND_RPC_SET_LOG_HASH_RATE::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(set_log_hash_rate);
    if(m_core.get_miner().is_mining())
    {
      m_core.get_miner().do_print_hashrate(req.visible);
      res.status = CORE_RPC_STATUS_OK;
    }
    else
    {
      res.status = CORE_RPC_STATUS_NOT_MINING;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_level(const COMMAND_RPC_SET_LOG_LEVEL::request& req, COMMAND_RPC_SET_LOG_LEVEL::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(set_log_level);
    if (req.level < 0 || req.level > 4)
    {
      res.status = "Error: log level not valid";
      return true;
    }
    mlog_set_log_level(req.level);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_log_categories(const COMMAND_RPC_SET_LOG_CATEGORIES::request& req, COMMAND_RPC_SET_LOG_CATEGORIES::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(set_log_categories);
    mlog_set_log(req.categories.c_str());
    res.categories = mlog_get_categories();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool(const COMMAND_RPC_GET_TRANSACTION_POOL::request& req, COMMAND_RPC_GET_TRANSACTION_POOL::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transaction_pool);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TRANSACTION_POOL>(invoke_http_mode::JON, "/get_transaction_pool", req, res, r))
      return r;

    CHECK_PAYMENT(req, res, 1);

    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;
    const bool allow_sensitive = !request_has_rpc_origin || !restricted;

    size_t n_txes = m_core.get_pool_transactions_count(allow_sensitive);
    if (n_txes > 0)
    {
      CHECK_PAYMENT_SAME_TS(req, res, n_txes * COST_PER_TX);
      m_core.get_pool_transactions_and_spent_keys_info(res.transactions, res.spent_key_images, allow_sensitive);
      for (tx_info& txi : res.transactions)
        txi.tx_blob = epee::string_tools::buff_to_hex_nodelimer(txi.tx_blob);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool_hashes_bin(const COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transaction_pool_hashes);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TRANSACTION_POOL_HASHES_BIN>(invoke_http_mode::JON, "/get_transaction_pool_hashes.bin", req, res, r))
      return r;

    CHECK_PAYMENT(req, res, 1);

    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;
    const bool allow_sensitive = !request_has_rpc_origin || !restricted;

    size_t n_txes = m_core.get_pool_transactions_count(allow_sensitive);
    if (n_txes > 0)
    {
      CHECK_PAYMENT_SAME_TS(req, res, n_txes * COST_PER_POOL_HASH);
      m_core.get_pool_transaction_hashes(res.tx_hashes, allow_sensitive);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool_hashes(const COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_HASHES::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transaction_pool_hashes);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TRANSACTION_POOL_HASHES>(invoke_http_mode::JON, "/get_transaction_pool_hashes", req, res, r))
      return r;

    CHECK_PAYMENT(req, res, 1);

    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;
    const bool allow_sensitive = !request_has_rpc_origin || !restricted;

    size_t n_txes = m_core.get_pool_transactions_count(allow_sensitive);
    if (n_txes > 0)
    {
      CHECK_PAYMENT_SAME_TS(req, res, n_txes * COST_PER_POOL_HASH);
      std::vector<crypto::hash> tx_hashes;
      m_core.get_pool_transaction_hashes(tx_hashes, allow_sensitive);
      res.tx_hashes.reserve(tx_hashes.size());
      for (const crypto::hash &tx_hash: tx_hashes)
        res.tx_hashes.push_back(epee::string_tools::pod_to_hex(tx_hash));
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_transaction_pool_stats(const COMMAND_RPC_GET_TRANSACTION_POOL_STATS::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_STATS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_transaction_pool_stats);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TRANSACTION_POOL_STATS>(invoke_http_mode::JON, "/get_transaction_pool_stats", req, res, r))
      return r;

    CHECK_PAYMENT_MIN1(req, res, COST_PER_TX_POOL_STATS, false);

    const bool restricted = m_restricted && ctx;
    const bool request_has_rpc_origin = ctx != NULL;
    m_core.get_pool_transaction_stats(res.pool_stats, !request_has_rpc_origin || !restricted);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_bootstrap_daemon(const COMMAND_RPC_SET_BOOTSTRAP_DAEMON::request& req, COMMAND_RPC_SET_BOOTSTRAP_DAEMON::response& res, const connection_context *ctx)
  {
    PERF_TIMER(on_set_bootstrap_daemon);

    boost::optional<epee::net_utils::http::login> credentials;
    if (!req.username.empty() || !req.password.empty())
    {
      credentials = epee::net_utils::http::login(req.username, req.password);
    }

    if (set_bootstrap_daemon(req.address, credentials, req.proxy))
    {
      res.status = CORE_RPC_STATUS_OK;
    }
    else
    {
      res.status = "Failed to set bootstrap daemon";
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& req, COMMAND_RPC_STOP_DAEMON::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(stop_daemon);
    // FIXME: replace back to original m_p2p.send_stop_signal() after
    // investigating why that isn't working quite right.
    m_p2p.send_stop_signal();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_getblockcount(const COMMAND_RPC_GETBLOCKCOUNT::request& req, COMMAND_RPC_GETBLOCKCOUNT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(getblockcount);
    {
      boost::shared_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
      if (m_should_use_bootstrap_daemon)
      {
        res.status = "This command is unsupported for bootstrap daemon";
        return true;
      }
    }
    res.count = m_core.get_current_blockchain_height();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_getblockhash(const COMMAND_RPC_GETBLOCKHASH::request& req, COMMAND_RPC_GETBLOCKHASH::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(getblockhash);
    {
      boost::shared_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
      if (m_should_use_bootstrap_daemon)
      {
        res = "This command is unsupported for bootstrap daemon";
        return true;
      }
    }
    if(req.size() != 1)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Wrong parameters, expected height";
      return false;
    }
    uint64_t h = req[0];
    if(m_core.get_current_blockchain_height() <= h)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
      error_resp.message = std::string("Requested block height: ") + std::to_string(h) + " greater than current top block height: " +  std::to_string(m_core.get_current_blockchain_height() - 1);
      return false;
    }
    res = string_tools::pod_to_hex(m_core.get_block_id_by_height(h));
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  // equivalent of strstr, but with arbitrary bytes (ie, NULs)
  // This does not differentiate between "not found" and "found at offset 0"
  size_t slow_memmem(const void* start_buff, size_t buflen,const void* pat,size_t patlen)
  {
    const void* buf = start_buff;
    const void* end=(const char*)buf+buflen;
    if (patlen > buflen || patlen == 0) return 0;
    while(buflen>0 && (buf=memchr(buf,((const char*)pat)[0],buflen-patlen+1)))
    {
      if(memcmp(buf,pat,patlen)==0)
        return (const char*)buf - (const char*)start_buff;
      buf=(const char*)buf+1;
      buflen = (const char*)end - (const char*)buf;
    }
    return 0;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::get_block_template(const account_public_address &address, const crypto::hash *prev_block, const cryptonote::blobdata &extra_nonce, size_t &reserved_offset, cryptonote::difficulty_type  &difficulty, uint64_t &height, uint64_t &expected_reward, block &b, uint64_t &seed_height, crypto::hash &seed_hash, crypto::hash &next_seed_hash, epee::json_rpc::error &error_resp)
  {
    b = boost::value_initialized<cryptonote::block>();
    if(!m_core.get_block_template(b, prev_block, address, difficulty, height, expected_reward, extra_nonce, seed_height, seed_hash))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to create block template");
      return false;
    }
    blobdata block_blob = t_serializable_object_to_blob(b);
    crypto::public_key tx_pub_key = cryptonote::get_tx_pub_key_from_extra(b.miner_tx);
    if(tx_pub_key == crypto::null_pkey)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to get tx pub key in coinbase extra");
      return false;
    }

    uint64_t next_height;
    crypto::rx_seedheights(height, &seed_height, &next_height);
    if (next_height != seed_height)
      next_seed_hash = m_core.get_block_id_by_height(next_height);
    else
      next_seed_hash = seed_hash;

    if (extra_nonce.empty())
    {
      reserved_offset = 0;
      return true;
    }

    reserved_offset = slow_memmem((void*)block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key));
    if(!reserved_offset)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to find tx pub key in blockblob");
      return false;
    }
    reserved_offset += sizeof(tx_pub_key) + 2; //2 bytes: tag for TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
    if(reserved_offset + extra_nonce.size() > block_blob.size())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to create block template";
      LOG_ERROR("Failed to calculate offset for ");
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_getblocktemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& req, COMMAND_RPC_GETBLOCKTEMPLATE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(getblocktemplate);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GETBLOCKTEMPLATE>(invoke_http_mode::JON_RPC, "getblocktemplate", req, res, r))
      return r;

    if(!check_core_ready())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_CORE_BUSY;
      error_resp.message = "Core is busy";
      return false;
    }

    if(req.reserve_size > 255)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE;
      error_resp.message = "Too big reserved size, maximum 255";
      return false;
    }

    if(req.reserve_size && !req.extra_nonce.empty())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Cannot specify both a reserve_size and an extra_nonce";
      return false;
    }

    if(req.extra_nonce.size() > 510)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE;
      error_resp.message = "Too big extra_nonce size, maximum 510 hex chars";
      return false;
    }

    cryptonote::address_parse_info info;

    if(!req.wallet_address.size() || !cryptonote::get_account_address_from_str(info, nettype(), req.wallet_address))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_WALLET_ADDRESS;
      error_resp.message = "Failed to parse wallet address";
      return false;
    }
    if (info.is_subaddress)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_MINING_TO_SUBADDRESS;
      error_resp.message = "Mining to subaddress is not supported yet";
      return false;
    }

    block b;
    cryptonote::blobdata blob_reserve;
    size_t reserved_offset;
    if(!req.extra_nonce.empty())
    {
      if(!string_tools::parse_hexstr_to_binbuff(req.extra_nonce, blob_reserve))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Parameter extra_nonce should be a hex string";
        return false;
      }
    }
    else
      blob_reserve.resize(req.reserve_size, 0);
    cryptonote::difficulty_type wdiff;
    crypto::hash prev_block;
    if (!req.prev_block.empty())
    {
      if (!epee::string_tools::hex_to_pod(req.prev_block, prev_block))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Invalid prev_block";
        return false;
      }
    }
    crypto::hash seed_hash, next_seed_hash;
    if (!get_block_template(info.address, req.prev_block.empty() ? NULL : &prev_block, blob_reserve, reserved_offset, wdiff, res.height, res.expected_reward, b, res.seed_height, seed_hash, next_seed_hash, error_resp))
      return false;
    if (b.major_version >= RX_BLOCK_VERSION)
    {
      res.seed_hash = string_tools::pod_to_hex(seed_hash);
      if (seed_hash != next_seed_hash)
        res.next_seed_hash = string_tools::pod_to_hex(next_seed_hash);
    }

    res.reserved_offset = reserved_offset;
    store_difficulty(wdiff, res.difficulty, res.wide_difficulty, res.difficulty_top64);
    blobdata block_blob = t_serializable_object_to_blob(b);
    blobdata hashing_blob = get_block_hashing_blob(b);
    res.prev_hash = string_tools::pod_to_hex(b.prev_id);
    res.blocktemplate_blob = string_tools::buff_to_hex_nodelimer(block_blob);
    res.blockhashing_blob =  string_tools::buff_to_hex_nodelimer(hashing_blob);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_getminerdata(const COMMAND_RPC_GETMINERDATA::request& req, COMMAND_RPC_GETMINERDATA::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    if(!check_core_ready())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_CORE_BUSY;
      error_resp.message = "Core is busy";
      return false;
    }

    crypto::hash prev_id, seed_hash;
    difficulty_type difficulty;

    std::vector<tx_block_template_backlog_entry> tx_backlog;
    if (!m_core.get_miner_data(res.major_version, res.height, prev_id, seed_hash, difficulty, res.median_weight, res.already_generated_coins, tx_backlog))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: failed to get miner data";
      LOG_ERROR("Failed to get miner data");
      return false;
    }

    res.tx_backlog.clear();
    res.tx_backlog.reserve(tx_backlog.size());

    for (const auto& entry : tx_backlog)
    {
      res.tx_backlog.emplace_back(COMMAND_RPC_GETMINERDATA::response::tx_backlog_entry{string_tools::pod_to_hex(entry.id), entry.weight, entry.fee});
    }

    res.prev_id = string_tools::pod_to_hex(prev_id);
    res.seed_hash = string_tools::pod_to_hex(seed_hash);
    res.difficulty = cryptonote::hex(difficulty);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_calcpow(const COMMAND_RPC_CALCPOW::request& req, COMMAND_RPC_CALCPOW::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(calcpow);

    blobdata blockblob;
    if(!string_tools::parse_hexstr_to_binbuff(req.block_blob, blockblob))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
      error_resp.message = "Wrong block blob";
      return false;
    }
    if(!m_core.check_incoming_block_size(blockblob))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE;
      error_resp.message = "Block blob size is too big, rejecting block";
      return false;
    }
    crypto::hash seed_hash, pow_hash;
    std::string buf;
    if(req.seed_hash.size())
    {
      if (!string_tools::parse_hexstr_to_binbuff(req.seed_hash, buf) ||
        buf.size() != sizeof(crypto::hash))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Wrong seed hash";
        return false;
      }
      buf.copy(reinterpret_cast<char *>(&seed_hash), sizeof(crypto::hash));
    }

    cryptonote::get_block_longhash(&(m_core.get_blockchain_storage()), blockblob, pow_hash, req.height,
      req.major_version, req.seed_hash.size() ? &seed_hash : NULL, 0);
    res = string_tools::pod_to_hex(pow_hash);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_add_aux_pow(const COMMAND_RPC_ADD_AUX_POW::request& req, COMMAND_RPC_ADD_AUX_POW::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(add_aux_pow);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_ADD_AUX_POW>(invoke_http_mode::JON_RPC, "add_aux_pow", req, res, r))
      return r;

    const bool restricted = m_restricted && ctx;

    if (restricted && req.aux_pow.size() > 10)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_RESTRICTED;
      error_resp.message = "Too many aux pow hashes";
      return false;
    }

    if (req.aux_pow.empty())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Empty aux pow hash vector";
      return false;
    }

    crypto::hash merkle_root;
    size_t merkle_tree_depth = 0;
    std::vector<std::pair<crypto::hash, crypto::hash>> aux_pow;
    std::vector<crypto::hash> aux_pow_raw;
    aux_pow.reserve(req.aux_pow.size());
    aux_pow_raw.reserve(req.aux_pow.size());
    for (const auto &s: req.aux_pow)
    {
      aux_pow.push_back({});
      if (!epee::string_tools::hex_to_pod(s.id, aux_pow.back().first))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid aux pow id";
        return false;
      }
      if (!epee::string_tools::hex_to_pod(s.hash, aux_pow.back().second))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid aux pow hash";
        return false;
      }
      aux_pow_raw.push_back(aux_pow.back().second);
    }

    size_t path_domain = 1;
    while ((1u << path_domain) < aux_pow.size())
      ++path_domain;
    uint32_t nonce;
    const uint32_t max_nonce = restricted ? 16384 : 65535;
    bool collision = true;
    for (nonce = 0; nonce <= max_nonce; ++nonce)
    {
      std::vector<bool> slots(aux_pow.size(), false);
      collision = false;
      for (size_t idx = 0; idx < aux_pow.size(); ++idx)
      {
        const uint32_t slot = cryptonote::get_aux_slot(aux_pow[idx].first, nonce, aux_pow.size());
        if (slot >= aux_pow.size())
        {
          error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
          error_resp.message = "Computed slot is out of range";
          return false;
        }
        if (slots[slot])
        {
          collision = true;
          break;
        }
        slots[slot] = true;
      }
      if (!collision)
        break;
    }
    if (collision)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to find a suitable nonce";
      return false;
    }

    crypto::tree_hash((const char(*)[crypto::HASH_SIZE])aux_pow_raw.data(), aux_pow_raw.size(), merkle_root.data);
    res.merkle_root = epee::string_tools::pod_to_hex(merkle_root);
    res.merkle_tree_depth = cryptonote::encode_mm_depth(aux_pow.size(), nonce);

    blobdata blocktemplate_blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.blocktemplate_blob, blocktemplate_blob))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Invalid blocktemplate_blob";
      return false;
    }

    block b;
    if (!parse_and_validate_block_from_blob(blocktemplate_blob, b))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
      error_resp.message = "Wrong blocktemplate_blob";
      return false;
    }

    if (!remove_field_from_tx_extra(b.miner_tx.extra, typeid(cryptonote::tx_extra_merge_mining_tag)))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Error removing existing merkle root";
      return false;
    }
    if (!add_mm_merkle_root_to_tx_extra(b.miner_tx.extra, merkle_root, merkle_tree_depth))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Error adding merkle root";
      return false;
    }
    b.invalidate_hashes();
    b.miner_tx.invalidate_hashes();

    const blobdata block_blob = t_serializable_object_to_blob(b);
    const blobdata hashing_blob = get_block_hashing_blob(b);

    res.blocktemplate_blob = string_tools::buff_to_hex_nodelimer(block_blob);
    res.blockhashing_blob = string_tools::buff_to_hex_nodelimer(hashing_blob);
    res.aux_pow = req.aux_pow;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_submitblock(const COMMAND_RPC_SUBMITBLOCK::request& req, COMMAND_RPC_SUBMITBLOCK::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(submitblock);
    {
      boost::shared_lock<boost::shared_mutex> lock(m_bootstrap_daemon_mutex);
      if (m_should_use_bootstrap_daemon)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_UNSUPPORTED_BOOTSTRAP;
        error_resp.message = "This command is unsupported for bootstrap daemon";
        return false;
      }
    }
    CHECK_CORE_READY();
    if(req.size()!=1)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Wrong param";
      return false;
    }
    blobdata blockblob;
    if(!string_tools::parse_hexstr_to_binbuff(req[0], blockblob))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
      error_resp.message = "Wrong block blob";
      return false;
    }
    
    // Fixing of high orphan issue for most pools
    // Thanks Boolberry!
    block b;
    crypto::hash blk_id;
    if(!parse_and_validate_block_from_blob(blockblob, b, blk_id))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
      error_resp.message = "Wrong block blob";
      return false;
    }

    // Fix from Boolberry neglects to check block
    // size, do that with the function below
    if(!m_core.check_incoming_block_size(blockblob))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB_SIZE;
      error_resp.message = "Block bloc size is too big, rejecting block";
      return false;
    }

    block_verification_context bvc;
    if(!m_core.handle_block_found(b, bvc))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED;
      error_resp.message = "Block not accepted";
      return false;
    }
    res.block_id = epee::string_tools::pod_to_hex(blk_id);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_generateblocks(const COMMAND_RPC_GENERATEBLOCKS::request& req, COMMAND_RPC_GENERATEBLOCKS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(generateblocks);

    CHECK_CORE_READY();
    
    res.status = CORE_RPC_STATUS_OK;

    if(m_core.get_nettype() != FAKECHAIN)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_REGTEST_REQUIRED;
      error_resp.message = "Regtest required when generating blocks";      
      return false;
    }

    COMMAND_RPC_GETBLOCKTEMPLATE::request template_req;
    COMMAND_RPC_GETBLOCKTEMPLATE::response template_res;
    COMMAND_RPC_SUBMITBLOCK::request submit_req;
    COMMAND_RPC_SUBMITBLOCK::response submit_res;

    template_req.reserve_size = 1;
    template_req.wallet_address = req.wallet_address;
    template_req.prev_block = req.prev_block;
    submit_req.push_back(std::string{});
    res.height = m_core.get_blockchain_storage().get_current_blockchain_height();

    for(size_t i = 0; i < req.amount_of_blocks; i++)
    {
      bool r = on_getblocktemplate(template_req, template_res, error_resp, ctx);
      res.status = template_res.status;
      template_req.prev_block.clear();
      
      if (!r) return false;

      blobdata blockblob;
      if(!string_tools::parse_hexstr_to_binbuff(template_res.blocktemplate_blob, blockblob))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
        error_resp.message = "Wrong block blob";
        return false;
      }
      block b;
      if(!parse_and_validate_block_from_blob(blockblob, b))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
        error_resp.message = "Wrong block blob";
        return false;
      }
      b.nonce = req.starting_nonce;
      crypto::hash seed_hash = crypto::null_hash;
      if (b.major_version >= RX_BLOCK_VERSION && !epee::string_tools::hex_to_pod(template_res.seed_hash, seed_hash))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Error converting seed hash";
        return false;
      }
      miner::find_nonce_for_given_block([this](const cryptonote::block &b, uint64_t height, const crypto::hash *seed_hash, unsigned int threads, crypto::hash &hash) {
        return cryptonote::get_block_longhash(&(m_core.get_blockchain_storage()), b, hash, height, seed_hash, threads);
      }, b, template_res.difficulty, template_res.height, &seed_hash);

      submit_req.front() = string_tools::buff_to_hex_nodelimer(block_to_blob(b));
      r = on_submitblock(submit_req, submit_res, error_resp, ctx);
      res.status = submit_res.status;

      if (!r) return false;

      res.blocks.push_back(epee::string_tools::pod_to_hex(get_block_hash(b)));
      template_req.prev_block = res.blocks.back();
      res.height = template_res.height;
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  uint64_t core_rpc_server::get_block_reward(const block& blk)
  {
    uint64_t reward = 0;
    for(const tx_out& out: blk.miner_tx.vout)
    {
      reward += out.amount;
    }
    return reward;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::fill_block_header_response(const block& blk, bool orphan_status, uint64_t height, const crypto::hash& hash, block_header_response& response, bool fill_pow_hash)
  {
    PERF_TIMER(fill_block_header_response);
    response.major_version = blk.major_version;
    response.minor_version = blk.minor_version;
    response.timestamp = blk.timestamp;
    response.prev_hash = string_tools::pod_to_hex(blk.prev_id);
    response.nonce = blk.nonce;
    response.orphan_status = orphan_status;
    response.height = height;
    response.depth = m_core.get_current_blockchain_height() - height - 1;
    response.hash = string_tools::pod_to_hex(hash);
    store_difficulty(m_core.get_blockchain_storage().block_difficulty(height),
        response.difficulty, response.wide_difficulty, response.difficulty_top64);
    store_difficulty(m_core.get_blockchain_storage().get_db().get_block_cumulative_difficulty(height),
        response.cumulative_difficulty, response.wide_cumulative_difficulty, response.cumulative_difficulty_top64);
    response.reward = get_block_reward(blk);
    response.block_size = response.block_weight = m_core.get_blockchain_storage().get_db().get_block_weight(height);
    response.num_txes = blk.tx_hashes.size();
    response.pow_hash = fill_pow_hash ? string_tools::pod_to_hex(get_block_longhash(&(m_core.get_blockchain_storage()), blk, height, 0)) : "";
    response.long_term_weight = m_core.get_blockchain_storage().get_db().get_block_long_term_weight(height);
    response.miner_tx_hash = string_tools::pod_to_hex(cryptonote::get_transaction_hash(blk.miner_tx));
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  template <typename COMMAND_TYPE>
  bool core_rpc_server::use_bootstrap_daemon_if_necessary(const invoke_http_mode &mode, const std::string &command_name, const typename COMMAND_TYPE::request& req, typename COMMAND_TYPE::response& res, bool &r)
  {
    res.untrusted = false;

    boost::upgrade_lock<boost::shared_mutex> upgrade_lock(m_bootstrap_daemon_mutex);

    if (m_bootstrap_daemon.get() == nullptr)
    {
      return false;
    }

    if (!m_should_use_bootstrap_daemon)
    {
      MINFO("The local daemon is fully synced. Not switching back to the bootstrap daemon");
      return false;
    }

    auto current_time = std::chrono::system_clock::now();
    if (current_time - m_bootstrap_height_check_time > std::chrono::seconds(30))  // update every 30s
    {
      {
        boost::upgrade_to_unique_lock<boost::shared_mutex> lock(upgrade_lock);
        m_bootstrap_height_check_time = current_time;
      }

      boost::optional<std::pair<uint64_t, uint64_t>> bootstrap_daemon_height_info = m_bootstrap_daemon->get_height();
      if (!bootstrap_daemon_height_info)
      {
        MERROR("Failed to fetch bootstrap daemon height");
        return false;
      }

      const uint64_t bootstrap_daemon_height = bootstrap_daemon_height_info->first;
      const uint64_t bootstrap_daemon_target_height = bootstrap_daemon_height_info->second;
      if (bootstrap_daemon_height < bootstrap_daemon_target_height)
      {
        MINFO("Bootstrap daemon is out of sync");
        return m_bootstrap_daemon->handle_result(false, {});
      }

      if (bootstrap_daemon_height < m_core.get_checkpoints().get_max_height())
      {
        MINFO("Bootstrap daemon height is lower than the latest checkpoint");
        return m_bootstrap_daemon->handle_result(false, {});
      }

      if (!m_p2p.get_payload_object().no_sync())
      {
        uint64_t top_height = m_core.get_current_blockchain_height();
        m_should_use_bootstrap_daemon = top_height + 10 < bootstrap_daemon_height;
        MINFO((m_should_use_bootstrap_daemon ? "Using" : "Not using") << " the bootstrap daemon (our height: " << top_height << ", bootstrap daemon's height: " << bootstrap_daemon_height << ")");

        if (!m_should_use_bootstrap_daemon)
          return false;
      }
    }

    if (mode == invoke_http_mode::JON)
    {
      r = m_bootstrap_daemon->invoke_http_json(command_name, req, res);
    }
    else if (mode == invoke_http_mode::BIN)
    {
      r = m_bootstrap_daemon->invoke_http_bin(command_name, req, res);
    }
    else if (mode == invoke_http_mode::JON_RPC)
    {
      r = m_bootstrap_daemon->invoke_http_json_rpc(command_name, req, res);
    }
    else
    {
      MERROR("Unknown invoke_http_mode: " << mode);
      return false;
    }

    {
      boost::upgrade_to_unique_lock<boost::shared_mutex> lock(upgrade_lock);
      m_was_bootstrap_ever_used = true;
    }

    if (r && res.status != CORE_RPC_STATUS_PAYMENT_REQUIRED && res.status != CORE_RPC_STATUS_OK)
    {
      MINFO("Failing RPC " << command_name << " due to peer return status " << res.status);
      r = false;
    }
    res.untrusted = true;
    return r;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& req, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_last_block_header);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_LAST_BLOCK_HEADER>(invoke_http_mode::JON_RPC, "getlastblockheader", req, res, r))
      return r;

    CHECK_CORE_READY();
    CHECK_PAYMENT_MIN1(req, res, COST_PER_BLOCK_HEADER, false);
    uint64_t last_block_height;
    crypto::hash last_block_hash;
    m_core.get_blockchain_top(last_block_height, last_block_hash);
    block last_block;
    bool have_last_block = m_core.get_block_by_hash(last_block_hash, last_block);
    if (!have_last_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get last block.";
      return false;
    }
    const bool restricted = m_restricted && ctx;
    bool response_filled = fill_block_header_response(last_block, false, last_block_height, last_block_hash, res.block_header, req.fill_pow_hash && !restricted);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_block_header_by_hash);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH>(invoke_http_mode::JON_RPC, "getblockheaderbyhash", req, res, r))
      return r;

    CHECK_PAYMENT_MIN1(req, res, COST_PER_BLOCK_HEADER, false);

    const bool restricted = m_restricted && ctx;
    if (restricted && req.hashes.size() > RESTRICTED_BLOCK_COUNT)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_RESTRICTED;
      error_resp.message = "Too many block headers requested in restricted mode";
      return false;
    }

    auto get = [this](const std::string &hash, bool fill_pow_hash, block_header_response &block_header, bool restricted, epee::json_rpc::error& error_resp) -> bool {
      crypto::hash block_hash;
      bool hash_parsed = parse_hash256(hash, block_hash);
      if(!hash_parsed)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Failed to parse hex representation of block hash. Hex = " + hash + '.';
        return false;
      }
      block blk;
      bool orphan = false;
      bool have_block = m_core.get_block_by_hash(block_hash, blk, &orphan);
      if (!have_block)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't get block by hash. Hash = " + hash + '.';
        return false;
      }
      if (blk.miner_tx.vin.size() != 1 || blk.miner_tx.vin.front().type() != typeid(txin_gen))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
        return false;
      }
      uint64_t block_height = boost::get<txin_gen>(blk.miner_tx.vin.front()).height;
      bool response_filled = fill_block_header_response(blk, orphan, block_height, block_hash, block_header, fill_pow_hash && !restricted);
      if (!response_filled)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't produce valid response.";
        return false;
      }
      return true;
    };

    if (!req.hash.empty())
    {
      if (!get(req.hash, req.fill_pow_hash, res.block_header, restricted, error_resp))
        return false;
    }
    res.block_headers.reserve(req.hashes.size());
    for (const std::string &hash: req.hashes)
    {
      res.block_headers.push_back({});
      if (!get(hash, req.fill_pow_hash, res.block_headers.back(), restricted, error_resp))
        return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_headers_range(const COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request& req, COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_block_headers_range);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BLOCK_HEADERS_RANGE>(invoke_http_mode::JON_RPC, "getblockheadersrange", req, res, r))
      return r;

    const uint64_t bc_height = m_core.get_current_blockchain_height();
    if (req.start_height >= bc_height || req.end_height >= bc_height || req.start_height > req.end_height)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
      error_resp.message = "Invalid start/end heights.";
      return false;
    }
    const bool restricted = m_restricted && ctx;
    if (restricted && req.end_height - req.start_height > RESTRICTED_BLOCK_HEADER_RANGE)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_RESTRICTED;
      error_resp.message = "Too many block headers requested.";
      return false;
    }

    CHECK_PAYMENT_MIN1(req, res, (req.end_height - req.start_height + 1) * COST_PER_BLOCK_HEADER, false);
    for (uint64_t h = req.start_height; h <= req.end_height; ++h)
    {
      crypto::hash block_hash = m_core.get_block_id_by_height(h);
      block blk;
      bool have_block = m_core.get_block_by_hash(block_hash, blk);
      if (!have_block)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't get block by height. Height = " + boost::lexical_cast<std::string>(h) + ". Hash = " + epee::string_tools::pod_to_hex(block_hash) + '.';
        return false;
      }
      if (blk.miner_tx.vin.size() != 1 || blk.miner_tx.vin.front().type() != typeid(txin_gen))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
        return false;
      }
      uint64_t block_height = boost::get<txin_gen>(blk.miner_tx.vin.front()).height;
      if (block_height != h)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: coinbase transaction in the block has the wrong height";
        return false;
      }
      res.headers.push_back(block_header_response());
      bool response_filled = fill_block_header_response(blk, false, block_height, block_hash, res.headers.back(), req.fill_pow_hash && !restricted);
      if (!response_filled)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Internal error: can't produce valid response.";
        return false;
      }
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& req, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_block_header_by_height);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT>(invoke_http_mode::JON_RPC, "getblockheaderbyheight", req, res, r))
      return r;

    if(m_core.get_current_blockchain_height() <= req.height)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
      error_resp.message = std::string("Requested block height: ") + std::to_string(req.height) + " greater than current top block height: " +  std::to_string(m_core.get_current_blockchain_height() - 1);
      return false;
    }
    CHECK_PAYMENT_MIN1(req, res, COST_PER_BLOCK_HEADER, false);
    crypto::hash block_hash = m_core.get_block_id_by_height(req.height);
    block blk;
    bool have_block = m_core.get_block_by_hash(block_hash, blk);
    if (!have_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get block by height. Height = " + std::to_string(req.height) + '.';
      return false;
    }
    const bool restricted = m_restricted && ctx;
    bool response_filled = fill_block_header_response(blk, false, req.height, block_hash, res.block_header, req.fill_pow_hash && !restricted);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_block(const COMMAND_RPC_GET_BLOCK::request& req, COMMAND_RPC_GET_BLOCK::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_block);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BLOCK>(invoke_http_mode::JON_RPC, "getblock", req, res, r))
      return r;

    CHECK_PAYMENT_MIN1(req, res, COST_PER_BLOCK, false);

    crypto::hash block_hash;
    if (!req.hash.empty())
    {
      bool hash_parsed = parse_hash256(req.hash, block_hash);
      if(!hash_parsed)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Failed to parse hex representation of block hash. Hex = " + req.hash + '.';
        return false;
      }
    }
    else
    {
      if(m_core.get_current_blockchain_height() <= req.height)
      {
        error_resp.code = CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT;
        error_resp.message = std::string("Requested block height: ") + std::to_string(req.height) + " greater than current top block height: " +  std::to_string(m_core.get_current_blockchain_height() - 1);
        return false;
      }
      block_hash = m_core.get_block_id_by_height(req.height);
    }
    block blk;
    bool orphan = false;
    bool have_block = m_core.get_block_by_hash(block_hash, blk, &orphan);
    if (!have_block)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't get block by hash. Hash = " + req.hash + '.';
      return false;
    }
    if (blk.miner_tx.vin.size() != 1 || blk.miner_tx.vin.front().type() != typeid(txin_gen))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: coinbase transaction in the block has the wrong type";
      return false;
    }
    uint64_t block_height = boost::get<txin_gen>(blk.miner_tx.vin.front()).height;
    const bool restricted = m_restricted && ctx;
    bool response_filled = fill_block_header_response(blk, orphan, block_height, block_hash, res.block_header, req.fill_pow_hash && !restricted);
    if (!response_filled)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Internal error: can't produce valid response.";
      return false;
    }
    res.miner_tx_hash = res.block_header.miner_tx_hash;
    for (size_t n = 0; n < blk.tx_hashes.size(); ++n)
    {
      res.tx_hashes.push_back(epee::string_tools::pod_to_hex(blk.tx_hashes[n]));
    }
    res.blob = string_tools::buff_to_hex_nodelimer(t_serializable_object_to_blob(blk));
    res.json = obj_to_json_str(blk);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_connections(const COMMAND_RPC_GET_CONNECTIONS::request& req, COMMAND_RPC_GET_CONNECTIONS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_connections);

    res.connections = m_p2p.get_payload_object().get_connections();

    res.status = CORE_RPC_STATUS_OK;

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_info_json(const COMMAND_RPC_GET_INFO::request& req, COMMAND_RPC_GET_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    if (!on_get_info(req, res, ctx) || res.status != CORE_RPC_STATUS_OK)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = res.status;
      return false;
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_hard_fork_info(const COMMAND_RPC_HARD_FORK_INFO::request& req, COMMAND_RPC_HARD_FORK_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(hard_fork_info);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_HARD_FORK_INFO>(invoke_http_mode::JON_RPC, "hard_fork_info", req, res, r))
      return r;

    CHECK_PAYMENT(req, res, COST_PER_HARD_FORK_INFO);
    const Blockchain &blockchain = m_core.get_blockchain_storage();
    uint8_t version = req.version > 0 ? req.version : blockchain.get_next_hard_fork_version();
    res.version = blockchain.get_current_hard_fork_version();
    res.enabled = blockchain.get_hard_fork_voting_info(version, res.window, res.votes, res.threshold, res.earliest_height, res.voting);
    res.state = blockchain.get_hard_fork_state();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_bans(const COMMAND_RPC_GETBANS::request& req, COMMAND_RPC_GETBANS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_bans);

    auto now = time(nullptr);
    std::map<std::string, time_t> blocked_hosts = m_p2p.get_blocked_hosts();
    for (std::map<std::string, time_t>::const_iterator i = blocked_hosts.begin(); i != blocked_hosts.end(); ++i)
    {
      if (i->second > now) {
        COMMAND_RPC_GETBANS::ban b;
        b.host = i->first;
        b.ip = 0;
        uint32_t ip;
        if (epee::string_tools::get_ip_int32_from_string(ip, b.host))
          b.ip = ip;
        b.seconds = i->second - now;
        res.bans.push_back(b);
      }
    }
    std::map<epee::net_utils::ipv4_network_subnet, time_t> blocked_subnets = m_p2p.get_blocked_subnets();
    for (std::map<epee::net_utils::ipv4_network_subnet, time_t>::const_iterator i = blocked_subnets.begin(); i != blocked_subnets.end(); ++i)
    {
      if (i->second > now) {
        COMMAND_RPC_GETBANS::ban b;
        b.host = i->first.host_str();
        b.ip = 0;
        b.seconds = i->second - now;
        res.bans.push_back(b);
      }
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_banned(const COMMAND_RPC_BANNED::request& req, COMMAND_RPC_BANNED::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    PERF_TIMER(on_banned);

    auto na_parsed = net::get_network_address(req.address, 0);
    if (!na_parsed)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Unsupported host type";
      return false;
    }
    epee::net_utils::network_address na = std::move(*na_parsed);

    time_t seconds;
    if (m_p2p.is_host_blocked(na, &seconds))
    {
      res.banned = true;
      res.seconds = seconds;
    }
    else
    {
      res.banned = false;
      res.seconds = 0;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_bans(const COMMAND_RPC_SETBANS::request& req, COMMAND_RPC_SETBANS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(set_bans);

    for (auto i = req.bans.begin(); i != req.bans.end(); ++i)
    {
      epee::net_utils::network_address na;

      // try subnet first
      if (!i->host.empty())
      {
        auto ns_parsed = net::get_ipv4_subnet_address(i->host);
        if (ns_parsed)
        {
          if (i->ban)
            m_p2p.block_subnet(*ns_parsed, i->seconds);
          else
            m_p2p.unblock_subnet(*ns_parsed);
          continue;
        }
      }

      // then host
      if (!i->host.empty())
      {
        auto na_parsed = net::get_network_address(i->host, 0);
        if (!na_parsed)
        {
          error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
          error_resp.message = "Unsupported host/subnet type";
          return false;
        }
        na = std::move(*na_parsed);
      }
      else
      {
        if (!i->ip)
        {
          error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
          error_resp.message = "No ip/host supplied";
          return false;
        }
        na = epee::net_utils::ipv4_network_address{i->ip, 0};
      }
      if (i->ban)
        m_p2p.block_host(na, i->seconds);
      else
        m_p2p.unblock_host(na);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_flush_txpool(const COMMAND_RPC_FLUSH_TRANSACTION_POOL::request& req, COMMAND_RPC_FLUSH_TRANSACTION_POOL::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(flush_txpool);

    bool failed = false;
    std::vector<crypto::hash> txids;
    if (req.txids.empty())
    {
      bool r = m_core.get_pool_transaction_hashes(txids, true);
      if (!r)
      {
        res.status = "Failed to get txpool contents";
        return true;
      }
    }
    else
    {
      for (const auto &str: req.txids)
      {
        crypto::hash txid;
        if(!epee::string_tools::hex_to_pod(str, txid))
        {
          failed = true;
        }
        else
        {
          txids.push_back(txid);
        }
      }
    }
    if (!m_core.get_blockchain_storage().flush_txes_from_pool(txids))
    {
      res.status = "Failed to remove one or more tx(es)";
      return true;
    }

    if (failed)
    {
      if (txids.empty())
        res.status = "Failed to parse txid";
      else
        res.status = "Failed to parse some of the txids";
      return true;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_output_histogram(const COMMAND_RPC_GET_OUTPUT_HISTOGRAM::request& req, COMMAND_RPC_GET_OUTPUT_HISTOGRAM::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_output_histogram);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_OUTPUT_HISTOGRAM>(invoke_http_mode::JON_RPC, "get_output_histogram", req, res, r))
      return r;

    const bool restricted = m_restricted && ctx;
    size_t amounts = req.amounts.size();
    if (restricted && amounts == 0)
    {
      res.status = "Restricted RPC will not serve histograms on the whole blockchain. Use your own node.";
      return true;
    }

    uint64_t cost = req.amounts.empty() ? COST_PER_FULL_OUTPUT_HISTOGRAM : (COST_PER_OUTPUT_HISTOGRAM * amounts);
    CHECK_PAYMENT_MIN1(req, res, cost, false);

    if (restricted && req.recent_cutoff > 0 && req.recent_cutoff < (uint64_t)time(NULL) - OUTPUT_HISTOGRAM_RECENT_CUTOFF_RESTRICTION)
    {
      res.status = "Recent cutoff is too old";
      return true;
    }

    std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> histogram;
    try
    {
      histogram = m_core.get_blockchain_storage().get_output_histogram(req.amounts, req.unlocked, req.recent_cutoff, req.min_count);
    }
    catch (const std::exception &e)
    {
      res.status = "Failed to get output histogram";
      return true;
    }

    res.histogram.clear();
    res.histogram.reserve(histogram.size());
    for (const auto &i: histogram)
    {
      if (std::get<0>(i.second) >= req.min_count && (std::get<0>(i.second) <= req.max_count || req.max_count == 0))
        res.histogram.push_back(COMMAND_RPC_GET_OUTPUT_HISTOGRAM::entry(i.first, std::get<0>(i.second), std::get<1>(i.second), std::get<2>(i.second)));
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_version(const COMMAND_RPC_GET_VERSION::request& req, COMMAND_RPC_GET_VERSION::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_version);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_VERSION>(invoke_http_mode::JON_RPC, "get_version", req, res, r))
      return r;

    res.version = CORE_RPC_VERSION;
    res.release = MONERO_VERSION_IS_RELEASE;
    res.current_height = m_core.get_current_blockchain_height();
    res.target_height = m_p2p.get_payload_object().is_synchronized() ? 0 : m_core.get_target_blockchain_height();
    for (const auto &hf : m_core.get_blockchain_storage().get_hardforks())
       res.hard_forks.push_back({hf.version, hf.height});
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_coinbase_tx_sum(const COMMAND_RPC_GET_COINBASE_TX_SUM::request& req, COMMAND_RPC_GET_COINBASE_TX_SUM::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_coinbase_tx_sum);
    const uint64_t bc_height = m_core.get_current_blockchain_height();
    if (req.height >= bc_height || req.count > bc_height)
    {
      res.status = "height or count is too large";
      return true;
    }
    CHECK_PAYMENT_MIN1(req, res, COST_PER_COINBASE_TX_SUM_BLOCK * req.count, false);
    std::pair<boost::multiprecision::uint128_t, boost::multiprecision::uint128_t> amounts = m_core.get_coinbase_tx_sum(req.height, req.count);
    store_128(amounts.first, res.emission_amount, res.wide_emission_amount, res.emission_amount_top64);
    store_128(amounts.second, res.fee_amount, res.wide_fee_amount, res.fee_amount_top64);
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_base_fee_estimate(const COMMAND_RPC_GET_BASE_FEE_ESTIMATE::request& req, COMMAND_RPC_GET_BASE_FEE_ESTIMATE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_base_fee_estimate);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_BASE_FEE_ESTIMATE>(invoke_http_mode::JON_RPC, "get_fee_estimate", req, res, r))
      return r;

    CHECK_PAYMENT(req, res, COST_PER_FEE_ESTIMATE);

    const uint8_t version = m_core.get_blockchain_storage().get_current_hard_fork_version();
    if (version >= HF_VERSION_2021_SCALING)
    {
      m_core.get_blockchain_storage().get_dynamic_base_fee_estimate_2021_scaling(req.grace_blocks, res.fees);
      res.fee = res.fees[0];
    }
    else
    {
      res.fee = m_core.get_blockchain_storage().get_dynamic_base_fee_estimate(req.grace_blocks);
    }
    res.quantization_mask = Blockchain::get_fee_quantization_mask();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_alternate_chains(const COMMAND_RPC_GET_ALTERNATE_CHAINS::request& req, COMMAND_RPC_GET_ALTERNATE_CHAINS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_alternate_chains);
    try
    {
      std::vector<std::pair<Blockchain::block_extended_info, std::vector<crypto::hash>>> chains = m_core.get_blockchain_storage().get_alternative_chains();
      for (const auto &i: chains)
      {
        difficulty_type wdiff = i.first.cumulative_difficulty;
        res.chains.push_back(COMMAND_RPC_GET_ALTERNATE_CHAINS::chain_info{epee::string_tools::pod_to_hex(get_block_hash(i.first.bl)), i.first.height, i.second.size(), 0, "", 0, {}, std::string()});
        store_difficulty(wdiff, res.chains.back().difficulty, res.chains.back().wide_difficulty, res.chains.back().difficulty_top64);
        res.chains.back().block_hashes.reserve(i.second.size());
        for (const crypto::hash &block_id: i.second)
          res.chains.back().block_hashes.push_back(epee::string_tools::pod_to_hex(block_id));
        if (i.first.height < i.second.size())
        {
          res.status = "Error finding alternate chain attachment point";
          return true;
        }
        cryptonote::block main_chain_parent_block;
        try { main_chain_parent_block = m_core.get_blockchain_storage().get_db().get_block_from_height(i.first.height - i.second.size()); }
        catch (const std::exception &e) { res.status = "Error finding alternate chain attachment point"; return true; }
        res.chains.back().main_chain_parent_block = epee::string_tools::pod_to_hex(get_block_hash(main_chain_parent_block));
      }
      res.status = CORE_RPC_STATUS_OK;
    }
    catch (...)
    {
      res.status = "Error retrieving alternate chains";
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_limit(const COMMAND_RPC_GET_LIMIT::request& req, COMMAND_RPC_GET_LIMIT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_limit);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_LIMIT>(invoke_http_mode::JON, "/get_limit", req, res, r))
      return r;

    res.limit_down = epee::net_utils::connection_basic::get_rate_down_limit();
    res.limit_up = epee::net_utils::connection_basic::get_rate_up_limit();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_set_limit(const COMMAND_RPC_SET_LIMIT::request& req, COMMAND_RPC_SET_LIMIT::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(set_limit);
    // -1 = reset to default
    //  0 = do not modify

    if (req.limit_down > 0)
    {
      epee::net_utils::connection_basic::set_rate_down_limit(req.limit_down);
    }
    else if (req.limit_down < 0)
    {
      if (req.limit_down != -1)
      {
        res.status = "Invalid parameter";
        return true;
      }
      epee::net_utils::connection_basic::set_rate_down_limit(nodetool::default_limit_down);
    }

    if (req.limit_up > 0)
    {
      epee::net_utils::connection_basic::set_rate_up_limit(req.limit_up);
    }
    else if (req.limit_up < 0)
    {
      if (req.limit_up != -1)
      {
        res.status = "Invalid parameter";
        return true;
      }
      epee::net_utils::connection_basic::set_rate_up_limit(nodetool::default_limit_up);
    }

    res.limit_down = epee::net_utils::connection_basic::get_rate_down_limit();
    res.limit_up = epee::net_utils::connection_basic::get_rate_up_limit();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_out_peers(const COMMAND_RPC_OUT_PEERS::request& req, COMMAND_RPC_OUT_PEERS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(out_peers);
    if (req.set)
      m_p2p.change_max_out_public_peers(req.out_peers);
    res.out_peers = m_p2p.get_max_out_public_peers();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_in_peers(const COMMAND_RPC_IN_PEERS::request& req, COMMAND_RPC_IN_PEERS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(in_peers);
    if (req.set)
      m_p2p.change_max_in_public_peers(req.in_peers);
    res.in_peers = m_p2p.get_max_in_public_peers();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_update(const COMMAND_RPC_UPDATE::request& req, COMMAND_RPC_UPDATE::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(update);

    res.update = false;
    if (m_core.offline())
    {
      res.status = "Daemon is running offline";
      return true;
    }

    static const char software[] = "monero";
#ifdef BUILD_TAG
    static const char buildtag[] = BOOST_PP_STRINGIZE(BUILD_TAG);
    static const char subdir[] = "cli";
#else
    static const char buildtag[] = "source";
    static const char subdir[] = "source";
#endif

    if (req.command != "check" && req.command != "download" && req.command != "update")
    {
      res.status = std::string("unknown command: '") + req.command + "'";
      return true;
    }

    std::string version, hash;
    if (!tools::check_updates(software, buildtag, version, hash))
    {
      res.status = "Error checking for updates";
      return true;
    }
    if (tools::vercmp(version.c_str(), MONERO_VERSION) <= 0)
    {
      res.update = false;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }
    res.update = true;
    res.version = version;
    res.user_uri = tools::get_update_url(software, subdir, buildtag, version, true);
    res.auto_uri = tools::get_update_url(software, subdir, buildtag, version, false);
    res.hash = hash;
    if (req.command == "check")
    {
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    boost::filesystem::path path;
    if (req.path.empty())
    {
      std::string filename;
      const char *slash = strrchr(res.auto_uri.c_str(), '/');
      if (slash)
        filename = slash + 1;
      else
        filename = std::string(software) + "-update-" + version;
      path = epee::string_tools::get_current_module_folder();
      path /= filename;
    }
    else
    {
      path = req.path;
    }

    crypto::hash file_hash;
    if (!tools::sha256sum(path.string(), file_hash) || (hash != epee::string_tools::pod_to_hex(file_hash)))
    {
      MDEBUG("We don't have that file already, downloading");
      if (!tools::download(path.string(), res.auto_uri))
      {
        MERROR("Failed to download " << res.auto_uri);
        return true;
      }
      if (!tools::sha256sum(path.string(), file_hash))
      {
        MERROR("Failed to hash " << path);
        return true;
      }
      if (hash != epee::string_tools::pod_to_hex(file_hash))
      {
        MERROR("Download from " << res.auto_uri << " does not match the expected hash");
        return true;
      }
      MINFO("New version downloaded to " << path);
    }
    else
    {
      MDEBUG("We already have " << path << " with expected hash");
    }
    res.path = path.string();

    if (req.command == "download")
    {
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    res.status = "'update' not implemented yet";
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_pop_blocks(const COMMAND_RPC_POP_BLOCKS::request& req, COMMAND_RPC_POP_BLOCKS::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(pop_blocks);

    m_core.get_blockchain_storage().pop_blocks(req.nblocks);

    res.height = m_core.get_current_blockchain_height();
    res.status = CORE_RPC_STATUS_OK;

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_relay_tx(const COMMAND_RPC_RELAY_TX::request& req, COMMAND_RPC_RELAY_TX::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(relay_tx);
    CHECK_PAYMENT_MIN1(req, res, req.txids.size() * COST_PER_TX_RELAY, false);

    const bool restricted = m_restricted && ctx;

    bool failed = false;
    res.status = "";
    for (const auto &str: req.txids)
    {
      crypto::hash txid;
      if(!epee::string_tools::hex_to_pod(str, txid))
      {
        if (!res.status.empty()) res.status += ", ";
        res.status += std::string("invalid transaction id: ") + str;
        failed = true;
        continue;
      }

      //TODO: The get_pool_transaction could have an optional meta parameter
      bool broadcasted = false;
      cryptonote::blobdata txblob;
      if ((broadcasted = m_core.get_pool_transaction(txid, txblob, relay_category::broadcasted)) || (!restricted && m_core.get_pool_transaction(txid, txblob, relay_category::all)))
      {
        // The settings below always choose i2p/tor if enabled. Otherwise, do fluff iff previously relayed else dandelion++ stem.
        NOTIFY_NEW_TRANSACTIONS::request r;
        r.txs.push_back(std::move(txblob));
        const auto tx_relay = broadcasted ? relay_method::fluff : relay_method::local;
        m_core.get_protocol()->relay_transactions(r, boost::uuids::nil_uuid(), epee::net_utils::zone::invalid, tx_relay);
        //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
      }
      else
      {
        if (!res.status.empty()) res.status += ", ";
        res.status += std::string("transaction not found in pool: ") + str;
        failed = true;
        continue;
      }
    }

    if (failed)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = res.status;
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_sync_info(const COMMAND_RPC_SYNC_INFO::request& req, COMMAND_RPC_SYNC_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(sync_info);
    CHECK_PAYMENT(req, res, COST_PER_SYNC_INFO);

    crypto::hash top_hash;
    m_core.get_blockchain_top(res.height, top_hash);
    ++res.height; // turn top block height into blockchain height
    res.target_height = m_p2p.get_payload_object().is_synchronized() ? 0 : m_core.get_target_blockchain_height();
    res.next_needed_pruning_seed = m_p2p.get_payload_object().get_next_needed_pruning_stripe().second;

    for (const auto &c: m_p2p.get_payload_object().get_connections())
      res.peers.push_back({c});
    const cryptonote::block_queue &block_queue = m_p2p.get_payload_object().get_block_queue();
    block_queue.foreach([&](const cryptonote::block_queue::span &span) {
      const std::string span_connection_id = epee::string_tools::pod_to_hex(span.connection_id);
      uint32_t speed = (uint32_t)(100.0f * block_queue.get_speed(span.connection_id) + 0.5f);
      res.spans.push_back({span.start_block_height, span.nblocks, span_connection_id, (uint32_t)(span.rate + 0.5f), speed, span.size, span.origin.str()});
      return true;
    });
    res.overview = block_queue.get_overview(res.height);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_txpool_backlog(const COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::request& req, COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_txpool_backlog);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_TRANSACTION_POOL_BACKLOG>(invoke_http_mode::JON_RPC, "get_txpool_backlog", req, res, r))
      return r;
    size_t n_txes = m_core.get_pool_transactions_count();
    CHECK_PAYMENT_MIN1(req, res, COST_PER_TX_POOL_STATS * n_txes, false);

    if (!m_core.get_txpool_backlog(res.backlog))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to get txpool backlog";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_output_distribution(const COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request& req, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_output_distribution);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_OUTPUT_DISTRIBUTION>(invoke_http_mode::JON_RPC, "get_output_distribution", req, res, r))
      return r;

    const bool restricted = m_restricted && ctx;
    if (restricted && req.amounts != std::vector<uint64_t>(1, 0))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_RESTRICTED;
      error_resp.message = "Restricted RPC can only get output distribution for rct outputs. Use your own node.";
      return false;
    }

    size_t n_0 = 0, n_non0 = 0;
    for (uint64_t amount: req.amounts)
      if (amount) ++n_non0; else ++n_0;
    CHECK_PAYMENT_MIN1(req, res, n_0 * COST_PER_OUTPUT_DISTRIBUTION_0 + n_non0 * COST_PER_OUTPUT_DISTRIBUTION, false);

    try
    {
      // 0 is placeholder for the whole chain
      const uint64_t req_to_height = req.to_height ? req.to_height : (m_core.get_current_blockchain_height() - 1);
      for (uint64_t amount: req.amounts)
      {
        auto data = rpc::RpcHandler::get_output_distribution([this](uint64_t amount, uint64_t from, uint64_t to, uint64_t &start_height, std::vector<uint64_t> &distribution, uint64_t &base) { return m_core.get_output_distribution(amount, from, to, start_height, distribution, base); }, amount, req.from_height, req_to_height, [this](uint64_t height) { return m_core.get_blockchain_storage().get_db().get_block_hash_from_height(height); }, req.cumulative, m_core.get_current_blockchain_height());
        if (!data)
        {
          error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
          error_resp.message = "Failed to get output distribution";
          return false;
        }

        res.distributions.push_back({std::move(*data), amount, "", req.binary, req.compress});
      }
    }
    catch (const std::exception &e)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to get output distribution";
      return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_get_output_distribution_bin(const COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::request& req, COMMAND_RPC_GET_OUTPUT_DISTRIBUTION::response& res, const connection_context *ctx)
  {
    RPC_TRACKER(get_output_distribution_bin);

    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_GET_OUTPUT_DISTRIBUTION>(invoke_http_mode::BIN, "/get_output_distribution.bin", req, res, r))
      return r;

    const bool restricted = m_restricted && ctx;
    if (restricted && req.amounts != std::vector<uint64_t>(1, 0))
    {
      res.status = "Restricted RPC can only get output distribution for rct outputs. Use your own node.";
      return false;
    }

    size_t n_0 = 0, n_non0 = 0;
    for (uint64_t amount: req.amounts)
      if (amount) ++n_non0; else ++n_0;
    CHECK_PAYMENT_MIN1(req, res, n_0 * COST_PER_OUTPUT_DISTRIBUTION_0 + n_non0 * COST_PER_OUTPUT_DISTRIBUTION, false);

    res.status = "Failed";

    if (!req.binary)
    {
      res.status = "Binary only call";
      return true;
    }
    try
    {
      // 0 is placeholder for the whole chain
      const uint64_t req_to_height = req.to_height ? req.to_height : (m_core.get_current_blockchain_height() - 1);
      for (uint64_t amount: req.amounts)
      {
        auto data = rpc::RpcHandler::get_output_distribution([this](uint64_t amount, uint64_t from, uint64_t to, uint64_t &start_height, std::vector<uint64_t> &distribution, uint64_t &base) { return m_core.get_output_distribution(amount, from, to, start_height, distribution, base); }, amount, req.from_height, req_to_height, [this](uint64_t height) { return m_core.get_blockchain_storage().get_db().get_block_hash_from_height(height); }, req.cumulative, m_core.get_current_blockchain_height());
        if (!data)
        {
          res.status = "Failed to get output distribution";
          return true;
        }

        res.distributions.push_back({std::move(*data), amount, "", req.binary, req.compress});
      }
    }
    catch (const std::exception &e)
    {
      res.status = "Failed to get output distribution";
      return true;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_prune_blockchain(const COMMAND_RPC_PRUNE_BLOCKCHAIN::request& req, COMMAND_RPC_PRUNE_BLOCKCHAIN::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(prune_blockchain);

    try
    {
      if (!(req.check ? m_core.check_blockchain_pruning() : m_core.prune_blockchain()))
      {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = req.check ? "Failed to check blockchain pruning" : "Failed to prune blockchain";
        return false;
      }
      res.pruning_seed = m_core.get_blockchain_pruning_seed();
      res.pruned = res.pruning_seed != 0;
    }
    catch (const std::exception &e)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Failed to prune blockchain";
      return false;
    }
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_rpc_access_info(const COMMAND_RPC_ACCESS_INFO::request& req, COMMAND_RPC_ACCESS_INFO::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(rpc_access_info);

    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_ACCESS_INFO>(invoke_http_mode::JON_RPC, "rpc_access_info", req, res, r))
      return r;

    // if RPC payment is not enabled
    if (m_rpc_payment == NULL)
    {
      res.diff = 0;
      res.credits_per_hash_found = 0;
      res.credits = 0;
      res.height = 0;
      res.seed_height = 0;
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    crypto::public_key client;
    uint64_t ts;
    if (!cryptonote::verify_rpc_payment_signature(req.client, client, ts))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INVALID_CLIENT;
      error_resp.message = "Invalid client ID";
      return false;
    }

    crypto::hash top_hash;
    m_core.get_blockchain_top(res.height, top_hash);
    ++res.height;
    cryptonote::blobdata hashing_blob;
    crypto::hash seed_hash, next_seed_hash;
    if (!m_rpc_payment->get_info(client, [&](const cryptonote::blobdata &extra_nonce, cryptonote::block &b, uint64_t &seed_height, crypto::hash &seed_hash)->bool{
      cryptonote::difficulty_type difficulty;
      uint64_t height, expected_reward;
      size_t reserved_offset;
      if (!get_block_template(m_rpc_payment->get_payment_address(), NULL, extra_nonce, reserved_offset, difficulty, height, expected_reward, b, seed_height, seed_hash, next_seed_hash, error_resp))
        return false;
      return true;
    }, hashing_blob, res.seed_height, seed_hash, top_hash, res.diff, res.credits_per_hash_found, res.credits, res.cookie))
    {
      return false;
    }
    if (hashing_blob.empty())
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB;
      error_resp.message = "Invalid hashing blob";
      return false;
    }
    res.hashing_blob = epee::string_tools::buff_to_hex_nodelimer(hashing_blob);
    res.top_hash = epee::string_tools::pod_to_hex(top_hash);
    if (hashing_blob[0] >= RX_BLOCK_VERSION)
    {
      res.seed_hash = string_tools::pod_to_hex(seed_hash);
      if (seed_hash != next_seed_hash)
        res.next_seed_hash = string_tools::pod_to_hex(next_seed_hash);
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_flush_cache(const COMMAND_RPC_FLUSH_CACHE::request& req, COMMAND_RPC_FLUSH_CACHE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(flush_cache);
    if (req.bad_blocks)
      m_core.flush_invalid_blocks();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_rpc_access_submit_nonce(const COMMAND_RPC_ACCESS_SUBMIT_NONCE::request& req, COMMAND_RPC_ACCESS_SUBMIT_NONCE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(rpc_access_submit_nonce);
    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_ACCESS_SUBMIT_NONCE>(invoke_http_mode::JON_RPC, "rpc_access_submit_nonce", req, res, r))
      return r;

    // if RPC payment is not enabled
    if (m_rpc_payment == NULL)
    {
      res.status = "Payment not necessary";
      return true;
    }

    crypto::public_key client;
    uint64_t ts;
    if (!cryptonote::verify_rpc_payment_signature(req.client, client, ts))
    {
      res.credits = 0;
      error_resp.code = CORE_RPC_ERROR_CODE_INVALID_CLIENT;
      error_resp.message = "Invalid client ID";
      return false;
    }

    crypto::hash hash;
    cryptonote::block block;
    crypto::hash top_hash;
    uint64_t height;
    bool stale;
    m_core.get_blockchain_top(height, top_hash);
    if (!m_rpc_payment->submit_nonce(client, req.nonce, top_hash, error_resp.code, error_resp.message, res.credits, hash, block, req.cookie, stale))
    {
      return false;
    }

    if (!stale)
    {
      // it might be a valid block!
      const difficulty_type current_difficulty = m_core.get_blockchain_storage().get_difficulty_for_next_block();
      if (check_hash(hash, current_difficulty))
      {
        MINFO("This payment meets the current network difficulty");
        block_verification_context bvc;
        if(m_core.handle_block_found(block, bvc))
          MGINFO_GREEN("Block found by RPC user at height " << get_block_height(block) << ": " <<
              print_money(cryptonote::get_outs_money_amount(block.miner_tx)));
        else
          MERROR("Seemingly valid block was not accepted");
      }
    }

    m_core.get_blockchain_top(height, top_hash);
    res.top_hash = epee::string_tools::pod_to_hex(top_hash);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_rpc_access_pay(const COMMAND_RPC_ACCESS_PAY::request& req, COMMAND_RPC_ACCESS_PAY::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(rpc_access_pay);

    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_ACCESS_PAY>(invoke_http_mode::JON_RPC, "rpc_access_pay", req, res, r))
      return r;

    // if RPC payment is not enabled
    if (m_rpc_payment == NULL)
    {
      res.status = "Payment not necessary";
      return true;
    }

    crypto::public_key client;
    uint64_t ts;
    if (!cryptonote::verify_rpc_payment_signature(req.client, client, ts))
    {
      res.credits = 0;
      error_resp.code = CORE_RPC_ERROR_CODE_INVALID_CLIENT;
      error_resp.message = "Invalid client ID";
      return false;
    }

    RPCTracker ext_tracker(("external:" + req.paying_for).c_str(), PERF_TIMER_NAME(rpc_access_pay));
    if (!check_payment(req.client, req.payment, req.paying_for, false, res.status, res.credits, res.top_hash))
      return true;
    ext_tracker.pay(req.payment);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_rpc_access_tracking(const COMMAND_RPC_ACCESS_TRACKING::request& req, COMMAND_RPC_ACCESS_TRACKING::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(rpc_access_tracking);

    if (req.clear)
    {
      RPCTracker::clear();
      res.status = CORE_RPC_STATUS_OK;
      return true;
    }

    auto data = RPCTracker::data();
    for (const auto &d: data)
    {
      res.data.resize(res.data.size() + 1);
      res.data.back().rpc = d.first;
      res.data.back().count = d.second.count;
      res.data.back().time = d.second.time;
      res.data.back().credits = d.second.credits;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_rpc_access_data(const COMMAND_RPC_ACCESS_DATA::request& req, COMMAND_RPC_ACCESS_DATA::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(rpc_access_data);

    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_ACCESS_DATA>(invoke_http_mode::JON_RPC, "rpc_access_data", req, res, r))
      return r;

    if (!m_rpc_payment)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_PAYMENTS_NOT_ENABLED;
      error_resp.message = "Payments not enabled";
      return false;
    }

    m_rpc_payment->foreach([&](const crypto::public_key &client, const rpc_payment::client_info &info){
      res.entries.push_back({
        epee::string_tools::pod_to_hex(client), info.credits, std::max(info.last_request_timestamp / 1000000, info.update_time),
        info.credits_total, info.credits_used, info.nonces_good, info.nonces_stale, info.nonces_bad, info.nonces_dupe
      });
      return true;
    });

    res.hashrate = m_rpc_payment->get_hashes(600) / 600;

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool core_rpc_server::on_rpc_access_account(const COMMAND_RPC_ACCESS_ACCOUNT::request& req, COMMAND_RPC_ACCESS_ACCOUNT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(rpc_access_account);

    bool r;
    if (use_bootstrap_daemon_if_necessary<COMMAND_RPC_ACCESS_ACCOUNT>(invoke_http_mode::JON_RPC, "rpc_access_account", req, res, r))
      return r;

    if (!m_rpc_payment)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_PAYMENTS_NOT_ENABLED;
      error_resp.message = "Payments not enabled";
      return false;
    }

    crypto::public_key client;
    if (!epee::string_tools::hex_to_pod(req.client.substr(0, 2 * sizeof(client)), client))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INVALID_CLIENT;
      error_resp.message = "Invalid client ID";
      return false;
    }

    res.credits = m_rpc_payment->balance(client, req.delta_balance);

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
    // ---------- VNS ADDITION START ----------
bool core_rpc_server::on_resolve_domain(const COMMAND_RPC_RESOLVE_DOMAIN::request& req, COMMAND_RPC_RESOLVE_DOMAIN::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
    RPC_TRACKER(resolve_domain);

    // 1. Get domain record from blockchain
    vns_domain_record rec = m_core.get_blockchain_storage().get_domain_record(req.domain_name);
    if (is_null_key(rec.registrant_key))
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Domain not found";
        return false;
    }

    // 2. Check status
    if (rec.status == 2) // EXPIRED
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Domain is expired";
        return false;
    }

    // 3. Fill basic info
    res.address = epee::string_tools::pod_to_hex(rec.registrant_key);
    res.health_score = rec.health_score;
    res.last_heartbeat = rec.last_heartbeat_block;
    res.fee_tier = rec.fee_tier;

    // 4. Fetch service descriptor from relay
    std::string relay_url(rec.relays[0].url);
    if (relay_url.empty())
    {
        // No relay configured, return empty descriptor
        res.service_descriptor = "";
        res.status = CORE_RPC_STATUS_OK;
        return true;
    }

    // Use nostr_client to fetch latest kind 30003
    nostr_client::service_descriptor_event sd_event;
    bool ok = m_core.get_blockchain_storage().get_nostr_client().fetch_service_descriptor(
        relay_url, req.domain_name, rec.registrant_key, sd_event, 10 // timeout seconds
    );
    if (!ok)
    {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Failed to fetch service descriptor from relay";
        return false;
    }

    // 5. Verify fingerprint using 33‑byte compressed key
    std::string fingerprint_data;
    fingerprint_data += req.domain_name;
    fingerprint_data.append(reinterpret_cast<const char*>(rec.registrant_key.data()), rec.registrant_key.size());
    uint64_t height_le = rec.registered_height;
    fingerprint_data.append(reinterpret_cast<const char*>(&height_le), sizeof(height_le));
    fingerprint_data.push_back(static_cast<char>(rec.fee_tier));
    crypto::hash expected_fingerprint;
    crypto::cn_fast_hash(fingerprint_data.data(), fingerprint_data.size(), expected_fingerprint);
    std::string expected_hex = epee::string_tools::pod_to_hex(expected_fingerprint);
    if (expected_hex != sd_event.fingerprint_hex)
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Fingerprint mismatch";
        return false;
    }

    // 6. Verify Merkle proof
    if (!m_core.get_blockchain_storage().verify_merkle_proof(
            rec.registration_tx_hash,
            sd_event.leaf_index,
            sd_event.sibling_hashes,
            sd_event.block_hash
        ))
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Merkle proof verification failed";
        return false;
    }

    // 7. Return the content
    res.service_descriptor = sd_event.content;
    res.status = CORE_RPC_STATUS_OK;
    return true;
}

bool core_rpc_server::on_get_domain_record(const COMMAND_RPC_GET_DOMAIN_RECORD::request& req, COMMAND_RPC_GET_DOMAIN_RECORD::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
    RPC_TRACKER(get_domain_record);
    vns_domain_record rec = m_core.get_blockchain_storage().get_domain_record(req.domain_name);

    // A valid domain has a non‑null registrant key (the default-constructed record has null key)
    if (!is_null_key(rec.registrant_key))
    {
        res.domain_name = req.domain_name;   // domain name is known from request
        res.fee_tier = rec.fee_tier;
        res.fee_burned = rec.fee_burned;
        res.registrant_key = epee::string_tools::buff_to_hex_nodelimer(std::string((const char*)rec.registrant_key.data(), rec.registrant_key.size()));
        res.genesis_fingerprint = epee::string_tools::pod_to_hex(rec.genesis_fingerprint);
        res.last_heartbeat_block = rec.last_heartbeat_block;
        res.health_score = rec.health_score;
        res.domain_status = rec.status;
        res.registered_height = rec.registered_height;
        res.heartbeat_count = rec.heartbeat_count;
        res.relay_url = std::string(rec.relays[0].url);
        res.registration_tx_hash = epee::string_tools::pod_to_hex(rec.registration_tx_hash);
    }
    // Always return OK so the wallet doesn't treat a missing domain as a fatal error
    res.status = CORE_RPC_STATUS_OK;
    return true;
}

// BEGIN_VNS_GET_DOMAIN_POLICY_HANDLER
bool core_rpc_server::on_get_domain_policy(const COMMAND_RPC_GET_DOMAIN_POLICY::request& req, COMMAND_RPC_GET_DOMAIN_POLICY::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
    RPC_TRACKER(get_domain_policy);

    std::string normalized = domain_utils::normalize_vns_domain(req.domain_name);
    if (normalized.empty())
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid domain format";
        return false;
    }

    cryptonote::domain_policy_result policy;
    if (!m_core.get_blockchain_storage().resolve_domain_policy(
            normalized, m_core.get_current_blockchain_height(), policy))
    {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Failed to resolve domain policy";
        return false;
    }

    res.domain = req.domain_name;
    res.normalized = normalized;
    res.registration_allowed = policy.registration_allowed;
    res.pending = policy.pending;
    res.banned = policy.banned;
    res.tier = policy.tier;
    res.fee = policy.fee;
    res.source = static_cast<uint8_t>(policy.source);
    res.policy_height = policy.policy_height;
    res.policy_id = epee::string_tools::pod_to_hex(policy.policy_id);
    res.premium = (policy.source == cryptonote::domain_policy_source::PREMIUM_LABEL);

    res.premium_policy_from_dao = policy.premium_policy_from_dao;
    res.premium_policy_height = policy.premium_policy_height;
    res.premium_policy_id = epee::string_tools::pod_to_hex(policy.premium_policy_id);

    res.ban_policy_from_dao = policy.ban_policy_from_dao;
    res.ban_policy_height = policy.ban_policy_height;
    res.ban_policy_id = epee::string_tools::pod_to_hex(policy.ban_policy_id);

    std::string label, extension;
    domain_utils::parse_vns_domain(normalized, label, extension);
    res.label = label;
    res.extension = extension;

    res.status = CORE_RPC_STATUS_OK;
    return true;
}
// END_VNS_GET_DOMAIN_POLICY_HANDLER

// ---------- VNS ADDITION START (continued) ----------
bool core_rpc_server::on_submit_heartbeat(const COMMAND_RPC_SUBMIT_HEARTBEAT::request& req, COMMAND_RPC_SUBMIT_HEARTBEAT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
 {
    RPC_TRACKER(submit_heartbeat);

    // 1. Get domain record
    vns_domain_record rec = m_core.get_blockchain_storage().get_domain_record(req.domain_name);
    if (is_null_key(rec.registrant_key)) {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Domain not found: " + req.domain_name;
        return false;
    }

    // 3. Parse signature
    crypto::signature sig;
    if (!epee::string_tools::hex_to_pod(req.signature_hex, sig)) {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid signature hex";
        return false;
    }

    // 4. Parse proof
    crypto::hash proof_hash;
    if (!epee::string_tools::hex_to_pod(req.proof_hex, proof_hash)) {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid proof hex";
        return false;
    }
    if (proof_hash == crypto::null_hash) {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Proof cannot be null";
        return false;
    }

    // 5. Parse current block hash
    crypto::hash block_hash;
    if (!epee::string_tools::hex_to_pod(req.current_block_hash, block_hash)) {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid current block hash";
        return false;
    }

    // 6. Verify signature (BIP340): message = domain_name + current_block_hash
    std::string message = req.domain_name + req.current_block_hash;
    crypto::hash message_hash;
    crypto::cn_fast_hash(message.data(), message.size(), message_hash);
    if (rec.registrant_key[0] != 0x02 && rec.registrant_key[0] != 0x03) {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid public key format";
        return false;
    }
    // Pass the full 33-byte compressed public key; bip340::verify expects this format
    if (!bip340::verify(rec.registrant_key.data(), (const unsigned char*)&message_hash, (const unsigned char*)&sig)) {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid signature";
        return false;
    }

    // 6.5 Verify Merkle proof
    crypto::hash proof_block_hash;
    if (!epee::string_tools::hex_to_pod(req.block_hash_hex, proof_block_hash)) {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid block_hash_hex";
        return false;
    }
    // The proof block does NOT need to be the current tip; it must exist on the main chain.
    // verify_merkle_proof() will check that and also validate the Merkle root.
    std::vector<crypto::hash> sibling_hashes;
    sibling_hashes.reserve(req.sibling_hashes.size());
    for (const auto& hex : req.sibling_hashes) {
        crypto::hash h;
        if (!epee::string_tools::hex_to_pod(hex, h)) {
            error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
            error_resp.message = "Invalid sibling hash hex";
            return false;
        }
        sibling_hashes.push_back(h);
    }
    if (!m_core.get_blockchain_storage().verify_merkle_proof(rec.registration_tx_hash, req.leaf_index, sibling_hashes, proof_block_hash)) {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Merkle proof verification failed";
        return false;
    }
        // 6.6 Parse the Nostr event ID (used as dedup proof)
    crypto::hash event_id = crypto::null_hash;
    if (!req.event_id_hex.empty())
    {
        if (!epee::string_tools::hex_to_pod(req.event_id_hex, event_id))
        {
            error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
            error_resp.message = "Invalid event_id_hex";
            return false;
        }
    }

    // 7. Get the current blockchain height (where this heartbeat is being recorded)
    uint64_t current_height = m_core.get_current_blockchain_height();

    // 8. Update heartbeat with current height (uses persistent proof store to avoid duplicate counts)
            uint64_t hb_height = req.heartbeat_height ? req.heartbeat_height : current_height;
            if (hb_height > current_height)
            {
                error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
                error_resp.message = "Heartbeat height is in the future";
                return false;
            }
            if (!m_core.get_blockchain_storage().update_domain_heartbeat(req.domain_name, hb_height, event_id, req.heartbeat_count)) {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Failed to update domain heartbeat";
        return false;
    }

    // 9. Get updated record
    vns_domain_record updated_rec = m_core.get_blockchain_storage().get_domain_record(req.domain_name);

    // 10. Fill response
    res.heartbeat_count = updated_rec.heartbeat_count;
    res.health_score = updated_rec.health_score;
    res.domain_status = updated_rec.status;
    res.status = CORE_RPC_STATUS_OK;

    return true;
}

// ---------- VNS PUBLISH NOSTR EVENT ----------
bool core_rpc_server::on_publish_nostr_event(const COMMAND_RPC_PUBLISH_NOSTR_EVENT::request& req, COMMAND_RPC_PUBLISH_NOSTR_EVENT::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
 {
    RPC_TRACKER(publish_nostr_event);

    if (req.relay_url.empty())
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "relay_url is empty";
        return false;
    }

    if (req.event_json.empty())
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "event_json is empty";
        return false;
    }

    bool success = m_core.get_blockchain_storage().get_nostr_client().publish_event(req.relay_url, req.event_json, 10);
    res.success = success;
    if (!success)
        res.error = "Failed to publish event to relay";
    else
        res.error = "";
    res.status = CORE_RPC_STATUS_OK;
    return true;
 }
// ---------- VNS PUBLISH NOSTR EVENT END ----------

// ---------- VNS SERVICE DESCR ----------
bool core_rpc_server::on_publish_service_descriptor(const COMMAND_RPC_PUBLISH_SERVICE_DESCRIPTOR::request& req, COMMAND_RPC_PUBLISH_SERVICE_DESCRIPTOR::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
    RPC_TRACKER(publish_service_descriptor);

    // 1. Parse event JSON
    rapidjson::Document doc;
    doc.Parse(req.event_json.c_str());
    if (doc.HasParseError() || !doc.IsObject())
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid JSON";
        return false;
    }

    // 2. Extract required fields
    if (!doc.HasMember("kind") || doc["kind"].GetInt() != 30003)
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Event kind must be 30003";
        return false;
    }
    if (!doc.HasMember("pubkey") || !doc["pubkey"].IsString())
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Missing pubkey";
        return false;
    }
    if (!doc.HasMember("tags") || !doc["tags"].IsArray())
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Missing tags";
        return false;
    }
    if (!doc.HasMember("content") || !doc["content"].IsString())
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Missing content";
        return false;
    }
    if (!doc.HasMember("sig") || !doc["sig"].IsString())
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Missing signature";
        return false;
    }

    // 3. Extract tags
    std::string domain;
    std::string fingerprint_hex;
    std::string block_hash_hex;
    std::string leaf_index_str;
    std::vector<std::string> sibling_hexes;

    for (const auto& tag : doc["tags"].GetArray())
    {
        if (!tag.IsArray() || tag.Size() < 2) continue;
        std::string tagname = tag[0].GetString();
        if (tagname == "d" && tag.Size() > 1) domain = tag[1].GetString();
        else if (tagname == "fingerprint" && tag.Size() > 1) fingerprint_hex = tag[1].GetString();
        else if (tagname == "block_hash" && tag.Size() > 1) block_hash_hex = tag[1].GetString();
        else if (tagname == "leaf_index" && tag.Size() > 1) leaf_index_str = tag[1].GetString();
        else if (tagname == "sibling_path" && tag.Size() > 1)
        {
            // tag may have multiple values; collect all after the first
            for (rapidjson::SizeType i = 1; i < tag.Size(); ++i)
            {
                if (tag[i].IsString())
                    sibling_hexes.push_back(tag[i].GetString());
            }
        }
    }
    if (domain.empty() || fingerprint_hex.empty() || block_hash_hex.empty() || leaf_index_str.empty() || sibling_hexes.empty())
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Missing required tags (d, fingerprint, block_hash, leaf_index, sibling_path)";
        return false;
    }

    // 4. Get domain record from blockchain
    vns_domain_record rec = m_core.get_blockchain_storage().get_domain_record(domain);
    if (is_null_key(rec.registrant_key))
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Domain not registered";
        return false;
    }
    if (rec.status == 2)
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Domain expired";
        return false;
    }

    // 5. Verify event signature (BIP340)
    std::string pubkey_hex = doc["pubkey"].GetString();
    if (pubkey_hex.size() != 64) {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid pubkey length, expected 64 hex chars";
        return false;
    }
    std::array<unsigned char, 32> pubkey_x;
    if (!epee::string_tools::hex_to_pod(pubkey_hex, pubkey_x)) {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid pubkey hex";
        return false;
    }
    // Compare x-coordinate with stored registrant key (skip the first byte)
    if (memcmp(pubkey_x.data(), rec.registrant_key.data() + 1, 32) != 0) {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Event pubkey does not match domain registrant";
        return false;
    }

    // 6. Verify fingerprint
    // Compute expected fingerprint = SHA256(domain + registrant_key + registration_height + fee_tier)
    std::string fingerprint_data;
    fingerprint_data += domain;
    fingerprint_data.append(reinterpret_cast<const char*>(rec.registrant_key.data()), rec.registrant_key.size());
    uint64_t height_le = rec.registered_height;
    fingerprint_data.append(reinterpret_cast<const char*>(&height_le), sizeof(height_le));
    fingerprint_data.push_back(static_cast<char>(rec.fee_tier));
    crypto::hash expected_fingerprint;
    crypto::cn_fast_hash(fingerprint_data.data(), fingerprint_data.size(), expected_fingerprint);
    std::string expected_hex = epee::string_tools::pod_to_hex(expected_fingerprint);
    if (expected_hex != fingerprint_hex)
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Fingerprint mismatch";
        return false;
    }

    // 7. Verify Merkle proof
    crypto::hash block_hash;
    if (!epee::string_tools::hex_to_pod(block_hash_hex, block_hash))
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid block_hash hex";
        return false;
    }
    uint64_t leaf_index;
    if (!string_tools::get_xtype_from_string(leaf_index, leaf_index_str))
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Invalid leaf_index";
        return false;
    }
    std::vector<crypto::hash> siblings;
    for (const auto& s : sibling_hexes)
    {
        crypto::hash h;
        if (!epee::string_tools::hex_to_pod(s, h))
        {
            error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
            error_resp.message = "Invalid sibling hash hex";
            return false;
        }
        siblings.push_back(h);
    }
    if (!m_core.get_blockchain_storage().verify_merkle_proof(rec.registration_tx_hash, leaf_index, siblings, block_hash))
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Merkle proof verification failed";
        return false;
    }

    // 8. Publish to relay
    std::string relay_url(rec.relays[0].url);
    if (relay_url.empty())
    {
        error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
        error_resp.message = "Domain has no relay URL configured";
        return false;
    }
    bool published = false;
    try
    {
    published = m_core.get_blockchain_storage().get_nostr_client().publish_event(relay_url, req.event_json);
    }
    catch (const std::exception &e)
    {
    error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
    error_resp.message = std::string("Exception while publishing: ") + e.what();
    return false;
    }
    if (!published)
    {
        error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
        error_resp.message = "Failed to publish event to relay";
        return false;
    }

    res.status = CORE_RPC_STATUS_OK;
    return true;
}
// ---------- VNS SERVICE DESCR END----------

  // ---------- VNS ADDITION END ----------
  //------------------------------------------------------------------------------------------------------------------------------
  const command_line::arg_descriptor<std::string, false, true, 2> core_rpc_server::arg_rpc_bind_port = {
      "rpc-bind-port"
    , "Port for RPC server"
    , std::to_string(config::RPC_DEFAULT_PORT)
    , {{ &cryptonote::arg_testnet_on, &cryptonote::arg_stagenet_on }}
    , [](std::array<bool, 2> testnet_stagenet, bool defaulted, std::string val)->std::string {
        if (testnet_stagenet[0] && defaulted)
          return std::to_string(config::testnet::RPC_DEFAULT_PORT);
        else if (testnet_stagenet[1] && defaulted)
          return std::to_string(config::stagenet::RPC_DEFAULT_PORT);
        return val;
      }
    };

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_rpc_restricted_bind_port = {
      "rpc-restricted-bind-port"
    , "Port for restricted RPC server"
    , ""
    };

  const command_line::arg_descriptor<bool> core_rpc_server::arg_restricted_rpc = {
      "restricted-rpc"
    , "Restrict RPC to view only commands and do not return privacy sensitive data in RPC calls"
    , false
    };

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_bootstrap_daemon_address = {
      "bootstrap-daemon-address"
    , "URL of a 'bootstrap' remote daemon that the connected wallets can use while this daemon is still not fully synced.\n"
      "Use 'auto' to enable automatic public nodes discovering and bootstrap daemon switching"
    , ""
    };

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_bootstrap_daemon_login = {
      "bootstrap-daemon-login"
    , "Specify username:password for the bootstrap daemon login"
    , ""
    };

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_bootstrap_daemon_proxy = {
      "bootstrap-daemon-proxy"
    , "<ip>:<port> socks proxy to use for bootstrap daemon connections"
    , ""
    };

  const command_line::arg_descriptor<std::string> core_rpc_server::arg_rpc_payment_address = {
      "rpc-payment-address"
    , "Restrict RPC to clients sending micropayment to this address"
    , ""
    };

  const command_line::arg_descriptor<uint64_t> core_rpc_server::arg_rpc_payment_difficulty = {
      "rpc-payment-difficulty"
    , "Restrict RPC to clients sending micropayment at this difficulty"
    , DEFAULT_PAYMENT_DIFFICULTY
    };

  const command_line::arg_descriptor<uint64_t> core_rpc_server::arg_rpc_payment_credits = {
      "rpc-payment-credits"
    , "Restrict RPC to clients sending micropayment, yields that many credits per payment"
    , DEFAULT_PAYMENT_CREDITS_PER_HASH
    };

  const command_line::arg_descriptor<bool> core_rpc_server::arg_rpc_payment_allow_free_loopback = {
      "rpc-payment-allow-free-loopback"
    , "Allow free access from the loopback address (ie, the local host)"
    , false
    };

  const command_line::arg_descriptor<std::size_t> core_rpc_server::arg_rpc_max_connections_per_public_ip = {
      "rpc-max-connections-per-public-ip"
    , "Max RPC connections per public IP permitted"
    , DEFAULT_RPC_MAX_CONNECTIONS_PER_PUBLIC_IP
  };

  const command_line::arg_descriptor<std::size_t> core_rpc_server::arg_rpc_max_connections_per_private_ip = {
      "rpc-max-connections-per-private-ip"
    , "Max RPC connections per private and localhost IP permitted"
    , DEFAULT_RPC_MAX_CONNECTIONS_PER_PRIVATE_IP
  };

  const command_line::arg_descriptor<std::size_t> core_rpc_server::arg_rpc_max_connections = {
      "rpc-max-connections"
    , "Max RPC connections permitted"
    , DEFAULT_RPC_MAX_CONNECTIONS
  };

  const command_line::arg_descriptor<std::size_t> core_rpc_server::arg_rpc_response_soft_limit = {
      "rpc-response-soft-limit"
    , "Max response bytes that can be queued, enforced at next response attempt"
    , DEFAULT_RPC_SOFT_LIMIT_SIZE
  };

  // BEGIN_VNS_TREASURY
    bool core_rpc_server::on_get_treasury_balance(const COMMAND_RPC_GET_TREASURY_BALANCE::request& req, COMMAND_RPC_GET_TREASURY_BALANCE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
    {
    RPC_TRACKER(get_treasury_balance);
    res.treasury_balance = m_core.get_blockchain_storage().get_treasury_balance();
    res.status = CORE_RPC_STATUS_OK;
    return true;
    }
  // END_VNS_TREASURY

  // BEGIN_VNS_BURNED_FEES
  bool core_rpc_server::on_get_total_burned_fees(const COMMAND_RPC_GET_TOTAL_BURNED_FEES::request& req, COMMAND_RPC_GET_TOTAL_BURNED_FEES::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_total_burned_fees);
    res.total_burned_fees = m_core.get_blockchain_storage().get_db().get_total_burned_fees();
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  // END_VNS_BURNED_FEES

  // BEGIN_VNS_GOVERNANCE
  bool core_rpc_server::on_get_governance_params(const COMMAND_RPC_GET_GOVERNANCE_PARAMS::request& req, COMMAND_RPC_GET_GOVERNANCE_PARAMS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_governance_params);
    governance_params gp;
    if (!m_core.get_blockchain_storage().get_governance_params(gp))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
      error_resp.message = "Governance parameters not found";
      return false;
    }

    // BEGIN_VNS_GOVERNANCE_PARAMS_DYNAMIC
    uint64_t current_height = m_core.get_current_blockchain_height();
    gp.proposal_submission_fee = m_core.get_blockchain_storage().governance().get_governance_parameter(governance_parameter::proposal_submission_fee, current_height);
    gp.voting_quorum_percent = m_core.get_blockchain_storage().governance().get_governance_parameter(governance_parameter::voting_quorum_percent, current_height);
    for (size_t i = 0; i < 6; ++i)
    {
      gp.tier_fees[i] = m_core.get_blockchain_storage().governance().get_governance_parameter(
          static_cast<governance_parameter>(static_cast<uint8_t>(governance_parameter::domain_tier_fee_0) + i),
          current_height);
    }
    // END_VNS_GOVERNANCE_PARAMS_DYNAMIC

    // BEGIN_VNS_EFFECTIVE_EXTENSION_MAP
    std::map<std::string, uint8_t> effective_extensions;
    for (size_t i = 0; i < gp.extension_tier_map_keys.size(); ++i)
      effective_extensions[gp.extension_tier_map_keys[i]] = gp.extension_tier_map_vals[i];

    std::vector<extension_policy_record> extension_policies;
    m_core.get_blockchain_storage().get_db().for_all_extension_policy_records(
      [&](const extension_policy_record& rec)
      {
        if (rec.activation_height <= current_height)
          extension_policies.push_back(rec);
        return true;
      });

    std::sort(extension_policies.begin(), extension_policies.end(),
      [](const extension_policy_record& a, const extension_policy_record& b)
      {
        return a.activation_height < b.activation_height;
      });

    for (const auto& rec : extension_policies)
      effective_extensions[std::string(rec.extension)] = rec.tier;

    gp.extension_tier_map_keys.clear();
    gp.extension_tier_map_vals.clear();
    for (const auto& [ext, tier] : effective_extensions)
    {
      gp.extension_tier_map_keys.push_back(ext);
      gp.extension_tier_map_vals.push_back(tier);
    }
    res.extension_tier_map_keys = gp.extension_tier_map_keys;
    res.extension_tier_map_vals = gp.extension_tier_map_vals;
    // END_VNS_EFFECTIVE_EXTENSION_MAP

    res.governance_params_blob = epee::string_tools::buff_to_hex_nodelimer(gp.serialize());

    // BEGIN_VNS_GOVERNANCE_PARAMS_RPC
    res.proposal_fee = gp.proposal_submission_fee;
    res.quorum = gp.voting_quorum_percent;
    res.voting_period = m_core.get_blockchain_storage().governance().get_governance_parameter(governance_parameter::voting_period_days, current_height);
    res.execution_delay = m_core.get_blockchain_storage().governance().get_governance_parameter(governance_parameter::execution_delay, current_height);
    res.premium_tier_fee = domain_utils::PREMIUM_TIER_FEE;
    // END_VNS_GOVERNANCE_PARAMS_RPC

    res.status = CORE_RPC_STATUS_OK;
    return true;
  }
  // END_VNS_GOVERNANCE

  // BEGIN_VNS_DKG
  bool core_rpc_server::on_start_dkg(const COMMAND_RPC_START_DKG::request& req, COMMAND_RPC_START_DKG::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(start_dkg);

    if (!m_core.get_blockchain_storage().start_dkg_ceremony(req.proposal_id))
    {
        res.status = "DKG ceremony could not be started";
        return true;
    }

    res.status = "STARTED";
    return true;
  }
  // END_VNS_DKG

  // BEGIN_VNS_DAO_RPC
  bool core_rpc_server::on_submit_proposal(const COMMAND_RPC_SUBMIT_PROPOSAL::request& req, COMMAND_RPC_SUBMIT_PROPOSAL::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(submit_proposal);
    if (!check_core_ready())
      return false;

    cryptonote::transaction tx;
    crypto::hash tx_hash;
    if (!cryptonote::parse_and_validate_tx_from_blob(req.tx_as_hex, tx, tx_hash))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Invalid transaction";
      return false;
    }

    // Submit to mempool; governance validation occurs at block inclusion.
    tx_verification_context tvc{};
    if(!m_core.handle_incoming_tx(req.tx_as_hex, tvc, relay_method::local, false) || tvc.m_verifivation_failed)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Transaction could not be added to mempool";
      return false;
    }

    // Extract proposal_id from tx hash
    crypto::hash proposal_id = tx_hash;

    res.status = "Submitted";
    res.proposal_id = proposal_id;
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

  bool core_rpc_server::on_vote(const COMMAND_RPC_VOTE::request& req, COMMAND_RPC_VOTE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(vote);
    if (!check_core_ready())
      return false;

    cryptonote::transaction tx;
    crypto::hash tx_hash;
    if (!cryptonote::parse_and_validate_tx_from_blob(req.tx_as_hex, tx, tx_hash))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Invalid transaction";
      return false;
    }

    uint64_t height = m_core.get_current_blockchain_height();
    vote_result res_vote = m_core.get_blockchain_storage().governance().process_vote(tx, height, true); // dry_run
    if (res_vote != vote_result::success)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Vote validation failed";
      return false;
    }

    tx_verification_context tvc{};
    if(!m_core.handle_incoming_tx(req.tx_as_hex, tvc, relay_method::local, false) || tvc.m_verifivation_failed)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Transaction could not be added to mempool";
      return false;
    }

    res.status = "Vote recorded";
    return true;
  }

  bool core_rpc_server::on_get_committee(const COMMAND_RPC_GET_COMMITTEE::request& req, COMMAND_RPC_GET_COMMITTEE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_committee);
    const auto& sorted = m_core.get_blockchain_storage().get_committee_eligible_sorted();
    for (const auto& p : sorted)
    {
      res.members.push_back(epee::string_tools::pod_to_hex(p.first));
      res.weights.push_back(p.second);
    }
    return true;
  }

  bool core_rpc_server::on_get_vote_tally(const COMMAND_RPC_GET_VOTE_TALLY::request& req, COMMAND_RPC_GET_VOTE_TALLY::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_vote_tally);
    crypto::hash proposal_id;
    if (!epee::string_tools::hex_to_pod(req.proposal_id, proposal_id))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Invalid proposal_id hex string";
      return false;
    }
    const auto& tallies = m_core.get_blockchain_storage().get_vote_tallies();
    auto it = tallies.find(proposal_id);
    if (it == tallies.end())
    {
      res.encrypted = false;
      res.yes_weight = 0;
      res.no_weight = 0;
      res.passed = false;
      return true;
    }
    res.encrypted = it->second.encrypted;
    res.yes_weight = it->second.total_yes_weight;
    res.no_weight = it->second.total_no_weight;
    // For plain tally, a proposal passes when yes > no (temporary)
    res.passed = (!it->second.encrypted && it->second.total_yes_weight > it->second.total_no_weight);
    return true;
  }

  // BEGIN_VNS_ELIGIBLE
  bool core_rpc_server::on_get_committee_key(const COMMAND_RPC_GET_COMMITTEE_KEY::request& req, COMMAND_RPC_GET_COMMITTEE_KEY::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
  {
    RPC_TRACKER(get_committee_key);
    crypto::secret_key privkey = m_core.get_node_key();
    crypto::public_key pubkey;
    crypto::secret_key_to_public_key(privkey, pubkey);
    // Check for known weak default key (secret key = 1 → public key starts with 0100...)
    const std::string pub_hex = epee::string_tools::pod_to_hex(pubkey);
    if (pub_hex == "0100000000000000000000000000000000000000000000000000000000000000")
    {
      MWARNING("Weak default committee key detected, regenerating.");
      crypto::secret_key new_priv;
      crypto::public_key new_pub;
      crypto::generate_keys(new_pub, new_priv);
      m_core.set_node_key(new_priv);
      res.committee_pubkey = epee::string_tools::pod_to_hex(new_pub);
    }
    else
    {
      res.committee_pubkey = pub_hex;
    }
    return true;
  }
  // BEGIN_VNS_GET_PROPOSALS
  bool core_rpc_server::on_get_proposals(const COMMAND_RPC_GET_PROPOSALS::request& req, COMMAND_RPC_GET_PROPOSALS::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
 {
    RPC_TRACKER(get_proposals);

    auto& blockchain = m_core.get_blockchain_storage();
    uint64_t current_height = m_core.get_current_blockchain_height();

    std::vector<COMMAND_RPC_GET_PROPOSALS::proposal_entry> entries;

    // First pass: collect proposal IDs and basic fields from proposal_record.
    // Do NOT call other DB getters inside this callback to avoid nested transactions.
    blockchain.get_db().for_all_proposal_records(
      [&](const crypto::hash& pid, const proposal_record& rec) {
        COMMAND_RPC_GET_PROPOSALS::proposal_entry entry;
        entry.proposal_id = epee::string_tools::pod_to_hex(pid);
        entry.type = rec.type;
        entry.title = std::string(rec.title, strnlen(rec.title, sizeof(rec.title)));
        entry.submission_height = rec.submission_height;
        entry.voting_end_height = rec.voting_end_height;
        // Default statuses until we fill them below
        entry.proposal_status = "active";
        entry.quorum_met = false;
        entry.tally_passed = false;
        entry.executed = false;
        entries.push_back(std::move(entry));
        return true;
      });

    // Second pass: fill in derived fields (can now safely use separate DB calls)
    for (auto& entry : entries)
    {
        crypto::hash pid;
        if (!epee::string_tools::hex_to_pod(entry.proposal_id, pid))
            continue;

        proposal_record rec;
        if (!blockchain.get_db().get_proposal_record(pid, rec))
            continue;

        // BEGIN_VNS_PROPOSAL_METADATA_ONCHAIN
        // Title is already populated from rec.title in the first pass.
        // No separate metadata fetch needed.
        // END_VNS_PROPOSAL_METADATA_ONCHAIN

        // Execution status
        proposal_execution_record exec_rec;
        entry.executed = blockchain.get_db().get_proposal_execution_record(pid, exec_rec);

        // Vote outcome
        uint64_t yes_w = 0, no_w = 0, yes_b = 0, no_b = 0;
        bool has_outcome = blockchain.get_db().get_proposal_outcome(pid, yes_w, no_w, yes_b, no_b);
        if (has_outcome)
        {
            // Evaluate proposal state
            if (current_height <= rec.voting_end_height)
            {
                entry.proposal_status = "active";
            }
            else
            {
                entry.tally_passed = blockchain.governance().is_proposal_passed(yes_w, no_w, yes_b, no_b, rec.voting_end_height);
                entry.proposal_status = entry.tally_passed ? "passed" : "rejected";

                uint64_t participating = yes_b + no_b;
                uint64_t minted = blockchain.get_db().get_block_already_generated_coins(rec.voting_end_height);
                uint64_t treasury = blockchain.get_db().get_treasury_balance();
                uint64_t burned = blockchain.get_db().get_total_burned_fees();
                uint64_t circulating = (minted > treasury + burned) ? (minted - treasury - burned) : 0;
                governance_params gp;
                if (!blockchain.get_governance_params(gp))
                    gp = governance_params::default_params();
                uint64_t required_quorum = circulating * gp.voting_quorum_percent / 100;
                entry.quorum_met = (participating >= required_quorum);
            }
        }
        else
        {
            if (current_height > rec.voting_end_height)
            {
                entry.proposal_status = "rejected";
            }
            else
            {
                entry.proposal_status = "active";
            }
        }
    }

    // Filter by optional proposal_id
    if (!req.proposal_id.empty())
    {
        entries.erase(std::remove_if(entries.begin(), entries.end(),
            [&](const auto& e) { return e.proposal_id != req.proposal_id; }),
            entries.end());
    }

    // Sort by submission_height descending
    std::sort(entries.begin(), entries.end(),
        [](const auto& a, const auto& b) {
            if (a.submission_height != b.submission_height)
                return a.submission_height > b.submission_height;
            return a.proposal_id < b.proposal_id;
        });

    // Pagination
    uint64_t start = req.offset;
    uint64_t count = req.limit;
    if (start < entries.size())
    {
        auto it = entries.begin() + start;
        auto end = (count > 0 && start + count < entries.size()) ? it + count : entries.end();
        entries.assign(it, end);
    }
    else
    {
        entries.clear();
    }

    res.proposals = std::move(entries);
    res.status = CORE_RPC_STATUS_OK;
    return true;
}
  // END_VNS_GET_PROPOSALS

  bool core_rpc_server::on_get_proposal(const COMMAND_RPC_GET_PROPOSAL::request& req, COMMAND_RPC_GET_PROPOSAL::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
{
  RPC_TRACKER(get_proposal);

  if (req.proposal_id.empty())
  {
    error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
    error_resp.message = "proposal_id is required";
    return false;
  }

  crypto::hash pid;
  if (!epee::string_tools::hex_to_pod(req.proposal_id, pid))
  {
    error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
    error_resp.message = "Invalid proposal_id hex string";
    return false;
  }

  auto& blockchain = m_core.get_blockchain_storage();
  proposal_record rec;
  if (!blockchain.get_db().get_proposal_record(pid, rec))
  {
    res.status = CORE_RPC_STATUS_OK;
    return true;
  }

  res.proposal_id = req.proposal_id;
  res.type = rec.type;

  // BEGIN_VNS_PROPOSAL_METADATA_ONCHAIN
  res.title = std::string(rec.title, strnlen(rec.title, sizeof(rec.title)));
  res.description = std::string(rec.description, strnlen(rec.description, sizeof(rec.description)));
  // END_VNS_PROPOSAL_METADATA_ONCHAIN

  res.recipient = std::string(rec.recipient, strnlen(rec.recipient, sizeof(rec.recipient)));
  res.amount = rec.amount;
  res.voting_period_days = rec.voting_period_days;
  res.submission_height = rec.submission_height;
  res.voting_end_height = rec.voting_end_height;
  res.submission_tx_hash = epee::string_tools::pod_to_hex(rec.submission_tx_hash);

  // BEGIN_VNS_GET_PROPOSAL_DATA_BLOB
  res.data_blob.clear();
  if (rec.type == 1)
  {
    std::string raw_data;
    if (blockchain.get_db().get_proposal_data(pid, raw_data))
      res.data_blob = epee::string_tools::buff_to_hex_nodelimer(raw_data);
  }
  // END_VNS_GET_PROPOSAL_DATA_BLOB

  proposal_execution_record exec_rec;
  res.executed = blockchain.get_db().get_proposal_execution_record(pid, exec_rec);

  uint64_t yes_w = 0, no_w = 0, yes_b = 0, no_b = 0;
  bool has_outcome = blockchain.get_db().get_proposal_outcome(pid, yes_w, no_w, yes_b, no_b);
  if (has_outcome)
  {
    res.yes_weight = yes_w;
    res.no_weight = no_w;
    res.yes_participation_balance = yes_b;
    res.no_participation_balance = no_b;

    uint64_t current_height = blockchain.get_current_blockchain_height();
    if (current_height > rec.voting_end_height)
    {
        uint64_t participating = yes_b + no_b;
        uint64_t minted = blockchain.get_db().get_block_already_generated_coins(rec.voting_end_height);
        uint64_t treasury = blockchain.get_db().get_treasury_balance();
        uint64_t burned = blockchain.get_db().get_total_burned_fees();
        uint64_t circulating = (minted > treasury + burned) ? (minted - treasury - burned) : 0;
        governance_params gp;
        if (!blockchain.get_governance_params(gp))
          gp = governance_params::default_params();
        uint64_t required_quorum = circulating * gp.voting_quorum_percent / 100;
        res.quorum_met = (participating >= required_quorum);
        res.tally_passed = blockchain.governance().is_proposal_passed(yes_w, no_w, yes_b, no_b, rec.voting_end_height);
        res.proposal_status = res.tally_passed ? "passed" : "rejected";
    }
    else
    {
        res.quorum_met = false;
        res.tally_passed = false;
        res.proposal_status = "active";
    }
  }
  else
  {
    res.yes_weight = 0;
    res.no_weight = 0;
    res.yes_participation_balance = 0;
    res.no_participation_balance = 0;
    res.quorum_met = false;
    res.tally_passed = false;
    uint64_t current_height = m_core.get_current_blockchain_height();
    res.proposal_status = (current_height > rec.voting_end_height) ? "rejected" : "active";
  }

  res.status = CORE_RPC_STATUS_OK;
  return true;
}

bool core_rpc_server::on_submit_vote(const COMMAND_RPC_SUBMIT_VOTE::request& req, COMMAND_RPC_SUBMIT_VOTE::response& res, epee::json_rpc::error& error_resp, const connection_context *ctx)
 {
    RPC_TRACKER(submit_vote);
    if (!check_core_ready())
      return false;

    cryptonote::transaction tx;
    crypto::hash tx_hash;
    if (!cryptonote::parse_and_validate_tx_from_blob(req.tx_as_hex, tx, tx_hash))
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Invalid transaction";
      return false;
    }

    // Submit to mempool; governance validation occurs at block inclusion.
    tx_verification_context tvc{};
    if(!m_core.handle_incoming_tx(req.tx_as_hex, tvc, relay_method::local, false) || tvc.m_verifivation_failed)
    {
      error_resp.code = CORE_RPC_ERROR_CODE_WRONG_PARAM;
      error_resp.message = "Transaction could not be added to mempool";
      return false;
    }

    res.accepted = true;
    res.reason = "Vote accepted";
    res.status = CORE_RPC_STATUS_OK;
    return true;
}

}  // namespace cryptonote
