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

#include <iostream>
#include <vector>
#include <cstdlib>
#include <fstream>
#include <string>

#include <boost/filesystem.hpp>

#include "gtest/gtest.h"

#include "common/dns_utils.h"

namespace {

#ifdef _WIN32
static void vr_set_env(const char* name, const char* value)
{
  _putenv_s(name, value ? value : "");
}
static void vr_unset_env(const char* name)
{
  _putenv_s(name, "");
}
#else
static void vr_set_env(const char* name, const char* value)
{
  if (value) setenv(name, value, 1);
  else unsetenv(name);
}
static void vr_unset_env(const char* name)
{
  unsetenv(name);
}
#endif

class scoped_env
{
public:
  scoped_env(const char* name, const char* value) : name_(name)
  {
    const char* old = std::getenv(name);
    if (old) { had_old_ = true; old_ = old; }
    vr_set_env(name, value);
  }
  ~scoped_env()
  {
    if (had_old_) vr_set_env(name_.c_str(), old_.c_str());
    else vr_unset_env(name_.c_str());
  }
private:
  std::string name_;
  bool had_old_ = false;
  std::string old_;
};

class temp_anchor_file
{
public:
  explicit temp_anchor_file(const std::string& contents)
  {
    path_ = boost::filesystem::temp_directory_path() /
            boost::filesystem::unique_path("vr_dns_anchor_%%%%-%%%%");
    std::ofstream out(path_.string().c_str());
    out << contents;
  }
  ~temp_anchor_file()
  {
    boost::system::error_code ec;
    boost::filesystem::remove(path_, ec);
  }
  std::string string() const { return path_.string(); }
private:
  boost::filesystem::path path_;
};

static const char* const VALID_KSK_2024 =
  "; VeilRoot DNSSEC root trust anchors\n"
  ". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n";

static const char* const VALID_KSK_2017 =
  ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n";

}  // anonymous namespace

TEST(DNSResolver, IPv4Success)
{
  tools::DNSResolver resolver = tools::DNSResolver::create();

  bool avail, valid;

  auto ips = resolver.get_ipv4("example.com", avail, valid);

  ASSERT_LE(1, ips.size());

  ips = tools::DNSResolver::instance().get_ipv4("example.com", avail, valid);

  ASSERT_LE(1, ips.size());
}

TEST(DNSResolver, IPv4Failure)
{
  // guaranteed by IANA/ICANN/RFC to be invalid
  tools::DNSResolver resolver = tools::DNSResolver::create();

  bool avail, valid;

  auto ips = resolver.get_ipv4("example.invalid", avail, valid);

  ASSERT_EQ(0, ips.size());

  ips = tools::DNSResolver::instance().get_ipv4("example.invalid", avail, valid);

  ASSERT_EQ(0, ips.size());
}

TEST(DNSResolver, DNSSECSuccess)
{
  tools::DNSResolver resolver = tools::DNSResolver::create();

  bool avail, valid;

  auto ips = resolver.get_ipv4("example.com", avail, valid);

  ASSERT_LE(1, ips.size());

  ASSERT_TRUE(avail);
  ASSERT_TRUE(valid);
}

TEST(DNSResolver, DNSSECFailure)
{
  tools::DNSResolver resolver = tools::DNSResolver::create();

  bool avail, valid;

  auto ips = resolver.get_ipv4("dnssec-failed.org", avail, valid);

  ASSERT_EQ(1, ips.size());

  //ASSERT_STREQ("93.184.216.119", ips[0].c_str());

  ASSERT_TRUE(avail);
  ASSERT_FALSE(valid);
}

// It would be great to include an IPv6 test and assume it'll pass, but not every ISP / resolver plays nicely with IPv6;)
/*TEST(DNSResolver, IPv6Success)
{
  tools::DNSResolver resolver = tools::DNSResolver::create();

  bool avail, valid;

  auto ips = resolver.get_ipv6("example.com", avail, valid);

  ASSERT_EQ(1, ips.size());

  ASSERT_STREQ("2606:2800:220:6d:26bf:1447:1097:aa7", ips[0].c_str());

  ips = tools::DNSResolver::instance().get_ipv6("example.com", avail, valid);

  ASSERT_EQ(1, ips.size());

  ASSERT_STREQ("2606:2800:220:6d:26bf:1447:1097:aa7", ips[0].c_str());
}*/

TEST(DNSResolver, IPv6Failure)
{
  // guaranteed by IANA/ICANN/RFC to be invalid
  tools::DNSResolver resolver = tools::DNSResolver::create();

  bool avail, valid;

  auto ips = resolver.get_ipv6("example.invalid", avail, valid);

  ASSERT_EQ(0, ips.size());

  ips = tools::DNSResolver::instance().get_ipv6("example.invalid", avail, valid);

  ASSERT_EQ(0, ips.size());
}

TEST(DNSResolver, GetTXTRecord)
{
  bool avail, valid;

  std::vector<std::string> records = tools::DNSResolver::instance().get_txt_record("donate.getmonero.org", avail, valid);

  EXPECT_NE(0, records.size());

  for (auto& rec : records)
  {
    std::cout << "TXT record for donate.getmonero.org: " << rec << std::endl;
  }

  // replace first @ with .
  std::string addr = tools::DNSResolver::instance().get_dns_format_from_oa_address("donate@getmonero.org");
  EXPECT_STREQ("donate.getmonero.org", addr.c_str());

  // no change
  addr = tools::DNSResolver::instance().get_dns_format_from_oa_address("donate.getmonero.org");
  EXPECT_STREQ("donate.getmonero.org", addr.c_str());
}

TEST(DNSResolver, Localhost)
{
  tools::DNSResolver resolver = tools::DNSResolver::create();

  bool avail, valid;
  std::vector<std::string> ips = resolver.get_ipv4("localhost", avail, valid);

  ASSERT_EQ(1, ips.size());
  ASSERT_EQ("127.0.0.1", ips[0]);
}

bool is_equal(const char *s, const std::vector<std::string> &v) { return v.size() == 1 && v[0] == s; }

TEST(DNS_PUBLIC, empty) { EXPECT_TRUE(tools::dns_utils::parse_dns_public("").empty()); }
TEST(DNS_PUBLIC, default) { EXPECT_TRUE(tools::dns_utils::parse_dns_public("tcp").size() > 0); }
TEST(DNS_PUBLIC, invalid_scheme) { EXPECT_TRUE(tools::dns_utils::parse_dns_public("invalid").empty()); }
TEST(DNS_PUBLIC, invalid_ip_alpha) { EXPECT_TRUE(tools::dns_utils::parse_dns_public("tcp://invalid").empty()); }
TEST(DNS_PUBLIC, invalid_ip_num1) { EXPECT_TRUE(tools::dns_utils::parse_dns_public("tcp://3").empty()); }
TEST(DNS_PUBLIC, invalid_ip_num3) { EXPECT_TRUE(tools::dns_utils::parse_dns_public("tcp://3.4.5").empty()); }
TEST(DNS_PUBLIC, invalid_ip_num4_extra) { EXPECT_TRUE(tools::dns_utils::parse_dns_public("tcp://3.4.5.6x").empty()); }
TEST(DNS_PUBLIC, invalid_ip_num4_range) { EXPECT_TRUE(tools::dns_utils::parse_dns_public("tcp://3.4.542.6").empty()); }
TEST(DNS_PUBLIC, invalid_ip_dot) { EXPECT_TRUE(tools::dns_utils::parse_dns_public("tcp://3.4.5.6.").empty()); }
TEST(DNS_PUBLIC, invalid_ip_num5) { EXPECT_TRUE(tools::dns_utils::parse_dns_public("tcp://3.4.5.6.7").empty()); }
TEST(DNS_PUBLIC, invalid_ip_4_missing) { EXPECT_TRUE(tools::dns_utils::parse_dns_public("tcp://3.4..7").empty()); }
TEST(DNS_PUBLIC, valid_ip_lo) { EXPECT_TRUE(is_equal("127.0.0.1", tools::dns_utils::parse_dns_public("tcp://127.0.0.1"))); }
TEST(DNS_PUBLIC, valid_ip) { EXPECT_TRUE(is_equal("3.4.5.6", tools::dns_utils::parse_dns_public("tcp://3.4.5.6"))); }
// ==================================================================
// VeilRoot DNSSEC trust-anchor file tests.
//
// Parser tests are fully deterministic: they operate on temporary
// files created and removed by the test itself, and never make a
// network request.
//
// The fail-closed resolver tests are also network-free: the anchor
// file is rejected during resolver construction, before the DNS
// probe, so get_ipv4() returns empty without a packet being sent.
//
// ValidAnchorFileOverride requires network DNS, exactly like the
// existing DNSSECSuccess test.
// ==================================================================

TEST(DNSSECTrustAnchorParser, AcceptsValidKSK2024)
{
  const temp_anchor_file f(VALID_KSK_2024);
  std::string error;
  EXPECT_TRUE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error)) << error;
  EXPECT_TRUE(error.empty());
}

TEST(DNSSECTrustAnchorParser, AcceptsMultipleRecords)
{
  const std::string contents = std::string(VALID_KSK_2017) + VALID_KSK_2024;
  const temp_anchor_file f(contents);
  std::string error;
  EXPECT_TRUE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error)) << error;
}

TEST(DNSSECTrustAnchorParser, AcceptsCommentsAndBlankLines)
{
  const temp_anchor_file f(
      "; full-line comment\n"
      "\n"
      "  ; indented comment\n"
      ". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16 ; trailing\n"
      "\n");
  std::string error;
  EXPECT_TRUE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error)) << error;
}

TEST(DNSSECTrustAnchorParser, AcceptsSha1Digest)
{
  const temp_anchor_file f(
      ". IN DS 12345 8 1 0123456789ABCDEF0123456789ABCDEF01234567\n");
  std::string error;
  EXPECT_TRUE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error)) << error;
}

TEST(DNSSECTrustAnchorParser, AcceptsSha384Digest)
{
  // SHA-384 DS records carry exactly 96 hex characters (48 bytes).
  const std::string digest(96, 'A');
  const temp_anchor_file f(
      ". IN DS 12345 8 4 " + digest + "\n");
  std::string error;
  EXPECT_TRUE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error)) << error;
}

TEST(DNSSECTrustAnchorParser, AcceptsLowercaseTokens)
{
  const temp_anchor_file f(
      ". in ds 38696 8 2 683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16\n");
  std::string error;
  EXPECT_TRUE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error)) << error;
}

TEST(DNSSECTrustAnchorParser, RejectsGarbage)
{
  const temp_anchor_file f("this is not a DS record\n");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
  EXPECT_FALSE(error.empty());
}

TEST(DNSSECTrustAnchorParser, RejectsEmptyFile)
{
  const temp_anchor_file f("");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
  EXPECT_FALSE(error.empty());
}

TEST(DNSSECTrustAnchorParser, RejectsCommentsOnly)
{
  const temp_anchor_file f("; nothing but comments\n\n");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
  EXPECT_FALSE(error.empty());
}

TEST(DNSSECTrustAnchorParser, RejectsMissingFile)
{
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      "/nonexistent/vr_dns_anchor_should_not_exist", error));
  EXPECT_FALSE(error.empty());
}

TEST(DNSSECTrustAnchorParser, RejectsTruncatedDigest)
{
  const temp_anchor_file f(". IN DS 38696 8 2 683D2D0A\n");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
  EXPECT_FALSE(error.empty());
}

TEST(DNSSECTrustAnchorParser, RejectsInvalidHex)
{
  const temp_anchor_file f(
      ". IN DS 38696 8 2 ZZZZ2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
  EXPECT_FALSE(error.empty());
}

TEST(DNSSECTrustAnchorParser, RejectsWrongLengthSha384Digest)
{
  // 128 hex characters: valid hex, wrong length for SHA-384.
  const std::string digest(128, 'A');
  const temp_anchor_file f(
      ". IN DS 12345 8 4 " + digest + "\n");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
  EXPECT_FALSE(error.empty());
}

TEST(DNSSECTrustAnchorParser, RejectsWrongLengthSha1Digest)
{
  // SHA-1 requires 40 hex characters; 64 must be rejected.
  const std::string digest(64, 'A');
  const temp_anchor_file f(
      ". IN DS 12345 8 1 " + digest + "\n");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
  EXPECT_FALSE(error.empty());
}

TEST(DNSSECTrustAnchorParser, RejectsUnsupportedDigestType)
{
  const temp_anchor_file f(
      ". IN DS 38696 8 3 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
  EXPECT_FALSE(error.empty());
}

TEST(DNSSECTrustAnchorParser, RejectsNonRootOwner)
{
  const temp_anchor_file f(
      "example.com. IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
}

TEST(DNSSECTrustAnchorParser, RejectsWrongClass)
{
  const temp_anchor_file f(
      ". CH DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
}

TEST(DNSSECTrustAnchorParser, RejectsWrongType)
{
  const temp_anchor_file f(
      ". IN DNSKEY 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
}

TEST(DNSSECTrustAnchorParser, RejectsKeyTagOutOfRange)
{
  const temp_anchor_file f(
      ". IN DS 65536 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
}

TEST(DNSSECTrustAnchorParser, RejectsZeroAlgorithm)
{
  const temp_anchor_file f(
      ". IN DS 38696 0 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n");
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
}

TEST(DNSSECTrustAnchorParser, RejectsWholeFileOnOneBadLine)
{
  const std::string contents =
      "; comment\n"
      ". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n"
      "this line is garbage\n";
  const temp_anchor_file f(contents);
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
  EXPECT_FALSE(error.empty());
}

TEST(DNSSECTrustAnchorParser, RejectsHashCommentSyntax)
{
  // '#' is not a DNS master-file comment delimiter.
  const std::string contents =
      "# this is not a comment\n"
      ". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n";
  const temp_anchor_file f(contents);
  std::string error;
  EXPECT_FALSE(tools::dns_utils::validate_dnssec_trust_anchor_file(
      f.string(), error));
}

// ------------------------------------------------------------------
// Resolver integration: env-var driven anchor file selection.
// Uses create() so the environment is read at construction time.
// ------------------------------------------------------------------

TEST(DNSResolver, ValidAnchorFileOverride)
{
  const temp_anchor_file f(VALID_KSK_2024);
  scoped_env env("DNSSEC_TRUST_ANCHOR_FILE", f.string().c_str());

  tools::DNSResolver resolver = tools::DNSResolver::create();
  bool avail = false, valid = false;
  auto ips = resolver.get_ipv4("example.com", avail, valid);
  // Requires network DNS, same dependency as DNSResolver.DNSSECSuccess.
  EXPECT_LE(1u, ips.size());
  EXPECT_TRUE(avail);
  EXPECT_TRUE(valid);
}

TEST(DNSResolver, GarbageAnchorFileFailsClosed)
{
  const temp_anchor_file f("this is not a DS record\n");
  scoped_env env("DNSSEC_TRUST_ANCHOR_FILE", f.string().c_str());

  tools::DNSResolver resolver = tools::DNSResolver::create();
  bool avail = true, valid = true;
  auto ips = resolver.get_ipv4("example.com", avail, valid);
  EXPECT_EQ(0u, ips.size());
  EXPECT_FALSE(avail);
  EXPECT_FALSE(valid);
}

TEST(DNSResolver, MissingExplicitAnchorFileFailsClosed)
{
  scoped_env env("DNSSEC_TRUST_ANCHOR_FILE",
                 "/nonexistent/vr_dns_anchor_should_not_exist");

  tools::DNSResolver resolver = tools::DNSResolver::create();
  bool avail = true, valid = true;
  auto ips = resolver.get_ipv4("example.com", avail, valid);
  EXPECT_EQ(0u, ips.size());
  EXPECT_FALSE(avail);
  EXPECT_FALSE(valid);
}

TEST(DNSResolver, RelativeAnchorFileOverrideFailsClosed)
{
  scoped_env env("DNSSEC_TRUST_ANCHOR_FILE", "relative/path/dns_anchors");

  tools::DNSResolver resolver = tools::DNSResolver::create();
  bool avail = true, valid = true;
  auto ips = resolver.get_ipv4("example.com", avail, valid);
  EXPECT_EQ(0u, ips.size());
  EXPECT_FALSE(avail);
  EXPECT_FALSE(valid);
}

TEST(DNSResolver, OverrideScopeIsClearedOnExit)
{
  // Failing override must not leak to the next construction.
  {
    const temp_anchor_file f("garbage\n");
    scoped_env env("DNSSEC_TRUST_ANCHOR_FILE", f.string().c_str());
    tools::DNSResolver r = tools::DNSResolver::create();
    bool a = true, v = true;
    auto ips = r.get_ipv4("example.invalid", a, v);
    EXPECT_EQ(0u, ips.size());
  }

  // After the scope ends, a fresh resolver must construct with the
  // compiled-anchor fallback. localhost comes from /etc/hosts and is
  // independent of DNSSEC anchor state, so it is a deterministic
  // "resolver is functional" check.
  tools::DNSResolver resolver = tools::DNSResolver::create();
  bool a = false, v = false;
  auto ips = resolver.get_ipv4("localhost", a, v);
  EXPECT_EQ(1u, ips.size());
  if (ips.size() == 1)
    EXPECT_EQ("127.0.0.1", ips[0]);
}
